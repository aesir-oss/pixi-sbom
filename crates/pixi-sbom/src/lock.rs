//! Converts one environment/platform of a `pixi.lock` into the [`Sbom`] model.
//!
//! Reading the lockfile is the shared crate's (`crate::lock::facts`, #58): what each package is, as the lockfile states
//! it, and the edges between packages. This module turns those facts into the SBOM model: the `pixi:*` properties,
//! suppliers, the PyPI source identities and the extras each package was asked for.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use self::facts::{BuildSource, Fact, Kind, ReadError};
use miette::Diagnostic;
use rattler_lock::LockFile;
use thiserror::Error;

use crate::model::{Package, PackageKind, Root, Sbom, Supplier};
use crate::purl;

/// The dependency names one package declares, before they are matched to packages present in the same environment.
pub(crate) use crate::lock::facts::Declared as DeclaredDeps;
pub(crate) use crate::lock::facts::local_path_reference;

/// The highest `pixi.lock` `version:` this build understands, from the lockfile reader it is
/// compiled against, so the help text cannot drift from what the reader accepts.
pub const MAX_LOCKFILE_VERSION: u16 = rattler_lock::FileFormatVersion::LATEST as u16;

/// Errors raised while reading the lockfile or selecting what to describe.
#[derive(Debug, Error, Diagnostic)]
pub enum LockError {
    /// The lockfile could not be parsed.
    #[error("cannot read lockfile {path}")]
    #[diagnostic(
        code(pixi_sbom::lock::parse),
        help(
            "this build reads pixi.lock up to version {MAX_LOCKFILE_VERSION}: run `pixi lock` to rewrite an \
             older or damaged one, or upgrade pixi-sbom if the file's `version:` is higher"
        )
    )]
    Parse {
        /// Lockfile path.
        path: String,
        #[source]
        source: Box<rattler_lock::ParseCondaLockError>,
    },

    /// The requested environment is not in the lockfile.
    #[error("environment '{name}' not found in lockfile; available: {}", available.join(", "))]
    #[diagnostic(
        code(pixi_sbom::lock::environment),
        help("pass one of the available names with --environment")
    )]
    EnvironmentNotFound {
        /// Requested environment.
        name: String,
        /// Environments the lockfile defines.
        available: Vec<String>,
    },

    /// The requested platform is not locked for the environment.
    #[error("platform '{platform}' is not locked for environment '{environment}'; available: {}", available.join(", "))]
    #[diagnostic(
        code(pixi_sbom::lock::platform),
        help("pass one of the available platforms with --platform")
    )]
    PlatformNotFound {
        /// Requested platform.
        platform: String,
        /// Environment that was searched.
        environment: String,
        /// Platforms locked for that environment.
        available: Vec<String>,
    },

    /// The host platform could not be determined and none was given.
    #[error("cannot determine the current platform")]
    #[diagnostic(
        code(pixi_sbom::lock::current_platform),
        help("pass the platform explicitly with --platform")
    )]
    UnknownCurrentPlatform,

    /// A package name the purl spec rejects.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Purl(#[from] purl::PurlError),
}

impl From<ReadError> for LockError {
    fn from(err: ReadError) -> Self {
        match err {
            ReadError::EnvironmentNotFound { name, available } => LockError::EnvironmentNotFound { name, available },
            ReadError::PlatformNotFound {
                platform,
                environment,
                available,
            } => LockError::PlatformNotFound {
                platform,
                environment,
                available,
            },
            ReadError::UnknownCurrentPlatform => LockError::UnknownCurrentPlatform,
            ReadError::Purl(err) => LockError::Purl(err.into()),
        }
    }
}

/// What to extract from the lockfile.
#[derive(Debug, Clone)]
pub struct Selection<'a> {
    /// Lock environment name.
    pub environment: &'a str,
    /// Platform name; `None` means the host platform.
    pub platform: Option<&'a str>,
}

/// A parsed lockfile together with the exact text it was parsed from.
#[derive(Debug)]
pub struct LoadedLock {
    /// The parsed lockfile.
    pub lock: LockFile,
    /// The lockfile's source text, which identifies the input for reproducible document ids.
    pub contents: String,
}

/// Read and parse the lockfile at `path`.
pub fn load(path: &Path) -> Result<LoadedLock, LockError> {
    let contents = std::fs::read_to_string(path).map_err(|err| LockError::Parse {
        path: path.display().to_string(),
        source: Box::new(err.into()),
    })?;
    parse(contents, path.parent(), &path.display().to_string())
}

/// Parse lockfile text that came from somewhere other than a file — a generated one, a
/// document under test — resolving any relative path in it against `base_dir`. `origin` names
/// the text in the diagnostic, since there may be no path to name.
pub fn parse(contents: String, base_dir: Option<&Path>, origin: &str) -> Result<LoadedLock, LockError> {
    let lock = LockFile::from_str_with_base_directory(&contents, base_dir).map_err(|source| LockError::Parse {
        path: origin.to_string(),
        source: Box::new(source),
    })?;
    Ok(LoadedLock { lock, contents })
}

/// Names of every environment in the lockfile: `default` first, the rest alphabetical.
pub fn environment_names(lock: &LockFile) -> Vec<String> {
    facts::environment_names(lock)
}

/// Names of every platform `environment` is locked for, alphabetical.
pub fn platform_names(lock: &LockFile, environment: &str) -> Result<Vec<String>, LockError> {
    Ok(facts::platform_names(lock, environment)?)
}

/// Parse `path` and build the SBOM model for the selected environment/platform.
#[cfg(test)]
pub fn build_sbom(path: &Path, selection: Selection<'_>, root: Root) -> Result<Sbom, LockError> {
    let lock = load(path)?.lock;
    sbom_from_lock(&lock, selection, root, &crate::discover::lockfile_name(path))
}

/// Build the SBOM model from an already parsed lockfile. `lockfile_name` is recorded in the
/// document as-is; pass the workspace-relative name, not an absolute path.
pub fn sbom_from_lock(
    lock: &LockFile,
    selection: Selection<'_>,
    root: Root,
    lockfile_name: &str,
) -> Result<Sbom, LockError> {
    sbom_from_lock_with_extras(lock, selection, root, lockfile_name, &BTreeMap::new())
}

/// [`sbom_from_lock`], told which extras the workspace manifest asks for, by PEP 503-normalized
/// PyPI name. A requirement gated on an extra (`pysocks; extra == 'socks'`) brings its package in
/// only when that extra was asked for, here or by another package's requirement.
pub fn sbom_from_lock_with_extras(
    lock: &LockFile,
    selection: Selection<'_>,
    root: Root,
    lockfile_name: &str,
    manifest_extras: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Sbom, LockError> {
    let read = facts::read(lock, selection.environment, selection.platform)?;
    tracing::info!(
        environment = selection.environment,
        platform = %read.platform,
        packages = read.packages.len(),
        "selected lock environment"
    );

    let mut packages = read
        .packages
        .iter()
        .map(convert_package)
        .collect::<Result<Vec<_>, _>>()?;
    // Edges by id, sorted, as `link_dependencies` gives them for every other reader.
    let ids: Vec<String> = packages.iter().map(|p| p.id.clone()).collect();
    for (package, fact) in packages.iter_mut().zip(&read.packages) {
        package.dependencies = fact
            .dependencies
            .iter()
            .map(|&to| ids[to].clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|dep| dep != &package.id)
            .collect();
    }
    record_extras(&read.packages, &mut packages, manifest_extras);
    for package in &mut packages {
        if let Some(raw) = &package.license
            && crate::license::is_rewritten(raw)
        {
            package.properties.insert("pixi:license-raw".into(), raw.clone());
        }
    }
    packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    Ok(Sbom {
        root,
        environment: selection.environment.to_string(),
        platform: read.platform,
        lockfile: lockfile_name.to_string(),
        prefix: None,
        document: None,
        packages,
        vulnerabilities: Vec::new(),
        excluded: Vec::new(),
        declared_missing: Vec::new(),
        incomplete: crate::model::Incomplete::default(),
        lifecycles: vec![crate::model::PHASE_LOCKFILE.into()],
        declared_roots: false,
        scopes: std::collections::BTreeMap::new(),
        interpreter: None,
    })
}

fn convert_package(fact: &Fact) -> Result<Package, LockError> {
    match fact.kind {
        Kind::Pypi => convert_pypi(fact),
        Kind::CondaBinary | Kind::CondaSource => Ok(convert_conda(fact)),
    }
}

fn convert_conda(fact: &Fact) -> Package {
    let mut properties = BTreeMap::new();
    let mut supplier = None;
    if fact.kind == Kind::CondaBinary {
        if let Some(url) = &fact.channel_url {
            properties.insert("pixi:channel-url".into(), url.clone());
        }
        supplier = fact.channel.as_ref().map(|name| Supplier {
            name: name.clone(),
            url: fact.channel_url.clone(),
        });
        if let Some(file_name) = &fact.file_name {
            properties.insert("pixi:file-name".into(), file_name.clone());
        }
    } else {
        if let Some(hash) = &fact.identifier_hash {
            properties.insert("pixi:identifier-hash".into(), hash.clone());
        }
        if let Some(source) = &fact.build_source {
            describe_build_source(source, &mut properties);
        }
    }
    if let Some(channel) = &fact.channel {
        properties.insert("pixi:channel".into(), channel.clone());
    }
    if let Some(subdir) = &fact.subdir {
        properties.insert("pixi:subdir".into(), subdir.clone());
    }
    if let Some(build) = &fact.build {
        properties.insert("pixi:build".into(), build.clone());
    }
    if let Some(build_number) = fact.build_number {
        properties.insert("pixi:build-number".into(), build_number.to_string());
        if let Some(family) = &fact.license_family {
            properties.insert("pixi:license-family".into(), family.clone());
        }
        if let Some(size) = fact.size {
            properties.insert("pixi:size".into(), size.to_string());
        }
        if fact.noarch {
            properties.insert("pixi:noarch".into(), "true".into());
        }
    }
    // pixi writes `purls:` as bare names, and the facts fill in the entry's own version. With no version to fill
    // in, say so, because the alternative is a package that quietly never gets asked about.
    if fact.version.is_none() && fact.stated_purls.iter().any(|p| !p.contains('@')) {
        tracing::warn!(
            package = %fact.name,
            "the lockfile states a PyPI purl with no version and the entry has no version either; \
             vulnerability lookups cannot query this package"
        );
    }
    Package {
        id: fact.purl.clone(),
        name: fact.name.clone(),
        version: fact.version.clone(),
        kind: match fact.kind {
            Kind::CondaSource => PackageKind::CondaSource,
            _ => PackageKind::CondaBinary,
        },
        purl: fact.purl.clone(),
        supplier,
        extra_purls: fact.stated_purls.clone(),
        purls_from_lock: fact.purls_from_lock,
        location: fact.location.clone(),
        sha256: fact.sha256.clone(),
        md5: fact.md5.clone(),
        sha512: None,
        license: fact.license.clone(),
        license_files: Vec::new(),
        description: None,
        homepage: None,
        repository: None,
        documentation: None,
        yanked: None,
        properties,
        dependencies: Vec::new(),
        occurrences: Vec::new(),
    }
}

/// A pixi-build source spec as `pixi:source-*` properties.
fn describe_build_source(source: &BuildSource, properties: &mut BTreeMap<String, String>) {
    match source {
        BuildSource::Git {
            url,
            rev,
            branch,
            tag,
            subdir,
        } => {
            properties.insert("pixi:source-git".into(), url.clone());
            properties.insert("pixi:source-rev".into(), rev.clone());
            if let Some(branch) = branch {
                properties.insert("pixi:source-branch".into(), branch.clone());
            }
            if let Some(tag) = tag {
                properties.insert("pixi:source-tag".into(), tag.clone());
            }
            if let Some(subdir) = subdir {
                properties.insert("pixi:source-subdirectory".into(), subdir.clone());
            }
        }
        BuildSource::Url { url, subdir, .. } => {
            properties.insert("pixi:source-url".into(), url.clone());
            if let Some(subdir) = subdir {
                properties.insert("pixi:source-subdirectory".into(), subdir.clone());
            }
        }
        BuildSource::Path { path } => {
            properties.insert("pixi:source-path".into(), path.clone());
        }
    }
}

fn convert_pypi(fact: &Fact) -> Result<Package, LockError> {
    let mut properties = BTreeMap::new();
    let mut supplier = None;
    if let Some(index) = &fact.index_url {
        properties.insert("pixi:index-url".into(), index.clone());
        supplier = Some(Supplier {
            name: fact.index_host.clone().unwrap_or_else(|| index.clone()),
            url: Some(index.clone()),
        });
    }
    if let Some(requires_python) = &fact.requires_python {
        properties.insert("pixi:requires-python".into(), requires_python.clone());
    }
    if fact.sdist {
        properties.insert("pixi:source".into(), "true".into());
    }
    // A git checkout or a local path, recorded as the other readers record them. A URL without
    // an index could be either an archive or an index wheel from an older lockfile, so it stays.
    let location = fact.location.clone();
    if let Some(git) = location.strip_prefix("git+") {
        let (rest, commit) = git.split_once('#').unwrap_or((git, ""));
        let repository = rest.split('?').next().unwrap_or(rest);
        properties.insert("pixi:direct-url".into(), repository.to_string());
        if !commit.is_empty() {
            properties.insert("pixi:source-rev".into(), commit.to_string());
        }
    } else if fact.location_is_path || location.starts_with("file://") {
        properties.insert("pixi:direct-url".into(), location.clone());
    }

    let mut package = Package {
        id: fact.purl.clone(),
        name: fact.name.clone(),
        version: fact.version.clone(),
        kind: PackageKind::Pypi,
        purl: fact.purl.clone(),
        supplier,
        extra_purls: Vec::new(),
        purls_from_lock: true,
        location,
        sha256: fact.sha256.clone(),
        md5: fact.md5.clone(),
        sha512: None,
        license: None,
        license_files: Vec::new(),
        description: None,
        homepage: None,
        repository: None,
        documentation: None,
        yanked: None,
        properties,
        dependencies: Vec::new(),
        occurrences: Vec::new(),
    };
    purl::identify_pypi_source(&mut package)?;
    Ok(package)
}

/// Which extras each PyPI package was asked for, and which packages are present only for one.
fn record_extras(facts: &[Fact], packages: &mut [Package], manifest_extras: &BTreeMap<String, BTreeSet<String>>) {
    let by_name: HashMap<String, String> = packages
        .iter()
        .filter(|p| p.kind == PackageKind::Pypi)
        .map(|p| (purl::normalize_pypi_name(&p.name), p.id.clone()))
        .collect();
    let mut extras = crate::extras::Extras::default();
    for (name, asked) in manifest_extras {
        if let Some(id) = by_name.get(name) {
            extras.request(id, asked.iter().cloned());
        }
    }
    let mut gates: Vec<(String, String, String, String)> = Vec::new();
    for (fact, package) in facts.iter().zip(packages.iter()) {
        if fact.kind != Kind::Pypi {
            continue;
        }
        for requirement in &fact.requirements {
            let Some(to) = by_name.get(&purl::normalize_pypi_name(&requirement.name)) else {
                continue;
            };
            if !package.dependencies.contains(to) {
                continue;
            }
            extras.request(to, requirement.extras.iter().cloned());
            for extra in crate::extras::gating_extras(&requirement.marker) {
                gates.push((package.id.clone(), package.name.clone(), extra, to.clone()));
            }
        }
    }
    // Only a gate whose extra was asked for brought anything in.
    for (from, name, extra, to) in gates {
        if extras.requested.get(&from).is_some_and(|asked| asked.contains(&extra)) {
            extras.gate(&from, &name, &extra, &to);
        } else {
            extras.unrequested.insert((from, to));
        }
    }
    extras.apply(packages);
}

/// Match each package's declared dependencies (same order as `packages`) to the packages present, as
/// `crate::lock::facts::link` does, giving each package its edges as sorted ids, never its own.
pub(crate) fn link_dependencies(packages: &mut [Package], declared: &[DeclaredDeps]) {
    let entries: Vec<(String, bool)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.kind == PackageKind::Pypi))
        .collect();
    let ids: Vec<String> = packages.iter().map(|p| p.id.clone()).collect();
    for (package, edges) in packages.iter_mut().zip(facts::link(&entries, declared)) {
        package.dependencies = edges
            .into_iter()
            .map(|to| ids[to].clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|dep| dep != &package.id)
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_can_be_parsed_without_a_file_and_names_itself_when_it_will_not() {
        let text = "version: 7\nplatforms:\n- name: linux-64\nenvironments:\n  default:\n    channels:\n    - url: https://conda.anaconda.org/conda-forge/\n    packages:\n      linux-64: []\npackages: []\n";
        let loaded = parse(text.to_string(), None, "<generated>").expect("a minimal lockfile parses");
        assert_eq!(
            loaded.contents, text,
            "the text is kept as given: it identifies the input"
        );
        assert_eq!(environment_names(&loaded.lock), vec!["default".to_string()]);

        // With no file to name, the diagnostic says where the text came from instead.
        let err = parse("not a lockfile".to_string(), None, "<generated>").unwrap_err();
        assert!(err.to_string().contains("<generated>"), "{err}");
        crate::assert_actionable(&err);
    }

    #[test]
    fn every_error_carries_a_code_and_a_next_step() {
        // Parse wraps the reader's own error, so it is taken from a real failed read.
        let parse = load(Path::new("/definitely/not/here/pixi.lock")).unwrap_err();
        for err in [
            parse,
            LockError::EnvironmentNotFound {
                name: "prod".to_string(),
                available: vec!["default".to_string()],
            },
            LockError::PlatformNotFound {
                platform: "win-64".to_string(),
                environment: "default".to_string(),
                available: vec!["linux-64".to_string()],
            },
            LockError::UnknownCurrentPlatform,
            LockError::Purl(purl::sample_error()),
        ] {
            crate::assert_actionable(&err);
        }
    }

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
            .join("pixi.lock")
    }

    fn root() -> Root {
        Root {
            name: "test".into(),
            version: Some("0.0.1".into()),
            ..Root::default()
        }
    }

    fn select<'a>(environment: &'a str, platform: &'a str) -> Selection<'a> {
        Selection {
            environment,
            platform: Some(platform),
        }
    }

    #[test]
    fn a_lockfile_purl_without_a_version_is_given_the_package_version() {
        // pixi records `purls:` for a conda package as a bare name, because the mapping behind
        // them is name to name. Taking that at face value produced a document whose PyPI
        // identity for the package was `pkg:pypi/click` — a name OSV cannot query — while the
        // version sat two lines away in the same entry (#215).
        let sbom = build_sbom(&fixture("lock-bare-purls"), select("default", "linux-64"), root()).unwrap();
        let find = |name: &str| sbom.packages.iter().find(|p| p.name == name).unwrap();

        assert_eq!(
            find("zlib").extra_purls,
            vec!["pkg:pypi/zlib@1.3.2?source=compressed-mapping"],
            "the bare name is completed from the entry's own version, qualifier kept"
        );
        assert!(find("zlib").purls_from_lock, "it is still the lockfile's answer");

        // One that already states a version is the lockfile being specific, and is not ours to
        // correct — even to the version of the conda package it sits on.
        assert_eq!(find("libzlib").extra_purls, vec!["pkg:pypi/libzlib@9.9.9"]);
    }

    #[test]
    fn an_empty_purls_list_still_means_no_pypi_identity() {
        // `purls: []` is a deliberate statement, not a gap to fill. Nothing to complete here,
        // and nothing may be invented.
        let sbom = build_sbom(&fixture("lock-bare-purls"), select("default", "osx-arm64"), root()).unwrap();
        let zlib = sbom.packages.iter().find(|p| p.name == "zlib").unwrap();
        assert!(zlib.extra_purls.is_empty());
        assert!(zlib.purls_from_lock);
    }

    #[test]
    fn conda_only_lock_yields_binary_packages_with_purls() {
        let sbom = build_sbom(&fixture("conda-only"), select("default", "linux-64"), root()).unwrap();

        assert_eq!(sbom.environment, "default");
        assert_eq!(sbom.platform, "linux-64");
        let names: Vec<_> = sbom.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["libzlib", "zlib"]);

        let zlib = &sbom.packages[1];
        assert_eq!(zlib.kind, PackageKind::CondaBinary);
        assert_eq!(zlib.version.as_deref(), Some("1.3.2"));
        assert_eq!(
            zlib.purl,
            "pkg:conda/zlib@1.3.2?build=h25fd6f3_3&channel=conda-forge&subdir=linux-64&type=conda"
        );
        assert!(zlib.location.ends_with("zlib-1.3.2-h25fd6f3_3.conda"));
        assert_eq!(zlib.sha256.as_deref().map(str::len), Some(64));
        assert_eq!(zlib.md5.as_deref().map(str::len), Some(32));
        assert_eq!(zlib.license.as_deref(), Some("Zlib"));
        assert!(!zlib.purls_from_lock, "conda-only lock has no purls: entries");
        assert_eq!(zlib.properties["pixi:channel"], "conda-forge");
        assert_eq!(zlib.properties["pixi:subdir"], "linux-64");
        assert_eq!(zlib.properties["pixi:build"], "h25fd6f3_3");
        assert_eq!(
            zlib.properties["pixi:channel-url"],
            "https://conda.anaconda.org/conda-forge/"
        );
        assert!(zlib.properties.contains_key("pixi:size"));
        assert_eq!(
            zlib.supplier,
            Some(Supplier {
                name: "conda-forge".into(),
                url: Some("https://conda.anaconda.org/conda-forge/".into()),
            })
        );
    }

    #[test]
    fn conda_dependencies_resolve_to_ids_and_skip_virtual_packages() {
        let sbom = build_sbom(&fixture("conda-only"), select("default", "linux-64"), root()).unwrap();

        let libzlib = &sbom.packages[0];
        let zlib = &sbom.packages[1];
        // libzlib depends only on __glibc (virtual) which must be dropped.
        assert!(libzlib.dependencies.is_empty());
        assert_eq!(zlib.dependencies, vec![libzlib.id.clone()]);
    }

    #[test]
    fn other_platform_is_selectable() {
        let sbom = build_sbom(&fixture("conda-only"), select("default", "osx-arm64"), root()).unwrap();

        assert_eq!(sbom.platform, "osx-arm64");
        assert!(sbom.packages.iter().all(|p| p.properties["pixi:subdir"] == "osx-arm64"));
    }

    #[test]
    fn git_and_path_pypi_packages_claim_no_pypi_release() {
        // #333: the with-pypi lockfile with urllib3 from a git commit and six from a local wheel.
        let text = std::fs::read_to_string(fixture("with-pypi")).unwrap();
        let urllib3 = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("- pypi: ").filter(|u| u.contains("/urllib3-")))
            .unwrap()
            .to_string();
        let six = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("- pypi: ").filter(|u| u.contains("/six-")))
            .unwrap()
            .to_string();
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let text = text
            .replace(
                &urllib3,
                &format!("git+https://github.com/urllib3/urllib3.git?tag=2.8.0#{commit}"),
            )
            .replace(&six, "./vendor/six-1.17.0-py2.py3-none-any.whl");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pixi.lock");
        std::fs::write(&path, text).unwrap();
        let sbom = build_sbom(&path, select("web", "linux-64"), root()).unwrap();
        let find = |name: &str| sbom.packages.iter().find(|p| p.name == name).unwrap();

        let urllib3 = find("urllib3");
        assert_eq!(urllib3.purl, format!("pkg:github/urllib3/urllib3@{commit}"));
        assert_eq!(
            urllib3.properties["pixi:direct-url"],
            "https://github.com/urllib3/urllib3.git"
        );
        assert_eq!(urllib3.properties["pixi:source-rev"], commit);
        let six = find("six");
        assert_eq!(six.purl, "pkg:generic/six@1.17.0");
        assert!(six.properties["pixi:direct-url"].ends_with("six-1.17.0-py2.py3-none-any.whl"));
        let requests = find("requests");
        assert!(
            requests.dependencies.contains(&urllib3.id),
            "edges follow the new identity: {:?}",
            requests.dependencies
        );
        assert!(!requests.properties.contains_key("pixi:direct-url"), "from the index");
    }

    #[test]
    fn pypi_packages_are_converted_and_link_to_conda_and_pypi_deps() {
        let sbom = build_sbom(&fixture("with-pypi"), select("web", "linux-64"), root()).unwrap();

        let pypi: Vec<_> = sbom.packages.iter().filter(|p| p.kind == PackageKind::Pypi).collect();
        let names: Vec<_> = pypi.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"requests"), "{names:?}");
        assert!(names.contains(&"six"), "{names:?}");

        let requests = pypi.iter().find(|p| p.name == "requests").unwrap();
        assert!(requests.purl.starts_with("pkg:pypi/requests@2."));
        assert_eq!(requests.sha256.as_deref().map(str::len), Some(64));
        assert!(requests.location.contains("files.pythonhosted.org"));
        assert!(requests.properties.contains_key("pixi:requires-python"));
        assert_eq!(
            requests.supplier,
            Some(Supplier {
                name: "pypi.org".into(),
                url: Some("https://pypi.org/simple".into()),
            })
        );
        let dep_names: Vec<_> = requests
            .dependencies
            .iter()
            .map(|id| sbom.packages.iter().find(|p| &p.id == id).unwrap().name.as_str())
            .collect();
        for expected in ["charset-normalizer", "idna", "urllib3", "certifi", "python"] {
            assert!(dep_names.contains(&expected), "{expected} missing from {dep_names:?}");
        }
        let python_id = &sbom.packages.iter().find(|p| p.name == "python").unwrap().id;
        assert!(
            pypi.iter().all(|p| p.dependencies.contains(python_id)),
            "every PyPI package depends on the interpreter"
        );
    }

    #[test]
    fn noarch_python_packages_carry_noarch_property_and_python_dependency() {
        let sbom = build_sbom(&fixture("with-pypi"), select("default", "linux-64"), root()).unwrap();

        let python = sbom.packages.iter().find(|p| p.name == "python").unwrap();
        assert_eq!(python.kind, PackageKind::CondaBinary);
        assert!(python.purls_from_lock, "lock states `purls: []` for python");
        assert!(python.dependencies.len() > 3, "python has many runtime deps");
        let noarch: Vec<_> = sbom
            .packages
            .iter()
            .filter(|p| p.properties.contains_key("pixi:noarch"))
            .collect();
        assert!(!noarch.is_empty());
        assert!(noarch.iter().all(|p| p.properties["pixi:subdir"] == "noarch"));
    }

    #[test]
    fn default_environment_excludes_feature_only_packages() {
        let default = build_sbom(&fixture("with-pypi"), select("default", "linux-64"), root()).unwrap();
        let web = build_sbom(&fixture("with-pypi"), select("web", "linux-64"), root()).unwrap();

        assert!(default.packages.iter().all(|p| p.name != "requests"));
        assert!(web.packages.len() > default.packages.len());
    }

    #[test]
    fn packages_are_sorted_deterministically() {
        let sbom = build_sbom(&fixture("with-pypi"), select("web", "linux-64"), root()).unwrap();

        let keys: Vec<_> = sbom.packages.iter().map(Package::sort_key).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        let ids: BTreeSet<_> = sbom.packages.iter().map(|p| &p.id).collect();
        assert_eq!(ids.len(), sbom.packages.len(), "ids are unique");
    }

    #[test]
    fn environment_names_put_default_first_then_alphabetical() {
        let lock = load(&fixture("with-pypi")).unwrap().lock;
        assert_eq!(environment_names(&lock), ["default", "web"]);
        let lock = load(&fixture("multi-env")).unwrap().lock;
        assert_eq!(environment_names(&lock), ["default", "alpha", "zeta"]);
        let lock = load(&fixture("conda-only")).unwrap().lock;
        assert_eq!(environment_names(&lock), ["default"]);
    }

    #[test]
    fn platform_names_are_alphabetical_per_environment() {
        let lock = load(&fixture("conda-only")).unwrap().lock;
        assert_eq!(platform_names(&lock, "default").unwrap(), ["linux-64", "osx-arm64"]);
        let lock = load(&fixture("multi-env")).unwrap().lock;
        assert_eq!(platform_names(&lock, "zeta").unwrap(), ["linux-64"]);
        let err = platform_names(&lock, "nope").unwrap_err();
        assert!(matches!(err, LockError::EnvironmentNotFound { .. }));
    }

    #[test]
    fn unknown_environment_lists_available() {
        let err = build_sbom(&fixture("with-pypi"), select("nope", "linux-64"), root()).unwrap_err();

        let text = err.to_string();
        assert!(text.contains("'nope'"));
        assert!(text.contains("default"));
        assert!(text.contains("web"));
    }

    #[test]
    fn unknown_platform_lists_available() {
        let err = build_sbom(&fixture("conda-only"), select("default", "win-64"), root()).unwrap_err();

        let text = err.to_string();
        assert!(text.contains("'win-64'"));
        assert!(text.contains("linux-64"));
        assert!(text.contains("osx-arm64"));
    }

    #[test]
    fn load_keeps_the_source_text() {
        let path = fixture("conda-only");
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.contents, std::fs::read_to_string(&path).unwrap());
    }

    #[test]
    fn missing_lockfile_is_a_parse_error() {
        let err = load(Path::new("/definitely/not/here/pixi.lock")).unwrap_err();
        assert!(matches!(err, LockError::Parse { .. }));
    }

    #[test]
    fn unparsable_lockfile_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pixi.lock");
        std::fs::write(&path, "version: 7\nthis: [is not a lockfile\n").unwrap();

        let err = build_sbom(&path, select("default", "linux-64"), root()).unwrap_err();
        assert!(matches!(err, LockError::Parse { .. }));
    }

    #[test]
    fn source_packages_use_build_source_for_location() {
        let sbom = build_sbom(&fixture("source-packages"), select("default", "linux-64"), root()).unwrap();
        let find = |name: &str| sbom.packages.iter().find(|p| p.name == name).unwrap();

        let git = find("pixi-tag-package");
        assert_eq!(git.kind, PackageKind::CondaSource);
        assert_eq!(git.version.as_deref(), Some("1.2.0"));
        assert_eq!(
            git.location,
            "git+https://github.com/example/pixi-package.git@def456789012345"
        );
        assert_eq!(
            git.purl,
            "pkg:conda/pixi-tag-package@1.2.0?build=pyhbf21a9e_0&subdir=noarch"
        );
        assert_eq!(git.properties["pixi:source-tag"], "v1.2.0");
        assert_eq!(git.properties["pixi:source-rev"], "def456789012345");
        assert_eq!(git.properties["pixi:identifier-hash"], "8a76ea86");
        assert_eq!(git.license.as_deref(), Some("MIT"));
        assert_eq!(git.supplier, None, "source packages have no supplier");
        assert_eq!(git.dependencies, vec![find("libzlib").id.clone()]);

        let archive = find("archive-package");
        assert_eq!(archive.location, "https://example.com/archive-package-2.0.0.tar.gz");
        assert_eq!(archive.sha256.as_deref().map(str::len), Some(64));
        assert_eq!(
            archive.properties["pixi:source-url"],
            "https://example.com/archive-package-2.0.0.tar.gz"
        );

        let local = find("local-package");
        assert_eq!(local.location, "../local-package");
        assert_eq!(local.properties["pixi:source-path"], "../local-package");
        assert_eq!(
            local.dependencies,
            vec![git.id.clone()],
            "virtual __unix dropped, source dep kept"
        );
    }

    #[test]
    fn partial_source_package_has_no_version_but_keeps_purls() {
        let sbom = build_sbom(&fixture("source-packages"), select("default", "linux-64"), root()).unwrap();
        let partial = sbom.packages.iter().find(|p| p.name == "my-partial-pkg").unwrap();

        assert_eq!(partial.version, None);
        assert_eq!(partial.purl, "pkg:conda/my-partial-pkg");
        assert_eq!(partial.extra_purls, vec!["pkg:pypi/my-partial-pkg@1.0"]);
        assert!(partial.purls_from_lock);
        assert_eq!(partial.license, None);
        assert!(partial.dependencies.is_empty(), "python is not in this environment");
    }

    #[test]
    fn pypi_packages_without_python_in_environment_get_no_extra_edge() {
        // A PyPI package linked in an environment with no conda python.
        let sbom = build_sbom(&fixture("with-pypi"), select("web", "linux-64"), root()).unwrap();
        let mut packages: Vec<Package> = sbom
            .packages
            .iter()
            .filter(|p| p.kind == PackageKind::Pypi)
            .cloned()
            .collect();
        let lock = load(&fixture("with-pypi")).unwrap().lock;
        let read = facts::read(&lock, "web", Some("linux-64")).unwrap();
        let declared: Vec<DeclaredDeps> = packages
            .iter()
            .map(|p| {
                read.packages
                    .iter()
                    .find(|f| f.kind == Kind::Pypi && f.name == p.name)
                    .map(|f| f.declared.clone())
                    .unwrap()
            })
            .collect();
        link_dependencies(&mut packages, &declared);
        assert!(
            packages
                .iter()
                .all(|p| !p.dependencies.iter().any(|d| d.contains("/python@")))
        );
    }

    #[test]
    fn describe_build_source_records_git_branch_and_subdir() {
        let mut properties = BTreeMap::new();
        let source = BuildSource::Git {
            url: "https://example.com/repo.git".into(),
            rev: "abc".into(),
            branch: Some("main".into()),
            tag: None,
            subdir: Some("sub/dir".into()),
        };
        describe_build_source(&source, &mut properties);
        assert_eq!(properties["pixi:source-git"], "https://example.com/repo.git");
        assert_eq!(properties["pixi:source-rev"], "abc");
        assert_eq!(properties["pixi:source-branch"], "main");
        assert_eq!(properties["pixi:source-subdirectory"], "sub/dir");

        let mut properties = BTreeMap::new();
        let source = BuildSource::Git {
            url: "git+ssh://git@example.com/repo.git".into(),
            rev: "abc".into(),
            branch: None,
            tag: Some("v1".into()),
            subdir: None,
        };
        describe_build_source(&source, &mut properties);
        assert!(!properties.contains_key("pixi:source-branch"));
        assert_eq!(properties["pixi:source-tag"], "v1");
    }

    #[test]
    fn local_paths_become_valid_uri_references() {
        assert_eq!(
            local_path_reference("/opt/channel/pkg.conda"),
            "file:///opt/channel/pkg.conda"
        );
        assert_eq!(
            local_path_reference("D:\\a\\channel\\pkg.conda"),
            "file:///D:/a/channel/pkg.conda"
        );
        assert_eq!(
            local_path_reference("C:/channel/pkg.conda"),
            "file:///C:/channel/pkg.conda"
        );
        assert_eq!(local_path_reference("../local-package"), "../local-package");
        assert_eq!(local_path_reference("sub\\dir"), "sub/dir");
    }

    #[test]
    fn host_platform_is_used_when_none_given() {
        let host = rattler_conda_types::Platform::current().unwrap().to_string();
        let selection = Selection {
            environment: "default",
            platform: None,
        };
        let result = build_sbom(&fixture("conda-only"), selection, root());
        match result {
            Ok(sbom) => assert_eq!(sbom.platform, host),
            Err(LockError::PlatformNotFound { platform, .. }) => assert_eq!(platform, host),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
}

/// The lockfile facts, as they were shared with pixi-policy (#58) until the tools moved to repositories of their own.
pub mod facts {
//! The facts of a `pixi.lock`, as the lockfile states them (#58): for one environment and platform, every package's
//! name, version, build, kind, channel or index, location, hashes, license, purl and the dependency edges between
//! them. pixi-sbom builds its SBOM model from these; pixi-policy checks them.
//!
//! Only what the lockfile says: normalizing a license is [`crate::license`]'s job, and enrichment (fetched licenses,
//! the PyPI mapping, CPEs) belongs to the tool that wants it. The manifest is not read here.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use rattler_conda_types::{PackageName, PackageRecord};
use rattler_lock::{
    CondaPackageData, GitShallowSpec, LockFile, LockedPackage, PackageBuildSource, PackageHashes, PypiPackageData,
    UrlOrPath,
};

use crate::purl::core::{self as purl, CondaPurl, PurlError};

/// Why the facts could not be read; each tool reports it in its own words.
#[derive(Debug)]
pub enum ReadError {
    /// The environment is not in the lockfile.
    EnvironmentNotFound { name: String, available: Vec<String> },
    /// The platform is not locked for the environment.
    PlatformNotFound {
        platform: String,
        environment: String,
        available: Vec<String>,
    },
    /// No platform was given and the host's could not be determined.
    UnknownCurrentPlatform,
    /// A package name the purl spec rejects.
    Purl(PurlError),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::EnvironmentNotFound { name, available } => write!(
                f,
                "environment '{name}' not found in lockfile; available: {}",
                available.join(", ")
            ),
            ReadError::PlatformNotFound {
                platform,
                environment,
                available,
            } => write!(
                f,
                "platform '{platform}' is not locked for environment '{environment}'; available: {}",
                available.join(", ")
            ),
            ReadError::UnknownCurrentPlatform => f.write_str("cannot determine the current platform"),
            ReadError::Purl(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for ReadError {}

impl From<PurlError> for ReadError {
    fn from(err: PurlError) -> Self {
        ReadError::Purl(err)
    }
}

/// What kind of package a lockfile entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A prebuilt conda archive from a channel.
    CondaBinary,
    /// A conda package pixi builds from source (pixi-build).
    CondaSource,
    /// A PyPI wheel or source distribution.
    Pypi,
}

/// Where a conda source package is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildSource {
    Git {
        url: String,
        rev: String,
        branch: Option<String>,
        tag: Option<String>,
        subdir: Option<String>,
    },
    Url {
        url: String,
        sha256: String,
        subdir: Option<String>,
    },
    Path {
        path: String,
    },
}

/// The dependency names a package declares, before they are matched to the packages present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Declared {
    /// Conda matchspecs (`libzlib >=1.3`, `__glibc >=2.17`).
    Conda(Vec<String>),
    /// PEP 508 requirement names.
    Pypi(Vec<String>),
}

/// A PyPI requirement as the lockfile records it, for the extras it asks for and the extras that gate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub name: String,
    pub extras: Vec<String>,
    /// The environment marker, as written (`extra == 'socks'`), or empty.
    pub marker: String,
}

/// One package of the selected environment and platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub name: String,
    pub version: Option<String>,
    pub kind: Kind,
    /// `pkg:conda` or `pkg:pypi`.
    pub purl: String,
    /// The other purls the lockfile states for a conda package (pixi's PyPI mapping), each given the
    /// package's version when it had none.
    pub stated_purls: Vec<String>,
    /// Whether the lockfile stated purls at all (an empty list is a statement too).
    pub purls_from_lock: bool,
    /// Where the package comes from: a URL, a `file://` URL or a relative path.
    pub location: String,
    /// Whether the lockfile gave the location as a local path rather than a URL.
    pub location_is_path: bool,
    pub sha256: Option<String>,
    pub md5: Option<String>,
    /// The license as the lockfile records it.
    pub license: Option<String>,
    pub license_family: Option<String>,
    pub build: Option<String>,
    pub build_number: Option<u64>,
    pub size: Option<u64>,
    pub noarch: bool,
    /// The channel's name (`conda-forge`) and base URL.
    pub channel: Option<String>,
    pub channel_url: Option<String>,
    pub subdir: Option<String>,
    pub file_name: Option<String>,
    pub archive_type: Option<String>,
    /// A source package's identifier hash and what it is built from.
    pub identifier_hash: Option<String>,
    pub build_source: Option<BuildSource>,
    /// A PyPI package's index, `Requires-Python`, and whether it is a source distribution.
    pub index_url: Option<String>,
    /// The index URL's host (`pypi.org`), when it has one.
    pub index_host: Option<String>,
    pub requires_python: Option<String>,
    pub sdist: bool,
    pub declared: Declared,
    pub requirements: Vec<Requirement>,
    /// The packages this one depends on, as indices into [`Facts::packages`], ascending.
    pub dependencies: Vec<usize>,
}

/// The packages of one environment and platform, in the lockfile's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub environment: String,
    pub platform: String,
    pub packages: Vec<Fact>,
}

/// Names of every environment in the lockfile: `default` first, the rest alphabetical.
pub fn environment_names(lock: &LockFile) -> Vec<String> {
    let mut names: Vec<String> = lock.environments().map(|(name, _)| name.to_string()).collect();
    names.sort_by_key(|name| (name != "default", name.clone()));
    names
}

/// Names of every platform `environment` is locked for, alphabetical.
pub fn platform_names(lock: &LockFile, environment: &str) -> Result<Vec<String>, ReadError> {
    let environment = lock
        .environment(environment)
        .ok_or_else(|| ReadError::EnvironmentNotFound {
            name: environment.to_string(),
            available: lock.environments().map(|(name, _)| name.to_string()).collect(),
        })?;
    let mut names: Vec<String> = environment.platforms().map(|p| p.name().to_string()).collect();
    names.sort();
    Ok(names)
}

/// The host's platform name, the default when none is asked for.
pub fn current_platform_name() -> Result<String, ReadError> {
    rattler_conda_types::Platform::current()
        .map(|platform| platform.to_string())
        .ok_or(ReadError::UnknownCurrentPlatform)
}

/// The facts of `environment` on `platform` (the host's when `None`).
pub fn read(lock: &LockFile, environment: &str, platform: Option<&str>) -> Result<Facts, ReadError> {
    let env = lock
        .environment(environment)
        .ok_or_else(|| ReadError::EnvironmentNotFound {
            name: environment.to_string(),
            available: lock.environments().map(|(name, _)| name.to_string()).collect(),
        })?;
    let platform_name = match platform {
        Some(name) => name.to_string(),
        None => current_platform_name()?,
    };
    let locked_platform = env
        .platforms()
        .find(|p| p.name().as_str() == platform_name)
        .ok_or_else(|| ReadError::PlatformNotFound {
            platform: platform_name.clone(),
            environment: environment.to_string(),
            available: env.platforms().map(|p| p.name().to_string()).collect(),
        })?;
    let locked: Vec<&LockedPackage> = env.packages(locked_platform).map(Iterator::collect).unwrap_or_default();
    let mut packages = locked
        .iter()
        .map(|package| match package {
            LockedPackage::Conda(conda) => conda_fact(conda),
            LockedPackage::Pypi(pypi) => pypi_fact(pypi),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let entries: Vec<(String, bool)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.kind == Kind::Pypi))
        .collect();
    let declared: Vec<Declared> = packages.iter().map(|p| p.declared.clone()).collect();
    for (package, edges) in packages.iter_mut().zip(link(&entries, &declared)) {
        package.dependencies = edges.into_iter().collect();
    }
    Ok(Facts {
        environment: environment.to_string(),
        platform: platform_name,
        packages,
    })
}

fn conda_fact(conda: &CondaPackageData) -> Result<Fact, ReadError> {
    let name = conda.name().as_source().to_string();
    let location_is_path = matches!(conda.location(), UrlOrPath::Path(_));
    let mut location = location_string(conda.location());
    let record = conda.record();
    let version = record.map(|record| record.version.as_str().into_owned());
    let mut sha256 = record.and_then(|r| r.sha256.as_ref()).map(hex);
    let mut license = record.and_then(|r| r.license.clone());
    let lock_purls = record.and_then(|record| record.purls.as_ref());
    let mut purls_from_lock = lock_purls.is_some();
    let mut stated_purls: Vec<String> = lock_purls
        .map(|purls| purls.iter().map(ToString::to_string).collect())
        .unwrap_or_default();
    let mut fact_channel_url = None;
    let mut file_name = None;
    let mut identifier_hash = None;
    let mut build_source = None;
    let (kind, channel, subdir, archive_type, build) = match conda {
        CondaPackageData::Binary(binary) => {
            let channel_url = binary.channel.as_ref().map(|c| c.url().to_string());
            let channel = channel_url
                .as_deref()
                .and_then(purl::channel_name_from_url)
                .map(str::to_string);
            fact_channel_url = channel_url;
            let name = binary.file_name.to_string();
            let archive_type = purl::archive_type_from_file_name(&name).map(str::to_string);
            file_name = Some(name);
            (
                Kind::CondaBinary,
                channel,
                Some(binary.package_record.subdir.clone()),
                archive_type,
                Some(binary.package_record.build.clone()),
            )
        }
        CondaPackageData::Source(source) => {
            identifier_hash = source.identifier_hash.clone();
            if let Some(partial) = source.metadata.as_partial() {
                license = partial.license.clone();
                purls_from_lock = partial.purls.is_some();
                stated_purls = partial
                    .purls
                    .as_ref()
                    .map(|purls| purls.iter().map(ToString::to_string).collect())
                    .unwrap_or_default();
            }
            if let Some(source) = &source.package_build_source {
                let built = build_source_of(source);
                let (from, hash) = source_location(&built);
                location = from;
                sha256 = hash.or(sha256);
                build_source = Some(built);
            }
            (
                Kind::CondaSource,
                None,
                record.map(|r| r.subdir.clone()),
                None,
                record.map(|r| r.build.clone()).filter(|b| !b.is_empty()),
            )
        }
    };
    if let Some(version) = version.as_deref() {
        for stated in &mut stated_purls {
            if let Some(versioned) = purl::with_version(stated, version) {
                *stated = versioned;
            }
        }
    }
    let purl = purl::conda(CondaPurl {
        name: &name,
        version: version.as_deref(),
        build: build.as_deref(),
        channel: channel.as_deref(),
        subdir: subdir.as_deref(),
        archive_type: archive_type.as_deref(),
    })?;
    let (license_family, build_number, size, noarch) = record_details(record);
    Ok(Fact {
        name,
        version,
        kind,
        purl,
        stated_purls,
        purls_from_lock,
        location,
        location_is_path,
        sha256,
        md5: record.and_then(|r| r.md5.as_ref()).map(hex),
        license,
        license_family,
        build,
        build_number,
        size,
        noarch,
        channel,
        channel_url: fact_channel_url,
        subdir,
        file_name,
        archive_type,
        identifier_hash,
        build_source,
        index_url: None,
        index_host: None,
        requires_python: None,
        sdist: false,
        declared: Declared::Conda(conda.depends().to_vec()),
        requirements: Vec::new(),
        dependencies: Vec::new(),
    })
}

fn record_details(record: Option<&PackageRecord>) -> (Option<String>, Option<u64>, Option<u64>, bool) {
    match record {
        Some(record) => (
            record.license_family.clone(),
            Some(record.build_number),
            record.size,
            !record.noarch.is_none(),
        ),
        None => (None, None, None, false),
    }
}

/// Where a source package is fetched from (a git URL in pip's VCS form, the archive URL, or the path), and the
/// archive's hash when it has one.
fn source_location(source: &BuildSource) -> (String, Option<String>) {
    match source {
        BuildSource::Git { url, rev, subdir, .. } => {
            let scheme = if url.starts_with("git+") { "" } else { "git+" };
            let subpath = subdir.as_ref().map(|s| format!("#{s}")).unwrap_or_default();
            (format!("{scheme}{url}@{rev}{subpath}"), None)
        }
        BuildSource::Url { url, sha256, .. } => (url.clone(), Some(sha256.clone())),
        BuildSource::Path { path } => (path.clone(), None),
    }
}

fn build_source_of(source: &PackageBuildSource) -> BuildSource {
    match source {
        PackageBuildSource::Git { url, spec, rev, subdir } => BuildSource::Git {
            url: url.to_string(),
            rev: rev.clone(),
            branch: match spec {
                Some(GitShallowSpec::Branch(branch)) => Some(branch.clone()),
                _ => None,
            },
            tag: match spec {
                Some(GitShallowSpec::Tag(tag)) => Some(tag.clone()),
                _ => None,
            },
            subdir: subdir.as_ref().map(ToString::to_string),
        },
        PackageBuildSource::Url { url, sha256, subdir } => BuildSource::Url {
            url: url.to_string(),
            sha256: hex(sha256),
            subdir: subdir.as_ref().map(ToString::to_string),
        },
        PackageBuildSource::Path { path } => BuildSource::Path { path: path.to_string() },
    }
}

fn pypi_fact(pypi: &PypiPackageData) -> Result<Fact, ReadError> {
    let name = pypi.name().to_string();
    let version = pypi.version().map(ToString::to_string);
    let purl = purl::pypi(&name, version.as_deref().unwrap_or("0"))?;
    let hashes = pypi.as_wheel().and_then(|wheel| wheel.hash.as_ref());
    let index = pypi.as_wheel().and_then(|wheel| wheel.index_url.as_ref());
    let requirements: Vec<Requirement> = pypi
        .requires_dist()
        .iter()
        .map(|req| Requirement {
            name: req.name.as_ref().to_string(),
            extras: req.extras.iter().map(ToString::to_string).collect(),
            marker: req.marker.try_to_string().unwrap_or_default(),
        })
        .collect();
    Ok(Fact {
        declared: Declared::Pypi(requirements.iter().map(|r| r.name.clone()).collect()),
        requirements,
        name,
        version,
        kind: Kind::Pypi,
        purl,
        stated_purls: Vec::new(),
        purls_from_lock: true,
        location: location_string(pypi.location().inner()),
        location_is_path: matches!(pypi.location().inner(), UrlOrPath::Path(_)),
        sha256: hashes.and_then(PackageHashes::sha256).map(hex),
        md5: hashes.and_then(PackageHashes::md5).map(hex),
        license: None,
        license_family: None,
        build: None,
        build_number: None,
        size: None,
        noarch: false,
        channel: None,
        channel_url: None,
        subdir: None,
        file_name: None,
        archive_type: None,
        identifier_hash: None,
        build_source: None,
        index_url: index.map(ToString::to_string),
        index_host: index.and_then(|url| url.host_str()).map(str::to_string),
        requires_python: pypi.requires_python().map(ToString::to_string),
        sdist: pypi.as_source().is_some(),
        dependencies: Vec::new(),
    })
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// A package location as a valid URI reference: URLs as they are, absolute local paths as
/// `file://` URLs (a Windows path such as `D:\x\y.conda` is not a URI), relative paths with
/// forward slashes.
fn location_string(location: &UrlOrPath) -> String {
    match location {
        UrlOrPath::Url(url) => url.to_string(),
        UrlOrPath::Path(path) => local_path_reference(path.as_ref()),
    }
}

/// A local path as a URI reference: absolute as `file://`, relative with forward slashes.
pub fn local_path_reference(path: &str) -> String {
    let forward = path.replace('\\', "/");
    let drive =
        forward.as_bytes().get(1) == Some(&b':') && forward.as_bytes().first().is_some_and(u8::is_ascii_alphabetic);
    if forward.starts_with('/') {
        format!("file://{forward}")
    } else if drive {
        format!("file:///{forward}")
    } else {
        forward
    }
}

/// Name of the conda package that provides the interpreter every PyPI package runs on.
const PYTHON: &str = "python";

/// Match each package's declared dependencies to the packages present, by index. `entries` is each package's name and
/// whether it is a PyPI package, in the same order as `declared`. Conda names match conda packages; PyPI names match
/// PyPI then conda packages (pixi satisfies PyPI requirements from conda when it can); virtual packages (`__glibc`)
/// are dropped; every PyPI package depends on the environment's conda `python`, which wheels never declare but cannot
/// run without. A package never depends on itself.
pub fn link(entries: &[(String, bool)], declared: &[Declared]) -> Vec<BTreeSet<usize>> {
    let conda: HashMap<String, usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, (_, is_pypi))| !is_pypi)
        .map(|(i, (name, _))| {
            (
                PackageName::new_unchecked(name.to_lowercase())
                    .as_normalized()
                    .to_string(),
                i,
            )
        })
        .collect();
    let pypi: HashMap<String, usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, (_, is_pypi))| *is_pypi)
        .map(|(i, (name, _))| (purl::normalize_pypi_name(name), i))
        .collect();
    declared
        .iter()
        .enumerate()
        .map(|(from, deps)| {
            let edges: BTreeSet<usize> = match deps {
                Declared::Conda(specs) => specs
                    .iter()
                    .map(|spec| PackageName::normalized_name_from_matchspec_str(spec).into_owned())
                    .filter(|dep| !dep.starts_with("__"))
                    .filter_map(|dep| conda.get(&dep).copied())
                    .collect(),
                Declared::Pypi(names) => names
                    .iter()
                    .map(|name| purl::normalize_pypi_name(name))
                    .filter_map(|dep| pypi.get(&dep).or_else(|| conda.get(&dep)).copied())
                    .chain(conda.get(PYTHON).copied())
                    .collect(),
            };
            edges.into_iter().filter(|&to| to != from).collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lockfile(name: &str) -> LockFile {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
            .join("pixi.lock");
        LockFile::from_path(&path).unwrap()
    }

    #[test]
    fn a_lockfile_s_facts_and_their_edges() {
        let lock = lockfile("with-pypi");
        let facts = read(&lock, "default", Some("linux-64")).unwrap();
        assert_eq!(facts.environment, "default");
        assert_eq!(facts.platform, "linux-64");
        assert!(!facts.packages.is_empty());
        let python = facts.packages.iter().position(|p| p.name == "python").unwrap();
        for (i, package) in facts.packages.iter().enumerate() {
            assert!(package.purl.starts_with(match package.kind {
                Kind::Pypi => "pkg:pypi/",
                _ => "pkg:conda/",
            }));
            assert!(!package.dependencies.contains(&i), "{} depends on itself", package.name);
            if package.kind == Kind::Pypi {
                assert!(
                    package.dependencies.contains(&python),
                    "{} runs on python",
                    package.name
                );
            }
        }
        let conda = facts.packages.iter().find(|p| p.kind == Kind::CondaBinary).unwrap();
        assert!(conda.channel.is_some() && conda.subdir.is_some() && conda.file_name.is_some());
        assert!(conda.sha256.is_some());
    }

    #[test]
    fn what_cannot_be_selected_is_an_error() {
        let lock = lockfile("with-pypi");
        assert!(matches!(
            read(&lock, "nope", Some("linux-64")),
            Err(ReadError::EnvironmentNotFound { .. })
        ));
        let err = read(&lock, "default", Some("win-arm64")).unwrap_err();
        assert!(
            err.to_string().starts_with("platform 'win-arm64' is not locked"),
            "{err}"
        );
        assert_eq!(environment_names(&lock)[0], "default");
        assert!(
            platform_names(&lock, "default")
                .unwrap()
                .contains(&"linux-64".to_string())
        );
        assert!(platform_names(&lock, "nope").is_err());
        assert_eq!(
            ReadError::UnknownCurrentPlatform.to_string(),
            "cannot determine the current platform"
        );
    }

    #[test]
    fn linking_drops_virtual_packages_and_self_edges_and_falls_back_to_conda() {
        let entries = vec![
            ("python".to_string(), false),
            ("libzlib".to_string(), false),
            ("Requests".to_string(), true),
            ("urllib3".to_string(), false),
        ];
        let declared = vec![
            Declared::Conda(vec!["libzlib >=1.3".into(), "__glibc >=2.17".into(), "python".into()]),
            Declared::Conda(vec![]),
            Declared::Pypi(vec!["urllib3".into(), "requests".into(), "missing".into()]),
            Declared::Conda(vec![]),
        ];
        let edges = link(&entries, &declared);
        assert_eq!(edges[0], BTreeSet::from([1]));
        assert_eq!(
            edges[2],
            BTreeSet::from([0, 3]),
            "urllib3 from conda, python always, no self-edge"
        );
    }

    #[test]
    fn a_source_package_is_fetched_from_its_build_source() {
        let git = |url: &str, subdir: Option<&str>| BuildSource::Git {
            url: url.into(),
            rev: "abc".into(),
            branch: Some("main".into()),
            tag: None,
            subdir: subdir.map(str::to_string),
        };
        assert_eq!(
            source_location(&git("https://example.com/repo.git", Some("sub/dir"))).0,
            "git+https://example.com/repo.git@abc#sub/dir"
        );
        assert_eq!(
            source_location(&git("git+ssh://git@example.com/repo.git", None)).0,
            "git+ssh://git@example.com/repo.git@abc",
            "an existing git+ prefix is kept"
        );
        let url = BuildSource::Url {
            url: "https://example.com/x.tar.gz".into(),
            sha256: "ab".into(),
            subdir: None,
        };
        assert_eq!(
            source_location(&url),
            ("https://example.com/x.tar.gz".into(), Some("ab".into()))
        );
        assert_eq!(
            source_location(&BuildSource::Path { path: "../pkg".into() }).0,
            "../pkg"
        );
    }

    #[test]
    fn local_paths_become_uri_references() {
        assert_eq!(local_path_reference("/opt/x.conda"), "file:///opt/x.conda");
        assert_eq!(local_path_reference(r"D:\x\y.conda"), "file:///D:/x/y.conda");
        assert_eq!(local_path_reference(r"libs\pkg"), "libs/pkg");
    }
}
}
