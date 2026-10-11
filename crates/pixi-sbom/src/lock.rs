//! Converts one environment/platform of a `pixi.lock` into the [`Sbom`] model.
//!
//! Reading the lockfile is the shared crate's (`common::lockfile`, #58): what each package is, as the lockfile states
//! it, and the edges between packages. This module turns those facts into the SBOM model: the `pixi:*` properties,
//! suppliers, the PyPI source identities and the extras each package was asked for.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use common::lockfile::{self as facts, BuildSource, Fact, Kind, ReadError};
use miette::Diagnostic;
use rattler_lock::LockFile;
use thiserror::Error;

use crate::model::{Package, PackageKind, Root, Sbom, Supplier};
use crate::purl;

/// The dependency names one package declares, before they are matched to packages present in the same environment.
pub(crate) use common::lockfile::Declared as DeclaredDeps;
pub(crate) use common::lockfile::local_path_reference;

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
            && common::license::is_rewritten(raw)
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
/// `common::lockfile::link` does, giving each package its edges as sorted ids, never its own.
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
