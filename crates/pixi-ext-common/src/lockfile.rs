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

use crate::purl::{self, CondaPurl, PurlError};

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
            .join("../pixi-sbom/tests/fixtures")
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
