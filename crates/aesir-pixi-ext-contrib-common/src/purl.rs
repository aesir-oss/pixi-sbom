//! Package URLs for conda and PyPI packages, as the lockfile facts carry them (#58).
//!
//! Follows the purl spec types `conda` (qualifiers `build`, `channel`, `subdir`, `type`) and `pypi`. Each tool
//! reports a [`PurlError`] in its own words.

use std::fmt;
use std::str::FromStr;

use packageurl::PackageUrl;

/// Failure to build a purl; only happens on names the purl spec rejects.
#[derive(Debug)]
pub struct PurlError {
    /// The package whose purl could not be built.
    pub name: String,
    /// What the purl spec rejected.
    pub source: packageurl::Error,
}

impl fmt::Display for PurlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot build a package URL for {}: {}", self.name, self.source)
    }
}

impl std::error::Error for PurlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Inputs for a conda purl.
#[derive(Debug, Clone, Copy)]
pub struct CondaPurl<'a> {
    /// Package name.
    pub name: &'a str,
    /// Package version, if known.
    pub version: Option<&'a str>,
    /// Build string, if known.
    pub build: Option<&'a str>,
    /// Channel name (e.g. `conda-forge`), if known.
    pub channel: Option<&'a str>,
    /// Subdir (e.g. `linux-64`, `noarch`), if known.
    pub subdir: Option<&'a str>,
    /// Archive type (`conda` or `tar.bz2`), if known.
    pub archive_type: Option<&'a str>,
}

/// Build a `pkg:conda/...` purl.
pub fn conda(input: CondaPurl<'_>) -> Result<String, PurlError> {
    let wrap = |source| PurlError {
        name: input.name.to_string(),
        source,
    };
    let mut purl = PackageUrl::new("conda", input.name).map_err(wrap)?;
    if let Some(version) = input.version {
        purl.with_version(version).map_err(wrap)?;
    }
    for (key, value) in [
        ("build", input.build),
        ("channel", input.channel),
        ("subdir", input.subdir),
        ("type", input.archive_type),
    ] {
        if let Some(value) = value {
            purl.add_qualifier(key, value).map_err(wrap)?;
        }
    }
    Ok(purl.to_string())
}

/// Build a `pkg:pypi/...` purl. The name is lower-cased and `_`/`.` runs are
/// collapsed to `-` per the purl spec.
pub fn pypi(name: &str, version: &str) -> Result<String, PurlError> {
    let wrap = |source| PurlError {
        name: name.to_string(),
        source,
    };
    let normalized = normalize_pypi_name(name);
    let mut purl = PackageUrl::new("pypi", normalized).map_err(wrap)?;
    purl.with_version(version).map_err(wrap)?;
    Ok(purl.to_string())
}

/// Fill a version into a purl that has none, leaving one that already has a version alone.
///
/// pixi records `purls:` for a conda package as a bare name — `pkg:pypi/click?source=...` — with
/// no version, because the mapping it comes from is name to name. A purl without a version is a
/// name, not an identity: OSV has nothing to look up, and a scanner reading the document cannot
/// tell which release is installed. The version is sitting in the same lock entry, so put it in.
///
/// Returns `None` when the string is not a purl we can parse, which leaves the original in place
/// rather than dropping what the lockfile said.
pub fn with_version(purl: &str, version: &str) -> Option<String> {
    let mut parsed = PackageUrl::from_str(purl).ok()?;
    if parsed.version().is_some() {
        return None;
    }
    parsed.with_version(version).ok()?;
    Some(parsed.to_string())
}

/// PEP 503 name normalization: lowercase, runs of `-`, `_`, `.` become a single `-`.
pub fn normalize_pypi_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = false;
    for ch in name.chars() {
        let is_sep = matches!(ch, '-' | '_' | '.');
        if is_sep {
            if !last_dash {
                out.push('-');
            }
            last_dash = true;
        } else {
            out.extend(ch.to_lowercase());
            last_dash = false;
        }
    }
    out
}

/// Derive the channel name used in purls from a channel base URL
/// (`https://conda.anaconda.org/conda-forge/` -> `conda-forge`).
pub fn channel_name_from_url(url: &str) -> Option<&str> {
    url.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
}

/// Archive type qualifier derived from an archive file name.
pub fn archive_type_from_file_name(file_name: &str) -> Option<&'static str> {
    if file_name.ends_with(".conda") {
        Some("conda")
    } else if file_name.ends_with(".tar.bz2") {
        Some("tar.bz2")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conda_and_pypi_purls_and_their_one_failure() {
        let purl = conda(CondaPurl {
            name: "libzlib",
            version: Some("1.3.1"),
            build: Some("h0"),
            channel: Some("conda-forge"),
            subdir: Some("linux-64"),
            archive_type: Some("conda"),
        })
        .unwrap();
        assert_eq!(
            purl,
            "pkg:conda/libzlib@1.3.1?build=h0&channel=conda-forge&subdir=linux-64&type=conda"
        );
        assert_eq!(
            pypi("Typing_Extensions", "4.0").unwrap(),
            "pkg:pypi/typing-extensions@4.0"
        );
        let err = conda(CondaPurl {
            name: "",
            version: None,
            build: None,
            channel: None,
            subdir: None,
            archive_type: None,
        })
        .unwrap_err();
        assert!(err.to_string().starts_with("cannot build a package URL for :"), "{err}");
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn helpers() {
        assert_eq!(normalize_pypi_name("Foo__Bar.baz"), "foo-bar-baz");
        assert_eq!(
            channel_name_from_url("https://conda.anaconda.org/conda-forge/"),
            Some("conda-forge")
        );
        assert_eq!(channel_name_from_url("/"), None);
        assert_eq!(archive_type_from_file_name("x-1-0.tar.bz2"), Some("tar.bz2"));
        assert_eq!(archive_type_from_file_name("x.whl"), None);
        assert_eq!(
            with_version("pkg:pypi/click?source=x", "8.0").as_deref(),
            Some("pkg:pypi/click@8.0?source=x")
        );
        assert_eq!(with_version("pkg:pypi/click@8.0", "9.0"), None);
        assert_eq!(with_version("not a purl", "1"), None);
    }
}
