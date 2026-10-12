//! JavaScript lockfiles (#29): `package-lock.json` (v2, v3), `yarn.lock` (v1 and Berry) and
//! `pnpm-lock.yaml` (v6+), read as inputs of their own the way `uv.lock` is.
//!
//! Each format is read into one shape: the workspace members (the project at the lockfile's
//! directory and any `workspaces`), each with what it declares as dependencies, development
//! dependencies and optional dependencies, and the locked packages with the edges between them.
//! Locked packages are `pkg:npm` components; members other than the project itself are
//! first-party, with a `pkg:generic` purl, since a `pkg:npm` purl would claim a release on the
//! registry. Development and optional scopes come from what each member declares, followed
//! through the graph. A yarn lockfile records neither the members nor which dependencies are for
//! development, so those come from the `package.json` files beside it; without them, the document
//! has the packages and edges but no scopes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use miette::Diagnostic;
use serde::Deserialize;
use thiserror::Error;

use crate::model::{Package, PackageKind, Root, Sbom};
use crate::purl;
use crate::scope::{self, Scope};

/// The JavaScript lockfiles, in the order one directory prefers them.
pub const LOCKFILE_NAMES: [&str; 3] = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"];

/// Whether a path names a JavaScript lockfile this module reads, or a project's installed
/// `node_modules`, which stands for one when there is none (#36).
pub fn is_js_lock_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| LOCKFILE_NAMES.contains(&n) || n == crate::jsinstalled::DIR_NAME)
}

/// The JavaScript lockfile in `dir`, if there is one, in [`LOCKFILE_NAMES`] order.
pub fn lockfile_in(dir: &Path) -> Option<std::path::PathBuf> {
    LOCKFILE_NAMES.iter().map(|n| dir.join(n)).find(|p| p.is_file())
}

/// Errors from reading a JavaScript lockfile.
#[derive(Debug, Error, Diagnostic)]
pub enum JsLockError {
    /// The file could not be read.
    #[error("cannot read {path}")]
    #[diagnostic(code(pixi_sbom::jslock::read))]
    Read {
        /// The lockfile.
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// The file is not a lockfile of the kind its name says.
    #[error("{path} is not a valid {kind}")]
    #[diagnostic(code(pixi_sbom::jslock::parse), help("{message}"))]
    Parse {
        /// The lockfile.
        path: String,
        /// What its name says it is.
        kind: &'static str,
        /// What the parser said.
        message: String,
    },

    /// A lockfile version this reader does not understand.
    #[error("{kind} version {found} is not supported")]
    #[diagnostic(
        code(pixi_sbom::jslock::version),
        help("pixi-sbom reads {supported}; rewrite the lockfile with a current version of the tool that wrote it")
    )]
    Version {
        /// The lockfile kind.
        kind: &'static str,
        /// The version the file declares.
        found: String,
        /// What is supported.
        supported: &'static str,
    },

    /// A package name the purl spec rejects.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Purl(#[from] purl::PurlError),
}

/// A workspace member: the project at the lockfile's directory (`path` `.`) or one of its
/// workspaces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Member {
    /// Its directory, relative to the lockfile's, with `/` separators.
    pub path: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub license: Option<String>,
    /// What it depends on, as node keys, with the kind of dependency it declared.
    pub dependencies: Vec<(String, Scope)>,
}

/// One locked package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub version: String,
    /// Where the tarball comes from, when the lockfile says.
    pub resolved: Option<String>,
    /// The Subresource Integrity string (`sha512-<base64>`), when the lockfile records one.
    pub integrity: Option<String>,
    pub license: Option<String>,
    /// What it depends on, as node keys.
    pub dependencies: Vec<String>,
}

/// A JavaScript lockfile in the shape the document is built from. Node keys are the format's own
/// (a `node_modules` path, a yarn descriptor, a pnpm `name@version`); a key starting with
/// `workspace:` names the member at that path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JsLock {
    /// What wrote it: `package-lock.json v3`, `yarn.lock v1`, ...
    pub kind: String,
    pub members: Vec<Member>,
    pub nodes: BTreeMap<String, Node>,
    /// Whether the members' declarations say which dependencies are for development: always for
    /// npm and pnpm, only with the `package.json` files for yarn.
    pub scoped: bool,
}

/// A parsed lockfile, with the text it was parsed from.
#[derive(Debug)]
pub struct Loaded {
    pub lock: JsLock,
    pub contents: String,
}

pub(crate) const MEMBER: &str = "workspace:";

/// Read and parse the lockfile at `path`, with the `package.json` files beside it; or, for a
/// project's `node_modules`, the installed tree.
pub fn load(path: &Path) -> Result<Loaded, JsLockError> {
    if crate::jsinstalled::is_installed_tree(path) {
        return crate::jsinstalled::read(path);
    }
    let contents = std::fs::read_to_string(path).map_err(|source| JsLockError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let origin = path.display().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let lock = match name {
        "package-lock.json" => package_lock(&contents, &origin)?,
        "pnpm-lock.yaml" => pnpm(&contents, &origin, dir)?,
        _ => yarn(&contents, &origin, dir)?,
    };
    Ok(Loaded { lock, contents })
}

/// The fields of a `package.json` this reads.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageJson {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub license: Option<serde_json::Value>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub repository: Option<serde_json::Value>,
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub dev_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub peer_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub workspaces: Option<serde_json::Value>,
}

impl PackageJson {
    /// What it declares, by name, with the scope each is declared in. A name declared twice
    /// counts as its least scope: a runtime dependency also listed for development is required.
    pub(crate) fn declared(&self) -> BTreeMap<String, (String, Scope)> {
        let mut out = BTreeMap::new();
        for (map, scope) in [
            (&self.dev_dependencies, Scope::Development),
            (&self.optional_dependencies, Scope::Optional),
            (&self.peer_dependencies, Scope::Required),
            (&self.dependencies, Scope::Required),
        ] {
            for (name, range) in map {
                out.insert(name.clone(), (range.clone(), scope));
            }
        }
        out
    }

    pub(crate) fn license_text(&self) -> Option<String> {
        match &self.license {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(serde_json::Value::Object(o)) => o.get("type").and_then(|t| t.as_str()).map(str::to_string),
            _ => None,
        }
    }

    /// The `workspaces` globs, in either spelling (`["packages/*"]` or `{"packages": [...]}`).
    pub(crate) fn workspace_globs(&self) -> Vec<String> {
        let list = match &self.workspaces {
            Some(serde_json::Value::Array(a)) => a.clone(),
            Some(serde_json::Value::Object(o)) => o
                .get("packages")
                .and_then(|p| p.as_array())
                .cloned()
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        list.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
    }
}

/// The `package.json` at `relative` under `dir`, if there is a readable one.
fn manifest(dir: &Path, relative: &str) -> Option<PackageJson> {
    let text = std::fs::read_to_string(dir.join(relative).join("package.json")).ok()?;
    serde_json::from_str(&text).ok()
}

/// The member directories a `workspaces` list names: literal paths, and `dir/*` globs expanded
/// one level, the form npm, yarn and pnpm projects use.
pub(crate) fn expand_workspaces(dir: &Path, globs: &[String]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for glob in globs {
        let glob = glob.trim_end_matches('/').trim_start_matches("./");
        match glob.strip_suffix("/*") {
            Some(parent) if !parent.contains('*') => {
                let Ok(entries) = std::fs::read_dir(dir.join(parent)) else {
                    continue;
                };
                for entry in entries.flatten() {
                    if entry.path().join("package.json").is_file() {
                        out.insert(format!("{parent}/{}", entry.file_name().to_string_lossy()));
                    }
                }
            }
            _ if !glob.contains('*') => {
                out.insert(glob.to_string());
            }
            _ => tracing::warn!(glob, "workspace pattern not followed; only `dir/*` and plain paths are"),
        }
    }
    out.into_iter().collect()
}

// ---- package-lock.json ------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NpmLock {
    lockfile_version: serde_json::Value,
    #[serde(default)]
    packages: BTreeMap<String, NpmEntry>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NpmEntry {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    resolved: Option<String>,
    #[serde(default)]
    integrity: Option<String>,
    #[serde(default)]
    license: Option<serde_json::Value>,
    #[serde(default)]
    link: bool,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default)]
    dev_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    peer_dependencies: BTreeMap<String, String>,
}

/// The package Node would load for `name` from code at `from`: `from/node_modules/name`, then
/// each enclosing `node_modules` outward.
fn node_resolve(entries: &BTreeMap<String, NpmEntry>, from: &str, name: &str) -> Option<String> {
    let mut base = from.to_string();
    loop {
        let candidate = if base.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{base}/node_modules/{name}")
        };
        if entries.contains_key(&candidate) {
            return Some(candidate);
        }
        if base.is_empty() {
            return None;
        }
        // `a/node_modules/b` -> `a`; `packages/util` -> ``.
        base = match base.rfind("/node_modules/") {
            Some(at) => base[..at].to_string(),
            None => String::new(),
        };
    }
}

fn package_lock(contents: &str, origin: &str) -> Result<JsLock, JsLockError> {
    const KIND: &str = "package-lock.json";
    let lock: NpmLock = serde_json::from_str(contents).map_err(|err| JsLockError::Parse {
        path: origin.to_string(),
        kind: KIND,
        message: err.to_string(),
    })?;
    let version = lock.lockfile_version.as_u64().unwrap_or(0);
    if !(2..=3).contains(&version) {
        return Err(JsLockError::Version {
            kind: KIND,
            found: lock.lockfile_version.to_string(),
            supported: "lockfileVersion 2 and 3 (npm 7 and later)",
        });
    }
    let entries = lock.packages;
    // A `link` entry points at the member it stands for.
    let target = |key: &str| -> String {
        match entries.get(key) {
            Some(entry) if entry.link => format!("{MEMBER}{}", entry.resolved.as_deref().unwrap_or_default()),
            _ => key.to_string(),
        }
    };
    let mut out = JsLock {
        kind: format!("{KIND} v{version}"),
        scoped: true,
        ..JsLock::default()
    };
    for (key, entry) in &entries {
        let is_member = key.is_empty() || !key.contains("node_modules/");
        if entry.link {
            continue;
        }
        let declared: Vec<(&String, Scope)> = entry
            .dev_dependencies
            .keys()
            .map(|n| (n, Scope::Development))
            .chain(entry.optional_dependencies.keys().map(|n| (n, Scope::Optional)))
            .chain(entry.peer_dependencies.keys().map(|n| (n, Scope::Required)))
            .chain(entry.dependencies.keys().map(|n| (n, Scope::Required)))
            .collect();
        if is_member {
            let mut dependencies: BTreeMap<String, Scope> = BTreeMap::new();
            for (name, scope) in declared {
                if let Some(found) = node_resolve(&entries, key, name) {
                    dependencies.insert(target(&found), scope);
                }
            }
            out.members.push(Member {
                path: if key.is_empty() { ".".into() } else { key.clone() },
                name: entry.name.clone(),
                version: entry.version.clone(),
                license: license_of(&entry.license),
                dependencies: dependencies.into_iter().collect(),
            });
            continue;
        }
        let name = entry.name.clone().unwrap_or_else(|| {
            key.rsplit_once("node_modules/")
                .map_or(key.as_str(), |(_, n)| n)
                .to_string()
        });
        let mut dependencies: Vec<String> = declared
            .iter()
            .filter(|(_, scope)| *scope != Scope::Development)
            .filter_map(|(dep, _)| node_resolve(&entries, key, dep).map(|k| target(&k)))
            .collect();
        dependencies.sort();
        dependencies.dedup();
        out.nodes.insert(
            key.clone(),
            Node {
                name,
                version: entry.version.clone().unwrap_or_default(),
                resolved: entry.resolved.clone(),
                integrity: entry.integrity.clone(),
                license: license_of(&entry.license),
                dependencies,
            },
        );
    }
    // Member keys are their paths; `.` is the root's.
    for member in &mut out.members {
        for (key, _) in &mut member.dependencies {
            if let Some(path) = key.strip_prefix(MEMBER) {
                *key = format!("{MEMBER}{}", if path.is_empty() { "." } else { path });
            }
        }
    }
    Ok(out)
}

fn license_of(value: &Option<serde_json::Value>) -> Option<String> {
    match value {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        Some(serde_json::Value::Object(o)) => o.get("type").and_then(|t| t.as_str()).map(str::to_string),
        _ => None,
    }
}

// ---- yarn.lock --------------------------------------------------------------------------------

/// A descriptor's package name: `@scope/name@^1` -> `@scope/name`, `name@npm:^1` -> `name`.
fn descriptor_name(descriptor: &str) -> &str {
    let start = usize::from(descriptor.starts_with('@'));
    match descriptor[start..].find('@') {
        Some(at) => &descriptor[..start + at],
        None => descriptor,
    }
}

/// One entry of a yarn lockfile, whichever version wrote it.
struct YarnEntry {
    descriptors: Vec<String>,
    version: String,
    resolved: Option<String>,
    integrity: Option<String>,
    /// What it depends on: name and range as the entry writes them.
    dependencies: Vec<(String, String)>,
    /// The workspace path, for a Berry `workspace:` entry.
    workspace: Option<String>,
}

fn unquote(text: &str) -> &str {
    text.trim().trim_matches('"')
}

/// yarn v1's own format: unindented descriptor lines ending in `:`, two-space fields
/// (`version "1.2.3"`), and four-space entries under `dependencies:`.
fn yarn_v1_entries(contents: &str) -> Vec<YarnEntry> {
    let mut entries: Vec<YarnEntry> = Vec::new();
    let mut section = "";
    for line in contents.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let text = line.trim();
        if indent == 0 {
            let head = text.trim_end_matches(':');
            entries.push(YarnEntry {
                descriptors: head.split(", ").map(|d| unquote(d).to_string()).collect(),
                version: String::new(),
                resolved: None,
                integrity: None,
                dependencies: Vec::new(),
                workspace: None,
            });
            section = "";
            continue;
        }
        let Some(entry) = entries.last_mut() else { continue };
        if indent == 2 {
            if let Some(name) = text.strip_suffix(':') {
                section = if matches!(name, "dependencies" | "optionalDependencies") {
                    "dependencies"
                } else {
                    "other"
                };
                continue;
            }
            section = "";
            let (key, value) = text.split_once(' ').unwrap_or((text, ""));
            match key {
                "version" => entry.version = unquote(value).to_string(),
                "resolved" => entry.resolved = Some(unquote(value).to_string()),
                "integrity" => entry.integrity = Some(unquote(value).to_string()),
                _ => {}
            }
        } else if section == "dependencies"
            && let Some((name, range)) = split_dependency(text)
        {
            entry.dependencies.push((name, range));
        }
    }
    entries
}

/// `"@scope/name" "^1.0"` or `name "^1.0"` as a name and a range.
fn split_dependency(text: &str) -> Option<(String, String)> {
    let (name, range) = if let Some(rest) = text.strip_prefix('"') {
        let end = rest.find('"')?;
        (&rest[..end], &rest[end + 1..])
    } else {
        text.split_once(' ')?
    };
    Some((name.to_string(), unquote(range).to_string()))
}

#[derive(Deserialize)]
struct BerryEntry {
    #[serde(default)]
    version: Option<serde_yaml::Value>,
    #[serde(default)]
    resolution: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, String>,
}

fn yarn_berry_entries(contents: &str, origin: &str) -> Result<Vec<YarnEntry>, JsLockError> {
    let raw: BTreeMap<String, serde_yaml::Value> =
        serde_yaml::from_str(contents).map_err(|err| JsLockError::Parse {
            path: origin.to_string(),
            kind: "yarn.lock",
            message: err.to_string(),
        })?;
    let mut entries = Vec::new();
    for (key, value) in raw {
        if key == "__metadata" {
            continue;
        }
        let Ok(entry) = serde_yaml::from_value::<BerryEntry>(value) else {
            continue;
        };
        let resolution = entry.resolution.unwrap_or_default();
        let version = match entry.version {
            Some(serde_yaml::Value::String(s)) => s,
            Some(serde_yaml::Value::Number(n)) => n.to_string(),
            _ => String::new(),
        };
        let workspace = resolution.split_once("@workspace:").map(|(_, path)| path.to_string());
        entries.push(YarnEntry {
            descriptors: key.split(", ").map(|d| d.trim().to_string()).collect(),
            version,
            resolved: None,
            integrity: None,
            dependencies: entry
                .dependencies
                .into_iter()
                .chain(entry.optional_dependencies)
                .collect(),
            workspace,
        });
    }
    Ok(entries)
}

fn yarn(contents: &str, origin: &str, dir: &Path) -> Result<JsLock, JsLockError> {
    let manifest = |path: &str| manifest(dir, path);
    let berry = contents.lines().any(|l| l.starts_with("__metadata:"));
    let entries = if berry {
        yarn_berry_entries(contents, origin)?
    } else if contents.contains("# yarn lockfile v1") {
        yarn_v1_entries(contents)
    } else {
        return Err(JsLockError::Version {
            kind: "yarn.lock",
            found: "unknown".into(),
            supported: "yarn.lock v1 (yarn 1) and the Berry format (yarn 2 and later)",
        });
    };
    // Every descriptor an entry answers for points at it; in Berry, a bare `npm:` range is also
    // written without its protocol in a `package.json`.
    let mut by_descriptor: HashMap<String, String> = HashMap::new();
    let mut out = JsLock {
        kind: if berry {
            "yarn.lock (Berry)".into()
        } else {
            "yarn.lock v1".into()
        },
        ..JsLock::default()
    };
    for entry in &entries {
        let key = match &entry.workspace {
            Some(path) => format!("{MEMBER}{path}"),
            None => entry.descriptors[0].clone(),
        };
        for descriptor in &entry.descriptors {
            by_descriptor.insert(descriptor.clone(), key.clone());
            if let Some((name, range)) = descriptor.rsplit_once("@npm:").filter(|(n, _)| !n.is_empty()) {
                by_descriptor
                    .entry(format!("{name}@{range}"))
                    .or_insert_with(|| key.clone());
            }
        }
    }
    let lookup = |name: &str, range: &str| -> Option<String> {
        by_descriptor
            .get(&format!("{name}@{range}"))
            .or_else(|| by_descriptor.get(&format!("{name}@npm:{range}")))
            .cloned()
    };
    // Members: Berry's workspace entries, or the `package.json` files for v1.
    let root = manifest(".");
    let mut member_paths: Vec<String> = entries.iter().filter_map(|e| e.workspace.clone()).collect();
    if member_paths.is_empty() && root.is_some() {
        member_paths.push(".".into());
        let globs = root.as_ref().map(PackageJson::workspace_globs).unwrap_or_default();
        member_paths.extend(expand_workspaces(dir, &globs));
    }
    member_paths.sort();
    member_paths.dedup();
    let by_name: HashMap<String, String> = member_paths
        .iter()
        .filter_map(|p| manifest(p).and_then(|m| m.name).map(|n| (n, format!("{MEMBER}{p}"))))
        .collect();
    out.scoped = root.is_some();
    for path in &member_paths {
        let declared = manifest(path).unwrap_or_default();
        let entry = entries.iter().find(|e| e.workspace.as_deref() == Some(path.as_str()));
        let mut dependencies: BTreeMap<String, Scope> = BTreeMap::new();
        if out.scoped {
            for (name, (range, scope)) in declared.declared() {
                let key = by_name
                    .get(&name)
                    .cloned()
                    .or_else(|| lookup(&name, &range))
                    .or_else(|| {
                        // Berry rewrites a member's ranges into the lockfile's own spelling.
                        entry
                            .and_then(|e| e.dependencies.iter().find(|(n, _)| *n == name))
                            .and_then(|(n, r)| lookup(n, r))
                    });
                if let Some(key) = key {
                    dependencies.insert(key, scope);
                }
            }
        } else if let Some(entry) = entry {
            for (name, range) in &entry.dependencies {
                if let Some(key) = lookup(name, range) {
                    dependencies.insert(key, Scope::Required);
                }
            }
        }
        out.members.push(Member {
            path: path.clone(),
            name: declared
                .name
                .clone()
                .or_else(|| entry.map(|e| descriptor_name(&e.descriptors[0]).to_string())),
            version: declared.version.clone(),
            license: declared.license_text(),
            dependencies: dependencies.into_iter().collect(),
        });
    }
    for entry in entries.iter().filter(|e| e.workspace.is_none()) {
        let mut dependencies: Vec<String> = entry
            .dependencies
            .iter()
            .filter_map(|(name, range)| by_name.get(name).cloned().or_else(|| lookup(name, range)))
            .collect();
        dependencies.sort();
        dependencies.dedup();
        let resolved = entry
            .resolved
            .as_deref()
            .map(|r| r.split_once('#').map_or(r, |(url, _)| url).to_string());
        out.nodes.insert(
            entry.descriptors[0].clone(),
            Node {
                name: descriptor_name(&entry.descriptors[0]).to_string(),
                version: entry.version.clone(),
                resolved,
                integrity: entry.integrity.clone(),
                license: None,
                dependencies,
            },
        );
    }
    Ok(out)
}

// ---- pnpm-lock.yaml ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PnpmLock {
    lockfile_version: serde_yaml::Value,
    #[serde(default)]
    importers: BTreeMap<String, PnpmImporter>,
    #[serde(default)]
    packages: BTreeMap<String, PnpmPackage>,
    #[serde(default)]
    snapshots: BTreeMap<String, PnpmPackage>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PnpmImporter {
    #[serde(default)]
    dependencies: BTreeMap<String, PnpmSpec>,
    #[serde(default)]
    dev_dependencies: BTreeMap<String, PnpmSpec>,
    #[serde(default)]
    optional_dependencies: BTreeMap<String, PnpmSpec>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PnpmSpec {
    Full { version: String },
    Bare(String),
}

impl PnpmSpec {
    fn version(&self) -> &str {
        match self {
            PnpmSpec::Full { version } | PnpmSpec::Bare(version) => version,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PnpmPackage {
    #[serde(default)]
    resolution: Option<PnpmResolution>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default)]
    optional_dependencies: BTreeMap<String, String>,
}

#[derive(Deserialize, Default)]
struct PnpmResolution {
    #[serde(default)]
    integrity: Option<String>,
    #[serde(default)]
    tarball: Option<String>,
}

/// A pnpm package key without its leading `/` (v6) or peer suffix: `/debug@4.3.4(supports-color@8)`
/// -> `debug@4.3.4`.
fn pnpm_key(key: &str) -> String {
    let key = key.strip_prefix('/').unwrap_or(key);
    key.split_once('(').map_or(key, |(k, _)| k).to_string()
}

/// The key a dependency's version points at: `link:../util` is a member, `1.2.3(peer)` is
/// `name@1.2.3`, and an alias (`npm:other@1.0.0`, or v6's `/other@1.0.0`) is the aliased package.
fn pnpm_target(importer: &str, name: &str, version: &str) -> String {
    if let Some(path) = version.strip_prefix("link:") {
        return format!("{MEMBER}{}", join_relative(importer, path));
    }
    let version = version.split_once('(').map_or(version, |(v, _)| v);
    if let Some(alias) = version.strip_prefix("npm:") {
        return alias.to_string();
    }
    if let Some(alias) = version.strip_prefix('/') {
        return alias.to_string();
    }
    format!("{name}@{version}")
}

/// `importer` joined with a relative `path`, normalized: `packages/app` + `../util` -> `packages/util`.
fn join_relative(importer: &str, path: &str) -> String {
    let mut parts: Vec<&str> = importer.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() { ".".into() } else { parts.join("/") }
}

fn pnpm(contents: &str, origin: &str, dir: &Path) -> Result<JsLock, JsLockError> {
    let manifest = |path: &str| manifest(dir, path);
    const KIND: &str = "pnpm-lock.yaml";
    let lock: PnpmLock = serde_yaml::from_str(contents).map_err(|err| JsLockError::Parse {
        path: origin.to_string(),
        kind: KIND,
        message: err.to_string(),
    })?;
    let version = match &lock.lockfile_version {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    let major: u32 = version.split('.').next().and_then(|m| m.parse().ok()).unwrap_or(0);
    if major < 6 {
        return Err(JsLockError::Version {
            kind: KIND,
            found: version,
            supported: "lockfileVersion 6 and later (pnpm 8 and later)",
        });
    }
    let mut out = JsLock {
        kind: format!("{KIND} v{version}"),
        scoped: true,
        ..JsLock::default()
    };
    for (path, importer) in &lock.importers {
        let declared = manifest(path).unwrap_or_default();
        let mut dependencies: BTreeMap<String, Scope> = BTreeMap::new();
        for (map, scope) in [
            (&importer.dev_dependencies, Scope::Development),
            (&importer.optional_dependencies, Scope::Optional),
            (&importer.dependencies, Scope::Required),
        ] {
            for (name, spec) in map {
                dependencies.insert(pnpm_target(path, name, spec.version()), scope);
            }
        }
        out.members.push(Member {
            path: path.clone(),
            name: declared.name.clone(),
            version: declared.version.clone(),
            license: declared.license_text(),
            dependencies: dependencies.into_iter().collect(),
        });
    }
    // v9 keeps the edges in `snapshots` (one per peer combination), v6 in `packages`.
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let graph = if lock.snapshots.is_empty() {
        &lock.packages
    } else {
        &lock.snapshots
    };
    for (key, package) in graph {
        let targets = edges.entry(pnpm_key(key)).or_default();
        for (name, version) in package.dependencies.iter().chain(&package.optional_dependencies) {
            targets.insert(pnpm_target(".", name, version));
        }
    }
    for (key, package) in &lock.packages {
        let key = pnpm_key(key);
        let (name, version) = match (&package.name, &package.version) {
            (Some(name), Some(version)) => (name.clone(), version.clone()),
            _ => {
                let at = key.rfind('@').filter(|&at| at > 0).unwrap_or(key.len());
                (key[..at].to_string(), key.get(at + 1..).unwrap_or_default().to_string())
            }
        };
        let resolution = package.resolution.as_ref();
        out.nodes.insert(
            key.clone(),
            Node {
                name,
                version,
                resolved: resolution.and_then(|r| r.tarball.clone()),
                integrity: resolution.and_then(|r| r.integrity.clone()),
                license: None,
                dependencies: edges.remove(&key).unwrap_or_default().into_iter().collect(),
            },
        );
    }
    Ok(out)
}

// ---- the document -----------------------------------------------------------------------------

/// A Subresource Integrity `sha512-<base64>` value as hex, the spelling the SBOM formats use.
pub fn sha512_hex(integrity: &str) -> Option<String> {
    let encoded = integrity
        .split_whitespace()
        .find_map(|part| part.strip_prefix("sha512-"))?;
    let bytes = base64_decode(encoded)?;
    (bytes.len() == 64).then(|| bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32)
    };
    let clean: Vec<u8> = text.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= value(c)? << (18 - 6 * i);
        }
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    Some(out)
}

/// The JavaScript project's own description, from the root member, for the document's root.
pub fn root_of(lock: &JsLock, dir: &Path, mut root: Root) -> Root {
    let manifest = manifest(dir, ".");
    if let Some(member) = lock.members.iter().find(|m| m.path == ".") {
        if root.name.is_empty()
            && let Some(name) = &member.name
        {
            root.name = name.clone();
        }
        root.version = root.version.or_else(|| member.version.clone());
        root.license = root.license.or_else(|| member.license.clone());
    }
    if let Some(manifest) = manifest {
        root.homepage = root.homepage.or(manifest.homepage);
        root.repository = root.repository.or_else(|| match manifest.repository {
            Some(serde_json::Value::String(s)) => Some(s),
            Some(serde_json::Value::Object(o)) => o.get("url").and_then(|u| u.as_str()).map(str::to_string),
            _ => None,
        });
    }
    root
}

/// The packages, the ids the root depends on, and the scopes, for `lock`.
pub fn packages(lock: &JsLock) -> Result<(Vec<Package>, BTreeMap<String, Scope>), JsLockError> {
    // Each node and member key, to the id of the component it is: one component per release.
    let mut ids: HashMap<String, String> = HashMap::new();
    let mut packages: BTreeMap<String, Package> = BTreeMap::new();
    for (key, node) in &lock.nodes {
        let id = purl::npm(&node.name, &node.version)?;
        ids.insert(key.clone(), id.clone());
        let package = packages.entry(id.clone()).or_insert_with(|| {
            package(
                id.clone(),
                &node.name,
                &node.version,
                PackageKind::External,
                node.license.clone(),
            )
        });
        if package.location.is_empty()
            && let Some(resolved) = &node.resolved
        {
            package.location = resolved.clone();
        }
        if package.sha512.is_none() {
            package.sha512 = node.integrity.as_deref().and_then(sha512_hex);
        }
    }
    for member in lock.members.iter().filter(|m| m.path != ".") {
        let name = member.name.clone().unwrap_or_else(|| member.path.clone());
        let version = member.version.clone().unwrap_or_else(|| "0.0.0".into());
        let id = purl::generic_js(&name, &version)?;
        ids.insert(format!("{MEMBER}{}", member.path), id.clone());
        let mut package = package(
            id.clone(),
            &name,
            &version,
            PackageKind::External,
            member.license.clone(),
        );
        package
            .properties
            .insert("pixi:source-path".into(), format!("./{}", member.path));
        packages.insert(id, package);
    }
    let resolve = |key: &str| ids.get(key).cloned();
    for (key, node) in &lock.nodes {
        let id = &ids[key];
        let deps: Vec<String> = node
            .dependencies
            .iter()
            .filter_map(|k| resolve(k))
            .filter(|d| d != id)
            .collect();
        let package = packages.get_mut(id).expect("every node has a package");
        package.dependencies.extend(deps);
    }
    let mut required = BTreeSet::new();
    let mut optional = BTreeSet::new();
    let mut development = BTreeSet::new();
    for member in &lock.members {
        let own = (member.path != ".").then(|| ids[&format!("{MEMBER}{}", member.path)].clone());
        if let Some(own) = &own {
            packages
                .get_mut(own)
                .expect("members have packages")
                .properties
                .insert(crate::manifest::DIRECT_PROPERTY.into(), "true".into());
        }
        for (key, scope) in &member.dependencies {
            let Some(id) = resolve(key) else { continue };
            match own.as_ref() {
                Some(own) => {
                    let deps = &mut packages.get_mut(own).expect("members have packages").dependencies;
                    deps.push(id.clone());
                }
                None => {
                    packages
                        .get_mut(&id)
                        .expect("resolved ids have packages")
                        .properties
                        .insert(crate::manifest::DIRECT_PROPERTY.into(), "true".into());
                }
            }
            match scope {
                Scope::Required => required.insert(id),
                Scope::Optional => optional.insert(id),
                Scope::Development => development.insert(id),
            };
        }
    }
    let mut packages: Vec<Package> = packages.into_values().collect();
    for package in &mut packages {
        package.dependencies.sort();
        package.dependencies.dedup();
    }
    packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    let scopes = if lock.scoped {
        scope::assign(&packages, &required, &optional, &development)
    } else {
        BTreeMap::new()
    };
    Ok((packages, scopes))
}

fn package(id: String, name: &str, version: &str, kind: PackageKind, license: Option<String>) -> Package {
    Package {
        purl: id.clone(),
        id,
        name: name.to_string(),
        version: Some(version.to_string()),
        kind,
        supplier: None,
        extra_purls: Vec::new(),
        // The lockfile is the authority on what was resolved.
        purls_from_lock: true,
        location: String::new(),
        sha256: None,
        md5: None,
        sha512: None,
        license,
        license_files: Vec::new(),
        description: None,
        homepage: None,
        repository: None,
        documentation: None,
        yanked: None,
        properties: BTreeMap::new(),
        dependencies: Vec::new(),
        occurrences: Vec::new(),
    }
}

/// The document for a JavaScript lockfile. JavaScript packages are the same on every platform, so
/// the platform is `noarch` unless one is asked for.
pub fn build_sbom(lock: &JsLock, platform: Option<&str>, root: Root, lockfile_name: &str) -> Result<Sbom, JsLockError> {
    let (packages, scopes) = packages(lock)?;
    tracing::info!(kind = %lock.kind, packages = packages.len(), "read JavaScript lockfile");
    Ok(Sbom {
        root,
        environment: "default".to_string(),
        platform: platform.unwrap_or("noarch").to_string(),
        lockfile: lockfile_name.to_string(),
        prefix: None,
        document: None,
        packages,
        vulnerabilities: Vec::new(),
        excluded: Vec::new(),
        declared_missing: Vec::new(),
        incomplete: crate::model::Incomplete::default(),
        lifecycles: vec![crate::model::PHASE_LOCKFILE.into()],
        declared_roots: true,
        scopes,
        interpreter: None,
    })
}

/// Add a JavaScript lockfile's packages to another input's document (#42): its
/// project's direct dependencies and workspaces become direct dependencies of the document's root.
pub fn merge_into(sbom: &mut Sbom, lock: &JsLock) -> Result<usize, JsLockError> {
    let (packages, scopes) = packages(lock)?;
    let known: BTreeSet<String> = sbom.packages.iter().map(|p| p.id.clone()).collect();
    let mut added = 0;
    for package in packages {
        if known.contains(&package.id) {
            continue;
        }
        sbom.packages.push(package);
        added += 1;
    }
    for (id, scope) in scopes {
        sbom.scopes.entry(id).or_insert(scope);
    }
    sbom.packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(dir: &str, file: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/js")
            .join(dir)
            .join(file)
    }

    const FIXTURES: [(&str, &str, &str); 6] = [
        ("npm-v2", "package-lock.json", "package-lock.json v2"),
        ("npm-v3", "package-lock.json", "package-lock.json v3"),
        ("yarn-v1", "yarn.lock", "yarn.lock v1"),
        ("yarn-berry", "yarn.lock", "yarn.lock (Berry)"),
        ("pnpm-v6", "pnpm-lock.yaml", "pnpm-lock.yaml v6.0"),
        ("pnpm-v9", "pnpm-lock.yaml", "pnpm-lock.yaml v9.0"),
    ];

    #[test]
    fn every_format_describes_the_same_project() {
        for (dir, file, kind) in FIXTURES {
            let path = fixture(dir, file);
            assert!(is_js_lock_name(&path));
            let Loaded { lock, contents } = load(&path).unwrap_or_else(|e| panic!("{dir}: {e}"));
            assert!(!contents.is_empty());
            assert_eq!(lock.kind, kind);
            let sbom = build_sbom(
                &lock,
                None,
                root_of(&lock, path.parent().unwrap(), Root::default()),
                file,
            )
            .unwrap();
            assert_eq!(sbom.platform, "noarch");
            assert_eq!(sbom.root.name, "js-demo", "{dir}");
            assert_eq!(sbom.root.version.as_deref(), Some("1.0.0"), "{dir}");
            assert_eq!(sbom.root.license.as_deref(), Some("MIT"), "{dir}");
            let ids: Vec<&str> = sbom.packages.iter().map(|p| p.id.as_str()).collect();
            assert_eq!(
                ids,
                [
                    "pkg:generic/%40demo/util@0.1.0",
                    "pkg:npm/%40sindresorhus/is@4.6.0",
                    "pkg:npm/debug@4.3.4",
                    "pkg:npm/is-number@7.0.0",
                    "pkg:npm/ms@2.1.2",
                    "pkg:npm/ms@2.1.3",
                ],
                "{dir}"
            );
            let find = |id: &str| sbom.packages.iter().find(|p| p.id == id).unwrap();
            // debug keeps its own, older ms; the workspace member uses the project's.
            assert_eq!(find("pkg:npm/debug@4.3.4").dependencies, ["pkg:npm/ms@2.1.2"], "{dir}");
            let util = find("pkg:generic/%40demo/util@0.1.0");
            assert_eq!(util.dependencies, ["pkg:npm/ms@2.1.3"], "{dir}");
            assert_eq!(util.properties["pixi:source-path"], "./packages/util");
            let direct: Vec<&str> = sbom
                .packages
                .iter()
                .filter(|p| p.properties.contains_key(crate::manifest::DIRECT_PROPERTY))
                .map(|p| p.name.as_str())
                .collect();
            assert_eq!(
                direct,
                ["@demo/util", "@sindresorhus/is", "debug", "is-number", "ms"],
                "{dir}"
            );
            assert_eq!(
                sbom.scopes.get("pkg:npm/is-number@7.0.0"),
                Some(&Scope::Development),
                "{dir}"
            );
            assert_eq!(sbom.scopes.get("pkg:npm/ms@2.1.2"), Some(&Scope::Required), "{dir}");
            assert_eq!(
                sbom.scopes.get("pkg:npm/ms@2.1.3"),
                Some(&Scope::Required),
                "{dir}: optional for the project, required by the workspace member"
            );
            let debug = find("pkg:npm/debug@4.3.4");
            if dir.starts_with("yarn-berry") {
                assert_eq!(
                    debug.sha512, None,
                    "Berry records its own checksum, not npm's integrity"
                );
            } else {
                assert_eq!(
                    debug.sha512.as_deref().map(|h| &h[..16]),
                    Some("3d15851ee494dde0"),
                    "{dir}"
                );
            }
            match dir {
                "npm-v2" | "npm-v3" => {
                    assert_eq!(debug.location, "https://registry.npmjs.org/debug/-/debug-4.3.4.tgz");
                    assert_eq!(debug.license.as_deref(), Some("MIT"));
                }
                "yarn-v1" => assert_eq!(debug.location, "https://registry.yarnpkg.com/debug/-/debug-4.3.4.tgz"),
                _ => assert_eq!(debug.location, "", "{dir} records no URL"),
            }
        }
    }

    #[test]
    fn a_yarn_lock_without_its_package_json_has_no_scopes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(fixture("yarn-v1", "yarn.lock"), dir.path().join("yarn.lock")).unwrap();
        let Loaded { lock, .. } = load(&dir.path().join("yarn.lock")).unwrap();
        assert!(!lock.scoped);
        assert!(lock.members.is_empty());
        let sbom = build_sbom(&lock, Some("linux-64"), Root::default(), "yarn.lock").unwrap();
        assert_eq!(sbom.platform, "linux-64");
        assert!(sbom.scopes.is_empty());
        assert_eq!(sbom.packages.len(), 5);
    }

    #[test]
    fn unsupported_versions_and_broken_files_say_so() {
        let dir = tempfile::tempdir().unwrap();
        for (file, text, wanted) in [
            (
                "package-lock.json",
                r#"{"lockfileVersion": 1, "dependencies": {}}"#,
                "version 1 is not supported",
            ),
            ("package-lock.json", "{not json", "is not a valid package-lock.json"),
            (
                "pnpm-lock.yaml",
                "lockfileVersion: '5.4'\n",
                "version 5.4 is not supported",
            ),
            (
                "pnpm-lock.yaml",
                "lockfileVersion: [\n",
                "is not a valid pnpm-lock.yaml",
            ),
            (
                "yarn.lock",
                "something else entirely\n",
                "yarn.lock version unknown is not supported",
            ),
            ("yarn.lock", "__metadata:\n  version: [\n", "is not a valid yarn.lock"),
        ] {
            let path = dir.path().join(file);
            std::fs::write(&path, text).unwrap();
            let err = load(&path).unwrap_err();
            assert!(err.to_string().contains(wanted), "{file}: {err}");
            crate::assert_actionable(&err);
        }
        let missing = load(&dir.path().join("missing/package-lock.json")).unwrap_err();
        assert!(missing.to_string().starts_with("cannot read"));
    }

    #[test]
    fn integrity_is_written_as_hex_and_odd_values_are_left_out() {
        let hex = sha512_hex(
            "sha512-PRWFHuSU3eDtQJPvnNY7Jcket1j0t5OuOsFzPPzsekD52Zl8qUfFIPEiswXqIvHWGVHOgX+7G/vCNNhehwxfkQ==",
        )
        .unwrap();
        assert_eq!(hex.len(), 128);
        assert!(hex.starts_with("3d15851ee494dde0"));
        assert_eq!(sha512_hex("sha1-abc"), None);
        assert_eq!(sha512_hex("sha512-not*base64"), None);
        assert_eq!(sha512_hex("sha512-AAAA"), None, "too short for a SHA-512");
    }

    #[test]
    fn small_spellings() {
        assert_eq!(descriptor_name("@scope/name@npm:^1.0"), "@scope/name");
        assert_eq!(descriptor_name("name@^1"), "name");
        assert_eq!(descriptor_name("bare"), "bare");
        assert_eq!(pnpm_key("/debug@4.3.4(supports-color@8.1.1)"), "debug@4.3.4");
        assert_eq!(
            pnpm_target("packages/app", "util", "link:../util"),
            "workspace:packages/util"
        );
        assert_eq!(pnpm_target(".", "x", "npm:other@1.0.0"), "other@1.0.0");
        assert_eq!(pnpm_target(".", "x", "/other@1.0.0"), "other@1.0.0");
        assert_eq!(pnpm_target(".", "ms", "2.1.3(peer@1)"), "ms@2.1.3");
        assert_eq!(join_relative(".", "./packages/a"), "packages/a");
        assert_eq!(join_relative("a", ".."), ".");
        assert_eq!(
            split_dependency(r#""@a/b" "^1.0""#),
            Some(("@a/b".into(), "^1.0".into()))
        );
        assert_eq!(split_dependency("ms \"2.1.2\""), Some(("ms".into(), "2.1.2".into())));
        assert_eq!(split_dependency("\"unterminated"), None);
        assert!(lockfile_in(&fixture("npm-v3", "")).is_some());
        assert!(lockfile_in(Path::new("/nonexistent")).is_none());
    }

    #[test]
    fn merged_into_another_document_the_project_s_dependencies_are_direct() {
        let Loaded { lock, .. } = load(&fixture("pnpm-v9", "pnpm-lock.yaml")).unwrap();
        let mut sbom = build_sbom(&lock, None, Root::default(), "pnpm-lock.yaml").unwrap();
        let before = sbom.packages.len();
        sbom.packages.retain(|p| p.name != "debug");
        sbom.scopes.clear();
        let added = merge_into(&mut sbom, &lock).unwrap();
        assert_eq!(added, 1, "only what was not there yet");
        assert_eq!(sbom.packages.len(), before);
        assert_eq!(sbom.scopes.get("pkg:npm/is-number@7.0.0"), Some(&Scope::Development));
    }
}
