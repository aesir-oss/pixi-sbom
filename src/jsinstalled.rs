//! A JavaScript project's installed `node_modules`, read when the project has no lockfile (#36).
//!
//! The installed tree is read into the shape [`crate::jslock`] reads a lockfile into, so the
//! document, the join into a pixi workspace's document and `--skip-input javascript` work as for
//! a lockfile. The members are the project's `package.json` and its workspaces (`workspaces` in
//! `package.json`, or `pnpm-workspace.yaml`); each declared dependency, and each installed
//! package's own dependencies, are found the way Node finds them: `node_modules/<name>` beside the
//! code, then in every enclosing directory. That one rule covers npm's and yarn's nested and
//! hoisted layouts and pnpm's `.pnpm` store, whose packages see their dependencies as links beside
//! them. Links are followed only inside the project: an `npm link` to elsewhere is not read.
//! Development scope comes from the members' `devDependencies`, followed through the graph as for
//! a lockfile. A package installed but reached by nothing is still a component, with no scope.
//! Yarn Plug'n'Play has no `node_modules` and is not read.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};

use crate::jslock::{JsLock, JsLockError, Loaded, MEMBER, Member, Node, PackageJson};

/// What stands for the lockfile of a project that has none: its `node_modules` directory.
pub const DIR_NAME: &str = "node_modules";

/// The installed tree to read in `dir`: its `node_modules`, when there is a `package.json` beside it.
pub fn in_dir(dir: &Path) -> Option<PathBuf> {
    let tree = dir.join(DIR_NAME);
    (dir.join("package.json").is_file() && tree.is_dir()).then_some(tree)
}

/// Whether `path` names an installed tree rather than a lockfile.
pub fn is_installed_tree(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == DIR_NAME)
}

/// The layout that wrote the tree, for the document's `kind`.
fn layout(tree: &Path) -> &'static str {
    if tree.join(".pnpm").is_dir() {
        "pnpm"
    } else if tree.join(".yarn-integrity").is_file() || tree.join(".yarn-state.yml").is_file() {
        "yarn"
    } else if tree.join(".package-lock.json").is_file() {
        "npm"
    } else {
        "unknown tool"
    }
}

struct Reader {
    /// The project directory, canonical.
    root: PathBuf,
    /// Each member's canonical directory, to its path relative to the project.
    members: HashMap<PathBuf, String>,
    nodes: BTreeMap<String, Node>,
    queue: VecDeque<PathBuf>,
}

impl Reader {
    /// Where Node finds `name` from code in `from`: `node_modules/<name>` in `from` and in each
    /// enclosing directory up to the project, never inside a `node_modules` directory itself.
    fn locate(&self, from: &Path, name: &str) -> Option<PathBuf> {
        for ancestor in from.ancestors() {
            if ancestor.file_name().is_some_and(|n| n == DIR_NAME) {
                continue;
            }
            let candidate = ancestor.join(DIR_NAME).join(name);
            if candidate.join("package.json").is_file() {
                let real = candidate.canonicalize().ok()?;
                return real.starts_with(&self.root).then_some(real);
            }
            if ancestor == self.root {
                break;
            }
        }
        None
    }

    /// The key a package or member is known by: a member's `workspace:<path>`, a package's path
    /// relative to the project.
    fn key(&self, real: &Path) -> String {
        match self.members.get(real) {
            Some(path) => format!("{MEMBER}{path}"),
            None => relative(&self.root, real),
        }
    }

    fn enqueue(&mut self, real: PathBuf) {
        if !self.members.contains_key(&real) {
            self.queue.push_back(real);
        }
    }

    /// Read every queued package, and whatever it depends on.
    fn drain(&mut self) {
        while let Some(real) = self.queue.pop_front() {
            let key = self.key(&real);
            if self.nodes.contains_key(&key) {
                continue;
            }
            let Some(manifest) = read_manifest(&real) else { continue };
            let (Some(name), Some(version)) = (manifest.name.clone(), manifest.version.clone()) else {
                continue;
            };
            let mut dependencies = Vec::new();
            let declared = manifest
                .dependencies
                .keys()
                .chain(manifest.optional_dependencies.keys())
                .chain(manifest.peer_dependencies.keys());
            for dependency in declared {
                if let Some(target) = self.locate(&real, dependency) {
                    dependencies.push(self.key(&target));
                    self.enqueue(target);
                }
            }
            dependencies.sort();
            dependencies.dedup();
            dependencies.retain(|d| *d != key);
            self.nodes.insert(
                key,
                Node {
                    name,
                    version,
                    resolved: None,
                    integrity: None,
                    license: manifest.license_text(),
                    dependencies,
                },
            );
        }
    }
}

fn read_manifest(dir: &Path) -> Option<PackageJson> {
    serde_json::from_str(&std::fs::read_to_string(dir.join("package.json")).ok()?).ok()
}

/// `real` relative to `root`, with `/` separators.
fn relative(root: &Path, real: &Path) -> String {
    real.strip_prefix(root)
        .unwrap_or(real)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Every package directory installed under the `node_modules` directory `tree`, canonical: scoped
/// ones, nested `node_modules`, and pnpm's `.pnpm` store. A link is resolved, never walked into.
fn installed(tree: &Path, root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(tree) else { return };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if name == ".pnpm" {
            for store in std::fs::read_dir(&path).into_iter().flatten().flatten() {
                if store.file_name() != DIR_NAME {
                    installed(&store.path().join(DIR_NAME), root, out);
                }
            }
        } else if name.starts_with('.') {
            continue;
        } else if name.starts_with('@') {
            installed_scope(&path, root, out);
        } else {
            package(&path, root, out);
        }
    }
}

fn installed_scope(scope: &Path, root: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(scope).into_iter().flatten().flatten() {
        package(&entry.path(), root, out);
    }
}

fn package(path: &Path, root: &Path, out: &mut Vec<PathBuf>) {
    if !path.join("package.json").is_file() {
        return;
    }
    let Ok(real) = path.canonicalize() else { return };
    if !real.starts_with(root) {
        return;
    }
    out.push(real);
    // Nested copies, but only in a real directory: a link's target is reached on its own.
    if !path.is_symlink() {
        installed(&path.join(DIR_NAME), root, out);
    }
}

/// The workspaces `pnpm-workspace.yaml` lists, for a pnpm project.
fn pnpm_workspace_globs(dir: &Path) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct Workspace {
        #[serde(default)]
        packages: Vec<String>,
    }
    std::fs::read_to_string(dir.join("pnpm-workspace.yaml"))
        .ok()
        .and_then(|text| crate::yaml::from_str::<Workspace>(&text).ok())
        .map(|w| w.packages.into_iter().filter(|p| !p.starts_with('!')).collect())
        .unwrap_or_default()
}

/// Read the installed tree at `tree` (a project's `node_modules`) into the lockfile shape.
pub fn read(tree: &Path) -> Result<Loaded, JsLockError> {
    let dir = tree.parent().unwrap_or(Path::new("."));
    let origin = tree.display().to_string();
    let root = dir.canonicalize().map_err(|source| JsLockError::Read {
        path: origin.clone(),
        source,
    })?;
    let manifest = read_manifest(dir).ok_or_else(|| JsLockError::Parse {
        path: dir.join("package.json").display().to_string(),
        kind: "package.json",
        message:
            "an installed node_modules is read from the package.json beside it, which is missing or not valid JSON"
                .to_string(),
    })?;
    let mut globs = manifest.workspace_globs();
    globs.extend(pnpm_workspace_globs(dir));
    let mut paths = vec![".".to_string()];
    paths.extend(crate::jslock::expand_workspaces(dir, &globs));
    let mut reader = Reader {
        members: paths
            .iter()
            .filter_map(|path| Some((dir.join(path).canonicalize().ok()?, path.clone())))
            .collect(),
        root,
        nodes: BTreeMap::new(),
        queue: VecDeque::new(),
    };
    let mut members = Vec::new();
    for path in &paths {
        let member_dir = dir.join(path);
        let Some(declared) = read_manifest(&member_dir) else {
            continue;
        };
        let Ok(real) = member_dir.canonicalize() else { continue };
        let mut dependencies = BTreeMap::new();
        for (name, (_, scope)) in declared.declared() {
            if let Some(target) = reader.locate(&real, &name) {
                dependencies.insert(reader.key(&target), scope);
                reader.enqueue(target);
            }
        }
        members.push(Member {
            path: path.clone(),
            name: declared.name.clone(),
            version: declared.version.clone(),
            license: declared.license_text(),
            dependencies: dependencies.into_iter().collect(),
        });
    }
    reader.drain();
    // What is installed but reached by nothing is installed all the same.
    let mut everything = Vec::new();
    for path in &paths {
        installed(&dir.join(path).join(DIR_NAME), &reader.root, &mut everything);
    }
    for real in everything {
        reader.enqueue(real);
    }
    reader.drain();
    let contents = reader
        .nodes
        .iter()
        .map(|(key, node)| format!("{key} {}", node.version))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Loaded {
        lock: JsLock {
            kind: format!("node_modules ({})", layout(tree)),
            members,
            nodes: reader.nodes,
            scoped: true,
        },
        contents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::Scope;

    fn fixture(tool: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/node-modules")
            .join(tool)
            .join(DIR_NAME)
    }

    /// The releases a tree holds, as `name@version`, and what the project declares with its scope.
    fn summary(lock: &JsLock) -> (Vec<String>, Vec<(String, Scope)>) {
        let mut releases: Vec<String> = lock
            .nodes
            .values()
            .map(|n| format!("{}@{}", n.name, n.version))
            .collect();
        releases.sort();
        releases.dedup();
        let root = lock.members.iter().find(|m| m.path == ".").unwrap();
        let mut declared: Vec<(String, Scope)> = root
            .dependencies
            .iter()
            .map(|(key, scope)| (lock.nodes[key].name.clone(), *scope))
            .collect();
        declared.sort();
        (releases, declared)
    }

    #[test]
    fn npm_and_yarn_trees_read_as_their_lockfile_does() {
        let npm = read(&fixture("npm")).unwrap().lock;
        assert_eq!(npm.kind, "node_modules (npm)");
        let (releases, declared) = summary(&npm);
        assert_eq!(releases.len(), 29);
        assert!(releases.contains(&"lodash@4.17.15".to_string()));
        assert!(declared.contains(&("semver".to_string(), Scope::Development)));
        assert!(declared.contains(&("axios".to_string(), Scope::Required)));
        // The same edges as the lockfile records: axios needs follow-redirects.
        let axios = npm.nodes.values().find(|n| n.name == "axios").unwrap();
        assert_eq!(axios.dependencies, ["node_modules/follow-redirects"]);

        let yarn = read(&fixture("yarn")).unwrap().lock;
        assert_eq!(yarn.kind, "node_modules (yarn)");
        assert_eq!(summary(&yarn), summary(&npm));
    }

    #[cfg(unix)]
    #[test]
    fn pnpm_s_store_is_read_through_its_links() {
        let npm = read(&fixture("npm")).unwrap().lock;
        let pnpm = read(&fixture("pnpm")).unwrap().lock;
        assert_eq!(pnpm.kind, "node_modules (pnpm)");
        assert_eq!(summary(&pnpm), summary(&npm));
        // Keyed by where the package really is, in the store.
        assert!(
            pnpm.nodes
                .contains_key("node_modules/.pnpm/lodash@4.17.15/node_modules/lodash")
        );
    }

    #[test]
    fn what_nothing_reaches_is_installed_all_the_same_and_a_package_without_a_version_is_not_one() {
        let dir = tempfile::tempdir().unwrap();
        let write = |path: &str, json: &str| {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, json).unwrap();
        };
        write("package.json", r#"{"name":"app","dependencies":{"a":"1"}}"#);
        write(
            "node_modules/a/package.json",
            r#"{"name":"a","version":"1.0.0","dependencies":{"b":"2"}}"#,
        );
        // Nested: a's own copy of b wins over the hoisted one.
        write(
            "node_modules/a/node_modules/b/package.json",
            r#"{"name":"b","version":"2.0.0"}"#,
        );
        write("node_modules/b/package.json", r#"{"name":"b","version":"1.0.0"}"#);
        write(
            "node_modules/@scope/left-over/package.json",
            r#"{"name":"@scope/left-over","version":"0.1.0"}"#,
        );
        write("node_modules/no-version/package.json", r#"{"name":"no-version"}"#);
        let lock = read(&dir.path().join(DIR_NAME)).unwrap().lock;
        assert_eq!(lock.kind, "node_modules (unknown tool)");
        assert_eq!(
            lock.nodes["node_modules/a"].dependencies,
            ["node_modules/a/node_modules/b"]
        );
        let keys: Vec<&str> = lock.nodes.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "node_modules/@scope/left-over",
                "node_modules/a",
                "node_modules/a/node_modules/b",
                "node_modules/b"
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_link_out_of_the_project_is_not_followed_and_a_workspace_link_is_its_member() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("package.json"),
            r#"{"name":"linked","version":"9.9.9"}"#,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let write = |path: &str, json: &str| {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, json).unwrap();
        };
        write(
            "package.json",
            r#"{"name":"app","workspaces":["packages/*"],"dependencies":{"linked":"*","util":"*"}}"#,
        );
        write("packages/util/package.json", r#"{"name":"util","version":"0.1.0"}"#);
        std::fs::create_dir_all(dir.path().join(DIR_NAME)).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("node_modules/linked")).unwrap();
        std::os::unix::fs::symlink("../packages/util", dir.path().join("node_modules/util")).unwrap();
        let lock = read(&dir.path().join(DIR_NAME)).unwrap().lock;
        assert!(lock.nodes.is_empty(), "{:?}", lock.nodes);
        let root = lock.members.iter().find(|m| m.path == ".").unwrap();
        assert_eq!(
            root.dependencies,
            [("workspace:packages/util".to_string(), Scope::Required)]
        );
    }

    #[test]
    fn a_tree_is_found_only_with_a_package_json_beside_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(DIR_NAME)).unwrap();
        assert_eq!(in_dir(dir.path()), None);
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        assert_eq!(in_dir(dir.path()), Some(dir.path().join(DIR_NAME)));
        assert!(is_installed_tree(&dir.path().join(DIR_NAME)));
        let err = read(&tempfile::tempdir().unwrap().path().join(DIR_NAME)).unwrap_err();
        assert!(matches!(err, JsLockError::Parse { .. }), "{err}");
    }
}
