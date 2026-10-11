//! Locating the lockfile and resolving the output path.

use std::path::{Path, PathBuf};

use miette::Diagnostic;
use thiserror::Error;

use crate::cli::{Format, SkipInput};

/// Name of the lockfile pixi writes next to its manifest.
pub const LOCKFILE_NAME: &str = "pixi.lock";

/// The lockfiles the upward search and `--scan` look for, in the order they prefer them within one
/// directory: `pixi.lock` first, as the most complete (a pixi workspace that also has a `uv.lock`
/// is a pixi workspace), then the Python lockfiles, then conda-lock, then the JavaScript lockfiles. `pylock.toml` also stands
/// for its named form, `pylock.<name>.toml`. An explicit conda spec file has no fixed name, so it
/// is only ever read through `--lockfile`.
pub const LOCKFILE_KINDS: [&str; 9] = [
    LOCKFILE_NAME,
    "uv.lock",
    "pylock.toml",
    "poetry.lock",
    "pdm.lock",
    "conda-lock.yml",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
];

/// [`LOCKFILE_KINDS`] for a message: `pixi.lock, uv.lock, ... or conda-lock.yml`.
const KINDS_TEXT: &str = "pixi.lock, uv.lock, pylock.toml, poetry.lock, pdm.lock, conda-lock.yml, package-lock.json, pnpm-lock.yaml or yarn.lock";

/// The lockfiles of [`LOCKFILE_KINDS`] in `dir`, in that order; named `pylock.<name>.toml` files
/// follow `pylock.toml`, sorted.
fn lockfiles_in(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for kind in LOCKFILE_KINDS {
        let path = dir.join(kind);
        if path.is_file() {
            found.push(path);
        }
        if kind == "pylock.toml" {
            let mut named: Vec<PathBuf> = std::fs::read_dir(dir)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file() && crate::pylock::is_pylock_name(p) && p.file_name() != Some(kind.as_ref()))
                .collect();
            named.sort();
            found.extend(named);
        }
    }
    found
}

/// Whether `--skip-input` leaves `lockfile` out.
pub fn is_skipped(lockfile: &Path, skip: &[SkipInput]) -> bool {
    let name = lockfile_name(lockfile);
    skip.iter().any(|input| input.covers(&name))
}

/// The lockfile a run reads in `dir`: the first conda or Python one in [`LOCKFILE_KINDS`] order
/// that `skip` leaves in, or a JavaScript one when there is none. Logs what was read, what joins
/// it and what was left out when there was more than one.
pub fn lockfile_in(dir: &Path, skip: &[SkipInput]) -> Option<PathBuf> {
    let found = lockfiles_in(dir);
    let (kept, skipped): (Vec<&PathBuf>, Vec<&PathBuf>) = found.iter().partition(|p| !is_skipped(p, skip));
    let chosen = kept
        .iter()
        .find(|p| !crate::jslock::is_js_lock_name(p))
        .or_else(|| kept.first())
        .map(|p| (*p).clone())?;
    let javascript = javascript_in(dir, &chosen, skip);
    if found.len() > 1 {
        let not_read: Vec<String> = kept
            .iter()
            .filter(|p| ***p != chosen && Some(**p) != javascript.as_ref())
            .map(|p| lockfile_name(p))
            .collect();
        let skipped: Vec<String> = skipped.iter().map(|p| lockfile_name(p)).collect();
        tracing::info!(
            dir = %dir.display(),
            reading = %lockfile_name(&chosen),
            joined_by = %javascript.as_deref().map(lockfile_name).unwrap_or_default(),
            not_read = %not_read.join(", "),
            skipped = %skipped.join(", "),
            "several lockfiles in one directory; reading one per ecosystem, the first in the order {KINDS_TEXT} \
             (--skip-input leaves one out, --lockfile reads one alone)"
        );
    }
    Some(chosen)
}

/// The JavaScript lockfile that joins `lockfile`'s document: the first in `dir` that `skip`
/// leaves in, unless `lockfile` is itself a JavaScript one.
pub fn javascript_in(dir: &Path, lockfile: &Path, skip: &[SkipInput]) -> Option<PathBuf> {
    if crate::jslock::is_js_lock_name(lockfile) {
        return None;
    }
    crate::jslock::LOCKFILE_NAMES
        .iter()
        .map(|name| dir.join(name))
        .find(|p| p.is_file() && !is_skipped(p, skip))
}

/// The names of the lockfiles in `dir` that `skip` leaves out, for a message.
fn skipped_in(dir: &Path, skip: &[SkipInput]) -> String {
    lockfiles_in(dir)
        .iter()
        .filter(|p| is_skipped(p, skip))
        .map(|p| lockfile_name(p))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Errors raised while locating input and output files.
#[derive(Debug, Error, Diagnostic)]
pub enum DiscoverError {
    /// No lockfile found walking up from the start directory.
    #[error("no {KINDS_TEXT} found in {start} or any parent directory")]
    #[diagnostic(
        code(pixi_sbom::discover::not_found),
        help(
            "{hint}write one with your project's tool (`pixi lock`, `uv lock`, `poetry lock`, `pdm lock`, `pip lock`, \
             `conda-lock`), or pass --lockfile with the path to one; an explicit conda spec file or a pinned requirements.txt is \
             only read that way"
        )
    )]
    NotFound {
        /// Directory the search started from.
        start: PathBuf,
        /// The nearest manifest that had no lockfile beside it, and how to lock it, as a sentence
        /// ending in a space; empty when there was none.
        hint: String,
    },

    /// The lockfile path given on the command line does not exist.
    #[error("lockfile {path} does not exist")]
    #[diagnostic(
        code(pixi_sbom::discover::missing),
        help("check the path --lockfile was given, or run `pixi lock` in that workspace to write it")
    )]
    Missing {
        /// The path that was checked.
        path: PathBuf,
    },

    /// `--scan` was pointed at something that is not a directory.
    #[error("{path} is not a directory")]
    #[diagnostic(code(pixi_sbom::discover::not_a_directory), help("--scan takes a directory to walk"))]
    NotADirectory {
        /// The path that was checked.
        path: PathBuf,
    },

    /// `--skip-input` left out every lockfile the nearest project (or every project of a scan) has.
    #[error("--skip-input left out every lockfile in {dir}: {skipped}")]
    #[diagnostic(
        code(pixi_sbom::discover::all_skipped),
        help(
            "drop one of the --skip-input values (or the skip-input configuration key), or pass --lockfile for another project"
        )
    )]
    AllSkipped {
        /// The directory whose lockfiles were all skipped.
        dir: PathBuf,
        /// The lockfiles left out, for the message.
        skipped: String,
    },

    /// `--lockfile` named a lockfile `--skip-input` leaves out.
    #[error("--lockfile {path} is a lockfile --skip-input leaves out")]
    #[diagnostic(
        code(pixi_sbom::discover::skipped),
        help("pass --lockfile without the --skip-input value that covers it, or leave --lockfile out to find another")
    )]
    Skipped {
        /// The lockfile given.
        path: PathBuf,
    },

    /// `--scan` walked the tree and came back with nothing.
    #[error("no {KINDS_TEXT} anywhere under {dir}")]
    #[diagnostic(
        code(pixi_sbom::discover::none_found),
        help(
            "--scan skips hidden directories and {skipped} (an installed environment is still found in a \
             hidden directory or venv outside any project), and stops at --scan-depth; check the directory, or \
             pass --lockfile for a single workspace"
        )
    )]
    NoneFound {
        /// The directory that was walked.
        dir: PathBuf,
        /// The directory names the walk never enters, for the message.
        skipped: String,
    },
}

/// Directories a scan never enters: environments, build output, caches, and dependencies of
/// other ecosystems. Hidden directories (`.pixi`, `.git`, `.venv`) are skipped by their dot.
pub const SCAN_SKIPPED_DIRS: &[&str] = &["node_modules", "target", "build", "dist", "venv", "__pycache__"];

/// Directly under a filesystem root (a directory holding `etc/` and `usr/`, such as an unpacked
/// container image or `/` itself), the kernel's pseudo-filesystems: never entered there, and
/// entered like any other directory anywhere else.
pub const SCAN_SKIPPED_ROOT_DIRS: &[&str] = &["proc", "sys", "dev"];

/// What a scan found: a project's lockfile, or an installed environment outside any project (#25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    Lockfile(PathBuf),
    /// Read as `--prefix` reads one.
    Environment(PathBuf),
}

impl Found {
    /// The lockfile, or the environment's directory.
    pub fn path(&self) -> &Path {
        match self {
            Found::Lockfile(path) | Found::Environment(path) => path,
        }
    }
}

/// One lockfile per project under `dir`, and every installed environment outside a project,
/// sorted by path so a scan is reproducible.
///
/// A project keeps its lockfile next to its manifest, so one directory is one project, and the
/// lockfile read for it is the one [`lockfile_in`] picks; a JavaScript lockfile beside it joins
/// its document ([`javascript_in`]). Hidden directories and [`SCAN_SKIPPED_DIRS`] are never
/// entered, symlinked directories are not followed (a cycle would never end), and `depth` caps
/// how far below `dir` the walk goes (`0` is `dir` itself).
///
/// Unless `skip` names [`SkipInput::Installed`], a directory that is an environment ([`is_environment`])
/// is found too, as long as no directory at or above it (within `dir`) has a lockfile that was read:
/// a project's `.pixi/envs` and `.venv` are what its lockfile describes, and listing both would
/// count everything twice. Outside a project, hidden directories and `venv` are searched for
/// environments only (`/app/.pixi/envs/prod`, `/root/.conda/envs/x`), never for lockfiles, and
/// `.git` is never entered. Nothing inside an environment is another one, except a conda
/// installation's `envs/`.
pub fn scan(dir: &Path, depth: Option<usize>, skip: &[SkipInput]) -> Result<Vec<Found>, DiscoverError> {
    if !dir.is_dir() {
        return Err(DiscoverError::NotADirectory {
            path: dir.to_path_buf(),
        });
    }
    let mut walked = Walked::default();
    walk(dir, 0, depth.unwrap_or(usize::MAX), skip, false, false, &mut walked);
    let Walked { mut found, skipped } = walked;
    found.sort_by(|a, b| a.path().cmp(b.path()));
    if found.is_empty() {
        if !skipped.is_empty() {
            return Err(DiscoverError::AllSkipped {
                dir: dir.to_path_buf(),
                skipped: skipped.join("; "),
            });
        }
        return Err(DiscoverError::NoneFound {
            dir: dir.to_path_buf(),
            skipped: SCAN_SKIPPED_DIRS.join(", "),
        });
    }
    Ok(found)
}

/// What a scan's walk collects: the lockfiles to read, and the directories whose lockfiles
/// `--skip-input` all left out (as `dir: names`, for a message).
#[derive(Default)]
struct Walked {
    found: Vec<Found>,
    skipped: Vec<String>,
}

/// Whether `dir` is an installed environment a scan reads: a conda environment, a venv, or a Python
/// installation with at least one package. A `lib` that is a link (a merged-`/usr` root's
/// `lib -> usr/lib`) does not make the directory an installation; the directory it points into is
/// found on its own.
pub fn is_environment(dir: &Path) -> bool {
    match crate::prefix::layout(dir) {
        Some(crate::prefix::Layout::Conda | crate::prefix::Layout::Venv) => true,
        Some(crate::prefix::Layout::Python) => {
            !dir.join("lib").is_symlink() && !crate::prefix::dist_infos(dir).is_empty()
        }
        None => false,
    }
}

/// A directory holding `etc/` and `usr/`: the root of a filesystem.
fn is_filesystem_root(dir: &Path) -> bool {
    dir.join("etc").is_dir() && dir.join("usr").is_dir()
}

/// Never entered even when looking for environments only: version control and caches.
const ENVIRONMENT_SEARCH_SKIPPED_DIRS: &[&str] = &[".git", "node_modules", "__pycache__"];

/// `owned`: a directory at or above this one had a lockfile that was read, so environments here are
/// that project's and are not looked for. `environments_only`: inside a hidden directory or a `venv`
/// outside any project (`/app/.pixi/envs/prod`, `/root/.conda/envs/x`, `~/.local`), where only
/// environments are looked for and a lockfile is not a project.
fn walk(
    dir: &Path,
    level: usize,
    max: usize,
    skip: &[SkipInput],
    owned: bool,
    environments_only: bool,
    walked: &mut Walked,
) {
    let mut owned = owned;
    if !environments_only {
        match lockfile_in(dir, skip) {
            Some(lockfile) => {
                walked.found.push(Found::Lockfile(lockfile));
                owned = true;
            }
            None => {
                let skipped = skipped_in(dir, skip);
                if !skipped.is_empty() {
                    walked.skipped.push(format!("{}: {skipped}", dir.display()));
                }
            }
        }
    }
    let installed = !owned && !skip.contains(&SkipInput::Installed);
    if environments_only && !installed {
        return;
    }
    if installed && is_environment(dir) {
        walked.found.push(Found::Environment(dir.to_path_buf()));
        // A conda installation (Miniforge's /opt/conda) keeps its other environments in envs/.
        let envs = dir.join("envs");
        if level + 2 <= max
            && envs.is_dir()
            && !envs.is_symlink()
            && let Ok(entries) = std::fs::read_dir(&envs)
        {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    walk(&entry.path(), level + 2, max, skip, false, true, walked);
                }
            }
        }
        return;
    }
    if level >= max {
        return;
    }
    let at_filesystem_root = level == 0 && is_filesystem_root(dir);
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            tracing::debug!(path = %dir.display(), %err, "cannot read directory; skipped");
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // `file_type` does not follow the link, so a symlinked directory is simply not one.
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if at_filesystem_root && SCAN_SKIPPED_ROOT_DIRS.contains(&name.as_str()) {
            continue;
        }
        if environments_only {
            if !ENVIRONMENT_SEARCH_SKIPPED_DIRS.contains(&name.as_str()) {
                walk(&path, level + 1, max, skip, owned, true, walked);
            }
        } else if name.starts_with('.') || SCAN_SKIPPED_DIRS.contains(&name.as_str()) {
            // Outside a project, a hidden directory or a `venv` can still be or hold an environment.
            if installed && !ENVIRONMENT_SEARCH_SKIPPED_DIRS.contains(&name.as_str()) {
                walk(&path, level + 1, max, skip, owned, true, walked);
            }
        } else {
            walk(&path, level + 1, max, skip, owned, false, walked);
        }
    }
}

/// Resolve the lockfile to read: an explicit path if given, otherwise the nearest lockfile
/// found by walking upward from `start`, with `skip` applied in the nearest directory that has
/// any. That directory is the project: when `skip` leaves out all of its lockfiles, the search
/// stops there rather than reaching a project above it.
pub fn resolve_lockfile(explicit: Option<&Path>, start: &Path, skip: &[SkipInput]) -> Result<PathBuf, DiscoverError> {
    match explicit {
        Some(path) if path.is_file() && is_skipped(path, skip) => Err(DiscoverError::Skipped {
            path: path.to_path_buf(),
        }),
        Some(path) if path.is_file() => Ok(path.to_path_buf()),
        Some(path) => Err(DiscoverError::Missing {
            path: path.to_path_buf(),
        }),
        None => {
            let dir = project_dir(start)?;
            lockfile_in(&dir, skip).ok_or_else(|| DiscoverError::AllSkipped {
                skipped: skipped_in(&dir, skip),
                dir,
            })
        }
    }
}

/// The nearest directory at or above `start` that has a lockfile of any kind: the project a run
/// without `--lockfile` describes, and where its configuration is looked up.
pub fn project_dir(start: &Path) -> Result<PathBuf, DiscoverError> {
    start
        .ancestors()
        .find(|dir| !lockfiles_in(dir).is_empty())
        .map(Path::to_path_buf)
        .ok_or_else(|| DiscoverError::NotFound {
            start: start.to_path_buf(),
            hint: crate::unlocked::nearest_manifest(start)
                .map(|(path, found)| format!("{} is {}: {}. Otherwise, ", path.display(), found.what, found.next))
                .unwrap_or_default(),
        })
}

/// The `--output` spelling that selects standard output.
pub const STDOUT: &str = "-";

/// Where a document goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Standard output.
    Stdout,
    /// A file, created (with its parent directories) on write.
    File(PathBuf),
}

impl std::fmt::Display for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Output::Stdout => f.write_str("<stdout>"),
            Output::File(path) => path.display().fmt(f),
        }
    }
}

/// Whether an explicit `--output` value means standard output.
pub fn is_stdout(explicit: Option<&Path>) -> bool {
    explicit.is_some_and(|path| path.as_os_str() == STDOUT)
}

/// Resolve where the SBOM is written: stdout for `-`, an explicit path if given, otherwise
/// the format's default file name in the same directory as the lockfile.
pub fn resolve_output(explicit: Option<&Path>, lockfile: &Path, format: Format) -> Output {
    match explicit {
        Some(_) if is_stdout(explicit) => Output::Stdout,
        Some(path) => Output::File(path.to_path_buf()),
        None => Output::File(lockfile_dir(lockfile).join(format.default_file_name())),
    }
}

/// Resolve one output file of a batch (`--all-environments` / `--all-platforms`):
/// `sbom-<labels...>` inside the explicit output directory if given, otherwise next to the
/// lockfile.
pub fn resolve_batch_output<'a>(
    explicit_dir: Option<&Path>,
    lockfile: &Path,
    format: Format,
    labels: impl IntoIterator<Item = &'a str>,
) -> PathBuf {
    explicit_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| lockfile_dir(lockfile))
        .join(format.batch_file_name(labels))
}

/// The lockfile's own name (normally `pixi.lock`), which is what the SBOM records. The
/// lockfile always lives at the workspace root, so this is its workspace-relative path; the
/// absolute path would leak the generating machine's layout and differ between machines.
pub fn lockfile_name(lockfile: &Path) -> String {
    lockfile
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| LOCKFILE_NAME.to_string())
}

fn lockfile_dir(lockfile: &Path) -> PathBuf {
    lockfile.parent().map(Path::to_path_buf).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_lockfile_per_directory_in_the_documented_order() {
        let dir = tempfile::tempdir().unwrap();
        let touch = |name: &str| std::fs::write(dir.path().join(name), "").unwrap();
        assert_eq!(lockfile_in(dir.path(), &[]), None);
        touch("spec.txt");
        assert_eq!(
            lockfile_in(dir.path(), &[]),
            None,
            "an explicit spec file is never discovered"
        );
        for name in [
            "yarn.lock",
            "pnpm-lock.yaml",
            "package-lock.json",
            "conda-lock.yml",
            "pdm.lock",
            "poetry.lock",
            "pylock.dev.toml",
            "pylock.toml",
            "uv.lock",
            "pixi.lock",
        ] {
            touch(name);
            assert_eq!(
                lockfile_in(dir.path(), &[]),
                Some(dir.path().join(name)),
                "{name} goes before the ones so far"
            );
        }
        let names: Vec<String> = lockfiles_in(dir.path()).iter().map(|p| lockfile_name(p)).collect();
        assert_eq!(
            names,
            [
                "pixi.lock",
                "uv.lock",
                "pylock.toml",
                "pylock.dev.toml",
                "poetry.lock",
                "pdm.lock",
                "conda-lock.yml",
                "package-lock.json",
                "pnpm-lock.yaml",
                "yarn.lock"
            ]
        );
        let named = tempfile::tempdir().unwrap();
        std::fs::write(named.path().join("pylock.web.toml"), "").unwrap();
        std::fs::write(named.path().join("pylock.api.toml"), "").unwrap();
        assert_eq!(
            lockfile_in(named.path(), &[]),
            Some(named.path().join("pylock.api.toml")),
            "named ones, sorted"
        );
    }

    #[test]
    fn a_scan_finds_every_kind_once_per_project() {
        let dir = tempfile::tempdir().unwrap();
        for (sub, name) in [
            ("a", "pixi.lock"),
            ("a", "uv.lock"),
            ("b", "uv.lock"),
            ("c/d", "poetry.lock"),
            ("e", "conda-lock.yml"),
            // A JavaScript lockfile beside a pixi one joins its document; one per directory among themselves.
            ("a", "package-lock.json"),
            ("f", "yarn.lock"),
            ("g", "pnpm-lock.yaml"),
            ("g", "yarn.lock"),
        ] {
            std::fs::create_dir_all(dir.path().join(sub)).unwrap();
            std::fs::write(dir.path().join(sub).join(name), "").unwrap();
        }
        let found: Vec<PathBuf> = scan(dir.path(), None, &[])
            .unwrap()
            .into_iter()
            .map(|p| p.path().strip_prefix(dir.path()).unwrap().to_path_buf())
            .collect();
        let found: Vec<&str> = found.iter().map(|p| p.to_str().unwrap()).collect();
        let expected = [
            "a/pixi.lock",
            "b/uv.lock",
            "c/d/poetry.lock",
            "e/conda-lock.yml",
            "f/yarn.lock",
            "g/pnpm-lock.yaml",
        ]
        .map(|p| p.replace('/', std::path::MAIN_SEPARATOR_STR));
        assert_eq!(found, expected);
        let empty = tempfile::tempdir().unwrap();
        let err = scan(empty.path(), None, &[]).unwrap_err().to_string();
        assert!(err.contains("yarn.lock anywhere under"), "{err}");
    }

    #[test]
    fn skip_input_picks_the_next_lockfile_of_the_ecosystem_and_leaves_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["pixi.lock", "uv.lock", "package-lock.json", "yarn.lock"] {
            std::fs::write(dir.path().join(name), "").unwrap();
        }
        let pick = |skip: &[SkipInput]| {
            let lockfile = lockfile_in(dir.path(), skip);
            let javascript = lockfile.as_ref().and_then(|l| javascript_in(dir.path(), l, skip));
            (
                lockfile.map(|p| lockfile_name(&p)),
                javascript.map(|p| lockfile_name(&p)),
            )
        };
        let both = |l: &str, j: Option<&str>| (Some(l.to_string()), j.map(str::to_string));
        assert_eq!(pick(&[]), both("pixi.lock", Some("package-lock.json")));
        assert_eq!(pick(&[SkipInput::Pixi]), both("uv.lock", Some("package-lock.json")));
        assert_eq!(pick(&[SkipInput::Npm]), both("pixi.lock", Some("yarn.lock")));
        assert_eq!(pick(&[SkipInput::Javascript]), both("pixi.lock", None));
        assert_eq!(
            pick(&[SkipInput::Pixi, SkipInput::Uv]),
            both("package-lock.json", None),
            "JavaScript alone"
        );
        let all = [SkipInput::Pixi, SkipInput::Uv, SkipInput::Javascript];
        assert_eq!(pick(&all), (None, None));

        let err = resolve_lockfile(None, dir.path(), &all).unwrap_err();
        assert!(matches!(err, DiscoverError::AllSkipped { .. }), "{err}");
        assert!(
            err.to_string()
                .contains("pixi.lock, uv.lock, package-lock.json, yarn.lock"),
            "{err}"
        );
        crate::assert_actionable(&err);
        let err = resolve_lockfile(Some(&dir.path().join("uv.lock")), dir.path(), &[SkipInput::Uv]).unwrap_err();
        assert!(matches!(err, DiscoverError::Skipped { .. }), "{err}");
        crate::assert_actionable(&err);
        // A scan leaves a fully skipped directory out, and says so when that leaves nothing.
        let err = scan(dir.path(), None, &all).unwrap_err();
        assert!(matches!(err, DiscoverError::AllSkipped { .. }), "{err}");
        assert_eq!(
            scan(dir.path(), None, &[SkipInput::Pixi]).unwrap(),
            [Found::Lockfile(dir.path().join("uv.lock"))]
        );
    }

    #[test]
    fn every_skip_input_value_names_its_own_lockfiles() {
        use clap::ValueEnum;
        // `installed` leaves out environments rather than lockfiles (#25), and names none.
        for input in SkipInput::value_variants() {
            let lockfiles = LOCKFILE_KINDS.into_iter().any(|n| input.covers(n));
            assert_eq!(lockfiles, *input != SkipInput::Installed, "{input:?}");
        }
        assert!(SkipInput::Pylock.covers("pylock.dev.toml"));
        assert!(!SkipInput::Pixi.covers("uv.lock"));
    }

    #[test]
    fn the_nearest_lockfile_wins_and_pixi_lock_first_within_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(dir.path().join("pixi.lock"), "").unwrap();
        std::fs::write(dir.path().join("a/uv.lock"), "").unwrap();
        assert_eq!(
            resolve_lockfile(None, &nested, &[]).unwrap(),
            dir.path().join("a/uv.lock"),
            "closer"
        );
        std::fs::write(dir.path().join("a/pixi.lock"), "").unwrap();
        assert_eq!(
            resolve_lockfile(None, &nested, &[]).unwrap(),
            dir.path().join("a/pixi.lock"),
            "pixi first"
        );
        std::fs::write(nested.join("pylock.toml"), "").unwrap();
        assert_eq!(
            resolve_lockfile(None, &nested, &[]).unwrap(),
            nested.join("pylock.toml")
        );
    }

    #[test]
    fn every_error_carries_a_code_and_a_next_step() {
        for err in [
            DiscoverError::NotFound {
                start: PathBuf::from("/workspace"),
                hint: String::new(),
            },
            DiscoverError::Missing {
                path: PathBuf::from("/workspace/pixi.lock"),
            },
            DiscoverError::NotADirectory {
                path: PathBuf::from("/workspace/pixi.lock"),
            },
            DiscoverError::NoneFound {
                dir: PathBuf::from("/workspace"),
                skipped: SCAN_SKIPPED_DIRS.join(", "),
            },
        ] {
            crate::assert_actionable(&err);
        }
    }

    #[test]
    fn explicit_lockfile_is_returned_when_it_exists() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("custom.lock");
        std::fs::write(&lock, "version: 6\n").unwrap();

        let found = resolve_lockfile(Some(&lock), dir.path(), &[]).unwrap();
        assert_eq!(found, lock);
    }

    #[test]
    fn explicit_lockfile_that_is_missing_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.lock");

        let err = resolve_lockfile(Some(&missing), dir.path(), &[]).unwrap_err();
        assert!(matches!(err, DiscoverError::Missing { path } if path == missing));
    }

    #[test]
    fn lockfile_is_found_in_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join(LOCKFILE_NAME);
        std::fs::write(&lock, "version: 6\n").unwrap();
        let nested = dir.path().join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();

        let found = resolve_lockfile(None, &nested, &[]).unwrap();
        assert_eq!(found, lock);
    }

    #[test]
    fn no_lockfile_anywhere_errors() {
        let dir = tempfile::tempdir().unwrap();

        let err = resolve_lockfile(None, dir.path(), &[]).unwrap_err();
        assert!(matches!(err, DiscoverError::NotFound { .. }));
        assert!(err.to_string().contains(LOCKFILE_NAME));
    }

    /// A tree of directories, each with a `pixi.lock` where the name says so.
    fn tree(dir: &Path, lockfiles: &[&str], empty_dirs: &[&str]) {
        for relative in lockfiles {
            let path = dir.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "version: 6\n").unwrap();
        }
        for relative in empty_dirs {
            std::fs::create_dir_all(dir.join(relative)).unwrap();
        }
    }

    #[test]
    fn scanning_finds_every_workspace_in_sorted_order() {
        let dir = tempfile::tempdir().unwrap();
        tree(
            dir.path(),
            &[
                "services/worker/pixi.lock",
                "services/api/pixi.lock",
                "tools/ci/pixi.lock",
                // Never entered: an installed environment, a hidden directory, and the
                // dependency trees of other ecosystems.
                "services/api/.pixi/envs/default/pixi.lock",
                "node_modules/pkg/pixi.lock",
                "target/debug/pixi.lock",
                ".git/worktree/pixi.lock",
            ],
            &["docs"],
        );
        let found = scan(dir.path(), None, &[]).unwrap();
        let relative: Vec<String> = found
            .iter()
            .map(|p| {
                p.path()
                    .strip_prefix(dir.path())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(
            relative,
            [
                "services/api/pixi.lock",
                "services/worker/pixi.lock",
                "tools/ci/pixi.lock"
            ]
        );
    }

    #[test]
    fn scanning_finds_the_directory_s_own_lockfile_and_stops_at_the_depth() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["pixi.lock", "a/pixi.lock", "a/b/pixi.lock"], &[]);
        let names = |depth: Option<usize>| scan(dir.path(), depth, &[]).unwrap().len();
        assert_eq!(names(Some(0)), 1, "the directory itself");
        assert_eq!(names(Some(1)), 2);
        assert_eq!(names(None), 3);
    }

    /// Relative paths of what a scan found, `L` for a lockfile and `E` for an environment.
    fn found(dir: &Path, depth: Option<usize>, skip: &[SkipInput]) -> Vec<String> {
        scan(dir, depth, skip)
            .unwrap()
            .iter()
            .map(|found| {
                let kind = if matches!(found, Found::Lockfile(_)) { "L" } else { "E" };
                let path = found
                    .path()
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                format!("{kind} {path}")
            })
            .collect()
    }

    #[test]
    fn a_container_root_filesystem_has_each_environment_found_once() {
        let dir = tempfile::tempdir().unwrap();
        tree(
            dir.path(),
            &[
                "app/.venv/pyvenv.cfg",
                // A plain Python installation with a package: found. One with an empty
                // site-packages describes nothing, and is not.
                "usr/local/lib/python3.12/site-packages/requests-2.32.0.dist-info/METADATA",
                // The kernel's pseudo-filesystems at a filesystem root are never entered.
                "proc/1/root/pyvenv.cfg",
                // A conda installation's own package cache is inside it, so never looked at.
                "opt/conda/pkgs/numpy-2.0-py312/lib/python3.12/site-packages/numpy-2.0.dist-info/METADATA",
                // pixi's production layout: the environment copied without its lockfile, under a
                // hidden directory; and a user's conda and pip --user installs under their home.
                "app/.pixi/envs/prod/conda-meta/history",
                "root/.conda/envs/tools/conda-meta/history",
                "root/.local/lib/python3.12/site-packages/httpx-0.28.0.dist-info/METADATA",
                // A lockfile inside a hidden directory is never a project.
                "root/.cache/uv/pixi.lock",
                // A project: its lockfile is read, and its environments are what that lockfile describes.
                "srv/web/pixi.lock",
                "srv/web/.pixi/envs/default/conda-meta/history",
                "srv/web/.venv/pyvenv.cfg",
            ],
            &[
                "etc",
                "opt/conda/conda-meta",
                "opt/conda/envs/app/conda-meta",
                "opt/conda/envs/tools/conda-meta",
                "usr/lib/python3.12/site-packages",
                "home/user/venv/conda-meta",
            ],
        );
        assert_eq!(
            found(dir.path(), None, &[]),
            [
                "E app/.pixi/envs/prod",
                "E app/.venv",
                "E home/user/venv",
                "E opt/conda",
                "E opt/conda/envs/app",
                "E opt/conda/envs/tools",
                "E root/.conda/envs/tools",
                "E root/.local",
                "L srv/web/pixi.lock",
                "E usr/local",
            ]
        );
        assert_eq!(
            found(dir.path(), None, &[SkipInput::Installed]),
            ["L srv/web/pixi.lock"]
        );
        assert_eq!(
            found(dir.path(), Some(2), &[]),
            [
                "E app/.venv",
                "E opt/conda",
                "E root/.local",
                "L srv/web/pixi.lock",
                "E usr/local"
            ]
        );
    }

    #[test]
    fn proc_sys_and_dev_are_skipped_only_at_a_filesystem_root() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["dev/pixi.lock", "proc/tool/pixi.lock"], &[]);
        assert_eq!(
            found(dir.path(), None, &[]),
            ["L dev/pixi.lock", "L proc/tool/pixi.lock"]
        );
        tree(dir.path(), &[], &["etc", "usr"]);
        assert!(matches!(
            scan(dir.path(), None, &[]),
            Err(DiscoverError::NoneFound { .. })
        ));
    }

    #[test]
    fn an_environment_is_found_unless_a_lockfile_above_it_was_read() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["pixi.lock", "sub/.venv/pyvenv.cfg"], &[]);
        assert_eq!(found(dir.path(), None, &[]), ["L pixi.lock"]);
        // Skipped, the lockfile describes nothing, so the environment is found after all.
        assert_eq!(found(dir.path(), None, &[SkipInput::Pixi]), ["E sub/.venv"]);
        // The scanned directory can be an environment itself.
        let venv = dir.path().join("sub/.venv");
        assert_eq!(found(&venv, None, &[]), ["E "]);
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_lib_does_not_make_a_root_a_python_installation() {
        let dir = tempfile::tempdir().unwrap();
        tree(
            dir.path(),
            &["usr/lib/python3.12/site-packages/six-1.17.0.dist-info/METADATA"],
            &["etc"],
        );
        std::os::unix::fs::symlink("usr/lib", dir.path().join("lib")).unwrap();
        assert_eq!(found(dir.path(), None, &[]), ["E usr"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["real/pixi.lock"], &[]);
        // A link back to the root would walk for ever.
        std::os::unix::fs::symlink(dir.path(), dir.path().join("real").join("loop")).unwrap();
        assert_eq!(scan(dir.path(), None, &[]).unwrap().len(), 1);
    }

    #[test]
    fn scanning_nothing_is_an_error_that_says_what_was_skipped() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["node_modules/pkg/pixi.lock"], &["empty"]);
        let err = scan(dir.path(), None, &[]).unwrap_err();
        assert!(matches!(err, DiscoverError::NoneFound { .. }));
        let file = dir.path().join("not-a-directory");
        std::fs::write(&file, "x").unwrap();
        assert!(matches!(
            scan(&file, None, &[]),
            Err(DiscoverError::NotADirectory { .. })
        ));
    }

    #[test]
    fn lockfile_name_is_the_file_name_only() {
        assert_eq!(lockfile_name(Path::new("/home/alice/proj/pixi.lock")), "pixi.lock");
        assert_eq!(lockfile_name(Path::new("custom.lock")), "custom.lock");
        assert_eq!(lockfile_name(Path::new("/")), LOCKFILE_NAME);
    }

    #[test]
    fn output_defaults_next_to_lockfile_per_format() {
        let lock = Path::new("/work/proj/pixi.lock");

        assert_eq!(
            resolve_output(None, lock, Format::Cyclonedx),
            Output::File("/work/proj/sbom.cdx.json".into())
        );
        assert_eq!(
            resolve_output(None, lock, Format::Spdx),
            Output::File("/work/proj/sbom.spdx.json".into())
        );
    }

    #[test]
    fn explicit_output_path_or_dash() {
        let lock = Path::new("/work/proj/pixi.lock");

        assert_eq!(
            resolve_output(Some(Path::new("out/x.json")), lock, Format::Spdx),
            Output::File("out/x.json".into())
        );
        assert_eq!(resolve_output(Some(Path::new("-")), lock, Format::Spdx), Output::Stdout);
        assert!(is_stdout(Some(Path::new("-"))));
        assert!(!is_stdout(Some(Path::new("-.json"))));
        assert!(!is_stdout(None));
        assert_eq!(Output::Stdout.to_string(), "<stdout>");
        assert_eq!(Output::File("a/b".into()).to_string(), "a/b");
    }

    #[test]
    fn batch_output_defaults_next_to_lockfile() {
        let lock = Path::new("/work/proj/pixi.lock");

        assert_eq!(
            resolve_batch_output(None, lock, Format::Cyclonedx, ["prod"]),
            Path::new("/work/proj/sbom-prod.cdx.json")
        );
        assert_eq!(
            resolve_batch_output(None, lock, Format::Spdx, ["default"]),
            Path::new("/work/proj/sbom-default.spdx.json")
        );
        assert_eq!(
            resolve_batch_output(None, lock, Format::Spdx, ["prod", "linux-64"]),
            Path::new("/work/proj/sbom-prod-linux-64.spdx.json")
        );
    }

    #[test]
    fn batch_output_uses_explicit_directory() {
        let lock = Path::new("/work/proj/pixi.lock");
        let dir = Path::new("/reports");

        assert_eq!(
            resolve_batch_output(Some(dir), lock, Format::Cyclonedx, ["web"]),
            Path::new("/reports/sbom-web.cdx.json")
        );
    }

    #[test]
    fn explicit_output_wins() {
        let lock = Path::new("/work/proj/pixi.lock");
        let out = Path::new("/elsewhere/bom.json");

        assert_eq!(
            resolve_output(Some(out), lock, Format::Cyclonedx),
            Output::File(out.to_path_buf())
        );
    }
}
