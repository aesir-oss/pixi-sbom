"""Write one extension's changelog from the commits that touched what it is built from.

An extension's changelog lists the commits that touched its own crate, every workspace crate it
depends on (read from `cargo metadata`, so a new dependency is followed without editing anything),
and the extra paths its Cargo.toml claims under `[package.metadata.changelog] include`. A commit
that touches only another extension never appears. Its releases are its own `<extension>-vX.Y.Z`
tags; release candidates stay invisible, so a section spans final release to final release.

`history-before` names the last tag made before the crate moved into `crates/`: the commits up to
it touched the old root layout, which no path filter can follow, so that part of the history is
written unfiltered and appended.

    pixi run changelog-of write pixi-sbom [--tag pixi-sbom-v1.13.0]
    pixi run changelog-of notes pixi-sbom
    pixi run changelog-of paths pixi-sbom
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "cliff.toml"
VERSION = r"v[0-9]+\.[0-9]+\.[0-9]+$"


class ChangelogError(Exception):
    """The extension cannot be found or its changelog settings are wrong."""


def metadata(root: Path = ROOT) -> dict[str, Any]:
    """Return `cargo metadata` for the workspace at root, without resolving registry dependencies."""
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    data: dict[str, Any] = json.loads(out)
    return data


def _package(meta: dict[str, Any], name: str) -> dict[str, Any]:
    for package in meta["packages"]:
        if package["name"] == name:
            found: dict[str, Any] = package
            return found
    members = sorted(p["name"] for p in meta["packages"])
    raise ChangelogError(f"no workspace crate named {name!r} (the workspace has {', '.join(members)})")


def _settings(package: dict[str, Any]) -> dict[str, Any]:
    settings = ((package.get("metadata") or {}).get("changelog")) or {}
    unknown = set(settings) - {"include", "history-before"}
    if unknown:
        raise ChangelogError(f"[package.metadata.changelog] of {package['name']} has unknown keys: {sorted(unknown)}")
    return dict(settings)


def include_paths(meta: dict[str, Any], name: str) -> list[str]:
    """Return the paths, relative to the workspace root, whose commits belong in the extension's changelog."""
    root = Path(meta["workspace_root"])
    by_dir = {Path(p["manifest_path"]).parent: p for p in meta["packages"]}
    crates: list[Path] = []
    pending = [_package(meta, name)]
    while pending:
        package = pending.pop()
        crate = Path(package["manifest_path"]).parent
        if crate in crates:
            continue
        crates.append(crate)
        for dependency in package["dependencies"]:
            if dependency.get("kind") == "dev" or not dependency.get("path"):
                continue
            target = by_dir.get(Path(dependency["path"]))
            if target is not None:
                pending.append(target)
    own, *dependencies = (f"{crate.relative_to(root).as_posix()}/**" for crate in crates)
    paths = [own, *sorted(dependencies)]
    paths += [p for p in _settings(_package(meta, name)).get("include", []) if p not in paths]
    return paths


def _cliff(root: Path, args: list[str]) -> str:
    return subprocess.run(
        ["git-cliff", "--config", str(CONFIG), *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def changelog(meta: dict[str, Any], name: str, tag: str | None = None, root: Path = ROOT) -> str:
    """Return the extension's whole changelog, with tag naming the release being made if given."""
    paths = include_paths(meta, name)
    before = _settings(_package(meta, name)).get("history-before")
    args = ["--tag-pattern", f"^{name}-{VERSION}"]
    for path in paths:
        args += ["--include-path", path]
    if tag:
        args += ["--tag", tag]
    if before:
        args.append(f"{before}..HEAD")
    text = _cliff(root, args)
    if before:
        first = subprocess.run(
            ["git", "rev-list", "--max-parents=0", before], cwd=root, check=True, capture_output=True, text=True
        ).stdout.split()[0]
        history = _cliff(root, ["--tag-pattern", f"^{VERSION}", "--strip", "header", f"{first}..{before}"])
        text = text.rstrip("\n") + "\n\n" + history.lstrip("\n")
    return text


def notes(meta: dict[str, Any], name: str, root: Path = ROOT) -> str:
    """Return the section of the extension's newest final release, without the header, for its release notes."""
    args = ["--tag-pattern", f"^{name}-{VERSION}", "--latest", "--strip", "header"]
    for path in include_paths(meta, name):
        args += ["--include-path", path]
    return _cliff(root, args)


def changelog_file(meta: dict[str, Any], name: str) -> Path:
    """Return where the extension's changelog lives: CHANGELOG.md beside its Cargo.toml."""
    return Path(_package(meta, name)["manifest_path"]).parent / "CHANGELOG.md"


def main(argv: list[str] | None = None) -> int:
    """Run the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["write", "notes", "paths"])
    parser.add_argument("extension")
    parser.add_argument("--tag", help="the tag of the release being made, which does not exist yet")
    args = parser.parse_args(argv)
    try:
        meta = metadata()
        if args.command == "paths":
            sys.stdout.write("\n".join(include_paths(meta, args.extension)) + "\n")
        elif args.command == "notes":
            sys.stdout.write(notes(meta, args.extension))
        else:
            target = changelog_file(meta, args.extension)
            target.write_text(changelog(meta, args.extension, args.tag), encoding="utf-8")
            sys.stderr.write(f"wrote {target.relative_to(ROOT)}\n")
    except ChangelogError as error:
        sys.stderr.write(f"error: {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
