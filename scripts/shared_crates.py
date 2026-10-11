"""Check that the workspace crates an extension builds on are released before the extension is (#57).

An extension published to crates.io depends on the shared crate's crates.io release, not on the code beside it, so
that release must exist and hold the code the extension was tested with: the crate's version is on crates.io, it has
a tag (`<crate>-vX.Y.Z`), and nothing in its directory changed since that tag. The Release workflow runs this before
it tags an extension; when it fails, release the shared crate first.

    pixi run shared-crates-check pixi-sbom
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import changelog

ROOT = Path(__file__).resolve().parent.parent
CRATES_IO = "https://crates.io/api/v1/crates"


@dataclass(frozen=True)
class Dependency:
    """A workspace crate an extension depends on by path."""

    name: str
    version: str
    directory: str

    @property
    def tag(self) -> str:
        """The tag a release of it carries."""
        return f"{self.name}-v{self.version}"


def dependencies(meta: dict[str, Any], name: str) -> list[Dependency]:
    """The workspace crates `name` depends on by path, directly or through another, excluding dev-dependencies."""
    root = Path(meta["workspace_root"])
    by_dir = {Path(p["manifest_path"]).parent: p for p in meta["packages"]}
    start = next((p for p in meta["packages"] if p["name"] == name), None)
    if start is None:
        raise changelog.ChangelogError(f"no workspace crate named {name!r}")
    found: dict[str, Dependency] = {}
    pending = [start]
    while pending:
        package = pending.pop()
        for dependency in package["dependencies"]:
            if dependency.get("kind") == "dev" or not dependency.get("path"):
                continue
            target = by_dir.get(Path(dependency["path"]))
            if target is None or target["name"] in found or target["name"] == name:
                continue
            directory = Path(target["manifest_path"]).parent.relative_to(root).as_posix()
            found[target["name"]] = Dependency(target["name"], target["version"], directory)
            pending.append(target)
    return sorted(found.values(), key=lambda d: d.name)


def problems(
    deps: list[Dependency],
    tag_exists: Callable[[str], bool],
    changed_since: Callable[[str, str], bool],
    published: Callable[[str, str], bool],
) -> list[str]:
    """What stands in the way of releasing an extension built on `deps`, one sentence each; empty when nothing."""
    found = []
    for dep in deps:
        if not tag_exists(dep.tag):
            found.append(f"{dep.name} {dep.version} has no release tag ({dep.tag}): release it first")
            continue
        if changed_since(dep.tag, dep.directory):
            found.append(f"{dep.directory} changed since {dep.tag}: release {dep.name} first, with a new version")
            continue
        if not published(dep.name, dep.version):
            found.append(f"{dep.name} {dep.version} is tagged but not on crates.io yet: wait for its publish job")
    return found


def git_tag_exists(tag: str) -> bool:
    """Whether the repository has the tag."""
    result = subprocess.run(
        ["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"], cwd=ROOT, capture_output=True, check=False
    )
    return result.returncode == 0


def git_changed_since(tag: str, directory: str) -> bool:
    """Whether anything under `directory` differs between the tag and HEAD."""
    result = subprocess.run(["git", "diff", "--quiet", tag, "HEAD", "--", directory], cwd=ROOT, check=False)
    return result.returncode != 0


def crates_io_has(name: str, version: str) -> bool:
    """Whether crates.io serves that version of the crate."""
    request = urllib.request.Request(
        f"{CRATES_IO}/{name}/{version}",
        headers={"User-Agent": "aesir-oss/pixi-ext-contrib release check (https://github.com/aesir-oss/pixi-ext-contrib)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return bool(response.status == 200)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise


def main(argv: list[str] | None = None) -> int:
    """Run the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("crate", help="the extension about to be released")
    args = parser.parse_args(argv)
    deps = dependencies(changelog.metadata(), args.crate)
    found = problems(deps, git_tag_exists, git_changed_since, crates_io_has)
    for problem in found:
        sys.stderr.write(f"error: {problem}\n")
    if not found:
        names = ", ".join(f"{d.name} {d.version}" for d in deps) or "none"
        sys.stderr.write(f"{args.crate}: the workspace crates it builds on are released ({names})\n")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
