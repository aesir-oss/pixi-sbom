"""Grype's findings from pixi-sbom's SBOM against syft's, for the same installed environments.

The acceptance test for replacing syft in front of Grype (#434). Each corpus environment is
installed, described by syft and by `pixi sbom --prefix`, and both documents are scanned by the same
Grype with the same database. Every conda, Python or npm finding from syft's document must also come from
pixi-sbom's, or be listed in tests/grype/exceptions.toml with a reason. Findings only pixi-sbom's
document produces are reported, not failed. What the default flags would lose (#449) is reported too.

    pixi run grype-compare                   # the whole corpus
    pixi run grype-compare --only django     # one environment
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCEPTIONS = ROOT / "tests" / "grype" / "exceptions.toml"
SYFT = "syft==1.54.1"
GRYPE = "grype==0.120.1"

# name, project, how it is installed
CORPUS = [
    ("django", "examples/projects/pixi/01-django", "pixi"),
    ("data-analysis", "examples/projects/pixi/04-data-analysis", "pixi"),
    ("dev-tooling", "examples/projects/pixi/10-dev-tooling", "pixi"),
    ("venv-flask", "examples/projects/requirements/02-flask/requirements.txt", "venv"),
    # Go programs, whose modules are read out of the binaries (#437).
    ("go-tools", "examples/projects/pixi/16-go-tools", "pixi"),
    # npm and its dependencies, installed by nodejs and a tool built on it (#438).
    ("node-tools", "examples/projects/pixi/17-node-tools", "pixi"),
    # Native libraries a wheel bundles (`PIL/.dylibs`, `pillow.libs`), read out of the binaries (#23).
    ("pillow-wheels", "examples/projects/requirements/18-image-wheels/requirements.txt", "venv"),
    # The JavaScript example read from its package-lock.json, not installed: both tools read the lockfile (#29).
    ("web-frontend", "examples/projects/npm/19-web-frontend", "lockfile"),
    # Unpacked container images, every environment in each found by --scan and merged (#25, #31).
    ("image-python-app", "examples/projects/container/20-images/python-app", "rootfs"),
    ("image-pixi-app", "examples/projects/container/20-images/pixi-app", "rootfs"),
]

# syft reads installed package.json files only in an image unless told to; on the environment that
# installs JavaScript it is, so its document lists what is installed. Elsewhere it is left off: in
# the data-analysis environment it would list JupyterLab's prebuilt extension bundles, which are
# not installed packages.
SYFT_EXTRA = {"node-tools": ["--select-catalogers", "+javascript-package-cataloger"]}

# Findings pixi-sbom's document must give Grype in an environment, whatever syft finds: the reason the
# environment is in the corpus. Matched on vulnerability and package; the version is the bundled copy's.
REQUIRED = {"pillow-wheels": {("CVE-2023-4863", "libwebp")}}

# syft artifact types this comparison is about: what a conda or Python environment installs.
COMPARED_TYPES = {"python", "conda", "binary", "npm", "go-module"}


@dataclass(frozen=True, order=True)
class Finding:
    """One vulnerability Grype reported against one package."""

    vulnerability: str
    package: str
    version: str


def normalize(name: str) -> str:
    """A package name both tools spell the same way: lower case, `_` and `.` as `-`."""
    return name.strip().lower().replace("_", "-").replace(".", "-")


def not_installed(syft_json: dict) -> set[str]:
    """The ids of syft's npm artifacts that are not installed packages: entries of a lockfile it
    found (JupyterLab's build-time `staging/yarn.lock`, a project's own lockfile), which describe
    what a build would fetch. pixi-sbom lists installed code (#438); project lockfiles are #493."""
    return {
        artifact["id"]
        for artifact in syft_json.get("artifacts", [])
        if artifact.get("type") == "npm" and artifact.get("foundBy") != "javascript-package-cataloger"
    }


def findings(grype_json: dict, types: set[str] | None = None, exclude: set[str] = frozenset()) -> set[Finding]:
    """The findings in Grype's JSON output, optionally only for some artifact types, without the
    artifacts whose ids are in `exclude`."""
    found = set()
    for match in grype_json.get("matches", []):
        artifact = match.get("artifact", {})
        if types is not None and artifact.get("type") not in types:
            continue
        if artifact.get("id") in exclude:
            continue
        found.add(Finding(match["vulnerability"]["id"], normalize(artifact["name"]), artifact.get("version", "")))
    return found


def load_exceptions(text: str) -> dict[tuple[str, str, str], str]:
    """The exceptions file: (environment, vulnerability, package) to the reason it is accepted."""
    loaded: dict[tuple[str, str, str], str] = {}
    for entry in tomllib.loads(text).get("exception", []):
        reason = str(entry.get("reason", "")).strip()
        key = (entry.get("environment", ""), entry.get("vulnerability", ""), normalize(entry.get("package", "")))
        if not all(key) or not reason:
            raise ValueError(f"an exception needs environment, vulnerability, package and a reason: {entry}")
        loaded[key] = reason
    return loaded


@dataclass
class Comparison:
    """How the two documents' findings line up for one environment."""

    agree: set[Finding]
    syft_only: set[Finding]
    excepted: set[Finding]
    pixi_only: set[Finding]


def compare(environment: str, syft: set[Finding], pixi: set[Finding], exceptions: dict) -> Comparison:
    """Line syft's findings up against pixi-sbom's. A finding is the same when the vulnerability, the
    package name and its version are."""
    missing = syft - pixi
    excepted = {f for f in missing if (environment, f.vulnerability, f.package) in exceptions}
    return Comparison(agree=syft & pixi, syft_only=missing - excepted, excepted=excepted, pixi_only=pixi - syft)


def missing_required(environment: str, pixi: set[Finding]) -> set[tuple[str, str]]:
    """The findings REQUIRED names for an environment that pixi-sbom's document did not give."""
    return REQUIRED.get(environment, set()) - {(f.vulnerability, f.package) for f in pixi}


def default_gap(recommended: set[Finding], default: set[Finding]) -> set[Finding]:
    """Findings the recommended flags give that a document with default flags does not: what
    leaving `--primary-purl` at `conda` costs a scanner."""
    return recommended - default


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command, failing loudly with its output."""
    result = subprocess.run(command, capture_output=True, text=True, check=False, **kwargs)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(command[:4])} ... exited {result.returncode}:\n{result.stderr[-2000:]}")
    return result


def install(name: str, project: str, how: str, work: Path) -> Path:
    """Install one corpus environment under `work` and return its prefix."""
    if how in ("lockfile", "rootfs"):
        copy = work / name
        # An image's venv links point into the image (`/usr/local/bin/python`): copied as links.
        shutil.copytree(ROOT / project, copy, symlinks=True)
        return copy
    if how == "pixi":
        copy = work / name
        shutil.copytree(ROOT / project, copy, ignore=shutil.ignore_patterns(".pixi"))
        run(["pixi", "install", "--locked", "--manifest-path", str(copy / "pixi.toml")])
        return copy / ".pixi" / "envs" / "default"
    venv = work / name
    run(["pixi", "exec", "--spec", "python=3.12", "python", "-m", "venv", str(venv)])
    pip = venv / ("Scripts" if os.name == "nt" else "bin") / "pip"
    run([str(pip), "install", "--quiet", "--no-deps", "-r", str(ROOT / project)])
    return venv


def pixi_sbom_input(prefix: Path, how: str) -> list[str]:
    """What pixi-sbom is pointed at: the project's lockfile for a `lockfile` entry, every environment in an
    unpacked image merged into one document for a `rootfs` one, the installed environment otherwise, with the
    binaries' own components read too."""
    if how == "lockfile":
        return ["--lockfile", str(prefix / "package-lock.json")]
    if how == "rootfs":
        return ["--scan", str(prefix), "--merge"]
    return ["--prefix", str(prefix), "--embedded-sboms"]


def grype(sbom: Path, db: Path) -> dict:
    """Grype's findings for a document, as JSON."""
    env = {**os.environ, "GRYPE_DB_CACHE_DIR": str(db), "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
    result = run(["pixi", "exec", "--spec", GRYPE, "grype", f"sbom:{sbom}", "-q", "-o", "json"], env=env)
    return json.loads(result.stdout)


def main(argv: list[str] | None = None) -> int:
    """Run the comparison over the corpus and report it."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", action="append", help="run only these corpus environments")
    parser.add_argument("--work", type=Path, default=ROOT / "target" / "grype-compare")
    parser.add_argument("--pixi-sbom", type=Path, default=ROOT / "target" / "debug" / "pixi-sbom")
    parser.add_argument("--db", type=Path, default=ROOT / "target" / "grype-db", help="Grype's database cache")
    args = parser.parse_args(argv)
    exceptions = load_exceptions(EXCEPTIONS.read_text(encoding="utf-8"))
    corpus = [c for c in CORPUS if not args.only or c[0] in args.only]
    if not corpus:
        sys.stderr.write(f"error: no corpus environment named {args.only}\n")
        return 1
    shutil.rmtree(args.work, ignore_errors=True)
    args.work.mkdir(parents=True)
    db = args.db
    unexplained = 0
    for name, project, how in corpus:
        prefix = install(name, project, how, args.work)
        syft_sbom = args.work / f"{name}.syft.json"
        pixi_sbom = args.work / f"{name}.cdx.json"
        default_sbom = args.work / f"{name}.default.cdx.json"
        run(
            ["pixi", "exec", "--spec", SYFT, "syft", "scan", f"dir:{prefix}", "-q", *SYFT_EXTRA.get(name, []),
             "-o", f"syft-json={syft_sbom}"]
        )
        # Offline: everything pixi-sbom needs to be matched is on disk or in its own tables.
        run(
            [str(args.pixi_sbom), *pixi_sbom_input(prefix, how), "--primary-purl", "pypi", "--output", str(pixi_sbom), "-q"],
            env={**os.environ, "PIXI_SBOM_OFFLINE": "1"},
        )
        run(
            [str(args.pixi_sbom), *pixi_sbom_input(prefix, how), "--output", str(default_sbom), "-q"],
            env={**os.environ, "PIXI_SBOM_OFFLINE": "1"},
        )
        recommended = findings(grype(pixi_sbom, db))
        # Where the lockfile is the subject, its entries are what is compared.
        lockfile_entries = (
            set() if how == "lockfile" else not_installed(json.loads(syft_sbom.read_text(encoding="utf-8")))
        )
        result = compare(
            name, findings(grype(syft_sbom, db), COMPARED_TYPES, lockfile_entries), recommended, exceptions
        )
        lost = default_gap(recommended, findings(grype(default_sbom, db)))
        sys.stderr.write(
            f"{name}: {len(result.agree)} agree, {len(result.syft_only)} syft-only, "
            f"{len(result.excepted)} excepted, {len(result.pixi_only)} pixi-sbom-only; "
            f"{len(lost)} lost with default flags (without --primary-purl pypi)\n"
        )
        for finding in sorted(result.syft_only):
            sys.stderr.write(f"  FAIL syft-only: {finding.vulnerability} {finding.package} {finding.version}\n")
        for finding in sorted(result.pixi_only):
            sys.stderr.write(f"  pixi-sbom-only: {finding.vulnerability} {finding.package} {finding.version}\n")
        unexplained += len(result.syft_only)
        for vulnerability, package in sorted(missing_required(name, recommended)):
            sys.stderr.write(f"  FAIL required: {vulnerability} {package} not found in pixi-sbom's document\n")
            unexplained += 1
    env = {**os.environ, "GRYPE_DB_CACHE_DIR": str(db), "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
    status = run(["pixi", "exec", "--spec", GRYPE, "grype", "db", "status", "-o", "json"], env=env)
    sys.stderr.write(f"Grype database built {json.loads(status.stdout).get('built', 'unknown')}\n")
    if unexplained:
        sys.stderr.write(
            f"{unexplained} syft-only or required finding(s) missing: fix pixi-sbom or add an exception with a reason\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
