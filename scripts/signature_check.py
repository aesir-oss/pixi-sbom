"""Check the bundled-library signatures (data/signatures.toml) against conda-forge's own builds, run weekly (#23).

A signature stops working when a library changes how it spells its version, or a toolchain changes the code
a version function compiles to. For each library and each of Linux, macOS and Windows, this downloads
conda-forge's latest build, puts the library's files in a wheel's `.libs` directory inside a scratch
environment, describes it with `pixi sbom --prefix --embedded-sboms`, and checks the version that comes out
is the package's own. The report says which did not; the exit status is 1 when any did not.

    pixi run signature-check --report target/signature-check.md [--only libwebp]
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
import zipfile
from compression import zstd
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
SIGNATURES = ROOT / "crates" / "pixi-sbom" / "data" / "signatures.toml"
ANACONDA = "https://api.anaconda.org/package/conda-forge/"
# One per object file format: ELF, Mach-O and PE.
PLATFORMS = ("linux-64", "osx-arm64", "win-64")


@dataclass(frozen=True)
class Result:
    """What one library's build for one platform gave."""

    library: str
    platform: str
    package: str
    expected: str
    found: list[str]
    files: list[str]

    @property
    def ok(self) -> bool:
        """Whether the package's own version came out of its files."""
        return self.expected in self.found


def signatures(text: str) -> dict[str, dict]:
    """The signature table, by library name."""
    return tomllib.loads(text)["library"]


def is_named(stems: list[str], file_name: str) -> bool:
    """Whether a file name is one of the library's: a stem, then nothing, a `.`, `-` or `_` (as pixi-sbom matches)."""
    for stem in stems:
        rest = file_name[len(stem) :] if file_name.startswith(stem) else None
        if rest is not None and (rest == "" or rest[0] in ".-_"):
            return True
    return False


def latest_build(files: list[dict], platform: str) -> dict | None:
    """The newest `.conda` build anaconda.org lists for a platform, by upload time."""
    builds = [
        f
        for f in files
        if f.get("attrs", {}).get("subdir") == platform and f.get("basename", "").endswith(".conda")
    ]
    return max(builds, key=lambda f: f.get("upload_time", ""), default=None)


def extract(archive: bytes) -> dict[str, bytes]:
    """The files of a `.conda` package: the `pkg-*.tar.zst` inside the zip, by path."""
    out: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as outer:
        for name in outer.namelist():
            if not (name.startswith("pkg-") and name.endswith(".tar.zst")):
                continue
            with tarfile.open(fileobj=io.BytesIO(zstd.decompress(outer.read(name)))) as tar:
                for member in tar.getmembers():
                    handle = tar.extractfile(member) if member.isfile() else None
                    if handle is not None:
                        out[member.name] = handle.read()
    return out


def scratch_environment(root: Path, libraries: dict[str, bytes]) -> Path:
    """A venv-shaped prefix whose one pip-installed distribution, `probe`, carries `libraries` in `probe.libs/`
    as auditwheel would, so pixi-sbom reads them as it reads a real wheel's."""
    site_packages = root / "lib" / "python3.14" / "site-packages"
    libs = site_packages / "probe.libs"
    dist_info = site_packages / "probe-1.0.dist-info"
    libs.mkdir(parents=True)
    dist_info.mkdir()
    record = []
    for name, data in sorted(libraries.items()):
        (libs / name).write_bytes(data)
        record.append(f"probe.libs/{name},,")
    (dist_info / "METADATA").write_text("Metadata-Version: 2.1\nName: probe\nVersion: 1.0\n", encoding="utf-8")
    (dist_info / "INSTALLER").write_text("pip\n", encoding="utf-8")
    record.append("probe-1.0.dist-info/METADATA,,")
    (dist_info / "RECORD").write_text("\n".join(record) + "\n", encoding="utf-8")
    return root


def versions_found(document: dict, library: str) -> list[str]:
    """The versions a pixi-sbom document gives the library's components."""
    return sorted(c.get("version", "") for c in document.get("components", []) if c.get("name") == library)


def report(results: list[Result], missing: list[str]) -> str:
    """The Markdown report."""
    failed = [r for r in results if not r.ok]
    lines = [
        "# Bundled-library signature check",
        "",
        f"{len(results) - len(failed)} of {len(results)} builds gave their own version.",
        "",
        "| Library | Platform | Package | Expected | Found | Files |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        found = ", ".join(r.found) or "nothing"
        mark = "" if r.ok else " **(failed)**"
        lines.append(
            f"| {r.library} | {r.platform} | {r.package} | {r.expected} | {found}{mark} | {', '.join(r.files)} |"
        )
    if missing:
        lines += ["", "No build or no file named like the library:", ""]
        lines += [f"- {m}" for m in missing]
    return "\n".join(lines) + "\n"


def get(url: str) -> bytes:
    """Fetch a URL."""
    request = urllib.request.Request(url, headers={"User-Agent": "pixi-sbom-signature-check"})
    with urllib.request.urlopen(request, timeout=300) as response:
        return response.read()


def check(binary: Path, library: str, signature: dict, platform: str, scratch: Path) -> Result | str:
    """Read one library's latest build for one platform through pixi-sbom, from the first of its conda packages
    that ships the library's shared files (`zlib` holds only the static library, `libzlib` the shared one); a
    string says why nothing could be checked."""
    first: Result | None = None
    for package in signature["conda"]:
        build = latest_build(json.loads(get(f"{ANACONDA}{package}/files")), platform)
        if build is None:
            continue
        url = build["download_url"]
        files = extract(get(url if url.startswith("http") else f"https:{url}"))
        named = {
            PurePosixPath(path).name: data
            for path, data in files.items()
            if is_named(signature["files"], PurePosixPath(path).name)
        }
        if not named:
            continue
        prefix = scratch_environment(scratch / f"{library}-{platform}-{package}", named)
        result = subprocess.run(
            [str(binary), "--prefix", str(prefix), "--embedded-sboms", "--output", "-", "-q"],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "PIXI_SBOM_OFFLINE": "1"},
        )
        if result.returncode != 0:
            return f"{library} {platform}: pixi-sbom failed: {result.stderr.strip()[-300:]}"
        outcome = Result(
            library=library,
            platform=platform,
            package=f"{package} {build['version']}",
            expected=build["version"],
            found=versions_found(json.loads(result.stdout), library),
            files=sorted(named),
        )
        if outcome.found:
            return outcome
        first = first or outcome
    return first or f"{library} {platform}"


def main(argv: list[str] | None = None) -> int:
    """Run the check and write the report."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--only", action="append", default=[], help="check only this library (repeatable)")
    parser.add_argument("--pixi-sbom", type=Path, default=ROOT / "target" / "debug" / "pixi-sbom")
    args = parser.parse_args(argv)
    table = signatures(SIGNATURES.read_text(encoding="utf-8"))
    results: list[Result] = []
    missing: list[str] = []
    with tempfile.TemporaryDirectory() as scratch:
        for library, signature in sorted(table.items()):
            if args.only and library not in args.only:
                continue
            for platform in PLATFORMS:
                outcome = check(args.pixi_sbom, library, signature, platform, Path(scratch))
                if isinstance(outcome, str):
                    missing.append(outcome)
                    sys.stderr.write(f"{outcome}: nothing to check\n")
                else:
                    results.append(outcome)
                    sys.stderr.write(f"{library} {platform}: expected {outcome.expected}, found {outcome.found}\n")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report(results, missing), encoding="utf-8")
    return 0 if results and all(r.ok for r in results) and not missing else 1


if __name__ == "__main__":
    sys.exit(main())
