"""Tests for the bundled-library signature check. Run with `pixi run signature-check-test`."""

from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
import zipfile
from compression import zstd
from pathlib import Path

import signature_check as s


def conda_archive(files: dict[str, bytes]) -> bytes:
    """A `.conda` package: a zip holding `pkg-*.tar.zst` with `files`."""
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("metadata.json", "{}")
        archive.writestr("pkg-demo-1.0-0.tar.zst", zstd.compress(tar_bytes.getvalue()))
        archive.writestr("info-demo-1.0-0.tar.zst", zstd.compress(b""))
    return out.getvalue()


class SignatureCheckTest(unittest.TestCase):
    def test_the_shipped_table_loads(self) -> None:
        table = s.signatures(s.SIGNATURES.read_text(encoding="utf-8"))
        self.assertIn("libwebp", table)
        for name, signature in table.items():
            self.assertTrue(signature["conda"] and signature["files"], name)

    def test_file_names_match_as_pixi_sbom_matches_them(self) -> None:
        stems = ["libwebp", "libwebpdecoder"]
        for name in ["libwebp.so.7", "libwebp-3a2b.so.7", "libwebp.dll", "libwebpdecoder.3.dylib", "libwebp"]:
            self.assertTrue(s.is_named(stems, name), name)
        for name in ["libwebpmux.so.3", "webp.dll", "libwebp2.so"]:
            self.assertFalse(s.is_named(stems, name), name)

    def test_the_newest_conda_build_for_the_platform(self) -> None:
        files = [
            {"basename": "linux-64/a-1.0-0.conda", "attrs": {"subdir": "linux-64"}, "upload_time": "2026-01-01"},
            {"basename": "linux-64/a-1.1-0.conda", "attrs": {"subdir": "linux-64"}, "upload_time": "2026-03-01"},
            {"basename": "linux-64/a-1.2-0.tar.bz2", "attrs": {"subdir": "linux-64"}, "upload_time": "2026-04-01"},
            {"basename": "win-64/a-1.3-0.conda", "attrs": {"subdir": "win-64"}, "upload_time": "2026-05-01"},
        ]
        self.assertEqual(s.latest_build(files, "linux-64")["basename"], "linux-64/a-1.1-0.conda")
        self.assertIsNone(s.latest_build(files, "osx-arm64"))

    def test_a_conda_package_is_read_from_its_pkg_tarball(self) -> None:
        files = s.extract(conda_archive({"lib/libz.so.1": b"\x7fELF", "include/zlib.h": b"/* */"}))
        self.assertEqual(files, {"lib/libz.so.1": b"\x7fELF", "include/zlib.h": b"/* */"})

    def test_the_scratch_environment_is_a_wheel_s_libs_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prefix = s.scratch_environment(Path(tmp) / "env", {"libz.so.1": b"\x7fELF"})
            site = prefix / "lib" / "python3.14" / "site-packages"
            self.assertEqual((site / "probe.libs" / "libz.so.1").read_bytes(), b"\x7fELF")
            record = (site / "probe-1.0.dist-info" / "RECORD").read_text(encoding="utf-8")
            self.assertIn("probe.libs/libz.so.1,,", record)
            self.assertIn("Name: probe", (site / "probe-1.0.dist-info" / "METADATA").read_text(encoding="utf-8"))

    def test_versions_come_from_the_library_s_components(self) -> None:
        document = {"components": [
            {"name": "zlib", "version": "1.3.1"},
            {"name": "probe", "version": "1.0"},
            {"name": "zlib", "version": "1.2.13"},
        ]}
        self.assertEqual(s.versions_found(document, "zlib"), ["1.2.13", "1.3.1"])
        self.assertEqual(s.versions_found({}, "zlib"), [])

    def test_the_report_marks_what_failed_and_what_could_not_be_checked(self) -> None:
        good = s.Result("zlib", "linux-64", "libzlib 1.3.1", "1.3.1", ["1.3.1"], ["libz.so.1"])
        bad = s.Result("expat", "win-64", "libexpat 2.7.1", "2.7.1", [], ["libexpat.dll"])
        self.assertTrue(good.ok)
        self.assertFalse(bad.ok)
        text = s.report([good, bad], ["sqlite osx-arm64"])
        self.assertIn("1 of 2 builds gave their own version.", text)
        self.assertIn("| expat | win-64 | libexpat 2.7.1 | 2.7.1 | nothing **(failed)** | libexpat.dll |", text)
        self.assertIn("| zlib | linux-64 | libzlib 1.3.1 | 1.3.1 | 1.3.1 | libz.so.1 |", text)
        self.assertIn("- sqlite osx-arm64", text)


if __name__ == "__main__":
    unittest.main()
