"""Tests for the per-extension changelog. Run with `pixi run changelog-test`."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import changelog


def _manifest(name: str, depends: tuple[str, ...] = (), dev: tuple[str, ...] = (), extra: str = "") -> str:
    lines = [f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2024"\n', extra, "[dependencies]"]
    lines += [f'{d} = {{ path = "../{d}" }}' for d in depends]
    lines += ["[dev-dependencies]"] + [f'{d} = {{ path = "../{d}" }}' for d in dev]
    return "\n".join(lines) + "\n"


class Workspace:
    """A throwaway Cargo workspace in its own git repository: alpha depends on common, beta on nothing."""

    def __init__(self, root: Path, alpha_extra: str = "") -> None:
        self.root = root
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Test")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "tag.gpgsign", "false")
        self.write("Cargo.toml", '[workspace]\nresolver = "3"\nmembers = ["crates/*"]\n')
        crates = {
            "alpha": _manifest("alpha", ("common",), ("beta",), alpha_extra),
            "beta": _manifest("beta"),
            "common": _manifest("common"),
        }
        for name, manifest in crates.items():
            self.write(f"crates/{name}/Cargo.toml", manifest)
            self.write(f"crates/{name}/src/lib.rs", "")
        self.commit("chore: the workspace")

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)

    def write(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def commit(self, message: str, *paths: str) -> None:
        for path in paths:
            self.write(path, message)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)


class CandidateTest(unittest.TestCase):
    def test_a_hyphen_after_the_version_is_a_release_candidate(self) -> None:
        self.assertTrue(changelog.is_candidate("pixi-sbom-v1.13.0-rc.1"))
        self.assertTrue(changelog.is_candidate("v1.0.0-beta.2"))
        self.assertFalse(changelog.is_candidate("pixi-sbom-v1.13.0"))
        self.assertFalse(changelog.is_candidate("aesir-pixi-ext-contrib-common-v0.1.0"))


class IncludePathsTest(unittest.TestCase):
    def test_a_crate_brings_the_crates_it_depends_on_and_the_paths_it_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Workspace(Path(tmp).resolve(), '[package.metadata.changelog]\ninclude = ["docs/**"]\n')
            meta = changelog.metadata(ws.root)
            self.assertEqual(changelog.include_paths(meta, "alpha"), ["crates/alpha/**", "crates/common/**", "docs/**"])
            self.assertEqual(changelog.include_paths(meta, "beta"), ["crates/beta/**"])

    def test_a_dependency_is_followed_through_another_workspace_crate(self) -> None:
        meta = {
            "workspace_root": "/w",
            "packages": [
                {"name": "a", "manifest_path": "/w/crates/a/Cargo.toml", "dependencies": [{"path": "/w/crates/b"}]},
                {"name": "b", "manifest_path": "/w/crates/b/Cargo.toml", "dependencies": [{"path": "/w/crates/c"}]},
                {"name": "c", "manifest_path": "/w/crates/c/Cargo.toml", "dependencies": [{"path": "/w/crates/a"}]},
            ],
        }
        self.assertEqual(changelog.include_paths(meta, "a"), ["crates/a/**", "crates/b/**", "crates/c/**"])

    def test_an_unknown_crate_or_setting_is_an_error(self) -> None:
        meta = {
            "workspace_root": "/w",
            "packages": [
                {
                    "name": "a",
                    "manifest_path": "/w/crates/a/Cargo.toml",
                    "dependencies": [],
                    "metadata": {"changelog": {"includes": ["docs/**"]}},
                }
            ],
        }
        with self.assertRaisesRegex(changelog.ChangelogError, "no workspace crate named 'z'"):
            changelog.include_paths(meta, "z")
        with self.assertRaisesRegex(changelog.ChangelogError, "unknown keys: \\['includes'\\]"):
            changelog.include_paths(meta, "a")


class ChangelogTest(unittest.TestCase):
    def test_only_commits_to_the_crate_and_what_it_depends_on_appear(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Workspace(Path(tmp).resolve())
            ws.commit("feat: alpha learns a trick", "crates/alpha/src/trick.rs")
            ws.commit("chore(release): alpha-v1.0.0", "crates/alpha/Cargo.lock")
            ws.git("tag", "-a", "alpha-v1.0.0", "-m", "alpha-v1.0.0")
            ws.commit("feat: beta alone changes", "crates/beta/src/beta.rs")
            ws.commit("fix: the shared code is fixed", "crates/common/src/shared.rs")
            ws.commit("feat: alpha candidate work", "crates/alpha/src/rc.rs")
            ws.git("tag", "-a", "alpha-v1.1.0-rc.1", "-m", "rc")
            ws.commit("ci: repository-wide workflow", ".github/workflows/ci.yml")
            meta = changelog.metadata(ws.root)

            text = changelog.changelog(meta, "alpha", "alpha-v1.1.0", ws.root)
            self.assertIn("## 1.1.0", text)
            self.assertIn("## 1.0.0", text)
            self.assertNotIn("rc.1", text, "a release candidate is not a section of its own")
            new = text.split("## 1.0.0")[0]
            self.assertIn("The shared code is fixed", new)
            self.assertIn("Alpha candidate work", new)
            self.assertNotIn("Beta alone changes", text)
            self.assertNotIn("Repository-wide workflow", text)

            notes = changelog.notes(meta, "alpha", ws.root)
            self.assertIn("## 1.0.0", notes)
            self.assertNotIn("# Changelog", notes)

            # #88: a release candidate's notes are what it adds since the last final, under its own version.
            candidate = changelog.notes(meta, "alpha", ws.root, tag="alpha-v1.1.0-rc.1")
            self.assertIn("## 1.1.0-rc.1", candidate)
            self.assertIn("Alpha candidate work", candidate)
            self.assertIn("The shared code is fixed", candidate)
            self.assertNotIn("## 1.0.0", candidate)
            self.assertNotIn("Alpha learns a trick", candidate)
            self.assertNotIn("Beta alone changes", candidate)
            # A final's are its own section, as before.
            self.assertEqual(changelog.notes(meta, "alpha", ws.root, tag="alpha-v1.0.0"), notes)

    def test_history_before_the_move_is_kept_whole(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            extra = '[package.metadata.changelog]\nhistory-before = "v0.9.0"\n'
            ws = Workspace(Path(tmp).resolve(), extra)
            ws.commit("feat: written at the old root", "src/old.rs")
            ws.git("tag", "-a", "v0.9.0", "-m", "v0.9.0")
            ws.commit("feat: written at the old root after the move", "src/later.rs")
            ws.commit("feat: alpha after the move", "crates/alpha/src/new.rs")
            meta = changelog.metadata(ws.root)

            text = changelog.changelog(meta, "alpha", "alpha-v1.0.0", ws.root)
            self.assertLess(text.index("## 1.0.0"), text.index("## 0.9.0"))
            self.assertEqual(text.count("# Changelog"), 1)
            self.assertIn("Written at the old root (", text)
            self.assertIn("Alpha after the move", text)
            self.assertNotIn("Written at the old root after the move", text)

    def test_the_changelog_lives_beside_the_crate(self) -> None:
        meta = {"packages": [{"name": "a", "manifest_path": "/w/crates/a/Cargo.toml"}]}
        self.assertEqual(changelog.changelog_file(meta, "a"), Path("/w/crates/a/CHANGELOG.md"))


if __name__ == "__main__":
    unittest.main()
