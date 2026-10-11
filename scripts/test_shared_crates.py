"""Tests for the shared-crate release check. Run with `pixi run shared-crates-test`."""

from __future__ import annotations

import unittest

import shared_crates

META = {
    "workspace_root": "/w",
    "packages": [
        {
            "name": "ext",
            "version": "1.0.0",
            "manifest_path": "/w/crates/ext/Cargo.toml",
            "dependencies": [
                {"name": "common", "path": "/w/crates/common"},
                {"name": "serde"},
                {"name": "testing", "path": "/w/crates/testing", "kind": "dev"},
            ],
        },
        {
            "name": "common",
            "version": "0.2.0",
            "manifest_path": "/w/crates/common/Cargo.toml",
            "dependencies": [{"name": "core", "path": "/w/crates/core"}],
        },
        {"name": "core", "version": "0.1.0", "manifest_path": "/w/crates/core/Cargo.toml", "dependencies": []},
        {"name": "testing", "version": "0.1.0", "manifest_path": "/w/crates/testing/Cargo.toml", "dependencies": []},
    ],
}


class DependenciesTest(unittest.TestCase):
    def test_path_dependencies_are_followed_and_dev_and_registry_ones_are_not(self) -> None:
        deps = shared_crates.dependencies(META, "ext")
        self.assertEqual(
            deps,
            [
                shared_crates.Dependency("common", "0.2.0", "crates/common"),
                shared_crates.Dependency("core", "0.1.0", "crates/core"),
            ],
        )
        self.assertEqual(deps[0].tag, "common-v0.2.0")
        self.assertEqual(shared_crates.dependencies(META, "core"), [])


class ProblemsTest(unittest.TestCase):
    deps = [shared_crates.Dependency("common", "0.2.0", "crates/common")]

    def check(self, tagged: bool, changed: bool, published: bool) -> list[str]:
        return shared_crates.problems(
            self.deps,
            tag_exists=lambda tag: tagged,
            changed_since=lambda tag, directory: changed,
            published=lambda name, version: published,
        )

    def test_a_released_unchanged_crate_lets_the_extension_release(self) -> None:
        self.assertEqual(self.check(tagged=True, changed=False, published=True), [])

    def test_an_unreleased_crate_stops_the_release(self) -> None:
        self.assertEqual(
            self.check(tagged=False, changed=False, published=False),
            ["common 0.2.0 has no release tag (common-v0.2.0): release it first"],
        )

    def test_changes_since_the_crate_s_release_stop_the_release(self) -> None:
        self.assertEqual(
            self.check(tagged=True, changed=True, published=True),
            ["crates/common changed since common-v0.2.0: release common first, with a new version"],
        )

    def test_a_tagged_but_unpublished_crate_stops_the_release(self) -> None:
        self.assertEqual(
            self.check(tagged=True, changed=False, published=False),
            ["common 0.2.0 is tagged but not on crates.io yet: wait for its publish job"],
        )


if __name__ == "__main__":
    unittest.main()
