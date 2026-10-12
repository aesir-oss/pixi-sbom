---
name: releases
description: "How pixi-sbom releases: tags vX.Y.Z, rc to TestPyPI and final to PyPI, the action and pre-commit mirrors on a final, a field test after every rc"
metadata:
  type: project
---

- Releases start from the Release workflow (`version` input) and are tagged `vX.Y.Z`; the tag starts Release
  artifacts. Archives are `pixi-sbom-vX.Y.Z-<platform>`, with provenance attestations signed by this repository's
  `release-artifacts.yml`. A final needs a non-empty `## Unreleased` on `docs/whats-new.md`, which becomes its section.
- A release candidate (`1.13.2-rc.1`) is a GitHub pre-release and goes to TestPyPI; a final goes to PyPI, is this
  repository's Latest release, and updates aesir-oss/pixi-sbom-action (`vX.Y.Z`, and `v1` moved) and
  aesir-oss/pixi-sbom-pre-commit. The docs deploy under the version; a final also moves `latest`.
- After every release candidate the maintainer's field-test checklist is run against the published files before a
  final is cut. Ask before cutting any release.
- Where releases live: up to 1.11.x millsks/pixi-sbom (tags `vX.Y.Z`), 1.12.0 to 1.13.1 aesir-oss/pixi-ext-contrib
  (tags `pixi-sbom-vX.Y.Z`), from 1.13.2 here. The action reads all three release lists; keep it that way.
- conda-forge builds from the `v*` source tarballs; the feedstock's bot follows new tags.

Related: [[issue-delivery-loop]], [[split-from-pixi-ext-contrib]], [[release-notes-span-last-tag]].
