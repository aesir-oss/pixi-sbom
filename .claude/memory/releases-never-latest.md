---
name: releases-never-latest
description: Every component release in this monorepo is published with latest=false; no extension's release is ever marked GitHub's "Latest"
metadata:
  type: project
---

This repository is a monorepo of pixi extensions (pixi-sbom now, pixi-policy and others later), each released on
its own tag (`pixi-sbom-vX.Y.Z`). GitHub's "Latest release" badge can point at only one release in the whole
repository, so no component's release may claim it: **every release is created with latest=false**, finals as well
as release candidates.

**Why:** with several components releasing on their own schedules, "Latest" would jump between unrelated
extensions and send `releases/latest` (and anything resolving it) to whichever component shipped last. Decided by
the maintainer on 2026-10-11.

**How to apply:**

- In `release-artifacts.yml`, the `softprops/action-gh-release` step sets `make_latest: false`. With `gh`, use
  `gh release create … --latest=false` or `gh release edit <tag> --latest=false`.
- A new extension's release workflow does the same from its first release.
- Never link to or resolve `releases/latest` in docs, install scripts or the Action. Name the tag
  (`releases/download/pixi-sbom-vX.Y.Z/…`) or query the newest `pixi-sbom-v*` tag instead.

Related: [[release-notes-span-last-tag]], [[issue-delivery-loop]].
