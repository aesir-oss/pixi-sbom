---
name: releases-never-latest
description: Extension releases are always latest=false; the repository release pixi-ext-contrib-YYYY.MM.N is the only one marked Latest
metadata:
  type: project
---

This repository is a monorepo of pixi extensions (pixi-sbom now, pixi-policy and others later), each released on
its own tag (`pixi-sbom-vX.Y.Z`). GitHub's "Latest release" badge can point at only one release in the whole
repository, so no extension's release may claim it: **every extension release is created with latest=false**, finals
as well as release candidates.

`latest=false` alone is not enough: GitHub treats the newest full release as Latest when nothing is marked (pixi-sbom
1.12.0 kept the badge after `gh release edit --latest=false`). So since #49, `repository-release.yml` publishes the
repository's own release, `pixi-ext-contrib-YYYY.MM.N`, after every successful final extension release, **marked
Latest**. It has no assets; its notes list every extension's newest final release. `scripts/repo_release.py` makes
none when nothing changed, so release candidates and re-runs are no-ops.

**Why:** with several components releasing on their own schedules, "Latest" would jump between unrelated
extensions and send `releases/latest` (and anything resolving it) to whichever component shipped last. Decided by
the maintainer on 2026-10-11; the repository release on the same day (#49).

**How to apply:**

- In `release-artifacts.yml`, the `softprops/action-gh-release` step sets `make_latest: false`. With `gh`, use
  `gh release create … --latest=false` or `gh release edit <tag> --latest=false`.
- A new extension's release workflow does the same from its first release; the repository release picks it up from
  its `<extension>-vX.Y.Z` tags with no change.
- The repository tag must never match an extension pattern (`v*`, `<extension>-v*`, `cliff.toml`, the Action's
  lookup); `pixi run repo-release-test` checks it.
- Never link to or resolve `releases/latest` in docs, install scripts or the Action: it is the repository release,
  which has no binaries. Name the tag (`releases/download/pixi-sbom-vX.Y.Z/…`) or query the newest `pixi-sbom-v*` tag.

Related: [[release-notes-span-last-tag]], [[issue-delivery-loop]].
