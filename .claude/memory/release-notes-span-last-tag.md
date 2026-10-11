---
name: release-notes-span-last-tag
description: git-cliff treated pixi-sbom rc tags as releases, so a stable release documented only what landed since its last rc
metadata:
  type: project
---

`cliff.toml`'s `tag_pattern` was unanchored (`^v[0-9]+\.[0-9]+\.[0-9]+`), so `v1.5.0-rc.1` matched
it and every release candidate became its own changelog section. A stable release cut after an rc
cycle then documented only the commits since the last rc — for v1.5.0 that was one commit out of
eleven.

Fixed 2026-10-04 by anchoring the pattern with `$` (millsks/pixi-sbom PR #316), which makes prerelease tags invisible
to git-cliff so sections span stable to stable.

**Why:** I first saw this after v1.4.0 and recorded it as "check the release body afterwards and
edit it by hand" — treating a generator bug as a manual cleanup step. It recurred immediately, and
the maintainer caught it, not me. A fix that depends on remembering to check is not a fix.

**How to apply:** if changelog sections ever look thin again, check `tag_pattern` before reaching
for a manual edit. More generally: when something generated comes out wrong, fix the generator
rather than writing a reminder to correct its output.

Since the move (2026-10-11) the pattern is `^(pixi-sbom-)?v[0-9]+\.[0-9]+\.[0-9]+$`: plain `vX.Y.Z` tags are
the releases made in millsks/pixi-sbom and `pixi-sbom-vX.Y.Z` the ones made here, still anchored so release
candidates stay invisible. The template links `(#N)` in `v`-tagged releases to millsks/pixi-sbom and later ones
here; the same rule applies: change `cliff.toml`, never `CHANGELOG.md`.

Note that GitHub release bodies published *before* the fix still under-report; editing those is an
outward-facing change and is the maintainer's call.

Related: [[issue-delivery-loop]].
