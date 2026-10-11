---
name: issue-delivery-loop
description: "pixi-sbom specifics for the standard guardrail/harness (issue delivery loop), which itself lives in global CLAUDE.md §6"
metadata:
  type: feedback
---

The "standard guardrail" / "harness" — branch, CI, PR, monitor to green, merge, sync main, clean branches,
then the next queued issue — is defined in global CLAUDE.md §6 "Issue delivery loop". Follow that.

pixi-ext-contrib specifics on top of it (since 2026-10-11 the repository is aesir-oss/pixi-ext-contrib; branches live in it, there is no fork):

- merge with `gh pr merge <n> --repo aesir-oss/pixi-ext-contrib --squash --admin --delete-branch` (squash is this repo's convention; `--admin` because `main`'s ruleset wants an approving review)
- PR bodies state what was measured, not just what changed
- gate the merge on the watch's exit status (`gh pr checks <n> --watch` exit 0, or zero `fail` rows),
  never on head/base checks alone: on 2026-10-07 millsks/pixi-sbom PR #375 merged with a red osx-64 job because the
  merge command only checked head and base (it was an artifact-upload timeout; a rerun went green)
- milestones and labels name the component (2026-10-11): `pixi-sbom 1.13.0`, `pixi-sbom 2.0.0`, `pixi-sbom launch`,
  and `pixi-ext-contrib` for work on the repository itself (release tooling, the shared docs site, CI). A new extension
  gets its own (`pixi-policy 0.1.0`). Every issue carries the matching label, `pixi-sbom`, `pixi-policy` or
  `pixi-ext-contrib`, and a new issue gets one when it is filed

**Why:** the maintainer gave standing permission (2026-10-03) to run queued issues without re-asking,
and on 2026-10-06 promoted the loop to global CLAUDE.md as their standard across all projects.

**How to apply:** treat "guardrail" or "harness" in a request as meaning that loop. Cutting a release is never part of it: ask first, every time.

Related: [[release-notes-span-last-tag]].
