Project memory for aesir-oss/pixi-ext-contrib. Committed and public: nothing private or employer-related belongs here.
Issue and PR numbers from before 2026-10-11 refer to millsks/pixi-sbom.

- [Architecture decisions](architecture-decisions.md) — rattler_lock, own CycloneDX/SPDX models, one SBOM per environment and platform, the workspace
- [Roadmap](roadmap.md) — release-by-release history and plans, from 0.1.0 to the move and pixi-policy
- [Not a scanner](not-a-scanner.md) — replace Syft, feed Grype; no new vulnerability sources or vuln DB
- [Minimal enrichment defaults](feedback-minimal-defaults.md) — the fact by default, bulky payloads behind their own flag
- [Issue delivery loop](issue-delivery-loop.md) — "guardrail"/"harness" = global CLAUDE.md §6 loop; merge with --squash --admin --delete-branch; never cut a release unasked
- [Force-push permission](force-push-permission.md) — own feature branches, and the stale-check trap behind it
- [Changelog generation](release-notes-span-last-tag.md) — anchored tag_pattern; per-extension changelog filtered by path, pre-move history appended whole; fix the generator, never the file
- [Marketplace listing](marketplace-listing.md) — the action ships from aesir-oss/pixi-sbom-action; its listing needs a new name
- [Concurrent CI runs SIGKILL](concurrent-ci-sigkill.md) — SIGKILL in cov = two ci runs overlapping (mine + stop hook), not a failing test
- [Concurrent sessions and the Stop hook](concurrent-sessions-stop-hook.md) — two sessions in one tree: CI runs kill each other; mass failures may not be real
- [Dev environment](dev-environment.md) — local quirks: the Stop hook, pre-commit through pixi, tests reading repo-root files
- [Releases are never latest](releases-never-latest.md) — monorepo: every component release, final or rc, is published with latest=false; never resolve releases/latest
