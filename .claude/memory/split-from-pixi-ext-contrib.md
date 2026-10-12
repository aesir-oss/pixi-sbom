---
name: split-from-pixi-ext-contrib
description: "pixi-sbom was split back out of the aesir-oss/pixi-ext-contrib monorepo in October 2026: what came with it and what stayed behind"
metadata:
  type: project
---

pixi-sbom started in millsks/pixi-sbom, moved into the aesir-oss/pixi-ext-contrib Cargo workspace on 2026-10-11
(releases 1.12.0 to 1.13.1, tagged `pixi-sbom-vX.Y.Z` there), and moved to this repository in October 2026 (plan:
aesir-oss/pixi-ext-contrib#131). Its whole history came with it, so commit messages reference both earlier
repositories' issues and PRs by number.

- The tags of every release are here as `vX.Y.Z`, but the GitHub releases, archives and attestations of 1.12.0 to
  1.13.1 stay in pixi-ext-contrib (archived) and those up to 1.11.x in millsks/pixi-sbom (which still serves
  `uses: millsks/pixi-sbom@v1`; never delete or rename it).
- The code once shared with pixi-policy is this crate's own again (see [[architecture-decisions]]); pixi-policy keeps
  its own copy, and nothing keeps the two in step.
- The docs for 1.12.0 to 1.13.1 stay on aesir-oss.github.io/pixi-ext-contrib/pixi-sbom/; this repository's site starts
  with 1.13.2.

**Why:** the maintainer wanted each extension in its own repository, so either can be handed to a new owner by
transferring one repository.

**How to apply:** links to the earlier repositories in old commits, the changelog and What's new are history; do not
rewrite them. New issues and PRs live here.
