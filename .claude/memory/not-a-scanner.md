---
name: not-a-scanner
description: "pixi-sbom must not become a vulnerability scanner; the goal is replacing Syft (inventory) and feeding Grype, not replacing Grype"
metadata:
  type: project
---

On 2026-10-09 the user rejected expanding pixi-sbom into a scanner (no NVD/CPE matching source, no offline vulnerability DB). Direction: make pixi-sbom a full Syft replacement for conda/Python environments so any scanner (Grype) consumes its output.

**Why:** keeps the product positioned as "not a scanner (it feeds one)" per README; avoids owning vulnerability data curation.

**How to apply:** propose inventory/identity work (CPEs, purls for more ecosystems, bundled-library detection) rather than new `--vulnerabilities` sources. Existing `--vulnerabilities osv` stays as is. Related: issue millsks/pixi-sbom#431 (now #22 here).
