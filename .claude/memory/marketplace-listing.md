---
name: marketplace-listing
description: Where the pixi-sbom GitHub Action is listed and published, and the name clash the new listing must avoid
metadata:
  type: project
---

The action was listed on the GitHub Marketplace from `millsks/pixi-sbom`'s v1.0.0 release (millsks/pixi-sbom#234)
as "pixi-sbom". Since 2026-10-11 its source is `actions/pixi-sbom/` in this repository, and the `action-repo` job in
`release-artifacts.yml` copies it to `aesir-oss/pixi-sbom-action` on every release, tags `vX.Y.Z` and moves `vX`.
`uses: millsks/pixi-sbom@v1` keeps working; that repository is to be archived after 1.12.0, once its action.yml
looks up releases in both repositories.

**Why:** the Marketplace lists one action per repository, with `action.yml` at its root, and action names are
unique: the new listing cannot be called "pixi-sbom" while the old one exists.

**How to apply:** publishing the new listing is a manual step on a release page of `aesir-oss/pixi-sbom-action`
(tick "Publish this Action to the GitHub Marketplace"; no API). Change `name:` in `actions/pixi-sbom/action.yml`
first, or delist the old one. Docs say `uses: aesir-oss/pixi-sbom-action@v1`. pixi-policy gets the same shape in
`aesir-oss/pixi-policy-action`.
