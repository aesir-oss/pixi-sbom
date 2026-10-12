---
hide:
  - navigation
  - toc
---

# pixi-ext-contrib

Extensions for the [pixi](https://pixi.sh) package manager. Each is a `pixi-<name>` binary that pixi runs as
`pixi <name>`, and each is released and documented on its own. This is a community project, not affiliated with
prefix.dev.

<div class="aesir-cards" id="aesir-extensions" markdown>

<div class="aesir-card" markdown>
### pixi-sbom
<p class="aesir-question">What's in it?</p>

CycloneDX and SPDX Software Bills of Materials from pixi.lock, with license, vulnerability and quality reports.

[Documentation](pixi-sbom/) · [GitHub Action](https://github.com/aesir-oss/pixi-sbom-action)
</div>

<div class="aesir-card" markdown>
### pixi-policy
<p class="aesir-question">Is it allowed?</p>

Write down what a workspace's environments may contain, and check pixi.toml and pixi.lock against it everywhere pixi
runs.

[Documentation](pixi-policy/)
</div>

</div>

## The repository

- [Source on GitHub](https://github.com/aesir-oss/pixi-ext-contrib), and its
  [issues](https://github.com/aesir-oss/pixi-ext-contrib/issues)
- [Releases](https://github.com/aesir-oss/pixi-ext-contrib/releases): the release marked Latest lists every extension's
  current version
- [Development](development.md): the toolchain, the change harness and how releases are made
- [Security policy](security.md): reporting a vulnerability privately
- [Changelogs](changelog.md): one per extension
