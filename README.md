# pixi-ext-contrib

Community pixi extensions for software supply-chain security: SBOMs, license and dependency policy, and more.

Each tool installs as a `pixi-<name>` executable, which pixi exposes as `pixi <name>`. Documentation:
https://aesir-oss.github.io/pixi-ext-contrib/

| Extension | Command | What it answers | Status |
|---|---|---|---|
| [pixi-sbom](crates/pixi-sbom/README.md) | `pixi sbom` | What's in this environment? CycloneDX or SPDX SBOMs from `pixi.lock` and other lockfiles | Stable (1.x) |
| [pixi-policy](crates/pixi-policy/README.md) | `pixi policy` | Is it allowed? Channel, package, license and hygiene rules for pixi environments | Release candidate (0.1.0) |

## Layout

```
crates/
  pixi-ext-common/  code the extensions share, compiled into each; never released
  pixi-policy/      the pixi-policy crate: source, tests, docs, PyPI packaging
  pixi-sbom/        the pixi-sbom crate: source, tests, docs, benchmarks, PyPI packaging
docs/             the workspace docs site: the extensions page, development, security
examples/         example projects and lockfiles the tests and docs run against
scripts/          maintenance and release tooling
```

## Development

Everything runs through [pixi](https://pixi.sh):

```sh
pixi run test   # unit and end-to-end tests
pixi run ci     # the full gate: pre-commit, build, check, lint, coverage
```

See [docs/development.md](docs/development.md) for the details.

## License

[Apache-2.0](LICENSE). A community project, not affiliated with prefix.dev.
