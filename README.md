# pixi-ext-contrib

Community pixi extensions for software supply-chain security: SBOMs, license and dependency policy, and more.

Each tool installs as a `pixi-<name>` executable, which pixi exposes as `pixi <name>`.

| Extension | Command | What it answers | Status |
|---|---|---|---|
| [pixi-sbom](crates/pixi-sbom/README.md) | `pixi sbom` | What's in this environment? CycloneDX or SPDX SBOMs from `pixi.lock` and other lockfiles | Stable (1.x) |
| pixi-policy | `pixi policy` | Is it allowed? Channel, package, license and hygiene rules for pixi environments | Planned |

## Layout

```
crates/
  pixi-sbom/     the pixi-sbom crate: source, tests, benchmarks, PyPI packaging
docs/            the documentation site
examples/        example projects and lockfiles the tests and docs run against
scripts/         maintenance and release tooling
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
