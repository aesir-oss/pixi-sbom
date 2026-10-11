# License policy with pixi-policy

pixi-policy's `[licenses]` table is the policy-file form of pixi-sbom's license gate (`--allow-license`,
`--deny-license`, `--require-license`). Both tools evaluate a license with the same shared verdict, so a package that
fails one fails the other.

```toml
# pixi-policy.toml
[licenses]
allow = ["MIT", "BSD-3-Clause", "Apache-2.0", "PSF-2.0"]
review = ["LGPL-*"]
deny = ["GPL-3.0-*", "AGPL-*"]
unknown = "warn"   # or "error", "allow"
```

| Rule | Severity | Finds a package whose license… |
|---|---|---|
| `licenses.deny` | error | cannot be satisfied without a `deny` license (`MIT OR GPL-3.0-only` passes: MIT is an option) |
| `licenses.not-allowed` | error | cannot be satisfied with `allow` and `review` licenses alone (only when `allow` is given) |
| `licenses.review` | warning | needs a `review` license |
| `licenses.unknown` | `unknown` | is missing, or is not an SPDX expression |

Entries are SPDX identifiers, or patterns with `*` that are expanded against the SPDX license list (`LGPL-*` is every
LGPL identifier). An `-or-later` entry accepts later versions of the same license, as in pixi-sbom.

## Moving from pixi-sbom's flags

| pixi-sbom | pixi-policy |
|---|---|
| `--allow-license MIT --allow-license Apache-2.0` | `[licenses] allow = ["MIT", "Apache-2.0"]` |
| `--deny-license GPL-3.0-only` | `[licenses] deny = ["GPL-3.0-only"]` |
| `--require-license` | `[licenses] unknown = "error"` |
| no `--require-license` | `[licenses] unknown = "allow"` (the default, `"warn"`, reports them without failing) |
| `--ignore-license PACKAGE:WHY` | a waiver with a reason and an expiry date (#66) |
| (no equivalent) | `[licenses] review = [...]`, reported as warnings |
| exit code 3 on a violation | exit code 1 on an error finding |

## What pixi-policy reads

Licenses come from `pixi.lock` only, offline. It records them for conda packages and never for PyPI ones, so every PyPI
package is `licenses.unknown` until pixi-policy 0.2.0 reads license files; set `unknown = "allow"` to stop those
warnings meanwhile. pixi-sbom's gate also covers npm packages it reads from a `package-lock.json` (and licenses it
fetches with `--fetch-licenses`); pixi-policy checks the packages in `pixi.lock`.
