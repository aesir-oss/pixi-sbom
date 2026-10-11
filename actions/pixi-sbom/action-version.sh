#!/usr/bin/env bash
# Prints the pixi-sbom version the action should install, without the leading `v`.
#
#   INPUT_VERSION  the action's `version` input; wins when set
#   ACTION_REF     github.action_ref: `v1.0.0` or `pixi-sbom-v1.0.0` pins that release, `v1` or
#                  `pixi-sbom-v1` the newest 1.x.y release, anything else (a branch, a sha, `./`)
#                  the newest release
#   GH_TOKEN       optional, for the GitHub API rate limit
#   RELEASES_API   space-separated release-list URLs, overridable so the test can use fixtures
#
# Releases up to 1.11.x are tagged vX.Y.Z in millsks/pixi-sbom; from 1.12.0 they are tagged
# pixi-sbom-vX.Y.Z in aesir-oss/pixi-ext-contrib. Both lists are read.
set -euo pipefail

apis="${RELEASES_API:-https://api.github.com/repos/aesir-oss/pixi-ext-contrib/releases https://api.github.com/repos/millsks/pixi-sbom/releases}"

fetch() {
  if [ -n "${GH_TOKEN:-}" ]; then
    curl -sSfL -H "Authorization: Bearer $GH_TOKEN" "$1"
  else
    curl -sSfL "$1"
  fi
}

version="${INPUT_VERSION:-}"
version="${version#pixi-sbom-}"
version="${version#v}"
ref="${ACTION_REF:-}"
ref="${ref#pixi-sbom-}"

if [ -z "$version" ] && [[ "$ref" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+ ]]; then
  version="${ref#v}"
fi

# The newest final release, or the newest in one major for a floating major tag: that tag moves with each release
# of its major, and the newest release overall would hand a v0 user a v1 binary behind v0's inputs.
newest() {
  local api
  for api in $apis; do
    fetch "${api}?per_page=100"
  done |
    grep -oE "\"tag_name\": *\"(pixi-sbom-)?v$1\.[0-9]+\.[0-9]+\"" |
    sed -E 's/.*"(pixi-sbom-)?v([^"]+)"/\2/' |
    sort -V | tail -n 1
}

if [ -z "$version" ] && [[ "$ref" =~ ^v?([0-9]+)$ ]]; then
  version=$(newest "${BASH_REMATCH[1]}" || true)
fi

if [ -z "$version" ]; then
  version=$(newest "[0-9]+")
fi

[ -n "$version" ] || { echo "::error::cannot determine the pixi-sbom version to install" >&2; exit 1; }
echo "$version"
