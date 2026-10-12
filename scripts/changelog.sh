#!/usr/bin/env bash
# Add a release's section to CHANGELOG.md, below the header and above the newest section already there. The sections
# already in the file are never regenerated: those from 1.12.0 to 1.13.1 were written in aesir-oss/pixi-ext-contrib, and
# earlier ones in millsks/pixi-sbom, with links to those repositories' commits.
#
#   scripts/changelog.sh v1.13.2
set -euo pipefail
tag="${1:?usage: changelog.sh vX.Y.Z}"
file="${2:-CHANGELOG.md}"
section="$(git cliff --unreleased --tag "$tag" | sed '/./,$!d')"
first=$(grep -n '^## ' "$file" | head -1 | cut -d: -f1)
{
  head -n "$((first - 1))" "$file"
  printf '%s\n\n' "$section"
  tail -n "+$first" "$file"
} > "$file.new"
mv "$file.new" "$file"
