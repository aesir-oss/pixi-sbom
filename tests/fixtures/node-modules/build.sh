#!/usr/bin/env bash
# Rebuild the installed node_modules fixtures (#36): examples/projects/<tool>/19-web-frontend installed
# from its lockfile by npm, yarn 1 and pnpm, then the lockfile dropped and the tree trimmed to what
# pixi-sbom reads (every package.json, the links between them, and the layout's own marker files).
# Needs the network and the examples environment's nodejs and corepack:
#
#   pixi run -e examples bash tests/fixtures/node-modules/build.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
examples="$(cd "$here/../../../../../examples/projects" && pwd)"

for tool in npm yarn pnpm; do
  work="$(mktemp -d)"
  cp "$examples/$tool/19-web-frontend/"* "$work/"
  (
    cd "$work"
    case "$tool" in
      npm) npm ci --ignore-scripts --no-audit --no-fund > /dev/null ;;
      yarn) COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack yarn@1.22.22 install --frozen-lockfile --ignore-scripts > /dev/null ;;
      pnpm) COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm@9.15.9 install --frozen-lockfile --ignore-scripts > /dev/null ;;
    esac
  )
  rm -rf "$here/$tool"
  mkdir -p "$here/$tool"
  cp "$work/package.json" "$here/$tool/"
  # Every package.json and every link, plus the files that say which tool wrote the tree.
  cp -a "$work/node_modules" "$here/$tool/node_modules"
  find "$here/$tool/node_modules" -type d -name .bin -prune -exec rm -rf {} +
  find "$here/$tool/node_modules" -type f ! -name package.json ! -name .package-lock.json \
    ! -name .yarn-integrity ! -name .modules.yaml -delete
  find "$here/$tool/node_modules" -type d -empty -delete
  rm -rf "$work"
  echo "$tool: $(find "$here/$tool" -name package.json | wc -l | tr -d ' ') package.json files, $(find "$here/$tool" -type l | wc -l | tr -d ' ') links"
done
