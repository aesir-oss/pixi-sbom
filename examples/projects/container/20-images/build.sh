#!/usr/bin/env bash
# Rebuild the two unpacked container images in this directory (#31): build each image from the
# example lockfiles, export its filesystem, and keep only what pixi-sbom and syft read from an
# installed environment. Needs docker (or podman as `docker`) and jq; takes a few minutes, mostly
# the linux/amd64 builds.
#
#   examples/projects/container/20-images/build.sh            # both
#   examples/projects/container/20-images/build.sh pixi-app   # one
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
projects="$(cd "$here/../.." && pwd)"
[ "$#" -gt 0 ] || set -- python-app pixi-app

for app in "$@"; do
  tag="pixi-sbom-example/${app}"
  docker build --platform linux/amd64 -q -f "$here/${app}.Dockerfile" -t "$tag" "$projects" > /dev/null
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  container="$(docker create --platform linux/amd64 "$tag")"
  docker export "$container" | tar -x -C "$work" 2> /dev/null || true
  docker rm "$container" > /dev/null
  # What an installed environment is read from: conda records, venv configuration, every installed
  # distribution's metadata, the interpreter's version header and its (small) executable, and the
  # distribution's os-release. Everything else, libraries and code included, is left behind.
  rm -rf "$here/$app"
  rsync -a --prune-empty-dirs \
    --include='*/' \
    --include='etc/os-release' \
    --include='**/conda-meta/**' \
    --include='pyvenv.cfg' \
    --include='**/site-packages/*.dist-info/**' \
    --include='**/site-packages/*.egg-info/**' \
    --include='**/include/python3*/patchlevel.h' \
    --include='usr/local/bin/python3*' \
    --include='app/.venv/bin/python*' \
    --exclude='*' \
    "$work/" "$here/$app/"
  # Each file's hash and size from the conda records: four fifths of their bytes, and read by neither tool.
  find "$here/$app" -path '*/conda-meta/*.json' -print0 | while IFS= read -r -d '' record; do
    jq --indent 1 'del(.paths_data)' "$record" > "$record.tmp" && mv "$record.tmp" "$record"
  done
  rm -rf "$work"
  trap - EXIT
  image="$(docker image inspect --format '{{.Id}}' "$tag")"
  echo "$app: $(find "$here/$app" -type f | wc -l | tr -d ' ') files from $tag ($image)"
done
