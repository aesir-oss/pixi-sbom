# pixi-ext-common

Code shared by the pixi extensions in [aesir-oss/pixi-ext-contrib](https://github.com/aesir-oss/pixi-ext-contrib):
license normalization and the license verdict, the lockfile facts, package URLs, output that a closed pipe ends
quietly, and terminal colour.

**This crate is not an API and is not published.** Each extension compiles it from this repository as a path
dependency (#106); its modules move, split and change whenever the extensions need them to. It is not affiliated
with prefix.dev or the pixi project.
