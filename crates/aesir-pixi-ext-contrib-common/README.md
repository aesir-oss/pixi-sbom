# aesir-pixi-ext-contrib-common

Code shared by the pixi extensions in [aesir-oss/pixi-ext-contrib](https://github.com/aesir-oss/pixi-ext-contrib):
license normalization, output that a closed pipe ends quietly, and terminal colour.

**This crate is not an API.** It is published to crates.io only because the extensions that use it are, and
crates.io refuses a crate whose dependencies are not published. Its modules move, split and change between
releases, including patch releases, without that counting as a breaking change, and no semver promise covers them.
Do not depend on it from outside pixi-ext-contrib.

It is not affiliated with prefix.dev or the pixi project; its name starts with the owner, not `pixi-`, so it is not
taken for one of theirs.
