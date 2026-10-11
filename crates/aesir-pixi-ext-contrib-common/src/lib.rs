//! `aesir-pixi-ext-contrib-common`: code the pixi extensions in aesir-oss/pixi-ext-contrib share.
//!
//! **This library is not an API.** It is published to crates.io only because the extensions that
//! use it are, and crates.io refuses a crate whose dependencies are not published (#54). Its
//! modules move, split and change between releases, including patch releases, without that counting
//! as a breaking change. Not affiliated with prefix.dev or the pixi project.

// No `unsafe` in what ships; see pixi-sbom's lib.rs for why tests are exempt.
#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod license;
pub mod pipe;
pub mod style;
