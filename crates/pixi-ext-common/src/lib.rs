//! `pixi-ext-common`: code the pixi extensions in aesir-oss/pixi-ext-contrib share.
//!
//! **This library is not an API.** It is compiled into each extension from this repository and
//! never published (#106); its modules move, split and change whenever the extensions need them to.
//! Not affiliated with prefix.dev or the pixi project.

// No `unsafe` in what ships; see pixi-sbom's lib.rs for why tests are exempt.
#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod license;
pub mod license_policy;
pub mod lockfile;
pub mod pipe;
pub mod purl;
pub mod style;
