//! Android shared library for the shared RAPP core.
//!
//! The protocol lives in `refineid-rapp` and stays there. This crate only
//! links that crate's UniFFI scaffolding into a `cdylib`, because a Kotlin
//! binding loads its Rust side through a JNI shared object and the library
//! crate builds as `rlib` and `staticlib` for the Apple binding.
//!
//! Re-exporting the crate keeps the scaffolding symbols in the linked output.
pub use refineid_rapp::*;
