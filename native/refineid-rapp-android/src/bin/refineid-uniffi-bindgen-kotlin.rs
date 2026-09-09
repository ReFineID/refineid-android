//! Generates the Kotlin binding for the shared RAPP core.
//!
//! The Apple side has an equivalent Swift generator. Both read the same
//! library, so a Kotlin and a Swift peer speak one protocol by construction
//! rather than by two hand-written implementations agreeing.
fn main() {
    uniffi::uniffi_bindgen_main();
}
