//! The `data/*.json` registries are compiled into the crate by `build.rs`.
//! Compilation itself is the primary test: if `build.rs` rejects a data source
//! (malformed, duplicate, wrong shape) the crate does not build — fail-closed,
//! a malformed registry never ships (Global Constraint: "a malformed source
//! FAILS THE BUILD"). D2: this build-time validation is what supersedes the
//! runtime `malformed_spif_member_cannot_widen_through_join` guard.
//!
//! These tests assert the generated tables are reachable and non-trivial. A
//! fail-closed demonstration (corrupt the data → build fails) is documented in
//! the plan (Task 2 Step 4) and exercised manually / in CI, not here (a test
//! cannot corrupt its own compiled-in table at runtime).

use maknae_dcs_core::registry;

#[test]
fn iso3166_table_compiled_and_nonempty() {
    assert!(registry::is_iso3166("USA"));
    assert!(!registry::is_iso3166("ZZZ"));
}
