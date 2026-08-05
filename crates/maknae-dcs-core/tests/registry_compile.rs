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

#[test]
fn iso3166_recognizes_real_codes_rejects_fake() {
    for c in [
        "USA", "GBR", "CAN", "AUS", "NZL", "JPN", "KOR", "PHL", "MYS", "IND", "FRA", "DEU", "ZAF",
        "TUR",
    ] {
        assert!(
            maknae_dcs_core::registry::is_iso3166(c),
            "{c} should be ISO-3166"
        );
    }
    assert!(!maknae_dcs_core::registry::is_iso3166("XYZ")); // structurally a trigraph, not a real country
}

#[test]
fn unck_expands_to_18_with_zaf_and_without_kor() {
    let m = registry::expand_coalition("UNCK").expect("UNCK registered");
    let set: std::collections::BTreeSet<&str> = m.iter().copied().collect();
    assert_eq!(set.len(), 18);
    assert!(set.contains("ZAF")); // CJCSI 2015.01A member
    assert!(!set.contains("KOR")); // host nation, NOT a member
    assert!(set.contains("DEU")); // 2 Aug 2024 accession
    assert_eq!(registry::expand_coalition("FVEY").unwrap().len(), 5);
    assert!(registry::expand_coalition("ZZZZ").is_none());
}
