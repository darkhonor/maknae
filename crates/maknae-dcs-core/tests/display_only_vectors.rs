//! DISPLAY ONLY decision vectors (#27): the display-only band views with a
//! DisplayOnly obligation and cannot receive; classified-only band validity.
mod common;
use common::*;
use maknae_dcs_core::{
    decide, validate_label, Action, Decision, DenyReason, Disclosure, LabelInvalidity, Obligation,
    Releasability,
};
use std::collections::BTreeSet;

fn display_only_secret() -> maknae_dcs_core::ResourceLabel {
    let mut r = mk_owned_classified("USA", "SECRET"); // long-token, classified level
    r.disclosure = Disclosure {
        release: Releasability::NoMarking, // REL USA (origin-only)
        display: Some(Releasability::Grant(set(&["AUS"]))), // DISPLAY ONLY AUS
        exclusions: BTreeSet::new(),
    };
    r
}

#[test]
fn display_only_band_matrix() {
    let spif = us_classified_spif();
    let r = display_only_secret();
    // MUST use sub_classified (TOP_SECRET clearance) — the "TS"-clearance `sub()`
    // has no rank in the long-token SPIF and would gate-2 Deny(Indeterminate).
    let go = |nat: &str, a: Action| decide(&sub_classified(nat), &r, a, &purpose(""), &spif);
    let ob: BTreeSet<Obligation> = [Obligation::DisplayOnly].into_iter().collect();
    assert_eq!(
        go("AUS", Action::Display),
        Decision::PermitWithObligations { obligations: ob }
    );
    assert_eq!(
        go("AUS", Action::Read),
        Decision::Deny(DenyReason::Releasability)
    );
    assert_eq!(
        go("AUS", Action::Export),
        Decision::Deny(DenyReason::Releasability)
    );
    assert_eq!(go("USA", Action::Read), Decision::Permit); // owner receives
    assert_eq!(
        go("JPN", Action::Display),
        Decision::Deny(DenyReason::Releasability)
    );
}

#[test]
fn display_only_band_on_unclassified_is_invalid() {
    let spif = us_classified_spif();
    let mut r = display_only_secret();
    r.classification.name = "UNCLASSIFIED".into();
    assert!(matches!(
        validate_label(&r, &spif),
        Err(LabelInvalidity::Label)
    ));
    // two-locus: decide() also denies the invalid label (InvalidLabel)
    assert_eq!(
        decide(
            &sub_classified("AUS"),
            &r,
            Action::Display,
            &purpose(""),
            &spif
        ),
        Decision::Deny(DenyReason::InvalidLabel)
    );
}

#[test]
fn empty_band_on_classified_skips_the_classified_gate() {
    // Mutation coverage of `band_nonempty = !disp_e.is_subset_of(&rel_e)`: an
    // EXPLICIT display equal to release (empty band) must NOT trigger the
    // classified-only gate — valid even on UNCLASSIFIED because the band is empty.
    let spif = us_classified_spif();
    let mut r = mk_owned_classified("USA", "UNCLASSIFIED");
    r.disclosure = Disclosure {
        release: Releasability::Grant(set(&["AUS"])),
        display: Some(Releasability::Grant(set(&["AUS"]))), // display == release → empty band
        exclusions: BTreeSet::new(),
    };
    assert_eq!(validate_label(&r, &spif), Ok(())); // empty band on unclassified is fine
}
