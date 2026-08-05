//! #26 NOT AUTHORIZED FOR — decide-path integration vectors: the gate-4
//! defense-in-depth refusals (Task 10) and the releasability NAF decisions
//! (Task 11). D9: integration tests (not `decide.rs`'s unit `mod tests`),
//! sharing `tests/common`.

mod common;
use common::*;
use maknae_dcs_core::{decide, Action, Decision, DenyReason, Releasability};

// --- Task 10: gate-4 defense-in-depth (a single-origin Owned label that did NOT
// pass validate_label still denies structurally at decide()). Joint owner-in-X is
// NOT here — decide short-circuits Joint to Indeterminate; that vector lives in
// validate_label (label.rs unit `owner_in_x_is_invalid_joint`). ---

#[test]
fn gate4_denies_owner_in_x_single_origin() {
    let mut r = mk_owned("USA");
    r.disclosure.exclusions = set(&["USA"]);
    assert_eq!(
        decide(&sub("USA"), &r, Action::Read, &purpose(""), &us_spif()),
        Decision::Deny(DenyReason::InvalidLabel)
    );
}

#[test]
fn gate4_denies_public_naf() {
    let mut r = mk_owned("USA");
    r.disclosure.release = Releasability::Public;
    r.disclosure.exclusions = set(&["ZAF"]);
    assert_eq!(
        decide(&sub("ZAF"), &r, Action::Read, &purpose(""), &us_spif()),
        Decision::Deny(DenyReason::InvalidLabel)
    );
}

#[test]
fn gate4_denies_unexpandable_coalition() {
    let mut r = mk_owned("USA");
    r.disclosure.release = Releasability::Grant(set(&["ZZZZ"]));
    assert_eq!(
        decide(&sub("USA"), &r, Action::Read, &purpose(""), &us_spif()),
        Decision::Deny(DenyReason::InvalidElement)
    );
}
