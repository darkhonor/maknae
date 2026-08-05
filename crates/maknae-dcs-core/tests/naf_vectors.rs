//! #26 NOT AUTHORIZED FOR — decide-path integration vectors: the gate-4
//! defense-in-depth refusals (Task 10) and the releasability NAF decisions
//! (Task 11). D9: integration tests (not `decide.rs`'s unit `mod tests`),
//! sharing `tests/common`.

mod common;
use common::*;
use maknae_dcs_core::{audit, decide, Action, Decision, DenyReason, Releasability};

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

// --- Task 11: the flagship NAF releasability decisions. REL UNCK NAF ZAF —
// ZAF is a UNCK member, excluded → Deny(Releasability) (a valid label whose
// resolved set simply omits ZAF, NOT InvalidLabel). ---

#[test]
fn excluded_member_denied_reason_releasability() {
    let mut r = mk_owned("USA");
    r.disclosure.release = Releasability::Grant(set(&["UNCK"]));
    r.disclosure.exclusions = set(&["ZAF"]);
    // ZAF (UNCK member, excluded) → Deny(Releasability), NOT InvalidLabel
    assert_eq!(
        decide(&sub("ZAF"), &r, Action::Read, &purpose(""), &us_spif()),
        Decision::Deny(DenyReason::Releasability)
    );
    // AUS (UNCK member, not excluded) → Permit
    assert_eq!(
        decide(&sub("AUS"), &r, Action::Read, &purpose(""), &us_spif()),
        Decision::Permit
    );
}

#[test]
fn excluded_member_denied_even_though_no_credential_arm_exists() {
    // the round-1 reviewer's bypass: the subject asserts the coalition credential
    // — now IGNORED (the credential arm is removed; eligibility is nationality).
    let mut r = mk_owned("USA");
    r.disclosure.release = Releasability::Grant(set(&["UNCK"]));
    r.disclosure.exclusions = set(&["ZAF"]);
    let mut s = sub("ZAF");
    s.coalition_memberships = set(&["UNCK"]); // asserted — must NOT help
    assert_eq!(
        decide(&s, &r, Action::Read, &purpose(""), &us_spif()),
        Decision::Deny(DenyReason::Releasability)
    );
}

#[test]
fn owner_is_never_excluded_permits() {
    // the owner is always eligible; a NAF that does not name the owner leaves the
    // owner permitted (owner-never-excluded, the co-property of the §6 refusal).
    let mut r = mk_owned("USA");
    r.disclosure.release = Releasability::Grant(set(&["UNCK"]));
    r.disclosure.exclusions = set(&["ZAF"]);
    assert_eq!(
        decide(&sub("USA"), &r, Action::Read, &purpose(""), &us_spif()),
        Decision::Permit
    );
}

#[test]
fn public_release_permits_any_nationality() {
    // legibility (+ the Universe arm of subtract_exclusions, defended explicitly):
    // a REL ALL/Public release with NO NAF permits any nationality through decide().
    let mut r = mk_owned("USA");
    r.disclosure.release = Releasability::Public;
    assert_eq!(
        decide(&sub("ZAF"), &r, Action::Read, &purpose(""), &us_spif()),
        Decision::Permit
    );
    assert_eq!(
        decide(&sub("JPN"), &r, Action::Read, &purpose(""), &us_spif()),
        Decision::Permit
    );
}

// --- Task 12: AuditRecord — pure return, classified-coalition non-disclosure. ---

#[test]
fn audit_record_carries_presented_label_and_decision_no_roster() {
    // REL UNCK NAF ZAF, ZAF subject → Deny(Releasability); the audit record
    // carries the UNEXPANDED label + the existence-agnostic reason, and (by TYPE)
    // no expanded roster — classified-coalition non-disclosure is structural.
    let mut r = mk_owned("USA");
    r.disclosure.release = Releasability::Grant(set(&["UNCK"]));
    r.disclosure.exclusions = set(&["ZAF"]);
    let dec = decide(&sub("ZAF"), &r, Action::Read, &purpose(""), &us_spif());
    assert_eq!(dec, Decision::Deny(DenyReason::Releasability));

    let rec = audit("req-1", &sub("ZAF"), &r, dec.clone());
    assert_eq!(rec.request_id, "req-1");
    assert_eq!(rec.decision, dec); // full Decision, incl. existence-agnostic reason
    assert_eq!(rec.presented_label, r); // UNEXPANDED authoritative input (no roster)
                                        // classified-coalition non-disclosure is structural: AuditRecord exposes no
                                        // eligible-set / expanded-roster field, so there is nothing to leak. The deny
                                        // reason names only a dimension (Releasability), never UNCK or ZAF's membership.
}
