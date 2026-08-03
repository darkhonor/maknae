//! Authoritative golden vectors for the ADR-0008 classification lattice.
//!
//! Subject-construction rule: coalition/foreign subjects carry a clearance
//! under the RESOURCE's policy — policy is the accrediting authority,
//! nationality is an independent field. This is exactly what routes a foreign
//! deny through gate 4 (releasability) instead of gate 1 (policy).

use maknae_dcs_core::{
    decide, validate_rel, Action, Affiliation, CategoryKind, Caveat, Classification, Decision,
    DenyReason, PolicyId, Purpose, RelValidationError, Releasability, ResourceLabel, Spif, Subject,
};
use std::collections::{BTreeMap, BTreeSet};

fn set(xs: &[&str]) -> BTreeSet<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

fn us_spif() -> Spif {
    Spif::builder("US")
        .levels(&["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"])
        .category("SCI", CategoryKind::Restrictive)
        .category("SAP", CategoryKind::Restrictive)
        .category("LDC", CategoryKind::RestrictivePredicate)
        .category("EYES", CategoryKind::Permissive)
        .category("HANDLING", CategoryKind::Informative)
        .tetragraph("CFCK", Some(&["USA", "KOR"]))
        // 18 UNC sending states per design/references/dcs-schema-migration.md:1215-1221
        .tetragraph(
            "UNCK",
            Some(&[
                "AUS", "BEL", "CAN", "COL", "DEU", "DNK", "FRA", "GRC", "ITA", "KOR", "NLD", "NZL",
                "NOR", "PHL", "THA", "TUR", "GBR", "USA",
            ]),
        )
        .tetragraph("FVEY", Some(&["USA", "AUS", "CAN", "GBR", "NZL"]))
        .tetragraph("NKIC", None)
        .build()
}

// spec §7: AUS has no CONFIDENTIAL — the fixture witnesses the national difference
fn aus_spif() -> Spif {
    Spif::builder("AUS")
        .levels(&["UNCLASSIFIED", "SECRET", "TOP_SECRET"])
        .build()
}

/// A subject cleared SECRET under `policy`, of the given nationality.
fn subject(policy: &str, nationality: &str) -> Subject {
    Subject {
        clearance: Classification {
            policy: PolicyId(policy.into()),
            name: "SECRET".into(),
        },
        nationality: nationality.into(),
        read_ins: BTreeMap::new(),
        coalition_memberships: BTreeSet::new(),
        affiliation: Affiliation::UsGovernment,
        purposes: BTreeSet::new(),
    }
}

/// A US-origin SECRET resource with the given releasability, nothing else.
fn resource(policy: &str, origin: &str, rel: Releasability) -> ResourceLabel {
    ResourceLabel {
        classification: Classification {
            policy: PolicyId(policy.into()),
            name: "SECRET".into(),
        },
        origin: origin.into(),
        categories: BTreeMap::new(),
        releasability: rel,
        caveats: BTreeSet::new(),
        compilation_level: None,
        need_to_know: None,
    }
}

fn read(s: &Subject, r: &ResourceLabel, spif: &Spif) -> Decision {
    decide(s, r, Action::Read, &Purpose(String::new()), spif)
}

#[test]
fn aus_kor_derivation_reduces_to_origin() {
    // #6 flagship: join(REL AUS, REL KOR) on US-origin SECRET → canonical
    // NoMarking = REL {origin}; NOT REL AUS,KOR, NOT REL ∅.
    let spif = us_spif();
    let a = resource("US", "USA", Releasability::Grant(set(&["AUS"])));
    let b = resource("US", "USA", Releasability::Grant(set(&["KOR"])));
    let j = a.join(&b, &spif).expect("same-policy, same-origin join");
    assert!(matches!(j.releasability, Releasability::NoMarking));
    assert_eq!(read(&subject("US", "USA"), &j, &spif), Decision::Permit);
    assert_eq!(
        read(&subject("US", "AUS"), &j, &spif),
        Decision::Deny(DenyReason::Releasability)
    );
    assert_eq!(
        read(&subject("US", "KOR"), &j, &spif),
        Decision::Deny(DenyReason::Releasability)
    );
}

#[test]
fn cfc_is_not_unc() {
    // REL CFCK ≠ REL UNCK: AUS is a UNC sending state but not in CFCK.
    let spif = us_spif();
    let r = resource("US", "USA", Releasability::Grant(set(&["CFCK"])));
    assert_eq!(read(&subject("US", "USA"), &r, &spif), Decision::Permit);
    assert_eq!(read(&subject("US", "KOR"), &r, &spif), Decision::Permit);
    assert_eq!(
        read(&subject("US", "AUS"), &r, &spif),
        Decision::Deny(DenyReason::Releasability)
    );
    assert_eq!(
        read(&subject("US", "JPN"), &r, &spif),
        Decision::Deny(DenyReason::Releasability)
    );
}

#[test]
fn unck_decomposes_to_the_18_sending_states() {
    // the other side of CFC≠UNC — asserts the 18-nation expansion actually decomposes
    let spif = us_spif();
    let r = resource("US", "USA", Releasability::Grant(set(&["UNCK"])));
    assert_eq!(read(&subject("US", "AUS"), &r, &spif), Decision::Permit); // a UNC sending state
    assert_eq!(
        read(&subject("US", "JPN"), &r, &spif),
        Decision::Deny(DenyReason::Releasability)
    ); // not one
}

#[test]
fn noforn_austeo_mirror() {
    // NOFORN is national-relative: absent REL = REL {origin} under EITHER policy.
    let us = us_spif();
    let r_us = resource("US", "USA", Releasability::NoMarking);
    assert_eq!(read(&subject("US", "USA"), &r_us, &us), Decision::Permit);
    assert_eq!(
        read(&subject("US", "AUS"), &r_us, &us),
        Decision::Deny(DenyReason::Releasability)
    );
    // The AUSTEO mirror: an AUS-origin resource under the AUS policy. The US
    // subject holds an AUS-policy clearance (nationality ≠ policy) so gate 4,
    // not gate 1, is the deciding gate — and UsGovernment affiliation does NOT
    // bypass (affiliation is not nationality).
    let aus = aus_spif();
    let r_aus = resource("AUS", "AUS", Releasability::NoMarking);
    assert_eq!(read(&subject("AUS", "AUS"), &r_aus, &aus), Decision::Permit);
    let us_official = Subject {
        clearance: Classification {
            policy: PolicyId("AUS".into()),
            name: "SECRET".into(),
        },
        nationality: "USA".into(),
        read_ins: BTreeMap::new(),
        coalition_memberships: BTreeSet::new(),
        affiliation: Affiliation::UsGovernment,
        purposes: BTreeSet::new(),
    };
    assert_eq!(
        read(&us_official, &r_aus, &aus),
        Decision::Deny(DenyReason::Releasability)
    );
}

#[test]
fn sci_sub_compartment_is_not_granted_by_parent() {
    let spif = us_spif();
    let mut r = resource("US", "USA", Releasability::NoMarking);
    r.categories = [("SCI".to_string(), set(&["SI//G"]))].into_iter().collect();
    let mut s = subject("US", "USA");
    s.read_ins = [("SCI".to_string(), set(&["SI"]))].into_iter().collect();
    assert_eq!(read(&s, &r, &spif), Decision::Deny(DenyReason::Compartment)); // parent ≠ sub-compartment
    s.read_ins = [("SCI".to_string(), set(&["SI//G"]))].into_iter().collect();
    assert_eq!(read(&s, &r, &spif), Decision::Permit); // exact
}

#[test]
fn fedcon_vs_fed_only() {
    // level UNCLASSIFIED (CUI is not a level; the LDC tag carries the control),
    // NoMarking + origin USA + all subjects USA-national — pins gate 4 to pass
    // so gate 3 is the deciding gate.
    let spif = us_spif();
    let mk = |controls: &[&str]| {
        let mut r = resource("US", "USA", Releasability::NoMarking);
        r.classification.name = "UNCLASSIFIED".into();
        r.categories = [("LDC".to_string(), set(controls))].into_iter().collect();
        r
    };
    let mk_subj = |aff: Affiliation| {
        let mut s = subject("US", "USA");
        s.affiliation = aff;
        s
    };
    let fedcon = mk(&["FEDCON"]);
    assert_eq!(
        read(&mk_subj(Affiliation::ClearedContractor), &fedcon, &spif),
        Decision::Permit
    );
    let fed_only = mk(&["FED_ONLY"]);
    assert_eq!(
        read(&mk_subj(Affiliation::ClearedContractor), &fed_only, &spif),
        Decision::Deny(DenyReason::AffiliationControl)
    );
    assert_eq!(
        read(&mk_subj(Affiliation::UsGovernment), &fed_only, &spif),
        Decision::Permit
    );
    assert_eq!(
        read(&mk_subj(Affiliation::Foreign), &fed_only, &spif),
        Decision::Deny(DenyReason::AffiliationControl)
    );
}

#[test]
fn permissive_tag_fails_closed() {
    // a fully-cleared US subject that passes gates 1-2 → gate 3 is the
    // deciding gate (an under-cleared or wrong-policy subject would deny
    // earlier with a different reason)
    let spif = us_spif();
    let mut r = resource("US", "USA", Releasability::NoMarking);
    r.categories = [("EYES".to_string(), set(&["USA"]))].into_iter().collect();
    assert_eq!(
        read(&subject("US", "USA"), &r, &spif),
        Decision::Deny(DenyReason::Indeterminate)
    );
}

#[test]
fn non_decomposable_nkic_needs_held_membership() {
    // spec §6.2: membership uninferrable → deny unless the subject carries the
    // coalition attribute directly
    let spif = us_spif();
    let r = resource("US", "USA", Releasability::Grant(set(&["NKIC"])));
    let mut kor = subject("US", "KOR");
    assert_eq!(
        read(&kor, &r, &spif),
        Decision::Deny(DenyReason::Releasability)
    );
    kor.coalition_memberships = set(&["NKIC"]);
    assert_eq!(read(&kor, &r, &spif), Decision::Permit);
}

#[test]
fn absent_rel_both_directions() {
    let spif = us_spif();
    let absent = resource("US", "USA", Releasability::NoMarking);
    assert_eq!(
        read(&subject("US", "USA"), &absent, &spif),
        Decision::Permit
    );
    assert_eq!(
        read(&subject("US", "AUS"), &absent, &spif),
        Decision::Deny(DenyReason::Releasability)
    );
    // explicit REL ∅ is the TOP: deny-all INCLUDING the origin
    let empty = resource("US", "USA", Releasability::Empty);
    assert_eq!(
        read(&subject("US", "USA"), &empty, &spif),
        Decision::Deny(DenyReason::Releasability)
    );
}

#[test]
fn cross_policy_unmapped_denies() {
    let spif = us_spif();
    let r = resource("US", "USA", Releasability::NoMarking);
    let mut s = subject("US", "USA");
    s.clearance.policy = PolicyId("AUS".into());
    assert_eq!(
        read(&s, &r, &spif),
        Decision::Deny(DenyReason::PolicyMismatch)
    );
}

#[test]
fn display_only_blocks_export_only() {
    let spif = us_spif();
    let mut r = resource("US", "USA", Releasability::NoMarking);
    r.caveats.insert(Caveat::DisplayOnly);
    let s = subject("US", "USA");
    let run = |action: Action| decide(&s, &r, action, &Purpose(String::new()), &spif);
    assert_eq!(run(Action::Read), Decision::Permit);
    assert_eq!(run(Action::Display), Decision::Permit);
    assert_eq!(
        run(Action::Export),
        Decision::Deny(DenyReason::ActionForbidden)
    );
}

#[test]
fn anti_duplication_ingest_validation() {
    let spif = us_spif();
    match validate_rel(&set(&["USA", "GBR", "FVEY"]), "USA", &spif) {
        Err(RelValidationError::DuplicativeTetragraph { token, covered }) => {
            assert_eq!(token, "GBR");
            assert_eq!(covered, "FVEY");
        }
        other => panic!("expected DuplicativeTetragraph(GBR/FVEY), got {other:?}"),
    }
    assert!(validate_rel(&set(&["USA", "FVEY"]), "USA", &spif).is_ok()); // origin exemption
    assert!(validate_rel(&set(&["FVEY"]), "USA", &spif).is_ok());
}
