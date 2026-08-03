//! The dominance decision: a fail-closed conjunction of per-dimension gates.
//!
//! `decide` is pure, total, and side-effect-free. It returns `Permit` only if
//! EVERY gate passes; any failure or indeterminate input → `Deny`. There is no
//! role or administrative bypass: a read permit derives only from clearance ∧
//! categories ∧ nationality/coalition ∧ purpose ∧ action.

use crate::label::{restrictive_dominates, Caveat, ResourceLabel};
use crate::policy::{is_trigraph, CategoryKind, Spif};
use crate::subject::{affiliation_satisfies, Subject};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Read,
    Display,
    Export,
}

/// The purpose the subject asserts for this access (need-to-know token).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Purpose(pub String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Permit,
    Deny(DenyReason),
}

/// Deny reasons are existence-agnostic: they never name a compartment,
/// program, or control — only the failing dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    Level,
    Compartment,
    AffiliationControl,
    Releasability,
    NeedToKnow,
    ActionForbidden,
    Indeterminate,
    PolicyMismatch,
}

/// The reference-monitor decision. Gate order (all must pass; first failure
/// returns its reason):
///
/// 1. Policy match — subject clearance, resource classification, and the SPIF
///    must share one policy (cross-policy resolution deferred → fail closed).
/// 2. Level with compilation-as-floor — explicit `match` on every rank
///    `Option`; unknown → `Indeterminate`, never a mislabeled `Level`.
/// 3. Category gates — per-tag dispatch on the SPIF-declared kind; empty
///    required-sets and unknown/Permissive kinds → `Indeterminate`.
/// 4. Releasability — origin-validated, two-namespace eligibility.
/// 5. Action — `DisplayOnly` blocks `Export` (Read/Display permitted at MVP;
///    recorded open question for LLM-endpoint principals).
/// 6. Need-to-know — exact token match when the label demands one.
pub fn decide(
    subject: &Subject,
    resource: &ResourceLabel,
    action: Action,
    purpose: &Purpose,
    spif: &Spif,
) -> Decision {
    // Gate 1: policy match.
    if subject.clearance.policy != resource.classification.policy
        || subject.clearance.policy != *spif.policy()
    {
        return Decision::Deny(DenyReason::PolicyMismatch);
    }

    // Gate 2: level, with compilation-as-floor. Explicit matches — never
    // compare Option<usize> with >= (None < Some(_) would mislabel the reason).
    let subject_rank = match spif.rank(&subject.clearance) {
        Some(r) => r,
        None => return Decision::Deny(DenyReason::Indeterminate),
    };
    let resource_rank = match spif.rank(&resource.classification) {
        Some(r) => r,
        None => return Decision::Deny(DenyReason::Indeterminate),
    };
    let effective_rank = match &resource.compilation_level {
        None => resource_rank,
        Some(c) => match spif.rank(c) {
            Some(comp) => resource_rank.max(comp),
            None => return Decision::Deny(DenyReason::Indeterminate),
        },
    };
    if subject_rank < effective_rank {
        return Decision::Deny(DenyReason::Level);
    }

    // Gate 3: category gates.
    for (tag, required) in &resource.categories {
        // An empty required-set never vacuously satisfies, for ANY kind —
        // makes the no-empty-value-set invariant self-enforcing at the gate.
        if required.is_empty() {
            return Decision::Deny(DenyReason::Indeterminate);
        }
        match spif.category_kind(tag) {
            None => return Decision::Deny(DenyReason::Indeterminate), // unknown tag
            Some(CategoryKind::Restrictive) => {
                let holds = subject
                    .read_ins
                    .get(tag)
                    .is_some_and(|held| restrictive_dominates(held, required));
                if !holds {
                    return Decision::Deny(DenyReason::Compartment);
                }
            }
            Some(CategoryKind::RestrictivePredicate) => {
                if !affiliation_satisfies(required, &subject.affiliation) {
                    return Decision::Deny(DenyReason::AffiliationControl);
                }
            }
            // At MVP releasability is the ONLY permissive dimension and it
            // lives in the dedicated typed field; a Permissive tag here is an
            // unhandled access-control dimension an accredited SPIF declared —
            // deny, never silently unenforce.
            Some(CategoryKind::Permissive) => return Decision::Deny(DenyReason::Indeterminate),
            Some(CategoryKind::Informative) => {} // ignored by definition
        }
    }

    // Gate 4: releasability (origin-validated).
    if !is_trigraph(&resource.origin) {
        return Decision::Deny(DenyReason::Indeterminate);
    }
    if !resource
        .releasability
        .eligible(&resource.origin, spif)
        .permits(&subject.nationality, &subject.coalition_memberships)
    {
        return Decision::Deny(DenyReason::Releasability);
    }

    // Gate 5: action.
    if resource.caveats.contains(&Caveat::DisplayOnly) && action == Action::Export {
        return Decision::Deny(DenyReason::ActionForbidden);
    }

    // Gate 6: need-to-know.
    if let Some(tk) = &resource.need_to_know {
        if !(subject.purposes.contains(tk) && purpose.0 == *tk) {
            return Decision::Deny(DenyReason::NeedToKnow);
        }
    }

    Decision::Permit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::label::Releasability;
    use crate::policy::{Classification, PolicyId};
    use crate::subject::Affiliation;
    use std::collections::BTreeSet;

    fn set(xs: &[&str]) -> BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    // IDENTICAL builder chain to Task 8's pinned us_spif() — the tests below
    // need SCI registered (else compartment_deny yields Indeterminate, not
    // Compartment), LDC, EYES, HANDLING, and at least one unregistered tag.
    fn us_spif() -> Spif {
        Spif::builder("US")
            .levels(&["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"])
            .category("SCI", CategoryKind::Restrictive)
            .category("SAP", CategoryKind::Restrictive)
            .category("LDC", CategoryKind::RestrictivePredicate)
            .category("EYES", CategoryKind::Permissive)
            .category("HANDLING", CategoryKind::Informative)
            .tetragraph("CFCK", Some(&["USA", "KOR"]))
            .tetragraph(
                "UNCK",
                Some(&[
                    "AUS", "BEL", "CAN", "COL", "DEU", "DNK", "FRA", "GRC", "ITA", "KOR", "NLD",
                    "NZL", "NOR", "PHL", "THA", "TUR", "GBR", "USA",
                ]),
            )
            .tetragraph("FVEY", Some(&["USA", "AUS", "CAN", "GBR", "NZL"]))
            .tetragraph("NKIC", None)
            .build()
    }

    fn mk_subject(clearance: &str) -> Subject {
        Subject {
            clearance: Classification {
                policy: PolicyId("US".into()),
                name: clearance.into(),
            },
            nationality: "USA".into(),
            read_ins: [("SCI".to_string(), set(&["SI", "TK"]))]
                .into_iter()
                .collect(),
            coalition_memberships: BTreeSet::new(),
            affiliation: Affiliation::UsGovernment,
            purposes: set(&["OPLAN"]),
        }
    }

    fn mk_resource(level: &str) -> ResourceLabel {
        ResourceLabel {
            classification: Classification {
                policy: PolicyId("US".into()),
                name: level.into(),
            },
            origin: "USA".into(),
            categories: [("SCI".to_string(), set(&["SI"]))].into_iter().collect(),
            releasability: Releasability::NoMarking,
            caveats: BTreeSet::new(),
            compilation_level: None,
            need_to_know: Some("OPLAN".into()),
        }
    }

    fn run(subject: &Subject, resource: &ResourceLabel, action: Action) -> Decision {
        decide(
            subject,
            resource,
            action,
            &Purpose("OPLAN".into()),
            &us_spif(),
        )
    }

    #[test]
    fn permit_happy_path() {
        assert_eq!(
            run(
                &mk_subject("TOP_SECRET"),
                &mk_resource("SECRET"),
                Action::Read
            ),
            Decision::Permit
        );
    }

    #[test]
    fn level_deny() {
        assert_eq!(
            run(
                &mk_subject("SECRET"),
                &mk_resource("TOP_SECRET"),
                Action::Read
            ),
            Decision::Deny(DenyReason::Level)
        );
    }

    #[test]
    fn unknown_level_is_indeterminate() {
        // subject clearance name not in SPIF — NOT Deny(Level)
        assert_eq!(
            run(
                &mk_subject("ULTRAVIOLET"),
                &mk_resource("SECRET"),
                Action::Read
            ),
            Decision::Deny(DenyReason::Indeterminate)
        );
    }

    #[test]
    fn compilation_raises_floor() {
        let mut r = mk_resource("SECRET");
        r.compilation_level = Some(Classification {
            policy: PolicyId("US".into()),
            name: "TOP_SECRET".into(),
        });
        assert_eq!(
            run(&mk_subject("SECRET"), &r, Action::Read),
            Decision::Deny(DenyReason::Level)
        );
    }

    #[test]
    fn unknown_compilation_is_indeterminate() {
        let mut r = mk_resource("SECRET");
        r.compilation_level = Some(Classification {
            policy: PolicyId("US".into()),
            name: "BOGUS".into(),
        });
        assert_eq!(
            run(&mk_subject("TOP_SECRET"), &r, Action::Read),
            Decision::Deny(DenyReason::Indeterminate)
        );
    }

    #[test]
    fn compartment_deny() {
        let mut r = mk_resource("SECRET");
        r.categories.insert("SCI".into(), set(&["SI", "TK", "HCS"])); // subject lacks HCS
        assert_eq!(
            run(&mk_subject("TOP_SECRET"), &r, Action::Read),
            Decision::Deny(DenyReason::Compartment)
        );
    }

    #[test]
    fn affiliation_control_deny() {
        let mut r = mk_resource("UNCLASSIFIED");
        r.categories = [("LDC".to_string(), set(&["FED_ONLY"]))]
            .into_iter()
            .collect();
        let mut s = mk_subject("SECRET");
        s.affiliation = Affiliation::ClearedContractor;
        assert_eq!(
            run(&s, &r, Action::Read),
            Decision::Deny(DenyReason::AffiliationControl)
        );
    }

    #[test]
    fn permissive_tag_denies_indeterminate() {
        let mut r = mk_resource("SECRET");
        r.categories.insert("EYES".into(), set(&["USA"])); // registered Permissive
        assert_eq!(
            run(&mk_subject("TOP_SECRET"), &r, Action::Read),
            Decision::Deny(DenyReason::Indeterminate)
        );
    }

    #[test]
    fn informative_tag_is_ignored() {
        // Informative is the ONLY gate-3 arm that skips — a conservative
        // Deny(Indeterminate) on this arm would pass every other test
        let mut r = mk_resource("SECRET");
        r.categories
            .insert("HANDLING".into(), set(&["REL_TO_MEDIA"]));
        assert_eq!(
            run(&mk_subject("TOP_SECRET"), &r, Action::Read),
            Decision::Permit
        );
    }

    #[test]
    fn releasability_deny() {
        let mut r = mk_resource("SECRET");
        r.releasability = Releasability::Grant(set(&["AUS"]));
        let mut s = mk_subject("TOP_SECRET");
        s.nationality = "KOR".into();
        assert_eq!(
            run(&s, &r, Action::Read),
            Decision::Deny(DenyReason::Releasability)
        );
    }

    #[test]
    fn malformed_origin_is_indeterminate() {
        // resource OTHERWISE identical to the happy path so gate 4's origin
        // precheck is the deciding gate
        for bad in ["", "usa", "USAA"] {
            let mut r = mk_resource("SECRET");
            r.origin = bad.into();
            assert_eq!(
                run(&mk_subject("TOP_SECRET"), &r, Action::Read),
                Decision::Deny(DenyReason::Indeterminate),
                "origin {bad:?}"
            );
        }
    }

    #[test]
    fn policy_mismatch_deny() {
        let mut s = mk_subject("SECRET");
        s.clearance.policy = PolicyId("AUS".into());
        assert_eq!(
            run(&s, &mk_resource("SECRET"), Action::Read),
            Decision::Deny(DenyReason::PolicyMismatch)
        );
    }

    #[test]
    fn display_only_blocks_export() {
        let mut r = mk_resource("SECRET");
        r.caveats.insert(Caveat::DisplayOnly);
        let s = mk_subject("TOP_SECRET");
        assert_eq!(run(&s, &r, Action::Read), Decision::Permit);
        assert_eq!(run(&s, &r, Action::Display), Decision::Permit);
        assert_eq!(
            run(&s, &r, Action::Export),
            Decision::Deny(DenyReason::ActionForbidden)
        );
    }

    #[test]
    fn need_to_know_deny() {
        let mut s = mk_subject("TOP_SECRET");
        s.purposes = BTreeSet::new(); // may not assert OPLAN
        assert_eq!(
            run(&s, &mk_resource("SECRET"), Action::Read),
            Decision::Deny(DenyReason::NeedToKnow)
        );
        // purpose argument mismatch also denies even if the subject HOLDS the token
        assert_eq!(
            decide(
                &mk_subject("TOP_SECRET"),
                &mk_resource("SECRET"),
                Action::Read,
                &Purpose("OTHER".into()),
                &us_spif()
            ),
            Decision::Deny(DenyReason::NeedToKnow)
        );
    }

    #[test]
    fn no_admin_bypass() {
        // UsGovernment affiliation, insufficient clearance — affiliation grants nothing
        let s = mk_subject("UNCLASSIFIED");
        assert_eq!(s.affiliation, Affiliation::UsGovernment);
        assert_eq!(
            run(&s, &mk_resource("SECRET"), Action::Read),
            Decision::Deny(DenyReason::Level)
        );
    }

    #[test]
    fn second_restrictive_tag_gates_independently() {
        // two-tag conjunction: holding SCI does not satisfy SAP — the per-tag
        // loop's short-circuit is load-bearing
        let mut r = mk_resource("SECRET");
        r.categories
            .insert("SAP".into(), set(&["BUTTERED_POPCORN"]));
        assert_eq!(
            run(&mk_subject("TOP_SECRET"), &r, Action::Read),
            Decision::Deny(DenyReason::Compartment)
        );
        let mut s = mk_subject("TOP_SECRET");
        s.read_ins.insert("SAP".into(), set(&["BUTTERED_POPCORN"]));
        assert_eq!(run(&s, &r, Action::Read), Decision::Permit);
    }

    #[test]
    fn unknown_category_tag_deny() {
        let mut r = mk_resource("SECRET");
        r.categories.insert("MYSTERY".into(), set(&["X"]));
        assert_eq!(
            run(&mk_subject("TOP_SECRET"), &r, Action::Read),
            Decision::Deny(DenyReason::Indeterminate)
        );
    }

    #[test]
    fn empty_category_values_deny() {
        // empty required-set never vacuously satisfies, any kind
        let mut r = mk_resource("UNCLASSIFIED");
        r.categories = [("LDC".to_string(), BTreeSet::new())].into_iter().collect();
        assert_eq!(
            run(&mk_subject("SECRET"), &r, Action::Read),
            Decision::Deny(DenyReason::Indeterminate)
        );
    }
}
