//! The dominance decision: a fail-closed conjunction of per-dimension gates.
//!
//! `decide` is pure, total, and side-effect-free. It returns `Permit` only if
//! EVERY gate passes; any failure or indeterminate input → `Deny`. There is no
//! role or administrative bypass: a read permit derives only from clearance ∧
//! categories ∧ nationality ∧ purpose ∧ action (releasability is decided by
//! nationality alone under #26 — the coalition-credential arm is removed).

use crate::label::{restrictive_dominates, Caveat, ResourceLabel};
use crate::ownership::Ownership;
use crate::policy::{is_trigraph, CategoryKind, Spif};
use crate::subject::{affiliation_satisfies, Subject};
use std::collections::BTreeSet;

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
    /// A permit that carries obligations the consumer MUST honor (spec §2.3;
    /// deny-biased contract — a consumer that cannot honor an obligation denies).
    /// Emission is Stage 3; the variant is landed Stage 1 so downstream code
    /// pattern-matches all three arms from the start.
    PermitWithObligations {
        obligations: BTreeSet<Obligation>,
    },
    Deny(DenyReason),
}

/// Redissemination scope for ORCON-family obligations (spec §2.3). Closed —
/// extend only by ADR amendment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RedisseminationScope {
    UsGov,
}

/// A closed obligation the engine attaches to a permit (spec §2.3). EMISSION
/// (which obligations fire, and the `Caveat` retirement into these) is Stage 3;
/// Stage 1 lands the type shell + the `⊑_obl` refinement order the monotonicity
/// law consumes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Obligation {
    DisplayOnly,
    OriginatorControlled { scope: Option<RedisseminationScope> },
    OwnerConsent,
    ReaderRecord,
    NoEgress,
    OperatorOnly,
}

/// The obligation-refinement order `⊑_obl` (spec §5): a SCOPED
/// `OriginatorControlled` is WEAKER (redissemination pre-approved) than an
/// unscoped one, so `OriginatorControlled{Some(_)} ⊑_obl OriginatorControlled{None}`;
/// every other obligation compares only by identity. Returns true iff `a ⊑_obl b`
/// (a is weaker-or-equal to b).
pub fn obligation_refines(a: &Obligation, b: &Obligation) -> bool {
    match (a, b) {
        (
            Obligation::OriginatorControlled { scope: sa },
            Obligation::OriginatorControlled { scope: sb },
        ) => match (sa, sb) {
            (_, None) => true,            // anything ⊑ the strongest (unscoped)
            (Some(x), Some(y)) => x == y, // identity among scoped
            (None, Some(_)) => false,     // stronger ⋢ weaker
        },
        _ => a == b,
    }
}

/// Set-level `⊑_obl` (Hoare/lower lift, spec §5 CR-r4 SF2): every obligation in
/// `a` is refined by some obligation in `b`. Empty `a` ⊑_obl anything.
pub fn obligations_refine(a: &BTreeSet<Obligation>, b: &BTreeSet<Obligation>) -> bool {
    a.iter().all(|x| b.iter().any(|y| obligation_refines(x, y)))
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
    /// A trigraph/tetragraph outside the encoded world view (#26).
    InvalidElement,
    /// A structurally malformed label (owner-in-X, empty exclusion set,
    /// restriction on Public/UNCLASSIFIED) (#26).
    InvalidLabel,
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
/// 4. Releasability — origin-validated, single nation-namespace eligibility
///    (nationality ∈ resolved ∖ exclusions); two-locus with `validate_label`.
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
                if !affiliation_satisfies(required, &subject.employment.to_affiliation()) {
                    return Decision::Deny(DenyReason::AffiliationControl);
                }
            }
            // At MVP releasability is the ONLY permissive dimension and it
            // lives in the dedicated typed field; a Permissive tag here is an
            // unhandled access-control dimension an accredited SPIF declared —
            // deny, never silently unenforce.
            Some(CategoryKind::Permissive) => return Decision::Deny(DenyReason::Indeterminate),
            // List-control (#30) decide semantics land Stage 5; until then an
            // unhandled ListControlled tag denies, never silently unenforces.
            Some(CategoryKind::ListControlled) => return Decision::Deny(DenyReason::Indeterminate),
            Some(CategoryKind::Informative) => {} // ignored by definition
        }
    }

    // Gate 4: releasability. Evaluates single-owner `Owned` AND multi-owner
    // `Joint` (#40 — each co-owner is eligible to data it co-produced, unioned
    // with the release set). `ConcealedForeign` still fails closed until Stage 5
    // wires its custodian-routed / OwnerConsent semantics.
    let owners = match &resource.ownership {
        Ownership::Owned { .. } | Ownership::Joint { .. } => resource.ownership.base_set(),
        Ownership::ConcealedForeign { .. } => return Decision::Deny(DenyReason::Indeterminate),
    };
    if owners.is_empty() || !owners.iter().all(|o| is_trigraph(o)) {
        // rejects the Owned{""} / joint_from(∅) sentinel and any malformed owner
        return Decision::Deny(DenyReason::Indeterminate);
    }
    // Two-locus defense-in-depth (#26): re-run the ingest predicate at the
    // decision point, so a label that reached decide() WITHOUT passing
    // validate_label (the engine is a decision point, not the ingest gate) still
    // denies structurally — owner/co-owner-in-X / restriction-on-Public / unknown
    // token never silently permit. `validate_label` is owner-set-aware, so it
    // covers `Joint` co-owner-in-X exactly as it covers single-origin owner-in-X.
    if let Err(inv) = crate::label::validate_label(resource, spif) {
        return Decision::Deny(match inv {
            crate::label::LabelInvalidity::Element => DenyReason::InvalidElement,
            crate::label::LabelInvalidity::Label => DenyReason::InvalidLabel,
        });
    }
    if !resource
        .disclosure
        .eligible_release(&owners, spif)
        .permits(&subject.nationality)
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

/// A pure, self-contained audit record of one decision (#26). The engine NEVER
/// logs — it RETURNS this; the caller owns persistence.
///
/// Classified-coalition NON-DISCLOSURE is STRUCTURAL, not a redaction step: the
/// record has NO expanded-eligible-set / roster field to leak, it carries the
/// UNEXPANDED authoritative `presented_label` (the in-memory coalition expansion
/// never leaves the engine — the protective measure), and `decision`'s deny
/// reason is existence-agnostic (it names only the failing dimension, never a
/// coalition or its membership). There is no secure channel because there is
/// nothing membership-revealing to protect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// Caller-supplied correlation id for this decision request.
    pub request_id: String,
    /// A reference to the requesting subject — its declared nationality (an input
    /// attribute the requester already holds), NOT any derived coalition
    /// membership. Never the expanded roster.
    pub subject_ref: String,
    /// The authoritative label AS PRESENTED — unexpanded. No resolved eligible
    /// set / coalition roster is carried (the expansion stayed in the engine).
    pub presented_label: ResourceLabel,
    /// The decision, including its existence-agnostic reason on a `Deny`.
    pub decision: Decision,
}

/// Build the pure audit record for a decision. Total, side-effect-free — no
/// logging, no I/O; the engine returns the record and the caller persists it.
pub fn audit(
    request_id: &str,
    subject: &Subject,
    label: &ResourceLabel,
    decision: Decision,
) -> AuditRecord {
    AuditRecord {
        request_id: request_id.to_string(),
        subject_ref: subject.nationality.clone(),
        presented_label: label.clone(),
        decision,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controls::Controls;
    use crate::label::{Disclosure, Releasability};
    use crate::policy::{Classification, PolicyId};
    use crate::subject::Employment;
    use std::collections::BTreeSet;

    fn set(xs: &[&str]) -> BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn new_deny_reasons_exist_and_are_existence_agnostic() {
        // existence-agnostic: the variants name a dimension, carry no payload
        let a = DenyReason::InvalidElement;
        let b = DenyReason::InvalidLabel;
        assert_ne!(a, b);
        assert_ne!(a, DenyReason::Indeterminate);
    }

    #[test]
    fn obligation_refinement_order() {
        use Obligation::*;
        // scoped OriginatorControlled is WEAKER ⊑_obl unscoped (stronger)
        assert!(obligation_refines(
            &OriginatorControlled {
                scope: Some(RedisseminationScope::UsGov)
            },
            &OriginatorControlled { scope: None },
        ));
        assert!(!obligation_refines(
            &OriginatorControlled { scope: None },
            &OriginatorControlled {
                scope: Some(RedisseminationScope::UsGov)
            },
        ));
        // two scoped OriginatorControlled compare by identity of scope
        assert!(obligation_refines(
            &OriginatorControlled {
                scope: Some(RedisseminationScope::UsGov)
            },
            &OriginatorControlled {
                scope: Some(RedisseminationScope::UsGov)
            },
        ));
        // identity for the other obligations
        assert!(obligation_refines(&DisplayOnly, &DisplayOnly));
        assert!(!obligation_refines(&DisplayOnly, &OwnerConsent));
        // set-level: {} ⊑_obl {OwnerConsent}; {OwnerConsent} ⋢ {}
        let empty: BTreeSet<Obligation> = BTreeSet::new();
        let owner: BTreeSet<Obligation> = [OwnerConsent].into_iter().collect();
        assert!(obligations_refine(&empty, &owner));
        assert!(!obligations_refine(&owner, &empty));
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
            // Coalitions (UNCK/FVEY) come from the GLOBAL registry now (D1) — no
            // per-SPIF roster. CFCK/NKIC are not in #26's registry (D4), so they
            // resolve to Unknown; the vectors that depended on them are reworked
            // in Task 11.
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
            employment: Employment::FederalCivilian,
            list_memberships: BTreeSet::new(),
            purposes: set(&["OPLAN"]),
        }
    }

    fn mk_resource(level: &str) -> ResourceLabel {
        ResourceLabel {
            classification: Classification {
                policy: PolicyId("US".into()),
                name: level.into(),
            },
            ownership: Ownership::Owned {
                owner: "USA".into(),
            },
            categories: [("SCI".to_string(), set(&["SI"]))].into_iter().collect(),
            disclosure: Disclosure {
                release: Releasability::NoMarking,
                display: None,
                exclusions: BTreeSet::new(),
            },
            controls: Controls::empty(),
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
        // resource classification name not in SPIF (subject known) → Indeterminate
        assert_eq!(
            run(&mk_subject("SECRET"), &mk_resource("MAGENTA"), Action::Read),
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
        s.employment = Employment::Contractor;
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
        r.disclosure.release = Releasability::Grant(set(&["AUS"]));
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
            r.ownership = Ownership::Owned { owner: bad.into() };
            assert_eq!(
                run(&mk_subject("TOP_SECRET"), &r, Action::Read),
                Decision::Deny(DenyReason::Indeterminate),
                "origin {bad:?}"
            );
        }
    }

    #[test]
    fn list_controlled_tag_fails_closed_stage1() {
        // #30 list-control decide semantics land Stage 5; until then a
        // ListControlled-registered tag → Indeterminate (kills the gate-3 arm
        // mutant, since the law sweep excludes ListControlled).
        let spif = Spif::builder("US")
            .levels(&["UNCLASSIFIED", "SECRET", "TOP_SECRET"])
            .category("SCI", CategoryKind::Restrictive)
            .category("ATTY", CategoryKind::ListControlled)
            .build();
        let mut r = mk_resource("SECRET");
        r.categories.insert("ATTY".into(), set(&["LEGAL_TEAM"]));
        assert_eq!(
            decide(
                &mk_subject("TOP_SECRET"),
                &r,
                Action::Read,
                &Purpose("OPLAN".into()),
                &spif,
            ),
            Decision::Deny(DenyReason::Indeterminate)
        );
    }

    #[test]
    fn joint_evaluates_concealed_foreign_and_sentinel_fail_closed() {
        // #40: JOINT is now EVALUATED (a co-owner is eligible to co-produced data).
        // ConcealedForeign + the joint_from(∅) sentinel still fail closed.
        let mut joint = mk_resource("SECRET");
        joint.ownership = Ownership::Joint {
            owners: set(&["USA", "KOR"]),
        };
        // NoMarking → eligible = {USA,KOR}; the USA-national subject is a co-owner → Permit.
        assert_eq!(
            run(&mk_subject("TOP_SECRET"), &joint, Action::Read),
            Decision::Permit
        );
        let mut cf = mk_resource("SECRET");
        cf.ownership = Ownership::ConcealedForeign {
            custodian: "USA".into(),
        };
        assert_eq!(
            run(&mk_subject("TOP_SECRET"), &cf, Action::Read),
            Decision::Deny(DenyReason::Indeterminate)
        );
        // Owned{""} sentinel (joint_from(∅)) → malformed origin → Indeterminate
        let mut empty_owner = mk_resource("SECRET");
        empty_owner.ownership = Ownership::joint_from(BTreeSet::new());
        assert_eq!(
            run(&mk_subject("TOP_SECRET"), &empty_owner, Action::Read),
            Decision::Deny(DenyReason::Indeterminate)
        );
    }

    #[test]
    fn policy_mismatch_deny() {
        let mut s = mk_subject("SECRET");
        s.clearance.policy = PolicyId("AUS".into());
        assert_eq!(
            run(&s, &mk_resource("SECRET"), Action::Read),
            Decision::Deny(DenyReason::PolicyMismatch)
        );
        // mutation-gate: EACH disjunct of gate 1 must deny ALONE (an ||→&&
        // mutant would fall through to gate 2 and mislabel as Indeterminate)
        let mut r = mk_resource("SECRET");
        r.classification.policy = PolicyId("AUS".into()); // resource ≠ spif, subject == spif
        assert_eq!(
            run(&mk_subject("SECRET"), &r, Action::Read),
            Decision::Deny(DenyReason::PolicyMismatch)
        );
        let mut both_aus = mk_subject("SECRET");
        both_aus.clearance.policy = PolicyId("AUS".into()); // subject == resource ≠ spif
        assert_eq!(
            run(&both_aus, &r, Action::Read),
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
        // Federal employment, insufficient clearance — affiliation grants nothing
        let s = mk_subject("UNCLASSIFIED");
        assert_eq!(s.employment, Employment::FederalCivilian);
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
