//! Resource labels, releasability (nation/coalition eligible sets), caveats,
//! and the label lattice: restriction-order `⊑` and derivation-join `∨`.
//!
//! Releasability orientation (ADR-0008 §2.4): restriction order — `∨` is the
//! least-upper-bound, the MORE-restrictive combine. `⊤` (most restrictive) is
//! explicit `REL ∅` (releasable to no one, including the origin); `⊥` (least
//! restrictive, the join identity) is `REL ALL`/public. The origin nation is
//! always a member of any non-empty REL set; an ABSENT REL marking computes to
//! `REL {origin}` (NOFORN-equivalent), never to ⊥. Join on releasability is
//! component-wise set INTERSECTION of eligible nations and eligible coalitions.

use crate::policy::{is_trigraph, Spif, TetraExpansion};
use std::collections::BTreeSet;

/// The releasability marking as originated (three explicit states + absence).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Releasability {
    /// No REL marking → computed `REL {origin}` (NOFORN-equivalent).
    NoMarking,
    /// Explicit `REL TO` set (nation trigraphs + tetragraph tokens).
    /// INVARIANT: non-empty (a would-be `Grant(∅)` is the `NoMarking` state).
    /// The origin is always eligible whether or not it is listed.
    Grant(BTreeSet<String>),
    /// Explicit `REL ∅` — releasable to none, INCLUDING the origin (`⊤`).
    Empty,
    /// Explicit `REL ALL` — everyone (`⊥`, the join identity).
    Public,
}

/// The expanded eligibility of a releasability marking. The nation and
/// coalition namespaces are STRUCTURALLY separate: a subject's coalition
/// assertions are matched only against `coalitions`, so asserting a nation
/// trigraph (even the origin) as a coalition membership grants nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EligibleNations {
    /// `⊥` — public, everyone eligible.
    Universe,
    /// Finite eligibility; both fields empty = deny-all = `⊤`.
    Set {
        /// Nation trigraphs, matched against `Subject::nationality`.
        nations: BTreeSet<String>,
        /// Registered non-decomposable coalition tokens, matched against
        /// `Subject::coalition_memberships`.
        coalitions: BTreeSet<String>,
    },
}

/// Ingest-validation failures for an explicit `REL TO` grant set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelValidationError {
    /// A listed member is already covered by a listed decomposable
    /// tetragraph's expansion (origin-exempt on both clauses).
    DuplicativeTetragraph { token: String, covered: String },
    /// An explicit empty grant — use `Releasability::Empty` or `NoMarking`.
    EmptyGrant,
    /// A non-trigraph token the SPIF does not register.
    UnknownToken(String),
}

impl Releasability {
    /// Expand to the canonical eligible sets for a given origin + SPIF.
    ///
    /// Trigraph-shaped tokens → nations; decomposable tetragraphs → their
    /// member nations; registered non-decomposable tokens → coalitions;
    /// unknown non-trigraph tokens → DROPPED (grant nothing — fail closed).
    /// The origin is unioned into nations for every non-`Empty` finite form.
    pub fn eligible(&self, origin: &str, spif: &Spif) -> EligibleNations {
        match self {
            Releasability::Public => EligibleNations::Universe,
            Releasability::Empty => EligibleNations::Set {
                nations: BTreeSet::new(),
                coalitions: BTreeSet::new(),
            },
            Releasability::NoMarking => EligibleNations::Set {
                nations: [origin.to_string()].into_iter().collect(),
                coalitions: BTreeSet::new(),
            },
            Releasability::Grant(tokens) => {
                let mut nations: BTreeSet<String> = BTreeSet::new();
                let mut coalitions: BTreeSet<String> = BTreeSet::new();
                for token in tokens {
                    if is_trigraph(token) {
                        nations.insert(token.clone());
                    } else {
                        match spif.expand_tetra(token) {
                            TetraExpansion::Nations(members) => nations.extend(members),
                            TetraExpansion::NonDecomposable => {
                                coalitions.insert(token.clone());
                            }
                            TetraExpansion::Unknown => {} // dropped — grants nothing
                        }
                    }
                }
                nations.insert(origin.to_string());
                EligibleNations::Set {
                    nations,
                    coalitions,
                }
            }
        }
    }

    /// Canonicalize an eligible set back to the unique `Releasability` form:
    /// `Universe → Public`; both-∅ → `Empty`; nations `== {origin}` with no
    /// coalitions → `NoMarking`; else `Grant((nations ∖ {origin}) ∪ coalitions)`
    /// — guaranteed non-empty.
    ///
    /// Precondition: `e` was produced by [`Releasability::eligible`] or
    /// [`EligibleNations::join`] with the same `origin` (every non-empty such
    /// set contains the origin). A caller-constructed set violating this would
    /// round-trip wider.
    pub fn from_eligible(e: &EligibleNations, origin: &str) -> Releasability {
        match e {
            EligibleNations::Universe => Releasability::Public,
            EligibleNations::Set {
                nations,
                coalitions,
            } => {
                debug_assert!(
                    (nations.is_empty() && coalitions.is_empty()) || nations.contains(origin),
                    "from_eligible precondition: input must come from eligible()/join()"
                );
                if nations.is_empty() && coalitions.is_empty() {
                    return Releasability::Empty;
                }
                let mut grant: BTreeSet<String> = nations.clone();
                grant.remove(origin);
                grant.extend(coalitions.iter().cloned());
                if grant.is_empty() {
                    Releasability::NoMarking
                } else {
                    Releasability::Grant(grant)
                }
            }
        }
    }
}

impl EligibleNations {
    /// Whether a subject with this nationality and these coalition assertions
    /// is eligible. Coalition assertions are matched ONLY against the
    /// coalitions field — the namespaces never cross.
    pub fn permits(&self, nationality: &str, subject_coalitions: &BTreeSet<String>) -> bool {
        match self {
            EligibleNations::Universe => true,
            EligibleNations::Set {
                nations,
                coalitions,
            } => nations.contains(nationality) || !subject_coalitions.is_disjoint(coalitions),
        }
    }

    /// `∨` on releasability = component-wise intersection (`Universe ∩ x = x`).
    pub fn join(&self, other: &EligibleNations) -> EligibleNations {
        match (self, other) {
            (EligibleNations::Universe, x) | (x, EligibleNations::Universe) => x.clone(),
            (
                EligibleNations::Set {
                    nations: n1,
                    coalitions: c1,
                },
                EligibleNations::Set {
                    nations: n2,
                    coalitions: c2,
                },
            ) => EligibleNations::Set {
                nations: n1.intersection(n2).cloned().collect(),
                coalitions: c1.intersection(c2).cloned().collect(),
            },
        }
    }

    /// `X ⊆ Universe` always; `Universe ⊆ Set` never; `Set ⊆ Set` = both
    /// fields subset.
    pub fn is_subset_of(&self, other: &EligibleNations) -> bool {
        match (self, other) {
            (_, EligibleNations::Universe) => true,
            (EligibleNations::Universe, EligibleNations::Set { .. }) => false,
            (
                EligibleNations::Set {
                    nations: n1,
                    coalitions: c1,
                },
                EligibleNations::Set {
                    nations: n2,
                    coalitions: c2,
                },
            ) => n1.is_subset(n2) && c1.is_subset(c2),
        }
    }
}

/// Ingest-time coalition validation (spec §6.3 anti-duplication). Two clauses:
///
/// 1. Nation-vs-tetragraph — per `design/references/dcs-schema-migration.md`
///    (REL TO validation rules): a listed NON-ORIGIN nation covered by a listed
///    decomposable tetragraph's expansion is a duplicate. The ORIGIN trigraph
///    is exempt: `REL TO USA, FVEY` (USA origin) is VALID per the reference.
/// 2. Tetragraph-vs-tetragraph — MAKNAE-LOCAL STRICTNESS (not in the DCS
///    reference): two listed decomposable tetragraphs whose expansions overlap
///    BEYOND the origin are duplicative. Overlap is computed on
///    `expansion ∖ {origin}`, so the origin exemption applies uniformly.
///
/// Non-decomposable tokens are excluded (membership unknowable ⇒ duplication
/// undetectable — intentional). The JOINT co-owner exception in the reference
/// is out of MVP scope. This crate provides the predicate; the enforcement
/// locus (kernel ingest / spifc) is recorded in the ADR.
pub fn validate_rel(
    grant: &BTreeSet<String>,
    origin: &str,
    spif: &Spif,
) -> Result<(), RelValidationError> {
    if grant.is_empty() {
        return Err(RelValidationError::EmptyGrant);
    }
    for token in grant {
        if !is_trigraph(token) && spif.expand_tetra(token) == TetraExpansion::Unknown {
            return Err(RelValidationError::UnknownToken(token.clone()));
        }
    }
    // Collect the decomposable tetragraphs and their origin-stripped expansions.
    let decomposable: Vec<(&String, BTreeSet<String>)> = grant
        .iter()
        .filter(|t| !is_trigraph(t))
        .filter_map(|t| match spif.expand_tetra(t) {
            TetraExpansion::Nations(mut members) => {
                members.remove(origin);
                Some((t, members))
            }
            _ => None,
        })
        .collect();
    for (tetra, expansion) in &decomposable {
        for member in grant {
            if member == *tetra {
                continue;
            }
            if is_trigraph(member) {
                // Clause 1: non-origin nation covered by a listed tetragraph.
                if member != origin && expansion.contains(member) {
                    return Err(RelValidationError::DuplicativeTetragraph {
                        token: member.clone(),
                        covered: (*tetra).clone(),
                    });
                }
            } else if let Some((_, other_expansion)) =
                decomposable.iter().find(|(t, _)| *t == member)
            {
                // Clause 2 (Maknae-local): expansions overlap beyond the origin.
                if !expansion.is_disjoint(other_expansion) {
                    return Err(RelValidationError::DuplicativeTetragraph {
                        token: member.clone(),
                        covered: (*tetra).clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Handling caveats carried on a label. `decide()` enforces ONLY
/// `DisplayOnly` (blocks `Action::Export`); `NoEgress` and `OperatorOnly` are
/// carried label data — joined by ∪, preserved through derivation — whose
/// enforcement locus is the kernel hooks (hook-E egress screen / session
/// gating), not this crate's read decision. Deliberate MVP division of labor,
/// recorded in ADR-0008.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Caveat {
    NoEgress,
    OperatorOnly,
    DisplayOnly,
}

/// Restrictive (containment) dominance: subject holds ⊇ resource, per tag.
/// Hierarchy via `PARENT//CHILD` path-encoded nodes treated as opaque distinct
/// tokens — exactness IS the hierarchy rule (holding `SI` does not contain
/// `SI//G`).
///
/// Empty-set polarity (pinned): `required = ∅` → `true` (vacuous ⊇) — but
/// UNREACHABLE from `decide()`, whose gate-3 precheck denies `Indeterminate`
/// on any empty required-set before dispatch. Contrast
/// [`crate::subject::affiliation_satisfies`], whose `∅` → `false`. Callers
/// outside `decide()` must precheck, per the gate-3 pattern.
pub fn restrictive_dominates(held: &BTreeSet<String>, required: &BTreeSet<String>) -> bool {
    required.is_subset(held)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Spif;

    fn set(xs: &[&str]) -> BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn restrictive_requires_superset() {
        assert!(restrictive_dominates(
            &set(&["SI", "TK", "HCS"]),
            &set(&["SI", "TK"])
        )); // ⊇ permit
        assert!(!restrictive_dominates(&set(&["SI"]), &set(&["SI", "TK"]))); // missing TK → deny
    }

    #[test]
    fn restrictive_hierarchy_parent_does_not_grant_child() {
        assert!(!restrictive_dominates(&set(&["SI"]), &set(&["SI//G"]))); // parent ≠ sub-compartment
        assert!(restrictive_dominates(&set(&["SI//G"]), &set(&["SI//G"]))); // exact
    }

    #[test]
    fn restrictive_empty_required_is_vacuously_true_but_unreachable_from_decide() {
        // pinned ∅-polarity: vacuous ⊇ (contrast affiliation_satisfies ∅ → false);
        // unreachable from decide() — gate 3's precheck denies Indeterminate first
        assert!(restrictive_dominates(&set(&[]), &set(&[])));
        assert!(restrictive_dominates(&set(&["SI"]), &set(&[])));
    }

    #[test]
    fn nomarking_is_origin_only() {
        let spif = Spif::builder("US").build();
        let e = Releasability::NoMarking.eligible("USA", &spif);
        assert!(e.permits("USA", &set(&[]))); // origin permits
        assert!(!e.permits("AUS", &set(&[]))); // foreign denies (NOFORN-equiv)
    }

    #[test]
    fn grant_includes_origin_and_listed() {
        let spif = Spif::builder("US").build();
        let e = Releasability::Grant(set(&["AUS"])).eligible("USA", &spif);
        assert!(e.permits("USA", &set(&[]))); // origin always eligible
        assert!(e.permits("AUS", &set(&[]))); // listed
        assert!(!e.permits("KOR", &set(&[]))); // not listed
    }

    #[test]
    fn nation_code_asserted_as_coalition_grants_nothing() {
        // the two namespaces are separate — a trigraph in coalition_memberships never matches
        let spif = Spif::builder("US").build();
        let e = Releasability::Grant(set(&["AUS"])).eligible("USA", &spif);
        assert!(!e.permits("KOR", &set(&["AUS"]))); // asserting AUS-as-coalition grants nothing
        assert!(!e.permits("KOR", &set(&["USA"]))); // asserting the ORIGIN-as-coalition grants nothing
    }

    #[test]
    fn empty_denies_all_including_origin() {
        let spif = Spif::builder("US").build();
        let e = Releasability::Empty.eligible("USA", &spif);
        assert!(!e.permits("USA", &set(&[]))); // ⊤ — deny even origin
        assert!(!e.permits("AUS", &set(&[])));
    }

    #[test]
    fn public_permits_everyone() {
        let spif = Spif::builder("US").build();
        assert!(Releasability::Public
            .eligible("USA", &spif)
            .permits("ANY", &set(&[])));
    }

    #[test]
    fn tetragraph_decomposes_in_eligible() {
        let spif = Spif::builder("US")
            .tetragraph("CFCK", Some(&["USA", "KOR"]))
            .build();
        let e = Releasability::Grant(set(&["CFCK"])).eligible("USA", &spif);
        assert!(e.permits("KOR", &set(&[]))); // decomposed into nations
        assert!(!e.permits("AUS", &set(&[]))); // AUS not in CFCK (CFC≠UNC)
    }

    #[test]
    fn non_decomposable_needs_subject_membership() {
        let spif = Spif::builder("US").tetragraph("NKIC", None).build();
        let e = Releasability::Grant(set(&["NKIC"])).eligible("USA", &spif);
        assert!(!e.permits("KOR", &set(&[]))); // nationality can't be inferred
        assert!(e.permits("KOR", &set(&["NKIC"]))); // subject holds the coalition membership
    }

    #[test]
    fn unknown_token_grants_nothing() {
        // fail-closed: an unregistered non-trigraph token is dropped — even a
        // subject ASSERTING it is denied
        let spif = Spif::builder("US").build(); // "ZZZZ" not registered
        let e = Releasability::Grant(set(&["ZZZZ"])).eligible("USA", &spif);
        assert!(e.permits("USA", &set(&[]))); // origin still eligible
        assert!(!e.permits("KOR", &set(&["ZZZZ"]))); // assertion of an unknown token grants nothing
    }

    #[test]
    fn join_is_intersection_aus_kor_reduces_to_origin() {
        // #6 flagship: REL AUS ⊕ REL KOR (US origin) → {USA} = REL {origin},
        // NOT REL AUS,KOR, NOT REL ∅.
        let spif = Spif::builder("US").build();
        let a = Releasability::Grant(set(&["AUS"])).eligible("USA", &spif); // nations {USA,AUS}
        let b = Releasability::Grant(set(&["KOR"])).eligible("USA", &spif); // nations {USA,KOR}
        let j = a.join(&b); // ∩ = {USA}
        assert!(j.permits("USA", &set(&[])));
        assert!(!j.permits("AUS", &set(&[])));
        assert!(!j.permits("KOR", &set(&[])));
    }

    #[test]
    fn join_universe_is_identity() {
        let spif = Spif::builder("US").build();
        let g = Releasability::Grant(set(&["AUS"])).eligible("USA", &spif);
        let j = EligibleNations::Universe.join(&g);
        assert!(
            j.permits("AUS", &set(&[]))
                && j.permits("USA", &set(&[]))
                && !j.permits("KOR", &set(&[]))
        );
    }

    #[test]
    fn from_eligible_is_canonical_and_unique() {
        // one form per semantic state; Grant(∅) can never be produced
        let origin = "USA";
        let s = |n: &[&str], c: &[&str]| EligibleNations::Set {
            nations: set(n),
            coalitions: set(c),
        };
        assert!(matches!(
            Releasability::from_eligible(&EligibleNations::Universe, origin),
            Releasability::Public
        ));
        assert!(matches!(
            Releasability::from_eligible(&s(&[], &[]), origin),
            Releasability::Empty
        ));
        assert!(matches!(
            Releasability::from_eligible(&s(&["USA"], &[]), origin),
            Releasability::NoMarking
        ));
        match Releasability::from_eligible(&s(&["USA", "AUS"], &[]), origin) {
            Releasability::Grant(g) => {
                assert_eq!(g, set(&["AUS"]));
                assert!(!g.is_empty());
            }
            other => panic!("expected Grant, got {other:?}"),
        }
        match Releasability::from_eligible(&s(&["USA"], &["NKIC"]), origin) {
            Releasability::Grant(g) => assert_eq!(g, set(&["NKIC"])), // coalition survives canonicalization
            other => panic!("expected Grant, got {other:?}"),
        }
    }

    #[test]
    fn subset_helper_handles_universe() {
        let s = |n: &[&str]| EligibleNations::Set {
            nations: set(n),
            coalitions: set(&[]),
        };
        assert!(s(&["USA"]).is_subset_of(&EligibleNations::Universe));
        assert!(!EligibleNations::Universe.is_subset_of(&s(&["USA"])));
        // reflexive — a match arm ordered (Universe, _) => false would pass the
        // two asserts above and break reflexivity for Public labels
        assert!(EligibleNations::Universe.is_subset_of(&EligibleNations::Universe));
        assert!(s(&["USA"]).is_subset_of(&s(&["USA", "AUS"])));
        assert!(!s(&["USA", "KOR"]).is_subset_of(&s(&["USA", "AUS"])));
    }

    #[test]
    fn validate_rel_origin_exempt_and_rejects_duplicative() {
        // per design/references/dcs-schema-migration.md REL TO validation:
        //   VALID:   REL TO USA, FVEY        (origin USA listed alongside its tetragraph)
        //   VALID:   REL TO USA, DEU, FVEY   (DEU not in FVEY)
        //   INVALID: REL TO USA, GBR, FVEY   (GBR ∈ FVEY — duplicate)
        let spif = Spif::builder("US")
            .tetragraph("FVEY", Some(&["USA", "AUS", "CAN", "GBR", "NZL"]))
            .build();
        assert!(validate_rel(&set(&["USA", "FVEY"]), "USA", &spif).is_ok());
        assert!(validate_rel(&set(&["USA", "DEU", "FVEY"]), "USA", &spif).is_ok());
        match validate_rel(&set(&["USA", "GBR", "FVEY"]), "USA", &spif) {
            Err(RelValidationError::DuplicativeTetragraph { token, covered }) => {
                assert_eq!(token, "GBR"); // fires on GBR, not the exempt origin
                assert_eq!(covered, "FVEY");
            }
            other => panic!("expected DuplicativeTetragraph(GBR), got {other:?}"),
        }
        assert!(matches!(
            validate_rel(&set(&[]), "USA", &spif),
            Err(RelValidationError::EmptyGrant)
        ));
        assert!(matches!(
            validate_rel(&set(&["ZZZZ"]), "USA", &spif),
            Err(RelValidationError::UnknownToken(_))
        ));
        assert!(validate_rel(&set(&["FVEY"]), "USA", &spif).is_ok());
        assert!(validate_rel(&set(&["KOR", "JPN"]), "USA", &spif).is_ok()); // bare trigraphs need no registration
    }

    #[test]
    fn validate_rel_tetra_tetra_overlap_is_origin_exempt() {
        // Maknae-local strictness: overlap computed on expansion ∖ {origin}
        let spif = Spif::builder("US")
            .tetragraph("FVEY", Some(&["USA", "AUS", "CAN", "GBR", "NZL"]))
            .tetragraph("CFCK", Some(&["USA", "KOR"]))
            .tetragraph("MINI", Some(&["USA", "KOR", "AUS"]))
            .build();
        // overlap = {USA} = origin only → VALID
        assert!(validate_rel(&set(&["CFCK", "FVEY"]), "USA", &spif).is_ok());
        // overlap ∖ origin = {KOR} → duplicate
        assert!(matches!(
            validate_rel(&set(&["CFCK", "MINI"]), "USA", &spif),
            Err(RelValidationError::DuplicativeTetragraph { .. })
        ));
    }
}
