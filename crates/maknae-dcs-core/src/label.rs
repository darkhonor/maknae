//! Resource labels, releasability (a single resolved nation eligible set),
//! obligations, and the label lattice: restriction-order `⊑` and derivation-join `∨`.
//!
//! Releasability orientation (ADR-0008 §2.4): restriction order — `∨` is the
//! least-upper-bound, the MORE-restrictive combine. `⊤` (most restrictive) is
//! `REL {owners}` = `NoMarking`/NOFORN (origin-only); `REL ∅`/`Empty` is a
//! fail-closed deny-all sentinel, not authorable (#51). `⊥` (least
//! restrictive, the join identity) is `REL ALL`/public. The origin nation is
//! always a member of any non-empty REL set; an ABSENT REL marking computes to
//! `REL {origin}` (NOFORN-equivalent), never to ⊥. Join on releasability is
//! set INTERSECTION of the resolved eligible nations (#26: coalition tetragraphs
//! decompose to member nations at expansion time — a single nation namespace).

use crate::controls::{ControlMarking, Controls};
use crate::ownership::Ownership;
use crate::policy::{is_trigraph, Spif, TetraExpansion};
use crate::registry;
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
    /// Fail-closed **deny-all sentinel** (#51): the `∅` eligible set. NOT an
    /// authorable marking and NOT the lattice `⊤` (the ⊤ is `{owners}` =
    /// `NoMarking`/NOFORN); `validate_label` rejects it. Only legitimate producer:
    /// `from_eligible` on a precondition violation (an eligible set missing an owner).
    Empty,
    /// Explicit `REL ALL` — everyone (`⊥`, the join identity).
    Public,
}

/// The expanded eligibility of a releasability marking: a SINGLE nation
/// namespace (#26 expand-or-deny). Coalition tetragraphs are decomposed to their
/// member nations at expansion time, so there is no separate coalition-
/// credential axis — a subject is eligible iff its nationality is in the
/// resolved nation set. A subject's coalition assertions are never consulted
/// (the coalition-credential arm is removed); membership is decided by
/// nationality alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EligibleNations {
    /// `⊥` — public, everyone eligible.
    Universe,
    /// Finite eligibility; empty set = fail-closed deny-all sentinel (#51 — not
    /// the lattice `⊤`; the ⊤ is `{owners}`).
    Set {
        /// Nation trigraphs, matched against `Subject::nationality`.
        nations: BTreeSet<String>,
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

/// Why `validate_label` rejects a label at ingest (#26 two-locus enforcement,
/// part 1). Existence-agnostic: a variant names the failing DIMENSION, never a
/// specific token/coalition, so the refusal discloses no membership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LabelInvalidity {
    /// A releasability or exclusion token outside the encoded world view — a
    /// trigraph that is not an ISO-3166 nation, or a non-trigraph that is not a
    /// registered coalition (maps to `DenyReason::InvalidElement`).
    Element,
    /// A structurally malformed label (maps to `DenyReason::InvalidLabel`):
    /// - an owner/co-owner appears in the NAF exclusion set (spec §6 — the owner
    ///   is never excluded); or
    /// - a NAF exclusion accompanies a `Public`/`Empty`/`NoMarking` release (DoDM
    ///   §e: a dissemination restriction is for classified, NAMED recipients, not
    ///   an all/none/origin marking); or
    /// - `display ⊉ release` (the dual-relation invariant).
    Label,
}

impl Releasability {
    /// Expand to the canonical resolved nation set for the OWNER SET + SPIF (#40).
    ///
    /// Trigraph-shaped tokens → nations; registered coalition tetragraphs →
    /// their member nations (in-memory expand-or-deny, #26); unknown non-trigraph
    /// tokens → DROPPED (grant nothing — fail closed). ALL co-owners are unioned
    /// into nations for every non-`Empty` finite form — each co-owner is eligible
    /// to data it co-produced (#40). Single-owner is the special case
    /// `owners = {origin}`, identical to the v1 behavior.
    pub fn eligible(&self, owners: &BTreeSet<String>, spif: &Spif) -> EligibleNations {
        match self {
            Releasability::Public => EligibleNations::Universe,
            Releasability::Empty => EligibleNations::Set {
                nations: BTreeSet::new(),
            },
            Releasability::NoMarking => EligibleNations::Set {
                nations: owners.clone(),
            },
            Releasability::Grant(tokens) => {
                let mut nations: BTreeSet<String> = BTreeSet::new();
                for token in tokens {
                    if is_trigraph(token) {
                        nations.insert(token.clone());
                    } else {
                        match spif.expand_tetra(token) {
                            // Coalitions decompose to member nations (#26
                            // expand-or-deny). Re-filter to trigraphs as
                            // belt-and-braces so a malformed expansion can never
                            // enter the namespace and widen through the join
                            // round-trip (build.rs also guarantees this at
                            // build time). An Unknown token is DROPPED here —
                            // grants nothing — and the Unknown→Deny is enforced
                            // at both loci (validate_label + gate-4), never
                            // silently in `eligible`.
                            TetraExpansion::Nations(members) => {
                                nations.extend(members.into_iter().filter(|m| is_trigraph(m)));
                            }
                            TetraExpansion::Unknown => {}
                        }
                    }
                }
                nations.extend(owners.iter().cloned());
                EligibleNations::Set { nations }
            }
        }
    }

    /// Canonicalize an eligible set back to the unique `Releasability` form:
    /// `Universe → Public`; ∅ → `Empty`; nations `== owners` → `NoMarking`;
    /// else `Grant(nations ∖ owners)` — guaranteed non-empty.
    ///
    /// The `∅ → Empty` case is a **fail-closed deny-all sentinel**, NOT a canonical
    /// authorable form (#51): both `Empty`-returning branches below (`nations` empty,
    /// or an owner absent) are only reachable from invalid/precondition-violating
    /// input — a join of owner-containing sets always retains the owners, so a valid
    /// derivation never lands here.
    ///
    /// Precondition (#40): `e` was produced by [`Releasability::eligible`] or
    /// [`EligibleNations::join`] with the same OWNER SET (every non-empty such
    /// set contains ALL co-owners). A caller-constructed set violating the
    /// precondition (some owner absent) FAILS CLOSED to `Empty` (deny-all) —
    /// never a panic (the crate is pure/total) and never a silent round-trip
    /// widening (`eligible` re-adds every owner, so representing the violating
    /// set as a `Grant` would make an owner eligible when it was not).
    pub fn from_eligible(e: &EligibleNations, owners: &BTreeSet<String>) -> Releasability {
        match e {
            EligibleNations::Universe => Releasability::Public,
            EligibleNations::Set { nations } => {
                if nations.is_empty() {
                    return Releasability::Empty;
                }
                if !owners.is_subset(nations) {
                    // precondition violated (some co-owner absent) → deny-all
                    return Releasability::Empty;
                }
                let mut grant: BTreeSet<String> = nations.clone();
                for o in owners {
                    grant.remove(o);
                }
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
    /// Whether a subject with this nationality is eligible. Decided by
    /// nationality alone (#26): coalition tetragraphs were already decomposed to
    /// member nations at expansion time, so a subject's asserted coalition
    /// memberships are NOT consulted — the credential arm is removed.
    pub fn permits(&self, nationality: &str) -> bool {
        match self {
            EligibleNations::Universe => true,
            EligibleNations::Set { nations } => nations.contains(nationality),
        }
    }

    /// `∨` on releasability = set intersection (`Universe ∩ x = x`).
    pub fn join(&self, other: &EligibleNations) -> EligibleNations {
        match (self, other) {
            (EligibleNations::Universe, x) | (x, EligibleNations::Universe) => x.clone(),
            (EligibleNations::Set { nations: n1 }, EligibleNations::Set { nations: n2 }) => {
                EligibleNations::Set {
                    nations: n1.intersection(n2).cloned().collect(),
                }
            }
        }
    }

    /// `X ⊆ Universe` always; `Universe ⊆ Set` never; `Set ⊆ Set` = nations
    /// subset.
    pub fn is_subset_of(&self, other: &EligibleNations) -> bool {
        match (self, other) {
            (_, EligibleNations::Universe) => true,
            (EligibleNations::Universe, EligibleNations::Set { .. }) => false,
            (EligibleNations::Set { nations: n1 }, EligibleNations::Set { nations: n2 }) => {
                n1.is_subset(n2)
            }
        }
    }
}

/// Dual-relation disclosure (spec §2.2): the release relation (v1 semantics),
/// an optional display relation (`display ⊇ release`), and NAF exclusions
/// (#26 NOT AUTHORIZED FOR). Exclusion ENFORCEMENT at permits-time is Stage 2;
/// this type lands the relations + their decomposed order/join.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disclosure {
    /// The release relation (who may RECEIVE a copy) — v1 releasability.
    pub release: Releasability,
    /// The display relation (who may VIEW). `None` means "display = release".
    /// INVARIANT (validate_label, Stage 4): display ⊇ release.
    pub display: Option<Releasability>,
    /// NOT AUTHORIZED FOR (#26): nations excluded regardless of grant. Carried
    /// + unioned on join in Stage 1; permits-time dominance is Stage 2.
    pub exclusions: BTreeSet<String>,
}

impl Disclosure {
    fn deny_all() -> EligibleNations {
        EligibleNations::Set {
            nations: BTreeSet::new(),
        }
    }

    /// Subtract the NAF exclusions (#26) from a resolved eligible set. Applied
    /// to the RELEASE relation only. A `Universe` (`REL ALL`/Public) set is
    /// returned unchanged: a NAF on a `Public`/`Empty`/`NoMarking` release is an
    /// `InvalidLabel`, rejected at BOTH loci (`validate_label` + gate-4) and
    /// asserted unreachable in the law universe, so this never sees a non-empty
    /// exclusion set over `Universe`.
    fn subtract_exclusions(&self, e: EligibleNations) -> EligibleNations {
        match e {
            EligibleNations::Universe => EligibleNations::Universe,
            EligibleNations::Set { mut nations } => {
                nations.retain(|n| !self.exclusions.contains(n));
                EligibleNations::Set { nations }
            }
        }
    }

    /// Eligible set for the RELEASE relation (who may receive a copy), with the
    /// NAF exclusions subtracted (#26 expand-or-deny: nationality ∈ resolved ∖ X).
    pub fn eligible_release(&self, base: &BTreeSet<String>, spif: &Spif) -> EligibleNations {
        // #40: any non-empty owner set (1 or ≥2 co-owners) resolves; only an
        // empty base fails closed. All owners are unioned into the resolved set
        // by `Releasability::eligible`.
        if base.is_empty() {
            return Self::deny_all();
        }
        self.subtract_exclusions(self.release.eligible(base, spif))
    }

    /// Eligible set for the DISPLAY relation (who may view). A `None` display
    /// tracks the RELEASE relation — INCLUDING its NAF subtraction (a copy you
    /// cannot receive you cannot view). An EXPLICIT display grant is untouched by
    /// release-side NAF (display-side exclusions are #27, out of #26 scope).
    pub fn eligible_display(&self, base: &BTreeSet<String>, spif: &Spif) -> EligibleNations {
        match &self.display {
            None => self.eligible_release(base, spif),
            Some(d) => {
                if base.is_empty() {
                    Self::deny_all()
                } else {
                    d.eligible(base, spif)
                }
            }
        }
    }

    /// The `display ⊇ release` invariant (validate_label consults this).
    pub fn display_covers_release(&self, base: &BTreeSet<String>, spif: &Spif) -> bool {
        self.eligible_release(base, spif)
            .is_subset_of(&self.eligible_display(base, spif))
    }

    /// `∨`: release ∩ release, display ∩ display. Ownership is identical at the
    /// ResourceLabel call site, so one `base` suffices.
    ///
    /// The NAF exclusions are NO LONGER a lattice axis (#26): `eligible_release`
    /// bakes the subtraction into each operand's RESOLVED set BEFORE the `∩`, so
    /// the joined `release` already omits every excluded nation. The result
    /// therefore carries an EMPTY `exclusions` field — the exclusion is consumed
    /// into the (narrower) release grant, not re-carried as a separate axis.
    pub fn join(&self, other: &Disclosure, base: &BTreeSet<String>, spif: &Spif) -> Disclosure {
        // #40: canonicalize the joined eligible sets against the whole owner set.
        let release = if base.is_empty() {
            Releasability::Empty
        } else {
            Releasability::from_eligible(
                &self
                    .eligible_release(base, spif)
                    .join(&other.eligible_release(base, spif)),
                base,
            )
        };
        // display present in the result iff either operand carried an explicit
        // display; otherwise it tracks release (None).
        let display = if self.display.is_none() && other.display.is_none() {
            None
        } else if base.is_empty() {
            Some(Releasability::Empty)
        } else {
            Some(Releasability::from_eligible(
                &self
                    .eligible_display(base, spif)
                    .join(&other.eligible_display(base, spif)),
                base,
            ))
        };
        Disclosure {
            release,
            display,
            exclusions: BTreeSet::new(),
        }
    }

    /// `⊑` (decomposed, spec §2.2): release-eligible(other) ⊆ release-eligible(self)
    /// AND display-eligible(other) ⊆ display-eligible(self). The exclusions are
    /// consumed by `eligible_release`'s subtraction (#26) — they are no longer a
    /// separate lattice axis, so two disclosures with equal RESOLVED release/
    /// display sets are `⊑` both ways regardless of their raw exclusion markings.
    /// Ownership identical at the call site → one base.
    pub fn le(&self, other: &Disclosure, base: &BTreeSet<String>, spif: &Spif) -> bool {
        other
            .eligible_release(base, spif)
            .is_subset_of(&self.eligible_release(base, spif))
            && other
                .eligible_display(base, spif)
                .is_subset_of(&self.eligible_display(base, spif))
    }
}

/// Ingest-time coalition validation (spec §6.3 anti-duplication). Two clauses:
///
/// 1. Nation-vs-tetragraph — per `design/references/dcs-schema-migration.md`
///    (REL TO validation rules): a listed NON-OWNER nation covered by a listed
///    decomposable tetragraph's expansion is a duplicate. Every CO-OWNER is
///    exempt: `REL TO USA, FVEY` (USA owner) is VALID, and for a JOINT label
///    `REL TO USA, KOR, FVEY` (owners USA+KOR) is VALID even though FVEY covers
///    KOR — a co-owner MAY appear in REL TO even when a listed tetragraph covers
///    it (#25 co-owner exemption, un-deferring the JOINT case from the reference).
/// 2. Tetragraph-vs-tetragraph — MAKNAE-LOCAL STRICTNESS (not in the DCS
///    reference): two listed decomposable tetragraphs whose expansions overlap
///    BEYOND the owners are duplicative. Overlap is computed on
///    `expansion ∖ owners`, so the co-owner exemption applies uniformly.
///
/// Non-decomposable tokens are excluded (membership unknowable ⇒ duplication
/// undetectable — intentional). This crate provides the predicate; the
/// enforcement locus (kernel ingest / spifc) is recorded in the ADR. Single-owner
/// is the special case `owners = {origin}`.
pub fn validate_rel(
    grant: &BTreeSet<String>,
    owners: &BTreeSet<String>,
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
    // Collect the decomposable tetragraphs and their owner-stripped expansions.
    let decomposable: Vec<(&String, BTreeSet<String>)> = grant
        .iter()
        .filter(|t| !is_trigraph(t))
        .filter_map(|t| match spif.expand_tetra(t) {
            TetraExpansion::Nations(mut members) => {
                members.retain(|m| !owners.contains(m));
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
                // Clause 1: non-owner nation covered by a listed tetragraph.
                if !owners.contains(member) && expansion.contains(member) {
                    return Err(RelValidationError::DuplicativeTetragraph {
                        token: member.clone(),
                        covered: (*tetra).clone(),
                    });
                }
            } else if let TetraExpansion::Nations(other) = spif.expand_tetra(member) {
                // Clause 2 (Maknae-local): `member` is another listed coalition;
                // if its OWNER-STRIPPED expansion overlaps this tetra's, they
                // are duplicative. Recompute the member's expansion directly (not
                // via a lookup keyed on `member`) so the co-owner-exemption is the
                // load-bearing, mutation-testable operation.
                let other: BTreeSet<String> =
                    other.into_iter().filter(|m| !owners.contains(m)).collect();
                if !expansion.is_disjoint(&other) {
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

/// Redissemination scope for ORCON-family obligations (spec §2.3). Closed —
/// extend only by ADR amendment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RedisseminationScope {
    /// ORCON-USGOV pre-approved redissemination scope (IC Register :7341):
    /// further dissemination WITHOUT originator approval to US Government
    /// Executive Branch departments/agencies (unconditional); and to congressional
    /// Intelligence Committees ONLY for disseminated analytic products (DAPs — "not
    /// unevaluated or raw intelligence"), per originating-agency/OLA consultation.
    /// Any other US recipient still requires originator approval. The PEP honors
    /// the precise contours; the engine only emits the scope token (#48).
    UsGov,
}

/// A closed obligation the engine attaches to a permit (spec §2.3). Co-located
/// with `ResourceLabel` (the label carries `obligations`) for the eventual #44
/// label-crate extraction — `decide` depends on `label`, not the reverse.
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

/// A resource's confidentiality label. No `Default` — there is no
/// access-granting default label.
///
/// The LDC predicate-tag convention: an LDC lives in `categories` under a tag
/// registered as `RestrictivePredicate` (e.g. `"LDC"`), with the control
/// tokens as the values — `{"LDC": {"FEDCON"}}`. The values are what the
/// predicate evaluates; they are never compared against read-ins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceLabel {
    pub classification: crate::policy::Classification,
    /// Who owns the information (#25). Generalizes v1 `origin`. The lattice
    /// `∨`/`⊑` are defined only WITHIN an identical ownership frame; malformed
    /// owner tokens poison them to `None` and `decide()` to `Indeterminate`.
    pub ownership: Ownership,
    /// tag → required values; the tag's SPIF-declared `CategoryKind` decides
    /// the satisfaction rule. INVARIANT: no empty value-sets stored (an
    /// empty-valued tag poisons `⊑`/`join` to `None` and `decide()` to
    /// `Deny(Indeterminate)` — never silently normalized).
    pub categories: std::collections::BTreeMap<String, BTreeSet<String>>,
    /// Dual-relation disclosure (#26/#27): release + optional display + NAF
    /// exclusions (subsumes v1 `releasability`).
    pub disclosure: Disclosure,
    /// Dissemination controls (#27): the product-of-chains controls lattice.
    pub controls: Controls,
    /// Carried handling obligations (#27): `NoEgress`/`OperatorOnly` only —
    /// enforced by the kernel hooks (hook-E egress screen / session gating), not
    /// this crate's read decision. `DisplayOnly` is DECISION-DERIVED (from the
    /// display relation), never carried; the carriable set is enforced by
    /// `validate_label`. Joined by the ⊑_obl LUB, preserved through derivation.
    pub obligations: BTreeSet<Obligation>,
    /// Raise-above-join floor (OCA compilation determination); `None` = no
    /// floor. A compilation at-or-below the level is semantically identical
    /// to `None` (both enforce the same effective rank).
    pub compilation_level: Option<crate::policy::Classification>,
    /// Optional purpose token that must match exactly at decision time.
    pub need_to_know: Option<String>,
}

/// Fail-closed precheck shared by `⊑` and `∨`: every category tag must be
/// registered, must not be `Permissive` (its polarity is ⊇/∩, not the ⊆/∪
/// this generic path applies), and must carry a non-empty value-set (the
/// degenerate state `decide()` denies must poison the lattice ops, never be
/// silently normalized away).
fn categories_comparable(label: &ResourceLabel, spif: &Spif) -> bool {
    label.categories.iter().all(|(tag, values)| {
        !values.is_empty()
            && matches!(
                spif.category_kind(tag),
                Some(
                    crate::policy::CategoryKind::Restrictive
                        | crate::policy::CategoryKind::RestrictivePredicate
                        | crate::policy::CategoryKind::Informative
                )
            )
    })
}

/// The ownership FRAME is structurally well-formed — delegates to the single
/// source of truth `Ownership::is_wellformed` (Owned=1 trigraph, Joint≥2
/// trigraphs, ConcealedForeign=trigraph custodian). A malformed frame (the
/// `Owned{""}` sentinel, a directly-constructed singleton/empty `Joint`, any
/// non-trigraph token) poisons `⊑`/`join` to `None` — the same boundary
/// `decide()` gate 4 and `validate_label` enforce, so they can never disagree.
fn ownership_wellformed(o: &Ownership) -> bool {
    o.is_wellformed()
}

/// The rank `decide()` actually enforces: `max(level, compilation-or-level)`.
/// `None` = any present rank unknown → indeterminate.
fn effective_rank(label: &ResourceLabel, spif: &Spif) -> Option<usize> {
    let base = spif.rank(&label.classification)?;
    match &label.compilation_level {
        None => Some(base),
        Some(c) => {
            let comp = spif.rank(c)?;
            Some(base.max(comp))
        }
    }
}

impl ResourceLabel {
    /// Restriction order: `self ⊑ other` iff `other` is at least as
    /// restrictive on EVERY dimension `decide()` reads:
    ///
    /// - level rank ≤ AND effective rank ≤ (effective = max(level,
    ///   compilation-or-level));
    /// - categories: for every `(tag, sv)` in `self.categories`,
    ///   `other.categories.get(tag).is_some_and(|ov| sv.is_subset(ov))`
    ///   (quantified over SELF's tags; a tag present only in self makes self
    ///   strictly more marked — absent-in-other = holds nothing = not ⊑);
    /// - `eligible(other) ⊆ eligible(self)` (fewer eligible = more
    ///   restrictive);
    /// - obligations: ⊑_obl refinement (self weaker-or-equal to other);
    /// - need-to-know: `(None, _)` ok; `(Some(a), Some(b))` ok iff `a == b`;
    ///   `(Some, None)` → NOT ⊑.
    ///
    /// `None` = indeterminate — fail closed on: unknown rank; policy or
    /// origin mismatch; malformed origin (not exactly 3 uppercase ASCII) in
    /// either label; or any category tag in EITHER label that is
    /// unregistered, `Permissive`, or empty-valued.
    pub fn at_most_as_restrictive_as(&self, other: &ResourceLabel, spif: &Spif) -> Option<bool> {
        if self.classification.policy != other.classification.policy
            // Identical ownership FRAME required (cross-ownership has no ⊑ —
            // a `derive` refusal, exactly as v1 required equal origins). This
            // guard MUST stay in lockstep with `ResourceLabel::join`, the other
            // consumer that gates the SAME frame condition through
            // `Ownership::same_frame`; both move together, so express the check
            // through the one predicate rather than a raw `!=` that could
            // silently drift from it. (`Disclosure::join` does not re-gate the
            // frame — it relies on the caller passing a single, already
            // frame-checked `base`.) The wellformedness check below covers both
            // labels since they are now proven equal.
            || !self.ownership.same_frame(&other.ownership)
            || !ownership_wellformed(&self.ownership)
            || !categories_comparable(self, spif)
            || !categories_comparable(other, spif)
        {
            return None;
        }
        let base = self.ownership.base_set();
        let (self_rank, other_rank) = (
            spif.rank(&self.classification)?,
            spif.rank(&other.classification)?,
        );
        let (self_eff, other_eff) = (effective_rank(self, spif)?, effective_rank(other, spif)?);
        let levels_ok = self_rank <= other_rank && self_eff <= other_eff;
        let categories_ok = self
            .categories
            .iter()
            .all(|(tag, sv)| other.categories.get(tag).is_some_and(|ov| sv.is_subset(ov)));
        // disclosure ⊑ (release + display eligibility + exclusions, decomposed)
        let disclosure_ok = self.disclosure.le(&other.disclosure, &base, spif);
        // controls ⊑ (product-of-chains: per-chain rank + non-chain ⊆)
        let controls_ok = self.controls.le(&other.controls);
        // obligations axis (#27): ⊑_obl refinement — self weaker-or-equal to
        // other (polarity of the retired `self.caveats ⊆ other.caveats`).
        let obligations_ok = obligations_refine(&self.obligations, &other.obligations);
        let ntk_ok = match (&self.need_to_know, &other.need_to_know) {
            (None, _) => true,
            (Some(a), Some(b)) => a == b,
            (Some(_), None) => false,
        };
        Some(levels_ok && categories_ok && disclosure_ok && controls_ok && obligations_ok && ntk_ok)
    }

    /// Lattice-join `∨` = least-upper-bound = the MORE-restrictive combine.
    ///
    /// PRECISION (per lattice-math review): this operation is PARTIAL, and its
    /// `None` has two mathematically distinct sources. (1) FRAME boundary:
    /// policy and ownership partition the label space into frames — same-policy
    /// and same-ownership are equivalence relations — so cross-policy /
    /// cross-ownership inputs are not elements of one lattice frame, and `∨`
    /// returns `None` as a DOMAIN-BOUNDARY refusal (mirroring v1's cross-origin
    /// refusal), total WITHIN a frame. (2) NO UPPER BOUND: NTK is NOT a frame
    /// axis (it is not transitive, so it cannot partition, and `⊑` carries no
    /// NTK guard — cross-NTK pairs are IN the order's domain and compare
    /// `Some(false)`). Cross-NTK `∨` returns `None` because a scalar NTK cannot
    /// hold two differing tokens at once, so the pair has no upper bound —
    /// `None` is the unique correct result (a partial join-semilattice). Neither
    /// `None` is a validity check, and neither threatens associativity, which is
    /// claimed WITHIN a frame (§5 law suite). VALIDITY refusals (exclusion
    /// pairs, §2.6 couplings) live in
    /// `validate_label`/`derive`, never here — a validity-`None` inside a
    /// binary `∨` is absorbing and WOULD break associativity. The per-axis
    /// operations (`Controls::join`, `Disclosure::join`, releasability `∩`) are
    /// unconditionally total — they never return `Option`.
    ///
    /// Combine rule: max rank; ∪ categories per-tag; ∩ releasability
    /// re-canonicalized via [`Releasability::from_eligible`]; ∪ obligations;
    /// compilation
    /// `(None, x) | (x, None) → x`, `(Some, Some)` → higher rank;
    /// need-to-know `(None, None) → None`, one `Some` → that `Some`, equal
    /// `Some`s → keep, DIFFERING `Some`s → `None` (fail closed — codex P1:
    /// keeping either token would let a subject holding it read derived
    /// content whose other source demanded the discarded token, and the
    /// discarded side would violate the upper-bound property `b ⊑ a∨b`; a
    /// scalar NTK cannot represent both requirements, so cross-NTK derivation
    /// is deferred exactly like cross-origin — set-valued NTK is the
    /// recorded follow-up).
    ///
    /// `None` (the frame-boundary refusals above) if policies differ,
    /// ownership frames differ (cross-ownership derivation deferred), ownership
    /// is malformed, a present NTK differs, any present rank is unknown, or any
    /// category tag in either label is unregistered, `Permissive`, or
    /// empty-valued (dropping an empty-valued tag would derive a Permit from a
    /// label `decide()` denies — the degenerate state must poison the join,
    /// never be normalized). All are DOMAIN/frame conditions, not validity
    /// checks over a valid same-frame pair.
    pub fn join(&self, other: &ResourceLabel, spif: &Spif) -> Option<ResourceLabel> {
        if self.classification.policy != other.classification.policy
            // identical ownership FRAME required — the ONLY ownership-frame
            // `None` (cross-ownership derivation deferred, as cross-origin was);
            // every OTHER v1 `None` path below is retained
            || !self.ownership.same_frame(&other.ownership)
            || !ownership_wellformed(&self.ownership)
            || !categories_comparable(self, spif)
            || !categories_comparable(other, spif)
        {
            return None;
        }
        let base = self.ownership.base_set();
        let (self_rank, other_rank) = (
            spif.rank(&self.classification)?,
            spif.rank(&other.classification)?,
        );
        let classification = if self_rank >= other_rank {
            self.classification.clone()
        } else {
            other.classification.clone()
        };
        // Per-tag ∪ over the union of key-sets. For invariant-honoring inputs
        // this can never produce an empty value-set (∪ of non-empties is
        // non-empty; a tag absent in both is never iterated), and
        // invariant-violating inputs never reach here (poisoned above).
        let mut categories = self.categories.clone();
        for (tag, values) in &other.categories {
            categories
                .entry(tag.clone())
                .and_modify(|v| v.extend(values.iter().cloned()))
                .or_insert_with(|| values.clone());
        }
        // disclosure ∨: release ∩, display ∩, exclusions ∪ (Disclosure::join)
        let disclosure = self.disclosure.join(&other.disclosure, &base, spif);
        // controls ∨: per-chain max + non-chain union (total, validity-agnostic)
        let controls = self.controls.join(&other.controls);
        // obligations ∨ = ⊑_obl LUB = set-union for the carried atoms (#27).
        let obligations: BTreeSet<Obligation> = self
            .obligations
            .union(&other.obligations)
            .cloned()
            .collect();
        let compilation_level = match (&self.compilation_level, &other.compilation_level) {
            (None, None) => None,
            (Some(c), None) | (None, Some(c)) => {
                spif.rank(c)?; // present-but-unknown poisons the join
                Some(c.clone())
            }
            (Some(a), Some(b)) => {
                let (ra, rb) = (spif.rank(a)?, spif.rank(b)?);
                Some(if ra >= rb { a.clone() } else { b.clone() })
            }
        };
        let need_to_know = match (&self.need_to_know, &other.need_to_know) {
            (None, None) => None,
            (Some(t), None) | (None, Some(t)) => Some(t.clone()),
            (Some(a), Some(b)) => {
                if a != b {
                    // codex P1: a scalar NTK cannot represent both
                    // requirements — discarding either widens access to the
                    // other source's material; fail closed like cross-origin
                    return None;
                }
                Some(a.clone())
            }
        };
        Some(ResourceLabel {
            classification,
            ownership: self.ownership.clone(),
            categories,
            disclosure,
            controls,
            obligations,
            compilation_level,
            need_to_know,
        })
    }
}

/// Every releasability token names a recognized WORLD-VIEW element: a trigraph
/// must be an ISO-3166 nation, a non-trigraph must be a registered coalition.
/// An unrecognized token → `Element` (#26: the engine has a complete world view
/// and refuses to decide on an unknown trigraph/tetragraph).
fn rel_tokens_recognized(rel: &Releasability) -> Result<(), LabelInvalidity> {
    if let Releasability::Grant(tokens) = rel {
        for t in tokens {
            let recognized = if is_trigraph(t) {
                registry::is_iso3166(t)
            } else {
                registry::expand_coalition(t).is_some()
            };
            if !recognized {
                return Err(LabelInvalidity::Element);
            }
        }
    }
    Ok(())
}

/// Ingest predicate — the FIRST enforcement locus of #26 (validate_label +
/// decide() gate-4 is the two-locus, defense-in-depth pair). Fail-closed to
/// `Err`. Enforces, for ANY ownership (single-origin `Owned` AND multi-origin
/// `Joint`, via `ownership.base_set()`):
///
/// - every release/display token is a recognized element (`Element`);
/// - every NAF exclusion token is a recognized nation (`Element`);
/// - no owner/co-owner is in the exclusion set (`Label`, spec §6);
/// - a NAF exclusion requires a `Grant` release — a restriction on
///   `Public`/`Empty`/`NoMarking` is invalid (`Label`, DoDM §e);
/// - `display ⊇ release` (`Label`).
///
/// (An EMPTY `exclusions` set is the "no NAF" state — absence, not a present
/// empty set: the `BTreeSet` representation cannot carry a present-but-empty
/// marking, so "non-empty when present" is a marking-layer invariant, not one
/// this adjudicator can observe.) The lattice `∨` never calls this — validity is
/// a `derive`-layer property (spec §2.3 total-∨/partial-derive split).
pub fn validate_label(label: &ResourceLabel, spif: &Spif) -> Result<(), LabelInvalidity> {
    let d = &label.disclosure;
    // (0a) the ownership FRAME is structurally well-formed — Owned=1 trigraph,
    //      Joint≥2 trigraphs (its documented invariant), ConcealedForeign=trigraph
    //      custodian. A directly-constructed singleton/empty `Joint` or the
    //      `Owned{""}` sentinel is a MALFORMED label. This is the SAME boundary
    //      `decide()` gate 4 and the lattice `⊑`/`∨` frame guard enforce, so
    //      `derive = validate_label ∘ ∨` can never emit a malformed frame.
    if !label.ownership.is_wellformed() {
        return Err(LabelInvalidity::Label);
    }
    // (0b) every owner/custodian is a recognized nation — the engine has a COMPLETE
    //     world view and refuses to adjudicate on an unrecognized owner trigraph.
    //     (`Owned("ZZZ")` with NoMarking would otherwise resolve to eligible
    //     {ZZZ} and permit a "ZZZ" nationality — a made-up nation.)
    for owner in label.ownership.base_set() {
        if !registry::is_iso3166(&owner) {
            return Err(LabelInvalidity::Element);
        }
    }
    // (0c) carried obligations (#27) may be ONLY the currently-carriable atoms.
    //      `DisplayOnly` is DECISION-DERIVED (never carried — decide() emits it
    //      from the display relation); `OriginatorControlled` (#48) and
    //      `OwnerConsent`/`ReaderRecord` (Stage-5) are not yet carriable. Enforces
    //      the "decision-derived only" invariant at ingest AND (two-locus) at gate-4.
    for ob in &label.obligations {
        if !matches!(ob, Obligation::NoEgress | Obligation::OperatorOnly) {
            return Err(LabelInvalidity::Label);
        }
    }
    // (0d) REL ∅ / display ∅ is not an authorable marking (#51). `Empty` excludes
    //      the origin (absolute denial) — not a valid policy state; it is retained
    //      ONLY as a fail-closed deny-all sentinel (`from_eligible` precondition-
    //      violation), never authored. Rejected at both loci (here + gate-4 re-run).
    if d.release == Releasability::Empty || d.display == Some(Releasability::Empty) {
        return Err(LabelInvalidity::Label);
    }
    // (0e) ORCON validity (#48). ORCON/ORCON-USGOV are incompatible with RELIDO
    //      (IC Register :7225/:7388) and are classified-only (Register :7222; DoDM
    //      :5323 — TS/S/C). `is_classified` fails closed (None → reject) on an
    //      undeclared floor / unknown rank. Enforced at both loci (here + gate-4).
    let cs = label.controls.as_set();
    let has_orcon = cs.contains(&ControlMarking::Orcon) || cs.contains(&ControlMarking::OrconUsGov);
    if has_orcon {
        if cs.contains(&ControlMarking::Relido) {
            return Err(LabelInvalidity::Label);
        }
        if spif.is_classified(&label.classification) != Some(true) {
            return Err(LabelInvalidity::Label);
        }
    }
    // (1) release + display tokens are recognized world-view elements.
    rel_tokens_recognized(&d.release)?;
    if let Some(disp) = &d.display {
        rel_tokens_recognized(disp)?;
    }
    // (2) every excluded token is a recognized nation (exclusions are trigraphs).
    for x in &d.exclusions {
        if !registry::is_iso3166(x) {
            return Err(LabelInvalidity::Element);
        }
    }
    // (3)+(4): NAF-specific structural checks (only when a NAF is present).
    if !d.exclusions.is_empty() {
        // (3) owner/co-owner is NEVER excluded (spec §6; all ownership).
        let owners = label.ownership.base_set();
        if !d.exclusions.is_disjoint(&owners) {
            return Err(LabelInvalidity::Label);
        }
        // (4) a NAF requires a NAMED release — an exclusion is only meaningful
        //     against a positive `Grant` to except a member FROM. A restriction
        //     on `Public` (REL ALL — everyone is authorized), `Empty` (REL NONE)
        //     or `NoMarking` (REL {origin} only) is structurally contradictory
        //     (DoDM §e: a dissemination restriction is for a named recipient set,
        //     not an all/none/origin marking).
        //
        //     This is deliberately NOT gated on classification LEVEL (SETTLED per
        //     policy — see the ADR-0008 Stage-2 "Policy basis" note). A release-
        //     side NAF subtracts from a `REL TO` grant, and REL TO applies to CUI
        //     as well as classified (DoDI 5200.48; 32 CFR 2002.4(dd) LDCs), so a
        //     level gate would wrongly reject valid CUI NAF labels. The classified-
        //     only level restriction is DISPLAY ONLY's (DoDM V2 §e, TS/S/C) and
        //     lands with #27 — where it needs explicit SPIF classified-level
        //     support, NOT a rank heuristic.
        if !matches!(d.release, Releasability::Grant(_)) {
            return Err(LabelInvalidity::Label);
        }
    }
    // (5) the dual-relation invariant: display ⊇ release.
    let base = label.ownership.base_set();
    if !d.display_covers_release(&base, spif) {
        return Err(LabelInvalidity::Label);
    }
    // (6) DISPLAY ONLY is classified-only (#27, DoDM V2 §e). A non-empty
    //     display-only band (display ⊋ release) requires a CLASSIFIED level.
    //     Band non-empty ⟺ release ⊆ display (checked in (5)) AND display ⊄ release.
    //     `is_classified` fails closed (None) on unknown/undeclared floor → deny.
    let rel_e = d.eligible_release(&base, spif);
    let disp_e = d.eligible_display(&base, spif);
    let band_nonempty = !disp_e.is_subset_of(&rel_e);
    if band_nonempty && spif.is_classified(&label.classification) != Some(true) {
        return Err(LabelInvalidity::Label);
    }
    Ok(())
}

/// The OPERATIONAL derivation step: `derive = validate_label ∘ ∨`. Returns the
/// derived, validated label, or `None` fail-closed. Every fail-closed refusal
/// is SURFACED here, but they originate in two distinct places (precision per
/// lattice-math review): the FRAME-boundary `None` (cross-policy / ownership /
/// NTK, malformed/unregistered inputs) originates in `join` as a domain-of-
/// definition refusal and is merely propagated through `derive`; the VALIDITY
/// `None` (Stage-1 `display ⊇ release`; Stages 2/4 exclusion pairs + §2.6
/// couplings) originates in `validate_label`. `decide()` consumes only `derive`
/// output.
pub fn derive(a: &ResourceLabel, b: &ResourceLabel, spif: &Spif) -> Option<ResourceLabel> {
    let joined = a.join(b, spif)?;
    validate_label(&joined, spif).ok()?;
    Some(joined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Spif;

    fn set(xs: &[&str]) -> BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
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

    // Shared #26 test helpers (D7). `sub`/`purpose` are decide-path helpers used
    // only by the integration NAF vectors (`tests/common/mod.rs`), so they are
    // NOT declared here (they would be dead code in the label.rs unit module).
    fn one(t: &str) -> BTreeSet<String> {
        [t.to_string()].into_iter().collect()
    }
    // US-policy SPIF, levels U<S<TS, NO tetragraph (coalitions are global, D1).
    fn us_spif() -> Spif {
        Spif::builder("US").levels(&["U", "S", "TS"]).build()
    }
    // Owned{origin}, classification U//US, everything else empty — gates 1-3/5
    // pass under us_spif() so gate 4 (releasability) is the deciding gate.
    fn mk_owned(origin: &str) -> ResourceLabel {
        ResourceLabel {
            classification: crate::policy::Classification {
                policy: crate::policy::PolicyId("US".into()),
                name: "U".into(),
            },
            ownership: Ownership::Owned {
                owner: origin.into(),
            },
            categories: std::collections::BTreeMap::new(),
            disclosure: Disclosure {
                release: Releasability::NoMarking,
                display: None,
                exclusions: BTreeSet::new(),
            },
            controls: Controls::empty(),
            obligations: BTreeSet::new(),
            compilation_level: None,
            need_to_know: None,
        }
    }
    // Same as mk_owned but Joint ownership (struct-update over mk_owned).
    fn joint_label(owners: &[&str]) -> ResourceLabel {
        ResourceLabel {
            ownership: Ownership::Joint {
                owners: set(owners),
            },
            ..mk_owned("USA")
        }
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
    fn disclosure_dual_relation_join_and_exclusions() {
        let spif = Spif::builder("US").levels(&["U", "S", "TS"]).build();
        let base = set(&["USA"]);

        // display None → display tracks release
        let d = Disclosure {
            release: Releasability::Grant(set(&["AUS"])),
            display: None,
            exclusions: BTreeSet::new(),
        };
        assert_eq!(
            d.eligible_release(&base, &spif),
            d.eligible_display(&base, &spif)
        );
        assert!(d.display_covers_release(&base, &spif));

        // explicit display ⊇ release holds; display ⊂ release violates the invariant
        let wide = Disclosure {
            release: Releasability::Grant(set(&["AUS"])),
            display: Some(Releasability::Grant(set(&["AUS", "KOR"]))),
            exclusions: BTreeSet::new(),
        };
        assert!(wide.display_covers_release(&base, &spif));
        let bad = Disclosure {
            release: Releasability::Grant(set(&["AUS", "KOR"])),
            display: Some(Releasability::Grant(set(&["AUS"]))),
            exclusions: BTreeSet::new(),
        };
        assert!(!bad.display_covers_release(&base, &spif));

        // join: release ∩ (resolved AUS,KOR ∩ AUS,NZL = AUS). The NAF exclusions
        // are baked into each operand's resolved release BEFORE the ∩ and are no
        // longer a carried axis — the joined disclosure has EMPTY exclusions (#26).
        let a = Disclosure {
            release: Releasability::Grant(set(&["AUS", "KOR"])),
            display: None,
            exclusions: set(&["DEU"]),
        };
        let b = Disclosure {
            release: Releasability::Grant(set(&["AUS", "NZL"])),
            display: None,
            exclusions: set(&["FRA"]),
        };
        let j = a.join(&b, &base, &spif);
        assert_eq!(j.release, Releasability::Grant(set(&["AUS"])));
        assert_eq!(j.exclusions, BTreeSet::new()); // consumed into the resolved release
        assert!(a.le(&j, &base, &spif)); // a ⊑ a∨b

        // #40: a MULTI-owner base (≥2 co-owners) now RESOLVES — every co-owner is
        // unioned into the resolved release (was deny-all under the |base|≠1 scalar).
        let multi = d.eligible_release(&set(&["USA", "KOR"]), &spif);
        assert!(multi.permits("USA") && multi.permits("KOR")); // both co-owners eligible
        assert!(multi.permits("AUS")); // + the release grant
                                       // only an EMPTY base fails closed to deny-all.
        let deny_all = EligibleNations::Set {
            nations: BTreeSet::new(),
        };
        assert_eq!(d.eligible_release(&BTreeSet::new(), &spif), deny_all);
    }

    #[test]
    fn equal_resolved_release_sets_are_le_both_ways() {
        // Task 7: the retained-exclusions lattice axis is removed. Two disclosures
        // with EQUAL resolved release sets are ⊑ both ways regardless of their raw
        // exclusion markings (canonical uniqueness over the resolved set).
        let spif = us_spif();
        let base = one("USA");
        // P: REL {AUS,CAN}, NAF AUS → resolved release {USA,CAN} (AUS subtracted)
        let p = Disclosure {
            release: Releasability::Grant(set(&["AUS", "CAN"])),
            display: None,
            exclusions: set(&["AUS"]),
        };
        // Q: REL {CAN}, no NAF → resolved release {USA,CAN}
        let q = Disclosure {
            release: Releasability::Grant(set(&["CAN"])),
            display: None,
            exclusions: BTreeSet::new(),
        };
        assert_eq!(
            p.eligible_release(&base, &spif),
            q.eligible_release(&base, &spif)
        );
        assert!(p.le(&q, &base, &spif));
        assert!(q.le(&p, &base, &spif));
    }

    #[test]
    fn naf_subtracts_an_expanded_member() {
        // Task 8: a NAF exclusion is subtracted from the RESOLVED (post-expansion)
        // release set — REL UNCK NAF ZAF removes ZAF though it is a UNCK member.
        let spif = us_spif();
        let base = one("USA");
        let d = Disclosure {
            release: Releasability::Grant(set(&["UNCK"])),
            display: None,
            exclusions: set(&["ZAF"]),
        };
        let e = d.eligible_release(&base, &spif);
        assert!(e.permits("AUS")); // UNCK member, not excluded
        assert!(!e.permits("ZAF")); // UNCK member, excluded → out
    }

    #[test]
    fn none_display_tracks_subtracted_release() {
        // display(None) tracks the SUBTRACTED release (ZAF out of both).
        let spif = us_spif();
        let base = one("USA");
        let d = Disclosure {
            release: Releasability::Grant(set(&["UNCK"])),
            display: None,
            exclusions: set(&["ZAF"]),
        };
        assert_eq!(
            d.eligible_display(&base, &spif),
            d.eligible_release(&base, &spif)
        );
        assert!(!d.eligible_display(&base, &spif).permits("ZAF"));
    }

    #[test]
    fn explicit_display_is_not_subtracted() {
        // an EXPLICIT display grant is untouched by release-side NAF (display-side
        // exclusions are #27, not #26): ZAF stays display-eligible.
        let spif = us_spif();
        let base = one("USA");
        let d = Disclosure {
            release: Releasability::Grant(set(&["USA"])),
            display: Some(Releasability::Grant(set(&["UNCK"]))),
            exclusions: set(&["ZAF"]),
        };
        assert!(d.eligible_display(&base, &spif).permits("ZAF"));
    }

    #[test]
    fn carried_obligations_allow_list() {
        let spif = us_spif();
        let mut l = mk_owned("USA");
        l.obligations = [Obligation::NoEgress, Obligation::OperatorOnly]
            .into_iter()
            .collect();
        assert_eq!(validate_label(&l, &spif), Ok(())); // both carriable
        for bad in [
            Obligation::DisplayOnly,
            Obligation::OwnerConsent,
            Obligation::ReaderRecord,
            Obligation::OriginatorControlled { scope: None },
        ] {
            let mut b = mk_owned("USA");
            b.obligations = [bad.clone()].into_iter().collect();
            assert!(
                matches!(validate_label(&b, &spif), Err(LabelInvalidity::Label)),
                "{bad:?} must not be carriable"
            );
        }
    }

    #[test]
    fn display_only_band_requires_classified() {
        let spif = Spif::builder("US")
            .levels(&["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"])
            .classified_floor("CONFIDENTIAL")
            .build();
        let mk = |lvl: &str| ResourceLabel {
            classification: crate::policy::Classification {
                policy: crate::policy::PolicyId("US".into()),
                name: lvl.into(),
            },
            ownership: Ownership::Owned {
                owner: "USA".into(),
            },
            categories: std::collections::BTreeMap::new(),
            disclosure: Disclosure {
                release: Releasability::NoMarking,                  // origin-only
                display: Some(Releasability::Grant(set(&["AUS"]))), // band = {AUS}
                exclusions: BTreeSet::new(),
            },
            controls: Controls::empty(),
            obligations: BTreeSet::new(),
            compilation_level: None,
            need_to_know: None,
        };
        assert!(matches!(
            validate_label(&mk("UNCLASSIFIED"), &spif),
            Err(LabelInvalidity::Label)
        )); // band on unclassified → invalid
        assert_eq!(validate_label(&mk("SECRET"), &spif), Ok(())); // band on classified → valid
                                                                  // no band (display None) on unclassified stays valid (rule fires only on a band)
        let mut nb = mk("UNCLASSIFIED");
        nb.disclosure.display = None;
        assert_eq!(validate_label(&nb, &spif), Ok(()));
    }

    #[test]
    fn orcon_relido_and_orcon_unclassified_are_invalid() {
        use crate::controls::{ControlMarking, Controls};
        let spif = Spif::builder("US")
            .levels(&["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"])
            .classified_floor("CONFIDENTIAL")
            .build();
        let mk = |lvl: &str, ctrls: &[ControlMarking]| {
            let mut l = mk_owned("USA");
            l.classification = crate::policy::Classification {
                policy: crate::policy::PolicyId("US".into()),
                name: lvl.into(),
            };
            l.controls = Controls::from_set(ctrls.iter().copied().collect());
            l
        };
        use ControlMarking::*;
        // ORCON × RELIDO — both arms
        assert!(matches!(
            validate_label(&mk("SECRET", &[Orcon, Relido]), &spif),
            Err(LabelInvalidity::Label)
        ));
        assert!(matches!(
            validate_label(&mk("SECRET", &[OrconUsGov, Relido]), &spif),
            Err(LabelInvalidity::Label)
        ));
        // ORCON on unclassified — both arms
        assert!(matches!(
            validate_label(&mk("UNCLASSIFIED", &[Orcon]), &spif),
            Err(LabelInvalidity::Label)
        ));
        assert!(matches!(
            validate_label(&mk("UNCLASSIFIED", &[OrconUsGov]), &spif),
            Err(LabelInvalidity::Label)
        ));
        // valid: ORCON on classified, no RELIDO
        assert_eq!(validate_label(&mk("SECRET", &[Orcon]), &spif), Ok(()));
        assert_eq!(validate_label(&mk("SECRET", &[OrconUsGov]), &spif), Ok(()));
        // RELIDO alone (no ORCON) is fine
        assert_eq!(validate_label(&mk("SECRET", &[Relido]), &spif), Ok(()));
    }

    #[test]
    fn empty_release_or_display_is_not_authorable() {
        // #51: REL ∅ (origin-excluding) is not a valid marking — Empty is a
        // fail-closed sentinel only, never authored. Rejected at ingest (both fields).
        let spif = us_spif();
        let mut r = mk_owned("USA");
        r.disclosure.release = Releasability::Empty;
        assert!(matches!(
            validate_label(&r, &spif),
            Err(LabelInvalidity::Label)
        ));
        let mut d = mk_owned("USA");
        d.disclosure.display = Some(Releasability::Empty);
        assert!(matches!(
            validate_label(&d, &spif),
            Err(LabelInvalidity::Label)
        ));
        // a normal NoMarking label still validates (guard is Empty-specific)
        assert_eq!(validate_label(&mk_owned("USA"), &spif), Ok(()));
    }

    #[test]
    fn owner_in_x_is_invalid_single_origin() {
        // Task 9 (spec §6): the owner is never excluded.
        let mut l = mk_owned("USA");
        l.disclosure.release = Releasability::Grant(set(&["AUS"]));
        l.disclosure.exclusions = set(&["USA"]);
        assert!(matches!(
            validate_label(&l, &us_spif()),
            Err(LabelInvalidity::Label)
        ));
    }

    #[test]
    fn owner_in_x_is_invalid_joint() {
        // MANDATORY (spec §6): asserted on the ingest predicate for MULTI-origin
        // Joint ownership (decide() short-circuits Joint to Indeterminate, so this
        // owner-in-X guard must live in validate_label).
        let mut l = joint_label(&["USA", "KOR"]);
        l.disclosure.release = Releasability::Grant(set(&["AUS"]));
        l.disclosure.exclusions = set(&["KOR"]);
        assert!(matches!(
            validate_label(&l, &us_spif()),
            Err(LabelInvalidity::Label)
        ));
    }

    #[test]
    fn public_with_naf_is_invalid() {
        // DoDM §e: a dissemination restriction is for a classified, NAMED release,
        // not a Public/all marking.
        let mut l = mk_owned("USA");
        l.disclosure.release = Releasability::Public;
        l.disclosure.exclusions = set(&["ZAF"]);
        assert!(matches!(
            validate_label(&l, &us_spif()),
            Err(LabelInvalidity::Label)
        ));
    }

    #[test]
    fn unknown_release_token_is_invalid_element() {
        // a release token outside the world view (neither ISO-3166 nor a
        // registered coalition) → Element.
        let mut l = mk_owned("USA");
        l.disclosure.release = Releasability::Grant(set(&["ZZZZ"]));
        assert!(matches!(
            validate_label(&l, &us_spif()),
            Err(LabelInvalidity::Element)
        ));
    }

    #[test]
    fn singleton_joint_is_malformed_at_validate_and_derive() {
        // #40 (Hobi P1): a singleton Joint violates the len≥2 invariant. The frame
        // boundary must NOT split-brain — validate_label rejects it (matching gate 4),
        // and the lattice poisons derive to None.
        let l = joint_label(&["USA"]); // singleton Joint (malformed)
        assert!(matches!(
            validate_label(&l, &us_spif()),
            Err(LabelInvalidity::Label)
        ));
        assert!(derive(&l, &l, &us_spif()).is_none());
    }

    #[test]
    fn unknown_owner_trigraph_is_invalid_element() {
        // codex P1: a syntactically-valid but non-ISO owner (ZZZ) must not
        // adjudicate — the engine has a complete world view. Without this,
        // Owned("ZZZ")+NoMarking resolves to eligible {ZZZ} and would permit a
        // "ZZZ" nationality.
        let l = mk_owned("ZZZ"); // not an ISO-3166 nation
        assert!(matches!(
            validate_label(&l, &us_spif()),
            Err(LabelInvalidity::Element)
        ));
    }

    #[test]
    fn naf_is_not_gated_on_classification_level() {
        // codex-r2: a NAF is valid regardless of classification level (CUI carries
        // dissemination controls too). The structural invariant is the NAMED
        // release, not the level — the same NAF validates at "U" and "S".
        let mut l = mk_owned("USA");
        l.disclosure.release = Releasability::Grant(set(&["UNCK"]));
        l.disclosure.exclusions = set(&["ZAF"]);
        assert_eq!(validate_label(&l, &us_spif()), Ok(())); // "U" (unclassified)
        l.classification.name = "S".into();
        assert_eq!(validate_label(&l, &us_spif()), Ok(())); // "S" (classified)
    }

    #[test]
    fn well_formed_naf_label_validates() {
        // a well-formed NAF label (Grant release, owner not excluded, recognized
        // tokens) passes ingest validation.
        let mut l = mk_owned("USA");
        l.disclosure.release = Releasability::Grant(set(&["UNCK"]));
        l.disclosure.exclusions = set(&["ZAF"]);
        assert_eq!(validate_label(&l, &us_spif()), Ok(()));
    }

    #[test]
    fn derive_and_validate_label_stage1() {
        use crate::policy::{Classification, PolicyId};
        use std::collections::BTreeMap;
        let spif = Spif::builder("US").levels(&["U", "S", "TS"]).build();
        let mk = |owner: &str, controls: Controls, disclosure: Disclosure| ResourceLabel {
            classification: Classification {
                policy: PolicyId("US".into()),
                name: "S".into(),
            },
            ownership: Ownership::Owned {
                owner: owner.into(),
            },
            categories: BTreeMap::new(),
            disclosure,
            controls,
            obligations: BTreeSet::new(),
            compilation_level: None,
            need_to_know: None,
        };
        let plain = |rel: Releasability| Disclosure {
            release: rel,
            display: None,
            exclusions: BTreeSet::new(),
        };
        use crate::controls::ControlMarking::*;

        // (a) a within-frame pair whose join yields a would-be-rejectable
        // control combo ({Relido,Displayed}) STILL derives to Some in Stage 1 —
        // exclusion rejection is Stage 2. TODO(stage2): flip this to None.
        let a = mk(
            "USA",
            Controls::from_set([Relido].into_iter().collect()),
            plain(Releasability::NoMarking),
        );
        let b = mk(
            "USA",
            Controls::from_set([Displayed].into_iter().collect()),
            plain(Releasability::NoMarking),
        );
        let d = derive(&a, &b, &spif).expect("within-frame derive is Some in Stage 1");
        assert_eq!(
            d.controls.as_set(),
            &[Relido, Displayed].into_iter().collect()
        );

        // (b) cross-ownership pair → derive None (the frame boundary, via join)
        let foreign = mk("DEU", Controls::empty(), plain(Releasability::NoMarking));
        assert!(derive(&a, &foreign, &spif).is_none());

        // (c) a directly-constructed display ⊂ release label → validate_label Err
        let malformed = mk(
            "USA",
            Controls::empty(),
            Disclosure {
                release: Releasability::Grant(set(&["AUS", "KOR"])),
                display: Some(Releasability::Grant(set(&["AUS"]))),
                exclusions: BTreeSet::new(),
            },
        );
        assert!(matches!(
            validate_label(&malformed, &spif),
            Err(LabelInvalidity::Label)
        ));
    }

    #[test]
    fn empty_owner_sentinel_contained_in_lattice_ops() {
        use crate::policy::{Classification, PolicyId};
        use std::collections::BTreeMap;
        let spif = Spif::builder("US").levels(&["U", "S", "TS"]).build();
        let mk = |owner: &str| ResourceLabel {
            classification: Classification {
                policy: PolicyId("US".into()),
                name: "S".into(),
            },
            ownership: Ownership::Owned {
                owner: owner.into(),
            },
            categories: BTreeMap::new(),
            disclosure: Disclosure {
                release: Releasability::NoMarking,
                display: None,
                exclusions: BTreeSet::new(),
            },
            controls: Controls::empty(),
            obligations: BTreeSet::new(),
            compilation_level: None,
            need_to_know: None,
        };
        let empty = mk("");
        let usa = mk("USA");
        // cross-frame (different ownership) → None both directions (never widens)
        assert_eq!(empty.at_most_as_restrictive_as(&usa, &spif), None);
        assert_eq!(usa.at_most_as_restrictive_as(&empty, &spif), None);
        assert!(empty.join(&usa, &spif).is_none());
        // even self-frame Owned{""} is malformed → ⊑/join poisoned to None
        assert_eq!(empty.at_most_as_restrictive_as(&empty, &spif), None);
        assert!(empty.join(&empty, &spif).is_none());
    }

    use crate::policy::{CategoryKind, Classification, PolicyId};
    use std::collections::BTreeMap;

    #[test]
    fn join_takes_max_level_union_categories_intersection_releasability() {
        // "SCI" MUST be registered — join fails closed (None) on unregistered tags
        let spif = Spif::builder("US")
            .levels(&["UNCLASSIFIED", "SECRET", "TOP_SECRET"])
            .category("SCI", CategoryKind::Restrictive)
            .build();
        let mk = |lvl: &str, rel: Releasability, sci: &[&str]| ResourceLabel {
            classification: Classification {
                policy: PolicyId("US".into()),
                name: lvl.into(),
            },
            ownership: Ownership::Owned {
                owner: "USA".into(),
            },
            categories: if sci.is_empty() {
                BTreeMap::new()
            } else {
                [("SCI".to_string(), set(sci))].into_iter().collect()
            },
            disclosure: Disclosure {
                release: rel,
                display: None,
                exclusions: BTreeSet::new(),
            },
            controls: Controls::empty(),
            obligations: BTreeSet::new(),
            compilation_level: None,
            need_to_know: None,
        };
        let a = mk("SECRET", Releasability::Grant(set(&["AUS"])), &["SI"]);
        let b = mk("TOP_SECRET", Releasability::Grant(set(&["KOR"])), &["TK"]);
        let j = a.join(&b, &spif).unwrap();
        assert_eq!(j.classification.name, "TOP_SECRET"); // max level
        assert_eq!(j.categories["SCI"], set(&["SI", "TK"])); // ∪ per-tag
        assert!(matches!(j.disclosure.release, Releasability::NoMarking)); // ∩ → {USA} → canonical NoMarking
        let e = j
            .disclosure
            .eligible_release(&j.ownership.base_set(), &spif);
        assert!(e.permits("USA") && !e.permits("AUS") && !e.permits("KOR"));
    }

    #[test]
    fn join_carries_obligations_by_union_and_max_compilation() {
        let spif = Spif::builder("US")
            .levels(&["UNCLASSIFIED", "SECRET", "TOP_SECRET"])
            .build();
        let base = |obs: &[Obligation], comp: Option<&str>| ResourceLabel {
            classification: Classification {
                policy: PolicyId("US".into()),
                name: "SECRET".into(),
            },
            ownership: Ownership::Owned {
                owner: "USA".into(),
            },
            categories: BTreeMap::new(),
            disclosure: Disclosure {
                release: Releasability::Public,
                display: None,
                exclusions: BTreeSet::new(),
            },
            controls: Controls::empty(),
            obligations: obs.iter().cloned().collect(),
            compilation_level: comp.map(|n| Classification {
                policy: PolicyId("US".into()),
                name: n.into(),
            }),
            need_to_know: None,
        };
        let a = base(&[Obligation::NoEgress], Some("SECRET"));
        let b = base(&[Obligation::OperatorOnly], Some("TOP_SECRET"));
        let j = a.join(&b, &spif).unwrap();
        assert!(
            j.obligations.contains(&Obligation::NoEgress)
                && j.obligations.contains(&Obligation::OperatorOnly)
        ); // ∪ carried
        assert_eq!(j.compilation_level.unwrap().name, "TOP_SECRET"); // max floor
    }

    #[test]
    fn join_preserves_lone_compilation_floor() {
        // (Some, None) keeps the Some — the OCA floor must survive derivation
        let spif = Spif::builder("US")
            .levels(&["UNCLASSIFIED", "SECRET", "TOP_SECRET"])
            .build();
        let mk = |comp: Option<&str>| ResourceLabel {
            classification: Classification {
                policy: PolicyId("US".into()),
                name: "SECRET".into(),
            },
            ownership: Ownership::Owned {
                owner: "USA".into(),
            },
            categories: BTreeMap::new(),
            disclosure: Disclosure {
                release: Releasability::NoMarking,
                display: None,
                exclusions: BTreeSet::new(),
            },
            controls: Controls::empty(),
            obligations: BTreeSet::new(),
            compilation_level: comp.map(|n| Classification {
                policy: PolicyId("US".into()),
                name: n.into(),
            }),
            need_to_know: None,
        };
        let a = mk(Some("TOP_SECRET"));
        let b = mk(None);
        assert_eq!(
            a.join(&b, &spif).unwrap().compilation_level.unwrap().name,
            "TOP_SECRET"
        );
        assert_eq!(
            b.join(&a, &spif).unwrap().compilation_level.unwrap().name,
            "TOP_SECRET"
        ); // symmetric
    }

    #[test]
    fn join_and_order_handle_need_to_know() {
        let spif = Spif::builder("US")
            .levels(&["UNCLASSIFIED", "SECRET"])
            .build();
        let mk = |ntk: Option<&str>| ResourceLabel {
            classification: Classification {
                policy: PolicyId("US".into()),
                name: "SECRET".into(),
            },
            ownership: Ownership::Owned {
                owner: "USA".into(),
            },
            categories: BTreeMap::new(),
            disclosure: Disclosure {
                release: Releasability::NoMarking,
                display: None,
                exclusions: BTreeSet::new(),
            },
            controls: Controls::empty(),
            obligations: BTreeSet::new(),
            compilation_level: None,
            need_to_know: ntk.map(|s| s.to_string()),
        };
        let none = mk(None);
        let oplan = mk(Some("OPLAN"));
        assert_eq!(
            none.join(&oplan, &spif).unwrap().need_to_know.as_deref(),
            Some("OPLAN")
        ); // Some wins
        assert_eq!(
            oplan.join(&none, &spif).unwrap().need_to_know.as_deref(),
            Some("OPLAN")
        ); // symmetric
        assert_eq!(none.at_most_as_restrictive_as(&oplan, &spif), Some(true)); // None ⊑ Some (NTK restricts)
        assert_eq!(oplan.at_most_as_restrictive_as(&none, &spif), Some(false)); // Some ⋢ None
                                                                                // codex P1: DIFFERING tokens fail closed — a scalar NTK cannot
                                                                                // represent both requirements, and keeping either would widen access
                                                                                // to the other source's material (and break b ⊑ a∨b)
        let conop = mk(Some("CONOP"));
        assert!(oplan.join(&conop, &spif).is_none());
        assert!(conop.join(&oplan, &spif).is_none()); // symmetric
    }

    #[test]
    fn join_refuses_cross_policy_and_cross_origin() {
        let spif = Spif::builder("US")
            .levels(&["UNCLASSIFIED", "SECRET"])
            .build();
        let us = ResourceLabel {
            classification: Classification {
                policy: PolicyId("US".into()),
                name: "SECRET".into(),
            },
            ownership: Ownership::Owned {
                owner: "USA".into(),
            },
            categories: BTreeMap::new(),
            disclosure: Disclosure {
                release: Releasability::NoMarking,
                display: None,
                exclusions: BTreeSet::new(),
            },
            controls: Controls::empty(),
            obligations: BTreeSet::new(),
            compilation_level: None,
            need_to_know: None,
        };
        let mut aus_origin = us.clone();
        aus_origin.ownership = Ownership::Owned {
            owner: "AUS".into(),
        };
        assert!(us.join(&aus_origin, &spif).is_none()); // cross-origin deferred → None, fail closed
                                                        // ⊑ poisons on origin mismatch ALONE (mutation-gate: this single
                                                        // assertion kills every ||→&& mutant in the poison disjunction —
                                                        // under any such mutant this case escapes the poison and computes
                                                        // Some(false) instead of None)
        assert_eq!(us.at_most_as_restrictive_as(&aus_origin, &spif), None);
        let mut aus_policy = us.clone();
        aus_policy.classification.policy = PolicyId("AUS".into());
        assert!(us.join(&aus_policy, &spif).is_none()); // cross-policy → None
    }

    #[test]
    fn order_and_join_fail_closed_on_permissive_and_unknown_tags() {
        // ⊑ and ∨ must be incomparable/undefined on the same dimensions decide() denies
        let spif = Spif::builder("US")
            .levels(&["UNCLASSIFIED", "SECRET"])
            .category("EYES", CategoryKind::Permissive)
            // MUST be registered — so the empty-value-set assertions below can
            // ONLY pass via the empty clause, not the unregistered clause
            .category("SCI_LIKE_TAG", CategoryKind::Restrictive)
            .build();
        let mk = |tag: Option<&str>| ResourceLabel {
            classification: Classification {
                policy: PolicyId("US".into()),
                name: "SECRET".into(),
            },
            ownership: Ownership::Owned {
                owner: "USA".into(),
            },
            categories: tag
                .map(|t| [(t.to_string(), set(&["USA"]))].into_iter().collect())
                .unwrap_or_default(),
            disclosure: Disclosure {
                release: Releasability::NoMarking,
                display: None,
                exclusions: BTreeSet::new(),
            },
            controls: Controls::empty(),
            obligations: BTreeSet::new(),
            compilation_level: None,
            need_to_know: None,
        };
        let plain = mk(None);
        let permissive = mk(Some("EYES")); // registered Permissive
        let unknown = mk(Some("MYSTERY")); // unregistered
        assert!(plain.join(&permissive, &spif).is_none());
        assert!(plain.join(&unknown, &spif).is_none());
        assert_eq!(plain.at_most_as_restrictive_as(&permissive, &spif), None);
        assert_eq!(unknown.at_most_as_restrictive_as(&plain, &spif), None);
        let mut bad_origin = mk(None);
        bad_origin.ownership = Ownership::Owned { owner: "".into() }; // malformed origin
        assert!(bad_origin.join(&bad_origin.clone(), &spif).is_none()); // equal-but-malformed → None
        assert_eq!(
            bad_origin.at_most_as_restrictive_as(&bad_origin.clone(), &spif),
            None
        );
        let mut empty_vals = mk(None); // empty value-set tag
        empty_vals
            .categories
            .insert("SCI_LIKE_TAG".into(), BTreeSet::new()); // registered Restrictive above
        assert!(plain.join(&empty_vals, &spif).is_none()); // never dropped/normalized → None
        assert_eq!(empty_vals.at_most_as_restrictive_as(&plain, &spif), None); // degenerate as self
                                                                               // BOTH directions — a self-quantified-only check would return Some(true)
                                                                               // here (plain has no tags), i.e. "a label decide() permits ⊑ a label
                                                                               // decide() denies" — the exact widening the poison rule forbids
        assert_eq!(plain.at_most_as_restrictive_as(&empty_vals, &spif), None);
    }

    #[test]
    fn nomarking_is_origin_only() {
        let spif = Spif::builder("US").build();
        let e = Releasability::NoMarking.eligible(&one("USA"), &spif);
        assert!(e.permits("USA")); // origin permits
        assert!(!e.permits("AUS")); // foreign denies (NOFORN-equiv)
    }

    #[test]
    fn grant_includes_origin_and_listed() {
        let spif = Spif::builder("US").build();
        let e = Releasability::Grant(set(&["AUS"])).eligible(&one("USA"), &spif);
        assert!(e.permits("USA")); // origin always eligible
        assert!(e.permits("AUS")); // listed
        assert!(!e.permits("KOR")); // not listed
    }

    #[test]
    fn only_nationality_is_consulted() {
        // #26: the coalition-credential arm is REMOVED — eligibility is decided by
        // nationality alone. A subject whose nationality is not in the resolved
        // set is denied; there is no coalition assertion that can rescue it (the
        // resolved set is nations, and `permits` takes only a nation).
        let spif = Spif::builder("US").build();
        let e = Releasability::Grant(set(&["AUS"])).eligible(&one("USA"), &spif);
        assert!(e.permits("AUS")); // in the resolved nation set
        assert!(!e.permits("KOR")); // not in the set → denied
    }

    #[test]
    fn empty_denies_all_including_origin() {
        let spif = Spif::builder("US").build();
        let e = Releasability::Empty.eligible(&one("USA"), &spif);
        assert!(!e.permits("USA")); // sentinel deny-all — denies even the origin (fail-closed)
        assert!(!e.permits("AUS"));
    }

    #[test]
    fn public_permits_everyone() {
        let spif = Spif::builder("US").build();
        assert!(Releasability::Public
            .eligible(&one("USA"), &spif)
            .permits("ANY"));
    }

    #[test]
    fn tetragraph_decomposes_in_eligible() {
        // a coalition tetragraph decomposes to its GLOBAL registry member nations
        let spif = Spif::builder("US").build();
        let e = Releasability::Grant(set(&["FVEY"])).eligible(&one("USA"), &spif);
        assert!(e.permits("GBR")); // FVEY member, decomposed into nations
        assert!(!e.permits("ZAF")); // ZAF not in FVEY
    }

    #[test]
    fn unexpandable_coalition_grants_only_origin() {
        // #26 expand-or-deny: a coalition the engine cannot expand (not in the
        // registry) is DROPPED from the resolved set — it grants nothing beyond
        // the origin. The Unknown-token → Deny is enforced at both loci
        // (validate_label + gate-4), not silently widened here.
        let spif = Spif::builder("US").build();
        let e = Releasability::Grant(set(&["NKIC"])).eligible(&one("USA"), &spif); // NKIC ∉ registry
        assert!(e.permits("USA")); // origin still eligible
        assert!(!e.permits("KOR")); // NKIC unexpandable → grants no other nation
    }

    #[test]
    fn unknown_token_grants_nothing() {
        // fail-closed: an unregistered non-trigraph token is dropped from the set
        let spif = Spif::builder("US").build(); // "ZZZZ" not registered
        let e = Releasability::Grant(set(&["ZZZZ"])).eligible(&one("USA"), &spif);
        assert!(e.permits("USA")); // origin still eligible
        assert!(!e.permits("KOR")); // an unknown token grants no nation
    }

    #[test]
    fn join_is_intersection_aus_kor_reduces_to_origin() {
        // #6 flagship: REL AUS ⊕ REL KOR (US origin) → {USA} = REL {origin},
        // NOT REL AUS,KOR, NOT REL ∅.
        let spif = Spif::builder("US").build();
        let a = Releasability::Grant(set(&["AUS"])).eligible(&one("USA"), &spif); // nations {USA,AUS}
        let b = Releasability::Grant(set(&["KOR"])).eligible(&one("USA"), &spif); // nations {USA,KOR}
        let j = a.join(&b); // ∩ = {USA}
        assert!(j.permits("USA"));
        assert!(!j.permits("AUS"));
        assert!(!j.permits("KOR"));
    }

    #[test]
    fn join_universe_is_identity() {
        let spif = Spif::builder("US").build();
        let g = Releasability::Grant(set(&["AUS"])).eligible(&one("USA"), &spif);
        let j = EligibleNations::Universe.join(&g);
        assert!(j.permits("AUS") && j.permits("USA") && !j.permits("KOR"));
    }

    #[test]
    fn from_eligible_is_canonical_and_unique() {
        // one form per semantic state; Grant(∅) can never be produced
        let origin = one("USA"); // #40: owner SET (single-owner special case)
        let s = |n: &[&str]| EligibleNations::Set { nations: set(n) };
        assert!(matches!(
            Releasability::from_eligible(&EligibleNations::Universe, &origin),
            Releasability::Public
        ));
        assert!(matches!(
            Releasability::from_eligible(&s(&[]), &origin),
            Releasability::Empty
        ));
        assert!(matches!(
            Releasability::from_eligible(&s(&["USA"]), &origin),
            Releasability::NoMarking
        ));
        match Releasability::from_eligible(&s(&["USA", "AUS"]), &origin) {
            Releasability::Grant(g) => {
                assert_eq!(g, set(&["AUS"]));
                assert!(!g.is_empty());
            }
            other => panic!("expected Grant, got {other:?}"),
        }
        // precondition violation (an owner absent from a non-empty set) FAILS
        // CLOSED to Empty — no panic, no round-trip widening
        assert!(matches!(
            Releasability::from_eligible(&s(&["AUS"]), &origin),
            Releasability::Empty
        ));
    }

    #[test]
    fn eligible_unions_all_coowners() {
        // #40 flagship: JOINT{USA,KOR} // REL FVEY → every co-owner + the release
        // expansion is eligible.
        let spif = us_spif();
        let owners = set(&["USA", "KOR"]);
        let e = Releasability::Grant(set(&["FVEY"])).eligible(&owners, &spif);
        for n in ["USA", "KOR", "AUS", "GBR", "CAN", "NZL"] {
            assert!(e.permits(n), "{n} should be eligible");
        }
        assert!(!e.permits("JPN"));
        // strictly larger than the single-owner form (anti-vacuity): KOR is in only
        // because it is a co-owner.
        let single = Releasability::Grant(set(&["FVEY"])).eligible(&one("USA"), &spif);
        assert!(!single.permits("KOR") && e.permits("KOR"));
    }

    #[test]
    fn from_eligible_round_trips_multi_owner() {
        let owners = set(&["USA", "KOR"]);
        // owners ∪ a released nation → Grant(non-owners)
        let e = EligibleNations::Set {
            nations: set(&["USA", "KOR", "AUS"]),
        };
        assert_eq!(
            Releasability::from_eligible(&e, &owners),
            Releasability::Grant(set(&["AUS"]))
        );
        // nations == owners → NoMarking
        assert_eq!(
            Releasability::from_eligible(
                &EligibleNations::Set {
                    nations: owners.clone()
                },
                &owners
            ),
            Releasability::NoMarking
        );
        // precondition violated (co-owner KOR absent) → Empty (fail-closed)
        let bad = EligibleNations::Set {
            nations: set(&["USA", "AUS"]),
        };
        assert_eq!(
            Releasability::from_eligible(&bad, &owners),
            Releasability::Empty
        );
    }

    // `malformed_spif_member_cannot_widen_through_join` is RETIRED (D2): the
    // per-SPIF `tetragraph` builder it exercised is gone, and its mutation-kill
    // role — a coalition member must be a well-formed nation — is now a BUILD-TIME
    // guarantee (build.rs cross-validates every member against ISO-3166; a
    // malformed member FAILS THE BUILD). See `tests/registry_compile.rs`.

    #[test]
    fn subset_helper_handles_universe() {
        let s = |n: &[&str]| EligibleNations::Set { nations: set(n) };
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
        // FVEY comes from the GLOBAL registry now (D1); no per-SPIF roster.
        let spif = Spif::builder("US").build();
        assert!(validate_rel(&set(&["USA", "FVEY"]), &set(&["USA"]), &spif).is_ok());
        assert!(validate_rel(&set(&["USA", "DEU", "FVEY"]), &set(&["USA"]), &spif).is_ok());
        match validate_rel(&set(&["USA", "GBR", "FVEY"]), &set(&["USA"]), &spif) {
            Err(RelValidationError::DuplicativeTetragraph { token, covered }) => {
                assert_eq!(token, "GBR"); // fires on GBR, not the exempt origin
                assert_eq!(covered, "FVEY");
            }
            other => panic!("expected DuplicativeTetragraph(GBR), got {other:?}"),
        }
        assert!(matches!(
            validate_rel(&set(&[]), &set(&["USA"]), &spif),
            Err(RelValidationError::EmptyGrant)
        ));
        assert!(matches!(
            validate_rel(&set(&["ZZZZ"]), &set(&["USA"]), &spif),
            Err(RelValidationError::UnknownToken(_))
        ));
        assert!(validate_rel(&set(&["FVEY"]), &set(&["USA"]), &spif).is_ok());
        assert!(validate_rel(&set(&["KOR", "JPN"]), &set(&["USA"]), &spif).is_ok());
        // bare trigraphs need no registration
    }

    #[test]
    fn validate_rel_coowner_exemption() {
        // #25: a CO-OWNER may appear in REL TO even when a listed tetragraph
        // covers it. GBR ∈ FVEY, so `REL USA, GBR, FVEY` is duplicative under a
        // SINGLE owner {USA}...
        let spif = Spif::builder("US").build();
        match validate_rel(&set(&["USA", "GBR", "FVEY"]), &set(&["USA"]), &spif) {
            Err(RelValidationError::DuplicativeTetragraph { token, .. }) => {
                assert_eq!(token, "GBR")
            }
            other => panic!("expected DuplicativeTetragraph(GBR), got {other:?}"),
        }
        // ...but VALID when GBR is a CO-OWNER (JOINT{USA,GBR}) — the exemption
        // computes on `expansion ∖ owners`, so GBR is not a duplicate.
        assert!(validate_rel(&set(&["USA", "GBR", "FVEY"]), &set(&["USA", "GBR"]), &spif).is_ok());
        // Clause 2 likewise: FVEY ⊂ UNCK overlaps beyond a single owner (duplicative),
        // but with enough co-owners the overlap ∖ owners can clear (owner-stripped).
        assert!(matches!(
            validate_rel(&set(&["FVEY", "UNCK"]), &set(&["USA"]), &spif),
            Err(RelValidationError::DuplicativeTetragraph { .. })
        ));
    }

    #[test]
    fn validate_rel_tetra_tetra_overlap_is_origin_exempt() {
        // Maknae-local strictness: overlap computed on expansion ∖ {origin}.
        // Registry witness (D5): FVEY ⊂ UNCK (all 5 FVEY members are UNCK
        // members), so REL TO FVEY, UNCK (USA origin) overlaps beyond the origin
        // → duplicative. (No two registry coalitions overlap ONLY at the origin,
        // so the origin-exempt VALID case is witnessed by the sibling test's
        // `REL TO USA, FVEY` — origin listed alongside its own tetragraph.)
        let spif = Spif::builder("US").build();
        // a single coalition alone has no overlap partner → VALID
        assert!(validate_rel(&set(&["FVEY"]), &set(&["USA"]), &spif).is_ok());
        // FVEY ⊂ UNCK: overlap ∖ origin ⊇ {AUS,CAN,GBR,NZL} → duplicate
        assert!(matches!(
            validate_rel(&set(&["FVEY", "UNCK"]), &set(&["USA"]), &spif),
            Err(RelValidationError::DuplicativeTetragraph { .. })
        ));
    }
}
