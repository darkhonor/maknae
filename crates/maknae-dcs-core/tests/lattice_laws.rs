//! Exhaustive §6.1 lattice-law suite over a small fixed policy universe.
//!
//! Equality is SEMANTIC, never derived `==`: `join` canonicalizes
//! releasability via `from_eligible`, so a raw enumerated label and its
//! canonical join-output form must compare equal by meaning. `sem_eq` is a
//! structural equality that MODELS the mutual-`⊑` quotient (a decidable proxy,
//! not literally `le(a,b) && le(b,a)`) — deliberate: it catches
//! quantifier-direction and polarity bugs, which is its job.
//!
//! Universe (origin USA, policy US), enumerated in EXACTLY this nesting order
//! (outermost → innermost): level, sci, releasability, obligations, compilation,
//! ntk. Total 3·4·5·4·2·2 = 960 labels. Pairwise loops run the full 960²;
//! triple-quantified laws (transitivity, associativity, leastness) run over a
//! stride-13 subsample whose full-axis coverage is ASSERTED (the assertions,
//! not the stride, are the guarantee).

use maknae_dcs_core::{
    decide, Action, CategoryKind, Classification, ControlMarking, Controls, Decision, Disclosure,
    Employment, Obligation, Ownership, PolicyId, Purpose, Releasability, ResourceLabel, Spif,
    Subject,
};
use std::collections::{BTreeMap, BTreeSet};

fn set(xs: &[&str]) -> BTreeSet<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

fn law_spif() -> Spif {
    // deliberately short level names — the golden vectors use the full names
    Spif::builder("US")
        .levels(&["U", "S", "TS"])
        .category("SCI", CategoryKind::Restrictive)
        .build()
}

fn class(name: &str) -> Classification {
    Classification {
        policy: PolicyId("US".into()),
        name: name.into(),
    }
}

fn universe() -> Vec<ResourceLabel> {
    let levels = ["U", "S", "TS"];
    // empty set = key omitted, per the category-map invariant
    let sci_states: [Option<&[&str]>; 4] = [None, Some(&["A"]), Some(&["B"]), Some(&["A", "B"])];
    // #51: Empty (REL ∅) is NOT a lattice point — it is a fail-closed sentinel,
    // non-authorable. The rel-axis ⊤ is NoMarking (= REL {owners}/NOFORN).
    let rels = [
        Releasability::NoMarking,
        Releasability::Public,
        Releasability::Grant(set(&["AUS"])),
        Releasability::Grant(set(&["KOR"])),
        Releasability::Grant(set(&["AUS", "KOR"])),
    ];
    // Obligations axis (#27): the carriable atoms {∅, {NoEgress}, {OperatorOnly},
    // {both}} ordered by ⊑_obl. DisplayOnly is decision-derived (not carried), so
    // it is excluded from this axis.
    let obligation_states: [&[Obligation]; 4] = [
        &[],
        &[Obligation::NoEgress],
        &[Obligation::OperatorOnly],
        &[Obligation::NoEgress, Obligation::OperatorOnly],
    ];
    let comp_states = [None, Some("TS")];
    let ntk_states = [None, Some("OPLAN")];

    let mut out = Vec::with_capacity(960);
    for level in levels {
        for sci in sci_states {
            for rel in &rels {
                for obs in obligation_states {
                    for comp in comp_states {
                        for ntk in ntk_states {
                            out.push(ResourceLabel {
                                classification: class(level),
                                ownership: Ownership::Owned {
                                    owner: "USA".into(),
                                },
                                categories: match sci {
                                    None => BTreeMap::new(),
                                    Some(vals) => {
                                        [("SCI".to_string(), set(vals))].into_iter().collect()
                                    }
                                },
                                disclosure: Disclosure {
                                    release: rel.clone(),
                                    display: None,
                                    exclusions: BTreeSet::new(),
                                },
                                controls: Controls::empty(),
                                obligations: obs.iter().cloned().collect(),
                                compilation_level: comp.map(class),
                                need_to_know: ntk.map(|s| s.to_string()),
                            });
                        }
                    }
                }
            }
        }
    }
    assert_eq!(out.len(), 960);
    out
}

/// The rank decide() actually enforces: max(level, compilation-or-level).
fn effective_rank(l: &ResourceLabel, spif: &Spif) -> Option<usize> {
    let base = spif.rank(&l.classification)?;
    match &l.compilation_level {
        None => Some(base),
        Some(c) => Some(base.max(spif.rank(c)?)),
    }
}

/// Semantic equality: a structural equality modeling the mutual-`⊑` quotient
/// (a decidable proxy, not literally `le(a,b) && le(b,a)`). Compares EFFECTIVE rank —
/// compilation at-or-below the level is semantically identical to None (`⊑`
/// compares effective rank, so sem_eq must quotient the same way or
/// antisymmetry provably fails on the {TS, comp:None} vs {TS, comp:Some(TS)}
/// pairs).
fn sem_eq(a: &ResourceLabel, b: &ResourceLabel, spif: &Spif) -> bool {
    let (ra, rb) = (spif.rank(&a.classification), spif.rank(&b.classification));
    debug_assert!(
        ra.is_some() && rb.is_some(),
        "law universe must have known ranks"
    );
    let (ba, bb) = (a.ownership.base_set(), b.ownership.base_set());
    ra == rb
        && a.ownership == b.ownership
        && a.categories == b.categories // well-defined: no-empty-value-set invariant
        && a.disclosure.eligible_release(&ba, spif) == b.disclosure.eligible_release(&bb, spif)
        && a.disclosure.eligible_display(&ba, spif) == b.disclosure.eligible_display(&bb, spif)
        // NAF exclusions are NO LONGER a semantic axis (#26): they are consumed
        // into `eligible_release`'s subtraction (already compared above), so
        // `le` carries no exclusions conjunct and `sem_eq` must quotient the same
        // way — two labels with equal RESOLVED release/display are sem_eq
        // regardless of their raw exclusion markings.
        && a.controls == b.controls
        && a.obligations == b.obligations
        && effective_rank(a, spif) == effective_rank(b, spif)
        && a.need_to_know == b.need_to_know
}

fn le(a: &ResourceLabel, b: &ResourceLabel, spif: &Spif) -> bool {
    a.at_most_as_restrictive_as(b, spif)
        .expect("⊑ total over the law universe")
}

fn stride_sample(universe: &[ResourceLabel]) -> Vec<&ResourceLabel> {
    let sample: Vec<&ResourceLabel> = universe.iter().step_by(13).collect(); // 74 labels
                                                                             // full-axis coverage assertions — the guarantee that the subsample is
                                                                             // non-degenerate on every axis (PartialEq-only distinct counting: no
                                                                             // Ord/Hash on Releasability, deliberately)
    let distinct_levels: BTreeSet<&str> = sample
        .iter()
        .map(|l| l.classification.name.as_str())
        .collect();
    assert_eq!(distinct_levels.len(), 3);
    let distinct_sci: BTreeSet<Option<&BTreeSet<String>>> =
        sample.iter().map(|l| l.categories.get("SCI")).collect();
    assert_eq!(distinct_sci.len(), 4);
    let mut distinct_rels: Vec<&Releasability> = Vec::new();
    for l in &sample {
        if !distinct_rels.contains(&&l.disclosure.release) {
            distinct_rels.push(&l.disclosure.release);
        }
    }
    assert_eq!(distinct_rels.len(), 5);
    assert!(sample.iter().any(|l| !l.obligations.is_empty()));
    assert!(sample.iter().any(|l| l.obligations.is_empty()));
    assert!(sample.iter().any(|l| l.compilation_level.is_some()));
    assert!(sample.iter().any(|l| l.compilation_level.is_none()));
    assert!(sample.iter().any(|l| l.need_to_know.is_some()));
    assert!(sample.iter().any(|l| l.need_to_know.is_none()));
    sample
}

#[test]
fn order_and_join_laws() {
    let spif = law_spif();
    let u = universe();

    // join totality: .expect, never if-let — and the counter pins the LOOP
    // BOUNDS at the full 960² (a truncated loop can't silently shrink coverage)
    let mut join_some_count: usize = 0;

    // reflexivity over all 960
    for a in &u {
        assert!(le(a, a, &spif), "reflexivity");
        let aa = a.join(a, &spif).expect("join total over the law universe");
        assert!(sem_eq(&aa, a, &spif), "idempotence a∨a ≈ a");
    }

    // pairwise laws over the full 960²
    for a in &u {
        for b in &u {
            let ab = a.join(b, &spif).expect("join total over the law universe");
            join_some_count += 1;
            let ba = b.join(a, &spif).expect("join total over the law universe");
            // commutativity (in-universe NTK uses a single token, so the
            // scalar keep-self rule is commutative here by construction)
            assert!(sem_eq(&ab, &ba, &spif), "commutativity");
            // absorption
            let a_ab = a.join(&ab, &spif).expect("join total");
            assert!(sem_eq(&a_ab, &ab, &spif), "absorption a∨(a∨b) ≈ a∨b");
            // upper bound
            assert!(le(a, &ab, &spif), "a ⊑ a∨b");
            assert!(le(b, &ab, &spif), "b ⊑ a∨b");
            // antisymmetry modulo sem_eq
            if le(a, b, &spif) && le(b, a, &spif) {
                assert!(sem_eq(a, b, &spif), "antisymmetry modulo sem_eq");
            }
            // releasability never widens on join (∩ only narrows)
            let e_ab = ab
                .disclosure
                .eligible_release(&ab.ownership.base_set(), &spif);
            assert!(e_ab.is_subset_of(
                &a.disclosure
                    .eligible_release(&a.ownership.base_set(), &spif)
            ));
            assert!(e_ab.is_subset_of(
                &b.disclosure
                    .eligible_release(&b.ownership.base_set(), &spif)
            ));
        }
    }
    assert_eq!(join_some_count, 960 * 960);

    // triple-quantified laws over the coverage-asserted stride sample
    let sample = stride_sample(&u);
    let mut strict_transitivity_antecedent_fires: usize = 0;
    let mut leastness_antecedent_fires: usize = 0;
    for a in &sample {
        for b in &sample {
            let ab = a.join(b, &spif).expect("join total");
            for c in &sample {
                // transitivity
                if le(a, b, &spif) && le(b, c, &spif) {
                    if !sem_eq(a, b, &spif) && !sem_eq(b, c, &spif) {
                        strict_transitivity_antecedent_fires += 1;
                    }
                    assert!(le(a, c, &spif), "transitivity");
                }
                // associativity
                let bc = b.join(c, &spif).expect("join total");
                let ab_c = ab.join(c, &spif).expect("join total");
                let a_bc = a.join(&bc, &spif).expect("join total");
                assert!(sem_eq(&ab_c, &a_bc, &spif), "associativity");
                // leastness (the LUB half)
                if le(a, c, &spif) && le(b, c, &spif) {
                    if !sem_eq(a, b, &spif) {
                        leastness_antecedent_fires += 1;
                    }
                    assert!(le(&ab, c, &spif), "leastness: a⊑c ∧ b⊑c ⟹ a∨b ⊑ c");
                }
            }
        }
    }
    // anti-vacuity: reflexive triples satisfy the raw antecedents for free,
    // so count only genuinely-distinct chains
    assert!(
        strict_transitivity_antecedent_fires > 0,
        "transitivity suite is vacuous"
    );
    assert!(leastness_antecedent_fires > 0, "leastness suite is vacuous");
}

/// The v2 axes (controls × display × coalition-derived-and-exclusion-reduced
/// release) swept with the v1 axes pinned small (spec §5 "Law universe v2").
/// Ownership FIXED to `Owned{USA}`, NTK ≤ 1 token; the `∨` is total +
/// validity-agnostic over this fixed-ownership sublattice, so the sweep MAY
/// include control combos (`{Relido},{Displayed}`) that `validate_label` would
/// reject — they are valid LATTICE points here (their `derive` rejection is a
/// targeted vector, see `derive_vectors.rs`).
///
/// #26 SF2 obligation: a non-empty NAF exclusion set is paired ONLY with a
/// `Grant` release — a NAF on `Public`/`Empty`/`NoMarking` is `InvalidLabel`,
/// rejected at both loci, NOT a lattice point (the release/exclusion axis is a
/// coupled `(release, exclusions)` list, not an independent cross-product). The
/// release axis is COALITION-DERIVED (`Grant([UNCK])` expands to 18 nations) and
/// EXCLUSION-REDUCED (`NAF ZAF` removes a UNCK member from the resolved set).
/// `ListControlled`/predicate category tags are DELIBERATELY excluded (they
/// aren't in `categories_comparable`'s allowed set → would poison `⊑`/`∨`).
fn universe_v2_axes() -> Vec<ResourceLabel> {
    use ControlMarking::*;
    let set_s = |xs: &[&str]| -> std::collections::BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
    };
    let levels = ["S", "TS"];
    // Coupled (release, exclusions): a non-empty NAF ONLY with a Grant (SF2), and
    // the exclusion names an ACTUAL member so the subtraction is load-bearing.
    let rel_excl_pairs: [(Releasability, BTreeSet<String>); 6] = [
        (Releasability::NoMarking, BTreeSet::new()),
        (Releasability::Grant(set_s(&["AUS"])), BTreeSet::new()),
        (
            Releasability::Grant(set_s(&["AUS", "KOR"])),
            BTreeSet::new(),
        ),
        (Releasability::Grant(set_s(&["UNCK"])), BTreeSet::new()), // coalition-derived (18 nations)
        (Releasability::Grant(set_s(&["UNCK"])), set_s(&["ZAF"])), // exclusion-reduced (ZAF is a UNCK member)
        (
            Releasability::Grant(set_s(&["AUS", "KOR"])),
            set_s(&["KOR"]),
        ), // exclusion-reduced (KOR listed)
    ];
    let displays: [Option<Releasability>; 2] = [None, Some(Releasability::Grant(set_s(&["AUS"])))];
    let controls_axis = [
        Controls::empty(),
        Controls::from_set([OrconUsGov].into_iter().collect()),
        Controls::from_set([Orcon].into_iter().collect()),
        Controls::from_set([Exdis].into_iter().collect()),
        Controls::from_set([Nodis].into_iter().collect()),
        Controls::from_set([Relido].into_iter().collect()),
        Controls::from_set([Displayed].into_iter().collect()),
    ];
    let mut out = Vec::new();
    for level in levels {
        for (rel, excl) in &rel_excl_pairs {
            for display in &displays {
                for controls in &controls_axis {
                    out.push(ResourceLabel {
                        classification: class(level),
                        ownership: Ownership::Owned {
                            owner: "USA".into(),
                        },
                        categories: BTreeMap::new(),
                        disclosure: Disclosure {
                            release: rel.clone(),
                            display: display.clone(),
                            exclusions: excl.clone(),
                        },
                        controls: controls.clone(),
                        obligations: BTreeSet::new(),
                        compilation_level: None,
                        need_to_know: None,
                    });
                }
            }
        }
    }
    assert_eq!(out.len(), 2 * 6 * 2 * 7); // 168
                                          // SF2 invariant: no swept label carries a NAF over a Public/Empty/NoMarking
                                          // release (those states are InvalidLabel, rejected at both loci — never a
                                          // lattice point that `eligible_release`'s Universe arm would have to subtract).
    for l in &out {
        assert!(
            l.disclosure.exclusions.is_empty()
                || matches!(l.disclosure.release, Releasability::Grant(_)),
            "SF2: a NAF exclusion must accompany a Grant release"
        );
    }
    out
}

/// #40: the co-owned (JOINT) sublattice, fixed to one owner frame `Joint{USA,KOR}`
/// (join is within-frame). Mirrors `universe_v2_axes` with a ONE-PAIR SWAP: the
/// v2 axis's `(Grant{AUS,KOR}, NAF KOR)` names co-owner KOR — that is owner-in-X =
/// `InvalidLabel`, NOT a lattice point, and would make `from_eligible`'s
/// `owners ⊆ nations` map lossy — so it is replaced with `(Grant{AUS,KOR}, NAF AUS)`
/// (AUS is not a co-owner). A machine-checked guard asserts no swept label NAFs a
/// co-owner (spec-CR-r2 NTH-2).
fn universe_v2_joint() -> Vec<ResourceLabel> {
    use ControlMarking::*;
    let set_s = |xs: &[&str]| -> std::collections::BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
    };
    let owners = set_s(&["USA", "KOR"]);
    let levels = ["S", "TS"];
    let rel_excl_pairs: [(Releasability, BTreeSet<String>); 6] = [
        (Releasability::NoMarking, BTreeSet::new()),
        (Releasability::Grant(set_s(&["AUS"])), BTreeSet::new()),
        (
            Releasability::Grant(set_s(&["AUS", "KOR"])),
            BTreeSet::new(),
        ),
        (Releasability::Grant(set_s(&["UNCK"])), BTreeSet::new()),
        (Releasability::Grant(set_s(&["UNCK"])), set_s(&["ZAF"])), // ZAF non-owner
        (
            Releasability::Grant(set_s(&["AUS", "KOR"])),
            set_s(&["AUS"]),
        ), // one-pair swap: AUS non-owner (was NAF KOR)
    ];
    let displays: [Option<Releasability>; 2] = [None, Some(Releasability::Grant(set_s(&["AUS"])))];
    let controls_axis = [
        Controls::empty(),
        Controls::from_set([OrconUsGov].into_iter().collect()),
        Controls::from_set([Orcon].into_iter().collect()),
        Controls::from_set([Exdis].into_iter().collect()),
        Controls::from_set([Nodis].into_iter().collect()),
        Controls::from_set([Relido].into_iter().collect()),
        Controls::from_set([Displayed].into_iter().collect()),
    ];
    let mut out = Vec::new();
    for level in levels {
        for (rel, excl) in &rel_excl_pairs {
            for display in &displays {
                for controls in &controls_axis {
                    out.push(ResourceLabel {
                        classification: class(level),
                        ownership: Ownership::Joint {
                            owners: owners.clone(),
                        },
                        categories: BTreeMap::new(),
                        disclosure: Disclosure {
                            release: rel.clone(),
                            display: display.clone(),
                            exclusions: excl.clone(),
                        },
                        controls: controls.clone(),
                        obligations: BTreeSet::new(),
                        compilation_level: None,
                        need_to_know: None,
                    });
                }
            }
        }
    }
    assert_eq!(out.len(), 2 * 6 * 2 * 7); // 168
    for l in &out {
        // SF2 (as v2) + the #40 non-owner-NAF guard (C1 unreachability, machine-checked).
        assert!(
            l.disclosure.exclusions.is_empty()
                || matches!(l.disclosure.release, Releasability::Grant(_)),
            "SF2: a NAF exclusion must accompany a Grant release"
        );
        assert!(
            l.disclosure.exclusions.is_disjoint(&owners),
            "#40: no swept Joint label may NAF a co-owner (owner-in-X is InvalidLabel)"
        );
    }
    out
}

#[test]
fn joint_v2_order_and_join_laws() {
    let spif = law_spif();
    let u = universe_v2_joint();
    let set_s = |xs: &[&str]| -> BTreeSet<String> { xs.iter().map(|s| s.to_string()).collect() };

    // anti-vacuity (NTH-1): the co-owned resolved set is STRICTLY LARGER than the
    // single-owner equivalent — KOR is eligible ONLY because it is a co-owner.
    let joint_fvey =
        Releasability::Grant(set_s(&["FVEY"])).eligible(&set_s(&["USA", "KOR"]), &spif);
    let owned_fvey = Releasability::Grant(set_s(&["FVEY"])).eligible(&set_s(&["USA"]), &spif);
    assert!(joint_fvey.permits("KOR") && !owned_fvey.permits("KOR"));

    // cross-frame refusal: Owned{USA} ∨ Joint{USA,KOR} = None (different frames).
    let owned = ResourceLabel {
        ownership: Ownership::Owned {
            owner: "USA".into(),
        },
        ..u[0].clone()
    };
    assert!(
        owned.join(&u[0], &spif).is_none(),
        "cross-frame join is None"
    );

    // full pairwise laws over the 168-label co-owned frame.
    let mut join_some_count: usize = 0;
    let mut antisymmetry_fires: usize = 0;
    for a in &u {
        assert!(le(a, a, &spif), "reflexivity");
        let aa = a
            .join(a, &spif)
            .expect("∨ total over the co-owned sublattice");
        assert!(sem_eq(&aa, a, &spif), "idempotence a∨a ≈ a");
    }
    for a in &u {
        for b in &u {
            let ab = a.join(b, &spif).expect("∨ total");
            join_some_count += 1;
            let ba = b.join(a, &spif).expect("∨ total");
            assert!(sem_eq(&ab, &ba, &spif), "commutativity");
            let a_ab = a.join(&ab, &spif).expect("∨ total");
            assert!(sem_eq(&a_ab, &ab, &spif), "absorption a∨(a∨b) ≈ a∨b");
            assert!(le(a, &ab, &spif), "a ⊑ a∨b");
            assert!(le(b, &ab, &spif), "b ⊑ a∨b");
            if le(a, b, &spif) && le(b, a, &spif) {
                assert!(sem_eq(a, b, &spif), "antisymmetry modulo sem_eq");
                if a != b {
                    antisymmetry_fires += 1;
                }
            }
            assert!(a.controls.le(&ab.controls) && b.controls.le(&ab.controls));
            assert!(ab.disclosure.exclusions.is_empty());
        }
    }
    assert_eq!(join_some_count, 168 * 168);
    assert!(
        antisymmetry_fires > 0,
        "joint antisymmetry suite is vacuous"
    );

    // associativity over a coverage-asserted stride subsample.
    let sample: Vec<&ResourceLabel> = u.iter().step_by(4).collect();
    assert!(sample.iter().any(|l| !l.disclosure.exclusions.is_empty()));
    assert!(sample.iter().any(|l| l.disclosure.exclusions.is_empty()));
    let mut assoc_checked: usize = 0;
    for a in &sample {
        for b in &sample {
            let ab = a.join(b, &spif).expect("∨ total");
            for c in &sample {
                let bc = b.join(c, &spif).expect("∨ total");
                let ab_c = ab.join(c, &spif).expect("∨ total");
                let a_bc = a.join(&bc, &spif).expect("∨ total");
                assert!(
                    sem_eq(&ab_c, &a_bc, &spif),
                    "associativity (a∨b)∨c ≈ a∨(b∨c) over the co-owned frame"
                );
                assoc_checked += 1;
            }
        }
    }
    assert_eq!(assoc_checked, sample.len().pow(3));
}

#[test]
fn v2_axes_order_and_join_laws() {
    let spif = law_spif();
    let u = universe_v2_axes();

    // axis-coverage: every controls value, both displays, both exclusions present
    let distinct_controls: BTreeSet<Vec<ControlMarking>> = u
        .iter()
        .map(|l| l.controls.as_set().iter().copied().collect())
        .collect();
    assert_eq!(distinct_controls.len(), 7);
    assert!(u.iter().any(|l| l.disclosure.display.is_some()));
    assert!(u.iter().any(|l| l.disclosure.display.is_none()));
    assert!(u.iter().any(|l| !l.disclosure.exclusions.is_empty()));

    let mut join_some_count: usize = 0;
    let mut antisymmetry_fires: usize = 0; // structurally-distinct mutually-⊑ pairs
    for a in &u {
        assert!(le(a, a, &spif), "reflexivity");
        let aa = a
            .join(a, &spif)
            .expect("∨ total over the fixed-ownership sublattice");
        assert!(sem_eq(&aa, a, &spif), "idempotence a∨a ≈ a");
    }
    for a in &u {
        for b in &u {
            let ab = a
                .join(b, &spif)
                .expect("∨ total over the fixed-ownership sublattice");
            join_some_count += 1;
            let ba = b.join(a, &spif).expect("∨ total");
            assert!(sem_eq(&ab, &ba, &spif), "commutativity");
            let a_ab = a.join(&ab, &spif).expect("∨ total");
            assert!(sem_eq(&a_ab, &ab, &spif), "absorption a∨(a∨b) ≈ a∨b");
            assert!(le(a, &ab, &spif), "a ⊑ a∨b");
            assert!(le(b, &ab, &spif), "b ⊑ a∨b");
            if le(a, b, &spif) && le(b, a, &spif) {
                assert!(sem_eq(a, b, &spif), "antisymmetry modulo sem_eq");
                if a != b {
                    // distinct reps that are mutually-⊑ (e.g. display=None vs
                    // display=Some(=release)) → the law is non-vacuously exercised
                    antisymmetry_fires += 1;
                }
            }
            // controls never shrink on join (monotone)
            assert!(a.controls.le(&ab.controls) && b.controls.le(&ab.controls));
            // NAF exclusions are NO LONGER a join axis (#26): the subtraction is
            // baked into each operand's resolved release BEFORE the ∩, so the
            // joined disclosure carries EMPTY exclusions (the exclusion is
            // consumed into the narrower release, not re-carried).
            assert!(ab.disclosure.exclusions.is_empty());
        }
    }
    assert_eq!(join_some_count, 168 * 168); // ∨ total: no fail-closed None in the sweep
    assert!(antisymmetry_fires > 0, "v2 antisymmetry suite is vacuous");

    // Associativity is a TRIPLE law the pairwise loop above cannot see. Sweep it
    // over a stride-4 subsample of the 168-label v2 universe whose axis coverage
    // is asserted (the v1 triple-law pattern), so the ADR's "associative over the
    // fixed-ownership sublattice" claim is earned, not assumed: (a∨b)∨c ≈ a∨(b∨c).
    let sample: Vec<&ResourceLabel> = u.iter().step_by(4).collect(); // 42 labels
    let sample_controls: BTreeSet<Vec<ControlMarking>> = sample
        .iter()
        .map(|l| l.controls.as_set().iter().copied().collect())
        .collect();
    assert_eq!(
        sample_controls.len(),
        7,
        "stride subsample dropped a controls value"
    );
    assert!(sample.iter().any(|l| l.disclosure.display.is_some()));
    assert!(sample.iter().any(|l| l.disclosure.display.is_none()));
    assert!(sample.iter().any(|l| !l.disclosure.exclusions.is_empty()));
    assert!(sample.iter().any(|l| l.disclosure.exclusions.is_empty()));
    let mut assoc_checked: usize = 0;
    for a in &sample {
        for b in &sample {
            let ab = a.join(b, &spif).expect("∨ total");
            for c in &sample {
                let bc = b.join(c, &spif).expect("∨ total");
                let ab_c = ab.join(c, &spif).expect("∨ total");
                let a_bc = a.join(&bc, &spif).expect("∨ total");
                assert!(
                    sem_eq(&ab_c, &a_bc, &spif),
                    "associativity (a∨b)∨c ≈ a∨(b∨c) over the v2 axes"
                );
                assoc_checked += 1;
            }
        }
    }
    assert_eq!(
        assoc_checked,
        sample.len().pow(3),
        "associativity sweep coverage"
    );
}

#[test]
fn dominance_monotonicity() {
    let spif = law_spif();
    let u = universe();

    // subject panel: clearance {S,TS} × read_ins {∅, {A}, {A,B}} × purposes
    // {∅, {OPLAN}} — 12 US subjects; × action {Read, Export} to exercise the
    // action-dispatch on both arms (the release/display matrix decides on the
    // relation, not the action, for these display-None labels — obligation
    // monotonicity rides the ⊑_obl axis). Plus one AUS-national subject so the
    // releasability clause of ⊑ is load-bearing (gate 4 distinguishes
    // NoMarking/Grant states only for a non-origin nationality).
    let mut panel: Vec<Subject> = Vec::new();
    for clearance in ["S", "TS"] {
        let read_in_states: [Option<&[&str]>; 3] = [None, Some(&["A"]), Some(&["A", "B"])];
        for read_ins in read_in_states {
            for purposes in [&[][..], &["OPLAN"][..]] {
                panel.push(Subject {
                    clearance: class(clearance),
                    nationality: "USA".into(),
                    read_ins: match read_ins {
                        None => BTreeMap::new(),
                        Some(vals) => [("SCI".to_string(), set(vals))].into_iter().collect(),
                    },
                    coalition_memberships: BTreeSet::new(),
                    employment: Employment::FederalCivilian,
                    list_memberships: BTreeSet::new(),
                    purposes: purposes.iter().map(|s| s.to_string()).collect(),
                });
            }
        }
    }
    panel.push(Subject {
        clearance: class("TS"),
        nationality: "AUS".into(),
        read_ins: [("SCI".to_string(), set(&["A", "B"]))]
            .into_iter()
            .collect(),
        coalition_memberships: BTreeSet::new(),
        employment: Employment::Foreign,
        list_memberships: BTreeSet::new(),
        purposes: set(&["OPLAN"]),
    });
    assert_eq!(panel.len(), 13);
    let purpose = Purpose("OPLAN".to_string());
    let actions = [Action::Read, Action::Export];

    // pairs-OUTER, subjects/actions-inner: compute ⊑ once per pair
    let mut antecedent_fires: usize = 0;
    let mut strict_antecedent_fires: usize = 0;
    for r1 in &u {
        for r2 in &u {
            if !le(r1, r2, &spif) {
                continue;
            }
            for s in &panel {
                for action in actions {
                    if decide(s, r2, action, &purpose, &spif) == Decision::Permit {
                        antecedent_fires += 1;
                        if !sem_eq(r1, r2, &spif) {
                            strict_antecedent_fires += 1;
                        }
                        // permit on the more-restrictive implies permit on the
                        // less-restrictive
                        assert_eq!(
                            decide(s, r1, action, &purpose, &spif),
                            Decision::Permit,
                            "monotonicity violated"
                        );
                    }
                }
            }
        }
    }
    assert!(
        antecedent_fires > 0 && strict_antecedent_fires > 0,
        "monotonicity suite is vacuous"
    );
}
