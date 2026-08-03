//! Exhaustive §6.1 lattice-law suite over a small fixed policy universe.
//!
//! Equality is SEMANTIC, never derived `==`: `join` canonicalizes
//! releasability via `from_eligible`, so a raw enumerated label and its
//! canonical join-output form must compare equal by meaning. `sem_eq` is
//! definitionally the mutual-`⊑` quotient — deliberate: it catches
//! quantifier-direction and polarity bugs, which is its job.
//!
//! Universe (origin USA, policy US), enumerated in EXACTLY this nesting order
//! (outermost → innermost): level, sci, releasability, caveats, compilation,
//! ntk. Total 3·4·6·2·2·2 = 576 labels. Pairwise loops run the full 576²;
//! triple-quantified laws (transitivity, associativity, leastness) run over a
//! stride-13 subsample whose full-axis coverage is ASSERTED (the assertions,
//! not the stride, are the guarantee).

use maknae_dcs_core::{
    decide, Action, Affiliation, CategoryKind, Caveat, Classification, Decision, PolicyId, Purpose,
    Releasability, ResourceLabel, Spif, Subject,
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
    let rels = [
        Releasability::NoMarking,
        Releasability::Empty,
        Releasability::Public,
        Releasability::Grant(set(&["AUS"])),
        Releasability::Grant(set(&["KOR"])),
        Releasability::Grant(set(&["AUS", "KOR"])),
    ];
    let caveat_states: [&[Caveat]; 2] = [&[], &[Caveat::DisplayOnly]];
    let comp_states = [None, Some("TS")];
    let ntk_states = [None, Some("OPLAN")];

    let mut out = Vec::with_capacity(576);
    for level in levels {
        for sci in sci_states {
            for rel in &rels {
                for cavs in caveat_states {
                    for comp in comp_states {
                        for ntk in ntk_states {
                            out.push(ResourceLabel {
                                classification: class(level),
                                origin: "USA".into(),
                                categories: match sci {
                                    None => BTreeMap::new(),
                                    Some(vals) => {
                                        [("SCI".to_string(), set(vals))].into_iter().collect()
                                    }
                                },
                                releasability: rel.clone(),
                                caveats: cavs.iter().copied().collect(),
                                compilation_level: comp.map(class),
                                need_to_know: ntk.map(|s| s.to_string()),
                            });
                        }
                    }
                }
            }
        }
    }
    assert_eq!(out.len(), 576);
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

/// Semantic equality: the mutual-`⊑` quotient. Compares EFFECTIVE rank —
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
    ra == rb
        && a.origin == b.origin
        && a.categories == b.categories // well-defined: no-empty-value-set invariant
        && a.releasability.eligible(&a.origin, spif) == b.releasability.eligible(&b.origin, spif)
        && a.caveats == b.caveats
        && effective_rank(a, spif) == effective_rank(b, spif)
        && a.need_to_know == b.need_to_know
}

fn le(a: &ResourceLabel, b: &ResourceLabel, spif: &Spif) -> bool {
    a.at_most_as_restrictive_as(b, spif)
        .expect("⊑ total over the law universe")
}

fn stride_sample(universe: &[ResourceLabel]) -> Vec<&ResourceLabel> {
    let sample: Vec<&ResourceLabel> = universe.iter().step_by(13).collect(); // 45 labels
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
        if !distinct_rels.contains(&&l.releasability) {
            distinct_rels.push(&l.releasability);
        }
    }
    assert_eq!(distinct_rels.len(), 6);
    assert!(sample.iter().any(|l| !l.caveats.is_empty()));
    assert!(sample.iter().any(|l| l.caveats.is_empty()));
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
    // BOUNDS at the full 576² (a truncated loop can't silently shrink coverage)
    let mut join_some_count: usize = 0;

    // reflexivity over all 576
    for a in &u {
        assert!(le(a, a, &spif), "reflexivity");
        let aa = a.join(a, &spif).expect("join total over the law universe");
        assert!(sem_eq(&aa, a, &spif), "idempotence a∨a ≈ a");
    }

    // pairwise laws over the full 576²
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
            let e_ab = ab.releasability.eligible(&ab.origin, &spif);
            assert!(e_ab.is_subset_of(&a.releasability.eligible(&a.origin, &spif)));
            assert!(e_ab.is_subset_of(&b.releasability.eligible(&b.origin, &spif)));
        }
    }
    assert_eq!(join_some_count, 576 * 576);

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

#[test]
fn dominance_monotonicity() {
    let spif = law_spif();
    let u = universe();

    // subject panel: clearance {S,TS} × read_ins {∅, {A}, {A,B}} × purposes
    // {∅, {OPLAN}} — 12 subjects; × action {Read, Export} (Export makes the
    // caveats-⊑ clause load-bearing under DisplayOnly)
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
                    affiliation: Affiliation::UsGovernment,
                    purposes: purposes.iter().map(|s| s.to_string()).collect(),
                });
            }
        }
    }
    assert_eq!(panel.len(), 12);
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
