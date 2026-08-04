//! `derive` fail-closed targeted vectors (spec §5): the partial derive-guard
//! cases proven as VECTORS, not sweep axes — exactly as v1 sweeps single-origin
//! and treats cross-origin `None` as targeted vectors. The lattice `∨` is total
//! and validity-agnostic; `derive = validate_label ∘ ∨` is where fail-closed
//! `None` lives (cross-ownership frame, cross-NTK, and — from Stage 2 —
//! exclusion pairs / couplings).
use maknae_dcs_core::{
    derive, Classification, ControlMarking, Controls, Disclosure, Ownership, PolicyId,
    Releasability, ResourceLabel, Spif,
};
use std::collections::{BTreeMap, BTreeSet};

fn spif() -> Spif {
    Spif::builder("US").levels(&["U", "S", "TS"]).build()
}
fn set(xs: &[&str]) -> BTreeSet<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

fn label(ownership: Ownership, ntk: Option<&str>, controls: Controls) -> ResourceLabel {
    ResourceLabel {
        classification: Classification {
            policy: PolicyId("US".into()),
            name: "S".into(),
        },
        ownership,
        categories: BTreeMap::new(),
        disclosure: Disclosure {
            release: Releasability::NoMarking,
            display: None,
            exclusions: BTreeSet::new(),
        },
        controls,
        caveats: BTreeSet::new(),
        compilation_level: None,
        need_to_know: ntk.map(|s| s.to_string()),
    }
}

#[test]
fn cross_ownership_derive_is_none() {
    let s = spif();
    let usa = label(
        Ownership::Owned {
            owner: "USA".into(),
        },
        None,
        Controls::empty(),
    );
    let joint = label(
        Ownership::Joint {
            owners: set(&["USA", "KOR"]),
        },
        None,
        Controls::empty(),
    );
    let cf = label(
        Ownership::ConcealedForeign {
            custodian: "USA".into(),
        },
        None,
        Controls::empty(),
    );
    // cross-ownership → None both orderings (the frame boundary, via join)
    assert!(derive(&usa, &joint, &s).is_none());
    assert!(derive(&joint, &usa, &s).is_none());
    assert!(derive(&usa, &cf, &s).is_none());
    // same-frame derive IS Some (join total over the fixed-ownership sublattice)
    assert!(derive(&usa, &usa, &s).is_some());
}

#[test]
fn cross_ntk_derive_is_none() {
    let s = spif();
    let oplan = label(
        Ownership::Owned {
            owner: "USA".into(),
        },
        Some("OPLAN"),
        Controls::empty(),
    );
    let conplan = label(
        Ownership::Owned {
            owner: "USA".into(),
        },
        Some("CONPLAN"),
        Controls::empty(),
    );
    assert!(derive(&oplan, &conplan, &s).is_none()); // differing NTK tokens
    assert!(derive(&oplan, &oplan, &s).is_some()); // equal token
}

#[test]
fn join_total_where_derive_will_later_refuse_exclusion_pair() {
    use ControlMarking::*;
    let s = spif();
    let relido = label(
        Ownership::Owned {
            owner: "USA".into(),
        },
        None,
        Controls::from_set([Relido].into_iter().collect()),
    );
    let displayed = label(
        Ownership::Owned {
            owner: "USA".into(),
        },
        None,
        Controls::from_set([Displayed].into_iter().collect()),
    );
    // ∨ is TOTAL: join returns Some even for a would-be-exclusion control pair
    let j = relido.join(&displayed, &s).expect("∨ total");
    assert_eq!(
        j.controls.as_set(),
        &[Relido, Displayed].into_iter().collect()
    );
    // Stage 1: derive is ALSO Some — exclusion rejection is Stage 2.
    // TODO(stage2): flip to None once validate_label rejects Relido × Displayed.
    assert!(derive(&relido, &displayed, &s).is_some());
}
