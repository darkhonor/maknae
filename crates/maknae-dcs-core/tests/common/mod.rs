//! Shared helpers for the #26 NAF decide-path integration vectors (D7/D9).
//!
//! These live in an integration `common` module — NOT `decide.rs`'s unit
//! `mod tests` (which keeps its clearance-keyed `mk_subject`). Bodies mirror the
//! label.rs unit D7 helpers, and construct a US-policy subject/label whose
//! clearance clears the label under `us_spif()` so every NAF vector reaches
//! gate 4 (releasability) — the deciding gate — rather than denying earlier.
//!
//! `#![allow(dead_code)]`: this module is compiled once per integration-test
//! binary; each binary uses a different subset of the shared helpers, so a
//! helper unused BY ONE binary is not dead — the standard `common/mod.rs` idiom.
#![allow(dead_code)]

use maknae_dcs_core::{
    Classification, Controls, Disclosure, Employment, Ownership, PolicyId, Purpose, Releasability,
    ResourceLabel, Spif, Subject,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn set(xs: &[&str]) -> BTreeSet<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

/// US-policy SPIF, levels U<S<TS, no per-SPIF tetragraph (coalitions are global).
pub fn us_spif() -> Spif {
    Spif::builder("US").levels(&["U", "S", "TS"]).build()
}

/// Owned{origin}, classification U//US, everything else empty — gates 1-3/5 pass
/// under `us_spif()` so gate 4 (releasability) is the deciding gate.
pub fn mk_owned(origin: &str) -> ResourceLabel {
    ResourceLabel {
        classification: Classification {
            policy: PolicyId("US".into()),
            name: "U".into(),
        },
        ownership: Ownership::Owned {
            owner: origin.into(),
        },
        categories: BTreeMap::new(),
        disclosure: Disclosure {
            release: Releasability::NoMarking,
            display: None,
            exclusions: BTreeSet::new(),
        },
        controls: Controls::empty(),
        caveats: BTreeSet::new(),
        compilation_level: None,
        need_to_know: None,
    }
}

/// US-policy subject, clearance TS (clears any `us_spif()` level), nationality
/// `nat`, all sets empty — gates 1-3/5 pass; gate 4 adjudicates on nationality.
pub fn sub(nat: &str) -> Subject {
    Subject {
        clearance: Classification {
            policy: PolicyId("US".into()),
            name: "TS".into(),
        },
        nationality: nat.into(),
        read_ins: BTreeMap::new(),
        coalition_memberships: BTreeSet::new(),
        employment: Employment::FederalCivilian,
        list_memberships: BTreeSet::new(),
        purposes: BTreeSet::new(),
    }
}

pub fn purpose(s: &str) -> Purpose {
    Purpose(s.to_string())
}

/// A co-owned (JOINT) label — same as `mk_owned` but `Ownership::Joint` (#40).
pub fn joint(owners: &[&str]) -> ResourceLabel {
    ResourceLabel {
        ownership: Ownership::Joint {
            owners: set(owners),
        },
        ..mk_owned("USA")
    }
}

/// US-policy SPIF with the long classification tokens + classified_floor
/// (#27 DISPLAY ONLY vectors — the "U"/"S"/"TS" `us_spif()` has no floor).
pub fn us_classified_spif() -> Spif {
    Spif::builder("US")
        .levels(&["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"])
        .classified_floor("CONFIDENTIAL")
        .build()
}

/// `mk_owned` at a long-token classification level (for the classified-floor
/// vectors). NoMarking release, everything else empty.
pub fn mk_owned_classified(origin: &str, level: &str) -> ResourceLabel {
    let mut r = mk_owned(origin);
    r.classification = Classification {
        policy: PolicyId("US".into()),
        name: level.into(),
    };
    r
}

/// A subject cleared under the LONG-token SPIF (clearance TOP_SECRET clears any
/// `us_classified_spif()` level) — the "TS"-clearance `sub()` has no rank there
/// and would gate-2 Deny(Indeterminate). Nationality `nat`, all sets empty.
pub fn sub_classified(nat: &str) -> Subject {
    let mut s = sub(nat);
    s.clearance = Classification {
        policy: PolicyId("US".into()),
        name: "TOP_SECRET".into(),
    };
    s
}

/// A ConcealedForeign label (Stage-5, still fails closed at decide).
pub fn cf(custodian: &str) -> ResourceLabel {
    ResourceLabel {
        ownership: Ownership::ConcealedForeign {
            custodian: custodian.into(),
        },
        ..mk_owned("USA")
    }
}
