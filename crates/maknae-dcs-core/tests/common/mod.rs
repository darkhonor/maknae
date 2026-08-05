//! Shared helpers for the #26 NAF decide-path integration vectors (D7/D9).
//!
//! These live in an integration `common` module — NOT `decide.rs`'s unit
//! `mod tests` (which keeps its clearance-keyed `mk_subject`). Bodies mirror the
//! label.rs unit D7 helpers, and construct a US-policy subject/label whose
//! clearance clears the label under `us_spif()` so every NAF vector reaches
//! gate 4 (releasability) — the deciding gate — rather than denying earlier.

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
            // "S" (CLASSIFIED, rank 1) — a NAF is valid only on classified data
            // (DoDM §e); subject clearance TS still clears it at gate 2.
            policy: PolicyId("US".into()),
            name: "S".into(),
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
