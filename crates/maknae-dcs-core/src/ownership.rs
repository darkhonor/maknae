//! Ownership axis (#25): who owns the information. The three grammars are
//! MUTUALLY EXCLUSIVE (DoDM 5200.01 V2 §4). Generalizes v1 `origin`.
use std::collections::BTreeSet;

/// Who owns the information (EPIC #33 spec §2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ownership {
    /// Single-nation owned (v1 `origin` generalized). US-owned = Owned{"USA"};
    /// single-source FGI = Owned{"DEU"} — the engine distinction is the owner.
    Owned { owner: String },
    /// Co-owned/co-produced (JOINT). INVARIANT: owners.len() >= 2.
    Joint { owners: BTreeSet<String> },
    /// FGI, source government(s) concealed but the FGI FACT acknowledged
    /// (`//FGI` no-codes form). Owners unknowable; access routes through the
    /// custodian. SOLE concealed variant Day-1 (operator decision 2026-08-04).
    ConcealedForeign { custodian: String },
}

impl Ownership {
    /// Known owners, or None when unknowable (ConcealedForeign).
    pub fn owners(&self) -> Option<BTreeSet<String>> {
        match self {
            Ownership::Owned { owner } => Some([owner.clone()].into_iter().collect()),
            Ownership::Joint { owners } => Some(owners.clone()),
            Ownership::ConcealedForeign { .. } => None,
        }
    }

    /// The trigraph used as the owners-set for baseline access: the sole owner
    /// for Owned, the custodian for ConcealedForeign, None for Joint.
    pub fn custodian(&self) -> Option<&str> {
        match self {
            Ownership::Owned { owner } => Some(owner.as_str()),
            Ownership::ConcealedForeign { custodian } => Some(custodian.as_str()),
            Ownership::Joint { .. } => None,
        }
    }

    /// The BASE owners-set for baseline access (custodian-implicit for
    /// ConcealedForeign, per spec §2.1 / V2 §4.e).
    pub fn base_set(&self) -> BTreeSet<String> {
        match self {
            Ownership::Owned { owner } => [owner.clone()].into_iter().collect(),
            Ownership::Joint { owners } => owners.clone(),
            Ownership::ConcealedForeign { custodian } => {
                [custodian.clone()].into_iter().collect()
            }
        }
    }

    /// The lattice `∨` is defined only WITHIN an identical ownership frame
    /// (spec §2.1: cross-ownership has no join — it is a `derive` refusal,
    /// exactly as v1 treats cross-origin). Total equality of the variant.
    pub fn same_frame(&self, other: &Ownership) -> bool {
        self == other
    }

    /// Constructor enforcing the Joint len>=2 invariant: a single-owner set
    /// collapses to Owned (fail-closed to the simpler frame); an empty set
    /// yields the `Owned{""}` sentinel, which every access check rejects (not a
    /// trigraph). Callers must not rely on the empty case as valid.
    pub fn joint_from(owners: BTreeSet<String>) -> Ownership {
        if owners.len() >= 2 {
            Ownership::Joint { owners }
        } else if let Some(one) = owners.into_iter().next() {
            Ownership::Owned { owner: one }
        } else {
            Ownership::Owned { owner: String::new() }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn s(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn owners_and_custodian_by_variant() {
        let owned = Ownership::Owned { owner: "USA".into() };
        assert_eq!(owned.owners(), Some(s(&["USA"])));
        assert_eq!(owned.custodian(), Some("USA"));

        let joint = Ownership::Joint { owners: s(&["USA", "KOR"]) };
        assert_eq!(joint.owners(), Some(s(&["USA", "KOR"])));
        assert_eq!(joint.custodian(), None); // Joint has no single custodian

        let cf = Ownership::ConcealedForeign { custodian: "USA".into() };
        assert_eq!(cf.owners(), None); // owners unknowable
        assert_eq!(cf.custodian(), Some("USA"));
    }

    #[test]
    fn same_frame_requires_identical_ownership() {
        let a = Ownership::Owned { owner: "USA".into() };
        assert!(a.same_frame(&Ownership::Owned { owner: "USA".into() }));
        assert!(!a.same_frame(&Ownership::Owned { owner: "DEU".into() }));
        assert!(!a.same_frame(&Ownership::Joint { owners: s(&["USA", "KOR"]) }));
        assert!(!a.same_frame(&Ownership::ConcealedForeign { custodian: "USA".into() }));
    }

    #[test]
    fn joint_invariant_two_or_more() {
        assert!(matches!(Ownership::joint_from(s(&["USA"])), Ownership::Owned { .. }));
        assert!(matches!(Ownership::joint_from(s(&["USA", "KOR"])), Ownership::Joint { .. }));
        // empty owner set → the Owned{""} sentinel (rejected downstream at gate 4
        // is_trigraph; this test kills the empty-arm mutant per the T1 0-missed gate)
        assert_eq!(
            Ownership::joint_from(BTreeSet::new()),
            Ownership::Owned { owner: String::new() }
        );
    }

    #[test]
    fn base_set_by_variant() {
        assert_eq!(Ownership::Owned { owner: "USA".into() }.base_set(), s(&["USA"]));
        assert_eq!(
            Ownership::Joint { owners: s(&["USA", "KOR"]) }.base_set(),
            s(&["USA", "KOR"])
        );
        // ConcealedForeign baseline is the custodian (spec §2.1 / V2 §4.e)
        assert_eq!(
            Ownership::ConcealedForeign { custodian: "USA".into() }.base_set(),
            s(&["USA"])
        );
    }
}
