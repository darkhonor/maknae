//! Ownership axis (#25): who owns the information. The three grammars are
//! MUTUALLY EXCLUSIVE (DoDM 5200.01 V2 §4). Generalizes v1 `origin`.
use crate::policy::is_trigraph;
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
            Ownership::ConcealedForeign { custodian } => [custodian.clone()].into_iter().collect(),
        }
    }

    /// Structural well-formedness of the ownership FRAME — the single source of
    /// truth used by `decide()` gate 4, the lattice `⊑`/`∨` frame guard, and
    /// `validate_label` (so the malformed-frame boundary can never split-brain).
    ///
    /// - `Owned` — its sole owner is a trigraph (rejects the `Owned{""}` /
    ///   `joint_from(∅)` sentinel);
    /// - `Joint` — at least TWO co-owners (its documented invariant; a
    ///   directly-constructed singleton/empty `Joint` is MALFORMED), all
    ///   trigraphs;
    /// - `ConcealedForeign` — its custodian is a trigraph. (Structural only —
    ///   the Stage-5 decide-time deferral of `ConcealedForeign` is a SEPARATE
    ///   concern from frame well-formedness.)
    ///
    /// Trigraph shape only — nation RECOGNITION (ISO-3166 membership) is the
    /// world-view check layered on top in `validate_label`.
    pub fn is_wellformed(&self) -> bool {
        match self {
            Ownership::Owned { owner } => is_trigraph(owner),
            Ownership::Joint { owners } => {
                owners.len() >= 2 && owners.iter().all(|o| is_trigraph(o))
            }
            Ownership::ConcealedForeign { custodian } => is_trigraph(custodian),
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
            Ownership::Owned {
                owner: String::new(),
            }
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
        let owned = Ownership::Owned {
            owner: "USA".into(),
        };
        assert_eq!(owned.owners(), Some(s(&["USA"])));
        assert_eq!(owned.custodian(), Some("USA"));

        let joint = Ownership::Joint {
            owners: s(&["USA", "KOR"]),
        };
        assert_eq!(joint.owners(), Some(s(&["USA", "KOR"])));
        assert_eq!(joint.custodian(), None); // Joint has no single custodian

        let cf = Ownership::ConcealedForeign {
            custodian: "USA".into(),
        };
        assert_eq!(cf.owners(), None); // owners unknowable
        assert_eq!(cf.custodian(), Some("USA"));
    }

    #[test]
    fn is_wellformed_by_variant() {
        // Owned: exactly one trigraph owner.
        assert!(Ownership::Owned {
            owner: "USA".into()
        }
        .is_wellformed());
        assert!(!Ownership::Owned {
            owner: String::new()
        }
        .is_wellformed()); // sentinel
        assert!(!Ownership::Owned {
            owner: "usa".into()
        }
        .is_wellformed()); // non-trigraph
                           // Joint: ≥2 trigraph co-owners.
        assert!(Ownership::Joint {
            owners: s(&["USA", "KOR"])
        }
        .is_wellformed());
        assert!(Ownership::Joint {
            owners: s(&["USA", "KOR", "JPN"])
        }
        .is_wellformed());
        assert!(!Ownership::Joint {
            owners: s(&["USA"])
        }
        .is_wellformed()); // singleton
        assert!(!Ownership::Joint {
            owners: BTreeSet::new()
        }
        .is_wellformed()); // empty
        assert!(!Ownership::Joint {
            owners: s(&["USA", "kor"])
        }
        .is_wellformed()); // non-trigraph member
                           // ConcealedForeign: trigraph custodian.
        assert!(Ownership::ConcealedForeign {
            custodian: "DEU".into()
        }
        .is_wellformed());
        assert!(!Ownership::ConcealedForeign {
            custodian: String::new()
        }
        .is_wellformed());
    }

    #[test]
    fn same_frame_requires_identical_ownership() {
        let a = Ownership::Owned {
            owner: "USA".into(),
        };
        assert!(a.same_frame(&Ownership::Owned {
            owner: "USA".into()
        }));
        assert!(!a.same_frame(&Ownership::Owned {
            owner: "DEU".into()
        }));
        assert!(!a.same_frame(&Ownership::Joint {
            owners: s(&["USA", "KOR"])
        }));
        assert!(!a.same_frame(&Ownership::ConcealedForeign {
            custodian: "USA".into()
        }));
    }

    #[test]
    fn joint_invariant_two_or_more() {
        assert!(matches!(
            Ownership::joint_from(s(&["USA"])),
            Ownership::Owned { .. }
        ));
        assert!(matches!(
            Ownership::joint_from(s(&["USA", "KOR"])),
            Ownership::Joint { .. }
        ));
        // empty owner set → the Owned{""} sentinel (rejected downstream at gate 4
        // is_trigraph; this test kills the empty-arm mutant per the T1 0-missed gate)
        assert_eq!(
            Ownership::joint_from(BTreeSet::new()),
            Ownership::Owned {
                owner: String::new()
            }
        );
    }

    #[test]
    fn base_set_by_variant() {
        assert_eq!(
            Ownership::Owned {
                owner: "USA".into()
            }
            .base_set(),
            s(&["USA"])
        );
        assert_eq!(
            Ownership::Joint {
                owners: s(&["USA", "KOR"])
            }
            .base_set(),
            s(&["USA", "KOR"])
        );
        // ConcealedForeign baseline is the custodian (spec §2.1 / V2 §4.e)
        assert_eq!(
            Ownership::ConcealedForeign {
                custodian: "USA".into()
            }
            .base_set(),
            s(&["USA"])
        );
    }
}
