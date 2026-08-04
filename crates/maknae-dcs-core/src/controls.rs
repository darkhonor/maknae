//! Controls axis (#27): the closed set of dissemination controls as a
//! PRODUCT-OF-CHAINS lattice (spec §2.3). Four 3-element precedence chains ×
//! the powerset of the rest. The join is TOTAL, ASSOCIATIVE, VALIDITY-AGNOSTIC
//! — mutual-exclusion rejection lives in validate_label (Stage 2/4), never here.
use std::collections::BTreeSet;

/// The closed set of every dissemination control the §2.6 tables reference
/// (spec §2.3). Adding a control is a deliberate ADR amendment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ControlMarking {
    Orcon,
    OrconUsGov,
    Relido,
    Nodis,
    Exdis,
    Imcon,
    Rsen,
    NoEgress,
    OperatorOnly,
    Fisa,
    Propin,
    Dsen,
    Les,
    LesNf,
    Ssi,
    Sbu,
    SbuNf,
    Displayed,
}

/// The four precedence chains: (dominant, dominated). Dominant = MORE restrictive.
const CHAINS: [(ControlMarking, ControlMarking); 4] = [
    (ControlMarking::Orcon, ControlMarking::OrconUsGov),
    (ControlMarking::Nodis, ControlMarking::Exdis),
    (ControlMarking::LesNf, ControlMarking::Les),
    (ControlMarking::SbuNf, ControlMarking::Sbu),
];

impl ControlMarking {
    /// Which chain this marking belongs to (index), or None if non-chain.
    fn chain(self) -> Option<usize> {
        CHAINS.iter().position(|&(d, s)| d == self || s == self)
    }
}

/// A canonical set of controls (each chain reduced to its MAX present element).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Controls(BTreeSet<ControlMarking>);

impl Controls {
    /// Build a canonical Controls: each chain keeps at most its MAX element.
    pub fn from_set(raw: BTreeSet<ControlMarking>) -> Controls {
        Controls(canonicalize(raw))
    }

    /// The empty control set (the ∨ identity for this axis).
    pub fn empty() -> Controls {
        Controls(BTreeSet::new())
    }

    /// The canonical underlying set.
    pub fn as_set(&self) -> &BTreeSet<ControlMarking> {
        &self.0
    }

    /// `a ⊑ b`: per-chain rank(a) <= rank(b) AND non-chain a ⊆ b. Total boolean
    /// (v1-faithful: incomparable → false both directions, never a panic).
    pub fn le(&self, other: &Controls) -> bool {
        for &(dominant, dominated) in &CHAINS {
            if chain_rank(&self.0, dominant, dominated) > chain_rank(&other.0, dominant, dominated)
            {
                return false;
            }
        }
        self.0
            .iter()
            .filter(|m| m.chain().is_none())
            .all(|m| other.0.contains(m))
    }

    /// `a ∨ b`: per-chain max + non-chain union, canonicalized. TOTAL — never
    /// returns Option, never validity-checks.
    pub fn join(&self, other: &Controls) -> Controls {
        let mut raw: BTreeSet<ControlMarking> = BTreeSet::new();
        for m in self.0.iter().chain(other.0.iter()) {
            if m.chain().is_none() {
                raw.insert(*m);
            }
        }
        for &(dominant, dominated) in &CHAINS {
            match chain_rank(&self.0, dominant, dominated)
                .max(chain_rank(&other.0, dominant, dominated))
            {
                2 => {
                    raw.insert(dominant);
                }
                1 => {
                    raw.insert(dominated);
                }
                _ => {}
            }
        }
        Controls(canonicalize(raw))
    }
}

/// Rank of a chain within a raw set: 2 = dominant present, 1 = dominated
/// present, 0 = absent.
fn chain_rank(
    set: &BTreeSet<ControlMarking>,
    dominant: ControlMarking,
    dominated: ControlMarking,
) -> usize {
    if set.contains(&dominant) {
        2
    } else if set.contains(&dominated) {
        1
    } else {
        0
    }
}

fn canonicalize(raw: BTreeSet<ControlMarking>) -> BTreeSet<ControlMarking> {
    let mut out: BTreeSet<ControlMarking> = BTreeSet::new();
    for m in &raw {
        if m.chain().is_none() {
            out.insert(*m);
        }
    }
    for &(dominant, dominated) in &CHAINS {
        match chain_rank(&raw, dominant, dominated) {
            2 => {
                out.insert(dominant);
            }
            1 => {
                out.insert(dominated);
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ControlMarking::*;
    fn c(items: &[ControlMarking]) -> Controls {
        Controls::from_set(items.iter().copied().collect())
    }
    fn set(items: &[ControlMarking]) -> BTreeSet<ControlMarking> {
        items.iter().copied().collect()
    }

    #[test]
    fn canonical_form_keeps_chain_max_only() {
        assert_eq!(c(&[Orcon, OrconUsGov]).as_set(), &set(&[Orcon]));
        assert_eq!(c(&[Nodis, Exdis]).as_set(), &set(&[Nodis]));
        assert_eq!(c(&[LesNf, Les]).as_set(), &set(&[LesNf]));
        assert_eq!(c(&[SbuNf, Sbu]).as_set(), &set(&[SbuNf]));
        // non-chain controls are untouched
        assert_eq!(c(&[Imcon, Rsen]).as_set(), &set(&[Imcon, Rsen]));
    }

    #[test]
    fn order_is_per_chain_rank_plus_nonchain_subset() {
        // {OrconUsGov}(rank 1) ⊑ {Orcon}(rank 2)
        assert!(c(&[OrconUsGov]).le(&c(&[Orcon])));
        assert!(!c(&[Orcon]).le(&c(&[OrconUsGov])));
        // incomparable across chains → both directions false (v1-faithful partial order)
        assert!(!c(&[Orcon]).le(&c(&[Nodis])));
        assert!(!c(&[Nodis]).le(&c(&[Orcon])));
        // non-chain subset
        assert!(c(&[Imcon]).le(&c(&[Imcon, Rsen])));
        // reflexive
        assert!(c(&[Orcon, Imcon]).le(&c(&[Orcon, Imcon])));
    }

    #[test]
    fn join_is_per_chain_max_plus_nonchain_union_and_is_total() {
        assert_eq!(c(&[OrconUsGov]).join(&c(&[Orcon])), c(&[Orcon]));
        // non-chain union — INCLUDING a pair validate_label would later reject
        // (Relido + Displayed). The LATTICE join is validity-agnostic: yields Some.
        assert_eq!(c(&[Relido]).join(&c(&[Displayed])), c(&[Relido, Displayed]));
        // idempotent, commutative
        assert_eq!(c(&[Orcon]).join(&c(&[Orcon])), c(&[Orcon]));
        assert_eq!(
            c(&[Orcon]).join(&c(&[Nodis])),
            c(&[Nodis]).join(&c(&[Orcon]))
        );
        // empty is the identity
        assert_eq!(c(&[Orcon]).join(&Controls::empty()), c(&[Orcon]));
    }

    #[test]
    fn absorption_and_upper_bound() {
        // a ⊑ a∨b, and a∨(a∨b) = a∨b
        let a = c(&[OrconUsGov, Imcon]);
        let b = c(&[Nodis]);
        let ab = a.join(&b);
        assert!(a.le(&ab));
        assert!(b.le(&ab));
        assert_eq!(a.join(&ab), ab);
    }

    #[test]
    fn associativity_holds_over_all_control_combinations() {
        let atoms = [Orcon, OrconUsGov, Nodis, Exdis, Imcon, Relido, Displayed];
        for &x in &atoms {
            for &y in &atoms {
                for &z in &atoms {
                    let l = c(&[x]).join(&c(&[y])).join(&c(&[z]));
                    let r = c(&[x]).join(&c(&[y]).join(&c(&[z])));
                    assert_eq!(l, r, "assoc {x:?} {y:?} {z:?}");
                }
            }
        }
    }
}
