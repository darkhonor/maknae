//! SPIF (Security Policy Information File) input types: policy-scoped classification
//! levels, typed category kinds, and tetragraph decomposition tables.
//!
//! The SPIF is a consumed Tier-0 input (generation is out of scope, spec §10).
//! Every lookup is total: unknown levels, tags, and tokens resolve to `None` /
//! `Unknown`, which every caller treats as deny / grants-nothing.

use std::collections::{BTreeMap, BTreeSet};

/// Identifier of the security policy authority a classification is scoped to
/// (e.g. `"US"`, `"AUS"`). Levels from different policies are never comparable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyId(pub String);

/// A policy-scoped classification level. Deliberately NO derived `Ord`:
/// ordering exists ONLY via [`Spif::rank`], which fails closed on unknown
/// levels and cross-policy comparisons.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classification {
    pub policy: PolicyId,
    pub name: String,
}

/// The satisfaction rule for a security category tag, declared by the SPIF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CategoryKind {
    /// Containment: subject read-ins ⊇ resource values (SCI/SAP/CUI-cat).
    Restrictive,
    /// Attribute-predicate over Subject fields (LDCs: FEDCON/FED_ONLY).
    RestrictivePredicate,
    /// Membership-shaped. At MVP releasability is the ONLY permissive
    /// dimension and lives in the dedicated typed field — a Permissive tag
    /// appearing in a label's category map is unhandled → decide() denies
    /// `Indeterminate` (fail closed).
    Permissive,
    /// Ignored by decide(); carried for handling.
    Informative,
}

/// Result of decomposing a coalition tetragraph token against the SPIF tables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TetraExpansion {
    /// Decomposable: expands to an enumerated set of nation trigraphs.
    Nations(BTreeSet<String>),
    /// Registered but non-decomposable (classified membership): satisfiable
    /// only by a subject holding the coalition attribute directly.
    NonDecomposable,
    /// Not registered — grants nothing, everywhere.
    Unknown,
}

/// A compiled security policy: level order, category kinds, tetragraph tables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spif {
    policy: PolicyId,
    levels: Vec<String>,
    categories: BTreeMap<String, CategoryKind>,
    /// `Some(nations)` = decomposable; `None` = registered non-decomposable.
    tetragraphs: BTreeMap<String, Option<BTreeSet<String>>>,
}

impl Spif {
    pub fn builder(policy: &str) -> SpifBuilder {
        SpifBuilder {
            policy: PolicyId(policy.to_string()),
            levels: Vec::new(),
            categories: BTreeMap::new(),
            tetragraphs: BTreeMap::new(),
        }
    }

    /// Rank of a classification in this policy's level order.
    /// `None` = unknown level or wrong policy → caller denies `Indeterminate`.
    pub fn rank(&self, c: &Classification) -> Option<usize> {
        if c.policy != self.policy {
            return None;
        }
        self.levels.iter().position(|l| *l == c.name)
    }

    /// Satisfaction kind for a category tag.
    /// `None` = unknown tag → caller denies `Indeterminate`.
    pub fn category_kind(&self, tag: &str) -> Option<CategoryKind> {
        self.categories.get(tag).copied()
    }

    pub fn expand_tetra(&self, token: &str) -> TetraExpansion {
        match self.tetragraphs.get(token) {
            Some(Some(nations)) => TetraExpansion::Nations(nations.clone()),
            Some(None) => TetraExpansion::NonDecomposable,
            None => TetraExpansion::Unknown,
        }
    }

    pub fn policy(&self) -> &PolicyId {
        &self.policy
    }
}

pub struct SpifBuilder {
    policy: PolicyId,
    levels: Vec<String>,
    categories: BTreeMap<String, CategoryKind>,
    tetragraphs: BTreeMap<String, Option<BTreeSet<String>>>,
}

/// True iff `token` has the shape of a bare nation trigraph
/// (exactly 3 uppercase ASCII characters).
pub(crate) fn is_trigraph(token: &str) -> bool {
    token.len() == 3 && token.bytes().all(|b| b.is_ascii_uppercase())
}

impl SpifBuilder {
    pub fn levels(mut self, ordered_low_to_high: &[&str]) -> Self {
        self.levels = ordered_low_to_high.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn category(mut self, tag: &str, kind: CategoryKind) -> Self {
        self.categories.insert(tag.to_string(), kind);
        self
    }

    /// Register a coalition tetragraph. `None` members = non-decomposable.
    /// `Some(&[])` is SKIPPED (an empty coalition is not a coalition), and a
    /// 3-uppercase-ASCII token is SKIPPED (it would collide with the trigraph
    /// nation namespace) — both then resolve to `TetraExpansion::Unknown`.
    pub fn tetragraph(mut self, token: &str, members: Option<&[&str]>) -> Self {
        if is_trigraph(token) {
            return self;
        }
        if let Some(m) = members {
            if m.is_empty() {
                return self;
            }
        }
        self.tetragraphs.insert(
            token.to_string(),
            members.map(|m| m.iter().map(|s| s.to_string()).collect()),
        );
        self
    }

    pub fn build(self) -> Spif {
        Spif {
            policy: self.policy,
            levels: self.levels,
            categories: self.categories,
            tetragraphs: self.tetragraphs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_orders_levels_and_rejects_unknown_and_wrong_policy() {
        let spif = Spif::builder("US")
            .levels(&["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"])
            .build();
        let s = Classification {
            policy: PolicyId("US".into()),
            name: "SECRET".into(),
        };
        let u = Classification {
            policy: PolicyId("US".into()),
            name: "UNCLASSIFIED".into(),
        };
        let (rs, ru) = (spif.rank(&s).unwrap(), spif.rank(&u).unwrap());
        assert!(rs > ru); // SECRET above UNCLASSIFIED
        assert_eq!(
            spif.rank(&Classification {
                policy: PolicyId("US".into()),
                name: "BOGUS".into()
            }),
            None
        ); // unknown level
        assert_eq!(
            spif.rank(&Classification {
                policy: PolicyId("AUS".into()),
                name: "SECRET".into()
            }),
            None
        ); // wrong policy
    }

    #[test]
    fn category_kinds_include_predicate() {
        let spif = Spif::builder("US")
            .category("SCI", CategoryKind::Restrictive)
            .category("LDC", CategoryKind::RestrictivePredicate)
            .build();
        assert_eq!(spif.category_kind("SCI"), Some(CategoryKind::Restrictive));
        assert_eq!(
            spif.category_kind("LDC"),
            Some(CategoryKind::RestrictivePredicate)
        );
        assert_eq!(spif.category_kind("NOPE"), None);
    }

    #[test]
    fn tetragraph_decomposition() {
        let spif = Spif::builder("US")
            .tetragraph("CFCK", Some(&["USA", "KOR"]))
            .tetragraph("NKIC", None)
            .build();
        assert!(
            matches!(spif.expand_tetra("CFCK"), TetraExpansion::Nations(n) if n.contains("KOR"))
        );
        assert!(matches!(
            spif.expand_tetra("NKIC"),
            TetraExpansion::NonDecomposable
        ));
        assert!(matches!(spif.expand_tetra("ZZZZ"), TetraExpansion::Unknown));
    }

    #[test]
    fn builder_skips_degenerate_tetragraph_registrations() {
        // pinned contracts — trigraph-shaped tokens and empty-member coalitions never register
        let spif = Spif::builder("US")
            .tetragraph("USA", None) // 3-uppercase-ASCII: collides with nation namespace → skipped
            .tetragraph("EMTY", Some(&[])) // empty member list: not a coalition → skipped
            .build();
        assert!(matches!(spif.expand_tetra("USA"), TetraExpansion::Unknown));
        assert!(matches!(spif.expand_tetra("EMTY"), TetraExpansion::Unknown));
    }
}
