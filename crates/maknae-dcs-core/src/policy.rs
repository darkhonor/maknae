//! SPIF (Security Policy Information File) input types: policy-scoped classification
//! levels and typed category kinds. Coalition tetragraph decomposition is now a
//! GLOBAL, versioned data fact (`registry::expand_coalition`), not per-SPIF (D1).
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
    /// List-controlled (#30): access gated by named-reader list membership
    /// (DL/NODIS/DISTRO-F). decide() semantics land Stage 5; in Stage 1 an
    /// unhandled `ListControlled` tag → `Indeterminate` (fail closed).
    ListControlled,
}

/// Result of decomposing a coalition tetragraph token against the GLOBAL
/// coalition registry (#26 expand-or-deny). Membership is a versioned data fact,
/// not policy-context-dependent — every registered coalition decomposes to
/// nation trigraphs (in-memory, never leaving the engine) or the token is
/// `Unknown` (grants nothing → the caller denies). There is no non-decomposable
/// arm: a coalition the engine cannot expand is a coalition it cannot decide on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TetraExpansion {
    /// Decomposable: expands to an enumerated set of nation trigraphs.
    Nations(BTreeSet<String>),
    /// Not registered — grants nothing, everywhere.
    Unknown,
}

/// A compiled security policy: level order and category kinds. (Coalition
/// tetragraphs decompose via the global registry, not per-SPIF tables — D1.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spif {
    policy: PolicyId,
    levels: Vec<String>,
    categories: BTreeMap<String, CategoryKind>,
    /// FGI `home_nation` gate (#25/#31): the policy's own nation. `None` until
    /// a policy declares it. Consumed by the OwnerConsent trigger in Stage 5.
    home_nation: Option<String>,
    /// Tetragraphs a SPIF flags as expandable for banner roll-up (#31).
    expandable: BTreeSet<String>,
}

impl Spif {
    pub fn builder(policy: &str) -> SpifBuilder {
        SpifBuilder {
            policy: PolicyId(policy.to_string()),
            levels: Vec::new(),
            categories: BTreeMap::new(),
            home_nation: None,
            expandable: BTreeSet::new(),
        }
    }

    /// The policy's own nation (#25 FGI `home_nation` gate), if declared.
    pub fn home_nation(&self) -> Option<&str> {
        self.home_nation.as_deref()
    }

    /// Whether `token` is flagged expandable for banner roll-up (#31).
    pub fn is_expandable_for_rollup(&self, token: &str) -> bool {
        self.expandable.contains(token)
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

    /// Decompose a coalition tetragraph via the GLOBAL registry (#26, D1).
    /// Coalition membership is not policy-context-dependent, so this ignores
    /// `self` and reads `registry::expand_coalition`. A registered coalition →
    /// its member nations (in-memory expand); anything else → `Unknown`.
    pub fn expand_tetra(&self, token: &str) -> TetraExpansion {
        match crate::registry::expand_coalition(token) {
            Some(members) => {
                TetraExpansion::Nations(members.iter().map(|s| s.to_string()).collect())
            }
            None => TetraExpansion::Unknown,
        }
    }

    pub fn policy(&self) -> &PolicyId {
        &self.policy
    }
}

#[derive(Clone, Debug)]
pub struct SpifBuilder {
    policy: PolicyId,
    levels: Vec<String>,
    categories: BTreeMap<String, CategoryKind>,
    home_nation: Option<String>,
    expandable: BTreeSet<String>,
}

/// True iff `token` has the shape of a bare nation trigraph
/// (exactly 3 uppercase ASCII characters). Exported so consumers (the kernel)
/// can pre-validate a label's `origin` before calling `⊑`/`join`.
pub fn is_trigraph(token: &str) -> bool {
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

    /// Declare the policy's own nation (#25 FGI `home_nation` gate).
    pub fn home_nation(mut self, nation: &str) -> Self {
        self.home_nation = Some(nation.to_string());
        self
    }

    /// Flag a tetragraph as expandable for banner roll-up (#31).
    pub fn expandable(mut self, token: &str) -> Self {
        self.expandable.insert(token.to_string());
        self
    }

    pub fn build(self) -> Spif {
        Spif {
            policy: self.policy,
            levels: self.levels,
            categories: self.categories,
            home_nation: self.home_nation,
            expandable: self.expandable,
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
    fn stage1_spif_scaffolding() {
        // ListControlled round-trips the builder. (The per-SPIF CUI `registry`
        // field is RETIRED — D3: CUI recognition is now the GLOBAL
        // `registry::is_cui_category` over `data/cui-registry.json`.)
        let spif = Spif::builder("US")
            .category("ATTY", CategoryKind::ListControlled)
            .home_nation("USA")
            .expandable("FVEY")
            .build();
        assert_eq!(
            spif.category_kind("ATTY"),
            Some(CategoryKind::ListControlled)
        );
        assert_eq!(spif.home_nation(), Some("USA"));
        assert!(spif.is_expandable_for_rollup("FVEY"));
        assert!(!spif.is_expandable_for_rollup("NATO")); // unflagged → false

        // defaults: no home_nation, nothing expandable
        let bare = Spif::builder("US").build();
        assert_eq!(bare.home_nation(), None);
        assert!(!bare.is_expandable_for_rollup("FVEY"));
    }

    #[test]
    fn expand_tetra_reads_global_registry() {
        // D1: expand_tetra ignores per-SPIF state and reads the GLOBAL coalition
        // registry. A registered coalition decomposes to its member nations; an
        // unregistered token (or a trigraph-shaped one) is Unknown.
        let spif = Spif::builder("US").build();
        match spif.expand_tetra("UNCK") {
            TetraExpansion::Nations(n) => {
                assert_eq!(n.len(), 18);
                assert!(n.contains("ZAF")); // CJCSI 2015.01A member
                assert!(!n.contains("KOR")); // host nation, not a member
            }
            other => panic!("expected Nations, got {other:?}"),
        }
        assert!(matches!(
            spif.expand_tetra("FVEY"),
            TetraExpansion::Nations(_)
        ));
        assert!(matches!(spif.expand_tetra("ZZZZ"), TetraExpansion::Unknown)); // unregistered
        assert!(matches!(spif.expand_tetra("USA"), TetraExpansion::Unknown)); // a trigraph is not a coalition
    }

    // D2: the builder-time member-shape guards (`builder_filters_non_trigraph_members`,
    // `builder_skips_degenerate_tetragraph_registrations`) are RETIRED with the
    // `SpifBuilder::tetragraph` mechanism — coalition membership is now a global
    // versioned data fact whose validity is enforced at BUILD time (build.rs
    // cross-validates every member against ISO-3166; a malformed member FAILS
    // THE BUILD). The runtime widen-guard's mutation-kill role is now the
    // build-validation, documented in `tests/registry_compile.rs`.
}
