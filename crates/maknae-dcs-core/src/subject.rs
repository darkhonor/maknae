//! Subject (principal) attributes and LDC affiliation predicates.
//!
//! The subject is principal-polymorphic: a human operator or an LLM model
//! endpoint — `decide()` treats both identically (no bypass by kind). Subject
//! context is kernel-minted (ADR-0014); this crate consumes it as data.

use crate::policy::Classification;
use std::collections::{BTreeMap, BTreeSet};

/// Employment/agency affiliation for Limited Dissemination Controls.
/// Affiliation is NOT nationality and grants no releasability. INTERNAL
/// predicate currency (spec §2.4): `affiliation_satisfies` reasons over it;
/// the public `Subject` attribute is `Employment`, bridged via
/// `Employment::to_affiliation`. Retires when the Employment predicates land
/// in Stage 5 (plan Task 5 disclosed deviation from spec §2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Affiliation {
    UsGovernment,
    ClearedContractor,
    Foreign,
}

/// The richer public employment attribute (spec §2.4, #29). Supersedes
/// `Affiliation` as the `Subject` attribute; the SLTT/consultant/grantee
/// predicate asymmetries are Stage 5. Stage 1 bridges to `Affiliation` for the
/// unchanged gate-3 logic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Employment {
    FederalCivilian,
    ArmedForces,
    Sltt,
    Contractor,
    Foreign,
}

impl Employment {
    /// Stage-1 compat bridge to the v1 `Affiliation` predicate currency.
    /// FederalCivilian|ArmedForces → UsGovernment; Sltt → UsGovernment
    /// (NARROWED in Stage 5 when the NOCON/SLTT asymmetry lands); Contractor →
    /// ClearedContractor; Foreign → Foreign.
    pub fn to_affiliation(self) -> Affiliation {
        match self {
            Employment::FederalCivilian | Employment::ArmedForces | Employment::Sltt => {
                Affiliation::UsGovernment
            }
            Employment::Contractor => Affiliation::ClearedContractor,
            Employment::Foreign => Affiliation::Foreign,
        }
    }
}

/// A principal's security attributes. No `Default` — there is no
/// access-granting default subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject {
    pub clearance: Classification,
    /// Nation trigraph, matched against eligible nations.
    pub nationality: String,
    /// tag → held values (containment tags: SCI/SAP/CUI-cat read-ins).
    pub read_ins: BTreeMap<String, BTreeSet<String>>,
    /// Non-decomposable coalition tokens held (kernel-minted; a distinct
    /// namespace from nation trigraphs — asserting a trigraph here grants
    /// nothing).
    pub coalition_memberships: BTreeSet<String>,
    /// Public employment attribute (#29); bridged to `Affiliation` at gate 3.
    pub employment: Employment,
    /// List-control memberships (#30): DL/NODIS/DISTRO-F named-reader lists the
    /// subject belongs to. Consumed at decide-time in Stage 5.
    pub list_memberships: BTreeSet<String>,
    /// Need-to-know tokens the subject may assert as a purpose.
    pub purposes: BTreeSet<String>,
}

/// LDC predicate resolution for `RestrictivePredicate` tags. `controls` = the
/// tag's value set from `ResourceLabel::categories` (e.g. `{"FEDCON"}` or
/// `{"FED_ONLY"}`). ALL controls must be satisfied.
///
/// EMPTY `controls` → `false` (fail closed: `.all()` over ∅ is vacuously true
/// — the classic empty-set polarity inversion; a registered predicate tag with
/// no controls is an UNHANDLED control, not a satisfied one).
///
/// FEDCON: UsGovernment | ClearedContractor. FED_ONLY: UsGovernment only.
/// Unknown control token → `false` (fail closed; the closed list is
/// {FEDCON, FED_ONLY} per ADR-0008, resolving spec §11 Q3).
pub fn affiliation_satisfies(controls: &BTreeSet<String>, affiliation: &Affiliation) -> bool {
    if controls.is_empty() {
        return false;
    }
    controls.iter().all(|control| match control.as_str() {
        "FEDCON" => matches!(
            affiliation,
            Affiliation::UsGovernment | Affiliation::ClearedContractor
        ),
        "FED_ONLY" => matches!(affiliation, Affiliation::UsGovernment),
        _ => false, // unknown control → fail closed
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(xs: &[&str]) -> BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn ldc_predicates() {
        assert!(affiliation_satisfies(
            &set(&["FEDCON"]),
            &Affiliation::UsGovernment
        ));
        assert!(affiliation_satisfies(
            &set(&["FEDCON"]),
            &Affiliation::ClearedContractor
        ));
        assert!(!affiliation_satisfies(
            &set(&["FEDCON"]),
            &Affiliation::Foreign
        ));
        assert!(affiliation_satisfies(
            &set(&["FED_ONLY"]),
            &Affiliation::UsGovernment
        ));
        assert!(!affiliation_satisfies(
            &set(&["FED_ONLY"]),
            &Affiliation::ClearedContractor
        ));
        assert!(!affiliation_satisfies(
            &set(&["BOGUS_CTRL"]),
            &Affiliation::UsGovernment
        )); // unknown → false
        assert!(!affiliation_satisfies(
            &set(&[]),
            &Affiliation::UsGovernment
        )); // EMPTY → false
    }

    #[test]
    fn employment_bridges_to_affiliation() {
        // 5→3 compat mapping keeps the v1 affiliation_satisfies vectors valid
        assert_eq!(
            Employment::FederalCivilian.to_affiliation(),
            Affiliation::UsGovernment
        );
        assert_eq!(
            Employment::ArmedForces.to_affiliation(),
            Affiliation::UsGovernment
        );
        assert_eq!(Employment::Sltt.to_affiliation(), Affiliation::UsGovernment);
        assert_eq!(
            Employment::Contractor.to_affiliation(),
            Affiliation::ClearedContractor
        );
        assert_eq!(Employment::Foreign.to_affiliation(), Affiliation::Foreign);
        // FEDCON admits Contractor; FED_ONLY does not — via the bridge
        assert!(affiliation_satisfies(
            &set(&["FEDCON"]),
            &Employment::Contractor.to_affiliation()
        ));
        assert!(!affiliation_satisfies(
            &set(&["FED_ONLY"]),
            &Employment::Contractor.to_affiliation()
        ));
    }
}
