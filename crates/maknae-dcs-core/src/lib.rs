//! maknae-dcs-core — the Maknae confidentiality classification lattice and the
//! pure, total, fail-closed dominance decision `decide(subject, resource, action, purpose, spif)`.
//!
//! Model (ADR-0008 + #26 Stage 2): one ordinal `Classification` + typed
//! categories (restrictive `⊇` / restrictive-predicate / permissive /
//! informative) + releasability (three-state, origin-always-member,
//! intersection-join, a SINGLE nation namespace — coalition tetragraphs
//! decompose to member nations at expansion time, expand-or-deny, and NAF
//! exclusions subtract from the resolved set) + caveats + compilation-level +
//! need-to-know. Deny-by-default; every degenerate input → `Deny`/grants-nothing.
#![forbid(unsafe_code)]

pub mod controls;
pub mod decide;
pub mod label;
pub mod ownership;
pub mod policy;
pub mod registry;
pub mod subject;

pub use controls::{ControlMarking, Controls};
pub use decide::{audit, decide, Action, AuditRecord, Decision, DenyReason, Purpose};
pub use label::{
    derive, obligation_refines, obligations_refine, restrictive_dominates, validate_label,
    validate_rel, Caveat, Disclosure, EligibleNations, LabelInvalidity, Obligation,
    RedisseminationScope, RelValidationError, Releasability, ResourceLabel,
};
pub use ownership::Ownership;
pub use policy::{
    is_trigraph, CategoryKind, Classification, PolicyId, Spif, SpifBuilder, TetraExpansion,
};
pub use subject::{affiliation_satisfies, Affiliation, Employment, Subject};
