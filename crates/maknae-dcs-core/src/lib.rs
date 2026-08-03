//! maknae-dcs-core — the Maknae confidentiality classification lattice and the
//! pure, total, fail-closed dominance decision `decide(subject, resource, action, purpose, spif)`.
//!
//! Model (ADR-0008): one ordinal `Classification` + typed categories
//! (restrictive `⊇` / restrictive-predicate / permissive / informative) +
//! releasability (three-state, origin-always-member, intersection-join,
//! nation/coalition namespaces structurally separate) + caveats +
//! compilation-level + need-to-know. Deny-by-default; every degenerate
//! input → `Deny` / grants-nothing.
#![forbid(unsafe_code)]

pub mod decide;
pub mod label;
pub mod policy;
pub mod subject;

pub use policy::{CategoryKind, Classification, PolicyId, Spif, SpifBuilder, TetraExpansion};
