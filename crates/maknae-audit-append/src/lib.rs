//! maknae-audit-append — PRIVILEGED trust-plane capability: audit append path.
//! Kernel-plane only (spec §3 P1). MUST NOT be reachable from bins/maknae.
//!
//! Implements ADR-0019: the AU-3/AU-3(1)-complete record schema
//! ([`record`]), deterministic canonical JSON so ADR-0007 signing bolts on
//! later without a format break, per-boot/per-connection session
//! correlation ids ([`session`]), and the fail-closed append-only JSONL
//! sink ([`sink`]) the run-loop (Task 7) drives through the [`AuditEmit`]
//! trait.
//! `#[used] static` (NOT const): a const inlines to nothing, blinding the P2b symbol scan.
#![forbid(unsafe_code)]

mod error;
mod record;
mod session;
mod sink;

pub use error::AuditError;
pub use record::{canonical_json, AuditRecord, Integrity, Outcome, Source, Subject, Where};
pub use session::{Seq, SessionIds};
pub use sink::{AuditEmit, AuditSink};

#[used]
pub static PRIVILEGED_MARKER: &[u8] = b"PRIVILEGED_MAKNAE_AUDIT_APPEND";
