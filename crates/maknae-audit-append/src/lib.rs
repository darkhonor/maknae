//! maknae-audit-append — PRIVILEGED trust-plane capability: audit append path.
//! Kernel-plane only (spec §3 P1). MUST NOT be reachable from bins/maknae.
//! `#[used] static` (NOT const): a const inlines to nothing, blinding the P2b symbol scan.
#[used]
pub static PRIVILEGED_MARKER: &[u8] = b"PRIVILEGED_MAKNAE_AUDIT_APPEND";
