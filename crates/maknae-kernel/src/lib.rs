//! maknae-kernel — PRIVILEGED trust-plane logic library (PDP, six KLC hooks, egress
//! enforcement, boot lake classification-match gate). Thin main in bins/maknaed.
//! MUST NOT be reachable from bins/maknae (spec §3 P1). Body gated on ADR-0005/0007/0008.
#[used]
pub static PRIVILEGED_MARKER: &[u8] = b"PRIVILEGED_MAKNAE_KERNEL";
