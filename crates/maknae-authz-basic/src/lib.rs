//! maknae-authz-basic — the RBAC PDP backend behind the `maknae-security`
//! seam (#85). Four code-defined roles (`admin`/`user`/`guest`/`adversary`)
//! decide four-valued verdicts from `authz.yaml` (+ the additive `bindings:`
//! key), per request, deny-by-default, fail-closed. Spec:
//! `~/claude-memory/maknae/specs/2026-08-26-maknae-authz-basic-design.md`.
#![forbid(unsafe_code)]

mod binding;
mod decide;
mod role;

/// P2 artifact-witness marker: this is a PRIVILEGED trust-plane crate,
/// forbidden from the untrusted client binary (P1 gate keys on
/// `PRIVILEGED_CRATES`; this marker is the P2 witness that a shipped
/// artifact actually links it).
#[used]
pub static PRIVILEGED_MARKER: &[u8] = b"PRIVILEGED_MAKNAE_AUTHZ_BASIC";
