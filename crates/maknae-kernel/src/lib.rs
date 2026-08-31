//! maknae-kernel — PRIVILEGED trust-plane logic library (the PDP call site, six KLC
//! hooks, egress enforcement, config boot). Thin main in bins/maknaed. MUST NOT be
//! reachable from bins/maknae (spec §3 P1). As of #77 the per-request PDP is WIRED
//! (boot_gate constructs it; handle() decides every request through the seam and
//! enforces the read PEP); KLC hooks/egress remain gated on ADR-0005/0007/0008.
mod authz;
mod blocking_guard;
mod boot;
mod boot_gate;
mod groupres;
mod handler;
mod posture;
mod run;
pub use authz::*;
pub use boot::{boot, BootConfig};
pub use boot_gate::{authz_boot_gate, AuthzBootRefusal};
pub use groupres::*;
pub use handler::{
    build_whoami, dispatch_verb, may_respond, serve_outcome_to_exit_code, Dispatch, ServeOutcome,
    KERNEL_ACTIONS,
};
pub use posture::{
    determine, CredentialSource, Posture, PostureMarker, MECHANISM_SEP, MECHANISM_TPM2,
};
pub use run::{accept_loop, handle, run, ConfigView, Conn, PlaneAccept, WhereCtx};

#[used]
pub static PRIVILEGED_MARKER: &[u8] = b"PRIVILEGED_MAKNAE_KERNEL";
