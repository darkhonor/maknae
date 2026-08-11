//! maknae-kernel — PRIVILEGED trust-plane logic library (PDP, six KLC hooks, egress
//! enforcement, config boot). Thin main in bins/maknaed. MUST NOT be reachable from
//! bins/maknae (spec §3 P1). The remaining body (PDP/hooks/egress) is gated on
//! ADR-0005/0007/0008; [`boot`] (config boot) is the first landed piece.
mod authz;
mod boot;
mod groupres;
mod handler;
mod run;
pub use authz::*;
pub use boot::{boot, BootConfig};
pub use groupres::*;
pub use handler::{
    build_whoami, dispatch_verb, may_respond, serve_outcome_to_exit_code, Dispatch, ServeOutcome,
};
pub use run::{accept_loop, handle, run, Conn, PlaneAccept, WhereCtx};

#[used]
pub static PRIVILEGED_MARKER: &[u8] = b"PRIVILEGED_MAKNAE_KERNEL";
