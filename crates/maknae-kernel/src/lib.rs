//! maknae-kernel — PRIVILEGED trust-plane logic library (the PDP call site, six KLC
//! hooks, egress enforcement, config boot). Thin main in bins/maknaed. MUST NOT be
//! reachable from bins/maknae (spec §3 P1). As of #77 the per-request PDP is WIRED
//! (boot_gate constructs it; handle() decides every request through the seam; reads
//! and writes are subject-side attempts); KLC hooks/egress remain gated on ADR-0005/0007/0008.
mod authz;
mod blocking_guard;
mod boot;
mod boot_gate;
mod ceiling_authz;
pub mod classification;
mod composition;
mod diag;
mod egress;
mod egress_socket;
mod groupres;
mod handler;
pub mod identity_report;
mod mutation;
mod mutation_exchange;
mod posture;
mod provider_choice;
pub mod reload;
mod run;
mod uid_gate;
pub mod vocabulary;
pub use authz::*;
pub use blocking_guard::BLOCKING_BREAKER_MAX_IN_FLIGHT;
pub use boot::{boot, BootConfig};
pub use boot_gate::{
    authz_boot_gate, authz_policy_source, classify_bounds_load_error, egress_bounds_boot_gate,
    AuthzBootRefusal, EgressBoundsRefusal,
};
pub use ceiling_authz::CeilingAuthorizer;
pub use composition::Composition;
pub use egress::{
    admitted_reply, outcome_for_failure, production_egress, production_egress_with, reply_capacity,
    reply_text_length, unavailable_egress, DurableEgressIntent, Egress, EgressBootRefusal,
    EgressFailure, EgressReply, EgressRequest, ReplyRefusal, SendOutcome, Unavailable,
    EGRESS_MAX_REPLY_FRAME_BYTES, EGRESS_USER,
};
pub use egress_socket::SocketEgress;
pub use groupres::*;
pub use handler::{
    admitted_user_for_test, build_authz_request, build_whoami, dispatch_verb, is_filesystem_verb,
    may_respond, serve_outcome_to_exit_code, Dispatch, ServeOutcome, KERNEL_ACTIONS,
};
pub use mutation::AttemptCaps;
pub use mutation_exchange::{MutationExchange, PendingReport, ReportError};
pub use posture::{
    determine, CredentialSource, Posture, PostureMarker, MECHANISM_KEYCHAIN, MECHANISM_TPM2,
};
pub use provider_choice::{
    admit_choice, provider_authority, AdmittedChoice, ChoiceRefusal, ProviderAuthority,
};
pub use run::{
    accept_loop, handle, handle_with_attempt_caps, run, ConfigView, Conn, KernelGraphStatus,
    PlaneAccept, WhereCtx, MAX_SUBJECT_USER_BYTES,
};

#[used]
pub static PRIVILEGED_MARKER: &[u8] = b"PRIVILEGED_MAKNAE_KERNEL";
