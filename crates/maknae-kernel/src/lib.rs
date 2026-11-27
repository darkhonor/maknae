//! maknae-kernel — PRIVILEGED trust-plane logic library (the PDP call site, six KLC
//! hooks, egress enforcement, config boot). Thin main in bins/maknaed. MUST NOT be
//! reachable from bins/maknae (spec §3 P1). As of #77 the per-request PDP is WIRED
//! (boot_gate constructs it; handle() decides every request through the seam; reads
//! and writes are subject-side attempts); KLC hooks/egress remain gated on ADR-0005/0007/0008.
mod authz;
pub mod baseline;
pub mod baseline_check;
mod blocking_guard;
mod board;
mod board_store;
mod board_verbs;
mod boot;
mod boot_gate;
mod ceiling_authz;
pub mod classification;
mod composition;
mod containment;
mod conversation;
mod deployment;
mod diag;
mod egress;
mod egress_socket;
mod enrollment;
mod groupres;
mod handler;
mod host_env;
pub mod identity_report;
mod listing;
pub mod live;
mod membership;
mod mutation;
mod mutation_exchange;
mod notice;
mod partition_authz;
mod posture;
mod provider_choice;
mod reach;
pub mod reload;
mod run;
mod sensitive_authz;
mod session;
pub mod session_facts;
pub mod sync;
mod task;
pub mod task_store;
mod task_verbs;
mod tool_call;
mod tool_launch;
mod uid_gate;
pub mod vocabulary;
mod workspace;
pub use authz::*;
pub use blocking_guard::BLOCKING_BREAKER_MAX_IN_FLIGHT;
pub use board::{BoardRefusal, BoardStore};
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub use board::{BoardSeam, Caps, Lifted};
pub use board_store::{
    BoardFinding, BoardKey, HeldFor, LabelValue, PostLabels, ReadPlan, Report, Settings, Stored,
    BOARD, BOARD_RECORD_MAX, BOARD_RETENTION,
};
pub use board_verbs::{BoardSwitches, ConfiguredSwitches};
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub use board_verbs::{FixedSwitches, READ_ROUNDS};
pub use boot::{boot, read_files, BootConfig};
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub use boot::{boot_as_owner, read_files_as_owner};
pub use boot_gate::{
    authz_boot_gate, authz_policy_source, classify_bounds_load_error, egress_bounds_boot_gate,
    AuthzBootRefusal, EgressBoundsRefusal,
};
pub use ceiling_authz::CeilingAuthorizer;
pub use composition::{CatalogNow, Composition};
pub use conversation::chain::ChainHead;
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub use conversation::dir_store::DirStore;
pub use conversation::facts::{ConversationFacts, FactState};
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub use conversation::mem_store::MemStore;
pub use conversation::record::{ConversationRecord, Provenance};
pub use conversation::store::{
    ConversationStore, Page, Scan, StoreError as ConversationStoreError,
};
pub use egress::{
    admitted_reply, outcome_for_failure, production_egress, production_egress_with, reply_capacity,
    reply_text_length, unavailable_egress, DurableEgressIntent, Egress, EgressBootRefusal,
    EgressFailure, EgressReply, EgressRequest, ReplyRefusal, SendOutcome, Unavailable,
    EGRESS_MAX_REPLY_FRAME_BYTES, EGRESS_USER,
};
pub use egress_socket::{
    no_reach, production_reach, production_reach_with, reach_socket_wait, ReachEgress,
    ReachOutcome, SocketEgress, Unanswered,
};
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub use enrollment::{Boarding, Containing, FixedEnrollment, Unresolving};
pub use enrollment::{EnrollmentView, Load, SnapshotEnrollment};
pub use groupres::*;
pub use handler::{
    admits, admitted_user_for_test, after_drain, agent_class, build_authz_request, build_whoami,
    client_class, dispatch_verb, is_filesystem_verb, may_respond, may_stop,
    serve_outcome_to_exit_code, Admission, ChannelClass, Dispatch, Drain, ServeOutcome, Stamp,
    APPLY_BY_RESTART_EXIT_CODE, KERNEL_ACTIONS,
};
pub use live::{LiveConfig, LiveValues};
pub use mutation::AttemptCaps;
pub use mutation_exchange::{MutationExchange, PendingReport, ReportError};
pub use posture::{
    determine, CredentialSource, Posture, PostureMarker, MECHANISM_KEYCHAIN, MECHANISM_TPM2,
};
pub use provider_choice::{
    admit_choice, provider_authority, AdmittedChoice, ChoiceRefusal, KeyOwner, ProviderAuthority,
};
pub use reach::{kernel_reach_permits, ForgeTraits, ReachSettings};
pub use run::{
    accept_loop, handle, handle_with_attempt_caps, run, AcceptAnswer, AdminOps, AgentAdmission,
    BaselineOps, BoxFuture, ConfigView, Conn, ContainAnswer, ContainRequest, ContainmentOps,
    ContainmentStatus, Corrective, HeldOp, HeldRequest, KernelGraphStatus, PlaneAccept,
    ReleaseRequest, WhereCtx, MAX_SUBJECT_USER_BYTES,
};
pub use sensitive_authz::SensitiveNow;
pub use sensitive_authz::{sensitive_match, SensitiveMatch};
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub use session::AllowFacts;
pub use session::{Facts, FactsGate, SessionChannel, SessionFacts, SessionRecord};
pub use task::{
    Claimed, Contained, Due, DueFor, Enrolled, GoodStanding, Heartbeat, HeldSelect, HeldTask,
    Notice, PlaneSigner, Reach, ReleasePlan, ReleaseRefusal, Released, Submitter, TaskRefusal,
    TaskSigner, TaskStore, MAX_FOLLOW_UPS_PER_TASK, MAX_HELD_REPORTS_PER_TASKER,
    MAX_LIVE_TASKS_PER_AGENT, MAX_LIVE_TASKS_PER_TASKER_PER_AGENT,
};
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub use task::{TaskObjectForTest, UnverifiedSigner};
pub use task_store::{Clock, RootTasker, SystemClock, TaskRecord, CLAIM_LEASE, REPORT_HOLD};
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub use task_store::{Fail, ManualClock, MemTaskBlobs};

#[used]
pub static PRIVILEGED_MARKER: &[u8] = b"PRIVILEGED_MAKNAE_KERNEL";

#[cfg(test)]
mod test_fixtures;
