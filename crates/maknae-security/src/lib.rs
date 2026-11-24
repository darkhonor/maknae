//! maknae-security — the policy-agnostic authorization seam.
//!
//! Zero-dependency narrow waist: the [`Authorizer`] contract, the request /
//! verdict / obligation types, the N-ary composition algorithm ([`combine`]),
//! and the fail-closed [`finalize`]. Contains no policy logic and no backend —
//! those are separate crates (`maknae-authz-basic`, `maknae-authz-dcs`).
//!
//! Fail-closed is the paramount property: anything that is not a definite
//! `Permit` becomes a `Deny` at the kernel→PEP boundary. See the design spec
//! (`maknae authorization-seam`) §3, §5, §6, §13, §15.4.
#![forbid(unsafe_code)]

mod authorizer;
mod classification;
mod compose;
mod obligation;
mod request;
mod value;
mod verdict;

pub use authorizer::{decide_each_cited, Authorizer, Decided, RuleCitation, SubjectBinding};
pub use classification::{first_token, ClassificationPolicy, Level};
pub use compose::{
    combine, compose_backend_name, compose_decide, compose_decide_cited, compose_decide_cited_all,
    compose_decide_reporting_role, compose_subjects, guarded_backend_name, guarded_decide,
    guarded_decide_cited, guarded_decide_cited_all, guarded_decide_reporting_role,
    guarded_subjects, undecided, ConjunctionAuthorizer, CONFLICTING_OBLIGATIONS,
    INDETERMINATE_BLOCKS,
};
pub use obligation::{merge_obligations, Obligation, ObligationConflict};
pub use request::{
    bound_key, decode_git_bound, encode_git_bound, Action, BoundEncodingError, Context,
    FsOperation, GitBoundValues, Lane, Request, Resource, Subject, CHANNEL_AGENT, CHANNEL_CLIENT,
    CONTEXT_BOARD_OP, CONTEXT_DAC_LANE, CONTEXT_FS_OPERATION, CONTEXT_SENSITIVE_PERSONAL,
    CONTEXT_TASK_OP, ENTRY_LABEL_PREFIX, GIT_BOUND_FIELDS, INITIATOR_KERNEL, POST_LABEL_PREFIX,
    RESOURCE_AGENT, RESOURCE_BINDING_KINDS, RESOURCE_BOARD, RESOURCE_BOUND_PREFIX,
    RESOURCE_CLASSIFICATION, RESOURCE_OS_ACCESSIBLE, RESOURCE_REACH_GIT_BASE,
    RESOURCE_REACH_GIT_HEAD, RESOURCE_TASK_HELD, RESOURCE_TASK_OWNED, RESOURCE_TASK_STATE,
    RESOURCE_TOOL_ARGV, RESOURCE_TOOL_BINDING, RESOURCE_TOOL_CLASS, RESOURCE_TOOL_ENTRY,
    RESOURCE_TOOL_FILES_SHA256, RESOURCE_TOOL_FORGE_BASE, RESOURCE_TOOL_FORGE_HEAD,
    RESOURCE_TOOL_LABELS, RESOURCE_TOOL_MODE, RESOURCE_TOOL_PROGRAM, RESOURCE_TOOL_SHAPE,
    RESOURCE_TOOL_STDIN_SHA256, SUBJECT_AGENT, SUBJECT_CHANNEL, SUBJECT_HOME, SUBJECT_INITIATOR,
    SUBJECT_ROOT_TASKER, SUBJECT_TASK, SUBJECT_TASKER, TOOL_MODE_OPEN, TOOL_MODE_POSITIONAL,
    TOOL_MODE_SHAPE,
};
pub use value::{AttrValue, Attributes};
// NOTE: `Verdict` and `Decision` implement `Default` as a deliberate *fail-closed
// contract* (`NotApplicable`→Deny / `Deny`), not an incidental derive. Downstream
// consumers may rely on a defaulted verdict/decision never being a fail-open;
// `defaults_are_fail_closed` (verdict.rs) guards it.
pub use verdict::{finalize, Decision, Verdict};
