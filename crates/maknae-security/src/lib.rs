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

pub use authorizer::{Authorizer, SubjectBinding};
pub use classification::{first_token, ClassificationPolicy, Level};
pub use compose::{
    combine, compose_backend_name, compose_decide, compose_decide_reporting_role, compose_subjects,
    guarded_backend_name, guarded_decide, guarded_decide_reporting_role, guarded_subjects,
    ConjunctionAuthorizer,
};
pub use obligation::{merge_obligations, Obligation, ObligationConflict};
pub use request::{
    Action, Context, FsOperation, Lane, Request, Resource, Subject, CONTEXT_DAC_LANE,
    CONTEXT_FS_OPERATION, RESOURCE_CLASSIFICATION, RESOURCE_OS_ACCESSIBLE,
};
pub use value::{AttrValue, Attributes};
// NOTE: `Verdict` and `Decision` implement `Default` as a deliberate *fail-closed
// contract* (`NotApplicable`→Deny / `Deny`), not an incidental derive. Downstream
// consumers may rely on a defaulted verdict/decision never being a fail-open;
// `defaults_are_fail_closed` (verdict.rs) guards it.
pub use verdict::{finalize, Decision, Verdict};
