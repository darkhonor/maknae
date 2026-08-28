//! T1 verb-dispatch decision points (spec §6). PURE — no I/O, no peer state beyond
//! the explicit arguments. The async request/response orchestration lives in `run.rs`
//! (T3); this module holds ONLY the mutation-gated decisions so a swapped verb arm,
//! an inverted audit-ordering gate, or a mis-built whoami view is caught by mutation
//! testing rather than shipped.
use std::process::ExitCode;

use maknae_proto::{Payload, Verb, WhoamiView};
use maknae_vault::VaultError;

/// What a request's verb resolves to. Carries NO peer facts: `WhoamiRequested` says
/// only "the peer asked who-am-I"; the whoami *view* is built separately from the
/// peer facts (`build_whoami`) so this decision stays a pure function of the verb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dispatch {
    Pong,
    WhoamiRequested,
    /// The peer asked to read a file; the path is the VERB's own datum
    /// (client-supplied, canonical-pre-gated by the PEP), not a peer fact.
    ReadRequested(String),
}

/// Resolve a verb to its dispatch. `Ping → Pong`, `Whoami → WhoamiRequested`.
pub fn dispatch_verb(verb: &Verb) -> Dispatch {
    match verb {
        Verb::Ping => Dispatch::Pong,
        Verb::Whoami => Dispatch::WhoamiRequested,
        Verb::Read { path } => Dispatch::ReadRequested(path.clone()),
    }
}

/// Build the `whoami` response payload from the kernel-verified peer facts.
pub fn build_whoami(uri: &str, uid: u32) -> Payload {
    Payload::Whoami(WhoamiView {
        peer_plane_uri_san: uri.to_string(),
        peer_uid: uid,
    })
}

/// Audit-then-respond ordering gate (ADR-0019): a response may be released ONLY
/// when the request's audit record was durably appended. `audit_ok == false`
/// (the append errored) → withhold the response (fail-closed).
pub fn may_respond(audit_ok: bool) -> bool {
    audit_ok
}

/// Why the serve loop (`run::accept_loop`) stopped accepting connections. Two, and
/// only two, ways the loop legitimately exits (codex round-5 P1): a requested
/// SIGTERM/SIGINT (`GracefulShutdown`) or the credential supervisor task resolving
/// (`SupervisorExited`) — e.g. `VaultError::RenewalExpired` when token renewal or
/// leaf rotation exhausts its retry window and the listener's cert slot + identity
/// are cleared. Distinguishing the two matters because they map to OPPOSITE process
/// outcomes: a shutdown is a clean success; a supervisor exit means the daemon can no
/// longer present a valid cert to new peers and must exit non-zero so process
/// supervision restarts it and re-mints (ADR-0018) — never re-authenticate in place.
#[derive(Debug)]
pub enum ServeOutcome {
    /// SIGTERM/SIGINT observed; in-flight handlers drained normally.
    GracefulShutdown,
    /// The credential supervisor's `JoinHandle` resolved — its retry window is
    /// exhausted (or it panicked/was cancelled) and the listener can no longer serve.
    /// The accept loop stopped BEFORE this variant is constructed.
    SupervisorExited(VaultError),
}

/// The pure `ServeOutcome` → process `ExitCode` mapping (codex round-5 P1). A
/// graceful shutdown is `SUCCESS`; ANY supervisor exit is `FAILURE` — there is no
/// variant of "the supervisor gave up" that should look like a clean stop, because
/// the daemon is left unable to present a cert to new peers.
pub fn serve_outcome_to_exit_code(outcome: &ServeOutcome) -> ExitCode {
    match outcome {
        ServeOutcome::GracefulShutdown => ExitCode::SUCCESS,
        ServeOutcome::SupervisorExited(_) => ExitCode::FAILURE,
    }
}

use std::time::Duration;

/// Verb → PDP action-class name (#85 spec §5; the audit record's `action`
/// field carries the same vocabulary — decision and record share one).
/// `Whoami → admin.whoami` is the ruled deliberate narrowing.
pub fn verb_to_action(verb: &Verb) -> &'static str {
    match verb {
        Verb::Ping => "liveness.ping",
        Verb::Whoami => "admin.whoami",
        Verb::Read { .. } => "acp.fs.read",
    }
}

/// Bound on one PDP decision (per-request policy re-read is sync file I/O on
/// the blocking pool; a stalled /etc/maknae must not pin tokio workers —
/// same rationale family as GROUP_LOOKUP_TIMEOUT). Elapse → Deny (fail
/// closed). 5s: §10.5's orphan-accumulation arithmetic assumes this value;
/// the VALUE is pinned by a T1 test here because the binding site in run.rs
/// is mutation-excluded orchestration. Degenerate configs that shrink the
/// frame budget to 0 are fail-closed by design, not a bug.
pub const AUTHZ_DECIDE_TIMEOUT: Duration = Duration::from_secs(5);

/// Build the seam Request from the verb + kernel-verified peer uid. Subject
/// carries `uid` only (i64 carriage of the u32 — lossless; the reserved
/// `name` token is door-stamped only for runtime-originated requests, and no
/// runtime channel exists — post-#117). `Read` carries the client-supplied
/// path as the resource `path` attribute; resource/context otherwise empty.
pub fn build_authz_request(verb: &Verb, peer_uid: u32) -> maknae_security::Request {
    use maknae_security::{Action, AttrValue, Attributes, Context, Resource, Subject};
    let mut subject = Attributes::new();
    subject.insert("uid", AttrValue::Int(i64::from(peer_uid)));
    let mut resource = Attributes::new();
    if let Verb::Read { path } = verb {
        resource.insert("path", AttrValue::Str(path.clone()));
    }
    maknae_security::Request {
        subject: Subject(subject),
        resource: Resource(resource),
        action: Action(verb_to_action(verb).to_string()),
        context: Context(Attributes::new()),
    }
}

/// An obligation the PEP has no registered handler for — the PEP fails
/// closed to Deny on it (audit-only reason names the id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnhonorableObligation(pub String);

/// Obligation discharge plan (spec D3): the registered handler set is exactly
/// `{"audit"}` with empty params (the pinned literal from #85); the audit
/// obligation is discharged by the audit-then-respond gate itself. Any other
/// id — or `audit` with params the handler does not understand — is
/// unhonorable → the caller denies. An EMPTY obligation list is fine: the
/// daemon audits unconditionally; obligations only add requirements.
pub fn discharge_plan(
    obligations: &[maknae_security::Obligation],
) -> Result<(), UnhonorableObligation> {
    for ob in obligations {
        if ob.id != "audit" || !ob.params.is_empty() {
            return Err(UnhonorableObligation(ob.id.clone()));
        }
    }
    Ok(())
}

/// The lexical canonical-form pre-gate over a client-supplied read path
/// (parent spec §4.4): absolute; no `.`/`..` components; no empty segments
/// after the leading `/` (no `//`, no trailing `/`; bare `/` passes vacuously
/// and matches no glob). The same rules exist as `canonical_violation` inside
/// maknae-authz-basic's decide core — deliberately duplicated: the PDP is
/// swappable behind the seam and the PEP must not depend on one backend's
/// helper. The vector tables in both crates cross-reference each other; a
/// divergence is a test failure on either side. Failing here is the
/// malformed-request class (BadRequest before the PDP), like a decode error.
pub fn lexical_pregate(path: &str) -> Result<(), &'static str> {
    if !path.starts_with('/') {
        return Err("not absolute");
    }
    if path == "/" {
        return Ok(()); // vacuous: matches no glob downstream
    }
    if path.ends_with('/') {
        return Err("trailing slash");
    }
    for seg in path[1..].split('/') {
        match seg {
            "" => return Err("empty segment"),
            "." | ".." => return Err("dot segment"),
            _ => {}
        }
    }
    Ok(())
}

/// Why the read PEP refused to hand back content (spec D5). The CONTENT case
/// is not here — this enum exists so the outcome→(record, wire) mapping is a
/// pure T1 table, not branching buried in orchestration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadRefusal {
    /// Target exceeds the frame budget: a PERMIT whose delivery is refused —
    /// never truncated (spec D5).
    TooLarge,
    /// PDP permitted a path outside the enrolled home: v1's PEP reads only
    /// under the anchor, regardless of grammar (spec D5).
    OutsideRoot,
    /// The anchor itself could not open (missing ACL, unmounted home, bad
    /// mode) — the read subsystem is unavailable; ping/whoami unaffected.
    Unavailable(String),
    /// The target refused a named requirement (symlink, hardlink, not a
    /// regular file, OS DAC) — reason is audit-only, wire stays generic.
    Refused(String),
    /// The bounded read elapsed (wedged filesystem) — fail closed.
    TimedOut,
    /// The blocking task did not complete — fail closed.
    JoinFailed,
}

/// The audit/wire disposition of one refusal: (outcome.result,
/// outcome.reason, outcome.posture, wire code, wire message). Reasons are
/// audit-only; every wire message here is a fixed generic string.
pub fn read_refusal_disposition(
    r: &ReadRefusal,
) -> (&'static str, String, &'static str, maknae_proto::ProtoErrCode, &'static str) {
    use maknae_proto::ProtoErrCode as C;
    match r {
        ReadRefusal::TooLarge => (
            "permit",
            "delivery refused: oversize".into(),
            "refused-oversize",
            C::TooLarge,
            "resource too large",
        ),
        ReadRefusal::OutsideRoot => (
            "permit",
            "delivery refused: outside anchored root".into(),
            "refused-outside-root",
            C::Internal,
            "read outside supported root",
        ),
        ReadRefusal::Unavailable(e) => (
            "deny",
            format!("read subsystem unavailable: {e}"),
            "unavailable",
            C::Internal,
            "read unavailable",
        ),
        ReadRefusal::Refused(e) => ("deny", e.clone(), "unauthorized", C::Unauthorized, "not authorized"),
        ReadRefusal::TimedOut => (
            "deny",
            "read timed out".into(),
            "unavailable",
            C::Internal,
            "read unavailable",
        ),
        ReadRefusal::JoinFailed => (
            "deny",
            "read failed (join)".into(),
            "unavailable",
            C::Internal,
            "read unavailable",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_dispatches_pong() {
        assert_eq!(dispatch_verb(&Verb::Ping), Dispatch::Pong);
    }

    #[test]
    fn whoami_dispatches_requested() {
        assert_eq!(dispatch_verb(&Verb::Whoami), Dispatch::WhoamiRequested);
    }

    #[test]
    fn may_respond_true_only_when_audit_ok() {
        assert!(may_respond(true));
        assert!(!may_respond(false));
    }

    #[test]
    fn graceful_shutdown_maps_to_success() {
        assert_eq!(
            serve_outcome_to_exit_code(&ServeOutcome::GracefulShutdown),
            ExitCode::SUCCESS
        );
    }

    #[test]
    fn supervisor_exited_maps_to_failure() {
        assert_eq!(
            serve_outcome_to_exit_code(&ServeOutcome::SupervisorExited(VaultError::RenewalExpired)),
            ExitCode::FAILURE
        );
    }

    #[test]
    fn supervisor_exited_is_failure_regardless_of_which_vault_error() {
        // ANY supervisor exit is a failure — not just RenewalExpired (e.g. a
        // panicked/cancelled supervisor task surfaces as a different variant, wrapped
        // by run.rs before construction, but the mapping itself must not special-case).
        assert_eq!(
            serve_outcome_to_exit_code(&ServeOutcome::SupervisorExited(VaultError::Renew(
                "supervisor task did not complete cleanly".to_string()
            ))),
            ExitCode::FAILURE
        );
    }

    #[test]
    fn graceful_shutdown_and_supervisor_exited_map_to_different_codes() {
        // A mutant collapsing the two arms to the same ExitCode must fail this.
        assert_ne!(
            serve_outcome_to_exit_code(&ServeOutcome::GracefulShutdown),
            serve_outcome_to_exit_code(&ServeOutcome::SupervisorExited(VaultError::RenewalExpired))
        );
    }

    #[test]
    fn whoami_view_carries_exact_peer_facts() {
        match build_whoami("maknae://d/plane/cli", 501) {
            Payload::Whoami(w) => {
                assert_eq!(w.peer_uid, 501);
                assert_eq!(w.peer_plane_uri_san, "maknae://d/plane/cli");
            }
            other => panic!("expected Payload::Whoami, got {other:?}"),
        }
    }

    #[test]
    fn build_whoami_is_not_pong() {
        // A mutant returning Payload::Pong must fail.
        assert_ne!(build_whoami("maknae://d/plane/cli", 1), Payload::Pong);
    }
    // ---- verb_to_action (T1: arm-swap killers via pairwise ne) ----

    #[test]
    fn verb_action_names_are_the_taxonomy() {
        assert_eq!(verb_to_action(&Verb::Ping), "liveness.ping");
        assert_eq!(verb_to_action(&Verb::Whoami), "admin.whoami");
        assert_eq!(verb_to_action(&Verb::Read { path: "/x".into() }), "acp.fs.read");
    }

    #[test]
    fn verb_action_names_are_pairwise_distinct() {
        let p = verb_to_action(&Verb::Ping);
        let w = verb_to_action(&Verb::Whoami);
        let r = verb_to_action(&Verb::Read { path: "/x".into() });
        assert_ne!(p, w);
        assert_ne!(p, r);
        assert_ne!(w, r);
    }

    #[test]
    fn read_dispatches_read_requested_with_its_path() {
        assert_eq!(
            dispatch_verb(&Verb::Read { path: "/home/op/a".into() }),
            Dispatch::ReadRequested("/home/op/a".into())
        );
        assert_ne!(dispatch_verb(&Verb::Read { path: "/x".into() }), Dispatch::Pong);
        assert_ne!(
            dispatch_verb(&Verb::Read { path: "/x".into() }),
            Dispatch::WhoamiRequested
        );
    }

    // ---- AUTHZ_DECIDE_TIMEOUT value pin (the binding site is T3) ----

    #[test]
    fn decide_timeout_is_five_seconds_and_nonzero() {
        assert_eq!(AUTHZ_DECIDE_TIMEOUT, Duration::from_secs(5));
        assert!(!AUTHZ_DECIDE_TIMEOUT.is_zero());
    }

    // ---- build_authz_request ----

    #[test]
    fn request_carries_uid_lossless_at_both_extremes() {
        let r = build_authz_request(&Verb::Ping, 0);
        assert_eq!(r.subject.0.get("uid"), Some(&maknae_security::AttrValue::Int(0)));
        let r = build_authz_request(&Verb::Whoami, u32::MAX);
        assert_eq!(
            r.subject.0.get("uid"),
            Some(&maknae_security::AttrValue::Int(i64::from(u32::MAX)))
        );
    }

    #[test]
    fn request_action_matches_taxonomy_and_resource_is_empty_for_non_read() {
        let r = build_authz_request(&Verb::Whoami, 501);
        assert_eq!(r.action.0, "admin.whoami");
        assert!(r.resource.0.is_empty());
        assert!(r.context.0.is_empty());
    }

    #[test]
    fn read_request_carries_the_path_resource() {
        let r = build_authz_request(&Verb::Read { path: "/home/op/n".into() }, 501);
        assert_eq!(r.action.0, "acp.fs.read");
        assert_eq!(
            r.resource.0.get("path"),
            Some(&maknae_security::AttrValue::Str("/home/op/n".into()))
        );
    }

    // ---- discharge_plan ----

    fn audit_ob() -> maknae_security::Obligation {
        maknae_security::Obligation { id: "audit".into(), params: maknae_security::Attributes::new() }
    }

    #[test]
    fn exactly_audit_discharges() {
        assert!(discharge_plan(&[audit_ob()]).is_ok());
        assert!(discharge_plan(&[]).is_ok(), "no obligations is fine — audit is unconditional");
    }

    #[test]
    fn unknown_obligation_is_unhonorable_regardless_of_order() {
        let exfil = maknae_security::Obligation { id: "exfil".into(), params: maknae_security::Attributes::new() };
        assert_eq!(
            discharge_plan(&[exfil.clone()]),
            Err(UnhonorableObligation("exfil".into()))
        );
        assert_eq!(
            discharge_plan(&[audit_ob(), exfil.clone()]),
            Err(UnhonorableObligation("exfil".into()))
        );
        assert_eq!(
            discharge_plan(&[exfil, audit_ob()]),
            Err(UnhonorableObligation("exfil".into()))
        );
    }

    #[test]
    fn audit_with_params_is_unhonorable() {
        let mut params = maknae_security::Attributes::new();
        params.insert("scope", maknae_security::AttrValue::Str("x".into()));
        let ob = maknae_security::Obligation { id: "audit".into(), params };
        assert_eq!(discharge_plan(&[ob]), Err(UnhonorableObligation("audit".into())));
    }

    // ---- lexical_pregate (vector table cross-referenced with
    //      maknae-authz-basic decide.rs::canonical_violation's tests) ----

    #[test]
    fn pregate_accepts_canonical_absolute_paths() {
        assert!(lexical_pregate("/home/op/notes.txt").is_ok());
        assert!(lexical_pregate("/").is_ok(), "bare / is vacuous — matches no glob");
        assert!(lexical_pregate("/a").is_ok());
    }

    #[test]
    fn pregate_refuses_every_non_canonical_form() {
        assert!(lexical_pregate("relative/x").is_err());
        assert!(lexical_pregate("").is_err());
        assert!(lexical_pregate("/a/../b").is_err());
        assert!(lexical_pregate("/a/./b").is_err());
        assert!(lexical_pregate("/a//b").is_err());
        assert!(lexical_pregate("/a/").is_err());
        assert!(lexical_pregate("~/x").is_err(), "~ is client-side only, never wire");
    }
    // ---- read_refusal_disposition (T1: the outcome table) ----

    #[test]
    fn oversize_is_a_permit_with_refused_delivery_and_too_large_on_the_wire() {
        let (result, reason, posture, code, msg) = read_refusal_disposition(&ReadRefusal::TooLarge);
        assert_eq!(result, "permit");
        assert!(reason.contains("oversize"));
        assert_eq!(posture, "refused-oversize");
        assert_eq!(code, maknae_proto::ProtoErrCode::TooLarge);
        assert_eq!(msg, "resource too large");
    }

    #[test]
    fn outside_root_is_a_permit_with_internal_not_unauthorized() {
        let (result, _, posture, code, _) = read_refusal_disposition(&ReadRefusal::OutsideRoot);
        assert_eq!(result, "permit", "a Permit was rendered — the record must say so");
        assert_eq!(posture, "refused-outside-root");
        assert_eq!(code, maknae_proto::ProtoErrCode::Internal);
        assert_ne!(code, maknae_proto::ProtoErrCode::Unauthorized);
    }

    #[test]
    fn target_refusals_deny_with_generic_wire_and_audit_only_reason() {
        let (result, reason, posture, code, msg) =
            read_refusal_disposition(&ReadRefusal::Refused("hard-linked (nlink=2): /x".into()));
        assert_eq!(result, "deny");
        assert!(reason.contains("nlink=2"), "reason is the io rendering, audit-only");
        assert_eq!(posture, "unauthorized");
        assert_eq!(code, maknae_proto::ProtoErrCode::Unauthorized);
        assert_eq!(msg, "not authorized");
        assert!(!msg.contains("nlink"), "wire stays generic");
    }

    #[test]
    fn unavailable_timeout_and_join_all_deny_unavailable() {
        for r in [
            ReadRefusal::Unavailable("acl missing".into()),
            ReadRefusal::TimedOut,
            ReadRefusal::JoinFailed,
        ] {
            let (result, _, posture, code, msg) = read_refusal_disposition(&r);
            assert_eq!(result, "deny", "{r:?}");
            assert_eq!(posture, "unavailable", "{r:?}");
            assert_eq!(code, maknae_proto::ProtoErrCode::Internal, "{r:?}");
            assert_eq!(msg, "read unavailable", "{r:?}");
        }
    }

    #[test]
    fn dispositions_are_pairwise_distinct_where_it_matters() {
        // Arm-swap killers: oversize vs outside-root differ in posture;
        // refused vs unavailable differ in code+message.
        assert_ne!(
            read_refusal_disposition(&ReadRefusal::TooLarge).2,
            read_refusal_disposition(&ReadRefusal::OutsideRoot).2
        );
        assert_ne!(
            read_refusal_disposition(&ReadRefusal::Refused("x".into())).3,
            read_refusal_disposition(&ReadRefusal::Unavailable("y".into())).3
        );
    }
}
