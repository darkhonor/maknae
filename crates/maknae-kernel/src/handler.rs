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
    /// An enumerated term with no behaviour. Reached only after a Permit.
    NoBehaviour,
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
        // Every enumerated-but-unbuilt term. NO wildcard: a new variant is a
        // compile error until someone decides what it dispatches to.
        Verb::AdminStatus
        | Verb::AdminConfigShow
        | Verb::AdminAuditTail
        | Verb::AdminPolicyReload
        | Verb::AdminSubjectList
        | Verb::AdminSubjectBind
        | Verb::AdminSubjectUnbind
        | Verb::AdminContain
        | Verb::AdminRelease
        | Verb::AdminCredentialRotate
        | Verb::AdminProviderList
        | Verb::AdminProviderSet
        | Verb::AdminProviderDisable
        | Verb::AdminCredentialBroker
        | Verb::AdminSessionList
        | Verb::AdminSessionTerminate
        | Verb::SessionNew
        | Verb::SessionResume
        | Verb::SessionClose
        | Verb::SessionDelete
        | Verb::SessionList
        | Verb::SessionFork
        | Verb::SessionPrompt
        | Verb::SessionCancel
        | Verb::SessionSetconfigoption
        | Verb::SessionSetmode
        | Verb::SessionLoad
        | Verb::SessionUpdate
        | Verb::SessionRequestpermission
        | Verb::SessionElicitCreate
        | Verb::SessionElicitComplete
        | Verb::SessionCompact
        | Verb::FsWrite
        | Verb::FsDelete
        | Verb::FsMove
        | Verb::FsList
        | Verb::FsStat
        | Verb::FsMkdir
        | Verb::FsLink
        | Verb::FsChmod
        | Verb::FsChown
        | Verb::TerminalCreate
        | Verb::TerminalOutput
        | Verb::TerminalWaitforexit
        | Verb::TerminalKill
        | Verb::TerminalRelease
        | Verb::TerminalInput
        | Verb::McpConnect
        | Verb::McpDisconnect
        | Verb::McpMessage
        | Verb::McpToolCall
        | Verb::McpResourceRead
        | Verb::McpPromptGet
        | Verb::McpSamplingCreate => Dispatch::NoBehaviour,
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
        Verb::AdminStatus => "admin.status",
        Verb::AdminConfigShow => "admin.config.show",
        Verb::AdminAuditTail => "admin.audit.tail",
        Verb::AdminPolicyReload => "admin.policy.reload",
        Verb::AdminSubjectList => "admin.subject.list",
        Verb::AdminSubjectBind => "admin.subject.bind",
        Verb::AdminSubjectUnbind => "admin.subject.unbind",
        Verb::AdminContain => "admin.contain",
        Verb::AdminRelease => "admin.release",
        Verb::AdminCredentialRotate => "admin.credential.rotate",
        Verb::AdminProviderList => "admin.provider.list",
        Verb::AdminProviderSet => "admin.provider.set",
        Verb::AdminProviderDisable => "admin.provider.disable",
        Verb::AdminCredentialBroker => "admin.credential.broker",
        Verb::AdminSessionList => "admin.session.list",
        Verb::AdminSessionTerminate => "admin.session.terminate",
        Verb::SessionNew => "session.new",
        Verb::SessionResume => "session.resume",
        Verb::SessionClose => "session.close",
        Verb::SessionDelete => "session.delete",
        Verb::SessionList => "session.list",
        Verb::SessionFork => "session.fork",
        Verb::SessionPrompt => "session.prompt",
        Verb::SessionCancel => "session.cancel",
        Verb::SessionSetconfigoption => "session.set_config_option",
        Verb::SessionSetmode => "session.set_mode",
        Verb::SessionLoad => "session.load",
        Verb::SessionUpdate => "session.update",
        Verb::SessionRequestpermission => "session.request_permission",
        Verb::SessionElicitCreate => "session.elicit.create",
        Verb::SessionElicitComplete => "session.elicit.complete",
        Verb::SessionCompact => "session.compact",
        Verb::Read { .. } => "fs.read",
        Verb::FsWrite => "fs.write",
        Verb::FsDelete => "fs.delete",
        Verb::FsMove => "fs.move",
        Verb::FsList => "fs.list",
        Verb::FsStat => "fs.stat",
        Verb::FsMkdir => "fs.mkdir",
        Verb::FsLink => "fs.link",
        Verb::FsChmod => "fs.chmod",
        Verb::FsChown => "fs.chown",
        Verb::TerminalCreate => "terminal.create",
        Verb::TerminalOutput => "terminal.output",
        Verb::TerminalWaitforexit => "terminal.wait_for_exit",
        Verb::TerminalKill => "terminal.kill",
        Verb::TerminalRelease => "terminal.release",
        Verb::TerminalInput => "terminal.input",
        Verb::McpConnect => "mcp.connect",
        Verb::McpDisconnect => "mcp.disconnect",
        Verb::McpMessage => "mcp.message",
        Verb::McpToolCall => "mcp.tool.call",
        Verb::McpResourceRead => "mcp.resource.read",
        Verb::McpPromptGet => "mcp.prompt.get",
        Verb::McpSamplingCreate => "mcp.sampling.create",
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

/// CBOR + response-envelope headroom subtracted from the daemon's own frame
/// budget before a read is sized (spec D5). Degenerate-but-legal configs
/// (frame_max_bytes as low as 1) make the budget 0 and every non-empty read
/// refuses TooLarge — fail-closed by design, not a bug. T1-pinned here; the
/// binding in run.rs is thin orchestration.
pub const FRAME_ENVELOPE_MARGIN: u64 = 512;

/// The read budget for one response frame.
pub fn read_budget(frame_max_bytes: usize) -> u64 {
    (frame_max_bytes as u64).saturating_sub(FRAME_ENVELOPE_MARGIN)
}

/// The read PEP's DECISION half (T1 — spec D5's "read-path decision logic
/// incl. the size bound and TargetRequired naming"): given the enrolled home,
/// its owner, the canonical client path and the budget, produce the
/// home-relative remainder plus the NAMED requirements the anchored open and
/// read must enforce — or the refusal. Pure; the two maknae-io calls stay in
/// run.rs as orchestration.
#[allow(clippy::type_complexity)]
pub fn read_plan(
    home: &std::path::Path,
    owner_uid: u32,
    path: &str,
    budget: u64,
) -> Result<
    (
        std::path::PathBuf,
        maknae_io::AnchorRequired,
        maknae_io::TargetRequired,
    ),
    ReadRefusal,
> {
    // Component-wise, never str::strip_prefix (`/home/opx` is a string-prefix
    // of `/home/op` and must NOT match).
    let rel = match std::path::Path::new(path).strip_prefix(home) {
        Ok(rel) => rel.to_path_buf(),
        Err(_) => return Err(ReadRefusal::OutsideRoot),
    };
    Ok((
        rel,
        // THE alias-planting boundary (spec D5): owner + no group/other write
        // on the home. A home any non-principal can write is refused outright.
        maknae_io::AnchorRequired {
            owner: Some(owner_uid),
            mode_mask: Some(0o022),
        },
        maknae_io::TargetRequired {
            // OS DAC at the target: the boundary requirement lives on the
            // ANCHOR above; nlink/regular/max_bytes ARE named (std-fs
            // allowlist carries the justified entry).
            owner: None,
            mode_mask: None,
            nlink_exactly_one: true,
            regular_file: true,
            max_bytes: Some(budget),
        },
    ))
}

/// The read PEP's error mapping (T1): io refusal → typed [`ReadRefusal`].
pub fn map_read_error(e: maknae_io::IoError) -> ReadRefusal {
    match e {
        maknae_io::IoError::TargetTooLarge { .. } => ReadRefusal::TooLarge,
        other => ReadRefusal::Refused(other.to_string()),
    }
}

/// The audit/wire disposition of one refusal: (outcome.result,
/// outcome.reason, outcome.posture, wire code, wire message). Reasons are
/// audit-only; every wire message here is a fixed generic string.
pub fn read_refusal_disposition(
    r: &ReadRefusal,
) -> (
    &'static str,
    String,
    &'static str,
    maknae_proto::ProtoErrCode,
    &'static str,
) {
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
        ReadRefusal::Refused(e) => (
            "deny",
            e.clone(),
            "unauthorized",
            C::Unauthorized,
            "not authorized",
        ),
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
        assert_eq!(verb_to_action(&Verb::Read { path: "/x".into() }), "fs.read");
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
            dispatch_verb(&Verb::Read {
                path: "/home/op/a".into()
            }),
            Dispatch::ReadRequested("/home/op/a".into())
        );
        assert_ne!(
            dispatch_verb(&Verb::Read { path: "/x".into() }),
            Dispatch::Pong
        );
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
        assert_eq!(
            r.subject.0.get("uid"),
            Some(&maknae_security::AttrValue::Int(0))
        );
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
        let r = build_authz_request(
            &Verb::Read {
                path: "/home/op/n".into(),
            },
            501,
        );
        assert_eq!(r.action.0, "fs.read");
        assert_eq!(
            r.resource.0.get("path"),
            Some(&maknae_security::AttrValue::Str("/home/op/n".into()))
        );
    }

    // ---- discharge_plan ----

    fn audit_ob() -> maknae_security::Obligation {
        maknae_security::Obligation {
            id: "audit".into(),
            params: maknae_security::Attributes::new(),
        }
    }

    #[test]
    fn exactly_audit_discharges() {
        assert!(discharge_plan(&[audit_ob()]).is_ok());
        assert!(
            discharge_plan(&[]).is_ok(),
            "no obligations is fine — audit is unconditional"
        );
    }

    #[test]
    fn unknown_obligation_is_unhonorable_regardless_of_order() {
        let exfil = maknae_security::Obligation {
            id: "exfil".into(),
            params: maknae_security::Attributes::new(),
        };
        assert_eq!(
            discharge_plan(std::slice::from_ref(&exfil)),
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
        let ob = maknae_security::Obligation {
            id: "audit".into(),
            params,
        };
        assert_eq!(
            discharge_plan(&[ob]),
            Err(UnhonorableObligation("audit".into()))
        );
    }

    // ---- lexical_pregate (vector table cross-referenced with
    //      maknae-authz-basic decide.rs::canonical_violation's tests) ----

    #[test]
    fn pregate_accepts_canonical_absolute_paths() {
        assert!(lexical_pregate("/home/op/notes.txt").is_ok());
        assert!(
            lexical_pregate("/").is_ok(),
            "bare / is vacuous — matches no glob"
        );
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
        assert!(
            lexical_pregate("~/x").is_err(),
            "~ is client-side only, never wire"
        );
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
        assert_eq!(
            result, "permit",
            "a Permit was rendered — the record must say so"
        );
        assert_eq!(posture, "refused-outside-root");
        assert_eq!(code, maknae_proto::ProtoErrCode::Internal);
        assert_ne!(code, maknae_proto::ProtoErrCode::Unauthorized);
    }

    #[test]
    fn target_refusals_deny_with_generic_wire_and_audit_only_reason() {
        let (result, reason, posture, code, msg) =
            read_refusal_disposition(&ReadRefusal::Refused("hard-linked (nlink=2): /x".into()));
        assert_eq!(result, "deny");
        assert!(
            reason.contains("nlink=2"),
            "reason is the io rendering, audit-only"
        );
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
    // ---- read_plan / map_read_error / read_budget (T1: spec D5's decision
    //      logic — the alias boundary, the named requirements, the bound) ----

    #[test]
    fn read_budget_subtracts_the_margin_and_saturates() {
        assert_eq!(read_budget(65536), 65536 - 512);
        assert_eq!(read_budget(512), 0);
        assert_eq!(
            read_budget(1),
            0,
            "degenerate config is fail-closed, not a bug"
        );
    }

    #[test]
    fn read_plan_names_the_boundary_and_target_requirements_exactly() {
        let (rel, anchor_req, target_req) = read_plan(
            std::path::Path::new("/home/op"),
            501,
            "/home/op/docs/notes.txt",
            1000,
        )
        .expect("in-home path plans");
        assert_eq!(rel, std::path::Path::new("docs/notes.txt"));
        assert_eq!(
            anchor_req.owner,
            Some(501),
            "anchor owner = the enrolled principal"
        );
        assert_eq!(
            anchor_req.mode_mask,
            Some(0o022),
            "no group/other write on home"
        );
        assert!(target_req.nlink_exactly_one, "hardlink aliases refused");
        assert!(target_req.regular_file, "no fifo/device");
        assert_eq!(
            target_req.max_bytes,
            Some(1000),
            "the budget is the named bound"
        );
        assert_eq!(target_req.owner, None);
        assert_eq!(target_req.mode_mask, None);
    }

    #[test]
    fn read_plan_refuses_outside_root_component_wise() {
        // String-prefix must NOT match: /home/opx is not under /home/op.
        assert_eq!(
            read_plan(std::path::Path::new("/home/op"), 501, "/home/opx/f", 10),
            Err(ReadRefusal::OutsideRoot)
        );
        assert_eq!(
            read_plan(std::path::Path::new("/home/op"), 501, "/etc/hostname", 10),
            Err(ReadRefusal::OutsideRoot)
        );
    }

    #[test]
    fn map_read_error_types_oversize_and_everything_else() {
        let too_large = maknae_io::IoError::TargetTooLarge {
            path: "/x".into(),
            limit: 10,
            actual: 20,
        };
        assert_eq!(map_read_error(too_large), ReadRefusal::TooLarge);
        let other = maknae_io::IoError::MultiplyLinked {
            path: "/x".into(),
            nlink: 2,
        };
        match map_read_error(other) {
            ReadRefusal::Refused(m) => assert!(m.contains("hard-linked"), "{m}"),
            r => panic!("expected Refused, got {r:?}"),
        }
    }

    /// Every term in the vocabulary, for the exhaustiveness properties below.
    /// The wildcard-free matches in `verb_to_action`/`dispatch_verb` are the
    /// real completeness control — the compiler refuses a variant with no arm.
    /// This list is what lets the properties be *asserted* rather than assumed.
    fn all_verbs() -> Vec<Verb> {
        vec![
            Verb::Ping,
            Verb::Whoami,
            Verb::AdminStatus,
            Verb::AdminConfigShow,
            Verb::AdminAuditTail,
            Verb::AdminPolicyReload,
            Verb::AdminSubjectList,
            Verb::AdminSubjectBind,
            Verb::AdminSubjectUnbind,
            Verb::AdminContain,
            Verb::AdminRelease,
            Verb::AdminCredentialRotate,
            Verb::AdminProviderList,
            Verb::AdminProviderSet,
            Verb::AdminProviderDisable,
            Verb::AdminCredentialBroker,
            Verb::AdminSessionList,
            Verb::AdminSessionTerminate,
            Verb::SessionNew,
            Verb::SessionResume,
            Verb::SessionClose,
            Verb::SessionDelete,
            Verb::SessionList,
            Verb::SessionFork,
            Verb::SessionPrompt,
            Verb::SessionCancel,
            Verb::SessionSetconfigoption,
            Verb::SessionSetmode,
            Verb::SessionLoad,
            Verb::SessionUpdate,
            Verb::SessionRequestpermission,
            Verb::SessionElicitCreate,
            Verb::SessionElicitComplete,
            Verb::SessionCompact,
            Verb::Read {
                path: String::new(),
            },
            Verb::FsWrite,
            Verb::FsDelete,
            Verb::FsMove,
            Verb::FsList,
            Verb::FsStat,
            Verb::FsMkdir,
            Verb::FsLink,
            Verb::FsChmod,
            Verb::FsChown,
            Verb::TerminalCreate,
            Verb::TerminalOutput,
            Verb::TerminalWaitforexit,
            Verb::TerminalKill,
            Verb::TerminalRelease,
            Verb::TerminalInput,
            Verb::McpConnect,
            Verb::McpDisconnect,
            Verb::McpMessage,
            Verb::McpToolCall,
            Verb::McpResourceRead,
            Verb::McpPromptGet,
            Verb::McpSamplingCreate,
        ]
    }

    /// #67 D4: the vocabulary is the size the spec says.
    #[test]
    fn the_vocabulary_is_fifty_seven_client_reachable_terms() {
        assert_eq!(all_verbs().len(), 57);
    }

    /// Two terms sharing an action string would be decided as one another —
    /// a typo'd class prefix in any arm is invisible without this.
    #[test]
    fn every_action_string_is_distinct() {
        let actions: Vec<&str> = all_verbs().iter().map(verb_to_action).collect();
        let uniq: std::collections::BTreeSet<&&str> = actions.iter().collect();
        assert_eq!(
            uniq.len(),
            actions.len(),
            "action strings must be pairwise distinct"
        );
    }

    /// #67 D1: nothing structural prevents this collision now the `acp.`
    /// prefix is gone, so it is a test obligation.
    #[test]
    fn no_action_string_equals_an_adr0019_pseudo_action() {
        for v in all_verbs() {
            let a = verb_to_action(&v);
            assert!(
                !["connect", "read", "decode", "authz", "posture"].contains(&a),
                "{a} collides with an ADR-0019 transport/boot pseudo-action"
            );
        }
    }

    /// Every term resolves to one of the seven closed classes. A term whose
    /// class prefix is wrong would fall to `None` -> Deny at runtime and be
    /// invisible; this fails the suite instead.
    #[test]
    fn every_term_resolves_to_a_closed_class() {
        const CLASSES: [&str; 7] = [
            "liveness", "admin", "session", "fs", "terminal", "mcp", "kernel",
        ];
        for v in all_verbs() {
            let a = verb_to_action(&v);
            let head = a.split('.').next().unwrap();
            assert!(CLASSES.contains(&head), "{a} resolves to no closed class");
        }
    }

    /// The shipped variants keep their identifiers because serde encodes
    /// externally-tagged variants BY NAME — the identifier IS the CBOR key.
    /// Renaming one is a silent hard wire break with no version bump.
    #[test]
    fn the_shipped_variants_keep_their_wire_keys() {
        for (verb, key) in [
            (Verb::Ping, "Ping"),
            (Verb::Whoami, "Whoami"),
            (Verb::Read { path: "/x".into() }, "Read"),
        ] {
            let bytes = maknae_proto::encode_request(&maknae_proto::Request {
                protocol_version: maknae_proto::PROTOCOL_VERSION,
                verb,
            })
            .expect("encodes");
            let hdr = [&[0x60 | key.len() as u8][..], key.as_bytes()].concat();
            assert!(
                bytes.windows(hdr.len()).any(|wnd| wnd == hdr.as_slice()),
                "{key} must appear as a CBOR text key of its exact length"
            );
        }
    }
}
