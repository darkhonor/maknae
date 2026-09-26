//! T1 verb-dispatch decision points (spec §6). PURE — no I/O, no peer state beyond
//! the explicit arguments. The async request/response orchestration lives in `run.rs`
//! (T3); this module holds ONLY the mutation-gated decisions so a swapped verb arm,
//! an inverted audit-ordering gate, or a mis-built whoami view is caught by mutation
//! testing rather than shipped.
use std::process::ExitCode;

use crate::blocking_guard::BLOCKING_OPERATION_TIMEOUT;
use maknae_proto::{Payload, Verb, WhoamiView};
use maknae_vault::VaultError;

/// What a request's verb resolves to. Carries NO peer facts: `WhoamiRequested` says
/// only "the peer asked who-am-I"; the whoami *view* is built separately from the
/// peer facts (`build_whoami`) so this decision stays a pure function of the verb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dispatch {
    /// An enumerated term with no behaviour. Reached only after a Permit —
    /// which, while `-basic` is the only operand that GRANTS (corrected 2026-09-06, #148/#154: the ceiling operand is composed too, but it never `Permit`s, so the arm stays unreachable), NOTHING can produce for an
    /// unbuilt term (grants are code-bounded to `GRANTABLE_ACTIONS`,
    /// ADR-0010), so this arm is production-unreachable TODAY. It is reachable
    /// by construction the moment an extension operand grants a term `-basic`
    /// abstains on (ADR-0008 D2), which is why the arm and its NOOP contract
    /// stay: the extension-permit pin in `enforce_loop.rs` drives exactly that
    /// path. An UNPERMITTED unbuilt term never reaches dispatch at all, and —
    /// operator wire ruling, 2026-09-02 — a PERMITTED one answers the SAME
    /// generic `Unauthorized`: "unauthorized is all that is published to the
    /// wire", every path, superseding the #67 NOOP contract's wire half. Build
    /// state lives in the audit trail only (permit / not-implemented); an
    /// extension that wants to expose it does so through its own channel.
    /// (Corrected 2026-09-02, #181, twice — same day, second time by ruling.)
    NoBehaviour,
    Pong,
    WhoamiRequested,
    /// Requires the dedicated descriptor/preparation and durable intent path.
    MutationRequested,
    /// The peer asked for the effective configuration (#162 Phase 2). Carries
    /// no datum: the config is the daemon's own, never client-supplied.
    ConfigShowRequested,
    /// The peer asked for runtime posture. No datum: the daemon's own state.
    StatusRequested,
    /// The peer asked to enumerate role bindings. No datum; the answer is read
    /// LIVE from the PDP, never from a boot snapshot.
    SubjectListRequested,
    /// The peer asked to send content to the registered provider (#172). The
    /// destination is the KERNEL's (the provider registered at boot), never the
    /// client's; the operands travel in the verb and are pre-gated in `run.rs`.
    PromptRequested,
}

/// Resolve a verb to its dispatch. `Ping → Pong`, `Whoami → WhoamiRequested`.
pub fn dispatch_verb(verb: &Verb) -> Dispatch {
    match verb {
        Verb::Ping => Dispatch::Pong,
        Verb::Whoami => Dispatch::WhoamiRequested,
        Verb::Read { .. } | Verb::FsWrite { .. } | Verb::FsDelete { .. } | Verb::FsMkdir { .. } => {
            Dispatch::MutationRequested
        }
        // Every enumerated-but-unbuilt term. NO wildcard: a new variant is a
        // compile error until someone decides what it dispatches to.
        Verb::AdminConfigShow => Dispatch::ConfigShowRequested,
        Verb::AdminStatus => Dispatch::StatusRequested,
        Verb::AdminSubjectList => Dispatch::SubjectListRequested,
        Verb::SessionPrompt { .. } => Dispatch::PromptRequested,
        Verb::AdminAuditTail
        | Verb::AdminPolicyReload
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
        | Verb::SessionCancel
        | Verb::SessionSetconfigoption
        | Verb::SessionSetmode
        | Verb::SessionLoad
        | Verb::SessionUpdate
        | Verb::SessionRequestpermission
        | Verb::SessionElicitCreate
        | Verb::SessionElicitComplete
        | Verb::SessionCompact
        | Verb::FsMove
        | Verb::FsList
        | Verb::FsStat
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
/// The actions the KERNEL initiates on its own behalf, which have no client
/// request and therefore no `Verb` variant (#67 D2). They are still PDP-decided
/// and audited, so they need action strings — and the drift gate needs a source
/// to diff the manifest against, or two of the vocabulary's 59 terms would carry
/// no recorded disposition (spec R7).
pub const KERNEL_ACTIONS: [&str; 2] = ["kernel.contain", "kernel.session.terminate"];

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
        Verb::SessionPrompt { .. } => "session.prompt",
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
        Verb::FsWrite { .. } => "fs.write",
        Verb::FsDelete { .. } => "fs.delete",
        Verb::FsMove => "fs.move",
        Verb::FsList => "fs.list",
        Verb::FsStat => "fs.stat",
        Verb::FsMkdir { .. } => "fs.mkdir",
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
pub const AUTHZ_DECIDE_TIMEOUT: Duration = BLOCKING_OPERATION_TIMEOUT;

/// The bound on `subject.user`, re-exported for the identity suite.
pub fn admitted_user_for_test(user: Option<&str>) -> Option<String> {
    crate::run::admitted_user_pub(user)
}

/// Build the seam Request from the verb + kernel-verified peer uid. Subject
/// carries `uid` only (i64 carriage of the u32 — lossless); the uid is the whole
/// subject (ADR-0024). `Read` carries the client-supplied
/// path as the resource `path` attribute; resource/context otherwise empty.
pub fn build_authz_request(
    verb: &Verb,
    peer_uid: u32,
    lane: maknae_security::Lane,
    // The provider registered at boot (#243), by name, or none. Supplied by
    // the accept loop's captured boot state, never read off the wire.
    provider_name: Option<&str>,
) -> maknae_security::Request {
    use maknae_security::{Action, AttrValue, Attributes, Context, Resource, Subject};
    let mut subject = Attributes::new();
    subject.insert("uid", AttrValue::Int(i64::from(peer_uid)));
    let mut resource = Attributes::new();
    if let Verb::Read { path, .. } = verb {
        resource.insert("path", AttrValue::Str(path.clone()));
    }
    // #172: the egress destination is the kernel's registered provider, stamped
    // here so the PDP decides on `provider:<name>` and the client never names
    // it. Deliberately a literal, like "path" above: the PDP is swappable behind
    // the seam and the PEP must not depend on one backend's constant. Absent
    // when no provider is registered — the arm refuses that.
    if let (Verb::SessionPrompt { .. }, Some(name)) = (verb, provider_name) {
        resource.insert("destination", AttrValue::Str(format!("provider:{name}")));
    }
    // The lane is an ARGUMENT, never derived from `verb`. That is the point: the
    // caller is the accept loop, which knows which listener accepted, and there is
    // therefore no code path by which client-supplied content could reach it
    // (ADR-0009 decision 8).
    let mut context = Attributes::new();
    context.insert(
        maknae_security::CONTEXT_DAC_LANE,
        AttrValue::Str(lane.as_str().to_string()),
    );
    maknae_security::Request {
        subject: Subject(subject),
        resource: Resource(resource),
        action: Action(verb_to_action(verb).to_string()),
        context: Context(context),
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
/// malformed-request class (BadRequest before the PDP), like a decode error
/// — which itself is audited and closed FRAMELESS, never answered (#181).
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

/// CBOR + response-envelope headroom subtracted from the daemon's own frame
/// budget before a read is sized (spec D5). Degenerate-but-legal configs
/// (frame_max_bytes as low as 1) make the budget 0 and every non-empty read
/// is refused — fail-closed by design, not a bug. T1-pinned here; the
/// binding in mutation.rs is thin orchestration.
pub const FRAME_ENVELOPE_MARGIN: u64 = 512;

/// The content bound for one read grant (and the reply frame's envelope margin).
pub fn read_budget(frame_max_bytes: usize) -> u64 {
    (frame_max_bytes as u64).saturating_sub(FRAME_ENVELOPE_MARGIN)
}

/// The named requirements for a SUBJECT-DELEGATED object descriptor (ADR-0009).
///
/// Three proofs, all required (decision 3): the descriptor proves where the object
/// is — the kernel-reported path — `confined_beneath` proves the object lies under
/// the enrolled home, and `root_required` proves the home itself is not a place where
/// aliases can be planted (decision 7). The descriptor confers no access; the OS
/// answers at the subject's own re-open.
///
/// `owner`/`mode_mask` on the TARGET stay `None` deliberately and are NOT a gap:
/// evaluating them daemon-side is the mode-algebra reimplementation that ACLs,
/// supplementary groups, SELinux and AppArmor make non-equivalent to the kernel's own
/// answer. `nlink_exactly_one` is load-bearing three ways (decision 5).
pub fn delegated_plan(home: &std::path::Path, owner_uid: u32) -> maknae_io::DelegatedRequired {
    maknae_io::DelegatedRequired {
        confined_beneath: home.to_path_buf(),
        root_required: maknae_io::AnchorRequired {
            owner: Some(owner_uid),
            mode_mask: Some(0o022),
        },
        target: maknae_io::TargetRequired {
            owner: None,
            mode_mask: None,
            nlink_exactly_one: true,
            regular_file: true,
            max_bytes: None,
        },
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
    fn session_prompt_dispatches_to_prompt_requested_and_its_siblings_do_not() {
        assert_eq!(
            dispatch_verb(&Verb::SessionPrompt {
                conversation: "c".into(),
                turns: vec![]
            }),
            Dispatch::PromptRequested
        );
        assert_eq!(dispatch_verb(&Verb::SessionCancel), Dispatch::NoBehaviour);
        assert_eq!(dispatch_verb(&Verb::SessionUpdate), Dispatch::NoBehaviour);
    }

    #[test]
    fn the_request_carries_the_registered_provider_as_the_destination_and_nothing_when_none() {
        let v = Verb::SessionPrompt {
            conversation: "c".into(),
            turns: vec![],
        };
        let r = build_authz_request(&v, 1002, maknae_security::Lane::Local, Some("openai"));
        assert_eq!(
            r.resource.0.get("destination"),
            Some(&maknae_security::AttrValue::Str("provider:openai".into()))
        );
        assert!(
            build_authz_request(&v, 1002, maknae_security::Lane::Local, None)
                .resource
                .0
                .get("destination")
                .is_none()
        );
        assert!(build_authz_request(
            &Verb::Ping,
            1002,
            maknae_security::Lane::Local,
            Some("openai")
        )
        .resource
        .0
        .get("destination")
        .is_none());
    }

    #[test]
    fn whoami_dispatches_requested() {
        assert_eq!(dispatch_verb(&Verb::Whoami), Dispatch::WhoamiRequested);
    }

    /// The three grantable disclosure terms dispatch here; the fourth grantable
    /// term, `session.prompt` (#172), is asserted by
    /// `every_grantable_term_dispatches_and_the_hand_copy_matches`. The
    /// `NoBehaviour` pin that guarded them is RETIRED here, having done its job twice.
    ///
    /// It was written in Phase 1 over all three, so that none could gain a
    /// dispatch without someone answering the disclosure question deliberately.
    /// It went red for `admin.config.show` and was narrowed; it went red again
    /// for these two. There are no grantable terms left for it to cover, so
    /// keeping it would be keeping a test that asserts nothing. What replaces
    /// it is the inverse claim, which is now the one worth holding: each term
    /// dispatches to its OWN arm, not to a shared or class-granular one.
    #[test]
    fn each_grantable_term_dispatches_to_its_own_arm() {
        assert_eq!(dispatch_verb(&Verb::AdminStatus), Dispatch::StatusRequested);
        assert_eq!(
            dispatch_verb(&Verb::AdminConfigShow),
            Dispatch::ConfigShowRequested
        );
        assert_eq!(
            dispatch_verb(&Verb::AdminSubjectList),
            Dispatch::SubjectListRequested
        );
        // And EVERY term that is not grantable still has no behaviour --
        // DERIVED, not hand-typed.
        //
        // The previous version listed thirteen literals while its own comment
        // complained that an earlier version listed two of thirteen. Same
        // defect, one scale up: a fourteenth ungrantable `admin.*` verb is
        // forced through `dispatch_verb` (a compile error) and through the
        // `all_verbs()` length pin, but NOT into a hand-typed list -- so the
        // class claim would silently cover 13 of 14. Derived, the invariant
        // maintains itself.
        //
        // (Corrected 2026-09-02, #181 S4: this comment said the grantable-side
        // tripwire "has no replacement" — true when written, false now. The
        // replacement is `every_grantable_term_dispatches_and_the_hand_copy_matches`
        // below, reaching the real constant through `-basic`'s
        // `grantable_actions()` re-export; the hand-typed list here is now
        // ASSERTED equal to the constant rather than trusted — and THIS list
        // is not a copy at all any more: it reads the re-export. Two hand-pins
        // remain, BOTH asserted against the constant: the tripwire test below
        // (cross-crate) and `-basic`'s in-crate pin for the mutation lane.)
        let grantable = maknae_authz_basic::grantable_actions();
        let ungrantable: Vec<Verb> = all_verbs()
            .into_iter()
            .filter(|v| {
                let a = verb_to_action(v);
                a.starts_with("admin.") && a != "admin.whoami" && !grantable.contains(&a)
            })
            .collect();
        assert!(
            ungrantable.len() >= 13,
            "the ungrantable admin set should not shrink unnoticed: {}",
            ungrantable.len()
        );
        for v in ungrantable {
            assert_eq!(
                dispatch_verb(&v),
                Dispatch::NoBehaviour,
                "{v:?} is not grantable and must still disclose nothing"
            );
        }
    }

    /// Does every element of `terms` map to a wire verb whose dispatch is a
    /// REAL arm (non-`NoBehaviour`)? Extracted so the discriminator itself is
    /// testable: asserting only over `GRANTABLE_ACTIONS` would go green
    /// vacuously if this helper always returned true.
    fn all_dispatch(terms: &[&str]) -> bool {
        terms.iter().all(|t| {
            all_verbs()
                .into_iter()
                .find(|v| verb_to_action(v) == *t)
                .is_some_and(|v| dispatch_verb(&v) != Dispatch::NoBehaviour)
        })
    }

    /// The grantable-side tripwire (#181 S4), replacing what the retired
    /// `NoBehaviour` pin provided: a FIFTH term joining `GRANTABLE_ACTIONS`
    /// without a dispatch arm — the "granted-but-unbuilt" state ADR-0010 makes
    /// a contradiction — turns this red, cross-crate, through the re-export.
    /// *(Corrected 2026-09-09: said FOURTH; #172 was the fourth, `session.prompt`.)*
    /// The hand-copied list above is asserted equal to the constant, so it can
    /// no longer drift silently either.
    #[test]
    fn every_grantable_term_dispatches_and_the_hand_copy_matches() {
        let real = maknae_authz_basic::grantable_actions();
        assert_eq!(
            real,
            [
                "admin.status",
                "admin.config.show",
                "admin.subject.list",
                "session.prompt"
            ],
            "the hand-copied list in the class test above must match the constant"
        );
        assert!(
            all_dispatch(real),
            "every grantable term must dispatch to a real arm — a grantable \
             term with NoBehaviour is granted-but-unbuilt, which ADR-0010 \
             defines out of existence"
        );
        // The discriminator discriminates: a known ungrantable term has no
        // real arm, so the helper must say false — otherwise the assert above
        // is vacuous.
        assert!(
            !all_dispatch(&["admin.contain"]),
            "all_dispatch must return false for an unbuilt term"
        );
    }

    /// `admin.config.show` DOES dispatch now (#162 Phase 2). Its response
    /// carries the already-redacted view; the redaction rule itself is
    /// `maknae_config::Document::disclosable_view` and is tested there.
    #[test]
    fn config_show_dispatches_to_its_own_arm() {
        assert_eq!(
            dispatch_verb(&Verb::AdminConfigShow),
            Dispatch::ConfigShowRequested
        );
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
        assert_eq!(
            verb_to_action(&Verb::Read {
                path: "/x".into(),
                conversation: None
            }),
            "fs.read"
        );
    }

    #[test]
    fn verb_action_names_are_pairwise_distinct() {
        let p = verb_to_action(&Verb::Ping);
        let w = verb_to_action(&Verb::Whoami);
        let r = verb_to_action(&Verb::Read {
            path: "/x".into(),
            conversation: None,
        });
        assert_ne!(p, w);
        assert_ne!(p, r);
        assert_ne!(w, r);
    }

    #[test]
    fn a_read_dispatches_to_the_attempt_lane() {
        assert_eq!(
            dispatch_verb(&Verb::Read {
                path: "/home/op/a".into(),
                conversation: None,
            }),
            Dispatch::MutationRequested
        );
        assert_ne!(
            dispatch_verb(&Verb::Read {
                path: "/x".into(),
                conversation: None
            }),
            Dispatch::Pong
        );
        assert_ne!(
            dispatch_verb(&Verb::Read {
                path: "/x".into(),
                conversation: None
            }),
            Dispatch::WhoamiRequested
        );
    }

    #[test]
    fn filesystem_mutations_require_the_dedicated_intent_path() {
        for verb in all_verbs()
            .into_iter()
            .filter(|v| matches!(verb_to_action(v), "fs.write" | "fs.delete" | "fs.mkdir"))
        {
            assert_eq!(dispatch_verb(&verb), Dispatch::MutationRequested);
        }
        assert_ne!(dispatch_verb(&Verb::FsMove), Dispatch::MutationRequested);
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
        let r = build_authz_request(&Verb::Ping, 0, maknae_security::Lane::Local, None);
        assert_eq!(
            r.subject.0.get("uid"),
            Some(&maknae_security::AttrValue::Int(0))
        );
        let r = build_authz_request(&Verb::Whoami, u32::MAX, maknae_security::Lane::Local, None);
        assert_eq!(
            r.subject.0.get("uid"),
            Some(&maknae_security::AttrValue::Int(i64::from(u32::MAX)))
        );
    }

    #[test]
    fn request_action_matches_taxonomy_and_resource_is_empty_for_non_read() {
        let r = build_authz_request(&Verb::Whoami, 501, maknae_security::Lane::Local, None);
        assert_eq!(r.action.0, "admin.whoami");
        assert!(r.resource.0.is_empty());
        // Context is no longer empty: every request carries its lane (ADR-0009 D8).
        assert_eq!(
            r.context.0.get(maknae_security::CONTEXT_DAC_LANE),
            Some(&maknae_security::AttrValue::Str("local".into()))
        );
    }

    #[test]
    fn read_request_carries_the_path_resource() {
        let r = build_authz_request(
            &Verb::Read {
                path: "/home/op/n".into(),
                conversation: None,
            },
            501,
            maknae_security::Lane::Local,
            None,
        );
        assert_eq!(r.action.0, "fs.read");
        assert_eq!(
            r.resource.0.get("path"),
            Some(&maknae_security::AttrValue::Str("/home/op/n".into()))
        );
    }

    /// ADR-0009 decision 8's load-bearing control, and the ADR calls it the single
    /// most important one in the design: **the lane comes from the ACCEPTING LISTENER
    /// and from nothing else.**
    ///
    /// A filesystem attempt is decided only on `local`: a remote peer has no uid on
    /// this host to perform it. So the lane must never follow anything the client
    /// controls, and the client controls the verb.
    #[test]
    fn the_lane_comes_from_the_listener_and_client_content_cannot_change_it() {
        use maknae_security::{AttrValue, Lane, CONTEXT_DAC_LANE};

        // The same verb on both lanes: the stamp follows the ARGUMENT, so it cannot
        // be a function of anything the client sent.
        let local = build_authz_request(&Verb::Whoami, 501, Lane::Local, None);
        let remote = build_authz_request(&Verb::Whoami, 501, Lane::Remote, None);
        assert_eq!(
            local.context.0.get(CONTEXT_DAC_LANE),
            Some(&AttrValue::Str("local".into()))
        );
        assert_eq!(
            remote.context.0.get(CONTEXT_DAC_LANE),
            Some(&AttrValue::Str("remote".into()))
        );

        // A client putting "remote" in the one field it controls gets nowhere.
        let smuggled = build_authz_request(
            &Verb::Read {
                path: "/home/op/remote".into(),
                conversation: None,
            },
            501,
            Lane::Local,
            None,
        );
        assert_eq!(
            smuggled.context.0.get(CONTEXT_DAC_LANE),
            Some(&AttrValue::Str("local".into())),
            "client-supplied content must never influence the lane"
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
    // ---- delegated_plan / read_budget (T1: the decision
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
    fn delegated_plan_names_all_three_proofs() {
        let req = delegated_plan(std::path::Path::new("/home/op"), 501);
        assert_eq!(
            req.confined_beneath,
            std::path::Path::new("/home/op"),
            "confinement is the enrolled home, and it is not optional"
        );
        assert_eq!(
            req.root_required.owner,
            Some(501),
            "the alias-planting boundary survives the anchor open (ADR-0009 D7)"
        );
        assert_eq!(
            req.root_required.mode_mask,
            Some(0o022),
            "no group/other write on home"
        );
        assert!(
            req.target.nlink_exactly_one,
            "load-bearing three ways (ADR-0009 D5)"
        );
        assert!(req.target.regular_file, "no fifo/device");
        assert_eq!(req.target.max_bytes, None);
        // NOT a gap: the OS answers at the subject's re-open, and recomputing the
        // mode algebra here is what the operator forbade (ADR-0009 D1).
        assert_eq!(req.target.owner, None);
        assert_eq!(req.target.mode_mask, None);
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
            Verb::SessionPrompt {
                conversation: "c".into(),
                turns: vec![],
            },
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
                conversation: None,
            },
            Verb::FsWrite {
                path: "/x".into(),
                content_length: 0,
                mode: maknae_proto::WriteMode::Existing,
                conversation: None,
            },
            Verb::FsDelete {
                path: "/x".into(),
                recursive: false,
            },
            Verb::FsMove,
            Verb::FsList,
            Verb::FsStat,
            Verb::FsMkdir {
                path: "/x".into(),
                parents: false,
                components: vec!["x".into()],
            },
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

    /// #148: every term is EXACTLY one of control plane or content-bearing, and
    /// the split is what the vocabulary says it is. Pinned over `all_verbs()`
    /// (57 client action terms) + the two `kernel.*` pseudo-actions, AND
    /// `all_verbs()` is cross-checked against `ci/gates/verb-manifest.txt`'s
    /// `action` rows (critical-review round 1 of PR B: the manifest is
    /// extracted from `verb_to_action`, which the compiler forces a new
    /// variant into; `all_verbs()` is hand-written and was not) -- so a new
    /// verb cannot land unpartitioned: an `admin.*` term is control plane;
    /// every `fs.*`/`session.*`/`terminal.*`/`mcp.*` term moves content and is
    /// evaluated against the ceiling.
    #[test]
    fn every_verb_partitions_into_control_plane_or_content() {
        use crate::ceiling_authz::is_control_plane;
        let manifest = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../ci/gates/verb-manifest.txt"),
        )
        .expect("the verb manifest is readable from the crate root");
        let mut manifest_actions: Vec<&str> = manifest
            .lines()
            .filter(|l| l.starts_with("action\t"))
            .map(|l| l.split('\t').nth(1).unwrap())
            .collect();
        manifest_actions.sort_unstable();
        let mut ours: Vec<&str> = all_verbs().iter().map(|v| verb_to_action(v)).collect();
        ours.sort_unstable();
        assert_eq!(
            ours, manifest_actions,
            "all_verbs() and verb-manifest.txt disagree -- a verb landed in one and not the other"
        );
        let mut control = 0usize;
        let mut content = 0usize;
        for v in all_verbs() {
            let action = verb_to_action(&v);
            let expected_control = action.starts_with("liveness.") || action.starts_with("admin.");
            assert_eq!(
                is_control_plane(action),
                expected_control,
                "{action} is {} but the operand says otherwise",
                if expected_control {
                    "control plane"
                } else {
                    "content"
                }
            );
            if expected_control {
                control += 1;
            } else {
                content += 1;
            }
        }
        for k in KERNEL_ACTIONS {
            assert!(
                is_control_plane(k),
                "kernel pseudo-action {k} is control plane"
            );
        }
        // Both halves are non-empty -- a partition that put everything on one
        // side would satisfy the loop above vacuously if the expectation were
        // wrong in the same direction.
        // Both halves non-empty -- a partition that put everything on one side
        // would satisfy the loop vacuously if the expectation were wrong in the
        // same direction. (A `control + content == len` assert was removed as
        // tautological: the loop increments exactly once per verb.)
        assert!(
            control > 0 && content > 0,
            "control={control} content={content}"
        );
    }

    /// The kernel actions have no `Verb` variant (#67 D2) but are still
    /// PDP-decided, so they must resolve to the `kernel` class like any other
    /// term — and must never collide with a client-reachable action string.
    #[test]
    fn kernel_actions_resolve_to_the_kernel_class_and_collide_with_nothing() {
        let client: Vec<&str> = all_verbs().iter().map(verb_to_action).collect();
        for a in KERNEL_ACTIONS {
            assert_eq!(
                a.split('.').next(),
                Some("kernel"),
                "{a} must be a kernel action"
            );
            assert!(
                !client.contains(&a),
                "{a} collides with a client-reachable term"
            );
        }
    }

    /// Claim: a parameterless `[N]` term supplies NO resource attribute, so
    /// `decide_fs` cannot reach the capability grammar with a path and an
    /// unbuilt `fs.*` term can never match `Read(~/**)`. That safety is
    /// STRUCTURAL, and this is what makes it provable: it was previously
    /// asserted in a PR body with `Whoami` as its only test case.
    #[test]
    fn only_read_carries_a_resource_attribute() {
        for v in all_verbs() {
            let r = build_authz_request(&v, 501, maknae_security::Lane::Local, None);
            if matches!(v, Verb::Read { .. }) {
                assert!(
                    r.resource.0.str("path").is_some(),
                    "fs.read must carry its path"
                );
            } else {
                assert!(
                    r.resource.0.str("path").is_none(),
                    "{} must carry NO path — the fs safety argument rests on it",
                    verb_to_action(&v)
                );
            }
        }
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
            (
                Verb::Read {
                    path: "/x".into(),
                    conversation: None,
                },
                "Read",
            ),
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
