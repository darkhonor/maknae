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
}

/// Resolve a verb to its dispatch. `Ping → Pong`, `Whoami → WhoamiRequested`.
pub fn dispatch_verb(verb: &Verb) -> Dispatch {
    match verb {
        Verb::Ping => Dispatch::Pong,
        Verb::Whoami => Dispatch::WhoamiRequested,
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
}
