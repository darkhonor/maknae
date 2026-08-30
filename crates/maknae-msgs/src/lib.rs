//! maknae-msgs — compiled-in en_US/ko_KR operator-facing message catalog
//! (spec §4.3).
//!
//! Zero-dependency (std-only) leaf crate. Every operator-facing string a
//! later task needs to show a human routes through `MsgId` + `msg()` so
//! locale selection and message content are centralized instead of scattered
//! across ad hoc `format!()` call sites in the daemon/CLI.

mod catalog_en_us;
mod catalog_ko_kr;

/// Operator-facing message identifiers. Grown per call site as later PR-J1
/// tasks wire up their message needs — this is a starter set covering the
/// enroll flow and daemon authz/posture refusals named in the plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MsgId {
    EnrollStarted,
    /// Carries a `{user}` placeholder — required (spec ambiguity resolution
    /// §10.7) so a constant-returning mutant on the catalog match arms
    /// cannot satisfy both the non-empty and placeholder-parity assertions.
    EnrollGroupAdded,
    EnrollAlreadyMember,
    EnrollFailed,
    AuthzDenied,
    AuthzPostureRefused,
    AuthzUnknownSubject,
    DaemonNotRunning,
    DaemonStartFailed,
    /// PR-J1 Task 7 (spec §5.4): the boot-time capability-grant config gate
    /// (`authz.yaml` + the enrolled `principal`) could not be resolved — the
    /// daemon refuses to start.
    AuthzConfigRefused,
    /// PR-J1 Task 7 (spec §5.2): a non-fatal boot warning — this boot's
    /// credential posture is not hardware/OS-root-of-trust sealed.
    PostureDegraded,

    // ---- PR-J1 Task 8 (`maknae enroll`, spec §4.1) --------------------
    /// Preflight (euid/`$SUDO_UID`/`$SUDO_USER`) rejected the invocation.
    EnrollPreflightFailed,
    /// The post-drop operator-context capability probe (spec §4.1 step 1)
    /// started, before any Vault mutation.
    EnrollProbeStarted,
    /// The capability probe failed — enroll aborts before minting anything.
    EnrollProbeFailed,
    /// The capability probe succeeded.
    EnrollProbeOk,
    /// The interactive no-echo Vault token prompt.
    EnrollTokenPrompt,
    /// Vault RoleID/SecretID/CA-chain operations (spec §4.1 step 3) started.
    EnrollVaultOpsStarted,
    /// Writing the daemon's `/etc/maknae` artifact set (spec §4.1 step 4).
    EnrollWritingDaemonConfig,
    /// Sealing the daemon's SecretID (spec §4.1 step 5).
    EnrollSealingDaemonCredential,
    /// Re-exec'd operator-context CLI provisioning (spec §4.1 step 7).
    EnrollProvisioningCli,
    /// The final posture summary. Carries a `{cli_dir}` placeholder.
    EnrollPostureSummary,
    /// Reminder that group membership is not live in pre-existing sessions.
    EnrollReloginNote,
    /// Pointer to the operator's own `systemctl enable --now maknaed` act.
    EnrollEnableDaemonHint,
    /// A pre-existing `enroll-state.yaml` was found — rotating (spec §4.1,
    /// unconditional-rotate semantics on re-enroll).
    EnrollRotating,
    /// A failure after minting destroyed the just-minted accessors (rollback).
    EnrollRollbackDestroyed,
    /// The post-mint rollback destroy (`destroy_and_report`) was attempted
    /// but one or more accessors FAILED to destroy — distinct from
    /// [`MsgId::EnrollRollbackDestroyed`] so the audit-facing line does not
    /// misleadingly claim success when the per-failure detail underneath
    /// says otherwise. Non-fatal (best-effort rollback stays non-fatal);
    /// this only fixes the message's honesty.
    EnrollRollbackDestroyPartial,
    /// The operator-context helper's self-verification (euid/egid) failed.
    HelperContextMismatch,
    /// The operator-context helper still carries root's supplementary groups —
    /// the exact "helper still holding root's groups" failure spec §4.1 names.
    HelperStillPrivileged,
}

/// Every `MsgId` variant, in declaration order. `all_slice_is_exhaustive`
/// guards this against drifting out of sync with the enum.
pub const ALL: &[MsgId] = &[
    MsgId::EnrollStarted,
    MsgId::EnrollGroupAdded,
    MsgId::EnrollAlreadyMember,
    MsgId::EnrollFailed,
    MsgId::AuthzDenied,
    MsgId::AuthzPostureRefused,
    MsgId::AuthzUnknownSubject,
    MsgId::DaemonNotRunning,
    MsgId::DaemonStartFailed,
    MsgId::AuthzConfigRefused,
    MsgId::PostureDegraded,
    MsgId::EnrollPreflightFailed,
    MsgId::EnrollProbeStarted,
    MsgId::EnrollProbeFailed,
    MsgId::EnrollProbeOk,
    MsgId::EnrollTokenPrompt,
    MsgId::EnrollVaultOpsStarted,
    MsgId::EnrollWritingDaemonConfig,
    MsgId::EnrollSealingDaemonCredential,
    MsgId::EnrollProvisioningCli,
    MsgId::EnrollPostureSummary,
    MsgId::EnrollReloginNote,
    MsgId::EnrollEnableDaemonHint,
    MsgId::EnrollRotating,
    MsgId::EnrollRollbackDestroyed,
    MsgId::EnrollRollbackDestroyPartial,
    MsgId::HelperContextMismatch,
    MsgId::HelperStillPrivileged,
];

/// Supported locales. Unknown/unset environment locale falls back to `EnUs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Locale {
    EnUs,
    KoKr,
}

/// Resolve the active locale from the environment: `LC_MESSAGES` first, then
/// `LANG`. A `ko`-prefixed value (e.g. `ko_KR.UTF-8`) selects `KoKr`; any
/// other non-empty value at whichever variable is checked first is
/// authoritative and selects `EnUs` without falling through to the next
/// variable. Unset/empty on both falls back to `EnUs`.
pub fn detect_locale() -> Locale {
    for var in ["LC_MESSAGES", "LANG"] {
        if let Ok(val) = std::env::var(var) {
            if val.starts_with("ko") {
                return Locale::KoKr;
            }
            if !val.is_empty() {
                return Locale::EnUs;
            }
        }
    }
    Locale::EnUs
}

/// Look up the catalog string for `id` in `locale`.
pub fn msg(locale: Locale, id: MsgId) -> &'static str {
    match locale {
        Locale::EnUs => catalog_en_us::text(id),
        Locale::KoKr => catalog_ko_kr::text(id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Extract the sorted, deduplicated set of `{token}` placeholder names in
    // `s`. Test-only: it exists to prove parity between the en_US/ko_KR
    // catalogs, not as a public interpolation utility (call sites substitute
    // via `str::replace`, per spec §4.3).
    fn placeholders(s: &str) -> Vec<&str> {
        let mut found = Vec::new();
        let mut rest = s;
        while let Some(start) = rest.find('{') {
            let after = &rest[start + 1..];
            if let Some(end) = after.find('}') {
                found.push(&after[..end]);
                rest = &after[end + 1..];
            } else {
                break;
            }
        }
        found.sort_unstable();
        found.dedup();
        found
    }

    // `LC_MESSAGES`/`LANG` are process-wide; without this lock the locale
    // tests below can interleave across cargo's multi-threaded test runner
    // (env-lock pattern per bins/maknae/src/cli.rs:250 ENV_LOCK).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn locale_detection_prefers_lc_messages() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("LC_MESSAGES", "ko_KR.UTF-8");
        std::env::set_var("LANG", "en_US.UTF-8");
        assert_eq!(detect_locale(), Locale::KoKr);
        std::env::remove_var("LC_MESSAGES");
        std::env::remove_var("LANG");
    }

    #[test]
    fn unknown_locale_falls_back_to_en_us() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("LC_MESSAGES", "de_DE.UTF-8");
        std::env::remove_var("LANG");
        assert_eq!(detect_locale(), Locale::EnUs);
        std::env::remove_var("LC_MESSAGES");
    }

    #[test]
    fn unset_locale_falls_back_to_en_us() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("LC_MESSAGES");
        std::env::remove_var("LANG");
        assert_eq!(detect_locale(), Locale::EnUs);
    }

    #[test]
    fn msg_dispatches_to_correct_locale_catalog() {
        // Content-pinning: the parity test only compares placeholder *sets*
        // (symmetric by construction) and cargo-mutants doesn't mutate this
        // match-arm-call shape, so a transposed dispatch arm (EnUs ->
        // catalog_ko_kr::text, KoKr -> catalog_en_us::text) is otherwise
        // invisible to both. Pin actual language identity so it fails RED.
        let en = msg(Locale::EnUs, MsgId::EnrollStarted);
        let ko = msg(Locale::KoKr, MsgId::EnrollStarted);
        assert_ne!(en, ko);
        assert_eq!(en, "Starting enrollment");
        assert_eq!(ko, "등록을 시작해요");
    }

    #[test]
    fn empty_lc_messages_falls_through_to_lang() {
        // A set-but-empty LC_MESSAGES is neither a ko match nor a non-empty
        // "authoritative" value — it must fall through to LANG rather than
        // short-circuiting to EnUs.
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("LC_MESSAGES", "");
        std::env::set_var("LANG", "ko_KR.UTF-8");
        assert_eq!(detect_locale(), Locale::KoKr);
        std::env::remove_var("LC_MESSAGES");
        std::env::remove_var("LANG");
    }

    #[test]
    fn every_msg_nonempty_and_placeholder_parity() {
        for &id in ALL {
            let (en, ko) = (msg(Locale::EnUs, id), msg(Locale::KoKr, id));
            assert!(!en.is_empty() && !ko.is_empty(), "{id:?}");
            assert_eq!(placeholders(en), placeholders(ko), "{id:?}");
        }
    }

    #[test]
    fn all_slice_is_exhaustive() {
        // A new variant added without a matching ALL entry breaks this
        // exhaustive match (compile error) before it can silently ship
        // without catalog coverage, and VARIANT_COUNT catches an ALL entry
        // added/removed without a matching enum edit.
        fn assert_covered(id: MsgId) {
            match id {
                MsgId::EnrollStarted
                | MsgId::EnrollGroupAdded
                | MsgId::EnrollAlreadyMember
                | MsgId::EnrollFailed
                | MsgId::AuthzDenied
                | MsgId::AuthzPostureRefused
                | MsgId::AuthzUnknownSubject
                | MsgId::DaemonNotRunning
                | MsgId::DaemonStartFailed
                | MsgId::AuthzConfigRefused
                | MsgId::PostureDegraded
                | MsgId::EnrollPreflightFailed
                | MsgId::EnrollProbeStarted
                | MsgId::EnrollProbeFailed
                | MsgId::EnrollProbeOk
                | MsgId::EnrollTokenPrompt
                | MsgId::EnrollVaultOpsStarted
                | MsgId::EnrollWritingDaemonConfig
                | MsgId::EnrollSealingDaemonCredential
                | MsgId::EnrollProvisioningCli
                | MsgId::EnrollPostureSummary
                | MsgId::EnrollReloginNote
                | MsgId::EnrollEnableDaemonHint
                | MsgId::EnrollRotating
                | MsgId::EnrollRollbackDestroyed
                | MsgId::EnrollRollbackDestroyPartial
                | MsgId::HelperContextMismatch
                | MsgId::HelperStillPrivileged => {}
            }
        }
        const VARIANT_COUNT: usize = 28;
        assert_eq!(ALL.len(), VARIANT_COUNT);
        for &id in ALL {
            assert_covered(id);
        }
    }

    #[test]
    fn placeholder_extraction() {
        assert_eq!(placeholders("no tokens here"), Vec::<&str>::new());
        assert_eq!(
            placeholders("Added {user} to {group}"),
            vec!["group", "user"]
        );
        assert_eq!(placeholders("{a}{a}"), vec!["a"]);
        assert_eq!(placeholders("{unterminated"), Vec::<&str>::new());
    }

    #[test]
    fn enroll_group_added_carries_user_placeholder() {
        // Required by spec (§10.7 ambiguity resolution): at least one MsgId
        // must carry a placeholder so a constant-returning mutant on the
        // catalog match arms can't satisfy the parity assertion.
        assert_eq!(
            placeholders(msg(Locale::EnUs, MsgId::EnrollGroupAdded)),
            vec!["user"]
        );
    }
}
