//! The macOS unified-log mirror (spec D1/D4/D5, #222) — the I/O half.
//!
//! T3 by tier: this file is `openlog`/`syslog` and nothing else. The line format
//! it sends, and every decision in it, lives in [`crate::syslog_fmt`] (T1,
//! mutation-proven).
//!
//! **No C shim, no FFI of our own.** `syslog(3)` reaches the unified log through
//! libSystem, called via `nix`'s safe wrapper — a crate already depended on. An
//! `os_log` binding would require a C shim (`wrapper.c` + `build.rs`), which
//! ADR-0002's 100% Rust TCB does not permit on a production target.
//!
//! **The verbatim payload is safe because of ONE line in `nix`.**
//! `nix-0.31.3/src/syslog.rs:82-96` calls `libc::syslog(priority, "%s", message)`.
//! That `%s` indirection is why a subject-controlled `object` or a
//! deployer-supplied `au3_1` containing `%n`/`%s` inside `MAKNAE_RECORD` is not
//! a format-string vulnerability in a privileged daemon. Never hand-roll this
//! call. (The same note is in `Cargo.toml` beside the feature, where the pin is
//! reviewed.)
//!
//! **On the ident's lifetime, stated so nobody "fixes" it into something
//! load-bearing.** `nix`'s non-Linux `openlog` hands `libc::openlog` a pointer
//! into a TEMPORARY `CString` built by `with_nix_path` (`syslog.rs:45-61`), and
//! nix's own comment quotes the man page: *"probably stored as-is ... if the
//! string it points to ceases to exist, the results are undefined."* Passing
//! `Some("maknaed")` does not avoid this — the `'static` is on the Rust side,
//! the pointer is to the temporary. Empirically inert (probed with a dropped
//! heap ident plus churn: no crash, no corruption) and MOOT anyway, because the
//! unified log DISCARDS the ident entirely. That is precisely why the identity
//! token is literal text inside the message instead.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use crate::journal::PrimaryOutcome;
use crate::record::AuditRecord;
use crate::syslog_fmt::format_record;
use nix::syslog::{openlog, syslog, Facility, LogFlags, Priority, Severity};
use std::path::Path;

/// A best-effort macOS unified-log mirror.
///
/// **No state:** `syslog(3)` keeps its own process-wide connection, so there is
/// nothing to hold. The unit struct exists to give `AuditSink` one shape across
/// platforms.
///
/// **Best-effort means every failure is dropped, never propagated.** Its absence
/// or failure can never mask or convert a primary-sink outcome (ADR-0019 D3).
///
/// **Severity is pinned to `LOG_WARNING`, unconditionally — spec D4.** Measured
/// on macOS 26.6.2: `LOG_WARNING` maps to the unified log's **Default** message
/// type, visible in a plain `log show` and persisted to disk. `LOG_INFO` maps to
/// the **info** type: hidden without `--info` and memory-backed, so a `permit`
/// record might never reach disk at all. Severity is therefore NOT where this
/// mirror carries deny/permit — `MAKNAE_OUTCOME` inside the line is.
///
/// **D5's non-blocking property is ASSUMED on darwin, not verified.** The Linux
/// half buys it with `set_nonblocking(true)` and proves it with a full-buffer
/// regression test. `syslog(3)` exposes no `O_NONBLOCK` analogue and `logd` is
/// not saturable from userspace, so the timing test below is a gross-stall
/// detector only. If `logd` ever applies real backpressure, this call is
/// synchronous on a tokio worker. Recorded here, in the ADR and in the PR body
/// rather than left to look like the Linux proof carried over.
pub(crate) struct SyslogMirror;

impl SyslogMirror {
    /// Open the process-wide syslog connection.
    ///
    /// `_ignored` exists so `AuditSink::open` keeps ONE body across platforms;
    /// `syslog(3)` has no endpoint to point at.
    ///
    /// **Be honest about the `None`.** `openlog` can only fail on an interior
    /// NUL in the ident, and `"maknaed"` has none — so this `Option` is
    /// effectively infallible and spec D5's "absence is a named `None`" has no
    /// real macOS referent. It is `Option` for shape parity with
    /// [`crate::journal_io::JournalMirror::open`], not because it guards
    /// anything.
    pub(crate) fn open(_ignored: &Path) -> Option<Self> {
        // The ONLY platform difference in this module. `nix` gives Linux
        // `openlog(Option<&'static CStr>, ..)` (syslog.rs:20-21) and everything
        // else `openlog(Option<&S: AsRef<OsStr>>, ..)` (:45-46); `CStr` does not
        // implement `AsRef<OsStr>`. Always `Some(..)`, never `None` — the
        // non-Linux `None` cannot infer `S`.
        #[cfg(target_os = "linux")]
        let ident: Option<&'static std::ffi::CStr> = Some(c"maknaed");
        #[cfg(not(target_os = "linux"))]
        let ident: Option<&str> = Some("maknaed");

        // LOG_PID: inert on the unified log (the PID is always present) but it
        // keeps syslog(3)'s contract honest, and the cap was measured with it
        // set. LOG_LOCAL0: an application facility, not a system one.
        openlog(ident, LogFlags::LOG_PID, Facility::LOG_LOCAL0).ok()?;
        Some(Self)
    }

    /// Format and send. Every error path is a deliberate drop.
    ///
    /// An oversize record (`Ok(None)`) is dropped rather than truncated — see
    /// [`crate::syslog_fmt::MACOS_SYSLOG_MAX`]. `syslog` itself returns
    /// `Err(EINVAL)` only on an interior NUL, which `canonical_json` escapes to
    /// its six-character JSON form, so that path is unreachable; the result is
    /// discarded either way. There is no length limit from `nix`: a message of
    /// 1024 bytes or more routes through `with_nix_path_allocating`
    /// (`nix-0.31.3/src/lib.rs:351-362`) with a heap `CString` and no error, so
    /// the 1015-byte cap is the PLATFORM's, not the crate's.
    pub(crate) fn mirror(&self, rec: &AuditRecord, primary: PrimaryOutcome) {
        let Ok(Some(line)) = format_record(rec, primary) else {
            return;
        };
        let _ = syslog(
            Priority::new(Severity::LOG_WARNING, Facility::LOG_LOCAL0),
            &line,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::PrimaryOutcome;

    fn rec(reason: &str) -> crate::record::AuditRecord {
        use crate::record::{AuditRecord, Integrity, Outcome, Source, Subject, Where};
        AuditRecord {
            ts: "2026-09-05T00:00:00.000Z".into(),
            event: "request".into(),
            where_: Where {
                host: "maknaed-01".into(),
                component: "kernel".into(),
                socket: "/run/maknae/plane.sock".into(),
            },
            source: Source {
                uid: 1000,
                gid: Some(1000),
                pid: Some(42),
                plane_uri_san: None,
            },
            subject: Subject {
                user: Some("alice".into()),
                plane_uri_san: None,
            },
            action: "fs.read".into(),
            object: Some("/home/alice/.ssh/id_rsa".into()),
            object_requested: None,
            mutation: None,
            egress: None,
            outcome: Outcome {
                result: "deny".into(),
                reason: reason.into(),
                posture: "unauthorized".into(),
            },
            session_id: 7,
            seq: 3,
            au3_1: serde_json::Value::Null,
            integrity: Integrity {
                prev_hash: None,
                sig: None,
            },
        }
    }

    #[test]
    fn mirroring_never_panics_across_every_outcome_and_an_oversize_record() {
        let m = SyslogMirror::open(std::path::Path::new(""))
            .expect("openlog is infallible for a NUL-free ident");
        for p in [
            PrimaryOutcome::Ok,
            PrimaryOutcome::RefusedBreakerOpen,
            PrimaryOutcome::RefusedAtCapacity,
            PrimaryOutcome::WriteFailed,
        ] {
            m.mirror(&rec("policy denied"), p);
        }
        let mut big = rec("no");
        big.au3_1 = serde_json::json!({ "pad": "x".repeat(64 * 1024) });
        // Dropped by the formatter's cap; must not panic.
        m.mirror(&big, PrimaryOutcome::Ok);
    }

    #[test]
    fn mirroring_a_burst_does_not_stall_the_caller_macos_and_linux_alike() {
        // The macOS analogue of journal_io's
        // `a_full_receive_buffer_drops_rather_than_blocking` -- and it is
        // WEAKER, deliberately, so nobody reads it as the same proof.
        //
        // `syslog(3)` has no `O_NONBLOCK` analogue to set, and `logd` is not
        // saturable from userspace, so this cannot demonstrate backpressure the
        // way the Linux test does. It is a GROSS-STALL detector: 2000 records
        // through the real call must not take minutes. Spec D5's non-blocking
        // property remains ASSUMED on darwin, not verified -- stated in the
        // struct doc, the ADR and the PR body.
        let m = SyslogMirror::open(std::path::Path::new("")).expect("infallible");
        let start = std::time::Instant::now();
        for i in 0..2000u64 {
            let mut r = rec("burst");
            r.seq = i;
            m.mirror(&r, PrimaryOutcome::Ok);
        }
        let elapsed = start.elapsed();
        // Generous by two orders of magnitude: measured well under a second on
        // both an M-series Mac and a CI Linux runner. A ceiling this loose does
        // not flake on a loaded runner, and still catches a call that has begun
        // blocking.
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "2000 mirrored records took {elapsed:?} -- the syslog call is stalling the audit path"
        );
    }
}
