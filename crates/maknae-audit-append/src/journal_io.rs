//! The journald socket (ADR-0019 D3, #189) — the I/O half of the appender.
//!
//! T3 by tier: this file is `connect`/`send` and nothing else. The wire format
//! it sends lives in [`crate::journal`] (T1, mutation-proven).
use crate::journal::{encode, PrimaryOutcome};
use crate::record::AuditRecord;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

/// The systemd native journal submission socket.
///
/// Its only caller is `AuditSink::open` (Task 3); the tests here use temp
pub(crate) const DEFAULT_JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

/// A best-effort, non-blocking journald mirror.
///
/// **Best-effort means every failure is dropped, never propagated.** Its
/// absence can never mask or convert a primary-sink outcome (ADR-0019 D3).
///
/// **Non-blocking is the whole freeze-proofing.** `O_NONBLOCK` means a full
/// journald buffer returns `EAGAIN` and the record is dropped instead of
/// stalling the audit path. systemd's own client falls back to a sealed `memfd`
/// over `SCM_RIGHTS` for oversize datagrams; we deliberately do not — records
/// are small, and oversize implies a pathological `au3_1`.
///
/// **Absence is structural, not `cfg`-gated.** `connect()` to a missing socket
/// fails, so on darwin (no journald) and on non-systemd Linux the mirror is
/// simply `None` and every append is a no-op — identical code everywhere.
///
/// Known limitation, accepted: the socket is connected once at construction, so
/// a journald restart (e.g. on package upgrade) silences the mirror until the
/// daemon restarts. Acceptable for a sink whose failure is already silent by
/// design; recorded in the PR body rather than worked around here.
pub(crate) struct JournalMirror {
    sock: UnixDatagram,
}

impl JournalMirror {
    /// `None` — a named, greppable absence — when the socket cannot be reached.
    pub(crate) fn open(path: &Path) -> Option<Self> {
        let sock = UnixDatagram::unbound().ok()?;
        sock.set_nonblocking(true).ok()?;
        sock.connect(path).ok()?;
        Some(Self { sock })
    }

    /// Encode and send. Every error path is a deliberate drop.
    pub(crate) fn mirror(&self, rec: &AuditRecord, primary: PrimaryOutcome) {
        let Ok(bytes) = encode(rec, primary) else {
            return;
        };
        let _ = self.sock.send(&bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{AuditRecord, Integrity, Outcome, Source, Subject, Where};
    use std::os::unix::net::UnixDatagram;

    /// The same literal record `journal.rs`'s tests build. It cannot be shared:
    /// that module is private to its own file.
    fn rec() -> AuditRecord {
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
                user: Some("byeori".into()),
                plane_uri_san: None,
            },
            action: "fs.read".into(),
            object: Some("/home/byeori/.ssh/id_rsa".into()),
            object_requested: None,
            outcome: Outcome {
                result: "deny".into(),
                reason: "policy denied".into(),
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

    /// A REAL bound receiving socket — not a stub. Works on Linux and macOS
    /// alike, so the round-trip is covered on every CI lane.
    fn receiver(dir: &std::path::Path) -> (UnixDatagram, std::path::PathBuf) {
        let path = dir.join("journal.sock");
        let rx = UnixDatagram::bind(&path).unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        (rx, path)
    }

    #[test]
    fn round_trips_a_record_through_a_real_socket() {
        let dir = tempfile::tempdir().unwrap();
        let (rx, path) = receiver(dir.path());
        let m = JournalMirror::open(&path).expect("connect to a bound socket must succeed");
        m.mirror(&rec(), PrimaryOutcome::Ok);
        let mut buf = vec![0u8; 64 * 1024];
        let n = rx.recv(&mut buf).expect("datagram must arrive");
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(text.contains("SYSLOG_IDENTIFIER=maknaed"), "got: {text}");
        assert!(text.contains("MAKNAE_PRIMARY=ok"), "got: {text}");
    }

    #[test]
    fn absent_socket_is_a_named_none_not_an_error() {
        // The darwin case, structurally: /run/systemd/journal/socket does not
        // exist there, so no cfg gate is needed anywhere in this crate.
        let dir = tempfile::tempdir().unwrap();
        assert!(JournalMirror::open(&dir.path().join("does-not-exist.sock")).is_none());
    }

    #[test]
    fn mirroring_after_the_peer_is_gone_drops_without_panicking() {
        // Exercises the `let _ = send(..)` DROP path -- a connected socket whose
        // peer is gone returns ECONNREFUSED. This is the real failure path, not
        // the None branch.
        let dir = tempfile::tempdir().unwrap();
        let (rx, path) = receiver(dir.path());
        let m = JournalMirror::open(&path).unwrap();
        drop(rx);
        std::fs::remove_file(&path).ok();
        m.mirror(&rec(), PrimaryOutcome::WriteFailed); // must not panic
    }

    #[test]
    fn an_oversize_datagram_is_dropped_without_panicking() {
        // Spec negative control 3. macOS pins net.local.dgram.maxdgram at 2048;
        // Linux is larger but finite. Either way the send fails and MUST be
        // swallowed -- and nothing must arrive.
        let dir = tempfile::tempdir().unwrap();
        let (rx, path) = receiver(dir.path());
        let m = JournalMirror::open(&path).unwrap();
        let mut r = rec();
        r.au3_1 = serde_json::json!({ "pad": "x".repeat(512 * 1024) });
        m.mirror(&r, PrimaryOutcome::Ok);
        let mut buf = vec![0u8; 1024];
        assert!(
            rx.recv(&mut buf).is_err(),
            "an oversize datagram must be dropped, not delivered"
        );
    }

    /// LINUX-ONLY EVIDENCE. Measured on darwin: a BLOCKING AF_UNIX/SOCK_DGRAM
    /// send to an undrained peer returns ENOBUFS after ~6 sends (BSD `uipc_send`
    /// does not sleep; `net.local.dgram.recvspace` is 4096), so this test would
    /// pass there even with `set_nonblocking(false)` and prove nothing. Linux
    /// `unix_dgram_sendmsg` DOES call `unix_wait_for_peer()`, so the assertion
    /// is real there and only there.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_full_receive_buffer_drops_rather_than_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let (_rx, path) = receiver(dir.path());
        let m = JournalMirror::open(&path).unwrap();
        let r = rec();
        let start = std::time::Instant::now();
        for _ in 0..10_000 {
            m.mirror(&r, PrimaryOutcome::Ok);
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "mirror blocked on a full peer buffer — O_NONBLOCK is not in effect"
        );
    }
}
