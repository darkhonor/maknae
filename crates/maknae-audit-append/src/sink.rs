//! The append-only JSONL audit sink (ADR-0019) + the `AuditEmit` trait the
//! run-loop (Task 7) is generic over.
//!
//! Fail-closed (AU-5): [`AuditSink::open`] errors if the primary JSONL file
//! cannot be opened at boot; [`AuditSink::append`] errors on a primary write
//! failure. The system-log mirror is best-effort — its absence or failure never
//! masks a primary-sink failure. The mechanism is platform-selected at the
//! import boundary below: a non-blocking journald datagram on Linux, a
//! `syslog(3)` line into the unified log on macOS (#222).
//!
//! T3 (`coverage-tiers.toml`): I/O-bound, report-only coverage; the
//! `tests/fail_closed.rs` integration test is the primary evidence.
use crate::blocking_guard::{AuditAttempt, BlockingBreaker, BreakerAdmission};
use crate::error::AuditError;
use crate::journal::PrimaryOutcome;
// ONE name for the platform mirror, chosen here at the module boundary, so the
// body of `open_with_journal` and `mirror_journald` is identical everywhere and
// no call site carries a `cfg`.
#[cfg(not(target_os = "macos"))]
use crate::journal_io::{JournalMirror as Mirror, DEFAULT_JOURNAL_SOCKET};
#[cfg(target_os = "macos")]
use crate::syslog_io::SyslogMirror as Mirror;

/// Inert on macOS: `syslog(3)` has no endpoint to point at. It exists so
/// `open()` keeps ONE body across platforms rather than a `cfg` per call site.
#[cfg(target_os = "macos")]
const DEFAULT_JOURNAL_SOCKET: &str = "";
use crate::record::{canonical_json, AuditRecord};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

fn open_audit_file(path: &Path) -> Result<File, AuditError> {
    maknae_io::open_audit_append(
        path,
        // Preserve the configured audit parent's OS DAC authority; the opened
        // leaf must satisfy the stronger artifact requirements below.
        &maknae_io::AnchorRequired::OS_DAC,
        &maknae_io::TargetRequired {
            owner: Some(nix::unistd::geteuid().as_raw()),
            mode_mask: Some(0o037),
            nlink_exactly_one: false,
            regular_file: true,
            max_bytes: None,
        },
        maknae_io::Mode(0o640),
    )
    .map_err(|e| AuditError::OpenPrimary {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })
}

/// The append-only JSONL audit sink: single-writer, off-runtime blocking I/O.
pub struct AuditSink {
    primary: Arc<Mutex<Primary>>,
    breaker: Arc<Mutex<BlockingBreaker>>,
    #[allow(dead_code)] // surfaced for future error context / re-open on failure
    path: PathBuf,
    /// Best-effort system-log mirror (ADR-0019 D3): journald on Linux
    /// ([`crate::journal_io`]), the unified log on macOS ([`crate::syslog_io`]).
    ///
    /// `None` is a named absence. On Linux it is REACHABLE — non-systemd, or
    /// journald unreachable at boot. On macOS it effectively is not: `syslog(3)`
    /// has no endpoint that can be missing, so the macOS `open` is infallible in
    /// practice and the `Option` is shape parity, not a guard.
    mirror: Option<Mirror>,
}

struct Primary {
    file: File,
    // Protected by the writer mutex: no queued writer can acknowledge a later
    // line after a failed/partial write or uncertain synchronization.
    failed: bool,
}

impl Primary {
    fn new(file: File) -> Self {
        Self {
            file,
            failed: false,
        }
    }
}

impl AuditSink {
    /// Open the primary JSONL sink. Steady state opens existing files with
    /// `O_APPEND` and no create flag; first-create retries use exclusive create
    /// with mode 0640 on unix. The validated file and its pinned parent are
    /// synchronized before success; a torn terminal JSONL line refuses boot.
    /// Fails closed: an unopenable primary sink is an `Err`, never a silent
    /// no-op sink.
    pub fn open(cfg: &maknae_config::AuditConfig) -> Result<Self, AuditError> {
        Self::open_with_journal(cfg, Path::new(DEFAULT_JOURNAL_SOCKET))
    }

    /// Test seam: the journal socket path is injectable so the round-trip is
    /// proven against a REAL bound socket rather than a stub.
    ///
    /// **On macOS the path is IGNORED** — `syslog(3)` has no injectable
    /// endpoint. The parameter is kept so this signature is identical on both
    /// platforms and the eighteen call sites below need no `cfg`. Delivery on
    /// darwin is therefore proven differently: by the on-host round-trip that
    /// reads the record back out of the real unified log.
    pub(crate) fn open_with_journal(
        cfg: &maknae_config::AuditConfig,
        journal: &Path,
    ) -> Result<Self, AuditError> {
        let file = open_audit_file(&cfg.jsonl_path)?;
        Ok(AuditSink {
            primary: Arc::new(Mutex::new(Primary::new(file))),
            breaker: Arc::new(Mutex::new(BlockingBreaker::default())),
            path: cfg.jsonl_path.clone(),
            mirror: Mirror::open(journal),
        })
    }

    /// Canonicalize `rec`, append it as one JSONL line, and durably flush
    /// (`sync_data`) before returning — so a caller doing audit-then-respond
    /// (ADR-0019 ordering) never releases a response the audit trail doesn't
    /// yet durably contain.
    ///
    /// The blocking write happens entirely inside `spawn_blocking`'s
    /// synchronous closure: the `std::sync::Mutex` guard is acquired and
    /// dropped there, never held across an `.await` — which is what keeps
    /// this future `Send` (a guard held across `.await` would not be, and
    /// would break `tokio::spawn` in the Task 7 run-loop).
    pub async fn append(&self, rec: &AuditRecord) -> Result<(), AuditError> {
        let mut line = canonical_json(rec)?;
        line.push('\n');
        let now = Instant::now();
        let admitted = {
            let mut breaker = self
                .breaker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            breaker.begin_attempt_at(now)
        };
        let attempt: AuditAttempt = match admitted {
            BreakerAdmission::Admit(attempt) => attempt,
            BreakerAdmission::RefuseOpen => {
                let should_log = self
                    .breaker
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .should_log_refusal_at(now);
                if should_log {
                    eprintln!(
                    "maknaed: AUDIT WRITE BREAKER OPEN for event={} action={} session_id={} — refusing append before spawning blocking audit work",
                    rec.event, rec.action, rec.session_id
                );
                }
                self.mirror_journald(rec, PrimaryOutcome::RefusedBreakerOpen);
                return Err(AuditError::WritePrimary(
                    "audit append circuit breaker open".into(),
                ));
            }
            BreakerAdmission::RefuseAtCapacity => {
                let should_log = self
                    .breaker
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .should_log_refusal_at(now);
                if should_log {
                    eprintln!(
                    "maknaed: AUDIT WRITE AT CAPACITY for event={} action={} session_id={} — refusing append before spawning blocking audit work",
                    rec.event, rec.action, rec.session_id
                );
                }
                self.mirror_journald(rec, PrimaryOutcome::RefusedAtCapacity);
                return Err(AuditError::WritePrimary(
                    "audit append worker capacity exhausted".into(),
                ));
            }
        };
        let primary = Arc::clone(&self.primary);
        let joined = tokio::task::spawn_blocking(move || write_line(&primary, &line)).await;
        // Join failure means the blocking worker ended instead of being
        // orphaned; the append still fails closed below, but it is not a stuck
        // in-flight append.
        self.breaker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_success(attempt);
        // The `?` used to return HERE, so a join failure -- the case where the
        // primary is most obviously wedged -- reached NEITHER sink. Mirror
        // first, then propagate.
        let joined = joined.map_err(|e| {
            AuditError::WritePrimary(format!("blocking write task panicked/was cancelled: {e}"))
        });
        // Borrow, never move: `joined` is consumed by the `?` below. Named
        // `outcome`, NOT `primary` -- `primary` is already bound above as the
        // Arc<Mutex<File>> clone.
        let outcome = match &joined {
            Ok(Ok(())) => PrimaryOutcome::Ok,
            _ => PrimaryOutcome::WriteFailed,
        };
        self.mirror_journald(rec, outcome);
        joined?
    }

    /// Best-effort journald mirror (ADR-0019 D3).
    ///
    /// **Called on every outcome path after canonicalization, including
    /// refusals — deliberately.** Three of the four call sites fire precisely
    /// *because* the primary did not durably write, so when the primary is
    /// wedged this is the last-chance record. `primary` marks which condition
    /// produced the copy, so the two sinks never diverge silently.
    ///
    /// Never takes a breaker admission: the breaker bounds *blocking* backends,
    /// and this send cannot wedge. Routing it through the breaker would let a
    /// wedged primary suppress the last-chance mirror — the exact inversion of
    /// this method's purpose.
    ///
    /// **The name says journald; the mechanism is platform-selected.** On macOS
    /// this is a `syslog(3)` line into the unified log, not a datagram. One name
    /// for two mechanisms is defensible; silence about it is not.
    fn mirror_journald(&self, rec: &AuditRecord, primary: PrimaryOutcome) {
        if let Some(m) = self.mirror.as_ref() {
            m.mirror(rec, primary);
        }
    }
}

fn write_line(file: &Mutex<Primary>, line: &str) -> Result<(), AuditError> {
    // A writer panic may leave a partial JSONL line. Appending after it would
    // acknowledge a record spliced into that line, not a durable valid record.
    let mut guard = file.lock().map_err(|_| {
        AuditError::WritePrimary("audit writer panicked; primary sink requires recovery".into())
    })?;
    if guard.failed {
        return Err(AuditError::WritePrimary(
            "prior audit append failed; primary sink requires recovery".into(),
        ));
    }
    guard.failed = true;
    guard
        .file
        .write_all(line.as_bytes())
        .map_err(|e| AuditError::WritePrimary(e.to_string()))?;
    guard
        .file
        .sync_data()
        .map_err(|e| AuditError::WritePrimary(e.to_string()))?;
    guard.failed = false;
    Ok(())
}

/// The interface the run-loop (Task 7) is generic over. **RPITIT + `Send`**
/// (not `async fn` in trait): a public `async fn` in a trait trips the
/// `async_fn_in_trait` lint under this workspace's `-D warnings`, and its
/// desugared future is not `Send` — which would make `tokio::spawn(async
/// move { sink.emit(&rec).await })` in the run-loop fail to compile.
pub trait AuditEmit {
    fn emit(
        &self,
        rec: &AuditRecord,
    ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send;
}

impl AuditEmit for AuditSink {
    fn emit(
        &self,
        rec: &AuditRecord,
    ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
        self.append(rec)
    }
}

/// Compile-time proof that `append`'s (and therefore `emit`'s) returned
/// future is `Send`. Never called — the assertion is that this function
/// compiles at all: `assert_send` only accepts a `Send` argument, so if
/// `append`'s future stopped being `Send` (e.g. a mutex guard reintroduced
/// across an `.await`), this file would fail to build.
#[allow(dead_code)]
fn _assert_append_and_emit_futures_are_send(sink: &AuditSink, rec: &AuditRecord) {
    fn assert_send<T: Send>(_: T) {}
    assert_send(sink.append(rec));
    assert_send(AuditEmit::emit(sink, rec));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> AuditRecord {
        use crate::record::{Integrity, Outcome, Source, Subject, Where};
        AuditRecord {
            ts: "2026-08-11T00:00:00.000Z".into(),
            event: "connection.accept".into(),
            where_: Where {
                host: "maknaed-01".into(),
                component: "kernel".into(),
                socket: "/run/maknae/plane.sock".into(),
            },
            source: Source {
                uid: 1000,
                gid: Some(1000),
                pid: Some(4242),
                plane_uri_san: Some("urn:maknae:plane:cli".into()),
            },
            subject: Subject {
                user: Some("alice".into()),
                role: None,
                plane_uri_san: Some("urn:maknae:plane:cli".into()),
            },
            action: "connect".into(),
            object: None,
            object_requested: None,
            mutation: None,
            egress: None,
            outcome: Outcome {
                result: "permit".into(),
                reason: "group membership: maknae-ops".into(),
                posture: "authorized".into(),
            },
            session_id: 42,
            seq: 1,
            au3_1: serde_json::json!({}),
            integrity: Integrity {
                prev_hash: None,
                sig: None,
            },
        }
    }

    #[test]
    fn reopen_refuses_torn_terminal_line_without_changing_trail() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let bytes = b"{\"complete\":true}\n{\"sentinel\":\"torn-158";
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let cfg = maknae_config::AuditConfig {
            jsonl_path: path.clone(),
            siem: None,
            au3_1: serde_json::json!({}),
        };
        assert!(
            AuditSink::open(&cfg).is_err(),
            "torn terminal JSONL must refuse boot"
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[tokio::test]
    async fn reopen_retains_valid_lines_and_appends_a_separate_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let cfg = maknae_config::AuditConfig {
            jsonl_path: path.clone(),
            siem: None,
            au3_1: serde_json::json!({}),
        };
        let sink = AuditSink::open(&cfg).unwrap();
        sink.append(&sample_record()).await.unwrap();
        sink.append(&sample_record()).await.unwrap();
        let before = std::fs::read(&path).unwrap();
        drop(sink);
        let sink = AuditSink::open(&cfg).unwrap();
        sink.append(&sample_record()).await.unwrap();
        let after = std::fs::read(&path).unwrap();
        assert!(after.starts_with(&before));
        assert_eq!(after.split(|b| *b == b'\n').count(), 4);
        for line in std::str::from_utf8(&after).unwrap().lines() {
            serde_json::from_str::<AuditRecord>(line).unwrap();
        }
    }

    #[tokio::test]
    async fn append_after_writer_panic_preserves_the_torn_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let cfg = maknae_config::AuditConfig {
            jsonl_path: path.clone(),
            siem: None,
            au3_1: serde_json::json!({}),
        };
        let sink = AuditSink::open(&cfg).unwrap();
        let primary = Arc::clone(&sink.primary);
        let partial = b"{\"sentinel\":\"interrupted-audit-158";
        let worker = std::thread::spawn(move || {
            let mut file = primary.lock().unwrap();
            file.file.write_all(partial).unwrap();
            panic!("simulate a writer panic after actual partial bytes");
        });
        assert!(worker.join().is_err());
        assert_eq!(std::fs::read(&path).unwrap(), partial);
        let result = sink.append(&sample_record()).await;
        assert!(
            result.is_err(),
            "a torn audit line must block later acknowledgments"
        );
        assert_eq!(std::fs::read(&path).unwrap(), partial);
    }

    #[tokio::test]
    async fn append_after_primary_write_failure_stays_refused() {
        assert_primary_failure_stays_refused(false).await;
    }

    #[tokio::test]
    async fn append_after_primary_sync_failure_stays_refused() {
        assert_primary_failure_stays_refused(true).await;
    }

    async fn assert_primary_failure_stays_refused(sync_failure: bool) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let cfg = maknae_config::AuditConfig {
            jsonl_path: path.clone(),
            siem: None,
            au3_1: serde_json::json!({}),
        };
        let sink = AuditSink::open(&cfg).unwrap();
        sink.append(&sample_record()).await.unwrap();
        let before = std::fs::read(&path).unwrap();
        // Real kernel errors: read-only fd makes write fail; writable /dev/null
        // accepts the bytes but cannot synchronize them. Restore only the fd to
        // simulate a recovered device, preserving all production failure state.
        let fault = std::fs::OpenOptions::new()
            .read(true)
            .write(sync_failure)
            .open("/dev/null")
            .unwrap();
        let expected = if sync_failure {
            fault.sync_data().unwrap_err().to_string()
        } else {
            (&fault).write_all(b"probe").unwrap_err().to_string()
        };
        let healthy = std::mem::replace(&mut sink.primary.lock().unwrap().file, fault);
        let error = sink.append(&sample_record()).await.unwrap_err();
        assert!(
            error.to_string().contains(&expected),
            "wrong injected failure: {error}"
        );
        sink.primary.lock().unwrap().file = healthy;
        assert!(
            sink.append(&sample_record()).await.is_err(),
            "a primary failure must block later acknowledgments even after the device recovers"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn append_multiple_records_writes_multiple_well_formed_lines() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = maknae_config::AuditConfig {
            jsonl_path: dir.path().join("audit.jsonl"),
            siem: None,
            au3_1: serde_json::json!({}),
        };
        let sink = AuditSink::open_with_journal(
            &cfg,
            std::path::Path::new("/nonexistent/maknae-test-no-journal.sock"),
        )
        .unwrap();
        for i in 0..3u64 {
            let mut rec = sample_record();
            rec.seq = i + 1;
            sink.append(&rec).await.unwrap();
        }
        let contents = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        for (i, line) in lines.iter().enumerate() {
            let parsed: AuditRecord = serde_json::from_str(line).unwrap();
            assert_eq!(parsed.seq, i as u64 + 1);
        }
    }

    #[tokio::test]
    async fn breaker_refusal_happens_before_any_audit_record_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let cfg = maknae_config::AuditConfig {
            jsonl_path: path.clone(),
            siem: None,
            au3_1: serde_json::json!({}),
        };
        let mut sink = AuditSink::open_with_journal(
            &cfg,
            std::path::Path::new("/nonexistent/maknae-test-no-journal.sock"),
        )
        .unwrap();
        sink.breaker = Arc::new(Mutex::new(BlockingBreaker::new(0)));

        assert!(sink.append(&sample_record()).await.is_err());
        let contents = std::fs::read_to_string(path).unwrap();
        assert_eq!(contents, "");
    }

    #[tokio::test]
    async fn open_fails_closed_when_path_is_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = maknae_config::AuditConfig {
            jsonl_path: dir.path().to_path_buf(), // a directory, not a file
            siem: None,
            au3_1: serde_json::json!({}),
        };
        assert!(AuditSink::open_with_journal(
            &cfg,
            std::path::Path::new("/nonexistent/maknae-test-no-journal.sock")
        )
        .is_err());
    }

    // ---- fail-closed audit-file integrity (O_NOFOLLOW + fstat) --------------

    // (a) A fresh path opens, and the created file is a regular file, owned by us,
    // and NOT group/world-writable (mode 0o640 & ~umask — the security mask the
    // validator enforces). The umask may tighten below 0o640; it never loosens it.
    #[cfg(unix)]
    #[tokio::test]
    async fn open_succeeds_on_fresh_path_regular_owned_not_group_world_writable() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let cfg = maknae_config::AuditConfig {
            jsonl_path: path.clone(),
            siem: None,
            au3_1: serde_json::json!({}),
        };
        assert!(AuditSink::open_with_journal(
            &cfg,
            std::path::Path::new("/nonexistent/maknae-test-no-journal.sock")
        )
        .is_ok());
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.file_type().is_file(), "created audit file is regular");
        assert_eq!(meta.uid(), nix::unistd::geteuid().as_raw(), "owned by us");
        assert_eq!(meta.mode() & 0o037, 0, "not group/world-writable");
        assert_eq!(meta.mode() & 0o600, 0o600, "owner can read+write");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn concurrent_first_create_race_opens_both_handles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let left_cfg = maknae_config::AuditConfig {
            jsonl_path: path.clone(),
            siem: None,
            au3_1: serde_json::json!({}),
        };
        let right_cfg = left_cfg.clone();

        let (left, right) = tokio::join!(
            tokio::task::spawn_blocking(move || AuditSink::open_with_journal(
                &left_cfg,
                std::path::Path::new("/nonexistent/maknae-test-no-journal.sock")
            )),
            tokio::task::spawn_blocking(move || AuditSink::open_with_journal(
                &right_cfg,
                std::path::Path::new("/nonexistent/maknae-test-no-journal.sock")
            )),
        );

        assert!(left.unwrap().is_ok());
        assert!(right.unwrap().is_ok());
        assert!(path.is_file());
    }

    // (b) A pre-existing world-writable file is refused — another user must not be
    // able to tamper with the durable audit trail.
    #[cfg(unix)]
    #[tokio::test]
    async fn open_fails_on_preexisting_world_writable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let cfg = maknae_config::AuditConfig {
            jsonl_path: path,
            siem: None,
            au3_1: serde_json::json!({}),
        };
        assert!(AuditSink::open_with_journal(
            &cfg,
            std::path::Path::new("/nonexistent/maknae-test-no-journal.sock")
        )
        .is_err());
    }

    // (c) A symlink at the audit path is refused (O_NOFOLLOW → ELOOP on open), so a
    // symlink cannot redirect privileged appends to another file.
    #[cfg(unix)]
    #[tokio::test]
    async fn open_fails_when_path_is_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real-target");
        std::fs::write(&target, b"").unwrap();
        let link = dir.path().join("audit.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let cfg = maknae_config::AuditConfig {
            jsonl_path: link,
            siem: None,
            au3_1: serde_json::json!({}),
        };
        assert!(AuditSink::open_with_journal(
            &cfg,
            std::path::Path::new("/nonexistent/maknae-test-no-journal.sock")
        )
        .is_err());
    }

    #[tokio::test]
    async fn emit_trait_method_delegates_to_append() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = maknae_config::AuditConfig {
            jsonl_path: dir.path().join("audit.jsonl"),
            siem: None,
            au3_1: serde_json::json!({}),
        };
        let sink = AuditSink::open_with_journal(
            &cfg,
            std::path::Path::new("/nonexistent/maknae-test-no-journal.sock"),
        )
        .unwrap();
        AuditEmit::emit(&sink, &sample_record()).await.unwrap();
        let contents = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert_eq!(contents.lines().count(), 1);
    }

    /// The `AuditConfig` these tests need. Authored here because the crate has
    /// NO existing helper -- every AuditConfig in this module is an inline
    /// literal. `siem` stays `None`: the field is retained by operator ruling
    /// and this task must not change its shape.
    fn cfg_at(dir: &std::path::Path) -> maknae_config::AuditConfig {
        maknae_config::AuditConfig {
            jsonl_path: dir.join("audit.jsonl"),
            siem: None,
            au3_1: serde_json::json!({}),
        }
    }

    #[cfg(target_os = "linux")] // journald socket round-trip: the macOS mirror ignores the injected path, so no datagram ever arrives and recv_text's expect() would panic after its 2s timeout
    fn journal_receiver(dir: &std::path::Path) -> (std::os::unix::net::UnixDatagram, PathBuf) {
        let p = dir.join("journal.sock");
        let rx = std::os::unix::net::UnixDatagram::bind(&p).unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        (rx, p)
    }

    #[cfg(target_os = "linux")] // journald socket round-trip: the macOS mirror ignores the injected path, so no datagram ever arrives and recv_text's expect() would panic after its 2s timeout
    fn recv_text(rx: &std::os::unix::net::UnixDatagram) -> String {
        let mut buf = vec![0u8; 128 * 1024];
        let n = rx.recv(&mut buf).expect("a datagram must arrive");
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_successful_append_mirrors_with_primary_ok() {
        let dir = tempfile::tempdir().unwrap();
        let (rx, jpath) = journal_receiver(dir.path());
        let sink = AuditSink::open_with_journal(&cfg_at(dir.path()), &jpath).unwrap();
        sink.append(&sample_record()).await.unwrap();
        assert!(recv_text(&rx).contains("MAKNAE_PRIMARY=ok"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_breaker_open_refusal_mirrors_refused_breaker_open() {
        // Assert the EXACT marker -- a `refused-` prefix match would pass with
        // the two markers swapped, and sink.rs is mutation-excluded so nothing
        // else would catch the swap.
        let dir = tempfile::tempdir().unwrap();
        let (rx, jpath) = journal_receiver(dir.path());
        let mut sink = AuditSink::open_with_journal(&cfg_at(dir.path()), &jpath).unwrap();
        // `trip_after == 0` makes begin_attempt_at return RefuseOpen
        // UNCONDITIONALLY (blocking_guard.rs:79-81), so this reaches the
        // breaker-open arm and never the at-capacity arm.
        sink.breaker = Arc::new(Mutex::new(BlockingBreaker::new(0)));
        assert!(
            sink.append(&sample_record()).await.is_err(),
            "primary must refuse"
        );
        assert!(
            recv_text(&rx).contains("MAKNAE_PRIMARY=refused-breaker-open"),
            "breaker-open refusal must carry its own exact marker"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_at_capacity_refusal_mirrors_refused_at_capacity() {
        // Reaching RefuseAtCapacity needs in_flight.len() >= max_in_flight, and
        // max_in_flight is a private field `new()` hardcodes -- hence the
        // new_with_limits seam. trip_after high enough not to trip; capacity 0
        // so the first attempt is at capacity immediately.
        let dir = tempfile::tempdir().unwrap();
        let (rx, jpath) = journal_receiver(dir.path());
        let mut sink = AuditSink::open_with_journal(&cfg_at(dir.path()), &jpath).unwrap();
        sink.breaker = Arc::new(Mutex::new(BlockingBreaker::new_with_limits(u8::MAX, 0)));
        assert!(
            sink.append(&sample_record()).await.is_err(),
            "primary must refuse"
        );
        assert!(
            recv_text(&rx).contains("MAKNAE_PRIMARY=refused-at-capacity"),
            "at-capacity refusal must carry its own exact marker"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_primary_write_failure_mirrors_write_failed() {
        // The PR's headline fix, asserted. Without this the `write-failed`
        // marker ships unproven -- and sink.rs is mutation-excluded, so there is
        // no other net. Seam: swap the primary handle for a READ-ONLY fd after
        // open. The breaker admits normally, `write_line` runs and fails EBADF,
        // and the join succeeds with an inner Err -- the `Ok(Err(_))` arm.
        let dir = tempfile::tempdir().unwrap();
        let (rx, jpath) = journal_receiver(dir.path());
        let mut sink = AuditSink::open_with_journal(&cfg_at(dir.path()), &jpath).unwrap();
        sink.primary = Arc::new(Mutex::new(Primary::new(File::open("/dev/null").unwrap())));
        assert!(
            sink.append(&sample_record()).await.is_err(),
            "the primary write must fail"
        );
        assert!(
            recv_text(&rx).contains("MAKNAE_PRIMARY=write-failed"),
            "a failed primary write must mirror with its own exact marker"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_mirror_send_failure_never_fails_a_good_primary_append() {
        // THE load-bearing assertion. The receiver is bound at open time (so the
        // mirror is Some and the send path is real), then torn down before the
        // append -- so `send` returns ECONNREFUSED and the DROP path is
        // genuinely exercised, not merely the `None` branch.
        let dir = tempfile::tempdir().unwrap();
        let (rx, jpath) = journal_receiver(dir.path());
        let cfg = cfg_at(dir.path());
        let sink = AuditSink::open_with_journal(&cfg, &jpath).unwrap();
        drop(rx);
        std::fs::remove_file(&jpath).ok();
        assert!(
            sink.append(&sample_record()).await.is_ok(),
            "a mirror failure must not fail the primary"
        );
        // Observe that the mirror really failed rather than trusting the name:
        // the primary line landed even though no datagram could be delivered.
        let jsonl = std::fs::read_to_string(&cfg.jsonl_path).unwrap();
        assert!(
            jsonl.lines().count() >= 1,
            "the primary append must still be durable"
        );
        assert!(
            !jpath.exists(),
            "the peer really is gone, so `send` really failed"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_absent_journal_socket_still_opens_the_sink() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            AuditSink::open_with_journal(&cfg_at(dir.path()), &dir.path().join("nope.sock"))
                .is_ok()
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_two_refusal_markers_are_not_interchangeable() {
        // A derived cross-check: whatever the two refusal paths emit, they must
        // DIFFER. This is what dies if an implementer swaps the two arms.
        // Both sides append THE SAME record, so the datagrams can differ only in
        // MAKNAE_PRIMARY; two different records would make assert_ne! vacuous.
        let dir = tempfile::tempdir().unwrap();
        // tempdir() creates only the root; bind into a missing subdir is ENOENT.
        std::fs::create_dir_all(dir.path().join("a")).unwrap();
        std::fs::create_dir_all(dir.path().join("b")).unwrap();
        let (rx1, j1) = journal_receiver(&dir.path().join("a"));
        let (rx2, j2) = journal_receiver(&dir.path().join("b"));

        let mut open_sink =
            AuditSink::open_with_journal(&cfg_at(&dir.path().join("a")), &j1).unwrap();
        open_sink.breaker = Arc::new(Mutex::new(BlockingBreaker::new(0)));
        let mut cap_sink =
            AuditSink::open_with_journal(&cfg_at(&dir.path().join("b")), &j2).unwrap();
        cap_sink.breaker = Arc::new(Mutex::new(BlockingBreaker::new_with_limits(u8::MAX, 0)));

        let r = sample_record();
        assert!(open_sink.append(&r).await.is_err());
        assert!(cap_sink.append(&r).await.is_err());
        assert_ne!(
            recv_text(&rx1),
            recv_text(&rx2),
            "the two refusal markers must be distinguishable"
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn the_sink_holds_a_live_mirror_on_macos() {
        // Assert the MIRROR, not the JSONL -- `append_writes_one_jsonl_line...`
        // in tests/fail_closed.rs already makes the line-count assertion, and a
        // test whose name says "mirror" must touch `sink.mirror`.
        //
        // On macOS the mirror needs no endpoint, so absence is not reachable the
        // way it is on Linux. What must hold is the contract: the sink opens,
        // the append succeeds, and the primary line is durable.
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_at(dir.path());
        let sink = AuditSink::open(&cfg).unwrap();
        // Task 3 forbids `assert!(open(..).is_some())` as `assert!(true)`. This
        // is different, and the difference is the point: `sink.rs` is
        // MUTATION-EXCLUDED, so this is the only thing pinning that the macOS
        // branch wires a mirror at all rather than leaving it `None`.
        assert!(
            sink.mirror.is_some(),
            "macOS must hold a live mirror — syslog(3) needs no endpoint"
        );
        sink.append(&sample_record()).await.unwrap();
        let jsonl = std::fs::read_to_string(&cfg.jsonl_path).unwrap();
        assert_eq!(
            jsonl.lines().count(),
            1,
            "the primary append must still be durable"
        );
    }

    // ----------------------------------------------------------------------
    // macOS unified-log acceptance (#222, spec §5).
    //
    // WHY HERE AND NOT IN `tests/`: the four MAKNAE_PRIMARY markers can only be
    // driven through the `sink.breaker` seam, which is pub(crate) and
    // unreachable from an integration test. And `sink.rs` is MUTATION-EXCLUDED,
    // so swapping the two refusal arms is caught by NO gate at all on macOS
    // unless a test asserts each marker exactly.
    //
    // WHY AGAINST THE REAL LOGGER: `syslog(3)` has no in-process interception
    // point. The Linux half proved delivery against a real bound socket; the
    // honest macOS equivalent is the real system logger read back with
    // `/usr/bin/log`. A fn-pointer seam would prove the plumbing and hide
    // everything else.
    // ----------------------------------------------------------------------

    /// What the lane should do when the unified-log store cannot be read.
    ///
    /// **THREE states, not two.** A bare `-> bool` invites returning "skip" for
    /// the fail case and silently inverting the property — and on CI the skip
    /// branch is DEAD (the `macos-26` runner is admin), so an inverted guard
    /// would leave the lane green with zero round-trip evidence. That is the
    /// #219 ok-on-nothing class one level up.
    #[cfg(target_os = "macos")]
    #[derive(Debug, PartialEq, Eq)]
    enum LaneAction {
        Proceed,
        /// Skip, with a loud reason. A skip here is a LANE GAP, not a pass.
        Skip,
        /// The lane demanded evidence and there is none.
        Fail,
    }

    /// | `readable` | `required` | outcome |
    /// |---|---|---|
    /// | true | any | proceed |
    /// | false | false | skip, loudly |
    /// | false | true | fail |
    #[cfg(target_os = "macos")]
    fn macos_lane_action(readable: bool, required: bool) -> LaneAction {
        match (readable, required) {
            (true, _) => LaneAction::Proceed,
            (false, false) => LaneAction::Skip,
            (false, true) => LaneAction::Fail,
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_lane_action_covers_all_four_readable_required_combinations() {
        assert_eq!(macos_lane_action(true, true), LaneAction::Proceed);
        assert_eq!(macos_lane_action(true, false), LaneAction::Proceed);
        assert_eq!(macos_lane_action(false, false), LaneAction::Skip);
        assert_eq!(
            macos_lane_action(false, true),
            LaneAction::Fail,
            "MAKNAE_AUDIT_REQUIRE_UNIFIED_LOG=1 must FAIL, never skip — a lane \
             that silently skips its only round-trip evidence is green on nothing"
        );
    }

    /// `/var/db/diagnostics` is `drwxr-x--- root:admin`, so a non-admin runner
    /// cannot read the log at all. Probe it rather than guessing.
    ///
    /// NOT `maknae-io`'s `skip_or_fail`: it is pub(crate) in a crate this one
    /// does not depend on, and it PANICS unless an opt-out env var is set —
    /// wiring it would make CI red on an unreadable store.
    #[cfg(target_os = "macos")]
    fn macos_log_store_is_readable() -> bool {
        std::process::Command::new("/usr/bin/log")
            .args(["show", "--last", "1s", "--style", "json"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// `true` to proceed; `false` to skip. Panics when the lane required
    /// evidence it cannot get.
    #[cfg(target_os = "macos")]
    fn macos_gate() -> bool {
        let required = std::env::var("MAKNAE_AUDIT_REQUIRE_UNIFIED_LOG").as_deref() == Ok("1");
        match macos_lane_action(macos_log_store_is_readable(), required) {
            LaneAction::Proceed => true,
            LaneAction::Skip => {
                eprintln!(
                    "SKIP: /var/db/diagnostics is not readable by this user (root:admin). \
                     This is a LANE GAP, not a pass. Set \
                     MAKNAE_AUDIT_REQUIRE_UNIFIED_LOG=1 to make it a hard failure."
                );
                false
            }
            LaneAction::Fail => panic!(
                "MAKNAE_AUDIT_REQUIRE_UNIFIED_LOG=1 but the unified-log store is \
                 unreadable — the lane demanded round-trip evidence and there is none"
            ),
        }
    }

    /// A per-run nonce. `/usr/bin/log` LOGS ITS OWN INVOCATION including the
    /// predicate text, and a PID-scoped query returns OS-emitted records the
    /// process never asked for — so "the set is non-empty" is satisfied even
    /// when the appender emitted nothing. The nonce is the discriminator; the
    /// PID is only the query scope.
    ///
    /// `cargo test` also runs this whole module in ONE process, so the other
    /// sink tests emit real `MAKNAE_*` records under the SAME pid. PID scoping
    /// is exactly what fails to isolate them.
    #[cfg(target_os = "macos")]
    fn macos_nonce() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        // Low bits of the clock, plus a counter, so two nonces in one run (the
        // sentinel and the oversize record) can never collide.
        (t % 1_000_000_000) * 1_000 + COUNTER.fetch_add(1, Ordering::SeqCst)
    }

    /// Every `eventMessage` this process emitted in the last two minutes.
    ///
    /// `--style json` JSON-ESCAPES the message, so it is decoded with
    /// `serde_json` rather than byte-matched against raw output. Deliberately
    /// NO `--info`: retrieval without it is what proves spec D4's default-level
    /// decision.
    #[cfg(target_os = "macos")]
    fn macos_log_messages() -> Vec<String> {
        let pred = format!("processIdentifier == {}", std::process::id());
        let out = std::process::Command::new("/usr/bin/log")
            .args([
                "show",
                "--last",
                "2m",
                "--style",
                "json",
                "--predicate",
                &pred,
            ])
            .output()
            .expect("/usr/bin/log must be executable");
        if !out.status.success() {
            return Vec::new();
        }
        let v: serde_json::Value = match serde_json::from_slice(&out.stdout) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        v.as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|r| r.get("eventMessage")?.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Poll with a bounded backoff (records take ~1s to appear). NOT a fixed
    /// sleep, and NOT unbounded.
    /// Poll the real unified log for a record we just submitted.
    ///
    /// **Fails fast when the formatter cannot produce the needle at all.** The
    /// 15s ceiling exists to let the log store settle, but under mutation a
    /// broken formatter would simply never emit the needle and this would burn
    /// the whole ceiling — cargo-mutants' auto timeout is 20s, so the mutant
    /// reports TIMEOUT rather than CAUGHT, and `coverage-tiers.sh` fails on
    /// timeouts exactly as it fails on misses. Checking the LOCAL formatting
    /// first turns that into an immediate, honest failure. Same reasoning as
    /// `syslog_fmt::tests::record_formatting_to_exactly`'s bounded loop.
    #[cfg(target_os = "macos")]
    fn macos_await_nonce_for(rec: &AuditRecord, nonce: u64) -> Vec<String> {
        let local = crate::syslog_fmt::format_line_unchecked(rec, PrimaryOutcome::Ok)
            .expect("the record must format at all");
        let needle = format!("session={nonce} ");
        assert!(
            local.contains(&needle),
            "the formatter does not produce the needle locally, so waiting on the \
             platform would only burn the ceiling: {local}"
        );
        macos_await_nonce(nonce)
    }

    #[cfg(target_os = "macos")]
    fn macos_await_nonce(nonce: u64) -> Vec<String> {
        let needle = format!("session={nonce} ");
        let mut waited = std::time::Duration::ZERO;
        let ceiling = std::time::Duration::from_secs(15);
        let mut step = std::time::Duration::from_millis(500);
        loop {
            let msgs = macos_log_messages();
            if msgs.iter().any(|m| m.contains(&needle)) {
                return msgs;
            }
            if waited >= ceiling {
                return msgs;
            }
            std::thread::sleep(step);
            waited += step;
            step = (step * 2).min(std::time::Duration::from_secs(4));
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_round_trip_delivers_the_record_byte_identical_to_the_jsonl() {
        if !macos_gate() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_at(dir.path());
        let sink = AuditSink::open(&cfg).unwrap();

        // TWO nonces. The oversize record is DROPPED by the formatter, so if it
        // shared the sentinel's nonce the negative could not be expressed at all.
        let oversize_nonce = macos_nonce();
        let sentinel_nonce = macos_nonce();

        // Emit the oversize record FIRST. If it went last, "absent" could just
        // mean "not yet delivered" — ok-on-nothing at one remove.
        let mut big = sample_record();
        big.session_id = oversize_nonce;
        big.au3_1 = serde_json::json!({ "pad": "x".repeat(8192) });
        sink.append(&big).await.unwrap();

        let mut rec = sample_record();
        rec.session_id = sentinel_nonce;
        sink.append(&rec).await.unwrap();

        let msgs = macos_await_nonce_for(&rec, sentinel_nonce);

        // POSITIVE CONTROL FIRST: at least one record carrying THIS RUN's nonce
        // — never merely "the set is non-empty".
        let needle = format!("session={sentinel_nonce} ");
        let mine: Vec<&String> = msgs.iter().filter(|m| m.contains(&needle)).collect();
        assert!(
            !mine.is_empty(),
            "no unified-log record carried this run's nonce {sentinel_nonce}; \
             {} records returned for this pid",
            msgs.len()
        );

        // MAKNAE_RECORD is everything after the FIRST `MAKNAE_RECORD=`.
        // `find`, NEVER `rfind`: under hostile input the last occurrence is
        // inside the payload, so rfind returns attacker-chosen bytes.
        let line = mine[0];
        let at = line
            .find("MAKNAE_RECORD=")
            .expect("the delivered record must carry the anchor");
        let delivered = &line[at + "MAKNAE_RECORD=".len()..];

        // `write_line` pushes a '\n' onto the canonical JSON, so compare
        // against the first LINE, not the whole file.
        let jsonl = std::fs::read_to_string(&cfg.jsonl_path).unwrap();
        let written = jsonl
            .lines()
            .find(|l| l.contains(&format!("\"session_id\":{sentinel_nonce}")))
            .expect("the sentinel must be in the JSONL too");
        assert_eq!(
            delivered, written,
            "the unified-log copy and the JSONL line must be byte-identical"
        );

        // #275: an oversize record is no longer DROPPED — it is delivered in
        // DEGRADED form. What must never happen is a truncated full record: the
        // degraded line carries no `MAKNAE_RECORD=` payload at all.
        let marker = format!("seq={oversize_nonce} ");
        let degraded: Vec<&String> = msgs
            .iter()
            .filter(|m| m.contains("MAKNAE_DEGRADED="))
            .collect();
        assert!(
            !degraded.is_empty() || !msgs.iter().any(|m| m.contains(&marker)),
            "an oversize record must be degraded, never truncated"
        );
        for m in degraded {
            assert!(
                !m.contains("MAKNAE_RECORD="),
                "a degraded line must not carry the payload: {m}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_delivers_each_of_the_four_primary_markers_exactly() {
        if !macos_gate() {
            return;
        }
        // Assert the EXACT marker for each outcome. A `refused-` prefix match
        // passes with the two refusal markers SWAPPED, and sink.rs is
        // mutation-excluded, so nothing else would catch that swap on macOS.
        let dir = tempfile::tempdir().unwrap();

        // ok
        let n_ok = macos_nonce();
        {
            let sink = AuditSink::open(&cfg_at(dir.path())).unwrap();
            let mut r = sample_record();
            r.session_id = n_ok;
            sink.append(&r).await.unwrap();
        }
        // refused-breaker-open: trip_after == 0 returns RefuseOpen
        // UNCONDITIONALLY (blocking_guard.rs:79-81).
        let n_breaker = macos_nonce();
        {
            let mut sink = AuditSink::open(&cfg_at(dir.path())).unwrap();
            sink.breaker = Arc::new(Mutex::new(BlockingBreaker::new(0)));
            let mut r = sample_record();
            r.session_id = n_breaker;
            assert!(sink.append(&r).await.is_err(), "primary must refuse");
        }
        // refused-at-capacity: trip_after high enough not to trip, capacity 0.
        let n_capacity = macos_nonce();
        {
            let mut sink = AuditSink::open(&cfg_at(dir.path())).unwrap();
            sink.breaker = Arc::new(Mutex::new(BlockingBreaker::new_with_limits(u8::MAX, 0)));
            let mut r = sample_record();
            r.session_id = n_capacity;
            assert!(sink.append(&r).await.is_err(), "primary must refuse");
        }
        // write-failed: a read-only primary fd. The breaker admits, write_line
        // fails EBADF, the join succeeds with an inner Err.
        let n_failed = macos_nonce();
        {
            let mut sink = AuditSink::open(&cfg_at(dir.path())).unwrap();
            sink.primary = Arc::new(Mutex::new(Primary::new(File::open("/dev/null").unwrap())));
            let mut r = sample_record();
            r.session_id = n_failed;
            assert!(
                sink.append(&r).await.is_err(),
                "the primary write must fail"
            );
        }

        // Same fast-fail as the other two sites; `r` is the last record built
        // above and carries `n_failed`.
        let mut probe = sample_record();
        probe.session_id = n_failed;
        let msgs = macos_await_nonce_for(&probe, n_failed);
        for (nonce, marker) in [
            (n_ok, "MAKNAE_PRIMARY=ok"),
            (n_breaker, "MAKNAE_PRIMARY=refused-breaker-open"),
            (n_capacity, "MAKNAE_PRIMARY=refused-at-capacity"),
            (n_failed, "MAKNAE_PRIMARY=write-failed"),
        ] {
            let needle = format!("session={nonce} ");
            let found = msgs
                .iter()
                .find(|m| m.contains(&needle))
                .unwrap_or_else(|| panic!("no delivered record carried nonce {nonce}"));
            assert!(
                found.contains(marker),
                "record {nonce} must carry the exact marker {marker}: {found}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_an_oversize_record_still_leaves_the_primary_append_ok() {
        // Spec §5 bullet 4. Task 4's Linux gating removes
        // `a_mirror_send_failure_never_fails_a_good_primary_append` on darwin
        // with nothing replacing it; this is the replacement. Needs no log
        // readback, so it runs even when the store is unreadable.
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_at(dir.path());
        let sink = AuditSink::open(&cfg).unwrap();
        let mut big = sample_record();
        big.au3_1 = serde_json::json!({ "pad": "x".repeat(8192) });
        sink.append(&big)
            .await
            .expect("a dropped mirror must never fail a good primary append");
        let jsonl = std::fs::read_to_string(&cfg.jsonl_path).unwrap();
        assert_eq!(
            jsonl.lines().count(),
            1,
            "the primary line must be durable even when the mirror drops"
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_a_line_of_exactly_the_cap_arrives_unmarked_from_the_platform() {
        if !macos_gate() {
            return;
        }
        // THE ONLY assertion in this PR that can detect a wrong
        // MACOS_SYSLOG_MAX — and that constant has been wrong TWICE (1024, then
        // 1018, both read off a TRUNCATED record). Every other check compares a
        // formatted line to the constant, i.e. the code against itself.
        use crate::syslog_fmt::{format_line_unchecked, MACOS_SYSLOG_MAX};
        let nonce = macos_nonce();

        // Grow the pad against the record that ALREADY carries the nonce: the
        // nonce appears TWICE in the line (`session=<n>` and `"session_id":<n>`),
        // so a template-grown pad is the wrong length once it is substituted.
        // BOUNDED — an unbounded loop here produces TIMEOUT mutants.
        let mut at_cap = None;
        for pad in 0..=MACOS_SYSLOG_MAX {
            let mut r = sample_record();
            r.session_id = nonce;
            r.au3_1 = serde_json::json!({ "p": "x".repeat(pad) });
            let len = format_line_unchecked(&r, PrimaryOutcome::Ok).unwrap().len();
            if len == MACOS_SYSLOG_MAX {
                at_cap = Some(r);
                break;
            }
            assert!(len < MACOS_SYSLOG_MAX, "overshot at pad {pad} (len {len})");
        }
        let at_cap = at_cap.expect("a record of exactly the cap must be constructible");
        let expected = format_line_unchecked(&at_cap, PrimaryOutcome::Ok).unwrap();
        assert_eq!(expected.len(), MACOS_SYSLOG_MAX);

        let dir = tempfile::tempdir().unwrap();
        let sink = AuditSink::open(&cfg_at(dir.path())).unwrap();
        sink.append(&at_cap).await.unwrap();

        let msgs = macos_await_nonce_for(&at_cap, nonce);
        let needle = format!("session={nonce} ");
        let got = msgs
            .iter()
            .find(|m| m.contains(&needle))
            .expect("a line of exactly the cap must be DELIVERED, not dropped");

        // Truncation is MARKED, which makes this cheap and decisive.
        assert!(
            !got.ends_with("<\u{2026}>"),
            "a line of exactly MACOS_SYSLOG_MAX bytes came back TRUNCATED — the \
             cap constant is too high: {got}"
        );
        assert_eq!(
            got.len(),
            MACOS_SYSLOG_MAX,
            "the delivered byte length must equal what was submitted"
        );
    }
}
