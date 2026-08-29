//! The append-only JSONL audit sink (ADR-0019) + the `AuditEmit` trait the
//! run-loop (Task 7) is generic over.
//!
//! Fail-closed (AU-5): [`AuditSink::open`] errors if the primary JSONL file
//! cannot be opened at boot; [`AuditSink::append`] errors on a primary write
//! failure. The journald/unified-log mirror is best-effort (Stage 3a: a
//! no-op stub) — its absence never masks a primary-sink failure.
//!
//! T3 (`coverage-tiers.toml`): I/O-bound, report-only coverage; the
//! `tests/fail_closed.rs` integration test is the primary evidence.
use crate::blocking_guard::{AuditAttempt, BlockingBreaker, BreakerAdmission};
use crate::error::AuditError;
use crate::record::{canonical_json, AuditRecord};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[cfg(unix)]
fn open_options() -> std::fs::OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    // `O_NOFOLLOW`: if the final path component is a symlink, `open()` fails with
    // ELOOP rather than following it — a symlink at the audit path must never
    // redirect privileged appends elsewhere. `custom_flags` is safe (no `unsafe`).
    opts.append(true)
        .create(true)
        .mode(0o640)
        .custom_flags(nix::libc::O_NOFOLLOW);
    opts
}

/// Fail-closed integrity check on the OPENED audit file descriptor. `fstat`s the
/// FILE HANDLE (`File::metadata`, never the path) so there is no TOCTOU window
/// between the check and subsequent appends: a pre-seeded audit file that is not a
/// regular file, is group/world-writable, or is not owned by our euid is refused so
/// another user cannot tamper with the durable audit trail (AU-9 / AU-5). A symlink
/// at the path is already refused upstream by `O_NOFOLLOW`.
///
/// A freshly-created file (the normal first-boot case) is a regular file, owned by
/// the daemon's euid, at mode `0o640 & ~umask` — which passes every check below.
#[cfg(unix)]
fn validate_secure_audit_file(file: &File, path: &Path) -> Result<(), AuditError> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata().map_err(|e| AuditError::OpenPrimary {
        path: path.to_path_buf(),
        detail: format!("cannot fstat opened audit file: {e}"),
    })?;
    let reject = |why: String| AuditError::OpenPrimary {
        path: path.to_path_buf(),
        detail: format!("insecure pre-existing audit file: {why}"),
    };
    if !meta.file_type().is_file() {
        return Err(reject("not a regular file".to_string()));
    }
    // Intended perms are 0o640 (owner rw, group r, other none). Reject any group
    // write/execute bit and ANY other-class bit (mask 0o037): another user must not
    // be able to write the trail. A freshly-created 0o640 file (group r only) passes.
    if meta.mode() & 0o037 != 0 {
        return Err(reject(format!(
            "group/world-accessible mode {:o} (require owner-only writable, e.g. 0o640)",
            meta.mode() & 0o7777
        )));
    }
    let euid = nix::unistd::geteuid().as_raw();
    if meta.uid() != euid {
        return Err(reject(format!(
            "owned by uid {} not our euid {euid}",
            meta.uid()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn open_options() -> std::fs::OpenOptions {
    let mut opts = std::fs::OpenOptions::new();
    opts.append(true).create(true);
    opts
}

/// The append-only JSONL audit sink: single-writer, off-runtime blocking I/O.
pub struct AuditSink {
    primary: Arc<Mutex<File>>,
    breaker: Arc<Mutex<BlockingBreaker>>,
    #[allow(dead_code)] // surfaced for future error context / re-open on failure
    path: PathBuf,
}

impl AuditSink {
    /// Open the primary JSONL sink (`O_APPEND|O_CREATE`, mode 0640 on unix).
    /// Fails closed: an unopenable primary sink is an `Err`, never a silent
    /// no-op sink.
    pub fn open(cfg: &maknae_config::AuditConfig) -> Result<Self, AuditError> {
        let file = open_options()
            .open(&cfg.jsonl_path)
            .map_err(|e| AuditError::OpenPrimary {
                path: cfg.jsonl_path.clone(),
                detail: e.to_string(),
            })?;
        // Validate the OPENED fd (not the path) — fail closed on an insecure or
        // symlinked pre-existing audit file (AU-9). A symlink already failed the
        // open above via O_NOFOLLOW; this catches perms / ownership / non-regular.
        #[cfg(unix)]
        validate_secure_audit_file(&file, &cfg.jsonl_path)?;
        Ok(AuditSink {
            primary: Arc::new(Mutex::new(file)),
            breaker: Arc::new(Mutex::new(BlockingBreaker::default())),
            path: cfg.jsonl_path.clone(),
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
                self.mirror_journald(rec);
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
                self.mirror_journald(rec);
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
        let result = joined.map_err(|e| {
            AuditError::WritePrimary(format!("blocking write task panicked/was cancelled: {e}"))
        })?;
        self.mirror_journald(rec);
        result
    }

    /// Best-effort journald/macOS-unified-log mirror (ADR-0019 "two sinks").
    /// Stage 3a stub: intentionally a no-op. Its absence never relieves the
    /// fail-closed requirement on the primary sink above.
    fn mirror_journald(&self, _rec: &AuditRecord) {}
}

fn write_line(file: &Mutex<File>, line: &str) -> Result<(), AuditError> {
    // A poisoned mutex (a prior writer panicked mid-write) still holds a
    // possibly-torn file handle; recovering it is strictly better than
    // wedging every subsequent append forever, and any partial prior write
    // is on the writer's own line (JSONL readers already must tolerate a
    // truncated last line from an unclean shutdown).
    let mut guard = file.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .write_all(line.as_bytes())
        .map_err(|e| AuditError::WritePrimary(e.to_string()))?;
    guard
        .sync_data()
        .map_err(|e| AuditError::WritePrimary(e.to_string()))
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
                plane_uri_san: Some("urn:maknae:plane:cli".into()),
            },
            action: "connect".into(),
            object: None,
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

    #[tokio::test]
    async fn append_multiple_records_writes_multiple_well_formed_lines() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = maknae_config::AuditConfig {
            jsonl_path: dir.path().join("audit.jsonl"),
            siem: None,
            au3_1: serde_json::json!({}),
        };
        let sink = AuditSink::open(&cfg).unwrap();
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
        let mut sink = AuditSink::open(&cfg).unwrap();
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
        assert!(AuditSink::open(&cfg).is_err());
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
        assert!(AuditSink::open(&cfg).is_ok());
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.file_type().is_file(), "created audit file is regular");
        assert_eq!(meta.uid(), nix::unistd::geteuid().as_raw(), "owned by us");
        assert_eq!(meta.mode() & 0o037, 0, "not group/world-writable");
        assert_eq!(meta.mode() & 0o600, 0o600, "owner can read+write");
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
        assert!(AuditSink::open(&cfg).is_err());
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
        assert!(AuditSink::open(&cfg).is_err());
    }

    #[tokio::test]
    async fn emit_trait_method_delegates_to_append() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = maknae_config::AuditConfig {
            jsonl_path: dir.path().join("audit.jsonl"),
            siem: None,
            au3_1: serde_json::json!({}),
        };
        let sink = AuditSink::open(&cfg).unwrap();
        AuditEmit::emit(&sink, &sample_record()).await.unwrap();
        let contents = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert_eq!(contents.lines().count(), 1);
    }
}
