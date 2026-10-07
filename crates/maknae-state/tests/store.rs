use maknae_graph::format;
use maknae_graph::graph::GraphBuilder;
use maknae_graph::kernel::SCHEMA;
use maknae_graph::record::GraphSpace;
use maknae_graph::schema::CompiledSet;
use maknae_state::anchor::{AnchorState, Checkpoint, Refusal};
use maknae_state::envelope::{self, ciphertext_digest, EnvelopeError, WrappingKey, KEY_LEN};
use maknae_state::store::{
    boot, BootAudit, BootOutcome, BootReport, StateDir, StoreError, MARKER_FILE, MAX_STORE_BYTES,
    REJECTED_PREFIX, STORE_FILE,
};
use std::fs;
use std::future::{ready, Future};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const NOW: u64 = 1_760_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Intent(u64, bool),
    Checkpoint(u64, [u8; 32], String),
}

#[derive(Default)]
struct Recorder {
    events: Vec<Event>,
    fail_intent: bool,
    fail_checkpoint: bool,
}

impl BootAudit for Recorder {
    fn intent_seed(
        &mut self,
        revision: u64,
        authorized: bool,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.events.push(Event::Intent(revision, authorized));
        ready(if self.fail_intent {
            Err(StoreError::Audit("intent refused".into()))
        } else {
            Ok(())
        })
    }

    fn checkpoint(
        &mut self,
        revision: u64,
        digest: [u8; 32],
        anchor: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.events
            .push(Event::Checkpoint(revision, digest, anchor.to_owned()));
        ready(if self.fail_checkpoint {
            Err(StoreError::Audit("checkpoint refused".into()))
        } else {
            Ok(())
        })
    }
}

fn key(byte: u8) -> WrappingKey {
    WrappingKey::new(Zeroizing::new([byte; KEY_LEN]))
}

struct Fixture {
    tmp: tempfile::TempDir,
    uid: u32,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(tmp.path()).unwrap().uid();
        Fixture { tmp, uid }
    }

    fn path(&self) -> &Path {
        self.tmp.path()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    fn dir(&self) -> StateDir {
        StateDir::open_with_marker_owner(self.path(), self.uid, self.uid).unwrap()
    }

    fn dir_with_marker_owner(&self, marker_owner: u32) -> StateDir {
        StateDir::open_with_marker_owner(self.path(), self.uid, marker_owner).unwrap()
    }

    fn write(&self, name: &str, bytes: &[u8], mode: u32) {
        let p = self.file(name);
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mark(&self, mode: u32) {
        self.write(MARKER_FILE, b"", mode);
    }

    fn store(&self) -> Vec<u8> {
        fs::read(self.file(STORE_FILE)).unwrap()
    }

    fn exists(&self, name: &str) -> bool {
        self.file(name).symlink_metadata().is_ok()
    }

    fn rejected(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with(REJECTED_PREFIX))
            .collect();
        names.sort();
        names
    }
}

fn sealed_graph(revision: u64, k: &WrappingKey) -> Vec<u8> {
    let g = GraphBuilder::new(GraphSpace::Kernel, revision)
        .build(&SCHEMA, &CompiledSet::default())
        .unwrap();
    envelope::seal(&format::encode(&g), k).unwrap()
}

fn revision_of(file: &[u8], k: &WrappingKey) -> u64 {
    let plain = envelope::open(file, k).unwrap();
    format::decode(&plain, GraphSpace::Kernel, &SCHEMA, &CompiledSet::default())
        .unwrap()
        .revision()
}

fn checkpoint_of(r: &BootReport) -> Option<Checkpoint> {
    Some(Checkpoint {
        revision: r.revision,
        digest: r.digest,
    })
}

async fn run(
    dir: &StateDir,
    k: &WrappingKey,
    checkpoint: Option<Checkpoint>,
) -> (Result<BootReport, StoreError>, Vec<Event>) {
    let mut audit = Recorder::default();
    let r = boot(dir, k, checkpoint, &mut audit, NOW).await;
    (r, audit.events)
}

#[tokio::test]
async fn first_boot_seeds_revision_1_and_checkpoints_seeded() {
    let fx = Fixture::new();
    let k = key(1);
    let (r, events) = run(&fx.dir(), &k, None).await;
    let r = r.unwrap();
    let file = fx.store();
    assert_eq!(r.revision, 1);
    assert_eq!(r.graph.revision(), 1);
    assert_eq!(r.digest, ciphertext_digest(&file));
    assert_eq!(
        r.outcome,
        BootOutcome::Seeded {
            authorized: false,
            rejected: None
        }
    );
    assert_eq!(
        events,
        vec![
            Event::Intent(1, false),
            Event::Checkpoint(1, r.digest, "seeded".into())
        ]
    );
    assert_eq!(revision_of(&file, &k), 1);
    let meta = fs::metadata(fx.file(STORE_FILE)).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o600);
    assert!(fx.rejected().is_empty());
}

#[tokio::test]
async fn restart_loads_verified() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let (r, events) = run(&fx.dir(), &k, checkpoint_of(&first)).await;
    let r = r.unwrap();
    assert_eq!(r.outcome, BootOutcome::Loaded(AnchorState::Verified));
    assert_eq!(r.revision, 1);
    assert_eq!(r.digest, first.digest);
    assert_eq!(r.graph, first.graph);
    assert_eq!(
        events,
        vec![Event::Checkpoint(1, first.digest, "verified".into())]
    );
}

#[tokio::test]
async fn a_store_without_a_checkpoint_loads_unavailable() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let (r, events) = run(&fx.dir(), &k, None).await;
    assert_eq!(
        r.unwrap().outcome,
        BootOutcome::Loaded(AnchorState::Unavailable)
    );
    assert_eq!(
        events,
        vec![Event::Checkpoint(
            1,
            first.digest,
            "rollback-anchor-unavailable".into()
        )]
    );
}

#[tokio::test]
async fn reseed_then_restart_verifies() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let old = fx.store();
    fx.mark(0o644);
    let (r, events) = run(&fx.dir(), &k, checkpoint_of(&first)).await;
    let r = r.unwrap();
    let name = format!("{REJECTED_PREFIX}{NOW}");
    assert_eq!(r.revision, 2);
    assert_eq!(
        r.outcome,
        BootOutcome::Seeded {
            authorized: true,
            rejected: Some(name.clone())
        }
    );
    assert_eq!(
        events,
        vec![
            Event::Intent(2, true),
            Event::Checkpoint(2, r.digest, "reseeded".into())
        ]
    );
    assert_eq!(fx.rejected(), vec![name.clone()]);
    assert_eq!(fs::read(fx.file(&name)).unwrap(), old);
    assert_eq!(fs::metadata(fx.file(&name)).unwrap().mode() & 0o777, 0o600);
    assert!(!fx.exists(MARKER_FILE));
    assert_eq!(revision_of(&fx.store(), &k), 2);

    let (again, _) = run(&fx.dir(), &k, checkpoint_of(&r)).await;
    let again = again.unwrap();
    assert_eq!(again.outcome, BootOutcome::Loaded(AnchorState::Verified));
    assert_eq!(again.revision, 2);
}

#[tokio::test]
async fn rolled_back_store_refuses() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let old = fx.store();
    fx.mark(0o644);
    let second = run(&fx.dir(), &k, checkpoint_of(&first)).await.0.unwrap();
    fx.write(STORE_FILE, &old, 0o600);
    let (r, events) = run(&fx.dir(), &k, checkpoint_of(&second)).await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::Refused(Refusal::RolledBack {
            store: 1,
            checkpoint: 2
        })
    );
    assert!(events.is_empty());
}

#[tokio::test]
async fn substituted_store_refuses() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let plain = envelope::open(&fx.store(), &k).unwrap();
    fx.write(STORE_FILE, &envelope::seal(&plain, &k).unwrap(), 0o600);
    let (r, _) = run(&fx.dir(), &k, checkpoint_of(&first)).await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::Refused(Refusal::Substituted { revision: 1 })
    );
}

#[tokio::test]
async fn advanced_store_loads_advanced() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    fx.write(STORE_FILE, &sealed_graph(3, &k), 0o600);
    let (r, _) = run(&fx.dir(), &k, checkpoint_of(&first)).await;
    let r = r.unwrap();
    assert_eq!(r.outcome, BootOutcome::Loaded(AnchorState::Advanced));
    assert_eq!(r.revision, 3);
}

#[tokio::test]
async fn missing_store_with_checkpoint_refuses() {
    let fx = Fixture::new();
    let k = key(1);
    let cp = Some(Checkpoint {
        revision: 3,
        digest: [7; 32],
    });
    let (r, events) = run(&fx.dir(), &k, cp).await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::Refused(Refusal::Missing { checkpoint: 3 })
    );
    assert!(events.is_empty());
    assert!(!fx.exists(STORE_FILE));
}

#[tokio::test]
async fn corrupt_store_refuses() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let mut file = fx.store();
    *file.last_mut().unwrap() ^= 1;
    fx.write(STORE_FILE, &file, 0o600);
    let (r, _) = run(&fx.dir(), &k, checkpoint_of(&first)).await;
    assert_eq!(r.unwrap_err(), StoreError::Envelope(EnvelopeError::Decrypt));
}

#[tokio::test]
async fn undecodable_plaintext_refuses_as_format() {
    let fx = Fixture::new();
    let k = key(1);
    fx.write(
        STORE_FILE,
        &envelope::seal(b"not a graph", &k).unwrap(),
        0o600,
    );
    let (r, _) = run(&fx.dir(), &k, None).await;
    assert!(matches!(r.unwrap_err(), StoreError::Format(_)));
}

#[tokio::test]
async fn wrong_key_refuses() {
    let fx = Fixture::new();
    let first = run(&fx.dir(), &key(1), None).await.0.unwrap();
    let (r, _) = run(&fx.dir(), &key(2), checkpoint_of(&first)).await;
    assert_eq!(r.unwrap_err(), StoreError::Envelope(EnvelopeError::Unwrap));
}

#[tokio::test]
async fn non_root_marker_does_not_authorize() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let mut file = fx.store();
    *file.last_mut().unwrap() ^= 1;
    fx.write(STORE_FILE, &file, 0o600);
    fx.mark(0o644);
    let other = fx.uid.wrapping_add(1);
    let (r, events) = run(&fx.dir_with_marker_owner(other), &k, checkpoint_of(&first)).await;
    assert_eq!(r.unwrap_err(), StoreError::Envelope(EnvelopeError::Decrypt));
    assert!(events.is_empty());
    assert!(fx.exists(MARKER_FILE));
    assert!(fx.rejected().is_empty());
}

#[tokio::test]
async fn an_ignored_marker_is_left_in_place_by_a_first_boot_seed() {
    let fx = Fixture::new();
    fx.mark(0o644);
    let other = fx.uid.wrapping_add(1);
    let (r, _) = run(&fx.dir_with_marker_owner(other), &key(1), None).await;
    assert_eq!(
        r.unwrap().outcome,
        BootOutcome::Seeded {
            authorized: false,
            rejected: None
        }
    );
    assert!(fx.exists(MARKER_FILE));
}

#[tokio::test]
async fn production_open_requires_a_root_owned_marker() {
    let fx = Fixture::new();
    if fx.uid == 0 {
        return;
    }
    fx.mark(0o644);
    let dir = StateDir::open(fx.path(), fx.uid).unwrap();
    let (r, _) = run(&dir, &key(1), None).await;
    assert_eq!(
        r.unwrap().outcome,
        BootOutcome::Seeded {
            authorized: false,
            rejected: None
        }
    );
    assert!(fx.exists(MARKER_FILE));
}

async fn marker_does_not_authorize(fx: &Fixture) {
    let (r, _) = run(&fx.dir(), &key(1), None).await;
    assert_eq!(
        r.unwrap().outcome,
        BootOutcome::Seeded {
            authorized: false,
            rejected: None
        }
    );
    assert!(fx.exists(MARKER_FILE));
}

#[tokio::test]
async fn group_writable_marker_does_not_authorize() {
    let fx = Fixture::new();
    fx.mark(0o664);
    marker_does_not_authorize(&fx).await;
}

#[tokio::test]
async fn other_writable_marker_does_not_authorize() {
    let fx = Fixture::new();
    fx.mark(0o646);
    marker_does_not_authorize(&fx).await;
}

#[tokio::test]
async fn hard_linked_marker_does_not_authorize() {
    let fx = Fixture::new();
    fx.mark(0o644);
    fs::hard_link(fx.file(MARKER_FILE), fx.file("second-link")).unwrap();
    marker_does_not_authorize(&fx).await;
}

#[tokio::test]
async fn oversized_marker_does_not_authorize() {
    let fx = Fixture::new();
    fx.write(MARKER_FILE, &[b'x'; 4097], 0o644);
    marker_does_not_authorize(&fx).await;
}

#[tokio::test]
async fn a_marker_at_the_size_limit_authorizes() {
    let fx = Fixture::new();
    fx.write(MARKER_FILE, &[b'x'; 4096], 0o644);
    let (r, _) = run(&fx.dir(), &key(1), None).await;
    assert_eq!(
        r.unwrap().outcome,
        BootOutcome::Seeded {
            authorized: true,
            rejected: None
        }
    );
    assert!(!fx.exists(MARKER_FILE));
}

#[tokio::test]
async fn directory_marker_does_not_authorize() {
    let fx = Fixture::new();
    fs::create_dir(fx.file(MARKER_FILE)).unwrap();
    let (r, _) = run(&fx.dir(), &key(1), None).await;
    assert_eq!(
        r.unwrap().outcome,
        BootOutcome::Seeded {
            authorized: false,
            rejected: None
        }
    );
}

#[tokio::test]
async fn reseed_floor_uses_a_decodable_old_store_without_a_checkpoint() {
    let fx = Fixture::new();
    let k = key(1);
    fx.write(STORE_FILE, &sealed_graph(9, &k), 0o600);
    fx.mark(0o644);
    let (r, events) = run(&fx.dir(), &k, None).await;
    let r = r.unwrap();
    assert_eq!(r.revision, 10);
    assert_eq!(events[0], Event::Intent(10, true));
    let name = format!("{REJECTED_PREFIX}{NOW}");
    let copy = fs::read(fx.file(&name)).unwrap();
    assert_eq!(revision_of(&copy, &k), 9);

    fx.write(STORE_FILE, &copy, 0o600);
    let (again, _) = run(&fx.dir(), &k, checkpoint_of(&r)).await;
    assert_eq!(
        again.unwrap_err(),
        StoreError::Refused(Refusal::RolledBack {
            store: 9,
            checkpoint: 10
        })
    );
}

#[tokio::test]
async fn reseed_floor_uses_the_checkpoint_over_a_lower_store() {
    let fx = Fixture::new();
    let k = key(1);
    fx.write(STORE_FILE, &sealed_graph(2, &k), 0o600);
    fx.mark(0o644);
    let cp = Some(Checkpoint {
        revision: 5,
        digest: [0; 32],
    });
    let (r, _) = run(&fx.dir(), &k, cp).await;
    assert_eq!(r.unwrap().revision, 6);
}

#[tokio::test]
async fn reseed_preserves_an_undecryptable_store() {
    let fx = Fixture::new();
    let k = key(1);
    fx.write(STORE_FILE, &sealed_graph(9, &key(2)), 0o600);
    let raw = fx.store();
    fx.mark(0o644);
    let cp = Some(Checkpoint {
        revision: 4,
        digest: [0; 32],
    });
    let (r, _) = run(&fx.dir(), &k, cp).await;
    let r = r.unwrap();
    let name = format!("{REJECTED_PREFIX}{NOW}");
    assert_eq!(r.revision, 5);
    assert_eq!(
        r.outcome,
        BootOutcome::Seeded {
            authorized: true,
            rejected: Some(name.clone())
        }
    );
    assert_eq!(fs::read(fx.file(&name)).unwrap(), raw);
}

#[tokio::test]
async fn reseed_replaces_an_unreadable_store() {
    let fx = Fixture::new();
    let k = key(1);
    fx.write(STORE_FILE, &sealed_graph(9, &k), 0o644);
    fx.mark(0o644);
    let (r, _) = run(&fx.dir(), &k, None).await;
    let r = r.unwrap();
    assert_eq!(r.revision, 1);
    match r.outcome {
        BootOutcome::Seeded {
            authorized: true,
            rejected: Some(why),
        } => assert!(
            why.starts_with("not preserved: insecure permissions"),
            "{why}"
        ),
        other => panic!("unexpected outcome {other:?}"),
    }
    assert!(fx.rejected().is_empty());
    assert_eq!(revision_of(&fx.store(), &k), 1);
    assert_eq!(
        fs::metadata(fx.file(STORE_FILE)).unwrap().mode() & 0o777,
        0o600
    );
    assert!(!fx.exists(MARKER_FILE));
}

#[tokio::test]
async fn unreadable_store_without_a_marker_refuses_as_io() {
    let fx = Fixture::new();
    let k = key(1);
    fx.write(STORE_FILE, &sealed_graph(1, &k), 0o644);
    let (r, events) = run(&fx.dir(), &k, None).await;
    match r.unwrap_err() {
        StoreError::Io(cause) => assert!(cause.contains("insecure permissions"), "{cause}"),
        other => panic!("unexpected error {other:?}"),
    }
    assert!(events.is_empty());
}

#[tokio::test]
async fn reseed_over_a_directory_store_fails_as_io() {
    let fx = Fixture::new();
    fs::create_dir(fx.file(STORE_FILE)).unwrap();
    fx.mark(0o644);
    let (r, events) = run(&fx.dir(), &key(1), None).await;
    assert!(matches!(r.unwrap_err(), StoreError::Io(_)));
    assert_eq!(events, vec![Event::Intent(1, true)]);
    assert!(fx.exists(MARKER_FILE));
}

#[tokio::test]
async fn seed_audits_intent_before_persist() {
    let fx = Fixture::new();
    let mut audit = Recorder {
        fail_intent: true,
        ..Recorder::default()
    };
    let r = boot(&fx.dir(), &key(1), None, &mut audit, NOW).await;
    assert_eq!(r.unwrap_err(), StoreError::Audit("intent refused".into()));
    assert!(!fx.exists(STORE_FILE));
    assert_eq!(audit.events, vec![Event::Intent(1, false)]);
}

#[tokio::test]
async fn reseed_intent_failure_writes_nothing() {
    let fx = Fixture::new();
    let k = key(1);
    run(&fx.dir(), &k, None).await.0.unwrap();
    let old = fx.store();
    fx.mark(0o644);
    let mut audit = Recorder {
        fail_intent: true,
        ..Recorder::default()
    };
    let r = boot(&fx.dir(), &k, None, &mut audit, NOW).await;
    assert!(matches!(r.unwrap_err(), StoreError::Audit(_)));
    assert_eq!(fx.store(), old);
    assert!(fx.rejected().is_empty());
    assert!(fx.exists(MARKER_FILE));
}

#[tokio::test]
async fn checkpoint_failure_fails_the_seed_and_the_load() {
    let fx = Fixture::new();
    let k = key(1);
    let mut audit = Recorder {
        fail_checkpoint: true,
        ..Recorder::default()
    };
    let r = boot(&fx.dir(), &k, None, &mut audit, NOW).await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::Audit("checkpoint refused".into())
    );
    let mut audit = Recorder {
        fail_checkpoint: true,
        ..Recorder::default()
    };
    let r = boot(&fx.dir(), &k, None, &mut audit, NOW).await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::Audit("checkpoint refused".into())
    );
}

#[tokio::test]
async fn oversized_store_refuses() {
    let fx = Fixture::new();
    let f = fs::File::create(fx.file(STORE_FILE)).unwrap();
    f.set_len(MAX_STORE_BYTES + 1).unwrap();
    drop(f);
    fs::set_permissions(fx.file(STORE_FILE), fs::Permissions::from_mode(0o600)).unwrap();
    let (r, _) = run(&fx.dir(), &key(1), None).await;
    match r.unwrap_err() {
        StoreError::Io(cause) => assert!(cause.contains("too large"), "{cause}"),
        other => panic!("unexpected error {other:?}"),
    }
}

#[test]
fn max_store_bytes_is_64_mib() {
    assert_eq!(MAX_STORE_BYTES, 64 * 1024 * 1024);
}

#[test]
fn state_dir_requires_owner_and_private_mode() {
    let fx = Fixture::new();
    assert!(matches!(
        StateDir::open(fx.path(), fx.uid.wrapping_add(1)).unwrap_err(),
        StoreError::Io(_)
    ));
    fs::set_permissions(fx.path(), fs::Permissions::from_mode(0o750)).unwrap();
    assert!(matches!(
        StateDir::open(fx.path(), fx.uid).unwrap_err(),
        StoreError::Io(_)
    ));
}

#[test]
fn store_error_display() {
    assert_eq!(
        StoreError::Io("gone".into()).to_string(),
        "graph store I/O failed: gone"
    );
    assert_eq!(
        StoreError::Envelope(EnvelopeError::Decrypt).to_string(),
        EnvelopeError::Decrypt.to_string()
    );
    assert_eq!(
        StoreError::Format("bad".into()).to_string(),
        "graph store does not decode: bad"
    );
    assert_eq!(
        StoreError::Refused(Refusal::Missing { checkpoint: 3 }).to_string(),
        Refusal::Missing { checkpoint: 3 }.to_string()
    );
    assert_eq!(
        StoreError::Audit("down".into()).to_string(),
        "graph store audit failed: down"
    );
}

fn encoded_graph(revision: u64) -> Vec<u8> {
    let g = GraphBuilder::new(GraphSpace::Kernel, revision)
        .build(&SCHEMA, &CompiledSet::default())
        .unwrap();
    format::encode(&g)
}

fn patch_u16(bytes: &mut [u8], at: usize, v: u16) {
    bytes[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

async fn boot_store(file: &[u8], k: &WrappingKey) -> StoreError {
    let fx = Fixture::new();
    fx.write(STORE_FILE, file, 0o600);
    run(&fx.dir(), k, None).await.0.unwrap_err()
}

fn sealed_with_graph_field(at: usize, v: u16, k: &WrappingKey) -> Vec<u8> {
    let mut plain = encoded_graph(1);
    patch_u16(&mut plain, at, v);
    envelope::seal(&plain, k).unwrap()
}

#[tokio::test]
async fn a_newer_envelope_version_is_a_newer_store() {
    let k = key(1);
    let mut file = sealed_graph(1, &k);
    patch_u16(&mut file, 4, 2);
    let e = boot_store(&file, &k).await;
    assert_eq!(
        e,
        StoreError::NewerStore(EnvelopeError::UnsupportedVersion(2).to_string())
    );
}

#[tokio::test]
async fn an_older_envelope_version_is_corruption() {
    let k = key(1);
    let mut file = sealed_graph(1, &k);
    patch_u16(&mut file, 4, 0);
    assert_eq!(
        boot_store(&file, &k).await,
        StoreError::Envelope(EnvelopeError::UnsupportedVersion(0))
    );
}

#[tokio::test]
async fn a_newer_graph_format_version_is_a_newer_store() {
    let k = key(1);
    let e = boot_store(&sealed_with_graph_field(4, 2, &k), &k).await;
    assert_eq!(
        e,
        StoreError::NewerStore(format::FormatError::UnsupportedFormatVersion(2).to_string())
    );
}

#[tokio::test]
async fn an_older_graph_format_version_is_a_format_error() {
    let k = key(1);
    let e = boot_store(&sealed_with_graph_field(4, 0, &k), &k).await;
    assert_eq!(
        e,
        StoreError::Format(format::FormatError::UnsupportedFormatVersion(0).to_string())
    );
}

#[tokio::test]
async fn a_newer_schema_version_is_a_newer_store() {
    let k = key(1);
    let e = boot_store(&sealed_with_graph_field(6, 2, &k), &k).await;
    assert_eq!(
        e,
        StoreError::NewerStore(
            format::FormatError::UnsupportedSchemaVersion {
                found: 2,
                expected: 1
            }
            .to_string()
        )
    );
}

#[tokio::test]
async fn an_older_schema_version_is_a_format_error() {
    let k = key(1);
    let e = boot_store(&sealed_with_graph_field(6, 0, &k), &k).await;
    assert_eq!(
        e,
        StoreError::Format(
            format::FormatError::UnsupportedSchemaVersion {
                found: 0,
                expected: 1
            }
            .to_string()
        )
    );
}

#[tokio::test]
async fn reseed_over_a_newer_store_preserves_it_and_seeds_past_the_checkpoint() {
    let fx = Fixture::new();
    let k = key(1);
    let mut file = sealed_graph(9, &k);
    patch_u16(&mut file, 4, 2);
    fx.write(STORE_FILE, &file, 0o600);
    fx.mark(0o644);
    let cp = Some(Checkpoint {
        revision: 3,
        digest: [0; 32],
    });
    let r = run(&fx.dir(), &k, cp).await.0.unwrap();
    let name = format!("{REJECTED_PREFIX}{NOW}");
    assert_eq!(r.revision, 4);
    assert_eq!(
        r.outcome,
        BootOutcome::Seeded {
            authorized: true,
            rejected: Some(name.clone())
        }
    );
    assert_eq!(fs::read(fx.file(&name)).unwrap(), file);
}

#[test]
fn newer_store_display() {
    assert_eq!(
        StoreError::NewerStore("v2".into()).to_string(),
        "the graph store was written by a newer maknaed: v2"
    );
}
