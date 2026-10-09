use maknae_graph::baseline::BaselineLayer;
use maknae_graph::format;
use maknae_graph::graph::{Graph, GraphBuilder};
use maknae_graph::identity::{
    self, IdentityLayer, ReleaseCause, Released, SubjectEntry, BINDINGS_KEY_DROPPED,
    BINDINGS_MISSING, BINDINGS_NOT_MOVED,
};
use maknae_graph::kernel::{
    persisted_compiled_set, ATTR_SHA256, ROLE, SCHEMA, SUBJECT, VOCABULARY_SOURCE_KEY,
};
use maknae_graph::record::{AttrValue, Attrs, GraphSpace, NodeRecord, ProvenanceKind};
use maknae_graph::schema::{CompiledNode, CompiledSet};
use maknae_graph::sync::SyncBase;
use maknae_state::anchor::{AnchorState, Checkpoint, Refusal};
use maknae_state::envelope::{
    self, ciphertext_digest, EnvelopeError, WrappingKey, ENVELOPE_VERSION, KEY_LEN,
};
use maknae_state::store::{
    boot, commit, commit_accept, commit_live, initiator_name, remedy, transition_initiator,
    BootAudit, BootInputs, BootOutcome, BootReport, Committed, LiveInitiator, Migration, Remedy,
    StateDir, StoreError, INITIATOR_KERNEL, INITIATOR_OPERATOR, INITIATOR_ROOT_FILE,
    INITIATOR_SEED, MARKER_FILE, MAX_STORE_BYTES, MIRROR_FILE, REJECTED_PREFIX, STORE_FILE,
};
use maknae_state::vocabulary;
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
    Migrate(u64, Option<[u8; 32]>, [u8; 32], Vec<u32>),
    Transition(u64, String),
    Released(u64, Vec<Released>),
    Baseline(u64, Vec<String>),
    Sync(u64, Vec<String>),
}

#[derive(Default)]
struct Recorder {
    events: Vec<Event>,
    fail_intent: bool,
    fail_checkpoint: bool,
    fail_checkpoint_anchor: Option<&'static str>,
    fail_migrate: bool,
    fail_transition: bool,
    fail_released: bool,
    fail_baseline: bool,
    fail_sync: bool,
    store_at_released: Option<PathBuf>,
    store_bytes_at_released: Option<Vec<u8>>,
}

fn refuse(fail: bool, what: &str) -> Result<(), StoreError> {
    if fail {
        Err(StoreError::Audit(format!("{what} refused")))
    } else {
        Ok(())
    }
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
        let fail = self.fail_checkpoint || self.fail_checkpoint_anchor == Some(anchor);
        ready(refuse(fail, "checkpoint"))
    }

    fn intent_migrate(
        &mut self,
        revision: u64,
        from: Option<[u8; 32]>,
        to: [u8; 32],
        unbound: &[u32],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.events
            .push(Event::Migrate(revision, from, to, unbound.to_vec()));
        ready(refuse(self.fail_migrate, "migrate"))
    }

    fn intent_transition(
        &mut self,
        revision: u64,
        initiator: &'static str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.events
            .push(Event::Transition(revision, initiator.to_owned()));
        ready(refuse(self.fail_transition, "transition"))
    }

    fn released(
        &mut self,
        revision: u64,
        released: &[Released],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.events
            .push(Event::Released(revision, released.to_vec()));
        if let Some(p) = &self.store_at_released {
            self.store_bytes_at_released = Some(fs::read(p).unwrap());
        }
        ready(refuse(self.fail_released, "released"))
    }

    fn baseline(
        &mut self,
        revision: u64,
        events: &[String],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.events.push(Event::Baseline(revision, events.to_vec()));
        ready(refuse(self.fail_baseline, "baseline"))
    }

    fn sync(
        &mut self,
        revision: u64,
        events: &[String],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.events.push(Event::Sync(revision, events.to_vec()));
        ready(refuse(self.fail_sync, "sync"))
    }
}

const SOURCE: &str = "/etc/maknae/bindings.yaml";
const PRINCIPAL_UID: u32 = 501;
const MOVED_FROM: &str = "/etc/maknae/authz.yaml";

struct Inputs {
    compiled: CompiledSet,
    digest: [u8; 32],
    layer: IdentityLayer,
    unresolved: Vec<String>,
    missing: bool,
    lists_nobody: bool,
    baseline: BaselineLayer,
    seen: Seen,
    events: Vec<String>,
    sync: SyncBase,
    sync_seen: SyncSeen,
    sync_events: Vec<String>,
    sync_kind: maknae_config::SyncKind,
}

enum SyncSeen {
    Peek,
    Exactly(Option<SyncBase>),
}

const ADMIN_ROOT: &str = r#"{"admin":["root"]}"#;
const CREATED: &str = "sync base created from bindings.yaml (the store had none)";

fn synced(section: &str) -> SyncBase {
    SyncBase {
        base: section.into(),
        live: section.into(),
        conflicts: "[]".into(),
    }
}

enum Seen {
    /// What the kernel does: read the store's baseline first.
    Peek,
    Exactly(Option<[u8; 32]>),
}

const SEEDED: &str = "baseline seeded from maknae.yaml and config.d (no accepted baseline yet)";

fn bl(core: &str) -> BaselineLayer {
    BaselineLayer {
        sections: [("core".to_string(), core.to_string())]
            .into_iter()
            .collect(),
        system: "US".into(),
        ceiling: "UNCLASSIFIED".into(),
        sha256: envelope::sha256(core.as_bytes()),
        moved_from: None,
    }
}

const A: &str = r#"{"deployment_id":"a"}"#;
const B: &str = r#"{"deployment_id":"b"}"#;

impl Inputs {
    fn boot<'a>(
        &'a self,
        seen: Option<[u8; 32]>,
        sync_seen: Option<&'a SyncBase>,
    ) -> BootInputs<'a> {
        BootInputs {
            compiled: &self.compiled,
            vocabulary_sha256: self.digest,
            identity: &self.layer,
            unresolved_adversaries: &self.unresolved,
            bindings_missing: self.missing,
            bindings_lists_nobody: self.lists_nobody,
            principal_uid: PRINCIPAL_UID,
            baseline: &self.baseline,
            accepted_seen: seen,
            baseline_events: &self.events,
            sync: &self.sync,
            sync_seen,
            sync_events: &self.sync_events,
            sync_kind: self.sync_kind,
        }
    }
}

fn layer_at(label: &str, bindings: Option<&[u8]>, subjects: &[(u32, &str, &str)]) -> IdentityLayer {
    IdentityLayer {
        aliases: Default::default(),
        source: SOURCE.into(),
        label: label.into(),
        bindings_sha256: bindings.map(envelope::sha256),
        subjects: subjects
            .iter()
            .map(|(uid, name, role)| SubjectEntry {
                uid: *uid,
                name: (*name).into(),
                role: (*role).into(),
            })
            .collect(),
    }
}

fn layer(bindings: Option<&[u8]>, subjects: &[(u32, &str, &str)]) -> IdentityLayer {
    layer_at("UNCLASSIFIED", bindings, subjects)
}

fn inputs_with(layer: IdentityLayer) -> Inputs {
    let compiled = persisted_compiled_set(&layer.label);
    let digest = vocabulary::digest(&compiled).unwrap();
    let section = if layer.bindings_sha256.is_some() {
        ADMIN_ROOT
    } else {
        "null"
    };
    Inputs {
        compiled,
        digest,
        layer,
        unresolved: Vec::new(),
        missing: false,
        lists_nobody: false,
        baseline: bl(A),
        seen: Seen::Peek,
        events: vec![SEEDED.into()],
        sync: synced(section),
        sync_seen: SyncSeen::Peek,
        sync_events: vec![CREATED.into()],
        sync_kind: maknae_config::SyncKind::Created,
    }
}

fn inputs() -> Inputs {
    inputs_with(layer(
        Some(br#"{"admin":["root"]}"#),
        &[(0, "root", "admin")],
    ))
}

fn edited() -> Inputs {
    inputs_with(layer(Some(br#"{"user":["root"]}"#), &[(0, "root", "user")]))
}

fn wider() -> CompiledSet {
    let mut v: Vec<CompiledNode> = persisted_compiled_set("UNCLASSIFIED")
        .iter()
        .cloned()
        .collect();
    v.push(CompiledNode {
        kind: ROLE,
        key: "superadmin".into(),
        label: "UNCLASSIFIED".into(),
        attrs: Attrs::new(),
    });
    CompiledSet::new(v)
}

fn seal_graph(g: &Graph, k: &WrappingKey) -> Vec<u8> {
    envelope::seal(&format::encode(g), k).unwrap()
}

fn rebuild(
    g: &Graph,
    edit: impl Fn(&NodeRecord) -> Option<NodeRecord>,
    compiled: &CompiledSet,
) -> Graph {
    let mut b = GraphBuilder::new(GraphSpace::Kernel, g.revision());
    for n in g.nodes().iter().filter_map(edit) {
        b = b.node(n);
    }
    for e in g.edges() {
        b = b.edge(e.clone());
    }
    b.build(&SCHEMA, compiled).unwrap()
}

fn sealed_before_identity(revision: u64, k: &WrappingKey) -> Vec<u8> {
    let g = GraphBuilder::new(GraphSpace::Kernel, revision)
        .build(&SCHEMA, &CompiledSet::default())
        .unwrap();
    seal_graph(&g, k)
}

fn extracted(g: &Graph) -> identity::Extracted {
    identity::extract(g).unwrap()
}

fn subject_provenance(g: &Graph) -> Vec<ProvenanceKind> {
    g.nodes()
        .iter()
        .filter(|n| n.kind == SUBJECT)
        .map(|n| n.provenance.kind)
        .collect()
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
    sealed_with_sync(revision, k, Some(&inputs().sync))
}

fn sealed_unsynced(revision: u64, k: &WrappingKey) -> Vec<u8> {
    sealed_with_sync(revision, k, None)
}

fn sealed_with_sync(revision: u64, k: &WrappingKey, sync: Option<&SyncBase>) -> Vec<u8> {
    let i = inputs();
    let g = identity::build(
        &i.layer,
        Some(&bl(A)),
        sync,
        &i.compiled,
        i.digest,
        revision,
        ProvenanceKind::Seed,
    )
    .unwrap();
    seal_graph(&g, k)
}

fn graph_of(file: &[u8], k: &WrappingKey) -> Graph {
    let plain = envelope::open(file, k).unwrap();
    format::decode_stored_compiled(&plain, GraphSpace::Kernel, &SCHEMA)
        .unwrap()
        .0
}

fn revision_of(file: &[u8], k: &WrappingKey) -> u64 {
    graph_of(file, k).revision()
}

fn rejected_name(prior: &[u8]) -> String {
    let tag: String = ciphertext_digest(prior)[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{REJECTED_PREFIX}{NOW}.{tag}")
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
    run_with(dir, k, checkpoint, &inputs()).await
}

async fn run_with(
    dir: &StateDir,
    k: &WrappingKey,
    checkpoint: Option<Checkpoint>,
    i: &Inputs,
) -> (Result<BootReport, StoreError>, Vec<Event>) {
    let mut audit = Recorder::default();
    let r = boot(
        dir,
        k,
        checkpoint,
        &mut audit,
        NOW,
        &i.boot(seen(dir, k, i), sync_seen(dir, k, i).as_ref()),
    )
    .await;
    (r, audit.events)
}

fn peeked(fx: &Fixture, k: &WrappingKey) -> Option<[u8; 32]> {
    maknae_state::store::peek_baseline(&fx.dir(), k)
        .unwrap()
        .map(|b| b.sha256)
}

fn seen(dir: &StateDir, k: &WrappingKey, i: &Inputs) -> Option<[u8; 32]> {
    match i.seen {
        Seen::Peek => maknae_state::store::peek_baseline(dir, k)
            .ok()
            .flatten()
            .map(|b| b.sha256),
        Seen::Exactly(d) => d,
    }
}

fn sync_seen(dir: &StateDir, k: &WrappingKey, i: &Inputs) -> Option<SyncBase> {
    match &i.sync_seen {
        SyncSeen::Peek => maknae_state::store::peek_sync(dir, k).ok().flatten(),
        SyncSeen::Exactly(s) => s.clone(),
    }
}

fn peeked_sync(fx: &Fixture, k: &WrappingKey) -> Option<SyncBase> {
    maknae_state::store::peek_sync(&fx.dir(), k).unwrap()
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
    assert_eq!(r.marker_ignored, None);
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
            Event::Baseline(1, vec![SEEDED.into()]),
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
    let name = rejected_name(&old);
    let tag = name
        .strip_prefix("kernel.graph.rejected.1760000000.")
        .unwrap();
    assert_eq!(tag.len(), 16);
    assert!(tag
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    assert_eq!(r.marker_ignored, None);
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
            Event::Baseline(2, vec![SEEDED.into()]),
            Event::Checkpoint(2, r.digest, "reseeded".into())
        ]
    );
    assert_eq!(fx.rejected(), vec![name.clone()]);
    assert_eq!(fs::read(fx.file(&name)).unwrap(), old);
    assert_eq!(fs::metadata(fx.file(&name)).unwrap().mode() & 0o777, 0o600);
    assert!(!fx.exists(MARKER_FILE));
    assert_eq!(revision_of(&fx.store(), &k), 2);
    assert_eq!(extracted(&r.graph).layer, inputs().layer);
    assert_eq!(subject_provenance(&r.graph), [ProvenanceKind::Seed]);

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
    let r = r.unwrap();
    let why = r.marker_ignored.clone().unwrap();
    assert!(why.starts_with(&format!("owned by {}", fx.uid)), "{why}");
    assert_eq!(
        r.outcome,
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
    let r = r.unwrap();
    assert!(r.marker_ignored.is_some());
    assert_eq!(
        r.outcome,
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
    let old = sealed_graph(9, &k);
    fx.write(STORE_FILE, &old, 0o600);
    fx.mark(0o644);
    let (r, events) = run(&fx.dir(), &k, None).await;
    let r = r.unwrap();
    assert_eq!(r.revision, 10);
    assert_eq!(events[0], Event::Intent(10, true));
    let name = rejected_name(&old);
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
    let name = rejected_name(&raw);
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
async fn an_authorized_reseed_refuses_an_unreadable_store_and_completes_once_it_is_fixed() {
    let fx = Fixture::new();
    let k = key(1);
    let valid = sealed_graph(9, &k);
    fx.write(STORE_FILE, &valid, 0o644);
    fx.mark(0o644);
    let (r, events) = run(&fx.dir(), &k, None).await;
    match r.unwrap_err() {
        StoreError::StoreFileRefused(cause) => {
            assert!(cause.contains("insecure permissions"), "{cause}")
        }
        other => panic!("unexpected error {other:?}"),
    }
    assert!(events.is_empty());
    assert_eq!(fx.store(), valid);
    assert_eq!(
        fs::metadata(fx.file(STORE_FILE)).unwrap().mode() & 0o777,
        0o644
    );
    assert!(fx.rejected().is_empty());
    assert!(fx.exists(MARKER_FILE));

    fs::set_permissions(fx.file(STORE_FILE), fs::Permissions::from_mode(0o600)).unwrap();
    let r = run(&fx.dir(), &k, None).await.0.unwrap();
    assert_eq!(r.revision, 10);
    assert_eq!(
        r.outcome,
        BootOutcome::Seeded {
            authorized: true,
            rejected: Some(rejected_name(&valid))
        }
    );
    assert_eq!(fs::read(fx.file(&rejected_name(&valid))).unwrap(), valid);
    assert!(!fx.exists(MARKER_FILE));
}

#[tokio::test]
async fn unreadable_store_without_a_marker_is_a_refused_store_file() {
    let fx = Fixture::new();
    let k = key(1);
    fx.write(STORE_FILE, &sealed_graph(1, &k), 0o644);
    let (r, events) = run(&fx.dir(), &k, None).await;
    match r.unwrap_err() {
        StoreError::StoreFileRefused(cause) => {
            assert!(cause.contains("insecure permissions"), "{cause}")
        }
        other => panic!("unexpected error {other:?}"),
    }
    assert!(events.is_empty());
}

#[tokio::test]
async fn reseed_over_a_directory_store_is_refused_before_any_intent() {
    let fx = Fixture::new();
    fs::create_dir(fx.file(STORE_FILE)).unwrap();
    fx.mark(0o644);
    let (r, events) = run(&fx.dir(), &key(1), None).await;
    assert!(matches!(r.unwrap_err(), StoreError::StoreFileRefused(_)));
    assert!(events.is_empty());
    assert!(fx.file(STORE_FILE).is_dir());
    assert!(fx.exists(MARKER_FILE));
}

#[tokio::test]
async fn no_unreadable_store_is_ever_overwritten_or_told_to_reseed() {
    let k = key(1);
    let valid = sealed_graph(3, &k);
    type Plant = fn(&Fixture, &[u8]);
    let plants: [(&str, Plant); 6] = [
        ("group-readable", |fx, b| fx.write(STORE_FILE, b, 0o640)),
        ("world-readable", |fx, b| fx.write(STORE_FILE, b, 0o604)),
        ("group-writable", |fx, b| fx.write(STORE_FILE, b, 0o620)),
        ("two links", |fx, b| {
            fx.write(STORE_FILE, b, 0o600);
            fs::hard_link(fx.file(STORE_FILE), fx.file("second-link")).unwrap();
        }),
        ("oversized", |fx, _| {
            let f = fs::File::create(fx.file(STORE_FILE)).unwrap();
            f.set_len(MAX_STORE_BYTES + 1).unwrap();
            fs::set_permissions(fx.file(STORE_FILE), fs::Permissions::from_mode(0o600)).unwrap();
        }),
        ("symlink", |fx, b| {
            fx.write("elsewhere", b, 0o600);
            std::os::unix::fs::symlink("elsewhere", fx.file(STORE_FILE)).unwrap();
        }),
    ];
    for (what, plant) in plants {
        for marked in [false, true] {
            let fx = Fixture::new();
            plant(&fx, &valid);
            if marked {
                fx.mark(0o644);
            }
            let before = fs::symlink_metadata(fx.file(STORE_FILE)).unwrap();
            let (r, events) = run(&fx.dir(), &k, None).await;
            let e = r.unwrap_err();
            assert!(
                matches!(e, StoreError::StoreFileRefused(_)),
                "{what} marked={marked}: {e:?}"
            );
            assert_eq!(remedy(&e), Remedy::CheckStoreFile, "{what}");
            assert_ne!(remedy(&e), Remedy::Reseed, "{what}");
            assert!(events.is_empty(), "{what} marked={marked}");
            let after = fs::symlink_metadata(fx.file(STORE_FILE)).unwrap();
            assert_eq!(
                (before.ino(), before.mode(), before.len()),
                (after.ino(), after.mode(), after.len()),
                "{what} marked={marked}"
            );
            assert_eq!(fx.exists(MARKER_FILE), marked, "{what}");
            assert!(fx.rejected().is_empty(), "{what}");
        }
    }
}

#[test]
fn a_refused_store_file_never_maps_to_reseed() {
    let causes = (0u8..=255)
        .map(|b| String::from_utf8_lossy(&[b]).into_owned())
        .chain(
            [
                "",
                "reseed",
                "insecure permissions 100644",
                "too large",
                "graph store does not decode",
                "the graph store does not decrypt: tampered or truncated",
                "graph store revision 3 is older than the audited checkpoint 7: rolled back",
            ]
            .map(String::from),
        );
    for cause in causes {
        let e = StoreError::StoreFileRefused(cause.clone());
        assert_eq!(remedy(&e), Remedy::CheckStoreFile, "{cause:?}");
        assert!(e
            .to_string()
            .starts_with("graph store file kernel.graph refused: "));
    }
}

#[tokio::test]
async fn seed_audits_intent_before_persist() {
    let fx = Fixture::new();
    let mut audit = Recorder {
        fail_intent: true,
        ..Recorder::default()
    };
    let (seen, sync_seen) = (peeked(&fx, &key(1)), peeked_sync(&fx, &key(1)));
    let r = boot(
        &fx.dir(),
        &key(1),
        None,
        &mut audit,
        NOW,
        &inputs().boot(seen, sync_seen.as_ref()),
    )
    .await;
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
    let (seen, sync_seen) = (peeked(&fx, &k), peeked_sync(&fx, &k));
    let r = boot(
        &fx.dir(),
        &k,
        None,
        &mut audit,
        NOW,
        &inputs().boot(seen, sync_seen.as_ref()),
    )
    .await;
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
    let (seen, sync_seen) = (peeked(&fx, &k), peeked_sync(&fx, &k));
    let r = boot(
        &fx.dir(),
        &k,
        None,
        &mut audit,
        NOW,
        &inputs().boot(seen, sync_seen.as_ref()),
    )
    .await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::Audit("checkpoint refused".into())
    );
    let mut audit = Recorder {
        fail_checkpoint: true,
        ..Recorder::default()
    };
    let (seen, sync_seen) = (peeked(&fx, &k), peeked_sync(&fx, &k));
    let r = boot(
        &fx.dir(),
        &k,
        None,
        &mut audit,
        NOW,
        &inputs().boot(seen, sync_seen.as_ref()),
    )
    .await;
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
        StoreError::StoreFileRefused(cause) => assert!(cause.contains("too large"), "{cause}"),
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
        StoreError::StateDir(_)
    ));
    fs::set_permissions(fx.path(), fs::Permissions::from_mode(0o750)).unwrap();
    assert!(matches!(
        StateDir::open(fx.path(), fx.uid).unwrap_err(),
        StoreError::StateDir(_)
    ));
}

#[test]
fn a_second_state_dir_open_is_refused_while_the_first_lives() {
    let fx = Fixture::new();
    let _first = fx.dir();
    assert_eq!(
        StateDir::open_with_marker_owner(fx.path(), fx.uid, fx.uid).unwrap_err(),
        StoreError::InUse
    );
    assert_eq!(
        StateDir::open(fx.path(), fx.uid).unwrap_err(),
        StoreError::InUse
    );
}

#[test]
fn the_lock_is_released_when_the_state_dir_drops() {
    let fx = Fixture::new();
    drop(fx.dir());
    StateDir::open(fx.path(), fx.uid).expect("the first StateDir released its lock");
}

#[test]
fn store_error_display() {
    assert_eq!(
        StoreError::Io("gone".into()).to_string(),
        "graph store I/O failed: gone"
    );
    assert_eq!(
        StoreError::StateDir("mode".into()).to_string(),
        "graph state directory refused: mode"
    );
    assert_eq!(
        StoreError::InUse.to_string(),
        "another maknaed holds the kernel graph state directory"
    );
    assert_eq!(
        StoreError::StoreFileRefused("too large".into()).to_string(),
        "graph store file kernel.graph refused: too large"
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
    assert_eq!(
        StoreError::Vocabulary("forged").to_string(),
        "graph store vocabulary refused: forged"
    );
    assert_eq!(
        StoreError::Identity("role `x` is not compiled in".into()).to_string(),
        "the kernel identity layer does not build: role `x` is not compiled in"
    );
    assert_eq!(
        StoreError::StaleRevision {
            store: 3,
            attempted: 2
        }
        .to_string(),
        "graph store commit at revision 2 does not advance the store's revision 3"
    );
    assert_eq!(
        StoreError::BindingsRefused(BINDINGS_MISSING).to_string(),
        BINDINGS_MISSING
    );
    assert_eq!(
        StoreError::RejectedNameInUse {
            name: "kernel.graph.rejected.1.00".into(),
            cause: "it holds other bytes".into(),
        }
        .to_string(),
        "the rejected-copy name kernel.graph.rejected.1.00 is in use and does not hold this \
         store (it holds other bytes); move it aside, then restart"
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
async fn a_newer_cipher_or_wrap_id_is_a_newer_store() {
    let k = key(1);
    for (at, newer, err) in [
        (6, 2, EnvelopeError::UnknownAead(2)),
        (6, u16::MAX, EnvelopeError::UnknownAead(u16::MAX)),
        (8, 2, EnvelopeError::UnknownWrap(2)),
        (8, u16::MAX, EnvelopeError::UnknownWrap(u16::MAX)),
    ] {
        let mut file = sealed_graph(1, &k);
        patch_u16(&mut file, at, newer);
        let e = boot_store(&file, &k).await;
        assert_eq!(e, StoreError::NewerStore(err.to_string()));
        assert_eq!(remedy(&e), Remedy::Reinstall);
    }
}

#[tokio::test]
async fn a_zero_cipher_or_wrap_id_is_corruption() {
    let k = key(1);
    for (at, err) in [
        (6, EnvelopeError::UnknownAead(0)),
        (8, EnvelopeError::UnknownWrap(0)),
    ] {
        let mut file = sealed_graph(1, &k);
        patch_u16(&mut file, at, 0);
        let e = boot_store(&file, &k).await;
        assert_eq!(e, StoreError::Envelope(err));
        assert_eq!(remedy(&e), Remedy::Reseed);
    }
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
    let name = rejected_name(&file);
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

#[tokio::test]
async fn an_ignored_marker_is_reported_on_a_load() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    fx.mark(0o664);
    let r = run(&fx.dir(), &k, checkpoint_of(&first)).await.0.unwrap();
    assert_eq!(r.outcome, BootOutcome::Loaded(AnchorState::Verified));
    let why = r.marker_ignored.unwrap();
    assert!(why.starts_with("insecure permissions 100664"), "{why}");
    assert!(fx.exists(MARKER_FILE));
}

#[tokio::test]
async fn a_second_reseed_in_the_same_second_keeps_the_first_rejected_copy() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let original = fx.store();
    fx.mark(0o644);
    let second = run(&fx.dir(), &k, checkpoint_of(&first)).await.0.unwrap();
    let interim = fx.store();
    // A marker that survives the reseed: a crash, or a failed removal, before the marker went.
    fx.mark(0o644);
    let third = run(&fx.dir(), &k, checkpoint_of(&second)).await.0.unwrap();
    assert_eq!(third.revision, 3);
    assert_eq!(
        third.outcome,
        BootOutcome::Seeded {
            authorized: true,
            rejected: Some(rejected_name(&interim))
        }
    );
    let mut want = vec![rejected_name(&original), rejected_name(&interim)];
    want.sort();
    assert_ne!(want[0], want[1]);
    assert_eq!(fx.rejected(), want);
    assert_eq!(
        fs::read(fx.file(&rejected_name(&original))).unwrap(),
        original
    );
    assert_eq!(
        fs::read(fx.file(&rejected_name(&interim))).unwrap(),
        interim
    );
}

async fn refused_by_occupied_name(fx: &Fixture, k: &WrappingKey, old: &[u8], name: &str) {
    let r = run(&fx.dir(), k, None).await.0;
    match r {
        Err(e @ StoreError::RejectedNameInUse { .. }) => {
            assert_eq!(remedy(&e), Remedy::ClearRejectedName);
            let why = e.to_string();
            assert!(
                why.starts_with(&format!(
                    "the rejected-copy name {name} is in use and does not hold this store ("
                )),
                "{why}"
            );
            assert!(why.ends_with("); move it aside, then restart"), "{why}");
            let StoreError::RejectedNameInUse { name: got, .. } = e else {
                unreachable!()
            };
            assert_eq!(got, name);
        }
        other => panic!("unexpected result {other:?}"),
    }
    assert_eq!(fx.store(), old);
    assert!(fx.exists(MARKER_FILE));
}

#[tokio::test]
async fn an_identical_copy_at_the_rejected_name_counts_as_preserved() {
    let fx = Fixture::new();
    let k = key(1);
    let old = sealed_graph(4, &k);
    fx.write(STORE_FILE, &old, 0o600);
    let name = rejected_name(&old);
    fx.write(&name, &old, 0o600);
    fx.mark(0o644);
    let r = run(&fx.dir(), &k, None).await.0.unwrap();
    assert_eq!(r.revision, 5);
    assert_eq!(
        r.outcome,
        BootOutcome::Seeded {
            authorized: true,
            rejected: Some(format!("{name} (already preserved)"))
        }
    );
    assert_eq!(fs::read(fx.file(&name)).unwrap(), old);
    assert_eq!(fx.rejected(), vec![name]);
    assert_eq!(revision_of(&fx.store(), &k), 5);
    assert!(!fx.exists(MARKER_FILE));
}

#[tokio::test]
async fn a_rejected_name_holding_other_bytes_refuses_the_reseed() {
    let fx = Fixture::new();
    let k = key(1);
    let old = sealed_graph(4, &k);
    fx.write(STORE_FILE, &old, 0o600);
    let name = rejected_name(&old);
    fx.write(&name, b"first preserved copy", 0o600);
    fx.mark(0o644);
    refused_by_occupied_name(&fx, &k, &old, &name).await;
    assert_eq!(fs::read(fx.file(&name)).unwrap(), b"first preserved copy");
    assert_eq!(fx.rejected(), vec![name]);
}

#[tokio::test]
async fn an_empty_file_at_the_rejected_name_refuses_the_reseed() {
    let fx = Fixture::new();
    let k = key(1);
    let old = sealed_graph(4, &k);
    fx.write(STORE_FILE, &old, 0o600);
    let name = rejected_name(&old);
    fx.write(&name, b"", 0o600);
    fx.mark(0o644);
    refused_by_occupied_name(&fx, &k, &old, &name).await;
    assert!(fs::read(fx.file(&name)).unwrap().is_empty());
}

#[tokio::test]
async fn a_rejected_name_held_by_a_non_file_refuses_the_reseed() {
    let fx = Fixture::new();
    let k = key(1);
    let old = sealed_graph(4, &k);
    fx.write(STORE_FILE, &old, 0o600);
    let name = rejected_name(&old);
    fs::create_dir(fx.file(&name)).unwrap();
    fx.mark(0o644);
    refused_by_occupied_name(&fx, &k, &old, &name).await;
    assert!(fx.file(&name).is_dir());
    assert_eq!(fs::read_dir(fx.file(&name)).unwrap().count(), 0);
}

#[tokio::test]
async fn an_unreadable_copy_at_the_rejected_name_refuses_the_reseed() {
    let fx = Fixture::new();
    let k = key(1);
    let old = sealed_graph(4, &k);
    fx.write(STORE_FILE, &old, 0o600);
    let name = rejected_name(&old);
    fx.write(&name, &old, 0o644);
    fx.mark(0o644);
    refused_by_occupied_name(&fx, &k, &old, &name).await;
    assert_eq!(fs::read(fx.file(&name)).unwrap(), old);
}

#[test]
fn each_store_error_has_its_remedy() {
    let cases = [
        (StoreError::NewerStore("v2".into()), Remedy::Reinstall),
        (
            StoreError::Refused(Refusal::RolledBack {
                store: 1,
                checkpoint: 2,
            }),
            Remedy::Reseed,
        ),
        (
            StoreError::Refused(Refusal::Substituted { revision: 1 }),
            Remedy::Reseed,
        ),
        (
            StoreError::Refused(Refusal::Missing { checkpoint: 1 }),
            Remedy::Reseed,
        ),
        (
            StoreError::Refused(Refusal::RevisionExhausted),
            Remedy::Investigate,
        ),
        (StoreError::Envelope(EnvelopeError::Decrypt), Remedy::Reseed),
        (StoreError::Format("bad".into()), Remedy::Reseed),
        (
            StoreError::StoreFileRefused("too large".into()),
            Remedy::CheckStoreFile,
        ),
        (
            StoreError::RejectedNameInUse {
                name: "n".into(),
                cause: "c".into(),
            },
            Remedy::ClearRejectedName,
        ),
        (StoreError::StateDir("mode".into()), Remedy::CheckStateDir),
        (StoreError::Io("EACCES".into()), Remedy::CheckStateDir),
        (StoreError::Audit("down".into()), Remedy::CheckAudit),
        (StoreError::InUse, Remedy::StopOtherInstance),
        (StoreError::Vocabulary("forged"), Remedy::Reseed),
        (
            StoreError::Identity("unknown role".into()),
            Remedy::Investigate,
        ),
        (
            StoreError::StaleRevision {
                store: 2,
                attempted: 2,
            },
            Remedy::Investigate,
        ),
        (
            StoreError::BindingsRefused(BINDINGS_MISSING),
            Remedy::Investigate,
        ),
    ];
    for (e, want) in cases {
        assert_eq!(remedy(&e), want, "{e:?}");
    }
}

#[tokio::test]
async fn a_newer_store_is_never_told_to_reseed() {
    let newer = [
        EnvelopeError::UnsupportedVersion(ENVELOPE_VERSION + 1).to_string(),
        EnvelopeError::UnsupportedVersion(u16::MAX).to_string(),
        format::FormatError::UnsupportedFormatVersion(u16::MAX).to_string(),
        String::new(),
        "reseed".into(),
        "graph store does not decode".into(),
    ];
    for detail in newer {
        assert_eq!(
            remedy(&StoreError::NewerStore(detail.clone())),
            Remedy::Reinstall,
            "{detail}"
        );
    }
    let k = key(1);
    for v in (ENVELOPE_VERSION + 1..=ENVELOPE_VERSION + 64).chain([u16::MAX]) {
        let mut file = sealed_graph(1, &k);
        patch_u16(&mut file, 4, v);
        let e = boot_store(&file, &k).await;
        assert_eq!(remedy(&e), Remedy::Reinstall, "{e:?}");
    }
}

fn cp(revision: u64, file: &[u8]) -> Option<Checkpoint> {
    Some(Checkpoint {
        revision,
        digest: ciphertext_digest(file),
    })
}

#[tokio::test]
async fn first_boot_seeds_the_identity_layer_and_the_digest_node() {
    let fx = Fixture::new();
    let k = key(1);
    let i = inputs();
    let dir = fx.dir();
    let r = run_with(&dir, &k, None, &i).await.0.unwrap();
    let e = extracted(&r.graph);
    assert_eq!(e.layer, i.layer);
    assert_eq!(e.vocabulary_sha256, Some(i.digest));
    assert!(e.unbound.is_empty());
    assert_eq!(r.graph.nodes().iter().filter(|n| n.kind == ROLE).count(), 4);
    assert_eq!(subject_provenance(&r.graph), [ProvenanceKind::Seed]);
    assert_eq!(graph_of(&fx.store(), &k), r.graph);
    assert_eq!((r.migration, r.identity_transition), (None, false));
    assert_eq!(dir.store_revision(), 1);
    assert_eq!(dir.owner(), fx.uid);
}

#[tokio::test]
async fn restart_with_the_same_file_loads_without_a_transition() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let before = fx.store();
    let dir = fx.dir();
    let (r, events) = run(&dir, &k, checkpoint_of(&first)).await;
    let r = r.unwrap();
    assert_eq!((r.migration, r.identity_transition), (None, false));
    assert_eq!(r.revision, 1);
    assert_eq!(
        events,
        vec![Event::Checkpoint(1, first.digest, "verified".into())]
    );
    assert_eq!(fx.store(), before);
    assert_eq!(dir.store_revision(), 1);
}

#[tokio::test]
async fn restart_after_a_file_edit_applies_a_root_file_transition() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let before = fx.store();
    let e = edited();
    let dir = fx.dir();
    let (r, events) = run_with(&dir, &k, checkpoint_of(&first), &e).await;
    let r = r.unwrap();
    assert!(r.identity_transition);
    assert_eq!(r.migration, None);
    assert_eq!(r.revision, 2);
    assert_eq!(r.outcome, BootOutcome::Loaded(AnchorState::Verified));
    assert_eq!(
        events,
        vec![
            Event::Checkpoint(1, first.digest, "verified".into()),
            Event::Transition(2, "root-file".into()),
            Event::Checkpoint(2, r.digest, "transitioned".into()),
        ]
    );
    let after = fx.store();
    assert_ne!(after, before);
    assert_eq!(r.digest, ciphertext_digest(&after));
    assert_eq!(graph_of(&after, &k), r.graph);
    assert_eq!(extracted(&r.graph).layer, e.layer);
    assert_eq!(subject_provenance(&r.graph), [ProvenanceKind::RootFile]);
    assert_eq!(dir.store_revision(), 2);
    drop(dir);

    let (third, events) = run_with(&fx.dir(), &k, checkpoint_of(&r), &e).await;
    let third = third.unwrap();
    assert_eq!(third.outcome, BootOutcome::Loaded(AnchorState::Verified));
    assert!(!third.identity_transition);
    assert_eq!(events.len(), 1);
}

#[tokio::test]
async fn a_failed_transition_intent_persists_nothing() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let before = fx.store();
    let mut audit = Recorder {
        fail_transition: true,
        ..Recorder::default()
    };
    let (seen, sync_seen) = (peeked(&fx, &k), peeked_sync(&fx, &k));
    let r = boot(
        &fx.dir(),
        &k,
        checkpoint_of(&first),
        &mut audit,
        NOW,
        &edited().boot(seen, sync_seen.as_ref()),
    )
    .await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::Audit("transition refused".into())
    );
    assert_eq!(fx.store(), before);
}

#[tokio::test]
async fn a_transition_persists_before_its_checkpoint() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let mut audit = Recorder {
        fail_checkpoint_anchor: Some("transitioned"),
        ..Recorder::default()
    };
    let (seen, sync_seen) = (peeked(&fx, &k), peeked_sync(&fx, &k));
    let r = boot(
        &fx.dir(),
        &k,
        checkpoint_of(&first),
        &mut audit,
        NOW,
        &edited().boot(seen, sync_seen.as_ref()),
    )
    .await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::Audit("checkpoint refused".into())
    );
    assert_eq!(revision_of(&fx.store(), &k), 2);
    let (again, _) = run_with(&fx.dir(), &k, checkpoint_of(&first), &edited()).await;
    let again = again.unwrap();
    assert_eq!(again.outcome, BootOutcome::Loaded(AnchorState::Advanced));
    assert_eq!((again.revision, again.identity_transition), (2, false));
}

async fn boot_over_a_store_from_before_identity(
    revision: u64,
    i: &Inputs,
) -> (
    Fixture,
    Result<BootReport, StoreError>,
    Vec<Event>,
    [u8; 32],
) {
    let fx = Fixture::new();
    let k = key(1);
    let old = sealed_before_identity(revision, &k);
    fx.write(STORE_FILE, &old, 0o600);
    let (r, events) = run_with(&fx.dir(), &k, cp(revision, &old), i).await;
    (fx, r, events, ciphertext_digest(&old))
}

fn migrated_digest(events: &[Event]) -> [u8; 32] {
    match &events[2] {
        Event::Checkpoint(_, d, anchor) if anchor == "migrated" => *d,
        other => panic!("expected the migrated checkpoint, got {other:?}"),
    }
}

#[tokio::test]
async fn a_store_from_before_identity_migrates_then_seeds_identity() {
    let i = inputs();
    let (fx, r, events, old) = boot_over_a_store_from_before_identity(1, &i).await;
    let r = r.unwrap();
    assert_eq!(
        r.migration,
        Some(Migration {
            from: None,
            to: i.digest,
            unbound: vec![]
        })
    );
    assert!(r.identity_transition);
    assert_eq!(r.revision, 3);
    assert_eq!(r.outcome, BootOutcome::Loaded(AnchorState::Verified));
    let m = migrated_digest(&events);
    assert_ne!(m, r.digest);
    assert_eq!(
        events,
        vec![
            Event::Checkpoint(1, old, "verified".into()),
            Event::Migrate(2, None, i.digest, vec![]),
            Event::Checkpoint(2, m, "migrated".into()),
            Event::Baseline(3, vec![SEEDED.into()]),
            Event::Sync(3, vec![CREATED.into()]),
            Event::Transition(3, "root-file".into()),
            Event::Checkpoint(3, r.digest, "transitioned".into()),
        ]
    );
    assert!(r.baseline_transition);
    assert_eq!(extracted(&r.graph).layer, i.layer);
    assert_eq!(r.digest, ciphertext_digest(&fx.store()));
}

#[tokio::test]
async fn a_store_from_before_identity_without_bindings_migrates_then_gains_the_baseline() {
    let i = inputs_with(layer(None, &[]));
    let (fx, r, events, old) = boot_over_a_store_from_before_identity(1, &i).await;
    let r = r.unwrap();
    assert!(r.migration.is_some());
    assert!(!r.identity_transition);
    assert!(r.baseline_transition);
    assert_eq!(r.revision, 3);
    let m = migrated_digest(&events);
    assert_eq!(
        events,
        vec![
            Event::Checkpoint(1, old, "verified".into()),
            Event::Migrate(2, None, i.digest, vec![]),
            Event::Checkpoint(2, m, "migrated".into()),
            Event::Baseline(3, vec![SEEDED.into()]),
            Event::Sync(3, vec![CREATED.into()]),
            Event::Transition(3, "root-file".into()),
            Event::Checkpoint(3, r.digest, "transitioned".into()),
        ]
    );
    let e = extracted(&graph_of(&fx.store(), &key(1)));
    assert_eq!(e.layer, i.layer);
    assert_eq!(e.vocabulary_sha256, Some(i.digest));
}

#[tokio::test]
async fn a_pre_identity_store_checkpointed_at_its_revision_is_verified_then_migrated() {
    let i = inputs();
    let (_fx, r, events, _) = boot_over_a_store_from_before_identity(7, &i).await;
    let r = r.unwrap();
    assert_eq!(r.outcome, BootOutcome::Loaded(AnchorState::Verified));
    assert_eq!(r.revision, 9);
    assert_eq!(events[1], Event::Migrate(8, None, i.digest, vec![]));
    assert_eq!(events[3], Event::Baseline(9, vec![SEEDED.into()]));
    assert_eq!(events[4], Event::Sync(9, vec![CREATED.into()]));
    assert_eq!(events[5], Event::Transition(9, "root-file".into()));
}

#[tokio::test]
async fn a_migration_at_the_last_revision_refuses_as_exhausted() {
    let (fx, r, _, _) = boot_over_a_store_from_before_identity(u64::MAX, &inputs()).await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::Refused(Refusal::RevisionExhausted)
    );
    assert_eq!(revision_of(&fx.store(), &key(1)), u64::MAX);
}

#[tokio::test]
async fn migration_persists_before_its_checkpoint_and_a_failed_intent_persists_nothing() {
    let fx = Fixture::new();
    let k = key(1);
    let old = sealed_before_identity(1, &k);
    fx.write(STORE_FILE, &old, 0o600);
    let mut audit = Recorder {
        fail_migrate: true,
        ..Recorder::default()
    };
    let (seen, sync_seen) = (peeked(&fx, &k), peeked_sync(&fx, &k));
    let r = boot(
        &fx.dir(),
        &k,
        cp(1, &old),
        &mut audit,
        NOW,
        &inputs().boot(seen, sync_seen.as_ref()),
    )
    .await;
    assert_eq!(r.unwrap_err(), StoreError::Audit("migrate refused".into()));
    assert_eq!(fx.store(), old);
    assert_eq!(audit.events.len(), 2);

    let mut audit = Recorder {
        fail_checkpoint_anchor: Some("migrated"),
        ..Recorder::default()
    };
    let (seen, sync_seen) = (peeked(&fx, &k), peeked_sync(&fx, &k));
    let r = boot(
        &fx.dir(),
        &k,
        cp(1, &old),
        &mut audit,
        NOW,
        &inputs().boot(seen, sync_seen.as_ref()),
    )
    .await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::Audit("checkpoint refused".into())
    );
    assert_eq!(revision_of(&fx.store(), &k), 2);
    assert_eq!(audit.events.len(), 3);
}

#[tokio::test]
async fn forged_vocabulary_refuses() {
    let k = key(1);
    let i = inputs();
    let l = layer(None, &[]);
    let claims_binary =
        identity::build(&l, None, None, &wider(), i.digest, 1, ProvenanceKind::Seed).unwrap();
    let roles_only = identity::build(
        &l,
        None,
        None,
        &i.compiled,
        i.digest,
        1,
        ProvenanceKind::Seed,
    )
    .unwrap();
    let no_digest = rebuild(
        &roles_only,
        |n| (n.key != VOCABULARY_SOURCE_KEY).then(|| n.clone()),
        &i.compiled,
    );
    let stale_claim =
        identity::build(&l, None, None, &wider(), [7; 32], 1, ProvenanceKind::Seed).unwrap();
    for forged in [claims_binary, no_digest, stale_claim] {
        let fx = Fixture::new();
        let file = seal_graph(&forged, &k);
        fx.write(STORE_FILE, &file, 0o600);
        let (r, events) = run_with(&fx.dir(), &k, cp(1, &file), &i).await;
        let e = r.unwrap_err();
        assert!(matches!(e, StoreError::Vocabulary(_)), "{e:?}");
        assert_eq!(remedy(&e), Remedy::Reseed);
        assert_eq!(fx.store(), file);
        assert!(events.is_empty(), "{events:?}");
    }

    let bad_hex = rebuild(
        &roles_only,
        |n| {
            let mut n = n.clone();
            if n.key == VOCABULARY_SOURCE_KEY {
                n.attrs
                    .insert(ATTR_SHA256.into(), AttrValue::Str("AB".repeat(32)));
            }
            Some(n)
        },
        &i.compiled,
    );
    let fx = Fixture::new();
    let file = seal_graph(&bad_hex, &k);
    fx.write(STORE_FILE, &file, 0o600);
    let (r, _) = run_with(&fx.dir(), &k, cp(1, &file), &i).await;
    assert!(matches!(r.unwrap_err(), StoreError::Format(_)));
}

#[tokio::test]
async fn a_binds_to_a_vanished_role_is_dropped_and_reported() {
    let k = key(1);
    let i = inputs();
    let old_bindings: &[u8] = br#"{"admin":["root"],"superadmin":["alice"]}"#;
    let stored = layer(
        Some(old_bindings),
        &[
            (1000, "alice", "superadmin"),
            (0, "root", "admin"),
            (666, "mallory", "adversary"),
        ],
    );
    let wide = vocabulary::digest(&wider()).unwrap();
    let g = identity::build(
        &stored,
        Some(&bl(A)),
        Some(&i.sync),
        &wider(),
        wide,
        1,
        ProvenanceKind::Seed,
    )
    .unwrap();
    let file = seal_graph(&g, &k);

    let kept = inputs_with(layer(
        Some(old_bindings),
        &[(0, "root", "admin"), (666, "mallory", "adversary")],
    ));
    let fx = Fixture::new();
    fx.write(STORE_FILE, &file, 0o600);
    let r = run_with(&fx.dir(), &k, cp(1, &file), &kept)
        .await
        .0
        .unwrap();
    assert_eq!(
        r.migration,
        Some(Migration {
            from: Some(wide),
            to: i.digest,
            unbound: vec![1000]
        })
    );
    assert!(!r.identity_transition);
    assert_eq!(r.revision, 2);
    assert_eq!(extracted(&r.graph).layer, kept.layer);

    let fx = Fixture::new();
    fx.write(STORE_FILE, &file, 0o600);
    let (r, events) = run_with(&fx.dir(), &k, cp(1, &file), &i).await;
    let r = r.unwrap();
    assert_eq!(r.migration.unwrap().unbound, vec![1000]);
    assert!(r.identity_transition);
    assert_eq!(r.revision, 3);
    assert_eq!(
        events[1],
        Event::Migrate(2, Some(wide), i.digest, vec![1000])
    );
    assert_eq!(extracted(&r.graph).layer, i.layer);
}

#[tokio::test]
async fn a_classification_system_change_migrates_the_role_labels() {
    let k = key(1);
    let fx = Fixture::new();
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let aus = inputs_with(layer_at(
        "UNOFFICIAL",
        Some(br#"{"admin":["root"]}"#),
        &[(0, "root", "admin")],
    ));
    let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&first), &aus).await;
    let r = r.unwrap();
    assert_eq!(r.migration.as_ref().unwrap().from, Some(inputs().digest));
    assert!(!r.identity_transition);
    assert_eq!(r.revision, 2);
    assert_eq!(events.len(), 3);
    assert_eq!(extracted(&r.graph).layer, aus.layer);
    assert!(r.graph.nodes().iter().all(|n| n.label == "UNOFFICIAL"));
}

#[tokio::test]
async fn a_multi_subject_restart_with_the_same_file_does_not_churn() {
    let fx = Fixture::new();
    let k = key(1);
    let b: &[u8] = b"five";
    let one = inputs_with(layer(
        Some(b),
        &[
            (1003, "c", "user"),
            (0, "root", "admin"),
            (666, "m", "adversary"),
            (1001, "a", "guest"),
            (1002, "b", "user"),
        ],
    ));
    let two = inputs_with(layer(
        Some(b),
        &[
            (1002, "b", "user"),
            (1001, "a", "guest"),
            (1003, "c", "user"),
            (666, "m", "adversary"),
            (0, "root", "admin"),
        ],
    ));
    let first = run_with(&fx.dir(), &k, None, &one).await.0.unwrap();
    let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&first), &two).await;
    let r = r.unwrap();
    assert!(!r.identity_transition);
    assert_eq!(r.revision, 1);
    assert_eq!(events.len(), 1);
}

#[tokio::test]
async fn an_identity_layer_that_does_not_build_refuses_before_any_intent() {
    let fx = Fixture::new();
    let k = key(1);
    let bad = inputs_with(layer(None, &[(5, "x", "superadmin")]));
    let (r, events) = run_with(&fx.dir(), &k, None, &bad).await;
    let e = r.unwrap_err();
    assert!(matches!(e, StoreError::Identity(_)), "{e:?}");
    assert_eq!(remedy(&e), Remedy::Investigate);
    assert!(events.is_empty());
    assert!(!fx.exists(STORE_FILE));
}

fn next_graph(revision: u64, i: &Inputs) -> Graph {
    identity::build(
        &i.layer,
        Some(&bl(A)),
        Some(&i.sync),
        &i.compiled,
        i.digest,
        revision,
        ProvenanceKind::RootFile,
    )
    .unwrap()
}

#[tokio::test]
async fn commit_persists_at_the_next_revision_and_checkpoints() {
    let fx = Fixture::new();
    let k = key(1);
    let dir = fx.dir();
    run(&dir, &k, None).await.0.unwrap();
    let e = edited();
    let mut audit = Recorder::default();
    let c = commit(
        &dir,
        &k,
        &next_graph(2, &e),
        &[],
        &[],
        &mut audit,
        INITIATOR_ROOT_FILE,
    )
    .await
    .unwrap();
    let file = fx.store();
    assert_eq!(
        c,
        Committed {
            revision: 2,
            digest: ciphertext_digest(&file),
            durability_error: None,
            checkpoint_error: None
        }
    );
    assert_eq!(
        audit.events,
        vec![
            Event::Transition(2, "root-file".into()),
            Event::Checkpoint(2, c.digest, "transitioned".into()),
        ]
    );
    assert_eq!(dir.store_revision(), 2);
    assert_eq!(graph_of(&file, &k), next_graph(2, &e));

    for stale in [1, 2] {
        let mut audit = Recorder::default();
        let r = commit(
            &dir,
            &k,
            &next_graph(stale, &e),
            &[],
            &[],
            &mut audit,
            INITIATOR_ROOT_FILE,
        )
        .await;
        assert_eq!(
            r.unwrap_err(),
            StoreError::StaleRevision {
                store: 2,
                attempted: stale
            }
        );
        assert!(audit.events.is_empty());
        assert_eq!(fx.store(), file);
    }
    drop(dir);
    let (r, _) = run_with(&fx.dir(), &k, cp(2, &file), &e).await;
    let r = r.unwrap();
    assert_eq!(r.outcome, BootOutcome::Loaded(AnchorState::Verified));
    assert!(!r.identity_transition);
}

#[tokio::test]
async fn commit_names_its_initiator() {
    let fx = Fixture::new();
    let k = key(1);
    let dir = fx.dir();
    run(&dir, &k, None).await.0.unwrap();
    let mut audit = Recorder::default();
    commit(
        &dir,
        &k,
        &next_graph(2, &edited()),
        &[],
        &[],
        &mut audit,
        INITIATOR_SEED,
    )
    .await
    .unwrap();
    assert_eq!(audit.events[0], Event::Transition(2, "seed".into()));
}

#[tokio::test]
async fn commit_with_a_failing_checkpoint_still_publishes_and_reports_it() {
    let fx = Fixture::new();
    let k = key(1);
    let dir = fx.dir();
    let first = run(&dir, &k, None).await.0.unwrap();
    let e = edited();
    let mut audit = Recorder {
        fail_checkpoint: true,
        ..Recorder::default()
    };
    let c = commit(
        &dir,
        &k,
        &next_graph(2, &e),
        &[],
        &[],
        &mut audit,
        INITIATOR_ROOT_FILE,
    )
    .await
    .unwrap();
    assert_eq!(
        c.checkpoint_error.as_deref(),
        Some("graph store audit failed: checkpoint refused")
    );
    assert_eq!(c.revision, 2);
    assert_eq!(c.digest, ciphertext_digest(&fx.store()));
    assert_eq!(revision_of(&fx.store(), &k), 2);
    assert_eq!(dir.store_revision(), 2);

    let mut audit = Recorder::default();
    let c3 = commit(
        &dir,
        &k,
        &next_graph(3, &e),
        &[],
        &[],
        &mut audit,
        INITIATOR_ROOT_FILE,
    )
    .await
    .unwrap();
    assert_eq!((c3.revision, c3.checkpoint_error), (3, None));
    drop(dir);
    let (r, _) = run_with(&fx.dir(), &k, checkpoint_of(&first), &e).await;
    let r = r.unwrap();
    assert_eq!(r.outcome, BootOutcome::Loaded(AnchorState::Advanced));
    assert_eq!(r.revision, 3);
}

const NOT_DURABLE: &str =
    "published, but the directory sync failed (Other { raw: 5 }): kernel.graph";

#[tokio::test]
async fn a_commit_whose_directory_sync_fails_is_committed_and_advances_the_floor() {
    let fx = Fixture::new();
    let k = key(1);
    let dir = fx.dir();
    run(&dir, &k, None).await.0.unwrap();
    let e = edited();
    dir.fail_next_directory_sync();
    let mut audit = Recorder::default();
    let c = commit(
        &dir,
        &k,
        &next_graph(2, &e),
        &[],
        &[],
        &mut audit,
        INITIATOR_ROOT_FILE,
    )
    .await
    .unwrap();
    assert_eq!(
        c,
        Committed {
            revision: 2,
            digest: ciphertext_digest(&fx.store()),
            durability_error: Some(NOT_DURABLE.into()),
            checkpoint_error: None
        }
    );
    assert_eq!(
        audit.events,
        vec![
            Event::Transition(2, "root-file".into()),
            Event::Checkpoint(2, c.digest, "transitioned".into()),
        ]
    );
    assert_eq!(dir.store_revision(), 2);
    assert_eq!(graph_of(&fx.store(), &k), next_graph(2, &e));

    let r = commit(
        &dir,
        &k,
        &next_graph(2, &e),
        &[],
        &[],
        &mut Recorder::default(),
        INITIATOR_ROOT_FILE,
    )
    .await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::StaleRevision {
            store: 2,
            attempted: 2
        }
    );
    let c3 = commit(
        &dir,
        &k,
        &next_graph(3, &e),
        &[],
        &[],
        &mut Recorder::default(),
        INITIATOR_ROOT_FILE,
    )
    .await
    .unwrap();
    assert_eq!((c3.revision, c3.durability_error), (3, None));
    assert_eq!(dir.store_revision(), 3);
}

#[tokio::test]
async fn a_boot_seed_whose_directory_sync_fails_boots_and_reports_it() {
    let fx = Fixture::new();
    let k = key(1);
    let dir = fx.dir();
    dir.fail_next_directory_sync();
    let (r, events) = run(&dir, &k, None).await;
    let r = r.unwrap();
    assert_eq!(r.durability_error.as_deref(), Some(NOT_DURABLE));
    assert_eq!(r.revision, 1);
    assert_eq!(r.digest, ciphertext_digest(&fx.store()));
    assert_eq!(
        events.last(),
        Some(&Event::Checkpoint(1, r.digest, "seeded".into()))
    );
    assert_eq!(dir.store_revision(), 1);
}

#[tokio::test]
async fn a_boot_transition_whose_directory_sync_fails_boots_and_reports_it() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    assert_eq!(first.durability_error, None);
    let dir = fx.dir();
    dir.fail_next_directory_sync();
    let (r, events) = run_with(&dir, &k, checkpoint_of(&first), &edited()).await;
    let r = r.unwrap();
    assert!(r.identity_transition);
    assert_eq!(r.durability_error.as_deref(), Some(NOT_DURABLE));
    assert_eq!(r.digest, ciphertext_digest(&fx.store()));
    assert_eq!(
        events.last(),
        Some(&Event::Checkpoint(2, r.digest, "transitioned".into()))
    );
    assert_eq!(dir.store_revision(), 2);
}

#[tokio::test]
async fn a_boot_migration_whose_directory_sync_fails_boots_and_reports_it() {
    let fx = Fixture::new();
    let k = key(1);
    let mut i = inputs_with(layer(None, &[]));
    let first = run_with(&fx.dir(), &k, None, &i).await.0.unwrap();
    i.compiled = wider();
    i.digest = vocabulary::digest(&i.compiled).unwrap();
    let dir = fx.dir();
    dir.fail_next_directory_sync();
    let (r, events) = run_with(&dir, &k, checkpoint_of(&first), &i).await;
    let r = r.unwrap();
    assert!(r.migration.is_some() && !r.identity_transition && !r.baseline_transition);
    assert_eq!(r.durability_error.as_deref(), Some(NOT_DURABLE));
    assert_eq!(
        events.last(),
        Some(&Event::Checkpoint(2, r.digest, "migrated".into()))
    );
    assert_eq!(dir.store_revision(), 2);
}

#[tokio::test]
async fn commit_with_a_failing_intent_writes_nothing() {
    let fx = Fixture::new();
    let k = key(1);
    let dir = fx.dir();
    run(&dir, &k, None).await.0.unwrap();
    let before = fx.store();
    let mut audit = Recorder {
        fail_transition: true,
        ..Recorder::default()
    };
    let r = commit(
        &dir,
        &k,
        &next_graph(2, &edited()),
        &[],
        &[],
        &mut audit,
        INITIATOR_ROOT_FILE,
    )
    .await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::Audit("transition refused".into())
    );
    assert_eq!(fx.store(), before);
    assert_eq!(dir.store_revision(), 1);
    assert_eq!(audit.events.len(), 1);
}

#[tokio::test]
async fn a_plain_load_sets_the_store_revision_floor() {
    let fx = Fixture::new();
    let k = key(1);
    fx.write(STORE_FILE, &sealed_graph(7, &k), 0o600);
    let dir = fx.dir();
    assert_eq!(dir.store_revision(), 0);
    let r = run(&dir, &k, None).await.0.unwrap();
    assert_eq!(r.outcome, BootOutcome::Loaded(AnchorState::Unavailable));
    assert_eq!(
        (r.revision, r.migration, r.identity_transition),
        (7, None, false)
    );
    assert_eq!(dir.store_revision(), 7);
    let before = fx.store();
    let e = edited();
    let r = commit(
        &dir,
        &k,
        &next_graph(7, &e),
        &[],
        &[],
        &mut Recorder::default(),
        INITIATOR_ROOT_FILE,
    )
    .await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::StaleRevision {
            store: 7,
            attempted: 7
        }
    );
    assert_eq!(fx.store(), before);
    commit(
        &dir,
        &k,
        &next_graph(8, &e),
        &[],
        &[],
        &mut Recorder::default(),
        INITIATOR_ROOT_FILE,
    )
    .await
    .unwrap();
    assert_eq!(dir.store_revision(), 8);
}

#[tokio::test]
async fn restoring_the_pre_reload_store_after_a_reload_refuses_as_rolled_back() {
    let fx = Fixture::new();
    let k = key(1);
    let saved = sealed_graph(7, &k);
    fx.write(STORE_FILE, &saved, 0o600);
    let dir = fx.dir();
    run(&dir, &k, cp(7, &saved)).await.0.unwrap();
    let next = next_graph(dir.store_revision() + 1, &edited());
    let c = commit(
        &dir,
        &k,
        &next,
        &[],
        &[],
        &mut Recorder::default(),
        INITIATOR_ROOT_FILE,
    )
    .await
    .unwrap();
    assert_eq!(c.revision, 8);
    drop(dir);
    fx.write(STORE_FILE, &saved, 0o600);
    let (r, _) = run(
        &fx.dir(),
        &k,
        Some(Checkpoint {
            revision: c.revision,
            digest: c.digest,
        }),
    )
    .await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::Refused(Refusal::RolledBack {
            store: 7,
            checkpoint: 8
        })
    );
}

#[test]
fn state_dir_is_shareable_across_threads() {
    fn shareable<T: Send + Sync>() {}
    shareable::<StateDir>();
}

#[tokio::test]
async fn a_stored_node_the_identity_layer_does_not_project_is_rewritten() {
    let fx = Fixture::new();
    let k = key(1);
    let i = inputs();
    let clean = identity::build(
        &i.layer,
        Some(&bl(A)),
        Some(&i.sync),
        &i.compiled,
        i.digest,
        1,
        ProvenanceKind::Seed,
    )
    .unwrap();
    let mut stray = clean
        .nodes()
        .iter()
        .find(|n| n.kind == SUBJECT)
        .unwrap()
        .clone();
    stray.id = maknae_graph::record::NodeId(clean.nodes().len() as u64 + 1);
    stray.key = "uid:4242".into();
    stray.attrs.insert("uid".into(), AttrValue::U64(4242));
    let mut b = GraphBuilder::new(GraphSpace::Kernel, 1);
    for n in clean.nodes().iter().cloned().chain([stray]) {
        b = b.node(n);
    }
    for e in clean.edges() {
        b = b.edge(e.clone());
    }
    let tampered = b.build(&SCHEMA, &i.compiled).unwrap();
    assert_eq!(extracted(&tampered).unbound, vec![4242]);
    assert_eq!(extracted(&tampered).layer, i.layer);
    let file = seal_graph(&tampered, &k);
    fx.write(STORE_FILE, &file, 0o600);

    let (r, events) = run_with(&fx.dir(), &k, cp(1, &file), &i).await;
    let r = r.unwrap();
    assert!(r.identity_transition);
    assert_eq!(r.revision, 2);
    assert_eq!(events[1], Event::Transition(2, "root-file".into()));
    let e = extracted(&graph_of(&fx.store(), &k));
    assert!(e.unbound.is_empty());
    assert_eq!(e.layer, i.layer);
}

#[tokio::test]
async fn a_migrated_store_reloads_without_churn() {
    let i = inputs_with(layer(None, &[]));
    let (fx, r, _, _) = boot_over_a_store_from_before_identity(1, &i).await;
    let r = r.unwrap();
    let (again, events) = run_with(&fx.dir(), &key(1), checkpoint_of(&r), &i).await;
    let again = again.unwrap();
    assert_eq!((again.revision, again.identity_transition), (3, false));
    assert_eq!(again.migration, None);
    assert_eq!(events.len(), 1);
}

struct Racer<'a> {
    dir: &'a StateDir,
    key: &'a WrappingKey,
    rival: Graph,
    inner: Recorder,
}

impl BootAudit for Racer<'_> {
    fn intent_seed(
        &mut self,
        revision: u64,
        authorized: bool,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.inner.intent_seed(revision, authorized)
    }

    fn checkpoint(
        &mut self,
        revision: u64,
        digest: [u8; 32],
        anchor: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.inner.checkpoint(revision, digest, anchor)
    }

    fn intent_migrate(
        &mut self,
        revision: u64,
        from: Option<[u8; 32]>,
        to: [u8; 32],
        unbound: &[u32],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.inner.intent_migrate(revision, from, to, unbound)
    }

    fn released(
        &mut self,
        revision: u64,
        released: &[Released],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.inner.released(revision, released)
    }

    fn sync(
        &mut self,
        revision: u64,
        events: &[String],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.inner.sync(revision, events)
    }

    fn baseline(
        &mut self,
        revision: u64,
        events: &[String],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.inner.baseline(revision, events)
    }

    fn intent_transition(
        &mut self,
        _revision: u64,
        _initiator: &'static str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let (dir, key, rival) = (self.dir, self.key, self.rival.clone());
        async move {
            commit(
                dir,
                key,
                &rival,
                &[],
                &[],
                &mut Recorder::default(),
                INITIATOR_ROOT_FILE,
            )
            .await
            .unwrap();
            Ok(())
        }
    }
}

#[tokio::test]
async fn a_commit_raced_past_its_check_refuses_at_publish() {
    let fx = Fixture::new();
    let k = key(1);
    let dir = fx.dir();
    run(&dir, &k, None).await.0.unwrap();
    let mut racer = Racer {
        dir: &dir,
        key: &k,
        rival: next_graph(2, &inputs()),
        inner: Recorder::default(),
    };
    let r = commit(
        &dir,
        &k,
        &next_graph(2, &edited()),
        &[],
        &[],
        &mut racer,
        INITIATOR_ROOT_FILE,
    )
    .await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::StaleRevision {
            store: 2,
            attempted: 2
        }
    );
    assert_eq!(graph_of(&fx.store(), &k), next_graph(2, &inputs()));
    assert_eq!(dir.store_revision(), 2);
}

fn bindings_layer(
    source: &str,
    bindings: Option<&[u8]>,
    subjects: &[(u32, &str, &str)],
) -> IdentityLayer {
    IdentityLayer {
        source: source.into(),
        ..layer(bindings, subjects)
    }
}

const MALLORY_AND_OP: &[(u32, &str, &str)] = &[(666, "mallory", "adversary"), (501, "op", "user")];
const BLOCK: &[u8] = br#"{"adversary":["mallory"],"user":["op"]}"#;

fn is_contained(g: &Graph, uid: u32) -> bool {
    g.lookup(SUBJECT, &identity::subject_key(uid))
        .is_some_and(|s| g.out_edges(s.id, maknae_graph::kernel::CONTAINED).count() == 1)
}

fn unsynced_with(fx: &Fixture, k: &WrappingKey, l: IdentityLayer) -> Option<Checkpoint> {
    let i = inputs_with(l);
    let g = identity::build(
        &i.layer,
        Some(&bl(A)),
        None,
        &i.compiled,
        i.digest,
        1,
        ProvenanceKind::Seed,
    )
    .unwrap();
    let file = seal_graph(&g, k);
    fx.write(STORE_FILE, &file, 0o600);
    cp(1, &file)
}

async fn seeded_with(fx: &Fixture, k: &WrappingKey, l: IdentityLayer) -> BootReport {
    run_with(&fx.dir(), k, None, &inputs_with(l))
        .await
        .0
        .unwrap()
}

#[tokio::test]
async fn an_upgrade_without_the_pasted_block_refuses_before_any_record() {
    let fx = Fixture::new();
    let k = key(1);
    let first = unsynced_with(
        &fx,
        &k,
        bindings_layer(MOVED_FROM, Some(BLOCK), MALLORY_AND_OP),
    );
    let before = fx.store();
    for missing in [false, true] {
        let shipped = Inputs {
            missing,
            ..inputs_with(bindings_layer(SOURCE, None, &[]))
        };
        let (r, events) = run_with(&fx.dir(), &k, first, &shipped).await;
        assert_eq!(
            r.unwrap_err(),
            StoreError::BindingsRefused(BINDINGS_NOT_MOVED),
            "missing: {missing}"
        );
        assert!(events.is_empty(), "nothing recorded: {events:?}");
        assert_eq!(fx.store(), before);
    }
    assert_eq!(
        StoreError::BindingsRefused(BINDINGS_NOT_MOVED).to_string(),
        BINDINGS_NOT_MOVED
    );
}

#[tokio::test]
async fn an_upgrade_with_the_pasted_block_keeps_containment_and_releases_nothing() {
    let fx = Fixture::new();
    let k = key(1);
    let first = seeded_with(
        &fx,
        &k,
        bindings_layer(MOVED_FROM, Some(BLOCK), MALLORY_AND_OP),
    )
    .await;
    assert!(is_contained(&first.graph, 666));
    let pasted = inputs_with(bindings_layer(SOURCE, Some(BLOCK), MALLORY_AND_OP));
    let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&first), &pasted).await;
    let r = r.unwrap();
    assert!(r.identity_transition);
    assert!(r.released.is_empty());
    assert!(is_contained(&r.graph, 666));
    assert!(is_contained(&graph_of(&fx.store(), &k), 666));
    assert_eq!(
        events,
        vec![
            Event::Checkpoint(1, first.digest, "verified".into()),
            Event::Transition(2, "root-file".into()),
            Event::Checkpoint(2, r.digest, "transitioned".into()),
        ]
    );
    assert_eq!(extracted(&r.graph).layer.source, SOURCE);
}

#[tokio::test]
async fn a_persisted_containment_whose_name_stops_resolving_boots_without_a_transition() {
    let fx = Fixture::new();
    let k = key(1);
    let first = seeded_with(&fx, &k, bindings_layer(SOURCE, Some(BLOCK), MALLORY_AND_OP)).await;
    let before = fx.store();
    for gone in [
        bindings_layer(SOURCE, Some(BLOCK), &[(501, "op", "user")]),
        bindings_layer(
            SOURCE,
            Some(BLOCK),
            &[(666, "bob", "user"), (501, "op", "user")],
        ),
    ] {
        let i = Inputs {
            unresolved: vec!["mallory".into()],
            ..inputs_with(gone)
        };
        let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&first), &i).await;
        let r = r.unwrap();
        assert!(!r.identity_transition);
        assert!(r.released.is_empty());
        assert!(is_contained(&r.graph, 666));
        assert_eq!(events.len(), 1);
        assert_eq!(fx.store(), before);
    }
}

#[tokio::test]
async fn a_carried_containment_survives_a_transition_that_releases_another() {
    let fx = Fixture::new();
    let k = key(1);
    let both = [
        (666, "mallory", "adversary"),
        (700, "trudy", "adversary"),
        (501, "op", "user"),
    ];
    let first = seeded_with(&fx, &k, bindings_layer(SOURCE, Some(BLOCK), &both)).await;
    let i = Inputs {
        unresolved: vec!["mallory".into()],
        ..inputs_with(bindings_layer(
            SOURCE,
            Some(br#"{"adversary":["mallory"],"user":["op"]}"#),
            &[(501, "op", "user")],
        ))
    };
    let (r, _) = run_with(&fx.dir(), &k, checkpoint_of(&first), &i).await;
    let r = r.unwrap();
    assert!(r.identity_transition);
    assert_eq!(
        r.released,
        [Released {
            uid: 700,
            name: "trudy".into(),
            cause: ReleaseCause::NotListed
        }]
    );
    let stored = graph_of(&fx.store(), &k);
    assert!(is_contained(&stored, 666));
    assert!(!is_contained(&stored, 700));
}

#[tokio::test]
async fn an_alias_that_stops_resolving_keeps_its_uid_contained_through_boot() {
    let fx = Fixture::new();
    let k = key(1);
    let mut seed = bindings_layer(SOURCE, Some(BLOCK), &[(1001, "alice", "adversary")]);
    seed.aliases.insert("alicia".into(), 1001);
    let first = seeded_with(&fx, &k, seed).await;
    let i = Inputs {
        unresolved: vec!["alicia".into()],
        ..inputs_with(bindings_layer(
            SOURCE,
            Some(BLOCK),
            &[(1001, "operator", "admin"), (1002, "alice", "adversary")],
        ))
    };
    let (r, _) = run_with(&fx.dir(), &k, checkpoint_of(&first), &i).await;
    let r = r.unwrap();
    assert!(r.identity_transition);
    assert!(r.released.is_empty());
    let stored = graph_of(&fx.store(), &k);
    assert!(is_contained(&stored, 1001));
    assert!(is_contained(&stored, 1002));
}

#[tokio::test]
async fn a_boot_writes_its_release_records_before_the_persist() {
    let fx = Fixture::new();
    let k = key(1);
    let first = seeded_with(
        &fx,
        &k,
        bindings_layer(SOURCE, Some(BLOCK), &[(666, "mallory", "adversary")]),
    )
    .await;
    let before = fx.store();
    let edit = inputs_with(bindings_layer(
        SOURCE,
        Some(br#"{"user":["op"]}"#),
        &[(501, "op", "user")],
    ));
    let mallory = vec![Released {
        uid: 666,
        name: "mallory".into(),
        cause: ReleaseCause::NotListed,
    }];

    let mut failing = Recorder {
        fail_released: true,
        ..Recorder::default()
    };
    let (seen, sync_seen) = (peeked(&fx, &k), peeked_sync(&fx, &k));
    let r = boot(
        &fx.dir(),
        &k,
        checkpoint_of(&first),
        &mut failing,
        NOW,
        &edit.boot(seen, sync_seen.as_ref()),
    )
    .await;
    assert_eq!(r.unwrap_err(), StoreError::Audit("released refused".into()));
    assert_eq!(fx.store(), before);
    assert_eq!(
        failing.events,
        vec![
            Event::Checkpoint(1, first.digest, "verified".into()),
            Event::Released(2, mallory.clone()),
        ]
    );

    let mut audit = Recorder {
        store_at_released: Some(fx.file(STORE_FILE)),
        ..Recorder::default()
    };
    let (seen, sync_seen) = (peeked(&fx, &k), peeked_sync(&fx, &k));
    let r = boot(
        &fx.dir(),
        &k,
        checkpoint_of(&first),
        &mut audit,
        NOW,
        &edit.boot(seen, sync_seen.as_ref()),
    )
    .await
    .unwrap();
    assert_eq!(
        audit.events,
        vec![
            Event::Checkpoint(1, first.digest, "verified".into()),
            Event::Released(2, mallory.clone()),
            Event::Transition(2, "root-file".into()),
            Event::Checkpoint(2, r.digest, "transitioned".into()),
        ]
    );
    assert_eq!(r.released, mallory);
    assert_eq!(audit.store_bytes_at_released, Some(before.clone()));
    assert_ne!(fx.store(), before);
}

#[tokio::test]
async fn a_commit_writes_its_release_records_before_the_persist() {
    let fx = Fixture::new();
    let k = key(1);
    let dir = fx.dir();
    run(&dir, &k, None).await.0.unwrap();
    let before = fx.store();
    let released = vec![Released {
        uid: 0,
        name: "root".into(),
        cause: ReleaseCause::BoundAs("user".into()),
    }];

    let mut failing = Recorder {
        fail_released: true,
        ..Recorder::default()
    };
    let r = commit(
        &dir,
        &k,
        &next_graph(2, &edited()),
        &released,
        &[],
        &mut failing,
        INITIATOR_ROOT_FILE,
    )
    .await;
    assert_eq!(r.unwrap_err(), StoreError::Audit("released refused".into()));
    assert_eq!(fx.store(), before);
    assert_eq!(dir.store_revision(), 1);
    assert_eq!(failing.events, vec![Event::Released(2, released.clone())]);

    let mut audit = Recorder {
        store_at_released: Some(fx.file(STORE_FILE)),
        ..Recorder::default()
    };
    let c = commit(
        &dir,
        &k,
        &next_graph(2, &edited()),
        &released,
        &[],
        &mut audit,
        INITIATOR_ROOT_FILE,
    )
    .await
    .unwrap();
    assert_eq!(
        audit.events,
        vec![
            Event::Released(2, released),
            Event::Transition(2, "root-file".into()),
            Event::Checkpoint(2, c.digest, "transitioned".into()),
        ]
    );
    assert_eq!(audit.store_bytes_at_released, Some(before.clone()));
    assert_ne!(fx.store(), before);
}

#[tokio::test]
async fn an_upgrade_from_any_other_spelling_of_authz_yaml_refuses() {
    for old in ["/private/etc/maknae/authz.yaml", "/opt/x/authz.yaml"] {
        let fx = Fixture::new();
        let k = key(1);
        let first = unsynced_with(&fx, &k, bindings_layer(old, Some(BLOCK), MALLORY_AND_OP));
        let before = fx.store();
        let shipped = inputs_with(bindings_layer(SOURCE, None, &[]));
        let (r, events) = run_with(&fx.dir(), &k, first, &shipped).await;
        assert_eq!(
            r.unwrap_err(),
            StoreError::BindingsRefused(BINDINGS_NOT_MOVED),
            "{old}"
        );
        assert!(events.is_empty());
        assert_eq!(fx.store(), before);
    }
}

fn with_baseline(i: Inputs, b: BaselineLayer, seen: Seen, events: &[&str]) -> Inputs {
    Inputs {
        baseline: b,
        seen,
        events: events.iter().map(|e| e.to_string()).collect(),
        ..i
    }
}

fn stored_baseline(fx: &Fixture, k: &WrappingKey) -> Option<BaselineLayer> {
    identity::extract(&graph_of(&fx.store(), k))
        .unwrap()
        .baseline
}

#[tokio::test]
async fn a_first_boot_seeds_the_baseline_with_its_events_written_ahead() {
    let fx = Fixture::new();
    let k = key(1);
    let (r, events) = run(&fx.dir(), &k, None).await;
    let r = r.unwrap();
    assert_eq!(
        events,
        vec![
            Event::Intent(1, false),
            Event::Baseline(1, vec![SEEDED.into()]),
            Event::Checkpoint(1, r.digest, "seeded".into())
        ]
    );
    assert_eq!(stored_baseline(&fx, &k), Some(bl(A)));
}

#[tokio::test]
async fn a_seed_without_a_baseline_record_persists_nothing() {
    let fx = Fixture::new();
    let k = key(1);
    let i = with_baseline(inputs(), bl(A), Seen::Exactly(None), &[]);
    let (r, events) = run_with(&fx.dir(), &k, None, &i).await;
    assert!(matches!(r, Err(StoreError::BaselineUnrecorded)), "{r:?}");
    assert!(events.is_empty(), "{events:?}");
    assert!(!fx.exists(STORE_FILE));
}

#[tokio::test]
async fn a_first_boot_decided_from_an_accepted_baseline_is_refused() {
    let fx = Fixture::new();
    let i = with_baseline(inputs(), bl(A), Seen::Exactly(Some(bl(A).sha256)), &["x"]);
    let (r, events) = run_with(&fx.dir(), &key(1), None, &i).await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::BaselineUnseen {
            stored: None,
            seen: Some(identity::hex(&bl(A).sha256)),
        }
    );
    assert!(events.is_empty(), "{events:?}");
    assert!(!fx.exists(STORE_FILE));
}

#[tokio::test]
async fn a_failed_seed_baseline_record_persists_nothing() {
    let fx = Fixture::new();
    let mut audit = Recorder {
        fail_baseline: true,
        ..Recorder::default()
    };
    let i = inputs();
    let r = boot(
        &fx.dir(),
        &key(1),
        None,
        &mut audit,
        NOW,
        &i.boot(None, None),
    )
    .await;
    assert_eq!(r.unwrap_err(), StoreError::Audit("baseline refused".into()));
    assert!(!fx.exists(STORE_FILE));
    assert_eq!(
        audit.events,
        vec![
            Event::Intent(1, false),
            Event::Baseline(1, vec![SEEDED.into()])
        ]
    );
}

#[tokio::test]
async fn an_authorized_reseed_persists_the_given_baseline() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    fx.mark(0o644);
    let i = with_baseline(inputs(), bl(B), Seen::Exactly(None), &["reseeded"]);
    let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&first), &i).await;
    let r = r.unwrap();
    assert_eq!(
        events,
        vec![
            Event::Intent(2, true),
            Event::Baseline(2, vec!["reseeded".into()]),
            Event::Checkpoint(2, r.digest, "reseeded".into())
        ]
    );
    assert_eq!(stored_baseline(&fx, &k), Some(bl(B)));
}

#[tokio::test]
async fn an_upgrade_store_without_a_baseline_gains_one_in_one_recorded_transition() {
    let fx = Fixture::new();
    let k = key(1);
    let i = inputs();
    let old = identity::build(
        &i.layer,
        None,
        None,
        &i.compiled,
        i.digest,
        4,
        ProvenanceKind::Seed,
    )
    .unwrap();
    fx.write(STORE_FILE, &seal_graph(&old, &k), 0o600);
    let cp = Some(Checkpoint {
        revision: 4,
        digest: ciphertext_digest(&fx.store()),
    });
    let (r, events) = run(&fx.dir(), &k, cp).await;
    let r = r.unwrap();
    assert_eq!(
        &events[1..],
        &[
            Event::Baseline(5, vec![SEEDED.into()]),
            Event::Sync(5, vec![CREATED.into()]),
            Event::Transition(5, INITIATOR_ROOT_FILE.into()),
            Event::Checkpoint(5, r.digest, "transitioned".into()),
        ]
    );
    assert!(r.baseline_transition);
    assert!(!r.identity_transition);
    assert_eq!(stored_baseline(&fx, &k), Some(bl(A)));
}

#[tokio::test]
async fn an_identity_transition_carries_the_stored_baseline() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&first), &edited()).await;
    let r = r.unwrap();
    assert!(r.identity_transition);
    assert!(!r.baseline_transition);
    assert!(!events.iter().any(|e| matches!(e, Event::Baseline(..))));
    assert_eq!(stored_baseline(&fx, &k), Some(bl(A)));
    let (again, events) = run_with(&fx.dir(), &k, checkpoint_of(&r), &edited()).await;
    assert_eq!(again.unwrap().revision, 2);
    assert_eq!(
        events,
        vec![Event::Checkpoint(2, r.digest, "verified".into())]
    );
}

#[tokio::test]
async fn a_recorded_baseline_change_persists_the_new_baseline_once() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let i = with_baseline(
        inputs(),
        bl(B),
        Seen::Exactly(Some(bl(A).sha256)),
        &["core follows"],
    );
    let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&first), &i).await;
    let r = r.unwrap();
    assert_eq!(
        events,
        vec![
            Event::Checkpoint(1, first.digest, "verified".into()),
            Event::Baseline(2, vec!["core follows".into()]),
            Event::Transition(2, INITIATOR_ROOT_FILE.into()),
            Event::Checkpoint(2, r.digest, "transitioned".into()),
        ]
    );
    assert!(r.baseline_transition && !r.identity_transition);
    assert_eq!(stored_baseline(&fx, &k), Some(bl(B)));
    let again = with_baseline(inputs(), bl(B), Seen::Peek, &[]);
    let (r2, events) = run_with(&fx.dir(), &k, checkpoint_of(&r), &again).await;
    assert_eq!(r2.unwrap().revision, 2);
    assert_eq!(
        events,
        vec![Event::Checkpoint(2, r.digest, "verified".into())]
    );
}

#[tokio::test]
async fn a_boot_writes_releases_then_the_baseline_then_the_sync_record_before_the_transition() {
    let fx = Fixture::new();
    let k = key(1);
    let first = seeded_with(
        &fx,
        &k,
        bindings_layer(
            SOURCE,
            Some(BLOCK),
            &[(666, "mallory", "adversary"), (1001, "bob", "user")],
        ),
    )
    .await;
    let edit = inputs_with(bindings_layer(
        SOURCE,
        Some(br#"{"user":["bob"]}"#),
        &[(1001, "bob", "user")],
    ));
    let mut i = with_baseline(
        edit,
        bl(B),
        Seen::Exactly(Some(bl(A).sha256)),
        &["one", "two"],
    );
    i.sync = synced(r#"{"user":["bob"]}"#);
    i.sync_kind = maknae_config::SyncKind::RootFile;
    i.sync_events = vec!["s".into()];
    let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&first), &i).await;
    let r = r.unwrap();
    assert_eq!(
        &events[1..],
        &[
            Event::Released(
                2,
                vec![Released {
                    uid: 666,
                    name: "mallory".into(),
                    cause: ReleaseCause::NotListed,
                }]
            ),
            Event::Baseline(2, vec!["one".into(), "two".into()]),
            Event::Sync(2, vec!["s".into()]),
            Event::Transition(2, INITIATOR_ROOT_FILE.into()),
            Event::Checkpoint(2, r.digest, "transitioned".into()),
        ]
    );
    assert!(r.baseline_transition && r.identity_transition);
    let stored = identity::extract(&graph_of(&fx.store(), &k)).unwrap();
    assert_eq!(stored.baseline, Some(bl(B)));
    assert_eq!(stored.sync, Some(i.sync.clone()));
    assert_eq!(sorted_subjects(&stored.layer), sorted_subjects(&i.layer));
}

fn sorted_subjects(l: &IdentityLayer) -> Vec<(u32, String)> {
    let mut v: Vec<_> = l.subjects.iter().map(|s| (s.uid, s.role.clone())).collect();
    v.sort();
    v
}

#[tokio::test]
async fn an_unchanged_baseline_writes_nothing() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let (r, events) = run(&fx.dir(), &k, checkpoint_of(&first)).await;
    let r = r.unwrap();
    assert_eq!(r.revision, 1);
    assert!(!r.baseline_transition);
    assert_eq!(
        events,
        vec![Event::Checkpoint(1, first.digest, "verified".into())]
    );
}

#[tokio::test]
async fn a_baseline_change_without_its_record_persists_nothing() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let before = fx.store();
    let i = with_baseline(inputs(), bl(B), Seen::Exactly(Some(bl(A).sha256)), &[]);
    let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&first), &i).await;
    assert!(matches!(r, Err(StoreError::BaselineUnrecorded)), "{r:?}");
    assert!(!events.iter().any(|e| matches!(e, Event::Transition(..))));
    assert_eq!(fx.store(), before);
}

#[tokio::test]
async fn a_failed_baseline_record_persists_nothing() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let before = fx.store();
    let i = with_baseline(
        inputs(),
        bl(B),
        Seen::Exactly(Some(bl(A).sha256)),
        &["vault follows maknae.yaml at start"],
    );
    let mut audit = Recorder {
        fail_baseline: true,
        ..Recorder::default()
    };
    let sync_seen = peeked_sync(&fx, &k);
    let r = boot(
        &fx.dir(),
        &k,
        checkpoint_of(&first),
        &mut audit,
        NOW,
        &i.boot(Some(bl(A).sha256), sync_seen.as_ref()),
    )
    .await;
    assert!(matches!(r, Err(StoreError::Audit(_))), "{r:?}");
    assert!(!audit
        .events
        .iter()
        .any(|e| matches!(e, Event::Transition(..))));
    assert_eq!(fx.store(), before);
}

#[tokio::test]
async fn a_boot_decided_from_another_baseline_is_refused() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let before = fx.store();
    for seen in [None, Some(bl(r#"{"deployment_id":"c"}"#).sha256)] {
        let i = with_baseline(inputs(), bl(B), Seen::Exactly(seen), &["x"]);
        let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&first), &i).await;
        let e = r.unwrap_err();
        assert!(matches!(e, StoreError::BaselineUnseen { .. }), "{e:?}");
        assert_eq!(remedy(&e), Remedy::Investigate);
        assert!(events.is_empty(), "{events:?}");
        assert_eq!(fx.store(), before);
    }
}

#[tokio::test]
async fn an_upgrade_store_read_as_having_a_baseline_is_refused() {
    let fx = Fixture::new();
    let k = key(1);
    let i = inputs();
    let old = identity::build(
        &i.layer,
        None,
        None,
        &i.compiled,
        i.digest,
        1,
        ProvenanceKind::Seed,
    )
    .unwrap();
    fx.write(STORE_FILE, &seal_graph(&old, &k), 0o600);
    let before = fx.store();
    let i = with_baseline(inputs(), bl(A), Seen::Exactly(Some(bl(A).sha256)), &["x"]);
    let (r, _) = run_with(&fx.dir(), &k, None, &i).await;
    assert_eq!(
        r.unwrap_err(),
        StoreError::BaselineUnseen {
            stored: None,
            seen: Some(identity::hex(&bl(A).sha256)),
        }
    );
    assert_eq!(fx.store(), before);
}

#[test]
fn baseline_refusals_name_their_cause() {
    let e = StoreError::BaselineUnseen {
        stored: Some("aa".into()),
        seen: None,
    };
    assert_eq!(
        e.to_string(),
        "the store's accepted baseline (aa) is not the one this start read (none); nothing was applied"
    );
    assert_eq!(
        StoreError::BaselineUnrecorded.to_string(),
        "the baseline would change with no recorded cause; nothing was applied"
    );
    assert_eq!(remedy(&StoreError::BaselineUnrecorded), Remedy::Investigate);
}

#[tokio::test]
async fn a_vocabulary_migration_carries_the_stored_baseline_unchanged() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let mut i = inputs();
    i.compiled = wider();
    i.digest = vocabulary::digest(&i.compiled).unwrap();
    let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&first), &i).await;
    r.unwrap();
    assert!(events.iter().any(|e| matches!(e, Event::Migrate(..))));
    assert!(!events.iter().any(|e| matches!(e, Event::Baseline(..))));
    assert_eq!(stored_baseline(&fx, &k), Some(bl(A)));
}

#[tokio::test]
async fn a_migration_carries_the_stored_baseline_not_the_input() {
    let fx = Fixture::new();
    let k = key(1);
    let first = run(&fx.dir(), &k, None).await.0.unwrap();
    let mut i = with_baseline(
        inputs(),
        bl(B),
        Seen::Exactly(Some(bl(A).sha256)),
        &["core follows"],
    );
    i.compiled = wider();
    i.digest = vocabulary::digest(&i.compiled).unwrap();
    let mut audit = Recorder {
        fail_baseline: true,
        ..Recorder::default()
    };
    let sync_seen = peeked_sync(&fx, &k);
    let r = boot(
        &fx.dir(),
        &k,
        checkpoint_of(&first),
        &mut audit,
        NOW,
        &i.boot(Some(bl(A).sha256), sync_seen.as_ref()),
    )
    .await;
    assert_eq!(r.unwrap_err(), StoreError::Audit("baseline refused".into()));
    assert!(audit.events.iter().any(|e| matches!(e, Event::Migrate(..))));
    assert_eq!(revision_of(&fx.store(), &k), 2);
    assert_eq!(stored_baseline(&fx, &k), Some(bl(A)));
}

#[tokio::test]
async fn a_store_with_a_baseline_is_canonical() {
    let fx = Fixture::new();
    let k = key(1);
    let i = inputs();
    let g = identity::build(
        &i.layer,
        Some(&bl(B)),
        Some(&i.sync),
        &i.compiled,
        i.digest,
        3,
        ProvenanceKind::RootFile,
    )
    .unwrap();
    fx.write(STORE_FILE, &seal_graph(&g, &k), 0o600);
    let before = fx.store();
    let i = with_baseline(inputs(), bl(B), Seen::Peek, &[]);
    let (r, events) = run_with(&fx.dir(), &k, None, &i).await;
    let r = r.unwrap();
    assert_eq!((r.revision, r.identity_transition), (3, false));
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(fx.store(), before);
}

#[tokio::test]
async fn a_non_canonical_store_is_rebuilt_with_its_baseline() {
    let fx = Fixture::new();
    let k = key(1);
    let i = inputs();
    let g = identity::build(
        &i.layer,
        Some(&bl(B)),
        None,
        &i.compiled,
        i.digest,
        3,
        ProvenanceKind::RootFile,
    )
    .unwrap();
    let skewed = rebuild(
        &g,
        |n| {
            let mut n = n.clone();
            if n.kind == SUBJECT {
                n.provenance.kind = ProvenanceKind::Seed;
            }
            Some(n)
        },
        &i.compiled,
    );
    assert_ne!(skewed, g);
    fx.write(STORE_FILE, &seal_graph(&skewed, &k), 0o600);
    let i = with_baseline(inputs(), bl(B), Seen::Peek, &[]);
    let (r, events) = run_with(&fx.dir(), &k, None, &i).await;
    let r = r.unwrap();
    assert_eq!((r.revision, r.identity_transition), (4, true));
    assert!(!events.iter().any(|e| matches!(e, Event::Baseline(..))));
    assert_eq!(stored_baseline(&fx, &k), Some(bl(B)));
}

#[test]
fn peek_reads_the_accepted_baseline_and_writes_nothing() {
    let fx = Fixture::new();
    let k = key(1);
    assert_eq!(
        maknae_state::store::peek_baseline(&fx.dir(), &k).unwrap(),
        None
    );
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(run(&fx.dir(), &k, None))
        .0
        .unwrap();
    let before = (
        fx.store(),
        fs::metadata(fx.file(STORE_FILE)).unwrap().mtime(),
    );
    assert_eq!(
        maknae_state::store::peek_baseline(&fx.dir(), &k).unwrap(),
        Some(bl(A))
    );
    assert_eq!(
        (
            fx.store(),
            fs::metadata(fx.file(STORE_FILE)).unwrap().mtime()
        ),
        before
    );
    assert!(matches!(
        maknae_state::store::peek_baseline(&fx.dir(), &key(2)),
        Err(StoreError::Envelope(_))
    ));
}

#[test]
fn peek_refuses_a_store_file_it_may_not_read() {
    let fx = Fixture::new();
    fx.write(STORE_FILE, b"x", 0o644);
    assert!(matches!(
        maknae_state::store::peek_baseline(&fx.dir(), &key(1)),
        Err(StoreError::StoreFileRefused(_))
    ));
}

#[test]
fn a_root_marker_authorizes_and_a_daemon_marker_does_not() {
    let fx = Fixture::new();
    assert!(!fx.dir().reseed_authorized());
    fx.mark(0o644);
    assert!(fx.dir().reseed_authorized());
    assert!(!fx
        .dir_with_marker_owner(fx.uid.wrapping_add(1))
        .reseed_authorized());
}

#[tokio::test]
async fn an_operator_commit_records_the_operator_initiator() {
    let fx = Fixture::new();
    let k = key(1);
    let dir = fx.dir();
    run(&dir, &k, None).await.0.unwrap();
    let i = inputs();
    let next = identity::build(
        &i.layer,
        Some(&bl(A)),
        None,
        &i.compiled,
        i.digest,
        2,
        ProvenanceKind::Operator,
    )
    .unwrap();
    let mut audit = Recorder::default();
    let c = commit(&dir, &k, &next, &[], &[], &mut audit, INITIATOR_OPERATOR)
        .await
        .unwrap();
    assert_eq!(INITIATOR_OPERATOR, "operator");
    assert_eq!(audit.events[0], Event::Transition(2, "operator".into()));
    assert_eq!(c.revision, 2);
    assert_eq!(stored_baseline(&fx, &k), Some(bl(A)));
}

#[tokio::test]
async fn an_accept_changes_the_baseline_after_recording_why_and_nothing_else_does() {
    let fx = Fixture::new();
    let k = key(1);
    let dir = fx.dir();
    run(&dir, &k, None).await.0.unwrap();
    let before = fx.store();
    let i = inputs();
    let build = |b: Option<&BaselineLayer>| {
        identity::build(
            &i.layer,
            b,
            Some(&i.sync),
            &i.compiled,
            i.digest,
            2,
            ProvenanceKind::Operator,
        )
        .unwrap()
    };
    for (next, events) in [
        (build(Some(&bl(B))), vec![]),
        (build(None), vec!["why".to_string()]),
    ] {
        let mut audit = Recorder::default();
        let r = commit_accept(&dir, &k, &next, &events, &mut audit).await;
        assert_eq!(r.unwrap_err(), StoreError::BaselineUnrecorded);
        assert!(audit.events.is_empty(), "{:?}", audit.events);
        assert_eq!(fx.store(), before);
    }
    let mut audit = Recorder {
        fail_baseline: true,
        ..Recorder::default()
    };
    let r = commit_accept(&dir, &k, &build(Some(&bl(B))), &["why".into()], &mut audit).await;
    assert!(matches!(r, Err(StoreError::Audit(_))), "{r:?}");
    assert_eq!(fx.store(), before);
    let mut audit = Recorder::default();
    let c = commit_accept(&dir, &k, &build(Some(&bl(B))), &["why".into()], &mut audit)
        .await
        .unwrap();
    assert_eq!(
        audit.events[..2],
        [
            Event::Baseline(2, vec!["why".into()]),
            Event::Transition(2, INITIATOR_OPERATOR.into())
        ]
    );
    assert!(matches!(audit.events[2], Event::Checkpoint(2, ..)));
    assert_eq!(c.revision, 2);
    assert_eq!(stored_baseline(&fx, &k), Some(bl(B)));
}

#[tokio::test]
async fn a_commit_that_changes_or_drops_the_baseline_is_refused() {
    let fx = Fixture::new();
    let k = key(1);
    let dir = fx.dir();
    run(&dir, &k, None).await.0.unwrap();
    let before = fx.store();
    let i = edited();
    for baseline in [Some(bl(B)), None] {
        let next = identity::build(
            &i.layer,
            baseline.as_ref(),
            None,
            &i.compiled,
            i.digest,
            2,
            ProvenanceKind::RootFile,
        )
        .unwrap();
        let mut audit = Recorder::default();
        let r = commit(&dir, &k, &next, &[], &[], &mut audit, INITIATOR_ROOT_FILE).await;
        assert_eq!(r.unwrap_err(), StoreError::BaselineUnrecorded);
        assert!(audit.events.is_empty(), "{:?}", audit.events);
        assert_eq!(fx.store(), before);
        assert_eq!(dir.store_revision(), 1);
    }
}

#[tokio::test]
async fn a_store_without_a_sync_base_adopts_the_file_as_a_kernel_transition() {
    let (fx, k) = (Fixture::new(), key(1));
    fx.write(STORE_FILE, &sealed_unsynced(4, &k), 0o600);
    let i = inputs();
    let (r, events) = run_with(&fx.dir(), &k, None, &i).await;
    let r = r.unwrap();
    assert_eq!(r.revision, 5);
    assert_eq!(extracted(&r.graph).sync, Some(i.sync.clone()));
    assert_eq!(
        extracted(&graph_of(&fx.store(), &k)).sync,
        Some(i.sync.clone())
    );
    assert!(events.contains(&Event::Sync(5, i.sync_events.clone())));
    assert!(
        events.contains(&Event::Transition(5, "kernel".into())),
        "{events:?}"
    );
    assert!(!events
        .iter()
        .any(|e| matches!(e, Event::Transition(_, who) if who == "root-file")));
    assert!(subject_provenance(&r.graph)
        .iter()
        .all(|p| *p == ProvenanceKind::Kernel));
    assert!(!r.identity_transition && !r.baseline_transition);
}

#[tokio::test]
async fn an_adoption_is_kernel_and_a_root_edit_is_root_file() {
    let (fx, k) = (Fixture::new(), key(1));
    let (first, _) = run_with(&fx.dir(), &k, None, &inputs()).await;
    let cp = checkpoint_of(&first.unwrap());
    let mut adopted = inputs();
    adopted.sync = synced(r#"{"admin":["root"],"guest":[]}"#);
    adopted.sync_kind = maknae_config::SyncKind::Adopted;
    adopted.sync_events =
        vec!["adopted: bindings.yaml holds the live section (0 unsynced entries)".into()];
    let (r, events) = run_with(&fx.dir(), &k, cp, &adopted).await;
    assert!(
        events.contains(&Event::Transition(2, "kernel".into())),
        "{events:?}"
    );
    assert!(events.contains(&Event::Sync(2, adopted.sync_events.clone())));
    let cp = checkpoint_of(&r.unwrap());
    let mut root = edited();
    root.sync_kind = maknae_config::SyncKind::RootFile;
    root.sync = synced(r#"{"user":["root"]}"#);
    root.sync_events = vec![];
    let (r, events) = run_with(&fx.dir(), &k, cp, &root).await;
    assert!(
        events.contains(&Event::Transition(3, "root-file".into())),
        "{events:?}"
    );
    assert!(
        !events.iter().any(|e| matches!(e, Event::Sync(..))),
        "{events:?}"
    );
    assert!(subject_provenance(&r.unwrap().graph)
        .iter()
        .all(|p| *p == ProvenanceKind::RootFile));
}

#[tokio::test]
async fn an_unchanged_sync_base_and_layer_commit_nothing() {
    let (fx, k) = (Fixture::new(), key(1));
    let (first, _) = run_with(&fx.dir(), &k, None, &inputs()).await;
    let first = first.unwrap();
    let before = fx.store();
    let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&first), &inputs()).await;
    assert_eq!(r.unwrap().revision, first.revision);
    assert_eq!(
        events,
        vec![Event::Checkpoint(1, first.digest, "verified".into())]
    );
    assert_eq!(fx.store(), before);
}

#[tokio::test]
async fn an_identity_transition_records_no_sync_event_when_the_sync_base_is_unchanged() {
    let (fx, k) = (Fixture::new(), key(1));
    let (first, _) = run_with(&fx.dir(), &k, None, &inputs()).await;
    let first = first.unwrap();
    let i = edited();
    assert!(!i.sync_events.is_empty());
    let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&first), &i).await;
    let r = r.unwrap();
    assert_eq!(
        events,
        vec![
            Event::Checkpoint(1, first.digest, "verified".into()),
            Event::Transition(2, "root-file".into()),
            Event::Checkpoint(2, r.digest, "transitioned".into()),
        ]
    );
}

#[tokio::test]
async fn a_store_whose_sync_base_is_not_the_one_merged_against_refuses() {
    let (fx, k) = (Fixture::new(), key(1));
    let (first, _) = run_with(&fx.dir(), &k, None, &inputs()).await;
    let cp = checkpoint_of(&first.unwrap());
    let before = fx.store();
    for seen in [None, Some(synced(r#"{"user":["root"]}"#))] {
        let mut i = inputs();
        i.sync_seen = SyncSeen::Exactly(seen);
        let (r, events) = run_with(&fx.dir(), &k, cp, &i).await;
        assert_eq!(r.unwrap_err(), StoreError::SyncUnseen);
        assert!(events.is_empty(), "{events:?}");
        assert_eq!(fx.store(), before);
    }
    fx.write(STORE_FILE, &sealed_unsynced(4, &k), 0o600);
    let mut i = inputs();
    i.sync_seen = SyncSeen::Exactly(Some(i.sync.clone()));
    let (r, _) = run_with(&fx.dir(), &k, None, &i).await;
    assert_eq!(r.unwrap_err(), StoreError::SyncUnseen);
}

#[tokio::test]
async fn a_sync_record_that_cannot_be_appended_persists_nothing() {
    let (fx, k) = (Fixture::new(), key(1));
    let (first, _) = run_with(&fx.dir(), &k, None, &inputs()).await;
    let before = fx.store();
    let mut audit = Recorder {
        fail_sync: true,
        ..Recorder::default()
    };
    let mut i = edited();
    i.sync_kind = maknae_config::SyncKind::RootFile;
    i.sync_events = vec![
        "conflict: x changed in bindings.yaml and by an unsynced live transition; failed closed: contained"
            .into(),
    ];
    i.sync = SyncBase {
        base: r#"{"user":["root"]}"#.into(),
        live: r#"{"user":["root"]}"#.into(),
        conflicts: r#"["x"]"#.into(),
    };
    let dir = fx.dir();
    let ss = sync_seen(&dir, &k, &i);
    let r = boot(
        &dir,
        &k,
        checkpoint_of(&first.unwrap()),
        &mut audit,
        NOW,
        &i.boot(seen(&dir, &k, &i), ss.as_ref()),
    )
    .await;
    assert_eq!(r.unwrap_err(), StoreError::Audit("sync refused".into()));
    assert_eq!(fx.store(), before);
    assert!(
        !audit
            .events
            .iter()
            .any(|e| matches!(e, Event::Transition(..))),
        "{:?}",
        audit.events
    );
    assert!(audit
        .events
        .contains(&Event::Sync(2, i.sync_events.clone())));
}

#[tokio::test]
async fn without_a_sync_base_a_lost_file_still_refuses_and_with_one_it_is_the_kernels_to_decide() {
    let (fx, k) = (Fixture::new(), key(1));
    let explicit = bindings_layer(SOURCE, Some(BLOCK), MALLORY_AND_OP);
    let i = inputs_with(explicit.clone());
    let g = identity::build(
        &explicit,
        Some(&bl(A)),
        None,
        &i.compiled,
        i.digest,
        1,
        ProvenanceKind::Seed,
    )
    .unwrap();
    fx.write(STORE_FILE, &seal_graph(&g, &k), 0o600);
    let before = fx.store();
    let missing = Inputs {
        missing: true,
        ..inputs_with(bindings_layer(SOURCE, None, &[]))
    };
    let keyless = inputs_with(bindings_layer(SOURCE, None, &[]));
    for (lost, why) in [
        (&missing, BINDINGS_MISSING),
        (&keyless, BINDINGS_KEY_DROPPED),
    ] {
        let (r, events) = run_with(&fx.dir(), &k, None, lost).await;
        assert_eq!(r.unwrap_err(), StoreError::BindingsRefused(why));
        assert!(events.is_empty(), "{events:?}");
        assert_eq!(fx.store(), before);
    }
    assert_eq!(
        remedy(&StoreError::BindingsRefused(BINDINGS_KEY_DROPPED)),
        Remedy::Investigate
    );

    let (adopted, _) = run_with(&fx.dir(), &k, None, &i).await;
    let adopted = adopted.unwrap();
    assert_eq!(extracted(&adopted.graph).sync, Some(i.sync.clone()));
    let after = fx.store();
    let lost = Inputs {
        missing: true,
        sync_kind: maknae_config::SyncKind::Lost,
        sync_events: vec!["lost: bindings.yaml is missing".into()],
        ..inputs_with(explicit)
    };
    let (r, events) = run_with(&fx.dir(), &k, checkpoint_of(&adopted), &lost).await;
    let r = r.unwrap();
    assert_eq!(r.revision, adopted.revision);
    assert!(r.released.is_empty());
    assert_eq!(
        events,
        vec![Event::Checkpoint(
            adopted.revision,
            adopted.digest,
            "verified".into()
        )]
    );
    assert_eq!(fx.store(), after);
}

#[test]
fn the_initiator_is_kernel_only_for_a_pure_creation_or_adoption() {
    use maknae_config::SyncKind::*;
    for kind in [Created, Unchanged, Adopted, RootFile, Lost] {
        for (id, bl, st) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let want = if matches!(kind, Created | Adopted) && !id && !bl && !st {
                ProvenanceKind::Kernel
            } else {
                ProvenanceKind::RootFile
            };
            assert_eq!(
                transition_initiator(kind, id, bl, st),
                want,
                "{kind:?} {id} {bl} {st}"
            );
        }
    }
}

#[test]
fn each_provenance_names_its_initiator() {
    assert_eq!(INITIATOR_KERNEL, "kernel");
    for (p, want) in [
        (ProvenanceKind::Seed, INITIATOR_SEED),
        (ProvenanceKind::RootFile, INITIATOR_ROOT_FILE),
        (ProvenanceKind::Operator, INITIATOR_OPERATOR),
        (ProvenanceKind::Kernel, INITIATOR_KERNEL),
        (ProvenanceKind::Compiled, "compiled"),
    ] {
        assert_eq!(initiator_name(p), want, "{p:?}");
    }
    assert_eq!(
        LiveInitiator::Operator.provenance(),
        ProvenanceKind::Operator
    );
    assert_eq!(LiveInitiator::Kernel.provenance(), ProvenanceKind::Kernel);
}

fn live_next(
    g: &Graph,
    revision: u64,
    baseline: Option<&BaselineLayer>,
    sync: Option<&SyncBase>,
) -> Graph {
    let i = inputs();
    identity::build(
        &extracted(g).layer,
        baseline,
        sync,
        &i.compiled,
        i.digest,
        revision,
        ProvenanceKind::Operator,
    )
    .unwrap()
}

const LIVE: &str = r#"{"admin":["root"],"adversary":[{"uid":7}]}"#;

#[tokio::test]
async fn a_live_commit_keeps_the_base_the_conflicts_and_the_baseline() {
    let (fx, k) = (Fixture::new(), key(1));
    let dir = fx.dir();
    let booted = run(&dir, &k, None).await.0.unwrap();
    let stored = extracted(&booted.graph).sync.unwrap();
    let live = SyncBase {
        live: LIVE.into(),
        ..stored.clone()
    };
    let events = vec!["live: uid:7 contained".to_string()];
    let before = fx.store();
    let g = &booted.graph;
    let refusals = [
        (
            live_next(
                g,
                2,
                Some(&bl(A)),
                Some(&SyncBase {
                    base: r#"{"user":["root"]}"#.into(),
                    ..live.clone()
                }),
            ),
            events.clone(),
            StoreError::SyncBaseChanged,
        ),
        (
            live_next(
                g,
                2,
                Some(&bl(A)),
                Some(&SyncBase {
                    conflicts: r#"["root"]"#.into(),
                    ..live.clone()
                }),
            ),
            events.clone(),
            StoreError::SyncBaseChanged,
        ),
        (
            live_next(g, 2, Some(&bl(A)), None),
            events.clone(),
            StoreError::SyncAbsent,
        ),
        (
            live_next(g, 2, Some(&bl(B)), Some(&live)),
            events.clone(),
            StoreError::BaselineUnrecorded,
        ),
        (
            live_next(g, 2, Some(&bl(A)), Some(&live)),
            vec![],
            StoreError::SyncUnrecorded,
        ),
    ];
    for (next, ev, want) in refusals {
        let mut audit = Recorder::default();
        let r = commit_live(
            &dir,
            &k,
            &next,
            &[],
            &ev,
            &mut audit,
            LiveInitiator::Operator,
        )
        .await;
        assert_eq!(r.unwrap_err(), want);
        assert!(audit.events.is_empty(), "{:?}", audit.events);
        assert_eq!(fx.store(), before);
        assert_eq!(dir.store_revision(), 1);
    }

    let mut audit = Recorder::default();
    let next = live_next(g, 2, Some(&bl(A)), Some(&live));
    let c = commit_live(
        &dir,
        &k,
        &next,
        &[],
        &events,
        &mut audit,
        LiveInitiator::Operator,
    )
    .await
    .unwrap();
    assert_eq!(
        audit.events,
        vec![
            Event::Sync(2, events.clone()),
            Event::Transition(2, "operator".into()),
            Event::Checkpoint(2, c.digest, "transitioned".into()),
        ]
    );
    assert_eq!(c.revision, 2);
    assert_eq!(
        extracted(&graph_of(&fx.store(), &k)).sync,
        Some(live.clone())
    );

    let released = vec![Released {
        uid: 7,
        name: "uid:7".into(),
        cause: ReleaseCause::NotListed,
    }];
    let mut audit = Recorder::default();
    let next = live_next(g, 3, Some(&bl(A)), Some(&stored));
    let c = commit_live(
        &dir,
        &k,
        &next,
        &released,
        &events,
        &mut audit,
        LiveInitiator::Kernel,
    )
    .await
    .unwrap();
    assert_eq!(
        audit.events,
        vec![
            Event::Released(3, released),
            Event::Sync(3, events.clone()),
            Event::Transition(3, "kernel".into()),
            Event::Checkpoint(3, c.digest, "transitioned".into()),
        ]
    );
    assert_eq!(extracted(&graph_of(&fx.store(), &k)).sync, Some(stored));
}

#[tokio::test]
async fn a_live_commit_over_a_store_without_a_sync_base_is_refused() {
    let (fx, k) = (Fixture::new(), key(1));
    fx.write(STORE_FILE, &sealed_unsynced(4, &k), 0o600);
    let before = fx.store();
    let dir = fx.dir();
    let g = graph_of(&before, &k);
    let mut audit = Recorder::default();
    let r = commit_live(
        &dir,
        &k,
        &live_next(&g, 5, Some(&bl(A)), Some(&synced(LIVE))),
        &[],
        &["live".into()],
        &mut audit,
        LiveInitiator::Operator,
    )
    .await;
    assert_eq!(r.unwrap_err(), StoreError::SyncAbsent);
    assert!(audit.events.is_empty());
    assert_eq!(fx.store(), before);
}

#[tokio::test]
async fn an_accept_carries_the_sync_base_unchanged() {
    let (fx, k) = (Fixture::new(), key(1));
    let dir = fx.dir();
    let booted = run(&dir, &k, None).await.0.unwrap();
    let stored = extracted(&booted.graph).sync.unwrap();
    let before = fx.store();
    let changed = SyncBase {
        live: LIVE.into(),
        ..stored.clone()
    };
    for sync in [Some(&changed), None] {
        let mut audit = Recorder::default();
        let next = live_next(&booted.graph, 2, Some(&bl(B)), sync);
        let r = commit_accept(&dir, &k, &next, &["why".into()], &mut audit).await;
        assert_eq!(r.unwrap_err(), StoreError::SyncBaseChanged);
        assert!(audit.events.is_empty(), "{:?}", audit.events);
        assert_eq!(fx.store(), before);
    }
    let mut audit = Recorder::default();
    let next = live_next(&booted.graph, 2, Some(&bl(B)), Some(&stored));
    commit_accept(&dir, &k, &next, &["why".into()], &mut audit)
        .await
        .unwrap();
    assert!(!audit.events.iter().any(|e| matches!(e, Event::Sync(..))));
    assert_eq!(extracted(&graph_of(&fx.store(), &k)).sync, Some(stored));
}

#[test]
fn peek_sync_reads_the_stored_sync_base_and_writes_nothing() {
    let fx = Fixture::new();
    let k = key(1);
    assert_eq!(maknae_state::store::peek_sync(&fx.dir(), &k).unwrap(), None);
    fx.write(STORE_FILE, &sealed_unsynced(4, &k), 0o600);
    assert_eq!(maknae_state::store::peek_sync(&fx.dir(), &k).unwrap(), None);
    fs::remove_file(fx.file(STORE_FILE)).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(run(&fx.dir(), &k, None))
        .0
        .unwrap();
    let before = fx.store();
    assert_eq!(peeked_sync(&fx, &k), Some(inputs().sync));
    assert_eq!(fx.store(), before);
    assert!(matches!(
        maknae_state::store::peek_sync(&fx.dir(), &key(2)),
        Err(StoreError::Envelope(_))
    ));
    fx.write(STORE_FILE, b"x", 0o644);
    assert!(matches!(
        maknae_state::store::peek_sync(&fx.dir(), &k),
        Err(StoreError::StoreFileRefused(_))
    ));
}

#[test]
fn sync_refusals_name_their_cause_and_remedy() {
    for (e, text) in [
        (
            StoreError::SyncUnseen,
            "the store's sync base is not the one this start merged against; nothing was applied",
        ),
        (
            StoreError::SyncBaseChanged,
            "a live identity edit would change the sync base; nothing was applied",
        ),
        (
            StoreError::SyncAbsent,
            "the store holds no sync base; nothing was applied",
        ),
        (
            StoreError::SyncUnrecorded,
            "a live identity edit was not recorded; nothing was applied",
        ),
    ] {
        assert_eq!(e.to_string(), text);
        assert_eq!(remedy(&e), Remedy::Investigate, "{e:?}");
    }
}

#[test]
fn the_mirror_is_published_daemon_owned_0600() {
    let fx = Fixture::new();
    assert_eq!(MIRROR_FILE, "bindings.mirror.yaml");
    fx.dir().publish_mirror(b"m").unwrap();
    let md = std::fs::symlink_metadata(fx.file(MIRROR_FILE)).unwrap();
    assert_eq!(
        (md.uid(), md.permissions().mode() & 0o7777),
        (fx.uid, 0o600)
    );
    assert_eq!(fs::read(fx.file(MIRROR_FILE)).unwrap(), b"m");
    fx.dir().remove_mirror().unwrap();
    assert!(!fx.exists(MIRROR_FILE));
    fx.dir().remove_mirror().unwrap();
    let d = fx.dir();
    d.publish_mirror(b"old").unwrap();
    d.fail_next_mirror_publish();
    assert!(d.publish_mirror(b"n").is_err());
    assert_eq!(
        fs::read(fx.file(MIRROR_FILE)).unwrap(),
        b"old",
        "the seam fails before the rename; removal is the kernel's job"
    );
    assert!(!fs::read_dir(fx.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains(".tmp.")));
    d.publish_mirror(b"n").unwrap();
    assert_eq!(fs::read(fx.file(MIRROR_FILE)).unwrap(), b"n");
}

#[test]
fn removing_the_mirror_reports_a_failure_other_than_absence() {
    let fx = Fixture::new();
    fs::create_dir(fx.file(MIRROR_FILE)).unwrap();
    fs::write(fx.file(MIRROR_FILE).join("x"), b"").unwrap();
    assert!(fx.dir().remove_mirror().is_err());
}

#[tokio::test]
async fn a_commit_whose_sync_record_cannot_be_appended_persists_nothing() {
    let (fx, k) = (Fixture::new(), key(1));
    let dir = fx.dir();
    let booted = run(&dir, &k, None).await.0.unwrap();
    let before = fx.store();
    let mut audit = Recorder {
        fail_sync: true,
        ..Recorder::default()
    };
    let live = SyncBase {
        live: LIVE.into(),
        ..extracted(&booted.graph).sync.unwrap()
    };
    let r = commit_live(
        &dir,
        &k,
        &live_next(&booted.graph, 2, Some(&bl(A)), Some(&live)),
        &[],
        &["live".into()],
        &mut audit,
        LiveInitiator::Operator,
    )
    .await;
    assert_eq!(r.unwrap_err(), StoreError::Audit("sync refused".into()));
    assert_eq!(audit.events, vec![Event::Sync(2, vec!["live".into()])]);
    assert_eq!(fx.store(), before);
    assert_eq!(dir.store_revision(), 1);
}

#[tokio::test]
async fn a_commit_over_no_store_is_refused_as_an_unrecorded_baseline() {
    let (fx, k) = (Fixture::new(), key(1));
    let mut audit = Recorder::default();
    let r = commit(
        &fx.dir(),
        &k,
        &next_graph(1, &inputs()),
        &[],
        &[],
        &mut audit,
        INITIATOR_ROOT_FILE,
    )
    .await;
    assert_eq!(r.unwrap_err(), StoreError::BaselineUnrecorded);
    assert!(audit.events.is_empty());
    assert!(!fx.exists(STORE_FILE));
}

#[tokio::test]
async fn a_commit_whose_sync_base_contradicts_its_bindings_is_refused() {
    let (fx, k) = (Fixture::new(), key(1));
    let dir = fx.dir();
    let booted = run(&dir, &k, None).await.0.unwrap();
    let before = fx.store();
    let mut audit = Recorder::default();
    let r = commit(
        &dir,
        &k,
        &live_next(&booted.graph, 2, Some(&bl(A)), Some(&synced("null"))),
        &[],
        &[],
        &mut audit,
        INITIATOR_ROOT_FILE,
    )
    .await;
    assert!(matches!(r, Err(StoreError::Identity(_))), "{r:?}");
    assert!(audit.events.is_empty());
    assert_eq!(fx.store(), before);
}
