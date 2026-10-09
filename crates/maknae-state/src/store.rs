use crate::anchor::{assess, AnchorState, BootAction, Checkpoint, Refusal, StoreFacts};
use crate::envelope::{
    ciphertext_digest, open, seal, EnvelopeError, WrappingKey, AEAD_AES_256_GCM, ENVELOPE_VERSION,
    WRAP_AES_256_GCM,
};
use crate::vocabulary::{self, Assessment};
use maknae_graph::baseline::BaselineLayer;
use maknae_graph::format::{self, FormatError, FORMAT_VERSION};
use maknae_graph::graph::Graph;
use maknae_graph::identity::{self, Extracted, IdentityLayer};
use maknae_graph::kernel::{ADVERSARY, CONFIG_SOURCE, ROLE, SCHEMA};
use maknae_graph::record::{GraphSpace, ProvenanceKind};
use maknae_graph::schema::CompiledSet;
use maknae_graph::sync::SyncBase;
use maknae_io::{
    open_anchor, Anchor, AnchorLock, AnchorRequired, IoError, IoKind, Mode, StrategyPref,
    TargetRequired, Zeroizing,
};
use std::fmt;
use std::future::Future;
use std::path::Path;
#[cfg(feature = "hermetic-test-seam")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

pub use maknae_config::state::{MARKER_FILE, MARKER_MAX_BYTES, MIRROR_FILE, STATE_DIR, STORE_FILE};

pub const REJECTED_PREFIX: &str = "kernel.graph.rejected.";
pub const MAX_STORE_BYTES: u64 = 64 << 20;
pub const ANCHOR_SEEDING: &str = "seeding";
pub const ANCHOR_SEEDED: &str = "seeded";
pub const ANCHOR_RESEEDED: &str = "reseeded";
pub const ANCHOR_MIGRATED: &str = "migrated";
pub const ANCHOR_TRANSITIONED: &str = "transitioned";
pub const INITIATOR_ROOT_FILE: &str = "root-file";
pub const INITIATOR_SEED: &str = "seed";
pub const INITIATOR_OPERATOR: &str = "operator";
pub const INITIATOR_KERNEL: &str = "kernel";

const STORE_MODE: Mode = Mode(0o600);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    StateDir(String),
    InUse,
    StoreFileRefused(String),
    Io(String),
    Envelope(EnvelopeError),
    Format(String),
    Refused(Refusal),
    Audit(String),
    NewerStore(String),
    RejectedNameInUse {
        name: String,
        cause: String,
    },
    Vocabulary(&'static str),
    Identity(String),
    StaleRevision {
        store: u64,
        attempted: u64,
    },
    BindingsRefused(&'static str),
    BaselineUnseen {
        stored: Option<String>,
        seen: Option<String>,
    },
    BaselineUnrecorded,
    SyncUnseen,
    SyncBaseChanged,
    SyncAbsent,
    SyncUnrecorded,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateDir(cause) => write!(f, "graph state directory refused: {cause}"),
            Self::InUse => write!(f, "another maknaed holds the kernel graph state directory"),
            Self::StoreFileRefused(cause) => {
                write!(f, "graph store file {STORE_FILE} refused: {cause}")
            }
            Self::Io(cause) => write!(f, "graph store I/O failed: {cause}"),
            Self::Envelope(e) => write!(f, "{e}"),
            Self::Format(cause) => write!(f, "graph store does not decode: {cause}"),
            Self::Refused(r) => write!(f, "{r}"),
            Self::Audit(cause) => write!(f, "graph store audit failed: {cause}"),
            Self::NewerStore(detail) => write!(
                f,
                "the graph store was written by a newer maknaed: {detail}"
            ),
            Self::RejectedNameInUse { name, cause } => write!(
                f,
                "the rejected-copy name {name} is in use and does not hold this store ({cause}); move it aside, then restart"
            ),
            Self::Vocabulary(cause) => write!(f, "graph store vocabulary refused: {cause}"),
            Self::Identity(cause) => {
                write!(f, "the kernel identity layer does not build: {cause}")
            }
            Self::StaleRevision { store, attempted } => write!(
                f,
                "graph store commit at revision {attempted} does not advance the store's revision {store}"
            ),
            Self::BindingsRefused(m) => f.write_str(m),
            Self::BaselineUnseen { stored, seen } => write!(
                f,
                "the store's accepted baseline ({}) is not the one this start read ({}); nothing was applied",
                stored.as_deref().unwrap_or("none"),
                seen.as_deref().unwrap_or("none")
            ),
            Self::BaselineUnrecorded => f.write_str(
                "the baseline would change with no recorded cause; nothing was applied",
            ),
            Self::SyncUnseen => f.write_str(
                "the store's sync base is not the one this start merged against; nothing was applied",
            ),
            Self::SyncBaseChanged => f.write_str(
                "a live identity edit would change the sync base; nothing was applied",
            ),
            Self::SyncAbsent => f.write_str("the store holds no sync base; nothing was applied"),
            Self::SyncUnrecorded => {
                f.write_str("a live identity edit was not recorded; nothing was applied")
            }
        }
    }
}

impl std::error::Error for StoreError {}

impl From<EnvelopeError> for StoreError {
    fn from(e: EnvelopeError) -> Self {
        Self::Envelope(e)
    }
}

/// The operator's next step for a boot failure. A store written by a newer `maknaed`,
/// or one that could not be read, is never `Reseed`: reseeding replaces a valid store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remedy {
    Reinstall,
    Reseed,
    CheckStateDir,
    StopOtherInstance,
    CheckStoreFile,
    ClearRejectedName,
    CheckAudit,
    Investigate,
}

pub fn remedy(e: &StoreError) -> Remedy {
    match e {
        StoreError::NewerStore(_) => Remedy::Reinstall,
        StoreError::Refused(Refusal::RevisionExhausted) => Remedy::Investigate,
        StoreError::Refused(_)
        | StoreError::Envelope(_)
        | StoreError::Format(_)
        | StoreError::Vocabulary(_) => Remedy::Reseed,
        StoreError::StoreFileRefused(_) => Remedy::CheckStoreFile,
        StoreError::RejectedNameInUse { .. } => Remedy::ClearRejectedName,
        StoreError::StateDir(_) | StoreError::Io(_) => Remedy::CheckStateDir,
        StoreError::InUse => Remedy::StopOtherInstance,
        StoreError::Audit(_) => Remedy::CheckAudit,
        StoreError::Identity(_)
        | StoreError::StaleRevision { .. }
        | StoreError::BindingsRefused(_)
        | StoreError::BaselineUnseen { .. }
        | StoreError::BaselineUnrecorded
        | StoreError::SyncUnseen
        | StoreError::SyncBaseChanged
        | StoreError::SyncAbsent
        | StoreError::SyncUnrecorded => Remedy::Investigate,
    }
}

impl From<IoError> for StoreError {
    fn from(e: IoError) -> Self {
        Self::Io(e.to_string())
    }
}

#[derive(Debug)]
pub struct StateDir {
    anchor: Anchor,
    _lock: AnchorLock,
    owner: u32,
    marker_owner: u32,
    store_revision: Mutex<u64>,
    #[cfg(feature = "hermetic-test-seam")]
    fail_next_sync: AtomicBool,
    #[cfg(feature = "hermetic-test-seam")]
    fail_next_mirror: AtomicBool,
}

struct Persisted {
    digest: [u8; 32],
    durability_error: Option<String>,
}

impl StateDir {
    pub fn open(path: &Path, owner: u32) -> Result<StateDir, StoreError> {
        Self::open_as(path, owner, 0)
    }

    /// Test seam: lets an unprivileged test play the marker's owner; production passes uid 0.
    #[cfg(feature = "hermetic-test-seam")]
    #[doc(hidden)]
    pub fn open_with_marker_owner(
        path: &Path,
        owner: u32,
        marker_owner: u32,
    ) -> Result<StateDir, StoreError> {
        Self::open_as(path, owner, marker_owner)
    }

    /// Test seam: the next publish lands, then reports a failed directory sync.
    #[cfg(feature = "hermetic-test-seam")]
    #[doc(hidden)]
    pub fn fail_next_directory_sync(&self) {
        self.fail_next_sync.store(true, Ordering::SeqCst);
    }

    /// Test seam: the next mirror publish fails before anything is written.
    #[cfg(feature = "hermetic-test-seam")]
    #[doc(hidden)]
    pub fn fail_next_mirror_publish(&self) {
        self.fail_next_mirror.store(true, Ordering::SeqCst);
    }

    pub fn publish_mirror(&self, bytes: &[u8]) -> Result<(), IoError> {
        #[cfg(feature = "hermetic-test-seam")]
        if self.fail_next_mirror.swap(false, Ordering::SeqCst) {
            return Err(IoError::Io {
                path: Path::new(MIRROR_FILE).to_path_buf(),
                kind: IoKind::Other { raw: 5 },
            });
        }
        self.anchor
            .publish(Path::new(MIRROR_FILE), None, bytes, STORE_MODE)
            .map(|_| ())
    }

    /// Not found is success.
    pub fn remove_mirror(&self) -> Result<(), IoError> {
        self.anchor.remove(Path::new(MIRROR_FILE), None).map(|_| ())
    }

    fn open_as(path: &Path, owner: u32, marker_owner: u32) -> Result<StateDir, StoreError> {
        let anchor = open_anchor(
            path,
            AnchorRequired {
                owner: Some(owner),
                mode_mask: Some(0o077),
            },
            StrategyPref::Auto,
        )
        .map_err(|e| StoreError::StateDir(e.to_string()))?;
        let lock = anchor.try_lock_exclusive().map_err(|e| match e {
            IoError::Locked { .. } => StoreError::InUse,
            e => StoreError::StateDir(e.to_string()),
        })?;
        Ok(StateDir {
            anchor,
            _lock: lock,
            owner,
            marker_owner,
            store_revision: Mutex::new(0),
            #[cfg(feature = "hermetic-test-seam")]
            fail_next_sync: AtomicBool::new(false),
            #[cfg(feature = "hermetic-test-seam")]
            fail_next_mirror: AtomicBool::new(false),
        })
    }

    pub fn owner(&self) -> u32 {
        self.owner
    }

    /// The revision of the store as this process last read or wrote it; a commit must exceed it.
    pub fn store_revision(&self) -> u64 {
        *self.floor()
    }

    fn floor(&self) -> MutexGuard<'_, u64> {
        self.store_revision
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn set_store_revision(&self, revision: u64) {
        *self.floor() = revision;
    }

    /// A publish that renamed but did not sync is committed: the store holds the new
    /// revision, so the floor advances and the failure is returned with the digest.
    fn persist(&self, key: &WrappingKey, graph: &Graph) -> Result<Persisted, StoreError> {
        let mut floor = self.floor();
        let attempted = graph.revision();
        if attempted <= *floor {
            return Err(StoreError::StaleRevision {
                store: *floor,
                attempted,
            });
        }
        let file = seal(&format::encode(graph), key)?;
        let durability_error = match self.publish(STORE_FILE, &file) {
            Ok(()) => None,
            Err(e @ IoError::PublishedNotDurable { .. }) => Some(e.to_string()),
            Err(e) => return Err(e.into()),
        };
        *floor = attempted;
        Ok(Persisted {
            digest: ciphertext_digest(&file),
            durability_error,
        })
    }

    /// Whether root's reseed marker authorizes a seed at this start (the same check `boot` makes).
    pub fn reseed_authorized(&self) -> bool {
        matches!(self.reseed_marker(), Ok(true))
    }

    fn reseed_marker(&self) -> Result<bool, IoError> {
        let marker = TargetRequired {
            owner: Some(self.marker_owner),
            mode_mask: Some(0o022),
            nlink_exactly_one: true,
            regular_file: true,
            max_bytes: Some(MARKER_MAX_BYTES),
        };
        match self.anchor.read(Path::new(MARKER_FILE), None, marker) {
            Ok(_) => Ok(true),
            Err(IoError::Io {
                kind: IoKind::NotFound,
                ..
            }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn preserve(&self, name: &str, bytes: &[u8]) -> Result<String, StoreError> {
        let copy = TargetRequired {
            owner: Some(self.owner),
            mode_mask: Some(0o077),
            nlink_exactly_one: true,
            regular_file: true,
            max_bytes: Some(MAX_STORE_BYTES),
        };
        let cause = match self.anchor.read(Path::new(name), None, copy) {
            Err(IoError::Io {
                kind: IoKind::NotFound,
                ..
            }) => {
                self.publish(name, bytes)?;
                return Ok(name.to_string());
            }
            Ok(existing) if existing.value[..] == bytes[..] => {
                return Ok(format!("{name} (already preserved)"));
            }
            Ok(_) => "it holds other bytes".to_string(),
            Err(e) => e.to_string(),
        };
        Err(StoreError::RejectedNameInUse {
            name: name.to_string(),
            cause,
        })
    }

    fn read_store(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IoError> {
        let store = TargetRequired {
            owner: Some(self.owner),
            mode_mask: Some(0o077),
            nlink_exactly_one: true,
            regular_file: true,
            max_bytes: Some(MAX_STORE_BYTES),
        };
        match self.anchor.read(Path::new(STORE_FILE), None, store) {
            Ok(outcome) => Ok(Some(outcome.value)),
            Err(IoError::Io {
                kind: IoKind::NotFound,
                ..
            }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn publish(&self, name: &str, bytes: &[u8]) -> Result<(), IoError> {
        self.anchor
            .publish(Path::new(name), None, bytes, STORE_MODE)?;
        #[cfg(feature = "hermetic-test-seam")]
        if self.fail_next_sync.swap(false, Ordering::SeqCst) {
            return Err(IoError::PublishedNotDurable {
                path: Path::new(name).to_path_buf(),
                kind: IoKind::Other { raw: 5 },
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootOutcome {
    Seeded {
        authorized: bool,
        rejected: Option<String>,
    },
    Loaded(AnchorState),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    pub from: Option<[u8; 32]>,
    pub to: [u8; 32],
    pub unbound: Vec<u32>,
}

#[derive(Debug)]
pub struct BootReport {
    pub revision: u64,
    pub digest: [u8; 32],
    pub outcome: BootOutcome,
    pub graph: Graph,
    pub marker_ignored: Option<String>,
    pub migration: Option<Migration>,
    pub identity_transition: bool,
    pub baseline_transition: bool,
    pub released: Vec<identity::Released>,
    /// The last store write's failed directory sync: it is in place, perhaps not durable.
    pub durability_error: Option<String>,
}

/// What the binary brings to boot: its persisted compiled set, that set's
/// `vocabulary::digest`, the identity layer resolved from `bindings.yaml`, the
/// `adversary:` names that did not resolve, whether the file is missing, whether its
/// `bindings:` key lists nobody, and the enrolled principal's uid.
pub struct BootInputs<'a> {
    pub compiled: &'a CompiledSet,
    pub vocabulary_sha256: [u8; 32],
    pub identity: &'a IdentityLayer,
    pub unresolved_adversaries: &'a [String],
    pub bindings_missing: bool,
    pub bindings_lists_nobody: bool,
    pub principal_uid: u32,
    /// The baseline this boot runs and persists.
    pub baseline: &'a BaselineLayer,
    /// The digest of the accepted baseline the caller read before deciding, `None` when it read none.
    pub accepted_seen: Option<[u8; 32]>,
    /// Written ahead of a persist that changes the baseline, one record each.
    pub baseline_events: &'a [String],
    /// The merged identity sync state this boot persists.
    pub sync: &'a SyncBase,
    /// The `SyncBase` the caller merged against; `None` when it read none.
    pub sync_seen: Option<&'a SyncBase>,
    /// Written ahead of a persist that changes the sync base, one record each.
    pub sync_events: &'a [String],
    pub sync_kind: maknae_config::SyncKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committed {
    pub revision: u64,
    pub digest: [u8; 32],
    pub durability_error: Option<String>,
    pub checkpoint_error: Option<String>,
}

pub trait BootAudit {
    fn intent_seed(
        &mut self,
        revision: u64,
        authorized: bool,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn checkpoint(
        &mut self,
        revision: u64,
        digest: [u8; 32],
        anchor: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn intent_migrate(
        &mut self,
        revision: u64,
        from: Option<[u8; 32]>,
        to: [u8; 32],
        unbound: &[u32],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn intent_transition(
        &mut self,
        revision: u64,
        initiator: &'static str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// Written ahead of the persist of a transition that ends these containments; an append
    /// failure refuses boot (as `intent_transition`'s does) and nothing is persisted.
    fn released(
        &mut self,
        revision: u64,
        released: &[identity::Released],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// Written ahead of a persist that changes the baseline; an append failure refuses
    /// as `released`'s does.
    fn baseline(
        &mut self,
        revision: u64,
        events: &[String],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// Written ahead of a transition that changes the sync base; an append failure
    /// refuses as `baseline`'s does.
    fn sync(
        &mut self,
        revision: u64,
        events: &[String],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Who a boot transition is attributed to: the kernel when it only creates or adopts
/// the sync base, root's file otherwise.
pub fn transition_initiator(
    kind: maknae_config::SyncKind,
    identity_changed: bool,
    baseline_changed: bool,
    stale: bool,
) -> ProvenanceKind {
    use maknae_config::SyncKind::{Adopted, Created};
    let pure = !(identity_changed || baseline_changed || stale);
    if pure && matches!(kind, Created | Adopted) {
        ProvenanceKind::Kernel
    } else {
        ProvenanceKind::RootFile
    }
}

pub fn initiator_name(p: ProvenanceKind) -> &'static str {
    match p {
        ProvenanceKind::Compiled => "compiled",
        ProvenanceKind::Seed => INITIATOR_SEED,
        ProvenanceKind::RootFile => INITIATOR_ROOT_FILE,
        ProvenanceKind::Operator => INITIATOR_OPERATOR,
        ProvenanceKind::Kernel => INITIATOR_KERNEL,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveInitiator {
    Operator,
    Kernel,
}

impl LiveInitiator {
    pub fn provenance(self) -> ProvenanceKind {
        match self {
            Self::Operator => ProvenanceKind::Operator,
            Self::Kernel => ProvenanceKind::Kernel,
        }
    }
}

fn newer_envelope(v: u16) -> bool {
    v > ENVELOPE_VERSION
}

fn newer_format(v: u16) -> bool {
    v > FORMAT_VERSION
}

fn newer_schema(found: u16, expected: u16) -> bool {
    found > expected
}

fn newer_aead(id: u16) -> bool {
    id > AEAD_AES_256_GCM
}

fn newer_wrap(id: u16) -> bool {
    id > WRAP_AES_256_GCM
}

fn classify_envelope(e: EnvelopeError) -> StoreError {
    match e {
        EnvelopeError::UnsupportedVersion(v) if newer_envelope(v) => {
            StoreError::NewerStore(e.to_string())
        }
        EnvelopeError::UnknownAead(a) if newer_aead(a) => StoreError::NewerStore(e.to_string()),
        EnvelopeError::UnknownWrap(w) if newer_wrap(w) => StoreError::NewerStore(e.to_string()),
        e => StoreError::Envelope(e),
    }
}

fn classify_format(e: FormatError) -> StoreError {
    match e {
        FormatError::UnsupportedFormatVersion(v) if newer_format(v) => {
            StoreError::NewerStore(e.to_string())
        }
        FormatError::UnsupportedSchemaVersion { found, expected }
            if newer_schema(found, expected) =>
        {
            StoreError::NewerStore(e.to_string())
        }
        e => StoreError::Format(e.to_string()),
    }
}

struct Decoded {
    graph: Graph,
    stored: CompiledSet,
    extracted: Extracted,
    facts: StoreFacts,
}

fn decode_store(file: &[u8], key: &WrappingKey) -> Result<Decoded, StoreError> {
    let plain = open(file, key).map_err(classify_envelope)?;
    let (graph, stored) = format::decode_stored_compiled(&plain, GraphSpace::Kernel, &SCHEMA)
        .map_err(classify_format)?;
    let extracted = identity::extract(&graph).map_err(|e| StoreError::Format(e.to_string()))?;
    let facts = StoreFacts {
        revision: graph.revision(),
        digest: ciphertext_digest(file),
    };
    Ok(Decoded {
        graph,
        stored,
        extracted,
        facts,
    })
}

fn build(
    layer: &IdentityLayer,
    baseline: Option<&BaselineLayer>,
    sync: Option<&SyncBase>,
    inputs: &BootInputs<'_>,
    revision: u64,
    initiator: ProvenanceKind,
) -> Result<Graph, StoreError> {
    identity::build(
        layer,
        baseline,
        sync,
        inputs.compiled,
        inputs.vocabulary_sha256,
        revision,
        initiator,
    )
    .map_err(|e| StoreError::Identity(e.to_string()))
}

fn next_revision(revision: u64) -> Result<u64, StoreError> {
    revision
        .checked_add(1)
        .ok_or(StoreError::Refused(Refusal::RevisionExhausted))
}

fn sorted(layer: &IdentityLayer) -> IdentityLayer {
    let mut l = layer.clone();
    l.subjects.sort_by_key(|s| s.uid);
    l
}

fn drop_vanished(layer: &mut IdentityLayer, compiled: &CompiledSet) -> Vec<u32> {
    let (keep, drop): (Vec<_>, Vec<_>) = layer
        .subjects
        .drain(..)
        .partition(|s| compiled.get(ROLE, &s.role).is_some());
    layer.subjects = keep;
    let subjects = &layer.subjects;
    layer
        .aliases
        .retain(|_, u| subjects.iter().any(|s| s.uid == *u && s.role == ADVERSARY));
    drop.into_iter().map(|s| s.uid).collect()
}

/// The stored layer carried across a vocabulary change: the label is the binary's, and a
/// store with no policy source (written before the identity layer) takes the file's source alone.
fn migrated_layer(
    stored: &IdentityLayer,
    file: &IdentityLayer,
    compiled: &CompiledSet,
) -> (IdentityLayer, Vec<u32>) {
    let mut layer = if stored.source.is_empty() {
        IdentityLayer {
            source: file.source.clone(),
            ..IdentityLayer::default()
        }
    } else {
        stored.clone()
    };
    layer.label = file.label.clone();
    let unbound = drop_vanished(&mut layer, compiled);
    (layer, unbound)
}

pub async fn boot(
    dir: &StateDir,
    key: &WrappingKey,
    checkpoint: Option<Checkpoint>,
    audit: &mut impl BootAudit,
    now_unix: u64,
    inputs: &BootInputs<'_>,
) -> Result<BootReport, StoreError> {
    let (authorized, marker_ignored) = match dir.reseed_marker() {
        Ok(authorized) => (authorized, None),
        Err(e) => (false, Some(e.to_string())),
    };
    let mut loaded = None;
    let prior = match dir.read_store() {
        Ok(None) => Prior::Absent,
        Ok(Some(file)) => {
            match decode_store(&file, key) {
                Ok(decoded) => loaded = Some(decoded),
                Err(e) if !authorized => return Err(e),
                Err(_) => {}
            }
            Prior::Readable(file, now_unix)
        }
        Err(e) => return Err(StoreError::StoreFileRefused(e.to_string())),
    };

    let mut report = match (
        assess(loaded.as_ref().map(|d| d.facts), checkpoint, authorized),
        loaded,
    ) {
        (BootAction::Refuse(r), _) => Err(StoreError::Refused(r)),
        (BootAction::Load(state), Some(decoded)) => {
            load(dir, key, audit, state, decoded, inputs).await
        }
        (BootAction::Load(_), None) => Err(StoreError::Format(
            "assessed a store that was never decoded".into(),
        )),
        (BootAction::SeedFirstBoot, _) => {
            seed(dir, key, audit, 1, false, Prior::Absent, inputs).await
        }
        (BootAction::SeedAuthorized { revision }, _) => {
            seed(dir, key, audit, revision, true, prior, inputs).await
        }
    }?;
    report.marker_ignored = marker_ignored;
    Ok(report)
}

/// Reads the accepted baseline before anything is appended; writes nothing.
pub fn peek_baseline(
    dir: &StateDir,
    key: &WrappingKey,
) -> Result<Option<BaselineLayer>, StoreError> {
    match dir.read_store() {
        Ok(None) => Ok(None),
        Ok(Some(file)) => decode_store(&file, key).map(|d| d.extracted.baseline),
        Err(e) => Err(StoreError::StoreFileRefused(e.to_string())),
    }
}

/// Reads the stored sync base before anything is appended; writes nothing.
pub fn peek_sync(dir: &StateDir, key: &WrappingKey) -> Result<Option<SyncBase>, StoreError> {
    match dir.read_store() {
        Ok(None) => Ok(None),
        Ok(Some(file)) => decode_store(&file, key).map(|d| d.extracted.sync),
        Err(e) => Err(StoreError::StoreFileRefused(e.to_string())),
    }
}

fn is_canonical(
    graph: &Graph,
    layer: &IdentityLayer,
    baseline: Option<&BaselineLayer>,
    sync: Option<&SyncBase>,
    inputs: &BootInputs<'_>,
) -> bool {
    graph
        .lookup(CONFIG_SOURCE, &layer.source)
        .and_then(|n| {
            build(
                layer,
                baseline,
                sync,
                inputs,
                graph.revision(),
                n.provenance.kind,
            )
            .ok()
        })
        .is_some_and(|rebuilt| rebuilt == *graph)
}

async fn load(
    dir: &StateDir,
    key: &WrappingKey,
    audit: &mut impl BootAudit,
    state: AnchorState,
    decoded: Decoded,
    inputs: &BootInputs<'_>,
) -> Result<BootReport, StoreError> {
    let Decoded {
        graph,
        stored,
        extracted,
        facts,
    } = decoded;
    let stored_sync = extracted.sync;
    if stored_sync.is_none() {
        if let Some(m) = identity::drops_explicit_bindings(
            &extracted.layer,
            inputs.identity,
            inputs.bindings_missing,
        ) {
            return Err(StoreError::BindingsRefused(m));
        }
    }
    let stored_baseline = extracted.baseline;
    if stored_baseline.as_ref().map(|b| b.sha256) != inputs.accepted_seen {
        return Err(StoreError::BaselineUnseen {
            stored: stored_baseline.as_ref().map(|b| identity::hex(&b.sha256)),
            seen: inputs.accepted_seen.map(|d| identity::hex(&d)),
        });
    }
    if stored_sync.as_ref() != inputs.sync_seen {
        return Err(StoreError::SyncUnseen);
    }
    let to = inputs.vocabulary_sha256;
    let mut layer = extracted.layer;
    let mut revision = facts.revision;
    let migration = match vocabulary::assess(extracted.vocabulary_sha256, &stored, to) {
        Assessment::Forged(why) => return Err(StoreError::Vocabulary(why)),
        Assessment::Current => None,
        Assessment::Upgrade { from } => {
            let (migrated, mut unbound) = migrated_layer(&layer, inputs.identity, inputs.compiled);
            unbound.extend(extracted.unbound);
            unbound.sort_unstable();
            revision = next_revision(revision)?;
            let next = build(
                &migrated,
                stored_baseline.as_ref(),
                stored_sync.as_ref(),
                inputs,
                revision,
                ProvenanceKind::Kernel,
            )?;
            layer = migrated;
            Some((Migration { from, to, unbound }, next))
        }
    };
    let file = identity::carry_forward(inputs.identity, inputs.unresolved_adversaries, &layer).0;
    let stale = migration.is_none()
        && !is_canonical(
            &graph,
            &layer,
            stored_baseline.as_ref(),
            stored_sync.as_ref(),
            inputs,
        );
    let identity_changed = stale || sorted(&layer) != sorted(&file);
    let baseline_changed = stored_baseline.as_ref() != Some(inputs.baseline);
    if baseline_changed && inputs.baseline_events.is_empty() {
        return Err(StoreError::BaselineUnrecorded);
    }
    let sync_changed = stored_sync.as_ref() != Some(inputs.sync);
    let initiator = transition_initiator(
        inputs.sync_kind,
        identity_changed && !stale,
        baseline_changed,
        stale,
    );
    let transition = if identity_changed || baseline_changed || sync_changed {
        revision = next_revision(revision)?;
        Some(build(
            &file,
            Some(inputs.baseline),
            Some(inputs.sync),
            inputs,
            revision,
            initiator,
        )?)
    } else {
        None
    };

    dir.set_store_revision(facts.revision);
    audit
        .checkpoint(facts.revision, facts.digest, state.as_str())
        .await?;
    let mut report = BootReport {
        revision: facts.revision,
        digest: facts.digest,
        outcome: BootOutcome::Loaded(state),
        graph,
        marker_ignored: None,
        migration: None,
        identity_transition: false,
        baseline_transition: false,
        released: Vec::new(),
        durability_error: None,
    };
    if let Some((m, next)) = migration {
        audit
            .intent_migrate(next.revision(), m.from, m.to, &m.unbound)
            .await?;
        let persisted = dir.persist(key, &next)?;
        audit
            .checkpoint(next.revision(), persisted.digest, ANCHOR_MIGRATED)
            .await?;
        report.revision = next.revision();
        report.digest = persisted.digest;
        report.durability_error = persisted.durability_error;
        report.graph = next;
        report.migration = Some(m);
    }
    if let Some(next) = transition {
        let released = identity::released(&layer, &file, inputs.bindings_lists_nobody);
        if !released.is_empty() {
            audit.released(next.revision(), &released).await?;
        }
        if baseline_changed {
            audit
                .baseline(next.revision(), inputs.baseline_events)
                .await?;
        }
        if sync_changed && !inputs.sync_events.is_empty() {
            audit.sync(next.revision(), inputs.sync_events).await?;
        }
        audit
            .intent_transition(next.revision(), initiator_name(initiator))
            .await?;
        let persisted = dir.persist(key, &next)?;
        audit
            .checkpoint(next.revision(), persisted.digest, ANCHOR_TRANSITIONED)
            .await?;
        report.revision = next.revision();
        report.digest = persisted.digest;
        report.durability_error = persisted.durability_error;
        report.graph = next;
        report.identity_transition = identity_changed;
        report.baseline_transition = baseline_changed;
        report.released = released;
    }
    Ok(report)
}

/// Persists a validated identity transition: the containments it ends, then `sync_events`;
/// intent, publish, checkpoint. The publish's rename is the point of no return, so a
/// failure after it is reported, not raised. Callers serialize commits; the floor is
/// re-checked at publish.
pub async fn commit(
    dir: &StateDir,
    key: &WrappingKey,
    next: &Graph,
    released: &[identity::Released],
    sync_events: &[String],
    audit: &mut impl BootAudit,
    initiator: &'static str,
) -> Result<Committed, StoreError> {
    let t = Transition {
        released,
        baseline_events: &[],
        sync_events,
        initiator,
        rule: SyncRule::Free,
    };
    transition(dir, key, next, t, audit).await
}

/// An operator's accept: the one commit that may change the accepted baseline, with
/// `events` written ahead of the transition intent. Dropping the baseline is refused,
/// and so is any change to the sync base.
pub async fn commit_accept(
    dir: &StateDir,
    key: &WrappingKey,
    next: &Graph,
    events: &[String],
    audit: &mut impl BootAudit,
) -> Result<Committed, StoreError> {
    let t = Transition {
        released: &[],
        baseline_events: events,
        sync_events: &[],
        initiator: INITIATOR_OPERATOR,
        rule: SyncRule::Unchanged,
    };
    transition(dir, key, next, t, audit).await
}

/// A live identity edit: only the sync base's `live` may change; its base, its conflicts
/// and the baseline are the stored ones, and `events` records it ahead of the intent.
pub async fn commit_live(
    dir: &StateDir,
    key: &WrappingKey,
    next: &Graph,
    released: &[identity::Released],
    events: &[String],
    audit: &mut impl BootAudit,
    initiator: LiveInitiator,
) -> Result<Committed, StoreError> {
    let t = Transition {
        released,
        baseline_events: &[],
        sync_events: events,
        initiator: initiator_name(initiator.provenance()),
        rule: SyncRule::BaseKept,
    };
    transition(dir, key, next, t, audit).await
}

enum SyncRule {
    Free,
    Unchanged,
    BaseKept,
}

struct Transition<'a> {
    released: &'a [identity::Released],
    baseline_events: &'a [String],
    sync_events: &'a [String],
    initiator: &'static str,
    rule: SyncRule,
}

fn check_sync(
    t: &Transition<'_>,
    stored: Option<&SyncBase>,
    proposed: Option<&SyncBase>,
) -> Result<(), StoreError> {
    match t.rule {
        SyncRule::Free => Ok(()),
        SyncRule::Unchanged if proposed != stored => Err(StoreError::SyncBaseChanged),
        SyncRule::Unchanged => Ok(()),
        SyncRule::BaseKept if t.sync_events.is_empty() => Err(StoreError::SyncUnrecorded),
        SyncRule::BaseKept => match (stored, proposed) {
            (Some(s), Some(p)) if s.base == p.base && s.conflicts == p.conflicts => Ok(()),
            (None, _) | (_, None) => Err(StoreError::SyncAbsent),
            _ => Err(StoreError::SyncBaseChanged),
        },
    }
}

async fn transition(
    dir: &StateDir,
    key: &WrappingKey,
    next: &Graph,
    t: Transition<'_>,
    audit: &mut impl BootAudit,
) -> Result<Committed, StoreError> {
    let revision = next.revision();
    let store = dir.store_revision();
    if revision <= store {
        return Err(StoreError::StaleRevision {
            store,
            attempted: revision,
        });
    }
    let proposed = identity::extract(next).map_err(|e| StoreError::Identity(e.to_string()))?;
    let stored = match dir.read_store() {
        Ok(None) => None,
        Ok(Some(file)) => Some(decode_store(&file, key)?.extracted),
        Err(e) => return Err(StoreError::StoreFileRefused(e.to_string())),
    };
    let (stored_baseline, stored_sync) = match stored {
        Some(e) => (e.baseline, e.sync),
        None => (None, None),
    };
    let unrecorded = if t.baseline_events.is_empty() {
        proposed.baseline != stored_baseline
    } else {
        proposed.baseline.is_none()
    };
    if unrecorded {
        return Err(StoreError::BaselineUnrecorded);
    }
    check_sync(&t, stored_sync.as_ref(), proposed.sync.as_ref())?;
    if !t.released.is_empty() {
        audit.released(revision, t.released).await?;
    }
    if !t.baseline_events.is_empty() {
        audit.baseline(revision, t.baseline_events).await?;
    }
    if !t.sync_events.is_empty() {
        audit.sync(revision, t.sync_events).await?;
    }
    audit.intent_transition(revision, t.initiator).await?;
    let persisted = dir.persist(key, next)?;
    let checkpoint_error = audit
        .checkpoint(revision, persisted.digest, ANCHOR_TRANSITIONED)
        .await
        .err()
        .map(|e| e.to_string());
    Ok(Committed {
        revision,
        digest: persisted.digest,
        durability_error: persisted.durability_error,
        checkpoint_error,
    })
}

enum Prior {
    Absent,
    Readable(Zeroizing<Vec<u8>>, u64),
}

async fn seed(
    dir: &StateDir,
    key: &WrappingKey,
    audit: &mut impl BootAudit,
    revision: u64,
    authorized: bool,
    prior: Prior,
    inputs: &BootInputs<'_>,
) -> Result<BootReport, StoreError> {
    if !authorized && inputs.accepted_seen.is_some() {
        return Err(StoreError::BaselineUnseen {
            stored: None,
            seen: inputs.accepted_seen.map(|d| identity::hex(&d)),
        });
    }
    if inputs.baseline_events.is_empty() {
        return Err(StoreError::BaselineUnrecorded);
    }
    let graph = build(
        inputs.identity,
        Some(inputs.baseline),
        Some(inputs.sync),
        inputs,
        revision,
        ProvenanceKind::Seed,
    )?;
    audit.intent_seed(revision, authorized).await?;
    audit.baseline(revision, inputs.baseline_events).await?;
    let rejected = match prior {
        Prior::Absent => None,
        Prior::Readable(bytes, now_unix) => {
            let tag: String = ciphertext_digest(&bytes)[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let name = format!("{REJECTED_PREFIX}{now_unix}.{tag}");
            Some(dir.preserve(&name, &bytes)?)
        }
    };
    let persisted = dir.persist(key, &graph)?;
    let digest = persisted.digest;
    if authorized {
        dir.anchor.remove(Path::new(MARKER_FILE), None)?;
    }
    let anchor = if authorized {
        ANCHOR_RESEEDED
    } else {
        ANCHOR_SEEDED
    };
    audit.checkpoint(revision, digest, anchor).await?;
    Ok(BootReport {
        revision,
        digest,
        outcome: BootOutcome::Seeded {
            authorized,
            rejected,
        },
        graph,
        marker_ignored: None,
        migration: None,
        identity_transition: false,
        baseline_transition: false,
        released: Vec::new(),
        durability_error: persisted.durability_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_graph::identity::SubjectEntry;
    use maknae_graph::kernel::persisted_compiled_set;

    fn subject(uid: u32, role: &str) -> SubjectEntry {
        SubjectEntry {
            uid,
            name: format!("u{uid}"),
            role: role.into(),
        }
    }

    fn file() -> IdentityLayer {
        IdentityLayer {
            aliases: Default::default(),
            source: "/etc/maknae/authz.yaml".into(),
            label: "UNOFFICIAL".into(),
            bindings_sha256: Some([1; 32]),
            subjects: vec![subject(0, "admin")],
        }
    }

    #[test]
    fn a_boot_reports_debug_never_prints_a_baseline_value() {
        let baseline = BaselineLayer {
            sections: [
                ("audit", r#"{"au3_1":{"enclave":"SCIF-B7"}}"#),
                ("core", r#"{"deployment_id":"d"}"#),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            system: "US".into(),
            ceiling: "SECRET".into(),
            sha256: [7; 32],
            moved_from: None,
        };
        let graph = identity::build(
            &file(),
            Some(&baseline),
            None,
            &persisted_compiled_set("UNOFFICIAL"),
            [9; 32],
            1,
            ProvenanceKind::RootFile,
        )
        .unwrap();
        let report = BootReport {
            revision: 1,
            digest: [0; 32],
            outcome: BootOutcome::Loaded(crate::anchor::AnchorState::Verified),
            graph,
            marker_ignored: None,
            migration: None,
            identity_transition: false,
            baseline_transition: false,
            released: Vec::new(),
            durability_error: None,
        };
        let shown = format!("{report:?}");
        assert!(shown.contains("BootReport"), "{shown}");
        for value in ["SCIF-B7", "SECRET"] {
            assert!(!shown.contains(value), "{value} in {shown}");
        }
    }

    #[test]
    fn an_empty_stored_layer_takes_the_files_source_and_label_and_nothing_else() {
        let (l, unbound) = migrated_layer(
            &IdentityLayer::default(),
            &file(),
            &persisted_compiled_set("UNOFFICIAL"),
        );
        assert_eq!(
            l,
            IdentityLayer {
                aliases: Default::default(),
                source: "/etc/maknae/authz.yaml".into(),
                label: "UNOFFICIAL".into(),
                bindings_sha256: None,
                subjects: vec![],
            }
        );
        assert!(unbound.is_empty());
    }

    #[test]
    fn a_populated_layer_keeps_its_source_bindings_and_subjects_under_the_binarys_label() {
        let stored = IdentityLayer {
            aliases: Default::default(),
            source: "/old/authz.yaml".into(),
            label: "UNCLASSIFIED".into(),
            bindings_sha256: Some([2; 32]),
            subjects: vec![
                subject(0, "user"),
                subject(666, "adversary"),
                subject(9, "guest"),
            ],
        };
        let (l, unbound) = migrated_layer(&stored, &file(), &persisted_compiled_set("UNOFFICIAL"));
        assert_eq!(
            l,
            IdentityLayer {
                label: "UNOFFICIAL".into(),
                ..stored
            }
        );
        assert!(unbound.is_empty());
    }

    #[test]
    fn a_vanished_role_is_dropped_and_its_uids_reported() {
        let stored = IdentityLayer {
            subjects: vec![
                subject(3, "superadmin"),
                subject(0, "admin"),
                subject(4, "gone"),
            ],
            ..file()
        };
        let (l, unbound) = migrated_layer(&stored, &file(), &persisted_compiled_set("UNOFFICIAL"));
        assert_eq!(l.subjects, vec![subject(0, "admin")]);
        assert_eq!(unbound, vec![3, 4]);
    }

    #[test]
    fn a_vanished_subject_takes_its_aliases_with_it() {
        let stored = IdentityLayer {
            subjects: vec![
                subject(0, "admin"),
                subject(5, ADVERSARY),
                subject(4, "gone"),
            ],
            aliases: [("keep", 5), ("bound", 0), ("gone", 4)]
                .map(|(n, u)| (n.to_string(), u))
                .into(),
            ..file()
        };
        let (l, _) = migrated_layer(&stored, &file(), &persisted_compiled_set("UNOFFICIAL"));
        assert_eq!(l.aliases, [("keep".to_string(), 5)].into());
    }

    #[test]
    fn layers_compare_without_regard_to_subject_order() {
        let a = IdentityLayer {
            subjects: vec![subject(2, "user"), subject(1, "user")],
            ..file()
        };
        let b = IdentityLayer {
            subjects: vec![subject(1, "user"), subject(2, "user")],
            ..file()
        };
        assert_eq!(sorted(&a), sorted(&b));
        assert_ne!(a, b);
    }
}
