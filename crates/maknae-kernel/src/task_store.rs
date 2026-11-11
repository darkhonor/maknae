//! The task store at rest (#628): one record per task and the counters, sealed under
//! `STATE_DIR/tasks` with the graph key.
use std::sync::Arc;
use std::time::Duration;

use maknae_config::AgentId;
use maknae_io::Zeroizing;
use maknae_proto::{SecretText, SignedTask, TaskClose, TaskId, TaskState, Tasker};
use serde::{Deserialize, Serialize};

use crate::conversation::dir_store::{DirBlobs, Layout};
use crate::conversation::store::{Blobs, StoreError as BlobError};

pub const CLAIM_LEASE: Duration = Duration::from_secs(15 * 60);

pub const RECORD_MAX: u64 = (3 * maknae_config::PROMPT_MAX_CEILING
    + maknae_proto::TASK_ENVELOPE_MARGIN
    + maknae_proto::TASK_SIGNATURE_MAX_BYTES
    + 4096) as u64;

pub const TASKS: Layout = Layout {
    what: "task",
    suffix: ".task",
    max_bytes: RECORD_MAX,
};

pub const COUNTERS: &str = "counters";

pub trait Clock: Send + Sync {
    fn now_secs(&self) -> i64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
    }
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
pub struct ManualClock(std::sync::atomic::AtomicI64);

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl ManualClock {
    pub fn at(secs: i64) -> Self {
        Self(std::sync::atomic::AtomicI64::new(secs))
    }

    pub fn set(&self, secs: i64) {
        self.0.store(secs, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl Clock for ManualClock {
    fn now_secs(&self) -> i64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The tasker at the root of a task's chain, whose partition the chain works in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RootTasker {
    Person { uid: u32 },
    Agent { agent: String },
}

impl RootTasker {
    pub fn partition(&self) -> String {
        match self {
            RootTasker::Person { uid } => format!("users/{uid}"),
            RootTasker::Agent { agent } => format!("agents/{agent}"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRecord {
    #[serde(with = "arc_signed")]
    pub signed: Arc<SignedTask>,
    #[serde(with = "agent_id")]
    pub agent: AgentId,
    pub agent_uid: u32,
    pub tasker: Tasker,
    pub root: RootTasker,
    pub parent: Option<TaskId>,
    pub state: TaskState,
    pub close: Option<TaskClose>,
    pub pending: bool,
    pub seq: u64,
    /// The tasker's own submission ordinal, the list cursor.
    pub tseq: u64,
    /// The tasker's own report ordinal, assigned when the report or the close lands.
    pub rseq: Option<u64>,
    pub submitted: i64,
    pub claimed: Option<i64>,
    pub follow_ups: Vec<SecretText>,
    pub report: Option<(SecretText, i64)>,
}

mod arc_signed {
    use super::*;

    pub fn serialize<S: serde::Serializer>(t: &Arc<SignedTask>, s: S) -> Result<S::Ok, S::Error> {
        t.as_ref().serialize(s)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Arc<SignedTask>, D::Error> {
        SignedTask::deserialize(d).map(Arc::new)
    }
}

mod agent_id {
    use super::*;

    pub fn serialize<S: serde::Serializer>(a: &AgentId, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(a.as_str())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<AgentId, D::Error> {
        AgentId::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// The highest values ever issued: the store-wide submission sequence, and each tasker's
/// own submission and report ordinals, so no cursor a tasker sees counts another's tasks.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counters {
    pub seq: u64,
    pub taskers: std::collections::BTreeMap<String, Ordinals>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ordinals {
    pub seq: u64,
    pub rseq: u64,
}

impl Counters {
    pub fn of(&self, tasker: &Tasker) -> Ordinals {
        self.taskers
            .get(&ordinal_key(tasker))
            .copied()
            .unwrap_or_default()
    }
}

/// A tasker's key in [`Counters`]; an agent's includes its uid, as [`Tasker`] equality does.
pub fn ordinal_key(tasker: &Tasker) -> String {
    match tasker {
        Tasker::Uid(uid) => format!("uid:{uid}"),
        Tasker::Agent { agent, uid } => format!("agent:{agent}@{uid}"),
        Tasker::Remote(id) => format!("remote:{id}"),
    }
}

/// In memory only; `lease_until` is never persisted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hot {
    pub actions: u32,
    pub last_action: Option<i64>,
    pub lease_until: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    Io(String),
    /// The write or unlink happened and is visible, but the directory was not synced.
    NotDurable(String),
    Counters(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(why) | StoreError::NotDurable(why) => f.write_str(why),
            StoreError::Counters(why) => write!(f, "task counters {why}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// What boot found that it must record in the trail before it touches the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootFinding {
    Discarded {
        name: String,
        task: TaskId,
        agent: String,
        tasker: Tasker,
        parent: Option<TaskId>,
    },
    Quarantined {
        name: String,
        why: String,
    },
}

pub trait TaskBlobs: Send + Sync {
    fn names(&self) -> Result<Vec<String>, StoreError>;
    fn load(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, StoreError>;
    fn save(&self, name: &str, plain: &[u8]) -> Result<(), StoreError>;
    fn delete(&self, name: &str) -> Result<(), StoreError>;
    fn quarantine(&self, name: &str) -> Result<(), StoreError>;
}

fn lift(e: BlobError) -> StoreError {
    match e {
        BlobError::NotDurable(why) => StoreError::NotDurable(why),
        other => StoreError::Io(other.to_string()),
    }
}

impl TaskBlobs for DirBlobs {
    fn names(&self) -> Result<Vec<String>, StoreError> {
        Blobs::names(self).map_err(lift)
    }

    fn load(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        Blobs::load(self, name).map_err(lift)
    }

    fn save(&self, name: &str, plain: &[u8]) -> Result<(), StoreError> {
        Blobs::save(self, name, plain).map_err(lift)
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.delete_settled(name).map_err(lift)
    }

    fn quarantine(&self, name: &str) -> Result<(), StoreError> {
        DirBlobs::quarantine(self, name).map_err(lift)
    }
}

struct Counted(usize);

impl std::io::Write for Counted {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Sized first, so the zeroizing buffer is allocated once and never grows.
pub fn encode<T: Serialize>(v: &T) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let mut size = Counted(0);
    ciborium::into_writer(v, &mut size).map_err(|e| StoreError::Io(e.to_string()))?;
    let mut buf = Zeroizing::new(vec![0u8; size.0]);
    ciborium::into_writer(v, &mut std::io::Cursor::new(buf.as_mut_slice()))
        .map_err(|e| StoreError::Io(e.to_string()))?;
    Ok(buf)
}

pub fn name_of(id: &TaskId) -> String {
    id.to_string()
}

/// Everything at rest, read once at open.
pub struct Loaded {
    pub records: Vec<TaskRecord>,
    pub counters: Counters,
    pub findings: Vec<BootFinding>,
}

fn read_record(blobs: &dyn TaskBlobs, name: &str) -> Result<TaskRecord, String> {
    let id: TaskId = name
        .parse()
        .map_err(|_| "the name is not a task id".to_string())?;
    let plain = blobs.load(name).map_err(|e| e.to_string())?;
    let rec: TaskRecord =
        ciborium::from_reader(plain.as_slice()).map_err(|_| "the record does not decode")?;
    if rec.signed.task.task_id != id {
        return Err("the record names another task".into());
    }
    Ok(rec)
}

/// A missing or unreadable `counters` is a reset only when nothing else is stored.
pub fn load(blobs: &dyn TaskBlobs) -> Result<Loaded, StoreError> {
    let mut names = blobs.names()?;
    names.sort();
    let mut counters = None;
    let mut records = Vec::new();
    let mut findings = Vec::new();
    let mut top = Counters::default();
    let mut behind = false;
    for name in names {
        if name == COUNTERS {
            counters = Some(
                blobs
                    .load(COUNTERS)
                    .ok()
                    .and_then(|b| ciborium::from_reader::<Counters, _>(b.as_slice()).ok()),
            );
            continue;
        }
        let rec = match read_record(blobs, &name) {
            Ok(rec) => rec,
            Err(why) => {
                findings.push(BootFinding::Quarantined { name, why });
                continue;
            }
        };
        top.seq = top.seq.max(rec.seq);
        let o = top.taskers.entry(ordinal_key(&rec.tasker)).or_default();
        o.seq = o.seq.max(rec.tseq);
        o.rseq = o.rseq.max(rec.rseq.unwrap_or(0));
        if rec.pending {
            findings.push(BootFinding::Discarded {
                name,
                task: rec.signed.task.task_id,
                agent: rec.agent.as_str().to_owned(),
                tasker: rec.tasker,
                parent: rec.parent,
            });
        } else {
            records.push(rec);
        }
    }
    let empty = records.is_empty() && findings.is_empty();
    let counters = match counters {
        Some(Some(c)) => c,
        None | Some(None) if empty => Counters::default(),
        None => {
            return Err(StoreError::Counters(
                "are missing beside stored tasks".into(),
            ))
        }
        Some(None) => return Err(StoreError::Counters("cannot be read".into())),
    };
    for (key, o) in &top.taskers {
        let have = counters.taskers.get(key).copied().unwrap_or_default();
        behind |= have.seq < o.seq || have.rseq < o.rseq;
    }
    if counters.seq < top.seq || behind {
        return Err(StoreError::Counters(
            "are behind a stored task's sequence".into(),
        ));
    }
    Ok(Loaded {
        records,
        counters,
        findings,
    })
}

/// In-memory blobs for tests, with write failures on demand.
#[cfg(any(test, feature = "hermetic-test-seam"))]
#[derive(Clone, Default)]
pub struct MemTaskBlobs(Arc<MemInner>);

/// A name and the bytes saved under it, or `None` for its unlink.
#[cfg(any(test, feature = "hermetic-test-seam"))]
type Unsynced = (String, Option<Zeroizing<Vec<u8>>>);

#[cfg(any(test, feature = "hermetic-test-seam"))]
#[derive(Default)]
pub struct MemInner {
    map: std::sync::Mutex<std::collections::BTreeMap<String, Zeroizing<Vec<u8>>>>,
    aside: std::sync::Mutex<Vec<String>>,
    fail: std::sync::Mutex<Option<Fail>>,
    slow: std::sync::Mutex<Option<Duration>>,
    stalls: std::sync::atomic::AtomicUsize,
    synced: std::sync::Mutex<std::collections::BTreeMap<String, Zeroizing<Vec<u8>>>>,
    unsynced: std::sync::Mutex<Vec<Unsynced>>,
    after_save: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fail {
    Every,
    Records,
    Unsynced,
    Unlinks,
    /// A save lands unsynced and an unlink is refused.
    UnsyncedNoUnlink,
    Panics,
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl MemTaskBlobs {
    fn map(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::BTreeMap<String, Zeroizing<Vec<u8>>>> {
        self.0
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn fail(&self, fail: Option<Fail>) {
        *self
            .0
            .fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = fail;
    }

    /// Every record save and delete takes `by` first, as a stalled fsync would.
    pub fn slow(&self, by: Option<Duration>) {
        *self
            .0
            .slow
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = by;
    }

    fn stall(&self, name: &str) {
        let by = *self
            .0
            .slow
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let (Some(by), false) = (by, name == COUNTERS) {
            self.0
                .stalls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(by);
        }
    }

    /// Returns once `n` stalled operations have begun, so a test waits on the store,
    /// never on a clock.
    pub fn await_stalls(&self, n: usize) {
        let until = std::time::Instant::now() + Duration::from_secs(10);
        while self.0.stalls.load(std::sync::atomic::Ordering::SeqCst) < n {
            assert!(std::time::Instant::now() < until, "no stall began");
            std::thread::yield_now();
        }
    }

    pub fn put(&self, name: &str, plain: &[u8]) {
        self.map()
            .insert(name.to_owned(), Zeroizing::new(plain.to_vec()));
        self.settle(name, Ok(()), Some(plain))
            .expect("a planted blob is synced");
    }

    /// Runs once, after the next record save has landed.
    pub fn after_save(&self, then: impl FnOnce() + Send + 'static) {
        *self
            .0
            .after_save
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(then));
    }

    /// The directory as a crash would leave it: what was last synced, then the first
    /// `kept` of the changes that landed unsynced since.
    pub fn crash(&self, kept: usize) {
        let mut disk = self
            .0
            .synced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let lost = std::mem::take(
            &mut *self
                .0
                .unsynced
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for (name, bytes) in lost.into_iter().take(kept) {
            match bytes {
                Some(b) => disk.insert(name, b),
                None => disk.remove(&name),
            };
        }
        *self.map() = disk;
    }

    fn settle(
        &self,
        name: &str,
        landed: Result<(), StoreError>,
        bytes: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        let mut unsynced = self
            .0
            .unsynced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &landed {
            Ok(()) => {
                unsynced.clear();
                *self
                    .0
                    .synced
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = self.map().clone();
            }
            Err(_) => unsynced.push((name.to_owned(), bytes.map(|b| Zeroizing::new(b.to_vec())))),
        }
        landed
    }

    pub fn has(&self, name: &str) -> bool {
        self.map().contains_key(name)
    }

    pub fn aside(&self) -> Vec<String> {
        self.0
            .aside
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn refuse(&self, name: &str) -> Result<(), StoreError> {
        let fail = *self
            .0
            .fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match fail {
            Some(Fail::Every) => Err(StoreError::Io("sentinel-628-write-refused".into())),
            Some(Fail::Records) if name != COUNTERS => {
                Err(StoreError::Io("sentinel-628-write-refused".into()))
            }
            Some(Fail::Panics) if name != COUNTERS => panic!("sentinel-628-store-panic"),
            Some(Fail::Records)
            | Some(Fail::Unsynced)
            | Some(Fail::Unlinks)
            | Some(Fail::UnsyncedNoUnlink)
            | Some(Fail::Panics)
            | None => Ok(()),
        }
    }

    fn landed(&self, name: &str) -> Result<(), StoreError> {
        let fail = *self
            .0
            .fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match fail {
            Some(Fail::Unsynced | Fail::UnsyncedNoUnlink) if name != COUNTERS => {
                Err(StoreError::NotDurable("sentinel-628-unsynced".into()))
            }
            Some(Fail::Every)
            | Some(Fail::Records)
            | Some(Fail::Unsynced)
            | Some(Fail::Unlinks)
            | Some(Fail::UnsyncedNoUnlink)
            | Some(Fail::Panics)
            | None => Ok(()),
        }
    }
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl TaskBlobs for MemTaskBlobs {
    fn names(&self) -> Result<Vec<String>, StoreError> {
        self.refuse(COUNTERS)?;
        Ok(self.map().keys().cloned().collect())
    }

    fn load(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.map()
            .get(name)
            .cloned()
            .ok_or_else(|| StoreError::Io(format!("{name}: not found")))
    }

    fn save(&self, name: &str, plain: &[u8]) -> Result<(), StoreError> {
        self.refuse(name)?;
        self.stall(name);
        self.map()
            .insert(name.to_owned(), Zeroizing::new(plain.to_vec()));
        let landed = self.settle(name, self.landed(name), Some(plain));
        let then = match name == COUNTERS {
            true => None,
            false => self
                .0
                .after_save
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        };
        if let Some(then) = then {
            then();
        }
        landed
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.refuse(name)?;
        let fail = *self
            .0
            .fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(fail, Some(Fail::Unlinks | Fail::UnsyncedNoUnlink)) {
            return Err(StoreError::Io("sentinel-628-unlink-refused".into()));
        }
        self.stall(name);
        self.map().remove(name);
        self.settle(name, self.landed(name), None)
    }

    fn quarantine(&self, name: &str) -> Result<(), StoreError> {
        self.refuse(name)?;
        self.map().remove(name);
        self.settle(name, Ok(()), None)?;
        self.0
            .aside
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(name.to_owned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment::FixedEnrollment;
    use crate::task::{Enrolled, TaskRefusal, TaskSigner, TaskStore};
    use maknae_proto::{Ask, Bytes, Labels, TaskObject, TaskSignature, TaskSubmission};
    use maknae_state::envelope::{WrappingKey, KEY_LEN};
    use std::os::unix::fs::PermissionsExt;

    const HOBI: u32 = 2001;
    const SENTINEL: &str = "sentinel-628-task-store-prompt";

    fn secret(s: &str) -> SecretText {
        SecretText(Zeroizing::new(s.into()))
    }

    fn signed(agent: &str, tasker: Tasker, prompt: &str) -> SignedTask {
        let mut id = [0u8; 16];
        maknae_crypto::random::fill(&mut id[..]).unwrap();
        SignedTask {
            task: TaskObject {
                schema: maknae_proto::TASK_SCHEMA.into(),
                version: maknae_proto::TASK_VERSION,
                task_id: TaskId(id),
                tasker,
                parent: None,
                agent: agent.into(),
                ask: Ask::Prompt {
                    prompt: secret(prompt),
                },
                labels: Labels {},
            },
            signature: TaskSignature {
                alg: "test".into(),
                leaf: Bytes(Zeroizing::new(vec![1])),
                chain: Vec::new(),
                sig: Bytes(Zeroizing::new(vec![2])),
            },
        }
    }

    struct Unverified;

    impl TaskSigner for Unverified {
        fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal> {
            let mut s = signed("hobi", Tasker::Uid(0), "");
            s.task = task;
            Ok(s)
        }
        fn current_leaf(&self) -> Option<[u8; 32]> {
            None
        }
    }

    fn hobi() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    fn by_uid(store: &TaskStore, prompt: &str) -> TaskId {
        store
            .insert_for_test(signed("hobi", Tasker::Uid(1000), prompt), HOBI)
            .task
            .task_id
    }

    fn open_mem(b: &MemTaskBlobs) -> TaskStore {
        TaskStore::open(Box::new(b.clone()), Arc::new(SystemClock)).unwrap()
    }

    fn rewrite(b: &MemTaskBlobs, store: &TaskStore, id: &TaskId, f: impl FnOnce(&mut TaskRecord)) {
        let mut rec = store.record(id).unwrap();
        f(&mut rec);
        b.put(&name_of(id), &encode(&rec).unwrap());
    }

    fn key() -> WrappingKey {
        WrappingKey::new(Zeroizing::new([9u8; KEY_LEN]))
    }

    fn open_dir(dir: &std::path::Path) -> Result<TaskStore, StoreError> {
        let uid = nix::unistd::geteuid().as_raw();
        let blobs = DirBlobs::open(dir, uid, key(), TASKS).unwrap();
        TaskStore::open(Box::new(blobs), Arc::new(SystemClock))
    }

    fn tmp() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        t
    }

    fn mint(store: &TaskStore) -> Result<Arc<SignedTask>, TaskRefusal> {
        let v = FixedEnrollment([(hobi(), HOBI)].into_iter().collect());
        let sub = TaskSubmission {
            schema: maknae_proto::TASK_SCHEMA.into(),
            version: maknae_proto::TASK_VERSION,
            agent: "hobi".into(),
            ask: Ask::Prompt {
                prompt: secret(SENTINEL),
            },
            labels: Labels {},
        };
        let enrolled = Enrolled {
            generation: store.generation(&hobi()),
            agent_uid: HOBI,
        };
        let t = store.mint(&Unverified, &v, enrolled, Tasker::Uid(1000), None, sub)?;
        store.confirm(&t.task.task_id, None)?;
        Ok(t)
    }

    #[test]
    fn a_record_seals_and_reopens_byte_identical() {
        let t = tmp();
        let store = open_dir(t.path()).unwrap();
        let id = mint(&store).unwrap().task.task_id;
        let before = encode(&store.record(&id).unwrap()).unwrap();
        drop(store);
        let raw = std::fs::read(t.path().join(format!("{id}.task"))).unwrap();
        assert!(!raw
            .windows(SENTINEL.len())
            .any(|w| w == SENTINEL.as_bytes()));
        assert!(t.path().join("counters.task").is_file());
        let reopened = open_dir(t.path()).unwrap();
        let after = encode(&reopened.record(&id).unwrap()).unwrap();
        assert_eq!(*before, *after);
        assert!(reopened.take_boot_findings().is_empty());
    }

    #[test]
    fn fifo_order_survives_reopen() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b);
        let ids: Vec<TaskId> = (0..8).map(|_| by_uid(&store, "q")).collect();
        assert_eq!(store.queue(&hobi()), ids);
        assert_eq!(open_mem(&b).queue(&hobi()), ids);
    }

    #[test]
    fn counters_never_go_backwards_after_every_report_is_acknowledged() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b);
        let first = by_uid(&store, "one");
        let old = store.publish_report(&first, secret("r1"), None).unwrap();
        assert_eq!(store.acknowledge(&Tasker::Uid(1000), &hobi(), old), Ok(1));
        assert!(store.record(&first).is_none());
        drop(store);
        let store = open_mem(&b);
        let second = by_uid(&store, "two");
        assert!(store.record(&second).unwrap().seq > 1);
        let new = store.publish_report(&second, secret("r2"), None).unwrap();
        assert!(new > old);
        assert_eq!(store.acknowledge(&Tasker::Uid(1000), &hobi(), old), Ok(0));
        assert!(store.record(&second).is_some());
    }

    #[test]
    fn an_ack_cursor_above_the_high_water_mark_is_refused() {
        let store = TaskStore::new();
        let id = by_uid(&store, "one");
        let rseq = store
            .publish_report(&id, secret("r"), Some(TaskClose::Stopped))
            .unwrap();
        let rec = store.record(&id).unwrap();
        assert_eq!(
            (rec.state, rec.close, rec.rseq),
            (TaskState::Closed, Some(TaskClose::Stopped), Some(rseq))
        );
        assert_eq!(
            store.acknowledge(&Tasker::Uid(1000), &hobi(), rseq + 1),
            Err(TaskRefusal::CursorAhead)
        );
        assert!(store.record(&id).is_some());
        assert_eq!(store.acknowledge(&Tasker::Uid(1000), &hobi(), rseq), Ok(1));
    }

    #[test]
    fn pending_records_are_discarded_at_open_with_a_record() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b);
        let kept = by_uid(&store, "kept");
        let pending = by_uid(&store, "pending");
        rewrite(&b, &store, &pending, |r| r.pending = true);
        let store = open_mem(&b);
        assert!(store.record(&kept).is_some());
        assert!(store.record(&pending).is_none());
        assert_eq!(store.hot(&pending), None);
        assert_eq!(
            store.resolve(&pending, &hobi(), HOBI),
            Err(TaskRefusal::Unknown)
        );
        assert_eq!(store.queue(&hobi()), vec![kept]);
        let found = store.take_boot_findings();
        assert_eq!(
            found,
            vec![BootFinding::Discarded {
                name: name_of(&pending),
                task: pending,
                agent: "hobi".into(),
                tasker: Tasker::Uid(1000),
                parent: None,
            }]
        );
        assert!(b.has(&name_of(&pending)));
        store.settle(&found[0]).unwrap();
        assert!(!b.has(&name_of(&pending)));
        assert!(store.take_boot_findings().is_empty());
        assert!(open_mem(&b).take_boot_findings().is_empty());
    }

    #[test]
    fn working_leases_are_extended_at_open() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b);
        let working = by_uid(&store, "w");
        let queued = by_uid(&store, "q");
        rewrite(&b, &store, &working, |r| r.state = TaskState::Working);
        let clock = Arc::new(ManualClock::at(1_000));
        let store = TaskStore::open(Box::new(b.clone()), clock.clone()).unwrap();
        let lease = 1_000 + CLAIM_LEASE.as_secs() as i64;
        assert_eq!(store.hot(&working).unwrap().lease_until, lease);
        assert_eq!(store.hot(&queued).unwrap().lease_until, 0);
        clock.set(5_000);
        assert_eq!(clock.now_secs(), 5_000);
    }

    #[test]
    fn an_unreadable_or_oversized_record_is_quarantined_and_boot_continues() {
        let t = tmp();
        let store = open_dir(t.path()).unwrap();
        let kept = mint(&store).unwrap().task.task_id;
        drop(store);
        let junk = TaskId([3; 16]);
        let big = TaskId([4; 16]);
        let put = |name: String, len: u64| {
            let path = t.path().join(format!("{name}.task"));
            let f = std::fs::File::create(&path).unwrap();
            f.set_len(len).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        put(junk.to_string(), 16);
        put(big.to_string(), RECORD_MAX + 1);
        put("not-a-task-id".into(), 16);
        let store = open_dir(t.path()).unwrap();
        assert!(store.record(&kept).is_some());
        let found = store.take_boot_findings();
        let names: Vec<&str> = found
            .iter()
            .map(|f| match f {
                BootFinding::Quarantined { name, .. } => name.as_str(),
                BootFinding::Discarded { .. } => panic!("{f:?}"),
            })
            .collect();
        let (junk, big) = (junk.to_string(), big.to_string());
        let mut want = vec![junk.as_str(), big.as_str(), "not-a-task-id"];
        want.sort();
        assert_eq!(names, want);
        for f in &found {
            store.settle(f).unwrap();
        }
        for name in want {
            assert!(!t.path().join(format!("{name}.task")).exists());
            assert!(t.path().join(format!("{name}.task.quarantine")).exists());
        }
        drop(store);
        let store = open_dir(t.path()).unwrap();
        assert!(store.take_boot_findings().is_empty());
        assert!(store.record(&kept).is_some());
    }

    #[test]
    fn a_record_that_names_another_task_or_does_not_decode_is_quarantined() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b);
        let a = by_uid(&store, "a");
        let other = TaskId([5; 16]);
        b.put(&name_of(&other), &b.load(&name_of(&a)).unwrap());
        let garbled = TaskId([6; 16]);
        b.put(&name_of(&garbled), b"\xff");
        let found = open_mem(&b).take_boot_findings();
        assert_eq!(
            found,
            vec![
                BootFinding::Quarantined {
                    name: name_of(&other),
                    why: "the record names another task".into(),
                },
                BootFinding::Quarantined {
                    name: name_of(&garbled),
                    why: "the record does not decode".into(),
                },
            ]
        );
        open_mem(&b).settle(&found[0]).unwrap();
        assert_eq!(b.aside(), vec![name_of(&other)]);
    }

    #[test]
    fn a_failed_write_leaves_memory_unchanged() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b);
        let id = by_uid(&store, "one");
        for fail in [Fail::Every, Fail::Records] {
            b.fail(Some(fail));
            assert!(matches!(
                mint(&store),
                Err(TaskRefusal::Store(why)) if why == "sentinel-628-write-refused"
            ));
            assert!(matches!(
                store.publish_report(&id, secret("r"), None),
                Err(TaskRefusal::Store(_))
            ));
            let rec = store.record(&id).unwrap();
            assert_eq!(
                (rec.state, rec.rseq, rec.report.is_none()),
                (TaskState::Queued, None, true)
            );
            assert_eq!(store.queue(&hobi()), vec![id]);
        }
        b.fail(None);
        let rseq = store.publish_report(&id, secret("r"), None).unwrap();
        b.fail(Some(Fail::Every));
        assert!(matches!(
            store.acknowledge(&Tasker::Uid(1000), &hobi(), rseq),
            Err(TaskRefusal::Store(_))
        ));
        assert!(store.record(&id).is_some());
        b.fail(None);
        let next = mint(&store).unwrap().task.task_id;
        assert!(store.record(&next).unwrap().seq > 1);
        assert_eq!(open_mem(&b).queue(&hobi()), vec![next]);
    }

    #[test]
    fn a_write_that_lands_unsynced_is_undone_before_it_is_refused() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b);
        let id = by_uid(&store, "one");
        b.fail(Some(Fail::Unsynced));
        assert!(matches!(
            mint(&store),
            Err(TaskRefusal::Store(why)) if why == "sentinel-628-unsynced"
        ));
        assert!(matches!(
            store.publish_report(&id, secret("r"), None),
            Err(TaskRefusal::Store(_))
        ));
        b.fail(None);
        for s in [&store, &open_mem(&b)] {
            let rec = s.record(&id).unwrap();
            assert_eq!((rec.state, rec.rseq), (TaskState::Queued, None));
            assert_eq!(s.queue(&hobi()), vec![id]);
        }
        assert_eq!(b.names().unwrap().len(), 2);
    }

    #[test]
    fn an_acknowledgement_whose_delete_lands_unsynced_is_taken() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b);
        let id = by_uid(&store, "one");
        let rseq = store.publish_report(&id, secret("r"), None).unwrap();
        b.fail(Some(Fail::Unsynced));
        assert_eq!(store.acknowledge(&Tasker::Uid(1000), &hobi(), rseq), Ok(1));
        assert!(store.record(&id).is_none());
        b.fail(None);
        assert!(open_mem(&b).record(&id).is_none());
        assert_eq!(store.acknowledge(&Tasker::Uid(1000), &hobi(), rseq), Ok(0));
    }

    #[test]
    fn a_withdrawn_or_purged_task_leaves_memory_even_when_its_record_cannot_be_removed() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b);
        let id = by_uid(&store, "one");
        b.fail(Some(Fail::Every));
        store.purge_agent(&hobi());
        assert!(store.record(&id).is_none());
        assert!(b.has(&name_of(&id)));
        b.fail(None);
        let id = by_uid(&store, "two");
        store.purge_agent(&hobi());
        assert!(!b.has(&name_of(&id)));
    }

    #[test]
    fn a_report_is_taken_once_and_only_for_a_live_task() {
        let store = TaskStore::new();
        let id = by_uid(&store, "one");
        store.publish_report(&id, secret("r"), None).unwrap();
        assert_eq!(
            store.publish_report(&id, secret("again"), None),
            Err(TaskRefusal::Finished)
        );
        assert_eq!(
            store.publish_report(&TaskId([8; 16]), secret("r"), None),
            Err(TaskRefusal::Unknown)
        );
    }

    #[test]
    fn a_persons_task_is_rooted_at_the_uid_and_an_agents_at_the_agent() {
        let store = TaskStore::new();
        let own = mint(&store).unwrap().task.task_id;
        let root = store.record(&own).unwrap().root;
        assert_eq!(root, RootTasker::Person { uid: 1000 });
        assert_eq!(root.partition(), "users/1000");
        let agents = store
            .insert_for_test(
                signed(
                    "hobi",
                    Tasker::Agent {
                        agent: "jin".into(),
                        uid: 2002,
                    },
                    "a",
                ),
                HOBI,
            )
            .task
            .task_id;
        assert_eq!(
            store.record(&agents).unwrap().root.partition(),
            "agents/jin"
        );
    }

    #[test]
    fn missing_or_behind_counters_beside_a_task_refuse_open() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b);
        by_uid(&store, "one");
        let counters = b.load(COUNTERS).unwrap();
        b.put(COUNTERS, b"\xff");
        assert_eq!(
            TaskStore::open(Box::new(b.clone()), Arc::new(SystemClock)).err(),
            Some(StoreError::Counters("cannot be read".into()))
        );
        b.put(COUNTERS, &encode(&Counters::default()).unwrap());
        assert_eq!(
            TaskStore::open(Box::new(b.clone()), Arc::new(SystemClock)).err(),
            Some(StoreError::Counters(
                "are behind a stored task's sequence".into()
            ))
        );
        b.delete(COUNTERS).unwrap();
        let refused = TaskStore::open(Box::new(b.clone()), Arc::new(SystemClock)).err();
        assert_eq!(
            refused.map(|e| e.to_string()),
            Some("task counters are missing beside stored tasks".into())
        );
        b.put(COUNTERS, &counters);
        assert!(TaskStore::open(Box::new(b.clone()), Arc::new(SystemClock)).is_ok());
    }

    #[test]
    fn an_empty_store_opens_with_unreadable_counters() {
        let b = MemTaskBlobs::default();
        b.put(COUNTERS, b"\xff");
        let store = open_mem(&b);
        let id = by_uid(&store, "one");
        assert_eq!(store.record(&id).unwrap().seq, 1);
    }

    #[test]
    fn an_unlistable_store_refuses_open_and_an_unmovable_record_refuses_settle() {
        let b = MemTaskBlobs::default();
        by_uid(&open_mem(&b), "a");
        b.put("junk", b"x");
        let store = open_mem(&b);
        let found = store.take_boot_findings();
        b.fail(Some(Fail::Every));
        assert_eq!(
            TaskStore::open(Box::new(b.clone()), Arc::new(SystemClock)).err(),
            Some(StoreError::Io("sentinel-628-write-refused".into()))
        );
        assert!(store.settle(&found[0]).is_err());
        assert!(b.has("junk"));
        assert!(b.load("absent").is_err());
    }

    #[test]
    fn a_record_naming_an_invalid_agent_does_not_decode() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b);
        let id = by_uid(&store, "a");
        let plain = b.load(&name_of(&id)).unwrap();
        let mut v: ciborium::Value = ciborium::from_reader(plain.as_slice()).unwrap();
        for (k, val) in v.as_map_mut().unwrap() {
            if k.as_text() == Some("agent") {
                *val = ciborium::Value::Text("Not An Agent".into());
            }
        }
        let mut bad = Vec::new();
        ciborium::into_writer(&v, &mut bad).unwrap();
        b.put(&name_of(&id), &bad);
        assert_eq!(
            open_mem(&b).take_boot_findings(),
            vec![BootFinding::Quarantined {
                name: name_of(&id),
                why: "the record does not decode".into(),
            }]
        );
    }

    #[test]
    fn removing_an_absent_record_from_the_directory_is_done() {
        let t = tmp();
        let uid = nix::unistd::geteuid().as_raw();
        let blobs = DirBlobs::open(t.path(), uid, key(), TASKS).unwrap();
        assert_eq!(TaskBlobs::delete(&blobs, "absent"), Ok(()));
        TaskBlobs::save(&blobs, "there", b"x").unwrap();
        assert_eq!(TaskBlobs::delete(&blobs, "there"), Ok(()));
        assert!(TaskBlobs::load(&blobs, "there").is_err());
    }

    #[test]
    fn a_purged_task_leaves_the_directory() {
        let t = tmp();
        let store = open_dir(t.path()).unwrap();
        let id = mint(&store).unwrap().task.task_id;
        let file = t.path().join(format!("{id}.task"));
        assert!(file.is_file());
        store.purge_agent(&hobi());
        assert!(!file.exists());
    }

    #[test]
    fn the_system_clock_reads_seconds_since_the_epoch() {
        assert!(SystemClock.now_secs() > 1_700_000_000);
    }

    #[test]
    fn a_store_error_reads_as_its_cause() {
        assert_eq!(StoreError::Io("disk".into()).to_string(), "disk");
    }

    #[test]
    fn the_state_directory_line_names_tasks() {
        let unit = include_str!("../../../packaging/common/maknaed.service");
        let lines: Vec<&str> = unit.lines().map(str::trim).collect();
        let want = "StateDirectory=maknae maknae/conversations maknae/tasks";
        assert_eq!(lines.iter().filter(|l| **l == want).count(), 1);
        assert_eq!(maknae_config::state::TASKS_DIR, "tasks");
    }
}
