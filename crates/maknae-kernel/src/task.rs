//! The in-kernel task store and the `session.task` submission path (#609).
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use maknae_audit_append::AuditEmit;
use maknae_config::AgentId;
use maknae_proto::{
    SecretText, SignedTask, TaskClose, TaskId, TaskObject, TaskReportPage, TaskState,
    TaskSubmission, TaskView, Tasker,
};
use maknae_security::Authorizer;

use crate::enrollment::{EnrollmentView, Load};
use crate::task_store::{
    encode, name_of, ordinal_key, BootFinding, Clock, Counters, Hot, RootTasker, StoreError,
    TaskBlobs, TaskRecord, CLAIM_LEASE, COUNTERS, REPORT_HOLD,
};

pub const MAX_LIVE_TASKS_PER_AGENT: usize = 256;
pub const MAX_LIVE_TASKS_PER_TASKER_PER_AGENT: usize = 32;
pub const MAX_HELD_REPORTS_PER_TASKER: usize = 256;
pub const MAX_FOLLOW_UPS_PER_TASK: usize = 32;
const RETRY_FIRST_SECS: u32 = 1;
const RETRY_MAX_SECS: u32 = 60;
const MOVED: &str = "not done: the queue changed during the claim";
const DUE_A_HOLD: &str = "not done: the task is due a hold";
const CONTAINED: &str = "the tasker, the root of its chain or the agent is contained";

/// A queued task whose tasker's standing was found good, and the policy load it was
/// found good on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoodStanding {
    pub task: TaskId,
    pub load: Load,
}

/// The trail's reason for a hold.
pub(crate) fn held_reason(who: Contained, agent: &AgentId) -> String {
    match who {
        Contained::Tasker => "task held: tasker contained".into(),
        Contained::Root => "task held: root contained".into(),
        Contained::Agent => format!("task held: agent {} contained", agent.as_str()),
    }
}

/// Who, of `rec`'s tasker, root and agent, the view holds contained.
fn contained_in(view: &dyn EnrollmentView, rec: &TaskRecord) -> Option<Contained> {
    let of = |t: &Tasker| match t {
        Tasker::Uid(uid) | Tasker::Agent { uid, .. } => Some(*uid),
        Tasker::Remote(_) => None,
    };
    let root = match &rec.root {
        RootTasker::Person { uid } => Some(*uid),
        RootTasker::Agent { agent } => AgentId::parse(agent)
            .ok()
            .and_then(|agent| view.agent_uid(&agent)),
    };
    let contained = |uid: u32| view.contained(uid);
    if of(&rec.tasker).is_some_and(contained) {
        Some(Contained::Tasker)
    } else if root.is_some_and(contained) {
        Some(Contained::Root)
    } else if open(rec) && contained(rec.agent_uid) {
        Some(Contained::Agent)
    } else {
        None
    }
}

/// Why a task is due an act of the kernel's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DueFor {
    Close(TaskClose),
    Expiry,
    Hold(Contained),
}

/// Who is contained, for a task that is held: its agent, the tasker who gave it, or the
/// person or agent at the root of its chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Contained {
    Tasker,
    Root,
    Agent,
}

/// A close or an expiry the kernel records before it asks the store to perform it.
/// `recorded` is true once this process has performed it in memory, so recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Due {
    pub task: TaskId,
    /// The agent the task was given to.
    pub agent: AgentId,
    pub tasker: Tasker,
    pub parent: Option<TaskId>,
    pub why: DueFor,
    pub recorded: bool,
}

/// What the store did, or could not do, outside any request; the kernel records each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// The disk may not hold `task` as memory does; every later store write retries it.
    Owed {
        task: TaskId,
        why: String,
    },
    Settled {
        task: TaskId,
    },
    /// An unconfirmed record that stays on disk until the next start discards it.
    Left {
        task: TaskId,
        why: String,
    },
    /// A confirm that outlived its submission, and how it ended.
    Late {
        task: TaskId,
        tasker: Tasker,
        failed: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Claimed {
    Delivered {
        signed: Arc<SignedTask>,
        partition: String,
    },
    Idle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Heartbeat {
    FollowUps {
        task: TaskId,
        tasker: Tasker,
        from: u32,
        items: Vec<SecretText>,
    },
    Closed(TaskView),
    Idle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskRefusal {
    Schema(String),
    Denied(String),
    AtCapacity { agent: String },
    Unknown,
    OtherAgent,
    ParentNotHeld,
    AgentGone,
    Random,
    Audit(String),
    Unsigned,
    Store(String),
    CursorAhead,
    Finished,
    TooLong,
    TaskerLive { agent: String },
    TaskerHeld,
    FollowUps,
    NotWorking,
    Unavailable(String),
}

impl std::fmt::Display for TaskRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskRefusal::Schema(why) => write!(f, "task refused: {why}"),
            TaskRefusal::Denied(why) => f.write_str(why),
            TaskRefusal::AtCapacity { agent } => write!(
                f,
                "agent {agent} holds {MAX_LIVE_TASKS_PER_AGENT} live tasks; no new task is taken"
            ),
            TaskRefusal::Unknown => f.write_str("no such task"),
            TaskRefusal::OtherAgent => f.write_str("the task belongs to another agent"),
            TaskRefusal::ParentNotHeld => {
                f.write_str("the cited task is not held by the submitting agent")
            }
            TaskRefusal::AgentGone => f.write_str("the target agent is no longer enrolled"),
            TaskRefusal::Random => f.write_str("no task id could be drawn"),
            TaskRefusal::Audit(why) => write!(f, "the task was not audited: {why}"),
            TaskRefusal::Unsigned => f.write_str("the task could not be signed"),
            TaskRefusal::Store(why) => write!(f, "the task store did not write: {why}"),
            TaskRefusal::CursorAhead => f.write_str("cursor_ahead"),
            TaskRefusal::Finished => f.write_str("the task has already reported or closed"),
            TaskRefusal::TooLong => f.write_str("the text exceeds prompt_max_bytes"),
            TaskRefusal::TaskerLive { agent } => write!(
                f,
                "the tasker holds {MAX_LIVE_TASKS_PER_TASKER_PER_AGENT} live tasks with agent {agent}"
            ),
            TaskRefusal::TaskerHeld => write!(
                f,
                "the tasker's live tasks and held reports reach {MAX_HELD_REPORTS_PER_TASKER}"
            ),
            TaskRefusal::FollowUps => write!(
                f,
                "the task holds {MAX_FOLLOW_UPS_PER_TASK} follow-ups or prompt_max_bytes of them"
            ),
            TaskRefusal::NotWorking => f.write_str("the task is not working"),
            TaskRefusal::Unavailable(why) => f.write_str(why),
        }
    }
}

/// Signs each task the kernel authorizes. `current_leaf` is the SHA-256 of the
/// current signing leaf's DER.
pub trait TaskSigner: Send + Sync {
    fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal>;
    fn current_leaf(&self) -> Option<[u8; 32]>;
}

/// Signs with the kernel's current `plane/kernel` leaf.
pub struct PlaneSigner(pub Arc<maknae_vault::PlaneClient>);

impl TaskSigner for PlaneSigner {
    fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal> {
        signed_by(self.0.current_identity().as_ref(), task)
    }
    fn current_leaf(&self) -> Option<[u8; 32]> {
        leaf_of(self.0.current_identity().as_ref())
    }
}

/// Signs nothing: a fixed placeholder signature, for stores no agent verifies.
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub struct UnverifiedSigner;

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl TaskSigner for UnverifiedSigner {
    fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal> {
        Ok(SignedTask {
            task,
            signature: maknae_proto::TaskSignature {
                alg: "unverified".into(),
                leaf: maknae_proto::Bytes::new(vec![0].into()),
                chain: Vec::new(),
                sig: maknae_proto::Bytes::new(vec![0].into()),
            },
        })
    }
    fn current_leaf(&self) -> Option<[u8; 32]> {
        None
    }
}

fn signed_by(
    identity: Option<&maknae_vault::PlaneIdentity>,
    task: TaskObject,
) -> Result<SignedTask, TaskRefusal> {
    let identity = identity.ok_or(TaskRefusal::Unsigned)?;
    maknae_vault::task_sig::sign_task(identity, task).map_err(|_| TaskRefusal::Unsigned)
}

fn leaf_of(identity: Option<&maknae_vault::PlaneIdentity>) -> Option<[u8; 32]> {
    maknae_vault::task_sig::identity_fingerprint(identity?).ok()
}

#[derive(Default)]
struct Held {
    tasks: BTreeMap<TaskId, TaskRecord>,
    hot: HashMap<TaskId, Hot>,
    generations: BTreeMap<AgentId, u64>,
    enrolled: BTreeMap<AgentId, u32>,
    issued: Counters,
    boot: Vec<BootFinding>,
    /// Gone from `tasks`, yet the disk may read them confirmed: each is held marked
    /// pending until a synced write of it, or a synced unlink.
    exposed: BTreeMap<TaskId, TaskRecord>,
    /// Stored tasks whose disk copy may differ from memory, until a synced write.
    stale: BTreeSet<TaskId>,
    /// The owed id that last failed; the next drain starts after it.
    stuck: Option<TaskId>,
    /// Open tasks no agent may be handed or act on any more, each with the close it is due.
    closing: BTreeMap<TaskId, TaskClose>,
    /// Marked tasks whose close the kernel has recorded, each with the variant recorded.
    recorded: BTreeMap<TaskId, TaskClose>,
    /// Tasks of a contained tasker or agent, due a hold: none is handed out, acted on,
    /// closed, expired or removed any more.
    holding: BTreeMap<TaskId, Contained>,
    /// Marked tasks whose hold the kernel has recorded.
    hold_said: BTreeSet<TaskId>,
    /// The submission sequence of the close the disk last refused; `due` starts after it.
    refused_close: Option<u64>,
    /// Agents whose exposed records the next writer retries whatever the drain's order.
    purged: BTreeSet<AgentId>,
    notices: Vec<Notice>,
    /// Ids a notice has called owed, until one calls them settled.
    owed_said: BTreeSet<TaskId>,
}

impl Held {
    fn generation(&self, agent: &AgentId) -> u64 {
        self.generations.get(agent).copied().unwrap_or(0)
    }

    fn live(&self, id: &TaskId) -> Option<&TaskRecord> {
        self.tasks.get(id).filter(|r| !r.pending)
    }

    fn note(&mut self, notice: Notice) {
        self.notices.push(notice);
    }

    fn unmark(&mut self, id: &TaskId) {
        self.closing.remove(id);
        self.recorded.remove(id);
    }

    fn owe(&mut self, id: &TaskId, why: String) {
        if self.owed_said.insert(*id) {
            self.note(Notice::Owed { task: *id, why });
        }
    }

    /// A recorded close or hold stays owed until it is itself stored.
    fn proven(&mut self, id: &TaskId) {
        let recorded = self.recorded.contains_key(id) || self.hold_said.contains(id);
        if !recorded && self.owed_said.remove(id) {
            self.note(Notice::Settled { task: *id });
        }
    }

    /// A task `agent` may still be handed or act on: its own, under this uid, with no
    /// close owed.
    fn held_by(&self, id: &TaskId, agent: &AgentId, uid: u32) -> Option<&TaskRecord> {
        self.live(id).filter(|r| {
            r.agent == *agent
                && r.agent_uid == uid
                && !self.closing.contains_key(id)
                && !self.holding.contains_key(id)
        })
    }

    /// Marks for a hold every task the view's contained subjects gave or are the root of,
    /// whatever its state, and every open task a contained agent holds. A submission not
    /// yet confirmed is marked too, so its confirm stores it held.
    fn hold_contained(&mut self, view: &dyn EnrollmentView) {
        let due: Vec<(TaskId, Contained)> = self
            .tasks
            .iter()
            .filter(|(id, r)| r.state != TaskState::Held && !self.holding.contains_key(id))
            .filter_map(|(id, r)| Some((*id, contained_in(view, r)?)))
            .collect();
        self.holding.extend(due);
    }

    /// Bumps the agent's generation, so a mint racing it is refused, and owes a close to
    /// each of its open tasks that `gone` selects.
    fn unenroll(&mut self, agent: &AgentId, gone: impl Fn(&TaskRecord) -> bool) {
        let g = self.generations.entry(agent.clone()).or_insert(0);
        *g = g.wrapping_add(1);
        let owed: Vec<TaskId> = self
            .tasks
            .iter()
            .filter(|(_, t)| t.agent == *agent && open(t) && gone(t))
            .map(|(id, _)| *id)
            .collect();
        for id in owed {
            self.closing.insert(id, TaskClose::AgentGone);
        }
        self.purged.insert(agent.clone());
    }

    fn expose(&mut self, mut rec: TaskRecord) {
        rec.pending = true;
        rec.removing = true;
        self.exposed.insert(rec.signed.task.task_id, rec);
    }

    /// Out of memory; a record the disk may read confirmed becomes exposed.
    /// [`Held::take_back`], unless the task is held or due a hold: read and taken in one
    /// section, so a hold marked a moment earlier is never missed. False when it is left.
    fn take_back_unless_held(&mut self, id: &TaskId) -> bool {
        let held = self.holding.contains_key(id)
            || self
                .tasks
                .get(id)
                .is_some_and(|r| r.state == TaskState::Held);
        if !held {
            self.take_back(id);
        }
        !held
    }

    fn take_back(&mut self, id: &TaskId) {
        self.hot.remove(id);
        if let Some(rec) = self.tasks.remove(id).filter(|r| !r.pending) {
            self.expose(rec);
        }
    }
}

/// The agent's generation and enrolled uid, as read before the decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enrolled {
    pub generation: u64,
    pub agent_uid: u32,
}

/// Tasks, written through to `blobs` before any change is visible in memory. Every change
/// is serialized by `writer`; `held` is locked only to read and to swap, never across I/O,
/// so a reader never waits behind an fsync.
pub struct TaskStore {
    held: Mutex<Held>,
    writer: Mutex<()>,
    abandoned: Mutex<Vec<TaskId>>,
    #[cfg(test)]
    scripted: Mutex<Vec<[u8; 16]>>,
    blobs: Box<dyn TaskBlobs>,
    clock: Arc<dyn Clock>,
}

enum Placed {
    Stored,
    Collided,
}

impl TaskStore {
    #[cfg(any(test, feature = "hermetic-test-seam"))]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::open(
            Box::new(crate::task_store::MemTaskBlobs::default()),
            Arc::new(crate::task_store::SystemClock),
        )
        .expect("an empty store opens")
    }

    /// Loads every record; a pending or unreadable one is left out of memory and named in
    /// [`TaskStore::take_boot_findings`], and every `Working` lease runs from now.
    pub fn open(blobs: Box<dyn TaskBlobs>, clock: Arc<dyn Clock>) -> Result<Self, StoreError> {
        let loaded = crate::task_store::load(&*blobs)?;
        let lease = clock.now_secs() + CLAIM_LEASE.as_secs() as i64;
        let mut held = Held {
            issued: loaded.counters,
            boot: loaded.findings,
            ..Held::default()
        };
        for rec in loaded.records {
            let lease_until = match rec.state {
                TaskState::Working => lease,
                TaskState::Queued | TaskState::Reported | TaskState::Closed | TaskState::Held => 0,
            };
            let id = rec.signed.task.task_id;
            held.hot.insert(
                id,
                Hot {
                    actions: rec.actions,
                    last_action: rec.last_action,
                    lease_until,
                    ..Hot::default()
                },
            );
            held.tasks.insert(id, rec);
        }
        Ok(Self {
            held: Mutex::new(held),
            writer: Mutex::new(()),
            abandoned: Mutex::new(Vec::new()),
            #[cfg(test)]
            scripted: Mutex::new(Vec::new()),
            blobs,
            clock,
        })
    }

    /// What boot must record before it calls [`TaskStore::settle`] on each.
    pub fn take_boot_findings(&self) -> Vec<BootFinding> {
        std::mem::take(&mut self.held().boot)
    }

    /// Removes a discarded record, or moves an unreadable one aside.
    pub fn settle(&self, finding: &BootFinding) -> Result<(), StoreError> {
        match finding {
            BootFinding::Discarded { name, .. } => self.blobs.delete(name),
            BootFinding::Quarantined { name, .. } => self.blobs.quarantine(name),
        }
    }

    /// A write that landed unsynced is undone to `prior`. It is refused only when the
    /// undo is synced; otherwise the outcome is unknown. A replaced record is stale from
    /// before the write until a synced one, so a write that unwinds is still rewritten.
    fn write(&self, rec: &TaskRecord, prior: Option<&TaskRecord>) -> Result<(), TaskRefusal> {
        let id = rec.signed.task.task_id;
        let name = name_of(&id);
        let plain = encode(rec).map_err(store)?;
        if prior.is_some() {
            self.held().stale.insert(id);
        }
        let why = match self.blobs.save(&name, &plain) {
            Ok(()) => {
                let mut held = self.held();
                held.stale.remove(&id);
                held.proven(&id);
                return Ok(());
            }
            Err(StoreError::NotDurable(why)) => why,
            Err(e @ (StoreError::Io(_) | StoreError::Counters(_))) => return Err(store(e)),
        };
        let undone = match prior {
            None => self.blobs.delete(&name),
            Some(p) => encode(p).and_then(|b| self.blobs.save(&name, &b)),
        };
        match (undone, prior) {
            (Ok(()), _) => {
                self.held().stale.remove(&id);
                Err(TaskRefusal::Store(why))
            }
            (Err(e), None) => {
                self.held().note(Notice::Left {
                    task: id,
                    why: e.to_string(),
                });
                Err(TaskRefusal::Store(why))
            }
            (Err(e), Some(_)) => {
                self.held()
                    .owe(&id, format!("written unsynced ({why}), not undone ({e})"));
                Err(TaskRefusal::Unavailable(format!("outcome unknown: {why}")))
            }
        }
    }

    /// The high-water marks are durable before a value is used. The caller holds the writer.
    fn issue(&self, edit: impl FnOnce(&mut Counters) -> Option<u64>) -> Result<u64, TaskRefusal> {
        let mut next = self.held().issued.clone();
        let issued =
            edit(&mut next).ok_or(TaskRefusal::Store("the sequence is exhausted".into()))?;
        let plain = encode(&next).map_err(store)?;
        self.blobs.save(COUNTERS, &plain).map_err(store)?;
        self.held().issued = next;
        Ok(issued)
    }

    /// The store-wide sequence and the tasker's own submission ordinal.
    fn issue_submission(&self, tasker: &Tasker) -> Result<(u64, u64), TaskRefusal> {
        let mut seq = 0;
        let tseq = self.issue(|c| {
            seq = c.seq.checked_add(1)?;
            c.seq = seq;
            let o = c.taskers.entry(ordinal_key(tasker)).or_default();
            o.seq = o.seq.checked_add(1)?;
            Some(o.seq)
        })?;
        Ok((seq, tseq))
    }

    fn issue_report(&self, tasker: &Tasker) -> Result<u64, TaskRefusal> {
        self.issue(|c| {
            let o = c.taskers.entry(ordinal_key(tasker)).or_default();
            o.rseq = o.rseq.checked_add(1)?;
            Some(o.rseq)
        })
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A task id: the next scripted one in a test, else a fresh random draw.
    fn next_id(&self) -> Result<[u8; 16], TaskRefusal> {
        #[cfg(test)]
        if let Some(id) = self
            .scripted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
        {
            return Ok(id);
        }
        draw_id()
    }

    /// The write path's own lock: held across I/O, never by a reader. Whoever takes it
    /// first withdraws every submission abandoned since.
    fn writing(&self) -> std::sync::MutexGuard<'_, ()> {
        let w = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        self.drain_abandoned();
        w
    }

    /// Retries what is owed, starting after the id that failed last and stopping at the
    /// first that fails now, then takes each queued id in hand; one in hand when the drain
    /// unwinds is put back.
    fn drain_abandoned(&self) {
        let queue = || {
            self.abandoned
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        };
        self.drop_marks();
        let taken_back = self.settle_owed();
        self.settle_purged();
        let rounds = queue().len();
        for _ in 0..rounds {
            let Some(id) = queue().pop() else {
                break;
            };
            let mut hand = PutBack {
                store: self,
                id: Some(id),
            };
            if !taken_back.contains(&id) {
                self.withdraw_locked(&id);
            }
            hand.id = None;
        }
    }

    /// Withdraws each marked record that was never confirmed, and forgets each mark whose
    /// task is no longer open.
    fn drop_marks(&self) {
        let (unconfirmed, finished): (Vec<TaskId>, Vec<TaskId>) = {
            let held = self.held();
            let pending = |id: &&TaskId| held.tasks.get(id).is_some_and(|r| r.pending);
            (
                held.closing.keys().filter(pending).copied().collect(),
                held.closing
                    .keys()
                    .filter(|id| !held.tasks.get(id).is_some_and(open))
                    .copied()
                    .collect(),
            )
        };
        for id in &finished {
            self.held().unmark(id);
        }
        let mut held = self.held();
        let settled: Vec<TaskId> = held
            .holding
            .keys()
            .filter(|id| {
                held.tasks
                    .get(id)
                    .is_none_or(|r| r.state == TaskState::Held)
            })
            .copied()
            .collect();
        for id in &settled {
            held.holding.remove(id);
            held.hold_said.remove(id);
        }
        drop(held);
        for id in &unconfirmed {
            self.held().unmark(id);
            self.withdraw_locked(id);
        }
    }

    /// Retries each exposed record of an agent purged since the last writer, once.
    fn settle_purged(&self) {
        let owed: Vec<TaskId> = {
            let mut held = self.held();
            let purged = std::mem::take(&mut held.purged);
            held.exposed
                .iter()
                .filter(|(_, r)| purged.contains(&r.agent))
                .map(|(id, _)| *id)
                .collect()
        };
        for id in owed {
            self.withdraw_locked(&id);
        }
    }

    /// The exposed ids it tried to take back.
    fn settle_owed(&self) -> Vec<TaskId> {
        let (mut owed, after) = {
            let held = self.held();
            let owed: BTreeSet<TaskId> = held
                .exposed
                .keys()
                .chain(held.stale.iter())
                .copied()
                .collect();
            (owed.into_iter().collect::<Vec<_>>(), held.stuck)
        };
        let first = owed.partition_point(|id| Some(*id) <= after);
        owed.rotate_left(first);
        let mut taken_back = Vec::new();
        for id in owed {
            if self.held().exposed.contains_key(&id) {
                taken_back.push(id);
            }
            let settled = self.settle_one(&id);
            let mut held = self.held();
            match (settled, held.stuck == Some(id)) {
                (true, true) => held.stuck = None,
                (true, false) => {}
                (false, _) => {
                    held.stuck = Some(id);
                    break;
                }
            }
        }
        taken_back
    }

    /// An exposed record is taken back; a stale task is written as memory holds it.
    fn settle_one(&self, id: &TaskId) -> bool {
        if self.held().exposed.contains_key(id) {
            return self.withdraw_locked(id);
        }
        let rec = self.held().tasks.get(id).cloned();
        let written = rec.map_or(Ok(()), |rec| {
            encode(&rec).and_then(|plain| self.blobs.save(&name_of(id), &plain))
        });
        let mut held = self.held();
        match written {
            Ok(()) => {
                held.stale.remove(id);
                held.proven(id);
                true
            }
            Err(why) => {
                held.owe(id, format!("not written as memory holds it: {why}"));
                false
            }
        }
    }

    /// Queues a submission's record for withdrawal by the next writer; never waits.
    pub(crate) fn abandon(&self, id: TaskId) {
        let mut queue = self
            .abandoned
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !queue.contains(&id) {
            queue.push(id);
        }
    }

    pub fn generation(&self, agent: &AgentId) -> u64 {
        self.held().generation(agent)
    }

    /// Marks every open task of `agent`, then closes what is due with no record made.
    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn purge_agent(&self, agent: &AgentId) -> Vec<Due> {
        self.held().unenroll(agent, |_| true);
        self.close_all_due()
    }

    /// Every due close and expiry, performed as the kernel would after recording each;
    /// what it returns is what the kernel would have recorded.
    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn close_all_due(&self) -> Vec<Due> {
        let mut said = Vec::new();
        for _ in 0..1024 {
            let batch = self.due(64);
            said.extend(batch.iter().filter(|d| !d.recorded).cloned());
            if batch.is_empty() || self.perform(&batch) == 0 {
                self.pass();
                return said;
            }
        }
        panic!("the sweep did not settle");
    }

    /// [`TaskStore::close_all_due`], then the counters.
    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn sweep(&self) -> Vec<Due> {
        let said = self.close_all_due();
        self.store_counters();
        said
    }

    /// The closes and expiries now due, oldest submission first, at most `limit`. Reads
    /// memory only: a marked open task, a working task whose lease has lapsed, and a
    /// report held past `REPORT_HOLD`.
    pub fn due(&self, limit: usize) -> Vec<Due> {
        let now = self.clock.now_secs();
        let hold = REPORT_HOLD.as_secs() as i64;
        let held = self.held();
        let why = |id: &TaskId, r: &TaskRecord| {
            let lapsed = || held.hot.get(id).is_none_or(|h| h.lease_until < now);
            match (
                held.recorded.get(id).or(held.closing.get(id)),
                r.state,
                &r.report,
            ) {
                _ if r.pending || r.state == TaskState::Held => None,
                _ if held.holding.contains_key(id) => {
                    held.holding.get(id).copied().map(DueFor::Hold)
                }
                (Some(close), TaskState::Queued | TaskState::Working, _) => {
                    Some(DueFor::Close(*close))
                }
                (None, TaskState::Working, _) if lapsed() => {
                    Some(DueFor::Close(TaskClose::AgentLost))
                }
                (_, _, Some((_, at))) if now.saturating_sub(*at) >= hold => Some(DueFor::Expiry),
                (_, _, _) => None,
            }
        };
        let mut due: Vec<(u64, Due)> = held
            .tasks
            .iter()
            .filter_map(|(id, r)| {
                let why = why(id, r)?;
                let due = Due {
                    task: *id,
                    agent: r.agent.clone(),
                    tasker: r.tasker.clone(),
                    parent: r.parent,
                    why,
                    recorded: match why {
                        DueFor::Hold(_) => held.hold_said.contains(id),
                        DueFor::Close(_) => held.recorded.contains_key(id),
                        DueFor::Expiry => false,
                    },
                };
                Some((r.seq, due))
            })
            .collect();
        due.sort_by_key(|(seq, _)| *seq);
        let first = due.partition_point(|(seq, _)| Some(*seq) <= held.refused_close);
        due.rotate_left(first);
        due.into_iter().take(limit).map(|(_, d)| d).collect()
    }

    /// Performs what the kernel has recorded: each task still due is marked, so no agent
    /// is handed it or acts on it again, then closed or removed on disk until the disk
    /// first refuses. A task is `Closed` in memory only once its record is synced. The
    /// count is of those done.
    pub fn perform(&self, due: &[Due]) -> usize {
        let _w = self.writing();
        let now = self.clock.now_secs();
        let hold = REPORT_HOLD.as_secs() as i64;
        let (mut done, mut disk) = (0, true);
        for d in due {
            let still = {
                let mut held = self.held();
                let lapsed = held.hot.get(&d.task).is_none_or(|h| h.lease_until < now);
                let rec = held.live(&d.task);
                let holding = held.holding.contains_key(&d.task);
                let still = match (d.why, held.closing.get(&d.task)) {
                    (DueFor::Hold(_), _) => holding,
                    (DueFor::Close(_) | DueFor::Expiry, _) if holding => false,
                    (DueFor::Close(_), Some(_)) => rec.is_some_and(open),
                    (DueFor::Close(TaskClose::AgentLost), None) => {
                        rec.is_some_and(|r| r.state == TaskState::Working) && lapsed
                    }
                    (
                        DueFor::Close(
                            TaskClose::AgentGone
                            | TaskClose::Stopped
                            | TaskClose::Dropped
                            | TaskClose::Withdrawn,
                        ),
                        None,
                    ) => false,
                    (DueFor::Expiry, _) => rec
                        .filter(|r| r.state != TaskState::Held)
                        .and_then(|r| r.report.as_ref())
                        .is_some_and(|(_, at)| now.saturating_sub(*at) >= hold),
                };
                match (still, d.why) {
                    (true, DueFor::Close(close)) => {
                        held.closing.insert(d.task, close);
                        held.recorded.insert(d.task, close);
                    }
                    (true, DueFor::Hold(_)) => {
                        held.hold_said.insert(d.task);
                    }
                    (true, DueFor::Expiry) | (false, _) => {}
                }
                still
            };
            match (still, d.why, disk) {
                (false, _, _) => {}
                (true, DueFor::Close(_), true) => {
                    disk = self.close_durably(&d.task);
                    done += usize::from(disk);
                }
                (true, DueFor::Close(_) | DueFor::Hold(_), false) => {}
                (true, DueFor::Hold(_), true) => {
                    disk = self.hold_durably(&d.task);
                    done += usize::from(disk);
                }
                (true, DueFor::Expiry, on_disk) => {
                    if self.held().take_back_unless_held(&d.task) {
                        done += 1;
                        if on_disk {
                            disk = self.withdraw_locked(&d.task);
                        }
                    }
                }
            }
        }
        done
    }

    /// Writes the marked task `id` closed, under a report ordinal issued for this attempt,
    /// so no close lands below a cursor its tasker has already acknowledged; memory
    /// follows only a synced write. The caller holds the writer.
    fn close_durably(&self, id: &TaskId) -> bool {
        let (prior, close, hot) = {
            let held = self.held();
            let (Some(prior), Some(close)) = (held.live(id).cloned(), held.recorded.get(id)) else {
                return true;
            };
            let hot = held.hot.get(id).copied().unwrap_or_default();
            (prior, *close, hot)
        };
        let written = self.issue_report(&prior.tasker).and_then(|rseq| {
            let mut next = prior.clone();
            next.state = TaskState::Closed;
            next.close = Some(close);
            next.rseq = Some(rseq);
            next.report = Some((SecretText(String::new().into()), self.clock.now_secs()));
            next.actions = hot.actions;
            next.last_action = hot.last_action;
            self.write(&next, Some(&prior)).map(|()| next)
        });
        let mut held = self.held();
        match written {
            Ok(next) => {
                if held.refused_close == Some(next.seq) {
                    held.refused_close = None;
                }
                held.tasks.insert(*id, next);
                held.unmark(id);
                held.proven(id);
                true
            }
            Err(why) => {
                held.refused_close = Some(prior.seq);
                held.owe(id, format!("the close is not stored: {why}"));
                false
            }
        }
    }

    /// Writes the marked task `id` held, keeping the state it was in; memory follows only
    /// a synced write. The caller holds the writer.
    fn hold_durably(&self, id: &TaskId) -> bool {
        let (prior, hot) = {
            let held = self.held();
            let Some(prior) = held.live(id).cloned() else {
                return true;
            };
            (prior, held.hot.get(id).copied().unwrap_or_default())
        };
        let mut next = prior.clone();
        next.held_from = Some(prior.state);
        next.state = TaskState::Held;
        next.actions = hot.actions;
        next.last_action = hot.last_action;
        let written = self.write(&next, Some(&prior));
        let mut held = self.held();
        match written {
            Ok(()) => {
                held.tasks.insert(*id, next);
                held.holding.remove(id);
                held.hold_said.remove(id);
                held.unmark(id);
                held.proven(id);
                true
            }
            Err(why) => {
                held.owe(id, format!("the hold is not stored: {why}"));
                false
            }
        }
    }

    /// Stores each working task's action counters that changed, until the disk first
    /// refuses.
    pub fn store_counters(&self) {
        let _w = self.writing();
        let counted: Vec<TaskId> = {
            let held = self.held();
            held.tasks
                .iter()
                .filter(|(id, r)| {
                    r.state == TaskState::Working
                        && !r.pending
                        && held.hot.get(id).is_some_and(|h| {
                            (h.actions, h.last_action) != (r.actions, r.last_action)
                        })
                })
                .map(|(id, _)| *id)
                .collect()
        };
        for id in &counted {
            let (Some(prior), Some(hot)) = (self.record(id), self.hot(id)) else {
                continue;
            };
            let mut next = prior.clone();
            next.actions = hot.actions;
            next.last_action = hot.last_action;
            if self.write(&next, Some(&prior)).is_err() {
                break;
            }
            self.held().tasks.insert(*id, next);
        }
    }

    /// One writer's pass: every owed close, removal and rewrite is tried.
    pub fn pass(&self) {
        drop(self.writing());
    }

    /// Without the writer and without I/O: every agent whose (id, uid) the view no longer
    /// holds as last seen has its generation bumped, and each of its open tasks bound to
    /// another uid is marked, due a close as `AgentGone`. Staleness is read from open tasks
    /// only. Every task of a contained tasker, and every open task of a contained agent, is
    /// marked for a hold.
    pub fn mark_unenrolled(&self, view: &dyn EnrollmentView) {
        let mut held = self.held();
        let known: BTreeSet<AgentId> = held
            .enrolled
            .keys()
            .chain(held.tasks.values().filter(|t| open(t)).map(|t| &t.agent))
            .cloned()
            .collect();
        for agent in known {
            let now = view.agent_uid(&agent);
            let stale = held.enrolled.get(&agent).is_some_and(|u| now != Some(*u))
                || held.tasks.iter().any(|(id, t)| {
                    t.agent == agent
                        && open(t)
                        && now != Some(t.agent_uid)
                        && !held.closing.contains_key(id)
                });
            if stale {
                held.unenroll(&agent, |t| now != Some(t.agent_uid));
            }
            match now {
                Some(uid) => held.enrolled.insert(agent, uid),
                None => held.enrolled.remove(&agent),
            };
        }
        held.hold_contained(view);
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn retain_enrolled(&self, view: &dyn EnrollmentView) -> Vec<Due> {
        self.mark_unenrolled(view);
        self.close_all_due()
    }

    /// The agent's generation and enrolled uid, read together before a decision.
    fn observe(&self, view: &dyn EnrollmentView, agent: &AgentId) -> (u64, Option<u32>) {
        let mut held = self.held();
        let uid = view.agent_uid(agent);
        if let Some(u) = uid {
            held.enrolled.entry(agent.clone()).or_insert(u);
        }
        (held.generation(agent), uid)
    }

    /// Signs before storing, outside the store lock; an unsigned task is never stored.
    /// The record is written pending; [`TaskStore::confirm`] makes it visible.
    #[allow(clippy::too_many_arguments)]
    pub fn mint(
        &self,
        signer: &dyn TaskSigner,
        view: &dyn EnrollmentView,
        enrolled: Enrolled,
        tasker: Tasker,
        parent: Option<TaskId>,
        sub: TaskSubmission,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        self.mint_with(
            &mut draw_id,
            signer,
            view,
            enrolled,
            tasker,
            parent,
            sub,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn mint_with(
        &self,
        draw: &mut dyn FnMut() -> Result<[u8; 16], TaskRefusal>,
        signer: &dyn TaskSigner,
        view: &dyn EnrollmentView,
        enrolled: Enrolled,
        tasker: Tasker,
        parent: Option<TaskId>,
        sub: TaskSubmission,
        ticket: Option<&Ticket>,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let agent = target(&sub)?;
        let mut task = TaskObject {
            schema: maknae_proto::TASK_SCHEMA.into(),
            version: maknae_proto::TASK_VERSION,
            task_id: TaskId(draw()?),
            tasker,
            parent,
            agent: sub.agent,
            ask: sub.ask,
            labels: sub.labels,
        };
        for _ in 0..4 {
            let signed = Arc::new(signer.sign(task)?);
            match self.place(view, &agent, enrolled, &signed, ticket)? {
                Placed::Stored => return Ok(signed),
                Placed::Collided => {
                    task = signed.task.clone();
                    task.task_id = TaskId(draw()?);
                }
            }
        }
        Err(TaskRefusal::Random)
    }

    fn place(
        &self,
        view: &dyn EnrollmentView,
        agent: &AgentId,
        enrolled: Enrolled,
        task: &Arc<SignedTask>,
        ticket: Option<&Ticket>,
    ) -> Result<Placed, TaskRefusal> {
        let Enrolled {
            generation,
            agent_uid,
        } = enrolled;
        let _w = self.writing();
        if ticket.is_some_and(Ticket::abandoned) {
            return Err(abandoned());
        }
        if view.agent_uid(agent) != Some(agent_uid) {
            return Err(TaskRefusal::AgentGone);
        }
        let root = {
            let held = self.held();
            if held.generation(agent) != generation {
                return Err(TaskRefusal::AgentGone);
            }
            let live = |t: &&TaskRecord| t.agent == *agent && open(t);
            if held.tasks.values().filter(live).count() >= MAX_LIVE_TASKS_PER_AGENT {
                return Err(TaskRefusal::AtCapacity {
                    agent: agent.as_str().to_string(),
                });
            }
            if held.tasks.contains_key(&task.task.task_id) {
                return Ok(Placed::Collided);
            }
            tasker_room(&held, &task.task.tasker, agent)?;
            root_of(&held, &task.task)?
        };
        let (seq, tseq) = self.issue_submission(&task.task.tasker)?;
        let rec = TaskRecord {
            signed: task.clone(),
            agent: agent.clone(),
            agent_uid,
            tasker: task.task.tasker.clone(),
            root,
            parent: task.task.parent,
            state: TaskState::Queued,
            close: None,
            held_from: None,
            pending: true,
            removing: false,
            seq,
            tseq,
            rseq: None,
            submitted: self.clock.now_secs(),
            claimed: None,
            follow_ups: Vec::new(),
            report: None,
            actions: 0,
            last_action: None,
        };
        self.write(&rec, None)?;
        if let Some(t) = ticket {
            if !t.keep(task.task.task_id) {
                if let Err(e) = self.blobs.delete(&name_of(&task.task.task_id)) {
                    self.held().note(Notice::Left {
                        task: task.task.task_id,
                        why: e.to_string(),
                    });
                }
                return Err(abandoned());
            }
        }
        let mut held = self.held();
        if contained_in(view, &rec).is_some() {
            drop(held);
            if let Err(e) = self.blobs.delete(&name_of(&task.task.task_id)) {
                self.held().note(Notice::Left {
                    task: task.task.task_id,
                    why: e.to_string(),
                });
            }
            return Err(TaskRefusal::Denied(CONTAINED.into()));
        }
        held.hot.insert(task.task.task_id, Hot::default());
        held.tasks.insert(task.task.task_id, rec);
        Ok(Placed::Stored)
    }

    pub fn resolve(
        &self,
        id: &TaskId,
        agent: &AgentId,
        uid: u32,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        handable(&self.held(), id, agent, uid)
    }

    /// Called when a task is handed out (#610), after the same ownership check as `resolve`:
    /// re-signs it outside the store lock when its signing leaf is not the signer's current
    /// one. A task replaced meanwhile is handed out only under the current leaf, after at most
    /// one more signature; otherwise, or without a current leaf or a signature, nothing is.
    pub fn resign_if_stale(
        &self,
        id: &TaskId,
        agent: &AgentId,
        uid: u32,
        signer: &dyn TaskSigner,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let mut held = handable(&self.held(), id, agent, uid)?;
        for _ in 0..2 {
            let current = signer.current_leaf().ok_or(TaskRefusal::Unsigned)?;
            if maknae_vault::task_sig::leaf_fingerprint(&held.signature.leaf.0) == current {
                return Ok(held);
            }
            let fresh = Arc::new(signer.sign(held.task.clone())?);
            let _w = self.writing();
            let prior = {
                let store = self.held();
                let now = handable(&store, id, agent, uid)?;
                if !Arc::ptr_eq(&now, &held) {
                    held = now;
                    continue;
                }
                store.tasks.get(id).cloned()
            };
            if let Some(prior) = prior {
                let mut next = prior.clone();
                next.signed = fresh.clone();
                self.write(&next, Some(&prior))?;
                self.held().tasks.insert(*id, next);
            }
            return Ok(fresh);
        }
        Err(TaskRefusal::Unsigned)
    }

    /// Records the report or the close and issues its `rseq`, under the writer, so no
    /// reader sees one `rseq` before a smaller one.
    pub fn publish_report(
        &self,
        id: &TaskId,
        text: SecretText,
        close: Option<TaskClose>,
    ) -> Result<u64, TaskRefusal> {
        let _w = self.writing();
        let rec = self.publish(id, text, close, |_| Ok(()))?;
        Ok(rec.rseq.unwrap_or_default())
    }

    /// The caller holds the writer.
    fn publish(
        &self,
        id: &TaskId,
        text: SecretText,
        close: Option<TaskClose>,
        check: impl FnOnce(&TaskRecord) -> Result<(), TaskRefusal>,
    ) -> Result<TaskRecord, TaskRefusal> {
        let prior = {
            let held = self.held();
            let rec = held.live(id).ok_or(TaskRefusal::Unknown)?;
            check(rec)?;
            match rec.state {
                TaskState::Queued | TaskState::Working if !held.holding.contains_key(id) => {}
                TaskState::Queued
                | TaskState::Working
                | TaskState::Reported
                | TaskState::Closed
                | TaskState::Held => return Err(TaskRefusal::Finished),
            }
            rec.clone()
        };
        let rseq = self.issue_report(&prior.tasker)?;
        let mut next = prior.clone();
        next.state = match close {
            None => TaskState::Reported,
            Some(_) => TaskState::Closed,
        };
        next.close = close;
        next.rseq = Some(rseq);
        next.report = Some((text, self.clock.now_secs()));
        let hot = self.hot(id).unwrap_or_default();
        next.actions = hot.actions;
        next.last_action = hot.last_action;
        self.write(&next, Some(&prior))?;
        self.held().tasks.insert(*id, next.clone());
        Ok(next)
    }

    /// Who gave the stored task `id`, and to which agent.
    pub fn tasker_of(&self, id: &TaskId) -> Option<(Tasker, AgentId)> {
        self.held()
            .live(id)
            .map(|r| (r.tasker.clone(), r.agent.clone()))
    }

    /// Marks the queued task `id` due a close as `Withdrawn`: its tasker may no longer
    /// task the agent. It is not handed out from here on.
    pub fn withdraw_authority(&self, id: &TaskId) {
        let mut held = self.held();
        let queued = held.live(id).is_some_and(|r| r.state == TaskState::Queued);
        if queued && !held.holding.contains_key(id) {
            held.closing.entry(*id).or_insert(TaskClose::Withdrawn);
        }
    }

    /// Whether `agent` holds a working task under `uid`, marked or not.
    pub fn holds_working(&self, agent: &AgentId, uid: u32) -> bool {
        self.held().tasks.values().any(|r| {
            !r.pending && r.state == TaskState::Working && r.agent == *agent && r.agent_uid == uid
        })
    }

    /// The task a claim would hand `agent`: its working task, else its oldest queued one.
    pub fn next_for(&self, agent: &AgentId, uid: u32) -> Option<(TaskId, TaskState)> {
        let guard = self.held();
        let held: &Held = &guard;
        let mine = |state: TaskState| {
            held.tasks
                .iter()
                .filter(move |(id, r)| r.state == state && held.held_by(id, agent, uid).is_some())
                .min_by_key(|(_, r)| r.seq)
                .map(|(id, _)| (*id, state))
        };
        let now = self.clock.now_secs();
        mine(TaskState::Working)
            .or_else(|| mine(TaskState::Queued))
            .filter(|(id, _)| held.hot.get(id).is_none_or(|h| h.retry_after <= now))
    }

    /// Hands `agent` its working task again, or starts its oldest queued one, under the
    /// signer's current leaf. A queued task is started only when it is `decided`, the one
    /// whose tasker's standing the caller has just decided, and only while `view` still
    /// reads the policy load it was decided on; otherwise the answer is idle. Any
    /// refusal leaves the task as it was. One the store or the signer gave holds the task
    /// back from the next claims, for 1 s doubling to 60 s; a hand-out ends that.
    pub fn claim(
        &self,
        agent: &AgentId,
        uid: u32,
        signer: &dyn TaskSigner,
        view: &dyn EnrollmentView,
        decided: Option<&GoodStanding>,
    ) -> Result<Claimed, TaskRefusal> {
        let Some((id, state)) = self.next_for(agent, uid) else {
            return Ok(Claimed::Idle);
        };
        let load = decided.filter(|d| d.task == id).map(|d| (view, &d.load));
        if state == TaskState::Queued && load.is_none() {
            return Ok(Claimed::Idle);
        }
        let handed = self.hand_out(&id, state, agent, uid, signer, load);
        let mut held = self.held();
        let now = self.clock.now_secs();
        if let Some(hot) = held.hot.get_mut(&id) {
            match &handed {
                Ok(_) => (hot.retry_after, hot.retry_secs) = (0, 0),
                Err(TaskRefusal::Unavailable(why)) if why == MOVED => {}
                Err(
                    TaskRefusal::Store(_) | TaskRefusal::Unavailable(_) | TaskRefusal::Unsigned,
                ) => {
                    hot.retry_secs = (hot.retry_secs * 2).clamp(RETRY_FIRST_SECS, RETRY_MAX_SECS);
                    hot.retry_after = now + i64::from(hot.retry_secs);
                }
                Err(_) => {}
            }
        }
        handed
    }

    fn hand_out(
        &self,
        id: &TaskId,
        state: TaskState,
        agent: &AgentId,
        uid: u32,
        signer: &dyn TaskSigner,
        decided_on: Option<(&dyn EnrollmentView, &Load)>,
    ) -> Result<Claimed, TaskRefusal> {
        let id = *id;
        self.resign_if_stale(&id, agent, uid, signer)?;
        let moved = || TaskRefusal::Unavailable(MOVED.into());
        let lease = self.clock.now_secs() + CLAIM_LEASE.as_secs() as i64;
        let delivered = |rec: &TaskRecord| Claimed::Delivered {
            signed: rec.signed.clone(),
            partition: format!(
                "{}/{}",
                crate::partition_authz::TASKS_DIR,
                rec.root.partition()
            ),
        };
        match state {
            TaskState::Working => {
                let mut held = self.held();
                let rec = held
                    .held_by(&id, agent, uid)
                    .filter(|r| r.state == TaskState::Working)
                    .ok_or_else(moved)?;
                let handed = delivered(rec);
                held.hot.entry(id).or_default().lease_until = lease;
                Ok(handed)
            }
            TaskState::Queued => {
                let _w = self.writing();
                if self.next_for(agent, uid) != Some((id, TaskState::Queued)) {
                    return Err(moved());
                }
                if !decided_on.is_some_and(|(view, load)| load.same(&view.load())) {
                    return Ok(Claimed::Idle);
                }
                let prior = self.held().live(&id).cloned().ok_or_else(moved)?;
                let mut next = prior.clone();
                next.state = TaskState::Working;
                next.claimed = Some(self.clock.now_secs());
                self.write(&next, Some(&prior))?;
                let handed = delivered(&next);
                let mut held = self.held();
                held.hot.entry(id).or_default().lease_until = lease;
                held.tasks.insert(id, next);
                match held.closing.contains_key(&id) || held.holding.contains_key(&id) {
                    true => Err(TaskRefusal::AgentGone),
                    false => Ok(handed),
                }
            }
            TaskState::Reported | TaskState::Closed | TaskState::Held => Err(moved()),
        }
    }

    /// The follow-ups after index `seen` on the agent's working task, as many as fit
    /// `budget` bytes and always the first; the lease runs from now. Without a working
    /// task, the agent's most recently claimed one when the kernel or its tasker closed it.
    pub fn heartbeat(&self, agent: &AgentId, uid: u32, seen: u32, budget: usize) -> Heartbeat {
        let now = self.clock.now_secs();
        let mut held = self.held();
        let working = held
            .tasks
            .iter()
            .find(|(id, r)| r.state == TaskState::Working && held.held_by(id, agent, uid).is_some())
            .map(|(id, r)| {
                let mut used = 0usize;
                let items: Vec<SecretText> = r
                    .follow_ups
                    .iter()
                    .skip(seen as usize)
                    .take_while(|f| {
                        let first = used == 0;
                        used = used.saturating_add(f.0.len().max(1));
                        first || used <= budget
                    })
                    .cloned()
                    .collect();
                (*id, r.tasker.clone(), items)
            });
        if let Some((task, tasker, items)) = working {
            held.hot.entry(task).or_default().lease_until = now + CLAIM_LEASE.as_secs() as i64;
            return Heartbeat::FollowUps {
                task,
                tasker,
                from: seen,
                items,
            };
        }
        let last = held
            .tasks
            .values()
            .filter(|r| {
                !r.pending && r.agent == *agent && r.agent_uid == uid && r.claimed.is_some()
            })
            .max_by_key(|r| r.seq);
        match last {
            Some(rec) if matches!(rec.state, TaskState::Closed | TaskState::Held) => {
                Heartbeat::Closed(self.view_of(&held, rec))
            }
            Some(_) | None => Heartbeat::Idle,
        }
    }

    pub fn report(
        &self,
        id: &TaskId,
        agent: &AgentId,
        uid: u32,
        text: SecretText,
    ) -> Result<TaskView, TaskRefusal> {
        let _w = self.writing();
        let held = self.held();
        if held.closing.contains_key(id) || held.holding.contains_key(id) {
            return Err(TaskRefusal::AgentGone);
        }
        drop(held);
        let next = self.publish(id, text, None, |rec| {
            match (rec.agent == *agent && rec.agent_uid == uid, rec.state) {
                (false, _) => Err(TaskRefusal::OtherAgent),
                (true, TaskState::Working) => Ok(()),
                (
                    true,
                    TaskState::Queued | TaskState::Reported | TaskState::Closed | TaskState::Held,
                ) => Err(TaskRefusal::NotWorking),
            }
        })?;
        Ok(self.view_of(&self.held(), &next))
    }

    /// One decided request citing the working task `id`: counted, and the lease renewed.
    pub fn acted(&self, id: &TaskId) {
        let now = self.clock.now_secs();
        let mut held = self.held();
        if held.live(id).is_some_and(|r| r.state == TaskState::Working) {
            let hot = held.hot.entry(*id).or_default();
            hot.actions = hot.actions.saturating_add(1);
            hot.last_action = Some(now);
            hot.lease_until = now + CLAIM_LEASE.as_secs() as i64;
        }
    }

    /// What the kernel has yet to record, oldest first.
    pub fn take_notices(&self) -> Vec<Notice> {
        std::mem::take(&mut self.held().notices)
    }

    /// Puts back, ahead of any newer ones, the notices the trail did not take.
    pub fn return_notices(&self, mut unsaid: Vec<Notice>) {
        let mut held = self.held();
        unsaid.extend(std::mem::take(&mut held.notices));
        held.notices = unsaid;
    }

    /// Removes `tasker`'s reports from `agent` up to its own report ordinal `upto`; a
    /// cursor above every ordinal this tasker was ever issued is refused. Answered done
    /// only when no such report is still owed its removal, from this call or an earlier one.
    pub fn acknowledge(
        &self,
        tasker: &Tasker,
        agent: &AgentId,
        upto: u64,
    ) -> Result<usize, TaskRefusal> {
        self.acknowledged(tasker, agent, upto)
            .map(|gone| gone.len())
    }

    /// [`TaskStore::acknowledge`], naming the tasks whose reports it removed.
    pub fn acknowledged(
        &self,
        tasker: &Tasker,
        agent: &AgentId,
        upto: u64,
    ) -> Result<Vec<TaskId>, TaskRefusal> {
        let _w = self.writing();
        let acked = |r: &TaskRecord| {
            r.tasker == *tasker && r.agent == *agent && r.rseq.is_some_and(|s| s <= upto)
        };
        let gone: Vec<TaskId> = {
            let held = self.held();
            if upto > held.issued.of(tasker).rseq {
                return Err(TaskRefusal::CursorAhead);
            }
            held.tasks
                .iter()
                .filter(|(_, r)| !r.pending && acked(r))
                .map(|(id, _)| *id)
                .collect()
        };
        let mut proven = true;
        let mut taken = Vec::with_capacity(gone.len());
        for id in gone {
            if !self.held().take_back_unless_held(&id) {
                continue;
            }
            taken.push(id);
            if proven {
                proven = self.withdraw_locked(&id);
            }
        }
        let gone = taken;
        match self.held().exposed.values().any(acked) {
            false => Ok(gone),
            true => Err(TaskRefusal::Unavailable(
                "outcome unknown: the acknowledgement is left to a later store write".into(),
            )),
        }
    }

    /// The agent's queued tasks, oldest submission first.
    pub fn queue(&self, agent: &AgentId) -> Vec<TaskId> {
        let held = self.held();
        let mut queued: Vec<&TaskRecord> = held
            .tasks
            .values()
            .filter(|r| !r.pending && r.agent == *agent && r.state == TaskState::Queued)
            .collect();
        queued.sort_by_key(|r| r.seq);
        queued.iter().map(|r| r.signed.task.task_id).collect()
    }

    pub fn hot(&self, id: &TaskId) -> Option<Hot> {
        self.held().hot.get(id).copied()
    }

    pub fn record(&self, id: &TaskId) -> Option<TaskRecord> {
        self.held().live(id).cloned()
    }

    pub fn now(&self) -> i64 {
        self.clock.now_secs()
    }

    /// Who is contained, for a task marked due a hold.
    pub(crate) fn hold_mark(&self, id: &TaskId) -> Option<Contained> {
        self.held().holding.get(id).copied()
    }

    /// Makes a minted task visible, once its submission is audited. A task marked due a
    /// hold is refused until the caller has recorded the hold and passes `held_for`; it
    /// is then stored held, never queued. The `ticket` is
    /// kept before anything is written: a submission that gave up first leaves the record
    /// pending, and one that gives up later can only call the outcome unknown. A write
    /// that fails once kept is taken back.
    pub(crate) fn confirm(
        &self,
        id: &TaskId,
        ticket: Option<&Ticket>,
        held_for: Option<Contained>,
    ) -> Result<(), TaskRefusal> {
        let _w = self.writing();
        let mut next = {
            let mut held = self.held();
            let prior = held
                .tasks
                .get(id)
                .filter(|r| r.pending)
                .cloned()
                .ok_or(TaskRefusal::Unknown)?;
            if held_for.is_none() && held.holding.contains_key(id) {
                return Err(TaskRefusal::Unavailable(DUE_A_HOLD.into()));
            }
            if ticket.is_some_and(|t| !t.keep(*id)) {
                return Err(abandoned());
            }
            held.expose(prior.clone());
            prior
        };
        next.pending = false;
        if held_for.is_some() {
            next.held_from = Some(next.state);
            next.state = TaskState::Held;
        }
        let late = |failed: Option<String>| Notice::Late {
            task: *id,
            tasker: next.tasker.clone(),
            failed,
        };
        match encode(&next).and_then(|plain| self.blobs.save(&name_of(id), &plain)) {
            Ok(()) => {
                let mut held = self.held();
                if ticket.is_some_and(|t| t.ended(None)) {
                    held.note(late(None));
                }
                held.exposed.remove(id);
                if next.state == TaskState::Held {
                    held.holding.remove(id);
                    held.hold_said.remove(id);
                }
                held.tasks.insert(*id, next);
                Ok(())
            }
            Err(e) => {
                self.withdraw_locked(id);
                if ticket.is_some_and(|t| t.ended(Some(e.to_string()))) {
                    self.held().note(late(Some(e.to_string())));
                }
                Err(store(e))
            }
        }
    }

    fn note(&self, notice: Notice) {
        self.held().note(notice);
    }

    /// The agent's own task `id`, only while it is `Working`.
    pub fn working(
        &self,
        id: &TaskId,
        agent: &AgentId,
        uid: u32,
    ) -> Result<CitedTask, TaskRefusal> {
        let held = self.held();
        let signed = owned(&held, id, agent, uid)?;
        match held.live(id).map(|r| (r.state, &r.root)) {
            Some((TaskState::Working, root)) => Ok(CitedTask {
                signed,
                root: root.clone(),
            }),
            Some((
                TaskState::Queued | TaskState::Reported | TaskState::Closed | TaskState::Held,
                _,
            ))
            | None => Err(TaskRefusal::NotWorking),
        }
    }

    /// The task's state when `tasker` submitted it; any other task, foreign or unknown,
    /// reads as `None`.
    pub fn state_for(&self, id: &TaskId, tasker: &Tasker) -> Option<TaskState> {
        tasker_record(&self.held(), id, tasker).map(|r| r.state)
    }

    /// `tasker`'s own task, as a view.
    pub fn status(&self, id: &TaskId, tasker: &Tasker) -> Option<TaskView> {
        let held = self.held();
        let rec = tasker_record(&held, id, tasker)?;
        Some(self.view_of(&held, rec))
    }

    fn view_of(&self, held: &Held, rec: &TaskRecord) -> TaskView {
        let hot = held
            .hot
            .get(&rec.signed.task.task_id)
            .copied()
            .unwrap_or_default();
        crate::task_verbs::view(rec, &hot, self.clock.now_secs())
    }

    /// Appends `text` to `tasker`'s working task, within the count and the byte total.
    pub fn follow_up(
        &self,
        id: &TaskId,
        tasker: &Tasker,
        text: SecretText,
        total_max: usize,
    ) -> Result<TaskView, TaskRefusal> {
        let _w = self.writing();
        let prior = {
            let held = self.held();
            let rec = tasker_record(&held, id, tasker).ok_or(TaskRefusal::Unknown)?;
            if rec.state != TaskState::Working || held.holding.contains_key(id) {
                return Err(TaskRefusal::NotWorking);
            }
            let total = rec.follow_ups.iter().map(|f| f.0.len()).sum::<usize>();
            if rec.follow_ups.len() >= MAX_FOLLOW_UPS_PER_TASK
                || total.saturating_add(text.0.len()) > total_max
            {
                return Err(TaskRefusal::FollowUps);
            }
            rec.clone()
        };
        let mut next = prior.clone();
        next.follow_ups.push(text);
        self.write(&next, Some(&prior))?;
        let mut held = self.held();
        let view = self.view_of(&held, &next);
        held.tasks.insert(*id, next);
        Ok(view)
    }

    /// Closes `tasker`'s working task as `Stopped`; the notice is collected like a report.
    pub fn stop(&self, id: &TaskId, tasker: &Tasker) -> Result<TaskView, TaskRefusal> {
        let _w = self.writing();
        let next = self.publish(
            id,
            SecretText(String::new().into()),
            Some(TaskClose::Stopped),
            |rec| match (rec.tasker == *tasker, rec.state) {
                (false, _) => Err(TaskRefusal::Unknown),
                (true, TaskState::Working) => Ok(()),
                (
                    true,
                    TaskState::Queued | TaskState::Reported | TaskState::Closed | TaskState::Held,
                ) => Err(TaskRefusal::NotWorking),
            },
        )?;
        Ok(self.view_of(&self.held(), &next))
    }

    /// Withdraws `tasker`'s queued task. Answered once the record is durably pending or
    /// gone; otherwise the task leaves memory and the outcome is unknown.
    pub fn drop_queued(&self, id: &TaskId, tasker: &Tasker) -> Result<TaskView, TaskRefusal> {
        let _w = self.writing();
        let mut view = {
            let held = self.held();
            if held.exposed.get(id).is_some_and(|r| r.tasker == *tasker) {
                return Err(drop_owed());
            }
            let rec = tasker_record(&held, id, tasker).ok_or(TaskRefusal::Unknown)?;
            if rec.state != TaskState::Queued || held.holding.contains_key(id) {
                return Err(TaskRefusal::Finished);
            }
            self.view_of(&held, rec)
        };
        if !self.held().take_back_unless_held(id) {
            return Err(TaskRefusal::Finished);
        }
        if !self.withdraw_locked(id) {
            return Err(drop_owed());
        }
        view.state = TaskState::Closed;
        view.close = Some(TaskClose::Dropped);
        Ok(view)
    }

    /// `tasker`'s tasks with `agent` after its own submission ordinal `after`, oldest
    /// first, at most `limit`, and the ordinal to resume after when more remain.
    pub fn list(
        &self,
        tasker: &Tasker,
        agent: &AgentId,
        after: Option<u64>,
        limit: usize,
    ) -> (Vec<TaskView>, Option<u64>) {
        let held = self.held();
        let mut mine: Vec<&TaskRecord> = held
            .tasks
            .values()
            .filter(|r| {
                !r.pending
                    && r.tasker == *tasker
                    && r.agent == *agent
                    && after.is_none_or(|a| r.tseq > a)
            })
            .collect();
        mine.sort_by_key(|r| r.tseq);
        let more = mine.len() > limit;
        mine.truncate(limit);
        let next = more.then(|| mine.last().map(|r| r.tseq)).flatten();
        let page = mine.into_iter().map(|r| self.view_of(&held, r)).collect();
        (page, next)
    }

    /// `tasker`'s reports and close notices from `agent`, in arrival order, as one page
    /// built under the lock; only the entries that fit are copied.
    pub fn reports(&self, tasker: &Tasker, agent: &AgentId, budget: usize) -> TaskReportPage {
        let held = self.held();
        let mut mine: Vec<&TaskRecord> = held
            .tasks
            .values()
            .filter(|r| !r.pending && r.tasker == *tasker && r.agent == *agent && r.rseq.is_some())
            .filter(|r| {
                r.state != TaskState::Held && !held.holding.contains_key(&r.signed.task.task_id)
            })
            .collect();
        mine.sort_by_key(|r| r.rseq);
        crate::task_verbs::report_page(mine.into_iter(), budget)
    }

    /// True when the disk no longer holds the record confirmed; otherwise the record
    /// stays exposed, for every later writer to retry. Queued first, so a withdrawal that
    /// unwinds is still owed.
    pub(crate) fn withdraw(&self, id: &TaskId) -> bool {
        self.abandon(*id);
        let _w = self.writing();
        !self.held().exposed.contains_key(id)
    }

    /// Takes a submission back: out of memory, written pending again if the disk may hold
    /// it confirmed, then unlinked. Only a synced pending write or a synced unlink ends the
    /// exposure. True when the record is not exposed. The caller holds the writer.
    fn withdraw_locked(&self, id: &TaskId) -> bool {
        let rewrite = {
            let mut held = self.held();
            held.take_back(id);
            held.exposed.get(id).cloned()
        };
        let name = name_of(id);
        let marked = rewrite
            .map(|rec| encode(&rec).and_then(|plain| self.blobs.save(&name, &plain)))
            .unwrap_or(Ok(()));
        let unlinked = self.blobs.delete(&name);
        let mut held = self.held();
        match (marked, unlinked) {
            (Err(mark), Err(unlink)) => {
                held.owe(
                    id,
                    format!("not marked pending ({mark}), not unlinked ({unlink})"),
                );
                false
            }
            (Ok(()), Err(unlink)) => {
                held.exposed.remove(id);
                held.proven(id);
                held.note(Notice::Left {
                    task: *id,
                    why: unlink.to_string(),
                });
                true
            }
            (_, Ok(())) => {
                held.exposed.remove(id);
                held.proven(id);
                true
            }
        }
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn insert_for_test(&self, signed: SignedTask, agent_uid: u32) -> Arc<SignedTask> {
        let agent = AgentId::parse(&signed.task.agent).expect("a test task names a valid agent id");
        let inherited = signed
            .task
            .parent
            .and_then(|p| self.held().live(&p).map(|r| r.root.clone()));
        let root = inherited.unwrap_or_else(|| match &signed.task.tasker {
            Tasker::Uid(uid) => RootTasker::Person { uid: *uid },
            Tasker::Agent { agent, .. } | Tasker::Remote(agent) => RootTasker::Agent {
                agent: agent.clone(),
            },
        });
        let task = Arc::new(signed);
        let _w = self.writing();
        let (seq, tseq) = self
            .issue_submission(&task.task.tasker)
            .expect("the test store issues a sequence");
        let rec = TaskRecord {
            signed: task.clone(),
            agent,
            agent_uid,
            tasker: task.task.tasker.clone(),
            root,
            parent: task.task.parent,
            state: TaskState::Queued,
            close: None,
            held_from: None,
            pending: false,
            removing: false,
            seq,
            tseq,
            rseq: None,
            submitted: self.clock.now_secs(),
            claimed: None,
            follow_ups: Vec::new(),
            report: None,
            actions: 0,
            last_action: None,
        };
        self.write(&rec, None)
            .expect("the test store writes the task");
        let mut held = self.held();
        held.hot.insert(task.task.task_id, Hot::default());
        held.tasks.insert(task.task.task_id, rec);
        task
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn start_for_test(&self, id: &TaskId) {
        let _w = self.writing();
        let prior = self.held().live(id).expect("a held task").clone();
        let mut next = prior.clone();
        next.state = TaskState::Working;
        next.claimed = Some(self.clock.now_secs());
        self.write(&next, Some(&prior))
            .expect("the test store writes the task");
        let lease = self.clock.now_secs() + CLAIM_LEASE.as_secs() as i64;
        let mut held = self.held();
        held.hot.entry(*id).or_default().lease_until = lease;
        held.tasks.insert(*id, next);
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn act_for_test(&self, id: &TaskId, at: i64) {
        let mut held = self.held();
        let hot = held.hot.entry(*id).or_default();
        hot.actions += 1;
        hot.last_action = Some(at);
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn count_for_test(&self) -> usize {
        self.held().tasks.len()
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn mint_live(
        &self,
        signer: &dyn TaskSigner,
        view: &dyn EnrollmentView,
        enrolled: Enrolled,
        tasker: Tasker,
        parent: Option<TaskId>,
        sub: TaskSubmission,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let t = self.mint(signer, view, enrolled, tasker, parent, sub)?;
        self.confirm(&t.task.task_id, None, None)?;
        Ok(t)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn mint_with_live(
        &self,
        draw: &mut dyn FnMut() -> Result<[u8; 16], TaskRefusal>,
        signer: &dyn TaskSigner,
        view: &dyn EnrollmentView,
        enrolled: Enrolled,
        tasker: Tasker,
        parent: Option<TaskId>,
        sub: TaskSubmission,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let t = self.mint_with(draw, signer, view, enrolled, tasker, parent, sub, None)?;
        self.confirm(&t.task.task_id, None, None)?;
        Ok(t)
    }

    /// Waits out any write in flight without draining the queue, so it counts as no write.
    #[cfg(test)]
    fn quiesce(&self) {
        drop(self.writer.lock().unwrap_or_else(PoisonError::into_inner));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.held().tasks.len()
    }
}

/// Shared by a submission and the mint it offloaded: whichever moves first decides
/// whether the minted record is kept, so a mint that outlives its submission never stays.
#[derive(Default)]
pub(crate) struct Ticket {
    state: std::sync::atomic::AtomicU8,
    stored: Mutex<Option<TaskId>>,
    fate: Mutex<Fate>,
}

/// Whether the submission stopped waiting for its kept confirm, and how the confirm ended.
#[derive(Default)]
struct Fate {
    gave_up: bool,
    ended: Option<Option<String>>,
}

const MINT_RUNNING: u8 = 0;
const MINT_KEPT: u8 = 1;
const MINT_ABANDONED: u8 = 2;

impl Ticket {
    fn abandoned(&self) -> bool {
        self.state.load(std::sync::atomic::Ordering::SeqCst) == MINT_ABANDONED
    }

    /// Called by the mint once its record is written; false when the submission gave up.
    fn keep(&self, id: TaskId) -> bool {
        *self.stored.lock().unwrap_or_else(PoisonError::into_inner) = Some(id);
        self.state
            .compare_exchange(
                MINT_RUNNING,
                MINT_KEPT,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
    }

    /// Called by the submission that gave up: the id the mint already kept, if it did.
    fn abandon(&self) -> Option<TaskId> {
        match self.state.compare_exchange(
            MINT_RUNNING,
            MINT_ABANDONED,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        ) {
            Ok(_) => None,
            Err(_) => *self.stored.lock().unwrap_or_else(PoisonError::into_inner),
        }
    }
}

impl Ticket {
    /// The confirm's end; true when the submission had already stopped waiting for it.
    fn ended(&self, failed: Option<String>) -> bool {
        let mut fate = self.fate.lock().unwrap_or_else(PoisonError::into_inner);
        fate.ended = Some(failed);
        fate.gave_up
    }

    /// The submission stops waiting; the confirm's end, when it has already come.
    fn gave_up(&self) -> Option<Option<String>> {
        let mut fate = self.fate.lock().unwrap_or_else(PoisonError::into_inner);
        fate.gave_up = true;
        fate.ended.clone()
    }
}

/// Puts the withdrawal in hand back on the queue if the drain unwinds.
struct PutBack<'a> {
    store: &'a TaskStore,
    id: Option<TaskId>,
}

impl Drop for PutBack<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.store.abandon(id);
        }
    }
}

fn drop_owed() -> TaskRefusal {
    TaskRefusal::Unavailable("outcome unknown: the drop is left to a later store write".into())
}

fn abandoned() -> TaskRefusal {
    TaskRefusal::Unavailable("not done: the submission was abandoned".into())
}

fn draw_id() -> Result<[u8; 16], TaskRefusal> {
    let mut id = [0u8; 16];
    maknae_crypto::random::fill(&mut id[..]).map_err(|_| TaskRefusal::Random)?;
    Ok(id)
}

fn store(e: StoreError) -> TaskRefusal {
    TaskRefusal::Store(e.to_string())
}

fn tasker_record<'h>(held: &'h Held, id: &TaskId, tasker: &Tasker) -> Option<&'h TaskRecord> {
    held.live(id).filter(|r| r.tasker == *tasker)
}

/// A tasker's live tasks with one agent, and its live tasks plus held reports overall,
/// are each capped; a close is never refused, so the cap applies here.
fn tasker_room(held: &Held, tasker: &Tasker, agent: &AgentId) -> Result<(), TaskRefusal> {
    let mut live_here = 0;
    let mut kept = 0;
    for r in held.tasks.values().filter(|r| r.tasker == *tasker) {
        kept += 1;
        if r.agent == *agent && matches!(r.state, TaskState::Queued | TaskState::Working) {
            live_here += 1;
        }
    }
    if live_here >= MAX_LIVE_TASKS_PER_TASKER_PER_AGENT {
        return Err(TaskRefusal::TaskerLive {
            agent: agent.as_str().to_owned(),
        });
    }
    if kept >= MAX_HELD_REPORTS_PER_TASKER {
        return Err(TaskRefusal::TaskerHeld);
    }
    Ok(())
}

/// A citable task: the agent's own `Working` task and the stored root of its chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CitedTask {
    pub signed: Arc<SignedTask>,
    pub root: RootTasker,
}

/// A sub-task works in its parent's partition, and is taken only while that parent is
/// working and due neither a hold nor a close; a person's own task works in the uid's.
fn root_of(held: &Held, task: &TaskObject) -> Result<RootTasker, TaskRefusal> {
    if let Some(parent) = task.parent {
        return held
            .live(&parent)
            .filter(|p| {
                p.state == TaskState::Working
                    && !held.holding.contains_key(&parent)
                    && !held.closing.contains_key(&parent)
            })
            .map(|p| p.root.clone())
            .ok_or(TaskRefusal::ParentNotHeld);
    }
    match &task.tasker {
        Tasker::Uid(uid) => Ok(RootTasker::Person { uid: *uid }),
        Tasker::Agent { agent, .. } => Ok(RootTasker::Agent {
            agent: agent.clone(),
        }),
        Tasker::Remote(_) => Err(TaskRefusal::Schema("a remote tasker is not taken".into())),
    }
}

/// The stored task `id`, if it is bound to this agent id and uid.
fn owned(
    held: &Held,
    id: &TaskId,
    agent: &AgentId,
    uid: u32,
) -> Result<Arc<SignedTask>, TaskRefusal> {
    let stored = held.live(id).ok_or(TaskRefusal::Unknown)?;
    if stored.agent != *agent || stored.agent_uid != uid {
        return Err(TaskRefusal::OtherAgent);
    }
    if held.closing.contains_key(id) || held.holding.contains_key(id) {
        return Err(TaskRefusal::Unknown);
    }
    Ok(stored.signed.clone())
}

/// [`owned`], while the task is queued or working.
fn handable(
    held: &Held,
    id: &TaskId,
    agent: &AgentId,
    uid: u32,
) -> Result<Arc<SignedTask>, TaskRefusal> {
    let task = owned(held, id, agent, uid)?;
    match held.live(id).is_some_and(open) {
        true => Ok(task),
        false => Err(TaskRefusal::Unknown),
    }
}

fn open(rec: &TaskRecord) -> bool {
    match rec.state {
        TaskState::Queued | TaskState::Working => true,
        TaskState::Reported | TaskState::Closed | TaskState::Held => false,
    }
}

fn target(sub: &TaskSubmission) -> Result<AgentId, TaskRefusal> {
    AgentId::parse(&sub.agent).map_err(|e| TaskRefusal::Schema(e.to_string()))
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
pub trait TaskObjectForTest {
    fn for_test(agent: &str, tasker_uid: u32) -> TaskObject;
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl TaskObjectForTest for TaskObject {
    fn for_test(agent: &str, tasker_uid: u32) -> TaskObject {
        let mut id = [0u8; 16];
        maknae_crypto::random::fill(&mut id[..]).expect("the test task id is drawn");
        TaskObject {
            schema: maknae_proto::TASK_SCHEMA.into(),
            version: maknae_proto::TASK_VERSION,
            task_id: TaskId(id),
            tasker: Tasker::Uid(tasker_uid),
            parent: None,
            agent: agent.into(),
            ask: maknae_proto::Ask::Prompt {
                prompt: maknae_proto::SecretText(String::new().into()),
            },
            labels: maknae_proto::Labels {},
        }
    }
}

/// Built by the kernel from the authenticated session, never from the submission.
/// `under` is the task the submitting request cited, already resolved by the kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Submitter {
    User {
        uid: u32,
        home: Option<PathBuf>,
    },
    Agent {
        agent: AgentId,
        uid: u32,
        home: Option<PathBuf>,
        under: Option<TaskId>,
    },
}

fn task_request(
    by: &Submitter,
    target: &str,
    parent: Option<&CitedTask>,
    sub: &TaskSubmission,
    lane: maknae_security::Lane,
) -> maknae_security::Request {
    use crate::handler::{build_authz_request, Stamp, TaskStamp};
    let parent = parent.map(TaskStamp::of);
    use maknae_security::{AttrValue, RESOURCE_AGENT};
    let (uid, home, stamp) = match by {
        Submitter::User { uid, home } => (*uid, home, Stamp::Client),
        Submitter::Agent {
            agent, uid, home, ..
        } => (
            *uid,
            home,
            Stamp::Agent {
                agent,
                task: parent.as_ref(),
            },
        ),
    };
    let verb = maknae_proto::Verb::TaskSubmit { task: sub.clone() };
    let mut req = build_authz_request(&verb, uid, home.as_deref(), lane, None, None, &stamp);
    req.resource
        .0
        .insert(RESOURCE_AGENT, AttrValue::Str(target.to_owned()));
    req
}

/// The connection a submission arrived on, for its audit record and its decision bound.
pub(crate) struct SubmitCtx<'a> {
    pub where_: &'a crate::run::WhereCtx,
    pub session_id: u64,
    pub seq: &'a maknae_audit_append::Seq,
    pub user: Option<&'a str>,
    pub peer_uri: Option<&'a str>,
    pub lane: maknae_security::Lane,
    pub decide_timeout: std::time::Duration,
    pub text_max: usize,
}

struct Attempt {
    uid: u32,
    agent: Option<AgentId>,
    tasker: Tasker,
    target: String,
    parent: Option<TaskId>,
    role: Option<&'static str>,
    ticket: Arc<Ticket>,
}

impl Attempt {
    fn record(
        &self,
        ctx: &SubmitCtx<'_>,
        task: Option<&TaskObject>,
        refusal: Option<&TaskRefusal>,
    ) -> maknae_audit_append::AuditRecord {
        let (result, reason, posture) = match refusal {
            None => ("permit", "task stored".to_string(), "authorized"),
            Some(r @ TaskRefusal::Unavailable(_)) => ("deny", r.to_string(), "unavailable"),
            Some(r) => ("deny", r.to_string(), "unauthorized"),
        };
        let mut rec = crate::run::make_record(
            "request",
            &ctx.where_.host,
            &ctx.where_.socket,
            self.uid,
            None,
            None,
            ctx.peer_uri,
            ctx.session_id,
            ctx.seq.next(),
            "session.task",
            Some(&format!("agent:{}", self.target)),
            result,
            &reason,
            posture,
            &ctx.where_.au3_1,
        );
        rec.subject.user = crate::run::admitted_user_pub(ctx.user);
        rec.subject.role = self.role.map(str::to_string);
        rec.subject.agent = self.agent.as_ref().map(|a| a.as_str().to_string());
        rec.subject.task_id = task.map(|t| t.task_id.to_string());
        rec.subject.parent_task_id = self.parent.map(|p| p.to_string());
        rec.subject.tasker = Some(maknae_proto::tasker_text(&self.tasker));
        rec.subject.task_op = Some("submit".into());
        rec
    }
}

/// Runs one store step off the async worker, under the submitting uid's slot, the shared
/// capacity and `deadline`.
pub(crate) async fn offload<T, F>(
    uid: u32,
    deadline: tokio::time::Instant,
    f: F,
) -> Result<T, TaskRefusal>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, TaskRefusal> + Send + 'static,
{
    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
    match crate::mutation::blocking(uid, left, f).await {
        Ok(done) => done,
        Err(crate::mutation::Blocked::NotStarted) => Err(TaskRefusal::Unavailable(
            "not done: the task store was busy".into(),
        )),
        Err(crate::mutation::Blocked::Unknown) => {
            Err(TaskRefusal::Unavailable(format!("outcome unknown: {LATE}")))
        }
    }
}

const LATE: &str = "the task store did not answer in time";

/// What a submission says of a confirm that did not answer `Ok`. Once the confirm kept
/// the ticket the record may be stored, so the outcome is unknown and nothing is taken
/// back here; before that nothing was written, and the pending record is withdrawn.
async fn unconfirmed(
    store: &Arc<TaskStore>,
    uid: u32,
    deadline: tokio::time::Instant,
    id: TaskId,
    kept: bool,
    refusal: TaskRefusal,
) -> (TaskRefusal, String) {
    let late = format!("outcome unknown: {LATE}");
    match (kept, refusal) {
        (true, TaskRefusal::Unavailable(why)) if why == late => {
            (TaskRefusal::Unavailable(late.clone()), late)
        }
        (true, other) => {
            let said = format!("outcome unknown: {other}");
            (TaskRefusal::Unavailable(said.clone()), said)
        }
        (false, refusal) => {
            let withdrawal = withdraw_within(store, uid, deadline, id).await;
            let refusal = match refusal {
                TaskRefusal::Unavailable(why) if why == late => {
                    TaskRefusal::Unavailable(format!("not done: {LATE}"))
                }
                other => other,
            };
            let said = match &refusal {
                TaskRefusal::Unavailable(why) => format!("{why}; {}", withdrawal.said()),
                other => format!("not stored: {other}; {}", withdrawal.said()),
            };
            (refusal, said)
        }
    }
}

/// What became of a submission's withdrawal, as the trail says it.
enum Withdrawal {
    Done,
    Queued,
    Running,
}

impl Withdrawal {
    fn said(&self) -> &'static str {
        match self {
            Withdrawal::Done => "withdrawn",
            Withdrawal::Queued => "withdrawal left to the next store write",
            Withdrawal::Running => "withdrawal outcome unknown",
        }
    }
}

/// Takes a submission back within what is left of `deadline`, at most once: when the step
/// never started, the next store writer does it instead.
async fn withdraw_within(
    store: &Arc<TaskStore>,
    uid: u32,
    deadline: tokio::time::Instant,
    id: TaskId,
) -> Withdrawal {
    let claimed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (s, c) = (Arc::clone(store), Arc::clone(&claimed));
    let done = offload(uid, deadline, move || {
        Ok(!c.swap(true, std::sync::atomic::Ordering::SeqCst) && s.withdraw(&id))
    })
    .await;
    match done {
        Ok(true) => Withdrawal::Done,
        Ok(false) => Withdrawal::Queued,
        Err(_) if !claimed.swap(true, std::sync::atomic::Ordering::SeqCst) => {
            store.abandon(id);
            Withdrawal::Queued
        }
        Err(_) => Withdrawal::Running,
    }
}

/// Decides one `session.task` submission and stores it only on `Permit`: the record is
/// written pending, the decision audited, then the record made visible.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn submit_task<P: Authorizer + Send + Sync + 'static>(
    authorizer: Arc<P>,
    store: &Arc<TaskStore>,
    signer: &Arc<dyn TaskSigner>,
    view: &Arc<dyn EnrollmentView>,
    ctx: &SubmitCtx<'_>,
    by: Submitter,
    sub: TaskSubmission,
    emit: &impl AuditEmit,
) -> Result<Arc<SignedTask>, TaskRefusal> {
    submit_under(decider(authorizer), store, signer, view, ctx, by, sub, emit).await
}

fn decider<P>(authorizer: Arc<P>) -> Decider<P> {
    Decider {
        authorizer,
        breaker: crate::run::authz_decide_breaker(),
    }
}

/// The PDP and the request path's decision breaker it is admitted under.
struct Decider<P> {
    authorizer: Arc<P>,
    breaker: Arc<tokio::sync::Mutex<crate::blocking_guard::BlockingBreaker>>,
}

/// The decision and the store's steps share two decision bounds, the handler drain's
/// decision and blocking-step terms.
#[allow(clippy::too_many_arguments)]
async fn submit_under<P: Authorizer + Send + Sync + 'static>(
    pdp: Decider<P>,
    store: &Arc<TaskStore>,
    signer: &Arc<dyn TaskSigner>,
    view: &Arc<dyn EnrollmentView>,
    ctx: &SubmitCtx<'_>,
    by: Submitter,
    sub: TaskSubmission,
    emit: &impl AuditEmit,
) -> Result<Arc<SignedTask>, TaskRefusal> {
    let deadline = tokio::time::Instant::now() + ctx.decide_timeout * 2;
    let (uid, agent, tasker) = match &by {
        Submitter::User { uid, .. } => (*uid, None, Tasker::Uid(*uid)),
        Submitter::Agent { agent, uid, .. } => (
            *uid,
            Some(agent.clone()),
            Tasker::Agent {
                agent: agent.as_str().to_string(),
                uid: *uid,
            },
        ),
    };
    let mut attempt = Attempt {
        uid,
        agent,
        tasker,
        target: sub.agent.clone(),
        parent: None,
        role: None,
        ticket: Arc::default(),
    };
    let decided = decide(
        pdp,
        store,
        signer,
        view,
        ctx,
        &by,
        sub,
        &mut attempt,
        deadline,
    )
    .await;
    let rec = match &decided {
        Ok(signed) => attempt.record(ctx, Some(&signed.task), None),
        Err(refusal) => attempt.record(ctx, None, Some(refusal)),
    };
    let audited = emit
        .emit_within(&rec, crate::blocking_guard::AUDIT_APPEND_TIMEOUT)
        .await;
    match (decided, audited) {
        (Ok(task), Ok(())) => {
            let id = task.task.task_id;
            let ticket = Arc::new(Ticket::default());
            let mut held_for = store.hold_mark(&id);
            let mut confirmed = Err(TaskRefusal::Unknown);
            for _ in 0..2 {
                if let Some(who) = held_for {
                    let mut hold = attempt.record(ctx, Some(&task.task), None);
                    hold.outcome.result = "deny".into();
                    hold.outcome.posture = "unavailable".into();
                    hold.outcome.reason = match AgentId::parse(&task.task.agent) {
                        Ok(agent) => held_reason(who, &agent),
                        Err(_) => "task held: contained".into(),
                    };
                    let said = emit
                        .emit_within(&hold, crate::blocking_guard::AUDIT_APPEND_TIMEOUT)
                        .await;
                    if let Err(e) = said {
                        withdraw_within(store, uid, deadline, id).await;
                        return Err(TaskRefusal::Audit(e.to_string()));
                    }
                }
                let (s, t) = (Arc::clone(store), Arc::clone(&ticket));
                confirmed =
                    offload(uid, deadline, move || s.confirm(&id, Some(&t), held_for)).await;
                match &confirmed {
                    Err(TaskRefusal::Unavailable(why))
                        if why == DUE_A_HOLD && held_for.is_none() =>
                    {
                        held_for = Some(store.hold_mark(&id).unwrap_or(Contained::Tasker));
                    }
                    _ => break,
                }
            }
            match confirmed {
                Ok(()) => Ok(task),
                Err(refusal) => {
                    let kept = ticket.abandon().is_some();
                    let late = TaskRefusal::Unavailable(format!("outcome unknown: {LATE}"));
                    if let (true, Some(failed)) = (kept && refusal == late, ticket.gave_up()) {
                        store.note(Notice::Late {
                            task: id,
                            tasker: attempt.tasker.clone(),
                            failed,
                        });
                    }
                    let (refusal, said) =
                        unconfirmed(store, uid, deadline, id, kept, refusal).await;
                    let mut corrective = attempt.record(ctx, Some(&task.task), Some(&refusal));
                    corrective.outcome.reason = said;
                    corrective.outcome.posture = "unavailable".into();
                    match emit
                        .emit_within(&corrective, crate::blocking_guard::AUDIT_APPEND_TIMEOUT)
                        .await
                    {
                        Err(e) if !kept => Err(TaskRefusal::Audit(e.to_string())),
                        Ok(()) | Err(_) => Err(refusal),
                    }
                }
            }
        }
        (Ok(signed), Err(e)) => {
            withdraw_within(store, uid, deadline, signed.task.task_id).await;
            Err(TaskRefusal::Audit(e.to_string()))
        }
        (Err(refusal), audited) => {
            if let Some(id) = attempt.ticket.abandon() {
                withdraw_within(store, uid, deadline, id).await;
            }
            match audited {
                Ok(()) => Err(refusal),
                Err(e) => Err(TaskRefusal::Audit(e.to_string())),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn decide<P: Authorizer + Send + Sync + 'static>(
    pdp: Decider<P>,
    store: &Arc<TaskStore>,
    signer: &Arc<dyn TaskSigner>,
    view: &Arc<dyn EnrollmentView>,
    ctx: &SubmitCtx<'_>,
    by: &Submitter,
    sub: TaskSubmission,
    attempt: &mut Attempt,
    deadline: tokio::time::Instant,
) -> Result<Arc<SignedTask>, TaskRefusal> {
    maknae_proto::validate_submission(&sub).map_err(|e| TaskRefusal::Schema(e.to_string()))?;
    let maknae_proto::Ask::Prompt { prompt } = &sub.ask;
    if prompt.0.len() > ctx.text_max {
        return Err(TaskRefusal::TooLong);
    }
    let target = target(&sub)?;
    let parent = match by {
        Submitter::User { .. } => None,
        Submitter::Agent {
            agent,
            uid,
            under: None,
            ..
        } => match store.holds_working(agent, *uid) {
            true => {
                return Err(TaskRefusal::Denied(
                    "an agent submits under the task it holds".into(),
                ))
            }
            false => None,
        },
        Submitter::Agent {
            agent,
            uid,
            under: Some(t),
            ..
        } => Some(
            store
                .working(t, agent, *uid)
                .map_err(|_| TaskRefusal::ParentNotHeld)?,
        ),
    };
    attempt.parent = parent.as_ref().map(|t| t.signed.task.task_id);
    let (generation, enrolled) = store.observe(&**view, &target);
    let req = task_request(by, target.as_str(), parent.as_ref(), &sub, ctx.lane);
    let decided = decide_admitted(pdp, ctx.decide_timeout, req).await?;
    attempt.role = decided.role;
    match maknae_security::finalize(decided.verdict) {
        maknae_security::Decision::Permit { obligations } => {
            crate::handler::discharge_plan(&obligations)
                .map_err(|u| TaskRefusal::Denied(format!("unhonorable obligation: {}", u.0)))?;
        }
        maknae_security::Decision::Deny { reason } => return Err(TaskRefusal::Denied(reason)),
    }
    let agent_uid = enrolled.ok_or(TaskRefusal::AgentGone)?;
    let first = store.next_id()?;
    let ticket = Arc::clone(&attempt.ticket);
    let (s, signer, view) = (Arc::clone(store), Arc::clone(signer), Arc::clone(view));
    let (tasker, parent) = (attempt.tasker.clone(), attempt.parent);
    offload(attempt.uid, deadline, move || {
        let mut once = Some(first);
        let mut draw = || match once.take() {
            Some(id) => Ok(id),
            None => s.next_id(),
        };
        s.mint_with(
            &mut draw,
            &*signer,
            &*view,
            Enrolled {
                generation,
                agent_uid,
            },
            tasker,
            parent,
            sub,
            Some(&ticket),
        )
    })
    .await
}

async fn decide_admitted<P: Authorizer + Send + Sync + 'static>(
    pdp: Decider<P>,
    bound: std::time::Duration,
    req: maknae_security::Request,
) -> Result<maknae_security::Decided, TaskRefusal> {
    use crate::blocking_guard::{admit_blocking, Offload};
    let authorizer = pdp.authorizer;
    let decided = admit_blocking(&pdp.breaker, bound, "authorization decision", move || {
        maknae_security::guarded_decide_cited(&*authorizer, &req)
    })
    .await;
    let reason = match decided {
        Ok(d) => return Ok(d),
        Err(Offload::Open) => "authorization decision circuit breaker open",
        Err(Offload::AtCapacity) => "authorization decision blocking worker budget exhausted",
        Err(Offload::Join) => "authorization decision failed (join)",
        Err(Offload::TimedOut) => "authorization decision timed out",
    };
    Err(TaskRefusal::Denied(reason.into()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]
    use super::*;
    use crate::blocking_guard::BlockingBreaker;
    use crate::enrollment::{FixedEnrollment, SnapshotEnrollment};
    use crate::test_fixtures::{fixture, DirGuard};
    use crate::Composition;
    use maknae_audit_append::{AuditError, AuditRecord};
    use maknae_authz_basic::{Baseline, HermeticAuthorizer};
    use maknae_crypto::plane_key::PlaneKey;
    use maknae_proto::{Ask, Labels, SecretText, TASK_SCHEMA, TASK_VERSION};
    use maknae_security::{Decided, Request, Verdict};
    use maknae_vault::task_sig::TaskSignatureError;
    use maknae_vault::test_pki::{TestCa, TRUST_DOMAIN};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const HOBI: u32 = 2001;
    const JIN: u32 = 2002;
    const SUGA: u32 = 2003;
    const HOBI_AGAIN: u32 = 2004;
    const SESSION: u64 = 77;
    const BOUND: std::time::Duration = std::time::Duration::from_secs(5);
    type Breaker = Arc<tokio::sync::Mutex<BlockingBreaker>>;
    const PROMPT: &str = "task-11-prompt-sentinel";
    const ACCOUNT: &str = "jimin";
    const AUTHZ: &str = "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nroles:\n  user:\n    allow: [\"session.task\"]\n";

    fn id(s: &str) -> AgentId {
        AgentId::parse(s).unwrap()
    }

    fn at(generation: u64, agent_uid: u32) -> Enrolled {
        Enrolled {
            generation,
            agent_uid,
        }
    }

    struct LeafSigner {
        ca: TestCa,
        key: PlaneKey,
        identity: Mutex<maknae_vault::PlaneIdentity>,
    }

    impl LeafSigner {
        fn new(key: PlaneKey) -> Self {
            let ca = TestCa::new(key);
            let identity = Mutex::new(ca.kernel(key, None));
            Self { ca, key, identity }
        }
        fn rotate(&self) {
            *self.identity.lock().unwrap() = self.ca.kernel(self.key, None);
        }
        fn verify(&self, signed: &SignedTask) -> Result<(), TaskSignatureError> {
            maknae_vault::task_sig::verify_task(
                &self.ca.trust(),
                TRUST_DOMAIN,
                &id(&signed.task.agent),
                signed,
                std::time::SystemTime::now(),
            )
        }
    }

    impl TaskSigner for LeafSigner {
        fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal> {
            signed_by(Some(&self.identity.lock().unwrap()), task)
        }
        fn current_leaf(&self) -> Option<[u8; 32]> {
            leaf_of(Some(&self.identity.lock().unwrap()))
        }
    }

    impl TaskSigner for &'static LeafSigner {
        fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal> {
            (**self).sign(task)
        }
        fn current_leaf(&self) -> Option<[u8; 32]> {
            (**self).current_leaf()
        }
    }

    fn shared_signer() -> Arc<dyn TaskSigner> {
        Arc::new(signer())
    }

    struct NoIdentity;

    impl TaskSigner for NoIdentity {
        fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal> {
            signed_by(None, task)
        }
        fn current_leaf(&self) -> Option<[u8; 32]> {
            leaf_of(None)
        }
    }

    fn signer() -> &'static LeafSigner {
        static SIGNER: std::sync::OnceLock<LeafSigner> = std::sync::OnceLock::new();
        SIGNER.get_or_init(|| LeafSigner::new(PlaneKey::EcdsaP384Sha384))
    }

    #[test]
    fn mint_never_stores_an_unsigned_task() {
        let store = Arc::new(TaskStore::new());
        let v = view(&[("hobi", HOBI)]);
        assert_eq!(NoIdentity.current_leaf(), None);
        assert_eq!(
            store
                .mint_live(
                    &NoIdentity,
                    &v,
                    at(0, HOBI),
                    Tasker::Uid(1000),
                    None,
                    sub("hobi")
                )
                .unwrap_err(),
            TaskRefusal::Unsigned
        );
        assert_eq!(store.len(), 0);
        for k in PlaneKey::ALL {
            let signing = LeafSigner::new(k);
            let held = store
                .mint_live(
                    &signing,
                    &v,
                    at(0, HOBI),
                    Tasker::Uid(1000),
                    None,
                    sub("hobi"),
                )
                .unwrap();
            assert_eq!(signing.verify(&held), Ok(()), "{k:?}");
        }
        assert_eq!(store.len(), PlaneKey::ALL.len());
    }

    #[test]
    fn a_collision_is_signed_again_under_the_new_id() {
        let store = Arc::new(TaskStore::new());
        let v = view(&[("hobi", HOBI)]);
        let mut draws = [[1u8; 16], [1; 16], [2; 16]].into_iter();
        let mut draw = || Ok(draws.next().unwrap());
        for _ in 0..2 {
            let signed = store
                .mint_with_live(
                    &mut draw,
                    signer(),
                    &v,
                    at(0, HOBI),
                    Tasker::Uid(1),
                    None,
                    sub("hobi"),
                )
                .unwrap();
            assert_eq!(signer().verify(&signed), Ok(()));
        }
    }

    struct DuringSign<'a> {
        inner: &'a LeafSigner,
        during: Box<dyn Fn() + Send + Sync + 'a>,
    }

    impl TaskSigner for DuringSign<'_> {
        fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal> {
            (self.during)();
            self.inner.sign(task)
        }
        fn current_leaf(&self) -> Option<[u8; 32]> {
            self.inner.current_leaf()
        }
    }

    struct Counting<'a> {
        inner: &'a LeafSigner,
        signs: AtomicUsize,
    }

    impl TaskSigner for Counting<'_> {
        fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal> {
            self.signs.fetch_add(1, Ordering::SeqCst);
            self.inner.sign(task)
        }
        fn current_leaf(&self) -> Option<[u8; 32]> {
            self.inner.current_leaf()
        }
    }

    fn fingerprint(t: &SignedTask) -> [u8; 32] {
        maknae_vault::task_sig::leaf_fingerprint(&t.signature.leaf.0)
    }

    #[test]
    fn resign_if_stale_refuses_another_agents_or_uids_task_before_signing() {
        let signing = LeafSigner::new(PlaneKey::EcdsaP384Sha384);
        let store = Arc::new(TaskStore::new());
        let v = view(&[("hobi", HOBI), ("jin", JIN)]);
        let hobis = store
            .mint_live(
                &signing,
                &v,
                at(0, HOBI),
                Tasker::Uid(1000),
                None,
                sub("hobi"),
            )
            .unwrap();
        signing.rotate();
        let counting = Counting {
            inner: &signing,
            signs: AtomicUsize::new(0),
        };
        let task_id = hobis.task.task_id;
        for (agent, uid) in [
            ("jin", JIN),
            ("jin", HOBI),
            ("hobi", JIN),
            ("hobi", HOBI_AGAIN),
        ] {
            assert_eq!(
                store
                    .resign_if_stale(&task_id, &id(agent), uid, &counting)
                    .unwrap_err(),
                TaskRefusal::OtherAgent,
                "{agent}/{uid}"
            );
        }
        assert_eq!(counting.signs.load(Ordering::SeqCst), 0, "nothing signed");
        let kept = store.resolve(&task_id, &id("hobi"), HOBI).unwrap();
        assert!(Arc::ptr_eq(&kept, &hobis));
        let handed = store
            .resign_if_stale(&task_id, &id("hobi"), HOBI, &counting)
            .unwrap();
        assert_eq!(counting.signs.load(Ordering::SeqCst), 1);
        assert_eq!(Some(fingerprint(&handed)), signing.current_leaf());
    }

    #[test]
    fn resign_if_stale_leaves_a_task_replaced_or_withdrawn_while_it_signed() {
        let signing = LeafSigner::new(PlaneKey::EcdsaP384Sha384);
        let store = Arc::new(TaskStore::new());
        let v = view(&[("hobi", HOBI)]);
        let old = store
            .mint_live(
                &signing,
                &v,
                at(0, HOBI),
                Tasker::Uid(1000),
                None,
                sub("hobi"),
            )
            .unwrap();
        let task_id = old.task.task_id;
        let hobi = id("hobi");
        signing.rotate();
        let current_replacement = signing.sign(old.task.clone()).unwrap();
        let once = std::sync::atomic::AtomicBool::new(false);
        let replacing_current = DuringSign {
            inner: &signing,
            during: Box::new(|| {
                if !once.swap(true, Ordering::SeqCst) {
                    store.insert_for_test(current_replacement.clone(), HOBI);
                }
            }),
        };
        let handed = store
            .resign_if_stale(&task_id, &hobi, HOBI, &replacing_current)
            .unwrap();
        assert_eq!(
            *handed, current_replacement,
            "a current replacement is handed out"
        );
        let held = store.resolve(&task_id, &hobi, HOBI).unwrap();
        assert!(Arc::ptr_eq(&held, &handed), "and not overwritten");

        let stale_replacement = (*handed).clone();
        signing.rotate();
        let once = std::sync::atomic::AtomicBool::new(false);
        let replacing_stale_once = DuringSign {
            inner: &signing,
            during: Box::new(|| {
                if !once.swap(true, Ordering::SeqCst) {
                    store.insert_for_test(stale_replacement.clone(), HOBI);
                }
            }),
        };
        let handed = store
            .resign_if_stale(&task_id, &hobi, HOBI, &replacing_stale_once)
            .unwrap();
        assert_eq!(Some(fingerprint(&handed)), signing.current_leaf());
        assert_eq!(handed.task, old.task);
        assert_eq!(signing.verify(&handed), Ok(()));
        let held = store.resolve(&task_id, &hobi, HOBI).unwrap();
        assert!(
            Arc::ptr_eq(&held, &handed),
            "the re-signed replacement is stored"
        );

        let stale_again = (*handed).clone();
        signing.rotate();
        let replacing_stale_always = DuringSign {
            inner: &signing,
            during: Box::new(|| {
                store.insert_for_test(stale_again.clone(), HOBI);
            }),
        };
        assert_eq!(
            store
                .resign_if_stale(&task_id, &hobi, HOBI, &replacing_stale_always)
                .unwrap_err(),
            TaskRefusal::Unsigned,
            "one retry, then refused"
        );

        let withdrawing = DuringSign {
            inner: &signing,
            during: Box::new(|| drop(store.purge_agent(&hobi))),
        };
        assert_eq!(
            store
                .resign_if_stale(&task_id, &hobi, HOBI, &withdrawing)
                .unwrap_err(),
            TaskRefusal::Unknown
        );
        assert_eq!(
            store.record(&task_id).unwrap().close,
            Some(TaskClose::AgentGone),
            "a closed task is not re-signed"
        );
    }

    #[test]
    fn resign_if_stale_gives_a_verifying_signature_under_the_current_leaf() {
        for k in PlaneKey::ALL {
            let signing = LeafSigner::new(k);
            let store = Arc::new(TaskStore::new());
            let v = view(&[("hobi", HOBI), ("jin", JIN)]);
            let mint_by = |s: &LeafSigner, to: &str| {
                store
                    .mint_live(s, &v, at(0, v.0[&id(to)]), Tasker::Uid(1000), None, sub(to))
                    .unwrap()
            };
            let before = mint_by(&signing, "hobi");
            let first = signing.current_leaf().unwrap();
            assert_eq!(
                maknae_vault::task_sig::leaf_fingerprint(&before.signature.leaf.0),
                first
            );
            signing.rotate();
            let current = signing.current_leaf().unwrap();
            assert_ne!(current, first, "{k:?}");
            let fresh = mint_by(&signing, "jin");
            let id_before = before.task.task_id;
            assert_eq!(
                store
                    .resign_if_stale(&id_before, &id("hobi"), HOBI, &NoIdentity)
                    .unwrap_err(),
                TaskRefusal::Unsigned,
                "no current leaf: nothing is handed out"
            );
            let kept = store.resolve(&id_before, &id("hobi"), HOBI).unwrap();
            assert!(Arc::ptr_eq(&kept, &before), "{k:?}");
            let after = store
                .resign_if_stale(&id_before, &id("hobi"), HOBI, &signing)
                .unwrap();
            assert_eq!(after.task, before.task, "{k:?}");
            assert_eq!(
                maknae_vault::task_sig::leaf_fingerprint(&after.signature.leaf.0),
                current,
                "{k:?}"
            );
            assert_eq!(signing.verify(&after), Ok(()), "{k:?}");
            let stored = store.resolve(&id_before, &id("hobi"), HOBI).unwrap();
            assert!(Arc::ptr_eq(&stored, &after), "{k:?}");
            let untouched = store
                .resign_if_stale(&fresh.task.task_id, &id("jin"), JIN, &signing)
                .unwrap();
            assert!(Arc::ptr_eq(&untouched, &fresh), "{k:?}");
            let mut unknown = id_before;
            unknown.0[0] ^= 0xff;
            assert_eq!(
                store
                    .resign_if_stale(&unknown, &id("hobi"), HOBI, &signing)
                    .unwrap_err(),
                TaskRefusal::Unknown
            );
        }
    }

    fn sub(agent: &str) -> TaskSubmission {
        TaskSubmission {
            schema: TASK_SCHEMA.into(),
            version: TASK_VERSION,
            agent: agent.into(),
            ask: Ask::Prompt {
                prompt: SecretText(String::from(PROMPT).into()),
            },
            labels: Labels {},
        }
    }

    fn view(pairs: &[(&str, u32)]) -> FixedEnrollment {
        FixedEnrollment(pairs.iter().map(|(a, u)| (id(a), *u)).collect())
    }

    fn mint(store: &TaskStore, v: &FixedEnrollment, agent: &str) -> Arc<SignedTask> {
        store
            .mint_live(
                signer(),
                v,
                at(store.generation(&id(agent)), v.0[&id(agent)]),
                Tasker::Uid(1000),
                None,
                sub(agent),
            )
            .unwrap()
    }

    #[test]
    fn mint_assigns_a_fresh_id_and_the_authenticated_tasker() {
        let store = Arc::new(TaskStore::new());
        let v = view(&[("hobi", HOBI)]);
        let tasker = Tasker::Agent {
            agent: "jin".into(),
            uid: JIN,
        };
        let parent = store
            .insert_for_test(
                signer().sign(TaskObject::for_test("jin", 1000)).unwrap(),
                JIN,
            )
            .task
            .task_id;
        store.start_for_test(&parent);
        let a = store
            .mint_live(
                signer(),
                &v,
                at(0, HOBI),
                tasker.clone(),
                Some(parent),
                sub("hobi"),
            )
            .unwrap();
        let b = mint(&store, &v, "hobi");
        assert_ne!(a.task.task_id, b.task.task_id);
        assert_eq!(a.task.tasker, tasker);
        assert_eq!(a.task.parent, Some(parent));
        assert_eq!(a.task.agent, "hobi");
        assert_eq!(
            (a.task.schema.as_str(), a.task.version),
            (TASK_SCHEMA, TASK_VERSION)
        );
        assert_eq!(a.task.ask, sub("hobi").ask);
        assert_eq!(b.task.tasker, Tasker::Uid(1000));
        assert_eq!(b.task.parent, None);
        assert_eq!(store.len(), 3);
        let got = store.resolve(&a.task.task_id, &id("hobi"), HOBI).unwrap();
        assert!(Arc::ptr_eq(&got, &a));
    }

    #[test]
    fn an_id_collision_draws_again() {
        let store = Arc::new(TaskStore::new());
        let v = view(&[("hobi", HOBI)]);
        let mut draws = [[1u8; 16], [1; 16], [2; 16]].into_iter();
        let mut draw = || Ok(draws.next().unwrap());
        let first = store
            .mint_with_live(
                &mut draw,
                signer(),
                &v,
                at(0, HOBI),
                Tasker::Uid(1),
                None,
                sub("hobi"),
            )
            .unwrap();
        let second = store
            .mint_with_live(
                &mut draw,
                signer(),
                &v,
                at(0, HOBI),
                Tasker::Uid(1),
                None,
                sub("hobi"),
            )
            .unwrap();
        assert_eq!(first.task.task_id, TaskId([1; 16]));
        assert_eq!(second.task.task_id, TaskId([2; 16]));
        assert_eq!(store.len(), 2);
        let mut failing = || Err(TaskRefusal::Random);
        assert_eq!(
            store
                .mint_with_live(
                    &mut failing,
                    signer(),
                    &v,
                    at(0, HOBI),
                    Tasker::Uid(1),
                    None,
                    sub("hobi")
                )
                .unwrap_err(),
            TaskRefusal::Random
        );
    }

    #[test]
    fn resolve_refuses_an_unknown_id() {
        let store = Arc::new(TaskStore::new());
        let v = view(&[("hobi", HOBI)]);
        let held = mint(&store, &v, "hobi");
        let mut other = held.task.task_id;
        other.0[0] ^= 0xff;
        assert_eq!(
            store.resolve(&other, &id("hobi"), HOBI).unwrap_err(),
            TaskRefusal::Unknown
        );
        assert!(store.resolve(&held.task.task_id, &id("hobi"), HOBI).is_ok());
    }

    #[test]
    fn resolve_refuses_another_agents_task() {
        let store = Arc::new(TaskStore::new());
        let v = view(&[("hobi", HOBI), ("jin", JIN)]);
        let hobis = mint(&store, &v, "hobi");
        assert_eq!(
            store
                .resolve(&hobis.task.task_id, &id("jin"), JIN)
                .unwrap_err(),
            TaskRefusal::OtherAgent
        );
        assert_eq!(
            store
                .resolve(&hobis.task.task_id, &id("jin"), HOBI)
                .unwrap_err(),
            TaskRefusal::OtherAgent
        );
    }

    #[test]
    fn a_re_enrolled_agent_id_with_a_new_uid_cannot_use_old_tasks() {
        let store = Arc::new(TaskStore::new());
        let old = mint(&store, &view(&[("hobi", HOBI)]), "hobi");
        assert_eq!(
            store
                .resolve(&old.task.task_id, &id("hobi"), 4040)
                .unwrap_err(),
            TaskRefusal::OtherAgent
        );
        let before = store.generation(&id("hobi"));
        let kept = mint(&store, &view(&[("jin", JIN)]), "jin");
        store.retain_enrolled(&view(&[("hobi", 4040), ("jin", JIN)]));
        assert_eq!(
            store
                .resolve(&old.task.task_id, &id("hobi"), HOBI)
                .unwrap_err(),
            TaskRefusal::Unknown
        );
        assert_eq!(store.generation(&id("hobi")), before + 1);
        assert_eq!(store.generation(&id("jin")), 0);
        assert!(store.resolve(&kept.task.task_id, &id("jin"), JIN).is_ok());
        store.retain_enrolled(&view(&[]));
        assert!(store.held().tasks.values().all(|t| !open(t)));
        assert_eq!(store.generation(&id("jin")), 1);
    }

    #[test]
    fn a_task_does_not_survive_its_agent_being_removed() {
        let store = Arc::new(TaskStore::new());
        let v = view(&[("hobi", HOBI), ("jin", JIN)]);
        let gone = mint(&store, &v, "hobi");
        let kept = mint(&store, &v, "jin");
        store.purge_agent(&id("hobi"));
        assert_eq!(
            store
                .resolve(&gone.task.task_id, &id("hobi"), HOBI)
                .unwrap_err(),
            TaskRefusal::Unknown
        );
        assert!(store.resolve(&kept.task.task_id, &id("jin"), JIN).is_ok());
        assert_eq!(store.generation(&id("hobi")), 1);
        store.purge_agent(&id("hobi"));
        assert_eq!(store.generation(&id("hobi")), 2);
    }

    fn held_by(store: &TaskStore, tasker: Tasker) -> TaskId {
        let mut task = TaskObject::for_test("hobi", 0);
        task.tasker = tasker;
        store
            .insert_for_test(signer().sign(task).unwrap(), HOBI)
            .task
            .task_id
    }

    /// A claim whose queued head, if any, has just been decided to stand.
    fn claim_head(
        store: &TaskStore,
        agent: &AgentId,
        uid: u32,
        signer: &dyn TaskSigner,
    ) -> Result<Claimed, TaskRefusal> {
        let decided = store.next_for(agent, uid).map(|(id, _)| id);
        claim_as(store, agent, uid, signer, decided)
    }

    /// A claim for which `decided`, if any, was found good on a load that has not changed.
    fn claim_as(
        store: &TaskStore,
        agent: &AgentId,
        uid: u32,
        signer: &dyn TaskSigner,
        decided: Option<TaskId>,
    ) -> Result<Claimed, TaskRefusal> {
        let decided = decided.map(|task| GoodStanding {
            task,
            load: Load::fixed(),
        });
        store.claim(agent, uid, signer, &view(&[]), decided.as_ref())
    }

    fn text(s: &str) -> SecretText {
        SecretText(String::from(s).into())
    }

    #[test]
    fn the_tasker_verbs_act_only_on_the_callers_task_in_its_state() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let mine = held_by(&store, me.clone());
        let theirs = held_by(&store, Tasker::Uid(1001));
        assert_eq!(store.state_for(&mine, &me), Some(TaskState::Queued));
        assert_eq!(store.state_for(&theirs, &me), None);
        assert!(store.status(&theirs, &me).is_none());
        assert_eq!(store.confirm(&mine, None, None), Err(TaskRefusal::Unknown));
        assert_eq!(
            store.follow_up(&theirs, &me, text("x"), 10).unwrap_err(),
            TaskRefusal::Unknown
        );
        assert_eq!(
            store.follow_up(&mine, &me, text("x"), 10).unwrap_err(),
            TaskRefusal::NotWorking
        );
        assert_eq!(store.stop(&theirs, &me).unwrap_err(), TaskRefusal::Unknown);
        assert_eq!(store.stop(&mine, &me).unwrap_err(), TaskRefusal::NotWorking);
        assert_eq!(
            store.drop_queued(&theirs, &me).unwrap_err(),
            TaskRefusal::Unknown
        );
        store.start_for_test(&mine);
        assert_eq!(
            store.drop_queued(&mine, &me).unwrap_err(),
            TaskRefusal::Finished
        );
        blobs.fail(Some(crate::task_store::Fail::Records));
        assert!(matches!(
            store.follow_up(&mine, &me, text("x"), 10),
            Err(TaskRefusal::Store(_))
        ));
        assert!(matches!(store.stop(&mine, &me), Err(TaskRefusal::Store(_))));
        blobs.fail(None);
        assert!(store.record(&mine).unwrap().follow_ups.is_empty());
        assert_eq!(store.record(&mine).unwrap().state, TaskState::Working);
        let added = store.follow_up(&mine, &me, text("x"), 10).unwrap();
        assert_eq!((added.actions, added.last_action_secs), (0, None));
        let closed = store.stop(&mine, &me).unwrap();
        assert_eq!(closed.close, Some(TaskClose::Stopped));
        assert_eq!(store.reports(&me, &id("hobi"), 0).entries.len(), 1);
        assert!(store.reports(&me, &id("jin"), 0).entries.is_empty());
    }

    #[test]
    fn an_agents_citation_is_not_held_behind_a_taskers_store_write() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = Arc::new(
            TaskStore::open(
                Box::new(blobs.clone()),
                Arc::new(crate::task_store::SystemClock),
            )
            .unwrap(),
        );
        let me = Tasker::Uid(1000);
        let cited = held_by(&store, me.clone());
        store.start_for_test(&cited);
        let writing = held_by(&store, me.clone());
        store.start_for_test(&writing);
        blobs.slow(Some(std::time::Duration::from_secs(2)));
        let (s, m) = (Arc::clone(&store), me.clone());
        let slow = std::thread::spawn(move || s.follow_up(&writing, &m, text("x"), 10));
        std::thread::sleep(std::time::Duration::from_millis(200));
        let began = std::time::Instant::now();
        let resolved = crate::authz::task_for(
            crate::handler::Admission::EnrolledAgent,
            Some(&cited),
            Some(&id("hobi")),
            HOBI,
            &store,
        );
        let waited = began.elapsed();
        assert!(resolved.unwrap().is_some());
        assert!(
            waited < std::time::Duration::from_millis(500),
            "task_for waited {waited:?} behind a store write"
        );
        assert!(slow.join().unwrap().is_ok());
    }

    #[test]
    fn working_resolves_only_the_agents_own_working_task() {
        let store = Arc::new(TaskStore::new());
        let t = held_by(&store, Tasker::Uid(1000));
        assert_eq!(
            store.working(&t, &id("hobi"), HOBI).unwrap_err(),
            TaskRefusal::NotWorking
        );
        assert_eq!(
            store.working(&t, &id("jin"), HOBI).unwrap_err(),
            TaskRefusal::OtherAgent
        );
        assert_eq!(
            store
                .working(&TaskId([9; 16]), &id("hobi"), HOBI)
                .unwrap_err(),
            TaskRefusal::Unknown
        );
        store.start_for_test(&t);
        assert!(store.working(&t, &id("hobi"), HOBI).is_ok());
    }

    #[test]
    fn a_pending_task_is_seen_by_no_tasker_verb_and_is_counted_against_the_caps() {
        let store = Arc::new(TaskStore::new());
        let v = view(&[("hobi", HOBI)]);
        let me = Tasker::Uid(1000);
        let pending = store
            .mint(signer(), &v, at(0, HOBI), me.clone(), None, sub("hobi"))
            .unwrap()
            .task
            .task_id;
        assert_eq!(store.state_for(&pending, &me), None);
        assert!(store.list(&me, &id("hobi"), None, 10).0.is_empty());
        for _ in 1..MAX_LIVE_TASKS_PER_TASKER_PER_AGENT {
            mint(&store, &v, "hobi");
        }
        assert_eq!(
            store
                .mint(signer(), &v, at(0, HOBI), me.clone(), None, sub("hobi"))
                .unwrap_err(),
            TaskRefusal::TaskerLive {
                agent: "hobi".into()
            }
        );
        store.confirm(&pending, None, None).unwrap();
        assert_eq!(store.state_for(&pending, &me), Some(TaskState::Queued));
        let (page, next) = store.list(&me, &id("hobi"), None, 10);
        assert_eq!(page.len(), 10);
        assert_eq!(page[0].task.to_id(), pending);
        let (rest, none) = store.list(&me, &id("hobi"), next, 100);
        assert_eq!(rest.len(), MAX_LIVE_TASKS_PER_TASKER_PER_AGENT - 10);
        assert_eq!(none, None);
    }

    #[test]
    fn the_store_refuses_a_new_task_at_capacity_and_keeps_the_rest() {
        let store = Arc::new(TaskStore::new());
        let v = view(&[("hobi", HOBI), ("jin", JIN)]);
        let held: Vec<_> = (0..MAX_LIVE_TASKS_PER_AGENT)
            .map(|i| {
                store
                    .mint_live(
                        signer(),
                        &v,
                        at(0, HOBI),
                        Tasker::Uid(i as u32),
                        None,
                        sub("hobi"),
                    )
                    .unwrap()
            })
            .collect();
        assert_eq!(
            store
                .mint_live(
                    signer(),
                    &v,
                    at(0, HOBI),
                    Tasker::Uid(1000),
                    None,
                    sub("hobi")
                )
                .unwrap_err(),
            TaskRefusal::AtCapacity {
                agent: "hobi".into()
            }
        );
        assert_eq!(store.len(), MAX_LIVE_TASKS_PER_AGENT);
        for t in &held {
            assert!(store.resolve(&t.task.task_id, &id("hobi"), HOBI).is_ok());
        }
        mint(&store, &v, "jin");
    }

    #[test]
    fn mint_refuses_when_the_view_has_no_agent() {
        let store = Arc::new(TaskStore::new());
        assert_eq!(
            store
                .mint_live(
                    signer(),
                    &view(&[("jin", JIN)]),
                    at(0, HOBI),
                    Tasker::Uid(1000),
                    None,
                    sub("hobi")
                )
                .unwrap_err(),
            TaskRefusal::AgentGone
        );
        assert_eq!(store.len(), 0);
        assert!(matches!(
            store.mint_live(
                signer(),
                &view(&[]),
                at(0, 0),
                Tasker::Uid(1000),
                None,
                sub("Not An Id")
            ),
            Err(TaskRefusal::Schema(_))
        ));
    }

    #[test]
    fn a_mint_with_a_stale_generation_does_not_insert() {
        let store = Arc::new(TaskStore::new());
        let v = view(&[("hobi", HOBI)]);
        let read = store.generation(&id("hobi"));
        store.purge_agent(&id("hobi"));
        assert_eq!(
            store
                .mint_live(
                    signer(),
                    &v,
                    at(read, HOBI),
                    Tasker::Uid(1000),
                    None,
                    sub("hobi")
                )
                .unwrap_err(),
            TaskRefusal::AgentGone
        );
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn the_test_seam_inserts_a_task_bound_to_its_agent() {
        let store = Arc::new(TaskStore::new());
        let held = store.insert_for_test(
            signer().sign(TaskObject::for_test("hobi", 1000)).unwrap(),
            HOBI,
        );
        assert_eq!(held.task.tasker, Tasker::Uid(1000));
        assert_eq!(held.task.agent, "hobi");
        let got = store
            .resolve(&held.task.task_id, &id("hobi"), HOBI)
            .unwrap();
        assert!(Arc::ptr_eq(&got, &held));
        assert_ne!(
            TaskObject::for_test("hobi", 1).task_id,
            TaskObject::for_test("hobi", 1).task_id
        );
    }

    #[test]
    fn every_refusal_reads_as_its_cause() {
        let cases = [
            (TaskRefusal::Schema("bad".into()), "task refused: bad"),
            (TaskRefusal::Denied("no grant".into()), "no grant"),
            (
                TaskRefusal::AtCapacity {
                    agent: "hobi".into(),
                },
                "agent hobi holds 256 live tasks; no new task is taken",
            ),
            (TaskRefusal::Unknown, "no such task"),
            (TaskRefusal::OtherAgent, "the task belongs to another agent"),
            (
                TaskRefusal::ParentNotHeld,
                "the cited task is not held by the submitting agent",
            ),
            (
                TaskRefusal::AgentGone,
                "the target agent is no longer enrolled",
            ),
            (TaskRefusal::Random, "no task id could be drawn"),
            (
                TaskRefusal::Audit("sink".into()),
                "the task was not audited: sink",
            ),
            (TaskRefusal::Unsigned, "the task could not be signed"),
            (
                TaskRefusal::Store("disk".into()),
                "the task store did not write: disk",
            ),
            (TaskRefusal::CursorAhead, "cursor_ahead"),
            (
                TaskRefusal::Finished,
                "the task has already reported or closed",
            ),
            (TaskRefusal::TooLong, "the text exceeds prompt_max_bytes"),
            (
                TaskRefusal::TaskerLive {
                    agent: "hobi".into(),
                },
                "the tasker holds 32 live tasks with agent hobi",
            ),
            (
                TaskRefusal::TaskerHeld,
                "the tasker's live tasks and held reports reach 256",
            ),
            (
                TaskRefusal::FollowUps,
                "the task holds 32 follow-ups or prompt_max_bytes of them",
            ),
            (TaskRefusal::NotWorking, "the task is not working"),
            (
                TaskRefusal::Unavailable("not done: busy".into()),
                "not done: busy",
            ),
        ];
        for (refusal, text) in cases {
            assert_eq!(refusal.to_string(), text);
        }
    }

    struct Recorder(Mutex<Vec<AuditRecord>>, bool);

    impl Recorder {
        fn new() -> Self {
            Self(Mutex::default(), false)
        }
        fn failing() -> Self {
            Self(Mutex::default(), true)
        }
        fn records(&self) -> Vec<AuditRecord> {
            self.0.lock().unwrap().clone()
        }
    }

    impl AuditEmit for Recorder {
        fn emit(
            &self,
            rec: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
            self.0.lock().unwrap().push(rec.clone());
            let fail = self.1;
            async move {
                if fail {
                    Err(AuditError::Serialize("sink refused".into()))
                } else {
                    Ok(())
                }
            }
        }
    }

    fn accounts(uid: u32) -> Result<Option<maknae_io::HostAccount>, String> {
        let name = match uid {
            HOBI | HOBI_AGAIN => "hobi-svc",
            JIN => "jin-svc",
            SUGA => "suga-svc",
            _ => return Ok(None),
        };
        Ok(Some(maknae_io::HostAccount {
            uid,
            name: name.into(),
            primary_gid: uid,
            shell: "/usr/sbin/nologin".into(),
            dir: "/var/empty".into(),
            named_groups: Vec::new(),
        }))
    }

    fn me() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    type Pdp = Arc<Composition<HermeticAuthorizer>>;

    /// hobi takes tasks from people; jin from hobi and suga; suga's own policy denies `session.task`.
    fn pdp(tag: &str) -> (DirGuard, Pdp) {
        let name = nix::unistd::User::from_uid(nix::unistd::geteuid())
            .unwrap()
            .unwrap()
            .name;
        let bindings = format!("schema_version: 1\nbindings:\n  user: [\"{name}\"]\n");
        let (g, basic) = fixture(&format!("task-{tag}"), AUTHZ, Some(&bindings));
        basic.set_hosts(maknae_authz_basic::HostLookups {
            account: accounts,
            ..crate::test_fixtures::HOBI_HOSTS
        });
        for (agent, uid, policy) in [
            ("hobi", HOBI, None),
            (
                "jin",
                JIN,
                Some("schema_version: 1\ntaskers: [\"agent:hobi\", \"agent:suga\"]\n"),
            ),
            (
                "suga",
                SUGA,
                Some("schema_version: 1\nactions:\n  allow: [\"session.task\"]\n  deny: [\"session.task\"]\n"),
            ),
        ] {
            crate::test_fixtures::write_agent(&g.0, agent, &format!("{agent}-svc"), uid, "user");
            if let Some(p) = policy {
                crate::test_fixtures::write_agent_policy(&g.0, agent, p);
            }
        }
        basic.reload_from_file().unwrap();
        let pdp = Arc::new(Composition::new(
            basic,
            crate::CeilingAuthorizer::new(
                maknae_config::Ceiling::baseline_for(&maknae_config::BasicPolicy),
                &maknae_config::BasicPolicy,
            ),
        ));
        assert_eq!(pdp.baseline().snapshot().agent_uid("suga"), Some(SUGA));
        (g, pdp)
    }

    struct Hooked<P> {
        inner: Arc<P>,
        calls: AtomicUsize,
        after: Box<dyn Fn() + Send + Sync>,
    }

    fn hooked<P>(inner: Arc<P>, after: impl Fn() + Send + Sync + 'static) -> Arc<Hooked<P>> {
        Arc::new(Hooked {
            inner,
            calls: AtomicUsize::new(0),
            after: Box::new(after),
        })
    }

    impl<P: Authorizer> Authorizer for Hooked<P> {
        fn decide(&self, req: &Request) -> Verdict {
            self.decide_cited(req).verdict
        }
        fn decide_reporting_role(&self, req: &Request) -> (Verdict, Option<&'static str>) {
            let d = self.decide_cited(req);
            (d.verdict, d.role)
        }
        fn decide_cited(&self, req: &Request) -> Decided {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let decided = self.inner.decide_cited(req);
            (self.after)();
            decided
        }
        fn decide_cited_all(&self, reqs: &[Request]) -> Vec<Decided> {
            reqs.iter().map(|r| self.decide_cited(r)).collect()
        }
    }

    fn user() -> Submitter {
        Submitter::User {
            uid: me(),
            home: None,
        }
    }

    fn agent(name: &str, uid: u32, under: Option<TaskId>) -> Submitter {
        Submitter::Agent {
            agent: id(name),
            uid,
            home: None,
            under,
        }
    }

    fn wctx() -> crate::run::WhereCtx {
        crate::run::WhereCtx {
            host: "task-host".into(),
            socket: "/run/maknae/task-11.sock".into(),
            au3_1: serde_json::json!({ "site": "task-11" }),
        }
    }

    async fn submit_via<
        P: Authorizer + Send + Sync + 'static,
        V: EnrollmentView + Clone + 'static,
    >(
        a: Arc<P>,
        store: &Arc<TaskStore>,
        v: &V,
        by: Submitter,
        sub: TaskSubmission,
        emit: &impl AuditEmit,
        (bound, breaker): (std::time::Duration, Option<Breaker>),
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let w = wctx();
        let seq = maknae_audit_append::Seq::new();
        let ctx = SubmitCtx {
            where_: &w,
            session_id: SESSION,
            seq: &seq,
            user: Some("alice"),
            peer_uri: None,
            lane: maknae_security::Lane::Local,
            decide_timeout: bound,
            text_max: 1 << 20,
        };
        let pdp = Decider {
            authorizer: a,
            breaker: breaker.unwrap_or_default(),
        };
        let v: Arc<dyn EnrollmentView> = Arc::new(v.clone());
        submit_under(pdp, store, &shared_signer(), &v, &ctx, by, sub, emit).await
    }

    async fn submit(
        pdp: &Pdp,
        store: &Arc<TaskStore>,
        by: Submitter,
        to: &str,
        emit: &Recorder,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let view = SnapshotEnrollment(pdp.clone());
        submit_via(pdp.clone(), store, &view, by, sub(to), emit, (BOUND, None)).await
    }

    struct BreaksStoreOnAudit(Recorder, crate::task_store::MemTaskBlobs);

    impl AuditEmit for BreaksStoreOnAudit {
        fn emit(
            &self,
            rec: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
            self.1.fail(Some(crate::task_store::Fail::Records));
            self.0.emit(rec)
        }
    }

    #[tokio::test]
    async fn a_kept_task_whose_pending_mark_cannot_clear_is_outcome_unknown() {
        let (_g, pdp) = pdp("unconfirmed");
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = Arc::new(
            TaskStore::open(
                Box::new(blobs.clone()),
                Arc::new(crate::task_store::SystemClock),
            )
            .unwrap(),
        );
        let emit = BreaksStoreOnAudit(Recorder::new(), blobs.clone());
        let view = SnapshotEnrollment(pdp.clone());
        let got = submit_via(
            pdp.clone(),
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (BOUND, None),
        )
        .await;
        assert!(matches!(got, Err(TaskRefusal::Unavailable(_))), "{got:?}");
        let trail: Vec<(String, String, String)> = emit
            .0
            .records()
            .iter()
            .map(|r| {
                (
                    r.outcome.result.clone(),
                    r.outcome.reason.clone(),
                    r.outcome.posture.clone(),
                )
            })
            .collect();
        assert_eq!(trail.len(), 2, "{trail:?}");
        assert_eq!(trail[0].1, "task stored");
        assert_eq!(trail[1].0, "deny");
        let seqs: Vec<u64> = emit.0.records().iter().map(|r| r.seq).collect();
        assert_eq!(
            seqs[1],
            seqs[0] + 1,
            "the corrective record has its own seq"
        );
        assert!(trail[1].1.starts_with("outcome unknown: "), "{trail:?}");
        assert!(!trail[1].1.contains("withdraw"), "{trail:?}");
        assert_eq!(trail[1].2, "unavailable");
        assert_eq!(store.len(), 0);
        assert!(
            !store
                .take_notices()
                .iter()
                .any(|n| matches!(n, Notice::Late { .. })),
            "a refusal the submission was told is not late"
        );
        blobs.fail(None);
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert_eq!(reopened.len(), 0);
        assert!(matches!(
            reopened.take_boot_findings()[..],
            [crate::task_store::BootFinding::Discarded { .. }]
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_mint_that_collides_then_times_out_leaves_nothing_behind() {
        let _alone = STALLS.lock().await;
        let (_g, pdp) = pdp("abandoned-mint");
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = Arc::new(
            TaskStore::open(
                Box::new(blobs.clone()),
                Arc::new(crate::task_store::SystemClock),
            )
            .unwrap(),
        );
        let mut taken = TaskObject::for_test("hobi", 0);
        taken.task_id = TaskId([7; 16]);
        taken.tasker = Tasker::Uid(999);
        store.insert_for_test(signer().sign(taken).unwrap(), HOBI);
        *store.scripted.lock().unwrap() = vec![[8; 16], [7; 16]];
        blobs.slow(Some(std::time::Duration::from_millis(2000)));
        let view = SnapshotEnrollment(pdp.clone());
        let emit = Recorder::new();
        let got = submit_via(
            pdp.clone(),
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (std::time::Duration::from_millis(400), None),
        )
        .await;
        assert!(matches!(got, Err(TaskRefusal::Unavailable(_))), "{got:?}");
        blobs.await_stalls(1);
        blobs.slow(None);
        store.quiesce();
        assert!(
            store.record(&TaskId([7; 16])).is_some(),
            "the colliding task is kept"
        );
        assert_eq!(store.len(), 1, "no pending record is left behind");
        assert!(!blobs.has(&name_of(&TaskId([8; 16]))));
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert!(reopened.take_boot_findings().is_empty());
    }

    /// The tests that stall the store share the euid's store slots; they take turns.
    static STALLS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct SlowsStoreOnAudit(Recorder, crate::task_store::MemTaskBlobs);

    impl AuditEmit for SlowsStoreOnAudit {
        fn emit(
            &self,
            rec: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
            assert!(
                !rec.outcome.reason.starts_with("task held"),
                "{}",
                rec.outcome.reason
            );
            self.1.slow(Some(std::time::Duration::from_millis(2000)));
            self.0.emit(rec)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_confirm_that_times_out_once_kept_is_outcome_unknown_and_may_reload_live() {
        let _alone = STALLS.lock().await;
        let (_g, pdp) = pdp("confirm-timeout");
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = Arc::new(
            TaskStore::open(
                Box::new(blobs.clone()),
                Arc::new(crate::task_store::SystemClock),
            )
            .unwrap(),
        );
        let emit = SlowsStoreOnAudit(Recorder::new(), blobs.clone());
        let view = SnapshotEnrollment(pdp.clone());
        let got = submit_via(
            pdp.clone(),
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (std::time::Duration::from_millis(400), None),
        )
        .await;
        let Err(TaskRefusal::Unavailable(said)) = got else {
            panic!("{got:?}");
        };
        assert_eq!(said, format!("outcome unknown: {LATE}"));
        assert_eq!(emit.0.records().len(), 2);
        let corrective = emit.0.records().pop().unwrap();
        assert_eq!(corrective.outcome.reason, said);
        blobs.await_stalls(1);
        blobs.slow(None);
        store.quiesce();
        assert_eq!(store.len(), 1);
        assert!(store.abandoned.lock().unwrap().is_empty());
        let stored = store.queue(&id("hobi"))[0];
        assert_eq!(
            store.take_notices(),
            vec![Notice::Late {
                task: stored,
                tasker: Tasker::Uid(me()),
                failed: None
            }],
            "the late outcome is said once"
        );
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert_eq!(reopened.len(), 1, "what was kept reloads");
        assert!(reopened.take_boot_findings().is_empty());
    }

    struct HoldsWriterOnAudit {
        trail: Recorder,
        store: Arc<TaskStore>,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl AuditEmit for HoldsWriterOnAudit {
        fn emit(
            &self,
            rec: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
            if let Some(release) = self.release.lock().unwrap().take() {
                let (store, (held, holding)) =
                    (Arc::clone(&self.store), std::sync::mpsc::channel());
                std::thread::spawn(move || {
                    let _w = store.writer.lock().unwrap();
                    held.send(()).unwrap();
                    let _ = release.recv();
                });
                holding.recv().unwrap();
            }
            self.trail.emit(rec)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_confirm_given_up_before_it_is_kept_writes_nothing_and_is_not_done() {
        let _alone = STALLS.lock().await;
        let (_g, pdp) = pdp("confirm-not-started");
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = Arc::new(
            TaskStore::open(
                Box::new(blobs.clone()),
                Arc::new(crate::task_store::SystemClock),
            )
            .unwrap(),
        );
        let (release, gate) = std::sync::mpsc::channel();
        let emit = HoldsWriterOnAudit {
            trail: Recorder::new(),
            store: Arc::clone(&store),
            release: Mutex::new(Some(gate)),
        };
        let view = SnapshotEnrollment(pdp.clone());
        let got = submit_via(
            pdp.clone(),
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (std::time::Duration::from_millis(400), None),
        )
        .await;
        assert!(matches!(got, Err(TaskRefusal::Unavailable(_))), "{got:?}");
        let corrective = emit.trail.records().pop().unwrap();
        assert!(
            corrective.outcome.reason.starts_with("not done: "),
            "{}",
            corrective.outcome.reason
        );
        release.send(()).unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while store.len() != 0 || !store.abandoned.lock().unwrap().is_empty() {
            assert!(std::time::Instant::now() < until, "the task is withdrawn");
            store.purge_agent(&id("nobody"));
            tokio::task::yield_now().await;
        }
        store.quiesce();
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert_eq!(reopened.len(), 0);
        assert!(
            reopened.take_boot_findings().is_empty(),
            "never confirmed, and unlinked"
        );
    }

    #[test]
    fn a_confirm_whose_ticket_was_abandoned_leaves_the_record_pending() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let v = view(&[("hobi", HOBI)]);
        let enrolled = at(store.generation(&id("hobi")), HOBI);
        let task = store
            .mint(signer(), &v, enrolled, Tasker::Uid(1000), None, sub("hobi"))
            .unwrap()
            .task
            .task_id;
        let ticket = Ticket::default();
        assert_eq!(ticket.abandon(), None);
        blobs.after_save(|| panic!("an abandoned confirm writes nothing"));
        assert!(store.confirm(&task, Some(&ticket), None).is_err());
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert_eq!(reopened.len(), 0);
        assert!(matches!(
            reopened.take_boot_findings()[..],
            [crate::task_store::BootFinding::Discarded { .. }]
        ));
    }

    #[test]
    fn a_ticket_is_kept_before_the_confirm_writes() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let v = view(&[("hobi", HOBI)]);
        let enrolled = at(store.generation(&id("hobi")), HOBI);
        let task = store
            .mint(signer(), &v, enrolled, Tasker::Uid(1000), None, sub("hobi"))
            .unwrap()
            .task
            .task_id;
        let ticket = Arc::new(Ticket::default());
        let seen = Arc::new(Mutex::new(None));
        let (t, s) = (Arc::clone(&ticket), Arc::clone(&seen));
        blobs.after_save(move || *s.lock().unwrap() = Some(t.abandon()));
        assert_eq!(store.confirm(&task, Some(&ticket), None), Ok(()));
        assert_eq!(
            *seen.lock().unwrap(),
            Some(Some(task)),
            "kept before the write"
        );
        assert!(store.record(&task).is_some());
    }

    #[test]
    fn a_withdrawal_whose_disk_step_fails_is_kept_for_the_next_writer() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let kept = held_by(&store, me.clone());
        blobs.fail(Some(crate::task_store::Fail::Records));
        assert!(!store.withdraw(&kept));
        blobs.fail(None);
        assert!(
            store.record(&kept).is_none(),
            "held back pending, so invisible"
        );
        assert!(blobs.has(&name_of(&kept)));
        held_by(&store, me);
        assert!(!blobs.has(&name_of(&kept)), "the next writer finished it");
        assert_eq!(store.len(), 1);
        let unwound = TaskId([3; 16]);
        drop(PutBack {
            store: &store,
            id: Some(unwound),
        });
        assert_eq!(*store.abandoned.lock().unwrap(), vec![unwound]);
    }

    #[tokio::test]
    async fn a_withdrawal_runs_or_is_queued_never_both_and_is_said_so() {
        let store = Arc::new(TaskStore::new());
        let id = held_by(&store, Tasker::Uid(1000));
        let w = withdraw_within(&store, 1000, tokio::time::Instant::now(), id).await;
        let queued = || store.abandoned.lock().unwrap().clone();
        match w {
            Withdrawal::Done => {
                assert!(queued().is_empty(), "done here is never also queued");
                assert!(store.record(&id).is_none());
            }
            Withdrawal::Queued => assert_eq!(queued(), vec![id]),
            Withdrawal::Running => {
                let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while store.record(&id).is_some() || !queued().is_empty() {
                    assert!(
                        std::time::Instant::now() < until,
                        "the one running finishes"
                    );
                    tokio::task::yield_now().await;
                }
            }
        }
        let again = held_by(&store, Tasker::Uid(1000));
        let w = withdraw_within(&store, 1000, tokio::time::Instant::now() + BOUND, again).await;
        assert_eq!(w.said(), "withdrawn");
        assert!(store.abandoned.lock().unwrap().is_empty());
        assert_eq!(
            Withdrawal::Queued.said(),
            "withdrawal left to the next store write"
        );
        assert_eq!(Withdrawal::Running.said(), "withdrawal outcome unknown");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_withdrawal_still_running_at_the_bound_is_not_also_queued() {
        let _alone = STALLS.lock().await;
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = Arc::new(
            TaskStore::open(
                Box::new(blobs.clone()),
                Arc::new(crate::task_store::SystemClock),
            )
            .unwrap(),
        );
        let id = held_by(&store, Tasker::Uid(1000));
        blobs.slow(Some(std::time::Duration::from_millis(400)));
        let w = withdraw_within(
            &store,
            1000,
            tokio::time::Instant::now() + std::time::Duration::from_millis(100),
            id,
        )
        .await;
        assert_eq!(w.said(), "withdrawal outcome unknown");
        assert!(store.abandoned.lock().unwrap().is_empty());
        blobs.await_stalls(1);
        blobs.slow(None);
        store.quiesce();
        assert!(!blobs.has(&name_of(&id)));
    }

    #[test]
    fn whichever_of_mint_and_submission_moves_first_decides_the_record() {
        let kept = Ticket::default();
        assert!(kept.keep(TaskId([1; 16])));
        assert_eq!(kept.abandon(), Some(TaskId([1; 16])));
        let given_up = Ticket::default();
        assert_eq!(given_up.abandon(), None);
        assert!(given_up.abandoned());
        assert!(!given_up.keep(TaskId([2; 16])));
    }

    #[test]
    fn an_abandoned_or_withdrawn_task_never_reloads() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let queued = held_by(&store, me.clone());
        store.abandon(queued);
        assert!(
            store.record(&queued).is_some(),
            "only the next writer withdraws"
        );
        held_by(&store, me.clone());
        assert!(store.record(&queued).is_none());
        assert!(!blobs.has(&name_of(&queued)));

        let kept = held_by(&store, me);
        blobs.fail(Some(crate::task_store::Fail::Unlinks));
        store.withdraw(&kept);
        blobs.fail(None);
        assert!(store.record(&kept).is_none());
        assert!(blobs.has(&name_of(&kept)), "the unlink was refused");
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert!(reopened.record(&kept).is_none());
        assert!(matches!(
            reopened.take_boot_findings()[..],
            [crate::task_store::BootFinding::Discarded { task, .. }] if task == kept
        ));
    }

    enum Via {
        Withdraw,
        Queue,
    }

    /// The disk fails as `fail` while a confirmed record is taken back by `via`, and
    /// through one retry; then it recovers, one writer passes, and the host crashes.
    fn nothing_reloads_after(fail: crate::task_store::Fail, via: Via) {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let nobody = id("nobody");
        let task = match via {
            Via::Withdraw => {
                let task = held_by(&store, Tasker::Uid(1000));
                blobs.fail(Some(fail));
                assert!(!store.withdraw(&task), "not proven off the disk");
                task
            }
            Via::Queue => {
                let task = held_by(&store, Tasker::Uid(1000));
                store.abandon(task);
                blobs.fail(Some(fail));
                store.purge_agent(&nobody);
                task
            }
        };
        store.purge_agent(&nobody);
        assert!(store.record(&task).is_none());
        blobs.fail(None);
        store.purge_agent(&nobody);
        blobs.crash(0);
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert_eq!(reopened.len(), 0, "no live task reloads");
    }

    #[test]
    fn a_withdrawal_whose_retry_fails_too_is_still_owed() {
        nothing_reloads_after(crate::task_store::Fail::Records, Via::Withdraw);
    }

    #[test]
    fn a_withdrawal_marked_pending_unsynced_and_not_unlinked_is_still_owed() {
        nothing_reloads_after(crate::task_store::Fail::UnsyncedNoUnlink, Via::Withdraw);
    }

    #[test]
    fn a_queued_withdrawal_whose_retry_fails_too_is_still_owed() {
        nothing_reloads_after(crate::task_store::Fail::Records, Via::Queue);
    }

    #[test]
    fn a_queued_withdrawal_marked_pending_unsynced_and_not_unlinked_is_still_owed() {
        nothing_reloads_after(crate::task_store::Fail::UnsyncedNoUnlink, Via::Queue);
    }

    enum Gone {
        Dropped,
        Acknowledged,
    }

    /// The disk fails as `fail` while a stored record is removed; then it recovers, one
    /// writer passes, and the host crashes.
    fn nothing_removed_reloads_after(fail: crate::task_store::Fail, gone: Gone) {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let task = held_by(&store, me.clone());
        match gone {
            Gone::Dropped => {
                blobs.fail(Some(fail));
                let said = store.drop_queued(&task, &me).unwrap_err();
                assert!(
                    matches!(&said, TaskRefusal::Unavailable(why) if why.starts_with("outcome unknown: ")),
                    "{said:?}"
                );
            }
            Gone::Acknowledged => {
                let rseq = store.publish_report(&task, text("r"), None).unwrap();
                blobs.fail(Some(fail));
                let said = store.acknowledge(&me, &id("hobi"), rseq).unwrap_err();
                assert!(
                    matches!(&said, TaskRefusal::Unavailable(why) if why.starts_with("outcome unknown: ")),
                    "{said:?}"
                );
            }
        }
        assert!(store.record(&task).is_none());
        blobs.fail(None);
        store.purge_agent(&id("nobody"));
        assert!(!blobs.has(&name_of(&task)));
        blobs.crash(0);
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert_eq!(reopened.len(), 0, "no removed task reloads");
    }

    fn mem() -> (crate::task_store::MemTaskBlobs, TaskStore) {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        (blobs, store)
    }

    fn reopen(blobs: &crate::task_store::MemTaskBlobs) -> TaskStore {
        TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap()
    }

    fn closed(store: &TaskStore, task: &TaskId) -> Option<TaskClose> {
        store
            .record(task)
            .filter(|r| r.state == TaskState::Closed)
            .and_then(|r| r.close)
    }

    fn containing(uids: &[u32]) -> crate::enrollment::Containing<FixedEnrollment> {
        crate::enrollment::Containing(
            view(&[("hobi", HOBI), ("jin", JIN)]),
            uids.iter().copied().collect(),
        )
    }

    fn gone(task: TaskId, recorded: bool) -> Due {
        Due {
            task,
            agent: id("hobi"),
            tasker: Tasker::Uid(1000),
            parent: None,
            why: DueFor::Close(TaskClose::AgentGone),
            recorded,
        }
    }

    /// The disk fails as `fail` while a recorded close is performed: the task stays as
    /// it was, marked, and nothing of the close is shown until a synced write.
    fn a_close_is_not_shown_until_stored_through(fail: crate::task_store::Fail) {
        let (blobs, store) = mem();
        let me = Tasker::Uid(1000);
        let task = held_by(&store, me.clone());
        blobs.fail(Some(fail));
        assert_eq!(store.purge_agent(&id("hobi")), vec![gone(task, false)]);
        assert_eq!(closed(&store, &task), None);
        assert_eq!(store.state_for(&task, &me), Some(TaskState::Queued));
        assert!(store
            .reports(&me, &id("hobi"), usize::MAX)
            .entries
            .is_empty());
        assert_eq!(store.list(&me, &id("hobi"), None, 8).0[0].close, None);
        assert_eq!(
            claim_head(&store, &id("hobi"), HOBI, signer()),
            Ok(Claimed::Idle),
            "marked: an agent enrolled again under the same uid is handed nothing"
        );
        assert_eq!(
            store.due(8),
            vec![gone(task, true)],
            "still due, already recorded"
        );
        let said = store.take_notices();
        assert!(
            matches!(&said[..], [Notice::Owed { task: t, .. }] if *t == task),
            "{said:?}"
        );
        assert!(store.purge_agent(&id("hobi")).is_empty(), "recorded once");
        assert!(store.take_notices().is_empty(), "owed once");
        blobs.fail(None);
        assert!(store.close_all_due().is_empty());
        assert_eq!(closed(&store, &task), Some(TaskClose::AgentGone));
        assert!(store.record(&task).unwrap().rseq.is_some());
        assert_eq!(store.take_notices(), vec![Notice::Settled { task }]);
        assert!(store.due(8).is_empty());
        let held = store.held();
        assert!(held.closing.is_empty() && held.recorded.is_empty());
        drop(held);
        blobs.crash(0);
        let reopened = reopen(&blobs);
        assert_eq!(closed(&reopened, &task), Some(TaskClose::AgentGone));
        let page = reopened.reports(&me, &id("hobi"), usize::MAX);
        assert_eq!(page.entries.len(), 1, "the notice is collectable");
        assert_eq!(page.entries[0].close, Some(TaskClose::AgentGone));
        assert!(page.entries[0].text.0.is_empty());
    }

    #[test]
    fn a_close_whose_record_is_refused_is_not_shown_until_it_is_stored() {
        a_close_is_not_shown_until_stored_through(crate::task_store::Fail::Records);
    }

    #[test]
    fn a_close_whose_record_lands_unsynced_is_not_shown_until_it_is_stored() {
        a_close_is_not_shown_until_stored_through(crate::task_store::Fail::Unsynced);
    }

    #[test]
    fn a_close_whose_ordinal_cannot_be_issued_is_not_shown_until_it_is_stored() {
        a_close_is_not_shown_until_stored_through(crate::task_store::Fail::Every);
    }

    #[test]
    fn a_close_that_lands_after_a_later_report_was_acknowledged_is_still_collected() {
        let (blobs, store) = mem();
        let me = Tasker::Uid(1000);
        let hobi = id("hobi");
        let closing = held_by(&store, me.clone());
        let reporting = held_by(&store, me.clone());
        store.start_for_test(&closing);
        blobs.stick(Some(name_of(&closing)));
        store.held().closing.insert(closing, TaskClose::AgentLost);
        assert_eq!(store.perform(&store.due(8)), 0, "the close is refused");
        let reported = store.publish_report(&reporting, text("r"), None).unwrap();
        let page = store.reports(&me, &hobi, usize::MAX);
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].cursor.seq(), reported);
        blobs.stick(None);
        assert_eq!(store.perform(&store.due(8)), 1, "the close lands");
        assert_eq!(store.acknowledge(&me, &hobi, reported), Ok(1));
        let page = store.reports(&me, &hobi, usize::MAX);
        assert_eq!(page.entries.len(), 1, "the close was not removed unseen");
        assert_eq!(page.entries[0].close, Some(TaskClose::AgentLost));
        assert!(page.entries[0].cursor.seq() > reported);
    }

    #[test]
    fn a_record_left_pending_by_a_removal_is_found_at_boot_as_withdrawn() {
        let (blobs, store) = mem();
        let task = held_by(&store, Tasker::Uid(1000));
        blobs.fail(Some(crate::task_store::Fail::Unlinks));
        assert!(store.withdraw(&task));
        blobs.fail(None);
        let found = reopen(&blobs).take_boot_findings();
        assert!(
            matches!(
                &found[..],
                [crate::task_store::BootFinding::Discarded { task: t, removing: true, .. }]
                    if *t == task
            ),
            "{found:?}"
        );
    }

    #[test]
    fn a_task_marked_for_a_hold_is_refused_everything_before_the_hold_is_stored() {
        let (blobs, store) = mem();
        let me = Tasker::Uid(1000);
        let hobi = id("hobi");
        let working = held_by(&store, me.clone());
        let queued = held_by(&store, me.clone());
        let reported = held_by(&store, me.clone());
        store.start_for_test(&working);
        let rseq = store.publish_report(&reported, text("r"), None).unwrap();
        store.held().closing.insert(queued, TaskClose::AgentGone);
        store.held().hold_contained(&containing(&[1000]));
        blobs.fail(Some(crate::task_store::Fail::Records));
        let due = store.due(8);
        assert!(
            due.iter().all(|d| matches!(d.why, DueFor::Hold(_))),
            "{due:?}"
        );
        assert_eq!(due.len(), 3, "a hold outranks a close and an expiry");
        assert_eq!(store.perform(&due), 0);
        assert!(store.due(8).iter().all(|d| d.recorded));
        assert_eq!(store.record(&working).unwrap().state, TaskState::Working);
        assert_eq!(claim_head(&store, &hobi, HOBI, signer()), Ok(Claimed::Idle));
        assert_eq!(store.heartbeat(&hobi, HOBI, 0, 0), Heartbeat::Idle);
        assert_eq!(
            store.working(&working, &hobi, HOBI),
            Err(TaskRefusal::Unknown)
        );
        assert_eq!(
            store.report(&working, &hobi, HOBI, text("late")),
            Err(TaskRefusal::AgentGone)
        );
        assert_eq!(
            store
                .follow_up(&working, &me, text("more"), 100)
                .unwrap_err(),
            TaskRefusal::NotWorking
        );
        assert_eq!(
            store.stop(&working, &me).unwrap_err(),
            TaskRefusal::Finished
        );
        assert_eq!(
            store.drop_queued(&queued, &me).unwrap_err(),
            TaskRefusal::Finished
        );
        assert_eq!(store.acknowledge(&me, &hobi, rseq), Ok(0));
        assert!(store.reports(&me, &hobi, usize::MAX).entries.is_empty());
        let said = store.take_notices();
        assert!(matches!(&said[..], [Notice::Owed { .. }]), "{said:?}");
        blobs.fail(None);
        store.pass();
        assert!(store.take_notices().is_empty(), "the hold is still owed");
        assert_eq!(store.perform(&store.due(8)), 3);
        for (task, from) in [
            (working, TaskState::Working),
            (queued, TaskState::Queued),
            (reported, TaskState::Reported),
        ] {
            let rec = reopen(&blobs).record(&task).unwrap();
            assert_eq!((rec.state, rec.held_from), (TaskState::Held, Some(from)));
        }
        let held = store.held();
        assert!(held.holding.is_empty() && held.hold_said.is_empty() && held.closing.is_empty());
        drop(held);
        assert!(matches!(
            store.heartbeat(&hobi, HOBI, 0, 0),
            Heartbeat::Closed(v) if v.state == TaskState::Held
        ));
        store
            .held()
            .hold_contained(&containing(&[1000, 1001, HOBI]));
        assert!(store.due(8).is_empty(), "a held task is held once");
    }

    #[test]
    fn a_sub_task_is_taken_only_under_a_working_parent_due_no_hold_or_close() {
        let (_blobs, store) = mem();
        let v = view(&[("hobi", HOBI), ("jin", JIN)]);
        let hobis = || Tasker::Agent {
            agent: "hobi".into(),
            uid: HOBI,
        };
        let under = |store: &TaskStore, view: &dyn EnrollmentView, parent: TaskId| {
            store
                .mint_live(
                    signer(),
                    view,
                    at(0, JIN),
                    hobis(),
                    Some(parent),
                    sub("jin"),
                )
                .map(|t| t.task.task_id)
        };
        let parent = held_by(&store, Tasker::Uid(1000));
        assert_eq!(under(&store, &v, parent), Err(TaskRefusal::ParentNotHeld));
        store.start_for_test(&parent);
        let child = under(&store, &v, parent).unwrap();
        assert_eq!(
            store.record(&child).unwrap().root,
            RootTasker::Person { uid: 1000 }
        );
        store.mark_unenrolled(&containing(&[1000]));
        assert_eq!(
            under(&store, &v, parent),
            Err(TaskRefusal::ParentNotHeld),
            "the parent is due a hold"
        );
        store.close_all_due();
        assert_eq!(store.record(&parent).unwrap().state, TaskState::Held);
        assert_eq!(
            under(&store, &v, parent),
            Err(TaskRefusal::ParentNotHeld),
            "the parent is held"
        );
        let closing = held_by(&store, Tasker::Uid(1001));
        store.start_for_test(&closing);
        store.held().closing.insert(closing, TaskClose::AgentLost);
        assert_eq!(
            under(&store, &v, closing),
            Err(TaskRefusal::ParentNotHeld),
            "the parent is due a close"
        );
    }

    #[test]
    fn a_submission_is_not_stored_when_its_tasker_root_or_agent_is_contained() {
        let (blobs, store) = mem();
        let v = view(&[("hobi", HOBI), ("jin", JIN)]);
        let before = store.len();
        for contained in [1000, HOBI] {
            let said = store.mint(
                signer(),
                &crate::enrollment::Containing(v.clone(), [contained].into()),
                at(0, HOBI),
                Tasker::Uid(1000),
                None,
                sub("hobi"),
            );
            assert_eq!(
                said.map(|t| t.task.task_id),
                Err(TaskRefusal::Denied(CONTAINED.into())),
                "{contained}"
            );
        }
        assert_eq!(store.len(), before);
        assert!(reopen(&blobs).take_boot_findings().is_empty());
    }

    #[test]
    fn a_submission_marked_before_its_confirm_is_stored_held_never_queued() {
        let (blobs, store) = mem();
        let v = view(&[("hobi", HOBI)]);
        let task = store
            .mint(
                signer(),
                &v,
                at(0, HOBI),
                Tasker::Uid(1000),
                None,
                sub("hobi"),
            )
            .unwrap()
            .task
            .task_id;
        assert_eq!(store.hold_mark(&task), None);
        store.mark_unenrolled(&containing(&[1000]));
        assert_eq!(store.hold_mark(&task), Some(Contained::Tasker));
        assert!(store.due(8).is_empty(), "not yet a task");
        store.pass();
        assert_eq!(
            store.hold_mark(&task),
            Some(Contained::Tasker),
            "a writer passing keeps the mark of a submission not yet confirmed"
        );
        assert_eq!(
            store.confirm(&task, None, None),
            Err(TaskRefusal::Unavailable(DUE_A_HOLD.into())),
            "not published as queued work"
        );
        assert!(store.record(&task).is_none());
        assert_eq!(store.confirm(&task, None, Some(Contained::Tasker)), Ok(()));
        let rec = store.record(&task).unwrap();
        assert_eq!(
            (rec.state, rec.held_from),
            (TaskState::Held, Some(TaskState::Queued))
        );
        assert_eq!(store.hold_mark(&task), None);
        store.mark_unenrolled(&v);
        assert!(store.close_all_due().is_empty(), "a release lifts no hold");
        assert_eq!(
            claim_head(&store, &id("hobi"), HOBI, signer()),
            Ok(Claimed::Idle)
        );
        let reopened = reopen(&blobs);
        assert_eq!(reopened.record(&task).unwrap().state, TaskState::Held);
    }

    #[test]
    fn an_expiry_selected_before_a_hold_landed_removes_nothing() {
        let (blobs, clock, store) = clocked();
        let me = Tasker::Uid(1000);
        let task = held_by(&store, me.clone());
        store.publish_report(&task, text("evidence"), None).unwrap();
        clock.set(1_000 + REPORT_HOLD.as_secs() as i64);
        let stale = store.due(8);
        assert_eq!(stale[0].why, DueFor::Expiry);
        store.mark_unenrolled(&containing(&[1000]));
        assert_eq!(store.close_all_due().len(), 1, "the hold lands");
        assert_eq!(store.record(&task).unwrap().state, TaskState::Held);
        assert_eq!(store.perform(&stale), 0, "the old expiry finds a held task");
        assert_eq!(store.record(&task).unwrap().state, TaskState::Held);
        assert!(blobs.has(&name_of(&task)));
        assert_eq!(reopen(&blobs).record(&task).unwrap().state, TaskState::Held);
    }

    #[test]
    fn a_standing_found_good_on_another_policy_load_starts_nothing() {
        let (_blobs, store) = mem();
        let hobi = id("hobi");
        let task = held_by(&store, Tasker::Uid(1000));
        let old: Arc<dyn std::any::Any + Send + Sync> = Arc::new(0u8);
        let decided = GoodStanding {
            task,
            load: Load::installed(old),
        };
        assert_eq!(
            store.claim(&hobi, HOBI, signer(), &view(&[]), Some(&decided)),
            Ok(Claimed::Idle),
            "the policy was replaced after the decision"
        );
        assert_eq!(store.record(&task).unwrap().state, TaskState::Queued);
        assert_eq!(store.hot(&task).unwrap().retry_after, 0);
        assert!(matches!(
            claim_as(&store, &hobi, HOBI, signer(), Some(task)),
            Ok(Claimed::Delivered { .. })
        ));
    }

    #[test]
    fn a_queued_task_is_started_only_when_it_is_the_one_just_decided() {
        let (_blobs, store) = mem();
        let me = Tasker::Uid(1000);
        let hobi = id("hobi");
        let first = held_by(&store, me.clone());
        let second = held_by(&store, me.clone());
        assert_eq!(
            claim_as(&store, &hobi, HOBI, signer(), None),
            Ok(Claimed::Idle)
        );
        assert_eq!(
            claim_as(&store, &hobi, HOBI, signer(), Some(second)),
            Ok(Claimed::Idle),
            "the decided task is not the head"
        );
        store.drop_queued(&first, &me).unwrap();
        assert_eq!(
            claim_as(&store, &hobi, HOBI, signer(), Some(first)),
            Ok(Claimed::Idle),
            "the head changed after the decision: the new head was never decided"
        );
        assert_eq!(store.record(&second).unwrap().state, TaskState::Queued);
        assert_eq!(
            store.hot(&second).unwrap().retry_after,
            0,
            "no back-off for it"
        );
        assert!(matches!(
            claim_as(&store, &hobi, HOBI, signer(), Some(second)),
            Ok(Claimed::Delivered { .. })
        ));
    }

    #[test]
    fn a_claim_decided_on_a_working_head_starts_no_queued_task_once_that_head_finishes() {
        let (_blobs, store) = mem();
        let hobi = id("hobi");
        let working = held_by(&store, Tasker::Uid(1000));
        let queued = held_by(&store, Tasker::Uid(1000));
        store.start_for_test(&working);
        assert_eq!(
            store.next_for(&hobi, HOBI),
            Some((working, TaskState::Working)),
            "nothing is decided for a working head"
        );
        store.report(&working, &hobi, HOBI, text("done")).unwrap();
        assert_eq!(
            claim_as(&store, &hobi, HOBI, signer(), None),
            Ok(Claimed::Idle)
        );
        assert_eq!(store.record(&queued).unwrap().state, TaskState::Queued);
        store.start_for_test(&queued);
        assert!(
            matches!(
                claim_as(&store, &hobi, HOBI, signer(), None),
                Ok(Claimed::Delivered { .. })
            ),
            "a working task is handed again with no decision"
        );
    }

    #[test]
    fn a_task_marked_for_a_hold_while_its_claim_is_written_is_not_handed_out() {
        let (blobs, store) = mem();
        let store = Arc::new(store);
        let task = held_by(&store, Tasker::Uid(1000));
        let marking = Arc::clone(&store);
        blobs.after_save(move || marking.mark_unenrolled(&containing(&[1000])));
        assert_eq!(
            claim_as(&store, &id("hobi"), HOBI, signer(), Some(task)),
            Err(TaskRefusal::AgentGone)
        );
        assert!(matches!(
            store.due(8)[..],
            [Due {
                why: DueFor::Hold(Contained::Tasker),
                ..
            }]
        ));
    }

    #[test]
    fn a_hold_is_due_its_own_record_though_a_close_of_the_task_was_recorded() {
        let (blobs, store) = mem();
        let task = held_by(&store, Tasker::Uid(1000));
        blobs.fail(Some(crate::task_store::Fail::Records));
        assert_eq!(store.purge_agent(&id("hobi")).len(), 1);
        assert_eq!(
            store.due(8),
            vec![gone(task, true)],
            "the close is recorded"
        );
        blobs.fail(None);
        store.mark_unenrolled(&containing(&[1000]));
        let due = store.due(8);
        assert_eq!(due.len(), 1);
        assert_eq!(
            (due[0].why, due[0].recorded),
            (DueFor::Hold(Contained::Tasker), false),
            "the hold has not been recorded"
        );
        assert_eq!(store.perform(&due), 1);
        assert_eq!(store.record(&task).unwrap().state, TaskState::Held);
    }

    #[test]
    fn a_hold_names_who_is_contained_and_reaches_the_chain_rooted_at_a_contained_agent() {
        let (_blobs, store) = mem();
        let v = view(&[("hobi", HOBI), ("jin", JIN), ("suga", SUGA)]);
        let hobis = Tasker::Agent {
            agent: "hobi".into(),
            uid: HOBI,
        };
        let jins = Tasker::Agent {
            agent: "jin".into(),
            uid: JIN,
        };
        let given = store
            .mint_live(signer(), &v, at(0, JIN), hobis, None, sub("jin"))
            .unwrap()
            .task
            .task_id;
        store.start_for_test(&given);
        let under = store
            .mint_live(signer(), &v, at(0, SUGA), jins, Some(given), sub("suga"))
            .unwrap()
            .task
            .task_id;
        let held_open = held_by(&store, Tasker::Uid(1000));
        let reported = held_by(&store, Tasker::Uid(1000));
        store.publish_report(&reported, text("r"), None).unwrap();
        let others = store
            .mint_live(
                signer(),
                &v,
                at(0, JIN),
                Tasker::Uid(1000),
                None,
                sub("jin"),
            )
            .unwrap()
            .task
            .task_id;
        store.mark_unenrolled(&crate::enrollment::Containing(v, [HOBI].into()));
        let mut why: Vec<(TaskId, DueFor)> =
            store.due(8).into_iter().map(|d| (d.task, d.why)).collect();
        why.sort_by_key(|(t, _)| *t);
        let mut want = vec![
            (given, DueFor::Hold(Contained::Tasker)),
            (under, DueFor::Hold(Contained::Root)),
            (held_open, DueFor::Hold(Contained::Agent)),
        ];
        want.sort_by_key(|(t, _)| *t);
        assert_eq!(why, want);
        assert_eq!(store.close_all_due().len(), 3);
        assert_eq!(store.record(&reported).unwrap().state, TaskState::Reported);
        assert_eq!(store.record(&others).unwrap().state, TaskState::Queued);
    }

    #[test]
    fn only_a_queued_task_not_due_a_hold_is_marked_withdrawn() {
        let (_blobs, store) = mem();
        let me = Tasker::Uid(1000);
        let queued = held_by(&store, me.clone());
        let working = held_by(&store, me.clone());
        let holding = held_by(&store, Tasker::Uid(1001));
        store.start_for_test(&working);
        store.held().hold_contained(&containing(&[1001]));
        assert_eq!(store.tasker_of(&queued), Some((me, id("hobi"))));
        assert_eq!(store.tasker_of(&TaskId([9; 16])), None);
        for task in [queued, working, holding, TaskId([9; 16])] {
            store.withdraw_authority(&task);
        }
        assert_eq!(
            store
                .held()
                .closing
                .iter()
                .map(|(t, c)| (*t, *c))
                .collect::<Vec<_>>(),
            [(queued, TaskClose::Withdrawn)]
        );
        assert_eq!(
            store.next_for(&id("hobi"), HOBI),
            Some((working, TaskState::Working))
        );
        store.close_all_due();
        assert_eq!(closed(&store, &queued), Some(TaskClose::Withdrawn));
        assert_eq!(store.record(&holding).unwrap().state, TaskState::Held);
    }

    #[test]
    fn a_rewrite_of_a_task_whose_close_is_not_stored_is_not_said_to_have_landed() {
        let (blobs, store) = mem();
        let task = held_by(&store, Tasker::Uid(1000));
        blobs.fail(Some(crate::task_store::Fail::Unsynced));
        store.purge_agent(&id("hobi"));
        assert!(matches!(&store.take_notices()[..], [Notice::Owed { .. }]));
        assert!(store.held().stale.contains(&task));
        blobs.fail(None);
        store.pass();
        assert!(!store.held().stale.contains(&task), "rewritten as it was");
        assert_eq!(closed(&store, &task), None);
        assert!(
            store.take_notices().is_empty(),
            "the close is still owed, so nothing has landed"
        );
        store.close_all_due();
        assert_eq!(closed(&store, &task), Some(TaskClose::AgentGone));
        assert_eq!(store.take_notices(), vec![Notice::Settled { task }]);
    }

    #[test]
    fn a_close_lost_in_a_crash_is_due_again_and_the_tasker_sees_it_once() {
        let (blobs, store) = mem();
        let me = Tasker::Uid(1000);
        let task = held_by(&store, me.clone());
        blobs.fail(Some(crate::task_store::Fail::Unsynced));
        store.purge_agent(&id("hobi"));
        assert!(store
            .reports(&me, &id("hobi"), usize::MAX)
            .entries
            .is_empty());
        blobs.fail(None);
        blobs.crash(0);
        let reopened = reopen(&blobs);
        assert_eq!(reopened.record(&task).unwrap().state, TaskState::Queued);
        assert_eq!(
            reopened.retain_enrolled(&view(&[])),
            vec![gone(task, false)],
            "recorded again"
        );
        assert_eq!(closed(&reopened, &task), Some(TaskClose::AgentGone));
        assert_eq!(
            reopened.reports(&me, &id("hobi"), usize::MAX).entries.len(),
            1
        );
        assert_eq!(closed(&reopen(&blobs), &task), Some(TaskClose::AgentGone));
    }

    #[test]
    fn a_close_that_panics_in_its_write_stays_marked_and_is_stored_later() {
        let (blobs, store) = mem();
        let task = held_by(&store, Tasker::Uid(1000));
        blobs.fail(Some(crate::task_store::Fail::Panics));
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.purge_agent(&id("hobi"));
        }));
        assert!(unwound.is_err());
        assert_eq!(closed(&store, &task), None);
        assert_eq!(store.due(8), vec![gone(task, true)]);
        blobs.fail(None);
        store.close_all_due();
        assert_eq!(closed(&reopen(&blobs), &task), Some(TaskClose::AgentGone));
    }

    #[test]
    fn a_close_is_performed_only_while_it_is_still_due() {
        let (_blobs, clock, store) = clocked();
        let me = Tasker::Uid(1000);
        let lease = CLAIM_LEASE.as_secs() as i64;
        let task = held_by(&store, me.clone());
        store.start_for_test(&task);
        clock.set(1_001 + lease);
        let due = store.due(8);
        assert_eq!(due[0].why, DueFor::Close(TaskClose::AgentLost));
        store.heartbeat(&id("hobi"), HOBI, 0, 0);
        assert_eq!(
            store.perform(&due),
            0,
            "the lease was renewed before the close"
        );
        assert_eq!(closed(&store, &task), None);
        assert!(store.due(8).is_empty());
        assert_eq!(store.perform(&[gone(task, false)]), 0, "never marked");
        clock.set(1_002 + 2 * lease);
        let due = store.due(8);
        store.stop(&task, &me).unwrap();
        assert_eq!(store.perform(&due), 0, "its tasker stopped it first");
        assert_eq!(closed(&store, &task), Some(TaskClose::Stopped));
        let reported = held_by(&store, me.clone());
        store.publish_report(&reported, text("r"), None).unwrap();
        let early = Due {
            task: reported,
            agent: id("hobi"),
            tasker: me,
            parent: None,
            why: DueFor::Expiry,
            recorded: false,
        };
        assert_eq!(store.perform(&[early]), 0, "its hold has not run out");
        assert!(store.record(&reported).is_some());
    }

    #[test]
    fn the_close_stored_is_the_one_recorded_though_the_mark_changed_since() {
        let (blobs, clock, store) = clocked();
        let task = held_by(&store, Tasker::Uid(1000));
        store.start_for_test(&task);
        clock.set(1_001 + CLAIM_LEASE.as_secs() as i64);
        let recorded = store.due(8);
        assert_eq!(recorded[0].why, DueFor::Close(TaskClose::AgentLost));
        store.held().unenroll(&id("hobi"), |_| true);
        assert_eq!(store.perform(&recorded), 1);
        assert_eq!(closed(&store, &task), Some(TaskClose::AgentLost));

        let again = held_by(&store, Tasker::Uid(1000));
        store.start_for_test(&again);
        clock.set(2_002 + 2 * CLAIM_LEASE.as_secs() as i64);
        blobs.fail(Some(crate::task_store::Fail::Records));
        assert_eq!(closes_of(&store.sweep()), [TaskClose::AgentLost]);
        store.held().unenroll(&id("hobi"), |_| true);
        assert_eq!(
            closes_of(&store.due(8)),
            [TaskClose::AgentLost],
            "still due as it was recorded"
        );
        blobs.fail(None);
        assert!(store.sweep().is_empty(), "and not recorded again");
        assert_eq!(closed(&store, &again), Some(TaskClose::AgentLost));
        assert_eq!(closed(&reopen(&blobs), &again), Some(TaskClose::AgentLost));
    }

    fn closes_of(due: &[Due]) -> Vec<TaskClose> {
        due.iter()
            .filter_map(|d| match d.why {
                DueFor::Close(close) => Some(close),
                DueFor::Expiry | DueFor::Hold(_) => None,
            })
            .collect()
    }

    #[test]
    fn a_close_the_disk_keeps_refusing_does_not_hold_back_a_newer_one() {
        let (blobs, store) = mem();
        let stuck = held_by(&store, Tasker::Uid(1000));
        let newer = held_by(&store, Tasker::Uid(1000));
        store.held().unenroll(&id("hobi"), |_| true);
        blobs.stick(Some(name_of(&stuck)));
        let due = store.due(8);
        assert_eq!([due[0].task, due[1].task], [stuck, newer]);
        assert_eq!(store.perform(&due), 0, "one refusal ends the pass");
        let due = store.due(8);
        assert_eq!(
            [due[0].task, due[1].task],
            [newer, stuck],
            "the next pass starts after the refused close"
        );
        assert_eq!(store.due(1)[0].task, newer);
        assert_eq!(store.perform(&due), 1);
        assert_eq!(closed(&store, &newer), Some(TaskClose::AgentGone));
        assert_eq!(closed(&store, &stuck), None);
        blobs.stick(None);
        assert_eq!(store.perform(&store.due(8)), 1);
        assert_eq!(closed(&store, &stuck), Some(TaskClose::AgentGone));
        assert_eq!(store.held().refused_close, None);
    }

    #[test]
    fn a_queue_that_changes_during_a_claim_sets_no_back_off() {
        let (_blobs, store) = mem();
        let hobi = id("hobi");
        let signing = LeafSigner::new(PlaneKey::EcdsaP384Sha384);
        let mut task = TaskObject::for_test("hobi", 1000);
        task.tasker = Tasker::Uid(1000);
        let task = store
            .insert_for_test(signing.sign(task).unwrap(), HOBI)
            .task
            .task_id;
        let other = held_by(&store, Tasker::Uid(1000));
        signing.rotate();
        let racing = DuringSign {
            inner: &signing,
            during: Box::new(|| store.start_for_test(&other)),
        };
        assert_eq!(
            claim_head(&store, &hobi, HOBI, &racing),
            Err(TaskRefusal::Unavailable(MOVED.into()))
        );
        let hot = store.hot(&task).unwrap();
        assert_eq!((hot.retry_after, hot.retry_secs), (0, 0));
    }

    #[test]
    fn a_lapsed_task_the_disk_does_not_close_is_marked_and_never_recorded_twice() {
        let (blobs, clock, store) = clocked();
        let task = held_by(&store, Tasker::Uid(1000));
        store.start_for_test(&task);
        clock.set(1_001 + CLAIM_LEASE.as_secs() as i64);
        blobs.fail(Some(crate::task_store::Fail::Records));
        assert_eq!(store.sweep().len(), 1);
        assert_eq!(closed(&store, &task), None);
        assert_eq!(
            store.heartbeat(&id("hobi"), HOBI, 0, 0),
            Heartbeat::Idle,
            "marked: the agent no longer holds it, and is not yet told it closed"
        );
        assert_eq!(
            store.report(&task, &id("hobi"), HOBI, text("late")),
            Err(TaskRefusal::AgentGone)
        );
        assert!(store.sweep().is_empty(), "recorded once");
        blobs.fail(None);
        assert!(store.sweep().is_empty());
        assert_eq!(closed(&store, &task), Some(TaskClose::AgentLost));
        assert!(matches!(
            store.heartbeat(&id("hobi"), HOBI, 0, 0),
            Heartbeat::Closed(v) if v.close == Some(TaskClose::AgentLost)
        ));
    }

    #[test]
    fn marking_the_unenrolled_does_no_io_and_no_agent_acts_on_a_marked_task() {
        let (blobs, store) = mem();
        let v = view(&[("hobi", HOBI)]);
        store.retain_enrolled(&v);
        let task = held_by(&store, Tasker::Uid(1000));
        let queued = held_by(&store, Tasker::Uid(1000));
        store.start_for_test(&task);
        let before = blobs.attempts();
        blobs.fail(Some(crate::task_store::Fail::Panics));
        store.mark_unenrolled(&view(&[]));
        store.mark_unenrolled(&view(&[]));
        blobs.fail(None);
        assert_eq!(blobs.attempts(), before);
        assert_eq!(store.generation(&id("hobi")), 1, "bumped once");
        assert_eq!(
            store.working(&task, &id("hobi"), HOBI),
            Err(TaskRefusal::Unknown)
        );
        assert_eq!(
            store.resolve(&task, &id("hobi"), HOBI),
            Err(TaskRefusal::Unknown)
        );
        assert_eq!(
            store.heartbeat(&id("hobi"), HOBI, 0, usize::MAX),
            Heartbeat::Idle
        );
        store.pass();
        assert_eq!(
            store.report(&task, &id("hobi"), HOBI, text("late")),
            Err(TaskRefusal::AgentGone),
            "a marked task is not reported, though a writer has passed"
        );
        assert_eq!(
            claim_head(&store, &id("hobi"), HOBI, signer()),
            Ok(Claimed::Idle)
        );
        assert_eq!(store.record(&task).unwrap().state, TaskState::Working);
        assert_eq!(store.record(&queued).unwrap().state, TaskState::Queued);
        assert_eq!(store.close_all_due().len(), 2);
        assert_eq!(closed(&store, &task), Some(TaskClose::AgentGone));
    }

    #[test]
    fn a_task_marked_while_its_claim_is_written_is_not_handed_out() {
        let (blobs, store) = mem();
        let store = Arc::new(store);
        let task = held_by(&store, Tasker::Uid(1000));
        let marking = Arc::clone(&store);
        blobs.after_save(move || marking.mark_unenrolled(&view(&[])));
        assert_eq!(
            claim_head(&store, &id("hobi"), HOBI, signer()),
            Err(TaskRefusal::AgentGone)
        );
        assert_eq!(store.due(8), vec![gone(task, false)], "due its close");
    }

    #[test]
    fn a_purge_retries_the_agents_exposed_records_whatever_the_drain_order() {
        let (blobs, store) = mem();
        let mut tasks = [
            TaskObject::for_test("jin", 1000),
            TaskObject::for_test("hobi", 1000),
        ];
        if tasks[0].task_id > tasks[1].task_id {
            let (a, b) = (tasks[0].task_id, tasks[1].task_id);
            (tasks[0].task_id, tasks[1].task_id) = (b, a);
        }
        let [jins, hobis] = tasks.map(|t| {
            let uid = if t.agent == "jin" { JIN } else { HOBI };
            store
                .insert_for_test(signer().sign(t).unwrap(), uid)
                .task
                .task_id
        });
        blobs.fail(Some(crate::task_store::Fail::Records));
        assert!(!store.withdraw(&jins));
        assert!(!store.withdraw(&hobis));
        blobs.fail(None);
        blobs.stick(Some(name_of(&jins)));
        store.held().stuck = None;
        store.purge_agent(&id("hobi"));
        assert!(
            blobs.has(&name_of(&jins)),
            "the drain stopped at the first refusal"
        );
        assert!(
            !blobs.has(&name_of(&hobis)),
            "the purged agent's record was still tried"
        );
        assert!(!store.held().exposed.contains_key(&hobis));
    }

    #[test]
    fn a_claim_starts_the_oldest_queued_task_and_hands_the_working_one_again() {
        let (blobs, store) = mem();
        let hobi = id("hobi");
        assert_eq!(claim_head(&store, &hobi, HOBI, signer()), Ok(Claimed::Idle));
        let first = held_by(&store, Tasker::Uid(1000));
        let second = held_by(&store, Tasker::Uid(1001));
        assert_eq!(
            store.next_for(&hobi, HOBI),
            Some((first, TaskState::Queued))
        );
        assert_eq!(
            store.next_for(&hobi, JIN),
            None,
            "another uid holds nothing"
        );
        assert_eq!(claim_head(&store, &hobi, JIN, signer()), Ok(Claimed::Idle));
        for _ in 0..2 {
            match claim_head(&store, &hobi, HOBI, signer()).unwrap() {
                Claimed::Delivered { signed, partition } => {
                    assert_eq!(signed.task.task_id, first);
                    assert_eq!(partition, "tasks/users/1000");
                }
                Claimed::Idle => panic!("idle"),
            }
        }
        assert_eq!(store.record(&second).unwrap().state, TaskState::Queued);
        assert_eq!(
            reopen(&blobs).record(&first).unwrap().state,
            TaskState::Working
        );
        assert_eq!(
            claim_head(&store, &hobi, HOBI, &NoIdentity),
            Err(TaskRefusal::Unsigned),
            "without a current leaf nothing is handed out"
        );
        assert_eq!(store.record(&first).unwrap().state, TaskState::Working);
    }

    #[test]
    fn a_claim_the_disk_does_not_take_leaves_the_task_queued() {
        let (blobs, clock, store) = clocked();
        let hobi = id("hobi");
        let task = held_by(&store, Tasker::Uid(1000));
        blobs.fail(Some(crate::task_store::Fail::UnsyncedOnce));
        assert!(
            matches!(
                claim_head(&store, &hobi, HOBI, signer()),
                Err(TaskRefusal::Store(_))
            ),
            "landed unsynced, then undone: refused"
        );
        clock.set(1_001);
        blobs.fail(Some(crate::task_store::Fail::Records));
        assert!(matches!(
            claim_head(&store, &hobi, HOBI, signer()),
            Err(TaskRefusal::Store(_))
        ));
        clock.set(1_003);
        blobs.fail(Some(crate::task_store::Fail::Unsynced));
        let said = claim_head(&store, &hobi, HOBI, signer()).unwrap_err();
        assert!(
            matches!(&said, TaskRefusal::Unavailable(why) if why.starts_with("outcome unknown: ")),
            "{said:?}"
        );
        assert_eq!(store.record(&task).unwrap().state, TaskState::Queued);
        assert_eq!(
            store.hot(&task).unwrap().lease_until,
            0,
            "no lease was begun"
        );
        assert_eq!(store.queue(&hobi), vec![task]);
        blobs.fail(None);
        store.pass();
        blobs.crash(1);
        clock.set(1_007);
        assert_eq!(
            reopen(&blobs).record(&task).unwrap().state,
            TaskState::Queued,
            "the disk is rewritten as memory holds it"
        );
        assert!(matches!(
            claim_head(&store, &hobi, HOBI, signer()),
            Ok(Claimed::Delivered { .. })
        ));
    }

    #[test]
    fn a_claim_under_a_rotated_leaf_is_signed_again_or_hands_out_nothing() {
        let (blobs, clock, store) = clocked();
        let hobi = id("hobi");
        let signing = LeafSigner::new(PlaneKey::EcdsaP384Sha384);
        let mut task = TaskObject::for_test("hobi", 1000);
        task.tasker = Tasker::Uid(1000);
        let task = store
            .insert_for_test(signing.sign(task).unwrap(), HOBI)
            .task
            .task_id;
        signing.rotate();
        blobs.fail(Some(crate::task_store::Fail::Unsynced));
        let said = claim_head(&store, &hobi, HOBI, &signing).unwrap_err();
        assert!(
            matches!(&said, TaskRefusal::Unavailable(why) if why.starts_with("outcome unknown: ")),
            "{said:?}"
        );
        assert_eq!(store.record(&task).unwrap().state, TaskState::Queued);
        assert_eq!(closed(&store, &task), None, "never closed for it");
        blobs.fail(None);
        clock.set(1_001);
        match claim_head(&store, &hobi, HOBI, &signing).unwrap() {
            Claimed::Delivered { signed, .. } => assert_eq!(signing.verify(&signed), Ok(())),
            Claimed::Idle => panic!("idle"),
        }
    }

    #[test]
    fn a_report_is_taken_only_from_the_holding_agent_while_working() {
        let (_blobs, store) = mem();
        let hobi = id("hobi");
        let task = held_by(&store, Tasker::Uid(1000));
        assert_eq!(
            store.report(&task, &hobi, HOBI, text("r")),
            Err(TaskRefusal::NotWorking)
        );
        store.start_for_test(&task);
        store.acted(&task);
        assert_eq!(
            store.report(&task, &id("jin"), HOBI, text("r")),
            Err(TaskRefusal::OtherAgent)
        );
        assert_eq!(
            store.report(&task, &hobi, JIN, text("r")),
            Err(TaskRefusal::OtherAgent)
        );
        let view = store.report(&task, &hobi, HOBI, text("r")).unwrap();
        assert_eq!((view.state, view.actions), (TaskState::Reported, 1));
        assert_eq!(store.record(&task).unwrap().actions, 1);
        assert_eq!(
            store.report(&task, &hobi, HOBI, text("again")),
            Err(TaskRefusal::NotWorking)
        );
        store.acted(&task);
        assert_eq!(
            store.hot(&task).unwrap().actions,
            1,
            "a finished task counts nothing"
        );
    }

    fn clocked() -> (
        crate::task_store::MemTaskBlobs,
        Arc<crate::task_store::ManualClock>,
        TaskStore,
    ) {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let clock = Arc::new(crate::task_store::ManualClock::at(1_000));
        let store = TaskStore::open(Box::new(blobs.clone()), clock.clone()).unwrap();
        (blobs, clock, store)
    }

    #[test]
    fn the_sweep_stores_changed_counters_and_a_refused_write_is_tried_again() {
        let (blobs, clock, store) = clocked();
        let task = held_by(&store, Tasker::Uid(1000));
        let idle = held_by(&store, Tasker::Uid(1000));
        store.start_for_test(&task);
        clock.set(1_010);
        store.acted(&task);
        store.acted(&idle);
        assert_eq!(
            store.hot(&idle).unwrap().actions,
            0,
            "a queued task counts nothing"
        );
        blobs.fail(Some(crate::task_store::Fail::Records));
        store.sweep();
        assert_eq!(store.record(&task).unwrap().actions, 0);
        blobs.fail(None);
        let before = blobs.attempts();
        store.sweep();
        let rec = store.record(&task).unwrap();
        assert_eq!((rec.actions, rec.last_action), (1, Some(1_010)));
        let wrote = blobs.attempts() - before;
        store.sweep();
        assert_eq!(
            blobs.attempts() - before,
            wrote,
            "unchanged counters are not written"
        );
        clock.set(5_000);
        let reopened = TaskStore::open(Box::new(blobs.clone()), clock.clone()).unwrap();
        let hot = reopened.hot(&task).unwrap();
        assert_eq!(
            (hot.actions, hot.last_action, hot.lease_until),
            (1, Some(1_010), 5_000 + CLAIM_LEASE.as_secs() as i64)
        );
    }

    #[test]
    fn an_expiry_the_disk_does_not_prove_leaves_memory_and_is_owed() {
        let (blobs, clock, store) = clocked();
        let me = Tasker::Uid(1000);
        let (one, two) = (held_by(&store, me.clone()), held_by(&store, me.clone()));
        store.publish_report(&one, text("r"), None).unwrap();
        store.publish_report(&two, text("r"), None).unwrap();
        clock.set(999 + REPORT_HOLD.as_secs() as i64);
        assert!(store.due(8).is_empty());
        clock.set(1_000 + REPORT_HOLD.as_secs() as i64);
        let due = store.due(8);
        assert_eq!(
            due.iter().map(|d| (d.task, d.why)).collect::<Vec<_>>(),
            [(one, DueFor::Expiry), (two, DueFor::Expiry)]
        );
        assert_eq!(store.due(1).len(), 1);
        blobs.fail(Some(crate::task_store::Fail::Unsynced));
        let before = blobs.attempts();
        assert_eq!(store.perform(&due), 2);
        assert_eq!(
            blobs.attempts() - before,
            2,
            "one failure ends the removals"
        );
        assert!(store.record(&one).is_none() && store.record(&two).is_none());
        assert!(store.due(8).is_empty());
        let said = store.take_notices();
        assert!(matches!(&said[..], [Notice::Owed { .. }]), "{said:?}");
        blobs.fail(None);
        store.pass();
        store.pass();
        blobs.crash(0);
        assert_eq!(reopen(&blobs).len(), 0, "no expired report reloads");
    }

    #[test]
    fn a_lapsed_lease_is_read_and_closed_in_one_step() {
        let (_blobs, clock, store) = clocked();
        let task = held_by(&store, Tasker::Uid(1000));
        store.start_for_test(&task);
        let lease = CLAIM_LEASE.as_secs() as i64;
        clock.set(1_000 + lease);
        assert_eq!(
            store.heartbeat(&id("hobi"), HOBI, 0, usize::MAX),
            Heartbeat::FollowUps {
                task,
                tasker: Tasker::Uid(1000),
                from: 0,
                items: Vec::new()
            }
        );
        clock.set(1_000 + 2 * lease);
        store.sweep();
        assert_eq!(closed(&store, &task), None, "the heartbeat renewed it");
        clock.set(1_000 + 2 * lease + 1);
        store.sweep();
        assert_eq!(closed(&store, &task), Some(TaskClose::AgentLost));
    }

    #[test]
    fn a_heartbeat_hands_the_follow_ups_that_fit_and_always_the_first() {
        let (_blobs, store) = mem();
        let me = Tasker::Uid(1000);
        let task = held_by(&store, me.clone());
        store.start_for_test(&task);
        for t in ["aaaa", "bbbb", "cccc"] {
            store.follow_up(&task, &me, text(t), 100).unwrap();
        }
        let items = |seen, budget| match store.heartbeat(&id("hobi"), HOBI, seen, budget) {
            Heartbeat::FollowUps { items, .. } => {
                items.iter().map(|i| i.0.to_string()).collect::<Vec<_>>()
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(items(0, 0), ["aaaa"]);
        assert_eq!(items(0, 8), ["aaaa", "bbbb"]);
        assert_eq!(items(1, 7), ["bbbb"]);
        assert_eq!(items(0, 12), ["aaaa", "bbbb", "cccc"]);
        assert!(items(3, 12).is_empty());
    }

    #[test]
    fn notices_the_trail_did_not_take_go_back_ahead_of_newer_ones() {
        let (_blobs, store) = mem();
        let note = |n: u8| Notice::Settled {
            task: TaskId([n; 16]),
        };
        store.note(note(2));
        store.return_notices(vec![note(1)]);
        assert_eq!(store.take_notices(), vec![note(1), note(2)]);
        assert!(store.take_notices().is_empty());
    }

    struct CountsSigns<'a>(&'a LeafSigner, AtomicUsize);

    impl TaskSigner for CountsSigns<'_> {
        fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.sign(task)
        }
        fn current_leaf(&self) -> Option<[u8; 32]> {
            self.0.current_leaf()
        }
    }

    #[test]
    fn a_hand_out_the_store_refuses_is_held_back_one_second_doubling_to_sixty() {
        let (blobs, clock, store) = clocked();
        let hobi = id("hobi");
        let signing = LeafSigner::new(PlaneKey::EcdsaP384Sha384);
        let mut task = TaskObject::for_test("hobi", 1000);
        task.tasker = Tasker::Uid(1000);
        let task = store
            .insert_for_test(signing.sign(task).unwrap(), HOBI)
            .task
            .task_id;
        let later = held_by(&store, Tasker::Uid(1000));
        signing.rotate();
        let counting = CountsSigns(&signing, AtomicUsize::new(0));
        let signs = || counting.1.load(Ordering::SeqCst);
        blobs.fail(Some(crate::task_store::Fail::Unsynced));
        let mut now = 1_000;
        for (n, wait) in [1, 2, 4, 8, 16, 32, 60, 60].into_iter().enumerate() {
            assert!(
                matches!(
                    claim_head(&store, &hobi, HOBI, &counting),
                    Err(TaskRefusal::Unavailable(_))
                ),
                "attempt {n}"
            );
            assert_eq!(signs(), n + 1);
            let hot = store.hot(&task).unwrap();
            assert_eq!(
                (hot.retry_secs, hot.retry_after),
                (wait, now + i64::from(wait))
            );
            let attempts = blobs.attempts();
            clock.set(now + i64::from(wait) - 1);
            for _ in 0..3 {
                assert_eq!(
                    claim_head(&store, &hobi, HOBI, &counting),
                    Ok(Claimed::Idle)
                );
                assert_eq!(
                    store.next_for(&hobi, HOBI),
                    None,
                    "nor is the next task taken"
                );
            }
            assert_eq!(signs(), n + 1, "no signature inside the window");
            assert_eq!(blobs.attempts(), attempts, "no write inside the window");
            now += i64::from(wait);
            clock.set(now);
        }
        blobs.fail(None);
        assert!(matches!(
            claim_head(&store, &hobi, HOBI, &counting),
            Ok(Claimed::Delivered { .. })
        ));
        let hot = store.hot(&task).unwrap();
        assert_eq!(
            (hot.retry_secs, hot.retry_after),
            (0, 0),
            "a hand-out ends it"
        );
        assert_eq!(store.record(&later).unwrap().state, TaskState::Queued);
        assert_eq!(
            claim_head(&store, &hobi, HOBI, &NoIdentity),
            Err(TaskRefusal::Unsigned)
        );
        assert_eq!(
            store.hot(&task).unwrap().retry_secs,
            1,
            "a signer's refusal holds it back too"
        );
        assert_eq!(
            claim_head(&store, &hobi, HOBI, &NoIdentity),
            Ok(Claimed::Idle)
        );
    }

    #[test]
    fn a_withdrawal_whose_unlink_is_refused_says_the_record_is_left() {
        let (blobs, store) = mem();
        let task = held_by(&store, Tasker::Uid(1000));
        blobs.fail(Some(crate::task_store::Fail::Unlinks));
        assert!(store.withdraw(&task), "the pending mark is synced");
        let said = store.take_notices();
        assert!(
            matches!(&said[..], [Notice::Left { task: t, why }] if *t == task && why.contains("sentinel-628-unlink-refused")),
            "{said:?}"
        );
    }

    #[test]
    fn a_drop_proven_by_neither_step_is_outcome_unknown_and_still_owed() {
        nothing_removed_reloads_after(crate::task_store::Fail::Unsynced, Gone::Dropped);
    }

    #[test]
    fn an_acknowledgement_proven_by_neither_step_is_outcome_unknown_and_still_owed() {
        nothing_removed_reloads_after(crate::task_store::Fail::Unsynced, Gone::Acknowledged);
    }

    #[test]
    fn a_drop_is_done_once_its_pending_mark_is_synced() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let task = held_by(&store, me.clone());
        blobs.fail(Some(crate::task_store::Fail::UnsyncedUnlinks));
        let view = store.drop_queued(&task, &me).unwrap();
        assert_eq!(view.close, Some(TaskClose::Dropped));
        blobs.crash(0);
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert_eq!(reopened.len(), 0, "a dropped task is not stored again");
        assert!(reopened.queue(&id("hobi")).is_empty(), "nothing to claim");
    }

    #[test]
    fn an_acknowledgement_is_done_once_each_pending_mark_is_synced() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let task = held_by(&store, me.clone());
        let rseq = store.publish_report(&task, text("r"), None).unwrap();
        blobs.fail(Some(crate::task_store::Fail::UnsyncedUnlinks));
        assert_eq!(store.acknowledge(&me, &id("hobi"), rseq), Ok(1));
        blobs.crash(0);
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert_eq!(
            reopened.len(),
            0,
            "an acknowledged report is not stored again"
        );
    }

    #[test]
    fn an_acknowledgement_that_removes_only_some_is_outcome_unknown_and_owes_the_rest() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let mut tasks = [held_by(&store, me.clone()), held_by(&store, me.clone())];
        tasks.sort();
        let mut upto = 0;
        for task in &tasks {
            upto = store.publish_report(task, text("r"), None).unwrap();
        }
        blobs.stick(Some(name_of(&tasks[1])));
        let said = store.acknowledge(&me, &id("hobi"), upto).unwrap_err();
        assert!(
            matches!(&said, TaskRefusal::Unavailable(why) if why.starts_with("outcome unknown: ")),
            "{said:?}"
        );
        assert_eq!(store.len(), 0, "neither is collected again");
        assert!(!blobs.has(&name_of(&tasks[0])));
        blobs.stick(None);
        store.purge_agent(&id("nobody"));
        assert!(!blobs.has(&name_of(&tasks[1])), "the rest was owed");
    }

    #[test]
    fn one_record_the_disk_keeps_refusing_does_not_hold_back_another() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let mut tasks = [held_by(&store, me.clone()), held_by(&store, me)];
        tasks.sort();
        blobs.fail(Some(crate::task_store::Fail::Records));
        assert!(!store.withdraw(&tasks[0]));
        assert!(!store.withdraw(&tasks[1]));
        blobs.fail(None);
        blobs.stick(Some(name_of(&tasks[0])));
        for _ in 0..2 {
            let before = blobs.attempts();
            store.purge_agent(&id("nobody"));
            assert!(blobs.attempts() - before <= 4, "one failure ends a drain");
        }
        assert!(blobs.has(&name_of(&tasks[0])));
        assert!(!blobs.has(&name_of(&tasks[1])), "the other one settled");
        assert_eq!(store.held().stuck, Some(tasks[0]));
        blobs.stick(None);
        store.purge_agent(&id("nobody"));
        assert!(!blobs.has(&name_of(&tasks[0])));
        assert_eq!(store.held().stuck, None);
    }

    #[test]
    fn a_retry_while_the_removal_is_still_owed_is_outcome_unknown() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let dropped = held_by(&store, me.clone());
        let reported = held_by(&store, me.clone());
        let rseq = store.publish_report(&reported, text("r"), None).unwrap();
        blobs.fail(Some(crate::task_store::Fail::Unsynced));
        for _ in 0..2 {
            for said in [
                store.drop_queued(&dropped, &me).map(drop),
                store.acknowledge(&me, &id("hobi"), rseq).map(drop),
            ] {
                assert!(
                    matches!(&said, Err(TaskRefusal::Unavailable(why)) if why.starts_with("outcome unknown: ")),
                    "{said:?}"
                );
            }
        }
        assert_eq!(
            store.drop_queued(&dropped, &Tasker::Uid(1001)),
            Err(TaskRefusal::Unknown),
            "another tasker learns nothing"
        );
        blobs.fail(None);
        assert_eq!(store.drop_queued(&dropped, &me), Err(TaskRefusal::Unknown));
        assert_eq!(store.acknowledge(&me, &id("hobi"), rseq), Ok(0));
    }

    #[test]
    fn a_queued_withdrawal_of_a_stale_task_is_not_skipped() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let task = working(&store, &me);
        blobs.fail(Some(crate::task_store::Fail::Unsynced));
        assert!(store.stop(&task, &me).is_err());
        blobs.fail(None);
        store.abandon(task);
        store.purge_agent(&id("nobody"));
        assert!(store.record(&task).is_none());
        assert!(!blobs.has(&name_of(&task)));
    }

    #[test]
    fn a_replacing_write_that_panics_after_it_landed_is_rewritten_as_memory_has_it() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let task = working(&store, &me);
        blobs.after_save(|| panic!("sentinel-628-write-panic"));
        let unwound =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.stop(&task, &me)));
        assert!(unwound.is_err());
        assert_eq!(store.record(&task).unwrap().state, TaskState::Working);
        store.purge_agent(&id("nobody"));
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert_eq!(reopened.record(&task).unwrap().state, TaskState::Working);
    }

    struct PurgesThenFails(Recorder, Arc<TaskStore>);

    impl AuditEmit for PurgesThenFails {
        fn emit(
            &self,
            rec: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
            let first = self.0.records().is_empty();
            if first {
                self.1.purge_agent(&id("hobi"));
            }
            let emitted = self.0.emit(rec);
            async move {
                emitted.await?;
                match first {
                    true => Ok(()),
                    false => Err(AuditError::Serialize("sink refused".into())),
                }
            }
        }
    }

    #[tokio::test]
    async fn an_unkept_task_whose_corrective_record_fails_is_not_audited() {
        let (_g, pdp) = pdp("unkept-unaudited");
        let store = Arc::new(TaskStore::new());
        let emit = PurgesThenFails(Recorder::new(), Arc::clone(&store));
        let view = SnapshotEnrollment(pdp.clone());
        let got = submit_via(
            pdp.clone(),
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (BOUND, None),
        )
        .await;
        assert_eq!(emit.0.records().len(), 2);
        assert!(matches!(got, Err(TaskRefusal::Audit(_))), "{got:?}");
    }

    fn working(store: &TaskStore, tasker: &Tasker) -> TaskId {
        let task = held_by(store, tasker.clone());
        store.start_for_test(&task);
        task
    }

    #[test]
    fn a_stop_or_follow_up_left_unsynced_and_not_undone_is_outcome_unknown() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let (stopped, added) = (working(&store, &me), working(&store, &me));
        blobs.fail(Some(crate::task_store::Fail::Unsynced));
        for said in [
            store.stop(&stopped, &me).unwrap_err(),
            store.follow_up(&added, &me, text("more"), 64).unwrap_err(),
        ] {
            assert!(
                matches!(&said, TaskRefusal::Unavailable(why) if why.starts_with("outcome unknown: ")),
                "{said:?}"
            );
        }
        blobs.fail(None);
        store.purge_agent(&id("nobody"));
        blobs.crash(1);
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        for task in [stopped, added] {
            let (now, then) = (
                store.record(&task).unwrap(),
                reopened.record(&task).unwrap(),
            );
            assert_eq!(then.state, TaskState::Working);
            assert_eq!(then.follow_ups.len(), 0);
            assert_eq!((now.state, now.follow_ups.len()), (then.state, 0));
        }
    }

    #[test]
    fn a_stop_left_unsynced_and_undone_is_refused() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let task = working(&store, &me);
        blobs.fail(Some(crate::task_store::Fail::UnsyncedOnce));
        assert!(matches!(store.stop(&task, &me), Err(TaskRefusal::Store(_))));
        blobs.crash(1);
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert_eq!(reopened.record(&task).unwrap().state, TaskState::Working);
    }

    #[test]
    fn a_drain_stops_at_the_first_record_the_disk_refuses() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let me = Tasker::Uid(1000);
        let (one, two) = (held_by(&store, me.clone()), held_by(&store, me));
        blobs.fail(Some(crate::task_store::Fail::Records));
        assert!(!store.withdraw(&one));
        assert!(!store.withdraw(&two));
        let before = blobs.attempts();
        store.purge_agent(&id("nobody"));
        assert_eq!(blobs.attempts() - before, 2, "one write and one unlink");
        blobs.fail(None);
        store.purge_agent(&id("nobody"));
        assert!(!blobs.has(&name_of(&one)) && !blobs.has(&name_of(&two)));
    }

    /// Contains the submitting person while the submission's own record is appended.
    struct ContainsOnAudit(Recorder, Arc<TaskStore>, bool);

    impl AuditEmit for ContainsOnAudit {
        fn emit(
            &self,
            rec: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
            let first = self.0.records().is_empty();
            if first {
                self.1.mark_unenrolled(&containing(&[me()]));
            }
            let (emitted, refuse) = (self.0.emit(rec), self.2 && !first);
            async move {
                emitted.await?;
                match refuse {
                    true => Err(AuditError::Serialize("sink refused".into())),
                    false => Ok(()),
                }
            }
        }
    }

    #[tokio::test]
    async fn a_hold_whose_record_the_trail_refuses_stores_no_task() {
        let (_g, pdp) = pdp("contained-unrecorded");
        let (blobs, store) = mem();
        let store = Arc::new(store);
        let emit = ContainsOnAudit(Recorder::new(), Arc::clone(&store), true);
        let view = SnapshotEnrollment(pdp.clone());
        let said = submit_via(
            pdp.clone(),
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (BOUND, None),
        )
        .await;
        assert!(matches!(said, Err(TaskRefusal::Audit(_))), "{said:?}");
        assert_eq!(store.len(), 0, "neither queued nor held");
        assert_eq!(reopen(&blobs).len(), 0);
    }

    #[tokio::test]
    async fn a_tasker_contained_during_the_submissions_audit_has_the_task_held_for_good() {
        let (_g, pdp) = pdp("contained-mid-submit");
        let (blobs, store) = mem();
        let store = Arc::new(store);
        let emit = ContainsOnAudit(Recorder::new(), Arc::clone(&store), false);
        let view = SnapshotEnrollment(pdp.clone());
        let task = submit_via(
            pdp.clone(),
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (BOUND, None),
        )
        .await
        .expect("the submission was permitted and is stored")
        .task
        .task_id;
        let said: Vec<(String, String, String)> = emit
            .0
            .records()
            .iter()
            .map(|r| {
                (
                    r.outcome.result.clone(),
                    r.outcome.reason.clone(),
                    r.outcome.posture.clone(),
                )
            })
            .collect();
        let s = |v: &str| v.to_string();
        assert_eq!(
            said,
            [
                (s("permit"), s("task stored"), s("authorized")),
                (
                    s("deny"),
                    s("task held: tasker contained"),
                    s("unavailable")
                ),
            ],
            "the hold is recorded before the task is stored held"
        );
        assert_eq!(emit.0.records()[1].subject.task_id, Some(task.to_string()));
        let rec = store.record(&task).unwrap();
        assert_eq!(
            (rec.state, rec.held_from),
            (TaskState::Held, Some(TaskState::Queued))
        );
        store.mark_unenrolled(&view);
        assert!(
            store.close_all_due().is_empty(),
            "the release lifts nothing"
        );
        assert_eq!(
            claim_head(&store, &id("hobi"), HOBI, signer()),
            Ok(Claimed::Idle),
            "never handed out"
        );
        assert_eq!(reopen(&blobs).record(&task).unwrap().state, TaskState::Held);
    }

    struct BreaksStoreThenFails(Recorder, crate::task_store::MemTaskBlobs);

    impl AuditEmit for BreaksStoreThenFails {
        fn emit(
            &self,
            rec: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
            let first = self.0.records().is_empty();
            self.1.fail(Some(crate::task_store::Fail::Records));
            let emitted = self.0.emit(rec);
            async move {
                emitted.await?;
                match first {
                    true => Ok(()),
                    false => Err(AuditError::Serialize("sink refused".into())),
                }
            }
        }
    }

    #[tokio::test]
    async fn a_kept_task_whose_corrective_record_fails_is_still_outcome_unknown() {
        let (_g, pdp) = pdp("kept-unaudited");
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = Arc::new(
            TaskStore::open(
                Box::new(blobs.clone()),
                Arc::new(crate::task_store::SystemClock),
            )
            .unwrap(),
        );
        let emit = BreaksStoreThenFails(Recorder::new(), blobs.clone());
        let view = SnapshotEnrollment(pdp.clone());
        let got = submit_via(
            pdp.clone(),
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (BOUND, None),
        )
        .await;
        assert_eq!(emit.0.records().len(), 2);
        assert!(
            matches!(&got, Err(TaskRefusal::Unavailable(why)) if why.starts_with("outcome unknown: ")),
            "{got:?}"
        );
    }

    #[test]
    fn a_confirm_that_lands_unsynced_is_taken_back_durably_before_it_is_done() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let v = view(&[("hobi", HOBI)]);
        let enrolled = at(store.generation(&id("hobi")), HOBI);
        let task = store
            .mint(signer(), &v, enrolled, Tasker::Uid(1000), None, sub("hobi"))
            .unwrap()
            .task
            .task_id;
        blobs.fail(Some(crate::task_store::Fail::Unsynced));
        assert!(matches!(
            store.confirm(&task, None, None),
            Err(TaskRefusal::Store(_))
        ));
        assert!(!store.withdraw(&task), "the unlink is not proven either");
        assert_eq!(store.len(), 0);
        blobs.fail(None);
        store.purge_agent(&id("nobody"));
        blobs.crash(1);
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert_eq!(reopened.len(), 0, "no live task reloads");
    }

    #[test]
    fn a_confirm_that_panics_after_its_write_is_still_taken_back() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let v = view(&[("hobi", HOBI)]);
        let enrolled = at(store.generation(&id("hobi")), HOBI);
        let task = store
            .mint(signer(), &v, enrolled, Tasker::Uid(1000), None, sub("hobi"))
            .unwrap()
            .task
            .task_id;
        blobs.after_save(|| panic!("sentinel-628-confirm-panic"));
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.confirm(&task, None, None)
        }));
        assert!(unwound.is_err());
        blobs.fail(Some(crate::task_store::Fail::Unlinks));
        assert!(store.withdraw(&task), "marked pending again, so done");
        blobs.fail(None);
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert_eq!(reopened.len(), 0, "no live task reloads");
    }

    #[test]
    fn a_withdrawal_that_panics_is_left_to_the_next_writer() {
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = TaskStore::open(
            Box::new(blobs.clone()),
            Arc::new(crate::task_store::SystemClock),
        )
        .unwrap();
        let v = view(&[("hobi", HOBI)]);
        let enrolled = at(store.generation(&id("hobi")), HOBI);
        let unconfirmed = store
            .mint(signer(), &v, enrolled, Tasker::Uid(1000), None, sub("hobi"))
            .unwrap()
            .task
            .task_id;
        let live = held_by(&store, Tasker::Uid(1000));
        blobs.fail(Some(crate::task_store::Fail::Panics));
        for task in [unconfirmed, live] {
            let unwound =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.withdraw(&task)));
            assert!(unwound.is_err());
        }
        blobs.fail(None);
        assert!(store.record(&live).is_none());
        store.purge_agent(&id("nobody"));
        assert!(!blobs.has(&name_of(&unconfirmed)));
        assert!(!blobs.has(&name_of(&live)));
        assert_eq!(store.len(), 0);
        assert!(store.abandoned.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn submit_stores_only_a_permitted_task() {
        let (_g, pdp) = pdp("permitted");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let task = submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
        assert_eq!(task.task.agent, "hobi");
        assert_eq!(store.len(), 1);
        let held = store
            .resolve(&task.task.task_id, &id("hobi"), HOBI)
            .unwrap();
        assert!(Arc::ptr_eq(&held, &task));
        assert_eq!(
            submit(&pdp, &store, user(), "jin", &emit)
                .await
                .unwrap_err(),
            TaskRefusal::Denied(format!("agent jin: uid {} is not a tasker", me()))
        );
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn a_refused_task_is_never_stored() {
        let (_g, pdp) = pdp("refused");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let counting = hooked(pdp.clone(), || {});
        let view = SnapshotEnrollment(pdp.clone());
        let refused = submit_via(
            counting.clone(),
            &store,
            &view,
            user(),
            sub("ghost"),
            &emit,
            (BOUND, None),
        )
        .await
        .unwrap_err();
        assert_eq!(
            refused,
            TaskRefusal::Denied("session.task: agent ghost is not enrolled".into())
        );
        assert_eq!(counting.calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.len(), 0);
        let mut bad = sub("hobi");
        bad.version = TASK_VERSION + 1;
        let refused = submit_via(
            counting.clone(),
            &store,
            &view,
            user(),
            bad,
            &emit,
            (BOUND, None),
        )
        .await
        .unwrap_err();
        assert!(matches!(refused, TaskRefusal::Schema(_)), "{refused:?}");
        assert_eq!(counting.calls.load(Ordering::SeqCst), 1, "no decision");
        assert_eq!(store.len(), 0);
        let records = emit.records();
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .all(|r| r.outcome.result == "deny" && r.subject.task_id.is_none()));
    }

    #[tokio::test]
    async fn submit_takes_the_tasker_from_the_connection_not_the_submission() {
        let (_g, pdp) = pdp("tasker");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let by_user = submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
        assert_eq!(by_user.task.tasker, Tasker::Uid(me()));
        let by_agent = submit(&pdp, &store, agent("hobi", HOBI, None), "jin", &emit)
            .await
            .unwrap();
        assert_eq!(
            by_agent.task.tasker,
            Tasker::Agent {
                agent: "hobi".into(),
                uid: HOBI
            }
        );
        let frame = maknae_proto::Request {
            protocol_version: maknae_proto::PROTOCOL_VERSION,
            verb: maknae_proto::Verb::TaskSubmit { task: sub("hobi") },
            task: None,
        };
        let bytes = maknae_proto::encode_request(&frame).unwrap();
        assert!(maknae_proto::decode_request(&bytes).is_ok());
        let schema = b"\x66schema";
        let at = bytes
            .windows(schema.len())
            .position(|w| w == schema)
            .unwrap();
        let labels = b"\x66labels\xa0";
        let end = bytes
            .windows(labels.len())
            .position(|w| w == labels)
            .unwrap()
            + labels.len();
        let mut forged = bytes[..end].to_vec();
        assert_eq!(forged[at - 1], 0xa5);
        forged[at - 1] = 0xa6;
        forged.extend_from_slice(b"\x66tasker\xa1\x63Uid\x00");
        forged.extend_from_slice(&bytes[end..]);
        assert!(maknae_proto::decode_request(&forged).is_err());
    }

    #[tokio::test]
    async fn every_submission_is_audited_with_task_agent_and_tasker() {
        let (_g, pdp) = pdp("audited");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let first = submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
        store.start_for_test(&first.task.task_id);
        let child = submit(
            &pdp,
            &store,
            agent("hobi", HOBI, Some(first.task.task_id)),
            "jin",
            &emit,
        )
        .await
        .unwrap();
        submit(&pdp, &store, user(), "jin", &emit)
            .await
            .unwrap_err();
        let records = emit.records();
        assert_eq!(records.len(), 3, "one record per submission");
        for r in &records {
            assert_eq!(
                (r.where_.host.as_str(), r.where_.socket.as_str()),
                ("task-host", "/run/maknae/task-11.sock")
            );
            assert_eq!((r.session_id, r.seq), (SESSION, 1));
            assert_eq!(r.subject.user.as_deref(), Some("alice"));
            assert_eq!(r.au3_1, serde_json::json!({ "site": "task-11" }));
        }
        let r = &records[0];
        assert_eq!(r.action, "session.task");
        assert_eq!(r.object.as_deref(), Some("agent:hobi"));
        assert_eq!(r.outcome.result, "permit");
        assert_eq!(r.source.uid, me());
        assert_eq!(r.subject.role.as_deref(), Some("user"));
        assert_eq!(r.subject.task_id, Some(first.task.task_id.to_string()));
        assert_eq!(
            r.subject.tasker.as_deref(),
            Some(format!("uid:{}", me()).as_str())
        );
        assert_eq!(
            (r.subject.agent.as_ref(), r.subject.parent_task_id.as_ref()),
            (None, None)
        );
        let r = &records[1];
        assert_eq!(r.object.as_deref(), Some("agent:jin"));
        assert_eq!(r.source.uid, HOBI);
        assert_eq!(r.subject.agent.as_deref(), Some("hobi"));
        assert_eq!(r.subject.task_id, Some(child.task.task_id.to_string()));
        assert_eq!(
            r.subject.parent_task_id,
            Some(first.task.task_id.to_string())
        );
        assert_eq!(r.subject.tasker.as_deref(), Some("agent:hobi"));
        let r = &records[2];
        assert_eq!(r.outcome.result, "deny");
        assert_eq!(
            r.outcome.reason,
            format!("agent jin: uid {} is not a tasker", me())
        );
        assert_eq!(r.object.as_deref(), Some("agent:jin"));
        assert_eq!(r.subject.task_id, None);
        assert!(records
            .iter()
            .all(|r| !maknae_audit_append::canonical_json(r)
                .unwrap()
                .contains(PROMPT)));
    }

    #[tokio::test]
    async fn an_audit_failure_withdraws_the_task() {
        let (_g, pdp) = pdp("audit-fails");
        let store = Arc::new(TaskStore::new());
        let refused = submit(&pdp, &store, user(), "hobi", &Recorder::failing())
            .await
            .unwrap_err();
        assert!(matches!(refused, TaskRefusal::Audit(_)), "{refused:?}");
        assert_eq!(store.len(), 0);
        let refused = submit(&pdp, &store, user(), "jin", &Recorder::failing())
            .await
            .unwrap_err();
        assert!(
            matches!(refused, TaskRefusal::Audit(_)),
            "an unaudited refusal is not answered: {refused:?}"
        );
    }

    #[tokio::test]
    async fn an_agent_whose_policy_denies_session_task_is_refused() {
        let (_g, pdp) = pdp("policy-deny");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let refused = submit(&pdp, &store, agent("suga", SUGA, None), "jin", &emit)
            .await
            .unwrap_err();
        assert_eq!(
            refused,
            TaskRefusal::Denied(
                "subject suga-svc: session.task denied by agents.suga.policy.actions entry session.task"
                    .into()
            )
        );
        assert_eq!(store.len(), 0);
        submit(&pdp, &store, agent("hobi", HOBI, None), "jin", &emit)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_child_records_exactly_the_task_the_submitting_request_cited() {
        let (_g, pdp) = pdp("child");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let parent = submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
        submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
        store.start_for_test(&parent.task.task_id);
        let child = submit(
            &pdp,
            &store,
            agent("hobi", HOBI, Some(parent.task.task_id)),
            "jin",
            &emit,
        )
        .await
        .unwrap();
        assert_eq!(child.task.parent, Some(parent.task.task_id));
        assert_eq!(
            child.task.tasker,
            Tasker::Agent {
                agent: "hobi".into(),
                uid: HOBI
            }
        );
        assert_eq!(child.task.agent, "jin");
        assert_eq!(
            store.record(&child.task.task_id).unwrap().root.partition(),
            format!("users/{}", me()),
            "a sub-task is rooted at the person who started the chain"
        );
    }

    #[tokio::test]
    async fn an_agent_task_on_its_own_initiative_records_no_parent() {
        let (_g, pdp) = pdp("initiative");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
        let child = submit(&pdp, &store, agent("hobi", HOBI, None), "jin", &emit)
            .await
            .unwrap();
        assert_eq!(child.task.parent, None);
    }

    #[tokio::test]
    async fn a_purged_under_task_refuses_the_child() {
        let (_g, pdp) = pdp("purged-parent");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let parent = submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
        store.purge_agent(&id("hobi"));
        let counting = hooked(pdp.clone(), || {});
        let view = SnapshotEnrollment(pdp.clone());
        let refused = submit_via(
            counting.clone(),
            &store,
            &view,
            agent("hobi", HOBI, Some(parent.task.task_id)),
            sub("jin"),
            &emit,
            (BOUND, None),
        )
        .await
        .unwrap_err();
        assert_eq!(refused, TaskRefusal::ParentNotHeld);
        assert_eq!(
            counting.calls.load(Ordering::SeqCst),
            0,
            "refused before the PDP"
        );
        assert_eq!(
            store.record(&parent.task.task_id).unwrap().close,
            Some(TaskClose::AgentGone)
        );
        let jins = submit(&pdp, &store, agent("hobi", HOBI, None), "jin", &emit)
            .await
            .unwrap();
        let refused = submit(
            &pdp,
            &store,
            agent("hobi", HOBI, Some(jins.task.task_id)),
            "jin",
            &emit,
        )
        .await
        .unwrap_err();
        assert_eq!(
            refused,
            TaskRefusal::ParentNotHeld,
            "jin's task is not hobi's"
        );
        let last = emit.records().pop().unwrap();
        assert_eq!(last.outcome.result, "deny");
        assert_eq!(last.subject.parent_task_id, None);
    }

    #[tokio::test]
    async fn a_user_task_has_no_parent() {
        let (_g, pdp) = pdp("user-parent");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let task = submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
        assert_eq!(task.task.parent, None);
        assert_eq!(emit.records()[0].subject.parent_task_id, None);
    }

    struct Obliging;

    impl Authorizer for Obliging {
        fn decide(&self, _: &Request) -> Verdict {
            Verdict::Permit {
                obligations: vec![maknae_security::Obligation {
                    id: "task-11-unknown-obligation".into(),
                    params: Default::default(),
                }],
            }
        }
        fn decide_cited_all(&self, reqs: &[Request]) -> Vec<Decided> {
            reqs.iter().map(|r| self.decide_cited(r)).collect()
        }
    }

    #[tokio::test]
    async fn a_permit_with_an_unhonorable_obligation_is_refused() {
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let refused = submit_via(
            Arc::new(Obliging),
            &store,
            &view(&[("hobi", HOBI)]),
            user(),
            sub("hobi"),
            &emit,
            (BOUND, None),
        )
        .await
        .unwrap_err();
        assert_eq!(
            refused,
            TaskRefusal::Denied("unhonorable obligation: task-11-unknown-obligation".into())
        );
        assert_eq!(store.len(), 0);
        assert_eq!(emit.records()[0].outcome.result, "deny");
    }

    #[tokio::test]
    async fn a_mint_racing_a_purge_does_not_insert() {
        let (_g, pdp) = pdp("race");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let purging = store.clone();
        let racing = hooked(pdp.clone(), move || drop(purging.purge_agent(&id("hobi"))));
        let view = SnapshotEnrollment(pdp.clone());
        let refused = submit_via(
            racing,
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (BOUND, None),
        )
        .await
        .unwrap_err();
        assert_eq!(refused, TaskRefusal::AgentGone);
        assert_eq!(store.len(), 0);
        assert_eq!(emit.records().len(), 1);
        assert_eq!(emit.records()[0].outcome.result, "deny");
    }

    #[tokio::test]
    async fn a_re_enrollment_between_the_decision_and_the_mint_does_not_insert() {
        let (g, pdp) = pdp("re-enrolled");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let config = g.0.clone();
        let reloading = pdp.clone();
        let racing = hooked(pdp.clone(), move || {
            crate::test_fixtures::write_agent(&config, "hobi", "hobi-svc", HOBI_AGAIN, "user");
            reloading.baseline().reload_from_file().unwrap();
        });
        let view = SnapshotEnrollment(pdp.clone());
        let refused = submit_via(
            racing,
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (BOUND, None),
        )
        .await
        .unwrap_err();
        assert_eq!(
            pdp.baseline().snapshot().agent_uid("hobi"),
            Some(HOBI_AGAIN)
        );
        assert_eq!(refused, TaskRefusal::AgentGone);
        assert_eq!(store.len(), 0);
        assert_eq!(emit.records().len(), 1);
        assert_eq!(emit.records()[0].outcome.result, "deny");
    }

    #[test]
    fn retain_enrolled_bumps_an_agent_whose_uid_changed_though_it_holds_no_task() {
        let store = Arc::new(TaskStore::new());
        let first = view(&[("hobi", HOBI), ("jin", JIN)]);
        assert_eq!(store.observe(&first, &id("hobi")), (0, Some(HOBI)));
        assert_eq!(store.observe(&first, &id("jin")), (0, Some(JIN)));
        assert_eq!(store.observe(&first, &id("suga")), (0, None));
        store.retain_enrolled(&first);
        assert_eq!(store.generation(&id("hobi")), 0);
        store.retain_enrolled(&view(&[("hobi", HOBI_AGAIN), ("jin", JIN)]));
        assert_eq!(store.generation(&id("hobi")), 1);
        assert_eq!(store.generation(&id("jin")), 0);
        store.retain_enrolled(&view(&[("hobi", HOBI_AGAIN)]));
        assert_eq!(store.generation(&id("hobi")), 1);
        assert_eq!(store.generation(&id("jin")), 1);
        store.retain_enrolled(&view(&[("hobi", HOBI_AGAIN)]));
        assert_eq!(store.generation(&id("jin")), 1);
        let back = view(&[("hobi", HOBI_AGAIN), ("jin", JIN)]);
        assert_eq!(store.observe(&back, &id("jin")), (1, Some(JIN)));
        store.retain_enrolled(&back);
        assert_eq!(store.generation(&id("jin")), 1);
        store.retain_enrolled(&view(&[("hobi", HOBI_AGAIN), ("jin", 4242)]));
        assert_eq!(store.generation(&id("jin")), 2);
        assert_eq!(store.len(), 0);
    }

    struct Panicking;

    impl Authorizer for Panicking {
        fn decide(&self, _: &Request) -> Verdict {
            panic!("task-11 authorizer panic")
        }
        fn decide_cited_all(&self, reqs: &[Request]) -> Vec<Decided> {
            reqs.iter().map(|r| self.decide_cited(r)).collect()
        }
    }

    struct Stalling;

    impl Authorizer for Stalling {
        fn decide(&self, _: &Request) -> Verdict {
            std::thread::sleep(std::time::Duration::from_millis(400));
            Verdict::Permit {
                obligations: Vec::new(),
            }
        }
        fn decide_cited_all(&self, reqs: &[Request]) -> Vec<Decided> {
            reqs.iter().map(|r| self.decide_cited(r)).collect()
        }
    }

    #[tokio::test]
    async fn a_panicking_authorizer_is_refused_and_audited() {
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let refused = submit_via(
            Arc::new(Panicking),
            &store,
            &view(&[("hobi", HOBI)]),
            user(),
            sub("hobi"),
            &emit,
            (BOUND, None),
        )
        .await
        .unwrap_err();
        assert_eq!(
            refused,
            TaskRefusal::Denied("indeterminate (fail-closed)".into())
        );
        assert_eq!(store.len(), 0);
        let records = emit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome.reason, "indeterminate (fail-closed)");
    }

    #[tokio::test]
    async fn an_authorizer_that_stalls_past_the_bound_is_refused_and_audited() {
        let breaker: Breaker = Arc::new(tokio::sync::Mutex::new(BlockingBreaker::new(1)));
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let refused = submit_via(
            Arc::new(Stalling),
            &store,
            &view(&[("hobi", HOBI)]),
            user(),
            sub("hobi"),
            &emit,
            (std::time::Duration::from_millis(50), Some(breaker.clone())),
        )
        .await
        .unwrap_err();
        let want = "authorization decision timed out";
        assert_eq!(refused, TaskRefusal::Denied(want.into()));
        assert!(
            breaker.lock().await.is_open_at(std::time::Instant::now()),
            "the timeout is recorded on the breaker"
        );
        assert_eq!(store.len(), 0);
        let records = emit.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome.reason, want);
    }

    #[tokio::test]
    async fn an_open_breaker_refuses_without_calling_the_pdp() {
        let (_g, pdp) = pdp("breaker-open");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let counting = hooked(pdp.clone(), || {});
        let view = SnapshotEnrollment(pdp.clone());
        let open: Breaker = Arc::new(tokio::sync::Mutex::new(BlockingBreaker::new(0)));
        let refused = submit_via(
            counting.clone(),
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (BOUND, Some(open)),
        )
        .await
        .unwrap_err();
        let want = "authorization decision circuit breaker open";
        assert_eq!(refused, TaskRefusal::Denied(want.into()));
        let full: Breaker = Arc::default();
        for _ in 0..crate::BLOCKING_BREAKER_MAX_IN_FLIGHT {
            full.lock()
                .await
                .begin_attempt_at(std::time::Instant::now());
        }
        let refused = submit_via(
            counting.clone(),
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (BOUND, Some(full.clone())),
        )
        .await
        .unwrap_err();
        let full_reason = "authorization decision blocking worker budget exhausted";
        assert_eq!(refused, TaskRefusal::Denied(full_reason.into()));
        assert_eq!(counting.calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.len(), 0);
        let reasons: Vec<_> = emit
            .records()
            .into_iter()
            .map(|r| r.outcome.reason)
            .collect();
        assert_eq!(reasons, [want, full_reason]);
    }

    #[tokio::test]
    async fn a_decision_releases_its_breaker_slot() {
        let (_g, pdp) = pdp("breaker-slot");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let view = SnapshotEnrollment(pdp.clone());
        let one: Breaker = Arc::default();
        for _ in 1..crate::BLOCKING_BREAKER_MAX_IN_FLIGHT {
            one.lock().await.begin_attempt_at(std::time::Instant::now());
        }
        for _ in 0..2 {
            submit_via(
                pdp.clone(),
                &store,
                &view,
                user(),
                sub("hobi"),
                &emit,
                (BOUND, Some(one.clone())),
            )
            .await
            .unwrap();
        }
    }

    struct Capturing<P> {
        inner: Arc<P>,
        seen: Mutex<Vec<Request>>,
    }

    impl<P: Authorizer> Authorizer for Capturing<P> {
        fn decide(&self, req: &Request) -> Verdict {
            self.decide_cited(req).verdict
        }
        fn decide_reporting_role(&self, req: &Request) -> (Verdict, Option<&'static str>) {
            let d = self.decide_cited(req);
            (d.verdict, d.role)
        }
        fn decide_cited(&self, req: &Request) -> Decided {
            self.seen.lock().unwrap().push(req.clone());
            self.inner.decide_cited(req)
        }
        fn decide_cited_all(&self, reqs: &[Request]) -> Vec<Decided> {
            reqs.iter().map(|r| self.decide_cited(r)).collect()
        }
    }

    #[tokio::test]
    async fn a_submission_carries_its_connections_san_and_lane() {
        let (_g, pdp) = pdp("san-lane");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let view: Arc<dyn EnrollmentView> = Arc::new(SnapshotEnrollment(pdp.clone()));
        let parent = submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
        store.start_for_test(&parent.task.task_id);
        let capturing = Arc::new(Capturing {
            inner: pdp.clone(),
            seen: Mutex::default(),
        });
        let w = wctx();
        let seq = maknae_audit_append::Seq::new();
        let ctx = SubmitCtx {
            where_: &w,
            session_id: SESSION,
            seq: &seq,
            user: None,
            peer_uri: Some("spiffe://d/plane/agent/hobi"),
            lane: maknae_security::Lane::Remote,
            decide_timeout: BOUND,
            text_max: 1 << 20,
        };
        let pdp_under = Decider {
            authorizer: capturing.clone(),
            breaker: Breaker::default(),
        };
        let _ = submit_under(
            pdp_under,
            &store,
            &shared_signer(),
            &view,
            &ctx,
            agent("hobi", HOBI, Some(parent.task.task_id)),
            sub("jin"),
            &emit,
        )
        .await;
        let last = emit.records().pop().unwrap();
        assert_eq!(
            last.subject.plane_uri_san.as_deref(),
            Some("spiffe://d/plane/agent/hobi")
        );
        let seen = capturing.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].context.0.get(maknae_security::CONTEXT_DAC_LANE),
            Some(&maknae_security::AttrValue::Str("remote".into()))
        );
    }

    #[tokio::test]
    async fn submit_task_decides_under_the_request_paths_breaker() {
        let (_g, pdp) = pdp("global-breaker");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let w = wctx();
        let seq = maknae_audit_append::Seq::new();
        let ctx = SubmitCtx {
            where_: &w,
            session_id: SESSION,
            seq: &seq,
            user: Some(ACCOUNT),
            peer_uri: None,
            lane: maknae_security::Lane::Local,
            decide_timeout: BOUND,
            text_max: 1 << 20,
        };
        let view: Arc<dyn EnrollmentView> = Arc::new(SnapshotEnrollment(pdp.clone()));
        submit_task(
            pdp.clone(),
            &store,
            &shared_signer(),
            &view,
            &ctx,
            user(),
            sub("hobi"),
            &emit,
        )
        .await
        .unwrap();
        assert_eq!(store.len(), 1);
        assert!(Arc::ptr_eq(
            &decider(pdp).breaker,
            &crate::run::authz_decide_breaker()
        ));
    }

    /// Gated: set `MAKNAE_TEST_VAULT_BIN` to a `vault` binary. Starts a throwaway
    /// `vault server -dev -dev-tls` on loopback, gives it the kernel plane's PKI and
    /// AppRole, mints a real leaf, and stops the server.
    #[tokio::test]
    async fn the_plane_signer_reports_the_minted_leaf() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Child, Command, Stdio};
        let Some(bin) = std::env::var_os("MAKNAE_TEST_VAULT_BIN") else {
            return;
        };
        struct Dev(Child, std::path::PathBuf);
        impl Drop for Dev {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
                let _ = std::fs::remove_dir_all(&self.1);
            }
        }
        let dir = std::env::temp_dir().join(format!("maknae-dev-vault-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tls")).unwrap();
        std::fs::create_dir_all(dir.join("vault-tls")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr = format!("https://127.0.0.1:{port}");
        let child = Command::new(&bin)
            .args(["server", "-dev", "-dev-tls", "-dev-root-token-id=root"])
            .arg(format!("-dev-listen-address=127.0.0.1:{port}"))
            .arg(format!(
                "-dev-tls-cert-dir={}",
                dir.join("vault-tls").display()
            ))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let _dev = Dev(child, dir.clone());
        let vault_ca = dir.join("vault-tls").join("vault-ca.pem");
        let vault = |args: &[&str], stdin: Option<&str>| -> String {
            use std::io::Write;
            let mut c = Command::new(&bin)
                .args(args)
                .env("VAULT_ADDR", &addr)
                .env("VAULT_CACERT", &vault_ca)
                .env("VAULT_TOKEN", "root")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = c.stdin.take().unwrap();
            input.write_all(stdin.unwrap_or("").as_bytes()).unwrap();
            drop(input);
            let out = c.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "vault {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        let mut up = false;
        for _ in 0..100 {
            let status = Command::new(&bin)
                .arg("status")
                .env("VAULT_ADDR", &addr)
                .env("VAULT_CACERT", &vault_ca)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            if status.success() {
                up = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(up, "the dev Vault did not come up");

        let ec = ["key_type=ec", "key_bits=384"];
        vault(
            &[
                "secrets",
                "enable",
                "-path=maknae-pki",
                "-max-lease-ttl=87600h",
                "pki",
            ],
            None,
        );
        let root = vault(
            &[
                &[
                    "write",
                    "-field=certificate",
                    "maknae-pki/root/generate/internal",
                    "common_name=root",
                    "ttl=87600h",
                ][..],
                &ec[..],
            ]
            .concat(),
            None,
        );
        vault(
            &[
                "secrets",
                "enable",
                "-path=maknae-pki-int",
                "-max-lease-ttl=43800h",
                "pki",
            ],
            None,
        );
        let csr = vault(
            &[
                &[
                    "write",
                    "-field=csr",
                    "maknae-pki-int/intermediate/generate/internal",
                    "common_name=int",
                ][..],
                &ec[..],
            ]
            .concat(),
            None,
        );
        let int = vault(
            &[
                "write",
                "-field=certificate",
                "maknae-pki/root/sign-intermediate",
                "csr=-",
                "format=pem",
                "ttl=43800h",
            ],
            Some(&csr),
        );
        vault(
            &[
                "write",
                "maknae-pki-int/intermediate/set-signed",
                "certificate=-",
            ],
            Some(&format!("{}\n{}", int.trim(), root.trim())),
        );
        vault(
            &[
                &[
                    "write",
                    "maknae-pki-int/roles/maknae-kernel",
                    "allowed_uri_sans=spiffe://dev-01/plane/kernel",
                    "use_csr_sans=true",
                    "use_csr_common_name=false",
                    "allow_ip_sans=false",
                    "allow_localhost=false",
                    "allow_wildcard_certificates=false",
                    "require_cn=false",
                    "key_usage=DigitalSignature",
                    "signature_bits=384",
                    "ttl=3600",
                    "max_ttl=3600",
                ][..],
                &ec[..],
            ]
            .concat(),
            None,
        );
        vault(
            &["policy", "write", "maknae-kernel", "-"],
            Some(
                "path \"maknae-pki-int/sign/maknae-kernel\" { capabilities = [\"update\"] }\n\
                 path \"maknae-pki-int/revoke\" { capabilities = [\"update\"] }\n\
                 path \"maknae-pki-int/issuer/default/json\" { capabilities = [\"read\"] }\n\
                 path \"auth/token/renew-self\" { capabilities = [\"update\"] }\n\
                 path \"auth/token/lookup-self\" { capabilities = [\"read\"] }\n\
                 path \"auth/token/revoke-self\" { capabilities = [\"update\"] }\n",
            ),
        );
        vault(&["auth", "enable", "-path=maknae-approle", "approle"], None);
        vault(
            &[
                "write",
                "auth/maknae-approle/role/maknaed",
                "token_policies=maknae-kernel",
                "token_no_default_policy=true",
            ],
            None,
        );
        let role_id = vault(
            &[
                "read",
                "-field=role_id",
                "auth/maknae-approle/role/maknaed/role-id",
            ],
            None,
        );
        let secret_id = vault(
            &[
                "write",
                "-f",
                "-field=secret_id",
                "auth/maknae-approle/role/maknaed/secret-id",
            ],
            None,
        );

        let file = |rel: &str, body: &str| {
            let path = dir.join(rel);
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        file(
            "maknae.yaml",
            &format!("core:\n  deployment_id: dev-01\nvault:\n  addr: {addr}\n  plane_key: ecdsa-p384-sha384\n"),
        );
        file("tls/maknae-root-ca.crt", &root);
        file("tls/maknae-int-ca.crt", &int);
        file(
            "tls/vault-ca.crt",
            &std::fs::read_to_string(&vault_ca).unwrap(),
        );
        file("maknaed-approle-id", &role_id);
        maknae_crypto::init().unwrap();
        let doc = maknae_config::load_config(
            &dir,
            &[maknae_config::SectionSpec {
                name: "vault".to_string(),
                required: true,
            }],
        )
        .unwrap();
        let client = Arc::new(
            maknae_vault::PlaneClient::from_document_with_secret(
                &doc,
                &dir,
                maknae_vault::Plane::Kernel,
                maknae_io::Zeroizing::new(secret_id.trim().to_string()),
            )
            .unwrap(),
        );
        let plane = PlaneSigner(Arc::clone(&client));
        assert_eq!(plane.current_leaf(), None, "no leaf before the first mint");
        let minted = client.mint().await.unwrap();
        let want = maknae_vault::task_sig::identity_fingerprint(&minted).unwrap();
        assert_eq!(plane.current_leaf(), Some(want));
    }

    #[test]
    fn perform_counts_only_the_closes_and_holds_the_disk_took() {
        let (blobs, store) = mem();
        held_by(&store, Tasker::Uid(1000));
        held_by(&store, Tasker::Uid(1000));
        store.held().unenroll(&id("hobi"), |_| true);
        let due = store.due(8);
        assert_eq!(due.len(), 2);
        blobs.fail(Some(crate::task_store::Fail::Records));
        assert_eq!(store.perform(&due), 0, "a refused close is not counted");
        blobs.fail(None);
        assert_eq!(store.perform(&store.due(8)), 2);
        let task = held_by(&store, Tasker::Uid(1001));
        store.held().hold_contained(&containing(&[1001]));
        let due = store.due(8);
        assert_eq!(due.len(), 1);
        blobs.fail(Some(crate::task_store::Fail::Records));
        assert_eq!(store.perform(&due), 0, "a refused hold is not counted");
        blobs.fail(None);
        assert_eq!(store.perform(&store.due(8)), 1);
        assert_eq!(store.record(&task).unwrap().state, TaskState::Held);
    }

    #[test]
    fn a_sweep_stops_at_a_disk_that_refuses() {
        let (blobs, store) = mem();
        let task = held_by(&store, Tasker::Uid(1000));
        blobs.fail(Some(crate::task_store::Fail::Records));
        assert_eq!(store.purge_agent(&id("hobi")).len(), 1);
        assert_eq!(store.record(&task).unwrap().state, TaskState::Queued);
    }

    #[test]
    fn a_stored_hold_is_not_marked_again() {
        let (_blobs, store) = mem();
        let task = held_by(&store, Tasker::Uid(1000));
        store.held().hold_contained(&containing(&[1000]));
        assert_eq!(store.perform(&store.due(8)), 1);
        assert_eq!(store.record(&task).unwrap().state, TaskState::Held);
        store.held().hold_contained(&containing(&[1000]));
        assert_eq!(store.hold_mark(&task), None);
    }

    #[test]
    fn an_agents_queue_holds_only_its_own_queued_tasks() {
        let (_blobs, store) = mem();
        let v = view(&[("hobi", HOBI), ("jin", JIN)]);
        mint(&store, &v, "hobi");
        let other = mint(&store, &v, "jin").task.task_id;
        let second = mint(&store, &v, "hobi").task.task_id;
        assert!(matches!(
            claim_head(&store, &id("hobi"), HOBI, signer()),
            Ok(Claimed::Delivered { .. })
        ));
        assert_eq!(store.queue(&id("hobi")), vec![second]);
        assert_eq!(store.queue(&id("jin")), vec![other]);
    }

    #[test]
    fn the_store_reads_its_own_clock() {
        let clock = Arc::new(crate::task_store::ManualClock::at(4_321));
        let store =
            TaskStore::open(Box::new(crate::task_store::MemTaskBlobs::default()), clock).unwrap();
        assert_eq!(store.now(), 4_321);
    }

    #[test]
    fn a_page_of_exactly_the_limit_names_no_next() {
        let (_blobs, store) = mem();
        let v = view(&[("hobi", HOBI)]);
        for _ in 0..3 {
            mint(&store, &v, "hobi");
        }
        let (page, next) = store.list(&Tasker::Uid(1000), &id("hobi"), None, 3);
        assert_eq!((page.len(), next), (3, None));
        let (page, next) = store.list(&Tasker::Uid(1000), &id("hobi"), None, 2);
        assert_eq!(page.len(), 2);
        assert!(next.is_some());
    }

    #[test]
    fn each_drawn_id_is_fresh() {
        assert_ne!(draw_id().unwrap(), draw_id().unwrap());
    }

    #[tokio::test]
    async fn an_unconfirmed_submission_is_said_in_its_own_words() {
        let store = Arc::new(TaskStore::new());
        let deadline = tokio::time::Instant::now() + BOUND;
        let late = format!("outcome unknown: {LATE}");
        let busy = "not done: the task store was busy".to_string();
        let said = |kept, why: &str| {
            let (store, why) = (Arc::clone(&store), why.to_string());
            async move {
                let task = held_by(&store, Tasker::Uid(1000));
                unconfirmed(
                    &store,
                    me(),
                    deadline,
                    task,
                    kept,
                    TaskRefusal::Unavailable(why),
                )
                .await
            }
        };
        assert_eq!(
            said(true, &late).await,
            (TaskRefusal::Unavailable(late.clone()), late.clone())
        );
        let unknown = format!("outcome unknown: {busy}");
        assert_eq!(
            said(true, &busy).await,
            (TaskRefusal::Unavailable(unknown.clone()), unknown)
        );
        let (refusal, why) = said(false, &late).await;
        assert_eq!(
            refusal,
            TaskRefusal::Unavailable(format!("not done: {LATE}"))
        );
        assert!(why.starts_with(&format!("not done: {LATE}; ")), "{why}");
        let (refusal, why) = said(false, &busy).await;
        assert_eq!(refusal, TaskRefusal::Unavailable(busy.clone()));
        assert!(why.starts_with(&format!("{busy}; ")), "{why}");
    }

    struct FailsUnsyncedOnAudit(SlowsStoreOnAudit);

    impl AuditEmit for FailsUnsyncedOnAudit {
        fn emit(
            &self,
            rec: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
            self.0 .1.fail(Some(crate::task_store::Fail::Unsynced));
            self.0.emit(rec)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_late_confirm_whose_write_then_fails_is_said_late_and_failed() {
        let _alone = STALLS.lock().await;
        let (_g, pdp) = pdp("confirm-late-failed");
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = Arc::new(
            TaskStore::open(
                Box::new(blobs.clone()),
                Arc::new(crate::task_store::SystemClock),
            )
            .unwrap(),
        );
        let emit = FailsUnsyncedOnAudit(SlowsStoreOnAudit(Recorder::new(), blobs.clone()));
        let view = SnapshotEnrollment(pdp.clone());
        let got = submit_via(
            pdp.clone(),
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (std::time::Duration::from_millis(400), None),
        )
        .await;
        assert_eq!(
            got.err(),
            Some(TaskRefusal::Unavailable(format!("outcome unknown: {LATE}")))
        );
        blobs.slow(None);
        store.quiesce();
        let late: Vec<Option<String>> = store
            .take_notices()
            .into_iter()
            .filter_map(|n| match n {
                Notice::Late { failed, .. } => Some(failed),
                _ => None,
            })
            .collect();
        assert!(
            matches!(&late[..], [Some(why)] if why.contains("sentinel-628-unsynced")),
            "{late:?}"
        );
    }

    #[tokio::test]
    async fn a_submission_confirmed_in_time_is_not_said_late() {
        let (_g, pdp) = pdp("confirmed-in-time");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
        assert!(!store
            .take_notices()
            .iter()
            .any(|n| matches!(n, Notice::Late { .. })));
    }

    struct ContainsBeforeConfirm {
        trail: Recorder,
        store: Arc<TaskStore>,
        blobs: crate::task_store::MemTaskBlobs,
        stale: TaskId,
        armed: std::sync::atomic::AtomicBool,
    }

    impl AuditEmit for ContainsBeforeConfirm {
        fn emit(
            &self,
            rec: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
            if self.armed.swap(false, Ordering::SeqCst) {
                self.blobs.fail(Some(crate::task_store::Fail::Unsynced));
                assert!(self
                    .store
                    .publish_report(&self.stale, text("r"), None)
                    .is_err());
                self.blobs.fail(None);
                let store = Arc::clone(&self.store);
                self.blobs
                    .after_save(move || store.mark_unenrolled(&containing(&[me()])));
            }
            self.trail.emit(rec)
        }
    }

    #[tokio::test]
    async fn a_hold_marked_after_the_submission_looked_is_recorded_and_stored_held() {
        let (_g, pdp) = pdp("held-before-confirm");
        let blobs = crate::task_store::MemTaskBlobs::default();
        let store = Arc::new(
            TaskStore::open(
                Box::new(blobs.clone()),
                Arc::new(crate::task_store::SystemClock),
            )
            .unwrap(),
        );
        let stale = held_by(&store, Tasker::Uid(1000));
        let emit = ContainsBeforeConfirm {
            trail: Recorder::new(),
            store: Arc::clone(&store),
            blobs,
            stale,
            armed: std::sync::atomic::AtomicBool::new(true),
        };
        let view = SnapshotEnrollment(pdp.clone());
        let task = submit_via(
            pdp.clone(),
            &store,
            &view,
            user(),
            sub("hobi"),
            &emit,
            (BOUND, None),
        )
        .await
        .unwrap()
        .task
        .task_id;
        let rec = store.record(&task).unwrap();
        assert_eq!(
            (rec.state, rec.held_from),
            (TaskState::Held, Some(TaskState::Queued))
        );
        let trail = emit.trail.records();
        assert!(trail.iter().any(
            |r| r.outcome.result == "deny" && r.outcome.reason == "task held: tasker contained"
        ));
    }

    #[test]
    fn a_draw_that_keeps_colliding_is_refused_as_a_broken_random_source() {
        let store = Arc::new(TaskStore::new());
        let v = view(&[("hobi", HOBI)]);
        let mut draw = || Ok([7u8; 16]);
        let mint = |draw: &mut dyn FnMut() -> Result<[u8; 16], TaskRefusal>| {
            store.mint_with_live(
                draw,
                signer(),
                &v,
                at(0, HOBI),
                Tasker::Uid(1),
                None,
                sub("hobi"),
            )
        };
        assert!(mint(&mut draw).is_ok());
        assert_eq!(mint(&mut draw).err(), Some(TaskRefusal::Random));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_close_selected_before_a_hold_was_marked_closes_nothing() {
        let (_blobs, store) = mem();
        let task = held_by(&store, Tasker::Uid(1000));
        store.held().unenroll(&id("hobi"), |_| true);
        let stale = store.due(8);
        assert!(matches!(
            stale[..],
            [Due {
                why: DueFor::Close(_),
                ..
            }]
        ));
        store.held().hold_contained(&containing(&[1000]));
        assert_eq!(store.perform(&stale), 0);
        assert_eq!(store.record(&task).unwrap().state, TaskState::Queued);
        store.perform(&store.due(8));
        assert_eq!(store.record(&task).unwrap().state, TaskState::Held);
    }

    #[test]
    fn a_lease_renewed_to_exactly_now_has_not_lapsed() {
        let clock = Arc::new(crate::task_store::ManualClock::at(1_000));
        let store = TaskStore::open(
            Box::new(crate::task_store::MemTaskBlobs::default()),
            clock.clone(),
        )
        .unwrap();
        let v = view(&[("hobi", HOBI)]);
        let task = mint(&store, &v, "hobi").task.task_id;
        assert!(matches!(
            claim_head(&store, &id("hobi"), HOBI, signer()),
            Ok(Claimed::Delivered { .. })
        ));
        let lease = store.hot(&task).unwrap().lease_until;
        clock.set(lease + 1);
        let stale = store.due(8);
        assert!(matches!(
            stale[..],
            [Due {
                why: DueFor::Close(TaskClose::AgentLost),
                ..
            }]
        ));
        clock.set(lease - 300);
        assert!(matches!(
            claim_head(&store, &id("hobi"), HOBI, signer()),
            Ok(Claimed::Delivered { .. })
        ));
        let renewed = store.hot(&task).unwrap().lease_until;
        assert_eq!(renewed, lease - 300 + CLAIM_LEASE.as_secs() as i64);
        clock.set(renewed);
        assert_eq!(store.perform(&stale), 0);
        assert_eq!(store.record(&task).unwrap().state, TaskState::Working);
    }
}
