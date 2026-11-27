//! The in-kernel task store and the `session.task` submission path (#609).
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use maknae_audit_append::AuditEmit;
use maknae_config::AgentId;
use maknae_proto::{
    Binding, SecretText, SignedTask, TaskClose, TaskId, TaskObject, TaskReportPage, TaskState,
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
pub(crate) const ID_DRAWS: u32 = 4;
const CONTAINED: &str = "the tasker, the root of its chain or the agent is contained";
const OWN_HELD: &str = "an agent submits under the task it holds";

/// A queued task whose tasker's standing was found good, and the policy load it was
/// found good on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoodStanding {
    pub task: TaskId,
    pub load: Load,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Confirm {
    Queued,
    Held(Option<Contained>),
}

/// The trail's reason for a hold.
pub(crate) fn held_reason(who: Contained, agent: &AgentId) -> String {
    match who {
        Contained::Tasker => "task held: tasker contained".into(),
        Contained::Root => "task held: root contained".into(),
        Contained::Agent => format!("task held: agent {} contained", agent.as_str()),
    }
}

fn tasker_uid(tasker: &Tasker) -> Option<u32> {
    match tasker {
        Tasker::Uid(uid) | Tasker::Agent { uid, .. } => Some(*uid),
        Tasker::Remote(_) => None,
    }
}

fn root_uid(view: &dyn EnrollmentView, root: &RootTasker) -> Option<u32> {
    match root {
        RootTasker::Person { uid } => Some(*uid),
        RootTasker::Agent { agent } => AgentId::parse(agent)
            .ok()
            .and_then(|agent| view.agent_uid(&agent)),
    }
}

/// Who, of `rec`'s tasker, root and agent, the view holds contained.
fn contained_in(view: &dyn EnrollmentView, rec: &TaskRecord) -> Option<Contained> {
    let contained = |uid: u32| view.contained(uid);
    if tasker_uid(&rec.tasker).is_some_and(contained) {
        Some(Contained::Tasker)
    } else if root_uid(view, &rec.root).is_some_and(contained) {
        Some(Contained::Root)
    } else if open(rec) && contained(rec.agent_uid) {
        Some(Contained::Agent)
    } else {
        None
    }
}

/// A tasker or root that is an agent the view no longer resolves, whose containment
/// therefore cannot be judged.
fn unresolved(view: &dyn EnrollmentView, rec: &TaskRecord) -> Option<ReleaseRefusal> {
    let gone = |agent: &str| {
        AgentId::parse(agent)
            .ok()
            .and_then(|agent| view.agent_uid(&agent))
            .is_none()
    };
    match (&rec.tasker, &rec.root) {
        (Tasker::Agent { agent, .. }, _) if gone(agent) => Some(ReleaseRefusal::TaskerUnresolved),
        (_, RootTasker::Agent { agent }) if gone(agent) => Some(ReleaseRefusal::RootUnresolved),
        _ => None,
    }
}

/// Why a task is due an act of the kernel's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DueFor {
    Close(TaskClose),
    Expiry,
    Hold(Contained),
    /// A report or close notice no tasker can collect: the task it was given under ended.
    Orphaned,
}

/// Who is contained, for a task that is held: its agent, the tasker who gave it, or the
/// person or agent at the root of its chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Contained {
    Tasker,
    Root,
    Agent,
}

/// The held tasks an administrator names: every one, or those whose tasker, root or
/// agent is the uid, or is the agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeldSelect<'a> {
    Every,
    Uid(u32),
    Agent(&'a AgentId),
}

/// A held task, as an administrator lists it; `held_from` reads `Held` when the record
/// does not name it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldTask {
    pub seq: u64,
    pub view: TaskView,
    pub tasker: Tasker,
    pub held_from: TaskState,
    pub held_for: Option<Contained>,
    pub held_at: Option<i64>,
}

/// What a release of `task` would do, as decided before it is recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleasePlan {
    pub task: TaskId,
    pub agent: AgentId,
    pub tasker: Tasker,
    pub parent: Option<TaskId>,
    pub from: TaskState,
    pub to: TaskState,
}

/// A stored release; `rseq` is the report ordinal issued again for a held report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Released {
    pub task: TaskId,
    pub from: TaskState,
    pub now: TaskState,
    pub rseq: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseRefusal {
    Unknown,
    NotHeld,
    ParentHeld(TaskId),
    StillContained(Contained),
    TaskerUnresolved,
    RootUnresolved,
    NotDone(String),
    OutcomeUnknown(String),
}

fn selected(view: &dyn EnrollmentView, rec: &TaskRecord, select: HeldSelect<'_>) -> bool {
    match select {
        HeldSelect::Every => true,
        HeldSelect::Uid(uid) => {
            tasker_uid(&rec.tasker) == Some(uid)
                || root_uid(view, &rec.root) == Some(uid)
                || rec.agent_uid == uid
        }
        HeldSelect::Agent(agent) => {
            matches!(&rec.tasker, Tasker::Agent { agent: a, .. } if a == agent.as_str())
                || matches!(&rec.root, RootTasker::Agent { agent: a } if a == agent.as_str())
                || rec.agent == *agent
        }
    }
}

fn release_state(from: TaskState) -> TaskState {
    match from {
        TaskState::Working => TaskState::Queued,
        TaskState::Queued | TaskState::Reported | TaskState::Closed | TaskState::Held => from,
    }
}

pub(crate) fn unreleased(refused: TaskRefusal) -> ReleaseRefusal {
    match refused {
        TaskRefusal::Unavailable(why) => ReleaseRefusal::OutcomeUnknown(
            why.strip_prefix(OUTCOME_UNKNOWN)
                .map_or_else(|| why.clone(), str::to_owned),
        ),
        TaskRefusal::Store(why) => ReleaseRefusal::NotDone(why),
        other => ReleaseRefusal::NotDone(other.to_string()),
    }
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
    /// `fresh` from the task's start from `Queued` until a request cites it.
    Delivered {
        signed: Arc<SignedTask>,
        partition: String,
        fresh: bool,
    },
    Idle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Heartbeat {
    /// `addendum` when the agent has not seen it.
    FollowUps {
        task: TaskId,
        tasker: Tasker,
        from: u32,
        items: Vec<SecretText>,
        addendum: Option<Arc<maknae_proto::SignedAddendum>>,
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
    FollowUpsUnseen,
    NotWorking,
    Unavailable(String),
    Unbound(String),
    Unreached(String),
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
            TaskRefusal::FollowUpsUnseen => {
                f.write_str("the task holds follow-ups the report has not seen")
            }
            TaskRefusal::NotWorking => f.write_str("the task is not working"),
            TaskRefusal::Unavailable(why) => f.write_str(why),
            TaskRefusal::Unbound(why) => write!(f, "task not bound: {why}"),
            TaskRefusal::Unreached(why) => write!(f, "task not reached: {why}"),
        }
    }
}

/// Signs each task the kernel authorizes. `current_leaf` is the SHA-256 of the
/// current signing leaf's DER.
pub trait TaskSigner: Send + Sync {
    fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal>;
    fn sign_addendum(
        &self,
        addendum: maknae_proto::TaskAddendum,
    ) -> Result<maknae_proto::SignedAddendum, TaskRefusal>;
    fn current_leaf(&self) -> Option<[u8; 32]>;
}

/// Signs with the kernel's current `plane/kernel` leaf.
pub struct PlaneSigner(pub Arc<maknae_vault::PlaneClient>);

impl TaskSigner for PlaneSigner {
    fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal> {
        signed_by(self.0.current_identity().as_ref(), task)
    }
    fn sign_addendum(
        &self,
        addendum: maknae_proto::TaskAddendum,
    ) -> Result<maknae_proto::SignedAddendum, TaskRefusal> {
        let identity = self.0.current_identity();
        let identity = identity.as_ref().ok_or(TaskRefusal::Unsigned)?;
        maknae_vault::task_sig::sign_addendum(identity, addendum).map_err(|_| TaskRefusal::Unsigned)
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
            signature: unverified(),
        })
    }
    fn sign_addendum(
        &self,
        addendum: maknae_proto::TaskAddendum,
    ) -> Result<maknae_proto::SignedAddendum, TaskRefusal> {
        Ok(maknae_proto::SignedAddendum {
            addendum,
            signature: unverified(),
        })
    }
    fn current_leaf(&self) -> Option<[u8; 32]> {
        None
    }
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
fn unverified() -> maknae_proto::TaskSignature {
    maknae_proto::TaskSignature {
        alg: "unverified".into(),
        leaf: maknae_proto::Bytes::new(vec![0].into()),
        chain: Vec::new(),
        sig: maknae_proto::Bytes::new(vec![0].into()),
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
    starts: u64,
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
    fn holds_working(&self, agent: &str, uid: u32) -> bool {
        self.tasks.values().any(|r| {
            !r.pending
                && r.state == TaskState::Working
                && r.agent.as_str() == agent
                && r.agent_uid == uid
        })
    }

    fn start(&mut self, id: TaskId, lease: i64) {
        self.starts += 1;
        let hot = self.hot.entry(id).or_default();
        (hot.lease_until, hot.cited, hot.start) = (lease, false, self.starts);
    }

    fn generation(&self, agent: &AgentId) -> u64 {
        self.generations.get(agent).copied().unwrap_or(0)
    }

    fn live(&self, id: &TaskId) -> Option<&TaskRecord> {
        self.tasks.get(id).filter(|r| !r.pending)
    }

    /// Whether a collect returns the record's report or close: neither held nor due a hold.
    fn collectable(&self, r: &TaskRecord) -> bool {
        r.rseq.is_some()
            && r.report.is_some()
            && r.state != TaskState::Held
            && !self.holding.contains_key(&r.signed.task.task_id)
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
    /// close owed and its parent, if any, still working.
    fn held_by(&self, id: &TaskId, agent: &AgentId, uid: u32) -> Option<&TaskRecord> {
        self.live(id).filter(|r| {
            r.agent == *agent
                && r.agent_uid == uid
                && !self.closing.contains_key(id)
                && !self.holding.contains_key(id)
                && !self.parent_ended(r)
        })
    }

    /// Whether `r` was given under a task that is gone, neither working, held nor due a
    /// hold, or started again since: no tasker can reach it any more.
    fn parent_ended(&self, r: &TaskRecord) -> bool {
        r.parent.is_some_and(|p| {
            !self.holding.contains_key(&p)
                && !self.live(&p).is_some_and(|p| {
                    matches!(p.state, TaskState::Working | TaskState::Held)
                        && r.parent_start.is_none_or(|s| s == p.starts)
                })
        })
    }

    /// An agent waits on every agent its working or pending tasks have a sub-task at.
    fn would_wait(&self, by: &str, target: &AgentId) -> bool {
        let waiting = |id: &TaskId, r: &TaskRecord| {
            (r.pending || open(r))
                && self.closing.get(id) != Some(&TaskClose::Withdrawn)
                && !self.parent_ended(r)
        };
        let mut agents = vec![target];
        let mut visited = BTreeSet::new();
        while let Some(agent) = agents.pop() {
            if agent.as_str() == by {
                return true;
            }
            if !visited.insert(agent) {
                continue;
            }
            let busy: BTreeSet<&TaskId> = self
                .tasks
                .iter()
                .filter(|(_, r)| r.agent == *agent && (r.pending || r.state == TaskState::Working))
                .map(|(id, _)| id)
                .collect();
            for (id, r) in &self.tasks {
                if r.parent.is_some_and(|p| busy.contains(&p)) && waiting(id, r) {
                    agents.push(&r.agent);
                }
            }
        }
        false
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

    fn held_page(
        &self,
        view: &dyn EnrollmentView,
        select: HeldSelect<'_>,
        after: Option<u64>,
        limit: usize,
    ) -> (Vec<&TaskRecord>, Option<u64>) {
        debug_assert!(limit > 0);
        let mut page: Vec<&TaskRecord> = self
            .tasks
            .values()
            .filter(|r| !r.pending && r.state == TaskState::Held)
            .filter(|r| after.is_none_or(|a| r.seq > a))
            .filter(|r| selected(view, r, select))
            .collect();
        page.sort_by_key(|r| r.seq);
        let more = page.len() > limit;
        page.truncate(limit);
        let next = more.then(|| page.last().map(|r| r.seq)).flatten();
        (page, next)
    }

    fn releasable(
        &self,
        id: &TaskId,
        view: &dyn EnrollmentView,
    ) -> Result<(TaskRecord, TaskState, TaskState), ReleaseRefusal> {
        let rec = self.live(id).ok_or(ReleaseRefusal::Unknown)?;
        if rec.state != TaskState::Held {
            return Err(ReleaseRefusal::NotHeld);
        }
        let from = rec
            .held_from
            .filter(|s| *s != TaskState::Held)
            .ok_or_else(|| {
                ReleaseRefusal::NotDone(
                    "the record does not name the state it was held from".into(),
                )
            })?;
        let parent_held = |p: &TaskId| {
            self.holding.contains_key(p) || self.live(p).is_some_and(|r| r.state == TaskState::Held)
        };
        if let Some(parent) = rec.parent.filter(parent_held) {
            return Err(ReleaseRefusal::ParentHeld(parent));
        }
        let to = release_state(from);
        let mut after = rec.clone();
        after.state = to;
        if let Some(who) = contained_in(view, &after) {
            return Err(ReleaseRefusal::StillContained(who));
        }
        if let Some(refusal) = unresolved(view, &after) {
            return Err(refusal);
        }
        Ok((rec.clone(), from, to))
    }

    fn take_back(&mut self, id: &TaskId) {
        self.hot.remove(id);
        if let Some(rec) = self.tasks.remove(id).filter(|r| !r.pending) {
            self.expose(rec);
        }
    }
}

/// A tasker's tasks with one agent: `open` those queued, working or held, `waiting` its
/// reports and close notices a collect would return.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Holding {
    pub records: usize,
    pub open: usize,
    pub waiting: u32,
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
                Err(TaskRefusal::Unavailable(format!("{OUTCOME_UNKNOWN}{why}")))
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
                _ if held.parent_ended(r) => match open(r) {
                    true => Some(DueFor::Close(TaskClose::ParentEnded)),
                    false => Some(DueFor::Orphaned),
                },
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
                        DueFor::Expiry | DueFor::Orphaned => false,
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
                    (DueFor::Close(_) | DueFor::Expiry | DueFor::Orphaned, _) if holding => false,
                    (DueFor::Close(TaskClose::ParentEnded), _) => {
                        rec.is_some_and(|r| open(r) && held.parent_ended(r))
                    }
                    (DueFor::Orphaned, _) => rec.is_some_and(|r| {
                        !open(r) && r.state != TaskState::Held && held.parent_ended(r)
                    }),
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
                    (true, DueFor::Close(TaskClose::ParentEnded)) => {}
                    (true, DueFor::Close(close)) => {
                        held.closing.insert(d.task, close);
                        held.recorded.insert(d.task, close);
                    }
                    (true, DueFor::Hold(_)) => {
                        held.hold_said.insert(d.task);
                    }
                    (true, DueFor::Expiry | DueFor::Orphaned) | (false, _) => {}
                }
                still
            };
            match (still, d.why, disk) {
                (false, _, _) => {}
                (true, DueFor::Close(TaskClose::ParentEnded) | DueFor::Orphaned, on_disk) => {
                    let mut held = self.held();
                    if held.take_back_unless_held(&d.task) {
                        held.unmark(&d.task);
                        drop(held);
                        done += 1;
                        if on_disk {
                            disk = self.withdraw_locked(&d.task);
                        }
                    }
                }
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
            next.report = Some((SecretText::new(String::new()), self.clock.now_secs()));
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
        let (prior, hot, cause) = {
            let held = self.held();
            let Some(prior) = held.live(id).cloned() else {
                return true;
            };
            let hot = held.hot.get(id).copied().unwrap_or_default();
            (prior, hot, held.holding.get(id).copied())
        };
        let mut next = prior.clone();
        next.held_from = Some(prior.state);
        next.held_for = cause;
        next.held_at = Some(self.clock.now_secs());
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

    /// The held tasks `select` picks, after the store-wide `seq` `after`, at most `limit`;
    /// the second value is the cursor of the last one when more remain.
    pub fn held_tasks(
        &self,
        view: &dyn EnrollmentView,
        select: HeldSelect<'_>,
        after: Option<u64>,
        limit: usize,
    ) -> (Vec<HeldTask>, Option<u64>) {
        let held = self.held();
        let (page, next) = held.held_page(view, select, after, limit);
        let tasks = page
            .into_iter()
            .map(|r| HeldTask {
                seq: r.seq,
                view: self.view_of(&held, r),
                tasker: r.tasker.clone(),
                held_from: r.held_from.unwrap_or(TaskState::Held),
                held_for: r.held_for,
                held_at: r.held_at,
            })
            .collect();
        (tasks, next)
    }

    /// [`TaskStore::held_tasks`], as ids.
    pub fn held_seqs(
        &self,
        view: &dyn EnrollmentView,
        select: HeldSelect<'_>,
        after: Option<u64>,
        limit: usize,
    ) -> (Vec<(u64, TaskId)>, Option<u64>) {
        let held = self.held();
        let (page, next) = held.held_page(view, select, after, limit);
        let ids = page
            .into_iter()
            .map(|r| (r.seq, r.signed.task.task_id))
            .collect();
        (ids, next)
    }

    /// What [`TaskStore::release`] would do now; no I/O.
    pub fn release_plan(
        &self,
        id: &TaskId,
        view: &dyn EnrollmentView,
    ) -> Result<ReleasePlan, ReleaseRefusal> {
        let (rec, from, to) = self.held().releasable(id, view)?;
        Ok(ReleasePlan {
            task: *id,
            agent: rec.agent,
            tasker: rec.tasker,
            parent: rec.parent,
            from,
            to,
        })
    }

    /// Writes the held task `id` in the state it was held from, a working task queued
    /// again and a report under a new report ordinal; memory follows only a synced write.
    /// Every check of [`TaskStore::release_plan`] is made again under the writer, and a
    /// containment installed meanwhile marks the task due a hold again.
    pub fn release(
        &self,
        id: &TaskId,
        view: &dyn EnrollmentView,
    ) -> Result<Released, ReleaseRefusal> {
        let _w = self.writing();
        let (prior, from, to) = self.held().releasable(id, view)?;
        let mut next = prior.clone();
        next.state = to;
        (next.held_from, next.held_for, next.held_at) = (None, None, None);
        if from == TaskState::Working {
            next.claimed = None;
        }
        if prior.rseq.is_some() {
            next.rseq = Some(self.issue_report(&prior.tasker).map_err(unreleased)?);
            let now = self.clock.now_secs();
            if let Some((_, at)) = next.report.as_mut() {
                *at = now;
            }
        }
        self.write(&next, Some(&prior)).map_err(unreleased)?;
        {
            let mut held = self.held();
            if let Some(hot) = held.hot.get_mut(id).filter(|_| from == TaskState::Working) {
                (hot.lease_until, hot.retry_after, hot.retry_secs) = (0, 0, 0);
            }
            held.tasks.insert(*id, next.clone());
        }
        self.mark_unenrolled(view);
        Ok(Released {
            task: *id,
            from,
            now: to,
            rseq: next.rseq,
        })
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
            next.unseen &= !hot.cited;
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
        bindings: Vec<Binding>,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let under = parent.map(|p| (p, run_of(&self.held(), &p)));
        self.mint_with(
            &mut draw_id,
            signer,
            view,
            enrolled,
            tasker,
            under,
            sub,
            (bindings, Vec::new()),
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
        under: Option<(TaskId, u64)>,
        sub: TaskSubmission,
        (bindings, reach): (Vec<Binding>, Vec<maknae_proto::BindingReach>),
        ticket: Option<&Ticket>,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let agent = target(&sub)?;
        let mut task = TaskObject {
            schema: maknae_proto::TASK_SCHEMA.into(),
            version: maknae_proto::TASK_VERSION,
            task_id: TaskId(draw()?),
            tasker,
            parent: under.map(|(p, _)| p),
            agent: sub.agent,
            ask: sub.ask,
            labels: sub.labels,
            bindings,
            reach,
        };
        for attempt in 1..=ID_DRAWS {
            let signed = Arc::new(signer.sign(task)?);
            match self.place(view, &agent, enrolled, &signed, under, ticket)? {
                Placed::Stored => return Ok(signed),
                Placed::Collided if attempt < ID_DRAWS => {
                    task = signed.task.clone();
                    task.task_id = TaskId(draw()?);
                }
                Placed::Collided => break,
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
        under: Option<(TaskId, u64)>,
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
            if let Tasker::Agent { agent: by, .. } = &task.task.tasker {
                if held.would_wait(by, agent) {
                    return Err(TaskRefusal::Denied(format!(
                        "task chain already waits on agent {}",
                        agent.as_str()
                    )));
                }
            }
            own_initiative(&held, &task.task.tasker, task.task.parent)?;
            let root = root_of(&held, &task.task.tasker, under)?;
            let parent_start = task
                .task
                .parent
                .and_then(|p| held.live(&p))
                .map(|p| p.starts);
            (root, parent_start)
        };
        let (root, parent_start) = root;
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
            held_at: None,
            held_for: None,
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
            unseen: false,
            starts: 0,
            parent_start,
            addendum: None,
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
    /// re-signs it, and its addendum, outside the store lock when either's signing leaf is not
    /// the signer's current one. A task replaced meanwhile is handed out only under the current leaf, after at most
    /// one more signature; otherwise, or without a current leaf or a signature, nothing is.
    pub fn resign_if_stale(
        &self,
        id: &TaskId,
        agent: &AgentId,
        uid: u32,
        signer: &dyn TaskSigner,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let signed_under = |leaf: &maknae_proto::Bytes, current: [u8; 32]| {
            maknae_vault::task_sig::leaf_fingerprint(&leaf.0) == current
        };
        let (mut held, mut added) = handable_with_addendum(&self.held(), id, agent, uid)?;
        for _ in 0..2 {
            let current = signer.current_leaf().ok_or(TaskRefusal::Unsigned)?;
            let task_stale = !signed_under(&held.signature.leaf, current);
            let added_stale = added
                .as_ref()
                .is_some_and(|a| !signed_under(&a.signature.leaf, current));
            if !task_stale && !added_stale {
                return Ok(held);
            }
            let fresh = match task_stale {
                true => Arc::new(signer.sign(held.task.clone())?),
                false => Arc::clone(&held),
            };
            let fresh_added = match &added {
                Some(a) if added_stale => Some(Arc::new(signer.sign_addendum(a.addendum.clone())?)),
                kept => kept.clone(),
            };
            let _w = self.writing();
            let prior = {
                let store = self.held();
                let (now, now_added) = handable_with_addendum(&store, id, agent, uid)?;
                let same_added = match (&now_added, &added) {
                    (Some(n), Some(a)) => Arc::ptr_eq(n, a),
                    (None, None) => true,
                    (Some(_), None) | (None, Some(_)) => false,
                };
                if !Arc::ptr_eq(&now, &held) || !same_added {
                    (held, added) = (now, now_added);
                    continue;
                }
                store.tasks.get(id).cloned()
            };
            if let Some(prior) = prior {
                let mut next = prior.clone();
                next.signed = fresh.clone();
                next.addendum = fresh_added;
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
        let rec = self.publish(id, text, close, |_, _| Ok(()))?;
        Ok(rec.rseq.unwrap_or_default())
    }

    /// The caller holds the writer.
    fn publish(
        &self,
        id: &TaskId,
        text: SecretText,
        close: Option<TaskClose>,
        check: impl FnOnce(&Held, &TaskRecord) -> Result<(), TaskRefusal>,
    ) -> Result<TaskRecord, TaskRefusal> {
        let prior = {
            let held = self.held();
            let rec = held.live(id).ok_or(TaskRefusal::Unknown)?;
            check(&held, rec)?;
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
        self.held().holds_working(agent.as_str(), uid)
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
        let delivered = |rec: &TaskRecord, fresh: bool| Claimed::Delivered {
            fresh,
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
                let cited = held.hot.get(&id).is_some_and(|h| h.cited);
                let handed = delivered(rec, rec.unseen && !cited);
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
                next.unseen = true;
                next.starts = prior.starts + 1;
                self.write(&next, Some(&prior))?;
                let handed = delivered(&next, true);
                let mut held = self.held();
                held.start(id, lease);
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
                let addendum = r
                    .addendum
                    .as_ref()
                    .filter(|a| a.addendum.seq() > seen)
                    .cloned();
                let budget = budget.saturating_sub(addendum.as_deref().map_or(0, |a| {
                    maknae_proto::bindings_encoded_len(std::slice::from_ref(a))
                }));
                let mut used = 0usize;
                let items: Vec<SecretText> = r
                    .follow_ups
                    .iter()
                    .skip(seen as usize)
                    .take_while(|f| {
                        let first = used == 0;
                        used = used.saturating_add(f.expose().len().max(1));
                        first || used <= budget
                    })
                    .cloned()
                    .collect();
                (*id, r.tasker.clone(), items, addendum)
            });
        if let Some((task, tasker, items, addendum)) = working {
            held.hot.entry(task).or_default().lease_until = now + CLAIM_LEASE.as_secs() as i64;
            return Heartbeat::FollowUps {
                task,
                tasker,
                from: seen,
                items,
                addendum,
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
        seen: Option<u32>,
    ) -> Result<TaskView, TaskRefusal> {
        let _w = self.writing();
        let held = self.held();
        if held.closing.contains_key(id) || held.holding.contains_key(id) {
            return Err(TaskRefusal::AgentGone);
        }
        drop(held);
        let next = self.publish(id, text, None, |_, rec| {
            match (rec.agent == *agent && rec.agent_uid == uid, rec.state) {
                (false, _) => Err(TaskRefusal::OtherAgent),
                (true, TaskState::Working)
                    if seen.is_some_and(|n| rec.follow_ups.len() > n as usize) =>
                {
                    Err(TaskRefusal::FollowUpsUnseen)
                }
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
    /// It marks the start seen only when it was resolved against that start.
    pub fn acted(&self, id: &TaskId, start: u64) {
        let now = self.clock.now_secs();
        let mut held = self.held();
        if held.live(id).is_some_and(|r| r.state == TaskState::Working) {
            let hot = held.hot.entry(*id).or_default();
            hot.actions = hot.actions.saturating_add(1);
            hot.last_action = Some(now);
            hot.cited |= hot.start == start;
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

    /// Removes the reports from `agent` that `by` reaches, up to its report ordinal `upto`.
    /// A person's cursor above every ordinal it was issued is refused; an agent's ordinals
    /// span every root it works for, so its cursor is never refused. Answered done only
    /// when no such report is still owed its removal, from this call or an earlier one.
    pub fn acknowledge<'a>(
        &self,
        by: impl Into<Reach<'a>>,
        agent: &AgentId,
        upto: u64,
    ) -> Result<usize, TaskRefusal> {
        self.acknowledged(by, agent, upto).map(|gone| gone.len())
    }

    /// [`TaskStore::acknowledge`], naming the tasks whose reports it removed.
    pub fn acknowledged<'a>(
        &self,
        by: impl Into<Reach<'a>>,
        agent: &AgentId,
        upto: u64,
    ) -> Result<Vec<TaskId>, TaskRefusal> {
        let by = by.into();
        let _w = self.writing();
        let spans_roots = matches!(by.tasker, Tasker::Agent { .. });
        if !spans_roots && upto > self.held().issued.of(by.tasker).rseq {
            return Err(TaskRefusal::CursorAhead);
        }
        let acked = |held: &Held, r: &TaskRecord| {
            by.reaches(held, r) && r.agent == *agent && r.rseq.is_some_and(|s| s <= upto)
        };
        let gone: Vec<TaskId> = {
            let held = self.held();
            held.tasks
                .iter()
                .filter(|(_, r)| !r.pending && acked(&held, r))
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
        let owed = {
            let held = self.held();
            held.exposed.values().any(|r| acked(&held, r))
        };
        match owed {
            false => Ok(gone),
            true => Err(TaskRefusal::Unavailable(format!(
                "{OUTCOME_UNKNOWN}the acknowledgement is left to a later store write"
            ))),
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
    /// hold is refused until the caller has recorded the hold and passes `Confirm::Held`
    /// with the cause that record named; it is then stored held, never queued. The `ticket` is
    /// kept before anything is written: a submission that gave up first leaves the record
    /// pending, and one that gives up later can only call the outcome unknown. A write
    /// that fails once kept is taken back.
    pub(crate) fn confirm(
        &self,
        id: &TaskId,
        ticket: Option<&Ticket>,
        how: Confirm,
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
            if how == Confirm::Queued && held.holding.contains_key(id) {
                return Err(TaskRefusal::Unavailable(DUE_A_HOLD.into()));
            }
            if ticket.is_some_and(|t| !t.keep(*id)) {
                return Err(abandoned());
            }
            held.expose(prior.clone());
            prior
        };
        next.pending = false;
        if let Confirm::Held(cause) = how {
            next.held_from = Some(next.state);
            next.held_for = cause;
            next.held_at = Some(self.clock.now_secs());
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
        match held.live(id).map(|r| (r.state, r)) {
            Some((TaskState::Working, rec)) => Ok(CitedTask {
                signed,
                root: rec.root.clone(),
                start: run_of(&held, id),
                addendum: rec.addendum.clone(),
            }),
            Some((
                TaskState::Queued | TaskState::Reported | TaskState::Closed | TaskState::Held,
                _,
            ))
            | None => Err(TaskRefusal::NotWorking),
        }
    }

    /// The task's state when `by` reaches it; any other task, foreign or unknown, reads
    /// as `None`.
    pub fn state_for<'a>(&self, id: &TaskId, by: impl Into<Reach<'a>>) -> Option<TaskState> {
        tasker_record(&self.held(), id, by.into()).map(|r| r.state)
    }

    /// The task, when `by` reaches it, as a view.
    pub fn status<'a>(&self, id: &TaskId, by: impl Into<Reach<'a>>) -> Option<TaskView> {
        let held = self.held();
        let rec = tasker_record(&held, id, by.into())?;
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

    /// Appends `text` to a working task `by` reaches, within the count and the byte total.
    pub fn follow_up<'a>(
        &self,
        id: &TaskId,
        by: impl Into<Reach<'a>>,
        text: SecretText,
        total_max: usize,
    ) -> Result<TaskView, TaskRefusal> {
        let by = by.into();
        let _w = self.writing();
        let prior = {
            let held = self.held();
            let rec = tasker_record(&held, id, by).ok_or(TaskRefusal::Unknown)?;
            if rec.state != TaskState::Working || held.holding.contains_key(id) {
                return Err(TaskRefusal::NotWorking);
            }
            room_for(&rec.follow_ups, &text, total_max)?;
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

    pub fn addendum_basis<'a>(
        &self,
        view: &dyn EnrollmentView,
        id: &TaskId,
        by: impl Into<Reach<'a>>,
    ) -> Result<TaskRecord, TaskRefusal> {
        let held = self.held();
        let rec = tasker_record(&held, id, by.into()).ok_or(TaskRefusal::Unknown)?;
        if rec.state != TaskState::Working || held.holding.contains_key(id) {
            return Err(TaskRefusal::NotWorking);
        }
        if let Some(parent) = rec.parent {
            working_parent(&held, &parent)?;
        }
        own_initiative(&held, &rec.tasker, rec.parent)?;
        if contained_in(view, rec).is_some() {
            return Err(TaskRefusal::Denied(CONTAINED.into()));
        }
        Ok(rec.clone())
    }

    /// The next cumulative addendum is numbered by `text`, appended as a follow-up; the
    /// task's own signed object is untouched.
    #[allow(clippy::too_many_arguments)]
    pub fn add_bindings<'a>(
        &self,
        view: &dyn EnrollmentView,
        id: &TaskId,
        by: impl Into<Reach<'a>>,
        text: SecretText,
        (added, reach): (Vec<Binding>, Vec<maknae_proto::BindingReach>),
        signer: &dyn TaskSigner,
        total_max: usize,
    ) -> Result<TaskView, TaskRefusal> {
        let _w = self.writing();
        let prior = self.addendum_basis(view, id, by)?;
        room_for(&prior.follow_ups, &text, total_max)?;
        let bound = prior.bound();
        addable(&bound, &added)?;
        let (mut bindings, mut so_far) = match &prior.addendum {
            Some(a) => (a.addendum.bindings().to_vec(), a.addendum.reach().to_vec()),
            None => (Vec::new(), Vec::new()),
        };
        bindings.extend(added);
        so_far.extend(reach);
        let own = crate::reach::TaskBound::of(&prior.signed.task, None);
        let all: Vec<&Binding> = own.bindings.iter().copied().chain(&bindings).collect();
        let all_reach: Vec<&maknae_proto::BindingReach> =
            own.reach.iter().copied().chain(&so_far).collect();
        within_bounds(&all, &all_reach)?;
        let seq = u32::try_from(prior.follow_ups.len() + 1).map_err(|_| TaskRefusal::FollowUps)?;
        let addendum = maknae_proto::TaskAddendum::new(*id, seq, bindings, so_far)
            .map_err(TaskRefusal::Unbound)?;
        let signed = signer.sign_addendum(addendum)?;
        let mut next = prior.clone();
        next.follow_ups.push(text);
        next.addendum = Some(Arc::new(signed));
        self.write(&next, Some(&prior))?;
        let mut held = self.held();
        let view = self.view_of(&held, &next);
        held.tasks.insert(*id, next);
        Ok(view)
    }

    /// Closes a working task `by` reaches as `Stopped`; the notice is collected like a report.
    pub fn stop<'a>(&self, id: &TaskId, by: impl Into<Reach<'a>>) -> Result<TaskView, TaskRefusal> {
        let by = by.into();
        let _w = self.writing();
        let next = self.publish(
            id,
            SecretText::new(String::new()),
            Some(TaskClose::Stopped),
            |held, rec| match (by.reaches(held, rec), rec.state) {
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

    /// Withdraws a queued task `by` reaches. Answered once the record is durably pending or
    /// gone; otherwise the task leaves memory and the outcome is unknown.
    pub fn drop_queued<'a>(
        &self,
        id: &TaskId,
        by: impl Into<Reach<'a>>,
    ) -> Result<TaskView, TaskRefusal> {
        let by = by.into();
        let _w = self.writing();
        let mut view = {
            let held = self.held();
            if held.exposed.get(id).is_some_and(|r| by.reaches(&held, r)) {
                return Err(drop_owed());
            }
            let rec = tasker_record(&held, id, by).ok_or(TaskRefusal::Unknown)?;
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

    /// The tasks `by` reaches with `agent` after the tasker's submission ordinal `after`,
    /// oldest first, at most `limit`, and the ordinal to resume after when more remain.
    pub fn list<'a>(
        &self,
        by: impl Into<Reach<'a>>,
        agent: &AgentId,
        after: Option<u64>,
        limit: usize,
    ) -> (Vec<TaskView>, Option<u64>) {
        let by = by.into();
        let held = self.held();
        let mut mine: Vec<&TaskRecord> = held
            .tasks
            .values()
            .filter(|r| {
                !r.pending
                    && by.reaches(&held, r)
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

    /// The reports and close notices from `agent` that `by` reaches, in arrival order, as
    /// one page built under the lock; only the entries that fit are copied.
    pub fn reports<'a>(
        &self,
        by: impl Into<Reach<'a>>,
        agent: &AgentId,
        budget: usize,
    ) -> TaskReportPage {
        let by = by.into();
        let held = self.held();
        let mut mine: Vec<&TaskRecord> = held
            .tasks
            .values()
            .filter(|r| !r.pending && by.reaches(&held, r) && r.agent == *agent)
            .filter(|r| held.collectable(r))
            .collect();
        mine.sort_by_key(|r| r.rseq);
        crate::task_verbs::report_page(mine.into_iter(), budget)
    }

    /// What `tasker` holds with each agent; `waiting` is every report and close notice
    /// [`TaskStore::reports`] would return, across all its pages.
    pub fn holdings(&self, tasker: &Tasker) -> BTreeMap<AgentId, Holding> {
        let held = self.held();
        let mut by_agent: BTreeMap<AgentId, Holding> = BTreeMap::new();
        for r in held
            .tasks
            .values()
            .filter(|r| !r.pending && r.tasker == *tasker)
        {
            let h = by_agent.entry(r.agent.clone()).or_default();
            h.records += 1;
            if matches!(
                r.state,
                TaskState::Queued | TaskState::Working | TaskState::Held
            ) {
                h.open += 1;
            }
            if held.collectable(r) {
                h.waiting = h.waiting.saturating_add(1);
            }
        }
        by_agent
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
        let (inherited, parent_start) = signed
            .task
            .parent
            .and_then(|p| self.held().live(&p).map(|r| (r.root.clone(), r.starts)))
            .unzip();
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
            held_at: None,
            held_for: None,
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
            unseen: false,
            starts: 0,
            parent_start,
            addendum: None,
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
        next.unseen = true;
        next.starts = prior.starts + 1;
        self.write(&next, Some(&prior))
            .expect("the test store writes the task");
        let lease = self.clock.now_secs() + CLAIM_LEASE.as_secs() as i64;
        let mut held = self.held();
        held.start(*id, lease);
        held.tasks.insert(*id, next);
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn act_for_test(&self, id: &TaskId, at: i64) {
        let mut held = self.held();
        let hot = held.hot.entry(*id).or_default();
        hot.actions += 1;
        hot.last_action = Some(at);
        hot.cited = true;
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
        bindings: Vec<Binding>,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let t = self.mint(signer, view, enrolled, tasker, parent, sub, bindings)?;
        self.confirm(&t.task.task_id, None, Confirm::Queued)?;
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
        bindings: Vec<Binding>,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let under = parent.map(|p| (p, run_of(&self.held(), &p)));
        let t = self.mint_with(
            draw,
            signer,
            view,
            enrolled,
            tasker,
            under,
            sub,
            (bindings, Vec::new()),
            None,
        )?;
        self.confirm(&t.task.task_id, None, Confirm::Queued)?;
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
    TaskRefusal::Unavailable(format!(
        "{OUTCOME_UNKNOWN}the drop is left to a later store write"
    ))
}

fn abandoned() -> TaskRefusal {
    TaskRefusal::Unavailable("not done: the submission was abandoned".into())
}

pub(crate) fn draw_id() -> Result<[u8; 16], TaskRefusal> {
    let mut id = [0u8; 16];
    maknae_crypto::random::fill(&mut id[..]).map_err(|_| TaskRefusal::Random)?;
    Ok(id)
}

fn store(e: StoreError) -> TaskRefusal {
    TaskRefusal::Store(e.to_string())
}

fn room_for(prior: &[SecretText], text: &SecretText, total_max: usize) -> Result<(), TaskRefusal> {
    let total = prior.iter().map(|f| f.expose().len()).sum::<usize>();
    match prior.len() >= MAX_FOLLOW_UPS_PER_TASK
        || total.saturating_add(text.expose().len()) > total_max
    {
        true => Err(TaskRefusal::FollowUps),
        false => Ok(()),
    }
}

fn tasker_record<'h>(held: &'h Held, id: &TaskId, by: Reach<'_>) -> Option<&'h TaskRecord> {
    held.live(id).filter(|r| by.reaches(held, r))
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

/// The tasks one tasker request reaches: those `tasker` gave under the task the request
/// cites, or with no parent when it cites none, and only `task` when the request names one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reach<'a> {
    pub tasker: &'a Tasker,
    pub under: Option<TaskId>,
    pub task: Option<TaskId>,
}

impl<'a> From<&'a Tasker> for Reach<'a> {
    fn from(tasker: &'a Tasker) -> Self {
        Reach {
            tasker,
            under: None,
            task: None,
        }
    }
}

impl Reach<'_> {
    fn reaches(&self, held: &Held, r: &TaskRecord) -> bool {
        !held.parent_ended(r)
            && r.tasker == *self.tasker
            && r.parent == self.under
            && self.task.is_none_or(|t| t == r.signed.task.task_id)
    }
}

/// A citable task: the agent's own `Working` task and the stored root of its chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CitedTask {
    pub signed: Arc<SignedTask>,
    pub root: RootTasker,
    pub start: u64,
    pub addendum: Option<Arc<maknae_proto::SignedAddendum>>,
}

impl CitedTask {
    pub(crate) fn bound(&self) -> crate::reach::TaskBound<'_> {
        crate::reach::TaskBound::of(&self.signed.task, self.addendum.as_deref())
    }
}

/// A sub-task works in its parent's partition, and is taken only while that parent is
/// working and due neither a hold nor a close; a person's own task works in the uid's.
fn root_of(
    held: &Held,
    tasker: &Tasker,
    under: Option<(TaskId, u64)>,
) -> Result<RootTasker, TaskRefusal> {
    if let Some((parent, run)) = under {
        let p = working_parent(held, &parent)?;
        if run_of(held, &parent) != run {
            return Err(TaskRefusal::ParentNotHeld);
        }
        return Ok(p.root.clone());
    }
    match tasker {
        Tasker::Uid(uid) => Ok(RootTasker::Person { uid: *uid }),
        Tasker::Agent { agent, .. } => Ok(RootTasker::Agent {
            agent: agent.clone(),
        }),
        Tasker::Remote(_) => Err(TaskRefusal::Schema("a remote tasker is not taken".into())),
    }
}

fn run_of(held: &Held, id: &TaskId) -> u64 {
    held.hot.get(id).map_or(0, |h| h.start)
}

fn working_parent<'h>(held: &'h Held, parent: &TaskId) -> Result<&'h TaskRecord, TaskRefusal> {
    held.live(parent)
        .filter(|p| {
            p.state == TaskState::Working
                && !held.holding.contains_key(parent)
                && !held.closing.contains_key(parent)
        })
        .ok_or(TaskRefusal::ParentNotHeld)
}

/// An agent's own-initiative task is not taken while that agent holds a working task.
fn own_initiative(held: &Held, tasker: &Tasker, parent: Option<TaskId>) -> Result<(), TaskRefusal> {
    if let (Tasker::Agent { agent, uid }, None) = (tasker, parent) {
        if held.holds_working(agent, *uid) {
            return Err(TaskRefusal::Denied(OWN_HELD.into()));
        }
    }
    Ok(())
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
    if held.closing.contains_key(id) || held.holding.contains_key(id) || held.parent_ended(stored) {
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

type HandedWithAddendum = (Arc<SignedTask>, Option<Arc<maknae_proto::SignedAddendum>>);

fn handable_with_addendum(
    held: &Held,
    id: &TaskId,
    agent: &AgentId,
    uid: u32,
) -> Result<HandedWithAddendum, TaskRefusal> {
    let task = handable(held, id, agent, uid)?;
    let added = held.live(id).and_then(|r| r.addendum.clone());
    Ok((task, added))
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
                prompt: maknae_proto::SecretText::new(String::new()),
            },
            labels: maknae_proto::Labels {},
            bindings: Vec::new(),
            reach: Vec::new(),
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
    let verb = maknae_proto::Verb::TaskSubmit {
        task: sub.clone(),
        forge_tokens: maknae_proto::ForgeTokens::default(),
    };
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
    pub forges: &'a maknae_config::ForgeSet,
    pub reach: crate::reach::ReachCtx<'a>,
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
        let mut rec = crate::run::decision_record(rec, self.role, None);
        rec.subject.agent = self.agent.as_ref().map(|a| a.as_str().to_string());
        rec.subject.task_id = task.map(|t| t.task_id.to_string());
        rec.subject.bindings =
            task.map_or_else(Vec::new, |t| crate::run::record_bindings(&t.bindings));
        rec.subject.reach = task.map_or_else(Vec::new, |t| crate::run::record_reach(&t.reach));
        rec.subject.parent_task_id = self.parent.map(|p| p.to_string());
        rec.subject.tasker = Some(maknae_proto::tasker_text(&self.tasker));
        rec.subject.task_op = Some("submit".into());
        rec
    }
}

impl Attempt {
    /// A reach frame's intent or outcome, on the submission's own connection and target.
    fn frame_record(
        &self,
        ctx: &SubmitCtx<'_>,
        (result, reason, posture): (&str, &str, &str),
    ) -> maknae_audit_append::AuditRecord {
        let mut rec = self.record(ctx, None, None);
        rec.outcome.result = result.into();
        rec.outcome.reason = reason.into();
        rec.outcome.posture = posture.into();
        rec
    }
}

/// Runs one store step off the async worker, under the submitting uid's slot, the shared
/// capacity and `deadline`.
fn store_deadline(decide_timeout: std::time::Duration) -> tokio::time::Instant {
    tokio::time::Instant::now() + decide_timeout * 2
}

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
        Err(crate::mutation::Blocked::NotStarted) => {
            Err(TaskRefusal::Unavailable(format!("not done: {BUSY}")))
        }
        Err(crate::mutation::Blocked::Unknown) => {
            Err(TaskRefusal::Unavailable(format!("{OUTCOME_UNKNOWN}{LATE}")))
        }
    }
}

pub(crate) const OUTCOME_UNKNOWN: &str = "outcome unknown: ";
pub(crate) const LATE: &str = "the task store did not answer in time";
pub(crate) const BUSY: &str = "the task store was busy";

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
    let late = format!("{OUTCOME_UNKNOWN}{LATE}");
    match (kept, refusal) {
        (true, TaskRefusal::Unavailable(why)) if why.starts_with(OUTCOME_UNKNOWN) => {
            (TaskRefusal::Unavailable(why.clone()), why)
        }
        (true, other) => {
            let said = format!("{OUTCOME_UNKNOWN}{other}");
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
    (sub, tokens): (TaskSubmission, maknae_proto::ForgeTokens),
    emit: &impl AuditEmit,
) -> Result<Arc<SignedTask>, TaskRefusal> {
    submit_under(
        decider(authorizer),
        store,
        signer,
        view,
        ctx,
        by,
        (sub, tokens),
        emit,
    )
    .await
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

/// The decision and the steps before reach share two decision bounds; the store's steps
/// after reach get two more (`maknae_config::TASK_REACH_REPLY_STAGES`).
#[allow(clippy::too_many_arguments)]
async fn submit_under<P: Authorizer + Send + Sync + 'static>(
    pdp: Decider<P>,
    store: &Arc<TaskStore>,
    signer: &Arc<dyn TaskSigner>,
    view: &Arc<dyn EnrollmentView>,
    ctx: &SubmitCtx<'_>,
    by: Submitter,
    (sub, tokens): (TaskSubmission, maknae_proto::ForgeTokens),
    emit: &impl AuditEmit,
) -> Result<Arc<SignedTask>, TaskRefusal> {
    let mut deadline = store_deadline(ctx.decide_timeout);
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
        (sub, tokens),
        (&mut attempt, emit),
        &mut deadline,
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
            let mut how = match store.hold_mark(&id) {
                Some(who) => Confirm::Held(Some(who)),
                None => Confirm::Queued,
            };
            let mut confirmed = Err(TaskRefusal::Unknown);
            for _ in 0..2 {
                if let Confirm::Held(cause) = how {
                    let mut hold = attempt.record(ctx, Some(&task.task), None);
                    hold.outcome.result = "deny".into();
                    hold.outcome.posture = "unavailable".into();
                    hold.outcome.reason = match (cause, AgentId::parse(&task.task.agent)) {
                        (Some(who), Ok(agent)) => held_reason(who, &agent),
                        (None, _) | (_, Err(_)) => "task held: contained".into(),
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
                confirmed = offload(uid, deadline, move || s.confirm(&id, Some(&t), how)).await;
                match &confirmed {
                    Err(TaskRefusal::Unavailable(why))
                        if why == DUE_A_HOLD && how == Confirm::Queued =>
                    {
                        how = Confirm::Held(store.hold_mark(&id));
                    }
                    _ => break,
                }
            }
            match confirmed {
                Ok(()) => Ok(task),
                Err(refusal) => {
                    let kept = ticket.abandon().is_some();
                    let late = TaskRefusal::Unavailable(format!("{OUTCOME_UNKNOWN}{LATE}"));
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
    (sub, tokens): (TaskSubmission, maknae_proto::ForgeTokens),
    (attempt, emit): (&mut Attempt, &impl AuditEmit),
    deadline: &mut tokio::time::Instant,
) -> Result<Arc<SignedTask>, TaskRefusal> {
    maknae_proto::validate_submission(&sub).map_err(|e| TaskRefusal::Schema(e.to_string()))?;
    let maknae_proto::Ask::Prompt { prompt } = &sub.ask;
    if prompt.expose().len() > ctx.text_max {
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
            true => return Err(TaskRefusal::Denied(OWN_HELD.into())),
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
    let mut bindings = match maknae_security::finalize(decided.verdict) {
        maknae_security::Decision::Permit { obligations } => {
            crate::handler::discharge_plan(&obligations)
                .map_err(|u| TaskRefusal::Denied(format!("unhonorable obligation: {}", u.0)))?;
            seal_bindings(
                &attempt.tasker,
                parent.as_ref().map(CitedTask::bound).as_ref(),
                &sub.bindings,
                ctx.forges,
            )?
        }
        maknae_security::Decision::Deny { reason } => return Err(TaskRefusal::Denied(reason)),
    };
    let agent_uid = enrolled.ok_or(TaskRefusal::AgentGone)?;
    let asker = match by {
        Submitter::User { .. } => crate::reach::Asker::Person { username: ctx.user },
        Submitter::Agent { agent, uid, .. } => match &parent {
            Some(p) => crate::reach::Asker::Parent(p.bound()),
            None => crate::reach::Asker::Agent { agent, uid: *uid },
        },
    };
    let seen: &Attempt = attempt;
    let record = |result: &str, reason: &str, posture: &str| {
        seen.frame_record(ctx, (result, reason, posture))
    };
    let reach = crate::reach::observe(
        &ctx.reach,
        &crate::reach::FrameTrail {
            emit,
            record: &record,
        },
        asker,
        tokens,
        crate::reach::Target {
            agent: &target,
            uid: agent_uid,
        },
        &mut bindings,
    )
    .await?;
    *deadline = store_deadline(ctx.decide_timeout);
    let first = store.next_id()?;
    let ticket = Arc::clone(&attempt.ticket);
    let (s, signer, view) = (Arc::clone(store), Arc::clone(signer), Arc::clone(view));
    let tasker = attempt.tasker.clone();
    let under = parent.as_ref().map(|p| (p.signed.task.task_id, p.start));
    offload(attempt.uid, *deadline, move || {
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
            under,
            sub,
            (bindings, reach),
            Some(&ticket),
        )
    })
    .await
}

/// Each binding's server must be a `git` forge's host; a sub-task's is copied from the
/// parent binding equal on (server, base, change), `head` included.
pub(crate) fn seal_bindings(
    tasker: &Tasker,
    parent: Option<&crate::reach::TaskBound<'_>>,
    asked: &[maknae_proto::BindingRequest],
    forges: &maknae_config::ForgeSet,
) -> Result<Vec<Binding>, TaskRefusal> {
    use maknae_proto::{BindingRequest, GitBinding};
    if asked.is_empty() {
        return Ok(Vec::new());
    }
    if let Tasker::Remote(_) = tasker {
        return Err(TaskRefusal::Unbound(
            "a remote tasker's task takes no binding".into(),
        ));
    }
    let mut sealed = Vec::with_capacity(asked.len());
    for BindingRequest::Git(r) in asked {
        let forge = forges
            .iter()
            .any(|f| f.kind == maknae_config::ForgeKind::Git && f.host == r.server);
        if !forge {
            return Err(TaskRefusal::Unbound(format!(
                "server {} is not the host of a git forge",
                r.server
            )));
        }
        let binding = match parent {
            None => Binding::Git(GitBinding {
                server: r.server.clone(),
                base: r.base.clone(),
                head: None,
                change: r.change,
            }),
            Some(p) => p
                .bindings
                .iter()
                .copied()
                .find(|Binding::Git(g)| {
                    g.server == r.server && g.base == r.base && g.change == r.change
                })
                .cloned()
                .ok_or_else(|| {
                    TaskRefusal::Unbound(format!(
                        "{} {}{} is not bound to the parent task",
                        r.server,
                        r.base,
                        r.change.map(|c| format!(" change {c}")).unwrap_or_default()
                    ))
                })?,
        };
        sealed.push(binding);
    }
    let len = maknae_proto::bindings_encoded_len(&sealed);
    if len > maknae_proto::TASK_BINDINGS_MAX_BYTES {
        return Err(TaskRefusal::Unbound(format!(
            "the sealed bindings encode to {len} bytes, more than {}",
            maknae_proto::TASK_BINDINGS_MAX_BYTES
        )));
    }
    Ok(sealed)
}

/// An addendum adds to a task sealed with reach, within the count, and never a binding the
/// task already holds.
pub(crate) fn addable(
    bound: &crate::reach::TaskBound<'_>,
    added: &[Binding],
) -> Result<(), TaskRefusal> {
    if bound.reach.len() != bound.bindings.len() {
        return Err(TaskRefusal::Unreached(
            "the task was sealed without reach and takes no addendum".into(),
        ));
    }
    let total = bound.bindings.len().saturating_add(added.len());
    if total > maknae_proto::TASK_BINDINGS_MAX {
        return Err(TaskRefusal::Unbound(format!(
            "a task holds at most {} bindings, its own and added, not {total}",
            maknae_proto::TASK_BINDINGS_MAX
        )));
    }
    for Binding::Git(g) in added {
        let held = bound.bindings.iter().any(|Binding::Git(b)| {
            b.server == g.server && b.base == g.base && b.change == g.change
        });
        if held {
            return Err(TaskRefusal::Unbound(format!(
                "{} {}{} is already bound to the task",
                g.server,
                g.base,
                g.change.map(|c| format!(" change {c}")).unwrap_or_default()
            )));
        }
    }
    Ok(())
}

fn within_bounds(
    bindings: &[&Binding],
    reach: &[&maknae_proto::BindingReach],
) -> Result<(), TaskRefusal> {
    encoded_within(bindings, maknae_proto::TASK_BINDINGS_MAX_BYTES).map_err(|len| {
        TaskRefusal::Unbound(format!(
            "the task's own and added bindings encode to {len} bytes, more than {}",
            maknae_proto::TASK_BINDINGS_MAX_BYTES
        ))
    })?;
    encoded_within(reach, maknae_proto::TASK_REACH_MAX_BYTES).map_err(|len| {
        TaskRefusal::Unreached(format!(
            "the task's own and added reach encode to {len} bytes, more than {}",
            maknae_proto::TASK_REACH_MAX_BYTES
        ))
    })
}

fn encoded_within<T: serde::Serialize>(items: &[T], max: usize) -> Result<(), usize> {
    let len = maknae_proto::bindings_encoded_len(items);
    match len > max {
        true => Err(len),
        false => Ok(()),
    }
}

pub(crate) struct AddCtx<'a> {
    pub user: Option<&'a str>,
    pub view: &'a Arc<dyn EnrollmentView>,
    pub decide_timeout: std::time::Duration,
    pub text_max: usize,
    pub forges: &'a maknae_config::ForgeSet,
    pub reach: crate::reach::ReachCtx<'a>,
}

/// `asked` is sealed as a submission's would be, its reach observed against the task's own
/// agent, and stored with `text` as one follow-up.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn add_task_bindings<E: AuditEmit>(
    store: &Arc<TaskStore>,
    signer: &Arc<dyn TaskSigner>,
    ctx: &AddCtx<'_>,
    (id, caller, under, uid): (TaskId, Tasker, Option<TaskId>, u32),
    text: SecretText,
    (asked, tokens): (&[maknae_proto::BindingRequest], maknae_proto::ForgeTokens),
    trail: &crate::reach::FrameTrail<'_, E>,
) -> Result<(TaskView, Vec<Binding>, Vec<maknae_proto::BindingReach>), TaskRefusal> {
    let rec = store.addendum_basis(
        &**ctx.view,
        &id,
        Reach {
            tasker: &caller,
            under,
            task: None,
        },
    )?;
    let parent = match (&rec.tasker, rec.parent) {
        (Tasker::Agent { agent, uid }, Some(p)) => {
            let agent = AgentId::parse(agent).map_err(|_| TaskRefusal::ParentNotHeld)?;
            Some(
                store
                    .working(&p, &agent, *uid)
                    .map_err(|_| TaskRefusal::ParentNotHeld)?,
            )
        }
        (Tasker::Agent { .. }, None) | (Tasker::Uid(_) | Tasker::Remote(_), _) => None,
    };
    let mut added = seal_bindings(
        &rec.tasker,
        parent.as_ref().map(CitedTask::bound).as_ref(),
        asked,
        ctx.forges,
    )?;
    addable(&rec.bound(), &added)?;
    let submitter = match &rec.tasker {
        Tasker::Agent { agent, .. } => {
            Some(AgentId::parse(agent).map_err(|_| TaskRefusal::Unknown)?)
        }
        Tasker::Uid(_) | Tasker::Remote(_) => None,
    };
    let asker = match (&submitter, &parent) {
        (Some(_), Some(p)) => crate::reach::Asker::Parent(p.bound()),
        (Some(agent), None) => crate::reach::Asker::Agent { agent, uid },
        (None, _) => crate::reach::Asker::Person { username: ctx.user },
    };
    let reach = crate::reach::observe(
        &ctx.reach,
        trail,
        asker,
        tokens,
        crate::reach::Target {
            agent: &rec.agent,
            uid: rec.agent_uid,
        },
        &mut added,
    )
    .await?;
    if added.is_empty() {
        return Err(TaskRefusal::Unbound(
            "an addendum adds at least one binding".into(),
        ));
    }
    let deadline = store_deadline(ctx.decide_timeout);
    let (s, signer, max) = (Arc::clone(store), Arc::clone(signer), ctx.text_max);
    let (sealed, sealed_reach) = (added.clone(), reach.clone());
    let enrolled = Arc::clone(ctx.view);
    let view = offload(uid, deadline, move || {
        s.add_bindings(
            &*enrolled,
            &id,
            Reach {
                tasker: &caller,
                under,
                task: None,
            },
            text,
            (sealed, sealed_reach),
            &*signer,
            max,
        )
    })
    .await?;
    Ok((view, added, reach))
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
                maknae_io::now_since_epoch().unwrap(),
            )
        }
    }

    impl TaskSigner for LeafSigner {
        fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal> {
            signed_by(Some(&self.identity.lock().unwrap()), task)
        }
        fn sign_addendum(
            &self,
            addendum: maknae_proto::TaskAddendum,
        ) -> Result<maknae_proto::SignedAddendum, TaskRefusal> {
            maknae_vault::task_sig::sign_addendum(&self.identity.lock().unwrap(), addendum)
                .map_err(|_| TaskRefusal::Unsigned)
        }
        fn current_leaf(&self) -> Option<[u8; 32]> {
            leaf_of(Some(&self.identity.lock().unwrap()))
        }
    }

    impl TaskSigner for &'static LeafSigner {
        fn sign(&self, task: TaskObject) -> Result<SignedTask, TaskRefusal> {
            (**self).sign(task)
        }
        fn sign_addendum(
            &self,
            addendum: maknae_proto::TaskAddendum,
        ) -> Result<maknae_proto::SignedAddendum, TaskRefusal> {
            (**self).sign_addendum(addendum)
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
        fn sign_addendum(
            &self,
            _addendum: maknae_proto::TaskAddendum,
        ) -> Result<maknae_proto::SignedAddendum, TaskRefusal> {
            Err(TaskRefusal::Unsigned)
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
                    sub("hobi"),
                    Vec::new()
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
                    Vec::new(),
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
                    Vec::new(),
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
        fn sign_addendum(
            &self,
            addendum: maknae_proto::TaskAddendum,
        ) -> Result<maknae_proto::SignedAddendum, TaskRefusal> {
            self.inner.sign_addendum(addendum)
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
        fn sign_addendum(
            &self,
            addendum: maknae_proto::TaskAddendum,
        ) -> Result<maknae_proto::SignedAddendum, TaskRefusal> {
            self.inner.sign_addendum(addendum)
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
                Vec::new(),
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

    fn one_binding_addendum(task_id: TaskId) -> maknae_proto::TaskAddendum {
        use maknae_proto::{
            AgentReach, BindingReach, EmptyReason, GitBinding, GitReach, SideReach, TaskerBasis,
        };
        maknae_proto::TaskAddendum::new(
            task_id,
            1,
            vec![Binding::Git(GitBinding {
                server: "github.com".into(),
                base: "o/r".into(),
                head: None,
                change: Some(5),
            })],
            vec![BindingReach::Git(GitReach {
                tasker: SideReach::EMPTY,
                basis: TaskerBasis::Token,
                agent: AgentReach::NoForgeCredential,
                why: Some(EmptyReason::NoForgeCredential),
            })],
        )
        .unwrap()
    }

    fn hobi_task(store: &TaskStore, signing: &LeafSigner) -> TaskId {
        store
            .mint_live(
                signing,
                &view(&[("hobi", HOBI)]),
                at(0, HOBI),
                Tasker::Uid(1000),
                None,
                sub("hobi"),
                Vec::new(),
            )
            .unwrap()
            .task
            .task_id
    }

    #[test]
    fn resign_if_stale_keeps_a_current_addendum_when_only_its_task_is_stale() {
        let signing = LeafSigner::new(PlaneKey::EcdsaP384Sha384);
        let store = Arc::new(TaskStore::new());
        let task_id = hobi_task(&store, &signing);
        signing.rotate();
        let current = Arc::new(
            signing
                .sign_addendum(one_binding_addendum(task_id))
                .unwrap(),
        );
        store.held().tasks.get_mut(&task_id).unwrap().addendum = Some(Arc::clone(&current));
        let handed = store
            .resign_if_stale(&task_id, &id("hobi"), HOBI, &signing)
            .unwrap();
        assert_eq!(Some(fingerprint(&handed)), signing.current_leaf());
        let kept = store.record(&task_id).unwrap().addendum.unwrap();
        assert!(Arc::ptr_eq(&kept, &current));
    }

    #[test]
    fn resign_if_stale_re_signs_a_stale_addendum_with_its_task() {
        let signing = LeafSigner::new(PlaneKey::EcdsaP384Sha384);
        let store = Arc::new(TaskStore::new());
        let task_id = hobi_task(&store, &signing);
        let added = one_binding_addendum(task_id);
        let leaf = |a: &maknae_proto::SignedAddendum| {
            maknae_vault::task_sig::leaf_fingerprint(&a.signature.leaf.0)
        };
        for task_too in [true, false] {
            if !task_too {
                store
                    .resign_if_stale(&task_id, &id("hobi"), HOBI, &signing)
                    .unwrap();
            }
            let stale = Arc::new(signing.sign_addendum(added.clone()).unwrap());
            store.held().tasks.get_mut(&task_id).unwrap().addendum = Some(stale);
            signing.rotate();
            if !task_too {
                store
                    .resign_if_stale(&task_id, &id("hobi"), HOBI, &signing)
                    .unwrap();
                let stale = Arc::new(signing.sign_addendum(added.clone()).unwrap());
                signing.rotate();
                store
                    .resign_if_stale(&task_id, &id("hobi"), HOBI, &signing)
                    .unwrap();
                store.held().tasks.get_mut(&task_id).unwrap().addendum = Some(stale);
            }
            let handed = store
                .resign_if_stale(&task_id, &id("hobi"), HOBI, &signing)
                .unwrap();
            assert_eq!(Some(fingerprint(&handed)), signing.current_leaf());
            let rec = store.record(&task_id).unwrap();
            let kept = rec.addendum.unwrap();
            assert_eq!(Some(leaf(&kept)), signing.current_leaf(), "{task_too}");
            assert_eq!(kept.addendum, added);
            assert!(Arc::ptr_eq(&rec.signed, &handed));
        }
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
                Vec::new(),
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
                    .mint_live(
                        s,
                        &v,
                        at(0, v.0[&id(to)]),
                        Tasker::Uid(1000),
                        None,
                        sub(to),
                        Vec::new(),
                    )
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
                prompt: SecretText::new(String::from(PROMPT)),
            },
            labels: Labels {},
            bindings: vec![],
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
                Vec::new(),
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
                Vec::new(),
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
                Vec::new(),
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
                Vec::new(),
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
                    sub("hobi"),
                    Vec::new()
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
        SecretText::new(String::from(s))
    }

    #[tokio::test(start_paused = true)]
    async fn the_store_steps_get_two_decision_bounds() {
        let bound = std::time::Duration::from_millis(1_500);
        let now = tokio::time::Instant::now();
        assert_eq!(
            store_deadline(bound) - now,
            std::time::Duration::from_secs(3)
        );
    }

    #[test]
    fn a_follow_up_fits_below_the_count_and_up_to_the_byte_total() {
        let some = vec![text("ab"); MAX_FOLLOW_UPS_PER_TASK - 1];
        let total = 2 * (MAX_FOLLOW_UPS_PER_TASK - 1);
        assert_eq!(room_for(&some, &text("xyz"), total + 3), Ok(()));
        assert_eq!(
            room_for(&some, &text("xyz"), total + 2),
            Err(TaskRefusal::FollowUps)
        );
        let full = vec![text(""); MAX_FOLLOW_UPS_PER_TASK];
        assert_eq!(
            room_for(&full, &text(""), usize::MAX),
            Err(TaskRefusal::FollowUps)
        );
        assert_eq!(room_for(&[], &text(""), 0), Ok(()));
    }

    #[test]
    fn bindings_and_reach_are_bounded_by_their_encoded_length() {
        use maknae_proto::{
            AgentReach, BindingReach, GitBinding, GitReach, SideReach, TaskerBasis,
        };
        let binding = |base: String| {
            Binding::Git(GitBinding {
                server: "github.com".into(),
                base,
                head: None,
                change: None,
            })
        };
        let one = [binding("o/r".into())];
        let len = maknae_proto::bindings_encoded_len(&one);
        assert_eq!(encoded_within(&one, len), Ok(()));
        assert_eq!(encoded_within(&one, len - 1), Err(len));

        let small = binding("o/r".into());
        let large = binding(format!(
            "o/{}",
            "r".repeat(maknae_proto::TASK_BINDINGS_MAX_BYTES)
        ));
        let entry = BindingReach::Git(GitReach {
            tasker: SideReach::EMPTY,
            basis: TaskerBasis::Token,
            agent: AgentReach::AtHandOut,
            why: None,
        });
        let reach_of = |n: usize| vec![&entry; n];
        let many = maknae_proto::TASK_REACH_MAX_BYTES;
        assert_eq!(within_bounds(&[&small], &reach_of(1)), Ok(()));
        assert!(matches!(
            within_bounds(&[&large], &reach_of(1)),
            Err(TaskRefusal::Unbound(_))
        ));
        assert!(matches!(
            within_bounds(&[&small], &reach_of(many)),
            Err(TaskRefusal::Unreached(_))
        ));
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
        assert_eq!(
            store.confirm(&mine, None, Confirm::Queued),
            Err(TaskRefusal::Unknown)
        );
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
    fn holdings_count_what_collect_would_return() {
        let (_blobs, store) = mem();
        let me = Tasker::Uid(1000);
        let held = held_by(&store, me.clone());
        store.publish_report(&held, text("h"), None).unwrap();
        store.mark_unenrolled(&crate::enrollment::Containing(
            view(&[("hobi", HOBI)]),
            [1000].into(),
        ));
        store.close_all_due();
        assert_eq!(store.record(&held).unwrap().state, TaskState::Held);
        let (a, b) = (held_by(&store, me.clone()), held_by(&store, me.clone()));
        store.publish_report(&a, text("a"), None).unwrap();
        store
            .publish_report(&b, text(""), Some(TaskClose::Stopped))
            .unwrap();
        held_by(&store, me.clone());
        let working = held_by(&store, me.clone());
        store.start_for_test(&working);
        held_by(&store, Tasker::Uid(1001));
        let got = store.holdings(&me);
        assert_eq!(
            got.into_iter().collect::<Vec<_>>(),
            [(
                id("hobi"),
                Holding {
                    records: 5,
                    open: 3,
                    waiting: 2
                }
            )]
        );
        assert_eq!(
            store.reports(&me, &id("hobi"), usize::MAX).entries.len(),
            2,
            "what a collect would return"
        );
        assert!(store.holdings(&Tasker::Uid(999)).is_empty());
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
            .mint(
                signer(),
                &v,
                at(0, HOBI),
                me.clone(),
                None,
                sub("hobi"),
                Vec::new(),
            )
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
                .mint(
                    signer(),
                    &v,
                    at(0, HOBI),
                    me.clone(),
                    None,
                    sub("hobi"),
                    Vec::new()
                )
                .unwrap_err(),
            TaskRefusal::TaskerLive {
                agent: "hobi".into()
            }
        );
        store.confirm(&pending, None, Confirm::Queued).unwrap();
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
                        Vec::new(),
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
                    sub("hobi"),
                    Vec::new()
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
                    sub("hobi"),
                    Vec::new()
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
                sub("Not An Id"),
                Vec::new()
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
                    sub("hobi"),
                    Vec::new()
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
        under: (std::time::Duration, Option<Breaker>),
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let none = maknae_config::ForgeSet::empty();
        submit_in(a, store, v, by, sub, emit, under, &none).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn submit_in<
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
        forges: &maknae_config::ForgeSet,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let w = wctx();
        let seq = maknae_audit_append::Seq::new();
        let settings = crate::reach::ReachSettings::of(forges, None, 1_000);
        let ctx = SubmitCtx {
            where_: &w,
            session_id: SESSION,
            seq: &seq,
            user: Some("alice"),
            peer_uri: None,
            lane: maknae_security::Lane::Local,
            decide_timeout: bound,
            text_max: 1 << 20,
            forges,
            reach: crate::reach::ReachCtx {
                settings: &settings,
                ..unreachable()
            },
        };
        let pdp = Decider {
            authorizer: a,
            breaker: breaker.unwrap_or_default(),
        };
        let v: Arc<dyn EnrollmentView> = Arc::new(v.clone());
        let none = maknae_proto::ForgeTokens::default();
        submit_under(
            pdp,
            store,
            &shared_signer(),
            &v,
            &ctx,
            by,
            (sub, none),
            emit,
        )
        .await
    }

    fn no_credentials(_: u32) -> Vec<maknae_proto::CredentialRef> {
        Vec::new()
    }

    /// Reach that no test here reaches: an absent socket, no forge traits, no credentials.
    fn unreachable() -> crate::reach::ReachCtx<'static> {
        static EGRESS: std::sync::OnceLock<Arc<dyn crate::egress_socket::ReachEgress>> =
            std::sync::OnceLock::new();
        static SETTINGS: std::sync::OnceLock<crate::reach::ReachSettings> =
            std::sync::OnceLock::new();
        static PERMITS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
        crate::reach::ReachCtx {
            egress: EGRESS.get_or_init(|| crate::egress_socket::no_reach("no socket in this test")),
            settings: SETTINGS.get_or_init(crate::reach::ReachSettings::default),
            permits: &PERMITS,
            credentials: &no_credentials,
        }
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

    /// The tests that stall the store, or need a slot free within a bound, share per-uid store
    /// slots; they take turns.
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
            .mint(
                signer(),
                &v,
                enrolled,
                Tasker::Uid(1000),
                None,
                sub("hobi"),
                Vec::new(),
            )
            .unwrap()
            .task
            .task_id;
        let ticket = Ticket::default();
        assert_eq!(ticket.abandon(), None);
        blobs.after_save(|| panic!("an abandoned confirm writes nothing"));
        assert!(store
            .confirm(&task, Some(&ticket), Confirm::Queued)
            .is_err());
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
            .mint(
                signer(),
                &v,
                enrolled,
                Tasker::Uid(1000),
                None,
                sub("hobi"),
                Vec::new(),
            )
            .unwrap()
            .task
            .task_id;
        let ticket = Arc::new(Ticket::default());
        let seen = Arc::new(Mutex::new(None));
        let (t, s) = (Arc::clone(&ticket), Arc::clone(&seen));
        blobs.after_save(move || *s.lock().unwrap() = Some(t.abandon()));
        assert_eq!(store.confirm(&task, Some(&ticket), Confirm::Queued), Ok(()));
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
        let _alone = STALLS.lock().await;
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
        assert!(page.entries[0].text.expose().is_empty());
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
            store.report(&working, &hobi, HOBI, text("late"), None),
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
                    Vec::new(),
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
    fn of_two_crossed_submissions_placed_before_either_confirms_the_second_is_refused() {
        let (_blobs, store) = mem();
        let v = view(&[("hobi", HOBI), ("jin", JIN)]);
        let working = |agent: &str| {
            let t = mint(&store, &v, agent).task.task_id;
            store.start_for_test(&t);
            t
        };
        let (t1, t3) = (working("hobi"), working("jin"));
        let by = |agent: &str, uid| Tasker::Agent {
            agent: agent.into(),
            uid,
        };
        let first = store
            .mint(
                signer(),
                &v,
                at(0, JIN),
                by("hobi", HOBI),
                Some(t1),
                sub("jin"),
                Vec::new(),
            )
            .unwrap();
        assert!(store.record(&first.task.task_id).is_none(), "still pending");
        assert_eq!(
            store
                .mint(
                    signer(),
                    &v,
                    at(0, HOBI),
                    by("jin", JIN),
                    Some(t3),
                    sub("hobi"),
                    Vec::new()
                )
                .unwrap_err(),
            TaskRefusal::Denied("task chain already waits on agent hobi".into())
        );
        store
            .confirm(&first.task.task_id, None, Confirm::Queued)
            .unwrap();
        assert_eq!(
            store.record(&first.task.task_id).unwrap().state,
            TaskState::Queued
        );
        assert_eq!(store.queue(&id("hobi")), Vec::<TaskId>::new());
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
                Vec::new(),
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
                Vec::new(),
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
            store.confirm(&task, None, Confirm::Queued),
            Err(TaskRefusal::Unavailable(DUE_A_HOLD.into())),
            "not published as queued work"
        );
        assert!(store.record(&task).is_none());
        assert_eq!(
            store.confirm(&task, None, Confirm::Held(Some(Contained::Tasker))),
            Ok(())
        );
        let rec = store.record(&task).unwrap();
        assert_eq!(
            (rec.state, rec.held_from, rec.held_for),
            (
                TaskState::Held,
                Some(TaskState::Queued),
                Some(Contained::Tasker)
            )
        );
        assert!(rec.held_at.is_some());
        assert_eq!(store.hold_mark(&task), None);
        store.mark_unenrolled(&v);
        assert!(store.close_all_due().is_empty(), "a release lifts no hold");
        assert_eq!(
            claim_head(&store, &id("hobi"), HOBI, signer()),
            Ok(Claimed::Idle)
        );
        let reopened = reopen(&blobs);
        assert_eq!(reopened.record(&task).unwrap().state, TaskState::Held);

        let fresh = || {
            store
                .mint(
                    signer(),
                    &v,
                    at(0, HOBI),
                    Tasker::Uid(1000),
                    None,
                    sub("hobi"),
                    Vec::new(),
                )
                .unwrap()
                .task
                .task_id
        };
        let (unmarked, rooted) = (fresh(), fresh());
        store.mark_unenrolled(&containing(&[1000]));
        assert_eq!(store.hold_mark(&unmarked), Some(Contained::Tasker));
        store.held().holding.remove(&unmarked);
        let gone = store.hold_mark(&unmarked);
        assert_eq!(gone, None);
        assert_eq!(store.confirm(&unmarked, None, Confirm::Held(gone)), Ok(()));
        assert_eq!(
            store.confirm(&rooted, None, Confirm::Held(Some(Contained::Root))),
            Ok(())
        );
        let reopened = reopen(&blobs);
        for (task, cause) in [(unmarked, None), (rooted, Some(Contained::Root))] {
            let rec = store.record(&task).unwrap();
            assert_eq!(
                (rec.state, rec.held_for),
                (TaskState::Held, cause),
                "the store keeps the cause the hold record named"
            );
            assert_eq!(reopened.record(&task).unwrap().held_for, cause);
        }
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
        store
            .report(&working, &hobi, HOBI, text("done"), None)
            .unwrap();
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
            .mint_live(
                signer(),
                &v,
                at(0, JIN),
                hobis,
                None,
                sub("jin"),
                Vec::new(),
            )
            .unwrap()
            .task
            .task_id;
        store.start_for_test(&given);
        let under = store
            .mint_live(
                signer(),
                &v,
                at(0, SUGA),
                jins,
                Some(given),
                sub("suga"),
                Vec::new(),
            )
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
                Vec::new(),
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
        for (task, cause) in want {
            let rec = store.record(&task).unwrap();
            assert_eq!(
                (rec.state, rec.held_for.map(DueFor::Hold)),
                (TaskState::Held, Some(cause))
            );
            assert!(rec.held_at.is_some());
        }
        assert_eq!(store.record(&reported).unwrap().state, TaskState::Reported);
        assert_eq!(store.record(&others).unwrap().state, TaskState::Queued);
    }

    const BOB: u32 = 1000;

    type HoldFields = (TaskState, Option<TaskState>, Option<Contained>, Option<i64>);

    fn hold_fields(store: &TaskStore, task: &TaskId) -> HoldFields {
        let r = store.record(task).unwrap();
        (r.state, r.held_from, r.held_for, r.held_at)
    }

    fn chain(store: &TaskStore) -> (TaskId, TaskId) {
        let t1 = held_by(store, Tasker::Uid(BOB));
        store.start_for_test(&t1);
        let hobis = Tasker::Agent {
            agent: "hobi".into(),
            uid: HOBI,
        };
        let t2 = store
            .mint_live(
                signer(),
                &view(&[("hobi", HOBI), ("jin", JIN)]),
                at(0, JIN),
                hobis,
                Some(t1),
                sub("jin"),
                Vec::new(),
            )
            .unwrap()
            .task
            .task_id;
        (t1, t2)
    }

    fn hold(store: &TaskStore, uids: &[u32]) {
        store.mark_unenrolled(&containing(uids));
        store.close_all_due();
    }

    #[test]
    fn release_mirrors_the_hold() {
        #[derive(Clone, Copy, Debug)]
        enum Of {
            T1,
            T2,
        }
        #[derive(Clone, Copy, Debug)]
        enum Want {
            Released(TaskState, TaskState),
            ParentHeld,
            Still(Contained),
        }
        use TaskState::{Queued, Working};
        type Row<'a> = (&'a [u32], &'a [u32], Contained, &'a [(Of, Want)]);
        let rows: [Row<'_>; 5] = [
            (
                &[BOB],
                &[],
                Contained::Root,
                &[
                    (Of::T1, Want::Released(Working, Queued)),
                    (Of::T2, Want::Released(Queued, Queued)),
                ],
            ),
            (&[BOB], &[], Contained::Root, &[(Of::T2, Want::ParentHeld)]),
            (
                &[BOB, HOBI],
                &[HOBI],
                Contained::Tasker,
                &[
                    (Of::T1, Want::Still(Contained::Agent)),
                    (Of::T2, Want::ParentHeld),
                ],
            ),
            (
                &[BOB],
                &[BOB],
                Contained::Root,
                &[(Of::T1, Want::Still(Contained::Tasker))],
            ),
            (
                &[HOBI],
                &[],
                Contained::Tasker,
                &[(Of::T1, Want::Released(Working, Queued))],
            ),
        ];
        for (row, (at_hold, at_release, t2_cause, steps)) in rows.iter().enumerate() {
            let (_blobs, store) = mem();
            let (t1, t2) = chain(&store);
            hold(&store, at_hold);
            assert_eq!(hold_fields(&store, &t2).2, Some(*t2_cause), "row {row}");
            let mut released = BTreeSet::new();
            let held = [
                (t1, hold_fields(&store, &t1)),
                (t2, hold_fields(&store, &t2)),
            ];
            let v = containing(at_release);
            for (of, want) in steps.iter() {
                let task = match of {
                    Of::T1 => t1,
                    Of::T2 => t2,
                };
                let want = match want {
                    Want::Released(from, now) => Ok(Released {
                        task,
                        from: *from,
                        now: *now,
                        rseq: None,
                    }),
                    Want::ParentHeld => Err(ReleaseRefusal::ParentHeld(t1)),
                    Want::Still(who) => Err(ReleaseRefusal::StillContained(*who)),
                };
                assert_eq!(
                    store
                        .release_plan(&task, &v)
                        .map(|p| (p.task, p.from, p.to)),
                    want.clone().map(|r| (r.task, r.from, r.now)),
                    "row {row} {of:?}"
                );
                assert_eq!(store.release(&task, &v), want, "row {row} {of:?}");
                if let Ok(r) = want {
                    released.insert(task);
                    assert_eq!(
                        hold_fields(&store, &task),
                        (r.now, None, None, None),
                        "row {row} {of:?}"
                    );
                }
            }
            for (task, fields) in held {
                if !released.contains(&task) {
                    assert_eq!(fields.0, TaskState::Held, "row {row}");
                    assert_eq!(hold_fields(&store, &task), fields, "row {row}");
                }
            }
        }
    }

    #[test]
    fn a_containment_between_plan_and_release_is_refused_under_the_writer() {
        let (_blobs, store) = mem();
        let (t1, _) = chain(&store);
        hold(&store, &[BOB]);
        let before = hold_fields(&store, &t1);
        assert!(store.release_plan(&t1, &containing(&[])).is_ok());
        assert_eq!(
            store.release(&t1, &containing(&[BOB])),
            Err(ReleaseRefusal::StillContained(Contained::Tasker))
        );
        assert_eq!(hold_fields(&store, &t1), before);
    }

    #[test]
    fn a_release_whose_tasker_or_root_agent_left_is_refused_unresolved() {
        let as_agent = |agent: &str, uid: u32| Tasker::Agent {
            agent: agent.into(),
            uid,
        };
        let hobi_root = RootTasker::Agent {
            agent: "hobi".into(),
        };
        let only_jin = |uids: &[u32]| {
            crate::enrollment::Containing(view(&[("jin", JIN)]), uids.iter().copied().collect())
        };
        let rows = [
            (
                as_agent("jin", JIN),
                &[HOBI][..],
                only_jin(&[HOBI]),
                Some(ReleaseRefusal::RootUnresolved),
            ),
            (
                as_agent("hobi", HOBI),
                &[JIN][..],
                only_jin(&[]),
                Some(ReleaseRefusal::TaskerUnresolved),
            ),
            (
                as_agent("jin", JIN),
                &[HOBI][..],
                crate::enrollment::Containing(
                    view(&[("jin", JIN), ("hobi", HOBI)]),
                    BTreeSet::new(),
                ),
                None,
            ),
        ];
        for (row, (tasker, at_hold, at_release, refusal)) in rows.into_iter().enumerate() {
            let (_blobs, store) = mem();
            let mut task = TaskObject::for_test("jin", 0);
            task.tasker = tasker;
            let task = store
                .insert_for_test(signer().sign(task).unwrap(), JIN)
                .task
                .task_id;
            store.held().tasks.get_mut(&task).unwrap().root = hobi_root.clone();
            store.start_for_test(&task);
            hold(&store, at_hold);
            let before = hold_fields(&store, &task);
            assert_eq!(before.0, TaskState::Held, "row {row}");
            let Some(refusal) = refusal else {
                assert_eq!(
                    store.release_plan(&task, &at_release).map(|p| p.task),
                    Ok(task),
                    "row {row}"
                );
                assert!(store.release(&task, &at_release).is_ok(), "row {row}");
                assert_eq!(hold_fields(&store, &task).0, TaskState::Queued, "row {row}");
                continue;
            };
            assert_eq!(
                store.release_plan(&task, &at_release).map(|p| p.task),
                Err(refusal.clone()),
                "row {row}"
            );
            assert_eq!(store.release(&task, &at_release), Err(refusal), "row {row}");
            assert_eq!(hold_fields(&store, &task), before, "row {row}");
        }
    }

    struct Switching {
        base: FixedEnrollment,
        contained: Arc<Mutex<BTreeSet<u32>>>,
    }

    impl EnrollmentView for Switching {
        fn agent_uid(&self, id: &AgentId) -> Option<u32> {
            self.base.agent_uid(id)
        }
        fn agents(&self) -> Vec<(AgentId, u32)> {
            self.base.agents()
        }
        fn is_enrolled(&self, uid: u32) -> bool {
            self.base.is_enrolled(uid)
        }
        fn contained(&self, uid: u32) -> bool {
            self.contained.lock().unwrap().contains(&uid)
        }
        fn unresolved(&self, uid: u32) -> bool {
            self.base.unresolved(uid)
        }
        fn board(&self, agent: &AgentId) -> bool {
            self.base.board(agent)
        }
    }

    #[test]
    fn a_containment_installed_during_the_write_marks_the_released_task_for_a_hold() {
        let (blobs, store) = mem();
        let (t1, t2) = chain(&store);
        hold(&store, &[BOB]);
        let contained = Arc::new(Mutex::new(BTreeSet::new()));
        let v = Switching {
            base: view(&[("hobi", HOBI), ("jin", JIN)]),
            contained: Arc::clone(&contained),
        };
        blobs.after_save(move || {
            contained.lock().unwrap().insert(BOB);
        });
        assert!(store.release(&t1, &v).is_ok());
        assert_eq!(store.record(&t1).unwrap().state, TaskState::Queued);
        assert_eq!(store.hold_mark(&t1), Some(Contained::Tasker));
        assert_eq!(store.next_for(&id("hobi"), HOBI), None);
        assert_eq!(
            store.release(&t2, &containing(&[])),
            Err(ReleaseRefusal::ParentHeld(t1)),
            "the parent is due a hold"
        );
        store.close_all_due();
        assert_eq!(store.record(&t1).unwrap().state, TaskState::Held);
    }

    fn cite(store: &TaskStore, id: &TaskId) {
        store.acted(id, store.hot(id).map_or(0, |h| h.start));
    }

    #[test]
    fn a_request_resolved_before_a_release_does_not_mark_the_new_start_seen() {
        let hobi = id("hobi");
        let fresh = |store: &TaskStore| match claim_head(store, &hobi, HOBI, signer()) {
            Ok(Claimed::Delivered { fresh, .. }) => fresh,
            other => panic!("{other:?}"),
        };
        let (_blobs, store) = mem();
        let task = held_by(&store, Tasker::Uid(BOB));
        assert!(fresh(&store));
        let before = store.working(&task, &hobi, HOBI).unwrap().start;
        hold(&store, &[BOB]);
        store.release(&task, &containing(&[])).unwrap();
        assert!(fresh(&store));
        store.acted(&task, before);
        assert!(fresh(&store), "a citation of the earlier start");
        store.acted(&task, store.working(&task, &hobi, HOBI).unwrap().start);
        assert!(!fresh(&store));
    }

    #[test]
    fn a_start_stays_fresh_until_a_request_cites_it_and_a_restart_errs_fresh() {
        let fresh = |store: &TaskStore| match claim_head(store, &id("hobi"), HOBI, signer()) {
            Ok(Claimed::Delivered { fresh, .. }) => fresh,
            other => panic!("{other:?}"),
        };
        let (blobs, store) = mem();
        let task = held_by(&store, Tasker::Uid(BOB));
        assert!(fresh(&store));
        assert!(store.record(&task).unwrap().unseen);
        let store = reopen(&blobs);
        assert!(fresh(&store), "a lost start is fresh again after a restart");
        cite(&store, &task);
        let store = reopen(&blobs);
        assert!(fresh(&store), "a citation not yet stored errs fresh");
        cite(&store, &task);
        assert!(!fresh(&store));
        store.store_counters();
        assert!(!store.record(&task).unwrap().unseen);
        assert!(!fresh(&reopen(&blobs)));
    }

    #[test]
    fn a_released_working_task_is_queued_and_handed_out_fresh() {
        let (_blobs, store) = mem();
        let hobi = id("hobi");
        let task = held_by(&store, Tasker::Uid(BOB));
        store.start_for_test(&task);
        cite(&store, &task);
        assert!(matches!(
            claim_head(&store, &hobi, HOBI, signer()),
            Ok(Claimed::Delivered { fresh: false, .. })
        ));
        if let Some(hot) = store.held().hot.get_mut(&task) {
            (hot.retry_after, hot.retry_secs) = (i64::MAX, RETRY_MAX_SECS);
        }
        hold(&store, &[BOB]);
        store.release(&task, &containing(&[])).unwrap();
        let rec = store.record(&task).unwrap();
        assert_eq!((rec.state, rec.claimed), (TaskState::Queued, None));
        let hot = store.hot(&task).unwrap();
        assert_eq!(
            (hot.lease_until, hot.retry_after, hot.retry_secs),
            (0, 0, 0)
        );
        assert_eq!(store.next_for(&hobi, HOBI), Some((task, TaskState::Queued)));
        for _ in 0..2 {
            assert!(matches!(
                claim_head(&store, &hobi, HOBI, signer()),
                Ok(Claimed::Delivered { fresh: true, .. })
            ));
        }
    }

    #[test]
    fn a_released_report_gets_a_new_rseq_and_is_collected_after_a_later_acknowledgement() {
        let (_blobs, store) = mem();
        let bob = Tasker::Uid(BOB);
        let jin = id("jin");
        let give = || {
            store
                .mint_live(
                    signer(),
                    &view(&[("hobi", HOBI), ("jin", JIN)]),
                    at(0, JIN),
                    bob.clone(),
                    None,
                    sub("jin"),
                    Vec::new(),
                )
                .unwrap()
                .task
                .task_id
        };
        let a = give();
        store.publish_report(&a, text("a"), None).unwrap();
        hold(&store, &[BOB]);
        let b = give();
        let rseq_b = store.publish_report(&b, text("b"), None).unwrap();
        assert_eq!(store.acknowledged(&bob, &jin, rseq_b), Ok(vec![b]));
        let released = store.release(&a, &containing(&[])).unwrap();
        assert!(released.rseq > Some(rseq_b), "{released:?}");
        assert_eq!(
            store
                .reports(&bob, &jin, usize::MAX)
                .entries
                .iter()
                .map(|e| e.task.clone())
                .collect::<Vec<_>>(),
            vec![maknae_proto::TaskRef::from_id(&a)]
        );
        assert_eq!(
            store.acknowledged(&bob, &jin, released.rseq.unwrap()),
            Ok(vec![a])
        );
    }

    #[test]
    fn a_report_held_past_report_hold_is_collectable_after_release() {
        let (_blobs, clock, store) = clocked();
        let me = Tasker::Uid(BOB);
        let task = held_by(&store, me.clone());
        store.publish_report(&task, text("r"), None).unwrap();
        hold(&store, &[BOB]);
        let hold_secs = REPORT_HOLD.as_secs() as i64;
        let now = 1_000 + hold_secs + 86_400;
        clock.set(now);
        store.release(&task, &containing(&[])).unwrap();
        assert!(store.due(8).iter().all(|d| d.why != DueFor::Expiry));
        assert_eq!(
            store
                .reports(&me, &id("hobi"), usize::MAX)
                .entries
                .iter()
                .map(|e| e.at_secs)
                .collect::<Vec<_>>(),
            vec![now]
        );
        clock.set(now + hold_secs);
        assert!(matches!(
            store.due(8)[..],
            [Due {
                why: DueFor::Expiry,
                ..
            }]
        ));
    }

    #[test]
    fn a_release_whose_write_is_refused_is_not_done_and_stays_held() {
        use crate::task_store::Fail;
        let (blobs, store) = mem();
        let working = held_by(&store, Tasker::Uid(BOB));
        store.start_for_test(&working);
        let reported = held_by(&store, Tasker::Uid(BOB));
        store.publish_report(&reported, text("r"), None).unwrap();
        hold(&store, &[BOB]);
        let lift = containing(&[]);
        for (task, fail, counters_kept) in [
            (working, Fail::UnsyncedOnce, true),
            (reported, Fail::Every, true),
            (reported, Fail::Records, false),
        ] {
            let before = (hold_fields(&store, &task), store.held().issued.clone());
            let rec = encode(&store.record(&task).unwrap()).unwrap();
            blobs.fail(Some(fail));
            let said = store.release(&task, &lift);
            blobs.fail(None);
            assert!(
                matches!(said, Err(ReleaseRefusal::NotDone(_))),
                "{fail:?} {said:?}"
            );
            assert_eq!(hold_fields(&store, &task), before.0, "{fail:?}");
            assert_eq!(
                *encode(&store.record(&task).unwrap()).unwrap(),
                *rec,
                "{fail:?}"
            );
            if counters_kept {
                assert_eq!(store.held().issued, before.1, "{fail:?}");
            }
            assert_eq!(reopen(&blobs).record(&task).unwrap().state, TaskState::Held);
        }
    }

    #[tokio::test]
    async fn a_release_whose_store_step_does_not_answer_is_outcome_unknown_and_a_repeat_is_safe() {
        let _alone = STALLS.lock().await;
        let (blobs, store) = mem();
        let task = held_by(&store, Tasker::Uid(BOB));
        hold(&store, &[BOB]);
        let lift = containing(&[]);
        blobs.fail(Some(crate::task_store::Fail::Unsynced));
        assert!(matches!(
            store.release(&task, &lift),
            Err(ReleaseRefusal::OutcomeUnknown(_))
        ));
        blobs.fail(None);
        store.pass();
        assert_eq!(reopen(&blobs).record(&task).unwrap().state, TaskState::Held);
        assert_eq!(
            store.release(&task, &lift).map(|r| r.now),
            Ok(TaskState::Queued)
        );
        for owed in [false, true] {
            let (blobs, store) = mem();
            let store = Arc::new(store);
            let task = held_by(&store, Tasker::Uid(BOB));
            hold(&store, &[BOB]);
            blobs.slow(Some(std::time::Duration::from_secs(1)));
            let s = Arc::clone(&store);
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(100);
            let said = offload(
                BOB,
                deadline,
                move || Ok(s.release(&task, &containing(&[]))),
            )
            .await;
            assert!(
                matches!(&said, Err(TaskRefusal::Unavailable(why)) if why.starts_with("outcome unknown: ")),
                "{said:?}"
            );
            blobs.await_stalls(1);
            if owed {
                blobs.fail(Some(crate::task_store::Fail::UnsyncedOnce));
            }
            blobs.slow(None);
            let s = Arc::clone(&store);
            tokio::task::spawn_blocking(move || s.pass()).await.unwrap();
            let lift = containing(&[]);
            if owed {
                assert_eq!(store.record(&task).unwrap().state, TaskState::Held);
                assert_eq!(
                    store.release(&task, &lift).map(|r| r.now),
                    Ok(TaskState::Queued)
                );
            } else {
                let landed = hold_fields(&store, &task);
                assert_eq!(landed, (TaskState::Queued, None, None, None));
                let attempts = blobs.attempts();
                assert_eq!(store.release(&task, &lift), Err(ReleaseRefusal::NotHeld));
                assert_eq!(
                    (hold_fields(&store, &task), blobs.attempts()),
                    (landed, attempts)
                );
            }
        }
    }

    #[test]
    fn a_second_release_is_not_held_and_an_unknown_task_is_unknown() {
        let (_blobs, store) = mem();
        let task = held_by(&store, Tasker::Uid(BOB));
        let lift = containing(&[]);
        assert_eq!(store.release(&task, &lift), Err(ReleaseRefusal::NotHeld));
        hold(&store, &[BOB]);
        assert!(store.release(&task, &lift).is_ok());
        assert_eq!(store.release(&task, &lift), Err(ReleaseRefusal::NotHeld));
        assert_eq!(
            store.release_plan(&task, &lift).map(|p| p.task),
            Err(ReleaseRefusal::NotHeld)
        );
        let unknown = TaskId([9; 16]);
        assert_eq!(store.release(&unknown, &lift), Err(ReleaseRefusal::Unknown));
        assert_eq!(
            store.release_plan(&unknown, &lift).map(|p| p.task),
            Err(ReleaseRefusal::Unknown)
        );
        for from in [None, Some(TaskState::Held)] {
            let bare = held_by(&store, Tasker::Uid(BOB));
            hold(&store, &[BOB]);
            store.held().tasks.get_mut(&bare).unwrap().held_from = from;
            assert!(
                matches!(
                    store.release_plan(&bare, &lift),
                    Err(ReleaseRefusal::NotDone(_))
                ),
                "{from:?}"
            );
            assert!(
                matches!(store.release(&bare, &lift), Err(ReleaseRefusal::NotDone(_))),
                "{from:?}"
            );
            assert_eq!(
                hold_fields(&store, &bare),
                (
                    TaskState::Held,
                    from,
                    Some(Contained::Tasker),
                    store.record(&bare).unwrap().held_at
                ),
                "{from:?}"
            );
            assert!(store.record(&bare).unwrap().held_at.is_some(), "{from:?}");
            let (page, _) = store.held_tasks(&lift, HeldSelect::Every, None, 32);
            let bare_ref = maknae_proto::TaskRef::from_id(&bare);
            assert_eq!(
                page.iter()
                    .find(|h| h.view.task == bare_ref)
                    .map(|h| h.held_from),
                Some(TaskState::Held),
                "{from:?}"
            );
        }
    }

    #[test]
    fn a_released_record_reopens_released() {
        let (blobs, store) = mem();
        let task = held_by(&store, Tasker::Uid(BOB));
        hold(&store, &[BOB]);
        store.release(&task, &containing(&[])).unwrap();
        assert_eq!(
            hold_fields(&reopen(&blobs), &task),
            (TaskState::Queued, None, None, None)
        );
    }

    #[test]
    fn held_tasks_select_by_tasker_root_or_agent_in_store_order_and_page() {
        let (_blobs, store) = mem();
        let all = view(&[("hobi", HOBI), ("jin", JIN), ("suga", SUGA)]);
        let (hobi, jin, suga) = (id("hobi"), id("jin"), id("suga"));
        let t1 = held_by(&store, Tasker::Uid(BOB));
        let hobis = Tasker::Agent {
            agent: "hobi".into(),
            uid: HOBI,
        };
        let jins = Tasker::Agent {
            agent: "jin".into(),
            uid: JIN,
        };
        let g = store
            .mint_live(
                signer(),
                &all,
                at(0, JIN),
                hobis.clone(),
                None,
                sub("jin"),
                Vec::new(),
            )
            .unwrap()
            .task
            .task_id;
        store.start_for_test(&t1);
        let t2 = store
            .mint_live(
                signer(),
                &all,
                at(0, JIN),
                hobis,
                Some(t1),
                sub("jin"),
                Vec::new(),
            )
            .unwrap()
            .task
            .task_id;
        store.start_for_test(&g);
        let u = store
            .mint_live(
                signer(),
                &all,
                at(0, SUGA),
                jins,
                Some(g),
                sub("suga"),
                Vec::new(),
            )
            .unwrap()
            .task
            .task_id;
        let free = store
            .mint_live(
                signer(),
                &all,
                at(0, SUGA),
                Tasker::Uid(1001),
                None,
                sub("suga"),
                Vec::new(),
            )
            .unwrap()
            .task
            .task_id;
        let v = crate::enrollment::Containing(all, [BOB, HOBI].into());
        store.mark_unenrolled(&v);
        store.close_all_due();
        assert_eq!(store.record(&free).unwrap().state, TaskState::Queued);
        for (select, want) in [
            (HeldSelect::Uid(BOB), vec![t1, t2]),
            (HeldSelect::Uid(HOBI), vec![t1, g, t2, u]),
            (HeldSelect::Uid(JIN), vec![g, t2, u]),
            (HeldSelect::Uid(SUGA), vec![u]),
            (HeldSelect::Agent(&hobi), vec![t1, g, t2, u]),
            (HeldSelect::Agent(&jin), vec![g, t2, u]),
            (HeldSelect::Agent(&suga), vec![u]),
            (HeldSelect::Every, vec![t1, g, t2, u]),
        ] {
            let (tasks, next) = store.held_tasks(&v, select, None, 32);
            assert_eq!(
                tasks
                    .iter()
                    .map(|h| h.view.task.clone())
                    .collect::<Vec<_>>(),
                want.iter()
                    .map(maknae_proto::TaskRef::from_id)
                    .collect::<Vec<_>>(),
                "{select:?}"
            );
            assert_eq!(next, None, "{select:?}");
            let (seqs, next) = store.held_seqs(&v, select, None, 32);
            assert_eq!(
                seqs,
                want.iter()
                    .map(|t| (store.record(t).unwrap().seq, *t))
                    .collect::<Vec<_>>(),
                "{select:?}"
            );
            assert_eq!(next, None, "{select:?}");
        }
        let (first, _) = store.held_tasks(&v, HeldSelect::Every, None, 1);
        let rec = store.record(&t1).unwrap();
        let [h] = &first[..] else {
            panic!("{first:?}");
        };
        assert_eq!(
            (
                h.seq,
                h.view.state,
                &h.tasker,
                h.held_from,
                h.held_for,
                h.held_at
            ),
            (
                rec.seq,
                TaskState::Held,
                &Tasker::Uid(BOB),
                TaskState::Working,
                Some(Contained::Tasker),
                rec.held_at
            )
        );
        assert!(rec.held_at.is_some());
        let (mut tasks, mut seqs, mut after) = (Vec::new(), Vec::new(), None);
        loop {
            let (page, next) = store.held_tasks(&v, HeldSelect::Every, after, 1);
            let (ids, ids_next) = store.held_seqs(&v, HeldSelect::Every, after, 1);
            assert_eq!(next, ids_next);
            assert_eq!(page.len(), 1);
            assert_eq!(next.is_some(), tasks.len() < 3);
            if let Some(n) = next {
                assert_eq!(n, page[0].seq);
            }
            tasks.extend(page.iter().map(|h| h.view.task.clone()));
            seqs.extend(ids.iter().map(|(_, t)| *t));
            match next {
                Some(n) => after = Some(n),
                None => break,
            }
        }
        assert_eq!(seqs, vec![t1, g, t2, u]);
        assert_eq!(
            tasks,
            [t1, g, t2, u]
                .iter()
                .map(maknae_proto::TaskRef::from_id)
                .collect::<Vec<_>>()
        );
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
        let working = held_by(&store, Tasker::Uid(1000));
        store.start_for_test(&working);
        let unparented = |task, why| Due {
            task,
            agent: id("hobi"),
            tasker: Tasker::Uid(1000),
            parent: None,
            why,
            recorded: false,
        };
        assert_eq!(
            store.perform(&[
                unparented(working, DueFor::Close(TaskClose::ParentEnded)),
                unparented(reported, DueFor::Orphaned),
            ]),
            0,
            "neither has a parent that ended"
        );
        assert_eq!(closed(&store, &working), None);
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
                DueFor::Expiry | DueFor::Hold(_) | DueFor::Orphaned => None,
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
            store.report(&task, &id("hobi"), HOBI, text("late"), None),
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
            store.report(&task, &id("hobi"), HOBI, text("late"), None),
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
        for (cites, fresh_now) in [(false, true), (true, true), (false, false)] {
            match claim_head(&store, &hobi, HOBI, signer()).unwrap() {
                Claimed::Delivered {
                    signed,
                    partition,
                    fresh,
                } => {
                    assert_eq!(signed.task.task_id, first);
                    assert_eq!(partition, "tasks/users/1000");
                    assert_eq!(fresh, fresh_now);
                }
                Claimed::Idle => panic!("idle"),
            }
            if cites {
                cite(&store, &first);
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
            store.report(&task, &hobi, HOBI, text("r"), None),
            Err(TaskRefusal::NotWorking)
        );
        store.start_for_test(&task);
        cite(&store, &task);
        assert_eq!(
            store.report(&task, &id("jin"), HOBI, text("r"), None),
            Err(TaskRefusal::OtherAgent)
        );
        assert_eq!(
            store.report(&task, &hobi, JIN, text("r"), None),
            Err(TaskRefusal::OtherAgent)
        );
        let view = store.report(&task, &hobi, HOBI, text("r"), None).unwrap();
        assert_eq!((view.state, view.actions), (TaskState::Reported, 1));
        assert_eq!(store.record(&task).unwrap().actions, 1);
        assert_eq!(
            store.report(&task, &hobi, HOBI, text("again"), None),
            Err(TaskRefusal::NotWorking)
        );
        cite(&store, &task);
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
        cite(&store, &task);
        cite(&store, &idle);
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
                items: Vec::new(),
                addendum: None,
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
            Heartbeat::FollowUps { items, .. } => items
                .iter()
                .map(|i| i.expose().to_string())
                .collect::<Vec<_>>(),
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
        fn sign_addendum(
            &self,
            addendum: maknae_proto::TaskAddendum,
        ) -> Result<maknae_proto::SignedAddendum, TaskRefusal> {
            self.0.sign_addendum(addendum)
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
            .mint(
                signer(),
                &v,
                enrolled,
                Tasker::Uid(1000),
                None,
                sub("hobi"),
                Vec::new(),
            )
            .unwrap()
            .task
            .task_id;
        blobs.fail(Some(crate::task_store::Fail::Unsynced));
        assert!(matches!(
            store.confirm(&task, None, Confirm::Queued),
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
            .mint(
                signer(),
                &v,
                enrolled,
                Tasker::Uid(1000),
                None,
                sub("hobi"),
                Vec::new(),
            )
            .unwrap()
            .task
            .task_id;
        blobs.after_save(|| panic!("sentinel-628-confirm-panic"));
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.confirm(&task, None, Confirm::Queued)
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
            .mint(
                signer(),
                &v,
                enrolled,
                Tasker::Uid(1000),
                None,
                sub("hobi"),
                Vec::new(),
            )
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
            verb: maknae_proto::Verb::TaskSubmit {
                task: sub("hobi"),
                forge_tokens: maknae_proto::ForgeTokens::default(),
            },
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

    const FORGE_HOST: &str = "git.sentinel-168a.example";
    const REPO: &str = "sentinel-168a/alpha";

    fn forges_of(hosts: &[&str]) -> maknae_config::ForgeSet {
        let yaml: String = hosts
            .iter()
            .enumerate()
            .map(|(i, h)| {
                format!("- {{ name: sentinel-168a-forge{i}, kind: git, host: \"{h}\", provider: gitlab }}\n")
            })
            .collect();
        if yaml.is_empty() {
            return maknae_config::ForgeSet::empty();
        }
        maknae_config::forges_from_section(Some(&maknae_config::load_str(&yaml).unwrap())).unwrap()
    }

    fn git(server: &str, base: &str, change: Option<u64>) -> maknae_proto::BindingRequest {
        maknae_proto::BindingRequest::Git(maknae_proto::GitRef {
            server: server.into(),
            base: base.into(),
            change,
        })
    }

    fn sealed(server: &str, base: &str, head: Option<&str>, change: Option<u64>) -> Binding {
        Binding::Git(maknae_proto::GitBinding {
            server: server.into(),
            base: base.into(),
            head: head.map(Into::into),
            change,
        })
    }

    fn bound(agent: &str, asked: Vec<maknae_proto::BindingRequest>) -> TaskSubmission {
        TaskSubmission {
            bindings: asked,
            ..sub(agent)
        }
    }

    async fn submit_bound(
        pdp: &Pdp,
        store: &Arc<TaskStore>,
        by: Submitter,
        sub: TaskSubmission,
        forges: &maknae_config::ForgeSet,
        emit: &Recorder,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let view = SnapshotEnrollment(pdp.clone());
        submit_in(
            pdp.clone(),
            store,
            &view,
            by,
            sub,
            emit,
            (BOUND, None),
            forges,
        )
        .await
    }

    /// A refused submission stores nothing and its trail record denies, naming `named`.
    fn refused_naming(
        got: Result<Arc<SignedTask>, TaskRefusal>,
        named: &str,
        store: &TaskStore,
        held: usize,
        emit: &Recorder,
    ) {
        let Err(TaskRefusal::Unbound(why)) = &got else {
            panic!("expected an unbound refusal, got {got:?}");
        };
        assert!(why.contains(named), "{why}");
        assert_eq!(store.len(), held);
        let last = emit.records().pop().unwrap();
        assert_eq!(last.outcome.result, "deny");
        assert!(
            last.outcome.reason.contains(named),
            "{}",
            last.outcome.reason
        );
    }

    /// A working task of hobi's, tasked by this uid, holding exactly `bindings`, each sealed
    /// with the reach a binding without a reach check gets.
    fn bound_parent(pdp: &Pdp, store: &Arc<TaskStore>, bindings: Vec<Binding>) -> Arc<SignedTask> {
        let reach = bindings
            .iter()
            .map(|_| {
                maknae_proto::BindingReach::Git(maknae_proto::GitReach {
                    tasker: maknae_proto::SideReach::EMPTY,
                    basis: maknae_proto::TaskerBasis::Token,
                    agent: maknae_proto::AgentReach::NoForgeCredential,
                    why: Some(maknae_proto::EmptyReason::NoReachCheck),
                })
            })
            .collect();
        reached_parent(pdp, store, bindings, reach)
    }

    /// A working task of hobi's, tasked by this uid, sealed with exactly `bindings` and `reach`.
    fn reached_parent(
        pdp: &Pdp,
        store: &Arc<TaskStore>,
        bindings: Vec<Binding>,
        reach: Vec<maknae_proto::BindingReach>,
    ) -> Arc<SignedTask> {
        let parent = queued_for_hobi(pdp, store, bindings, reach);
        store.start_for_test(&parent.task.task_id);
        parent
    }

    fn queued_for_hobi(
        pdp: &Pdp,
        store: &Arc<TaskStore>,
        bindings: Vec<Binding>,
        reach: Vec<maknae_proto::BindingReach>,
    ) -> Arc<SignedTask> {
        let v = SnapshotEnrollment(pdp.clone());
        let parent = store
            .mint_with(
                &mut draw_id,
                signer(),
                &v,
                at(store.generation(&id("hobi")), HOBI),
                Tasker::Uid(me()),
                None,
                sub("hobi"),
                (bindings, reach),
                None,
            )
            .unwrap();
        store
            .confirm(&parent.task.task_id, None, Confirm::Queued)
            .unwrap();
        parent
    }

    #[tokio::test]
    async fn a_binding_to_a_host_not_in_forges_is_refused_naming_it() {
        let (_g, pdp) = pdp("unbound-host");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let stranger = "git.stranger-168a.example";
        for (forges, named) in [
            (forges_of(&[FORGE_HOST]), stranger),
            (forges_of(&[]), FORGE_HOST),
        ] {
            let got = submit_bound(
                &pdp,
                &store,
                user(),
                bound(
                    "hobi",
                    vec![git(FORGE_HOST, REPO, None), git(stranger, REPO, Some(1))],
                ),
                &forges,
                &emit,
            )
            .await;
            refused_naming(got, named, &store, 0, &emit);
        }
        submit_bound(
            &pdp,
            &store,
            user(),
            bound("hobi", vec![git(FORGE_HOST, REPO, None)]),
            &forges_of(&[FORGE_HOST]),
            &emit,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn an_unauthorized_subject_with_a_bad_binding_gets_the_pdp_deny() {
        let (_g, pdp) = pdp("unbound-unauthorized");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let stranger = "git.stranger-168a-deny.example";
        let got = submit_bound(
            &pdp,
            &store,
            user(),
            bound("jin", vec![git(stranger, REPO, Some(1))]),
            &forges_of(&[FORGE_HOST]),
            &emit,
        )
        .await;
        let why = format!("agent jin: uid {} is not a tasker", me());
        assert_eq!(got.unwrap_err(), TaskRefusal::Denied(why.clone()));
        assert_eq!(store.len(), 0);
        let r = emit.records().pop().unwrap();
        assert_eq!(r.outcome.result, "deny");
        assert_eq!(r.outcome.reason, why);
        assert_eq!(r.subject.role.as_deref(), Some("user"));
        assert!(!maknae_audit_append::canonical_json(&r)
            .unwrap()
            .contains(stranger));
    }

    #[tokio::test]
    async fn a_forge_name_is_not_a_server() {
        let (_g, pdp) = pdp("forge-name");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let forges = forges_of(&[FORGE_HOST]);
        assert!(forges.get("sentinel-168a-forge0").is_some());
        let got = submit_bound(
            &pdp,
            &store,
            user(),
            bound("hobi", vec![git("sentinel-168a-forge0", REPO, None)]),
            &forges,
            &emit,
        )
        .await;
        refused_naming(got, "sentinel-168a-forge0", &store, 0, &emit);
    }

    #[tokio::test]
    async fn a_forge_host_with_another_port_is_not_that_forge() {
        let (_g, pdp) = pdp("forge-port");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let ported = format!("{FORGE_HOST}:8443");
        for (forge, asked) in [
            (ported.as_str(), FORGE_HOST.to_owned()),
            (FORGE_HOST, format!("{FORGE_HOST}:443")),
            (ported.as_str(), format!("{FORGE_HOST}:443")),
        ] {
            let got = submit_bound(
                &pdp,
                &store,
                user(),
                bound("hobi", vec![git(&asked, REPO, None)]),
                &forges_of(&[forge]),
                &emit,
            )
            .await;
            refused_naming(got, &asked, &store, 0, &emit);
        }
        let task = submit_bound(
            &pdp,
            &store,
            user(),
            bound("hobi", vec![git(&ported, REPO, None)]),
            &forges_of(&[&ported]),
            &emit,
        )
        .await
        .unwrap();
        assert_eq!(task.task.bindings, vec![sealed(&ported, REPO, None, None)]);
    }

    #[tokio::test]
    async fn the_sealed_binding_has_no_head() {
        let (_g, pdp) = pdp("no-head");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let task = submit_bound(
            &pdp,
            &store,
            user(),
            bound(
                "hobi",
                vec![
                    git(FORGE_HOST, REPO, Some(7)),
                    git(FORGE_HOST, "sentinel-168a/beta", None),
                ],
            ),
            &forges_of(&[FORGE_HOST]),
            &emit,
        )
        .await
        .unwrap();
        let want = vec![
            sealed(FORGE_HOST, REPO, None, Some(7)),
            sealed(FORGE_HOST, "sentinel-168a/beta", None, None),
        ];
        assert_eq!(task.task.bindings, want);
        assert_eq!(signer().verify(&task), Ok(()));
        let stored = store.record(&task.task.task_id).unwrap();
        assert_eq!(stored.signed.task.bindings, want);
    }

    #[test]
    fn mint_seals_only_what_intake_passed() {
        let store = TaskStore::new();
        let v = view(&[("hobi", HOBI)]);
        let asked = bound("hobi", vec![git(FORGE_HOST, REPO, Some(1))]);
        let passed = vec![sealed(FORGE_HOST, "sentinel-168a/beta", None, Some(2))];
        let task = store
            .mint_live(
                signer(),
                &v,
                at(0, HOBI),
                Tasker::Uid(1000),
                None,
                asked.clone(),
                passed.clone(),
            )
            .unwrap();
        assert_eq!(task.task.bindings, passed);
        let task = store
            .mint_live(
                signer(),
                &v,
                at(0, HOBI),
                Tasker::Uid(1000),
                None,
                asked,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(task.task.bindings, Vec::new());
    }

    #[tokio::test]
    async fn a_sub_task_binding_its_parent_holds_is_copied_from_the_parent() {
        let (_g, pdp) = pdp("sub-copied");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let held = sealed(FORGE_HOST, REPO, Some("sentinel-168a-fork/alpha"), Some(1));
        let other = sealed(FORGE_HOST, "sentinel-168a/beta", None, None);
        let parent = bound_parent(&pdp, &store, vec![other, held.clone()]);
        let child = submit_bound(
            &pdp,
            &store,
            agent("hobi", HOBI, Some(parent.task.task_id)),
            bound("jin", vec![git(FORGE_HOST, REPO, Some(1))]),
            &forges_of(&[FORGE_HOST]),
            &emit,
        )
        .await
        .unwrap();
        assert_eq!(child.task.bindings, vec![held]);
    }

    #[tokio::test]
    async fn a_sub_task_binding_its_parent_lacks_is_refused() {
        let (_g, pdp) = pdp("sub-lacks");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let parent = bound_parent(&pdp, &store, vec![sealed(FORGE_HOST, REPO, None, Some(1))]);
        let under = || agent("hobi", HOBI, Some(parent.task.task_id));
        for asked in [
            vec![git(FORGE_HOST, REPO, Some(2))],
            vec![
                git(FORGE_HOST, REPO, Some(1)),
                git(FORGE_HOST, REPO, Some(2)),
            ],
            vec![git(FORGE_HOST, "sentinel-168a/beta", Some(1))],
            vec![git("git.other-168a.example", REPO, Some(1))],
        ] {
            let got = submit_bound(
                &pdp,
                &store,
                under(),
                bound("jin", asked),
                &forges_of(&[FORGE_HOST, "git.other-168a.example"]),
                &emit,
            )
            .await;
            refused_naming(got, "parent", &store, 1, &emit);
        }
        let none = submit_bound(
            &pdp,
            &store,
            under(),
            sub("jin"),
            &forges_of(&[FORGE_HOST]),
            &emit,
        )
        .await
        .unwrap();
        assert_eq!(none.task.bindings, Vec::new());
    }

    #[tokio::test]
    async fn a_repository_binding_does_not_match_a_parent_change_binding() {
        let (_g, pdp) = pdp("sub-repo");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let parent = bound_parent(&pdp, &store, vec![sealed(FORGE_HOST, REPO, None, Some(1))]);
        let got = submit_bound(
            &pdp,
            &store,
            agent("hobi", HOBI, Some(parent.task.task_id)),
            bound("jin", vec![git(FORGE_HOST, REPO, None)]),
            &forges_of(&[FORGE_HOST]),
            &emit,
        )
        .await;
        refused_naming(got, REPO, &store, 1, &emit);
    }

    #[tokio::test]
    async fn a_parent_binding_whose_host_left_forges_is_refused_for_the_sub_task() {
        let (_g, pdp) = pdp("sub-host-left");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let parent = bound_parent(&pdp, &store, vec![sealed(FORGE_HOST, REPO, None, Some(1))]);
        let under = || agent("hobi", HOBI, Some(parent.task.task_id));
        let asked = || bound("jin", vec![git(FORGE_HOST, REPO, Some(1))]);
        for forges in [forges_of(&["git.other-168a.example"]), forges_of(&[])] {
            let got = submit_bound(&pdp, &store, under(), asked(), &forges, &emit).await;
            refused_naming(got, FORGE_HOST, &store, 1, &emit);
        }
        submit_bound(
            &pdp,
            &store,
            under(),
            asked(),
            &forges_of(&[FORGE_HOST]),
            &emit,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn an_own_initiative_agent_task_passes_the_persons_intake() {
        let (_g, pdp) = pdp("own-initiative-bound");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let forges = forges_of(&[FORGE_HOST]);
        let stranger = "git.stranger-168a.example";
        let got = submit_bound(
            &pdp,
            &store,
            agent("hobi", HOBI, None),
            bound("jin", vec![git(stranger, REPO, Some(1))]),
            &forges,
            &emit,
        )
        .await;
        refused_naming(got, stranger, &store, 0, &emit);
        let task = submit_bound(
            &pdp,
            &store,
            agent("hobi", HOBI, None),
            bound("jin", vec![git(FORGE_HOST, REPO, Some(1))]),
            &forges,
            &emit,
        )
        .await
        .unwrap();
        assert_eq!(task.task.parent, None);
        assert_eq!(
            task.task.bindings,
            vec![sealed(FORGE_HOST, REPO, None, Some(1))]
        );
    }

    #[test]
    fn a_remote_tasker_with_a_binding_is_refused() {
        let remote = Tasker::Remote("site-b/ops".into());
        let forges = forges_of(&[FORGE_HOST]);
        let got = seal_bindings(&remote, None, &[git(FORGE_HOST, REPO, Some(1))], &forges);
        assert!(matches!(got, Err(TaskRefusal::Unbound(_))), "{got:?}");
        assert_eq!(seal_bindings(&remote, None, &[], &forges), Ok(Vec::new()));
        assert_eq!(
            seal_bindings(
                &Tasker::Uid(1000),
                None,
                &[git(FORGE_HOST, REPO, Some(1))],
                &forges
            ),
            Ok(vec![sealed(FORGE_HOST, REPO, None, Some(1))])
        );
    }

    #[tokio::test]
    async fn the_task_view_carries_the_sealed_bindings() {
        let (_g, pdp) = pdp("view-bound");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let task = submit_bound(
            &pdp,
            &store,
            user(),
            bound("hobi", vec![git(FORGE_HOST, REPO, Some(3))]),
            &forges_of(&[FORGE_HOST]),
            &emit,
        )
        .await
        .unwrap();
        let want = vec![sealed(FORGE_HOST, REPO, None, Some(3))];
        let me = Tasker::Uid(me());
        assert_eq!(
            store.status(&task.task.task_id, &me).unwrap().bindings,
            want
        );
        assert_eq!(store.list(&me, &id("hobi"), None, 8).0[0].bindings, want);
    }

    fn recorded(
        server: &str,
        base: &str,
        head: Option<&str>,
        change: Option<u64>,
    ) -> maknae_audit_append::RecordBinding {
        maknae_audit_append::RecordBinding {
            kind: maknae_audit_append::BindingKind::Git,
            server: server.into(),
            base: base.into(),
            head: head.map(Into::into),
            change,
        }
    }

    #[tokio::test]
    async fn the_submission_records_carry_the_sealed_bindings() {
        let (_g, pdp) = pdp("records-bound");
        let store = Arc::new(TaskStore::new());
        let emit = Recorder::new();
        let fork = "sentinel-168c-fork/alpha";
        let parent = bound_parent(
            &pdp,
            &store,
            vec![sealed(FORGE_HOST, REPO, Some(fork), Some(1))],
        );
        let child = submit_bound(
            &pdp,
            &store,
            agent("hobi", HOBI, Some(parent.task.task_id)),
            bound("jin", vec![git(FORGE_HOST, REPO, Some(1))]),
            &forges_of(&[FORGE_HOST]),
            &emit,
        )
        .await
        .unwrap();
        let want = vec![recorded(FORGE_HOST, REPO, Some(fork), Some(1))];
        let stored = emit.records().pop().unwrap();
        assert_eq!(stored.outcome.reason, "task stored");
        assert_eq!(stored.subject.bindings, want);
        let mut base = stored.clone();
        base.subject.bindings.clear();
        for said in ["task queued", "task held"] {
            base.outcome.reason = said.into();
            let rec = crate::run::submit_outcome_record(base.clone(), &child.task);
            assert_eq!(rec.subject.bindings, want, "{said}");
        }

        let store = Arc::new(TaskStore::new());
        let emit = ContainsOnAudit(Recorder::new(), Arc::clone(&store), false);
        let view = SnapshotEnrollment(pdp.clone());
        submit_in(
            pdp.clone(),
            &store,
            &view,
            user(),
            bound("hobi", vec![git(FORGE_HOST, REPO, Some(7))]),
            &emit,
            (BOUND, None),
            &forges_of(&[FORGE_HOST]),
        )
        .await
        .unwrap();
        let trail = emit.0.records();
        let said: Vec<&str> = trail.iter().map(|r| r.outcome.reason.as_str()).collect();
        assert_eq!(said, ["task stored", "task held: tasker contained"]);
        for rec in &trail {
            assert_eq!(
                rec.subject.bindings,
                vec![recorded(FORGE_HOST, REPO, None, Some(7))],
                "{}",
                rec.outcome.reason
            );
        }

        let refused = Recorder::new();
        let got = submit_bound(
            &pdp,
            &store,
            user(),
            bound("hobi", vec![git("git.stranger-168c.example", REPO, None)]),
            &forges_of(&[FORGE_HOST]),
            &refused,
        )
        .await;
        assert!(matches!(got, Err(TaskRefusal::Unbound(_))), "{got:?}");
        assert!(refused.records().pop().unwrap().subject.bindings.is_empty());
    }

    /// Eight requests on [`FORGE_HOST`] whose request form encodes to exactly `total`.
    fn requests_of_len(total: usize) -> Vec<maknae_proto::BindingRequest> {
        let mut bases: Vec<String> = (0..maknae_proto::TASK_BINDINGS_MAX)
            .map(|i| format!("sentinel-168a/bound-{i}-padding-xxxx"))
            .collect();
        let of = |bases: &[String]| -> Vec<maknae_proto::BindingRequest> {
            bases
                .iter()
                .enumerate()
                .map(|(i, b)| git(FORGE_HOST, b, Some(i as u64 + 1)))
                .collect()
        };
        let mut at = 0;
        while maknae_proto::bindings_encoded_len(&of(&bases)) < total {
            if bases[at].len() == maknae_proto::REPOSITORY_PATH_MAX_BYTES {
                at += 1;
            }
            bases[at].push('x');
        }
        let asked = of(&bases);
        assert_eq!(maknae_proto::bindings_encoded_len(&asked), total);
        asked
    }

    #[tokio::test]
    async fn a_submission_at_the_byte_bound_survives_sealing_delivery_and_reload() {
        let (_g, pdp) = pdp("byte-bound");
        let (blobs, store) = mem();
        let store = Arc::new(store);
        let emit = Recorder::new();
        let asked = bound(
            "hobi",
            requests_of_len(maknae_proto::TASK_BINDING_REQUESTS_MAX_BYTES),
        );
        let mut wire = Vec::new();
        ciborium::into_writer(&asked, &mut wire).unwrap();
        let decoded: TaskSubmission = ciborium::from_reader(wire.as_slice()).unwrap();
        assert_eq!(decoded, asked, "the submission decodes at its bound");
        let task = submit_bound(
            &pdp,
            &store,
            user(),
            asked,
            &forges_of(&[FORGE_HOST]),
            &emit,
        )
        .await
        .unwrap();
        let id_ = task.task.task_id;
        let sealed = maknae_proto::bindings_encoded_len(&task.task.bindings);
        assert_eq!(
            sealed,
            maknae_proto::TASK_BINDING_REQUESTS_MAX_BYTES + 6 * maknae_proto::TASK_BINDINGS_MAX
        );
        assert!(sealed <= maknae_proto::TASK_BINDINGS_MAX_BYTES, "{sealed}");
        let me = Tasker::Uid(me());
        let accepted = store.status(&id_, &me).unwrap();
        let body = maknae_proto::encode_response(&maknae_proto::Response::new(
            maknae_proto::PROTOCOL_VERSION,
            maknae_proto::RespResult::Ok(maknae_proto::Payload::TaskAccepted(accepted.clone())),
            None,
        ))
        .unwrap();
        assert_eq!(
            maknae_proto::decode_response(&body).unwrap().result,
            maknae_proto::RespResult::Ok(maknae_proto::Payload::TaskAccepted(accepted))
        );
        let Ok(Claimed::Delivered { signed, .. }) = claim_head(&store, &id("hobi"), HOBI, signer())
        else {
            panic!("the bound task is delivered");
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&*signed, &mut bytes).unwrap();
        let delivered: SignedTask = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(delivered.task.bindings, task.task.bindings);
        assert_eq!(signer().verify(&delivered), Ok(()));
        let again = reopen(&blobs);
        assert_eq!(again.take_boot_findings(), Vec::new());
        assert_eq!(
            again.record(&id_).unwrap().signed.task.bindings,
            task.task.bindings
        );
    }

    #[test]
    fn a_sealed_list_over_its_byte_bound_is_refused() {
        let forges = forges_of(&[FORGE_HOST]);
        let held: Vec<Binding> = requests_of_len(maknae_proto::TASK_BINDING_REQUESTS_MAX_BYTES)
            .into_iter()
            .map(|maknae_proto::BindingRequest::Git(r)| {
                Binding::Git(maknae_proto::GitBinding {
                    head: Some(
                        "h/".to_owned()
                            + &"x".repeat(
                                (maknae_proto::TASK_BINDINGS_MAX_BYTES
                                    - maknae_proto::TASK_BINDING_REQUESTS_MAX_BYTES)
                                    / maknae_proto::TASK_BINDINGS_MAX,
                            ),
                    ),
                    server: r.server,
                    base: r.base,
                    change: r.change,
                })
            })
            .collect();
        assert!(maknae_proto::bindings_encoded_len(&held) > maknae_proto::TASK_BINDINGS_MAX_BYTES);
        let parent = TaskObject {
            bindings: held.clone(),
            ..TaskObject::for_test("hobi", 1000)
        };
        let asked: Vec<_> = held
            .iter()
            .map(|Binding::Git(g)| git(&g.server, &g.base, g.change))
            .collect();
        let tasker = Tasker::Agent {
            agent: "hobi".into(),
            uid: HOBI,
        };
        let parent = crate::reach::TaskBound::of(&parent, None);
        let got = seal_bindings(&tasker, Some(&parent), &asked, &forges);
        assert!(matches!(got, Err(TaskRefusal::Unbound(_))), "{got:?}");
        assert_eq!(
            seal_bindings(&tasker, Some(&parent), &asked[..1], &forges),
            Ok(held[..1].to_vec())
        );
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
            forges: &maknae_config::ForgeSet::empty(),
            reach: unreachable(),
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
            (sub("jin"), maknae_proto::ForgeTokens::default()),
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
            forges: &maknae_config::ForgeSet::empty(),
            reach: unreachable(),
        };
        let view: Arc<dyn EnrollmentView> = Arc::new(SnapshotEnrollment(pdp.clone()));
        submit_task(
            pdp.clone(),
            &store,
            &shared_signer(),
            &view,
            &ctx,
            user(),
            (sub("hobi"), maknae_proto::ForgeTokens::default()),
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
                maknae_io::MaknaeSecret::new(maknae_io::Zeroizing::new(
                    secret_id.trim().to_string(),
                ))
                .unwrap(),
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
        let busy = format!("not done: {BUSY}");
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
        let unsynced = "outcome unknown: sentinel-632-unsynced".to_string();
        assert_eq!(
            said(true, &unsynced).await,
            (TaskRefusal::Unavailable(unsynced.clone()), unsynced)
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
        let drawn = std::cell::Cell::new(0u32);
        let mut draw = || {
            drawn.set(drawn.get() + 1);
            match drawn.get() {
                1..=5 => Ok([7u8; 16]),
                _ => Err(TaskRefusal::Unknown),
            }
        };
        let mint = |draw: &mut dyn FnMut() -> Result<[u8; 16], TaskRefusal>| {
            store.mint_with_live(
                draw,
                signer(),
                &v,
                at(0, HOBI),
                Tasker::Uid(1),
                None,
                sub("hobi"),
                Vec::new(),
            )
        };
        assert!(mint(&mut draw).is_ok());
        assert_eq!(mint(&mut draw).err(), Some(TaskRefusal::Random));
        assert_eq!(drawn.get(), 5, "no id is drawn after the last attempt");
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

    mod reach_intake {
        use super::*;
        use crate::egress_socket::{ReachEgress, SocketEgress};
        use maknae_proto::{
            AgentReach, BindingReach, EgressFrame, EgressSocketReply, EmptyReason, ForgeOp,
            ForgeOps, ForgeTokens, GitReach, Observations, ReachRefusal, ReachReply, ReachRequest,
            ReachSide, RepoObservation, SealedForgeToken, SealedKey, SideReach, TaskerBasis,
        };
        use std::io::{Read, Write};
        use std::time::Duration;

        const HOST: &str = "git.sentinel-168c.example";
        const LAB: &str = "lab.sentinel-168c.example";
        const BASE: &str = "sentinel-168c/alpha";
        const FORK: &str = "sentinel-168c-fork/alpha";
        const PREFIX: &str = "maknae/users";
        const NONCE: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
        fn sealed_token() -> Vec<u8> {
            b"sentinel-168c-sealed-forge-token-".repeat(5)
        }
        const APP: &str = "maknae-github-read";
        const GRANT: &str = "Tool(github-read gh:pr.view)";

        type Answer = Box<dyn Fn(&ReachRequest) -> (Duration, Option<EgressSocketReply>) + Send>;

        /// The Egress Daemon's socket: each connection's reach frame, answered by `answer`.
        struct Stub {
            egress: Arc<dyn ReachEgress>,
            seen: Arc<Mutex<Vec<ReachRequest>>>,
            _dir: tempfile::TempDir,
        }

        impl Stub {
            fn new(answer: Answer) -> Self {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("egress.sock");
                let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
                let seen: Arc<Mutex<Vec<ReachRequest>>> = Arc::default();
                let kept = Arc::clone(&seen);
                std::thread::spawn(move || {
                    for conn in listener.incoming() {
                        let Ok(mut c) = conn else { return };
                        let mut len = [0u8; 4];
                        if c.read_exact(&mut len).is_err() {
                            continue;
                        }
                        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                        if c.read_exact(&mut body).is_err() {
                            continue;
                        }
                        let Ok(EgressFrame::Reach(req)) = maknae_proto::decode_egress_frame(&body)
                        else {
                            continue;
                        };
                        let (delay, reply) = answer(&req);
                        kept.lock().unwrap().push(req);
                        std::thread::sleep(delay);
                        if let Some(reply) = reply {
                            let mut out = Vec::new();
                            ciborium::into_writer(&reply, &mut out).unwrap();
                            let _ = c.write_all(&(out.len() as u32).to_be_bytes());
                            let _ = c.write_all(&out);
                        }
                    }
                });
                let egress: Arc<dyn ReachEgress> = Arc::new(SocketEgress::new(
                    path,
                    me(),
                    Duration::from_secs(5),
                    64 * 1024,
                ));
                Self {
                    egress,
                    seen,
                    _dir: dir,
                }
            }

            /// Answers the tasker side with `tasker` and every agent with `agent`.
            fn sides(tasker: ReachReply, agent: ReachReply) -> Self {
                let cbor = |r: ReachReply| {
                    let mut out = Vec::new();
                    ciborium::into_writer(&EgressSocketReply::Reach(r), &mut out).unwrap();
                    out
                };
                let (tasker, agent) = (cbor(tasker), cbor(agent));
                Self::new(Box::new(move |req| {
                    let reply = match req.side() {
                        ReachSide::Tasker { .. } => &tasker,
                        ReachSide::Agent { .. } => &agent,
                    };
                    (
                        Duration::ZERO,
                        Some(ciborium::from_reader(&reply[..]).unwrap()),
                    )
                }))
            }

            fn frames(&self) -> usize {
                self.seen.lock().unwrap().len()
            }

            fn side(&self, at: usize) -> String {
                match self.seen.lock().unwrap()[at].side() {
                    ReachSide::Tasker { tasker, .. } => format!("tasker {tasker}"),
                    ReachSide::Agent { agent, .. } => format!("agent {agent}"),
                }
            }
        }

        fn ops(list: &[ForgeOp]) -> ForgeOps {
            list.iter().copied().collect()
        }

        fn seen(
            base: &[ForgeOp],
            head: Option<(&str, &[ForgeOp])>,
            covered: bool,
        ) -> RepoObservation {
            RepoObservation::new(
                ops(base),
                head.map(|(h, _)| h.to_owned()),
                head.map_or(ForgeOps::EMPTY, |(_, o)| ops(o)),
                false,
                covered,
            )
            .unwrap()
        }

        fn observed(list: Vec<RepoObservation>) -> ReachReply {
            ReachReply::Observed(Observations::new(list).unwrap())
        }

        const WRITE: &[ForgeOp] = &[
            ForgeOp::Read,
            ForgeOp::Review,
            ForgeOp::IssueWrite,
            ForgeOp::Merge,
        ];
        const READ: &[ForgeOp] = &[ForgeOp::Read, ForgeOp::Review];

        fn forges(entries: &[(&str, &str)]) -> maknae_config::ForgeSet {
            let yaml: String = entries
                .iter()
                .enumerate()
                .map(|(i, (h, p))| {
                    format!("- {{ name: sentinel-168c-forge{i}, kind: git, host: \"{h}\", provider: {p} }}\n")
                })
                .collect();
            maknae_config::forges_from_section(Some(&maknae_config::load_str(&yaml).unwrap()))
                .unwrap()
        }

        fn github() -> maknae_config::ForgeSet {
            forges(&[(HOST, "github"), (LAB, "gitlab")])
        }

        /// `pdp`'s agents, with hobi and jin granted the homelab `github-read` entry.
        fn reach_pdp(tag: &str) -> (DirGuard, Pdp) {
            let (g, pdp) = pdp(&format!("reach-{tag}"));
            crate::test_fixtures::write_tools(
                &g.0,
                include_str!("../../../packaging/common/tools-homelab.yaml"),
            );
            crate::test_fixtures::write_shipped_gh_grammar(&g.0);
            let site = format!(
                "schema_version: 1\npermissions:\n  allow: [\"{GRANT}\"]\n  deny: []\nroles:\n  user:\n    allow: [\"session.task\"]\n"
            );
            std::fs::write(&maknae_authz_basic::PolicyPaths::in_dir(&g.0).authz, site).unwrap();
            crate::test_fixtures::write_agent_policy(
                &g.0,
                "hobi",
                &format!("schema_version: 1\npermissions:\n  allow: [\"{GRANT}\"]\n"),
            );
            crate::test_fixtures::write_agent_policy(
                &g.0,
                "jin",
                &format!("schema_version: 1\ntaskers: [\"agent:hobi\", \"agent:suga\"]\npermissions:\n  allow: [\"{GRANT}\"]\n"),
            );
            pdp.baseline().reload_from_file().unwrap();
            let app = maknae_proto::CredentialRef {
                kind: "github-app-installation".into(),
                name: APP.into(),
            };
            assert_eq!(
                crate::CatalogNow::forge_credentials(&*pdp, HOBI),
                std::slice::from_ref(&app)
            );
            assert_eq!(crate::CatalogNow::forge_credentials(&*pdp, JIN), [app]);
            (g, pdp)
        }

        fn token(server: &str) -> ForgeTokens {
            ForgeTokens::new(vec![SealedForgeToken::new(
                server.into(),
                NONCE.into(),
                SealedKey::new(sealed_token()).unwrap(),
            )
            .unwrap()])
            .unwrap()
        }

        fn change(server: &str, base: &str, change: Option<u64>) -> maknae_proto::BindingRequest {
            maknae_proto::BindingRequest::Git(maknae_proto::GitRef {
                server: server.into(),
                base: base.into(),
                change,
            })
        }

        fn asking(agent: &str, bindings: Vec<maknae_proto::BindingRequest>) -> TaskSubmission {
            TaskSubmission {
                bindings,
                ..sub(agent)
            }
        }

        struct Reaching<'a> {
            pdp: &'a Pdp,
            stub: &'a Stub,
            forges: maknae_config::ForgeSet,
            deadline_ms: u64,
            permits: tokio::sync::Semaphore,
            decide_timeout: Duration,
            view: Arc<dyn EnrollmentView>,
        }

        impl<'a> Reaching<'a> {
            fn new(pdp: &'a Pdp, stub: &'a Stub) -> Self {
                Self {
                    pdp,
                    stub,
                    forges: github(),
                    deadline_ms: 5_000,
                    permits: tokio::sync::Semaphore::new(maknae_config::REACH_CONCURRENCY_MAX),
                    decide_timeout: BOUND,
                    view: Arc::new(SnapshotEnrollment(Arc::clone(pdp))),
                }
            }

            async fn submit(
                &self,
                store: &Arc<TaskStore>,
                by: Submitter,
                (sub, tokens): (TaskSubmission, ForgeTokens),
                emit: &impl AuditEmit,
            ) -> Result<Arc<SignedTask>, TaskRefusal> {
                let w = wctx();
                let seq = maknae_audit_append::Seq::new();
                let settings = crate::reach::ReachSettings::of(
                    &self.forges,
                    Some(PREFIX.into()),
                    self.deadline_ms,
                );
                let pdp = Arc::clone(self.pdp);
                let credentials = move |uid| crate::CatalogNow::forge_credentials(&*pdp, uid);
                let ctx = SubmitCtx {
                    where_: &w,
                    session_id: SESSION,
                    seq: &seq,
                    user: Some(ACCOUNT),
                    peer_uri: None,
                    lane: maknae_security::Lane::Local,
                    decide_timeout: self.decide_timeout,
                    text_max: 1 << 20,
                    forges: &self.forges,
                    reach: crate::reach::ReachCtx {
                        egress: &self.stub.egress,
                        settings: &settings,
                        permits: &self.permits,
                        credentials: &credentials,
                    },
                };
                let pdp = Decider {
                    authorizer: Arc::clone(self.pdp),
                    breaker: Breaker::default(),
                };
                let view = Arc::clone(&self.view);
                submit_under(
                    pdp,
                    store,
                    &shared_signer(),
                    &view,
                    &ctx,
                    by,
                    (sub, tokens),
                    emit,
                )
                .await
            }
        }

        type Added = Result<(TaskView, Vec<Binding>, Vec<BindingReach>), TaskRefusal>;

        impl Reaching<'_> {
            async fn add(
                &self,
                store: &Arc<TaskStore>,
                (id, caller, under, uid): (TaskId, Tasker, Option<TaskId>, u32),
                text: &str,
                (asked, tokens): (Vec<maknae_proto::BindingRequest>, ForgeTokens),
                emit: &impl AuditEmit,
            ) -> Added {
                let w = wctx();
                let settings = crate::reach::ReachSettings::of(
                    &self.forges,
                    Some(PREFIX.into()),
                    self.deadline_ms,
                );
                let pdp = Arc::clone(self.pdp);
                let credentials = move |uid| crate::CatalogNow::forge_credentials(&*pdp, uid);
                let ctx = AddCtx {
                    user: Some(ACCOUNT),
                    view: &self.view,
                    decide_timeout: self.decide_timeout,
                    text_max: 1 << 20,
                    forges: &self.forges,
                    reach: crate::reach::ReachCtx {
                        egress: &self.stub.egress,
                        settings: &settings,
                        permits: &self.permits,
                        credentials: &credentials,
                    },
                };
                let record = |result: &str, reason: &str, posture: &str| {
                    crate::run::make_record(
                        "request",
                        &w.host,
                        &w.socket,
                        uid,
                        None,
                        None,
                        None,
                        SESSION,
                        0,
                        "session.task",
                        Some(&format!("task:{id}")),
                        result,
                        reason,
                        posture,
                        &w.au3_1,
                    )
                };
                add_task_bindings(
                    store,
                    &shared_signer(),
                    &ctx,
                    (id, caller, under, uid),
                    SecretText::new(text.to_owned()),
                    (&asked, tokens),
                    &crate::reach::FrameTrail {
                        emit,
                        record: &record,
                    },
                )
                .await
            }
        }

        /// Answers every ask with `tasker` or `agent` base ops, covered, with no head.
        fn each_ask(tasker: &'static [ForgeOp], agent: &'static [ForgeOp]) -> Stub {
            Stub::new(Box::new(move |req| {
                let base = match req.side() {
                    ReachSide::Tasker { .. } => tasker,
                    ReachSide::Agent { .. } => agent,
                };
                let list = req.asks().iter().map(|_| seen(base, None, true)).collect();
                let reply = EgressSocketReply::Reach(observed(list));
                (Duration::ZERO, Some(reply))
            }))
        }

        type Hook = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

        /// As `each_ask`, running the hook set at the time once, at the next frame.
        fn hooked(tasker: &'static [ForgeOp], agent: &'static [ForgeOp]) -> (Stub, Hook) {
            let hook: Hook = Arc::default();
            let at = Arc::clone(&hook);
            let stub = Stub::new(Box::new(move |req| {
                if let Some(f) = at.lock().unwrap().take() {
                    f();
                }
                let base = match req.side() {
                    ReachSide::Tasker { .. } => tasker,
                    ReachSide::Agent { .. } => agent,
                };
                let list = req.asks().iter().map(|_| seen(base, None, true)).collect();
                (
                    Duration::ZERO,
                    Some(EgressSocketReply::Reach(observed(list))),
                )
            }));
            (stub, hook)
        }

        fn person(id: TaskId) -> (TaskId, Tasker, Option<TaskId>, u32) {
            (id, Tasker::Uid(me()), None, me())
        }

        fn alpha_parent(pdp: &Pdp, store: &Arc<TaskStore>) -> Arc<SignedTask> {
            reached_parent(
                pdp,
                store,
                vec![sealed(HOST, BASE, None, Some(7))],
                vec![parent_reach(WRITE, READ)],
            )
        }

        const BETA: &str = "sentinel-168c/beta";

        fn added_refusal(got: &Added) -> &TaskRefusal {
            match got {
                Err(r) => r,
                Ok(_) => panic!("the addendum was taken"),
            }
        }

        #[tokio::test]
        async fn the_original_task_is_byte_identical_after_an_addendum() {
            let (_g, pdp) = reach_pdp("addendum-bytes");
            let stub = each_ask(WRITE, READ);
            let store = Arc::new(TaskStore::new());
            let parent = alpha_parent(&pdp, &store);
            let id = parent.task.task_id;
            let before = crate::task_store::encode(&*store.record(&id).unwrap().signed).unwrap();
            let emit = Recorder::new();
            let (view, added, reach) = Reaching::new(&pdp, &stub)
                .add(
                    &store,
                    person(id),
                    "also beta",
                    (vec![change(HOST, BETA, Some(9))], token(HOST)),
                    &emit,
                )
                .await
                .unwrap();
            let rec = store.record(&id).unwrap();
            let after = crate::task_store::encode(&*rec.signed).unwrap();
            assert_eq!(*before, *after);
            assert_eq!(rec.signed, parent);
            let addendum = &rec.addendum.as_ref().unwrap().addendum;
            assert_eq!((addendum.task_id(), addendum.seq()), (&id, 1));
            assert_eq!(addendum.bindings(), &added[..]);
            assert_eq!(addendum.reach(), &reach[..]);
            assert_eq!(rec.follow_ups.len(), 1);
            assert_eq!(view.bindings.len(), 2);
            assert_eq!(view.reach.len(), 2);
            assert_eq!(maknae_proto::effective_reach(&reach[0]).base(), ops(READ));
            assert_eq!(
                (stub.frames(), stub.side(0)),
                (2, format!("tasker {ACCOUNT}"))
            );
            assert_eq!(stub.side(1), "agent hobi");
            let (_, more, _) = Reaching::new(&pdp, &stub)
                .add(
                    &store,
                    person(id),
                    "and gamma",
                    (vec![change(HOST, "sentinel-168c/gamma", None)], token(HOST)),
                    &emit,
                )
                .await
                .unwrap();
            let rec = store.record(&id).unwrap();
            let addendum = &rec.addendum.as_ref().unwrap().addendum;
            assert_eq!(addendum.seq(), 2);
            assert_eq!(addendum.bindings(), &[added[0].clone(), more[0].clone()]);
            assert_eq!(*crate::task_store::encode(&*rec.signed).unwrap(), *before);
        }

        #[tokio::test]
        async fn an_addendum_outside_working_or_from_another_tasker_is_refused() {
            let (_g, pdp) = reach_pdp("addendum-who");
            let stub = each_ask(WRITE, READ);
            let store = Arc::new(TaskStore::new());
            let parent = alpha_parent(&pdp, &store);
            let id = parent.task.task_id;
            let asked = || (vec![change(HOST, BETA, Some(9))], token(HOST));
            let r = Reaching::new(&pdp, &stub);
            let stranger = (id, Tasker::Uid(me() + 1), None, me() + 1);
            let got = r
                .add(&store, stranger, "x", asked(), &Recorder::new())
                .await;
            assert_eq!(added_refusal(&got), &TaskRefusal::Unknown);
            let hobi = (
                id,
                Tasker::Agent {
                    agent: "hobi".into(),
                    uid: HOBI,
                },
                Some(id),
                HOBI,
            );
            let got = r.add(&store, hobi, "x", asked(), &Recorder::new()).await;
            assert_eq!(added_refusal(&got), &TaskRefusal::Unknown);
            store
                .stop(
                    &id,
                    Reach {
                        tasker: &Tasker::Uid(me()),
                        under: None,
                        task: None,
                    },
                )
                .unwrap();
            let got = r
                .add(&store, person(id), "x", asked(), &Recorder::new())
                .await;
            assert_eq!(added_refusal(&got), &TaskRefusal::NotWorking);
            let rec = store.record(&id).unwrap();
            assert!(rec.addendum.is_none() && rec.follow_ups.is_empty());
            assert_eq!(stub.frames(), 0);
        }

        #[tokio::test]
        async fn an_agent_holding_a_task_cannot_widen_its_own_task_by_addendum() {
            let (_g, pdp) = reach_pdp("addendum-held");
            let stub = each_ask(WRITE, READ);
            let store = Arc::new(TaskStore::new());
            let r = Reaching::new(&pdp, &stub);
            let emit = Recorder::new();
            let own = r
                .submit(
                    &store,
                    agent("hobi", HOBI, None),
                    (
                        asking("jin", vec![change(HOST, BASE, Some(7))]),
                        ForgeTokens::default(),
                    ),
                    &emit,
                )
                .await
                .unwrap();
            let task = own.task.task_id;
            store.start_for_test(&task);
            let hobi = || {
                (
                    task,
                    Tasker::Agent {
                        agent: "hobi".into(),
                        uid: HOBI,
                    },
                    None,
                    HOBI,
                )
            };
            r.add(
                &store,
                hobi(),
                "also beta",
                (vec![change(HOST, BETA, Some(9))], ForgeTokens::default()),
                &emit,
            )
            .await
            .unwrap();
            alpha_parent(&pdp, &store);
            assert!(store.holds_working(&id("hobi"), HOBI));
            let before = store.record(&task).unwrap();
            let frames = stub.frames();
            let got = r
                .add(
                    &store,
                    hobi(),
                    "and gamma",
                    (
                        vec![change(HOST, "sentinel-168c/gamma", Some(3))],
                        ForgeTokens::default(),
                    ),
                    &emit,
                )
                .await;
            assert_eq!(
                added_refusal(&got),
                &TaskRefusal::Denied("an agent submits under the task it holds".into())
            );
            assert_eq!(stub.frames(), frames);
            let after = store.record(&task).unwrap();
            assert_eq!(after.follow_ups.len(), before.follow_ups.len());
            assert_eq!(after.addendum, before.addendum);
        }

        #[tokio::test]
        async fn a_claim_during_an_own_initiative_submissions_reach_refuses_its_store_write() {
            let (_g, pdp) = reach_pdp("own-claimed-in-flight");
            let (stub, hook) = hooked(WRITE, READ);
            let store = Arc::new(TaskStore::new());
            let queued = queued_for_hobi(&pdp, &store, Vec::new(), Vec::new())
                .task
                .task_id;
            let s = Arc::clone(&store);
            *hook.lock().unwrap() = Some(Box::new(move || s.start_for_test(&queued)));
            let before = store.len();
            let got = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    agent("hobi", HOBI, None),
                    (
                        asking("jin", vec![change(HOST, BASE, Some(7))]),
                        ForgeTokens::default(),
                    ),
                    &Recorder::new(),
                )
                .await;
            assert_eq!(
                got.map(|t| t.task.task_id),
                Err(TaskRefusal::Denied(
                    "an agent submits under the task it holds".into()
                ))
            );
            assert!(stub.frames() > 0);
            assert!(store.holds_working(&id("hobi"), HOBI));
            assert_eq!(store.len(), before);
        }

        #[tokio::test]
        async fn a_subtask_addendum_is_refused_when_its_parent_is_due_a_close_during_reach() {
            let (_g, pdp) = reach_pdp("addendum-parent-closing");
            let (stub, hook) = hooked(WRITE, READ);
            let store = Arc::new(TaskStore::new());
            let parent = alpha_parent(&pdp, &store).task.task_id;
            let r = Reaching::new(&pdp, &stub);
            r.add(
                &store,
                person(parent),
                "also beta",
                (vec![change(HOST, BETA, Some(9))], token(HOST)),
                &Recorder::new(),
            )
            .await
            .unwrap();
            let child = r
                .submit(
                    &store,
                    agent("hobi", HOBI, Some(parent)),
                    (
                        asking("jin", vec![change(HOST, BASE, Some(7))]),
                        ForgeTokens::default(),
                    ),
                    &Recorder::new(),
                )
                .await
                .unwrap()
                .task
                .task_id;
            store.start_for_test(&child);
            let before = store.record(&child).unwrap();
            let s = Arc::clone(&store);
            *hook.lock().unwrap() = Some(Box::new(move || {
                s.held().closing.insert(parent, TaskClose::AgentLost);
            }));
            let frames = stub.frames();
            let hobi = Tasker::Agent {
                agent: "hobi".into(),
                uid: HOBI,
            };
            let got = r
                .add(
                    &store,
                    (child, hobi, Some(parent), HOBI),
                    "and beta",
                    (vec![change(HOST, BETA, Some(9))], ForgeTokens::default()),
                    &Recorder::new(),
                )
                .await;
            assert_eq!(added_refusal(&got), &TaskRefusal::ParentNotHeld);
            assert!(stub.frames() > frames);
            let after = store.record(&child).unwrap();
            assert_eq!(after.follow_ups.len(), before.follow_ups.len());
            assert_eq!(after.addendum, before.addendum);
        }

        #[tokio::test]
        async fn a_subtask_is_refused_when_its_parent_starts_again_during_reach() {
            let (_g, pdp) = reach_pdp("subtask-parent-restarted");
            let (stub, hook) = hooked(WRITE, READ);
            let store = Arc::new(TaskStore::new());
            let parent = alpha_parent(&pdp, &store).task.task_id;
            let s = Arc::clone(&store);
            *hook.lock().unwrap() = Some(Box::new(move || s.start_for_test(&parent)));
            let before = store.len();
            let got = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    agent("hobi", HOBI, Some(parent)),
                    (
                        asking("jin", vec![change(HOST, BASE, Some(7))]),
                        ForgeTokens::default(),
                    ),
                    &Recorder::new(),
                )
                .await;
            assert_eq!(got.map(|t| t.task.task_id), Err(TaskRefusal::ParentNotHeld));
            assert!(stub.frames() > 0);
            assert_eq!(store.len(), before);
        }

        #[tokio::test]
        async fn a_subtask_addendum_is_refused_when_its_parent_starts_again_during_reach() {
            let (_g, pdp) = reach_pdp("addendum-parent-restarted");
            let (stub, hook) = hooked(WRITE, READ);
            let store = Arc::new(TaskStore::new());
            let parent = alpha_parent(&pdp, &store).task.task_id;
            let r = Reaching::new(&pdp, &stub);
            r.add(
                &store,
                person(parent),
                "also beta",
                (vec![change(HOST, BETA, Some(9))], token(HOST)),
                &Recorder::new(),
            )
            .await
            .unwrap();
            let child = r
                .submit(
                    &store,
                    agent("hobi", HOBI, Some(parent)),
                    (
                        asking("jin", vec![change(HOST, BASE, Some(7))]),
                        ForgeTokens::default(),
                    ),
                    &Recorder::new(),
                )
                .await
                .unwrap()
                .task
                .task_id;
            store.start_for_test(&child);
            let before = store.record(&child).unwrap();
            let s = Arc::clone(&store);
            *hook.lock().unwrap() = Some(Box::new(move || s.start_for_test(&parent)));
            let hobi = Tasker::Agent {
                agent: "hobi".into(),
                uid: HOBI,
            };
            let got = r
                .add(
                    &store,
                    (child, hobi, Some(parent), HOBI),
                    "and beta",
                    (vec![change(HOST, BETA, Some(9))], ForgeTokens::default()),
                    &Recorder::new(),
                )
                .await;
            assert_eq!(added_refusal(&got), &TaskRefusal::Unknown);
            let after = store.record(&child).unwrap();
            assert_eq!(after.follow_ups.len(), before.follow_ups.len());
            assert_eq!(after.addendum, before.addendum);
        }

        #[tokio::test]
        async fn an_addendum_is_refused_when_its_tasker_or_agent_is_contained_during_reach() {
            let (_g, pdp) = reach_pdp("addendum-contained");
            for contained in [me(), HOBI] {
                let (stub, hook) = hooked(WRITE, READ);
                let store = Arc::new(TaskStore::new());
                let task = alpha_parent(&pdp, &store).task.task_id;
                let held = Arc::new(Mutex::new(BTreeSet::new()));
                let mut r = Reaching::new(&pdp, &stub);
                r.view = Arc::new(Switching {
                    base: view(&[("hobi", HOBI), ("jin", JIN)]),
                    contained: Arc::clone(&held),
                });
                *hook.lock().unwrap() = Some(Box::new(move || {
                    held.lock().unwrap().insert(contained);
                }));
                let got = r
                    .add(
                        &store,
                        person(task),
                        "also beta",
                        (vec![change(HOST, BETA, Some(9))], token(HOST)),
                        &Recorder::new(),
                    )
                    .await;
                assert_eq!(
                    added_refusal(&got),
                    &TaskRefusal::Denied(CONTAINED.into()),
                    "{contained}"
                );
                assert!(stub.frames() > 0);
                let rec = store.record(&task).unwrap();
                assert!(rec.addendum.is_none() && rec.follow_ups.is_empty());
            }
        }

        #[tokio::test]
        async fn a_ninth_binding_across_task_and_addendum_is_refused() {
            let (_g, pdp) = reach_pdp("addendum-ninth");
            let stub = each_ask(WRITE, READ);
            let store = Arc::new(TaskStore::new());
            let base = |i: usize| format!("sentinel-168c/r{i}");
            let own: Vec<Binding> = (0..5)
                .map(|i| sealed(HOST, &base(i), None, Some(7)))
                .collect();
            let parent = reached_parent(&pdp, &store, own, vec![parent_reach(WRITE, READ); 5]);
            let id = parent.task.task_id;
            let r = Reaching::new(&pdp, &stub);
            let emit = Recorder::new();
            let asked = |range: std::ops::Range<usize>| {
                range
                    .map(|i| change(HOST, &base(i), Some(7)))
                    .collect::<Vec<_>>()
            };
            let got = r
                .add(
                    &store,
                    person(id),
                    "again",
                    (asked(4..5), token(HOST)),
                    &emit,
                )
                .await;
            assert_eq!(
                added_refusal(&got).to_string(),
                format!(
                    "task not bound: {HOST} {} change 7 is already bound to the task",
                    base(4)
                )
            );
            assert_eq!(stub.frames(), 0);
            r.add(
                &store,
                person(id),
                "six to eight",
                (asked(5..8), token(HOST)),
                &emit,
            )
            .await
            .unwrap();
            assert_eq!(store.record(&id).unwrap().bound().bindings.len(), 8);
            let frames = stub.frames();
            let got = r
                .add(
                    &store,
                    person(id),
                    "ninth",
                    (asked(8..9), token(HOST)),
                    &emit,
                )
                .await;
            assert_eq!(
                added_refusal(&got).to_string(),
                "task not bound: a task holds at most 8 bindings, its own and added, not 9"
            );
            assert_eq!(stub.frames(), frames);
            let rec = store.record(&id).unwrap();
            assert_eq!(rec.follow_ups.len(), 1);
            assert_eq!(rec.addendum.as_ref().unwrap().addendum.bindings().len(), 3);
        }

        #[tokio::test]
        async fn a_later_addendum_counts_the_earlier_one_once_against_the_byte_bound() {
            let (_g, pdp) = reach_pdp("addendum-bytes-once");
            let stub = each_ask(WRITE, READ);
            let store = Arc::new(TaskStore::new());
            let base = |i: usize| format!("sentinel-168c/{}{i}", "x".repeat(150));
            let bound = |range: std::ops::Range<usize>| {
                range
                    .map(|i| sealed(HOST, &base(i), None, Some(7)))
                    .collect::<Vec<_>>()
            };
            let len =
                |b: &[Binding]| maknae_proto::bindings_encoded_len(&b.iter().collect::<Vec<_>>());
            let (own, earlier, new) = (bound(0..1), bound(1..4), bound(4..5));
            let once = [own.clone(), earlier.clone(), new.clone()].concat();
            let twice = [own.clone(), earlier.clone(), earlier, new].concat();
            assert!(len(&once) <= maknae_proto::TASK_BINDINGS_MAX_BYTES);
            assert!(len(&twice) > maknae_proto::TASK_BINDINGS_MAX_BYTES);
            let parent = reached_parent(&pdp, &store, own, vec![parent_reach(WRITE, READ)]);
            let id = parent.task.task_id;
            let r = Reaching::new(&pdp, &stub);
            let asked = |range: std::ops::Range<usize>| {
                range
                    .map(|i| change(HOST, &base(i), Some(7)))
                    .collect::<Vec<_>>()
            };
            for (text, range) in [("earlier", 1..4), ("new", 4..5)] {
                r.add(
                    &store,
                    person(id),
                    text,
                    (asked(range), token(HOST)),
                    &Recorder::new(),
                )
                .await
                .unwrap();
            }
            let rec = store.record(&id).unwrap();
            assert_eq!(rec.addendum.unwrap().addendum.bindings().len(), 4);
        }

        #[tokio::test]
        async fn an_addendum_is_handed_before_follow_ups_and_fits_the_response_cap() {
            let (_g, pdp) = reach_pdp("addendum-handed");
            let stub = each_ask(WRITE, READ);
            let store = Arc::new(TaskStore::new());
            let parent = alpha_parent(&pdp, &store);
            let id = parent.task.task_id;
            let by = Reach {
                tasker: &Tasker::Uid(me()),
                under: None,
                task: None,
            };
            let text_max = 1 << 20;
            store
                .follow_up(&id, by, SecretText::new("first".to_owned()), text_max)
                .unwrap();
            Reaching::new(&pdp, &stub)
                .add(
                    &store,
                    person(id),
                    "also beta",
                    (vec![change(HOST, BETA, Some(9))], token(HOST)),
                    &Recorder::new(),
                )
                .await
                .unwrap();
            store
                .follow_up(&id, by, SecretText::new("later".to_owned()), text_max)
                .unwrap();
            let signed = store.record(&id).unwrap().addendum.unwrap();
            assert_eq!(signed.addendum.seq(), 2);
            let budget = maknae_proto::prompt_request_cap(text_max);
            let beat = |seen| match store.heartbeat(
                &AgentId::parse("hobi").unwrap(),
                HOBI,
                seen,
                budget,
            ) {
                Heartbeat::FollowUps {
                    from,
                    items,
                    addendum,
                    ..
                } => (from, items, addendum),
                other => panic!("{other:?}"),
            };
            for seen in [0, 1] {
                let (from, items, addendum) = beat(seen);
                assert_eq!(from, seen);
                assert_eq!(addendum.as_deref(), Some(&*signed), "{seen}");
                assert_eq!(items.len(), 3 - seen as usize);
                let response = maknae_proto::Response::new(
                    maknae_proto::PROTOCOL_VERSION,
                    maknae_proto::RespResult::Ok(maknae_proto::Payload::TaskFollowUps(
                        maknae_proto::TaskFollowUps {
                            task: maknae_proto::TaskRef::from_id(&id),
                            from,
                            items,
                            addendum: Some(maknae_proto::Bytes::new(
                                crate::task_store::encode(&*signed).unwrap(),
                            )),
                        },
                    )),
                    Some(maknae_proto::CatalogDigest([0xff; 32])),
                );
                let len = maknae_proto::encode_response(&response).unwrap().len();
                assert!(len <= maknae_proto::prompt_response_cap(text_max), "{len}");
            }
            for seen in [2, 3] {
                let (_, items, addendum) = beat(seen);
                assert_eq!(addendum, None, "{seen}");
                assert_eq!(items.len(), 3 - seen as usize);
            }
            let tight = store.heartbeat(&AgentId::parse("hobi").unwrap(), HOBI, 0, 1);
            assert!(
                matches!(&tight, Heartbeat::FollowUps { items, addendum: Some(_), .. } if items.len() == 1),
                "{tight:?}"
            );
        }

        #[test]
        fn a_task_sealed_without_reach_takes_no_addendum() {
            let own = TaskObject {
                bindings: vec![sealed(HOST, BASE, None, Some(7))],
                ..TaskObject::for_test("hobi", 1000)
            };
            let bound = crate::reach::TaskBound::of(&own, None);
            assert_eq!(
                addable(&bound, &[sealed(HOST, BETA, None, None)]),
                Err(TaskRefusal::Unreached(
                    "the task was sealed without reach and takes no addendum".into()
                ))
            );
        }

        #[tokio::test]
        async fn a_subtask_may_bind_an_addendum_binding() {
            let (_g, pdp) = reach_pdp("addendum-subtask");
            let stub = each_ask(WRITE, READ);
            let store = Arc::new(TaskStore::new());
            let parent = alpha_parent(&pdp, &store);
            let id = parent.task.task_id;
            let asked = || vec![change(HOST, BETA, Some(9))];
            let r = Reaching::new(&pdp, &stub);
            let emit = Recorder::new();
            let under = || {
                r.submit(
                    &store,
                    agent("hobi", HOBI, Some(id)),
                    (asking("jin", asked()), ForgeTokens::default()),
                    &emit,
                )
            };
            let before = under().await;
            assert!(matches!(before, Err(TaskRefusal::Unbound(_))), "{before:?}");
            let (_, added, _) = r
                .add(
                    &store,
                    person(id),
                    "also beta",
                    (asked(), token(HOST)),
                    &Recorder::new(),
                )
                .await
                .unwrap();
            let frames = stub.frames();
            let task = under().await.unwrap();
            assert_eq!(task.task.bindings, added);
            let g = git_reach(&task, 0);
            assert_eq!(g.basis, TaskerBasis::Parent);
            assert_eq!(
                g.tasker,
                SideReach::new(ops(READ), ForgeOps::EMPTY).unwrap()
            );
            assert_eq!(stub.frames(), frames + 1);
            assert_eq!(stub.side(frames), "agent jin");
            let cited = store
                .working(&id, &AgentId::parse("hobi").unwrap(), HOBI)
                .unwrap();
            let mut resource = maknae_security::Attributes::default();
            crate::handler::stamp_task_bindings(&mut resource, &cited);
            let bound = maknae_security::decode_git_bound(&resource).unwrap();
            assert_eq!(bound.len(), 2);
            assert!(bound[1].iter().any(|(_, v)| v == BETA), "{bound:?}");
        }

        fn git_reach(t: &SignedTask, at: usize) -> GitReach {
            let BindingReach::Git(g) = t.task.reach[at];
            g
        }

        fn head_of(t: &SignedTask, at: usize) -> Option<String> {
            let Binding::Git(g) = &t.task.bindings[at];
            g.head.clone()
        }

        fn unreached(got: &Result<Arc<SignedTask>, TaskRefusal>) -> String {
            match got {
                Err(TaskRefusal::Unreached(why)) => why.clone(),
                other => panic!("expected a reach refusal, got {other:?}"),
            }
        }

        fn reasons(emit: &Recorder) -> Vec<String> {
            emit.records()
                .iter()
                .map(|r| format!("{} {}", r.outcome.result, r.outcome.reason))
                .collect()
        }

        #[tokio::test]
        async fn a_tasks_reach_is_the_intersection_of_tasker_and_agent() {
            let (_g, pdp) = reach_pdp("intersection");
            let stub = Stub::sides(
                observed(vec![seen(
                    WRITE,
                    Some((BASE, &[ForgeOp::PushHead, ForgeOp::Read])),
                    true,
                )]),
                observed(vec![seen(READ, Some((BASE, &[ForgeOp::PushHead])), true)]),
            );
            let store = Arc::new(TaskStore::new());
            let emit = Recorder::new();
            let task = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    user(),
                    (
                        asking("hobi", vec![change(HOST, BASE, Some(7))]),
                        token(HOST),
                    ),
                    &emit,
                )
                .await
                .unwrap();
            let g = git_reach(&task, 0);
            assert_eq!(g.basis, TaskerBasis::Token);
            assert_eq!(
                g.tasker,
                SideReach::new(ops(WRITE), ops(&[ForgeOp::PushHead, ForgeOp::Read])).unwrap()
            );
            assert_eq!(
                g.agent,
                AgentReach::Observed(SideReach::new(ops(READ), ops(&[ForgeOp::PushHead])).unwrap())
            );
            assert_eq!(g.why, None);
            assert_eq!(
                maknae_proto::effective_reach(&task.task.reach[0]),
                SideReach::new(ops(READ), ops(&[ForgeOp::PushHead])).unwrap()
            );
            assert_eq!(head_of(&task, 0).as_deref(), Some(BASE));
            assert_eq!(stub.frames(), 2);
            assert_eq!(stub.side(0), format!("tasker {ACCOUNT}"));
            assert_eq!(stub.side(1), "agent hobi");
            let frames = stub.seen.lock().unwrap();
            let ReachSide::Tasker {
                expected_path,
                key_field,
                nonce,
                sealed,
                ..
            } = frames[0].side()
            else {
                unreachable!()
            };
            assert_eq!(
                *expected_path,
                format!("{PREFIX}/{ACCOUNT}/forges/git.sentinel-168c.example")
            );
            assert_eq!(key_field, "token");
            assert_eq!(
                (nonce.as_str(), sealed.as_bytes()),
                (NONCE, &sealed_token()[..])
            );
            assert_eq!(frames[0].asks()[0].head, None);
            assert_eq!(frames[0].provider(), "github");
            let ReachSide::Agent { credentials, .. } = frames[1].side() else {
                unreachable!()
            };
            assert_eq!(credentials.len(), 1);
            assert_eq!(credentials[0].name, APP);
            assert_eq!(frames[1].asks()[0].head.as_deref(), Some(BASE));
            assert!(frames[1].deadline_ms() <= frames[0].deadline_ms());
            drop(frames);
            let trail = reasons(&emit);
            assert_eq!(
                trail,
                [
                    format!("permit reach intent recorded (tasker {HOST})"),
                    format!("permit reach observed (tasker {HOST})"),
                    format!("permit reach intent recorded (agent hobi {HOST})"),
                    format!("permit reach observed (agent hobi {HOST})"),
                    "permit task stored".to_owned(),
                ]
            );
            let stored = emit.records().pop().unwrap();
            assert_eq!(
                stored.subject.reach,
                crate::run::record_reach(&task.task.reach)
            );
            assert_eq!(stored.subject.reach.len(), 1);
        }

        #[tokio::test]
        async fn a_missing_login_refuses_the_task() {
            let (_g, pdp) = reach_pdp("no-login");
            let stub = Stub::sides(
                ReachReply::Refused(ReachRefusal::Request),
                ReachReply::NoForgeCredential,
            );
            let store = Arc::new(TaskStore::new());
            let emit = Recorder::new();
            let got = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    user(),
                    (
                        asking("hobi", vec![change(HOST, BASE, Some(7))]),
                        ForgeTokens::default(),
                    ),
                    &emit,
                )
                .await;
            assert_eq!(unreached(&got), format!("no forge login for {HOST}"));
            assert_eq!((stub.frames(), store.len()), (0, 0));
            let last = emit.records().pop().unwrap();
            assert_eq!(last.outcome.result, "deny");
            assert_eq!(
                last.outcome.reason,
                format!("task not reached: no forge login for {HOST}")
            );
        }

        async fn refused_by(class: ReachRefusal, said: &str) {
            let (_g, pdp) = reach_pdp(&format!("refused-{said}"));
            for asked in [change(HOST, BASE, Some(7)), change(HOST, BASE, None)] {
                let stub = Stub::sides(ReachReply::Refused(class), ReachReply::NoForgeCredential);
                let store = Arc::new(TaskStore::new());
                let emit = Recorder::new();
                let got = Reaching::new(&pdp, &stub)
                    .submit(
                        &store,
                        user(),
                        (asking("hobi", vec![asked]), token(HOST)),
                        &emit,
                    )
                    .await;
                assert_eq!(
                    unreached(&got),
                    format!("reach refused: {said} (tasker {HOST})")
                );
                assert_eq!((stub.frames(), store.len()), (1, 0));
                let trail = reasons(&emit);
                assert_eq!(
                    trail[1],
                    format!("deny reach refused: {said} (tasker {HOST})")
                );
                assert_eq!(emit.records()[1].outcome.posture, "unauthorized");
            }
        }

        #[tokio::test]
        async fn a_404_refuses_the_task() {
            refused_by(ReachRefusal::NotFound, "not_found").await;
        }

        #[tokio::test]
        async fn a_401_refuses_the_task() {
            refused_by(ReachRefusal::Unauthorized, "unauthorized").await;
        }

        #[tokio::test]
        async fn a_fork_fills_head_and_push_follows_the_agents_coverage() {
            let (_g, pdp) = reach_pdp("fork");
            let tasker = || observed(vec![seen(WRITE, Some((FORK, &[ForgeOp::PushHead])), true)]);
            for (agent_head, pushes) in [
                (Some((FORK, &[ForgeOp::PushHead][..])), true),
                (None, false),
            ] {
                let agent = observed(vec![RepoObservation::new(
                    ops(READ),
                    Some(FORK.into()),
                    agent_head.map_or(ForgeOps::EMPTY, |(_, o)| ops(o)),
                    false,
                    true,
                )
                .unwrap()]);
                let stub = Stub::sides(tasker(), agent);
                let store = Arc::new(TaskStore::new());
                let task = Reaching::new(&pdp, &stub)
                    .submit(
                        &store,
                        user(),
                        (
                            asking("hobi", vec![change(HOST, BASE, Some(7))]),
                            token(HOST),
                        ),
                        &Recorder::new(),
                    )
                    .await
                    .unwrap();
                assert_eq!(head_of(&task, 0).as_deref(), Some(FORK));
                assert_eq!(
                    stub.seen.lock().unwrap()[1].asks()[0].head.as_deref(),
                    Some(FORK)
                );
                let effective = maknae_proto::effective_reach(&task.task.reach[0]);
                assert_eq!(effective.head().contains(ForgeOp::PushHead), pushes);
                assert_eq!(effective.base(), ops(READ));
            }
        }

        #[tokio::test]
        async fn an_uncovered_agent_gives_empty_reach_not_a_refusal() {
            let (_g, pdp) = reach_pdp("uncovered");
            let stub = Stub::sides(
                observed(vec![seen(WRITE, None, true)]),
                observed(vec![seen(&[], None, false)]),
            );
            let store = Arc::new(TaskStore::new());
            let task = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    user(),
                    (asking("hobi", vec![change(HOST, BASE, None)]), token(HOST)),
                    &Recorder::new(),
                )
                .await
                .unwrap();
            let g = git_reach(&task, 0);
            assert_eq!(g.why, Some(EmptyReason::AgentNotCovered));
            assert_eq!(g.tasker.base(), ops(WRITE));
            assert_eq!(
                maknae_proto::effective_reach(&task.task.reach[0]),
                SideReach::EMPTY
            );
            assert_eq!(store.len(), 1);
        }

        #[tokio::test]
        async fn a_tasker_without_any_permission_seals_empty_reach() {
            let (_g, pdp) = reach_pdp("no-permission");
            let stub = Stub::sides(
                observed(vec![seen(&[], None, true)]),
                observed(vec![seen(READ, None, true)]),
            );
            let store = Arc::new(TaskStore::new());
            let task = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    user(),
                    (asking("hobi", vec![change(HOST, BASE, None)]), token(HOST)),
                    &Recorder::new(),
                )
                .await
                .unwrap();
            assert_eq!(git_reach(&task, 0).tasker, SideReach::EMPTY);
            assert_eq!(
                maknae_proto::effective_reach(&task.task.reach[0]),
                SideReach::EMPTY
            );
        }

        #[tokio::test]
        async fn a_gitlab_binding_seals_empty_reach_with_no_frame() {
            let (_g, pdp) = reach_pdp("gitlab");
            let stub = Stub::sides(
                ReachReply::Refused(ReachRefusal::Request),
                ReachReply::NoForgeCredential,
            );
            let store = Arc::new(TaskStore::new());
            let emit = Recorder::new();
            let task = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    user(),
                    (
                        asking("hobi", vec![change(LAB, BASE, Some(3))]),
                        ForgeTokens::default(),
                    ),
                    &emit,
                )
                .await
                .unwrap();
            assert_eq!(
                task.task.reach,
                [BindingReach::Git(GitReach {
                    tasker: SideReach::EMPTY,
                    basis: TaskerBasis::Token,
                    agent: AgentReach::NoForgeCredential,
                    why: Some(EmptyReason::NoReachCheck),
                })]
            );
            assert_eq!(head_of(&task, 0), None);
            assert_eq!(stub.frames(), 0);
            assert_eq!(reasons(&emit), ["permit task stored"]);
        }

        fn parent_reach(tasker: &[ForgeOp], agent: &[ForgeOp]) -> BindingReach {
            BindingReach::Git(GitReach {
                tasker: SideReach::new(ops(tasker), ForgeOps::EMPTY).unwrap(),
                basis: TaskerBasis::Token,
                agent: AgentReach::Observed(SideReach::new(ops(agent), ForgeOps::EMPTY).unwrap()),
                why: None,
            })
        }

        #[tokio::test]
        async fn a_subtask_takes_its_parents_effective_reach_and_its_own_agent_side() {
            let (_g, pdp) = reach_pdp("subtask");
            let stub = Stub::sides(
                ReachReply::Refused(ReachRefusal::Request),
                observed(vec![seen(&[ForgeOp::Read, ForgeOp::Merge], None, true)]),
            );
            let store = Arc::new(TaskStore::new());
            let parent = reached_parent(
                &pdp,
                &store,
                vec![sealed(HOST, BASE, None, Some(7))],
                vec![parent_reach(WRITE, READ)],
            );
            let task = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    agent("hobi", HOBI, Some(parent.task.task_id)),
                    (
                        asking("jin", vec![change(HOST, BASE, Some(7))]),
                        ForgeTokens::default(),
                    ),
                    &Recorder::new(),
                )
                .await
                .unwrap();
            let g = git_reach(&task, 0);
            assert_eq!(g.basis, TaskerBasis::Parent);
            assert_eq!(
                g.tasker,
                SideReach::new(ops(READ), ForgeOps::EMPTY).unwrap()
            );
            assert_eq!(
                maknae_proto::effective_reach(&task.task.reach[0]).base(),
                ops(&[ForgeOp::Read])
            );
            assert_eq!(stub.frames(), 1);
            assert_eq!(stub.side(0), "agent jin");
        }

        #[tokio::test]
        async fn a_subtask_under_a_parent_without_reach_is_refused() {
            let (_g, pdp) = reach_pdp("pr-a-parent");
            let stub = Stub::sides(
                ReachReply::Refused(ReachRefusal::Request),
                observed(vec![seen(READ, None, true)]),
            );
            let store = Arc::new(TaskStore::new());
            let parent = reached_parent(
                &pdp,
                &store,
                vec![sealed(HOST, BASE, None, Some(7))],
                Vec::new(),
            );
            let got = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    agent("hobi", HOBI, Some(parent.task.task_id)),
                    (
                        asking("jin", vec![change(HOST, BASE, Some(7))]),
                        ForgeTokens::default(),
                    ),
                    &Recorder::new(),
                )
                .await;
            assert_eq!(unreached(&got), "parent task has no reach");
            assert_eq!((stub.frames(), store.len()), (0, 1));
        }

        #[tokio::test]
        async fn a_subtask_carrying_a_token_is_refused() {
            let (_g, pdp) = reach_pdp("subtask-token");
            let stub = Stub::sides(
                ReachReply::Refused(ReachRefusal::Request),
                observed(vec![seen(READ, None, true)]),
            );
            let store = Arc::new(TaskStore::new());
            let parent = reached_parent(
                &pdp,
                &store,
                vec![sealed(HOST, BASE, None, Some(7))],
                vec![parent_reach(WRITE, READ)],
            );
            let got = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    agent("hobi", HOBI, Some(parent.task.task_id)),
                    (
                        asking("jin", vec![change(HOST, BASE, Some(7))]),
                        token(HOST),
                    ),
                    &Recorder::new(),
                )
                .await;
            assert_eq!(
                unreached(&got),
                "an agent's submission carries no forge token"
            );
            assert_eq!((stub.frames(), store.len()), (0, 1));
        }

        #[tokio::test]
        async fn an_agent_submission_carrying_a_token_is_refused() {
            let (_g, pdp) = reach_pdp("agent-token");
            let stub = Stub::sides(
                ReachReply::Refused(ReachRefusal::Request),
                observed(vec![seen(READ, None, true)]),
            );
            let store = Arc::new(TaskStore::new());
            for asked in [vec![change(HOST, BASE, Some(7))], Vec::new()] {
                let got = Reaching::new(&pdp, &stub)
                    .submit(
                        &store,
                        agent("hobi", HOBI, None),
                        (asking("jin", asked), token(HOST)),
                        &Recorder::new(),
                    )
                    .await;
                assert_eq!(
                    unreached(&got),
                    "an agent's submission carries no forge token"
                );
            }
            assert_eq!((stub.frames(), store.len()), (0, 0));
        }

        #[tokio::test]
        async fn a_token_for_an_unbound_server_is_refused() {
            let (_g, pdp) = reach_pdp("unbound-token");
            let stub = Stub::sides(
                observed(vec![seen(WRITE, None, true)]),
                observed(vec![seen(READ, None, true)]),
            );
            let store = Arc::new(TaskStore::new());
            for asked in [vec![change(LAB, BASE, Some(7))], Vec::new()] {
                let got = Reaching::new(&pdp, &stub)
                    .submit(
                        &store,
                        user(),
                        (asking("hobi", asked), token(HOST)),
                        &Recorder::new(),
                    )
                    .await;
                assert_eq!(
                    unreached(&got),
                    format!("a forge token for {HOST}, which no binding names")
                );
            }
            assert_eq!((stub.frames(), store.len()), (0, 0));
        }

        #[tokio::test]
        async fn an_own_initiative_task_intersects_the_two_agents() {
            let (_g, pdp) = reach_pdp("own-initiative");
            let stub = Stub::new(Box::new(|req| {
                let base: &[ForgeOp] = match req.side() {
                    ReachSide::Agent { agent, .. } if agent == "hobi" => WRITE,
                    _ => &[ForgeOp::Read, ForgeOp::IssueWrite],
                };
                assert!(req.asks().iter().all(|a| a.head.is_none()));
                let reply = observed(vec![seen(base, None, true)]);
                (Duration::ZERO, Some(EgressSocketReply::Reach(reply)))
            }));
            let store = Arc::new(TaskStore::new());
            let task = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    agent("hobi", HOBI, None),
                    (
                        asking("jin", vec![change(HOST, BASE, Some(7))]),
                        ForgeTokens::default(),
                    ),
                    &Recorder::new(),
                )
                .await
                .unwrap();
            let g = git_reach(&task, 0);
            assert_eq!(g.basis, TaskerBasis::Submitter);
            assert_eq!(g.tasker.base(), ops(WRITE));
            assert_eq!(head_of(&task, 0), None);
            assert_eq!(
                maknae_proto::effective_reach(&task.task.reach[0]).base(),
                ops(&[ForgeOp::Read, ForgeOp::IssueWrite])
            );
            assert_eq!(
                (stub.side(0), stub.side(1)),
                ("agent hobi".into(), "agent jin".into())
            );
        }

        #[tokio::test]
        async fn an_own_initiative_task_whose_submitter_has_no_credential_seals_empty() {
            let (_g, pdp) = reach_pdp("own-initiative-none");
            let stub = Stub::new(Box::new(|req| {
                let reply = match req.side() {
                    ReachSide::Agent { agent, .. } if agent == "hobi" => {
                        ReachReply::NoForgeCredential
                    }
                    _ => observed(vec![seen(READ, None, true)]),
                };
                (Duration::ZERO, Some(EgressSocketReply::Reach(reply)))
            }));
            let store = Arc::new(TaskStore::new());
            let task = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    agent("hobi", HOBI, None),
                    (
                        asking("jin", vec![change(HOST, BASE, None)]),
                        ForgeTokens::default(),
                    ),
                    &Recorder::new(),
                )
                .await
                .unwrap();
            let g = git_reach(&task, 0);
            assert_eq!(g.tasker, SideReach::EMPTY);
            assert_eq!(g.why, Some(EmptyReason::NoForgeCredential));
            assert_eq!(
                maknae_proto::effective_reach(&task.task.reach[0]),
                SideReach::EMPTY
            );
        }

        #[tokio::test]
        async fn an_own_initiative_task_whose_submitter_is_seen_at_hand_out_says_why_it_is_empty() {
            let (g, pdp) = reach_pdp("own-initiative-at-hand-out");
            let homelab = include_str!("../../../packaging/common/tools-homelab.yaml");
            let app = "kind: github-app-installation\n    source: minted-per-task\n    narrowing: provider\n    lifetime: { expires: 1h, revoke_on: task-outcome }\n    minting: trust-plane\n    delivery: [env:GH_TOKEN, git-credential-file]\n    app: maknae-github-read\n";
            assert!(homelab.contains(app));
            crate::test_fixtures::write_tools(
                &g.0,
                &homelab.replacen(
                    app,
                    "kind: github-machine-user\n    delivery: [env:GH_TOKEN, git-credential-file]\n",
                    1,
                ),
            );
            pdp.baseline().reload_from_file().unwrap();
            let user = maknae_proto::CredentialRef {
                kind: "github-machine-user".into(),
                name: "github-read".into(),
            };
            assert_eq!(crate::CatalogNow::forge_credentials(&*pdp, HOBI), [user]);
            let stub = each_ask(WRITE, READ);
            let store = Arc::new(TaskStore::new());
            let task = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    agent("hobi", HOBI, None),
                    (
                        asking("jin", vec![change(HOST, BASE, None)]),
                        ForgeTokens::default(),
                    ),
                    &Recorder::new(),
                )
                .await
                .unwrap();
            let g = git_reach(&task, 0);
            assert_eq!(g.basis, TaskerBasis::Submitter);
            assert_eq!(
                (g.tasker, g.agent),
                (SideReach::EMPTY, AgentReach::AtHandOut)
            );
            assert_eq!(g.why, Some(EmptyReason::NoForgeCredential));
            assert_eq!(stub.frames(), 0);
        }

        #[tokio::test]
        async fn the_reach_deadline_refuses_the_task() {
            let (_g, pdp) = reach_pdp("deadline");
            let stub = Stub::new(Box::new(|req| {
                let reply = observed(vec![seen(WRITE, None, true)]);
                let delay = match req.side() {
                    ReachSide::Tasker { .. } => Duration::from_millis(600),
                    ReachSide::Agent { .. } => Duration::ZERO,
                };
                (delay, Some(EgressSocketReply::Reach(reply)))
            }));
            let store = Arc::new(TaskStore::new());
            let emit = Recorder::new();
            let reaching = Reaching {
                deadline_ms: 300,
                ..Reaching::new(&pdp, &stub)
            };
            let got = reaching
                .submit(
                    &store,
                    user(),
                    (asking("hobi", vec![change(HOST, BASE, None)]), token(HOST)),
                    &emit,
                )
                .await;
            assert_eq!(unreached(&got), "the reach deadline passed");
            assert_eq!((stub.frames(), store.len()), (1, 0));
            assert!(stub.seen.lock().unwrap()[0].deadline_ms() <= 300);
        }

        #[tokio::test]
        async fn a_slow_reach_still_stores_the_task() {
            let (_g, pdp) = reach_pdp("slow-reach");
            let decide_timeout = Duration::from_millis(200);
            let slow = decide_timeout * 3;
            let stub = Stub::new(Box::new(move |req| {
                let reply = observed(vec![seen(WRITE, None, true)]);
                let delay = match req.side() {
                    ReachSide::Tasker { .. } => slow,
                    ReachSide::Agent { .. } => Duration::ZERO,
                };
                (delay, Some(EgressSocketReply::Reach(reply)))
            }));
            let store = Arc::new(TaskStore::new());
            let reaching = Reaching {
                decide_timeout,
                ..Reaching::new(&pdp, &stub)
            };
            let task = reaching
                .submit(
                    &store,
                    user(),
                    (asking("hobi", vec![change(HOST, BASE, None)]), token(HOST)),
                    &Recorder::new(),
                )
                .await
                .unwrap();
            assert_eq!((stub.frames(), store.len()), (2, 1));
            assert_eq!(task.task.reach.len(), 1);
        }

        #[tokio::test]
        async fn a_reach_at_the_kernels_capacity_is_outcome_unknown() {
            let (_g, pdp) = reach_pdp("capacity");
            let stub = Stub::sides(
                observed(vec![seen(WRITE, None, true)]),
                observed(vec![seen(READ, None, true)]),
            );
            let store = Arc::new(TaskStore::new());
            let reaching = Reaching {
                deadline_ms: 200,
                permits: tokio::sync::Semaphore::new(0),
                ..Reaching::new(&pdp, &stub)
            };
            let got = reaching
                .submit(
                    &store,
                    user(),
                    (asking("hobi", vec![change(HOST, BASE, None)]), token(HOST)),
                    &Recorder::new(),
                )
                .await;
            assert_eq!(unreached(&got), "reach outcome unknown: at capacity");
            assert_eq!((stub.frames(), store.len()), (0, 0));
        }

        #[tokio::test]
        async fn no_frame_is_sent_without_a_durable_intent() {
            let (_g, pdp) = reach_pdp("durable-intent");
            let stub = Stub::sides(
                observed(vec![seen(WRITE, None, true)]),
                observed(vec![seen(READ, None, true)]),
            );
            let store = Arc::new(TaskStore::new());
            let emit = Recorder::failing();
            let got = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    user(),
                    (asking("hobi", vec![change(HOST, BASE, None)]), token(HOST)),
                    &emit,
                )
                .await;
            assert!(matches!(got, Err(TaskRefusal::Audit(_))), "{got:?}");
            assert_eq!((stub.frames(), store.len()), (0, 0));
            assert!(reasons(&emit)[0].starts_with("permit reach intent recorded"));
        }

        fn holds(hay: &[u8], needle: &[u8]) -> bool {
            hay.windows(needle.len()).any(|w| w == needle)
        }

        fn hex(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }

        #[tokio::test]
        async fn the_tasker_token_is_in_no_store_trail_or_delivery_bytes_of_a_submit_or_an_add() {
            let (_g, pdp) = reach_pdp("token-bytes");
            let stub = Stub::sides(
                observed(vec![seen(WRITE, Some((FORK, &[ForgeOp::PushHead])), true)]),
                observed(vec![seen(READ, None, true)]),
            );
            let blobs = crate::task_store::MemTaskBlobs::default();
            let store = Arc::new(
                TaskStore::open(
                    Box::new(blobs.clone()),
                    Arc::new(crate::task_store::SystemClock),
                )
                .unwrap(),
            );
            let emit = Recorder::new();
            let task = Reaching::new(&pdp, &stub)
                .submit(
                    &store,
                    user(),
                    (
                        asking("hobi", vec![change(HOST, BASE, Some(7))]),
                        token(HOST),
                    ),
                    &emit,
                )
                .await
                .unwrap();
            {
                let frames = stub.seen.lock().unwrap();
                let ReachSide::Tasker { sealed, .. } = frames[0].side() else {
                    panic!("the first frame is the tasker's");
                };
                assert_eq!(
                    sealed.as_bytes(),
                    sealed_token(),
                    "the token did reach the egress socket"
                );
            }
            let id = task.task.task_id;
            store.start_for_test(&id);
            let seen = stub.frames();
            let (added_view, added, added_reach) = Reaching::new(&pdp, &stub)
                .add(
                    &store,
                    person(id),
                    "also beta",
                    (vec![change(HOST, BETA, Some(9))], token(HOST)),
                    &emit,
                )
                .await
                .unwrap();
            let frames = stub.seen.lock().unwrap();
            let ReachSide::Tasker { sealed, .. } = frames[seen].side() else {
                panic!("the add's first frame is the tasker's");
            };
            assert_eq!(sealed.as_bytes(), sealed_token());
            drop(frames);
            let mut bytes: Vec<(String, Vec<u8>)> = Vec::new();
            let rec = store.record(&id).unwrap();
            let addendum = rec.addendum.as_deref().expect("the addendum is stored");
            let mut handed = Vec::new();
            ciborium::into_writer(addendum, &mut handed).unwrap();
            bytes.push(("addendum delivery".into(), handed));
            let mut acked = Vec::new();
            ciborium::into_writer(&added_view, &mut acked).unwrap();
            bytes.push(("addendum acknowledgement".into(), acked));
            bytes.push((
                "addendum sealed".into(),
                serde_json::to_vec(&(
                    crate::run::record_bindings(&added),
                    crate::run::record_reach(&added_reach),
                ))
                .unwrap(),
            ));
            for name in crate::task_store::TaskBlobs::names(&blobs).unwrap() {
                let b = crate::task_store::TaskBlobs::load(&blobs, &name).unwrap();
                bytes.push((format!("store {name}"), b.to_vec()));
            }
            assert!(!bytes.is_empty());
            for r in emit.records() {
                bytes.push(("trail".into(), serde_json::to_vec(&r).unwrap()));
            }
            let mut delivered = Vec::new();
            ciborium::into_writer(&*task, &mut delivered).unwrap();
            bytes.push(("delivery".into(), delivered));
            let reach = crate::task::Reach {
                tasker: &Tasker::Uid(me()),
                under: None,
                task: None,
            };
            let view = store.status(&task.task.task_id, reach).unwrap();
            let mut shown = Vec::new();
            ciborium::into_writer(&view, &mut shown).unwrap();
            bytes.push(("view".into(), shown));
            for (at, b) in &bytes {
                for needle in [
                    sealed_token(),
                    NONCE.as_bytes().to_vec(),
                    hex(&sealed_token()).into_bytes(),
                    hex(NONCE.as_bytes()).into_bytes(),
                ] {
                    assert!(!holds(b, &needle), "{at} holds the token");
                }
            }
        }

        #[tokio::test]
        async fn heads_over_the_sealed_bound_refuse_by_name() {
            let (_g, pdp) = reach_pdp("heads-bound");
            let bases: Vec<String> = (0..maknae_proto::TASK_BINDINGS_MAX)
                .map(|i| format!("sentinel-168c/{i}{}", "b".repeat(40)))
                .collect();
            let asked: Vec<_> = bases.iter().map(|b| change(HOST, b, Some(1))).collect();
            assert!(
                maknae_proto::bindings_encoded_len(&asked)
                    <= maknae_proto::TASK_BINDING_REQUESTS_MAX_BYTES
            );
            let head = format!("sentinel-168c-fork/{}", "h".repeat(200));
            let tasker = observed(
                (0..maknae_proto::TASK_BINDINGS_MAX)
                    .map(|_| seen(WRITE, Some((&head, &[ForgeOp::PushHead])), true))
                    .collect(),
            );
            let stub = Stub::sides(tasker, observed(vec![seen(READ, None, true)]));
            let store = Arc::new(TaskStore::new());
            let emit = Recorder::new();
            let got = Reaching::new(&pdp, &stub)
                .submit(&store, user(), (asking("hobi", asked), token(HOST)), &emit)
                .await;
            let Err(TaskRefusal::Unbound(why)) = &got else {
                panic!("expected the bound refusal, got {got:?}");
            };
            assert!(
                why.contains(&format!("{HOST} {} change 1 head {head}", bases[0])),
                "{why}"
            );
            assert!(why.contains("more than 1280"), "{why}");
            assert_eq!((stub.frames(), store.len()), (1, 0));
        }
    }
}
