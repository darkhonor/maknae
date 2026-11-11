//! The in-kernel task store and the `session.task` submission path (#609).
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use maknae_audit_append::AuditEmit;
use maknae_config::AgentId;
use maknae_proto::{
    SecretText, SignedTask, TaskClose, TaskId, TaskObject, TaskReportPage, TaskState,
    TaskSubmission, TaskView, Tasker,
};
use maknae_security::Authorizer;

use crate::enrollment::EnrollmentView;
use crate::task_store::{
    encode, name_of, ordinal_key, BootFinding, Clock, Counters, Hot, RootTasker, StoreError,
    TaskBlobs, TaskRecord, CLAIM_LEASE, COUNTERS,
};

pub const MAX_LIVE_TASKS_PER_AGENT: usize = 256;
pub const MAX_LIVE_TASKS_PER_TASKER_PER_AGENT: usize = 32;
pub const MAX_HELD_REPORTS_PER_TASKER: usize = 256;
pub const MAX_FOLLOW_UPS_PER_TASK: usize = 32;

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
}

impl Held {
    fn generation(&self, agent: &AgentId) -> u64 {
        self.generations.get(agent).copied().unwrap_or(0)
    }

    fn live(&self, id: &TaskId) -> Option<&TaskRecord> {
        self.tasks.get(id).filter(|r| !r.pending)
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
                TaskState::Queued | TaskState::Reported | TaskState::Closed => 0,
            };
            let id = rec.signed.task.task_id;
            held.hot.insert(
                id,
                Hot {
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

    /// A write that landed unsynced is undone to `prior` before it is refused, so a
    /// restart never reloads what was refused.
    fn write(&self, rec: &TaskRecord, prior: Option<&TaskRecord>) -> Result<(), TaskRefusal> {
        let name = name_of(&rec.signed.task.task_id);
        let plain = encode(rec).map_err(store)?;
        match self.blobs.save(&name, &plain) {
            Err(StoreError::NotDurable(why)) => {
                let undone = match prior {
                    None => self.blobs.delete(&name),
                    Some(p) => encode(p).and_then(|b| self.blobs.save(&name, &b)),
                };
                match undone {
                    Ok(()) | Err(StoreError::NotDurable(_)) => {}
                    Err(e @ (StoreError::Io(_) | StoreError::Counters(_))) => {
                        eprintln!("maknaed: refused task write to {name} was not undone: {e}");
                    }
                }
                Err(TaskRefusal::Store(why))
            }
            other => other.map_err(store),
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

    /// An unlink that landed unsynced is taken, so memory matches the visible disk
    /// record by record, and a repeated acknowledgement finds nothing left to remove.
    /// The caller holds the writer.
    fn erase(&self, id: &TaskId) -> Result<(), TaskRefusal> {
        match self.blobs.delete(&name_of(id)) {
            Ok(()) | Err(StoreError::NotDurable(_)) => {}
            Err(e @ (StoreError::Io(_) | StoreError::Counters(_))) => return Err(store(e)),
        }
        let mut held = self.held();
        held.tasks.remove(id);
        held.hot.remove(id);
        Ok(())
    }

    /// Bumps the generation and drops the agent's tasks from memory in one step, so a mint
    /// racing it is refused; the records are removed after, and one that cannot be is
    /// purged again by the next boot's reconcile.
    fn forget(held: &mut Held, agent: &AgentId) -> Vec<TaskId> {
        let g = held.generations.entry(agent.clone()).or_insert(0);
        *g = g.wrapping_add(1);
        let gone: Vec<TaskId> = held
            .tasks
            .iter()
            .filter(|(_, t)| t.agent == *agent)
            .map(|(id, _)| *id)
            .collect();
        for id in &gone {
            held.tasks.remove(id);
            held.hot.remove(id);
        }
        gone
    }

    fn unlink_all(&self, gone: Vec<TaskId>) {
        for id in gone {
            if let Err(e) = self.blobs.delete(&name_of(&id)) {
                eprintln!("maknaed: purged task {id} stays on disk: {e}");
            }
        }
    }

    /// A purge bumps the generation before it removes anything, so a panic inside
    /// one leaves a state in which a mint racing it is still refused.
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

    /// One at a time, so a panic loses nothing queued: the item in hand is put back on
    /// unwind, and one whose disk step failed is put back for the next writer.
    fn drain_abandoned(&self) {
        let queue = || {
            self.abandoned
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        };
        let rounds = queue().len();
        for _ in 0..rounds {
            let Some(id) = queue().pop() else {
                break;
            };
            let mut hand = PutBack {
                store: self,
                id: Some(id),
            };
            if self.withdraw_locked(&id, false) {
                hand.id = None;
            } else if let Some(id) = hand.id.take() {
                queue().insert(0, id);
            }
        }
    }

    /// Queues a submission's record for withdrawal by the next writer; never waits.
    pub(crate) fn abandon(&self, id: TaskId) {
        self.abandoned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(id);
    }

    pub fn generation(&self, agent: &AgentId) -> u64 {
        self.held().generation(agent)
    }

    pub fn purge_agent(&self, agent: &AgentId) {
        let _w = self.writing();
        let gone = Self::forget(&mut self.held(), agent);
        self.unlink_all(gone);
    }

    /// Purges every agent whose (id, uid) the view no longer holds as last seen,
    /// whether or not it holds tasks.
    pub fn retain_enrolled(&self, view: &dyn EnrollmentView) {
        let _w = self.writing();
        let mut gone = Vec::new();
        {
            let mut held = self.held();
            let known: std::collections::BTreeSet<AgentId> = held
                .enrolled
                .keys()
                .chain(held.tasks.values().map(|t| &t.agent))
                .cloned()
                .collect();
            for agent in known {
                let now = view.agent_uid(&agent);
                let stale = held.enrolled.get(&agent).is_some_and(|u| now != Some(*u))
                    || held
                        .tasks
                        .values()
                        .any(|t| t.agent == agent && now != Some(t.agent_uid));
                if stale {
                    gone.extend(Self::forget(&mut held, &agent));
                }
                match now {
                    Some(uid) => held.enrolled.insert(agent, uid),
                    None => held.enrolled.remove(&agent),
                };
            }
        }
        self.unlink_all(gone);
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
        loop {
            let signed = Arc::new(signer.sign(task)?);
            match self.place(view, &agent, enrolled, &signed, ticket)? {
                Placed::Stored => return Ok(signed),
                Placed::Collided => {
                    task = signed.task.clone();
                    task.task_id = TaskId(draw()?);
                }
            }
        }
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
            if held.tasks.values().filter(|t| t.agent == *agent).count() >= MAX_LIVE_TASKS_PER_AGENT
            {
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
            pending: true,
            seq,
            tseq,
            rseq: None,
            submitted: self.clock.now_secs(),
            claimed: None,
            follow_ups: Vec::new(),
            report: None,
        };
        self.write(&rec, None)?;
        if let Some(t) = ticket {
            if !t.keep(task.task.task_id) {
                if let Err(e) = self.blobs.delete(&name_of(&task.task.task_id)) {
                    eprintln!(
                        "maknaed: abandoned task {} stays on disk: {e}",
                        task.task.task_id
                    );
                }
                return Err(abandoned());
            }
        }
        let mut held = self.held();
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
        owned(&self.held(), id, agent, uid)
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
        let mut held = owned(&self.held(), id, agent, uid)?;
        for _ in 0..2 {
            let current = signer.current_leaf().ok_or(TaskRefusal::Unsigned)?;
            if maknae_vault::task_sig::leaf_fingerprint(&held.signature.leaf.0) == current {
                return Ok(held);
            }
            let fresh = Arc::new(signer.sign(held.task.clone())?);
            let _w = self.writing();
            let prior = {
                let store = self.held();
                let now = owned(&store, id, agent, uid)?;
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
                TaskState::Queued | TaskState::Working => {}
                TaskState::Reported | TaskState::Closed => return Err(TaskRefusal::Finished),
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
        self.write(&next, Some(&prior))?;
        self.held().tasks.insert(*id, next.clone());
        Ok(next)
    }

    /// Removes, durably, `tasker`'s reports from `agent` up to its own report ordinal
    /// `upto`; a cursor above every ordinal this tasker was ever issued is refused.
    pub fn acknowledge(
        &self,
        tasker: &Tasker,
        agent: &AgentId,
        upto: u64,
    ) -> Result<usize, TaskRefusal> {
        let _w = self.writing();
        let gone: Vec<TaskId> = {
            let held = self.held();
            if upto > held.issued.of(tasker).rseq {
                return Err(TaskRefusal::CursorAhead);
            }
            held.tasks
                .iter()
                .filter(|(_, r)| {
                    !r.pending
                        && r.tasker == *tasker
                        && r.agent == *agent
                        && r.rseq.is_some_and(|s| s <= upto)
                })
                .map(|(id, _)| *id)
                .collect()
        };
        for id in &gone {
            self.erase(id)?;
        }
        Ok(gone.len())
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

    /// Makes a minted task visible, once its submission is audited.
    /// With a `ticket`, a submission that gave up first wins: the record is not made
    /// visible, and one already written confirmed is withdrawn again.
    pub(crate) fn confirm(&self, id: &TaskId, ticket: Option<&Ticket>) -> Result<(), TaskRefusal> {
        let _w = self.writing();
        if ticket.is_some_and(Ticket::abandoned) {
            return Err(abandoned());
        }
        let prior = self
            .held()
            .tasks
            .get(id)
            .filter(|r| r.pending)
            .cloned()
            .ok_or(TaskRefusal::Unknown)?;
        let mut next = prior.clone();
        next.pending = false;
        self.write(&next, Some(&prior))?;
        if ticket.is_some_and(|t| !t.keep(*id)) {
            if !self.withdraw_locked(id, true) {
                self.abandon(*id);
            }
            return Err(abandoned());
        }
        self.held().tasks.insert(*id, next);
        Ok(())
    }

    /// The agent's own task `id`, only while it is `Working`.
    pub fn working(
        &self,
        id: &TaskId,
        agent: &AgentId,
        uid: u32,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let held = self.held();
        let task = owned(&held, id, agent, uid)?;
        match held.live(id).map(|r| r.state) {
            Some(TaskState::Working) => Ok(task),
            Some(TaskState::Queued | TaskState::Reported | TaskState::Closed) | None => {
                Err(TaskRefusal::NotWorking)
            }
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
            if rec.state != TaskState::Working {
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
                (true, TaskState::Queued | TaskState::Reported | TaskState::Closed) => {
                    Err(TaskRefusal::NotWorking)
                }
            },
        )?;
        Ok(self.view_of(&self.held(), &next))
    }

    /// Withdraws `tasker`'s queued task; its record is removed before the answer.
    pub fn drop_queued(&self, id: &TaskId, tasker: &Tasker) -> Result<TaskView, TaskRefusal> {
        let _w = self.writing();
        let mut view = {
            let held = self.held();
            let rec = tasker_record(&held, id, tasker).ok_or(TaskRefusal::Unknown)?;
            if rec.state != TaskState::Queued {
                return Err(TaskRefusal::Finished);
            }
            self.view_of(&held, rec)
        };
        self.erase(id)?;
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
            .collect();
        mine.sort_by_key(|r| r.rseq);
        crate::task_verbs::report_page(mine.into_iter(), budget)
    }

    /// True when the record is off the disk or left pending there; otherwise it is queued
    /// for the next writer.
    pub(crate) fn withdraw(&self, id: &TaskId) -> bool {
        let _w = self.writing();
        let done = self.withdraw_locked(id, false);
        if !done {
            self.abandon(*id);
        }
        done
    }

    /// Takes a submission back: out of memory, marked pending on disk if the disk may hold
    /// it confirmed, then unlinked. True when the disk no longer holds it confirmed: gone, or
    /// pending for boot to discard. When false the record is kept in memory, pending, for a
    /// retry. The caller holds the writer.
    fn withdraw_locked(&self, id: &TaskId, disk_confirmed: bool) -> bool {
        let removed = {
            let mut held = self.held();
            held.hot.remove(id);
            held.tasks.remove(id)
        };
        let confirmed = disk_confirmed || removed.as_ref().is_some_and(|r| !r.pending);
        let mut pending_on_disk = !confirmed;
        if let (true, Some(rec)) = (confirmed, &removed) {
            let mut rec = rec.clone();
            rec.pending = true;
            match encode(&rec).and_then(|plain| self.blobs.save(&name_of(id), &plain)) {
                Ok(()) | Err(StoreError::NotDurable(_)) => pending_on_disk = true,
                Err(e @ (StoreError::Io(_) | StoreError::Counters(_))) => {
                    eprintln!("maknaed: withdrawn task {id} was not marked pending: {e}");
                }
            }
        }
        match self.blobs.delete(&name_of(id)) {
            Ok(()) | Err(StoreError::NotDurable(_)) => true,
            Err(StoreError::Io(_) | StoreError::Counters(_)) if pending_on_disk => true,
            Err(e @ (StoreError::Io(_) | StoreError::Counters(_))) => {
                eprintln!("maknaed: withdrawn task {id} stays on disk confirmed: {e}");
                if let Some(mut rec) = removed {
                    rec.pending = true;
                    self.held().tasks.insert(*id, rec);
                }
                false
            }
        }
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn insert_for_test(&self, signed: SignedTask, agent_uid: u32) -> Arc<SignedTask> {
        let agent = AgentId::parse(&signed.task.agent).expect("a test task names a valid agent id");
        let root = match &signed.task.tasker {
            Tasker::Uid(uid) => RootTasker::Person { uid: *uid },
            Tasker::Agent { agent, .. } | Tasker::Remote(agent) => RootTasker::Agent {
                agent: agent.clone(),
            },
        };
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
            pending: false,
            seq,
            tseq,
            rseq: None,
            submitted: self.clock.now_secs(),
            claimed: None,
            follow_ups: Vec::new(),
            report: None,
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
        let mut next = self.held().live(id).expect("a held task").clone();
        next.state = TaskState::Working;
        next.claimed = Some(self.clock.now_secs());
        self.write(&next, None)
            .expect("the test store writes the task");
        self.held().tasks.insert(*id, next);
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
        self.confirm(&t.task.task_id, None)?;
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
        self.confirm(&t.task.task_id, None)?;
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

/// A sub-task works in its parent's partition; a person's own task, in the uid's.
fn root_of(held: &Held, task: &TaskObject) -> Result<RootTasker, TaskRefusal> {
    if let Some(parent) = task.parent {
        return held
            .live(&parent)
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
    Ok(stored.signed.clone())
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
    parent: Option<&SignedTask>,
    sub: &TaskSubmission,
    lane: maknae_security::Lane,
) -> maknae_security::Request {
    use crate::handler::{build_authz_request, Stamp, TaskStamp};
    let parent = parent.map(|p| TaskStamp::of(&p.task));
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
    pub seq: u64,
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
            ctx.seq,
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
        Err(crate::mutation::Blocked::Unknown) => Err(TaskRefusal::Unavailable(
            "outcome unknown: the task store did not answer in time".into(),
        )),
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
            let (s, id) = (Arc::clone(store), task.task.task_id);
            let ticket = Arc::new(Ticket::default());
            let t = Arc::clone(&ticket);
            match offload(uid, deadline, move || s.confirm(&id, Some(&t))).await {
                Ok(()) => Ok(task),
                Err(_) if ticket.abandon().is_some() => Ok(task),
                Err(refusal) => {
                    let withdrawal = withdraw_within(store, uid, deadline, id).await;
                    let mut corrective = attempt.record(ctx, Some(&task.task), Some(&refusal));
                    corrective.outcome.reason = match &refusal {
                        TaskRefusal::Unavailable(why) => format!("{why}; {}", withdrawal.said()),
                        other => format!("not stored: {other}; {}", withdrawal.said()),
                    };
                    corrective.outcome.posture = "unavailable".into();
                    emit.emit_within(&corrective, crate::blocking_guard::AUDIT_APPEND_TIMEOUT)
                        .await
                        .map_err(|e| TaskRefusal::Audit(e.to_string()))?;
                    Err(refusal)
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
        Submitter::User { .. } | Submitter::Agent { under: None, .. } => None,
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
    attempt.parent = parent.as_ref().map(|t| t.task.task_id);
    let (generation, enrolled) = store.observe(&**view, &target);
    let req = task_request(by, target.as_str(), parent.as_deref(), &sub, ctx.lane);
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
            during: Box::new(|| store.purge_agent(&hobi)),
        };
        assert_eq!(
            store
                .resign_if_stale(&task_id, &hobi, HOBI, &withdrawing)
                .unwrap_err(),
            TaskRefusal::Unknown
        );
        assert_eq!(store.len(), 0, "a withdrawn task is not put back");
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
        assert_eq!(store.len(), 0);
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
        assert_eq!(store.confirm(&mine, None), Err(TaskRefusal::Unknown));
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
        store.confirm(&pending, None).unwrap();
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
        let ctx = SubmitCtx {
            where_: &w,
            session_id: SESSION,
            seq: 5,
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
    async fn a_task_whose_pending_mark_cannot_clear_is_refused_and_corrected() {
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
        assert!(matches!(got, Err(TaskRefusal::Store(_))), "{got:?}");
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
        assert!(trail[1].1.starts_with("not stored: "), "{trail:?}");
        assert_eq!(trail[1].2, "unavailable");
        assert_eq!(store.len(), 0);
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
            self.1.slow(Some(std::time::Duration::from_millis(2000)));
            self.0.emit(rec)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_confirm_that_times_out_never_reloads_as_a_live_task() {
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
        assert!(matches!(got, Err(TaskRefusal::Unavailable(_))), "{got:?}");
        let corrective = emit.0.records().pop().unwrap();
        assert!(
            corrective.outcome.reason.starts_with("outcome unknown: "),
            "{}",
            corrective.outcome.reason
        );
        blobs.await_stalls(1);
        blobs.slow(None);
        store.quiesce();
        let reopened =
            TaskStore::open(Box::new(blobs), Arc::new(crate::task_store::SystemClock)).unwrap();
        assert_eq!(reopened.len(), 0, "no live task reloads");
        assert!(reopened
            .take_boot_findings()
            .iter()
            .all(|f| matches!(f, crate::task_store::BootFinding::Discarded { .. })));
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
        let queued = store.abandoned.lock().unwrap().clone();
        match w {
            Withdrawal::Done => {
                assert!(queued.is_empty(), "done here is never also queued");
                assert!(store.record(&id).is_none());
            }
            Withdrawal::Queued => assert_eq!(queued, vec![id]),
            Withdrawal::Running => panic!("an expired bound either ran it or queued it"),
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
            assert_eq!((r.session_id, r.seq), (SESSION, 5));
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
        assert_eq!(store.len(), 0);
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
        let racing = hooked(pdp.clone(), move || purging.purge_agent(&id("hobi")));
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
        let ctx = SubmitCtx {
            where_: &w,
            session_id: SESSION,
            seq: 6,
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
        let ctx = SubmitCtx {
            where_: &w,
            session_id: SESSION,
            seq: 5,
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
}
