//! The in-kernel task store and the `session.task` submission path (#609).
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use maknae_audit_append::AuditEmit;
use maknae_config::AgentId;
use maknae_proto::{
    SecretText, SignedTask, TaskClose, TaskId, TaskObject, TaskState, TaskSubmission, Tasker,
};
use maknae_security::Authorizer;

use crate::enrollment::EnrollmentView;
use crate::task_store::{
    encode, name_of, BootFinding, Clock, Counters, Hot, RootTasker, StoreError, TaskBlobs,
    TaskRecord, CLAIM_LEASE, COUNTERS,
};

pub const MAX_LIVE_TASKS_PER_AGENT: usize = 256;

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

/// Tasks, written through to `blobs` before any change is visible in memory.
pub struct TaskStore {
    held: Mutex<Held>,
    blobs: Box<dyn TaskBlobs>,
    clock: Arc<dyn Clock>,
}

enum Sequence {
    Submission,
    Report,
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

    /// The high-water mark is durable before the value is used.
    fn issue(&self, held: &mut Held, which: Sequence) -> Result<u64, TaskRefusal> {
        let mut next = held.issued;
        let slot = match which {
            Sequence::Submission => &mut next.seq,
            Sequence::Report => &mut next.rseq,
        };
        *slot = slot
            .checked_add(1)
            .ok_or(TaskRefusal::Store("the sequence is exhausted".into()))?;
        let issued = *slot;
        let plain = encode(&next).map_err(store)?;
        self.blobs.save(COUNTERS, &plain).map_err(store)?;
        held.issued = next;
        Ok(issued)
    }

    /// An unlink that landed unsynced is taken, so memory matches the visible disk
    /// record by record, and a repeated acknowledgement finds nothing left to remove.
    fn erase(&self, held: &mut Held, id: &TaskId) -> Result<(), TaskRefusal> {
        match self.blobs.delete(&name_of(id)) {
            Ok(()) | Err(StoreError::NotDurable(_)) => {}
            Err(e @ (StoreError::Io(_) | StoreError::Counters(_))) => return Err(store(e)),
        }
        held.tasks.remove(id);
        held.hot.remove(id);
        Ok(())
    }

    /// Bumps the generation first, so a mint racing it is refused; a task whose record
    /// cannot be removed is still dropped from memory, and the next boot's reconcile
    /// purges it again.
    fn purge(&self, held: &mut Held, agent: &AgentId) {
        let g = held.generations.entry(agent.clone()).or_insert(0);
        *g = g.wrapping_add(1);
        let gone: Vec<TaskId> = held
            .tasks
            .iter()
            .filter(|(_, t)| t.agent == *agent)
            .map(|(id, _)| *id)
            .collect();
        for id in gone {
            held.tasks.remove(&id);
            held.hot.remove(&id);
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

    pub fn generation(&self, agent: &AgentId) -> u64 {
        self.held().generation(agent)
    }

    pub fn purge_agent(&self, agent: &AgentId) {
        let mut held = self.held();
        self.purge(&mut held, agent);
    }

    /// Purges every agent whose (id, uid) the view no longer holds as last seen,
    /// whether or not it holds tasks.
    pub fn retain_enrolled(&self, view: &dyn EnrollmentView) {
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
                self.purge(&mut held, &agent);
            }
            match now {
                Some(uid) => held.enrolled.insert(agent, uid),
                None => held.enrolled.remove(&agent),
            };
        }
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
        let mut draw = || {
            let mut id = [0u8; 16];
            maknae_crypto::random::fill(&mut id[..]).map_err(|_| TaskRefusal::Random)?;
            Ok(id)
        };
        self.mint_with(&mut draw, signer, view, enrolled, tasker, parent, sub)
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
            match self.place(view, &agent, enrolled, &signed)? {
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
    ) -> Result<Placed, TaskRefusal> {
        let Enrolled {
            generation,
            agent_uid,
        } = enrolled;
        let mut held = self.held();
        if view.agent_uid(agent) != Some(agent_uid) || held.generation(agent) != generation {
            return Err(TaskRefusal::AgentGone);
        }
        if held.tasks.values().filter(|t| t.agent == *agent).count() >= MAX_LIVE_TASKS_PER_AGENT {
            return Err(TaskRefusal::AtCapacity {
                agent: agent.as_str().to_string(),
            });
        }
        if held.tasks.contains_key(&task.task.task_id) {
            return Ok(Placed::Collided);
        }
        let root = root_of(&held, &task.task)?;
        let seq = self.issue(&mut held, Sequence::Submission)?;
        let rec = TaskRecord {
            signed: task.clone(),
            agent: agent.clone(),
            agent_uid,
            tasker: task.task.tasker.clone(),
            root,
            parent: task.task.parent,
            state: TaskState::Queued,
            close: None,
            pending: false,
            seq,
            rseq: None,
            submitted: self.clock.now_secs(),
            claimed: None,
            follow_ups: Vec::new(),
            report: None,
        };
        self.write(&rec, None)?;
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
            let mut store = self.held();
            let now = owned(&store, id, agent, uid)?;
            if !Arc::ptr_eq(&now, &held) {
                held = now;
                continue;
            }
            if let Some(slot) = store.tasks.get_mut(id) {
                let mut next = slot.clone();
                next.signed = fresh.clone();
                self.write(&next, Some(slot))?;
                *slot = next;
            }
            return Ok(fresh);
        }
        Err(TaskRefusal::Unsigned)
    }

    /// Records the report or the close and issues its `rseq`, all under the store lock, so
    /// no reader sees one `rseq` before a smaller one.
    pub fn publish_report(
        &self,
        id: &TaskId,
        text: SecretText,
        close: Option<TaskClose>,
    ) -> Result<u64, TaskRefusal> {
        let mut held = self.held();
        let rec = held.live(id).ok_or(TaskRefusal::Unknown)?;
        match rec.state {
            TaskState::Queued | TaskState::Working => {}
            TaskState::Reported | TaskState::Closed => return Err(TaskRefusal::Finished),
        }
        let mut next = rec.clone();
        let rseq = self.issue(&mut held, Sequence::Report)?;
        next.state = match close {
            None => TaskState::Reported,
            Some(_) => TaskState::Closed,
        };
        next.close = close;
        next.rseq = Some(rseq);
        next.report = Some((text, self.clock.now_secs()));
        self.write(&next, held.tasks.get(id))?;
        held.tasks.insert(*id, next);
        Ok(rseq)
    }

    /// Removes, durably, `tasker`'s reports from `agent` up to `upto`; a cursor above every
    /// `rseq` ever issued is refused.
    pub fn acknowledge(
        &self,
        tasker: &Tasker,
        agent: &AgentId,
        upto: u64,
    ) -> Result<usize, TaskRefusal> {
        let mut held = self.held();
        if upto > held.issued.rseq {
            return Err(TaskRefusal::CursorAhead);
        }
        let gone: Vec<TaskId> = held
            .tasks
            .iter()
            .filter(|(_, r)| {
                !r.pending
                    && r.tasker == *tasker
                    && r.agent == *agent
                    && r.rseq.is_some_and(|s| s <= upto)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &gone {
            self.erase(&mut held, id)?;
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

    fn withdraw(&self, id: &TaskId) {
        let mut held = self.held();
        held.tasks.remove(id);
        held.hot.remove(id);
        if let Err(e) = self.blobs.delete(&name_of(id)) {
            eprintln!("maknaed: withdrawn task {id} stays on disk: {e}");
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
        let mut held = self.held();
        let seq = self
            .issue(&mut held, Sequence::Submission)
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
            rseq: None,
            submitted: self.clock.now_secs(),
            claimed: None,
            follow_ups: Vec::new(),
            report: None,
        };
        self.write(&rec, None)
            .expect("the test store writes the task");
        held.hot.insert(task.task.task_id, Hot::default());
        held.tasks.insert(task.task.task_id, rec);
        task
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.held().tasks.len()
    }
}

fn store(e: StoreError) -> TaskRefusal {
    TaskRefusal::Store(e.to_string())
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
}

struct Attempt {
    uid: u32,
    agent: Option<AgentId>,
    tasker: Tasker,
    target: String,
    parent: Option<TaskId>,
    role: Option<&'static str>,
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
        rec
    }
}

/// Decides one `session.task` submission and stores it only on `Permit`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "#610's TaskSubmit arm is the caller")
)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn submit_task<P: Authorizer + Send + Sync + 'static>(
    authorizer: Arc<P>,
    store: &TaskStore,
    signer: &dyn TaskSigner,
    view: &dyn EnrollmentView,
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

#[allow(clippy::too_many_arguments)]
async fn submit_under<P: Authorizer + Send + Sync + 'static>(
    pdp: Decider<P>,
    store: &TaskStore,
    signer: &dyn TaskSigner,
    view: &dyn EnrollmentView,
    ctx: &SubmitCtx<'_>,
    by: Submitter,
    sub: TaskSubmission,
    emit: &impl AuditEmit,
) -> Result<Arc<SignedTask>, TaskRefusal> {
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
    };
    let decided = decide(pdp, store, signer, view, ctx, &by, sub, &mut attempt).await;
    let rec = match &decided {
        Ok(signed) => attempt.record(ctx, Some(&signed.task), None),
        Err(refusal) => attempt.record(ctx, None, Some(refusal)),
    };
    let audited = emit
        .emit_within(&rec, crate::blocking_guard::AUDIT_APPEND_TIMEOUT)
        .await;
    match (decided, audited) {
        (Ok(task), Ok(())) => Ok(task),
        (Ok(signed), Err(e)) => {
            store.withdraw(&signed.task.task_id);
            Err(TaskRefusal::Audit(e.to_string()))
        }
        (Err(refusal), _) => Err(refusal),
    }
}

#[allow(clippy::too_many_arguments)]
async fn decide<P: Authorizer + Send + Sync + 'static>(
    pdp: Decider<P>,
    store: &TaskStore,
    signer: &dyn TaskSigner,
    view: &dyn EnrollmentView,
    ctx: &SubmitCtx<'_>,
    by: &Submitter,
    sub: TaskSubmission,
    attempt: &mut Attempt,
) -> Result<Arc<SignedTask>, TaskRefusal> {
    maknae_proto::validate_submission(&sub).map_err(|e| TaskRefusal::Schema(e.to_string()))?;
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
                .resolve(t, agent, *uid)
                .map_err(|_| TaskRefusal::ParentNotHeld)?,
        ),
    };
    attempt.parent = parent.as_ref().map(|t| t.task.task_id);
    let (generation, enrolled) = store.observe(view, &target);
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
    store.mint(
        signer,
        view,
        Enrolled {
            generation,
            agent_uid,
        },
        attempt.tasker.clone(),
        attempt.parent,
        sub,
    )
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
        let store = TaskStore::new();
        let v = view(&[("hobi", HOBI)]);
        assert_eq!(NoIdentity.current_leaf(), None);
        assert_eq!(
            store
                .mint(
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
                .mint(
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
        let store = TaskStore::new();
        let v = view(&[("hobi", HOBI)]);
        let mut draws = [[1u8; 16], [1; 16], [2; 16]].into_iter();
        let mut draw = || Ok(draws.next().unwrap());
        for _ in 0..2 {
            let signed = store
                .mint_with(
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
        let store = TaskStore::new();
        let v = view(&[("hobi", HOBI), ("jin", JIN)]);
        let hobis = store
            .mint(
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
        let store = TaskStore::new();
        let v = view(&[("hobi", HOBI)]);
        let old = store
            .mint(
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
            let store = TaskStore::new();
            let v = view(&[("hobi", HOBI), ("jin", JIN)]);
            let mint_by = |s: &LeafSigner, to: &str| {
                store
                    .mint(s, &v, at(0, v.0[&id(to)]), Tasker::Uid(1000), None, sub(to))
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
            .mint(
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
        let store = TaskStore::new();
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
            .mint(
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
        let store = TaskStore::new();
        let v = view(&[("hobi", HOBI)]);
        let mut draws = [[1u8; 16], [1; 16], [2; 16]].into_iter();
        let mut draw = || Ok(draws.next().unwrap());
        let first = store
            .mint_with(
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
            .mint_with(
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
                .mint_with(
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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

    #[test]
    fn the_store_refuses_a_new_task_at_capacity_and_keeps_the_rest() {
        let store = TaskStore::new();
        let v = view(&[("hobi", HOBI), ("jin", JIN)]);
        let held: Vec<_> = (0..MAX_LIVE_TASKS_PER_AGENT)
            .map(|_| mint(&store, &v, "hobi"))
            .collect();
        assert_eq!(
            store
                .mint(
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
        let store = TaskStore::new();
        assert_eq!(
            store
                .mint(
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
            store.mint(
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
        let store = TaskStore::new();
        let v = view(&[("hobi", HOBI)]);
        let read = store.generation(&id("hobi"));
        store.purge_agent(&id("hobi"));
        assert_eq!(
            store
                .mint(
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
        let store = TaskStore::new();
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

    async fn submit_via<P: Authorizer + Send + Sync + 'static>(
        a: Arc<P>,
        store: &TaskStore,
        v: &dyn EnrollmentView,
        by: Submitter,
        sub: TaskSubmission,
        emit: &Recorder,
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
        };
        let pdp = Decider {
            authorizer: a,
            breaker: breaker.unwrap_or_default(),
        };
        submit_under(pdp, store, signer(), v, &ctx, by, sub, emit).await
    }

    async fn submit(
        pdp: &Pdp,
        store: &TaskStore,
        by: Submitter,
        to: &str,
        emit: &Recorder,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let view = SnapshotEnrollment(pdp.clone());
        submit_via(pdp.clone(), store, &view, by, sub(to), emit, (BOUND, None)).await
    }

    #[tokio::test]
    async fn submit_stores_only_a_permitted_task() {
        let (_g, pdp) = pdp("permitted");
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
        let emit = Recorder::new();
        let first = submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
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
        let store = TaskStore::new();
        let refused = submit(&pdp, &store, user(), "hobi", &Recorder::failing())
            .await
            .unwrap_err();
        assert!(matches!(refused, TaskRefusal::Audit(_)), "{refused:?}");
        assert_eq!(store.len(), 0);
    }

    #[tokio::test]
    async fn an_agent_whose_policy_denies_session_task_is_refused() {
        let (_g, pdp) = pdp("policy-deny");
        let store = TaskStore::new();
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
        let store = TaskStore::new();
        let emit = Recorder::new();
        let parent = submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
        submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
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
        let store = TaskStore::new();
        let emit = Recorder::new();
        let view = SnapshotEnrollment(pdp.clone());
        let parent = submit(&pdp, &store, user(), "hobi", &emit).await.unwrap();
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
        };
        let pdp_under = Decider {
            authorizer: capturing.clone(),
            breaker: Breaker::default(),
        };
        let _ = submit_under(
            pdp_under,
            &store,
            signer(),
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
        let store = TaskStore::new();
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
        };
        let view = SnapshotEnrollment(pdp.clone());
        submit_task(
            pdp.clone(),
            &store,
            signer(),
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
