//! The in-kernel task store and the `session.task` submission path (#609).
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use maknae_audit_append::AuditEmit;
use maknae_config::AgentId;
use maknae_proto::{SignedTask, TaskId, TaskObject, TaskSubmission, Tasker};
use maknae_security::Authorizer;

use crate::enrollment::EnrollmentView;

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
        }
    }
}

/// Signs each task the kernel authorizes (R-S). `current_leaf` is the SHA-256 of the
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

/// A task bound to the agent id and the uid enrolled when it was minted (M2).
pub struct StoredTask {
    pub task: Arc<SignedTask>,
    pub agent: AgentId,
    pub agent_uid: u32,
}

#[derive(Default)]
struct Held {
    tasks: BTreeMap<TaskId, StoredTask>,
    generations: BTreeMap<AgentId, u64>,
    enrolled: BTreeMap<AgentId, u32>,
}

impl Held {
    fn generation(&self, agent: &AgentId) -> u64 {
        self.generations.get(agent).copied().unwrap_or(0)
    }

    fn purge(&mut self, agent: &AgentId) {
        let g = self.generations.entry(agent.clone()).or_insert(0);
        *g = g.wrapping_add(1);
        self.tasks.retain(|_, t| t.agent != *agent);
    }
}

/// The agent's generation and enrolled uid, as read before the decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enrolled {
    pub generation: u64,
    pub agent_uid: u32,
}

/// Live tasks, in memory for `maknaed`'s life (Q4).
#[derive(Default)]
pub struct TaskStore {
    held: Mutex<Held>,
}

enum Placed {
    Stored,
    Collided,
}

impl TaskStore {
    pub fn new() -> Self {
        Self::default()
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
        self.held().purge(agent);
    }

    /// Purges every agent whose (id, uid) the view no longer holds as last seen,
    /// whether or not it holds tasks (M8).
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
                held.purge(&agent);
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
        let Enrolled {
            generation,
            agent_uid,
        } = enrolled;
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
            match self.place(view, &agent, generation, agent_uid, &signed)? {
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
        generation: u64,
        agent_uid: u32,
        task: &Arc<SignedTask>,
    ) -> Result<Placed, TaskRefusal> {
        let mut held = self.held();
        if view.agent_uid(agent) != Some(agent_uid) || held.generation(agent) != generation {
            return Err(TaskRefusal::AgentGone);
        }
        if held.tasks.values().filter(|t| t.agent == *agent).count() >= MAX_LIVE_TASKS_PER_AGENT {
            return Err(TaskRefusal::AtCapacity {
                agent: agent.as_str().to_string(),
            });
        }
        match held.tasks.entry(task.task.task_id) {
            std::collections::btree_map::Entry::Occupied(_) => Ok(Placed::Collided),
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(StoredTask {
                    task: task.clone(),
                    agent: agent.clone(),
                    agent_uid,
                });
                Ok(Placed::Stored)
            }
        }
    }

    pub fn resolve(
        &self,
        id: &TaskId,
        agent: &AgentId,
        uid: u32,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let held = self.held();
        let stored = held.tasks.get(id).ok_or(TaskRefusal::Unknown)?;
        if stored.agent != *agent || stored.agent_uid != uid {
            return Err(TaskRefusal::OtherAgent);
        }
        Ok(stored.task.clone())
    }

    /// Called when a task is handed out (#610): re-signs it outside the store lock when its
    /// signing leaf is not the signer's current one. Without a current leaf, or a signature,
    /// nothing is handed out. A task replaced meanwhile is handed out as replaced.
    pub fn resign_if_stale(
        &self,
        id: &TaskId,
        signer: &dyn TaskSigner,
    ) -> Result<Arc<SignedTask>, TaskRefusal> {
        let held = self
            .held()
            .tasks
            .get(id)
            .map(|t| t.task.clone())
            .ok_or(TaskRefusal::Unknown)?;
        let current = signer.current_leaf().ok_or(TaskRefusal::Unsigned)?;
        if maknae_vault::task_sig::leaf_fingerprint(&held.signature.leaf.0) == current {
            return Ok(held);
        }
        let fresh = Arc::new(signer.sign(held.task.clone())?);
        let mut store = self.held();
        let slot = store.tasks.get_mut(id).ok_or(TaskRefusal::Unknown)?;
        if Arc::ptr_eq(&slot.task, &held) {
            slot.task = fresh;
        }
        Ok(slot.task.clone())
    }

    fn withdraw(&self, id: &TaskId) {
        self.held().tasks.remove(id);
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn insert_for_test(&self, signed: SignedTask, agent_uid: u32) -> Arc<SignedTask> {
        let agent = AgentId::parse(&signed.task.agent).expect("a test task names a valid agent id");
        let task = Arc::new(signed);
        self.held().tasks.insert(
            task.task.task_id,
            StoredTask {
                task: task.clone(),
                agent,
                agent_uid,
            },
        );
        task
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.held().tasks.len()
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

/// Built by the kernel from the authenticated session, never from the submission (H5).
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

fn task_request(by: &Submitter, target: &str) -> maknae_security::Request {
    use maknae_security::{
        Action, AttrValue, Attributes, Context, Request, Resource, Subject, CHANNEL_AGENT,
        CHANNEL_CLIENT, RESOURCE_AGENT, SUBJECT_AGENT, SUBJECT_CHANNEL, SUBJECT_HOME,
    };
    let mut subject = Attributes::new();
    let (uid, home) = match by {
        Submitter::User { uid, home } => {
            subject.insert(SUBJECT_CHANNEL, AttrValue::Str(CHANNEL_CLIENT.into()));
            (*uid, home)
        }
        Submitter::Agent {
            agent, uid, home, ..
        } => {
            subject.insert(SUBJECT_CHANNEL, AttrValue::Str(CHANNEL_AGENT.into()));
            subject.insert(SUBJECT_AGENT, AttrValue::Str(agent.as_str().into()));
            (*uid, home)
        }
    };
    subject.insert("uid", AttrValue::Int(i64::from(uid)));
    if let Some(h) = home.as_deref().and_then(std::path::Path::to_str) {
        subject.insert(SUBJECT_HOME, AttrValue::Str(h.to_owned()));
    }
    let mut resource = Attributes::new();
    resource.insert(RESOURCE_AGENT, AttrValue::Str(target.to_owned()));
    Request {
        subject: Subject(subject),
        resource: Resource(resource),
        action: Action("session.task".into()),
        context: Context(Attributes::new()),
    }
}

/// The connection a submission arrived on, for its audit record and its decision bound.
pub(crate) struct SubmitCtx<'a> {
    pub where_: &'a crate::run::WhereCtx,
    pub session_id: u64,
    pub seq: u64,
    pub user: Option<&'a str>,
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
            None,
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

/// Decides one `session.task` submission and stores it only on `Permit` (R-T, R-O).
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
    attempt.parent = match by {
        Submitter::User { .. } => None,
        Submitter::Agent { under: None, .. } => None,
        Submitter::Agent {
            agent,
            uid,
            under: Some(t),
            ..
        } => {
            store
                .resolve(t, agent, *uid)
                .map_err(|_| TaskRefusal::ParentNotHeld)?;
            Some(*t)
        }
    };
    let (generation, enrolled) = store.observe(view, &target);
    let req = task_request(by, target.as_str());
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
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const HOBI: u32 = 2001;
    const JIN: u32 = 2002;
    const SUGA: u32 = 2003;
    const HOBI_AGAIN: u32 = 2004;
    const SESSION: u64 = 77;
    const BOUND: std::time::Duration = std::time::Duration::from_secs(5);
    type Breaker = Arc<tokio::sync::Mutex<BlockingBreaker>>;
    const PROMPT: &str = "task-11-prompt-sentinel";
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
        signing.rotate();
        let replacement = signing.sign(old.task.clone()).unwrap();
        let replacing = DuringSign {
            inner: &signing,
            during: Box::new(|| {
                store.insert_for_test(replacement.clone(), HOBI);
            }),
        };
        signing.rotate();
        let handed = store.resign_if_stale(&task_id, &replacing).unwrap();
        assert_eq!(*handed, replacement, "the replacement is handed out");
        let held = store.resolve(&task_id, &id("hobi"), HOBI).unwrap();
        assert!(Arc::ptr_eq(&held, &handed), "and not overwritten");
        let withdrawing = DuringSign {
            inner: &signing,
            during: Box::new(|| store.purge_agent(&id("hobi"))),
        };
        assert_eq!(
            store.resign_if_stale(&task_id, &withdrawing).unwrap_err(),
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
                store.resign_if_stale(&id_before, &NoIdentity).unwrap_err(),
                TaskRefusal::Unsigned,
                "no current leaf: nothing is handed out"
            );
            let kept = store.resolve(&id_before, &id("hobi"), HOBI).unwrap();
            assert!(Arc::ptr_eq(&kept, &before), "{k:?}");
            let after = store.resign_if_stale(&id_before, &signing).unwrap();
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
                .resign_if_stale(&fresh.task.task_id, &signing)
                .unwrap();
            assert!(Arc::ptr_eq(&untouched, &fresh), "{k:?}");
            let mut unknown = id_before;
            unknown.0[0] ^= 0xff;
            assert_eq!(
                store.resign_if_stale(&unknown, &signing).unwrap_err(),
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
        let parent = TaskId([7; 16]);
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
        assert_eq!(store.len(), 2);
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

    fn no_daemons() -> Result<maknae_io::DaemonFacts, String> {
        Ok(maknae_io::DaemonFacts {
            uids: Vec::new(),
            gids: Vec::new(),
        })
    }

    fn no_group(_: &str) -> Result<Option<u32>, String> {
        Ok(None)
    }

    fn put(path: &std::path::Path, body: &str) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
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
            daemons: no_daemons,
            group: no_group,
        });
        let agents = g.0.join(maknae_config::AGENTS_DIR);
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
            let dir = agents.join(agent);
            std::fs::create_dir_all(&dir).unwrap();
            for d in [&agents, &dir] {
                std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o750)).unwrap();
            }
            put(
                &dir.join(maknae_config::ENROLLMENT_FILE),
                &format!("agent_id: {agent}\naccount: {agent}-svc\nuid: {uid}\nrole: user\n"),
            );
            if let Some(p) = policy {
                put(&dir.join(maknae_config::POLICY_FILE), p);
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
        let file =
            g.0.join(maknae_config::AGENTS_DIR)
                .join("hobi")
                .join(maknae_config::ENROLLMENT_FILE);
        let reloading = pdp.clone();
        let racing = hooked(pdp.clone(), move || {
            put(
                &file,
                &format!("agent_id: hobi\naccount: hobi-svc\nuid: {HOBI_AGAIN}\nrole: user\n"),
            );
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
            user: None,
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
}
