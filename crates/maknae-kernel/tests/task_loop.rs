//! #628: submitting, the tasker verbs, and the agent's claim and report, driven through
//! the real `handle()`, the real composed PDP, and a store with a manual clock.
mod common;
use common::Records;
use maknae_io::Zeroizing;
use maknae_kernel::{
    AgentAdmission, Claimed, Due, DueFor, FixedEnrollment, ManualClock, MemTaskBlobs, RootTasker,
    TaskRefusal, TaskStore, CLAIM_LEASE, REPORT_HOLD,
};
use maknae_proto::{
    Payload, ProtoErrCode, RespResult, Response, SecretText, TaskClose, TaskCursor, TaskId,
    TaskRef, TaskState, TaskSubmission, Tasker, Verb,
};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const HOBI_UID: u32 = 12_101;
const SUGA_UID: u32 = 12_102;
const OTHER: u32 = 31_337;
const T0: i64 = 1_800_000_000;

/// Every test is the same euid, so they share its store slots; a test that stalls the
/// store takes them all.
static STORE: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

struct World {
    root: common::DirGuard,
    pdp: Arc<maknae_kernel::Composition<maknae_authz_basic::HermeticAuthorizer>>,
    agents: AgentAdmission,
    clock: Arc<ManualClock>,
    blobs: MemTaskBlobs,
    me: u32,
    user: String,
    cfg: maknae_config::TransportConfig,
}

/// The uid of `nobody`, whom every test world binds to `user`.
fn another() -> u32 {
    nix::unistd::User::from_name("nobody")
        .expect("NSS")
        .expect("the host has a nobody account")
        .uid
        .as_raw()
}

fn secret(s: &str) -> SecretText {
    SecretText(Zeroizing::new(s.into()))
}

const LEAF: u8 = 1;

/// Signs nothing; its current leaf is the one every test task carries.
struct FixedSigner;

impl maknae_kernel::TaskSigner for FixedSigner {
    fn sign(
        &self,
        task: maknae_proto::TaskObject,
    ) -> Result<maknae_proto::SignedTask, TaskRefusal> {
        Ok(maknae_proto::SignedTask {
            task,
            signature: maknae_proto::TaskSignature {
                alg: "test".into(),
                leaf: maknae_proto::Bytes::new(vec![LEAF].into()),
                chain: Vec::new(),
                sig: maknae_proto::Bytes::new(vec![2].into()),
            },
        })
    }
    fn current_leaf(&self) -> Option<[u8; 32]> {
        Some(maknae_crypto::sha256(&[LEAF]))
    }
}

struct AgentFacts {
    user: String,
    dir: PathBuf,
}

impl maknae_kernel::SessionFacts for AgentFacts {
    fn membership(
        &self,
        _admission: maknae_kernel::Admission,
        _uid: u32,
    ) -> Result<maknae_kernel::Membership, maknae_kernel::AuthzError> {
        Ok(maknae_kernel::Membership {
            in_group: false,
            user: self.user.clone(),
            dir: self.dir.clone(),
        })
    }

    fn account(&self, _uid: u32) -> maknae_kernel::session_facts::AccountFact {
        maknae_kernel::session_facts::AccountFact::NotChecked(
            maknae_kernel::session_facts::NotCheckedWhy::Platform,
        )
    }
}

const PLAIN: &str = "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n";
const GRANTED: &str = "schema_version: 1\nactions:\n  allow: [\"session.task\"]\n";
const UNGRANTED: &str = "schema_version: 1\nactions:\n  allow: [\"fs.read\"]\n";
const DENIED: &str =
    "schema_version: 1\nactions:\n  allow: [\"session.task\"]\n  deny: [\"session.task\"]\n";
const TASKED_BY_HOBI: &str = "schema_version: 1\ntaskers: [\"agent:hobi\"]\n";

fn world(tag: &str, role: &str, grant: bool) -> World {
    world_with(tag, role, grant, PLAIN, PLAIN)
}

fn world_with(tag: &str, role: &str, grant: bool, hobi: &str, suga: &str) -> World {
    let dir = std::env::temp_dir().join(format!("task628_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = common::DirGuard(dir.canonicalize().unwrap());
    let paths = maknae_authz_basic::PolicyPaths::in_dir(&root);
    let roles = match (grant, role) {
        (false, _) => String::new(),
        (true, "user") => "roles:\n  user:\n    allow: [\"session.task\"]\n".to_string(),
        (true, _) => format!(
            "roles:\n  {role}:\n    allow: [\"session.task\"]\n  user:\n    allow: [\"session.task\"]\n"
        ),
    };
    common::write_0640(
        &paths.authz,
        &format!("schema_version: 1\npermissions:\n  allow: []\n  deny: []\n{roles}"),
    );
    common::write_0640(&paths.sensitive, common::EMPTY_SENSITIVE);
    let user = common::euid_name();
    common::write_0640(
        &paths.bindings,
        &match role {
            "user" => {
                format!("schema_version: 1\nbindings:\n  user: [\"{user}\", \"nobody\"]\n")
            }
            _ => format!(
                "schema_version: 1\nbindings:\n  {role}: [\"{user}\"]\n  user: [\"nobody\"]\n"
            ),
        },
    );
    let agents_dir = root.join(maknae_config::AGENTS_DIR);
    std::fs::create_dir_all(&agents_dir).unwrap();
    std::fs::set_permissions(&agents_dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    for (id, uid, policy) in [("hobi", HOBI_UID, hobi), ("suga", SUGA_UID, suga)] {
        let d = agents_dir.join(id);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o750)).unwrap();
        common::write_0640(
            &d.join(maknae_config::ENROLLMENT_FILE),
            &format!("agent_id: {id}\naccount: {id}-svc\nuid: {uid}\nrole: user\n"),
        );
        common::write_0640(&d.join(maknae_config::POLICY_FILE), policy);
    }
    let me = nix::unistd::geteuid().as_raw();
    let basic = maknae_authz_basic::HermeticAuthorizer::new(
        paths,
        maknae_config::Principal {
            name: "operator".into(),
            uid: me + 1,
        },
        maknae_config::TargetRequired {
            owner: None,
            mode_mask: Some(0o022),
            nlink_exactly_one: false,
            regular_file: true,
            max_bytes: None,
        },
        maknae_crypto::sha256,
    )
    .unwrap();
    basic.set_hosts(maknae_authz_basic::HostLookups {
        account: |uid| {
            let name = match uid {
                HOBI_UID => "hobi-svc",
                SUGA_UID => "suga-svc",
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
        },
        daemons: || {
            Ok(maknae_io::DaemonFacts {
                uids: Vec::new(),
                gids: Vec::new(),
            })
        },
        group: |_| Ok(None),
    });
    basic.reload_from_file().unwrap();
    let us = &maknae_config::BasicPolicy;
    let pdp = Arc::new(maknae_kernel::Composition::new(
        basic,
        maknae_kernel::CeilingAuthorizer::new(maknae_config::Ceiling::baseline_for(us), us),
    ));
    let clock = Arc::new(ManualClock::at(T0));
    let blobs = MemTaskBlobs::default();
    let tasks =
        Arc::new(TaskStore::open(Box::new(blobs.clone()), clock.clone()).expect("an empty store"));
    let agents = AgentAdmission {
        view: Arc::new(maknae_kernel::SnapshotEnrollment(Arc::clone(&pdp))),
        tasks,
        signer: Arc::new(FixedSigner),
    };
    let mut cfg = maknae_config::transport_from_section(None).unwrap();
    cfg.prompt_max_bytes = maknae_config::PROMPT_MAX_BYTES_FLOOR;
    World {
        root,
        pdp,
        agents,
        clock,
        blobs,
        me,
        user,
        cfg,
    }
}

impl World {
    fn store(&self) -> &TaskStore {
        &self.agents.tasks
    }

    async fn raw(&self, verb: Verb, records: &Arc<Records>) -> Vec<u8> {
        let _shared = STORE.read().await;
        self.raw_alone(verb, records).await
    }

    async fn raw_alone(&self, verb: Verb, records: &Arc<Records>) -> Vec<u8> {
        let session = maknae_kernel::SessionRecord::for_test(self.me, Some(self.user.clone()))
            .with_session_id(628);
        let gate = maknae_kernel::FactsGate::allow_as(
            Some(self.user.clone()),
            Some(PathBuf::from(&*self.root)),
        );
        self.serve(session, gate, verb, None, records, None).await
    }

    /// One request on the agent channel as `agent`, citing `task`.
    async fn agent_raw(
        &self,
        agent: &str,
        verb: Verb,
        task: Option<TaskId>,
        records: &Arc<Records>,
    ) -> Vec<u8> {
        self.agent_raw_delegating(agent, verb, task, records, None)
            .await
    }

    async fn agent_raw_delegating(
        &self,
        agent: &str,
        verb: Verb,
        task: Option<TaskId>,
        records: &Arc<Records>,
        dir: Option<&std::path::Path>,
    ) -> Vec<u8> {
        let _shared = STORE.read().await;
        let uid = if agent == "hobi" { HOBI_UID } else { SUGA_UID };
        let mut session = maknae_kernel::SessionRecord::for_test(uid, Some(format!("{agent}-svc")))
            .with_session_id(629);
        session.admission = maknae_kernel::Admission::EnrolledAgent;
        session.channel = maknae_kernel::SessionChannel::Agent {
            agent: maknae_config::AgentId::parse(agent).unwrap(),
            leaf_expires: std::time::Instant::now() + Duration::from_secs(3600),
        };
        let gate = maknae_kernel::FactsGate::for_test(
            Arc::new(AgentFacts {
                user: format!("{agent}-svc"),
                dir: PathBuf::from(&*self.root),
            }),
            Duration::from_secs(5),
        );
        self.serve(session, gate, verb, task, records, dir).await
    }

    async fn agent_with(
        &self,
        agent: &str,
        verb: Verb,
        task: Option<TaskId>,
        records: &Arc<Records>,
    ) -> Option<RespResult> {
        let raw = self.agent_raw(agent, verb, task, records).await;
        let mut cursor = &raw[..];
        let frame = common::read_frame(&mut cursor, 1 << 20).await.ok()?;
        Some(maknae_proto::decode_response(&frame).unwrap().result)
    }

    async fn agent(&self, agent: &str, verb: Verb, task: Option<TaskId>) -> RespResult {
        let records = Records::new(0);
        self.agent_with(agent, verb, task, &records)
            .await
            .unwrap_or_else(|| panic!("no answer: {:?}", reasons(&records)))
    }

    /// `agent` claims; the delivered task and its partition, or `None` when idle.
    async fn claim(&self, agent: &str) -> Option<(maknae_proto::SignedTask, String)> {
        match self.agent(agent, CLAIM, None).await {
            RespResult::Ok(Payload::TaskDelivered(d)) => {
                let signed: maknae_proto::SignedTask =
                    ciborium::from_reader(d.signed.0.as_slice()).expect("a signed task");
                Some((signed, d.partition))
            }
            RespResult::Ok(Payload::TaskIdle) => None,
            other => panic!("claim: {other:?}"),
        }
    }

    async fn claimed(&self, agent: &str) -> TaskId {
        self.claim(agent).await.expect("a task").0.task.task_id
    }

    async fn beat(&self, agent: &str, seen: u32) -> RespResult {
        self.agent(
            agent,
            Verb::TaskClaim {
                seen_follow_ups: Some(seen),
            },
            None,
        )
        .await
    }

    /// Whether a request citing `task` was refused for citing a task that is not working.
    async fn cannot_cite(&self, agent: &str, verb: Verb, task: TaskId) -> bool {
        let records = Records::new(0);
        let got = self.agent_with(agent, verb, Some(task), &records).await;
        let cause = format!("task-not-working:{task}");
        got.is_none_or(|r| unauthorized(&r))
            && records
                .snapshot()
                .iter()
                .any(|r| r.outcome.result == "deny" && r.outcome.reason.contains(&cause))
    }

    async fn agent_reports(&self, agent: &str, id: &TaskId, text: &str) -> RespResult {
        self.agent(agent, Verb::TaskReport { text: secret(text) }, Some(*id))
            .await
    }

    /// The same disk and clock under a store opened afresh, as after a restart.
    fn restarted(&self) -> World {
        let tasks = Arc::new(
            TaskStore::open(Box::new(self.blobs.clone()), self.clock.clone()).expect("reopens"),
        );
        World {
            root: common::DirGuard(self.root.0.clone()),
            pdp: Arc::clone(&self.pdp),
            agents: AgentAdmission {
                view: self.agents.view.clone(),
                tasks,
                signer: self.agents.signer.clone(),
            },
            clock: self.clock.clone(),
            blobs: self.blobs.clone(),
            me: self.me,
            user: self.user.clone(),
            cfg: self.cfg.clone(),
        }
    }

    async fn serve(
        &self,
        session: maknae_kernel::SessionRecord,
        gate: Arc<maknae_kernel::FactsGate>,
        verb: Verb,
        task: Option<TaskId>,
        records: &Arc<Records>,
        dir: Option<&std::path::Path>,
    ) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let delegated = maknae_io::DelegatedFds::new(4);
        if let Some(dir) = dir {
            delegated.push(std::fs::File::open(dir).unwrap().into());
        }
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let served = maknae_kernel::handle_with_attempt_caps(
            server,
            Some("spiffe://d/plane/cli".into()),
            Arc::new(session),
            gate,
            Arc::clone(records),
            self.cfg.clone(),
            serde_json::json!({}),
            Arc::clone(&self.pdp),
            Arc::new(maknae_kernel::LiveConfig::new(Default::default(), None)),
            Arc::new("basic+ceiling".into()),
            Arc::new("US".into()),
            Arc::new("ml-dsa-87".to_string()),
            Arc::new(None),
            maknae_kernel::unavailable_egress(),
            Duration::from_secs(2),
            delegated,
            common::no_baseline(),
            maknae_kernel::AttemptCaps::default(),
            common::conversations(),
            self.agents.clone(),
        );
        let serving = tokio::spawn(served);
        let body = maknae_proto::encode_request(&maknae_proto::Request {
            task,
            protocol_version: maknae_proto::PROTOCOL_VERSION,
            verb,
        })
        .unwrap();
        common::write_frame(&mut client, &body).await.unwrap();
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut received))
            .await
            .expect("the daemon closes within 5s")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .unwrap()
            .unwrap();
        received
    }

    async fn ask_with(&self, verb: Verb, records: &Arc<Records>) -> RespResult {
        let raw = self.raw(verb, records).await;
        let mut cursor = &raw[..];
        let frame = common::read_frame(&mut cursor, 1 << 20)
            .await
            .expect("one frame");
        let resp: Response = maknae_proto::decode_response(&frame).unwrap();
        resp.result
    }

    async fn ask(&self, verb: Verb) -> RespResult {
        self.ask_with(verb, &Records::new(0)).await
    }

    async fn submit(&self, agent: &str, prompt: &str) -> TaskId {
        match self.ask(submit(agent, prompt)).await {
            RespResult::Ok(Payload::TaskAccepted(v)) => v.task.to_id(),
            other => panic!("submit refused: {other:?}"),
        }
    }

    fn insert(&self, agent: &str, uid: u32, tasker: Tasker) -> TaskId {
        use maknae_kernel::TaskObjectForTest;
        let mut task = maknae_proto::TaskObject::for_test(agent, 0);
        task.tasker = tasker;
        self.store()
            .insert_for_test(
                maknae_proto::SignedTask {
                    task,
                    signature: maknae_proto::TaskSignature {
                        alg: "test".into(),
                        leaf: maknae_proto::Bytes::new(vec![1].into()),
                        chain: Vec::new(),
                        sig: maknae_proto::Bytes::new(vec![2].into()),
                    },
                },
                uid,
            )
            .task
            .task_id
    }

    fn mine(&self, agent: &str) -> TaskId {
        let uid = if agent == "hobi" { HOBI_UID } else { SUGA_UID };
        self.insert(agent, uid, Tasker::Uid(self.me))
    }

    /// A task from another person who holds the `user` role, as a hand-out requires.
    fn anothers(&self, agent: &str) -> TaskId {
        let uid = if agent == "hobi" { HOBI_UID } else { SUGA_UID };
        self.insert(agent, uid, Tasker::Uid(another()))
    }

    fn theirs(&self, agent: &str) -> TaskId {
        let uid = if agent == "hobi" { HOBI_UID } else { SUGA_UID };
        self.insert(agent, uid, Tasker::Uid(OTHER))
    }

    fn working(&self, id: &TaskId) {
        self.store().start_for_test(id);
    }

    fn report(&self, id: &TaskId, text: &str) {
        self.store().publish_report(id, secret(text), None).unwrap();
    }
}

fn submit(agent: &str, prompt: &str) -> Verb {
    Verb::TaskSubmit {
        task: TaskSubmission {
            schema: maknae_proto::TASK_SCHEMA.into(),
            version: maknae_proto::TASK_VERSION,
            agent: agent.into(),
            ask: maknae_proto::Ask::Prompt {
                prompt: secret(prompt),
            },
            labels: maknae_proto::Labels {},
        },
    }
}

const CLAIM: Verb = Verb::TaskClaim {
    seen_follow_ups: None,
};

fn hobi() -> maknae_config::AgentId {
    maknae_config::AgentId::parse("hobi").unwrap()
}

fn only(pairs: &[(&str, u32)]) -> FixedEnrollment {
    FixedEnrollment(
        pairs
            .iter()
            .map(|(a, u)| (maknae_config::AgentId::parse(a).unwrap(), *u))
            .collect(),
    )
}

fn follow_ups(r: RespResult) -> (u32, Vec<String>) {
    match r {
        RespResult::Ok(Payload::TaskFollowUps(f)) => {
            (f.from, f.items.iter().map(|i| i.0.to_string()).collect())
        }
        other => panic!("not follow-ups: {other:?}"),
    }
}

fn holds(due: &[Due]) -> Vec<TaskId> {
    due.iter()
        .filter(|d| matches!(d.why, DueFor::Hold(_)))
        .map(|d| d.task)
        .collect()
}

fn containing(w: &World, uids: &[u32]) -> maknae_kernel::Containing<FixedEnrollment> {
    let _ = w;
    maknae_kernel::Containing(
        only(&[("hobi", HOBI_UID), ("suga", SUGA_UID)]),
        uids.iter().copied().collect(),
    )
}

fn closes(due: &[Due]) -> Vec<(TaskId, TaskClose)> {
    due.iter()
        .filter_map(|d| match d.why {
            DueFor::Close(close) => Some((d.task, close)),
            DueFor::Expiry | DueFor::Hold(_) => None,
        })
        .collect()
}

fn r(id: &TaskId) -> TaskRef {
    TaskRef::from_id(id)
}

fn list(agent: &str, after: Option<u64>) -> Verb {
    Verb::TaskList {
        agent: agent.into(),
        after: after.map(TaskCursor::from_seq),
    }
}

fn collect(agent: &str, after: Option<u64>) -> Verb {
    Verb::TaskCollect {
        agent: agent.into(),
        after: after.map(TaskCursor::from_seq),
    }
}

fn unauthorized(r: &RespResult) -> bool {
    matches!(r, RespResult::Err(e) if e.code == ProtoErrCode::Unauthorized)
}

fn page(r: RespResult) -> maknae_proto::TaskPage {
    match r {
        RespResult::Ok(Payload::TaskList(p)) => p,
        other => panic!("not a list page: {other:?}"),
    }
}

fn reports(r: RespResult) -> maknae_proto::TaskReportPage {
    match r {
        RespResult::Ok(Payload::TaskReports(p)) => p,
        other => panic!("not a report page: {other:?}"),
    }
}

fn ids(p: &maknae_proto::TaskPage) -> Vec<TaskId> {
    p.entries.iter().map(|v| v.task.to_id()).collect()
}

fn report_ids(p: &maknae_proto::TaskReportPage) -> Vec<TaskId> {
    p.entries.iter().map(|v| v.task.to_id()).collect()
}

fn reasons(records: &Records) -> Vec<String> {
    records
        .snapshot()
        .iter()
        .filter(|r| r.action == "session.task")
        .map(|r| format!("{} {}", r.outcome.result, r.outcome.reason))
        .collect()
}

#[tokio::test]
async fn a_person_submits_and_sees_the_task_queued() {
    let w = world("submit", "user", true);
    let records = Records::new(0);
    let view = match w
        .ask_with(submit("hobi", "sentinel-628-ask"), &records)
        .await
    {
        RespResult::Ok(Payload::TaskAccepted(v)) => v,
        other => panic!("{other:?}: {:?}", reasons(&records)),
    };
    assert_eq!(view.agent, "hobi");
    assert_eq!(view.state, TaskState::Queued);
    assert_eq!(view.close, None);
    assert_eq!(view.submitted_secs, T0);
    let rec = w.store().record(&view.task.to_id()).expect("stored");
    assert!(!rec.pending);
    assert_eq!(rec.tasker, Tasker::Uid(w.me));
    assert_eq!(rec.root, RootTasker::Person { uid: w.me });
    let trail = reasons(&records);
    assert!(trail.iter().any(|t| t == "permit task stored"), "{trail:?}");
    assert!(records
        .snapshot()
        .iter()
        .all(|r| !format!("{r:?}").contains("sentinel-628-ask")));
}

#[tokio::test]
async fn status_reports_elapsed_actions_and_last_action_and_nothing_about_others() {
    let w = world("status", "user", true);
    w.theirs("hobi");
    let id = w.submit("hobi", "a").await;
    w.theirs("hobi");
    w.working(&id);
    w.store().act_for_test(&id, T0 + 30);
    w.store().act_for_test(&id, T0 + 40);
    w.clock.set(T0 + 42);
    let view = match w.ask(Verb::TaskStatus { task: r(&id) }).await {
        RespResult::Ok(Payload::TaskState(v)) => v,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        view,
        maknae_proto::TaskView {
            task: r(&id),
            agent: "hobi".into(),
            state: TaskState::Working,
            close: None,
            submitted_secs: T0,
            elapsed_secs: 42,
            actions: 2,
            last_action_secs: Some(T0 + 40),
        }
    );
}

#[tokio::test]
async fn list_shows_only_the_callers_tasks_with_that_agent_even_for_admin() {
    let w = world("list-admin", "admin", true);
    let a = w.mine("hobi");
    w.theirs("hobi");
    w.mine("suga");
    let b = w.mine("hobi");
    w.theirs("hobi");
    let p = page(w.ask(list("hobi", None)).await);
    assert_eq!(ids(&p), vec![a, b]);
    assert_eq!(p.next, None);
    let p = page(w.ask(list("nobody", None)).await);
    assert!(p.entries.is_empty());
    assert!(unauthorized(&w.ask(list("Not An Agent", None)).await));
}

#[tokio::test]
async fn list_and_collect_page_oldest_first() {
    let w = world("paging", "user", true);
    let all: Vec<TaskId> = (0..40).map(|_| w.mine("hobi")).collect();
    let first = page(w.ask(list("hobi", None)).await);
    assert_eq!(ids(&first), all[..32]);
    let next = first.next.clone().expect("a second page");
    let second = page(w.ask(list("hobi", Some(next.seq()))).await);
    assert_eq!(ids(&second), all[32..]);
    assert_eq!(second.next, None);

    for id in all.iter().rev() {
        w.report(id, "done");
    }
    let mut want: Vec<TaskId> = all.clone();
    want.reverse();
    let first = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(report_ids(&first), want[..32]);
    let upto = first.next.clone().expect("more reports remain");
    assert_eq!(upto, first.entries.last().unwrap().cursor);
    let second = reports(w.ask(collect("hobi", Some(upto.seq()))).await);
    assert_eq!(report_ids(&second), want[32..]);
    assert_eq!(second.next, None);
}

#[tokio::test]
async fn a_foreign_task_id_is_indistinguishable_from_an_unknown_one() {
    let w = world("foreign", "user", true);
    let foreign = w.theirs("hobi");
    let foreign_working = w.theirs("hobi");
    w.working(&foreign_working);
    let unknown = TaskId([0x5a; 16]);
    for target in [foreign, foreign_working] {
        for verb in [
            |t: TaskRef| Verb::TaskStatus { task: t },
            |t: TaskRef| Verb::TaskStop { task: t },
            |t: TaskRef| Verb::TaskDrop { task: t },
            |t: TaskRef| Verb::TaskAdd {
                task: t,
                text: SecretText(Zeroizing::new("more".into())),
            },
        ] {
            let (fr, ur) = (Records::new(0), Records::new(0));
            let theirs = w.raw(verb(r(&target)), &fr).await;
            let none = w.raw(verb(r(&unknown)), &ur).await;
            assert_eq!(theirs, none, "{:?}", verb(r(&target)));
            assert_eq!(reasons(&fr), reasons(&ur));
        }
    }
    let rec = w.store().record(&foreign_working).unwrap();
    assert_eq!(rec.state, TaskState::Working);
    assert!(rec.follow_ups.is_empty());
    assert!(w.store().record(&foreign).is_some());
}

#[tokio::test]
async fn drop_withdraws_a_queued_task_and_refuses_a_working_one() {
    let w = world("drop", "user", true);
    let queued = w.submit("hobi", "a").await;
    let working = w.submit("hobi", "b").await;
    w.working(&working);
    match w.ask(Verb::TaskDrop { task: r(&queued) }).await {
        RespResult::Ok(Payload::TaskAcknowledged(v)) => {
            assert_eq!(v.state, TaskState::Closed);
            assert_eq!(v.close, Some(TaskClose::Dropped));
        }
        other => panic!("{other:?}"),
    }
    assert!(w.store().record(&queued).is_none());
    assert!(unauthorized(
        &w.ask(Verb::TaskDrop { task: r(&working) }).await
    ));
    assert_eq!(
        w.store().record(&working).unwrap().state,
        TaskState::Working
    );
    assert!(unauthorized(
        &w.ask(Verb::TaskDrop { task: r(&queued) }).await
    ));
}

#[tokio::test]
async fn stop_closes_a_working_task_with_notice_stopped() {
    let w = world("stop", "user", true);
    let queued = w.submit("hobi", "a").await;
    let working = w.submit("hobi", "b").await;
    w.working(&working);
    assert!(unauthorized(
        &w.ask(Verb::TaskStop { task: r(&queued) }).await
    ));
    match w.ask(Verb::TaskStop { task: r(&working) }).await {
        RespResult::Ok(Payload::TaskAcknowledged(v)) => {
            assert_eq!(v.state, TaskState::Closed);
            assert_eq!(v.close, Some(TaskClose::Stopped));
        }
        other => panic!("{other:?}"),
    }
    let p = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(report_ids(&p), vec![working]);
    assert_eq!(p.entries[0].close, Some(TaskClose::Stopped));
    assert!(unauthorized(
        &w.ask(Verb::TaskStop { task: r(&working) }).await
    ));
}

#[tokio::test]
async fn add_appends_a_follow_up_to_the_running_task_only() {
    let w = world("add", "user", true);
    let queued = w.submit("hobi", "a").await;
    let working = w.submit("hobi", "b").await;
    w.working(&working);
    let add = |id: &TaskId, text: &str| Verb::TaskAdd {
        task: r(id),
        text: secret(text),
    };
    assert!(unauthorized(&w.ask(add(&queued, "more")).await));
    assert!(w.store().record(&queued).unwrap().follow_ups.is_empty());
    assert!(matches!(
        w.ask(add(&working, "sentinel-628-more")).await,
        RespResult::Ok(Payload::TaskAcknowledged(_))
    ));
    let held = w.store().record(&working).unwrap().follow_ups;
    assert_eq!(held.len(), 1);
    assert_eq!(&*held[0].0, "sentinel-628-more");
}

#[tokio::test]
async fn the_33rd_follow_up_and_one_byte_over_the_total_are_refused() {
    let w = world("add-caps", "user", true);
    let max = w.cfg.prompt_max_bytes;
    let id = w.submit("hobi", "a").await;
    w.working(&id);
    let add = |text: String| Verb::TaskAdd {
        task: r(&id),
        text: SecretText(Zeroizing::new(text)),
    };
    for _ in 0..32 {
        assert!(matches!(
            w.ask(add("x".into())).await,
            RespResult::Ok(Payload::TaskAcknowledged(_))
        ));
    }
    let records = Records::new(0);
    assert!(unauthorized(&w.ask_with(add("x".into()), &records).await));
    assert_eq!(w.store().record(&id).unwrap().follow_ups.len(), 32);

    let id = w.submit("hobi", "b").await;
    w.working(&id);
    let add = |text: String| Verb::TaskAdd {
        task: r(&id),
        text: SecretText(Zeroizing::new(text)),
    };
    assert!(unauthorized(&w.ask(add("y".repeat(max + 1))).await));
    assert!(matches!(
        w.ask(add("y".repeat(max - 10))).await,
        RespResult::Ok(Payload::TaskAcknowledged(_))
    ));
    assert!(unauthorized(&w.ask(add("y".repeat(11))).await));
    assert!(matches!(
        w.ask(add("y".repeat(10))).await,
        RespResult::Ok(Payload::TaskAcknowledged(_))
    ));
    let total: usize = w
        .store()
        .record(&id)
        .unwrap()
        .follow_ups
        .iter()
        .map(|f| f.0.len())
        .sum();
    assert_eq!(total, max);
}

#[tokio::test]
async fn a_submission_one_byte_over_the_prompt_cap_is_refused() {
    let w = world("submit-cap", "user", true);
    let max = w.cfg.prompt_max_bytes;
    assert!(unauthorized(
        &w.ask(submit("hobi", &"z".repeat(max + 1))).await
    ));
    assert!(matches!(
        w.ask(submit("hobi", &"z".repeat(max))).await,
        RespResult::Ok(Payload::TaskAccepted(_))
    ));
}

#[tokio::test]
async fn collect_returns_each_report_until_acknowledged_and_never_after() {
    let w = world("collect", "user", true);
    let a = w.mine("hobi");
    let b = w.mine("hobi");
    w.report(&a, "sentinel-628-report-a");
    let first = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(report_ids(&first), vec![a]);
    assert_eq!(&*first.entries[0].text.0, "sentinel-628-report-a");
    let again = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(report_ids(&again), vec![a]);
    let upto = first.entries[0].cursor.seq();
    let after = reports(w.ask(collect("hobi", Some(upto))).await);
    assert!(after.entries.is_empty());
    assert!(w.store().record(&a).is_none());
    w.report(&b, "b");
    let later = reports(w.ask(collect("hobi", Some(upto))).await);
    assert_eq!(report_ids(&later), vec![b]);
    assert!(unauthorized(
        &w.ask(collect("hobi", Some(upto + 100))).await
    ));
}

#[tokio::test]
async fn a_report_landing_after_the_page_is_never_acknowledged_unseen() {
    let w = world("collect-race", "user", true);
    let older = w.mine("hobi");
    let newer = w.mine("hobi");
    w.report(&newer, "newer");
    let first = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(report_ids(&first), vec![newer]);
    w.report(&older, "older");
    let upto = first.entries[0].cursor.seq();
    let second = reports(w.ask(collect("hobi", Some(upto))).await);
    assert_eq!(report_ids(&second), vec![older]);
    assert!(w.store().record(&older).is_some());
    assert!(w.store().record(&newer).is_none());
}

#[tokio::test]
async fn acknowledging_one_agents_reports_leaves_another_agents_untouched() {
    let w = world("collect-agents", "user", true);
    let h = w.mine("hobi");
    let s = w.mine("suga");
    w.report(&s, "suga");
    w.report(&h, "hobi");
    let hp = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(report_ids(&hp), vec![h]);
    let upto = hp.entries[0].cursor.seq();
    reports(w.ask(collect("hobi", Some(upto))).await);
    assert!(w.store().record(&h).is_none());
    assert!(w.store().record(&s).is_some());
    let sp = reports(w.ask(collect("suga", None)).await);
    assert_eq!(report_ids(&sp), vec![s]);
}

#[tokio::test]
async fn submission_without_session_task_is_refused_and_records_the_cause() {
    let w = world("no-grant", "user", false);
    let records = Records::new(0);
    let got = w.ask_with(submit("hobi", "a"), &records).await;
    assert!(unauthorized(&got), "{got:?}");
    assert!(w
        .store()
        .queue(&maknae_config::AgentId::parse("hobi").unwrap())
        .is_empty());
    let trail = reasons(&records);
    assert!(
        trail
            .iter()
            .any(|t| t.starts_with("deny") && t.contains("no rule for session.task")),
        "{trail:?}"
    );
}

#[tokio::test]
async fn a_tasker_at_its_live_cap_or_held_cap_is_refused() {
    let w = world("caps", "user", true);
    for _ in 0..maknae_kernel::MAX_LIVE_TASKS_PER_TASKER_PER_AGENT {
        w.mine("hobi");
    }
    let records = Records::new(0);
    assert!(unauthorized(
        &w.ask_with(submit("hobi", "a"), &records).await
    ));
    assert!(
        reasons(&records)
            .iter()
            .any(|t| t.starts_with("deny") && t.contains("live tasks with agent hobi")),
        "{:?}",
        reasons(&records)
    );
    w.submit("suga", "other agent still takes it").await;

    let w = world("caps-held", "user", true);
    for i in 0..maknae_kernel::MAX_HELD_REPORTS_PER_TASKER {
        let id = w.mine(if i % 2 == 0 { "hobi" } else { "suga" });
        w.report(&id, "r");
    }
    let records = Records::new(0);
    assert!(unauthorized(
        &w.ask_with(submit("hobi", "a"), &records).await
    ));
    assert!(
        reasons(&records)
            .iter()
            .any(|t| t.starts_with("deny") && t.contains("held reports")),
        "{:?}",
        reasons(&records)
    );
}

#[tokio::test]
async fn a_submission_whose_audit_fails_leaves_no_task() {
    let w = world("audit-fails", "user", true);
    let records = Records::new(2);
    let got = w.raw(submit("hobi", "a"), &records).await;
    assert!(
        got.is_empty() || {
            let mut c = &got[..];
            let f = common::read_frame(&mut c, 1 << 20).await.unwrap();
            unauthorized(&maknae_proto::decode_response(&f).unwrap().result)
        }
    );
    assert!(w
        .store()
        .queue(&maknae_config::AgentId::parse("hobi").unwrap())
        .is_empty());
    assert_eq!(w.store().count_for_test(), 0);
}

#[tokio::test]
async fn a_full_size_report_is_collected_whole_and_alone() {
    let w = world("collect-full", "user", true);
    let max = w.cfg.prompt_max_bytes;
    let a = w.mine("hobi");
    let b = w.mine("hobi");
    w.report(&a, &"r".repeat(max));
    w.report(&b, &"s".repeat(max));
    let first = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(report_ids(&first), vec![a]);
    assert_eq!(first.entries[0].text.0.len(), max);
    let upto = first
        .next
        .expect("the small report waits for the next page");
    let second = reports(w.ask(collect("hobi", Some(upto.seq()))).await);
    assert_eq!(report_ids(&second), vec![b]);
}

fn task_records(records: &Records) -> Vec<maknae_audit_append::AuditRecord> {
    records
        .snapshot()
        .into_iter()
        .filter(|r| r.action == "session.task")
        .collect()
}

#[tokio::test]
async fn every_task_record_names_its_op_and_its_tasker() {
    let w = world("records", "user", true);
    let id = w.submit("hobi", "a").await;
    w.working(&id);
    let me = format!("uid:{}", w.me);
    for (verb, op) in [
        (submit("hobi", "b"), "submit"),
        (Verb::TaskStatus { task: r(&id) }, "status"),
        (
            Verb::TaskAdd {
                task: r(&id),
                text: secret("more"),
            },
            "add",
        ),
        (list("hobi", None), "list"),
        (Verb::TaskStop { task: r(&id) }, "stop"),
        (Verb::TaskDrop { task: r(&id) }, "drop"),
        (collect("hobi", Some(1)), "collect"),
    ] {
        let records = Records::new(0);
        w.ask_with(verb, &records).await;
        let recs = task_records(&records);
        assert!(!recs.is_empty(), "{op}");
        for rec in recs {
            assert_eq!(rec.subject.task_op.as_deref(), Some(op), "{op}: {rec:?}");
            assert_eq!(rec.subject.tasker.as_deref(), Some(me.as_str()), "{op}");
            assert_eq!(rec.subject.agent, None, "{op}");
            assert!(
                !rec.outcome.reason.starts_with(&format!("{op}:")),
                "{op}: {}",
                rec.outcome.reason
            );
        }
    }
}

#[tokio::test]
async fn a_callers_cursors_do_not_count_another_taskers_tasks() {
    let cursors = |busy: bool| async move {
        let w = world(
            if busy {
                "cursors-busy"
            } else {
                "cursors-quiet"
            },
            "user",
            true,
        );
        let mut mine = Vec::new();
        for _ in 0..33 {
            if busy {
                let t = w.theirs("hobi");
                w.report(&t, "theirs");
            }
            mine.push(w.mine("hobi"));
        }
        for id in &mine {
            if busy {
                let t = w.theirs("hobi");
                w.report(&t, "theirs");
            }
            w.report(id, "mine");
        }
        let listed = page(w.ask(list("hobi", None)).await).next;
        let first = reports(w.ask(collect("hobi", None)).await);
        let seen: Vec<TaskCursor> = first.entries.iter().map(|e| e.cursor.clone()).collect();
        let ahead = unauthorized(&w.ask(collect("hobi", Some(34))).await);
        (listed, seen, first.next, ahead)
    };
    let quiet = cursors(false).await;
    let busy = cursors(true).await;
    assert_eq!(quiet, busy);
    assert!(quiet.3, "a cursor past the caller's own reports is refused");
    assert_eq!(quiet.0, Some(TaskCursor::from_seq(32)));
}

#[tokio::test]
async fn a_store_that_does_not_answer_in_time_is_refused_as_unavailable() {
    let w = world("store-slow", "user", true);
    let id = w.submit("hobi", "a").await;
    w.working(&id);
    let _alone = STORE.write().await;
    w.blobs.slow(Some(Duration::from_millis(2500)));
    let records = Records::new(0);
    let raw = w
        .raw_alone(
            Verb::TaskAdd {
                task: r(&id),
                text: secret("more"),
            },
            &records,
        )
        .await;
    let mut cursor = &raw[..];
    let frame = common::read_frame(&mut cursor, 1 << 20).await.unwrap();
    let got = maknae_proto::decode_response(&frame).unwrap().result;
    assert!(unauthorized(&got), "{got:?}");
    let last = task_records(&records).pop().unwrap();
    assert_eq!(
        (last.outcome.result.as_str(), last.outcome.posture.as_str()),
        ("permit", "unavailable")
    );
    assert!(
        last.outcome.reason == "outcome unknown: the task store did not answer in time",
        "{}",
        last.outcome.reason
    );
    w.blobs.slow(None);
    let landed = tokio::time::Instant::now() + Duration::from_secs(3);
    while w.store().record(&id).unwrap().follow_ups.is_empty() {
        assert!(
            tokio::time::Instant::now() < landed,
            "the late write never lands"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn an_agent_claims_in_fifo_order_across_taskers() {
    let w = world("claim-fifo", "user", true);
    let a = w.anothers("hobi");
    let b = w.submit("hobi", "sentinel-628-b").await;
    let c = w.anothers("hobi");
    w.mine("suga");
    let (first, partition) = w.claim("hobi").await.expect("the oldest task");
    assert_eq!(first.task.task_id, a);
    assert_eq!(partition, format!("tasks/users/{}", another()));
    let rec = w.store().record(&a).unwrap();
    assert_eq!((rec.state, rec.claimed), (TaskState::Working, Some(T0)));
    assert_eq!(w.store().record(&b).unwrap().state, TaskState::Queued);
    assert!(matches!(
        w.agent_reports("hobi", &a, "ra").await,
        RespResult::Ok(Payload::TaskAcknowledged(v)) if v.state == TaskState::Reported
    ));
    let (second, partition) = w.claim("hobi").await.expect("the next task");
    assert_eq!(second.task.task_id, b);
    assert_eq!(partition, format!("tasks/users/{}", w.me));
    let maknae_proto::Ask::Prompt { prompt } = &second.task.ask;
    assert_eq!(&*prompt.0, "sentinel-628-b");
    w.agent_reports("hobi", &b, "rb").await;
    assert_eq!(w.claimed("hobi").await, c);
    w.agent_reports("hobi", &c, "rc").await;
    assert!(w.claim("hobi").await.is_none(), "suga's task is not hobi's");
}

#[tokio::test]
async fn claim_with_none_redelivers_the_working_task_and_some_returns_only_new_follow_ups() {
    let w = world("claim-again", "user", true);
    let id = w.submit("hobi", "a").await;
    let later = w.submit("hobi", "b").await;
    assert_eq!(w.claimed("hobi").await, id);
    assert_eq!(w.claimed("hobi").await, id, "the working task again");
    assert_eq!(w.store().record(&later).unwrap().state, TaskState::Queued);
    assert_eq!(follow_ups(w.beat("hobi", 0).await), (0, vec![]));
    for text in ["f1", "f2"] {
        w.ask(Verb::TaskAdd {
            task: r(&id),
            text: secret(text),
        })
        .await;
    }
    assert_eq!(
        follow_ups(w.beat("hobi", 0).await),
        (0, vec!["f1".to_string(), "f2".to_string()])
    );
    assert_eq!(
        follow_ups(w.beat("hobi", 1).await),
        (1, vec!["f2".to_string()])
    );
    assert_eq!(follow_ups(w.beat("hobi", 2).await), (2, vec![]));
    w.ask(Verb::TaskAdd {
        task: r(&id),
        text: secret("f3"),
    })
    .await;
    assert_eq!(
        follow_ups(w.beat("hobi", 2).await),
        (2, vec!["f3".to_string()])
    );
    assert_eq!(follow_ups(w.beat("hobi", 9).await), (9, vec![]));
}

#[tokio::test]
async fn a_report_reaches_only_the_tasks_own_tasker() {
    let w = world("report-owner", "user", true);
    let theirs = w.anothers("hobi");
    let mine = w.mine("hobi");
    assert_eq!(w.claimed("hobi").await, theirs);
    w.clock.set(T0 + 7);
    let records = Records::new(0);
    let got = w
        .agent_with(
            "hobi",
            Verb::TaskReport {
                text: secret("sentinel-628-theirs"),
            },
            Some(theirs),
            &records,
        )
        .await;
    assert!(
        matches!(&got, Some(RespResult::Ok(Payload::TaskAcknowledged(v))) if v.state == TaskState::Reported),
        "{got:?}"
    );
    assert!(records
        .snapshot()
        .iter()
        .all(|r| !format!("{r:?}").contains("sentinel-628-theirs")));
    let rec = w.store().record(&theirs).unwrap();
    assert_eq!(rec.state, TaskState::Reported);
    assert_eq!(
        rec.report.as_ref().map(|(t, at)| (&**t.0, *at)),
        Some(("sentinel-628-theirs", T0 + 7))
    );
    assert!(reports(w.ask(collect("hobi", None)).await)
        .entries
        .is_empty());
    assert_eq!(w.claimed("hobi").await, mine);
    w.agent_reports("hobi", &mine, "sentinel-628-mine").await;
    let page = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(report_ids(&page), vec![mine]);
    assert_eq!(&**page.entries[0].text.0, "sentinel-628-mine");
    assert_eq!(page.entries[0].close, None);
}

#[tokio::test]
async fn a_report_needs_the_agents_own_working_task_cited() {
    let w = world("report-cited", "user", true);
    let id = w.mine("hobi");
    let sugas = w.mine("suga");
    let records = Records::new(0);
    let uncited = w
        .agent_with(
            "hobi",
            Verb::TaskReport { text: secret("r") },
            None,
            &records,
        )
        .await
        .unwrap();
    assert!(unauthorized(&uncited), "{uncited:?}");
    assert!(
        reasons(&records)
            .iter()
            .any(|t| t.starts_with("deny") && t.contains("cites no working task")),
        "{:?}",
        reasons(&records)
    );
    assert!(
        w.cannot_cite("hobi", Verb::TaskReport { text: secret("r") }, id)
            .await,
        "a queued task is not citable"
    );
    assert_eq!(w.claimed("suga").await, sugas);
    let records = Records::new(0);
    let foreign = w
        .agent_with(
            "hobi",
            Verb::TaskReport { text: secret("r") },
            Some(sugas),
            &records,
        )
        .await;
    assert!(foreign.is_none_or(|r| unauthorized(&r)));
    assert!(
        records
            .snapshot()
            .iter()
            .any(|r| r.outcome.reason.contains("task-other-agent")),
        "another agent's task"
    );
    assert_eq!(w.store().record(&sugas).unwrap().state, TaskState::Working);
    assert_eq!(w.store().record(&id).unwrap().state, TaskState::Queued);
    assert_eq!(w.claimed("hobi").await, id);
    let over = w
        .agent(
            "hobi",
            Verb::TaskReport {
                text: secret(&"r".repeat(w.cfg.prompt_max_bytes + 1)),
            },
            Some(id),
        )
        .await;
    assert!(unauthorized(&over), "one byte over is refused");
    assert_eq!(w.store().record(&id).unwrap().state, TaskState::Working);
}

#[tokio::test]
async fn a_sub_tasks_report_is_collected_by_the_submitting_agent() {
    let w = world_with("sub-report", "user", true, PLAIN, TASKED_BY_HOBI);
    let parent = w.submit("hobi", "parent").await;
    assert_eq!(w.claimed("hobi").await, parent);
    let sub = match w.agent("hobi", submit("suga", "sub"), Some(parent)).await {
        RespResult::Ok(Payload::TaskAccepted(v)) => v.task.to_id(),
        other => panic!("{other:?}"),
    };
    let rec = w.store().record(&sub).unwrap();
    assert_eq!(rec.parent, Some(parent));
    assert_eq!(rec.root, RootTasker::Person { uid: w.me });
    let (task, partition) = w.claim("suga").await.expect("the sub-task");
    assert_eq!(task.task.task_id, sub);
    assert_eq!(
        partition,
        format!("tasks/users/{}", w.me),
        "the root person's partition"
    );
    w.agent_reports("hobi", &parent, "parent done").await;
    w.agent_reports("suga", &sub, "sentinel-628-sub").await;
    assert!(
        reports(w.ask(collect("suga", None)).await)
            .entries
            .is_empty(),
        "the person did not submit the sub-task"
    );
    let page = reports(w.agent("hobi", collect("suga", None), None).await);
    assert_eq!(report_ids(&page), vec![sub]);
    assert_eq!(&**page.entries[0].text.0, "sentinel-628-sub");
}

#[tokio::test]
async fn an_agent_denied_session_task_still_claims_and_reports_but_cannot_submit() {
    let w = world_with("held-not-granted", "user", true, DENIED, TASKED_BY_HOBI);
    let id = w.submit("hobi", "a").await;
    assert_eq!(w.claimed("hobi").await, id);
    assert_eq!(follow_ups(w.beat("hobi", 0).await), (0, vec![]));
    let records = Records::new(0);
    let refused = w
        .agent_with("hobi", submit("suga", "sub"), Some(id), &records)
        .await
        .unwrap();
    assert!(unauthorized(&refused), "{refused:?}");
    assert!(
        reasons(&records)
            .iter()
            .any(|t| t.starts_with("deny") && t.contains("session.task denied by")),
        "{:?}",
        reasons(&records)
    );
    assert!(matches!(
        w.agent_reports("hobi", &id, "done").await,
        RespResult::Ok(Payload::TaskAcknowledged(v)) if v.state == TaskState::Reported
    ));
}

#[tokio::test]
async fn claim_and_report_are_refused_on_the_client_channel() {
    let w = world("client-claims", "admin", true);
    let id = w.mine("hobi");
    for verb in [
        CLAIM,
        Verb::TaskClaim {
            seen_follow_ups: Some(0),
        },
        Verb::TaskReport { text: secret("r") },
    ] {
        let records = Records::new(0);
        let got = w.ask_with(verb.clone(), &records).await;
        assert!(unauthorized(&got), "{verb:?}: {got:?}");
        assert!(
            reasons(&records)
                .iter()
                .any(|t| t.starts_with("deny") && t.contains("on the agent channel")),
            "{:?}",
            reasons(&records)
        );
    }
    assert_eq!(w.store().record(&id).unwrap().state, TaskState::Queued);
}

#[tokio::test]
async fn cited_requests_count_actions_and_renew_the_lease() {
    let w = world("counted", "user", true);
    let id = w.submit("hobi", "a").await;
    assert_eq!(w.claimed("hobi").await, id);
    let lease = CLAIM_LEASE.as_secs() as i64;
    let hot = w.store().hot(&id).unwrap();
    assert_eq!(
        (hot.actions, hot.last_action, hot.lease_until),
        (0, None, T0 + lease)
    );
    w.clock.set(T0 + 100);
    assert!(matches!(
        w.agent("hobi", Verb::Ping, Some(id)).await,
        RespResult::Ok(_)
    ));
    let hot = w.store().hot(&id).unwrap();
    assert_eq!(
        (hot.actions, hot.last_action, hot.lease_until),
        (1, Some(T0 + 100), T0 + 100 + lease)
    );
    w.clock.set(T0 + 200);
    assert!(unauthorized(
        &w.agent("hobi", Verb::AdminStatus, Some(id)).await
    ));
    assert_eq!(
        w.store().hot(&id).unwrap().actions,
        2,
        "a denied request counts"
    );
    w.agent("hobi", Verb::Ping, None).await;
    w.agent_raw(
        "hobi",
        Verb::Read {
            path: "not/absolute".into(),
            conversation: None,
            page: None,
        },
        Some(id),
        &Records::new(0),
    )
    .await;
    let hot = w.store().hot(&id).unwrap();
    assert_eq!(
        (hot.actions, hot.last_action, hot.lease_until),
        (2, Some(T0 + 200), T0 + 200 + lease),
        "an uncited request and a pre-gate refusal count nothing"
    );
    w.clock.set(T0 + 300);
    w.beat("hobi", 0).await;
    let hot = w.store().hot(&id).unwrap();
    assert_eq!((hot.actions, hot.lease_until), (2, T0 + 300 + lease));
    w.clock.set(T0 + 400);
    assert_eq!(w.claimed("hobi").await, id);
    assert_eq!(w.store().hot(&id).unwrap().lease_until, T0 + 400 + lease);
    let view = match w.ask(Verb::TaskStatus { task: r(&id) }).await {
        RespResult::Ok(Payload::TaskState(v)) => v,
        other => panic!("{other:?}"),
    };
    assert_eq!((view.actions, view.last_action_secs), (2, Some(T0 + 200)));
    w.clock.set(T0 + 500);
    w.agent_reports("hobi", &id, "done").await;
    let rec = w.store().record(&id).unwrap();
    assert_eq!(
        (rec.actions, rec.last_action),
        (3, Some(T0 + 500)),
        "the report is a cited request, and the counters are stored with it"
    );
}

#[tokio::test]
async fn a_lapsed_lease_closes_the_task_with_agent_lost() {
    let w = world("lapsed", "user", true);
    let id = w.submit("hobi", "a").await;
    let queued = w.submit("hobi", "b").await;
    assert_eq!(w.claimed("hobi").await, id);
    let lease = CLAIM_LEASE.as_secs() as i64;
    w.clock.set(T0 + lease);
    assert!(w.store().sweep().is_empty());
    assert_eq!(w.store().record(&id).unwrap().state, TaskState::Working);
    w.clock.set(T0 + lease + 1);
    let said = w.store().sweep();
    let rec = w.store().record(&id).unwrap();
    assert_eq!(
        (rec.state, rec.close),
        (TaskState::Closed, Some(TaskClose::AgentLost))
    );
    assert_eq!(
        w.store().record(&queued).unwrap().state,
        TaskState::Queued,
        "a queued task holds no lease"
    );
    assert_eq!(closes(&said), vec![(id, TaskClose::AgentLost)]);
    assert!(w.store().sweep().is_empty(), "closed once");
    let page = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(report_ids(&page), vec![id]);
    assert_eq!(page.entries[0].close, Some(TaskClose::AgentLost));
    assert!(
        page.entries[0].text.0.is_empty(),
        "the kernel writes no report text"
    );
    assert_eq!(page.entries[0].at_secs, T0 + lease + 1);
    assert!(
        w.cannot_cite("hobi", Verb::Ping, id).await,
        "the closed task is no longer citable"
    );
}

#[tokio::test]
async fn a_working_task_survives_restart_and_is_reclaimable() {
    let w = world("restart", "user", true);
    let id = w.submit("hobi", "sentinel-628-restart").await;
    assert_eq!(w.claimed("hobi").await, id);
    w.clock.set(T0 + 50);
    w.agent("hobi", Verb::Ping, Some(id)).await;
    w.store().sweep();
    let lease = CLAIM_LEASE.as_secs() as i64;
    w.clock.set(T0 + 10 * lease);
    let w = w.restarted();
    let hot = w.store().hot(&id).unwrap();
    assert_eq!(
        (hot.actions, hot.last_action, hot.lease_until),
        (1, Some(T0 + 50), T0 + 11 * lease),
        "the counters are stored; the lease runs from the restart"
    );
    w.store().retain_enrolled(&*w.agents.view);
    w.store().sweep();
    assert_eq!(w.store().record(&id).unwrap().state, TaskState::Working);
    let (task, _) = w.claim("hobi").await.expect("the working task again");
    assert_eq!(task.task.task_id, id);
    let maknae_proto::Ask::Prompt { prompt } = &task.task.ask;
    assert_eq!(&*prompt.0, "sentinel-628-restart");
    assert!(matches!(
        w.agent_reports("hobi", &id, "done").await,
        RespResult::Ok(Payload::TaskAcknowledged(_))
    ));
}

#[tokio::test]
async fn deenrolling_an_agent_closes_its_tasks_once() {
    let w = world("deenroll", "user", true);
    let reported = w.mine("hobi");
    w.working(&reported);
    w.report(&reported, "kept");
    let working = w.mine("hobi");
    w.working(&working);
    let queued = w.theirs("hobi");
    let sugas = w.mine("suga");
    assert!(w
        .store()
        .retain_enrolled(&only(&[("hobi", HOBI_UID), ("suga", SUGA_UID)]))
        .is_empty());
    let mut closed = closes(&w.store().retain_enrolled(&only(&[("suga", SUGA_UID)])));
    closed.sort_by_key(|c| c.0);
    let mut want = vec![
        (working, TaskClose::AgentGone),
        (queued, TaskClose::AgentGone),
    ];
    want.sort_by_key(|c| c.0);
    assert_eq!(closed, want);
    for id in [working, queued] {
        let rec = w.store().record(&id).unwrap();
        assert_eq!(
            (rec.state, rec.close),
            (TaskState::Closed, Some(TaskClose::AgentGone))
        );
        assert!(rec.report.as_ref().is_some_and(|(t, _)| t.0.is_empty()));
    }
    let before = w.store().record(&working).unwrap().rseq;
    assert_eq!(
        w.store().record(&reported).unwrap().state,
        TaskState::Reported
    );
    assert_eq!(w.store().record(&sugas).unwrap().state, TaskState::Queued);
    assert!(w
        .store()
        .retain_enrolled(&only(&[("suga", SUGA_UID)]))
        .is_empty());
    assert!(w.store().purge_agent(&hobi()).is_empty());
    assert_eq!(
        closes(&w.store().retain_enrolled(&only(&[]))),
        vec![(sugas, TaskClose::AgentGone)],
        "hobi's tasks are closed once"
    );
    assert_eq!(w.store().record(&working).unwrap().rseq, before);
    let reopened = w.restarted();
    assert_eq!(
        reopened.store().record(&working).unwrap().close,
        Some(TaskClose::AgentGone),
        "the close is stored"
    );
}

#[tokio::test]
async fn reenrolling_under_a_new_uid_never_closes_the_new_tasks() {
    const AGAIN: u32 = 12_201;
    let w = world("reenroll", "user", true);
    let old = w.mine("hobi");
    w.working(&old);
    let old_queued = w.mine("hobi");
    let renamed = only(&[("hobi", AGAIN), ("suga", SUGA_UID)]);
    w.store()
        .retain_enrolled(&only(&[("hobi", HOBI_UID), ("suga", SUGA_UID)]));
    let new = w.insert("hobi", AGAIN, Tasker::Uid(w.me));
    w.store().mark_unenrolled(&renamed);
    let later = w.insert("hobi", AGAIN, Tasker::Uid(w.me));
    let mut closed = closes(&w.store().retain_enrolled(&renamed));
    let generation = w.store().generation(&hobi());
    assert!(w.store().retain_enrolled(&renamed).is_empty());
    assert_eq!(
        w.store().generation(&hobi()),
        generation,
        "the closed tasks of the old uid make nothing stale"
    );
    closed.sort_by_key(|c| c.0);
    let mut want = vec![
        (old, TaskClose::AgentGone),
        (old_queued, TaskClose::AgentGone),
    ];
    want.sort_by_key(|c| c.0);
    assert_eq!(closed, want, "each old task once, the new task never");
    for id in [new, later] {
        assert_eq!(w.store().record(&id).unwrap().state, TaskState::Queued);
    }
    assert_eq!(
        w.store().claim(
            &hobi(),
            HOBI_UID,
            &FixedSigner,
            w.store().next_for(&hobi(), HOBI_UID).map(|(id, _)| id)
        ),
        Ok(Claimed::Idle),
        "the old uid is handed nothing"
    );
    match w.store().claim(
        &hobi(),
        AGAIN,
        &FixedSigner,
        w.store().next_for(&hobi(), AGAIN).map(|(id, _)| id),
    ) {
        Ok(Claimed::Delivered { signed, .. }) => assert_eq!(signed.task.task_id, new),
        other => panic!("{other:?}"),
    }
    assert!(w.store().retain_enrolled(&renamed).is_empty());
    assert_eq!(w.store().record(&new).unwrap().state, TaskState::Working);
}

#[tokio::test]
async fn an_agent_deenrolled_while_down_is_closed_before_it_can_claim() {
    let w = world("down", "user", true);
    let working = w.submit("hobi", "a").await;
    let queued = w.submit("hobi", "b").await;
    assert_eq!(w.claimed("hobi").await, working);
    let w = w.restarted();
    assert_eq!(
        w.store().record(&working).unwrap().state,
        TaskState::Working
    );
    let mut closed = closes(&w.store().retain_enrolled(&only(&[("suga", SUGA_UID)])));
    closed.sort_by_key(|c| c.0);
    let mut want = vec![
        (working, TaskClose::AgentGone),
        (queued, TaskClose::AgentGone),
    ];
    want.sort_by_key(|c| c.0);
    assert_eq!(closed, want);
    assert!(
        w.claim("hobi").await.is_none(),
        "enrolled again under the same uid, it is handed neither"
    );
    assert!(
        w.cannot_cite("hobi", Verb::Ping, working).await,
        "nor may it cite the closed task"
    );
    let w = w.restarted();
    assert!(w.claim("hobi").await.is_none(), "nor after another restart");
}

#[tokio::test]
async fn a_close_owed_by_deenrollment_is_refused_to_the_agent_before_any_writer_runs() {
    let w = world("owed-close", "user", true);
    let id = w.submit("hobi", "a").await;
    assert_eq!(w.claimed("hobi").await, id);
    w.store().mark_unenrolled(&only(&[("suga", SUGA_UID)]));
    assert_eq!(
        w.store().record(&id).unwrap().state,
        TaskState::Working,
        "nothing is recorded yet, so nothing is closed"
    );
    assert!(w.cannot_cite("hobi", Verb::Ping, id).await, "not citable");
    assert!(matches!(
        w.beat("hobi", 0).await,
        RespResult::Ok(Payload::TaskIdle)
    ));
    assert!(w.claim("hobi").await.is_none());
    w.store().pass();
    assert_eq!(
        w.store().record(&id).unwrap().state,
        TaskState::Working,
        "a writer passing closes nothing: no record has been made"
    );
    assert!(w.claim("hobi").await.is_none());
    assert_eq!(
        closes(&w.store().close_all_due()),
        vec![(id, TaskClose::AgentGone)]
    );
    assert_eq!(
        w.store().record(&id).unwrap().close,
        Some(TaskClose::AgentGone)
    );
}

#[tokio::test]
async fn nothing_is_redelivered_after_a_kernel_close() {
    let w = world("no-redelivery", "user", true);
    let lost = w.submit("hobi", "a").await;
    let gone = w.submit("hobi", "b").await;
    assert_eq!(w.claimed("hobi").await, lost);
    w.clock.set(T0 + CLAIM_LEASE.as_secs() as i64 + 1);
    w.store().sweep();
    assert_eq!(
        w.claimed("hobi").await,
        gone,
        "the lost task is not handed out again"
    );
    w.store().retain_enrolled(&only(&[("suga", SUGA_UID)]));
    assert!(w.claim("hobi").await.is_none());
    let w = w.restarted();
    assert!(w.claim("hobi").await.is_none(), "nor after a restart");
    for id in [lost, gone] {
        assert_eq!(w.store().record(&id).unwrap().state, TaskState::Closed);
    }
}

#[tokio::test]
async fn a_heartbeat_after_stop_tells_the_agent_it_was_stopped() {
    let w = world("beat-stopped", "user", true);
    let earlier = w.submit("hobi", "a").await;
    assert_eq!(w.claimed("hobi").await, earlier);
    w.agent_reports("hobi", &earlier, "done").await;
    assert!(
        matches!(w.beat("hobi", 0).await, RespResult::Ok(Payload::TaskIdle)),
        "a reported task is not a stop"
    );
    let id = w.submit("hobi", "b").await;
    w.submit("hobi", "c").await;
    assert_eq!(w.claimed("hobi").await, id);
    w.ask(Verb::TaskStop { task: r(&id) }).await;
    match w.beat("hobi", 0).await {
        RespResult::Ok(Payload::TaskState(v)) => {
            assert_eq!(v.task, r(&id));
            assert_eq!(
                (v.state, v.close),
                (TaskState::Closed, Some(TaskClose::Stopped))
            );
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_heartbeat_after_the_closed_record_is_gone_answers_idle() {
    let w = world("beat-gone", "user", true);
    let id = w.submit("hobi", "a").await;
    assert_eq!(w.claimed("hobi").await, id);
    w.ask(Verb::TaskStop { task: r(&id) }).await;
    let page = reports(w.ask(collect("hobi", None)).await);
    reports(
        w.ask(collect("hobi", Some(page.entries[0].cursor.seq())))
            .await,
    );
    assert!(w.store().record(&id).is_none());
    assert!(matches!(
        w.beat("hobi", 0).await,
        RespResult::Ok(Payload::TaskIdle)
    ));
    assert!(matches!(
        w.beat("suga", 3).await,
        RespResult::Ok(Payload::TaskIdle)
    ));
}

#[tokio::test]
async fn a_caller_collects_agent_gone_notices_after_deenrollment() {
    let w = world("gone-notices", "user", true);
    let working = w.submit("hobi", "a").await;
    let queued = w.submit("hobi", "b").await;
    w.theirs("hobi");
    assert_eq!(w.claimed("hobi").await, working);
    w.clock.set(T0 + 9);
    w.store().retain_enrolled(&only(&[("suga", SUGA_UID)]));
    let listed = page(w.ask(list("hobi", None)).await);
    assert!(listed
        .entries
        .iter()
        .all(|v| (v.state, v.close) == (TaskState::Closed, Some(TaskClose::AgentGone))));
    let page = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(report_ids(&page), vec![working, queued]);
    for e in &page.entries {
        assert_eq!(e.close, Some(TaskClose::AgentGone));
        assert!(e.text.0.is_empty());
        assert_eq!(e.at_secs, T0 + 9);
    }
    let upto = page.entries[1].cursor.seq();
    assert!(reports(w.ask(collect("hobi", Some(upto))).await)
        .entries
        .is_empty());
    assert!(w.store().record(&working).is_none(), "acknowledged");
}

#[tokio::test]
async fn pending_records_are_invisible_to_claim_list_and_status() {
    let w = world("pending", "user", true);
    let sub = match submit("hobi", "unconfirmed") {
        Verb::TaskSubmit { task } => task,
        _ => unreachable!(),
    };
    let pending = w
        .store()
        .mint(
            &FixedSigner,
            &*w.agents.view,
            maknae_kernel::Enrolled {
                generation: w.store().generation(&hobi()),
                agent_uid: HOBI_UID,
            },
            Tasker::Uid(w.me),
            None,
            sub,
        )
        .unwrap()
        .task
        .task_id;
    assert!(w.store().record(&pending).is_none());
    assert!(w.claim("hobi").await.is_none());
    assert!(matches!(
        w.beat("hobi", 0).await,
        RespResult::Ok(Payload::TaskIdle)
    ));
    assert!(page(w.ask(list("hobi", None)).await).entries.is_empty());
    assert!(unauthorized(
        &w.ask(Verb::TaskStatus { task: r(&pending) }).await
    ));
    assert!(reports(w.ask(collect("hobi", None)).await)
        .entries
        .is_empty());
    w.clock.set(T0 + 100 * REPORT_HOLD.as_secs() as i64);
    assert!(w.store().sweep().is_empty());
    assert_eq!(w.store().count_for_test(), 1, "still awaiting its confirm");
    assert!(
        w.store()
            .retain_enrolled(&only(&[("suga", SUGA_UID)]))
            .is_empty(),
        "never a task, so never closed"
    );
    assert_eq!(w.store().count_for_test(), 0, "withdrawn with its agent");
}

#[tokio::test]
async fn an_agent_tasks_another_only_with_its_own_grant_and_the_targets_taskers() {
    for (tag, hobi_policy, suga_policy, accepted, cause) in [
        ("neither", UNGRANTED, PLAIN, false, "session.task is not in"),
        ("grant", GRANTED, PLAIN, false, "is not a tasker"),
        (
            "taskers",
            UNGRANTED,
            TASKED_BY_HOBI,
            false,
            "session.task is not in",
        ),
        ("both", GRANTED, TASKED_BY_HOBI, true, ""),
    ] {
        let w = world_with(
            &format!("a2a-{tag}"),
            "user",
            true,
            hobi_policy,
            suga_policy,
        );
        let parent = w.submit("hobi", "parent").await;
        assert_eq!(
            w.claimed("hobi").await,
            parent,
            "{tag}: claiming needs no grant"
        );
        let records = Records::new(0);
        let got = w
            .agent_with("hobi", submit("suga", "sub"), Some(parent), &records)
            .await
            .unwrap();
        match accepted {
            true => {
                let RespResult::Ok(Payload::TaskAccepted(v)) = got else {
                    panic!("{tag}: {got:?} {:?}", reasons(&records));
                };
                let rec = w.store().record(&v.task.to_id()).unwrap();
                assert_eq!(
                    rec.parent,
                    Some(parent),
                    "under resolves to the claimed parent"
                );
                assert_eq!(
                    rec.tasker,
                    Tasker::Agent {
                        agent: "hobi".into(),
                        uid: HOBI_UID
                    }
                );
            }
            false => {
                assert!(unauthorized(&got), "{tag}: {got:?}");
                assert!(
                    reasons(&records)
                        .iter()
                        .any(|t| t.starts_with("deny") && t.contains(cause)),
                    "{tag}: {:?}",
                    reasons(&records)
                );
                assert!(w
                    .store()
                    .queue(&maknae_config::AgentId::parse("suga").unwrap())
                    .is_empty());
            }
        }
    }
}

#[tokio::test]
async fn the_submitting_agent_can_stop_and_add_to_its_sub_task() {
    let w = world_with("sub-owner", "user", true, GRANTED, TASKED_BY_HOBI);
    let parent = w.submit("hobi", "parent").await;
    assert_eq!(w.claimed("hobi").await, parent);
    let sub = match w.agent("hobi", submit("suga", "sub"), Some(parent)).await {
        RespResult::Ok(Payload::TaskAccepted(v)) => v.task.to_id(),
        other => panic!("{other:?}"),
    };
    assert_eq!(w.claimed("suga").await, sub);
    let added = w
        .agent(
            "hobi",
            Verb::TaskAdd {
                task: r(&sub),
                text: secret("sentinel-628-more"),
            },
            Some(parent),
        )
        .await;
    assert!(
        matches!(added, RespResult::Ok(Payload::TaskAcknowledged(_))),
        "{added:?}"
    );
    assert_eq!(
        follow_ups(w.beat("suga", 0).await),
        (0, vec!["sentinel-628-more".to_string()])
    );
    assert!(
        unauthorized(&w.ask(Verb::TaskStop { task: r(&sub) }).await),
        "the person is not the sub-task's tasker"
    );
    let status = w
        .agent("hobi", Verb::TaskStatus { task: r(&sub) }, None)
        .await;
    assert!(
        matches!(status, RespResult::Ok(Payload::TaskState(v)) if v.state == TaskState::Working)
    );
    let stopped = w
        .agent("hobi", Verb::TaskStop { task: r(&sub) }, None)
        .await;
    assert!(
        matches!(&stopped, RespResult::Ok(Payload::TaskAcknowledged(v)) if v.close == Some(TaskClose::Stopped)),
        "{stopped:?}"
    );
    assert!(matches!(
        w.beat("suga", 1).await,
        RespResult::Ok(Payload::TaskState(v)) if v.close == Some(TaskClose::Stopped)
    ));
    w.ask(Verb::TaskStop { task: r(&parent) }).await;
    assert_eq!(
        w.store().record(&sub).unwrap().close,
        Some(TaskClose::Stopped),
        "the parent's close changes nothing in the sub-task"
    );
    let page = reports(w.agent("hobi", collect("suga", None), None).await);
    assert_eq!(
        report_ids(&page),
        vec![sub],
        "held for the submitting agent"
    );
}

#[tokio::test]
async fn an_uncollected_report_expires_after_the_hold() {
    let w = world("expiry", "user", true);
    let id = w.submit("hobi", "a").await;
    let stopped = w.submit("hobi", "b").await;
    let live = w.submit("hobi", "c").await;
    assert_eq!(w.claimed("hobi").await, id);
    w.agent_reports("hobi", &id, "never collected").await;
    assert_eq!(w.claimed("hobi").await, stopped);
    w.clock.set(T0 + 10);
    w.ask(Verb::TaskStop { task: r(&stopped) }).await;
    let hold = REPORT_HOLD.as_secs() as i64;
    assert_eq!(hold, 30 * 24 * 60 * 60);
    w.clock.set(T0 + hold - 1);
    assert!(w.store().sweep().is_empty());
    assert!(w.store().record(&id).is_some());
    w.clock.set(T0 + hold);
    let said = w.store().sweep();
    assert!(w.store().record(&id).is_none());
    assert!(!w.blobs.has(&id.to_string()));
    assert!(
        w.store().record(&stopped).is_some(),
        "its hold began ten seconds later"
    );
    assert_eq!(
        said,
        vec![Due {
            task: id,
            agent: hobi(),
            tasker: Tasker::Uid(w.me),
            parent: None,
            why: DueFor::Expiry,
            recorded: false
        }]
    );
    assert_eq!(
        report_ids(&reports(w.ask(collect("hobi", None)).await)),
        vec![stopped]
    );
    w.clock.set(T0 + hold + 10);
    w.store().sweep();
    assert!(
        w.store().record(&stopped).is_none(),
        "a close notice expires too"
    );
    assert_eq!(
        w.store().record(&live).unwrap().state,
        TaskState::Queued,
        "a task never expires on a clock"
    );
    assert!(w.restarted().store().record(&id).is_none());
}

#[tokio::test]
async fn a_full_size_task_round_trips_within_the_frame_caps() {
    let w = world("full-size", "user", true);
    let max = w.cfg.prompt_max_bytes;
    assert!(unauthorized(
        &w.ask(submit("hobi", &"p".repeat(max + 1))).await
    ));
    let id = w.submit("hobi", &"p".repeat(max)).await;
    let raw = w.agent_raw("hobi", CLAIM, None, &Records::new(0)).await;
    assert!(
        raw.len() <= maknae_proto::prompt_response_cap(max) + 4,
        "{}",
        raw.len()
    );
    let mut cursor = &raw[..];
    let frame = common::read_frame(&mut cursor, 1 << 20).await.unwrap();
    let RespResult::Ok(Payload::TaskDelivered(d)) =
        maknae_proto::decode_response(&frame).unwrap().result
    else {
        panic!("not delivered");
    };
    let signed: maknae_proto::SignedTask = ciborium::from_reader(d.signed.0.as_slice()).unwrap();
    let maknae_proto::Ask::Prompt { prompt } = &signed.task.ask;
    assert_eq!((signed.task.task_id, prompt.0.len()), (id, max));
    assert!(matches!(
        w.agent_reports("hobi", &id, &"r".repeat(max)).await,
        RespResult::Ok(Payload::TaskAcknowledged(_))
    ));
    let page = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(page.entries[0].text.0.len(), max);
}

#[tokio::test]
async fn a_claim_or_report_whose_record_fails_is_refused_and_recorded() {
    let w = world("claim-audit", "user", true);
    let id = w.submit("hobi", "a").await;
    let raw = w.agent_raw("hobi", CLAIM, None, &Records::new(2)).await;
    assert!(raw.is_empty(), "no intent record, no claim");
    assert_eq!(w.store().record(&id).unwrap().state, TaskState::Queued);
    let records = Records::new(0);
    let got = w.agent_with("hobi", CLAIM, None, &records).await;
    assert!(matches!(
        got,
        Some(RespResult::Ok(Payload::TaskDelivered(_)))
    ));
    let recs = task_records(&records);
    let last = recs.last().unwrap();
    assert_eq!(last.subject.task_op.as_deref(), Some("claim"));
    assert_eq!(last.subject.agent.as_deref(), Some("hobi"));
    assert_eq!(last.subject.task_id, Some(id.to_string()));
    assert_eq!(last.subject.tasker, Some(format!("uid:{}", w.me)));
    assert_eq!(last.object, Some(format!("task:{id}")));
    assert_eq!(last.outcome.reason, "delivered");
    let raw = w
        .agent_raw(
            "hobi",
            Verb::TaskReport { text: secret("r") },
            Some(id),
            &Records::new(2),
        )
        .await;
    assert!(raw.is_empty(), "no intent record, no report");
    assert_eq!(w.store().record(&id).unwrap().state, TaskState::Working);
    let idle = Records::new(0);
    w.agent_with("suga", CLAIM, None, &idle).await;
    assert_eq!(
        reasons(&idle),
        vec!["permit idle"],
        "an idle poll is one record"
    );
}

#[tokio::test]
async fn a_claim_the_store_cannot_write_hands_out_nothing_and_is_held_back() {
    let w = world("claim-disk", "user", true);
    let id = w.submit("hobi", "a").await;
    w.blobs.fail(Some(maknae_kernel::Fail::Unsynced));
    let records = Records::new(0);
    let got = w.agent_with("hobi", CLAIM, None, &records).await.unwrap();
    assert!(unauthorized(&got), "{got:?}");
    let last = task_records(&records).pop().unwrap();
    assert_eq!(last.outcome.posture, "unavailable");
    assert!(
        last.outcome.reason.starts_with("outcome unknown: "),
        "{}",
        last.outcome.reason
    );
    assert_eq!(w.store().record(&id).unwrap().state, TaskState::Queued);
    let hot = w.store().hot(&id).unwrap();
    assert_eq!((hot.lease_until, hot.retry_after), (0, T0 + 1));
    w.blobs.fail(None);
    for _ in 0..3 {
        let held_back = Records::new(0);
        let got = w.agent_with("hobi", CLAIM, None, &held_back).await;
        assert!(
            matches!(got, Some(RespResult::Ok(Payload::TaskIdle))),
            "{got:?}"
        );
        assert_eq!(
            reasons(&held_back),
            vec!["permit idle"],
            "inside the window: no intent and no outcome, only the idle answer's record"
        );
    }
    assert_eq!(w.store().record(&id).unwrap().state, TaskState::Queued);
    w.clock.set(T0 + 1);
    assert_eq!(
        w.claimed("hobi").await,
        id,
        "after the window it is handed out"
    );
    assert_eq!(w.store().hot(&id).unwrap().retry_after, 0);
}

#[tokio::test]
async fn a_cited_fs_list_counts_one_action() {
    let w = world("counted-list", "user", true);
    let id = w.submit("hobi", "a").await;
    assert_eq!(w.claimed("hobi").await, id);
    std::fs::write(w.root.join("one"), b"1").unwrap();
    std::fs::write(w.root.join("two"), b"2").unwrap();
    let verb = Verb::FsList {
        path: w.root.to_str().unwrap().into(),
        after: None,
        conversation: None,
    };
    let _turn = common::fs_turn(&verb).await;
    let records = Records::new(0);
    w.agent_raw_delegating("hobi", verb, Some(id), &records, Some(&w.root))
        .await;
    assert!(
        records.snapshot().iter().any(|r| r.action == "fs.list"),
        "the list was served as a filesystem request"
    );
    assert_eq!(
        w.store().hot(&id).unwrap().actions,
        1,
        "one request, one action, however many entries it decides"
    );
}

#[tokio::test]
async fn a_close_the_disk_has_not_taken_is_shown_to_nobody() {
    let w = world("unstored-close", "user", true);
    let id = w.submit("hobi", "a").await;
    assert_eq!(w.claimed("hobi").await, id);
    w.blobs.fail(Some(maknae_kernel::Fail::Records));
    assert_eq!(
        closes(&w.store().retain_enrolled(&only(&[("suga", SUGA_UID)]))),
        vec![(id, TaskClose::AgentGone)]
    );
    assert!(reports(w.ask(collect("hobi", None)).await)
        .entries
        .is_empty());
    let shown = match w.ask(Verb::TaskStatus { task: r(&id) }).await {
        RespResult::Ok(Payload::TaskState(v)) => v,
        other => panic!("{other:?}"),
    };
    assert_eq!((shown.state, shown.close), (TaskState::Working, None));
    assert_eq!(page(w.ask(list("hobi", None)).await).entries[0].close, None);
    assert!(matches!(
        w.beat("hobi", 0).await,
        RespResult::Ok(Payload::TaskIdle)
    ));
    assert!(
        w.claim("hobi").await.is_none(),
        "the agent is refused it all the same"
    );
    w.blobs.fail(None);
    assert!(w.store().close_all_due().is_empty(), "recorded once");
    let page = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(report_ids(&page), vec![id]);
    assert!(matches!(
        w.beat("hobi", 0).await,
        RespResult::Ok(Payload::TaskState(v)) if v.close == Some(TaskClose::AgentGone)
    ));
}

#[tokio::test]
async fn tombstones_do_not_count_against_a_re_enrolled_agents_queue() {
    let w = world("tombstones", "user", true);
    for _ in 0..maknae_kernel::MAX_LIVE_TASKS_PER_AGENT {
        w.theirs("hobi");
    }
    assert!(
        unauthorized(&w.ask(submit("hobi", "full")).await),
        "256 open tasks fill the queue"
    );
    w.store().retain_enrolled(&only(&[("suga", SUGA_UID)]));
    w.store()
        .retain_enrolled(&only(&[("hobi", HOBI_UID), ("suga", SUGA_UID)]));
    let id = w.submit("hobi", "new work").await;
    assert_eq!(w.claimed("hobi").await, id);
}

#[tokio::test]
async fn a_sub_tasks_records_name_the_sub_task_and_the_submitting_agent() {
    let w = world_with("sub-records", "user", true, GRANTED, TASKED_BY_HOBI);
    let parent = w.submit("hobi", "parent").await;
    assert_eq!(w.claimed("hobi").await, parent);
    let records = Records::new(0);
    let sub = match w
        .agent_with("hobi", submit("suga", "sub"), Some(parent), &records)
        .await
    {
        Some(RespResult::Ok(Payload::TaskAccepted(v))) => v.task.to_id(),
        other => panic!("{other:?}"),
    };
    let named = |reason: &str| {
        let rec = task_records(&records)
            .into_iter()
            .find(|r| r.outcome.reason == reason)
            .unwrap_or_else(|| panic!("no {reason:?} record"));
        (
            rec.subject.task_id,
            rec.subject.tasker,
            rec.subject.parent_task_id,
        )
    };
    let want = (
        Some(sub.to_string()),
        Some("agent:hobi".to_string()),
        Some(parent.to_string()),
    );
    assert_eq!(named("task stored"), want);
    assert_eq!(named("task queued"), want);
    assert_eq!(w.claimed("suga").await, sub);
    for verb in [
        Verb::TaskStatus { task: r(&sub) },
        Verb::TaskAdd {
            task: r(&sub),
            text: secret("more"),
        },
        Verb::TaskStop { task: r(&sub) },
    ] {
        let records = Records::new(0);
        w.agent_with("hobi", verb.clone(), Some(parent), &records)
            .await;
        let recs = task_records(&records);
        assert!(!recs.is_empty());
        for rec in recs {
            assert_eq!(rec.subject.task_id, Some(sub.to_string()), "{verb:?}");
            assert_eq!(rec.subject.tasker.as_deref(), Some("agent:hobi"));
        }
    }
    let records = Records::new(0);
    let first = reports(
        w.agent_with("hobi", collect("suga", None), Some(parent), &records)
            .await
            .unwrap(),
    );
    let upto = first.entries[0].cursor.seq();
    w.agent_with("hobi", collect("suga", Some(upto)), Some(parent), &records)
        .await;
    assert!(
        task_records(&records)
            .iter()
            .all(|r| r.subject.task_id.is_none()
                && r.subject.tasker.as_deref() == Some("agent:hobi")),
        "a collect names no task, so the cited one is not paired with the agent as tasker"
    );
    let said = reasons(&records);
    assert!(
        said.iter()
            .any(|t| t == &format!("permit collected 1 reports: {sub}")),
        "{said:?}"
    );
    assert!(
        said.iter()
            .any(|t| t == &format!("permit acknowledged 1: {sub}; collected 0 reports")),
        "{said:?}"
    );
    let uncited = Records::new(0);
    w.agent_with("hobi", Verb::Ping, Some(parent), &uncited)
        .await;
    assert!(
        uncited
            .snapshot()
            .iter()
            .filter(|r| r.event == "request")
            .any(|r| r.subject.task_id == Some(parent.to_string())
                && r.subject.tasker == Some(format!("uid:{}", w.me))),
        "a record that names no task of its own carries the cited one"
    );
    let later = match w.agent("hobi", submit("suga", "later"), Some(parent)).await {
        RespResult::Ok(Payload::TaskAccepted(v)) => v.task.to_id(),
        other => panic!("{other:?}"),
    };
    let due = w.store().retain_enrolled(&only(&[("hobi", HOBI_UID)]));
    assert_eq!(due.len(), 1);
    assert_eq!(
        (due[0].task, due[0].parent, due[0].tasker.clone()),
        (
            later,
            Some(parent),
            Tasker::Agent {
                agent: "hobi".into(),
                uid: HOBI_UID
            }
        ),
        "the close joins to the submission by the sub-task's id"
    );
}

#[tokio::test]
async fn an_agent_holding_a_task_submits_only_under_it() {
    let w = world_with("under", "user", true, GRANTED, TASKED_BY_HOBI);
    let parent = w.submit("hobi", "parent").await;
    assert_eq!(w.claimed("hobi").await, parent);
    let records = Records::new(0);
    let got = w
        .agent_with("hobi", submit("suga", "loose"), None, &records)
        .await
        .unwrap();
    assert!(unauthorized(&got), "{got:?}");
    assert!(
        reasons(&records)
            .iter()
            .any(|t| t.starts_with("deny") && t.contains("submits under the task it holds")),
        "{:?}",
        reasons(&records)
    );
    assert!(w
        .store()
        .queue(&maknae_config::AgentId::parse("suga").unwrap())
        .is_empty());
    w.agent_reports("hobi", &parent, "done").await;
    let own = match w
        .agent("hobi", submit("suga", "own initiative"), None)
        .await
    {
        RespResult::Ok(Payload::TaskAccepted(v)) => v.task.to_id(),
        other => panic!("{other:?}"),
    };
    let rec = w.store().record(&own).unwrap();
    assert_eq!(rec.parent, None);
    assert_eq!(
        rec.root,
        RootTasker::Agent {
            agent: "hobi".into()
        }
    );
}

#[tokio::test]
async fn a_lowered_prompt_cap_strands_no_stored_report_and_no_queued_prompt() {
    let mut w = world("lowered-cap", "user", true);
    let floor = w.cfg.prompt_max_bytes;
    w.cfg.prompt_max_bytes = 2 * floor;
    let big = w.submit("hobi", &"p".repeat(2 * floor)).await;
    let done = w.submit("hobi", "small").await;
    w.cfg.prompt_max_bytes = floor;
    let (task, _) = w
        .claim("hobi")
        .await
        .expect("the oversize prompt is still handed out");
    let maknae_proto::Ask::Prompt { prompt } = &task.task.ask;
    assert_eq!((task.task.task_id, prompt.0.len()), (big, 2 * floor));
    w.cfg.prompt_max_bytes = 2 * floor;
    w.agent_reports("hobi", &big, &"r".repeat(2 * floor)).await;
    w.cfg.prompt_max_bytes = floor;
    assert_eq!(w.claimed("hobi").await, done);
    w.agent_reports("hobi", &done, "ok").await;
    let page = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(report_ids(&page), vec![big]);
    assert_eq!(page.entries[0].text.0.len(), 2 * floor);
    let rest = reports(
        w.ask(collect("hobi", Some(page.entries[0].cursor.seq())))
            .await,
    );
    assert_eq!(report_ids(&rest), vec![done]);
}

#[tokio::test]
async fn a_hand_out_the_signer_refuses_is_recorded_unavailable_and_held_back() {
    let mut w = world("unsigned", "user", true);
    let id = w.submit("hobi", "a").await;
    w.agents.signer = Arc::new(maknae_kernel::UnverifiedSigner);
    let records = Records::new(0);
    let got = w.agent_with("hobi", CLAIM, None, &records).await.unwrap();
    assert!(unauthorized(&got), "{got:?}");
    let last = task_records(&records).pop().unwrap();
    assert_eq!(
        (last.outcome.reason.as_str(), last.outcome.posture.as_str()),
        ("the task could not be signed", "unavailable")
    );
    assert!(matches!(
        w.agent("hobi", CLAIM, None).await,
        RespResult::Ok(Payload::TaskIdle)
    ));
    assert_eq!(w.store().record(&id).unwrap().state, TaskState::Queued);
    w.agents.signer = Arc::new(FixedSigner);
    w.clock.set(T0 + 1);
    assert_eq!(w.claimed("hobi").await, id);
}

#[tokio::test]
async fn a_contained_taskers_tasks_are_held_and_stay_held_after_release() {
    let w = world("hold-tasker", "user", true);
    let working = w.submit("hobi", "a").await;
    let queued = w.submit("hobi", "b").await;
    let reported = w.submit("suga", "c").await;
    let theirs = w.anothers("hobi");
    assert_eq!(w.claimed("hobi").await, working);
    assert_eq!(w.claimed("suga").await, reported);
    w.agent_reports("suga", &reported, "evidence").await;
    let bindings = maknae_authz_basic::PolicyPaths::in_dir(&w.root).bindings;
    let bound = std::fs::read_to_string(&bindings).unwrap();
    common::write_0640(
        &bindings,
        &format!(
            "schema_version: 1\nbindings:\n  adversary: [\"{}\"]\n  user: [\"nobody\"]\n",
            w.user
        ),
    );
    w.pdp.baseline().reload_from_file().unwrap();
    let mut held = holds(&w.store().retain_enrolled(&*w.agents.view));
    held.sort();
    let mut want = vec![working, queued, reported];
    want.sort();
    assert_eq!(
        held, want,
        "every task the contained person gave, open or reported"
    );
    let me = Tasker::Uid(w.me);
    for (id, from) in [
        (working, TaskState::Working),
        (queued, TaskState::Queued),
        (reported, TaskState::Reported),
    ] {
        let rec = w.store().record(&id).unwrap();
        assert_eq!((rec.state, rec.held_from), (TaskState::Held, Some(from)));
        assert_eq!(w.store().state_for(&id, &me), Some(TaskState::Held));
    }
    assert_eq!(w.store().record(&theirs).unwrap().state, TaskState::Queued);
    match w.beat("hobi", 0).await {
        RespResult::Ok(Payload::TaskState(v)) => {
            assert_eq!((v.task, v.state), (r(&working), TaskState::Held));
        }
        other => panic!("{other:?}"),
    }
    let beat = Records::new(0);
    w.agent_with(
        "hobi",
        Verb::TaskClaim {
            seen_follow_ups: Some(0),
        },
        None,
        &beat,
    )
    .await;
    assert_eq!(reasons(&beat), vec!["permit heartbeat: the task is held"]);
    assert!(w.cannot_cite("hobi", Verb::Ping, working).await);
    assert_eq!(
        w.claimed("hobi").await,
        theirs,
        "another person's task is still handed out; the held ones never are"
    );
    assert!(unauthorized(
        &w.ask(Verb::TaskStatus { task: r(&queued) }).await
    ));
    common::write_0640(&bindings, &bound);
    w.pdp.baseline().reload_from_file().unwrap();
    assert!(w.store().retain_enrolled(&*w.agents.view).is_empty());
    let shown = match w.ask(Verb::TaskStatus { task: r(&queued) }).await {
        RespResult::Ok(Payload::TaskState(v)) => v,
        other => panic!("{other:?}"),
    };
    assert_eq!(shown.state, TaskState::Held, "a release lifts no hold");
    assert!(page(w.ask(list("hobi", None)).await)
        .entries
        .iter()
        .all(|v| v.state == TaskState::Held));
    assert!(
        reports(w.ask(collect("suga", None)).await)
            .entries
            .is_empty(),
        "a held report is not released"
    );
    for verb in [
        Verb::TaskDrop { task: r(&queued) },
        Verb::TaskStop { task: r(&working) },
        Verb::TaskAdd {
            task: r(&working),
            text: secret("more"),
        },
    ] {
        assert!(unauthorized(&w.ask(verb.clone()).await), "{verb:?}");
    }
    assert_eq!(w.store().record(&queued).unwrap().state, TaskState::Held);
}

#[tokio::test]
async fn a_contained_agents_open_tasks_are_held() {
    let w = world("hold-agent", "user", true);
    let done = w.submit("hobi", "a").await;
    assert_eq!(w.claimed("hobi").await, done);
    w.agent_reports("hobi", &done, "finished before").await;
    let working = w.submit("hobi", "b").await;
    let queued = w.submit("hobi", "c").await;
    let sugas = w.submit("suga", "d").await;
    assert_eq!(w.claimed("hobi").await, working);
    let mut held = holds(&w.store().retain_enrolled(&containing(&w, &[HOBI_UID])));
    held.sort();
    let mut want = vec![working, queued];
    want.sort();
    assert_eq!(held, want);
    assert_eq!(w.store().record(&sugas).unwrap().state, TaskState::Queued);
    assert_eq!(
        report_ids(&reports(w.ask(collect("hobi", None)).await)),
        vec![done],
        "a report it had already made is still its tasker's to collect"
    );
    assert!(w
        .store()
        .retain_enrolled(&containing(&w, &[HOBI_UID]))
        .is_empty());
    assert!(w.store().retain_enrolled(&containing(&w, &[])).is_empty());
    assert_eq!(w.store().record(&working).unwrap().state, TaskState::Held);
}

#[tokio::test]
async fn a_held_task_never_lapses_expires_or_leaves_and_survives_a_restart() {
    let w = world("hold-clock", "user", true);
    let working = w.submit("hobi", "a").await;
    let reported = w.submit("suga", "b").await;
    assert_eq!(w.claimed("hobi").await, working);
    assert_eq!(w.claimed("suga").await, reported);
    w.agent_reports("suga", &reported, "r").await;
    let cursor = reports(w.ask(collect("suga", None)).await).entries[0]
        .cursor
        .seq();
    w.store().mark_unenrolled(&containing(&w, &[w.me]));
    w.clock.set(T0 + 100 * REPORT_HOLD.as_secs() as i64);
    assert_eq!(
        holds(&w.store().sweep()).len(),
        2,
        "marked: due a hold, and nothing else, however late"
    );
    w.clock.set(T0 + 200 * REPORT_HOLD.as_secs() as i64);
    assert!(w.store().sweep().is_empty(), "no lapse and no expiry");
    let me = Tasker::Uid(w.me);
    let suga = maknae_config::AgentId::parse("suga").unwrap();
    assert_eq!(w.store().acknowledge(&me, &suga, cursor), Ok(0));
    assert!(w.store().drop_queued(&working, &me).is_err());
    let w = w.restarted();
    for (id, from) in [
        (working, TaskState::Working),
        (reported, TaskState::Reported),
    ] {
        let rec = w.store().record(&id).unwrap();
        assert_eq!((rec.state, rec.held_from), (TaskState::Held, Some(from)));
    }
    assert!(w.store().sweep().is_empty());
    assert!(w.claim("hobi").await.is_none());
    assert!(matches!(
        w.beat("hobi", 0).await,
        RespResult::Ok(Payload::TaskState(v)) if v.state == TaskState::Held
    ));
}

impl World {
    fn agent_policy(&self, agent: &str, policy: &str) {
        let file = self
            .root
            .join(maknae_config::AGENTS_DIR)
            .join(agent)
            .join(maknae_config::POLICY_FILE);
        common::write_0640(&file, policy);
        self.pdp.baseline().reload_from_file().unwrap();
    }

    /// The tasker's working task finishes; its queued one is closed `Withdrawn` at the
    /// next claim, after the claim's own record.
    async fn withdrawn_at_the_next_claim(&self, working: TaskId, queued: TaskId, cause: &str) {
        assert_eq!(
            self.claimed("hobi").await,
            working,
            "a running task is not re-decided"
        );
        assert!(matches!(
            self.agent_reports("hobi", &working, "finished").await,
            RespResult::Ok(Payload::TaskAcknowledged(_))
        ));
        let records = Records::new(0);
        let got = self.agent_with("hobi", CLAIM, None, &records).await;
        assert!(
            matches!(got, Some(RespResult::Ok(Payload::TaskIdle))),
            "{got:?}"
        );
        let said = task_records(&records);
        let rec = said.last().unwrap();
        assert_eq!(rec.outcome.result, "permit");
        assert!(
            rec.outcome
                .reason
                .starts_with("idle: the tasker's authority was withdrawn: ")
                && rec.outcome.reason.contains(cause),
            "{}",
            rec.outcome.reason
        );
        assert_eq!(rec.subject.task_id, Some(queued.to_string()));
        assert_eq!(rec.subject.tasker, Some(format!("uid:{}", self.me)));
        assert_eq!(
            self.store().record(&queued).unwrap().state,
            TaskState::Queued,
            "recorded before it is closed"
        );
        assert!(self.claim("hobi").await.is_none(), "and never handed out");
        assert_eq!(
            closes(&self.store().close_all_due()),
            vec![(queued, TaskClose::Withdrawn)]
        );
        let rec = self.store().record(&queued).unwrap();
        assert_eq!(
            (rec.state, rec.close),
            (TaskState::Closed, Some(TaskClose::Withdrawn))
        );
    }
}

#[tokio::test]
async fn a_person_removed_from_taskers_has_queued_tasks_withdrawn_and_the_running_one_finishes() {
    let w = world("withdrawn-taskers", "user", true);
    let working = w.submit("hobi", "a").await;
    let queued = w.submit("hobi", "b").await;
    assert_eq!(w.claimed("hobi").await, working);
    w.agent_policy("hobi", "schema_version: 1\ntaskers: []\n");
    w.withdrawn_at_the_next_claim(working, queued, "is not a tasker")
        .await;
    let page = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(report_ids(&page), vec![working, queued]);
    assert_eq!(page.entries[0].close, None);
    assert_eq!(page.entries[1].close, Some(TaskClose::Withdrawn));
    assert!(page.entries[1].text.0.is_empty());
}

#[tokio::test]
async fn a_tasker_whose_role_loses_the_grant_has_queued_tasks_withdrawn() {
    let w = world("withdrawn-grant", "user", true);
    let working = w.submit("hobi", "a").await;
    let queued = w.submit("hobi", "b").await;
    let theirs_later = w.submit("suga", "c").await;
    assert_eq!(w.claimed("hobi").await, working);
    common::write_0640(
        &maknae_authz_basic::PolicyPaths::in_dir(&w.root).authz,
        "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
    );
    w.pdp.baseline().reload_from_file().unwrap();
    w.withdrawn_at_the_next_claim(working, queued, "no rule for session.task")
        .await;
    for verb in [
        collect("hobi", None),
        list("hobi", None),
        Verb::TaskStatus { task: r(&queued) },
    ] {
        assert!(
            unauthorized(&w.ask(verb.clone()).await),
            "{verb:?}: without the grant the tasker cannot collect the close it is owed"
        );
    }
    assert_eq!(
        w.store().record(&queued).unwrap().close,
        Some(TaskClose::Withdrawn),
        "it waits out its hold"
    );
    assert!(w.claim("suga").await.is_none(), "every agent re-decides");
    assert_eq!(
        closes(&w.store().close_all_due()),
        vec![(theirs_later, TaskClose::Withdrawn)]
    );
}

#[tokio::test]
async fn a_contained_taskers_queued_task_is_held_never_withdrawn() {
    let w = world("held-not-withdrawn", "user", true);
    let queued = w.submit("hobi", "a").await;
    let bindings = maknae_authz_basic::PolicyPaths::in_dir(&w.root).bindings;
    common::write_0640(
        &bindings,
        &format!(
            "schema_version: 1\nbindings:\n  adversary: [\"{}\"]\n",
            w.user
        ),
    );
    w.pdp.baseline().reload_from_file().unwrap();
    assert!(w.claim("hobi").await.is_none(), "not handed out");
    assert!(
        w.store().due(8).is_empty(),
        "and not marked withdrawn: containment holds, it does not close"
    );
    assert_eq!(
        holds(&w.store().retain_enrolled(&*w.agents.view)),
        vec![queued]
    );
    assert_eq!(w.store().record(&queued).unwrap().state, TaskState::Held);
    assert!(w.store().close_all_due().is_empty());
}

#[tokio::test]
async fn a_tasker_whose_name_did_not_resolve_keeps_the_queued_task_until_it_resolves() {
    let w = world("unresolved-tasker", "user", true);
    let queued = w.anothers("hobi");
    let bindings = maknae_authz_basic::PolicyPaths::in_dir(&w.root).bindings;
    let bind = |names: &str| {
        common::write_0640(
            &bindings,
            &format!(
                "schema_version: 1\nbindings:\n  user: [\"{}\"{names}]\n",
                w.user
            ),
        );
        w.pdp.baseline().reload_from_file().unwrap();
    };
    bind(", \"sentinel-628-no-such-user\"");
    for _ in 0..2 {
        let records = Records::new(0);
        let got = w.agent_with("hobi", CLAIM, None, &records).await;
        assert!(
            matches!(got, Some(RespResult::Ok(Payload::TaskIdle))),
            "{got:?}"
        );
        let rec = task_records(&records).pop().unwrap();
        assert_eq!(
            rec.outcome.reason,
            "idle: the tasker's standing could not be decided: the tasker's identity could not be resolved"
        );
        assert_eq!(rec.outcome.posture, "unavailable");
        assert_eq!(rec.subject.task_id, Some(queued.to_string()));
        assert_eq!(rec.subject.tasker, Some(format!("uid:{}", another())));
    }
    assert!(w.store().due(8).is_empty(), "nothing is withdrawn");
    assert_eq!(w.store().record(&queued).unwrap().state, TaskState::Queued);
    bind(", \"nobody\"");
    assert_eq!(
        w.claimed("hobi").await,
        queued,
        "delivered once the name resolves"
    );

    let w = world("resolved-no-role", "user", true);
    let queued = w.anothers("hobi");
    common::write_0640(
        &maknae_authz_basic::PolicyPaths::in_dir(&w.root).bindings,
        &format!("schema_version: 1\nbindings:\n  user: [\"{}\"]\n", w.user),
    );
    w.pdp.baseline().reload_from_file().unwrap();
    assert!(w.claim("hobi").await.is_none());
    assert_eq!(
        closes(&w.store().close_all_due()),
        vec![(queued, TaskClose::Withdrawn)],
        "every bound name resolved, and the tasker holds no role: withdrawn"
    );
}
