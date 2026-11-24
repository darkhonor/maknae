//! #630: the agents a person may task, listed through the real `handle()` and decided per
//! agent by the real composed PDP, over a task store with a manual clock.
mod common;
use common::Records;
use maknae_io::Zeroizing;
use maknae_kernel::{AgentAdmission, ManualClock, MemTaskBlobs, TaskRefusal, TaskStore};
use maknae_proto::{
    AgentEntry, AgentPage, AgentStanding, BannerSpec, Payload, ProtoErrCode, RespResult, Response,
    SecretText, TaskClose, TaskCursor, TaskId, TaskState, TaskSubmission, Tasker, Verb,
};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const HOBI_UID: u32 = 12_201;
const JIN_UID: u32 = 12_202;
const MANY_UID: u32 = 13_000;
const OTHER: u32 = 31_337;
const T0: i64 = 1_800_000_000;

const PLAIN: &str = "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n";
const NOT_PEOPLE: &str = "schema_version: 1\ntaskers: [\"agent:hobi\"]\n";
const GRANT: &str = "roles:\n  user:\n    allow: [\"session.task\"]\n";

/// Every test is the same euid, so they share its store slots.
static STORE: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

fn secret(s: &str) -> SecretText {
    SecretText(Zeroizing::new(s.into()))
}

fn nobody() -> u32 {
    nix::unistd::User::from_name("nobody")
        .expect("NSS")
        .expect("the host has a nobody account")
        .uid
        .as_raw()
}

fn many(n: u32) -> String {
    format!("a{n:03}")
}

fn account_of(uid: u32) -> Option<String> {
    match uid {
        HOBI_UID => Some("hobi-svc".into()),
        JIN_UID => Some("jin-svc".into()),
        MANY_UID..=13_999 => Some(format!("{}-svc", many(uid - MANY_UID))),
        _ if uid == nobody() => Some("nobody".into()),
        _ => None,
    }
}

struct FixedSigner;

impl maknae_kernel::TaskSigner for FixedSigner {
    fn sign(
        &self,
        task: maknae_proto::TaskObject,
    ) -> Result<maknae_proto::SignedTask, TaskRefusal> {
        Ok(signed(task))
    }
    fn sign_addendum(
        &self,
        _addendum: maknae_proto::TaskAddendum,
    ) -> Result<maknae_proto::SignedAddendum, TaskRefusal> {
        Err(TaskRefusal::Unsigned)
    }
    fn current_leaf(&self) -> Option<[u8; 32]> {
        Some(maknae_crypto::sha256(&[1]))
    }
}

fn signed(task: maknae_proto::TaskObject) -> maknae_proto::SignedTask {
    maknae_proto::SignedTask {
        task,
        signature: maknae_proto::TaskSignature {
            alg: "test".into(),
            leaf: maknae_proto::Bytes::new(vec![1].into()),
            chain: Vec::new(),
            sig: maknae_proto::Bytes::new(vec![2].into()),
        },
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

/// An agent to enroll: its id, uid, account and `policy.yaml`.
struct Agent {
    id: String,
    uid: u32,
    policy: &'static str,
}

fn agent(id: &str, uid: u32, policy: &'static str) -> Agent {
    Agent {
        id: id.into(),
        uid,
        policy,
    }
}

fn hobi_and_jin() -> Vec<Agent> {
    vec![
        agent("hobi", HOBI_UID, PLAIN),
        agent("jin", JIN_UID, NOT_PEOPLE),
    ]
}

struct World {
    root: common::DirGuard,
    pdp: Arc<maknae_kernel::Composition<maknae_authz_basic::HermeticAuthorizer>>,
    agents: AgentAdmission,
    me: u32,
    user: String,
    cfg: maknae_config::TransportConfig,
}

fn world(tag: &str, agents: &[Agent]) -> World {
    let user = common::euid_name();
    world_bound(
        tag,
        agents,
        &format!("schema_version: 1\nbindings:\n  user: [\"{user}\"]\n"),
    )
}

fn world_bound(tag: &str, agents: &[Agent], bindings: &str) -> World {
    let dir = std::env::temp_dir().join(format!("agents630_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = common::DirGuard(dir.canonicalize().unwrap());
    let paths = maknae_authz_basic::PolicyPaths::in_dir(&root);
    common::write_0640(&paths.authz, &format!("{PLAIN}{GRANT}"));
    common::write_0640(&paths.sensitive, common::EMPTY_SENSITIVE);
    common::write_0640(&paths.bindings, bindings);
    let agents_dir = root.join(maknae_config::AGENTS_DIR);
    std::fs::create_dir_all(&agents_dir).unwrap();
    std::fs::set_permissions(&agents_dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    for a in agents {
        let d = agents_dir.join(&a.id);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o750)).unwrap();
        let account = account_of(a.uid).expect("a test agent's account");
        common::write_0640(
            &d.join(maknae_config::ENROLLMENT_FILE),
            &format!(
                "agent_id: {}\naccount: {account}\nuid: {}\nrole: user\n",
                a.id, a.uid
            ),
        );
        common::write_0640(&d.join(maknae_config::POLICY_FILE), a.policy);
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
            Ok(account_of(uid).map(|name| maknae_io::HostAccount {
                uid,
                name,
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
    let tasks = Arc::new(
        TaskStore::open(
            Box::new(MemTaskBlobs::default()),
            Arc::new(ManualClock::at(T0)),
        )
        .expect("an empty store"),
    );
    let agents = AgentAdmission {
        view: Arc::new(maknae_kernel::SnapshotEnrollment(Arc::clone(&pdp))),
        tasks,
        signer: Arc::new(FixedSigner),
        banner: Default::default(),
        reach: maknae_kernel::no_reach("no egress socket in this test"),
        board: Arc::new(maknae_kernel::BoardStore::new()),
        switches: Arc::new(maknae_kernel::FixedSwitches::default()),
    };
    let mut cfg = maknae_config::transport_from_section(None).unwrap();
    cfg.prompt_max_bytes = maknae_config::PROMPT_MAX_BYTES_FLOOR;
    World {
        root,
        pdp,
        agents,
        me,
        user: common::euid_name(),
        cfg,
    }
}

impl World {
    fn store(&self) -> &TaskStore {
        &self.agents.tasks
    }

    fn reload(&self) {
        self.pdp.baseline().reload_from_file().unwrap();
    }

    fn agent_policy(&self, agent: &str, policy: &str) {
        common::write_0640(
            &self
                .root
                .join(maknae_config::AGENTS_DIR)
                .join(agent)
                .join(maknae_config::POLICY_FILE),
            policy,
        );
        self.reload();
    }

    async fn as_uid(&self, uid: u32, verb: Verb, records: &Arc<Records>) -> Option<RespResult> {
        let _shared = STORE.read().await;
        let name = if uid == self.me {
            self.user.clone()
        } else {
            format!("u{uid}")
        };
        let session =
            maknae_kernel::SessionRecord::for_test(uid, Some(name.clone())).with_session_id(630);
        let gate = maknae_kernel::FactsGate::allow_as(Some(name), Some(PathBuf::from(&*self.root)));
        let raw = self.serve(session, gate, verb, None, records).await;
        answer(&raw).await
    }

    async fn ask_with(&self, verb: Verb, records: &Arc<Records>) -> RespResult {
        self.as_uid(self.me, verb, records)
            .await
            .unwrap_or_else(|| panic!("no answer: {:?}", reasons(records)))
    }

    async fn ask(&self, verb: Verb) -> RespResult {
        self.ask_with(verb, &Records::new(0)).await
    }

    async fn list_as(&self, uid: u32, after: Option<&str>) -> AgentPage {
        let records = Records::new(0);
        match self.as_uid(uid, list(after), &records).await {
            Some(RespResult::Ok(Payload::Agents(page))) => page,
            other => panic!("not an agent page: {other:?}: {:?}", reasons(&records)),
        }
    }

    async fn list(&self, after: Option<&str>) -> AgentPage {
        self.list_as(self.me, after).await
    }

    async fn agent_ask(
        &self,
        agent: &str,
        uid: u32,
        verb: Verb,
        task: Option<TaskId>,
        records: &Arc<Records>,
    ) -> Option<RespResult> {
        let _shared = STORE.read().await;
        let mut session = maknae_kernel::SessionRecord::for_test(uid, Some(format!("{agent}-svc")))
            .with_session_id(631);
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
        let raw = self.serve(session, gate, verb, task, records).await;
        answer(&raw).await
    }

    async fn serve(
        &self,
        session: maknae_kernel::SessionRecord,
        gate: Arc<maknae_kernel::FactsGate>,
        verb: Verb,
        task: Option<TaskId>,
        records: &Arc<Records>,
    ) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
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
            maknae_io::DelegatedFds::new(4),
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
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut received))
            .await
            .expect("the daemon closes within 10s")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .unwrap()
            .unwrap();
        received
    }

    async fn submit(&self, agent: &str) -> TaskId {
        match self.ask(submit(agent)).await {
            RespResult::Ok(Payload::TaskAccepted(v)) => v.task.to_id(),
            other => panic!("submit refused: {other:?}"),
        }
    }

    /// A task of mine with `agent`, inserted as a submission would leave it.
    fn mine(&self, agent: &str, agent_uid: u32) -> TaskId {
        use maknae_kernel::TaskObjectForTest;
        let mut task = maknae_proto::TaskObject::for_test(agent, 0);
        task.tasker = Tasker::Uid(self.me);
        self.store()
            .insert_for_test(signed(task), agent_uid)
            .task
            .task_id
    }

    fn report(&self, id: &TaskId, text: &str) {
        self.store().publish_report(id, secret(text), None).unwrap();
    }

    async fn claimed(&self, agent: &str, uid: u32) -> TaskId {
        let records = Records::new(0);
        match self
            .agent_ask(agent, uid, CLAIM, None, &records)
            .await
            .expect("an answer")
        {
            RespResult::Ok(Payload::TaskDelivered(d)) => {
                let signed: maknae_proto::SignedTask =
                    ciborium::from_reader(d.signed.0.as_slice()).expect("a signed task");
                signed.task.task_id
            }
            other => panic!("claim: {other:?}: {:?}", reasons(&records)),
        }
    }
}

const CLAIM: Verb = Verb::TaskClaim {
    seen_follow_ups: None,
};

async fn answer(raw: &[u8]) -> Option<RespResult> {
    let mut cursor = raw;
    let frame = common::read_frame(&mut cursor, 1 << 20).await.ok()?;
    let resp: Response = maknae_proto::decode_response(&frame).unwrap();
    Some(resp.result)
}

fn list(after: Option<&str>) -> Verb {
    Verb::AgentList {
        after: after.map(str::to_owned),
    }
}

fn submit(agent: &str) -> Verb {
    Verb::TaskSubmit {
        task: TaskSubmission {
            schema: maknae_proto::TASK_SCHEMA.into(),
            version: maknae_proto::TASK_VERSION,
            agent: agent.into(),
            ask: maknae_proto::Ask::Prompt {
                prompt: secret("sentinel-630-prompt"),
            },
            labels: maknae_proto::Labels {},
            bindings: vec![],
        },
        forge_tokens: maknae_proto::ForgeTokens::default(),
    }
}

fn collect(agent: &str, after: Option<u64>) -> Verb {
    Verb::TaskCollect {
        agent: agent.into(),
        after: after.map(TaskCursor::from_seq),
        task: None,
    }
}

fn reports(r: RespResult) -> maknae_proto::TaskReportPage {
    match r {
        RespResult::Ok(Payload::TaskReports(p)) => p,
        other => panic!("not a report page: {other:?}"),
    }
}

fn entry(agent: &str, standing: AgentStanding, waiting: u32) -> AgentEntry {
    AgentEntry {
        agent: agent.into(),
        standing,
        waiting,
    }
}

fn reasons(records: &Records) -> Vec<String> {
    records
        .snapshot()
        .iter()
        .filter(|r| r.action == "session.task")
        .map(|r| format!("{} {}", r.outcome.result, r.outcome.reason))
        .collect()
}

fn hobi() -> maknae_config::AgentId {
    maknae_config::AgentId::parse("hobi").unwrap()
}

#[tokio::test]
async fn the_list_holds_exactly_the_agents_the_caller_may_task() {
    let w = world("exactly", &hobi_and_jin());
    let records = Records::new(0);
    let page = match w.ask_with(list(None), &records).await {
        RespResult::Ok(Payload::Agents(page)) => page,
        other => panic!("{other:?}: {:?}", reasons(&records)),
    };
    assert_eq!(page.entries, [entry("hobi", AgentStanding::Enrolled, 0)]);
    assert_eq!((page.next, page.undecided, page.banner), (None, 0, None));
    let said = records.snapshot();
    let listed: Vec<_> = said.iter().filter(|r| r.action == "session.task").collect();
    assert_eq!(listed.len(), 1, "one record for the request: {said:?}");
    let rec = listed[0];
    assert_eq!(
        (rec.outcome.result.as_str(), rec.outcome.reason.as_str()),
        (
            "permit",
            "listed 1 agents, 0 undecided: hobi:enrolled,jin:refused"
        )
    );
    assert_eq!(rec.object.as_deref(), Some("1 agents"));
    assert_eq!(rec.subject.tasker, Some(format!("uid:{}", w.me)));
    assert_eq!(rec.subject.task_op, None);
    assert!(
        w.store().holdings(&Tasker::Uid(w.me)).is_empty(),
        "no submission was made"
    );
}

#[tokio::test]
async fn agent_list_is_not_refused_for_lacking_an_op() {
    let w = world("no-op", &hobi_and_jin());
    assert!(matches!(
        w.ask(list(None)).await,
        RespResult::Ok(Payload::Agents(_))
    ));
}

#[tokio::test]
async fn a_contained_agent_is_listed_only_for_a_caller_with_tasks_there() {
    let user = common::euid_name();
    let w = world_bound(
        "contained",
        &[agent("hobi", nobody(), PLAIN), agent("jin", JIN_UID, PLAIN)],
        &format!("schema_version: 1\nbindings:\n  user: [\"{user}\"]\n  adversary: [\"nobody\"]\n"),
    );
    w.mine("hobi", nobody());
    assert_eq!(
        w.list(None).await.entries,
        [
            entry("hobi", AgentStanding::Contained, 0),
            entry("jin", AgentStanding::Enrolled, 0)
        ]
    );
    let theirs = w.list_as(OTHER, None).await;
    assert!(
        theirs.entries.iter().all(|e| e.agent != "hobi"),
        "{theirs:?}"
    );
}

#[tokio::test]
async fn a_caller_whose_grant_is_revoked_sees_no_contained_agent() {
    let user = common::euid_name();
    let w = world_bound(
        "contained-revoked",
        &[agent("hobi", nobody(), PLAIN), agent("jin", JIN_UID, PLAIN)],
        &format!("schema_version: 1\nbindings:\n  user: [\"{user}\"]\n  adversary: [\"nobody\"]\n"),
    );
    w.mine("hobi", nobody());
    assert_eq!(
        w.list(None).await.entries,
        [
            entry("hobi", AgentStanding::Contained, 0),
            entry("jin", AgentStanding::Enrolled, 0)
        ]
    );
    common::write_0640(
        &maknae_authz_basic::PolicyPaths::in_dir(&w.root).authz,
        PLAIN,
    );
    w.reload();
    let page = w.list(None).await;
    assert!(page.entries.is_empty(), "{page:?}");
    assert_eq!(page.undecided, 0);
}

#[tokio::test]
async fn a_removed_agent_with_waiting_reports_is_listed_removed() {
    let w = world("removed", &hobi_and_jin());
    let id = w.submit("hobi").await;
    w.report(&id, "r");
    std::fs::remove_dir_all(w.root.join(maknae_config::AGENTS_DIR).join("hobi")).unwrap();
    w.reload();
    assert_eq!(
        w.list(None).await.entries,
        [entry("hobi", AgentStanding::Removed, 1)]
    );
    let page = reports(w.ask(collect("hobi", None)).await);
    let cursor = page.entries[0].cursor.seq();
    reports(w.ask(collect("hobi", Some(cursor))).await);
    assert!(w.list(None).await.entries.is_empty(), "nothing waits");
}

#[tokio::test]
async fn waiting_counts_what_collect_would_return() {
    let w = world("waiting", &hobi_and_jin());
    let held = w.mine("hobi", HOBI_UID);
    w.report(&held, "held");
    w.store().mark_unenrolled(&maknae_kernel::Containing(
        maknae_kernel::FixedEnrollment([(hobi(), HOBI_UID)].into()),
        [w.me].into(),
    ));
    w.store().close_all_due();
    assert_eq!(w.store().record(&held).unwrap().state, TaskState::Held);
    for text in ["a", "b"] {
        let id = w.mine("hobi", HOBI_UID);
        w.report(&id, text);
    }
    assert_eq!(
        w.list(None).await.entries,
        [entry("hobi", AgentStanding::Enrolled, 2)]
    );
    assert_eq!(reports(w.ask(collect("hobi", None)).await).entries.len(), 2);
}

#[tokio::test]
async fn a_withdrawn_tasker_still_sees_and_collects_its_notice() {
    let w = world("withdrawn", &hobi_and_jin());
    let queued = w.submit("hobi").await;
    w.agent_policy("hobi", "schema_version: 1\ntaskers: []\n");
    let records = Records::new(0);
    let idle = w.agent_ask("hobi", HOBI_UID, CLAIM, None, &records).await;
    assert!(
        matches!(idle, Some(RespResult::Ok(Payload::TaskIdle))),
        "{idle:?}"
    );
    w.store().close_all_due();
    assert_eq!(
        w.store().record(&queued).unwrap().close,
        Some(TaskClose::Withdrawn)
    );
    assert_eq!(
        w.list(None).await.entries,
        [entry("hobi", AgentStanding::Withdrawn, 1)]
    );
    let page = reports(w.ask(collect("hobi", None)).await);
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].close, Some(TaskClose::Withdrawn));
}

#[tokio::test]
async fn a_withdrawn_tasker_with_a_working_task_can_still_stop_it() {
    let w = world("withdrawn-working", &hobi_and_jin());
    let id = w.submit("hobi").await;
    assert_eq!(w.claimed("hobi", HOBI_UID).await, id);
    w.agent_policy("hobi", "schema_version: 1\ntaskers: []\n");
    assert_eq!(
        w.list(None).await.entries,
        [entry("hobi", AgentStanding::Withdrawn, 0)]
    );
    let stopped = w
        .ask(Verb::TaskStop {
            task: maknae_proto::TaskRef::from_id(&id),
        })
        .await;
    assert!(
        matches!(&stopped, RespResult::Ok(Payload::TaskAcknowledged(v)) if v.close == Some(TaskClose::Stopped)),
        "{stopped:?}"
    );
}

#[tokio::test]
async fn waiting_is_the_total_across_collect_pages() {
    let w = world("pages", &hobi_and_jin());
    let total = 40;
    for n in 0..total {
        let id = w.mine("hobi", HOBI_UID);
        w.report(&id, &format!("r{n}"));
    }
    let listed = w.list(None).await.entries;
    assert_eq!(listed, [entry("hobi", AgentStanding::Enrolled, total)]);
    let (mut seen, mut pages, mut after) = (0, 0, None);
    loop {
        let page = reports(w.ask(collect("hobi", after)).await);
        if page.entries.is_empty() {
            break;
        }
        seen += page.entries.len();
        pages += 1;
        after = Some(page.entries.last().unwrap().cursor.seq());
    }
    assert!(pages > 1, "the reports span more than one collect page");
    assert_eq!(seen, total as usize);
}

fn many_agents(n: u32) -> Vec<Agent> {
    (0..n)
        .map(|i| agent(&many(i), MANY_UID + i, PLAIN))
        .collect()
}

#[tokio::test]
async fn the_list_pages_by_agent_id() {
    let w = world("paging", &many_agents(300));
    let removed = w.mine("a150b", 14_000);
    w.report(&removed, "r");
    let first = w.list(None).await;
    assert_eq!(first.entries.len(), maknae_proto::AGENT_PAGE_MAX);
    assert_eq!(
        first.next.as_deref(),
        Some(first.entries.last().unwrap().agent.as_str())
    );
    let second = w.list(first.next.as_deref()).await;
    assert_eq!(second.next, None);
    let got: Vec<AgentEntry> = first.entries.into_iter().chain(second.entries).collect();
    let mut want: Vec<AgentEntry> = (0..300)
        .map(|i| entry(&many(i), AgentStanding::Enrolled, 0))
        .collect();
    want.push(entry("a150b", AgentStanding::Removed, 1));
    want.sort_by(|a, b| a.agent.cmp(&b.agent));
    assert_eq!(got, want);
}

#[tokio::test]
async fn an_invalid_after_is_a_bad_request() {
    let w = world("bad-after", &hobi_and_jin());
    let records = Records::new(0);
    let got = w.ask_with(list(Some("Not An Id")), &records).await;
    assert!(
        matches!(&got, RespResult::Err(e) if e.code == ProtoErrCode::BadRequest),
        "{got:?}"
    );
    let said = records.snapshot();
    assert!(
        said.iter().any(|r| r.outcome.result == "deny"
            && r.outcome.reason == "agent list fails operand pre-gate: cursor not acceptable"),
        "{said:?}"
    );
}

#[tokio::test]
async fn a_cursor_naming_an_agent_the_caller_may_not_task_is_refused() {
    let w = world("cursor-refused", &hobi_and_jin());
    for after in ["jin", "zzz"] {
        let records = Records::new(0);
        let got = w.ask_with(list(Some(after)), &records).await;
        assert!(
            matches!(&got, RespResult::Err(e) if e.code == ProtoErrCode::Unauthorized),
            "{after}: {got:?}"
        );
        assert_eq!(
            reasons(&records),
            ["deny the cursor names no agent the caller holds tasks with or may task"],
            "{after}"
        );
    }
}

#[tokio::test]
async fn a_cursor_naming_a_held_agent_is_accepted() {
    let w = world("cursor-held", &hobi_and_jin());
    w.mine("hobi", HOBI_UID);
    w.agent_policy("hobi", "schema_version: 1\ntaskers: []\n");
    let page = w.list(Some("hobi")).await;
    assert!(page.entries.is_empty(), "{page:?}");
    assert_eq!((page.next, page.undecided), (None, 0));
}

#[tokio::test]
async fn a_refused_collect_leaves_withdrawn_and_removed_candidates_out() {
    let w = world("collect-refused", &hobi_and_jin());
    let held = w.mine("hobi", HOBI_UID);
    w.report(&held, "r");
    let gone = w.mine("rm", 14_000);
    w.report(&gone, "r");
    assert_eq!(
        w.list(None).await.entries,
        [
            entry("hobi", AgentStanding::Enrolled, 1),
            entry("rm", AgentStanding::Removed, 1)
        ]
    );
    common::write_0640(
        &maknae_authz_basic::PolicyPaths::in_dir(&w.root).authz,
        PLAIN,
    );
    w.reload();
    assert!(
        unauthorized(&w.ask(collect("hobi", None)).await),
        "the collect decision is refused"
    );
    let page = w.list(None).await;
    assert!(page.entries.is_empty(), "{page:?}");
    assert_eq!(page.undecided, 0);
}

fn unauthorized(r: &RespResult) -> bool {
    matches!(r, RespResult::Err(e) if e.code == ProtoErrCode::Unauthorized)
}

#[tokio::test]
async fn the_banner_rides_every_page() {
    let w = world("banner", &hobi_and_jin());
    let spec = BannerSpec {
        text: "sentinel-630-banner".into(),
        color: None,
    };
    *w.agents.banner.write().unwrap() = Some(spec.clone());
    for after in [None, Some("hobi")] {
        assert_eq!(w.list(after).await.banner, Some(spec.clone()), "{after:?}");
    }
}

#[tokio::test]
async fn the_agent_channel_cannot_list_agents() {
    let w = world("agent-channel", &hobi_and_jin());
    let records = Records::new(0);
    let got = w
        .agent_ask("hobi", HOBI_UID, list(None), None, &records)
        .await;
    assert!(
        got.is_none_or(|r| matches!(r, RespResult::Err(e) if e.code == ProtoErrCode::Unauthorized)),
        "refused"
    );
    let said = records.snapshot();
    assert!(
        said.iter().any(|r| r.action == "session.task"
            && r.outcome.result == "deny"
            && r.outcome.reason == "an agent is not a tasker here"),
        "{said:?}"
    );
}

#[tokio::test]
#[ignore = "a measurement, run by hand"]
async fn list_of_a_hundred_agents() {
    let w = world("hundred", &many_agents(100));
    w.list(None).await;
    let started = std::time::Instant::now();
    let page = w.list(None).await;
    let elapsed = started.elapsed();
    assert_eq!(page.entries.len(), 100);
    println!("list_of_a_hundred_agents: {elapsed:?} for one AgentList through handle()");
}
