//! #628 Task 3: submitting and the tasker verbs, driven through the real `handle()`,
//! the real composed PDP, and a store with a manual clock.
mod common;
use common::Records;
use maknae_io::Zeroizing;
use maknae_kernel::{AgentAdmission, ManualClock, MemTaskBlobs, RootTasker, TaskStore};
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

fn secret(s: &str) -> SecretText {
    SecretText(Zeroizing::new(s.into()))
}

fn world(tag: &str, role: &str, grant: bool) -> World {
    let dir = std::env::temp_dir().join(format!("task628_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = common::DirGuard(dir.canonicalize().unwrap());
    let paths = maknae_authz_basic::PolicyPaths::in_dir(&root);
    let roles = if grant {
        format!("roles:\n  {role}:\n    allow: [\"session.task\"]\n")
    } else {
        String::new()
    };
    common::write_0640(
        &paths.authz,
        &format!("schema_version: 1\npermissions:\n  allow: []\n  deny: []\n{roles}"),
    );
    common::write_0640(&paths.sensitive, common::EMPTY_SENSITIVE);
    let user = common::euid_name();
    common::write_0640(
        &paths.bindings,
        &format!("schema_version: 1\nbindings:\n  {role}: [\"{user}\"]\n"),
    );
    let agents_dir = root.join(maknae_config::AGENTS_DIR);
    std::fs::create_dir_all(&agents_dir).unwrap();
    std::fs::set_permissions(&agents_dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    for (id, uid) in [("hobi", HOBI_UID), ("suga", SUGA_UID)] {
        let d = agents_dir.join(id);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o750)).unwrap();
        common::write_0640(
            &d.join(maknae_config::ENROLLMENT_FILE),
            &format!("agent_id: {id}\naccount: {id}-svc\nuid: {uid}\nrole: user\n"),
        );
        common::write_0640(
            &d.join(maknae_config::POLICY_FILE),
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
        );
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
        signer: Arc::new(maknae_kernel::UnverifiedSigner),
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
        use tokio::io::AsyncReadExt;
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let session = maknae_kernel::SessionRecord::for_test(self.me, Some(self.user.clone()))
            .with_session_id(628);
        let served = maknae_kernel::handle_with_attempt_caps(
            server,
            Some("spiffe://d/plane/cli".into()),
            Arc::new(session),
            maknae_kernel::FactsGate::allow_as(
                Some(self.user.clone()),
                Some(PathBuf::from(&*self.root)),
            ),
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
            maknae_io::DelegatedFds::new(1),
            common::no_baseline(),
            maknae_kernel::AttemptCaps::default(),
            common::conversations(),
            self.agents.clone(),
        );
        let task = tokio::spawn(served);
        let body = maknae_proto::encode_request(&maknae_proto::Request {
            task: None,
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
        tokio::time::timeout(Duration::from_secs(5), task)
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
        last.outcome.reason.contains("did not answer in time"),
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
