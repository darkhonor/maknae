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
const JIN_UID: u32 = 12_103;
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
    board_blobs: MemTaskBlobs,
    me: u32,
    user: String,
    cfg: maknae_config::TransportConfig,
    forges: maknae_config::ForgeSet,
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
    let roles = match (grant, role) {
        (false, _) => String::new(),
        (true, "user") => "roles:\n  user:\n    allow: [\"session.task\"]\n".to_string(),
        (true, _) => format!(
            "roles:\n  {role}:\n    allow: [\"session.task\"]\n  user:\n    allow: [\"session.task\"]\n"
        ),
    };
    world_in(tag, role, &roles, hobi, suga)
}

fn world_in(tag: &str, role: &str, roles: &str, hobi: &str, suga: &str) -> World {
    world_of(
        tag,
        role,
        roles,
        &[("hobi", HOBI_UID, hobi), ("suga", SUGA_UID, suga)],
    )
}

fn uid_of(agent: &str) -> u32 {
    match agent {
        "hobi" => HOBI_UID,
        "jin" => JIN_UID,
        _ => SUGA_UID,
    }
}

fn world_of(tag: &str, role: &str, roles: &str, agents: &[(&str, u32, &str)]) -> World {
    let dir = std::env::temp_dir().join(format!("task628_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = common::DirGuard(dir.canonicalize().unwrap());
    let paths = maknae_authz_basic::PolicyPaths::in_dir(&root);
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
    for &(id, uid, policy) in agents {
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
                JIN_UID => "jin-svc",
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
    let board_blobs = MemTaskBlobs::default();
    let board = maknae_kernel::BoardStore::open(Box::new(board_blobs.clone()), clock.clone())
        .expect("an empty board");
    let agents = AgentAdmission {
        view: Arc::new(maknae_kernel::SnapshotEnrollment(Arc::clone(&pdp))),
        tasks,
        signer: Arc::new(FixedSigner),
        banner: Default::default(),
        board: Arc::new(board),
        switches: Arc::new(maknae_kernel::SwitchesOff),
    };
    let mut cfg = maknae_config::transport_from_section(None).unwrap();
    cfg.prompt_max_bytes = maknae_config::PROMPT_MAX_BYTES_FLOOR;
    World {
        root,
        pdp,
        agents,
        clock,
        blobs,
        board_blobs,
        me,
        user,
        cfg,
        forges: maknae_config::ForgeSet::empty(),
    }
}

struct Wiring {
    live: Arc<maknae_kernel::LiveConfig>,
    egress: Arc<dyn maknae_kernel::Egress>,
    conversations: Arc<dyn maknae_kernel::ConversationStore>,
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
        let (session, gate) = self.agent_session(agent);
        self.serve(session, gate, verb, task, records, dir).await
    }

    fn agent_session(
        &self,
        agent: &str,
    ) -> (maknae_kernel::SessionRecord, Arc<maknae_kernel::FactsGate>) {
        let uid = uid_of(agent);
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
        (session, gate)
    }

    /// One request on the agent channel as `agent`, decided by `authorizer`.
    async fn agent_as<P>(
        &self,
        authorizer: &Arc<P>,
        agent: &str,
        verb: Verb,
        task: Option<TaskId>,
        records: &Arc<Records>,
    ) -> Option<RespResult>
    where
        P: maknae_security::Authorizer
            + maknae_kernel::SensitiveNow
            + maknae_kernel::CatalogNow
            + Send
            + Sync
            + 'static,
    {
        let _shared = STORE.read().await;
        let (session, gate) = self.agent_session(agent);
        let raw = self
            .serve_as(
                Arc::clone(authorizer),
                session,
                gate,
                verb,
                task,
                records,
                None,
                Wiring {
                    live: Arc::new(maknae_kernel::LiveConfig::new(Default::default(), None)),
                    egress: maknae_kernel::unavailable_egress(),
                    conversations: common::conversations(),
                },
            )
            .await;
        let mut cursor = &raw[..];
        let frame = common::read_frame(&mut cursor, 1 << 20).await.ok()?;
        Some(maknae_proto::decode_response(&frame).unwrap().result)
    }

    /// One request on the agent channel whose reply is never read: the pipe holds one byte
    /// and the write bound is 300 ms.
    async fn serve_unread<P>(
        &self,
        authorizer: &Arc<P>,
        agent: &str,
        verb: Verb,
        task: Option<TaskId>,
        records: &Arc<Records>,
    ) where
        P: maknae_security::Authorizer
            + maknae_kernel::SensitiveNow
            + maknae_kernel::CatalogNow
            + Send
            + Sync
            + 'static,
    {
        let _shared = STORE.read().await;
        let (session, gate) = self.agent_session(agent);
        let (mut client, server) = tokio::io::duplex(1);
        let mut cfg = self.cfg.clone();
        cfg.read_timeout_ms = 300;
        let body = maknae_proto::encode_request(&maknae_proto::Request {
            task,
            protocol_version: maknae_proto::PROTOCOL_VERSION,
            verb,
        })
        .unwrap();
        let writer = tokio::spawn(async move {
            let _ = common::write_frame(&mut client, &body).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(client);
        });
        let served = maknae_kernel::handle_with_attempt_caps(
            server,
            Some("spiffe://d/plane/cli".into()),
            Arc::new(session),
            gate,
            Arc::clone(records),
            cfg,
            serde_json::json!({}),
            Arc::clone(authorizer),
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
        tokio::time::timeout(Duration::from_secs(4), served)
            .await
            .expect("the handler returns within the write bound");
        writer.abort();
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
        self.agent(
            agent,
            Verb::TaskReport {
                text: secret(text),
                seen_follow_ups: None,
            },
            Some(*id),
        )
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
                banner: self.agents.banner.clone(),
                board: Arc::new(
                    maknae_kernel::BoardStore::open(
                        Box::new(self.board_blobs.clone()),
                        self.clock.clone(),
                    )
                    .expect("the board reopens"),
                ),
                switches: self.agents.switches.clone(),
            },
            clock: self.clock.clone(),
            blobs: self.blobs.clone(),
            board_blobs: self.board_blobs.clone(),
            me: self.me,
            user: self.user.clone(),
            cfg: self.cfg.clone(),
            forges: self.forges.clone(),
        }
    }

    async fn serve<E: maknae_audit_append::AuditEmit + Send + Sync + 'static>(
        &self,
        session: maknae_kernel::SessionRecord,
        gate: Arc<maknae_kernel::FactsGate>,
        verb: Verb,
        task: Option<TaskId>,
        records: &Arc<E>,
        dir: Option<&std::path::Path>,
    ) -> Vec<u8> {
        self.serve_wired(
            session,
            gate,
            verb,
            task,
            records,
            dir,
            Wiring {
                live: Arc::new(maknae_kernel::LiveConfig::with_forges_for_test(
                    Default::default(),
                    None,
                    self.forges.clone(),
                )),
                egress: maknae_kernel::unavailable_egress(),
                conversations: common::conversations(),
            },
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn serve_wired<E: maknae_audit_append::AuditEmit + Send + Sync + 'static>(
        &self,
        session: maknae_kernel::SessionRecord,
        gate: Arc<maknae_kernel::FactsGate>,
        verb: Verb,
        task: Option<TaskId>,
        records: &Arc<E>,
        dir: Option<&std::path::Path>,
        wiring: Wiring,
    ) -> Vec<u8> {
        self.serve_as(
            Arc::clone(&self.pdp),
            session,
            gate,
            verb,
            task,
            records,
            dir,
            wiring,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn serve_as<P, E>(
        &self,
        authorizer: Arc<P>,
        session: maknae_kernel::SessionRecord,
        gate: Arc<maknae_kernel::FactsGate>,
        verb: Verb,
        task: Option<TaskId>,
        records: &Arc<E>,
        dir: Option<&std::path::Path>,
        wiring: Wiring,
    ) -> Vec<u8>
    where
        P: maknae_security::Authorizer
            + maknae_kernel::SensitiveNow
            + maknae_kernel::CatalogNow
            + Send
            + Sync
            + 'static,
        E: maknae_audit_append::AuditEmit + Send + Sync + 'static,
    {
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
            authorizer,
            wiring.live,
            Arc::new("basic+ceiling".into()),
            Arc::new("US".into()),
            Arc::new("ml-dsa-87".to_string()),
            Arc::new(None),
            wiring.egress,
            Duration::from_secs(2),
            delegated,
            common::no_baseline(),
            maknae_kernel::AttemptCaps::default(),
            wiring.conversations,
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
        let uid = uid_of(agent);
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
            bindings: vec![],
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

/// The head of hobi's queue under `uid`, as a standing found good on an unchanging load.
fn standing(w: &World, uid: u32) -> Option<maknae_kernel::GoodStanding> {
    w.store()
        .next_for(&hobi(), uid)
        .map(|(task, _)| maknae_kernel::GoodStanding {
            task,
            load: maknae_kernel::Load::fixed(),
        })
}

fn closes(due: &[Due]) -> Vec<(TaskId, TaskClose)> {
    due.iter()
        .filter_map(|d| match d.why {
            DueFor::Close(close) => Some((d.task, close)),
            DueFor::Expiry | DueFor::Hold(_) | DueFor::Orphaned => None,
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
        task: None,
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

/// Signs with a kernel leaf of a test CA, so an agent can verify what it is handed.
struct CaSigner(maknae_vault::PlaneIdentity);

impl maknae_kernel::TaskSigner for CaSigner {
    fn sign(
        &self,
        task: maknae_proto::TaskObject,
    ) -> Result<maknae_proto::SignedTask, TaskRefusal> {
        maknae_vault::task_sig::sign_task(&self.0, task).map_err(|_| TaskRefusal::Unsigned)
    }
    fn current_leaf(&self) -> Option<[u8; 32]> {
        maknae_vault::task_sig::identity_fingerprint(&self.0).ok()
    }
}

#[tokio::test]
async fn a_bound_task_is_accepted_sealed_and_delivered_verified() {
    use maknae_crypto::plane_key::PlaneKey;
    const HOST: &str = "git.sentinel-168a.example";
    const STRANGER: &str = "git.stranger-168a.example";
    const REPO: &str = "sentinel-168a/alpha";
    let mut w = world("bound", "user", true);
    let ca = maknae_vault::test_pki::TestCa::new(PlaneKey::MlDsa87);
    w.agents.signer = Arc::new(CaSigner(ca.kernel(PlaneKey::MlDsa87, None)));
    w.forges = maknae_config::forges_from_section(Some(
        &maknae_config::load_str(&format!(
            "- {{ name: sentinel-168a-forge, kind: git, host: {HOST}, provider: github }}\n"
        ))
        .unwrap(),
    ))
    .unwrap();
    let bound_to = |server: &str| {
        let Verb::TaskSubmit { mut task } = submit("hobi", "sentinel-168a-ask") else {
            unreachable!()
        };
        task.bindings = vec![maknae_proto::BindingRequest::Git(maknae_proto::GitRef {
            server: server.into(),
            base: REPO.into(),
            change: Some(5),
        })];
        Verb::TaskSubmit { task }
    };
    let records = Records::new(0);
    let refused = w.ask_with(bound_to(STRANGER), &records).await;
    assert!(unauthorized(&refused), "{refused:?}");
    let trail = reasons(&records);
    assert!(
        trail
            .iter()
            .any(|t| t.starts_with("deny") && t.contains(STRANGER)),
        "{trail:?}"
    );
    assert!(w.claim("hobi").await.is_none(), "nothing was stored");
    let sealed = vec![maknae_proto::Binding::Git(maknae_proto::GitBinding {
        server: HOST.into(),
        base: REPO.into(),
        head: None,
        change: Some(5),
    })];
    let records = Records::new(0);
    let view = match w.ask_with(bound_to(HOST), &records).await {
        RespResult::Ok(Payload::TaskAccepted(v)) => v,
        other => panic!("{other:?}"),
    };
    assert_eq!(view.bindings, sealed);
    let queued: Vec<_> = records
        .snapshot()
        .into_iter()
        .filter(|r| r.action == "session.task" && r.outcome.reason == "task queued")
        .collect();
    assert_eq!(queued.len(), 1, "{:?}", reasons(&records));
    assert_eq!(
        queued[0].subject.bindings,
        [maknae_audit_append::RecordBinding {
            kind: maknae_audit_append::BindingKind::Git,
            server: HOST.into(),
            base: REPO.into(),
            head: None,
            change: Some(5),
        }]
    );
    let (signed, _) = w.claim("hobi").await.expect("the bound task is delivered");
    assert_eq!(signed.task.task_id, view.task.to_id());
    assert_eq!(signed.task.bindings, sealed);
    assert_eq!(
        maknae_vault::task_sig::verify_task(
            &ca.trust(),
            maknae_vault::test_pki::TRUST_DOMAIN,
            &hobi(),
            &signed,
            maknae_io::now_since_epoch().unwrap(),
        ),
        Ok(())
    );
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
            cursor: maknae_proto::TaskCursor::from_seq(1),
            bindings: vec![],
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
async fn an_agent_fetches_the_catalog_its_claim_stamped() {
    let w = world_in(
        "catalog-fetch",
        "user",
        "roles:\n  user:\n    allow: [\"session.task\", \"tool.catalog\"]\n",
        PLAIN,
        PLAIN,
    );
    let records = Records::new(0);
    let reply = |raw: Vec<u8>| async move {
        let mut cursor = &raw[..];
        let frame = common::read_frame(&mut cursor, 1 << 20)
            .await
            .expect("one frame");
        maknae_proto::decode_response(&frame).unwrap()
    };
    let claim = reply(w.agent_raw("hobi", CLAIM, None, &records).await).await;
    assert!(
        matches!(claim.result, RespResult::Ok(Payload::TaskIdle)),
        "{claim:?}"
    );
    let stamp = claim.catalog_digest.expect("a claim reply is stamped");
    let fetched = reply(
        w.agent_raw("hobi", Verb::ToolCatalog {}, None, &records)
            .await,
    )
    .await;
    let RespResult::Ok(Payload::ToolCatalog(view)) = fetched.result else {
        panic!("tool.catalog: {fetched:?} {:?}", reasons(&records));
    };
    assert_eq!(view.digest, stamp);
    assert_eq!(
        maknae_proto::CatalogDigest(maknae_crypto::sha256(&view.graph.0)),
        view.digest
    );
}

#[tokio::test]
async fn a_board_request_is_refused_board_off_site() {
    let w = world_in(
        "board-off",
        "user",
        "roles:\n  user:\n    allow: [\"session.task\", \"board.post\", \"board.read\"]\n",
        PLAIN,
        PLAIN,
    );
    let id = w.submit("hobi", "a").await;
    assert_eq!(w.claimed("hobi").await, id);
    let records = Records::new(0);
    let post = Verb::BoardPost {
        post: maknae_proto::PostDraft {
            kind: maknae_proto::PostKind::Note,
            to: maknae_proto::Addressee::Board,
            in_reply_to: None,
            body: secret("sentinel-695-board-off"),
            attachments: vec![],
        },
    };
    let read = Verb::BoardRead { seen_through: None };
    for (verb, action) in [(post, "board.post"), (read, "board.read")] {
        let answer = w
            .agent_with("hobi", verb, Some(id), &records)
            .await
            .expect("an answer");
        assert!(unauthorized(&answer), "{action}: {answer:?}");
        let trail: Vec<_> = records
            .snapshot()
            .into_iter()
            .filter(|r| r.action == action)
            .map(|r| (r.outcome.result, r.outcome.reason, r.outcome.posture))
            .collect();
        assert_eq!(
            trail,
            [(
                "deny".to_string(),
                "board off: site".to_string(),
                "unavailable".to_string()
            )],
            "{action}"
        );
    }
    assert!(records
        .snapshot()
        .iter()
        .all(|r| !format!("{r:?}").contains("sentinel-695-board-off")));
    assert_eq!(w.store().hot(&id).unwrap().actions, 2);
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
async fn a_heartbeats_follow_ups_name_the_working_task() {
    let w = world("beat-names", "user", true);
    let first = w.submit("hobi", "a").await;
    w.submit("hobi", "b").await;
    assert_eq!(w.claimed("hobi").await, first);
    match w.beat("hobi", 0).await {
        RespResult::Ok(Payload::TaskFollowUps(f)) => assert_eq!(f.task, r(&first)),
        other => panic!("not follow-ups: {other:?}"),
    }
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
                seen_follow_ups: None,
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
async fn a_report_that_has_not_seen_every_follow_up_is_refused_and_changes_nothing() {
    let w = world("report-unseen", "user", true);
    let id = w.submit("hobi", "a").await;
    let other = w.submit("hobi", "b").await;
    assert_eq!(w.claimed("hobi").await, id);
    w.ask(Verb::TaskAdd {
        task: r(&id),
        text: secret("f1"),
    })
    .await;
    let report = |seen| Verb::TaskReport {
        text: secret("sentinel-629-unseen"),
        seen_follow_ups: seen,
    };
    let records = Records::new(0);
    let stale = w
        .agent_with("hobi", report(Some(0)), Some(id), &records)
        .await
        .unwrap();
    assert!(unauthorized(&stale), "{stale:?}");
    assert!(
        reasons(&records)
            .iter()
            .any(|t| t.contains("follow-ups the report has not seen")),
        "{:?}",
        reasons(&records)
    );
    let rec = w.store().record(&id).unwrap();
    assert_eq!(
        (rec.state, rec.report.is_none()),
        (TaskState::Working, true)
    );
    let seen = w.agent("hobi", report(Some(1)), Some(id)).await;
    assert!(
        matches!(&seen, RespResult::Ok(Payload::TaskAcknowledged(v)) if v.state == TaskState::Reported),
        "{seen:?}"
    );
    assert_eq!(w.claimed("hobi").await, other);
    let unchecked = w.agent("hobi", report(None), Some(other)).await;
    assert!(
        matches!(&unchecked, RespResult::Ok(Payload::TaskAcknowledged(_))),
        "{unchecked:?}"
    );
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
            Verb::TaskReport {
                text: secret("r"),
                seen_follow_ups: None,
            },
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
        w.cannot_cite(
            "hobi",
            Verb::TaskReport {
                text: secret("r"),
                seen_follow_ups: None,
            },
            id
        )
        .await,
        "a queued task is not citable"
    );
    assert_eq!(w.claimed("suga").await, sugas);
    let records = Records::new(0);
    let foreign = w
        .agent_with(
            "hobi",
            Verb::TaskReport {
                text: secret("r"),
                seen_follow_ups: None,
            },
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
                seen_follow_ups: None,
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
    w.agent_reports("suga", &sub, "sentinel-628-sub").await;
    assert!(
        reports(w.ask(collect("suga", None)).await)
            .entries
            .is_empty(),
        "the person did not submit the sub-task"
    );
    assert!(
        reports(w.agent("hobi", collect("suga", None), None).await)
            .entries
            .is_empty(),
        "an uncited collect reaches only tasks given with no parent"
    );
    let page = reports(w.agent("hobi", collect("suga", None), Some(parent)).await);
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
        Verb::TaskReport {
            text: secret("r"),
            seen_follow_ups: None,
        },
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
            &only(&[]),
            standing(&w, HOBI_UID).as_ref(),
        ),
        Ok(Claimed::Idle),
        "the old uid is handed nothing"
    );
    match w.store().claim(
        &hobi(),
        AGAIN,
        &FixedSigner,
        &only(&[]),
        standing(&w, AGAIN).as_ref(),
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
            Vec::new(),
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
    assert!(
        unauthorized(
            &w.agent("hobi", Verb::TaskStatus { task: r(&sub) }, None)
                .await
        ),
        "an uncited status does not reach a sub-task"
    );
    let status = w
        .agent("hobi", Verb::TaskStatus { task: r(&sub) }, Some(parent))
        .await;
    assert!(
        matches!(status, RespResult::Ok(Payload::TaskState(v)) if v.state == TaskState::Working)
    );
    let stopped = w
        .agent("hobi", Verb::TaskStop { task: r(&sub) }, Some(parent))
        .await;
    assert!(
        matches!(&stopped, RespResult::Ok(Payload::TaskAcknowledged(v)) if v.close == Some(TaskClose::Stopped)),
        "{stopped:?}"
    );
    assert!(matches!(
        w.beat("suga", 1).await,
        RespResult::Ok(Payload::TaskState(v)) if v.close == Some(TaskClose::Stopped)
    ));
    let page = reports(w.agent("hobi", collect("suga", None), Some(parent)).await);
    assert_eq!(
        report_ids(&page),
        vec![sub],
        "held for the submitting agent under its parent"
    );
    w.ask(Verb::TaskStop { task: r(&parent) }).await;
    let said = w.store().sweep();
    assert!(
        said.iter()
            .any(|d| d.task == sub && d.parent == Some(parent) && d.why == DueFor::Orphaned),
        "{said:?}"
    );
    assert!(
        w.store().record(&sub).is_none(),
        "once its parent ends, no tasker can collect the stop notice, and it is removed"
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
async fn a_started_task_is_delivered_fresh_until_a_request_cites_it() {
    let w = world("claim-fresh", "user", true);
    let id = w.submit("hobi", "a").await;
    for (cite, fresh) in [(false, true), (true, true), (false, false)] {
        match w.agent("hobi", CLAIM, None).await {
            RespResult::Ok(Payload::TaskDelivered(d)) => assert_eq!(d.fresh, fresh),
            other => panic!("claim: {other:?}"),
        }
        if cite {
            assert!(matches!(
                w.agent("hobi", Verb::Ping, Some(id)).await,
                RespResult::Ok(_)
            ));
        }
    }
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
            Verb::TaskReport {
                text: secret("r"),
                seen_follow_ups: None,
            },
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

#[tokio::test]
async fn an_acknowledgement_leaves_a_report_that_is_held_while_it_runs() {
    let w = world("ack-held", "user", true);
    let first = w.mine("hobi");
    let second = w.mine("hobi");
    w.report(&first, "r1");
    w.report(&second, "r2");
    let me = Tasker::Uid(w.me);
    let (store, view) = (Arc::clone(&w.agents.tasks), containing(&w, &[w.me]));
    w.blobs.after_save(move || store.mark_unenrolled(&view));
    let gone = w.store().acknowledged(&me, &hobi(), 2).unwrap();
    assert_eq!(gone.len(), 1, "only the report taken before the hold");
    let left = if gone[0] == first { second } else { first };
    assert!(w.store().record(&gone[0]).is_none());
    assert_eq!(
        w.store().record(&left).unwrap().state,
        TaskState::Reported,
        "held mid-way: left in place"
    );
    assert_eq!(holds(&w.store().close_all_due()), vec![left]);
    assert_eq!(w.store().record(&left).unwrap().state, TaskState::Held);
}

#[tokio::test]
async fn an_expiry_pass_leaves_a_report_that_is_held_while_it_runs() {
    let w = world("expiry-held", "user", true);
    let first = w.mine("hobi");
    let second = w.mine("hobi");
    w.report(&first, "r1");
    w.report(&second, "r2");
    w.clock.set(T0 + REPORT_HOLD.as_secs() as i64);
    let due = w.store().due(8);
    assert_eq!(due.len(), 2);
    let (store, view) = (Arc::clone(&w.agents.tasks), containing(&w, &[w.me]));
    w.blobs.after_save(move || store.mark_unenrolled(&view));
    assert_eq!(w.store().perform(&due), 1);
    assert!(w.store().record(&first).is_none());
    assert_eq!(
        w.store().record(&second).unwrap().state,
        TaskState::Reported
    );
    assert_eq!(holds(&w.store().close_all_due()), vec![second]);
}

/// Contains the tasker while the submission's `task stored` record is appended.
struct ContainsOnStored {
    inner: Arc<Records>,
    store: Arc<TaskStore>,
    view: maknae_kernel::Containing<FixedEnrollment>,
}

impl maknae_audit_append::AuditEmit for ContainsOnStored {
    fn emit(
        &self,
        record: &maknae_audit_append::AuditRecord,
    ) -> impl std::future::Future<Output = Result<(), maknae_audit_append::AuditError>> + Send {
        if record.outcome.reason == "task stored" {
            self.store.mark_unenrolled(&self.view);
        }
        self.inner.emit(record)
    }
}

#[tokio::test]
async fn a_submission_held_at_its_confirm_is_recorded_and_answered_as_held() {
    let w = world("submit-held", "user", true);
    let records = Records::new(0);
    let emit = Arc::new(ContainsOnStored {
        inner: Arc::clone(&records),
        store: Arc::clone(&w.agents.tasks),
        view: containing(&w, &[w.me]),
    });
    let session =
        maknae_kernel::SessionRecord::for_test(w.me, Some(w.user.clone())).with_session_id(628);
    let gate =
        maknae_kernel::FactsGate::allow_as(Some(w.user.clone()), Some(PathBuf::from(&*w.root)));
    let raw = {
        let _shared = STORE.read().await;
        w.serve(session, gate, submit("hobi", "a"), None, &emit, None)
            .await
    };
    let mut cursor = &raw[..];
    let frame = common::read_frame(&mut cursor, 1 << 20).await.unwrap();
    let view = match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Ok(Payload::TaskAccepted(v)) => v,
        other => panic!("{other:?}"),
    };
    assert_eq!(view.state, TaskState::Held);
    assert_eq!(
        reasons(&records),
        vec![
            "permit task stored",
            "deny task held: tasker contained",
            "permit task held"
        ],
        "the trail never calls a held submission queued"
    );
    let id = view.task.to_id();
    assert!(task_records(&records)
        .iter()
        .all(|r| r.subject.task_id == Some(id.to_string())));
    assert!(w.claim("hobi").await.is_none());
    assert_eq!(w.store().record(&id).unwrap().state, TaskState::Held);
}

const PROMPTING: &str = "roles:\n  user:\n    allow: [\"session.prompt\", \"session.new\"]\ndestinations:\n  user:\n    allow: [\"provider:openai\"]\n";
const AGENT_PROMPTS: &str =
    "schema_version: 1\nactions:\n  allow: [\"session.prompt\", \"session.new\"]\n";
const AGENT_PREFIX: &str = "maknae/agents";

#[derive(Default)]
struct KeyPaths(std::sync::Mutex<Vec<String>>);

impl KeyPaths {
    fn seen(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

impl maknae_kernel::Egress for KeyPaths {
    fn ready(&self) -> Result<(), maknae_kernel::EgressFailure> {
        Ok(())
    }
    fn deadline(&self) -> Duration {
        Duration::from_secs(5)
    }
    fn send(
        &self,
        _: &maknae_kernel::DurableEgressIntent,
        r: maknae_kernel::EgressRequest,
    ) -> Result<maknae_kernel::EgressReply, maknae_kernel::EgressFailure> {
        self.0.lock().unwrap().push(r.key_vault_path);
        Ok(maknae_kernel::EgressReply {
            reply: maknae_proto::PromptReply {
                reasoning: None,
                tool_calls: vec![],
                blocks: vec![maknae_proto::ContentBlock::Text { text: secret("ok") }],
                usage: None,
            },
        })
    }
}

fn prompt_wiring(owner: u32, agent_prefix: Option<&str>, egress: &Arc<KeyPaths>) -> Wiring {
    let mut authority = common::authority(Some("openai")).unwrap();
    authority.agent_prefix = agent_prefix.map(str::to_string);
    Wiring {
        live: Arc::new(maknae_kernel::LiveConfig::new(
            Default::default(),
            Some(authority),
        )),
        egress: egress.clone(),
        conversations: common::seeded(owner, "/"),
    }
}

fn prompt(subpath: &str) -> Verb {
    Verb::SessionPrompt {
        conversation: common::CONV.into(),
        turns: vec![maknae_proto::Turn::User {
            content: vec![maknae_proto::ContentBlock::Text {
                text: secret("hello"),
            }],
        }],
        output_tokens: None,
        choice: Some(common::choice("openai", common::TEST_MODEL, subpath)),
    }
}

impl World {
    async fn prompt_as_hobi(&self, wiring: Wiring, records: &Arc<Records>) -> Option<RespResult> {
        let _shared = STORE.read().await;
        let mut session = maknae_kernel::SessionRecord::for_test(HOBI_UID, Some("hobi-svc".into()))
            .with_session_id(473);
        session.admission = maknae_kernel::Admission::EnrolledAgent;
        session.channel = maknae_kernel::SessionChannel::Agent {
            agent: hobi(),
            leaf_expires: std::time::Instant::now() + Duration::from_secs(3600),
        };
        let gate = maknae_kernel::FactsGate::for_test(
            Arc::new(AgentFacts {
                user: "hobi-svc".into(),
                dir: PathBuf::from(&*self.root),
            }),
            Duration::from_secs(5),
        );
        let raw = self
            .serve_wired(
                session,
                gate,
                prompt("openai/hobi"),
                None,
                records,
                None,
                wiring,
            )
            .await;
        first(&raw).await
    }

    async fn prompt_as_me(&self, wiring: Wiring, records: &Arc<Records>) -> Option<RespResult> {
        let _shared = STORE.read().await;
        let session = maknae_kernel::SessionRecord::for_test(self.me, Some(self.user.clone()))
            .with_session_id(474);
        let gate = maknae_kernel::FactsGate::allow_as(
            Some(self.user.clone()),
            Some(PathBuf::from(&*self.root)),
        );
        let raw = self
            .serve_wired(
                session,
                gate,
                prompt("openai/hobi"),
                None,
                records,
                None,
                wiring,
            )
            .await;
        first(&raw).await
    }
}

async fn first(raw: &[u8]) -> Option<RespResult> {
    let mut cursor = raw;
    let frame = common::read_frame(&mut cursor, 1 << 20).await.ok()?;
    Some(maknae_proto::decode_response(&frame).unwrap().result)
}

fn prompting(tag: &str) -> World {
    world_in(tag, "user", PROMPTING, AGENT_PROMPTS, PLAIN)
}

#[tokio::test]
async fn an_agent_prompt_reaches_egress_under_its_own_id_never_its_account_or_a_users_tree() {
    let w = prompting("agentkey");
    let egress = Arc::new(KeyPaths::default());
    let records = Records::new(0);
    let got = w
        .prompt_as_hobi(
            prompt_wiring(HOBI_UID, Some(AGENT_PREFIX), &egress),
            &records,
        )
        .await;
    assert!(
        matches!(got, Some(RespResult::Ok(Payload::PromptReply(_)))),
        "{got:?}: {:?}",
        records.snapshot()
    );
    assert_eq!(egress.seen(), ["maknae/agents/hobi/openai/hobi"]);
}

#[tokio::test]
async fn an_agent_prompt_with_no_agent_prefix_is_refused_before_egress() {
    let w = prompting("agentnoprefix");
    let egress = Arc::new(KeyPaths::default());
    let records = Records::new(0);
    let got = w
        .prompt_as_hobi(prompt_wiring(HOBI_UID, None, &egress), &records)
        .await;
    assert!(got.as_ref().is_some_and(unauthorized), "{got:?}");
    assert!(egress.seen().is_empty());
    let denied: Vec<_> = records
        .snapshot()
        .into_iter()
        .filter(|r| {
            r.outcome.result == "deny"
                && r.outcome.reason == maknae_kernel::ChoiceRefusal::NoAgentPrefix.reason()
        })
        .collect();
    assert_eq!(denied.len(), 1, "{:?}", records.snapshot());
    assert_eq!(denied[0].subject.agent.as_deref(), Some("hobi"));
}

#[tokio::test]
async fn a_client_prompt_on_a_host_with_an_agent_prefix_stays_under_the_user_prefix() {
    let w = prompting("userkey");
    let egress = Arc::new(KeyPaths::default());
    let records = Records::new(0);
    let got = w
        .prompt_as_me(prompt_wiring(w.me, Some(AGENT_PREFIX), &egress), &records)
        .await;
    assert!(
        matches!(got, Some(RespResult::Ok(Payload::PromptReply(_)))),
        "{got:?}: {:?}",
        records.snapshot()
    );
    assert_eq!(
        egress.seen(),
        [format!(
            "{}/{}/openai/hobi",
            common::TEST_USER_PREFIX,
            w.user
        )]
    );
}

fn openai() -> maknae_config::ProviderSet {
    use maknae_config::Value;
    maknae_config::providers_from_section(Some(&Value::Seq(vec![Value::Map(vec![
        ("name".into(), Value::Str("openai".into())),
        (
            "endpoint".into(),
            Value::Str("https://api.example.test/v1".into()),
        ),
        (
            "models".into(),
            Value::Seq(vec![Value::Str("gpt-5.6-luna".into())]),
        ),
    ])])))
    .unwrap()
}

/// Opens `sealed` as the Egress Daemon does, at the path the kernel admitted.
fn egress_opens(
    recipient: &maknae_seal::SealPrivateKey,
    admitted: &maknae_kernel::AdmittedChoice<'_>,
    conversation: &str,
) -> bool {
    let expect = maknae_vault::WrapExpectation::new(
        "maknae-kv",
        &admitted.key_vault_path,
        admitted.key_field,
        maknae_vault::USER_KEY_WRAP_TTL,
    )
    .unwrap();
    let p = maknae_vault::aad_parts(&expect, conversation, "openai", admitted.model);
    let aad = maknae_seal::SealAad::new(&maknae_seal::SealContext {
        conversation: p.conversation,
        provider: p.provider,
        model: p.model,
        expected_path: p.expected_path,
        key_field: p.key_field,
    })
    .unwrap();
    maknae_seal::open(recipient, &aad, admitted.sealed_key.as_bytes()).is_ok()
}

#[tokio::test]
async fn an_agents_sealed_key_opens_only_on_the_path_the_kernel_admits_for_that_agent() {
    maknae_crypto::init().unwrap();
    let recipient = maknae_seal::SealPrivateKey::generate().unwrap();
    let hobi = maknae_config::AgentId::parse("hobi").unwrap();
    let suga = maknae_config::AgentId::parse("suga").unwrap();
    let provider = maknae_config::AgentProvider {
        provider: "openai".into(),
        model: "gpt-5.6-luna".into(),
        key_subpath: "openai/main".into(),
        key_field: "api_key".into(),
        context_tokens: 128_000,
        output_tokens: None,
    };
    let key = maknae_loop::keys::AgentKeyContext {
        provider: &provider,
        kv_mount: "maknae-kv",
        agent_prefix: "maknae/agents",
        agent: &hobi,
        seal_key: recipient.public_key(),
    };
    let read = std::sync::Mutex::new(None);
    let choice = maknae_loop::keys::agent_choice(&key, "c-629", |path| {
        *read.lock().unwrap() = Some(path.clone());
        async move {
            Ok(maknae_vault::WrappedSecret {
                token: maknae_vault::WrappingToken::new(Zeroizing::new(
                    "hvs.wrap-sentinel-629".into(),
                ))
                .unwrap(),
                ttl: Duration::from_secs(60),
                creation_path: path,
                creation_time: "2026-11-13T00:00:00Z".into(),
            })
        }
    })
    .await
    .unwrap();
    let set = openai();
    let admit = |owner| {
        maknae_kernel::admit_choice(
            &set,
            Some(&choice),
            owner,
            "maknae/users",
            Some("maknae/agents"),
        )
        .unwrap()
    };
    let own = admit(maknae_kernel::KeyOwner::Agent(&hobi));
    assert_eq!(
        read.lock().unwrap().as_deref(),
        Some(own.key_vault_path.as_str())
    );
    assert!(egress_opens(&recipient, &own, "c-629"));
    assert!(!egress_opens(
        &recipient,
        &admit(maknae_kernel::KeyOwner::Agent(&suga)),
        "c-629"
    ));
    assert!(!egress_opens(
        &recipient,
        &admit(maknae_kernel::KeyOwner::User(Some("hobi"))),
        "c-629"
    ));
}

const ROLES_TASK: &str = "roles:\n  user:\n    allow: [\"session.task\"]\n";

/// An agent policy granting `session.task`, tasked by the agents named.
fn tasks_and_tasked_by(taskers: &[&str]) -> String {
    let listed: Vec<String> = taskers.iter().map(|a| format!("\"agent:{a}\"")).collect();
    format!(
        "schema_version: 1\nactions:\n  allow: [\"session.task\"]\ntaskers: [{}]\n",
        listed.join(", ")
    )
}

/// hobi works for the person and tasks jin; jin tasks suga; suga takes jin's tasks.
fn chain_world(tag: &str) -> World {
    let (jin, suga) = (
        tasks_and_tasked_by(&["hobi"]),
        tasks_and_tasked_by(&["jin"]),
    );
    world_of(
        tag,
        "user",
        ROLES_TASK,
        &[
            ("hobi", HOBI_UID, GRANTED),
            ("suga", SUGA_UID, &suga),
            ("jin", JIN_UID, &jin),
        ],
    )
}

fn everyone() -> FixedEnrollment {
    only(&[("hobi", HOBI_UID), ("suga", SUGA_UID), ("jin", JIN_UID)])
}

fn hobis() -> Tasker {
    Tasker::Agent {
        agent: "hobi".into(),
        uid: HOBI_UID,
    }
}

impl World {
    /// `by`'s submission to `target`, citing `under`.
    async fn give(&self, by: &str, target: &str, under: TaskId) -> TaskId {
        let records = Records::new(0);
        match self
            .agent_with(by, submit(target, "sub"), Some(under), &records)
            .await
        {
            Some(RespResult::Ok(Payload::TaskAccepted(v))) => v.task.to_id(),
            other => panic!("{by} -> {target}: {other:?} {:?}", reasons(&records)),
        }
    }

    /// hobi working the person's T1, and jin's S1 given under it.
    async fn chain(&self) -> (TaskId, TaskId) {
        let t1 = self.mine("hobi");
        self.working(&t1);
        let s1 = self.give("hobi", "jin", t1).await;
        (t1, s1)
    }

    async fn stop_as_person(&self, id: &TaskId) {
        let stopped = self.ask(Verb::TaskStop { task: r(id) }).await;
        assert!(
            matches!(stopped, RespResult::Ok(Payload::TaskAcknowledged(_))),
            "{stopped:?}"
        );
    }
}

fn parent_ended(said: &[Due], sub: TaskId, parent: TaskId) -> bool {
    said.iter().any(|d| {
        d.task == sub
            && d.parent == Some(parent)
            && d.why == DueFor::Close(TaskClose::ParentEnded)
            && d.tasker == hobis()
    })
}

#[tokio::test]
async fn a_sub_task_is_closed_parent_ended_however_its_parent_stops_working() {
    for ending in [
        "stopped",
        "reported",
        "restarted",
        "lapsed",
        "deenrolled",
        "released",
    ] {
        let mut w = chain_world(&format!("orphan-{ending}"));
        let (t1, s1) = w.chain().await;
        assert_eq!(w.claimed("jin").await, s1, "{ending}");
        let mut said = Vec::new();
        match ending {
            "stopped" => w.stop_as_person(&t1).await,
            "reported" => {
                w.agent_reports("hobi", &t1, "done").await;
            }
            "restarted" => {
                w = w.restarted();
                assert!(matches!(
                    w.agent_reports("hobi", &t1, "RESTARTED").await,
                    RespResult::Ok(Payload::TaskAcknowledged(_))
                ));
            }
            "lapsed" => {
                let lease = CLAIM_LEASE.as_secs() as i64;
                w.clock.set(T0 + lease / 2);
                follow_ups(w.beat("jin", 0).await);
                w.clock.set(T0 + lease + 1);
            }
            "deenrolled" => {
                said = w
                    .store()
                    .retain_enrolled(&only(&[("suga", SUGA_UID), ("jin", JIN_UID)]));
            }
            "released" => {
                w.store().mark_unenrolled(&maknae_kernel::Containing(
                    everyone(),
                    [HOBI_UID].into_iter().collect(),
                ));
                w.store().sweep();
                assert_eq!(w.store().record(&s1).unwrap().state, TaskState::Held);
                w.store().release(&t1, &everyone()).unwrap();
                assert_eq!(w.store().record(&t1).unwrap().state, TaskState::Queued);
                assert!(
                    w.store().sweep().is_empty(),
                    "a held sub-task stays held under an ended parent"
                );
                w.store().release(&s1, &everyone()).unwrap();
                assert_eq!(
                    w.claim("jin").await.map(|(t, _)| t.task.task_id),
                    None,
                    "a released sub-task under an ended parent is never handed out"
                );
            }
            _ => unreachable!(),
        }
        said.extend(w.store().sweep());
        assert!(parent_ended(&said, s1, t1), "{ending}: {said:?}");
        assert_eq!(
            said.iter().filter(|d| d.task == s1).count(),
            1,
            "{ending}: one close, never a collectable record first: {said:?}"
        );
        assert!(w.store().record(&s1).is_none(), "{ending}");
        assert!(
            w.store().holdings(&hobis()).is_empty(),
            "{ending}: hobi holds no record"
        );
        assert!(w.store().sweep().is_empty(), "{ending}: closed once");
    }
}

#[tokio::test]
async fn a_shutdown_stop_then_a_restarted_parent_leaves_hobi_no_record() {
    let w = chain_world("orphan-shutdown");
    let (t1, s1) = w.chain().await;
    assert_eq!(w.claimed("jin").await, s1);
    let stopped = w
        .agent("hobi", Verb::TaskStop { task: r(&s1) }, Some(t1))
        .await;
    assert!(
        matches!(&stopped, RespResult::Ok(Payload::TaskAcknowledged(v)) if v.close == Some(TaskClose::Stopped)),
        "{stopped:?}"
    );
    let w = w.restarted();
    w.agent_reports("hobi", &t1, "RESTARTED").await;
    let said = w.store().sweep();
    assert!(
        said.iter()
            .any(|d| d.task == s1 && d.parent == Some(t1) && d.why == DueFor::Orphaned),
        "{said:?}"
    );
    assert!(w.store().holdings(&hobis()).is_empty());
    assert!(
        w.restarted().store().record(&s1).is_none(),
        "gone from disk"
    );
}

#[tokio::test]
async fn a_working_orphan_is_refused_its_next_cited_request_before_any_sweep() {
    let w = chain_world("orphan-cite");
    let (t1, s1) = w.chain().await;
    assert_eq!(w.claimed("jin").await, s1);
    w.stop_as_person(&t1).await;
    let read = Verb::Read {
        path: "/etc/hostname".into(),
        conversation: None,
        page: None,
    };
    assert!(w.cannot_cite("jin", read, s1).await);
    assert!(
        !matches!(
            w.beat("jin", 0).await,
            RespResult::Ok(Payload::TaskFollowUps(_))
        ),
        "its heartbeat no longer runs it"
    );
}

#[tokio::test]
async fn a_close_left_by_a_crash_before_the_sweep_is_made_on_the_first_sweep() {
    let w = chain_world("orphan-crash");
    let (t1, s1) = w.chain().await;
    assert_eq!(w.claimed("jin").await, s1);
    w.stop_as_person(&t1).await;
    let w = w.restarted();
    assert!(parent_ended(&w.store().sweep(), s1, t1));
    assert!(w.store().record(&s1).is_none());
}

#[tokio::test]
async fn a_grandchild_closes_after_its_parent() {
    let w = chain_world("orphan-grandchild");
    let (t1, s1) = w.chain().await;
    assert_eq!(w.claimed("jin").await, s1);
    let g1 = w.give("jin", "suga", s1).await;
    w.stop_as_person(&t1).await;
    let said = w.store().sweep();
    assert!(parent_ended(&said, s1, t1), "{said:?}");
    assert!(
        said.iter().any(|d| d.task == g1
            && d.parent == Some(s1)
            && d.why == DueFor::Close(TaskClose::ParentEnded)),
        "{said:?}"
    );
    assert!(w.store().record(&g1).is_none());
}

#[tokio::test]
async fn a_queued_orphan_is_never_delivered() {
    let w = chain_world("orphan-queued");
    let (t1, s1) = w.chain().await;
    w.stop_as_person(&t1).await;
    assert_eq!(w.claim("jin").await.map(|(t, _)| t.task.task_id), None);
    assert!(parent_ended(&w.store().sweep(), s1, t1));
}

#[tokio::test]
async fn an_agent_taskers_verbs_reach_only_the_sub_tasks_of_the_task_it_cites() {
    let w = chain_world("scoped");
    let (t1, s1) = w.chain().await;
    let t9 = w.anothers("hobi");
    w.working(&t9);
    assert_eq!(w.claimed("jin").await, s1);
    w.agent_reports("jin", &s1, "sentinel-609-scoped").await;
    let rseq = w.store().record(&s1).unwrap().rseq.unwrap();
    for under in [Some(t9), None] {
        for verb in [
            Verb::TaskStatus { task: r(&s1) },
            Verb::TaskStop { task: r(&s1) },
            Verb::TaskDrop { task: r(&s1) },
            Verb::TaskAdd {
                task: r(&s1),
                text: secret("more"),
            },
        ] {
            let got = w.agent("hobi", verb.clone(), under).await;
            assert!(unauthorized(&got), "{under:?} {verb:?}: {got:?}");
        }
        assert!(ids(&page(w.agent("hobi", list("jin", None), under).await)).is_empty());
        let acked = reports(w.agent("hobi", collect("jin", Some(rseq)), under).await);
        assert!(acked.entries.is_empty(), "{under:?}");
    }
    let got = reports(w.agent("hobi", collect("jin", None), Some(t1)).await);
    assert_eq!(report_ids(&got), vec![s1], "the report survives");
    assert_eq!(&**got.entries[0].text.0, "sentinel-609-scoped");
    assert_eq!(
        ids(&page(w.agent("hobi", list("jin", None), Some(t1)).await)),
        vec![s1]
    );
    assert!(matches!(
        w.agent("hobi", Verb::TaskStatus { task: r(&s1) }, Some(t1))
            .await,
        RespResult::Ok(Payload::TaskState(_))
    ));
    assert_eq!(
        ids(&page(w.ask(list("hobi", None)).await)),
        vec![t1],
        "the person's own view is unchanged"
    );
}

fn collect_one(agent: &str, after: Option<u64>, task: TaskId) -> Verb {
    Verb::TaskCollect {
        agent: agent.into(),
        after: after.map(TaskCursor::from_seq),
        task: Some(r(&task)),
    }
}

#[tokio::test]
async fn a_collect_naming_a_task_returns_and_acknowledges_only_that_task() {
    let w = chain_world("collect-one");
    let (t1, a) = w.chain().await;
    let b = w.give("hobi", "jin", t1).await;
    assert_eq!(w.claimed("jin").await, a);
    w.agent_reports("jin", &a, "sentinel-609-a").await;
    assert_eq!(w.claimed("jin").await, b);
    w.agent_reports("jin", &b, "sentinel-609-b").await;
    let only_b = reports(w.agent("hobi", collect_one("jin", None, b), Some(t1)).await);
    assert_eq!(report_ids(&only_b), vec![b]);
    let upto = w.store().record(&b).unwrap().rseq.unwrap();
    let after = reports(
        w.agent("hobi", collect_one("jin", Some(upto), b), Some(t1))
            .await,
    );
    assert!(after.entries.is_empty());
    assert!(w.store().record(&b).is_none(), "b acknowledged");
    assert!(
        w.store().record(&a).is_some(),
        "a, below the cursor, is not acknowledged"
    );
    let rest = reports(w.agent("hobi", collect("jin", None), Some(t1)).await);
    assert_eq!(report_ids(&rest), vec![a]);
}

const WAITS_ON_HOBI: &str = "deny task chain already waits on agent hobi";

/// hobi and jin each grant `session.task` and take each other's tasks, and hobi its own.
fn crossed_world(tag: &str) -> World {
    let (hobi, jin, suga) = (
        tasks_and_tasked_by(&["hobi", "jin"]),
        tasks_and_tasked_by(&["hobi"]),
        tasks_and_tasked_by(&["jin"]),
    );
    world_of(
        tag,
        "user",
        ROLES_TASK,
        &[
            ("hobi", HOBI_UID, &hobi),
            ("suga", SUGA_UID, &suga),
            ("jin", JIN_UID, &jin),
        ],
    )
}

impl World {
    /// `by`'s submission to `target` under `under`, refused, and the trail's reasons.
    async fn refused_as(&self, by: &str, target: &str, under: TaskId) -> Vec<String> {
        self.refused_citing(by, target, Some(under)).await
    }

    async fn refused_citing(&self, by: &str, target: &str, under: Option<TaskId>) -> Vec<String> {
        let records = Records::new(0);
        let got = self
            .agent_with(by, submit(target, "sub"), under, &records)
            .await
            .unwrap();
        assert!(unauthorized(&got), "{by} -> {target}: {got:?}");
        reasons(&records)
    }
}

#[tokio::test]
async fn an_agent_cannot_task_itself() {
    let w = crossed_world("waits-self");
    let said = w.refused_citing("hobi", "hobi", None).await;
    assert!(said.iter().any(|r| r == WAITS_ON_HOBI), "{said:?}");
    let t1 = w.mine("hobi");
    w.working(&t1);
    let said = w.refused_as("hobi", "hobi", t1).await;
    assert!(said.iter().any(|r| r == WAITS_ON_HOBI), "{said:?}");
}

#[tokio::test]
async fn a_sub_task_cannot_task_an_agent_up_its_chain() {
    let w = crossed_world("waits-chain");
    let (_, s1) = w.chain().await;
    assert_eq!(w.claimed("jin").await, s1);
    let said = w.refused_as("jin", "hobi", s1).await;
    assert!(said.iter().any(|r| r == WAITS_ON_HOBI), "{said:?}");
    assert!(w.store().queue(&hobi()).is_empty());
}

#[tokio::test]
async fn two_chains_cannot_wait_on_each_other() {
    let w = crossed_world("waits-crossed");
    let t1 = w.mine("hobi");
    w.working(&t1);
    let t3 = w.mine("jin");
    w.working(&t3);
    let sa = w.give("hobi", "jin", t1).await;
    assert_eq!(w.store().record(&sa).unwrap().state, TaskState::Queued);
    let said = w.refused_as("jin", "hobi", t3).await;
    assert!(said.iter().any(|r| r == WAITS_ON_HOBI), "{said:?}");
}

#[tokio::test]
async fn a_chain_that_waits_on_no_one_behind_it_is_taken() {
    let w = crossed_world("waits-none");
    let (_t1, s1) = w.chain().await;
    assert_eq!(w.claimed("jin").await, s1);
    let g1 = w.give("jin", "suga", s1).await;
    assert_eq!(w.store().record(&g1).unwrap().parent, Some(s1));
}

/// hobi, jin and suga each take tasks from the other two.
fn triangle_world(tag: &str) -> World {
    let (hobi, jin, suga) = (
        tasks_and_tasked_by(&["jin", "suga"]),
        tasks_and_tasked_by(&["hobi", "suga"]),
        tasks_and_tasked_by(&["hobi", "jin"]),
    );
    world_of(
        tag,
        "user",
        ROLES_TASK,
        &[
            ("hobi", HOBI_UID, &hobi),
            ("suga", SUGA_UID, &suga),
            ("jin", JIN_UID, &jin),
        ],
    )
}

#[tokio::test]
async fn a_wait_through_a_third_agents_queue_is_refused() {
    let w = triangle_world("waits-triangle");
    let working = |agent: &str| {
        let t = w.mine(agent);
        w.working(&t);
        t
    };
    let (ta, tb, tc) = (working("hobi"), working("jin"), working("suga"));
    let to_c = w.give("hobi", "suga", ta).await;
    let to_b = w.give("suga", "jin", tc).await;
    for queued in [to_c, to_b] {
        assert_eq!(w.store().record(&queued).unwrap().state, TaskState::Queued);
    }
    let said = w.refused_as("jin", "hobi", tb).await;
    assert!(said.iter().any(|r| r == WAITS_ON_HOBI), "{said:?}");
}

#[tokio::test]
async fn a_wait_closed_by_a_queued_sub_task_under_an_unrelated_task_is_refused() {
    let w = triangle_world("waits-unrelated-queue");
    let (_, s1) = w.chain().await;
    assert_eq!(w.claimed("jin").await, s1);
    let ts = w.mine("suga");
    w.working(&ts);
    let h = w.give("suga", "hobi", ts).await;
    assert_eq!(w.store().record(&h).unwrap().state, TaskState::Queued);
    let said = w.refused_as("jin", "suga", s1).await;
    assert!(
        said.iter()
            .any(|r| r == "deny task chain already waits on agent suga"),
        "{said:?}"
    );
}

#[tokio::test]
async fn a_parent_released_and_started_again_never_revives_its_old_sub_task() {
    let w = chain_world("orphan-restarted-parent");
    let (t1, s1) = w.chain().await;
    assert_eq!(w.claimed("jin").await, s1);
    w.store().mark_unenrolled(&maknae_kernel::Containing(
        everyone(),
        [HOBI_UID].into_iter().collect(),
    ));
    w.store().sweep();
    assert_eq!(w.store().record(&s1).unwrap().state, TaskState::Held);
    w.store().release(&t1, &everyone()).unwrap();
    assert_eq!(w.claimed("hobi").await, t1, "the parent starts afresh");
    w.store().release(&s1, &everyone()).unwrap();
    assert_eq!(
        w.claim("jin").await.map(|(t, _)| t.task.task_id),
        None,
        "the old sub-task is not delivered again"
    );
    assert!(parent_ended(&w.store().sweep(), s1, t1));
    assert!(w.store().record(&s1).is_none());
    let reopened = w.restarted();
    assert!(reopened.store().record(&s1).is_none());
}

#[tokio::test]
async fn an_acknowledgement_under_one_root_answers_alike_whatever_another_root_has_reported() {
    let w = chain_world("ack-scope");
    let (t1, s1) = w.chain().await;
    let t9 = w.anothers("hobi");
    w.working(&t9);
    assert_eq!(w.claimed("jin").await, s1);
    w.agent_reports("jin", &s1, "sentinel-609-other-root").await;
    let high = w.store().record(&s1).unwrap().rseq.unwrap();
    let mut answers = Vec::new();
    for upto in [high - 1, high, high + 1] {
        let records = Records::new(0);
        let got = w
            .agent_with("hobi", collect("jin", Some(upto)), Some(t9), &records)
            .await
            .unwrap();
        let reasons: Vec<String> = reasons(&records)
            .into_iter()
            .map(|r| r.replace(&format!("through {upto}"), "through N"))
            .collect();
        answers.push((format!("{got:?}"), reasons));
    }
    assert!(answers.windows(2).all(|a| a[0] == a[1]), "{answers:#?}");
    assert!(
        w.store().record(&s1).is_some(),
        "the other root's report is untouched"
    );
    let page = reports(w.agent("hobi", collect("jin", None), Some(t1)).await);
    assert_eq!(report_ids(&page), vec![s1]);
}

#[tokio::test]
async fn a_parent_started_again_reaches_none_of_its_old_runs_sub_tasks_before_any_sweep() {
    let w = triangle_world("old-run");
    let t1 = w.mine("hobi");
    w.working(&t1);
    let s1 = w.give("hobi", "jin", t1).await;
    let s2 = w.give("hobi", "suga", t1).await;
    assert_eq!(w.claimed("jin").await, s1);
    w.agent_reports("jin", &s1, "sentinel-609-old-run").await;
    w.store().mark_unenrolled(&maknae_kernel::Containing(
        everyone(),
        [HOBI_UID].into_iter().collect(),
    ));
    w.store().sweep();
    w.store().release(&t1, &everyone()).unwrap();
    w.working(&t1);
    for old in [s1, s2] {
        w.store().release(&old, &everyone()).unwrap();
    }
    let status = w
        .agent("hobi", Verb::TaskStatus { task: r(&s1) }, Some(t1))
        .await;
    assert!(unauthorized(&status), "{status:?}");
    assert!(
        reports(w.agent("hobi", collect("jin", None), Some(t1)).await)
            .entries
            .is_empty()
    );
    let rseq = w.store().record(&s1).unwrap().rseq.unwrap();
    w.agent("hobi", collect("jin", Some(rseq)), Some(t1)).await;
    assert!(
        w.store().record(&s1).is_some(),
        "not acknowledged by the new run"
    );
    let ts = w.mine("suga");
    w.working(&ts);
    w.give("suga", "hobi", ts).await;
}

#[tokio::test]
async fn a_fan_out_whose_branches_meet_at_one_agent_is_taken() {
    let w = triangle_world("waits-fan-out");
    let (t1, s1) = w.chain().await;
    let s2 = w.give("hobi", "suga", t1).await;
    assert_eq!(w.claimed("jin").await, s1);
    assert_eq!(w.store().record(&s2).unwrap().state, TaskState::Queued);
    let g = w.give("jin", "suga", s1).await;
    assert_eq!(w.store().record(&g).unwrap().parent, Some(s1));
}

#[tokio::test]
async fn a_queued_task_waits_on_nothing_even_while_due_a_hold() {
    let w = triangle_world("waits-queued-parent");
    let (t1, s1) = w.chain().await;
    let hold_hobi = || {
        w.store().mark_unenrolled(&maknae_kernel::Containing(
            everyone(),
            [HOBI_UID].into_iter().collect(),
        ))
    };
    hold_hobi();
    w.store().sweep();
    for id in [t1, s1] {
        w.store().release(&id, &everyone()).unwrap();
        assert_eq!(w.store().record(&id).unwrap().state, TaskState::Queued);
    }
    hold_hobi();
    let tj = w.mine("jin");
    w.working(&tj);
    w.give("jin", "hobi", tj).await;
}

const HOMELAB_TOOLS: &str = include_str!("../../../packaging/common/tools-homelab.yaml");
const RUST_BUILD: &str =
    "schema_version: 1\npermissions:\n  allow: [\"Tool(rust-build cargo build *)\"]\n";

impl World {
    async fn agent_response(&self, agent: &str, verb: Verb) -> Response {
        self.agent_response_with(agent, verb, &Records::new(0))
            .await
    }

    async fn agent_response_with(
        &self,
        agent: &str,
        verb: Verb,
        records: &Arc<Records>,
    ) -> Response {
        let raw = self.agent_raw(agent, verb, None, records).await;
        let mut cursor = &raw[..];
        let frame = common::read_frame(&mut cursor, 1 << 20)
            .await
            .expect("one frame");
        maknae_proto::decode_response(&frame).unwrap()
    }

    fn catalog_digest(&self, uid: u32) -> maknae_proto::CatalogDigest {
        self.pdp
            .catalog_for(uid, self.me + 1, &maknae_config::ForgeSet::empty())
            .unwrap()
            .digest
    }

    fn tools(&self, body: &str) {
        common::write_0640(&self.root.join(maknae_config::TOOLS_FILE), body);
        self.pdp.baseline().reload_from_file().unwrap();
    }
}

#[tokio::test]
async fn every_task_claim_reply_kind_is_stamped() {
    let w = world_with("stamp-kinds", "user", true, RUST_BUILD, PLAIN);
    w.tools(HOMELAB_TOOLS);
    let want = Some(w.catalog_digest(HOBI_UID));
    let stamped = |resp: Response, kind: &str| {
        assert_eq!(resp.catalog_digest, want, "{kind}: {resp:?}");
        resp.result
    };
    let idle = stamped(w.agent_response("hobi", CLAIM).await, "claim idle");
    assert!(
        matches!(idle, RespResult::Ok(Payload::TaskIdle)),
        "{idle:?}"
    );
    let beat = || Verb::TaskClaim {
        seen_follow_ups: Some(0),
    };
    let idle = stamped(w.agent_response("hobi", beat()).await, "heartbeat idle");
    assert!(
        matches!(idle, RespResult::Ok(Payload::TaskIdle)),
        "{idle:?}"
    );

    let id = w.submit("hobi", "a").await;
    w.submit("hobi", "b").await;
    let delivered = stamped(w.agent_response("hobi", CLAIM).await, "delivered");
    assert!(
        matches!(delivered, RespResult::Ok(Payload::TaskDelivered(_))),
        "{delivered:?}"
    );
    let follow_ups = stamped(w.agent_response("hobi", beat()).await, "follow-ups");
    assert!(
        matches!(follow_ups, RespResult::Ok(Payload::TaskFollowUps(_))),
        "{follow_ups:?}"
    );
    w.ask(Verb::TaskStop { task: r(&id) }).await;
    let closed = stamped(w.agent_response("hobi", beat()).await, "closed");
    assert!(
        matches!(closed, RespResult::Ok(Payload::TaskState(_))),
        "{closed:?}"
    );
}

#[tokio::test]
async fn a_tools_reload_changes_the_next_stamp() {
    let w = world_with("stamp-reload", "user", true, RUST_BUILD, PLAIN);
    w.tools(HOMELAB_TOOLS);
    let before = w.agent_response("hobi", CLAIM).await.catalog_digest;
    assert_eq!(before, Some(w.catalog_digest(HOBI_UID)));
    w.tools(&HOMELAB_TOOLS.replace(
        "Build, check, lint and test a workspace with no network.",
        "sentinel-674 reloaded",
    ));
    let after = w.agent_response("hobi", CLAIM).await.catalog_digest;
    assert_eq!(after, Some(w.catalog_digest(HOBI_UID)));
    assert_ne!(after, before);
}

#[tokio::test]
async fn an_idle_claim_whose_tasker_standing_is_undecided_is_stamped() {
    let w = world("stamp-undecided", "user", true);
    let queued = w.anothers("hobi");
    common::write_0640(
        &maknae_authz_basic::PolicyPaths::in_dir(&w.root).bindings,
        &format!(
            "schema_version: 1\nbindings:\n  user: [\"{}\", \"sentinel-674-no-such-user\"]\n",
            w.user
        ),
    );
    w.pdp.baseline().reload_from_file().unwrap();
    let records = Records::new(0);
    let resp = w.agent_response_with("hobi", CLAIM, &records).await;
    assert!(
        matches!(resp.result, RespResult::Ok(Payload::TaskIdle)),
        "{resp:?}"
    );
    let rec = task_records(&records).pop().unwrap();
    assert!(
        rec.outcome
            .reason
            .starts_with("idle: the tasker's standing could not be decided: "),
        "{}",
        rec.outcome.reason
    );
    assert_eq!(rec.subject.task_id, Some(queued.to_string()));
    assert_eq!(resp.catalog_digest, Some(w.catalog_digest(HOBI_UID)));
}

/// `inner`, whose load reads as another after its first `stable` readings.
struct LoadChangesAfter {
    inner: Arc<dyn maknae_kernel::EnrollmentView>,
    stable: usize,
    reads: std::sync::atomic::AtomicUsize,
    first: Arc<dyn std::any::Any + Send + Sync>,
}

impl maknae_kernel::EnrollmentView for LoadChangesAfter {
    fn agent_uid(&self, id: &maknae_config::AgentId) -> Option<u32> {
        self.inner.agent_uid(id)
    }
    fn agents(&self) -> Vec<(maknae_config::AgentId, u32)> {
        self.inner.agents()
    }
    fn is_enrolled(&self, uid: u32) -> bool {
        self.inner.is_enrolled(uid)
    }
    fn contained(&self, uid: u32) -> bool {
        self.inner.contained(uid)
    }
    fn unresolved(&self, uid: u32) -> bool {
        self.inner.unresolved(uid)
    }
    fn load(&self) -> maknae_kernel::Load {
        let n = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n < self.stable {
            maknae_kernel::Load::installed(Arc::clone(&self.first))
        } else {
            maknae_kernel::Load::installed(Arc::new(n))
        }
    }
}

#[tokio::test]
async fn a_claim_that_loses_the_race_to_a_reload_is_idle_and_stamped() {
    let mut w = world("stamp-lost-race", "user", true);
    let queued = w.submit("hobi", "a").await;
    w.agents.view = Arc::new(LoadChangesAfter {
        inner: Arc::clone(&w.agents.view),
        stable: 2,
        reads: Default::default(),
        first: Arc::new(()),
    });
    let records = Records::new(0);
    let resp = w.agent_response_with("hobi", CLAIM, &records).await;
    assert!(
        matches!(resp.result, RespResult::Ok(Payload::TaskIdle)),
        "{resp:?}"
    );
    let said = task_records(&records);
    assert_eq!(
        said.iter()
            .map(|r| r.outcome.reason.as_str())
            .collect::<Vec<_>>(),
        ["intent recorded", "idle"]
    );
    assert_eq!(w.store().record(&queued).unwrap().state, TaskState::Queued);
    assert_eq!(resp.catalog_digest, Some(w.catalog_digest(HOBI_UID)));
}

mod board {
    use super::*;
    use maknae_audit_append::AuditRecord;
    use maknae_kernel::{
        BoardKey, BoardSeam, BoardStore, Caps, Fail, FixedSwitches, LabelValue, PostLabels,
        Settings,
    };
    use maknae_proto::{
        Addressee, Author, BoardDefect, BoardPage, Labels, PostDraft, PostId, PostKind,
    };

    const BOARD_ROLES: &str =
        "roles:\n  user:\n    allow: [\"session.task\", \"board.post\", \"board.read\"]\n";
    const LABEL: &str = "post.sentinel-695.level";

    type Pdp = maknae_kernel::Composition<maknae_authz_basic::HermeticAuthorizer>;

    fn board_world(tag: &str) -> World {
        let mut w = world_of(
            tag,
            "user",
            BOARD_ROLES,
            &[
                ("hobi", HOBI_UID, PLAIN),
                ("suga", SUGA_UID, PLAIN),
                ("jin", JIN_UID, PLAIN),
            ],
        );
        w.switch(true, &["hobi", "suga", "jin"]);
        w.enable(w.me, true);
        w.enable(OTHER, true);
        w
    }

    impl World {
        fn switch(&mut self, site: bool, agents: &[&str]) {
            self.agents.switches = Arc::new(FixedSwitches {
                site,
                agents: agents
                    .iter()
                    .map(|a| maknae_config::AgentId::parse(a).unwrap())
                    .collect(),
            });
        }

        fn enable(&self, uid: u32, on: bool) {
            self.agents
                .board
                .set_settings(
                    BoardKey(uid),
                    Settings {
                        enabled: on,
                        ..Settings::default()
                    },
                )
                .unwrap();
        }

        fn key(&self) -> BoardKey {
            BoardKey(self.me)
        }

        fn at_work(&self, agent: &str) -> TaskId {
            let id = self.mine(agent);
            self.working(&id);
            id
        }

        async fn board(
            &self,
            agent: &str,
            verb: Verb,
            task: TaskId,
        ) -> (RespResult, Vec<AuditRecord>) {
            let pdp = Arc::clone(&self.pdp);
            self.board_as(&pdp, agent, verb, task).await
        }

        async fn board_as<P>(
            &self,
            authorizer: &Arc<P>,
            agent: &str,
            verb: Verb,
            task: TaskId,
        ) -> (RespResult, Vec<AuditRecord>)
        where
            P: maknae_security::Authorizer
                + maknae_kernel::SensitiveNow
                + maknae_kernel::CatalogNow
                + Send
                + Sync
                + 'static,
        {
            let records = Records::new(0);
            let answer = self
                .agent_as(authorizer, agent, verb, Some(task), &records)
                .await
                .unwrap_or_else(|| panic!("no answer: {:?}", records.snapshot()));
            let records = records
                .snapshot()
                .into_iter()
                .filter(|r| r.action.starts_with("board."))
                .collect();
            (answer, records)
        }

        /// A post written through the store, as the kernel writes one from `author`.
        fn stored(&self, author: &str, body: &str, labels: PostLabels) -> PostId {
            self.agents
                .board
                .post(
                    self.key(),
                    (Author::Agent(author.into()), Some(uid_of(author))),
                    None,
                    labels,
                    note(body),
                    &*self.agents.view,
                )
                .unwrap()
                .post
                .id
        }

        fn seq(&self, id: PostId) -> u64 {
            self.agents.board.get(self.key(), id).unwrap().seq
        }

        fn cursor(&self, agent: &str) -> u64 {
            let agent = maknae_config::AgentId::parse(agent).unwrap();
            self.agents.board.plan_read(self.key(), &agent, None).cursor
        }
    }

    fn note(body: &str) -> PostDraft {
        PostDraft {
            kind: PostKind::Note,
            to: Addressee::Board,
            in_reply_to: None,
            body: secret(body),
            attachments: vec![],
        }
    }

    fn reply(body: &str, to: PostId) -> PostDraft {
        PostDraft {
            kind: PostKind::Answer,
            in_reply_to: Some(to),
            ..note(body)
        }
    }

    fn post(draft: PostDraft) -> Verb {
        Verb::BoardPost { post: draft }
    }

    fn read(seen_through: Option<PostId>) -> Verb {
        Verb::BoardRead { seen_through }
    }

    fn labelled() -> PostLabels {
        PostLabels(
            [(
                "sentinel-695.level".to_string(),
                LabelValue::Str("x".into()),
            )]
            .into(),
        )
    }

    fn posted(r: RespResult) -> PostId {
        match r {
            RespResult::Ok(Payload::BoardPosted(id)) => id,
            other => panic!("not posted: {other:?}"),
        }
    }

    fn page_of(r: RespResult) -> BoardPage {
        match r {
            RespResult::Ok(Payload::BoardPage(p)) => p,
            other => panic!("not a page: {other:?}"),
        }
    }

    fn bodies(page: &BoardPage) -> Vec<String> {
        page.posts
            .iter()
            .map(|p| p.draft.body.0.to_string())
            .collect()
    }

    fn refused(r: &RespResult) -> Option<BoardDefect> {
        match r {
            RespResult::Err(e) => match e.code {
                ProtoErrCode::BoardRefused(d) => Some(d),
                _ => None,
            },
            RespResult::Ok(_) => None,
        }
    }

    fn said(records: &[AuditRecord]) -> Vec<(String, String, String)> {
        records
            .iter()
            .map(|r| {
                (
                    r.outcome.result.clone(),
                    r.outcome.reason.clone(),
                    r.outcome.posture.clone(),
                )
            })
            .collect()
    }

    fn one(result: &str, reason: &str, posture: &str) -> Vec<(String, String, String)> {
        vec![(result.into(), reason.into(), posture.into())]
    }

    fn read_outcome(records: &[AuditRecord]) -> maknae_audit_append::BoardAudit {
        records
            .iter()
            .find(|r| r.action == "board.read" && r.outcome.reason == "done")
            .and_then(|r| r.board.clone())
            .unwrap_or_else(|| panic!("no read outcome: {records:?}"))
    }

    fn denies(w: &World, readers: &[&str]) -> Arc<common::DeniesLabel<Pdp>> {
        Arc::new(common::DeniesLabel {
            inner: Arc::clone(&w.pdp),
            label: LABEL,
            readers: readers.iter().map(|r| r.to_string()).collect(),
        })
    }

    #[tokio::test]
    async fn two_agents_of_one_person_post_and_read_each_other() {
        let w = board_world("board-two");
        let (h, j) = (w.at_work("hobi"), w.at_work("jin"));
        let question = PostDraft {
            kind: PostKind::Question,
            to: Addressee::Agents(vec!["jin".into()]),
            ..note("sentinel-695-question")
        };
        let q = posted(w.board("hobi", post(question), h).await.0);
        let page = page_of(w.board("jin", read(None), j).await.0);
        assert!(!page.more);
        assert_eq!(page.posts.len(), 1);
        let got = &page.posts[0];
        assert_eq!(got.id, q);
        assert_eq!(got.author, Author::Agent("hobi".into()));
        assert_eq!(got.task, Some(h));
        assert_eq!(got.at_secs, T0);
        assert_eq!(got.labels, Labels {});
        assert_eq!(got.draft.kind, PostKind::Question);
        assert_eq!(got.draft.to, Addressee::Agents(vec!["jin".into()]));
        assert_eq!(got.draft.body.0.as_str(), "sentinel-695-question");
        assert_eq!(
            bodies(&page_of(w.board("hobi", read(None), h).await.0)),
            ["sentinel-695-question"]
        );
        let a = posted(
            w.board("jin", post(reply("sentinel-695-answer", q)), j)
                .await
                .0,
        );
        let page = page_of(w.board("hobi", read(Some(q)), h).await.0);
        assert_eq!(w.cursor("hobi"), w.seq(q));
        assert_eq!(bodies(&page), ["sentinel-695-answer"]);
        let answer = &page.posts[0];
        assert_eq!(answer.id, a);
        assert_eq!(answer.author, Author::Agent("jin".into()));
        assert_eq!(answer.task, Some(j));
        assert_eq!(answer.draft.in_reply_to, Some(q));
    }

    #[tokio::test]
    async fn an_agent_working_for_another_person_sees_only_its_own_board() {
        let w = board_world("board-other");
        let h = w.at_work("hobi");
        let s = w.theirs("suga");
        w.working(&s);
        posted(w.board("hobi", post(note("sentinel-695-mine")), h).await.0);
        let page = page_of(w.board("suga", read(None), s).await.0);
        assert!(page.posts.is_empty(), "{page:?}");
        posted(
            w.board("suga", post(note("sentinel-695-theirs")), s)
                .await
                .0,
        );
        let page = page_of(w.board("hobi", read(None), h).await.0);
        assert_eq!(bodies(&page), ["sentinel-695-mine"]);
        let theirs = page_of(w.board("suga", read(None), s).await.0);
        assert_eq!(bodies(&theirs), ["sentinel-695-theirs"]);
    }

    #[tokio::test]
    async fn each_switch_off_refuses_with_its_reason() {
        let mut w = board_world("board-switches");
        let h = w.at_work("hobi");
        let cases: [(&str, bool, &[&str], bool); 3] = [
            ("board off: site", false, &["hobi"], true),
            ("board off: agent", true, &["jin"], true),
            ("board off: tasker", true, &["hobi"], false),
        ];
        for (reason, site, agents, enabled) in cases {
            w.switch(site, agents);
            w.enable(w.me, enabled);
            for verb in [post(note("sentinel-695-off")), read(None)] {
                let (answer, records) = w.board("hobi", verb, h).await;
                assert!(unauthorized(&answer), "{reason}: {answer:?}");
                assert_eq!(said(&records), one("deny", reason, "unavailable"));
                assert_eq!(
                    records[0].object.as_deref(),
                    Some(&*format!("board:users/{}", w.me))
                );
            }
        }
        w.switch(true, &["hobi"]);
        w.enable(w.me, true);
        posted(w.board("hobi", post(note("sentinel-695-on")), h).await.0);
        assert_eq!(
            bodies(&page_of(w.board("hobi", read(None), h).await.0)),
            ["sentinel-695-on"]
        );
    }

    #[tokio::test]
    async fn an_agent_rooted_chain_has_no_board() {
        let w = board_world("board-rooted");
        let j = w.insert(
            "jin",
            JIN_UID,
            Tasker::Agent {
                agent: "hobi".into(),
                uid: HOBI_UID,
            },
        );
        w.working(&j);
        for verb in [post(note("sentinel-695-rooted")), read(None)] {
            let (answer, records) = w.board("jin", verb, j).await;
            assert!(unauthorized(&answer), "{answer:?}");
            assert_eq!(
                said(&records),
                one("deny", "board off: the chain has no tasker", "unavailable")
            );
        }
    }

    #[tokio::test]
    async fn a_person_on_the_client_channel_is_refused_not_served() {
        let w = board_world("board-client");
        let h = w.at_work("hobi");
        posted(
            w.board("hobi", post(note("sentinel-695-client")), h)
                .await
                .0,
        );
        for verb in [post(note("sentinel-695-client")), read(None)] {
            let records = Records::new(0);
            let answer = w.ask_with(verb, &records).await;
            assert!(unauthorized(&answer), "{answer:?}");
            let records: Vec<_> = records
                .snapshot()
                .into_iter()
                .filter(|r| r.action.starts_with("board."))
                .collect();
            assert_eq!(
                said(&records),
                one(
                    "deny",
                    "board: not served on the client channel",
                    "unavailable"
                )
            );
        }
    }

    #[tokio::test]
    async fn a_malformed_addressee_is_a_bad_request_before_the_gate() {
        let w = world_in("board-pregate", "user", BOARD_ROLES, PLAIN, PLAIN);
        let h = w.at_work("hobi");
        let draft = PostDraft {
            to: Addressee::Agents(vec!["Not An Agent".into()]),
            ..note("sentinel-695-pregate")
        };
        let (answer, records) = w.board("hobi", post(draft), h).await;
        assert!(
            matches!(&answer, RespResult::Err(e) if e.code == ProtoErrCode::BadRequest),
            "{answer:?}"
        );
        assert_eq!(
            said(&records),
            one(
                "deny",
                "board.post fails operand pre-gate: addressee not an agent id",
                "unauthorized"
            )
        );
    }

    #[tokio::test]
    async fn a_post_and_a_read_are_audited_without_the_body() {
        let w = board_world("board-audit");
        let (h, j) = (w.at_work("hobi"), w.at_work("jin"));
        let draft = PostDraft {
            attachments: vec![maknae_proto::Attachment {
                label: "sentinel-695-label".into(),
                media: maknae_proto::Media::TextPlain,
                content: secret("sentinel-695-attachment"),
            }],
            to: Addressee::Agents(vec!["jin".into(), "suga".into()]),
            ..note("sentinel-695-body")
        };
        let (answer, posting) = w.board("hobi", post(draft), h).await;
        let id = posted(answer);
        assert_eq!(
            said(&posting),
            [
                (
                    "permit".into(),
                    "intent recorded".into(),
                    "authorized".into()
                ),
                ("permit".into(), "done".into(), "authorized".into())
            ]
        );
        let object = format!("board:users/{}", w.me);
        for r in &posting {
            assert_eq!(r.object.as_deref(), Some(&*object));
            assert_eq!(r.subject.agent.as_deref(), Some("hobi"));
            assert_eq!(r.subject.task_id, Some(h.to_string()));
            assert_eq!(r.subject.role.as_deref(), Some("user"));
            let b = r.board.as_ref().expect("a board block");
            assert_eq!(b.kind.as_deref(), Some("note"));
            assert_eq!(b.to.as_deref(), Some("agents:jin,suga"));
            assert_eq!(b.attachments, Some(1));
            assert_eq!(b.body_bytes, Some("sentinel-695-body".len() as u32));
            assert_eq!(
                b.attachment_bytes,
                Some("sentinel-695-attachment".len() as u32)
            );
            let digest = b.digest.as_deref().expect("a digest");
            assert_eq!(digest.len(), 64);
            assert!(digest
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
        }
        let outcome = posting[1].board.as_ref().unwrap();
        assert_eq!(outcome.post_id, Some(id.to_string()));
        assert_eq!(outcome.seq, Some(w.seq(id)));
        assert_eq!(posting[0].board.as_ref().unwrap().post_id, None);
        let (answer, reading) = w.board("jin", read(None), j).await;
        assert_eq!(page_of(answer).posts.len(), 1);
        assert_eq!(
            said(&reading),
            [
                (
                    "permit".into(),
                    "intent recorded".into(),
                    "authorized".into()
                ),
                ("permit".into(), "done".into(), "authorized".into())
            ]
        );
        assert_eq!(reading[0].board.as_ref().unwrap().cursor, Some(0));
        let b = read_outcome(&reading);
        let seq = w.seq(id);
        assert_eq!(
            (b.first_seq, b.last_seq, b.returned, b.withheld, b.cursor),
            (Some(seq), Some(seq), Some(1), Some(0), Some(0))
        );
        for r in posting.iter().chain(&reading) {
            let json = maknae_audit_append::canonical_json(r).unwrap();
            assert!(!json.contains("sentinel-695-body"), "{json}");
            assert!(!json.contains("sentinel-695-attachment"), "{json}");
        }
    }

    #[tokio::test]
    async fn an_acknowledged_post_is_not_redelivered_and_an_unacknowledged_one_is() {
        let w = board_world("board-ack");
        let (h, j) = (w.at_work("hobi"), w.at_work("jin"));
        let p1 = posted(w.board("hobi", post(note("p1")), h).await.0);
        let p2 = posted(w.board("hobi", post(note("p2")), h).await.0);
        assert_eq!(
            bodies(&page_of(w.board("jin", read(None), j).await.0)),
            ["p1", "p2"]
        );
        assert_eq!(
            bodies(&page_of(w.board("jin", read(Some(p1)), j).await.0)),
            ["p2"]
        );
        assert_eq!(w.cursor("jin"), w.seq(p1));
        assert_eq!(
            bodies(&page_of(w.board("jin", read(None), j).await.0)),
            ["p2"],
            "an unacknowledged post comes again"
        );
        let w = w.restarted();
        assert_eq!(w.cursor("jin"), w.seq(p1), "the cursor is durable");
        assert_eq!(
            bodies(&page_of(w.board("jin", read(Some(p2)), j).await.0)),
            ["p2"],
            "after a restart nothing was sent, so the acknowledgement moves nothing"
        );
        assert_eq!(
            bodies(&page_of(w.board("jin", read(Some(p2)), j).await.0)),
            Vec::<String>::new()
        );
        assert_eq!(w.cursor("jin"), w.seq(p2));
        let w = w.restarted();
        assert!(page_of(w.board("jin", read(None), j).await.0)
            .posts
            .is_empty());
    }

    #[tokio::test]
    async fn a_labelled_post_is_withheld_from_one_reader_and_returned_to_another() {
        let w = board_world("board-withheld");
        let (j, s) = (w.at_work("jin"), w.at_work("suga"));
        w.stored("hobi", "sentinel-695-labelled", labelled());
        w.stored("hobi", "p2", PostLabels::default());
        w.stored("hobi", "p3", PostLabels::default());
        let pdp = denies(&w, &["jin"]);
        let (answer, records) = w.board_as(&pdp, "jin", read(None), j).await;
        let page = page_of(answer);
        assert_eq!(bodies(&page), ["p2", "p3"]);
        assert!(!page.more);
        let b = read_outcome(&records);
        assert_eq!((b.returned, b.withheld), (Some(2), Some(1)));
        let theirs = page_of(w.board_as(&pdp, "suga", read(None), s).await.0);
        assert_eq!(bodies(&theirs), ["sentinel-695-labelled", "p2", "p3"]);
    }

    #[tokio::test]
    async fn a_reply_to_a_post_withheld_below_the_cursor_arrives_without_its_target() {
        let w = board_world("board-reply-below");
        let (h, j) = (w.at_work("hobi"), w.at_work("jin"));
        let a = w.stored("hobi", "sentinel-695-labelled", labelled());
        let b = w.stored("hobi", "b", PostLabels::default());
        let pdp = denies(&w, &["jin"]);
        assert_eq!(
            bodies(&page_of(w.board_as(&pdp, "jin", read(None), j).await.0)),
            ["b"]
        );
        assert!(page_of(w.board_as(&pdp, "jin", read(Some(b)), j).await.0)
            .posts
            .is_empty());
        assert_eq!(w.cursor("jin"), w.seq(b));
        let r = posted(w.board_as(&pdp, "hobi", post(reply("r", a)), h).await.0);
        let page = page_of(w.board_as(&pdp, "jin", read(None), j).await.0);
        assert_eq!(bodies(&page), ["r"]);
        assert_eq!(page.posts[0].id, r);
        assert_eq!(page.posts[0].draft.in_reply_to, None);
        let theirs = page_of(w.board_as(&pdp, "hobi", read(None), h).await.0);
        let got = theirs.posts.iter().find(|p| p.id == r).unwrap();
        assert_eq!(got.draft.in_reply_to, Some(a), "visible to its author");
    }

    #[tokio::test]
    async fn a_reply_naming_a_withheld_post_is_refused_as_a_reply_to_no_post() {
        let w = board_world("board-reply-withheld");
        let j = w.at_work("jin");
        let a = w.stored("hobi", "sentinel-695-labelled", labelled());
        let pdp = denies(&w, &["jin"]);
        let (withheld, withheld_said) = w.board_as(&pdp, "jin", post(reply("x", a)), j).await;
        let (missing, missing_said) = w
            .board_as(&pdp, "jin", post(reply("x", PostId([0x69; 16]))), j)
            .await;
        assert_eq!(refused(&withheld), Some(BoardDefect::NoSuchPost));
        assert_eq!(withheld, missing);
        assert_eq!(said(&withheld_said), said(&missing_said));
        assert_eq!(
            said(&withheld_said),
            one(
                "deny",
                "in_reply_to names no post on the board",
                "unauthorized"
            )
        );
        assert_eq!(w.agents.board.candidates(w.key(), 0, 10).len(), 1);
    }

    #[tokio::test]
    async fn a_reader_behind_only_withheld_posts_gets_an_empty_page_and_its_cursor_stays() {
        let w = board_world("board-behind");
        let j = w.at_work("jin");
        let posted: Vec<PostId> = (0..40)
            .map(|n| w.stored("hobi", &format!("sentinel-695-l{n}"), labelled()))
            .collect();
        let last = posted[39];
        let pdp = denies(&w, &["jin"]);
        let (answer, records) = w.board_as(&pdp, "jin", read(None), j).await;
        let page = page_of(answer);
        assert!(page.posts.is_empty());
        assert!(!page.more);
        assert_eq!(
            w.cursor("jin"),
            0,
            "only an acknowledgement moves the cursor"
        );
        assert!(!w.board_blobs.has(&format!("cursor.{}.jin", w.me)));
        assert!(w.seq(last) > 0);
        let b = read_outcome(&records);
        assert_eq!(
            (b.returned, b.withheld, b.cursor),
            (Some(0), Some(40), Some(0))
        );
        w.stored("hobi", "p", PostLabels::default());
        let (answer, records) = w.board_as(&pdp, "jin", read(None), j).await;
        assert_eq!(bodies(&page_of(answer)), ["p"]);
        assert_eq!(
            read_outcome(&records).withheld,
            Some(40),
            "the next read decides them again"
        );
    }

    #[tokio::test]
    async fn a_permit_with_an_obligation_the_kernel_cannot_honour_is_undecided() {
        let w = board_world("board-obligation");
        let j = w.at_work("jin");
        w.stored("hobi", "sentinel-695-labelled", labelled());
        w.stored("hobi", "p", PostLabels::default());
        let pdp = Arc::new(common::PermitsWithObligation {
            inner: Arc::clone(&w.pdp),
            label: LABEL,
        });
        let (answer, records) = w.board_as(&pdp, "jin", read(None), j).await;
        assert_eq!(refused(&answer), Some(BoardDefect::TryAgain), "{answer:?}");
        assert_eq!(
            said(&records)[1..],
            one(
                "deny",
                "board: the decision did not complete",
                "unavailable"
            )
        );
        assert_eq!(w.cursor("jin"), 0, "neither delivered nor skipped");
        assert_eq!(
            bodies(&page_of(w.board("jin", read(None), j).await.0)),
            ["sentinel-695-labelled", "p"]
        );
    }

    #[tokio::test]
    async fn an_undecided_post_is_never_skipped_and_refuses_the_read() {
        let w = board_world("board-undecided");
        let j = w.at_work("jin");
        for n in 0..3 {
            w.stored("hobi", &format!("l{n}"), labelled());
        }
        let pdp = Arc::new(common::PanicsOnLabel {
            inner: Arc::clone(&w.pdp),
            label: LABEL,
        });
        let (answer, records) = w.board_as(&pdp, "jin", read(None), j).await;
        assert_eq!(refused(&answer), Some(BoardDefect::TryAgain), "{answer:?}");
        assert_eq!(
            said(&records)[1..],
            one(
                "deny",
                "board: the decision did not complete",
                "unavailable"
            )
        );
        assert_eq!(w.cursor("jin"), 0);
        assert_eq!(
            bodies(&page_of(w.board("jin", read(None), j).await.0)),
            ["l0", "l1", "l2"]
        );
    }

    #[tokio::test]
    async fn a_stalled_walk_returns_what_it_kept_and_says_more() {
        let w = board_world("board-stalled");
        let j = w.at_work("jin");
        w.stored("hobi", "p1", PostLabels::default());
        let p2 = w.stored("hobi", "p2", PostLabels::default());
        w.stored("hobi", "l", labelled());
        w.stored("hobi", "p4", PostLabels::default());
        let own = posted(w.board("jin", post(note("j")), j).await.0);
        let pdp = Arc::new(common::UndecidedOnLabel {
            inner: Arc::clone(&w.pdp),
            label: LABEL,
        });
        let (answer, records) = w.board_as(&pdp, "jin", read(None), j).await;
        let page = page_of(answer);
        assert_eq!(bodies(&page), ["p1", "p2"]);
        assert!(page.more);
        let b = read_outcome(&records);
        assert_eq!((b.returned, b.withheld), (Some(2), Some(0)));
        assert_eq!(w.cursor("jin"), 0);
        let again = page_of(w.board_as(&pdp, "jin", read(Some(own)), j).await.0);
        assert_eq!(bodies(&again), ["p1", "p2"]);
        assert_eq!(
            w.cursor("jin"),
            0,
            "a post past what was sent is not acknowledged"
        );
        assert_eq!(
            bodies(&page_of(w.board("jin", read(Some(p2)), j).await.0)),
            ["l", "p4", "j"]
        );
        assert_eq!(w.cursor("jin"), w.seq(p2));
    }

    #[tokio::test]
    async fn an_unwritten_reply_lets_no_acknowledgement_pass_unsent_posts() {
        let w = board_world("board-unwritten");
        let (h, j) = (w.at_work("hobi"), w.at_work("jin"));
        for body in ["p1", "p2", "p3"] {
            posted(w.board("hobi", post(note(body)), h).await.0);
        }
        let own = posted(w.board("jin", post(note("j")), j).await.0);
        let records = Records::new(0);
        let pdp = Arc::clone(&w.pdp);
        w.serve_unread(&pdp, "jin", read(None), Some(j), &records)
            .await;
        let undelivered: Vec<_> = records
            .snapshot()
            .into_iter()
            .filter(|r| r.action == "board.read")
            .map(|r| (r.outcome.result, r.outcome.reason, r.outcome.posture))
            .collect();
        assert!(
            undelivered.contains(&(
                "permit".into(),
                "delivery failed: response not written".into(),
                "undelivered".into()
            )),
            "{undelivered:?}"
        );
        assert_eq!(w.cursor("jin"), 0);
        assert_eq!(
            bodies(&page_of(w.board("jin", read(Some(own)), j).await.0)),
            ["p1", "p2", "p3", "j"]
        );
    }

    #[tokio::test]
    async fn a_refused_post_names_its_defect_on_the_wire() {
        let mut w = board_world("board-refused");
        w.agents.board = Arc::new(
            BoardStore::open_with(
                Box::new(w.board_blobs.clone()),
                w.clock.clone(),
                Caps {
                    board: 4,
                    author: 2,
                },
            )
            .unwrap(),
        );
        let (h, j) = (w.at_work("hobi"), w.at_work("jin"));
        let ask = |agent: &'static str, task: TaskId, draft: PostDraft| {
            let w = &w;
            async move { w.board(agent, post(draft), task).await }
        };
        let (answer, records) = ask("hobi", h, reply("x", PostId([0x69; 16]))).await;
        assert_eq!(refused(&answer), Some(BoardDefect::NoSuchPost));
        assert_eq!(
            said(&records),
            one(
                "deny",
                "in_reply_to names no post on the board",
                "unauthorized"
            )
        );

        w.board_blobs.fail(Some(Fail::Every));
        let (answer, records) = ask("hobi", h, note("x")).await;
        w.board_blobs.fail(None);
        assert_eq!(refused(&answer), Some(BoardDefect::TryAgain));
        assert_eq!(records[1].outcome.result, "permit");
        assert!(
            records[1].outcome.reason.starts_with("store: "),
            "{records:?}"
        );

        let armed = w.board_blobs.clone();
        w.board_blobs
            .after_save(move || armed.fail(Some(Fail::Unsynced)));
        let (answer, records) = ask("hobi", h, note("x")).await;
        w.board_blobs.fail(None);
        assert_eq!(refused(&answer), Some(BoardDefect::OutcomeUnknown));
        assert!(
            records[1].outcome.reason.starts_with("outcome unknown: "),
            "{records:?}"
        );
        assert_eq!(records[1].outcome.posture, "unavailable");

        for body in ["h1", "h2"] {
            posted(ask("hobi", h, note(body)).await.0);
        }
        let (answer, records) = ask("hobi", h, note("h3")).await;
        assert_eq!(refused(&answer), Some(BoardDefect::AuthorAtCap));
        assert_eq!(records[1].outcome.reason, "author at cap");
        for body in ["j1", "j2"] {
            posted(ask("jin", j, note(body)).await.0);
        }
        let (answer, records) = ask("jin", j, note("j3")).await;
        assert_eq!(refused(&answer), Some(BoardDefect::Full));
        assert_eq!(records[1].outcome.reason, "board full");

        let other = Arc::new(common::OtherBoard {
            inner: Arc::clone(&w.pdp),
            board: "users/31337",
        });
        let (answer, records) = w.board_as(&other, "hobi", read(None), h).await;
        assert!(unauthorized(&answer), "{answer:?}");
        assert_eq!(
            said(&records),
            one(
                "deny",
                "partition: the board is outside the task's partition",
                "unauthorized"
            )
        );

        w.switch(false, &["hobi", "jin"]);
        let (answer, _) = w.board("hobi", read(None), h).await;
        assert!(unauthorized(&answer), "{answer:?}");
    }

    #[tokio::test]
    async fn a_switch_turned_off_refuses_the_next_request() {
        let mut w = board_world("board-switch-off");
        let h = w.at_work("hobi");
        posted(w.board("hobi", post(note("a")), h).await.0);
        w.switch(false, &["hobi"]);
        let (answer, records) = w.board("hobi", post(note("b")), h).await;
        assert!(unauthorized(&answer));
        assert_eq!(
            said(&records),
            one("deny", "board off: site", "unavailable")
        );
        w.switch(true, &["hobi"]);
        w.enable(w.me, false);
        let (answer, records) = w.board("hobi", read(None), h).await;
        assert!(unauthorized(&answer));
        assert_eq!(
            said(&records),
            one("deny", "board off: tasker", "unavailable")
        );
        assert_eq!(w.agents.board.candidates(w.key(), 0, 10).len(), 1);
    }

    #[tokio::test]
    async fn board_requests_renew_the_lease_and_count_as_actions() {
        let w = board_world("board-lease");
        let h = w.at_work("hobi");
        let lease = CLAIM_LEASE.as_secs() as i64;
        w.clock.set(T0 + 50);
        posted(w.board("hobi", post(note("a")), h).await.0);
        let hot = w.store().hot(&h).unwrap();
        assert_eq!(
            (hot.actions, hot.last_action, hot.lease_until),
            (1, Some(T0 + 50), T0 + 50 + lease)
        );
        w.clock.set(T0 + 80);
        page_of(w.board("hobi", read(None), h).await.0);
        let hot = w.store().hot(&h).unwrap();
        assert_eq!(
            (hot.actions, hot.last_action, hot.lease_until),
            (2, Some(T0 + 80), T0 + 80 + lease)
        );
    }

    #[tokio::test]
    async fn a_contained_agents_posts_disappear_from_reads_and_return_on_release() {
        let w = board_world("board-held-release");
        let (h, j) = (w.at_work("hobi"), w.at_work("jin"));
        for body in ["sentinel-695-held-a", "sentinel-695-held-b"] {
            posted(w.board("hobi", post(note(body)), h).await.0);
        }
        posted(w.board("jin", post(note("sentinel-695-free")), j).await.0);
        let all = [
            "sentinel-695-held-a",
            "sentinel-695-held-b",
            "sentinel-695-free",
        ];
        let jin_reads = || async { bodies(&page_of(w.board("jin", read(None), j).await.0)) };
        assert_eq!(jin_reads().await, all);
        let everyone = only(&[("hobi", HOBI_UID), ("suga", SUGA_UID), ("jin", JIN_UID)]);
        let board = &w.agents.board;
        board.mark(&maknae_kernel::Containing(
            everyone.clone(),
            [HOBI_UID].into_iter().collect(),
        ));
        let due = board.due(100);
        assert_eq!(board.perform(&due, &*w.agents.view), 2);
        assert_eq!(jin_reads().await, ["sentinel-695-free"]);
        assert_eq!(w.cursor("jin"), 0);
        board.mark(&everyone);
        assert_eq!(
            jin_reads().await,
            ["sentinel-695-free"],
            "a written hold outlives the containment"
        );
        let held = board.held_for(HOBI_UID, maknae_proto::HELD_PAGE_MAX);
        assert_eq!(held.len(), 2);
        for (key, id, _, lifted) in held {
            assert_eq!(
                board.release(key, id, lifted, &everyone),
                Ok(maknae_kernel::Lifted::Done)
            );
        }
        assert_eq!(jin_reads().await, all);
        assert_eq!(w.cursor("jin"), 0);
        assert_eq!(board.held_count(HOBI_UID), 0);
    }

    /// Runs `then` once, while the trail appends `action`'s intent record.
    struct OnIntent {
        inner: Arc<Records>,
        action: &'static str,
        then: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl maknae_audit_append::AuditEmit for OnIntent {
        fn emit(
            &self,
            record: &AuditRecord,
        ) -> impl std::future::Future<Output = Result<(), maknae_audit_append::AuditError>> + Send
        {
            if record.action == self.action && record.outcome.reason == "intent recorded" {
                if let Some(then) = self.then.lock().unwrap().take() {
                    then();
                }
            }
            self.inner.emit(record)
        }
    }

    impl World {
        /// `verb` from `agent`, with `then` run while its intent record is appended.
        async fn board_during_intent(
            &self,
            agent: &str,
            verb: Verb,
            task: TaskId,
            then: impl FnOnce() + Send + 'static,
        ) -> (RespResult, Vec<AuditRecord>) {
            let pdp = Arc::clone(&self.pdp);
            self.board_during_intent_as(&pdp, agent, verb, task, then)
                .await
        }

        /// [`Self::board_during_intent`], decided by `authorizer`.
        async fn board_during_intent_as<P>(
            &self,
            authorizer: &Arc<P>,
            agent: &str,
            verb: Verb,
            task: TaskId,
            then: impl FnOnce() + Send + 'static,
        ) -> (RespResult, Vec<AuditRecord>)
        where
            P: maknae_security::Authorizer
                + maknae_kernel::SensitiveNow
                + maknae_kernel::CatalogNow
                + Send
                + Sync
                + 'static,
        {
            let action = match verb {
                Verb::BoardPost { .. } => "board.post",
                _ => "board.read",
            };
            let records = Records::new(0);
            let emit = Arc::new(OnIntent {
                inner: Arc::clone(&records),
                action,
                then: std::sync::Mutex::new(Some(Box::new(then))),
            });
            let raw = {
                let _shared = STORE.read().await;
                let (session, gate) = self.agent_session(agent);
                self.serve_as(
                    Arc::clone(authorizer),
                    session,
                    gate,
                    verb,
                    Some(task),
                    &emit,
                    None,
                    Wiring {
                        live: Arc::new(maknae_kernel::LiveConfig::new(Default::default(), None)),
                        egress: maknae_kernel::unavailable_egress(),
                        conversations: common::conversations(),
                    },
                )
                .await
            };
            let mut cursor = &raw[..];
            let frame = common::read_frame(&mut cursor, 1 << 20).await.unwrap();
            let answer = maknae_proto::decode_response(&frame).unwrap().result;
            let records = records
                .snapshot()
                .into_iter()
                .filter(|r| r.action.starts_with("board."))
                .collect();
            (answer, records)
        }

        /// Rewrites the bindings and reloads the policy, as an admin's edit installs it.
        fn rebind(&self, bindings: &str) -> impl Fn() + Send + Sync + 'static {
            let path = maknae_authz_basic::PolicyPaths::in_dir(&self.root).bindings;
            self.reload(path, format!("schema_version: 1\nbindings:\n{bindings}"))
        }

        /// Rewrites the role grants and reloads the policy.
        fn regrant(&self, roles: &str) -> impl Fn() + Send + Sync + 'static {
            let path = maknae_authz_basic::PolicyPaths::in_dir(&self.root).authz;
            self.reload(
                path,
                format!("schema_version: 1\npermissions:\n  allow: []\n  deny: []\n{roles}"),
            )
        }

        fn reload(&self, path: PathBuf, text: String) -> impl Fn() + Send + Sync + 'static {
            let pdp = Arc::clone(&self.pdp);
            move || {
                common::write_0640(&path, &text);
                pdp.baseline().reload_from_file().unwrap();
            }
        }
    }

    #[tokio::test]
    async fn a_post_written_after_its_board_is_contained_is_withheld() {
        let w = board_world("board-post-contained");
        let h = w.at_work("hobi");
        let contain = w.rebind(&format!(
            "  adversary: [\"{}\"]\n  user: [\"nobody\"]\n",
            w.user
        ));
        let (board, view) = (Arc::clone(&w.agents.board), w.agents.view.clone());
        let (answer, records) = w
            .board_during_intent(
                "hobi",
                post(note("sentinel-695-after-contain")),
                h,
                move || {
                    contain();
                    board.mark(&*view);
                },
            )
            .await;
        let id = posted(answer);
        assert_eq!(
            said(&records)
                .iter()
                .map(|(_, reason, _)| reason.as_str())
                .collect::<Vec<_>>(),
            ["intent recorded", "done"],
            "the post was accepted and stored"
        );
        assert!(w.agents.view.contained(w.me));
        let board = &w.agents.board;
        assert!(board.get(w.key(), id).is_none());
        assert!(board.candidates(w.key(), 0, 10).is_empty());
        let due = board.due(10);
        assert_eq!(due.iter().map(|d| d.post).collect::<Vec<_>>(), [Some(id)]);
        assert_eq!(board.perform(&due, &*w.agents.view), 1);
        let held: Vec<_> = board
            .held_for(w.me, 10)
            .into_iter()
            .map(|(key, id, _, lifted)| (key, id, lifted))
            .collect();
        assert_eq!(held, [(w.key(), id, maknae_kernel::HeldFor::Person)]);
    }

    #[tokio::test]
    async fn a_reader_contained_mid_read_is_refused_and_keeps_every_post() {
        let w = board_world("board-read-contained");
        let (h, j) = (w.at_work("hobi"), w.at_work("jin"));
        let all = ["sentinel-695-mid-a", "sentinel-695-mid-b"];
        for body in all {
            posted(w.board("hobi", post(note(body)), h).await.0);
        }
        let bound = format!("  user: [\"{}\", \"nobody\"]\n", w.user);
        let contain = w.rebind(&format!("{bound}  adversary: [{{uid: {JIN_UID}}}]\n"));
        let (answer, records) = w.board_during_intent("jin", read(None), j, contain).await;
        assert!(w.agents.view.contained(JIN_UID));
        assert_eq!(refused(&answer), Some(BoardDefect::TryAgain), "{answer:?}");
        assert_eq!(
            said(&records)[1..],
            one(
                "deny",
                "board: the decision did not complete",
                "unavailable"
            )
        );
        assert_eq!(w.cursor("jin"), 0, "the cursor did not move");
        w.rebind(&bound)();
        assert!(!w.agents.view.contained(JIN_UID));
        assert_eq!(bodies(&page_of(w.board("jin", read(None), j).await.0)), all);
    }

    #[tokio::test]
    async fn a_reader_whose_grant_is_removed_mid_read_is_refused_and_keeps_every_post() {
        let w = board_world("board-read-ungranted");
        let (h, j) = (w.at_work("hobi"), w.at_work("jin"));
        let all = ["sentinel-695-grant-a", "sentinel-695-grant-b"];
        for body in all {
            posted(w.board("hobi", post(note(body)), h).await.0);
        }
        let ungrant = w.regrant("roles:\n  user:\n    allow: [\"session.task\", \"board.post\"]\n");
        let (answer, records) = w.board_during_intent("jin", read(None), j, ungrant).await;
        assert_eq!(refused(&answer), Some(BoardDefect::TryAgain), "{answer:?}");
        assert_eq!(
            said(&records)[1..],
            one(
                "deny",
                "board: the decision did not complete",
                "unavailable"
            )
        );
        assert_eq!(w.cursor("jin"), 0, "the cursor did not move");
        w.regrant(BOARD_ROLES)();
        assert_eq!(bodies(&page_of(w.board("jin", read(None), j).await.0)), all);
    }

    #[tokio::test]
    async fn a_post_marked_while_its_read_is_decided_is_not_delivered() {
        let w = board_world("board-marked-mid-read");
        let j = w.at_work("jin");
        w.stored("hobi", "sentinel-695-a", PostLabels::default());
        w.stored("suga", "sentinel-695-b", PostLabels::default());
        w.stored("hobi", "sentinel-695-c", PostLabels::default());
        let everyone = only(&[("hobi", HOBI_UID), ("suga", SUGA_UID), ("jin", JIN_UID)]);
        let pdp = Arc::new(common::MarksDuringBatch {
            inner: Arc::clone(&w.pdp),
            board: Arc::clone(&w.agents.board),
            view: maknae_kernel::Containing(everyone.clone(), [SUGA_UID].into_iter().collect()),
            armed: true.into(),
            label: None,
        });
        let (answer, records) = w.board_as(&pdp, "jin", read(None), j).await;
        let page = page_of(answer);
        assert_eq!(bodies(&page), ["sentinel-695-a", "sentinel-695-c"]);
        assert!(!page.more);
        assert_eq!(read_outcome(&records).returned, Some(2));
        assert_eq!(w.cursor("jin"), 0);
        w.agents.board.mark(&everyone);
        assert_eq!(
            bodies(&page_of(w.board("jin", read(None), j).await.0)),
            ["sentinel-695-a", "sentinel-695-b", "sentinel-695-c"],
            "the post was not acknowledged over"
        );
    }

    #[tokio::test]
    async fn an_acknowledgement_of_a_post_never_sent_is_ignored() {
        let w = board_world("board-ack-unsent");
        let j = w.at_work("jin");
        w.stored("hobi", "sentinel-695-a", PostLabels::default());
        let b = w.stored("hobi", "sentinel-695-b", labelled());
        let c = w.stored("hobi", "sentinel-695-c", PostLabels::default());
        w.stored("hobi", "sentinel-695-d", PostLabels::default());
        let pdp = denies(&w, &["jin"]);
        let page = page_of(w.board_as(&pdp, "jin", read(None), j).await.0);
        assert_eq!(
            bodies(&page),
            ["sentinel-695-a", "sentinel-695-c", "sentinel-695-d"]
        );
        let unknown = page_of(
            w.board_as(&pdp, "jin", read(Some(PostId([0x5e; 16]))), j)
                .await
                .0,
        );
        assert_eq!(w.cursor("jin"), 0);
        let withheld = page_of(w.board_as(&pdp, "jin", read(Some(b)), j).await.0);
        assert_eq!(w.cursor("jin"), 0, "the withheld id moves nothing");
        assert_eq!(bodies(&withheld), bodies(&unknown));
        page_of(w.board_as(&pdp, "jin", read(Some(c)), j).await.0);
        assert_eq!(w.cursor("jin"), w.seq(c));
    }

    /// Reads as jin while suga is contained inside the batch that decides suga's labelled post.
    async fn read_while_suga_is_contained(w: &World, j: TaskId) -> BoardPage {
        let everyone = only(&[("hobi", HOBI_UID), ("suga", SUGA_UID), ("jin", JIN_UID)]);
        let pdp = Arc::new(common::MarksDuringBatch {
            inner: Arc::clone(&w.pdp),
            board: Arc::clone(&w.agents.board),
            view: maknae_kernel::Containing(everyone, [SUGA_UID].into_iter().collect()),
            armed: true.into(),
            label: Some(LABEL),
        });
        page_of(w.board_as(&pdp, "jin", read(None), j).await.0)
    }

    fn hobi_posts(w: &World, range: std::ops::Range<usize>) -> Vec<String> {
        range
            .map(|n| {
                let body = format!("sentinel-695-h{n}");
                w.stored("hobi", &body, PostLabels::default());
                body
            })
            .collect()
    }

    #[tokio::test]
    async fn a_lookahead_contained_while_its_read_is_decided_does_not_set_more() {
        let w = board_world("board-lookahead-alone");
        let j = w.at_work("jin");
        let page_posts = hobi_posts(&w, 0..maknae_proto::BOARD_READ_PAGE_POSTS);
        w.stored("suga", "sentinel-695-lookahead", labelled());
        let page = read_while_suga_is_contained(&w, j).await;
        assert_eq!(bodies(&page), page_posts);
        assert!(!page.more, "as if the lookahead were not there");
    }

    #[tokio::test]
    async fn a_lookahead_contained_while_its_read_is_decided_looks_further() {
        let w = board_world("board-lookahead-further");
        let j = w.at_work("jin");
        let page_posts = hobi_posts(&w, 0..maknae_proto::BOARD_READ_PAGE_POSTS);
        w.stored("suga", "sentinel-695-lookahead", labelled());
        w.stored("hobi", "sentinel-695-after", PostLabels::default());
        let page = read_while_suga_is_contained(&w, j).await;
        assert_eq!(bodies(&page), page_posts);
        assert!(page.more, "the next live post beyond it is still more");
    }

    #[tokio::test]
    async fn a_post_dropped_at_delivery_leaves_its_room_to_the_next_post() {
        let w = board_world("board-dropped-room");
        let j = w.at_work("jin");
        w.stored("suga", "sentinel-695-dropped", labelled());
        let want = hobi_posts(&w, 0..maknae_proto::BOARD_READ_PAGE_POSTS);
        let page = read_while_suga_is_contained(&w, j).await;
        assert_eq!(
            bodies(&page),
            want,
            "the page the read would give without it"
        );
        assert!(!page.more);
    }

    #[tokio::test]
    async fn a_read_behind_withheld_posts_writes_no_cursor_even_when_the_disk_refuses() {
        let w = board_world("board-no-skip-refused");
        let j = w.at_work("jin");
        w.stored("hobi", "sentinel-695-withheld", labelled());
        let pdp = denies(&w, &["jin"]);
        w.board_blobs.fail(Some(Fail::Every));
        let (answer, records) = w.board_as(&pdp, "jin", read(None), j).await;
        w.board_blobs.fail(None);
        let page = page_of(answer);
        assert!(
            page.posts.is_empty() && !page.more,
            "the page of an empty board"
        );
        assert_eq!(
            said(&records)[1..],
            one("permit", "done", "authorized"),
            "nothing is written after the reply"
        );
        page_of(w.board_as(&pdp, "jin", read(None), j).await.0);
        assert_eq!(w.cursor("jin"), 0, "and nothing on the next read either");
    }

    #[tokio::test]
    async fn a_read_never_walks_past_the_posts_there_when_it_was_admitted() {
        let w = board_world("board-upper-bound");
        let j = w.at_work("jin");
        let first = w.stored("hobi", "sentinel-695-first", labelled());
        let pdp = Arc::new(common::AppendsDuringBatch {
            inner: Arc::clone(&w.pdp),
            board: Arc::clone(&w.agents.board),
            key: w.key(),
            label: LABEL,
            labels: labelled(),
            limit: 5,
            batches: 0.into(),
        });
        let (answer, _) = w.board_as(&pdp, "jin", read(None), j).await;
        let page = page_of(answer);
        assert!(page.posts.is_empty() && !page.more);
        assert_eq!(
            pdp.batches.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a post appended during the read is for the next read"
        );
        assert_eq!(w.cursor("jin"), 0);
        assert!(w.seq(first) > 0);
    }

    #[tokio::test]
    async fn a_reader_ungranted_mid_read_gets_the_same_answer_from_an_empty_board_and_a_withheld_one(
    ) {
        let ungranted = "roles:\n  user:\n    allow: [\"session.task\", \"board.post\"]\n";
        let mut answers = Vec::new();
        for withheld in [false, true] {
            let w = board_world(&format!("board-base-{withheld}"));
            let j = w.at_work("jin");
            if withheld {
                w.stored("hobi", "sentinel-695-withheld", labelled());
            }
            let pdp = denies(&w, &["jin"]);
            let (answer, records) = w
                .board_during_intent_as(&pdp, "jin", read(None), j, w.regrant(ungranted))
                .await;
            answers.push((
                refused(&answer),
                said(&records)[1..].to_vec(),
                w.cursor("jin"),
            ));
        }
        assert_eq!(answers[0], answers[1]);
        assert_eq!(
            answers[0],
            (
                Some(BoardDefect::TryAgain),
                one(
                    "deny",
                    "board: the decision did not complete",
                    "unavailable"
                ),
                0
            )
        );
    }

    /// Reads as jin while suga's labelled post is undecided and suga is contained inside the
    /// batch that decides it.
    async fn read_while_the_stop_is_contained(w: &World, j: TaskId) -> RespResult {
        let everyone = only(&[("hobi", HOBI_UID), ("suga", SUGA_UID), ("jin", JIN_UID)]);
        let undecided = Arc::new(common::UndecidedOnLabel {
            inner: Arc::clone(&w.pdp),
            label: LABEL,
        });
        let pdp = Arc::new(common::MarksDuringBatch {
            inner: undecided,
            board: Arc::clone(&w.agents.board),
            view: maknae_kernel::Containing(everyone, [SUGA_UID].into_iter().collect()),
            armed: true.into(),
            label: Some(LABEL),
        });
        w.board_as(&pdp, "jin", read(None), j).await.0
    }

    #[tokio::test]
    async fn an_undecided_stop_contained_mid_decision_answers_as_an_empty_board() {
        let w = board_world("board-stop-alone");
        let j = w.at_work("jin");
        w.stored("suga", "sentinel-695-stop", labelled());
        let page = page_of(read_while_the_stop_is_contained(&w, j).await);
        assert!(page.posts.is_empty());
        assert!(!page.more, "the page of an empty board");
        assert_eq!(w.cursor("jin"), 0);
    }

    #[tokio::test]
    async fn an_undecided_stop_contained_mid_decision_lets_the_walk_go_past_it() {
        let w = board_world("board-stop-between");
        let j = w.at_work("jin");
        w.stored("hobi", "sentinel-695-p1", PostLabels::default());
        w.stored("suga", "sentinel-695-stop", labelled());
        w.stored("hobi", "sentinel-695-p2", PostLabels::default());
        let page = page_of(read_while_the_stop_is_contained(&w, j).await);
        assert_eq!(bodies(&page), ["sentinel-695-p1", "sentinel-695-p2"]);
        assert!(!page.more);
    }

    #[tokio::test]
    async fn a_reply_target_contained_while_it_is_decided_loses_the_link() {
        let w = board_world("board-target-contained");
        let j = w.at_work("jin");
        let t = w.stored("suga", "sentinel-695-target", labelled());
        page_of(w.board("jin", read(None), j).await.0);
        page_of(w.board("jin", read(Some(t)), j).await.0);
        assert_eq!(w.cursor("jin"), w.seq(t));
        w.agents
            .board
            .post(
                w.key(),
                (Author::Agent("hobi".into()), Some(HOBI_UID)),
                None,
                PostLabels::default(),
                reply("sentinel-695-reply", t),
                &*w.agents.view,
            )
            .unwrap();
        let everyone = only(&[("hobi", HOBI_UID), ("suga", SUGA_UID), ("jin", JIN_UID)]);
        let pdp = Arc::new(common::MarksDuringBatch {
            inner: Arc::clone(&w.pdp),
            board: Arc::clone(&w.agents.board),
            view: maknae_kernel::Containing(everyone, [SUGA_UID].into_iter().collect()),
            armed: true.into(),
            label: Some(LABEL),
        });
        let page = page_of(w.board_as(&pdp, "jin", read(None), j).await.0);
        assert_eq!(bodies(&page), ["sentinel-695-reply"]);
        assert_eq!(
            page.posts[0].draft.in_reply_to, None,
            "as for a target that is gone"
        );
    }

    #[tokio::test]
    async fn a_dead_stop_is_never_decided_again_and_the_read_ends() {
        let w = board_world("board-stop-dead-ends");
        let j = w.at_work("jin");
        w.stored("suga", "sentinel-695-stop", labelled());
        w.stored("hobi", "sentinel-695-undecided-too", labelled());
        let bound = format!("  user: [\"{}\", \"nobody\"]\n", w.user);
        w.rebind(&format!("{bound}  adversary: [{{uid: {SUGA_UID}}}]\n"))();
        let pdp = Arc::new(common::UndecidedOnLabel {
            inner: Arc::clone(&w.pdp),
            label: LABEL,
        });
        let read = tokio::time::timeout(
            Duration::from_secs(20),
            w.board_as(&pdp, "jin", read(None), j),
        )
        .await
        .expect("the read ends");
        assert_eq!(
            refused(&read.0),
            Some(BoardDefect::TryAgain),
            "the live undecided post after it stops the read, as on a board without the dead one"
        );
    }

    /// jin's read behind one post denied to it, with the board's disk in `disk`'s state while
    /// the read's skip is written; the answer.
    async fn read_behind_a_withheld_post(
        tag: &str,
        disk: impl FnOnce(&MemTaskBlobs),
    ) -> RespResult {
        let w = board_world(tag);
        let j = w.at_work("jin");
        w.stored("hobi", "sentinel-695-withheld", labelled());
        let pdp = denies(&w, &["jin"]);
        let _alone = STORE.write().await;
        disk(&w.board_blobs);
        let (session, gate) = w.agent_session("jin");
        let records = Records::new(0);
        let raw = w
            .serve_as(
                pdp,
                session,
                gate,
                read(None),
                Some(j),
                &records,
                None,
                Wiring {
                    live: Arc::new(maknae_kernel::LiveConfig::new(Default::default(), None)),
                    egress: maknae_kernel::unavailable_egress(),
                    conversations: common::conversations(),
                },
            )
            .await;
        w.board_blobs.slow(None);
        w.board_blobs.fail(None);
        let mut cursor = &raw[..];
        let frame = common::read_frame(&mut cursor, 1 << 20).await.unwrap();
        maknae_proto::decode_response(&frame).unwrap().result
    }

    #[tokio::test]
    async fn the_reply_behind_a_withheld_post_is_the_same_whatever_the_disk_does() {
        let stored = read_behind_a_withheld_post("board-skip-stored", |_| {}).await;
        let refused =
            read_behind_a_withheld_post("board-skip-refused", |b| b.fail(Some(Fail::Every))).await;
        let timed_out = read_behind_a_withheld_post("board-skip-timed-out", |b| {
            b.slow(Some(Duration::from_millis(2500)))
        })
        .await;
        let page = page_of(stored);
        assert!(page.posts.is_empty() && !page.more);
        for other in [refused, timed_out] {
            assert_eq!(page_of(other), page);
        }
    }

    const UNGRANTED: &str = "roles:\n  user:\n    allow: [\"session.task\", \"board.post\"]\n";

    fn expired_at() -> i64 {
        T0 + maknae_kernel::BOARD_RETENTION.as_secs() as i64
    }

    #[tokio::test]
    async fn a_reader_revoked_before_its_batch_whose_candidate_expires_meanwhile_gets_try_again() {
        let mut answers = Vec::new();
        for expired_at_admission in [false, true] {
            let w = board_world(&format!("board-base-observed-{expired_at_admission}"));
            let j = w.at_work("jin");
            w.stored("hobi", "sentinel-695-only", PostLabels::default());
            if expired_at_admission {
                w.clock.set(expired_at());
            }
            let pdp = Arc::new(common::AdvancesClockDuringBatch {
                inner: Arc::clone(&w.pdp),
                clock: Arc::clone(&w.clock),
                at: expired_at(),
                armed: true.into(),
            });
            let (answer, records) = w
                .board_during_intent_as(&pdp, "jin", read(None), j, w.regrant(UNGRANTED))
                .await;
            answers.push((
                refused(&answer),
                said(&records)[1..].to_vec(),
                w.cursor("jin"),
            ));
        }
        assert_eq!(answers[0], answers[1]);
        assert_eq!(
            answers[0],
            (
                Some(BoardDefect::TryAgain),
                one(
                    "deny",
                    "board: the decision did not complete",
                    "unavailable"
                ),
                0
            )
        );
    }

    impl World {
        /// `verb` from `agent`, decided by `authorizer`: how long the first frame took, the
        /// frame, and the board records once the handler has returned.
        async fn first_frame<P>(
            &self,
            authorizer: &Arc<P>,
            agent: &str,
            verb: Verb,
            task: TaskId,
        ) -> (Duration, Vec<u8>, Vec<AuditRecord>)
        where
            P: maknae_security::Authorizer
                + maknae_kernel::SensitiveNow
                + maknae_kernel::CatalogNow
                + Send
                + Sync
                + 'static,
        {
            let (session, gate) = self.agent_session(agent);
            let records = Records::new(0);
            let (mut client, server) = tokio::io::duplex(1 << 20);
            let served = maknae_kernel::handle_with_attempt_caps(
                server,
                Some("spiffe://d/plane/cli".into()),
                Arc::new(session),
                gate,
                Arc::clone(&records),
                self.cfg.clone(),
                serde_json::json!({}),
                Arc::clone(authorizer),
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
                task: Some(task),
                protocol_version: maknae_proto::PROTOCOL_VERSION,
                verb,
            })
            .unwrap();
            let started = std::time::Instant::now();
            common::write_frame(&mut client, &body).await.unwrap();
            let frame = common::read_frame(&mut client, 1 << 20).await.unwrap();
            let took = started.elapsed();
            tokio::time::timeout(Duration::from_secs(10), serving)
                .await
                .unwrap()
                .unwrap();
            let records = records
                .snapshot()
                .into_iter()
                .filter(|r| r.action.starts_with("board."))
                .collect();
            (took, frame, records)
        }
    }

    /// jin's read behind one post denied to it, with the board's disk set by `disk` before it.
    async fn skip_behind_a_withheld_post(
        tag: &str,
        disk: impl FnOnce(&MemTaskBlobs),
    ) -> (Duration, Vec<u8>, Vec<AuditRecord>) {
        let w = board_world(tag);
        let j = w.at_work("jin");
        w.stored("hobi", "sentinel-695-withheld", labelled());
        let pdp = denies(&w, &["jin"]);
        let _alone = STORE.write().await;
        disk(&w.board_blobs);
        let got = w.first_frame(&pdp, "jin", read(None), j).await;
        w.board_blobs.slow(None);
        w.board_blobs.fail(None);
        got
    }

    #[tokio::test]
    async fn a_read_behind_a_withheld_post_records_nothing_after_its_reply() {
        let (_, written, done) = skip_behind_a_withheld_post("board-skip-after-ok", |_| {}).await;
        let outcome = |records: &[AuditRecord]| {
            records
                .iter()
                .find(|r| r.outcome.reason == "done")
                .map(|r| {
                    (
                        r.outcome.result.clone(),
                        r.outcome.posture.clone(),
                        r.board.clone(),
                    )
                })
                .unwrap_or_else(|| panic!("no outcome: {records:?}"))
        };
        for (tag, slow) in [
            ("board-skip-after-stalled", true),
            ("board-skip-after-refused", false),
        ] {
            let (took, frame, records) = skip_behind_a_withheld_post(tag, |b| match slow {
                true => b.slow(Some(Duration::from_millis(2500))),
                false => b.fail(Some(Fail::Every)),
            })
            .await;
            assert_eq!(frame, written, "{tag}: the reply, byte for byte");
            assert_eq!(
                outcome(&records),
                outcome(&done),
                "{tag}: the outcome record"
            );
            assert_eq!(
                records.len(),
                2,
                "{tag}: intent and outcome only: {records:?}"
            );
            if slow {
                assert!(
                    took < Duration::from_millis(1500),
                    "the reply does not wait on the disk: {took:?}"
                );
            }
        }
    }
}
