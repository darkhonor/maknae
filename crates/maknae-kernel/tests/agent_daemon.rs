//! #629: the agent daemon's task driver and plane (`maknae-agent`'s `TaskDriver` over
//! `maknae-loop`'s `AgentPlane`) against the real kernel: every connection is served by
//! the real `handle()` on the agent channel, decided by the real composed PDP, with a
//! real task store, kernel-signed tasks verified against a test CA, and a scripted egress.
mod common;
use common::Records;
use maknae_agent::budget::ContextBudget;
use maknae_agent::drive::Budget;
use maknae_agent::task_driver::{
    Clock, DriverConfig, DriverEvent, Ending, PersonaMode, ShutdownHandle, TaskDriver,
};
use maknae_crypto::plane_key::PlaneKey;
use maknae_io::Zeroizing;
use maknae_kernel::{
    AgentAdmission, ManualClock, MemTaskBlobs, TaskRefusal, TaskStore, CLAIM_LEASE,
};
use maknae_loop::agent::{AgentPlane, PersonaFiles, PersonaRead, TaskTrust};
use maknae_loop::keys::{AgentKeys, WrappedRead};
use maknae_loop::plane::{Dial, LoopPlane};
use maknae_proto::{
    ContentBlock, Payload, PromptReply, ProposedToolCall, RespResult, SecretText, TaskClose,
    TaskId, TaskState, TaskSubmission, Turn, Verb,
};
use maknae_vault::test_pki::{TestCa, TRUST_DOMAIN};
use std::collections::VecDeque;
use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

const HOBI_UID: u32 = 12_101;
const T0: i64 = 1_800_000_000;
const AGENT_PREFIX: &str = "maknae/agents";
/// The kernel's `TASK_SWEEP_EVERY`.
const SWEEP_EVERY: Duration = Duration::from_secs(60);
const _: () = assert!(
    maknae_agent::task_driver::UNDECODABLE_WAIT.as_secs()
        > CLAIM_LEASE.as_secs() + SWEEP_EVERY.as_secs()
);

/// The kernel admits one filesystem preparation per uid at a time, and every test
/// here is the same uids: one daemon runs at a time.
static ONE_DAEMON: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn secret(s: &str) -> SecretText {
    SecretText(Zeroizing::new(s.into()))
}

/// Signs each hand-out with a kernel leaf of the test CA, as `PlaneSigner` does.
struct CaSigner {
    identity: maknae_vault::PlaneIdentity,
}

impl maknae_kernel::TaskSigner for CaSigner {
    fn sign(
        &self,
        task: maknae_proto::TaskObject,
    ) -> Result<maknae_proto::SignedTask, TaskRefusal> {
        maknae_vault::task_sig::sign_task(&self.identity, task)
            .map_err(|e| TaskRefusal::Unavailable(e.to_string()))
    }
    fn current_leaf(&self) -> Option<[u8; 32]> {
        maknae_vault::task_sig::identity_fingerprint(&self.identity).ok()
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

const ROLES: &str = "roles:\n  user:\n    allow: [\"session.task\", \"session.prompt\", \"session.new\", \"session.close\"]\ndestinations:\n  user:\n    allow: [\"provider:openai\"]\n";
const HOBI_POLICY: &str = "schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\", \"Write(~/**)\"]\n  deny: []\nactions:\n  allow: [\"session.prompt\", \"session.new\", \"session.close\", \"fs.mkdir\", \"fs.read\", \"fs.write\"]\n";

type Hook<T> = Box<dyn FnMut(T) + Send>;

/// The scripted model: each prompt takes the next reply; the hook sees its number first.
#[derive(Default)]
struct Model {
    replies: Mutex<VecDeque<PromptReply>>,
    seen: Mutex<Vec<Vec<Turn>>>,
    on_prompt: Mutex<Option<Hook<usize>>>,
}

impl Model {
    fn script(replies: Vec<PromptReply>) -> Arc<Self> {
        Arc::new(Model {
            replies: Mutex::new(replies.into()),
            ..Default::default()
        })
    }
    fn prompts(&self) -> Vec<Vec<Turn>> {
        self.seen.lock().unwrap().clone()
    }
}

impl maknae_kernel::Egress for Model {
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
        assert_eq!(
            r.key_vault_path, "maknae/agents/hobi/openai/hobi",
            "the agent's own key path"
        );
        let n = {
            let mut seen = self.seen.lock().unwrap();
            seen.push(r.turns.clone());
            seen.len()
        };
        if let Some(hook) = self.on_prompt.lock().unwrap().as_mut() {
            hook(n);
        }
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("the model's script ran out");
        Ok(maknae_kernel::EgressReply { reply })
    }
}

fn answer(text: &str) -> PromptReply {
    PromptReply {
        reasoning: None,
        blocks: vec![ContentBlock::Text { text: secret(text) }],
        tool_calls: vec![],
        usage: None,
    }
}

fn tool(name: &str, call: &str, args: String) -> PromptReply {
    PromptReply {
        reasoning: None,
        blocks: vec![],
        tool_calls: vec![ProposedToolCall {
            name: name.into(),
            call_id: call.into(),
            arguments: secret(&args),
            refused: None,
        }],
        usage: None,
    }
}

fn write_file(call: &str, path: &str, content: &str) -> PromptReply {
    tool(
        "write_file",
        call,
        serde_json::json!({ "path": path, "content": content }).to_string(),
    )
}

fn read_file(call: &str, path: &str) -> PromptReply {
    tool(
        "read_file",
        call,
        serde_json::json!({ "path": path }).to_string(),
    )
}

/// The text of every tool result in `turns`.
fn tool_results(turns: &[Turn]) -> Vec<String> {
    turns
        .iter()
        .filter_map(|t| match t {
            Turn::Tool { content, .. } => match content.first() {
                Some(ContentBlock::Text { text }) => Some(text.0.to_string()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// What the kernel is between restarts; the disk, the clock and the conversations
/// outlive it.
struct Kernel {
    agents: AgentAdmission,
    boot: Box<dyn Fn() -> AgentAdmission + Send>,
    restarts: u32,
    /// Connections that still reach the kernel before it goes down.
    up_for: u32,
    /// Connections refused before the handshake, as when the kernel is down.
    down: u32,
    /// The kernel comes back from `down` restarted.
    restart_when_up: bool,
    /// The next delivery the agent sees is not a `SignedTask`.
    garble: Arc<AtomicBool>,
    /// The next connection ends after the kernel's first answer, as when the kernel
    /// dies with a write granted and its outcome not yet reported.
    cut: bool,
}

impl Kernel {
    fn restart(&mut self) {
        self.agents = (self.boot)();
        self.restarts += 1;
    }

    /// Goes down after `up_for` more connections, for `down` connections.
    fn fail(&mut self, up_for: u32, down: u32, restart: bool) {
        (self.up_for, self.down, self.restart_when_up) = (up_for, down, restart);
    }

    /// `false` when this connection is refused.
    fn connects(&mut self) -> bool {
        if self.down == 0 {
            return true;
        }
        if self.up_for > 0 {
            self.up_for -= 1;
            return true;
        }
        self.down -= 1;
        if self.down == 0 && std::mem::take(&mut self.restart_when_up) {
            self.restart();
        }
        false
    }
}

struct World {
    root: common::DirGuard,
    pdp: Arc<maknae_kernel::Composition<maknae_authz_basic::HermeticAuthorizer>>,
    clock: Arc<ManualClock>,
    me: u32,
    user: String,
    cfg: maknae_config::TransportConfig,
    ca: Arc<TestCa>,
    kernel: Arc<Mutex<Kernel>>,
    conversations: Arc<dyn maknae_kernel::ConversationStore>,
    records: Arc<Records>,
}

fn world(tag: &str, hobi_policy: &str) -> World {
    let dir = std::env::temp_dir().join(format!("agentd629_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = common::DirGuard(dir.canonicalize().unwrap());
    let paths = maknae_authz_basic::PolicyPaths::in_dir(&root);
    common::write_0640(
        &paths.authz,
        &format!("schema_version: 1\npermissions:\n  allow: []\n  deny: []\n{ROLES}"),
    );
    common::write_0640(&paths.sensitive, common::EMPTY_SENSITIVE);
    let user = common::euid_name();
    common::write_0640(
        &paths.bindings,
        &format!("schema_version: 1\nbindings:\n  user: [\"{user}\"]\n"),
    );
    let agents_dir = root.join(maknae_config::AGENTS_DIR);
    let hobi_dir = agents_dir.join("hobi");
    std::fs::create_dir_all(&hobi_dir).unwrap();
    for d in [&agents_dir, &hobi_dir] {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o750)).unwrap();
    }
    common::write_0640(
        &hobi_dir.join(maknae_config::ENROLLMENT_FILE),
        &format!("agent_id: hobi\naccount: hobi-svc\nuid: {HOBI_UID}\nrole: user\n"),
    );
    common::write_0640(&hobi_dir.join(maknae_config::POLICY_FILE), hobi_policy);
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
            if uid != HOBI_UID {
                return Ok(None);
            }
            Ok(Some(maknae_io::HostAccount {
                uid,
                name: "hobi-svc".into(),
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
    maknae_crypto::init().unwrap();
    let ca = Arc::new(TestCa::new(PlaneKey::MlDsa87));
    let clock = Arc::new(ManualClock::at(T0));
    let blobs = MemTaskBlobs::default();
    let mut cfg = maknae_config::transport_from_section(None).unwrap();
    cfg.prompt_max_bytes = maknae_config::PROMPT_MAX_BYTES_FLOOR;
    let boot = {
        let (blobs, clock, pdp, ca) = (blobs.clone(), clock.clone(), pdp.clone(), ca.clone());
        Box::new(move || admission(&blobs, &clock, &pdp, &ca))
    };
    World {
        root,
        pdp,
        clock,
        me,
        user,
        cfg,
        kernel: Arc::new(Mutex::new(Kernel {
            agents: boot(),
            boot,
            restarts: 0,
            up_for: 0,
            down: 0,
            restart_when_up: false,
            garble: Arc::new(AtomicBool::new(false)),
            cut: false,
        })),
        conversations: common::conversations(),
        records: Records::new(0),
        ca,
    }
}

/// A kernel's task admission over `blobs`: opening it is what a kernel boot does.
fn admission(
    blobs: &MemTaskBlobs,
    clock: &Arc<ManualClock>,
    pdp: &Arc<maknae_kernel::Composition<maknae_authz_basic::HermeticAuthorizer>>,
    ca: &TestCa,
) -> AgentAdmission {
    AgentAdmission {
        view: Arc::new(maknae_kernel::SnapshotEnrollment(Arc::clone(pdp))),
        tasks: Arc::new(TaskStore::open(Box::new(blobs.clone()), clock.clone()).expect("opens")),
        signer: Arc::new(CaSigner {
            identity: ca.kernel(PlaneKey::MlDsa87, None),
        }),
    }
}

impl World {
    fn store(&self) -> Arc<TaskStore> {
        Arc::clone(&self.kernel.lock().unwrap().agents.tasks)
    }

    fn agents(&self) -> AgentAdmission {
        self.kernel.lock().unwrap().agents.clone()
    }

    fn wiring(&self, model: &Arc<Model>) -> Wiring {
        let mut authority = common::authority(Some("openai")).unwrap();
        authority.agent_prefix = Some(AGENT_PREFIX.into());
        Wiring {
            live: Arc::new(maknae_kernel::LiveConfig::new(
                Default::default(),
                Some(authority),
            )),
            egress: model.clone(),
        }
    }

    fn partition(&self) -> PathBuf {
        self.root.join(format!("tasks/users/{}", self.me))
    }

    async fn ask(&self, verb: Verb) -> RespResult {
        let session = maknae_kernel::SessionRecord::for_test(self.me, Some(self.user.clone()))
            .with_session_id(629);
        let gate = maknae_kernel::FactsGate::allow_as(
            Some(self.user.clone()),
            Some(PathBuf::from(&*self.root)),
        );
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let served = maknae_kernel::handle_with_attempt_caps(
            server,
            Some("spiffe://d/plane/cli".into()),
            Arc::new(session),
            gate,
            Arc::clone(&self.records),
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
            self.agents(),
        );
        let serving = tokio::spawn(served);
        let body = maknae_proto::encode_request(&maknae_proto::Request {
            task: None,
            protocol_version: maknae_proto::PROTOCOL_VERSION,
            verb,
        })
        .unwrap();
        common::write_frame(&mut client, &body).await.unwrap();
        let frame = common::read_frame(&mut client, 1 << 20)
            .await
            .expect("an answer");
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(5), serving).await;
        maknae_proto::decode_response(&frame).unwrap().result
    }

    async fn submit(&self, prompt: &str) -> TaskId {
        let verb = Verb::TaskSubmit {
            task: TaskSubmission {
                schema: maknae_proto::TASK_SCHEMA.into(),
                version: maknae_proto::TASK_VERSION,
                agent: "hobi".into(),
                ask: maknae_proto::Ask::Prompt {
                    prompt: secret(prompt),
                },
                labels: maknae_proto::Labels {},
            },
        };
        match self.ask(verb).await {
            RespResult::Ok(Payload::TaskAccepted(v)) => v.task.to_id(),
            other => panic!("submit refused: {other:?}"),
        }
    }

    /// The tasker's reports, oldest first: (task, close, text).
    async fn collected(&self) -> Vec<(TaskId, Option<TaskClose>, String)> {
        match self
            .ask(Verb::TaskCollect {
                agent: "hobi".into(),
                after: None,
            })
            .await
        {
            RespResult::Ok(Payload::TaskReports(page)) => page
                .entries
                .iter()
                .map(|e| (e.task.to_id(), e.close, e.text.0.to_string()))
                .collect(),
            other => panic!("collect: {other:?}"),
        }
    }

    fn state(&self, id: &TaskId) -> TaskState {
        self.store().record(id).expect("a task record").state
    }

    fn snapshot(&self) -> Vec<maknae_audit_append::AuditRecord> {
        self.records.snapshot()
    }
}

struct Wiring {
    live: Arc<maknae_kernel::LiveConfig>,
    egress: Arc<dyn maknae_kernel::Egress>,
}

/// One connection to the kernel's agent channel per dial, as the agent socket gives.
struct KernelDial {
    kernel: Arc<Mutex<Kernel>>,
    pdp: Arc<maknae_kernel::Composition<maknae_authz_basic::HermeticAuthorizer>>,
    cfg: maknae_config::TransportConfig,
    home: PathBuf,
    wiring: Wiring,
    conversations: Arc<dyn maknae_kernel::ConversationStore>,
    records: Arc<Records>,
}

/// The client end; a delegated descriptor joins the connection's queue, as SCM_RIGHTS does.
struct Conn {
    stream: tokio::io::DuplexStream,
    delegated: maknae_io::DelegatedFds,
}

impl tokio::io::AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl maknae_loop::send::Wire for Conn {
    fn arm(&self, fd: std::os::fd::OwnedFd) -> bool {
        self.delegated.push(fd);
        true
    }
}

impl Dial for KernelDial {
    type Stream = Conn;
    fn dial(&self) -> impl Future<Output = Result<Conn, maknae_vault::VaultError>> + Send {
        let (agents, garble) = {
            let mut k = self.kernel.lock().unwrap();
            if !k.connects() {
                return std::future::ready(Err(maknae_vault::VaultError::Io {
                    path: "maknaed-agent.sock".into(),
                    source: std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
                }));
            }
            let garble = k
                .garble
                .load(Ordering::SeqCst)
                .then(|| Arc::clone(&k.garble));
            let relay = garble.is_some() || std::mem::take(&mut k.cut);
            (k.agents.clone(), relay.then_some(garble))
        };
        let mut session = maknae_kernel::SessionRecord::for_test(HOBI_UID, Some("hobi-svc".into()))
            .with_session_id(629);
        session.admission = maknae_kernel::Admission::EnrolledAgent;
        session.channel = maknae_kernel::SessionChannel::Agent {
            agent: maknae_config::AgentId::parse("hobi").unwrap(),
            leaf_expires: std::time::Instant::now() + Duration::from_secs(3600),
        };
        let gate = maknae_kernel::FactsGate::for_test(
            Arc::new(AgentFacts {
                user: "hobi-svc".into(),
                dir: self.home.clone(),
            }),
            Duration::from_secs(5),
        );
        let delegated = maknae_io::DelegatedFds::new(4);
        let (client, server) = tokio::io::duplex(1 << 20);
        let (kernel_end, relay) = match garble {
            Some(flag) => {
                let (inner, kernel_end) = tokio::io::duplex(1 << 20);
                (kernel_end, Some((server, inner, flag)))
            }
            None => (server, None),
        };
        let served = maknae_kernel::handle_with_attempt_caps(
            kernel_end,
            Some("spiffe://d/agent/hobi".into()),
            Arc::new(session),
            gate,
            Arc::clone(&self.records),
            self.cfg.clone(),
            serde_json::json!({}),
            Arc::clone(&self.pdp),
            Arc::clone(&self.wiring.live),
            Arc::new("basic+ceiling".into()),
            Arc::new("US".into()),
            Arc::new("ml-dsa-87".to_string()),
            Arc::new(None),
            Arc::clone(&self.wiring.egress),
            Duration::from_secs(2),
            delegated.clone(),
            common::no_baseline(),
            maknae_kernel::AttemptCaps::default(),
            Arc::clone(&self.conversations),
            agents,
        );
        tokio::spawn(served);
        if let Some((outer, inner, garble)) = relay {
            tokio::spawn(relay_one_exchange(outer, inner, garble));
        }
        std::future::ready(Ok(Conn {
            stream: client,
            delegated,
        }))
    }
}

/// Relays one request and its answer, then ends the connection; with `garble`, a
/// delivered task's bytes are replaced with junk.
async fn relay_one_exchange(
    mut outer: tokio::io::DuplexStream,
    mut inner: tokio::io::DuplexStream,
    garble: Option<Arc<AtomicBool>>,
) {
    let caps = maknae_proto::FrameCaps {
        control: 1 << 26,
        attempt: 1 << 26,
        prompt: 1 << 26,
    };
    let Ok((class, body)) = maknae_proto::read_frame_zeroizing(&mut outer, &caps).await else {
        return;
    };
    maknae_proto::write_frame(&mut inner, class, &body)
        .await
        .unwrap();
    let Ok((class, body)) = maknae_proto::read_frame_zeroizing(&mut inner, &caps).await else {
        return;
    };
    let mut resp = maknae_proto::decode_response(&body).unwrap();
    if let (Some(flag), RespResult::Ok(Payload::TaskDelivered(d))) = (garble, &mut resp.result) {
        flag.store(false, Ordering::SeqCst);
        d.signed = maknae_proto::Bytes::new(Zeroizing::new(b"sentinel-629-not-a-task".to_vec()));
    }
    let body = maknae_proto::encode_response(&resp).unwrap();
    let _ = maknae_proto::write_frame(&mut outer, class, &body).await;
}

/// The agent's Vault login: a wrapping token for whatever path it is asked for.
struct Vault;

impl WrappedRead for Vault {
    fn read_wrapped(
        &self,
        _kv_mount: &str,
        secret_path: &str,
    ) -> impl Future<Output = Result<maknae_vault::WrappedSecret, maknae_vault::VaultError>> + Send
    {
        let path = secret_path.to_string();
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
    }
}

/// The production persona checks over the test's home; no `/etc` persona.
struct Personas(PersonaFiles);

impl PersonaRead for Personas {
    fn etc(&mut self) -> Result<Option<SecretText>, String> {
        Ok(None)
    }
    fn present(&mut self, rel: &Path) -> Result<bool, String> {
        self.0.present(rel)
    }
    fn home(&self) -> &Path {
        self.0.home()
    }
}

/// A test clock: a sleep advances the agent's time at once, yields, and lets the
/// kernel's own clock follow when the test asks it to.
#[derive(Clone)]
struct Ticks {
    now: Arc<Mutex<Duration>>,
    slept: Arc<Mutex<Vec<Duration>>>,
    on_sleep: Arc<Mutex<Option<Hook<Duration>>>>,
}

impl Ticks {
    fn new() -> Self {
        Ticks {
            now: Arc::new(Mutex::new(Duration::ZERO)),
            slept: Arc::new(Mutex::new(Vec::new())),
            on_sleep: Arc::new(Mutex::new(None)),
        }
    }
    fn slept(&self) -> Vec<Duration> {
        self.slept.lock().unwrap().clone()
    }
}

impl Clock for Ticks {
    fn now(&self) -> Duration {
        *self.now.lock().unwrap()
    }
    fn sleep(&mut self, d: Duration) -> impl Future<Output = ()> + Send {
        *self.now.lock().unwrap() += d;
        self.slept.lock().unwrap().push(d);
        if let Some(hook) = self.on_sleep.lock().unwrap().as_mut() {
            hook(d);
        }
        tokio::time::sleep(Duration::from_millis(2))
    }
}

type Plane = AgentPlane<AgentKeys<Vault>, Personas, KernelDial>;

struct Daemon {
    shutdown: ShutdownHandle,
    events: Arc<Mutex<Vec<DriverEvent>>>,
    ticks: Ticks,
    running: tokio::task::JoinHandle<()>,
}

impl Daemon {
    fn endings(&self) -> Vec<(Option<TaskId>, Ending)> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                DriverEvent::Ended { task, ending } => Some((*task, *ending)),
                _ => None,
            })
            .collect()
    }

    /// The task's ending is noted after its report is acknowledged and before its close.
    fn ended(&self, id: &TaskId) -> bool {
        self.endings().iter().any(|(t, _)| t.as_ref() == Some(id))
    }

    fn close_failures(&self) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, DriverEvent::CloseFailed(_)))
            .count()
    }

    /// Waits until `done` holds, up to 20 s of wall time.
    async fn until(&self, what: &str, mut done: impl FnMut(&Self) -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !done(self) {
            assert!(
                std::time::Instant::now() < deadline,
                "{what}: never happened; endings {:?}",
                self.endings()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn stop(self) {
        self.shutdown.shut_down();
        tokio::time::timeout(Duration::from_secs(20), self.running)
            .await
            .expect("the driver stops")
            .unwrap();
    }
}

fn plane(w: &World, model: &Arc<Model>, events: &Arc<Mutex<Vec<DriverEvent>>>) -> Plane {
    let home = PathBuf::from(&*w.root);
    let dial = KernelDial {
        kernel: Arc::clone(&w.kernel),
        pdp: Arc::clone(&w.pdp),
        cfg: w.cfg.clone(),
        home: home.clone(),
        wiring: w.wiring(model),
        conversations: Arc::clone(&w.conversations),
        records: Arc::clone(&w.records),
    };
    let hobi = maknae_config::AgentId::parse("hobi").unwrap();
    let recipient = maknae_seal::SealPrivateKey::generate().unwrap();
    let keys = AgentKeys::new(
        Arc::new(Vault),
        maknae_config::AgentProvider {
            provider: "openai".into(),
            model: common::TEST_MODEL.into(),
            key_subpath: "openai/hobi".into(),
            key_field: "api_key".into(),
            context_tokens: 128_000,
            output_tokens: None,
        },
        "maknae-kv".into(),
        AGENT_PREFIX.into(),
        hobi.clone(),
        recipient.public_key().clone(),
    );
    let lp = LoopPlane::with_dial(dial, w.cfg.clone(), None, w.cfg.prompt_max_bytes, keys);
    let seen = Arc::clone(events);
    AgentPlane::new(
        lp,
        TaskTrust {
            trust: w.ca.trust(),
            trust_domain: TRUST_DOMAIN.into(),
            agent: hobi,
        },
        Personas(PersonaFiles {
            config_dir: home.join("etc"),
            agent: maknae_config::AgentId::parse("hobi").unwrap(),
            home,
            owner: nix::unistd::geteuid().as_raw(),
        }),
        Box::new(move |e| seen.lock().unwrap().push(e)),
    )
}

const BUDGET: Budget = Budget {
    max_steps: 8,
    max_tool_calls_per_step: 4,
};

fn start(w: &World, model: &Arc<Model>) -> Daemon {
    start_with(w, model, Ticks::new(), BUDGET)
}

fn start_with(w: &World, model: &Arc<Model>, ticks: Ticks, budget: Budget) -> Daemon {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut driver = TaskDriver::new(
        plane(w, model, &events),
        ticks.clone(),
        DriverConfig {
            home: w.root.to_str().unwrap().to_string(),
            persona: PersonaMode::Own,
            budget,
            context: ContextBudget::new(128_000, None).unwrap(),
        },
    );
    let shutdown = driver.shutdown_handle();
    let running = tokio::spawn(async move { driver.run().await });
    Daemon {
        shutdown,
        events,
        ticks,
        running,
    }
}

fn records(w: &World, action: &str, reason: &str) -> Vec<maknae_audit_append::AuditRecord> {
    w.snapshot()
        .into_iter()
        .filter(|r| r.action == action && r.outcome.reason.contains(reason))
        .collect()
}

fn closed(w: &World) -> Vec<maknae_audit_append::AuditRecord> {
    records(w, "session.close", "conversation closed")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_carries_out_a_prompt_task_in_its_taskers_partition() {
    let _one = ONE_DAEMON.lock().await;
    let w = world("carries", HOBI_POLICY);
    let id = w.submit("sentinel-629-carry-prompt").await;
    let persona = w.root.join("persona.md");
    std::fs::write(&persona, "sentinel-629-home-persona").unwrap();
    std::fs::set_permissions(&persona, std::fs::Permissions::from_mode(0o600)).unwrap();
    let notes = w.partition().join("notes.md");
    let model = Model::script(vec![
        write_file("w1", notes.to_str().unwrap(), "sentinel-629-written"),
        answer("sentinel-629-answer"),
    ]);
    let d = start(&w, &model);
    d.until("the report", |d| d.ended(&id)).await;
    d.until("the conversation is closed", |d| {
        !closed(&w).is_empty() || d.close_failures() > 0
    })
    .await;
    assert_eq!(d.close_failures(), 0, "{:?}", d.events.lock().unwrap());
    let endings = d.endings();
    d.stop().await;
    assert_eq!(endings, vec![(Some(id), Ending::Answered)]);
    assert_eq!(
        std::fs::read_to_string(&notes).unwrap(),
        "sentinel-629-written"
    );
    let prompts = model.prompts();
    assert_eq!(prompts.len(), 2);
    let first = match &prompts[0][0] {
        Turn::User { content } => match &content[0] {
            ContentBlock::Text { text } => text.0.to_string(),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    };
    assert_eq!(
        first,
        "sentinel-629-home-persona\n\nsentinel-629-carry-prompt"
    );
    let persona_reads: Vec<_> = cited(&w, &id, "fs.read")
        .into_iter()
        .filter(|r| r.object.as_deref() == persona.to_str())
        .collect();
    assert!(
        persona_reads.iter().any(|r| r.outcome.result == "permit"),
        "the home persona is read through the kernel under the task: {persona_reads:?}"
    );
    let reports = w.collected().await;
    assert_eq!(reports, vec![(id, None, "sentinel-629-answer".to_string())]);
    let close = closed(&w);
    assert_eq!(close.len(), 1);
    assert_eq!(close[0].outcome.result, "permit");
    assert_eq!(close[0].subject.task_id, None, "the close is not cited");
    assert_eq!(close[0].subject.agent.as_deref(), Some("hobi"));
}

fn user_text(turn: &Turn) -> Option<String> {
    match turn {
        Turn::User { content } => match content.first() {
            Some(ContentBlock::Text { text }) => Some(text.0.to_string()),
            _ => None,
        },
        _ => None,
    }
}

/// The audit records of requests that cite `id`, by action.
fn cited(w: &World, id: &TaskId, action: &str) -> Vec<maknae_audit_append::AuditRecord> {
    let id = id.to_string();
    w.snapshot()
        .into_iter()
        .filter(|r| r.action == action && r.subject.task_id.as_deref() == Some(id.as_str()))
        .collect()
}

fn deliveries(w: &World, id: &TaskId) -> usize {
    cited(w, id, "session.task")
        .iter()
        .filter(|r| r.outcome.reason == "delivered")
        .count()
}

fn reported(w: &World, id: &TaskId) -> bool {
    cited(w, id, "session.task")
        .iter()
        .any(|r| r.outcome.reason == "done")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_is_refused_what_its_policy_denies() {
    let _one = ONE_DAEMON.lock().await;
    let me = nix::unistd::geteuid().as_raw();
    let policy = HOBI_POLICY.replace(
        "  deny: []\n",
        &format!("  deny: [\"Write(~/tasks/users/{me}/sentinel-629-denied.md)\"]\n"),
    );
    let w = world("policy-denied", &policy);
    let id = w.submit("sentinel-629-denied-prompt").await;
    let denied = w.partition().join("sentinel-629-denied.md");
    let model = Model::script(vec![
        write_file("w1", denied.to_str().unwrap(), "sentinel-629-must-not-land"),
        answer("sentinel-629-denied-answer"),
    ]);
    let d = start(&w, &model);
    d.until("the report", |d| d.ended(&id)).await;
    d.stop().await;
    assert!(!denied.exists(), "the denied write landed");
    let writes = cited(&w, &id, "fs.write");
    assert_eq!(writes.len(), 1, "{writes:?}");
    assert_eq!(writes[0].outcome.result, "deny");
    assert_eq!(writes[0].subject.agent.as_deref(), Some("hobi"));
    assert_eq!(
        writes[0].outcome.reason,
        format!(
            "denied by agents.hobi.policy.permissions entry Write(~/tasks/users/{me}/sentinel-629-denied.md)"
        )
    );
    let results = tool_results(&model.prompts()[1]);
    assert_eq!(results.len(), 1);
    assert!(!results[0].starts_with("applied"), "{results:?}");
    assert_eq!(
        w.collected().await,
        vec![(id, None, "sentinel-629-denied-answer".to_string())]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_request_outside_its_taskers_partition_is_refused() {
    let _one = ONE_DAEMON.lock().await;
    let w = world("out-of-partition", HOBI_POLICY);
    let theirs = w.root.join("tasks/users/31337");
    std::fs::create_dir_all(&theirs).unwrap();
    let secret_file = theirs.join("notes.md");
    std::fs::write(&secret_file, "sentinel-629-another-taskers-notes").unwrap();
    let id = w.submit("sentinel-629-partition-prompt").await;
    let model = Model::script(vec![
        read_file("r1", secret_file.to_str().unwrap()),
        answer("sentinel-629-partition-answer"),
    ]);
    let d = start(&w, &model);
    d.until("the report", |d| d.ended(&id)).await;
    d.stop().await;
    let reads = cited(&w, &id, "fs.read");
    assert_eq!(reads.len(), 1, "{reads:?}");
    assert_eq!(reads[0].outcome.result, "deny");
    assert!(
        reads[0].outcome.reason.starts_with("partition: "),
        "{:?}",
        reads[0].outcome.reason
    );
    let results = tool_results(&model.prompts()[1]);
    assert!(
        results
            .iter()
            .all(|r| !r.contains("sentinel-629-another-taskers-notes")),
        "{results:?}"
    );
    assert_eq!(
        w.collected().await,
        vec![(id, None, "sentinel-629-partition-answer".to_string())]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_resumes_its_working_task_after_a_kernel_restart() {
    let _one = ONE_DAEMON.lock().await;
    let w = world("kernel-restart", HOBI_POLICY);
    let id = w.submit("sentinel-629-restart-prompt").await;
    let notes = w.partition().join("notes.md");
    let model = Model::script(vec![
        read_file("r1", notes.to_str().unwrap()),
        answer("sentinel-629-restart-answer"),
    ]);
    let kernel = Arc::clone(&w.kernel);
    *model.on_prompt.lock().unwrap() = Some(Box::new(move |n| {
        if n == 1 {
            kernel.lock().unwrap().fail(1, 1, true);
        }
    }));
    std::fs::create_dir_all(w.partition()).unwrap();
    std::fs::write(&notes, "sentinel-629-notes").unwrap();
    let d = start(&w, &model);
    d.until("the report", |d| d.ended(&id)).await;
    let endings = d.endings();
    let slept = d.ticks.slept();
    d.stop().await;
    assert_eq!(w.kernel.lock().unwrap().restarts, 1);
    assert_eq!(endings, vec![(Some(id), Ending::Answered)]);
    assert!(
        slept.contains(&maknae_agent::task_driver::BACKOFF_FIRST),
        "{slept:?}"
    );
    assert_eq!(deliveries(&w, &id), 1, "the task was handed out once");
    let prompts = model.prompts();
    assert_eq!(
        prompts.len(),
        2,
        "the step lost to the restart is the only one re-sent"
    );
    assert_eq!(
        user_text(&prompts[1][0]).as_deref(),
        Some("sentinel-629-restart-prompt"),
        "the resumed session is the same conversation"
    );
    assert!(tool_results(&prompts[1])
        .iter()
        .any(|r| r.contains("sentinel-629-notes")));
    assert_eq!(
        w.collected().await,
        vec![(id, None, "sentinel-629-restart-answer".to_string())]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_kernel_restart_mid_step_resumes_the_same_task_with_the_lost_tool_call_closed_as_outcome_unknown(
) {
    let _one = ONE_DAEMON.lock().await;
    let w = world("mid-step", HOBI_POLICY);
    let id = w.submit("sentinel-629-mid-step-prompt").await;
    let lost = w.partition().join("sentinel-629-lost.md");
    let model = Model::script(vec![
        write_file("w1", lost.to_str().unwrap(), "sentinel-629-lost-content"),
        answer("sentinel-629-mid-step-answer"),
    ]);
    let kernel = Arc::clone(&w.kernel);
    *model.on_prompt.lock().unwrap() = Some(Box::new(move |n| {
        if n == 1 {
            let mut k = kernel.lock().unwrap();
            k.cut = true;
            k.fail(1, 1, true);
        }
    }));
    let d = start(&w, &model);
    d.until("the report", |d| d.ended(&id)).await;
    let endings = d.endings();
    d.stop().await;
    assert_eq!(w.kernel.lock().unwrap().restarts, 1);
    assert_eq!(endings, vec![(Some(id), Ending::Answered)]);
    assert_eq!(deliveries(&w, &id), 1);
    let granted = cited(&w, &id, "fs.write");
    assert!(
        granted.iter().any(|r| r.outcome.result == "permit"),
        "the write was granted before the kernel went: {granted:?}"
    );
    let prompts = model.prompts();
    assert_eq!(prompts.len(), 2);
    let results = tool_results(&prompts[1]);
    assert_eq!(results.len(), 1);
    assert!(results[0].starts_with("outcome unknown"), "{results:?}");
    assert_eq!(
        w.collected().await,
        vec![(id, None, "sentinel-629-mid-step-answer".to_string())]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_task_held_mid_work_answers_held_to_the_uncited_heartbeat_and_is_not_reported() {
    let _one = ONE_DAEMON.lock().await;
    let w = world("held", HOBI_POLICY);
    let id = w.submit("sentinel-629-held-prompt").await;
    let notes = w.partition().join("notes.md");
    let model = Model::script(vec![read_file("r1", notes.to_str().unwrap())]);
    let ticks = Ticks::new();
    let (now, pdp, view, kernel, bindings, user) = (
        Arc::clone(&ticks.now),
        Arc::clone(&w.pdp),
        Arc::new(maknae_kernel::SnapshotEnrollment(Arc::clone(&w.pdp))),
        Arc::clone(&w.kernel),
        maknae_authz_basic::PolicyPaths::in_dir(&w.root).bindings,
        w.user.clone(),
    );
    *model.on_prompt.lock().unwrap() = Some(Box::new(move |_| {
        *now.lock().unwrap() += maknae_agent::task_driver::HEARTBEAT_EVERY;
        common::write_0640(
            &bindings,
            &format!("schema_version: 1\nbindings:\n  adversary: [\"{user}\"]\n"),
        );
        pdp.baseline().reload_from_file().unwrap();
        let tasks = Arc::clone(&kernel.lock().unwrap().agents.tasks);
        tasks.retain_enrolled(&*view);
    }));
    let d = start_with(&w, &model, ticks, BUDGET);
    d.until("the hold ends the task", |d| !d.endings().is_empty())
        .await;
    let endings = d.endings();
    d.stop().await;
    assert_eq!(endings, vec![(Some(id), Ending::Held)]);
    assert_eq!(w.state(&id), TaskState::Held);
    assert!(!reported(&w, &id));
    assert!(
        cited(&w, &id, "fs.read").is_empty(),
        "no file request is made under a held task"
    );
    let beats: Vec<_> = records(&w, "session.task", "the task is held");
    assert_eq!(beats.len(), 1, "{beats:?}");
    assert_eq!(beats[0].outcome.result, "permit");
    assert!(closed(&w).is_empty(), "a held task's conversation is kept");
    assert_eq!(model.prompts().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_that_stops_without_an_answer_is_reported_stopped_and_the_next_task_follows() {
    let _one = ONE_DAEMON.lock().await;
    let w = world("no-answer", HOBI_POLICY);
    let first = w.submit("sentinel-629-first-prompt").await;
    let second = w.submit("sentinel-629-second-prompt").await;
    let notes = w.partition().join("notes.md");
    let model = Model::script(vec![
        read_file("r1", notes.to_str().unwrap()),
        answer("sentinel-629-second-answer"),
    ]);
    let d = start_with(
        &w,
        &model,
        Ticks::new(),
        Budget {
            max_steps: 1,
            max_tool_calls_per_step: 4,
        },
    );
    d.until("both reports", |d| d.ended(&first) && d.ended(&second))
        .await;
    let endings = d.endings();
    d.stop().await;
    assert_eq!(
        endings,
        vec![
            (Some(first), Ending::Stopped("step-budget")),
            (Some(second), Ending::Answered)
        ]
    );
    assert_eq!(
        w.collected().await,
        vec![
            (first, None, "stopped: step-budget".to_string()),
            (second, None, "sentinel-629-second-answer".to_string())
        ]
    );
    assert_eq!(closed(&w).len(), 2, "each conversation is closed");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_restarted_mid_task_reports_it_stopped_and_does_not_rerun_it() {
    let _one = ONE_DAEMON.lock().await;
    let w = world("agent-restart", HOBI_POLICY);
    let id = w.submit("sentinel-629-agent-restart-prompt").await;
    let notes = w.partition().join("notes.md");
    let model = Model::script(vec![read_file("r1", notes.to_str().unwrap())]);
    let shutdown: Arc<Mutex<Option<ShutdownHandle>>> = Arc::new(Mutex::new(None));
    let stopping = Arc::clone(&shutdown);
    *model.on_prompt.lock().unwrap() = Some(Box::new(move |_| {
        stopping.lock().unwrap().as_ref().unwrap().shut_down();
    }));
    let first = start(&w, &model);
    *shutdown.lock().unwrap() = Some(first.shutdown.clone());
    first
        .until("the first daemon ends", |d| !d.endings().is_empty())
        .await;
    let before = first.endings();
    first.stop().await;
    assert_eq!(before, vec![(Some(id), Ending::Shutdown)]);
    assert_eq!(w.state(&id), TaskState::Working);
    assert!(!reported(&w, &id));

    let second = start(&w, &model);
    second.until("the report", |d| d.ended(&id)).await;
    let after = second.endings();
    second.stop().await;
    assert_eq!(after, vec![(Some(id), Ending::Restarted)]);
    assert_eq!(model.prompts().len(), 1, "the task is never re-run");
    assert_eq!(
        w.collected().await,
        vec![(id, None, maknae_agent::task_driver::RESTARTED.to_string())]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_undecodable_delivery_lapses_to_agent_lost_under_the_real_sweep_and_the_next_task_follows(
) {
    let _one = ONE_DAEMON.lock().await;
    let w = world("undecodable", HOBI_POLICY);
    let lost = w.submit("sentinel-629-undecodable-prompt").await;
    let next = w.submit("sentinel-629-next-prompt").await;
    w.kernel
        .lock()
        .unwrap()
        .garble
        .store(true, Ordering::SeqCst);
    let model = Model::script(vec![answer("sentinel-629-next-answer")]);
    let ticks = Ticks::new();
    let (clock, kernel) = (Arc::clone(&w.clock), Arc::clone(&w.kernel));
    *ticks.on_sleep.lock().unwrap() = Some(Box::new(move |d| {
        let mut left = d;
        while !left.is_zero() {
            let step = left.min(SWEEP_EVERY);
            clock.set(maknae_kernel::Clock::now_secs(&*clock) + step.as_secs() as i64);
            let tasks = Arc::clone(&kernel.lock().unwrap().agents.tasks);
            tasks.sweep();
            left -= step;
        }
    }));
    let d = start_with(&w, &model, ticks, BUDGET);
    d.until("the next task's report", |d| d.ended(&next)).await;
    let endings = d.endings();
    let slept = d.ticks.slept();
    d.stop().await;
    assert_eq!(
        endings,
        vec![(None, Ending::Undecodable), (Some(next), Ending::Answered)]
    );
    assert!(
        slept.contains(&maknae_agent::task_driver::UNDECODABLE_WAIT),
        "{slept:?}"
    );
    let rec = w.store().record(&lost).unwrap();
    assert_eq!(
        (rec.state, rec.close),
        (TaskState::Closed, Some(TaskClose::AgentLost))
    );
    let agent_cited: Vec<_> = w
        .snapshot()
        .into_iter()
        .filter(|r| {
            r.subject.task_id.as_deref() == Some(lost.to_string().as_str())
                && r.subject.agent.as_deref() == Some("hobi")
                && r.action != "session.task"
        })
        .collect();
    assert!(
        agent_cited.is_empty(),
        "the undecodable task was never cited: {agent_cited:?}"
    );
    assert_eq!(
        w.collected().await,
        vec![
            (lost, Some(TaskClose::AgentLost), String::new()),
            (next, None, "sentinel-629-next-answer".to_string())
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_uncited_close_after_a_report_is_permitted_and_a_policy_refused_close_is_not_fatal() {
    let _one = ONE_DAEMON.lock().await;
    let unclosable = HOBI_POLICY.replace("\"session.close\", ", "");
    assert_ne!(unclosable, HOBI_POLICY);
    let w = world("close", &unclosable);
    let first = w.submit("sentinel-629-close-first").await;
    let second = w.submit("sentinel-629-close-second").await;
    let model = Model::script(vec![
        answer("sentinel-629-close-first-answer"),
        answer("sentinel-629-close-second-answer"),
    ]);
    let d = start(&w, &model);
    d.until("both reports", |d| d.ended(&first) && d.ended(&second))
        .await;
    d.until("both closes", |d| d.close_failures() == 2).await;
    d.stop().await;
    let refused = records(&w, "session.close", "session.close is not in");
    assert_eq!(refused.len(), 2, "{refused:?}");
    assert!(refused
        .iter()
        .all(|r| r.outcome.result == "deny" && r.subject.task_id.is_none()));
    assert_eq!(w.collected().await.len(), 2);
}
