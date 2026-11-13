//! The real Plane: one authenticated client, one connection per verb. Needs a
//! live daemon, Vault and certificates, so it is T3; every decision it feeds
//! is T1 in `maknae_agent::wire`.
use crate::keys::{AgentKeys, KeySupply};
use crate::send::{send_via, write_request, Wire};
use maknae_agent::plane::{
    ListOutcome, Plane, PlaneError, ReadBasis, ReadOutcome, StatOutcome, WriteOutcome,
};
use maknae_agent::wire::{
    check_for, close_outcome, list_outcome, open_outcome, prompt_outcome, read_outcome,
    stat_outcome, write_outcome, WireOutcome,
};
use maknae_config::AgentId;
use maknae_config::TransportConfig;
use maknae_proto::{ConversationId, ConversationView, ProviderChoice, TaskId, Turn, Verb};
use maknae_vault::{
    AuthenticatedStream, PlaneClient, PlaneConnector, PlaneSubject, TrustBundle, VaultError,
};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

/// A wrapped key whose frame was refused as too large before it was sent, so it is unconsumed.
pub struct Spare {
    conversation: String,
    minted_at: u64,
    choice: ProviderChoice,
}

pub const SPARE_MAX_AGE_SECS: u64 = maknae_vault::USER_KEY_WRAP_TTL.as_secs() / 2;

fn take_spare(spare: &mut Option<Spare>, conversation: &str, now: u64) -> Option<Spare> {
    let s = spare.take()?;
    (s.conversation == conversation && now <= s.minted_at + SPARE_MAX_AGE_SECS).then_some(s)
}

/// Measured against the frame cap before sending (ADR-0023 d7).
pub(crate) fn frame_fits(verb: &Verb, cap: usize) -> bool {
    maknae_proto::encode_request_zeroizing(
        &maknae_proto::Request {
            task: None,
            protocol_version: maknae_proto::PROTOCOL_VERSION,
            verb: verb.clone(),
        },
        cap,
    )
    .is_ok()
}

fn now_unix() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "the system clock reads before 1970; set the clock, then retry".to_string())
}

/// Opens one connection to the kernel. Every verb dials its own: the kernel
/// binds a connection's audit task once (send.rs).
pub trait Dial: Send + Sync {
    type Stream: Wire;
    fn dial(&self) -> impl Future<Output = Result<Self::Stream, VaultError>> + Send;
}

pub struct PlaneDial {
    socket: PathBuf,
    client: Arc<PlaneClient>,
    trust: Arc<TrustBundle>,
}

impl Dial for PlaneDial {
    type Stream = AuthenticatedStream;
    fn dial(&self) -> impl Future<Output = Result<AuthenticatedStream, VaultError>> + Send {
        PlaneConnector::connect(&self.socket, &self.client, &self.trust)
    }
}

/// What a loop and its task client share: the way to the kernel and the cited task.
pub(crate) struct Link<D> {
    dial: D,
    transport: TransportConfig,
    cite: Mutex<Option<TaskId>>,
}

/// A claim or heartbeat never cites (the kernel ends a connection whose cited task
/// is not `Working`); every other verb a loop sends carries the cite.
fn cite_for(verb: &Verb, cited: Option<TaskId>) -> Option<TaskId> {
    match verb {
        Verb::TaskClaim { .. } => None,
        _ => cited,
    }
}

impl<D: Dial> Link<D> {
    fn cited(&self) -> Option<TaskId> {
        // A poisoned guard still holds a whole `Option<TaskId>`: it is only ever assigned.
        *self.cite.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn transport(&self) -> &TransportConfig {
        &self.transport
    }

    pub(crate) async fn send(
        &self,
        verb: Verb,
        content: Option<maknae_proto::Bytes>,
        check: crate::mutation::WriteCheck,
        diag: &mut (dyn FnMut(String) + Send),
    ) -> Result<crate::outcome::SentOutcome, String> {
        send_via(
            self.dial.dial(),
            cite_for(&verb, self.cited()),
            verb,
            content,
            check,
            &self.transport,
            diag,
        )
        .await
    }
}

/// Each loop owns its client: one loop's token lifecycle must not reach another's.
pub struct LoopPlane<K: KeySupply, D: Dial = PlaneDial> {
    link: Arc<Link<D>>,
    output_tokens: Option<u64>,
    write_max: usize,
    keys: K,
    spare: Option<Spare>,
    diagnostics: Vec<String>,
}

impl<K: KeySupply> LoopPlane<K, PlaneDial> {
    pub fn new(
        transport: TransportConfig,
        client: PlaneClient,
        trust: Arc<TrustBundle>,
        output_tokens: Option<u64>,
        write_max: usize,
        keys: K,
    ) -> Self {
        let socket = transport.socket_path.clone();
        Self::over(
            transport,
            socket,
            Arc::new(client),
            trust,
            output_tokens,
            write_max,
            keys,
        )
    }

    fn over(
        transport: TransportConfig,
        socket: PathBuf,
        client: Arc<PlaneClient>,
        trust: Arc<TrustBundle>,
        output_tokens: Option<u64>,
        write_max: usize,
        keys: K,
    ) -> Self {
        let dial = PlaneDial {
            socket,
            client,
            trust,
        };
        Self::dialled(dial, transport, output_tokens, write_max, keys)
    }

    pub fn into_client(self) -> Arc<PlaneClient> {
        Arc::clone(&self.link.dial.client)
    }
}

/// Refuses a client whose leaf would not be `agent`'s own.
fn agent_subject(subject: &PlaneSubject, agent: &AgentId) -> Result<(), String> {
    match subject {
        PlaneSubject::Agent(id) if id == agent => Ok(()),
        PlaneSubject::Agent(id) => Err(format!(
            "the plane client is agent {}'s, not agent {}'s",
            id.as_str(),
            agent.as_str()
        )),
        PlaneSubject::Fixed(plane) => Err(format!(
            "the plane client is the {plane:?} plane's, not agent {}'s",
            agent.as_str()
        )),
    }
}

impl LoopPlane<AgentKeys, PlaneDial> {
    /// The agent's loop: the kernel's agent socket, under the leaf of the same
    /// client its keys read with.
    pub fn for_agent(
        transport: TransportConfig,
        trust: Arc<TrustBundle>,
        output_tokens: Option<u64>,
        write_max: usize,
        keys: AgentKeys,
    ) -> Result<Self, String> {
        let client = Arc::clone(keys.reader());
        agent_subject(client.subject(), keys.agent())?;
        let socket = transport.agent_socket_path.clone();
        Ok(Self::over(
            transport,
            socket,
            client,
            trust,
            output_tokens,
            write_max,
            keys,
        ))
    }
}

impl<K: KeySupply, D: Dial> LoopPlane<K, D> {
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_dial(
        dial: D,
        transport: TransportConfig,
        output_tokens: Option<u64>,
        write_max: usize,
        keys: K,
    ) -> Self {
        Self::dialled(dial, transport, output_tokens, write_max, keys)
    }

    fn dialled(
        dial: D,
        transport: TransportConfig,
        output_tokens: Option<u64>,
        write_max: usize,
        keys: K,
    ) -> Self {
        LoopPlane {
            link: Arc::new(Link {
                dial,
                transport,
                cite: Mutex::new(None),
            }),
            output_tokens,
            write_max,
            keys,
            spare: None,
            diagnostics: vec![],
        }
    }

    #[cfg(test)]
    pub(crate) fn link_for_test(&self) -> &D {
        &self.link.dial
    }

    /// Every later file, session and report request carries `task` until it is replaced.
    pub fn cite(&self, task: Option<TaskId>) {
        *self
            .link
            .cite
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = task;
    }

    pub fn tasks(&self) -> crate::task::TaskClient<D> {
        crate::task::TaskClient::over(Arc::clone(&self.link))
    }

    /// A whole-file read that belongs to no conversation, carrying the cite.
    pub async fn read_whole(&mut self, path: &str) -> ReadOutcome {
        let diagnostics = &mut self.diagnostics;
        read_outcome(
            self.link
                .send(
                    Verb::Read {
                        path: path.to_string(),
                        conversation: None,
                        page: Some(maknae_proto::WHOLE_FILE),
                    },
                    None,
                    crate::mutation::WriteCheck::Unchecked,
                    &mut |l| diagnostics.push(l),
                )
                .await
                .map(WireOutcome::from),
        )
    }

    /// The directory is created mode 0700, as every subject-side mkdir is.
    pub async fn mkdir(&mut self, path: &str, parents: bool) -> WriteOutcome {
        let diagnostics = &mut self.diagnostics;
        write_outcome(
            self.link
                .send(
                    Verb::FsMkdir {
                        path: path.to_string(),
                        parents,
                        components: Vec::new(),
                    },
                    None,
                    crate::mutation::WriteCheck::Unchecked,
                    &mut |l| diagnostics.push(l),
                )
                .await
                .map(WireOutcome::from),
        )
    }
}

impl<K: KeySupply, D: Dial> Plane for LoopPlane<K, D> {
    async fn open(
        &mut self,
        cwd: &std::path::Path,
        sensitive: &[String],
    ) -> Result<ConversationId, PlaneError> {
        let cwd = cwd.to_str().ok_or_else(|| {
            PlaneError::Transport("the working directory is not valid UTF-8".into())
        })?;
        let diagnostics = &mut self.diagnostics;
        open_outcome(
            self.link
                .send(
                    Verb::SessionNew {
                        cwd: cwd.into(),
                        sensitive: sensitive.to_vec(),
                    },
                    None,
                    crate::mutation::WriteCheck::Unchecked,
                    &mut |l| diagnostics.push(l),
                )
                .await
                .map(WireOutcome::from),
        )
    }
    async fn close(
        &mut self,
        conversation: &ConversationId,
    ) -> Result<ConversationView, PlaneError> {
        let diagnostics = &mut self.diagnostics;
        close_outcome(
            conversation,
            self.link
                .send(
                    Verb::SessionClose {
                        conversation: conversation.clone(),
                    },
                    None,
                    crate::mutation::WriteCheck::Unchecked,
                    &mut |l| diagnostics.push(l),
                )
                .await
                .map(WireOutcome::from),
        )
    }
    async fn prompt(
        &mut self,
        conversation: &str,
        turns: &[Turn],
    ) -> Result<maknae_proto::PromptReply, PlaneError> {
        let mut verb = Verb::SessionPrompt {
            conversation: conversation.to_string(),
            turns: turns.to_vec(),
            output_tokens: self.output_tokens,
            choice: None,
        };
        let cap = maknae_proto::prompt_request_cap(self.link.transport.prompt_max_bytes);
        // Checked before the key is wrapped, so a retry after shedding reasoning costs no Vault call.
        if !frame_fits(&verb, cap) {
            return Err(PlaneError::FrameTooLarge);
        }
        let now = now_unix().map_err(PlaneError::Transport)?;
        let (choice, minted_at) = match take_spare(&mut self.spare, conversation, now) {
            Some(s) => (s.choice, s.minted_at),
            None => {
                let c = self
                    .keys
                    .choice(conversation, now)
                    .await
                    .map_err(PlaneError::Transport)?;
                (c, now)
            }
        };
        if let Verb::SessionPrompt { choice: c, .. } = &mut verb {
            *c = Some(choice);
        }
        if !frame_fits(&verb, cap) {
            if let Verb::SessionPrompt {
                choice: Some(choice),
                ..
            } = verb
            {
                self.spare = Some(Spare {
                    conversation: conversation.to_string(),
                    minted_at,
                    choice,
                });
            }
            return Err(PlaneError::FrameTooLarge);
        }
        let diagnostics = &mut self.diagnostics;
        prompt_outcome(
            self.link
                .send(
                    verb,
                    None,
                    crate::mutation::WriteCheck::Unchecked,
                    &mut |l| diagnostics.push(l),
                )
                .await
                .map(WireOutcome::from),
        )
    }
    async fn read(
        &mut self,
        conversation: &str,
        path: &str,
        page: maknae_proto::PageRequest,
    ) -> ReadOutcome {
        let diagnostics = &mut self.diagnostics;
        read_outcome(
            self.link
                .send(
                    Verb::Read {
                        path: path.to_string(),
                        conversation: Some(conversation.to_string()),
                        page: Some(page),
                    },
                    None,
                    crate::mutation::WriteCheck::Unchecked,
                    &mut |l| diagnostics.push(l),
                )
                .await
                .map(WireOutcome::from),
        )
    }
    async fn write(
        &mut self,
        conversation: &str,
        path: &str,
        content: &[u8],
        basis: ReadBasis,
    ) -> WriteOutcome {
        // The prompt-budget refusal is LOCAL and pre-send — nothing left
        // the process, nothing is on the trail, the file is untouched.
        let Ok((verb, content)) = write_request(
            path.to_string(),
            zeroize::Zeroizing::new(content.to_vec()),
            Some(conversation.to_string()),
            self.write_max,
        ) else {
            return WriteOutcome::NotSent;
        };
        let diagnostics = &mut self.diagnostics;
        let sent = self
            .link
            .send(verb, Some(content), check_for(basis), &mut |l| {
                diagnostics.push(l)
            })
            .await;
        if let Ok(crate::outcome::SentOutcome::NotAttempted { why }) = &sent {
            diagnostics.push(format!("write not performed: {why}; nothing was written"));
        }
        write_outcome(sent.map(WireOutcome::from))
    }
    async fn list(&mut self, conversation: &str, path: &str, after: Option<&str>) -> ListOutcome {
        let diagnostics = &mut self.diagnostics;
        list_outcome(
            self.link
                .send(
                    Verb::FsList {
                        path: path.to_string(),
                        after: after.map(str::to_string),
                        conversation: Some(conversation.to_string()),
                    },
                    None,
                    crate::mutation::WriteCheck::Unchecked,
                    &mut |l| diagnostics.push(l),
                )
                .await
                .map(WireOutcome::from),
        )
    }
    async fn stat(&mut self, conversation: &str, path: &str) -> StatOutcome {
        let diagnostics = &mut self.diagnostics;
        stat_outcome(
            self.link
                .send(
                    Verb::FsStat {
                        path: path.to_string(),
                        conversation: Some(conversation.to_string()),
                    },
                    None,
                    crate::mutation::WriteCheck::Unchecked,
                    &mut |l| diagnostics.push(l),
                )
                .await
                .map(WireOutcome::from),
        )
    }
    fn take_diagnostics(&mut self) -> Vec<String> {
        std::mem::take(&mut self.diagnostics)
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use maknae_proto::{FrameCaps, Request, RespResult, Response};
    use std::collections::VecDeque;

    impl Wire for tokio::io::DuplexStream {
        fn arm(&self, _fd: std::os::fd::OwnedFd) -> bool {
            false
        }
    }

    #[derive(Default)]
    pub struct Seen {
        pub requests: Vec<Request>,
        pub frames_per_connection: Vec<usize>,
    }

    /// Answers the first frame on each connection with the next scripted answer.
    #[derive(Default)]
    pub struct FakeKernel {
        answers: Mutex<VecDeque<RespResult>>,
        seen: Arc<Mutex<Seen>>,
        servers: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    }

    impl FakeKernel {
        pub fn answering(answers: Vec<RespResult>) -> Self {
            FakeKernel {
                answers: Mutex::new(answers.into()),
                ..Default::default()
            }
        }

        pub async fn finish(&self) -> Seen {
            let servers = std::mem::take(&mut *self.servers.lock().unwrap());
            for s in servers {
                s.await.unwrap();
            }
            std::mem::take(&mut *self.seen.lock().unwrap())
        }
    }

    impl Dial for FakeKernel {
        type Stream = tokio::io::DuplexStream;
        fn dial(&self) -> impl Future<Output = Result<tokio::io::DuplexStream, VaultError>> + Send {
            let (client, mut server) = tokio::io::duplex(1 << 16);
            let mut answer = self.answers.lock().unwrap().pop_front();
            let seen = Arc::clone(&self.seen);
            self.servers.lock().unwrap().push(tokio::spawn(async move {
                let caps = FrameCaps {
                    control: 1 << 26,
                    attempt: 1 << 26,
                    prompt: 1 << 26,
                };
                let mut frames = 0;
                while let Ok((class, body)) =
                    maknae_proto::read_frame_zeroizing(&mut server, &caps).await
                {
                    frames += 1;
                    let request = maknae_proto::decode_request(&body).unwrap();
                    seen.lock().unwrap().requests.push(request);
                    let Some(result) = answer.take() else {
                        break;
                    };
                    let reply = maknae_proto::encode_response(&Response {
                        protocol_version: maknae_proto::PROTOCOL_VERSION,
                        result,
                    })
                    .unwrap();
                    let _ = maknae_proto::write_frame(&mut server, class, &reply).await;
                }
                seen.lock().unwrap().frames_per_connection.push(frames);
            }));
            async move { Ok(client) }
        }
    }

    pub fn refused() -> RespResult {
        RespResult::Err(maknae_proto::ProtoError {
            code: maknae_proto::ProtoErrCode::Unauthorized,
            message: "sentinel-629-refused".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::SealedKey;

    struct FakeKeys;
    impl KeySupply for FakeKeys {
        async fn choice(&mut self, _c: &str, _now: u64) -> Result<ProviderChoice, String> {
            Err("unused".into())
        }
    }

    struct Keys;
    impl KeySupply for Keys {
        async fn choice(&mut self, _c: &str, _now: u64) -> Result<ProviderChoice, String> {
            Ok(a_choice())
        }
    }

    fn fake_plane(answers: Vec<maknae_proto::RespResult>) -> LoopPlane<Keys, fake::FakeKernel> {
        LoopPlane::with_dial(
            fake::FakeKernel::answering(answers),
            TransportConfig::default(),
            None,
            4096,
            Keys,
        )
    }

    fn user_turn() -> Vec<Turn> {
        vec![Turn::User {
            content: vec![maknae_proto::ContentBlock::Text {
                text: maknae_proto::SecretText(zeroize::Zeroizing::new("hello".into())),
            }],
        }]
    }

    const VERBS: [&str; 9] = [
        "open", "close", "read", "write", "mkdir", "list", "stat", "prompt", "report",
    ];

    async fn every_cited_verb(
        plane: &mut LoopPlane<Keys, fake::FakeKernel>,
        dir: &std::path::Path,
    ) {
        let d = dir.to_str().unwrap();
        let conversation = ConversationId::parse(&"a".repeat(32)).unwrap();
        let _ = plane.open(dir, &[]).await;
        let _ = plane.close(&conversation).await;
        let _ = plane
            .read("c", &format!("{d}/absent"), maknae_proto::WHOLE_FILE)
            .await;
        let _ = plane
            .write("c", &format!("{d}/new"), b"x", ReadBasis::Unread)
            .await;
        let _ = plane.mkdir(&format!("{d}/tasks/users/1000"), true).await;
        let _ = plane.list("c", d, None).await;
        let _ = plane.stat("c", d).await;
        let _ = plane.prompt("c", &user_turn()).await;
        let _ = plane
            .tasks()
            .report(maknae_proto::SecretText(zeroize::Zeroizing::new(
                "r".into(),
            )))
            .await;
    }

    #[tokio::test]
    async fn a_cited_task_is_stamped_on_every_request_until_uncited() {
        let dir = tempfile::TempDir::new().unwrap();
        let id = TaskId([0x62; 16]);
        let mut plane = fake_plane(vec![fake::refused(); 2 * VERBS.len()]);
        plane.cite(Some(id));
        every_cited_verb(&mut plane, dir.path()).await;
        plane.cite(None);
        every_cited_verb(&mut plane, dir.path()).await;
        let seen = plane.link.dial.finish().await;
        let sent: Vec<_> = seen
            .requests
            .iter()
            .map(|r| (verb_name(&r.verb), r.task))
            .collect();
        let all = |task| VERBS.map(|v| (v, task));
        assert_eq!(sent, [all(Some(id)), all(None)].concat());
    }

    #[tokio::test]
    async fn each_verb_opens_its_own_connection() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut plane = fake_plane(vec![fake::refused(); VERBS.len() + 2]);
        plane.cite(Some(TaskId([7; 16])));
        every_cited_verb(&mut plane, dir.path()).await;
        let tasks = plane.tasks();
        let _ = tasks.claim().await;
        let _ = tasks.heartbeat(0).await;
        drop(tasks);
        let seen = plane.link.dial.finish().await;
        assert_eq!(seen.requests.len(), VERBS.len() + 2);
        assert_eq!(seen.frames_per_connection, vec![1; VERBS.len() + 2]);
    }

    #[test]
    fn only_a_claim_or_heartbeat_goes_uncited() {
        let id = Some(TaskId([1; 16]));
        let text = || maknae_proto::SecretText(zeroize::Zeroizing::new("r".into()));
        for seen in [None, Some(0)] {
            let claim = Verb::TaskClaim {
                seen_follow_ups: seen,
            };
            assert_eq!(cite_for(&claim, id), None);
        }
        for verb in [
            Verb::TaskReport { text: text() },
            Verb::FsStat {
                path: "/p".into(),
                conversation: None,
            },
            Verb::SessionClose {
                conversation: ConversationId::parse(&"b".repeat(32)).unwrap(),
            },
        ] {
            assert_eq!(cite_for(&verb, id), id, "{verb:?}");
            assert_eq!(cite_for(&verb, None), None);
        }
    }

    fn pem() -> String {
        let params = maknae_crypto::rcgen::CertificateParams::new(vec!["ca.test".into()]).unwrap();
        let key = maknae_crypto::rcgen::KeyPair::generate_for(
            &maknae_crypto::rcgen::PKCS_ECDSA_P384_SHA384,
        )
        .unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    /// A real agent client: CA pins on disk, a dead Vault, never minted.
    fn agent_client(dir: &std::path::Path, agent: &str) -> PlaneClient {
        maknae_crypto::init().unwrap();
        std::fs::create_dir_all(dir.join("tls")).unwrap();
        for f in ["maknae-root-ca.crt", "maknae-int-ca.crt", "vault-ca.crt"] {
            std::fs::write(dir.join("tls").join(f), pem()).unwrap();
        }
        let login = maknae_vault::AgentLogin {
            config_dir: dir.to_path_buf(),
            addr: "https://127.0.0.1:1".into(),
            trust_domain: "dev-01".into(),
            pki_int_mount: maknae_vault::DEFAULT_PKI_INT_MOUNT.into(),
            plane_key: maknae_crypto::plane_key::PlaneKey::ALL[0],
            approle_mount: "agents-approle".into(),
            role_id: "agent-role".into(),
            agent: AgentId::parse(agent).unwrap(),
        };
        let secret = maknae_vault::AgentSecret::new(zeroize::Zeroizing::new("s".into()));
        PlaneClient::for_agent(&login, secret).unwrap()
    }

    fn agent_keys(client: PlaneClient, agent: &str) -> AgentKeys {
        AgentKeys::new(
            Arc::new(client),
            maknae_config::AgentProvider {
                provider: "openai".into(),
                model: "m".into(),
                key_subpath: "openai/main".into(),
                key_field: "api_key".into(),
                context_tokens: 128_000,
                output_tokens: None,
            },
            "maknae-kv".into(),
            "maknae/agents".into(),
            AgentId::parse(agent).unwrap(),
            maknae_seal::SealPrivateKey::generate()
                .unwrap()
                .public_key()
                .clone(),
        )
    }

    fn trust(dir: &std::path::Path) -> Arc<TrustBundle> {
        TrustBundle::from_pins(&[&maknae_vault::load_ca_pin(dir).unwrap()]).unwrap()
    }

    #[test]
    fn the_agent_loop_dials_the_agent_socket_with_its_keys_own_client() {
        let dir = tempfile::TempDir::new().unwrap();
        let keys = agent_keys(agent_client(dir.path(), "hobi"), "hobi");
        let reader = Arc::clone(keys.reader());
        let transport = TransportConfig {
            socket_path: "/run/maknae/sentinel-client.sock".into(),
            agent_socket_path: "/run/maknae/sentinel-agent.sock".into(),
            ..Default::default()
        };
        let plane =
            LoopPlane::for_agent(transport.clone(), trust(dir.path()), None, 4096, keys).unwrap();
        assert_eq!(plane.link.dial.socket, transport.agent_socket_path);
        assert!(Arc::ptr_eq(&plane.link.dial.client, &reader));
        let cli = LoopPlane::new(
            transport.clone(),
            agent_client(dir.path(), "hobi"),
            trust(dir.path()),
            None,
            4096,
            FakeKeys,
        );
        assert_eq!(cli.link.dial.socket, transport.socket_path);
    }

    #[test]
    fn the_agent_loop_refuses_a_client_that_is_not_its_agents() {
        let dir = tempfile::TempDir::new().unwrap();
        let keys = agent_keys(agent_client(dir.path(), "suga"), "hobi");
        let refused = LoopPlane::for_agent(
            TransportConfig::default(),
            trust(dir.path()),
            None,
            4096,
            keys,
        );
        assert!(
            matches!(&refused, Err(m) if m.contains("agent suga's, not agent hobi's")),
            "{:?}",
            refused.as_ref().err()
        );
        let hobi = AgentId::parse("hobi").unwrap();
        assert!(agent_subject(&PlaneSubject::Agent(hobi.clone()), &hobi).is_ok());
        for plane in [maknae_vault::Plane::Cli, maknae_vault::Plane::Kernel] {
            let got = agent_subject(&PlaneSubject::Fixed(plane), &hobi).unwrap_err();
            assert!(got.contains("not agent hobi's"), "{got}");
        }
    }

    fn verb_name(v: &Verb) -> &'static str {
        match v {
            Verb::SessionNew { .. } => "open",
            Verb::SessionClose { .. } => "close",
            Verb::Read { .. } => "read",
            Verb::FsWrite { .. } => "write",
            Verb::FsMkdir { .. } => "mkdir",
            Verb::FsList { .. } => "list",
            Verb::FsStat { .. } => "stat",
            Verb::SessionPrompt { .. } => "prompt",
            Verb::TaskClaim { .. } => "claim",
            Verb::TaskReport { .. } => "report",
            _ => "other",
        }
    }

    #[test]
    fn loop_plane_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<LoopPlane<FakeKeys>>();
    }

    #[test]
    fn the_loops_same_content_agrees_with_the_file_versions() {
        let base = maknae_io::FileVersion {
            dev: 1,
            ino: 2,
            size: 3,
            mtime: 4,
            mtime_nsec: 5,
            ctime: 6,
            ctime_nsec: 7,
        };
        let changed: [fn(&mut maknae_io::FileVersion); 7] = [
            |v| v.dev += 1,
            |v| v.ino += 1,
            |v| v.size += 1,
            |v| v.mtime += 1,
            |v| v.mtime_nsec += 1,
            |v| v.ctime += 1,
            |v| v.ctime_nsec += 1,
        ];
        for (i, change) in changed.iter().enumerate() {
            let mut v = base;
            change(&mut v);
            assert_eq!(
                maknae_agent::plane::same_content(&base.key(), &v.key()),
                base.same_content(&v),
                "field {i}"
            );
        }
    }

    #[test]
    fn frame_fits_is_the_encoders_cap_check() {
        let verb = |n: usize| Verb::SessionPrompt {
            conversation: "c".into(),
            turns: vec![Turn::User {
                content: vec![maknae_proto::ContentBlock::Text {
                    text: maknae_proto::SecretText(zeroize::Zeroizing::new("a".repeat(n))),
                }],
            }],
            output_tokens: None,
            choice: None,
        };
        assert!(frame_fits(&verb(10), 65_536));
        assert!(!frame_fits(&verb(70_000), 65_536));
    }

    #[test]
    fn the_prompt_frame_is_sized_before_the_key_is_wrapped() {
        let src = include_str!("plane.rs");
        let body = &src[src.find(concat!("async fn ", "prompt(")).unwrap()..];
        let fits = body.find(concat!("frame_fits(", "&verb")).unwrap();
        let wrap = body
            .find(concat!(".choice(", "conversation, now)"))
            .unwrap();
        assert!(fits < wrap);
    }

    /// Structural tripwire: a LoopPlane needs a live daemon, so this pins the
    /// wiring by source. Without the override, the trait default drops every
    /// line `maknae agent` used to print.
    #[test]
    fn loop_plane_hands_its_diagnostics_to_the_loop() {
        let src = include_str!("plane.rs");
        let body = &src[src
            .find(concat!(
                "impl<K: KeySupply, D: Dial> Plane ",
                "for LoopPlane"
            ))
            .unwrap()..];
        assert_eq!(body.matches(concat!("diagnostics", ".push(l)")).count(), 7);
        assert!(body.contains(concat!(
            "fn take_diagnostics(&mut self) -> Vec<String> {\n",
            "        std::mem::take(&mut self.diagnostics)"
        )));
    }

    fn a_choice() -> ProviderChoice {
        ProviderChoice {
            provider: "p".into(),
            model: "m".into(),
            key_subpath: "k".into(),
            key_field: "f".into(),
            sealed_key: SealedKey::new(vec![7; maknae_proto::SEALED_KEY_MIN_BYTES]).unwrap(),
        }
    }

    #[test]
    fn a_spare_choice_is_reused_once_for_its_conversation_while_its_wrap_is_young() {
        let mut spare = Some(Spare {
            conversation: "c".into(),
            minted_at: 100,
            choice: a_choice(),
        });
        assert!(take_spare(&mut spare, "other", 101).is_none());
        assert!(spare.is_none());

        let mut spare = Some(Spare {
            conversation: "c".into(),
            minted_at: 100,
            choice: a_choice(),
        });
        assert!(take_spare(&mut spare, "c", 100 + SPARE_MAX_AGE_SECS + 1).is_none());

        let mut spare = Some(Spare {
            conversation: "c".into(),
            minted_at: 100,
            choice: a_choice(),
        });
        let s = take_spare(&mut spare, "c", 100 + SPARE_MAX_AGE_SECS).unwrap();
        assert_eq!((s.choice, s.minted_at), (a_choice(), 100));
        assert!(take_spare(&mut spare, "c", 101).is_none());
    }

    #[test]
    fn a_spare_is_never_older_than_half_the_wrap() {
        assert_eq!(
            SPARE_MAX_AGE_SECS * 2,
            maknae_vault::USER_KEY_WRAP_TTL.as_secs()
        );
    }
}
