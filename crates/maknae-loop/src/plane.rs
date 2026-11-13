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
use maknae_config::TransportConfig;
use maknae_proto::{ConversationId, ConversationView, ProviderChoice, TaskId, Turn, Verb};
use maknae_vault::{AuthenticatedStream, PlaneClient, PlaneConnector, TrustBundle, VaultError};
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
fn frame_fits(verb: &Verb, cap: usize) -> bool {
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

impl<D: Dial> Link<D> {
    pub(crate) fn cited(&self) -> Option<TaskId> {
        // A poisoned guard still holds a whole `Option<TaskId>`: it is only ever assigned.
        *self.cite.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) async fn send(
        &self,
        task: Option<TaskId>,
        verb: Verb,
        content: Option<maknae_proto::Bytes>,
        check: crate::mutation::WriteCheck,
        diag: &mut (dyn FnMut(String) + Send),
    ) -> Result<crate::outcome::SentOutcome, String> {
        send_via(
            self.dial.dial(),
            task,
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
            client,
            trust,
            output_tokens,
            write_max,
            keys,
        )
    }

    fn over(
        transport: TransportConfig,
        socket: PathBuf,
        client: PlaneClient,
        trust: Arc<TrustBundle>,
        output_tokens: Option<u64>,
        write_max: usize,
        keys: K,
    ) -> Self {
        let dial = PlaneDial {
            socket,
            client: Arc::new(client),
            trust,
        };
        Self::with_dial(dial, transport, output_tokens, write_max, keys)
    }

    pub fn into_client(self) -> Arc<PlaneClient> {
        Arc::clone(&self.link.dial.client)
    }
}

impl LoopPlane<AgentKeys, PlaneDial> {
    /// The agent's loop: the kernel's agent socket, under the agent's own leaf.
    pub fn for_agent(
        transport: TransportConfig,
        client: PlaneClient,
        trust: Arc<TrustBundle>,
        output_tokens: Option<u64>,
        write_max: usize,
        keys: AgentKeys,
    ) -> Self {
        let socket = transport.agent_socket_path.clone();
        Self::over(
            transport,
            socket,
            client,
            trust,
            output_tokens,
            write_max,
            keys,
        )
    }
}

impl<K: KeySupply, D: Dial> LoopPlane<K, D> {
    pub fn with_dial(
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

    /// The directory is created mode 0700, as every subject-side mkdir is.
    pub async fn mkdir(&mut self, path: &str, parents: bool) -> WriteOutcome {
        let diagnostics = &mut self.diagnostics;
        write_outcome(
            self.link
                .send(
                    self.link.cited(),
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
                    self.link.cited(),
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
                    self.link.cited(),
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
                    self.link.cited(),
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
                    self.link.cited(),
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
            .send(
                self.link.cited(),
                verb,
                Some(content),
                check_for(basis),
                &mut |l| diagnostics.push(l),
            )
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
                    self.link.cited(),
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
                    self.link.cited(),
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

    async fn every_file_and_session_verb(plane: &mut LoopPlane<Keys, fake::FakeKernel>, dir: &str) {
        let _ = plane
            .read("c", &format!("{dir}/absent"), maknae_proto::WHOLE_FILE)
            .await;
        let _ = plane
            .write("c", &format!("{dir}/new"), b"x", ReadBasis::Unread)
            .await;
        let _ = plane.mkdir(&format!("{dir}/tasks/users/1000"), true).await;
        let _ = plane.prompt("c", &user_turn()).await;
    }

    #[tokio::test]
    async fn a_cited_task_is_stamped_on_every_request_until_uncited() {
        let dir = tempfile_dir("cite");
        let id = TaskId([0x62; 16]);
        let mut plane = fake_plane(vec![fake::refused(); 8]);
        plane.cite(Some(id));
        every_file_and_session_verb(&mut plane, &dir).await;
        plane.cite(None);
        every_file_and_session_verb(&mut plane, &dir).await;
        let seen = plane.link.dial.finish().await;
        let verbs: Vec<_> = seen
            .requests
            .iter()
            .map(|r| (verb_name(&r.verb), r.task))
            .collect();
        let once = |task| {
            [
                ("read", task),
                ("write", task),
                ("mkdir", task),
                ("prompt", task),
            ]
        };
        assert_eq!(verbs, [once(Some(id)), once(None)].concat());
    }

    #[tokio::test]
    async fn each_verb_opens_its_own_connection() {
        let dir = tempfile_dir("connections");
        let mut plane = fake_plane(vec![fake::refused(); 7]);
        plane.cite(Some(TaskId([7; 16])));
        every_file_and_session_verb(&mut plane, &dir).await;
        let tasks = plane.tasks();
        let _ = tasks.claim().await;
        let _ = tasks.heartbeat(0).await;
        let _ = tasks
            .report(maknae_proto::SecretText(zeroize::Zeroizing::new(
                "r".into(),
            )))
            .await;
        drop(tasks);
        let seen = plane.link.dial.finish().await;
        assert_eq!(seen.requests.len(), 7);
        assert_eq!(seen.frames_per_connection, [1; 7]);
    }

    #[test]
    fn the_agent_loop_dials_the_agent_socket_and_the_cli_the_client_socket() {
        let src = include_str!("plane.rs");
        let body = |f: &str| {
            let at = src.find(f).unwrap();
            &src[at..at + src[at..].find("Self::over(").unwrap()]
        };
        assert!(body(concat!("pub fn ", "for_agent("))
            .contains(concat!("transport.agent_", "socket_path.clone()")));
        assert!(body(concat!("pub fn ", "new(\n"))
            .contains(concat!("transport.", "socket_path.clone()")));
    }

    fn verb_name(v: &Verb) -> &'static str {
        match v {
            Verb::Read { .. } => "read",
            Verb::FsWrite { .. } => "write",
            Verb::FsMkdir { .. } => "mkdir",
            Verb::SessionPrompt { .. } => "prompt",
            Verb::TaskClaim { .. } => "claim",
            Verb::TaskReport { .. } => "report",
            _ => "other",
        }
    }

    fn tempfile_dir(tag: &str) -> String {
        let dir =
            std::env::temp_dir().join(format!("maknae-loop-629-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.to_str().unwrap().to_string()
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
