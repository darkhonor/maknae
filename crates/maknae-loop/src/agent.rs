//! The agent host's plane (#629): the loop's [`LoopPlane`] with the task verbs,
//! the signature check and the persona reads the task driver asks for.
use crate::keys::KeySupply;
use crate::plane::{Dial, LoopPlane, PlaneDial};
use maknae_agent::plane::{
    ListOutcome, Plane, PlaneError, ReadBasis, ReadOutcome, StatOutcome, WriteOutcome,
};
use maknae_agent::task::{BeatAnswer, ClaimAnswer, ReportOutcome};
use maknae_agent::task_driver::{DriverEvent, PersonaAt, TaskPlane, Unverified};
use maknae_config::AgentId;
use maknae_io::{
    AnchorRequired, DescendantRequired, IoError, IoKind, StrategyPref, TargetRequired, Zeroizing,
};
use maknae_proto::{Bytes, ConversationId, ConversationView, SecretText, SignedTask, TaskId, Turn};
use maknae_vault::TrustBundle;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const PERSONA_MAX_BYTES: u64 = 64 * 1024;

/// What a delivered task's kernel signature is checked against.
pub struct TaskTrust {
    pub trust: Arc<TrustBundle>,
    pub trust_domain: String,
    pub agent: AgentId,
}

impl TaskTrust {
    pub fn verify(
        &self,
        signed: &Bytes,
        now: std::time::SystemTime,
    ) -> Result<SignedTask, Unverified> {
        let task: SignedTask =
            ciborium::from_reader(signed.0.as_slice()).map_err(|_| Unverified::Undecodable)?;
        maknae_vault::task_sig::verify_task(
            &self.trust,
            &self.trust_domain,
            &self.agent,
            &task,
            now,
        )
        .map_err(|e| Unverified::Failed {
            task: task.task.task_id,
            class: crate::task::verify_class(e),
        })?;
        Ok(task)
    }
}

pub trait PersonaRead: Send {
    fn read(&mut self, at: PersonaAt<'_>) -> Result<Option<SecretText>, String>;
}

/// `/etc` through the root-owned agent reader; the home and partition copies only
/// when the agent's own account owns them and no one else can write them.
pub struct PersonaFiles {
    pub config_dir: PathBuf,
    pub agent: AgentId,
    pub home: PathBuf,
    pub owner: u32,
}

impl PersonaFiles {
    fn own(&self, rel: &Path) -> Result<Option<SecretText>, String> {
        let dir = AnchorRequired {
            owner: Some(self.owner),
            mode_mask: Some(0o022),
        };
        let desc = rel
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|_| DescendantRequired {
                owner: Some(self.owner),
                mode_mask: Some(0o022),
            });
        let target = TargetRequired {
            owner: Some(self.owner),
            mode_mask: Some(0o022),
            nlink_exactly_one: true,
            regular_file: true,
            max_bytes: Some(PERSONA_MAX_BYTES),
        };
        let full = self.home.join(rel);
        let read = maknae_io::open_anchor(&self.home, dir, StrategyPref::Auto)
            .and_then(|anchor| anchor.read(rel, desc, target));
        match read {
            Ok(out) => text(out.value).map(Some),
            Err(IoError::Io {
                kind: IoKind::NotFound,
                path,
            }) if path == full => Ok(None),
            Err(e) => Err(format!("{}: {e}", full.display())),
        }
    }
}

fn text(mut bytes: Zeroizing<Vec<u8>>) -> Result<SecretText, String> {
    String::from_utf8(std::mem::take(&mut *bytes))
        .map(|s| SecretText(Zeroizing::new(s)))
        .map_err(|e| {
            drop(Zeroizing::new(e.into_bytes()));
            "the persona is not UTF-8".to_string()
        })
}

impl PersonaRead for PersonaFiles {
    fn read(&mut self, at: PersonaAt<'_>) -> Result<Option<SecretText>, String> {
        match at {
            PersonaAt::Etc => maknae_config::read_persona(&self.config_dir, &self.agent)
                .map(|p| p.map(SecretText))
                .map_err(|e| e.to_string()),
            PersonaAt::Home => self.own(Path::new(maknae_config::PERSONA_FILE)),
            PersonaAt::Partition(partition) => {
                self.own(&Path::new(partition).join(maknae_config::PERSONA_FILE))
            }
        }
    }
}

pub struct AgentPlane<K: KeySupply, R: PersonaRead, D: Dial = PlaneDial> {
    plane: LoopPlane<K, D>,
    trust: TaskTrust,
    personas: R,
    note: Box<dyn FnMut(DriverEvent) + Send>,
}

impl<K: KeySupply, R: PersonaRead, D: Dial> AgentPlane<K, R, D> {
    pub fn new(
        plane: LoopPlane<K, D>,
        trust: TaskTrust,
        personas: R,
        note: Box<dyn FnMut(DriverEvent) + Send>,
    ) -> Self {
        AgentPlane {
            plane,
            trust,
            personas,
            note,
        }
    }
}

impl<K: KeySupply, R: PersonaRead, D: Dial> Plane for AgentPlane<K, R, D> {
    async fn open(
        &mut self,
        cwd: &Path,
        sensitive: &[String],
    ) -> Result<ConversationId, PlaneError> {
        self.plane.open(cwd, sensitive).await
    }
    async fn close(
        &mut self,
        conversation: &ConversationId,
    ) -> Result<ConversationView, PlaneError> {
        self.plane.close(conversation).await
    }
    async fn prompt(
        &mut self,
        conversation: &str,
        turns: &[Turn],
    ) -> Result<maknae_proto::PromptReply, PlaneError> {
        self.plane.prompt(conversation, turns).await
    }
    async fn read(
        &mut self,
        conversation: &str,
        path: &str,
        page: maknae_proto::PageRequest,
    ) -> ReadOutcome {
        self.plane.read(conversation, path, page).await
    }
    async fn write(
        &mut self,
        conversation: &str,
        path: &str,
        content: &[u8],
        basis: ReadBasis,
    ) -> WriteOutcome {
        self.plane.write(conversation, path, content, basis).await
    }
    async fn list(&mut self, conversation: &str, path: &str, after: Option<&str>) -> ListOutcome {
        self.plane.list(conversation, path, after).await
    }
    async fn stat(&mut self, conversation: &str, path: &str) -> StatOutcome {
        self.plane.stat(conversation, path).await
    }
    fn take_diagnostics(&mut self) -> Vec<String> {
        self.plane.take_diagnostics()
    }
}

impl<K: KeySupply, R: PersonaRead, D: Dial> TaskPlane for AgentPlane<K, R, D> {
    async fn claim(&mut self) -> Result<ClaimAnswer, String> {
        self.plane.tasks().claim().await
    }
    async fn heartbeat(&mut self, seen: u32) -> Result<BeatAnswer, String> {
        self.plane.tasks().heartbeat(seen).await
    }
    async fn report(&mut self, text: SecretText) -> Result<ReportOutcome, String> {
        self.plane.tasks().report(text).await
    }
    fn cite(&mut self, task: Option<TaskId>) {
        self.plane.cite(task);
    }
    async fn mkdir(&mut self, path: &str, parents: bool) -> WriteOutcome {
        self.plane.mkdir(path, parents).await
    }
    fn verify(&mut self, signed: &Bytes) -> Result<SignedTask, Unverified> {
        self.trust.verify(signed, std::time::SystemTime::now())
    }
    fn persona(&mut self, at: PersonaAt<'_>) -> Result<Option<SecretText>, String> {
        self.personas.read(at)
    }
    fn note(&mut self, event: DriverEvent) {
        (self.note)(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_agent::task_driver::VerifyClass;
    use maknae_crypto::plane_key::PlaneKey;
    use maknae_proto::{Ask, Labels, TaskObject, Tasker, TASK_SCHEMA, TASK_VERSION};
    use maknae_vault::test_pki::{TestCa, TRUST_DOMAIN};
    use std::os::unix::fs::PermissionsExt;

    fn hobi() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    fn task(to: &str) -> TaskObject {
        TaskObject {
            schema: TASK_SCHEMA.into(),
            version: TASK_VERSION,
            task_id: TaskId([0x62; 16]),
            tasker: Tasker::Uid(1000),
            parent: None,
            agent: to.into(),
            ask: Ask::Prompt {
                prompt: SecretText(Zeroizing::new("sentinel-629-agentd-prompt".into())),
            },
            labels: Labels {},
        }
    }

    fn wire(signed: &SignedTask) -> Bytes {
        let mut out = Vec::new();
        ciborium::into_writer(signed, &mut out).unwrap();
        Bytes::new(Zeroizing::new(out))
    }

    struct Keys;
    impl KeySupply for Keys {
        async fn choice(
            &mut self,
            _c: &str,
            _now: u64,
        ) -> Result<maknae_proto::ProviderChoice, String> {
            Ok(maknae_proto::ProviderChoice {
                provider: "p".into(),
                model: "m".into(),
                key_subpath: "k".into(),
                key_field: "f".into(),
                sealed_key: maknae_proto::SealedKey::new(vec![
                    7;
                    maknae_proto::SEALED_KEY_MIN_BYTES
                ])
                .unwrap(),
            })
        }
    }

    struct NoPersona;
    impl PersonaRead for NoPersona {
        fn read(&mut self, at: PersonaAt<'_>) -> Result<Option<SecretText>, String> {
            match at {
                PersonaAt::Partition(p) => Ok(Some(SecretText(Zeroizing::new(format!(
                    "sentinel-629-{p}"
                ))))),
                PersonaAt::Etc | PersonaAt::Home => Ok(None),
            }
        }
    }

    #[tokio::test]
    async fn every_verb_goes_to_the_kernel_through_the_loop_plane_and_only_claims_go_uncited() {
        use crate::plane::fake::{refused, FakeKernel};
        use maknae_proto::Verb;
        let ca = TestCa::new(PlaneKey::MlDsa87);
        let verbs = 12;
        let lp = LoopPlane::with_dial(
            FakeKernel::answering(vec![refused(); verbs]),
            maknae_config::TransportConfig::default(),
            None,
            4096,
            Keys,
        );
        let noted = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&noted);
        let mut plane = AgentPlane::new(
            lp,
            TaskTrust {
                trust: ca.trust(),
                trust_domain: TRUST_DOMAIN.into(),
                agent: hobi(),
            },
            NoPersona,
            Box::new(move |e| seen.lock().unwrap().push(e)),
        );
        let id = TaskId([0x29; 16]);
        let dir = std::env::temp_dir();
        let d = dir.to_str().unwrap();
        let conversation = ConversationId::parse(&"a".repeat(32)).unwrap();
        let turn = [Turn::User {
            content: vec![maknae_proto::ContentBlock::Text {
                text: SecretText(Zeroizing::new("q".into())),
            }],
        }];
        plane.cite(Some(id));
        let _ = plane.claim().await;
        let _ = plane.heartbeat(3).await;
        let _ = plane.report(SecretText(Zeroizing::new("r".into()))).await;
        let _ = plane.mkdir(&format!("{d}/tasks/users/1000"), true).await;
        let _ = plane.open(&dir, &[]).await;
        let _ = plane.prompt("c", &turn).await;
        let _ = plane
            .read("c", &format!("{d}/absent"), maknae_proto::WHOLE_FILE)
            .await;
        let _ = plane
            .write("c", &format!("{d}/new"), b"x", ReadBasis::Unread)
            .await;
        let _ = plane.list("c", d, None).await;
        let _ = plane.stat("c", d).await;
        let _ = plane.close(&conversation).await;
        plane.cite(None);
        let _ = plane.report(SecretText(Zeroizing::new("r".into()))).await;
        let _ = plane.take_diagnostics();
        plane.note(DriverEvent::CloseFailed(PlaneError::Refused));
        assert_eq!(
            plane
                .persona(PersonaAt::Partition("tasks/users/1000"))
                .unwrap()
                .unwrap()
                .0
                .as_str(),
            "sentinel-629-tasks/users/1000"
        );
        let sent: Vec<_> = plane
            .plane
            .link_for_test()
            .finish()
            .await
            .requests
            .iter()
            .map(|r| {
                let name = match &r.verb {
                    Verb::TaskClaim {
                        seen_follow_ups: None,
                    } => "claim",
                    Verb::TaskClaim {
                        seen_follow_ups: Some(3),
                    } => "heartbeat",
                    Verb::TaskReport { .. } => "report",
                    Verb::FsMkdir { parents: true, .. } => "mkdir",
                    Verb::SessionNew { .. } => "open",
                    Verb::SessionPrompt { .. } => "prompt",
                    Verb::Read { .. } => "read",
                    Verb::FsWrite { .. } => "write",
                    Verb::FsList { .. } => "list",
                    Verb::FsStat { .. } => "stat",
                    Verb::SessionClose { .. } => "close",
                    other => panic!("unexpected {other:?}"),
                };
                (name, r.task)
            })
            .collect();
        let cited = |v| (v, Some(id));
        assert_eq!(
            sent,
            [
                ("claim", None),
                ("heartbeat", None),
                cited("report"),
                cited("mkdir"),
                cited("open"),
                cited("prompt"),
                cited("read"),
                cited("write"),
                cited("list"),
                cited("stat"),
                cited("close"),
                ("report", None),
            ]
        );
        assert_eq!(
            *noted.lock().unwrap(),
            [DriverEvent::CloseFailed(PlaneError::Refused)]
        );
    }

    #[test]
    fn a_kernel_signed_task_for_this_agent_verifies_and_decodes_whole() {
        maknae_crypto::init().unwrap();
        let ca = TestCa::new(PlaneKey::MlDsa87);
        let signed =
            maknae_vault::task_sig::sign_task(&ca.kernel(PlaneKey::MlDsa87, None), task("hobi"))
                .unwrap();
        let trust = TaskTrust {
            trust: ca.trust(),
            trust_domain: TRUST_DOMAIN.into(),
            agent: hobi(),
        };
        let got = trust
            .verify(&wire(&signed), std::time::SystemTime::now())
            .unwrap();
        assert_eq!(got, signed);
    }

    #[test]
    fn a_task_that_fails_verification_names_its_id_and_class() {
        maknae_crypto::init().unwrap();
        let ca = TestCa::new(PlaneKey::MlDsa87);
        let kernel = ca.kernel(PlaneKey::MlDsa87, None);
        let trust = TaskTrust {
            trust: ca.trust(),
            trust_domain: TRUST_DOMAIN.into(),
            agent: hobi(),
        };
        let now = std::time::SystemTime::now();
        let suga = maknae_vault::task_sig::sign_task(&kernel, task("suga")).unwrap();
        assert_eq!(
            trust.verify(&wire(&suga), now),
            Err(Unverified::Failed {
                task: TaskId([0x62; 16]),
                class: VerifyClass::Agent
            })
        );
        let mut forged = maknae_vault::task_sig::sign_task(&kernel, task("hobi")).unwrap();
        forged.task.ask = Ask::Prompt {
            prompt: SecretText(Zeroizing::new("sentinel-629-forged".into())),
        };
        assert_eq!(
            trust.verify(&wire(&forged), now),
            Err(Unverified::Failed {
                task: TaskId([0x62; 16]),
                class: VerifyClass::Signature
            })
        );
        let other = TestCa::new(PlaneKey::MlDsa87);
        let foreign =
            maknae_vault::task_sig::sign_task(&other.kernel(PlaneKey::MlDsa87, None), task("hobi"))
                .unwrap();
        assert_eq!(
            trust.verify(&wire(&foreign), now),
            Err(Unverified::Failed {
                task: TaskId([0x62; 16]),
                class: VerifyClass::NotKernel
            })
        );
    }

    #[test]
    fn bytes_that_are_not_a_signed_task_are_undecodable() {
        let ca = TestCa::new(PlaneKey::MlDsa87);
        let trust = TaskTrust {
            trust: ca.trust(),
            trust_domain: TRUST_DOMAIN.into(),
            agent: hobi(),
        };
        for junk in [vec![], vec![0xff; 9], b"sentinel-629-junk".to_vec()] {
            assert_eq!(
                trust.verify(
                    &Bytes::new(Zeroizing::new(junk)),
                    std::time::SystemTime::now()
                ),
                Err(Unverified::Undecodable)
            );
        }
    }

    struct Home(PathBuf);
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn home(tag: &str) -> (Home, PersonaFiles) {
        let dir = std::env::temp_dir().join(format!("loop-persona-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tasks/users/1000")).unwrap();
        for d in [
            &dir,
            &dir.join("tasks"),
            &dir.join("tasks/users"),
            &dir.join("tasks/users/1000"),
        ] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let dir = dir.canonicalize().unwrap();
        let files = PersonaFiles {
            config_dir: dir.join("etc"),
            agent: hobi(),
            home: dir.clone(),
            owner: nix::unistd::geteuid().as_raw(),
        };
        (Home(dir), files)
    }

    fn put(path: &Path, body: &str, mode: u32) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn read(files: &mut PersonaFiles, at: PersonaAt<'_>) -> Result<Option<String>, String> {
        files.read(at).map(|p| p.map(|t| t.0.to_string()))
    }

    #[test]
    fn the_home_and_partition_personas_are_read_when_present_and_absent_otherwise() {
        let (h, mut files) = home("present");
        let part = PersonaAt::Partition("tasks/users/1000");
        assert_eq!(read(&mut files, PersonaAt::Home), Ok(None));
        assert_eq!(read(&mut files, part), Ok(None));
        put(&h.0.join("persona.md"), "sentinel-629-home-persona", 0o600);
        put(
            &h.0.join("tasks/users/1000/persona.md"),
            "sentinel-629-partition-persona",
            0o644,
        );
        assert_eq!(
            read(&mut files, PersonaAt::Home),
            Ok(Some("sentinel-629-home-persona".into()))
        );
        assert_eq!(
            read(&mut files, part),
            Ok(Some("sentinel-629-partition-persona".into()))
        );
    }

    #[test]
    fn a_persona_others_can_write_or_that_is_linked_or_too_big_or_not_utf8_is_an_error() {
        let (h, mut files) = home("refused");
        let path = h.0.join("persona.md");
        for mode in [0o620, 0o602] {
            put(&path, "sentinel-629-writable", mode);
            assert!(read(&mut files, PersonaAt::Home).is_err(), "{mode:o}");
        }
        std::fs::remove_file(&path).unwrap();
        put(&h.0.join("elsewhere.md"), "sentinel-629-linked", 0o600);
        std::os::unix::fs::symlink(h.0.join("elsewhere.md"), &path).unwrap();
        assert!(read(&mut files, PersonaAt::Home).is_err());
        std::fs::remove_file(&path).unwrap();
        put(&path, &"p".repeat(PERSONA_MAX_BYTES as usize + 1), 0o600);
        assert!(read(&mut files, PersonaAt::Home).is_err());
        std::fs::write(&path, b"\xff\xfe").unwrap();
        assert_eq!(
            read(&mut files, PersonaAt::Home),
            Err("the persona is not UTF-8".into())
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::set_permissions(&h.0, std::fs::Permissions::from_mode(0o720)).unwrap();
        assert!(
            read(&mut files, PersonaAt::Home).is_err(),
            "a home others can write"
        );
    }

    #[test]
    fn a_persona_owned_by_another_account_is_an_error() {
        let (h, mut files) = home("owner");
        put(&h.0.join("persona.md"), "sentinel-629-owner", 0o600);
        files.owner = files.owner.wrapping_add(1);
        assert!(read(&mut files, PersonaAt::Home).is_err());
    }

    #[test]
    fn the_etc_persona_is_read_through_the_root_owned_agent_reader() {
        let (_h, mut files) = home("etc");
        let got = read(&mut files, PersonaAt::Etc);
        assert!(
            got.is_err(),
            "a missing agents directory is never an absent persona: {got:?}"
        );
    }
}
