//! Minting's start-up state and the Egress Daemon's only Vault login (#168, ADR-0038
//! decisions 5 and 7). The re-login state machine is `maknae-deputy`'s `ServiceSigner`.

use crate::opener::SealedOpener;
use crate::reach::{EgressReach, Parts};
use crate::serve::{Frames, MintFrames};
use maknae_config::{
    AgentId, ConfigError, EgressBounds, GithubAppConfig, MintingConfig, MintingFile, MINTING_FILE,
    MINT_ROLE_ID_FILE,
};
use maknae_deputy::mint::admit::AdmittedMint;
use maknae_deputy::mint::github::GithubClient;
use maknae_deputy::mint::minter::{self, LiveTokens, MintDeps};
use maknae_deputy::mint::signer::{ServiceSigner, SignError, VaultLogin, VaultSignError};
use maknae_io::MaknaeSecret;
use maknae_proto::{MintRefusal, MintReply, RevokeReply, RevokeRequest};
use maknae_seal::SealPrivateKey;
use maknae_vault::{VaultApi, VaultError};
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

fn journal(line: impl Display) {
    eprintln!("maknae-egress: {line}");
}

type Journal = fn(&str);

fn stderr_journal(line: &str) {
    journal(line);
}

pub(crate) struct ApproleLogin {
    api: Arc<VaultApi>,
    mount: String,
    role_id: String,
    secret_id: MaknaeSecret,
    journal: Journal,
}

impl std::fmt::Debug for ApproleLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApproleLogin")
            .field("mount", &self.mount)
            .finish_non_exhaustive()
    }
}

impl VaultLogin for ApproleLogin {
    type Token = MaknaeSecret;

    async fn login(&self) -> Result<(MaknaeSecret, Duration), SignError> {
        match self
            .api
            .approle_login(&self.mount, &self.role_id, &self.secret_id)
            .await
        {
            Ok(login) => Ok((login.token, login.ttl)),
            Err(e) => {
                (self.journal)(&format!("Vault login failed: {e}"));
                Err(SignError)
            }
        }
    }

    async fn sign(
        &self,
        token: &MaknaeSecret,
        mount: &str,
        key: &str,
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultSignError> {
        self.api
            .transit_sign_rs256(token, mount, key, input)
            .await
            .map_err(|e| {
                (self.journal)(&format!("Transit sign failed: {e}"));
                sign_failure(&e)
            })
    }

    fn refused_after_fresh_login(&self) {
        (self.journal)(
            "Transit sign was refused again right after a fresh Vault login: \
             the AppRole's policy may lack Transit sign on this key",
        );
    }
}

fn sign_failure(e: &VaultError) -> VaultSignError {
    match e {
        VaultError::VaultStatus { status: 403, .. } => VaultSignError::TokenRefused,
        _ => VaultSignError::Failed,
    }
}

/// What `minting_state` reads, so a test can count the reads.
pub(crate) trait MintingReads {
    fn minting(&self, path: &Path) -> Result<Option<MintingFile>, ConfigError>;
    fn role_id(&self, path: &Path) -> Result<String, ConfigError>;
    fn secret_id(&self, credentials_dir: Option<&Path>) -> Result<MaknaeSecret, VaultError>;
}

pub(crate) struct FileReads;

impl MintingReads for FileReads {
    fn minting(&self, path: &Path) -> Result<Option<MintingFile>, ConfigError> {
        maknae_config::load_minting(path)
    }

    fn role_id(&self, path: &Path) -> Result<String, ConfigError> {
        maknae_config::load_mint_role_id(path)
    }

    fn secret_id(&self, credentials_dir: Option<&Path>) -> Result<MaknaeSecret, VaultError> {
        maknae_vault::read_egress_secret_id(credentials_dir)
    }
}

pub(crate) type EgressSigner = ServiceSigner<ApproleLogin>;

#[derive(Debug)]
pub(crate) enum MintingState {
    Off,
    Ready(Arc<EgressSigner>, MintingConfig),
    Unavailable(&'static str),
}

/// `minting.yaml` as loaded (its `apis:` serve reach with or without a minter) and minting's state.
#[derive(Debug)]
pub(crate) struct Minting {
    pub(crate) file: Option<MintingFile>,
    pub(crate) state: MintingState,
}

pub(crate) fn minting_state(
    egress_dir: &Path,
    credentials_dir: Option<&Path>,
    api: &Arc<VaultApi>,
    read: &dyn MintingReads,
) -> Minting {
    let file = match read.minting(&egress_dir.join(MINTING_FILE)) {
        Ok(f) => f,
        Err(e) => {
            return Minting {
                file: None,
                state: unavailable("minting.yaml could not be loaded", e),
            }
        }
    };
    let state = match file.as_ref().and_then(MintingFile::minting) {
        None => MintingState::Off,
        Some(c) => minter_state(egress_dir, credentials_dir, api, read, c.clone()),
    };
    Minting { file, state }
}

fn minter_state(
    egress_dir: &Path,
    credentials_dir: Option<&Path>,
    api: &Arc<VaultApi>,
    read: &dyn MintingReads,
    config: MintingConfig,
) -> MintingState {
    let role_id = match read.role_id(&egress_dir.join(MINT_ROLE_ID_FILE)) {
        Ok(r) => r,
        Err(e) => return unavailable("the role id could not be read", e),
    };
    let secret_id = match read.secret_id(credentials_dir) {
        Ok(s) => s,
        Err(e) => return unavailable("the SecretID could not be read", e),
    };
    let login = ApproleLogin {
        api: Arc::clone(api),
        mount: config.vault.approle_mount.clone(),
        role_id,
        secret_id,
        journal: stderr_journal,
    };
    MintingState::Ready(Arc::new(ServiceSigner::new(login)), config)
}

fn unavailable(why: &'static str, e: impl Display) -> MintingState {
    journal(format_args!("minting is unavailable: {why}: {e}"));
    MintingState::Unavailable(why)
}

struct Ready {
    config: MintingConfig,
    signer: Arc<EgressSigner>,
    github: GithubClient,
    own_key: Arc<SealPrivateKey>,
    egress_dir: PathBuf,
    rt: tokio::runtime::Handle,
}

impl Ready {
    fn deps<'a>(&'a self, journal: &'a mut dyn FnMut(&str)) -> MintDeps<'a, EgressSigner> {
        MintDeps {
            signer: &*self.signer,
            github: &self.github,
            own_pub: self.own_key.public_key(),
            own_key: &self.own_key,
            egress_dir: &self.egress_dir,
            clock: &unix_now,
            journal,
        }
    }
}

pub(crate) struct EgressMinting {
    ready: Result<Ready, &'static str>,
    journal: Journal,
}

pub(crate) struct Wiring {
    pub(crate) own_key: Arc<SealPrivateKey>,
    pub(crate) opener: Arc<SealedOpener>,
    pub(crate) bounds: Arc<EgressBounds>,
    pub(crate) egress_dir: PathBuf,
    pub(crate) rt: tokio::runtime::Handle,
}

pub(crate) fn frames(minting: Minting, w: Wiring) -> Frames {
    frames_journaled(minting, w, stderr_journal)
}

fn frames_journaled(minting: Minting, w: Wiring, journal: Journal) -> Frames {
    let github = GithubClient::new()
        .map_err(|e| journal(&format!("the GitHub client could not be built: {e:?}")))
        .ok();
    let (mint, minter) = mint_frames(minting.state, github.clone(), &w, journal);
    let reach = EgressReach::new(Parts {
        file: minting.file,
        minter,
        opener: w.opener,
        github,
        bounds: w.bounds,
        rt: w.rt,
        journal,
    });
    Frames {
        mint,
        reach: Arc::new(reach),
    }
}

type MintAndMinter = (Option<Arc<dyn MintFrames>>, Option<Arc<EgressSigner>>);

fn mint_frames(
    state: MintingState,
    github: Option<GithubClient>,
    w: &Wiring,
    journal: Journal,
) -> MintAndMinter {
    let ready = match state {
        MintingState::Off => return (None, None),
        MintingState::Unavailable(why) => Err(why),
        MintingState::Ready(signer, config) => match github {
            Some(github) => Ok(Ready {
                config,
                signer,
                github,
                own_key: Arc::clone(&w.own_key),
                egress_dir: w.egress_dir.clone(),
                rt: w.rt.clone(),
            }),
            None => {
                journal("minting is unavailable: the GitHub client could not be built");
                Err("the GitHub client could not be built")
            }
        },
    };
    let minter = ready.as_ref().ok().map(|r| Arc::clone(&r.signer));
    (Some(Arc::new(EgressMinting { ready, journal })), minter)
}

pub(crate) fn unix_now() -> Option<u64> {
    maknae_io::now_unix().ok()
}

impl MintFrames for EgressMinting {
    fn config(&self) -> Result<&MintingConfig, &'static str> {
        self.ready.as_ref().map(|r| &r.config).map_err(|why| *why)
    }

    fn mint(&self, admitted: &AdmittedMint<'_>) -> (MintReply, LiveTokens) {
        let refused = || {
            (
                MintReply::Refused(MintRefusal::Signer),
                LiveTokens {
                    api: admitted.app.api.clone(),
                    label: String::new(),
                    tokens: Vec::new(),
                },
            )
        };
        let Ok(r) = &self.ready else {
            return refused();
        };
        let mut log = |l: &str| (self.journal)(l);
        let mut d = r.deps(&mut log);
        r.rt.block_on(minter::mint(admitted, &mut d))
    }

    fn revoke(&self, req: &RevokeRequest, agent: &AgentId, app: &GithubAppConfig) -> RevokeReply {
        let Ok(r) = &self.ready else {
            return RevokeReply::Refused(MintRefusal::Signer);
        };
        let mut log = |l: &str| (self.journal)(l);
        let mut d = r.deps(&mut log);
        r.rt.block_on(minter::revoke(req, agent, app, &mut d))
    }

    fn revoke_all(&self, live: LiveTokens) {
        if let Ok(r) = &self.ready {
            r.rt.block_on(minter::revoke_all(&r.github, live, &mut |l| {
                (self.journal)(l)
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_frames::{
        agent_reach, canned_reply, prompt_frame, served_frame, served_frame_reaching, tasker_reach,
    };
    use maknae_config::{ApiBase, MintVault};
    use maknae_deputy::mint::admit::admit_mint;
    use maknae_deputy::mint::signer::Signer;
    use maknae_proto::{
        AccessLevel, EgressFrame, EgressSocketReply, GithubPermission, MintRequest, PermissionSet,
        ReachRefusal, ReachReply, SealedCredentialBytes,
    };
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[test]
    fn the_minting_clock_is_the_wall_clock() {
        let read = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };
        let before = read();
        let now = unix_now().unwrap();
        assert!((before..=read()).contains(&now), "{now}");
    }

    fn fips() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| maknae_crypto::init().unwrap());
    }

    thread_local! {
        static LINES: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    fn record(line: &str) {
        LINES.with(|l| l.borrow_mut().push(line.to_owned()));
    }

    fn recorded() -> Vec<String> {
        LINES.with(|l| std::mem::take(&mut *l.borrow_mut()))
    }

    fn dead_vault() -> (tempfile::TempDir, Arc<VaultApi>) {
        fips();
        let d = tempfile::tempdir().unwrap();
        let ca = d.path().join(maknae_vault::EGRESS_VAULT_CA_FILE);
        std::fs::write(&ca, crate::opener::tests::TEST_CA_PEM).unwrap();
        let api = Arc::new(VaultApi::new("https://127.0.0.1:1", &ca).unwrap());
        (d, api)
    }

    fn config() -> MintingConfig {
        MintingConfig {
            vault: MintVault {
                approle_mount: "approle-mint".into(),
            },
            github_apps: BTreeMap::from([(
                "deploy".to_string(),
                GithubAppConfig {
                    app_id: 5834363,
                    installation_id: 77,
                    host: "github.example".into(),
                    api: ApiBase::parse("https://api.github.example").unwrap(),
                    transit_mount: "transit".into(),
                    transit_key: "deploy-app".into(),
                },
            )]),
        }
    }

    const MINTING_YAML: &str = concat!(
        "vault:\n",
        "  approle_mount: approle-mint\n",
        "apis:\n",
        "  github.example:\n",
        "    provider: github\n",
        "    api: https://api.github.example\n",
        "github_apps:\n",
        "  deploy:\n",
        "    app_id: 5834363\n",
        "    installation_id: 77\n",
        "    host: github.example\n",
        "    api: https://api.github.example\n",
        "    transit_mount: transit\n",
        "    transit_key: deploy-app\n",
    );

    const APIS_ONLY_YAML: &str = concat!(
        "apis:\n",
        "  github.example:\n",
        "    provider: github\n",
        "    api: https://api.github.example\n",
    );

    fn file(yaml: &str) -> MintingFile {
        maknae_config::minting_from_document(&maknae_config::load_str(yaml).unwrap()).unwrap()
    }

    struct Reads {
        minting: Result<Option<MintingFile>, ()>,
        role: Result<&'static str, ()>,
        secret: Result<&'static str, ()>,
        calls: Mutex<Vec<(&'static str, Option<PathBuf>)>>,
    }

    impl Reads {
        fn new(
            minting: Result<Option<MintingFile>, ()>,
            role: Result<&'static str, ()>,
            secret: Result<&'static str, ()>,
        ) -> Self {
            Self {
                minting,
                role,
                secret,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(&'static str, Option<PathBuf>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl MintingReads for Reads {
        fn minting(&self, path: &Path) -> Result<Option<MintingFile>, ConfigError> {
            self.calls
                .lock()
                .unwrap()
                .push(("minting", Some(path.to_owned())));
            self.minting
                .clone()
                .map_err(|()| ConfigError::InvalidMinting("SENTINEL".into()))
        }

        fn role_id(&self, path: &Path) -> Result<String, ConfigError> {
            self.calls
                .lock()
                .unwrap()
                .push(("role-id", Some(path.to_owned())));
            self.role
                .map(str::to_owned)
                .map_err(|()| ConfigError::InvalidMintRoleId("SENTINEL"))
        }

        fn secret_id(&self, credentials_dir: Option<&Path>) -> Result<MaknaeSecret, VaultError> {
            self.calls
                .lock()
                .unwrap()
                .push(("secret-id", credentials_dir.map(Path::to_owned)));
            self.secret
                .map(|s| MaknaeSecret::new(Zeroizing::new(s.to_owned())).unwrap())
                .map_err(|()| VaultError::CredentialSource("SENTINEL".into()))
        }
    }

    const EGRESS: &str = "/etc/maknae/egress";
    const CREDS: &str = "/run/credentials/maknae-egress.service";

    fn loaded(reads: &Reads, api: &Arc<VaultApi>) -> Minting {
        minting_state(Path::new(EGRESS), Some(Path::new(CREDS)), api, reads)
    }

    fn state(reads: &Reads, api: &Arc<VaultApi>) -> MintingState {
        loaded(reads, api).state
    }

    fn runtime() -> tokio::runtime::Runtime {
        crate::runtime().unwrap()
    }

    fn wired(minting: Minting, rt: &tokio::runtime::Runtime) -> (Frames, tempfile::TempDir) {
        let (_d, api) = dead_vault();
        let egress = tempfile::tempdir().unwrap();
        let own_key = Arc::new(SealPrivateKey::generate().unwrap());
        let w = Wiring {
            opener: Arc::new(SealedOpener {
                key: Arc::clone(&own_key),
                api,
            }),
            own_key,
            bounds: Arc::new(crate::test_frames::bounds()),
            egress_dir: egress.path().to_owned(),
            rt: rt.handle().clone(),
        };
        (frames_journaled(minting, w, record), egress)
    }

    fn frames_for(
        st: MintingState,
        rt: &tokio::runtime::Runtime,
    ) -> (Option<Arc<dyn MintFrames>>, tempfile::TempDir) {
        let (f, egress) = wired(
            Minting {
                file: Some(file(MINTING_YAML)),
                state: st,
            },
            rt,
        );
        (f.mint, egress)
    }

    fn minting_yaml() -> Option<PathBuf> {
        Some(Path::new(EGRESS).join(MINTING_FILE))
    }

    fn role_id_file() -> Option<PathBuf> {
        Some(Path::new(EGRESS).join(MINT_ROLE_ID_FILE))
    }

    fn mint_frame(sets: Vec<PermissionSet>) -> EgressFrame {
        EgressFrame::Mint(MintRequest {
            task: "task-1".into(),
            agent: "coder".into(),
            class: "git-write".into(),
            kind: "github-app-installation".into(),
            app: "deploy".into(),
            sets,
        })
    }

    fn revoke_frame() -> EgressFrame {
        EgressFrame::Revoke(RevokeRequest {
            task: "task-1".into(),
            agent: "coder".into(),
            class: "git-write".into(),
            kind: "github-app-installation".into(),
            app: "deploy".into(),
            set: 0,
            for_revocation: SealedCredentialBytes::new(vec![5; maknae_proto::SEALED_KEY_MIN_BYTES])
                .unwrap(),
        })
    }

    fn set(repo: &str) -> PermissionSet {
        PermissionSet {
            repositories: vec![repo.into()],
            permissions: BTreeMap::from([(GithubPermission::Contents, AccessLevel::Write)]),
        }
    }

    #[test]
    fn minting_state_is_off_without_the_file_and_reads_nothing() {
        let (_d, api) = dead_vault();
        let reads = Reads::new(Ok(None), Ok("role"), Ok("secret"));
        let st = loaded(&reads, &api);
        assert!(matches!(st.state, MintingState::Off), "{st:?}");
        assert!(st.file.is_none());
        assert_eq!(reads.calls(), [("minting", minting_yaml())]);
        let rt = runtime();
        assert!(wired(st, &rt).0.mint.is_none());
    }

    #[test]
    fn an_apis_only_file_is_kept_for_reach_and_minting_is_off() {
        let (_d, api) = dead_vault();
        let reads = Reads::new(Ok(Some(file(APIS_ONLY_YAML))), Ok("role"), Ok("secret"));
        let st = loaded(&reads, &api);
        assert!(matches!(st.state, MintingState::Off), "{st:?}");
        assert_eq!(st.file, Some(file(APIS_ONLY_YAML)));
        assert_eq!(reads.calls(), [("minting", minting_yaml())]);
    }

    #[test]
    fn a_reach_frame_without_minting_is_refused_and_prompts_still_serve() {
        let (_d, api) = dead_vault();
        let rt = runtime();
        let tasker = EgressFrame::Reach(tasker_reach("github.example"));
        let agent = EgressFrame::Reach(agent_reach("github.example", "deploy"));
        let reach = |reply| Some(EgressSocketReply::Reach(reply));
        let refused = reach(ReachReply::Refused(ReachRefusal::Request));
        let no_credential = reach(ReachReply::NoForgeCredential);
        for (what, minting, frame, want) in [
            ("no minting.yaml", Ok(None), &tasker, &refused),
            ("no minting.yaml", Ok(None), &agent, &refused),
            ("an unloadable minting.yaml", Err(()), &agent, &refused),
            (
                "apis only",
                Ok(Some(file(APIS_ONLY_YAML))),
                &agent,
                &no_credential,
            ),
            (
                "an unavailable minter",
                Ok(Some(file(MINTING_YAML))),
                &agent,
                &no_credential,
            ),
        ] {
            let reads = Reads::new(minting, Ok("role"), Err(()));
            let (f, _egress) = wired(loaded(&reads, &api), &rt);
            let (out, reply) = served_frame_reaching(frame, f.mint.as_deref(), &*f.reach);
            assert_eq!(out, Ok(()), "{what}");
            assert_eq!(&reply, want, "{what}");
            let (out, reply) = served_frame_reaching(&prompt_frame(), f.mint.as_deref(), &*f.reach);
            assert_eq!(out, Ok(()), "{what}");
            assert_eq!(
                reply,
                Some(canned_reply()),
                "{what}: the provider path is served"
            );
        }
    }

    #[test]
    fn a_ready_minter_admits_the_agent_side_and_signs_for_it() {
        let (_d, api) = dead_vault();
        let rt = runtime();
        let reads = Reads::new(Ok(Some(file(MINTING_YAML))), Ok("role"), Ok("secret"));
        let (f, _egress) = wired(loaded(&reads, &api), &rt);
        recorded();
        let (out, reply) = served_frame_reaching(
            &EgressFrame::Reach(agent_reach("github.example", "deploy")),
            f.mint.as_deref(),
            &*f.reach,
        );
        assert_eq!(out, Ok(()));
        assert_eq!(
            reply,
            Some(EgressSocketReply::Reach(ReachReply::Refused(
                ReachRefusal::Signer
            ))),
            "the App side reached mint's signer, whose Vault is dead"
        );
        let lines = recorded();
        assert_eq!(
            lines,
            ["reach server=\"github.example\" provider=\"github\" side=agent asks=1: refused signer"]
        );
    }

    #[test]
    fn an_unreadable_secret_id_is_unavailable_and_provider_path_starts() {
        let (_d, api) = dead_vault();
        let reads = Reads::new(Ok(Some(file(MINTING_YAML))), Ok("role"), Err(()));
        let st = state(&reads, &api);
        assert!(
            matches!(
                st,
                MintingState::Unavailable("the SecretID could not be read")
            ),
            "{st:?}"
        );
        assert_eq!(
            reads.calls(),
            [
                ("minting", minting_yaml()),
                ("role-id", role_id_file()),
                ("secret-id", Some(PathBuf::from(CREDS))),
            ]
        );
        let rt = runtime();
        let (m, _egress) = frames_for(st, &rt);
        let m = m.expect("unavailable minting still answers its frames");
        assert_eq!(m.config().err(), Some("the SecretID could not be read"));

        let (out, reply) = served_frame(&prompt_frame(), Some(&*m));
        assert_eq!(out, Ok(()));
        assert_eq!(reply, Some(canned_reply()), "the provider path is served");

        for frame in [mint_frame(vec![set("a")]), mint_frame(vec![])] {
            let (out, reply) = served_frame(&frame, Some(&*m));
            assert_eq!(out, Ok(()));
            assert_eq!(
                reply,
                Some(EgressSocketReply::Mint(MintReply::Refused(
                    MintRefusal::Signer
                )))
            );
        }
        let (out, reply) = served_frame(&revoke_frame(), Some(&*m));
        assert_eq!(out, Ok(()));
        assert_eq!(
            reply,
            Some(EgressSocketReply::Revoke(RevokeReply::Refused(
                MintRefusal::Signer
            )))
        );
    }

    #[test]
    fn an_unloadable_minting_yaml_or_role_id_is_unavailable_and_reads_no_further() {
        let (_d, api) = dead_vault();
        let bad_file = Reads::new(Err(()), Ok("role"), Ok("secret"));
        let st = state(&bad_file, &api);
        assert!(
            matches!(
                st,
                MintingState::Unavailable("minting.yaml could not be loaded")
            ),
            "{st:?}"
        );
        assert_eq!(bad_file.calls(), [("minting", minting_yaml())]);

        let bad_role = Reads::new(Ok(Some(file(MINTING_YAML))), Err(()), Ok("secret"));
        let st = state(&bad_role, &api);
        assert!(
            matches!(
                st,
                MintingState::Unavailable("the role id could not be read")
            ),
            "{st:?}"
        );
        assert_eq!(
            bad_role.calls(),
            [("minting", minting_yaml()), ("role-id", role_id_file())]
        );
    }

    #[test]
    fn a_complete_configuration_is_ready_and_mints_and_revokes_through_the_minter() {
        let (_d, api) = dead_vault();
        let reads = Reads::new(Ok(Some(file(MINTING_YAML))), Ok("role"), Ok("secret"));
        let st = state(&reads, &api);
        let MintingState::Ready(_, ref got) = st else {
            panic!("expected Ready, got {st:?}");
        };
        assert_eq!(got, &config());
        assert_eq!(reads.calls().len(), 3);

        let rt = runtime();
        let (m, _egress) = frames_for(st, &rt);
        let m = m.unwrap();
        let cfg = m.config().unwrap();
        assert_eq!(cfg, &config());
        let EgressFrame::Mint(req) = mint_frame(vec![set("a")]) else {
            unreachable!()
        };
        let admitted = admit_mint(&req, Some(cfg)).unwrap();
        let (reply, live) = m.mint(&admitted);
        assert_eq!(
            reply,
            MintReply::Refused(MintRefusal::Recipient),
            "the minter ran, and found no recipient key"
        );
        assert!(live.tokens.is_empty());
        m.revoke_all(live);

        let EgressFrame::Revoke(r) = revoke_frame() else {
            unreachable!()
        };
        let agent = AgentId::parse("coder").unwrap();
        assert_eq!(
            m.revoke(&r, &agent, &cfg.github_apps["deploy"]),
            RevokeReply::Refused(MintRefusal::Request),
            "a blob not sealed to this key does not open"
        );
    }

    #[test]
    fn file_reads_go_to_the_minting_loaders() {
        let d = tempfile::tempdir().unwrap();
        assert!(matches!(
            FileReads.minting(&d.path().join(MINTING_FILE)),
            Ok(None)
        ));
        assert!(matches!(
            FileReads.role_id(&d.path().join(MINT_ROLE_ID_FILE)),
            Err(ConfigError::NotFound { .. })
        ));
        assert!(matches!(
            FileReads.secret_id(None),
            Err(VaultError::CredentialSource(_))
        ));
    }

    #[test]
    fn unavailable_minting_refuses_a_direct_mint_and_revoke_and_revokes_nothing() {
        let (_d, api) = dead_vault();
        let reads = Reads::new(Ok(Some(file(MINTING_YAML))), Ok("role"), Err(()));
        let rt = runtime();
        let (m, _egress) = frames_for(state(&reads, &api), &rt);
        let m = m.unwrap();
        let cfg = config();
        let EgressFrame::Mint(req) = mint_frame(vec![set("a")]) else {
            unreachable!()
        };
        let admitted = admit_mint(&req, Some(&cfg)).unwrap();
        let (reply, live) = m.mint(&admitted);
        assert_eq!(reply, MintReply::Refused(MintRefusal::Signer));
        assert!(live.tokens.is_empty());
        assert_eq!(live.api, cfg.github_apps["deploy"].api);

        let EgressFrame::Revoke(r) = revoke_frame() else {
            unreachable!()
        };
        let agent = AgentId::parse("coder").unwrap();
        assert_eq!(
            m.revoke(&r, &agent, &cfg.github_apps["deploy"]),
            RevokeReply::Refused(MintRefusal::Signer)
        );
        recorded();
        m.revoke_all(LiveTokens {
            api: ApiBase::parse("https://127.0.0.1:1").unwrap(),
            label: String::new(),
            tokens: vec![MaknaeSecret::new(Zeroizing::new("ghs_SENTINEL".into())).unwrap()],
        });
        assert_eq!(recorded(), Vec::<String>::new(), "no client, no attempt");
    }

    #[test]
    fn ready_minting_attempts_every_live_token_on_revoke_all() {
        let (_d, api) = dead_vault();
        let reads = Reads::new(Ok(Some(file(MINTING_YAML))), Ok("role"), Ok("secret"));
        let rt = runtime();
        let (m, _egress) = frames_for(state(&reads, &api), &rt);
        recorded();
        m.unwrap().revoke_all(LiveTokens {
            api: ApiBase::parse("https://127.0.0.1:1").unwrap(),
            label: "mint task=\"t\" agent=coder".into(),
            tokens: vec![
                MaknaeSecret::new(Zeroizing::new("ghs_SENTINEL1".into())).unwrap(),
                MaknaeSecret::new(Zeroizing::new("ghs_SENTINEL2".into())).unwrap(),
            ],
        });
        let lines = recorded();
        assert_eq!(lines.len(), 2, "{lines:?}");
        for (set, line) in lines.iter().enumerate() {
            assert!(
                line.starts_with(&format!(
                    "mint task=\"t\" agent=coder set={set}: a minted token could not be revoked: "
                )),
                "{line}"
            );
            assert!(!line.contains("SENTINEL"), "{line}");
        }
    }

    #[test]
    fn a_refusal_right_after_a_fresh_login_is_journalled_naming_the_policy() {
        let (_d, api) = dead_vault();
        let login = ApproleLogin {
            api,
            mount: "approle-mint".into(),
            role_id: "role".into(),
            secret_id: MaknaeSecret::new(Zeroizing::new("SECRET-SENTINEL".into())).unwrap(),
            journal: record,
        };
        recorded();
        login.refused_after_fresh_login();
        assert_eq!(
            recorded(),
            [
                "Transit sign was refused again right after a fresh Vault login: \
              the AppRole's policy may lack Transit sign on this key"
            ]
        );
    }

    #[test]
    fn the_real_signer_over_a_dead_vault_is_a_sign_error() {
        let (_d, api) = dead_vault();
        let signer = ServiceSigner::new(ApproleLogin {
            api,
            mount: "approle-mint".into(),
            role_id: "role".into(),
            secret_id: MaknaeSecret::new(Zeroizing::new("SECRET-SENTINEL".into())).unwrap(),
            journal: record,
        });
        recorded();
        assert_eq!(
            runtime().block_on(signer.sign("transit", "deploy-app", b"a.b")),
            Err(SignError)
        );
        let lines = recorded();
        assert!(
            lines.iter().any(|l| l.starts_with("Vault login failed: ")),
            "{lines:?}"
        );
    }

    #[test]
    fn the_signer_minting_state_builds_fails_closed_over_a_dead_vault() {
        let (_d, api) = dead_vault();
        let reads = Reads::new(Ok(Some(file(MINTING_YAML))), Ok("role"), Ok("secret"));
        let MintingState::Ready(signer, _) = state(&reads, &api) else {
            panic!("expected Ready");
        };
        assert_eq!(
            runtime().block_on(signer.sign("transit", "deploy-app", b"a.b")),
            Err(SignError)
        );
    }

    #[test]
    fn only_a_vault_403_is_a_refused_token() {
        let status = |status| VaultError::VaultStatus {
            op: "Transit sign",
            status,
            hint: "",
        };
        assert_eq!(sign_failure(&status(403)), VaultSignError::TokenRefused);
        for e in [
            status(400),
            status(401),
            status(404),
            status(500),
            VaultError::VaultTransport {
                op: "Transit sign",
                detail: "x".into(),
            },
        ] {
            assert_eq!(sign_failure(&e), VaultSignError::Failed, "{e:?}");
        }
    }

    #[test]
    fn the_login_s_debug_names_its_mount_and_never_its_secret() {
        let (_d, api) = dead_vault();
        let login = ApproleLogin {
            api,
            mount: "approle-mint".into(),
            role_id: "ROLE-SENTINEL".into(),
            secret_id: MaknaeSecret::new(Zeroizing::new("SECRET-SENTINEL".into())).unwrap(),
            journal: record,
        };
        let shown = format!("{login:?}");
        assert_eq!(shown, "ApproleLogin { mount: \"approle-mint\", .. }");
    }
}
