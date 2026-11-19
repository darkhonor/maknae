//! Minting's start-up state and the Egress Daemon's only Vault login (#168, ADR-0038
//! decisions 5 and 7). The re-login state machine is `maknae-deputy`'s `ServiceSigner`.

use crate::serve::MintFrames;
use maknae_config::{
    AgentId, ConfigError, GithubAppConfig, MintingConfig, MINTING_FILE, MINT_ROLE_ID_FILE,
};
use maknae_deputy::mint::admit::AdmittedMint;
use maknae_deputy::mint::github::GithubClient;
use maknae_deputy::mint::minter::{self, LiveTokens, MintDeps};
use maknae_deputy::mint::signer::{ServiceSigner, SignError, VaultLogin, VaultSignError};
use maknae_proto::{MintRefusal, MintReply, RevokeReply, RevokeRequest};
use maknae_seal::SealPrivateKey;
use maknae_vault::{ServiceToken, VaultApi, VaultError};
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

fn journal(line: impl Display) {
    eprintln!("maknae-egress: {line}");
}

pub(crate) struct ApproleLogin {
    api: Arc<VaultApi>,
    mount: String,
    role_id: String,
    secret_id: Zeroizing<String>,
}

impl std::fmt::Debug for ApproleLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApproleLogin")
            .field("mount", &self.mount)
            .finish_non_exhaustive()
    }
}

impl VaultLogin for ApproleLogin {
    type Token = ServiceToken;

    async fn login(&self) -> Result<(ServiceToken, Duration), SignError> {
        match self
            .api
            .approle_login(&self.mount, &self.role_id, &self.secret_id)
            .await
        {
            Ok(login) => Ok((login.token, login.ttl)),
            Err(e) => {
                journal(format_args!("Vault login failed: {e}"));
                Err(SignError)
            }
        }
    }

    async fn sign(
        &self,
        token: &ServiceToken,
        mount: &str,
        key: &str,
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultSignError> {
        self.api
            .transit_sign_rs256(token, mount, key, input)
            .await
            .map_err(|e| {
                journal(format_args!("Transit sign failed: {e}"));
                sign_failure(&e)
            })
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
    fn minting(&self, path: &Path) -> Result<Option<MintingConfig>, ConfigError>;
    fn role_id(&self, path: &Path) -> Result<String, ConfigError>;
    fn secret_id(&self, credentials_dir: Option<&Path>) -> Result<Zeroizing<String>, VaultError>;
}

pub(crate) struct FileReads;

impl MintingReads for FileReads {
    fn minting(&self, path: &Path) -> Result<Option<MintingConfig>, ConfigError> {
        maknae_config::load_minting(path)
    }

    fn role_id(&self, path: &Path) -> Result<String, ConfigError> {
        maknae_config::load_mint_role_id(path)
    }

    fn secret_id(&self, credentials_dir: Option<&Path>) -> Result<Zeroizing<String>, VaultError> {
        maknae_vault::read_egress_secret_id(credentials_dir)
    }
}

#[derive(Debug)]
pub(crate) enum MintingState {
    Off,
    Ready(ServiceSigner<ApproleLogin>, MintingConfig),
    Unavailable(&'static str),
}

pub(crate) fn minting_state(
    egress_dir: &Path,
    credentials_dir: Option<&Path>,
    api: &Arc<VaultApi>,
    read: &dyn MintingReads,
) -> MintingState {
    let config = match read.minting(&egress_dir.join(MINTING_FILE)) {
        Ok(None) => return MintingState::Off,
        Ok(Some(c)) => c,
        Err(e) => return unavailable("minting.yaml could not be loaded", e),
    };
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
    };
    MintingState::Ready(ServiceSigner::new(login), config)
}

fn unavailable(why: &'static str, e: impl Display) -> MintingState {
    journal(format_args!("minting is unavailable: {why}: {e}"));
    MintingState::Unavailable(why)
}

struct Ready {
    config: MintingConfig,
    signer: ServiceSigner<ApproleLogin>,
    github: GithubClient,
    own_key: Arc<SealPrivateKey>,
    egress_dir: PathBuf,
    rt: tokio::runtime::Handle,
}

impl Ready {
    fn deps<'a>(
        &'a self,
        now: u64,
        journal: &'a mut dyn FnMut(&str),
    ) -> MintDeps<'a, ServiceSigner<ApproleLogin>> {
        MintDeps {
            signer: &self.signer,
            github: &self.github,
            own_pub: self.own_key.public_key(),
            own_key: &self.own_key,
            egress_dir: &self.egress_dir,
            now,
            journal,
        }
    }
}

pub(crate) struct EgressMinting {
    ready: Result<Ready, &'static str>,
}

/// The `MintFrames` serve is handed: none when minting is off.
pub(crate) fn frames(
    state: MintingState,
    own_key: Arc<SealPrivateKey>,
    egress_dir: PathBuf,
    rt: tokio::runtime::Handle,
) -> Option<Arc<dyn MintFrames>> {
    let ready = match state {
        MintingState::Off => return None,
        MintingState::Unavailable(why) => Err(why),
        MintingState::Ready(signer, config) => match GithubClient::new() {
            Ok(github) => Ok(Ready {
                config,
                signer,
                github,
                own_key,
                egress_dir,
                rt,
            }),
            Err(e) => {
                journal(format_args!("minting is unavailable: GitHub client: {e:?}"));
                Err("the GitHub client could not be built")
            }
        },
    };
    Some(Arc::new(EgressMinting { ready }))
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
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
                    tokens: Vec::new(),
                },
            )
        };
        let Ok(r) = &self.ready else {
            return refused();
        };
        let Some(now) = unix_now() else {
            journal("mint refused: the clock is before 1970");
            return refused();
        };
        let mut log = |l: &str| journal(l);
        let mut d = r.deps(now, &mut log);
        r.rt.block_on(minter::mint(admitted, &mut d))
    }

    fn revoke(&self, req: &RevokeRequest, agent: &AgentId, app: &GithubAppConfig) -> RevokeReply {
        let Ok(r) = &self.ready else {
            return RevokeReply::Refused(MintRefusal::Signer);
        };
        let mut log = |l: &str| journal(l);
        let mut d = r.deps(unix_now().unwrap_or_default(), &mut log);
        r.rt.block_on(minter::revoke(req, agent, app, &mut d))
    }

    fn revoke_all(&self, live: LiveTokens) {
        if let Ok(r) = &self.ready {
            r.rt.block_on(minter::revoke_all(&r.github, live, &mut |l| journal(l)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serve::tests::{canned_reply, prompt_frame, served_frame};
    use maknae_config::{ApiBase, MintVault};
    use maknae_deputy::mint::admit::admit_mint;
    use maknae_deputy::mint::signer::Signer;
    use maknae_proto::{
        AccessLevel, EgressFrame, EgressSocketReply, GithubPermission, MintRequest, PermissionSet,
        SealedCredentialBytes,
    };
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    fn fips() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| maknae_crypto::init().unwrap());
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
                    api: ApiBase::parse("https://api.github.example").unwrap(),
                    transit_mount: "transit".into(),
                    transit_key: "deploy-app".into(),
                },
            )]),
        }
    }

    struct Reads {
        minting: Result<Option<MintingConfig>, ()>,
        role: Result<&'static str, ()>,
        secret: Result<&'static str, ()>,
        calls: Mutex<Vec<(&'static str, Option<PathBuf>)>>,
    }

    impl Reads {
        fn new(
            minting: Result<Option<MintingConfig>, ()>,
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
        fn minting(&self, path: &Path) -> Result<Option<MintingConfig>, ConfigError> {
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

        fn secret_id(
            &self,
            credentials_dir: Option<&Path>,
        ) -> Result<Zeroizing<String>, VaultError> {
            self.calls
                .lock()
                .unwrap()
                .push(("secret-id", credentials_dir.map(Path::to_owned)));
            self.secret
                .map(|s| Zeroizing::new(s.to_owned()))
                .map_err(|()| VaultError::CredentialSource("SENTINEL".into()))
        }
    }

    const EGRESS: &str = "/etc/maknae/egress";
    const CREDS: &str = "/run/credentials/maknae-egress.service";

    fn state(reads: &Reads, api: &Arc<VaultApi>) -> MintingState {
        minting_state(Path::new(EGRESS), Some(Path::new(CREDS)), api, reads)
    }

    fn runtime() -> tokio::runtime::Runtime {
        crate::runtime().unwrap()
    }

    fn frames_for(
        st: MintingState,
        rt: &tokio::runtime::Runtime,
    ) -> (Option<Arc<dyn MintFrames>>, tempfile::TempDir) {
        let egress = tempfile::tempdir().unwrap();
        let m = frames(
            st,
            Arc::new(SealPrivateKey::generate().unwrap()),
            egress.path().to_owned(),
            rt.handle().clone(),
        );
        (m, egress)
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
        let st = state(&reads, &api);
        assert!(matches!(st, MintingState::Off), "{st:?}");
        assert_eq!(reads.calls(), [("minting", minting_yaml())]);
        assert!(frames_for(st, &runtime()).0.is_none());
    }

    #[test]
    fn an_unreadable_secret_id_is_unavailable_and_provider_path_starts() {
        let (_d, api) = dead_vault();
        let reads = Reads::new(Ok(Some(config())), Ok("role"), Err(()));
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

        let bad_role = Reads::new(Ok(Some(config())), Err(()), Ok("secret"));
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
        let reads = Reads::new(Ok(Some(config())), Ok("role"), Ok("secret"));
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
    fn the_real_signer_over_a_dead_vault_is_a_sign_error() {
        let (_d, api) = dead_vault();
        let signer = ServiceSigner::new(ApproleLogin {
            api,
            mount: "approle-mint".into(),
            role_id: "role".into(),
            secret_id: Zeroizing::new("SECRET-SENTINEL".into()),
        });
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
            secret_id: Zeroizing::new("SECRET-SENTINEL".into()),
        };
        let shown = format!("{login:?}");
        assert_eq!(shown, "ApproleLogin { mount: \"approle-mint\", .. }");
    }
}
