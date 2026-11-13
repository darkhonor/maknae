//! The production [`TaskPlane`](maknae_agent::task_driver::TaskPlane): the agent's
//! loop plane over the kernel's agent socket, under the leaf its AppRole login mints.
use maknae_agent::budget::ContextBudget;
use maknae_agent::drive::{Budget, LoopEvent};
use maknae_agent::task_driver::{self, DriverConfig, DriverEvent};
use maknae_config::{AgentClientConfig, AgentId};
use maknae_crypto::plane_key::PlaneKey;
use maknae_loop::agent::{AgentPlane, PersonaFiles, TaskTrust};
use maknae_loop::keys::AgentKeys;
use maknae_loop::plane::LoopPlane;
use maknae_vault::{AgentLogin, PlaneClient, TrustBundle, VaultError};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

pub const MAX_STEPS: u32 = 8;
pub const MAX_TOOL_CALLS_PER_STEP: u32 = 4;

pub type Plane = AgentPlane<AgentKeys, PersonaFiles>;

pub fn login(config_dir: &Path, cfg: &AgentClientConfig) -> Result<AgentLogin, String> {
    let plane_key = PlaneKey::parse(&cfg.plane_key).ok_or_else(|| {
        format!(
            "agent.yaml: vault.plane_key {:?} is not a plane key algorithm",
            cfg.plane_key
        )
    })?;
    Ok(AgentLogin {
        config_dir: config_dir.to_path_buf(),
        addr: cfg.vault_addr.clone(),
        trust_domain: cfg.trust_domain.clone(),
        pki_int_mount: cfg.pki_int_mount.clone(),
        plane_key,
        approle_mount: cfg.approle_mount.clone(),
        role_id: cfg.role_id.clone(),
        agent: cfg.agent.clone(),
    })
}

pub fn persona_mode(mode: maknae_config::PersonaMode) -> task_driver::PersonaMode {
    match mode {
        maknae_config::PersonaMode::Admin => task_driver::PersonaMode::Admin,
        maknae_config::PersonaMode::SelfAuthored => task_driver::PersonaMode::Own,
    }
}

pub fn driver_config(cfg: &AgentClientConfig, home: &str) -> Result<DriverConfig, String> {
    let context = ContextBudget::new(cfg.provider.context_tokens, cfg.provider.output_tokens)
        .map_err(|e| format!("agent.yaml: provider: {e}"))?;
    Ok(DriverConfig {
        home: home.to_string(),
        persona: persona_mode(cfg.persona),
        budget: Budget {
            max_steps: MAX_STEPS,
            max_tool_calls_per_step: MAX_TOOL_CALLS_PER_STEP,
        },
        context,
    })
}

/// One line per event, naming no task text.
pub fn describe(event: &DriverEvent) -> Option<String> {
    match event {
        DriverEvent::Ended { task, ending } => Some(match task {
            Some(id) => format!("task {id} ended: {ending:?}"),
            None => format!("a delivered task ended: {ending:?}"),
        }),
        DriverEvent::CloseFailed(e) => Some(format!("closing a task's conversation failed: {e:?}")),
        DriverEvent::Loop(LoopEvent::Diagnostic(d)) => Some(d.clone()),
        DriverEvent::Loop(LoopEvent::Stopped(reason)) => {
            Some(format!("a step stopped: {reason:?}"))
        }
        DriverEvent::Loop(_) => None,
    }
}

pub fn task_trust(cfg: &AgentClientConfig, trust: Arc<TrustBundle>) -> TaskTrust {
    TaskTrust {
        trust,
        trust_domain: cfg.trust_domain.clone(),
        agent: cfg.agent.clone(),
    }
}

pub struct Connected {
    pub plane: Plane,
}

pub struct Assembly<'a> {
    pub config_dir: &'a Path,
    pub cfg: &'a AgentClientConfig,
    pub client: Arc<PlaneClient>,
    pub trust: Arc<TrustBundle>,
    pub seal_key: maknae_seal::SealPublicKey,
    pub home: PathBuf,
    pub owner: u32,
}

pub fn connect(a: Assembly<'_>) -> Result<Connected, String> {
    let cfg = a.cfg;
    let mut transport = maknae_config::transport_from_section(None).map_err(|e| e.to_string())?;
    transport.agent_socket_path = cfg.agent_socket_path.clone();
    let write_max = transport.prompt_max_bytes;
    let keys = AgentKeys::new(
        Arc::clone(&a.client),
        cfg.provider.clone(),
        cfg.kv_mount.clone(),
        cfg.agent_prefix.clone(),
        cfg.agent.clone(),
        a.seal_key,
    );
    let output_tokens = cfg.provider.output_tokens;
    let plane = LoopPlane::for_agent(
        transport,
        Arc::clone(&a.trust),
        output_tokens,
        write_max,
        keys,
    )?;
    let trust = task_trust(cfg, a.trust);
    let personas = PersonaFiles {
        config_dir: a.config_dir.to_path_buf(),
        agent: cfg.agent.clone(),
        home: a.home,
        owner: a.owner,
    };
    let note = Box::new(|event: DriverEvent| {
        if let Some(line) = describe(&event) {
            eprintln!("maknae-agentd: {line}");
        }
    });
    Ok(Connected {
        plane: AgentPlane::new(plane, trust, personas, note),
    })
}

pub const MINT_BACKOFF_FIRST: Duration = Duration::from_secs(1);
pub const MINT_BACKOFF_MAX: Duration = Duration::from_secs(60);

pub fn next_backoff(d: Duration) -> Duration {
    (d * 2).min(MINT_BACKOFF_MAX)
}

/// The agent's Vault login, as the daemon's lifecycle uses it.
pub trait Credential: Send + Sync + 'static {
    fn mint(&self) -> impl Future<Output = Result<(), String>> + Send;
    /// Renews the token and rotates the leaf; resolves only when it gives up.
    fn supervise(&self) -> tokio::task::JoinHandle<VaultError>;
    fn revoke(&self) -> impl Future<Output = ()> + Send;
}

impl Credential for PlaneClient {
    async fn mint(&self) -> Result<(), String> {
        PlaneClient::mint(self)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    fn supervise(&self) -> tokio::task::JoinHandle<VaultError> {
        self.spawn_supervisor()
    }
    async fn revoke(&self) {
        self.shutdown().await;
    }
}

/// Mints until a leaf is held; `false` when the stop signal came first.
pub async fn mint_until_held<C: Credential>(cred: &C, stop: &watch::Receiver<bool>) -> bool {
    let mut wait = MINT_BACKOFF_FIRST;
    loop {
        if *stop.borrow() {
            return false;
        }
        match cred.mint().await {
            Ok(()) => return true,
            Err(e) => eprintln!(
                "maknae-agentd: minting the plane leaf failed ({e}); retrying in {}s",
                wait.as_secs()
            ),
        }
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = crate::shutdown::stopped(stop.clone()) => return false,
        }
        wait = next_backoff(wait);
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<VaultError>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Keeps a current leaf: the supervisor renews the token and rotates the leaf before
/// its `not_after`; when it gives up, the login is minted again. On `done` the
/// supervisor is aborted and reaped before this returns.
async fn keep_leaf<C: Credential>(cred: Arc<C>, done: watch::Receiver<bool>) {
    loop {
        let mut supervisor = AbortOnDrop(cred.supervise());
        let gave_up = tokio::select! {
            r = &mut supervisor.0 => r,
            () = crate::shutdown::stopped(done.clone()) => {
                supervisor.0.abort();
                let _ = (&mut supervisor.0).await;
                return;
            }
        };
        match gave_up {
            Ok(e) => {
                eprintln!("maknae-agentd: the plane credential lapsed ({e}); logging in again")
            }
            Err(e) => {
                eprintln!("maknae-agentd: the credential supervisor ended ({e}); logging in again")
            }
        }
        if !mint_until_held(&*cred, &done).await {
            return;
        }
    }
}

/// Runs `serve` with the leaf kept current, then, whatever `serve` returned, stops
/// and reaps the supervisor and revokes the login within `PLANE_SHUTDOWN_BOUND`.
pub async fn run_minted<C, F>(cred: Arc<C>, serve: F) -> Result<(), String>
where
    C: Credential,
    F: Future<Output = Result<(), String>>,
{
    let (done, rx) = watch::channel(false);
    let mut leaf = tokio::spawn(keep_leaf(Arc::clone(&cred), rx));
    let result = serve.await;
    let _ = done.send(true);
    if tokio::time::timeout(maknae_vault::PLANE_HTTP_TIMEOUT, &mut leaf)
        .await
        .is_err()
    {
        leaf.abort();
        let _ = leaf.await;
    }
    if tokio::time::timeout(maknae_vault::PLANE_SHUTDOWN_BOUND, cred.revoke())
        .await
        .is_err()
    {
        eprintln!("maknae-agentd: revoking the plane login did not finish in time");
    }
    result
}

pub fn agent_id(args: &[String]) -> Result<AgentId, String> {
    match args {
        [id] => AgentId::parse(id).map_err(|e| format!("{id:?} is not an agent id: {}", e.0)),
        _ => Err("usage: maknae-agentd <agent-id>".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_agent::task_driver::{Ending, VerifyClass};
    use maknae_proto::TaskId;

    fn cfg() -> AgentClientConfig {
        AgentClientConfig {
            agent: AgentId::parse("hobi").unwrap(),
            vault_addr: "https://vault.example:8200".into(),
            approle_mount: "maknae-agent-approle".into(),
            role_id: "role-uuid-1".into(),
            pki_int_mount: "maknae-pki-int".into(),
            plane_key: "ml-dsa-87".into(),
            kv_mount: "maknae-kv".into(),
            agent_prefix: "maknae/agents".into(),
            trust_domain: "maknae.example".into(),
            agent_socket_path: PathBuf::from("/run/maknae-agent/maknaed.sock"),
            provider: maknae_config::AgentProvider {
                provider: "openai".into(),
                model: "gpt-5.6".into(),
                key_subpath: "openai/hobi".into(),
                key_field: "api_key".into(),
                context_tokens: 128_000,
                output_tokens: Some(16_000),
            },
            persona: maknae_config::PersonaMode::SelfAuthored,
        }
    }

    #[test]
    fn the_login_carries_every_agent_yaml_field_and_refuses_an_unknown_key_algorithm() {
        let login = login(Path::new("/etc/maknae"), &cfg()).unwrap();
        assert_eq!(login.config_dir, PathBuf::from("/etc/maknae"));
        assert_eq!(login.addr, "https://vault.example:8200");
        assert_eq!(login.trust_domain, "maknae.example");
        assert_eq!(login.pki_int_mount, "maknae-pki-int");
        assert_eq!(login.plane_key, PlaneKey::MlDsa87);
        assert_eq!(login.approle_mount, "maknae-agent-approle");
        assert_eq!(login.role_id, "role-uuid-1");
        assert_eq!(login.agent.as_str(), "hobi");
        let mut bad = cfg();
        bad.plane_key = "rsa-2048".into();
        assert!(super::login(Path::new("/etc/maknae"), &bad)
            .unwrap_err()
            .contains("rsa-2048"));
    }

    #[test]
    fn the_driver_runs_in_the_agents_home_with_its_persona_mode_and_context() {
        let got = driver_config(&cfg(), "/var/lib/hobi").unwrap();
        assert_eq!(got.home, "/var/lib/hobi");
        assert_eq!(got.persona, task_driver::PersonaMode::Own);
        assert_eq!(
            (got.budget.max_steps, got.budget.max_tool_calls_per_step),
            (MAX_STEPS, MAX_TOOL_CALLS_PER_STEP)
        );
        assert_eq!(
            got.context,
            ContextBudget::new(128_000, Some(16_000)).unwrap()
        );
        assert_eq!(
            persona_mode(maknae_config::PersonaMode::Admin),
            task_driver::PersonaMode::Admin
        );
        let mut huge = cfg();
        huge.provider.context_tokens = u64::MAX;
        assert!(driver_config(&huge, "/var/lib/hobi").is_err());
    }

    #[test]
    fn an_event_line_names_the_task_and_its_ending_and_nothing_else() {
        let id = TaskId([0x29; 16]);
        let line = describe(&DriverEvent::Ended {
            task: Some(id),
            ending: Ending::Unverified(VerifyClass::Key),
        })
        .unwrap();
        assert!(line.contains(&id.to_string()), "{line}");
        assert!(line.contains("Unverified(Key)"), "{line}");
        assert_eq!(
            describe(&DriverEvent::Ended {
                task: None,
                ending: Ending::Undecodable
            }),
            Some("a delivered task ended: Undecodable".into())
        );
        assert_eq!(describe(&DriverEvent::Loop(LoopEvent::Answered)), None);
    }

    #[test]
    fn the_mint_backoff_doubles_from_one_second_to_a_minute() {
        let mut d = MINT_BACKOFF_FIRST;
        let mut seen = vec![d.as_secs()];
        for _ in 0..8 {
            d = next_backoff(d);
            seen.push(d.as_secs());
        }
        assert_eq!(seen, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
    }

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct FakeLogin {
        mint_fails: bool,
        mints: AtomicUsize,
        revoke_hangs: bool,
        supervisor_running: Arc<AtomicBool>,
        revoked_with_supervisor_running: std::sync::Mutex<Vec<bool>>,
    }

    struct Running(Arc<AtomicBool>);
    impl Drop for Running {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    impl Credential for FakeLogin {
        async fn mint(&self) -> Result<(), String> {
            self.mints.fetch_add(1, Ordering::SeqCst);
            if self.mint_fails {
                Err("sentinel-629-vault-down".into())
            } else {
                Ok(())
            }
        }
        fn supervise(&self) -> tokio::task::JoinHandle<VaultError> {
            let flag = Arc::clone(&self.supervisor_running);
            flag.store(true, Ordering::SeqCst);
            tokio::spawn(async move {
                let _running = Running(flag);
                std::future::pending::<VaultError>().await
            })
        }
        async fn revoke(&self) {
            self.revoked_with_supervisor_running
                .lock()
                .unwrap()
                .push(self.supervisor_running.load(Ordering::SeqCst));
            if self.revoke_hangs {
                std::future::pending::<()>().await;
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_supervisor_is_reaped_before_the_login_is_revoked() {
        let login = Arc::new(FakeLogin::default());
        let ran = run_minted(Arc::clone(&login), async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(())
        })
        .await;
        assert_eq!(ran, Ok(()));
        assert_eq!(
            *login.revoked_with_supervisor_running.lock().unwrap(),
            [false]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_after_the_mint_still_reaps_and_revokes() {
        let login = Arc::new(FakeLogin::default());
        let ran = run_minted(Arc::clone(&login), async {
            tokio::task::yield_now().await;
            Err("sentinel-629-connect-failed".to_string())
        })
        .await;
        assert_eq!(ran, Err("sentinel-629-connect-failed".to_string()));
        assert_eq!(
            *login.revoked_with_supervisor_running.lock().unwrap(),
            [false]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_revoke_that_hangs_ends_at_the_shutdown_bound() {
        let login = Arc::new(FakeLogin {
            revoke_hangs: true,
            ..Default::default()
        });
        let start = tokio::time::Instant::now();
        let ran = run_minted(Arc::clone(&login), async { Ok(()) }).await;
        assert_eq!(ran, Ok(()));
        assert_eq!(start.elapsed(), maknae_vault::PLANE_SHUTDOWN_BOUND);
        assert_eq!(
            login.revoked_with_supervisor_running.lock().unwrap().len(),
            1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_stop_signal_ends_the_mint_backoff() {
        let login = FakeLogin {
            mint_fails: true,
            ..Default::default()
        };
        let (tx, rx) = crate::shutdown::stop_signal();
        let start = tokio::time::Instant::now();
        let stopper = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(20)).await;
            tx.send(true).unwrap();
        });
        assert!(!mint_until_held(&login, &rx).await);
        stopper.await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_secs(20));
        assert_eq!(
            login.mints.load(Ordering::SeqCst),
            5,
            "1+2+4+8 s of backoff, then the stop"
        );
    }

    #[test]
    fn the_task_trust_is_the_agents_own_id_and_trust_domain() {
        let ca = maknae_vault::test_pki::TestCa::new(PlaneKey::MlDsa87);
        let trust = task_trust(&cfg(), ca.trust());
        assert_eq!(trust.agent.as_str(), "hobi");
        assert_eq!(trust.trust_domain, "maknae.example");
    }

    #[test]
    fn the_daemon_takes_exactly_one_agent_id() {
        let arg = |s: &str| s.to_string();
        assert_eq!(agent_id(&[arg("hobi")]).unwrap().as_str(), "hobi");
        assert!(agent_id(&[]).unwrap_err().contains("usage"));
        assert!(agent_id(&[arg("hobi"), arg("suga")])
            .unwrap_err()
            .contains("usage"));
        assert!(agent_id(&[arg("../etc")]).is_err());
    }
}
