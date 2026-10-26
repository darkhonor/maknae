use super::artifact_table::{Artifact, ContentKind, Owner};
use super::artifact_write::{self, emit_yaml, yaml_map, OwnerResolver};
use super::EnrollError;
use clap::Args;
use maknae_config::Value;
use maknae_io::{AnchorRequired, FileOwner, IoError, IoKind, Mode, StrategyPref, TargetRequired};
use maknae_msgs::{msg, Locale, MsgId};
use maknae_vault::agent_enroll::{
    AccountFacts, AgentId, BindCidrs, HostAccounts, DEFAULT_AGENT_APPROLE_MOUNT,
    MAKNAE_DAEMON_ACCOUNTS,
};
use std::path::{Path, PathBuf};
use yaml_rust2::Yaml;
use zeroize::Zeroizing;

/// `maknae enroll agent` — enroll one Agent Daemon on this host.
#[derive(Args, Debug, Clone)]
pub struct AgentArgs {
    /// The agent's id; its AppRole role is `agent-<ID>`.
    #[arg(value_name = "ID")]
    pub id: String,
    /// The service account the Agent Daemon runs as.
    #[arg(long)]
    pub account: String,
    /// An address or CIDR the SecretID may be used from (repeatable).
    #[arg(long = "bind-cidr", required = true)]
    pub bind_cidr: Vec<String>,
    /// The AppRole auth mount the agent's role lives on.
    #[arg(long, default_value = DEFAULT_AGENT_APPROLE_MOUNT)]
    pub approle_mount: String,
    /// Read the Vault token from this file instead of an interactive prompt.
    #[arg(long)]
    pub token_file: Option<PathBuf>,
    /// Replace an enrolled agent's SecretID and destroy the earlier ones.
    #[arg(long)]
    pub rotate: bool,
    /// Print raw operation detail.
    #[arg(long)]
    pub verbose: bool,
}

const PRIVATE_DIR: &str = "/etc/maknae/private";
const ETC_DIR: &str = "/etc/maknae";
const AGENTS_ENTRY: &str = "agents";
const AGENTS_DIR: &str = "/etc/maknae/agents";
const HOST_CONFIG: &str = "/etc/maknae/maknae.yaml";
const VAULT_CA: &str = "/etc/maknae/tls/vault-ca.crt";
const SMALL_FILE: u64 = 64 * 1024;

fn state_file(agent: &AgentId) -> String {
    format!("agent-{}-enroll-state.yaml", agent.as_str())
}

fn record_file(agent_id: &str) -> String {
    format!("{agent_id}.yaml")
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn cred_path(agent: &AgentId) -> PathBuf {
    Path::new(PRIVATE_DIR).join(format!("agent-{}-secret-id.cred", agent.as_str()))
}

pub(crate) fn state_path(agent: &AgentId) -> PathBuf {
    Path::new(PRIVATE_DIR).join(state_file(agent))
}

pub(crate) fn record_path(agent: &AgentId) -> PathBuf {
    Path::new(AGENTS_DIR).join(record_file(agent.as_str()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostEnrollment {
    pub vault_addr: String,
    pub approle_mount: String,
    pub principal_uid: u32,
}

pub(crate) fn parse_host_enrollment(text: &str) -> Result<HostEnrollment, EnrollError> {
    let doc = maknae_config::load_str(text)
        .map_err(|e| EnrollError::State(format!("maknae.yaml: {e:?}")))?;
    let missing = |key: &str| EnrollError::HostNotEnrolled(format!("maknae.yaml has no {key}"));
    let vault = field(&doc, "vault").ok_or_else(|| missing("vault"))?;
    let principal = field(&doc, "principal").ok_or_else(|| missing("principal"))?;
    let vault_addr = str_field(vault, "addr").ok_or_else(|| missing("vault.addr"))?;
    let approle_mount =
        str_field(vault, "approle_mount").ok_or_else(|| missing("vault.approle_mount"))?;
    let principal_uid = match field(principal, "uid") {
        Some(Value::Int(n)) => u32::try_from(*n).ok(),
        _ => None,
    }
    .ok_or_else(|| missing("principal.uid"))?;
    Ok(HostEnrollment {
        vault_addr,
        approle_mount,
        principal_uid,
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AgentState {
    pub approle_mount: String,
    pub role: String,
    pub live: Vec<String>,
    pub pending: Vec<String>,
    pub retiring: Vec<String>,
}

impl AgentState {
    pub(crate) fn to_yaml(&self) -> String {
        emit_yaml(yaml_map(vec![
            ("approle_mount", Yaml::String(self.approle_mount.clone())),
            ("role", Yaml::String(self.role.clone())),
            ("live", yaml_list(&self.live)),
            ("pending", yaml_list(&self.pending)),
            ("retiring", yaml_list(&self.retiring)),
        ]))
    }

    pub(crate) fn parse(text: &str) -> Result<Self, EnrollError> {
        const WHAT: &str = "agent enroll state";
        let doc = load(text, WHAT)?;
        Ok(Self {
            approle_mount: req_str(&doc, "approle_mount", WHAT)?,
            role: req_str(&doc, "role", WHAT)?,
            live: req_list(&doc, "live", WHAT)?,
            pending: req_list(&doc, "pending", WHAT)?,
            retiring: req_list(&doc, "retiring", WHAT)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SecretSource {
    Tpm2,
    Keychain,
}

impl SecretSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Tpm2 => "tpm2",
            Self::Keychain => "keychain",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentRecord {
    pub agent_id: String,
    pub account: String,
    pub uid: u32,
    pub approle_mount: String,
    pub role_name: String,
    pub role_id: String,
    pub bind_cidrs: Vec<String>,
    pub source: SecretSource,
}

impl AgentRecord {
    pub(crate) fn to_yaml(&self) -> String {
        emit_yaml(yaml_map(vec![
            ("agent_id", Yaml::String(self.agent_id.clone())),
            ("account", Yaml::String(self.account.clone())),
            ("uid", Yaml::Integer(i64::from(self.uid))),
            ("approle_mount", Yaml::String(self.approle_mount.clone())),
            ("role_name", Yaml::String(self.role_name.clone())),
            ("role_id", Yaml::String(self.role_id.clone())),
            ("bind_cidrs", yaml_list(&self.bind_cidrs)),
            ("source", Yaml::String(self.source.as_str().to_string())),
        ]))
    }

    pub(crate) fn parse(text: &str) -> Result<Self, EnrollError> {
        const WHAT: &str = "agent record";
        let doc = load(text, WHAT)?;
        let uid = match field(&doc, "uid") {
            Some(Value::Int(n)) => u32::try_from(*n).ok(),
            _ => None,
        }
        .ok_or_else(|| EnrollError::State(format!("{WHAT}: uid is not a uid")))?;
        let source = match req_str(&doc, "source", WHAT)?.as_str() {
            "tpm2" => SecretSource::Tpm2,
            "keychain" => SecretSource::Keychain,
            other => {
                return Err(EnrollError::State(format!(
                    "{WHAT}: unknown source {other:?}"
                )))
            }
        };
        Ok(Self {
            agent_id: req_str(&doc, "agent_id", WHAT)?,
            account: req_str(&doc, "account", WHAT)?,
            uid,
            approle_mount: req_str(&doc, "approle_mount", WHAT)?,
            role_name: req_str(&doc, "role_name", WHAT)?,
            role_id: req_str(&doc, "role_id", WHAT)?,
            bind_cidrs: req_list(&doc, "bind_cidrs", WHAT)?,
            source,
        })
    }
}

fn yaml_list(items: &[String]) -> Yaml {
    Yaml::Array(items.iter().cloned().map(Yaml::String).collect())
}

fn load(text: &str, what: &str) -> Result<Value, EnrollError> {
    let doc =
        maknae_config::load_str(text).map_err(|e| EnrollError::State(format!("{what}: {e:?}")))?;
    match doc {
        Value::Map(_) => Ok(doc),
        _ => Err(EnrollError::State(format!("{what} is not a map"))),
    }
}

fn field<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    match field(v, key) {
        Some(Value::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

fn req_str(doc: &Value, key: &str, what: &str) -> Result<String, EnrollError> {
    str_field(doc, key).ok_or_else(|| EnrollError::State(format!("{what}: {key} is missing")))
}

fn req_list(doc: &Value, key: &str, what: &str) -> Result<Vec<String>, EnrollError> {
    let bad = || EnrollError::State(format!("{what}: {key} is not a list of strings"));
    match field(doc, key) {
        Some(Value::Seq(items)) => items
            .iter()
            .map(|i| match i {
                Value::Str(s) => Ok(s.clone()),
                _ => Err(bad()),
            })
            .collect(),
        _ => Err(bad()),
    }
}

pub(crate) trait AgentOps {
    async fn read_role_id(&self, mount: &str, role: &str) -> Result<String, EnrollError>;
    async fn mint(
        &self,
        mount: &str,
        role: &str,
        cidrs: &BindCidrs,
    ) -> Result<(Zeroizing<String>, String), EnrollError>;
    async fn destroy(&self, mount: &str, role: &str, accessor: &str) -> Result<(), EnrollError>;
    async fn list_accessors(&self, mount: &str, role: &str) -> Result<Vec<String>, EnrollError>;
    async fn seal(
        &self,
        agent: &AgentId,
        secret: &Zeroizing<String>,
    ) -> Result<SecretSource, EnrollError>;
    fn write_state(&self, agent: &AgentId, state: &AgentState) -> Result<(), EnrollError>;
    fn write_record(&self, record: &AgentRecord) -> Result<(), EnrollError>;
}

pub(crate) struct AgentPlan {
    pub agent: AgentId,
    pub account: String,
    pub uid: u32,
    pub mount: String,
    pub cidrs: BindCidrs,
    pub rotate: bool,
}

#[derive(Debug)]
pub(crate) struct AgentOutcome {
    pub record: AgentRecord,
    pub retired: usize,
}

pub(crate) async fn enroll_agent<O: AgentOps>(
    ops: &O,
    plan: &AgentPlan,
    host: &HostEnrollment,
    prior_record: Option<&AgentRecord>,
    prior_state: AgentState,
) -> Result<AgentOutcome, EnrollError> {
    let id = plan.agent.as_str();
    let refuse =
        |field: &'static str, recorded: &str, given: &str| EnrollError::AgentRekeyRefused {
            agent: id.to_string(),
            field,
            recorded: recorded.to_string(),
            given: given.to_string(),
        };
    if plan.mount == host.approle_mount {
        return Err(EnrollError::AgentMountIsDaemons(plan.mount.clone()));
    }
    if let Some(r) = prior_record {
        if !plan.rotate {
            return Err(EnrollError::AgentAlreadyEnrolled(id.to_string()));
        }
        if r.account != plan.account {
            return Err(refuse("account", &r.account, &plan.account));
        }
        if r.approle_mount != plan.mount {
            return Err(refuse("approle_mount", &r.approle_mount, &plan.mount));
        }
    }
    if !prior_state.approle_mount.is_empty() && prior_state.approle_mount != plan.mount {
        return Err(refuse(
            "approle_mount",
            &prior_state.approle_mount,
            &plan.mount,
        ));
    }

    let mount = plan.mount.as_str();
    let role = plan.agent.role_name();
    let role_id = ops.read_role_id(mount, &role).await?;
    let (secret, acc) = ops.mint(mount, &role, &plan.cidrs).await?;

    let base = AgentState {
        approle_mount: plan.mount.clone(),
        role: role.clone(),
        ..prior_state
    };
    let mut pending = base.clone();
    pending.pending.push(acc.clone());
    if let Err(e) = ops.write_state(&plan.agent, &pending) {
        drop(secret);
        return Err(match ops.destroy(mount, &role, &acc).await {
            Ok(()) => e,
            Err(_) => EnrollError::AgentOrphanedAccessor {
                accessor: acc,
                cause: e.to_string(),
                recorded: false,
            },
        });
    }

    let sealed = ops.seal(&plan.agent, &secret).await;
    drop(secret);
    let source = match sealed {
        Ok(source) => source,
        Err(e) => {
            return Err(match ops.destroy(mount, &role, &acc).await {
                Ok(()) => {
                    let _ = ops.write_state(&plan.agent, &base);
                    e
                }
                Err(_) => EnrollError::AgentOrphanedAccessor {
                    accessor: acc,
                    cause: e.to_string(),
                    recorded: true,
                },
            });
        }
    };

    let listed = ops.list_accessors(mount, &role).await?;
    let retiring: Vec<String> = dedup(
        base.live
            .iter()
            .chain(&base.pending)
            .chain(&base.retiring)
            .chain(&listed),
    )
    .into_iter()
    .filter(|a| *a != acc)
    .collect();
    let record = AgentRecord {
        agent_id: id.to_string(),
        account: plan.account.clone(),
        uid: plan.uid,
        approle_mount: plan.mount.clone(),
        role_name: role.clone(),
        role_id,
        bind_cidrs: plan.cidrs.as_slice().to_vec(),
        source,
    };
    ops.write_record(&record)?;
    let live = AgentState {
        live: vec![acc],
        pending: Vec::new(),
        retiring: retiring.clone(),
        ..base
    };
    ops.write_state(&plan.agent, &live)?;

    let mut failures = Vec::new();
    for a in &retiring {
        if ops.destroy(mount, &role, a).await.is_err() {
            failures.push(a.clone());
        }
    }
    let retired = retiring.len() - failures.len();
    let done = AgentState {
        retiring: failures.clone(),
        ..live
    };
    ops.write_state(&plan.agent, &done)?;
    if !failures.is_empty() {
        return Err(EnrollError::AgentRetireFailed {
            agent: id.to_string(),
            accessors: failures,
        });
    }
    Ok(AgentOutcome { record, retired })
}

fn dedup<'a>(items: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for i in items {
        if !out.contains(i) {
            out.push(i.clone());
        }
    }
    out
}

fn io_error(path: &Path, e: IoError) -> EnrollError {
    EnrollError::Io {
        path: path.to_path_buf(),
        source: e.to_string(),
    }
}

fn is_not_found(e: &IoError) -> bool {
    matches!(
        e,
        IoError::Io {
            kind: IoKind::NotFound,
            ..
        }
    )
}

fn root_file(mode_mask: u32, max_bytes: u64) -> TargetRequired {
    TargetRequired {
        owner: Some(0),
        mode_mask: Some(mode_mask),
        nlink_exactly_one: true,
        regular_file: true,
        max_bytes: Some(max_bytes),
    }
}

fn utf8(path: &Path, bytes: &[u8]) -> Result<String, EnrollError> {
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| EnrollError::State(format!("{} is not UTF-8", path.display())))
}

fn redact(raw: Zeroizing<String>, secret: &str) -> String {
    raw.replace(secret, "<redacted>")
}

fn render(args: std::fmt::Arguments<'_>) -> Zeroizing<String> {
    struct Count(usize);
    impl std::fmt::Write for Count {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            self.0 += s.len();
            Ok(())
        }
    }
    let mut n = Count(0);
    let _ = std::fmt::write(&mut n, args);
    let mut out = Zeroizing::new(String::with_capacity(n.0));
    let _ = std::fmt::write(&mut *out, args);
    out
}

fn scrub_secret(e: EnrollError, secret: &Zeroizing<String>) -> EnrollError {
    let secret = secret.as_str();
    if secret.is_empty() {
        return e;
    }
    let r = |t: String| redact(Zeroizing::new(t), secret);
    let e = match e {
        EnrollError::Command { program, detail } => EnrollError::Command {
            program: r(program),
            detail: r(detail),
        },
        EnrollError::Owner(m) => EnrollError::Owner(r(m)),
        EnrollError::State(m) => EnrollError::State(r(m)),
        EnrollError::Io { path, source } => EnrollError::Io {
            path,
            source: r(source),
        },
        EnrollError::HrotUnavailable { detail } => {
            EnrollError::HrotUnavailable { detail: r(detail) }
        }
        #[cfg(target_os = "macos")]
        EnrollError::Keychain { op, detail } => EnrollError::Keychain {
            op,
            detail: r(detail),
        },
        #[cfg(target_os = "macos")]
        EnrollError::NotDeveloperIdSigned { binary, reason } => EnrollError::NotDeveloperIdSigned {
            binary,
            reason: r(reason),
        },
        #[cfg(target_os = "macos")]
        EnrollError::NotRootInstalled { path, detail } => EnrollError::NotRootInstalled {
            path,
            detail: r(detail),
        },
        other => other,
    };
    if render(format_args!("{e} {e:?}")).contains(secret) {
        EnrollError::State(redact(render(format_args!("{e}")), secret))
    } else {
        e
    }
}

struct RealAgentOps {
    client: maknae_vault::OperatorClient,
    private: maknae_io::Anchor,
    agents: maknae_io::Anchor,
    daemon_gid: u32,
    #[cfg(not(target_os = "macos"))]
    verbose: bool,
    #[cfg(target_os = "macos")]
    team: String,
}

impl RealAgentOps {
    #[cfg(not(target_os = "macos"))]
    async fn seal_platform(
        &self,
        agent: &AgentId,
        secret: &str,
    ) -> Result<SecretSource, EnrollError> {
        let path = cred_path(agent);
        super::seal_linux(
            secret.as_bytes(),
            &path,
            maknae_vault::agent_enroll::AGENT_CREDENTIAL_NAME,
            self.verbose,
        )
        .await?;
        let row = Artifact {
            path,
            owner: Owner::RootRoot,
            mode: 0o600,
            content: ContentKind::SealedAgentSecret,
        };
        artifact_write::apply_ownership_and_mode(&row, &RootOnly)?;
        Ok(SecretSource::Tpm2)
    }

    #[cfg(target_os = "macos")]
    async fn seal_platform(
        &self,
        agent: &AgentId,
        secret: &str,
    ) -> Result<SecretSource, EnrollError> {
        super::keychain_write::seal_agent_secret_macos(secret, agent, &self.team).await?;
        Ok(SecretSource::Keychain)
    }
}

impl AgentOps for RealAgentOps {
    async fn read_role_id(&self, mount: &str, role: &str) -> Result<String, EnrollError> {
        Ok(self.client.read_role_id(mount, role).await?)
    }

    async fn mint(
        &self,
        mount: &str,
        role: &str,
        cidrs: &BindCidrs,
    ) -> Result<(Zeroizing<String>, String), EnrollError> {
        Ok(self.client.mint_bound_secret_id(mount, role, cidrs).await?)
    }

    async fn destroy(&self, mount: &str, role: &str, accessor: &str) -> Result<(), EnrollError> {
        Ok(self
            .client
            .destroy_accessor_if_present(mount, role, accessor)
            .await?)
    }

    async fn list_accessors(&self, mount: &str, role: &str) -> Result<Vec<String>, EnrollError> {
        Ok(self.client.list_secret_id_accessors(mount, role).await?)
    }

    async fn seal(
        &self,
        agent: &AgentId,
        secret: &Zeroizing<String>,
    ) -> Result<SecretSource, EnrollError> {
        self.seal_platform(agent, secret.as_str())
            .await
            .map_err(|e| scrub_secret(e, secret))
    }

    fn write_state(&self, agent: &AgentId, state: &AgentState) -> Result<(), EnrollError> {
        self.private
            .publish_owned(
                Path::new(&state_file(agent)),
                None,
                state.to_yaml().as_bytes(),
                Mode(0o600),
                FileOwner { uid: 0, gid: 0 },
            )
            .map(|_| ())
            .map_err(|e| io_error(&state_path(agent), e))
    }

    fn write_record(&self, record: &AgentRecord) -> Result<(), EnrollError> {
        let agent = AgentId::parse(&record.agent_id)?;
        self.agents
            .publish_owned(
                Path::new(&record_file(agent.as_str())),
                None,
                record.to_yaml().as_bytes(),
                Mode(0o640),
                FileOwner {
                    uid: 0,
                    gid: self.daemon_gid,
                },
            )
            .map(|_| ())
            .map_err(|e| io_error(&record_path(&agent), e))
    }
}

#[cfg(not(target_os = "macos"))]
struct RootOnly;

#[cfg(not(target_os = "macos"))]
impl OwnerResolver for RootOnly {
    fn resolve(
        &self,
        owner: Owner,
    ) -> Result<(Option<nix::unistd::Uid>, Option<nix::unistd::Gid>), EnrollError> {
        match owner {
            Owner::RootRoot => Ok((
                Some(nix::unistd::Uid::from_raw(0)),
                Some(nix::unistd::Gid::from_raw(0)),
            )),
            other => Err(EnrollError::Owner(format!(
                "agent enrollment does not write {other:?} files"
            ))),
        }
    }
}

type OtherAgent = (String, u32);

fn read_records(
    agents: &maknae_io::Anchor,
    agent: &AgentId,
) -> Result<(Option<AgentRecord>, Vec<OtherAgent>), EnrollError> {
    let entries = agents
        .enumerate(Path::new(""), None)
        .map_err(|e| io_error(Path::new(AGENTS_DIR), e))?
        .value;
    let mut prior = None;
    let mut others = Vec::new();
    for entry in entries {
        let Some(name) = entry.name.to_str() else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".yaml") else {
            continue;
        };
        let path = Path::new(AGENTS_DIR).join(name);
        let bytes = agents
            .read(Path::new(name), None, root_file(0o027, SMALL_FILE))
            .map_err(|e| io_error(&path, e))?
            .value;
        let record = AgentRecord::parse(&utf8(&path, &bytes)?)
            .map_err(|e| EnrollError::State(format!("{}: {e}", path.display())))?;
        if record.agent_id != stem {
            return Err(EnrollError::State(format!(
                "{}: records agent {}",
                path.display(),
                record.agent_id
            )));
        }
        if stem == agent.as_str() {
            prior = Some(record);
        } else {
            others.push((record.agent_id, record.uid));
        }
    }
    Ok((prior, others))
}

fn read_state(private: &maknae_io::Anchor, agent: &AgentId) -> Result<AgentState, EnrollError> {
    let path = state_path(agent);
    match private.read(
        Path::new(&state_file(agent)),
        None,
        root_file(0o077, SMALL_FILE),
    ) {
        Ok(out) => AgentState::parse(&utf8(&path, &out.value)?)
            .map_err(|e| EnrollError::State(format!("{}: {e}", path.display()))),
        Err(e) if is_not_found(&e) => Ok(AgentState::default()),
        Err(e) => Err(io_error(&path, e)),
    }
}

fn owner_error(what: &str, e: impl std::fmt::Display) -> EnrollError {
    EnrollError::Owner(format!("{what}: {e}"))
}

fn check_account(
    args: &AgentArgs,
    agent: &AgentId,
    host: &HostEnrollment,
    other_agents: &[(String, u32)],
) -> Result<u32, EnrollError> {
    use nix::unistd::{Group, User};
    let acct = User::from_name(&args.account)
        .map_err(|e| owner_error(&format!("user {}", args.account), e))?
        .map(|u| AccountFacts {
            name: u.name,
            uid: u.uid.as_raw(),
            primary_gid: u.gid.as_raw(),
            shell: u.shell.to_string_lossy().into_owned(),
        });
    let maknae = Group::from_name("maknae")
        .map_err(|e| owner_error("group maknae", e))?
        .ok_or_else(|| EnrollError::Owner("no maknae group".to_string()))?;
    let mut daemon_uids = Vec::new();
    let mut daemon_groups = Vec::new();
    for name in MAKNAE_DAEMON_ACCOUNTS {
        if let Some(uid) =
            maknae_vault::account_uid(name).map_err(|e| owner_error(&format!("user {name}"), e))?
        {
            daemon_uids.push(uid);
        }
        if let Some(g) =
            Group::from_name(name).map_err(|e| owner_error(&format!("group {name}"), e))?
        {
            daemon_groups.push((g.gid.as_raw(), g.mem));
        }
    }
    maknae_vault::agent_enroll::service_account_check(
        acct.as_ref(),
        &args.account,
        agent,
        &HostAccounts {
            maknae_gid: maknae.gid.as_raw(),
            maknae_members: &maknae.mem,
            principal_uid: host.principal_uid,
            daemon_uids: &daemon_uids,
            daemon_groups: &daemon_groups,
            other_agents,
        },
    )?;
    acct.map(|a| a.uid)
        .ok_or_else(|| EnrollError::Owner(format!("no such user: {}", args.account)))
}

fn read_host() -> Result<HostEnrollment, EnrollError> {
    let path = Path::new(HOST_CONFIG);
    let out = maknae_io::read_absolute(
        path,
        TargetRequired {
            owner: Some(0),
            mode_mask: Some(0o022),
            nlink_exactly_one: false,
            regular_file: true,
            max_bytes: Some(1 << 20),
        },
        StrategyPref::Auto,
    )
    .map_err(|e| {
        if is_not_found(&e) {
            EnrollError::HostNotEnrolled(format!("{HOST_CONFIG} does not exist"))
        } else {
            io_error(path, e)
        }
    })?;
    parse_host_enrollment(&utf8(path, &out.value)?)
}

fn check_mount(what: &str, mount: &str) -> Result<(), EnrollError> {
    maknae_config::mount_path_is_acceptable(mount)
        .map_err(|why| EnrollError::InvalidVaultMount(format!("{what} {why}")))?;
    if !maknae_config::vault_path_is_safe(mount) {
        return Err(EnrollError::InvalidVaultMount(format!(
            "{what} has a character outside [A-Za-z0-9._/-]"
        )));
    }
    Ok(())
}

fn agents_dir_check(kind: Option<maknae_io::Kind>) -> Result<(), EnrollError> {
    match kind {
        None | Some(maknae_io::Kind::Dir) => Ok(()),
        Some(_) => Err(EnrollError::State(format!(
            "{AGENTS_DIR} is not a directory; refusing to follow it"
        ))),
    }
}

fn agents_dir_kind() -> Result<Option<maknae_io::Kind>, EnrollError> {
    let etc = open_dir(ETC_DIR, 0o027)?;
    let entries = etc
        .enumerate(Path::new(""), None)
        .map_err(|e| io_error(Path::new(ETC_DIR), e))?
        .value;
    Ok(entries
        .into_iter()
        .find(|e| e.name == AGENTS_ENTRY)
        .map(|e| e.kind))
}

fn open_dir(path: &str, mode_mask: u32) -> Result<maknae_io::Anchor, EnrollError> {
    maknae_io::open_anchor(
        Path::new(path),
        AnchorRequired {
            owner: Some(0),
            mode_mask: Some(mode_mask),
        },
        StrategyPref::Auto,
    )
    .map_err(|e| io_error(Path::new(path), e))
}

#[cfg(target_os = "macos")]
async fn platform_gate() -> Result<String, EnrollError> {
    use super::keychain_write::{check_install_path, own_team, verify_release, AGENT_BINARY};
    let me = std::env::current_exe().map_err(|e| EnrollError::Command {
        program: "current_exe".to_string(),
        detail: e.to_string(),
    })?;
    check_install_path(&me)?;
    let team = own_team().await?;
    check_install_path(Path::new(AGENT_BINARY))?;
    verify_release(
        AGENT_BINARY,
        maknae_vault::agent_enroll::AGENT_SIGNING_IDENTIFIER,
        &team,
    )
    .await?;
    Ok(team)
}

#[cfg(not(target_os = "macos"))]
fn platform_gate(verbose: bool) -> Result<(), EnrollError> {
    if super::detect_hrot_capability(verbose) {
        Ok(())
    } else {
        Err(EnrollError::HrotUnavailable {
            detail: "agent credentials are sealed with systemd-creds --with-key=tpm2; this host has no usable TPM2".to_string(),
        })
    }
}

pub(crate) async fn run_enroll_agent(
    args: &AgentArgs,
    locale: Locale,
) -> Result<String, EnrollError> {
    let euid = nix::unistd::geteuid().as_raw();
    let sudo_uid = super::env_u32("SUDO_UID");
    let sudo_user = std::env::var("SUDO_USER").ok();
    let operator = super::preflight_check(euid, sudo_uid, sudo_user.as_deref(), &super::RealPasswd)
        .inspect_err(|_| eprintln!("{}", msg(locale, MsgId::EnrollPreflightFailed)))?;

    let agent = AgentId::parse(&args.id)?;
    let cidrs = BindCidrs::parse(&args.bind_cidr)?;
    check_mount("--approle-mount", &args.approle_mount)?;

    let host = read_host()?;
    check_mount("maknae.yaml vault.approle_mount", &host.approle_mount)?;

    let resolver = artifact_write::RealOwnerResolver {
        operator_uid: operator.uid,
        operator_gid: operator.gid,
    };
    agents_dir_check(agents_dir_kind()?)?;
    artifact_write::ensure_dir(
        &Artifact {
            path: PathBuf::from(AGENTS_DIR),
            owner: Owner::RootMaknaeGroup,
            mode: 0o750,
            content: ContentKind::Dir,
        },
        &resolver,
    )?;
    let daemon_gid = match resolver.resolve(Owner::RootMaknaeGroup)? {
        (_, Some(gid)) => gid.as_raw(),
        (_, None) => return Err(EnrollError::Owner("no _maknae group".to_string())),
    };
    let agents = open_dir(AGENTS_DIR, 0o022)?;
    let _lock = agents.try_lock_exclusive().map_err(|e| match e {
        IoError::Locked { .. } => {
            EnrollError::State("another maknae enroll agent is running".to_string())
        }
        e => io_error(Path::new(AGENTS_DIR), e),
    })?;
    let private = open_dir(PRIVATE_DIR, 0o027)?;

    let (prior_record, other_agents) = read_records(&agents, &agent)?;
    let prior_state = read_state(&private, &agent)?;
    let uid = check_account(args, &agent, &host, &other_agents)?;

    #[cfg(target_os = "macos")]
    let team = platform_gate().await?;
    #[cfg(not(target_os = "macos"))]
    platform_gate(args.verbose)?;

    let token = super::intake_token_from(args.token_file.as_deref(), locale)?;
    let client = maknae_vault::OperatorClient::new(&host.vault_addr, Path::new(VAULT_CA), token)?;
    let ops = RealAgentOps {
        client,
        private,
        agents,
        daemon_gid,
        #[cfg(not(target_os = "macos"))]
        verbose: args.verbose,
        #[cfg(target_os = "macos")]
        team,
    };
    let plan = AgentPlan {
        agent,
        account: args.account.clone(),
        uid,
        mount: args.approle_mount.clone(),
        cidrs,
        rotate: args.rotate,
    };

    println!(
        "{}",
        msg(locale, MsgId::EnrollAgentStarted).replace("{agent}", plan.agent.as_str())
    );
    let outcome = enroll_agent(&ops, &plan, &host, prior_record.as_ref(), prior_state).await?;
    let mut summary = msg(locale, MsgId::EnrollAgentEnrolled)
        .replace("{agent}", plan.agent.as_str())
        .replace("{role}", &outcome.record.role_name)
        .replace("{cidrs}", &outcome.record.bind_cidrs.join(", "));
    if outcome.retired > 0 {
        summary.push('\n');
        summary.push_str(
            &msg(locale, MsgId::EnrollAgentRetired)
                .replace("{count}", &outcome.retired.to_string()),
        );
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::HashSet;

    const SENTINEL: &str = "5ec7e7aa-0000-4000-8000-5ec7e7aa0000";
    const ROLE_ID: &str = "role-uuid-1111-2222-3333-444455556666";

    #[derive(Default)]
    struct Fake {
        log: RefCell<Vec<String>>,
        fail: RefCell<HashSet<String>>,
        states: RefCell<Vec<AgentState>>,
        written: RefCell<Vec<u8>>,
        sealed: RefCell<Vec<String>>,
        state_calls: Cell<usize>,
        listed: RefCell<Vec<String>>,
    }

    impl Fake {
        fn failing(keys: &[&str]) -> Self {
            let f = Fake::default();
            f.fail
                .borrow_mut()
                .extend(keys.iter().map(|k| k.to_string()));
            f
        }

        fn check(&self, key: &str) -> Result<(), EnrollError> {
            if self.fail.borrow().contains(key) {
                Err(EnrollError::State(format!("{key} failed")))
            } else {
                Ok(())
            }
        }

        fn listing(self, accessors: &[&str]) -> Self {
            *self.listed.borrow_mut() = strings(accessors);
            self
        }

        fn log(&self) -> Vec<String> {
            self.log.borrow().clone()
        }

        fn states(&self) -> Vec<AgentState> {
            self.states.borrow().clone()
        }
    }

    impl AgentOps for Fake {
        async fn read_role_id(&self, _mount: &str, _role: &str) -> Result<String, EnrollError> {
            self.log.borrow_mut().push("read_role_id".into());
            Ok(ROLE_ID.into())
        }

        async fn mint(
            &self,
            mount: &str,
            role: &str,
            cidrs: &BindCidrs,
        ) -> Result<(Zeroizing<String>, String), EnrollError> {
            self.log.borrow_mut().push(format!(
                "mint:{mount}:{role}:{}",
                cidrs.as_slice().join(",")
            ));
            self.check("mint")?;
            Ok((Zeroizing::new(SENTINEL.into()), "acc-new".into()))
        }

        async fn destroy(
            &self,
            _mount: &str,
            _role: &str,
            accessor: &str,
        ) -> Result<(), EnrollError> {
            let key = format!("destroy:{accessor}");
            self.log.borrow_mut().push(key.clone());
            self.check(&key)
        }

        async fn list_accessors(
            &self,
            _mount: &str,
            _role: &str,
        ) -> Result<Vec<String>, EnrollError> {
            self.log.borrow_mut().push("list".into());
            self.check("list")?;
            Ok(self.listed.borrow().clone())
        }

        async fn seal(
            &self,
            _agent: &AgentId,
            secret: &Zeroizing<String>,
        ) -> Result<SecretSource, EnrollError> {
            self.log.borrow_mut().push("seal".into());
            self.sealed.borrow_mut().push(secret.to_string());
            self.check("seal")?;
            Ok(SecretSource::Tpm2)
        }

        fn write_state(&self, _agent: &AgentId, state: &AgentState) -> Result<(), EnrollError> {
            self.log.borrow_mut().push("state".into());
            let n = self.state_calls.get() + 1;
            self.state_calls.set(n);
            self.check(&format!("state#{n}"))?;
            self.states.borrow_mut().push(state.clone());
            self.written
                .borrow_mut()
                .extend_from_slice(state.to_yaml().as_bytes());
            Ok(())
        }

        fn write_record(&self, record: &AgentRecord) -> Result<(), EnrollError> {
            self.log.borrow_mut().push("record".into());
            self.check("record")?;
            self.written
                .borrow_mut()
                .extend_from_slice(record.to_yaml().as_bytes());
            Ok(())
        }
    }

    const MOUNT: &str = "maknae-agent-approle";
    const ROLE: &str = "agent-hobi";

    fn plan(rotate: bool) -> AgentPlan {
        AgentPlan {
            agent: AgentId::parse("hobi").unwrap(),
            account: "hobi-svc".into(),
            uid: 990,
            mount: MOUNT.into(),
            cidrs: BindCidrs::parse(&["10.0.0.5".to_string()]).unwrap(),
            rotate,
        }
    }

    fn host() -> HostEnrollment {
        HostEnrollment {
            vault_addr: "https://vault.example:8200".into(),
            approle_mount: "maknae-approle".into(),
            principal_uid: 1000,
        }
    }

    fn strings(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    fn record() -> AgentRecord {
        AgentRecord {
            agent_id: "hobi".into(),
            account: "hobi-svc".into(),
            uid: 990,
            approle_mount: MOUNT.into(),
            role_name: ROLE.into(),
            role_id: "role-uuid-old".into(),
            bind_cidrs: strings(&["10.0.0.5/32"]),
            source: SecretSource::Tpm2,
        }
    }

    fn prior(live: &[&str], pending: &[&str], retiring: &[&str]) -> (AgentRecord, AgentState) {
        (
            record(),
            AgentState {
                approle_mount: MOUNT.into(),
                role: ROLE.into(),
                live: strings(live),
                pending: strings(pending),
                retiring: strings(retiring),
            },
        )
    }

    fn state(live: &[&str], pending: &[&str], retiring: &[&str]) -> AgentState {
        AgentState {
            approle_mount: MOUNT.into(),
            role: ROLE.into(),
            live: strings(live),
            pending: strings(pending),
            retiring: strings(retiring),
        }
    }

    async fn first(fake: &Fake) -> Result<AgentOutcome, EnrollError> {
        enroll_agent(fake, &plan(false), &host(), None, AgentState::default()).await
    }

    async fn rotate(
        fake: &Fake,
        live: &[&str],
        pending: &[&str],
        retiring: &[&str],
    ) -> Result<AgentOutcome, EnrollError> {
        let (r, s) = prior(live, pending, retiring);
        enroll_agent(fake, &plan(true), &host(), Some(&r), s).await
    }

    #[tokio::test]
    async fn first_enrollment_order() {
        let fake = Fake::default();
        let out = first(&fake).await.unwrap();
        assert_eq!(
            fake.log(),
            strings(&[
                "read_role_id",
                "mint:maknae-agent-approle:agent-hobi:10.0.0.5/32",
                "state",
                "seal",
                "list",
                "record",
                "state",
                "state",
            ])
        );
        assert_eq!(
            fake.states(),
            vec![
                state(&[], &["acc-new"], &[]),
                state(&["acc-new"], &[], &[]),
                state(&["acc-new"], &[], &[]),
            ]
        );
        assert_eq!(out.retired, 0);
        assert_eq!(
            out.record,
            AgentRecord {
                role_id: ROLE_ID.into(),
                ..record()
            }
        );
    }

    #[tokio::test]
    async fn mount_equal_to_maknaeds_is_refused_before_any_call() {
        let fake = Fake::default();
        let mut p = plan(false);
        p.mount = "maknae-approle".into();
        let e = enroll_agent(&fake, &p, &host(), None, AgentState::default())
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentMountIsDaemons(m) if m == "maknae-approle"),
            "{e:?}"
        );
        assert!(fake.log().is_empty());
    }

    #[tokio::test]
    async fn re_enroll_without_rotate_is_refused_before_any_call() {
        let fake = Fake::default();
        let (r, s) = prior(&["a"], &[], &[]);
        let e = enroll_agent(&fake, &plan(false), &host(), Some(&r), s)
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentAlreadyEnrolled(id) if id == "hobi"),
            "{e:?}"
        );
        assert!(fake.log().is_empty());
    }

    #[tokio::test]
    async fn rotate_with_a_different_account_is_refused_before_any_call() {
        let fake = Fake::default();
        let (mut r, s) = prior(&["a"], &[], &[]);
        r.account = "other-svc".into();
        let e = enroll_agent(&fake, &plan(true), &host(), Some(&r), s)
            .await
            .unwrap_err();
        match &e {
            EnrollError::AgentRekeyRefused {
                agent,
                field,
                recorded,
                given,
            } => {
                assert_eq!(agent, "hobi");
                assert_eq!(*field, "account");
                assert_eq!(recorded, "other-svc");
                assert_eq!(given, "hobi-svc");
            }
            other => panic!("{other:?}"),
        }
        assert!(fake.log().is_empty());
    }

    #[tokio::test]
    async fn rotate_with_a_different_mount_is_refused_before_any_call() {
        let fake = Fake::default();
        let (mut r, s) = prior(&["a"], &[], &[]);
        r.approle_mount = "old-mount".into();
        let e = enroll_agent(&fake, &plan(true), &host(), Some(&r), s)
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentRekeyRefused { field, recorded, given, .. }
                if *field == "approle_mount" && recorded == "old-mount" && given == MOUNT),
            "{e:?}"
        );
        assert!(fake.log().is_empty());
    }

    #[tokio::test]
    async fn a_state_file_on_a_different_mount_is_refused_before_any_call() {
        let fake = Fake::default();
        let mut s = state(&["a"], &[], &[]);
        s.approle_mount = "old-mount".into();
        let e = enroll_agent(&fake, &plan(false), &host(), None, s)
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentRekeyRefused { field, recorded, .. }
                if *field == "approle_mount" && recorded == "old-mount"),
            "{e:?}"
        );
        assert!(fake.log().is_empty());
    }

    #[tokio::test]
    async fn rotate_retires_everything_previously_recorded() {
        let fake = Fake::default();
        let out = rotate(&fake, &["a"], &["p"], &["r"]).await.unwrap();
        assert_eq!(
            fake.log(),
            strings(&[
                "read_role_id",
                "mint:maknae-agent-approle:agent-hobi:10.0.0.5/32",
                "state",
                "seal",
                "list",
                "record",
                "state",
                "destroy:a",
                "destroy:p",
                "destroy:r",
                "state",
            ])
        );
        assert_eq!(
            fake.states(),
            vec![
                state(&["a"], &["p", "acc-new"], &["r"]),
                state(&["acc-new"], &[], &["a", "p", "r"]),
                state(&["acc-new"], &[], &[]),
            ]
        );
        assert_eq!(out.retired, 3);
    }

    #[tokio::test]
    async fn retiring_deduplicates_the_prior_lists() {
        let fake = Fake::default();
        let out = rotate(&fake, &["a"], &["a", "p"], &["p", "r"])
            .await
            .unwrap();
        assert_eq!(fake.states()[1], state(&["acc-new"], &[], &["a", "p", "r"]));
        assert_eq!(out.retired, 3);
    }

    #[tokio::test]
    async fn a_rerun_after_a_partial_failure_completes() {
        let fake = Fake::default();
        let s = state(&[], &["acc-stale"], &["gone"]);
        let out = enroll_agent(&fake, &plan(false), &host(), None, s)
            .await
            .unwrap();
        assert_eq!(
            fake.log()[7..],
            strings(&["destroy:acc-stale", "destroy:gone", "state"])[..]
        );
        assert_eq!(fake.states().last(), Some(&state(&["acc-new"], &[], &[])));
        assert_eq!(out.retired, 2);
    }

    #[tokio::test]
    async fn a_failed_retire_stays_recorded_and_exits_non_zero() {
        let fake = Fake::failing(&["destroy:b"]);
        let e = rotate(&fake, &["a", "b"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentRetireFailed { agent, accessors }
                if agent == "hobi" && *accessors == strings(&["b"])),
            "{e:?}"
        );
        assert_eq!(
            fake.log()[6..],
            strings(&["state", "destroy:a", "destroy:b", "state"])[..]
        );
        assert_eq!(
            fake.states().last(),
            Some(&state(&["acc-new"], &[], &["b"]))
        );
    }

    #[tokio::test]
    async fn pending_write_failure_destroys_the_new_accessor_and_never_seals() {
        let fake = Fake::failing(&["state#1"]);
        let e = first(&fake).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "state#1 failed"),
            "{e:?}"
        );
        assert_eq!(
            fake.log(),
            strings(&[
                "read_role_id",
                "mint:maknae-agent-approle:agent-hobi:10.0.0.5/32",
                "state",
                "destroy:acc-new",
            ])
        );
        assert!(fake.sealed.borrow().is_empty());
        assert!(fake.states().is_empty());
    }

    #[tokio::test]
    async fn pending_write_failure_with_a_failed_destroy_names_the_orphan() {
        let fake = Fake::failing(&["state#1", "destroy:acc-new"]);
        let e = first(&fake).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentOrphanedAccessor { accessor, cause, recorded: false }
                if accessor == "acc-new" && cause == "state#1 failed"),
            "{e:?}"
        );
        let shown = e.to_string();
        assert!(
            shown.contains("is not recorded")
                && shown.contains("Vault's accessor list")
                && shown.contains("maknae enroll agent --rotate"),
            "{shown}"
        );
        assert!(!shown.contains("pending"), "{shown}");
        assert!(!shown.contains("destroy it in Vault"), "{shown}");
        assert!(!fake.log().contains(&"seal".to_string()));
    }

    #[tokio::test]
    async fn seal_failure_destroys_new_and_restores_prior() {
        let fake = Fake::failing(&["seal"]);
        let e = rotate(&fake, &["a"], &["p"], &["r"]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "seal failed"),
            "{e:?}"
        );
        assert_eq!(
            fake.log(),
            strings(&[
                "read_role_id",
                "mint:maknae-agent-approle:agent-hobi:10.0.0.5/32",
                "state",
                "seal",
                "destroy:acc-new",
                "state",
            ])
        );
        assert_eq!(
            fake.states(),
            vec![
                state(&["a"], &["p", "acc-new"], &["r"]),
                state(&["a"], &["p"], &["r"]),
            ]
        );
    }

    #[tokio::test]
    async fn seal_failure_on_first_enrollment_restores_an_empty_state_with_mount_and_role() {
        let fake = Fake::failing(&["seal"]);
        first(&fake).await.unwrap_err();
        assert_eq!(fake.states().last(), Some(&state(&[], &[], &[])));
    }

    #[tokio::test]
    async fn seal_failure_with_a_failed_destroy_keeps_it_pending_and_names_it() {
        let fake = Fake::failing(&["seal", "destroy:acc-new"]);
        let e = rotate(&fake, &["a"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentOrphanedAccessor { accessor, cause, recorded: true }
                if accessor == "acc-new" && cause == "seal failed"),
            "{e:?}"
        );
        let shown = e.to_string();
        assert!(
            shown.contains("stays recorded under pending")
                && shown.contains("maknae enroll agent --rotate"),
            "{shown}"
        );
        assert!(!shown.contains("not recorded"), "{shown}");
        assert_eq!(
            fake.log().last().map(String::as_str),
            Some("destroy:acc-new")
        );
        let last = fake.states().last().cloned().unwrap();
        assert!(last.pending.contains(&"acc-new".to_string()));
        assert_eq!(last.live, strings(&["a"]));
    }

    #[tokio::test]
    async fn record_write_failure_keeps_the_new_accessor_recorded() {
        let fake = Fake::failing(&["record"]);
        let e = rotate(&fake, &["a"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "record failed"),
            "{e:?}"
        );
        assert!(!fake.log().iter().any(|l| l.starts_with("destroy:")));
        assert_eq!(fake.log().last().map(String::as_str), Some("record"));
        let last = fake.states().last().cloned().unwrap();
        assert!(last.pending.contains(&"acc-new".to_string()));
        assert_eq!(last.live, strings(&["a"]));
    }

    #[tokio::test]
    async fn live_write_failure_destroys_nothing() {
        let fake = Fake::failing(&["state#2"]);
        let e = rotate(&fake, &["a"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "state#2 failed"),
            "{e:?}"
        );
        assert!(!fake.log().iter().any(|l| l.starts_with("destroy:")));
        assert_eq!(fake.states(), vec![state(&["a"], &["acc-new"], &[])]);
    }

    #[tokio::test]
    async fn a_vault_accessor_missing_from_state_is_retired() {
        let fake = Fake::default().listing(&["stray", "acc-new"]);
        let out = first(&fake).await.unwrap();
        assert_eq!(
            fake.log()[4..],
            strings(&["list", "record", "state", "destroy:stray", "state"])[..]
        );
        assert_eq!(
            fake.states(),
            vec![
                state(&[], &["acc-new"], &[]),
                state(&["acc-new"], &[], &["stray"]),
                state(&["acc-new"], &[], &[]),
            ]
        );
        assert_eq!(out.retired, 1);
    }

    #[tokio::test]
    async fn listed_accessors_follow_the_recorded_ones_without_repeats() {
        let fake = Fake::default().listing(&["x", "r", "acc-new", "a", "x"]);
        let out = rotate(&fake, &["a"], &["p"], &["r"]).await.unwrap();
        assert_eq!(
            fake.states()[1],
            state(&["acc-new"], &[], &["a", "p", "r", "x"])
        );
        assert_eq!(out.retired, 4);
    }

    #[tokio::test]
    async fn the_new_accessor_is_never_retired_even_if_listed() {
        let fake = Fake::default().listing(&["acc-new", "a"]);
        let out = rotate(&fake, &["a"], &[], &[]).await.unwrap();
        assert!(!fake.log().contains(&"destroy:acc-new".to_string()));
        assert_eq!(fake.states()[1], state(&["acc-new"], &[], &["a"]));
        assert_eq!(fake.states().last(), Some(&state(&["acc-new"], &[], &[])));
        assert_eq!(out.retired, 1);
    }

    #[tokio::test]
    async fn a_list_failure_after_seal_keeps_the_new_accessor_pending() {
        let fake = Fake::failing(&["list"]).listing(&["stray"]);
        let e = rotate(&fake, &["a"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "list failed"),
            "{e:?}"
        );
        assert!(!fake.log().iter().any(|l| l.starts_with("destroy:")));
        assert!(!fake.log().contains(&"record".to_string()));
        assert_eq!(fake.log().last().map(String::as_str), Some("list"));
        assert_eq!(fake.sealed.borrow().len(), 1);
        assert_eq!(fake.states(), vec![state(&["a"], &["acc-new"], &[])]);
    }

    #[test]
    fn a_percent_encoded_or_unsafe_mount_is_refused() {
        for bad in [
            "%6daknae-approle",
            "a?b",
            "a#b",
            "a b",
            "maknae%2dagent",
            "a;b",
        ] {
            assert!(
                matches!(
                    check_mount("--approle-mount", bad),
                    Err(EnrollError::InvalidVaultMount(ref m)) if m.starts_with("--approle-mount ")
                ),
                "{bad:?}"
            );
        }
        for ok in [DEFAULT_AGENT_APPROLE_MOUNT, "team/agents", "a.b_c-d"] {
            assert!(check_mount("--approle-mount", ok).is_ok(), "{ok:?}");
        }
        assert!(matches!(
            check_mount("--approle-mount", "/x"),
            Err(EnrollError::InvalidVaultMount(_))
        ));
    }

    #[test]
    fn only_an_absent_or_real_agents_directory_is_used() {
        use maknae_io::Kind;
        assert!(agents_dir_check(None).is_ok());
        assert!(agents_dir_check(Some(Kind::Dir)).is_ok());
        for k in [Kind::Symlink, Kind::File, Kind::Other] {
            let e = agents_dir_check(Some(k)).unwrap_err();
            assert!(
                matches!(&e, EnrollError::State(m)
                    if m == "/etc/maknae/agents is not a directory; refusing to follow it"),
                "{k:?}: {e:?}"
            );
        }
    }

    fn assert_no_leak(name: &str, fake: &Fake, result: &Result<AgentOutcome, EnrollError>) {
        let sealed = fake.sealed.borrow().clone();
        assert!(
            sealed.is_empty() || sealed == strings(&[SENTINEL]),
            "{name}: sealed {sealed:?}"
        );
        let written = String::from_utf8(fake.written.borrow().clone()).unwrap();
        assert!(!written.contains(SENTINEL), "{name}: written");
        match result {
            Ok(out) => {
                assert!(!format!("{:?}", out.record).contains(SENTINEL), "{name}");
                assert!(!out.record.to_yaml().contains(SENTINEL), "{name}");
            }
            Err(e) => {
                assert!(!format!("{e}").contains(SENTINEL), "{name}: Display");
                assert!(!format!("{e:?}").contains(SENTINEL), "{name}: Debug");
            }
        }
    }

    #[tokio::test]
    async fn the_secret_reaches_only_seal() {
        let mut sealed_once = 0;
        let fake = Fake::default();
        let r = first(&fake).await;
        assert_no_leak("first", &fake, &r);
        sealed_once += fake.sealed.borrow().len();

        let fake = Fake::default();
        let r = rotate(&fake, &["a"], &["p"], &["r"]).await;
        assert_no_leak("rotate", &fake, &r);
        sealed_once += fake.sealed.borrow().len();

        let fake = Fake::default().listing(&["stray", "acc-new"]);
        let r = rotate(&fake, &["a"], &[], &[]).await;
        assert_no_leak("reconcile", &fake, &r);
        sealed_once += fake.sealed.borrow().len();

        let cases: [(&str, &[&str], bool); 10] = [
            ("retire", &["destroy:a"], true),
            ("pending", &["state#1"], false),
            ("pending+destroy", &["state#1", "destroy:acc-new"], false),
            ("seal", &["seal"], true),
            ("seal+destroy", &["seal", "destroy:acc-new"], true),
            ("record", &["record"], true),
            ("live", &["state#2"], true),
            ("mint", &["mint"], false),
            ("list", &["list"], true),
            ("list+destroy", &["list", "destroy:acc-new"], true),
        ];
        for (name, keys, reaches_seal) in cases {
            let fake = Fake::failing(keys);
            let r = rotate(&fake, &["a"], &[], &[]).await;
            assert!(r.is_err(), "{name}");
            assert_no_leak(name, &fake, &r);
            assert_eq!(
                fake.sealed.borrow().len(),
                usize::from(reaches_seal),
                "{name}"
            );
        }
        assert_eq!(sealed_once, 3);
    }

    #[test]
    fn enroll_agent_prints_nothing() {
        let src = include_str!("agent.rs");
        let start = src
            .lines()
            .position(|l| l.starts_with("pub(crate) async fn enroll_agent"))
            .expect("enroll_agent is defined at top level");
        let body: Vec<&str> = src.lines().skip(start).take_while(|l| *l != "}").collect();
        assert!(body.iter().any(|l| l.contains("ops.seal(")));
        for mac in [
            "println!",
            "eprintln!",
            "print!",
            "eprint!",
            "dbg!",
            "format!",
        ] {
            assert!(
                !body.iter().any(|l| l.contains(mac)),
                "enroll_agent uses {mac}"
            );
        }
    }

    #[test]
    fn state_and_record_yaml_round_trip() {
        let s = state(&["a", "b"], &["p"], &["r1", "r2"]);
        assert_eq!(AgentState::parse(&s.to_yaml()).unwrap(), s);
        let empty = state(&[], &[], &[]);
        assert_eq!(AgentState::parse(&empty.to_yaml()).unwrap(), empty);
        for source in [SecretSource::Tpm2, SecretSource::Keychain] {
            let r = AgentRecord {
                source,
                bind_cidrs: strings(&["10.0.0.5/32", "fd00::/64"]),
                ..record()
            };
            assert_eq!(AgentRecord::parse(&r.to_yaml()).unwrap(), r);
        }
        for bad in [
            "",
            "- a\n",
            "approle_mount: m\nrole: r\nlive: []\npending: []\n",
            "approle_mount: m\nrole: r\nlive: x\npending: []\nretiring: []\n",
            "approle_mount: m\nrole: r\nlive: [1]\npending: []\nretiring: []\n",
            "approle_mount: [\n",
        ] {
            assert!(
                matches!(AgentState::parse(bad), Err(EnrollError::State(_))),
                "{bad:?}"
            );
        }
        let good = record().to_yaml();
        for bad in [
            good.replace("source: tpm2", "source: plaintext"),
            good.replace("uid: 990", "uid: -1"),
            good.replace("uid: 990", "uid: x"),
            good.replace("role_id:", "role_idx:"),
            String::new(),
        ] {
            assert_ne!(bad, good);
            assert!(
                matches!(AgentRecord::parse(&bad), Err(EnrollError::State(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn host_enrollment_parses_build_daemon_yaml_output() {
        let op = crate::enroll::Operator {
            uid: 1000,
            gid: 1000,
            name: "ops".into(),
            home: std::path::PathBuf::from("/home/ops"),
        };
        let text = crate::enroll::build_daemon_yaml(
            "dev-01",
            "https://v.example:8200",
            "maknae-approle",
            "pki_int",
            "userpass",
            None,
            "/var/log/maknae/audit.jsonl",
            false,
            None,
            &op,
            "ml-dsa-87",
        );
        assert_eq!(
            parse_host_enrollment(&text).unwrap(),
            HostEnrollment {
                vault_addr: "https://v.example:8200".into(),
                approle_mount: "maknae-approle".into(),
                principal_uid: 1000,
            }
        );
        let no_principal = text.split("principal:").next().unwrap().to_string();
        assert!(!no_principal.contains("uid"));
        assert!(matches!(
            parse_host_enrollment(&no_principal),
            Err(EnrollError::HostNotEnrolled(_))
        ));
        let no_mount = text.replace("approle_mount:", "approle_mountx:");
        assert!(matches!(
            parse_host_enrollment(&no_mount),
            Err(EnrollError::HostNotEnrolled(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_linux_seal_names_the_agent_credential() {
        let id = AgentId::parse("hobi").unwrap();
        let p = cred_path(&id);
        let (bin, argv) = crate::enroll::seal_argv(
            maknae_vault::agent_enroll::AGENT_CREDENTIAL_NAME,
            p.to_str().unwrap(),
        );
        assert_eq!(bin, "systemd-creds");
        assert_eq!(
            argv,
            [
                "encrypt",
                "--with-key=tpm2",
                "--name=maknae-agent-secret-id",
                "-",
                "/etc/maknae/private/agent-hobi-secret-id.cred"
            ]
        );
    }

    #[test]
    fn agent_paths_never_name_maknaeds_artifacts() {
        let id = AgentId::parse("hobi").unwrap();
        for p in [state_path(&id), record_path(&id)] {
            let s = p.to_string_lossy().into_owned();
            assert!(
                s.contains("hobi")
                    && !s.ends_with("/enroll-state.yaml")
                    && !s.ends_with("/maknae.yaml"),
                "{s}"
            );
        }
        assert_eq!(
            state_path(&id),
            std::path::Path::new("/etc/maknae/private/agent-hobi-enroll-state.yaml")
        );
        assert_eq!(
            record_path(&id),
            std::path::Path::new("/etc/maknae/agents/hobi.yaml")
        );
    }

    #[test]
    fn render_sizes_its_buffer_before_writing() {
        let out = render(format_args!("{} {:?}", "abc", "d"));
        assert_eq!(out.as_str(), "abc \"d\"");
        assert_eq!(out.capacity(), out.len());
    }

    #[test]
    fn a_seal_error_never_carries_the_secret() {
        let secret = Zeroizing::new(SENTINEL.to_string());
        let leaked = [
            EnrollError::Command {
                program: "systemd-creds encrypt".into(),
                detail: format!("bad input: {SENTINEL} echoed"),
            },
            EnrollError::Owner(format!("x{SENTINEL}x")),
            EnrollError::State(SENTINEL.into()),
            EnrollError::Io {
                path: std::path::PathBuf::from("/p"),
                source: format!("{SENTINEL} {SENTINEL}"),
            },
            EnrollError::HrotUnavailable {
                detail: SENTINEL.into(),
            },
            EnrollError::Vault(maknae_vault::VaultError::Operator(format!("op {SENTINEL}"))),
        ];
        for e in leaked {
            let scrubbed = scrub_secret(e, &secret);
            let shown = format!("{scrubbed} {scrubbed:?}");
            assert!(!shown.contains(SENTINEL), "{shown}");
            assert!(shown.contains("<redacted>"), "{shown}");
        }
        let clean = scrub_secret(
            EnrollError::Command {
                program: "security".into(),
                detail: "exit 1".into(),
            },
            &secret,
        );
        assert!(matches!(
            clean,
            EnrollError::Command { ref detail, .. } if detail == "exit 1"
        ));
    }
}
