use super::agent_access;
use super::agent_unit;
use super::artifact_table::{Artifact, ContentKind, Owner};
use super::artifact_write::{self, emit_yaml, yaml_map, OwnerResolver};
use super::EnrollError;
use crate::stderr::errln;
use clap::{Args, ValueEnum};
use maknae_config::{AgentClientConfig, AgentProvider, AgentRole, PersonaMode, Value};
use maknae_io::{AnchorRequired, FileOwner, IoError, IoKind, Mode, StrategyPref, TargetRequired};
use maknae_msgs::{msg, Locale, MsgId};
use maknae_vault::agent_enroll::{AgentId, BindCidrs, HostAccounts, DEFAULT_AGENT_APPROLE_MOUNT};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use yaml_rust2::Yaml;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum RoleArg {
    User,
    Guest,
}

impl From<RoleArg> for AgentRole {
    fn from(r: RoleArg) -> Self {
        match r {
            RoleArg::User => AgentRole::User,
            RoleArg::Guest => AgentRole::Guest,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PersonaArg {
    Admin,
    #[value(name = "self")]
    SelfAuthored,
}

impl From<PersonaArg> for PersonaMode {
    fn from(p: PersonaArg) -> Self {
        match p {
            PersonaArg::Admin => PersonaMode::Admin,
            PersonaArg::SelfAuthored => PersonaMode::SelfAuthored,
        }
    }
}

/// `maknae enroll agent` — enroll one Agent Daemon on this host.
#[derive(Args, Debug, Clone)]
pub struct AgentArgs {
    /// The agent's id; its AppRole role is `agent-<ID>`.
    #[arg(value_name = "ID")]
    pub id: String,
    /// The service account the Agent Daemon runs as.
    #[arg(long, required_unless_present = "refresh_access")]
    pub account: Option<String>,
    /// An address or CIDR the SecretID may be used from (repeatable).
    #[arg(long = "bind-cidr", required_unless_present = "refresh_access")]
    pub bind_cidr: Vec<String>,
    /// The role the agent is bound to; an agent is never `admin`.
    #[arg(long, value_enum, default_value_t = RoleArg::User)]
    pub role: RoleArg,
    /// The AppRole auth mount the agent's role lives on.
    #[arg(long, default_value = DEFAULT_AGENT_APPROLE_MOUNT)]
    pub approle_mount: String,
    /// Read the Vault token from this file instead of an interactive prompt.
    #[arg(long)]
    pub token_file: Option<PathBuf>,
    /// The authorized provider the agent's model calls go to.
    #[arg(long, required_unless_present = "refresh_access")]
    pub provider: Option<String>,
    /// The model the agent uses.
    #[arg(long, required_unless_present = "refresh_access")]
    pub model: Option<String>,
    /// Where the agent's API key sits in Vault, below `<agent_prefix>/<ID>/`.
    #[arg(long, required_unless_present = "refresh_access")]
    pub key_subpath: Option<String>,
    /// The field of that secret that holds the API key.
    #[arg(long, required_unless_present = "refresh_access")]
    pub key_field: Option<String>,
    /// The model's context window, in tokens.
    #[arg(long, required_unless_present = "refresh_access")]
    pub context_tokens: Option<u64>,
    /// The most tokens one answer may hold.
    #[arg(long)]
    pub output_tokens: Option<u64>,
    /// Who writes the agent's persona: `admin` (only `persona.md` beside `agent.yaml`) or `self`.
    #[arg(long, value_enum, default_value_t = PersonaArg::Admin)]
    pub persona: PersonaArg,
    /// Replace an enrolled agent's SecretID and destroy the earlier ones.
    #[arg(long)]
    pub rotate: bool,
    /// Grant the enrolled agent's account its read access again; touches no Vault.
    #[arg(long, conflicts_with_all = [
        "account", "bind_cidr", "provider", "model", "key_subpath", "key_field",
        "context_tokens", "output_tokens", "persona", "rotate", "token_file", "role",
        "approle_mount",
    ])]
    pub refresh_access: bool,
    /// Print raw operation detail.
    #[arg(long)]
    pub verbose: bool,
}

pub(crate) const PRIVATE_DIR: &str = "/etc/maknae/private";
pub(crate) const ETC_DIR: &str = "/etc/maknae";
const AGENTS_ENTRY: &str = "agents";
pub(crate) const AGENTS_DIR: &str = "/etc/maknae/agents";
const HOST_CONFIG: &str = "/etc/maknae/maknae.yaml";
const EGRESS_BOUNDS: &str = "/etc/maknae/egress-bounds.yaml";
pub(crate) const VAULT_CA: &str = "/etc/maknae/tls/vault-ca.crt";
#[cfg(target_os = "macos")]
pub(crate) const RELOAD_COMMAND: &str = "sudo launchctl kill SIGHUP system/io.maknae.maknaed";
#[cfg(not(target_os = "macos"))]
pub(crate) const RELOAD_COMMAND: &str = "sudo systemctl reload maknaed";
const SMALL_FILE: u64 = 64 * 1024;

pub(crate) fn state_file(agent: &AgentId) -> String {
    format!("agent-{}-enroll-state.yaml", agent.as_str())
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn cred_path(agent: &AgentId) -> PathBuf {
    Path::new(PRIVATE_DIR).join(format!("agent-{}-secret-id.cred", agent.as_str()))
}

pub(crate) fn state_path(agent: &AgentId) -> PathBuf {
    Path::new(PRIVATE_DIR).join(state_file(agent))
}

pub(crate) fn record_path(agent: &AgentId) -> PathBuf {
    Path::new(AGENTS_DIR)
        .join(agent.as_str())
        .join(maknae_config::ENROLLMENT_FILE)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostEnrollment {
    pub vault_addr: String,
    pub approle_mount: String,
    pub principal_uid: u32,
    pub trust_domain: String,
    pub pki_int_mount: String,
    pub plane_key: String,
    pub agent_socket_path: PathBuf,
    pub prompt_max_bytes: usize,
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
    let trust_domain = field(&doc, "core")
        .and_then(|c| str_field(c, "deployment_id"))
        .or_else(|| str_field(vault, "deployment_id"))
        .ok_or_else(|| missing("core.deployment_id"))?;
    maknae_vault::validate_deployment_id(&trust_domain)?;
    let pki_int_mount = str_field(vault, "pki_int_mount")
        .unwrap_or_else(|| maknae_vault::DEFAULT_PKI_INT_MOUNT.to_string());
    let plane_key = match str_field(vault, "plane_key") {
        None => maknae_crypto::plane_key::PlaneKey::MlDsa87,
        Some(k) => maknae_crypto::plane_key::PlaneKey::parse(&k).ok_or_else(|| {
            EnrollError::State(format!(
                "maknae.yaml: vault.plane_key {k:?} is not a plane key"
            ))
        })?,
    }
    .as_str()
    .to_string();
    let transport = maknae_config::transport_from_section(field(&doc, "transport"))
        .map_err(|e| EnrollError::State(format!("maknae.yaml: {e}")))?;
    Ok(HostEnrollment {
        vault_addr,
        approle_mount,
        principal_uid,
        trust_domain,
        pki_int_mount,
        plane_key,
        agent_socket_path: transport.agent_socket_path,
        prompt_max_bytes: transport.prompt_max_bytes,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientPlan {
    pub kv_mount: String,
    pub agent_prefix: String,
    pub provider: AgentProvider,
    pub persona: PersonaMode,
}

pub(crate) fn client_plan(
    bounds: &maknae_config::EgressBounds,
    args: &AgentArgs,
) -> Result<ClientPlan, EnrollError> {
    let agent_prefix = bounds
        .agent_prefix
        .clone()
        .ok_or(EnrollError::AgentPrefixMissing)?;
    Ok(ClientPlan {
        kv_mount: bounds.kv_mount.clone(),
        agent_prefix,
        provider: AgentProvider {
            provider: given(&args.provider, "--provider")?,
            model: given(&args.model, "--model")?,
            key_subpath: given(&args.key_subpath, "--key-subpath")?,
            key_field: given(&args.key_field, "--key-field")?,
            context_tokens: given(&args.context_tokens, "--context-tokens")?,
            output_tokens: args.output_tokens,
        },
        persona: args.persona.into(),
    })
}

fn given<T: Clone>(v: &Option<T>, flag: &str) -> Result<T, EnrollError> {
    v.clone()
        .ok_or_else(|| EnrollError::State(format!("{flag} is required")))
}

fn yaml_tokens(n: u64) -> Yaml {
    Yaml::Integer(i64::try_from(n).unwrap_or(i64::MAX))
}

pub(crate) fn agent_client_yaml(c: &AgentClientConfig) -> String {
    let s = |v: &str| Yaml::String(v.to_string());
    let mut provider = vec![
        ("provider", s(&c.provider.provider)),
        ("model", s(&c.provider.model)),
        (
            "key",
            yaml_map(vec![
                ("subpath", s(&c.provider.key_subpath)),
                ("field", s(&c.provider.key_field)),
            ]),
        ),
        ("context_tokens", yaml_tokens(c.provider.context_tokens)),
    ];
    if let Some(n) = c.provider.output_tokens {
        provider.push(("output_tokens", yaml_tokens(n)));
    }
    emit_yaml(yaml_map(vec![
        ("agent_id", s(c.agent.as_str())),
        (
            "vault",
            yaml_map(vec![
                ("addr", s(&c.vault_addr)),
                ("approle_mount", s(&c.approle_mount)),
                ("role_id", s(&c.role_id)),
                ("pki_int_mount", s(&c.pki_int_mount)),
                ("plane_key", s(&c.plane_key)),
                ("kv_mount", s(&c.kv_mount)),
                ("agent_prefix", s(&c.agent_prefix)),
            ]),
        ),
        ("trust_domain", s(&c.trust_domain)),
        (
            "agent_socket_path",
            s(&c.agent_socket_path.to_string_lossy()),
        ),
        (
            "prompt_max_bytes",
            Yaml::Integer(i64::try_from(c.prompt_max_bytes).unwrap_or(i64::MAX)),
        ),
        ("provider", yaml_map(provider)),
        ("persona", s(c.persona.key())),
    ]))
}

fn checked_client(client: AgentClientConfig) -> Result<AgentClientConfig, EnrollError> {
    match maknae_config::parse_agent_client(&client.agent, &agent_client_yaml(&client)) {
        Ok(read) if read == client => Ok(client),
        Ok(_) => Err(EnrollError::State(format!(
            "{}/{}/{}: the written file would not read back as written",
            AGENTS_DIR,
            client.agent.as_str(),
            maknae_config::AGENT_CLIENT_FILE
        ))),
        Err(e) => Err(EnrollError::State(e.to_string())),
    }
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
    pub role: AgentRole,
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
            ("role", Yaml::String(self.role.key().to_string())),
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
        let role = req_str(&doc, "role", WHAT)?;
        let role = AgentRole::parse(&role)
            .ok_or_else(|| EnrollError::State(format!("{WHAT}: unknown role {role:?}")))?;
        Ok(Self {
            agent_id: req_str(&doc, "agent_id", WHAT)?,
            account: req_str(&doc, "account", WHAT)?,
            uid,
            approle_mount: req_str(&doc, "approle_mount", WHAT)?,
            role_name: req_str(&doc, "role_name", WHAT)?,
            role_id: req_str(&doc, "role_id", WHAT)?,
            bind_cidrs: req_list(&doc, "bind_cidrs", WHAT)?,
            role,
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

pub(crate) trait AgentVaultOps {
    async fn read_role_id(&self, mount: &str, role: &str) -> Result<String, EnrollError>;
    async fn find_role_id(&self, mount: &str, role: &str) -> Result<Option<String>, EnrollError>;
    async fn destroy(&self, mount: &str, role: &str, accessor: &str) -> Result<(), EnrollError>;
    async fn list_accessors(&self, mount: &str, role: &str) -> Result<Vec<String>, EnrollError>;
    fn write_state(&self, agent: &AgentId, state: &AgentState) -> Result<(), EnrollError>;
    async fn entity(&self, name: &str) -> Result<Option<maknae_vault::EntityFacts>, EnrollError>;
    async fn set_entity_disabled(&self, name: &str, disabled: bool) -> Result<(), EnrollError>;
}

pub(crate) trait AgentOps: AgentVaultOps {
    async fn mint(
        &self,
        mount: &str,
        role: &str,
        cidrs: &BindCidrs,
    ) -> Result<(Zeroizing<String>, String), EnrollError>;
    async fn seal(
        &self,
        agent: &AgentId,
        secret: &Zeroizing<String>,
    ) -> Result<SecretSource, EnrollError>;
    fn write_record(&self, record: &AgentRecord) -> Result<(), EnrollError>;
    fn write_client(&self, client: &AgentClientConfig) -> Result<(), EnrollError>;
    fn grant_access(
        &self,
        agent: &AgentId,
        account: &agent_access::Account,
    ) -> Result<(), EnrollError>;
    fn start_agent(
        &self,
        agent: &AgentId,
        account: &agent_unit::ServiceAccount,
    ) -> Result<(), EnrollError>;
}

pub(crate) fn has_alias_on(entity: &maknae_vault::EntityFacts, mount: &str, role_id: &str) -> bool {
    let want = format!("auth/{}", mount.trim_matches('/'));
    entity
        .aliases
        .iter()
        .any(|a| a.mount_path.trim_matches('/') == want && a.name == role_id)
}

pub(crate) struct AgentPlan {
    pub agent: AgentId,
    pub account: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub mount: String,
    pub cidrs: BindCidrs,
    pub role: AgentRole,
    pub rotate: bool,
    pub client: ClientPlan,
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
    let client = checked_client(AgentClientConfig {
        agent: plan.agent.clone(),
        vault_addr: host.vault_addr.clone(),
        approle_mount: plan.mount.clone(),
        role_id: role_id.clone(),
        pki_int_mount: host.pki_int_mount.clone(),
        plane_key: host.plane_key.clone(),
        kv_mount: plan.client.kv_mount.clone(),
        agent_prefix: plan.client.agent_prefix.clone(),
        trust_domain: host.trust_domain.clone(),
        agent_socket_path: host.agent_socket_path.clone(),
        prompt_max_bytes: host.prompt_max_bytes,
        provider: plan.client.provider.clone(),
        persona: plan.client.persona,
    })?;
    let entity = plan.agent.entity_name();
    let reenable = match ops.entity(&entity).await? {
        Some(facts) if has_alias_on(&facts, mount, &role_id) => facts.disabled,
        _ => {
            return Err(EnrollError::AgentEntityMissing {
                agent: id.to_string(),
                entity,
                mount: plan.mount.clone(),
                remains: Vec::new(),
            })
        }
    };
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
        role: plan.role,
        source,
    };
    ops.write_record(&record)?;
    ops.write_client(&client)?;
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
    if reenable && failures.is_empty() {
        ops.set_entity_disabled(&entity, false).await?;
    }
    let granted = ops.grant_access(
        &plan.agent,
        &agent_access::Account {
            name: plan.account.clone(),
            uid: plan.uid,
        },
    );
    if !failures.is_empty() {
        return Err(EnrollError::AgentRetireFailed {
            agent: id.to_string(),
            accessors: failures,
            access: granted.err().map(Box::new),
        });
    }
    granted?;
    ops.start_agent(
        &plan.agent,
        &agent_unit::ServiceAccount {
            uid: plan.uid,
            gid: plan.gid,
            home: plan.home.clone(),
        },
    )?;
    Ok(AgentOutcome { record, retired })
}

pub(crate) fn dedup<'a>(items: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for i in items {
        if !out.contains(i) {
            out.push(i.clone());
        }
    }
    out
}

pub(crate) fn io_error(path: &Path, e: IoError) -> EnrollError {
    EnrollError::Io {
        path: path.to_path_buf(),
        source: e.to_string(),
    }
}

pub(crate) fn is_not_found(e: &IoError) -> bool {
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

pub(crate) struct RealVault {
    pub(crate) client: maknae_vault::OperatorClient,
    pub(crate) private: maknae_io::Anchor,
}

pub(crate) trait HasVault {
    fn vault(&self) -> &RealVault;
}

impl HasVault for RealVault {
    fn vault(&self) -> &RealVault {
        self
    }
}

impl<T: HasVault> AgentVaultOps for T {
    async fn read_role_id(&self, mount: &str, role: &str) -> Result<String, EnrollError> {
        Ok(self.vault().client.read_role_id(mount, role).await?)
    }

    async fn find_role_id(&self, mount: &str, role: &str) -> Result<Option<String>, EnrollError> {
        Ok(self.vault().client.find_role_id(mount, role).await?)
    }

    async fn destroy(&self, mount: &str, role: &str, accessor: &str) -> Result<(), EnrollError> {
        Ok(self
            .vault()
            .client
            .destroy_accessor_if_present(mount, role, accessor)
            .await?)
    }

    async fn list_accessors(&self, mount: &str, role: &str) -> Result<Vec<String>, EnrollError> {
        Ok(self
            .vault()
            .client
            .list_secret_id_accessors(mount, role)
            .await?)
    }

    fn write_state(&self, agent: &AgentId, state: &AgentState) -> Result<(), EnrollError> {
        self.vault()
            .private
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

    async fn entity(&self, name: &str) -> Result<Option<maknae_vault::EntityFacts>, EnrollError> {
        Ok(self.vault().client.entity(name).await?)
    }

    async fn set_entity_disabled(&self, name: &str, disabled: bool) -> Result<(), EnrollError> {
        Ok(self
            .vault()
            .client
            .set_entity_disabled(name, disabled)
            .await?)
    }
}

struct RealAgentOps {
    vault: RealVault,
    agents: maknae_io::Anchor,
    root: PathBuf,
    runner: Box<dyn agent_access::Run>,
    daemon_gid: u32,
    resolver: artifact_write::RealOwnerResolver,
    #[cfg(not(target_os = "macos"))]
    verbose: bool,
    #[cfg(target_os = "macos")]
    team: String,
}

impl HasVault for RealAgentOps {
    fn vault(&self) -> &RealVault {
        &self.vault
    }
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
    async fn mint(
        &self,
        mount: &str,
        role: &str,
        cidrs: &BindCidrs,
    ) -> Result<(Zeroizing<String>, String), EnrollError> {
        Ok(self
            .vault
            .client
            .mint_bound_secret_id(mount, role, cidrs)
            .await?)
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

    fn write_record(&self, record: &AgentRecord) -> Result<(), EnrollError> {
        let agent = AgentId::parse(&record.agent_id)?;
        artifact_write::ensure_dir(
            &Artifact {
                path: Path::new(AGENTS_DIR).join(agent.as_str()),
                owner: Owner::RootMaknaeGroup,
                mode: 0o750,
                content: ContentKind::Dir,
            },
            &self.resolver,
        )?;
        self.agents
            .publish_owned(
                &Path::new(agent.as_str()).join(maknae_config::ENROLLMENT_FILE),
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

    fn write_client(&self, client: &AgentClientConfig) -> Result<(), EnrollError> {
        let agent = &client.agent;
        let rel = Path::new(agent.as_str()).join(maknae_config::AGENT_CLIENT_FILE);
        self.agents
            .publish_owned(
                &rel,
                None,
                agent_client_yaml(client).as_bytes(),
                Mode(0o640),
                FileOwner {
                    uid: 0,
                    gid: self.daemon_gid,
                },
            )
            .map(|_| ())
            .map_err(|e| io_error(&Path::new(AGENTS_DIR).join(&rel), e))
    }

    fn grant_access(
        &self,
        agent: &AgentId,
        account: &agent_access::Account,
    ) -> Result<(), EnrollError> {
        refresh_access(
            &*self.runner,
            agent_access::Platform::HOST,
            &self.root,
            &self.agents,
            agent,
            account,
        )
    }

    fn start_agent(
        &self,
        agent: &AgentId,
        account: &agent_unit::ServiceAccount,
    ) -> Result<(), EnrollError> {
        start_instance(&*self.runner, agent, account)
    }
}

#[cfg(not(target_os = "macos"))]
fn start_instance(
    r: &dyn agent_access::Run,
    agent: &AgentId,
    account: &agent_unit::ServiceAccount,
) -> Result<(), EnrollError> {
    agent_unit::start(r, agent, || write_drop_in(agent, account))
}

#[cfg(target_os = "macos")]
fn start_instance(
    _r: &dyn agent_access::Run,
    _agent: &AgentId,
    _account: &agent_unit::ServiceAccount,
) -> Result<(), EnrollError> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn write_drop_in(agent: &AgentId, account: &agent_unit::ServiceAccount) -> Result<(), EnrollError> {
    let dir = Path::new(agent_unit::UNIT_DIR).join(agent_unit::drop_in_dir(agent));
    artifact_write::ensure_dir(
        &Artifact {
            path: dir.clone(),
            owner: Owner::RootRoot,
            mode: 0o755,
            content: ContentKind::Dir,
        },
        &RootOnly,
    )?;
    let text = dir.to_string_lossy().into_owned();
    open_dir(&text, 0o022)?
        .publish_owned(
            Path::new(agent_unit::DROP_IN_FILE),
            None,
            agent_unit::drop_in(account).as_bytes(),
            Mode(0o644),
            FileOwner { uid: 0, gid: 0 },
        )
        .map_err(|e| io_error(&dir.join(agent_unit::DROP_IN_FILE), e))?;
    artifact_write::maybe_restorecon(&dir.join(agent_unit::DROP_IN_FILE));
    Ok(())
}

pub(crate) fn refresh_access(
    r: &dyn agent_access::Run,
    platform: agent_access::Platform,
    root: &Path,
    agents: &maknae_io::Anchor,
    agent: &AgentId,
    account: &agent_access::Account,
) -> Result<(), EnrollError> {
    let persona = persona_present(agents, agent)?;
    agent_access::grant(
        r,
        platform,
        agent,
        account,
        &agent_access::grant_entries(root, agent, persona),
    )
}

/// A changed home reaches the instance's drop-in only through `start`.
pub(crate) fn refresh_and_restart(
    r: &dyn agent_access::Run,
    platform: agent_access::Platform,
    root: &Path,
    agents: &maknae_io::Anchor,
    agent: &AgentId,
    account: &agent_access::Account,
    start: impl FnOnce() -> Result<(), EnrollError>,
) -> Result<(), EnrollError> {
    refresh_access(r, platform, root, agents, agent, account)?;
    start()
}

pub(crate) fn readmitted(
    agent: &AgentId,
    recorded: &agent_access::Account,
    admitted: Result<u32, EnrollError>,
) -> Result<agent_access::Account, EnrollError> {
    let current = admitted?;
    if current != recorded.uid {
        return Err(EnrollError::AgentIdentityChanged {
            agent: agent.as_str().to_string(),
            account: recorded.name.clone(),
            recorded: recorded.uid,
            current,
        });
    }
    Ok(recorded.clone())
}

pub(crate) fn enrolled_account(
    agent: &AgentId,
    record: Option<&AgentRecord>,
) -> Result<agent_access::Account, EnrollError> {
    record
        .map(|r| agent_access::Account {
            name: r.account.clone(),
            uid: r.uid,
        })
        .ok_or_else(|| {
            EnrollError::State(format!(
                "agent {} is not enrolled on this host; there is no access to refresh",
                agent.as_str()
            ))
        })
}

pub(crate) fn present_own_files(
    agents: &maknae_io::Anchor,
    agent: &AgentId,
) -> Result<Vec<&'static str>, EnrollError> {
    let entries = agents
        .enumerate(Path::new(agent.as_str()), None)
        .map_err(|e| io_error(&Path::new(AGENTS_DIR).join(agent.as_str()), e))?
        .value;
    Ok(agent_access::own_files()
        .into_iter()
        .filter(|f| {
            entries
                .iter()
                .any(|e| e.name == *f && e.kind == maknae_io::Kind::File)
        })
        .collect())
}

pub(crate) fn persona_present(
    agents: &maknae_io::Anchor,
    agent: &AgentId,
) -> Result<bool, EnrollError> {
    Ok(present_own_files(agents, agent)?.contains(&maknae_config::PERSONA_FILE))
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

pub(crate) fn read_records(
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
        if entry.kind != maknae_io::Kind::Dir || AgentId::parse(name).is_err() {
            continue;
        }
        let rel = Path::new(name).join(maknae_config::ENROLLMENT_FILE);
        let path = Path::new(AGENTS_DIR).join(&rel);
        let bytes = match agents.read(&rel, None, root_file(0o027, SMALL_FILE)) {
            Ok(out) => out.value,
            Err(e) if is_not_found(&e) => continue,
            Err(e) => return Err(io_error(&path, e)),
        };
        let record = AgentRecord::parse(&utf8(&path, &bytes)?)
            .map_err(|e| EnrollError::State(format!("{}: {e}", path.display())))?;
        if record.agent_id != name {
            return Err(EnrollError::State(format!(
                "{}: records agent {}",
                path.display(),
                record.agent_id
            )));
        }
        if name == agent.as_str() {
            prior = Some(record);
        } else {
            others.push((record.agent_id, record.uid));
        }
    }
    Ok((prior, others))
}

pub(crate) fn read_state(
    private: &maknae_io::Anchor,
    agent: &AgentId,
) -> Result<AgentState, EnrollError> {
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

fn named_account(
    requested: &str,
    acct: Option<maknae_io::HostAccount>,
) -> Result<Option<maknae_io::HostAccount>, EnrollError> {
    match acct {
        Some(a) if a.name != requested => Err(EnrollError::Owner(format!(
            "account {requested} shares uid {} with account {}; give the Agent Daemon an account with its own uid",
            a.uid, a.name
        ))),
        other => Ok(other),
    }
}

pub(crate) fn agent_group_command(account: &str) -> String {
    let account = if agent_access::account_name_ok(account) {
        account
    } else {
        "<account>"
    };
    let group = maknae_io::MAKNAE_AGENTS_GROUP;
    if cfg!(target_os = "macos") {
        format!("dseditgroup -o edit -a {account} -t user {group}")
    } else {
        format!("usermod -aG {group} {account}")
    }
}

pub(crate) fn agent_group_create_command() -> String {
    let group = maknae_io::MAKNAE_AGENTS_GROUP;
    if cfg!(target_os = "macos") {
        format!("dseditgroup -o create {group}")
    } else {
        format!("groupadd --system {group}")
    }
}

fn admit_account(
    requested: &str,
    agent: &AgentId,
    acct: Option<maknae_io::HostAccount>,
    host: &HostAccounts<'_>,
    agents_gid: Option<u32>,
    bindings: &maknae_config::Bindings,
    uid_of: &BTreeMap<String, u32>,
) -> Result<u32, EnrollError> {
    let acct = named_account(requested, acct)?;
    maknae_vault::agent_enroll::service_account_check(acct.as_ref(), requested, agent, host)?;
    let acct = acct.ok_or_else(|| EnrollError::Owner(format!("no such user: {requested}")))?;
    if let Some(role) =
        maknae_config::bindings_conflict(bindings, requested, acct.uid, |n| uid_of.get(n).copied())
    {
        return Err(EnrollError::AgentBound {
            agent: agent.as_str().to_string(),
            account: requested.to_string(),
            role,
        });
    }
    let Some(agents_gid) = agents_gid else {
        return Err(EnrollError::AgentGroupMissing {
            group: maknae_io::MAKNAE_AGENTS_GROUP,
        });
    };
    if !acct.named_groups.contains(&agents_gid) {
        return Err(EnrollError::AgentNotInAgentGroup {
            account: requested.to_string(),
            group: maknae_io::MAKNAE_AGENTS_GROUP,
        });
    }
    Ok(acct.uid)
}

fn check_account(
    account: &str,
    agent: &AgentId,
    host: &HostEnrollment,
    other_agents: &[(String, u32)],
) -> Result<agent_unit::ServiceAccount, EnrollError> {
    let acct = match maknae_io::user_by_name(account)
        .map_err(|e| owner_error(&format!("user {account}"), e))?
    {
        Some(u) => maknae_io::host_account(u.uid.as_raw())
            .map_err(|e| owner_error(&format!("user {account}"), e))?,
        None => None,
    };
    let maknae_gid = maknae_io::group_gid(maknae_io::MAKNAE_GROUP)
        .map_err(|e| owner_error("group maknae", e))?
        .ok_or_else(|| EnrollError::Owner("no maknae group".to_string()))?;
    let agents_gid = maknae_io::group_gid(maknae_io::MAKNAE_AGENTS_GROUP)
        .map_err(|e| owner_error("group maknae-agents", e))?;
    let daemons =
        maknae_io::daemon_facts().map_err(|e| owner_error("Maknae daemon accounts", e))?;
    let bindings =
        maknae_config::load_bindings(&Path::new(ETC_DIR).join(maknae_config::BINDINGS_FILE))
            .map_err(|e| EnrollError::Bindings(format!("bindings.yaml: {e}")))?;
    let unit = acct.as_ref().map(|a| (a.primary_gid, a.dir.clone()));
    let uid = admit_account(
        account,
        agent,
        acct,
        &HostAccounts {
            maknae_gid: Some(maknae_gid),
            principal_uid: host.principal_uid,
            daemons: &daemons,
            other_agents,
        },
        agents_gid,
        &bindings,
        &binding_uids(&bindings)?,
    )?;
    let Some((gid, dir)) = unit else {
        return Err(EnrollError::Owner(format!("no such user: {account}")));
    };
    let home = maknae_io::unit_safe_home(&dir).map_err(|why| {
        EnrollError::Owner(format!(
            "account {account}: its home {dir:?} {why}; the Agent Daemon's unit cannot name it"
        ))
    })?;
    Ok(agent_unit::ServiceAccount { uid, gid, home })
}

fn binding_uids(bindings: &maknae_config::Bindings) -> Result<BTreeMap<String, u32>, EnrollError> {
    let mut out = BTreeMap::new();
    for entry in bindings.roles.iter().flatten().flat_map(|(_, e)| e) {
        let maknae_config::BindingEntry::Name(name) = entry else {
            continue;
        };
        if let Some(u) =
            maknae_io::user_by_name(name).map_err(|e| owner_error(&format!("user {name}"), e))?
        {
            out.insert(name.clone(), u.uid.as_raw());
        }
    }
    Ok(out)
}

pub(crate) fn read_host() -> Result<HostEnrollment, EnrollError> {
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

pub(crate) fn check_mount(what: &str, mount: &str) -> Result<(), EnrollError> {
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

pub(crate) fn open_dir(path: &str, mode_mask: u32) -> Result<maknae_io::Anchor, EnrollError> {
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

async fn admit_then_enroll<P, Fut>(
    admit: impl FnOnce() -> Result<agent_unit::ServiceAccount, EnrollError>,
    build: impl FnOnce() -> Fut,
    mut plan: AgentPlan,
    host: &HostEnrollment,
    prior_record: Option<&AgentRecord>,
    prior_state: AgentState,
) -> Result<AgentOutcome, EnrollError>
where
    P: std::ops::Deref,
    P::Target: AgentOps + Sized,
    Fut: std::future::Future<Output = Result<P, EnrollError>>,
{
    let service = admit()?;
    plan.uid = service.uid;
    plan.gid = service.gid;
    plan.home = service.home;
    let ops = build().await?;
    enroll_agent(&*ops, &plan, host, prior_record, prior_state).await
}

fn run_refresh_access(agent: &AgentId, locale: Locale) -> Result<String, EnrollError> {
    agents_dir_check(agents_dir_kind()?)?;
    let agents = open_dir(AGENTS_DIR, 0o022)?;
    let _lock = agents.try_lock_exclusive().map_err(|e| match e {
        IoError::Locked { .. } => {
            EnrollError::State("another maknae enroll agent is running".to_string())
        }
        e => io_error(Path::new(AGENTS_DIR), e),
    })?;
    let (record, others) = read_records(&agents, agent)?;
    let enrolled = enrolled_account(agent, record.as_ref())?;
    let host = read_host()?;
    let (admitted, service) = match check_account(&enrolled.name, agent, &host, &others) {
        Ok(s) => (Ok(s.uid), Some(s)),
        Err(e) => (Err(e), None),
    };
    let account = readmitted(agent, &enrolled, admitted)?;
    let service =
        service.ok_or_else(|| EnrollError::State("the account was not admitted".into()))?;
    refresh_and_restart(
        &agent_access::Host,
        agent_access::Platform::HOST,
        Path::new(ETC_DIR),
        &agents,
        agent,
        &account,
        || start_instance(&agent_access::Host, agent, &service),
    )?;
    Ok(msg(locale, MsgId::EnrollAgentAccessRefreshed)
        .replace("{agent}", agent.as_str())
        .replace("{account}", &account.name))
}

pub(crate) async fn run_enroll_agent(
    args: &AgentArgs,
    locale: Locale,
) -> Result<String, EnrollError> {
    let euid = nix::unistd::geteuid().as_raw();
    let sudo_uid = super::env_u32("SUDO_UID");
    let sudo_user = std::env::var("SUDO_USER").ok();
    let operator = super::preflight_check(euid, sudo_uid, sudo_user.as_deref(), &super::RealPasswd)
        .inspect_err(|_| errln!("{}", msg(locale, MsgId::EnrollPreflightFailed)))?;

    let agent = AgentId::parse(&args.id)?;
    if args.refresh_access {
        return run_refresh_access(&agent, locale);
    }
    let account = given(&args.account, "--account")?;
    let cidrs = BindCidrs::parse(&args.bind_cidr)?;
    check_mount("--approle-mount", &args.approle_mount)?;

    let host = read_host()?;
    check_mount("maknae.yaml vault.approle_mount", &host.approle_mount)?;
    check_mount("maknae.yaml vault.pki_int_mount", &host.pki_int_mount)?;
    let bounds = maknae_config::load_egress_bounds(Path::new(EGRESS_BOUNDS))
        .map_err(|e| EnrollError::State(format!("{EGRESS_BOUNDS}: {e}")))?;
    let client = client_plan(&bounds, args)?;

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
    let plan = AgentPlan {
        agent: agent.clone(),
        account: account.clone(),
        uid: 0,
        gid: 0,
        home: String::new(),
        mount: args.approle_mount.clone(),
        cidrs,
        role: args.role.into(),
        rotate: args.rotate,
        client,
    };
    let outcome = admit_then_enroll(
        || check_account(&account, &agent, &host, &other_agents),
        || async {
            #[cfg(target_os = "macos")]
            let team = platform_gate().await?;
            #[cfg(not(target_os = "macos"))]
            platform_gate(args.verbose)?;

            let token = super::intake_token_from(args.token_file.as_deref(), locale)?;
            let client =
                maknae_vault::OperatorClient::new(&host.vault_addr, Path::new(VAULT_CA), token)?;
            println!(
                "{}",
                msg(locale, MsgId::EnrollAgentStarted).replace("{agent}", agent.as_str())
            );
            Ok(Box::new(RealAgentOps {
                vault: RealVault { client, private },
                agents,
                root: PathBuf::from(ETC_DIR),
                runner: Box::new(agent_access::Host),
                daemon_gid,
                resolver,
                #[cfg(not(target_os = "macos"))]
                verbose: args.verbose,
                #[cfg(target_os = "macos")]
                team,
            }))
        },
        plan,
        &host,
        prior_record.as_ref(),
        prior_state,
    )
    .await?;
    let mut summary = msg(locale, MsgId::EnrollAgentEnrolled)
        .replace("{agent}", &outcome.record.agent_id)
        .replace("{role}", &outcome.record.role_name)
        .replace("{cidrs}", &outcome.record.bind_cidrs.join(", "));
    if outcome.retired > 0 {
        summary.push('\n');
        summary.push_str(
            &msg(locale, MsgId::EnrollAgentRetired)
                .replace("{count}", &outcome.retired.to_string()),
        );
    }
    summary.push('\n');
    summary.push_str(&msg(locale, MsgId::EnrollAgentReload).replace("{command}", RELOAD_COMMAND));
    Ok(summary)
}

#[cfg(test)]
mod named_account_tests {
    use super::*;

    fn acct(name: &str) -> maknae_io::HostAccount {
        maknae_io::HostAccount {
            uid: 990,
            name: name.into(),
            primary_gid: 990,
            shell: "/usr/sbin/nologin".into(),
            dir: "/var/empty".into(),
            named_groups: vec![990],
        }
    }

    #[test]
    fn the_requested_account_passes_through() {
        assert_eq!(
            named_account("hobi-svc", Some(acct("hobi-svc"))).unwrap(),
            Some(acct("hobi-svc"))
        );
        assert_eq!(named_account("hobi-svc", None).unwrap(), None);
    }

    #[test]
    fn a_uid_shared_with_another_name_is_refused() {
        let got = named_account("hobi-svc", Some(acct("toor"))).map_err(|e| e.to_string());
        assert_eq!(
            got,
            Err("account hobi-svc shares uid 990 with account toor; give the Agent Daemon an account with its own uid".into())
        );
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::HashSet;

    const SENTINEL: &str = "5ec7e7aa-0000-4000-8000-5ec7e7aa0000";
    pub(crate) const ROLE_ID: &str = "role-uuid-1111-2222-3333-444455556666";

    #[derive(Default)]
    pub(crate) struct Fake {
        pub(crate) log: RefCell<Vec<String>>,
        pub(crate) fail: RefCell<HashSet<String>>,
        pub(crate) states: RefCell<Vec<AgentState>>,
        written: RefCell<Vec<u8>>,
        sealed: RefCell<Vec<String>>,
        state_calls: Cell<usize>,
        pub(crate) listed: RefCell<Vec<String>>,
        entity: RefCell<Option<Option<maknae_vault::EntityFacts>>>,
        pub(crate) scopes: RefCell<Vec<(String, String)>>,
        pub(crate) present: RefCell<Option<Vec<String>>>,
        pub(crate) clients: RefCell<Vec<maknae_config::AgentClientConfig>>,
    }

    impl Fake {
        pub(crate) fn failing(keys: &[&str]) -> Self {
            let f = Fake::default();
            f.fail
                .borrow_mut()
                .extend(keys.iter().map(|k| k.to_string()));
            f
        }

        pub(crate) fn check(&self, key: &str) -> Result<(), EnrollError> {
            if self.fail.borrow().contains(key) {
                Err(EnrollError::State(format!("{key} failed")))
            } else {
                Ok(())
            }
        }

        pub(crate) fn listing(self, accessors: &[&str]) -> Self {
            *self.listed.borrow_mut() = strings(accessors);
            self
        }

        pub(crate) fn with_entity(self, entity: Option<maknae_vault::EntityFacts>) -> Self {
            *self.entity.borrow_mut() = Some(entity);
            self
        }

        pub(crate) fn log(&self) -> Vec<String> {
            self.log.borrow().clone()
        }

        pub(crate) fn states(&self) -> Vec<AgentState> {
            self.states.borrow().clone()
        }
    }

    impl AgentVaultOps for Fake {
        async fn read_role_id(&self, mount: &str, role: &str) -> Result<String, EnrollError> {
            self.scopes.borrow_mut().push((mount.into(), role.into()));
            self.log.borrow_mut().push("read_role_id".into());
            Ok(ROLE_ID.into())
        }

        async fn find_role_id(
            &self,
            mount: &str,
            role: &str,
        ) -> Result<Option<String>, EnrollError> {
            self.scopes.borrow_mut().push((mount.into(), role.into()));
            self.log.borrow_mut().push("read_role_id".into());
            self.check("find_role_id")?;
            Ok(if self.fail.borrow().contains("role_missing") {
                None
            } else {
                Some(ROLE_ID.into())
            })
        }

        async fn destroy(
            &self,
            mount: &str,
            role: &str,
            accessor: &str,
        ) -> Result<(), EnrollError> {
            self.scopes.borrow_mut().push((mount.into(), role.into()));
            let key = format!("destroy:{accessor}");
            self.log.borrow_mut().push(key.clone());
            self.check(&key)
        }

        async fn list_accessors(
            &self,
            mount: &str,
            role: &str,
        ) -> Result<Vec<String>, EnrollError> {
            self.scopes.borrow_mut().push((mount.into(), role.into()));
            self.log.borrow_mut().push("list".into());
            self.check("list")?;
            Ok(self.listed.borrow().clone())
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

        async fn entity(
            &self,
            name: &str,
        ) -> Result<Option<maknae_vault::EntityFacts>, EnrollError> {
            self.log.borrow_mut().push(format!("entity {name}"));
            self.check("entity")?;
            Ok(match &*self.entity.borrow() {
                Some(configured) => configured.clone(),
                None => Some(healthy(false)),
            })
        }

        async fn set_entity_disabled(&self, name: &str, disabled: bool) -> Result<(), EnrollError> {
            self.log
                .borrow_mut()
                .push(format!("set_entity_disabled {name} {disabled}"));
            self.check("set_entity_disabled")
        }
    }

    impl AgentOps for Fake {
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

        fn write_record(&self, record: &AgentRecord) -> Result<(), EnrollError> {
            self.log.borrow_mut().push("record".into());
            self.check("record")?;
            self.written
                .borrow_mut()
                .extend_from_slice(record.to_yaml().as_bytes());
            Ok(())
        }

        fn write_client(
            &self,
            client: &maknae_config::AgentClientConfig,
        ) -> Result<(), EnrollError> {
            self.log.borrow_mut().push("client".into());
            self.check("client")?;
            self.clients.borrow_mut().push(client.clone());
            self.written
                .borrow_mut()
                .extend_from_slice(agent_client_yaml(client).as_bytes());
            Ok(())
        }

        fn grant_access(
            &self,
            agent: &AgentId,
            account: &agent_access::Account,
        ) -> Result<(), EnrollError> {
            self.log.borrow_mut().push(format!(
                "grant {} {}:{}",
                agent.as_str(),
                account.name,
                account.uid
            ));
            self.check("grant")
        }

        fn start_agent(
            &self,
            agent: &AgentId,
            account: &agent_unit::ServiceAccount,
        ) -> Result<(), EnrollError> {
            self.log.borrow_mut().push(format!(
                "start {} {}:{} {}",
                agent.as_str(),
                account.uid,
                account.gid,
                account.home
            ));
            self.check("start")
        }
    }

    pub(crate) const MOUNT: &str = "maknae-agent-approle";
    pub(crate) const ENTITY_MOUNT: &str = "auth/maknae-agent-approle/";
    pub(crate) const ROLE: &str = "agent-hobi";

    pub(crate) fn entity_facts(
        disabled: bool,
        aliases: &[(&str, &str)],
    ) -> maknae_vault::EntityFacts {
        maknae_vault::EntityFacts {
            id: "entity-id-1".into(),
            disabled,
            aliases: aliases
                .iter()
                .map(|(mount_path, name)| maknae_vault::EntityAlias {
                    mount_path: (*mount_path).into(),
                    name: (*name).into(),
                })
                .collect(),
        }
    }

    pub(crate) fn healthy(disabled: bool) -> maknae_vault::EntityFacts {
        entity_facts(disabled, &[(ENTITY_MOUNT, ROLE_ID)])
    }

    fn provider() -> maknae_config::AgentProvider {
        maknae_config::AgentProvider {
            provider: "openai".into(),
            model: "gpt-5.6".into(),
            key_subpath: "openai/hobi".into(),
            key_field: "api_key".into(),
            context_tokens: 128_000,
            output_tokens: Some(16_000),
        }
    }

    fn client_plan_of() -> ClientPlan {
        ClientPlan {
            kv_mount: "maknae-kv".into(),
            agent_prefix: "maknae/agents".into(),
            provider: provider(),
            persona: maknae_config::PersonaMode::Admin,
        }
    }

    fn plan(rotate: bool) -> AgentPlan {
        AgentPlan {
            agent: AgentId::parse("hobi").unwrap(),
            account: "hobi-svc".into(),
            uid: 990,
            gid: 991,
            home: "/home/hobi-svc".into(),
            mount: MOUNT.into(),
            cidrs: BindCidrs::parse(&["10.0.0.5".to_string()]).unwrap(),
            role: AgentRole::User,
            rotate,
            client: client_plan_of(),
        }
    }

    fn host() -> HostEnrollment {
        HostEnrollment {
            vault_addr: "https://vault.example:8200".into(),
            approle_mount: "maknae-approle".into(),
            principal_uid: 1000,
            trust_domain: "dev-01".into(),
            pki_int_mount: "maknae-pki-int".into(),
            plane_key: "ml-dsa-87".into(),
            agent_socket_path: PathBuf::from("/run/maknae-agent/maknaed.sock"),
            prompt_max_bytes: 524_288,
        }
    }

    fn client_config() -> maknae_config::AgentClientConfig {
        maknae_config::AgentClientConfig {
            agent: AgentId::parse("hobi").unwrap(),
            vault_addr: "https://vault.example:8200".into(),
            approle_mount: MOUNT.into(),
            role_id: ROLE_ID.into(),
            pki_int_mount: "maknae-pki-int".into(),
            plane_key: "ml-dsa-87".into(),
            kv_mount: "maknae-kv".into(),
            agent_prefix: "maknae/agents".into(),
            trust_domain: "dev-01".into(),
            agent_socket_path: PathBuf::from("/run/maknae-agent/maknaed.sock"),
            prompt_max_bytes: 524_288,
            provider: provider(),
            persona: maknae_config::PersonaMode::Admin,
        }
    }

    pub(crate) fn strings(xs: &[&str]) -> Vec<String> {
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
            role: AgentRole::User,
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

    pub(crate) fn state(live: &[&str], pending: &[&str], retiring: &[&str]) -> AgentState {
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
                "entity maknae-agent-hobi",
                "mint:maknae-agent-approle:agent-hobi:10.0.0.5/32",
                "state",
                "seal",
                "list",
                "record",
                "client",
                "state",
                "state",
                "grant hobi hobi-svc:990",
                "start hobi 990:991 /home/hobi-svc",
            ])
        );
        assert_eq!(*fake.clients.borrow(), vec![client_config()]);
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
                "entity maknae-agent-hobi",
                "mint:maknae-agent-approle:agent-hobi:10.0.0.5/32",
                "state",
                "seal",
                "list",
                "record",
                "client",
                "state",
                "destroy:a",
                "destroy:p",
                "destroy:r",
                "state",
                "grant hobi hobi-svc:990",
                "start hobi 990:991 /home/hobi-svc",
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
            fake.log()[9..],
            strings(&[
                "destroy:acc-stale",
                "destroy:gone",
                "state",
                "grant hobi hobi-svc:990",
                "start hobi 990:991 /home/hobi-svc",
            ])[..]
        );
        assert_eq!(fake.states().last(), Some(&state(&["acc-new"], &[], &[])));
        assert_eq!(out.retired, 2);
    }

    #[tokio::test]
    async fn a_failed_retire_stays_recorded_and_exits_non_zero() {
        let fake = Fake::failing(&["destroy:b"]);
        let e = rotate(&fake, &["a", "b"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentRetireFailed { agent, accessors, .. }
                if agent == "hobi" && *accessors == strings(&["b"])),
            "{e:?}"
        );
        assert_eq!(
            fake.log()[7..],
            strings(&[
                "client",
                "state",
                "destroy:a",
                "destroy:b",
                "state",
                "grant hobi hobi-svc:990"
            ])[..]
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
                "entity maknae-agent-hobi",
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
                "entity maknae-agent-hobi",
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
    async fn client_write_failure_keeps_the_new_accessor_recorded() {
        let fake = Fake::failing(&["client"]);
        let e = rotate(&fake, &["a"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "client failed"),
            "{e:?}"
        );
        assert!(!fake.log().iter().any(|l| l.starts_with("destroy:")));
        assert_eq!(fake.log().last().map(String::as_str), Some("client"));
        let last = fake.states().last().cloned().unwrap();
        assert!(last.pending.contains(&"acc-new".to_string()));
        assert_eq!(last.live, strings(&["a"]));
    }

    #[tokio::test]
    async fn a_grant_failure_comes_after_a_complete_enrollment() {
        let fake = Fake::failing(&["grant"]);
        let e = rotate(&fake, &["a"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "grant failed"),
            "{e:?}"
        );
        assert_eq!(
            fake.log().last().map(String::as_str),
            Some("grant hobi hobi-svc:990")
        );
        assert!(fake.log().contains(&"destroy:a".to_string()));
        assert_eq!(fake.states().last(), Some(&state(&["acc-new"], &[], &[])));
    }

    #[tokio::test]
    async fn neither_a_grant_nor_a_retire_failure_starts_the_instance() {
        for failing in [&["grant"][..], &["destroy:a"][..]] {
            let fake = Fake::failing(failing);
            rotate(&fake, &["a"], &[], &[]).await.unwrap_err();
            assert!(
                !fake.log().iter().any(|l| l.starts_with("start")),
                "{failing:?}: {:?}",
                fake.log()
            );
        }
    }

    #[tokio::test]
    async fn a_start_failure_comes_last_and_keeps_the_enrollment() {
        let fake = Fake::failing(&["start"]);
        let e = rotate(&fake, &["a"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "start failed"),
            "{e:?}"
        );
        assert_eq!(
            fake.log().last().map(String::as_str),
            Some("start hobi 990:991 /home/hobi-svc")
        );
        assert_eq!(fake.states().last(), Some(&state(&["acc-new"], &[], &[])));
    }

    #[tokio::test]
    async fn a_grant_failure_never_hides_a_retire_failure() {
        let fake = Fake::failing(&["destroy:b", "grant"]);
        let e = rotate(&fake, &["a", "b"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentRetireFailed { accessors, access: Some(inner), .. }
                if *accessors == strings(&["b"]) && matches!(&**inner, EnrollError::State(m) if m == "grant failed")),
            "{e:?}"
        );
        let text = e.to_string();
        assert!(
            text.contains("could not be destroyed: b") && text.contains("grant failed"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn the_client_config_carries_the_plans_prefix_and_persona() {
        let fake = Fake::default();
        let mut p = plan(false);
        p.client.agent_prefix = "corp/agents".into();
        p.client.kv_mount = "corp-kv".into();
        p.client.persona = maknae_config::PersonaMode::SelfAuthored;
        enroll_agent(&fake, &p, &host(), None, AgentState::default())
            .await
            .unwrap();
        let got = fake.clients.borrow()[0].clone();
        assert_eq!(
            (
                got.agent_prefix.as_str(),
                got.kv_mount.as_str(),
                got.persona
            ),
            (
                "corp/agents",
                "corp-kv",
                maknae_config::PersonaMode::SelfAuthored
            )
        );
    }

    #[tokio::test]
    async fn a_client_config_that_would_not_load_refuses_before_minting() {
        let fake = Fake::default();
        let mut p = plan(false);
        p.client.provider.model = "gpt 5".into();
        let e = enroll_agent(&fake, &p, &host(), None, AgentState::default())
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m.contains("agent.yaml") && m.contains("provider.model")),
            "{e:?}"
        );
        assert!(
            !fake.log().iter().any(|l| l.starts_with("mint")),
            "{:?}",
            fake.log()
        );
        let fake = Fake::default();
        let mut p = plan(false);
        p.client.provider.context_tokens = u64::MAX;
        let e = enroll_agent(&fake, &p, &host(), None, AgentState::default())
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m.ends_with("would not read back as written")),
            "{e:?}"
        );
        assert!(!fake.log().iter().any(|l| l.starts_with("mint")));
    }

    #[test]
    fn client_plan_copies_the_bounds_and_refuses_without_agent_prefix() {
        let mut bounds = maknae_config::EgressBounds {
            call_timeout_ms: maknae_config::DEFAULT_CALL_TIMEOUT_MS,
            kv_mount: "corp-kv".into(),
            user_prefix: "corp/users".into(),
            agent_prefix: Some("corp/agents".into()),
            vault_addr: "https://v.example:8200".into(),
        };
        let args = parse_args(&["--persona", "self", "--output-tokens", "16000"]).unwrap();
        assert_eq!(
            client_plan(&bounds, &args).unwrap(),
            ClientPlan {
                kv_mount: "corp-kv".into(),
                agent_prefix: "corp/agents".into(),
                provider: provider(),
                persona: maknae_config::PersonaMode::SelfAuthored,
            }
        );
        let plain = parse_args(&[]).unwrap();
        let got = client_plan(&bounds, &plain).unwrap();
        assert_eq!(got.persona, maknae_config::PersonaMode::Admin);
        assert_eq!(got.provider.output_tokens, None);
        bounds.agent_prefix = None;
        let e = client_plan(&bounds, &args).unwrap_err();
        assert!(matches!(e, EnrollError::AgentPrefixMissing), "{e:?}");
        assert!(e.to_string().contains("agent_prefix"), "{e}");
    }

    #[test]
    fn the_client_yaml_loads_through_the_daemons_parser() {
        let id = AgentId::parse("hobi").unwrap();
        for persona in [
            maknae_config::PersonaMode::Admin,
            maknae_config::PersonaMode::SelfAuthored,
        ] {
            for output_tokens in [None, Some(16_000)] {
                let mut c = client_config();
                c.persona = persona;
                c.provider.output_tokens = output_tokens;
                let yaml = agent_client_yaml(&c);
                assert_eq!(maknae_config::parse_agent_client(&id, &yaml), Ok(c));
                assert!(
                    yaml.contains(&format!("persona: {}", persona.key())),
                    "{yaml}"
                );
            }
        }
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
            fake.log()[5..],
            strings(&[
                "list",
                "record",
                "client",
                "state",
                "destroy:stray",
                "state",
                "grant hobi hobi-svc:990",
                "start hobi 990:991 /home/hobi-svc",
            ])[..]
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
            "errln!",
            "stderr::",
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
            true,
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
                trust_domain: "dev-01".into(),
                pki_int_mount: "pki_int".into(),
                plane_key: "ml-dsa-87".into(),
                agent_socket_path: PathBuf::from(if cfg!(target_os = "macos") {
                    "/usr/local/var/run/maknae-agent/maknaed.sock"
                } else {
                    "/run/maknae-agent/maknaed.sock"
                }),
                prompt_max_bytes: 1_048_576,
            }
        );
        let moved = format!(
            "{text}transport:\n  agent_socket_path: /run/agents/a.sock\n  prompt_max_bytes: 262144\n"
        );
        let got = parse_host_enrollment(&moved).unwrap();
        assert_eq!(
            (got.agent_socket_path, got.prompt_max_bytes),
            (PathBuf::from("/run/agents/a.sock"), 262_144)
        );
        let defaults = text
            .replace("  pki_int_mount: pki_int\n", "")
            .replace("  plane_key: ml-dsa-87\n", "");
        let got = parse_host_enrollment(&defaults).unwrap();
        assert_eq!(
            (got.pki_int_mount.as_str(), got.plane_key.as_str()),
            ("maknae-pki-int", "ml-dsa-87")
        );
        let p384 = text.replace("plane_key: ml-dsa-87", "plane_key: ecdsa-p384-sha384");
        assert_eq!(
            parse_host_enrollment(&p384).unwrap().plane_key,
            "ecdsa-p384-sha384"
        );
        for bad in [
            text.replace("plane_key: ml-dsa-87", "plane_key: p256"),
            text.replace("deployment_id: dev-01", "deployment_id: Dev 01"),
            text.replace("deployment_id:", "deployment_idx:"),
            format!("{text}transport:\n  agent_socket_path: relative.sock\n"),
        ] {
            assert!(parse_host_enrollment(&bad).is_err(), "{bad}");
        }
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
        assert_eq!(bin, maknae_io::program::Program::SystemdCreds);
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
    }

    #[test]
    fn the_record_lands_in_the_agents_own_directory() {
        let id = AgentId::parse("hobi").unwrap();
        assert_eq!(
            record_path(&id),
            std::path::Path::new("/etc/maknae/agents/hobi/enrollment.yaml")
        );
    }

    #[test]
    fn the_record_round_trips_its_role() {
        let id = AgentId::parse("hobi").unwrap();
        for role in [AgentRole::User, AgentRole::Guest] {
            let r = AgentRecord { role, ..record() };
            let yaml = r.to_yaml();
            assert!(yaml.contains(&format!("role: {}", role.key())), "{yaml}");
            assert_eq!(AgentRecord::parse(&yaml).unwrap(), r);
            let enrolled = maknae_config::parse_agent_enrollment(&id, &yaml).unwrap();
            assert_eq!((enrolled.role, enrolled.uid), (role, 990));
        }
        let admin = record().to_yaml().replace("role: user", "role: admin");
        assert!(matches!(
            AgentRecord::parse(&admin),
            Err(EnrollError::State(_))
        ));
        let missing = record().to_yaml().replace("role: user\n", "");
        assert!(matches!(
            AgentRecord::parse(&missing),
            Err(EnrollError::State(_))
        ));
    }

    #[derive(clap::Parser, Debug)]
    struct Cli {
        #[command(flatten)]
        agent: AgentArgs,
    }

    fn parse_args(extra: &[&str]) -> Result<AgentArgs, clap::Error> {
        use clap::Parser;
        let base = [
            "maknae",
            "hobi",
            "--account",
            "hobi-svc",
            "--bind-cidr",
            "10.0.0.5",
            "--provider",
            "openai",
            "--model",
            "gpt-5.6",
            "--key-subpath",
            "openai/hobi",
            "--key-field",
            "api_key",
            "--context-tokens",
            "128000",
        ];
        Cli::try_parse_from(base.iter().chain(extra)).map(|c| c.agent)
    }

    #[test]
    fn role_admin_is_not_a_choice() {
        assert!(parse_args(&["--role", "admin"]).is_err());
        assert_eq!(
            AgentRole::from(parse_args(&["--role", "guest"]).unwrap().role),
            AgentRole::Guest
        );
    }

    #[test]
    fn the_provider_flags_are_required_and_persona_is_admin_or_self() {
        use clap::Parser;
        let full = [
            "maknae",
            "hobi",
            "--account",
            "hobi-svc",
            "--bind-cidr",
            "10.0.0.5",
            "--provider",
            "openai",
            "--model",
            "gpt-5.6",
            "--key-subpath",
            "openai/hobi",
            "--key-field",
            "api_key",
            "--context-tokens",
            "128000",
        ];
        assert!(Cli::try_parse_from(full).is_ok());
        for flag in [
            "--provider",
            "--model",
            "--key-subpath",
            "--key-field",
            "--context-tokens",
        ] {
            let at = full.iter().position(|a| *a == flag).unwrap();
            let without: Vec<&str> = full
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != at && *i != at + 1)
                .map(|(_, a)| *a)
                .collect();
            assert!(Cli::try_parse_from(without).is_err(), "{flag}");
        }
        assert!(parse_args(&["--persona", "root"]).is_err());
        assert!(parse_args(&["--context-tokens", "-1"]).is_err());
    }

    #[test]
    fn refresh_access_needs_only_the_id_and_takes_nothing_else() {
        use clap::Parser;
        let got = Cli::try_parse_from(["maknae", "hobi", "--refresh-access"]).unwrap();
        assert!(got.agent.refresh_access);
        assert_eq!(got.agent.account, None);
        assert!(got.agent.bind_cidr.is_empty());
        assert!(Cli::try_parse_from(["maknae", "--refresh-access"]).is_err());
        for extra in [
            &["--account", "hobi-svc"][..],
            &["--bind-cidr", "10.0.0.5"],
            &["--provider", "openai"],
            &["--model", "m"],
            &["--key-subpath", "k"],
            &["--key-field", "f"],
            &["--context-tokens", "1"],
            &["--output-tokens", "1"],
            &["--persona", "self"],
            &["--rotate"],
            &["--token-file", "/t"],
            &["--role", "guest"],
            &["--approle-mount", "m"],
        ] {
            let argv: Vec<&str> = ["maknae", "hobi", "--refresh-access"]
                .into_iter()
                .chain(extra.iter().copied())
                .collect();
            assert!(Cli::try_parse_from(argv).is_err(), "{extra:?}");
        }
        assert!(Cli::try_parse_from(["maknae", "hobi"]).is_err());
        assert!(parse_args(&["--refresh-access"]).is_err());
    }

    #[test]
    fn the_role_defaults_to_user() {
        assert_eq!(
            AgentRole::from(parse_args(&[]).unwrap().role),
            AgentRole::User
        );
    }

    fn account(groups: &[u32]) -> maknae_io::HostAccount {
        maknae_io::HostAccount {
            uid: 990,
            name: "hobi-svc".into(),
            primary_gid: 990,
            shell: "/usr/sbin/nologin".into(),
            dir: "/var/empty".into(),
            named_groups: groups.to_vec(),
        }
    }

    const AGENTS_GID: u32 = 960;

    fn admit(
        acct: maknae_io::HostAccount,
        agents_gid: Option<u32>,
        bindings: &maknae_config::Bindings,
    ) -> Result<u32, EnrollError> {
        admit_aliased(acct, agents_gid, bindings, &BTreeMap::new())
    }

    fn admit_aliased(
        acct: maknae_io::HostAccount,
        agents_gid: Option<u32>,
        bindings: &maknae_config::Bindings,
        uid_of: &BTreeMap<String, u32>,
    ) -> Result<u32, EnrollError> {
        let daemons = maknae_io::DaemonFacts {
            uids: vec![970, 971],
            gids: vec![970, 971],
        };
        admit_account(
            "hobi-svc",
            &AgentId::parse("hobi").unwrap(),
            Some(acct),
            &HostAccounts {
                maknae_gid: Some(950),
                principal_uid: 1000,
                daemons: &daemons,
                other_agents: &[],
            },
            agents_gid,
            bindings,
            uid_of,
        )
    }

    fn recorded() -> agent_access::Account {
        agent_access::Account {
            name: "hobi-svc".into(),
            uid: 990,
        }
    }

    fn refresh_admit(acct: Option<maknae_io::HostAccount>) -> Result<u32, EnrollError> {
        let daemons = maknae_io::DaemonFacts {
            uids: vec![970, 971],
            gids: vec![970, 971],
        };
        admit_account(
            "hobi-svc",
            &hobi_id(),
            acct,
            &HostAccounts {
                maknae_gid: Some(950),
                principal_uid: 1000,
                daemons: &daemons,
                other_agents: &[("suga".to_string(), 995)],
            },
            Some(AGENTS_GID),
            &maknae_config::Bindings::absent(),
            &BTreeMap::new(),
        )
    }

    #[test]
    fn refresh_readmits_the_enrolled_identity() {
        let got = readmitted(
            &hobi_id(),
            &recorded(),
            refresh_admit(Some(account(&[990, AGENTS_GID]))),
        );
        assert_eq!(got.unwrap(), recorded());
    }

    #[test]
    fn refresh_refuses_an_account_that_is_gone() {
        let e = readmitted(&hobi_id(), &recorded(), refresh_admit(None)).unwrap_err();
        assert!(e.to_string().contains("no account named hobi-svc"), "{e}");
    }

    #[test]
    fn refresh_refuses_a_name_now_on_another_uid() {
        let mut moved = account(&[991, AGENTS_GID]);
        moved.uid = 991;
        let e = readmitted(&hobi_id(), &recorded(), refresh_admit(Some(moved))).unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentIdentityChanged { agent, account, recorded: 990, current: 991 }
                if agent == "hobi" && account == "hobi-svc"),
            "{e:?}"
        );
        assert_eq!(
            e.to_string(),
            "agent hobi was enrolled for account hobi-svc with uid 990, but hobi-svc now has uid 991; nothing was granted. Restore the account, or remove the agent and enroll it again"
        );
    }

    #[test]
    fn refresh_refuses_a_recorded_uid_now_under_another_name() {
        let mut other = account(&[990, AGENTS_GID]);
        other.name = "intruder".into();
        let e = readmitted(&hobi_id(), &recorded(), refresh_admit(Some(other))).unwrap_err();
        assert!(
            e.to_string()
                .contains("shares uid 990 with account intruder"),
            "{e}"
        );
    }

    #[test]
    fn refresh_refuses_an_account_that_left_the_agent_group() {
        let e = readmitted(
            &hobi_id(),
            &recorded(),
            refresh_admit(Some(account(&[990]))),
        )
        .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentNotInAgentGroup { .. }),
            "{e:?}"
        );
    }

    #[test]
    fn refresh_refuses_a_uid_another_agent_holds() {
        let mut taken = account(&[995, AGENTS_GID]);
        taken.uid = 995;
        let e = readmitted(&hobi_id(), &recorded(), refresh_admit(Some(taken))).unwrap_err();
        assert!(
            e.to_string().contains("already enrolled for agent suga"),
            "{e}"
        );
    }

    #[test]
    fn an_account_a_uid_alias_binds_to_admin_is_refused() {
        let b = maknae_config::parse_bindings(
            "schema_version: 1\nbindings:\n  admin: [\"hobi-alt\"]\n",
        )
        .unwrap();
        let alias = BTreeMap::from([("hobi-alt".to_string(), 990)]);
        let e =
            admit_aliased(account(&[990, AGENTS_GID]), Some(AGENTS_GID), &b, &alias).unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentBound { account, role, .. }
                if account == "hobi-svc" && *role == "admin"),
            "{e:?}"
        );
    }

    fn bound(role: &str) -> maknae_config::Bindings {
        maknae_config::parse_bindings(&format!(
            "schema_version: 1\nbindings:\n  {role}: [\"hobi-svc\"]\n"
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn an_account_bound_in_bindings_is_refused_before_vault() {
        for role in ["admin", "user", "guest"] {
            let fake = Fake::default();
            let built = Cell::new(false);
            let got = admit_then_enroll(
                || {
                    admit(account(&[990, AGENTS_GID]), Some(AGENTS_GID), &bound(role)).map(|uid| {
                        agent_unit::ServiceAccount {
                            uid,
                            gid: 990,
                            home: "/home/hobi-svc".into(),
                        }
                    })
                },
                || async {
                    built.set(true);
                    Ok(&fake)
                },
                plan(false),
                &host(),
                None,
                AgentState::default(),
            )
            .await;
            assert!(
                matches!(&got, Err(EnrollError::AgentBound { agent, account, role: r })
                    if agent == "hobi" && account == "hobi-svc" && *r == role),
                "{role}: {got:?}"
            );
            assert!(!built.get(), "{role}: the Vault client was built");
            assert!(fake.log().is_empty(), "{role}: {:?}", fake.log());
        }
    }

    #[test]
    fn an_account_outside_the_agent_group_is_refused_with_the_command() {
        let none = maknae_config::Bindings::absent();
        let command = if cfg!(target_os = "macos") {
            "dseditgroup -o edit -a hobi-svc -t user maknae-agents"
        } else {
            "usermod -aG maknae-agents hobi-svc"
        };
        for (groups, gid) in [
            (vec![990], Some(AGENTS_GID)),
            (vec![990, 5], Some(AGENTS_GID)),
        ] {
            let e = admit(account(&groups), gid, &none).unwrap_err();
            assert!(
                matches!(&e, EnrollError::AgentNotInAgentGroup { account, group }
                    if account == "hobi-svc" && *group == "maknae-agents"),
                "{e:?}"
            );
            assert!(e.to_string().contains(command), "{e}");
        }
        assert_eq!(
            admit(account(&[990, AGENTS_GID]), Some(AGENTS_GID), &none).unwrap(),
            990
        );
    }

    #[tokio::test]
    async fn re_enrollment_re_enables_a_disabled_entity() {
        let fake = Fake::default().with_entity(Some(healthy(true)));
        let (r, s) = prior(&["a"], &[], &[]);
        enroll_agent(&fake, &plan(true), &host(), Some(&r), s)
            .await
            .unwrap();
        assert_eq!(
            fake.log()[fake.log().len() - 3..],
            strings(&[
                "set_entity_disabled maknae-agent-hobi false",
                "grant hobi hobi-svc:990",
                "start hobi 990:991 /home/hobi-svc",
            ])[..]
        );
    }

    #[tokio::test]
    async fn an_enabled_entity_is_left_alone() {
        let fake = Fake::default();
        first(&fake).await.unwrap();
        assert!(!fake.log().iter().any(|l| l.starts_with("set_entity")));
    }

    #[tokio::test]
    async fn a_missing_entity_refuses_before_minting_anything() {
        let other_role = entity_facts(false, &[(ENTITY_MOUNT, "another-role-id")]);
        let other_mount = entity_facts(false, &[("auth/other/", ROLE_ID)]);
        for entity in [
            None,
            Some(entity_facts(false, &[])),
            Some(other_mount),
            Some(other_role),
        ] {
            let fake = Fake::default().with_entity(entity);
            let e = rotate(&fake, &["a"], &[], &[]).await.unwrap_err();
            assert!(
                matches!(&e, EnrollError::AgentEntityMissing { agent, entity, mount, .. }
                    if agent == "hobi" && entity == "maknae-agent-hobi" && mount == MOUNT),
                "{e:?}"
            );
            assert!(e.to_string().contains("create the AppRole role"), "{e}");
            assert_eq!(
                fake.log(),
                strings(&["read_role_id", "entity maknae-agent-hobi"])
            );
        }
    }

    #[tokio::test]
    async fn an_entity_read_error_refuses_before_minting_anything() {
        let fake = Fake::failing(&["entity"]);
        assert!(first(&fake).await.is_err());
        assert_eq!(
            fake.log(),
            strings(&["read_role_id", "entity maknae-agent-hobi"])
        );
    }

    #[tokio::test]
    async fn a_disabled_entity_stays_disabled_while_old_secret_ids_survive() {
        let fake = Fake::failing(&["destroy:b"]).with_entity(Some(healthy(true)));
        let e = rotate(&fake, &["a", "b"], &[], &[]).await.unwrap_err();
        assert!(matches!(&e, EnrollError::AgentRetireFailed { .. }), "{e:?}");
        assert!(e.to_string().contains("stays disabled"), "{e}");
        assert!(!fake.log().iter().any(|l| l.starts_with("set_entity")));
    }

    #[tokio::test]
    async fn the_refusal_for_a_missing_group_names_the_group_not_usermod() {
        let none = maknae_config::Bindings::absent();
        let e = admit(account(&[990]), None, &none).unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentGroupMissing { group } if *group == "maknae-agents"),
            "{e:?}"
        );
        let text = e.to_string();
        assert!(
            text.contains("does not exist") && !text.contains("usermod"),
            "{text}"
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

    pub(crate) struct Scratch(PathBuf);

    impl std::ops::Deref for Scratch {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) fn scratch_anchor(tag: &str) -> (Scratch, maknae_io::Anchor) {
        let d = std::env::temp_dir().join(format!("maknae-agent-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let anchor = maknae_io::open_anchor(
            &d,
            AnchorRequired {
                owner: None,
                mode_mask: None,
            },
            StrategyPref::Auto,
        )
        .unwrap();
        (Scratch(d), anchor)
    }

    pub(crate) fn unreachable_vault(tag: &str, private: maknae_io::Anchor) -> RealVault {
        RealVault {
            client: super::super::tests::operator_client_at(tag, "https://127.0.0.1:1"),
            private,
        }
    }

    fn hobi_id() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    fn running_as_root() -> bool {
        nix::unistd::geteuid().is_root()
    }

    fn real_ops(tag: &str) -> ([Scratch; 2], RealAgentOps) {
        let (scratch, ops, _) = real_ops_with(tag);
        (scratch, ops)
    }

    fn real_ops_with(
        tag: &str,
    ) -> (
        [Scratch; 2],
        RealAgentOps,
        std::rc::Rc<agent_access::tests::FakeHost>,
    ) {
        let (d, agents) = scratch_anchor(&format!("{tag}-agents"));
        let (p, private) = scratch_anchor(&format!("{tag}-private"));
        let host = std::rc::Rc::new(agent_access::tests::FakeHost::default());
        let ops = RealAgentOps {
            vault: unreachable_vault(tag, private),
            agents,
            root: d.to_path_buf(),
            runner: Box::new(host.clone()),
            daemon_gid: nix::unistd::getegid().as_raw(),
            resolver: artifact_write::RealOwnerResolver {
                operator_uid: nix::unistd::geteuid().as_raw(),
                operator_gid: nix::unistd::getegid().as_raw(),
            },
            #[cfg(not(target_os = "macos"))]
            verbose: false,
            #[cfg(target_os = "macos")]
            team: String::new(),
        };
        ([d, p], ops, host)
    }

    #[tokio::test]
    async fn every_vault_call_reports_an_unreachable_vault() {
        let (_scratch, ops) = real_ops("vault-down");
        fn refused<T>(r: Result<T, EnrollError>) {
            let e = r.err();
            assert!(matches!(e, Some(EnrollError::Vault(_))), "{e:?}");
        }
        refused(ops.read_role_id(MOUNT, ROLE).await);
        refused(ops.find_role_id(MOUNT, ROLE).await);
        refused(ops.destroy(MOUNT, ROLE, "accessor-1").await);
        refused(ops.list_accessors(MOUNT, ROLE).await);
        refused(ops.entity("maknae-agent-hobi").await);
        refused(ops.set_entity_disabled("maknae-agent-hobi", true).await);
        let cidrs = BindCidrs::parse(&["10.0.0.5".to_string()]).unwrap();
        refused(ops.mint(MOUNT, ROLE, &cidrs).await);
    }

    #[test]
    fn write_state_publishes_a_root_owned_0600_file_or_refuses() {
        use std::os::unix::fs::PermissionsExt;
        let (d, private) = scratch_anchor("write-state");
        let vault = unreachable_vault("write-state", private);
        let s = state(&["a"], &["p"], &[]);
        let got = vault.write_state(&hobi_id(), &s);
        let path = d.join(state_file(&hobi_id()));
        if running_as_root() {
            got.unwrap();
            let text = std::fs::read_to_string(&path).unwrap();
            assert_eq!(AgentState::parse(&text).unwrap(), s);
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        } else {
            assert!(matches!(&got, Err(EnrollError::Io { .. })), "{got:?}");
            assert!(!path.exists());
        }
    }

    #[test]
    fn write_record_off_root_is_refused_and_writes_nothing() {
        if running_as_root() {
            return;
        }
        let ([d, _], ops) = real_ops("write-record");
        let got = ops.write_record(&record());
        assert!(got.is_err(), "{got:?}");
        assert!(!d.join("hobi").exists());
    }

    #[test]
    fn write_client_publishes_a_root_group_0640_file_or_refuses() {
        use std::os::unix::fs::PermissionsExt;
        let ([d, _], ops, host) = real_ops_with("write-client");
        std::fs::create_dir(d.join("hobi")).unwrap();
        let got = ops.write_client(&client_config());
        let path = d.join("hobi").join(maknae_config::AGENT_CLIENT_FILE);
        if running_as_root() {
            got.unwrap();
            let text = std::fs::read_to_string(&path).unwrap();
            assert_eq!(
                maknae_config::parse_agent_client(&hobi_id(), &text),
                Ok(client_config())
            );
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o640);
        } else {
            assert!(matches!(&got, Err(EnrollError::Io { .. })), "{got:?}");
            assert!(!path.exists());
        }
        assert!(host.calls().is_empty(), "writing the file grants nothing");
    }

    #[test]
    fn grant_access_runs_on_the_injected_runner_below_the_configured_root() {
        let ([d, _], ops, host) = real_ops_with("grant-access");
        std::fs::create_dir(d.join("hobi")).unwrap();
        let account = agent_access::Account {
            name: "hobi-svc".into(),
            uid: 990,
        };
        ops.grant_access(&hobi_id(), &account).unwrap();
        let calls = host.calls();
        assert_eq!(calls.len(), 2 * 9, "{calls:?}");
        let root = d.display().to_string();
        for c in &calls {
            assert!(c.ends_with(&root) || c.contains(&format!("{root}/")), "{c}");
            assert!(!c.contains(" /etc/maknae"), "{c}");
        }
        assert!(!calls.iter().any(|c| c.contains("persona.md")));
        write_0640(
            &d.join("hobi").join(maknae_config::PERSONA_FILE),
            "You are hobi.",
        );
        ops.grant_access(&hobi_id(), &account).unwrap();
        assert_eq!(host.calls().len(), 2 * 9 + 2 * 10);
    }

    #[test]
    fn refresh_access_refuses_an_unenrolled_agent_and_otherwise_only_grants() {
        let e = enrolled_account(&hobi_id(), None).unwrap_err();
        assert!(
            e.to_string()
                .contains("agent hobi is not enrolled on this host"),
            "{e}"
        );
        let r = record();
        assert_eq!(
            enrolled_account(&hobi_id(), Some(&r)).unwrap(),
            agent_access::Account {
                name: "hobi-svc".into(),
                uid: 990
            }
        );
        let (d, agents) = scratch_anchor("refresh");
        std::fs::create_dir(d.join("hobi")).unwrap();
        write_0640(
            &d.join("hobi").join(maknae_config::ENROLLMENT_FILE),
            &r.to_yaml(),
        );
        let host = agent_access::tests::FakeHost::default();
        refresh_access(
            &host,
            agent_access::Platform::Linux,
            Path::new("/srv/cfg"),
            &agents,
            &hobi_id(),
            &enrolled_account(&hobi_id(), Some(&r)).unwrap(),
        )
        .unwrap();
        let mut want = Vec::new();
        for e in agent_access::grant_entries(Path::new("/srv/cfg"), &hobi_id(), false) {
            let p = e.path.display();
            let perms = if e.dir { "r-x" } else { "r--" };
            want.push(format!(
                "/usr/bin/setfacl -P | -n | -m | u:990:{perms} | {p}"
            ));
            want.push(format!("/usr/bin/getfacl -P | -p | -n | {p}"));
        }
        assert_eq!(host.calls(), want);
        let mut names: Vec<_> = std::fs::read_dir(d.join("hobi"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, [maknae_config::ENROLLMENT_FILE]);
    }

    #[test]
    fn refresh_regrants_then_restarts_and_a_refused_grant_starts_nothing() {
        let r = record();
        let (d, agents) = scratch_anchor("refresh-restart");
        std::fs::create_dir(d.join("hobi")).unwrap();
        let account = enrolled_account(&hobi_id(), Some(&r)).unwrap();
        let root = Path::new("/srv/cfg");
        let host = agent_access::tests::FakeHost::default();
        let started_after = Cell::new(None);
        refresh_and_restart(
            &host,
            agent_access::Platform::Linux,
            root,
            &agents,
            &hobi_id(),
            &account,
            || {
                started_after.set(Some(host.calls().len()));
                Ok(())
            },
        )
        .unwrap();
        let grants = 2 * agent_access::grant_entries(root, &hobi_id(), false).len();
        assert_eq!(started_after.get(), Some(grants));

        let first = format!(
            "/usr/bin/setfacl -P | -n | -m | u:990:r-x | {}",
            root.display()
        );
        let host = agent_access::tests::FakeHost::default().refusing(&first);
        let started = Cell::new(false);
        refresh_and_restart(
            &host,
            agent_access::Platform::Linux,
            root,
            &agents,
            &hobi_id(),
            &account,
            || {
                started.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(!started.get());
    }

    #[test]
    fn the_group_hint_never_prints_an_unsafe_account_name() {
        assert!(agent_group_command("hobi-svc").contains("hobi-svc"));
        for bad in ["-rf", "hobi; rm -rf /", "a b", ""] {
            let hint = agent_group_command(bad);
            assert!(hint.contains("<account>"), "{bad:?}: {hint}");
            if !bad.is_empty() {
                assert!(!hint.contains(bad), "{bad:?}: {hint}");
            }
        }
    }

    #[test]
    fn persona_present_finds_only_a_regular_persona_file() {
        let (d, agents) = scratch_anchor("persona-present");
        std::fs::create_dir(d.join("hobi")).unwrap();
        assert!(!persona_present(&agents, &hobi_id()).unwrap());
        std::fs::create_dir(d.join("hobi").join(maknae_config::PERSONA_FILE)).unwrap();
        assert!(!persona_present(&agents, &hobi_id()).unwrap());
        std::fs::remove_dir(d.join("hobi").join(maknae_config::PERSONA_FILE)).unwrap();
        write_0640(
            &d.join("hobi").join(maknae_config::PERSONA_FILE),
            "You are hobi.",
        );
        assert!(persona_present(&agents, &hobi_id()).unwrap());
        assert!(persona_present(&agents, &AgentId::parse("suga").unwrap()).is_err());
    }

    fn write_0640(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
    }

    #[test]
    fn read_records_skips_what_is_not_an_agent_directory() {
        let (d, agents) = scratch_anchor("records-skip");
        std::fs::create_dir(d.join("hobi")).unwrap();
        std::fs::create_dir(d.join("Not An Id!")).unwrap();
        write_0640(
            &d.join("Not An Id!").join(maknae_config::ENROLLMENT_FILE),
            &record().to_yaml(),
        );
        write_0640(&d.join("jin"), &record().to_yaml());
        let (prior, others) = read_records(&agents, &hobi_id()).unwrap();
        assert_eq!((prior, others), (None, vec![]));
    }

    #[test]
    fn read_records_reads_root_owned_records_and_refuses_any_other() {
        let (d, agents) = scratch_anchor("records-read");
        for id in ["hobi", "jin"] {
            std::fs::create_dir(d.join(id)).unwrap();
            let mut r = record();
            r.agent_id = id.into();
            r.uid = if id == "hobi" { 990 } else { 991 };
            write_0640(
                &d.join(id).join(maknae_config::ENROLLMENT_FILE),
                &r.to_yaml(),
            );
        }
        let got = read_records(&agents, &hobi_id());
        if running_as_root() {
            let (prior, others) = got.unwrap();
            assert_eq!(prior, Some(record()));
            assert_eq!(others, vec![("jin".to_string(), 991)]);
        } else {
            assert!(
                matches!(&got, Err(EnrollError::Io { source, .. }) if source.contains("require 0")),
                "{got:?}"
            );
        }
    }

    #[test]
    fn read_records_refuses_a_record_others_can_write() {
        use std::os::unix::fs::PermissionsExt;
        let (d, agents) = scratch_anchor("records-mode");
        std::fs::create_dir(d.join("hobi")).unwrap();
        let path = d.join("hobi").join(maknae_config::ENROLLMENT_FILE);
        std::fs::write(&path, record().to_yaml()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let got = read_records(&agents, &hobi_id());
        assert!(matches!(&got, Err(EnrollError::Io { .. })), "{got:?}");
    }

    #[test]
    fn agent_group_create_command_names_the_agent_group() {
        let want = if cfg!(target_os = "macos") {
            "dseditgroup -o create maknae-agents"
        } else {
            "groupadd --system maknae-agents"
        };
        assert_eq!(agent_group_create_command(), want);
    }

    #[test]
    fn binding_uids_maps_only_the_names_passwd_knows() {
        let me = nix::unistd::User::from_uid(nix::unistd::geteuid())
            .unwrap()
            .expect("the test account has a passwd entry");
        let b = maknae_config::parse_bindings(&format!(
            "schema_version: 1\nbindings:\n  admin: [\"root\", {{uid: 4242}}]\n  user: [\"{}\", \"maknae-no-such-user-609\"]\n",
            me.name
        ))
        .unwrap();
        let got = binding_uids(&b).unwrap();
        assert_eq!(
            got,
            BTreeMap::from([("root".to_string(), 0), (me.name.clone(), me.uid.as_raw())])
        );
    }

    #[test]
    fn check_account_refuses_an_account_the_host_does_not_have() {
        let got = check_account("maknae-no-such-user-609", &hobi_id(), &host(), &[]);
        assert!(got.is_err(), "{got:?}");
    }

    #[tokio::test]
    async fn run_enroll_agent_off_root_is_refused_before_anything_else() {
        if running_as_root() {
            return;
        }
        let args = parse_args(&[]).unwrap();
        let got = run_enroll_agent(&args, Locale::EnUs).await;
        assert!(matches!(got, Err(EnrollError::NotRoot)), "{got:?}");
    }
}
