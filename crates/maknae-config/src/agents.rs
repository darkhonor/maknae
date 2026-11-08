use crate::authz::{AuthzError, SubjectPolicy};
use crate::bindings::{name_fault, BindingEntry, Bindings};
use crate::value::Value;
use crate::ConfigError;
use maknae_io::{
    AnchorRequired, DaemonFacts, DescendantRequired, HostAccount, IoError, IoKind, Kind,
    StrategyPref, TargetRequired,
};
use std::path::Path;

pub const AGENTS_DIR: &str = "agents";
pub const ENROLLMENT_FILE: &str = "enrollment.yaml";
pub const POLICY_FILE: &str = "policy.yaml";
pub const NON_LOGIN_SHELLS: [&str; 5] = [
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/usr/bin/nologin",
    "/bin/false",
    "/usr/bin/false",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidAgentId(pub String);

impl std::fmt::Display for InvalidAgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "agent id {:?} is not valid; use 1 to 32 characters of a-z, 0-9, '.', '_' or '-', starting and ending with a letter, digit or '_', and not \"data\"",
            self.0
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentId(String);

impl AgentId {
    pub fn parse(raw: &str) -> Result<Self, InvalidAgentId> {
        let bytes = raw.as_bytes();
        let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_';
        let inner = |b: u8| edge(b) || b == b'.' || b == b'-';
        let ok = (1..=32).contains(&bytes.len())
            && edge(bytes[0])
            && edge(bytes[bytes.len() - 1])
            && bytes.iter().all(|&b| inner(b))
            && raw != "data";
        if ok {
            Ok(Self(raw.to_string()))
        } else {
            Err(InvalidAgentId(raw.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn role_name(&self) -> String {
        format!("agent-{}", self.0)
    }

    pub fn entity_name(&self) -> String {
        format!("{AGENT_ENTITY_PREFIX}{}", self.0)
    }
}

pub const AGENT_ENTITY_PREFIX: &str = "maknae-agent-";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentRole {
    User,
    Guest,
}

impl AgentRole {
    pub fn key(self) -> &'static str {
        match self {
            AgentRole::User => "user",
            AgentRole::Guest => "guest",
        }
    }

    pub fn parse(raw: &str) -> Option<AgentRole> {
        match raw {
            "user" => Some(AgentRole::User),
            "guest" => Some(AgentRole::Guest),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentEnrollment {
    pub id: AgentId,
    pub account: String,
    pub uid: u32,
    pub role: AgentRole,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskerRef {
    Uid(u32),
    Account(String),
    Agent(AgentId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentPolicy {
    pub id: AgentId,
    pub entry: SubjectPolicy,
    pub canonical: String,
    pub taskers: Option<Vec<TaskerRef>>,
}

fn field<'a>(map: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

pub fn parse_agent_enrollment(dir: &AgentId, text: &str) -> Result<AgentEnrollment, ConfigError> {
    let what = format!("{AGENTS_DIR}/{}/{ENROLLMENT_FILE}", dir.as_str());
    let invalid = |why: &str| ConfigError::InvalidAgent(format!("{what}: {why}"));
    let root = crate::load_str(text).map_err(|e| invalid(&e.to_string()))?;
    let Value::Map(map) = root else {
        return Err(invalid("the root must be a mapping"));
    };
    let text_of = |key: &str| match field(&map, key) {
        Some(Value::Str(s)) => Ok(s.as_str()),
        Some(_) => Err(invalid(&format!("`{key}` must be a string"))),
        None => Err(invalid(&format!("`{key}` is missing"))),
    };
    let agent_id = text_of("agent_id")?;
    if agent_id != dir.as_str() {
        return Err(invalid(&format!(
            "the record names agent {agent_id:?}, not its directory's agent {:?}",
            dir.as_str()
        )));
    }
    let account = text_of("account")?;
    if name_fault(account).is_some() {
        return Err(invalid(&format!(
            "`account` {account:?} is not an account name"
        )));
    }
    let uid = match field(&map, "uid") {
        Some(Value::Int(n)) => u32::try_from(*n).ok(),
        _ => None,
    }
    .ok_or_else(|| invalid("`uid` must be a whole number from 0 to 4294967295"))?;
    let role = text_of("role")?;
    let role = AgentRole::parse(role).ok_or_else(|| {
        invalid(&format!(
            "role {role:?} is refused; an agent is bound to `user` or `guest`, never `admin`"
        ))
    })?;
    Ok(AgentEnrollment {
        id: dir.clone(),
        account: account.to_string(),
        uid,
        role,
    })
}

fn tasker(raw: &str) -> Result<TaskerRef, AuthzError> {
    let bad = || {
        AuthzError::Yaml(format!(
            "taskers: {raw:?} is not `uid:<n>`, an account name or `agent:<id>`"
        ))
    };
    if let Some(n) = raw.strip_prefix("uid:") {
        let canonical = n.bytes().all(|b| b.is_ascii_digit()) && (n == "0" || !n.starts_with('0'));
        return match n.parse::<u32>() {
            Ok(uid) if canonical => Ok(TaskerRef::Uid(uid)),
            _ => Err(bad()),
        };
    }
    if let Some(id) = raw.strip_prefix("agent:") {
        return AgentId::parse(id).map(TaskerRef::Agent).map_err(|_| bad());
    }
    match name_fault(raw) {
        None => Ok(TaskerRef::Account(raw.to_string())),
        Some(_) => Err(bad()),
    }
}

fn taskers(v: &Value) -> Result<Vec<TaskerRef>, AuthzError> {
    let Value::Seq(items) = v else {
        return Err(AuthzError::Yaml(
            "taskers must be a sequence (write `taskers: []` for nobody)".into(),
        ));
    };
    items
        .iter()
        .map(|item| match item {
            Value::Str(s) => tasker(s),
            _ => Err(AuthzError::Yaml(
                "taskers entries must be quoted strings".into(),
            )),
        })
        .collect()
}

pub fn parse_agent_policy(id: &AgentId, text: &str) -> Result<AgentPolicy, AuthzError> {
    let root = crate::load_str(text).map_err(|e| AuthzError::Yaml(e.to_string()))?;
    let Value::Map(map) = &root else {
        return Err(AuthzError::Yaml(format!(
            "{POLICY_FILE} root must be a mapping"
        )));
    };
    crate::reject_unknown_keys(
        "policy",
        map,
        &[
            "schema_version",
            "permissions",
            "actions",
            "models",
            "taskers",
        ],
    )
    .map_err(AuthzError::Config)?;
    match field(map, "schema_version") {
        Some(Value::Int(1)) => {}
        Some(Value::Int(n)) => return Err(AuthzError::UnknownSchemaVersion(*n)),
        _ => return Err(AuthzError::UnknownSchemaVersion(0)),
    }
    let entry = map
        .iter()
        .filter(|(k, _)| matches!(k.as_str(), "permissions" | "actions" | "models"))
        .cloned()
        .collect();
    Ok(AgentPolicy {
        id: id.clone(),
        entry: crate::authz::parse_subject_at("policy", id.as_str(), &Value::Map(entry))?,
        canonical: crate::value::canonical_json(&root),
        taskers: field(map, "taskers").map(taskers).transpose()?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkippedAgentEntry {
    NotADirectory(String),
    NoEnrollment(String),
    InvalidName(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AgentsLoad {
    pub enrollments: Vec<AgentEnrollment>,
    pub policies: Vec<AgentPolicy>,
    pub skipped: Vec<SkippedAgentEntry>,
}

pub(crate) fn agents_dir_required() -> AnchorRequired {
    AnchorRequired {
        owner: Some(0),
        mode_mask: Some(0o027),
    }
}

pub(crate) fn agent_file_required() -> TargetRequired {
    TargetRequired {
        owner: Some(0),
        mode_mask: Some(0o027),
        nlink_exactly_one: true,
        regular_file: true,
        max_bytes: Some(64 * 1024),
    }
}

pub fn load_agents(config_dir: &Path) -> Result<AgentsLoad, ConfigError> {
    load_agents_required(config_dir, agents_dir_required(), agent_file_required())
}

#[cfg(feature = "hermetic-test-seam")]
pub fn load_agents_with_requirement(
    config_dir: &Path,
    dir: AnchorRequired,
    target: TargetRequired,
) -> Result<AgentsLoad, ConfigError> {
    load_agents_required(config_dir, dir, target)
}

fn read_optional(
    anchor: &maknae_io::Anchor,
    agents: &Path,
    rel: &Path,
    desc: &DescendantRequired,
    target: &TargetRequired,
) -> Result<Option<String>, ConfigError> {
    let full = agents.join(rel);
    match anchor.read(rel, Some(desc.clone()), target.clone()) {
        Ok(out) => std::str::from_utf8(&out.value)
            .map(|s| Some(s.to_string()))
            .map_err(|e| ConfigError::Io(format!("{}: invalid UTF-8: {e}", full.display()))),
        Err(IoError::Io {
            kind: IoKind::NotFound,
            path,
        }) if path == full => Ok(None),
        Err(e) => Err(crate::loader::map_io(e)),
    }
}

fn load_agents_required(
    config_dir: &Path,
    dir: AnchorRequired,
    target: TargetRequired,
) -> Result<AgentsLoad, ConfigError> {
    let agents = std::path::absolute(config_dir.join(AGENTS_DIR))
        .map_err(|e| ConfigError::Io(e.to_string()))?;
    let desc = DescendantRequired {
        owner: dir.owner,
        mode_mask: dir.mode_mask,
    };
    let anchor = match maknae_io::open_anchor(&agents, dir, StrategyPref::Auto) {
        Ok(a) => a,
        Err(IoError::Io {
            kind: IoKind::NotFound,
            path,
        }) if path == agents => return Ok(AgentsLoad::default()),
        Err(e) => return Err(crate::loader::map_io(e)),
    };
    let mut entries = anchor
        .enumerate(Path::new(""), None)
        .map_err(crate::loader::map_io)?
        .value;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let mut load = AgentsLoad::default();
    for entry in entries {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        let shown = entry.name.to_string_lossy().into_owned();
        if entry.kind != Kind::Dir {
            load.skipped.push(SkippedAgentEntry::NotADirectory(shown));
            continue;
        }
        let Some(id) = entry.name.to_str().and_then(|n| AgentId::parse(n).ok()) else {
            load.skipped.push(SkippedAgentEntry::InvalidName(shown));
            continue;
        };
        let at = Path::new(id.as_str());
        let Some(text) =
            read_optional(&anchor, &agents, &at.join(ENROLLMENT_FILE), &desc, &target)?
        else {
            load.skipped.push(SkippedAgentEntry::NoEnrollment(shown));
            continue;
        };
        load.enrollments.push(parse_agent_enrollment(&id, &text)?);
        if let Some(text) = read_optional(&anchor, &agents, &at.join(POLICY_FILE), &desc, &target)?
        {
            let policy = parse_agent_policy(&id, &text).map_err(|e| {
                ConfigError::InvalidAgent(format!(
                    "{AGENTS_DIR}/{}/{POLICY_FILE}: {e}",
                    id.as_str()
                ))
            })?;
            load.policies.push(policy);
        }
    }
    Ok(load)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountRefusal {
    NoSuchAccount(String),
    RootAccount,
    IsPrincipal,
    MaknaeDaemonAccount(String),
    MaknaeGroupMember,
    LoginShell(String),
    AccountInUse { account: String, agent: String },
}

impl std::fmt::Display for AccountRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchAccount(a) => write!(
                f,
                "no account named {a} exists on this host; create a service account for the Agent Daemon first"
            ),
            Self::RootAccount => write!(
                f,
                "the account is root; run the Agent Daemon under its own unprivileged service account"
            ),
            Self::IsPrincipal => write!(
                f,
                "the account is the principal's own account; run the Agent Daemon under a separate service account"
            ),
            Self::MaknaeDaemonAccount(a) => write!(
                f,
                "account {a} belongs to a Maknae daemon or can read its files; run the Agent Daemon under its own service account"
            ),
            Self::MaknaeGroupMember => write!(
                f,
                "the account is in the maknae group, which grants read of Maknae's configuration; use an account outside it"
            ),
            Self::LoginShell(s) => write!(
                f,
                "the account's shell {s} is not a non-login shell; give the Agent Daemon account /usr/sbin/nologin (Linux) or /usr/bin/false (macOS)"
            ),
            Self::AccountInUse { account, agent } => write!(
                f,
                "account {account} is already enrolled for agent {agent}; each Agent Daemon needs its own account"
            ),
        }
    }
}

impl std::error::Error for AccountRefusal {}

pub struct HostAccounts<'a> {
    pub maknae_gid: Option<u32>,
    pub principal_uid: u32,
    pub daemons: &'a DaemonFacts,
    pub other_agents: &'a [(String, u32)],
}

pub fn service_account_check(
    acct: Option<&HostAccount>,
    account_name: &str,
    agent: &AgentId,
    host: &HostAccounts<'_>,
) -> Result<(), AccountRefusal> {
    let acct = acct.ok_or_else(|| AccountRefusal::NoSuchAccount(account_name.to_string()))?;
    if acct.uid == 0 {
        return Err(AccountRefusal::RootAccount);
    }
    if acct.uid == host.principal_uid {
        return Err(AccountRefusal::IsPrincipal);
    }
    let daemon = maknae_io::MAKNAE_DAEMON_ACCOUNTS.contains(&acct.name.as_str())
        || host.daemons.uids.contains(&acct.uid)
        || acct
            .named_groups
            .iter()
            .any(|g| host.daemons.gids.contains(g));
    if daemon {
        return Err(AccountRefusal::MaknaeDaemonAccount(acct.name.clone()));
    }
    if host
        .maknae_gid
        .is_some_and(|g| acct.named_groups.contains(&g))
    {
        return Err(AccountRefusal::MaknaeGroupMember);
    }
    let shell = acct.shell.trim();
    if !NON_LOGIN_SHELLS.contains(&shell) {
        let shown = if shell.is_empty() { "(empty)" } else { shell };
        return Err(AccountRefusal::LoginShell(shown.to_string()));
    }
    if let Some((other, _)) = host
        .other_agents
        .iter()
        .find(|(id, uid)| id != agent.as_str() && *uid == acct.uid)
    {
        return Err(AccountRefusal::AccountInUse {
            account: acct.name.clone(),
            agent: other.clone(),
        });
    }
    Ok(())
}

/// The highest of `admin`, `user` and `guest` whose entries name the account: by its name,
/// a `uid:` entry, or another name `uid_of` resolves to its uid.
pub fn bindings_conflict(
    bindings: &Bindings,
    account: &str,
    uid: u32,
    uid_of: impl Fn(&str) -> Option<u32>,
) -> Option<&'static str> {
    let roles = bindings.roles.as_ref()?;
    ["admin", "user", "guest"].into_iter().find(|role| {
        roles.get(*role).is_some_and(|members| {
            members.iter().any(|m| match m {
                BindingEntry::Name(n) => n == account || uid_of(n) == Some(uid),
                BindingEntry::Uid(u) => *u == uid,
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{ActionPattern, ModelRef};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn hobi() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    fn account() -> HostAccount {
        HostAccount {
            uid: 990,
            name: "hobi-svc".into(),
            primary_gid: 990,
            shell: "/usr/sbin/nologin".into(),
            dir: "/var/empty".into(),
            named_groups: vec![990],
        }
    }

    fn daemons() -> DaemonFacts {
        DaemonFacts {
            uids: vec![970, 971],
            gids: vec![970, 971],
        }
    }

    fn check_with(
        a: Option<&HostAccount>,
        maknae_gid: Option<u32>,
        others: &[(String, u32)],
    ) -> Result<(), AccountRefusal> {
        let d = daemons();
        let host = HostAccounts {
            maknae_gid,
            principal_uid: 1000,
            daemons: &d,
            other_agents: others,
        };
        let name = a.map_or("ghost".to_string(), |a| a.name.clone());
        service_account_check(a, &name, &hobi(), &host)
    }

    fn check(a: &HostAccount, others: &[(String, u32)]) -> Result<(), AccountRefusal> {
        check_with(Some(a), Some(980), others)
    }

    #[test]
    fn agent_id_keeps_the_enrollment_charset() {
        for ok in ["hobi", "a", "_x", "a.b-c_d", &"a".repeat(32)] {
            assert_eq!(AgentId::parse(ok).unwrap().as_str(), ok);
        }
        for bad in [
            "",
            "*",
            "a/b",
            "data",
            "Hobi",
            "-a",
            "a-",
            "a.",
            "a b",
            "a+b",
            &"a".repeat(33),
        ] {
            assert_eq!(
                AgentId::parse(bad),
                Err(InvalidAgentId(bad.into())),
                "{bad:?}"
            );
        }
        assert_eq!(hobi().role_name(), "agent-hobi");
        assert!(InvalidAgentId("Q".into()).to_string().contains("\"Q\""));
    }

    #[test]
    fn agent_role_never_parses_admin_or_adversary() {
        assert_eq!(AgentRole::parse("user"), Some(AgentRole::User));
        assert_eq!(AgentRole::parse("guest"), Some(AgentRole::Guest));
        for refused in ["admin", "adversary", "User", "", " user", "agent"] {
            assert_eq!(AgentRole::parse(refused), None, "{refused:?}");
        }
        for role in [AgentRole::User, AgentRole::Guest] {
            assert_eq!(AgentRole::parse(role.key()), Some(role));
        }
        assert_eq!(AgentRole::User.key(), "user");
        assert_eq!(AgentRole::Guest.key(), "guest");
    }

    #[test]
    fn each_refusal_in_order() {
        let in_use = vec![("suga".to_string(), 990), ("jin".to_string(), 0)];
        let mut worst = account();
        worst.named_groups = vec![990, 970, 980];
        worst.shell = "/bin/bash".into();

        assert_eq!(
            check_with(None, Some(980), &in_use),
            Err(AccountRefusal::NoSuchAccount("ghost".into()))
        );
        let mut a = worst.clone();
        a.uid = 0;
        a.name = "_maknae".into();
        assert_eq!(check(&a, &in_use), Err(AccountRefusal::RootAccount));
        let mut a = worst.clone();
        a.uid = 1000;
        a.name = "_maknae".into();
        assert_eq!(check(&a, &in_use), Err(AccountRefusal::IsPrincipal));
        let mut a = worst.clone();
        a.name = "_maknae-egress".into();
        assert_eq!(
            check(&a, &in_use),
            Err(AccountRefusal::MaknaeDaemonAccount("_maknae-egress".into()))
        );
        let mut a = worst.clone();
        a.named_groups = vec![990, 980];
        a.uid = 971;
        assert_eq!(
            check(&a, &in_use),
            Err(AccountRefusal::MaknaeDaemonAccount("hobi-svc".into()))
        );
        assert_eq!(
            check(&worst, &in_use),
            Err(AccountRefusal::MaknaeDaemonAccount("hobi-svc".into()))
        );
        let mut a = worst.clone();
        a.named_groups = vec![990, 980];
        assert_eq!(check(&a, &in_use), Err(AccountRefusal::MaknaeGroupMember));
        let mut a = worst.clone();
        a.named_groups = vec![990];
        assert_eq!(
            check(&a, &in_use),
            Err(AccountRefusal::LoginShell("/bin/bash".into()))
        );
        assert_eq!(
            check(&account(), &in_use),
            Err(AccountRefusal::AccountInUse {
                account: "hobi-svc".into(),
                agent: "suga".into()
            })
        );
        assert_eq!(check(&account(), &[]), Ok(()));
        let own = vec![("hobi".to_string(), 990)];
        assert_eq!(check(&account(), &own), Ok(()));
    }

    #[test]
    fn a_daemon_primary_group_is_a_daemon_account() {
        let mut a = account();
        a.primary_gid = 970;
        a.named_groups = vec![970];
        assert_eq!(
            check(&a, &[]),
            Err(AccountRefusal::MaknaeDaemonAccount("hobi-svc".into()))
        );
    }

    #[test]
    fn a_member_of_a_daemon_group_with_its_own_gid_is_a_daemon_account() {
        let daemons = DaemonFacts::assemble(&[(971, 971)], &[975]);
        let host = HostAccounts {
            maknae_gid: Some(980),
            principal_uid: 1000,
            daemons: &daemons,
            other_agents: &[],
        };
        let mut a = account();
        a.named_groups = vec![990, 975];
        assert_eq!(
            service_account_check(Some(&a), &a.name, &hobi(), &host),
            Err(AccountRefusal::MaknaeDaemonAccount("hobi-svc".into()))
        );
        assert_eq!(
            service_account_check(Some(&account()), "hobi-svc", &hobi(), &host),
            Ok(())
        );
    }

    #[test]
    fn a_supplementary_maknae_member_is_refused() {
        let mut a = account();
        a.named_groups = vec![990, 980];
        assert_eq!(check(&a, &[]), Err(AccountRefusal::MaknaeGroupMember));
        let mut a = account();
        a.primary_gid = 980;
        a.named_groups = vec![980];
        assert_eq!(check(&a, &[]), Err(AccountRefusal::MaknaeGroupMember));
        let mut a = account();
        a.named_groups = vec![990, 980];
        assert_eq!(check_with(Some(&a), None, &[]), Ok(()));
    }

    #[test]
    fn each_non_login_shell_passes() {
        for sh in NON_LOGIN_SHELLS {
            for spelled in [sh.to_string(), format!(" {sh} ")] {
                let mut a = account();
                a.shell = spelled.clone();
                assert_eq!(check(&a, &[]), Ok(()), "{spelled:?}");
            }
        }
        for sh in [
            "/bin/bash",
            "/usr/bin/zsh",
            "/bin/sh",
            "/usr/sbin/nologin2",
            "/usr/sbin/nologin/x",
        ] {
            let mut a = account();
            a.shell = format!(" {sh} ");
            assert_eq!(
                check(&a, &[]),
                Err(AccountRefusal::LoginShell(sh.into())),
                "{sh:?}"
            );
        }
    }

    #[test]
    fn an_empty_shell_is_a_login_shell() {
        for empty in ["", "  "] {
            let mut a = account();
            a.shell = empty.into();
            assert_eq!(
                check(&a, &[]),
                Err(AccountRefusal::LoginShell("(empty)".into())),
                "{empty:?}"
            );
        }
    }

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("maknae_agents_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o750)).unwrap();
            Self { root }
        }

        fn agents(&self) -> PathBuf {
            let dir = self.root.join(AGENTS_DIR);
            if !dir.exists() {
                std::fs::create_dir(&dir).unwrap();
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
            }
            dir
        }

        fn dir(&self, name: &str) -> PathBuf {
            let dir = self.agents().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
            dir
        }

        fn file(&self, rel: &str, body: &str, mode: u32) {
            let path = self.agents().join(rel);
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }

        fn enroll(&self, id: &str, body: &str) {
            self.dir(id);
            self.file(&format!("{id}/{ENROLLMENT_FILE}"), body, 0o640);
        }

        fn load(&self) -> Result<AgentsLoad, ConfigError> {
            use std::os::unix::fs::MetadataExt;
            let uid = std::fs::metadata(&self.root).unwrap().uid();
            load_agents_required(
                &self.root,
                AnchorRequired {
                    owner: Some(uid),
                    ..agents_dir_required()
                },
                TargetRequired {
                    owner: Some(uid),
                    ..agent_file_required()
                },
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn enrollment(id: &str, account: &str, uid: u32, role: &str) -> String {
        format!(
            "agent_id: {id}\naccount: {account}\nuid: {uid}\nrole: {role}\napprole_mount: maknae-agent-approle\nrole_name: agent-{id}\nrole_id: r-1\nbind_cidrs: [\"10.0.0.5/32\"]\nsource: tpm2\n"
        )
    }

    const POLICY: &str = "schema_version: 1\npermissions:\n  allow: [\"Read(~/work/**)\"]\n  deny: [\"Write(/etc/**)\"]\nactions:\n  allow: [\"fs.*\", \"session.task\"]\n  deny: [\"fs.write\"]\nmodels:\n  allow: [\"anthropic/claude-opus\"]\n";

    #[test]
    fn production_requirements_are_root_owned_and_masked() {
        assert_eq!(
            agents_dir_required(),
            AnchorRequired {
                owner: Some(0),
                mode_mask: Some(0o027),
            }
        );
        assert_eq!(
            agent_file_required(),
            TargetRequired {
                owner: Some(0),
                mode_mask: Some(0o027),
                nlink_exactly_one: true,
                regular_file: true,
                max_bytes: Some(64 * 1024),
            }
        );
    }

    #[test]
    fn load_agents_reads_one_directory_per_agent() {
        let f = Fixture::new("reads");
        f.enroll("suga", &enrollment("suga", "suga-svc", 991, "guest"));
        f.enroll("hobi", &enrollment("hobi", "hobi-svc", 990, "user"));
        f.file(&format!("hobi/{POLICY_FILE}"), POLICY, 0o640);
        let got = f.load().unwrap();
        assert_eq!(
            got.enrollments,
            vec![
                AgentEnrollment {
                    id: hobi(),
                    account: "hobi-svc".into(),
                    uid: 990,
                    role: AgentRole::User,
                },
                AgentEnrollment {
                    id: AgentId::parse("suga").unwrap(),
                    account: "suga-svc".into(),
                    uid: 991,
                    role: AgentRole::Guest,
                },
            ]
        );
        assert_eq!(
            got.policies,
            vec![parse_agent_policy(&hobi(), POLICY).unwrap()]
        );
        assert_eq!(got.skipped, vec![]);
    }

    #[test]
    fn a_directory_without_enrollment_is_skipped() {
        let f = Fixture::new("noenroll");
        f.dir("jin");
        f.file(&format!("jin/{POLICY_FILE}"), POLICY, 0o640);
        let got = f.load().unwrap();
        assert_eq!(
            got.skipped,
            vec![SkippedAgentEntry::NoEnrollment("jin".into())]
        );
        assert_eq!((got.enrollments, got.policies), (vec![], vec![]));
    }

    #[test]
    fn a_stray_file_in_agents_is_skipped() {
        let f = Fixture::new("stray");
        f.file(
            "hobi.yaml",
            &enrollment("hobi", "hobi-svc", 990, "user"),
            0o640,
        );
        let got = f.load().unwrap();
        assert_eq!(
            got.skipped,
            vec![SkippedAgentEntry::NotADirectory("hobi.yaml".into())]
        );
        assert_eq!(got.enrollments, vec![]);
    }

    #[test]
    fn an_invalid_directory_name_is_skipped() {
        let f = Fixture::new("badname");
        f.enroll("Hobi", &enrollment("Hobi", "hobi-svc", 990, "user"));
        f.enroll("data", &enrollment("data", "data-svc", 992, "user"));
        let got = f.load().unwrap();
        assert_eq!(
            got.skipped,
            vec![
                SkippedAgentEntry::InvalidName("Hobi".into()),
                SkippedAgentEntry::InvalidName("data".into()),
            ]
        );
        assert_eq!(got.enrollments, vec![]);
    }

    #[test]
    fn a_record_for_another_id_refuses_the_load() {
        let f = Fixture::new("otherid");
        f.enroll("hobi", &enrollment("suga", "hobi-svc", 990, "user"));
        assert!(
            matches!(f.load(), Err(ConfigError::InvalidAgent(ref m)) if m.contains("hobi") && m.contains("suga")),
            "{:?}",
            f.load()
        );
    }

    #[test]
    fn role_admin_refuses_the_load() {
        for role in ["admin", "adversary", "root"] {
            let f = Fixture::new(&format!("role_{role}"));
            f.enroll("hobi", &enrollment("hobi", "hobi-svc", 990, role));
            assert!(
                matches!(f.load(), Err(ConfigError::InvalidAgent(ref m)) if m.contains(role)),
                "{role}: {:?}",
                f.load()
            );
        }
    }

    #[test]
    fn a_malformed_enrollment_refuses_the_load() {
        let good = "agent_id: hobi\naccount: hobi-svc\nuid: 990\nrole: user\n";
        assert!(parse_agent_enrollment(&hobi(), good).is_ok());
        for bad in [
            "agent_id: hobi\naccount: hobi-svc\nuid: 990\n",
            "account: hobi-svc\nuid: 990\nrole: user\n",
            "agent_id: hobi\nuid: 990\nrole: user\n",
            "agent_id: hobi\naccount: hobi-svc\nrole: user\n",
            "agent_id: hobi\naccount: \"\"\nuid: 990\nrole: user\n",
            "agent_id: hobi\naccount: \"a:b\"\nuid: 990\nrole: user\n",
            "agent_id: hobi\naccount: hobi-svc\nuid: -1\nrole: user\n",
            "agent_id: hobi\naccount: hobi-svc\nuid: 4294967296\nrole: user\n",
            "agent_id: hobi\naccount: hobi-svc\nuid: \"990\"\nrole: user\n",
            "agent_id: hobi\naccount: 7\nuid: 990\nrole: user\n",
            "agent_id: hobi\naccount: hobi-svc\nuid: 990\nrole: [user]\n",
            "- agent_id: hobi\n",
            "agent_id: [\n",
        ] {
            assert!(
                matches!(
                    parse_agent_enrollment(&hobi(), bad),
                    Err(ConfigError::InvalidAgent(_))
                ),
                "{bad:?}"
            );
        }
        let f = Fixture::new("malformed");
        f.enroll("hobi", "agent_id: hobi\naccount: hobi-svc\nuid: 990\n");
        assert!(matches!(f.load(), Err(ConfigError::InvalidAgent(_))));
    }

    #[test]
    fn a_non_utf8_enrollment_refuses_the_load() {
        let f = Fixture::new("utf8");
        f.dir("hobi");
        let path = f.agents().join("hobi").join(ENROLLMENT_FILE);
        std::fs::write(&path, b"agent_id: \xff\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            matches!(f.load(), Err(ConfigError::Io(ref m)) if m.contains("UTF-8")),
            "{:?}",
            f.load()
        );
    }

    #[test]
    fn a_malformed_policy_refuses_the_load() {
        let f = Fixture::new("badpolicy");
        f.enroll("hobi", &enrollment("hobi", "hobi-svc", 990, "user"));
        f.file(
            &format!("hobi/{POLICY_FILE}"),
            "schema_version: 1\nbogus: 1\n",
            0o640,
        );
        assert_eq!(
            f.load().map_err(|e| e.to_string()),
            Err("agent configuration refused: agents/hobi/policy.yaml: unknown key 'bogus' in 'policy'".into())
        );
        f.file(
            &format!("hobi/{POLICY_FILE}"),
            "schema_version: 1\npermissions:\n  extra: []\n",
            0o640,
        );
        assert_eq!(
            f.load().map_err(|e| e.to_string()),
            Err("agent configuration refused: agents/hobi/policy.yaml: unknown key 'extra' in 'policy.permissions'".into())
        );
    }

    #[test]
    fn an_insecure_or_linked_file_refuses_the_load() {
        let f = Fixture::new("groupw");
        f.enroll("hobi", &enrollment("hobi", "hobi-svc", 990, "user"));
        std::fs::set_permissions(
            f.agents().join("hobi").join(ENROLLMENT_FILE),
            std::fs::Permissions::from_mode(0o660),
        )
        .unwrap();
        assert!(matches!(
            f.load(),
            Err(ConfigError::InsecurePermissions { .. })
        ));

        let f = Fixture::new("worldr");
        f.enroll("hobi", &enrollment("hobi", "hobi-svc", 990, "user"));
        f.file(&format!("hobi/{POLICY_FILE}"), POLICY, 0o644);
        assert!(matches!(
            f.load(),
            Err(ConfigError::InsecurePermissions { .. })
        ));

        let f = Fixture::new("symlink");
        f.enroll("hobi", &enrollment("hobi", "hobi-svc", 990, "user"));
        f.file("elsewhere.yaml", POLICY, 0o640);
        std::os::unix::fs::symlink(
            f.agents().join("elsewhere.yaml"),
            f.agents().join("hobi").join(POLICY_FILE),
        )
        .unwrap();
        assert!(
            matches!(f.load(), Err(ConfigError::Symlink { .. })),
            "{:?}",
            f.load()
        );

        let f = Fixture::new("hardlink");
        f.enroll("hobi", &enrollment("hobi", "hobi-svc", 990, "user"));
        std::fs::hard_link(
            f.agents().join("hobi").join(ENROLLMENT_FILE),
            f.root.join("linked.yaml"),
        )
        .unwrap();
        assert!(
            matches!(f.load(), Err(ConfigError::Io(ref m)) if m.contains("link")),
            "{:?}",
            f.load()
        );

        let f = Fixture::new("big");
        let pad = format!("# {}\n", "x".repeat(64 * 1024));
        f.enroll(
            "hobi",
            &(enrollment("hobi", "hobi-svc", 990, "user") + &pad),
        );
        assert!(
            matches!(f.load(), Err(ConfigError::Io(ref m)) if m.contains("65536")),
            "{:?}",
            f.load()
        );

        let f = Fixture::new("dirmode");
        f.enroll("hobi", &enrollment("hobi", "hobi-svc", 990, "user"));
        std::fs::set_permissions(
            f.agents().join("hobi"),
            std::fs::Permissions::from_mode(0o770),
        )
        .unwrap();
        assert!(matches!(
            f.load(),
            Err(ConfigError::InsecurePermissions { .. })
        ));

        let f = Fixture::new("agentsmode");
        f.enroll("hobi", &enrollment("hobi", "hobi-svc", 990, "user"));
        std::fs::set_permissions(f.agents(), std::fs::Permissions::from_mode(0o757)).unwrap();
        assert!(matches!(
            f.load(),
            Err(ConfigError::InsecurePermissions { .. })
        ));
    }

    #[test]
    fn a_symlinked_agent_directory_is_skipped_never_followed() {
        let f = Fixture::new("dirlink");
        f.enroll("real", &enrollment("hobi", "hobi-svc", 990, "user"));
        std::os::unix::fs::symlink(f.agents().join("real"), f.agents().join("hobi")).unwrap();
        let got = f.load();
        assert!(
            matches!(&got, Err(ConfigError::InvalidAgent(_))),
            "the real directory's mismatched record refuses: {got:?}"
        );
        std::fs::write(
            f.agents().join("real").join(ENROLLMENT_FILE),
            enrollment("real", "real-svc", 993, "user"),
        )
        .unwrap();
        let got = f.load().unwrap();
        assert_eq!(
            got.skipped,
            vec![SkippedAgentEntry::NotADirectory("hobi".into())]
        );
        assert_eq!(got.enrollments.len(), 1);
    }

    #[test]
    fn load_agents_holds_the_tree_to_root_ownership() {
        use std::os::unix::fs::MetadataExt;
        let f = Fixture::new("production");
        f.enroll("hobi", &enrollment("hobi", "hobi-svc", 990, "user"));
        let got = load_agents(&f.root);
        if std::fs::metadata(&f.root).unwrap().uid() == 0 {
            assert_eq!(got.unwrap().enrollments.len(), 1);
        } else {
            assert!(
                matches!(&got, Err(ConfigError::Io(m)) if m.contains("require 0")),
                "{got:?}"
            );
        }
    }

    #[test]
    fn load_agents_with_requirement_reads_under_the_given_requirement() {
        use std::os::unix::fs::MetadataExt;
        let f = Fixture::new("seam");
        f.enroll("hobi", &enrollment("hobi", "hobi-svc", 990, "user"));
        let uid = std::fs::metadata(&f.root).unwrap().uid();
        let got = load_agents_with_requirement(
            &f.root,
            AnchorRequired {
                owner: Some(uid),
                ..agents_dir_required()
            },
            TargetRequired {
                owner: Some(uid),
                ..agent_file_required()
            },
        )
        .unwrap();
        assert_eq!(got, f.load().unwrap());
        assert_eq!(got.enrollments[0].id, hobi());
    }

    #[test]
    fn a_missing_agent_directory_under_read_optional_is_an_error_not_absence() {
        use std::os::unix::fs::MetadataExt;
        let f = Fixture::new("gone_intermediate");
        let agents = f.agents();
        let uid = std::fs::metadata(&f.root).unwrap().uid();
        let dir = AnchorRequired {
            owner: Some(uid),
            ..agents_dir_required()
        };
        let desc = DescendantRequired {
            owner: dir.owner,
            mode_mask: dir.mode_mask,
        };
        let target = TargetRequired {
            owner: Some(uid),
            ..agent_file_required()
        };
        let abs = std::path::absolute(&agents).unwrap();
        let anchor = maknae_io::open_anchor(&abs, dir, StrategyPref::Auto).unwrap();
        let rel = Path::new("nope").join(ENROLLMENT_FILE);
        assert!(
            read_optional(&anchor, &abs, &rel, &desc, &target).is_err(),
            "a missing agent directory is not a missing enrollment"
        );
        f.dir("nope");
        assert_eq!(read_optional(&anchor, &abs, &rel, &desc, &target), Ok(None));
    }

    #[test]
    fn entity_name_is_the_prefixed_id() {
        assert_eq!(hobi().entity_name(), "maknae-agent-hobi");
        assert!(hobi().entity_name().starts_with(AGENT_ENTITY_PREFIX));
    }

    #[test]
    fn every_account_refusal_says_what_to_do() {
        let shown = [
            (
                AccountRefusal::NoSuchAccount("ghost".into()),
                "no account named ghost",
            ),
            (AccountRefusal::RootAccount, "the account is root"),
            (AccountRefusal::IsPrincipal, "principal's own account"),
            (
                AccountRefusal::MaknaeDaemonAccount("_maknae".into()),
                "account _maknae belongs to a Maknae daemon",
            ),
            (AccountRefusal::MaknaeGroupMember, "in the maknae group"),
            (
                AccountRefusal::LoginShell("/bin/bash".into()),
                "shell /bin/bash is not",
            ),
            (
                AccountRefusal::AccountInUse {
                    account: "hobi-svc".into(),
                    agent: "suga".into(),
                },
                "account hobi-svc is already enrolled for agent suga",
            ),
        ];
        for (refusal, want) in shown {
            let text = refusal.to_string();
            assert!(text.contains(want), "{text}");
        }
    }

    #[test]
    fn a_missing_agents_directory_is_no_agents() {
        let f = Fixture::new("missing");
        assert_eq!(f.load(), Ok(AgentsLoad::default()));
        let gone = Fixture::new("gone_root");
        let root = gone.root.join("nope");
        assert_eq!(
            load_agents_required(&root, agents_dir_required(), agent_file_required()),
            Err(ConfigError::NotFound {
                path: root.display().to_string()
            })
        );
    }

    #[test]
    fn agent_policy_parses_the_subjects_entry_grammar() {
        let got = parse_agent_policy(&hobi(), POLICY).unwrap();
        assert_eq!(got.id, hobi());
        assert_eq!(got.taskers, None);
        let p = got.entry.permissions.as_ref().unwrap();
        assert_eq!(p.allow_sources(), ["Read(~/work/**)"]);
        assert_eq!(p.deny_sources(), ["Write(/etc/**)"]);
        let a = got.entry.actions.as_ref().unwrap();
        assert_eq!(
            a.allow,
            vec![
                ActionPattern::Family("fs".into()),
                ActionPattern::Exact("session.task".into())
            ]
        );
        assert_eq!(a.deny, vec![ActionPattern::Exact("fs.write".into())]);
        assert_eq!(
            got.entry.models,
            Some(vec![ModelRef {
                provider: "anthropic".into(),
                model: "claude-opus".into()
            }])
        );
        let body = crate::load_str(POLICY).unwrap();
        let crate::value::Value::Map(m) = body else {
            panic!()
        };
        let entry: Vec<_> = m
            .into_iter()
            .filter(|(k, _)| k != "schema_version")
            .collect();
        assert_eq!(
            got.entry,
            crate::authz::parse_subject_entry("hobi", &crate::value::Value::Map(entry)).unwrap()
        );
        assert_eq!(
            got.canonical,
            crate::value::canonical_json(&crate::load_str(POLICY).unwrap())
        );
        let other = parse_agent_policy(&hobi(), "schema_version: 1\n").unwrap();
        assert_ne!(other.canonical, got.canonical);
    }

    #[test]
    fn agent_policy_refuses_an_unknown_key() {
        for unknown in ["subjects", "roles", "bindings", "destinations", "role"] {
            let text = format!("schema_version: 1\n{unknown}: {{}}\n");
            assert!(
                matches!(
                    parse_agent_policy(&hobi(), &text),
                    Err(AuthzError::Config(ConfigError::UnknownKey { ref key, .. })) if key == unknown
                ),
                "{text}"
            );
        }
        assert!(matches!(
            parse_agent_policy(
                &hobi(),
                "schema_version: 1\npermissions:\n  allow: []\n  extra: []\n"
            ),
            Err(AuthzError::Config(ConfigError::UnknownKey { .. }))
        ));
        assert_eq!(
            parse_agent_policy(&hobi(), "permissions: {}\n"),
            Err(AuthzError::UnknownSchemaVersion(0))
        );
        assert_eq!(
            parse_agent_policy(&hobi(), "schema_version: 2\n"),
            Err(AuthzError::UnknownSchemaVersion(2))
        );
        assert!(matches!(
            parse_agent_policy(&hobi(), "- 1\n"),
            Err(AuthzError::Yaml(_))
        ));
        assert!(matches!(
            parse_agent_policy(&hobi(), "schema_version: [\n"),
            Err(AuthzError::Yaml(_))
        ));
        assert!(matches!(
            parse_agent_policy(
                &hobi(),
                "schema_version: 1\nactions:\n  allow: [\"nope\"]\n"
            ),
            Err(AuthzError::BadPattern(_))
        ));
    }

    #[test]
    fn agent_policy_is_optional() {
        let f = Fixture::new("optional");
        f.enroll("hobi", &enrollment("hobi", "hobi-svc", 990, "user"));
        let got = f.load().unwrap();
        assert_eq!(got.enrollments.len(), 1);
        assert_eq!(got.policies, vec![]);
        let bare = parse_agent_policy(&hobi(), "schema_version: 1\n").unwrap();
        assert_eq!(bare.entry, SubjectPolicy::default());
        assert_eq!(bare.taskers, None);
    }

    #[test]
    fn taskers_parse_uid_account_and_agent_forms() {
        let got = parse_agent_policy(
            &hobi(),
            "schema_version: 1\ntaskers: [\"uid:1001\", \"ann\", \"agent:suga\", \"uid:0\"]\n",
        )
        .unwrap();
        assert_eq!(
            got.taskers,
            Some(vec![
                TaskerRef::Uid(1001),
                TaskerRef::Account("ann".into()),
                TaskerRef::Agent(AgentId::parse("suga").unwrap()),
                TaskerRef::Uid(0),
            ])
        );
        let none = parse_agent_policy(&hobi(), "schema_version: 1\ntaskers: []\n").unwrap();
        assert_eq!(none.taskers, Some(vec![]));
    }

    #[test]
    fn a_malformed_tasker_refuses_the_policy() {
        for bad in [
            "\"uid:x\"",
            "\"agent:HOBI\"",
            "\"uid:\"",
            "\"uid:+1\"",
            "\"uid:01\"",
            "\"uid:4294967296\"",
            "\"agent:\"",
            "\"\"",
            "\"x:y\"",
            "\"a,b\"",
            "7",
            "{uid: 7}",
        ] {
            let text = format!("schema_version: 1\ntaskers: [{bad}]\n");
            assert!(parse_agent_policy(&hobi(), &text).is_err(), "{bad}");
        }
        assert!(parse_agent_policy(&hobi(), "schema_version: 1\ntaskers: ann\n").is_err());
    }

    fn bindings(body: &str) -> Bindings {
        crate::bindings::parse_bindings(&format!("schema_version: 1\nbindings:\n{body}")).unwrap()
    }

    #[test]
    fn bindings_conflict_names_admin_user_and_guest_by_name_or_uid() {
        for role in ["admin", "user", "guest"] {
            let by_name = bindings(&format!("  {role}: [\"hobi-svc\"]\n"));
            assert_eq!(
                bindings_conflict(&by_name, "hobi-svc", 990, none),
                Some(role)
            );
            let by_uid = bindings(&format!("  {role}: [{{uid: 990}}]\n"));
            assert_eq!(
                bindings_conflict(&by_uid, "hobi-svc", 990, none),
                Some(role)
            );
            assert_eq!(bindings_conflict(&by_uid, "hobi-svc", 991, none), None);
            assert_eq!(bindings_conflict(&by_name, "suga-svc", 990, none), None);
        }
        let both = bindings("  user: [\"hobi-svc\"]\n  admin: [{uid: 990}]\n");
        assert_eq!(
            bindings_conflict(&both, "hobi-svc", 990, none),
            Some("admin")
        );
    }

    fn none(_: &str) -> Option<u32> {
        None
    }

    #[test]
    fn bindings_conflict_names_a_role_bound_by_a_uid_alias() {
        let alias = |n: &str| (n == "hobi-alt").then_some(990);
        let b = bindings("  user: [\"hobi-svc\"]\n  admin: [\"hobi-alt\"]\n");
        assert_eq!(bindings_conflict(&b, "hobi-svc", 990, alias), Some("admin"));
        assert_eq!(bindings_conflict(&b, "suga-svc", 991, alias), None);
    }

    #[test]
    fn bindings_conflict_ignores_adversary_and_absent() {
        let adv = bindings("  adversary: [\"hobi-svc\", {uid: 990}]\n");
        assert_eq!(bindings_conflict(&adv, "hobi-svc", 990, none), None);
        assert_eq!(
            bindings_conflict(&Bindings::absent(), "hobi-svc", 990, none),
            None
        );
        assert_eq!(
            bindings_conflict(&Bindings::missing(), "hobi-svc", 990, none),
            None
        );
        assert_eq!(
            bindings_conflict(&bindings("  admin: []\n"), "hobi-svc", 990, none),
            None
        );
    }
}
