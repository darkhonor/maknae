use std::fmt;
use std::net::IpAddr;

pub const DEFAULT_AGENT_APPROLE_MOUNT: &str = "maknae-agent-approle";
pub const AGENT_CREDENTIAL_NAME: &str = "maknae-agent-secret-id";
pub const AGENT_SIGNING_IDENTIFIER: &str = "io.maknae.maknae-agentd";
pub const MAKNAE_DAEMON_ACCOUNTS: [&str; 2] = ["_maknae", "_maknae-egress"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentEnrollError {
    InvalidAgentId(String),
    NoBindCidr,
    InvalidCidr(String),
    CatchAllCidr(String),
    HostBitsSet { given: String, network: String },
    NoSuchAccount(String),
    ShellsUnreadable,
    RootAccount,
    IsPrincipal,
    MaknaeDaemonAccount(String),
    MaknaeGroupMember,
    LoginShell(String),
    AccountInUse { account: String, agent: String },
}

impl fmt::Display for AgentEnrollError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAgentId(id) => write!(
                f,
                "agent id {id:?} is not valid; use 1 to 32 characters of a-z, 0-9, '.', '_' or '-', starting and ending with a letter, digit or '_', and not \"data\""
            ),
            Self::NoBindCidr => write!(
                f,
                "at least one --bind-cidr is required; the SecretID is only usable from the Agent Daemon's own address"
            ),
            Self::InvalidCidr(c) => write!(
                f,
                "{c:?} is not an IP address or CIDR; use addr or addr/prefix, for example 10.0.0.5/32"
            ),
            Self::CatchAllCidr(c) => write!(
                f,
                "{c} matches every address and would not bind the SecretID; name the Agent Daemon's own address or network"
            ),
            Self::HostBitsSet { given, network } => {
                write!(f, "{given} has host bits set; use {network}")
            }
            Self::NoSuchAccount(a) => write!(
                f,
                "no account named {a} exists on this host; create a service account for the Agent Daemon first"
            ),
            Self::ShellsUnreadable => write!(
                f,
                "/etc/shells could not be read, so the account's shell cannot be checked; restore /etc/shells and retry"
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
                "the account's shell {s} is listed in /etc/shells, so a person can log in as it; give the Agent Daemon account a shell that is not (for example /usr/sbin/nologin)"
            ),
            Self::AccountInUse { account, agent } => write!(
                f,
                "account {account} is already enrolled for agent {agent}; each Agent Daemon needs its own account"
            ),
        }
    }
}

impl std::error::Error for AgentEnrollError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentId(String);

impl AgentId {
    pub fn parse(raw: &str) -> Result<Self, AgentEnrollError> {
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
            Err(AgentEnrollError::InvalidAgentId(raw.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn role_name(&self) -> String {
        format!("agent-{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindCidrs(Vec<String>);

impl BindCidrs {
    pub fn parse(raw: &[String]) -> Result<Self, AgentEnrollError> {
        if raw.is_empty() {
            return Err(AgentEnrollError::NoBindCidr);
        }
        let mut out: Vec<String> = Vec::new();
        for item in raw {
            let canonical = canonical_cidr(item)?;
            if !out.contains(&canonical) {
                out.push(canonical);
            }
        }
        Ok(Self(out))
    }

    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

fn canonical_cidr(item: &str) -> Result<String, AgentEnrollError> {
    let invalid = || AgentEnrollError::InvalidCidr(item.to_string());
    let (addr_text, prefix_text) = match item.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (item, None),
    };
    let addr: IpAddr = addr_text.parse().map_err(|_| invalid())?;
    let max: u8 = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_text {
        Some(p) => p.parse::<u8>().map_err(|_| invalid())?,
        None => max,
    };
    if prefix > max {
        return Err(invalid());
    }
    if prefix == 0 {
        return Err(AgentEnrollError::CatchAllCidr(item.to_string()));
    }
    let (masked, network) = match addr {
        IpAddr::V4(a) => {
            let bits = u32::from(a);
            let m = bits & (u32::MAX << (32 - u32::from(prefix)));
            (m == bits, IpAddr::from(m.to_be_bytes()))
        }
        IpAddr::V6(a) => {
            let bits = u128::from(a);
            let m = bits & (u128::MAX << (128 - u32::from(prefix)));
            (m == bits, IpAddr::from(m.to_be_bytes()))
        }
    };
    if !masked {
        return Err(AgentEnrollError::HostBitsSet {
            given: item.to_string(),
            network: format!("{network}/{prefix}"),
        });
    }
    Ok(format!("{addr}/{prefix}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountFacts {
    pub name: String,
    pub uid: u32,
    pub primary_gid: u32,
    pub shell: String,
}

pub struct HostAccounts<'a> {
    pub login_shells: Option<&'a str>,
    pub maknae_gid: u32,
    pub maknae_members: &'a [String],
    pub principal_uid: u32,
    pub daemon_uids: &'a [u32],
    pub daemon_groups: &'a [(u32, Vec<String>)],
    pub other_agents: &'a [(String, u32)],
}

pub fn service_account_check(
    acct: Option<&AccountFacts>,
    account_name: &str,
    agent: &AgentId,
    host: &HostAccounts<'_>,
) -> Result<(), AgentEnrollError> {
    let acct = acct.ok_or_else(|| AgentEnrollError::NoSuchAccount(account_name.to_string()))?;
    if acct.uid == 0 {
        return Err(AgentEnrollError::RootAccount);
    }
    if acct.uid == host.principal_uid {
        return Err(AgentEnrollError::IsPrincipal);
    }
    let daemon = MAKNAE_DAEMON_ACCOUNTS.contains(&acct.name.as_str())
        || host.daemon_uids.contains(&acct.uid)
        || host
            .daemon_groups
            .iter()
            .any(|(gid, members)| *gid == acct.primary_gid || members.contains(&acct.name));
    if daemon {
        return Err(AgentEnrollError::MaknaeDaemonAccount(acct.name.clone()));
    }
    if acct.primary_gid == host.maknae_gid || host.maknae_members.contains(&acct.name) {
        return Err(AgentEnrollError::MaknaeGroupMember);
    }
    let shells = host
        .login_shells
        .ok_or(AgentEnrollError::ShellsUnreadable)?;
    let shell = match acct.shell.trim() {
        "" => "/bin/sh",
        s => s,
    };
    let listed = shells
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .any(|l| l == shell);
    if listed {
        return Err(AgentEnrollError::LoginShell(shell.to_string()));
    }
    if let Some((other, _)) = host
        .other_agents
        .iter()
        .find(|(id, uid)| id != agent.as_str() && *uid == acct.uid)
    {
        return Err(AgentEnrollError::AccountInUse {
            account: acct.name.clone(),
            agent: other.clone(),
        });
    }
    Ok(())
}

pub fn accessor_already_gone(code: u16, errors: &[String]) -> bool {
    errors
        .iter()
        .any(|e| e.contains("failed to find accessor entry"))
        || (code == 404 && errors.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct() -> AccountFacts {
        AccountFacts {
            name: "hobi-svc".into(),
            uid: 990,
            primary_gid: 990,
            shell: "/usr/sbin/nologin".into(),
        }
    }
    const SHELLS: &str = "# /etc/shells\n/bin/sh\n/bin/bash\n  /usr/bin/zsh  \n";
    fn hobi() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }
    static DAEMON_GROUPS: std::sync::OnceLock<Vec<(u32, Vec<String>)>> = std::sync::OnceLock::new();
    fn host<'a>(members: &'a [String], others: &'a [(String, u32)]) -> HostAccounts<'a> {
        HostAccounts {
            login_shells: Some(SHELLS),
            maknae_gid: 980,
            maknae_members: members,
            principal_uid: 1000,
            daemon_uids: &[970, 971],
            daemon_groups: DAEMON_GROUPS
                .get_or_init(|| vec![(970, vec![]), (971, vec!["egress-helper".to_string()])]),
            other_agents: others,
        }
    }
    fn check(a: &AccountFacts, h: &HostAccounts<'_>) -> Result<(), AgentEnrollError> {
        service_account_check(Some(a), &a.name, &hobi(), h)
    }

    #[test]
    fn agent_id_accepts_the_slice_one_charset() {
        for ok in ["hobi", "a", "_x", "a.b-c_d", &"a".repeat(32)] {
            assert_eq!(AgentId::parse(ok).unwrap().as_str(), ok);
        }
    }

    #[test]
    fn agent_id_refuses_what_could_widen_a_path_or_glob() {
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
            assert!(
                matches!(
                    AgentId::parse(bad),
                    Err(AgentEnrollError::InvalidAgentId(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn role_name_is_agent_prefixed() {
        assert_eq!(hobi().role_name(), "agent-hobi");
    }

    #[test]
    fn cidrs_normalise_bare_addresses_and_collapse_duplicates() {
        let got = BindCidrs::parse(&[
            "10.0.0.5".into(),
            "10.0.0.5/32".into(),
            "fd00::1".into(),
            "10.1.0.0/16".into(),
        ])
        .unwrap();
        assert_eq!(
            got.as_slice(),
            ["10.0.0.5/32", "fd00::1/128", "10.1.0.0/16"]
        );
    }

    #[test]
    fn cidrs_refuse_empty_garbage_catch_all_and_host_bits() {
        assert_eq!(BindCidrs::parse(&[]), Err(AgentEnrollError::NoBindCidr));
        for bad in [
            "nope",
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0.0/",
            "10.0.0.0/-1",
            "/8",
        ] {
            assert!(
                matches!(
                    BindCidrs::parse(&[bad.into()]),
                    Err(AgentEnrollError::InvalidCidr(_))
                ),
                "{bad}"
            );
        }
        assert!(matches!(
            BindCidrs::parse(&["0.0.0.0/0".into()]),
            Err(AgentEnrollError::CatchAllCidr(_))
        ));
        assert!(matches!(
            BindCidrs::parse(&["::/0".into()]),
            Err(AgentEnrollError::CatchAllCidr(_))
        ));
        assert_eq!(
            BindCidrs::parse(&["10.0.0.5/24".into()]),
            Err(AgentEnrollError::HostBitsSet {
                given: "10.0.0.5/24".into(),
                network: "10.0.0.0/24".into()
            })
        );
        assert_eq!(
            BindCidrs::parse(&["fd00::1/64".into()]),
            Err(AgentEnrollError::HostBitsSet {
                given: "fd00::1/64".into(),
                network: "fd00::/64".into()
            })
        );
    }

    #[test]
    fn a_service_account_passes() {
        assert_eq!(check(&acct(), &host(&[], &[])), Ok(()));
    }

    #[test]
    fn an_account_already_enrolled_for_this_same_agent_passes() {
        let own = vec![("hobi".to_string(), 990)];
        assert_eq!(check(&acct(), &host(&[], &own)), Ok(()));
    }

    #[test]
    fn each_human_or_shared_signal_is_refused() {
        let h = host(&[], &[]);
        assert_eq!(
            service_account_check(None, "ghost", &hobi(), &h),
            Err(AgentEnrollError::NoSuchAccount("ghost".into()))
        );
        let mut a = acct();
        a.uid = 0;
        assert_eq!(check(&a, &h), Err(AgentEnrollError::RootAccount));
        let mut a = acct();
        a.uid = 1000;
        assert_eq!(check(&a, &h), Err(AgentEnrollError::IsPrincipal));
        let mut a = acct();
        a.uid = 970;
        assert_eq!(
            check(&a, &h),
            Err(AgentEnrollError::MaknaeDaemonAccount("hobi-svc".into()))
        );
        let mut a = acct();
        a.name = "_maknae-egress".into();
        assert_eq!(
            check(&a, &h),
            Err(AgentEnrollError::MaknaeDaemonAccount(
                "_maknae-egress".into()
            ))
        );
        let mut a = acct();
        a.primary_gid = 970;
        assert_eq!(
            check(&a, &h),
            Err(AgentEnrollError::MaknaeDaemonAccount("hobi-svc".into()))
        );
        let mut a = acct();
        a.name = "egress-helper".into();
        assert_eq!(
            check(&a, &h),
            Err(AgentEnrollError::MaknaeDaemonAccount(
                "egress-helper".into()
            ))
        );
        let mut a = acct();
        a.primary_gid = 980;
        assert_eq!(check(&a, &h), Err(AgentEnrollError::MaknaeGroupMember));
        let members = vec!["hobi-svc".to_string()];
        assert_eq!(
            check(&acct(), &host(&members, &[])),
            Err(AgentEnrollError::MaknaeGroupMember)
        );
        for sh in ["/bin/bash", "/usr/bin/zsh", " /bin/bash "] {
            let mut a = acct();
            a.shell = sh.into();
            assert_eq!(
                check(&a, &h),
                Err(AgentEnrollError::LoginShell(sh.trim().into())),
                "{sh:?}"
            );
        }
        let mut a = acct();
        a.shell = "".into();
        assert_eq!(
            check(&a, &h),
            Err(AgentEnrollError::LoginShell("/bin/sh".into()))
        );
        let others = vec![("suga".to_string(), 990)];
        assert_eq!(
            check(&acct(), &host(&[], &others)),
            Err(AgentEnrollError::AccountInUse {
                account: "hobi-svc".into(),
                agent: "suga".into()
            })
        );
        let mut no_shells = host(&[], &[]);
        no_shells.login_shells = None;
        assert_eq!(
            check(&acct(), &no_shells),
            Err(AgentEnrollError::ShellsUnreadable)
        );
    }

    #[test]
    fn only_an_unknown_accessor_counts_as_already_gone() {
        assert!(accessor_already_gone(404, &[]));
        assert!(accessor_already_gone(
            500,
            &["failed to find accessor entry for secret_id_accessor: \"x\"".into()]
        ));
        assert!(!accessor_already_gone(
            404,
            &["no handler for route \"auth/x\"".into()]
        ));
        assert!(!accessor_already_gone(403, &["permission denied".into()]));
        assert!(!accessor_already_gone(500, &["internal error".into()]));
        assert!(!accessor_already_gone(500, &[]));
    }

    #[test]
    fn a_commented_shell_line_is_not_a_login_shell() {
        let mut a = acct();
        a.shell = "/bin/fish".into();
        let mut h = host(&[], &[]);
        h.login_shells = Some("# /bin/fish\n/bin/sh\n");
        assert_eq!(check(&a, &h), Ok(()));
    }

    #[test]
    fn an_empty_shell_passes_only_when_sh_is_not_a_login_shell() {
        let mut a = acct();
        a.shell = "  ".into();
        let mut h = host(&[], &[]);
        h.login_shells = Some("/bin/bash\n");
        assert_eq!(check(&a, &h), Ok(()));
    }

    #[test]
    fn a_shell_that_looks_like_a_comment_is_not_matched_by_a_commented_line() {
        let mut a = acct();
        a.shell = "#odd".into();
        let mut h = host(&[], &[]);
        h.login_shells = Some("#odd\n");
        assert_eq!(check(&a, &h), Ok(()));
    }

    #[test]
    fn every_error_renders_its_values() {
        let cases = [
            (AgentEnrollError::InvalidAgentId("Q".into()), "\"Q\""),
            (AgentEnrollError::NoBindCidr, "--bind-cidr"),
            (AgentEnrollError::InvalidCidr("zz".into()), "\"zz\""),
            (
                AgentEnrollError::CatchAllCidr("0.0.0.0/0".into()),
                "0.0.0.0/0",
            ),
            (
                AgentEnrollError::HostBitsSet {
                    given: "g".into(),
                    network: "n".into(),
                },
                "g has host bits set; use n",
            ),
            (AgentEnrollError::NoSuchAccount("ghost".into()), "ghost"),
            (AgentEnrollError::ShellsUnreadable, "/etc/shells"),
            (AgentEnrollError::RootAccount, "root"),
            (AgentEnrollError::IsPrincipal, "principal"),
            (
                AgentEnrollError::MaknaeDaemonAccount("dm".into()),
                "account dm",
            ),
            (AgentEnrollError::MaknaeGroupMember, "maknae group"),
            (
                AgentEnrollError::LoginShell("/bin/bash".into()),
                "shell /bin/bash is listed",
            ),
            (
                AgentEnrollError::AccountInUse {
                    account: "a".into(),
                    agent: "b".into(),
                },
                "account a is already enrolled for agent b",
            ),
        ];
        for (e, want) in cases {
            assert!(e.to_string().contains(want), "{e:?}: {e}");
        }
    }
}
