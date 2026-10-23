use std::fmt;
use std::net::IpAddr;

pub const DEFAULT_AGENT_APPROLE_MOUNT: &str = "maknae-agent-approle";
pub const AGENT_CREDENTIAL_NAME: &str = "maknae-agent-secret-id";
pub const AGENT_SIGNING_IDENTIFIER: &str = "io.maknae.maknae-agentd";
pub const MAKNAE_DAEMON_ACCOUNTS: [&str; 2] = ["_maknae", "_maknae-egress"];
pub const NON_LOGIN_SHELLS: [&str; 5] = [
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/usr/bin/nologin",
    "/bin/false",
    "/usr/bin/false",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentEnrollError {
    InvalidAgentId(String),
    NoBindCidr,
    InvalidCidr(String),
    CatchAllCidr(String),
    HostBitsSet { given: String, network: String },
    NoSuchAccount(String),
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
        let mut v4: Vec<(u128, u128)> = Vec::new();
        let mut v6: Vec<(u128, u128)> = Vec::new();
        for item in raw {
            let (network, prefix) = canonical_cidr(item)?;
            let (spans, start, width) = match network {
                IpAddr::V4(a) => (&mut v4, u128::from(u32::from(a)), 32),
                IpAddr::V6(a) => (&mut v6, u128::from(a), 128),
            };
            spans.push((start, start + ((1u128 << (width - prefix)) - 1)));
            let canonical = format!("{network}/{prefix}");
            if !out.contains(&canonical) {
                out.push(canonical);
            }
        }
        if covers_all(v4, u128::from(u32::MAX)) || covers_all(v6, u128::MAX) {
            return Err(AgentEnrollError::CatchAllCidr(raw.join(",")));
        }
        Ok(Self(out))
    }

    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

fn covers_all(mut spans: Vec<(u128, u128)>, max: u128) -> bool {
    spans.sort_unstable();
    let mut next = 0u128;
    for (start, end) in spans {
        if start > next {
            return false;
        }
        if end >= next {
            if end == max {
                return true;
            }
            next = end + 1;
        }
    }
    false
}

fn is_prefix_text(p: &str) -> bool {
    !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && (p == "0" || !p.starts_with('0'))
}

fn canonical_cidr(item: &str) -> Result<(IpAddr, u32), AgentEnrollError> {
    let invalid = || AgentEnrollError::InvalidCidr(item.to_string());
    let (addr_text, prefix_text) = match item.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (item, None),
    };
    let addr: IpAddr = addr_text.parse().map_err(|_| invalid())?;
    let max: u32 = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_text {
        Some(p) if is_prefix_text(p) => p.parse::<u32>().map_err(|_| invalid())?,
        Some(_) => return Err(invalid()),
        None => max,
    };
    if prefix > max {
        return Err(invalid());
    }
    let (addr, prefix) = match addr {
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) if prefix >= 96 => (IpAddr::V4(v4), prefix - 96),
            _ => (addr, prefix),
        },
        IpAddr::V4(_) => (addr, prefix),
    };
    if prefix == 0 {
        return Err(AgentEnrollError::CatchAllCidr(item.to_string()));
    }
    let (masked, network) = match addr {
        IpAddr::V4(a) => {
            let bits = u32::from(a);
            let m = bits & (u32::MAX << (32 - prefix));
            (m == bits, IpAddr::from(m.to_be_bytes()))
        }
        IpAddr::V6(a) => {
            let bits = u128::from(a);
            let m = bits & (u128::MAX << (128 - prefix));
            (m == bits, IpAddr::from(m.to_be_bytes()))
        }
    };
    if !masked {
        return Err(AgentEnrollError::HostBitsSet {
            given: item.to_string(),
            network: format!("{network}/{prefix}"),
        });
    }
    Ok((addr, prefix))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountFacts {
    pub name: String,
    pub uid: u32,
    pub primary_gid: u32,
    pub shell: String,
}

pub struct HostAccounts<'a> {
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
    let shell = acct.shell.trim();
    if !NON_LOGIN_SHELLS.contains(&shell) {
        let shown = if shell.is_empty() { "(empty)" } else { shell };
        return Err(AgentEnrollError::LoginShell(shown.to_string()));
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

pub fn list_is_empty(code: u16, errors: &[String]) -> bool {
    code == 404 && errors.is_empty()
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
    fn hobi() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }
    static DAEMON_GROUPS: std::sync::OnceLock<Vec<(u32, Vec<String>)>> = std::sync::OnceLock::new();
    fn host<'a>(members: &'a [String], others: &'a [(String, u32)]) -> HostAccounts<'a> {
        HostAccounts {
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
            "10.0.0.5/+32",
            "10.0.0.0/08",
            "10.0.0.5/032",
            "10.0.0.0/00",
            "10.0.0.5/ 32",
            "10.0.0.5/32 ",
            "fd00::/+64",
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
    fn a_cidr_set_that_together_covers_a_family_is_refused() {
        for set in [
            &["0.0.0.0/1", "128.0.0.0/1"][..],
            &["::/1", "8000::/1"][..],
            &["10.0.0.0/8", "128.0.0.0/1", "0.0.0.0/1"][..],
            &["0.0.0.0/1", "10.0.0.0/8", "128.0.0.0/1"][..],
            &["fd00::/8", "::/1", "8000::/1"][..],
        ] {
            let raw: Vec<String> = set.iter().map(|s| s.to_string()).collect();
            assert_eq!(
                BindCidrs::parse(&raw),
                Err(AgentEnrollError::CatchAllCidr(set.join(","))),
                "{set:?}"
            );
        }
    }

    #[test]
    fn a_chain_of_adjacent_cidrs_down_to_one_address_covers_ipv4() {
        let mut raw = vec!["0.0.0.0/32".to_string()];
        for p in (1..=32u32).rev() {
            let start = if p == 32 { 1u32 } else { 1u32 << (32 - p) };
            raw.push(format!("{}/{p}", std::net::Ipv4Addr::from(start)));
        }
        assert!(
            matches!(
                BindCidrs::parse(&raw),
                Err(AgentEnrollError::CatchAllCidr(_))
            ),
            "{raw:?}"
        );
        raw.remove(0);
        assert!(BindCidrs::parse(&raw).is_ok(), "{raw:?}");
    }

    #[test]
    fn a_cidr_set_with_a_gap_is_accepted() {
        for set in [
            &["0.0.0.0/1", "128.0.0.0/2"][..],
            &["10.0.0.0/8", "fd00::/8"][..],
            &["128.0.0.0/1", "0.0.0.0/2", "64.0.0.0/3"][..],
            &["0.0.0.0/1", "128.0.0.1/32"][..],
            &["0.0.0.0/2", "128.0.0.0/1"][..],
            &["0.0.0.0/1", "8000::/1"][..],
        ] {
            let raw: Vec<String> = set.iter().map(|s| s.to_string()).collect();
            assert!(BindCidrs::parse(&raw).is_ok(), "{set:?}");
        }
    }

    #[test]
    fn an_ipv4_mapped_cidr_is_judged_as_ipv4() {
        assert_eq!(
            BindCidrs::parse(&["::ffff:10.0.0.5".into(), "::ffff:10.1.0.0/112".into()])
                .unwrap()
                .as_slice(),
            ["10.0.0.5/32", "10.1.0.0/16"]
        );
        assert!(matches!(
            BindCidrs::parse(&["::ffff:0.0.0.0/96".into()]),
            Err(AgentEnrollError::CatchAllCidr(_))
        ));
        assert_eq!(
            BindCidrs::parse(&["::ffff:10.0.0.0/95".into()]),
            Err(AgentEnrollError::HostBitsSet {
                given: "::ffff:10.0.0.0/95".into(),
                network: "::fffe:0:0/95".into()
            })
        );
        assert_eq!(
            BindCidrs::parse(&["::ffff:0.0.0.0/97".into(), "128.0.0.0/1".into()]),
            Err(AgentEnrollError::CatchAllCidr(
                "::ffff:0.0.0.0/97,128.0.0.0/1".into()
            ))
        );
    }

    #[test]
    fn only_an_empty_404_is_an_empty_list() {
        assert!(list_is_empty(404, &[]));
        assert!(!list_is_empty(
            404,
            &["no handler for route \"auth/x\"".into()]
        ));
        assert!(!list_is_empty(403, &[]));
        assert!(!list_is_empty(500, &[]));
        assert!(!list_is_empty(200, &[]));
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
        let others = vec![("suga".to_string(), 990)];
        assert_eq!(
            check(&acct(), &host(&[], &others)),
            Err(AgentEnrollError::AccountInUse {
                account: "hobi-svc".into(),
                agent: "suga".into()
            })
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
    fn only_an_allowlisted_non_login_shell_passes() {
        let h = host(&[], &[]);
        for sh in NON_LOGIN_SHELLS {
            for spelled in [sh.to_string(), format!(" {sh} ")] {
                let mut a = acct();
                a.shell = spelled.clone();
                assert_eq!(check(&a, &h), Ok(()), "{spelled:?}");
            }
        }
        for sh in [
            "/bin/bash",
            "/usr/bin/zsh",
            "/bin/fish",
            "/bin/sh",
            "/usr/sbin/nologin2",
            "/usr/sbin/nologin/x",
        ] {
            let mut a = acct();
            a.shell = format!(" {sh} ");
            assert_eq!(
                check(&a, &h),
                Err(AgentEnrollError::LoginShell(sh.into())),
                "{sh:?}"
            );
        }
        for empty in ["", "  "] {
            let mut a = acct();
            a.shell = empty.into();
            assert_eq!(
                check(&a, &h),
                Err(AgentEnrollError::LoginShell("(empty)".into())),
                "{empty:?}"
            );
        }
    }

    #[test]
    fn the_shell_is_checked_before_the_account_in_use_test() {
        let mut a = acct();
        a.shell = "/bin/bash".into();
        let others = vec![("suga".to_string(), 990)];
        assert_eq!(
            check(&a, &host(&[], &others)),
            Err(AgentEnrollError::LoginShell("/bin/bash".into()))
        );
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
            (AgentEnrollError::RootAccount, "root"),
            (AgentEnrollError::IsPrincipal, "principal"),
            (
                AgentEnrollError::MaknaeDaemonAccount("dm".into()),
                "account dm",
            ),
            (AgentEnrollError::MaknaeGroupMember, "maknae group"),
            (
                AgentEnrollError::LoginShell("/bin/bash".into()),
                "shell /bin/bash is not a non-login shell",
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
