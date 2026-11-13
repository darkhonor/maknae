use super::EnrollError;
use maknae_io::program::{command, Program};
use maknae_vault::agent_enroll::AgentId;
use std::path::{Path, PathBuf};

const TLS_DIR: &str = "tls";
const TLS_FILES: [&str; 3] = ["maknae-root-ca.crt", "maknae-int-ca.crt", "vault-ca.crt"];
const OWN_FILES: [&str; 3] = [
    maknae_config::AGENT_CLIENT_FILE,
    maknae_config::ENROLLMENT_FILE,
    maknae_config::PERSONA_FILE,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Platform {
    Linux,
    Macos,
}

impl Platform {
    pub(crate) const HOST: Platform = if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Linux
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Account {
    pub name: String,
    pub uid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub path: PathBuf,
    pub dir: bool,
}

fn dir(path: impl Into<PathBuf>) -> Entry {
    Entry {
        path: path.into(),
        dir: true,
    }
}

fn file(path: impl Into<PathBuf>) -> Entry {
    Entry {
        path: path.into(),
        dir: false,
    }
}

/// Every entry the Agent Daemon's account reads through, below the configuration root:
/// the directories its anchored reader opens, its own files, and the certificates
/// `AgentLogin` loads.
pub(crate) fn grant_entries(root: &Path, agent: &AgentId, persona: bool) -> Vec<Entry> {
    let agents = root.join(maknae_config::AGENTS_DIR);
    let own = agents.join(agent.as_str());
    let tls = root.join(TLS_DIR);
    let mut out = vec![dir(root), dir(&agents), dir(&own), dir(&tls)];
    out.extend(
        OWN_FILES
            .iter()
            .filter(|f| persona || **f != maknae_config::PERSONA_FILE)
            .map(|f| file(own.join(f))),
    );
    out.extend(TLS_FILES.iter().map(|f| file(tls.join(f))));
    out
}

/// [`grant_entries`] less the agent's own files that are not `present`.
pub(crate) fn revoke_entries(root: &Path, agent: &AgentId, present: &[&str]) -> Vec<Entry> {
    let own = root.join(maknae_config::AGENTS_DIR).join(agent.as_str());
    grant_entries(root, agent, true)
        .into_iter()
        .filter(|e| {
            e.path.parent() != Some(own.as_path())
                || e.dir
                || e.path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| present.contains(&n))
        })
        .collect()
}

pub(crate) fn own_files() -> [&'static str; 3] {
    OWN_FILES
}

/// An account name that is safe to write into an ACE or a printed command.
pub(crate) fn account_name_ok(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ran {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

type Call = (Program, Vec<String>);

pub(crate) trait Run {
    fn run(&self, program: Program, args: &[String]) -> Result<Ran, String>;
}

pub(crate) struct Host;

impl Run for Host {
    fn run(&self, program: Program, args: &[String]) -> Result<Ran, String> {
        command(program)
            .args(args)
            .output()
            .map(|o| Ran {
                ok: o.status.success(),
                stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&o.stderr).trim().to_string(),
            })
            .map_err(|e| e.to_string())
    }
}

fn path_arg(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn perms(e: &Entry) -> &'static str {
    if e.dir {
        "r-x"
    } else {
        "r--"
    }
}

fn macos_ace(account: &Account, e: &Entry) -> String {
    format!(
        "user:{} allow {}",
        account.name,
        if e.dir { "list,search" } else { "read" }
    )
}

fn entry_text(platform: Platform, account: &Account, e: &Entry) -> String {
    match platform {
        Platform::Linux => format!("u:{}:{}", account.uid, perms(e)),
        Platform::Macos => macos_ace(account, e),
    }
}

fn grant_call(platform: Platform, account: &Account, e: &Entry) -> Call {
    match platform {
        Platform::Linux => (
            Program::Setfacl,
            vec![
                "-P".into(),
                "-n".into(),
                "-m".into(),
                entry_text(platform, account, e),
                path_arg(&e.path),
            ],
        ),
        Platform::Macos => (
            Program::Chmod,
            vec![
                "-h".into(),
                "+a".into(),
                macos_ace(account, e),
                path_arg(&e.path),
            ],
        ),
    }
}

fn remove_call(platform: Platform, account: &Account, e: &Entry) -> Call {
    match platform {
        Platform::Linux => (
            Program::Setfacl,
            vec![
                "-P".into(),
                "-n".into(),
                "-x".into(),
                format!("u:{}", account.uid),
                path_arg(&e.path),
            ],
        ),
        Platform::Macos => (
            Program::Chmod,
            vec![
                "-h".into(),
                "-a".into(),
                macos_ace(account, e),
                path_arg(&e.path),
            ],
        ),
    }
}

fn readback(platform: Platform, e: &Entry) -> Call {
    match platform {
        Platform::Linux => (
            Program::Getfacl,
            vec!["-P".into(), "-p".into(), "-n".into(), path_arg(&e.path)],
        ),
        Platform::Macos => (Program::Ls, vec!["-led".into(), path_arg(&e.path)]),
    }
}

/// `getfacl -n` renders `u:UID:r-x` as the whole line `user:UID:r-x`; an entry the mask
/// limits carries an `#effective:` suffix and does not match.
fn linux_granted(uid: u32, e: &Entry, out: &str) -> bool {
    let want = format!("user:{uid}:{}", perms(e));
    out.lines().any(|l| l.trim() == want)
}

fn macos_listed(ace: &str, out: &str) -> bool {
    out.lines().any(|l| {
        l.trim().split_once(": ").is_some_and(|(i, a)| {
            !i.is_empty() && i.chars().all(|c| c.is_ascii_digit()) && a == ace
        })
    })
}

fn granted(platform: Platform, account: &Account, e: &Entry, out: &str) -> bool {
    match platform {
        Platform::Linux => linux_granted(account.uid, e, out),
        Platform::Macos => macos_listed(&macos_ace(account, e), out),
    }
}

fn held(platform: Platform, account: &Account, e: &Entry, out: &str) -> bool {
    match platform {
        Platform::Linux => {
            let who = format!("user:{}:", account.uid);
            out.lines().any(|l| l.starts_with(&who))
        }
        Platform::Macos => macos_listed(&macos_ace(account, e), out),
    }
}

fn refusal(agent: &AgentId, grant: bool, e: &Entry, entry: String, detail: String) -> EnrollError {
    EnrollError::AgentAccess {
        agent: agent.as_str().to_string(),
        grant,
        path: e.path.clone(),
        entry,
        detail,
    }
}

fn ran(r: &dyn Run, (program, args): Call) -> Result<Ran, String> {
    r.run(program, &args)
}

fn check_name(platform: Platform, account: &Account) -> Result<(), EnrollError> {
    if platform == Platform::Macos && !account_name_ok(&account.name) {
        return Err(EnrollError::Owner(format!(
            "account {:?} is not 1 or more of [A-Za-z0-9._-] starting with a letter, digit, '.' or '_'; it cannot be named in an ACE",
            account.name
        )));
    }
    Ok(())
}

pub(crate) fn grant(
    r: &dyn Run,
    platform: Platform,
    agent: &AgentId,
    account: &Account,
    entries: &[Entry],
) -> Result<(), EnrollError> {
    check_name(platform, account)?;
    for e in entries {
        let entry = entry_text(platform, account, e);
        match ran(r, grant_call(platform, account, e)) {
            Ok(out) if out.ok => {}
            Ok(out) => return Err(refusal(agent, true, e, entry, out.stderr)),
            Err(why) => return Err(refusal(agent, true, e, entry, why)),
        }
        match ran(r, readback(platform, e)) {
            Ok(out) if out.ok && granted(platform, account, e, &out.stdout) => {}
            Ok(_) => {
                return Err(refusal(
                    agent,
                    true,
                    e,
                    entry,
                    "the entry did not read back".into(),
                ))
            }
            Err(why) => return Err(refusal(agent, true, e, entry, why)),
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Revoked {
    Done,
    Unresolved,
}

pub(crate) fn revoke(
    r: &dyn Run,
    platform: Platform,
    agent: &AgentId,
    account: &Account,
    resolves: bool,
    entries: &[Entry],
) -> Result<Revoked, EnrollError> {
    if platform == Platform::Macos && !resolves {
        return Ok(Revoked::Unresolved);
    }
    check_name(platform, account)?;
    for e in entries {
        let entry = match platform {
            Platform::Linux => format!("u:{}", account.uid),
            Platform::Macos => macos_ace(account, e),
        };
        let still_held = || match ran(r, readback(platform, e)) {
            Ok(out) if out.ok => Ok(held(platform, account, e, &out.stdout)),
            Ok(out) => Err(refusal(agent, false, e, entry.clone(), out.stderr)),
            Err(why) => Err(refusal(agent, false, e, entry.clone(), why)),
        };
        if !still_held()? {
            continue;
        }
        match ran(r, remove_call(platform, account, e)) {
            Ok(out) if out.ok => {}
            Ok(out) => return Err(refusal(agent, false, e, entry.clone(), out.stderr)),
            Err(why) => return Err(refusal(agent, false, e, entry.clone(), why)),
        }
        if still_held()? {
            return Err(refusal(
                agent,
                false,
                e,
                entry.clone(),
                "the entry is still listed".into(),
            ));
        }
    }
    Ok(Revoked::Done)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};

    fn hobi() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    const ROOT: &str = "/etc/maknae";

    fn acct() -> Account {
        Account {
            name: "hobi-svc".into(),
            uid: 990,
        }
    }

    #[derive(Default, Clone)]
    struct Acl {
        users: BTreeMap<String, String>,
        mask: Option<String>,
        aces: BTreeSet<String>,
    }

    const GROUP: &str = "r-x";

    fn union(a: &str, b: &str) -> String {
        a.chars()
            .zip(b.chars())
            .map(|(x, y)| if x != '-' { x } else { y })
            .collect()
    }

    fn and(a: &str, b: &str) -> String {
        a.chars()
            .zip(b.chars())
            .map(|(x, y)| if x != '-' && y != '-' { x } else { '-' })
            .collect()
    }

    /// A host whose ACL state the calls change, mask included, so a read-back sees what
    /// was written.
    #[derive(Default)]
    pub(crate) struct FakeHost {
        calls: RefCell<Vec<String>>,
        acl: RefCell<BTreeMap<String, Acl>>,
        refuse: RefCell<BTreeSet<String>>,
        deaf: RefCell<BTreeSet<String>>,
    }

    impl FakeHost {
        pub(crate) fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        pub(crate) fn refusing(self, call: &str) -> Self {
            self.refuse.borrow_mut().insert(call.into());
            self
        }

        fn ignoring_writes_to(self, path: &str) -> Self {
            self.deaf.borrow_mut().insert(path.into());
            self
        }

        fn user(self, path: &str, uid: &str, perms: &str) -> Self {
            self.acl
                .borrow_mut()
                .entry(path.into())
                .or_default()
                .users
                .insert(uid.into(), perms.into());
            self
        }

        fn mask(self, path: &str, mask: &str) -> Self {
            self.acl.borrow_mut().entry(path.into()).or_default().mask = Some(mask.into());
            self
        }

        fn ace(self, path: &str, ace: &str) -> Self {
            self.acl
                .borrow_mut()
                .entry(path.into())
                .or_default()
                .aces
                .insert(ace.into());
            self
        }

        fn state(&self, path: &str) -> Acl {
            self.acl.borrow().get(path).cloned().unwrap_or_default()
        }
    }

    fn recalc(acl: &mut Acl) {
        acl.mask = Some(
            acl.users
                .values()
                .fold(GROUP.to_string(), |m, p| union(&m, p)),
        );
    }

    impl Run for FakeHost {
        fn run(&self, program: Program, args: &[String]) -> Result<Ran, String> {
            let call = format!("{} {}", program.path().display(), args.join(" | "));
            self.calls.borrow_mut().push(call.clone());
            if self.refuse.borrow().contains(&call) {
                return Ok(Ran {
                    ok: false,
                    stdout: String::new(),
                    stderr: "Operation not supported".into(),
                });
            }
            let path = args.last().unwrap().clone();
            let deaf = self.deaf.borrow().contains(&path);
            let keep_mask = args.iter().any(|a| a == "-n");
            let mut all = self.acl.borrow_mut();
            let acl = all.entry(path.clone()).or_default();
            let ok = |stdout: String| {
                Ok(Ran {
                    ok: true,
                    stdout,
                    stderr: String::new(),
                })
            };
            let op = args
                .iter()
                .find(|a| ["-m", "-x", "+a", "-a"].contains(&a.as_str()));
            match (program, op.map(String::as_str)) {
                (Program::Setfacl, Some("-m")) if !deaf => {
                    let spec = &args[args.len() - 2];
                    let (who, p) = spec.rsplit_once(':').unwrap();
                    acl.users
                        .insert(who.strip_prefix("u:").unwrap().into(), p.into());
                    if !keep_mask || acl.mask.is_none() {
                        recalc(acl);
                    }
                    ok(String::new())
                }
                (Program::Setfacl, Some("-x")) => {
                    let spec = &args[args.len() - 2];
                    acl.users.remove(spec.strip_prefix("u:").unwrap());
                    if !keep_mask {
                        recalc(acl);
                    }
                    ok(String::new())
                }
                (Program::Getfacl, _) => {
                    let mut out = format!("# file: {path}\n# owner: 0\nuser::rwx\n");
                    for (u, p) in &acl.users {
                        match &acl.mask {
                            Some(m) if and(p, m) != *p => {
                                out.push_str(&format!("user:{u}:{p}\t#effective:{}\n", and(p, m)))
                            }
                            _ => out.push_str(&format!("user:{u}:{p}\n")),
                        }
                    }
                    out.push_str(&format!("group::{GROUP}\n"));
                    if let Some(m) = &acl.mask {
                        out.push_str(&format!("mask::{m}\n"));
                    }
                    out.push_str("other::---\n");
                    ok(out)
                }
                (Program::Chmod, Some("+a")) if !deaf => {
                    acl.aces.insert(args[args.len() - 2].clone());
                    ok(String::new())
                }
                (Program::Chmod, Some("-a")) => {
                    acl.aces.remove(&args[args.len() - 2]);
                    ok(String::new())
                }
                (Program::Ls, _) => ok(format!(
                    "drwxr-x---+ 3 root  wheel  96 Nov 13 10:00 {path}\n{}",
                    acl.aces
                        .iter()
                        .enumerate()
                        .map(|(i, l)| format!(" {i}: {l}\n"))
                        .collect::<String>()
                )),
                _ => ok(String::new()),
            }
        }
    }

    impl Run for std::rc::Rc<FakeHost> {
        fn run(&self, program: Program, args: &[String]) -> Result<Ran, String> {
            (**self).run(program, args)
        }
    }

    fn paths(entries: &[Entry]) -> Vec<(String, bool)> {
        entries
            .iter()
            .map(|e| (e.path.display().to_string(), e.dir))
            .collect()
    }

    #[test]
    fn the_grant_covers_exactly_what_the_daemon_reads_below_the_root() {
        assert_eq!(
            paths(&grant_entries(Path::new(ROOT), &hobi(), true)),
            [
                ("/etc/maknae", true),
                ("/etc/maknae/agents", true),
                ("/etc/maknae/agents/hobi", true),
                ("/etc/maknae/tls", true),
                ("/etc/maknae/agents/hobi/agent.yaml", false),
                ("/etc/maknae/agents/hobi/enrollment.yaml", false),
                ("/etc/maknae/agents/hobi/persona.md", false),
                ("/etc/maknae/tls/maknae-root-ca.crt", false),
                ("/etc/maknae/tls/maknae-int-ca.crt", false),
                ("/etc/maknae/tls/vault-ca.crt", false),
            ]
            .map(|(p, d)| (p.to_string(), d))
        );
        let without = paths(&grant_entries(Path::new(ROOT), &hobi(), false));
        assert_eq!(without.len(), 9);
        assert!(!without.iter().any(|(p, _)| p.ends_with("persona.md")));
        let elsewhere = grant_entries(Path::new("/srv/cfg"), &hobi(), true);
        assert!(elsewhere.iter().all(|e| e.path.starts_with("/srv/cfg")));
    }

    #[test]
    fn no_entry_is_ever_on_private_or_another_agent() {
        for e in grant_entries(Path::new(ROOT), &hobi(), true)
            .iter()
            .chain(&revoke_entries(Path::new(ROOT), &hobi(), &own_files()))
        {
            let p = e.path.display().to_string();
            assert!(!p.contains("private"), "{p}");
            assert!(
                !p.starts_with("/etc/maknae/agents/") || p.starts_with("/etc/maknae/agents/hobi"),
                "{p}"
            );
        }
    }

    #[test]
    fn revoke_entries_are_the_grant_entries_less_absent_own_files() {
        let root = Path::new(ROOT);
        assert_eq!(
            revoke_entries(root, &hobi(), &own_files()),
            grant_entries(root, &hobi(), true)
        );
        let some = paths(&revoke_entries(
            root,
            &hobi(),
            &[maknae_config::ENROLLMENT_FILE],
        ));
        let all = paths(&grant_entries(root, &hobi(), true));
        let dropped: Vec<_> = all.iter().filter(|e| !some.contains(e)).collect();
        assert_eq!(
            dropped,
            [
                &("/etc/maknae/agents/hobi/agent.yaml".to_string(), false),
                &("/etc/maknae/agents/hobi/persona.md".to_string(), false),
            ]
        );
        let none = paths(&revoke_entries(root, &hobi(), &[]));
        assert_eq!(none.len(), 7);
        assert!(none.contains(&("/etc/maknae/agents/hobi".to_string(), true)));
    }

    #[test]
    fn linux_grants_each_entry_by_uid_without_following_links_or_widening_the_mask() {
        let host = FakeHost::default();
        let entries = grant_entries(Path::new(ROOT), &hobi(), true);
        grant(&host, Platform::Linux, &hobi(), &acct(), &entries).unwrap();
        let mut want = Vec::new();
        for e in &entries {
            let p = e.path.display();
            want.push(format!(
                "/usr/bin/setfacl -P | -n | -m | u:990:{} | {p}",
                perms(e)
            ));
            want.push(format!("/usr/bin/getfacl -P | -p | -n | {p}"));
        }
        assert_eq!(host.calls(), want);
    }

    #[test]
    fn a_linux_grant_never_widens_an_entry_the_mask_held_back() {
        let host = FakeHost::default()
            .user(ROOT, "1234", "rwx")
            .mask(ROOT, "r-x");
        grant(&host, Platform::Linux, &hobi(), &acct(), &[dir(ROOT)]).unwrap();
        let after = host.state(ROOT);
        assert_eq!(after.mask.as_deref(), Some("r-x"));
        assert_eq!(after.users.get("990").map(String::as_str), Some("r-x"));
    }

    #[test]
    fn a_linux_grant_the_mask_limits_does_not_read_back() {
        let host = FakeHost::default().mask(ROOT, "r--");
        let e = grant(&host, Platform::Linux, &hobi(), &acct(), &[dir(ROOT)]).unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentAccess { grant: true, detail, .. } if detail == "the entry did not read back"),
            "{e:?}"
        );
    }

    #[test]
    fn macos_grants_each_entry_on_the_path_itself_and_reads_it_back() {
        let host = FakeHost::default();
        let entries = grant_entries(Path::new(ROOT), &hobi(), true);
        grant(&host, Platform::Macos, &hobi(), &acct(), &entries).unwrap();
        let mut want = Vec::new();
        for e in &entries {
            let perms = if e.dir { "list,search" } else { "read" };
            let p = e.path.display();
            want.push(format!(
                "/bin/chmod -h | +a | user:hobi-svc allow {perms} | {p}"
            ));
            want.push(format!("/bin/ls -led | {p}"));
        }
        assert_eq!(host.calls(), want);
    }

    #[test]
    fn a_macos_account_name_an_ace_cannot_carry_is_refused_before_any_call() {
        for name in [
            "", "-hobi", "hobi svc", "hobi:x", "hobi,y", "h\u{e9}", "a\nb",
        ] {
            let host = FakeHost::default();
            let a = Account {
                name: name.into(),
                uid: 990,
            };
            let entries = [dir(ROOT)];
            for got in [
                grant(&host, Platform::Macos, &hobi(), &a, &entries).err(),
                revoke(&host, Platform::Macos, &hobi(), &a, true, &entries).err(),
            ] {
                assert!(
                    matches!(got, Some(EnrollError::Owner(_))),
                    "{name:?}: {got:?}"
                );
            }
            assert!(host.calls().is_empty(), "{name:?}");
            assert!(
                grant(&host, Platform::Linux, &hobi(), &a, &entries).is_ok(),
                "{name:?}"
            );
        }
        for ok in ["hobi", "hobi-svc", "_hobi", "hobi.svc", "Hobi9"] {
            assert!(account_name_ok(ok), "{ok}");
        }
    }

    #[test]
    fn an_entry_that_does_not_read_back_refuses_and_stops() {
        for platform in [Platform::Linux, Platform::Macos] {
            let host = FakeHost::default().ignoring_writes_to("/etc/maknae/agents/hobi");
            let e = grant(
                &host,
                platform,
                &hobi(),
                &acct(),
                &grant_entries(Path::new(ROOT), &hobi(), true),
            )
            .unwrap_err();
            assert!(
                matches!(&e, EnrollError::AgentAccess { grant: true, path, detail, .. }
                    if path == Path::new("/etc/maknae/agents/hobi") && detail == "the entry did not read back"),
                "{platform:?}: {e:?}"
            );
            assert_eq!(
                host.calls().len(),
                6,
                "{platform:?}: stops at the third entry"
            );
        }
    }

    #[test]
    fn a_mask_limited_linux_entry_does_not_read_back() {
        let d = dir(ROOT);
        assert!(linux_granted(990, &d, "user:990:r-x\n"));
        assert!(linux_granted(990, &d, "  user:990:r-x  \n"));
        for out in [
            "user:990:r-x\t#effective:r--\n",
            "default:user:990:r-x\n",
            "user:990:r--\n",
            "user:9900:r-x\n",
            "",
        ] {
            assert!(!linux_granted(990, &d, out), "{out:?}");
        }
        assert!(linux_granted(990, &file("/x"), "user:990:r--\n"));
        assert!(!linux_granted(990, &file("/x"), "user:990:r-x\n"));
    }

    #[test]
    fn a_macos_ace_reads_back_only_as_its_own_numbered_line() {
        let ace = "user:hobi-svc allow list,search";
        assert!(macos_listed(ace, " 0: user:hobi-svc allow list,search\n"));
        assert!(macos_listed(
            ace,
            "drwx  x\n 12: user:hobi-svc allow list,search\n"
        ));
        for out in [
            " 0: user:hobi-svc allow list,search,add_file\n",
            " 0: user:hobi-svc deny list,search\n",
            " x: user:hobi-svc allow list,search\n",
            ": user:hobi-svc allow list,search\n",
            "user:hobi-svc allow list,search\n",
            "",
        ] {
            assert!(!macos_listed(ace, out), "{out:?}");
        }
    }

    #[test]
    fn a_refused_grant_names_the_entry_and_the_tools_reason() {
        let host = FakeHost::default()
            .refusing("/usr/bin/setfacl -P | -n | -m | u:990:r-x | /etc/maknae/tls");
        let e = grant(
            &host,
            Platform::Linux,
            &hobi(),
            &acct(),
            &grant_entries(Path::new(ROOT), &hobi(), false),
        )
        .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentAccess { grant: true, path, entry, detail, .. }
                if path == Path::new("/etc/maknae/tls") && entry == "u:990:r-x" && detail == "Operation not supported"),
            "{e:?}"
        );
        let text = e.to_string();
        assert!(
            text.contains("/etc/maknae/tls")
                && text.contains("run `sudo maknae enroll agent hobi --refresh-access`"),
            "{text}"
        );
    }

    struct Absent;

    impl Run for Absent {
        fn run(&self, program: Program, _: &[String]) -> Result<Ran, String> {
            Err(format!("{} not found", program.path().display()))
        }
    }

    #[test]
    fn a_missing_tool_refuses_the_grant_and_the_revoke() {
        let entries = grant_entries(Path::new(ROOT), &hobi(), false);
        for platform in [Platform::Linux, Platform::Macos] {
            let e = grant(&Absent, platform, &hobi(), &acct(), &entries).unwrap_err();
            assert!(
                matches!(&e, EnrollError::AgentAccess { grant: true, detail, .. } if detail.ends_with("not found")),
                "{e:?}"
            );
            let e = revoke(&Absent, platform, &hobi(), &acct(), true, &entries).unwrap_err();
            assert!(
                matches!(&e, EnrollError::AgentAccess { grant: false, detail, .. } if detail.ends_with("not found")),
                "{e:?}"
            );
        }
    }

    #[test]
    fn linux_revokes_each_held_entry_by_uid_and_keeps_the_mask() {
        let entries = revoke_entries(Path::new(ROOT), &hobi(), &own_files());
        let mut host = FakeHost::default();
        for e in &entries {
            host = host.user(&e.path.display().to_string(), "990", perms(e));
        }
        host = host.user(ROOT, "991", "rwx").mask(ROOT, "r-x");
        assert_eq!(
            revoke(&host, Platform::Linux, &hobi(), &acct(), true, &entries).ok(),
            Some(Revoked::Done)
        );
        let mut want = Vec::new();
        for e in &entries {
            let p = e.path.display();
            want.push(format!("/usr/bin/getfacl -P | -p | -n | {p}"));
            want.push(format!("/usr/bin/setfacl -P | -n | -x | u:990 | {p}"));
            want.push(format!("/usr/bin/getfacl -P | -p | -n | {p}"));
        }
        assert_eq!(host.calls(), want);
        let root = host.state(ROOT);
        assert_eq!(
            root.users,
            BTreeMap::from([("991".to_string(), "rwx".to_string())])
        );
        assert_eq!(root.mask.as_deref(), Some("r-x"));
    }

    #[test]
    fn macos_revokes_each_held_entry_on_the_path_itself() {
        let entries = revoke_entries(Path::new(ROOT), &hobi(), &[]);
        let mut host = FakeHost::default();
        for e in &entries {
            host = host.ace(&e.path.display().to_string(), &macos_ace(&acct(), e));
        }
        assert_eq!(
            revoke(&host, Platform::Macos, &hobi(), &acct(), true, &entries).ok(),
            Some(Revoked::Done)
        );
        let mut want = Vec::new();
        for e in &entries {
            let p = e.path.display();
            let ace = macos_ace(&acct(), e);
            want.push(format!("/bin/ls -led | {p}"));
            want.push(format!("/bin/chmod -h | -a | {ace} | {p}"));
            want.push(format!("/bin/ls -led | {p}"));
        }
        assert_eq!(host.calls(), want);
        assert!(host.acl.borrow().values().all(|a| a.aces.is_empty()));
    }

    #[test]
    fn an_unresolved_macos_account_is_skipped_and_linux_is_not() {
        let entries = [dir(ROOT)];
        let host = FakeHost::default().ace(ROOT, &macos_ace(&acct(), &dir(ROOT)));
        assert_eq!(
            revoke(&host, Platform::Macos, &hobi(), &acct(), false, &entries).ok(),
            Some(Revoked::Unresolved)
        );
        assert!(host.calls().is_empty());
        let host = FakeHost::default().user(ROOT, "990", "r-x");
        assert_eq!(
            revoke(&host, Platform::Linux, &hobi(), &acct(), false, &entries).ok(),
            Some(Revoked::Done)
        );
        assert!(host.state(ROOT).users.is_empty());
    }

    #[test]
    fn revoke_skips_an_entry_that_is_not_held() {
        let entries = vec![dir(ROOT)];
        for platform in [Platform::Linux, Platform::Macos] {
            let host = FakeHost::default().user(ROOT, "9900", "r-x");
            revoke(&host, platform, &hobi(), &acct(), true, &entries).unwrap();
            assert_eq!(host.calls().len(), 1, "{platform:?}: {:?}", host.calls());
        }
    }

    #[test]
    fn an_entry_still_listed_after_revoke_refuses() {
        struct Stuck;
        impl Run for Stuck {
            fn run(&self, program: Program, _: &[String]) -> Result<Ran, String> {
                let stdout = match program {
                    Program::Getfacl => "user:990:r-x\n".into(),
                    Program::Ls => " 0: user:hobi-svc allow list,search\n".into(),
                    _ => String::new(),
                };
                Ok(Ran {
                    ok: true,
                    stdout,
                    stderr: String::new(),
                })
            }
        }
        for platform in [Platform::Linux, Platform::Macos] {
            let e = revoke(&Stuck, platform, &hobi(), &acct(), true, &[dir(ROOT)]).unwrap_err();
            assert!(
                matches!(&e, EnrollError::AgentAccess { grant: false, detail, .. } if detail == "the entry is still listed"),
                "{platform:?}: {e:?}"
            );
            assert!(e.to_string().contains("remove-agent"), "{e}");
        }
    }

    #[test]
    fn a_refused_revoke_or_read_names_the_reason() {
        let held = || FakeHost::default().user(ROOT, "990", "r-x");
        let e = revoke(
            &held().refusing("/usr/bin/setfacl -P | -n | -x | u:990 | /etc/maknae"),
            Platform::Linux,
            &hobi(),
            &acct(),
            true,
            &[dir(ROOT)],
        )
        .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentAccess { grant: false, entry, detail, .. }
                if entry == "u:990" && detail == "Operation not supported"),
            "{e:?}"
        );
        let e = revoke(
            &held().refusing("/usr/bin/getfacl -P | -p | -n | /etc/maknae"),
            Platform::Linux,
            &hobi(),
            &acct(),
            true,
            &[dir(ROOT)],
        )
        .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentAccess { grant: false, detail, .. } if detail == "Operation not supported"),
            "{e:?}"
        );
    }
}
