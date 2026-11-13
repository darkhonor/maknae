use super::EnrollError;
use maknae_io::program::{command, Program};
use maknae_vault::agent_enroll::AgentId;
use std::path::{Path, PathBuf};

const ETC_DIR: &str = "/etc/maknae";
const TLS_DIR: &str = "/etc/maknae/tls";
const TLS_FILES: [&str; 3] = ["maknae-root-ca.crt", "maknae-int-ca.crt", "vault-ca.crt"];

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

fn agent_dir(agent: &AgentId) -> PathBuf {
    Path::new(super::agent::AGENTS_DIR).join(agent.as_str())
}

/// Every entry the Agent Daemon's account reads through: the directories its anchored
/// reader opens, its own files, and the three certificates `AgentLogin` loads.
pub(crate) fn grant_entries(agent: &AgentId, persona: bool) -> Vec<Entry> {
    let own = agent_dir(agent);
    let mut out = vec![
        dir(ETC_DIR),
        dir(super::agent::AGENTS_DIR),
        dir(&own),
        dir(TLS_DIR),
        file(own.join(maknae_config::AGENT_CLIENT_FILE)),
        file(own.join(maknae_config::ENROLLMENT_FILE)),
    ];
    if persona {
        out.push(file(own.join(maknae_config::PERSONA_FILE)));
    }
    out.extend(TLS_FILES.iter().map(|f| file(Path::new(TLS_DIR).join(f))));
    out
}

/// The entries that outlive `remove-agent`: everything but the two files it deletes.
pub(crate) fn kept_entries(agent: &AgentId, persona: bool) -> Vec<Entry> {
    let own = agent_dir(agent);
    let gone = [
        own.join(maknae_config::AGENT_CLIENT_FILE),
        own.join(maknae_config::ENROLLMENT_FILE),
    ];
    grant_entries(agent, persona)
        .into_iter()
        .filter(|e| !gone.contains(&e.path))
        .collect()
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

fn linux_spec(account: &str, e: &Entry) -> String {
    format!("u:{account}:{}", if e.dir { "r-x" } else { "r--" })
}

fn macos_ace(account: &str, e: &Entry) -> String {
    format!(
        "user:{account} allow {}",
        if e.dir { "list,search" } else { "read" }
    )
}

fn entry_text(platform: Platform, account: &str, e: &Entry) -> String {
    match platform {
        Platform::Linux => linux_spec(account, e),
        Platform::Macos => macos_ace(account, e),
    }
}

fn grant_call(platform: Platform, account: &str, e: &Entry) -> Call {
    match platform {
        Platform::Linux => (
            Program::Setfacl,
            vec!["-m".into(), linux_spec(account, e), path_arg(&e.path)],
        ),
        Platform::Macos => (
            Program::Chmod,
            vec!["+a".into(), macos_ace(account, e), path_arg(&e.path)],
        ),
    }
}

fn grant_readback(platform: Platform, e: &Entry) -> Call {
    match platform {
        Platform::Linux => (Program::Getfacl, vec!["-p".into(), path_arg(&e.path)]),
        Platform::Macos => (Program::Ls, vec!["-led".into(), path_arg(&e.path)]),
    }
}

/// `getfacl -p` renders `u:NAME:r-x` as the whole line `user:NAME:r-x`; a mask-limited
/// entry carries a `#effective:` suffix and does not match.
fn linux_granted(account: &str, e: &Entry, out: &str) -> bool {
    let want = format!("user:{account}:{}", if e.dir { "r-x" } else { "r--" });
    out.lines().any(|l| l.trim() == want)
}

fn macos_listed(ace: &str, out: &str) -> bool {
    out.lines().any(|l| {
        l.trim().split_once(": ").is_some_and(|(i, a)| {
            !i.is_empty() && i.chars().all(|c| c.is_ascii_digit()) && a == ace
        })
    })
}

fn granted(platform: Platform, account: &str, e: &Entry, out: &str) -> bool {
    match platform {
        Platform::Linux => linux_granted(account, e, out),
        Platform::Macos => macos_listed(&macos_ace(account, e), out),
    }
}

fn refusal(grant: bool, e: &Entry, entry: String, detail: String) -> EnrollError {
    EnrollError::AgentAccess {
        grant,
        path: e.path.clone(),
        entry,
        detail,
    }
}

fn ran(r: &impl Run, (program, args): Call) -> Result<Ran, String> {
    r.run(program, &args)
}

pub(crate) fn grant(
    r: &impl Run,
    platform: Platform,
    account: &str,
    entries: &[Entry],
) -> Result<(), EnrollError> {
    for e in entries {
        let entry = entry_text(platform, account, e);
        match ran(r, grant_call(platform, account, e)) {
            Ok(out) if out.ok => {}
            Ok(out) => return Err(refusal(true, e, entry, out.stderr)),
            Err(why) => return Err(refusal(true, e, entry, why)),
        }
        match ran(r, grant_readback(platform, e)) {
            Ok(out) if out.ok && granted(platform, account, e, &out.stdout) => {}
            Ok(_) => {
                return Err(refusal(
                    true,
                    e,
                    entry,
                    "the entry did not read back".into(),
                ))
            }
            Err(why) => return Err(refusal(true, e, entry, why)),
        }
    }
    Ok(())
}

fn revoke_calls(platform: Platform, account: &str, uid: u32, e: &Entry) -> (String, Call, Call) {
    match platform {
        Platform::Linux => (
            format!("u:{uid}"),
            (
                Program::Getfacl,
                vec![
                    "-p".into(),
                    "-n".into(),
                    "--omit-header".into(),
                    path_arg(&e.path),
                ],
            ),
            (
                Program::Setfacl,
                vec!["-x".into(), format!("u:{uid}"), path_arg(&e.path)],
            ),
        ),
        Platform::Macos => {
            let ace = macos_ace(account, e);
            (
                ace.clone(),
                grant_readback(platform, e),
                (Program::Chmod, vec!["-a".into(), ace, path_arg(&e.path)]),
            )
        }
    }
}

fn held(platform: Platform, entry: &str, uid: u32, out: &str) -> bool {
    match platform {
        Platform::Linux => {
            let who = format!("user:{uid}:");
            out.lines().any(|l| l.starts_with(&who))
        }
        Platform::Macos => macos_listed(entry, out),
    }
}

/// Linux revokes by uid, so an entry left by an account deleted since enrollment is still
/// found and removed, and a later account given that uid inherits nothing.
pub(crate) fn revoke(
    r: &impl Run,
    platform: Platform,
    account: &str,
    uid: u32,
    entries: &[Entry],
) -> Result<(), EnrollError> {
    for e in entries {
        let (entry, look, remove) = revoke_calls(platform, account, uid, e);
        let still_held = || match ran(r, look.clone()) {
            Ok(out) if out.ok => Ok(held(platform, &entry, uid, &out.stdout)),
            Ok(out) => Err(refusal(false, e, entry.clone(), out.stderr)),
            Err(why) => Err(refusal(false, e, entry.clone(), why)),
        };
        if !still_held()? {
            continue;
        }
        match ran(r, remove) {
            Ok(out) if out.ok => {}
            Ok(out) => return Err(refusal(false, e, entry.clone(), out.stderr)),
            Err(why) => return Err(refusal(false, e, entry.clone(), why)),
        }
        if still_held()? {
            return Err(refusal(
                false,
                e,
                entry.clone(),
                "the entry is still listed".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};

    fn hobi() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    const ACCT: &str = "hobi-svc";
    const UID: u32 = 990;

    /// A host whose ACL state the calls change, so a read-back sees what was written.
    #[derive(Default)]
    struct FakeHost {
        calls: RefCell<Vec<String>>,
        acl: RefCell<BTreeMap<String, BTreeSet<String>>>,
        refuse: RefCell<BTreeSet<String>>,
        deaf: RefCell<BTreeSet<String>>,
    }

    impl FakeHost {
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        fn refusing(self, call: &str) -> Self {
            self.refuse.borrow_mut().insert(call.into());
            self
        }

        fn ignoring_writes_to(self, path: &str) -> Self {
            self.deaf.borrow_mut().insert(path.into());
            self
        }

        fn holding(self, path: &str, line: &str) -> Self {
            self.acl
                .borrow_mut()
                .entry(path.into())
                .or_default()
                .insert(line.into());
            self
        }
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
            let mut acl = self.acl.borrow_mut();
            let lines = acl.entry(path.clone()).or_default();
            let ok = |stdout: String| {
                Ok(Ran {
                    ok: true,
                    stdout,
                    stderr: String::new(),
                })
            };
            match (program, args[0].as_str()) {
                (Program::Setfacl, "-m") if !deaf => {
                    let (who, perms) = args[1].rsplit_once(':').unwrap();
                    let name = who.strip_prefix("u:").unwrap();
                    lines.insert(format!("user:{name}:{perms}"));
                    ok(String::new())
                }
                (Program::Setfacl, "-x") => {
                    let who = format!("user:{}:", args[1].strip_prefix("u:").unwrap());
                    lines.retain(|l| !l.starts_with(&who));
                    ok(String::new())
                }
                (Program::Getfacl, _) => ok(format!(
                    "# file: {path}\nuser::rwx\n{}\ngroup::r-x\nmask::r-x\nother::---\n",
                    lines.iter().cloned().collect::<Vec<_>>().join("\n")
                )),
                (Program::Chmod, "+a") if !deaf => {
                    lines.insert(args[1].clone());
                    ok(String::new())
                }
                (Program::Chmod, "-a") => {
                    lines.remove(&args[1]);
                    ok(String::new())
                }
                (Program::Ls, _) => ok(format!(
                    "drwxr-x---+ 3 root  wheel  96 Nov 13 10:00 {path}\n{}",
                    lines
                        .iter()
                        .enumerate()
                        .map(|(i, l)| format!(" {i}: {l}\n"))
                        .collect::<String>()
                )),
                _ => ok(String::new()),
            }
        }
    }

    fn paths(entries: &[Entry]) -> Vec<(String, bool)> {
        entries
            .iter()
            .map(|e| (e.path.display().to_string(), e.dir))
            .collect()
    }

    #[test]
    fn the_grant_covers_exactly_what_the_daemon_reads() {
        assert_eq!(
            paths(&grant_entries(&hobi(), true)),
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
        let without = paths(&grant_entries(&hobi(), false));
        assert_eq!(without.len(), 9);
        assert!(!without.iter().any(|(p, _)| p.ends_with("persona.md")));
    }

    #[test]
    fn no_entry_is_ever_on_private_or_another_agent() {
        for persona in [true, false] {
            for e in grant_entries(&hobi(), persona)
                .iter()
                .chain(&kept_entries(&hobi(), persona))
            {
                let p = e.path.display().to_string();
                assert!(!p.starts_with(super::super::agent::PRIVATE_DIR), "{p}");
                assert!(!p.contains("private"), "{p}");
                assert!(
                    !p.starts_with("/etc/maknae/agents/")
                        || p.starts_with("/etc/maknae/agents/hobi"),
                    "{p}"
                );
            }
        }
    }

    #[test]
    fn kept_entries_drop_only_the_files_remove_agent_deletes() {
        let kept = paths(&kept_entries(&hobi(), true));
        let all = paths(&grant_entries(&hobi(), true));
        let dropped: Vec<_> = all.iter().filter(|e| !kept.contains(e)).collect();
        assert_eq!(
            dropped,
            [
                &("/etc/maknae/agents/hobi/agent.yaml".to_string(), false),
                &("/etc/maknae/agents/hobi/enrollment.yaml".to_string(), false),
            ]
        );
        assert_eq!(kept.len(), all.len() - 2);
    }

    #[test]
    fn linux_grants_each_entry_with_setfacl_and_reads_it_back() {
        let host = FakeHost::default();
        let entries = grant_entries(&hobi(), true);
        grant(&host, Platform::Linux, ACCT, &entries).unwrap();
        let mut want = Vec::new();
        for e in &entries {
            let perms = if e.dir { "r-x" } else { "r--" };
            let p = e.path.display();
            want.push(format!("/usr/bin/setfacl -m | u:{ACCT}:{perms} | {p}"));
            want.push(format!("/usr/bin/getfacl -p | {p}"));
        }
        assert_eq!(host.calls(), want);
    }

    #[test]
    fn macos_grants_each_entry_with_chmod_and_reads_it_back() {
        let host = FakeHost::default();
        let entries = grant_entries(&hobi(), true);
        grant(&host, Platform::Macos, ACCT, &entries).unwrap();
        let mut want = Vec::new();
        for e in &entries {
            let perms = if e.dir { "list,search" } else { "read" };
            let p = e.path.display();
            want.push(format!("/bin/chmod +a | user:{ACCT} allow {perms} | {p}"));
            want.push(format!("/bin/ls -led | {p}"));
        }
        assert_eq!(host.calls(), want);
    }

    #[test]
    fn an_entry_that_does_not_read_back_refuses_and_stops() {
        for platform in [Platform::Linux, Platform::Macos] {
            let host = FakeHost::default().ignoring_writes_to("/etc/maknae/agents/hobi");
            let e = grant(&host, platform, ACCT, &grant_entries(&hobi(), true)).unwrap_err();
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
        let d = dir("/etc/maknae");
        assert!(linux_granted(ACCT, &d, "user:hobi-svc:r-x\n"));
        assert!(linux_granted(ACCT, &d, "  user:hobi-svc:r-x  \n"));
        for out in [
            "user:hobi-svc:r-x\t#effective:r--\n",
            "default:user:hobi-svc:r-x\n",
            "user:hobi-svc:r--\n",
            "user:hobi-svc2:r-x\n",
            "",
        ] {
            assert!(!linux_granted(ACCT, &d, out), "{out:?}");
        }
        assert!(linux_granted(ACCT, &file("/x"), "user:hobi-svc:r--\n"));
        assert!(!linux_granted(ACCT, &file("/x"), "user:hobi-svc:r-x\n"));
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
        let host =
            FakeHost::default().refusing("/usr/bin/setfacl -m | u:hobi-svc:r-x | /etc/maknae/tls");
        let e = grant(&host, Platform::Linux, ACCT, &grant_entries(&hobi(), false)).unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentAccess { grant: true, path, entry, detail }
                if path == Path::new("/etc/maknae/tls") && entry == "u:hobi-svc:r-x" && detail == "Operation not supported"),
            "{e:?}"
        );
        let text = e.to_string();
        assert!(
            text.contains("/etc/maknae/tls") && text.contains("--rotate"),
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
        let entries = grant_entries(&hobi(), false);
        for platform in [Platform::Linux, Platform::Macos] {
            let e = grant(&Absent, platform, ACCT, &entries).unwrap_err();
            assert!(
                matches!(&e, EnrollError::AgentAccess { grant: true, detail, .. } if detail.ends_with("not found")),
                "{e:?}"
            );
            let e = revoke(&Absent, platform, ACCT, UID, &entries).unwrap_err();
            assert!(
                matches!(&e, EnrollError::AgentAccess { grant: false, detail, .. } if detail.ends_with("not found")),
                "{e:?}"
            );
        }
    }

    #[test]
    fn linux_revokes_each_held_entry_by_uid_and_confirms_it_gone() {
        let entries = kept_entries(&hobi(), true);
        let mut host = FakeHost::default();
        for e in &entries {
            host = host.holding(&e.path.display().to_string(), "user:990:r-x");
        }
        host = host.holding("/etc/maknae", "user:991:r-x");
        revoke(&host, Platform::Linux, ACCT, UID, &entries).unwrap();
        let mut want = Vec::new();
        for e in &entries {
            let p = e.path.display();
            want.push(format!("/usr/bin/getfacl -p | -n | --omit-header | {p}"));
            want.push(format!("/usr/bin/setfacl -x | u:990 | {p}"));
            want.push(format!("/usr/bin/getfacl -p | -n | --omit-header | {p}"));
        }
        assert_eq!(host.calls(), want);
        assert_eq!(
            host.acl.borrow().get("/etc/maknae").cloned().unwrap(),
            BTreeSet::from(["user:991:r-x".to_string()])
        );
    }

    #[test]
    fn macos_revokes_each_held_entry_and_confirms_it_gone() {
        let entries = kept_entries(&hobi(), false);
        let mut host = FakeHost::default();
        for e in &entries {
            host = host.holding(&e.path.display().to_string(), &macos_ace(ACCT, e));
        }
        revoke(&host, Platform::Macos, ACCT, UID, &entries).unwrap();
        let mut want = Vec::new();
        for e in &entries {
            let p = e.path.display();
            let ace = macos_ace(ACCT, e);
            want.push(format!("/bin/ls -led | {p}"));
            want.push(format!("/bin/chmod -a | {ace} | {p}"));
            want.push(format!("/bin/ls -led | {p}"));
        }
        assert_eq!(host.calls(), want);
        assert!(host.acl.borrow().values().all(BTreeSet::is_empty));
    }

    #[test]
    fn revoke_skips_an_entry_that_is_not_held() {
        let entries = vec![dir("/etc/maknae")];
        for platform in [Platform::Linux, Platform::Macos] {
            let host = FakeHost::default().holding("/etc/maknae", "user:9900:r-x");
            revoke(&host, platform, ACCT, UID, &entries).unwrap();
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
            let e = revoke(&Stuck, platform, ACCT, UID, &[dir("/etc/maknae")]).unwrap_err();
            assert!(
                matches!(&e, EnrollError::AgentAccess { grant: false, detail, .. } if detail == "the entry is still listed"),
                "{platform:?}: {e:?}"
            );
            assert!(e.to_string().contains("remove-agent"), "{e}");
        }
    }

    #[test]
    fn a_refused_revoke_or_read_names_the_reason() {
        let held = || FakeHost::default().holding("/etc/maknae", "user:990:r-x");
        let e = revoke(
            &held().refusing("/usr/bin/setfacl -x | u:990 | /etc/maknae"),
            Platform::Linux,
            ACCT,
            UID,
            &[dir("/etc/maknae")],
        )
        .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentAccess { grant: false, entry, detail, .. }
                if entry == "u:990" && detail == "Operation not supported"),
            "{e:?}"
        );
        let e = revoke(
            &held().refusing("/usr/bin/getfacl -p | -n | --omit-header | /etc/maknae"),
            Platform::Linux,
            ACCT,
            UID,
            &[dir("/etc/maknae")],
        )
        .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentAccess { grant: false, detail, .. } if detail == "Operation not supported"),
            "{e:?}"
        );
    }

    #[test]
    fn the_host_platform_matches_the_build_target() {
        assert_eq!(
            Platform::HOST,
            if cfg!(target_os = "macos") {
                Platform::Macos
            } else {
                Platform::Linux
            }
        );
    }
}
