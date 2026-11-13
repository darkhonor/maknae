//! The enrolled agent's home, named to the shared `maknae-agentd` AppArmor profile
//! through one tunables file per agent.
#![cfg_attr(target_os = "macos", allow(dead_code))]
use super::agent::{io_error, is_not_found};
use super::agent_access::Run;
use super::EnrollError;
use maknae_io::program::Program;
use maknae_io::{AnchorRequired, FileOwner, Mode, StrategyPref};
use maknae_vault::agent_enroll::AgentId;
use std::path::Path;

pub(crate) const TUNABLES_DIR: &str = "/etc/apparmor.d/tunables/maknae-agents.d";
pub(crate) const PROFILE: &str = "/etc/apparmor.d/usr.bin.maknae-agentd";

pub(crate) const ENABLED_PARAM: &str = "/sys/module/apparmor/parameters/enabled";

/// AppArmor's directory include skips names ending `.orig`, `.rej`, `.dpkg-*`
/// and the like, which an agent id may; the fixed suffix keeps every file read.
pub(crate) fn file_name(agent: &AgentId) -> String {
    format!("{}.home", agent.as_str())
}

/// `None` when the kernel has no AppArmor module.
pub(crate) fn read_enabled() -> Option<String> {
    let out = maknae_io::read_absolute(
        Path::new(ENABLED_PARAM),
        maknae_io::TargetRequired {
            owner: Some(0),
            mode_mask: Some(0o022),
            nlink_exactly_one: false,
            regular_file: true,
            // sysfs reports PAGE_SIZE as st_size; arm64 may run 64 KiB pages.
            max_bytes: Some(64 * 1024),
        },
        StrategyPref::Auto,
    )
    .ok()?;
    String::from_utf8(out.value.to_vec()).ok()
}

/// A host that ships the profile but whose kernel does not enforce AppArmor
/// would run the agent unconfined.
pub(crate) fn require_enabled(
    profile_host: bool,
    enabled: Option<&str>,
) -> Result<(), EnrollError> {
    if !profile_host || enabled.map(str::trim) == Some("Y") {
        return Ok(());
    }
    Err(EnrollError::State(format!(
        "AppArmor is not enabled in this kernel ({ENABLED_PARAM} does not read Y), so the Agent Daemon would run unconfined; enable AppArmor and enroll again"
    )))
}

/// A home the profile can name: AppArmor reads `*`, `?`, `[`, `{`, `,`, `@`, `^`,
/// `#`, `=` and `+` in a variable's value as pattern or syntax.
pub(crate) fn home_ok(home: &str) -> bool {
    home.len() > 1
        && home.starts_with('/')
        && home
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
}

pub(crate) fn home_refusal(account: &str, home: &str) -> EnrollError {
    EnrollError::Owner(format!(
        "account {account}: its home {home:?} has a character outside [A-Za-z0-9._/-]; the Agent Daemon's AppArmor profile cannot name it"
    ))
}

pub(crate) fn tunable(account: &str, home: &str) -> Result<String, EnrollError> {
    if !home_ok(home) {
        return Err(home_refusal(account, home));
    }
    let parent = Path::new(home)
        .parent()
        .and_then(Path::to_str)
        .ok_or_else(|| home_refusal(account, home))?;
    Ok(format!(
        "@{{MAKNAE_AGENT_HOMES}}+={home}\n@{{MAKNAE_AGENT_HOME_PARENTS}}+={parent}\n"
    ))
}

/// `None` on a host without the packaged tunables directory: no AppArmor profile to feed.
pub(crate) fn open_tunables(path: &Path) -> Result<Option<maknae_io::Anchor>, EnrollError> {
    match maknae_io::open_anchor(
        path,
        AnchorRequired {
            owner: Some(0),
            mode_mask: Some(0o022),
        },
        StrategyPref::Auto,
    ) {
        Ok(a) => Ok(Some(a)),
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(io_error(path, e)),
    }
}

fn reload(r: &dyn Run) -> Result<(), EnrollError> {
    let args = vec!["-r".to_string(), PROFILE.to_string()];
    let program = format!("{} -r {PROFILE}", Program::ApparmorParser);
    match r.run(Program::ApparmorParser, &args) {
        Ok(out) if out.ok => Ok(()),
        Ok(out) => Err(EnrollError::Command {
            program,
            detail: out.stderr,
        }),
        Err(detail) => Err(EnrollError::Command { program, detail }),
    }
}

/// Writes the agent's tunables file, then reloads the profile so the instance
/// started next may write its home.
pub(crate) fn place(
    r: &dyn Run,
    dir: Option<&maknae_io::Anchor>,
    agent: &AgentId,
    account: &str,
    home: &str,
    owner: FileOwner,
) -> Result<(), EnrollError> {
    let Some(dir) = dir else {
        return Ok(());
    };
    let text = tunable(account, home)?;
    dir.publish_owned(
        Path::new(&file_name(agent)),
        None,
        text.as_bytes(),
        Mode(0o644),
        owner,
    )
    .map_err(|e| io_error(&Path::new(TUNABLES_DIR).join(file_name(agent)), e))?;
    reload(r)
}

/// Removes the agent's tunables file, once its instance has stopped, and reloads.
pub(crate) fn withdraw(
    r: &dyn Run,
    dir: Option<&maknae_io::Anchor>,
    agent: &AgentId,
) -> Result<(), EnrollError> {
    let Some(dir) = dir else {
        return Ok(());
    };
    match dir.remove(Path::new(&file_name(agent)), None) {
        Ok(_) => {}
        Err(e) if is_not_found(&e) => {}
        Err(e) => return Err(io_error(&Path::new(TUNABLES_DIR).join(file_name(agent)), e)),
    }
    reload(r)
}

#[cfg(test)]
mod tests {
    use super::super::agent_access::Ran;
    use super::*;
    use std::cell::RefCell;

    const PROFILE_TEXT: &str =
        include_str!("../../../../packaging/deb/apparmor/usr.bin.maknae-agentd");
    const TUNABLE_TEXT: &str =
        include_str!("../../../../packaging/deb/apparmor/tunables.maknae-agents");
    const BUILD_DEB: &str = include_str!("../../../../packaging/deb/build-deb.sh");
    const POSTINST: &str = include_str!("../../../../packaging/deb/postinst");
    const PRERM: &str = include_str!("../../../../packaging/deb/prerm");

    fn hobi() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    #[derive(Default)]
    struct Recorder {
        log: RefCell<Vec<String>>,
        refuse: bool,
    }

    impl Run for Recorder {
        fn run(&self, program: Program, args: &[String]) -> Result<Ran, String> {
            self.log
                .borrow_mut()
                .push(format!("{program} {}", args.join(" ")));
            Ok(Ran {
                ok: !self.refuse,
                code: Some(i32::from(self.refuse)),
                stdout: String::new(),
                stderr: if self.refuse {
                    "parse error".into()
                } else {
                    String::new()
                },
            })
        }
    }

    fn me() -> FileOwner {
        FileOwner {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
        }
    }

    fn rules() -> Vec<&'static str> {
        PROFILE_TEXT
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    }

    fn has_rule(path: &str, mode: &str) -> bool {
        rules().iter().any(|l| {
            let mut w = l.trim_end_matches(',').split_whitespace();
            w.next_back() == Some(mode) && w.collect::<Vec<_>>().join(" ") == path
        })
    }

    #[test]
    fn each_agents_file_ends_home_so_the_directory_include_reads_it() {
        for (id, want) in [
            ("hobi", "hobi.home"),
            ("a.orig", "a.orig.home"),
            ("a.dpkg-old", "a.dpkg-old.home"),
            ("a.rej", "a.rej.home"),
        ] {
            assert_eq!(file_name(&AgentId::parse(id).unwrap()), want);
        }
        let (dir, anchor) = super::super::agent::tests::scratch_anchor("aa-suffix");
        let id = AgentId::parse("a.dpkg-old").unwrap();
        let r = Recorder::default();
        place(&r, Some(&anchor), &id, "a", "/srv/a", me()).unwrap();
        assert!(dir.join("a.dpkg-old.home").exists());
        assert!(!dir.join("a.dpkg-old").exists());
        withdraw(&r, Some(&anchor), &id).unwrap();
        assert!(!dir.join("a.dpkg-old.home").exists());
    }

    #[test]
    fn a_host_with_the_profile_refuses_to_enroll_when_the_kernel_does_not_enforce_apparmor() {
        for enabled in [None, Some("N\n"), Some(""), Some("y\n")] {
            let e = require_enabled(true, enabled).unwrap_err();
            assert!(
                matches!(&e, EnrollError::State(m) if m.contains("unconfined")),
                "{enabled:?}: {e:?}"
            );
        }
        require_enabled(true, Some("Y\n")).unwrap();
        require_enabled(false, None).unwrap();
        require_enabled(false, Some("N\n")).unwrap();
    }

    #[test]
    fn the_tunable_names_the_home_and_its_parent() {
        assert_eq!(
            tunable("hobi", "/var/lib/maknae-agents/hobi").unwrap(),
            "@{MAKNAE_AGENT_HOMES}+=/var/lib/maknae-agents/hobi\n@{MAKNAE_AGENT_HOME_PARENTS}+=/var/lib/maknae-agents\n"
        );
    }

    #[test]
    fn a_home_with_an_apparmor_pattern_character_is_refused() {
        for bad in [
            "/home/a*",
            "/home/a?",
            "/home/[a]",
            "/home/{a}",
            "/home/a,b",
            "/home/@{x}",
            "/home/a^",
            "/home/a#",
            "/home/a=b",
            "/home/a+b",
            "/",
            "home/a",
            "/home/a b",
        ] {
            assert!(!home_ok(bad), "{bad}");
            let e = tunable("hobi", bad).unwrap_err();
            assert!(
                matches!(&e, EnrollError::Owner(m) if m.contains("AppArmor")),
                "{bad}: {e:?}"
            );
        }
        for good in [
            "/var/lib/maknae-agents/hobi",
            "/home/hobi.svc",
            "/srv/a_b-c",
        ] {
            assert!(home_ok(good), "{good}");
        }
    }

    #[test]
    fn place_writes_the_agents_file_then_reloads_the_profile() {
        let (dir, anchor) = super::super::agent::tests::scratch_anchor("aa-place");
        let r = Recorder::default();
        place(
            &r,
            Some(&anchor),
            &hobi(),
            "hobi",
            "/var/lib/maknae-agents/hobi",
            me(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("hobi.home")).unwrap(),
            tunable("hobi", "/var/lib/maknae-agents/hobi").unwrap()
        );
        assert_eq!(
            *r.log.borrow(),
            ["/usr/sbin/apparmor_parser -r /etc/apparmor.d/usr.bin.maknae-agentd"]
        );
    }

    #[test]
    fn a_refused_home_writes_nothing_and_reloads_nothing() {
        let (dir, anchor) = super::super::agent::tests::scratch_anchor("aa-refuse");
        let r = Recorder::default();
        assert!(place(&r, Some(&anchor), &hobi(), "hobi", "/home/a*", me()).is_err());
        assert!(!dir.join("hobi.home").exists());
        assert!(r.log.borrow().is_empty());
    }

    #[test]
    fn a_failed_reload_fails_the_step() {
        let (_dir, anchor) = super::super::agent::tests::scratch_anchor("aa-reload");
        let r = Recorder {
            refuse: true,
            ..Recorder::default()
        };
        let e = place(&r, Some(&anchor), &hobi(), "hobi", "/srv/hobi", me()).unwrap_err();
        assert!(
            matches!(&e, EnrollError::Command { program, detail }
                if program.ends_with("apparmor_parser -r /etc/apparmor.d/usr.bin.maknae-agentd")
                    && detail == "parse error"),
            "{e:?}"
        );
        let e = withdraw(&r, Some(&anchor), &hobi()).unwrap_err();
        assert!(matches!(e, EnrollError::Command { .. }), "{e:?}");
    }

    #[test]
    fn withdraw_removes_only_the_agents_file_and_a_missing_one_is_already_removed() {
        let (dir, anchor) = super::super::agent::tests::scratch_anchor("aa-withdraw");
        std::fs::write(dir.join("hobi.home"), "x").unwrap();
        std::fs::write(dir.join("jin.home"), "y").unwrap();
        let r = Recorder::default();
        withdraw(&r, Some(&anchor), &hobi()).unwrap();
        assert!(!dir.join("hobi.home").exists());
        assert!(dir.join("jin.home").exists());
        withdraw(&r, Some(&anchor), &hobi()).unwrap();
        assert_eq!(r.log.borrow().len(), 2);
    }

    #[test]
    fn without_the_tunables_directory_nothing_runs() {
        let r = Recorder::default();
        place(&r, None, &hobi(), "hobi", "/home/a*", me()).unwrap();
        withdraw(&r, None, &hobi()).unwrap();
        assert!(r.log.borrow().is_empty());
        let missing =
            std::env::temp_dir().join(format!("maknae-no-tunables-{}", std::process::id()));
        assert!(open_tunables(&missing).unwrap().is_none());
    }

    #[test]
    fn the_package_ships_the_tunable_the_profile_includes_and_its_directory() {
        assert!(PROFILE_TEXT
            .lines()
            .any(|l| l == "#include <tunables/maknae-agents>"));
        let defs: Vec<&str> = TUNABLE_TEXT
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();
        assert_eq!(
            defs,
            [
                "@{MAKNAE_AGENT_HOMES}=/nonexistent/maknae-no-agent",
                "@{MAKNAE_AGENT_HOME_PARENTS}=/nonexistent/maknae-no-agent",
                "include if exists <tunables/maknae-agents.d>",
            ]
        );
        assert_eq!(
            Path::new(TUNABLES_DIR).file_name().unwrap(),
            "maknae-agents.d"
        );
        for needle in [
            "\"$PKG_ROOT/etc/apparmor.d/tunables/maknae-agents\"",
            "install -d -m 0755 \"$PKG_ROOT/etc/apparmor.d/tunables/maknae-agents.d\"",
            "\n/etc/apparmor.d/usr.bin.maknae-agentd\n",
            "\n/etc/apparmor.d/tunables/maknae-agents\n",
        ] {
            assert!(BUILD_DEB.contains(needle), "build-deb.sh: {needle}");
        }
        assert!(POSTINST.contains(&format!("apparmor_parser -r {PROFILE} ")));
        assert!(PRERM.contains(&format!("apparmor_parser -R {PROFILE} ")));
    }

    #[test]
    fn the_profile_attaches_to_the_agent_daemon_and_reads_exactly_its_configuration() {
        assert!(rules().contains(&"profile maknae-agentd /usr/bin/maknae-agentd {"));
        for (path, mode) in [
            ("/etc/maknae/", "r"),
            ("/etc/maknae/agents/", "r"),
            ("/etc/maknae/agents/*/", "r"),
            (
                "/etc/maknae/agents/*/{agent.yaml,persona.md,enrollment.yaml}",
                "r",
            ),
            (
                "/etc/maknae/tls/{maknae-root-ca,maknae-int-ca,vault-ca}.crt",
                "r",
            ),
            ("/etc/ssl/maknae/seal.pub", "r"),
            ("/run/credentials/maknae-agent@*.service/**", "r"),
            ("/run/maknae-agent/maknaed.sock", "rw"),
            ("owner @{MAKNAE_AGENT_HOMES}/**", "rwk"),
        ] {
            assert!(has_rule(path, mode), "{path} {mode}");
        }
        let etc: Vec<&str> = rules()
            .into_iter()
            .filter(|l| l.starts_with("/etc/maknae"))
            .collect();
        assert_eq!(etc.len(), 6, "{etc:?}");
        assert!(!rules().iter().any(|l| l.starts_with("/etc/maknae/**")));
        assert!(!rules()
            .iter()
            .any(|l| l.contains("MAKNAE_AGENT_HOMES") && !l.starts_with("owner ")));
    }

    #[test]
    fn the_profile_denies_the_mail_spool_terminals_and_the_broadcast_programs() {
        for (path, mode) in [
            ("deny /var/mail/**", "rwklx"),
            ("deny /var/spool/mail/**", "rwklx"),
            ("deny /dev/tty*", "w"),
            ("deny /dev/pts/*", "w"),
            ("deny /usr/bin/wall", "x"),
            ("deny /usr/bin/write", "x"),
            ("deny /etc/maknae/private/**", "rwklx"),
            ("deny /var/lib/maknae/**", "rwklx"),
            ("deny /var/log/maknae/**", "rwklx"),
            ("deny /dev/log", "w"),
            ("deny /run/systemd/journal/socket", "w"),
            ("deny /run/systemd/journal/dev-log", "w"),
            ("deny /run/systemd/journal/stdout", "w"),
        ] {
            assert!(has_rule(path, mode), "{path} {mode}");
        }
        for abstract_ in ["deny unix addr=@**,", "deny unix peer=(addr=@**),"] {
            assert!(rules().contains(&abstract_), "{abstract_}");
        }
        let executes = |l: &&str| {
            l.trim_end_matches(',')
                .split_whitespace()
                .next_back()
                .is_some_and(|mode| mode.contains('x'))
        };
        let exec: Vec<&str> = rules()
            .into_iter()
            .filter(|l| !l.starts_with("deny "))
            .filter(executes)
            .collect();
        assert!(exec.is_empty(), "{exec:?}");
    }
}
