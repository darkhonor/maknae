//! The Agent Daemon's launchd job: the per-agent plist enroll writes into
//! `/Library/LaunchDaemons`, and the `launchctl` calls that start and stop it.
// Only macOS enrollment calls it; its tests run on both lanes.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
use super::agent::{io_error, is_not_found};
use super::agent_access::Run;
use super::artifact_table::{Artifact, ContentKind, Owner};
use super::artifact_write::{self, OwnerResolver};
use super::keychain_write::AGENT_BINARY;
use super::EnrollError;
use maknae_io::program::Program;
use maknae_io::{AnchorRequired, FileOwner, IoError, Mode, MutationFailure, StrategyPref};
use maknae_vault::agent_enroll::AgentId;
use nix::unistd::{Gid, Uid};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) const DAEMON_DIR: &str = "/Library/LaunchDaemons";
pub(crate) const TEMPLATE: &str =
    include_str!("../../../../packaging/macos/io.maknae.maknae-agentd.template.plist");
const NO_SUCH_SERVICE: i32 = 113;
pub(crate) const UNLOAD_POLL: Duration = Duration::from_millis(500);
/// The template's `ExitTimeOut` plus margin, held by a test.
pub(crate) const UNLOAD_WAIT: Duration = Duration::from_secs(191);

pub(crate) fn label(agent: &AgentId) -> String {
    format!("io.maknae.maknae-agentd.{}", agent.as_str())
}

pub(crate) fn plist_file(agent: &AgentId) -> String {
    format!("{}.plist", label(agent))
}

fn target(agent: &AgentId) -> String {
    format!("system/{}", label(agent))
}

pub(crate) fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

pub(crate) const LOG_ROOT: &str = "/usr/local/var/log/maknae-agent";

pub(crate) fn stderr_path(log_root: &Path, agent: &AgentId) -> PathBuf {
    log_root.join(agent.as_str()).join("agentd.err")
}

struct LogOwners {
    root: FileOwner,
}

impl OwnerResolver for LogOwners {
    fn resolve(&self, owner: Owner) -> Result<(Option<Uid>, Option<Gid>), EnrollError> {
        let (uid, gid) = match owner {
            Owner::RootRoot => (self.root.uid, self.root.gid),
            Owner::Account { uid, gid } => (uid, gid),
            other => {
                return Err(EnrollError::Owner(format!(
                    "the agent's log directory is never {other:?}"
                )))
            }
        };
        Ok((Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))))
    }
}

/// A directory another account holds, or opened wider than 0750, is emptied
/// first: the new account could neither write nor replace what is in it.
pub(crate) fn ensure_log_dir(
    log_root: &Path,
    agent: &AgentId,
    account: FileOwner,
    root: FileOwner,
) -> Result<(), EnrollError> {
    let owners = LogOwners { root };
    artifact_write::ensure_dir(
        &Artifact {
            path: log_root.to_path_buf(),
            owner: Owner::RootRoot,
            mode: 0o755,
            content: ContentKind::Dir,
        },
        &owners,
    )?;
    let dir = log_root.join(agent.as_str());
    let held_by_other = match maknae_io::open_anchor(
        &dir,
        AnchorRequired {
            owner: Some(account.uid),
            mode_mask: Some(0o027),
        },
        StrategyPref::Auto,
    ) {
        Ok(_) => false,
        Err(IoError::NotOwned { .. } | IoError::InsecurePermissions { .. }) => true,
        Err(e) if is_not_found(&e) => false,
        Err(e) => return Err(io_error(&dir, e)),
    };
    if held_by_other {
        remove_log_dir(log_root, agent)?;
    }
    artifact_write::ensure_dir(
        &Artifact {
            path: dir,
            owner: Owner::Account {
                uid: account.uid,
                gid: account.gid,
            },
            mode: 0o750,
            content: ContentKind::Dir,
        },
        &owners,
    )
}

/// Each entry is unlinked, never followed: the account owns the directory.
pub(crate) fn remove_log_dir(log_root: &Path, agent: &AgentId) -> Result<(), EnrollError> {
    let failed = |e: MutationFailure| io_error(&e.at, e.source);
    let root = match maknae_io::delegated::open_directory_for_delegation(log_root) {
        Ok(fd) => maknae_io::verify_mutation_directory(fd).map_err(|e| io_error(log_root, e))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(EnrollError::State(format!("{}: {e}", log_root.display()))),
    };
    let dir = match root.open_child_directory(agent.as_str()) {
        Ok(d) => d,
        Err(e) if is_not_found(&e) => return Ok(()),
        Err(e) => return Err(io_error(&log_root.join(agent.as_str()), e)),
    };
    let mut names = Vec::new();
    let mut cursor = dir.cursor().map_err(|e| io_error(dir.path(), e))?;
    while let Some(entry) = cursor.next_entry().map_err(|e| io_error(dir.path(), e))? {
        names.push(entry.name);
    }
    for name in names {
        let leaf = name.to_string_lossy();
        dir.remove_entry(&leaf).map_err(failed)?;
    }
    drop(dir);
    root.remove_entry(agent.as_str()).map_err(failed)?;
    Ok(())
}

pub(crate) fn plist(agent: &AgentId, user: &str) -> String {
    render(agent, user, &stderr_path(Path::new(LOG_ROOT), agent))
}

/// `user` is substituted last, so no account name is read as a placeholder.
fn render(agent: &AgentId, user: &str, stderr: &Path) -> String {
    TEMPLATE
        .replace("@AGENT_ID@", &xml_escape(agent.as_str()))
        .replace("@PROGRAM@", &xml_escape(AGENT_BINARY))
        .replace("@STDERR_PATH@", &xml_escape(&stderr.to_string_lossy()))
        .replace("@USER_NAME@", &xml_escape(user))
}

pub(crate) fn write_plist(
    daemons: &maknae_io::Anchor,
    agent: &AgentId,
    user: &str,
    owner: FileOwner,
) -> Result<(), EnrollError> {
    let rel = plist_file(agent);
    daemons
        .publish_owned(
            Path::new(&rel),
            None,
            plist(agent, user).as_bytes(),
            Mode(0o644),
            owner,
        )
        .map(|_| ())
        .map_err(|e| io_error(&Path::new(DAEMON_DIR).join(&rel), e))
}

pub(crate) fn remove_plist(
    daemons: &maknae_io::Anchor,
    agent: &AgentId,
) -> Result<(), EnrollError> {
    let rel = plist_file(agent);
    match daemons.remove(Path::new(&rel), None) {
        Ok(_) => Ok(()),
        Err(e) if is_not_found(&e) => Ok(()),
        Err(e) => Err(io_error(&Path::new(DAEMON_DIR).join(&rel), e)),
    }
}

fn launchctl(r: &dyn Run, args: &[&str]) -> Result<(), EnrollError> {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let program = format!("{} {}", Program::Launchctl, args.join(" "));
    match r.run(Program::Launchctl, &args) {
        Ok(out) if out.ok => Ok(()),
        Ok(out) => Err(EnrollError::Command {
            program,
            detail: out.stderr,
        }),
        Err(detail) => Err(EnrollError::Command { program, detail }),
    }
}

fn loaded(r: &dyn Run, agent: &AgentId) -> Result<bool, EnrollError> {
    let target = target(agent);
    let program = format!("{} print {target}", Program::Launchctl);
    match r.run(Program::Launchctl, &["print".to_string(), target]) {
        Ok(out) if out.ok => Ok(true),
        Ok(out) if out.code == Some(NO_SUCH_SERVICE) => Ok(false),
        Ok(out) => Err(EnrollError::Command {
            program,
            detail: format!("exit {:?}: {}", out.code, out.stderr),
        }),
        Err(detail) => Err(EnrollError::Command { program, detail }),
    }
}

/// `bootout` can return before launchd has reaped the job.
fn unload(
    r: &dyn Run,
    agent: &AgentId,
    pause: &mut dyn FnMut(Duration),
) -> Result<(), EnrollError> {
    if !loaded(r, agent)? {
        return Ok(());
    }
    launchctl(r, &["bootout", &target(agent)])?;
    let mut waited = Duration::ZERO;
    while loaded(r, agent)? {
        if waited >= UNLOAD_WAIT {
            return Err(EnrollError::State(format!(
                "launchd still holds {} {}s after bootout",
                label(agent),
                waited.as_secs()
            )));
        }
        pause(UNLOAD_POLL);
        waited += UNLOAD_POLL;
    }
    Ok(())
}

/// `write` places the plist. A loaded job is booted out first, so a
/// re-enrollment replaces a running login with the new SecretID.
pub(crate) fn start(
    r: &dyn Run,
    agent: &AgentId,
    pause: &mut dyn FnMut(Duration),
    write: impl FnOnce() -> Result<(), EnrollError>,
) -> Result<(), EnrollError> {
    write()?;
    unload(r, agent, pause)?;
    launchctl(r, &["enable", &target(agent)])?;
    let path = Path::new(DAEMON_DIR).join(plist_file(agent));
    launchctl(r, &["bootstrap", "system", &path.to_string_lossy()])
}

/// `remove` deletes the plist, once launchd no longer holds the job.
pub(crate) fn stop(
    r: &dyn Run,
    agent: &AgentId,
    pause: &mut dyn FnMut(Duration),
    remove: impl FnOnce() -> Result<(), EnrollError>,
) -> Result<(), EnrollError> {
    unload(r, agent, pause)?;
    remove()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]
    use super::super::agent_access::Ran;
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    fn hobi() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    const HOSTILE: &str = "a&b<c>d\"e'f";

    /// Answers `print` from a script: `true` loaded, `false` not; every other
    /// call succeeds unless it is `refuse`.
    #[derive(Default)]
    struct Launchd {
        log: RefCell<Vec<String>>,
        loaded: RefCell<VecDeque<bool>>,
        refuse: Option<&'static str>,
        print_code: Option<i32>,
    }

    impl Launchd {
        fn loaded(states: &[bool]) -> Self {
            Launchd {
                loaded: RefCell::new(states.iter().copied().collect()),
                ..Launchd::default()
            }
        }
    }

    impl Run for Launchd {
        fn run(&self, program: Program, args: &[String]) -> Result<Ran, String> {
            let line = format!("{program} {}", args.join(" "));
            self.log.borrow_mut().push(line.clone());
            let code = if args[0] == "print" {
                match self.print_code {
                    Some(c) => c,
                    None if self.loaded.borrow_mut().pop_front().unwrap_or(false) => 0,
                    None => NO_SUCH_SERVICE,
                }
            } else if self.refuse == Some(args[0].as_str()) {
                5
            } else {
                0
            };
            Ok(Ran {
                ok: code == 0,
                code: Some(code),
                stdout: String::new(),
                stderr: if code == 0 {
                    String::new()
                } else {
                    format!("{line} failed: {code}")
                },
            })
        }
    }

    fn integer(text: &str, key: &str) -> u64 {
        let after = text
            .split_once(&format!("<key>{key}</key>"))
            .unwrap_or_else(|| panic!("no {key}"))
            .1;
        let v = after
            .trim_start()
            .strip_prefix("<integer>")
            .and_then(|r| r.split_once("</integer>"))
            .unwrap_or_else(|| panic!("{key} is not followed by an integer"))
            .0;
        v.parse().unwrap()
    }

    #[test]
    fn the_job_is_named_for_the_agent() {
        assert_eq!(label(&hobi()), "io.maknae.maknae-agentd.hobi");
        assert_eq!(plist_file(&hobi()), "io.maknae.maknae-agentd.hobi.plist");
    }

    #[test]
    fn every_xml_special_character_is_escaped() {
        assert_eq!(xml_escape(HOSTILE), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
        assert_eq!(xml_escape("&amp;"), "&amp;amp;");
        assert_eq!(xml_escape("hobi-svc"), "hobi-svc");
    }

    #[test]
    fn the_plist_runs_the_agent_daemon_as_the_enrolled_account() {
        let p = plist(&hobi(), "hobi-svc");
        for placeholder in ["@AGENT_ID@", "@PROGRAM@", "@USER_NAME@", "@STDERR_PATH@"] {
            assert!(TEMPLATE.contains(placeholder) && !p.contains(placeholder));
        }
        for want in [
            "<key>Label</key>\n  <string>io.maknae.maknae-agentd.hobi</string>",
            "<key>ProgramArguments</key>\n  <array>\n    <string>/usr/local/bin/maknae-agentd</string>\n    <string>hobi</string>\n  </array>",
            "<key>UserName</key>\n  <string>hobi-svc</string>",
            "<key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>",
            "<key>RunAtLoad</key>\n  <true/>",
            "<key>ProcessType</key>\n  <string>Standard</string>",
            "<key>StandardErrorPath</key>\n  <string>/usr/local/var/log/maknae-agent/hobi/agentd.err</string>",
        ] {
            assert!(p.contains(want), "missing {want:?}");
        }
        assert_eq!(integer(&p, "ThrottleInterval"), 5);
        assert!(!p.contains("<key>EnvironmentVariables</key>"));
        assert!(!p.contains("<key>GroupName</key>"));
        assert!(!p.contains("<key>InitGroups</key>"));
    }

    /// The keychain item's `-T` trusts [`AGENT_BINARY`]; the job must run that file.
    #[test]
    fn the_job_runs_the_binary_the_keychain_item_trusts_and_the_package_installs() {
        assert!(plist(&hobi(), "x").contains(&format!("<string>{AGENT_BINARY}</string>")));
        let build = include_str!("../../../../packaging/macos/build-pkg.sh");
        assert!(build.contains(&format!("\"$D{AGENT_BINARY}\"")));
    }

    #[test]
    fn every_rendered_string_is_escaped() {
        let p = plist(&hobi(), HOSTILE);
        assert!(p.contains("<string>a&amp;b&lt;c&gt;d&quot;e&apos;f</string>"));
        assert!(!p.contains(HOSTILE));
        let p = render(&hobi(), "x", Path::new("/l/a&b<c>d\"e'f/hobi/agentd.err"));
        assert!(p.contains("<string>/l/a&amp;b&lt;c&gt;d&quot;e&apos;f/hobi/agentd.err</string>"));
        let p = plist(&hobi(), "@AGENT_ID@@PROGRAM@");
        assert!(p.contains("<string>@AGENT_ID@@PROGRAM@</string>"), "{p}");
    }

    #[test]
    fn the_unload_wait_outlasts_the_jobs_exit_timeout() {
        let exit = Duration::from_secs(integer(TEMPLATE, "ExitTimeOut"));
        assert!(UNLOAD_WAIT > exit);
        assert!(UNLOAD_WAIT <= exit + Duration::from_secs(10));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_rendered_plist_lints_and_reads_back_unescaped() {
        let (dir, _) = super::super::agent::tests::scratch_anchor("plist-lint");
        let file = dir.join(plist_file(&hobi()));
        std::fs::write(&file, plist(&hobi(), HOSTILE)).unwrap();
        let run = |args: &[&str]| {
            std::process::Command::new("/usr/bin/plutil")
                .args(args)
                .arg(&file)
                .output()
                .unwrap()
        };
        assert!(run(&["-lint"]).status.success());
        let user = run(&["-extract", "UserName", "raw", "-o", "-"]);
        assert_eq!(String::from_utf8(user.stdout).unwrap().trim_end(), HOSTILE);
        std::fs::write(
            &file,
            render(&hobi(), "x", Path::new("/l/a&b<c/agentd.err")),
        )
        .unwrap();
        assert!(run(&["-lint"]).status.success());
        let err = run(&["-extract", "StandardErrorPath", "raw", "-o", "-"]);
        assert_eq!(
            String::from_utf8(err.stdout).unwrap().trim_end(),
            "/l/a&b<c/agentd.err"
        );
        let exit = run(&["-extract", "ExitTimeOut", "raw", "-o", "-"]);
        assert_eq!(String::from_utf8(exit.stdout).unwrap().trim_end(), "181");
        assert!(
            !run(&["-extract", "EnvironmentVariables", "raw", "-o", "-"])
                .status
                .success()
        );
    }

    fn no_pause() -> impl FnMut(Duration) {
        |_| {}
    }

    #[test]
    fn start_writes_the_plist_enables_and_bootstraps_a_job_not_yet_loaded() {
        let r = Launchd::default();
        start(&r, &hobi(), &mut no_pause(), || {
            r.log.borrow_mut().push("write".into());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            *r.log.borrow(),
            [
                "write",
                "/bin/launchctl print system/io.maknae.maknae-agentd.hobi",
                "/bin/launchctl enable system/io.maknae.maknae-agentd.hobi",
                "/bin/launchctl bootstrap system /Library/LaunchDaemons/io.maknae.maknae-agentd.hobi.plist",
            ]
        );
    }

    /// A re-enrollment replaces the running login: the loaded job is booted
    /// out, and bootstrapped only once launchd no longer holds it.
    #[test]
    fn start_boots_out_a_loaded_job_and_waits_for_it_to_go() {
        let r = Launchd::loaded(&[true, true, true, false]);
        let mut waited = Duration::ZERO;
        start(&r, &hobi(), &mut |d| waited += d, || Ok(())).unwrap();
        assert_eq!(
            *r.log.borrow(),
            [
                "/bin/launchctl print system/io.maknae.maknae-agentd.hobi",
                "/bin/launchctl bootout system/io.maknae.maknae-agentd.hobi",
                "/bin/launchctl print system/io.maknae.maknae-agentd.hobi",
                "/bin/launchctl print system/io.maknae.maknae-agentd.hobi",
                "/bin/launchctl print system/io.maknae.maknae-agentd.hobi",
                "/bin/launchctl enable system/io.maknae.maknae-agentd.hobi",
                "/bin/launchctl bootstrap system /Library/LaunchDaemons/io.maknae.maknae-agentd.hobi.plist",
            ]
        );
        assert_eq!(waited, UNLOAD_POLL * 2);
    }

    #[test]
    fn a_job_that_never_unloads_is_refused_after_the_wait() {
        let r = Launchd::loaded(&[true; 1000]);
        let mut waited = Duration::ZERO;
        let e = start(&r, &hobi(), &mut |d| waited += d, || Ok(())).unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m.contains("io.maknae.maknae-agentd.hobi")),
            "{e:?}"
        );
        assert!(waited >= UNLOAD_WAIT && waited < UNLOAD_WAIT + UNLOAD_POLL);
        assert!(!r.log.borrow().iter().any(|l| l.contains("bootstrap")));
    }

    #[test]
    fn a_failed_write_or_call_stops_the_start_there() {
        let r = Launchd::default();
        let e = start(&r, &hobi(), &mut no_pause(), || {
            Err(EnrollError::State("write failed".into()))
        })
        .unwrap_err();
        assert!(matches!(e, EnrollError::State(m) if m == "write failed"));
        assert!(r.log.borrow().is_empty());

        let r = Launchd {
            refuse: Some("enable"),
            ..Launchd::default()
        };
        let e = start(&r, &hobi(), &mut no_pause(), || Ok(())).unwrap_err();
        assert!(
            matches!(&e, EnrollError::Command { program, detail }
                if program == "/bin/launchctl enable system/io.maknae.maknae-agentd.hobi"
                    && detail.contains("failed")),
            "{e:?}"
        );
        assert_eq!(r.log.borrow().len(), 2);
    }

    #[test]
    fn a_print_that_neither_finds_nor_misses_the_job_is_refused() {
        let r = Launchd {
            print_code: Some(1),
            ..Launchd::default()
        };
        let removed = std::cell::Cell::new(false);
        let e = stop(&r, &hobi(), &mut no_pause(), || {
            removed.set(true);
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(&e, EnrollError::Command { program, .. }
                if program == "/bin/launchctl print system/io.maknae.maknae-agentd.hobi"),
            "{e:?}"
        );
        assert!(!removed.get());
        let e = start(&r, &hobi(), &mut no_pause(), || Ok(())).unwrap_err();
        assert!(matches!(e, EnrollError::Command { .. }), "{e:?}");
    }

    #[test]
    fn stop_boots_out_the_job_before_removing_its_plist() {
        let r = Launchd::loaded(&[true, false]);
        stop(&r, &hobi(), &mut no_pause(), || {
            r.log.borrow_mut().push("remove".into());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            *r.log.borrow(),
            [
                "/bin/launchctl print system/io.maknae.maknae-agentd.hobi",
                "/bin/launchctl bootout system/io.maknae.maknae-agentd.hobi",
                "/bin/launchctl print system/io.maknae.maknae-agentd.hobi",
                "remove",
            ]
        );
    }

    #[test]
    fn stopping_a_job_launchd_does_not_hold_only_removes_its_plist() {
        let r = Launchd::default();
        stop(&r, &hobi(), &mut no_pause(), || {
            r.log.borrow_mut().push("remove".into());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            *r.log.borrow(),
            [
                "/bin/launchctl print system/io.maknae.maknae-agentd.hobi",
                "remove"
            ]
        );
    }

    #[test]
    fn a_refused_bootout_removes_nothing() {
        let r = Launchd {
            refuse: Some("bootout"),
            ..Launchd::loaded(&[true])
        };
        let removed = std::cell::Cell::new(false);
        let e = stop(&r, &hobi(), &mut no_pause(), || {
            removed.set(true);
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(&e, EnrollError::Command { program, .. }
                if program == "/bin/launchctl bootout system/io.maknae.maknae-agentd.hobi"),
            "{e:?}"
        );
        assert!(!removed.get());

        let r = Launchd::loaded(&[true; 1000]);
        let e = stop(&r, &hobi(), &mut no_pause(), || {
            removed.set(true);
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(e, EnrollError::State(_)), "{e:?}");
        assert!(!removed.get());
    }

    #[test]
    fn the_plist_is_written_mode_0644_to_the_owner_named() {
        use std::os::unix::fs::MetadataExt;
        let (dir, daemons) = super::super::agent::tests::scratch_anchor("write-plist");
        let me = FileOwner {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
        };
        write_plist(&daemons, &hobi(), HOSTILE, me).unwrap();
        let file = dir.join(plist_file(&hobi()));
        let meta = std::fs::metadata(&file).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o644);
        assert_eq!((meta.uid(), meta.gid()), (me.uid, me.gid));
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            plist(&hobi(), HOSTILE)
        );
        write_plist(&daemons, &hobi(), "hobi-svc", me).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            plist(&hobi(), "hobi-svc")
        );
    }

    #[test]
    fn removing_the_plist_unlinks_only_this_agents_and_a_missing_one_is_already_removed() {
        let (dir, daemons) = super::super::agent::tests::scratch_anchor("agent-plist");
        remove_plist(&daemons, &hobi()).unwrap();
        std::fs::write(dir.join(plist_file(&hobi())), plist(&hobi(), "x")).unwrap();
        std::fs::write(dir.join("io.maknae.maknaed.plist"), "").unwrap();
        remove_plist(&daemons, &hobi()).unwrap();
        assert!(!dir.join(plist_file(&hobi())).exists());
        assert!(dir.join("io.maknae.maknaed.plist").exists());
    }

    fn shell_function(script: &str, name: &str) -> String {
        let start = script
            .find(&format!("\n{name}() {{\n"))
            .unwrap_or_else(|| panic!("no {name}()"))
            + 1;
        let len = script[start..].find("\n}\n").unwrap() + 3;
        script[start..start + len].to_string()
    }

    struct Stub<'a> {
        services: &'a str,
        system_rc: i32,
        loaded: &'a [&'a str],
        print_rc: i32,
        kick_rc: i32,
    }

    const STUB: Stub = Stub {
        services: "",
        system_rc: 0,
        loaded: &[],
        print_rc: NO_SUCH_SERVICE,
        kick_rc: 0,
    };

    /// Runs `name` from a packaging script on `plists` (a LaunchDaemons stand-in)
    /// against a `launchctl` stub that logs each call.
    fn run_shell(script: &str, name: &str, plists: &[&str], stub: &Stub) -> (String, i32, String) {
        static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (dir, _) = super::super::agent::tests::scratch_anchor(&format!("sh-{name}-{n}"));
        let daemons = dir.join("LaunchDaemons");
        std::fs::create_dir(&daemons).unwrap();
        for p in plists {
            std::fs::write(daemons.join(p), "").unwrap();
        }
        let log = dir.join("launchctl.log");
        let program = format!(
            r#"set -euo pipefail
launchctl() {{
    echo "$*" >> "$2"
    case "$1" in
        print)
            if [ "$2" = system ]; then printf '%s\n' '{services}'; return {system_rc}; fi
            for l in {loaded}; do [ "$2" = "system/$l" ] && return 0; done
            return {print_rc} ;;
        kickstart) return {kick_rc} ;;
    esac
}}
{function}
{name} "$1"
"#,
            services = stub.services,
            system_rc = stub.system_rc,
            loaded = stub.loaded.join(" "),
            print_rc = stub.print_rc,
            kick_rc = stub.kick_rc,
            function = shell_function(script, name),
        );
        let program = program.replace(r#">> "$2""#, &format!(">> '{}'", log.display()));
        let out = std::process::Command::new("/bin/bash")
            .arg("-c")
            .arg(program)
            .arg("sh")
            .arg(&daemons)
            .output()
            .unwrap();
        (
            String::from_utf8(out.stdout).unwrap(),
            out.status.code().unwrap(),
            std::fs::read_to_string(&log).unwrap_or_default(),
        )
    }

    const UNINSTALL: &str = include_str!("../../../../packaging/macos/uninstall.sh");
    const POSTINSTALL: &str = include_str!("../../../../packaging/macos/scripts/postinstall");

    #[test]
    fn uninstall_finds_every_agent_job_on_disk_or_loaded_and_nothing_else() {
        let services = "\t     834      - \tio.maknae.maknae-agentd.orphan\n\t     949      1 \tio.maknae.maknaed\n\t     12      - \tio.maknae.maknae-agentd.hobi";
        let (out, rc, _) = run_shell(
            UNINSTALL,
            "agent_labels",
            &[
                "io.maknae.maknae-agentd.hobi.plist",
                "io.maknae.maknae-agentd.jin.plist",
                "io.maknae.maknae-agentd..x.plist",
                "io.maknae.maknae-agentd.A.plist",
                "io.maknae.maknaed.plist",
            ],
            &Stub { services, ..STUB },
        );
        assert_eq!(rc, 0);
        assert_eq!(
            out,
            "io.maknae.maknae-agentd.hobi\nio.maknae.maknae-agentd.jin\nio.maknae.maknae-agentd.orphan\n"
        );
        let (out, rc, _) = run_shell(UNINSTALL, "agent_labels", &[], &STUB);
        assert_eq!((out.as_str(), rc), ("", 0));
    }

    #[test]
    fn uninstall_refuses_when_it_cannot_list_launchds_services() {
        let (_, rc, _) = run_shell(
            UNINSTALL,
            "agent_labels",
            &["io.maknae.maknae-agentd.hobi.plist"],
            &Stub {
                system_rc: 1,
                ..STUB
            },
        );
        assert_ne!(rc, 0);
        assert!(UNINSTALL.contains("AGENT_LABELS=\"$(agent_labels /Library/LaunchDaemons)\" || {"));
        assert!(UNINSTALL.contains(
            "for LABEL in $AGENT_LABELS io.maknae.policy-sync io.maknae.maknaed io.maknae.maknae-egress; do\n    rc=\"$(print_rc"
        ));
    }

    #[test]
    fn postinstall_restarts_each_loaded_agent_and_disables_none() {
        let plists = [
            "io.maknae.maknae-agentd.gone.plist",
            "io.maknae.maknae-agentd.hobi.plist",
        ];
        let (_, rc, log) = run_shell(
            POSTINSTALL,
            "restart_agents",
            &plists,
            &Stub {
                loaded: &["io.maknae.maknae-agentd.hobi"],
                ..STUB
            },
        );
        assert_eq!(rc, 0);
        assert_eq!(
            log,
            "print system/io.maknae.maknae-agentd.gone\nprint system/io.maknae.maknae-agentd.hobi\nkickstart -k system/io.maknae.maknae-agentd.hobi\n"
        );
        assert!(!POSTINSTALL.contains("io.maknae.maknae-agentd\""));
        assert!(POSTINSTALL.contains("\nrestart_agents /Library/LaunchDaemons || exit 1\n"));

        for stub in [
            Stub {
                print_rc: 1,
                ..STUB
            },
            Stub {
                loaded: &["io.maknae.maknae-agentd.hobi"],
                kick_rc: 1,
                ..STUB
            },
        ] {
            let (_, rc, _) = run_shell(POSTINSTALL, "restart_agents", &plists, &stub);
            assert_ne!(rc, 0);
        }
        let (_, rc, log) = run_shell(POSTINSTALL, "restart_agents", &[], &STUB);
        assert_eq!((rc, log.as_str()), (0, ""));
    }

    #[test]
    fn the_agents_stderr_lands_in_its_own_log_directory() {
        assert_eq!(
            stderr_path(Path::new(LOG_ROOT), &hobi()),
            Path::new("/usr/local/var/log/maknae-agent/hobi/agentd.err")
        );
    }

    fn me() -> FileOwner {
        FileOwner {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
        }
    }

    #[test]
    fn the_log_directory_is_made_root_0755_then_the_accounts_0750() {
        use std::os::unix::fs::MetadataExt;
        let (dir, _) = super::super::agent::tests::scratch_anchor("log-dir");
        let root = dir.join("log/maknae-agent");
        for _ in 0..2 {
            ensure_log_dir(&root, &hobi(), me(), me()).unwrap();
            for (path, mode) in [(root.clone(), 0o755), (root.join("hobi"), 0o750)] {
                let meta = std::fs::symlink_metadata(&path).unwrap();
                assert!(meta.is_dir(), "{path:?}");
                assert_eq!(meta.mode() & 0o7777, mode, "{path:?}");
                assert_eq!((meta.uid(), meta.gid()), (me().uid, me().gid));
            }
        }
        std::fs::write(root.join("hobi/agentd.err"), "kept").unwrap();
        ensure_log_dir(&root, &hobi(), me(), me()).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("hobi/agentd.err")).unwrap(),
            "kept"
        );
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.join("hobi"), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        ensure_log_dir(&root, &hobi(), me(), me()).unwrap();
        assert!(!root.join("hobi/agentd.err").exists());
        let meta = std::fs::symlink_metadata(root.join("hobi")).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o750);
    }

    #[test]
    fn removing_the_log_directory_unlinks_what_the_agent_planted_and_nothing_it_names() {
        let (dir, _) = super::super::agent::tests::scratch_anchor("log-rm");
        let root = dir.join("maknae-agent");
        remove_log_dir(&root, &hobi()).unwrap();
        ensure_log_dir(&root, &hobi(), me(), me()).unwrap();
        ensure_log_dir(&root, &AgentId::parse("jin").unwrap(), me(), me()).unwrap();
        remove_log_dir(&root, &hobi()).unwrap();
        assert!(!root.join("hobi").exists());
        ensure_log_dir(&root, &hobi(), me(), me()).unwrap();
        let outside = dir.join("outside");
        std::fs::write(&outside, "x").unwrap();
        std::fs::write(root.join("hobi/agentd.err"), "e").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("hobi/link")).unwrap();
        remove_log_dir(&root, &hobi()).unwrap();
        assert!(!root.join("hobi").exists());
        assert!(root.join("jin").is_dir());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "x");
        remove_log_dir(&root, &hobi()).unwrap();
    }

    #[test]
    fn uninstall_removes_every_agents_log_directory() {
        assert!(UNINSTALL
            .lines()
            .any(|l| l.starts_with("rm -rf ") && l.split(' ').any(|w| w == LOG_ROOT)));
    }

    #[test]
    fn uninstalls_agent_wait_is_the_unload_wait() {
        let polls: Vec<u32> = UNINSTALL
            .lines()
            .filter_map(|l| {
                l.trim()
                    .strip_prefix("case \"$LABEL\" in io.maknae.maknae-agentd.*) polls=")
            })
            .map(|r| {
                r.split_once(' ')
                    .unwrap()
                    .0
                    .trim_end_matches(';')
                    .parse()
                    .unwrap()
            })
            .collect();
        assert_eq!(polls.len(), 1, "{polls:?}");
        assert!(UNINSTALL.contains("        sleep 0.5\n"));
        assert_eq!(UNLOAD_POLL, Duration::from_millis(500));
        assert_eq!(UNLOAD_POLL * polls[0], UNLOAD_WAIT);
    }
}
