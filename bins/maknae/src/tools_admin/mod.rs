mod available;
mod dirs;
mod disable;
mod enable;
mod inventory;
mod template;
mod test_support;

use crate::cli::{terminal_safe, ToolsCommand};
use crate::enroll::{Host, Platform, Ran, Run};
use crate::policy_sync::{kernel_gid, CONFIG_DIR, RELOAD};
use crate::tools_admin::available::available;
use crate::tools_admin::disable::disable;
use crate::tools_admin::enable::{enable, Enable};
use maknae_config::{
    tool_entry_name_ok, tool_program_name_ok, VENDOR_GRAMMAR_DIR, VENDOR_TOOLS_DIR,
};
use maknae_io::program::Program;
use maknae_io::FileOwner;
use std::io::Write;
use std::path::PathBuf;

pub(crate) struct Paths {
    pub config: PathBuf,
    pub vendor_grammars: PathBuf,
    pub vendor_templates: PathBuf,
}

pub(crate) struct Owners {
    pub dir: u32,
    pub file: FileOwner,
}

pub(crate) trait Reload {
    fn reload(&self) -> Result<(), String>;
}

fn say(out: &mut dyn Write, line: &str) -> Result<(), String> {
    writeln!(out, "{}", terminal_safe(line))
        .map_err(|e| format!("cannot write to standard output: {e}"))
}

fn program_ok(program: &str) -> Result<(), String> {
    if tool_program_name_ok(program) {
        Ok(())
    } else {
        Err(format!(
            "`{}` is not a tool program name",
            terminal_safe(program)
        ))
    }
}

fn entry_ok(entry: &str) -> Result<(), String> {
    if tool_entry_name_ok(entry) {
        Ok(())
    } else {
        Err(format!(
            "`{}` is not a tool entry name",
            terminal_safe(entry)
        ))
    }
}

fn requested(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux => "requested a reload of maknaed; if it refuses the new files it keeps the previous policy, and `sudo journalctl -u maknaed` says `maknaed: reload refused: <cause>`",
        Platform::Macos => "requested a reload of maknaed; if it refuses the new files it keeps the previous policy, and /usr/local/var/log/maknae/maknaed.err says `maknaed: reload refused: <cause>`",
    }
}

struct Committed {
    done: Vec<String>,
    lines: Vec<String>,
    notes: Vec<String>,
}

fn report(c: Committed, reload: bool, r: &dyn Reload, out: &mut dyn Write) -> Result<(), String> {
    let mut printed = c.lines.iter().try_for_each(|line| say(out, line));
    let state = if reload {
        r.reload().map(|()| requested(Platform::HOST))
    } else {
        Ok(RELOAD)
    };
    if let (Ok(()), Ok(line)) = (&printed, &state) {
        printed = say(out, line);
    }
    if printed.is_ok() && state.is_ok() && c.notes.is_empty() {
        return Ok(());
    }
    let mut parts = c.done;
    parts.push(match state {
        Ok(line) => line.to_string(),
        Err(cause) => format!("maknaed was not reloaded: {cause}; {RELOAD}"),
    });
    parts.extend(printed.err());
    parts.extend(c.notes);
    Err(terminal_safe(&parts.join("; ")))
}

fn preflight(euid: u32, sub: &str) -> Result<(), String> {
    if euid == 0 {
        Ok(())
    } else {
        Err(format!(
            "maknae tools {sub} must run as root: run `sudo maknae tools {sub}`"
        ))
    }
}

fn reload_call(platform: Platform) -> (Program, Vec<String>) {
    let (program, args): (Program, &[&str]) = match platform {
        Platform::Linux => (Program::Systemctl, &["reload", "maknaed"]),
        Platform::Macos => (
            Program::Launchctl,
            &["kill", "SIGHUP", "system/io.maknae.maknaed"],
        ),
    };
    (program, args.iter().map(|a| (*a).to_string()).collect())
}

struct HostReload<'a>(&'a dyn Run);

impl Reload for HostReload<'_> {
    fn reload(&self) -> Result<(), String> {
        let (program, args) = reload_call(Platform::HOST);
        let ran: Ran = self.0.run(program, &args)?;
        let stderr = ran.stderr.trim();
        match (ran.ok, ran.code) {
            (true, _) => Ok(()),
            (false, _) if !stderr.is_empty() => Err(stderr.to_string()),
            (false, Some(code)) => Err(format!("the reload exited with status {code}")),
            (false, None) => Err("the reload was ended by a signal".to_string()),
        }
    }
}

fn production_paths() -> Paths {
    Paths {
        config: PathBuf::from(CONFIG_DIR),
        vendor_grammars: PathBuf::from(VENDOR_GRAMMAR_DIR),
        vendor_templates: PathBuf::from(VENDOR_TOOLS_DIR),
    }
}

fn production_owners(kernel_gid: u32) -> Owners {
    Owners {
        dir: 0,
        file: FileOwner {
            uid: 0,
            gid: kernel_gid,
        },
    }
}

fn sub_name(cmd: &ToolsCommand) -> &'static str {
    match cmd {
        ToolsCommand::Available => "available",
        ToolsCommand::Enable { .. } => "enable",
        ToolsCommand::Disable { .. } => "disable",
    }
}

fn dispatch(
    cmd: ToolsCommand,
    p: &Paths,
    o: &Owners,
    r: &dyn Reload,
    out: &mut dyn Write,
) -> Result<(), String> {
    match cmd {
        ToolsCommand::Available => available(p, o, out),
        ToolsCommand::Enable {
            program,
            image,
            shapes,
            entry,
            no_reload,
        } => {
            let req = Enable {
                program,
                image,
                shapes,
                entry,
                reload: !no_reload,
            };
            enable(p, o, &req, r, out)
        }
        ToolsCommand::Disable { entry, no_reload } => disable(p, o, &entry, !no_reload, r, out),
    }
}

fn production(euid: u32, cmd: ToolsCommand, out: &mut dyn Write) -> Result<(), String> {
    preflight(euid, sub_name(&cmd))?;
    let o = production_owners(kernel_gid()?);
    dispatch(cmd, &production_paths(), &o, &HostReload(&Host), out)
}

fn finish_run(result: Result<(), String>, err: &mut dyn Write) -> u8 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(err, "maknae: {}", terminal_safe(&e));
            1
        }
    }
}

pub(crate) fn run_with(
    euid: u32,
    cmd: ToolsCommand,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    finish_run(production(euid, cmd, out), err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools_admin::test_support::{
        disable_run, enable_cmd, err, me, plan, ran, req, run_as, spawn, Broken, Fail, FakeReload,
        Fx, Plan,
    };
    use std::path::Path;

    #[test]
    fn operands_are_checked() {
        let fx = Fx::new();
        let r = FakeReload::ok();
        let mut bad = req(None, None);
        bad.program = "../x".to_string();
        let e = err(fx.enable(&bad, &r).0);
        assert!(e.contains("`../x`"), "{e}");
        let e = err(fx.enable(&req(Some("a/b"), None), &r).0);
        assert!(e.contains("`a/b`"), "{e}");
        let e = err(fx.disable("sub/x", &r).0);
        assert!(e.contains("`sub/x`"), "{e}");
        assert!(fx.dropins().is_empty());
        assert_eq!(fx.link(), None);
        assert_eq!(r.calls.get(), 0);
    }

    #[test]
    fn enable_reloads_and_reports_when_stdout_fails() {
        let fx = Fx::new();
        let r = FakeReload::ok();
        let e = err(enable(
            &fx.paths(),
            &me(),
            &req(Some("github-post"), None),
            &r,
            &mut Broken,
        ));
        let wrote = fx.tools().join("github-post.yaml");
        assert_eq!(
            e,
            format!(
                "wrote {}; linked {} to {}; {}; cannot write to standard output: {}",
                wrote.display(),
                fx.grammars().join("gh.yaml").display(),
                fx.vendor_grammars().join("gh.yaml").display(),
                requested(Platform::HOST),
                std::io::Error::from(std::io::ErrorKind::BrokenPipe)
            )
        );
        assert_eq!(r.calls.get(), 1);
        assert_eq!(fx.dropins(), ["github-post.yaml"]);
        assert_eq!(fx.link(), fx.exact());

        let mut no = req(Some("github-read"), None);
        no.reload = false;
        let e = err(enable(&fx.paths(), &me(), &no, &r, &mut Broken));
        assert!(
            e.starts_with(&format!(
                "wrote {}; {RELOAD}; cannot write to standard output",
                fx.tools().join("github-read.yaml").display()
            )),
            "{e}"
        );
        assert_eq!(r.calls.get(), 1);
    }

    #[test]
    fn disable_reloads_and_reports_when_stdout_fails() {
        let fx = Fx::new();
        fx.enabled_one("github-post");
        let r = FakeReload::ok();
        let e = err(disable(
            &fx.paths(),
            &me(),
            "github-post",
            true,
            &r,
            &mut Broken,
        ));
        assert!(
            e.starts_with(&format!(
                "removed {}; removed {}; {}; cannot write to standard output",
                fx.tools().join("github-post.yaml").display(),
                fx.grammars().join("gh.yaml").display(),
                requested(Platform::HOST)
            )),
            "{e}"
        );
        assert_eq!(r.calls.get(), 1);
        assert!(fx.dropins().is_empty());
        assert_eq!(fx.link(), None);
    }

    #[test]
    fn disable_reloads_and_reports_a_link_it_cannot_remove() {
        let fx = Fx::new();
        fx.enabled_one("github-post");
        let r = FakeReload::ok();
        let stuck = Plan {
            link_removes: Fail::NotDone,
            ..plan()
        };
        let (result, out) = disable_run(&fx, "github-post", &r, stuck);
        let link = fx.grammars().join("gh.yaml");
        let dropin = fx.tools().join("github-post.yaml");
        assert_eq!(
            err(result),
            format!(
                "removed {}; {}; cannot remove {}: disk full; the link remains and disable cannot be run again for it: sudo rm {}",
                dropin.display(),
                requested(Platform::HOST),
                link.display(),
                link.display()
            )
        );
        assert_eq!(r.calls.get(), 1);
        assert!(fx.dropins().is_empty());
        assert_eq!(fx.link(), fx.exact());
        assert_eq!(
            out,
            format!(
                "removed {}\n{}\n",
                dropin.display(),
                requested(Platform::HOST)
            )
        );

        fx.enabled_one("github-post");
        let unsynced = Plan {
            link_removes: Fail::DoneNotDurable,
            ..plan()
        };
        let e = err(disable_run(&fx, "github-post", &r, unsynced).0);
        assert_eq!(
            e,
            format!(
                "removed {}; removed {}; {}; the removal is not yet durable: sync failed",
                dropin.display(),
                link.display(),
                requested(Platform::HOST)
            )
        );
        assert_eq!(fx.link(), None);
    }

    #[test]
    fn requested_names_where_a_refused_reload_is_reported() {
        assert_eq!(
            requested(Platform::Linux),
            "requested a reload of maknaed; if it refuses the new files it keeps the previous policy, and `sudo journalctl -u maknaed` says `maknaed: reload refused: <cause>`"
        );
        assert_eq!(
            requested(Platform::Macos),
            "requested a reload of maknaed; if it refuses the new files it keeps the previous policy, and /usr/local/var/log/maknae/maknaed.err says `maknaed: reload refused: <cause>`"
        );
    }

    #[test]
    fn enable_with_no_reload_prints_the_command() {
        let fx = Fx::new();
        let r = FakeReload::ok();
        let mut no = req(None, None);
        no.reload = false;
        let (result, out) = fx.enable(&no, &r);
        result.unwrap();
        assert_eq!(r.calls.get(), 0);
        assert!(out.contains(RELOAD), "{out}");
        assert!(!out.contains("requested a reload"), "{out}");

        let mut out = Vec::new();
        disable(&fx.paths(), &me(), "github-post", false, &r, &mut out).unwrap();
        assert_eq!(r.calls.get(), 0);
        assert!(String::from_utf8(out).unwrap().contains(RELOAD));
    }

    #[test]
    fn a_failed_reload_reports_files_in_place() {
        let fx = Fx::new();
        let r = FakeReload::failing();
        let e = err(fx.enable(&req(Some("github-post"), None), &r).0);
        assert!(e.contains("maknaed was not reloaded"), "{e}");
        assert!(e.contains("unit maknaed not loaded"), "{e}");
        assert!(e.contains(RELOAD), "{e}");
        let wrote = fx.tools().join("github-post.yaml");
        assert!(e.contains(&format!("wrote {}", wrote.display())), "{e}");
        assert!(wrote.exists());
        assert_eq!(fx.link(), fx.exact());
        assert_eq!(r.calls.get(), 1);

        let e = err(fx.disable("github-post", &r).0);
        assert!(e.contains("maknaed was not reloaded"), "{e}");
        assert!(e.contains(&format!("removed {}", wrote.display())), "{e}");
        assert!(!wrote.exists());
    }

    #[test]
    fn run_refuses_unless_root() {
        let disable = || ToolsCommand::Disable {
            entry: "x".into(),
            no_reload: true,
        };
        let enable = || ToolsCommand::Enable {
            program: "gh".into(),
            image: "i".into(),
            shapes: None,
            entry: None,
            no_reload: true,
        };
        for (cmd, sub) in [
            (ToolsCommand::Available, "available"),
            (enable(), "enable"),
            (disable(), "disable"),
        ] {
            let (code, err) = run_as(1000, cmd);
            assert_eq!(code, 1);
            assert_eq!(
                err,
                format!(
                    "maknae: maknae tools {sub} must run as root: run `sudo maknae tools {sub}`\n"
                )
            );
        }
    }

    #[test]
    fn run_reports_a_refusal_as_exit_one() {
        let (code, err) = run_as(
            0,
            ToolsCommand::Enable {
                program: "Bad Name".into(),
                image: "i".into(),
                shapes: None,
                entry: None,
                no_reload: true,
            },
        );
        assert_eq!(code, 1);
        assert!(err.starts_with("maknae: "), "{err}");
    }

    #[test]
    fn finish_maps_success_and_failure() {
        let mut err = Vec::new();
        assert_eq!(finish_run(Ok(()), &mut err), 0);
        assert!(err.is_empty());
        assert_eq!(finish_run(Err("bad\x1b[31m".into()), &mut err), 1);
        let text = String::from_utf8(err).unwrap();
        assert!(text.starts_with("maknae: bad"), "{text}");
        assert!(!text.contains('\x1b'), "{text:?}");
    }

    #[test]
    fn reload_call_names_each_platform_command() {
        assert_eq!(
            reload_call(Platform::Linux),
            (Program::Systemctl, vec!["reload".into(), "maknaed".into()])
        );
        assert_eq!(
            reload_call(Platform::Macos),
            (
                Program::Launchctl,
                vec![
                    "kill".into(),
                    "SIGHUP".into(),
                    "system/io.maknae.maknaed".into()
                ]
            )
        );
    }

    #[test]
    fn host_reload_runs_the_host_call_and_reports_stderr() {
        let ok = spawn(Ok(ran(true, "")));
        assert_eq!(HostReload(&ok).reload(), Ok(()));
        let (program, args) = reload_call(Platform::HOST);
        assert_eq!(*ok.ran.borrow(), vec![(program, args)]);

        let failed = spawn(Ok(ran(false, "Unit maknaed.service not loaded.")));
        assert_eq!(
            HostReload(&failed).reload(),
            Err("Unit maknaed.service not loaded.".to_string())
        );

        for stderr in ["", " \n"] {
            let silent = spawn(Ok(ran(false, stderr)));
            assert_eq!(
                HostReload(&silent).reload(),
                Err("the reload exited with status 1".to_string())
            );
        }
        let signalled = spawn(Ok(Ran {
            code: None,
            ..ran(false, "")
        }));
        assert_eq!(
            HostReload(&signalled).reload(),
            Err("the reload was ended by a signal".to_string())
        );

        let missing = spawn(Err("/usr/bin/systemctl not found".into()));
        assert_eq!(
            HostReload(&missing).reload(),
            Err("/usr/bin/systemctl not found".to_string())
        );
    }

    #[test]
    fn production_paths_and_owners_are_the_installed_ones() {
        let p = production_paths();
        assert_eq!(p.config, Path::new("/etc/maknae"));
        assert_eq!(p.vendor_grammars, Path::new(VENDOR_GRAMMAR_DIR));
        assert_eq!(p.vendor_templates, Path::new(VENDOR_TOOLS_DIR));
        let o = production_owners(77);
        assert_eq!(o.dir, 0);
        assert_eq!(o.file.uid, 0);
        assert_eq!(o.file.gid, 77);
    }

    #[test]
    fn dispatch_reloads_unless_no_reload() {
        for (no_reload, calls) in [(true, 0), (false, 1)] {
            let fx = Fx::new();
            let r = FakeReload::ok();
            let mut out = Vec::new();
            dispatch(enable_cmd(no_reload), &fx.paths(), &me(), &r, &mut out).unwrap();
            assert_eq!(r.calls.get(), calls, "enable no_reload={no_reload}");

            let r = FakeReload::ok();
            let cmd = ToolsCommand::Disable {
                entry: "github-post".into(),
                no_reload,
            };
            dispatch(cmd, &fx.paths(), &me(), &r, &mut out).unwrap();
            assert_eq!(r.calls.get(), calls, "disable no_reload={no_reload}");
        }
    }

    #[test]
    fn dispatch_available_lists_the_grammars() {
        let fx = Fx::new();
        let mut out = Vec::new();
        dispatch(
            ToolsCommand::Available,
            &fx.paths(),
            &me(),
            &FakeReload::ok(),
            &mut out,
        )
        .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), fx.available());
    }
}
