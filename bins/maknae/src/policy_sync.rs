use crate::cli::terminal_safe;
use maknae_config::{
    check_roles, parse_bindings, parse_mirror, plan_sync, Bindings, Mirror, Section, SyncPlan,
    BINDINGS_FILE, MIRROR_FILE, MIRROR_MAX_BYTES, STATE_DIR,
};
use maknae_io::{
    open_anchor, open_anchor_resolved, Anchor, AnchorRequired, FileOwner, IoError, IoKind, Mode,
    StrategyPref, TargetRequired,
};
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::process::ExitCode;

pub(crate) const CONFIG_DIR: &str = "/etc/maknae";

const NO_MIRROR: &str = "maknaed has published no mirror (its last render failed: see maknae status); nothing was installed";

#[cfg(target_os = "macos")]
const RELOAD: &str =
    "reload maknaed to adopt it: sudo launchctl kill SIGHUP system/io.maknae.maknaed";
#[cfg(not(target_os = "macos"))]
const RELOAD: &str = "reload maknaed to adopt it: sudo systemctl reload maknaed";

const ANSWER_MAX_BYTES: u64 = 64;

pub(crate) struct Owners {
    pub state_dir: u32,
    pub config_dir: u32,
    pub file: FileOwner,
}

#[derive(Debug)]
pub(crate) enum Outcome {
    Installed,
    NothingToInstall,
    WouldInstall,
}

fn preflight(euid: u32) -> Result<(), String> {
    if euid == 0 {
        Ok(())
    } else {
        Err("maknae policy sync must run as root: run `sudo maknae policy sync`".into())
    }
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b).as_ref());
    out
}

fn say(out: &mut dyn Write, line: &str) -> Result<(), String> {
    writeln!(out, "{line}").map_err(|e| format!("cannot write to standard output: {e}"))
}

fn read_mirror(state_dir: &Path, owner: u32) -> Result<Mirror, String> {
    let at = state_dir.join(MIRROR_FILE);
    let anchor = open_anchor(
        state_dir,
        AnchorRequired {
            owner: Some(owner),
            mode_mask: Some(0o077),
        },
        StrategyPref::Auto,
    )
    .map_err(|e| {
        format!(
            "cannot use the state directory {}: {e}",
            state_dir.display()
        )
    })?;
    let required = TargetRequired {
        owner: Some(owner),
        mode_mask: Some(0o077),
        nlink_exactly_one: true,
        regular_file: true,
        max_bytes: Some(MIRROR_MAX_BYTES),
    };
    let bytes = match anchor.read(Path::new(MIRROR_FILE), None, required) {
        Ok(o) => o.value,
        Err(IoError::Io {
            kind: IoKind::NotFound,
            ..
        }) => return Err(NO_MIRROR.into()),
        Err(e) => return Err(format!("cannot read the mirror {}: {e}", at.display())),
    };
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "the mirror is not valid: not UTF-8".to_string())?;
    parse_mirror(text).map_err(|e| format!("the mirror is not valid: {e}"))
}

fn read_bindings(etc: &Anchor, config_dir: &Path, owner: u32) -> Result<Bindings, String> {
    let required = TargetRequired {
        owner: Some(owner),
        mode_mask: Some(0o027),
        nlink_exactly_one: true,
        regular_file: true,
        max_bytes: Some(MIRROR_MAX_BYTES),
    };
    let bytes = match etc.read(Path::new(BINDINGS_FILE), None, required) {
        Ok(o) => o.value,
        Err(IoError::Io {
            kind: IoKind::NotFound,
            ..
        }) => return Ok(Bindings::missing()),
        Err(e) => {
            return Err(format!(
                "cannot read {}: {e}",
                config_dir.join(BINDINGS_FILE).display()
            ))
        }
    };
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "bindings.yaml is not valid: not UTF-8".to_string())?;
    let bindings = parse_bindings(text).map_err(|e| format!("bindings.yaml is not valid: {e}"))?;
    check_roles(&bindings).map_err(|e| format!("bindings.yaml is not valid: {e}"))?;
    Ok(bindings)
}

fn install(etc: &Anchor, config_dir: &Path, bytes: &[u8], owner: FileOwner) -> Result<(), String> {
    etc.publish_owned(Path::new(BINDINGS_FILE), None, bytes, Mode(0o640), owner)
        .map(|_| ())
        .map_err(|e| {
            format!(
                "cannot install {}: {e}",
                config_dir.join(BINDINGS_FILE).display()
            )
        })
}

fn confirm(
    conflicts: usize,
    answer: &mut dyn BufRead,
    terminal: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    if !terminal {
        return Err(format!(
            "the mirror lists {conflicts} conflicts; run sudo maknae policy sync on a terminal to review them"
        ));
    }
    write!(
        out,
        "install bindings.yaml with these entries as the mirror holds them? [y/N] "
    )
    .and_then(|()| out.flush())
    .map_err(|e| format!("cannot write to standard output: {e}"))?;
    let mut line = String::new();
    answer
        .take(ANSWER_MAX_BYTES)
        .read_line(&mut line)
        .map_err(|e| format!("cannot read the answer: {e}"))?;
    let line = line.trim();
    if line.eq_ignore_ascii_case("y") || line.eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err("not installed: the conflicts were not accepted".into())
    }
}

pub(crate) fn sync(
    state_dir: &Path,
    config_dir: &Path,
    owners: Owners,
    check: bool,
    answer: &mut dyn BufRead,
    terminal: bool,
    out: &mut dyn Write,
) -> Result<Outcome, String> {
    let mirror = read_mirror(state_dir, owners.state_dir)?;
    let etc = open_anchor_resolved(
        config_dir,
        AnchorRequired {
            owner: Some(owners.config_dir),
            mode_mask: Some(0o022),
        },
        StrategyPref::Auto,
    )
    .map_err(|e| format!("cannot use {}: {e}", config_dir.display()))?;
    let file = read_bindings(&etc, config_dir, owners.config_dir)?;
    let revision = mirror.header.revision;
    match plan_sync(&mirror, &Section::of(&file), sha256, CONFIG_DIR) {
        SyncPlan::OtherConfigDir { found } => Err(format!(
            "maknaed reads its configuration from {}, not {CONFIG_DIR}; policy sync installs only {CONFIG_DIR}/{BINDINGS_FILE}",
            terminal_safe(&found)
        )),
        SyncPlan::NothingToInstall => {
            say(out, "bindings.yaml already holds the mirror; nothing to install")?;
            Ok(Outcome::NothingToInstall)
        }
        SyncPlan::BaseChanged { .. } => Err(
            "bindings.yaml changed since maknaed last loaded it; reload maknaed so it merges, then sync again"
                .into(),
        ),
        SyncPlan::Restore {
            diff,
            conflicts,
            bytes,
        } => {
            say(
                out,
                "restoring bindings.yaml, which is missing or has no bindings: key, from the bindings maknaed enforces",
            )?;
            for l in &diff {
                say(out, &terminal_safe(l))?;
            }
            for c in &conflicts {
                say(
                    out,
                    &format!(
                        "  conflict (installed as maknaed enforces it): {}",
                        terminal_safe(&c.render())
                    ),
                )?;
            }
            if check {
                return Ok(Outcome::WouldInstall);
            }
            install(&etc, config_dir, bytes.as_bytes(), owners.file)?;
            say(
                out,
                &format!(
                    "restored {}/{BINDINGS_FILE} from the mirror at revision {revision}; {RELOAD}",
                    config_dir.display()
                ),
            )?;
            Ok(Outcome::Installed)
        }
        SyncPlan::Install {
            diff,
            conflicts,
            bytes,
        } => {
            for l in &diff {
                say(out, &terminal_safe(l))?;
            }
            if !conflicts.is_empty() {
                say(
                    out,
                    "the mirror fails these entries closed (contained, or unbound when neither side contained them):",
                )?;
                for c in &conflicts {
                    say(out, &format!("  conflict: {}", terminal_safe(&c.render())))?;
                }
            }
            if check {
                return Ok(Outcome::WouldInstall);
            }
            if !conflicts.is_empty() {
                confirm(conflicts.len(), answer, terminal, out)?;
            }
            install(&etc, config_dir, bytes.as_bytes(), owners.file)?;
            say(
                out,
                &format!(
                    "installed {}/{BINDINGS_FILE} from the mirror at revision {revision}; {RELOAD}",
                    config_dir.display()
                ),
            )?;
            Ok(Outcome::Installed)
        }
    }
}

fn exit_code(r: &Result<Outcome, String>) -> u8 {
    match r {
        Ok(Outcome::Installed) => 0,
        Ok(Outcome::WouldInstall) => 1,
        Err(_) => 2,
        Ok(Outcome::NothingToInstall) => 3,
    }
}

fn kernel_gid() -> Result<u32, String> {
    nix::unistd::Group::from_name("_maknae")
        .map_err(|e| format!("group _maknae: {e}"))?
        .map(|g| g.gid.as_raw())
        .ok_or_else(|| "no such group: _maknae; is maknae installed?".to_string())
}

fn production(euid: u32, check: bool) -> Result<Outcome, String> {
    preflight(euid)?;
    let owners = Owners {
        state_dir: crate::reseed::kernel_uid()?,
        config_dir: 0,
        file: FileOwner {
            uid: 0,
            gid: kernel_gid()?,
        },
    };
    let stdin = std::io::stdin();
    sync(
        Path::new(STATE_DIR),
        Path::new(CONFIG_DIR),
        owners,
        check,
        &mut stdin.lock(),
        crate::tty::stdin_is_terminal(),
        &mut std::io::stdout(),
    )
}

pub(crate) fn run(euid: u32, check: bool) -> ExitCode {
    let r = production(euid, check);
    if let Err(e) = &r {
        eprintln!("maknae: {e}");
    }
    ExitCode::from(exit_code(&r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_config::{
        base_token, installable, parse_bindings, parse_mirror, render_mirror, BindingEntry,
        MirrorHeader, Section, MIRROR_FILE, MIRROR_MAX_BYTES,
    };
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const BASE: &str = "schema_version: 1\nbindings:\n  admin: [\"root\"]\n";
    const LIVE: &str =
        "schema_version: 1\nbindings:\n  admin: [\"root\"]\n  adversary: [{uid: 4242}]\n";

    fn section(text: &str) -> Section {
        Section::of(&parse_bindings(text).unwrap())
    }

    fn mirror_in(config_dir: &str, base: &str, live: &str, conflicts: &[BindingEntry]) -> String {
        render_mirror(
            &MirrorHeader {
                revision: 7,
                config_dir: config_dir.into(),
                base: base_token(&section(base), sha256),
                conflicts: conflicts.iter().cloned().collect(),
            },
            &section(live),
        )
    }

    fn mirror_over(base: &str, live: &str, conflicts: &[BindingEntry]) -> String {
        mirror_in("/etc/maknae", base, live, conflicts)
    }

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Fx(PathBuf);

    impl Fx {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "maknae_cli_policy_sync_{}_{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let fx = Fx(root);
            for (dir, mode) in [(fx.state_dir(), 0o700), (fx.config_dir(), 0o750)] {
                std::fs::create_dir(&dir).unwrap();
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            }
            fx
        }

        fn state_dir(&self) -> PathBuf {
            self.0.join("state")
        }

        fn config_dir(&self) -> PathBuf {
            self.0.join("etc")
        }

        fn write(path: &Path, body: &str, mode: u32) {
            std::fs::write(path, body).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }

        fn config(&self, name: &str, body: &str) {
            Self::write(&self.config_dir().join(name), body, 0o640);
        }

        fn mirror(&self, body: &str) {
            Self::write(&self.state_dir().join(MIRROR_FILE), body, 0o600);
        }

        fn read_config(&self, name: &str) -> String {
            std::fs::read_to_string(self.config_dir().join(name)).unwrap()
        }

        fn sync_out(
            &self,
            check: bool,
            answer: &str,
            terminal: bool,
        ) -> (Result<Outcome, String>, String) {
            let (uid, gid) = (
                nix::unistd::geteuid().as_raw(),
                nix::unistd::getegid().as_raw(),
            );
            let mut out = Vec::new();
            let r = sync(
                &self.state_dir(),
                &self.config_dir(),
                Owners {
                    state_dir: uid,
                    config_dir: uid,
                    file: FileOwner { uid, gid },
                },
                check,
                &mut answer.as_bytes(),
                terminal,
                &mut out,
            );
            (r, String::from_utf8(out).unwrap())
        }

        fn sync(&self, check: bool, answer: &str, terminal: bool) -> Result<Outcome, String> {
            self.sync_out(check, answer, terminal).0
        }
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_installer_names_one_path_and_takes_none() {
        let src = include_str!("policy_sync.rs");
        let prod = &src[..src.find("\n#[cfg(test)]").unwrap()];
        assert_eq!(prod.matches("publish_owned(").count(), 1);
        assert!(
            prod.contains("publish_owned(\n        Path::new(BINDINGS_FILE),")
                || prod.contains("publish_owned(Path::new(BINDINGS_FILE),")
        );
        for other in ["authz.yaml", "maknae.yaml", "config.d", "AUTHZ", "publish("] {
            assert!(!prod.contains(other), "{other}");
        }
        use clap::Parser;
        for argv in [
            &["maknae", "policy", "sync", "/etc/maknae/authz.yaml"][..],
            &["maknae", "policy", "sync", "--path", "x"][..],
            &["maknae", "policy", "sync", "--target", "x"][..],
        ] {
            assert!(crate::cli::Cli::try_parse_from(argv).is_err(), "{argv:?}");
        }
    }

    #[test]
    fn only_bindings_yaml_changes() {
        let fx = Fx::new();
        fx.config("authz.yaml", "schema_version: 1\n");
        fx.config("maknae.yaml", "core: {}\n");
        fx.config("bindings.yaml", BASE);
        fx.mirror(&mirror_over(BASE, LIVE, &[]));
        let ino = |n: &str| {
            std::fs::symlink_metadata(fx.config_dir().join(n))
                .unwrap()
                .ino()
        };
        let (a, m, b) = (ino("authz.yaml"), ino("maknae.yaml"), ino("bindings.yaml"));
        let (r, out) = fx.sync_out(false, "", true);
        assert!(matches!(r, Ok(Outcome::Installed)), "{r:?}");
        assert!(out.contains("adversary: +uid:4242"), "{out}");
        assert!(
            out.contains(&format!(
                "installed {}/bindings.yaml from the mirror at revision 7; {RELOAD}",
                fx.config_dir().display()
            )),
            "{out}"
        );
        assert_eq!((ino("authz.yaml"), ino("maknae.yaml")), (a, m));
        assert_ne!(ino("bindings.yaml"), b);
        let md = std::fs::symlink_metadata(fx.config_dir().join("bindings.yaml")).unwrap();
        assert_eq!(md.permissions().mode() & 0o7777, 0o640);
        assert_eq!(
            parse_bindings(&fx.read_config("bindings.yaml"))
                .unwrap()
                .section_canonical(),
            Some(r#"{"admin":["root"],"adversary":[{"uid":4242}]}"#)
        );
        let names: Vec<_> = std::fs::read_dir(fx.config_dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.len(), 3, "{names:?}");
    }

    #[test]
    fn a_mirror_that_fails_the_schema_is_refused_and_nothing_is_written() {
        for bad in [
            mirror_over(BASE, LIVE, &[]).replace("  adversary:", "  root:"),
            "garbage\n".to_string(),
            mirror_over(BASE, LIVE, &[]).replace("# revision: 7", "# revision: x"),
        ] {
            let fx = Fx::new();
            fx.config("bindings.yaml", BASE);
            fx.mirror(&bad);
            let e = fx.sync(false, "y\n", true).unwrap_err();
            assert!(e.starts_with("the mirror is not valid"), "{e}");
            assert_eq!(fx.read_config("bindings.yaml"), BASE);
        }
    }

    #[test]
    fn a_mirror_that_is_not_utf8_is_refused() {
        let fx = Fx::new();
        fx.config("bindings.yaml", BASE);
        std::fs::write(fx.state_dir().join(MIRROR_FILE), b"\xff\xfe\n").unwrap();
        std::fs::set_permissions(
            fx.state_dir().join(MIRROR_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert_eq!(
            fx.sync(false, "y\n", true).unwrap_err(),
            "the mirror is not valid: not UTF-8"
        );
        assert_eq!(fx.read_config("bindings.yaml"), BASE);
    }

    #[test]
    fn a_changed_bindings_yaml_is_refused_and_left_unchanged() {
        let fx = Fx::new();
        fx.config(
            "bindings.yaml",
            "schema_version: 1\nbindings:\n  admin: [\"someone\"]\n",
        );
        fx.mirror(&mirror_over(BASE, LIVE, &[]));
        let e = fx.sync(false, "", true).unwrap_err();
        assert_eq!(
            e,
            "bindings.yaml changed since maknaed last loaded it; reload maknaed so it merges, then sync again"
        );
        assert!(fx.read_config("bindings.yaml").contains("someone"));
    }

    #[test]
    fn an_unusable_bindings_yaml_is_refused_and_never_restored_over() {
        type Spoil = fn(&Fx, &Path);
        let cases: [(&str, Spoil, &str); 5] = [
            (
                "malformed",
                |fx, _| fx.config("bindings.yaml", "bindings: [\n"),
                "bindings.yaml is not valid: ",
            ),
            (
                "bad role",
                |fx, _| {
                    fx.config(
                        "bindings.yaml",
                        "schema_version: 1\nbindings:\n  admin: [{uid: 5}]\n",
                    )
                },
                "bindings.yaml is not valid: ",
            ),
            (
                "group writable",
                |fx, p| {
                    fx.config("bindings.yaml", BASE);
                    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o660)).unwrap();
                },
                "cannot read ",
            ),
            (
                "world readable",
                |fx, p| {
                    fx.config("bindings.yaml", BASE);
                    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
                },
                "cannot read ",
            ),
            (
                "symlink",
                |fx, p| {
                    fx.config("elsewhere", BASE);
                    std::os::unix::fs::symlink(fx.config_dir().join("elsewhere"), p).unwrap();
                },
                "cannot read ",
            ),
        ];
        for (what, spoil, want) in cases {
            let fx = Fx::new();
            let p = fx.config_dir().join("bindings.yaml");
            spoil(&fx, &p);
            let before = std::fs::symlink_metadata(&p).unwrap();
            fx.mirror(&mirror_over(BASE, LIVE, &[]));
            let e = fx.sync(false, "", false).unwrap_err();
            assert!(e.starts_with(want), "{what}: {e}");
            let after = std::fs::symlink_metadata(&p).unwrap();
            assert_eq!(
                (after.ino(), after.mode()),
                (before.ino(), before.mode()),
                "{what}"
            );
        }
        let fx = Fx::new();
        let p = fx.config_dir().join("bindings.yaml");
        fx.config("bindings.yaml", BASE);
        std::fs::hard_link(&p, fx.config_dir().join("second")).unwrap();
        fx.mirror(&mirror_over(BASE, LIVE, &[]));
        let e = fx.sync(false, "", false).unwrap_err();
        assert!(
            e.starts_with(&format!("cannot read {}: ", p.display())),
            "{e}"
        );
        assert_eq!(fx.read_config("bindings.yaml"), BASE);
    }

    #[test]
    fn the_configuration_directory_must_be_roots_and_not_writable_by_others() {
        let fx = Fx::new();
        fx.config("bindings.yaml", BASE);
        fx.mirror(&mirror_over(BASE, LIVE, &[]));
        std::fs::set_permissions(fx.config_dir(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let e = fx.sync(false, "", false).unwrap_err();
        assert!(
            e.starts_with(&format!("cannot use {}: ", fx.config_dir().display())),
            "{e}"
        );
        assert_eq!(fx.read_config("bindings.yaml"), BASE);
    }

    #[test]
    fn check_prints_the_diff_and_installs_nothing() {
        let fx = Fx::new();
        fx.config("bindings.yaml", BASE);
        fx.mirror(&mirror_over(BASE, LIVE, &[]));
        let (r, out) = fx.sync_out(true, "", false);
        assert!(matches!(r, Ok(Outcome::WouldInstall)), "{r:?}");
        assert!(out.contains("adversary: +uid:4242"), "{out}");
        assert!(!out.contains("installed"), "{out}");
        assert_eq!(fx.read_config("bindings.yaml"), BASE);
    }

    #[test]
    fn check_lists_conflicts_without_asking() {
        let c = [BindingEntry::Uid(4242)];
        let fx = Fx::new();
        fx.config("bindings.yaml", BASE);
        fx.mirror(&mirror_over(BASE, LIVE, &c));
        let (r, out) = fx.sync_out(true, "y\n", false);
        assert!(matches!(r, Ok(Outcome::WouldInstall)), "{r:?}");
        assert!(out.contains("  conflict: uid:4242"), "{out}");
        assert!(!out.contains("[y/N]"), "{out}");
        assert_eq!(fx.read_config("bindings.yaml"), BASE);
    }

    #[test]
    fn conflicts_are_asked_on_a_terminal_and_refused_without_one() {
        let c = [BindingEntry::Uid(4242)];
        for (answer, terminal, installed) in [
            ("y\n", true, true),
            ("YES\n", true, true),
            (" yes \n", true, true),
            ("n\n", true, false),
            ("yess\n", true, false),
            ("", true, false),
            ("y\n", false, false),
        ] {
            let fx = Fx::new();
            fx.config("bindings.yaml", BASE);
            fx.mirror(&mirror_over(BASE, LIVE, &c));
            let (r, out) = fx.sync_out(false, answer, terminal);
            assert_eq!(r.is_ok(), installed, "{answer:?} {terminal}: {r:?}");
            if terminal {
                assert!(
                    out.contains(
                        "the mirror fails these entries closed (contained, or unbound when neither side contained them):\n  conflict: uid:4242\n"
                    ),
                    "{out}"
                );
                assert!(
                    out.contains(
                        "install bindings.yaml with these entries as the mirror holds them? [y/N] "
                    ),
                    "{out}"
                );
                if !installed {
                    assert_eq!(
                        r.unwrap_err(),
                        "not installed: the conflicts were not accepted"
                    );
                }
            } else {
                assert!(!out.contains("[y/N]"), "{out}");
                assert_eq!(
                    r.unwrap_err(),
                    "the mirror lists 1 conflicts; run sudo maknae policy sync on a terminal to review them"
                );
            }
            assert_eq!(fx.read_config("bindings.yaml") == BASE, !installed);
        }
    }

    #[test]
    fn no_terminal_refuses_before_reading_the_answer() {
        let c = [BindingEntry::Uid(4242)];
        let fx = Fx::new();
        fx.config("bindings.yaml", BASE);
        fx.mirror(&mirror_over(BASE, LIVE, &c));
        let (uid, gid) = (
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        );
        let mut answer: &[u8] = b"y\n";
        let r = sync(
            &fx.state_dir(),
            &fx.config_dir(),
            Owners {
                state_dir: uid,
                config_dir: uid,
                file: FileOwner { uid, gid },
            },
            false,
            &mut answer,
            false,
            &mut Vec::new(),
        );
        assert!(r.is_err());
        assert_eq!(answer, b"y\n");
    }

    #[test]
    fn a_lost_file_is_restored_without_a_prompt() {
        let c = [BindingEntry::Uid(4242)];
        for lost in [None, Some("schema_version: 1\n")] {
            for terminal in [true, false] {
                let fx = Fx::new();
                if let Some(body) = lost {
                    fx.config("bindings.yaml", body);
                }
                fx.mirror(&mirror_over(BASE, LIVE, &c));
                let (r, out) = fx.sync_out(false, "", terminal);
                assert!(
                    matches!(r, Ok(Outcome::Installed)),
                    "{lost:?} {terminal}: {r:?}"
                );
                assert!(!out.contains("[y/N]"), "no prompt: {out}");
                assert!(out.contains("restoring bindings.yaml, which is missing or has no bindings: key, from the bindings maknaed enforces\n"), "{out}");
                assert!(out.contains("adversary: +uid:4242\n"), "{out}");
                assert!(
                    out.contains("  conflict (installed as maknaed enforces it): uid:4242\n"),
                    "{out}"
                );
                assert!(
                    out.contains(&format!(
                        "restored {}/bindings.yaml from the mirror at revision 7; {RELOAD}",
                        fx.config_dir().display()
                    )),
                    "{out}"
                );
                let md = std::fs::symlink_metadata(fx.config_dir().join("bindings.yaml")).unwrap();
                assert_eq!(md.permissions().mode() & 0o7777, 0o640);
                assert!(fx
                    .read_config("bindings.yaml")
                    .contains("    - uid: 4242\n"));
            }
        }
    }

    #[test]
    fn check_on_a_lost_file_restores_nothing() {
        let fx = Fx::new();
        fx.mirror(&mirror_over(BASE, LIVE, &[]));
        let (r, out) = fx.sync_out(true, "", false);
        assert!(matches!(r, Ok(Outcome::WouldInstall)), "{r:?}");
        assert!(out.contains("restoring bindings.yaml"), "{out}");
        assert!(!fx.config_dir().join("bindings.yaml").exists());
    }

    #[test]
    fn nothing_to_install_is_success_and_idempotent() {
        let fx = Fx::new();
        let mirror = mirror_over(BASE, LIVE, &[]);
        let installed = installable(&parse_mirror(&mirror).unwrap());
        fx.config("bindings.yaml", &installed);
        fx.mirror(&mirror);
        let ino = || {
            std::fs::symlink_metadata(fx.config_dir().join("bindings.yaml"))
                .unwrap()
                .ino()
        };
        let before = ino();
        for check in [false, true, false] {
            let (r, out) = fx.sync_out(check, "", true);
            assert!(matches!(r, Ok(Outcome::NothingToInstall)), "{r:?}");
            assert_eq!(
                out,
                "bindings.yaml already holds the mirror; nothing to install\n"
            );
            assert_eq!(fx.read_config("bindings.yaml"), installed);
            assert_eq!(ino(), before);
        }
    }

    #[test]
    fn a_daemon_on_another_configuration_directory_is_refused() {
        let fx = Fx::new();
        fx.config("bindings.yaml", BASE);
        fx.mirror(&mirror_in("/opt/maknae/etc", BASE, LIVE, &[]));
        let e = fx.sync(false, "", false).unwrap_err();
        assert_eq!(e, "maknaed reads its configuration from /opt/maknae/etc, not /etc/maknae; policy sync installs only /etc/maknae/bindings.yaml");
        assert_eq!(fx.read_config("bindings.yaml"), BASE);
    }

    #[test]
    fn exit_codes_tell_an_install_from_nothing_to_do() {
        assert_eq!(exit_code(&Ok(Outcome::Installed)), 0);
        assert_eq!(exit_code(&Ok(Outcome::NothingToInstall)), 3);
        assert_eq!(exit_code(&Ok(Outcome::WouldInstall)), 1);
        assert_eq!(exit_code(&Err("x".into())), 2);
    }

    #[test]
    fn no_mirror_refuses_even_when_the_file_is_lost() {
        let fx = Fx::new();
        let e = fx.sync(false, "", false).unwrap_err();
        assert_eq!(e, "maknaed has published no mirror (its last render failed: see maknae status); nothing was installed");
        assert!(!fx.config_dir().join("bindings.yaml").exists());
    }

    #[test]
    fn run_names_the_production_directories() {
        let src = include_str!("policy_sync.rs");
        let prod = &src[..src.find("\n#[cfg(test)]").unwrap()];
        assert!(
            prod.contains("sync(\n        Path::new(STATE_DIR),\n        Path::new(CONFIG_DIR),")
                || prod.contains("sync(Path::new(STATE_DIR), Path::new(CONFIG_DIR),")
        );
        assert_eq!(CONFIG_DIR, "/etc/maknae");
    }

    #[test]
    fn the_mirror_must_be_the_daemons_0600_single_link_file() {
        type Spoil = fn(&Fx, &Path);
        let cases: [(&str, Spoil); 3] = [
            ("mode 0644", |_, p| {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap()
            }),
            ("hard link", |fx, p| {
                std::fs::hard_link(p, fx.state_dir().join("second")).unwrap()
            }),
            ("symlink", |fx, p| {
                std::fs::rename(p, fx.state_dir().join("real")).unwrap();
                std::os::unix::fs::symlink(fx.state_dir().join("real"), p).unwrap();
            }),
        ];
        for (what, spoil) in cases {
            let fx = Fx::new();
            fx.config("bindings.yaml", BASE);
            fx.mirror(&mirror_over(BASE, LIVE, &[]));
            let p = fx.state_dir().join(MIRROR_FILE);
            spoil(&fx, &p);
            let e = fx.sync(false, "", false).unwrap_err();
            assert!(
                e.starts_with(&format!("cannot read the mirror {}: ", p.display())),
                "{what}: {e}"
            );
            assert_eq!(fx.read_config("bindings.yaml"), BASE, "{what}");
        }
    }

    #[test]
    fn the_state_directory_must_be_the_daemons_and_private() {
        let fx = Fx::new();
        fx.config("bindings.yaml", BASE);
        fx.mirror(&mirror_over(BASE, LIVE, &[]));
        std::fs::set_permissions(fx.state_dir(), std::fs::Permissions::from_mode(0o750)).unwrap();
        let e = fx.sync(false, "", false).unwrap_err();
        assert!(
            e.starts_with(&format!(
                "cannot use the state directory {}: ",
                fx.state_dir().display()
            )),
            "{e}"
        );
        assert_eq!(fx.read_config("bindings.yaml"), BASE);
    }

    #[test]
    fn sha256_is_the_daemons_digest() {
        let hex: String = sha256(b"abc").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sync_refuses_unless_root() {
        assert_eq!(
            preflight(1000).unwrap_err(),
            "maknae policy sync must run as root: run `sudo maknae policy sync`"
        );
        assert!(preflight(0).is_ok());
    }

    #[test]
    fn run_as_a_non_root_caller_exits_refused() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        assert_eq!(run(1000, false), ExitCode::from(2));
        assert_eq!(run(1000, true), ExitCode::from(2));
    }

    #[test]
    fn an_oversize_bindings_yaml_is_refused() {
        let fx = Fx::new();
        let mut big = String::from(BASE);
        big.push_str(&"#".repeat(MIRROR_MAX_BYTES as usize));
        big.push('\n');
        fx.config("bindings.yaml", &big);
        fx.mirror(&mirror_over(BASE, LIVE, &[]));
        let e = fx.sync(false, "", false).unwrap_err();
        assert!(e.starts_with("cannot read "), "{e}");
        assert_eq!(fx.read_config("bindings.yaml"), big);
    }
}
