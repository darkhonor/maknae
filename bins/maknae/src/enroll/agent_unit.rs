//! The Agent Daemon's systemd instance: the drop-in that binds `maknae-agent@<id>`
//! to its account, and the `systemctl` calls that start and stop it.
// Only Linux enrollment calls the systemd half; its tests run on both lanes.
#![cfg_attr(target_os = "macos", allow(dead_code))]
use super::agent::{io_error, is_not_found};
use super::agent_access::Run;
use super::EnrollError;
use maknae_io::program::Program;
use maknae_vault::agent_enroll::AgentId;
use std::path::Path;

pub(crate) const UNIT_DIR: &str = "/etc/systemd/system";
pub(crate) const DROP_IN_FILE: &str = "account.conf";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceAccount {
    pub uid: u32,
    pub gid: u32,
    /// Only ever a value [`checked_home`] returned.
    pub home: String,
}

pub(crate) fn unit_name(agent: &AgentId) -> String {
    format!("maknae-agent@{}.service", agent.as_str())
}

pub(crate) fn drop_in_dir(agent: &AgentId) -> String {
    format!("{}.d", unit_name(agent))
}

fn forbidden(c: char) -> bool {
    c.is_whitespace() || c.is_control() || matches!(c, '%' | '"' | '\'' | '\\')
}

/// The passwd home, as a unit file or a plist may carry it unquoted: absolute,
/// canonical, and free of anything systemd would expand (`%`), unquote (`"`, `'`,
/// `\`) or split on (whitespace, control characters).
pub(crate) fn checked_home(
    account: &str,
    raw: &Path,
    canonical: Option<&Path>,
) -> Result<String, EnrollError> {
    let refuse = |why: &str| {
        Err(EnrollError::Owner(format!(
            "account {account}: its home {raw:?} {why}; the Agent Daemon's unit cannot name it"
        )))
    };
    let Some(text) = raw.to_str() else {
        return refuse("is not UTF-8");
    };
    if !raw.is_absolute() {
        return refuse("is not absolute");
    }
    if let Some(c) = text.chars().find(|c| forbidden(*c)) {
        return refuse(&format!("contains {c:?}"));
    }
    if canonical.and_then(Path::to_str) != Some(text) {
        return refuse(
            "is not canonical (a symlink, `.`, `..` or a repeated `/`), or does not exist",
        );
    }
    Ok(text.to_string())
}

pub(crate) fn drop_in(account: &ServiceAccount) -> String {
    format!(
        "[Service]\nUser={}\nGroup={}\nSupplementaryGroups={}\nReadWritePaths={}\n",
        account.uid,
        account.gid,
        maknae_io::MAKNAE_AGENTS_GROUP,
        account.home
    )
}

/// Leaves the empty drop-in directory: `maknae-io` removes no directory, and an
/// empty one configures nothing.
pub(crate) fn remove_drop_in(
    units: &maknae_io::Anchor,
    agent: &AgentId,
) -> Result<(), EnrollError> {
    let rel = Path::new(&drop_in_dir(agent)).join(DROP_IN_FILE);
    match units.remove(&rel, None) {
        Ok(_) => Ok(()),
        Err(e) if is_not_found(&e) => Ok(()),
        Err(e) => Err(io_error(&Path::new(UNIT_DIR).join(&rel), e)),
    }
}

fn systemctl(r: &dyn Run, args: &[&str]) -> Result<(), EnrollError> {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let program = format!("{} {}", Program::Systemctl, args.join(" "));
    match r.run(Program::Systemctl, &args) {
        Ok(out) if out.ok => Ok(()),
        Ok(out) => Err(EnrollError::Command {
            program,
            detail: out.stderr,
        }),
        Err(detail) => Err(EnrollError::Command { program, detail }),
    }
}

/// `write` places the drop-in. `restart`, not `start`: a re-enrollment must
/// replace a running instance's login with the new SecretID.
pub(crate) fn start(
    r: &dyn Run,
    agent: &AgentId,
    write: impl FnOnce() -> Result<(), EnrollError>,
) -> Result<(), EnrollError> {
    let unit = unit_name(agent);
    write()?;
    systemctl(r, &["daemon-reload"])?;
    systemctl(r, &["enable", &unit])?;
    systemctl(r, &["restart", &unit])
}

/// `remove` deletes the drop-in, once the instance has stopped.
pub(crate) fn stop(
    r: &dyn Run,
    agent: &AgentId,
    remove: impl FnOnce() -> Result<(), EnrollError>,
) -> Result<(), EnrollError> {
    systemctl(r, &["disable", "--now", &unit_name(agent)])?;
    remove()?;
    systemctl(r, &["daemon-reload"])
}

#[cfg(test)]
mod tests {
    use super::super::agent_access::Ran;
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;

    const UNIT: &str = include_str!("../../../../packaging/common/maknae-agent@.service");
    const PRESET: &str = include_str!("../../../../packaging/common/80-maknae.preset");

    fn hobi() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    #[derive(Default)]
    struct Recorder {
        log: RefCell<Vec<String>>,
        refuse: Option<&'static str>,
    }

    impl Run for Recorder {
        fn run(&self, program: Program, args: &[String]) -> Result<Ran, String> {
            let line = format!("{program} {}", args.join(" "));
            self.log.borrow_mut().push(line.clone());
            let ok = self.refuse != Some(args[0].as_str());
            Ok(Ran {
                ok,
                stdout: String::new(),
                stderr: if ok {
                    String::new()
                } else {
                    format!("{line} refused")
                },
            })
        }
    }

    fn service_lines() -> Vec<&'static str> {
        let mut in_service = false;
        let mut out = Vec::new();
        for l in UNIT.lines().map(str::trim) {
            if l.starts_with('[') {
                in_service = l == "[Service]";
            } else if in_service && !l.is_empty() && !l.starts_with('#') {
                out.push(l);
            }
        }
        out
    }

    #[test]
    fn the_unit_runs_the_agent_daemon_on_its_own_sealed_credential() {
        let lines = service_lines();
        for want in [
            "ExecStart=/usr/bin/maknae-agentd %i",
            "LoadCredentialEncrypted=maknae-agent-secret-id:/etc/maknae/private/agent-%i-secret-id.cred",
            "PrivateTmp=yes",
            "ProtectHome=read-only",
            "ProtectSystem=strict",
            "Restart=on-failure",
            "RestartPreventExitStatus=2",
        ] {
            assert!(lines.contains(&want), "{want} is not in maknae-agent@.service");
        }
        for owned_by_the_drop_in in ["User=", "Group=", "SupplementaryGroups=", "ReadWritePaths="] {
            assert!(
                !lines.iter().any(|l| l.starts_with(owned_by_the_drop_in)),
                "{owned_by_the_drop_in} belongs to the drop-in"
            );
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn the_units_credential_is_the_file_enroll_seals() {
        let line = service_lines()
            .into_iter()
            .find_map(|l| l.strip_prefix("LoadCredentialEncrypted="))
            .unwrap();
        let (name, path) = line.split_once(':').unwrap();
        assert_eq!(name, maknae_vault::agent_enroll::AGENT_CREDENTIAL_NAME);
        assert_eq!(
            Path::new(&path.replace("%i", "hobi")),
            super::super::agent::cred_path(&hobi())
        );
    }

    #[test]
    fn the_package_enables_no_agent_instance() {
        let install: Vec<&str> = UNIT
            .lines()
            .map(str::trim)
            .skip_while(|l| *l != "[Install]")
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        assert_eq!(install, ["[Install]", "WantedBy=multi-user.target"]);
        for l in PRESET.lines().map(str::trim) {
            assert!(
                !(l.starts_with("enable") && l.contains("maknae-agent")),
                "the preset enables an agent: {l}"
            );
        }
        assert!(PRESET
            .lines()
            .any(|l| l.trim() == "disable maknae-agent@.service"));
    }

    fn account() -> ServiceAccount {
        ServiceAccount {
            uid: 990,
            gid: 991,
            home: "/home/hobi-svc".into(),
        }
    }

    #[test]
    fn the_drop_in_binds_the_instance_to_the_enrolled_uid_and_its_home() {
        assert_eq!(
            drop_in(&account()),
            "[Service]\nUser=990\nGroup=991\nSupplementaryGroups=maknae-agents\nReadWritePaths=/home/hobi-svc\n"
        );
        assert_eq!(unit_name(&hobi()), "maknae-agent@hobi.service");
        assert_eq!(drop_in_dir(&hobi()), "maknae-agent@hobi.service.d");
    }

    #[test]
    fn a_canonical_home_passes_as_its_text() {
        let home = Path::new("/home/hobi-svc");
        assert_eq!(
            checked_home("hobi-svc", home, Some(home)).unwrap(),
            "/home/hobi-svc"
        );
    }

    #[test]
    fn a_home_a_unit_could_expand_split_or_unquote_is_refused() {
        for bad in [
            "/home/ho bi",
            "/home/ho\tbi",
            "/home/ho\nbi",
            "/home/ho\rbi",
            "/home/ho\u{7}bi",
            "/home/ho\u{a0}bi",
            "/home/ho%ibi",
            "/home/ho\"bi",
            "/home/ho'bi",
            "/home/ho\\bi",
        ] {
            let home = Path::new(bad);
            let e = checked_home("hobi-svc", home, Some(home)).unwrap_err();
            assert!(
                matches!(&e, EnrollError::Owner(m) if m.contains("contains") && m.contains("hobi-svc")),
                "{bad:?}: {e:?}"
            );
        }
    }

    #[test]
    fn a_relative_non_canonical_or_missing_home_is_refused() {
        let rel = Path::new("home/hobi");
        assert!(matches!(
            checked_home("h", rel, Some(rel)),
            Err(EnrollError::Owner(m)) if m.contains("not absolute")
        ));
        for (raw, canonical) in [
            ("/home/./hobi", Some("/home/hobi")),
            ("/home/link", Some("/data/hobi")),
            ("/home//hobi", Some("/home/hobi")),
            ("/home/hobi/", Some("/home/hobi")),
            ("/home/gone", None),
        ] {
            let canonical = canonical.map(PathBuf::from);
            assert!(
                matches!(
                    checked_home("h", Path::new(raw), canonical.as_deref()),
                    Err(EnrollError::Owner(m)) if m.contains("not canonical")
                ),
                "{raw}"
            );
        }
    }

    #[test]
    fn a_non_utf8_home_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let raw = Path::new(std::ffi::OsStr::from_bytes(b"/home/h\xffbi"));
        assert!(matches!(
            checked_home("h", raw, Some(raw)),
            Err(EnrollError::Owner(m)) if m.contains("not UTF-8")
        ));
    }

    #[test]
    fn start_writes_the_drop_in_reloads_enables_and_restarts_the_instance() {
        let r = Recorder::default();
        start(&r, &hobi(), || {
            r.log.borrow_mut().push("write".into());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            *r.log.borrow(),
            [
                "write",
                "/usr/bin/systemctl daemon-reload",
                "/usr/bin/systemctl enable maknae-agent@hobi.service",
                "/usr/bin/systemctl restart maknae-agent@hobi.service",
            ]
        );
    }

    #[test]
    fn a_failed_write_or_call_stops_the_start_there() {
        let r = Recorder::default();
        let e = start(&r, &hobi(), || {
            Err(EnrollError::State("write failed".into()))
        })
        .unwrap_err();
        assert!(matches!(e, EnrollError::State(m) if m == "write failed"));
        assert!(r.log.borrow().is_empty());

        let r = Recorder {
            refuse: Some("enable"),
            ..Recorder::default()
        };
        let e = start(&r, &hobi(), || Ok(())).unwrap_err();
        assert!(
            matches!(&e, EnrollError::Command { program, detail }
                if program == "/usr/bin/systemctl enable maknae-agent@hobi.service"
                    && detail.contains("refused")),
            "{e:?}"
        );
        assert_eq!(r.log.borrow().len(), 2);
    }

    #[test]
    fn stop_disables_the_instance_before_removing_its_drop_in() {
        let r = Recorder::default();
        stop(&r, &hobi(), || {
            r.log.borrow_mut().push("remove".into());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            *r.log.borrow(),
            [
                "/usr/bin/systemctl disable --now maknae-agent@hobi.service",
                "remove",
                "/usr/bin/systemctl daemon-reload",
            ]
        );
    }

    #[test]
    fn removing_the_drop_in_unlinks_it_and_a_missing_one_is_already_removed() {
        let (dir, units) = super::super::agent::tests::scratch_anchor("drop-in");
        remove_drop_in(&units, &hobi()).unwrap();
        let d = dir.join(drop_in_dir(&hobi()));
        std::fs::create_dir(&d).unwrap();
        remove_drop_in(&units, &hobi()).unwrap();
        std::fs::write(d.join(DROP_IN_FILE), drop_in(&account())).unwrap();
        std::fs::write(d.join("operator.conf"), "").unwrap();
        remove_drop_in(&units, &hobi()).unwrap();
        assert!(!d.join(DROP_IN_FILE).exists());
        assert!(d.join("operator.conf").exists());
    }

    #[test]
    fn a_refused_stop_leaves_the_drop_in() {
        let r = Recorder {
            refuse: Some("disable"),
            ..Recorder::default()
        };
        let removed = std::cell::Cell::new(false);
        let e = stop(&r, &hobi(), || {
            removed.set(true);
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(e, EnrollError::Command { .. }), "{e:?}");
        assert!(!removed.get());
    }
}
