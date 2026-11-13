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
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    /// Only ever a value [`maknae_io::unit_safe_home`] returned.
    pub home: String,
}

pub(crate) fn unit_name(agent: &AgentId) -> String {
    format!("maknae-agent@{}.service", agent.as_str())
}

pub(crate) fn drop_in_dir(agent: &AgentId) -> String {
    format!("{}.d", unit_name(agent))
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
    systemctl(r, &["reset-failed", &unit])?;
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
                code: Some(if ok { 0 } else { 1 }),
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

    fn section_lines(section: &str) -> Vec<&'static str> {
        let mut inside = false;
        let mut out = Vec::new();
        for l in UNIT.lines().map(str::trim) {
            if l.starts_with('[') {
                inside = l == section;
            } else if inside && !l.is_empty() && !l.starts_with('#') {
                out.push(l);
            }
        }
        out
    }

    fn the_one(lines: &[&'static str], key: &str) -> &'static str {
        let found: Vec<&str> = lines
            .iter()
            .filter_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .collect();
        assert_eq!(found.len(), 1, "{key}= appears {} times", found.len());
        found[0]
    }

    const UNENROLLED: &str = "maknae-agent-unenrolled";

    #[test]
    fn the_unit_runs_the_agent_daemon_on_its_own_sealed_credential() {
        let lines = service_lines();
        for (key, want) in [
            ("ExecStart", "/usr/bin/maknae-agentd %i"),
            ("User", UNENROLLED),
            (
                "LoadCredentialEncrypted",
                "maknae-agent-secret-id:/etc/maknae/private/agent-%i-secret-id.cred",
            ),
            ("PrivateTmp", "yes"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", ""),
            ("Restart", "on-failure"),
            ("RestartPreventExitStatus", "2"),
        ] {
            assert_eq!(the_one(&lines, key), want, "{key}");
        }
        the_one(&lines, "TimeoutStopSec");
        for owned_by_the_drop_in in ["Group=", "SupplementaryGroups=", "ReadWritePaths="] {
            assert!(
                !lines.iter().any(|l| l.starts_with(owned_by_the_drop_in)),
                "{owned_by_the_drop_in} belongs to the drop-in"
            );
        }
    }

    /// systemd fails an instance whose `User=` does not resolve (217/USER) before
    /// exec, so an instance without its drop-in never runs as root.
    #[test]
    fn no_package_creates_the_unenrolled_sentinel_account() {
        for (name, text) in [
            (
                "maknae.sysusers",
                include_str!("../../../../packaging/common/maknae.sysusers"),
            ),
            (
                "maknae.spec",
                include_str!("../../../../packaging/rpm/maknae.spec"),
            ),
            (
                "postinst",
                include_str!("../../../../packaging/deb/postinst"),
            ),
            (
                "build-deb.sh",
                include_str!("../../../../packaging/deb/build-deb.sh"),
            ),
        ] {
            assert!(!text.contains(UNENROLLED), "{name} names {UNENROLLED}");
        }
        assert!(!drop_in(&account()).contains(UNENROLLED));
        assert!(drop_in(&account()).contains("\nUser=990\n"));
    }

    #[test]
    fn repeated_failures_stop_the_instance_within_minutes() {
        let unit = section_lines("[Unit]");
        let interval: u64 = the_one(&unit, "StartLimitIntervalSec").parse().unwrap();
        let burst: u64 = the_one(&unit, "StartLimitBurst").parse().unwrap();
        let restart_sec: u64 = the_one(&service_lines(), "RestartSec")
            .trim_end_matches('s')
            .parse()
            .unwrap();
        assert_eq!((interval, burst), (300, 10));
        assert!(burst * restart_sec < interval, "the limit never trips");
        for key in ["StartLimitIntervalSec=", "StartLimitBurst="] {
            assert!(!service_lines().iter().any(|l| l.starts_with(key)), "{key}");
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
            name: "hobi-svc".into(),
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
                "/usr/bin/systemctl reset-failed maknae-agent@hobi.service",
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
