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

pub(crate) const UNENROLLED_ACCOUNT: &str = "maknae-agent-unenrolled";

/// The template's `User=`: an account of that name would let an instance with no
/// drop-in start as it.
pub(crate) fn require_no_unenrolled_account(exists: bool) -> Result<(), EnrollError> {
    if !exists {
        return Ok(());
    }
    Err(EnrollError::State(format!(
        "an account named {UNENROLLED_ACCOUNT} exists, so an Agent Daemon instance without its drop-in would run as it; delete that account and enroll again"
    )))
}

pub(crate) const SELINUX_ENFORCE: &str = "/sys/fs/selinux/enforce";
pub(crate) const SELINUX_POLICY_PACKAGE: &str =
    "/usr/share/selinux/packages/targeted/maknae.pp.bz2";
pub(crate) const AGENT_HOME_TYPE: &str = "maknae_agent_home_t";

/// A host that ships the Maknae policy but does not enforce it would run the
/// agent unconfined.
pub(crate) fn require_selinux_enforcing(
    policy_host: bool,
    enforce: Option<&str>,
) -> Result<(), EnrollError> {
    if !policy_host || enforce.map(str::trim) == Some("1") {
        return Ok(());
    }
    Err(EnrollError::State(format!(
        "SELinux is not enforcing ({SELINUX_ENFORCE} does not read 1), so the Agent Daemon would run unconfined; run setenforce 1, set SELINUX=enforcing in /etc/selinux/config, and enroll again"
    )))
}

/// `maknae_agentd_t` writes files only in `maknae_agent_home_t`; a home of another type
/// would leave an instance that starts and cannot write.
pub(crate) fn selinux_home_check(
    r: &dyn Run,
    account: &str,
    home: &str,
) -> Result<(), EnrollError> {
    let args = vec!["--format=%C".to_string(), home.to_string()];
    let program = format!("{} --format=%C {home}", Program::Stat);
    let label = match r.run(Program::Stat, &args) {
        Ok(out) if out.ok => out.stdout,
        Ok(out) => {
            return Err(EnrollError::Command {
                program,
                detail: out.stderr,
            })
        }
        Err(detail) => return Err(EnrollError::Command { program, detail }),
    };
    let label = label.trim();
    if label.split(':').nth(2) == Some(AGENT_HOME_TYPE) {
        return Ok(());
    }
    Err(EnrollError::Owner(format!(
        "account {account}: its home {home:?} is labelled {label:?}, not {AGENT_HOME_TYPE}, so the Agent Daemon could not write it; put the home under /var/lib/maknae-agents and run restorecon -RF {home}"
    )))
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

    const UNENROLLED: &str = UNENROLLED_ACCOUNT;

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
            (
                "RestrictAddressFamilies",
                "AF_UNIX AF_INET AF_INET6 AF_NETLINK",
            ),
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

    const TE: &str = include_str!("../../../../packaging/common/maknae.te");
    const FC: &str = include_str!("../../../../packaging/common/maknae.fc");
    const SPEC: &str = include_str!("../../../../packaging/rpm/maknae.spec");

    /// The rules that start with `head`, or for a bare type, mention it.
    fn te_rules(head: &str) -> Vec<&'static str> {
        TE.lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .filter(|l| {
                if head.contains(' ') {
                    l.starts_with(head)
                } else {
                    l.contains(head)
                }
            })
            .collect()
    }

    #[test]
    fn the_agent_daemon_runs_in_its_own_domain_from_its_own_entrypoint() {
        for line in [
            "type maknae_agentd_t;",
            "type maknae_agentd_exec_t;",
            "init_daemon_domain(maknae_agentd_t, maknae_agentd_exec_t)",
            "allow init_t maknae_agentd_t:process2 { nnp_transition nosuid_transition };",
        ] {
            assert!(TE.lines().any(|l| l == line), "{line}");
        }
        assert!(FC.lines().any(|l| l.split_whitespace().collect::<Vec<_>>()
            == [
                "/usr/bin/maknae-agentd",
                "--",
                "gen_context(system_u:object_r:maknae_agentd_exec_t,s0)"
            ]));
        for want in [
            [
                "/var/lib/maknae-agents",
                "-d",
                "gen_context(system_u:object_r:maknae_agent_homes_root_t,s0)",
            ]
            .as_slice(),
            &[
                "/var/lib/maknae-agents/.*",
                "gen_context(system_u:object_r:maknae_agent_home_t,s0)",
            ],
            &[
                "/etc/maknae/agents(/.*)?",
                "gen_context(system_u:object_r:maknae_agent_etc_t,s0)",
            ],
            &[
                "/etc/maknae/tls(/.*)?",
                "gen_context(system_u:object_r:maknae_tls_t,s0)",
            ],
        ] {
            assert!(
                FC.lines()
                    .any(|l| l.split_whitespace().collect::<Vec<_>>() == want),
                "{want:?}"
            );
        }
        assert!(!TE.contains("policy_module(maknae, 1.0.3)"));
    }

    /// A connect is `write` on the socket file and `connectto` on the listener's domain.
    #[test]
    fn the_agent_daemon_reaches_maknaed_only_on_its_socket_and_vault_only_on_the_labeled_port() {
        let rules = te_rules("allow maknae_agentd_t");
        for want in [
            "allow maknae_agentd_t maknae_runtime_t:sock_file write;",
            "allow maknae_agentd_t maknaed_t:unix_stream_socket connectto;",
            "allow maknae_agentd_t maknae_vault_port_t:tcp_socket name_connect;",
        ] {
            assert!(rules.contains(&want), "{want}");
        }
        let connectto: Vec<_> = rules.iter().filter(|l| l.contains("connectto")).collect();
        assert_eq!(connectto.len(), 1, "{connectto:?}");
        let ports: Vec<_> = rules
            .iter()
            .filter(|l| l.contains("name_connect"))
            .collect();
        assert_eq!(ports.len(), 1, "{ports:?}");
        assert!(!TE.contains("corenet_tcp_connect_http_port(maknae_agentd_t)"));
        assert!(TE
            .lines()
            .any(|l| l == "allow maknaed_t maknae_agentd_t:fd use;"));
    }

    #[test]
    fn the_agent_daemon_is_granted_nothing_on_the_kernels_secrets_state_or_audit() {
        let rules = te_rules("allow maknae_agentd_t");
        for forbidden in [
            "maknae_private_t",
            "maknae_secret_t",
            "maknae_state_t",
            "maknae_audit_t",
            "maknae_egress_etc_t",
            "maknae_egress_bounds_t",
            "mail_spool_t",
            "tty_device_t",
            "devpts_t",
            "bin_t",
            "shell_exec_t",
        ] {
            assert!(
                !rules.iter().any(|l| l.contains(forbidden)),
                "maknae_agentd_t is granted {forbidden}"
            );
        }
        let exec: Vec<_> = rules.iter().filter(|l| l.contains("execute")).collect();
        assert_eq!(
            exec,
            [&"allow maknae_agentd_t maknae_agentd_exec_t:file { read execute execute_no_trans open getattr };"]
        );
        for line in [
            "neverallow maknae_agentd_t { maknae_private_t maknae_secret_t maknae_egress_etc_t maknae_egress_bounds_t }:file { read open };",
            "neverallow maknae_agentd_t { maknae_state_t maknae_audit_t }:{ dir file } *;",
            "neverallow maknae_agentd_t mail_spool_t:{ dir file } *;",
            "neverallow maknae_agentd_t { tty_device_t devpts_t user_tty_device_t user_devpts_t console_device_t ptmx_t }:chr_file { write append };",
        ] {
            assert!(TE.lines().any(|l| l == line), "{line}");
        }
    }

    /// journald forwards an emerg message to every terminal (`ForwardToWall=yes`,
    /// `MaxLevelWall=emerg`), so no journal or syslog socket may be reachable and
    /// the inherited stream may carry no level prefix.
    #[test]
    fn the_agent_daemon_cannot_raise_a_journal_message_to_wall() {
        for reach in [
            "logging_send_syslog_msg(maknae_agentd_t)",
            "logging_send_audit_msgs(maknae_agentd_t)",
            "devlog_t",
            "syslogd_var_run_t",
            "syslogd_t",
            "kernel_t:unix_dgram_socket",
            "unix_dgram_socket",
        ] {
            assert!(
                !te_rules("maknae_agentd_t")
                    .iter()
                    .any(|l| !l.starts_with("neverallow") && l.contains(reach)),
                "{reach}"
            );
        }
        assert_eq!(the_one(&service_lines(), "SyslogLevelPrefix"), "no");
        assert!(!service_lines()
            .iter()
            .any(|l| l.starts_with("LogLevelMax=")));
    }

    #[test]
    fn the_agent_daemon_reads_its_configuration_types_and_only_lists_the_rest_of_etc() {
        let on_etc: Vec<_> = te_rules("allow maknae_agentd_t")
            .into_iter()
            .filter(|l| l.contains("maknae_etc_t"))
            .collect();
        assert_eq!(
            on_etc,
            ["allow maknae_agentd_t maknae_etc_t:dir { open read search getattr };"]
        );
        for who in ["maknaed_t", "maknae_agentd_t"] {
            for class in [
                "dir { open read search getattr };",
                "file { read open getattr };",
            ] {
                let line = format!("allow {who} {{ maknae_agent_etc_t maknae_tls_t }}:{class}");
                assert!(TE.lines().any(|l| l == line), "{line}");
            }
        }
    }

    #[test]
    fn maknaed_only_stats_and_receives_in_agent_homes() {
        let on_homes: Vec<_> = te_rules("maknaed_t")
            .into_iter()
            .filter(|l| l.contains("maknae_agent_home"))
            .collect();
        assert_eq!(
            on_homes,
            [
                "allow maknaed_t maknae_agent_homes_root_t:dir { search getattr };",
                "allow maknaed_t maknae_agent_home_t:dir { getattr ioctl };",
                "allow maknaed_t maknae_agent_home_t:file { getattr ioctl };",
                "allowxperm maknaed_t maknae_agent_home_t:dir ioctl 0x0000;",
                "allowxperm maknaed_t maknae_agent_home_t:file ioctl 0x0000;",
            ]
        );
        assert!(TE
            .lines()
            .any(|l| l == "allow maknaed_t maknae_agentd_t:fd use;"));
    }

    #[test]
    fn the_agent_daemon_writes_only_agent_homes() {
        let writes: Vec<_> = te_rules("maknae_agentd_t")
            .into_iter()
            .filter(|l| {
                l.starts_with("manage_")
                    || (l.starts_with("allow maknae_agentd_t")
                        && [" write", " create", " add_name", " unlink", " rename"]
                            .iter()
                            .any(|p| l.contains(p))
                        && !l.contains("_socket")
                        && !l.contains("sock_file write;"))
            })
            .collect();
        assert_eq!(
            writes,
            [
                "manage_dirs_pattern(maknae_agentd_t, maknae_agent_home_t, maknae_agent_home_t)",
                "manage_files_pattern(maknae_agentd_t, maknae_agent_home_t, maknae_agent_home_t)",
            ]
        );
    }

    #[test]
    fn the_rpm_labels_the_agent_daemon_and_the_agent_home_root() {
        let restorecon = SPEC
            .lines()
            .find(|l| l.starts_with("restorecon -Rv "))
            .unwrap();
        for path in [
            "%{_bindir}/maknae-agentd",
            "%{_localstatedir}/lib/maknae-agents",
        ] {
            assert!(restorecon.split_whitespace().any(|w| w == path), "{path}");
        }
        assert!(SPEC
            .lines()
            .any(|l| l == "%dir %attr(0755,root,root) %{_localstatedir}/lib/maknae-agents"));
    }

    struct Labelled(&'static str, bool);

    impl Run for Labelled {
        fn run(&self, program: Program, args: &[String]) -> Result<Ran, String> {
            assert_eq!(program, Program::Stat);
            assert_eq!(args, ["--format=%C", "/var/lib/maknae-agents/hobi"]);
            Ok(Ran {
                ok: self.1,
                code: Some(i32::from(!self.1)),
                stdout: self.0.to_string(),
                stderr: if self.1 {
                    String::new()
                } else {
                    "stat: cannot stat".into()
                },
            })
        }
    }

    #[test]
    fn an_selinux_host_admits_only_a_home_labelled_for_the_agent_domain() {
        let home = "/var/lib/maknae-agents/hobi";
        selinux_home_check(
            &Labelled("system_u:object_r:maknae_agent_home_t:s0\n", true),
            "hobi",
            home,
        )
        .unwrap();
        for label in [
            "system_u:object_r:maknae_agent_homes_root_t:s0\n",
            "unconfined_u:object_r:user_home_dir_t:s0\n",
            "system_u:object_r:var_lib_t:s0\n",
            "?\n",
            "",
        ] {
            let e = selinux_home_check(&Labelled(label, true), "hobi", home).unwrap_err();
            assert!(
                matches!(&e, EnrollError::Owner(m) if m.contains("restorecon -RF /var/lib/maknae-agents/hobi")),
                "{label:?}: {e:?}"
            );
        }
        let e = selinux_home_check(&Labelled("", false), "hobi", home).unwrap_err();
        assert!(
            matches!(&e, EnrollError::Command { program, detail }
                if program == "/usr/bin/stat --format=%C /var/lib/maknae-agents/hobi"
                    && detail == "stat: cannot stat"),
            "{e:?}"
        );
    }

    #[test]
    fn the_unenrolled_sentinel_is_the_templates_user_and_must_not_exist() {
        assert_eq!(UNENROLLED_ACCOUNT, "maknae-agent-unenrolled");
        require_no_unenrolled_account(false).unwrap();
        let e = require_no_unenrolled_account(true).unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m)
                if m.contains("maknae-agent-unenrolled") && m.contains("delete")),
            "{e:?}"
        );
    }

    #[test]
    fn a_host_with_the_maknae_policy_enrolls_only_while_selinux_enforces() {
        require_selinux_enforcing(false, None).unwrap();
        require_selinux_enforcing(false, Some("0")).unwrap();
        require_selinux_enforcing(true, Some("1")).unwrap();
        require_selinux_enforcing(true, Some("1\n")).unwrap();
        for enforce in [
            None,
            Some("0"),
            Some("0\n"),
            Some(""),
            Some("10"),
            Some("Y"),
        ] {
            let e = require_selinux_enforcing(true, enforce).unwrap_err();
            assert!(
                matches!(&e, EnrollError::State(m)
                    if m.contains(SELINUX_ENFORCE) && m.contains("setenforce 1")),
                "{enforce:?}: {e:?}"
            );
        }
    }

    #[test]
    fn the_policy_package_path_is_where_the_rpm_installs_the_module() {
        let spec = include_str!("../../../../packaging/rpm/maknae.spec");
        assert!(spec.contains("%global selinuxtype targeted\n"));
        let rendered = "%{_datadir}/selinux/packages/%{selinuxtype}/maknae.pp.bz2"
            .replace("%{_datadir}", "/usr/share")
            .replace("%{selinuxtype}", "targeted");
        assert_eq!(rendered, SELINUX_POLICY_PACKAGE);
        assert!(spec.contains("\n%{_datadir}/selinux/packages/%{selinuxtype}/maknae.pp.bz2\n"));
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
