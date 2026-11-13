use super::agent::{
    check_mount, dedup, has_alias_on, io_error, is_not_found, open_dir, read_host, read_records,
    read_state, AgentState, AgentVaultOps, HasVault, RealVault, AGENTS_DIR, PRIVATE_DIR,
    RELOAD_COMMAND, VAULT_CA,
};
use super::agent_access;
#[cfg(target_os = "macos")]
use super::agent_launchd;
#[cfg(not(target_os = "macos"))]
use super::agent_unit;
use super::EnrollError;
use crate::stderr::errln;
use clap::Args;
use maknae_io::IoError;
use maknae_msgs::{msg, Locale, MsgId};
use maknae_vault::agent_enroll::AgentId;
use std::path::{Path, PathBuf};

/// `maknae enroll remove-agent` — de-enroll one Agent Daemon on this host.
#[derive(Args, Debug, Clone)]
pub struct RemoveAgentArgs {
    /// The agent's id.
    #[arg(value_name = "ID")]
    pub id: String,
    /// Read the Vault token from this file instead of an interactive prompt.
    #[arg(long)]
    pub token_file: Option<PathBuf>,
    /// Print raw operation detail.
    #[arg(long)]
    pub verbose: bool,
}

pub(crate) trait RemoveOps: AgentVaultOps {
    fn stop_agent(&self, agent: &AgentId) -> Result<(), EnrollError>;
    fn revoke_access(&self, agent: &AgentId) -> Result<(), EnrollError>;
    fn remove_enrollment(&self, agent: &AgentId) -> Result<(), EnrollError>;
    async fn remove_sealed_secret(&self, agent: &AgentId) -> Result<(), EnrollError>;
    fn remove_state(&self, agent: &AgentId) -> Result<(), EnrollError>;
    async fn leftovers(&self, agent: &AgentId) -> Result<Vec<String>, EnrollError>;
}

pub(crate) fn resolve_mount(
    agent: &AgentId,
    record_mount: Option<&str>,
    state_mount: &str,
    host_mount: &str,
) -> Result<String, EnrollError> {
    let mount = match (record_mount, state_mount.is_empty()) {
        (None, true) => {
            return Err(EnrollError::State(format!(
                "agent {} is not enrolled on this host",
                agent.as_str()
            )))
        }
        (Some(r), true) => r,
        (Some(r), false) if r != state_mount => {
            return Err(EnrollError::State(format!(
                "agent {}: enrollment.yaml names mount {r} but the state file names {state_mount}; resolve the difference by hand",
                agent.as_str()
            )))
        }
        (_, false) => state_mount,
    };
    if mount == host_mount {
        return Err(EnrollError::AgentMountIsDaemons(mount.to_string()));
    }
    Ok(mount.to_string())
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RemoveOutcome {
    pub destroyed: usize,
    pub role_absent: bool,
}

pub(crate) async fn remove_agent<O: RemoveOps>(
    ops: &O,
    agent: &AgentId,
    state: AgentState,
) -> Result<RemoveOutcome, EnrollError> {
    ops.stop_agent(agent)?;
    ops.revoke_access(agent)?;
    ops.remove_enrollment(agent)?;

    let mount = state.approle_mount.clone();
    let mount = mount.as_str();
    let role = agent.role_name();
    let entity = agent.entity_name();
    let recorded = dedup(
        state
            .live
            .iter()
            .chain(&state.pending)
            .chain(&state.retiring),
    );
    let Some(role_id) = ops.find_role_id(mount, &role).await? else {
        if ops.entity(&entity).await?.is_some() {
            let mut remains = ops.leftovers(agent).await?;
            if !recorded.is_empty() {
                remains.push(format!("SecretID accessors {}", recorded.join(", ")));
            }
            return Err(EnrollError::AgentRoleMissing {
                agent: agent.as_str().to_string(),
                mount: mount.to_string(),
                entity,
                remains,
            });
        }
        ops.remove_sealed_secret(agent).await?;
        ops.remove_state(agent)?;
        return Ok(RemoveOutcome {
            destroyed: 0,
            role_absent: true,
        });
    };
    match ops.entity(&entity).await? {
        Some(facts) if has_alias_on(&facts, mount, &role_id) => {}
        _ => {
            let mut remains = ops.leftovers(agent).await?;
            if !recorded.is_empty() {
                remains.push(format!("SecretID accessors {}", recorded.join(", ")));
            }
            return Err(EnrollError::AgentEntityMissing {
                agent: agent.as_str().to_string(),
                entity,
                mount: mount.to_string(),
                remains,
            });
        }
    }
    ops.set_entity_disabled(&entity, true).await?;

    let listed = ops.list_accessors(mount, &role).await?;
    let all = dedup(recorded.iter().chain(&listed));
    let retiring = AgentState {
        live: Vec::new(),
        pending: Vec::new(),
        retiring: all.clone(),
        ..state
    };
    ops.write_state(agent, &retiring)?;

    let mut failures = Vec::new();
    for a in &all {
        if ops.destroy(mount, &role, a).await.is_err() {
            failures.push(a.clone());
        }
    }
    if !failures.is_empty() {
        ops.write_state(
            agent,
            &AgentState {
                retiring: failures.clone(),
                ..retiring
            },
        )?;
        return Err(EnrollError::AgentRemoveRetireFailed {
            agent: agent.as_str().to_string(),
            accessors: failures,
        });
    }
    ops.remove_sealed_secret(agent).await?;
    ops.remove_state(agent)?;
    Ok(RemoveOutcome {
        destroyed: all.len(),
        role_absent: false,
    })
}

fn summary(locale: Locale, agent: &AgentId, out: &RemoveOutcome) -> String {
    let mut text = if out.role_absent {
        msg(locale, MsgId::EnrollAgentRoleAbsent).replace("{agent}", agent.as_str())
    } else {
        msg(locale, MsgId::EnrollAgentRemoved)
            .replace("{agent}", agent.as_str())
            .replace("{count}", &out.destroyed.to_string())
    };
    text.push('\n');
    text.push_str(&msg(locale, MsgId::EnrollAgentReload).replace("{command}", RELOAD_COMMAND));
    text
}

fn unresolved_warning(root: &Path, account: &agent_access::Account) -> String {
    format!(
        "maknae enroll remove-agent: account {:?} (uid {}) no longer exists, so its ACL entries under {} cannot be named and are left in place; they grant nothing until an account of that name exists again. Remove them by hand with `chmod -h -a`",
        account.name,
        account.uid,
        root.display()
    )
}

pub(crate) fn remove_enrollment_file(
    agents: &maknae_io::Anchor,
    agent: &AgentId,
) -> Result<(), EnrollError> {
    for file in [
        maknae_config::AGENT_CLIENT_FILE,
        maknae_config::ENROLLMENT_FILE,
    ] {
        let rel = Path::new(agent.as_str()).join(file);
        match agents.remove(&rel, None) {
            Ok(_) => {}
            Err(e) if is_not_found(&e) => {}
            Err(e) => return Err(io_error(&Path::new(AGENTS_DIR).join(&rel), e)),
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
async fn sealed_secret_present(
    private: &maknae_io::Anchor,
    agent: &AgentId,
) -> Result<bool, EnrollError> {
    let path = super::agent::cred_path(agent);
    let leaf = path.file_name().map(PathBuf::from).unwrap_or_default();
    private
        .entry_identity(leaf.as_os_str())
        .map(|i| i.is_some())
        .map_err(|e| io_error(&path, e))
}

#[cfg(not(target_os = "macos"))]
fn remove_sealed_secret_file(
    private: &maknae_io::Anchor,
    agent: &AgentId,
) -> Result<(), EnrollError> {
    let name = super::agent::cred_path(agent);
    let leaf = name.file_name().map(PathBuf::from).unwrap_or_default();
    private
        .remove(&leaf, None)
        .map(|_| ())
        .map_err(|e: IoError| io_error(&name, e))
}

struct RealRemoveOps {
    vault: RealVault,
    agents: maknae_io::Anchor,
    root: PathBuf,
    runner: Box<dyn agent_access::Run>,
    owner: Option<agent_access::Account>,
}

impl HasVault for RealRemoveOps {
    fn vault(&self) -> &RealVault {
        &self.vault
    }
}

impl RemoveOps for RealRemoveOps {
    #[cfg(not(target_os = "macos"))]
    fn stop_agent(&self, agent: &AgentId) -> Result<(), EnrollError> {
        agent_unit::stop(&*self.runner, agent, || {
            agent_unit::remove_drop_in(&open_dir(agent_unit::UNIT_DIR, 0o022)?, agent)
        })
    }

    #[cfg(target_os = "macos")]
    fn stop_agent(&self, agent: &AgentId) -> Result<(), EnrollError> {
        agent_launchd::stop(&*self.runner, agent, &mut std::thread::sleep, || {
            agent_launchd::remove_plist(&open_dir(agent_launchd::DAEMON_DIR, 0o022)?, agent)?;
            let logs = Path::new(agent_launchd::LOG_ROOT);
            if let Err(e) = agent_launchd::remove_log_dir(logs, agent) {
                errln!(
                    "maknae: {e}; remove {} by hand",
                    logs.join(agent.as_str()).display()
                );
            }
            Ok(())
        })
    }

    fn revoke_access(&self, agent: &AgentId) -> Result<(), EnrollError> {
        let Some(account) = &self.owner else {
            return Ok(());
        };
        let present = super::agent::present_own_files(&self.agents, agent)?;
        let resolves = matches!(maknae_io::user_by_name(&account.name), Ok(Some(_)));
        let revoked = agent_access::revoke(
            &*self.runner,
            agent_access::Platform::HOST,
            agent,
            account,
            resolves,
            &agent_access::revoke_entries(&self.root, agent, &present),
        )?;
        if revoked == agent_access::Revoked::Unresolved {
            errln!("{}", unresolved_warning(&self.root, account));
        }
        Ok(())
    }

    fn remove_enrollment(&self, agent: &AgentId) -> Result<(), EnrollError> {
        remove_enrollment_file(&self.agents, agent)
    }

    async fn remove_sealed_secret(&self, agent: &AgentId) -> Result<(), EnrollError> {
        #[cfg(target_os = "macos")]
        return super::keychain_write::delete_agent_secret_macos(agent).await;
        #[cfg(not(target_os = "macos"))]
        remove_sealed_secret_file(&self.vault.private, agent)
    }

    async fn leftovers(&self, agent: &AgentId) -> Result<Vec<String>, EnrollError> {
        let mut out = Vec::new();
        #[cfg(target_os = "macos")]
        let sealed = super::keychain_write::agent_secret_present_macos(agent).await?;
        #[cfg(not(target_os = "macos"))]
        let sealed = sealed_secret_present(&self.vault.private, agent).await?;
        if sealed {
            out.push("the sealed SecretID".to_string());
        }
        let state = super::agent::state_file(agent);
        let present = self
            .vault
            .private
            .entry_identity(std::ffi::OsStr::new(&state))
            .map_err(|e| io_error(&super::agent::state_path(agent), e))?;
        if present.is_some() {
            out.push("the enroll state file".to_string());
        }
        Ok(out)
    }

    fn remove_state(&self, agent: &AgentId) -> Result<(), EnrollError> {
        let leaf = super::agent::state_file(agent);
        self.vault
            .private
            .remove(Path::new(&leaf), None)
            .map(|_| ())
            .map_err(|e| io_error(&super::agent::state_path(agent), e))
    }
}

pub(crate) async fn run_remove_agent(
    args: &RemoveAgentArgs,
    locale: Locale,
) -> Result<String, EnrollError> {
    let euid = nix::unistd::geteuid().as_raw();
    let sudo_uid = super::env_u32("SUDO_UID");
    let sudo_user = std::env::var("SUDO_USER").ok();
    super::preflight_check(euid, sudo_uid, sudo_user.as_deref(), &super::RealPasswd)
        .inspect_err(|_| errln!("{}", msg(locale, MsgId::EnrollPreflightFailed)))?;

    let agent = AgentId::parse(&args.id)?;
    let host = read_host()?;
    check_mount("maknae.yaml vault.approle_mount", &host.approle_mount)?;

    let agents = open_dir(AGENTS_DIR, 0o022)?;
    let _lock = agents.try_lock_exclusive().map_err(|e| match e {
        IoError::Locked { .. } => {
            EnrollError::State("another maknae enroll command is running".to_string())
        }
        e => io_error(Path::new(AGENTS_DIR), e),
    })?;
    let private = open_dir(PRIVATE_DIR, 0o027)?;

    let (record, _) = read_records(&agents, &agent)?;
    let mut state = read_state(&private, &agent)?;
    let mount = resolve_mount(
        &agent,
        record.as_ref().map(|r| r.approle_mount.as_str()),
        &state.approle_mount,
        &host.approle_mount,
    )?;
    check_mount("the agent's AppRole mount", &mount)?;
    state.approle_mount = mount;
    state.role = agent.role_name();

    let token = super::intake_token_from(args.token_file.as_deref(), locale)?;
    let client = maknae_vault::OperatorClient::new(&host.vault_addr, Path::new(VAULT_CA), token)?;
    println!(
        "{}",
        msg(locale, MsgId::EnrollAgentRemoveStarted).replace("{agent}", agent.as_str())
    );
    let ops = RealRemoveOps {
        vault: RealVault { client, private },
        agents,
        root: PathBuf::from(super::agent::ETC_DIR),
        runner: Box::new(agent_access::Host),
        owner: record.map(|r| agent_access::Account {
            name: r.account,
            uid: r.uid,
        }),
    };
    let out = remove_agent(&ops, &agent, state).await?;
    Ok(summary(locale, &agent, &out))
}

#[cfg(test)]
mod tests {
    use super::super::agent::tests::{
        entity_facts, strings, Fake, ENTITY_MOUNT, MOUNT, ROLE, ROLE_ID,
    };
    use super::*;
    use clap::Parser;

    impl RemoveOps for Fake {
        fn stop_agent(&self, agent: &AgentId) -> Result<(), EnrollError> {
            self.log
                .borrow_mut()
                .push(format!("stop_agent {}", agent.as_str()));
            self.check("stop_agent")
        }

        fn revoke_access(&self, _agent: &AgentId) -> Result<(), EnrollError> {
            self.log.borrow_mut().push("revoke_access".into());
            self.check("revoke_access")
        }

        fn remove_enrollment(&self, _agent: &AgentId) -> Result<(), EnrollError> {
            self.log.borrow_mut().push("remove_enrollment".into());
            self.check("remove_enrollment")
        }

        async fn remove_sealed_secret(&self, _agent: &AgentId) -> Result<(), EnrollError> {
            self.log.borrow_mut().push("remove_sealed_secret".into());
            self.check("remove_sealed_secret")
        }

        fn remove_state(&self, _agent: &AgentId) -> Result<(), EnrollError> {
            self.log.borrow_mut().push("remove_state".into());
            self.check("remove_state")
        }

        async fn leftovers(&self, _agent: &AgentId) -> Result<Vec<String>, EnrollError> {
            Ok(self
                .present
                .borrow()
                .clone()
                .unwrap_or_else(|| strings(&["the sealed SecretID", "the enroll state file"])))
        }
    }

    fn hobi() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    fn state(live: &[&str], pending: &[&str], retiring: &[&str]) -> AgentState {
        AgentState {
            approle_mount: MOUNT.into(),
            role: ROLE.into(),
            live: strings(live),
            pending: strings(pending),
            retiring: strings(retiring),
        }
    }

    #[tokio::test]
    async fn remove_runs_in_order() {
        let fake = Fake::default().listing(&["l", "a"]);
        let out = remove_agent(&fake, &hobi(), state(&["a"], &["p"], &["r"]))
            .await
            .unwrap();
        assert_eq!(
            fake.log(),
            strings(&[
                "stop_agent hobi",
                "revoke_access",
                "remove_enrollment",
                "read_role_id",
                "entity maknae-agent-hobi",
                "set_entity_disabled maknae-agent-hobi true",
                "list",
                "state",
                "destroy:a",
                "destroy:p",
                "destroy:r",
                "destroy:l",
                "remove_sealed_secret",
                "remove_state",
            ])
        );
        assert_eq!(fake.states(), vec![state(&[], &[], &["a", "p", "r", "l"])]);
        assert_eq!(
            out,
            RemoveOutcome {
                destroyed: 4,
                role_absent: false
            }
        );
    }

    #[tokio::test]
    async fn a_failed_stop_removes_nothing() {
        let fake = Fake::failing(&["stop_agent"]);
        let e = remove_agent(&fake, &hobi(), state(&["a"], &[], &[]))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "stop_agent failed"),
            "{e:?}"
        );
        assert_eq!(fake.log(), strings(&["stop_agent hobi"]));
    }

    #[tokio::test]
    async fn a_failed_revoke_removes_nothing() {
        let fake = Fake::failing(&["revoke_access"]);
        let e = remove_agent(&fake, &hobi(), state(&["a"], &[], &[]))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "revoke_access failed"),
            "{e:?}"
        );
        assert_eq!(fake.log(), strings(&["stop_agent hobi", "revoke_access"]));
    }

    type Host = std::rc::Rc<agent_access::tests::FakeHost>;

    fn revoking_ops(
        tag: &str,
        owner: Option<agent_access::Account>,
    ) -> (
        super::super::agent::tests::Scratch,
        super::super::agent::tests::Scratch,
        RealRemoveOps,
        Host,
    ) {
        use super::super::agent::tests::{scratch_anchor, unreachable_vault};
        let (agents_dir, agents) = scratch_anchor(&format!("{tag}-agents"));
        let (private_dir, private) = scratch_anchor(&format!("{tag}-private"));
        std::fs::create_dir(agents_dir.join("hobi")).unwrap();
        let host = Host::default();
        let ops = RealRemoveOps {
            vault: unreachable_vault(tag, private),
            agents,
            root: agents_dir.to_path_buf(),
            runner: Box::new(host.clone()),
            owner,
        };
        (agents_dir, private_dir, ops, host)
    }

    fn me() -> agent_access::Account {
        let uid = nix::unistd::geteuid();
        agent_access::Account {
            name: nix::unistd::User::from_uid(uid).unwrap().unwrap().name,
            uid: uid.as_raw(),
        }
    }

    #[test]
    fn revoke_without_a_record_has_no_account_to_revoke() {
        let (_a, _p, ops, host) = revoking_ops("rm-noowner", None);
        assert!(ops.revoke_access(&hobi()).is_ok());
        assert!(host.calls().is_empty());
    }

    #[test]
    fn revoke_reads_every_grant_entry_whose_file_is_present() {
        let (d, _p, ops, host) = revoking_ops("rm-present", Some(me()));
        std::fs::write(d.join("hobi").join(maknae_config::ENROLLMENT_FILE), "x").unwrap();
        std::fs::write(d.join("hobi").join(maknae_config::PERSONA_FILE), "x").unwrap();
        ops.revoke_access(&hobi()).unwrap();
        let calls = host.calls();
        assert_eq!(calls.len(), 9, "{calls:?}");
        assert!(calls.iter().any(|c| c.ends_with("/hobi/enrollment.yaml")));
        assert!(calls.iter().any(|c| c.ends_with("/hobi/persona.md")));
        assert!(!calls.iter().any(|c| c.ends_with("/hobi/agent.yaml")));
        let root = d.display().to_string();
        assert!(calls.iter().all(|c| c.contains(&root)), "{calls:?}");
    }

    #[test]
    fn an_account_that_no_longer_exists_is_skipped_on_macos_only() {
        let gone = agent_access::Account {
            name: "maknae-test-no-such-account".into(),
            uid: 990,
        };
        let (_a, _p, ops, host) = revoking_ops("rm-gone", Some(gone.clone()));
        ops.revoke_access(&hobi()).unwrap();
        assert_eq!(
            host.calls().is_empty(),
            cfg!(target_os = "macos"),
            "{:?}",
            host.calls()
        );
        let text = unresolved_warning(Path::new("/etc/maknae"), &gone);
        assert!(
            text.contains("\"maknae-test-no-such-account\" (uid 990) no longer exists")
                && text.contains("/etc/maknae")
                && text.contains("chmod -h -a"),
            "{text}"
        );
    }

    #[test]
    fn a_failed_removal_leaves_the_enrollment_for_the_rerun() {
        let d = scratch("partial");
        let own = d.join("hobi");
        std::fs::write(own.join(maknae_config::AGENT_CLIENT_FILE), "x").unwrap();
        std::fs::create_dir(own.join(maknae_config::ENROLLMENT_FILE)).unwrap();
        std::fs::write(own.join(maknae_config::ENROLLMENT_FILE).join("x"), "x").unwrap();
        let agents = maknae_io::open_anchor(
            &d,
            maknae_io::AnchorRequired {
                owner: None,
                mode_mask: None,
            },
            maknae_io::StrategyPref::Auto,
        )
        .unwrap();
        assert!(remove_enrollment_file(&agents, &hobi()).is_err());
        assert!(!own.join(maknae_config::AGENT_CLIENT_FILE).exists());
        assert!(own.join(maknae_config::ENROLLMENT_FILE).exists());
        std::fs::remove_dir_all(own.join(maknae_config::ENROLLMENT_FILE)).unwrap();
        std::fs::write(own.join(maknae_config::ENROLLMENT_FILE), "x").unwrap();
        remove_enrollment_file(&agents, &hobi()).unwrap();
        assert!(!own.join(maknae_config::ENROLLMENT_FILE).exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn remove_never_names_another_agent_or_the_daemons_mount() {
        let fake = Fake::default().listing(&["l"]);
        remove_agent(&fake, &hobi(), state(&["a"], &[], &[]))
            .await
            .unwrap();
        let scopes = fake.scopes.borrow().clone();
        assert!(!scopes.is_empty());
        for (mount, role) in &scopes {
            assert_eq!(mount, MOUNT);
            assert_eq!(role, ROLE);
        }
        for line in fake.log() {
            assert!(!line.contains("lease"), "{line}");
            if line.starts_with("entity ") || line.starts_with("set_entity_disabled ") {
                assert!(line.contains("maknae-agent-hobi"), "{line}");
            }
        }
    }

    #[tokio::test]
    async fn a_missing_entity_is_refused_and_names_what_remains() {
        let other_role = entity_facts(false, &[(ENTITY_MOUNT, "another-role-id")]);
        let other_mount = entity_facts(false, &[("auth/other/", ROLE_ID)]);
        for entity in [
            None,
            Some(entity_facts(false, &[])),
            Some(other_mount),
            Some(other_role),
        ] {
            let fake = Fake::default().with_entity(entity);
            let e = remove_agent(&fake, &hobi(), state(&["a"], &["p"], &[]))
                .await
                .unwrap_err();
            assert!(
                matches!(&e, EnrollError::AgentEntityMissing { agent, entity, mount, remains }
                    if agent == "hobi" && entity == "maknae-agent-hobi" && mount == MOUNT && !remains.is_empty()),
                "{e:?}"
            );
            let shown = e.to_string();
            assert!(
                shown.contains("sealed SecretID")
                    && shown.contains("state file")
                    && shown.contains("a, p"),
                "{shown}"
            );
            assert_eq!(
                fake.log(),
                strings(&[
                    "stop_agent hobi",
                    "revoke_access",
                    "remove_enrollment",
                    "read_role_id",
                    "entity maknae-agent-hobi"
                ])
            );
        }
    }

    #[tokio::test]
    async fn a_failed_destroy_keeps_the_accessor_recorded() {
        let fake = Fake::failing(&["destroy:b"]);
        let e = remove_agent(&fake, &hobi(), state(&["a", "b"], &[], &[]))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentRemoveRetireFailed { agent, accessors }
                if agent == "hobi" && *accessors == strings(&["b"])),
            "{e:?}"
        );
        assert_eq!(fake.states().last(), Some(&state(&[], &[], &["b"])));
        let log = fake.log();
        assert_eq!(log.last().map(String::as_str), Some("state"));
        assert!(!log.contains(&"remove_sealed_secret".to_string()));
        assert!(!log.contains(&"remove_state".to_string()));
    }

    #[tokio::test]
    async fn a_failed_entity_disable_destroys_nothing() {
        let fake = Fake::failing(&["set_entity_disabled"]);
        remove_agent(&fake, &hobi(), state(&["a"], &[], &[]))
            .await
            .unwrap_err();
        assert!(!fake.log().iter().any(|l| l.starts_with("destroy:")));
        assert!(!fake.log().contains(&"remove_sealed_secret".to_string()));
    }

    #[tokio::test]
    async fn an_enrollment_removal_failure_touches_nothing_else() {
        let fake = Fake::failing(&["remove_enrollment"]);
        remove_agent(&fake, &hobi(), state(&["a"], &[], &[]))
            .await
            .unwrap_err();
        assert_eq!(
            fake.log(),
            strings(&["stop_agent hobi", "revoke_access", "remove_enrollment"])
        );
    }

    #[test]
    fn remove_agent_tells_the_operator_to_reload() {
        let out = summary(
            Locale::EnUs,
            &hobi(),
            &RemoveOutcome {
                destroyed: 2,
                role_absent: false,
            },
        );
        assert!(out.contains(RELOAD_COMMAND), "{out}");
        assert!(out.contains("hobi") && out.contains('2'), "{out}");
        assert!(out.contains("policy.yaml"), "{out}");
    }

    #[tokio::test]
    async fn a_missing_role_completes_locally_and_skips_vault() {
        let fake = Fake::failing(&["role_missing"]).with_entity(None);
        let out = remove_agent(&fake, &hobi(), state(&["a"], &["p"], &[]))
            .await
            .unwrap();
        assert_eq!(
            fake.log(),
            strings(&[
                "stop_agent hobi",
                "revoke_access",
                "remove_enrollment",
                "read_role_id",
                "entity maknae-agent-hobi",
                "remove_sealed_secret",
                "remove_state",
            ])
        );
        assert_eq!(
            out,
            RemoveOutcome {
                destroyed: 0,
                role_absent: true
            }
        );
    }

    #[tokio::test]
    async fn a_missing_role_with_a_live_entity_refuses_and_keeps_local_files() {
        let fake = Fake::failing(&["role_missing"]);
        let e = remove_agent(&fake, &hobi(), state(&["a"], &[], &[]))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentRoleMissing { mount, entity, remains, .. }
                if mount == MOUNT && entity == "maknae-agent-hobi" && !remains.is_empty()),
            "{e:?}"
        );
        let shown = e.to_string();
        assert!(
            shown.contains("role was not found") && shown.contains("still exists"),
            "{shown}"
        );
        let log = fake.log();
        assert!(!log.contains(&"remove_sealed_secret".to_string()));
        assert!(!log.contains(&"remove_state".to_string()));
        assert!(!log
            .iter()
            .any(|l| l.starts_with("destroy:") || l.starts_with("set_entity")));
    }

    #[tokio::test]
    async fn a_role_read_error_that_is_not_a_404_refuses() {
        let fake = Fake::failing(&["find_role_id"]);
        remove_agent(&fake, &hobi(), state(&["a"], &[], &[]))
            .await
            .unwrap_err();
        assert_eq!(
            fake.log(),
            strings(&[
                "stop_agent hobi",
                "revoke_access",
                "remove_enrollment",
                "read_role_id"
            ])
        );
    }

    #[tokio::test]
    async fn a_present_role_with_a_missing_entity_still_refuses() {
        let fake = Fake::default().with_entity(None);
        let e = remove_agent(&fake, &hobi(), state(&["a"], &[], &[]))
            .await
            .unwrap_err();
        assert!(matches!(e, EnrollError::AgentEntityMissing { .. }), "{e:?}");
        assert!(!fake.log().contains(&"remove_sealed_secret".to_string()));
    }

    #[tokio::test]
    async fn remains_names_only_what_exists() {
        let fake = Fake::default().with_entity(None);
        *fake.present.borrow_mut() = Some(Vec::new());
        let e = remove_agent(&fake, &hobi(), state(&[], &[], &[]))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentEntityMissing { remains, .. } if remains.is_empty()),
            "{e:?}"
        );
        let fake = Fake::default().with_entity(None);
        *fake.present.borrow_mut() = Some(strings(&["the enroll state file"]));
        let e = remove_agent(&fake, &hobi(), state(&["a"], &[], &[]))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentEntityMissing { remains, .. }
                if *remains == strings(&["the enroll state file", "SecretID accessors a"])),
            "{e:?}"
        );
    }

    #[test]
    fn an_absent_role_is_reported_in_the_summary() {
        let out = summary(
            Locale::EnUs,
            &hobi(),
            &RemoveOutcome {
                destroyed: 0,
                role_absent: true,
            },
        );
        assert!(
            out.contains("role and entity for agent hobi were already absent"),
            "{out}"
        );
        assert!(!out.contains("gone with"), "{out}");
        assert!(out.contains(RELOAD_COMMAND), "{out}");
    }

    #[test]
    fn resolve_mount_branches() {
        let a = hobi();
        let r = |rec, st, host| resolve_mount(&a, rec, st, host);
        assert_eq!(r(Some("m"), "", "d").unwrap(), "m");
        assert_eq!(r(None, "m", "d").unwrap(), "m");
        assert_eq!(r(Some("m"), "m", "d").unwrap(), "m");
        let e = r(None, "", "d").unwrap_err();
        assert!(e.to_string().contains("not enrolled"), "{e}");
        let e = r(Some("m1"), "m2", "d").unwrap_err();
        assert!(
            e.to_string().contains("m1") && e.to_string().contains("m2"),
            "{e}"
        );
        let e = r(Some("d"), "", "d").unwrap_err();
        assert!(matches!(e, EnrollError::AgentMountIsDaemons(m) if m == "d"));
        let e = r(None, "d", "d").unwrap_err();
        assert!(matches!(e, EnrollError::AgentMountIsDaemons(_)));
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("maknae-rm-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("hobi")).unwrap();
        d
    }

    #[test]
    fn remove_leaves_policy_yaml() {
        let d = scratch("policy");
        std::fs::write(d.join("hobi").join(maknae_config::ENROLLMENT_FILE), "x").unwrap();
        std::fs::write(d.join("hobi").join("policy.yaml"), "subjects: []").unwrap();
        std::fs::write(d.join("hobi").join(maknae_config::AGENT_CLIENT_FILE), "x").unwrap();
        std::fs::write(
            d.join("hobi").join(maknae_config::PERSONA_FILE),
            "You are hobi.",
        )
        .unwrap();
        let agents = maknae_io::open_anchor(
            &d,
            maknae_io::AnchorRequired {
                owner: None,
                mode_mask: None,
            },
            maknae_io::StrategyPref::Auto,
        )
        .unwrap();
        remove_enrollment_file(&agents, &hobi()).unwrap();
        remove_enrollment_file(&agents, &hobi()).unwrap();
        assert!(!d.join("hobi").join(maknae_config::ENROLLMENT_FILE).exists());
        assert!(!d
            .join("hobi")
            .join(maknae_config::AGENT_CLIENT_FILE)
            .exists());
        assert!(d.join("hobi").join(maknae_config::PERSONA_FILE).exists());
        assert_eq!(
            std::fs::read_to_string(d.join("hobi").join("policy.yaml")).unwrap(),
            "subjects: []"
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_removed_agent_directory_counts_as_removed() {
        let d = scratch("gone");
        let agents = maknae_io::open_anchor(
            &d,
            maknae_io::AnchorRequired {
                owner: None,
                mode_mask: None,
            },
            maknae_io::StrategyPref::Auto,
        )
        .unwrap();
        std::fs::remove_dir_all(d.join("hobi")).unwrap();
        remove_enrollment_file(&agents, &hobi()).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_non_directory_at_the_agent_path_still_refuses() {
        let d = scratch("notdir");
        let agents = maknae_io::open_anchor(
            &d,
            maknae_io::AnchorRequired {
                owner: None,
                mode_mask: None,
            },
            maknae_io::StrategyPref::Auto,
        )
        .unwrap();
        std::fs::remove_dir_all(d.join("hobi")).unwrap();
        std::os::unix::fs::symlink("/tmp", d.join("hobi")).unwrap();
        assert!(remove_enrollment_file(&agents, &hobi()).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[derive(Parser, Debug)]
    struct Cli {
        #[command(flatten)]
        args: RemoveAgentArgs,
    }

    #[test]
    fn the_token_comes_from_a_file_or_the_prompt_never_an_argument() {
        let ok = Cli::try_parse_from(["maknae", "hobi", "--token-file", "/t"]).unwrap();
        assert_eq!(ok.args.token_file, Some(PathBuf::from("/t")));
        assert!(Cli::try_parse_from(["maknae", "hobi", "--token", "s.x"]).is_err());
        assert!(Cli::try_parse_from(["maknae"]).is_err());
    }

    #[tokio::test]
    async fn a_missing_role_names_recorded_accessors_only_when_there_are_some() {
        let present = strings(&["the sealed SecretID", "the enroll state file"]);
        for (recorded, extra) in [
            (&[][..], None),
            (&["a", "p"][..], Some("SecretID accessors a, p")),
        ] {
            let fake = Fake::failing(&["role_missing"]);
            let e = remove_agent(&fake, &hobi(), state(recorded, &[], &[]))
                .await
                .unwrap_err();
            let mut want = present.clone();
            want.extend(extra.map(String::from));
            assert!(
                matches!(&e, EnrollError::AgentRoleMissing { remains, .. } if *remains == want),
                "{e:?}"
            );
        }
    }

    fn real_remove_ops(
        tag: &str,
    ) -> (
        super::super::agent::tests::Scratch,
        super::super::agent::tests::Scratch,
        RealRemoveOps,
    ) {
        use super::super::agent::tests::{scratch_anchor, unreachable_vault};
        let (agents_dir, agents) = scratch_anchor(&format!("{tag}-agents"));
        let (private_dir, private) = scratch_anchor(&format!("{tag}-private"));
        let ops = RealRemoveOps {
            vault: unreachable_vault(tag, private),
            agents,
            root: agents_dir.to_path_buf(),
            runner: Box::new(agent_access::tests::FakeHost::default()),
            owner: None,
        };
        (agents_dir, private_dir, ops)
    }

    #[cfg(not(target_os = "macos"))]
    fn sealed_leaf() -> PathBuf {
        PathBuf::from(super::super::agent::cred_path(&hobi()).file_name().unwrap())
    }

    #[test]
    fn real_remove_enrollment_unlinks_the_record() {
        let (agents_dir, _private_dir, ops) = real_remove_ops("rm-enrollment");
        let record = agents_dir.join("hobi").join(maknae_config::ENROLLMENT_FILE);
        std::fs::create_dir(agents_dir.join("hobi")).unwrap();
        std::fs::write(&record, "x").unwrap();
        ops.remove_enrollment(&hobi()).unwrap();
        assert!(!record.exists());
    }

    #[test]
    fn real_remove_state_unlinks_the_state_file() {
        let (_agents_dir, private_dir, ops) = real_remove_ops("rm-state");
        let path = private_dir.join(super::super::agent::state_file(&hobi()));
        std::fs::write(&path, "x").unwrap();
        ops.remove_state(&hobi()).unwrap();
        assert!(!path.exists());
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn real_leftovers_name_what_is_on_disk_and_removal_clears_it() {
        let (_agents_dir, private_dir, ops) = real_remove_ops("rm-leftovers");
        assert_eq!(ops.leftovers(&hobi()).await.unwrap(), Vec::<String>::new());
        let sealed = private_dir.join(sealed_leaf());
        std::fs::write(&sealed, "x").unwrap();
        assert!(sealed_secret_present(&ops.vault.private, &hobi())
            .await
            .unwrap());
        assert_eq!(
            ops.leftovers(&hobi()).await.unwrap(),
            strings(&["the sealed SecretID"])
        );
        std::fs::write(
            private_dir.join(super::super::agent::state_file(&hobi())),
            "x",
        )
        .unwrap();
        assert_eq!(
            ops.leftovers(&hobi()).await.unwrap(),
            strings(&["the sealed SecretID", "the enroll state file"])
        );
        ops.remove_sealed_secret(&hobi()).await.unwrap();
        assert!(!sealed.exists());
        assert!(!sealed_secret_present(&ops.vault.private, &hobi())
            .await
            .unwrap());
        ops.remove_state(&hobi()).unwrap();
        assert_eq!(ops.leftovers(&hobi()).await.unwrap(), Vec::<String>::new());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn real_leftovers_on_macos_name_the_state_file_and_no_unsealed_secret() {
        let (_agents_dir, private_dir, ops) = real_remove_ops("rm-leftovers-macos");
        let id = AgentId::parse("neversealedprobe").unwrap();
        assert_eq!(ops.leftovers(&id).await.unwrap(), Vec::<String>::new());
        std::fs::write(private_dir.join(super::super::agent::state_file(&id)), "x").unwrap();
        assert_eq!(
            ops.leftovers(&id).await.unwrap(),
            strings(&["the enroll state file"])
        );
        ops.remove_state(&id).unwrap();
        assert_eq!(ops.leftovers(&id).await.unwrap(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn run_remove_agent_off_root_is_refused_before_anything_else() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let cli = Cli::try_parse_from(["maknae", "hobi"]).unwrap();
        let got = run_remove_agent(&cli.args, Locale::EnUs).await;
        assert!(matches!(got, Err(EnrollError::NotRoot)), "{got:?}");
    }
}
