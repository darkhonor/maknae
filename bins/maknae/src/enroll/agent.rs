use super::artifact_write::{emit_yaml, yaml_map};
use super::EnrollError;
use maknae_config::Value;
use maknae_vault::agent_enroll::{AgentId, BindCidrs};
use yaml_rust2::Yaml;
use zeroize::Zeroizing;

#[cfg_attr(not(test), expect(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostEnrollment {
    pub vault_addr: String,
    pub approle_mount: String,
    pub principal_uid: u32,
}

#[cfg_attr(not(test), expect(dead_code))]
pub(crate) fn parse_host_enrollment(text: &str) -> Result<HostEnrollment, EnrollError> {
    let doc = maknae_config::load_str(text)
        .map_err(|e| EnrollError::State(format!("maknae.yaml: {e:?}")))?;
    let missing = |key: &str| EnrollError::HostNotEnrolled(format!("maknae.yaml has no {key}"));
    let vault = field(&doc, "vault").ok_or_else(|| missing("vault"))?;
    let principal = field(&doc, "principal").ok_or_else(|| missing("principal"))?;
    let vault_addr = str_field(vault, "addr").ok_or_else(|| missing("vault.addr"))?;
    let approle_mount =
        str_field(vault, "approle_mount").ok_or_else(|| missing("vault.approle_mount"))?;
    let principal_uid = match field(principal, "uid") {
        Some(Value::Int(n)) => u32::try_from(*n).ok(),
        _ => None,
    }
    .ok_or_else(|| missing("principal.uid"))?;
    Ok(HostEnrollment {
        vault_addr,
        approle_mount,
        principal_uid,
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AgentState {
    pub approle_mount: String,
    pub role: String,
    pub live: Vec<String>,
    pub pending: Vec<String>,
    pub retiring: Vec<String>,
}

impl AgentState {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn to_yaml(&self) -> String {
        emit_yaml(yaml_map(vec![
            ("approle_mount", Yaml::String(self.approle_mount.clone())),
            ("role", Yaml::String(self.role.clone())),
            ("live", yaml_list(&self.live)),
            ("pending", yaml_list(&self.pending)),
            ("retiring", yaml_list(&self.retiring)),
        ]))
    }

    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn parse(text: &str) -> Result<Self, EnrollError> {
        const WHAT: &str = "agent enroll state";
        let doc = load(text, WHAT)?;
        Ok(Self {
            approle_mount: req_str(&doc, "approle_mount", WHAT)?,
            role: req_str(&doc, "role", WHAT)?,
            live: req_list(&doc, "live", WHAT)?,
            pending: req_list(&doc, "pending", WHAT)?,
            retiring: req_list(&doc, "retiring", WHAT)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SecretSource {
    Tpm2,
    Keychain,
}

impl SecretSource {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Tpm2 => "tpm2",
            Self::Keychain => "keychain",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentRecord {
    pub agent_id: String,
    pub account: String,
    pub uid: u32,
    pub approle_mount: String,
    pub role_name: String,
    pub role_id: String,
    pub bind_cidrs: Vec<String>,
    pub source: SecretSource,
}

impl AgentRecord {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn to_yaml(&self) -> String {
        emit_yaml(yaml_map(vec![
            ("agent_id", Yaml::String(self.agent_id.clone())),
            ("account", Yaml::String(self.account.clone())),
            ("uid", Yaml::Integer(i64::from(self.uid))),
            ("approle_mount", Yaml::String(self.approle_mount.clone())),
            ("role_name", Yaml::String(self.role_name.clone())),
            ("role_id", Yaml::String(self.role_id.clone())),
            ("bind_cidrs", yaml_list(&self.bind_cidrs)),
            ("source", Yaml::String(self.source.as_str().to_string())),
        ]))
    }

    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn parse(text: &str) -> Result<Self, EnrollError> {
        const WHAT: &str = "agent record";
        let doc = load(text, WHAT)?;
        let uid = match field(&doc, "uid") {
            Some(Value::Int(n)) => u32::try_from(*n).ok(),
            _ => None,
        }
        .ok_or_else(|| EnrollError::State(format!("{WHAT}: uid is not a uid")))?;
        let source = match req_str(&doc, "source", WHAT)?.as_str() {
            "tpm2" => SecretSource::Tpm2,
            "keychain" => SecretSource::Keychain,
            other => {
                return Err(EnrollError::State(format!(
                    "{WHAT}: unknown source {other:?}"
                )))
            }
        };
        Ok(Self {
            agent_id: req_str(&doc, "agent_id", WHAT)?,
            account: req_str(&doc, "account", WHAT)?,
            uid,
            approle_mount: req_str(&doc, "approle_mount", WHAT)?,
            role_name: req_str(&doc, "role_name", WHAT)?,
            role_id: req_str(&doc, "role_id", WHAT)?,
            bind_cidrs: req_list(&doc, "bind_cidrs", WHAT)?,
            source,
        })
    }
}

#[cfg_attr(not(test), expect(dead_code))]
fn yaml_list(items: &[String]) -> Yaml {
    Yaml::Array(items.iter().cloned().map(Yaml::String).collect())
}

fn load(text: &str, what: &str) -> Result<Value, EnrollError> {
    let doc =
        maknae_config::load_str(text).map_err(|e| EnrollError::State(format!("{what}: {e:?}")))?;
    match doc {
        Value::Map(_) => Ok(doc),
        _ => Err(EnrollError::State(format!("{what} is not a map"))),
    }
}

fn field<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    match field(v, key) {
        Some(Value::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

fn req_str(doc: &Value, key: &str, what: &str) -> Result<String, EnrollError> {
    str_field(doc, key).ok_or_else(|| EnrollError::State(format!("{what}: {key} is missing")))
}

fn req_list(doc: &Value, key: &str, what: &str) -> Result<Vec<String>, EnrollError> {
    let bad = || EnrollError::State(format!("{what}: {key} is not a list of strings"));
    match field(doc, key) {
        Some(Value::Seq(items)) => items
            .iter()
            .map(|i| match i {
                Value::Str(s) => Ok(s.clone()),
                _ => Err(bad()),
            })
            .collect(),
        _ => Err(bad()),
    }
}

pub(crate) trait AgentOps {
    async fn read_role_id(&self, mount: &str, role: &str) -> Result<String, EnrollError>;
    async fn mint(
        &self,
        mount: &str,
        role: &str,
        cidrs: &BindCidrs,
    ) -> Result<(Zeroizing<String>, String), EnrollError>;
    async fn destroy(&self, mount: &str, role: &str, accessor: &str) -> Result<(), EnrollError>;
    async fn seal(
        &self,
        agent: &AgentId,
        secret: &Zeroizing<String>,
    ) -> Result<SecretSource, EnrollError>;
    fn write_state(&self, agent: &AgentId, state: &AgentState) -> Result<(), EnrollError>;
    fn write_record(&self, record: &AgentRecord) -> Result<(), EnrollError>;
}

#[cfg_attr(not(test), expect(dead_code))]
pub(crate) struct AgentPlan {
    pub agent: AgentId,
    pub account: String,
    pub uid: u32,
    pub mount: String,
    pub cidrs: BindCidrs,
    pub rotate: bool,
}

#[cfg_attr(not(test), expect(dead_code))]
#[derive(Debug)]
pub(crate) struct AgentOutcome {
    pub record: AgentRecord,
    pub retired: usize,
}

#[cfg_attr(not(test), expect(dead_code))]
pub(crate) async fn enroll_agent<O: AgentOps>(
    ops: &O,
    plan: &AgentPlan,
    host: &HostEnrollment,
    prior_record: Option<&AgentRecord>,
    prior_state: AgentState,
) -> Result<AgentOutcome, EnrollError> {
    let id = plan.agent.as_str();
    let refuse =
        |field: &'static str, recorded: &str, given: &str| EnrollError::AgentRekeyRefused {
            agent: id.to_string(),
            field,
            recorded: recorded.to_string(),
            given: given.to_string(),
        };
    if plan.mount == host.approle_mount {
        return Err(EnrollError::AgentMountIsDaemons(plan.mount.clone()));
    }
    if let Some(r) = prior_record {
        if !plan.rotate {
            return Err(EnrollError::AgentAlreadyEnrolled(id.to_string()));
        }
        if r.account != plan.account {
            return Err(refuse("account", &r.account, &plan.account));
        }
        if r.approle_mount != plan.mount {
            return Err(refuse("approle_mount", &r.approle_mount, &plan.mount));
        }
    }
    if !prior_state.approle_mount.is_empty() && prior_state.approle_mount != plan.mount {
        return Err(refuse(
            "approle_mount",
            &prior_state.approle_mount,
            &plan.mount,
        ));
    }

    let mount = plan.mount.as_str();
    let role = plan.agent.role_name();
    let role_id = ops.read_role_id(mount, &role).await?;
    let (secret, acc) = ops.mint(mount, &role, &plan.cidrs).await?;

    let base = AgentState {
        approle_mount: plan.mount.clone(),
        role: role.clone(),
        ..prior_state
    };
    let mut pending = base.clone();
    pending.pending.push(acc.clone());
    if let Err(e) = ops.write_state(&plan.agent, &pending) {
        drop(secret);
        return Err(match ops.destroy(mount, &role, &acc).await {
            Ok(()) => e,
            Err(_) => EnrollError::AgentOrphanedAccessor {
                accessor: acc,
                cause: e.to_string(),
            },
        });
    }

    let sealed = ops.seal(&plan.agent, &secret).await;
    drop(secret);
    let source = match sealed {
        Ok(source) => source,
        Err(e) => {
            return Err(match ops.destroy(mount, &role, &acc).await {
                Ok(()) => {
                    let _ = ops.write_state(&plan.agent, &base);
                    e
                }
                Err(_) => EnrollError::AgentOrphanedAccessor {
                    accessor: acc,
                    cause: e.to_string(),
                },
            });
        }
    };

    let retiring = dedup(base.live.iter().chain(&base.pending).chain(&base.retiring));
    let record = AgentRecord {
        agent_id: id.to_string(),
        account: plan.account.clone(),
        uid: plan.uid,
        approle_mount: plan.mount.clone(),
        role_name: role.clone(),
        role_id,
        bind_cidrs: plan.cidrs.as_slice().to_vec(),
        source,
    };
    ops.write_record(&record)?;
    let live = AgentState {
        live: vec![acc],
        pending: Vec::new(),
        retiring: retiring.clone(),
        ..base
    };
    ops.write_state(&plan.agent, &live)?;

    let mut failures = Vec::new();
    for a in &retiring {
        if ops.destroy(mount, &role, a).await.is_err() {
            failures.push(a.clone());
        }
    }
    let retired = retiring.len() - failures.len();
    let done = AgentState {
        retiring: failures.clone(),
        ..live
    };
    ops.write_state(&plan.agent, &done)?;
    if !failures.is_empty() {
        return Err(EnrollError::AgentRetireFailed {
            agent: id.to_string(),
            accessors: failures,
        });
    }
    Ok(AgentOutcome { record, retired })
}

fn dedup<'a>(items: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for i in items {
        if !out.contains(i) {
            out.push(i.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::HashSet;

    const SENTINEL: &str = "5ec7e7aa-0000-4000-8000-5ec7e7aa0000";
    const ROLE_ID: &str = "role-uuid-1111-2222-3333-444455556666";

    #[derive(Default)]
    struct Fake {
        log: RefCell<Vec<String>>,
        fail: RefCell<HashSet<String>>,
        states: RefCell<Vec<AgentState>>,
        written: RefCell<Vec<u8>>,
        sealed: RefCell<Vec<String>>,
        state_calls: Cell<usize>,
    }

    impl Fake {
        fn failing(keys: &[&str]) -> Self {
            let f = Fake::default();
            f.fail
                .borrow_mut()
                .extend(keys.iter().map(|k| k.to_string()));
            f
        }

        fn check(&self, key: &str) -> Result<(), EnrollError> {
            if self.fail.borrow().contains(key) {
                Err(EnrollError::State(format!("{key} failed")))
            } else {
                Ok(())
            }
        }

        fn log(&self) -> Vec<String> {
            self.log.borrow().clone()
        }

        fn states(&self) -> Vec<AgentState> {
            self.states.borrow().clone()
        }
    }

    impl AgentOps for Fake {
        async fn read_role_id(&self, _mount: &str, _role: &str) -> Result<String, EnrollError> {
            self.log.borrow_mut().push("read_role_id".into());
            Ok(ROLE_ID.into())
        }

        async fn mint(
            &self,
            mount: &str,
            role: &str,
            cidrs: &BindCidrs,
        ) -> Result<(Zeroizing<String>, String), EnrollError> {
            self.log.borrow_mut().push(format!(
                "mint:{mount}:{role}:{}",
                cidrs.as_slice().join(",")
            ));
            self.check("mint")?;
            Ok((Zeroizing::new(SENTINEL.into()), "acc-new".into()))
        }

        async fn destroy(
            &self,
            _mount: &str,
            _role: &str,
            accessor: &str,
        ) -> Result<(), EnrollError> {
            let key = format!("destroy:{accessor}");
            self.log.borrow_mut().push(key.clone());
            self.check(&key)
        }

        async fn seal(
            &self,
            _agent: &AgentId,
            secret: &Zeroizing<String>,
        ) -> Result<SecretSource, EnrollError> {
            self.log.borrow_mut().push("seal".into());
            self.sealed.borrow_mut().push(secret.to_string());
            self.check("seal")?;
            Ok(SecretSource::Tpm2)
        }

        fn write_state(&self, _agent: &AgentId, state: &AgentState) -> Result<(), EnrollError> {
            self.log.borrow_mut().push("state".into());
            let n = self.state_calls.get() + 1;
            self.state_calls.set(n);
            self.check(&format!("state#{n}"))?;
            self.states.borrow_mut().push(state.clone());
            self.written
                .borrow_mut()
                .extend_from_slice(state.to_yaml().as_bytes());
            Ok(())
        }

        fn write_record(&self, record: &AgentRecord) -> Result<(), EnrollError> {
            self.log.borrow_mut().push("record".into());
            self.check("record")?;
            self.written
                .borrow_mut()
                .extend_from_slice(record.to_yaml().as_bytes());
            Ok(())
        }
    }

    const MOUNT: &str = "maknae-agent-approle";
    const ROLE: &str = "agent-hobi";

    fn plan(rotate: bool) -> AgentPlan {
        AgentPlan {
            agent: AgentId::parse("hobi").unwrap(),
            account: "hobi-svc".into(),
            uid: 990,
            mount: MOUNT.into(),
            cidrs: BindCidrs::parse(&["10.0.0.5".to_string()]).unwrap(),
            rotate,
        }
    }

    fn host() -> HostEnrollment {
        HostEnrollment {
            vault_addr: "https://vault.example:8200".into(),
            approle_mount: "maknae-approle".into(),
            principal_uid: 1000,
        }
    }

    fn strings(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    fn record() -> AgentRecord {
        AgentRecord {
            agent_id: "hobi".into(),
            account: "hobi-svc".into(),
            uid: 990,
            approle_mount: MOUNT.into(),
            role_name: ROLE.into(),
            role_id: "role-uuid-old".into(),
            bind_cidrs: strings(&["10.0.0.5/32"]),
            source: SecretSource::Tpm2,
        }
    }

    fn prior(live: &[&str], pending: &[&str], retiring: &[&str]) -> (AgentRecord, AgentState) {
        (
            record(),
            AgentState {
                approle_mount: MOUNT.into(),
                role: ROLE.into(),
                live: strings(live),
                pending: strings(pending),
                retiring: strings(retiring),
            },
        )
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

    async fn first(fake: &Fake) -> Result<AgentOutcome, EnrollError> {
        enroll_agent(fake, &plan(false), &host(), None, AgentState::default()).await
    }

    async fn rotate(
        fake: &Fake,
        live: &[&str],
        pending: &[&str],
        retiring: &[&str],
    ) -> Result<AgentOutcome, EnrollError> {
        let (r, s) = prior(live, pending, retiring);
        enroll_agent(fake, &plan(true), &host(), Some(&r), s).await
    }

    #[tokio::test]
    async fn first_enrollment_order() {
        let fake = Fake::default();
        let out = first(&fake).await.unwrap();
        assert_eq!(
            fake.log(),
            strings(&[
                "read_role_id",
                "mint:maknae-agent-approle:agent-hobi:10.0.0.5/32",
                "state",
                "seal",
                "record",
                "state",
                "state",
            ])
        );
        assert_eq!(
            fake.states(),
            vec![
                state(&[], &["acc-new"], &[]),
                state(&["acc-new"], &[], &[]),
                state(&["acc-new"], &[], &[]),
            ]
        );
        assert_eq!(out.retired, 0);
        assert_eq!(
            out.record,
            AgentRecord {
                role_id: ROLE_ID.into(),
                ..record()
            }
        );
    }

    #[tokio::test]
    async fn mount_equal_to_maknaeds_is_refused_before_any_call() {
        let fake = Fake::default();
        let mut p = plan(false);
        p.mount = "maknae-approle".into();
        let e = enroll_agent(&fake, &p, &host(), None, AgentState::default())
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentMountIsDaemons(m) if m == "maknae-approle"),
            "{e:?}"
        );
        assert!(fake.log().is_empty());
    }

    #[tokio::test]
    async fn re_enroll_without_rotate_is_refused_before_any_call() {
        let fake = Fake::default();
        let (r, s) = prior(&["a"], &[], &[]);
        let e = enroll_agent(&fake, &plan(false), &host(), Some(&r), s)
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentAlreadyEnrolled(id) if id == "hobi"),
            "{e:?}"
        );
        assert!(fake.log().is_empty());
    }

    #[tokio::test]
    async fn rotate_with_a_different_account_is_refused_before_any_call() {
        let fake = Fake::default();
        let (mut r, s) = prior(&["a"], &[], &[]);
        r.account = "other-svc".into();
        let e = enroll_agent(&fake, &plan(true), &host(), Some(&r), s)
            .await
            .unwrap_err();
        match &e {
            EnrollError::AgentRekeyRefused {
                agent,
                field,
                recorded,
                given,
            } => {
                assert_eq!(agent, "hobi");
                assert_eq!(*field, "account");
                assert_eq!(recorded, "other-svc");
                assert_eq!(given, "hobi-svc");
            }
            other => panic!("{other:?}"),
        }
        assert!(fake.log().is_empty());
    }

    #[tokio::test]
    async fn rotate_with_a_different_mount_is_refused_before_any_call() {
        let fake = Fake::default();
        let (mut r, s) = prior(&["a"], &[], &[]);
        r.approle_mount = "old-mount".into();
        let e = enroll_agent(&fake, &plan(true), &host(), Some(&r), s)
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentRekeyRefused { field, recorded, given, .. }
                if *field == "approle_mount" && recorded == "old-mount" && given == MOUNT),
            "{e:?}"
        );
        assert!(fake.log().is_empty());
    }

    #[tokio::test]
    async fn a_state_file_on_a_different_mount_is_refused_before_any_call() {
        let fake = Fake::default();
        let mut s = state(&["a"], &[], &[]);
        s.approle_mount = "old-mount".into();
        let e = enroll_agent(&fake, &plan(false), &host(), None, s)
            .await
            .unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentRekeyRefused { field, recorded, .. }
                if *field == "approle_mount" && recorded == "old-mount"),
            "{e:?}"
        );
        assert!(fake.log().is_empty());
    }

    #[tokio::test]
    async fn rotate_retires_everything_previously_recorded() {
        let fake = Fake::default();
        let out = rotate(&fake, &["a"], &["p"], &["r"]).await.unwrap();
        assert_eq!(
            fake.log(),
            strings(&[
                "read_role_id",
                "mint:maknae-agent-approle:agent-hobi:10.0.0.5/32",
                "state",
                "seal",
                "record",
                "state",
                "destroy:a",
                "destroy:p",
                "destroy:r",
                "state",
            ])
        );
        assert_eq!(
            fake.states(),
            vec![
                state(&["a"], &["p", "acc-new"], &["r"]),
                state(&["acc-new"], &[], &["a", "p", "r"]),
                state(&["acc-new"], &[], &[]),
            ]
        );
        assert_eq!(out.retired, 3);
    }

    #[tokio::test]
    async fn retiring_deduplicates_the_prior_lists() {
        let fake = Fake::default();
        let out = rotate(&fake, &["a"], &["a", "p"], &["p", "r"])
            .await
            .unwrap();
        assert_eq!(fake.states()[1], state(&["acc-new"], &[], &["a", "p", "r"]));
        assert_eq!(out.retired, 3);
    }

    #[tokio::test]
    async fn a_rerun_after_a_partial_failure_completes() {
        let fake = Fake::default();
        let s = state(&[], &["acc-stale"], &["gone"]);
        let out = enroll_agent(&fake, &plan(false), &host(), None, s)
            .await
            .unwrap();
        assert_eq!(
            fake.log()[6..],
            strings(&["destroy:acc-stale", "destroy:gone", "state"])[..]
        );
        assert_eq!(fake.states().last(), Some(&state(&["acc-new"], &[], &[])));
        assert_eq!(out.retired, 2);
    }

    #[tokio::test]
    async fn a_failed_retire_stays_recorded_and_exits_non_zero() {
        let fake = Fake::failing(&["destroy:b"]);
        let e = rotate(&fake, &["a", "b"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentRetireFailed { agent, accessors }
                if agent == "hobi" && *accessors == strings(&["b"])),
            "{e:?}"
        );
        assert_eq!(
            fake.log()[5..],
            strings(&["state", "destroy:a", "destroy:b", "state"])[..]
        );
        assert_eq!(
            fake.states().last(),
            Some(&state(&["acc-new"], &[], &["b"]))
        );
    }

    #[tokio::test]
    async fn pending_write_failure_destroys_the_new_accessor_and_never_seals() {
        let fake = Fake::failing(&["state#1"]);
        let e = first(&fake).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "state#1 failed"),
            "{e:?}"
        );
        assert_eq!(
            fake.log(),
            strings(&[
                "read_role_id",
                "mint:maknae-agent-approle:agent-hobi:10.0.0.5/32",
                "state",
                "destroy:acc-new",
            ])
        );
        assert!(fake.sealed.borrow().is_empty());
        assert!(fake.states().is_empty());
    }

    #[tokio::test]
    async fn pending_write_failure_with_a_failed_destroy_names_the_orphan() {
        let fake = Fake::failing(&["state#1", "destroy:acc-new"]);
        let e = first(&fake).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentOrphanedAccessor { accessor, cause }
                if accessor == "acc-new" && cause == "state#1 failed"),
            "{e:?}"
        );
        assert!(!fake.log().contains(&"seal".to_string()));
    }

    #[tokio::test]
    async fn seal_failure_destroys_new_and_restores_prior() {
        let fake = Fake::failing(&["seal"]);
        let e = rotate(&fake, &["a"], &["p"], &["r"]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "seal failed"),
            "{e:?}"
        );
        assert_eq!(
            fake.log(),
            strings(&[
                "read_role_id",
                "mint:maknae-agent-approle:agent-hobi:10.0.0.5/32",
                "state",
                "seal",
                "destroy:acc-new",
                "state",
            ])
        );
        assert_eq!(
            fake.states(),
            vec![
                state(&["a"], &["p", "acc-new"], &["r"]),
                state(&["a"], &["p"], &["r"]),
            ]
        );
    }

    #[tokio::test]
    async fn seal_failure_on_first_enrollment_restores_an_empty_state_with_mount_and_role() {
        let fake = Fake::failing(&["seal"]);
        first(&fake).await.unwrap_err();
        assert_eq!(fake.states().last(), Some(&state(&[], &[], &[])));
    }

    #[tokio::test]
    async fn seal_failure_with_a_failed_destroy_keeps_it_pending_and_names_it() {
        let fake = Fake::failing(&["seal", "destroy:acc-new"]);
        let e = rotate(&fake, &["a"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::AgentOrphanedAccessor { accessor, cause }
                if accessor == "acc-new" && cause == "seal failed"),
            "{e:?}"
        );
        assert_eq!(
            fake.log().last().map(String::as_str),
            Some("destroy:acc-new")
        );
        let last = fake.states().last().cloned().unwrap();
        assert!(last.pending.contains(&"acc-new".to_string()));
        assert_eq!(last.live, strings(&["a"]));
    }

    #[tokio::test]
    async fn record_write_failure_keeps_the_new_accessor_recorded() {
        let fake = Fake::failing(&["record"]);
        let e = rotate(&fake, &["a"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "record failed"),
            "{e:?}"
        );
        assert!(!fake.log().iter().any(|l| l.starts_with("destroy:")));
        assert_eq!(fake.log().last().map(String::as_str), Some("record"));
        let last = fake.states().last().cloned().unwrap();
        assert!(last.pending.contains(&"acc-new".to_string()));
        assert_eq!(last.live, strings(&["a"]));
    }

    #[tokio::test]
    async fn live_write_failure_destroys_nothing() {
        let fake = Fake::failing(&["state#2"]);
        let e = rotate(&fake, &["a"], &[], &[]).await.unwrap_err();
        assert!(
            matches!(&e, EnrollError::State(m) if m == "state#2 failed"),
            "{e:?}"
        );
        assert!(!fake.log().iter().any(|l| l.starts_with("destroy:")));
        assert_eq!(fake.states(), vec![state(&["a"], &["acc-new"], &[])]);
    }

    fn assert_no_leak(name: &str, fake: &Fake, result: &Result<AgentOutcome, EnrollError>) {
        let sealed = fake.sealed.borrow().clone();
        assert!(
            sealed.is_empty() || sealed == strings(&[SENTINEL]),
            "{name}: sealed {sealed:?}"
        );
        let written = String::from_utf8(fake.written.borrow().clone()).unwrap();
        assert!(!written.contains(SENTINEL), "{name}: written");
        match result {
            Ok(out) => {
                assert!(!format!("{:?}", out.record).contains(SENTINEL), "{name}");
                assert!(!out.record.to_yaml().contains(SENTINEL), "{name}");
            }
            Err(e) => {
                assert!(!format!("{e}").contains(SENTINEL), "{name}: Display");
                assert!(!format!("{e:?}").contains(SENTINEL), "{name}: Debug");
            }
        }
    }

    #[tokio::test]
    async fn the_secret_reaches_only_seal() {
        let mut sealed_once = 0;
        let fake = Fake::default();
        let r = first(&fake).await;
        assert_no_leak("first", &fake, &r);
        sealed_once += fake.sealed.borrow().len();

        let fake = Fake::default();
        let r = rotate(&fake, &["a"], &["p"], &["r"]).await;
        assert_no_leak("rotate", &fake, &r);
        sealed_once += fake.sealed.borrow().len();

        let cases: [(&str, &[&str], bool); 8] = [
            ("retire", &["destroy:a"], true),
            ("pending", &["state#1"], false),
            ("pending+destroy", &["state#1", "destroy:acc-new"], false),
            ("seal", &["seal"], true),
            ("seal+destroy", &["seal", "destroy:acc-new"], true),
            ("record", &["record"], true),
            ("live", &["state#2"], true),
            ("mint", &["mint"], false),
        ];
        for (name, keys, reaches_seal) in cases {
            let fake = Fake::failing(keys);
            let r = rotate(&fake, &["a"], &[], &[]).await;
            assert!(r.is_err(), "{name}");
            assert_no_leak(name, &fake, &r);
            assert_eq!(
                fake.sealed.borrow().len(),
                usize::from(reaches_seal),
                "{name}"
            );
        }
        assert_eq!(sealed_once, 2);
    }

    #[test]
    fn enroll_agent_prints_nothing() {
        let src = include_str!("agent.rs");
        let start = src
            .lines()
            .position(|l| l.starts_with("pub(crate) async fn enroll_agent"))
            .expect("enroll_agent is defined at top level");
        let body: Vec<&str> = src.lines().skip(start).take_while(|l| *l != "}").collect();
        assert!(body.iter().any(|l| l.contains("ops.seal(")));
        for mac in [
            "println!",
            "eprintln!",
            "print!",
            "eprint!",
            "dbg!",
            "format!",
        ] {
            assert!(
                !body.iter().any(|l| l.contains(mac)),
                "enroll_agent uses {mac}"
            );
        }
    }

    #[test]
    fn state_and_record_yaml_round_trip() {
        let s = state(&["a", "b"], &["p"], &["r1", "r2"]);
        assert_eq!(AgentState::parse(&s.to_yaml()).unwrap(), s);
        let empty = state(&[], &[], &[]);
        assert_eq!(AgentState::parse(&empty.to_yaml()).unwrap(), empty);
        for source in [SecretSource::Tpm2, SecretSource::Keychain] {
            let r = AgentRecord {
                source,
                bind_cidrs: strings(&["10.0.0.5/32", "fd00::/64"]),
                ..record()
            };
            assert_eq!(AgentRecord::parse(&r.to_yaml()).unwrap(), r);
        }
        for bad in [
            "",
            "- a\n",
            "approle_mount: m\nrole: r\nlive: []\npending: []\n",
            "approle_mount: m\nrole: r\nlive: x\npending: []\nretiring: []\n",
            "approle_mount: m\nrole: r\nlive: [1]\npending: []\nretiring: []\n",
            "approle_mount: [\n",
        ] {
            assert!(
                matches!(AgentState::parse(bad), Err(EnrollError::State(_))),
                "{bad:?}"
            );
        }
        let good = record().to_yaml();
        for bad in [
            good.replace("source: tpm2", "source: plaintext"),
            good.replace("uid: 990", "uid: -1"),
            good.replace("uid: 990", "uid: x"),
            good.replace("role_id:", "role_idx:"),
            String::new(),
        ] {
            assert_ne!(bad, good);
            assert!(
                matches!(AgentRecord::parse(&bad), Err(EnrollError::State(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn host_enrollment_parses_build_daemon_yaml_output() {
        let op = crate::enroll::Operator {
            uid: 1000,
            gid: 1000,
            name: "ops".into(),
            home: std::path::PathBuf::from("/home/ops"),
        };
        let text = crate::enroll::build_daemon_yaml(
            "dev-01",
            "https://v.example:8200",
            "maknae-approle",
            "pki_int",
            "userpass",
            None,
            "/var/log/maknae/audit.jsonl",
            false,
            None,
            &op,
        );
        assert_eq!(
            parse_host_enrollment(&text).unwrap(),
            HostEnrollment {
                vault_addr: "https://v.example:8200".into(),
                approle_mount: "maknae-approle".into(),
                principal_uid: 1000,
            }
        );
        let no_principal = text.split("principal:").next().unwrap().to_string();
        assert!(!no_principal.contains("uid"));
        assert!(matches!(
            parse_host_enrollment(&no_principal),
            Err(EnrollError::HostNotEnrolled(_))
        ));
        let no_mount = text.replace("approle_mount:", "approle_mountx:");
        assert!(matches!(
            parse_host_enrollment(&no_mount),
            Err(EnrollError::HostNotEnrolled(_))
        ));
    }
}
