//! The one validator boot, reload, show and accept share (#490): whether a
//! baseline document can start, over an injected environment.

use std::path::Path;

use maknae_config::{BaselineSections, Document};

use crate::baseline::InvalidFile;

#[derive(Debug)]
pub struct Validated {
    pub boot: crate::BootConfig,
    pub transport: maknae_config::TransportConfig,
    pub egress: maknae_config::EgressConfig,
    pub audit: maknae_config::AuditConfig,
    pub principal: maknae_config::Principal,
    pub egress_bounds: Option<maknae_config::EgressBounds>,
    /// Resolved only in `Mode::Accept`; empty in `Mode::Boot`.
    pub readers: Vec<maknae_config::ReaderAccount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    /// Exit 1; at a first start, before the audit sink opens, with no record.
    Document(String),
    /// Exit 1, audited: what today's boot refuses after the audit sink opens.
    Environment(String),
    /// Exit 4, audited (#189).
    Offload(String),
    /// Exit 3, audited (#77).
    Principal(String),
    /// Exit 1, audited, refused after the policy loads; `principal` is the one
    /// the policy load needs.
    Vault {
        cause: String,
        principal: maknae_config::Principal,
    },
}

impl Invalid {
    pub fn cause(&self) -> &str {
        match self {
            Invalid::Document(m)
            | Invalid::Environment(m)
            | Invalid::Offload(m)
            | Invalid::Principal(m)
            | Invalid::Vault { cause: m, .. } => m,
        }
    }

    pub fn exit_code(&self) -> u8 {
        match self {
            Invalid::Document(_) | Invalid::Environment(_) | Invalid::Vault { .. } => 1,
            Invalid::Principal(_) => 3,
            Invalid::Offload(_) => 4,
        }
    }

    /// The pending-set form: the cause, and the sections of the document refused
    /// (`maknae_config::document_sections` of it, taken before [`validate`]).
    pub fn into_file(self, proposed: Option<BaselineSections>) -> InvalidFile {
        InvalidFile {
            cause: self.cause().to_string(),
            proposed,
        }
    }
}

pub trait Env: maknae_config::ReaderLookup + Send + Sync {
    fn egress_bounds(&self) -> Result<maknae_config::EgressBounds, maknae_config::ConfigError>;
    /// The egress deputy's uid, `Ok(None)` when the account does not exist.
    fn egress_account(&self) -> Result<Option<u32>, String>;
    /// An existing, daemon-owned, append-only trail at `path`.
    fn trail_prepared(&self, path: &Path) -> Result<(), String>;
    /// Bind a listener at `path` (absent) and remove it again.
    fn listener_bindable(&self, path: &Path) -> Result<(), String>;
    /// Connect to the deputy's socket at `path` and close.
    fn deputy_reachable(&self, path: &Path) -> Result<(), String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Boot, reload and show: `audit.readers` syntax only (the parser's check).
    Boot,
    /// Accept: `audit.readers` resolved through NSS as well.
    Accept,
}

fn document(e: impl std::fmt::Display) -> Invalid {
    Invalid::Document(e.to_string())
}

fn environment(e: impl std::fmt::Display) -> Invalid {
    Invalid::Environment(e.to_string())
}

/// The entry point for a document read from the files.
pub fn validate_file(
    doc: Document,
    mode: Mode,
    config_dir: &Path,
    env: &dyn Env,
) -> Result<Validated, Invalid> {
    validate(doc, mode, config_dir, env)
}

/// Today's boot order and exit codes: sections (1, pre-sink); offload (4); a present
/// principal, shadowed ones included (3); egress bounds, egress account, root vault
/// keys (1); an absent principal (3); the vault block (1); at accept, the readers.
pub fn validate(
    doc: Document,
    mode: Mode,
    config_dir: &Path,
    env: &dyn Env,
) -> Result<Validated, Invalid> {
    let boot = crate::boot::assemble(doc).map_err(document)?;
    let transport =
        maknae_config::transport_from_section(boot.section(maknae_config::TRANSPORT_SECTION))
            .map_err(document)?;
    let egress = maknae_config::egress_from_section(boot.section(maknae_config::EGRESS_SECTION))
        .map_err(document)?;
    let audit = audit_of(boot.document(), config_dir)?;
    crate::boot_gate::audit_offload_boot_gate(&audit)
        .map_err(|e| Invalid::Offload(e.to_string()))?;
    shadowed_principals(boot.document())?;
    let principal =
        maknae_config::principal_from_section(boot.section(maknae_config::PRINCIPAL_SECTION))
            .map_err(|e| Invalid::Principal(e.to_string()))?;
    let egress_bounds = if boot.providers().is_empty() {
        None
    } else {
        let bounds = env
            .egress_bounds()
            .map_err(|e| environment(crate::boot_gate::classify_bounds_load_error(e)))?;
        crate::boot_gate::egress_bounds_boot_gate(boot.providers(), Some(&bounds))
            .map_err(environment)?;
        match env.egress_account() {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(environment(
                    crate::egress::EgressBootRefusal::NoSuchAccount(
                        crate::egress::EGRESS_USER.to_string(),
                    ),
                ))
            }
            Err(e) => return Err(environment(crate::egress::EgressBootRefusal::Resolve(e))),
        }
        Some(bounds)
    };
    crate::boot_gate::root_vault_boot_gate(boot.section(maknae_vault::VAULT_SECTION))
        .map_err(environment)?;
    shadowed_vaults(boot.document())?;
    let principal = principal.ok_or_else(|| {
        Invalid::Principal(crate::boot_gate::AuthzBootRefusal::MissingPrincipal.to_string())
    })?;
    if let Err(e) = maknae_vault::vault_config_from_document(boot.document()) {
        return Err(Invalid::Vault {
            cause: e.to_string(),
            principal,
        });
    }
    let readers = match mode {
        Mode::Boot => Vec::new(),
        Mode::Accept => maknae_config::resolve_readers(&audit.readers, env).map_err(document)?,
    };
    Ok(Validated {
        boot,
        transport,
        egress,
        audit,
        principal,
        egress_bounds,
        readers,
    })
}

fn shadowed_principals(file: &Document) -> Result<(), Invalid> {
    for shadowed in file.shadowed_sections(maknae_config::PRINCIPAL_SECTION) {
        maknae_config::principal_keys_known(shadowed)
            .map_err(|e| Invalid::Principal(e.to_string()))?;
    }
    Ok(())
}

fn shadowed_vaults(file: &Document) -> Result<(), Invalid> {
    for shadowed in file.shadowed_sections(maknae_vault::VAULT_SECTION) {
        crate::boot_gate::root_vault_boot_gate(Some(shadowed)).map_err(environment)?;
    }
    Ok(())
}

/// The checks only a file can fail: what `config.d` shadowed.
pub fn check_sources(file: &Document) -> Result<(), Invalid> {
    shadowed_principals(file)?;
    for shadowed in file.shadowed_sections(maknae_config::PROVIDERS_SECTION) {
        maknae_config::refuse_plaintext_keys(shadowed).map_err(document)?;
    }
    shadowed_vaults(file)
}

/// The move rules: a sibling, prepared by root.
pub fn check_move(accepted: Option<&Path>, run: &Path, env: &dyn Env) -> Result<(), String> {
    match crate::baseline::move_of(accepted, run)? {
        Some(m) => env.trail_prepared(&m.to),
        None => Ok(()),
    }
}

/// The system and ceiling level the graph records for a validated baseline.
pub fn classification_of(v: &Validated) -> (String, String) {
    (
        v.boot.classification_policy_name().to_string(),
        v.boot.ceiling().classification.name.clone(),
    )
}

/// Accept only: probe each socket path the proposal changes.
pub fn check_sockets(
    accepted: &BaselineSections,
    proposed: &Validated,
    env: &dyn Env,
) -> Result<(), Invalid> {
    let was = Document::from_baseline(accepted).map_err(document)?;
    let transport =
        maknae_config::transport_from_section(was.section(maknae_config::TRANSPORT_SECTION))
            .map_err(document)?;
    let egress = maknae_config::egress_from_section(was.section(maknae_config::EGRESS_SECTION))
        .map_err(document)?;
    let probe = |path: &Path, outcome: Result<(), String>| {
        outcome.map_err(|e| Invalid::Document(format!("{}: {e}", path.display())))
    };
    let listener = &proposed.transport.socket_path;
    if *listener != transport.socket_path {
        probe(listener, env.listener_bindable(listener))?;
    }
    let deputy = &proposed.egress.socket_path;
    if !proposed.boot.providers().is_empty() && *deputy != egress.socket_path {
        probe(deputy, env.deputy_reachable(deputy))?;
    }
    Ok(())
}

/// The `transport` section alone: the listener a refusal record names.
pub fn transport_of(doc: &Document) -> Result<maknae_config::TransportConfig, Invalid> {
    maknae_config::transport_from_section(doc.section(maknae_config::TRANSPORT_SECTION))
        .map_err(document)
}

/// The `audit` section alone: where the trail is, for the sink a refusal is recorded in.
pub fn audit_of(doc: &Document, config_dir: &Path) -> Result<maknae_config::AuditConfig, Invalid> {
    maknae_config::audit_from_section(doc.section(maknae_config::AUDIT_SECTION), config_dir)
        .map_err(document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_config::{BaselineSections, Document, ReaderAccount, ReaderLookup};
    use std::path::Path;
    use std::sync::Mutex;

    struct FakeEnv {
        bounds: Option<maknae_config::EgressBounds>,
        egress_uid: Result<Option<u32>, String>,
        prepared: Result<(), String>,
        bindable: Result<(), String>,
        reachable: Result<(), String>,
        accounts: Vec<ReaderAccount>,
        probed: Mutex<Vec<String>>,
    }

    impl Default for FakeEnv {
        fn default() -> Self {
            FakeEnv {
                bounds: None,
                egress_uid: Ok(Some(981)),
                prepared: Ok(()),
                bindable: Ok(()),
                reachable: Ok(()),
                accounts: Vec::new(),
                probed: Mutex::new(Vec::new()),
            }
        }
    }

    impl FakeEnv {
        fn with_bounds() -> Self {
            FakeEnv {
                bounds: Some(maknae_config::EgressBounds {
                    kv_mount: "kv".into(),
                    user_prefix: "users".into(),
                    vault_addr: "https://v:8200".into(),
                }),
                ..FakeEnv::default()
            }
        }
        fn probed(&self) -> Vec<String> {
            self.probed.lock().unwrap().clone()
        }
    }

    impl ReaderLookup for FakeEnv {
        fn account(&self, name: &str) -> Result<Option<ReaderAccount>, String> {
            Ok(self.accounts.iter().find(|a| a.name == name).cloned())
        }
        fn daemon_gid(&self) -> Result<Option<u32>, String> {
            Ok(Some(970))
        }
        fn service_uids(&self) -> Result<Vec<u32>, String> {
            Ok(vec![970, 981])
        }
    }

    impl Env for FakeEnv {
        fn egress_bounds(&self) -> Result<maknae_config::EgressBounds, maknae_config::ConfigError> {
            self.bounds
                .clone()
                .ok_or_else(|| maknae_config::ConfigError::NotFound {
                    path: maknae_config::EGRESS_BOUNDS_FILE.into(),
                })
        }
        fn egress_account(&self) -> Result<Option<u32>, String> {
            self.egress_uid.clone()
        }
        fn trail_prepared(&self, path: &Path) -> Result<(), String> {
            self.probed
                .lock()
                .unwrap()
                .push(format!("prepared {}", path.display()));
            self.prepared.clone()
        }
        fn listener_bindable(&self, path: &Path) -> Result<(), String> {
            self.probed
                .lock()
                .unwrap()
                .push(format!("bind {}", path.display()));
            self.bindable.clone()
        }
        fn deputy_reachable(&self, path: &Path) -> Result<(), String> {
            self.probed
                .lock()
                .unwrap()
                .push(format!("connect {}", path.display()));
            self.reachable.clone()
        }
    }

    fn doc(pairs: &[(&str, &str)]) -> Document {
        let s: BaselineSections = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Document::from_baseline(&s).unwrap()
    }
    const AUDIT: &str = r#"{"jsonl_path":"/var/log/maknae/audit.jsonl"}"#;
    const PRINCIPAL: &str = r#"{"name":"op","uid":1000}"#;
    const PROVIDERS: &str =
        r#"[{"endpoint":"https://api.example.test/v1","models":["m"],"name":"openai"}]"#;
    const VAULT: &str = r#"{"addr":"https://v:8200"}"#;
    fn minimal() -> Vec<(&'static str, &'static str)> {
        vec![
            ("core", r#"{"deployment_id":"d"}"#),
            ("audit", AUDIT),
            ("principal", PRINCIPAL),
            ("vault", VAULT),
        ]
    }
    fn sections(pairs: &[(&str, &str)]) -> BaselineSections {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    fn reader(name: &str, uid: u32) -> ReaderAccount {
        ReaderAccount {
            name: name.into(),
            uid,
            gid: uid,
            groups: Vec::new(),
        }
    }

    #[test]
    fn no_debug_form_prints_a_suppressed_setting() {
        let mut file = minimal();
        file[0] = (
            "core",
            r#"{"deployment_id":"d","handling":{"accreditation_ref":"ACCRED-7Q","ceiling":{"classification":"SECRET","cui_categories_permitted":[],"cui_permitted":false,"dissemination_permitted":["Distribution Statement A"],"releasable_to":[],"sci":false}}}"#,
        );
        file[1] = (
            "audit",
            r#"{"au3_1":{"enclave":"SCIF-B7"},"jsonl_path":"/var/log/maknae/audit.jsonl"}"#,
        );
        let proposed = sections(&file);
        let v = validate(doc(&file), Mode::Boot, Path::new("/e"), &FakeEnv::default()).unwrap();
        assert_eq!(classification_of(&v).1, "SECRET");
        let accepted = sections(&minimal());
        let invalid = InvalidFile {
            cause: "refused".into(),
            proposed: Some(proposed.clone()),
        };
        let valid_set = crate::baseline::pending(&accepted, &Ok(proposed.clone())).unwrap();
        let invalid_set = crate::baseline::pending(&accepted, &Err(invalid.clone())).unwrap();
        let state = crate::baseline::BaselineState {
            accepted: proposed.clone(),
            pending: Some(valid_set.clone()),
        };
        for shown in [
            format!("{proposed:?}"),
            format!("{v:?}"),
            format!("{:?}", v.boot.document()),
            format!("{:?}", v.audit),
            format!("{invalid:?}"),
            format!("{valid_set:?}"),
            format!("{:?}", valid_set.state),
            format!("{invalid_set:?}"),
            format!("{state:?}"),
        ] {
            for value in ["SECRET", "ACCRED-7Q", "SCIF-B7"] {
                assert!(!shown.contains(value), "{value} in {shown}");
            }
        }
    }

    #[test]
    fn a_minimal_baseline_validates() {
        let v = validate(
            doc(&minimal()),
            Mode::Boot,
            Path::new("/etc/maknae"),
            &FakeEnv::default(),
        )
        .unwrap();
        assert_eq!(v.principal.uid, 1000);
        assert_eq!(
            classification_of(&v),
            ("US".to_string(), "UNCLASSIFIED".to_string())
        );
        assert_eq!(v.audit.jsonl_path, Path::new("/var/log/maknae/audit.jsonl"));
        assert!(v.egress_bounds.is_none() && v.readers.is_empty());
        assert_eq!(
            v.transport.socket_path,
            maknae_config::TransportConfig::default().socket_path
        );
        assert_eq!(v.egress, maknae_config::EgressConfig::default());
    }

    #[test]
    fn the_classification_is_the_declared_system_and_ceiling() {
        let mut aus = minimal();
        aus[0] = (
            "core",
            r#"{"deployment_id":"d","handling":{"accreditation_ref":null,"ceiling":{"classification":"protected","cui_categories_permitted":[],"cui_permitted":false,"dissemination_permitted":["Distribution Statement A"],"releasable_to":[],"sci":false},"policy":"aus"}}"#,
        );
        let v = validate(doc(&aus), Mode::Boot, Path::new("/e"), &FakeEnv::default()).unwrap();
        assert_eq!(
            classification_of(&v),
            ("AUS".to_string(), "PROTECTED".to_string())
        );
    }

    #[test]
    fn each_refusal_keeps_its_exit_code() {
        let mut no_principal = minimal();
        no_principal.retain(|(k, _)| *k != "principal");
        assert!(matches!(
            validate(
                doc(&no_principal),
                Mode::Boot,
                Path::new("/e"),
                &FakeEnv::default()
            ),
            Err(Invalid::Principal(_))
        ));
        let mut siem = minimal();
        siem[1] = (
            "audit",
            r#"{"jsonl_path":"/var/log/maknae/audit.jsonl","siem":"https://s"}"#,
        );
        assert!(matches!(
            validate(doc(&siem), Mode::Boot, Path::new("/e"), &FakeEnv::default()),
            Err(Invalid::Offload(_))
        ));
        let mut unknown = minimal();
        unknown[0] = ("core", r#"{"deployment_id":"d","handlng":{}}"#);
        assert!(matches!(
            validate(
                doc(&unknown),
                Mode::Boot,
                Path::new("/e"),
                &FakeEnv::default()
            ),
            Err(Invalid::Document(_))
        ));
        assert_eq!(Invalid::Document(String::new()).exit_code(), 1);
        assert_eq!(Invalid::Environment(String::new()).exit_code(), 1);
        assert_eq!(Invalid::Principal(String::new()).exit_code(), 3);
        assert_eq!(Invalid::Offload(String::new()).exit_code(), 4);
        assert_eq!(vault_invalid("v").exit_code(), 1);
    }

    fn vault_invalid(cause: &str) -> Invalid {
        Invalid::Vault {
            cause: cause.into(),
            principal: maknae_config::Principal {
                name: "op".into(),
                uid: 1000,
            },
        }
    }

    #[test]
    fn the_transport_of_a_document_is_its_section_or_the_default() {
        assert_eq!(
            transport_of(&doc(&minimal())).unwrap().socket_path,
            maknae_config::TransportConfig::default().socket_path
        );
        let mut t = minimal();
        t.push(("transport", r#"{"socket_path":"/run/x.sock"}"#));
        assert_eq!(
            transport_of(&doc(&t)).unwrap().socket_path,
            Path::new("/run/x.sock")
        );
        t.pop();
        t.push(("transport", r#"{"colour":1,"socket_path":"/run/x.sock"}"#));
        assert!(matches!(transport_of(&doc(&t)), Err(Invalid::Document(_))));
    }

    #[test]
    fn the_refusal_text_is_what_boot_prints_today() {
        let mut no_principal = minimal();
        no_principal.retain(|(k, _)| *k != "principal");
        let refused = validate(
            doc(&no_principal),
            Mode::Boot,
            Path::new("/e"),
            &FakeEnv::default(),
        )
        .unwrap_err();
        let today = crate::boot_gate::authz_policy_source(Path::new("/e"), None)
            .err()
            .unwrap()
            .to_string();
        assert_eq!(refused.cause(), today);
        let mut bad = minimal();
        bad[2] = ("principal", r#"{"home":"/h","name":"op","uid":1000}"#);
        assert_eq!(
            validate(doc(&bad), Mode::Boot, Path::new("/e"), &FakeEnv::default()).err(),
            Some(Invalid::Principal(
                "unknown key 'home' in 'principal'".to_string()
            ))
        );
        let mut siem = minimal();
        siem[1] = ("audit", r#"{"jsonl_path":"/x","siem":"https://s"}"#);
        assert_eq!(
            validate(doc(&siem), Mode::Boot, Path::new("/e"), &FakeEnv::default()).err(),
            Some(Invalid::Offload(
                crate::boot_gate::SiemOffloadUnsupported.to_string()
            ))
        );
        for (invalid, text) in [
            (Invalid::Document("d".into()), "d"),
            (Invalid::Environment("e".into()), "e"),
            (Invalid::Offload("o".into()), "o"),
            (Invalid::Principal("p".into()), "p"),
            (vault_invalid("v"), "v"),
        ] {
            assert_eq!(invalid.cause(), text);
        }
    }

    #[test]
    fn a_refusal_becomes_an_invalid_file_carrying_what_was_refused() {
        let s = sections(&minimal());
        assert_eq!(
            Invalid::Principal("why".into()).into_file(Some(s.clone())),
            InvalidFile {
                cause: "why".into(),
                proposed: Some(s)
            }
        );
        assert_eq!(Invalid::Document("d".into()).into_file(None).cause, "d");
        assert_eq!(
            Invalid::Offload("o".into()).into_file(None),
            InvalidFile {
                cause: "o".into(),
                proposed: None
            }
        );
    }

    #[test]
    fn offload_is_refused_before_principal_as_boot_does_today() {
        let mut both = minimal();
        both.retain(|(k, _)| *k != "principal");
        both[1] = ("audit", r#"{"jsonl_path":"/x","siem":"https://s"}"#);
        assert!(matches!(
            validate(doc(&both), Mode::Boot, Path::new("/e"), &FakeEnv::default()),
            Err(Invalid::Offload(_))
        ));
    }

    #[test]
    fn an_unparseable_section_refuses_as_a_document() {
        for (section, value) in [
            ("transport", r#"{"socket_path":7}"#),
            ("egress", r#""disabled""#),
            ("audit", r#""x""#),
        ] {
            let mut d = minimal();
            d.retain(|(k, _)| *k != section);
            d.push((section, value));
            assert!(
                matches!(
                    validate(doc(&d), Mode::Boot, Path::new("/e"), &FakeEnv::default()),
                    Err(Invalid::Document(_))
                ),
                "{section}"
            );
        }
        let mut no_audit = minimal();
        no_audit.retain(|(k, _)| *k != "audit");
        assert!(matches!(
            validate(doc(&no_audit), Mode::Boot, Path::new("/e"), &FakeEnv::default()),
            Err(Invalid::Document(ref m)) if m.contains("audit")
        ));
    }

    #[test]
    fn providers_need_the_bounds_file_and_the_egress_account() {
        let mut p = minimal();
        p.push(("providers", PROVIDERS));
        let env = FakeEnv {
            bounds: None,
            ..FakeEnv::default()
        };
        assert!(
            matches!(validate(doc(&p), Mode::Boot, Path::new("/e"), &env), Err(Invalid::Environment(ref m)) if m.contains("egress-bounds"))
        );
        let env = FakeEnv {
            egress_uid: Ok(None),
            ..FakeEnv::with_bounds()
        };
        assert!(
            matches!(validate(doc(&p), Mode::Boot, Path::new("/e"), &env), Err(Invalid::Environment(ref m)) if m.contains("_maknae-egress"))
        );
        let env = FakeEnv {
            egress_uid: Err("nss down".into()),
            ..FakeEnv::with_bounds()
        };
        assert!(
            matches!(validate(doc(&p), Mode::Boot, Path::new("/e"), &env), Err(Invalid::Environment(ref m)) if m.contains("nss down"))
        );
        let v = validate(
            doc(&p),
            Mode::Boot,
            Path::new("/e"),
            &FakeEnv::with_bounds(),
        )
        .unwrap();
        assert_eq!(v.egress_bounds, FakeEnv::with_bounds().bounds);
    }

    #[test]
    fn refused_bounds_refuse_the_baseline() {
        let mut p = minimal();
        p.push(("providers", PROVIDERS));
        let mut env = FakeEnv::with_bounds();
        env.bounds.as_mut().unwrap().user_prefix = "a b".into();
        assert!(
            matches!(validate(doc(&p), Mode::Boot, Path::new("/e"), &env), Err(Invalid::Environment(ref m)) if m.contains("user_prefix"))
        );
    }

    #[test]
    fn without_providers_neither_the_bounds_nor_the_account_is_asked() {
        let env = FakeEnv {
            egress_uid: Err("asked".into()),
            ..FakeEnv::default()
        };
        assert!(validate(doc(&minimal()), Mode::Boot, Path::new("/e"), &env).is_ok());
    }

    #[test]
    fn readers_are_resolved_at_accept_and_only_parsed_at_boot() {
        let mut r = minimal();
        r[1] = ("audit", r#"{"jsonl_path":"/x","readers":["ghost"]}"#);
        assert!(
            validate(doc(&r), Mode::Boot, Path::new("/e"), &FakeEnv::default()).is_ok(),
            "boot never asks NSS about readers"
        );
        assert!(
            matches!(validate(doc(&r), Mode::Accept, Path::new("/e"), &FakeEnv::default()), Err(Invalid::Document(ref m)) if m.contains("ghost"))
        );
        r[1] = ("audit", r#"{"jsonl_path":"/x","readers":["Not A Name"]}"#);
        assert!(
            matches!(
                validate(doc(&r), Mode::Boot, Path::new("/e"), &FakeEnv::default()),
                Err(Invalid::Document(_))
            ),
            "syntax is checked at boot"
        );
    }

    #[test]
    fn an_accept_carries_the_resolved_readers() {
        let mut r = minimal();
        r[1] = ("audit", r#"{"jsonl_path":"/x","readers":["alice"]}"#);
        let env = FakeEnv {
            accounts: vec![reader("alice", 1001)],
            ..FakeEnv::default()
        };
        let v = validate(doc(&r), Mode::Accept, Path::new("/e"), &env).unwrap();
        assert_eq!(v.readers, vec![reader("alice", 1001)]);
        let v = validate(doc(&r), Mode::Boot, Path::new("/e"), &env).unwrap();
        assert!(v.readers.is_empty());
    }

    #[test]
    fn bounds_are_checked_before_root_vault_keys_as_boot_does_today() {
        let mut p = minimal();
        p.push(("providers", PROVIDERS));
        p.push(("vault", r#"{"addr":"https://v:8200","kv_mount":"kv"}"#));
        let env = FakeEnv {
            bounds: None,
            ..FakeEnv::default()
        };
        assert!(
            matches!(validate(doc(&p), Mode::Boot, Path::new("/e"), &env), Err(Invalid::Environment(ref m)) if m.contains("egress-bounds"))
        );
    }

    #[test]
    fn a_root_vault_key_is_refused() {
        let mut v = minimal();
        v.push(("vault", r#"{"addr":"https://v:8200","kv_mount":"kv"}"#));
        assert!(
            matches!(validate(doc(&v), Mode::Boot, Path::new("/e"), &FakeEnv::default()), Err(Invalid::Environment(ref m)) if m.contains("kv_mount"))
        );
    }

    #[test]
    fn a_vault_block_that_does_not_parse_is_refused_and_one_that_does_validates() {
        let mut v = minimal();
        v.push(("vault", r#"{"addr":"https://v:8200","colour":"red"}"#));
        assert!(
            matches!(validate(doc(&v), Mode::Boot, Path::new("/e"), &FakeEnv::default()), Err(Invalid::Vault { ref cause, ref principal }) if cause.contains("colour") && principal.uid == 1000)
        );
        let mut v = minimal();
        v.push(("vault", r#"{"addr":"https://v:8200"}"#));
        assert!(validate(doc(&v), Mode::Boot, Path::new("/e"), &FakeEnv::default()).is_ok());
    }

    #[test]
    fn audit_of_agrees_with_the_validator() {
        let d = doc(&minimal());
        let alone = audit_of(&d, Path::new("/etc/maknae")).unwrap();
        let v = validate(d, Mode::Boot, Path::new("/etc/maknae"), &FakeEnv::default()).unwrap();
        assert_eq!(alone.jsonl_path, v.audit.jsonl_path);
        let mut defaulted = minimal();
        defaulted[1] = ("audit", "{}");
        assert_eq!(
            audit_of(&doc(&defaulted), Path::new("/etc/maknae"))
                .unwrap()
                .jsonl_path,
            Path::new("/etc/maknae/audit.jsonl")
        );
        let mut no_audit = minimal();
        no_audit.retain(|(k, _)| *k != "audit");
        assert!(matches!(
            audit_of(&doc(&no_audit), Path::new("/e")),
            Err(Invalid::Document(_))
        ));
    }

    fn file_with(base: &str, members: &[(&str, &str)]) -> Document {
        let dir = std::env::temp_dir().join(format!(
            "maknae_bcheck_{}_{}",
            std::process::id(),
            members.first().map_or("none", |m| m.0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config.d")).unwrap();
        std::fs::write(dir.join("maknae.yaml"), base).unwrap();
        for (name, body) in members {
            std::fs::write(dir.join("config.d").join(name), body).unwrap();
        }
        use std::os::unix::fs::PermissionsExt;
        for p in [dir.clone(), dir.join("config.d")] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750)).unwrap();
        }
        let mut files = vec![dir.join("maknae.yaml")];
        files.extend(members.iter().map(|(n, _)| dir.join("config.d").join(n)));
        for f in files {
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        let doc = crate::boot::read_files_as_owner(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        doc
    }

    #[test]
    fn check_sources_refuses_what_config_d_shadowed() {
        let clean = file_with(
            "core: {}\nprincipal:\n  name: op\n  uid: 1000\n",
            &[("10-principal.yaml", "principal:\n  name: op\n  uid: 1001\n")],
        );
        assert_eq!(check_sources(&clean), Ok(()));
        let home = file_with(
            "core: {}\nprincipal:\n  name: op\n  uid: 1000\n  home: /h\n",
            &[("10-home.yaml", "principal:\n  name: op\n  uid: 1000\n")],
        );
        assert_eq!(
            check_sources(&home),
            Err(Invalid::Principal(
                "unknown key 'home' in 'principal'".to_string()
            ))
        );
        let key = file_with(
            "core: {}\nproviders:\n  - name: openai\n    api_key: sk-live\n",
            &[(
                "10-providers.yaml",
                "providers:\n  - name: openai\n    endpoint: https://api.example.test/v1\n    models: [m]\n",
            )],
        );
        assert!(
            matches!(check_sources(&key), Err(Invalid::Document(ref m)) if m.contains("api_key"))
        );
        let vault = file_with(
            "core: {}\nvault:\n  addr: https://v:8200\n  kv_mount: kv\n",
            &[("10-vault.yaml", "vault:\n  addr: https://v:8200\n")],
        );
        assert!(
            matches!(check_sources(&vault), Err(Invalid::Environment(ref m)) if m.contains("kv_mount"))
        );
    }

    #[test]
    fn check_sockets_probes_only_what_changed() {
        let accepted: maknae_config::BaselineSections = minimal()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let never = FakeEnv {
            bindable: Err("probed".into()),
            reachable: Err("probed".into()),
            ..FakeEnv::default()
        };
        let same = validate(doc(&minimal()), Mode::Accept, Path::new("/e"), &never).unwrap();
        assert!(
            check_sockets(&accepted, &same, &never).is_ok(),
            "nothing changed, nothing probed"
        );
        let mut moved = minimal();
        moved.push(("transport", r#"{"socket_path":"/run/maknae/other.sock"}"#));
        let v = validate(
            doc(&moved),
            Mode::Accept,
            Path::new("/e"),
            &FakeEnv::default(),
        )
        .unwrap();
        assert!(check_sockets(&accepted, &v, &FakeEnv::default()).is_ok());
        let refused = check_sockets(
            &accepted,
            &v,
            &FakeEnv {
                bindable: Err("EACCES".into()),
                ..FakeEnv::default()
            },
        );
        assert!(
            matches!(refused, Err(Invalid::Document(ref m)) if m.contains("/run/maknae/other.sock") && m.contains("EACCES")),
            "{refused:?}"
        );
        let mut egress = minimal();
        egress.push((
            "egress",
            r#"{"socket_path":"/run/maknae-egress/other.sock"}"#,
        ));
        let v = validate(
            doc(&egress),
            Mode::Accept,
            Path::new("/e"),
            &FakeEnv::default(),
        )
        .unwrap();
        assert!(
            check_sockets(&accepted, &v, &never).is_ok(),
            "no providers: the deputy path is not probed"
        );
        egress.push(("providers", PROVIDERS));
        let v = validate(
            doc(&egress),
            Mode::Accept,
            Path::new("/e"),
            &FakeEnv::with_bounds(),
        )
        .unwrap();
        assert!(check_sockets(
            &accepted,
            &v,
            &FakeEnv {
                reachable: Err("ECONNREFUSED".into()),
                ..FakeEnv::with_bounds()
            }
        )
        .is_err());
    }

    #[test]
    fn check_sockets_probes_the_real_paths_and_names_the_failure() {
        let accepted = sections(&minimal());
        let mut both = minimal();
        both.push(("transport", r#"{"socket_path":"/run/maknae/a.sock"}"#));
        both.push(("egress", r#"{"socket_path":"/run/maknae-egress/b.sock"}"#));
        both.push(("providers", PROVIDERS));
        let v = validate(
            doc(&both),
            Mode::Accept,
            Path::new("/e"),
            &FakeEnv::with_bounds(),
        )
        .unwrap();
        let env = FakeEnv::with_bounds();
        assert_eq!(check_sockets(&accepted, &v, &env), Ok(()));
        assert_eq!(
            env.probed(),
            vec![
                "bind /run/maknae/a.sock".to_string(),
                "connect /run/maknae-egress/b.sock".to_string()
            ]
        );
        let env = FakeEnv {
            reachable: Err("ECONNREFUSED".into()),
            ..FakeEnv::with_bounds()
        };
        assert_eq!(
            check_sockets(&accepted, &v, &env),
            Err(Invalid::Document(
                "/run/maknae-egress/b.sock: ECONNREFUSED".to_string()
            ))
        );
        let same_paths = sections(&both);
        let env = FakeEnv::with_bounds();
        assert_eq!(check_sockets(&same_paths, &v, &env), Ok(()));
        assert!(env.probed().is_empty(), "{:?}", env.probed());
    }

    #[test]
    fn check_sockets_refuses_an_accepted_baseline_it_cannot_read() {
        let v = validate(
            doc(&minimal()),
            Mode::Accept,
            Path::new("/e"),
            &FakeEnv::default(),
        )
        .unwrap();
        for broken in [
            sections(&[("transport", "{ not json")]),
            sections(&[("transport", r#"{"socket_path":7}"#)]),
            sections(&[("egress", r#""x""#)]),
        ] {
            assert!(
                matches!(
                    check_sockets(&broken, &v, &FakeEnv::default()),
                    Err(Invalid::Document(_))
                ),
                "{broken:?}"
            );
        }
    }

    #[test]
    fn check_move_requires_a_prepared_sibling() {
        let a = Path::new("/var/log/maknae/audit.jsonl");
        let b = Path::new("/var/log/maknae/audit-2.jsonl");
        assert!(check_move(
            Some(a),
            a,
            &FakeEnv {
                prepared: Err("never asked".into()),
                ..FakeEnv::default()
            }
        )
        .is_ok());
        assert!(check_move(Some(a), b, &FakeEnv::default()).is_ok());
        assert!(check_move(
            Some(a),
            b,
            &FakeEnv {
                prepared: Err("not append-only".into()),
                ..FakeEnv::default()
            }
        )
        .unwrap_err()
        .contains("not append-only"));
        assert!(check_move(Some(a), Path::new("/tmp/audit.jsonl"), &FakeEnv::default()).is_err());
    }

    #[test]
    fn check_move_asks_about_the_new_trail_only_when_it_moves() {
        let b = Path::new("/var/log/maknae/audit-2.jsonl");
        let env = FakeEnv::default();
        assert_eq!(check_move(None, b, &env), Ok(()));
        assert!(env.probed().is_empty());
        assert_eq!(
            check_move(Some(Path::new("/var/log/maknae/audit.jsonl")), b, &env),
            Ok(())
        );
        assert_eq!(env.probed(), vec![format!("prepared {}", b.display())]);
    }

    /// Boot and accept are the same function: no section parser is called from run.rs.
    #[test]
    fn the_accept_and_the_boot_share_one_validator() {
        let run = include_str!("run.rs");
        let production = &run[..run.find("\n#[cfg(test)]").unwrap()];
        for parser in [
            "transport_from_section(",
            "egress_from_section(",
            "audit_from_section(",
            "principal_from_section(",
            "ceiling_from_core(",
            "providers_from_section(",
            "load_egress_bounds(",
            "resolve_readers(",
        ] {
            assert!(
                !production.contains(parser),
                "run.rs parses outside the validator: {parser}"
            );
        }
        assert_eq!(
            production.matches("baseline_check::validate_file(").count(),
            1,
            "the files are read through the file entry point"
        );
        assert!(
            production.matches("baseline_check::validate(").count() >= 2,
            "the boot mix and the run baseline each call the validator"
        );
    }

    #[test]
    fn a_baseline_without_vault_is_refused_as_today_after_the_sink_opens() {
        let mut no_vault = minimal();
        no_vault.retain(|(k, _)| *k != "vault");
        let refused = validate(
            doc(&no_vault),
            Mode::Accept,
            Path::new("/e"),
            &FakeEnv::default(),
        )
        .err()
        .unwrap();
        assert!(
            matches!(refused, Invalid::Vault { ref cause, .. } if cause.contains("vault")),
            "{refused:?}"
        );
    }

    #[test]
    fn an_absent_principal_is_refused_after_the_environment_checks_as_today() {
        let mut p = minimal();
        p.retain(|(k, _)| *k != "principal");
        p.push(("vault", r#"{"addr":"https://v:8200","kv_mount":"kv"}"#));
        let refused = validate(doc(&p), Mode::Boot, Path::new("/e"), &FakeEnv::default()).err();
        assert!(
            matches!(refused, Some(Invalid::Environment(ref m)) if m.contains("kv_mount")),
            "{refused:?}"
        );
        assert_eq!(refused.unwrap().exit_code(), 1);
        let mut p = minimal();
        p.retain(|(k, _)| *k != "principal");
        p.push(("providers", PROVIDERS));
        assert!(matches!(
            validate(doc(&p), Mode::Boot, Path::new("/e"), &FakeEnv::default()),
            Err(Invalid::Environment(_))
        ));
        let mut p = minimal();
        p.retain(|(k, _)| *k != "principal");
        p.push(("vault", r#"{"addr":"https://v:8200","colour":"red"}"#));
        assert!(
            matches!(
                validate(doc(&p), Mode::Boot, Path::new("/e"), &FakeEnv::default()),
                Err(Invalid::Principal(_))
            ),
            "the vault block is parsed after the principal, as today"
        );
    }

    #[test]
    fn a_malformed_principal_is_refused_before_the_environment_checks_as_today() {
        let mut p = minimal();
        p[2] = ("principal", r#"{"home":"/h","name":"op","uid":1000}"#);
        p.push(("providers", PROVIDERS));
        assert!(matches!(
            validate(doc(&p), Mode::Boot, Path::new("/e"), &FakeEnv::default()),
            Err(Invalid::Principal(_))
        ));
    }

    #[test]
    fn validate_file_refuses_what_config_d_shadowed_in_todays_order() {
        let vault = file_with(
            "core:\n  deployment_id: d\naudit:\n  jsonl_path: /x\nprincipal:\n  name: op\n  uid: 1000\nvault:\n  addr: https://v:8200\n  kv_mount: kv\n",
            &[("10-vault.yaml", "vault:\n  addr: https://v:8200\n")],
        );
        let refused =
            validate_file(vault, Mode::Accept, Path::new("/e"), &FakeEnv::default()).err();
        assert!(
            matches!(refused, Some(Invalid::Environment(ref m)) if m.contains("kv_mount")),
            "{refused:?}"
        );
        let both = file_with(
            "core:\n  deployment_id: d\naudit:\n  jsonl_path: /x\n  siem: https://s\nprincipal:\n  name: op\n  uid: 1000\n  home: /h\nvault:\n  addr: https://v:8200\n",
            &[("10-both.yaml", "principal:\n  name: op\n  uid: 1000\n")],
        );
        assert!(matches!(
            validate_file(both, Mode::Boot, Path::new("/e"), &FakeEnv::default()),
            Err(Invalid::Offload(_))
        ));
        let principal_first = file_with(
            "core:\n  deployment_id: d\naudit:\n  jsonl_path: /x\nprincipal:\n  name: op\n  uid: 1000\n  home: /h\nvault:\n  addr: https://v:8200\n  kv_mount: kv\n",
            &[
                ("10-principal.yaml", "principal:\n  name: op\n  uid: 1000\n"),
                ("20-vault.yaml", "vault:\n  addr: https://v:8200\n"),
            ],
        );
        assert!(matches!(
            validate_file(
                principal_first,
                Mode::Boot,
                Path::new("/e"),
                &FakeEnv::default()
            ),
            Err(Invalid::Principal(_))
        ));
    }
}
