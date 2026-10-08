//! The fail-closed authz boot gate (#77, spec D1): the daemon compiles its PDP
//! at boot or refuses to start. T1 — a wrong arm here is a daemon that serves
//! without a decider.
//!
//! Three refusal triggers, and only three:
//!   1. the `principal` section is absent — the PDP's default role resolution
//!      keys on the enrolled uid, so a daemon with no principal can authorize
//!      no one: "boot anyway, deny everything, look healthy" would hide a
//!      dead deployment behind a green service (operator ruling 2026-08-28);
//!   2. `PolicySource::load` refuses — policy load, bindings semantics,
//!      (added 2026-08-31, #162) `roles:` grant semantics: an unknown role, a
//!      structural role (`guest`/`adversary`), a term outside
//!      `GRANTABLE_ACTIONS`, or a term the role may not hold (`user` holds
//!      `session.prompt` only; corrected 2026-09-09, #172: the term set is
//!      two-role now), or (added 2026-09-09, #172) `destinations:` role-key
//!      semantics. One trigger: the load validates all of them eagerly;
//!   3. the snapshot compiler refuses the loaded policy against the booted
//!      kernel graph's identity layer or the binary's vocabulary (#489).

use maknae_authz_basic::snapshot::{compile, CompileError};
use maknae_authz_basic::{AuthzBasicError, BasicAuthorizer, PolicyPaths, PolicySource};
use maknae_config::Principal;
use maknae_graph::graph::Graph;
use maknae_graph::schema::CompiledSet;
use std::path::Path;
use std::sync::Arc;

/// Why boot was refused at the authz gate. Rendered into the AU-3 boot
/// refusal record and the `RunError::Authz` message (exit code 3).
#[derive(Debug)]
pub enum AuthzBootRefusal {
    /// No `principal` section: nothing to key the enrolled-admin default on.
    MissingPrincipal,
    /// The policy load refused (hardened policy load or bindings semantics)
    /// — the inner rendering carries the reason.
    Construct(AuthzBasicError),
    /// The snapshot compiler refused the loaded policy.
    Compile(CompileError),
}

impl std::fmt::Display for AuthzBootRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthzBootRefusal::MissingPrincipal => write!(
                f,
                "config has no `principal` section: the daemon cannot authorize anyone (enroll first)"
            ),
            AuthzBootRefusal::Construct(e) => write!(f, "{e}"),
            AuthzBootRefusal::Compile(e) => write!(f, "authz {e}"),
        }
    }
}

impl From<AuthzBasicError> for AuthzBootRefusal {
    fn from(e: AuthzBasicError) -> Self {
        AuthzBootRefusal::Construct(e)
    }
}

/// Load and validate `authz.yaml` and `bindings.yaml` through the root-owned door,
/// or refuse.
pub fn authz_policy_source(
    config_dir: &Path,
    principal: Option<Principal>,
) -> Result<PolicySource, AuthzBootRefusal> {
    authz_policy_source_with(config_dir, principal, PolicySource::load)
}

/// The load with its loader injected: production passes [`PolicySource::load`]
/// (root-owned door), whose success arm is unconstructible off-root. Ordering
/// and mapping are this fn's own, tested logic.
fn authz_policy_source_with(
    config_dir: &Path,
    principal: Option<Principal>,
    load: impl FnOnce(PolicyPaths, Principal) -> Result<PolicySource, AuthzBasicError>,
) -> Result<PolicySource, AuthzBootRefusal> {
    let principal = principal.ok_or(AuthzBootRefusal::MissingPrincipal)?;
    Ok(load(PolicyPaths::in_dir(config_dir), principal)?)
}

/// Compile the boot-time PDP's first snapshot over the booted kernel graph, or
/// refuse. Sections are digested with SHA-256, the digest the baseline keeps
/// for every later reload.
pub fn authz_boot_gate(
    source: PolicySource,
    graph: Arc<Graph>,
    vocabulary: &CompiledSet,
) -> Result<BasicAuthorizer, AuthzBootRefusal> {
    let digest: fn(&[u8]) -> [u8; 32] = maknae_state::envelope::sha256;
    let snapshot = compile(graph, &source, vocabulary, &source.section_digests(digest))
        .map_err(AuthzBootRefusal::Compile)?;
    Ok(BasicAuthorizer::from_snapshot(
        source.principal().clone(),
        source.paths().clone(),
        digest,
        Arc::new(snapshot),
    ))
}

/// `audit.siem` is configured, but off-host audit offload is not implemented.
///
/// No `Default` derive — this type is returned by a mutated function, where a
/// `Default` makes the mutant equivalent-and-unkillable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiemOffloadUnsupported;

impl std::fmt::Display for SiemOffloadUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The catalog string this is joined to already says "audit.siem is
        // configured but off-host audit offload is not implemented", so this
        // carries only what the operator must DO about it. Measured on
        // the Rocky 9 test host: the two together previously said it twice.
        f.write_str(
            "remove `audit.siem` (offload arrives with issue #223) and ship the \
             audit JSONL with a host log agent instead — see packaging/README.md",
        )
    }
}

/// Why an authorized provider set is not startable.
#[derive(Debug, PartialEq, Eq)]
pub enum EgressBoundsRefusal {
    /// Providers are authorized but `egress-bounds.yaml` is absent or could not be read.
    Undeclared(String),
    /// The bounds file's parser refused it, or this gate's own `user_prefix`/`vault.addr` check did.
    Refused(String),
}

impl std::fmt::Display for EgressBoundsRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EgressBoundsRefusal::Undeclared(e) => write!(
                f,
                "providers are authorized but {} could not be read: {e}",
                maknae_config::EGRESS_BOUNDS_FILE
            ),
            EgressBoundsRefusal::Refused(e) => write!(
                f,
                "providers are authorized but the egress bounds were refused — {e}"
            ),
        }
    }
}

/// Which refusal a failed bounds LOAD is (#240b). Pure, over the loader's own
/// error taxonomy, so the mapping is tested with real values rather than
/// inferred from a variant name (round 8 of self-review: an absent file is
/// `ConfigError::NotFound`, not `Io`, and a match written against the name
/// sent the single most common operator state — no file — to "refused").
///
/// `Undeclared` — the file could not be READ: absent, unreadable, a symlink,
/// insecure permissions, an unsupported platform. The operator's next step is
/// on the file's existence or mode. `Refused` — the file WAS read and its
/// content was refused: a YAML error, a duplicate key, a shape refusal. The
/// next step is in the file's content.
pub fn classify_bounds_load_error(e: maknae_config::ConfigError) -> EgressBoundsRefusal {
    use maknae_config::ConfigError;
    match e {
        ConfigError::Io(_)
        | ConfigError::NotFound { .. }
        | ConfigError::Symlink { .. }
        | ConfigError::InsecurePermissions { .. }
        | ConfigError::PermissionsUnsupported => EgressBoundsRefusal::Undeclared(e.to_string()),
        other => EgressBoundsRefusal::Refused(other.to_string()),
    }
}

pub fn egress_bounds_boot_gate(
    providers: &maknae_config::ProviderSet,
    bounds: Option<&maknae_config::EgressBounds>,
) -> Result<(), EgressBoundsRefusal> {
    if providers.is_empty() {
        return Ok(());
    }
    let Some(b) = bounds else {
        return Err(EgressBoundsRefusal::Undeclared(format!(
            "{} is absent or unreadable",
            maknae_config::EGRESS_BOUNDS_FILE
        )));
    };
    if let Err(why) = maknae_config::kv_fragment_is_acceptable(&b.user_prefix) {
        return Err(EgressBoundsRefusal::Refused(format!("user_prefix {why}")));
    }
    if !maknae_config::vault_path_is_safe(&b.user_prefix) {
        return Err(EgressBoundsRefusal::Refused(
            "user_prefix has a character outside [A-Za-z0-9._/-]".into(),
        ));
    }
    if b.user_prefix.len() > maknae_config::MAX_USER_PREFIX_BYTES {
        return Err(EgressBoundsRefusal::Refused(format!(
            "user_prefix exceeds {} bytes",
            maknae_config::MAX_USER_PREFIX_BYTES
        )));
    }
    if let Err(e) = maknae_vault::validate_vault_addr(&b.vault_addr) {
        return Err(EgressBoundsRefusal::Refused(format!("vault.addr: {e}")));
    }
    Ok(())
}

/// Fail closed when the config promises offload the daemon cannot perform.
///
/// **Pure predicate, deliberately here and not in `run.rs`.** `run.rs` is T3 and
/// mutation-excluded — it is orchestration, and its decisions live in the T1
/// files — so a refusal decision placed there would never be mutation-tested.
///
/// **Deliberately not in the parser either.** Erroring during parse would make
/// `AuditConfig.siem == Some(_)` unreachable at runtime, stranding the
/// `document.rs` disclosure-mask logic the key is retained for (operator ruling
/// 2026-09-05: the key stays, reserved for #223). Parse normally; refuse here.
pub fn audit_offload_boot_gate(
    cfg: &maknae_config::AuditConfig,
) -> Result<(), SiemOffloadUnsupported> {
    match cfg.siem {
        Some(_) => Err(SiemOffloadUnsupported),
        None => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootVaultKeyRefused(pub &'static str);

impl std::fmt::Display for RootVaultKeyRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "vault.{0} in the root maknae.yaml is not read by maknaed: set {0} in {1}",
            self.0,
            maknae_config::EGRESS_BOUNDS_FILE
        )
    }
}

pub fn root_vault_boot_gate(
    vault: Option<&maknae_config::Value>,
) -> Result<(), RootVaultKeyRefused> {
    let Some(maknae_config::Value::Map(entries)) = vault else {
        return Ok(());
    };
    match ["kv_mount", "user_prefix"]
        .into_iter()
        .find(|key| entries.iter().any(|(k, _)| k.as_str() == *key))
    {
        Some(key) => Err(RootVaultKeyRefused(key)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    // ---- #240a D5-E: the egress bounds boot gate -------------------------

    fn set() -> maknae_config::ProviderSet {
        use maknae_config::Value;
        maknae_config::providers_from_section(Some(&Value::Seq(vec![Value::Map(vec![
            ("name".into(), Value::Str("openai".into())),
            (
                "endpoint".into(),
                Value::Str("https://api.example.test/v1".into()),
            ),
            ("models".into(), Value::Seq(vec![Value::Str("m".into())])),
        ])])))
        .unwrap()
    }

    fn bounds(user_prefix: &str) -> maknae_config::EgressBounds {
        maknae_config::EgressBounds {
            kv_mount: "maknae-kv".into(),
            user_prefix: user_prefix.into(),
            vault_addr: "https://vault.example:8200".into(),
        }
    }

    #[test]
    fn no_authorized_provider_needs_no_bounds() {
        let empty = maknae_config::ProviderSet::empty();
        assert_eq!(super::egress_bounds_boot_gate(&empty, None), Ok(()));
        assert_eq!(
            super::egress_bounds_boot_gate(&empty, Some(&bounds("/not a fragment"))),
            Ok(())
        );
    }

    #[test]
    fn an_authorized_set_with_sound_bounds_boots() {
        assert_eq!(
            super::egress_bounds_boot_gate(&set(), Some(&bounds("maknae/users"))),
            Ok(())
        );
        let at = "u".repeat(maknae_config::MAX_USER_PREFIX_BYTES);
        assert_eq!(
            super::egress_bounds_boot_gate(&set(), Some(&bounds(&at))),
            Ok(())
        );
    }

    #[test]
    fn an_authorized_set_refuses_a_user_prefix_that_is_not_a_mount_relative_fragment() {
        for bad in [
            "",
            "/maknae/users",
            "maknae/users/",
            "maknae-kv/data/maknae/users",
            "maknae/../users",
            "maknae users",
            "maknae/us%rs",
            "maknae/üsers",
            "maknae/{users}",
        ] {
            match super::egress_bounds_boot_gate(&set(), Some(&bounds(bad))) {
                Err(super::EgressBoundsRefusal::Refused(m)) => {
                    assert!(m.starts_with("user_prefix "), "{bad:?}: {m}")
                }
                other => panic!("expected Refused for {bad:?}, got {other:?}"),
            }
        }
        let over = "u".repeat(maknae_config::MAX_USER_PREFIX_BYTES + 1);
        match super::egress_bounds_boot_gate(&set(), Some(&bounds(&over))) {
            Err(super::EgressBoundsRefusal::Refused(m)) => assert!(m.contains("exceeds"), "{m}"),
            other => panic!("expected an over-length refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_authorized_set_with_undeclared_bounds_refuses_to_boot() {
        match super::egress_bounds_boot_gate(&set(), None) {
            Err(super::EgressBoundsRefusal::Undeclared(m)) => {
                assert!(m.contains(maknae_config::EGRESS_BOUNDS_FILE), "{m}")
            }
            other => panic!("expected an undeclared-bounds refusal, got {other:?}"),
        }
    }

    #[test]
    fn both_refusals_render_actionably() {
        let u = super::EgressBoundsRefusal::Undeclared("no such file".into()).to_string();
        assert!(
            u.contains("authorized") && u.contains("could not be read"),
            "{u}"
        );
        let r = super::EgressBoundsRefusal::Refused("user_prefix is empty".into()).to_string();
        assert!(
            r.contains("authorized") && r.contains("user_prefix is empty"),
            "{r}"
        );
    }

    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn principal() -> Principal {
        Principal {
            name: "operator".into(),
            uid: 501,
        }
    }

    /// Trigger 1: reachable off-root, unconditionally.
    #[test]
    fn missing_principal_refuses_boot() {
        let d = std::env::temp_dir().join(format!("bg_nop_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let got = authz_policy_source(&d, None);
        let _ = std::fs::remove_dir_all(&d);
        match got {
            Err(AuthzBootRefusal::MissingPrincipal) => {}
            other => panic!("expected MissingPrincipal, got {other:?}"),
        }
    }

    /// The MissingPrincipal rendering names the section and the remedy —
    /// operators grep boot logs for this.
    #[test]
    fn missing_principal_rendering_names_the_section() {
        let msg = AuthzBootRefusal::MissingPrincipal.to_string();
        assert!(msg.contains("principal"), "{msg}");
        assert!(msg.contains("enroll"), "{msg}");
    }

    fn policy_dir(tag: &str, authz: &str, bindings: Option<&str>) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bg_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        let files = [("authz.yaml", Some(authz)), ("bindings.yaml", bindings)];
        for (name, body) in files {
            let Some(body) = body else { continue };
            std::fs::write(d.join(name), body).unwrap();
            std::fs::set_permissions(d.join(name), std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        d
    }

    const EMPTY_POLICY: &str = "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n";
    const ADMIN_ROOT: &str = "schema_version: 1\nbindings:\n  admin: [\"root\"]\n";

    /// Trigger 2, load half: off-root the euid-owned fixture refuses at the
    /// hardened door with the `Load` discriminant; as root the fixture IS
    /// root-owned and the load succeeds (both branches carried).
    #[test]
    fn refused_policy_load_maps_to_construct_load() {
        let d = policy_dir("load", EMPTY_POLICY, None);
        let got = authz_policy_source(&d, Some(principal()));
        let _ = std::fs::remove_dir_all(&d);
        if nix::unistd::geteuid().is_root() {
            assert!(got.is_ok(), "as root the fixture IS root-owned: {got:?}");
        } else {
            match got {
                Err(AuthzBootRefusal::Construct(AuthzBasicError::Load(ref m))) => {
                    assert!(
                        m.contains("root"),
                        "load refusal must name the owner rule: {m}"
                    )
                }
                other => panic!("expected Construct(Load), got {other:?}"),
            }
        }
    }

    fn hermetic_load(paths: PolicyPaths, pr: Principal) -> Result<PolicySource, AuthzBasicError> {
        PolicySource::load_with_requirement(
            paths,
            pr,
            maknae_config::TargetRequired {
                owner: None,
                mode_mask: Some(0o022),
                nlink_exactly_one: false,
                regular_file: true,
                max_bytes: None,
            },
        )
    }

    const LABEL: &str = "UNCLASSIFIED";

    fn sha_digests(source: &PolicySource) -> std::collections::BTreeMap<String, [u8; 32]> {
        source.section_digests(maknae_state::envelope::sha256)
    }

    /// The identity graph the store would hold for `layer`, built in memory.
    fn identity_graph(layer: &maknae_graph::identity::IdentityLayer) -> Arc<Graph> {
        let persisted = maknae_graph::kernel::persisted_compiled_set(LABEL);
        let vocab = maknae_state::vocabulary::digest(&persisted).unwrap();
        Arc::new(
            maknae_graph::identity::build(
                layer,
                None,
                &persisted,
                vocab,
                1,
                maknae_graph::record::ProvenanceKind::Seed,
            )
            .unwrap(),
        )
    }

    /// The SUCCESS arm, off-root, nothing stubbed: the hermetic load door
    /// builds a real `PolicySource`, and the gate compiles the PDP over the
    /// identity graph that source declares.
    #[test]
    fn gate_success_returns_the_authorizer() {
        use maknae_authz_basic::Baseline;
        use maknae_security::Authorizer;
        let d = policy_dir("ok", EMPTY_POLICY, Some(ADMIN_ROOT));
        let source = authz_policy_source_with(&d, Some(principal()), hermetic_load);
        let _ = std::fs::remove_dir_all(&d);
        let source = source.expect("load success arm");
        assert_eq!(source.paths(), &PolicyPaths::in_dir(&d));
        let digests = sha_digests(&source);
        let graph = identity_graph(&source.identity_layer(LABEL, digests.get("bindings").copied()));
        let auth = authz_boot_gate(
            source,
            graph.clone(),
            &maknae_authz_basic::compiled_set(LABEL),
        )
        .expect("gate success arm");
        assert!(Arc::ptr_eq(auth.snapshot().persisted(), &graph));
        assert_eq!(Baseline::principal(&auth), &principal());
        assert_eq!(
            Baseline::digest(&auth)(b"x"),
            maknae_state::envelope::sha256(b"x")
        );
        assert_eq!(
            auth.subjects().unwrap()[0].members,
            vec!["uid:0".to_string()]
        );
        let refused = Baseline::load_source(&auth);
        assert!(
            matches!(refused, Err(AuthzBasicError::Load(_))),
            "the production loader reloads from the gate's path: {refused:?}"
        );
    }

    /// Trigger 3: a booted identity layer that is not the file's refuses
    /// with the compiler's reason.
    #[test]
    fn a_compile_refusal_refuses_boot_naming_the_cause() {
        let d = policy_dir("compile", EMPTY_POLICY, Some(ADMIN_ROOT));
        let source = authz_policy_source_with(&d, Some(principal()), hermetic_load);
        let _ = std::fs::remove_dir_all(&d);
        let source = source.unwrap();
        let stale = identity_graph(&source.identity_layer(LABEL, None));
        let got = authz_boot_gate(source, stale, &maknae_authz_basic::compiled_set(LABEL));
        match got {
            Err(e @ AuthzBootRefusal::Compile(CompileError::Identity(_))) => {
                let m = e.to_string();
                assert!(m.starts_with("authz snapshot identity refused: "), "{m}");
                assert!(m.contains("differs"), "{m}");
            }
            other => panic!("expected Compile(Identity), got {other:?}"),
        }
    }

    #[test]
    fn the_principal_reaches_the_load_verbatim() {
        let d = policy_dir("verbatim", EMPTY_POLICY, None);
        let sent = Principal {
            name: "verbatim".into(),
            uid: 4242,
        };
        let seen: std::cell::RefCell<Option<Principal>> = std::cell::RefCell::new(None);
        let got = authz_policy_source_with(&d, Some(sent.clone()), |paths, pr| {
            *seen.borrow_mut() = Some(pr.clone());
            hermetic_load(paths, pr)
        });
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(got.expect("load success arm").principal(), &sent);
        assert_eq!(*seen.borrow(), Some(sent));
    }

    #[test]
    fn an_authz_yaml_that_still_carries_bindings_refuses_naming_bindings_yaml() {
        let d = policy_dir(
            "moved",
            "schema_version: 1\nbindings:\n  admin: [\"root\"]\n",
            None,
        );
        let got = authz_policy_source_with(&d, Some(principal()), hermetic_load);
        let _ = std::fs::remove_dir_all(&d);
        match got {
            Err(AuthzBootRefusal::Construct(AuthzBasicError::Load(ref m))) => {
                assert!(
                    m.contains("bindings.yaml") && m.contains("authz.yaml"),
                    "{m}"
                )
            }
            other => panic!("expected Construct(Load), got {other:?}"),
        }
    }

    #[test]
    fn an_invalid_bindings_yaml_refuses_boot_and_a_missing_one_is_absent() {
        let bad = policy_dir(
            "badb",
            EMPTY_POLICY,
            Some("schema_version: 1\nbindings: [\n"),
        );
        let got = authz_policy_source_with(&bad, Some(principal()), hermetic_load);
        assert!(
            matches!(
                &got,
                Err(AuthzBootRefusal::Construct(AuthzBasicError::Load(m))) if m.contains("bindings.yaml")
            ),
            "{got:?}"
        );
        let missing = policy_dir("nob", EMPTY_POLICY, None);
        let s = authz_policy_source_with(&missing, Some(principal()), hermetic_load).unwrap();
        assert_eq!(s.bindings().roles, None);
        assert!(s.bindings().is_missing());
        for d in [bad, missing] {
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// Trigger 2, bindings half — the filesystem-free mapping killer that
    /// holds on EVERY lane (root included): a constructed `Bindings` error
    /// converts to the `Construct` arm and its rendering passes through.
    #[test]
    fn bindings_error_maps_through_construct_arm_verbatim() {
        let e = AuthzBasicError::Bindings(
            "looking up 'ghost' failed (errno 5); nothing was changed".into(),
        );
        let refusal: AuthzBootRefusal = e.into();
        match &refusal {
            AuthzBootRefusal::Construct(AuthzBasicError::Bindings(m)) => {
                assert!(m.contains("ghost"))
            }
            other => panic!("expected Construct(Bindings), got {other:?}"),
        }
        assert!(
            refusal.to_string().contains("ghost"),
            "rendering must pass through"
        );
        assert!(
            refusal.to_string().contains("bindings invalid"),
            "AuthzBasicError's own prefix must survive: {refusal}"
        );
    }

    fn audit_cfg(siem: Option<&str>) -> maknae_config::AuditConfig {
        maknae_config::AuditConfig {
            readers: Vec::new(),
            jsonl_path: std::path::PathBuf::from("/var/log/maknae/audit.jsonl"),
            siem: siem.map(String::from),
            au3_1: serde_json::Value::Null,
        }
    }

    #[test]
    fn an_unset_siem_permits_boot() {
        assert!(audit_offload_boot_gate(&audit_cfg(None)).is_ok());
    }

    #[test]
    fn a_configured_siem_refuses_boot() {
        assert_eq!(
            audit_offload_boot_gate(&audit_cfg(Some("https://siem.example.mil:8443/ingest"))),
            Err(SiemOffloadUnsupported)
        );
    }

    #[test]
    fn even_an_empty_siem_string_refuses_boot() {
        // PRESENCE of the key is the signal, not its content -- an empty string
        // is still an operator asserting they configured offload.
        assert_eq!(
            audit_offload_boot_gate(&audit_cfg(Some(""))),
            Err(SiemOffloadUnsupported)
        );
    }

    /// THE classifier, over REAL loader errors — round 8 of self-review found
    /// the previous test asserting only the Display of a hand-built variant,
    /// which cannot see a wrong mapping. An absent file is `NotFound`, and it
    /// must be "could not be read"; a parse refusal must be "refused".
    #[test]
    fn a_failed_bounds_load_is_classified_by_what_happened_not_by_variant_name() {
        use maknae_config::ConfigError;
        let undeclared = |e: ConfigError| match super::classify_bounds_load_error(e) {
            super::EgressBoundsRefusal::Undeclared(m) => m,
            other => panic!("expected Undeclared, got {other}"),
        };
        let refused = |e: ConfigError| match super::classify_bounds_load_error(e) {
            super::EgressBoundsRefusal::Refused(m) => m,
            other => panic!("expected Refused, got {other}"),
        };
        // could not be read: absent, unreadable, a symlink, insecure mode
        assert!(undeclared(ConfigError::NotFound {
            path: "/etc/maknae/egress-bounds.yaml".into()
        })
        .contains("egress-bounds.yaml"));
        undeclared(ConfigError::Io("permission denied".into()));
        undeclared(ConfigError::Symlink {
            path: "/etc/maknae/egress-bounds.yaml".into(),
        });
        undeclared(ConfigError::InsecurePermissions {
            path: "/etc/maknae/egress-bounds.yaml".into(),
            mode: 0o666,
        });
        // read and refused: the content
        let m = refused(ConfigError::InvalidEgressBounds(
            "'vault' is required".into(),
        ));
        assert!(m.contains("'vault' is required"), "{m}");
        refused(ConfigError::DuplicateKey {
            key: "kv_mount".into(),
            line: 3,
            col: 1,
        });
    }

    /// #240b: a plaintext Vault address in the bounds file is a BOOT refusal,
    /// not a first-request failure in the deputy.
    #[test]
    fn a_plaintext_vault_addr_in_the_bounds_is_refused_at_boot() {
        let mut b = bounds("maknae/users");
        b.vault_addr = "http://vault.example:8200".into();
        match super::egress_bounds_boot_gate(&set(), Some(&b)) {
            Err(super::EgressBoundsRefusal::Refused(m)) => assert!(m.contains("vault.addr"), "{m}"),
            other => panic!("expected a Refused naming vault.addr, got {other:?}"),
        }
    }

    /// #240b: a bounds file that was READ and refused says so, with the
    /// parser's reason, and never "could not be read".
    #[test]
    fn a_refused_bounds_file_says_refused_and_carries_the_reason() {
        let m =
            super::EgressBoundsRefusal::Refused("egress-bounds.yaml: 'vault' is required".into())
                .to_string();
        assert!(m.contains("were refused"), "{m}");
        assert!(m.contains("'vault' is required"), "{m}");
        assert!(!m.contains("could not be read"), "{m}");
        let u = super::EgressBoundsRefusal::Undeclared("absent".into()).to_string();
        assert!(
            u.contains("could not be read") && u.contains("absent"),
            "{u}"
        );
    }

    #[test]
    fn the_refusal_message_names_the_key_and_the_tracking_issue() {
        let m = SiemOffloadUnsupported.to_string();
        assert!(m.contains("audit.siem"), "must name the key: {m}");
        assert!(m.contains("223"), "must point at the tracking issue: {m}");
    }

    /// The credential-lifecycle invariant, asserted on the source because the
    /// type system cannot hold it.
    ///
    /// Every post-`mint()` startup failure must route through the
    /// unconditional revoke, or the privileged kernel-plane Vault token leaks
    /// until lease expiry. The egress-bounds gate needs no Vault — a config
    /// read and a string comparison — so it belongs BEFORE the mint, where a
    /// failure has nothing minted to revoke.
    ///
    /// A behavioural test cannot reach this: registering a provider requires a
    /// root-owned config section, so the boot-binary harness can never get a
    /// provider past `maknae-config` to exercise the gate. What CAN regress is
    /// someone moving the call during a refactor, and that is exactly what
    /// this catches.
    /// #240: the egress backend is chosen PRE-MINT for the same reason —
    /// a missing `_maknae-egress` account must refuse before anything is
    /// minted — and after the bounds gate, so the refusals come in the order
    /// an operator fixes them.
    #[test]
    fn the_egress_backend_is_selected_after_the_bounds_gate_and_before_the_vault_mint() {
        let run_rs = include_str!("run.rs");
        let gate = run_rs
            .find("egress_bounds_boot_gate(boot.providers()")
            .expect("the egress-bounds gate call moved or was renamed");
        let select = run_rs
            .find("production_egress(boot.providers(), &egress_cfg)")
            .expect("the egress backend selection moved or was renamed");
        let mint = run_rs
            .find(".mint()")
            .expect("the vault mint call moved or was renamed");
        assert!(
            gate < select,
            "the bounds gate must precede the backend selection"
        );
        assert!(select < mint, "the backend selection must precede mint()");
    }

    #[test]
    fn the_egress_bounds_gate_is_called_before_the_vault_mint() {
        let run_rs = include_str!("run.rs");
        let gate = run_rs
            .find("egress_bounds_boot_gate(boot.providers()")
            .expect("the egress-bounds gate call moved or was renamed");
        let mint = run_rs
            .find(".mint()")
            .expect("the vault mint call moved or was renamed");
        assert!(
            gate < mint,
            "the egress-bounds gate must run BEFORE mint(): a post-mint refusal \
             leaves the privileged kernel-plane token live until lease expiry \
             unless it routes through the unconditional revoke"
        );
    }

    #[test]
    fn a_root_vault_block_naming_the_user_key_layout_refuses_boot_and_points_at_the_bounds_file() {
        use maknae_config::Value;
        let block = |extra: &[(&str, &str)]| {
            let mut m = vec![(
                "addr".to_string(),
                Value::Str("https://vault.example:8200".into()),
            )];
            m.extend(
                extra
                    .iter()
                    .map(|(k, v)| (k.to_string(), Value::Str((*v).into()))),
            );
            Value::Map(m)
        };
        assert_eq!(super::root_vault_boot_gate(None), Ok(()));
        assert_eq!(super::root_vault_boot_gate(Some(&block(&[]))), Ok(()));
        assert_eq!(
            super::root_vault_boot_gate(Some(&block(&[("kv_mount", "maknae-kv")]))),
            Err(super::RootVaultKeyRefused("kv_mount"))
        );
        assert_eq!(
            super::root_vault_boot_gate(Some(&block(&[("user_prefix", "maknae/users")]))),
            Err(super::RootVaultKeyRefused("user_prefix"))
        );
        assert_eq!(
            super::RootVaultKeyRefused("user_prefix").to_string(),
            "vault.user_prefix in the root maknae.yaml is not read by maknaed: set user_prefix in egress-bounds.yaml"
        );
    }

    #[test]
    fn the_root_vault_gate_runs_before_the_vault_mint() {
        let run_rs = include_str!("run.rs");
        const GATE: &str = "root_vault_boot_gate(boot.section(maknae_vault::VAULT_SECTION))";
        const SHADOWED: &str = "for shadowed in boot.shadowed_sections(maknae_vault::VAULT_SECTION) {\n        crate::boot_gate::root_vault_boot_gate(Some(shadowed))";
        const MINT: &str = "    client\n        .mint()\n        .await\n";
        assert_eq!(run_rs.matches(GATE).count(), 1, "the root vault gate call");
        assert_eq!(
            run_rs.matches(SHADOWED).count(),
            1,
            "the shadowed vault gate loop"
        );
        assert_eq!(run_rs.matches(MINT).count(), 1, "the vault mint call");
        let gate = run_rs.find(GATE).unwrap();
        let shadowed = run_rs.find(SHADOWED).unwrap();
        let mint = run_rs.find(MINT).unwrap();
        assert!(gate < mint, "the root vault gate must run before mint()");
        assert!(
            shadowed < mint,
            "the shadowed vault gate must run before mint()"
        );
    }
}
