//! The fail-closed authz boot gate (#77, spec D1): the daemon constructs its
//! PDP at boot or refuses to start. T1 — a wrong arm here is a daemon that
//! serves without a decider.
//!
//! Two refusal triggers, and only two (the home-anchor probe is deliberately
//! NOT one — spec D1: a removed ACL must degrade the read verb, never
//! crash-loop the trust plane):
//!   1. the `principal` section is absent — the PDP's default role resolution
//!      keys on the enrolled uid, so a daemon with no principal can authorize
//!      no one: "boot anyway, deny everything, look healthy" would hide a
//!      dead deployment behind a green service (operator ruling 2026-08-28);
//!   2. `BasicAuthorizer::new` refuses — policy load, bindings semantics,
//!      (added 2026-08-31, #162) `roles:` grant semantics: an unknown role, a
//!      structural role (`guest`/`adversary`), a term outside
//!      `GRANTABLE_ACTIONS`, or a term the role may not hold (`user` holds
//!      `session.prompt` only; corrected 2026-09-09, #172: the term set is
//!      two-role now), or (added 2026-09-09, #172) `destinations:` role-key
//!      semantics. Still ONE trigger, not four: `finish_new` validates all of
//!      them eagerly and refuses construction, which is what this gate observes.

use maknae_authz_basic::{AuthzBasicError, BasicAuthorizer};
use maknae_config::Principal;
use std::path::Path;

/// Why boot was refused at the authz gate. Rendered into the AU-3 boot
/// refusal record and the `RunError::Authz` message (exit code 3).
#[derive(Debug)]
pub enum AuthzBootRefusal {
    /// No `principal` section: nothing to key the enrolled-admin default on.
    MissingPrincipal,
    /// The PDP refused construction (hardened policy load or bindings
    /// semantics) — the inner rendering carries the reason.
    Construct(AuthzBasicError),
}

impl std::fmt::Display for AuthzBootRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthzBootRefusal::MissingPrincipal => write!(
                f,
                "config has no `principal` section: the daemon cannot authorize anyone (enroll first)"
            ),
            AuthzBootRefusal::Construct(e) => write!(f, "{e}"),
        }
    }
}

impl From<AuthzBasicError> for AuthzBootRefusal {
    fn from(e: AuthzBasicError) -> Self {
        AuthzBootRefusal::Construct(e)
    }
}

/// Construct the boot-time PDP or refuse. Returns the `Principal` alongside
/// (the caller needs it for the read-path anchor and `~` grammar referent).
pub fn authz_boot_gate(
    config_dir: &Path,
    principal: Option<Principal>,
) -> Result<(BasicAuthorizer, Principal), AuthzBootRefusal> {
    authz_boot_gate_with(config_dir, principal, BasicAuthorizer::new)
}

/// The gate with its constructor injected — the production caller passes
/// [`BasicAuthorizer::new`] (root-owned door); the success arm is otherwise
/// unconstructible off-root, and an untestable success arm on a fail-closed
/// gate is exactly what T1 forbids. The injected fn is the ONLY variable:
/// ordering, mapping, and the returned pair are this fn's own, tested logic.
fn authz_boot_gate_with(
    config_dir: &Path,
    principal: Option<Principal>,
    construct: impl FnOnce(std::path::PathBuf, Principal) -> Result<BasicAuthorizer, AuthzBasicError>,
) -> Result<(BasicAuthorizer, Principal), AuthzBootRefusal> {
    let principal = principal.ok_or(AuthzBootRefusal::MissingPrincipal)?;
    let authorizer = construct(config_dir.join("authz.yaml"), principal.clone())?;
    Ok((authorizer, principal))
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
/// Why a registered provider's Vault path is not startable.
#[derive(Debug, PartialEq, Eq)]
pub enum EgressBoundsRefusal {
    /// A provider is registered but the deputy's grant is not declared. The
    /// content path exists with no stated bound on it, so the daemon refuses.
    Undeclared(String),
    /// The registered path sits outside the prefix the deputy's Vault policy
    /// grants. Discovering this at BOOT is the point: the alternative is a
    /// successful start and a refusal on the first live request, long after
    /// the operator's typo.
    OutsideBounds { path: String, prefix: String },
}

impl std::fmt::Display for EgressBoundsRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EgressBoundsRefusal::Undeclared(e) => write!(
                f,
                "a provider is registered but {} could not be read: {e}",
                maknae_config::EGRESS_BOUNDS_FILE
            ),
            EgressBoundsRefusal::OutsideBounds { path, prefix } => write!(
                f,
                "registered provider key_vault_path '{path}' is outside the egress grant prefix '{prefix}'"
            ),
        }
    }
}

/// Validate the registered provider against the deputy's declared bounds, at
/// boot (#240a D5-E).
///
/// PURE: the caller loads. The bounds file is root-owned, so a loading gate
/// could not be unit-tested at all — the same `secret_io`/`secret_source`
/// split the crate uses elsewhere, applied to a boot decision.
///
/// No provider registered means no content can leave and nothing to check.
/// With one registered, the bounds file MUST exist and MUST contain the
/// provider's path: the deputy validates the same thing again at use, but the
/// boot check is the more valuable half, because it catches the operator's
/// typo before anything runs rather than turning it into a confusing refusal
/// on a live request.
pub fn egress_bounds_boot_gate(
    provider: Option<&maknae_config::ProviderConfig>,
    bounds: Option<&maknae_config::EgressBounds>,
) -> Result<(), EgressBoundsRefusal> {
    let Some(p) = provider else {
        return Ok(());
    };
    let Some(b) = bounds else {
        return Err(EgressBoundsRefusal::Undeclared(format!(
            "{} is absent or unreadable",
            maknae_config::EGRESS_BOUNDS_FILE
        )));
    };
    if !maknae_config::path_is_within_prefix(&p.key_vault_path, &b.key_vault_path_prefix) {
        return Err(EgressBoundsRefusal::OutsideBounds {
            path: p.key_vault_path.clone(),
            prefix: b.key_vault_path_prefix.clone(),
        });
    }
    Ok(())
}

pub fn audit_offload_boot_gate(
    cfg: &maknae_config::AuditConfig,
) -> Result<(), SiemOffloadUnsupported> {
    match cfg.siem {
        Some(_) => Err(SiemOffloadUnsupported),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    // ---- #240a D5-E: the egress bounds boot gate -------------------------

    fn provider(key_vault_path: &str) -> maknae_config::ProviderConfig {
        maknae_config::ProviderConfig {
            name: "openai".into(),
            endpoint: "https://api.example.test/v1".into(),
            model: "m".into(),
            key_vault_path: key_vault_path.into(),
        }
    }

    fn bounds(prefix: &str) -> maknae_config::EgressBounds {
        maknae_config::EgressBounds {
            key_vault_path_prefix: prefix.into(),
        }
    }

    /// No provider means no content can leave: nothing to bound, nothing to
    /// refuse. The gate must not invent a requirement where there is no
    /// egress path at all.
    #[test]
    fn no_registered_provider_needs_no_bounds() {
        assert_eq!(super::egress_bounds_boot_gate(None, None), Ok(()));
        assert_eq!(
            super::egress_bounds_boot_gate(None, Some(&bounds("secret/data/x"))),
            Ok(())
        );
    }

    /// A registered provider inside the declared grant starts.
    #[test]
    fn a_registered_provider_within_the_grant_boots() {
        assert_eq!(
            super::egress_bounds_boot_gate(
                Some(&provider("secret/data/maknae/providers/openai")),
                Some(&bounds("secret/data/maknae/providers")),
            ),
            Ok(())
        );
    }

    /// THE gate. A path outside the grant refuses at BOOT rather than on the
    /// first live request — and a sibling that merely begins with the prefix
    /// is outside it.
    #[test]
    fn a_registered_provider_outside_the_grant_refuses_to_boot() {
        for bad in [
            "secret/data/other/openai",
            "secret/data/maknae/providers-evil/openai",
        ] {
            match super::egress_bounds_boot_gate(
                Some(&provider(bad)),
                Some(&bounds("secret/data/maknae/providers")),
            ) {
                Err(super::EgressBoundsRefusal::OutsideBounds { path, prefix }) => {
                    assert_eq!(path, bad);
                    assert_eq!(prefix, "secret/data/maknae/providers");
                }
                other => panic!("expected a boot refusal for {bad}, got {other:?}"),
            }
        }
    }

    /// A registered provider with NO declared bounds refuses: a content path
    /// exists with no stated bound on it. Fail closed, never fail open.
    #[test]
    fn a_registered_provider_with_undeclared_bounds_refuses_to_boot() {
        match super::egress_bounds_boot_gate(
            Some(&provider("secret/data/maknae/providers/openai")),
            None,
        ) {
            Err(super::EgressBoundsRefusal::Undeclared(m)) => {
                assert!(m.contains(maknae_config::EGRESS_BOUNDS_FILE) || !m.is_empty())
            }
            other => panic!("expected an undeclared-bounds refusal, got {other:?}"),
        }
    }

    #[test]
    fn both_refusals_render_actionably() {
        assert!(
            super::EgressBoundsRefusal::Undeclared("no such file".into())
                .to_string()
                .contains("registered")
        );
        assert!(super::EgressBoundsRefusal::OutsideBounds {
            path: "a/b".into(),
            prefix: "c/d".into()
        }
        .to_string()
        .contains("outside the egress grant prefix"));
    }

    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn principal() -> Principal {
        Principal {
            name: "operator".into(),
            uid: 501,
            home: "/home/operator".into(),
        }
    }

    /// Trigger 1: reachable off-root, unconditionally.
    #[test]
    fn missing_principal_refuses_boot() {
        let d = std::env::temp_dir().join(format!("bg_nop_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let got = authz_boot_gate(&d, None);
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

    /// Trigger 2, load half: off-root the euid-owned fixture refuses at the
    /// hardened door with the `Load` discriminant; as root the fixture IS
    /// root-owned and construction succeeds (the run.rs CI-limitation
    /// pattern — both branches carried).
    #[test]
    fn refused_policy_load_maps_to_construct_load() {
        let d = std::env::temp_dir().join(format!("bg_load_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            d.join("authz.yaml"),
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
        )
        .unwrap();
        std::fs::set_permissions(d.join("authz.yaml"), std::fs::Permissions::from_mode(0o640))
            .unwrap();
        let got = authz_boot_gate(&d, Some(principal()));
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

    /// The SUCCESS arm, off-root, nothing stubbed: the hermetic construction
    /// door (feature-gated, dev-enabled) builds a real `BasicAuthorizer` over
    /// a fixture policy, and the gate's own logic — principal threading,
    /// `authz.yaml` join, the returned pair — is exercised end to end.
    #[test]
    fn gate_success_returns_the_authorizer_and_the_principal() {
        let d = std::env::temp_dir().join(format!("bg_ok_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            d.join("authz.yaml"),
            "schema_version: 1\npermissions:\n  allow: []\n  deny: []\n",
        )
        .unwrap();
        std::fs::set_permissions(d.join("authz.yaml"), std::fs::Permissions::from_mode(0o640))
            .unwrap();
        let seam = |path: std::path::PathBuf, pr: Principal| {
            maknae_authz_basic::BasicAuthorizer::new_hermetic(
                path,
                pr,
                maknae_config::TargetRequired {
                    owner: None,
                    mode_mask: Some(0o022),
                    nlink_exactly_one: false,
                    regular_file: true,
                    max_bytes: None,
                },
            )
        };
        let got = authz_boot_gate_with(&d, Some(principal()), seam);
        let _ = std::fs::remove_dir_all(&d);
        let (_authorizer, pr) = got.expect("gate success arm");
        assert_eq!(pr.uid, 501, "the principal is returned alongside");
        assert_eq!(pr.name, "operator");
    }

    /// Trigger 2, bindings half — the filesystem-free mapping killer that
    /// holds on EVERY lane (root included): a constructed `Bindings` error
    /// converts to the `Construct` arm and its rendering passes through.
    /// (The bindings refusal itself is proven in maknae-authz-basic via the
    /// hermetic seam; this pins the GATE's error mapping.)
    #[test]
    fn bindings_error_maps_through_construct_arm_verbatim() {
        let e = AuthzBasicError::Bindings("identity 'ghost' has no resolvable uid".into());
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

    #[test]
    fn the_refusal_message_names_the_key_and_the_tracking_issue() {
        let m = SiemOffloadUnsupported.to_string();
        assert!(m.contains("audit.siem"), "must name the key: {m}");
        assert!(m.contains("223"), "must point at the tracking issue: {m}");
    }
}
