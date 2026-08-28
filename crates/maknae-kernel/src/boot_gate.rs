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
//!   2. `BasicAuthorizer::new` refuses (policy load or bindings semantics).

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

#[cfg(test)]
mod tests {
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
}
