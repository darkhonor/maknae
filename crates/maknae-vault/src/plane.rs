//! The two planes. Never hardcode a bare `maknae`/`maknaed` string; derive from here (spec §3 tri-naming).

use crate::agent_enroll::{AgentId, AGENT_ROLE_PREFIX};
use std::borrow::Cow;

/// Which plane a client acts as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plane {
    /// The privileged trust-plane daemon (`maknaed`).
    Kernel,
    /// The untrusted operator CLI (`maknae`).
    Cli,
}

impl Plane {
    /// PKI role used to `pki/sign`.
    pub fn pki_sign_role(&self) -> &'static str {
        match self {
            Plane::Kernel => "maknae-kernel",
            Plane::Cli => "maknae-cli",
        }
    }

    /// Config-file prefix (`<prefix>-approle-id`, `<prefix>-secret-id`); only the kernel plane has an AppRole.
    pub fn config_prefix(&self) -> Option<&'static str> {
        match self {
            Plane::Kernel => Some("maknaed"),
            Plane::Cli => None,
        }
    }

    /// The URI-SAN this plane's leaf must carry.
    pub fn uri_san(&self, trust_domain: &str) -> String {
        let plane = match self {
            Plane::Kernel => "kernel",
            Plane::Cli => "cli",
        };
        format!("spiffe://{trust_domain}/plane/{plane}")
    }
}

pub fn agent_uri_san(trust_domain: &str, agent: &AgentId) -> String {
    format!("spiffe://{trust_domain}/plane/agent/{}", agent.as_str())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlaneSubject {
    Fixed(Plane),
    Agent(AgentId),
}

impl PlaneSubject {
    pub fn pki_sign_role(&self) -> Cow<'static, str> {
        match self {
            PlaneSubject::Fixed(plane) => Cow::Borrowed(plane.pki_sign_role()),
            PlaneSubject::Agent(id) => Cow::Owned(format!("{AGENT_ROLE_PREFIX}{}", id.as_str())),
        }
    }

    pub fn san(&self, trust_domain: &str) -> String {
        match self {
            PlaneSubject::Fixed(plane) => plane.uri_san(trust_domain),
            PlaneSubject::Agent(id) => agent_uri_san(trust_domain, id),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlaneTokenSource {
    AppRoleLogin,
    StoredUserLogin,
}

impl PlaneTokenSource {
    pub(crate) fn revoked_by_the_client(self) -> bool {
        match self {
            PlaneTokenSource::AppRoleLogin => true,
            PlaneTokenSource::StoredUserLogin => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_names() {
        assert_eq!(Plane::Kernel.pki_sign_role(), "maknae-kernel");
        assert_eq!(Plane::Kernel.config_prefix(), Some("maknaed"));
        assert_eq!(
            Plane::Kernel.uri_san("dev-01"),
            "spiffe://dev-01/plane/kernel"
        );
    }

    #[test]
    fn cli_names() {
        assert_eq!(Plane::Cli.pki_sign_role(), "maknae-cli");
        assert_eq!(Plane::Cli.config_prefix(), None);
        assert_eq!(Plane::Cli.uri_san("dev-01"), "spiffe://dev-01/plane/cli");
    }

    fn hobi() -> AgentId {
        AgentId::parse("hobi").unwrap()
    }

    #[test]
    fn agent_identity_signs_with_its_own_role_and_one_san() {
        let subject = PlaneSubject::Agent(hobi());
        assert_eq!(subject.pki_sign_role(), "maknae-agent-hobi");
        assert_eq!(subject.san("dev-01"), "spiffe://dev-01/plane/agent/hobi");
        assert_eq!(subject.san("dev-01"), agent_uri_san("dev-01", &hobi()));
        assert_eq!(
            crate::SanRule::for_subject(&subject, "dev-01"),
            crate::SanRule::Exact("spiffe://dev-01/plane/agent/hobi".into())
        );
        for k in maknae_crypto::plane_key::PlaneKey::ALL {
            let (_, csr) = crate::generate_plane_csr(&subject, "dev-01", k).unwrap();
            assert!(crate::csr::csr_matches_plane_shape(
                &csr,
                "spiffe://dev-01/plane/agent/hobi",
                k
            ));
            assert!(!crate::csr::csr_matches_plane_shape(
                &csr,
                "spiffe://dev-01/plane/cli",
                k
            ));
        }
    }

    #[test]
    fn fixed_planes_sign_exactly_as_before() {
        for (plane, role, san) in [
            (
                Plane::Kernel,
                "maknae-kernel",
                "spiffe://dev-01/plane/kernel",
            ),
            (Plane::Cli, "maknae-cli", "spiffe://dev-01/plane/cli"),
        ] {
            let subject = PlaneSubject::Fixed(plane);
            assert!(matches!(subject.pki_sign_role(), Cow::Borrowed(r) if r == role));
            assert_eq!(subject.san("dev-01"), san);
            assert_eq!(
                crate::SanRule::for_subject(&subject, "dev-01"),
                crate::SanRule::for_plane(plane, "dev-01")
            );
            let k = maknae_crypto::plane_key::PlaneKey::ALL[0];
            let (_, csr) = crate::generate_plane_csr(&subject, "dev-01", k).unwrap();
            assert!(crate::csr::csr_matches_plane_shape(&csr, san, k));
        }
    }

    #[test]
    fn only_a_token_the_client_minted_by_approle_is_revoked_by_it() {
        assert!(PlaneTokenSource::AppRoleLogin.revoked_by_the_client());
        assert!(!PlaneTokenSource::StoredUserLogin.revoked_by_the_client());
    }
}
