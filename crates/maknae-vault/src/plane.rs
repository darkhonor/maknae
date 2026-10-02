//! The two planes. Never hardcode a bare `maknae`/`maknaed` string; derive from here (spec §3 tri-naming).

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

    /// The plane on the OTHER end of a plane-to-plane channel. `Kernel`'s peer is the
    /// `Cli`, and vice versa. Used to compute the expected peer URI-SAN for mTLS.
    pub fn peer(self) -> Plane {
        match self {
            Plane::Kernel => Plane::Cli,
            Plane::Cli => Plane::Kernel,
        }
    }

    /// The URI-SAN this plane's leaf must carry.
    pub fn uri_san(&self, deployment_id: &str) -> String {
        let plane = match self {
            Plane::Kernel => "kernel",
            Plane::Cli => "cli",
        };
        format!("maknae://{deployment_id}/plane/{plane}")
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
            "maknae://dev-01/plane/kernel"
        );
    }

    #[test]
    fn peer_is_the_other_plane() {
        assert_eq!(Plane::Kernel.peer(), Plane::Cli);
        assert_eq!(Plane::Cli.peer(), Plane::Kernel);
    }

    #[test]
    fn cli_names() {
        assert_eq!(Plane::Cli.pki_sign_role(), "maknae-cli");
        assert_eq!(Plane::Cli.config_prefix(), None);
        assert_eq!(Plane::Cli.uri_san("dev-01"), "maknae://dev-01/plane/cli");
    }

    #[test]
    fn only_a_token_the_client_minted_by_approle_is_revoked_by_it() {
        assert!(PlaneTokenSource::AppRoleLogin.revoked_by_the_client());
        assert!(!PlaneTokenSource::StoredUserLogin.revoked_by_the_client());
    }
}
