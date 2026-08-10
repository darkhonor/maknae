//! The two planes. Each maps to THREE distinct names — never hardcode a bare
//! `maknae`/`maknaed` string; derive from here (spec §3 tri-naming).

/// Which plane a client acts as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plane {
    /// The privileged trust-plane daemon (`maknaed`).
    Kernel,
    /// The untrusted operator CLI (`maknae`).
    Cli,
}

impl Plane {
    /// AppRole role used to LOG IN.
    pub fn approle_role(&self) -> &'static str {
        match self {
            Plane::Kernel => "maknaed",
            Plane::Cli => "maknae",
        }
    }

    /// PKI role used to `pki/sign`.
    pub fn pki_sign_role(&self) -> &'static str {
        match self {
            Plane::Kernel => "maknae-kernel",
            Plane::Cli => "maknae-cli",
        }
    }

    /// Config-file prefix (`<prefix>-approle-id`, `<prefix>-secret-id`).
    pub fn config_prefix(&self) -> &'static str {
        match self {
            Plane::Kernel => "maknaed",
            Plane::Cli => "maknae",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_names() {
        assert_eq!(Plane::Kernel.approle_role(), "maknaed");
        assert_eq!(Plane::Kernel.pki_sign_role(), "maknae-kernel");
        assert_eq!(Plane::Kernel.config_prefix(), "maknaed");
        assert_eq!(
            Plane::Kernel.uri_san("dev-01"),
            "maknae://dev-01/plane/kernel"
        );
    }

    #[test]
    fn cli_names() {
        assert_eq!(Plane::Cli.approle_role(), "maknae");
        assert_eq!(Plane::Cli.pki_sign_role(), "maknae-cli");
        assert_eq!(Plane::Cli.config_prefix(), "maknae");
        assert_eq!(Plane::Cli.uri_san("dev-01"), "maknae://dev-01/plane/cli");
    }
}
