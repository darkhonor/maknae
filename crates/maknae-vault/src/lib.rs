//! maknae-vault — shared, NON-PRIVILEGED Vault plane-cert client (ADR-0005, amended
//! by ADR-0018). Stage 1: config -> AppRole auth (standing raw SecretID) -> P-384 CSR ->
//! pki/sign -> memory-only leaf, plus the CA-pin loader + URI-SAN verifier.
//! FIPS: the runtime `.fips()` assertion (assert_fips_provider, in fips_glue) is
//! authoritative; the load-bearing install-before-first-Vault-client ordering keeps
//! vaultrs's reqwest on the FIPS provider (spec §6.1).
#![forbid(unsafe_code)]

mod auth;
mod ca;
mod client;
mod config;
mod csr;
mod csr_gen;
mod error;
mod fips;
mod fips_glue;
mod operator;
mod plane;
mod plane_verify;
mod resolver;
mod secret_io;
mod secret_source;
mod supervisor;
mod supervisor_run;
mod tls;
mod verify;
// The UDS transport is unix-only (UnixStream / SO_PEERCRED); the pure-rustls layers above
// (tls/resolver/plane_verify) compile everywhere so the Stage-1 client stays cross-platform.
#[cfg(unix)]
mod peercred;
#[cfg(unix)]
mod socket;
#[cfg(unix)]
mod stream;
pub use auth::{AppRoleAuth, AuthMethod, VaultToken};
pub use ca::{load_ca_pin, CaBundle};
pub use client::{PlaneClient, PlaneIdentity};
pub use config::{
    load_vault_config, validate_deployment_id, vault_config_from_document, VaultConfig,
    DEFAULT_APPROLE_MOUNT, DEFAULT_PKI_INT_MOUNT, VAULT_SECTION,
};
pub use csr_gen::generate_plane_csr;
pub use error::VaultError;
pub use fips_glue::{assert_fips_provider, install_default_crypto_provider};
pub use operator::OperatorClient;
#[cfg(unix)]
pub use peercred::PeerCreds;
pub use plane::Plane;
pub use secret_source::{
    resolve_cli_secret_source, resolve_daemon_secret_source, CliSecretSource, CredentialSourceKind,
    DaemonSecretSource,
};
#[cfg(unix)]
pub use stream::{
    AcceptRejection, AuthenticatedStream, PlaneConnector, PlaneListener, RawPlaneConn, RejectReason,
};
pub use verify::{verify_plane_uri_san, VerifyError};

#[used]
pub static CRATE_MARKER: &[u8] = b"MAKNAE_VAULT";

/// Read a non-sensitive regular file (CA pins, sealed-source artifacts, plaintext
/// credential files after their own gate) through `maknae-io`'s anchor-relative
/// checked read — `regular_file: true`, no owner/mode/nlink requirement of its own
/// (callers that need a permission gate apply it separately, e.g.
/// `client::read_secret_credential`'s `mode & 0o077` check). The target shape is
/// fixed and built internally so no `maknae_io` type crosses this function's
/// signature — `#[cfg(unix)]` callers never need to name it, and the non-unix arm
/// below never needs it to exist.
///
/// Non-Unix has no `maknae-io` dependency (it is `cfg(unix)`-only in `Cargo.toml`;
/// the crate's unconditional `nix` dependency means no non-unix build exists today
/// regardless) and no portable equivalent of the anchor-relative, `O_NOFOLLOW`-checked
/// read it performs, so this refuses rather than falling back to an unchecked
/// `std::fs::read` (fail closed; mirrors `maknae-config::load_file`).
///
/// A relative `path` is absolutized by `read_absolute` itself (issue #137); the
/// `absolute_storage_path` helper that used to do it here — one of three hand-rolled
/// copies of the same plumbing — is gone, and with it this crate's only ambient
/// `current_dir` read.
fn read_storage(path: &std::path::Path) -> Result<zeroize::Zeroizing<Vec<u8>>, VaultError> {
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(VaultError::PermissionsUnsupported)
    }
    #[cfg(unix)]
    {
        let target = maknae_io::TargetRequired {
            owner: None,
            mode_mask: None,
            nlink_exactly_one: false,
            regular_file: true,
        };
        maknae_io::read_absolute(path, target, maknae_io::StrategyPref::Auto)
            .map(|out| out.value)
            .map_err(|error| VaultError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::other(error.to_string()),
            })
    }
}

#[cfg(test)]
mod transport_tests;

#[cfg(test)]
mod storage_tests {
    use super::*;

    // Compiles/runs only with the real (unix) `maknae-io` lane wired through
    // `read_storage` — the regression this guards is #133:
    // a `#[cfg(not(unix))] mod maknae_io` shim that referenced `maknae_io::` types
    // unqualified from sibling modules, which cannot compile on non-unix (E0433,
    // a crate-root module is not in the extern prelude) and was unreachable anyway
    // since `nix` is an unconditional dependency.
    #[cfg(unix)]
    #[test]
    fn read_storage_reads_a_regular_file() {
        let path = std::env::temp_dir().join(format!(
            "maknae-vault-read-storage-ok-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"stage-1-storage-bytes").unwrap();
        let got = read_storage(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(got.unwrap().as_slice(), b"stage-1-storage-bytes");
    }

    #[cfg(unix)]
    #[test]
    fn read_storage_missing_file_fails_closed() {
        let path = std::path::Path::new("/nonexistent/maknae-vault-read-storage-nope");
        assert!(matches!(read_storage(path), Err(VaultError::Io { .. })));
    }

    #[cfg(not(unix))]
    #[test]
    fn read_storage_refuses_without_unix_permissions() {
        let path = std::path::Path::new("storage.bin");
        assert!(matches!(
            read_storage(path),
            Err(VaultError::PermissionsUnsupported)
        ));
    }
}
