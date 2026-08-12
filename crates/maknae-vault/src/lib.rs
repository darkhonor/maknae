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
#[cfg(test)]
mod transport_tests;

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
