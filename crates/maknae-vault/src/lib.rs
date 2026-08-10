//! maknae-vault — shared, NON-PRIVILEGED Vault plane-cert client (ADR-0005).
//! Stage 1: config -> AppRole auth (response-wrapped SecretID) -> P-384 CSR ->
//! pki/sign -> memory-only leaf, plus the CA-pin loader + URI-SAN verifier.
//! FIPS: the runtime `.fips()` assertion (assert_fips_provider, in fips_glue) is
//! authoritative; the load-bearing install-before-first-Vault-client ordering keeps
//! vaultrs's reqwest on the FIPS provider (spec §6.1).
#![forbid(unsafe_code)]

mod ca;
mod config;
mod csr;
mod error;
mod fips;
mod fips_glue;
mod plane;
mod verify;

pub use ca::{load_ca_pin, CaBundle};
pub use config::{load_vault_config, validate_deployment_id, VaultConfig};
pub use csr::generate_plane_csr;
pub use error::VaultError;
pub use fips_glue::assert_fips_provider;
pub use plane::Plane;
pub use verify::{verify_plane_uri_san, VerifyError};

// Later tasks add: mod auth; mod client;

#[used]
pub static CRATE_MARKER: &[u8] = b"MAKNAE_VAULT";
