//! `maknae-vault` error type — hand-rolled, fail-closed, consistent with
//! `maknae-config`'s `ConfigError` pattern (no extra dep). Every fallible path in
//! the crate returns one of these; there is no partial-identity / non-FIPS / file
//! fallback anywhere.
use std::path::PathBuf;

#[derive(Debug)]
pub enum VaultError {
    /// The process is not running the aws-lc-rs FIPS provider (or none installed).
    FipsUnavailable,
    /// A config-load failure from `maknae-config`.
    Config(maknae_config::ConfigError),
    /// A required config key was absent.
    MissingKey(&'static str),
    /// `deployment_id` failed the charset guard (empty / glob / slash / space).
    InvalidDeploymentId(String),
    /// `vault.addr` is not a valid `https://` URL (a non-TLS addr would disclose
    /// credentials; the CA cert cannot protect a plaintext connection).
    InvalidAddr(String),
    /// A file could not be read.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A sensitive credential file has unsafe permissions (group/other access) or is a
    /// symlink — refused before reading (fail-closed).
    InsecureCredential { path: PathBuf, detail: String },
    /// The Unix permission model is unavailable on this target, so a sensitive credential
    /// file's owner-only permissions cannot be verified — refuse rather than read it
    /// unchecked (fail-closed; mirrors `maknae-config`'s non-Unix refusal).
    PermissionsUnsupported,
    /// A PEM artifact (CA cert) was malformed.
    Pem(&'static str),
    /// A response-wrapped SecretID could not be unwrapped (already used / expired).
    WrapUnwrap(String),
    /// AppRole login failed.
    Auth(String),
    /// Local keypair / CSR generation failed.
    CsrGen(String),
    /// `pki/sign` was rejected (e.g. a SAN mismatch surfaced by Vault).
    Sign(String),
    /// The renewable token hit `token_max_ttl` — the caller must re-authenticate.
    RenewalExpired,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::FipsUnavailable => write!(
                f,
                "FIPS provider not active: the process default is not aws-lc-rs FIPS (refusing to start)"
            ),
            VaultError::Config(e) => write!(f, "config error: {e}"),
            VaultError::MissingKey(k) => write!(f, "required config key absent: {k}"),
            VaultError::InvalidDeploymentId(id) => write!(
                f,
                "deployment_id {id:?} is invalid: must be non-empty and match ^[A-Za-z0-9._-]+$ \
                 (a glob/slash would corrupt the plane URI-SAN)"
            ),
            VaultError::InvalidAddr(msg) => write!(f, "invalid vault.addr: {msg}"),
            VaultError::Io { path, source } => write!(f, "reading {}: {source}", path.display()),
            VaultError::InsecureCredential { path, detail } => {
                write!(f, "refusing credential file {}: {detail}", path.display())
            }
            VaultError::PermissionsUnsupported => write!(
                f,
                "cannot verify credential-file permissions on this (non-Unix) target — refusing to read (fail closed)"
            ),
            VaultError::Pem(what) => write!(f, "malformed PEM: {what}"),
            VaultError::WrapUnwrap(msg) => write!(
                f,
                "response-wrapped SecretID unwrap failed (already used / expired?): {msg}"
            ),
            VaultError::Auth(msg) => write!(f, "AppRole login failed: {msg}"),
            VaultError::CsrGen(msg) => write!(f, "keypair/CSR generation failed: {msg}"),
            VaultError::Sign(msg) => write!(f, "pki/sign rejected: {msg}"),
            VaultError::RenewalExpired => write!(
                f,
                "token reached max_ttl — re-authentication with a fresh SecretID required"
            ),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<maknae_config::ConfigError> for VaultError {
    fn from(e: maknae_config::ConfigError) -> Self {
        VaultError::Config(e)
    }
}
