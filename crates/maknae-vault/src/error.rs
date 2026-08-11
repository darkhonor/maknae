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
    /// A single background `renew_self` attempt failed (transient or terminal — the
    /// credential supervisor's `retry_action` decides which; this variant only
    /// carries the underlying detail for logging).
    Renew(String),
    /// The UDS parent directory has unsafe ownership/permissions — refused before bind.
    InsecureSocketDir { path: PathBuf, detail: String },
    /// Binding/listening on the UDS failed (incl. a live socket already present).
    SocketBind(String),
    /// Setting the bound UDS's group ownership failed (codex round-7 P1) — the 0660
    /// group-gate is meaningless if the socket ends up group-owned by whatever the
    /// daemon process's PRIMARY group happens to be rather than the resolved `maknae`
    /// group, so this fails the bind closed rather than serving un-group-owned.
    SocketGroupOwn(String),
    /// Peer-credential capture failed — a local connection whose kernel creds cannot be
    /// read cannot be policed by the daemon, so it is refused (fail closed).
    PeerCred(String),
    /// The TLS handshake failed (chain invalid/expired, foreign CA, absent client cert).
    Handshake(String),
    /// The peer leaf's plane URI-SAN was wrong/absent/extra (wraps the T1 verifier error).
    PeerIdentity(crate::VerifyError),
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
            VaultError::Renew(msg) => write!(f, "renew_self failed: {msg}"),
            VaultError::InsecureSocketDir { path, detail } => {
                write!(f, "refusing UDS dir {}: {detail}", path.display())
            }
            VaultError::SocketBind(msg) => write!(f, "UDS bind failed: {msg}"),
            VaultError::SocketGroupOwn(msg) => write!(f, "UDS group-chown failed: {msg}"),
            VaultError::PeerCred(msg) => write!(f, "peer-credential capture failed: {msg}"),
            VaultError::Handshake(msg) => write!(f, "TLS handshake failed: {msg}"),
            VaultError::PeerIdentity(e) => write!(f, "peer plane identity rejected: {e:?}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<maknae_config::ConfigError> for VaultError {
    fn from(e: maknae_config::ConfigError) -> Self {
        VaultError::Config(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transport_variants_display() {
        let cases: Vec<VaultError> = vec![
            VaultError::InsecureSocketDir {
                path: PathBuf::from("/run/maknae"),
                detail: "mode 0777".into(),
            },
            VaultError::SocketBind("addr in use".into()),
            VaultError::SocketGroupOwn("chown group 1000: EPERM".into()),
            VaultError::PeerCred("getsockopt failed".into()),
            VaultError::Handshake("bad cert".into()),
            VaultError::PeerIdentity(crate::VerifyError::NoUriSan),
        ];
        for e in cases {
            assert!(!format!("{e}").is_empty());
        }
    }
}
