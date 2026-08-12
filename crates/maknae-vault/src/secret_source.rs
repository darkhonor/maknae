//! Per-plane SecretID credential-SOURCE resolution (spec §5.1) — PURE decision logic,
//! no I/O. The daemon (`Plane::Kernel`) and the CLI (`Plane::Cli`) each have their own
//! ordered list of places a SecretID may come from; this module decides WHICH source
//! wins, `secret_io.rs` then reads it. Keeping resolution pure (no filesystem/env
//! reads inside these functions — the caller supplies already-observed inputs) is what
//! makes the fail-closed precedence provably testable and mutation-hardened (T1).
use crate::VaultError;
use std::path::{Path, PathBuf};

/// The credential name `$CREDENTIALS_DIRECTORY` always carries for the daemon
/// (systemd `LoadCredential=maknaed-secret-id:...` / `SetCredentialEncrypted`).
const CREDENTIALS_DIRECTORY_CRED_NAME: &str = "maknaed-secret-id";

/// The CLI's user-scoped `systemd-creds` credential file name.
const CLI_USER_CREDS_FILE: &str = "maknae-secret-id.cred";

/// The CLI's residual plaintext file name (RHEL-9 fallback / no user-creds target).
const CLI_RESIDUAL_FILE: &str = "maknae-secret-id";

/// Where the daemon's (`maknaed`) standing SecretID comes from — resolved by
/// [`resolve_daemon_secret_source`], read by `secret_io::read_daemon_secret`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonSecretSource {
    /// systemd `$CREDENTIALS_DIRECTORY/maknaed-secret-id` — the HRoT-sealed boot path
    /// (`LoadCredential`/`SetCredentialEncrypted`), preferred whenever present.
    CredentialsDirectory(PathBuf),
    /// A macOS Secure-Enclave-sealed blob (opt-in, no systemd on darwin).
    SepSealed(PathBuf),
    /// An operator-opted-in plaintext file (`vault.insecure_plaintext_secret_path`) —
    /// the weakest posture, last resort, never a silent default.
    PlaintextPath(PathBuf),
}

/// Where the CLI's (`maknae`) SecretID comes from — resolved by
/// [`resolve_cli_secret_source`], read by `secret_io::read_cli_secret`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliSecretSource {
    /// A user-scoped `systemd-creds`-encrypted file (`<cli_dir>/maknae-secret-id.cred`).
    UserCreds(PathBuf),
    /// The macOS Keychain (no path — looked up by service/account name at read time).
    Keychain,
    /// A residual plaintext file (`<cli_dir>/maknae-secret-id`) — RHEL-9 / no
    /// user-creds-capable target and no Keychain. The universal fallback: this arm
    /// never fails to resolve (whether the file actually exists is a read-time
    /// concern, not a resolution-time one).
    ResidualFile(PathBuf),
}

/// A small `Copy` classifier mirroring the three DAEMON source kinds — the posture
/// record `PlaneClient::secret_source()` exposes for Task 7's audit. Both
/// [`DaemonSecretSource`] and [`CliSecretSource`] map onto it (the CLI's three
/// branches are the same POSTURE shape: OS-credential-store-sealed, hardware/OS
/// enclave-sealed, or plaintext-on-disk) so the audit can reason about "is this
/// plane's SecretID sealed or plaintext" uniformly across planes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSourceKind {
    CredentialsDirectory,
    SepSealed,
    PlaintextPath,
}

impl From<&DaemonSecretSource> for CredentialSourceKind {
    fn from(src: &DaemonSecretSource) -> Self {
        match src {
            DaemonSecretSource::CredentialsDirectory(_) => {
                CredentialSourceKind::CredentialsDirectory
            }
            DaemonSecretSource::SepSealed(_) => CredentialSourceKind::SepSealed,
            DaemonSecretSource::PlaintextPath(_) => CredentialSourceKind::PlaintextPath,
        }
    }
}

impl From<&CliSecretSource> for CredentialSourceKind {
    fn from(src: &CliSecretSource) -> Self {
        match src {
            // systemd-creds --user is an OS-managed credential store, same posture
            // family as the daemon's $CREDENTIALS_DIRECTORY.
            CliSecretSource::UserCreds(_) => CredentialSourceKind::CredentialsDirectory,
            // Keychain is OS/hardware-backed secure storage, same posture family as SEP.
            CliSecretSource::Keychain => CredentialSourceKind::SepSealed,
            CliSecretSource::ResidualFile(_) => CredentialSourceKind::PlaintextPath,
        }
    }
}

/// Resolve the DAEMON's SecretID source (spec §5.1). Resolution order — first match
/// wins, no fallthrough once a source is chosen:
///
/// 1. `$CREDENTIALS_DIRECTORY/maknaed-secret-id` (if `credentials_dir_env` is `Some`
///    — the systemd HRoT-sealed boot path; ALWAYS preferred when present, regardless
///    of what else is configured).
/// 2. The SEP-sealed blob (if `sep_blob` is `Some`).
/// 3. The configured plaintext path (if `insecure_plaintext_secret_path` is `Some`).
/// 4. Else `Err` — fail closed. There is no silent plaintext default.
pub fn resolve_daemon_secret_source(
    credentials_dir_env: Option<&str>,
    sep_blob: Option<&Path>,
    insecure_plaintext_secret_path: Option<&Path>,
) -> Result<DaemonSecretSource, VaultError> {
    if let Some(dir) = credentials_dir_env {
        return Ok(DaemonSecretSource::CredentialsDirectory(
            Path::new(dir).join(CREDENTIALS_DIRECTORY_CRED_NAME),
        ));
    }
    if let Some(blob) = sep_blob {
        return Ok(DaemonSecretSource::SepSealed(blob.to_path_buf()));
    }
    if let Some(path) = insecure_plaintext_secret_path {
        return Ok(DaemonSecretSource::PlaintextPath(path.to_path_buf()));
    }
    Err(VaultError::CredentialSource(
        "no daemon SecretID source configured (spec §5.1): set $CREDENTIALS_DIRECTORY, \
         provide a SEP-sealed blob, or configure vault.insecure_plaintext_secret_path"
            .to_string(),
    ))
}

/// Resolve the CLI's SecretID source. Resolution order — first match wins:
///
/// 1. `<cli_dir>/maknae-secret-id.cred` (if `target_has_user_creds` — a user-scoped
///    `systemd-creds`-encrypted file is available on this target).
/// 2. The macOS Keychain (if `macos`).
/// 3. `<cli_dir>/maknae-secret-id` — the residual plaintext fallback (RHEL-9 /
///    no user-creds target and no Keychain). This arm is infallible: it always
///    resolves to a path, whether or not that file exists (existence is a
///    read-time concern).
pub fn resolve_cli_secret_source(
    cli_dir: &Path,
    target_has_user_creds: bool,
    macos: bool,
) -> Result<CliSecretSource, VaultError> {
    if target_has_user_creds {
        return Ok(CliSecretSource::UserCreds(
            cli_dir.join(CLI_USER_CREDS_FILE),
        ));
    }
    if macos {
        return Ok(CliSecretSource::Keychain);
    }
    Ok(CliSecretSource::ResidualFile(
        cli_dir.join(CLI_RESIDUAL_FILE),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- daemon resolution ---------------------------------------------------

    #[test]
    fn daemon_prefers_credentials_directory() {
        let s = resolve_daemon_secret_source(
            Some("/run/credentials/maknaed.service"),
            None,
            Some(Path::new("/x")),
        )
        .unwrap();
        assert!(matches!(
            s,
            DaemonSecretSource::CredentialsDirectory(p) if p.ends_with("maknaed-secret-id")
        ));
    }

    #[test]
    fn daemon_no_source_fails_closed() {
        assert!(resolve_daemon_secret_source(None, None, None).is_err());
    }

    /// Precedence, not fallthrough: when BOTH CredentialsDirectory and SEP are
    /// available, CredentialsDirectory wins — SEP is never consulted (renamed from
    /// `daemon_sealed_never_falls_through`, round-1 SF7: that name implied a
    /// fallthrough-on-failure guarantee this test doesn't make; it only proves
    /// ordering among available sources. The real no-fallthrough control lives in
    /// `secret_io.rs`'s `read_daemon_secret` tests.)
    #[test]
    fn daemon_precedence_credentials_over_sep() {
        let s = resolve_daemon_secret_source(
            Some("/run/credentials/maknaed.service"),
            Some(Path::new("/sep/blob")),
            None,
        )
        .unwrap();
        assert!(matches!(s, DaemonSecretSource::CredentialsDirectory(_)));
    }

    #[test]
    fn daemon_sep_used_when_no_credentials_directory() {
        let s = resolve_daemon_secret_source(None, Some(Path::new("/sep/blob")), None).unwrap();
        assert_eq!(s, DaemonSecretSource::SepSealed(PathBuf::from("/sep/blob")));
    }

    #[test]
    fn daemon_plaintext_only_when_configured() {
        let s =
            resolve_daemon_secret_source(None, None, Some(Path::new("/etc/maknaed/x"))).unwrap();
        assert_eq!(
            s,
            DaemonSecretSource::PlaintextPath(PathBuf::from("/etc/maknaed/x"))
        );
    }

    /// Mutation probe: swapping the SEP/plaintext order arms would make this pass
    /// with the WRONG variant. Explicitly assert the variant, not just "is Ok".
    #[test]
    fn daemon_order_is_credentials_then_sep_then_plaintext() {
        assert!(matches!(
            resolve_daemon_secret_source(
                Some("/run/creds"),
                Some(Path::new("/sep")),
                Some(Path::new("/plain"))
            )
            .unwrap(),
            DaemonSecretSource::CredentialsDirectory(_)
        ));
        assert!(matches!(
            resolve_daemon_secret_source(None, Some(Path::new("/sep")), Some(Path::new("/plain")))
                .unwrap(),
            DaemonSecretSource::SepSealed(_)
        ));
        assert!(matches!(
            resolve_daemon_secret_source(None, None, Some(Path::new("/plain"))).unwrap(),
            DaemonSecretSource::PlaintextPath(_)
        ));
    }

    // ---- CLI resolution -------------------------------------------------------

    #[test]
    fn cli_prefers_user_creds() {
        let s = resolve_cli_secret_source(Path::new("/home/u/.maknae"), true, true).unwrap();
        assert!(matches!(s, CliSecretSource::UserCreds(p) if p.ends_with("maknae-secret-id.cred")));
    }

    #[test]
    fn cli_falls_back_to_keychain_on_macos() {
        let s = resolve_cli_secret_source(Path::new("/home/u/.maknae"), false, true).unwrap();
        assert_eq!(s, CliSecretSource::Keychain);
    }

    #[test]
    fn cli_falls_back_to_residual_file() {
        let s = resolve_cli_secret_source(Path::new("/home/u/.maknae"), false, false).unwrap();
        assert!(matches!(s, CliSecretSource::ResidualFile(p) if p.ends_with("maknae-secret-id")));
    }

    /// Mutation probe: swapping the user-creds/keychain order arms would make this
    /// resolve to Keychain instead of UserCreds when BOTH are available.
    #[test]
    fn cli_order_is_usercreds_then_keychain_then_residual() {
        assert!(matches!(
            resolve_cli_secret_source(Path::new("/d"), true, true).unwrap(),
            CliSecretSource::UserCreds(_)
        ));
        assert!(matches!(
            resolve_cli_secret_source(Path::new("/d"), false, true).unwrap(),
            CliSecretSource::Keychain
        ));
        assert!(matches!(
            resolve_cli_secret_source(Path::new("/d"), false, false).unwrap(),
            CliSecretSource::ResidualFile(_)
        ));
    }

    // ---- CredentialSourceKind mapping -----------------------------------------

    #[test]
    fn daemon_source_kind_mapping() {
        assert_eq!(
            CredentialSourceKind::from(&DaemonSecretSource::CredentialsDirectory(PathBuf::from(
                "/x"
            ))),
            CredentialSourceKind::CredentialsDirectory
        );
        assert_eq!(
            CredentialSourceKind::from(&DaemonSecretSource::SepSealed(PathBuf::from("/x"))),
            CredentialSourceKind::SepSealed
        );
        assert_eq!(
            CredentialSourceKind::from(&DaemonSecretSource::PlaintextPath(PathBuf::from("/x"))),
            CredentialSourceKind::PlaintextPath
        );
    }

    #[test]
    fn cli_source_kind_mapping() {
        assert_eq!(
            CredentialSourceKind::from(&CliSecretSource::UserCreds(PathBuf::from("/x"))),
            CredentialSourceKind::CredentialsDirectory
        );
        assert_eq!(
            CredentialSourceKind::from(&CliSecretSource::Keychain),
            CredentialSourceKind::SepSealed
        );
        assert_eq!(
            CredentialSourceKind::from(&CliSecretSource::ResidualFile(PathBuf::from("/x"))),
            CredentialSourceKind::PlaintextPath
        );
    }
}
