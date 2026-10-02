//! Read a resolved [`DaemonSecretSource`] into the actual
//! SecretID bytes (T3, I/O). Each function takes exactly ONE already-resolved source
//! and returns exactly one `Result` — there is no retry-another-source path here BY
//! CONSTRUCTION: the no-fallthrough control (spec §5.1) is that
//! `resolve_*_secret_source` (secret_source.rs, T1) picks ONE winner, and this module
//! never sees the sources it didn't pick, so it cannot silently fall back to a
//! weaker one.
//!
//! **Permission-gating split (LOAD BEARING):** the PLAINTEXT branch
//! (`DaemonSecretSource::PlaintextPath`) routes
//! through `client::read_secret_credential`'s `mode & 0o077` gate — a plaintext file
//! must be owner-only. The non-plaintext branches (`CredentialsDirectory`, `Keychain`)
//! do NOT go through that gate: systemd `LoadCredential`/
//! `SetCredentialEncrypted` produce their own `0400`-or-stricter, already-trusted
//! artifacts, and the keychain arm reads no file as the secret, so re-applying the
//! plaintext gate to them would be redundant at best and a spurious refusal at
//! worst (systemd may root-own the credentials directory in a way this process's
//! uid doesn't "own" by our check).
use crate::client::read_secret_credential;
use crate::keychain::read_plane_secret;
use crate::secret_source::DaemonSecretSource;
use crate::{KeychainPlane, VaultError};
use std::path::Path;
use zeroize::Zeroizing;

/// Read a sealed artifact verbatim (trimmed) with NO owner/mode gate — the sealing
/// mechanism (systemd credentials dir) is the trust boundary for the file's CONTENT,
/// so no permission bits are required. Inode IDENTITY is still enforced (ADR-0021):
/// the read goes through `maknae-io`, which refuses a symlinked final component and
/// requires a regular file — systemd materializes credentials as regular files, and
/// symlink-farm layouts (e.g. Kubernetes projected volumes) are out of scope, #134.
fn read_sealed_trimmed(path: &Path) -> Result<Zeroizing<String>, VaultError> {
    let bytes = crate::read_storage(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|e| VaultError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(e.to_string()),
    })?;
    Ok(Zeroizing::new(text.trim().to_string()))
}

/// Read the daemon's SecretID from an already-resolved source. Exactly one source in,
/// exactly one `Result` out — no fallthrough to a different source on failure.
pub(crate) fn read_daemon_secret(
    src: &DaemonSecretSource,
) -> Result<Zeroizing<String>, VaultError> {
    match src {
        DaemonSecretSource::CredentialsDirectory(path) => read_sealed_trimmed(path),
        DaemonSecretSource::Keychain(pointer) => read_plane_secret(pointer, KeychainPlane::Daemon),
        DaemonSecretSource::PlaintextPath(path) => read_secret_credential(path).map(Zeroizing::new),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmpfile(name: &str, body: &str, mode: u32) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("mv-secretio-{}-{}", std::process::id(), name));
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    // ---- sealed branches: no permission gate -----------------------------------

    #[test]
    fn credentials_directory_reads_regardless_of_mode() {
        // A world-readable file would be REFUSED by the plaintext gate; the sealed
        // branch must NOT apply that gate (systemd owns the trust boundary here).
        let p = tmpfile("cd-open", "sealed-value", 0o644);
        let src = DaemonSecretSource::CredentialsDirectory(p.clone());
        assert_eq!(read_daemon_secret(&src).unwrap().as_str(), "sealed-value");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn credentials_directory_missing_file_fails_closed() {
        let src = DaemonSecretSource::CredentialsDirectory(std::path::PathBuf::from(
            "/nonexistent/maknaed-secret-id",
        ));
        assert!(matches!(
            read_daemon_secret(&src),
            Err(VaultError::Io { .. })
        ));
    }

    // ---- no-fallthrough control (spec §5.1 core property) ----------------------

    #[test]
    fn plaintext_path_nonexistent_fails_closed_no_retry() {
        // The core §5.1 control: a failing PlaintextPath read returns Err directly —
        // there is no OTHER source for it to silently retry (the function signature
        // takes exactly one already-resolved source).
        let src = DaemonSecretSource::PlaintextPath(std::path::PathBuf::from(
            "/nonexistent/insecure-secret-id",
        ));
        assert!(matches!(
            read_daemon_secret(&src),
            Err(VaultError::Io { .. })
        ));
    }

    #[test]
    fn a_keychain_source_never_returns_the_pointer_file_as_the_secret() {
        let p = tmpfile("kc-pointer-plaintext", "not-a-secret-id", 0o600);
        let got = read_daemon_secret(&DaemonSecretSource::Keychain(p.clone()));
        let _ = std::fs::remove_file(&p);
        assert!(
            got.is_err(),
            "a keychain source must not read its pointer as the secret"
        );
    }

    // ---- plaintext branches: gate enforced --------------------------------------

    #[test]
    fn daemon_plaintext_branch_rejects_group_other_access() {
        let p = tmpfile("plain-open", "secret-value", 0o644);
        let src = DaemonSecretSource::PlaintextPath(p.clone());
        assert!(matches!(
            read_daemon_secret(&src),
            Err(VaultError::InsecureCredential { .. })
        ));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn daemon_plaintext_branch_accepts_owner_only() {
        let p = tmpfile("plain-secure", "secret-value", 0o600);
        let src = DaemonSecretSource::PlaintextPath(p.clone());
        assert_eq!(read_daemon_secret(&src).unwrap().as_str(), "secret-value");
        let _ = std::fs::remove_file(&p);
    }
}
