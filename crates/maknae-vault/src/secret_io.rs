//! Read a resolved [`DaemonSecretSource`]/[`CliSecretSource`] into the actual
//! SecretID bytes (T3, I/O). Each function takes exactly ONE already-resolved source
//! and returns exactly one `Result` — there is no retry-another-source path here BY
//! CONSTRUCTION: the no-fallthrough control (spec §5.1) is that
//! `resolve_*_secret_source` (secret_source.rs, T1) picks ONE winner, and this module
//! never sees the sources it didn't pick, so it cannot silently fall back to a
//! weaker one.
//!
//! **Permission-gating split (LOAD BEARING):** the PLAINTEXT branches
//! (`DaemonSecretSource::PlaintextPath`, `CliSecretSource::ResidualFile`) route
//! through `client::read_secret_credential`'s `mode & 0o077` gate — a plaintext file
//! must be owner-only. The SEALED branches (`CredentialsDirectory`, `SepSealed`,
//! `UserCreds`) do NOT go through that gate: systemd `LoadCredential`/
//! `SetCredentialEncrypted` and SEP both produce their own `0400`-or-stricter,
//! already-trusted artifacts, and re-applying the plaintext gate to them would be
//! redundant at best and a spurious refusal at worst (systemd may root-own the
//! credentials directory in a way this process's uid doesn't "own" by our check).
use crate::client::read_secret_credential;
use crate::secret_source::{CliSecretSource, DaemonSecretSource};
use crate::VaultError;
use std::path::Path;
use zeroize::Zeroizing;

/// Read a sealed artifact verbatim (trimmed) with NO permission gate — the sealing
/// mechanism (systemd credentials dir) is the trust boundary, not this process's
/// view of the file mode.
fn read_sealed_trimmed(path: &Path) -> Result<Zeroizing<String>, VaultError> {
    let bytes = crate::read_storage(
        path,
        maknae_io::TargetRequired {
            owner: None,
            mode_mask: None,
            nlink_exactly_one: false,
            regular_file: true,
        },
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|e| VaultError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(e.to_string()),
    })?;
    Ok(Zeroizing::new(text.trim().to_string()))
}

/// SEP-sealed SecretID unwrap. Real Secure-Enclave-backed unsealing requires FFI
/// into Apple's Security framework, which is out of reach for this task (and this
/// exact worktree is iterated on a macOS dev host, so an `unimplemented!()` here
/// would PANIC `cargo test` locally rather than fail an assertion — worse than a
/// clean `Err`). Stubbed to fail closed rather than silently treating the sealed
/// blob as plaintext (that would be exactly the fallthrough-to-plaintext hole this
/// task exists to prevent). TODO(PR-J2 spec §6.2): real SEP unseal.
fn read_sep_sealed(_path: &Path) -> Result<Zeroizing<String>, VaultError> {
    Err(VaultError::CredentialSource(
        "SEP-sealed SecretID unwrap is not yet implemented (PR-J2 spec §6.2)".to_string(),
    ))
}

/// macOS Keychain SecretID lookup. Same rationale as `read_sep_sealed`: real
/// Keychain access needs Security-framework FFI, stubbed to fail closed rather than
/// faked. TODO(PR-J2 spec §6.3): real Keychain read.
fn read_keychain_secret() -> Result<Zeroizing<String>, VaultError> {
    Err(VaultError::CredentialSource(
        "macOS Keychain SecretID lookup is not yet implemented (PR-J2 spec §6.3)".to_string(),
    ))
}

/// `systemd-creds decrypt --user <path> -` — decrypts a user-scoped credential file
/// to stdout, captured straight into `Zeroizing` (never touches an intermediate
/// on-disk plaintext copy). A real Linux implementation (not stubbed): the CLI's
/// user-creds branch is expected to work today wherever `systemd-creds --user` is
/// available.
fn read_systemd_creds_user(path: &Path) -> Result<Zeroizing<String>, VaultError> {
    let output = std::process::Command::new("systemd-creds")
        .arg("decrypt")
        .arg("--user")
        // Pin the credential name to match the enroll-time seal
        // (`systemd-creds encrypt --name=maknae-secret-id` in enroll/helper.rs).
        // Without this, systemd-creds derives the expected name from the input
        // FILENAME — `maknae-secret-id.cred`, WITH the extension — which does not
        // match the embedded `maknae-secret-id` and fails "Name in credential
        // doesn't match expectations." Runtime seam bug found on live hardware.
        .arg("--name=maknae-secret-id")
        .arg(path)
        .arg("-")
        .output()
        .map_err(|source| VaultError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(VaultError::CredentialSource(format!(
            "systemd-creds decrypt --user {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    // Wrap the decrypted bytes in `Zeroizing` THE MOMENT we own them — `output.stdout`
    // is otherwise a bare `Vec<u8>` holding the plaintext SecretID in an un-zeroized
    // heap allocation. `str::from_utf8` below borrows from `raw` rather than producing
    // a second owned (bare) copy, so there is no un-zeroized intermediate at any point.
    let raw = Zeroizing::new(output.stdout);
    let text = std::str::from_utf8(&raw).map_err(|_| {
        VaultError::CredentialSource(format!(
            "systemd-creds decrypt --user {} produced non-UTF-8 output",
            path.display()
        ))
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
        DaemonSecretSource::SepSealed(path) => read_sep_sealed(path),
        DaemonSecretSource::PlaintextPath(path) => read_secret_credential(path).map(Zeroizing::new),
    }
}

/// Read the CLI's SecretID from an already-resolved source. Same single-source
/// contract as [`read_daemon_secret`].
pub(crate) fn read_cli_secret(src: &CliSecretSource) -> Result<Zeroizing<String>, VaultError> {
    match src {
        CliSecretSource::UserCreds(path) => read_systemd_creds_user(path),
        CliSecretSource::Keychain => read_keychain_secret(),
        CliSecretSource::ResidualFile(path) => read_secret_credential(path).map(Zeroizing::new),
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
    fn sep_sealed_read_fails_closed_does_not_fall_through_to_plaintext() {
        // Prove the single-source contract for the OTHER sealed branch too: even a
        // path that points at a REAL, READABLE plaintext file must NOT get read as
        // plaintext just because the SEP unseal itself isn't implemented yet — that
        // would be exactly the fallthrough-to-plaintext hole. It must fail closed.
        let p = tmpfile("sep-real-plaintext", "not-actually-sealed", 0o600);
        let src = DaemonSecretSource::SepSealed(p.clone());
        let result = read_daemon_secret(&src);
        assert!(result.is_err(), "SEP-sealed read must fail closed, not silently return the underlying file's plaintext bytes");
        if let Err(VaultError::CredentialSource(msg)) = &result {
            assert!(!msg.is_empty());
        } else {
            panic!("expected CredentialSource error, got {result:?}");
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn keychain_read_fails_closed() {
        assert!(matches!(
            read_cli_secret(&CliSecretSource::Keychain),
            Err(VaultError::CredentialSource(_))
        ));
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

    #[test]
    fn cli_residual_branch_rejects_group_other_access() {
        let p = tmpfile("cli-plain-open", "cli-secret", 0o644);
        let src = CliSecretSource::ResidualFile(p.clone());
        assert!(matches!(
            read_cli_secret(&src),
            Err(VaultError::InsecureCredential { .. })
        ));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn cli_residual_branch_accepts_owner_only() {
        let p = tmpfile("cli-plain-secure", "cli-secret", 0o600);
        let src = CliSecretSource::ResidualFile(p.clone());
        assert_eq!(read_cli_secret(&src).unwrap().as_str(), "cli-secret");
        let _ = std::fs::remove_file(&p);
    }

    // ---- CLI user-creds branch: real systemd-creds invocation -------------------

    #[test]
    fn cli_user_creds_missing_binary_or_file_fails_closed() {
        // No live systemd-creds assumed on the test host; either the binary is
        // absent (Io error) or it runs and rejects a nonexistent/garbage input
        // (CredentialSource error) — either way this must be Err, never a
        // fabricated Ok.
        let src = CliSecretSource::UserCreds(std::path::PathBuf::from(
            "/nonexistent/maknae-secret-id.cred",
        ));
        assert!(read_cli_secret(&src).is_err());
    }
}
