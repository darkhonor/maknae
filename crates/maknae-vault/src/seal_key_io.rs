use crate::keychain::{observe_pointer, read_plane_secret};
use crate::secret_source::{
    resolve_egress_seal_key_source, seal_key_der, seal_key_from_hex, EgressSealKeySource,
};
use crate::{KeychainPlane, VaultError, MAX_SEAL_KEY_BYTES};
use maknae_io::{MaknaeSecret, MaknaeSecretBytes};
use std::path::Path;

pub fn read_egress_seal_key(
    credentials_dir: Option<&str>,
    egress_dir: &Path,
) -> Result<MaknaeSecretBytes, VaultError> {
    let pointer = match credentials_dir {
        None => observe_pointer(egress_dir, KeychainPlane::Egress)?,
        Some(_) => None,
    };
    match resolve_egress_seal_key_source(credentials_dir, pointer.as_deref())? {
        EgressSealKeySource::CredentialsDirectory(path) => {
            let der = crate::read_storage_within(&path, Some(MAX_SEAL_KEY_BYTES as u64))?;
            seal_key_der(der)
        }
        EgressSealKeySource::Keychain(pointer) => {
            seal_key_from_hex(&read_plane_secret(&pointer, KeychainPlane::Egress)?)
        }
    }
}

#[cfg(target_os = "linux")]
pub fn read_egress_secret_id(credentials_dir: Option<&Path>) -> Result<MaknaeSecret, VaultError> {
    let path = crate::secret_source::resolve_egress_secret_id_source(credentials_dir)?;
    let bytes = crate::read_storage_within(&path, Some(crate::MAX_TOKEN_BYTES as u64))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| VaultError::InvalidSecret {
        what: "egress SecretID",
        why: "not UTF-8",
    })?;
    let text = text.trim();
    crate::transit::approle_credential("egress SecretID", text)?;
    MaknaeSecret::new(crate::secret_source::exact_text(text))
        .map_err(|e| crate::error::secret_error("egress SecretID", e))
}

#[cfg(not(target_os = "linux"))]
pub fn read_egress_secret_id(_credentials_dir: Option<&Path>) -> Result<MaknaeSecret, VaultError> {
    Err(VaultError::CredentialSource(format!(
        "the egress SecretID has no custody on {}: it is read only from $CREDENTIALS_DIRECTORY on Linux",
        std::env::consts::OS
    )))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn der() -> maknae_io::MaknaeSecretBytes {
        maknae_seal::SealPrivateKey::generate()
            .unwrap()
            .to_pkcs8_der()
            .unwrap()
    }

    fn creds_with(bytes: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(crate::EGRESS_SEAL_KEY_CRED_NAME), bytes).unwrap();
        dir
    }

    const NO_EGRESS_DIR: &str = "/nonexistent/maknae-egress";

    fn creds_named(name: &str, bytes: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(name), bytes).unwrap();
        dir
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_secret_id_is_read_from_credentials_directory_only_under_its_name() {
        assert_eq!(crate::EGRESS_SECRET_ID_CRED_NAME, "maknae-egress-secret-id");
        let creds = creds_named(
            crate::EGRESS_SECRET_ID_CRED_NAME,
            b"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\n",
        );
        let got = read_egress_secret_id(Some(creds.path())).unwrap();
        assert!(got.expose() == "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0");
        for other in [
            crate::DAEMON_CREDENTIALS_DIRECTORY_CRED_NAME,
            crate::EGRESS_SEAL_KEY_CRED_NAME,
            "maknae-agent-secret-id",
            "secret-id",
        ] {
            let elsewhere = creds_named(other, b"0f1e2d3c");
            assert!(
                matches!(
                    read_egress_secret_id(Some(elsewhere.path())),
                    Err(VaultError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound
                ),
                "{other}"
            );
        }
        assert!(matches!(
            read_egress_secret_id(None),
            Err(VaultError::CredentialSource(m)) if m.contains("$CREDENTIALS_DIRECTORY is unset")
        ));
        assert!(matches!(
            read_egress_secret_id(Some(Path::new(""))),
            Err(VaultError::CredentialSource(m)) if m.contains("exported but empty")
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn off_linux_the_secret_id_is_refused_by_platform() {
        let creds = creds_named(crate::EGRESS_SECRET_ID_CRED_NAME, b"0f1e2d3c");
        assert!(matches!(
            read_egress_secret_id(Some(creds.path())),
            Err(VaultError::CredentialSource(m)) if m.contains(std::env::consts::OS)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_secret_id_that_is_empty_oversized_or_misshapen_is_refused() {
        for bad in [&b""[..], b"\n", b"a b", b"a\"b", b"\xff\xfe"] {
            let creds = creds_named(crate::EGRESS_SECRET_ID_CRED_NAME, bad);
            assert!(
                read_egress_secret_id(Some(creds.path())).is_err(),
                "{bad:?}"
            );
        }
        let creds = creds_named(
            crate::EGRESS_SECRET_ID_CRED_NAME,
            &vec![b'a'; crate::MAX_TOKEN_BYTES + 1],
        );
        assert!(matches!(
            read_egress_secret_id(Some(creds.path())),
            Err(VaultError::Io { source, .. }) if source.kind() == std::io::ErrorKind::FileTooLarge
        ));
        let creds = creds_named(
            crate::EGRESS_SECRET_ID_CRED_NAME,
            &vec![b'a'; crate::MAX_TOKEN_BYTES],
        );
        assert_eq!(
            read_egress_secret_id(Some(creds.path()))
                .unwrap()
                .expose()
                .len(),
            crate::MAX_TOKEN_BYTES
        );
        let creds = creds_named(crate::EGRESS_SECRET_ID_CRED_NAME, b"SENTINEL x");
        let e = read_egress_secret_id(Some(creds.path()))
            .unwrap_err()
            .to_string();
        assert!(!e.contains("SENTINEL"), "{e}");
    }

    #[test]
    fn a_credential_holding_a_seal_key_is_read_whole() {
        let key = der();
        let creds = creds_with(key.expose());
        let got = read_egress_seal_key(creds.path().to_str(), Path::new(NO_EGRESS_DIR)).unwrap();
        assert!(got.expose() == key.expose());
        let reloaded = maknae_seal::SealPrivateKey::from_pkcs8_der(got.expose()).unwrap();
        let original = maknae_seal::SealPrivateKey::from_pkcs8_der(key.expose()).unwrap();
        assert_eq!(
            reloaded.public_key().spki_der(),
            original.public_key().spki_der()
        );
    }

    #[test]
    fn an_empty_or_oversized_credential_is_refused_and_the_bound_is_inclusive() {
        let empty = creds_with(&[]);
        assert!(matches!(
            read_egress_seal_key(empty.path().to_str(), Path::new(NO_EGRESS_DIR)),
            Err(VaultError::SealKey(_))
        ));
        let over = creds_with(&vec![0x30; crate::MAX_SEAL_KEY_BYTES + 1]);
        assert!(matches!(
            read_egress_seal_key(over.path().to_str(), Path::new(NO_EGRESS_DIR)),
            Err(VaultError::Io { source, .. }) if source.to_string().starts_with("too large (513 bytes, limit 512)")
        ));
        let creds = creds_with(&[0x30; crate::MAX_SEAL_KEY_BYTES]);
        assert_eq!(
            read_egress_seal_key(creds.path().to_str(), Path::new(NO_EGRESS_DIR))
                .unwrap()
                .expose()
                .len(),
            crate::MAX_SEAL_KEY_BYTES
        );
    }

    #[test]
    fn a_huge_credential_is_refused_by_its_size_before_any_read() {
        let creds = tempfile::tempdir().unwrap();
        std::fs::File::create(creds.path().join(crate::EGRESS_SEAL_KEY_CRED_NAME))
            .unwrap()
            .set_len(1 << 26)
            .unwrap();
        assert!(matches!(
            read_egress_seal_key(creds.path().to_str(), Path::new(NO_EGRESS_DIR)),
            Err(VaultError::Io { source, .. }) if source.to_string().starts_with("too large (67108864 bytes, limit 512)")
        ));
    }

    #[test]
    fn a_missing_credential_or_an_empty_directory_variable_is_refused() {
        let empty = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_egress_seal_key(empty.path().to_str(), Path::new(NO_EGRESS_DIR)),
            Err(VaultError::Io { .. })
        ));
        assert!(matches!(
            read_egress_seal_key(Some(""), Path::new(NO_EGRESS_DIR)),
            Err(VaultError::CredentialSource(_))
        ));
    }

    #[test]
    fn without_a_credential_or_a_pointer_nothing_is_read() {
        let egress = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_egress_seal_key(None, egress.path()),
            Err(VaultError::CredentialSource(m)) if m.starts_with("no egress seal key source")
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_pointer_reaches_the_keychain_read_only_as_the_egress_account() {
        let egress = tempfile::tempdir().unwrap();
        std::fs::write(
            egress
                .path()
                .join(crate::KeychainPlane::Egress.pointer_file()),
            "",
        )
        .unwrap();
        assert!(matches!(
            read_egress_seal_key(None, egress.path()),
            Err(VaultError::WrongAccount {
                expected: "_maknae-egress",
                ..
            })
        ));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn off_macos_a_pointer_is_never_consulted() {
        let egress = tempfile::tempdir().unwrap();
        std::fs::write(
            egress
                .path()
                .join(crate::KeychainPlane::Egress.pointer_file()),
            "",
        )
        .unwrap();
        assert!(matches!(
            read_egress_seal_key(None, egress.path()),
            Err(VaultError::CredentialSource(_))
        ));
    }
}
