use crate::keychain::{observe_pointer, read_plane_secret};
use crate::secret_source::{
    check_seal_key_len, resolve_egress_seal_key_source, seal_key_from_hex, EgressSealKeySource,
    SealKeyDer,
};
use crate::{KeychainPlane, VaultError};
use std::path::Path;

pub fn read_egress_seal_key(
    credentials_dir: Option<&str>,
    egress_dir: &Path,
) -> Result<SealKeyDer, VaultError> {
    let pointer = match credentials_dir {
        None => observe_pointer(egress_dir, KeychainPlane::Egress)?,
        Some(_) => None,
    };
    match resolve_egress_seal_key_source(credentials_dir, pointer.as_deref())? {
        EgressSealKeySource::CredentialsDirectory(path) => {
            let der = crate::read_storage(&path)?;
            check_seal_key_len(der.len())?;
            Ok(SealKeyDer::new(der))
        }
        EgressSealKeySource::Keychain(pointer) => {
            seal_key_from_hex(&read_plane_secret(&pointer, KeychainPlane::Egress)?)
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn der() -> Zeroizing<Vec<u8>> {
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

    #[test]
    fn a_credential_holding_a_seal_key_is_read_whole() {
        let key = der();
        let creds = creds_with(&key);
        let got = read_egress_seal_key(creds.path().to_str(), Path::new(NO_EGRESS_DIR)).unwrap();
        assert!(got.expose() == key.as_slice());
        let reloaded = maknae_seal::SealPrivateKey::from_pkcs8_der(got.expose()).unwrap();
        let original = maknae_seal::SealPrivateKey::from_pkcs8_der(&key).unwrap();
        assert_eq!(
            reloaded.public_key().spki_der(),
            original.public_key().spki_der()
        );
    }

    #[test]
    fn an_empty_or_oversized_credential_is_refused_and_the_bound_is_inclusive() {
        for n in [0, crate::MAX_SEAL_KEY_BYTES + 1] {
            let creds = creds_with(&vec![0x30; n]);
            assert!(
                matches!(
                    read_egress_seal_key(creds.path().to_str(), Path::new(NO_EGRESS_DIR)),
                    Err(VaultError::SealKey(_))
                ),
                "{n}"
            );
        }
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
