use crate::keychain::{observe_pointer, read_plane_secret};
use crate::keychain_policy::daemon_keychain_dir;
use crate::secret_source::{
    graph_key_from_bytes, graph_key_from_hex, resolve_graph_key_source, GraphKey, GraphKeySource,
    GRAPH_KEY_LENGTH,
};
use crate::{KeychainPlane, VaultError, GRAPH_KEY_BYTES};
use std::io::ErrorKind;
use std::path::Path;

pub fn read_graph_key(
    credentials_dir: Option<&str>,
    config_dir: &Path,
) -> Result<GraphKey, VaultError> {
    let pointer = match credentials_dir {
        None => observe_pointer(&daemon_keychain_dir(config_dir), KeychainPlane::Graph)?,
        Some(_) => None,
    };
    match resolve_graph_key_source(credentials_dir, pointer.as_deref())? {
        GraphKeySource::CredentialsDirectory(path) => {
            match crate::read_storage_within(&path, Some(GRAPH_KEY_BYTES as u64)) {
                Ok(bytes) => graph_key_from_bytes(&bytes),
                Err(VaultError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Err(
                    VaultError::GraphKeyAbsent(format!("{} does not exist", path.display())),
                ),
                Err(VaultError::Io { source, .. }) if source.kind() == ErrorKind::FileTooLarge => {
                    Err(VaultError::GraphKey(GRAPH_KEY_LENGTH))
                }
                Err(e) => Err(e),
            }
        }
        GraphKeySource::Keychain(pointer) => {
            graph_key_from_hex(&read_plane_secret(&pointer, KeychainPlane::Graph)?)
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn creds_with(bytes: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(crate::GRAPH_KEY_CRED_NAME), bytes).unwrap();
        dir
    }

    const NO_CONFIG_DIR: &str = "/nonexistent/maknae";

    #[test]
    fn a_credential_of_32_bytes_is_the_key() {
        let key: Vec<u8> = (100u8..132).collect();
        let creds = creds_with(&key);
        let got = read_graph_key(creds.path().to_str(), Path::new(NO_CONFIG_DIR)).unwrap();
        assert_eq!(got.into_bytes().as_slice(), key.as_slice());
    }

    #[test]
    fn a_credential_of_any_other_length_is_malformed() {
        for n in [0, 31, 33, 1 << 16] {
            let creds = creds_with(&vec![1; n]);
            assert!(
                matches!(
                    read_graph_key(creds.path().to_str(), Path::new(NO_CONFIG_DIR)),
                    Err(VaultError::GraphKey("not exactly 32 bytes"))
                ),
                "{n}"
            );
        }
    }

    #[test]
    fn an_absent_credential_or_directory_names_enroll() {
        let empty = tempfile::tempdir().unwrap();
        let missing_dir = empty.path().join("gone");
        for dir in [empty.path(), missing_dir.as_path()] {
            let err = read_graph_key(dir.to_str(), Path::new(NO_CONFIG_DIR)).unwrap_err();
            assert!(matches!(err, VaultError::GraphKeyAbsent(_)), "{err:?}");
            assert!(
                err.to_string().ends_with("run `sudo maknae enroll`"),
                "{err}"
            );
        }
    }

    #[test]
    fn an_unreadable_credential_is_an_io_refusal_not_absence() {
        let creds = tempfile::tempdir().unwrap();
        std::fs::create_dir(creds.path().join(crate::GRAPH_KEY_CRED_NAME)).unwrap();
        assert!(matches!(
            read_graph_key(creds.path().to_str(), Path::new(NO_CONFIG_DIR)),
            Err(VaultError::Io { .. })
        ));
    }

    #[test]
    fn an_empty_directory_variable_is_refused() {
        assert!(matches!(
            read_graph_key(Some(""), Path::new(NO_CONFIG_DIR)),
            Err(VaultError::CredentialSource(_))
        ));
    }

    #[test]
    fn without_a_credential_or_a_pointer_the_key_is_absent() {
        let config = tempfile::tempdir().unwrap();
        std::fs::create_dir(config.path().join("private")).unwrap();
        assert!(matches!(
            read_graph_key(None, config.path()),
            Err(VaultError::GraphKeyAbsent(_))
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_pointer_under_private_reaches_the_keychain_only_as_the_daemon_account() {
        let config = tempfile::tempdir().unwrap();
        std::fs::create_dir(config.path().join("private")).unwrap();
        std::fs::write(crate::graph_keychain_pointer(config.path()), "").unwrap();
        assert!(matches!(
            read_graph_key(None, config.path()),
            Err(VaultError::WrongAccount {
                expected: "_maknae",
                ..
            })
        ));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn off_macos_a_pointer_is_never_consulted() {
        let config = tempfile::tempdir().unwrap();
        std::fs::create_dir(config.path().join("private")).unwrap();
        std::fs::write(crate::graph_keychain_pointer(config.path()), "").unwrap();
        assert!(matches!(
            read_graph_key(None, config.path()),
            Err(VaultError::GraphKeyAbsent(_))
        ));
    }
}
