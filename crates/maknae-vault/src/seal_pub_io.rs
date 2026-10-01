use crate::seal_pub_store::{
    choose_present, seal_pub_dir_required, seal_pub_file_required, seal_pub_path, seal_pub_refusal,
    SealPubHome, HOST_HOMES,
};
use crate::VaultError;
use std::path::Path;
use zeroize::Zeroizing;

const ROOT_UID: u32 = 0;

pub fn read_seal_pub_pem() -> Result<String, VaultError> {
    let candidates: Vec<(SealPubHome, &Path)> = HOST_HOMES
        .iter()
        .map(|&home| (home, Path::new(seal_pub_path(home))))
        .collect();
    read_seal_pub_among(&candidates, ROOT_UID)
}

pub(crate) fn read_seal_pub_among(
    candidates: &[(SealPubHome, &Path)],
    owner: u32,
) -> Result<String, VaultError> {
    let mut reads = Vec::with_capacity(candidates.len());
    for &(home, path) in candidates {
        reads.push((home, path, read_one(path, owner)?));
    }
    let found: Vec<(SealPubHome, bool)> = reads
        .iter()
        .map(|(home, _, read)| (*home, read.is_some()))
        .collect();
    let chosen = choose_present(&found)?;
    let (path, bytes) = reads
        .into_iter()
        .find_map(|(home, path, read)| read.filter(|_| home == chosen).map(|b| (path, b)))
        .ok_or(VaultError::SealPubAbsent)?;
    std::str::from_utf8(&bytes)
        .map(str::to_string)
        .map_err(|_| VaultError::SealPubRefused {
            path: path.to_path_buf(),
            detail: "not UTF-8".to_string(),
        })
}

fn read_one(path: &Path, owner: u32) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(VaultError::SealPubRefused {
            path: path.to_path_buf(),
            detail: "not a file path".to_string(),
        });
    };
    let anchor = match maknae_io::open_anchor(
        dir,
        seal_pub_dir_required(owner),
        maknae_io::StrategyPref::Auto,
    ) {
        Ok(anchor) => anchor,
        Err(e) => return seal_pub_refusal(e, path).map_or(Ok(None), Err),
    };
    match anchor.read(Path::new(name), None, seal_pub_file_required(owner)) {
        Ok(out) => Ok(Some(out.value)),
        Err(e) => seal_pub_refusal(e, path).map_or(Ok(None), Err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn euid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    fn pem() -> String {
        maknae_seal::SealPrivateKey::generate()
            .unwrap()
            .public_key()
            .to_pem()
    }

    fn publish(dir: &Path, text: &str, mode: u32) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = dir.join("seal.pub");
        std::fs::write(&file, text).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        file
    }

    struct Layout {
        _root: tempfile::TempDir,
        redhat: PathBuf,
        debian: PathBuf,
    }

    impl Layout {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let redhat = root.path().join("pki").join("seal.pub");
            let debian = root.path().join("ssl").join("seal.pub");
            Self {
                _root: root,
                redhat,
                debian,
            }
        }

        fn read(&self, owner: u32) -> Result<String, VaultError> {
            read_seal_pub_among(
                &[
                    (SealPubHome::RedHat, self.redhat.as_path()),
                    (SealPubHome::Debian, self.debian.as_path()),
                ],
                owner,
            )
        }
    }

    #[test]
    fn exactly_one_published_key_is_read() {
        let l = Layout::new();
        let text = pem();
        publish(l.redhat.parent().unwrap(), &text, 0o644);
        assert_eq!(l.read(euid()).unwrap(), text);
        assert_eq!(text.len(), crate::MAX_SEAL_PUB_BYTES);
    }

    #[test]
    fn no_published_key_is_absent() {
        let l = Layout::new();
        assert!(matches!(l.read(euid()), Err(VaultError::SealPubAbsent)));
        let dir = l.debian.parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(l.read(euid()), Err(VaultError::SealPubAbsent)));
    }

    #[test]
    fn two_published_keys_refuse_naming_both_locations() {
        let l = Layout::new();
        publish(l.redhat.parent().unwrap(), &pem(), 0o644);
        publish(l.debian.parent().unwrap(), &pem(), 0o644);
        assert!(matches!(
            l.read(euid()),
            Err(VaultError::SealPubAmbiguous {
                first: "/etc/pki/maknae/seal.pub",
                second: "/etc/ssl/maknae/seal.pub"
            })
        ));
    }

    #[test]
    fn a_writable_oversized_linked_or_foreign_key_is_refused() {
        let writable = Layout::new();
        publish(writable.redhat.parent().unwrap(), &pem(), 0o664);
        let oversized = Layout::new();
        publish(
            oversized.redhat.parent().unwrap(),
            &format!("{}x", pem()),
            0o644,
        );
        let linked = Layout::new();
        let file = publish(linked.redhat.parent().unwrap(), &pem(), 0o644);
        std::fs::hard_link(&file, file.with_file_name("second")).unwrap();
        let open_dir = Layout::new();
        let dir = open_dir.redhat.parent().unwrap();
        publish(dir, &pem(), 0o644);
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o775)).unwrap();
        for (label, l, owner) in [
            ("group-writable file", &writable, euid()),
            ("216 bytes", &oversized, euid()),
            ("two links", &linked, euid()),
            ("group-writable directory", &open_dir, euid()),
        ] {
            assert!(
                matches!(l.read(owner), Err(VaultError::SealPubRefused { .. })),
                "{label}"
            );
        }
        let foreign = Layout::new();
        publish(foreign.redhat.parent().unwrap(), &pem(), 0o644);
        assert!(matches!(
            foreign.read(euid() + 1),
            Err(VaultError::SealPubRefused { .. })
        ));
    }

    #[test]
    fn a_refused_location_is_not_skipped_for_a_valid_one() {
        let l = Layout::new();
        publish(l.redhat.parent().unwrap(), &pem(), 0o644);
        publish(l.debian.parent().unwrap(), &pem(), 0o666);
        assert!(matches!(
            l.read(euid()),
            Err(VaultError::SealPubRefused { path, .. }) if path == l.debian
        ));
    }
}
