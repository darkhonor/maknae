use super::store::{BlobStore, Blobs, StoreError};
use maknae_io::{
    open_anchor, Anchor, AnchorLock, AnchorRequired, IoError, IoKind, Mode, StrategyPref,
    TargetRequired, Zeroizing,
};
use maknae_state::envelope::{open, seal, WrappingKey};
use std::path::{Path, PathBuf};

pub const RECORD_SUFFIX: &str = ".conv";
pub const RECORD_MAX_BYTES: u64 = 64 << 10;

pub struct DirBlobs {
    anchor: Anchor,
    _lock: AnchorLock,
    owner: u32,
    key: WrappingKey,
}

pub type DirStore = BlobStore<DirBlobs>;

impl BlobStore<DirBlobs> {
    pub fn open(dir: &Path, dir_owner: u32, key: WrappingKey) -> Result<DirStore, StoreError> {
        let anchor = open_anchor(
            dir,
            AnchorRequired {
                owner: Some(dir_owner),
                mode_mask: Some(0o077),
            },
            StrategyPref::Auto,
        )
        .map_err(io)?;
        let lock = anchor.try_lock_exclusive().map_err(|e| match e {
            IoError::Locked { .. } => {
                StoreError::Io("another maknaed holds the conversation directory".into())
            }
            e => io(e),
        })?;
        Ok(BlobStore::with(DirBlobs {
            anchor,
            _lock: lock,
            owner: dir_owner,
            key,
        }))
    }
}

fn file(name: &str) -> PathBuf {
    PathBuf::from(format!("{name}{RECORD_SUFFIX}"))
}

fn io(e: IoError) -> StoreError {
    match e {
        IoError::Io {
            kind: IoKind::NotFound,
            ..
        } => StoreError::NotFound,
        e @ (IoError::PublishedNotDurable { .. } | IoError::RemovedNotDurable { .. }) => {
            StoreError::NotDurable(e.to_string())
        }
        e => StoreError::Io(e.to_string()),
    }
}

impl Blobs for DirBlobs {
    fn names(&self) -> Result<Vec<String>, StoreError> {
        let entries = self.anchor.enumerate(Path::new(""), None).map_err(io)?;
        Ok(entries
            .value
            .into_iter()
            .filter_map(|e| {
                let name = e.name.into_string().ok()?;
                name.strip_suffix(RECORD_SUFFIX).map(str::to_owned)
            })
            .collect())
    }

    fn load(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let target = TargetRequired {
            owner: Some(self.owner),
            mode_mask: Some(0o077),
            nlink_exactly_one: true,
            regular_file: true,
            max_bytes: Some(RECORD_MAX_BYTES),
        };
        let sealed = self.anchor.read(&file(name), None, target).map_err(io)?;
        open(&sealed.value, &self.key).map_err(|_| StoreError::Corrupt)
    }

    fn save(&self, name: &str, plain: &[u8]) -> Result<(), StoreError> {
        let sealed = seal(plain, &self.key).map_err(|e| StoreError::Io(e.to_string()))?;
        self.anchor
            .publish(&file(name), None, &sealed, Mode(0o600))
            .map(|_| ())
            .map_err(io)
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        match self
            .anchor
            .remove_durable(&file(name), None)
            .map_err(io)?
            .value
        {
            true => Ok(()),
            false => Err(StoreError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_state::envelope::KEY_LEN;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_unit_creates_the_conversation_store_for_the_daemon_alone() {
        let unit = include_str!("../../../../packaging/common/maknaed.service");
        let lines: Vec<&str> = unit.lines().map(str::trim).collect();
        for want in [
            "StateDirectory=maknae maknae/conversations",
            "StateDirectoryMode=0700",
        ] {
            assert_eq!(lines.iter().filter(|l| **l == want).count(), 1, "{want}");
        }
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.starts_with("StateDirectory"))
                .count(),
            2
        );
    }

    fn key() -> WrappingKey {
        WrappingKey::new(Zeroizing::new([7u8; KEY_LEN]))
    }

    fn open_in(tmp: &tempfile::TempDir) -> DirStore {
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        DirStore::open(tmp.path(), nix::unistd::geteuid().as_raw(), key()).unwrap()
    }

    #[test]
    fn an_unflushed_publish_or_unlink_is_not_durable() {
        let path = PathBuf::from("/s/c.conv");
        let kind = IoKind::Other { raw: 5 };
        for e in [
            IoError::PublishedNotDurable {
                path: path.clone(),
                kind: kind.clone(),
            },
            IoError::RemovedNotDurable {
                path: path.clone(),
                kind: kind.clone(),
            },
        ] {
            let want = StoreError::NotDurable(e.to_string());
            assert_eq!(io(e), want);
        }
    }

    #[test]
    fn deleting_an_absent_record_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_in(&tmp);
        assert_eq!(store.blobs.delete("absent"), Err(StoreError::NotFound));
    }

    #[test]
    fn deleting_a_saved_record_removes_its_file() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_in(&tmp);
        store.blobs.save("gone", b"payload").unwrap();
        assert!(tmp.path().join("gone.conv").exists());
        store.blobs.delete("gone").unwrap();
        assert!(!tmp.path().join("gone.conv").exists());
        assert_eq!(store.blobs.load("gone").unwrap_err(), StoreError::NotFound);
    }

    #[test]
    fn a_saved_record_loads_back_and_only_suffixed_files_are_named() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_in(&tmp);
        store.blobs.save("kept", b"payload").unwrap();
        fs::write(tmp.path().join("stray.txt"), b"x").unwrap();
        assert_eq!(&**store.blobs.load("kept").unwrap(), b"payload");
        assert_eq!(store.blobs.names().unwrap(), vec!["kept".to_owned()]);
    }

    #[test]
    fn a_file_that_is_not_a_sealed_envelope_is_corrupt() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_in(&tmp);
        let path = tmp.path().join("junk.conv");
        fs::write(&path, b"not an envelope").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(store.blobs.load("junk").unwrap_err(), StoreError::Corrupt);
    }

    #[test]
    fn a_record_over_the_size_bound_is_an_io_error() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_in(&tmp);
        let path = tmp.path().join("big.conv");
        fs::write(&path, vec![0u8; RECORD_MAX_BYTES as usize + 1]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(store.blobs.load("big"), Err(StoreError::Io(_))));
    }

    #[test]
    fn a_record_with_a_second_link_is_an_io_error() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_in(&tmp);
        store.blobs.save("linked", b"payload").unwrap();
        fs::hard_link(
            tmp.path().join("linked.conv"),
            tmp.path().join("alias.conv"),
        )
        .unwrap();
        assert!(matches!(store.blobs.load("linked"), Err(StoreError::Io(_))));
    }

    #[test]
    fn a_directory_named_like_a_record_is_an_io_error() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_in(&tmp);
        fs::create_dir(tmp.path().join("dir.conv")).unwrap();
        assert!(matches!(store.blobs.load("dir"), Err(StoreError::Io(_))));
    }

    #[test]
    fn a_non_directory_anchor_is_an_io_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("file");
        fs::write(&path, b"x").unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        assert!(matches!(
            DirStore::open(&path, uid, key()),
            Err(StoreError::Io(_))
        ));
    }

    #[test]
    fn a_missing_anchor_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        assert!(matches!(
            DirStore::open(&tmp.path().join("absent"), uid, key()),
            Err(StoreError::NotFound)
        ));
    }

    #[test]
    fn a_read_only_directory_refuses_a_delete_as_an_io_error() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let store = open_in(&tmp);
        store.blobs.save("held", b"payload").unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let denied = store.blobs.delete("held");
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(denied, Err(StoreError::Io(_))));
        assert_eq!(&**store.blobs.load("held").unwrap(), b"payload");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_name_that_is_not_utf8_is_not_a_record() {
        use std::os::unix::ffi::OsStrExt;
        let tmp = tempfile::tempdir().unwrap();
        let store = open_in(&tmp);
        store.blobs.save("kept", b"payload").unwrap();
        let odd = std::ffi::OsStr::from_bytes(b"\xff\xfe.conv");
        fs::write(tmp.path().join(odd), b"x").unwrap();
        assert_eq!(store.blobs.names().unwrap(), vec!["kept".to_owned()]);
    }
}
