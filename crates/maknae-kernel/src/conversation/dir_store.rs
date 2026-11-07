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
        match self.anchor.remove(&file(name), None).map_err(io)?.value {
            true => Ok(()),
            false => Err(StoreError::NotFound),
        }
    }
}
