use super::store::{BlobStore, Blobs, StoreError};
use maknae_io::Zeroizing;
use maknae_proto::ConversationId;
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

#[derive(Default)]
pub struct MemBlobs(Mutex<BTreeMap<String, Vec<u8>>>);

pub type MemStore = BlobStore<MemBlobs>;

impl MemBlobs {
    fn map(&self) -> MutexGuard<'_, BTreeMap<String, Vec<u8>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for BlobStore<MemBlobs> {
    fn default() -> Self {
        BlobStore::with(MemBlobs::default())
    }
}

impl BlobStore<MemBlobs> {
    pub fn raw(&self, id: &ConversationId) -> Option<Vec<u8>> {
        self.blobs.map().get(id.as_str()).cloned()
    }

    pub fn put_raw(&self, id: &ConversationId, bytes: Vec<u8>) {
        self.blobs.map().insert(id.as_str().to_owned(), bytes);
    }
}

impl Blobs for MemBlobs {
    fn names(&self) -> Result<Vec<String>, StoreError> {
        Ok(self.map().keys().cloned().collect())
    }

    fn load(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.map()
            .get(name)
            .map(|b| Zeroizing::new(b.clone()))
            .ok_or(StoreError::NotFound)
    }

    fn save(&self, name: &str, plain: &[u8]) -> Result<(), StoreError> {
        self.map().insert(name.to_owned(), plain.to_vec());
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.map()
            .remove(name)
            .map(|_| ())
            .ok_or(StoreError::NotFound)
    }
}
