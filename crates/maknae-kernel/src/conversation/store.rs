use super::record::{decode, encode, ConversationRecord};
use maknae_proto::ConversationId;
use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    StaleFence,
    Exists,
    OwnerFull,
    IdMismatch,
    Corrupt,
    Io(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("conversation not found"),
            Self::StaleFence => f.write_str("conversation changed since it was read"),
            Self::Exists => f.write_str("conversation already exists"),
            Self::OwnerFull => f.write_str("owner holds the maximum number of conversations"),
            Self::IdMismatch => f.write_str("conversation record names another conversation"),
            Self::Corrupt => f.write_str("conversation record cannot be opened"),
            Self::Io(cause) => write!(f, "conversation store: {cause}"),
        }
    }
}

impl std::error::Error for StoreError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan<T> {
    pub value: T,
    pub unreadable: Vec<String>,
}

pub type Page = (Vec<ConversationRecord>, Option<ConversationId>);

pub trait ConversationStore: Send + Sync {
    fn create(&self, rec: ConversationRecord, max_for_owner: usize)
        -> Result<Scan<()>, StoreError>;

    fn get(&self, id: &ConversationId) -> Result<ConversationRecord, StoreError>;

    fn update(
        &self,
        id: &ConversationId,
        expected_fence: u64,
        f: &mut dyn FnMut(&mut ConversationRecord),
    ) -> Result<ConversationRecord, StoreError>;

    fn remove(
        &self,
        id: &ConversationId,
        expected_fence: u64,
    ) -> Result<ConversationRecord, StoreError>;

    fn list_by_owner(
        &self,
        owner: u32,
        after: Option<&ConversationId>,
        limit: usize,
    ) -> Result<Scan<Page>, StoreError>;

    fn idle_for_owner(
        &self,
        owner: u32,
        older_than_epoch: u64,
    ) -> Result<Scan<Vec<ConversationRecord>>, StoreError>;
}

pub trait Blobs: Send + Sync {
    fn names(&self) -> Result<Vec<String>, StoreError>;
    fn load(&self, name: &str) -> Result<maknae_io::Zeroizing<Vec<u8>>, StoreError>;
    fn save(&self, name: &str, plain: &[u8]) -> Result<(), StoreError>;
    fn delete(&self, name: &str) -> Result<(), StoreError>;
}

pub struct BlobStore<B> {
    pub(super) blobs: B,
    lock: Mutex<()>,
}

impl<B: Blobs> BlobStore<B> {
    pub(super) fn with(blobs: B) -> Self {
        Self {
            blobs,
            lock: Mutex::new(()),
        }
    }

    fn serial(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn read(&self, id: &ConversationId) -> Result<ConversationRecord, StoreError> {
        decode(&self.blobs.load(id.as_str())?, id)
    }

    fn scan(&self) -> Result<Scan<Vec<ConversationRecord>>, StoreError> {
        let mut names = self.blobs.names()?;
        names.sort();
        let mut value = Vec::new();
        let mut unreadable = Vec::new();
        for name in names {
            match ConversationId::parse(&name).map(|id| self.read(&id)) {
                Some(Ok(rec)) => value.push(rec),
                _ => unreadable.push(name),
            }
        }
        Ok(Scan { value, unreadable })
    }

    fn fenced(
        &self,
        id: &ConversationId,
        expected_fence: u64,
    ) -> Result<ConversationRecord, StoreError> {
        let rec = self.read(id)?;
        if rec.fence != expected_fence {
            return Err(StoreError::StaleFence);
        }
        Ok(rec)
    }
}

impl<B: Blobs> ConversationStore for BlobStore<B> {
    fn create(
        &self,
        rec: ConversationRecord,
        max_for_owner: usize,
    ) -> Result<Scan<()>, StoreError> {
        let _serial = self.serial();
        match self.read(&rec.id) {
            Err(StoreError::NotFound) => {}
            Ok(_) => return Err(StoreError::Exists),
            Err(e) => return Err(e),
        }
        let all = self.scan()?;
        let held = all.value.iter().filter(|r| r.owner == rec.owner).count();
        if held >= max_for_owner {
            return Err(StoreError::OwnerFull);
        }
        self.blobs.save(rec.id.as_str(), &encode(&rec)?)?;
        Ok(Scan {
            value: (),
            unreadable: all.unreadable,
        })
    }

    fn get(&self, id: &ConversationId) -> Result<ConversationRecord, StoreError> {
        self.read(id)
    }

    fn update(
        &self,
        id: &ConversationId,
        expected_fence: u64,
        f: &mut dyn FnMut(&mut ConversationRecord),
    ) -> Result<ConversationRecord, StoreError> {
        let _serial = self.serial();
        let mut rec = self.fenced(id, expected_fence)?;
        let owner = rec.owner;
        f(&mut rec);
        rec.id = id.clone();
        rec.owner = owner;
        rec.fence = expected_fence + 1;
        self.blobs.save(id.as_str(), &encode(&rec)?)?;
        Ok(rec)
    }

    fn remove(
        &self,
        id: &ConversationId,
        expected_fence: u64,
    ) -> Result<ConversationRecord, StoreError> {
        let _serial = self.serial();
        let rec = self.fenced(id, expected_fence)?;
        self.blobs.delete(id.as_str())?;
        Ok(rec)
    }

    fn list_by_owner(
        &self,
        owner: u32,
        after: Option<&ConversationId>,
        limit: usize,
    ) -> Result<Scan<Page>, StoreError> {
        let _serial = self.serial();
        let all = self.scan()?;
        let mut matching: Vec<ConversationRecord> = all
            .value
            .into_iter()
            .filter(|r| r.owner == owner && after.is_none_or(|a| r.id > *a))
            .collect();
        let more = matching.len() > limit;
        matching.truncate(limit);
        let next = if more {
            matching.last().map(|r| r.id.clone())
        } else {
            None
        };
        Ok(Scan {
            value: (matching, next),
            unreadable: all.unreadable,
        })
    }

    fn idle_for_owner(
        &self,
        owner: u32,
        older_than_epoch: u64,
    ) -> Result<Scan<Vec<ConversationRecord>>, StoreError> {
        let _serial = self.serial();
        let all = self.scan()?;
        Ok(Scan {
            value: all
                .value
                .into_iter()
                .filter(|r| r.owner == owner && r.last_active < older_than_epoch)
                .collect(),
            unreadable: all.unreadable,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::chain::ChainHead;
    use crate::conversation::dir_store::DirStore;
    use crate::conversation::mem_store::MemStore;
    use crate::conversation::record::Provenance;
    use maknae_io::Zeroizing;
    use maknae_state::envelope::{WrappingKey, KEY_LEN};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Barrier;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn fresh_id() -> ConversationId {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        ConversationId::parse(&format!("{n:032x}")).unwrap()
    }

    fn rec(owner: u32, last_active: u64) -> ConversationRecord {
        let id = fresh_id();
        ConversationRecord {
            chain: ChainHead::genesis(&id),
            id,
            owner,
            cwd: "/home/u/project".into(),
            opened_at: 10,
            last_active,
            full: false,
            turns: 0,
            bytes: 0,
            last_reply: None,
            fence: 0,
            provenance: Provenance::new("UNCLASSIFIED"),
        }
    }

    trait Fixture {
        fn store(&self) -> &dyn ConversationStore;
        fn copy_record(&self, from: &ConversationId, to: &ConversationId);
        fn tamper(&self, id: &ConversationId);
        fn reopen(&mut self);
    }

    fn key() -> WrappingKey {
        WrappingKey::new(Zeroizing::new([7u8; KEY_LEN]))
    }

    struct DirFx {
        tmp: tempfile::TempDir,
        uid: u32,
        store: Option<DirStore>,
    }

    impl DirFx {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let uid = nix::unistd::geteuid().as_raw();
            let store = Some(DirStore::open(tmp.path(), uid, key()).unwrap());
            Self { tmp, uid, store }
        }

        fn file(&self, id: &ConversationId) -> std::path::PathBuf {
            self.tmp.path().join(format!("{}.conv", id.as_str()))
        }
    }

    impl Fixture for DirFx {
        fn store(&self) -> &dyn ConversationStore {
            self.store.as_ref().unwrap()
        }

        fn copy_record(&self, from: &ConversationId, to: &ConversationId) {
            let bytes = fs::read(self.file(from)).unwrap();
            fs::write(self.file(to), bytes).unwrap();
        }

        fn tamper(&self, id: &ConversationId) {
            let mut bytes = fs::read(self.file(id)).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
            fs::write(self.file(id), bytes).unwrap();
        }

        fn reopen(&mut self) {
            self.store = None;
            self.store = Some(DirStore::open(self.tmp.path(), self.uid, key()).unwrap());
        }
    }

    struct MemFx(MemStore);

    impl Fixture for MemFx {
        fn store(&self) -> &dyn ConversationStore {
            &self.0
        }

        fn copy_record(&self, from: &ConversationId, to: &ConversationId) {
            self.0.put_raw(to, self.0.raw(from).unwrap());
        }

        fn tamper(&self, id: &ConversationId) {
            let mut bytes = self.0.raw(id).unwrap();
            bytes.truncate(bytes.len() / 2);
            self.0.put_raw(id, bytes);
        }

        fn reopen(&mut self) {}
    }

    macro_rules! both {
        ($($name:ident),* $(,)?) => {$(
            mod $name {
                #[test]
                fn dir() {
                    super::$name(&mut super::DirFx::new());
                }

                #[test]
                fn mem() {
                    super::$name(&mut super::MemFx(super::MemStore::default()));
                }
            }
        )*};
    }

    both!(
        create_then_get_round_trips,
        create_twice_is_exists,
        create_over_an_unreadable_record_is_refused_and_leaves_it,
        create_at_the_owner_bound_is_owner_full_and_concurrent_creates_cannot_exceed_it,
        update_with_a_stale_fence_is_refused,
        remove_with_a_stale_fence_is_refused,
        a_missing_record_is_not_found,
        a_swapped_record_file_is_id_mismatch,
        a_tampered_ciphertext_is_corrupt,
        one_unreadable_record_is_skipped_and_reported_not_fatal,
        list_is_owner_scoped_and_paged,
        idle_for_owner_returns_only_that_owners_stale_records,
        records_survive_reopen,
    );

    fn create_then_get_round_trips(fx: &mut dyn Fixture) {
        let mut r = rec(1000, 50);
        r.last_reply = Some([9; 32]);
        r.full = true;
        let scan = fx.store().create(r.clone(), 32).unwrap();
        assert!(scan.unreadable.is_empty());
        assert_eq!(fx.store().get(&r.id).unwrap(), r);
    }

    fn create_twice_is_exists(fx: &mut dyn Fixture) {
        let r = rec(1000, 50);
        fx.store().create(r.clone(), 32).unwrap();
        let mut again = r.clone();
        again.cwd = "/elsewhere".into();
        assert_eq!(fx.store().create(again, 32), Err(StoreError::Exists));
        assert_eq!(fx.store().get(&r.id).unwrap(), r);
    }

    fn create_over_an_unreadable_record_is_refused_and_leaves_it(fx: &mut dyn Fixture) {
        let r = rec(1000, 50);
        fx.store().create(r.clone(), 32).unwrap();
        fx.tamper(&r.id);
        assert_eq!(fx.store().create(r.clone(), 32), Err(StoreError::Corrupt));
        assert_eq!(fx.store().get(&r.id), Err(StoreError::Corrupt));
    }

    fn create_at_the_owner_bound_is_owner_full_and_concurrent_creates_cannot_exceed_it(
        fx: &mut dyn Fixture,
    ) {
        let store = fx.store();
        for _ in 0..31 {
            store.create(rec(1000, 1), 32).unwrap();
        }
        let gate = Barrier::new(2);
        let results: Vec<_> = std::thread::scope(|s| {
            let racers: Vec<_> = (0..2)
                .map(|_| {
                    s.spawn(|| {
                        let r = rec(1000, 1);
                        gate.wait();
                        store.create(r, 32)
                    })
                })
                .collect();
            racers.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert!(results.contains(&Err(StoreError::OwnerFull)));
        assert_eq!(store.create(rec(1000, 1), 32), Err(StoreError::OwnerFull));
        let (page, _) = store.list_by_owner(1000, None, 64).unwrap().value;
        assert_eq!(page.len(), 32);
        store.create(rec(1001, 1), 32).unwrap();
    }

    fn update_with_a_stale_fence_is_refused(fx: &mut dyn Fixture) {
        let r = rec(1000, 50);
        fx.store().create(r.clone(), 32).unwrap();
        let mut ran = false;
        assert_eq!(
            fx.store().update(&r.id, 1, &mut |_| ran = true),
            Err(StoreError::StaleFence)
        );
        assert!(!ran);
        let updated = fx
            .store()
            .update(&r.id, 0, &mut |x| {
                x.turns = 5;
                x.fence = 77;
                x.owner = 4242;
                x.id = fresh_id();
            })
            .unwrap();
        assert_eq!(updated.fence, 1);
        assert_eq!(updated.turns, 5);
        assert_eq!(updated.owner, 1000);
        assert_eq!(updated.id, r.id);
        assert_eq!(fx.store().get(&r.id).unwrap(), updated);
        assert_eq!(
            fx.store().update(&r.id, 0, &mut |_| {}),
            Err(StoreError::StaleFence)
        );
        assert_eq!(fx.store().update(&r.id, 1, &mut |_| {}).unwrap().fence, 2);
    }

    fn remove_with_a_stale_fence_is_refused(fx: &mut dyn Fixture) {
        let r = rec(1000, 50);
        fx.store().create(r.clone(), 32).unwrap();
        fx.store().update(&r.id, 0, &mut |_| {}).unwrap();
        assert_eq!(fx.store().remove(&r.id, 0), Err(StoreError::StaleFence));
        assert_eq!(fx.store().get(&r.id).unwrap().fence, 1);
        assert_eq!(fx.store().remove(&r.id, 1).unwrap().id, r.id);
        assert_eq!(fx.store().get(&r.id), Err(StoreError::NotFound));
    }

    fn a_missing_record_is_not_found(fx: &mut dyn Fixture) {
        let id = fresh_id();
        assert_eq!(fx.store().get(&id), Err(StoreError::NotFound));
        assert_eq!(
            fx.store().update(&id, 0, &mut |_| {}),
            Err(StoreError::NotFound)
        );
        assert_eq!(fx.store().remove(&id, 0), Err(StoreError::NotFound));
    }

    fn a_swapped_record_file_is_id_mismatch(fx: &mut dyn Fixture) {
        let a = rec(1000, 50);
        let b = rec(1000, 50);
        fx.store().create(a.clone(), 32).unwrap();
        fx.store().create(b.clone(), 32).unwrap();
        fx.copy_record(&a.id, &b.id);
        assert_eq!(fx.store().get(&b.id), Err(StoreError::IdMismatch));
        assert_eq!(
            fx.store().update(&b.id, 0, &mut |_| {}),
            Err(StoreError::IdMismatch)
        );
        assert_eq!(fx.store().remove(&b.id, 0), Err(StoreError::IdMismatch));
        let listed = fx.store().list_by_owner(1000, None, 12).unwrap();
        assert_eq!(listed.value.0, vec![a.clone()]);
        assert_eq!(listed.unreadable, vec![b.id.as_str().to_owned()]);
        assert_eq!(fx.store().get(&a.id).unwrap(), a);
    }

    fn a_tampered_ciphertext_is_corrupt(fx: &mut dyn Fixture) {
        let r = rec(1000, 50);
        fx.store().create(r.clone(), 32).unwrap();
        fx.tamper(&r.id);
        assert_eq!(fx.store().get(&r.id), Err(StoreError::Corrupt));
        assert_eq!(
            fx.store().update(&r.id, 0, &mut |_| {}),
            Err(StoreError::Corrupt)
        );
    }

    fn one_unreadable_record_is_skipped_and_reported_not_fatal(fx: &mut dyn Fixture) {
        let good = [rec(1000, 10), rec(1000, 10)];
        let bad = rec(1000, 10);
        for r in good.iter().chain([&bad]) {
            fx.store().create(r.clone(), 32).unwrap();
        }
        fx.tamper(&bad.id);
        let want = vec![bad.id.as_str().to_owned()];

        let listed = fx.store().list_by_owner(1000, None, 12).unwrap();
        assert_eq!(listed.value.0, good.to_vec());
        assert_eq!(listed.unreadable, want);

        let idle = fx.store().idle_for_owner(1000, 100).unwrap();
        assert_eq!(idle.value, good.to_vec());
        assert_eq!(idle.unreadable, want);

        let created = fx.store().create(rec(1000, 10), 3).unwrap();
        assert_eq!(created.unreadable, want);

        assert_eq!(fx.store().get(&bad.id), Err(StoreError::Corrupt));
    }

    fn list_is_owner_scoped_and_paged(fx: &mut dyn Fixture) {
        let mut mine: Vec<ConversationRecord> = (0..30).map(|_| rec(1000, 1)).collect();
        for r in &mine {
            fx.store().create(r.clone(), 32).unwrap();
        }
        for _ in 0..3 {
            fx.store().create(rec(1001, 1), 32).unwrap();
        }
        mine.sort_by(|a, b| a.id.cmp(&b.id));

        let mut seen = Vec::new();
        let mut sizes = Vec::new();
        let mut after: Option<ConversationId> = None;
        loop {
            let page = fx.store().list_by_owner(1000, after.as_ref(), 12).unwrap();
            assert!(page.unreadable.is_empty());
            let (entries, next) = page.value;
            sizes.push(entries.len());
            if let Some(n) = &next {
                assert_eq!(Some(n), entries.last().map(|r| &r.id));
            }
            seen.extend(entries);
            match next {
                Some(n) => after = Some(n),
                None => break,
            }
        }
        assert_eq!(sizes, vec![12, 12, 6]);
        assert_eq!(seen, mine);

        let theirs = fx.store().list_by_owner(1001, None, 12).unwrap().value;
        assert_eq!(theirs.0.len(), 3);
        assert!(theirs.0.iter().all(|r| r.owner == 1001));
        assert_eq!(theirs.1, None);

        let exact = fx.store().list_by_owner(1001, None, 3).unwrap().value;
        assert_eq!((exact.0.len(), exact.1), (3, None));
    }

    fn idle_for_owner_returns_only_that_owners_stale_records(fx: &mut dyn Fixture) {
        let stale = rec(1000, 100);
        let boundary = rec(1000, 150);
        let fresh = rec(1000, 200);
        let other = rec(1001, 100);
        for r in [&stale, &boundary, &fresh, &other] {
            fx.store().create(r.clone(), 32).unwrap();
        }
        let idle = fx.store().idle_for_owner(1000, 150).unwrap();
        assert_eq!(idle.value, vec![stale]);
        assert!(idle.unreadable.is_empty());
    }

    fn records_survive_reopen(fx: &mut dyn Fixture) {
        let r = rec(1000, 50);
        fx.store().create(r.clone(), 32).unwrap();
        let updated = fx.store().update(&r.id, 0, &mut |x| x.turns = 3).unwrap();
        fx.reopen();
        assert_eq!(fx.store().get(&r.id).unwrap(), updated);
    }

    #[test]
    fn a_second_open_of_the_same_dir_is_refused() {
        let fx = DirFx::new();
        assert!(matches!(
            DirStore::open(fx.tmp.path(), fx.uid, key()),
            Err(StoreError::Io(_))
        ));
        drop(fx.store);
        assert!(DirStore::open(fx.tmp.path(), fx.uid, key()).is_ok());
    }

    #[test]
    fn a_record_under_the_wrong_key_is_corrupt() {
        let mut fx = DirFx::new();
        let r = rec(1000, 50);
        fx.store().create(r.clone(), 32).unwrap();
        fx.store = None;
        let other = WrappingKey::new(Zeroizing::new([8u8; KEY_LEN]));
        fx.store = Some(DirStore::open(fx.tmp.path(), fx.uid, other).unwrap());
        assert_eq!(fx.store().get(&r.id), Err(StoreError::Corrupt));
    }

    #[test]
    fn a_record_file_is_sealed_and_owner_only() {
        let fx = DirFx::new();
        let mut r = rec(1000, 50);
        r.cwd = "/home/u/a-distinctive-sentinel-path".into();
        fx.store().create(r.clone(), 32).unwrap();
        let path = fx.file(&r.id);
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes
            .windows(b"distinctive-sentinel".len())
            .any(|w| w == b"distinctive-sentinel"));
    }

    #[test]
    fn a_group_readable_record_is_refused() {
        let fx = DirFx::new();
        let r = rec(1000, 50);
        fx.store().create(r.clone(), 32).unwrap();
        fs::set_permissions(fx.file(&r.id), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(fx.store().get(&r.id), Err(StoreError::Io(_))));
    }

    #[test]
    fn a_loose_or_foreign_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            DirStore::open(tmp.path(), uid, key()),
            Err(StoreError::Io(_))
        ));
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            DirStore::open(tmp.path(), uid.wrapping_add(1), key()),
            Err(StoreError::Io(_))
        ));
    }

    #[test]
    fn a_failed_publish_is_an_io_error_and_changes_nothing() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let fx = DirFx::new();
        let r = rec(1000, 50);
        fx.store().create(r.clone(), 32).unwrap();
        fs::set_permissions(fx.tmp.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let update = fx.store().update(&r.id, 0, &mut |x| x.turns = 9);
        let create = fx.store().create(rec(1000, 50), 32);
        fs::set_permissions(fx.tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(update, Err(StoreError::Io(_))));
        assert!(matches!(create, Err(StoreError::Io(_))));
        assert_eq!(fx.store().get(&r.id).unwrap(), r);
    }

    #[test]
    fn every_store_error_names_itself() {
        let all = [
            StoreError::NotFound,
            StoreError::StaleFence,
            StoreError::Exists,
            StoreError::OwnerFull,
            StoreError::IdMismatch,
            StoreError::Corrupt,
            StoreError::Io("disk-sentinel".into()),
        ];
        let shown: std::collections::BTreeSet<String> =
            all.iter().map(ToString::to_string).collect();
        assert_eq!(shown.len(), all.len());
        assert!(all[6].to_string().contains("disk-sentinel"));
    }
}
