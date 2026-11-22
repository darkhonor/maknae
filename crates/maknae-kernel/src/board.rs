//! The agent message board (#695, ADR-0040): one board per person, written through to
//! sealed records before memory shows any change.
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::{Arc, Mutex, PoisonError};

use maknae_config::AgentId;
use maknae_proto::{Author, Labels, Post, PostDraft, PostId, TaskId};

use crate::board_store::{
    load, Board, BoardFinding, BoardKey, CursorRecord, Name, PostLabels, PostRecord, ReadPlan,
    Settings, Stored, FIRST_SEQ,
};
use crate::task::{draw_id, ID_DRAWS, OUTCOME_UNKNOWN};
use crate::task_store::{encode, Clock, StoreError, TaskBlobs};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    pub board: usize,
    pub author: usize,
}

const CAPS: Caps = Caps {
    board: maknae_proto::BOARD_POSTS_MAX,
    author: maknae_proto::BOARD_AUTHOR_POSTS_MAX,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoardRefusal {
    Full,
    AuthorAtCap,
    NoSuchPost,
    Store(String),
    Unavailable(String),
    Random,
}

impl std::fmt::Display for BoardRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoardRefusal::Full => f.write_str("board full"),
            BoardRefusal::AuthorAtCap => f.write_str("author at cap"),
            BoardRefusal::NoSuchPost => f.write_str("in_reply_to names no post on the board"),
            BoardRefusal::Store(why) => write!(f, "store: {why}"),
            BoardRefusal::Unavailable(why) => f.write_str(why),
            BoardRefusal::Random => f.write_str("no random id"),
        }
    }
}

impl std::error::Error for BoardRefusal {}

fn store(e: StoreError) -> BoardRefusal {
    BoardRefusal::Store(e.to_string())
}

#[derive(Default)]
struct Held {
    boards: BTreeMap<BoardKey, Board>,
    /// Post records written unsynced whose removal did not sync either.
    owed: BTreeSet<String>,
    boot: Vec<BoardFinding>,
}

impl Held {
    fn live(&self, key: BoardKey, id: PostId) -> Option<&Arc<Stored>> {
        let board = self.boards.get(&key)?;
        let seq = board.ids.get(&id)?;
        board.posts.get(seq).filter(|s| s.held.is_empty())
    }
}

/// Posts, settings and cursors, written through to `blobs` before any change is visible in
/// memory. Every change is serialized by `writer`; `held` is locked only to read and to
/// swap, never across I/O.
pub struct BoardStore {
    held: Mutex<Held>,
    writer: Mutex<()>,
    blobs: Box<dyn TaskBlobs>,
    clock: Arc<dyn Clock>,
    caps: Caps,
}

impl BoardStore {
    #[cfg(any(test, feature = "hermetic-test-seam"))]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::open(
            Box::new(crate::task_store::MemTaskBlobs::default()),
            Arc::new(crate::task_store::SystemClock),
        )
        .expect("an empty store opens")
    }

    pub fn open(blobs: Box<dyn TaskBlobs>, clock: Arc<dyn Clock>) -> Result<Self, StoreError> {
        Self::opened(blobs, clock, CAPS)
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn open_with(
        blobs: Box<dyn TaskBlobs>,
        clock: Arc<dyn Clock>,
        caps: Caps,
    ) -> Result<Self, StoreError> {
        Self::opened(blobs, clock, caps)
    }

    fn opened(
        blobs: Box<dyn TaskBlobs>,
        clock: Arc<dyn Clock>,
        caps: Caps,
    ) -> Result<Self, StoreError> {
        let loaded = load(&*blobs)?;
        Ok(Self {
            held: Mutex::new(Held {
                boards: loaded.boards,
                owed: BTreeSet::new(),
                boot: loaded.findings,
            }),
            writer: Mutex::new(()),
            blobs,
            clock,
            caps,
        })
    }

    pub fn take_boot_findings(&self) -> Vec<BoardFinding> {
        std::mem::take(&mut self.held().boot)
    }

    pub fn settle(&self, finding: &BoardFinding) -> Result<(), StoreError> {
        match finding {
            BoardFinding::Quarantined { name, .. } => self.blobs.quarantine(name),
        }
    }

    pub fn settings(&self, key: BoardKey) -> Settings {
        self.held()
            .boards
            .get(&key)
            .map_or_else(Settings::default, |b| b.settings)
    }

    pub fn set_settings(&self, key: BoardKey, settings: Settings) -> Result<(), BoardRefusal> {
        let _w = self.writing();
        let mut rec = self.board_record(key);
        rec.settings = settings;
        self.save_board(key, rec)
    }

    pub fn post(
        &self,
        key: BoardKey,
        author: Author,
        author_uid: Option<u32>,
        task: Option<TaskId>,
        labels: PostLabels,
        draft: PostDraft,
    ) -> Result<Arc<Stored>, BoardRefusal> {
        let mut draw = || draw_id().map_err(|_| BoardRefusal::Random);
        self.place(&mut draw, key, author, author_uid, task, labels, draft)
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    #[allow(clippy::too_many_arguments)]
    pub fn post_with(
        &self,
        draw: &mut dyn FnMut() -> Result<[u8; 16], BoardRefusal>,
        key: BoardKey,
        author: Author,
        author_uid: Option<u32>,
        task: Option<TaskId>,
        labels: PostLabels,
        draft: PostDraft,
    ) -> Result<Arc<Stored>, BoardRefusal> {
        self.place(draw, key, author, author_uid, task, labels, draft)
    }

    pub fn get(&self, key: BoardKey, id: PostId) -> Option<Arc<Stored>> {
        self.held().live(key, id).cloned()
    }

    /// An acknowledgement moves the cursor to `seen_through`, never past what was walked.
    pub fn plan_read(
        &self,
        key: BoardKey,
        reader: &AgentId,
        seen_through: Option<PostId>,
    ) -> ReadPlan {
        let held = self.held();
        let board = held.boards.get(&key);
        let cursor = board
            .and_then(|b| b.cursors.get(reader))
            .copied()
            .unwrap_or(0);
        let ack_to = seen_through.and_then(|id| {
            let board = board?;
            let seq = *board.ids.get(&id)?;
            let to = seq.min(*board.walked.get(reader)?);
            (to > cursor).then_some(to)
        });
        ReadPlan { cursor, ack_to }
    }

    pub fn advance(&self, key: BoardKey, reader: &AgentId, to: u64) -> Result<u64, BoardRefusal> {
        let _w = self.writing();
        let (cursor, next_seq) = {
            let held = self.held();
            let board = held.boards.get(&key);
            (
                board
                    .and_then(|b| b.cursors.get(reader))
                    .copied()
                    .unwrap_or(0),
                board.map_or(FIRST_SEQ, |b| b.next_seq),
            )
        };
        if to <= cursor {
            return Ok(cursor);
        }
        if to >= next_seq {
            return Err(BoardRefusal::Store(format!(
                "cursor {to} is past the board's sequence"
            )));
        }
        let rec = CursorRecord {
            board: key.0,
            agent: reader.as_str().to_owned(),
            cursor: to,
        };
        let plain = encode(&rec).map_err(store)?;
        let name = Name::Cursor(key, reader.clone()).text();
        self.blobs.save(&name, &plain).map_err(store)?;
        self.held()
            .boards
            .entry(key)
            .or_default()
            .cursors
            .insert(reader.clone(), to);
        Ok(to)
    }

    pub fn candidates(&self, key: BoardKey, after: u64, limit: usize) -> Vec<Arc<Stored>> {
        let held = self.held();
        let Some(board) = held.boards.get(&key) else {
            return Vec::new();
        };
        board
            .posts
            .range((Bound::Excluded(after), Bound::Unbounded))
            .map(|(_, s)| s)
            .filter(|s| s.held.is_empty())
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn walked(&self, key: BoardKey, reader: &AgentId, upto: u64) {
        let mut held = self.held();
        let walked = held
            .boards
            .entry(key)
            .or_default()
            .walked
            .entry(reader.clone())
            .or_insert(upto);
        *walked = (*walked).max(upto);
    }

    #[allow(clippy::too_many_arguments)]
    fn place(
        &self,
        draw: &mut dyn FnMut() -> Result<[u8; 16], BoardRefusal>,
        key: BoardKey,
        author: Author,
        author_uid: Option<u32>,
        task: Option<TaskId>,
        labels: PostLabels,
        draft: PostDraft,
    ) -> Result<Arc<Stored>, BoardRefusal> {
        let _w = self.writing();
        self.room(key, &author, draft.in_reply_to)?;
        let mut rec = self.board_record(key);
        let seq = rec.next_seq;
        rec.next_seq = seq
            .checked_add(1)
            .ok_or(BoardRefusal::Store("the sequence is exhausted".into()))?;
        self.save_board(key, rec)?;
        let id = self.fresh_id(key, draw)?;
        let stored = Stored {
            post: Post {
                id,
                author,
                task,
                at_secs: self.clock.now_secs(),
                labels: Labels {},
                draft,
            },
            seq,
            author_uid,
            labels,
            held: BTreeSet::new(),
        };
        let name = Name::Post(key, id).text();
        let plain = encode(&PostRecord {
            board: key.0,
            stored: &stored,
        })
        .map_err(store)?;
        let why = match self.blobs.save(&name, &plain) {
            Ok(()) => {
                let stored = Arc::new(stored);
                let mut held = self.held();
                let board = held.boards.entry(key).or_default();
                board.ids.insert(id, seq);
                board.posts.insert(seq, Arc::clone(&stored));
                return Ok(stored);
            }
            Err(StoreError::NotDurable(why)) => why,
            Err(e @ (StoreError::Io(_) | StoreError::Counters(_))) => return Err(store(e)),
        };
        match self.blobs.delete(&name) {
            Ok(()) => Err(BoardRefusal::Store(why)),
            Err(e) => {
                self.held().owed.insert(name);
                Err(BoardRefusal::Unavailable(format!(
                    "{OUTCOME_UNKNOWN}{why}; not removed: {e}"
                )))
            }
        }
    }

    fn room(
        &self,
        key: BoardKey,
        author: &Author,
        in_reply_to: Option<PostId>,
    ) -> Result<(), BoardRefusal> {
        let held = self.held();
        if let Some(board) = held.boards.get(&key) {
            let live = board.posts.values().filter(|s| s.held.is_empty()).count();
            if live >= self.caps.board {
                return Err(BoardRefusal::Full);
            }
            let authored = board
                .posts
                .values()
                .filter(|s| s.post.author == *author)
                .count();
            if authored >= self.caps.author {
                return Err(BoardRefusal::AuthorAtCap);
            }
        }
        match in_reply_to {
            Some(target) if held.live(key, target).is_none() => Err(BoardRefusal::NoSuchPost),
            Some(_) | None => Ok(()),
        }
    }

    fn fresh_id(
        &self,
        key: BoardKey,
        draw: &mut dyn FnMut() -> Result<[u8; 16], BoardRefusal>,
    ) -> Result<PostId, BoardRefusal> {
        for _ in 0..ID_DRAWS {
            let id = PostId(draw()?);
            let held = self.held();
            let taken = held
                .boards
                .get(&key)
                .is_some_and(|b| b.ids.contains_key(&id))
                || held.owed.contains(&Name::Post(key, id).text());
            if !taken {
                return Ok(id);
            }
        }
        Err(BoardRefusal::Random)
    }

    fn board_record(&self, key: BoardKey) -> crate::board_store::BoardRecord {
        let held = self.held();
        held.boards
            .get(&key)
            .map_or_else(|| Board::default().record(key), |b| b.record(key))
    }

    /// Any failure, unsynced included, changes nothing in memory.
    fn save_board(
        &self,
        key: BoardKey,
        rec: crate::board_store::BoardRecord,
    ) -> Result<(), BoardRefusal> {
        let plain = encode(&rec).map_err(store)?;
        self.blobs
            .save(&Name::Board(key).text(), &plain)
            .map_err(store)?;
        let mut held = self.held();
        let board = held.boards.entry(key).or_default();
        board.next_seq = rec.next_seq;
        board.settings = rec.settings;
        Ok(())
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The write path's own lock: held across I/O, never by a reader. Whoever takes it
    /// first retries every owed removal.
    fn writing(&self) -> std::sync::MutexGuard<'_, ()> {
        let w = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let owed: Vec<String> = self.held().owed.iter().cloned().collect();
        for name in owed {
            if self.blobs.delete(&name).is_ok() {
                self.held().owed.remove(&name);
            }
        }
        w
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_store::{labels_of, HeldFor, LabelValue, Report, BOARD, BOARD_RECORD_MAX};
    use crate::conversation::dir_store::DirBlobs;
    use crate::task_store::{encode, Fail, ManualClock, MemTaskBlobs, RootTasker};
    use maknae_io::Zeroizing;
    use maknae_proto::{Addressee, Attachment, Media, PostKind, SecretText, TaskId};
    use maknae_state::envelope::{WrappingKey, KEY_LEN};
    use std::os::unix::fs::PermissionsExt;

    const BOB: BoardKey = BoardKey(1000);
    const ALICE: BoardKey = BoardKey(1001);
    const T0: i64 = 1_800_000_000;
    const SMALL: Caps = Caps {
        board: 4,
        author: 3,
    };

    fn secret(s: &str) -> SecretText {
        SecretText(Zeroizing::new(s.into()))
    }

    fn draft(body: &str) -> PostDraft {
        PostDraft {
            kind: PostKind::Note,
            to: Addressee::Board,
            in_reply_to: None,
            body: secret(body),
            attachments: Vec::new(),
        }
    }

    fn reply(body: &str, to: PostId) -> PostDraft {
        PostDraft {
            in_reply_to: Some(to),
            ..draft(body)
        }
    }

    fn hobi() -> Author {
        Author::Agent("hobi".into())
    }

    fn jin() -> Author {
        Author::Agent("jin".into())
    }

    fn reader(s: &str) -> AgentId {
        AgentId::parse(s).unwrap()
    }

    fn open_mem(b: &MemTaskBlobs, caps: Caps) -> BoardStore {
        BoardStore::open_with(Box::new(b.clone()), Arc::new(ManualClock::at(T0)), caps).unwrap()
    }

    fn put(store: &BoardStore, key: BoardKey, author: Author, body: &str) -> Arc<Stored> {
        store
            .post(
                key,
                author,
                Some(2001),
                None,
                PostLabels::default(),
                draft(body),
            )
            .unwrap()
    }

    fn fixed(ids: Vec<[u8; 16]>) -> impl FnMut() -> Result<[u8; 16], BoardRefusal> {
        let mut ids = ids.into_iter();
        move || ids.next().ok_or(BoardRefusal::Random)
    }

    fn put_with(
        store: &BoardStore,
        ids: Vec<[u8; 16]>,
        body: &str,
    ) -> Result<Arc<Stored>, BoardRefusal> {
        store.post_with(
            &mut fixed(ids),
            BOB,
            hobi(),
            Some(2001),
            None,
            PostLabels::default(),
            draft(body),
        )
    }

    fn post_name(key: BoardKey, id: PostId) -> String {
        format!("post.{}.{id}", key.0)
    }

    fn plant(b: &MemTaskBlobs, key: BoardKey, stored: &Stored) {
        let rec = PostRecord {
            board: key.0,
            stored,
        };
        b.put(&post_name(key, stored.post.id), &encode(&rec).unwrap());
    }

    fn held_post(id: [u8; 16], seq: u64, author: Author) -> Stored {
        Stored {
            post: Post {
                id: PostId(id),
                author,
                task: None,
                at_secs: T0,
                labels: maknae_proto::Labels {},
                draft: draft("sentinel-695-held"),
            },
            seq,
            author_uid: Some(2001),
            labels: PostLabels::default(),
            held: [HeldFor::Author].into_iter().collect(),
        }
    }

    fn ids(posts: &[Arc<Stored>]) -> Vec<PostId> {
        posts.iter().map(|s| s.post.id).collect()
    }

    fn key() -> WrappingKey {
        WrappingKey::new(Zeroizing::new([9u8; KEY_LEN]))
    }

    fn tmp() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        t
    }

    fn open_dir(dir: &std::path::Path) -> Result<BoardStore, StoreError> {
        let uid = nix::unistd::geteuid().as_raw();
        let blobs = DirBlobs::open(dir, uid, key(), BOARD).unwrap();
        BoardStore::open(Box::new(blobs), Arc::new(ManualClock::at(T0)))
    }

    #[test]
    fn a_post_is_stored_sealed_and_survives_a_reopen() {
        const BODY: &str = "sentinel-695-body";
        let t = tmp();
        let store = open_dir(t.path()).unwrap();
        let task = TaskId([5; 16]);
        let mut labels = PostLabels::default();
        labels
            .0
            .insert("dcs.level".into(), LabelValue::Str("sentinel-695-l".into()));
        let posted = store
            .post(
                BOB,
                hobi(),
                Some(2001),
                Some(task),
                labels.clone(),
                draft(BODY),
            )
            .unwrap();
        assert_eq!(posted.post.at_secs, T0);
        assert_eq!(posted.post.author, hobi());
        drop(store);
        let mut files = 0;
        for entry in std::fs::read_dir(t.path()).unwrap() {
            let raw = std::fs::read(entry.unwrap().path()).unwrap();
            files += 1;
            assert!(!raw.windows(BODY.len()).any(|w| w == BODY.as_bytes()));
        }
        assert_eq!(files, 2);
        assert!(t
            .path()
            .join(format!("post.1000.{}.board", posted.post.id))
            .is_file());
        assert!(t.path().join("board.1000.board").is_file());
        let store = open_dir(t.path()).unwrap();
        assert!(store.take_boot_findings().is_empty());
        let back = store.get(BOB, posted.post.id).unwrap();
        assert_eq!(back.post.draft.body.0.as_str(), BODY);
        assert_eq!(
            (back.seq, back.author_uid, back.post.task, &back.labels),
            (posted.seq, Some(2001), Some(task), &labels)
        );
        assert_eq!(back.post.at_secs, T0);
        assert!(!format!("{back:?}").contains(BODY));
    }

    #[test]
    fn a_max_post_sealed_fits_the_record_bound_and_reloads() {
        let t = tmp();
        let store = open_dir(t.path()).unwrap();
        let first = put(&store, BOB, hobi(), "first");
        let content = 1000;
        let body_len = maknae_proto::BOARD_POST_MAX_BYTES - 8 * (64 + content);
        let attachments = (0..8u8)
            .map(|i| Attachment {
                label: format!("{i}{}", "l".repeat(63)),
                media: Media::TextDiff,
                content: secret(&"c".repeat(content)),
            })
            .collect();
        let to = (0..8u8).map(|i| format!("{}{i}", "a".repeat(31))).collect();
        let max = PostDraft {
            kind: PostKind::Question,
            to: Addressee::Agents(to),
            in_reply_to: Some(first.post.id),
            body: secret(&"b".repeat(body_len)),
            attachments,
        };
        assert_eq!(max.content_len(), maknae_proto::BOARD_POST_MAX_BYTES);
        let labels = PostLabels(
            (0..8u8)
                .map(|i| {
                    let set = (0..4u8).map(|j| format!("{}{j}", "v".repeat(31))).collect();
                    (format!("ns{i}.{}", "k".repeat(28)), LabelValue::Set(set))
                })
                .collect(),
        );
        let posted = store
            .post(
                BOB,
                hobi(),
                Some(2001),
                Some(TaskId([6; 16])),
                labels,
                max.clone(),
            )
            .unwrap();
        drop(store);
        let name = t.path().join(format!("post.1000.{}.board", posted.post.id));
        let len = std::fs::metadata(name).unwrap().len();
        assert!(len <= BOARD_RECORD_MAX, "{len}");
        let store = open_dir(t.path()).unwrap();
        assert!(store.take_boot_findings().is_empty());
        let back = store.get(BOB, posted.post.id).unwrap();
        assert!(back.post.draft == max);
        assert_eq!(back.labels, posted.labels);
        drop(store);
        let over = t
            .path()
            .join(format!("post.1000.{}.board", PostId([0xee; 16])));
        std::fs::write(&over, vec![0u8; BOARD_RECORD_MAX as usize + 1]).unwrap();
        std::fs::set_permissions(&over, std::fs::Permissions::from_mode(0o600)).unwrap();
        let store = open_dir(t.path()).unwrap();
        let found = store.take_boot_findings();
        assert_eq!(found.len(), 1);
        let BoardFinding::Quarantined { name, .. } = &found[0];
        assert_eq!(*name, format!("post.1000.{}", PostId([0xee; 16])));
        assert!(store.get(BOB, posted.post.id).is_some());
    }

    #[test]
    fn a_failed_sequence_write_refuses_and_changes_nothing() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        b.fail(Some(Fail::Unsynced));
        let refused = store.post(BOB, hobi(), None, None, PostLabels::default(), draft("x"));
        assert!(
            matches!(refused, Err(BoardRefusal::Store(_))),
            "{refused:?}"
        );
        assert!(refused.unwrap_err().to_string().starts_with("store: "));
        assert!(store.candidates(BOB, 0, 10).is_empty());
        b.fail(None);
        assert_eq!(put(&store, BOB, hobi(), "y").seq, 1);

        let full = MemTaskBlobs::default();
        full.put(
            "board.1000",
            &encode(&crate::board_store::BoardRecord {
                board: 1000,
                next_seq: u64::MAX,
                settings: Settings::default(),
            })
            .unwrap(),
        );
        let store = open_mem(&full, SMALL);
        let refused = store.post(BOB, hobi(), None, None, PostLabels::default(), draft("x"));
        assert_eq!(
            refused.unwrap_err(),
            BoardRefusal::Store("the sequence is exhausted".into())
        );
    }

    #[test]
    fn a_post_whose_write_does_not_sync_is_undone_and_refused() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let armed = b.clone();
        b.after_save(move || armed.fail(Some(Fail::UnsyncedOnce)));
        let refused = put_with(&store, vec![[1; 16]], "lost");
        assert!(
            matches!(refused, Err(BoardRefusal::Store(_))),
            "{refused:?}"
        );
        assert!(store.get(BOB, PostId([1; 16])).is_none());
        assert!(store.candidates(BOB, 0, 10).is_empty());
        b.crash(0);
        let store = open_mem(&b, SMALL);
        assert!(store.get(BOB, PostId([1; 16])).is_none());
        assert!(store.take_boot_findings().is_empty());
    }

    #[test]
    fn a_post_whose_undo_does_not_sync_is_outcome_unknown_and_owed() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let armed = b.clone();
        b.after_save(move || armed.fail(Some(Fail::Unsynced)));
        let refused = put_with(&store, vec![[1; 16]], "unknown");
        let Err(BoardRefusal::Unavailable(why)) = &refused else {
            panic!("{refused:?}");
        };
        assert!(why.starts_with("outcome unknown: "), "{why}");
        assert_eq!(refused.as_ref().unwrap_err().to_string(), *why);
        assert!(store.get(BOB, PostId([1; 16])).is_none());
        assert!(store.candidates(BOB, 0, 10).is_empty());
        b.crash(1);
        let name = post_name(BOB, PostId([1; 16]));
        assert!(b.has(&name));
        b.fail(Some(Fail::Unlinks));
        store.set_settings(BOB, Settings::default()).unwrap();
        assert!(b.has(&name));
        b.fail(None);
        let reopened = open_mem(&b, SMALL);
        assert_eq!(
            reopened
                .get(BOB, PostId([1; 16]))
                .unwrap()
                .post
                .draft
                .body
                .0
                .as_str(),
            "unknown"
        );
        drop(reopened);
        let next = put_with(&store, vec![[2; 16]], "next").unwrap();
        assert!(!b.has(&name));
        assert!(next.seq > 1);
        let reopened = open_mem(&b, SMALL);
        assert!(reopened.get(BOB, PostId([1; 16])).is_none());
    }

    #[test]
    fn a_crash_after_the_sequence_write_leaves_a_gap_and_loads() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let first = put(&store, BOB, hobi(), "one");
        let armed = b.clone();
        b.after_save(move || armed.fail(Some(Fail::Every)));
        let refused = put_with(&store, vec![[1; 16]], "lost");
        assert!(
            matches!(refused, Err(BoardRefusal::Store(_))),
            "{refused:?}"
        );
        assert!(matches!(
            BoardStore::open(Box::new(b.clone()), Arc::new(ManualClock::at(T0))),
            Err(StoreError::Io(_))
        ));
        b.fail(None);
        b.crash(0);
        let store = open_mem(&b, SMALL);
        assert!(store.take_boot_findings().is_empty());
        let next = put(&store, BOB, hobi(), "three");
        assert_eq!(next.seq, first.seq + 2);
        assert_eq!(
            ids(&store.candidates(BOB, 0, 10)),
            vec![first.post.id, next.post.id]
        );
    }

    #[test]
    fn a_colliding_post_id_is_redrawn() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        put_with(&store, vec![[1; 16]], "first").unwrap();
        let second = put_with(&store, vec![[1; 16], [2; 16]], "second").unwrap();
        assert_eq!(second.post.id, PostId([2; 16]));
        assert_eq!(
            store
                .get(BOB, PostId([1; 16]))
                .unwrap()
                .post
                .draft
                .body
                .0
                .as_str(),
            "first"
        );
        let mut draws = 0;
        let refused = store.post_with(
            &mut || {
                draws += 1;
                Ok([1; 16])
            },
            BOB,
            hobi(),
            None,
            None,
            PostLabels::default(),
            draft("third"),
        );
        assert_eq!(refused.unwrap_err(), BoardRefusal::Random);
        assert_eq!(draws, 4);
        assert_eq!(
            put_with(&store, Vec::new(), "no draw").unwrap_err(),
            BoardRefusal::Random
        );
        assert_eq!(store.candidates(BOB, 0, 10).len(), 2);
        assert_eq!(BoardRefusal::Random.to_string(), "no random id");
    }

    #[test]
    fn the_board_cap_refuses_and_evicts_nothing() {
        let b = MemTaskBlobs::default();
        plant(&b, BOB, &held_post([9; 16], 1, jin()));
        b.put(
            "board.1000",
            &encode(&crate::board_store::BoardRecord {
                board: 1000,
                next_seq: 2,
                settings: Settings::default(),
            })
            .unwrap(),
        );
        let store = open_mem(&b, SMALL);
        let posted: Vec<_> = (0..4)
            .map(|i| put(&store, BOB, [hobi(), jin()][i % 2].clone(), "p"))
            .collect();
        let refused = store.post(BOB, hobi(), None, None, PostLabels::default(), draft("x"));
        assert_eq!(refused.unwrap_err(), BoardRefusal::Full);
        assert_eq!(ids(&store.candidates(BOB, 0, 10)), ids(&posted));
        assert_eq!(BoardRefusal::Full.to_string(), "board full");
        put(&store, ALICE, hobi(), "elsewhere");
    }

    #[test]
    fn the_author_cap_refuses_one_author_only() {
        let b = MemTaskBlobs::default();
        plant(&b, BOB, &held_post([9; 16], 1, hobi()));
        b.put(
            "board.1000",
            &encode(&crate::board_store::BoardRecord {
                board: 1000,
                next_seq: 2,
                settings: Settings::default(),
            })
            .unwrap(),
        );
        let store = open_mem(&b, SMALL);
        put(&store, BOB, hobi(), "one");
        put(&store, BOB, hobi(), "two");
        let refused = store.post(BOB, hobi(), None, None, PostLabels::default(), draft("x"));
        assert_eq!(refused.unwrap_err(), BoardRefusal::AuthorAtCap);
        assert_eq!(BoardRefusal::AuthorAtCap.to_string(), "author at cap");
        put(&store, BOB, jin(), "jin");
        let tasker = Author::Tasker(1000);
        put(&store, BOB, tasker, "the tasker");
        assert_eq!(store.candidates(BOB, 0, 10).len(), 4);
    }

    #[test]
    fn a_reply_must_name_a_live_post_on_the_same_board() {
        let b = MemTaskBlobs::default();
        plant(&b, BOB, &held_post([9; 16], 1, jin()));
        b.put(
            "board.1000",
            &encode(&crate::board_store::BoardRecord {
                board: 1000,
                next_seq: 2,
                settings: Settings::default(),
            })
            .unwrap(),
        );
        let store = open_mem(
            &b,
            Caps {
                board: 16,
                author: 16,
            },
        );
        let root = put(&store, BOB, hobi(), "root");
        let elsewhere = put(&store, ALICE, hobi(), "alice");
        let answered = store
            .post(
                BOB,
                jin(),
                None,
                None,
                PostLabels::default(),
                reply("ok", root.post.id),
            )
            .unwrap();
        assert_eq!(answered.post.draft.in_reply_to, Some(root.post.id));
        for target in [PostId([7; 16]), PostId([9; 16]), elsewhere.post.id] {
            let refused = store.post(
                BOB,
                jin(),
                None,
                None,
                PostLabels::default(),
                reply("no", target),
            );
            assert_eq!(refused.unwrap_err(), BoardRefusal::NoSuchPost);
        }
        assert_eq!(
            BoardRefusal::NoSuchPost.to_string(),
            "in_reply_to names no post on the board"
        );
        assert_eq!(store.candidates(BOB, 0, 10).len(), 2);
    }

    #[test]
    fn candidates_are_in_order_above_the_given_sequence_and_limited() {
        let b = MemTaskBlobs::default();
        let store = open_mem(
            &b,
            Caps {
                board: 16,
                author: 16,
            },
        );
        let posted: Vec<_> = (0..5).map(|_| put(&store, BOB, hobi(), "p")).collect();
        assert_eq!(ids(&store.candidates(BOB, 0, 10)), ids(&posted));
        assert_eq!(
            ids(&store.candidates(BOB, posted[1].seq, 2)),
            ids(&posted[2..4])
        );
        assert!(store.candidates(BOB, posted[4].seq, 10).is_empty());
        assert!(store.candidates(BOB, 0, 0).is_empty());
        let seqs: Vec<u64> = posted.iter().map(|s| s.seq).collect();
        assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    }

    #[test]
    fn an_acknowledgement_moves_the_cursor_only_to_what_was_walked() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let posted: Vec<_> = (0..3).map(|_| put(&store, BOB, hobi(), "p")).collect();
        let r = reader("rm");
        let last = Some(posted[2].post.id);
        assert_eq!(
            store.plan_read(BOB, &r, last),
            ReadPlan {
                cursor: 0,
                ack_to: None
            }
        );
        store.walked(BOB, &r, posted[1].seq);
        assert_eq!(store.plan_read(BOB, &r, last).ack_to, Some(posted[1].seq));
        assert_eq!(
            store.plan_read(BOB, &r, Some(posted[0].post.id)).ack_to,
            Some(posted[0].seq)
        );
        assert_eq!(store.plan_read(BOB, &r, Some(PostId([7; 16]))).ack_to, None);
        assert_eq!(store.plan_read(BOB, &r, None).ack_to, None);
        assert_eq!(store.plan_read(BOB, &reader("suga"), last).ack_to, None);
        assert_eq!(store.advance(BOB, &r, posted[1].seq), Ok(posted[1].seq));
        assert_eq!(
            store.plan_read(BOB, &r, Some(posted[0].post.id)),
            ReadPlan {
                cursor: posted[1].seq,
                ack_to: None
            }
        );
        assert_eq!(store.plan_read(BOB, &r, last).ack_to, None);
    }

    #[test]
    fn walked_keeps_the_maximum() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let posted: Vec<_> = (0..3).map(|_| put(&store, BOB, hobi(), "p")).collect();
        let r = reader("rm");
        store.walked(BOB, &r, posted[1].seq);
        store.walked(BOB, &r, posted[0].seq);
        assert_eq!(
            store.plan_read(BOB, &r, Some(posted[2].post.id)).ack_to,
            Some(posted[1].seq)
        );
    }

    #[test]
    fn advance_is_durable_and_never_moves_backwards() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let posted: Vec<_> = (0..3).map(|_| put(&store, BOB, hobi(), "p")).collect();
        let r = reader("rm");
        assert_eq!(store.advance(BOB, &r, posted[1].seq), Ok(posted[1].seq));
        assert_eq!(store.advance(BOB, &r, posted[0].seq), Ok(posted[1].seq));
        assert_eq!(store.plan_read(BOB, &r, None).cursor, posted[1].seq);
        assert!(b.has("cursor.1000.rm"));
        let past = store.advance(BOB, &r, posted[2].seq + 1);
        assert!(matches!(past, Err(BoardRefusal::Store(_))), "{past:?}");
        b.fail(Some(Fail::Unsynced));
        let refused = store.advance(BOB, &r, posted[2].seq);
        assert!(
            matches!(refused, Err(BoardRefusal::Store(_))),
            "{refused:?}"
        );
        assert_eq!(store.plan_read(BOB, &r, None).cursor, posted[1].seq);
        b.fail(None);
        b.crash(0);
        let store = open_mem(&b, SMALL);
        assert_eq!(store.plan_read(BOB, &r, None).cursor, posted[1].seq);
        assert_eq!(store.plan_read(BOB, &reader("suga"), None).cursor, 0);
    }

    #[test]
    fn after_a_restart_an_acknowledgement_moves_nothing_until_posts_are_walked_again() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let posted: Vec<_> = (0..2).map(|_| put(&store, BOB, hobi(), "p")).collect();
        let r = reader("rm");
        store.walked(BOB, &r, posted[1].seq);
        assert_eq!(
            store.plan_read(BOB, &r, Some(posted[1].post.id)).ack_to,
            Some(posted[1].seq)
        );
        drop(store);
        let store = open_mem(&b, SMALL);
        assert_eq!(
            store.plan_read(BOB, &r, Some(posted[1].post.id)).ack_to,
            None
        );
        store.walked(BOB, &r, posted[1].seq);
        assert_eq!(
            store.plan_read(BOB, &r, Some(posted[1].post.id)).ack_to,
            Some(posted[1].seq)
        );
    }

    #[test]
    fn boards_do_not_see_each_other() {
        let store = BoardStore::new();
        let bob = put(&store, BOB, hobi(), "bob");
        let r = reader("rm");
        assert!(store.candidates(ALICE, 0, 10).is_empty());
        assert!(store.get(ALICE, bob.post.id).is_none());
        store.walked(ALICE, &r, bob.seq);
        assert_eq!(store.plan_read(ALICE, &r, Some(bob.post.id)).ack_to, None);
        let alice = put(&store, ALICE, hobi(), "alice");
        assert_eq!(alice.seq, bob.seq);
        assert_eq!(ids(&store.candidates(BOB, 0, 10)), vec![bob.post.id]);
        assert_eq!(ids(&store.candidates(ALICE, 0, 10)), vec![alice.post.id]);
        store
            .set_settings(
                ALICE,
                Settings {
                    enabled: true,
                    participate: true,
                    report: Report::Every,
                },
            )
            .unwrap();
        assert_eq!(store.settings(BOB), Settings::default());
    }

    #[test]
    fn settings_default_off_and_persist() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let off = store.settings(BOB);
        assert_eq!(
            (off.enabled, off.participate, off.report),
            (false, false, Report::Off)
        );
        let on = Settings {
            enabled: true,
            participate: false,
            report: Report::Summary,
        };
        let first = put(&store, BOB, hobi(), "before");
        store.set_settings(BOB, on).unwrap();
        assert_eq!(store.settings(BOB), on);
        let second = put(&store, BOB, hobi(), "after");
        assert_eq!(second.seq, first.seq + 1);
        b.fail(Some(Fail::Unsynced));
        let refused = store.set_settings(BOB, Settings::default());
        assert!(
            matches!(refused, Err(BoardRefusal::Store(_))),
            "{refused:?}"
        );
        assert_eq!(store.settings(BOB), on);
        b.fail(None);
        b.crash(0);
        let store = open_mem(&b, SMALL);
        assert_eq!(store.settings(BOB), on);
        assert_eq!(put(&store, BOB, hobi(), "third").seq, second.seq + 1);
        let fresh = open_mem(&MemTaskBlobs::default(), SMALL);
        fresh.set_settings(ALICE, on).unwrap();
        assert_eq!(put(&fresh, ALICE, hobi(), "x").seq, 1);
    }

    #[test]
    fn load_quarantines_what_it_cannot_read_and_refuses_a_sequence_behind_a_post() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let kept = put_with(&store, vec![[0x10; 16]], "kept").unwrap();
        let other = put_with(&store, vec![[0x20; 16]], "other").unwrap();
        let third = put_with(&store, vec![[0x30; 16]], "third").unwrap();
        store.advance(BOB, &reader("rm"), kept.seq).unwrap();
        drop(store);
        let moved = format!("post.01000.{}", third.post.id);
        b.put(&moved, &b.load(&post_name(BOB, third.post.id)).unwrap());
        b.delete(&post_name(BOB, third.post.id)).unwrap();
        let twin = post_name(BOB, PostId([0x40; 16]));
        let mut same_seq = held_post([0x40; 16], other.seq, hobi());
        same_seq.held.clear();
        plant(&b, BOB, &same_seq);
        let cursor = b.load("cursor.1000.rm").unwrap();
        b.put("cursor.1000.suga", &cursor);
        b.put("cursor.1001.rm", &cursor);
        let misnamed = post_name(BOB, PostId([3; 16]));
        b.put(&misnamed, &b.load(&post_name(BOB, other.post.id)).unwrap());
        let on_alice = post_name(ALICE, kept.post.id);
        b.put(&on_alice, &b.load(&post_name(BOB, kept.post.id)).unwrap());
        let garbage = post_name(BOB, PostId([4; 16]));
        b.put(&garbage, b"sentinel-695-not-cbor");
        b.put("post.01000.0", b"x");
        b.put("junk", b"x");
        b.put("board.1000.x", b"x");
        b.put("cursor.1000.Not-An-Agent", b"x");
        let store = open_mem(&b, SMALL);
        let mut found: Vec<String> = store
            .take_boot_findings()
            .into_iter()
            .map(|BoardFinding::Quarantined { name, .. }| name)
            .collect();
        found.sort();
        let mut want = vec![
            misnamed.clone(),
            on_alice.clone(),
            garbage.clone(),
            "post.01000.0".to_string(),
            "junk".to_string(),
            "board.1000.x".to_string(),
            "cursor.1000.Not-An-Agent".to_string(),
            moved.clone(),
            twin.clone(),
            "cursor.1000.suga".to_string(),
            "cursor.1001.rm".to_string(),
        ];
        want.sort();
        assert_eq!(found, want);
        assert_eq!(
            ids(&store.candidates(BOB, 0, 10)),
            vec![kept.post.id, other.post.id]
        );
        assert!(store.candidates(ALICE, 0, 10).is_empty());
        assert_eq!(
            store
                .get(BOB, other.post.id)
                .unwrap()
                .post
                .draft
                .body
                .0
                .as_str(),
            "other"
        );
        assert_eq!(store.plan_read(BOB, &reader("suga"), None).cursor, 0);
        assert_eq!(store.plan_read(BOB, &reader("rm"), None).cursor, kept.seq);
        assert_eq!(store.plan_read(ALICE, &reader("rm"), None).cursor, 0);
        for name in &want {
            store
                .settle(&BoardFinding::Quarantined {
                    name: name.clone(),
                    why: String::new(),
                })
                .unwrap();
        }
        let mut aside = b.aside();
        aside.sort();
        assert_eq!(aside, want);
        drop(store);

        let behind = |next_seq: u64| {
            b.put(
                "board.1000",
                &encode(&crate::board_store::BoardRecord {
                    board: 1000,
                    next_seq,
                    settings: Settings::default(),
                })
                .unwrap(),
            );
            BoardStore::open(Box::new(b.clone()), Arc::new(ManualClock::at(T0)))
        };
        assert!(matches!(behind(other.seq), Err(StoreError::Counters(_))));
        assert!(behind(third.seq + 1).is_ok());
        b.delete("board.1000").unwrap();
        assert!(matches!(
            BoardStore::open(Box::new(b.clone()), Arc::new(ManualClock::at(T0))),
            Err(StoreError::Counters(_))
        ));
        b.put(
            "board.1000",
            &encode(&crate::board_store::BoardRecord {
                board: 1001,
                next_seq: other.seq + 1,
                settings: Settings::default(),
            })
            .unwrap(),
        );
        assert!(matches!(
            BoardStore::open(Box::new(b.clone()), Arc::new(ManualClock::at(T0))),
            Err(StoreError::Counters(_))
        ));

        let cursors = MemTaskBlobs::default();
        let store = open_mem(&cursors, SMALL);
        let p = put(&store, BOB, hobi(), "p");
        store.advance(BOB, &reader("rm"), p.seq).unwrap();
        drop(store);
        cursors.delete(&post_name(BOB, p.post.id)).unwrap();
        assert!(open_mem(&cursors, SMALL).candidates(BOB, 0, 10).is_empty());
        cursors.delete("board.1000").unwrap();
        assert!(matches!(
            BoardStore::open(Box::new(cursors.clone()), Arc::new(ManualClock::at(T0))),
            Err(StoreError::Counters(_))
        ));

        let lone = MemTaskBlobs::default();
        lone.put("board.1000", b"sentinel-695-unreadable");
        let store = open_mem(&lone, SMALL);
        assert_eq!(store.settings(BOB), Settings::default());
        assert_eq!(store.take_boot_findings().len(), 1);
    }

    #[test]
    fn a_board_key_is_a_person_never_an_agent() {
        assert_eq!(BoardKey::of(&RootTasker::Person { uid: 1000 }), Some(BOB));
        assert_eq!(
            BoardKey::of(&RootTasker::Agent {
                agent: "hobi".into()
            }),
            None
        );
        assert_eq!(BOB.partition(), "users/1000");
    }

    #[test]
    fn labels_of_an_unlabelled_task_is_empty() {
        assert_eq!(labels_of(&maknae_proto::Labels {}), PostLabels::default());
        assert!(PostLabels::default().0.is_empty());
    }
}
