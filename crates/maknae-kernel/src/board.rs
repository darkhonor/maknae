//! The agent message board (#695, ADR-0040): one board per person, written through to
//! sealed records before memory shows any change.
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::{Arc, Mutex, PoisonError};

use maknae_config::AgentId;
use maknae_proto::{Author, Labels, Post, PostDraft, PostId, TaskId};

use crate::board_store::{
    load, Board, BoardFinding, BoardKey, CursorRecord, HeldFor, Name, PostLabels, PostRecord,
    ReadPlan, Settings, Stored, BOARD_OWED_MAX, BOARD_RETENTION, FIRST_SEQ,
};
use crate::enrollment::{EnrollmentView, Load};
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
    StillContained,
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
            BoardRefusal::StillContained => f.write_str("still contained"),
        }
    }
}

impl std::error::Error for BoardRefusal {}

/// [`BoardStore::observe`]'s answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Observed {
    pub live: BTreeSet<u64>,
    pub in_range: BTreeSet<u64>,
}

/// What one [`BoardStore::write_settings`] did: the settings before it, those memory holds
/// after it, and why it is not done, if it is not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Written {
    pub before: Settings,
    pub now: Settings,
    pub refused: Option<BoardRefusal>,
}

/// What [`BoardStore::clear`] removed, and why it stopped early, if it did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cleared {
    pub removed: Vec<PostId>,
    pub stopped: Option<BoardRefusal>,
}

/// What [`BoardStore::release`] did with a hold it lifted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifted {
    Done,
    /// The subject was found contained after the write; the hold is written back.
    Remarked,
}

fn store(e: StoreError) -> BoardRefusal {
    BoardRefusal::Store(e.to_string())
}

/// Why an item is due an act of the kernel's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BoardDueFor {
    Expire,
    Hold(HeldFor),
    DropCursor,
}

/// An expiry, a hold or a cursor removal the kernel records before the store performs it.
/// `recorded` is true once this process has recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoardDue {
    pub key: BoardKey,
    pub post: Option<PostId>,
    pub seq: Option<u64>,
    pub reader: Option<AgentId>,
    pub why: BoardDueFor,
    pub recorded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoardNotice {
    Settled { key: BoardKey, id: PostId },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Item {
    Post(BoardKey, u64, BoardDueFor),
    Cursor(BoardKey, AgentId),
}

#[derive(Default)]
struct Held {
    boards: BTreeMap<BoardKey, Board>,
    /// Post records whose removal did not sync: a post's undo, or a cleared post's unlink.
    owed: BTreeSet<(BoardKey, PostId)>,
    boot: Vec<BoardFinding>,
    /// Holds not yet stored, by board and sequence.
    marked: BTreeMap<(BoardKey, u64), BTreeSet<HeldFor>>,
    /// Cursors due removal: their reader is no longer enrolled.
    noted: BTreeSet<(BoardKey, AgentId)>,
    /// Posts whose expiry passed its check and whose delete is under way.
    expiring: BTreeSet<(BoardKey, u64)>,
    said: BTreeSet<Item>,
    notices: Vec<BoardNotice>,
    /// Notices taken for the trail and not yet returned.
    in_flight: usize,
}

impl Held {
    /// Held, marked for a hold, or in its expiry's delete.
    fn held_back(&self, key: BoardKey, s: &Stored) -> bool {
        !s.held.is_empty()
            || self.marked.contains_key(&(key, s.seq))
            || self.expiring.contains(&(key, s.seq))
    }

    /// Kept from every reader: held back, or past retention at `now`, swept or not.
    fn withheld(&self, key: BoardKey, s: &Stored, now: i64) -> bool {
        self.held_back(key, s) || expired(s, now)
    }

    fn live(&self, key: BoardKey, id: PostId, now: i64) -> Option<&Arc<Stored>> {
        let board = self.boards.get(&key)?;
        let seq = board.ids.get(&id)?;
        board.posts.get(seq).filter(|s| !self.withheld(key, s, now))
    }

    fn holds_of(&self, uid: u32) -> impl Iterator<Item = (BoardKey, PostId, u64, HeldFor)> + '_ {
        self.boards.iter().flat_map(move |(key, b)| {
            b.posts.values().flat_map(move |s| {
                s.held
                    .iter()
                    .filter(move |f| match f {
                        HeldFor::Author => s.author_uid == Some(uid),
                        HeldFor::Person => key.0 == uid,
                    })
                    .map(move |f| (*key, s.post.id, s.seq, *f))
            })
        })
    }

    fn at(&self, key: BoardKey, seq: u64, id: Option<PostId>) -> Option<&Arc<Stored>> {
        let s = self.boards.get(&key)?.posts.get(&seq)?;
        (Some(s.post.id) == id).then_some(s)
    }

    /// Removals owed, and notices not yet recorded: what `BOARD_OWED_MAX` bounds.
    fn owing(&self) -> usize {
        self.owed
            .len()
            .saturating_add(self.notices.len())
            .saturating_add(self.in_flight)
    }

    /// The record name of the post at `seq` with `id`, noted expiring, when `due` holds for
    /// it, it is not held back, and `view` contains neither its author nor `key`'s person.
    /// A post `view` contains is marked for its holds instead.
    fn claim(
        &mut self,
        key: BoardKey,
        seq: u64,
        id: Option<PostId>,
        view: &dyn EnrollmentView,
        due: impl FnOnce(&Stored) -> bool,
    ) -> Option<String> {
        let (name, author_uid) = self
            .at(key, seq, id)
            .filter(|s| !self.held_back(key, s) && due(s))
            .map(|s| (Name::Post(key, s.post.id).text(), s.author_uid))?;
        let contained = contained_on(view, key, std::iter::once(author_uid));
        let why = contained_for(key, author_uid, &contained);
        if !why.is_empty() {
            self.marked.entry((key, seq)).or_default().extend(why);
            return None;
        }
        self.expiring.insert((key, seq));
        Some(name)
    }

    /// The post at `seq` when it is now marked, or `view` now contains its author or `key`'s
    /// person, in which case it is marked for those holds.
    fn contained_since(
        &mut self,
        key: BoardKey,
        seq: u64,
        view: &dyn EnrollmentView,
    ) -> Option<Arc<Stored>> {
        let s = Arc::clone(self.boards.get(&key)?.posts.get(&seq)?);
        let contained = contained_on(view, key, std::iter::once(s.author_uid));
        let why = contained_for(key, s.author_uid, &contained);
        if !why.is_empty() {
            self.marked.entry((key, seq)).or_default().extend(why);
        }
        self.marked.contains_key(&(key, seq)).then_some(s)
    }

    /// See [`BoardStore::mark`].
    fn mark(&mut self, view: &dyn EnrollmentView) {
        let held = self;
        let uids: BTreeSet<u32> = held
            .boards
            .iter()
            .flat_map(|(key, b)| {
                std::iter::once(key.0).chain(b.posts.values().filter_map(|s| s.author_uid))
            })
            .collect();
        let among = view.contained_among(&uids);
        let contained = |uid: u32| among.contains(&uid);
        let mut marked = BTreeMap::new();
        for (key, board) in &held.boards {
            let person = contained(key.0);
            for (seq, s) in &board.posts {
                let mut why = BTreeSet::new();
                if s.author_uid.is_some_and(contained) && !s.held.contains(&HeldFor::Author) {
                    why.insert(HeldFor::Author);
                }
                if person && !s.held.contains(&HeldFor::Person) {
                    why.insert(HeldFor::Person);
                }
                if !why.is_empty() {
                    marked.insert((*key, *seq), why);
                }
            }
        }
        held.said.retain(|item| match item {
            Item::Post(key, seq, BoardDueFor::Hold(f)) => {
                marked.get(&(*key, *seq)).is_some_and(|w| w.contains(f))
            }
            Item::Post(_, _, BoardDueFor::Expire | BoardDueFor::DropCursor) | Item::Cursor(..) => {
                true
            }
        });
        held.marked = marked;

        let gone: BTreeSet<AgentId> = held
            .boards
            .values()
            .flat_map(|b| b.cursors.keys().chain(b.sent.keys()))
            .filter(|agent| view.agent_uid(agent).is_none())
            .cloned()
            .collect();
        for board in held.boards.values_mut() {
            board.sent.retain(|agent, _| !gone.contains(agent));
        }
        held.noted = held
            .boards
            .iter()
            .flat_map(|(key, b)| {
                b.cursors
                    .keys()
                    .filter(|a| gone.contains(*a))
                    .map(|a| (*key, a.clone()))
            })
            .collect();
        let noted = &held.noted;
        held.said.retain(|item| match item {
            Item::Cursor(key, reader) => noted.contains(&(*key, reader.clone())),
            Item::Post(..) => true,
        });
    }

    /// Forgets the post at `seq` once its record is deleted.
    fn forget(&mut self, key: BoardKey, seq: u64) {
        if let Some(board) = self.boards.get_mut(&key) {
            if let Some(gone) = board.posts.remove(&seq) {
                board.ids.remove(&gone.post.id);
            }
            for sent in board.sent.values_mut() {
                sent.remove(&seq);
            }
            board.sent.retain(|_, sent| !sent.is_empty());
        }
        self.marked.remove(&(key, seq));
        self.said
            .retain(|i| !matches!(i, Item::Post(k, s, _) if (*k, *s) == (key, seq)));
    }
}

/// Clears an `expiring` entry if `expire` unwinds before it clears the entry itself.
struct Expiring<'a> {
    store: &'a BoardStore,
    at: (BoardKey, u64),
    armed: bool,
}

impl Drop for Expiring<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.store.held().expiring.remove(&self.at);
        }
    }
}

/// What [`BoardStore::unlink_claimed`] left of a claimed post.
enum After<'a> {
    /// Neither marked nor contained since its claim: the caller acts on the delete's result.
    Unlinked(std::sync::MutexGuard<'a, Held>, Result<(), StoreError>),
    /// Kept in memory, marked, its record written back.
    Kept,
    /// Kept in memory and marked, its record not written back.
    NotRestored(StoreError),
}

enum Step {
    Skipped,
    Done,
    Refused,
}

/// The holds `contained` (one answer from the view) calls for on a post by `author_uid`
/// on `key`'s board.
fn contained_for(
    key: BoardKey,
    author_uid: Option<u32>,
    contained: &BTreeSet<u32>,
) -> BTreeSet<HeldFor> {
    let mut why = BTreeSet::new();
    if author_uid.is_some_and(|uid| contained.contains(&uid)) {
        why.insert(HeldFor::Author);
    }
    if contained.contains(&key.0) {
        why.insert(HeldFor::Person);
    }
    why
}

/// The uids among `key`'s person and `authors` that `view` contains, from one answer.
fn contained_on(
    view: &dyn EnrollmentView,
    key: BoardKey,
    authors: impl Iterator<Item = Option<u32>>,
) -> BTreeSet<u32> {
    let uids: BTreeSet<u32> = std::iter::once(key.0).chain(authors.flatten()).collect();
    view.contained_among(&uids)
}

fn expired(s: &Stored, now: i64) -> bool {
    s.post
        .at_secs
        .saturating_add(BOARD_RETENTION.as_secs() as i64)
        <= now
}

/// Posts, settings and cursors, written through to `blobs` before any change is visible in
/// memory. Every change is serialized by `writer`; `held` is locked only to read and to
/// swap, never across I/O.
pub struct BoardStore {
    held: Mutex<Held>,
    writer: Mutex<()>,
    blobs: Box<dyn TaskBlobs>,
    clock: Arc<dyn Clock>,
    /// The highest time this store has read, so that its now never runs backwards.
    seen: std::sync::atomic::AtomicI64,
    caps: Caps,
    #[cfg(any(test, feature = "hermetic-test-seam"))]
    after_settings: Mutex<Option<SettingsHook>>,
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
type SettingsHook = Box<dyn FnOnce(&BoardStore) + Send>;

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
                boot: loaded.findings,
                ..Held::default()
            }),
            writer: Mutex::new(()),
            blobs,
            clock,
            seen: std::sync::atomic::AtomicI64::new(i64::MIN),
            caps,
            #[cfg(any(test, feature = "hermetic-test-seam"))]
            after_settings: Mutex::new(None),
        })
    }

    /// The clock's reading, or the highest one this store has read before.
    fn now(&self) -> i64 {
        let read = self.clock.now_secs();
        self.seen
            .fetch_max(read, std::sync::atomic::Ordering::SeqCst)
            .max(read)
    }

    pub fn take_boot_findings(&self) -> Vec<BoardFinding> {
        std::mem::take(&mut self.held().boot)
    }

    pub fn settle(&self, finding: &BoardFinding) -> Result<(), StoreError> {
        match finding {
            BoardFinding::Quarantined { name, .. } => self.blobs.quarantine(name),
        }
    }

    /// `agent` and whether the tasker's board is enabled, read in one hold of the memory
    /// lock. `agent` reads only what an install swaps under that lock.
    pub(crate) fn enabled_with<T>(&self, key: BoardKey, agent: impl FnOnce() -> T) -> (T, bool) {
        let held = self.held();
        let agent = agent();
        (
            agent,
            held.boards.get(&key).is_some_and(|b| b.settings.enabled),
        )
    }

    /// Whether `view`'s installed load is still `load`, read under the memory lock.
    pub(crate) fn still_installed(&self, load: &Load, view: &dyn EnrollmentView) -> bool {
        let _held = self.held();
        view.load() == *load
    }

    pub fn settings(&self, key: BoardKey) -> Settings {
        self.held()
            .boards
            .get(&key)
            .map_or_else(Settings::default, |b| b.settings)
    }

    /// Writes `settings`: the settings before, those memory holds after, and why the write
    /// is not done, if it is not. A write that does not sync leaves memory with `enabled` on
    /// only where both values have it on, and the old `report`.
    pub(crate) fn write_settings(&self, key: BoardKey, settings: Settings) -> Written {
        let written = self.write_settings_alone(key, settings);
        #[cfg(any(test, feature = "hermetic-test-seam"))]
        {
            let then = self
                .after_settings
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(then) = then {
                then(self);
            }
        }
        written
    }

    fn write_settings_alone(&self, key: BoardKey, settings: Settings) -> Written {
        let _w = self.writing();
        let mut rec = self.board_record(key);
        let before = rec.settings;
        rec.settings = settings;
        match self.save_board(key, rec) {
            Ok(()) => Written {
                before,
                now: settings,
                refused: None,
            },
            Err(StoreError::NotDurable(why)) => {
                let now = Settings {
                    enabled: before.enabled && settings.enabled,
                    report: before.report,
                };
                self.held().boards.entry(key).or_default().settings = now;
                Written {
                    before,
                    now,
                    refused: Some(BoardRefusal::Unavailable(format!("{OUTCOME_UNKNOWN}{why}"))),
                }
            }
            Err(e @ (StoreError::Io(_) | StoreError::Counters(_))) => Written {
                before,
                now: before,
                refused: Some(store(e)),
            },
        }
    }

    /// [`Self::write_settings`], answering the settings before it.
    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub(crate) fn set_settings(
        &self,
        key: BoardKey,
        settings: Settings,
    ) -> Result<Settings, BoardRefusal> {
        let written = self.write_settings(key, settings);
        match written.refused {
            None => Ok(written.before),
            Some(why) => Err(why),
        }
    }

    /// Runs `then` once, after the next settings write has returned its writer.
    #[cfg(any(test, feature = "hermetic-test-seam"))]
    pub fn after_settings_write(&self, then: impl FnOnce(&BoardStore) + Send + 'static) {
        *self
            .after_settings
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(then));
    }

    /// `by` is the author and its uid. A post whose author uid or whose board's uid `view`
    /// holds contained is stored marked for a hold, as [`Self::mark`] would mark it.
    pub fn post(
        &self,
        key: BoardKey,
        by: (Author, Option<u32>),
        task: Option<TaskId>,
        labels: PostLabels,
        draft: PostDraft,
        view: &dyn EnrollmentView,
    ) -> Result<Arc<Stored>, BoardRefusal> {
        let mut draw = || draw_id().map_err(|_| BoardRefusal::Random);
        self.place(&mut draw, key, by, task, labels, draft, view)
    }

    #[cfg(any(test, feature = "hermetic-test-seam"))]
    #[allow(clippy::too_many_arguments)]
    pub fn post_with(
        &self,
        draw: &mut dyn FnMut() -> Result<[u8; 16], BoardRefusal>,
        key: BoardKey,
        by: (Author, Option<u32>),
        task: Option<TaskId>,
        labels: PostLabels,
        draft: PostDraft,
        view: &dyn EnrollmentView,
    ) -> Result<Arc<Stored>, BoardRefusal> {
        self.place(draw, key, by, task, labels, draft, view)
    }

    pub fn get(&self, key: BoardKey, id: PostId) -> Option<Arc<Stored>> {
        let held = self.held();
        let now = self.now();
        held.live(key, id, now).cloned()
    }

    /// Those of `seqs` that are on the board, not withheld, and whose author and person
    /// `view` does not contain, now.
    #[cfg(test)]
    pub(crate) fn still_live(
        &self,
        key: BoardKey,
        seqs: &[u64],
        view: &dyn EnrollmentView,
    ) -> BTreeSet<u64> {
        self.observe(key, seqs, (0, 0), view).live
    }

    /// One observation, in one hold of the memory lock with one time and one answer from
    /// `view`: which of `seqs` are live, and every live sequence in `(lo, hi]`.
    pub(crate) fn observe(
        &self,
        key: BoardKey,
        seqs: &[u64],
        (lo, hi): (u64, u64),
        view: &dyn EnrollmentView,
    ) -> Observed {
        let held = self.held();
        let now = self.now();
        let Some(board) = held.boards.get(&key) else {
            return Observed::default();
        };
        let listed: Vec<&Arc<Stored>> =
            seqs.iter().filter_map(|seq| board.posts.get(seq)).collect();
        let ranged: Vec<&Arc<Stored>> = board
            .posts
            .range((Bound::Excluded(lo), Bound::Included(hi.max(lo))))
            .map(|(_, s)| s)
            .collect();
        let contained = contained_on(
            view,
            key,
            listed.iter().chain(&ranged).map(|s| s.author_uid),
        );
        let alive = |s: &&Arc<Stored>| {
            !held.withheld(key, s, now) && contained_for(key, s.author_uid, &contained).is_empty()
        };
        Observed {
            live: listed.into_iter().filter(alive).map(|s| s.seq).collect(),
            in_range: ranged.into_iter().filter(alive).map(|s| s.seq).collect(),
        }
    }

    /// An acknowledgement moves the cursor to `seen_through` only when that post was sent to
    /// `reader` and is not past retention. A sent set holds only posts above the cursor.
    pub fn plan_read(
        &self,
        key: BoardKey,
        reader: &AgentId,
        seen_through: Option<PostId>,
    ) -> ReadPlan {
        let held = self.held();
        let now = self.now();
        let board = held.boards.get(&key);
        let cursor = board
            .and_then(|b| b.cursors.get(reader))
            .copied()
            .unwrap_or(0);
        let ack_to = seen_through.and_then(|id| {
            let board = board?;
            let seq = *board.ids.get(&id)?;
            let current = board.posts.get(&seq).is_some_and(|s| !expired(s, now));
            let sent = board.sent.get(reader)?.contains(&seq);
            (sent && current).then_some(seq)
        });
        let upper = board
            .and_then(|b| b.posts.last_key_value())
            .map_or(cursor, |(seq, _)| *seq);
        ReadPlan {
            cursor,
            ack_to,
            upper,
        }
    }

    /// Moves `reader`'s cursor to `to` for an acknowledgement, checked again under the
    /// writer as `plan_read` checked it: `to` is a post on the board, sent to `reader` (so
    /// above its cursor) and not past retention. Otherwise nothing moves and the cursor is
    /// returned.
    pub fn acknowledge(
        &self,
        key: BoardKey,
        reader: &AgentId,
        to: u64,
    ) -> Result<u64, BoardRefusal> {
        let _w = self.writing();
        let (cursor, still) = {
            let held = self.held();
            let now = self.now();
            let board = held.boards.get(&key);
            let cursor = board
                .and_then(|b| b.cursors.get(reader))
                .copied()
                .unwrap_or(0);
            let still = board.is_some_and(|b| {
                b.posts.get(&to).is_some_and(|s| !expired(s, now))
                    && b.sent.get(reader).is_some_and(|sent| sent.contains(&to))
            });
            (cursor, still)
        };
        if !still {
            return Ok(cursor);
        }
        self.move_cursor(key, reader, to)
    }

    pub fn advance(&self, key: BoardKey, reader: &AgentId, to: u64) -> Result<u64, BoardRefusal> {
        let _w = self.writing();
        self.move_cursor(key, reader, to)
    }

    /// Writes `reader`'s cursor `to`, never backwards; the caller holds the writer.
    fn move_cursor(&self, key: BoardKey, reader: &AgentId, to: u64) -> Result<u64, BoardRefusal> {
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
        let mut held = self.held();
        let board = held.boards.entry(key).or_default();
        board.cursors.insert(reader.clone(), to);
        if let Some(sent) = board.sent.get_mut(reader) {
            sent.retain(|seq| *seq > to);
            if sent.is_empty() {
                board.sent.remove(reader);
            }
        }
        Ok(to)
    }

    pub fn candidates(&self, key: BoardKey, after: u64, limit: usize) -> Vec<Arc<Stored>> {
        let held = self.held();
        let now = self.now();
        let Some(board) = held.boards.get(&key) else {
            return Vec::new();
        };
        board
            .posts
            .range((Bound::Excluded(after), Bound::Unbounded))
            .map(|(_, s)| s)
            .filter(|s| !held.withheld(key, s, now))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Without the writer and without I/O: marks for a hold each post whose recorded author
    /// uid, or whose board's uid, the view holds contained, dropping any mark it no longer
    /// bears out; and notes each cursor, and forgets each walk, of a reader it no longer
    /// enrolls.
    pub(crate) fn mark(&self, view: &dyn EnrollmentView) {
        self.held().mark(view);
    }

    /// Runs `install` and then [`Self::mark`] against it, in one hold of the memory lock, so
    /// a check made under that lock sees the install with its marks or neither. `install`
    /// swaps what `view` reads; it must not block, do I/O or take a board lock.
    pub(crate) fn install_and_mark(&self, install: impl FnOnce(), view: &dyn EnrollmentView) {
        let mut held = self.held();
        install();
        held.mark(view);
    }

    /// What is due, at most `limit`, from memory only: marked holds, then posts past
    /// retention that are neither held nor marked, then noted cursors.
    pub(crate) fn due(&self, limit: usize) -> Vec<BoardDue> {
        let guard = self.held();
        let now = self.now();
        let held = &*guard;
        let holds = held
            .marked
            .iter()
            .filter(|(at, _)| !held.expiring.contains(at))
            .flat_map(|((key, seq), fors)| {
                let id = held
                    .boards
                    .get(key)
                    .and_then(|b| b.posts.get(seq))
                    .map(|s| s.post.id);
                fors.iter().filter_map(move |f| {
                    let why = BoardDueFor::Hold(*f);
                    Some(BoardDue {
                        key: *key,
                        post: Some(id?),
                        seq: Some(*seq),
                        reader: None,
                        why,
                        recorded: held.said.contains(&Item::Post(*key, *seq, why)),
                    })
                })
            });
        let expiries = held.boards.iter().flat_map(|(key, b)| {
            b.posts
                .values()
                .filter(|s| !held.held_back(*key, s) && expired(s, now))
                .map(|s| BoardDue {
                    key: *key,
                    post: Some(s.post.id),
                    seq: Some(s.seq),
                    reader: None,
                    why: BoardDueFor::Expire,
                    recorded: held
                        .said
                        .contains(&Item::Post(*key, s.seq, BoardDueFor::Expire)),
                })
        });
        let cursors = held.noted.iter().map(|(key, reader)| BoardDue {
            key: *key,
            post: None,
            seq: None,
            reader: Some(reader.clone()),
            why: BoardDueFor::DropCursor,
            recorded: held.said.contains(&Item::Cursor(*key, reader.clone())),
        });
        holds.chain(expiries).chain(cursors).take(limit).collect()
    }

    /// Performs what the kernel has recorded: each item still due is written until the disk
    /// first refuses; memory follows only a synced write. The count is of those done.
    pub(crate) fn perform(&self, due: &[BoardDue], view: &dyn EnrollmentView) -> usize {
        let _w = self.writing();
        let mut done = 0;
        for d in due {
            let step = match (d.why, d.seq, &d.reader) {
                (BoardDueFor::Expire, Some(seq), _) => self.expire(d.key, seq, d.post, view),
                (BoardDueFor::Hold(f), Some(seq), _) => self.hold(d.key, seq, d.post, f),
                (BoardDueFor::DropCursor, _, Some(reader)) => self.drop_cursor(d.key, reader, view),
                (BoardDueFor::Expire | BoardDueFor::Hold(_), None, _)
                | (BoardDueFor::DropCursor, _, None) => Step::Skipped,
            };
            match step {
                Step::Skipped => {}
                Step::Done => done += 1,
                Step::Refused => break,
            }
        }
        done
    }

    fn expire(
        &self,
        key: BoardKey,
        seq: u64,
        id: Option<PostId>,
        view: &dyn EnrollmentView,
    ) -> Step {
        let item = Item::Post(key, seq, BoardDueFor::Expire);
        let name = {
            let mut held = self.held();
            let now = self.now();
            let Some(name) = held.claim(key, seq, id, view, |s| expired(s, now)) else {
                held.said.remove(&item);
                return Step::Skipped;
            };
            held.said.insert(item.clone());
            name
        };
        match self.unlink_claimed(key, seq, &name, view) {
            After::Unlinked(mut held, Ok(())) => {
                held.forget(key, seq);
                Step::Done
            }
            After::Unlinked(
                _,
                Err(StoreError::Io(_) | StoreError::NotDurable(_) | StoreError::Counters(_)),
            ) => Step::Refused,
            After::Kept => {
                self.held().said.remove(&item);
                Step::Skipped
            }
            After::NotRestored(_) => {
                self.held().said.remove(&item);
                Step::Refused
            }
        }
    }

    /// [`Self::delete_claimed`], then the re-check: a post now marked, or whose author or
    /// person `view` now contains, is kept in memory, marked, and its record written back.
    fn unlink_claimed(
        &self,
        key: BoardKey,
        seq: u64,
        name: &str,
        view: &dyn EnrollmentView,
    ) -> After<'_> {
        let (mut held, deleted) = self.delete_claimed(key, seq, name);
        let kept = match &deleted {
            Ok(()) | Err(StoreError::NotDurable(_)) => held.contained_since(key, seq, view),
            Err(StoreError::Io(_) | StoreError::Counters(_)) => None,
        };
        let Some(kept) = kept else {
            return After::Unlinked(held, deleted);
        };
        drop(held);
        match self.restore(key, &kept) {
            Ok(()) => After::Kept,
            Err(why) => After::NotRestored(why),
        }
    }

    /// Deletes the record `name` that [`Held::claim`] returned for `seq`, then ends the
    /// claim; the caller decides what memory follows, under the guard returned.
    fn delete_claimed(
        &self,
        key: BoardKey,
        seq: u64,
        name: &str,
    ) -> (std::sync::MutexGuard<'_, Held>, Result<(), StoreError>) {
        let mut marker = Expiring {
            store: self,
            at: (key, seq),
            armed: true,
        };
        let deleted = self.blobs.delete(name);
        let mut held = self.held();
        held.expiring.remove(&(key, seq));
        marker.armed = false;
        (held, deleted)
    }

    /// Writes back the record of a post kept in memory after its delete.
    fn restore(&self, key: BoardKey, kept: &Stored) -> Result<(), StoreError> {
        let plain = encode(&PostRecord {
            board: key.0,
            stored: kept,
        })?;
        self.blobs
            .save(&Name::Post(key, kept.post.id).text(), &plain)
    }

    /// Memory only: up to `BOARD_CLEAR_PAGE` posts of `key`'s board that are not withheld,
    /// lowest sequence first, and whether more remain.
    pub(crate) fn clearable(&self, key: BoardKey) -> (Vec<(u64, PostId)>, bool) {
        let held = self.held();
        let now = self.now();
        let Some(board) = held.boards.get(&key) else {
            return (Vec::new(), false);
        };
        let mut open = board
            .posts
            .values()
            .filter(|s| !held.withheld(key, s, now))
            .map(|s| (s.seq, s.post.id));
        let page: Vec<(u64, PostId)> = open
            .by_ref()
            .take(crate::board_store::BOARD_CLEAR_PAGE)
            .collect();
        let more = open.next().is_some();
        (page, more)
    }

    /// Under the writer: removes each of `posts` that is still on `key`'s board at that
    /// sequence, not withheld, and whose author and person `view` does not contain; a post
    /// `view` contains is marked for its holds instead. Takes at most `BOARD_CLEAR_PAGE`.
    /// A post found marked or contained after its delete is kept and its record written
    /// back. Stops at the first delete, or write-back, that fails.
    pub(crate) fn clear(
        &self,
        key: BoardKey,
        posts: &[(u64, PostId)],
        view: &dyn EnrollmentView,
    ) -> Cleared {
        let _w = self.writing();
        let mut cleared = Cleared {
            removed: Vec::new(),
            stopped: None,
        };
        if self.held().owing() >= BOARD_OWED_MAX {
            cleared.stopped = Some(BoardRefusal::Store("removals are owed".into()));
            return cleared;
        }
        for &(seq, id) in posts.iter().take(crate::board_store::BOARD_CLEAR_PAGE) {
            let name = {
                let mut held = self.held();
                let now = self.now();
                let Some(name) = held.claim(key, seq, Some(id), view, |s| !expired(s, now)) else {
                    continue;
                };
                name
            };
            let (mut held, deleted) = match self.unlink_claimed(key, seq, &name, view) {
                After::Unlinked(held, deleted) => (held, deleted),
                After::Kept => continue,
                After::NotRestored(why) => {
                    cleared.stopped = Some(BoardRefusal::Unavailable(format!(
                        "{OUTCOME_UNKNOWN}contained during the clear; the record is not restored: {why}"
                    )));
                    break;
                }
            };
            match deleted {
                Ok(()) => {
                    held.forget(key, seq);
                    cleared.removed.push(id);
                }
                Err(StoreError::NotDurable(why)) => {
                    held.forget(key, seq);
                    held.owed.insert((key, id));
                    cleared.removed.push(id);
                    cleared.stopped =
                        Some(BoardRefusal::Unavailable(format!("{OUTCOME_UNKNOWN}{why}")));
                    break;
                }
                Err(e @ (StoreError::Io(_) | StoreError::Counters(_))) => {
                    cleared.stopped = Some(store(e));
                    break;
                }
            }
        }
        cleared
    }

    fn hold(&self, key: BoardKey, seq: u64, id: Option<PostId>, f: HeldFor) -> Step {
        let item = Item::Post(key, seq, BoardDueFor::Hold(f));
        let prior = {
            let mut held = self.held();
            let marked = held.marked.get(&(key, seq)).is_some_and(|w| w.contains(&f));
            let Some(prior) = held.at(key, seq, id).filter(|_| marked).cloned() else {
                held.said.remove(&item);
                return Step::Skipped;
            };
            held.said.insert(item.clone());
            prior
        };
        let mut next = Stored::clone(&prior);
        next.held.insert(f);
        let Ok(plain) = encode(&PostRecord {
            board: key.0,
            stored: &next,
        }) else {
            return Step::Refused;
        };
        if self
            .blobs
            .save(&Name::Post(key, next.post.id).text(), &plain)
            .is_err()
        {
            return Step::Refused;
        }
        let mut held = self.held();
        if let Some(board) = held.boards.get_mut(&key) {
            board.posts.insert(seq, Arc::new(next));
        }
        if let Some(why) = held.marked.get_mut(&(key, seq)) {
            why.remove(&f);
            if why.is_empty() {
                held.marked.remove(&(key, seq));
            }
        }
        held.said.remove(&item);
        Step::Done
    }

    fn drop_cursor(&self, key: BoardKey, reader: &AgentId, view: &dyn EnrollmentView) -> Step {
        let item = Item::Cursor(key, reader.clone());
        let noted = (key, reader.clone());
        {
            let mut held = self.held();
            if !held.noted.contains(&noted) || view.agent_uid(reader).is_some() {
                held.noted.remove(&noted);
                held.said.remove(&item);
                return Step::Skipped;
            }
            held.said.insert(item.clone());
        }
        if self
            .blobs
            .delete(&Name::Cursor(key, reader.clone()).text())
            .is_err()
        {
            return Step::Refused;
        }
        let mut held = self.held();
        if let Some(board) = held.boards.get_mut(&key) {
            board.cursors.remove(reader);
            board.sent.remove(reader);
        }
        held.noted.remove(&noted);
        held.said.remove(&item);
        Step::Done
    }

    /// The written holds for `uid`: as a post's recorded author, and as the person whose
    /// board it is; in board, sequence and hold order.
    pub fn held_for(&self, uid: u32, limit: usize) -> Vec<(BoardKey, PostId, u64, HeldFor)> {
        self.held().holds_of(uid).take(limit).collect()
    }

    pub fn held_count(&self, uid: u32) -> usize {
        self.held().holds_of(uid).count()
    }

    /// Lifts one written hold unless `view` holds its subject contained.
    pub(crate) fn release(
        &self,
        key: BoardKey,
        id: PostId,
        lifted: HeldFor,
        view: &dyn EnrollmentView,
    ) -> Result<Lifted, BoardRefusal> {
        let _w = self.writing();
        let prior = {
            let held = self.held();
            let board = held.boards.get(&key);
            board
                .and_then(|b| b.posts.get(b.ids.get(&id)?))
                .filter(|s| s.held.contains(&lifted))
                .cloned()
        };
        let Some(prior) = prior else {
            return Err(BoardRefusal::Store("the post is not held for that".into()));
        };
        let subject = match lifted {
            HeldFor::Author => prior.author_uid,
            HeldFor::Person => Some(key.0),
        };
        if subject.is_some_and(|uid| view.contained(uid)) {
            return Err(BoardRefusal::StillContained);
        }
        let mut next = Stored::clone(&prior);
        next.held.remove(&lifted);
        let plain = encode(&PostRecord {
            board: key.0,
            stored: &next,
        })
        .map_err(store)?;
        match self.blobs.save(&Name::Post(key, id).text(), &plain) {
            Ok(()) => {}
            Err(StoreError::NotDurable(why)) => {
                return Err(BoardRefusal::Unavailable(format!("{OUTCOME_UNKNOWN}{why}")))
            }
            Err(e @ (StoreError::Io(_) | StoreError::Counters(_))) => return Err(store(e)),
        }
        let next = Arc::new(next);
        let seq = next.seq;
        {
            let mut held = self.held();
            if let Some(board) = held.boards.get_mut(&key) {
                board.posts.insert(seq, Arc::clone(&next));
            }
            // A containment installed since the check is marked here, so `mark` cannot miss it.
            if !subject.is_some_and(|uid| view.contained(uid)) {
                return Ok(Lifted::Done);
            }
            held.marked.entry((key, seq)).or_default().insert(lifted);
        }
        let restored = encode(&PostRecord {
            board: key.0,
            stored: &*prior,
        })
        .map_err(store)
        .and_then(|plain| {
            self.blobs
                .save(&Name::Post(key, id).text(), &plain)
                .map_err(store)
        });
        if let Err(why) = restored {
            return Err(BoardRefusal::Unavailable(format!(
                "{OUTCOME_UNKNOWN}contained again; the hold is not written back: {why}"
            )));
        }
        let mut held = self.held();
        if let Some(board) = held.boards.get_mut(&key) {
            board.posts.insert(seq, prior);
        }
        if let Some(why) = held.marked.get_mut(&(key, seq)) {
            why.remove(&lifted);
            if why.is_empty() {
                held.marked.remove(&(key, seq));
            }
        }
        Ok(Lifted::Remarked)
    }

    /// What the kernel has yet to record, oldest first.
    pub fn take_notices(&self) -> Vec<BoardNotice> {
        let mut held = self.held();
        let taken = std::mem::take(&mut held.notices);
        held.in_flight = held.in_flight.saturating_add(taken.len());
        taken
    }

    /// Ends `taken` notices' flight: puts back, ahead of any newer ones, those the trail did
    /// not take (`back`); the rest are recorded.
    pub fn return_notices(&self, mut back: Vec<BoardNotice>, taken: usize) {
        let mut held = self.held();
        held.in_flight = held.in_flight.saturating_sub(taken);
        back.extend(std::mem::take(&mut held.notices));
        held.notices = back;
    }

    /// Notes `seqs` as sent to `reader`, after their reply was written.
    pub fn sent(&self, key: BoardKey, reader: &AgentId, seqs: &[u64]) {
        let mut held = self.held();
        let board = held.boards.entry(key).or_default();
        let cursor = board.cursors.get(reader).copied().unwrap_or(0);
        let on: Vec<u64> = seqs
            .iter()
            .copied()
            .filter(|seq| *seq > cursor && board.posts.contains_key(seq))
            .collect();
        if !on.is_empty() {
            board.sent.entry(reader.clone()).or_default().extend(on);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn place(
        &self,
        draw: &mut dyn FnMut() -> Result<[u8; 16], BoardRefusal>,
        key: BoardKey,
        (author, author_uid): (Author, Option<u32>),
        task: Option<TaskId>,
        labels: PostLabels,
        draft: PostDraft,
        view: &dyn EnrollmentView,
    ) -> Result<Arc<Stored>, BoardRefusal> {
        let _w = self.writing();
        if self.held().owing() >= BOARD_OWED_MAX {
            return Err(BoardRefusal::Store("removals are owed".into()));
        }
        self.room(key, &author, draft.in_reply_to, view)?;
        let mut rec = self.board_record(key);
        let seq = rec.next_seq;
        rec.next_seq = seq
            .checked_add(1)
            .ok_or(BoardRefusal::Store("the sequence is exhausted".into()))?;
        self.save_board(key, rec).map_err(store)?;
        let id = self.fresh_id(key, draw)?;
        let stored = Stored {
            post: Post {
                id,
                author,
                task,
                at_secs: self.now(),
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
                // A containment installed before this insert is in `view`; one installed after
                // it is `mark`'s, which finds this post.
                let contained = contained_on(view, key, std::iter::once(author_uid));
                let why = contained_for(key, author_uid, &contained);
                if !why.is_empty() {
                    held.marked.insert((key, seq), why);
                }
                return Ok(stored);
            }
            Err(StoreError::NotDurable(why)) => why,
            Err(e @ (StoreError::Io(_) | StoreError::Counters(_))) => return Err(store(e)),
        };
        match self.blobs.delete(&name) {
            Ok(()) => Err(BoardRefusal::Store(why)),
            Err(e) => {
                self.held().owed.insert((key, id));
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
        view: &dyn EnrollmentView,
    ) -> Result<(), BoardRefusal> {
        let held = self.held();
        let now = self.now();
        if let Some(board) = held.boards.get(&key) {
            let live = board
                .posts
                .values()
                .filter(|s| !held.withheld(key, s, now))
                .count();
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
        let gone = |target| {
            held.live(key, target, now).is_none_or(|s| {
                let contained = contained_on(view, key, std::iter::once(s.author_uid));
                !contained_for(key, s.author_uid, &contained).is_empty()
            })
        };
        match in_reply_to {
            Some(target) if gone(target) => Err(BoardRefusal::NoSuchPost),
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
                || held.owed.contains(&(key, id));
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

    /// Any failure, unsynced included, changes nothing in memory; the one exception is
    /// [`Self::set_settings`], which on an unsynced write sets memory itself.
    fn save_board(
        &self,
        key: BoardKey,
        rec: crate::board_store::BoardRecord,
    ) -> Result<(), StoreError> {
        let plain = encode(&rec)?;
        self.blobs.save(&Name::Board(key).text(), &plain)?;
        let mut held = self.held();
        let board = held.boards.entry(key).or_default();
        board.next_seq = rec.next_seq;
        board.settings = rec.settings;
        Ok(())
    }

    /// Poison is recovered: what a reader acts on changes only after the I/O that justifies
    /// it; `marked` and `expiring` only withhold, so a panic leaves at worst more withheld.
    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The write path's own lock: held across I/O, never by a reader. Whoever takes it
    /// first retries every owed removal. Poison is recovered: it guards no state of its own.
    fn writing(&self) -> std::sync::MutexGuard<'_, ()> {
        let w = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let owed: Vec<(BoardKey, PostId)> = self.held().owed.iter().copied().collect();
        for (key, id) in owed {
            if self.blobs.delete(&Name::Post(key, id).text()).is_ok() {
                let mut held = self.held();
                held.owed.remove(&(key, id));
                held.notices.push(BoardNotice::Settled { key, id });
            }
        }
        w
    }
}

/// [`BoardStore`]'s kernel-only operations, for the integration tests.
#[cfg(any(test, feature = "hermetic-test-seam"))]
pub trait BoardSeam {
    fn set_settings(&self, key: BoardKey, settings: Settings) -> Result<(), BoardRefusal>;
    fn mark(&self, view: &dyn EnrollmentView);
    fn due(&self, limit: usize) -> Vec<BoardDue>;
    fn perform(&self, due: &[BoardDue], view: &dyn EnrollmentView) -> usize;
    fn release(
        &self,
        key: BoardKey,
        id: PostId,
        lifted: HeldFor,
        view: &dyn EnrollmentView,
    ) -> Result<Lifted, BoardRefusal>;
}

#[cfg(any(test, feature = "hermetic-test-seam"))]
impl BoardSeam for BoardStore {
    fn set_settings(&self, key: BoardKey, settings: Settings) -> Result<(), BoardRefusal> {
        BoardStore::set_settings(self, key, settings).map(drop)
    }

    fn mark(&self, view: &dyn EnrollmentView) {
        BoardStore::mark(self, view)
    }

    fn due(&self, limit: usize) -> Vec<BoardDue> {
        BoardStore::due(self, limit)
    }

    fn perform(&self, due: &[BoardDue], view: &dyn EnrollmentView) -> usize {
        BoardStore::perform(self, due, view)
    }

    fn release(
        &self,
        key: BoardKey,
        id: PostId,
        lifted: HeldFor,
        view: &dyn EnrollmentView,
    ) -> Result<Lifted, BoardRefusal> {
        BoardStore::release(self, key, id, lifted, view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_store::{HeldFor, LabelValue, Report, BOARD, BOARD_RECORD_MAX};
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
                (author, Some(2001)),
                None,
                PostLabels::default(),
                draft(body),
                &free(),
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
            (hobi(), Some(2001)),
            None,
            PostLabels::default(),
            draft(body),
            &free(),
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
                (hobi(), Some(2001)),
                Some(task),
                labels.clone(),
                draft(BODY),
                &free(),
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
                (hobi(), Some(2001)),
                Some(TaskId([6; 16])),
                labels,
                max.clone(),
                &free(),
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
        store.settle(&found[0]).unwrap();
        store.mark(&containing(&[], &[1000, 2001]));
        assert_eq!(store.perform(&store.due(10), &free()), 4);
        drop(store);
        let name = t.path().join(format!("post.1000.{}.board", posted.post.id));
        let len = std::fs::metadata(name).unwrap().len();
        assert!(len <= BOARD_RECORD_MAX, "held for both: {len}");
        let store = open_dir(t.path()).unwrap();
        assert!(store.take_boot_findings().is_empty());
        assert!(store.get(BOB, posted.post.id).is_none());
        drop(store);
        let uid = nix::unistd::geteuid().as_raw();
        let blobs = DirBlobs::open(t.path(), uid, key(), BOARD).unwrap();
        let plain = TaskBlobs::load(&blobs, &post_name(BOB, posted.post.id)).unwrap();
        let rec: PostRecord<Stored> = ciborium::from_reader(plain.as_slice()).unwrap();
        assert_eq!(
            rec.stored.held,
            [HeldFor::Author, HeldFor::Person].into_iter().collect()
        );
        assert!(rec.stored.post.draft == max);
    }

    #[test]
    fn a_failed_sequence_write_refuses_and_changes_nothing() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        b.fail(Some(Fail::Unsynced));
        let refused = store.post(
            BOB,
            (hobi(), None),
            None,
            PostLabels::default(),
            draft("x"),
            &free(),
        );
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
        let refused = store.post(
            BOB,
            (hobi(), None),
            None,
            PostLabels::default(),
            draft("x"),
            &free(),
        );
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
        assert!(!b.has(&crate::board_store::Name::Post(BOB, PostId([1; 16])).text()));
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
    fn a_post_is_refused_while_the_owed_removals_are_at_their_bound() {
        let b = MemTaskBlobs::default();
        let store = open_mem(
            &b,
            Caps {
                board: 64,
                author: 64,
            },
        );
        b.fail(Some(Fail::Unlinks));
        for i in 0..crate::board_store::BOARD_OWED_MAX {
            let armed = b.clone();
            b.after_save(move || armed.fail(Some(Fail::UnsyncedNoUnlink)));
            let refused = put_with(&store, vec![[i as u8 + 1; 16]], "owed");
            assert!(
                matches!(refused, Err(BoardRefusal::Unavailable(_))),
                "{refused:?}"
            );
            b.fail(Some(Fail::Unlinks));
        }
        assert_eq!(store.held().owed.len(), crate::board_store::BOARD_OWED_MAX);
        let before = b.names().unwrap();
        let refused = put_with(&store, vec![[0xee; 16]], "one too many");
        assert_eq!(
            refused.unwrap_err(),
            BoardRefusal::Store("removals are owed".into())
        );
        assert_eq!(b.names().unwrap(), before, "nothing is written");
        b.fail(None);
        let refused = put_with(&store, vec![[0xef; 16]], "settled, not yet recorded");
        assert_eq!(
            refused.unwrap_err(),
            BoardRefusal::Store("removals are owed".into())
        );
        assert!(store.held().owed.is_empty(), "the removals were settled");
        let unrecorded = store.take_notices();
        assert_eq!(unrecorded.len(), crate::board_store::BOARD_OWED_MAX);
        assert_eq!(
            put_with(&store, vec![[0xee; 16]], "notices in flight").unwrap_err(),
            BoardRefusal::Store("removals are owed".into()),
            "the notices being recorded still count toward the bound"
        );
        store.return_notices(unrecorded, crate::board_store::BOARD_OWED_MAX);
        assert!(
            put_with(&store, vec![[0xf0; 16]], "trail still down").is_err(),
            "the settled notices the trail refused count toward the bound"
        );
        let recorded = store.take_notices();
        assert_eq!(recorded.len(), crate::board_store::BOARD_OWED_MAX);
        store.return_notices(Vec::new(), recorded.len());
        let next = put_with(&store, vec![[0xf1; 16]], "trail recovered").unwrap();
        assert!(store.get(BOB, next.post.id).is_some());
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
            (hobi(), None),
            None,
            PostLabels::default(),
            draft("third"),
            &free(),
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
        let refused = store.post(
            BOB,
            (hobi(), None),
            None,
            PostLabels::default(),
            draft("x"),
            &free(),
        );
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
        let refused = store.post(
            BOB,
            (hobi(), None),
            None,
            PostLabels::default(),
            draft("x"),
            &free(),
        );
        assert_eq!(refused.unwrap_err(), BoardRefusal::AuthorAtCap);
        assert_eq!(BoardRefusal::AuthorAtCap.to_string(), "author at cap");
        put(&store, BOB, jin(), "jin");
        put(&store, BOB, Author::Agent("suga".into()), "suga");
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
                (jin(), None),
                None,
                PostLabels::default(),
                reply("ok", root.post.id),
                &free(),
            )
            .unwrap();
        assert_eq!(answered.post.draft.in_reply_to, Some(root.post.id));
        for target in [PostId([7; 16]), PostId([9; 16]), elsewhere.post.id] {
            let refused = store.post(
                BOB,
                (jin(), None),
                None,
                PostLabels::default(),
                reply("no", target),
                &free(),
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
    fn an_acknowledgement_moves_the_cursor_only_to_a_post_sent() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let posted: Vec<_> = (0..3).map(|_| put(&store, BOB, hobi(), "p")).collect();
        let r = reader("rm");
        let last = Some(posted[2].post.id);
        assert_eq!(
            store.plan_read(BOB, &r, last),
            ReadPlan {
                cursor: 0,
                ack_to: None,
                upper: posted[2].seq
            }
        );
        store.sent(BOB, &r, &[posted[0].seq, posted[1].seq]);
        assert_eq!(store.plan_read(BOB, &r, last).ack_to, None, "never sent");
        assert_eq!(
            store.plan_read(BOB, &r, Some(posted[1].post.id)).ack_to,
            Some(posted[1].seq)
        );
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
                ack_to: None,
                upper: posted[2].seq
            }
        );
        assert_eq!(store.plan_read(BOB, &r, last).ack_to, None);
    }

    #[test]
    fn a_read_admitted_while_a_post_is_written_does_not_reach_it() {
        let b = MemTaskBlobs::default();
        let store = Arc::new(open_mem(&b, SMALL));
        let first = put(&store, BOB, hobi(), "published");
        let seen = Arc::new(Mutex::new(None));
        let (planning, out, inner) = (Arc::clone(&store), Arc::clone(&seen), b.clone());
        b.after_save(move || {
            inner.after_save(move || {
                *out.lock().unwrap() = Some(planning.plan_read(BOB, &reader("rm"), None).upper);
            });
        });
        let second = put(&store, BOB, hobi(), "in flight");
        assert!(second.seq > first.seq);
        assert_eq!(
            *seen.lock().unwrap(),
            Some(first.seq),
            "the sequence reserved for the post in flight is not in the read's range"
        );
    }

    #[test]
    fn sent_accumulates_across_replies() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let posted: Vec<_> = (0..3).map(|_| put(&store, BOB, hobi(), "p")).collect();
        let r = reader("rm");
        store.sent(BOB, &r, &[posted[1].seq]);
        store.sent(BOB, &r, &[posted[0].seq]);
        for p in &posted[..2] {
            assert_eq!(
                store.plan_read(BOB, &r, Some(p.post.id)).ack_to,
                Some(p.seq)
            );
        }
        assert_eq!(
            store.plan_read(BOB, &r, Some(posted[2].post.id)).ack_to,
            None
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
    fn after_a_restart_an_acknowledgement_moves_nothing_until_posts_are_sent_again() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let posted: Vec<_> = (0..2).map(|_| put(&store, BOB, hobi(), "p")).collect();
        let r = reader("rm");
        store.sent(BOB, &r, &[posted[1].seq]);
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
        store.sent(BOB, &r, &[posted[1].seq]);
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
        store.sent(ALICE, &r, &[bob.seq]);
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
        assert_eq!((off.enabled, off.report), (false, Report::Off));
        let on = Settings {
            enabled: true,
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
            matches!(refused, Err(BoardRefusal::Unavailable(_))),
            "{refused:?}"
        );
        assert_eq!(
            store.settings(BOB),
            Settings {
                enabled: false,
                report: Report::Summary,
            }
        );
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

    fn board_record_with_participate(next_seq: u64) -> Zeroizing<Vec<u8>> {
        use ciborium::Value;
        let text = |s: &str| Value::Text(s.into());
        encode(&Value::Map(vec![
            (text("board"), Value::Integer(1000.into())),
            (text("next_seq"), Value::Integer(next_seq.into())),
            (
                text("settings"),
                Value::Map(vec![
                    (text("enabled"), Value::Bool(true)),
                    (text("participate"), Value::Bool(true)),
                    (text("report"), text("Every")),
                ]),
            ),
        ]))
        .unwrap()
    }

    #[test]
    fn a_board_record_with_participate_on_a_board_with_nothing_else_is_quarantined() {
        let b = MemTaskBlobs::default();
        b.put("board.1000", &board_record_with_participate(7));
        let store = open_mem(&b, SMALL);
        let found = store.take_boot_findings();
        assert_eq!(
            found,
            [BoardFinding::Quarantined {
                name: "board.1000".into(),
                why: "the record does not decode".into(),
            }]
        );
        assert_eq!(store.settings(BOB), Settings::default());
        store.settle(&found[0]).unwrap();
        assert_eq!(b.aside(), ["board.1000"]);
        assert_eq!(put(&store, BOB, hobi(), "after").seq, 1);
    }

    #[test]
    fn a_board_record_with_participate_beside_a_post_or_a_cursor_refuses_boot() {
        let refusal = |b: &MemTaskBlobs| match BoardStore::open(
            Box::new(b.clone()),
            Arc::new(ManualClock::at(T0)),
        ) {
            Ok(_) => "opened".to_string(),
            Err(e) => e.to_string(),
        };
        const BEHIND: &str =
            "task counters of board 1000 are missing or behind a stored post or cursor";

        let posts = MemTaskBlobs::default();
        let store = open_mem(&posts, SMALL);
        let p = put(&store, BOB, hobi(), "kept");
        drop(store);
        posts.put("board.1000", &board_record_with_participate(p.seq + 1));
        assert_eq!(refusal(&posts), BEHIND);

        let cursors = MemTaskBlobs::default();
        let store = open_mem(&cursors, SMALL);
        let p = put(&store, BOB, hobi(), "read");
        store.advance(BOB, &reader("rm"), p.seq).unwrap();
        drop(store);
        cursors.put(&post_name(BOB, p.post.id), b"sentinel-719-unreadable");
        cursors.put("board.1000", &board_record_with_participate(p.seq + 1));
        assert_eq!(refusal(&cursors), BEHIND);
    }

    fn addressed_to_the_tasker(record: &[u8]) -> Zeroizing<Vec<u8>> {
        use ciborium::Value;
        fn field<'v>(v: &'v mut Value, name: &str) -> &'v mut Value {
            let Value::Map(fields) = v else {
                panic!("{name} is under a map")
            };
            &mut fields
                .iter_mut()
                .find(|(k, _)| k.as_text() == Some(name))
                .unwrap()
                .1
        }
        let mut v: Value = ciborium::from_reader(record).unwrap();
        let draft = field(field(field(&mut v, "stored"), "post"), "draft");
        *field(draft, "to") = Value::Text("Tasker".into());
        encode(&v).unwrap()
    }

    #[test]
    fn a_stored_post_addressed_to_the_tasker_is_quarantined_and_boot_goes_on() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let kept = put(&store, BOB, hobi(), "kept");
        let live = put(&store, BOB, jin(), "sentinel-719-to-the-tasker");
        drop(store);
        let held = held_post([0x71; 16], live.seq + 1, hobi());
        plant(&b, BOB, &held);
        b.put(
            "board.1000",
            &encode(&crate::board_store::BoardRecord {
                board: 1000,
                next_seq: held.seq + 1,
                settings: Settings::default(),
            })
            .unwrap(),
        );
        let mut want = vec![post_name(BOB, live.post.id), post_name(BOB, held.post.id)];
        want.sort();
        for name in &want {
            b.put(name, &addressed_to_the_tasker(&b.load(name).unwrap()));
        }
        let store = open_mem(&b, SMALL);
        let found = store.take_boot_findings();
        let mut named: Vec<String> = found
            .iter()
            .map(|BoardFinding::Quarantined { name, why }| {
                assert_eq!(why, "the record does not decode", "{name}");
                name.clone()
            })
            .collect();
        named.sort();
        assert_eq!(named, want);
        assert_eq!(ids(&store.candidates(BOB, 0, 10)), vec![kept.post.id]);
        assert!(store.get(BOB, live.post.id).is_none());
        for f in &found {
            store.settle(f).unwrap();
        }
        let mut aside = b.aside();
        aside.sort();
        assert_eq!(aside, want);
        assert_eq!(put(&store, BOB, hobi(), "after").seq, held.seq + 1);
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

    const RETAIN: i64 = crate::board_store::BOARD_RETENTION.as_secs() as i64;

    fn clocked(b: &MemTaskBlobs) -> (BoardStore, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::at(T0));
        let store = BoardStore::open_with(Box::new(b.clone()), clock.clone(), SMALL).unwrap();
        (store, clock)
    }

    fn by(
        store: &BoardStore,
        key: BoardKey,
        author: Author,
        uid: Option<u32>,
        body: &str,
    ) -> Arc<Stored> {
        store
            .post(
                key,
                (author, uid),
                None,
                PostLabels::default(),
                draft(body),
                &free(),
            )
            .unwrap()
    }

    fn enrolled(agents: &[(&str, u32)]) -> crate::enrollment::FixedEnrollment {
        crate::enrollment::FixedEnrollment(
            agents.iter().map(|(a, uid)| (reader(a), *uid)).collect(),
        )
    }

    fn containing(
        agents: &[(&str, u32)],
        uids: &[u32],
    ) -> crate::enrollment::Containing<crate::enrollment::FixedEnrollment> {
        crate::enrollment::Containing(enrolled(agents), uids.iter().copied().collect())
    }

    fn whys(due: &[BoardDue]) -> Vec<(Option<PostId>, Option<AgentId>, BoardDueFor)> {
        due.iter()
            .map(|d| (d.post, d.reader.clone(), d.why))
            .collect()
    }

    fn stored_on_disk(b: &MemTaskBlobs, key: BoardKey, id: PostId) -> Stored {
        let plain = b.load(&post_name(key, id)).unwrap();
        let rec: PostRecord<Stored> = ciborium::from_reader(plain.as_slice()).unwrap();
        rec.stored
    }

    #[test]
    fn a_post_expires_after_seven_days_and_not_before() {
        let b = MemTaskBlobs::default();
        let (store, clock) = clocked(&b);
        let old = by(&store, BOB, hobi(), Some(2001), "sentinel-695-old");
        clock.set(T0 + 10);
        let young = by(&store, BOB, hobi(), Some(2001), "sentinel-695-young");
        clock.set(T0 + RETAIN - 1);
        assert!(store.due(10).is_empty());
        clock.set(T0 + RETAIN);
        let due = store.due(10);
        assert_eq!(
            whys(&due),
            vec![(Some(old.post.id), None, BoardDueFor::Expire)]
        );
        assert_eq!(
            (due[0].key, due[0].seq, due[0].recorded),
            (BOB, Some(old.seq), false)
        );
        assert_eq!(store.perform(&due, &free()), 1);
        assert!(store.get(BOB, old.post.id).is_none());
        assert!(!b.has(&post_name(BOB, old.post.id)));
        assert_eq!(ids(&store.candidates(BOB, 0, 10)), vec![young.post.id]);
        assert!(store.due(10).is_empty());
        drop(store);
        let (store, clock) = clocked(&b);
        assert!(store.get(BOB, old.post.id).is_none());
        assert!(b.has("board.1000"));
        clock.set(T0 + 10 + RETAIN);
        assert_eq!(store.perform(&store.due(10), &free()), 1);
        assert!(store.candidates(BOB, 0, 10).is_empty());
        assert!(b.has("board.1000"), "a board's record outlives its posts");
        assert_eq!(by(&store, BOB, hobi(), None, "next").seq, young.seq + 1);
    }

    #[test]
    fn still_live_and_a_reply_consult_the_view_and_the_marks() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let free_post = by(&store, BOB, hobi(), Some(2001), "sentinel-695-free");
        let author = by(&store, BOB, jin(), Some(2002), "sentinel-695-author");
        let marked = by(&store, BOB, hobi(), Some(2003), "sentinel-695-marked");
        store.mark(&containing(&[], &[2003]));
        let all = [free_post.seq, author.seq, marked.seq, 99];
        let view = containing(&[], &[2002]);
        assert_eq!(
            store.still_live(BOB, &all, &view),
            [free_post.seq].into_iter().collect()
        );
        assert_eq!(
            store.still_live(BOB, &all, &free()),
            [free_post.seq, author.seq].into_iter().collect()
        );
        assert!(store
            .still_live(BOB, &all, &containing(&[], &[1000]))
            .is_empty());
        let replied = |to: PostId| {
            store.post(
                BOB,
                (hobi(), Some(2001)),
                None,
                PostLabels::default(),
                reply("r", to),
                &view,
            )
        };
        assert_eq!(
            replied(author.post.id).unwrap_err(),
            BoardRefusal::NoSuchPost,
            "a target whose author the view contains, before any mark"
        );
        assert_eq!(
            replied(marked.post.id).unwrap_err(),
            BoardRefusal::NoSuchPost
        );
        assert!(replied(free_post.post.id).is_ok());
    }

    /// Whether the post is still in the store, readable or not.
    fn in_store(store: &BoardStore, key: BoardKey, id: PostId) -> bool {
        store
            .held()
            .boards
            .get(&key)
            .is_some_and(|b| b.ids.contains_key(&id))
    }

    fn sent_set(store: &BoardStore, key: BoardKey, r: &AgentId) -> Option<BTreeSet<u64>> {
        store.held().boards.get(&key)?.sent.get(r).cloned()
    }

    #[test]
    fn the_record_bound_and_the_retention_are_exact() {
        assert_eq!(crate::board_store::BOARD_RECORD_MAX, 40_960);
        assert_eq!(crate::board_store::BOARD_RETENTION.as_secs(), 604_800);
    }

    #[test]
    fn a_sent_set_never_holds_a_post_at_or_below_the_cursor() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let posted: Vec<_> = (0..3).map(|_| put(&store, BOB, hobi(), "p")).collect();
        let r = reader("rm");
        store.advance(BOB, &r, posted[1].seq).unwrap();
        store.sent(BOB, &r, &[posted[0].seq, posted[1].seq, posted[2].seq]);
        assert_eq!(
            sent_set(&store, BOB, &r),
            Some([posted[2].seq].into_iter().collect())
        );
    }

    #[test]
    fn an_acknowledgement_keeps_the_later_sent_posts_acknowledgeable() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let posted: Vec<_> = (0..3).map(|_| put(&store, BOB, hobi(), "p")).collect();
        let r = reader("rm");
        store.sent(BOB, &r, &[posted[0].seq, posted[1].seq, posted[2].seq]);
        assert_eq!(store.acknowledge(BOB, &r, posted[1].seq), Ok(posted[1].seq));
        assert_eq!(
            sent_set(&store, BOB, &r),
            Some([posted[2].seq].into_iter().collect()),
            "the acknowledged and earlier ones go, the later one stays"
        );
        assert_eq!(
            store.plan_read(BOB, &r, Some(posted[2].post.id)).ack_to,
            Some(posted[2].seq)
        );
    }

    #[test]
    fn an_expiry_forgets_only_its_own_due_records() {
        let b = MemTaskBlobs::default();
        let (store, clock) = clocked(&b);
        let old = by(&store, BOB, jin(), Some(2002), "sentinel-695-old");
        clock.set(T0 + 10);
        let marked = by(&store, BOB, hobi(), Some(2001), "sentinel-695-marked");
        clock.set(T0 + RETAIN);
        store.mark(&containing(&[], &[2001]));
        let due = store.due(10);
        assert_eq!(
            whys(&due),
            vec![
                (
                    Some(marked.post.id),
                    None,
                    BoardDueFor::Hold(HeldFor::Author)
                ),
                (Some(old.post.id), None, BoardDueFor::Expire),
            ]
        );
        b.fail(Some(Fail::Unsynced));
        assert_eq!(store.perform(&due, &free()), 0);
        b.fail(None);
        assert_eq!(store.perform(&due[1..], &free()), 1);
        let left = store.due(10);
        assert_eq!(
            left.iter()
                .map(|d| (d.post, d.recorded))
                .collect::<Vec<_>>(),
            [(Some(marked.post.id), true)],
            "the hold's record, refused before, is still known as recorded"
        );
    }

    #[test]
    fn a_sent_set_holds_only_posts_on_the_board_and_goes_when_empty() {
        let b = MemTaskBlobs::default();
        let (store, clock) = clocked(&b);
        let old = by(&store, BOB, hobi(), Some(2001), "sentinel-695-old");
        clock.set(T0 + 10);
        let young = by(&store, BOB, hobi(), Some(2001), "sentinel-695-young");
        let r = reader("rm");
        store.sent(BOB, &r, &[old.seq, young.seq, 99]);
        assert_eq!(
            sent_set(&store, BOB, &r),
            Some([old.seq, young.seq].into_iter().collect()),
            "a sequence not on the board is not noted"
        );
        clock.set(T0 + RETAIN);
        assert_eq!(store.perform(&store.due(10), &free()), 1);
        assert_eq!(
            sent_set(&store, BOB, &r),
            Some([young.seq].into_iter().collect()),
            "an expired post leaves every sent set"
        );
        store.advance(BOB, &r, young.seq).unwrap();
        assert_eq!(sent_set(&store, BOB, &r), None, "an empty set is dropped");
    }

    #[test]
    fn a_reader_enrolled_again_before_the_sweep_keeps_its_cursor() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let p = by(&store, BOB, hobi(), Some(2001), "p");
        let r = reader("rm");
        store.advance(BOB, &r, p.seq).unwrap();
        store.mark(&enrolled(&[]));
        let due = store.due(10);
        assert_eq!(
            whys(&due),
            vec![(None, Some(r.clone()), BoardDueFor::DropCursor)]
        );
        let back = enrolled(&[("rm", 3000)]);
        assert_eq!(store.perform(&due, &back), 0, "re-checked at the delete");
        assert!(b.has("cursor.1000.rm"));
        store.mark(&enrolled(&[]));
        let due = store.due(10);
        store.mark(&back);
        assert!(
            store.due(10).is_empty(),
            "the mark reconciles what it noted"
        );
        assert_eq!(store.perform(&due, &enrolled(&[])), 0);
        assert!(b.has("cursor.1000.rm"));
        assert_eq!(store.plan_read(BOB, &r, None).cursor, p.seq);
        assert!(store.held().said.is_empty());
        store.mark(&enrolled(&[]));
        b.fail(Some(Fail::Every));
        assert_eq!(store.perform(&store.due(10), &enrolled(&[])), 0);
        b.fail(None);
        assert!(
            store.due(10).iter().all(|d| d.recorded),
            "the refused drop was recorded"
        );
        store.mark(&back);
        assert!(
            store.held().said.is_empty(),
            "a re-enrolled reader's recorded drop is forgotten"
        );
    }

    #[test]
    fn a_published_containment_stops_an_expiry_before_mark_runs() {
        for (uids, f) in [(2001, HeldFor::Author), (1000, HeldFor::Person)] {
            let b = MemTaskBlobs::default();
            let (store, clock) = clocked(&b);
            let old = by(&store, BOB, hobi(), Some(2001), "sentinel-695-overdue");
            clock.set(T0 + RETAIN);
            let due = store.due(10);
            assert_eq!(
                whys(&due),
                vec![(Some(old.post.id), None, BoardDueFor::Expire)]
            );
            let view = containing(&[], &[uids]);
            assert_eq!(store.perform(&due, &view), 0, "{f:?}");
            assert!(b.has(&post_name(BOB, old.post.id)), "{f:?}: not deleted");
            assert!(store.get(BOB, old.post.id).is_none(), "{f:?}: withheld");
            let due = store.due(10);
            assert_eq!(
                whys(&due),
                vec![(Some(old.post.id), None, BoardDueFor::Hold(f))]
            );
            assert_eq!(store.perform(&due, &view), 1);
            assert_eq!(
                stored_on_disk(&b, BOB, old.post.id).held,
                [f].into_iter().collect()
            );
        }
    }

    #[test]
    fn a_post_past_retention_is_never_readable_whether_or_not_it_was_swept() {
        let b = MemTaskBlobs::default();
        let (store, clock) = clocked(&b);
        let a = by(&store, BOB, hobi(), Some(2001), "sentinel-695-a");
        clock.set(T0 + 1);
        let others: Vec<_> = (0..3)
            .map(|_| by(&store, BOB, jin(), Some(2002), "live"))
            .collect();
        clock.set(T0 + RETAIN);
        assert!(store.get(BOB, a.post.id).is_none(), "no sweep has run");
        assert_eq!(ids(&store.candidates(BOB, 0, 10)), ids(&others));
        assert!(store.still_live(BOB, &[a.seq], &free()).is_empty());
        let reply = store.post(
            BOB,
            (Author::Agent("suga".into()), None),
            None,
            PostLabels::default(),
            reply("r", a.post.id),
            &free(),
        );
        assert_eq!(reply.unwrap_err(), BoardRefusal::NoSuchPost);
        let fourth = by(
            &store,
            BOB,
            hobi(),
            Some(2001),
            "the cap no longer counts it",
        );
        b.fail(Some(Fail::Unlinks));
        assert_eq!(store.perform(&store.due(10), &free()), 0);
        b.fail(None);
        assert!(b.has(&post_name(BOB, a.post.id)), "the delete failed");
        assert!(store.get(BOB, a.post.id).is_none(), "and nothing reappears");
        assert!(!ids(&store.candidates(BOB, 0, 10)).contains(&a.post.id));
        let r = reader("rm");
        store.sent(BOB, &r, &[fourth.seq]);
        let to = store
            .plan_read(BOB, &r, Some(fourth.post.id))
            .ack_to
            .unwrap();
        store.advance(BOB, &r, to).unwrap();
        assert!(
            a.seq < to,
            "the acknowledgement passed a post that was never deliverable"
        );
    }

    #[test]
    fn an_acknowledgement_of_a_post_past_retention_moves_nothing_swept_or_not() {
        let b = MemTaskBlobs::default();
        let (store, clock) = clocked(&b);
        let old = by(&store, BOB, hobi(), Some(2001), "sentinel-695-old");
        let r = reader("rm");
        store.sent(BOB, &r, &[old.seq]);
        assert_eq!(
            store.plan_read(BOB, &r, Some(old.post.id)).ack_to,
            Some(old.seq)
        );
        clock.set(T0 + RETAIN);
        assert_eq!(
            store.plan_read(BOB, &r, Some(old.post.id)).ack_to,
            None,
            "expired, not yet swept"
        );
        assert_eq!(store.perform(&store.due(10), &free()), 1);
        assert_eq!(
            store.plan_read(BOB, &r, Some(old.post.id)).ack_to,
            None,
            "swept"
        );
    }

    #[test]
    fn a_clock_set_back_does_not_make_an_expired_post_readable_again() {
        let b = MemTaskBlobs::default();
        let (store, clock) = clocked(&b);
        let old = by(&store, BOB, hobi(), Some(2001), "sentinel-695-old");
        let r = reader("rm");
        store.sent(BOB, &r, &[old.seq]);
        clock.set(T0 + RETAIN);
        assert!(store.get(BOB, old.post.id).is_none());
        clock.set(T0);
        assert!(store.get(BOB, old.post.id).is_none(), "get");
        assert!(store.candidates(BOB, 0, 10).is_empty(), "candidates");
        assert!(
            store.still_live(BOB, &[old.seq], &free()).is_empty(),
            "still_live"
        );
        assert_eq!(
            store.plan_read(BOB, &r, Some(old.post.id)).ack_to,
            None,
            "plan_read"
        );
        let young = by(&store, BOB, hobi(), Some(2001), "sentinel-695-young");
        assert_eq!(
            young.post.at_secs,
            T0 + RETAIN,
            "a post is stamped with the store's now"
        );
    }

    #[test]
    fn an_acknowledgement_is_checked_again_when_it_is_written() {
        let b = MemTaskBlobs::default();
        let (store, clock) = clocked(&b);
        let p = by(&store, BOB, hobi(), Some(2001), "sentinel-695-p");
        let r = reader("rm");
        store.sent(BOB, &r, &[p.seq]);
        let to = store.plan_read(BOB, &r, Some(p.post.id)).ack_to.unwrap();
        clock.set(T0 + RETAIN);
        assert_eq!(
            store.acknowledge(BOB, &r, to),
            Ok(0),
            "expired since it was planned"
        );
        assert!(!b.has("cursor.1000.rm"));
        let (store, _) = clocked(&b);
        let q = by(&store, BOB, hobi(), Some(2001), "sentinel-695-q");
        store.sent(BOB, &r, &[q.seq]);
        let to = store.plan_read(BOB, &r, Some(q.post.id)).ack_to.unwrap();
        store.mark(&enrolled(&[]));
        assert_eq!(store.acknowledge(BOB, &r, to), Ok(0), "no longer sent");
        store.sent(BOB, &r, &[q.seq]);
        assert_eq!(
            store.acknowledge(BOB, &r, q.seq + 1),
            Ok(0),
            "not a post on the board"
        );
        assert_eq!(store.acknowledge(BOB, &r, q.seq), Ok(q.seq));
        assert_eq!(
            store.acknowledge(BOB, &r, q.seq),
            Ok(q.seq),
            "not above the cursor"
        );
    }

    #[test]
    fn a_held_post_never_expires_and_is_never_a_candidate() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let live = put_with(&store, vec![[0x11; 16]], "live").unwrap();
        drop(store);
        let held = held_post([0x22; 16], live.seq + 1, jin());
        plant(&b, BOB, &held);
        b.put(
            "board.1000",
            &encode(&crate::board_store::BoardRecord {
                board: 1000,
                next_seq: held.seq + 1,
                settings: Settings::default(),
            })
            .unwrap(),
        );
        let (store, clock) = clocked(&b);
        clock.set(T0 + 10 * RETAIN);
        assert_eq!(
            whys(&store.due(10)),
            vec![(Some(live.post.id), None, BoardDueFor::Expire)]
        );
        assert!(
            store.candidates(BOB, 0, 10).is_empty(),
            "neither the expired post nor the held one"
        );
        assert!(store.get(BOB, held.post.id).is_none());
        let forged = BoardDue {
            key: BOB,
            post: Some(held.post.id),
            seq: Some(held.seq),
            reader: None,
            why: BoardDueFor::Expire,
            recorded: false,
        };
        let before = b.attempts();
        assert_eq!(store.perform(&[forged], &free()), 0);
        assert_eq!(b.attempts(), before, "nothing is written for a held post");
        assert!(b.has(&post_name(BOB, held.post.id)));
        store.mark(&containing(&[], &[]));
        assert!(store
            .candidates(BOB, 0, 10)
            .iter()
            .all(|s| s.post.id != held.post.id));
    }

    /// Contains the uids in its set, which a test changes while a post is written.
    #[derive(Clone, Default)]
    struct Installed(Arc<Mutex<BTreeSet<u32>>>);

    impl EnrollmentView for Installed {
        fn agent_uid(&self, _: &AgentId) -> Option<u32> {
            None
        }

        fn agents(&self) -> Vec<(AgentId, u32)> {
            Vec::new()
        }

        fn is_enrolled(&self, _: u32) -> bool {
            false
        }

        fn contained(&self, uid: u32) -> bool {
            self.0.lock().unwrap().contains(&uid)
        }

        fn unresolved(&self, _: u32) -> bool {
            false
        }

        fn board(&self, _: &AgentId) -> bool {
            false
        }
    }

    /// Answers each `contained` call from the next snapshot in turn, as if one were installed
    /// between every two calls; `contained_among` answers from one.
    struct Snapshots(Mutex<std::collections::VecDeque<BTreeSet<u32>>>);

    impl Snapshots {
        fn next(&self) -> BTreeSet<u32> {
            let mut all = self.0.lock().unwrap();
            let now = all.front().cloned().unwrap_or_default();
            if all.len() > 1 {
                all.pop_front();
            }
            now
        }
    }

    impl EnrollmentView for Snapshots {
        fn agent_uid(&self, _: &AgentId) -> Option<u32> {
            None
        }

        fn agents(&self) -> Vec<(AgentId, u32)> {
            Vec::new()
        }

        fn is_enrolled(&self, _: u32) -> bool {
            false
        }

        fn contained(&self, uid: u32) -> bool {
            self.next().contains(&uid)
        }

        fn contained_among(&self, uids: &BTreeSet<u32>) -> BTreeSet<u32> {
            self.next().intersection(uids).copied().collect()
        }

        fn unresolved(&self, _: u32) -> bool {
            false
        }

        fn board(&self, _: &AgentId) -> bool {
            false
        }
    }

    fn installs(snapshots: &[&[u32]]) -> Snapshots {
        Snapshots(Mutex::new(
            snapshots
                .iter()
                .map(|s| s.iter().copied().collect())
                .collect(),
        ))
    }

    #[test]
    fn a_check_over_several_posts_reads_one_snapshot() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let a = by(&store, BOB, hobi(), Some(2001), "sentinel-695-a");
        let c = by(&store, BOB, jin(), Some(2002), "sentinel-695-c");
        let live = store.still_live(BOB, &[a.seq, c.seq], &installs(&[&[], &[], &[2001, 2002]]));
        assert_ne!(live.len(), 1, "a mix of two snapshots: {live:?}");
        store.mark(&installs(&[&[], &[], &[2001, 2002]]));
        assert_ne!(store.due(10).len(), 1, "a mix of two snapshots");
    }

    #[test]
    fn a_post_written_under_a_containment_is_stored_marked_for_each_hold() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let posted = |key, author, uid, view: &dyn EnrollmentView| {
            store
                .post(
                    key,
                    (author, Some(uid)),
                    None,
                    PostLabels::default(),
                    draft("sentinel-695-contained-at-insert"),
                    view,
                )
                .unwrap()
        };
        let author = posted(BOB, hobi(), 2001, &containing(&[], &[2001]));
        let person = posted(BOB, jin(), 2002, &containing(&[], &[1000]));
        let both = posted(ALICE, jin(), 2002, &containing(&[], &[1001, 2002]));
        for (key, s) in [(BOB, &author), (BOB, &person), (ALICE, &both)] {
            assert!(store.get(key, s.post.id).is_none());
            assert!(stored_on_disk(&b, key, s.post.id).held.is_empty());
        }
        assert!(store.candidates(BOB, 0, 10).is_empty());
        assert!(store.candidates(ALICE, 0, 10).is_empty());
        let due = store.due(10);
        let mut got = whys(&due);
        got.sort();
        let mut want = vec![
            (
                Some(author.post.id),
                None,
                BoardDueFor::Hold(HeldFor::Author),
            ),
            (
                Some(person.post.id),
                None,
                BoardDueFor::Hold(HeldFor::Person),
            ),
            (Some(both.post.id), None, BoardDueFor::Hold(HeldFor::Author)),
            (Some(both.post.id), None, BoardDueFor::Hold(HeldFor::Person)),
        ];
        want.sort();
        assert_eq!(got, want);
        let refused = store.post(
            BOB,
            (jin(), Some(2002)),
            None,
            PostLabels::default(),
            reply("r", author.post.id),
            &free(),
        );
        assert_eq!(refused.unwrap_err(), BoardRefusal::NoSuchPost);
        for (author, uid) in [(hobi(), 2001), (hobi(), 2001), (jin(), 2002), (jin(), 2002)] {
            by(&store, BOB, author, Some(uid), "live");
        }
        let full = store.post(
            BOB,
            (Author::Agent("suga".into()), None),
            None,
            PostLabels::default(),
            draft("x"),
            &free(),
        );
        assert_eq!(
            full.unwrap_err(),
            BoardRefusal::Full,
            "held posts are outside the board cap"
        );
        assert_eq!(store.perform(&due, &free()), 4);
        assert!(store.due(10).is_empty());
        assert_eq!(
            stored_on_disk(&b, ALICE, both.post.id).held,
            [HeldFor::Author, HeldFor::Person].into_iter().collect()
        );
        assert_eq!(
            stored_on_disk(&b, BOB, person.post.id).held,
            [HeldFor::Person].into_iter().collect()
        );
    }

    #[test]
    fn a_containment_installed_while_a_post_is_written_holds_the_post() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let store = Arc::new(store);
        let view = Installed::default();
        let (inner, installed, marking) = (b.clone(), view.clone(), Arc::clone(&store));
        b.after_save(move || {
            inner.after_save(move || {
                installed.0.lock().unwrap().insert(2001);
                marking.mark(&installed);
            });
        });
        let posted = store
            .post(
                BOB,
                (hobi(), Some(2001)),
                None,
                PostLabels::default(),
                draft("sentinel-695-raced"),
                &view,
            )
            .unwrap();
        assert!(store.get(BOB, posted.post.id).is_none());
        assert!(store.candidates(BOB, 0, 10).is_empty());
        assert_eq!(
            whys(&store.due(10)),
            vec![(
                Some(posted.post.id),
                None,
                BoardDueFor::Hold(HeldFor::Author)
            )]
        );
    }

    #[test]
    fn a_marked_post_is_withheld_before_the_hold_is_written() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let first = by(&store, BOB, hobi(), Some(2001), "sentinel-695-marked");
        let other = by(&store, BOB, jin(), Some(2002), "other");
        let replied = store.post(
            BOB,
            (jin(), Some(2002)),
            None,
            PostLabels::default(),
            reply("r", first.post.id),
            &free(),
        );
        assert!(replied.is_ok());
        b.fail(Some(Fail::Every));
        let before = b.attempts();
        store.mark(&containing(&[("hobi", 2001)], &[2001]));
        assert_eq!(b.attempts(), before, "a mark makes no I/O");
        assert!(store.get(BOB, first.post.id).is_none());
        assert!(!ids(&store.candidates(BOB, 0, 10)).contains(&first.post.id));
        assert!(ids(&store.candidates(BOB, 0, 10)).contains(&other.post.id));
        let due = store.due(10);
        assert_eq!(
            whys(&due),
            vec![(
                Some(first.post.id),
                None,
                BoardDueFor::Hold(HeldFor::Author)
            )]
        );
        assert!(!due[0].recorded);
        b.fail(None);
        let refused = store.post(
            BOB,
            (jin(), Some(2002)),
            None,
            PostLabels::default(),
            reply("r2", first.post.id),
            &free(),
        );
        assert_eq!(refused.unwrap_err(), BoardRefusal::NoSuchPost);
        assert!(stored_on_disk(&b, BOB, first.post.id).held.is_empty());
        store.mark(&enrolled(&[("hobi", 2001)]));
        assert!(
            store.due(10).is_empty(),
            "a mark no longer contained is dropped"
        );
        assert!(store.get(BOB, first.post.id).is_some());
        assert!(ids(&store.candidates(BOB, 0, 10)).contains(&first.post.id));
    }

    #[test]
    fn a_contained_authors_posts_are_held_by_the_uid_recorded_with_the_post() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let before = by(&store, BOB, hobi(), Some(2001), "sentinel-695-before");
        let after = by(&store, BOB, hobi(), Some(2002), "sentinel-695-after");
        let anon = by(&store, BOB, hobi(), None, "sentinel-695-anon");
        let gone = by(&store, BOB, jin(), Some(2003), "sentinel-695-gone");
        let view = containing(&[("hobi", 2002)], &[2001]);
        store.mark(&view);
        let due = store.due(10);
        assert_eq!(
            whys(&due),
            vec![(
                Some(before.post.id),
                None,
                BoardDueFor::Hold(HeldFor::Author)
            )]
        );
        assert_eq!(store.perform(&due, &free()), 1);
        assert!(store.due(10).is_empty());
        assert_eq!(
            stored_on_disk(&b, BOB, before.post.id).held,
            [HeldFor::Author].into_iter().collect()
        );
        assert_eq!(
            ids(&store.candidates(BOB, 0, 10)),
            vec![after.post.id, anon.post.id, gone.post.id]
        );
        store.mark(&enrolled(&[("hobi", 2001)]));
        assert!(
            store.get(BOB, before.post.id).is_none(),
            "a written hold stays"
        );
        drop(store);
        let (store, _) = clocked(&b);
        assert!(store.get(BOB, before.post.id).is_none());
        store.mark(&containing(&[("hobi", 2001)], &[2002]));
        assert_eq!(
            whys(&store.due(10)),
            vec![(
                Some(after.post.id),
                None,
                BoardDueFor::Hold(HeldFor::Author)
            )]
        );
    }

    #[test]
    fn a_contained_persons_board_is_held_for_the_person() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let mine = by(&store, BOB, hobi(), Some(2001), "sentinel-695-mine");
        let both = by(&store, BOB, jin(), Some(2002), "sentinel-695-both");
        let theirs = by(&store, ALICE, hobi(), Some(2001), "sentinel-695-theirs");
        store.mark(&containing(&[], &[1000, 2002]));
        assert!(store.candidates(BOB, 0, 10).is_empty());
        assert_eq!(ids(&store.candidates(ALICE, 0, 10)), vec![theirs.post.id]);
        let mut got = whys(&store.due(10));
        got.sort();
        let mut want = vec![
            (Some(mine.post.id), None, BoardDueFor::Hold(HeldFor::Person)),
            (Some(both.post.id), None, BoardDueFor::Hold(HeldFor::Author)),
            (Some(both.post.id), None, BoardDueFor::Hold(HeldFor::Person)),
        ];
        want.sort();
        assert_eq!(got, want);
        assert_eq!(store.perform(&store.due(10), &free()), 3);
        assert!(store.due(10).is_empty());
        assert_eq!(
            stored_on_disk(&b, BOB, mine.post.id).held,
            [HeldFor::Person].into_iter().collect()
        );
        assert_eq!(
            stored_on_disk(&b, BOB, both.post.id).held,
            [HeldFor::Author, HeldFor::Person].into_iter().collect()
        );
        assert!(stored_on_disk(&b, ALICE, theirs.post.id).held.is_empty());
        store.mark(&containing(&[], &[1000, 2002]));
        assert!(
            store.due(10).is_empty(),
            "a post held for a reason is not marked again"
        );
    }

    #[test]
    fn a_deenrolled_agents_cursor_is_dropped() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let p = by(&store, BOB, hobi(), Some(2001), "p");
        let q = by(&store, ALICE, hobi(), Some(2001), "q");
        for r in ["rm", "suga", "jimin"] {
            store.advance(BOB, &reader(r), p.seq).unwrap();
        }
        store.advance(ALICE, &reader("rm"), q.seq).unwrap();
        store.mark(&enrolled(&[("rm", 3000), ("suga", 3001), ("jimin", 3002)]));
        assert!(store.due(10).is_empty());
        store.sent(BOB, &reader("v"), &[p.seq]);
        assert_eq!(
            store.plan_read(BOB, &reader("v"), Some(p.post.id)).ack_to,
            Some(p.seq)
        );
        store.mark(&enrolled(&[("suga", 3001), ("jimin", 3005)]));
        assert_eq!(
            store.plan_read(BOB, &reader("v"), Some(p.post.id)).ack_to,
            None,
            "a de-enrolled reader's sent posts are forgotten"
        );
        let mut got = whys(&store.due(10));
        got.sort();
        let want = vec![
            (None, Some(reader("rm")), BoardDueFor::DropCursor),
            (None, Some(reader("rm")), BoardDueFor::DropCursor),
        ];
        assert_eq!(got, want);
        assert!(store
            .due(10)
            .iter()
            .all(|d| d.post.is_none() && d.seq.is_none()));
        assert_eq!(store.perform(&store.due(10), &free()), 2);
        assert!(store.due(10).is_empty());
        assert!(!b.has("cursor.1000.rm") && !b.has("cursor.1001.rm"));
        assert!(
            b.has("cursor.1000.jimin"),
            "a re-enrolled agent id keeps its cursor"
        );
        assert!(b.has("cursor.1000.suga"));
        assert_eq!(store.plan_read(BOB, &reader("rm"), None).cursor, 0);
        assert_eq!(store.plan_read(BOB, &reader("suga"), None).cursor, p.seq);
        drop(store);
        let (store, _) = clocked(&b);
        assert_eq!(store.plan_read(ALICE, &reader("rm"), None).cursor, 0);
        assert_eq!(store.plan_read(BOB, &reader("suga"), None).cursor, p.seq);
    }

    #[test]
    fn perform_rechecks_and_changes_memory_only_after_a_synced_write() {
        let b = MemTaskBlobs::default();
        let (store, clock) = clocked(&b);
        let old = by(&store, BOB, hobi(), Some(2001), "old");
        store.advance(BOB, &reader("rm"), old.seq).unwrap();
        clock.set(T0 + 100);
        let young = by(&store, BOB, jin(), Some(2002), "young");
        clock.set(T0 + RETAIN);
        store.mark(&enrolled(&[("rm", 3000)]));
        store.mark(&containing(&[], &[2002]));
        let due = store.due(10);
        assert_eq!(
            whys(&due),
            vec![
                (
                    Some(young.post.id),
                    None,
                    BoardDueFor::Hold(HeldFor::Author)
                ),
                (Some(old.post.id), None, BoardDueFor::Expire),
                (None, Some(reader("rm")), BoardDueFor::DropCursor),
            ]
        );
        b.fail(Some(Fail::Unsynced));
        let before = b.attempts();
        assert_eq!(store.perform(&due, &free()), 0);
        assert_eq!(b.attempts(), before + 1, "stops at the first refusal");
        assert_eq!(store.perform(&due[1..], &free()), 0);
        assert_eq!(store.perform(&due[2..], &free()), 0);
        assert!(!b.has(&post_name(BOB, old.post.id)) && !b.has("cursor.1000.rm"));
        assert!(
            in_store(&store, BOB, old.post.id),
            "an unsynced delete leaves the post"
        );
        assert!(store.get(BOB, old.post.id).is_none(), "past retention");
        assert_eq!(store.plan_read(BOB, &reader("rm"), None).cursor, old.seq);
        assert!(store.get(BOB, young.post.id).is_none(), "still marked");
        let again = store.due(10);
        assert_eq!(whys(&again), whys(&due));
        assert!(again.iter().all(|d| d.recorded));
        store.mark(&containing(&[], &[]));
        assert!(
            store.get(BOB, young.post.id).is_some(),
            "an unsynced hold is not in memory"
        );
        assert_eq!(whys(&store.due(10)), whys(&due[1..]));
        b.fail(None);
        let before = b.attempts();
        assert_eq!(
            store.perform(&due[..1], &free()),
            0,
            "a dropped mark is not written"
        );
        assert_eq!(b.attempts(), before);
        store.mark(&containing(&[], &[2002]));
        let last = store.due(10);
        assert_eq!(
            last.iter().map(|d| d.recorded).collect::<Vec<_>>(),
            [false, true, true]
        );
        assert_eq!(store.perform(&last, &free()), 3);
        assert!(store.get(BOB, old.post.id).is_none());
        assert!(store.get(BOB, young.post.id).is_none());
        assert_eq!(store.plan_read(BOB, &reader("rm"), None).cursor, 0);
        assert!(store.due(10).is_empty());
        let before = b.attempts();
        assert_eq!(store.perform(&due, &free()), 0, "nothing is due any more");
        assert_eq!(b.attempts(), before);
    }

    /// `mark` runs while `expire`'s delete is stalled inside the blobs, after the expiry's
    /// check and before its outcome.
    fn mark_during_the_delete(
        b: &MemTaskBlobs,
        store: &Arc<BoardStore>,
        post: &Arc<Stored>,
    ) -> (usize, Vec<BoardDue>) {
        contain_during_the_delete(b, store, post, &[2001])
    }

    /// [`mark_during_the_delete`], containing `uids`.
    fn contain_during_the_delete(
        b: &MemTaskBlobs,
        store: &Arc<BoardStore>,
        post: &Arc<Stored>,
        uids: &[u32],
    ) -> (usize, Vec<BoardDue>) {
        b.slow(Some(std::time::Duration::from_millis(300)));
        let performing = Arc::clone(store);
        let due = store.due(10);
        assert_eq!(
            whys(&due),
            vec![(Some(post.post.id), None, BoardDueFor::Expire)]
        );
        let worker = std::thread::spawn(move || performing.perform(&due, &free()));
        b.await_stalls(1);
        store.mark(&containing(&[], uids));
        let during = store.due(10);
        assert!(store.get(BOB, post.post.id).is_none(), "being removed");
        assert!(store.candidates(BOB, 0, 10).is_empty());
        let done = worker.join().unwrap();
        b.slow(None);
        (done, during)
    }

    fn holds(due: &[BoardDue]) -> usize {
        due.iter()
            .filter(|d| matches!(d.why, BoardDueFor::Hold(_)))
            .count()
    }

    #[test]
    fn an_expiring_post_is_withheld_while_its_delete_is_under_way() {
        for refused in [false, true] {
            let b = MemTaskBlobs::default();
            let (store, clock) = clocked(&b);
            let store = Arc::new(store);
            let post = by(&store, BOB, hobi(), Some(2001), "sentinel-695-expiring");
            clock.set(T0 + RETAIN);
            if refused {
                b.fail(Some(Fail::UnsyncedUnlinks));
            }
            b.slow(Some(std::time::Duration::from_millis(300)));
            let performing = Arc::clone(&store);
            let due = store.due(10);
            let worker = std::thread::spawn(move || performing.perform(&due, &free()));
            b.await_stalls(1);
            assert!(store.get(BOB, post.post.id).is_none(), "refused: {refused}");
            assert!(!ids(&store.candidates(BOB, 0, 10)).contains(&post.post.id));
            let done = worker.join().unwrap();
            b.slow(None);
            b.fail(None);
            assert_eq!(done, usize::from(!refused));
            assert_eq!(in_store(&store, BOB, post.post.id), refused);
            assert!(store.get(BOB, post.post.id).is_none(), "refused: {refused}");
            assert!(!ids(&store.candidates(BOB, 0, 10)).contains(&post.post.id));
        }
    }

    #[test]
    fn a_delete_that_panics_clears_the_expiring_marker() {
        let b = MemTaskBlobs::default();
        let (store, clock) = clocked(&b);
        let post = by(&store, BOB, hobi(), Some(2001), "sentinel-695-panic");
        clock.set(T0 + RETAIN);
        let due = store.due(10);
        b.fail(Some(Fail::Panics));
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.perform(&due, &free())
        }));
        b.fail(None);
        assert!(panicked.is_err());
        assert!(store.held().expiring.is_empty());
        assert!(in_store(&store, BOB, post.post.id));
        assert!(store.get(BOB, post.post.id).is_none(), "past retention");
        assert_eq!(
            whys(&store.due(10)),
            vec![(Some(post.post.id), None, BoardDueFor::Expire)]
        );
        assert_eq!(store.perform(&store.due(10), &free()), 1);
        assert!(store.get(BOB, post.post.id).is_none());
        assert!(!b.has(&post_name(BOB, post.post.id)));
    }

    #[test]
    fn a_containment_marked_during_an_expirys_unlink_keeps_the_post() {
        for (uid, why) in [(2001, HeldFor::Author), (1000, HeldFor::Person)] {
            let b = MemTaskBlobs::default();
            let (store, clock) = clocked(&b);
            let store = Arc::new(store);
            let post = by(&store, BOB, hobi(), Some(2001), "sentinel-695-race");
            clock.set(T0 + RETAIN);
            let (done, during) = contain_during_the_delete(&b, &store, &post, &[uid]);
            assert_eq!(
                holds(&during),
                0,
                "{why:?}: no hold is listed while it is removed"
            );
            assert_eq!(done, 0, "{why:?}: the expiry is not done");
            assert!(in_store(&store, BOB, post.post.id), "{why:?}");
            assert!(store.get(BOB, post.post.id).is_none(), "{why:?}: withheld");
            assert!(
                b.has(&post_name(BOB, post.post.id)),
                "{why:?}: written back"
            );
            assert!(store.held().expiring.is_empty());
            assert!(
                !store
                    .held()
                    .said
                    .contains(&Item::Post(BOB, post.seq, BoardDueFor::Expire)),
                "{why:?}: the expiry is no longer under way"
            );
            assert_eq!(
                whys(&store.due(10)),
                vec![(Some(post.post.id), None, BoardDueFor::Hold(why))],
                "{why:?}"
            );
            assert_eq!(store.perform(&store.due(10), &free()), 1);
            assert_eq!(
                stored_on_disk(&b, BOB, post.post.id).held,
                [why].into_iter().collect(),
                "{why:?}"
            );
            drop(store);
            b.crash(0);
            let (reloaded, _) = clocked(&b);
            assert!(in_store(&reloaded, BOB, post.post.id), "{why:?}");
            assert!(
                reloaded.due(10).is_empty(),
                "{why:?}: held, so not due to expire"
            );
        }
    }

    #[test]
    fn a_containment_installed_after_an_expiry_does_not_bring_the_post_back() {
        let b = MemTaskBlobs::default();
        let (store, clock) = clocked(&b);
        let post = by(&store, BOB, hobi(), Some(2001), "sentinel-698-expired");
        clock.set(T0 + RETAIN);
        assert_eq!(store.perform(&store.due(10), &free()), 1);
        store.mark(&containing(&[], &[2001, 1000]));
        assert!(store.due(10).is_empty());
        assert!(!in_store(&store, BOB, post.post.id));
        assert!(!b.has(&post_name(BOB, post.post.id)));
        drop(store);
        let (store, _) = clocked(&b);
        assert!(!in_store(&store, BOB, post.post.id));
    }

    #[test]
    fn an_expiry_kept_whose_record_is_not_written_back_stops_the_sweep() {
        for unsynced in [false, true] {
            let b = MemTaskBlobs::default();
            let (store, clock) = clocked(&b);
            let post = by(&store, BOB, hobi(), Some(2001), "sentinel-698-evidence");
            let name = post_name(BOB, post.post.id);
            clock.set(T0 + RETAIN);
            let view = ThenRefuse {
                b: b.clone(),
                name: name.clone(),
                unsynced,
                calls: Mutex::new(0),
            };
            let due = store.due(10);
            assert_eq!(
                whys(&due),
                vec![(Some(post.post.id), None, BoardDueFor::Expire)]
            );
            assert_eq!(store.perform(&due, &view), 0, "unsynced {unsynced}");
            b.fail(None);
            b.stick(None);
            assert_eq!(b.has(&name), unsynced, "unsynced {unsynced}");
            assert!(in_store(&store, BOB, post.post.id));
            assert!(store.get(BOB, post.post.id).is_none(), "marked");
            assert!(store.held().owed.is_empty());
            assert!(!store
                .held()
                .said
                .contains(&Item::Post(BOB, post.seq, BoardDueFor::Expire)));
            assert_eq!(
                whys(&store.due(10)),
                vec![(Some(post.post.id), None, BoardDueFor::Hold(HeldFor::Author))]
            );
            assert_eq!(store.perform(&store.due(10), &free()), 1);
            assert_eq!(
                stored_on_disk(&b, BOB, post.post.id).held,
                [HeldFor::Author].into_iter().collect()
            );
        }
    }

    #[test]
    fn an_expiry_whose_delete_is_refused_leaves_the_later_mark_due() {
        let b = MemTaskBlobs::default();
        let (store, clock) = clocked(&b);
        let store = Arc::new(store);
        let post = by(&store, BOB, hobi(), Some(2001), "sentinel-695-race-refused");
        clock.set(T0 + RETAIN);
        b.fail(Some(Fail::UnsyncedUnlinks));
        let (done, during) = mark_during_the_delete(&b, &store, &post);
        b.fail(None);
        assert_eq!(holds(&during), 0);
        assert_eq!(done, 0);
        assert!(store.get(BOB, post.post.id).is_none(), "withheld");
        assert!(store.candidates(BOB, 0, 10).is_empty());
        assert_eq!(
            whys(&store.due(10)),
            vec![(Some(post.post.id), None, BoardDueFor::Hold(HeldFor::Author))]
        );
        assert_eq!(store.perform(&store.due(10), &free()), 1);
        assert_eq!(
            stored_on_disk(&b, BOB, post.post.id).held,
            [HeldFor::Author].into_iter().collect()
        );
    }

    #[test]
    fn a_settled_owed_removal_is_queued_as_a_notice() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let armed = b.clone();
        b.after_save(move || armed.fail(Some(Fail::UnsyncedNoUnlink)));
        let unknown = put_with(&store, vec![[0x50; 16]], "sentinel-695-unknown");
        assert!(
            matches!(&unknown, Err(BoardRefusal::Unavailable(why)) if why.starts_with(OUTCOME_UNKNOWN)),
            "{unknown:?}"
        );
        assert!(store.take_notices().is_empty());
        let id = PostId([0x50; 16]);
        b.fail(Some(Fail::Unlinks));
        store.set_settings(BOB, Settings::default()).unwrap();
        assert!(b.has(&post_name(BOB, id)));
        assert!(store.take_notices().is_empty(), "nothing settled yet");
        b.fail(None);
        store.set_settings(BOB, Settings::default()).unwrap();
        assert!(!b.has(&post_name(BOB, id)));
        let settled = vec![BoardNotice::Settled { key: BOB, id }];
        assert_eq!(store.take_notices(), settled);
        assert!(store.take_notices().is_empty());
        store.return_notices(settled.clone(), 1);
        assert_eq!(store.take_notices(), settled);
    }

    fn free() -> crate::enrollment::Containing<crate::enrollment::FixedEnrollment> {
        containing(&[], &[])
    }

    fn holding(store: &BoardStore, uids: &[u32]) {
        store.mark(&containing(&[], uids));
        let due = store.due(100);
        assert_eq!(store.perform(&due, &free()), due.len());
    }

    #[test]
    fn a_post_held_for_two_is_live_only_after_both_are_lifted() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let post = by(&store, BOB, hobi(), Some(2001), "sentinel-695-two");
        holding(&store, &[1000, 2001]);
        let id = post.post.id;
        let both: BTreeSet<HeldFor> = [HeldFor::Author, HeldFor::Person].into_iter().collect();
        assert_eq!(stored_on_disk(&b, BOB, id).held, both);
        store.mark(&containing(&[], &[]));
        assert_eq!(
            store.release(BOB, id, HeldFor::Author, &free()),
            Ok(Lifted::Done)
        );
        assert_eq!(
            stored_on_disk(&b, BOB, id).held,
            [HeldFor::Person].into_iter().collect()
        );
        assert!(store.get(BOB, id).is_none(), "the person's hold remains");
        assert!(store.candidates(BOB, 0, 10).is_empty());
        let before = b.attempts();
        assert!(store.release(BOB, id, HeldFor::Author, &free()).is_err());
        assert_eq!(b.attempts(), before, "a hold already lifted writes nothing");
        b.fail(Some(Fail::Every));
        assert!(store.release(BOB, id, HeldFor::Person, &free()).is_err());
        b.fail(None);
        assert!(
            store.get(BOB, id).is_none(),
            "a refused write lifts nothing"
        );
        assert_eq!(
            store.release(BOB, id, HeldFor::Person, &free()),
            Ok(Lifted::Done)
        );
        assert!(stored_on_disk(&b, BOB, id).held.is_empty());
        assert!(store.get(BOB, id).is_some());
        assert_eq!(ids(&store.candidates(BOB, 0, 10)), vec![id]);
        drop(store);
        let (store, _) = clocked(&b);
        assert!(store.get(BOB, id).is_some(), "the lift is durable");
    }

    #[test]
    fn an_unsynced_lift_is_outcome_unknown_and_changes_nothing_in_memory() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let post = by(
            &store,
            BOB,
            hobi(),
            Some(2001),
            "sentinel-695-unsynced-lift",
        );
        holding(&store, &[2001]);
        store.mark(&containing(&[], &[]));
        b.fail(Some(Fail::Unsynced));
        let got = store.release(BOB, post.post.id, HeldFor::Author, &free());
        b.fail(None);
        assert!(
            matches!(&got, Err(BoardRefusal::Unavailable(why)) if why.starts_with(OUTCOME_UNKNOWN)),
            "{got:?}"
        );
        assert!(store.get(BOB, post.post.id).is_none());
        assert_eq!(store.held_count(2001), 1);
    }

    #[test]
    fn held_for_lists_a_uids_author_and_person_holds() {
        const MINE: BoardKey = BoardKey(2001);
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let a = by(&store, BOB, hobi(), Some(2001), "a");
        let c = by(&store, BOB, jin(), Some(2002), "c");
        let d = by(&store, ALICE, hobi(), Some(2001), "d");
        let bb = by(&store, MINE, jin(), Some(2002), "b");
        let f = by(&store, MINE, hobi(), Some(2001), "f");
        holding(&store, &[2001]);
        let e = by(
            &store,
            ALICE,
            hobi(),
            Some(2001),
            "sentinel-695-marked-only",
        );
        store.mark(&containing(&[], &[2001]));
        assert!(store.get(ALICE, e.post.id).is_none(), "marked");
        let all = vec![
            (BOB, a.post.id, a.seq, HeldFor::Author),
            (ALICE, d.post.id, d.seq, HeldFor::Author),
            (MINE, bb.post.id, bb.seq, HeldFor::Person),
            (MINE, f.post.id, f.seq, HeldFor::Author),
            (MINE, f.post.id, f.seq, HeldFor::Person),
        ];
        assert_eq!(store.held_for(2001, 100), all);
        assert_eq!(store.held_count(2001), all.len());
        assert_eq!(store.held_for(2001, 2), all[..2]);
        assert!(store.held_for(2002, 100).is_empty());
        assert_eq!(store.held_count(2002), 0);
        assert!(store.get(BOB, c.post.id).is_some());
    }

    #[test]
    fn a_released_post_past_retention_expires_at_the_next_sweep() {
        let b = MemTaskBlobs::default();
        let (store, clock) = clocked(&b);
        let post = by(&store, BOB, hobi(), Some(2001), "sentinel-695-late");
        holding(&store, &[2001]);
        store.mark(&containing(&[], &[]));
        clock.set(T0 + 2 * RETAIN);
        assert!(store.due(10).is_empty(), "a held post does not expire");
        assert_eq!(
            store.release(BOB, post.post.id, HeldFor::Author, &free()),
            Ok(Lifted::Done)
        );
        assert!(store.get(BOB, post.post.id).is_none(), "past retention");
        let due = store.due(10);
        assert_eq!(
            whys(&due),
            vec![(Some(post.post.id), None, BoardDueFor::Expire)]
        );
        assert_eq!(store.perform(&due, &free()), 1);
        assert!(!b.has(&post_name(BOB, post.post.id)));
    }

    #[test]
    fn a_post_held_on_disk_for_a_subject_no_longer_contained_is_released() {
        let b = MemTaskBlobs::default();
        let held = held_post([0x33; 16], FIRST_SEQ, hobi());
        plant(&b, BOB, &held);
        b.put(
            "board.1000",
            &encode(&crate::board_store::BoardRecord {
                board: 1000,
                next_seq: held.seq + 1,
                settings: Settings::default(),
            })
            .unwrap(),
        );
        let (store, _) = clocked(&b);
        store.mark(&enrolled(&[("hobi", 2001)]));
        assert!(store.get(BOB, held.post.id).is_none());
        assert_eq!(
            store.held_for(2001, 10),
            vec![(BOB, held.post.id, held.seq, HeldFor::Author)]
        );
        assert_eq!(
            store.release(BOB, held.post.id, HeldFor::Author, &free()),
            Ok(Lifted::Done)
        );
        assert!(store.get(BOB, held.post.id).is_some());
        assert_eq!(store.held_count(2001), 0);
    }

    #[test]
    fn a_release_is_refused_while_the_holds_subject_is_contained() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let post = by(&store, BOB, hobi(), Some(2001), "sentinel-695-still");
        let id = post.post.id;
        holding(&store, &[1000, 2001]);
        let both: BTreeSet<HeldFor> = [HeldFor::Author, HeldFor::Person].into_iter().collect();
        let before = b.attempts();
        for (lifted, contained) in [(HeldFor::Author, 2001), (HeldFor::Person, 1000)] {
            assert_eq!(
                store.release(BOB, id, lifted, &containing(&[], &[contained])),
                Err(BoardRefusal::StillContained),
                "{lifted:?}"
            );
        }
        assert_eq!(b.attempts(), before, "a refused lift writes nothing");
        assert_eq!(stored_on_disk(&b, BOB, id).held, both);
        assert_eq!(store.held_count(2001), 1);
        assert_eq!(store.held_count(1000), 1);
        assert_eq!(
            store.release(BOB, id, HeldFor::Author, &containing(&[], &[1000])),
            Ok(Lifted::Done),
            "the board's person contained does not keep the author's hold"
        );
        assert_eq!(
            stored_on_disk(&b, BOB, id).held,
            [HeldFor::Person].into_iter().collect()
        );
        assert!(store.get(BOB, id).is_none());
    }

    /// Answers "not contained" to the first question and "contained" after it.
    struct ContainedAfterOne(std::sync::atomic::AtomicBool);

    impl EnrollmentView for ContainedAfterOne {
        fn agent_uid(&self, _: &AgentId) -> Option<u32> {
            None
        }
        fn agents(&self) -> Vec<(AgentId, u32)> {
            Vec::new()
        }
        fn is_enrolled(&self, _: u32) -> bool {
            false
        }
        fn contained(&self, _: u32) -> bool {
            self.0.swap(true, std::sync::atomic::Ordering::SeqCst)
        }
        fn unresolved(&self, _: u32) -> bool {
            false
        }
        fn board(&self, _: &AgentId) -> bool {
            false
        }
    }

    #[test]
    fn a_containment_seen_after_the_lift_is_written_marks_the_post_again() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let post = by(&store, BOB, hobi(), Some(2001), "sentinel-695-late-contain");
        holding(&store, &[2001]);
        let late = || ContainedAfterOne(std::sync::atomic::AtomicBool::new(false));
        let id = post.post.id;
        let author: BTreeSet<HeldFor> = [HeldFor::Author].into_iter().collect();
        assert_eq!(
            store.release(BOB, id, HeldFor::Author, &late()),
            Ok(Lifted::Remarked)
        );
        assert!(store.get(BOB, id).is_none(), "withheld");
        assert_eq!(stored_on_disk(&b, BOB, id).held, author, "written back");
        assert_eq!(store.held_count(2001), 1);
        assert!(store.due(10).is_empty(), "nothing left for the sweep");

        let armed = b.clone();
        b.after_save(move || armed.fail(Some(Fail::Every)));
        let got = store.release(BOB, id, HeldFor::Author, &late());
        b.fail(None);
        assert!(
            matches!(&got, Err(BoardRefusal::Unavailable(why)) if why.starts_with(OUTCOME_UNKNOWN)),
            "{got:?}"
        );
        assert!(store.get(BOB, id).is_none(), "the mark keeps it withheld");
        assert!(stored_on_disk(&b, BOB, id).held.is_empty());
        assert_eq!(
            whys(&store.due(10)),
            vec![(Some(id), None, BoardDueFor::Hold(HeldFor::Author))]
        );
        assert_eq!(store.perform(&store.due(10), &free()), 1);
        assert_eq!(stored_on_disk(&b, BOB, id).held, author);
    }

    #[test]
    fn a_post_of_an_unlabelled_task_has_no_labels() {
        assert!(PostLabels::default().0.is_empty());
    }

    const WIDE: Caps = Caps {
        board: 64,
        author: 64,
    };

    fn wide(b: &MemTaskBlobs) -> (BoardStore, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::at(T0));
        let store = BoardStore::open_with(Box::new(b.clone()), clock.clone(), WIDE).unwrap();
        (store, clock)
    }

    fn put_as(store: &BoardStore, key: BoardKey, id: u8, uid: u32) -> Arc<Stored> {
        store
            .post_with(
                &mut fixed(vec![[id; 16]]),
                key,
                (hobi(), Some(uid)),
                None,
                PostLabels::default(),
                draft("sentinel-698-clear"),
                &free(),
            )
            .unwrap()
    }

    fn pairs<'a>(posts: impl IntoIterator<Item = &'a Arc<Stored>>) -> Vec<(u64, PostId)> {
        posts.into_iter().map(|s| (s.seq, s.post.id)).collect()
    }

    fn cleared(removed: &[&Arc<Stored>], stopped: Option<BoardRefusal>) -> Cleared {
        Cleared {
            removed: removed.iter().map(|s| s.post.id).collect(),
            stopped,
        }
    }

    const UNSYNCED: &str = "outcome unknown: sentinel-628-unsynced";

    #[test]
    fn the_clear_page_is_32() {
        assert_eq!(crate::board_store::BOARD_CLEAR_PAGE, 32);
    }

    #[test]
    fn a_settings_write_returns_the_settings_before_it() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let first = Settings {
            enabled: true,
            report: Report::Every,
        };
        let second = Settings {
            enabled: false,
            report: Report::Summary,
        };
        assert_eq!(store.set_settings(BOB, first), Ok(Settings::default()));
        assert_eq!(store.set_settings(BOB, second), Ok(first));
        assert_eq!(store.settings(BOB), second);
        assert_eq!(store.settings(ALICE), Settings::default());
        b.crash(0);
        assert_eq!(open_mem(&b, SMALL).settings(BOB), second);
    }

    #[test]
    fn a_settings_write_the_disk_refuses_is_store_and_changes_nothing() {
        let b = MemTaskBlobs::default();
        let store = open_mem(&b, SMALL);
        let on = Settings {
            enabled: true,
            report: Report::Every,
        };
        store.set_settings(BOB, on).unwrap();
        b.fail(Some(Fail::Every));
        let refused = store.set_settings(BOB, Settings::default());
        assert_eq!(
            refused,
            Err(BoardRefusal::Store("sentinel-628-write-refused".into()))
        );
        assert_eq!(store.settings(BOB), on);
        b.fail(None);
        b.crash(0);
        assert_eq!(open_mem(&b, SMALL).settings(BOB), on);
    }

    #[test]
    fn an_unsynced_settings_write_keeps_enabled_off_where_either_value_has_it_off() {
        let s = |enabled, report| Settings { enabled, report };
        let cases = [
            (
                s(true, Report::Summary),
                s(false, Report::Every),
                s(false, Report::Summary),
            ),
            (
                s(false, Report::Every),
                s(true, Report::Off),
                s(false, Report::Every),
            ),
            (
                s(true, Report::Off),
                s(true, Report::Summary),
                s(true, Report::Off),
            ),
        ];
        for (old, new, merged) in cases {
            for crash in [None, Some(0), Some(1)] {
                let b = MemTaskBlobs::default();
                let store = open_mem(&b, SMALL);
                store.set_settings(BOB, old).unwrap();
                b.fail(Some(Fail::Unsynced));
                assert_eq!(
                    store.set_settings(BOB, new),
                    Err(BoardRefusal::Unavailable(UNSYNCED.into())),
                    "{old:?} -> {new:?}"
                );
                assert_eq!(store.settings(BOB), merged, "{old:?} -> {new:?}");
                b.fail(None);
                match crash {
                    Some(kept) => {
                        b.crash(kept);
                        let on_disk = [old, new][kept];
                        assert_eq!(open_mem(&b, SMALL).settings(BOB), on_disk);
                    }
                    None => {
                        put(&store, BOB, hobi(), "after");
                        b.crash(0);
                        assert_eq!(open_mem(&b, SMALL).settings(BOB), merged);
                        let plain = b.load("board.1000").unwrap();
                        let rec: crate::board_store::BoardRecord =
                            ciborium::from_reader(plain.as_slice()).unwrap();
                        assert_eq!(rec.settings, merged);
                    }
                }
            }
        }
    }

    #[test]
    fn clearable_pages_by_32_lowest_sequence_first() {
        for (n, more) in [(0u8, false), (32, false), (33, true)] {
            let b = MemTaskBlobs::default();
            let (store, _) = wide(&b);
            let posts: Vec<_> = (1..=n).map(|i| put_as(&store, BOB, i, 2001)).collect();
            let page = usize::from(n).min(32);
            assert_eq!(store.clearable(BOB), (pairs(&posts[..page]), more), "{n}");
        }
        let b = MemTaskBlobs::default();
        let (store, _) = wide(&b);
        let posts: Vec<_> = (1..=32).map(|i| put_as(&store, BOB, i, 2001)).collect();
        put_as(&store, BOB, 33, 2010);
        holding(&store, &[2010]);
        assert_eq!(store.clearable(BOB), (pairs(&posts), false));
        assert_eq!(store.clearable(ALICE), (Vec::new(), false));
    }

    #[test]
    fn clearable_skips_held_marked_expiring_and_aged_posts() {
        let b = MemTaskBlobs::default();
        let (store, clock) = wide(&b);
        let aged = put_as(&store, BOB, 0xe0, 2001);
        clock.set(T0 + RETAIN - 1);
        let held = put_as(&store, BOB, 0xe1, 2010);
        let marked = put_as(&store, BOB, 0xe2, 2011);
        let expiring = put_as(&store, BOB, 0xe3, 2012);
        holding(&store, &[2010]);
        clock.set(T0 + RETAIN);
        store.held().expiring.insert((BOB, expiring.seq));
        store.mark(&containing(&[], &[2011]));
        let at = |s: &Arc<Stored>| store.held().boards[&BOB].posts[&s.seq].clone();
        assert!(expired(&at(&aged), T0 + RETAIN));
        assert!(at(&aged).held.is_empty());
        for s in [&held, &marked, &expiring] {
            assert!(!expired(&at(s), T0 + RETAIN));
        }
        assert!(!at(&held).held.is_empty());
        assert!(store.held().marked.contains_key(&(BOB, marked.seq)));
        let posts: Vec<_> = (1..=40).map(|i| put_as(&store, BOB, i, 2001)).collect();
        assert_eq!(store.clearable(BOB), (pairs(&posts[..32]), true));
    }

    #[test]
    fn a_clear_removes_the_named_posts_and_frees_their_counts() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let suga = reader("suga");
        let mine: Vec<_> = (1..=3).map(|i| put_as(&store, BOB, i, 2001)).collect();
        let other = by(&store, BOB, jin(), Some(2002), "sentinel-698-kept");
        assert_eq!(
            put_with(&store, vec![[9; 16]], "full").unwrap_err(),
            BoardRefusal::Full
        );
        store.advance(BOB, &suga, 2).unwrap();
        store.sent(BOB, &suga, &[3, 4]);
        let (page, more) = store.clearable(BOB);
        assert_eq!((page.len(), more), (4, false));
        assert_eq!(
            store.clear(BOB, &pairs(&mine), &free()),
            cleared(&[&mine[0], &mine[1], &mine[2]], None)
        );
        for s in &mine {
            assert!(!in_store(&store, BOB, s.post.id));
            assert!(!b.has(&post_name(BOB, s.post.id)));
        }
        assert!(b.has(&post_name(BOB, other.post.id)));
        assert_eq!(ids(&store.candidates(BOB, 0, 10)), vec![other.post.id]);
        assert_eq!(store.plan_read(BOB, &suga, None).cursor, 2);
        assert_eq!(
            sent_set(&store, BOB, &suga),
            Some([4].into_iter().collect())
        );
        let again: Vec<_> = (11..=13).map(|i| put_as(&store, BOB, i, 2001)).collect();
        drop(store);
        let (store, _) = clocked(&b);
        for s in &mine {
            assert!(!in_store(&store, BOB, s.post.id));
        }
        let mut want = vec![other.post.id];
        want.extend(ids(&again));
        assert_eq!(ids(&store.candidates(BOB, 0, 10)), want);
    }

    #[test]
    fn a_post_held_aged_or_gone_since_the_page_was_taken_is_not_cleared() {
        let b = MemTaskBlobs::default();
        let (store, clock) = wide(&b);
        let aged = put_as(&store, BOB, 1, 2012);
        clock.set(T0 + 10);
        let held = put_as(&store, BOB, 2, 2010);
        let marked = put_as(&store, BOB, 3, 2011);
        let gone = put_as(&store, BOB, 4, 2001);
        let free_post = put_as(&store, BOB, 5, 2001);
        let (page, more) = store.clearable(BOB);
        assert_eq!(
            (&page, more),
            (&pairs([&aged, &held, &marked, &gone, &free_post]), false)
        );
        assert_eq!(
            store.clear(BOB, &pairs([&gone]), &free()),
            cleared(&[&gone], None)
        );
        holding(&store, &[2010]);
        store.mark(&containing(&[], &[2011]));
        clock.set(T0 + RETAIN);
        assert_eq!(
            store.clear(BOB, &page, &free()),
            cleared(&[&free_post], None)
        );
        for s in [&aged, &held, &marked] {
            assert!(in_store(&store, BOB, s.post.id));
            assert!(b.has(&post_name(BOB, s.post.id)));
        }
        for s in [&gone, &free_post] {
            assert!(!in_store(&store, BOB, s.post.id));
            assert!(!b.has(&post_name(BOB, s.post.id)));
        }
    }

    #[test]
    fn a_post_whose_author_or_person_is_contained_since_the_page_is_marked_not_cleared() {
        let b = MemTaskBlobs::default();
        let (store, _) = wide(&b);
        let contained = put_as(&store, BOB, 1, 2010);
        let free_post = put_as(&store, BOB, 2, 2001);
        let alices = put_as(&store, ALICE, 3, 2001);
        let page = store.clearable(BOB).0;
        assert_eq!(page.len(), 2);
        assert_eq!(
            store.clear(BOB, &page, &containing(&[], &[2010])),
            cleared(&[&free_post], None)
        );
        assert!(in_store(&store, BOB, contained.post.id));
        assert!(b.has(&post_name(BOB, contained.post.id)));
        assert!(store.get(BOB, contained.post.id).is_none());
        assert_eq!(
            store.held().marked.get(&(BOB, contained.seq)),
            Some(&[HeldFor::Author].into_iter().collect())
        );
        let page = store.clearable(ALICE).0;
        assert_eq!(page, pairs([&alices]));
        assert_eq!(
            store.clear(ALICE, &page, &containing(&[], &[1001])),
            cleared(&[], None)
        );
        assert!(b.has(&post_name(ALICE, alices.post.id)));
        assert_eq!(
            store.held().marked.get(&(ALICE, alices.seq)),
            Some(&[HeldFor::Person].into_iter().collect())
        );
    }

    #[test]
    fn a_pair_that_names_no_post_of_this_board_removes_nothing() {
        let b = MemTaskBlobs::default();
        let (store, _) = wide(&b);
        let bobs = put_as(&store, BOB, 1, 2001);
        let alices = put_as(&store, ALICE, 2, 2001);
        assert_eq!(bobs.seq, alices.seq);
        let before = b.attempts();
        for named in [
            vec![(alices.seq, alices.post.id)],
            vec![(bobs.seq, PostId([9; 16]))],
            vec![(bobs.seq + 1, bobs.post.id)],
        ] {
            assert_eq!(store.clear(BOB, &named, &free()), cleared(&[], None));
        }
        assert_eq!(b.attempts(), before, "nothing is deleted");
        assert!(in_store(&store, BOB, bobs.post.id));
        assert!(in_store(&store, ALICE, alices.post.id));
        assert_eq!(
            store.clear(BOB, &pairs([&bobs]), &free()),
            cleared(&[&bobs], None)
        );
        assert!(in_store(&store, ALICE, alices.post.id));
    }

    #[test]
    fn a_clear_stops_at_the_first_delete_the_disk_refuses() {
        let b = MemTaskBlobs::default();
        let (store, _) = wide(&b);
        let posts: Vec<_> = (1..=5).map(|i| put_as(&store, BOB, i, 2001)).collect();
        b.stick(Some(post_name(BOB, posts[2].post.id)));
        let got = store.clear(BOB, &pairs(&posts), &free());
        b.stick(None);
        assert_eq!(
            got,
            cleared(
                &[&posts[0], &posts[1]],
                Some(BoardRefusal::Store("sentinel-628-stuck".into()))
            )
        );
        assert_eq!(
            got.stopped.unwrap().to_string(),
            "store: sentinel-628-stuck"
        );
        assert!(store.held().expiring.is_empty());
        assert!(store.held().owed.is_empty());
        for s in &posts[2..] {
            assert!(store.get(BOB, s.post.id).is_some());
            assert!(b.has(&post_name(BOB, s.post.id)));
        }
        assert_eq!(ids(&store.candidates(BOB, 0, 10)), ids(&posts[2..]));
    }

    #[test]
    fn a_clear_whose_delete_does_not_sync_counts_the_post_removed_and_owes_it() {
        let b = MemTaskBlobs::default();
        let (store, _) = wide(&b);
        let posts: Vec<_> = (1..=2).map(|i| put_as(&store, BOB, i, 2001)).collect();
        b.fail(Some(Fail::UnsyncedUnlinks));
        let got = store.clear(BOB, &pairs(&posts), &free());
        b.fail(None);
        assert_eq!(
            got,
            cleared(
                &[&posts[0]],
                Some(BoardRefusal::Unavailable(UNSYNCED.into()))
            )
        );
        assert_eq!(
            store.held().owed,
            [(BOB, posts[0].post.id)].into_iter().collect()
        );
        assert!(store.held().expiring.is_empty());
        assert!(!in_store(&store, BOB, posts[0].post.id));
        assert!(store.get(BOB, posts[1].post.id).is_some());
        b.crash(0);
        assert!(
            b.has(&post_name(BOB, posts[0].post.id)),
            "the unlink was lost"
        );
        store.set_settings(BOB, Settings::default()).unwrap();
        assert!(!b.has(&post_name(BOB, posts[0].post.id)));
        assert!(store.held().owed.is_empty());
        assert_eq!(
            store.take_notices(),
            vec![BoardNotice::Settled {
                key: BOB,
                id: posts[0].post.id
            }]
        );
    }

    #[test]
    fn a_clear_deletes_nothing_while_the_owed_removals_are_at_their_bound() {
        let max = crate::board_store::BOARD_OWED_MAX;
        for below in [true, false] {
            let b = MemTaskBlobs::default();
            let (store, _) = wide(&b);
            let victim = put_as(&store, BOB, 0xa0, 2001);
            let n = max - usize::from(below);
            b.fail(Some(Fail::Unlinks));
            for i in 0..n {
                let armed = b.clone();
                b.after_save(move || armed.fail(Some(Fail::UnsyncedNoUnlink)));
                let refused = put_with(&store, vec![[i as u8 + 1; 16]], "owed");
                assert!(
                    matches!(refused, Err(BoardRefusal::Unavailable(_))),
                    "{refused:?}"
                );
                b.fail(Some(Fail::Unlinks));
            }
            assert_eq!(store.held().owed.len(), n);
            b.fail(Some(Fail::UnsyncedUnlinks));
            let got = store.clear(BOB, &pairs([&victim]), &free());
            b.fail(None);
            if below {
                assert_eq!(
                    got,
                    cleared(&[&victim], Some(BoardRefusal::Unavailable(UNSYNCED.into())))
                );
                assert_eq!(store.held().owed.len(), max);
                assert!(!in_store(&store, BOB, victim.post.id));
            } else {
                assert_eq!(
                    got,
                    cleared(&[], Some(BoardRefusal::Store("removals are owed".into())))
                );
                assert_eq!(store.held().owed.len(), max);
                assert!(in_store(&store, BOB, victim.post.id));
                assert!(b.has(&post_name(BOB, victim.post.id)));
            }
        }
    }

    #[test]
    fn a_clear_takes_at_most_a_page_whatever_it_is_passed() {
        let b = MemTaskBlobs::default();
        let (store, _) = wide(&b);
        let posts: Vec<_> = (1..=33).map(|i| put_as(&store, BOB, i, 2001)).collect();
        let got = store.clear(BOB, &pairs(&posts), &free());
        assert_eq!(got.removed, ids(&posts[..32]));
        assert_eq!(got.stopped, None);
        assert!(in_store(&store, BOB, posts[32].post.id));
        assert!(b.has(&post_name(BOB, posts[32].post.id)));
    }

    /// `clear` runs on another thread with every delete and save stalled; `during` runs
    /// once its first delete has begun, after the claim and before the outcome.
    fn clear_while(
        b: &MemTaskBlobs,
        store: &Arc<BoardStore>,
        named: Vec<(u64, PostId)>,
        during: impl FnOnce(),
    ) -> Cleared {
        b.slow(Some(std::time::Duration::from_millis(300)));
        let clearing = Arc::clone(store);
        let worker = std::thread::spawn(move || clearing.clear(BOB, &named, &free()));
        b.await_stalls(1);
        during();
        let got = worker.join().unwrap();
        b.slow(None);
        got
    }

    #[test]
    fn a_containment_marked_while_a_post_is_cleared_keeps_the_post() {
        for (uid, why) in [(2001, HeldFor::Author), (1000, HeldFor::Person)] {
            for unsynced in [false, true] {
                let b = MemTaskBlobs::default();
                let (store, _) = clocked(&b);
                let store = Arc::new(store);
                let kept = by(&store, BOB, hobi(), Some(2001), "sentinel-698-evidence");
                let other = by(&store, BOB, jin(), Some(2002), "sentinel-698-other");
                if unsynced {
                    b.fail(Some(Fail::UnsyncedUnlinks));
                }
                let got = clear_while(&b, &store, pairs([&kept, &other]), || {
                    store.mark(&containing(&[], &[uid]))
                });
                b.fail(None);
                let case = format!("{why:?} unsynced {unsynced}");
                let removed: &[&Arc<Stored>] = match (why, unsynced) {
                    (HeldFor::Author, _) => &[&other],
                    (HeldFor::Person, _) => &[],
                };
                let stopped = (unsynced && why == HeldFor::Author)
                    .then(|| BoardRefusal::Unavailable(UNSYNCED.into()));
                assert_eq!(got, cleared(removed, stopped), "{case}");
                assert!(!store.held().owed.contains(&(BOB, kept.post.id)), "{case}");
                assert!(store.held().expiring.is_empty(), "{case}");
                assert!(in_store(&store, BOB, kept.post.id), "{case}");
                assert!(store.get(BOB, kept.post.id).is_none(), "{case}: withheld");
                assert!(b.has(&post_name(BOB, kept.post.id)), "{case}: restored");
                let due = store.due(10);
                assert!(
                    whys(&due).contains(&(Some(kept.post.id), None, BoardDueFor::Hold(why))),
                    "{case}: {:?}",
                    whys(&due)
                );
                assert_eq!(store.perform(&due, &free()), due.len(), "{case}");
                assert_eq!(
                    stored_on_disk(&b, BOB, kept.post.id).held,
                    [why].into_iter().collect(),
                    "{case}"
                );
                drop(due);
                b.crash(0);
                let (reloaded, _) = clocked(&b);
                assert!(in_store(&reloaded, BOB, kept.post.id), "{case}");
                assert!(reloaded.get(BOB, kept.post.id).is_none(), "{case}: held");
            }
        }
    }

    #[test]
    fn a_containment_the_view_shows_after_the_unlink_keeps_the_post() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let kept = by(&store, BOB, hobi(), Some(2001), "sentinel-698-evidence");
        let got = store.clear(BOB, &pairs([&kept]), &installs(&[&[], &[2001]]));
        assert_eq!(got, cleared(&[], None));
        assert_eq!(
            store.held().marked.get(&(BOB, kept.seq)),
            Some(&[HeldFor::Author].into_iter().collect())
        );
        assert!(store.held().expiring.is_empty());
        assert!(b.has(&post_name(BOB, kept.post.id)));
        assert_eq!(store.perform(&store.due(10), &free()), 1);
        assert_eq!(
            stored_on_disk(&b, BOB, kept.post.id).held,
            [HeldFor::Author].into_iter().collect()
        );
    }

    #[test]
    fn a_containment_installed_after_the_clear_returned_does_not_bring_a_post_back() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let gone = by(&store, BOB, hobi(), Some(2001), "sentinel-698-gone");
        assert_eq!(
            store.clear(BOB, &pairs([&gone]), &free()),
            cleared(&[&gone], None)
        );
        store.mark(&containing(&[], &[2001, 1000]));
        assert!(store.due(10).is_empty());
        assert!(!in_store(&store, BOB, gone.post.id));
        assert!(!b.has(&post_name(BOB, gone.post.id)));
        drop(store);
        let (store, _) = clocked(&b);
        assert!(!in_store(&store, BOB, gone.post.id));
    }

    /// Contains nobody at the first check and uid 2001 from the second, and makes the disk
    /// refuse `name` (or stop syncing) as it first says so.
    struct ThenRefuse {
        b: MemTaskBlobs,
        name: String,
        unsynced: bool,
        calls: Mutex<usize>,
    }

    impl EnrollmentView for ThenRefuse {
        fn agent_uid(&self, _: &AgentId) -> Option<u32> {
            None
        }

        fn agents(&self) -> Vec<(AgentId, u32)> {
            Vec::new()
        }

        fn is_enrolled(&self, _: u32) -> bool {
            false
        }

        fn contained(&self, uid: u32) -> bool {
            self.contained_among(&[uid].into_iter().collect())
                .contains(&uid)
        }

        fn contained_among(&self, uids: &BTreeSet<u32>) -> BTreeSet<u32> {
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            if *calls < 2 {
                return BTreeSet::new();
            }
            match self.unsynced {
                true => self.b.fail(Some(Fail::Unsynced)),
                false => self.b.stick(Some(self.name.clone())),
            }
            uids.iter().copied().filter(|u| *u == 2001).collect()
        }

        fn unresolved(&self, _: u32) -> bool {
            false
        }

        fn board(&self, _: &AgentId) -> bool {
            false
        }
    }

    #[test]
    fn a_kept_post_whose_record_is_not_restored_stops_the_clear_and_is_not_removed() {
        for unsynced in [false, true] {
            let b = MemTaskBlobs::default();
            let (store, _) = clocked(&b);
            let kept = by(&store, BOB, hobi(), Some(2001), "sentinel-698-evidence");
            let next = by(&store, BOB, jin(), Some(2002), "sentinel-698-next");
            let name = post_name(BOB, kept.post.id);
            let view = ThenRefuse {
                b: b.clone(),
                name: name.clone(),
                unsynced,
                calls: Mutex::new(0),
            };
            let got = store.clear(BOB, &pairs([&kept, &next]), &view);
            b.fail(None);
            b.stick(None);
            let why = match unsynced {
                true => "sentinel-628-unsynced",
                false => "sentinel-628-stuck",
            };
            assert_eq!(
                got,
                cleared(
                    &[],
                    Some(BoardRefusal::Unavailable(format!(
                        "outcome unknown: contained during the clear; the record is not restored: {why}"
                    )))
                ),
                "unsynced {unsynced}"
            );
            assert_eq!(b.has(&name), unsynced);
            assert!(in_store(&store, BOB, kept.post.id));
            assert!(store.get(BOB, kept.post.id).is_none(), "marked");
            assert!(store.held().owed.is_empty());
            assert!(in_store(&store, BOB, next.post.id), "the clear stopped");
            assert_eq!(store.perform(&store.due(10), &free()), 1);
            assert_eq!(
                stored_on_disk(&b, BOB, kept.post.id).held,
                [HeldFor::Author].into_iter().collect()
            );
        }
    }

    /// Answers from `installed`; at its second answer, the re-check after a clear's unlink,
    /// it starts an install containing uid 2001 and gives it 300 ms before it answers what it
    /// read first. `landed` says whether the install ran in that time.
    struct InstallDuringTheRecheck {
        installed: Installed,
        store: Arc<BoardStore>,
        calls: Mutex<usize>,
        installer: Mutex<Option<std::thread::JoinHandle<()>>>,
        landed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl EnrollmentView for InstallDuringTheRecheck {
        fn agent_uid(&self, _: &AgentId) -> Option<u32> {
            None
        }

        fn agents(&self) -> Vec<(AgentId, u32)> {
            Vec::new()
        }

        fn is_enrolled(&self, _: u32) -> bool {
            false
        }

        fn contained(&self, uid: u32) -> bool {
            self.contained_among(&[uid].into_iter().collect())
                .contains(&uid)
        }

        fn contained_among(&self, uids: &BTreeSet<u32>) -> BTreeSet<u32> {
            let answer = self.installed.contained_among(uids);
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            if *calls == 2 {
                let (store, installed, landed) = (
                    Arc::clone(&self.store),
                    self.installed.clone(),
                    Arc::clone(&self.landed),
                );
                let (done, wait) = std::sync::mpsc::channel();
                *self.installer.lock().unwrap() = Some(std::thread::spawn(move || {
                    let view = installed.clone();
                    store.install_and_mark(
                        || {
                            installed.0.lock().unwrap().insert(2001);
                            landed.store(true, std::sync::atomic::Ordering::SeqCst);
                        },
                        &view,
                    );
                    let _ = done.send(());
                }));
                let _ = wait.recv_timeout(std::time::Duration::from_millis(300));
            }
            answer
        }

        fn unresolved(&self, _: u32) -> bool {
            false
        }

        fn board(&self, _: &AgentId) -> bool {
            false
        }
    }

    #[test]
    fn an_install_cannot_land_between_a_clears_recheck_and_its_forget() {
        let b = MemTaskBlobs::default();
        let (store, _) = clocked(&b);
        let store = Arc::new(store);
        let post = by(&store, BOB, hobi(), Some(2001), "sentinel-698-raced");
        let view = InstallDuringTheRecheck {
            installed: Installed::default(),
            store: Arc::clone(&store),
            calls: Mutex::new(0),
            installer: Mutex::new(None),
            landed: Arc::default(),
        };
        let got = store.clear(BOB, &pairs([&post]), &view);
        let landed = view.landed.load(std::sync::atomic::Ordering::SeqCst);
        view.installer
            .lock()
            .unwrap()
            .take()
            .expect("the re-check started the install")
            .join()
            .unwrap();
        assert!(
            !landed,
            "the install landed while the clear held its check: contained and removed"
        );
        assert_eq!(got, cleared(&[&post], None), "the clear came first");
        assert!(!in_store(&store, BOB, post.post.id));
        assert!(!b.has(&post_name(BOB, post.post.id)));
        assert!(store.due(10).is_empty(), "nothing is brought back to hold");

        let kept = by(&store, BOB, hobi(), Some(2001), "sentinel-698-kept");
        let page = store.clearable(BOB).0;
        assert_eq!(page, pairs([&kept]));
        let installed = Installed::default();
        store.install_and_mark(
            || {
                installed.0.lock().unwrap().insert(2001);
            },
            &installed,
        );
        assert_eq!(
            store.clear(BOB, &page, &installed),
            cleared(&[], None),
            "the install came first"
        );
        assert!(in_store(&store, BOB, kept.post.id));
        assert!(b.has(&post_name(BOB, kept.post.id)));
        assert_eq!(
            whys(&store.due(10)),
            vec![(Some(kept.post.id), None, BoardDueFor::Hold(HeldFor::Author))]
        );
    }

    #[test]
    fn installs_and_every_board_call_run_together_without_a_deadlock() {
        use maknae_authz_basic::Baseline;
        let (_g, pdp) = crate::test_fixtures::shipped_composition();
        let (_h, adversary) = crate::test_fixtures::shipped_composition_with(
            "",
            Some("schema_version: 1\nbindings:\n  adversary: [\"nobody\"]\n"),
        );
        let author = nix::unistd::User::from_name("nobody")
            .unwrap()
            .expect("the nobody account exists on every supported host")
            .uid
            .as_raw();
        let pdp = Arc::new(pdp);
        let view = crate::enrollment::SnapshotEnrollment(Arc::clone(&pdp));
        let snapshots = [pdp.baseline().snapshot(), adversary.baseline().snapshot()];
        for (snapshot, contained) in snapshots.iter().zip([false, true]) {
            pdp.baseline().install(Arc::clone(snapshot));
            assert_eq!(view.contained(author), contained);
        }
        let b = MemTaskBlobs::default();
        let (store, _) = wide(&b);
        let store = Arc::new(store);
        let tasks = Arc::new(crate::task::TaskStore::new());
        let (done, finished) = std::sync::mpsc::channel::<&str>();
        let rounds = 200;
        let mut workers = Vec::new();
        let mut spawn = |name: &'static str, work: Box<dyn Fn(usize) + Send>| {
            let done = done.clone();
            workers.push(std::thread::spawn(move || {
                for i in 0..rounds {
                    work(i);
                }
                let _ = done.send(name);
            }));
        };
        {
            let (store, tasks, pdp, view) = (
                Arc::clone(&store),
                Arc::clone(&tasks),
                Arc::clone(&pdp),
                view.clone(),
            );
            let snapshots = snapshots.clone();
            spawn(
                "install",
                Box::new(move |i| {
                    let next = Arc::clone(&snapshots[i % 2]);
                    store.install_and_mark(|| pdp.baseline().install(next), &view);
                    tasks.mark_unenrolled(&view);
                }),
            );
        }
        {
            let (store, view) = (Arc::clone(&store), view.clone());
            spawn(
                "post and clear",
                Box::new(move |i| {
                    let _ = store.post(
                        BOB,
                        (hobi(), Some(author)),
                        None,
                        PostLabels::default(),
                        draft("sentinel-698-load"),
                        &view,
                    );
                    if i % 8 == 0 {
                        let page = store.clearable(BOB).0;
                        store.clear(BOB, &page, &view);
                    }
                }),
            );
        }
        {
            let (store, view) = (Arc::clone(&store), view.clone());
            spawn(
                "read",
                Box::new(move |_| {
                    let seqs: Vec<u64> =
                        store.candidates(BOB, 0, 32).iter().map(|s| s.seq).collect();
                    store.observe(BOB, &seqs, (0, u64::MAX), &view);
                }),
            );
        }
        {
            let store = Arc::clone(&store);
            spawn(
                "settings",
                Box::new(move |i| {
                    let _ = store.write_settings(
                        BOB,
                        Settings {
                            enabled: i % 2 == 0,
                            ..Settings::default()
                        },
                    );
                }),
            );
        }
        {
            let (store, view) = (Arc::clone(&store), view.clone());
            spawn(
                "gate",
                Box::new(move |_| {
                    store.enabled_with(BOB, || view.board(&reader("hobi")));
                }),
            );
        }
        drop(done);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut ended = Vec::new();
        while ended.len() < workers.len() {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match finished.recv_timeout(left) {
                Ok(name) => ended.push(name),
                Err(_) => panic!("deadlocked: only {ended:?} finished"),
            }
        }
        for w in workers {
            w.join().unwrap();
        }
        assert!(
            view.contained(author),
            "the last install contains the author"
        );
        let left = store.held().boards[&BOB].posts.len();
        assert!(left > 0);
        assert!(
            store.candidates(BOB, 0, 1024).is_empty(),
            "every post left is marked"
        );
        store.install_and_mark(|| pdp.baseline().install(Arc::clone(&snapshots[0])), &view);
        assert_eq!(
            store.candidates(BOB, 0, 1024).len(),
            left,
            "every mark is dropped"
        );
        store.install_and_mark(|| pdp.baseline().install(Arc::clone(&snapshots[1])), &view);
        assert!(
            store.candidates(BOB, 0, 1024).is_empty(),
            "every post is marked again"
        );
    }
}
