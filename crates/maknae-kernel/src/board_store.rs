//! The board store at rest (#695): one sealed record per post, per board and per reader's
//! cursor, under `STATE_DIR/board` with the graph key.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use maknae_config::AgentId;
use maknae_proto::{Post, PostId};
use serde::{Deserialize, Serialize};

use crate::conversation::dir_store::Layout;
use crate::task_store::{RootTasker, StoreError, TaskBlobs};

pub const BOARD_RECORD_MAX: u64 =
    (maknae_proto::BOARD_POST_MAX_BYTES + 2 * maknae_proto::BOARD_ENVELOPE) as u64;

pub const BOARD: Layout = Layout {
    what: "board",
    suffix: ".board",
    max_bytes: BOARD_RECORD_MAX,
};

pub const BOARD_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The first sequence a board issues; a cursor of 0 has read nothing.
pub const FIRST_SEQ: u64 = 1;
/// The most post removals the store may owe; past it, a post or a clear is refused before
/// any write.
pub const BOARD_OWED_MAX: usize = 32;
/// The most posts one clear removes; equal to the read page.
pub const BOARD_CLEAR_PAGE: usize = 32;

/// A board belongs to the person at the root of a task chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoardKey(pub u32);

impl BoardKey {
    pub fn of(root: &RootTasker) -> Option<Self> {
        match root {
            RootTasker::Person { uid } => Some(BoardKey(*uid)),
            RootTasker::Agent { .. } => None,
        }
    }

    pub fn partition(self) -> String {
        format!("users/{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LabelValue {
    Str(String),
    Set(BTreeSet<String>),
}

/// Keyed `<namespace>.<key>`; stamped by the kernel, never supplied by the author.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostLabels(pub BTreeMap<String, LabelValue>);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HeldFor {
    Author,
    Person,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stored {
    pub post: Post,
    pub seq: u64,
    pub author_uid: Option<u32>,
    pub labels: PostLabels,
    pub held: BTreeSet<HeldFor>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub report: Report,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Report {
    #[default]
    Off,
    Summary,
    Every,
}

/// What boot must record in the trail before it calls `BoardStore::settle`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoardFinding {
    Quarantined { name: String, why: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadPlan {
    pub cursor: u64,
    pub ack_to: Option<u64>,
    /// The board's highest sequence when the read was admitted; the read walks no further.
    pub upper: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PostRecord<S> {
    pub board: u32,
    pub stored: S,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BoardRecord {
    pub board: u32,
    pub next_seq: u64,
    pub settings: Settings,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CursorRecord {
    pub board: u32,
    pub agent: String,
    pub cursor: u64,
}

pub(crate) enum Name {
    Post(BoardKey, PostId),
    Board(BoardKey),
    Cursor(BoardKey, AgentId),
}

impl Name {
    pub fn text(&self) -> String {
        match self {
            Name::Post(key, id) => format!("post.{}.{id}", key.0),
            Name::Board(key) => format!("board.{}", key.0),
            Name::Cursor(key, agent) => format!("cursor.{}.{}", key.0, agent.as_str()),
        }
    }

    /// Only a name that [`Name::text`] writes back unchanged.
    fn parse(name: &str) -> Option<Name> {
        let mut parts = name.splitn(3, '.');
        let kind = parts.next()?;
        let key = BoardKey(parts.next()?.parse().ok()?);
        let rest = parts.next();
        let parsed = match (kind, rest) {
            ("post", Some(id)) => Name::Post(key, id.parse().ok()?),
            ("board", None) => Name::Board(key),
            ("cursor", Some(agent)) => Name::Cursor(key, AgentId::parse(agent).ok()?),
            _ => return None,
        };
        (parsed.text() == name).then_some(parsed)
    }
}

pub(crate) struct Board {
    pub next_seq: u64,
    pub settings: Settings,
    pub posts: BTreeMap<u64, Arc<Stored>>,
    pub ids: BTreeMap<PostId, u64>,
    pub cursors: BTreeMap<AgentId, u64>,
    /// Per reader, the sequences sent in a written reply and not yet acknowledged past.
    pub sent: BTreeMap<AgentId, BTreeSet<u64>>,
}

impl Default for Board {
    fn default() -> Self {
        Board {
            next_seq: FIRST_SEQ,
            settings: Settings::default(),
            posts: BTreeMap::new(),
            ids: BTreeMap::new(),
            cursors: BTreeMap::new(),
            sent: BTreeMap::new(),
        }
    }
}

impl Board {
    pub fn record(&self, key: BoardKey) -> BoardRecord {
        BoardRecord {
            board: key.0,
            next_seq: self.next_seq,
            settings: self.settings,
        }
    }
}

pub(crate) struct Loaded {
    pub boards: BTreeMap<BoardKey, Board>,
    pub findings: Vec<BoardFinding>,
}

fn decode<T: serde::de::DeserializeOwned>(blobs: &dyn TaskBlobs, name: &str) -> Result<T, String> {
    let plain = blobs.load(name).map_err(|e| e.to_string())?;
    ciborium::from_reader(plain.as_slice()).map_err(|_| "the record does not decode".into())
}

const MISNAMED: &str = "the record names another";

/// Every record, read once at open. A board's sequence, `FIRST_SEQ` when its record is
/// missing, must be above every stored post's and cursor's.
pub(crate) fn load(blobs: &dyn TaskBlobs) -> Result<Loaded, StoreError> {
    let mut names = blobs.names()?;
    names.sort();
    let mut boards: BTreeMap<BoardKey, Board> = BTreeMap::new();
    let mut findings = Vec::new();
    for name in names {
        let read = match Name::parse(&name) {
            None => Err("the name is not a board record".to_string()),
            Some(Name::Board(key)) => decode::<BoardRecord>(blobs, &name).and_then(|rec| {
                if rec.board != key.0 {
                    return Err(MISNAMED.into());
                }
                let board = boards.entry(key).or_default();
                board.next_seq = rec.next_seq;
                board.settings = rec.settings;
                Ok(())
            }),
            Some(Name::Post(key, id)) => {
                decode::<PostRecord<Stored>>(blobs, &name).and_then(|rec| {
                    if rec.board != key.0 || rec.stored.post.id != id {
                        return Err(MISNAMED.into());
                    }
                    let board = boards.entry(key).or_default();
                    if board.posts.contains_key(&rec.stored.seq) {
                        return Err("the sequence is another post's".into());
                    }
                    board.ids.insert(id, rec.stored.seq);
                    board.posts.insert(rec.stored.seq, Arc::new(rec.stored));
                    Ok(())
                })
            }
            Some(Name::Cursor(key, agent)) => {
                decode::<CursorRecord>(blobs, &name).and_then(|rec| {
                    if rec.board != key.0 || rec.agent != agent.as_str() {
                        return Err(MISNAMED.into());
                    }
                    boards
                        .entry(key)
                        .or_default()
                        .cursors
                        .insert(agent, rec.cursor);
                    Ok(())
                })
            }
        };
        if let Err(why) = read {
            findings.push(BoardFinding::Quarantined { name, why });
        }
    }
    for (key, board) in &boards {
        let top = board
            .posts
            .keys()
            .chain(board.cursors.values())
            .copied()
            .max()
            .unwrap_or(0);
        if board.next_seq <= top {
            return Err(StoreError::Counters(format!(
                "of board {} are missing or behind a stored post or cursor",
                key.0
            )));
        }
    }
    Ok(Loaded { boards, findings })
}
