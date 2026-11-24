//! The agent message board's wire types (#695, ADR-0040).
use crate::{Labels, ProtoCodecError, SecretText, TaskId};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

pub const BOARD_POST_MAX_BYTES: usize = 32 * 1024;
pub const BOARD_POSTS_MAX: usize = 1024;
pub const BOARD_AUTHOR_POSTS_MAX: usize = 128;
pub const BOARD_READ_PAGE_POSTS: usize = 32;
pub const BOARD_ENVELOPE: usize = 4096;
pub const BOARD_ADDRESSEES_MAX: usize = 8;
pub const BOARD_ATTACHMENTS_MAX: usize = 8;
pub const BOARD_LABEL_MAX_BYTES: usize = 64;
const AGENT_ID_MAX_BYTES: usize = 32;

/// Kernel-assigned; 16 CBOR bytes on the wire, 32 lowercase hex digits in text.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PostId(pub [u8; 16]);

impl Serialize for PostId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for PostId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> de::Visitor<'de> for V {
            type Value = PostId;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a 16-byte byte string")
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<PostId, E> {
                <[u8; 16]>::try_from(v.as_slice())
                    .map(PostId)
                    .map_err(|_| E::invalid_length(v.len(), &self))
            }
        }
        d.deserialize_byte_buf(V)
    }
}

impl std::fmt::Display for PostId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostIdTextError;

impl std::fmt::Display for PostIdTextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a post id is 32 lowercase hex digits")
    }
}
impl std::error::Error for PostIdTextError {}

impl std::str::FromStr for PostId {
    type Err = PostIdTextError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fn nibble(c: u8) -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                _ => None,
            }
        }
        let text: &[u8; 32] = s.as_bytes().try_into().map_err(|_| PostIdTextError)?;
        let (pairs, _) = text.as_chunks::<2>();
        let mut id = [0u8; 16];
        for (out, [hi, lo]) in id.iter_mut().zip(pairs) {
            let (Some(hi), Some(lo)) = (nibble(*hi), nibble(*lo)) else {
                return Err(PostIdTextError);
            };
            *out = hi * 16 + lo;
        }
        Ok(PostId(id))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PostKind {
    Note,
    Question,
    Answer,
    Intent,
}

impl PostKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PostKind::Note => "note",
            PostKind::Question => "question",
            PostKind::Answer => "answer",
            PostKind::Intent => "intent",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Addressee {
    Agents(#[serde(deserialize_with = "bounded_agents")] Vec<String>),
    Tasker,
    Board,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Media {
    TextPlain,
    TextMarkdown,
    TextDiff,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub label: String,
    pub media: Media,
    pub content: SecretText,
}

impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attachment")
            .field("label_bytes", &self.label.len())
            .field("media", &self.media)
            .field("content", &self.content)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "PostDraftWire")]
pub struct PostDraft {
    pub kind: PostKind,
    pub to: Addressee,
    pub in_reply_to: Option<PostId>,
    pub body: SecretText,
    pub attachments: Vec<Attachment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PostDraftWire {
    kind: PostKind,
    to: Addressee,
    in_reply_to: Option<PostId>,
    body: SecretText,
    #[serde(deserialize_with = "bounded_attachments")]
    attachments: Vec<Attachment>,
}

fn bounded_agents<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    bounded(d, BOARD_ADDRESSEES_MAX, |n| {
        format!("board post addresses {n} agents, not 1 to {BOARD_ADDRESSEES_MAX}")
    })
}

fn bounded_attachments<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Attachment>, D::Error> {
    bounded(d, BOARD_ATTACHMENTS_MAX, |n| {
        format!("board post has {n} attachments, over {BOARD_ATTACHMENTS_MAX}")
    })
}

/// A sequence of at most `max` entries: past `max` the rest are counted, never decoded.
fn bounded<'de, D, T>(d: D, max: usize, over: fn(usize) -> String) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct V<T> {
        max: usize,
        over: fn(usize) -> String,
        of: std::marker::PhantomData<T>,
    }
    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for V<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a sequence of at most {} entries", self.max)
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            if let Some(n) = seq.size_hint().filter(|n| *n > self.max) {
                return Err(de::Error::custom((self.over)(n)));
            }
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(self.max));
            while out.len() < self.max {
                match seq.next_element()? {
                    Some(item) => out.push(item),
                    None => return Ok(out),
                }
            }
            let mut n = self.max;
            while seq.next_element::<de::IgnoredAny>()?.is_some() {
                n = n.saturating_add(1);
            }
            if n > self.max {
                return Err(de::Error::custom((self.over)(n)));
            }
            Ok(out)
        }
    }
    d.deserialize_seq(V {
        max,
        over,
        of: std::marker::PhantomData,
    })
}

impl TryFrom<PostDraftWire> for PostDraft {
    type Error = String;
    fn try_from(w: PostDraftWire) -> Result<Self, String> {
        let draft = PostDraft {
            kind: w.kind,
            to: w.to,
            in_reply_to: w.in_reply_to,
            body: w.body,
            attachments: w.attachments,
        };
        draft.check()?;
        Ok(draft)
    }
}

impl PostDraft {
    pub fn content_len(&self) -> usize {
        self.attachments
            .iter()
            .map(|a| a.label.len().saturating_add(a.content.0.len()))
            .fold(self.body.0.len(), usize::saturating_add)
    }

    fn check(&self) -> Result<(), String> {
        if let Addressee::Agents(ids) = &self.to {
            if !(1..=BOARD_ADDRESSEES_MAX).contains(&ids.len()) {
                return Err(format!(
                    "board post addresses {} agents, not 1 to {BOARD_ADDRESSEES_MAX}",
                    ids.len()
                ));
            }
            if ids
                .iter()
                .any(|id| !(1..=AGENT_ID_MAX_BYTES).contains(&id.len()))
            {
                return Err(format!(
                    "board post addressee id is not 1 to {AGENT_ID_MAX_BYTES} bytes"
                ));
            }
            let mut seen: Vec<&str> = ids.iter().map(String::as_str).collect();
            seen.sort_unstable();
            if seen.windows(2).any(|p| p[0] == p[1]) {
                return Err("board post addresses an agent more than once".into());
            }
        }
        for a in &self.attachments {
            if a.label.is_empty() || a.label.len() > BOARD_LABEL_MAX_BYTES {
                return Err(format!(
                    "board attachment label is not 1 to {BOARD_LABEL_MAX_BYTES} bytes"
                ));
            }
            if a.label.chars().any(char::is_control) {
                return Err("board attachment label holds a control character".into());
            }
        }
        if self.body.0.is_empty() {
            return Err("board post body is empty".into());
        }
        let len = self.content_len();
        if len > BOARD_POST_MAX_BYTES {
            return Err(format!(
                "board post content of {len} bytes exceeds {BOARD_POST_MAX_BYTES}"
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for PostDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostDraft")
            .field("kind", &self.kind)
            .field("to", &self.to)
            .field("in_reply_to", &self.in_reply_to)
            .field("body", &self.body)
            .field("attachments", &self.attachments)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Author {
    Agent(String),
    Tasker(u32),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Post {
    pub id: PostId,
    pub author: Author,
    pub task: Option<TaskId>,
    pub at_secs: i64,
    pub labels: Labels,
    pub draft: PostDraft,
}

impl std::fmt::Debug for Post {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Post")
            .field("id", &self.id)
            .field("author", &self.author)
            .field("task", &self.task)
            .field("at_secs", &self.at_secs)
            .field("labels", &self.labels)
            .field("draft", &self.draft)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardPage {
    pub posts: Vec<Post>,
    pub more: bool,
}

impl std::fmt::Debug for BoardPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoardPage")
            .field("posts", &self.posts)
            .field("more", &self.more)
            .finish()
    }
}

/// Why a permitted board request was not carried out; availability, never policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoardDefect {
    TryAgain,
    OutcomeUnknown,
    Full,
    AuthorAtCap,
    NoSuchPost,
}

impl BoardDefect {
    pub const ALL: [BoardDefect; 5] = [
        BoardDefect::TryAgain,
        BoardDefect::OutcomeUnknown,
        BoardDefect::Full,
        BoardDefect::AuthorAtCap,
        BoardDefect::NoSuchPost,
    ];
}

/// What the board reports to its tasker.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoardReport {
    #[default]
    Off,
    Summary,
    Every,
}

/// A tasker's three board settings, each off by default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardSettings {
    pub enabled: bool,
    pub participate: bool,
    pub report: BoardReport,
}

/// A `board.manage` operation on the caller's own board; `set: None` reads the settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoardOp {
    Settings { set: Option<BoardSettings> },
    Clear,
}

/// What one `board.manage` clear removed, and whether posts that are not held remain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardCleared {
    pub removed: u32,
    pub more: bool,
}

pub fn board_refused_message(d: BoardDefect) -> &'static str {
    match d {
        BoardDefect::TryAgain => "try again",
        BoardDefect::OutcomeUnknown => "outcome unknown",
        BoardDefect::Full => "board full",
        BoardDefect::AuthorAtCap => "author at cap",
        BoardDefect::NoSuchPost => "no such post",
    }
}

pub fn board_page_budget(prompt_max_bytes: usize) -> usize {
    prompt_max_bytes.saturating_sub(BOARD_ENVELOPE)
}

struct Counter(usize);

impl std::io::Write for Counter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn post_content_bytes(
    draft: &PostDraft,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ProtoCodecError> {
    let content = (&draft.body, &draft.attachments);
    let mut counter = Counter(0);
    ciborium::into_writer(&content, &mut counter)
        .map_err(|e| ProtoCodecError::Encode(e.to_string()))?;
    let mut buf = zeroize::Zeroizing::new(vec![0; counter.0]);
    let mut writer = std::io::Cursor::new(buf.as_mut_slice());
    ciborium::into_writer(&content, &mut writer)
        .map_err(|e| ProtoCodecError::Encode(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "sentinel-695-body";
    const ATT: &str = "sentinel-695-att";

    fn enc<T: Serialize>(v: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(v, &mut buf).unwrap();
        buf
    }

    fn dec<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, String> {
        ciborium::from_reader(b).map_err(|e| e.to_string())
    }

    fn text(s: &str) -> SecretText {
        SecretText(zeroize::Zeroizing::new(s.to_owned()))
    }

    fn draft() -> PostDraft {
        PostDraft {
            kind: PostKind::Note,
            to: Addressee::Board,
            in_reply_to: None,
            body: text(BODY),
            attachments: vec![Attachment {
                label: "log".into(),
                media: Media::TextPlain,
                content: text(ATT),
            }],
        }
    }

    #[test]
    fn board_settings_and_ops_have_their_wire_spellings() {
        use ciborium::Value;
        let settings = BoardSettings {
            enabled: true,
            participate: false,
            report: BoardReport::Summary,
        };
        let as_value = |b: &[u8]| ciborium::from_reader::<Value, _>(b).unwrap();
        let text = |s: &str| Value::Text(s.into());
        let settings_value = Value::Map(vec![
            (text("enabled"), Value::Bool(true)),
            (text("participate"), Value::Bool(false)),
            (text("report"), text("summary")),
        ]);
        assert_eq!(as_value(&enc(&settings)), settings_value);
        for (report, spelled) in [
            (BoardReport::Off, "off"),
            (BoardReport::Summary, "summary"),
            (BoardReport::Every, "every"),
        ] {
            assert_eq!(as_value(&enc(&report)), text(spelled));
            assert_eq!(dec::<BoardReport>(&enc(&report)), Ok(report));
        }
        assert_eq!(BoardReport::default(), BoardReport::Off);
        assert_eq!(
            BoardSettings::default(),
            BoardSettings {
                enabled: false,
                participate: false,
                report: BoardReport::Off
            }
        );
        assert_eq!(as_value(&enc(&BoardOp::Clear)), text("clear"));
        assert_eq!(
            as_value(&enc(&BoardOp::Settings { set: None })),
            Value::Map(vec![(
                text("settings"),
                Value::Map(vec![(text("set"), Value::Null)])
            )])
        );
        assert_eq!(
            as_value(&enc(&BoardOp::Settings {
                set: Some(settings)
            })),
            Value::Map(vec![(
                text("settings"),
                Value::Map(vec![(text("set"), settings_value)])
            )])
        );
        for op in [
            BoardOp::Clear,
            BoardOp::Settings { set: None },
            BoardOp::Settings {
                set: Some(settings),
            },
        ] {
            assert_eq!(dec::<BoardOp>(&enc(&op)), Ok(op));
        }
    }

    #[test]
    fn board_cleared_has_its_wire_spelling_and_refuses_an_unknown_key() {
        use ciborium::Value;
        let text = |s: &str| Value::Text(s.into());
        let cleared = BoardCleared {
            removed: 32,
            more: true,
        };
        let fields = vec![
            (text("removed"), Value::Integer(32.into())),
            (text("more"), Value::Bool(true)),
        ];
        assert_eq!(
            ciborium::from_reader::<Value, _>(enc(&cleared).as_slice()).unwrap(),
            Value::Map(fields.clone())
        );
        assert_eq!(dec::<BoardCleared>(&enc(&cleared)), Ok(cleared));
        let mut extra = fields;
        extra.push((text("ids"), Value::Array(vec![])));
        let refused = dec::<BoardCleared>(&enc(&Value::Map(extra))).unwrap_err();
        assert!(refused.contains("unknown field `ids`"), "{refused}");
    }

    #[test]
    fn board_settings_refuse_an_unknown_or_missing_key() {
        use ciborium::Value;
        let text = |s: &str| Value::Text(s.into());
        let mut fields = vec![
            (text("enabled"), Value::Bool(true)),
            (text("participate"), Value::Bool(true)),
            (text("report"), text("every")),
        ];
        let decoded = |f: &[(Value, Value)]| dec::<BoardSettings>(&enc(&Value::Map(f.to_vec())));
        assert_eq!(
            decoded(&fields),
            Ok(BoardSettings {
                enabled: true,
                participate: true,
                report: BoardReport::Every
            })
        );
        fields.push((text("hidden"), Value::Bool(true)));
        let extra = decoded(&fields).unwrap_err();
        assert!(extra.contains("unknown field `hidden`"), "{extra}");
        fields.truncate(2);
        let missing = decoded(&fields).unwrap_err();
        assert!(missing.contains("missing field `report`"), "{missing}");
        let loud = decoded(&[
            (text("enabled"), Value::Bool(true)),
            (text("participate"), Value::Bool(true)),
            (text("report"), text("Every")),
        ])
        .unwrap_err();
        assert!(loud.contains("unknown variant `Every`"), "{loud}");
        let truthy = decoded(&[
            (text("enabled"), Value::Integer(1.into())),
            (text("participate"), Value::Bool(true)),
            (text("report"), text("off")),
        ]);
        assert!(truthy.is_err(), "{truthy:?}");
    }

    #[test]
    fn a_post_id_round_trips_as_hex() {
        let id = PostId([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f,
            0x69, 0x78,
        ]);
        assert_eq!(id.to_string(), "0123456789abcdef0a1b2c3d4e5f6978");
        assert_eq!(id.to_string().parse::<PostId>(), Ok(id));
        assert_eq!(dec::<PostId>(&enc(&id)), Ok(id));
        for bad in [
            "",
            "0123456789ABCDEF0a1b2c3d4e5f6978",
            "0123456789abcdef0a1b2c3d4e5f69",
            "0123456789abcdef0a1b2c3d4e5f69zz",
        ] {
            assert_eq!(bad.parse::<PostId>(), Err(PostIdTextError), "{bad}");
        }
        for n in [15, 17] {
            assert!(dec::<PostId>(&enc(&crate::Bytes::new(vec![0u8; n].into()))).is_err());
        }
    }

    #[test]
    fn a_draft_decodes_when_it_is_within_every_bound() {
        let mut d = draft();
        d.to = Addressee::Agents(
            (0..8)
                .map(|i| {
                    if i == 0 {
                        "a".repeat(32)
                    } else {
                        format!("agent-{i}")
                    }
                })
                .collect(),
        );
        d.attachments = (0..8)
            .map(|i| Attachment {
                label: if i == 0 {
                    "l".repeat(64)
                } else {
                    format!("a{i}")
                },
                media: Media::TextDiff,
                content: text("x"),
            })
            .collect();
        let labels: usize = d.attachments.iter().map(|a| a.label.len() + 1).sum();
        d.body = text(&"b".repeat(BOARD_POST_MAX_BYTES - labels));
        assert_eq!(d.content_len(), BOARD_POST_MAX_BYTES);
        assert_eq!(dec::<PostDraft>(&enc(&d)), Ok(d));
    }

    #[test]
    fn a_draft_is_refused_for_each_broken_rule() {
        let agents = |ids: Vec<String>| PostDraft {
            to: Addressee::Agents(ids),
            ..draft()
        };
        let with_label = |l: &str| {
            let mut d = draft();
            d.attachments[0].label = l.into();
            d
        };
        let mut over = draft();
        over.body = text(&"b".repeat(BOARD_POST_MAX_BYTES - 3 - ATT.len() + 1));
        assert_eq!(over.content_len(), BOARD_POST_MAX_BYTES + 1);
        let mut many = draft();
        many.attachments = vec![many.attachments[0].clone(); 9];
        let mut empty = draft();
        empty.body = text("");
        let rows: Vec<(PostDraft, &str)> = vec![
            (agents(vec![]), "addresses 0 agents"),
            (
                agents((0..9).map(|i| format!("a{i}")).collect()),
                "addresses 9 agents",
            ),
            (agents(vec!["a".repeat(33)]), "not 1 to 32 bytes"),
            (agents(vec![String::new()]), "not 1 to 32 bytes"),
            (agents(vec!["a".into(), "a".into()]), "more than once"),
            (many, "9 attachments"),
            (with_label(""), "label is not 1 to 64"),
            (with_label(&"l".repeat(65)), "label is not 1 to 64"),
            (with_label("a\nb"), "control character"),
            (empty, "body is empty"),
            (over, "exceeds"),
        ];
        for (d, fragment) in rows {
            let err = dec::<PostDraft>(&enc(&d)).unwrap_err();
            assert!(err.contains(fragment), "{err} lacks {fragment}");
        }
    }

    /// `d` encoded, with `extra` appended to the array found under `path` from the top.
    fn with_extra(d: &PostDraft, path: &[&str], extra: ciborium::Value) -> Vec<u8> {
        let mut v = ciborium::Value::serialized(d).unwrap();
        let mut at = &mut v;
        for key in path {
            let ciborium::Value::Map(entries) = at else {
                panic!("not a map at {key}");
            };
            at = entries
                .iter_mut()
                .find(|(k, _)| k.as_text() == Some(*key))
                .map(|(_, v)| v)
                .unwrap();
        }
        let ciborium::Value::Array(items) = at else {
            panic!("not an array");
        };
        items.push(extra);
        enc(&v)
    }

    #[test]
    fn a_ninth_entry_is_refused_for_the_count_before_it_is_decoded() {
        let malformed = ciborium::Value::Integer(7.into());
        let mut d = draft();
        d.attachments = vec![d.attachments[0].clone(); 8];
        let err =
            dec::<PostDraft>(&with_extra(&d, &["attachments"], malformed.clone())).unwrap_err();
        assert!(err.contains("9 attachments"), "{err}");
        let mut d = draft();
        d.to = Addressee::Agents((0..8).map(|i| format!("a{i}")).collect());
        let err = dec::<PostDraft>(&with_extra(&d, &["to", "Agents"], malformed)).unwrap_err();
        assert!(err.contains("addresses 9 agents"), "{err}");
    }

    #[test]
    fn a_sequence_of_unknown_length_is_counted_past_the_bound() {
        use serde::de::value::{Error, SeqDeserializer};
        let names: Vec<String> = (0..10).map(|i| format!("a{i}")).collect();
        let unsized_seq = |n: usize| {
            SeqDeserializer::<_, Error>::new(names[..n].iter().map(String::as_str).filter(|_| true))
        };
        assert_eq!(bounded_agents(unsized_seq(8)).unwrap(), names[..8]);
        let err = bounded_agents(unsized_seq(10)).unwrap_err().to_string();
        assert!(err.contains("addresses 10 agents"), "{err}");
    }

    #[test]
    fn a_post_id_text_error_and_each_kind_name_themselves() {
        assert_eq!(
            PostIdTextError.to_string(),
            "a post id is 32 lowercase hex digits"
        );
        for (kind, name) in [
            (PostKind::Note, "note"),
            (PostKind::Question, "question"),
            (PostKind::Answer, "answer"),
            (PostKind::Intent, "intent"),
        ] {
            assert_eq!(kind.as_str(), name);
        }
    }

    #[test]
    fn a_bounded_sequence_refuses_what_is_not_one_and_any_entry_it_cannot_decode() {
        let mut d = draft();
        d.to = Addressee::Agents(vec!["a".into()]);
        let mut v = ciborium::Value::serialized(&d).unwrap();
        let ciborium::Value::Map(entries) = &mut v else {
            panic!("not a map");
        };
        let to = entries
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("to"))
            .map(|(_, v)| v)
            .unwrap();
        *to = ciborium::Value::Map(vec![(
            ciborium::Value::Text("Agents".into()),
            ciborium::Value::Integer(7.into()),
        )]);
        let err = dec::<PostDraft>(&enc(&v)).unwrap_err();
        assert!(
            err.contains("invalid type: integer `7`, expected array"),
            "{err}"
        );
        use serde::de::IntoDeserializer;
        let err =
            bounded_agents(IntoDeserializer::<serde::de::value::Error>::into_deserializer(7u32))
                .unwrap_err()
                .to_string();
        assert_eq!(
            err,
            "invalid type: integer `7`, expected a sequence of at most 8 entries"
        );
        let err = dec::<PostDraft>(&with_extra(
            &PostDraft {
                attachments: Vec::new(),
                ..draft()
            },
            &["attachments"],
            ciborium::Value::Integer(7.into()),
        ))
        .unwrap_err();
        assert!(err.contains("invalid type: integer `7`"), "{err}");
        let mut indefinite = vec![0x9f];
        for i in 0..8u8 {
            indefinite.extend([0x62, b'a', b'0' + i]);
        }
        indefinite.extend([0x63, b'z']);
        #[derive(Debug, Deserialize)]
        #[serde(transparent)]
        struct Agents(#[serde(deserialize_with = "bounded_agents")] Vec<String>);
        let err = dec::<Agents>(&indefinite).map(|a| a.0).unwrap_err();
        assert!(
            !err.contains("agents"),
            "a truncated ninth entry fails to read: {err}"
        );
    }

    #[test]
    fn an_attachment_debugs_as_its_sizes_and_media_only() {
        let a = Attachment {
            label: "log".into(),
            media: Media::TextDiff,
            content: text(ATT),
        };
        assert_eq!(
            format!("{a:?}"),
            "Attachment { label_bytes: 3, media: TextDiff, content: <16 bytes> }"
        );
    }

    #[test]
    fn a_post_id_decoder_says_what_it_expects() {
        use serde::de::IntoDeserializer;
        let err = PostId::deserialize(
            IntoDeserializer::<serde::de::value::Error>::into_deserializer(7u32),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            err,
            "invalid type: integer `7`, expected a 16-byte byte string"
        );
    }

    #[test]
    fn each_hex_pair_is_the_high_nibble_times_sixteen_plus_the_low() {
        let id: PostId = "f00f1001ff00a55a0123456789abcdef".parse().unwrap();
        assert_eq!(
            id.0,
            [
                0xf0, 0x0f, 0x10, 0x01, 0xff, 0x00, 0xa5, 0x5a, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef
            ]
        );
    }

    #[test]
    fn debug_prints_sizes_never_content() {
        let d = draft();
        let post = Post {
            id: PostId([1; 16]),
            author: Author::Agent("hobi".into()),
            task: None,
            at_secs: 0,
            labels: Labels {},
            draft: d.clone(),
        };
        let page = BoardPage {
            posts: vec![post.clone()],
            more: false,
        };
        for shown in [format!("{d:?}"), format!("{post:?}"), format!("{page:?}")] {
            assert!(!shown.contains(BODY) && !shown.contains(ATT), "{shown}");
            assert!(shown.contains("<17 bytes>"), "{shown}");
        }
    }

    #[test]
    fn post_content_bytes_is_stable_and_never_grows() {
        let d = draft();
        let a = post_content_bytes(&d).unwrap();
        let b = post_content_bytes(&d).unwrap();
        assert_eq!(*a, *b);
        assert_eq!(a.capacity(), a.len());
        assert_eq!(*a, enc(&(&d.body, &d.attachments)));
    }

    #[test]
    fn the_page_budget_is_the_prompt_size_less_the_envelope() {
        assert_eq!(board_page_budget(10_000), 10_000 - BOARD_ENVELOPE);
        assert_eq!(board_page_budget(BOARD_ENVELOPE), 0);
        assert_eq!(board_page_budget(1), 0);
        assert_eq!(board_page_budget(0), 0);
    }
}
