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
            *out = hi << 4 | lo;
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
    Agents(Vec<String>),
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
    attachments: Vec<Attachment>,
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
        if self.attachments.len() > BOARD_ATTACHMENTS_MAX {
            return Err(format!(
                "board post has {} attachments, over {BOARD_ATTACHMENTS_MAX}",
                self.attachments.len()
            ));
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

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardPosted {
    pub id: PostId,
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
    use std::io::Write;
    let content = (&draft.body, &draft.attachments);
    let mut counter = Counter(0);
    ciborium::into_writer(&content, &mut counter)
        .map_err(|e| ProtoCodecError::Encode(e.to_string()))?;
    let mut buf = zeroize::Zeroizing::new(vec![0; counter.0]);
    let mut writer = std::io::Cursor::new(buf.as_mut_slice());
    ciborium::into_writer(&content, &mut writer)
        .map_err(|e| ProtoCodecError::Encode(e.to_string()))?;
    writer
        .flush()
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
