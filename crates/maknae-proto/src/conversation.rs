//! Kernel-recorded conversation identity and the views the session verbs return.
use serde::{Deserialize, Serialize};

pub const CONVERSATION_ID_HEX_LEN: usize = 32;

/// A kernel-assigned conversation id: exactly 32 lowercase hex characters.
/// Decoding goes through [`ConversationId::parse`], so a malformed id fails the
/// frame decode.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ConversationId(String);

impl ConversationId {
    pub fn parse(s: &str) -> Option<Self> {
        let ok = s.len() == CONVERSATION_ID_HEX_LEN
            && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        ok.then(|| Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ConversationId {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        if Self::parse(&s).is_some() {
            Ok(Self(s))
        } else {
            Err("conversation id must be 32 lowercase hex characters".into())
        }
    }
}

impl From<ConversationId> for String {
    fn from(id: ConversationId) -> String {
        id.0
    }
}

/// One conversation's record as the owner sees it. Times are epoch seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationView {
    pub conversation: ConversationId,
    pub cwd: String,
    pub opened_at: u64,
    pub last_active: u64,
    pub turns: u64,
    pub bytes: u64,
    pub chain_head: String,
}

/// One page of the owner's conversations; `next` is the cursor for the page after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationPage {
    pub entries: Vec<ConversationView>,
    pub next: Option<ConversationId>,
}
