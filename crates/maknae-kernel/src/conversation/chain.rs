use maknae_proto::{ContentBlock, ConversationId, PromptReply, ProposedToolCall, Turn};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
enum TurnRef<'a> {
    User {
        content: &'a [ContentBlock],
    },
    Assistant {
        content: &'a [ContentBlock],
        tool_calls: &'a [ProposedToolCall],
    },
    Tool {
        call_id: &'a str,
        content: &'a [ContentBlock],
    },
}

impl<'a> From<&'a Turn> for TurnRef<'a> {
    fn from(t: &'a Turn) -> Self {
        match t {
            Turn::User { content } => TurnRef::User { content },
            Turn::Assistant {
                content,
                tool_calls,
                ..
            } => TurnRef::Assistant {
                content,
                tool_calls,
            },
            Turn::Tool { call_id, content } => TurnRef::Tool { call_id, content },
        }
    }
}

const CHAIN_TAG: &[u8] = b"maknae-conversation-chain-v1";
const REPLY_TAG: &[u8] = b"maknae-conversation-reply-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ChainHead([u8; 32]);

impl TryFrom<String> for ChainHead {
    type Error = &'static str;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_hex(&s).ok_or("chain head must be 64 lowercase hex characters")
    }
}

impl From<ChainHead> for String {
    fn from(h: ChainHead) -> String {
        h.to_hex()
    }
}

impl ChainHead {
    pub fn genesis(id: &ConversationId) -> Self {
        let mut h = maknae_crypto::sha256_hasher();
        h.update(CHAIN_TAG);
        h.update(id.as_str().as_bytes());
        Self(finish(h))
    }

    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        let mut digits = s.bytes();
        for byte in &mut out {
            let hi = nibble(digits.next()?)?;
            let lo = nibble(digits.next()?)?;
            *byte = hi * 16 + lo;
        }
        Some(Self(out))
    }
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn finish(h: maknae_crypto::digest::Hasher) -> [u8; 32] {
    let d = h.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    Encode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extends {
    Retry,
    Advance { new: usize },
    Rewrite,
}

struct HashWriter<'a>(&'a mut maknae_crypto::digest::Hasher);

impl std::io::Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Counter(u64);

impl std::io::Write for Counter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encoded_len<T: Serialize>(v: &T) -> Result<u64, ChainError> {
    let mut c = Counter(0);
    ciborium::into_writer(v, &mut c).map_err(|_| ChainError::Encode)?;
    Ok(c.0)
}

fn feed<T: Serialize>(h: &mut maknae_crypto::digest::Hasher, v: &T) -> Result<(), ChainError> {
    ciborium::into_writer(v, HashWriter(h)).map_err(|_| ChainError::Encode)
}

pub fn advance(head: &ChainHead, turns: &[Turn]) -> Result<ChainHead, ChainError> {
    let mut head = *head;
    for turn in turns {
        let turn = TurnRef::from(turn);
        let len = encoded_len(&turn)?;
        let mut h = maknae_crypto::sha256_hasher();
        h.update(CHAIN_TAG);
        h.update(&head.0);
        h.update(&len.to_be_bytes());
        feed(&mut h, &turn)?;
        head = ChainHead(finish(h));
    }
    Ok(head)
}

pub fn turn_bytes(turns: &[Turn]) -> Result<u64, ChainError> {
    turns.iter().try_fold(0u64, |sum, t| {
        Ok(sum.saturating_add(encoded_len(&TurnRef::from(t))?))
    })
}

fn digest_of(
    content: &[ContentBlock],
    tool_calls: &[ProposedToolCall],
) -> Result<[u8; 32], ChainError> {
    let mut h = maknae_crypto::sha256_hasher();
    h.update(REPLY_TAG);
    feed(&mut h, &(content, tool_calls))?;
    Ok(finish(h))
}

pub fn reply_bytes(reply: &PromptReply) -> Result<u64, ChainError> {
    encoded_len(&(&reply.blocks, &reply.tool_calls))
}

pub fn reply_digest(reply: &PromptReply) -> Result<[u8; 32], ChainError> {
    digest_of(&reply.blocks, &reply.tool_calls)
}

pub fn assistant_digest(turn: &Turn) -> Result<Option<[u8; 32]>, ChainError> {
    match turn {
        Turn::Assistant {
            content,
            tool_calls,
            ..
        } => digest_of(content, tool_calls).map(Some),
        Turn::User { .. } | Turn::Tool { .. } => Ok(None),
    }
}

pub fn extends(
    rec_head: &ChainHead,
    rec_turns: u64,
    id: &ConversationId,
    last_reply: Option<&[u8; 32]>,
    request: &[Turn],
) -> Result<Extends, ChainError> {
    let held = match usize::try_from(rec_turns) {
        Ok(n) if n <= request.len() => n,
        _ => return Ok(Extends::Rewrite),
    };
    let (prefix, new) = request.split_at(held);
    if advance(&ChainHead::genesis(id), prefix)? != *rec_head {
        return Ok(Extends::Rewrite);
    }
    let Some((first, rest)) = new.split_first() else {
        return Ok(Extends::Retry);
    };
    let rest = match last_reply {
        Some(bound) => {
            if assistant_digest(first)?.as_ref() != Some(bound) {
                return Ok(Extends::Rewrite);
            }
            rest
        }
        None => new,
    };
    if rest.iter().any(|t| matches!(t, Turn::Assistant { .. })) {
        return Ok(Extends::Rewrite);
    }
    Ok(Extends::Advance { new: new.len() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_agent::transcript::Transcript;
    use maknae_io::Zeroizing;
    use maknae_proto::{ContentBlock, ProposedToolCall, SecretText};

    fn text(s: &str) -> ContentBlock {
        ContentBlock::Text {
            text: SecretText(Zeroizing::new(s.into())),
        }
    }
    fn user(s: &str) -> Turn {
        Turn::User {
            content: vec![text(s)],
        }
    }
    fn tool(id: &str, s: &str) -> Turn {
        Turn::Tool {
            call_id: id.into(),
            content: vec![text(s)],
        }
    }
    fn assistant(s: &str) -> Turn {
        Turn::Assistant {
            content: vec![text(s)],
            tool_calls: vec![],
            reasoning: None,
        }
    }
    fn call(name: &str, id: &str) -> ProposedToolCall {
        ProposedToolCall {
            name: name.into(),
            call_id: id.into(),
            arguments: SecretText(Zeroizing::new("{}".into())),
            refused: None,
        }
    }
    fn id(c: char) -> ConversationId {
        ConversationId::parse(&c.to_string().repeat(32)).unwrap()
    }
    fn head_of(turns: &[Turn]) -> ChainHead {
        advance(&ChainHead::genesis(&id('0')), turns).unwrap()
    }
    fn reply(s: &str) -> PromptReply {
        PromptReply {
            blocks: vec![text(s)],
            tool_calls: vec![call("read_file", "c1")],
            usage: None,
            reasoning: Some(SecretText(Zeroizing::new("hidden".into()))),
        }
    }

    #[test]
    fn role_and_boundaries_change_the_head() {
        let a = head_of(&[user("ab"), tool("x", "c")]);
        let b = head_of(&[user("abc")]);
        let c = head_of(&[assistant("ab"), tool("x", "c")]);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn tool_call_name_and_call_id_change_the_head() {
        let with = |name: &str, cid: &str| {
            head_of(&[Turn::Assistant {
                content: vec![],
                tool_calls: vec![call(name, cid)],
                reasoning: None,
            }])
        };
        let base = with("read_file", "c1");
        assert_ne!(base, with("write_file", "c1"));
        assert_ne!(base, with("read_file", "c2"));
        assert_eq!(base, with("read_file", "c1"));
    }

    #[test]
    fn reasoning_does_not_change_the_head_or_the_reply_digest() {
        let plain = Turn::Assistant {
            content: vec![text("a")],
            tool_calls: vec![],
            reasoning: None,
        };
        let shed = Turn::Assistant {
            content: vec![text("a")],
            tool_calls: vec![],
            reasoning: Some(SecretText(Zeroizing::new("r".into()))),
        };
        assert_eq!(
            head_of(std::slice::from_ref(&plain)),
            head_of(std::slice::from_ref(&shed))
        );
        assert_eq!(
            assistant_digest(&plain).unwrap(),
            assistant_digest(&shed).unwrap()
        );
        let mut r = reply("a");
        let with = reply_digest(&r).unwrap();
        r.reasoning = None;
        assert_eq!(with, reply_digest(&r).unwrap());
    }

    #[test]
    fn turn_ref_encodes_like_a_turn_without_reasoning() {
        let cases = [
            user("u"),
            tool("c", "t"),
            Turn::Assistant {
                content: vec![text("a")],
                tool_calls: vec![call("n", "i")],
                reasoning: None,
            },
        ];
        for t in cases {
            let mut want = Vec::new();
            ciborium::into_writer(&t, &mut want).unwrap();
            let mut got = Vec::new();
            ciborium::into_writer(&TurnRef::from(&t), &mut got).unwrap();
            assert_eq!(got, want);
        }
        let full = Turn::Assistant {
            content: vec![text("a")],
            tool_calls: vec![],
            reasoning: Some(SecretText(Zeroizing::new("r".into()))),
        };
        let bare = Turn::Assistant {
            content: vec![text("a")],
            tool_calls: vec![],
            reasoning: None,
        };
        let mut want = Vec::new();
        ciborium::into_writer(&bare, &mut want).unwrap();
        let mut got = Vec::new();
        ciborium::into_writer(&TurnRef::from(&full), &mut got).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn reply_and_pushed_assistant_digest_equal() {
        let r = reply("answer");
        let mut t = Transcript::new("c", "q");
        t.push_assistant(&r);
        let pushed = &t.turns()[1];
        assert_eq!(
            assistant_digest(pushed).unwrap(),
            Some(reply_digest(&r).unwrap())
        );
        assert_eq!(assistant_digest(&user("q")).unwrap(), None);
        assert_ne!(
            reply_digest(&r).unwrap(),
            reply_digest(&reply("other")).unwrap()
        );
    }

    struct Unencodable;

    impl Serialize for Unencodable {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("unencodable"))
        }
    }

    #[test]
    fn an_unencodable_value_is_an_encode_error_on_both_paths() {
        assert_eq!(encoded_len(&Unencodable), Err(ChainError::Encode));
        let mut h = maknae_crypto::sha256_hasher();
        assert_eq!(feed(&mut h, &Unencodable), Err(ChainError::Encode));
    }

    #[test]
    fn the_writers_flush_without_effect() {
        use std::io::Write;
        assert!(Counter(0).flush().is_ok());
        let mut h = maknae_crypto::sha256_hasher();
        assert!(HashWriter(&mut h).flush().is_ok());
    }

    #[test]
    fn genesis_differs_per_id() {
        assert_ne!(ChainHead::genesis(&id('a')), ChainHead::genesis(&id('b')));
    }

    #[test]
    fn hex_round_trips_and_refuses_malformed() {
        let h = head_of(&[user("a")]);
        assert_eq!(ChainHead::from_hex(&h.to_hex()), Some(h));
        assert_eq!(h.to_hex().len(), 64);
        assert_eq!(ChainHead::from_hex(&"0".repeat(63)), None);
        assert_eq!(ChainHead::from_hex(&"0".repeat(65)), None);
        assert_eq!(ChainHead::from_hex(&"g".repeat(64)), None);
        assert_eq!(ChainHead::from_hex(&"A".repeat(64)), None);
        assert_eq!(ChainHead::from_hex(&"é".repeat(32)), None);
    }

    #[test]
    fn reply_bytes_counts_the_digested_cbor() {
        let r = reply("hello");
        let mut b = Vec::new();
        ciborium::into_writer(&(&r.blocks, &r.tool_calls), &mut b).unwrap();
        assert_eq!(reply_bytes(&r).unwrap(), b.len() as u64);
        assert!(reply_bytes(&reply("hello world")).unwrap() > reply_bytes(&r).unwrap());
    }

    #[test]
    fn advance_is_stepwise_and_turn_bytes_counts_cbor() {
        let ts = [user("a"), tool("x", "b")];
        let g = ChainHead::genesis(&id('0'));
        let step = advance(&advance(&g, &ts[..1]).unwrap(), &ts[1..]).unwrap();
        assert_eq!(advance(&g, &ts).unwrap(), step);
        assert_eq!(advance(&g, &[]).unwrap(), g);
        let mut total = 0u64;
        for t in &ts {
            let mut b = Vec::new();
            ciborium::into_writer(&TurnRef::from(t), &mut b).unwrap();
            total += b.len() as u64;
        }
        assert_eq!(turn_bytes(&ts).unwrap(), total);
        assert_eq!(turn_bytes(&[]).unwrap(), 0);
    }

    #[test]
    fn extends_classifies_retry_advance_and_rewrite() {
        let i = id('0');
        let first = [user("q")];
        let rec = advance(&ChainHead::genesis(&i), &first).unwrap();
        let rd = reply_digest(&reply("a")).unwrap();
        let asst = {
            let mut t = Transcript::new("c", "q");
            t.push_assistant(&reply("a"));
            t.turns()[1].clone()
        };

        assert_eq!(extends(&rec, 1, &i, None, &first).unwrap(), Extends::Retry);
        assert_eq!(
            extends(&rec, 1, &i, Some(&rd), &first).unwrap(),
            Extends::Retry
        );
        assert_eq!(extends(&rec, 1, &i, None, &[]).unwrap(), Extends::Rewrite);
        assert_eq!(
            extends(&rec, 1, &i, None, &[user("q2")]).unwrap(),
            Extends::Rewrite
        );
        assert_eq!(
            extends(&rec, u64::MAX, &i, None, &first).unwrap(),
            Extends::Rewrite
        );

        let ok = [user("q"), asst.clone(), user("next")];
        assert_eq!(
            extends(&rec, 1, &i, Some(&rd), &ok).unwrap(),
            Extends::Advance { new: 2 }
        );
        let altered = [user("q"), assistant("a-altered"), user("next")];
        assert_eq!(
            extends(&rec, 1, &i, Some(&rd), &altered).unwrap(),
            Extends::Rewrite
        );
        let not_assistant = [user("q"), user("next")];
        assert_eq!(
            extends(&rec, 1, &i, Some(&rd), &not_assistant).unwrap(),
            Extends::Rewrite
        );
        let forged_second = [user("q"), asst.clone(), assistant("x")];
        assert_eq!(
            extends(&rec, 1, &i, Some(&rd), &forged_second).unwrap(),
            Extends::Rewrite
        );
        let forged_later = [user("q"), asst.clone(), user("u"), assistant("x")];
        assert_eq!(
            extends(&rec, 1, &i, Some(&rd), &forged_later).unwrap(),
            Extends::Rewrite
        );
        assert_eq!(
            extends(&rec, 1, &i, None, &[user("q"), user("more")]).unwrap(),
            Extends::Advance { new: 1 }
        );
        assert_eq!(
            extends(&rec, 1, &i, None, &[user("q"), asst.clone()]).unwrap(),
            Extends::Rewrite
        );

        let genesis = ChainHead::genesis(&i);
        assert_eq!(
            extends(&genesis, 0, &i, None, &[user("q")]).unwrap(),
            Extends::Advance { new: 1 }
        );
        assert_eq!(
            extends(&genesis, 0, &i, None, &[assistant("a")]).unwrap(),
            Extends::Rewrite
        );
        assert_eq!(
            extends(&genesis, 0, &id('1'), None, &[]).unwrap(),
            Extends::Rewrite
        );
        assert_eq!(
            extends(&rec, 1, &id('1'), None, &first).unwrap(),
            Extends::Rewrite
        );
    }

    #[test]
    fn the_domain_tags_are_pinned() {
        let zero = ConversationId::parse(&"0".repeat(32)).unwrap();
        assert_eq!(
            ChainHead::genesis(&zero).to_hex(),
            "15e1176889a2ffc69c210b3a06c94a9953da62e64cad764ac60b697487a9b16f"
        );
        assert_eq!(
            head_of(&[user("a")]).to_hex(),
            "e267a98a75dda40cc0e3f6629ae073cdfefa8afdcacfd1991c8f907a18e5ebe3"
        );
        let empty = PromptReply {
            blocks: vec![],
            tool_calls: vec![],
            usage: None,
            reasoning: None,
        };
        let hex: String = reply_digest(&empty)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "52270ad3cf46b725815a0008a249763adb1956755f118eedb67e8099b6209679"
        );
    }
}
