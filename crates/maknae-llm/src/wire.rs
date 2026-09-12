//! The OpenAI-compatible chat-completions wire shapes, and the mapping into
//! Maknae's own reply type (#240b).
//!
//! PURE. No I/O lives here: this is the request/response MAPPING that #240
//! declares T1, and it is the part worth mutation-testing. The HTTP call is
//! `client.rs`.
//!
//! **The provider is untrusted.** Everything arriving here is bytes from a
//! third party, outside the enforcement boundary (`design/model-conduit-policy.md`).
//! A shape we do not recognise is a REFUSAL the loop sees, never an empty
//! success — #240's scope says so in terms.

use serde::{Deserialize, Serialize};

/// What we send. Only the fields Maknae actually sets: no temperature, no
/// sampling knobs, nothing the operator has not asked for.
#[derive(Debug, Serialize)]
pub struct ChatRequest<'a> {
    pub model: &'a str,
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolDef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<&'a str>,
    /// Non-streaming only (#240 scope). Sent explicitly rather than relying on
    /// a provider default.
    pub stream: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolDef {
    #[serde(rename = "type")]
    pub kind: String,
    pub function: ToolFn,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolFn {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// What we accept back. Deliberately NOT a faithful model of the provider's
/// schema — only the fields Maknae reads. Unknown fields are ignored by serde;
/// unknown SHAPES (no choices, no message) are refused below.
#[derive(Debug, Deserialize)]
pub struct ChatResponse {
    pub choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
pub struct Choice {
    pub message: RespMessage,
}

#[derive(Debug, Deserialize)]
pub struct RespMessage {
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub tool_calls: Vec<RespToolCall>,
}

#[derive(Debug, Deserialize)]
pub struct RespToolCall {
    pub id: String,
    pub function: RespToolFn,
}

#[derive(Debug, Deserialize)]
pub struct RespToolFn {
    pub name: String,
    pub arguments: String,
}

/// Why a provider answer is not usable. Each variant is a refusal the loop
/// sees; there is no variant meaning "carry on with nothing".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyError {
    /// The body did not parse as a chat completion at all.
    Malformed(String),
    /// Parsed, but carried no choices — nothing to deliver.
    NoChoices,
    /// Parsed, but the message had neither content nor tool calls. An empty
    /// success is exactly what #240's scope forbids.
    EmptyMessage,
    /// A tool call named a tool this deployment did not offer. The model may
    /// PROPOSE; it may not invent the vocabulary.
    UnknownTool(String),
    /// A field exceeded the bound `maknae-proto` enforces on the reply.
    Unacceptable(String),
}

impl std::fmt::Display for ReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplyError::Malformed(m) => write!(f, "provider reply is malformed: {m}"),
            ReplyError::NoChoices => write!(f, "provider reply carried no choices"),
            ReplyError::EmptyMessage => {
                write!(f, "provider reply had neither content nor tool calls")
            }
            ReplyError::UnknownTool(t) => write!(f, "provider proposed an unknown tool '{t}'"),
            ReplyError::Unacceptable(m) => write!(f, "provider reply is not admissible: {m}"),
        }
    }
}

/// Map a parsed provider response into Maknae's reply type.
///
/// `offered` is the set of tool names this deployment put on the request. A
/// call naming anything else is refused: under the conduit design the model
/// PROPOSES and the PDP authorizes, so a model that invents a tool name is
/// proposing outside the vocabulary it was given.
pub fn to_prompt_reply(
    resp: ChatResponse,
    offered: &[String],
) -> Result<maknae_proto::PromptReply, ReplyError> {
    let choice = resp
        .choices
        .into_iter()
        .next()
        .ok_or(ReplyError::NoChoices)?;
    let msg = choice.message;

    let mut blocks = Vec::new();
    if let Some(text) = msg.content.filter(|c| !c.is_empty()) {
        blocks.push(maknae_proto::ContentBlock::Text {
            text: maknae_proto::SecretText(zeroize::Zeroizing::new(text)),
        });
    }

    let mut tool_calls = Vec::new();
    for c in msg.tool_calls {
        if !offered.iter().any(|o| *o == c.function.name) {
            return Err(ReplyError::UnknownTool(c.function.name));
        }
        let proposed = maknae_proto::ProposedToolCall {
            name: c.function.name,
            call_id: c.id,
            arguments: maknae_proto::SecretText(zeroize::Zeroizing::new(c.function.arguments)),
        };
        // Bounded HERE, against the same predicate the kernel applies, so an
        // over-long proposal is refused at the boundary it arrived on rather
        // than becoming a kernel-side refusal with less context.
        if !maknae_proto::proposed_tool_call_is_acceptable(&proposed) {
            return Err(ReplyError::Unacceptable(format!(
                "tool call '{}' exceeds a declared bound",
                proposed.name
            )));
        }
        tool_calls.push(proposed);
    }

    if blocks.is_empty() && tool_calls.is_empty() {
        return Err(ReplyError::EmptyMessage);
    }
    Ok(maknae_proto::PromptReply { blocks, tool_calls })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(body: &str) -> Result<ChatResponse, ReplyError> {
        serde_json::from_str(body).map_err(|e| ReplyError::Malformed(e.to_string()))
    }

    fn offered() -> Vec<String> {
        vec!["read_file".to_string(), "write_file".to_string()]
    }

    #[test]
    fn a_plain_text_reply_becomes_one_text_block() {
        let r = parse(r#"{"choices":[{"message":{"content":"hello"}}]}"#).unwrap();
        let reply = to_prompt_reply(r, &offered()).unwrap();
        assert_eq!(reply.blocks.len(), 1);
        assert!(reply.tool_calls.is_empty());
    }

    #[test]
    fn a_tool_call_reply_becomes_a_proposal_and_no_prose() {
        let r = parse(
            r#"{"choices":[{"message":{"content":null,"tool_calls":[
                 {"id":"call_1","function":{"name":"read_file","arguments":"{\"p\":\"/x\"}"}}]}}]}"#,
        )
        .unwrap();
        let reply = to_prompt_reply(r, &offered()).unwrap();
        assert!(reply.blocks.is_empty());
        assert_eq!(reply.tool_calls.len(), 1);
        assert_eq!(reply.tool_calls[0].name, "read_file");
        assert_eq!(reply.tool_calls[0].call_id, "call_1");
    }

    #[test]
    fn content_and_tool_calls_together_both_arrive() {
        let r = parse(
            r#"{"choices":[{"message":{"content":"on it","tool_calls":[
                 {"id":"c","function":{"name":"read_file","arguments":"{}"}}]}}]}"#,
        )
        .unwrap();
        let reply = to_prompt_reply(r, &offered()).unwrap();
        assert_eq!(reply.blocks.len(), 1);
        assert_eq!(reply.tool_calls.len(), 1);
    }

    /// THE vocabulary control. The model PROPOSES; it does not get to invent
    /// the tool names. A call naming a tool this deployment never offered is a
    /// refusal, not a pass-through for someone downstream to notice.
    #[test]
    fn a_tool_this_deployment_never_offered_is_refused_by_name() {
        let r = parse(
            r#"{"choices":[{"message":{"tool_calls":[
                 {"id":"c","function":{"name":"exfiltrate","arguments":"{}"}}]}}]}"#,
        )
        .unwrap();
        assert_eq!(
            to_prompt_reply(r, &offered()),
            Err(ReplyError::UnknownTool("exfiltrate".into()))
        );
        // and an EMPTY offered set admits nothing — an unset vocabulary is not
        // a universal one (the bounds-prefix lesson, same shape).
        let r2 = parse(
            r#"{"choices":[{"message":{"tool_calls":[
                 {"id":"c","function":{"name":"read_file","arguments":"{}"}}]}}]}"#,
        )
        .unwrap();
        assert_eq!(
            to_prompt_reply(r2, &[]),
            Err(ReplyError::UnknownTool("read_file".into()))
        );
    }

    /// #240's scope in terms: a malformed body is a refusal the loop sees,
    /// NEVER an empty success.
    #[test]
    fn every_unusable_shape_is_its_own_refusal() {
        assert!(matches!(parse("not json"), Err(ReplyError::Malformed(_))));
        assert_eq!(
            to_prompt_reply(parse(r#"{"choices":[]}"#).unwrap(), &offered()),
            Err(ReplyError::NoChoices)
        );
        // content present but EMPTY, and no calls: still nothing to deliver.
        assert_eq!(
            to_prompt_reply(
                parse(r#"{"choices":[{"message":{"content":""}}]}"#).unwrap(),
                &offered()
            ),
            Err(ReplyError::EmptyMessage)
        );
        assert_eq!(
            to_prompt_reply(
                parse(r#"{"choices":[{"message":{}}]}"#).unwrap(),
                &offered()
            ),
            Err(ReplyError::EmptyMessage)
        );
    }

    /// The proposal is bounded HERE, at the boundary it arrived on, against the
    /// same predicate the kernel applies.
    #[test]
    fn an_over_bound_proposal_is_refused_at_the_boundary() {
        let big = "a".repeat(maknae_proto::MAX_TOOL_CALL_ARGS_BYTES + 1);
        let body = format!(
            r#"{{"choices":[{{"message":{{"tool_calls":[
                 {{"id":"c","function":{{"name":"read_file","arguments":"{big}"}}}}]}}}}]}}"#
        );
        assert!(matches!(
            to_prompt_reply(parse(&body).unwrap(), &offered()),
            Err(ReplyError::Unacceptable(_))
        ));
    }

    /// The request carries only what Maknae sets — no sampling knobs, and
    /// `stream` explicitly false rather than left to a provider default.
    #[test]
    fn the_request_carries_only_what_maknae_sets() {
        let req = ChatRequest {
            model: "m",
            messages: vec![ChatMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
            tools: vec![],
            tool_choice: None,
            stream: false,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<_> = obj.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["messages", "model", "stream"],
            "an empty tools list and an absent tool_choice must not be sent at all"
        );
        assert_eq!(obj["stream"], serde_json::json!(false));
    }

    /// Every refusal renders something an operator can act on, and NONE of
    /// them renders provider content. These strings reach the audit trail and
    /// the terminal; `UnknownTool` names the tool (a name the model proposed,
    /// not a secret), and nothing else echoes the body.
    #[test]
    fn every_refusal_renders_actionably_and_echoes_no_content() {
        let cases = [
            (ReplyError::Malformed("expected value".into()), "malformed"),
            (ReplyError::NoChoices, "no choices"),
            (ReplyError::EmptyMessage, "neither content nor tool calls"),
            (ReplyError::UnknownTool("exfiltrate".into()), "exfiltrate"),
            (
                ReplyError::Unacceptable("over a bound".into()),
                "not admissible",
            ),
        ];
        for (e, needle) in cases {
            let rendered = e.to_string();
            assert!(
                rendered.contains(needle),
                "{e:?} rendered as {rendered:?}, expected to mention {needle:?}"
            );
        }
    }
}
