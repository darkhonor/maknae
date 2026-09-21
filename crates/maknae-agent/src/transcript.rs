//! The turns the loop re-sends on every call. The loop is stateless and the
//! kernel holds no conversation (ADR-0023 d7), so this is the whole memory
//! there is, and the frame cap bounds it.
use maknae_proto::{ContentBlock, PromptReply, SecretText, Turn};
use zeroize::Zeroizing;

pub struct Transcript {
    conversation: String,
    turns: Vec<Turn>,
}

fn text(s: &str) -> ContentBlock {
    ContentBlock::Text {
        text: SecretText(Zeroizing::new(s.to_string())),
    }
}

impl Transcript {
    pub fn new(conversation: impl Into<String>, prompt: &str) -> Self {
        Self {
            conversation: conversation.into(),
            turns: vec![Turn::User {
                content: vec![text(prompt)],
            }],
        }
    }
    pub fn conversation(&self) -> &str {
        &self.conversation
    }
    pub fn turns(&self) -> &[Turn] {
        &self.turns
    }
    /// The model's reply, echoed back verbatim so the provider can see which
    /// tool calls the following tool turns answer.
    pub fn push_assistant(&mut self, reply: &PromptReply) {
        self.turns.push(Turn::Assistant {
            content: reply.blocks.clone(),
            tool_calls: reply.tool_calls.clone(),
        });
    }
    pub fn push_tool_result(&mut self, call_id: &str, result: &str) {
        self.turns.push(Turn::Tool {
            call_id: call_id.to_string(),
            content: vec![text(result)],
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{ContentBlock, PromptReply, ProposedToolCall, SecretText, Turn};
    use zeroize::Zeroizing;
    fn text(s: &str) -> ContentBlock {
        ContentBlock::Text {
            text: SecretText(Zeroizing::new(s.into())),
        }
    }
    fn call(id: &str) -> ProposedToolCall {
        ProposedToolCall {
            name: "read_file".into(),
            call_id: id.into(),
            arguments: SecretText(Zeroizing::new("{}".into())),
        }
    }
    #[test]
    fn a_new_transcript_is_one_user_turn_carrying_the_prompt() {
        let t = Transcript::new("conv1", "hello");
        assert_eq!(t.conversation(), "conv1");
        assert_eq!(
            t.turns(),
            &[Turn::User {
                content: vec![text("hello")]
            }]
        );
    }
    #[test]
    fn the_models_reply_is_echoed_as_an_assistant_turn_with_its_tool_calls() {
        let mut t = Transcript::new("c", "q");
        t.push_assistant(&PromptReply {
            blocks: vec![text("thinking")],
            tool_calls: vec![call("c1"), call("c2")],
        });
        assert_eq!(
            t.turns()[1],
            Turn::Assistant {
                content: vec![text("thinking")],
                tool_calls: vec![call("c1"), call("c2")]
            }
        );
    }
    #[test]
    fn a_tool_result_answers_its_call_id_as_a_tool_turn() {
        let mut t = Transcript::new("c", "q");
        t.push_assistant(&PromptReply {
            blocks: vec![],
            tool_calls: vec![call("c1")],
        });
        t.push_tool_result("c1", "the contents");
        assert_eq!(
            t.turns()[2],
            Turn::Tool {
                call_id: "c1".into(),
                content: vec![text("the contents")]
            }
        );
    }
}
