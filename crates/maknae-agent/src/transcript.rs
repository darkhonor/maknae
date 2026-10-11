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
            reasoning: reply.reasoning.clone(),
        });
    }
    /// Drop the oldest assistant turn's reasoning; `false` when none is left.
    pub fn shed_oldest_reasoning(&mut self) -> bool {
        for t in &mut self.turns {
            if let Turn::Assistant { reasoning, .. } = t {
                if reasoning.take().is_some() {
                    return true;
                }
            }
        }
        false
    }
    pub fn bytes(&self) -> u64 {
        let block = |b: &ContentBlock| match b {
            ContentBlock::Text { text } => text.0.len(),
            _ => 0,
        };
        let n: usize = self
            .turns
            .iter()
            .map(|t| match t {
                Turn::User { content } | Turn::Tool { content, .. } => {
                    content.iter().map(block).sum()
                }
                Turn::Assistant {
                    reasoning,
                    content,
                    tool_calls,
                } => {
                    content.iter().map(block).sum::<usize>()
                        + tool_calls
                            .iter()
                            .map(|c| c.arguments.0.len())
                            .sum::<usize>()
                        + reasoning.as_ref().map_or(0, |r| r.0.len())
                }
            })
            .sum();
        n as u64
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
            reasoning: None,
            blocks: vec![text("thinking")],
            tool_calls: vec![call("c1"), call("c2")],
            usage: None,
        });
        assert_eq!(
            t.turns()[1],
            Turn::Assistant {
                reasoning: None,
                content: vec![text("thinking")],
                tool_calls: vec![call("c1"), call("c2")]
            }
        );
    }
    #[test]
    fn a_tool_result_answers_its_call_id_as_a_tool_turn() {
        let mut t = Transcript::new("c", "q");
        t.push_assistant(&PromptReply {
            reasoning: None,
            blocks: vec![],
            tool_calls: vec![call("c1")],
            usage: None,
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
    #[test]
    fn bytes_counts_every_turns_text_and_tool_arguments() {
        let mut t = Transcript::new("c", "12345");
        assert_eq!(t.bytes(), 5);
        t.push_assistant(&PromptReply {
            reasoning: None,
            blocks: vec![text("abc")],
            tool_calls: vec![ProposedToolCall {
                name: "read_file".into(),
                call_id: "c1".into(),
                arguments: SecretText(Zeroizing::new("{\"p\":1}".into())),
            }],
            usage: None,
        });
        assert_eq!(t.bytes(), 5 + 3 + 7);
        t.push_tool_result("c1", "0123456789");
        assert_eq!(t.bytes(), 5 + 3 + 7 + 10);
    }

    fn why(s: &str) -> Option<maknae_proto::SecretText> {
        Some(maknae_proto::SecretText(zeroize::Zeroizing::new(s.into())))
    }

    fn reply_with_reasoning(id: &str, r: &str) -> PromptReply {
        PromptReply {
            blocks: vec![],
            tool_calls: vec![call(id)],
            usage: None,
            reasoning: why(r),
        }
    }

    #[test]
    fn the_models_reasoning_is_kept_on_its_assistant_turn() {
        let mut t = Transcript::new("c", "q");
        t.push_assistant(&reply_with_reasoning("c1", "read it, then patch line 40"));
        assert_eq!(
            t.turns()[1],
            Turn::Assistant {
                content: vec![],
                tool_calls: vec![call("c1")],
                reasoning: why("read it, then patch line 40"),
            }
        );
    }

    #[test]
    fn bytes_counts_reasoning() {
        let mut t = Transcript::new("c", "12345");
        t.push_assistant(&PromptReply {
            blocks: vec![text("ab")],
            tool_calls: vec![],
            usage: None,
            reasoning: why("xyz"),
        });
        assert_eq!(t.bytes(), 10);
    }

    #[test]
    fn shedding_removes_the_oldest_reasoning_first_and_reports_when_none_is_left() {
        let mut t = Transcript::new("c", "q");
        t.push_assistant(&reply_with_reasoning("c1", "first"));
        t.push_tool_result("c1", "r1");
        t.push_assistant(&reply_with_reasoning("c2", "second"));
        let reasoning = |t: &Transcript, i: usize| match &t.turns()[i] {
            Turn::Assistant { reasoning, .. } => reasoning.clone(),
            _ => panic!("not an assistant turn"),
        };
        assert!(t.shed_oldest_reasoning());
        assert_eq!((reasoning(&t, 1), reasoning(&t, 3)), (None, why("second")));
        assert!(t.shed_oldest_reasoning());
        assert_eq!(reasoning(&t, 3), None);
        assert!(!t.shed_oldest_reasoning());
    }
}
