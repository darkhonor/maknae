//! Outcome → the text the model sees. `NOT_AUTHORIZED`, `APPLIED` and
//! `OUTCOME_UNKNOWN` are HALF OF A CONTRACT: the other half is
//! `crates/maknae-llm/prompt/core-prompt.txt`, which tells the model that
//! refusals say "Not authorized" and that a write comes back "applied, or
//! outcome unknown". Duplicated here by contract, never by linkage.
//! `READ_UNAVAILABLE` and `tool error:` are renderer-only: the prompt does not
//! promise them, and they describe transport and argument faults, not
//! decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolOutcome {
    ReadContent(Vec<u8>),
    ReadRefused,
    ReadUnavailable,
    WriteApplied,
    WriteUnknown,
    WriteNotSent,
    BadCall(String),
}

pub const NOT_AUTHORIZED: &str = "Not authorized";
pub const APPLIED: &str = "applied";
/// The prompt's own clause, in full (R8).
pub const OUTCOME_UNKNOWN: &str = "outcome unknown — the write may have happened: do not retry it, do not assume the previous contents survived, and do not touch that file again";
pub const READ_UNAVAILABLE: &str = "read unavailable — do not retry";
/// R13: a LOCAL pre-send refusal is a tool error, not an unknown outcome.
pub const WRITE_NOT_SENT: &str = "tool error: write not sent — content exceeds the frame bound";

pub fn render(outcome: &ToolOutcome, steps_remaining: u32) -> String {
    let body = match outcome {
        ToolOutcome::ReadContent(bytes) => match std::str::from_utf8(bytes) {
            Ok(s) => s.to_string(),
            // Never lossily converted: the model would act on U+FFFD as if it were the file.
            Err(_) => format!("binary content, {} bytes", bytes.len()),
        },
        ToolOutcome::ReadRefused => NOT_AUTHORIZED.to_string(),
        ToolOutcome::ReadUnavailable => READ_UNAVAILABLE.to_string(),
        ToolOutcome::WriteApplied => APPLIED.to_string(),
        ToolOutcome::WriteUnknown => OUTCOME_UNKNOWN.to_string(),
        ToolOutcome::WriteNotSent => WRITE_NOT_SENT.to_string(),
        ToolOutcome::BadCall(why) => format!("tool error: {why}"),
    };
    // The live step count rides HERE, in per-turn content — never in the
    // compiled prompt, which ships verbatim (#264).
    format!("{body}\n\nsteps remaining: {steps_remaining}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn the_strings_the_compiled_prompt_promises_are_exact() {
        // Duplicated BY CONTRACT with crates/maknae-llm/prompt/core-prompt.txt
        // (this crate must never link maknae-llm). Wording changes there change here.
        assert_eq!(
            render(&ToolOutcome::ReadRefused, 3),
            "Not authorized\n\nsteps remaining: 3"
        );
        assert_eq!(
            render(&ToolOutcome::WriteApplied, 2),
            "applied\n\nsteps remaining: 2"
        );
        assert_eq!(render(&ToolOutcome::WriteUnknown, 1),
            "outcome unknown — the write may have happened: do not retry it, do not assume the previous contents survived, and do not touch that file again\n\nsteps remaining: 1");
    }
    #[test]
    fn a_read_result_is_the_text_and_binary_is_described_not_lossily_converted() {
        assert_eq!(
            render(&ToolOutcome::ReadContent(b"line\n".to_vec()), 5),
            "line\n\n\nsteps remaining: 5"
        );
        let r = render(&ToolOutcome::ReadContent(vec![0xff, 0x00, 0xfe]), 5);
        assert!(r.starts_with("binary content, 3 bytes"), "{r}");
        assert!(!r.contains('\u{FFFD}'));
    }
    #[test]
    fn a_bad_call_and_an_unsent_write_are_tool_errors_and_steps_remaining_rides_on_every_result() {
        assert!(
            render(&ToolOutcome::BadCall("missing field `path`".into()), 4)
                .starts_with("tool error: missing field `path`")
        );
        // R13: never "may have happened" for a write that never left the process.
        assert_eq!(
            render(&ToolOutcome::WriteNotSent, 4),
            "tool error: write not sent — content exceeds the frame bound\n\nsteps remaining: 4"
        );
        for o in [
            ToolOutcome::ReadRefused,
            ToolOutcome::ReadUnavailable,
            ToolOutcome::WriteApplied,
            ToolOutcome::WriteUnknown,
            ToolOutcome::WriteNotSent,
        ] {
            assert!(render(&o, 7).ends_with("steps remaining: 7"), "{o:?}");
        }
    }
}
