//! Outcome → the text the model sees. `NOT_AUTHORIZED`, `APPLIED` and
//! `OUTCOME_UNKNOWN` are HALF OF A CONTRACT: the other half is
//! `crates/maknae-llm/prompt/core-prompt.txt`, which tells the model that
//! refusals say "Not authorized" and that a write comes back "applied, or
//! outcome unknown". Duplicated here by contract, never by linkage.
//! `READ_UNAVAILABLE` and `tool error:` are renderer-only: the prompt does not
//! promise them, and they describe transport and argument faults, not
//! decisions.
/// `ReadContent` carries a `Zeroizing<Vec<u8>>` for the reason
/// [`crate::plane::ReadOutcome`] states: the read path MOVES its buffer
/// through and never copies content out of a `Zeroizing` into a plain `Vec`
/// (R28). `from_utf8` below reads it through `Deref`.
#[derive(Clone, PartialEq, Eq)]
pub enum ToolOutcome {
    ReadContent(zeroize::Zeroizing<Vec<u8>>),
    ReadRefused,
    ReadUnavailable,
    WriteApplied,
    WriteUnknown,
    WriteNotSent,
    BadCall(String),
}

/// Redacting, by hand — the crate convention (`route.rs`'s `ToolRequest`,
/// `maknae-proto`'s `Bytes` and `SecretText`): a derived `Debug` prints
/// `ReadContent(Zeroizing([83, 69, …]))`, dumping kernel-served home-file
/// content into any `{:?}`, including a test's `panic!("{other:?}")` (R31).
/// Length only. `BadCall`'s `String` IS printed — it is router-authored text
/// (a tool name, a serde message), never served content.
impl std::fmt::Debug for ToolOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolOutcome::ReadContent(bytes) => f
                .debug_tuple("ReadContent")
                .field(&format_args!("<{} bytes>", bytes.len()))
                .finish(),
            ToolOutcome::ReadRefused => f.write_str("ReadRefused"),
            ToolOutcome::ReadUnavailable => f.write_str("ReadUnavailable"),
            ToolOutcome::WriteApplied => f.write_str("WriteApplied"),
            ToolOutcome::WriteUnknown => f.write_str("WriteUnknown"),
            ToolOutcome::WriteNotSent => f.write_str("WriteNotSent"),
            ToolOutcome::BadCall(why) => f.debug_tuple("BadCall").field(why).finish(),
        }
    }
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
    fn the_renderer_only_strings_are_exact() {
        // NOT promised by the compiled prompt (see the module doc): these
        // describe transport and argument faults, not decisions. R24 pins the
        // text LITERALLY and not via the const, so swapping the arm to
        // NOT_AUTHORIZED goes red — a transport fault rendered as a refusal
        // would tell the model the kernel decided.
        assert_eq!(
            render(&ToolOutcome::ReadUnavailable, 4),
            "read unavailable — do not retry\n\nsteps remaining: 4"
        );
    }
    #[test]
    fn a_read_result_is_the_text_and_binary_is_described_not_lossily_converted() {
        assert_eq!(
            render(
                &ToolOutcome::ReadContent(zeroize::Zeroizing::new(b"line\n".to_vec())),
                5
            ),
            "line\n\n\nsteps remaining: 5"
        );
        let r = render(
            &ToolOutcome::ReadContent(zeroize::Zeroizing::new(vec![0xff, 0x00, 0xfe])),
            5,
        );
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

    /// R31: the read bytes are kernel-served home-file content, so
    /// `ToolOutcome`'s `Debug` is hand-written and redacting — the crate
    /// convention `route.rs`'s `ToolRequest` already follows. The loop above
    /// formats every OTHER variant, which is why it can exclude this one.
    #[test]
    fn a_read_results_debug_never_prints_the_served_bytes() {
        let d = format!(
            "{:?}",
            ToolOutcome::ReadContent(zeroize::Zeroizing::new(b"SENTINEL-READ-BYTES".to_vec()))
        );
        assert!(!d.contains("SENTINEL-READ-BYTES"), "{d}");
        // A `#[derive(Debug)]` substitution prints `Zeroizing([83, 69, ...])`, so
        // the ABSENCE line fails on its own — not only the `<19 bytes>` marker.
        assert!(!d.contains("Zeroizing"), "{d}");
        assert!(d.contains("<19 bytes>"), "{d}");
        // `BadCall` carries ROUTER-authored text, not content: it is printed.
        assert_eq!(
            format!("{:?}", ToolOutcome::BadCall("unknown tool nope".into())),
            "BadCall(\"unknown tool nope\")"
        );
        // Every remaining arm, formatted EAGERLY and by name. The loop above
        // cannot stand in for this: `assert!(cond, "{o:?}")` evaluates its
        // message only when the assertion FAILS, so on a green run those arms
        // are never executed (measured: render.rs fell to 72% against the 95
        // floor with this block absent).
        for (o, want) in [
            (ToolOutcome::ReadRefused, "ReadRefused"),
            (ToolOutcome::ReadUnavailable, "ReadUnavailable"),
            (ToolOutcome::WriteApplied, "WriteApplied"),
            (ToolOutcome::WriteUnknown, "WriteUnknown"),
            (ToolOutcome::WriteNotSent, "WriteNotSent"),
        ] {
            assert_eq!(format!("{o:?}"), want);
        }
    }
}
