//! Outcome → the text the model sees. `NOT_AUTHORIZED`, `APPLIED` and
//! `OUTCOME_UNKNOWN` are HALF OF A CONTRACT: the other half is
//! `crates/maknae-llm/prompt/core-prompt.txt`, which tells the model that
//! refusals say "Not authorized" and that a write comes back "applied, or
//! outcome unknown". Duplicated here by contract, never by linkage.
//! `READ_UNAVAILABLE` and `tool error:` are renderer-only: the prompt does not
//! promise them, and they describe transport and argument faults, not
//! decisions.
use zeroize::Zeroizing;

/// `ReadContent` carries a `Zeroizing<Vec<u8>>` for the reason
/// [`crate::plane::ReadOutcome`] states: the read path MOVES its buffer
/// through and never copies content out of a `Zeroizing` into a plain `Vec`.
/// `from_utf8` below reads it through `Deref`.
#[derive(Clone, PartialEq, Eq)]
pub enum ToolOutcome {
    ReadContent(Zeroizing<Vec<u8>>),
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
/// content into any `{:?}`, including a test's `panic!("{other:?}")`.
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
/// The prompt's own clause, in full.
pub const OUTCOME_UNKNOWN: &str = "outcome unknown — the write may have happened: do not retry it, do not assume the previous contents survived, and do not touch that file again";
pub const READ_UNAVAILABLE: &str = "read unavailable — do not retry";
/// A LOCAL pre-send refusal is a tool error, not an unknown outcome.
pub const WRITE_NOT_SENT: &str = "tool error: write not sent — content exceeds the frame bound";

/// Headroom the read arm pre-allocates for the suffix `render` appends, so the
/// append never reallocates: 19 bytes of `"\n\nsteps remaining: "` plus the 10
/// digits of a `u32` at its maximum, plus slack. Sized here rather than
/// measured at each call because the body it protects is kernel-served content
/// (see [`render`]).
const SUFFIX_HEADROOM: usize = 32;

/// The output is a `Zeroizing<String>`, and it is BUILT as one. On the read
/// path this text IS the kernel-served file content, so a plain `String`
/// anywhere on the way — including a `format!` that copies a finished body into
/// a fresh buffer — would leave a non-zeroizing copy of home-file bytes behind
/// until the allocator reused the page.
///
/// The property that holds, stated exactly (corrected 2026-09-22, #241 — the
/// earlier text claimed the append alone was enough; scoped again
/// 2026-09-22, #344 — it was stated over the whole `ReadContent` arm, and the
/// arm has two sub-arms): on the UTF-8 TEXT path, the only path that carries
/// kernel-served content, the read arm allocates
/// ONCE, with `SUFFIX_HEADROOM` for the suffix, appends in place, and hands
/// that single zeroizing buffer to the transcript. There is no second plain
/// buffer and no reallocation of the body. Without the headroom the first
/// `push_str` reallocated: capacity equalled length, so the body was
/// memcpy'd into a fresh allocation and the old one — kernel-served content —
/// was freed unzeroized. The non-UTF-8 sub-arm relies on `format!`'s
/// over-allocation rather than on named headroom, so whether the suffix
/// reallocates depends on the digit counts (measured with `rustc -O`:
/// `format!` capacity is 44 and the finished string is
/// `41 + digits(len) + digits(steps)`, so the append fits exactly while
/// `41 + digits(len) + digits(steps) <= 44`, i.e. exactly while
/// `digits(len) + digits(steps) <= 3` — no realloc for a body under 100 bytes
/// and a single-digit step counter, a realloc once the two digit counts
/// exceed three) — and either way what
/// it holds is a short renderer-authored
/// length (`binary content, N bytes`), not a file.
///
/// The caller ([`crate::transcript::Transcript::push_tool_result`]) copies this
/// into a `SecretText`, which zeroizes too — so on the READ direction the
/// content lands in no plain buffer anywhere in THIS crate's chain, from
/// `maknae_proto::Bytes` through to the transcript's `SecretText`. Scoped by
/// component deliberately (2026-09-22, #344): once a `Tool` turn leaves the
/// trust plane the deputy hands it to `reqwest`'s `.json()`, which serialises
/// through `serde_json::to_vec` into a plain body buffer, so the bytes do sit
/// in un-zeroized heap there — and the NEARER residue is the CLI's own, two
/// frames below the `ReadOutcome` this renders (`RealPlane::read` →
/// `send_verb` → `read_frame`): `maknae_proto::read_frame`
/// is `read_frame_zeroizing(..).map(|mut body| std::mem::take(&mut *body))`,
/// so the served frame is moved out of its `Zeroizing` into a plain
/// `Vec<u8>` before the brain ever sees it. A #241 code gap, not fixed by
/// #344's prose pass. Same discipline as [`crate::plane::ReadOutcome`] one
/// layer up, whose doc also names the write direction's residue.
///
/// One caller obligation: `Zeroizing<String>`'s `Debug` is the inner
/// `String`'s — it is NOT redacting, unlike [`ToolOutcome`]'s above — so a
/// `{:?}` of this return value prints the served body. Never format it; the
/// only production caller passes it as a `&str`.
pub fn render(outcome: &ToolOutcome, steps_remaining: u32) -> Zeroizing<String> {
    let mut out = match outcome {
        ToolOutcome::ReadContent(bytes) => match std::str::from_utf8(bytes) {
            Ok(s) => {
                // Capacity for the body AND the suffix, so the `push_str`
                // below never reallocates — a realloc memcpy's the body and
                // frees the old buffer unzeroized (measured on #241).
                let mut z = Zeroizing::new(String::with_capacity(s.len() + SUFFIX_HEADROOM));
                z.push_str(s);
                z
            }
            // Never lossily converted: the model would act on U+FFFD as if it were the file.
            Err(_) => Zeroizing::new(format!("binary content, {} bytes", bytes.len())),
        },
        // The non-read arms do NOT pre-size, and that is the inverse of the
        // read arm's discipline above, deliberately: `CONST.to_string()`
        // allocates at exactly `len`, so `render`'s suffix `push_str`
        // reallocates and frees each of these buffers. What it frees is a
        // HEAP COPY of a compiled-in constant — `NOT_AUTHORIZED`,
        // `READ_UNAVAILABLE`, `APPLIED`, `OUTCOME_UNKNOWN`, `WRITE_NOT_SENT`
        // — never the `.rodata` original, which is not freed at all, so
        // nothing secret is freed and headroom would buy nothing. One arm is
        // different, and is the reason this is written down: `BadCall(why)`
        // formats router-authored text that can
        // quote the model's own tool arguments through a serde message, so its
        // realloc frees model-authored bytes. Accepted — those bytes already
        // transit the deputy's plain HTTP buffers, the same deferred residual
        // #241 recorded for serde_json's scratch — and named here so the
        // asymmetry reads as a decision rather than an omission.
        ToolOutcome::ReadRefused => Zeroizing::new(NOT_AUTHORIZED.to_string()),
        ToolOutcome::ReadUnavailable => Zeroizing::new(READ_UNAVAILABLE.to_string()),
        ToolOutcome::WriteApplied => Zeroizing::new(APPLIED.to_string()),
        ToolOutcome::WriteUnknown => Zeroizing::new(OUTCOME_UNKNOWN.to_string()),
        ToolOutcome::WriteNotSent => Zeroizing::new(WRITE_NOT_SENT.to_string()),
        ToolOutcome::BadCall(why) => Zeroizing::new(format!("tool error: {why}")),
    };
    // The live step count rides HERE, in per-turn content — never in the
    // compiled prompt, which ships verbatim (#264). Appended IN PLACE into the
    // headroom the read arm reserved, so the body is never copied into a
    // second buffer and the first one is never freed.
    out.push_str("\n\nsteps remaining: ");
    out.push_str(&steps_remaining.to_string());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn the_strings_the_compiled_prompt_promises_are_exact() {
        // Duplicated BY CONTRACT with crates/maknae-llm/prompt/core-prompt.txt
        // (this crate must never link maknae-llm). Wording changes there change here.
        assert_eq!(
            render(&ToolOutcome::ReadRefused, 3).as_str(),
            "Not authorized\n\nsteps remaining: 3"
        );
        assert_eq!(
            render(&ToolOutcome::WriteApplied, 2).as_str(),
            "applied\n\nsteps remaining: 2"
        );
        assert_eq!(render(&ToolOutcome::WriteUnknown, 1).as_str(),
            "outcome unknown — the write may have happened: do not retry it, do not assume the previous contents survived, and do not touch that file again\n\nsteps remaining: 1");
    }
    #[test]
    fn the_renderer_only_strings_are_exact() {
        // NOT promised by the compiled prompt (see the module doc): these
        // describe transport and argument faults, not decisions. This pins
        // the text LITERALLY and not via the const, so swapping the arm to
        // NOT_AUTHORIZED goes red — a transport fault rendered as a refusal
        // would tell the model the kernel decided.
        assert_eq!(
            render(&ToolOutcome::ReadUnavailable, 4).as_str(),
            "read unavailable — do not retry\n\nsteps remaining: 4"
        );
    }
    #[test]
    fn a_read_result_is_the_text_and_binary_is_described_not_lossily_converted() {
        assert_eq!(
            render(
                &ToolOutcome::ReadContent(Zeroizing::new(b"line\n".to_vec())),
                5
            )
            .as_str(),
            "line\n\n\nsteps remaining: 5"
        );
        let r = render(
            &ToolOutcome::ReadContent(Zeroizing::new(vec![0xff, 0x00, 0xfe])),
            5,
        );
        assert!(r.starts_with("binary content, 3 bytes"), "{}", *r);
        assert!(!r.contains('\u{FFFD}'));
    }
    #[test]
    fn a_bad_call_and_an_unsent_write_are_tool_errors_and_steps_remaining_rides_on_every_result() {
        assert!(
            render(&ToolOutcome::BadCall("missing field `path`".into()), 4)
                .starts_with("tool error: missing field `path`")
        );
        // Never "may have happened" for a write that never left the process.
        assert_eq!(
            render(&ToolOutcome::WriteNotSent, 4).as_str(),
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

    /// The read bytes are kernel-served home-file content, so
    /// `ToolOutcome`'s `Debug` is hand-written and redacting — the crate
    /// convention `route.rs`'s `ToolRequest` already follows.
    #[test]
    fn a_read_results_debug_never_prints_the_served_bytes() {
        let d = format!(
            "{:?}",
            ToolOutcome::ReadContent(Zeroizing::new(b"SENTINEL-READ-BYTES".to_vec()))
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

    /// The read arm allocates ONCE, with headroom, and never grows: a growth
    /// memcpy's the kernel-served body into a fresh buffer and frees the old
    /// allocation WITHOUT zeroizing it (measured on #241 — the earlier
    /// `String::from(s)` had capacity == len, so the first `push_str` moved
    /// the body). The observable from outside the function: the returned
    /// buffer's capacity is still EXACTLY what `with_capacity` asked for;
    /// any reallocation replaces it with an amortized-doubled capacity.
    #[test]
    fn a_read_body_is_never_moved_to_make_room_for_the_suffix() {
        let body = b"SENTINEL-READ-BODY-long-enough-that-doubling-shows\n".to_vec();
        // `u32::MAX` renders the LONGEST suffix the renderer can produce.
        let r = render(
            &ToolOutcome::ReadContent(Zeroizing::new(body.clone())),
            u32::MAX,
        );
        assert!(r.starts_with("SENTINEL-READ-BODY"), "{}", *r);
        assert_eq!(
            r.len(),
            body.len() + "\n\nsteps remaining: 4294967295".len(),
            "the worst-case suffix, measured"
        );
        assert!(
            r.len() <= body.len() + SUFFIX_HEADROOM,
            "the headroom does not cover the worst-case suffix"
        );
        assert_eq!(
            r.capacity(),
            body.len() + SUFFIX_HEADROOM,
            "the read buffer GREW: the body was memcpy'd and the old allocation freed unzeroized"
        );
    }
}
