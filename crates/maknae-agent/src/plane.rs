//! The seam between the brain and the world. The brain calls these; it never
//! opens a socket or a file. The CLI implements it over the plane client; the
//! kernel's tests implement it over the in-process fixture — same brain, both.
use maknae_proto::{PromptReply, Turn};
use std::future::Future;

/// `Refused` is the wire's `Unauthorized` — for a READ that word is honest (no
/// side effect). `Unavailable` is a transport failure: no frame, a timeout.
///
/// `Content` carries a `Zeroizing<Vec<u8>>`, not a plain `Vec`: the buffer is
/// kernel-served home-file content, and `maknae_proto::Bytes::new` states the
/// rule the read path obeys — MOVE the buffer through, never copy content out
/// of a `Zeroizing` into a plain `Vec`.
///
/// What that buys, precisely: the served bytes are moved from
/// `maknae_proto::Bytes` into this variant, moved on into
/// [`crate::render::ToolOutcome::ReadContent`], rendered into a
/// `Zeroizing<String>` that [`crate::render::render`] allocates ONCE with
/// headroom for its suffix — appended in place, so the body is never
/// reallocated and no old allocation is freed unzeroized (corrected
/// 2026-09-22, #241: before the headroom it was) — and copied from there into
/// a `maknae_proto::SecretText`, which zeroizes too. So the CONTENT never
/// lands in a plain buffer anywhere on the path. It is not a claim that
/// nothing is ever copied: the render and the `SecretText` are copies, both
/// into zeroizing destinations, and that is the property, not zero-copy.
#[derive(Clone, PartialEq, Eq)]
pub enum ReadOutcome {
    Content(zeroize::Zeroizing<Vec<u8>>),
    Refused,
    Unavailable,
}

/// Redacting, by hand — the crate convention (`route.rs`'s `ToolRequest`,
/// `maknae-proto`'s `Bytes` and `SecretText`): a derived `Debug` prints
/// `Content(Zeroizing([83, 69, …]))`, dumping kernel-served home-file content
/// into any `{:?}`, including a test's `panic!("{other:?}")`. Length
/// only. The other two arms carry nothing but their own names.
impl std::fmt::Debug for ReadOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadOutcome::Content(bytes) => f
                .debug_tuple("Content")
                .field(&format_args!("<{} bytes>", bytes.len()))
                .finish(),
            ReadOutcome::Refused => f.write_str("Refused"),
            ReadOutcome::Unavailable => f.write_str("Unavailable"),
        }
    }
}

/// ONLY a clean `Applied`; everything that came back from the wire other than
/// that — `Unauthorized`, a non-Applied completion, a missing frame, a
/// client-reported non-success — is `Unknown`, because on the wire the loop
/// cannot tell uncertain from refused and must not manufacture certainty
/// (ADR-0023 d4). `NotSent` is the one LOCAL refusal (the encoded request
/// exceeds the frame bound, judged before a byte leaves the process): nothing
/// is on the trail and the file is untouched, so "may have happened" would be
/// false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    Applied,
    Unknown,
    NotSent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaneError {
    /// The encoded request would exceed `transport.frame_max_bytes` (ADR-0023 d7).
    FrameTooLarge,
    Transport(String),
    /// The kernel refused `session.prompt` itself.
    Refused,
}

pub trait Plane {
    fn prompt(
        &mut self,
        conversation: &str,
        turns: &[Turn],
    ) -> impl Future<Output = Result<PromptReply, PlaneError>> + Send;
    fn read(&mut self, path: &str) -> impl Future<Output = ReadOutcome> + Send;
    fn write(&mut self, path: &str, content: &[u8]) -> impl Future<Output = WriteOutcome> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_outcome_variant_is_constructible_comparable_and_debuggable() {
        let reads = [
            ReadOutcome::Content(zeroize::Zeroizing::new(vec![1])),
            ReadOutcome::Refused,
            ReadOutcome::Unavailable,
        ];
        for (i, a) in reads.iter().enumerate() {
            assert_eq!(a.clone(), *a);
            assert!(!format!("{a:?}").is_empty());
            for (j, b) in reads.iter().enumerate() {
                assert_eq!(a == b, i == j);
            }
        }
        let writes = [
            WriteOutcome::Applied,
            WriteOutcome::Unknown,
            WriteOutcome::NotSent,
        ];
        for (i, a) in writes.iter().enumerate() {
            assert_eq!(a.clone(), *a);
            for (j, b) in writes.iter().enumerate() {
                assert_eq!(a == b, i == j);
            }
        }
        assert!(format!("{:?}{:?}{:?}", writes[0], writes[1], writes[2]).contains("NotSent"));
        let errs = [
            PlaneError::FrameTooLarge,
            PlaneError::Transport("t".into()),
            PlaneError::Refused,
        ];
        for (i, a) in errs.iter().enumerate() {
            assert_eq!(a.clone(), *a);
            for (j, b) in errs.iter().enumerate() {
                assert_eq!(a == b, i == j);
            }
        }
        assert!(format!("{:?}", errs[1]).contains("Transport"));
    }

    /// The served bytes are kernel-served home-file content, so
    /// `ReadOutcome`'s `Debug` is hand-written and redacting — the crate
    /// convention `route.rs`'s `ToolRequest` already follows.
    #[test]
    fn a_read_outcomes_debug_never_prints_the_served_bytes() {
        let d = format!(
            "{:?}",
            ReadOutcome::Content(zeroize::Zeroizing::new(b"SENTINEL-READ-BYTES".to_vec()))
        );
        assert!(!d.contains("SENTINEL-READ-BYTES"), "{d}");
        // A `#[derive(Debug)]` substitution prints `Zeroizing([83, 69, ...])`, so
        // the ABSENCE line fails on its own — not only the `<19 bytes>` marker.
        assert!(!d.contains("Zeroizing"), "{d}");
        assert!(d.contains("<19 bytes>"), "{d}");
        // The other two arms of the hand-written impl are T1 regions too.
        assert_eq!(format!("{:?}", ReadOutcome::Refused), "Refused");
        assert_eq!(format!("{:?}", ReadOutcome::Unavailable), "Unavailable");
    }
}
