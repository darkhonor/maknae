//! The seam between the brain and the world. The brain calls these; it never
//! opens a socket or a file. The CLI implements it over the plane client; the
//! kernel's tests implement it over the in-process fixture — same brain, both.
use maknae_proto::{PromptReply, Turn};
use std::future::Future;

/// `Refused` is the wire's `Unauthorized` on an ARMED read — for a read that
/// word is honest (no side effect). `Unavailable` is everything else: a missing
/// frame or a timeout, a `BadRequest` (a client-shape fault the subject can
/// fix, not a decision), an UNARMED refusal of any code (`armed: false`: the
/// client could not prepare a descriptor), and a grant that ended without an
/// acknowledged success. None of these is a verdict on content. The mapping is
/// made and tested in `read_outcome`, in `bins/maknae`'s `agent`.
///
/// `Content` carries a [`ReadPage`] whose bytes are the CLI's own zeroizing
/// read buffer, moved through, never copied out into a plain `Vec`
/// (`maknae_proto::Bytes::new` states the rule). It is moved on into
/// [`crate::render::ToolOutcome::ReadContent`] and rendered into a
/// `Zeroizing<String>` that [`crate::render::render`] allocates ONCE with
/// headroom for its suffix, so the body is never reallocated. The render is
/// copied into a `maknae_proto::SecretText`, which zeroizes
/// too: copies into zeroizing destinations, not zero-copy. Beyond this crate,
/// the deputy hands the same bytes to `reqwest`'s `.json()`, which serialises
/// into a plain body buffer. The WRITE direction has a known residue: escapes
/// in the model's JSON write content are un-escaped into a scratch allocation
/// serde_json owns — accepted residual, #241, stated in full at `route.rs`'s
/// `ZeroizingString`.
#[derive(Clone, PartialEq, Eq)]
pub struct ReadPage {
    pub content: zeroize::Zeroizing<Vec<u8>>,
    pub level: String,
    pub lines: Option<(u64, u64)>,
    pub complete_line: bool,
    pub next: Option<(u64, u64)>,
    pub eof: bool,
    pub version: [i64; 7],
    pub changed: bool,
}

impl std::fmt::Debug for ReadPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadPage")
            .field("content", &format_args!("<{} bytes>", self.content.len()))
            .field("level", &self.level)
            .field("lines", &self.lines)
            .field("next", &self.next)
            .field("eof", &self.eof)
            .field("changed", &self.changed)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ReadOutcome {
    Content(ReadPage),
    Refused,
    Unavailable,
}

/// Redacting, by hand — the crate convention (`route.rs`'s `ToolRequest`,
/// `maknae-proto`'s `Bytes` and `SecretText`): a derived `Debug` prints
/// `Content(Zeroizing([83, 69, …]))`, dumping home-file content
/// into any `{:?}`, including a test's `panic!("{other:?}")`. Length
/// only. The other two arms carry nothing but their own names.
impl std::fmt::Debug for ReadOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadOutcome::Content(page) => f
                .debug_tuple("Content")
                .field(&format_args!("<{} bytes>", page.content.len()))
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
    /// The encoded request would exceed `transport.prompt_max_bytes` (ADR-0023 d7).
    FrameTooLarge,
    Transport(String),
    /// The kernel refused `session.prompt` itself.
    Refused,
    /// The kernel rejected the prompt request's SHAPE (`BadRequest`) — a
    /// pre-gate fault, decided before the exchange was attempted, so the
    /// prompt provably never reached the provider.
    Malformed,
}

pub trait Plane {
    fn prompt(
        &mut self,
        conversation: &str,
        turns: &[Turn],
    ) -> impl Future<Output = Result<PromptReply, PlaneError>> + Send;
    fn read(
        &mut self,
        conversation: &str,
        path: &str,
        page: maknae_proto::PageRequest,
    ) -> impl Future<Output = ReadOutcome> + Send;
    fn write(
        &mut self,
        conversation: &str,
        path: &str,
        content: &[u8],
    ) -> impl Future<Output = WriteOutcome> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_page(content: &[u8]) -> ReadPage {
        ReadPage {
            content: zeroize::Zeroizing::new(content.to_vec()),
            level: "UNCLASSIFIED".into(),
            lines: Some((1, 1)),
            complete_line: true,
            next: None,
            eof: true,
            version: [0; 7],
            changed: false,
        }
    }
    #[test]
    fn every_outcome_variant_is_constructible_comparable_and_debuggable() {
        let reads = [
            ReadOutcome::Content(test_page(&[1])),
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
            PlaneError::Malformed,
        ];
        for (i, a) in errs.iter().enumerate() {
            assert_eq!(a.clone(), *a);
            for (j, b) in errs.iter().enumerate() {
                assert_eq!(a == b, i == j);
            }
        }
        assert!(format!("{:?}", errs[1]).contains("Transport"));
        // `Malformed` is NOT `Refused`: a `BadRequest` on the prompt leg is a
        // shape fault the subject can fix, and the loop must report it as one
        // instead of sending them to look for an
        // egress intent that was never written. The refusal itself IS recorded
        // — the kernel appends a pre-gate deny before answering — so what
        // distinguishes the two is where the subject is pointed, not whether
        // anything was audited.
        assert_ne!(PlaneError::Malformed, PlaneError::Refused);
    }

    /// The served bytes are home-file content, so
    /// `ReadOutcome`'s `Debug` is hand-written and redacting — the crate
    /// convention `route.rs`'s `ToolRequest` already follows.
    #[test]
    fn a_read_outcomes_debug_never_prints_the_served_bytes() {
        let d = format!(
            "{:?}",
            ReadOutcome::Content(test_page(b"SENTINEL-READ-BYTES"))
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
