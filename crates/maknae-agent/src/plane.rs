//! The seam between the brain and the world. The brain calls these; it never
//! opens a socket or a file. The CLI implements it over the plane client; the
//! kernel's tests implement it over the in-process fixture — same brain, both.
use maknae_proto::{PromptReply, Turn};
use std::future::Future;

/// `Refused` is the wire's `Unauthorized` — for a READ that word is honest (no
/// side effect). `Unavailable` is a transport failure: no frame, a timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOutcome {
    Content(Vec<u8>),
    Refused,
    Unavailable,
}

/// ONLY a clean `Applied`; everything that came back from the wire other than
/// that — `Unauthorized`, a non-Applied completion, a missing frame, a
/// client-reported non-success — is `Unknown`, because on the wire the loop
/// cannot tell uncertain from refused and must not manufacture certainty
/// (ADR-0023 d4). `NotSent` is the one LOCAL refusal (the encoded request
/// exceeds the frame bound, judged before a byte leaves the process): nothing
/// is on the trail and the file is untouched, so "may have happened" would be
/// false (R13).
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
            ReadOutcome::Content(vec![1]),
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
}
