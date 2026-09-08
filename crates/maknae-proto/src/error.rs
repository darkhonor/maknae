//! maknae-proto typed errors — non-leaky, hand-rolled Display + Error.
#[derive(Debug)]
pub enum ProtoCodecError {
    Encode(String),
    Decode(String),
    UnsupportedVersion(u16),
}
impl ProtoCodecError {
    /// The error's CLASS, with no client bytes in it. `Decode` carries the
    /// decoder's diagnostic, which quotes the offending value verbatim (serde:
    /// `invalid type: string "…"`); a malformed prompt could therefore carry
    /// prompt text into an audit record through `Display`. The audit trail
    /// records this instead (#172).
    pub fn category(&self) -> &'static str {
        match self {
            ProtoCodecError::Encode(_) => "encode",
            ProtoCodecError::Decode(_) => "decode",
            ProtoCodecError::UnsupportedVersion(_) => "unsupported-version",
        }
    }
}

impl std::fmt::Display for ProtoCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoCodecError::Encode(e) => write!(f, "proto encode: {e}"),
            ProtoCodecError::Decode(e) => write!(f, "proto decode: {e}"),
            ProtoCodecError::UnsupportedVersion(v) => write!(f, "proto unsupported version: {v}"),
        }
    }
}
impl std::error::Error for ProtoCodecError {}

#[derive(Debug)]
pub enum ProtoFrameError {
    Oversize { declared: usize, max: usize },
    Truncated,
    Io(String),
}
impl std::fmt::Display for ProtoFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoFrameError::Oversize { declared, max } => {
                write!(f, "frame oversize: declared {declared} > max {max}")
            }
            ProtoFrameError::Truncated => write!(f, "frame truncated"),
            ProtoFrameError::Io(e) => write!(f, "frame io: {e}"),
        }
    }
}
impl std::error::Error for ProtoFrameError {}

#[cfg(test)]
mod category_tests {
    use super::*;

    #[test]
    fn category_names_the_class_and_never_the_payload() {
        let e = ProtoCodecError::Decode("invalid type: string \"the secret plan\"".into());
        assert_eq!(e.category(), "decode");
        assert!(!e.category().contains("secret"));
        assert!(
            e.to_string().contains("secret"),
            "Display still carries it; the trail must not use Display"
        );
        assert_eq!(ProtoCodecError::Encode("x".into()).category(), "encode");
        assert_eq!(
            ProtoCodecError::UnsupportedVersion(9).category(),
            "unsupported-version"
        );
    }
}
