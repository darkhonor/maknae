//! maknae-proto typed errors — non-leaky, hand-rolled Display + Error.
#[derive(Debug)]
pub enum ProtoCodecError {
    Encode(String),
    Decode(String),
    UnsupportedVersion(u16),
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
