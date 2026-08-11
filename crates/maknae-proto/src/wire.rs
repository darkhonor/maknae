//! Versioned CBOR request/response contract (spec §3).
use crate::error::ProtoCodecError;
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verb {
    Ping,
    Whoami,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhoamiView {
    pub peer_plane_uri_san: String,
    pub peer_uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload {
    Pong,
    Whoami(WhoamiView),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtoErrCode {
    UnknownVerb,
    Unauthorized,
    BadRequest,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtoError {
    pub code: ProtoErrCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RespResult {
    Ok(Payload),
    Err(ProtoError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub protocol_version: u16,
    pub verb: Verb,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub protocol_version: u16,
    pub result: RespResult,
}

fn enc<T: Serialize>(v: &T) -> Result<Vec<u8>, ProtoCodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(v, &mut buf).map_err(|e| ProtoCodecError::Encode(e.to_string()))?;
    Ok(buf)
}
pub fn encode_request(r: &Request) -> Result<Vec<u8>, ProtoCodecError> {
    enc(r)
}
pub fn encode_response(r: &Response) -> Result<Vec<u8>, ProtoCodecError> {
    enc(r)
}
pub fn decode_request(b: &[u8]) -> Result<Request, ProtoCodecError> {
    let r: Request =
        ciborium::from_reader(b).map_err(|e| ProtoCodecError::Decode(e.to_string()))?;
    if r.protocol_version != PROTOCOL_VERSION {
        return Err(ProtoCodecError::UnsupportedVersion(r.protocol_version));
    }
    Ok(r)
}
pub fn decode_response(b: &[u8]) -> Result<Response, ProtoCodecError> {
    let r: Response =
        ciborium::from_reader(b).map_err(|e| ProtoCodecError::Decode(e.to_string()))?;
    if r.protocol_version != PROTOCOL_VERSION {
        return Err(ProtoCodecError::UnsupportedVersion(r.protocol_version));
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_round_trips() {
        let r = Request {
            protocol_version: PROTOCOL_VERSION,
            verb: Verb::Whoami,
        };
        let bytes = encode_request(&r).unwrap();
        let back = decode_request(&bytes).unwrap();
        assert_eq!(back.verb, Verb::Whoami);
        assert_eq!(back.protocol_version, PROTOCOL_VERSION);
    }
    #[test]
    fn response_round_trips() {
        let r = Response {
            protocol_version: PROTOCOL_VERSION,
            result: RespResult::Ok(Payload::Whoami(WhoamiView {
                peer_plane_uri_san: "maknae://d/plane/cli".into(),
                peer_uid: 501,
            })),
        };
        let bytes = encode_response(&r).unwrap();
        match decode_response(&bytes).unwrap().result {
            RespResult::Ok(Payload::Whoami(w)) => {
                assert_eq!(w.peer_uid, 501);
            }
            _ => panic!("wrong variant"),
        }
    }
    #[test]
    fn decode_rejects_wrong_version() {
        let mut r = Request {
            protocol_version: 999,
            verb: Verb::Ping,
        };
        let bytes = {
            let mut b = Vec::new();
            ciborium::into_writer(&r, &mut b).unwrap();
            b
        };
        assert!(matches!(
            decode_request(&bytes),
            Err(ProtoCodecError::UnsupportedVersion(999))
        ));
        r.protocol_version = PROTOCOL_VERSION; // silence unused-mut on some toolchains
        let _ = r;
    }
    #[test]
    fn decode_response_rejects_wrong_version() {
        let r = Response {
            protocol_version: 999,
            result: RespResult::Ok(Payload::Pong),
        };
        let bytes = {
            let mut b = Vec::new();
            ciborium::into_writer(&r, &mut b).unwrap();
            b
        };
        assert!(matches!(
            decode_response(&bytes),
            Err(ProtoCodecError::UnsupportedVersion(999))
        ));
    }
    #[test]
    fn decode_rejects_malformed_cbor() {
        assert!(matches!(
            decode_request(&[0xff, 0xff, 0xff]),
            Err(ProtoCodecError::Decode(_))
        ));
    }
    #[test]
    fn decode_response_rejects_malformed_cbor() {
        assert!(matches!(
            decode_response(&[0xff, 0xff, 0xff]),
            Err(ProtoCodecError::Decode(_))
        ));
    }

    /// A type whose `Serialize` impl always errors — the only way to exercise
    /// `enc`'s `Encode` branch, since `ciborium::into_writer` never fails for
    /// this crate's own well-formed types.
    struct AlwaysFailsToSerialize;
    impl Serialize for AlwaysFailsToSerialize {
        fn serialize<S: serde::Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("deliberate test failure"))
        }
    }
    #[test]
    fn enc_surfaces_serialize_failure_as_encode_error() {
        assert!(matches!(
            enc(&AlwaysFailsToSerialize),
            Err(ProtoCodecError::Encode(_))
        ));
    }
}
