//! Versioned CBOR request/response contract (spec §3).
use crate::error::ProtoCodecError;
use serde::{Deserialize, Serialize};

// PROTOCOL_VERSION STAYS 1 (#77): adding `Verb::Read`/`Payload::ReadContent`/
// `ProtoErrCode::TooLarge` are ADDITIVE CBOR enum variants — no version bump.
// A pre-#77 CLI never sends `Read`, so it keeps interoperating with a #77
// daemon for `ping`/`whoami` (same wire version); only the new read verb
// needs the new CLI. A version bump would be an irreversible hard mutual
// break (strict-equality check both directions) and was NOT authorized.
pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verb {
    Ping,
    Whoami,
    /// Read a file under the enrolled principal's home (spec D5). `path` is
    /// the client-supplied lexically-absolute path; the daemon re-runs its
    /// own canonical pre-gate and NEVER trusts client canonicalization. CBOR
    /// text (a byte-string path fails String's visitor at decode).
    Read {
        path: String,
    },
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
    /// File content for a permitted `Read` — byte-string on the wire,
    /// zeroize-on-drop, redacting Debug (see [`crate::Bytes`]).
    ReadContent(crate::Bytes),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtoErrCode {
    UnknownVerb,
    Unauthorized,
    BadRequest,
    Internal,
    /// A permitted read whose content exceeds the daemon's frame budget —
    /// delivery refused, never truncated (spec D5).
    TooLarge,
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
/// Encode into a pre-sized zeroizing buffer — the read path's encode (spec
/// D5: zeroization preserved to the wire). Pre-sizing prevents realloc from
/// leaving un-zeroized partial copies of content in freed heap; `capacity`
/// should be the frame budget plus envelope margin. Ping/Whoami keep the
/// plain [`encode_response`].
pub fn encode_response_zeroizing(
    r: &Response,
    capacity: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ProtoCodecError> {
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
    ciborium::into_writer(r, &mut *buf).map_err(|e| ProtoCodecError::Encode(e.to_string()))?;
    Ok(buf)
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
    mod v2 {
        use super::super::*;
        use zeroize::Zeroizing;

        #[test]
        fn read_verb_round_trips_with_path() {
            let r = Request {
                protocol_version: PROTOCOL_VERSION,
                verb: Verb::Read {
                    path: "/home/op/notes.txt".into(),
                },
            };
            let back = decode_request(&encode_request(&r).unwrap()).unwrap();
            assert_eq!(
                back.verb,
                Verb::Read {
                    path: "/home/op/notes.txt".into()
                }
            );
        }

        #[test]
        fn read_content_round_trips_bytes() {
            let r = Response {
                protocol_version: PROTOCOL_VERSION,
                result: RespResult::Ok(Payload::ReadContent(crate::Bytes(Zeroizing::new(vec![
                    0xff, 0x00,
                ])))),
            };
            match decode_response(&encode_response(&r).unwrap())
                .unwrap()
                .result
            {
                RespResult::Ok(Payload::ReadContent(b)) => assert_eq!(*b.0, vec![0xff, 0x00]),
                other => panic!("wrong variant: {other:?}"),
            }
        }

        #[test]
        fn too_large_code_round_trips() {
            let r = Response {
                protocol_version: PROTOCOL_VERSION,
                result: RespResult::Err(ProtoError {
                    code: ProtoErrCode::TooLarge,
                    message: "resource too large".into(),
                }),
            };
            match decode_response(&encode_response(&r).unwrap())
                .unwrap()
                .result
            {
                RespResult::Err(e) => assert_eq!(e.code, ProtoErrCode::TooLarge),
                other => panic!("wrong variant: {other:?}"),
            }
        }

        #[test]
        fn adding_read_is_additive_no_version_bump() {
            // #77 stays on wire version 1: PROTOCOL_VERSION is 1, so a pre-#77
            // CLI's Ping (version 1, the unchanged verbs) still decodes on a
            // #77 daemon — no hard break — and the NEW Read verb round-trips at
            // the SAME version.
            assert_eq!(PROTOCOL_VERSION, 1, "no unauthorized wire bump");
            let ping = Request {
                protocol_version: 1,
                verb: Verb::Ping,
            };
            let mut b = Vec::new();
            ciborium::into_writer(&ping, &mut b).unwrap();
            assert_eq!(decode_request(&b).unwrap().verb, Verb::Ping);

            let read = Request {
                protocol_version: 1,
                verb: Verb::Read {
                    path: "/home/op/x".into(),
                },
            };
            let mut b = Vec::new();
            ciborium::into_writer(&read, &mut b).unwrap();
            assert_eq!(
                decode_request(&b).unwrap().verb,
                Verb::Read {
                    path: "/home/op/x".into()
                }
            );
        }

        #[test]
        fn a_genuinely_wrong_version_still_refuses_cleanly() {
            // The version guard still exists for a real mismatch (a future
            // deliberate bump, or garbage) — typed, never a panic.
            let req = Request {
                protocol_version: 999,
                verb: Verb::Ping,
            };
            let mut b = Vec::new();
            ciborium::into_writer(&req, &mut b).unwrap();
            assert!(matches!(
                decode_request(&b),
                Err(ProtoCodecError::UnsupportedVersion(999))
            ));
        }

        #[test]
        fn encode_response_zeroizing_carries_content_and_does_not_grow() {
            let content = vec![0xabu8; 1000];
            let r = Response {
                protocol_version: PROTOCOL_VERSION,
                result: RespResult::Ok(Payload::ReadContent(crate::Bytes(Zeroizing::new(
                    content.clone(),
                )))),
            };
            let cap = 1000 + 1024;
            let buf = encode_response_zeroizing(&r, cap).unwrap();
            // Pre-sizing held: no realloc means capacity is exactly what we asked.
            assert_eq!(
                buf.capacity(),
                cap,
                "encode grew the buffer — realloc leaves un-zeroized copies"
            );
            // And the content actually rides inside.
            let back = decode_response(&buf).unwrap();
            match back.result {
                RespResult::Ok(Payload::ReadContent(b)) => assert_eq!(*b.0, content),
                other => panic!("wrong variant: {other:?}"),
            }
        }
    }
}
