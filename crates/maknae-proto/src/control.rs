//! The agent control channel's wire types (#746): one verb, one closed notice set, no task and no credential.
use crate::{ProtoCodecError, ProtoError, TaskId, PROTOCOL_VERSION};
use serde::de::DeserializeOwned;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

pub const NOTICES_MAX: usize = 8;
pub const CONTROL_REPLY_ENVELOPE: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NoticeId(pub [u8; 16]);

impl Serialize for NoticeId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for NoticeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> de::Visitor<'de> for V {
            type Value = NoticeId;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a 16-byte byte string")
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<NoticeId, E> {
                <[u8; 16]>::try_from(v.as_slice())
                    .map(NoticeId)
                    .map_err(|_| E::invalid_length(v.len(), &self))
            }
        }
        d.deserialize_byte_buf(V)
    }
}

impl std::fmt::Display for NoticeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

mod sealed {
    pub trait Sealed {}
}

/// A closed set of notice bodies. Sealed: only this crate defines one.
///
/// ```compile_fail,E0277
/// #[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
/// struct Outside;
/// impl maknae_proto::NoticeBody for Outside {
///     const NOTICE_MAX_BYTES: usize = 1;
///     fn kind(&self) -> &'static str { "outside" }
/// }
/// ```
pub trait NoticeBody:
    sealed::Sealed
    + Serialize
    + DeserializeOwned
    + Clone
    + PartialEq
    + std::fmt::Debug
    + Send
    + Sync
    + 'static
{
    const NOTICE_MAX_BYTES: usize;
    fn kind(&self) -> &'static str;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentNotice {
    Stop,
}

impl sealed::Sealed for AgentNotice {}

impl NoticeBody for AgentNotice {
    const NOTICE_MAX_BYTES: usize = 96;
    fn kind(&self) -> &'static str {
        match self {
            AgentNotice::Stop => "stop",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlVerb {
    NoticePoll {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlRequest {
    pub protocol_version: u16,
    pub verb: ControlVerb,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Notice<B: NoticeBody> {
    pub id: NoticeId,
    pub task: Option<TaskId>,
    pub body: B,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ControlResponse<B: NoticeBody> {
    pub protocol_version: u16,
    pub result: Result<Vec<Notice<B>>, ProtoError>,
}

pub const fn control_reply_cap<B: NoticeBody>() -> usize {
    NOTICES_MAX * B::NOTICE_MAX_BYTES + CONTROL_REPLY_ENVELOPE
}

pub fn encode_control_request(r: &ControlRequest) -> Result<Vec<u8>, ProtoCodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(r, &mut buf).map_err(|e| ProtoCodecError::Encode(e.to_string()))?;
    Ok(buf)
}

pub fn decode_control_request(b: &[u8]) -> Result<ControlRequest, ProtoCodecError> {
    let r: ControlRequest =
        ciborium::from_reader(b).map_err(|e| ProtoCodecError::Decode(e.to_string()))?;
    if r.protocol_version != PROTOCOL_VERSION {
        return Err(ProtoCodecError::UnsupportedVersion(r.protocol_version));
    }
    Ok(r)
}

pub fn encode_control_response<B: NoticeBody>(
    r: &ControlResponse<B>,
) -> Result<Vec<u8>, ProtoCodecError> {
    if matches!(&r.result, Ok(n) if n.len() > NOTICES_MAX) {
        return Err(ProtoCodecError::Encode("too many notices".into()));
    }
    let mut buf = Vec::new();
    ciborium::into_writer(r, &mut buf).map_err(|e| ProtoCodecError::Encode(e.to_string()))?;
    if buf.len() > control_reply_cap::<B>() {
        return Err(ProtoCodecError::Encode("control reply over its cap".into()));
    }
    Ok(buf)
}

pub fn decode_control_response<B: NoticeBody>(
    b: &[u8],
) -> Result<ControlResponse<B>, ProtoCodecError> {
    let r: ControlResponse<B> =
        ciborium::from_reader(b).map_err(|e| ProtoCodecError::Decode(e.to_string()))?;
    if r.protocol_version != PROTOCOL_VERSION {
        return Err(ProtoCodecError::UnsupportedVersion(r.protocol_version));
    }
    if matches!(&r.result, Ok(n) if n.len() > NOTICES_MAX) {
        return Err(ProtoCodecError::Decode("too many notices".into()));
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        decode_request, decode_response, encode_request, encode_response, ProtoErrCode, Request,
        RespResult, Response, Verb, CONTROL_REQUEST_MAX, CONTROL_RESPONSE_MAX,
    };

    fn poll() -> ControlRequest {
        ControlRequest {
            protocol_version: PROTOCOL_VERSION,
            verb: ControlVerb::NoticePoll {},
        }
    }

    fn widest() -> Notice<AgentNotice> {
        Notice {
            id: NoticeId([0xff; 16]),
            task: Some(TaskId([0xff; 16])),
            body: AgentNotice::Stop,
        }
    }

    fn refusal() -> ProtoError {
        ProtoError {
            code: ProtoErrCode::Unauthorized,
            message: "not authorized".into(),
        }
    }

    fn reply(n: usize) -> ControlResponse<AgentNotice> {
        ControlResponse {
            protocol_version: PROTOCOL_VERSION,
            result: Ok(vec![widest(); n]),
        }
    }

    #[test]
    fn a_notice_poll_request_fits_the_control_request_cap() {
        assert!(encode_control_request(&poll()).unwrap().len() <= CONTROL_REQUEST_MAX);
    }

    #[test]
    fn a_control_request_round_trips() {
        let b = encode_control_request(&poll()).unwrap();
        assert_eq!(decode_control_request(&b).unwrap(), poll());
    }

    #[test]
    fn a_control_request_is_not_a_data_plane_request() {
        let b = encode_control_request(&poll()).unwrap();
        assert!(matches!(
            decode_request(&b),
            Err(ProtoCodecError::Decode(_))
        ));
    }

    #[test]
    fn a_data_plane_request_is_not_a_control_request() {
        for verb in [
            Verb::Ping,
            Verb::Whoami,
            Verb::ToolCatalog {},
            Verb::TaskClaim {
                seen_follow_ups: None,
            },
        ] {
            let b = encode_request(&Request {
                protocol_version: PROTOCOL_VERSION,
                verb,
                task: None,
            })
            .unwrap();
            assert!(matches!(
                decode_control_request(&b),
                Err(ProtoCodecError::Decode(_))
            ));
        }
    }

    #[test]
    fn a_data_plane_request_of_another_version_is_still_a_decode_error() {
        let b = encode_request(&Request {
            protocol_version: 2,
            verb: Verb::Ping,
            task: None,
        })
        .unwrap();
        assert!(matches!(
            decode_control_request(&b),
            Err(ProtoCodecError::Decode(_))
        ));
    }

    #[test]
    fn a_control_request_of_another_version_is_refused() {
        let mut r = poll();
        r.protocol_version = 2;
        let b = encode_control_request(&r).unwrap();
        assert!(matches!(
            decode_control_request(&b),
            Err(ProtoCodecError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn a_control_response_of_another_version_is_refused() {
        let mut r = reply(1);
        r.protocol_version = 2;
        let b = encode_control_response(&r).unwrap();
        assert!(matches!(
            decode_control_response::<AgentNotice>(&b),
            Err(ProtoCodecError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn the_widest_stop_notice_fits_its_bound() {
        let mut b = Vec::new();
        ciborium::into_writer(&widest(), &mut b).unwrap();
        assert!(b.len() <= AgentNotice::NOTICE_MAX_BYTES);
    }

    #[test]
    fn a_full_reply_fits_the_reply_cap() {
        let b = encode_control_response(&reply(NOTICES_MAX)).unwrap();
        assert!(b.len() <= control_reply_cap::<AgentNotice>());
        assert_eq!(control_reply_cap::<AgentNotice>(), 1024);
    }

    #[test]
    fn the_refusal_reply_fits_the_reply_cap() {
        let b = encode_control_response(&ControlResponse::<AgentNotice> {
            protocol_version: PROTOCOL_VERSION,
            result: Err(refusal()),
        })
        .unwrap();
        assert!(b.len() <= control_reply_cap::<AgentNotice>());
    }

    #[test]
    fn the_reply_cap_is_within_the_control_response_cap() {
        assert!(control_reply_cap::<AgentNotice>() <= CONTROL_RESPONSE_MAX);
    }

    #[test]
    fn a_reply_over_the_cap_is_refused_on_encode() {
        let r = ControlResponse::<AgentNotice> {
            protocol_version: PROTOCOL_VERSION,
            result: Err(ProtoError {
                code: ProtoErrCode::Unauthorized,
                message: "x".repeat(control_reply_cap::<AgentNotice>()),
            }),
        };
        assert!(matches!(
            encode_control_response(&r),
            Err(ProtoCodecError::Encode(_))
        ));
    }

    #[test]
    fn a_reply_with_more_than_eight_notices_is_refused_both_ways() {
        assert!(matches!(
            encode_control_response(&reply(NOTICES_MAX + 1)),
            Err(ProtoCodecError::Encode(_))
        ));
        let mut b = Vec::new();
        ciborium::into_writer(&reply(NOTICES_MAX + 1), &mut b).unwrap();
        assert!(matches!(
            decode_control_response::<AgentNotice>(&b),
            Err(ProtoCodecError::Decode(_))
        ));
    }

    #[test]
    fn eight_notices_decode() {
        let b = encode_control_response(&reply(NOTICES_MAX)).unwrap();
        assert_eq!(
            decode_control_response::<AgentNotice>(&b).unwrap(),
            reply(NOTICES_MAX)
        );
    }

    #[test]
    fn a_control_response_round_trips_and_is_not_a_data_plane_response() {
        let b = encode_control_response(&reply(2)).unwrap();
        assert_eq!(
            decode_control_response::<AgentNotice>(&b).unwrap(),
            reply(2)
        );
        assert!(decode_response(&b).is_err());
    }

    #[test]
    fn a_data_plane_refusal_and_a_control_refusal_encode_identically() {
        let data = encode_response(&Response::new(
            PROTOCOL_VERSION,
            RespResult::Err(refusal()),
            None,
        ))
        .unwrap();
        let control = encode_control_response(&ControlResponse::<AgentNotice> {
            protocol_version: PROTOCOL_VERSION,
            result: Err(refusal()),
        })
        .unwrap();
        assert_eq!(data, control);
    }

    #[test]
    fn the_notice_id_prints_as_32_hex() {
        assert_eq!(NoticeId([0xab; 16]).to_string(), "ab".repeat(16));
    }

    #[test]
    fn a_notice_id_of_another_length_does_not_decode() {
        let mut b = Vec::new();
        ciborium::into_writer(&serde_bytes_like(&[1u8; 15]), &mut b).unwrap();
        let e = ciborium::from_reader::<NoticeId, _>(b.as_slice()).unwrap_err();
        assert!(e.to_string().contains("16-byte"));
    }

    #[test]
    fn a_reply_of_exactly_the_cap_encodes_and_one_over_does_not() {
        let cap = control_reply_cap::<AgentNotice>();
        let sized = |m: usize| ControlResponse::<AgentNotice> {
            protocol_version: PROTOCOL_VERSION,
            result: Err(ProtoError {
                code: ProtoErrCode::Unauthorized,
                message: "x".repeat(m),
            }),
        };
        let raw = |m: usize| {
            let mut b = Vec::new();
            ciborium::into_writer(&sized(m), &mut b).unwrap();
            b.len()
        };
        let m = (0..cap).find(|m| raw(*m) == cap).unwrap();
        assert_eq!(encode_control_response(&sized(m)).unwrap().len(), cap);
        assert!(encode_control_response(&sized(m + 1)).is_err());
    }

    fn serde_bytes_like(v: &[u8]) -> ciborium::Value {
        ciborium::Value::Bytes(v.to_vec())
    }

    #[test]
    fn the_stop_kind_is_stop() {
        assert_eq!(AgentNotice::Stop.kind(), "stop");
    }
}
