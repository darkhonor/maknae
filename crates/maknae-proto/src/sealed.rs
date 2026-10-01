use crate::ProtoCodecError;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub const SEALED_KEY_MIN_BYTES: usize = 127;
pub const SEALED_KEY_MAX_BYTES: usize = 1150;

#[derive(Clone, PartialEq, Eq)]
pub struct SealedKey(Vec<u8>);

impl SealedKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProtoCodecError> {
        if !(SEALED_KEY_MIN_BYTES..=SEALED_KEY_MAX_BYTES).contains(&bytes.len()) {
            return Err(ProtoCodecError::Encode(format!(
                "sealed key is {} bytes; it must be {SEALED_KEY_MIN_BYTES}..={SEALED_KEY_MAX_BYTES}",
                bytes.len()
            )));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SealedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedKey(<{} bytes>)", self.0.len())
    }
}

impl Serialize for SealedKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SealedKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> de::Visitor<'de> for V {
            type Value = SealedKey;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    f,
                    "a sealed key of {SEALED_KEY_MIN_BYTES}..={SEALED_KEY_MAX_BYTES} bytes"
                )
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<SealedKey, E> {
                let n = v.len();
                SealedKey::new(v).map_err(|_| E::invalid_length(n, &self))
            }
        }
        d.deserialize_byte_buf(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(k: &SealedKey) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(k, &mut buf).unwrap();
        buf
    }

    fn byte_string(n: usize) -> Vec<u8> {
        let mut buf = match u8::try_from(n) {
            Ok(len) => vec![0x58, len],
            Err(_) => {
                let len = u16::try_from(n).unwrap().to_be_bytes();
                vec![0x59, len[0], len[1]]
            }
        };
        buf.resize(buf.len() + n, 7);
        buf
    }

    #[test]
    fn the_bounds_are_the_v1_sealed_blob_bounds() {
        assert_eq!((SEALED_KEY_MIN_BYTES, SEALED_KEY_MAX_BYTES), (127, 1150));
    }

    #[test]
    fn a_sealed_key_is_accepted_only_within_its_bounds() {
        for n in [SEALED_KEY_MIN_BYTES, SEALED_KEY_MAX_BYTES] {
            assert_eq!(SealedKey::new(vec![1; n]).unwrap().as_bytes(), vec![1u8; n]);
        }
        for n in [0, SEALED_KEY_MIN_BYTES - 1, SEALED_KEY_MAX_BYTES + 1] {
            match SealedKey::new(vec![1; n]) {
                Err(ProtoCodecError::Encode(m)) => {
                    assert_eq!(m, format!("sealed key is {n} bytes; it must be 127..=1150"))
                }
                other => panic!("{n} bytes: {other:?}"),
            }
        }
    }

    #[test]
    fn a_sealed_key_encodes_as_a_cbor_byte_string_and_round_trips() {
        let k = SealedKey::new((0..127u8).collect()).unwrap();
        let buf = enc(&k);
        assert_eq!(buf[..2], [0x58, 127]);
        assert_eq!(&buf[2..], k.as_bytes());
        let back: SealedKey = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn decoding_refuses_a_byte_string_outside_the_bounds() {
        for n in [SEALED_KEY_MIN_BYTES - 1, SEALED_KEY_MAX_BYTES + 1] {
            let got: Result<SealedKey, _> = ciborium::from_reader(byte_string(n).as_slice());
            let msg = got.expect_err("out of bounds").to_string();
            assert!(
                msg.contains(&format!("invalid length {n}"))
                    && msg.contains("a sealed key of 127..=1150 bytes"),
                "{msg}"
            );
        }
        for n in [SEALED_KEY_MIN_BYTES, SEALED_KEY_MAX_BYTES] {
            let got: SealedKey = ciborium::from_reader(byte_string(n).as_slice()).unwrap();
            assert_eq!(got.as_bytes().len(), n);
        }
    }

    #[test]
    fn decoding_refuses_an_array_or_a_text_string() {
        let mut arr = Vec::new();
        ciborium::into_writer(&vec![1u8; SEALED_KEY_MIN_BYTES], &mut arr).unwrap();
        let msg = ciborium::from_reader::<SealedKey, _>(arr.as_slice())
            .expect_err("array form")
            .to_string();
        assert!(msg.contains("a sealed key of 127..=1150 bytes"), "{msg}");
        let mut txt = Vec::new();
        ciborium::into_writer(&"x".repeat(SEALED_KEY_MIN_BYTES), &mut txt).unwrap();
        assert!(ciborium::from_reader::<SealedKey, _>(txt.as_slice()).is_err());
    }

    #[test]
    fn debug_prints_only_the_length() {
        let k = SealedKey::new(vec![0x53; SEALED_KEY_MIN_BYTES]).unwrap();
        assert_eq!(format!("{k:?}"), "SealedKey(<127 bytes>)");
    }
}
