//! CBOR byte-string carriage for file content (spec D5). serde's derive on
//! `Vec<u8>` emits a CBOR ARRAY (~2 wire bytes per content byte, which would
//! halve the real read ceiling and route oversize to a client-side framing
//! error instead of `TooLarge`); this newtype pins the byte-string major type
//! with a hand-written impl — deliberately no `serde_bytes` dependency
//! (supply-chain: an unreviewed pinned dep for twenty lines of visitor).
//! Content is secret-adjacent (the deny-list grammar exists because home
//! files are): the buffer zeroizes on drop, and `Debug` redacts.
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// File content on the wire. CBOR byte-string major type (asserted by test),
/// zeroize-on-drop, redacting `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Bytes(pub Zeroizing<Vec<u8>>);

impl Bytes {
    /// Wrap an already-zeroizing buffer (the read path MOVES its buffer in —
    /// never copy content out of a `Zeroizing` into a plain `Vec`).
    pub fn new(buf: Zeroizing<Vec<u8>>) -> Self {
        Bytes(buf)
    }
}

/// Redacting: `Response`/`Payload` derive `Debug`, so a derived impl here
/// would dump home-file content into any `{:?}` (e.g. a future eprintln on a
/// write-failure path). Length only.
impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bytes(<{} bytes>)", self.0.len())
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> de::Visitor<'de> for V {
            type Value = Bytes;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a byte string")
            }
            // ONLY visit_byte_buf: ciborium's deserialize_byte_buf calls it
            // unconditionally for a Bytes header; a visit_bytes arm would be
            // dead code here — an uncovered T1 region and an unkillable
            // mutant. Non-Bytes headers: an Array routes to the default
            // visit_seq (refused, rendering this visitor's `expecting`);
            // everything else is short-circuited by ciborium itself with its
            // own "byte buffer" expected-text before the visitor is reached.
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Bytes, E> {
                Ok(Bytes(Zeroizing::new(v)))
            }
        }
        d.deserialize_byte_buf(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(b: &Bytes) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(b, &mut buf).unwrap();
        buf
    }

    #[test]
    fn bytes_encode_as_cbor_byte_string_major_type() {
        // CBOR major type 2 (byte string): high 3 bits of the initial byte
        // are 0b010. An array (major 4) would be 0b100.
        let buf = enc(&Bytes(Zeroizing::new(vec![0x41, 0x42, 0x43])));
        assert_eq!(
            buf[0] & 0xe0,
            0x40,
            "major type must be 2 (byte string), got {:#04x}",
            buf[0]
        );
        assert_ne!(buf[0] & 0xe0, 0x80, "must not be the derive's array form");
        // 3-byte definite-length byte string is exactly 0x43 then the bytes.
        assert_eq!(buf, vec![0x43, 0x41, 0x42, 0x43]);
    }

    #[test]
    fn bytes_roundtrip_non_utf8() {
        let b = Bytes(Zeroizing::new(vec![0xff, 0x00, 0xfe]));
        let back: Bytes = ciborium::from_reader(enc(&b).as_slice()).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn bytes_roundtrip_empty() {
        let b = Bytes(Zeroizing::new(Vec::new()));
        let back: Bytes = ciborium::from_reader(enc(&b).as_slice()).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn cbor_array_refused_with_visitor_expecting_text() {
        // serde's derive-form (array) must NOT deserialize into Bytes: the
        // Array header routes to the default visit_seq, whose error renders
        // this visitor's `expecting` — the `expecting`-mutant killer.
        let mut arr = Vec::new();
        ciborium::into_writer(&vec![1u8, 2, 3], &mut arr).unwrap();
        let got: Result<Bytes, _> = ciborium::from_reader(arr.as_slice());
        let msg = got.expect_err("array form must refuse").to_string();
        assert!(
            msg.contains("byte string"),
            "error must render the visitor's expecting text, got: {msg}"
        );
    }

    #[test]
    fn cbor_text_string_refused() {
        // Non-Bytes/non-Array headers are short-circuited by ciborium itself
        // ("byte buffer" is ciborium's own expected-text) before the visitor.
        let mut txt = Vec::new();
        ciborium::into_writer(&"hello", &mut txt).unwrap();
        let got: Result<Bytes, _> = ciborium::from_reader(txt.as_slice());
        let msg = got.expect_err("text form must refuse").to_string();
        assert!(
            msg.contains("byte"),
            "refusal must name the expected type, got: {msg}"
        );
    }

    #[test]
    fn debug_redacts_content() {
        let b = Bytes(Zeroizing::new(vec![0x53, 0x45, 0x43]));
        let s = format!("{b:?}");
        assert!(s.contains("<3 bytes>"), "{s}");
        assert!(
            !s.contains("53") && !s.contains("SEC"),
            "content leaked into Debug: {s}"
        );
    }
}
