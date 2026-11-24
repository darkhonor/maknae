use crate::ProtoCodecError;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub const SEALED_KEY_MIN_BYTES: usize = 127;
pub const SEALED_KEY_MAX_BYTES: usize = 1150;

fn bounded(what: &str, bytes: Vec<u8>) -> Result<Vec<u8>, ProtoCodecError> {
    if !(SEALED_KEY_MIN_BYTES..=SEALED_KEY_MAX_BYTES).contains(&bytes.len()) {
        return Err(ProtoCodecError::Encode(format!(
            "{what} is {} bytes; it must be {SEALED_KEY_MIN_BYTES}..={SEALED_KEY_MAX_BYTES}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

struct BoundedBytes<T> {
    what: &'static str,
    make: fn(Vec<u8>) -> Result<T, ProtoCodecError>,
}

impl<'de, T> de::Visitor<'de> for BoundedBytes<T> {
    type Value = T;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "a {} of {SEALED_KEY_MIN_BYTES}..={SEALED_KEY_MAX_BYTES} bytes",
            self.what
        )
    }
    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<T, E> {
        let n = v.len();
        (self.make)(v).map_err(|_| E::invalid_length(n, &self))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SealedKey(Vec<u8>);

impl SealedKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProtoCodecError> {
        bounded("sealed key", bytes).map(Self)
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
        d.deserialize_byte_buf(BoundedBytes {
            what: "sealed key",
            make: SealedKey::new,
        })
    }
}

/// A credential sealed to one recipient, inside the same length bounds as a [`SealedKey`].
#[derive(Clone, PartialEq, Eq)]
pub struct SealedCredentialBytes(Vec<u8>);

impl SealedCredentialBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProtoCodecError> {
        bounded("sealed credential", bytes).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SealedCredentialBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedCredentialBytes(<{} bytes>)", self.0.len())
    }
}

impl Serialize for SealedCredentialBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SealedCredentialBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_byte_buf(BoundedBytes {
            what: "sealed credential",
            make: SealedCredentialBytes::new,
        })
    }
}

pub const FORGE_TOKENS_MAX: usize = 8;
pub const FORGE_NONCE_HEX_LEN: usize = 32;

pub(crate) fn forge_nonce_is_acceptable(nonce: &str) -> bool {
    let hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    nonce.len() == FORGE_NONCE_HEX_LEN && nonce.bytes().all(hex)
}

/// A tasker's forge token sealed to the Egress Daemon for one bound `server`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "SealedForgeTokenWire")]
pub struct SealedForgeToken {
    server: String,
    nonce: String,
    sealed: SealedKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedForgeTokenWire {
    server: String,
    nonce: String,
    sealed: SealedKey,
}

impl TryFrom<SealedForgeTokenWire> for SealedForgeToken {
    type Error = ProtoCodecError;
    fn try_from(w: SealedForgeTokenWire) -> Result<Self, ProtoCodecError> {
        SealedForgeToken::new(w.server, w.nonce, w.sealed)
    }
}

impl SealedForgeToken {
    pub fn new(server: String, nonce: String, sealed: SealedKey) -> Result<Self, ProtoCodecError> {
        if !crate::server_is_acceptable(&server) {
            return Err(ProtoCodecError::Encode(format!(
                "forge token `server` is not a lowercase host[:port] of at most {} bytes",
                crate::SERVER_MAX_BYTES
            )));
        }
        if !forge_nonce_is_acceptable(&nonce) {
            return Err(ProtoCodecError::Encode(format!(
                "forge token `nonce` is not {FORGE_NONCE_HEX_LEN} lowercase hex digits"
            )));
        }
        Ok(Self {
            server,
            nonce,
            sealed,
        })
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn sealed(&self) -> &SealedKey {
        &self.sealed
    }

    /// `(server, nonce, sealed)`, consuming the token.
    pub fn into_parts(self) -> (String, String, SealedKey) {
        (self.server, self.nonce, self.sealed)
    }
}

impl fmt::Debug for SealedForgeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedForgeToken")
            .field("server", &self.server)
            .field("sealed", &self.sealed)
            .finish()
    }
}

/// At most one token per server, so at most [`FORGE_TOKENS_MAX`].
#[derive(Clone, PartialEq, Eq, Default, Debug, Serialize)]
#[serde(transparent)]
pub struct ForgeTokens(Vec<SealedForgeToken>);

impl ForgeTokens {
    pub fn new(tokens: Vec<SealedForgeToken>) -> Result<Self, ProtoCodecError> {
        if tokens.len() > FORGE_TOKENS_MAX {
            return Err(ProtoCodecError::Encode(format!(
                "more than {FORGE_TOKENS_MAX} forge tokens"
            )));
        }
        if tokens
            .iter()
            .enumerate()
            .any(|(i, t)| tokens[..i].iter().any(|u| u.server == t.server))
        {
            return Err(ProtoCodecError::Encode(
                "two forge tokens for one server".into(),
            ));
        }
        Ok(Self(tokens))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slice(&self) -> &[SealedForgeToken] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<SealedForgeToken> {
        self.0
    }
}

impl<'de> Deserialize<'de> for ForgeTokens {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        ForgeTokens::new(Vec::deserialize(d)?).map_err(de::Error::custom)
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

    #[derive(Serialize, Clone)]
    struct RawToken<'a> {
        server: &'a str,
        nonce: &'a str,
        sealed: &'a SealedKey,
    }

    fn raw(t: &SealedForgeToken) -> RawToken<'_> {
        RawToken {
            server: t.server(),
            nonce: t.nonce(),
            sealed: t.sealed(),
        }
    }

    fn decode_tokens(list: &[RawToken<'_>]) -> Result<ForgeTokens, String> {
        let mut buf = Vec::new();
        ciborium::into_writer(list, &mut buf).unwrap();
        ciborium::from_reader::<ForgeTokens, _>(buf.as_slice()).map_err(|e| e.to_string())
    }

    #[test]
    fn a_ninth_token_or_a_duplicate_server_never_decodes() {
        let nine = crate::testutil::widest_forge_tokens(FORGE_TOKENS_MAX + 1);
        let eight = &nine[..FORGE_TOKENS_MAX];
        let raws: Vec<RawToken<'_>> = eight.iter().map(raw).collect();
        assert_eq!(decode_tokens(&raws).unwrap().as_slice(), eight);
        assert_eq!(ForgeTokens::new(eight.to_vec()).unwrap().as_slice(), eight);

        let all: Vec<RawToken<'_>> = nine.iter().map(raw).collect();
        let msg = decode_tokens(&all).expect_err("a ninth token");
        assert!(msg.contains("more than 8 forge tokens"), "{msg}");
        assert!(ForgeTokens::new(nine.clone()).is_err());

        let mut twin = raws[..2].to_vec();
        twin[1].server = twin[0].server;
        let msg = decode_tokens(&twin).expect_err("a duplicate server");
        assert!(msg.contains("two forge tokens for one server"), "{msg}");
        let dup = SealedForgeToken::new(
            nine[0].server().into(),
            nine[1].nonce().into(),
            nine[1].sealed().clone(),
        )
        .unwrap();
        assert!(ForgeTokens::new(vec![nine[0].clone(), dup]).is_err());

        let sealed = nine[0].sealed();
        let good_nonce = nine[0].nonce();
        let long_server = format!("a{}", nine[0].server());
        for server in [
            "Forge.example",
            "forge example",
            "",
            "-forge",
            "forge:0",
            &long_server,
        ] {
            let msg = decode_tokens(&[RawToken {
                server,
                nonce: good_nonce,
                sealed,
            }])
            .expect_err(server);
            assert!(msg.contains("forge token `server`"), "{server}: {msg}");
            assert!(
                SealedForgeToken::new(server.into(), good_nonce.into(), sealed.clone()).is_err()
            );
        }
        let short = "0".repeat(FORGE_NONCE_HEX_LEN - 1);
        let long = "0".repeat(FORGE_NONCE_HEX_LEN + 1);
        let upper = "A".repeat(FORGE_NONCE_HEX_LEN);
        let not_hex = "g".repeat(FORGE_NONCE_HEX_LEN);
        for nonce in [short.as_str(), &long, &upper, &not_hex, ""] {
            let msg = decode_tokens(&[RawToken {
                server: "forge.example",
                nonce,
                sealed,
            }])
            .expect_err(nonce);
            assert!(msg.contains("forge token `nonce`"), "{nonce}: {msg}");
            assert!(
                SealedForgeToken::new("forge.example".into(), nonce.into(), sealed.clone())
                    .is_err()
            );
        }
    }

    #[test]
    fn a_forge_token_debug_names_no_bytes() {
        let tokens = ForgeTokens::new(crate::testutil::widest_forge_tokens(2)).unwrap();
        let nonce = tokens.as_slice()[1].nonce().to_owned();
        let shown = [
            format!("{:?}", tokens.as_slice()[1]),
            format!("{tokens:?}"),
            format!(
                "{:?}",
                crate::Verb::TaskAdd {
                    task: crate::TaskRef::parse(&"a5".repeat(16)).unwrap(),
                    text: crate::SecretText(zeroize::Zeroizing::new("more".into())),
                    bindings: vec![],
                    forge_tokens: tokens.clone(),
                }
            ),
        ];
        for s in &shown {
            assert!(!s.contains(&nonce), "{s}");
            assert!(!s.contains("83, 83"), "{s}");
            assert!(s.contains(tokens.as_slice()[1].server()), "{s}");
            assert!(s.contains("<1150 bytes>"), "{s}");
        }
        assert_eq!(
            format!("{:?}", tokens.as_slice()[0]),
            format!(
                "SealedForgeToken {{ server: {:?}, sealed: SealedKey(<1150 bytes>) }}",
                tokens.as_slice()[0].server()
            )
        );
    }

    #[test]
    fn forge_tokens_give_back_the_tokens_they_hold() {
        let two = crate::testutil::widest_forge_tokens(2);
        assert_eq!(ForgeTokens::new(two.clone()).unwrap().into_vec(), two);
    }
}
