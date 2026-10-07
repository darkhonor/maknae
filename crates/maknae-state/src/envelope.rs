use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::digest::{digest, SHA256};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use std::fmt;
use zeroize::Zeroizing;

pub const MAGIC: [u8; 4] = *b"MKNE";
pub const ENVELOPE_VERSION: u16 = 1;
pub const AEAD_AES_256_GCM: u16 = 1;
pub const WRAP_AES_256_GCM: u16 = 1;
pub const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const PREFIX_LEN: usize = 12;
const WRAP_NONCE: usize = PREFIX_LEN;
const WRAPPED_DEK: usize = WRAP_NONCE + NONCE_LEN;
const WRAP_TAG: usize = WRAPPED_DEK + KEY_LEN;
const PAYLOAD_NONCE: usize = WRAP_TAG + TAG_LEN;
pub const HEADER_LEN: usize = PAYLOAD_NONCE + NONCE_LEN;

pub struct WrappingKey(Zeroizing<[u8; KEY_LEN]>);

impl WrappingKey {
    pub fn new(bytes: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for WrappingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WrappingKey(..)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    Truncated,
    BadMagic,
    UnsupportedVersion(u16),
    UnknownAead(u16),
    UnknownWrap(u16),
    NonZeroReserved,
    Unwrap,
    Decrypt,
    Crypto,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("graph store is truncated"),
            Self::BadMagic => f.write_str("graph store does not begin with the MKNE magic"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported graph store envelope version {v}")
            }
            Self::UnknownAead(v) => write!(f, "unknown graph store cipher {v}"),
            Self::UnknownWrap(v) => write!(f, "unknown graph store key wrap {v}"),
            Self::NonZeroReserved => f.write_str("a reserved graph store field is not zero"),
            Self::Unwrap => {
                f.write_str("the graph store key does not unwrap: wrong key or tampered header")
            }
            Self::Decrypt => f.write_str("the graph store does not decrypt: tampered or truncated"),
            Self::Crypto => f.write_str("the cryptographic provider refused the operation"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

fn key(bytes: &[u8]) -> Result<LessSafeKey, EnvelopeError> {
    UnboundKey::new(&AES_256_GCM, bytes)
        .map(LessSafeKey::new)
        .map_err(|_| EnvelopeError::Crypto)
}

fn random<const N: usize>(rng: &SystemRandom) -> Result<[u8; N], EnvelopeError> {
    let mut out = [0u8; N];
    rng.fill(&mut out).map_err(|_| EnvelopeError::Crypto)?;
    Ok(out)
}

pub fn seal(plain: &[u8], kek: &WrappingKey) -> Result<Vec<u8>, EnvelopeError> {
    let rng = SystemRandom::new();
    let mut dek = Zeroizing::new([0u8; KEY_LEN]);
    rng.fill(&mut dek[..]).map_err(|_| EnvelopeError::Crypto)?;
    let wrap_nonce: [u8; NONCE_LEN] = random(&rng)?;
    let payload_nonce: [u8; NONCE_LEN] = random(&rng)?;

    let mut out = Vec::with_capacity(HEADER_LEN + plain.len() + TAG_LEN);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    out.extend_from_slice(&AEAD_AES_256_GCM.to_le_bytes());
    out.extend_from_slice(&WRAP_AES_256_GCM.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    let prefix: [u8; PREFIX_LEN] = out[..PREFIX_LEN].try_into().expect("prefix is 12 bytes");

    let mut wrapped = Zeroizing::new(*dek);
    let wrap_tag = key(&kek.0[..])?
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(wrap_nonce),
            Aad::from(prefix),
            &mut wrapped[..],
        )
        .map_err(|_| EnvelopeError::Crypto)?;
    out.extend_from_slice(&wrap_nonce);
    out.extend_from_slice(&wrapped[..]);
    out.extend_from_slice(wrap_tag.as_ref());
    out.extend_from_slice(&payload_nonce);

    let header: [u8; HEADER_LEN] = out[..].try_into().expect("header is complete");
    let start = out.len();
    out.extend_from_slice(plain);
    let tag = key(&dek[..])?
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(payload_nonce),
            Aad::from(header),
            &mut out[start..],
        )
        .map_err(|_| EnvelopeError::Crypto)?;
    out.extend_from_slice(tag.as_ref());
    Ok(out)
}

pub fn open(file: &[u8], kek: &WrappingKey) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    if file.len() < HEADER_LEN + TAG_LEN {
        return Err(EnvelopeError::Truncated);
    }
    if file[..4] != MAGIC {
        return Err(EnvelopeError::BadMagic);
    }
    let field = |at: usize| u16::from_le_bytes([file[at], file[at + 1]]);
    match (field(4), field(6), field(8), field(10)) {
        (v, _, _, _) if v != ENVELOPE_VERSION => return Err(EnvelopeError::UnsupportedVersion(v)),
        (_, a, _, _) if a != AEAD_AES_256_GCM => return Err(EnvelopeError::UnknownAead(a)),
        (_, _, w, _) if w != WRAP_AES_256_GCM => return Err(EnvelopeError::UnknownWrap(w)),
        (_, _, _, r) if r != 0 => return Err(EnvelopeError::NonZeroReserved),
        _ => {}
    }
    let nonce = |at: usize| {
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(&file[at..at + NONCE_LEN]);
        Nonce::assume_unique_for_key(n)
    };

    let mut wrapped = Zeroizing::new([0u8; KEY_LEN + TAG_LEN]);
    wrapped.copy_from_slice(&file[WRAPPED_DEK..PAYLOAD_NONCE]);
    let dek = key(&kek.0[..])?
        .open_in_place(
            nonce(WRAP_NONCE),
            Aad::from(&file[..PREFIX_LEN]),
            &mut wrapped[..],
        )
        .map_err(|_| EnvelopeError::Unwrap)?;

    let mut body = Zeroizing::new(file[HEADER_LEN..].to_vec());
    let plain_len = key(dek)?
        .open_in_place(
            nonce(PAYLOAD_NONCE),
            Aad::from(&file[..HEADER_LEN]),
            &mut body[..],
        )
        .map_err(|_| EnvelopeError::Decrypt)?
        .len();
    body.truncate(plain_len);
    Ok(body)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, bytes).as_ref());
    out
}

pub fn ciphertext_digest(file: &[u8]) -> [u8; 32] {
    sha256(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek(b: u8) -> WrappingKey {
        WrappingKey::new(Zeroizing::new([b; KEY_LEN]))
    }

    #[test]
    fn round_trip_and_layout() {
        let sealed = seal(b"graph bytes", &kek(7)).unwrap();
        assert_eq!(&sealed[..4], b"MKNE");
        assert_eq!(sealed.len(), HEADER_LEN + 11 + 16);
        assert_eq!(&sealed[4..12], &[1, 0, 1, 0, 1, 0, 0, 0]);
        assert_eq!(sealed.capacity(), sealed.len());
        assert_eq!(&*open(&sealed, &kek(7)).unwrap(), b"graph bytes");
        let empty = seal(b"", &kek(7)).unwrap();
        assert_eq!(empty.capacity(), empty.len());
        assert_eq!(&*open(&empty, &kek(7)).unwrap(), b"");
        let big = vec![0x5a; 200];
        let sealed_big = seal(&big, &kek(7)).unwrap();
        assert_eq!(sealed_big.capacity(), sealed_big.len());
        assert_eq!(&*open(&sealed_big, &kek(7)).unwrap(), &big[..]);
    }

    #[test]
    fn every_write_uses_a_fresh_data_key_and_nonces() {
        let a = seal(b"same", &kek(7)).unwrap();
        let b = seal(b"same", &kek(7)).unwrap();
        assert_ne!(a[12..24], b[12..24]);
        assert_ne!(a[24..56], b[24..56]);
        assert_ne!(a[72..84], b[72..84]);
        assert_ne!(a[84..], b[84..]);
    }

    #[test]
    fn wrong_key_refuses() {
        let sealed = seal(b"graph bytes", &kek(7)).unwrap();
        assert_eq!(open(&sealed, &kek(8)).unwrap_err(), EnvelopeError::Unwrap);
    }

    #[test]
    fn every_header_byte_is_authenticated() {
        let sealed = seal(b"graph bytes", &kek(7)).unwrap();
        for i in 0..sealed.len() {
            let mut m = sealed.clone();
            m[i] ^= 0x01;
            assert!(
                open(&m, &kek(7)).is_err(),
                "byte {i} flipped and still opened"
            );
        }
    }

    #[test]
    fn header_refusals_are_specific() {
        let sealed = seal(b"x", &kek(7)).unwrap();
        assert_eq!(
            open(&sealed[..HEADER_LEN + 15], &kek(7)).unwrap_err(),
            EnvelopeError::Truncated
        );
        assert_eq!(open(&[], &kek(7)).unwrap_err(), EnvelopeError::Truncated);
        let mut m = sealed.clone();
        m[0] = b'X';
        assert_eq!(open(&m, &kek(7)).unwrap_err(), EnvelopeError::BadMagic);
        let mut m = sealed.clone();
        m[4] = 2;
        assert_eq!(
            open(&m, &kek(7)).unwrap_err(),
            EnvelopeError::UnsupportedVersion(2)
        );
        let mut m = sealed.clone();
        m[6] = 9;
        assert_eq!(
            open(&m, &kek(7)).unwrap_err(),
            EnvelopeError::UnknownAead(9)
        );
        let mut m = sealed.clone();
        m[8] = 9;
        assert_eq!(
            open(&m, &kek(7)).unwrap_err(),
            EnvelopeError::UnknownWrap(9)
        );
        let mut m = sealed.clone();
        m[10] = 1;
        assert_eq!(
            open(&m, &kek(7)).unwrap_err(),
            EnvelopeError::NonZeroReserved
        );
        let mut m = sealed.clone();
        let last = m.len() - 1;
        m[last] ^= 1;
        assert_eq!(open(&m, &kek(7)).unwrap_err(), EnvelopeError::Decrypt);
    }

    #[test]
    fn digest_is_sha256_of_the_file() {
        assert_eq!(ciphertext_digest(b"abc")[..4], [0xba, 0x78, 0x16, 0xbf]);
    }

    #[test]
    fn sha256_is_the_digest_ciphertext_digest_uses() {
        assert_eq!(sha256(b"abc")[..4], [0xba, 0x78, 0x16, 0xbf]);
        assert_eq!(sha256(b"abc")[28..], [0xf2, 0x00, 0x15, 0xad]);
        assert_eq!(ciphertext_digest(b"graph"), sha256(b"graph"));
    }

    #[test]
    fn debug_never_prints_key_material() {
        assert_eq!(format!("{:?}", kek(0xab)), "WrappingKey(..)");
    }

    #[test]
    fn error_messages() {
        for (e, t) in [
            (EnvelopeError::Truncated, "graph store is truncated"),
            (
                EnvelopeError::BadMagic,
                "graph store does not begin with the MKNE magic",
            ),
            (
                EnvelopeError::UnsupportedVersion(2),
                "unsupported graph store envelope version 2",
            ),
            (
                EnvelopeError::UnknownAead(9),
                "unknown graph store cipher 9",
            ),
            (
                EnvelopeError::UnknownWrap(9),
                "unknown graph store key wrap 9",
            ),
            (
                EnvelopeError::NonZeroReserved,
                "a reserved graph store field is not zero",
            ),
            (
                EnvelopeError::Unwrap,
                "the graph store key does not unwrap: wrong key or tampered header",
            ),
            (
                EnvelopeError::Decrypt,
                "the graph store does not decrypt: tampered or truncated",
            ),
            (
                EnvelopeError::Crypto,
                "the cryptographic provider refused the operation",
            ),
        ] {
            assert_eq!(e.to_string(), t);
        }
    }
}
