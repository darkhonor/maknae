//! AES-256-GCM. Sealing goes through `RandomizedNonceKey`, so the module picks every
//! nonce (aws-lc-rs: `LessSafeKey` sealing must not be used under FIPS).
use crate::CryptoError;
use aws_lc_rs::aead::{self, Aad, LessSafeKey, RandomizedNonceKey, UnboundKey, AES_256_GCM};
use std::fmt;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = aead::NONCE_LEN;
pub const TAG_LEN: usize = 16;

pub struct Aes256GcmKey {
    sealer: RandomizedNonceKey,
    opener: LessSafeKey,
}

impl Aes256GcmKey {
    pub fn new(key: &[u8; KEY_LEN]) -> Result<Self, CryptoError> {
        let sealer = RandomizedNonceKey::new(&AES_256_GCM, key);
        let sealer = sealer.map_err(|_| CryptoError::AeadKey)?;
        let opener = UnboundKey::new(&AES_256_GCM, key);
        let opener = opener.map_err(|_| CryptoError::AeadKey)?;
        let opener = LessSafeKey::new(opener);
        Ok(Self { sealer, opener })
    }

    pub fn seal_in_place(
        &self,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], [u8; TAG_LEN]), CryptoError> {
        let (nonce, tag) = self
            .sealer
            .seal_in_place_separate_tag(Aad::from(aad), buf)
            .map_err(|_| CryptoError::AeadSeal)?;
        let mut t = [0u8; TAG_LEN];
        t.copy_from_slice(tag.as_ref());
        Ok((*nonce.as_ref(), t))
    }

    pub fn open_in_place<'b>(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &'b mut [u8],
    ) -> Result<&'b mut [u8], CryptoError> {
        self.opener
            .open_in_place(
                aead::Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                buf,
            )
            .map_err(|_| CryptoError::AeadOpen)
    }
}

impl fmt::Debug for Aes256GcmKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Aes256GcmKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Aes256GcmKey {
        Aes256GcmKey::new(&[b; KEY_LEN]).unwrap()
    }

    fn sealed(k: &Aes256GcmKey, aad: &[u8], plain: &[u8]) -> ([u8; NONCE_LEN], Vec<u8>) {
        let mut buf = plain.to_vec();
        let (nonce, tag) = k.seal_in_place(aad, &mut buf).unwrap();
        buf.extend_from_slice(&tag);
        (nonce, buf)
    }

    #[test]
    fn a_sealed_buffer_opens_to_its_plaintext() {
        let k = key(7);
        let (n, mut buf) = sealed(&k, b"aad", b"plaintext");
        assert_eq!(k.open_in_place(&n, b"aad", &mut buf).unwrap(), b"plaintext");
    }

    #[test]
    fn the_module_picks_a_different_nonce_each_seal() {
        let k = key(7);
        let (n1, c1) = sealed(&k, b"", b"same");
        let (n2, c2) = sealed(&k, b"", b"same");
        assert_ne!(n1, n2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn every_wrong_input_is_refused() {
        let k = key(7);
        let (n, buf) = sealed(&k, b"aad", b"plaintext");
        let open = |k: &Aes256GcmKey, n: &[u8; NONCE_LEN], aad: &[u8], mut b: Vec<u8>| {
            k.open_in_place(n, aad, &mut b).map(|p| p.to_vec())
        };
        assert!(open(&k, &n, b"aad", buf.clone()).is_ok());
        assert!(matches!(
            open(&key(8), &n, b"aad", buf.clone()),
            Err(CryptoError::AeadOpen)
        ));
        let mut n2 = n;
        n2[0] ^= 1;
        assert!(matches!(
            open(&k, &n2, b"aad", buf.clone()),
            Err(CryptoError::AeadOpen)
        ));
        assert!(matches!(
            open(&k, &n, b"aaD", buf.clone()),
            Err(CryptoError::AeadOpen)
        ));
        let mut tampered = buf.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            open(&k, &n, b"aad", tampered),
            Err(CryptoError::AeadOpen)
        ));
        assert!(matches!(
            open(&k, &n, b"aad", buf[..TAG_LEN - 1].to_vec()),
            Err(CryptoError::AeadOpen)
        ));
    }

    #[test]
    fn debug_shows_no_key_material() {
        assert_eq!(format!("{:?}", key(7)), "Aes256GcmKey(<redacted>)");
    }
}
