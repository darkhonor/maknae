use crate::glue::{fips_gate, lc};
use crate::seal_pub::{check_canonical, check_length, check_tag, encode_seal_pub};
use crate::SealError;
use aws_lc_rs::agreement::{
    ParsedPublicKey, ParsedPublicKeyFormat, PrivateKey, UnparsedPublicKey, ECDH_P384,
};
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use std::fmt;
use zeroize::Zeroizing;

pub const SPKI_P384_LEN: usize = 120;

#[derive(Clone, PartialEq, Eq)]
pub struct SealPublicKey {
    spki: [u8; SPKI_P384_LEN],
}

impl SealPublicKey {
    pub fn from_spki_der(der: &[u8]) -> Result<Self, SealError> {
        let spki: [u8; SPKI_P384_LEN] = lc(der.try_into(), SealError::PublicKey)?;
        let parsed = lc(
            ParsedPublicKey::try_from(UnparsedPublicKey::new(&ECDH_P384, &spki[..])),
            SealError::PublicKey,
        )?;
        if !matches!(parsed.format(), ParsedPublicKeyFormat::X509) {
            return Err(SealError::PublicKey);
        }
        Ok(Self { spki })
    }

    pub fn from_pem(text: &str) -> Result<Self, SealError> {
        check_length(text)?;
        let block = lc(pem::parse(text), SealError::PublicKey)?;
        check_tag(block.tag())?;
        let key = Self::from_spki_der(block.contents())?;
        check_canonical(text, key.spki_der())?;
        Ok(key)
    }

    pub fn to_pem(&self) -> String {
        encode_seal_pub(&self.spki)
    }

    pub fn spki_der(&self) -> &[u8] {
        &self.spki
    }
}

impl fmt::Debug for SealPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealPublicKey(P-384)")
    }
}

pub struct SealPrivateKey {
    key: PrivateKey,
    public: SealPublicKey,
}

impl SealPrivateKey {
    pub fn generate() -> Result<Self, SealError> {
        fips_gate()?;
        Self::from_key(lc(PrivateKey::generate(&ECDH_P384), SealError::Crypto)?)
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, SealError> {
        fips_gate()?;
        Self::from_key(lc(
            PrivateKey::from_private_key_der(&ECDH_P384, der),
            SealError::PrivateKey,
        )?)
    }

    fn from_key(key: PrivateKey) -> Result<Self, SealError> {
        let public = lc(key.compute_public_key(), SealError::Crypto)?;
        let spki: PublicKeyX509Der<'static> = lc(public.as_der(), SealError::Crypto)?;
        let public = SealPublicKey::from_spki_der(spki.as_ref())?;
        Ok(Self { key, public })
    }

    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let der: Pkcs8V1Der<'static> = lc(self.key.as_der(), SealError::Crypto)?;
        Ok(Zeroizing::new(der.as_ref().to_vec()))
    }

    pub fn public_key(&self) -> &SealPublicKey {
        &self.public
    }

    pub(crate) fn agreement_key(&self) -> &PrivateKey {
        &self.key
    }
}

impl fmt::Debug for SealPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealPrivateKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SEAL_PUB_PEM_LEN;
    use aws_lc_rs::agreement::ECDH_P256;

    #[test]
    fn a_generated_key_has_a_120_byte_p384_spki_and_a_redacted_debug() {
        let key = SealPrivateKey::generate().unwrap();
        assert_eq!(key.public_key().spki_der().len(), SPKI_P384_LEN);
        assert!(format!("{key:?}") == "SealPrivateKey(<redacted>)");
        assert_eq!(format!("{:?}", key.public_key()), "SealPublicKey(P-384)");
    }

    #[test]
    fn two_generated_keys_differ() {
        let a = SealPrivateKey::generate().unwrap();
        let b = SealPrivateKey::generate().unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn pkcs8_round_trips_into_the_same_public_key_and_does_not_grow() {
        let key = SealPrivateKey::generate().unwrap();
        let der = key.to_pkcs8_der().unwrap();
        assert_eq!(der.len(), der.capacity());
        let back = SealPrivateKey::from_pkcs8_der(&der).unwrap();
        assert_eq!(back.public_key(), key.public_key());
    }

    #[test]
    fn a_p256_or_garbage_private_key_is_refused() {
        let p256 = PrivateKey::generate(&ECDH_P256).unwrap();
        let der: Pkcs8V1Der<'static> = p256.as_der().unwrap();
        assert_eq!(
            SealPrivateKey::from_pkcs8_der(der.as_ref()).unwrap_err(),
            SealError::PrivateKey
        );
        assert_eq!(
            SealPrivateKey::from_pkcs8_der(b"not a key").unwrap_err(),
            SealError::PrivateKey
        );
    }

    #[test]
    fn the_public_pem_is_canonical_and_round_trips() {
        let key = SealPrivateKey::generate().unwrap();
        let pem_text = key.public_key().to_pem();
        assert_eq!(pem_text.len(), SEAL_PUB_PEM_LEN);
        assert!(pem_text.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem_text.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(!pem_text.contains('\r'));
        assert_eq!(
            &SealPublicKey::from_pem(&pem_text).unwrap(),
            key.public_key()
        );
    }

    #[test]
    fn a_non_canonical_or_foreign_public_pem_is_refused() {
        let key = SealPrivateKey::generate().unwrap();
        let canonical = key.public_key().to_pem();
        let other = SealPrivateKey::generate().unwrap().public_key().to_pem();
        let p256 = PrivateKey::generate(&ECDH_P256).unwrap();
        let p256_spki: PublicKeyX509Der<'static> =
            p256.compute_public_key().unwrap().as_der().unwrap();
        let p256_pem = pem::encode_config(
            &pem::Pem::new("PUBLIC KEY", p256_spki.as_ref().to_vec()),
            pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        );
        let mut reflowed = canonical.replacen('\n', "", 2);
        reflowed.insert(26, '\n');
        reflowed.push('\n');
        assert_eq!(reflowed.len(), SEAL_PUB_PEM_LEN);
        for bad in [
            canonical.replace('\n', "\r\n"),
            format!("{canonical}trailing"),
            format!("{canonical}{other}"),
            canonical.replace("PUBLIC KEY", "PRIVATE KEY"),
            canonical.replace("PUBLIC KEY", "PUBLIC KEZ"),
            p256_pem,
            reflowed,
            "x".repeat(SEAL_PUB_PEM_LEN),
            String::new(),
        ] {
            assert_eq!(
                SealPublicKey::from_pem(&bad).unwrap_err(),
                SealError::PublicKey,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_spki_of_the_wrong_length_or_content_is_refused() {
        let key = SealPrivateKey::generate().unwrap();
        let spki = key.public_key().spki_der();
        assert_eq!(
            &SealPublicKey::from_spki_der(spki).unwrap(),
            key.public_key()
        );
        assert_eq!(
            SealPublicKey::from_spki_der(&spki[..SPKI_P384_LEN - 1]).unwrap_err(),
            SealError::PublicKey
        );
        assert_eq!(
            SealPublicKey::from_spki_der(&[0u8; SPKI_P384_LEN]).unwrap_err(),
            SealError::PublicKey
        );
    }
}
