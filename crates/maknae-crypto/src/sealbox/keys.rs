use crate::fips::assert_fips_module;
use crate::CryptoError;
use aws_lc_rs::agreement::{
    ParsedPublicKey, ParsedPublicKeyFormat, PrivateKey as AgreementKey, UnparsedPublicKey,
    ECDH_P384,
};
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use std::fmt;
use zeroize::Zeroizing;

/// The DER length of a P-384 SubjectPublicKeyInfo.
pub const SPKI_LEN: usize = 120;
/// The length of a canonical P-384 public-key PEM with LF line endings.
pub const PEM_LEN: usize = 215;
const PEM_TAG: &str = "PUBLIC KEY";

/// A sealed-box recipient's P-384 public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    spki: [u8; SPKI_LEN],
}

impl PublicKey {
    /// Parses a P-384 SubjectPublicKeyInfo, refusing any other key or encoding.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CryptoError> {
        let spki: [u8; SPKI_LEN] = der.try_into().map_err(|_| CryptoError::SealPublicKey)?;
        let parsed = ParsedPublicKey::try_from(UnparsedPublicKey::new(&ECDH_P384, &spki[..]));
        let parsed = parsed.map_err(|_| CryptoError::SealPublicKey)?;
        match parsed.format() {
            ParsedPublicKeyFormat::X509 => Ok(Self { spki }),
            _ => Err(CryptoError::SealPublicKey),
        }
    }

    /// Parses exactly one canonical `PUBLIC KEY` PEM block holding a P-384 key.
    pub fn from_pem(text: &str) -> Result<Self, CryptoError> {
        check_length(text)?;
        let block = pem::parse(text).map_err(|_| CryptoError::SealPublicKey)?;
        check_tag(block.tag())?;
        let key = Self::from_spki_der(block.contents())?;
        check_canonical(text, key.spki_der())?;
        Ok(key)
    }

    /// The canonical PEM encoding of the key.
    pub fn to_pem(&self) -> String {
        encode_pem(&self.spki)
    }

    /// The key's SubjectPublicKeyInfo DER.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(P-384)")
    }
}

/// A sealed-box recipient's P-384 private key.
pub struct PrivateKey {
    key: AgreementKey,
    public: PublicKey,
}

impl PrivateKey {
    /// Generates a fresh key in the FIPS module.
    pub fn generate() -> Result<Self, CryptoError> {
        let generated = assert_fips_module()
            .and_then(|()| AgreementKey::generate(&ECDH_P384).map_err(|_| CryptoError::Primitive));
        Self::from_key(generated?)
    }

    /// Parses a P-384 PKCS#8 private key.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        let parsed = assert_fips_module().and_then(|()| {
            AgreementKey::from_private_key_der(&ECDH_P384, der)
                .map_err(|_| CryptoError::SealPrivateKey)
        });
        Self::from_key(parsed?)
    }

    fn from_key(key: AgreementKey) -> Result<Self, CryptoError> {
        let spki = key.compute_public_key().and_then(|point| point.as_der());
        let spki: PublicKeyX509Der<'static> = spki.map_err(|_| CryptoError::Primitive)?;
        let public = PublicKey::from_spki_der(spki.as_ref())?;
        Ok(Self { key, public })
    }

    /// The key's PKCS#8 DER, in a zeroizing buffer.
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let der: Result<Pkcs8V1Der<'static>, _> = self.key.as_der();
        let der = der.map_err(|_| CryptoError::Primitive)?;
        Ok(Zeroizing::new(der.as_ref().to_vec()))
    }

    /// The matching public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub(super) fn agreement_key(&self) -> &AgreementKey {
        &self.key
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

fn encode_pem(spki: &[u8]) -> String {
    pem::encode_config(
        &pem::Pem::new(PEM_TAG, spki.to_vec()),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
}

fn check_length(text: &str) -> Result<(), CryptoError> {
    if text.len() != PEM_LEN {
        return Err(CryptoError::SealPublicKey);
    }
    Ok(())
}

fn check_tag(tag: &str) -> Result<(), CryptoError> {
    if tag != PEM_TAG {
        return Err(CryptoError::SealPublicKey);
    }
    Ok(())
}

fn check_canonical(text: &str, spki: &[u8]) -> Result<(), CryptoError> {
    if encode_pem(spki) != text {
        return Err(CryptoError::SealPublicKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::agreement::ECDH_P256;

    fn p256_pkcs8() -> Vec<u8> {
        let key = AgreementKey::generate(&ECDH_P256).unwrap();
        let der: Pkcs8V1Der<'static> = key.as_der().unwrap();
        der.as_ref().to_vec()
    }

    #[test]
    fn a_generated_key_has_a_120_byte_p384_spki_and_a_redacted_debug() {
        let key = PrivateKey::generate().unwrap();
        assert_eq!(key.public_key().spki_der().len(), SPKI_LEN);
        assert_eq!(format!("{key:?}"), "PrivateKey(<redacted>)");
        assert_eq!(format!("{:?}", key.public_key()), "PublicKey(P-384)");
    }

    #[test]
    fn two_generated_keys_differ() {
        let a = PrivateKey::generate().unwrap();
        let b = PrivateKey::generate().unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn pkcs8_round_trips_into_the_same_public_key_and_does_not_grow() {
        let key = PrivateKey::generate().unwrap();
        let der = key.to_pkcs8_der().unwrap();
        assert_eq!(der.len(), der.capacity());
        let back = PrivateKey::from_pkcs8_der(&der).unwrap();
        assert_eq!(back.public_key(), key.public_key());
    }

    #[test]
    fn a_p256_or_garbage_private_key_is_refused() {
        for der in [p256_pkcs8(), b"not a key".to_vec()] {
            assert!(matches!(
                PrivateKey::from_pkcs8_der(&der),
                Err(CryptoError::SealPrivateKey)
            ));
        }
    }

    #[test]
    fn the_public_pem_is_canonical_and_round_trips() {
        let key = PrivateKey::generate().unwrap();
        let text = key.public_key().to_pem();
        assert_eq!(text.len(), PEM_LEN);
        assert!(text.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(text.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(!text.contains('\r'));
        assert_eq!(&PublicKey::from_pem(&text).unwrap(), key.public_key());
        assert_eq!(
            &PublicKey::from_spki_der(key.public_key().spki_der()).unwrap(),
            key.public_key()
        );
    }

    const P256_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwb+kKvUQ/6NXarrQo1llFsZkKq3p\nuwMJSL1oX7GpbcalqGg9o0UfaXuMQoO4n+cJ7zqWEHgkmImfZBUhkoVpHQ==\n-----END PUBLIC KEY-----\n";

    #[test]
    fn a_non_canonical_foreign_or_malformed_public_key_is_refused() {
        let key = PrivateKey::generate().unwrap();
        let canonical = key.public_key().to_pem();
        let other = PrivateKey::generate().unwrap().public_key().to_pem();
        let spki = key.public_key().spki_der();
        let mut reflowed = canonical.replacen('\n', "", 2);
        reflowed.insert(26, '\n');
        reflowed.push('\n');
        assert_eq!(reflowed.len(), PEM_LEN);
        for bad in [
            canonical.replace('\n', "\r\n"),
            format!("{canonical}trailing"),
            format!("{canonical}{other}"),
            canonical.replace("PUBLIC KEY", "PRIVATE KEY"),
            canonical.replace("PUBLIC KEY", "PUBLIC KEZ"),
            P256_PUBLIC_PEM.to_string(),
            reflowed,
            encode_pem(&[0u8; SPKI_LEN]),
            "x".repeat(PEM_LEN),
            String::new(),
        ] {
            assert!(
                matches!(PublicKey::from_pem(&bad), Err(CryptoError::SealPublicKey)),
                "{bad:?}"
            );
        }
        for bad in [&spki[..SPKI_LEN - 1], &[0u8; SPKI_LEN][..]] {
            assert!(matches!(
                PublicKey::from_spki_der(bad),
                Err(CryptoError::SealPublicKey)
            ));
        }
    }

    const SPKI: [u8; SPKI_LEN] = [7u8; SPKI_LEN];

    #[test]
    fn the_encoding_is_215_bytes_of_lf_pem() {
        let text = encode_pem(&SPKI);
        assert_eq!(text.len(), PEM_LEN);
        assert!(text.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(text.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(!text.contains('\r'));
    }

    #[test]
    fn the_pem_length_must_be_exact() {
        assert!(check_length(&"x".repeat(PEM_LEN)).is_ok());
        for n in [0, PEM_LEN - 1, PEM_LEN + 1] {
            assert!(
                matches!(
                    check_length(&"x".repeat(n)),
                    Err(CryptoError::SealPublicKey)
                ),
                "{n}"
            );
        }
    }

    #[test]
    fn only_the_public_key_tag_is_accepted() {
        assert!(check_tag("PUBLIC KEY").is_ok());
        for tag in ["PUBLIC KEZ", "PRIVATE KEY", "EC PUBLIC KEY", ""] {
            assert!(
                matches!(check_tag(tag), Err(CryptoError::SealPublicKey)),
                "{tag:?}"
            );
        }
    }

    #[test]
    fn only_the_byte_exact_re_encoding_is_canonical() {
        let text = encode_pem(&SPKI);
        assert!(check_canonical(&text, &SPKI).is_ok());
        let mut other = SPKI;
        other[0] = 8;
        assert!(matches!(
            check_canonical(&text, &other),
            Err(CryptoError::SealPublicKey)
        ));
        assert!(matches!(
            check_canonical(&text.replace('\n', "\r\n"), &SPKI),
            Err(CryptoError::SealPublicKey)
        ));
    }
}
