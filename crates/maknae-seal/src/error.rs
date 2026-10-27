use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    FipsUnavailable,
    PlaintextLength,
    AadField,
    BlobLength,
    Version,
    EphemeralKey,
    PublicKey,
    PrivateKey,
    Open,
    Crypto,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SealError::FipsUnavailable => "the aws-lc FIPS module is not active",
            SealError::PlaintextLength => "the sealed value must be 1..=1024 bytes",
            SealError::AadField => "a sealed-request field is empty or over 1024 bytes",
            SealError::BlobLength => "the sealed blob's length is out of bounds",
            SealError::Version => "the sealed blob has an unknown version",
            SealError::EphemeralKey => {
                "the sealed blob's ephemeral key is not an uncompressed P-384 point"
            }
            SealError::PublicKey => {
                "the sealing public key is not a canonical P-384 SubjectPublicKeyInfo PEM"
            }
            SealError::PrivateKey => "the sealing private key is not a P-384 PKCS#8 key",
            SealError::Open => "the seal does not match this request",
            SealError::Crypto => "a cryptographic primitive failed",
        })
    }
}

impl std::error::Error for SealError {}

impl From<maknae_crypto::CryptoError> for SealError {
    fn from(e: maknae_crypto::CryptoError) -> Self {
        use maknae_crypto::CryptoError as C;
        match e {
            C::FipsModuleUnavailable | C::FipsUnavailable => SealError::FipsUnavailable,
            C::SealPlaintext => SealError::PlaintextLength,
            C::SealBlob => SealError::BlobLength,
            C::SealVersion => SealError::Version,
            C::SealEphemeralKey => SealError::EphemeralKey,
            C::SealPublicKey => SealError::PublicKey,
            C::SealPrivateKey => SealError::PrivateKey,
            C::SealOpen => SealError::Open,
            C::Primitive
            | C::Random
            | C::AeadKey
            | C::AeadSeal
            | C::AeadOpen
            | C::KxGroupsDrift
            | C::Csr(_)
            | C::Tls(_) => SealError::Crypto,
            _ => SealError::Crypto,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_crypto::CryptoError as C;

    #[test]
    fn each_crypto_refusal_maps_to_its_seal_error_and_message() {
        let crypto = "a cryptographic primitive failed";
        let table: [(C, SealError, &str); 17] = [
            (
                C::FipsModuleUnavailable,
                SealError::FipsUnavailable,
                "the aws-lc FIPS module is not active",
            ),
            (
                C::FipsUnavailable,
                SealError::FipsUnavailable,
                "the aws-lc FIPS module is not active",
            ),
            (
                C::SealPlaintext,
                SealError::PlaintextLength,
                "the sealed value must be 1..=1024 bytes",
            ),
            (
                C::SealBlob,
                SealError::BlobLength,
                "the sealed blob's length is out of bounds",
            ),
            (
                C::SealVersion,
                SealError::Version,
                "the sealed blob has an unknown version",
            ),
            (
                C::SealEphemeralKey,
                SealError::EphemeralKey,
                "the sealed blob's ephemeral key is not an uncompressed P-384 point",
            ),
            (
                C::SealPublicKey,
                SealError::PublicKey,
                "the sealing public key is not a canonical P-384 SubjectPublicKeyInfo PEM",
            ),
            (
                C::SealPrivateKey,
                SealError::PrivateKey,
                "the sealing private key is not a P-384 PKCS#8 key",
            ),
            (
                C::SealOpen,
                SealError::Open,
                "the seal does not match this request",
            ),
            (C::Primitive, SealError::Crypto, crypto),
            (C::Random, SealError::Crypto, crypto),
            (C::AeadKey, SealError::Crypto, crypto),
            (C::AeadSeal, SealError::Crypto, crypto),
            (C::AeadOpen, SealError::Crypto, crypto),
            (C::KxGroupsDrift, SealError::Crypto, crypto),
            (C::Csr("refused".into()), SealError::Crypto, crypto),
            (C::Tls("refused".into()), SealError::Crypto, crypto),
        ];
        for (from, want, text) in table {
            let got = SealError::from(from);
            assert_eq!(got, want);
            assert_eq!(got.to_string(), text);
        }
        assert_eq!(
            SealError::AadField.to_string(),
            "a sealed-request field is empty or over 1024 bytes"
        );
    }
}
