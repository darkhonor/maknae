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
