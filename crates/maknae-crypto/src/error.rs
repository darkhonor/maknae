#[derive(Debug)]
#[non_exhaustive]
pub enum CryptoError {
    /// The process is not running the aws-lc-rs FIPS provider (or none installed).
    FipsUnavailable,
    /// The process provider's key-exchange groups are not exactly Maknae's list (#564).
    KxGroupsDrift,
    /// Key or certificate-request generation failed.
    Csr(String),
    /// The FIPS module's random generator failed.
    Random,
    /// The AEAD key was refused.
    AeadKey,
    /// AEAD sealing failed.
    AeadSeal,
    /// The AEAD ciphertext did not authenticate.
    AeadOpen,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::FipsUnavailable => write!(
                f,
                "FIPS provider not active: the process default is not aws-lc-rs FIPS (refusing to start)"
            ),
            CryptoError::KxGroupsDrift => write!(
                f,
                "the process TLS provider does not carry Maknae's key-exchange groups (refusing TLS)"
            ),
            CryptoError::Csr(e) => write!(f, "keypair/CSR generation failed: {e}"),
            CryptoError::Random => write!(f, "the random generator failed"),
            CryptoError::AeadKey => write!(f, "the AEAD key was refused"),
            CryptoError::AeadSeal => write!(f, "AEAD sealing failed"),
            CryptoError::AeadOpen => write!(f, "the AEAD ciphertext does not authenticate"),
        }
    }
}

impl std::error::Error for CryptoError {}
