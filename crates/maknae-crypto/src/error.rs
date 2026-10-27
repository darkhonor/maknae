#[derive(Debug)]
pub enum CryptoError {
    /// The process is not running the aws-lc-rs FIPS provider (or none installed).
    FipsUnavailable,
    /// The process provider's key-exchange groups are not exactly Maknae's list (#564).
    KxGroupsDrift,
    /// Key or certificate-request generation failed.
    Csr(String),
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
            CryptoError::Csr(e) => write!(f, "key or CSR generation failed: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {}
