#[derive(Debug)]
#[non_exhaustive]
pub enum CryptoError {
    /// The process is not running the aws-lc-rs FIPS provider (or none installed).
    FipsUnavailable,
    /// The process provider's key-exchange groups are not exactly [`crate::KX_GROUPS`].
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
    /// A sealed-box plaintext is empty.
    SealPlaintext,
    /// A sealed blob is shorter than a header, one byte and a tag.
    SealBlob,
    /// A sealed blob carries an unknown version.
    SealVersion,
    /// A sealed blob's ephemeral key is not a P-384 point.
    SealEphemeralKey,
    /// A sealing public key is not a canonical P-384 SubjectPublicKeyInfo.
    SealPublicKey,
    /// A sealing private key is not a P-384 PKCS#8 key.
    SealPrivateKey,
    /// A sealed blob does not open under this key, domain and AAD.
    SealOpen,
    /// A cryptographic primitive failed.
    Primitive,
    /// The aws-lc FIPS module is not active.
    FipsModuleUnavailable,
    /// A TLS configuration or private key was refused.
    Tls(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::FipsUnavailable => write!(
                f,
                "FIPS provider not active: the process default is not the aws-lc-rs FIPS provider"
            ),
            CryptoError::KxGroupsDrift => write!(
                f,
                "the process TLS provider does not carry the configured key-exchange groups"
            ),
            CryptoError::Csr(e) => write!(f, "keypair/CSR generation failed: {e}"),
            CryptoError::Random => write!(f, "the random generator failed"),
            CryptoError::AeadKey => write!(f, "the AEAD key was refused"),
            CryptoError::AeadSeal => write!(f, "AEAD sealing failed"),
            CryptoError::AeadOpen => write!(f, "the AEAD ciphertext does not authenticate"),
            CryptoError::SealPlaintext => write!(f, "the sealed plaintext is empty"),
            CryptoError::SealBlob => write!(f, "the sealed blob is too short"),
            CryptoError::SealVersion => write!(f, "the sealed blob has an unknown version"),
            CryptoError::SealEphemeralKey => write!(
                f,
                "the sealed blob's ephemeral key is not an uncompressed P-384 point"
            ),
            CryptoError::SealPublicKey => write!(
                f,
                "the sealing public key is not a canonical P-384 SubjectPublicKeyInfo PEM"
            ),
            CryptoError::SealPrivateKey => {
                write!(f, "the sealing private key is not a P-384 PKCS#8 key")
            }
            CryptoError::SealOpen => write!(
                f,
                "the sealed blob does not open under this key, domain and AAD"
            ),
            CryptoError::Primitive => write!(f, "a cryptographic primitive failed"),
            CryptoError::FipsModuleUnavailable => write!(f, "the aws-lc FIPS module is not active"),
            CryptoError::Tls(e) => write!(f, "TLS configuration failed: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {}
