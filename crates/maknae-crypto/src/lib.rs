//! Maknae's single door to its cryptography (ADR-0030, ADR-0031): the `crypto-profile-awslc4`
//! API, the `preferred` profile resolved once, and the plane signature keys. `rustls` is
//! re-exported because its types are API; `rcgen` only under `test-support`.
#![deny(missing_docs)]

pub use crypto_profile_awslc4::rustls;
pub use crypto_profile_awslc4::{aead, csr, digest, fips, random, sealbox, signature, tls};
#[cfg(feature = "test-support")]
pub use crypto_profile_awslc4::{rcgen, test_support};
pub use crypto_profile_awslc4::{
    Admitted, AeadAlgorithm, Algorithm, CipherSuite, CryptoError, CsrError, HashAlgorithm,
    KdfAlgorithm, KeyAgreementAlgorithm, KxGroup, Options, Profile, Resolved, SignatureAlgorithm,
    TlsError, TlsSignatureScheme, TlsVersion,
};

pub mod plane_key;
mod policy;

pub use policy::{admitted, assert_fips_provider, init, policy, sha256, sha256_hasher};
