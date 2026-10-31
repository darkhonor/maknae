//! Maknae's single door to its cryptography (ADR-0030, ADR-0031): the `crypto-profile-awslc4`
//! API, the `preferred` profile resolved once, and the plane signature keys. `rustls` is
//! re-exported because its types are API; `rcgen` only under `test-support`.
#![deny(missing_docs)]

#[cfg(feature = "test-support")]
pub use crypto_profile_awslc4::rcgen;
pub use crypto_profile_awslc4::rustls;
pub use crypto_profile_awslc4::{aead, csr, digest, fips, random, sealbox, signature, tls};
pub use crypto_profile_awslc4::{
    CipherSuite, CryptoError, CsrError, HashAlgorithm, KxGroup, Options, Profile, Resolved,
    SignatureAlgorithm, TlsError, TlsSignatureScheme, TlsVersion,
};

pub mod plane_key;
mod policy;

pub use policy::{assert_fips_provider, init, policy};
