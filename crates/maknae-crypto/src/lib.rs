//! The single implementation of each cryptographic function (ADR-0030).
//! `rustls` is re-exported because its types are API; the listed rustls entry
//! points are refused by `clippy.toml` (residual: #581). `rcgen` is re-exported
//! only under `test-support`.
#![deny(missing_docs)]

#[cfg(feature = "test-support")]
pub use rcgen;
pub use rustls;

pub mod aead;
mod csr;
pub mod digest;
mod error;
pub mod fips;
mod glue;
mod provider;
pub mod random;
pub mod sealbox;
pub mod signature;
pub mod tls;

pub use csr::generate_csr;
pub use error::CryptoError;
pub use glue::{assert_fips_provider, install_default_crypto_provider};
pub use provider::{crypto_provider, KX_GROUPS};
