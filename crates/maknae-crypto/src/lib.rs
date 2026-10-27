//! Maknae's cryptographic libraries and its single implementation of each
//! cryptographic function (ADR-0030). The only workspace crate that declares
//! `aws-lc-rs`, `rustls` or `rcgen`; every other crate uses the re-exports below.
pub use aws_lc_rs;
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

pub use csr::generate_csr;
pub use error::CryptoError;
pub use glue::{assert_fips_provider, install_default_crypto_provider};
pub use provider::{crypto_provider, KX_GROUPS};
