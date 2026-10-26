//! Maknae's cryptographic libraries and the policy over them (ADR-0030). The only
//! workspace crate that declares `aws-lc-rs` or `rustls`; every other crate uses
//! the re-exports below.
pub use aws_lc_rs;
pub use rustls;

mod error;
mod glue;
mod provider;

pub use error::CryptoError;
pub use glue::{assert_fips_provider, install_default_crypto_provider};
pub use provider::{crypto_provider, KX_GROUPS};
