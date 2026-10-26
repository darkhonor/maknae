//! Its own test binary: the process-default provider is install-once, and this
//! file installs a FIPS provider with the wrong key-exchange groups.
use maknae_vault::{assert_fips_provider, crypto_provider, VaultError};
use rustls::crypto::aws_lc_rs::kx_group;
use rustls::crypto::CryptoProvider;

#[test]
fn a_fips_default_without_maknaes_groups_is_refused() {
    CryptoProvider {
        kx_groups: vec![kx_group::SECP256R1],
        ..crypto_provider()
    }
    .install_default()
    .unwrap();
    assert!(CryptoProvider::get_default().unwrap().fips());
    assert!(matches!(
        assert_fips_provider(),
        Err(VaultError::KxGroupsDrift)
    ));
}
