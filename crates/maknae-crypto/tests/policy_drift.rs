//! A process default that is FIPS but not the policy is refused (#589).
use maknae_crypto::{assert_fips_provider, init, policy, tls, CryptoError, KxGroup};

#[test]
fn a_default_with_other_groups_is_drift() {
    let mut sentinel = policy().unwrap().tls.clone();
    sentinel.kx_groups = vec![KxGroup::Secp256r1];
    tls::install_default(&sentinel).unwrap();
    assert_eq!(assert_fips_provider(), Err(CryptoError::PolicyDrift));
    assert_eq!(init(), Err(CryptoError::PolicyDrift));
}
