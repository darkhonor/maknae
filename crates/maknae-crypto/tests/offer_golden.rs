//! The process default's offer, golden-pinned so a change to it is a named change (#589).
use maknae_crypto::rustls::crypto::CryptoProvider;
use maknae_crypto::rustls::{CipherSuite as C, NamedGroup as G, SignatureScheme as S};
use maknae_crypto::KxGroup;

#[test]
fn the_installed_default_offers_exactly_this() {
    maknae_crypto::init().unwrap();
    let p = CryptoProvider::get_default().unwrap();
    let groups: Vec<G> = p.kx_groups.iter().map(|g| g.name()).collect();
    let suites: Vec<C> = p.cipher_suites.iter().map(|s| s.suite()).collect();
    let schemes: Vec<S> = p
        .signature_verification_algorithms
        .mapping
        .iter()
        .map(|(s, _)| *s)
        .collect();
    assert_eq!(
        groups,
        [
            G::MLKEM1024,
            G::from(KxGroup::Secp384r1MlKem1024.iana()),
            G::X25519MLKEM768,
            G::secp256r1MLKEM768,
            G::secp384r1,
            G::secp256r1,
        ]
    );
    assert_eq!(
        suites,
        [C::TLS13_AES_256_GCM_SHA384, C::TLS13_AES_128_GCM_SHA256]
    );
    assert_eq!(
        schemes,
        [
            S::ML_DSA_87,
            S::ECDSA_NISTP384_SHA384,
            S::ECDSA_NISTP256_SHA256,
            S::ECDSA_NISTP521_SHA512,
            S::RSA_PSS_SHA384,
            S::RSA_PSS_SHA512,
            S::RSA_PSS_SHA256,
        ]
    );
}
