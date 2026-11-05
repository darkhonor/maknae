//! The `preferred` profile resolved once, and the process default built from it (#589).
use crate::{
    digest, fips, tls, Admitted, CryptoError, HashAlgorithm, Options, Profile, Resolved, TlsError,
};
use crypto_profile_awslc4::rustls::crypto::CryptoProvider;
use std::sync::OnceLock;

const SHA256_ADMITTED: &str =
    "preferred admits SHA-256 (preferred_admits_every_family_maknae_uses)";

/// The profile every Maknae TLS configuration uses, resolved against the linked module.
pub fn policy() -> Result<&'static Resolved, CryptoError> {
    static POLICY: OnceLock<Result<Resolved, CryptoError>> = OnceLock::new();
    POLICY
        .get_or_init(|| crypto_profile_awslc4::resolve(Profile::Preferred, Options::default()))
        .as_ref()
        .map_err(|e| *e)
}

/// The `preferred` profile's families outside TLS, admitted once.
pub fn admitted() -> &'static Admitted {
    static ADMITTED: OnceLock<Admitted> = OnceLock::new();
    ADMITTED.get_or_init(|| crypto_profile_awslc4::admit(Profile::Preferred, Options::default()))
}

/// SHA-256 of `data` under [`admitted`].
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(admitted(), HashAlgorithm::Sha256, data).expect(SHA256_ADMITTED);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// A streaming SHA-256 under [`admitted`].
pub fn sha256_hasher() -> digest::Hasher {
    digest::Hasher::new(admitted(), HashAlgorithm::Sha256).expect(SHA256_ADMITTED)
}

/// Asserts FIPS mode, installs [`policy`]'s provider as the process default if none is
/// installed, then refuses unless the installed default matches it. Safe to call again.
pub fn init() -> Result<(), CryptoError> {
    let p = &policy()?.tls;
    fips::assert_fips_module()?;
    match tls::install_default(p) {
        Ok(()) | Err(CryptoError::Tls(TlsError::DefaultProviderInstalled)) => {}
        Err(e) => return Err(e),
    }
    assert_fips_provider()
}

/// Refuses unless the module is in FIPS mode and the process default is a FIPS provider
/// carrying exactly [`policy`]'s lists; `PolicyDrift` when none is installed.
pub fn assert_fips_provider() -> Result<(), CryptoError> {
    fips::assert_fips_module()?;
    let installed = CryptoProvider::get_default().ok_or(CryptoError::PolicyDrift)?;
    if !installed.fips() {
        return Err(CryptoError::NotFips);
    }
    tls::assert_provider_matches(installed, &policy()?.tls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AeadAlgorithm, Algorithm, KdfAlgorithm, KeyAgreementAlgorithm};

    fn maknae_families(a: &Admitted) -> Result<(), CryptoError> {
        a.admit_hash(HashAlgorithm::Sha256)?;
        a.admit_aead(AeadAlgorithm::Aes256Gcm)?;
        a.admit_key_agreement(KeyAgreementAlgorithm::EcdhP384)?;
        a.admit_kdf(KdfAlgorithm::HkdfSha384)
    }

    #[test]
    fn preferred_admits_every_family_maknae_uses() {
        assert_eq!(maknae_families(admitted()), Ok(()));
        assert_eq!(
            maknae_families(&crypto_profile_awslc4::admit(
                Profile::Cnsa2,
                Options::default()
            )),
            Err(CryptoError::NotInProfile {
                profile: Profile::Cnsa2,
                algorithm: Algorithm::Hash(HashAlgorithm::Sha256),
            })
        );
        assert_eq!(
            maknae_families(&crypto_profile_awslc4::admit(
                Profile::Bsi,
                Options::default()
            )),
            Err(CryptoError::NotInProfile {
                profile: Profile::Bsi,
                algorithm: Algorithm::KeyAgreement(KeyAgreementAlgorithm::EcdhP384),
            })
        );
    }

    #[test]
    fn sha256_is_fips_180_4() {
        let hex: String = sha256(b"abc").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_hasher_matches_sha256() {
        let mut h = sha256_hasher();
        h.update(b"ab");
        h.update(b"c");
        assert_eq!(h.finish(), sha256(b"abc"));
    }

    #[test]
    fn preferred_resolves_on_this_module() {
        let r = policy().unwrap();
        assert_eq!(r.profile, Profile::Preferred);
        assert_eq!(r.options, Options::default());
        assert!(r.excluded.is_empty(), "{:?}", r.excluded);
    }

    #[test]
    fn init_twice_is_ok() {
        init().unwrap();
        init().unwrap();
    }

    #[test]
    fn after_init_the_installed_default_matches_the_policy() {
        init().unwrap();
        assert_eq!(assert_fips_provider(), Ok(()));
    }
}
