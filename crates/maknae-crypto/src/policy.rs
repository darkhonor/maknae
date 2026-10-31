//! The `preferred` profile resolved once, and the process default built from it (#589).
use crate::{fips, tls, CryptoError, Options, Profile, Resolved, TlsError};
use crypto_profile_awslc4::rustls::crypto::CryptoProvider;
use std::sync::OnceLock;

/// The profile every Maknae TLS configuration uses, resolved against the linked module.
pub fn policy() -> Result<&'static Resolved, CryptoError> {
    static POLICY: OnceLock<Result<Resolved, CryptoError>> = OnceLock::new();
    POLICY
        .get_or_init(|| crypto_profile_awslc4::resolve(Profile::Preferred, Options::default()))
        .as_ref()
        .map_err(|e| *e)
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
