//! The FIPS module check, independent of any TLS provider.
use crate::CryptoError;

pub fn assert_fips_module() -> Result<(), CryptoError> {
    fips_result(aws_lc_rs::try_fips_mode().is_ok())
}

pub(crate) fn fips_result(active: bool) -> Result<(), CryptoError> {
    if active {
        Ok(())
    } else {
        Err(CryptoError::FipsModuleUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_decision_and_this_build() {
        assert!(fips_result(true).is_ok());
        assert!(matches!(
            fips_result(false),
            Err(CryptoError::FipsModuleUnavailable)
        ));
        assert!(assert_fips_module().is_ok());
    }
}
