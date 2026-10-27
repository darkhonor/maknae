//! The FIPS module decision; the probe that feeds it is `glue::assert_fips_module`.
pub use crate::glue::assert_fips_module;
use crate::CryptoError;

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
    fn the_decision_has_both_branches() {
        assert!(fips_result(true).is_ok());
        assert!(matches!(
            fips_result(false),
            Err(CryptoError::FipsModuleUnavailable)
        ));
    }
}
