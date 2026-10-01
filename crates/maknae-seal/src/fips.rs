use crate::SealError;

pub(crate) fn fips_result(fips: bool) -> Result<(), SealError> {
    if fips {
        Ok(())
    } else {
        Err(SealError::FipsUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fips_result_has_both_branches() {
        assert_eq!(fips_result(true), Ok(()));
        assert_eq!(fips_result(false), Err(SealError::FipsUnavailable));
    }
}
