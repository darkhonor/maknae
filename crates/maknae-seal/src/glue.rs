use crate::fips::fips_result;
use crate::SealError;

pub(crate) fn fips_gate() -> Result<(), SealError> {
    fips_result(aws_lc_rs::try_fips_mode().is_ok())
}

pub(crate) fn lc<T, E>(r: Result<T, E>, err: SealError) -> Result<T, SealError> {
    r.map_err(|_| err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_build_runs_the_fips_module() {
        assert_eq!(fips_gate(), Ok(()));
    }

    #[test]
    fn lc_maps_only_the_error() {
        assert_eq!(lc::<u8, ()>(Ok(7), SealError::Crypto), Ok(7));
        assert_eq!(lc::<u8, ()>(Err(()), SealError::Open), Err(SealError::Open));
    }
}
