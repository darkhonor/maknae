//! Random bytes from the FIPS module's DRBG.
use crate::CryptoError;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

/// Fills `out` from the FIPS module's DRBG.
pub fn fill(out: &mut [u8]) -> Result<(), CryptoError> {
    SystemRandom::new()
        .fill(out)
        .map_err(|_| CryptoError::Random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fill_is_not_all_zero_and_two_fills_differ() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }
}
