//! The FIPS provider and the pure decisions over it. `.fips()` proves a FIPS
//! build of the AWS-LC module, never a CMVP certificate (ADR-0025).
use crate::CryptoError;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::NamedGroup;

/// Every TLS configuration's key-exchange groups, in preference order (#564, epic #569).
pub const KX_GROUPS: [&dyn SupportedKxGroup; 5] = [
    kx_group::MLKEM1024,
    kx_group::X25519MLKEM768,
    kx_group::SECP256R1MLKEM768,
    kx_group::SECP384R1,
    kx_group::SECP256R1,
];

/// The aws-lc-rs FIPS provider carrying [`KX_GROUPS`].
#[expect(clippy::disallowed_methods)]
pub fn crypto_provider() -> CryptoProvider {
    CryptoProvider {
        kx_groups: KX_GROUPS.to_vec(),
        ..aws_lc_rs::default_provider()
    }
}

/// PURE decision — both branches are unit-killable (this is the T1 / 0-missed surface).
pub(crate) fn fips_result(is_fips: bool) -> Result<(), CryptoError> {
    if is_fips {
        Ok(())
    } else {
        Err(CryptoError::FipsUnavailable)
    }
}

/// PURE decision: the process provider's groups are exactly [`KX_GROUPS`], in order.
pub(crate) fn kx_groups_result(names: &[NamedGroup]) -> Result<(), CryptoError> {
    if names.iter().copied().eq(KX_GROUPS.iter().map(|g| g.name())) {
        Ok(())
    } else {
        Err(CryptoError::KxGroupsDrift)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(groups: &[&dyn SupportedKxGroup]) -> Vec<NamedGroup> {
        groups.iter().map(|g| g.name()).collect()
    }

    #[test]
    fn the_provider_carries_ml_kem_1024_first_then_the_hybrids_then_classical() {
        assert_eq!(
            names(&crypto_provider().kx_groups),
            [
                NamedGroup::MLKEM1024,
                NamedGroup::X25519MLKEM768,
                NamedGroup::secp256r1MLKEM768,
                NamedGroup::secp384r1,
                NamedGroup::secp256r1,
            ]
        );
    }

    #[test]
    fn every_group_is_approved_on_this_build() {
        assert!(crypto_provider().kx_groups.iter().all(|g| g.fips()));
        assert!(crypto_provider().fips());
    }

    #[test]
    fn kx_groups_result_takes_only_the_exact_list() {
        let exact = names(&KX_GROUPS);
        assert!(kx_groups_result(&exact).is_ok());
        let mut reordered = exact.clone();
        reordered.swap(0, 1);
        let missing = &exact[1..];
        let mut extra = exact.clone();
        extra.push(NamedGroup::X25519);
        for drift in [&reordered[..], missing, &extra[..], &[][..]] {
            assert!(matches!(
                kx_groups_result(drift),
                Err(CryptoError::KxGroupsDrift)
            ));
        }
    }

    #[test]
    fn fips_result_both_branches() {
        assert!(fips_result(true).is_ok());
        // `is_err()` (not `matches!`) — FipsUnavailable is the only Err variant, and
        // a `matches!` leaves an uncovered `_ => false` arm.
        assert!(fips_result(false).is_err());
    }
}
