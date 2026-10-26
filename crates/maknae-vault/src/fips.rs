//! FIPS gate — PURE decisions, and the provider they decide about.
//! The AUTHORITATIVE FIPS proof is the runtime `.fips()`
//! value asserted here: aws-lc-rs reports fips only when built against the AWS-LC-FIPS
//! module with its power-on self-tests passing.
//!
//! *Corrected 2026-09-19 (#320): this said "the CMVP-validated module". What `.fips()`
//! proves is the FIPS BUILD, never a certificate — the value is identical on a
//! validated module and on one under review, and Maknae now builds on the 4.x line,
//! which is submitted and in process. The decision of record is
//! `design/adr/ADR-0025-fips-validation-is-a-goal-not-a-constraint.md`; this
//! crate's Cargo.toml mirrors it with the dependency facts.*
//!
//! The non-FIPS `aws-lc-sys` (pulled by `rcgen[aws_lc_rs]`)
//! and `ring` (reqwest's bundled fallback) are both present-but-dead and unbannable;
//! this runtime assertion — not dependency-tree hygiene — is the gate.
//!
//! *Corrected 2026-09-19 (#320) — the two crates named just above have both moved,
//! and the sentence was rewritten around them, so it is measured here rather than
//! inherited: `aws-lc-sys` is pulled by **`aws-lc-rs` itself** (`cargo tree -i
//! aws-lc-sys --target all` roots at aws-lc-rs, with rcgen one consumer among
//! four), not by `rcgen[aws_lc_rs]` as this said. And **`ring` is no longer in any
//! build graph on any target** — `cargo tree -i ring --target all` prints nothing;
//! it left when reqwest moved 0.12→0.13 under `rustls-no-provider`, and this
//! commit's regenerated `THIRD-PARTY-NOTICES.md` drops it. So "present-but-dead
//! and unbannable" no longer describes ring: it is simply absent, and whether to
//! ban it outright is the maintainer's call, not this comment's. What is unchanged
//! is the conclusion — the runtime assertion, not the dependency tree, is the gate.*
use crate::VaultError;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::NamedGroup;

/// Every TLS configuration's key-exchange groups, in preference order (#564, epic #569).
pub(crate) const KX_GROUPS: [&dyn SupportedKxGroup; 5] = [
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
pub(crate) fn fips_result(is_fips: bool) -> Result<(), VaultError> {
    if is_fips {
        Ok(())
    } else {
        Err(VaultError::FipsUnavailable)
    }
}

/// PURE decision: the process provider's groups are exactly [`KX_GROUPS`], in order.
pub(crate) fn kx_groups_result(names: &[NamedGroup]) -> Result<(), VaultError> {
    if names.iter().copied().eq(KX_GROUPS.iter().map(|g| g.name())) {
        Ok(())
    } else {
        Err(VaultError::KxGroupsDrift)
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
                Err(VaultError::KxGroupsDrift)
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
