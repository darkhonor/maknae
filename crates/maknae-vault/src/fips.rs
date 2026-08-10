//! FIPS gate — PURE decision. The AUTHORITATIVE FIPS proof is the runtime `.fips()`
//! value asserted here: aws-lc-rs reports fips only when built + self-tested on the
//! CMVP-validated module. The non-FIPS `aws-lc-sys` (pulled by `rcgen[aws_lc_rs]`)
//! and `ring` (reqwest's bundled fallback) are both present-but-dead and unbannable;
//! this runtime assertion — not dependency-tree hygiene — is the gate.
use crate::VaultError;

/// PURE decision — both branches are unit-killable (this is the T1 / 0-missed surface).
pub(crate) fn fips_result(is_fips: bool) -> Result<(), VaultError> {
    if is_fips {
        Ok(())
    } else {
        Err(VaultError::FipsUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_result_both_branches() {
        assert!(fips_result(true).is_ok());
        // `is_err()` (not `matches!`) — FipsUnavailable is the only Err variant, and
        // a `matches!` leaves an uncovered `_ => false` arm.
        assert!(fips_result(false).is_err());
    }
}
