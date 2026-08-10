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
        assert!(matches!(fips_result(false), Err(VaultError::FipsUnavailable)));
    }
}
