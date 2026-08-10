//! Local keypair + PKCS#10 CSR generation (rcgen, aws-lc-rs FIPS backend). EC P-384,
//! EMPTY subject, exactly one URI SAN. The private key is returned as
//! `Zeroizing<Vec<u8>>` (wiped on drop) and never leaves memory.
//!
//! ## Why this file is ADR-0016 **T3** (not T1), and why that is not a coverage dodge
//!
//! The security *decision* for a plane CSR — "empty subject, exactly one URI-SAN,
//! EC P-384" — is NOT in this file. It lives in the pure predicates of `csr.rs`
//! (`csr_matches_plane_shape` + its parts), which are **T1**: mutation-covered and
//! ≥95% region, with negative tests that prove they REJECT a bad shape. This file
//! only *orchestrates I/O*: it calls `rcgen` (a non-deterministic keygen) and
//! propagates rcgen's failures via `.map_err`. Those `.map_err` arms cannot be
//! unit-covered without forcing rcgen to fail on valid input — that would test
//! rcgen's error handling, not our logic. That is the definition of a T3 boundary
//! (I/O + external-error plumbing), the same split as `fips.rs` (T1 decision) vs
//! `fips_glue.rs` (T3 provider fetch). No decision logic was demoted: the shape
//! decision is T1 and self-checked below, fail-closed.
use crate::csr::csr_matches_plane_shape;
use crate::{Plane, VaultError};
use zeroize::Zeroizing;

/// Generate the plane's keypair + CSR. Returns `(key_der, csr_pem)`.
pub fn generate_plane_csr(
    plane: Plane,
    deployment_id: &str,
) -> Result<(Zeroizing<Vec<u8>>, String), VaultError> {
    let mut params =
        rcgen::CertificateParams::new(vec![]).map_err(|e| VaultError::CsrGen(e.to_string()))?;
    params.distinguished_name = rcgen::DistinguishedName::new(); // empty subject — no CN
    let want = plane.uri_san(deployment_id);
    let san = want
        .as_str()
        .try_into()
        .map_err(|e: rcgen::Error| VaultError::CsrGen(e.to_string()))?;
    params.subject_alt_names = vec![rcgen::SanType::URI(san)];
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
        .map_err(|e| VaultError::CsrGen(e.to_string()))?;
    let csr_pem = params
        .serialize_request(&key)
        .map_err(|e| VaultError::CsrGen(e.to_string()))?
        .pem()
        .map_err(|e| VaultError::CsrGen(e.to_string()))?;
    // Fail-closed self-check via the T1 shape predicate (never hand Vault a CSR whose
    // shape we did not intend). The reject path is proven by csr.rs's negative tests.
    if !csr_matches_plane_shape(&csr_pem, &want) {
        return Err(VaultError::CsrGen(
            "generated CSR failed its shape self-check (subject/SAN/curve)".to_string(),
        ));
    }
    Ok((Zeroizing::new(key.serialize_der()), csr_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_shape() {
        let (key_der, csr_pem) = generate_plane_csr(Plane::Kernel, "dev-01").unwrap();
        assert!(csr_matches_plane_shape(
            &csr_pem,
            "maknae://dev-01/plane/kernel"
        ));
        assert!(!key_der.is_empty());
    }

    #[test]
    fn key_der_is_a_real_p384_key() {
        let (key_der, _csr) = generate_plane_csr(Plane::Cli, "dev-01").unwrap();
        let kp = rcgen::KeyPair::try_from(key_der.as_slice()).expect("valid key DER");
        assert!(kp.is_compatible(&rcgen::PKCS_ECDSA_P384_SHA384));
    }
}
