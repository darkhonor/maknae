//! Local keypair + PKCS#10 CSR generation (rcgen, aws-lc-rs FIPS backend). EC P-384,
//! EMPTY subject, exactly one URI SAN. The private key is returned as
//! `Zeroizing<Vec<u8>>` (wiped on drop) and never leaves memory. This is I/O (keygen
//! is non-deterministic) → T3, mutation-excluded; the pure shape checks it performs
//! live in `csr.rs` (T1).
use crate::csr::{csr_has_empty_subject, csr_is_p384, csr_single_uri_san};
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
    let san = plane
        .uri_san(deployment_id)
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
    // Fail-closed self-check: never hand Vault a CSR whose shape we did not intend.
    let want = plane.uri_san(deployment_id);
    if !(csr_has_empty_subject(&csr_pem)
        && csr_single_uri_san(&csr_pem, &want)
        && csr_is_p384(&csr_pem))
    {
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
        assert!(csr_has_empty_subject(&csr_pem));
        assert!(csr_single_uri_san(&csr_pem, "maknae://dev-01/plane/kernel"));
        assert!(csr_is_p384(&csr_pem));
        assert!(!key_der.is_empty());
    }

    #[test]
    fn key_der_is_a_real_p384_key() {
        let (key_der, _csr) = generate_plane_csr(Plane::Cli, "dev-01").unwrap();
        let kp = rcgen::KeyPair::try_from(key_der.as_slice()).expect("valid key DER");
        assert!(kp.is_compatible(&rcgen::PKCS_ECDSA_P384_SHA384));
    }
}
