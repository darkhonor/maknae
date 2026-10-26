//! Local keypair + PKCS#10 CSR generation (rcgen, aws-lc-rs FIPS backend). The configured
//! `PlaneKey`, EMPTY subject, exactly one URI SAN. The private key is returned as
//! `Zeroizing<Vec<u8>>` (wiped on drop) and never leaves memory.
//!
//! ## Why this file is ADR-0016 **T3** (not T1), and why that is not a coverage dodge
//!
//! The security *decision* for a plane CSR — "empty subject, exactly one URI-SAN,
//! the configured key algorithm" — is NOT in this file. It lives in the pure predicates of `csr.rs`
//! (`csr_matches_plane_shape` + its parts), which are **T1**: mutation-covered and
//! ≥95% region, with negative tests that prove they REJECT a bad shape. This file
//! only *orchestrates I/O*: it calls `rcgen` (a non-deterministic keygen) and
//! propagates rcgen's failures via `.map_err`. Those `.map_err` arms cannot be
//! unit-covered without forcing rcgen to fail on valid input — that would test
//! rcgen's error handling, not our logic. That is the definition of a T3 boundary
//! (I/O + external-error plumbing), the same split as `maknae-crypto`'s `provider.rs`
//! (T1 decision) vs `glue.rs` (T3 provider fetch). No decision logic was demoted: the shape
//! decision is T1 and self-checked below, fail-closed.
use crate::csr::csr_matches_plane_shape;
use crate::{Plane, PlaneKey, VaultError};
use zeroize::Zeroizing;

/// Generate the plane's keypair + CSR. Returns `(key_der, csr_pem)`.
pub fn generate_plane_csr(
    plane: Plane,
    deployment_id: &str,
    plane_key: PlaneKey,
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
    let alg: &'static rcgen::SignatureAlgorithm = match plane_key {
        PlaneKey::MlDsa87 => &rcgen::PKCS_ML_DSA_87,
        PlaneKey::P384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        PlaneKey::P521 => &rcgen::PKCS_ECDSA_P521_SHA512,
    };
    let key = rcgen::KeyPair::generate_for(alg).map_err(|e| VaultError::CsrGen(e.to_string()))?;
    let csr_pem = params
        .serialize_request(&key)
        .map_err(|e| VaultError::CsrGen(e.to_string()))?
        .pem()
        .map_err(|e| VaultError::CsrGen(e.to_string()))?;
    // Fail-closed self-check via the T1 shape predicate (never hand Vault a CSR whose
    // shape we did not intend). The reject path is proven by csr.rs's negative tests.
    if !csr_matches_plane_shape(&csr_pem, &want, plane_key) {
        return Err(VaultError::CsrGen(
            "generated CSR failed its shape self-check (subject/SAN/key algorithm)".to_string(),
        ));
    }
    Ok((Zeroizing::new(key.serialize_der()), csr_pem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_crypto::rustls::pki_types::PrivateKeyDer;
    use maknae_crypto::rustls::SignatureScheme;

    const SCHEMES: [SignatureScheme; 3] = [
        SignatureScheme::ML_DSA_87,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP521_SHA512,
    ];

    fn scheme_of(k: PlaneKey) -> SignatureScheme {
        match k {
            PlaneKey::MlDsa87 => SignatureScheme::ML_DSA_87,
            PlaneKey::P384 => SignatureScheme::ECDSA_NISTP384_SHA384,
            PlaneKey::P521 => SignatureScheme::ECDSA_NISTP521_SHA512,
        }
    }

    #[test]
    fn each_plane_key_generates_its_own_shape_and_a_key_rustls_signs_with() {
        for k in PlaneKey::ALL {
            let (key_der, csr_pem) = generate_plane_csr(Plane::Kernel, "dev-01", k).unwrap();
            assert!(csr_matches_plane_shape(
                &csr_pem,
                "maknae://dev-01/plane/kernel",
                k
            ));
            let signing = maknae_crypto::crypto_provider()
                .key_provider
                .load_private_key(PrivateKeyDer::Pkcs8(key_der.to_vec().into()))
                .unwrap();
            for scheme in SCHEMES {
                let chosen = signing.choose_scheme(&[scheme]).map(|s| s.scheme());
                if scheme == scheme_of(k) {
                    assert_eq!(chosen, Some(scheme), "{k:?}");
                } else {
                    assert_eq!(chosen, None, "{k:?} offered {scheme:?}");
                }
            }
        }
    }
}
