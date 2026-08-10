//! Local keypair + PKCS#10 CSR generation: EC P-384, EMPTY subject, exactly one
//! URI SAN (`maknae://<deployment_id>/plane/<plane>`), no CN. The Vault roles set
//! `require_cn=false`/`use_csr_common_name=false`, so a CN would be dropped and a
//! DNS/other SAN rejected — this builds the URI-SAN-only shape the roles honor.
//!
//! Keygen via `rcgen` on the aws-lc-rs FIPS backend. The private key is returned as
//! `Zeroizing<Vec<u8>>` (wiped on drop). The shape predicates are pure T1 logic.
use crate::{Plane, VaultError};
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;
use zeroize::Zeroizing;

/// Uncompressed EC P-384 public-key point length: 0x04 || X(48) || Y(48) = 97 bytes.
const P384_UNCOMPRESSED_POINT_LEN: usize = 97;

/// Generate the plane's keypair + CSR. Returns `(key_der, csr_pem)`; the key DER is
/// zeroized on drop and never leaves memory.
pub fn generate_plane_csr(
    plane: Plane,
    deployment_id: &str,
) -> Result<(Zeroizing<Vec<u8>>, String), VaultError> {
    let mut params = rcgen::CertificateParams::new(vec![])
        .map_err(|e| VaultError::CsrGen(e.to_string()))?;
    // Empty subject — no CN.
    params.distinguished_name = rcgen::DistinguishedName::new();
    // Exactly one URI SAN.
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
    let key_der = Zeroizing::new(key.serialize_der());
    Ok((key_der, csr_pem))
}

// ---- pure shape predicates (T1) --------------------------------------------

fn parse_csr(pem: &str) -> Option<Vec<u8>> {
    // Strip the PEM armor to DER.
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).ok()?;
    Some(pem.contents)
}

/// True iff the CSR's subject Distinguished Name is empty (no RDNs — no CN).
pub fn csr_has_empty_subject(pem: &str) -> bool {
    let Some(der) = parse_csr(pem) else { return false };
    let Ok((_, csr)) = X509CertificationRequest::from_der(&der) else {
        return false;
    };
    csr.certification_request_info.subject.iter().count() == 0
}

/// True iff the CSR carries EXACTLY one URI SAN equal to `want`.
pub fn csr_single_uri_san(pem: &str, want: &str) -> bool {
    let Some(der) = parse_csr(pem) else { return false };
    let Ok((_, csr)) = X509CertificationRequest::from_der(&der) else {
        return false;
    };
    let mut uris: Vec<String> = Vec::new();
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for gn in &san.general_names {
                    if let GeneralName::URI(u) = gn {
                        uris.push(u.to_string());
                    }
                }
            }
        }
    }
    uris.len() == 1 && uris[0] == want
}

/// True iff the CSR's public key is EC on the P-384 curve (by the uncompressed
/// point length, which is unambiguous for P-384).
pub fn csr_is_p384(pem: &str) -> bool {
    let Some(der) = parse_csr(pem) else { return false };
    let Ok((_, csr)) = X509CertificationRequest::from_der(&der) else {
        return false;
    };
    csr.certification_request_info
        .subject_pki
        .subject_public_key
        .data
        .len()
        == P384_UNCOMPRESSED_POINT_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_empty_subject_single_uri_p384() {
        let (key_der, csr_pem) = generate_plane_csr(Plane::Kernel, "dev-01").unwrap();
        assert!(csr_has_empty_subject(&csr_pem));
        assert!(csr_single_uri_san(&csr_pem, "maknae://dev-01/plane/kernel"));
        assert!(!csr_single_uri_san(&csr_pem, "maknae://dev-01/plane/cli"));
        assert!(csr_is_p384(&csr_pem));
        assert!(!key_der.is_empty());
    }

    #[test]
    fn key_der_is_a_real_p384_key() {
        let (key_der, _csr) = generate_plane_csr(Plane::Cli, "dev-01").unwrap();
        // The DER must round-trip back into an rcgen KeyPair as P-384 — kills a mutant
        // that returns an empty/garbage key while leaving the CSR shape intact.
        let kp = rcgen::KeyPair::try_from(key_der.as_slice()).expect("valid key DER");
        assert!(kp.is_compatible(&rcgen::PKCS_ECDSA_P384_SHA384));
    }
}
