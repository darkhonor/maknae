//! Pure CSR-shape predicates (T1, 0-missed): assert an empty subject, exactly one
//! URI SAN, and an EC P-384 key. `generate_plane_csr` (the rcgen keygen I/O) lives in
//! `csr_gen.rs` (T3) and self-checks its output with these predicates.
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

/// Uncompressed EC P-384 public-key point length: 0x04 || X(48) || Y(48) = 97 bytes.
const P384_UNCOMPRESSED_POINT_LEN: usize = 97;

fn parse_csr(pem: &str) -> Option<Vec<u8>> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).ok()?;
    Some(pem.contents)
}

/// True iff the CSR's subject Distinguished Name is empty (no RDNs — no CN).
pub fn csr_has_empty_subject(pem: &str) -> bool {
    let Some(der) = parse_csr(pem) else {
        return false;
    };
    let Ok((_, csr)) = X509CertificationRequest::from_der(&der) else {
        return false;
    };
    csr.certification_request_info.subject.iter().count() == 0
}

/// True iff the CSR carries EXACTLY one URI SAN equal to `want`.
pub fn csr_single_uri_san(pem: &str, want: &str) -> bool {
    let Some(der) = parse_csr(pem) else {
        return false;
    };
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
    let Some(der) = parse_csr(pem) else {
        return false;
    };
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

    /// Build a CSR with a configurable CN, URI SANs, and key algorithm.
    fn make_csr(
        cn: Option<&str>,
        uris: &[&str],
        alg: &'static rcgen::SignatureAlgorithm,
    ) -> String {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        if let Some(cn) = cn {
            dn.push(rcgen::DnType::CommonName, cn);
        }
        params.distinguished_name = dn;
        params.subject_alt_names = uris
            .iter()
            .map(|u| rcgen::SanType::URI((*u).try_into().unwrap()))
            .collect();
        let key = rcgen::KeyPair::generate_for(alg).unwrap();
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    #[test]
    fn empty_subject_true_and_false() {
        let empty = make_csr(
            None,
            &["maknae://d/plane/kernel"],
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        assert!(csr_has_empty_subject(&empty));
        let with_cn = make_csr(
            Some("someone"),
            &["maknae://d/plane/kernel"],
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        assert!(!csr_has_empty_subject(&with_cn));
    }

    #[test]
    fn single_uri_san_variants() {
        let one = make_csr(
            None,
            &["maknae://d/plane/kernel"],
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        assert!(csr_single_uri_san(&one, "maknae://d/plane/kernel"));
        assert!(!csr_single_uri_san(&one, "maknae://d/plane/cli")); // wrong value
        let none = make_csr(None, &[], &rcgen::PKCS_ECDSA_P384_SHA384);
        assert!(!csr_single_uri_san(&none, "maknae://d/plane/kernel")); // zero SANs
        let two = make_csr(
            None,
            &["maknae://d/plane/kernel", "maknae://d/plane/cli"],
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        assert!(!csr_single_uri_san(&two, "maknae://d/plane/kernel")); // two SANs
    }

    #[test]
    fn p384_true_and_false() {
        let p384 = make_csr(
            None,
            &["maknae://d/plane/kernel"],
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        assert!(csr_is_p384(&p384));
        let p256 = make_csr(
            None,
            &["maknae://d/plane/kernel"],
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        assert!(!csr_is_p384(&p256));
    }

    #[test]
    fn malformed_pem_all_false() {
        assert!(!csr_has_empty_subject("garbage"));
        assert!(!csr_single_uri_san("garbage", "x"));
        assert!(!csr_is_p384("garbage"));
    }
}
