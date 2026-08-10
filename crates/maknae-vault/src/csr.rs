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

/// True iff the CSR carries EXACTLY one SAN of ANY type, and that sole SAN is a URI
/// equal to `want`. A rogue DNS/IP/email SAN alongside the plane URI is rejected — the
/// same URI-SAN-ONLY shape the returned-leaf verifier enforces (defense in depth: do
/// NOT rely on the Vault role config to strip a second identity).
pub fn csr_single_uri_san(pem: &str, want: &str) -> bool {
    let Some(der) = parse_csr(pem) else {
        return false;
    };
    let Ok((_, csr)) = X509CertificationRequest::from_der(&der) else {
        return false;
    };
    let mut all_sans = 0usize;
    let mut uris: Vec<String> = Vec::new();
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for gn in &san.general_names {
                    all_sans += 1;
                    if let GeneralName::URI(u) = gn {
                        uris.push(u.to_string());
                    }
                }
            }
        }
    }
    all_sans == 1 && uris.len() == 1 && uris[0] == want
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

/// True iff the CSR matches the required plane-cert shape: empty subject, EXACTLY one
/// URI SAN == `want_uri_san`, and EC P-384. This is the fail-closed self-check that
/// `csr_gen::generate_plane_csr` applies to its own output. The AND-decision lives
/// here (T1, mutation-covered — the negative tests prove it REJECTS a bad shape) so
/// that `csr_gen.rs` is left with only external-error plumbing (T3).
pub fn csr_matches_plane_shape(pem: &str, want_uri_san: &str) -> bool {
    csr_has_empty_subject(pem) && csr_single_uri_san(pem, want_uri_san) && csr_is_p384(pem)
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

    /// Build a CSR with an empty subject and an arbitrary mix of SAN types (P-384).
    fn make_csr_sans(sans: Vec<rcgen::SanType>) -> String {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.subject_alt_names = sans;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    #[test]
    fn rejects_plane_uri_plus_rogue_dns() {
        // The expected plane URI PLUS a rogue DNS SAN — must be rejected as URI-only,
        // exactly as the returned-leaf verifier does (codex r6 P2).
        let want = "maknae://d/plane/kernel";
        let mixed = make_csr_sans(vec![
            rcgen::SanType::URI(want.try_into().unwrap()),
            rcgen::SanType::DnsName("evil.example".try_into().unwrap()),
        ]);
        assert!(!csr_single_uri_san(&mixed, want)); // second (DNS) SAN → reject
        assert!(!csr_matches_plane_shape(&mixed, want));
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

    #[test]
    fn matches_plane_shape_accepts_and_rejects_each_failure() {
        let want = "maknae://d/plane/kernel";
        // Good shape: empty subject, one URI-SAN == want, P-384.
        let good = make_csr(None, &[want], &rcgen::PKCS_ECDSA_P384_SHA384);
        assert!(csr_matches_plane_shape(&good, want));
        // Each SINGLE failing dimension must flip it to false (this also kills the
        // `&&`->`||` mutants — with only one predicate false, `||` would still be true).
        let cn = make_csr(Some("x"), &[want], &rcgen::PKCS_ECDSA_P384_SHA384); // subject not empty
        assert!(!csr_matches_plane_shape(&cn, want));
        let wrong_san = make_csr(
            None,
            &["maknae://d/plane/cli"],
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        assert!(!csr_matches_plane_shape(&wrong_san, want)); // SAN != want
        let p256 = make_csr(None, &[want], &rcgen::PKCS_ECDSA_P256_SHA256); // not P-384
        assert!(!csr_matches_plane_shape(&p256, want));
    }
}
