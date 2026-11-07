//! The URI-SAN plane-identity verifier — the register's single consciously-owned
//! code (ADR-0016 T1, 0 missed mutants). rustls/webpki validates the CHAIN; this
//! asserts the peer leaf carries EXACTLY the accepted plane or agent URI-SAN and nothing
//! else. SAN extraction via `x509-parser` (webpki is verification-only and does not
//! enumerate SANs — verified).
use crate::agent_enroll::AgentId;
use crate::agent_uri_san;
use crate::peer_auth::SanRule;
use std::time::{Duration, SystemTime};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

/// Why a peer leaf's plane identity was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The leaf carried no URI SAN at all.
    NoUriSan,
    /// The leaf's URI SAN was not the SAN the rule accepts.
    WrongSan { found: Vec<String> },
    /// The leaf carried more than one URI SAN.
    ExtraSans,
    /// The DER could not be parsed.
    ParseError,
}

/// Assert the peer leaf carries exactly one SAN, a URI accepted by `rule`, and
/// return it. Fail-closed on any deviation.
pub fn verify_uri_san(peer_cert_der: &[u8], rule: &SanRule) -> Result<String, VerifyError> {
    verify_san(peer_cert_der, rule).map(|verified| match verified {
        VerifiedSan::Plane(san) | VerifiedSan::Agent { san, .. } => san,
    })
}

pub(crate) enum VerifiedSan {
    Plane(String),
    Agent { san: String, agent: AgentId },
}

pub(crate) fn verify_san(peer_cert_der: &[u8], rule: &SanRule) -> Result<VerifiedSan, VerifyError> {
    let (_, cert) =
        X509Certificate::from_der(peer_cert_der).map_err(|_| VerifyError::ParseError)?;
    // Collect ALL SANs of ANY type — the plane URI must be the leaf's ONLY SAN, so a
    // rogue DNS/IP/email SAN alongside it is a rejectable second identity (defense in
    // depth: do NOT rely on Vault's role config for this).
    let mut all_sans: Vec<String> = Vec::new();
    let mut uris: Vec<String> = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                all_sans.push(format!("{gn:?}"));
                if let GeneralName::URI(u) = gn {
                    uris.push(u.to_string());
                }
            }
        }
    }
    if all_sans.is_empty() {
        return Err(VerifyError::NoUriSan);
    }
    if all_sans.len() > 1 {
        // more than one SAN of ANY type (e.g. the plane URI + a DNS SAN)
        return Err(VerifyError::ExtraSans);
    }
    // Exactly one SAN — it must be the expected plane URI.
    match (rule, uris.pop()) {
        (SanRule::Exact(want), Some(got)) if uris.is_empty() && got == *want => {
            Ok(VerifiedSan::Plane(got))
        }
        (SanRule::Exact(_), _) => Err(VerifyError::WrongSan { found: all_sans }),
        (SanRule::Agent { trust_domain }, Some(got)) if uris.is_empty() => {
            match agent_from_san(trust_domain, &got) {
                Some(agent) => Ok(VerifiedSan::Agent { san: got, agent }),
                None => Err(VerifyError::WrongSan { found: all_sans }),
            }
        }
        (SanRule::Agent { .. }, _) => Err(VerifyError::WrongSan { found: all_sans }),
    }
}

fn agent_from_san(trust_domain: &str, san: &str) -> Option<AgentId> {
    let id = san.strip_prefix(&format!("spiffe://{trust_domain}/plane/agent/"))?;
    let agent = AgentId::parse(id).ok()?;
    (agent_uri_san(trust_domain, &agent) == san).then_some(agent)
}

pub fn leaf_not_after(der: &[u8]) -> Result<SystemTime, VerifyError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| VerifyError::ParseError)?;
    let secs = u64::try_from(cert.validity().not_after.timestamp())
        .map_err(|_| VerifyError::ParseError)?;
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Plane;
    use maknae_crypto::rcgen;

    fn check(der: &[u8], expect: Plane, dep: &str) -> Result<String, VerifyError> {
        verify_uri_san(der, &SanRule::for_plane(expect, dep))
    }

    /// Build a self-signed leaf carrying exactly the given URI SANs (DER).
    fn leaf_with_uri_sans(uris: &[&str]) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.subject_alt_names = uris
            .iter()
            .map(|u| rcgen::SanType::URI((*u).try_into().unwrap()))
            .collect();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        params.self_signed(&key).unwrap().der().as_ref().to_vec()
    }

    #[test]
    fn accepts_exact_plane_san() {
        let der = leaf_with_uri_sans(&["spiffe://dev-01/plane/kernel"]);
        assert!(check(&der, Plane::Kernel, "dev-01").is_ok());
    }

    #[test]
    fn rejects_wrong_plane() {
        let der = leaf_with_uri_sans(&["spiffe://dev-01/plane/cli"]);
        assert!(matches!(
            check(&der, Plane::Kernel, "dev-01"),
            Err(VerifyError::WrongSan { .. })
        ));
    }

    #[test]
    fn rejects_wrong_deployment_id() {
        let der = leaf_with_uri_sans(&["spiffe://other/plane/kernel"]);
        assert!(matches!(
            check(&der, Plane::Kernel, "dev-01"),
            Err(VerifyError::WrongSan { .. })
        ));
    }

    fn cert_with_sans(sans: Vec<rcgen::SanType>) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.subject_alt_names = sans;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        params.self_signed(&key).unwrap().der().as_ref().to_vec()
    }

    #[test]
    fn rejects_dns_only_san() {
        // A single DNS SAN (one SAN, but not the plane URI) → rejected.
        let der = cert_with_sans(vec![rcgen::SanType::DnsName(
            "example.com".try_into().unwrap(),
        )]);
        assert!(matches!(
            check(&der, Plane::Kernel, "dev-01"),
            Err(VerifyError::WrongSan { .. })
        ));
    }

    #[test]
    fn rejects_no_san_at_all() {
        let der = cert_with_sans(vec![]);
        assert_eq!(
            check(&der, Plane::Kernel, "dev-01"),
            Err(VerifyError::NoUriSan)
        );
    }

    #[test]
    fn rejects_plane_uri_plus_rogue_dns() {
        // The expected plane URI PLUS a rogue DNS SAN — the P1 codex caught: must reject.
        let der = cert_with_sans(vec![
            rcgen::SanType::URI("spiffe://dev-01/plane/kernel".try_into().unwrap()),
            rcgen::SanType::DnsName("evil.example".try_into().unwrap()),
        ]);
        assert_eq!(
            check(&der, Plane::Kernel, "dev-01"),
            Err(VerifyError::ExtraSans)
        );
    }

    #[test]
    fn rejects_extra_sans() {
        let der =
            leaf_with_uri_sans(&["spiffe://dev-01/plane/kernel", "spiffe://dev-01/plane/cli"]);
        assert_eq!(
            check(&der, Plane::Kernel, "dev-01"),
            Err(VerifyError::ExtraSans)
        );
    }

    fn agent_rule() -> SanRule {
        SanRule::Agent {
            trust_domain: "d".to_string(),
        }
    }

    #[test]
    fn the_agent_rule_accepts_an_agent_san_and_names_it() {
        let der = leaf_with_uri_sans(&["spiffe://d/plane/agent/hobi.2_x-y"]);
        assert_eq!(
            verify_uri_san(&der, &agent_rule()),
            Ok("spiffe://d/plane/agent/hobi.2_x-y".to_string())
        );
        let id = crate::agent_enroll::AgentId::parse("hobi").unwrap();
        assert_eq!(
            crate::agent_uri_san("d", &id),
            "spiffe://d/plane/agent/hobi"
        );
    }

    #[test]
    fn the_agent_rule_refuses() {
        for bad in [
            "spiffe://d/plane/cli",
            "spiffe://d/plane/kernel",
            "spiffe://other/plane/agent/hobi",
            "spiffe://d/plane/agent/",
            "spiffe://d/plane/agent/HOBI",
            "spiffe://d/plane/agent/a*",
            "spiffe://d/plane/agent/hobi/x",
            "spiffe://d/plane/agent/data",
            "spiffe://d/plane/agent/hob%69",
            "spiffe://d/plane/agent/hobi/",
            "spiffe://d/plane/agent/hobi?x",
            "spiffe://d/plane/agent/hobi#x",
            "spiffe://D/plane/agent/hobi",
            "SPIFFE://d/plane/agent/hobi",
            "spiffe://d//plane/agent/hobi",
            "spiffe://dd/plane/agent/hobi",
            "spiffe://d.evil/plane/agent/hobi",
        ] {
            let der = leaf_with_uri_sans(&[bad]);
            assert!(
                matches!(
                    verify_uri_san(&der, &agent_rule()),
                    Err(VerifyError::WrongSan { .. })
                ),
                "{bad}"
            );
        }
        let der = cert_with_sans(vec![rcgen::SanType::DnsName("hobi".try_into().unwrap())]);
        assert!(matches!(
            verify_uri_san(&der, &agent_rule()),
            Err(VerifyError::WrongSan { .. })
        ));
        let der = cert_with_sans(vec![
            rcgen::SanType::URI("spiffe://d/plane/agent/hobi".try_into().unwrap()),
            rcgen::SanType::DnsName("evil.example".try_into().unwrap()),
        ]);
        assert_eq!(
            verify_uri_san(&der, &agent_rule()),
            Err(VerifyError::ExtraSans)
        );
    }

    #[test]
    fn the_agent_rule_refuses_a_second_san() {
        let der = leaf_with_uri_sans(&[
            "spiffe://d/plane/agent/hobi",
            "spiffe://d/plane/agent/other",
        ]);
        assert_eq!(
            verify_uri_san(&der, &agent_rule()),
            Err(VerifyError::ExtraSans)
        );
    }

    #[test]
    fn leaf_not_after_reads_the_validity() {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.not_before = rcgen::date_time_ymd(2030, 1, 1);
        params.not_after = rcgen::date_time_ymd(2031, 6, 7);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let der = params.self_signed(&key).unwrap().der().to_vec();
        let want = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_938_556_800);
        assert_eq!(leaf_not_after(&der), Ok(want));
        assert_eq!(leaf_not_after(b"junk"), Err(VerifyError::ParseError));
    }

    #[test]
    fn rejects_unparseable() {
        assert_eq!(
            check(b"not a cert", Plane::Kernel, "dev-01"),
            Err(VerifyError::ParseError)
        );
    }
}
