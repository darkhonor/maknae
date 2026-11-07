use crate::agent_enroll::AgentId;
use crate::plane::Plane;
use crate::verify::{agent_from_san, leaf_not_after, verify_uri_san, VerifyError};
use maknae_crypto::rustls::pki_types::CertificateDer;
use maknae_crypto::tls::{PeerIdentity, PeerLeaf};
use std::time::SystemTime;

pub(crate) const PLANE_URI_SAN_PREFIX: &str = "plane URI-SAN";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanRule {
    Exact(String),
    Agent { trust_domain: String },
}

impl SanRule {
    pub fn for_plane(plane: Plane, trust_domain: &str) -> Self {
        SanRule::Exact(plane.uri_san(trust_domain))
    }
}

#[derive(Debug)]
pub(crate) struct SanIdentity(pub(crate) SanRule);

impl PeerIdentity for SanIdentity {
    fn check(&self, leaf: &PeerLeaf<'_>) -> Result<(), maknae_crypto::rustls::Error> {
        identity_holds(&self.0, leaf.der(), leaf.uri_names())
    }
}

fn identity_holds(
    rule: &SanRule,
    der: &[u8],
    webpki_uris: Result<Vec<&str>, maknae_crypto::rustls::Error>,
) -> Result<(), maknae_crypto::rustls::Error> {
    let refuse = |why: String| {
        maknae_crypto::rustls::Error::General(format!("{PLANE_URI_SAN_PREFIX}: {why}"))
    };
    let accepted = verify_uri_san(der, rule).map_err(|e| refuse(format!("{e:?}")))?;
    let names = webpki_uris.map_err(|e| refuse(e.to_string()))?;
    match names.as_slice() {
        [one] if *one == accepted => Ok(()),
        _ => Err(refuse(format!(
            "parsers disagree: {accepted:?} against {names:?}"
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAuth {
    Certless,
    PlaneLeaf { accept: SanRule },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelPeer {
    Certless,
    Certified(String),
    Agent {
        san: String,
        agent: AgentId,
        not_after: SystemTime,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PeerAuthRefusal {
    UnexpectedClientCert,
    NoClientCert,
    San(VerifyError),
}

pub(crate) fn decide(
    auth: &PeerAuth,
    peer_certs: Option<&[CertificateDer<'_>]>,
) -> Result<ChannelPeer, PeerAuthRefusal> {
    let leaf = peer_certs.and_then(<[_]>::first);
    match (auth, leaf) {
        (PeerAuth::Certless, None) => Ok(ChannelPeer::Certless),
        (PeerAuth::Certless, Some(_)) => Err(PeerAuthRefusal::UnexpectedClientCert),
        (PeerAuth::PlaneLeaf { .. }, None) => Err(PeerAuthRefusal::NoClientCert),
        (PeerAuth::PlaneLeaf { accept }, Some(leaf)) => {
            let san = verify_uri_san(leaf.as_ref(), accept).map_err(PeerAuthRefusal::San)?;
            match accept {
                SanRule::Exact(_) => Ok(ChannelPeer::Certified(san)),
                SanRule::Agent { trust_domain } => {
                    let agent = agent_from_san(trust_domain, &san)
                        .ok_or(PeerAuthRefusal::San(VerifyError::ParseError))?;
                    let not_after = leaf_not_after(leaf.as_ref()).map_err(PeerAuthRefusal::San)?;
                    Ok(ChannelPeer::Agent {
                        san,
                        agent,
                        not_after,
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_crypto::rcgen;

    fn leaf(sans: Vec<rcgen::SanType>) -> CertificateDer<'static> {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.subject_alt_names = sans;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        params.self_signed(&key).unwrap().der().clone()
    }

    fn uri(u: &str) -> rcgen::SanType {
        rcgen::SanType::URI(u.try_into().unwrap())
    }

    const CLI: &str = "spiffe://d/plane/cli";

    fn plane_leaf() -> PeerAuth {
        PeerAuth::PlaneLeaf {
            accept: SanRule::for_plane(Plane::Cli, "d"),
        }
    }

    #[test]
    fn the_identity_holds_only_when_both_parsers_name_the_accepted_san() {
        let good = leaf(vec![uri(CLI)]);
        let rule = SanRule::Exact(CLI.to_string());
        let bad_encoding = || Err(maknae_crypto::rustls::CertificateError::BadEncoding.into());

        assert_eq!(identity_holds(&rule, &good, Ok(vec![CLI])), Ok(()));
        let refusals = [
            identity_holds(
                &rule,
                &leaf(vec![uri("spiffe://d/plane/kernel")]),
                Ok(vec![CLI]),
            ),
            identity_holds(&rule, &good, bad_encoding()),
            identity_holds(&rule, &good, Ok(vec![])),
            identity_holds(&rule, &good, Ok(vec![CLI, CLI])),
            identity_holds(&rule, &good, Ok(vec!["spiffe://d/plane/kernel"])),
        ];
        for refusal in refusals {
            match refusal {
                Err(maknae_crypto::rustls::Error::General(msg)) => {
                    assert!(msg.starts_with(PLANE_URI_SAN_PREFIX), "{msg}");
                }
                other => panic!("expected a {PLANE_URI_SAN_PREFIX} refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn decide_follows_the_class() {
        let good = leaf(vec![uri(CLI)]);
        let wrong_scheme = leaf(vec![uri("maknae://d/plane/cli")]);
        let extra = leaf(vec![
            uri(CLI),
            rcgen::SanType::DnsName("evil.example".try_into().unwrap()),
        ]);

        assert_eq!(decide(&PeerAuth::Certless, None), Ok(ChannelPeer::Certless));
        assert_eq!(
            decide(&PeerAuth::Certless, Some(std::slice::from_ref(&good))),
            Err(PeerAuthRefusal::UnexpectedClientCert)
        );
        assert_eq!(
            decide(&plane_leaf(), None),
            Err(PeerAuthRefusal::NoClientCert)
        );
        assert_eq!(
            decide(&plane_leaf(), Some(&[good])),
            Ok(ChannelPeer::Certified(CLI.to_string()))
        );
        assert!(matches!(
            decide(&plane_leaf(), Some(&[wrong_scheme])),
            Err(PeerAuthRefusal::San(VerifyError::WrongSan { .. }))
        ));
        assert_eq!(
            decide(&plane_leaf(), Some(&[extra])),
            Err(PeerAuthRefusal::San(VerifyError::ExtraSans))
        );
    }

    #[test]
    fn decide_reads_only_the_first_certificate_and_an_empty_chain_is_no_cert() {
        let good = leaf(vec![uri(CLI)]);
        let kernel = leaf(vec![uri("spiffe://d/plane/kernel")]);

        assert_eq!(
            decide(&PeerAuth::Certless, Some(&[])),
            Ok(ChannelPeer::Certless)
        );
        assert_eq!(
            decide(&plane_leaf(), Some(&[])),
            Err(PeerAuthRefusal::NoClientCert)
        );
        assert_eq!(
            decide(&plane_leaf(), Some(&[good.clone(), kernel.clone()])),
            Ok(ChannelPeer::Certified(CLI.to_string()))
        );
        assert!(matches!(
            decide(&plane_leaf(), Some(&[kernel, good])),
            Err(PeerAuthRefusal::San(VerifyError::WrongSan { .. }))
        ));
    }

    #[test]
    fn an_agent_leaf_decides_to_an_agent_peer() {
        let san = "spiffe://d/plane/agent/hobi";
        let rule = PeerAuth::PlaneLeaf {
            accept: SanRule::Agent {
                trust_domain: "d".to_string(),
            },
        };
        let der = leaf(vec![uri(san)]);
        let want = crate::leaf_not_after(&der).unwrap();
        assert_eq!(
            decide(&rule, Some(std::slice::from_ref(&der))),
            Ok(ChannelPeer::Agent {
                san: san.to_string(),
                agent: AgentId::parse("hobi").unwrap(),
                not_after: want,
            })
        );
        assert!(matches!(
            decide(&rule, Some(&[leaf(vec![uri(CLI)])])),
            Err(PeerAuthRefusal::San(VerifyError::WrongSan { .. }))
        ));
    }

    #[test]
    fn a_plane_rule_names_that_plane_in_the_trust_domain() {
        assert_eq!(
            SanRule::for_plane(Plane::Cli, "d"),
            SanRule::Exact(CLI.to_string())
        );
        assert_eq!(
            SanRule::for_plane(Plane::Kernel, "example.org"),
            SanRule::Exact("spiffe://example.org/plane/kernel".to_string())
        );
    }
}
