use crate::verify::{verify_uri_san, VerifyError};
use maknae_crypto::rustls::pki_types::CertificateDer;
use maknae_crypto::tls::{PeerIdentity, PeerLeaf};

pub(crate) const PLANE_URI_SAN_PREFIX: &str = "plane URI-SAN";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanRule {
    Exact(String),
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
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the listener and connector")
)]
pub(crate) enum PeerAuthRefusal {
    UnexpectedClientCert,
    NoClientCert,
    San(VerifyError),
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the listener and connector")
)]
pub(crate) fn decide(
    auth: &PeerAuth,
    peer_certs: Option<&[CertificateDer<'_>]>,
) -> Result<ChannelPeer, PeerAuthRefusal> {
    let leaf = peer_certs.and_then(<[_]>::first);
    match (auth, leaf) {
        (PeerAuth::Certless, None) => Ok(ChannelPeer::Certless),
        (PeerAuth::Certless, Some(_)) => Err(PeerAuthRefusal::UnexpectedClientCert),
        (PeerAuth::PlaneLeaf { .. }, None) => Err(PeerAuthRefusal::NoClientCert),
        (PeerAuth::PlaneLeaf { accept }, Some(leaf)) => verify_uri_san(leaf.as_ref(), accept)
            .map(ChannelPeer::Certified)
            .map_err(PeerAuthRefusal::San),
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
            accept: SanRule::Exact(CLI.to_string()),
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
}
