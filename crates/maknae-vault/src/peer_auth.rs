use crate::verify::{verify_uri_san, VerifyError};
use maknae_crypto::rustls::pki_types::CertificateDer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanRule {
    Exact(String),
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
