use crate::{CaBundle, VaultError};
use arc_swap::ArcSwap;
use maknae_crypto::rustls::pki_types::CertificateDer;
use maknae_crypto::rustls::RootCertStore;
use std::sync::Arc;

fn roots_of(pins: &[&CaBundle]) -> Result<RootCertStore, VaultError> {
    if pins.is_empty() {
        return Err(VaultError::Handshake("trust bundle: no pinned root".into()));
    }
    let mut roots = RootCertStore::empty();
    for pin in pins {
        roots
            .add(CertificateDer::from(pin.root_der.clone()))
            .map_err(|e| VaultError::Handshake(format!("pin root anchor: {e}")))?;
    }
    Ok(roots)
}

#[derive(Debug)]
pub struct TrustBundle(ArcSwap<RootCertStore>);

impl TrustBundle {
    pub fn from_pins(pins: &[&CaBundle]) -> Result<Arc<Self>, VaultError> {
        Ok(Arc::new(Self(ArcSwap::from_pointee(roots_of(pins)?))))
    }

    pub fn replace(&self, pins: &[&CaBundle]) -> Result<(), VaultError> {
        self.0.store(Arc::new(roots_of(pins)?));
        Ok(())
    }

    pub(crate) fn roots(&self) -> Arc<RootCertStore> {
        self.0.load_full()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_crypto::rcgen;

    fn ca() -> CaBundle {
        let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let der = p.self_signed(&kp).unwrap().der().to_vec();
        CaBundle {
            root_der: der.clone(),
            int_der: der,
        }
    }

    fn spkis(t: &TrustBundle) -> Vec<Vec<u8>> {
        t.roots()
            .roots
            .iter()
            .map(|a| a.subject_public_key_info.to_vec())
            .collect()
    }

    fn spki_of(ca: &CaBundle) -> Vec<Vec<u8>> {
        let mut s = RootCertStore::empty();
        s.add(ca.root_der.clone().into()).unwrap();
        s.roots
            .iter()
            .map(|a| a.subject_public_key_info.to_vec())
            .collect()
    }

    #[test]
    fn a_trust_bundle_needs_a_root_and_keeps_the_old_one_on_a_bad_replace() {
        let a = ca();
        let b = ca();
        let garbage = CaBundle {
            root_der: vec![0x30, 0x03, 0x02, 0x01, 0x00],
            int_der: vec![],
        };
        assert!(TrustBundle::from_pins(&[]).is_err());
        assert!(TrustBundle::from_pins(&[&garbage]).is_err());
        let t = TrustBundle::from_pins(&[&a]).unwrap();
        assert_eq!(spkis(&t), spki_of(&a));
        assert!(t.replace(&[]).is_err());
        assert_eq!(spkis(&t), spki_of(&a));
        assert!(t.replace(&[&b, &garbage]).is_err());
        assert_eq!(spkis(&t), spki_of(&a));
        t.replace(&[&b]).unwrap();
        assert_eq!(spkis(&t), spki_of(&b));
        t.replace(&[&a, &b]).unwrap();
        assert_eq!(spkis(&t), [spki_of(&a), spki_of(&b)].concat());
    }
}
