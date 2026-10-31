//! Hot-reload server-cert resolver (Layer 1, T3) — mirrors Microkosmos
//! `vault_cert_resolver.rs`. Backed by `ArcSwapOption<CertifiedKey>` (one atomic load per
//! handshake, no read-lock contention with the renewal writer). An EMPTY/cleared slot
//! resolves to `None` → the handshake aborts cleanly: a daemon whose Vault-backed identity
//! was cleared (renewal expired) cannot present a live plane cert (fail closed).
use arc_swap::ArcSwapOption;
use maknae_crypto::rustls::server::{ClientHello, ResolvesServerCert};
use maknae_crypto::rustls::sign::CertifiedKey;
use std::sync::Arc;

pub(crate) struct PlaneCertResolver(pub(crate) Arc<ArcSwapOption<CertifiedKey>>);

impl PlaneCertResolver {
    pub(crate) fn new_empty() -> Self {
        PlaneCertResolver(Arc::new(ArcSwapOption::from(None)))
    }
    /// The shared slot the mint/expire path in `client.rs` stores into (§4.3 cert sink).
    pub(crate) fn slot(&self) -> Arc<ArcSwapOption<CertifiedKey>> {
        Arc::clone(&self.0)
    }
}

impl std::fmt::Debug for PlaneCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PlaneCertResolver")
    }
}

impl ResolvesServerCert for PlaneCertResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.load_full() // None when empty → fail closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_crypto::rcgen;

    fn dummy_certified_key() -> Arc<CertifiedKey> {
        maknae_crypto::init().unwrap();
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let params = rcgen::CertificateParams::new(vec![]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let key = maknae_crypto::tls::load_private_key(
            &maknae_crypto::policy().unwrap().tls,
            maknae_crypto::rustls::pki_types::PrivateKeyDer::Pkcs8(kp.serialize_der().into()),
        )
        .unwrap();
        Arc::new(CertifiedKey::new(vec![cert.der().clone()], key))
    }

    #[test]
    fn empty_resolves_none_populated_resolves_some() {
        let r = PlaneCertResolver::new_empty();
        assert!(r.0.load().is_none());
        r.slot().store(Some(dummy_certified_key()));
        assert!(r.0.load().is_some());
    }
}
