//! The asymmetric mTLS peer verifier (Layer 1, T3 adapter over the T1 decision). Chain +
//! proof-of-possession stay in rustls' trusted primitives; we ADD exactly one thing — the
//! T1 `verify_plane_uri_san` — after the library says the chain is valid. ASYMMETRIC
//! because rustls bakes DNS/IP name-matching into the *server*-cert path but a plane leaf
//! is URI-SAN-only, so the client side uses the name-free primitives (spec §4.2).
use crate::{verify_plane_uri_san, CaBundle, Plane, VaultError};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use std::sync::Arc;

/// RootCertStore with the PINNED ROOT anchor ONLY (never the intermediate — that rides the
/// peer-presented chain).
pub(crate) fn root_store(ca: &CaBundle) -> Result<RootCertStore, VaultError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.root_der.clone()))
        .map_err(|e| VaultError::Handshake(format!("pin root anchor: {e}")))?;
    Ok(roots)
}

// ---- server side: wrap WebPkiClientVerifier (no name check) + add URI-SAN --------------

#[derive(Debug)]
pub(crate) struct PlaneClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    expect: Plane,
    deployment_id: String,
}

impl PlaneClientCertVerifier {
    pub(crate) fn new(
        ca: &CaBundle,
        expect: Plane,
        deployment_id: &str,
    ) -> Result<Arc<Self>, VaultError> {
        let roots = Arc::new(root_store(ca)?);
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let inner = WebPkiClientVerifier::builder_with_provider(roots, provider)
            .build()
            .map_err(|e| VaultError::Handshake(format!("client verifier: {e}")))?;
        Ok(Arc::new(Self {
            inner,
            expect,
            deployment_id: deployment_id.to_string(),
        }))
    }
}

impl ClientCertVerifier for PlaneClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // chain + expiry + anchor (no name check on the client-cert path)
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;
        // ADD the plane identity decision (T1)
        verify_plane_uri_san(end_entity.as_ref(), self.expect, &self.deployment_id)
            .map_err(|e| rustls::Error::General(format!("plane URI-SAN: {e:?}")))?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ---- client side: name-free primitives (URI-SAN leaf can't pass WebPkiServerVerifier) ---

#[derive(Debug)]
pub(crate) struct PlaneServerCertVerifier {
    roots: RootCertStore,
    provider: Arc<rustls::crypto::CryptoProvider>,
    expect: Plane,
    deployment_id: String,
}

impl PlaneServerCertVerifier {
    pub(crate) fn new(
        ca: &CaBundle,
        expect: Plane,
        deployment_id: &str,
    ) -> Result<Arc<Self>, VaultError> {
        Ok(Arc::new(Self {
            roots: root_store(ca)?,
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            expect,
            deployment_id: deployment_id.to_string(),
        }))
    }
}

impl ServerCertVerifier for PlaneServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>, // IGNORED — identity is the URI-SAN, not a hostname
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        verify_plane_uri_san(end_entity.as_ref(), self.expect, &self.deployment_id)
            .map_err(|e| rustls::Error::General(format!("plane URI-SAN: {e:?}")))?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    fn provider() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
    }

    /// The CA keeps its `CertificateParams`, not its `Certificate`: rcgen 0.14
    /// signs against an `Issuer`, which is built from the issuing params + key.
    /// (`Issuer::from_ca_cert_der` would recover one from DER, but it needs
    /// rcgen's `x509-parser` feature, which this crate does not enable.)
    struct Ca {
        der: Vec<u8>,
        kp: rcgen::KeyPair,
        params: rcgen::CertificateParams,
    }
    impl Ca {
        fn issuer(&self) -> rcgen::Issuer<'_, &rcgen::KeyPair> {
            rcgen::Issuer::from_params(&self.params, &self.kp)
        }
    }
    fn mk_ca() -> Ca {
        let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let cert = p.self_signed(&kp).unwrap();
        Ca {
            der: cert.der().to_vec(),
            kp,
            params: p,
        }
    }
    fn mk_leaf(ca: &Ca, uri: &str) -> Vec<u8> {
        let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        p.signed_by(&kp, &ca.issuer()).unwrap().der().to_vec()
    }

    #[test]
    fn server_verifier_accepts_kernel_rejects_cli() {
        provider();
        let ca = mk_ca();
        let cab = crate::CaBundle {
            root_der: ca.der.clone(),
            int_der: ca.der.clone(),
        };
        let v = PlaneServerCertVerifier::new(&cab, Plane::Kernel, "d").unwrap();
        let name = ServerName::try_from("maknae.invalid").unwrap();
        let now = UnixTime::now();
        let ca_int = CertificateDer::from(ca.der.clone());
        // Correct plane (kernel) accepted:
        let kernel = CertificateDer::from(mk_leaf(&ca, "maknae://d/plane/kernel"));
        assert!(v
            .verify_server_cert(&kernel, std::slice::from_ref(&ca_int), &name, &[], now)
            .is_ok());
        // Wrong plane (cli) rejected:
        let cli = CertificateDer::from(mk_leaf(&ca, "maknae://d/plane/cli"));
        assert!(v
            .verify_server_cert(&cli, std::slice::from_ref(&ca_int), &name, &[], now)
            .is_err());
    }
}
