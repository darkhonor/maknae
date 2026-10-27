//! rustls configuration builders on the crate's FIPS provider, TLS 1.3 only.
use crate::{crypto_provider, CryptoError};
use rustls::{ClientConfig, ConfigBuilder, ServerConfig, WantsVerifier};
use std::sync::Arc;

#[expect(clippy::disallowed_methods)]
pub fn client_builder() -> Result<ConfigBuilder<ClientConfig, WantsVerifier>, CryptoError> {
    ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| CryptoError::Tls(e.to_string()))
}

#[expect(clippy::disallowed_methods)]
pub fn server_builder() -> Result<ConfigBuilder<ServerConfig, WantsVerifier>, CryptoError> {
    ServerConfig::builder_with_provider(Arc::new(crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| CryptoError::Tls(e.to_string()))
}

#[expect(clippy::disallowed_methods)]
pub fn load_private_key(
    der: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<dyn rustls::sign::SigningKey>, CryptoError> {
    crypto_provider()
        .key_provider
        .load_private_key(der)
        .map_err(|e| CryptoError::Tls(e.to_string()))
}

#[expect(clippy::disallowed_methods)]
pub fn client_cert_verifier_builder(
    roots: Arc<rustls::RootCertStore>,
) -> rustls::server::ClientCertVerifierBuilder {
    rustls::server::WebPkiClientVerifier::builder_with_provider(roots, Arc::new(crypto_provider()))
}

#[expect(clippy::disallowed_methods)]
pub fn server_cert_verifier_builder(
    roots: Arc<rustls::RootCertStore>,
) -> rustls::client::ServerCertVerifierBuilder {
    rustls::client::WebPkiServerVerifier::builder_with_provider(roots, Arc::new(crypto_provider()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KX_GROUPS;
    use rustls::pki_types::{PrivateKeyDer, ServerName};

    fn names(groups: &[&'static dyn rustls::crypto::SupportedKxGroup]) -> Vec<rustls::NamedGroup> {
        groups.iter().map(|g| g.name()).collect()
    }

    fn p384() -> rcgen::KeyPair {
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap()
    }

    fn pump(
        client: &mut rustls::ClientConnection,
        server: &mut rustls::ServerConnection,
    ) -> Result<(), rustls::Error> {
        while client.is_handshaking() || server.is_handshaking() {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            server.read_tls(&mut buf.as_slice()).unwrap();
            server.process_new_packets()?;
            let mut buf = Vec::new();
            server.write_tls(&mut buf).unwrap();
            client.read_tls(&mut buf.as_slice()).unwrap();
            client.process_new_packets()?;
        }
        Ok(())
    }

    #[test]
    fn both_builders_carry_the_crate_provider() {
        let want = names(&KX_GROUPS);
        let client = client_builder()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        assert_eq!(names(&client.crypto_provider().kx_groups), want);
        assert!(client.fips());
        let resolver = std::sync::Arc::new(rustls::server::ResolvesServerCertUsingSni::new());
        let server = server_builder()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        assert_eq!(names(&server.crypto_provider().kx_groups), want);
        assert!(server.fips());
    }

    #[test]
    fn the_builders_negotiate_tls13_and_the_verifier_builders_verify() {
        crate::install_default_crypto_provider();
        let ca_key = p384();
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let leaf_key = p384();
        let leaf = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let roots = Arc::new(roots);
        let server_verifier = server_cert_verifier_builder(roots.clone()).build().unwrap();
        let client_verifier = client_cert_verifier_builder(roots).build().unwrap();

        let leaf_der = || PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
        let server_cfg = server_builder()
            .unwrap()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![leaf.der().clone()], leaf_der())
            .unwrap();
        let client_cfg = client_builder()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(server_verifier)
            .with_client_auth_cert(vec![leaf.der().clone()], leaf_der())
            .unwrap();

        let mut client = rustls::ClientConnection::new(
            Arc::new(client_cfg),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server_cfg)).unwrap();
        pump(&mut client, &mut server).unwrap();
        assert_eq!(
            client.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            server.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
    }

    #[test]
    fn garbage_key_der_is_a_tls_error() {
        let got = load_private_key(PrivateKeyDer::Pkcs8(vec![0u8; 8].into()));
        assert!(matches!(got, Err(CryptoError::Tls(_))));
    }
}
