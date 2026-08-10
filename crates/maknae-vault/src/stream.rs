//! PlaneListener / PlaneConnector / AuthenticatedStream (Layer 2 + Layer 1 glue, T3). The
//! transport REPORTS the verified peer URI-SAN + captured peer-creds; it does NOT decide
//! uid policy or emit audit (Boundary A — those are the Stage-3 daemon's).
use crate::peercred::{self, PeerCreds};
use crate::resolver::PlaneCertResolver;
use crate::{socket, tls, CaBundle, Plane, PlaneClient, VaultError};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{TlsAcceptor, TlsConnector};

enum TlsStream {
    Server(tokio_rustls::server::TlsStream<tokio::net::UnixStream>),
    Client(tokio_rustls::client::TlsStream<tokio::net::UnixStream>),
}

/// A connected, mutually-authenticated plane channel.
pub struct AuthenticatedStream {
    inner: TlsStream,
    peer_uri_san: String,
    peer_creds: PeerCreds,
}

impl AuthenticatedStream {
    /// The peer's verified plane URI-SAN (`maknae://<dep>/plane/<peer>`).
    pub fn peer_uri_san(&self) -> &str {
        &self.peer_uri_san
    }
    /// Kernel-captured peer credentials — the daemon polices `uid`.
    pub fn peer_creds(&self) -> &PeerCreds {
        &self.peer_creds
    }
}

impl AsyncRead for AuthenticatedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.inner {
            TlsStream::Server(s) => Pin::new(s).poll_read(cx, buf),
            TlsStream::Client(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AuthenticatedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.inner {
            TlsStream::Server(s) => Pin::new(s).poll_write(cx, b),
            TlsStream::Client(s) => Pin::new(s).poll_write(cx, b),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.inner {
            TlsStream::Server(s) => Pin::new(s).poll_flush(cx),
            TlsStream::Client(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.inner {
            TlsStream::Server(s) => Pin::new(s).poll_shutdown(cx),
            TlsStream::Client(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Recompute the peer's URI-SAN string to report it (the verifier already accepted the
/// leaf; this re-confirms and yields the canonical string).
fn peer_uri_san(
    peer_certs: Option<&[rustls::pki_types::CertificateDer<'static>]>,
    expect: Plane,
    dep: &str,
) -> Result<String, VaultError> {
    let leaf = peer_certs
        .and_then(|c| c.first())
        .ok_or_else(|| VaultError::Handshake("peer presented no cert".into()))?;
    crate::verify_plane_uri_san(leaf.as_ref(), expect, dep).map_err(VaultError::PeerIdentity)?;
    Ok(expect.uri_san(dep))
}

/// Daemon (server) side.
pub struct PlaneListener {
    listener: tokio::net::UnixListener,
    acceptor: TlsAcceptor,
    expect: Plane,
    deployment_id: String,
}

impl PlaneListener {
    /// Bind a group-gated listener presenting this client's live leaf, requiring the peer
    /// to prove `plane == this.plane().peer()`.
    ///
    /// **Must be called from within a Tokio runtime** (it binds a `UnixListener`, which
    /// registers with the reactor and panics otherwise).
    pub fn bind(path: &Path, client: &PlaneClient, ca: &CaBundle) -> Result<Self, VaultError> {
        let resolver = Arc::new(PlaneCertResolver::new_empty());
        // Registers the slot AND seeds it from the current identity atomically under the
        // identity lock (fail-closed against a racing renewal-expiry — codex r1).
        client.attach_cert_sink(resolver.slot())?;
        let cfg = tls::server_config(client, ca, resolver)?;
        let listener = socket::bind_listener(path)?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(cfg),
            expect: client.plane().peer(),
            deployment_id: client.deployment_id().to_string(),
        })
    }

    /// Accept one connection: capture peer-creds, complete the mTLS server handshake, and
    /// report the verified peer identity. Fail-closed on any error.
    pub async fn accept(&self) -> Result<AuthenticatedStream, VaultError> {
        let (raw, _addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| VaultError::SocketBind(e.to_string()))?;
        let peer_creds = peercred::capture(&raw)?;
        let tls = self
            .acceptor
            .accept(raw)
            .await
            .map_err(|e| VaultError::Handshake(e.to_string()))?;
        let peer_certs = tls.get_ref().1.peer_certificates().map(|c| c.to_vec());
        let peer_uri = peer_uri_san(peer_certs.as_deref(), self.expect, &self.deployment_id)?;
        Ok(AuthenticatedStream {
            inner: TlsStream::Server(tls),
            peer_uri_san: peer_uri,
            peer_creds,
        })
    }
}

/// CLI (client) side.
pub struct PlaneConnector;

impl PlaneConnector {
    /// Connect + mutually authenticate; report the verified daemon identity.
    pub async fn connect(
        path: &Path,
        client: &PlaneClient,
        ca: &CaBundle,
    ) -> Result<AuthenticatedStream, VaultError> {
        let expect = client.plane().peer();
        let cfg = tls::client_config(client, ca, expect)?;
        let raw = socket::connect(path).await?;
        let peer_creds = peercred::capture(&raw)?;
        let name = rustls::pki_types::ServerName::try_from("maknae.invalid")
            .map_err(|e| VaultError::Handshake(format!("placeholder server name: {e}")))?;
        let tls = TlsConnector::from(cfg)
            .connect(name, raw)
            .await
            .map_err(|e| VaultError::Handshake(e.to_string()))?;
        let peer_certs = tls.get_ref().1.peer_certificates().map(|c| c.to_vec());
        let peer_uri = peer_uri_san(peer_certs.as_deref(), expect, client.deployment_id())?;
        Ok(AuthenticatedStream {
            inner: TlsStream::Client(tls),
            peer_uri_san: peer_uri,
            peer_creds,
        })
    }
}
