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
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Why `PlaneListener::accept()` refused a connection — carries the SAME captured
/// `PeerCreds` the transport would have attached on success, so the (non-privileged)
/// transport can REPORT a rejection with identity attached without itself auditing it
/// (Boundary A — the Stage-3 daemon decides what to do with this).
#[derive(Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// The TLS handshake failed for a reason not further distinguished below.
    Handshake,
    /// The handshake did not complete within the configured bound.
    HandshakeTimeout,
    /// The peer's leaf carried a plane URI-SAN other than the one expected (the T1
    /// `verify_plane_uri_san` check — this crate's own decision, not rustls').
    WrongPlane,
    /// The peer's leaf was expired / not yet valid.
    ExpiredOrInvalidCert,
    /// The peer's chain did not validate against the pinned root (unknown issuer, bad
    /// signature, revoked).
    ChainOrCa,
    /// Kernel peer-credential capture failed — the connection is refused before any
    /// identity is known (fail-closed; mirrors `VaultError::PeerCred`).
    PeerCredCapture,
    /// The raw accept on the listening socket itself failed (no peer connected yet, so no
    /// creds exist to capture).
    Io,
}

/// A refused `accept()` — carries whatever `PeerCreds` were captured before the failure
/// (`Some` in the common case: creds are captured before the TLS handshake even starts) so
/// the daemon can audit WHO was rejected and WHY. The transport reports; it never audits.
#[derive(Debug)]
pub struct AcceptRejection {
    pub peer_creds: Option<PeerCreds>,
    pub reason: RejectReason,
}

/// Classify a failed `TlsAcceptor::accept()` outcome. tokio-rustls wraps the underlying
/// `rustls::Error` as the io::Error's source (`io::Error::new(InvalidData, rustls_err)`), so
/// downcast to it when present. `rustls::Error` and `CertificateError` are `#[non_exhaustive]`
/// — an unmatched variant falls back to `Handshake` per the brief (WrongPlane is preserved
/// exactly because that's OUR OWN `plane_verify` rejection, tagged by its message prefix).
fn classify_handshake_error(e: &std::io::Error) -> RejectReason {
    let Some(rustls_err) = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    else {
        return RejectReason::Handshake;
    };
    match rustls_err {
        // plane_verify.rs wraps a WrongSan/NoUriSan/ExtraSans/ParseError rejection as
        // `rustls::Error::General("plane URI-SAN: {e:?}")` — see PlaneClientCertVerifier.
        rustls::Error::General(msg) if msg.starts_with("plane URI-SAN") => RejectReason::WrongPlane,
        rustls::Error::InvalidCertificate(cert_err) => match cert_err {
            rustls::CertificateError::Expired
            | rustls::CertificateError::ExpiredContext { .. }
            | rustls::CertificateError::NotValidYet
            | rustls::CertificateError::NotValidYetContext { .. } => {
                RejectReason::ExpiredOrInvalidCert
            }
            rustls::CertificateError::UnknownIssuer
            | rustls::CertificateError::BadSignature
            | rustls::CertificateError::Revoked
            | rustls::CertificateError::UnknownRevocationStatus
            | rustls::CertificateError::ExpiredRevocationList
            | rustls::CertificateError::ExpiredRevocationListContext { .. } => {
                RejectReason::ChainOrCa
            }
            _ => RejectReason::Handshake,
        },
        _ => RejectReason::Handshake,
    }
}

enum TlsStream {
    Server(tokio_rustls::server::TlsStream<tokio::net::UnixStream>),
    Client(tokio_rustls::client::TlsStream<tokio::net::UnixStream>),
}

/// A raw-accepted plane connection: the bare UDS stream plus the `PeerCreds` captured
/// (fast syscalls) BEFORE any TLS handshake. Produced by [`PlaneListener::accept_raw`],
/// consumed by [`PlaneListener::finish_handshake`]. This split lets the daemon's accept
/// loop take the socket promptly and run the bounded TLS handshake per-connection under
/// its concurrency semaphore — so a client that stalls the handshake cannot serialize
/// acceptance and starve the loop (anti-DoS, spec §6a/§10). Opaque on purpose: the raw
/// `tokio::net::UnixStream` never crosses into the kernel crate (which does not link
/// tokio's `net` feature); the kernel only names this wrapper.
pub struct RawPlaneConn(tokio::net::UnixStream);

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
    /// The bound pathname socket — unlinked on drop (tokio/std `UnixListener` leaves it).
    path: std::path::PathBuf,
    /// Detaches this listener's cert sink from the client on drop (frees the client to bind
    /// a replacement listener). Field order places it last so it drops after the others.
    _sink_guard: crate::client::CertSinkGuard,
}

impl Drop for PlaneListener {
    fn drop(&mut self) {
        // Remove the pathname socket so a retired listener leaves no stale endpoint behind
        // (best-effort — bind_listener's stale-socket detection would also reclaim it).
        let _ = std::fs::remove_file(&self.path);
    }
}

impl PlaneListener {
    /// Bind a group-gated listener presenting this client's live leaf, requiring the peer
    /// to prove `plane == this.plane().peer()`.
    ///
    /// **One client backs one listener.** A `PlaneClient` may back at most one active
    /// `PlaneListener`; a second `bind` on the same client returns `VaultError::SocketBind`
    /// (mint/expiry/shutdown drive a single resolver slot).
    ///
    /// **Must be called from within a Tokio runtime** (it binds a `UnixListener`, which
    /// registers with the reactor and panics otherwise).
    pub fn bind(path: &Path, client: &PlaneClient, ca: &CaBundle) -> Result<Self, VaultError> {
        let resolver = Arc::new(PlaneCertResolver::new_empty());
        let cfg = tls::server_config(client, ca, Arc::clone(&resolver))?;
        let listener = socket::bind_listener(path)?;
        // Attach LAST — after every other fallible step has succeeded — so a failed
        // config/bind never replaces (orphans) an existing listener's sink (codex r4).
        // attach registers the slot AND seeds it from the current identity atomically under
        // the identity lock (fail-closed against a racing renewal-expiry — codex r1); the
        // returned guard detaches the sink when this listener drops (codex r6).
        let sink_guard = match client.attach_cert_sink(resolver.slot()) {
            Ok(g) => g,
            Err(e) => {
                // attach failed AFTER we bound the socket — unlink it so we don't leave a
                // stale endpoint behind (codex r7).
                drop(listener);
                let _ = std::fs::remove_file(path);
                return Err(e);
            }
        };
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(cfg),
            expect: client.plane().peer(),
            deployment_id: client.deployment_id().to_string(),
            path: path.to_path_buf(),
            _sink_guard: sink_guard,
        })
    }

    /// Prompt half of accept (anti-DoS): do ONLY the `UnixListener::accept()` +
    /// `SO_PEERCRED`/`LOCAL_PEERCRED` capture — both fast syscalls — and return the raw
    /// stream with its peer-creds. NO TLS handshake happens here, so this cannot be stalled
    /// by a slow peer: the daemon's accept loop stays free to accept the next connection
    /// while the (bounded) handshake runs elsewhere, under the concurrency semaphore. Only a
    /// raw-accept syscall error (or a peer-cred capture failure) surfaces here, as an
    /// `io::Error` the loop logs-and-continues (never `?`).
    pub async fn accept_raw(&self) -> Result<(RawPlaneConn, PeerCreds), std::io::Error> {
        accept_raw_on(&self.listener).await
    }

    /// Bounded half of accept (anti-DoS): complete the mTLS server handshake within
    /// `handshake_timeout`, verify the plane URI-SAN, and report the authenticated peer.
    /// Fail-closed on any error — but the returned `AcceptRejection` carries the `PeerCreds`
    /// captured by `accept_raw` (before the handshake started) so the daemon can audit WHO
    /// was rejected and WHY; a timeout is `HandshakeTimeout`. The transport only REPORTS
    /// this; it never audits (Boundary A). Run this per-connection under the accept loop's
    /// semaphore: a stalled handshake then occupies ONE permit for at most
    /// `handshake_timeout`, never the accept loop itself.
    pub async fn finish_handshake(
        &self,
        raw: RawPlaneConn,
        peer_creds: PeerCreds,
        handshake_timeout: Duration,
    ) -> Result<AuthenticatedStream, AcceptRejection> {
        finish_handshake_on(
            &self.acceptor,
            self.expect,
            &self.deployment_id,
            raw,
            peer_creds,
            handshake_timeout,
        )
        .await
    }
}

/// The prompt raw-accept, factored out of the `PlaneListener` method so tests can drive it
/// against a bare `UnixListener` (peer-creds need a real socket; `PlaneListener` itself
/// additionally requires a live `PlaneClient` cert-sink attachment not needed here). A
/// peer-cred capture failure fails closed to an `io::Error` — a peer we cannot identify
/// cannot be policed, and the caller drops the socket.
pub(crate) async fn accept_raw_on(
    listener: &tokio::net::UnixListener,
) -> Result<(RawPlaneConn, PeerCreds), std::io::Error> {
    let (raw, _addr) = listener.accept().await?;
    // Capture peer-creds BEFORE the handshake — so they're available to report even on a
    // handshake/SAN failure (the whole point of `AcceptRejection`).
    let peer_creds = peercred::capture(&raw).map_err(std::io::Error::other)?;
    Ok((RawPlaneConn(raw), peer_creds))
}

/// The bounded handshake half, factored out for the same testability reason as
/// `accept_raw_on`. Consumes the raw stream + its captured creds and produces the
/// authenticated stream (or an `AcceptRejection` carrying those creds).
pub(crate) async fn finish_handshake_on(
    acceptor: &TlsAcceptor,
    expect: Plane,
    deployment_id: &str,
    raw: RawPlaneConn,
    peer_creds: PeerCreds,
    handshake_timeout: Duration,
) -> Result<AuthenticatedStream, AcceptRejection> {
    let tls = match tokio::time::timeout(handshake_timeout, acceptor.accept(raw.0)).await {
        Err(_elapsed) => {
            return Err(AcceptRejection {
                peer_creds: Some(peer_creds),
                reason: RejectReason::HandshakeTimeout,
            })
        }
        Ok(Err(e)) => {
            return Err(AcceptRejection {
                peer_creds: Some(peer_creds),
                reason: classify_handshake_error(&e),
            })
        }
        Ok(Ok(tls)) => tls,
    };
    let peer_certs = tls.get_ref().1.peer_certificates().map(|c| c.to_vec());
    match peer_uri_san(peer_certs.as_deref(), expect, deployment_id) {
        Ok(peer_uri) => Ok(AuthenticatedStream {
            inner: TlsStream::Server(tls),
            peer_uri_san: peer_uri,
            peer_creds,
        }),
        // Recomputing the SAN post-handshake failed — the client-cert verifier already
        // accepted this leaf, so in practice this path is defense-in-depth, not a live
        // negative case; classify by the same rule as the live handshake-time check.
        Err(VaultError::PeerIdentity(_)) => Err(AcceptRejection {
            peer_creds: Some(peer_creds),
            reason: RejectReason::WrongPlane,
        }),
        Err(_) => Err(AcceptRejection {
            peer_creds: Some(peer_creds),
            reason: RejectReason::Handshake,
        }),
    }
}

/// Compose the two halves into a single accept — used by the in-crate transport test (and
/// any caller that does not need the anti-DoS split). A raw-accept / peer-cred failure maps
/// to `RejectReason::Io` (no creds captured yet).
#[cfg(test)]
pub(crate) async fn accept_on(
    listener: &tokio::net::UnixListener,
    acceptor: &TlsAcceptor,
    expect: Plane,
    deployment_id: &str,
    handshake_timeout: Duration,
) -> Result<AuthenticatedStream, AcceptRejection> {
    let (raw, peer_creds) = accept_raw_on(listener).await.map_err(|_| AcceptRejection {
        peer_creds: None,
        reason: RejectReason::Io,
    })?;
    finish_handshake_on(
        acceptor,
        expect,
        deployment_id,
        raw,
        peer_creds,
        handshake_timeout,
    )
    .await
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
