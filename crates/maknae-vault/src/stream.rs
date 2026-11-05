//! PlaneListener / PlaneConnector / AuthenticatedStream (Layer 2 + Layer 1 glue, T3). The
//! transport REPORTS the authenticated channel peer + captured peer-creds; it does NOT
//! decide uid policy or emit audit (Boundary A — those are the Stage-3 daemon's).
use crate::peer_auth::{decide, PeerAuthRefusal};
use crate::peercred::{self, PeerCreds};
use crate::resolver::PlaneCertResolver;
use crate::{
    socket, tls, ChannelPeer, PeerAuth, Plane, PlaneClient, SanRule, TrustBundle, VaultError,
};
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
    /// `verify_uri_san` check — this crate's own decision, not rustls').
    WrongPlane,
    /// The peer's leaf was expired / not yet valid.
    ExpiredOrInvalidCert,
    /// The peer's chain did not validate against the pinned root (unknown issuer, bad
    /// signature, revoked).
    ChainOrCa,
    /// The peer presented a certificate on a channel class that requests none.
    UnexpectedClientCert,
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
/// `maknae_crypto::rustls::Error` as the io::Error's source (`io::Error::new(InvalidData, rustls_err)`), so
/// downcast to it when present. `maknae_crypto::rustls::Error` and `CertificateError` are `#[non_exhaustive]`
/// — an unmatched variant falls back to `Handshake` per the brief (WrongPlane is preserved
/// exactly because that's OUR OWN `SanIdentity` rejection, tagged by `PLANE_URI_SAN_PREFIX`).
fn classify_handshake_error(e: &std::io::Error) -> RejectReason {
    let Some(rustls_err) = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<maknae_crypto::rustls::Error>())
    else {
        return RejectReason::Handshake;
    };
    match rustls_err {
        maknae_crypto::rustls::Error::General(msg)
            if msg.starts_with(crate::peer_auth::PLANE_URI_SAN_PREFIX) =>
        {
            RejectReason::WrongPlane
        }
        maknae_crypto::rustls::Error::InvalidCertificate(cert_err) => match cert_err {
            maknae_crypto::rustls::CertificateError::Expired
            | maknae_crypto::rustls::CertificateError::ExpiredContext { .. }
            | maknae_crypto::rustls::CertificateError::NotValidYet
            | maknae_crypto::rustls::CertificateError::NotValidYetContext { .. } => {
                RejectReason::ExpiredOrInvalidCert
            }
            maknae_crypto::rustls::CertificateError::UnknownIssuer
            | maknae_crypto::rustls::CertificateError::BadSignature
            | maknae_crypto::rustls::CertificateError::Revoked
            | maknae_crypto::rustls::CertificateError::UnknownRevocationStatus
            | maknae_crypto::rustls::CertificateError::ExpiredRevocationList
            | maknae_crypto::rustls::CertificateError::ExpiredRevocationListContext { .. } => {
                RejectReason::ChainOrCa
            }
            _ => RejectReason::Handshake,
        },
        _ => RejectReason::Handshake,
    }
}

enum TlsStream {
    Server(tokio_rustls::server::TlsStream<maknae_plane::FdCollector>),
    Client(tokio_rustls::client::TlsStream<maknae_plane::FdSender>),
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

/// A connected plane channel, authenticated as its channel class requires.
pub struct AuthenticatedStream {
    inner: TlsStream,
    peer: ChannelPeer,
    peer_creds: PeerCreds,
    delegated: maknae_io::DelegatedFds,
    /// Present only on a CLIENT stream: the handle for arming the descriptor the next
    /// request carries. `None` server-side — delegation is one-directional.
    armer: Option<maknae_plane::FdArmer>,
}

impl AuthenticatedStream {
    pub fn peer(&self) -> &ChannelPeer {
        &self.peer
    }
    /// Kernel-captured peer credentials — the daemon polices `uid`.
    pub fn peer_creds(&self) -> &PeerCreds {
        &self.peer_creds
    }

    /// Descriptors this peer delegated over `SCM_RIGHTS`, collected BENEATH the TLS
    /// layer (ADR-0009). Empty on a client-side stream: delegation is one-directional.
    pub fn delegated(&self) -> maknae_io::DelegatedFds {
        self.delegated.clone()
    }

    /// Arm the descriptor the next request will carry (ADR-0009, client side).
    ///
    /// Available only on a connected CLIENT stream, and only AFTER the handshake —
    /// which is exactly when this is reachable, since the handshake produces the
    /// stream. Arming earlier would have let the handshake's own writes consume it.
    pub fn armer(&self) -> Option<maknae_plane::FdArmer> {
        self.armer.clone()
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

/// The one cert sink a `PlaneClient` backs, shared by every listener built over it.
pub struct ServerIdentity {
    resolver: Arc<PlaneCertResolver>,
    _sink_guard: crate::client::CertSinkGuard,
}

impl ServerIdentity {
    /// Attach this client's live leaf as the server certificate. A `PlaneClient` backs at
    /// most one `ServerIdentity`; a second attach returns `VaultError::SocketBind`.
    pub fn attach(client: &PlaneClient) -> Result<Arc<Self>, VaultError> {
        let resolver = Arc::new(PlaneCertResolver::new_empty());
        let sink_guard = client.attach_cert_sink(resolver.slot())?;
        Ok(Arc::new(Self {
            resolver,
            _sink_guard: sink_guard,
        }))
    }

    pub(crate) fn acceptor(
        &self,
        trust: &Arc<TrustBundle>,
        auth: &PeerAuth,
    ) -> Result<TlsAcceptor, VaultError> {
        acceptor_over(&self.resolver, trust, auth)
    }
}

fn acceptor_over(
    resolver: &Arc<PlaneCertResolver>,
    trust: &Arc<TrustBundle>,
    auth: &PeerAuth,
) -> Result<TlsAcceptor, VaultError> {
    tls::server_config(trust, auth, Arc::clone(resolver)).map(TlsAcceptor::from)
}

/// Daemon (server) side.
pub struct PlaneListener {
    listener: tokio::net::UnixListener,
    trust: Arc<TrustBundle>,
    auth: PeerAuth,
    /// The bound pathname socket — unlinked on drop (tokio/std `UnixListener` leaves it).
    path: std::path::PathBuf,
    identity: Arc<ServerIdentity>,
}

impl Drop for PlaneListener {
    fn drop(&mut self) {
        // Remove the pathname socket so a retired listener leaves no stale endpoint behind
        // (best-effort — bind_listener's stale-socket detection would also reclaim it).
        let _ = std::fs::remove_file(&self.path);
    }
}

impl PlaneListener {
    /// Bind a group-gated listener presenting `identity`'s live leaf and authenticating
    /// the peer as `auth` requires. Each handshake builds its acceptor from `trust` as it
    /// stands then, so a `TrustBundle::replace` applies from the next handshake.
    ///
    /// `group`, when `Some`, group-owns the bound socket's pathname (codex round-7 P1) so
    /// the 0660 mode actually gates on that group rather than the daemon process's PRIMARY
    /// group — see `socket::bind_listener`. The caller is expected to resolve the `maknae`
    /// gid and fail closed if it can't; `None` skips group-owning (tests / non-daemon binds).
    ///
    /// **Must be called from within a Tokio runtime** (it binds a `UnixListener`, which
    /// registers with the reactor and panics otherwise).
    pub fn bind(
        path: &Path,
        identity: Arc<ServerIdentity>,
        trust: Arc<TrustBundle>,
        auth: &PeerAuth,
        group: Option<nix::unistd::Gid>,
    ) -> Result<Self, VaultError> {
        identity.acceptor(&trust, auth)?;
        let listener = socket::bind_listener(path, group)?;
        Ok(Self {
            listener,
            trust,
            auth: auth.clone(),
            path: path.to_path_buf(),
            identity,
        })
    }

    /// Prompt half of accept (anti-DoS): do ONLY the `UnixListener::accept()` +
    /// `SO_PEERCRED`/`LOCAL_PEERCRED` capture — both fast syscalls — and return the raw
    /// stream with its peer-creds. NO TLS handshake happens here, so this cannot be stalled
    /// by a slow peer: the daemon's accept loop stays free to accept the next connection
    /// while the (bounded) handshake runs elsewhere, under the concurrency semaphore. Never
    /// `?` in the loop: see [`RawAcceptError`].
    pub async fn accept_raw(&self) -> Result<(RawPlaneConn, PeerCreds), RawAcceptError> {
        accept_raw_on(&self.listener).await
    }

    pub fn peer_auth(&self) -> &PeerAuth {
        &self.auth
    }

    /// Bounded half of accept (anti-DoS): complete the TLS server handshake within
    /// `handshake_timeout`, authenticate the peer as the listener's `PeerAuth` requires,
    /// and report it.
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
            &self.identity.resolver,
            &self.trust,
            &self.auth,
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
/// peer we cannot identify cannot be policed: the socket is dropped.
pub(crate) async fn accept_raw_on(
    listener: &tokio::net::UnixListener,
) -> Result<(RawPlaneConn, PeerCreds), RawAcceptError> {
    let (raw, _addr) = listener.accept().await.map_err(RawAcceptError::Accept)?;
    // Capture peer-creds BEFORE the handshake — so they're available to report even on a
    // handshake/SAN failure (the whole point of `AcceptRejection`).
    let peer_creds =
        peercred::capture(&raw).map_err(|e| RawAcceptError::PeerCreds(e.to_string()))?;
    Ok((RawPlaneConn(raw), peer_creds))
}

/// Why a raw accept produced no connection: the syscall itself, or a peer
/// whose credentials could not be captured (#265 A4 — the second is audited).
#[derive(Debug)]
pub enum RawAcceptError {
    Accept(std::io::Error),
    PeerCreds(String),
}

impl std::fmt::Display for RawAcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawAcceptError::Accept(e) => write!(f, "accept: {e}"),
            RawAcceptError::PeerCreds(e) => write!(f, "peer credentials: {e}"),
        }
    }
}

/// The bounded handshake half, factored out for the same testability reason as
/// `accept_raw_on`. Consumes the raw stream + its captured creds and produces the
/// authenticated stream (or an `AcceptRejection` carrying those creds).
pub(crate) async fn finish_handshake_on(
    resolver: &Arc<PlaneCertResolver>,
    trust: &Arc<TrustBundle>,
    auth: &PeerAuth,
    raw: RawPlaneConn,
    peer_creds: PeerCreds,
    handshake_timeout: Duration,
) -> Result<AuthenticatedStream, AcceptRejection> {
    let refuse = |peer_creds, reason| AcceptRejection {
        peer_creds: Some(peer_creds),
        reason,
    };
    let Ok(acceptor) = acceptor_over(resolver, trust, auth) else {
        return Err(refuse(peer_creds, RejectReason::Handshake));
    };
    // Interposed BEFORE the acceptor: rustls reads through this, and tokio's own
    // `read(2)` path would destroy every attached descriptor with no error at all.
    let collector = maknae_plane::FdCollector::new(raw.0, maknae_io::DELEGATED_FDS_PER_CONNECTION);
    let delegated = collector.delegated();
    let tls = match tokio::time::timeout(handshake_timeout, acceptor.accept(collector)).await {
        Err(_elapsed) => return Err(refuse(peer_creds, RejectReason::HandshakeTimeout)),
        Ok(Err(e)) => return Err(refuse(peer_creds, classify_handshake_error(&e))),
        Ok(Ok(tls)) => tls,
    };
    let reason = match decide(auth, tls.get_ref().1.peer_certificates()) {
        Ok(peer) => {
            return Ok(AuthenticatedStream {
                inner: TlsStream::Server(tls),
                peer,
                peer_creds,
                delegated,
                // Server-side: nothing to arm. The daemon never delegates outward.
                armer: None,
            });
        }
        Err(PeerAuthRefusal::UnexpectedClientCert) => RejectReason::UnexpectedClientCert,
        Err(PeerAuthRefusal::NoClientCert) => RejectReason::Handshake,
        Err(PeerAuthRefusal::San(_)) => RejectReason::WrongPlane,
    };
    Err(refuse(peer_creds, reason))
}

/// CLI (client) side.
pub struct PlaneConnector;

impl PlaneConnector {
    /// Connect and authenticate the daemon's kernel-plane leaf; report it.
    pub async fn connect(
        path: &Path,
        client: &PlaneClient,
        trust: &Arc<TrustBundle>,
    ) -> Result<AuthenticatedStream, VaultError> {
        let accept = SanRule::for_plane(Plane::Kernel, client.deployment_id());
        let cfg = tls::client_config(client, trust, accept.clone())?;
        let kernel = PeerAuth::PlaneLeaf { accept };
        let raw = socket::connect(path).await?;
        let peer_creds = peercred::capture(&raw)?;
        let name = maknae_crypto::rustls::pki_types::ServerName::try_from("maknae.invalid")
            .map_err(|e| VaultError::Handshake(format!("placeholder server name: {e}")))?;
        // Interposed BEFORE the connector, for the same reason the collector sits
        // beneath the acceptor: SCM_RIGHTS is ancillary data on the raw socket and
        // rustls can neither carry it nor see it.
        let sender = maknae_plane::FdSender::new(raw);
        let armer = sender.armer();
        let tls = TlsConnector::from(cfg)
            .connect(name, sender)
            .await
            .map_err(|e| VaultError::Handshake(e.to_string()))?;
        let peer = decide(&kernel, tls.get_ref().1.peer_certificates()).map_err(|r| match r {
            PeerAuthRefusal::San(e) => VaultError::PeerIdentity(e),
            PeerAuthRefusal::NoClientCert | PeerAuthRefusal::UnexpectedClientCert => {
                VaultError::Handshake("daemon presented no plane leaf".into())
            }
        })?;
        Ok(AuthenticatedStream {
            inner: TlsStream::Client(tls),
            peer,
            peer_creds,
            // Cap 0, not merely empty: delegation is one-directional (subject to
            // daemon), so a CLIENT-side stream can never legitimately receive a
            // descriptor. A queue that cannot hold one says so structurally.
            delegated: maknae_io::DelegatedFds::new(0),
            armer: Some(armer),
        })
    }
}

/// Compose the two halves into a single accept — used by the in-crate transport test (and
/// any caller that does not need the anti-DoS split). A raw-accept / peer-cred failure maps
/// to `RejectReason::Io` (no creds captured yet).
#[cfg(test)]
pub(crate) async fn accept_on(
    listener: &tokio::net::UnixListener,
    resolver: &Arc<PlaneCertResolver>,
    trust: &Arc<TrustBundle>,
    auth: &PeerAuth,
    handshake_timeout: Duration,
) -> Result<AuthenticatedStream, AcceptRejection> {
    let (raw, peer_creds) = accept_raw_on(listener).await.map_err(|_| AcceptRejection {
        peer_creds: None,
        reason: RejectReason::Io,
    })?;
    finish_handshake_on(resolver, trust, auth, raw, peer_creds, handshake_timeout).await
}
