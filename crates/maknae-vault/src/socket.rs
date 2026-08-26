//! Pathname Unix-domain-socket binding + connect (Layer 2, T3). The socket is the OUTER
//! fence only (mTLS + peer-creds are the real gate); provisioning is hardened against the
//! Docker-adjacent path/perm race class: verify the parent dir is owner-only before bind,
//! set 0660 atomically, and never blindly unlink an attacker-influenceable stale socket.
use crate::VaultError;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;

/// Refuse a UDS whose parent directory is group/other-writable or not owned by us —
/// an attacker who can write the dir could pre-create/swap the socket path.
fn verify_parent_dir(path: &Path) -> Result<(), VaultError> {
    let dir = path.parent().ok_or_else(|| VaultError::InsecureSocketDir {
        path: path.to_path_buf(),
        detail: "socket path has no parent directory".into(),
    })?;
    let meta = std::fs::metadata(dir).map_err(|e| VaultError::InsecureSocketDir {
        path: dir.to_path_buf(),
        detail: format!("cannot stat: {e}"),
    })?;
    if meta.uid() != nix::unistd::geteuid().as_raw() {
        return Err(VaultError::InsecureSocketDir {
            path: dir.to_path_buf(),
            detail: format!("owned by uid {} not us", meta.uid()),
        });
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(VaultError::InsecureSocketDir {
            path: dir.to_path_buf(),
            detail: format!("mode {mode:o} is group/other-writable"),
        });
    }
    Ok(())
}

/// Bind a group-gated (0660) listener. Fail-closed if the parent dir is unsafe. A stale
/// socket is removed ONLY if it is actually a socket AND the dir was verified owner-only
/// above (so an attacker cannot have planted it); otherwise bind surfaces the error.
///
/// `group`, when `Some`, group-owns the freshly bound socket's pathname entry (codex
/// round-7 P1): under a service account whose PRIMARY group isn't `maknae` (the
/// normal production setup — `maknae` is a supplementary group), a bare bind leaves the
/// 0660 socket group-owned by the wrong group, so authorized `maknae`-group peers get
/// permission-denied at the socket layer before mTLS/`uid_in_maknae_group` ever runs. The
/// caller resolves the gid and fails closed if it can't (see
/// `maknae-kernel::groupres::maknae_gid`); `None` is for callers that don't need the
/// group-gate to actually gate (tests, the CLI-side connector never binds).
///
/// **Must be called from within a Tokio runtime** — `tokio::net::UnixListener::bind`
/// registers with the reactor and panics ("there is no reactor running") otherwise.
pub(crate) fn bind_listener(
    path: &Path,
    group: Option<nix::unistd::Gid>,
) -> Result<tokio::net::UnixListener, VaultError> {
    verify_parent_dir(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            // Probe liveness before unlinking: a STABLE successful connect means a daemon
            // is already serving this path → refuse (do NOT steal it out from under a
            // live listener). `ConnectionRefused` proves the socket is stale and safe to
            // remove; any other probe error fails closed. See `classify_stale_probe` for
            // why a single successful connect is NOT trusted (#125).
            let verdict = classify_stale_probe(
                || std::os::unix::net::UnixStream::connect(path).map(drop),
                || std::thread::sleep(PROBE_SETTLE),
            );
            match verdict {
                ProbeVerdict::Live => {
                    return Err(VaultError::SocketBind(format!(
                        "{} is already served by a live listener",
                        path.display()
                    )));
                }
                ProbeVerdict::Stale => {
                    std::fs::remove_file(path)
                        .map_err(|e| VaultError::SocketBind(format!("stale socket unlink: {e}")))?;
                }
                ProbeVerdict::FailClosed(e) => {
                    return Err(VaultError::SocketBind(format!(
                        "probing {}: {e}",
                        path.display()
                    )));
                }
            }
        }
        Ok(_) => {
            return Err(VaultError::SocketBind(format!(
                "{} exists and is not a socket — refusing to remove",
                path.display()
            )));
        }
        Err(_) => {} // absent — normal
    }
    let listener =
        tokio::net::UnixListener::bind(path).map_err(|e| VaultError::SocketBind(e.to_string()))?;
    // Group-own immediately after bind, before the chmod below — minimizes the insecure
    // window (the parent dir is already owner-only, so nothing outside us can race the
    // path in between regardless). Path-based `chown`, not `fchown` on the bound fd: a
    // bound `UnixListener`'s fd is a socket, not a regular-file fd, and `fchown` on it
    // returns `EINVAL` on at least macOS/BSD — `chown` on the pathname is the portable
    // way to set ownership on a UDS's filesystem entry.
    // On any post-bind setup failure below, unlink the pathname we just created before
    // erroring: dropping a `UnixListener` does NOT unlink its filesystem entry, and a
    // failed startup must not leave a stale socket behind (the next bind's liveness
    // probe would reclaim it, but tooling/clients in between would see a dead socket).
    let cleanup = |e: VaultError| {
        let _ = std::fs::remove_file(path);
        e
    };
    if let Some(gid) = group {
        nix::unistd::chown(path, None, Some(gid)).map_err(|e| {
            cleanup(VaultError::SocketGroupOwn(format!(
                "chown group {gid}: {e}"
            )))
        })?;
    }
    // Atomic-enough: set 0660 immediately after bind (the parent dir is already owner-only,
    // so there is no window a non-group process could connect through).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| cleanup(VaultError::SocketBind(format!("chmod 0660: {e}"))))?;
    Ok(listener)
}

/// How long a first successful probe must remain answerable before it counts as a live
/// listener. The #125 window (below) was measured self-healing within single-digit
/// milliseconds on a loaded machine; 100ms gives >20× margin. Startup-only cost, and
/// only paid on the anomalous Ok path — the common cases (absent path, refused probe)
/// never sleep.
const PROBE_SETTLE: std::time::Duration = std::time::Duration::from_millis(100);

/// The stale-socket probe verdict (issue #125).
///
/// A SINGLE successful `connect()` is not proof of a live listener: on macOS, `close()`
/// of a listening UDS can return before the kernel fully disassociates the listening
/// pcb from the socket's vnode, and under heavy multi-process unix-socket load a
/// `connect()` landing in that window returns `Ok` against a socket that is already
/// dead — instrumented on #125: the probe's `Ok` was followed, milliseconds later, by
/// unbroken `ECONNREFUSED` (3/3), with the binding process's own fd table clean and no
/// other holder of the socket. A daemon restarting after an unclean shutdown could hit
/// its own stale socket in that window and refuse to start — an availability failure.
///
/// So: an `Ok` first probe is confirmed by a settle delay + re-probe. A live daemon
/// answers both probes (→ `Live`, refuse to bind); the transient window has died by the
/// re-probe (→ `Stale`, reclaim). The asymmetry is deliberate and fail-closed both
/// ways: we never reclaim a path that ANSWERED the second probe, and any error other
/// than `ConnectionRefused` on either probe is `FailClosed`, never `Stale`.
enum ProbeVerdict {
    Live,
    Stale,
    FailClosed(String),
}

fn classify_stale_probe(
    mut probe: impl FnMut() -> std::io::Result<()>,
    settle: impl Fn(),
) -> ProbeVerdict {
    match probe() {
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => ProbeVerdict::Stale,
        Err(e) => ProbeVerdict::FailClosed(e.to_string()),
        Ok(()) => {
            settle();
            match probe() {
                Ok(()) => ProbeVerdict::Live,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => ProbeVerdict::Stale,
                Err(e) => ProbeVerdict::FailClosed(e.to_string()),
            }
        }
    }
}

/// Connect to a plane socket.
pub(crate) async fn connect(path: &Path) -> Result<tokio::net::UnixStream, VaultError> {
    tokio::net::UnixStream::connect(path)
        .await
        .map_err(|e| VaultError::SocketBind(format!("connect {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmpdir(tag: &str, mode: u32) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("mv-sock-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    // ---- #125: the stale-probe classifier over an injected prober ----
    //
    // The macOS kernel window (a listening UDS answers connect() for a few
    // hundred µs–ms after close() under multi-process unix-socket load) cannot
    // be summoned deterministically, so the classifier is tested through the
    // prober seam with scripted sequences. The real-connect paths are covered
    // by `refuses_binding_over_a_live_listener` / `removes_a_stale_socket_and_binds`.

    fn scripted(
        seq: Vec<std::io::Result<()>>,
    ) -> (
        impl FnMut() -> std::io::Result<()>,
        std::rc::Rc<std::cell::Cell<usize>>,
    ) {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let c = calls.clone();
        let mut it = seq.into_iter();
        (
            move || {
                c.set(c.get() + 1);
                it.next().expect("prober called more times than scripted")
            },
            calls,
        )
    }

    fn refused() -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
    }

    #[test]
    fn probe_ok_then_refused_is_stale_the_125_window() {
        // The #125 flake shape: first connect lands in the post-close kernel
        // window (Ok), the settle delay outlives the window, re-probe refuses.
        let (probe, calls) = scripted(vec![Ok(()), refused()]);
        assert!(matches!(
            classify_stale_probe(probe, || ()),
            ProbeVerdict::Stale
        ));
        assert_eq!(
            calls.get(),
            2,
            "an Ok probe must be confirmed by a re-probe"
        );
    }

    #[test]
    fn probe_ok_twice_is_live() {
        let (probe, calls) = scripted(vec![Ok(()), Ok(())]);
        assert!(matches!(
            classify_stale_probe(probe, || ()),
            ProbeVerdict::Live
        ));
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn probe_refused_is_stale_without_a_second_probe() {
        let (probe, calls) = scripted(vec![refused()]);
        assert!(matches!(
            classify_stale_probe(probe, || ()),
            ProbeVerdict::Stale
        ));
        assert_eq!(
            calls.get(),
            1,
            "a refused first probe needs no settle/re-probe"
        );
    }

    #[test]
    fn probe_other_error_fails_closed() {
        let (probe, _) = scripted(vec![Err(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        ))]);
        assert!(matches!(
            classify_stale_probe(probe, || ()),
            ProbeVerdict::FailClosed(_)
        ));
    }

    #[test]
    fn probe_ok_then_other_error_fails_closed() {
        let (probe, _) = scripted(vec![
            Ok(()),
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        ]);
        assert!(matches!(
            classify_stale_probe(probe, || ()),
            ProbeVerdict::FailClosed(_)
        ));
    }

    #[test]
    fn refuses_group_other_writable_parent_dir() {
        let dir = tmpdir("open", 0o777); // group/other-writable → unsafe
        let sock = dir.join("s.sock");
        assert!(matches!(
            bind_listener(&sock, None),
            Err(VaultError::InsecureSocketDir { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn binds_and_sets_0660_in_safe_dir() {
        let dir = tmpdir("safe", 0o700);
        let sock = dir.join("s.sock");
        let _l = bind_listener(&sock, None).expect("bind in a 0700 dir");
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "socket must be group-gated 0660");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The codex round-7 P1 fix: `Some(gid)` group-owns the bound socket, so the 0660 mode
    /// actually gates on the resolved group — not whatever the daemon process's primary
    /// group happens to be. No `maknae` group exists on this dev host, so this exercises
    /// the underlying mechanism against the current process's own gid (always resolvable,
    /// no fixture/root dependency).
    #[tokio::test]
    async fn binds_and_group_owns_when_group_is_given() {
        let dir = tmpdir("group-own", 0o700);
        let sock = dir.join("s.sock");
        let gid = nix::unistd::getgid();
        let _l = bind_listener(&sock, Some(gid)).expect("bind + group-own in a 0700 dir");
        let meta = std::fs::metadata(&sock).unwrap();
        assert_eq!(
            meta.gid(),
            gid.as_raw(),
            "socket must be group-owned by the resolved gid"
        );
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "socket must still be group-gated 0660");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn refuses_to_replace_a_live_socket() {
        let dir = tmpdir("live", 0o700);
        let sock = dir.join("s.sock");
        let _live = std::os::unix::net::UnixListener::bind(&sock).unwrap(); // live listener
        assert!(matches!(
            bind_listener(&sock, None),
            Err(VaultError::SocketBind(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn removes_a_stale_socket_and_binds() {
        let dir = tmpdir("stale", 0o700);
        let sock = dir.join("s.sock");
        {
            // std UnixListener does NOT unlink on drop → leaves a stale socket file.
            let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        }
        assert!(sock.exists(), "stale socket file remains after drop");
        let _l =
            bind_listener(&sock, None).expect("stale socket detected + removed, bind succeeds");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
