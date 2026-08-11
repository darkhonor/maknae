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
            // Probe liveness before unlinking: a successful connect means a daemon is
            // already serving this path → refuse (do NOT steal it out from under a live
            // listener). Only `ConnectionRefused` (no listener accepting) proves the socket
            // is stale and safe to remove; any other probe error fails closed.
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => {
                    return Err(VaultError::SocketBind(format!(
                        "{} is already served by a live listener",
                        path.display()
                    )));
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(path)
                        .map_err(|e| VaultError::SocketBind(format!("stale socket unlink: {e}")))?;
                }
                Err(e) => {
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
