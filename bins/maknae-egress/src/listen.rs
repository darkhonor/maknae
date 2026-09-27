//! Socket acquisition (#240a D4-A, maintainer ruling: option b).
//!
//! On Linux the socket is created by a systemd `.socket` (`SocketGroup=_maknae`,
//! `SocketMode=0660`) and arrives through `LISTEN_FDS`. On macOS the deputy binds
//! it itself; see [`bind_gated`].
//!
//! Adopting an inherited fd needs `unsafe`, which `[workspace.lints.rust]
//! unsafe_code = "forbid"` denies and an in-crate `#[allow]` cannot lift.
//! `forbid` is per-crate, so the adoption lives in a vetted dependency that
//! hands back an owned `UnixListener`.

use std::os::unix::net::UnixListener;
use std::path::Path;

#[derive(Debug)]
pub enum ListenError {
    NoSocket(String),
    Bind(String),
}

impl std::fmt::Display for ListenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListenError::NoSocket(m) => write!(f, "no listening socket: {m}"),
            ListenError::Bind(m) => write!(f, "cannot bind: {m}"),
        }
    }
}

/// Take the socket the init system passed us.
pub fn from_init_system() -> Result<Option<UnixListener>, ListenError> {
    let mut fds = listenfd::ListenFd::from_env();
    match fds.take_unix_listener(0) {
        Ok(Some(l)) => Ok(Some(l)),
        Ok(None) => Ok(None),
        Err(e) => Err(ListenError::NoSocket(e.to_string())),
    }
}

/// Bind a path ourselves, group-gated through `maknae-vault`'s shared UDS
/// bind. Only reachable when the init system passed nothing. The shipped
/// Linux unit always socket-activates, and a test asserts the packaged unit
/// carries no bind path; on macOS this is the launchd job's only path, since
/// launchd's socket hand-off is a C API (`launch_activate_socket`).
pub fn bind_gated(
    rt: &tokio::runtime::Runtime,
    path: &Path,
    group: nix::unistd::Gid,
) -> Result<UnixListener, ListenError> {
    let bind = |e: String| ListenError::Bind(format!("{}: {e}", path.display()));
    let l = rt
        .block_on(async { maknae_vault::bind_group_gated_uds(path, Some(group)) })
        .map_err(|e| bind(e.to_string()))?
        .into_std()
        .map_err(|e| bind(e.to_string()))?;
    l.set_nonblocking(false).map_err(|e| bind(e.to_string()))?;
    Ok(l)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With no `LISTEN_FDS` in the environment there is no inherited socket,
    /// and that is `Ok(None)` — an absence to fall back from, never an error
    /// and never a silent success.
    #[test]
    fn an_absent_listen_fds_is_a_named_absence() {
        assert!(matches!(from_init_system(), Ok(None)));
    }

    #[test]
    fn a_bound_socket_is_group_gated() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // A group the socket is NOT born with (egid on Linux, the dir's on
        // macOS), so the gid assertion fails if the chown is dropped.
        let born = [
            nix::unistd::getegid().as_raw(),
            std::os::unix::fs::MetadataExt::gid(&std::fs::metadata(d.path()).unwrap()),
        ];
        // `id -G`: nix's `getgroups` is configured out on Apple targets.
        let ids = std::process::Command::new("id").arg("-G").output().unwrap();
        let gid = String::from_utf8(ids.stdout)
            .unwrap()
            .split_whitespace()
            .filter_map(|g| g.parse::<u32>().ok())
            .find(|g| !born.contains(g))
            .map_or_else(nix::unistd::getegid, nix::unistd::Gid::from_raw);
        let p = d.path().join("egress.sock");
        let _l = bind_gated(&rt, &p, gid).unwrap();
        let meta = std::fs::metadata(&p).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o660);
        assert_eq!(std::os::unix::fs::MetadataExt::gid(&meta), gid.as_raw());
        match bind_gated(&rt, &d.path().join("nope").join("egress.sock"), gid) {
            Err(ListenError::Bind(m)) => assert!(m.contains("cannot stat"), "{m}"),
            other => panic!("expected a parent-directory refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_group_writable_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(matches!(
            bind_gated(&rt, &d.path().join("egress.sock"), nix::unistd::getegid()),
            Err(ListenError::Bind(_))
        ));
    }

    /// Both error shapes render something an operator can act on — these
    /// strings reach the journal when the deputy refuses to start.
    #[test]
    fn both_error_shapes_render_actionably() {
        assert!(ListenError::NoSocket("bad fd".into())
            .to_string()
            .contains("no listening socket"));
        assert!(ListenError::Bind("/run/x: denied".into())
            .to_string()
            .contains("cannot bind"));
    }
}
