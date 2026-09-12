//! Socket acquisition (#240a D4-A, maintainer ruling: option b).
//!
//! The listening socket is created by the init system — a systemd `.socket`
//! with `SocketUser=_maknae-egress`, `SocketGroup=_maknae`, `SocketMode=0660`
//! — so there is no `chgrp`, no `CAP_CHOWN`, and no supplementary-group
//! workaround. The fd arrives through `LISTEN_FDS`.
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

/// The DEVELOPMENT path: bind a path ourselves.
///
/// Only reachable when the init system passed nothing. The shipped unit always
/// socket-activates, and a test asserts the packaged unit carries no bind path,
/// so this cannot become the production route by accident.
pub fn bind_path(p: &Path) -> Result<UnixListener, ListenError> {
    UnixListener::bind(p).map_err(|e| ListenError::Bind(format!("{}: {e}", p.display())))
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
    fn the_development_path_binds_and_reports_its_own_failures() {
        let d = tempfile::tempdir().unwrap();
        assert!(bind_path(&d.path().join("egress.sock")).is_ok());
        // Binding the same path twice fails, and the message names the path.
        let p = d.path().join("egress.sock");
        match bind_path(&p) {
            Err(ListenError::Bind(m)) => assert!(m.contains("egress.sock"), "{m}"),
            other => panic!("expected a bind failure, got {other:?}"),
        }
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
