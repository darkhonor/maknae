//! `maknae-egress` — the egress deputy (#240a).
//!
//! The only process with a route out, running as `_maknae-egress` under its
//! own Vault policy. It holds a credential and a socket and nothing else: no
//! policy, no provider registry, no identity map, no audit sink. It never
//! learns WHO the subject is — the kernel decided that long before the frame
//! existed — and it never originates a call of its own.
//!
//! Thin by design (T3, the `bins/maknaed` precedent): the decision is in
//! `handle`, the I/O in `serve`, the socket in `listen`.

mod handle;
mod listen;
mod serve;

use std::path::PathBuf;

const BOUNDS_PATH: &str = "/etc/maknae/egress-bounds.yaml";
/// The account the kernel runs as. The deputy speaks to nobody else.
const KERNEL_USER: &str = "_maknae";

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("maknae-egress: refusing to start: {msg}");
    std::process::exit(1)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut bind: Option<PathBuf> = None;
    let mut bounds_path = PathBuf::from(BOUNDS_PATH);
    while let Some(a) = args.next() {
        match a.as_str() {
            // Development only. The shipped unit socket-activates and passes
            // no bind path; a packaging test asserts that.
            "--bind" => bind = args.next().map(PathBuf::from),
            "--bounds" => bounds_path = args.next().map(PathBuf::from).unwrap_or(bounds_path),
            other => fail(format!("unknown argument '{other}'")),
        }
    }

    let bounds = match maknae_config::load_egress_bounds(&bounds_path) {
        Ok(b) => b,
        Err(e) => fail(format!("{}: {e}", bounds_path.display())),
    };

    // Resolved ONCE, at startup, fail-closed. Never per request: a name lookup
    // on the serving path is the hazard the group-lookup circuit breaker
    // exists to prevent.
    let expected_uid = match nix::unistd::User::from_name(KERNEL_USER) {
        Ok(Some(u)) => u.uid.as_raw(),
        Ok(None) => fail(format!("no such account '{KERNEL_USER}'")),
        Err(e) => fail(format!("cannot resolve '{KERNEL_USER}': {e}")),
    };

    let listener = match listen::from_init_system() {
        Ok(Some(l)) => l,
        Ok(None) => match bind {
            Some(p) => match listen::bind_path(&p) {
                Ok(l) => l,
                Err(e) => fail(e),
            },
            None => fail("no socket from the init system and no --bind path"),
        },
        Err(e) => fail(e),
    };

    // Accept forever. A failed connection is refused and the loop continues:
    // one bad or hostile peer must not take the deputy down. This is wiring,
    // not logic — the decision is `handle::decide`, the per-connection I/O is
    // `serve::serve_one`, and both are tested.
    for conn in listener.incoming() {
        match conn {
            Ok(s) => {
                if let Err(e) = serve::serve_one(s, expected_uid, &bounds) {
                    eprintln!("maknae-egress: connection refused: {e:?}");
                }
            }
            Err(e) => eprintln!("maknae-egress: accept failed: {e}"),
        }
    }
}
