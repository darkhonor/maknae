//! maknaed — Maknae trust-plane daemon. Thin entrypoint: resolve the config directory
//! (default `/etc/maknae`, overridable by a positional argument) and hand off to
//! `maknae_kernel::run`, which owns the whole run-loop (FIPS assert → boot → audit sink
//! → authz gate → boot posture record → plane credential → bind → accept loop →
//! graceful shutdown) and returns the process exit code. Fail-closed: startup errors
//! exit non-zero — a fail-closed capability-grant policy refusal (spec §5.4) exits with its
//! own distinct code (3), every other startup failure exits 1.
use std::process::ExitCode;

fn main() -> ExitCode {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/maknae".to_string());
    maknae_kernel::run(std::path::Path::new(&dir))
}
