//! maknaed — Maknae trust-plane daemon. Thin entrypoint: resolve the config directory
//! (default `/etc/maknae`, overridable by a positional argument) and hand off to
//! `maknae_kernel::run`, which owns the whole run-loop (FIPS assert → boot → audit sink
//! → plane credential → bind → accept loop → graceful shutdown) and returns the process
//! exit code. Fail-closed: any startup error → exit 1.
use std::process::ExitCode;

fn main() -> ExitCode {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/maknae".to_string());
    maknae_kernel::run(std::path::Path::new(&dir))
}
