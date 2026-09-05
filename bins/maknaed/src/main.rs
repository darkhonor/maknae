//! maknaed — Maknae trust-plane daemon. Thin entrypoint: resolve the config directory
//! (default `/etc/maknae`, overridable by a positional argument) and hand off to
//! `maknae_kernel::run`, which owns the whole run-loop (FIPS assert → boot → audit sink
//! → authz gate → boot posture record → plane credential → bind → accept loop →
//! graceful shutdown) and returns the process exit code. Fail-closed: startup errors
//! exit non-zero, and two refusals carry their own distinct codes so a
//! supervision script can tell them apart without parsing stderr: a
//! capability-grant policy refusal (spec §5.4) exits **3**, and a configured
//! but unimplemented `audit.siem` (#189, tracked to #223) exits **4**. Every
//! other startup failure exits 1.
use std::process::ExitCode;

fn main() -> ExitCode {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/maknae".to_string());
    maknae_kernel::run(std::path::Path::new(&dir))
}
