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
    // FIRST, before anything else reads the environment or spawns a thread
    // (#318): the unit's environment is not clean — `DefaultEnvironment=` and
    // `systemctl set-environment` reach every service — and `remove_var` is
    // only sound while the process is single-threaded. On macOS this is the
    // WHOLE control: launchd has no `UnsetEnvironment=`. The names, and the
    // ones deliberately kept, are `maknae_vault::{SCRUBBED_ENV,
    // NEVER_SCRUB_ENV}`; `maknaed.service` carries the same list.
    maknae_vault::scrub_with(|k| std::env::remove_var(k));
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/maknae".to_string());
    maknae_kernel::run(std::path::Path::new(&dir))
}

#[cfg(test)]
mod tests {
    /// The scrub runs BEFORE the kernel does anything (#318). A behavioural
    /// test cannot reach a T3 `main`, so the ordering is pinned by source order
    /// — the same treatment the deputy's `main` and the kernel's
    /// gate-before-mint get. The assertion names the WHOLE call site, remover
    /// included: `scrub_with(|_| {})` would otherwise keep this green while the
    /// daemon inherited `VAULT_TOKEN` again.
    #[test]
    fn main_scrubs_the_environment_before_the_kernel_runs() {
        let src = include_str!("main.rs");
        let at = |needle: &str| {
            src.find(needle)
                .unwrap_or_else(|| panic!("{needle} not in main.rs"))
        };
        // Split so this literal is NOT itself findable in main.rs: the test
        // source is part of the file it scans, and a contiguous needle here
        // would match the TEST rather than the call site (observed while
        // writing this test — it failed on its own text).
        let scrub = at(concat!(
            "maknae_vault::scrub_with(|k| ",
            "std::env::remove_var(k))"
        ));
        let run = at("maknae_kernel::run(");
        assert!(
            scrub < run,
            "the scrub must precede the kernel: remove_var is only sound while single-threaded"
        );
    }
}
