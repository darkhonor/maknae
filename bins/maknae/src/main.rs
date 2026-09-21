//! maknae — Maknae CLI, untrusted interaction plane (spec §3). Thin entrypoint:
//! all logic lives in `cli::run_cli` (T3 — arg parse + orchestration, no
//! decision logic of its own).
mod agent;
mod cli;
mod enroll;
mod mutation;

use std::process::ExitCode;

fn main() -> ExitCode {
    // FIRST, and specifically before the runtime is built (#318):
    // `remove_var` is only sound while the process is single-threaded, and
    // building the multi-threaded runtime below ends that. `sudo -E maknae
    // enroll` carries the operator's whole shell, so this is the CLI's
    // in-process half — there is no init-system half for a user-invoked
    // binary at all. The names, and the
    // ones deliberately kept (MAKNAE_CONFIG_DIR, HOME, SUDO_*, LANG, PATH),
    // are `maknae_vault::{SCRUBBED_ENV, NEVER_SCRUB_ENV}`.
    maknae_vault::scrub_with(|k| std::env::remove_var(k));
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("maknae: cannot start runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(cli::run_cli());
    // A timed-out namespace syscall may still be running. Runtime teardown
    // must not wait forever for it; this does not imply cancellation or rollback.
    runtime.shutdown_timeout(std::time::Duration::ZERO);
    result
}

#[cfg(test)]
mod tests {
    /// The scrub runs BEFORE the tokio runtime is built (#318) — not a
    /// stylistic preference: `std::env::remove_var` is only sound while the
    /// process is single-threaded, and `new_multi_thread().build()` ends that.
    /// It also precedes `cli::run_cli`, which is what reaches a Vault client.
    /// Pinned by source order because a T3 `main` is not behaviourally
    /// reachable; the assertion names the WHOLE call site, remover included.
    #[test]
    fn main_scrubs_the_environment_before_the_runtime_and_the_cli() {
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
        // The FULL builder path, so a mention of the bare method name in a
        // comment cannot satisfy this (observed: the first version of this
        // test matched its own explanatory comment).
        let runtime = at("tokio::runtime::Builder::new_multi_thread");
        let cli = at("cli::run_cli()");
        assert!(
            scrub < runtime,
            "the scrub must precede the runtime build: remove_var needs a single-threaded process"
        );
        assert!(scrub < cli, "the scrub must precede any Vault client");
    }
}
