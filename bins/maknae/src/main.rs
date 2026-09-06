//! maknae — Maknae CLI, untrusted interaction plane (spec §3). Thin entrypoint:
//! all logic lives in `cli::run_cli` (T3 — arg parse + orchestration, no
//! decision logic of its own).
mod cli;
mod enroll;
mod mutation;

use std::process::ExitCode;

fn main() -> ExitCode {
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
