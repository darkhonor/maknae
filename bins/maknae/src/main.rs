//! maknae — Maknae CLI, untrusted interaction plane (spec §3). Thin entrypoint:
//! all logic lives in `cli::run_cli` (T3 — arg parse + orchestration, no
//! decision logic of its own).
mod cli;

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    cli::run_cli().await
}
