//! `maknae-agentd <id>` (#629): the enrolled agent's daemon. It logs in as the
//! agent, mints its plane leaf, and runs the task driver against the kernel's
//! agent socket until SIGTERM. Untrusted, as the CLI is: the kernel decides
//! every request it makes.
mod plane_impl;
mod shutdown;

use maknae_agent::task_driver::TaskDriver;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

const CONFIG_DIR: &str = "/etc/maknae";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let id = match plane_impl::agent_id(&args) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("maknae-agentd: {e}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("maknae-agentd: cannot start the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(run(id));
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("maknae-agentd: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(id: maknae_config::AgentId) -> Result<(), String> {
    use tokio::signal::unix::{signal, SignalKind};
    let (stop_tx, stop_rx) = shutdown::stop_signal();
    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        let _ = stop_tx.send(true);
    });

    maknae_crypto::init().map_err(|e| maknae_vault::crypto_refusal_message(&e))?;
    let config_dir = PathBuf::from(CONFIG_DIR);
    let cfg = maknae_config::load_agent_client(&config_dir, &id).map_err(|e| e.to_string())?;
    let enrollment =
        maknae_config::load_agent_enrollment(&config_dir, &id).map_err(|e| e.to_string())?;
    let euid = nix::unistd::geteuid().as_raw();
    if euid != enrollment.uid {
        return Err(format!(
            "agent {} is enrolled as uid {}; this process runs as uid {euid}",
            id.as_str(),
            enrollment.uid
        ));
    }
    let home = maknae_io::session_home()
        .ok_or("the agent account has no usable home directory in its passwd record")?;
    let home_text = home
        .to_str()
        .ok_or("the agent's home is not UTF-8")?
        .to_string();
    let driver_config = plane_impl::driver_config(&cfg, &home_text)?;
    let secret = maknae_vault::read_agent_secret(&id, enrollment.uid).map_err(|e| e.to_string())?;
    let login = plane_impl::login(&config_dir, &cfg)?;
    let client =
        Arc::new(maknae_vault::PlaneClient::for_agent(&login, secret).map_err(|e| e.to_string())?);
    let ca = maknae_vault::load_ca_pin(&config_dir).map_err(|e| e.to_string())?;
    let trust = maknae_vault::TrustBundle::from_pins(&[&ca]).map_err(|e| e.to_string())?;
    let seal_key = maknae_seal::SealPublicKey::from_pem(
        &maknae_vault::read_seal_pub_pem().map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("the Egress Daemon public key on this host is not usable: {e}"))?;
    if !plane_impl::mint_until_held(&*client, &stop_rx).await {
        return Ok(());
    }
    let assembly = plane_impl::Assembly {
        config_dir: &config_dir,
        cfg: &cfg,
        client: Arc::clone(&client),
        trust,
        seal_key,
        home,
        owner: enrollment.uid,
    };
    plane_impl::run_minted(client, serve(assembly, driver_config, stop_rx)).await
}

async fn serve(
    assembly: plane_impl::Assembly<'_>,
    driver_config: maknae_agent::task_driver::DriverConfig,
    stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let connected = plane_impl::connect(assembly)?;
    let mut driver = TaskDriver::new(
        connected.plane,
        shutdown::TokioClock::new(stop.clone()),
        driver_config,
    );
    let handle = driver.shutdown_handle();
    let ended = shutdown::run_until_drained(
        driver.run(),
        shutdown::stopped(stop),
        || handle.shut_down(),
        shutdown::AGENTD_EXCHANGE_DRAIN,
    )
    .await;
    if ended == shutdown::Ended::Abandoned {
        eprintln!(
            "maknae-agentd: the exchange in flight did not end within {}s; its task is reported at the next start",
            shutdown::AGENTD_EXCHANGE_DRAIN.as_secs()
        );
    }
    Ok(())
}
