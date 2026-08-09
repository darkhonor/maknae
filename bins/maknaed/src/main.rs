//! maknaed — Maknae trust-plane daemon. Boots by loading Maknae's config directory
//! (default `/etc/maknae`, overridable by a positional argument), reading the core
//! ceiling into the ingest posture, and refusing to start (exit 1) on any error.
//! No run loop yet — a successful boot exits 0 (boot-check).
fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/maknae".to_string());
    match maknae_kernel::boot(std::path::Path::new(&dir)) {
        Ok(cfg) => {
            println!("maknaed: booted; ingest posture = {:?}", cfg.ingest_posture());
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("maknaed: refusing to start: {e}");
            std::process::exit(1);
        }
    }
}
