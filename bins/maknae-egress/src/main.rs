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

mod call;
mod handle;
mod keys;
mod keys_vault;
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

    // FIRST, before any client exists: the process-default CryptoProvider.
    // `maknae-llm` and `maknae-vault` both assert `.fips()` at the moment a
    // credential rides TLS; without this install every call would refuse.
    // The same ordering as `maknae_kernel::run`.
    maknae_vault::install_default_crypto_provider();
    if let Err(e) = maknae_vault::assert_fips_provider() {
        fail(e);
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

    // The third plane's credential (#240b): the RoleID and the Vault CA sit
    // beside the bounds file under `egress/`, the SecretID comes from
    // $CREDENTIALS_DIRECTORY (the unit's LoadCredentialEncrypted=). Resolved
    // ONCE, fail-closed, and the SecretID is `Zeroizing` from the read. The
    // AppRole mount defaults to the packaged Terraform's, resolved HERE rather
    // than in the config crate so there is one place for that default.
    let egress_dir = bounds_path
        .parent()
        .map(|p| p.join("egress"))
        .unwrap_or_else(|| PathBuf::from("/etc/maknae/egress"));
    let approle_mount = bounds
        .approle_mount
        .clone()
        .unwrap_or_else(|| maknae_vault::DEFAULT_APPROLE_MOUNT.to_string());
    let auth = match maknae_vault::load_egress_auth(
        &egress_dir,
        approle_mount,
        std::env::var("CREDENTIALS_DIRECTORY").ok().as_deref(),
    ) {
        Ok(a) => a,
        Err(e) => fail(format!("egress credential: {e}")),
    };
    let vault = match maknae_vault::EgressVault::new(
        &bounds.vault_addr,
        &egress_dir.join(maknae_vault::EGRESS_VAULT_CA_FILE),
        auth,
    ) {
        Ok(v) => v,
        Err(e) => fail(format!("vault client: {e}")),
    };

    // One current-thread runtime for the process: the provider call and the
    // Vault read are futures, and the serving path is otherwise blocking.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => fail(format!("cannot start a runtime: {e}")),
    };

    // Boot probe BEFORE the listener is adopted: one login and one revoke. A
    // wrong SecretID, or a Vault the deputy cannot reach, refuses START — not
    // the first live request (the same preference the kernel's bounds boot
    // gate records) — and refuses it before the listener is adopted, so the
    // connections already queued on the activation socket are not accepted
    // and dropped by a process that is about to exit.
    if let Err(e) = rt.block_on(vault.probe_login()) {
        fail(format!("vault login probe: {e}"));
    }

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

    // ONE cache for the PROCESS, outside the accept loop.
    //
    // Reviewed finding (#296): this was constructed inside the per-connection
    // closure, which gave "read on first use, cached per destination" a lifetime
    // of exactly one request — every prompt would have re-read Vault and then
    // dropped the entry. The unit test passed because IT held a cache across
    // calls; the deputy never did. A cache the production path rebuilds per
    // request is not a cache.
    //
    // CONCURRENCY MODEL, stated because a shared mutable cache needs one: the
    // accept loop is SEQUENTIAL — `incoming()` yields one connection at a time
    // and each is served to completion before the next is accepted — so access
    // is serialized by construction and needs no lock. If the deputy ever serves
    // connections concurrently, this becomes shared state and must gain one;
    // the `&mut` borrow here is what will force that decision rather than
    // letting it pass silently.
    let mut keys = keys::KeyCache::new(keys_vault::VaultKeys { vault });

    // Accept forever. A failed connection is refused and the loop continues:
    // one bad or hostile peer must not take the deputy down. This is wiring,
    // not logic — the decision is `handle::decide`, the per-connection I/O is
    // `serve::serve_one`, and both are tested.
    for conn in listener.incoming() {
        match conn {
            Ok(s) => {
                if let Err(e) = serve::serve_one(s, expected_uid, &bounds, |admitted| {
                    // The real fulfilment path: the key is read through the
                    // cache on first use per destination (#240b), then the
                    // provider call is made under the FIPS provider installed
                    // above.
                    rt.block_on(call::fulfil(
                        admitted,
                        &mut keys,
                        &[],
                        call::CallBounds::default(),
                        // #308: the KV mount, from the deputy's own bounds
                        // document — the only place it is declared, because the
                        // deputy is the only component in the tree that reads KV.
                        &bounds.kv_mount,
                    ))
                    .map_err(|e| serve::ServeError::Fulfil(e.to_string()))
                }) {
                    eprintln!("maknae-egress: connection refused: {e:?}");
                }
            }
            Err(e) => eprintln!("maknae-egress: accept failed: {e}"),
        }
    }
}
