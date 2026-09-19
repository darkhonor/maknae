//! What the three binaries refuse to inherit from their process environment,
//! and what they must never stop inheriting (#318).
//!
//! The deputy closed this class for itself in #240b, in
//! `bins/maknae-egress/src/env.rs`. #318 is the same class for the other two —
//! and the asymmetry WAS the bug: the least-trusted of the three processes was
//! the best protected, while `systemctl set-environment` and
//! `DefaultEnvironment=` (system.conf) reach every unit, and `sudo -E maknae
//! enroll` carries the operator's whole shell. The list lives here, in the
//! crate that builds every Vault client all three send through, so there is
//! one list rather than three copies — the `maknae-io` lesson applied to the
//! environment instead of to `open`.
//!
//! **Two lists, and the second one is the load-bearing half.** A scrub list on
//! its own is a footgun: several of the variables these binaries read ARE the
//! mechanism by which a shipped feature works, and scrubbing one would break it
//! *silently*. `CREDENTIALS_DIRECTORY` is the sealed SecretID systemd decrypts;
//! `LISTEN_FDS`/`LISTEN_PID`/`LISTEN_FDNAMES` carry the deputy's
//! socket-activated fd (read by `listenfd::ListenFd::from_env()` AFTER the
//! scrub runs); `XDG_RUNTIME_DIR` is how `systemd-creds --user` finds the
//! runtime directory in the enroll helper, which is itself a `maknae` process
//! and so runs this scrub; `MAKNAE_CONFIG_DIR` is documented operator workflow;
//! and `SUDO_UID`/`SUDO_USER` are the operator identity enroll provisions for.
//! So [`NEVER_SCRUB_ENV`] names every one of them with its reader, and a test
//! holds the two lists DISJOINT. That turns "remember not to add that one" into
//! a gate. The count is deliberately not stated here — an exact number in prose
//! is the thing that goes stale when the list grows.
//!
//! **What the scrub is worth, stated honestly, because the fix must not claim
//! more than it does** (measured 2026-09-19):
//!
//! * The **proxy** family decides where a connection goes, and it sits in the
//!   IDENTICAL position to the root-store pair below — measured, not assumed:
//!   reqwest defaults `auto_sys_proxy: true` and pushes `ProxyMatcher::system()`
//!   at build (reqwest 0.13.5 `async_impl/client.rs`), which reads the eight
//!   spellings through hyper-util's matcher. So the client vaultrs constructs
//!   DOES resolve an ambient proxy; the client that actually sends states
//!   `no_proxy()` (`http.rs`, and `maknae-llm`'s provider client likewise) and
//!   is not the one that read it. The scrub is the second line here, and the
//!   first line's guarantee is again "harden() ran", not "never read".
//!   (Round-3 review: this bullet had kept the un-corrected framing that the
//!   root-store bullet below had already been fixed twice for.)
//! * The **`VAULT_*`** family is the live half. `vaultrs 0.8.0` fills unset
//!   settings from the environment (`client.rs`'s `default_token`,
//!   `default_address`, `default_verify`, `default_ca_certs`,
//!   `default_identity`), and `harden()` replaces only the reqwest client — it
//!   keeps vaultrs's token middleware. An inherited `VAULT_TOKEN` therefore
//!   reaches the wire. It can never be a legitimate input: `AuthMethod` has
//!   exactly one variant, `AppRole` (`auth.rs`), and the only token-based path
//!   is the OPERATOR's own during `maknae enroll`, from `--token-file` or a
//!   no-echo prompt. So there is no workflow to preserve. Each constructor
//!   states its token rather than inheriting one: the two machine planes state
//!   `.token("")` (login supplies it), and enroll's states the operator's own
//!   token explicitly; all three state `.identity(None)`.
//! * **`SSL_CERT_FILE`/`SSL_CERT_DIR`** feed `rustls-native-certs`, which
//!   REPLACES (never extends) the root store it builds. **These two ARE read
//!   by `maknaed` and `maknae` on Linux, and an earlier version of this
//!   comment said they were not** — the correction is worth the words, because
//!   the reason it gave was wrong even though its conclusion was right.
//!   `VaultClient::new` does not use `tls_certs_only`: on an `https://`
//!   address vaultrs takes `tls_certs_merge` (vaultrs 0.8.0 `client.rs`), and
//!   reqwest routes a non-empty root set with `!tls_certs_only` into
//!   `rustls_platform_verifier::Verifier::new_with_extra_roots`
//!   (reqwest 0.13.5 `async_impl/client.rs`), whose constructor EAGERLY calls
//!   `rustls_native_certs::load_native_certs()` on unix-not-apple
//!   (rustls-platform-verifier 0.7.0 `verification/others.rs`). So the
//!   variables are read, at client construction, on Linux. (On macOS that cfg
//!   excludes the load and Apple's trust store is used instead, so they are
//!   not read there.)
//!
//!   **What makes them harmless anyway is a different fact:** `http.rs`'s
//!   `harden()` REPLACES `client.http` before any request is sent — at
//!   `client.rs`, `operator.rs` and `egress.rs` alike, each immediately after
//!   `VaultClient::new` — with a client pinned by `tls_certs_only`. The
//!   verifier that read the environment therefore never verifies a connection.
//!   That is a narrower guarantee than "not read": it holds only while every
//!   construction site is followed by `harden()`. The scrub is what keeps the
//!   property true if a site is ever added without it, or if one of these
//!   binaries gains a second TLS leg.
//!
//! **Two shipped surfaces have no init-system half at all**, which is why the
//! in-process scrub is not merely belt-and-braces. `UnsetEnvironment=` is a
//! systemd directive: launchd has no equivalent and cannot remove an inherited
//! variable, so on macOS — a production target (AGENTS.md) — the in-process
//! scrub IS the control, and `io.maknae.maknaed.plist` records that delta. The
//! `FROM scratch` OCI image (`packaging/oci/Dockerfile.maknaed`) runs `maknaed`
//! as PID 1 with no init system either, and container runtimes routinely inject
//! `HTTP_PROXY`.

/// Every variable removed before the first client is built. Pure data, so a
/// test can hold the list against the families it must cover and against the
/// shipped units that carry the same list at the init-system layer.
pub const SCRUBBED_ENV: &[&str] = &[
    // reqwest's ambient proxy set, both spellings it reads (hyper-util's
    // matcher). Decides WHERE a connection goes.
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    // vaultrs 0.8.0's settings defaults — the names its `client.rs` reads when
    // the corresponding setting is left unset.
    "VAULT_ADDR",
    "VAULT_TOKEN",
    "VAULT_SKIP_VERIFY",
    "VAULT_CACERT",
    "VAULT_CAPATH",
    "VAULT_CLIENT_CERT",
    "VAULT_CLIENT_KEY",
    // NOT read by vaultrs 0.8.0 (its `namespace` has a plain default); listed
    // so a future version that starts reading it cannot do so silently.
    "VAULT_NAMESPACE",
    // rustls-native-certs: either of these REPLACES the system trust store for
    // the platform verifier. READ by all three on Linux at client
    // construction, and neutralised on the Vault leg only because `harden()`
    // replaces that client before it sends — see the module docs, which
    // correct an earlier claim that they were not read at all. Live and
    // UNMEDIATED on the deputy's provider leg, where the consequence is the
    // sharp one: that leg uses the platform verifier for real, so an inherited
    // root turns an environment variable directly into the provider key in an
    // attacker's hands. (Restated here because the #240b module doc carrying
    // that sentence was deleted by #318's dedup — round-3 review caught the
    // loss.)
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// What the scrub must never remove, held DISJOINT from [`SCRUBBED_ENV`] by a
/// test. Pure data.
///
/// **Scope, stated precisely because a looser phrasing invites a wrong
/// addition:** every variable read by ANY workspace code that `maknaed`,
/// `maknae` or `maknae-egress` links — `LC_MESSAGES`/`LANG` live in
/// `maknae-msgs` and `HOSTNAME` in `maknae-kernel`, not in the binaries' own
/// source — PLUS every variable their CHILD processes need —
/// `XDG_RUNTIME_DIR` is here for the second reason only, since the enroll
/// helper's `systemd-creds --user` consumes it and the helper is itself a
/// `maknae` process running this scrub. The workspace's fourth binary,
/// `maknae-spifc`, is a scaffold stub that reads no environment and is not
/// covered. Runtime and loader variables (`RUST_BACKTRACE`, `LD_*`) are
/// deliberately absent: nothing here reads them and none is on the scrub list.
///
/// This is an inventory measured at one point in time (2026-09-19), not a
/// derived gate: nothing here scans the tree, so a NEW env read added later
/// will not appear by itself. It is written down because the alternative —
/// each agent rediscovering it — is what produced #318.
pub const NEVER_SCRUB_ENV: &[&str] = &[
    // THE MECHANISM, not a convenience: systemd decrypts the sealed SecretID
    // into this directory. `client.rs` (daemon) and `bins/maknae-egress/src/main.rs`
    // read it; without it the deputy refuses to start, by design.
    "CREDENTIALS_DIRECTORY",
    // Socket activation. `listenfd::ListenFd::from_env()` in
    // `bins/maknae-egress/src/listen.rs` reads these, and it runs AFTER the
    // scrub — so scrubbing one silently unmakes the deputy's inherited fd.
    "LISTEN_FDS",
    "LISTEN_PID",
    "LISTEN_FDNAMES",
    // Documented operator workflow (`docs/runbook.md`): relocates the CLI's
    // config directory. `bins/maknae/src/cli.rs`.
    "MAKNAE_CONFIG_DIR",
    // `systemd-creds --user` needs it to find the user's runtime directory, and
    // the enroll HELPER is itself a `maknae` process — so it runs this scrub.
    // The parent sets it explicitly for the child (`enroll/mod.rs` builds
    // `XDG_RUNTIME_DIR=/run/user/<uid>` rather than passing its own through),
    // which is exactly why removing it here would break the seal it was set for.
    "XDG_RUNTIME_DIR",
    // The CLI's config-dir fallback when MAKNAE_CONFIG_DIR is unset
    // (`cli.rs`). Note it falls back to "." when HOME itself is unset.
    "HOME",
    // The operator identity `maknae enroll` provisions FOR. `enroll/mod.rs`
    // reads both and `preflight_check` cross-validates them against passwd,
    // refusing on mismatch — this is the sudo contract, and removing either
    // would make every enroll fail `MissingSudoContext`.
    "SUDO_UID",
    "SUDO_USER",
    // Message locale for the CLI *and* the daemon (`maknae-msgs`'
    // `detect_locale`, which `maknae-kernel` links). Scrubbing these would
    // silently force en-US on an operator who chose ko-KR.
    "LC_MESSAGES",
    "LANG",
    // Chooses which binary the CLI plane's helpers actually are —
    // `systemd-creds`, `setfacl`, `apparmor_parser` and the rest are spawned by
    // BARE NAME, including on the CLI's credential-read path
    // (`secret_io.rs`). That is a defect, tracked as #327; the fix is to stop
    // depending on PATH, NOT to scrub it, which would break every helper.
    "PATH",
    // Read for the AU-3c host label (`maknae-kernel`'s `run.rs`), which is
    // documented non-security-load-bearing and falls back to "maknaed".
    // Usually not inherited at all: systemd does not export HOSTNAME to
    // services (it is a shell variable), so the fallback is what runs in a
    // default estate. That is NOT a guarantee — `DefaultEnvironment=` and
    // `systemctl set-environment` can set it, which is the very premise this
    // module rests on, and `run.rs` reads it straight into the AU-3c host
    // label. Kept because the label is correlation-only, never a decision
    // input. (Round-2 review struck a wrong reason from this comment:
    // ProtectHostname=yes gives a private UTS namespace and blocks
    // sethostname; it does nothing to the environment block.)
    "HOSTNAME",
];

/// The scrub, over an injected remover. Each `main` passes
/// `std::env::remove_var`, first thing, while the process is still
/// single-threaded (the CLI's `main` builds a multi-thread runtime, so
/// "before the runtime" is not a stylistic preference there). Injected so a
/// test can prove every listed name is passed to it WITHOUT mutating the test
/// binary's real environment — the setenv/getenv race is between a write and
/// ANY concurrent read, not only a read of the same name. There is
/// deliberately no zero-argument wrapper: one would be a production function
/// no test could execute safely.
pub fn scrub_with(mut remove: impl FnMut(&str)) {
    for k in SCRUBBED_ENV {
        remove(k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every family the scrub must cover, by NAME: a proxy variable in each
    /// spelling reqwest reads, every `vaultrs` env default that changes where a
    /// connection goes or how it is verified, and the two root-store variables.
    #[test]
    fn the_scrub_list_names_every_family_it_must_cover() {
        for must in [
            // reqwest's ambient proxy set, both spellings it reads.
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
            // vaultrs 0.8.0's settings defaults.
            "VAULT_ADDR",
            "VAULT_TOKEN",
            "VAULT_SKIP_VERIFY",
            "VAULT_CACERT",
            "VAULT_CAPATH",
            "VAULT_CLIENT_CERT",
            "VAULT_CLIENT_KEY",
            "VAULT_NAMESPACE",
            // rustls-native-certs: either REPLACES the system trust store.
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ] {
            assert!(SCRUBBED_ENV.contains(&must), "{must} must be scrubbed");
        }
    }

    /// The keep-list names every environment input the three binaries read, so
    /// the disjointness assertion below has something to protect. Each entry's
    /// reader is named in the const's own comments.
    #[test]
    fn the_never_scrub_list_names_every_environment_input_the_three_binaries_read() {
        for must in [
            "CREDENTIALS_DIRECTORY",
            "LISTEN_FDS",
            "LISTEN_PID",
            "LISTEN_FDNAMES",
            "MAKNAE_CONFIG_DIR",
            "XDG_RUNTIME_DIR",
            "HOME",
            "SUDO_UID",
            "SUDO_USER",
            "LC_MESSAGES",
            "LANG",
            "PATH",
            "HOSTNAME",
        ] {
            assert!(
                NEVER_SCRUB_ENV.contains(&must),
                "{must} is read by production code and must never be scrubbed"
            );
        }
    }

    /// THE gate this module exists for: a name cannot be on both lists. Adding
    /// `LISTEN_FDS` to the scrub list would break socket activation with no
    /// error anywhere — the deputy's scrub runs BEFORE `ListenFd::from_env()`.
    #[test]
    fn the_scrub_list_and_the_never_scrub_list_are_disjoint() {
        for k in SCRUBBED_ENV {
            assert!(
                !NEVER_SCRUB_ENV.contains(k),
                "{k} is on both lists: scrubbing it breaks a shipped mechanism"
            );
        }
    }

    /// Neither list repeats a name — a paste error in a list this long is
    /// otherwise invisible, and a duplicate would make the exactly-once
    /// assertion below lie. (No count is written here on purpose: the module
    /// doc gives the reason.)
    #[test]
    fn neither_list_repeats_a_name() {
        for list in [SCRUBBED_ENV, NEVER_SCRUB_ENV] {
            let mut seen: Vec<&&str> = list.iter().collect();
            seen.sort_unstable();
            let before = seen.len();
            seen.dedup();
            assert_eq!(before, seen.len(), "a name is listed twice");
        }
    }

    /// The scrub passes every listed name, once, to the remover — proven over
    /// an injected remover rather than the process environment.
    #[test]
    fn scrub_removes_every_listed_variable_exactly_once() {
        let mut removed: Vec<String> = vec![];
        scrub_with(|k| removed.push(k.to_string()));
        assert_eq!(removed.len(), SCRUBBED_ENV.len());
        for k in SCRUBBED_ENV {
            assert_eq!(removed.iter().filter(|r| r == k).count(), 1, "{k}");
        }
    }

    /// Both shipped units carry EXACTLY this list at the init-system layer, so
    /// adding a name here and forgetting either unit goes red in ONE place.
    /// Read from the shipped files. Every `UnsetEnvironment=` line is taken,
    /// not the first: a second one would otherwise be silently unchecked.
    #[test]
    fn both_shipped_units_unset_exactly_the_scrub_list() {
        for (name, unit) in [
            (
                "maknaed.service",
                include_str!("../../../packaging/common/maknaed.service"),
            ),
            (
                "maknae-egress.service",
                include_str!("../../../packaging/common/maknae-egress.service"),
            ),
        ] {
            // Only lines inside [Service] count: systemd IGNORES
            // UnsetEnvironment= under [Unit], so a misplaced directive would
            // otherwise satisfy this test while doing nothing on the host.
            let mut in_service = false;
            let mut in_unit: Vec<&str> = Vec::new();
            for raw in unit.lines() {
                let l = raw.trim();
                if l.starts_with('[') {
                    in_service = l == "[Service]";
                    continue;
                }
                if in_service {
                    if let Some(rest) = l.strip_prefix("UnsetEnvironment=") {
                        in_unit.extend(rest.split_whitespace());
                    }
                }
            }
            assert!(
                !in_unit.is_empty(),
                "{name} carries no UnsetEnvironment= line inside [Service]"
            );
            let mut here: Vec<&str> = SCRUBBED_ENV.to_vec();
            in_unit.sort_unstable();
            here.sort_unstable();
            assert_eq!(in_unit, here, "env.rs and {name} disagree");
        }
    }

    /// launchd has no `UnsetEnvironment=`, so the daemon's plist cannot carry
    /// the list — and that delta must be RECORDED rather than left as a silent
    /// platform gap on a production target. Pinned to the plist's own text so
    /// deleting the note goes red.
    #[test]
    fn the_daemon_plist_records_that_launchd_has_no_unset_equivalent() {
        let plist = include_str!("../../../packaging/macos/io.maknae.maknaed.plist");
        assert!(
            plist.contains("launchd has NO UnsetEnvironment= equivalent"),
            "the plist must record WHY the in-process scrub is the whole control \
             on darwin, not merely mention the directive somewhere (#318)"
        );
        assert!(
            !plist.contains("<key>EnvironmentVariables</key>"),
            "an EnvironmentVariables dict would hand launchd the inheritance the scrub removes"
        );
    }
}
