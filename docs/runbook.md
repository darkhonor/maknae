# Maknae runbook

Operator-facing procedures for standing up and evaluating Maknae capabilities. Grown
per implementation stage.

---

## Chapter 1 — Mint a plane cert (`maknae-vault` Stage 1)

Prove the plane-cert client authenticates to your Vault and mints a memory-only
`maknae://<deployment_id>/plane/kernel` EC P-384 leaf. This is the first live milestone;
the daemon + CLI round-trip arrives in later stages.

### Prerequisites

- The Vault PKI is applied (`deploy/vault-pki/`) and your Vault is reachable.
- `aws-lc-rs` FIPS builds on the host (verified on macOS/aarch64 and Linux).

### 1. Lay out the config dir

Pick a config dir — dev on your workstation: `~/.maknae`. It must contain:

```
~/.maknae/maknae.yaml            # 0o600 — non-sensitive settings
~/.maknae/tls/vault-ca.crt       # the Vault server's TLS CA (trusts the HTTPS endpoint)
~/.maknae/tls/maknae-root-ca.crt # Maknae plane root CA (pinned trust anchor)
~/.maknae/tls/maknae-int-ca.crt  # Maknae plane intermediate CA
~/.maknae/maknaed-approle-id     # the trust-plane RoleID (non-secret)
~/.maknae/maknaed-secret-id      # 0o400 — the response-wrapped SecretID (seeded in step 3)
```

`maknae.yaml` (note the perms — `maknae-config` **rejects** a world/other-readable config
file or a group/other-accessible config dir):

```yaml
vault:
  addr: https://vault.private.darkhonor.net:8200
core:
  deployment_id: <the SAME value you passed to `terraform apply -var deployment_id=…`>
```

```bash
chmod 700 ~/.maknae ~/.maknae/tls
chmod 600 ~/.maknae/maknae.yaml
```

> The `deployment_id` MUST equal the value baked into the Vault roles' `allowed_uri_sans`,
> or `pki/sign` rejects the CSR's URI-SAN.

> **Non-default mounts.** If you overrode the deploy module's `approle_path` or
> `int_mount_path`, set the matching keys under `vault:` — they default to
> `maknae-approle` / `maknae-pki-int` when absent:
> ```yaml
> vault:
>   approle_mount: <your approle_path>
>   pki_int_mount: <your int_mount_path>
> ```

### 2. Point the vars

```bash
export VAULT_ADDR="https://vault.private.darkhonor.net:8200"   # your CLI is already authed with root
export MAKNAE_CONFIG_DIR="$HOME/.maknae"
```

### 3. Seed "secret 0" — a RESPONSE-WRAPPED, single-use SecretID (just-in-time)

The SecretID is single-use with a ~10-minute TTL, so create it immediately before minting:

```bash
# Response-wrap a fresh single-use SecretID (note the auth/ mount prefix):
vault write -wrap-ttl=90s -f auth/maknae-approle/role/maknaed/secret-id

# Deliver the returned WRAPPING TOKEN (wrapping_info.token) to the 0o400 file:
umask 077
printf '%s' '<the wrapping token>' > ~/.maknae/maknaed-secret-id
chmod 400 ~/.maknae/maknaed-secret-id
```

The client unwraps the wrapping token exactly once (`sys/wrapping/unwrap`) to recover the
SecretID — no plaintext SecretID ever touches disk. If the wrap was already used or has
expired, the mint fails closed (interception-detection).

### 4. Mint

```bash
cargo test -p maknae-vault --test live_smoke -- --ignored --nocapture
```

Expected: `LIVE SMOKE OK: minted maknae://<deployment_id>/plane/kernel (P-384), revoked on shutdown`.

### What it proves

- FIPS: the process runs the aws-lc-rs FIPS provider (`.fips()==true`, asserted
  fail-closed before the Vault client is built — so vaultrs's reqwest rides the FIPS
  provider, not its ring fallback).
- The AppRole login used a response-wrapped, single-use SecretID (unwrapped once).
- The CSR is empty-subject, URI-SAN-only, EC P-384; the leaf's only SAN is
  `maknae://<deployment_id>/plane/kernel` (self-checked in `mint()`).
- The leaf + key are held **memory-only** and the token is revoked on shutdown.

### Teardown

Nothing to clean — the leaf and key are memory-only and gone when the process exits; the
token is revoked on `shutdown`. The single-use SecretID is consumed by the login.

---

## Chapter 2 — Plane-to-plane mTLS (`maknae-vault` Stage 2)

Prove the two planes establish a **mutually-authenticated TLS 1.3 channel over a local
Unix domain socket**, each verifying the peer's `maknae://<deployment_id>/plane/<other>`
URI-SAN, and the daemon captures the peer's kernel credentials. This is the second live
milestone (the transport; the daemon run-loop + CLI arrive in Stage 3).

### Prerequisites

- Chapter 1 works (both planes can mint a leaf against your Vault).
- **Two config dirs** — one per plane — each a Chapter-1 layout with its own RoleID +
  response-wrapped SecretID:
  - **kernel** → `~/.maknae` (`maknaed-approle-id`, `maknaed-secret-id`, the shared
    `tls/` CAs, `maknae.yaml`).
  - **cli** → `~/.maknae-cli` (`maknae-approle-id`, `maknae-secret-id`, the same `tls/`
    CAs, `maknae.yaml`). The CLI plane uses the `maknae` AppRole role + `maknae-cli` PKI
    role; copy the `tls/` dir and `maknae.yaml` from `~/.maknae`, then add the CLI RoleID
    and a freshly-wrapped CLI SecretID.

### 1. Seed both response-wrapped SecretIDs (just-in-time)

```bash
export VAULT_ADDR="https://vault.private.darkhonor.net:8200"   # already authed with root
# kernel plane:
vault write -wrap-ttl=90s -f auth/maknae-approle/role/maknaed/secret-id   # → 0o400 ~/.maknae/maknaed-secret-id
# cli plane:
vault write -wrap-ttl=90s -f auth/maknae-approle/role/maknae/secret-id     # → 0o400 ~/.maknae-cli/maknae-secret-id
```
Deliver each returned `wrapping_info.token` to the matching `…-secret-id` file
(`umask 077; printf '%s' '<token>' > <path>; chmod 400 <path>`), as in Chapter 1 §3.

### 2. Socket dir + the `maknae` group (defense-in-depth outer fence)

The listener binds a pathname socket in a directory the daemon owns and only it can write.
The socket is group-gated `0660`; the operator account joins the `maknae` group so the CLI
can `connect()`. Group membership is **only** the outer fence — a valid plane cert (mTLS)
is still required to authenticate.

- **Linux (Debian/RHEL)** — systemd provisions the dir: `RuntimeDirectory=maknae`
  (`/run/maknae`, `_maknae:maknae`, `0750`); add the operator to `maknae`
  (`usermod -aG maknae <you>`).
- **macOS (arm64)** — launchd (or `mkdir`) creates e.g. `/usr/local/var/run/maknae`
  owned by the service account, `0750`; add the operator to `maknae` via `dscl`.

The client library **verifies the parent dir's ownership + mode before binding** and
refuses (fail-closed) if it is group/other-writable — so this step is checked, not assumed.

### 3. Run the live loopback

```bash
export MAKNAE_KERNEL_DIR="$HOME/.maknae"
export MAKNAE_CLI_DIR="$HOME/.maknae-cli"
cargo test -p maknae-vault --test live_transport_smoke -- --ignored --nocapture
```

Expected: `LIVE TRANSPORT OK: kernel<->cli mTLS + peer-creds round-trip over UDS`.

### What it proves

- **Mutual mTLS with plane-URI-SAN identity** — each side presents its Vault-minted P-384
  leaf and verifies the peer's leaf carries **exactly** the expected
  `maknae://<deployment_id>/plane/{kernel,cli}` URI-SAN (the T1 verifier), over TLS 1.3 on
  the aws-lc-rs FIPS provider.
- **Peer-cred capture** — the daemon reads the connecting uid (+ pid) from the kernel
  (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED`+`LOCAL_PEERPID` on macOS). The transport
  *reports* these; uid **policy** + audit are the Stage-3 daemon's job.
- **Fail-closed** — a wrong-plane, expired, foreign-CA, absent, or extra-SAN peer cert
  aborts the handshake (see the in-process negative suite); a listener whose identity was
  cleared (renewal expired) presents no leaf and the handshake fails.

### Teardown

The socket file is removed at the end of the run; leaves + keys are memory-only and gone
when the process exits; both tokens are revoked on `shutdown`.
