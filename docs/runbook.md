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
  addr: https://vault.example.internal:8200
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
export VAULT_ADDR="https://vault.example.internal:8200"   # your CLI is already authed with root
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
