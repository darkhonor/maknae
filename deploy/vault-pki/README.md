# Maknae Vault PKI (dev)

Terraform that provisions a **self-contained Maknae PKI in HashiCorp Vault** for
development: a dedicated Maknae **Root CA**, one **Intermediate CA** it signs, two
SAN-locked plane **roles** (`maknae-kernel`, `maknae-cli`), two signing-scoped
per-plane **policies**, and two **AppRoles** (`maknaed`, `maknae`).

This is the *provisioning* half of the plane-cert identity. The Rust plane-cert
client (`maknae-vault`) and the mTLS transport that **consume** this PKI are
separate, following cycles.

## What it stands up

- **Root CA** (`maknae-pki-root`, EC P-384, ~10y) — signs exactly one thing: the
  Maknae intermediate. Dev-only; production would instead chain the intermediate
  under the operator's enterprise root.
- **Intermediate CA** (`maknae-pki-int`, EC P-384, ~5y) — issues all plane leaves.
- **Roles** `maknae-kernel` / `maknae-cli` — 72h EC P-384 leaves whose **only**
  identity is the plane URI-SAN `maknae://<deployment_id>/plane/{kernel,cli}`.
  Every other SAN channel (IP, localhost, wildcard, domains, other-SANs) is pinned
  off; presence of the correct plane-SAN is enforced downstream by the peer verifier.
- **Policies** — each plane can sign **only its own role** (signing-scoped isolation)
  and manage its own token. (`revoke` is mount-wide — a Vault limitation, see below.)
- **AppRoles** — single-use SecretID → one renewable token per login, background-renewed
  up to 24h, then fail-closed re-auth with a fresh SecretID.

## Requirements

- Terraform `>= 1.5`, `hashicorp/vault` provider `~> 5.0` (pinned in
  `.terraform.lock.hcl` to the validated `5.10.1`). The lock carries `h1:` + registry
  `zh:` hashes for **linux and darwin, amd64 and arm64**, so a clean `terraform init`
  is reproducible on any of them without lock drift. To refresh after a version bump,
  regenerate for all supported platforms (not a single-platform `init`, which records
  only the local hash):
  ```bash
  terraform providers lock \
    -platform=linux_amd64 -platform=linux_arm64 \
    -platform=darwin_amd64 -platform=darwin_arm64
  ```
- A reachable Vault with a token that can create PKI mounts, roles, policies, and an
  AppRole auth mount. Provide it via the environment — **never in code**:
  ```bash
  export VAULT_ADDR="https://vault.example.internal:8200"
  export VAULT_TOKEN="<a token with the privileges above>"
  ```

## Run it

```bash
cd deploy/vault-pki
terraform init
terraform plan  -var 'deployment_id=<your-deployment-id>'
terraform apply -var 'deployment_id=<your-deployment-id>'
```

`deployment_id` has **no default** — you must pass an explicit value; it is branded
into every leaf SAN. TTLs, mount paths, and `approle_path` have dev defaults you can
override with additional `-var`s (all TTLs are **seconds**).

## Offline validation (no Vault needed)

```bash
terraform init -backend=false
terraform fmt -check
terraform validate
```

This is the mechanical gate the CI/pre-push flow relies on. It checks provider-schema
and config validity; it does **not** contact Vault and does **not** prove the SAN locks
are present (a permissive role is still schema-valid) — that is a review concern.

## Dev caveats (read before any non-dev use)

- **Dedicated dev root.** This stands up its own Maknae Root CA rather than chaining
  under an enterprise root. That is a **dev** choice; production chaining is a later delta.
- **`deployment_id`.** A wrong value silently mislabels every cert. The no-default +
  validation block forces an explicit choice; still pick it deliberately (it is the
  shared "this is dev" guard with the dedicated-root decision). It is constrained to
  `[A-Za-z0-9._-]` because Vault's `allowed_uri_sans` treats `*` as a **glob** — a `*`
  in `deployment_id` would make the leaf SAN `maknae://*/plane/...` match *any*
  deployment and defeat plane isolation; the charset guard blocks that.
- **`revoke` is mount-wide.** Vault has no per-role revoke path, so either plane's token
  can revoke the *other* plane's live cert (a cross-plane DoS, bounded by requiring the
  target serial — no `list` is granted). Revocation denies service; it never forges
  identity. Recorded, not eliminated (a Vault capability-model limitation).

## Operational follow-up: SecretID delivery (not Terraform)

AppRole login needs **two** things: the **RoleID** (non-secret, stable) and a
**SecretID** (secret, single-use). Terraform provisions both roles and outputs the
RoleIDs; it does not generate or deliver SecretIDs.

Read the RoleIDs from the outputs (non-secret — safe to bake into each plane's config):

```bash
terraform output -raw maknaed_role_id   # trust plane
terraform output -raw maknae_role_id    # CLI plane
```

Then issue a response-wrapped single-use SecretID per plane and deliver it to that
plane's `0o400` file (note the `auth/` mount prefix):

```bash
vault write -wrap-ttl=90s -f auth/<approle-path>/role/maknaed/secret-id
vault write -wrap-ttl=90s -f auth/<approle-path>/role/maknae/secret-id
```

Each plane logs in with `role_id` + the unwrapped `secret_id`, then background-renews
until `token_max_ttl`, then fails closed and awaits a fresh SecretID.
