# Maknae Vault PKI (dev)

Terraform that provisions a **self-contained Maknae PKI and user identity in HashiCorp
Vault** for development: a dedicated Maknae **Root CA**, one **Intermediate CA** it signs,
two SAN-locked plane **roles** (`maknae-kernel`, `maknae-cli`), the **`maknaed` AppRole**
and its policy, a **userpass** auth mount for local users with one **templated user
policy**, the **KV v2** mount holding each user's provider API keys, and the
`maknae-enroll` policy.

The Rust plane-cert client (`maknae-vault`) and the mTLS transport consume this PKI.

## What it stands up

- **Root CA** (`maknae-pki-root`, EC P-384, ~10y) — signs exactly one thing: the
  Maknae intermediate. Dev-only; production would instead chain the intermediate
  under the operator's enterprise root.
- **Intermediate CA** (`maknae-pki-int`, EC P-384, ~5y) — issues all plane leaves.
- **Roles** `maknae-kernel` / `maknae-cli` — 72h EC P-384 leaves whose **only**
  identity is the plane URI-SAN `maknae://<deployment_id>/plane/{kernel,cli}`.
  Every other SAN channel (IP, localhost, wildcard, domains, other-SANs) is pinned
  off; presence of the correct plane-SAN is enforced downstream by the peer verifier.
- **`maknaed` AppRole** (ADR-0018) — a **periodic token** (renews indefinitely; fails
  closed only on genuine Vault failure/revocation) and a **standing SecretID** (hands-free
  reboots), under the `maknae-kernel` policy: sign its own role, manage its own token.
  (`revoke` is mount-wide — a Vault limitation, see below.)
- **Userpass mount** (`maknae-userpass`, ADR-0028) — each local user's single Vault
  identity. The Vault username must equal the local username.
- **`maknae-user` policy** — templated on the userpass alias name, so each user reaches
  only `<kv_mount>/data/<user_prefix>/<own username>/*` (every read must be
  response-wrapped: `min_wrapping_ttl = "1s"`) and the matching `metadata/` paths, signs
  the `maknae-cli` role, and looks up and revokes its own token.
- **Users** — one `vault_userpass_auth_backend_user` per entry of `maknae_users`, carrying
  no policy of its own, with an 8h token TTL and a 24h maximum. The user token does
  **not** carry Vault's `default` policy (`token_no_default_policy = true`). The `maknae`
  CLI needs nothing from it: it calls only the userpass login, `auth/token/lookup-self`,
  `auth/token/revoke-self`, the response-wrapped read of the user's own KV key, and
  `<pki_int>/sign/maknae-cli`. It reads no issuer bundle from Vault, never renews a
  token, and never revokes a certificate.
- **User identities** — one identity entity per user, named `maknae-<user>`, with one
  alias: the username, on the userpass mount.
- **`maknae-users` group** — an internal identity group whose members are those entities;
  it carries the `maknae-user` policy, so every user token gets it as an identity policy.
- **KV v2 mount** (`maknae-kv`) — provider API keys, one subtree per user. The Egress
  Daemon holds no Vault identity; it opens only the single-use wrapping token a user's
  CLI sends it.

## Requirements

- Terraform `>= 1.11` (write-only attributes and ephemeral resources),
  `hashicorp/vault` `~> 5.10` and `hashicorp/random` `~> 3.7`, pinned in
  `.terraform.lock.hcl` to the validated versions. The lock carries `h1:` + registry
  `zh:` hashes for **linux and darwin, amd64 and arm64**, so a clean `terraform init`
  is reproducible on any of them without lock drift. To refresh after a version bump,
  regenerate for all supported platforms (not a single-platform `init`, which records
  only the local hash):
  ```bash
  terraform providers lock \
    -platform=linux_amd64 -platform=linux_arm64 \
    -platform=darwin_amd64 -platform=darwin_arm64
  ```
- A reachable Vault with a token that can create PKI and KV mounts, roles, policies, and
  AppRole and userpass auth mounts and users. Provide it via the environment — **never in
  code**:
  ```bash
  export VAULT_ADDR="https://vault.example.internal:8200"
  export VAULT_TOKEN="<a token with the privileges above>"
  ```

## Run it

```bash
cd deploy/vault-pki
terraform init
terraform plan  -var 'deployment_id=<your-deployment-id>' -var 'maknae_users={"alice"={password_version=1}}'
terraform apply -var 'deployment_id=<your-deployment-id>' -var 'maknae_users={"alice"={password_version=1}}'
```

`deployment_id` has **no default** — you must pass an explicit value; it is branded
into every leaf SAN. TTLs, mount paths, `approle_path`, `userpass_mount`, `kv_mount_path`
and `user_prefix` have dev defaults you can override with additional `-var`s (all TTLs
are **seconds**). `userpass_mount`, `kv_mount_path` and `user_prefix` must equal the
values passed to `maknae enroll` (`--userpass-mount`, `--kv-mount`, `--user-prefix`);
the outputs of the same names print them.

## Users and passwords

Each key of `maknae_users` is a local username: 1–32 bytes of `[a-z0-9._-]`, starting
and ending with `[a-z0-9_]`, and not `data` (Vault lower-cases userpass usernames, and
`maknaed` derives the key path from the local account, refuses a `data` segment in it,
and refuses a name longer than the 32 bytes its audit trail records). `user_prefix` likewise has no `data` segment. Terraform creates the user with a random password
from an ephemeral `random_password`, sent through the write-only `password_wo`: it is in
neither the plan nor the state, and nobody learns it. Set the user's real password out of
band, with an admin token. The path is `auth/<userpass_mount>/users/<username>/password`;
with the default `userpass_mount`, in zsh (macOS):

```zsh
read -rs "PW?New password: " && echo && printf %s "$PW" | vault write auth/maknae-userpass/users/alice/password password=- && unset PW
```

In bash: `read -rsp "New password: " PW && echo && printf %s "$PW" | vault write auth/maknae-userpass/users/alice/password password=- && unset PW`
(the bash form is not yet measured). `read -s` keeps the password off the screen and out of
history, and `printf %s` sends no trailing newline. Do not type the password into a bare
`password=-` prompt: it is echoed, and the Enter key is stored as part of the password, so
every login fails.

Never edit a user resource after creation. The provider resends the write-only password
on any in-place update of a `vault_userpass_auth_backend_user`, and the ephemeral value is
a fresh random one each run, so any such update resets that user's password (measured: an
apply that only changed `token_policies` reset every user). The user policy is bound through
the `maknae-users` identity group, whose members are per-user identity entities aliased to
the userpass mount, so policy changes, adding a policy, and adding or removing users never
touch an existing user's resource. A user's password is reset by: changing an attribute
applied to every user (for example a shared TTL), renaming a key in `maknae_users`, or
incrementing that user's `password_version`; each locks the user out until a password is set again.

Removing a user from `maknae_users` deletes the Vault userpass user, its identity entity and
alias, and its group membership, and nothing else: the user's KV subtree
`<kv_mount>/<user_prefix>/<username>/` remains and is removed by hand (`vault kv metadata
delete` per key). Re-adding a removed username gives the new holder the old KV subtree;
remove the subtree first.

## Loading a user's provider key

Every read of a key under the user policy is answered only wrapped, and an unwrapped read is refused with `403 permission denied` (measured on the homelab Vault; Vault reports a `min_wrapping_ttl` violation as a plain permission denied). An unwrapped write is refused too (measured on a throwaway Vault 2.0.0 in #434). The user loads their own key, logged in with their userpass identity, so the command uses `-wrap-ttl=60s`.

Get a user token without replacing another token in the shell: `vault login -method=userpass -path=<userpass_mount> -token-only username=<user>` (`maknae login` keeps its own token, not `VAULT_TOKEN`).

zsh (measured on macOS; it stored the key at `maknae-kv/data/maknae/users/<user>/openai`):

```zsh
read -rs "VT?Maknae user token: " && echo && read -rs "KEY?OpenAI API key: " && echo && printf '{"data":{"api_key":"%s"}}' "$KEY" | VAULT_TOKEN="$VT" vault write -wrap-ttl=60s <kv_mount>/data/<user_prefix>/<username>/<subpath> - ; unset VT KEY
```

bash (not yet measured):

```bash
read -rsp "Maknae user token: " VT && echo && read -rsp "OpenAI API key: " KEY && echo && printf '{"data":{"api_key":"%s"}}' "$KEY" | VAULT_TOKEN="$VT" vault write -wrap-ttl=60s <kv_mount>/data/<user_prefix>/<username>/<subpath> - ; unset VT KEY
```

`read -s` keeps both secrets off the screen and out of shell history; `printf` is a builtin, so the key never appears in `ps`; `vault write <kv_mount>/data/...` with `-` writes the KV v2 data path directly, avoiding the `vault kv` preflight against `sys/internal/ui/mounts`, which a user token may not be allowed; Vault answers with a wrapping token around the write's metadata, which holds nothing secret. Do not use `vault kv put ... api_key=-` (measured not to work for a user). A wrapping token from a wrapped read wraps the key itself, so never paste one anywhere.

## Offline validation (no Vault needed)

```bash
terraform init -backend=false
terraform fmt -check
terraform validate
```

This is the mechanical gate the CI/pre-push flow relies on. It checks provider-schema
and config validity; it does **not** contact Vault and does **not** prove the SAN locks
or the policy templates are right (a permissive role is still schema-valid) — that is a
review concern.

## Dev caveats (read before any non-dev use)

- **Dedicated dev root.** This stands up its own Maknae Root CA rather than chaining
  under an enterprise root. That is a **dev** choice; production chaining is a later delta.
- **`deployment_id`.** A wrong value silently mislabels every cert. The no-default +
  validation block forces an explicit choice; still pick it deliberately (it is the
  shared "this is dev" guard with the dedicated-root decision). It is constrained to
  `[A-Za-z0-9._-]` because Vault's `allowed_uri_sans` treats `*` as a **glob** — a `*`
  in `deployment_id` would make the leaf SAN `maknae://*/plane/...` match *any*
  deployment and defeat plane isolation; the charset guard blocks that.
- **`revoke` is mount-wide.** Vault has no per-role revoke path, so the trust plane's
  token can revoke a CLI plane's live cert (a DoS, bounded by requiring the target serial
  — no `list` is granted). Revocation denies service; it never forges identity. Recorded,
  not eliminated (a Vault capability-model limitation). The `maknae-user` policy grants no
  `revoke`.

## Operational follow-up: the `maknaed` SecretID (not Terraform)

AppRole login needs **two** things: the **RoleID** (non-secret, stable) and a
**SecretID** (secret; **standing** under ADR-0018 — `num_uses=0`, `ttl=0`). Terraform
provisions the `maknaed` role and outputs its RoleID; it does not generate or deliver
the SecretID. `maknae enroll` reads the RoleID and mints the SecretID over the API:

```bash
terraform output -raw maknaed_role_id
```

`maknae enroll` runs under the **operator's own Vault token**, not the plane's AppRole
token. This Terraform provisions a least-privilege `maknae-enroll` policy (read the
`maknaed` RoleID, create/update its SecretID, destroy its accessors, read the
intermediate issuer bundle — no `list`, per §4.5), but **provisioning the policy does not
grant it to anyone**: before running `sudo maknae enroll`, the operator's Vault identity
must be attached to it — e.g. via `vault token create -policy=maknae-enroll` for a direct
token, or by adding `maknae-enroll` to whatever external auth-method mapping (LDAP/OIDC
group, userpass policy list, etc.) governs that operator's login. Without this grant,
`maknae enroll` 403s on every AppRole/PKI call it makes.

The daemon's bootstrap SecretID is protected at rest and decrypted only into memory at
startup (ADR-0018): on Linux a `_maknae`-owned credential **sealed to TPM 2.0**; on macOS a
System-keychain item, under that keychain's root-held key, that only the signed daemon can
read (ADR-0018 decision 6). The daemon logs in with `role_id` + `secret_id` and renews its
**periodic token indefinitely**; because the SecretID is standing, reboots need no re-seed.

Users need no SecretID: each logs in with `maknae login` (userpass), which stores only the
resulting token.
