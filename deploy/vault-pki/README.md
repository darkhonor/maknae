# Maknae Vault PKI (dev)

Terraform that provisions a **self-contained Maknae PKI and user identity in HashiCorp
Vault** for development: a dedicated Maknae **Root CA**, one **Intermediate CA** it signs,
two SAN-locked plane **roles** (`maknae-kernel`, `maknae-cli`), the **`maknaed` AppRole**
and its policy, a **userpass** auth mount for local users with one **templated user
policy**, the **KV v2** mount holding each user's provider API keys, the
`maknae-enroll` and `maknae-enroll-agent` policies, and, per Agent Daemon, a read-only credential policy and an
**AppRole** role on a separate agent mount, plus the administrator policy that writes
agent credentials.

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
- **Agent AppRole mount** (`maknae-agent-approle`, #168) — the mount Agent Daemons log in
  through, separate from `maknaed`'s.
- **`maknae-agent-<id>` policy and `agent-<id>` role** — one pair per entry of
  `maknae_agents`: the policy allows only a wrapped read of
  `<kv_mount>/data/<agent_prefix>/<id>/*`; the role issues a bounded, non-periodic token
  carrying that policy alone (see "Agent credentials").
- **`maknae-admin-agent-credentials` policy** — what an administrator attaches to their own
  token to write agent credentials; it reaches nothing outside `<agent_prefix>`.
- **`maknae-enroll-agent` policy** — what an operator attaches to their own token to run
  `maknae enroll agent`: read a role's RoleID, mint its SecretID, destroy a SecretID accessor,
  on the agent mount only.

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

## Agent credentials (#168)

Each Agent Daemon's credentials live at `<kv_mount_path>/data/<agent_prefix>/<id>/<name>`,
for example `maknae-kv/data/maknae/agents/hobi/github`. `agent_prefix` defaults to
`maknae/agents` and must not equal, contain or sit inside `user_prefix`.

`maknae_agents = { hobi = {} }` creates the policy `maknae-agent-hobi` and the AppRole role
`agent-hobi` on the `maknae-agent-approle` mount (`agent_approle_path`, which must differ
from `approle_path`). Agent ids follow the same rule as usernames: 1–32 bytes of
`[a-z0-9._-]`, starting and ending with `[a-z0-9_]`, and not `data`.

The agent may do one thing: a response-wrapped read of its own subtree
(`min_wrapping_ttl = "1s"`, `max_wrapping_ttl = "300s"`), plus lookup, renew and revoke of
its own token. Everything else there is denied (unwrapped read, write, patch, delete, and
every `metadata/`, `delete/`, `destroy/`, `undelete/` and `subkeys/` path), and it gets
nothing outside its subtree.

The RoleID is not secret and is published as an output: `terraform output -json agent_role_ids`
(or `vault read -field=role_id auth/maknae-agent-approle/role/agent-<id>/role-id` with an admin
or root token). Login requires the SecretID as well (`bind_secret_id = true`), and the token is
a revocable `service` token.

The token is bounded and never periodic: `agent_token_ttl` (default 1h) and
`agent_token_max_ttl` (default 24h, also set as the hard `explicit_max_ttl`; never 0)
(ADR-0006 decision 9). The SecretID is standing. On the agent's host,
`sudo maknae enroll agent <id> --account <service-account> --bind-cidr <host address>` (with an
operator token carrying `maknae-enroll-agent`) mints the agent's SecretID bound to that address
(`cidr_list` and `token_bound_cidrs`), seals it into OS custody, and `--rotate` replaces it.

`maknae enroll agent` runs under the operator's own Vault token, which must carry the
`maknae-enroll-agent` policy. Provisioning the policy does not grant it to anyone: the
administrator attaches it to the operator's identity the same way as `maknae-enroll`. It
allows `read` on `auth/<agent_approle_path>/role/+/role-id`, `create`, `update` and `list`
on `.../role/+/secret-id`, and `update` on `.../role/+/secret-id-accessor/destroy`, and
nothing else. `list` lets enrollment find and retire a SecretID that an interrupted earlier
run minted but never recorded.

The separate mount keeps agent login leases off `maknaed`'s prefix. It does **not**
separate one agent's leases from another's; per-agent revocation is #472.

To write a credential, an administrator attaches `maknae-admin-agent-credentials` to an
admin token, then writes the KV v2 data path directly (`read -s` keeps both secrets off the
screen and out of history). The subpath `github` and the field `token` are an example: the
Egress Daemon's GitHub call (#168 slice 3) fixes the real layout.

```bash
read -rsp "Admin token: " VT && echo && read -rsp "Credential: " CRED && echo && printf '{"data":{"token":"%s"}}' "$CRED" | VAULT_TOKEN="$VT" vault write <kv_mount>/data/<agent_prefix>/<id>/github - ; unset VT CRED
```

Do not use `vault kv put`: it preflights `sys/internal/ui/mounts` and was measured not to
work for a policy-scoped token (see "Loading a user's provider key").

## Offline validation (no Vault needed)

```bash
terraform init -backend=false
terraform fmt -check
terraform validate
terraform test
```

`terraform test` runs `tests/agents.tftest.hcl` under a mocked Vault provider: it needs
`init` but no Vault. It pins the agent policies byte for byte and the validations that
guard the agent ids, prefix, mount and token lifetimes.

No CI workflow runs this module; run these before pushing. They check provider-schema and
config validity and the agent policies; they do **not** contact Vault and do **not** prove
the SAN locks or the other policy templates are right (a permissive role is still
schema-valid) — those remain a review concern.

## Verify on a live Vault (post-merge, maintainer; not CI)

Getting a SecretID for `agent-hobi` needs a token carrying `maknae-enroll-agent` (see
"Agent credentials"), or a root token, on
`auth/maknae-agent-approle/role/agent-hobi/secret-id`. Take the RoleID from `terraform output -json agent_role_ids` (or `vault read
-field=role_id auth/maknae-agent-approle/role/agent-hobi/role-id` with an admin or root
token). Then, as `hobi` logged in by AppRole on the agent mount, confirm:

- a wrapped read of its own credential succeeds;
- an unwrapped read is refused;
- write, patch and delete are refused;
- every `metadata/`, `delete/`, `destroy/`, `undelete/` and `subkeys/` operation is refused;
- an AppRole login with the RoleID and no SecretID is refused;
- an admin token with `maknae-admin-agent-credentials` can
  `vault list <kv_mount>/metadata/<agent_prefix>`;
- another agent's credential is refused;
- a wrap TTL above 300s is refused (`max_wrapping_ttl`);
- `token lookup-self` shows `explicit_max_ttl` equal to `agent_token_max_ttl` (it comes from
  `token_explicit_max_ttl`) and no `period`.

Write every check with raw `vault read`, `write`, `delete` and `list` against the KV v2 API
paths, never `vault kv …`: the `kv` subcommands preflight `sys/internal/ui/mounts`, which an
agent token is not granted, so a refusal there proves nothing.

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
