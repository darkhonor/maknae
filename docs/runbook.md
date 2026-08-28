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

### 3. Seed "secret 0" — a RESPONSE-WRAPPED SecretID (interception-detecting delivery)

Under ADR-0018 the SecretID itself is **standing** (non-expiring, unlimited uses); the
**response-wrap** is what's single-use (~90s). Wrapping this *local* daemon file is a
transitional **Stage-1 client constraint** (the current client only accepts a wrapping
token), **not** the ADR-0018 steady state — where a local `_maknae`/operator-owned bootstrap
file needs no wrap (see `deploy/vault-pki/README.md`). Create it just before minting:

```bash
# Response-wrap the standing SecretID for interception-detecting delivery (auth/ mount prefix):
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
- The AppRole login used a response-wrapped **standing** SecretID (the wrap is single-use —
  unwrapped once — for interception detection; the SecretID itself does not expire).
- The CSR is empty-subject, URI-SAN-only, EC P-384; the leaf's only SAN is
  `maknae://<deployment_id>/plane/kernel` (self-checked in `mint()`).
- The leaf + key are held **memory-only** and the token is revoked on shutdown.

### Teardown

Nothing to clean — the leaf and key are memory-only and gone when the process exits; the
token is revoked on `shutdown`. The SecretID is **standing** (not consumed by the login); the
response-wrap it rode in on is single-use and already spent.

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

---

## Chapter 3 — It responds (`maknaed` run-loop + `maknae` CLI, Stage 3a)

Prove the daemon actually serves a request end-to-end: `maknaed` boots, binds the
group-gated plane socket, and a real `ssh`-in operator session running `maknae ping`
and `maknae whoami` gets a real answer — authorized by mTLS + peer-creds + group
membership AND, since #77, a per-request PDP verdict (the enrolled principal
resolves `admin` via the policy defaults; a non-enrolled in-group peer is DENIED
per request — see the deny record below), with every request landing an AU-3
line in the audit log. This is the third
live milestone; Chapters 1–2 proved the credential and the transport in isolation, this
chapter proves the whole daemon.

### Prerequisites

- Chapter 1 works for **both** planes (kernel + cli each mint against your Vault).
- Chapter 2's live loopback passes (mTLS + peer-creds round-trip already proven).
- A host you can `ssh` into as the operator account that will run the CLI — this chapter
  is written as a two-terminal exercise: one terminal starts `maknaed` in the foreground,
  the other `ssh`-es in fresh and runs `maknae`.

### 1. Provision the `maknae` group + the operator's membership

Skip this if you already did it for Chapter 2 on this host — it's the same group, done
once per host, not once per chapter.

```bash
# Linux
sudo groupadd --system maknae               # idempotent: ignore "already exists"
sudo usermod -aG maknae "$(whoami)"
# log out/in (or `newgrp maknae`) for the new group membership to take effect in your shell

# macOS
sudo dscl . -create /Groups/maknae
sudo dscl . -append /Groups/maknae GroupMembership "$(whoami)"
```

> Group membership is the **outer fence only** (`authorize_connection`, `maknae-kernel/src/authz.rs`)
> — a peer uid outside `maknae` is denied before a request is even read. Since #77 a
> cert-valid, in-group peer is then decided PER REQUEST by the PDP: with the shipped
> (bindings-absent) policy the ENROLLED principal's uid resolves `admin` and is served;
> every other in-group uid has no role and is denied everything, including `ping` —
> deny-by-default made operational. It is not a substitute for the mTLS half.

### 2. Seed the daemon's standing SecretID

Same response-wrap flow as Chapter 1 §3, targeted at the **daemon's** config dir
(`/etc/maknae` in production; `~/.maknae` here for a dev/manual run) and the `maknaed`
AppRole role:

```bash
export VAULT_ADDR="https://vault.private.darkhonor.net:8200"   # already authed with root
vault write -wrap-ttl=90s -f auth/maknae-approle/role/maknaed/secret-id

umask 077
printf '%s' '<wrapping_info.token>' > ~/.maknae/maknaed-secret-id
chmod 400 ~/.maknae/maknaed-secret-id
```

The file MUST end up `0400` — `maknae-vault`'s config loader (Chapter 1) fails closed on
a group/other-readable secret file, and `maknaed` will refuse to boot rather than mint
against a loosely-permissioned identity.

### 3. Create the socket dir

`maknaed` binds a pathname UDS under `transport.socket_path`
(`maknae-config/src/transport.rs`; default `/run/maknae/maknaed.sock`, overridable in
`maknae.yaml`'s `transport:` section). The **parent directory** must be owner-only —
`maknae-vault`'s `verify_parent_dir` (Chapter 2 §2) refuses to bind if it is group/other
**writable**, so `0750` (group-readable+executable, not writable) is correct; `0770`/`0777`
are not.

```bash
# Linux — a dev/manual run (no systemd unit yet):
sudo mkdir -p /run/maknae
sudo chown "$(whoami)":maknae /run/maknae
sudo chmod 0750 /run/maknae

# macOS:
sudo mkdir -p /usr/local/var/run/maknae
sudo chown "$(whoami)":maknae /usr/local/var/run/maknae
sudo chmod 0750 /usr/local/var/run/maknae
```

Point `maknae.yaml`'s `transport.socket_path` at whichever of these you created (or leave
the default and use `/run/maknae/maknaed.sock` on Linux).

### 4. Start `maknaed`

In terminal 1 (stays in the foreground — there is no daemonization/systemd unit yet at
this stage):

```bash
export MAKNAE_CONFIG_DIR="$HOME/.maknae"     # the daemon's OWN config dir (Chapter 1)
cargo run -p maknaed -- "$MAKNAE_CONFIG_DIR"
```

`maknaed` runs its full boot sequence in order (spec §6.1/§6): install + assert the
aws-lc-rs FIPS provider → boot Maknae's own config (`transport`/`audit` sections,
optional) → open the fail-closed JSONL audit sink (AU-5: an unopenable sink is a boot
failure, not a silent no-op) → mint the kernel plane leaf → spawn the credential
supervisor → bind the group-gated socket → serve. Any failure at any of these steps
exits non-zero with a `maknaed: refusing to start: ...` message on stderr — there is no
"start anyway, serve degraded" path.

A quiescent, successfully-bound daemon prints nothing further and blocks; it responds to
`SIGTERM`/`SIGINT` with a graceful drain (finishes in-flight handlers, then exits).

### 5. `ssh` in and run the acceptance verbs

In terminal 2, a **fresh** session (proves the CLI's own leaf mint + connect works from a
cold start, not a warm terminal that happens to already have Vault env vars set):

```bash
ssh <operator>@<host>
export MAKNAE_CONFIG_DIR="$HOME/.maknae-cli"   # the CLI's OWN config dir (Chapter 2)
maknae ping
maknae whoami
```

Expected output:

```
$ maknae ping
pong

$ maknae whoami
maknae://<deployment_id>/plane/cli uid=<your uid>
```

Exit code `0` on both **when run as the enrolled principal**. A non-`maknae`-group
uid, an in-group-but-NOT-enrolled uid (per-request deny since #77 — the CLI prints
`maknae: daemon refused: Unauthorized: not authorized`), an expired/wrong-plane cert,
or the daemon not running each produce a non-zero exit with a `maknae: <reason>` line
on stderr instead — the CLI never prints a placeholder or partial answer on failure (`bins/maknae/src/cli.rs`
`execute`'s single `Result<bool, String>` return: `Ok(true)` on a real verb response,
`Err` for everything else).

### 6. Read the audit trail

Back in terminal 1's config dir (or wherever `audit.jsonl_path` resolved to — default
`<config_dir>/audit.jsonl` if the `audit:` section is absent):

```bash
tail -f ~/.maknae/audit.jsonl
```

Each `ping`/`whoami` call lands (at least) one line — audit-then-respond ordering
(`may_respond`, `maknae-kernel/src/handler.rs`) means the CLI's response was released
**only because** this record durably landed first:

```json
{"action":"liveness.ping","au3_1":{},"event":"request","integrity":{"prev_hash":null,"sig":null},"outcome":{"posture":"authorized","reason":"authorized","result":"permit"},"seq":2,"session_id":...,"source":{"gid":null,"pid":null,"plane_uri_san":"maknae://<deployment_id>/plane/cli","uid":<your uid>},"subject":{"plane_uri_san":"maknae://<deployment_id>/plane/cli","user":null},"ts":"...","where":{"component":"kernel","host":"maknaed","socket":"/run/maknae/maknaed.sock"}}
```

A **deny** record (a non-enrolled in-group uid running any verb, or a read of a
deny-listed path) looks like this — the REASON and the OBJECT live only here, never
on the wire (the client sees the generic `not authorized`):

```json
{"action":"acp.fs.read","au3_1":{},"event":"request","object":"/home/<user>/.ssh/id_rsa","outcome":{"posture":"unauthorized","reason":"denied by policy entry Read(~/.ssh/**)","result":"deny"},...}
```

(seq 1 is the connection-admission record emitted by `handle` on cert-verified
accept; seq 2+ are the per-request records above. Exact key order is
canonical-sorted — `maknae-audit-append/src/record.rs` — not declaration order.)

### What it proves

- **mTLS** — the CLI's Vault-minted `maknae://<deployment_id>/plane/cli` leaf and the
  daemon's `.../plane/kernel` leaf completed a real TLS 1.3 handshake and each verified
  the other's URI-SAN (Chapter 2's proof, now exercised through the full daemon rather
  than the loopback smoke test).
- **Peer-creds** — the daemon captured your real connecting uid off the kernel
  (`SO_PEERCRED`/`LOCAL_PEERCRED`) and it is exactly what `maknae whoami` echoes back —
  proof the kernel-verified fact, not a client-asserted one, is what's in the response.
- **Group ADMISSION** — you are in `maknae` (step 1); `authorize_connection` permits the
  connection on `(cert_verified=true, uid_in_group=true)`. Removing yourself from the
  group (and starting a fresh `ssh` session so group membership re-resolves) turns the
  same commands into a denied connection — an audited `deny`/`unauthorized` record, no
  response, non-zero CLI exit. Admission is the TRANSPORT half.
- **Per-request AUTHORIZATION (#77)** — the DECISION half: every admitted request is
  decided by the PDP (`maknae-authz-basic` behind the `maknae-security` seam), policy
  re-read per request. `maknae read ~/some-file` returns bytes under `Read(~/**)`;
  `maknae read ~/.ssh/id_rsa` is DENIED by the shipped deny list — wire says
  `not authorized`, the trail says which pattern and which object. Editing
  `/etc/maknae/authz.yaml` bindings flips behavior on the NEXT request, no restart.
- **AU-3 audit lines** — every connection and every request produces a durable,
  canonically-ordered JSONL record (§6 above) BEFORE the daemon released a response —
  the fail-closed audit-then-respond ordering is not just a code comment, it's
  observable: kill the daemon's write access to `audit.jsonl_path` mid-run and the next
  `maknae ping` hangs until its `read_timeout_ms` and then fails, rather than getting a
  `pong` with no audit trail behind it.

### A note on what this chapter validates that automated tests don't

`transport.handshake_timeout_ms` (default 5000ms, spec/`maknae-config/src/transport.rs`)
bounds how long `PlaneListener::accept` will wait for a peer to complete the TLS
handshake before giving up and auditing a `HandshakeTimeout` rejection
(`RejectReason::HandshakeTimeout`, `maknae-kernel/src/run.rs`'s `reject_reason_str`). This
is enforced by a real wall-clock timeout racing a real network handshake — there is no
unit or integration test that fakes time here (Stage 3a scope), so the only proof it
actually fires is live: open a raw TCP-adjacent connection to the socket (e.g.
`nc -U /run/maknae/maknaed.sock` and then just sit there without speaking TLS) and
confirm the daemon closes it and emits a `handshake timeout` / `deny` audit record within
`handshake_timeout_ms` rather than holding the connection (and its semaphore permit)
open indefinitely.

### Teardown

`SIGTERM`/`SIGINT` the `maknaed` process (Ctrl-C in terminal 1) for a graceful drain; the
socket file and the memory-only kernel leaf are gone when it exits, and its Vault token
is revoked on shutdown. The CLI never holds state between invocations — each `maknae`
run mints, connects, asks, revokes, exits.
