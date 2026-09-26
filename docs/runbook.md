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
export VAULT_ADDR="https://vault.example.internal:8200"   # a CLI token holding the policies below
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
  provider, not its ring fallback — corrected 2026-09-19 (#320): `ring` is no longer
  in the graph at all, so there is no fallback to ride past; the assertion is unchanged).
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
export VAULT_ADDR="https://vault.example.internal:8200"   # a CLI token holding the policies below
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
export VAULT_ADDR="https://vault.example.internal:8200"   # a CLI token holding the policies below
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

The three `admin.*` subcommands are reachable from the same CLI —
`maknae status` (daemon version, protocol version, listener, deciding backend),
`maknae config-show` (the effective configuration, secrets rendered
`<value set>`), and `maknae subject-list` (the role bindings the PDP is using
right now, read live rather than from a boot snapshot). All three ship
**ungranted**: nothing in the packaged `authz.yaml` names them, so each answers
`not authorized` until a site adds a `roles:` grant. A refusal here is the
default posture, not a fault to debug — check the grant before the daemon.

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

**Reading `subject` and `role` (#275).** `subject.user` is the peer's OS
username, resolved from the peer uid; `subject.role` is the role the PDP
actually decided on. Two sentinels are deliberately distinct in the rendered
summary: `subject=unknown` means the record carried no username — every
fail-closed connection arm is like this, because resolving a name there would
put a blocking NSS lookup back on the async worker — while `role=none` means the
PDP resolved no role, or the record carries no decision at all (a connection is
not a decision). Do not read one as the other.

**macOS: a `DEGRADED` mirror line means "read the JSONL" (#275/#273).** The
unified log delivers one line and drops anything past 1015 bytes. With identity
on the record the widest `session.prompt` records exceed that — measured at
1027–1123 bytes — so **on macOS those records mirror as a degraded marker as a
matter of course, not as an exception**. The marker carries `MAKNAE_SESSION`,
`MAKNAE_SEQ` and `MAKNAE_PRIMARY`; use the session and seq to find the complete
record in the append-only JSONL, which has no size cap on either platform. A
`MAKNAE_PRIMARY` other than `ok` means the primary sink did not durably write,
so there is nothing to go read — that is an AU-5 condition, and the count of
degraded emissions is the signal your enclave should alert on.

```json
{"action":"liveness.ping","au3_1":{},"event":"request","integrity":{"prev_hash":null,"sig":null},"outcome":{"posture":"authorized","reason":"authorized","result":"permit"},"seq":2,"session_id":...,"source":{"gid":null,"pid":null,"plane_uri_san":"maknae://<deployment_id>/plane/cli","uid":<your uid>},"subject":{"plane_uri_san":"maknae://<deployment_id>/plane/cli","role":"user","user":"<your login>"},"ts":"...","where":{"component":"kernel","host":"maknaed","socket":"/run/maknae/maknaed.sock"}}
```

A **deny** record (a non-enrolled in-group uid running any verb, or a read of a
deny-listed path) looks like this — the REASON and the OBJECT live only here, never
on the wire (the client sees the generic `not authorized`):

```json
{"action":"fs.read","au3_1":{},"event":"request","object":"/home/<user>/.ssh/id_rsa","outcome":{"posture":"unauthorized","reason":"denied by policy entry Read(~/.ssh/**)","result":"deny"},...}
```

(seq 1 is the connection-admission record emitted by `handle` on cert-verified
accept; seq 2+ are the per-request records above. Exact key order is
canonical-sorted — `maknae-audit-append/src/record.rs` — not declaration order.)

### 7. Grants and destinations (`authz.yaml`)

Two additive keys govern what a role may DO beyond the shipped baseline, and both ship
absent: **nothing is granted and nothing is allowlisted** until you write it.

```yaml
roles:                       # #162: per-role action grants; deny beats allow inside a role
  user:
    allow: ["session.prompt"]
destinations:                # #172: per-role egress allowlist for session.prompt
  user:
    allow: ["provider:openai"]   # provider:<name>, the name registered in maknae.yaml §6.1
```

- **Which terms a role may hold.** `admin`: the three disclosure terms (`admin.status`,
  `admin.config.show`, `admin.subject.list`) and `session.prompt`. `user`: `session.prompt`
  only — writing an `admin.*` term under `user` refuses at boot, naming both the role and
  the term. `guest` and `adversary` are structural and take no grants; a `roles:` or
  `destinations:` key naming them refuses at boot too.
- **`destinations:` grammar.** Allow-only (a `deny:` key refuses at load, so it cannot be
  silently ignored); each entry is `provider:<name>` with `<name>` at most 32 bytes and
  matching the registered provider's `name`. URL patterns are a later grammar and are
  refused now. An absent or empty allowlist refuses every prompt: the second condition of
  `session.prompt` is the destination, and it never defaults open.
- **Separation of duties (recommended).** Bind the loop's account to `user`. An
  admin-bound loop also holds the disclosure verbs, and a loop that has been injected can
  quote `admin.config.show` into its next prompt; a `user`-bound loop cannot ask. The
  single-account HomeLab shape collapses both roles into one person, and the trail still
  names every destination, every intent and every outcome.
- **What a prompt carries.** Text-only content blocks (any other kind is refused before
  the decision, `BadRequest` on the wire) and a conversation id of at most 32 bytes in
  `[A-Za-z0-9._-]`. The trail records the text's length and a 32-hex digest, never the text.
- **Egress deputy and a Vault outage (#240b).** The deputy probes a Vault login at
  start and exits 1 if it fails, so during an outage every activation fails; systemd's
  default trigger limit then stops `maknae-egress.socket` and it does NOT restart on
  its own when Vault returns. Recovery: `systemctl reset-failed maknae-egress.socket &&
  systemctl restart maknae-egress.socket`.
- **A permitted prompt, and where it goes (#240).** With a `provider` registered, a
  permitted `session.prompt` is handed to the egress deputy over `egress.socket_path`
  (§6.2 of the configuration reference) under `egress.deadline_ms`; the trail carries the
  intent before the send and the outcome after it. With no provider, or before the
  deputy's socket exists, the prompt is refused with posture `unavailable` and reason
  `egress backend not ready`, and `Unauthorized` on the wire like every refusal — build
  state is never disclosed there. **The deputy's socket unit is preset-disabled and
  nothing enables it for you:** after `egress-bounds.yaml` is complete, `sudo systemctl
  enable --now maknae-egress.socket`, or every permitted prompt is refused as not ready
  (enroll's closing hint says so; found by review round 6). The provider key the deputy
  reads is cached for the life of its process: after rotating the key in Vault, or
  changing the deputy's grant, `systemctl restart maknae-egress.service`. *(Rewritten
  2026-09-15: this bullet described the `Unavailable`-only kernel.)*
- **Boot refuses when a provider is registered but the deputy cannot be found.**
  `maknaed: refusing to start: a provider is registered but the egress deputy's account
  '_maknae-egress' does not exist on this host` — the package creates the account; on a
  source-built host create it (`packaging/common/maknae.sysusers`) before registering a
  provider.

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
  decided by the PDP — the `Composition` of `maknae-authz-basic` and the
  classification-ceiling operand, behind the `maknae-security` seam (#148/#154) —
  policy re-read per request. `maknae read ~/some-file` returns bytes under `Read(~/**)`
  (the kernel decides; the CLI reads under your credentials);
  `maknae read ~/.ssh/id_rsa` is DENIED by the shipped deny list — wire says
  `not authorized`, the trail says which pattern and which object. Re-roling or
  removing an identity ALREADY KNOWN at boot bites on the NEXT request, no
  restart (containment). Introducing a brand-NEW username is restart-scoped by
  design (#85 §3, zero per-request NSS): until the restart, a policy naming an
  unresolvable identity makes every decision Indeterminate → deny — fail
  closed, recover by restarting (or reverting the edit); #84's reload lifts this.
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

---

## Chapter 4 — It acts (packaged agent conversation, #242)

Prove Maknae works as an agent on a **packaged** Linux install. An operator enrolls, registers an OpenAI-compatible provider whose key is held only in Vault, and holds a short conversation in which the model reads one file and writes another through the kernel. Every leg is decided and audited: the prompt goes out through the egress deputy (`maknae-egress`), and the read and the write are decided by `maknaed`. The audit lines you quote at the end are the evidence.

**Model.** Runs on the maintainer's key use `model: gpt-5.6-luna` (ruling 2026-09-13, recorded on #242). If you test on your own key, the model is your choice.

### Prerequisites

- **RHEL / Rocky 10**, SELinux enforcing, **with a TPM2** (a vTPM on a VM). Enroll refuses without a working `systemd-creds --with-key=tpm2` round-trip. fapolicyd may be active. RHEL 9 cannot run this chapter: `maknae enroll` seals with `systemd-creds --user`, which needs systemd ≥ 256, and el9 ships 252 (`packaging/rpm/README.md`).
- **Vault with `deploy/vault-pki` applied** (`terraform apply -var 'deployment_id=<id>'`). This creates the AppRole mount `maknae-approle`, the PKI mounts, the **KV v2** mount `maknae-kv`, the three AppRoles (`maknaed`, `maknae`, `maknae-egress`) and their policies. `maknae-egress` may read `maknae-kv/data/maknae/providers/*` and revoke its own token, and nothing else. Enroll creates none of these; it expects them.
- **An operator Vault token carrying the `maknae-enroll` policy** (`vault token create -policy=maknae-enroll`). Without it, every enroll call returns 403.
- **The Vault CA** as a PEM file on the host.
- **The RPM, built on the target OS** (`packaging/rpm/README.md`), so its SELinux module is compiled against that host's policy.
- **`jq` and `semanage`**: `sudo dnf install -y jq policycoreutils-python-utils`.
- **#365 PR 1 landed** (writes are subject-side attempts, and the SELinux policy lets `maknaed` receive no-access home descriptors). Before it, the shipped SELinux policy refuses every write on an enforcing host (`denied { ioctl }` for `maknaed_t` on `user_home_t` `dir`), and the trail records `fs.write` `deny`, reason `mutation descriptor missing`.
- **#365 PR 2 landed** (reads are subject-side attempts).
- **A provider API key**, which you will put into Vault in step 6. It never goes in a file on this host.

### 1. Install

```bash
sudo dnf install ./maknae-<ver>-1.el10.x86_64.rpm
id _maknae; id _maknae-egress; getenforce
```

A locally built package is unsigned. On a host that enforces GPG checks for local packages, either sign it (`packaging/sign.sh`) or pass `--nogpgcheck` for that one transaction.

### 2. Label the Vault port (SELinux)

```bash
sudo /usr/libexec/maknae/maknae-selinux-ports.sh add 8200   # your Vault's TCP port
```

### 3. Enroll

```bash
sudo maknae enroll \
  --deployment-id <id> \
  --vault-addr https://<vault-host>:8200 \
  --vault-ca /path/to/vault-ca.pem
```

- **`--vault-addr`** must be `https://` and carry an explicit port.
- **CA:** give exactly one of `--vault-ca` or `--ca-dir`.
- **Operator token:** you are prompted for it; `--token-file <path>` reads it from a file instead. `VAULT_TOKEN` is scrubbed from the environment and ignored.
- **Run it through `sudo`.** Bare root is refused, because enroll takes the operator's identity from `SUDO_UID`/`SUDO_USER`.
- **Run it from an unconfined session.** On SELinux, `sudo su -l <operator>` from an account mapped to `staff_u` lands in `sysadm_r:sysadm_t`, which is denied `/dev/tpmrm0`, and enroll's seal check fails with `no hardware root of trust available`. Run enroll from a session whose `id -Z` shows `unconfined_u`, such as a direct login as an operator on the default `unconfined_u` mapping. An operator mapped to a confined SELinux user is not supported for enrollment.
- **What enroll does:**
  - Mints the SecretIDs for all three planes. The two daemon SecretIDs are sealed to the TPM2; the CLI's is sealed with `systemd-creds --user`.
  - Writes the CA chain.
  - Adds you to the `maknae` group.
  - **Rewrites `/etc/maknae/maknae.yaml`** with four sections: `core`, `vault`, `audit`, `principal`.
- **Anything else you put in `maknae.yaml` is lost on the next enroll.** That is why the provider goes in `config.d/` (step 5).
- **A host enrolled before the deputy existed must re-enroll**, so that the `maknae-egress` plane gets its SecretID.
- **A host enrolled before #365 should re-enroll** to remove the `_maknae` ACL entry from your home and enroll's AppArmor include. The daemon needs neither; enroll keeps an include file it did not write. Afterwards `ls -ld ~` may still show `+`: an empty `mask::---` entry remains and grants nothing. Enroll touches only the home it is enrolling; on a home enrolled earlier by another operator, run `sudo setfacl -x u:_maknae <that home>`.

Log out and back in (or `newgrp maknae`) so your shell carries the group.

### 4. Declare the deputy's bounds

The deputy reads `/etc/maknae/egress-bounds.yaml`. Its owner must be root and it must not be group- or world-writable. It is `0644` because `_maknae-egress` is in neither `root` nor `_maknae`.

```bash
sudo tee /etc/maknae/egress-bounds.yaml >/dev/null <<'EOF'
kv_mount: maknae-kv
key_vault_path_prefix: maknae/providers
vault:
  addr: https://<vault-host>:8200
EOF
sudo chown root:root /etc/maknae/egress-bounds.yaml
sudo chmod 0644 /etc/maknae/egress-bounds.yaml
sudo restorecon -v /etc/maknae/egress-bounds.yaml
```

`key_vault_path_prefix` must **equal** the Terraform `provider_key_prefix` (default `maknae/providers`). **Nothing checks this equality.** A mismatch boots clean and becomes a 403 when the key is read (`docs/configuration.md` §6.1).

### 5. Register the provider

The package does not create `config.d/`. The directory and the file must be root-owned and not group- or world-writable; `660`/`770` are refused (`docs/configuration.md` §9.3).

```bash
sudo install -d -m 0750 -o root -g _maknae /etc/maknae/config.d
sudo tee /etc/maknae/config.d/10-provider.yaml >/dev/null <<'EOF'
provider:
  name: openai
  endpoint: https://api.openai.com/v1/chat/completions
  model: gpt-5.6-luna
  key_vault_path: maknae/providers/openai
  key_field: api-key
EOF
sudo chown root:_maknae /etc/maknae/config.d/10-provider.yaml
sudo chmod 0640 /etc/maknae/config.d/10-provider.yaml
sudo restorecon -Rv /etc/maknae
```

- **`endpoint` is POSTed exactly as written.** Give the full chat-completions URL, not the API base (`crates/maknae-llm/src/client.rs`).
- **All five keys are required.** A field named `key`, `api_key`, `token` or `secret` is refused as a plaintext key.
- **`key_vault_path` is mount-relative**, carries no `data/` segment, and must sit **strictly beneath** the prefix from step 4, or boot refuses with `OutsideBounds`.

### 6. Put the key in Vault

From a machine and token allowed to write the path, not from this host:

```bash
read -rsp 'API key: ' KEY && echo && [ -n "$KEY" ] && printf %s "$KEY" | vault kv put maknae-kv/maknae/providers/openai api-key=-; unset KEY
```

`printf %s` keeps a trailing newline out of the stored value. A newline would make every provider call fail, because it is not allowed in the `Authorization` header.

The field name must equal `key_field`; nothing defaults. The deputy caches the key for the life of its process, so after rotating the key run `sudo systemctl restart maknae-egress.service`.

### 7. Grant the prompt

Append to `/etc/maknae/authz.yaml`. `tee -a` keeps its owner, mode and label. The policy is re-read on every request, so no restart is needed:

```bash
sudo tee -a /etc/maknae/authz.yaml >/dev/null <<'EOF'
roles:
  admin:
    allow: ["session.prompt"]
destinations:
  admin:
    allow: ["provider:openai"]
EOF
sudo stat -c '%U:%G %a %C %n' /etc/maknae/authz.yaml   # root:_maknae 640
```

**Grant `admin`, not `user`.** The shipped policy has no `bindings:` key, and without one the enrolled principal resolves to **`admin`** (`crates/maknae-authz-basic/src/binding.rs`). If you add `bindings:`, that default stops applying and the grants belong under whichever role you bind.

The shipped path rules already allow `Read(~/**)` and `Write(~/projects/**)`, so the write target must be under `~/projects/`.

### 8. Prepare the files

```bash
mkdir -p ~/projects/maknae-242
printf 'Maknae is a security kernel for AI agents.\n' > ~/projects/maknae-242/input.txt
rm -f ~/projects/maknae-242/output.txt
```

**Do not create `output.txt`.** The kernel decides the write and records its intent; the CLI creates the file under your own permissions and reports the outcome. The kernel does not read or write your files (ADR-0009, #365).

Before any re-run of step 10, repeat `rm -f ~/projects/maknae-242/output.txt`. A second write to the same file takes the replace lane (`mutation.operation:"WriteExisting"`).

### 9. Start

```bash
sudo systemctl enable --now maknae-egress.socket
sudo systemctl enable maknaed && sudo systemctl restart maknaed
systemctl is-active maknaed maknae-egress.socket
unset MAKNAE_CONFIG_DIR                      # Chapters 2–3 set it; enroll's CLI config is ~/.maknae
maknae ping                                  # expect: pong
```

**Restart, don't just enable.** The provider is registered at boot, and `enable --now` does nothing to a daemon that is already running. A daemon still on its old configuration denies every prompt with `no provider registered for session.prompt`.

- **The deputy is socket-activated.** It starts on the first prompt, and before it accepts that connection it runs a Vault login-and-revoke probe.
- **Neither daemon prints a "ready" line.** A failure prints `refusing to start: …` to the journal (`journalctl -u maknaed -u maknae-egress`).
- **Without the socket unit, every permitted prompt is refused** with the reason `egress backend not ready`.

### 10. Hold the conversation

```bash
START=$(date -u +%Y-%m-%dT%H:%M:%S)
maknae agent "Read $HOME/projects/maknae-242/input.txt, write a one-sentence summary of it to $HOME/projects/maknae-242/output.txt, then tell me what you wrote."
cat ~/projects/maknae-242/output.txt
```

- **Paths must be absolute.** The loop refuses relative paths.
- **Exit codes:** the model's answer on stdout with exit `0`; a stop is `maknae agent: stopped: …` with exit `2`.
- **Record what happened.** An exit `2` or an error is a finding. Capture it together with the audit lines from step 11.

### 11. Quote the audit trail

The trail is `/var/log/maknae/audit.jsonl`. Its directory is `0700 _maknae`, so reading it needs `sudo`.

```bash
: "${START:?run step 10 in this shell}"
sudo jq -c --arg t "$START" 'select(.ts >= $t) | select(.action=="session.prompt" or .action=="fs.read" or .action=="fs.write") | {seq, ts, action, object, result: .outcome.result, reason: .outcome.reason, posture: .outcome.posture, egress, mutation, conversation}' /var/log/maknae/audit.jsonl
sudo jq -c 'select(.event=="boot" and .action=="authz") | {ts, reason: .outcome.reason}' /var/log/maknae/audit.jsonl | tail -n 1
```

`ts` is UTC, which is why `START` is taken with `date -u`.

What to find:

| Record | Shape |
|---|---|
| Boot composition evidence | `event:"boot"`, `action:"authz"`, reason `authorization composition: …; system: …; ceiling: …`. Written at every boot, before serving |
| `session.prompt` intent | `object:"provider:openai"`, reason `intent recorded`, `egress.status:"IntentOnly"` with `content_length`, `content_digest` and `conversation` |
| `session.prompt` outcome | the same identity at a later `seq`: `egress.status:"Sent"` with `reply_length`, or a named failure (`Failed`, `DeadlineExpired`, `OutcomeUnknown`, `LandedUndelivered`) |
| `session.prompt` refused before intent | a single record: `result:"deny"`, reason `egress backend not ready`, `egress.status:"BackendUnavailable"`, with no intent ahead of it |
| `fs.read` intent | `object` = the canonical path, `mutation.phase:"Intent"`, `mutation.operation:"Read"`, `origin:"KernelObserved"`, `status:"IntentOnly"`, no `content_length` |
| `fs.read` progress | `mutation.phase:"Progress"`, `origin:"ClientReported"`, `status:"ReportedProgress"`, `effects:[{…,"effect":"ReadFile","length":N}]` |
| `fs.read` completion | `mutation.phase:"Completion"`, `origin:"ClientReported"`, `status:"ReportedSuccess"` (or another `Reported*` status), `intent_seq` pointing at the intent |
| `fs.read` refused | `result:"deny"` with the reason, and no `mutation` block (e.g. `read descriptor missing` or `read evidence refused: …`) |
| `fs.write` intent | reason `authorized; intent alone does not establish execution`, `mutation.phase:"Intent"`, `mutation.operation:"WriteCreate"` (`"WriteExisting"` when replacing), `origin:"KernelObserved"`, `status:"IntentOnly"`, `content_length` (the length the request declared; the kernel never sees the bytes) |
| `fs.write` progress | `mutation.phase:"Progress"`, `origin:"ClientReported"`, `status:"ReportedProgress"`, with the created (`CreatedFile`) or replaced (`ReplacedFile`) file in `effects` |
| `fs.write` completion | `mutation.phase:"Completion"`, `origin:"ClientReported"`, `status:"ReportedSuccess"` (or another `Reported*` status), `intent_seq` pointing at the intent |
| `fs.write` refused | `result:"deny"` with the reason, and no `mutation` block (e.g. `mutation descriptor missing`, what an enforcing host without #365 PR 1 records) |
| `fs.write` descriptor refused | `result:"deny"`, reason `replacement evidence refused: descriptor confers access beyond location: …` (a descriptor that could read or write was delegated) |
| `fs.write` incomplete | `mutation.phase:"Completion"`, `status:"Incomplete"`, `intent_seq` pointing at the intent; the reason names what was lost (`attempt grant not delivered; no effect authorized`, `mutation acknowledgment not delivered; effects unknown`, or a missing report) |

There is **one `session.prompt` intent-and-outcome pair per model turn that is sent**, so a read-then-write conversation has several.

**Correlation:**
- `session_id` is per connection and each turn is a connection, so it does **not** group the conversation.
- `conversation` does. It is in `egress.conversation` on prompt records and top-level on `fs.write` and `fs.read`.

### 12. The refused turns

- **An oversize read.** Ask the agent to read a file larger than the read grant's byte limit (`transport.frame_max_bytes` − 512 = 65024 bytes by default), e.g. `head -c 70000 /dev/urandom | base64 > ~/projects/maknae-242/big.txt`. The CLI refuses the read against the grant's byte limit and reports it: `fs.read` completion `status:"ReportedLimitReached"`, with no `ReadFile` effect. The model is told the read was unavailable and usually answers anyway, with exit `0`.
- **Over the conversation cap.** Two files, each inside the read budget, that together exceed the frame: `for n in 1 2; do head -c 30000 /dev/urandom | base64 > ~/projects/maknae-242/half$n.txt; done` (about 40 KB each). Ask the agent to read both. Both reads succeed, and the transcript then outgrows the frame, so the loop refuses to send the next prompt: `maknae agent: stopped: the conversation has reached the platform's frame bound`, exit `2`. Nothing oversize is sent.
- **Marked content above the system level** (#242, the diagnostic-artifact case). **Not runnable yet.** Nothing stamps a marking on content until #229, so there is nothing to refuse.

### 13. Custody check (manual)

The custody assertion is **not built** (ADR-0023, ADR-0026). Check it by hand:

```bash
id                                                   # the operator: in maknae, not _maknae or _maknae-egress
sudo stat -c '%U:%G %a %n' /etc/maknae /etc/maknae/private /etc/maknae/egress \
  /etc/maknae/private/maknae-egress-secret-id.cred /etc/maknae/egress/maknae-egress-approle-id
sudo getfacl -p /etc/maknae
sudo test -e /run/credentials/maknae-egress.service/maknae-egress-secret-id && echo "runtime credential present"
for f in /etc/maknae/private/maknae-egress-secret-id.cred \
         /etc/maknae/egress/maknae-egress-approle-id \
         /run/credentials/maknae-egress.service/maknae-egress-secret-id; do
  test -r "$f" && echo "READABLE: $f" || echo "not readable: $f"
done
sudo -u _maknae test -r /etc/maknae/egress/maknae-egress-approle-id && echo "READABLE by _maknae" || echo "not readable by _maknae"
```

- **Expected owners and modes:** `/etc/maknae` `root:_maknae 750`, with an ACL entry for `_maknae-egress` only; `private/` `root:_maknae 750`; `egress/` `root:_maknae-egress 750`; the sealed `.cred` `root:root 400`; the RoleID `root:_maknae-egress 640`.
- **Expected reads:** every `test -r` says `not readable`, for the operator and for `_maknae`.
  - The operator's `not readable` proves only that `/etc/maknae` (`root:_maknae 750`) cannot be traversed. Judge the file modes from the `stat` output. The same holds for `_maknae` and `egress/` (`root:_maknae-egress 750`).
  - The runtime credential exists only once the deputy has started. Run `maknae agent` once, and confirm `runtime credential present` before reading its `test -r` line.
- **What this check does not cover:** the operator's own `maknae-enroll` token can mint a `maknae-egress` SecretID in Vault. That lies outside the file-custody claim; state it alongside the result.

### 14. SELinux

```bash
sudo grep -h 'type=AVC' /var/log/audit/audit.log* | grep -E 'maknaed_t|maknae_egress_t'
sudo grep -h 'type=FANOTIFY' /var/log/audit/audit.log* | grep -i maknae    # fapolicyd denials
```

Search with `grep`: on a STIG'd Rocky 10 host `ausearch -m AVC` was measured missing AVC records that the log holds. The log rotates quickly, so run this soon after step 10.

**Expected:** no denials. A denial is a finding: quote it. This chapter is the first run of the location-only read descriptor under an enforcing policy.

### What it proves

- **A packaged Maknae acts as an agent against a real provider:** one conversation, one read, one write, and every leg decided by `maknaed` and audited before its delivery or effect.
- **The write is performed by the client under your own permissions**; the kernel only decides it and records it.
- **The provider key lives only in Vault** and is read only by the deputy, under its own AppRole and policy.
- **The trail shows each decision and its outcome in order**, with the boot composition record ahead of them.

### Teardown

```bash
sudo systemctl disable --now maknae-egress.socket maknae-egress.service
sudo rm /etc/maknae/config.d/10-provider.yaml /etc/maknae/egress-bounds.yaml
sudoedit /etc/maknae/authz.yaml                 # remove the roles:/destinations: block from step 7
sudo systemctl restart maknaed
sudo /usr/libexec/maknae/maknae-selinux-ports.sh remove 8200
rm -r ~/projects/maknae-242
vault kv metadata delete maknae-kv/maknae/providers/openai   # when the key is retired
```
