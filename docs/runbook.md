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
~/.maknae/maknaed-secret-id      # 0o400 — the standing raw SecretID (seeded in step 3)
```

`maknae.yaml` (note the perms — `maknae-config` **rejects** a world/other-readable config
file or a group/other-accessible config dir):

```yaml
vault:
  addr: https://vault.example.internal:8200
  insecure_plaintext_secret_path: <your home>/.maknae/maknaed-secret-id   # absolute
core:
  deployment_id: <the SAME value you passed to `terraform apply -var deployment_id=…`>
```

```bash
chmod 700 ~/.maknae ~/.maknae/tls
chmod 600 ~/.maknae/maknae.yaml
```

> The `deployment_id` MUST equal the value baked into the Vault roles' `allowed_uri_sans`,
> or `pki/sign` rejects the CSR's URI-SAN.

> **Where the kernel plane finds its SecretID.** In order: `$CREDENTIALS_DIRECTORY/maknaed-secret-id`
> (systemd), the System-keychain pointer (macOS), then `vault.insecure_plaintext_secret_path`;
> with none of them it refuses (`crates/maknae-vault/src/secret_source.rs`). A dev dir has
> only the last, so the key above is required. The path must be absolute, and the file must
> be `0600` or stricter (`crates/maknae-vault/src/client.rs`).

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
export VAULT_ADDR="https://vault.example.internal:8200"   # a token carrying the maknae-enroll policy
export MAKNAE_CONFIG_DIR="$HOME/.maknae"
```

### 3. Seed "secret 0" — the standing raw SecretID

Under ADR-0018 the `maknaed` SecretID is **standing** (non-expiring, unlimited uses), and
the client reads it raw: there is no response-wrapping. The `maknae-enroll` policy
(`deploy/vault-pki/main.tf`) may mint it. This form is not yet measured:

```bash
umask 077
vault write -f -field=secret_id auth/maknae-approle/role/maknaed/secret-id > ~/.maknae/maknaed-secret-id
chmod 400 ~/.maknae/maknaed-secret-id
```

The client trims surrounding whitespace from the file, so a trailing newline is harmless.

### 4. Mint

```bash
cargo test -p maknae-vault --test live_smoke -- --ignored --nocapture
```

Expected: `LIVE SMOKE OK: minted maknae://<deployment_id>/plane/kernel (P-384), revoked on shutdown`.

### What it proves

- FIPS: the process runs the aws-lc-rs FIPS provider (`.fips()==true`, asserted
  fail-closed before the Vault client is built, so vaultrs's reqwest rides the FIPS
  provider; `ring` is not in the graph).
- The AppRole login used the **standing** raw SecretID; the SecretID does not expire and
  the login does not consume it.
- The CSR is empty-subject, URI-SAN-only, EC P-384; the leaf's only SAN is
  `maknae://<deployment_id>/plane/kernel` (self-checked in `mint()`).
- The leaf + key are held **memory-only** and the token is revoked on shutdown.

### Teardown

Nothing to clean — the leaf and key are memory-only and gone when the process exits; the
token is revoked on `shutdown`. The SecretID is **standing** (not consumed by the login);
remove `~/.maknae/maknaed-secret-id` when you are done with the dev dir.

---

## Chapter 2 — Plane-to-plane mTLS (`maknae-vault` Stage 2)

Prove the two planes establish a **mutually-authenticated TLS 1.3 channel over a local
Unix domain socket**, each verifying the peer's `maknae://<deployment_id>/plane/<other>`
URI-SAN, and the daemon captures the peer's kernel credentials. This is the second live
milestone (the transport; the daemon run-loop + CLI arrive in Stage 3).

### Prerequisites

- Chapter 1 works (the kernel plane mints a leaf against your Vault).
- Your account is a Vault userpass user with a password set ([first-provider step 1](first-provider.md#1-create-the-user-in-vault)). The CLI plane has no AppRole: it mints its leaf with the Vault token `maknae login` stores (`crates/maknae-vault/src/client.rs`, `PlaneClient::for_user`).
- **Two config dirs** — one per plane:
  - **kernel** → `~/.maknae`, the Chapter-1 layout (`maknaed-approle-id`, `maknaed-secret-id`, the `tls/` CAs, `maknae.yaml`).
  - **cli** → `~/.maknae-cli` (`0700`): a copy of the `tls/` dir (`0700`, files `0600`) and a `0600` `maknae.yaml` holding only `vault.addr` and `core.deployment_id`. The CLI plane signs with the `maknae-cli` PKI role.

### 1. Log the CLI plane in

```bash
export MAKNAE_CONFIG_DIR="$HOME/.maknae-cli"
maknae login
unset MAKNAE_CONFIG_DIR
```

`maknae login` needs a terminal and refuses to run as root. What it prints and where it keeps the token are in [first-provider step U1](first-provider.md#u1-log-in); on Linux the token lands under `~/.maknae-cli`, because the CLI resolves its config dir from `MAKNAE_CONFIG_DIR`. On macOS the token is the login-keychain item `maknae-cli`/`maknae-vault-token` whatever the config dir (`crates/maknae-vault/src/token_record.rs`, `keychain_policy.rs`), so `~/.maknae-cli` and `~/.maknae` share one token.

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
export MAKNAE_KERNEL_CONFIG_DIR="$HOME/.maknae"
export MAKNAE_CLI_CONFIG_DIR="$HOME/.maknae-cli"
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
when the process exits. The kernel plane's AppRole token is revoked on `shutdown`; the
CLI plane's login token is not, and stays valid until it expires or you run
`MAKNAE_CONFIG_DIR="$HOME/.maknae-cli" maknae logout`. On macOS that logout revokes and erases the one shared keychain token, the one `~/.maknae` uses too.

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

- Chapter 1 works for the kernel plane, and Chapter 2's CLI dir holds a `maknae login` token (Chapter 2 §1).
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

Same raw-SecretID flow as Chapter 1 §3, targeted at the **daemon's** config dir
(`/etc/maknae` in production; `~/.maknae` here for a dev/manual run) and the `maknaed`
AppRole role. If you completed Chapter 1 in `~/.maknae`, the file is already there.

The file MUST be `0600` or stricter, and `vault.insecure_plaintext_secret_path` must name
it (Chapter 1 §1) — `maknae-vault` fails closed on a group/other-readable secret file, and
`maknaed` will refuse to boot rather than mint against a loosely-permissioned identity.

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
maknae login                                   # skip if the Chapter 2 login has not expired
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
`<value set>`), and `maknae subject-list` (one row per subject `bindings.yaml`
names: its uid, a label and its state, from the snapshot the PDP decides from
now, as of the last applied reload). All three ship
**ungranted**: nothing in the packaged `authz.yaml` names them, so each answers
`not authorized` until a site adds a `roles:` grant. A refusal here is the
default posture, not a fault to debug — check the grant before the daemon.

Every verb needs a stored login: without one the CLI prints
``maknae: no Vault token is stored: run `maknae login` `` and exits non-zero.

Exit code `0` on both **when run as the enrolled principal**. A non-`maknae`-group
uid, an in-group-but-NOT-enrolled uid (per-request deny since #77 — the CLI prints
`maknae: daemon refused: Unauthorized: not authorized`), an expired/wrong-plane cert,
or the daemon not running each produce a non-zero exit with a `maknae: <reason>` line
on stderr instead — the CLI never prints a placeholder or partial answer on failure (`bins/maknae/src/cli.rs`
`execute`'s single `Result<bool, String>` return: `Ok(true)` on a real verb response,
`Err` for everything else). A streamed `maknae read` is the one exception: it writes each
page to stdout as that page is released, so a failure on page N leaves pages 1 to N−1 on
stdout and a non-zero exit.

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

**Reading `rule` (#489).** A decision made by a rule in `authz.yaml` carries a
`rule` block: `{"key":"<key>","node":<n>,"section":"<path>#<section>"}`, for example
`{"key":"rule:permissions:allow:3","node":95,"section":"/etc/maknae/authz.yaml#permissions"}`
for the fourth `allow` entry of `permissions:`, or a `rule:roles.admin:allow:0` key in
section `/etc/maknae/authz.yaml#roles.admin` for a role grant. The `key` names the
entry by section, effect and position. `node` is the rule's node in the compiled
policy; node numbers shift on any recompile that adds a node, and two daemons running
the same `authz.yaml` over different store histories can number the same rule
differently. Identify a rule by `policy_sha256` and `key` together, never by `node`:
`policy_sha256` names the policy in force, and the boot `authz` record and each
`graph.reload` outcome carry it (see "What the trail shows" under the reload section).
A record of what a permitted action then did keeps the rule that permitted it,
whatever the result, because authorization is separate from effect: every egress
outcome (sent, send failed, send deadline expired, send outcome unknown, or a
refused reply), every mutation completion including an incomplete one, and the
corrective record that follows a permitted response which could not be delivered (an
`admin.subject.list` whose bindings could not be enumerated, a response over the
frame limit, or one that could not be encoded). A query on `rule.key` therefore finds
the outcome that says whether content may have left, not only the decision. A record
has no `rule` block when no rule in the file decided: a structural role decision
(such as liveness) or deny-by-default. Nor does a refusal made before the PDP decided:
a request that could not be read or decoded, a path or operand pre-gate, a refused
provider choice, an open decision breaker, an exhausted decision worker budget, a
decision task that failed, a decision timeout, or a mutation that could not be
prepared. Nor does a deny written in place of a permit that was never
acted on: an unhonorable obligation, a mutation whose object label could not be
resolved, a `session.prompt` refused because the egress backend was not ready, and
two defence-in-depth denies that no request should reach (a mutation dispatch
without prepared evidence, and a `session.prompt` without an admitted provider
choice). Connection, boot, reload and shutdown records carry no decision and no
`rule`. An `fs.mkdir` with `parents` decides every directory it creates from one
policy, and its record cites the rule for the last directory decided: on a permit,
the requested directory; on a deny, the one refused.

**macOS: a `DEGRADED` mirror line means "read the JSONL" (#275/#273).** The
unified log delivers one line and drops anything past 1015 bytes. With identity
on the record the widest `session.prompt` records exceed that — measured at
1027–1123 bytes — so **on macOS those records mirror as a degraded marker as a
matter of course, not as an exception**. The marker carries `MAKNAE_SESSION`,
`MAKNAE_SEQ` and `MAKNAE_PRIMARY`; use the session and seq to find the complete
record in the append-only JSONL, which has no size cap on either platform. `MAKNAE_PRIMARY=ok`
means the record is durable in the JSONL. `write-unconfirmed` means the write
may have landed, so check the JSONL (the marker's hint is `primary-unconfirmed`).
`refused-breaker-open` and `refused-at-capacity` mean the primary never attempted
the write, so nothing was written and there is nothing to go read. `write-failed`
means the write or its durability sync failed: the record, or partial bytes of it,
may be present in the JSONL but is not confirmed durable (the marker's hint is
`primary-write-failed`). Each of these is an AU-5 condition, and the
count of degraded emissions is the signal your enclave should alert on.

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
    allow: ["provider:openai"]   # provider:<name>, an authorized provider's name (configuration §6.1)
```

- **Which terms a role may hold.** `admin`: the three disclosure terms (`admin.status`,
  `admin.config.show`, `admin.subject.list`) and `session.prompt`. `user`: `session.prompt`
  only — writing an `admin.*` term under `user` refuses at boot, naming both the role and
  the term. `guest` and `adversary` are structural and take no grants; a `roles:` or
  `destinations:` key naming them refuses at boot too.
- **`destinations:` grammar.** Allow-only (a `deny:` key refuses at load, so it cannot be
  silently ignored); each entry is `provider:<name>` with `<name>` at most 32 bytes and
  matching the `name` of an entry in the authorized `providers` list. URL patterns are a later grammar and are
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
- **Egress deputy and a Vault outage (#240b).** The deputy makes no Vault login and does
  not contact Vault at start-up (`bins/maknae-egress/src/main.rs`): it reaches Vault only per turn, to
  look up and unwrap the user's wrapping token. During an outage the user's own CLI
  cannot mint its leaf or make its wrapped read of the key, so the turn fails before it
  reaches the kernel. If Vault becomes unreachable after the CLI's read, the deputy's
  lookup or unwrap fails, it answers refused-before-send, and `maknaed` records the turn's outcome
  `egress.status:"Failed"`; the deputy's journal shows `OpenFailed(Vault)`. Nothing has
  to be restarted when Vault returns.
- **A permitted prompt, and where it goes (#240).** With providers authorized, a
  permitted `session.prompt` is handed to the egress deputy over `egress.socket_path`
  (§6.2 of the configuration reference) under `egress.deadline_ms`; the trail carries the
  intent before the send and the outcome after it. With no providers authorized, the
  kernel refuses the prompt at admission, reason
  `no model access: no providers are authorized on this host`. Before the deputy's
  socket exists, the prompt is refused with posture `unavailable` and reason
  `egress backend not ready`. Either way the wire says `Unauthorized` like every
  refusal — build state is never disclosed there. **The deputy's socket unit is
  preset-disabled and nothing enables it for you:** `sudo systemctl enable --now
  maknae-egress.socket`, or every permitted prompt is refused as not ready (enroll's
  closing hint says so). The deputy keeps no key cache: each turn's key is read fresh
  under the user's own login, so rotating a key in Vault needs no restart.
- **Boot refuses when providers are authorized but the deputy cannot be found.**
  `maknaed: refusing to start: providers are authorized but the egress deputy's account
  '_maknae-egress' does not exist on this host` — the package creates the account; on a
  source-built host create it (`packaging/common/maknae.sysusers`) before authorizing a
  provider.
- **When an edit applies.** `maknaed` decides from a snapshot of `authz.yaml` compiled at
  start; an edit applies at the next [reload](#reload-the-policy) or restart.

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
  from a snapshot of `authz.yaml` compiled at start and at each reload (#489).
  `maknae read ~/some-file` returns bytes under `Read(~/**)`
  (the kernel decides; the CLI reads under your credentials);
  `maknae read ~/.ssh/id_rsa` is DENIED by the shipped deny list — wire says
  `not authorized`, the trail says which pattern and which object, and the record's
  `rule` block names the policy section that decided it. A policy edit — re-roling or
  removing an identity, or adding a new username — applies at the next
  [reload](#reload-the-policy) or restart, never on the next request. A reload resolves
  every username on the host the way a start does, and refuses (keeping the running
  policy) when one has no account; no lookup happens per request (#85 §3).
- **AU-3 audit lines** — every connection and every request produces a durable,
  canonically-ordered JSONL record (§6 above) BEFORE the daemon released a response —
  the fail-closed audit-then-respond ordering is not just a code comment, it's
  observable: kill the daemon's write access to `audit.jsonl_path` mid-run and the next
  `maknae ping` fails within about 5 s with either `frame truncated` (the daemon
  closed the connection without replying) or `no response from daemon within {N}ms; it
  may be slow admitting the connection (group lookup or admission audit)`. The daemon
  never returns a `pong` without a durable admission record.

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
is revoked on shutdown. The CLI holds only its stored login between invocations — each
`maknae` run mints a leaf with that token, connects, asks and exits; the token stays valid
until it expires or you run `maknae logout`.

---

## Chapter 4 — It acts (packaged agent conversation, #242)

Prove Maknae works as an agent on a **packaged** Linux install. An operator enrolls and authorizes an OpenAI-compatible provider; the operator, as a user, stores their own API key in Vault under their own login, and holds a short conversation in which the model reads one file and writes another through the kernel. Every leg is decided and audited: the prompt goes out through the egress deputy (`maknae-egress`), and the read and the write are decided by `maknaed`. The audit lines you quote at the end are the evidence.

**Model.** Runs on the maintainer's key use `model: gpt-5.6-luna` (ruling 2026-09-13, recorded on #242). If you test on your own key, the model is your choice.

### Prerequisites

- **RHEL / Rocky 10**, SELinux enforcing, **with a TPM2** (a vTPM on a VM). Enroll refuses without a working `systemd-creds --with-key=tpm2` round-trip; the TPM2 seals both the daemon's credential and the Egress Daemon's sealing key. fapolicyd may be active. On RHEL 9, enroll is expected to work but has not been run live there, nor has enroll → serve (`packaging/rpm/README.md`).
- **Vault with `deploy/vault-pki` applied** (`terraform apply -var 'deployment_id=<id>'`). This creates the AppRole mount `maknae-approle` with the one AppRole `maknaed` and its policy, the PKI mounts, the **KV v2** mount `maknae-kv`, the userpass mount `maknae-userpass`, the `maknae-user` policy, one userpass user per entry in `maknae_users`, an identity entity `maknae-<user>` for each, and the group `maknae-users` that grants them the policy. Each user's keys live under `user_prefix` (default `maknae/users`), at `maknae-kv/data/maknae/users/<user>/…`, which only that user's login may read or write (`deploy/vault-pki/main.tf`). Enroll creates none of these; it expects them.
- **You are a Vault user with a password set** ([first-provider step 1](first-provider.md#1-create-the-user-in-vault)): the operator who enrolls is also the user who holds the conversation.
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
- **CA:** give exactly one of `--vault-ca` or `--ca-dir`. The `--vault-ca` bundle must hold every certificate needed to anchor Vault's server certificate, and each certificate in it is a trust anchor: if Vault serves only its leaf, include the issuing intermediate as well as the root.
- **Operator token:** you are prompted for it; `--token-file <path>` reads it from a file instead. `VAULT_TOKEN` is scrubbed from the environment and ignored.
- **Run it through `sudo`.** Bare root is refused, because enroll takes the operator's identity from `SUDO_UID`/`SUDO_USER`.
- **Run it from an unconfined session.** On SELinux, `sudo su -l <operator>` from an account mapped to `staff_u` lands in `sysadm_r:sysadm_t`, which is denied `/dev/tpmrm0`, and enroll's seal check fails with `no hardware root of trust available`. Run enroll from a session whose `id -Z` shows `unconfined_u`, such as a direct login as an operator on the default `unconfined_u` mapping. An operator mapped to a confined SELinux user is not supported for enrollment.
- **The Vault layout flags.** `--userpass-mount` (default `maknae-userpass`), `--kv-mount` (default `maknae-kv`) and `--user-prefix` (default `maknae/users`) must equal Terraform's `userpass_mount`, `kv_mount_path` and `user_prefix` (step 4).
- **What enroll does:**
  - Mints `maknaed`'s SecretID (the only AppRole) and seals it to the TPM2 (`/etc/maknae/private/maknaed-secret-id.cred`, `root:root 0400`). A re-enroll rotates it.
  - Generates the Egress Daemon's sealing key pair when none is in place: the private key is sealed to the TPM2 at `/etc/maknae/private/maknae-egress-seal-key.cred` (`root:root 0400`), and the public key is published as `seal.pub` (`/etc/pki/maknae/seal.pub` on the Red Hat family, `/etc/ssl/maknae/seal.pub` on the Debian family), where every user's CLI reads it. On a first enroll it prints `` Generated the Egress Daemon's sealing key and published its public key at {path}. An Egress Daemon that is already running still holds the previous key: restart it with `sudo {restart}` ``, with `{restart}` = `systemctl try-restart maknae-egress.service`; on a re-enroll it prints `Kept the Egress Daemon's sealing key and its published public key; pass --rotate-seal-key to replace them`.
  - Creates the kernel graph key when none is in place, sealed to the TPM2 at `/etc/maknae/private/maknaed-graph-key.cred` (on macOS, the System-keychain item `io.maknae.maknaed.graph`). It never rotates an existing one, because a new key cannot read the existing store ([the kernel graph store refuses to start](#the-kernel-graph-store-refuses-to-start)).
  - Writes `/etc/maknae/egress-bounds.yaml` from `--vault-addr`, `--kv-mount` and `--user-prefix` (step 4).
  - Writes the CA chain.
  - Writes your CLI configuration, `~/.maknae/maknae.yaml` (with the `vault` block carrying `user_auth`, `kv_mount` and `user_prefix`) and `~/.maknae/tls/`. It writes no token: you log in yourself (step 9).
  - Adds you to the `maknae` group.
  - **Rewrites `/etc/maknae/maknae.yaml`** with four sections: `core`, `vault` (with `user_auth`), `audit`, `principal`.
- **Anything else you put in `maknae.yaml` is lost on the next enroll.** That is why the provider list goes in `config.d/` (step 5).
- **A host enrolled before #365 should re-enroll** to remove the `_maknae` ACL entry from your home and enroll's AppArmor include. The daemon needs neither; enroll keeps an include file it did not write. Afterwards `ls -ld ~` may still show `+`: an empty `mask::---` entry remains and grants nothing. Enroll touches only the home it is enrolling; on a home enrolled earlier by another operator, run `sudo setfacl -x u:_maknae <that home>`.

It closes with `` Log out and back in (or run `newgrp maknae`), then run `maknae login` before using the CLI ``. Log out and back in (or `newgrp maknae`) so your shell carries the group; you log in to Vault in step 9.

### 3a. Upgrading a host enrolled before the switch

A host enrolled before per-user providers (#153) carries the removed AppRoles' credentials. In this order:

1. **Apply the current `deploy/vault-pki` Terraform first.** It deletes the `maknae` and `maknae-egress` AppRoles, and creates the userpass mount, the `maknae-user` policy and the users. Every SecretID minted for the deleted roles dies with them.
2. **Re-enroll** with step 3's command. Enroll mints only `maknaed`'s SecretID now, rotating it, and generates the sealing key pair.
3. **Delete the leftovers by hand.** Enroll does not remove them, and nothing reads them:

   ```bash
   sudo rm -f /etc/maknae/private/maknae-egress-secret-id.cred /etc/maknae/egress/maknae-egress-approle-id
   rm -f ~/.maknae/maknae-approle-id ~/.maknae/maknae-secret-id.cred
   ```

   On macOS, also delete the login-keychain item `maknae-cli`/`maknae-secret-id` (`security delete-generic-password -s maknae-cli -a maknae-secret-id`; this form is not yet measured). Remove any `provider:` block from `~/.maknae/maknae.yaml`: every CLI verb fails while it is there.

4. **Authorize the provider again** in the new shape (step 5), and have each user log in and store their own key (steps 6 and 9). A key stored at the old shared path is no longer read.

   The administrator then deletes the old shared key with an admin Vault token. It sits at the old `key_vault_path`, under the old `key_vault_path_prefix` (default `maknae/providers`); with the old defaults (not yet measured):

   ```bash
   vault delete maknae-kv/metadata/maknae/providers/openai
   ```

   This removes every version of that key. Use your old `kv_mount`, prefix and provider name if they differed.

### 3b. Upgrading a host whose principal carries `home`

A host enrolled before #440 has a `home:` line under `principal:` in `/etc/maknae/maknae.yaml`. The package upgrade restarts `maknaed`, and the daemon then refuses to start with:

```text
maknae daemon refused to start: the authorization policy could not be loaded: unknown key 'home' in 'principal'
```

It refuses while any file carries the key, whether `maknae.yaml` or a `config.d/` member. Delete the `home:` line from whichever file carries it. Re-enrolling with step 3's command also removes it, but only from `/etc/maknae/maknae.yaml`. Then restart `maknaed`: `sudo systemctl restart maknaed`; on macOS, `sudo launchctl kickstart -k system/io.maknae.maknaed`.

### 3c. More than one user

Enroll writes `~/.maknae` only for the account that ran it. To give another local account the agent, follow [first-provider step 4a](first-provider.md#4a-add-another-local-user): it adds the account to the `maknae` group, copies your CLI configuration to it, binds it in `bindings.yaml` and creates its Vault user. The consequence for you: once `bindings.yaml` has a `bindings:` block, only the names it lists have a role, so the enrolled administrator must be listed under `admin` too, and step 7's grant then belongs under each bound role; [reload](#reload-the-policy) `maknaed` after adding a name. A second user's file actions are confined to their own home, resolved per request.

### 4. Check the deputy's bounds

Enroll wrote `/etc/maknae/egress-bounds.yaml` in step 3; this step only checks it. Its owner must be root and it must not be group- or world-writable. It is `0644` because `_maknae-egress` is in neither `root` nor `_maknae`.

```bash
sudo stat -c '%U:%G %a %n' /etc/maknae/egress-bounds.yaml   # root:root 644
sudo cat /etc/maknae/egress-bounds.yaml
```

The file is `0644`, but `/etc/maknae` is `root:_maknae 0750`, enroll adds you to `maknae`, not `_maknae`, and the directory's ACL lets only `_maknae-egress` traverse it. So you read it with `sudo`.

It holds exactly `vault.addr`, `kv_mount` and `user_prefix` (`docs/configuration.md` §6.1.3). Do not edit it by hand: the next enroll rewrites it.

**What must match.** Each Vault layout flag of step 3 must **equal** its Terraform input: `--userpass-mount` ↔ `userpass_mount`, `--kv-mount` ↔ `kv_mount_path`, `--user-prefix` ↔ `user_prefix` (`deploy/vault-pki/variables.tf`). Enroll checks the flags' grammar, not that they equal the Terraform values. Enroll writes the same `kv_mount` and `user_prefix` into this file and into your `~/.maknae/maknae.yaml`, and a user whose copy differs from this file seals a key the Egress Daemon cannot open (`docs/configuration.md` §6.1.2).

### 5. Authorize the provider

The package does not create `config.d/`. The directory and the file must be root-owned and not group- or world-writable; `660`/`770` are refused (`docs/configuration.md` §9.3).

```bash
sudo install -d -m 0750 -o root -g _maknae /etc/maknae/config.d
sudo tee /etc/maknae/config.d/10-provider.yaml >/dev/null <<'EOF'
providers:
  - name: openai
    endpoint: https://api.openai.com/v1/chat/completions
    models: [gpt-5.6-luna]
    reasoning_effort: none
EOF
sudo chown root:_maknae /etc/maknae/config.d/10-provider.yaml
sudo chmod 0640 /etc/maknae/config.d/10-provider.yaml
sudo restorecon -Rv /etc/maknae
```

- **`endpoint` is POSTed exactly as written.** Give the full chat-completions URL, not the API base (`crates/maknae-llm/src/client.rs`).
- **`models`** lists the models users may ask this provider for; the kernel refuses any other at admission.
- **`reasoning_effort: none` is required for `gpt-5.6-luna`.** Without it the model refuses the loop's tools on chat completions: every turn is recorded `OutcomeUnknown`, with `provider answered 400` in the deputy's journal. The journal line carries up to 4 KiB of the provider's error body with the key masked, and that body can quote the rejected request — prompt and file content included — so treat the deputy's journal as holding conversation content (`docs/configuration.md` §6.2).
- **No key goes in this file.** A field named like a key (`key`, `api_key`, `token`, `secret` and others) refuses boot. Each entry may hold only the keys `name`, `endpoint`, `models`, `reasoning_effort` and `output_tokens_field`; the last two are optional (`docs/configuration.md` §6.1).
- **The daemon's prompt cap.** `transport.prompt_max_bytes` in `/etc/maknae/maknae.yaml` defaults to 1 MiB, enough for a context window of about 174,000 tokens. For a larger window raise it to `context_tokens × 6`, at most 16 MiB, or the daemon refuses the loop's larger frames. Enroll rewrites that file, so set it again after a re-enroll.

### 6. Store your key and choose your provider

As yourself, not root, store your own API key in Vault under your own login: [first-provider step U2](first-provider.md#u2-store-your-key-in-vault). Then write `~/.maknae/providers.yaml`, naming the provider and model from step 5, the key's `subpath` and `field`, and the model's `context_tokens`: [first-provider step U3](first-provider.md#u3-choose-your-provider).

- **The key never goes in a file on this host,** and never in `providers.yaml`, which names only where it is in Vault.
- **Use the model's documented window** for `context_tokens`. `output_tokens` is optional; it rides on every prompt, and the intent record carries it (`docs/configuration.md` §6.1.1).
- **Rotating the key needs no restart.** Each turn reads it fresh under your login; nothing caches it.

### 7. Grant the prompt

Append to `/etc/maknae/authz.yaml`. `tee -a` keeps its owner, mode and label. Step 9's restart applies it; a daemon that is already serving applies it at the next reload, `sudo systemctl reload maknaed` ([Reload the policy](#reload-the-policy)):

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

**Grant `admin`, not `user`.** The shipped `bindings.yaml` has no `bindings:` key, and without one the enrolled principal resolves to **`admin`** (`crates/maknae-authz-basic/src/binding.rs`). If you add `bindings:`, that default stops applying and the grants belong under whichever role you bind ([Bind a user, contain a subject](#bind-a-user-contain-a-subject)).

The shipped path rules already allow `Read(~/**)` and `Write(~/projects/**)`, so the write target must be under `~/projects/`.

### 8. Prepare the files

```bash
mkdir -p ~/projects/maknae-242
printf 'Maknae is a security kernel for AI agents.\n' > ~/projects/maknae-242/input.txt
rm -f ~/projects/maknae-242/output.txt
```

**Do not create `output.txt`.** The kernel decides the write and records its intent; the CLI creates the file under your own permissions and reports the outcome. The kernel does not read or write your files (ADR-0009, #365).

Before any re-run of step 10, repeat `rm -f ~/projects/maknae-242/output.txt`. A second write to the same file takes the replace lane (`mutation.operation:"WriteExisting"`), and since #388 the agent may replace only a file it has read (§12b): a re-run without the `rm` meets an `output.txt` this conversation never read, so the trail shows a first `fs.write` ending `ReportedPathChanged` with no effect, then an `fs.read` of `output.txt`, then the write that lands.

### 9. Start

```bash
sudo systemctl enable --now maknae-egress.socket
sudo systemctl enable maknaed && sudo systemctl restart maknaed
systemctl is-active maknaed maknae-egress.socket
unset MAKNAE_CONFIG_DIR                      # Chapters 2–3 set it; enroll's CLI config is ~/.maknae
maknae login                                 # see first-provider step U1
maknae ping                                  # expect: pong
```

`maknae login` asks for your Vault password and stores a token; every CLI verb, `maknae ping` included, needs it, and without one fails with `` maknae: no Vault token is stored: run `maknae login` ``. What it prints, where it keeps the token and how long it lasts are in [first-provider step U1](first-provider.md#u1-log-in).

**Restart, don't just enable.** The authorized provider set is read at boot, and `enable --now` does nothing to a daemon that is already running. A daemon that booted with no providers refuses every prompt: the user sees `maknae agent: stopped: ` and the CLI's generic refusal text, and the administrator's `jq` over the trail (step 11) shows the reason `no model access: no providers are authorized on this host`.

- **The deputy is socket-activated.** It starts on the first prompt. It makes no Vault login and does not contact Vault at start-up; it reaches Vault only per turn, to unwrap the user's key.
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
| Boot composition evidence | `event:"boot"`, `action:"authz"`, reason `authorization composition: …; system: …; ceiling: …`, and `policy_sha256`, the digest of the policy the daemon starts with. Written at every boot, before serving |
| `session.prompt` intent | `object:"provider:openai"`, reason `intent recorded`, `egress.status:"IntentOnly"` with `content_length`, `content_digest`, `conversation` and `model` (the admitted model), and `output_tokens` when the user set a reply cap |
| `session.prompt` outcome | the same identity, `model` included, at a later `seq`: `egress.status:"Sent"` with `reply_length`, or a named failure (`Failed`, `DeadlineExpired`, `OutcomeUnknown`, `LandedUndelivered`). `prompt_tokens` and `completion_tokens` appear when the provider reported usage; they are the provider's claim, informational |
| `session.prompt` refused before send | the intent, then an outcome with `egress.status:"Failed"`: the deputy refused before any provider I/O (for example a seal it cannot open, or a wrapping token whose lookup fails). The deputy's journal names the cause (`OpenFailed(…)`) |
| `session.prompt` refused at admission | a single record, no `object` and no `egress` block: `result:"deny"`, posture `unauthorized`, reason `no model access: no providers are authorized on this host`, `provider not in the authorized set`, `model not on the authorized provider's list`, `local account has no name usable as a key path segment`, `key subpath malformed`, `key field malformed` or `session.prompt carries no provider choice` (`crates/maknae-kernel/src/provider_choice.rs`) |
| `session.prompt` refused by policy | a single record: `result:"deny"`, reason `role <r>: no rule for session.prompt` (no action grant) or `destination not allowlisted for role <r>: provider:<name>` (no destination) (`crates/maknae-authz-basic/src/decide.rs`) |
| `session.prompt` refused before intent | a single record: `result:"deny"`, reason `egress backend not ready`, `egress.status:"BackendUnavailable"`, with no intent ahead of it |
| `fs.read` intent | `object` = the canonical path, `mutation.phase:"Intent"`, `mutation.operation:"Read"`, `mutation.label:{"level":"UNCLASSIFIED","categories":[]}`, `mutation.requested_page` for a paged read, `origin:"KernelObserved"`, `status:"IntentOnly"`, no `content_length` |
| `fs.read` progress | `mutation.phase:"Progress"`, `origin:"ClientReported"`, `status:"ReportedProgress"`, `effects:[{…,"effect":"ReadFile","length":N,"range":{"start":S,"end":S+N},"lines":{"first":F,"last":L,"complete_last":…}}]` |
| `fs.read` completion | `mutation.phase:"Completion"`, `origin:"ClientReported"`, `status:"ReportedSuccess"` (or another `Reported*` status), `intent_seq` pointing at the intent |
| `fs.read` refused | `result:"deny"` with the reason, and no `mutation` block (e.g. `read descriptor missing` or `read evidence refused: …`) |
| `fs.write` intent | reason `authorized; intent alone does not establish execution`, `mutation.phase:"Intent"`, `mutation.label`, `mutation.operation:"WriteCreate"` (`"WriteExisting"` when replacing), `origin:"KernelObserved"`, `status:"IntentOnly"`, `content_length` (the length the request declared; the kernel never sees the bytes) |
| `fs.write` progress | `mutation.phase:"Progress"`, `origin:"ClientReported"`, `status:"ReportedProgress"`, with the created (`CreatedFile`) or replaced (`ReplacedFile`) file in `effects` |
| `fs.write` completion | `mutation.phase:"Completion"`, `origin:"ClientReported"`, `status:"ReportedSuccess"` (or another `Reported*` status), `intent_seq` pointing at the intent |
| `fs.write` refused | `result:"deny"` with the reason, and no `mutation` block (e.g. `mutation descriptor missing`, what an enforcing host without #365 PR 1 records) |
| `fs.write` descriptor refused | `result:"deny"`, reason `replacement evidence refused: descriptor confers access beyond location: …` (a descriptor that could read or write was delegated) |
| `fs.write` incomplete | `mutation.phase:"Completion"`, `status:"Incomplete"`, `intent_seq` pointing at the intent; the reason names what was lost (`attempt grant not delivered; no effect authorized`, `mutation acknowledgment not delivered; effects unknown`, or a missing report) |

There is **one `session.prompt` intent-and-outcome pair per model turn that is sent**, so a read-then-write conversation has several.

Every refusal reaches the user the same way: `maknae agent: stopped: ` followed by the CLI's generic refusal text (`docs/configuration.md` §6.1.1), exit `2`. The reasons in the table are what the administrator's `jq` shows; they never reach the user's terminal.

**Correlation:**
- `session_id` is per connection and each turn is a connection, so it does **not** group the conversation.
- `conversation` does. It is in `egress.conversation` on prompt records and top-level on `fs.write` and `fs.read`.

### 12. The refused turns

- **An oversize read** is no longer refused: reads are paged (§12a).
- **At the context budget.** Set `context_tokens: 4096` (and no `output_tokens`) in your entry in `~/.maknae/providers.yaml`. Create two files, each inside one page: `for n in 1 2; do head -c 6000 /dev/urandom | base64 > ~/projects/maknae-242/half$n.txt; done` (about 8 KB each). Ask the agent to read both. As the transcript grows, the loop prints `warning: this conversation is at …% of the declared context budget (… of 4,096 tokens)` once it passes 80% and again past 95%; one large read can jump straight past both, so a warning line is not guaranteed. Before a turn would exceed the budget, it stops: `maknae agent: stopped: the conversation has reached the declared context budget; compaction arrives with #171`, exit `2`. The trail has no intent for the stopped turn, because nothing was sent. Restore `context_tokens` afterwards.

### 12a. Paged reads

Every read is paged: each page is its own decided, recorded `fs.read` attempt of at most 64 KiB (`READ_PAGE_MAX_BYTES`).

- **Stream a whole file.** `head -c 70000 /dev/urandom | base64 > ~/projects/maknae-242/big.txt`, then `set -o pipefail; maknae read ~/projects/maknae-242/big.txt | cmp - ~/projects/maknae-242/big.txt; echo $?` prints `0`. Each page is its own intent (with `requested_page` and `label`), progress (with the page's `range` and `lines`) and completion.
- **Binary content streams byte-exactly too.** `head -c 70000 /dev/urandom > ~/projects/maknae-242/big.bin; set -o pipefail; maknae read ~/projects/maknae-242/big.bin | cmp - ~/projects/maknae-242/big.bin; echo $?` prints `0`.
- **One page.** `maknae read --offset 2 --limit 1 <file>` prints that page and names the next position on stderr (`next: line L column C`, or `eof`). `--column` continues a long line.
- **A file that changes.** Maknae does not lock the file: Unix locks are advisory and a held lock would hang your own tools. A file written while a page is read refuses that page (`PathChanged`, nothing released). A file that changes between pages, edited in place or replaced, stops `maknae read` with `file changed during the read`, and the agent sees `"changed": true` and reads again. Detection rests on size and timestamps, so a same-size edit within one timestamp tick is not seen.
- **Practical ceiling.** Each page rescans the file from the start, and each page is its own connection with about four audit records, so a very large file is slow; past roughly 6 GB, one page exceeds the default 5 s `read_timeout_ms`.
- **The agent.** `read_file` takes `offset`, `limit` (default 2000 lines) and `column`, and returns the page as JSON with the file's text only in `content`. The loop's prompt cap follows `provider.context_tokens` (about 768 KB for a 128,000-token window), so a full 64 KiB page fits alongside the rest of the conversation.

### 12b. Read before write

Since #388 the agent replaces an existing file only if it has read that file in this conversation and the file has not changed since — Claude Code's rule. A new file needs no read.

- **What the model is told.** `not written — the file exists and you have not read it; read it first, then write`, or `not written — the file changed since you read it; read it again, then write`. Nothing was written in either case; the model reads, then writes again. A path the policy refuses is still answered `outcome unknown` and never "read it first": the check runs only after the kernel grants the attempt.
- **What changes count.** The device, inode, size and modification time. A change to permissions or extended attributes alone (`chmod`, `restorecon`) does not refuse a write. A same-size edit within one timestamp tick is not seen, as for paged reads (§12a).
- **The agent's own writes.** An applied write records the written file's version, so the agent may write the same file again without reading it.
- **The trail.** A refused replacement has its `fs.write` intent, as every write does, and a completion with `ReportedPathChanged` and no effect. Since #388 that completion can mean "the agent had not read the file, or it changed since", not only a race. The agent's user sees it only in the model's answer and the trail; nothing is printed to the terminal.
- **Try it.** `printf 'keep me\n' > ~/projects/maknae-242/existing.txt`, then `maknae agent "Replace $HOME/projects/maknae-242/existing.txt with the word hello."` It exits `0` either way, and what the trail shows depends on the model. A model that follows the `write_file` description reads first: an `fs.read`, then one applied `fs.write`. A model that writes blind is refused: an `fs.write` ending `ReportedPathChanged`, then the `fs.read`, then the applied `fs.write`. To see the refusal regardless of the model, edit the file between the agent's read and its write (the "changed since you read it" case).
- **`maknae write` is not checked.** A human may replace a file without reading it, as before.
- **Write-permitted, read-denied paths.** If your policy — or the file's own mode, such as `0200` — lets the subject write a path but not read it, the agent cannot replace an existing file there: it is told to read first, and the read is refused. That answer also tells the model a file exists at that path. The shipped policy keeps its read and write denies symmetric; a file mode can still do it.
- **A refused write still opens the file for writing.** The check runs after the ordinary refusals, which need the file opened for writing, so a tool watching for write-closes (an IDE, a build watcher) sees one, although the bytes, size and modification time are unchanged.

### 13. Custody check (manual)

The custody assertion is **not built** (ADR-0023, ADR-0026). Check it by hand.

**On Linux:**

```bash
id                                                   # the operator: in maknae, not _maknae or _maknae-egress
sudo stat -c '%U:%G %a %n' /etc/maknae /etc/maknae/private /etc/maknae/egress \
  /etc/maknae/private/maknae-egress-seal-key.cred
sudo getfacl -p /etc/maknae
sudo test -e /run/credentials/maknae-egress.service/maknae-egress-seal-key && echo "runtime credential present"
for f in /etc/maknae/private/maknae-egress-seal-key.cred \
         /run/credentials/maknae-egress.service/maknae-egress-seal-key; do
  test -r "$f" && echo "READABLE: $f" || echo "not readable: $f"
done
sudo -u _maknae test -r /etc/maknae/private/maknae-egress-seal-key.cred && echo "READABLE by _maknae" || echo "not readable by _maknae"
```

- **Expected owners and modes:** `/etc/maknae` `root:_maknae 750`, with an ACL entry for `_maknae-egress` only; `private/` `root:_maknae 750`; `egress/` `root:_maknae-egress 750`; the sealed seal key `root:root 400`.
- **Expected reads:** every `test -r` says `not readable`, for the operator and for `_maknae`.
  - The operator's `not readable` proves only that `/etc/maknae` (`root:_maknae 750`) cannot be traversed. Judge the file modes from the `stat` output. The same holds for `_maknae`, which can traverse `private/` but not read a `root:root 400` file.
  - The runtime credential exists only once the deputy has started. Run `maknae agent` once, and confirm `runtime credential present` before reading its `test -r` line.
- **What this check does not cover:** your own processes can read your key. Your Vault login reads it, so any process running as you can make its own wrapped read, unwrap it and call the provider without `maknaed` — the agent loop included (ADR-0028). Each such read is in Vault's audit log under your identity. That lies outside the file-custody claim; state it alongside the result.

**On macOS**, run this from a console session:

```bash
id                                                   # the operator: in maknae, not _maknae or _maknae-egress
sudo stat -f '%Su:%Sg %Lp %N' /etc/maknae /etc/maknae/private /etc/maknae/egress \
  /etc/maknae/private/maknaed-secret-id.keychain /etc/maknae/egress/maknae-egress-secret-id.keychain
ls -led /etc/maknae
sudo -u _maknae security find-generic-password -s io.maknae.maknae-egress -a secret-id -w /Library/Keychains/System.keychain >/dev/null; echo "exit $?"
security find-generic-password -s io.maknae.maknaed -a secret-id -w /Library/Keychains/System.keychain >/dev/null; echo "exit $?"
```

- **Expected owners and modes:** `/etc/maknae` and `private/` `root:_maknae 750`; `egress/` `root:_maknae-egress 750`; `maknaed-secret-id.keychain` `root:_maknae 640`; `maknae-egress-secret-id.keychain` `root:_maknae-egress 640`; `ls -led` shows one ACL entry, `user:_maknae-egress allow list,search`.
- **What the items hold.** The `io.maknae.maknaed` item holds `maknaed`'s Vault SecretID. The `io.maknae.maknae-egress` item keeps its name, but holds the Egress Daemon's **sealing private key** (ADR-0028 §6), not a SecretID.
- **Expected reads:** each `security` read raises an administrator-approval dialog; deny it, and the command exits 128 (`errSecUserCanceled`, -128). **Deny both dialogs:** `>/dev/null` keeps the value off the terminal, but an administrator who approves one has read it.
  - **If the `maknaed` dialog was approved,** rotate its SecretID by running step 3's `sudo maknae enroll` again with the same arguments.
  - **If the egress dialog was approved,** the sealing private key is exposed. Run step 3's full `sudo maknae enroll` invocation again with `--rotate-seal-key` added. It needs your administrator Vault token, and it also rotates `maknaed`'s SecretID. Then restart the deputy, as the enroll output says: `sudo launchctl kickstart -k system/io.maknae.maknae-egress`. Until that restart, the running deputy holds the old key and every turn is recorded `Failed`.
- The same "does not cover" note applies.

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
- **The provider key lives only in Vault, under your own login.** Each turn the CLI makes a wrapped read of it and seals the wrapping token to the Egress Daemon's `seal.pub`; the kernel admits the turn on the provider, the model and your account name and never sees the key; the deputy, which has no Vault identity of its own, opens the seal and unwraps the key once. Your own processes can read the key too (step 13).
- **The trail shows each decision and its outcome in order**, with the boot composition record ahead of them.

### Teardown

```bash
sudo systemctl disable --now maknae-egress.socket maknae-egress.service
sudo rm /etc/maknae/config.d/10-provider.yaml
sudoedit /etc/maknae/authz.yaml                 # remove the roles:/destinations: block from step 7
sudo systemctl restart maknaed
sudo /usr/libexec/maknae/maknae-selinux-ports.sh remove 8200
rm -r ~/projects/maknae-242
rm ~/.maknae/providers.yaml
maknae logout                                   # revokes your Vault token and erases it
```

`/etc/maknae/egress-bounds.yaml` is enroll's; with no providers authorized it is not read, so it can stay.

**Retiring your key.** You delete it yourself, with your own login: the `maknae-user` policy grants `delete` on your own `metadata/` path (`deploy/vault-pki/main.tf`), and deleting the metadata removes every version. Get a token as in [first-provider step U2](first-provider.md#u2-store-your-key-in-vault), with the same `VAULT_ADDR` and `VAULT_CACERT`, then paste it at the prompt. This form is not yet measured:

```bash
read -rsp "Maknae user token: " VT && echo && VAULT_TOKEN="$VT" vault delete <kv_mount>/metadata/<user_prefix>/<username>/<subpath>; unset VT
```

With enroll's defaults and the subpath `openai`, the path is `maknae-kv/metadata/maknae/users/<username>/openai`. Use `vault delete`, not `vault kv metadata delete`: `vault kv` first queries `sys/internal/ui/mounts`, which your user token (it has no `default` policy) may not be allowed.

---

## Reload the policy

`maknaed` decides every request from a snapshot of `/etc/maknae/authz.yaml` and `/etc/maknae/bindings.yaml` compiled when it starts. An edit to either file changes nothing until you reload the daemon or restart it:

```bash
sudo systemctl reload maknaed                          # Linux
sudo launchctl kill SIGHUP system/io.maknae.maknaed    # macOS
```

Both send `SIGHUP`, as does `kill -HUP <pid>` for a daemon started by hand. The command returns before the reload finishes, so read the result in the trail.

- **What a reload reads.** `authz.yaml` and `bindings.yaml`, together, as one policy. The principal, the classification system and ceiling, the transport, the audit configuration and the providers are read at start, and a change to any of them needs a restart.
- **All or nothing.** A reload loads and validates both files and resolves every username in `bindings.yaml` on the host, as a start does, so a new username needs only a reload. If either file fails (it does not parse or validate, `authz.yaml` still carries `bindings:`, or an account lookup fails rather than finding no such user), the reload is refused before it touches the store, and the running policy stands; an `authz.yaml` edit made at the same time as a refused `bindings.yaml` edit does not apply either. A name with no account on the host does not refuse the reload: that name alone is affected, and a `graph.identity` record reports it ([Bind a user, contain a subject](#bind-a-user-contain-a-subject); configuration §2.3 lists what refuses the whole file and what is decided per subject). A reload refused while writing the store also keeps the running policy; see the first case under "Records that look out of order" below. The journal (`journalctl -u maknaed`; on macOS `/usr/local/var/log/maknae/maknaed.err`) says `maknaed: reload refused: <cause>; the previous policy stands`. An invalid `authz.yaml` or `bindings.yaml` at start refuses to start, with exit 3.
- **One at a time.** Reloads run in turn. Signals that arrive while one runs produce one more reload, and a `SIGHUP` sent while the daemon is starting is applied once it serves. One that lands in the first milliseconds of the process, before its handler exists, ends it; systemd (`RestartForceExitStatus=SIGHUP`) and launchd (`KeepAlive`) start it again, after `RestartSec` (5 seconds) on Linux.
- **Stopping.** A graceful stop abandons a reload that is still loading the file, recorded as `reload refused: shutdown`. It waits up to 5 seconds for a reload that already holds its turn (writing the store or its audit records), then stops without it, so the stop record and the token revoke never wait on a reload for longer than that.

**What the trail shows.** Each reload is its own session, and its records carry `event:"reload"`, so a query that selects `event=="boot"` does not see them. In order:

| Record | Shape |
|---|---|
| Intent | `action:"graph.reload"`, `result:"permit"`, reason `intent recorded (SIGHUP)`, `graph.anchor:"reloading"` |
| Release (only when a containment ends) | `action:"graph.identity"`, `result:"permit"`, posture `authorized`, `graph.anchor:"releasing"`, reason `uid <n> ('<name>') is no longer contained: <cause>`, one per containment the new bindings end, at the next store revision and written ahead of the store transition. The cause is `its name is no longer listed under adversary`, `its name now resolves to uid <m>`, `it is now listed under <role>`, `bindings.yaml now binds nobody` (its `bindings:` key lists no entry) or `bindings.yaml has no bindings: key, so the enrolled principal is admin and nobody else holds a role`. A release counts only when a `graph.checkpoint` with reason `transitioned` follows at the same revision. |
| Principal admin (only when explicit bindings end) | `action:"graph.identity"`, `result:"permit"`, posture `authorized`, `graph.anchor:"promoting"`, reason `uid <n>, the enrolled principal, now holds admin: bindings.yaml has no bindings: key`, once, when the store held a `bindings:` key and the new `bindings.yaml` has none, whether or not anything was contained. It is at the next store revision, after any releases and ahead of the store transition, and like a release it counts only when a `transitioned` checkpoint follows at the same revision. |
| Store transition (only when the bindings changed) | `action:"graph.transition"`, reason `intent recorded (root-file)`, at the next store revision; then `action:"graph.checkpoint"`, reason `transitioned`, with that revision and the new store's `ciphertext_sha256` |
| Outcome, applied | `action:"graph.reload"`, `result:"permit"`, posture `authorized`, reason `reload applied: revision <n>; identity persisted` (or `identity unchanged`), followed by `; store not durable: <cause>` and `; checkpoint append failed: <cause>` when those happened, `graph.anchor:"reloaded"`, and `policy_sha256` of the policy now in force |
| Outcome, refused | `action:"graph.reload"`, `result:"deny"`, posture `unavailable`, reason `reload refused: <cause>`, where the cause starts `policy load:`, `compile:` or `persist:`, or is `shutdown`; `graph.anchor:"reload-refused"`, and `policy_sha256` of the policy that stands. A missing `bindings.yaml` over explicit bindings is `reload refused: policy load: bindings.yaml is missing but the store holds explicit bindings; …`, and a store whose bindings still come from `authz.yaml` is `reload refused: policy load: the store holds explicit bindings from authz.yaml; paste the bindings: block into /etc/maknae/bindings.yaml` ([upgrading](upgrading.md#bindings-move-to-bindingsyaml-496)) |
| Identity problem (applied reloads only) | `action:"graph.identity"`, `result:"deny"`, posture `unauthorized`, or `unavailable` for a name under `adversary` that has no account; reason as in [Bind a user, contain a subject](#bind-a-user-contain-a-subject); after the applied outcome, one per problem the previous load did not have, so an unchanged reload writes none. A refused reload writes none |

`policy_sha256` is the SHA-256 of one `<section>=<sha256 of the section's canonical JSON>` line per top-level section of `authz.yaml`, plus a `bindings=` line for `bindings.yaml`'s `bindings:` section when it has one, in section-name order. Moving a `bindings:` block unchanged from `authz.yaml` to `bindings.yaml` keeps the value. Two loads of the same policy carry the same value, and a reload that changed only `permissions:`, which leaves the store as it was, still carries a new one. It covers the text of the two files only, not the uids their names resolve to: a reload after only a bound account's uid changed carries the same `policy_sha256` and a new `graph.revision`, which tells the two apart.

```bash
sudo jq -c 'select(.action=="graph.reload") | {ts, session_id, result: .outcome.result, reason: .outcome.reason, policy: .policy_sha256}' /var/log/maknae/audit.jsonl | tail -n 2
```

If the intent itself cannot be appended, nothing is loaded and no outcome is written; the journal says `reload refused: audit append failed: <cause>`. Each reload audit record is given 5 seconds. An intent or store record that cannot be appended in that time refuses the reload, the running policy stands, and the next `SIGHUP` runs; an outcome or identity record that cannot is reported in the journal, and the reload it describes stands.

**At boot** the trail carries the same `graph.identity` records: each release and the principal-admin record ahead of the store transition that makes them, as above, and each identity problem after the `authz` composition record. A problem record that cannot be appended at boot refuses the start, like every boot record.

**`maknae status`** prints `kernel graph: revision <n> (<state>)`. The revision follows every reload that changed the bindings. The state is the result of this start's rollback check (`seeded`, `reseeded`, `verified`, `advanced` or `rollback-anchor-unavailable`) and stays the same until the next restart. When the last applied load had identity problems it also prints their counts by kind, such as `identity problems: 1 unresolved, 1 carried forward`; the kinds are `unresolved`, `unresolved adversary`, `contained`, `unbound conflict`, `carried forward`, `released` and `principal admin`, and a release or a principal admin is counted until the next applied load. The problem list and the subject list are published just after the new snapshot is installed, so for an instant `maknae status` and `maknae subject-list` can still describe the previous load.

**Records that look out of order.** Seven cases leave the trail looking unusual. In each, the store and the trail agree once the next start has checked them, or that start refuses.

- **A `graph.transition` with no `graph.checkpoint` after it, then `reload refused: persist: …`.** The store write failed after its intent was recorded, and the running policy is the previous one. Nothing reached disk: sealing the store failed, or writing or renaming its temporary file failed (a full or failing disk). Any later reload that changes the bindings rewrites that revision and checkpoints it. Otherwise the next start loads the store and applies `authz.yaml` as a new transition if the file differs from it.
- **`reload applied: …; store not durable: <cause>`.** The new store was renamed into place, then the directory `fsync` failed. The new policy is in force and the store holds it, with its checkpoint, but a crash before the file system flushes the directory can bring back the previous store, and the next start then refuses it as rolled back against that checkpoint ([The kernel graph store refuses to start](#the-kernel-graph-store-refuses-to-start)). Check the file system. At start, the same failure on a seed, migration or transition is not a refusal: `maknaed` starts and the journal says `kernel graph store revision <n> is in place but may not survive a crash: <cause>`.
- **`reload applied: …; checkpoint append failed: <cause>`.** The new policy is in force and the store holds it, but the trail has no checkpoint for it; the next start reports `advanced`.
- **Reload records after the stop record.** A reload in flight can append its records after the stop record, `reload refused: shutdown` included, in two cases: when `maknaed` exits because its credential supervisor stopped, and when a graceful stop gives up its 5-second wait for a reload that is writing the store. They carry their own session id and match the store.
- **A reload intent with no outcome record.** The daemon exited while a reload was still writing; a `graph.transition` may follow the intent with no checkpoint. The next start checks the store as above and reports what it found.
- **A `graph.identity` release or principal-admin record (`graph.anchor:"releasing"` or `"promoting"`) with no `transitioned` checkpoint at its revision.** These records are written ahead of the store write, at boot and at reload. A failure after they are appended (the transition intent, the store write, an abort) leaves them with nothing after them, and what they name did not happen: the store and the running policy still hold the containment and the explicit bindings. Only a record followed by a `transitioned` checkpoint at the same revision happened.
- **An applied reload with no `graph.identity` record for a problem it reports.** An identity problem record that cannot be appended after an applied reload goes to the journal only (`maknaed: AUDIT WRITE FAILED on an identity record (<reason>): <cause>`) and is not retried; the policy is applied, and `maknae status` and `maknae subject-list` show the problem.

---

## Bind a user, contain a subject

Who holds which role on this host, and who is contained, is `/etc/maknae/bindings.yaml` (configuration §2.3). `authz.yaml` holds what each role may do. Edit `bindings.yaml` in place, then reload:

```bash
sudoedit /etc/maknae/bindings.yaml
sudo systemctl reload maknaed                          # Linux
sudo launchctl kill SIGHUP system/io.maknae.maknaed    # macOS
```

```yaml
schema_version: 1
bindings:
  admin: ["alice"]
  user: ["bob"]
  adversary:
    - "mallory"
    - uid: 4242
```

- **Once a `bindings:` key exists, only the entries it lists hold a role.** List yourself under `admin`. With no `bindings:` key, as shipped, the enrolled principal holds `admin`. Do not delete the file to return to that default: over explicit bindings a missing file refuses the start and the reload. Remove the `bindings:` key instead.
- **Contain a subject** by listing its username under `adversary`, or its id as `- uid: <n>`. A `uid:` entry contains the id whether or not an account has it, and does not depend on the user directory.
- **Containment wins.** A uid listed under `adversary` and under another role is contained, and a `graph.identity` record says so: `uid 1003 (mallory) is under adversary, user; containment wins and it is contained`.
- **One uid under two other roles holds no role**, whether by one name or two: `uid 1002 (gus, gustav) is under guest, user; it holds no role`. Keep one of them.
- **A name with no account holds no role**, and the rest of the file loads: `'bob' under user has no account on this host; it holds no role`. Under `adversary`, the name contains nothing: `'trudy' under adversary has no account on this host, so the name contains nothing; a "- uid: <n>" entry contains an id whether or not it has an account`.
- **Release a containment** by deleting its entry and reloading. The reload records one release per containment it ends, ahead of the store write: `uid 1003 ('mallory') is no longer contained: its name is no longer listed under adversary`. A typo in a contained name (`malory` for `mallory`) also ends that containment, and the release record shows it.

Read the result:

```bash
maknae subject-list
maknae status
sudo jq -c 'select(.action=="graph.identity") | {ts, event, result: .outcome.result, posture: .outcome.posture, reason: .outcome.reason}' /var/log/maknae/audit.jsonl | tail -n 20
```

`maknae subject-list` prints one row per subject the file names, with its uid, the role it is listed under, a label and its state. The labels come from the last applied load, never from a live account lookup:

```text
UID   ROLE       SUBJECT                 STATE
0     admin      root (uid 0)            bound admin
666   adversary  uid 666 (mallory)       contained (carried forward)
1002             uid 1002 (gus, gustav)  unbound (conflict: guest, user)
-     user       ghost (no account)      unresolved (no account)
-     adversary  trudy (no account)      unresolved adversary (no account, not contained)
```

A contained subject is one row, labelled with every name under `adversary` that claims it; the `containment wins` record names any other role it is also listed under. A carried-forward row also lists the names whose bindings it overrides.

`maknae status` prints only the counts by kind, with no names or uids. Each is a separate grant: `admin.subject.list` discloses who holds what, and `admin.status` does not.

A subject that holds no role is decided like any uid the file does not list, which denies in the default build. A contained subject is denied by a mandatory decision that nothing overrides.

**When the user directory is down.** sssd or LDAP being unavailable usually reads as "no such user", the same as a deleted account, and on macOS a failed lookup cannot be told from a missing account at all. A contained name that stops resolving stays contained under its stored uid (carried forward) until you remove it from `adversary:`. The record says `'mallory' under adversary no longer resolves; uid 666 stays contained (carried forward)`, followed by `; this overrides <name> (<role>)` if another name in the file now has that uid. A name that never resolved is not contained, and a role binding to a directory name holds no role until the directory is back. After an outage at a reload or at boot, reload once the directory is back. On Linux the unit's ordering after `nss-user-lookup.target` waits only for the local lookup services (such as sssd) to start, not for the directory server; launchd has no such ordering. A lookup that fails with an error other than "no such user" refuses the whole load (`looking up '<name>' failed (errno <n>); nothing was changed`). On macOS that includes an account whose passwd record is larger than 4 KiB, which refuses every load while the file names it (#501).

---

## The audit trail

The trail is `/var/log/maknae/audit.jsonl`, `_maknae:_maknae 0640` in a `0700 _maknae` directory. On Linux the file carries the append-only attribute (`chattr +a`), set by the package on every install and upgrade: writes only append, and truncating, unlinking or opening the file for writing without `O_APPEND` is refused, root included. On Debian the attribute is the trail's only append-only control, because AppArmor cannot express append; on the Red Hat family SELinux enforces it as well. Check it with `lsattr /var/log/maknae/audit.jsonl`, which shows `a`. On macOS the file carries `uappnd` (`ls -lO`).

### Rotate, restore or recreate the trail

While the attribute is clear, nothing else keeps the trail append-only on Debian, so stop the daemon first: it holds the file open. Root then holds the directory: it takes it to root, removes every ACL entry, sets `0700` and checks all three before it acts, so the daemon account cannot swap `audit.jsonl` for a link to another file while root acts on it. Owning the directory is not enough on its own, because an ACL entry or a group or other write bit left by `_maknae` would still let it change the directory's entries. The archived copy stays in `/var/log/maknae`, owned by root and append-only, so neither the daemon account nor a rotation can rewrite or remove it.

On Linux:

```bash
sudo systemctl stop maknaed.service
sudo bash -eu <<'ROTATE'
d=/var/log/maknae f=/var/log/maknae/audit.jsonl
[ -d "$d" ] && [ ! -h "$d" ] || { echo "$d is not a directory" >&2; exit 1; }
chown root:root "$d"
setfacl -P -b "$d"
chmod 0700 "$d"
acl="$(getfacl -P -s -p "$d")"
[ "$(stat -c '%u %g %a' "$d")" = "0 0 700" ] && [ -z "$acl" ] || { echo "$d is not root:root 0700 with no ACL; it is left root-owned" >&2; exit 1; }
if [ -h "$f" ] || [ ! -f "$f" ] || [ "$(stat -c %h "$f")" != 1 ]; then
    echo "$f is not a regular, single-link file; $d is left root-owned" >&2; exit 1
fi
a="$f.$(date -u +%Y%m%dT%H%M%SZ)"
chattr -a "$f"
mv "$f" "$a"
chown root:root "$a"
chattr +a "$a"
install -m 0640 -o _maknae -g _maknae /dev/null "$f"
if command -v restorecon >/dev/null; then restorecon "$a" "$f"; fi
chattr +a "$f"
for x in "$a" "$f"; do
    lsattr -d "$x" | cut -c6 | grep -qx a || { echo "$x is not append-only; $d is left root-owned" >&2; exit 1; }
done
chown -h _maknae:_maknae "$d"
ROTATE
sudo systemctl start maknaed.service
```

On macOS:

```bash
sudo launchctl bootout system/io.maknae.maknaed
sudo bash -eu <<'ROTATE'
d=/var/log/maknae f=/var/log/maknae/audit.jsonl
[ -d "$d" ] && [ ! -L "$d" ] || { echo "$d is not a directory" >&2; exit 1; }
chown 0:0 "$d"
chmod -N "$d"
chmod 0700 "$d"
[ "$(stat -f '%u %g %Lp' "$d")" = "0 0 700" ] && [ "$(ls -led "$d" | wc -l)" -eq 1 ] || { echo "$d is not root 0700 with no ACL; it is left root-owned" >&2; exit 1; }
if [ -L "$f" ] || [ ! -f "$f" ] || [ "$(stat -f %l "$f")" != 1 ]; then
    echo "$f is not a regular, single-link file; $d is left root-owned" >&2; exit 1
fi
a="$f.$(date -u +%Y%m%dT%H%M%SZ)"
chflags nouappnd "$f"
mv "$f" "$a"
chown 0:0 "$a"
chflags uappnd "$a"
install -m 0640 -o _maknae -g _maknae /dev/null "$f"
chflags uappnd "$f"
for x in "$a" "$f"; do
    stat -f %Sf "$x" | grep -q uappnd || { echo "$x is not flagged uappnd; $d is left root-owned" >&2; exit 1; }
done
chown -h _maknae:_maknae "$d"
ROTATE
sudo launchctl bootstrap system /Library/LaunchDaemons/io.maknae.maknaed.plist
```

The block refuses unless both files carry `a` (Linux) or `uappnd` (macOS). On macOS, `_maknae` owns the live file and can clear `uappnd` on it; it cannot clear the flag on the root-owned archive. To restore a copy instead of starting an empty trail, give the copy's path in place of `/dev/null`. If the block refuses or stops with an error, leave the daemon stopped and work through [The package refuses the audit trail](#the-package-refuses-the-audit-trail). A recreated file loses any ACL granted to a log agent; re-apply it ([Granting the agent read access](../packaging/README.md#granting-the-agent-read-access)). A trail without a `graph.checkpoint` record starts with [`rollback-anchor-unavailable`](#rollback-anchor-unavailable).

### The package refuses the audit trail

The Debian `postinst`, the RPM `%post` and the macOS `postinstall` act on `/var/log/maknae/audit.jsonl` as root. Before they act, they take the directory to root (`0:0`), remove every ACL entry on it, set it `0700` and check the result, and they refuse an entry that is not what the package created:

```
maknae: cannot hold /var/log/maknae as root:root 0700 with no ACL; it is left root-owned
maknae: /var/log/maknae/audit.jsonl is not a regular, single-link _maknae:_maknae file; /var/log/maknae is left root-owned
maknae: cannot set the append-only attribute on /var/log/maknae/audit.jsonl (filesystem: <type>); /var/log/maknae is left root-owned
```

(macOS prints `as root 0700` and `is not a regular, single-link file`.) The first message means the directory could not be taken to root `0700` with no ACL entry; on Linux, check that `setfacl` and `getfacl` are installed (the `acl` package) and that the file system accepts them. The second means the entry is a symbolic link, a directory or other non-regular file, a file with a second hard link, or a file owned by another account. A symbolic link or a second link is what a compromised daemon account would plant to make root act on another file, so treat it as a possible compromise until you know otherwise. The third means the file system cannot hold the attribute. In every case the directory stays root-owned, so `maknaed` cannot open the trail and the next start fails. On Debian the package stays half-configured. On the Red Hat family, rpm reports the scriptlet failure but keeps the install. On macOS, the installer fails. While the directory is root-held, `rpm -V maknae` reports `UG` on `/var/log/maknae`.

A refused upgrade does not stop the old daemon: it keeps running on the descriptor it already holds. Stop it before you touch the trail, so nothing writes to the file while its protection is lifted:

```bash
sudo systemctl stop maknaed                          # Linux
sudo launchctl bootout system/io.maknae.maknaed      # macOS
```

Inspect the entry without following it:

```bash
sudo ls -la /var/log/maknae
sudo stat /var/log/maknae/audit.jsonl                               # stat does not follow a symlink
sudo find / -xdev -samefile /var/log/maknae/audit.jsonl 2>/dev/null # every name of a multiply-linked file
```

To recover, first hold the directory completely, because a refused hold can leave an ACL entry or a write bit in place. On Linux:

```bash
sudo bash -eu <<'HOLD'
d=/var/log/maknae
[ -d "$d" ] && [ ! -h "$d" ] || { echo "$d is not a directory" >&2; exit 1; }
chown root:root "$d"
setfacl -P -b "$d"
chmod 0700 "$d"
acl="$(getfacl -P -s -p "$d")"
[ "$(stat -c '%u %g %a' "$d")" = "0 0 700" ] && [ -z "$acl" ] || { echo "$d is not root:root 0700 with no ACL; it is left root-owned" >&2; exit 1; }
HOLD
```

On macOS:

```bash
sudo bash -eu <<'HOLD'
d=/var/log/maknae
[ -d "$d" ] && [ ! -L "$d" ] || { echo "$d is not a directory" >&2; exit 1; }
chown 0:0 "$d"
chmod -N "$d"
chmod 0700 "$d"
[ "$(stat -f '%u %g %Lp' "$d")" = "0 0 700" ] && [ "$(ls -led "$d" | wc -l)" -eq 1 ] || { echo "$d is not root 0700 with no ACL; it is left root-owned" >&2; exit 1; }
HOLD
```

If the block refuses, do not go on: find out what keeps the directory from being held. Then:

1. Preserve what is there: `sudo cp -a /var/log/maknae /root/maknae-audit-evidence.$(date -u +%Y%m%dT%H%M%SZ)` (`cp -a` copies a link as a link).
2. Move the entry aside. `mv` moves a link itself, never its target: `sudo mv /var/log/maknae/audit.jsonl /root/`. If the entry is your own trail with the wrong owner (for example a copy restored as root), and `stat` shows a regular file with one link, re-own it instead: `sudo chattr -a` (macOS: `chflags nouappnd`), then `sudo chown -h _maknae:_maknae`, on that path (with the daemon stopped, as above).
3. For the attribute failure, put `/var/log/maknae` on a file system that supports `chattr +a` (ext4, xfs and btrfs do).
4. Re-run the package's configuration: `sudo dpkg --configure maknae`, `sudo dnf reinstall maknae`, or the macOS installer again. It creates the file when it is absent, sets the attribute, verifies it and hands the directory back. Then start `maknaed`.

### Remove a kept trail

Removing the package keeps the trail, except a Debian `purge`. On Linux the files keep `+a`, so `rm` is refused until it is cleared. Remove them with the daemon gone and the directory root-held. On Linux:

```bash
sudo bash -eu <<'REMOVE'
d=/var/log/maknae
[ -d "$d" ] && [ ! -h "$d" ] || { echo "$d is not a directory" >&2; exit 1; }
chown root:root "$d"
setfacl -P -b "$d"
chmod 0700 "$d"
acl="$(getfacl -P -s -p "$d")"
[ "$(stat -c '%u %g %a' "$d")" = "0 0 700" ] && [ -z "$acl" ] || { echo "$d is not root:root 0700 with no ACL; it is left root-owned" >&2; exit 1; }
find "$d" -xdev -mindepth 1 -maxdepth 1 -type f -links 1 -exec chattr -a {} +
rm -rf "$d"
REMOVE
```

On macOS:

```bash
sudo bash -eu <<'REMOVE'
d=/var/log/maknae
[ -d "$d" ] && [ ! -L "$d" ] || { echo "$d is not a directory" >&2; exit 1; }
chown 0:0 "$d"
chmod -N "$d"
chmod 0700 "$d"
[ "$(stat -f '%u %g %Lp' "$d")" = "0 0 700" ] && [ "$(ls -led "$d" | wc -l)" -eq 1 ] || { echo "$d is not root 0700 with no ACL; it is left root-owned" >&2; exit 1; }
find "$d" -xdev -mindepth 1 -maxdepth 1 -type f -links 1 -exec chflags nouappnd {} +
rm -rf "$d"
REMOVE
```

## The kernel graph store refuses to start

`maknaed` keeps its enforcement state in an encrypted store, `kernel.graph`, in its state directory: `/var/lib/maknae` on Linux, `/usr/local/var/db/maknae/state` on macOS. Each start checks the store against the latest `graph.checkpoint` record in the audit trail, and refuses to start when the store cannot be trusted. The refusal goes to the journal (`journalctl -u maknaed`) on Linux or to `/usr/local/var/log/maknae/maknaed.err` on macOS, as a first line naming the cause and, for every graph refusal, a second line naming the next step:

```text
maknaed: refusing to start: kernel graph store: graph store revision 3 is older than the audited checkpoint 7: rolled back
maknaed: if this is expected, run `sudo maknae reseed` and restart; a readable current kernel.graph is kept for forensics
```

**Exit codes:** a boot record that cannot be appended to the audit trail exits 1, graph records included; every other graph refusal exits 5.

`maknae status` prints the store's state once the daemon runs, as `kernel graph: revision <n> (<state>)`.

On an RPM host the package runs `restorecon -R` over `/var/lib/maknae`, which would relabel a foreign file hard-linked into the directory. It relies on `fs.protected_hardlinks=1`, the RHEL and Debian default; keep it set. `/var/log/maknae` has carried the same residual since before the graph store.

### The causes

In the table, `<dir>` is the state directory. Each first line starts `maknaed: refusing to start: `, and each second line starts `maknaed: `; both prefixes are left out.

| Cause | First line | Second line | Exit | What to do |
|---|---|---|---|---|
| Rolled back | `kernel graph store: graph store revision <n> is older than the audited checkpoint <m>: rolled back` | `` if this is expected, run `sudo maknae reseed` and restart; a readable current kernel.graph is kept for forensics `` | 5 | An older copy of the store, from a backup or snapshot, was put back. If you restored it yourself, reseed; otherwise investigate first. |
| Substituted | `kernel graph store: graph store at revision <n> differs from the audited checkpoint: substituted` | as for rolled back | 5 | The store is not the one the trail recorded at that revision. Investigate, then reseed. |
| Missing | `kernel graph store: graph store is missing but the audit trail holds checkpoint <n>` | as for rolled back | 5 | The store was deleted. Reseed. |
| Revision exhausted | `kernel graph store: graph store revision is exhausted; reseed cannot advance it` | `no automatic remedy; keep <dir> as it is and investigate` | 5 | The revision counter is at its maximum, which no real history reaches. Leave the directory as it is and investigate. |
| Does not decrypt | `kernel graph store: the graph store does not decrypt: tampered or truncated` | as for rolled back | 5 | The file is damaged. Reseed. The same second line follows the other envelope and decoding errors, such as `graph store is truncated` or `graph store does not decode: …`. |
| Key does not unwrap | `kernel graph store: the graph store key does not unwrap: wrong key or tampered header` | as for rolled back | 5 | The store was written under a different key, or its header was altered. If the key was replaced, reseed; otherwise investigate first. |
| Written by a newer version | `kernel graph store: the graph store was written by a newer maknaed: <detail>`, where `<detail>` is, for example, `unsupported graph store envelope version 2`, `unknown graph store cipher 2`, `unknown graph store key wrap 2`, `unsupported store format version 2` or `store schema version 2 differs from the binary's 1` | `this store was written by a newer maknaed; reinstall that version (do not reseed: that replaces a valid store)` | 5 | **Reinstall the newer version. Do not reseed:** the store is valid. |
| Store file refused | `kernel graph store: graph store file kernel.graph refused: <cause>` | `fix the ownership and mode of <dir>/kernel.graph (it must be _maknae, 0600, one link, ≤64 MiB), then restart; do not reseed — the store may be valid` | 5 | Fix the file and restart. A pending reseed does not replace a file that cannot be read: the start refuses, the marker stays, and the reseed completes at the first start after the file is fixed. |
| Rejected-copy name in use | `kernel graph store: the rejected-copy name <name> is in use and does not hold this store (<cause>); move it aside, then restart` | `move <dir>/<name> aside (the current store is intact), then restart; the authorized reseed will complete` | 5 | A reseed found its rejected-copy name held by something other than a copy of the current store. Nothing was written and the marker stays. Move that name out of the state directory and restart. See [Reseed](#reseed). |
| State directory refused | `kernel graph store: graph state directory refused: <cause>` | `check the ownership and mode of <dir>: it must be owned by the maknaed user, mode 0700` | 5 | Fix the directory: owner `_maknae`, mode `0700`. |
| Another maknaed running | `kernel graph store: another maknaed holds the kernel graph state directory` | `another maknaed is already running against <dir>; stop it before starting this one` | 5 | A second `maknaed` was started while one already holds the state directory. Stop the other instance, or leave it running and do not start this one. Do not reseed: the store is not at fault. |
| I/O failure while seeding | `kernel graph store: graph store I/O failed: <cause>` | as for the state directory | 5 | Writing the new store, its rejected copy or removing the marker failed. Check the directory and its file system. |
| Audit trail unreadable | `kernel graph store: graph store audit failed: <cause>` | `the audit trail anchors the graph store; check that the audit file is readable` | 5 | Check `/var/log/maknae/audit.jsonl`. |
| Audit append failure | `the boot graph record was not durably appended: <cause>`, or the same with `graph reseed` or `graph rejected-store` for `graph` | none | 1 | A boot record could not be written to the audit trail. Check the audit file and its file system. |
| No key | `` kernel graph key: no kernel graph key (<detail>): run `sudo maknae enroll` `` | `` run `sudo maknae enroll` to create the kernel graph key `` | 5 | Run `sudo maknae enroll` ([upgrading](upgrading.md#kernel-graph-store-488)), then restart. On Linux systemd refuses the unit first, with `status=243/CREDENTIALS`. |
| Forged vocabulary | `kernel graph store: graph store vocabulary refused: <cause>`, where `<cause>` is, for example, `compiled nodes differ from the digest they claim` or `the stored digest does not cover the stored compiled nodes` | as for rolled back | 5 | The store's role vocabulary does not match the digest it records, which an upgrade never produces. Investigate, then reseed. A store from an older binary is [migrated](#upgrades-migrate-the-store), not refused. |
| Identity layer does not build | `kernel graph store: the kernel identity layer does not build: <cause>` | `the identity layer is built from bindings.yaml in the configuration directory (/etc/maknae/bindings.yaml by default); correct it, then restart; do not reseed` | 5 | Correct `bindings:` in `bindings.yaml` and restart. |
| Malformed key | `kernel graph key: the kernel graph key is malformed (<why>)` | `` replace the key as the runbook's "Replace a malformed key" says: remove it, run `sudo maknae enroll`, then `sudo maknae reseed` `` | 5 | [Replace the key](#replace-a-malformed-key). |
| Key unreadable | `kernel graph key: <cause>` | `` the kernel graph key could not be read; check the credential `sudo maknae enroll` created (enroll never replaces an existing key) `` | 5 | Check the credential's ownership and mode, or the keychain item. |

Two refusals about the bindings come from the store check but are not graph-store refusals. Each exits 3, has no second line, and is recorded as a denied boot `authz` record with the same reason; nothing is written to the store:

- `the store holds explicit bindings from authz.yaml; paste the bindings: block into /etc/maknae/bindings.yaml`: the store's bindings were seeded from `authz.yaml` by an earlier release, and `bindings.yaml` has no `bindings:` key. Move the block ([upgrading](upgrading.md#bindings-move-to-bindingsyaml-496)) and restart.
- ``bindings.yaml is missing but the store holds explicit bindings; to return to principal-as-admin write bindings.yaml without a `bindings:` key``: put the file back, or write it with `schema_version: 1` and no `bindings:` key, and restart.

### Upgrades migrate the store

The store records a digest of the role vocabulary it was written with. A start that finds a store whose digest is consistent with its own contents but differs from the binary's migrates the store in place. That happens on the first start after an upgrade that changes the vocabulary (including the first start over a store written before #489) and after a change of classification system (`core.handling.policy`), since the compiled roles carry that system's lowest level. After the start's usual `graph.checkpoint`, the trail shows:

- a `graph.migrate` record, reason `intent recorded (vocabulary <old digest, or none> -> <new digest>; unbound: [<uids>])`, at the next revision. `unbound` lists the uids of bindings to a role the new binary no longer has; those bindings are dropped;
- a `graph.checkpoint`, reason `migrated`, at that revision;
- if `bindings.yaml`'s bindings differ from the migrated store, a `graph.transition` (`root-file`) and a `graph.checkpoint` (`transitioned`) at the revision after.

No action is needed. `maknae status` reports the new revision.

### Reseed

A reseed replaces the store with a fresh one, seeded from `/etc/maknae/bindings.yaml`. Every containment comes from `bindings.yaml` today, so the reseed restores it, except a carried-forward containment whose name no longer resolves: a reseed has no stored uid to carry, so list such an id as `- uid: <n>` before you reseed. A reseed is recorded by its own `graph.seed` records, not as releases, and a reseed over a formerly explicit store with a keyless `bindings.yaml` writes no principal-admin record. Once live containment (#165) exists, a reseed will drop any containment not yet synced back to the policy files (#491).

```bash
sudo maknae reseed
sudo systemctl restart maknaed                          # Linux
sudo launchctl kickstart -k system/io.maknae.maknaed    # macOS
```

`sudo maknae reseed` reads and decrypts nothing. It writes a root-owned authorization marker, `reseed.authorized`, into the state directory, prints `reseed authorized; restart maknaed to seed a fresh kernel graph …`, and exits. At its next start `maknaed` finds the marker and seeds the store:

- **A readable current store is kept** as `kernel.graph.rejected.<unix-seconds>.<16 hex digits>` in the state directory. The hex digits are the start of the store's ciphertext SHA-256. A rejected copy is never replaced. If that name already holds a byte-identical copy of the store, the copy counts as kept. If it holds anything else (other bytes, an empty file, a directory, or a file that cannot be read), the start refuses with `kernel graph store: the rejected-copy name <name> is in use and does not hold this store (<cause>); move it aside, then restart` and the hint `move <dir>/<name> aside (the current store is intact), then restart; the authorized reseed will complete`. The store and the marker stay, and nothing is written. Move that name out of the state directory and restart.
- **Rejected copies are never pruned.** Each can be up to 64 MiB. Remove old `kernel.graph.rejected.*` files by hand once you no longer need them.
- **A store that cannot be read** (wrong owner or mode, more than one link, too large) is never overwritten. The start refuses with `graph store file kernel.graph refused`, and the marker stays; fix the file and restart.
- **The trail records the reseed:** a `graph.seed` record, a `graph.checkpoint` record and, when there was a store to keep, a `graph.rejected` record naming the kept copy. `maknae status` then reports `reseeded`, and `verified` from the next restart on.

Run `sudo maknae reseed` from an unconfined session, as for enroll. On an SELinux host where administrators are confined users (`sysadm_t`), the marker write into the state directory (`maknae_state_t`) may be denied.

**A marker that root did not write authorizes nothing.** The daemon starts or refuses as if no marker were there; when it starts, it writes `` maknaed: reseed marker ignored: <cause>; only a root-owned reseed.authorized in <directory> written by `sudo maknae reseed` authorizes a reseed ``, and the trail records a denied `graph.reseed`. `sudo maknae reseed` refuses while that file is there (`an unexpected file is at …; investigate before reseeding`). Find out who wrote it, remove it, and run the reseed again.

### Replace a malformed key

The store cannot be read without its key, so a new key needs a reseed. `sudo maknae enroll` never replaces an existing key, so remove it first.

1. Remove the key. Linux: `sudo rm /etc/maknae/private/maknaed-graph-key.cred`. macOS: `sudo security delete-generic-password -a secret-id -s io.maknae.maknaed.graph /Library/Keychains/System.keychain`.
2. Run `sudo maknae enroll` with your enrollment arguments. It creates a new key, and warns `a kernel graph store already exists and cannot be opened with the new key; run sudo maknae reseed`.
3. Run `sudo maknae reseed`, then restart `maknaed`, as above.

**The same holds whenever enroll creates a key while a store exists,** for example after the key was deleted by hand: enroll prints the same warning, the store no longer decrypts, and without a reseed the daemon refuses with `the graph store key does not unwrap: wrong key or tampered header`. Reseed.

### `rollback-anchor-unavailable`

When the audit trail holds no `graph.checkpoint` record, for example after you rotate or restore the audit file by hand, the daemon cannot tell whether the store was rolled back. It starts anyway and records `rollback-anchor-unavailable`, and `maknae status` reports it until the next restart. That start also writes a new checkpoint, so from the next restart on the store is checked against it and `maknae status` reports `verified`. A store rolled back before that start is not detected, and the new checkpoint anchors it: rotate the audit file only while you trust the state directory.
