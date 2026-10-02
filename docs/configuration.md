# Maknae Configuration Reference

This is the reference for Maknae's configuration language: where the config lives,
the file/directory layout, the accepted YAML subset, and every section and key that
is defined today. It is **fail-closed** by design — when a control cannot be applied
or a value cannot be validated, Maknae refuses to load rather than run with a guessed
or weakened configuration.

> **Status.** The configuration backbone is built in cycles. This document covers what exists today: the **loading core**, the **document/registry model**, the **`core` section's classification ceiling**, the **`providers` section** that authorizes model providers (§6.1), each user's **`providers.yaml`** (§6.1.1) and the **egress bounds** (§6.1.3). Sections owned by subsystems not yet built (`authz`, `channels`, `dcs`) are marked **Forthcoming**, and `llm` and `provider` (singular) are **Withdrawn**. **Writing any of them refuses boot** — an unregistered section is `ConfigError::UnknownSection`, not a warning — so treat every Forthcoming row as "do not write this yet", never as "ignored until it lands". This reference is updated by every cycle that changes the configuration language.

---

## 1. Where the configuration lives

Maknae's configuration is a **directory** of YAML files, not a single file and not
environment variables (ADR-0005, decision 8: *"Configuration is YAML files, never ENV
values"*).

- In a deployment it is the **`authority-config` volume** (see
  `design/container-architecture.md` §4), mounted **read-only** into the kernel
  container. It is **Tier-0 signed-git**: changes arrive as **signed commits, never
  in-place writes**.
- The path is passed to the loader **explicitly** — there is **no environment-variable
  lookup and no magic discovery**. The kernel (the caller) hands the mounted directory
  to the loader. The concrete mount path is pinned when the kernel is wired; the
  intended convention is a read-only `/etc/maknae/`.

Because the location is caller-supplied, this reference describes the **contents and
rules** of the directory, independent of where a given deployment mounts it.

### 1.1 How Maknae reads it at boot

The trust-plane daemon (`maknaed`) resolves the config directory — a positional
argument, defaulting to **`/etc/maknae`** — loads it, selects the classification
system `core.handling.policy` names from the ones compiled into the build (§4.1; an
unknown name is `UnknownClassificationPolicy`), reads `core.handling.ceiling` through
that system into the runtime **ingest posture**, and **refuses to start (exit 1)** on
any config error. After the config is read the
daemon builds its authorization composition — the RBAC baseline and the classification
ceiling, both non-removable (ADR-0008 decision 1; §4.1) — records the composition, the
selected system and the ceiling level in the audit trail, mints its plane credential,
binds the client socket and **serves**: every request is decided through that
composition until a shutdown signal, and the process exits with the outcome the accept
loop stopped on. A boot that fails any of those steps exits non-zero, and a step after
the credential mint retires the credential on the way out.

- An **empty or `core`-less `maknae.yaml`** boots at the **Public baseline** (§4.1).
- An **absent config directory or a missing `maknae.yaml`** **fails closed** (exit 1) —
  a fresh install with no `/etc/maknae` does not come up.
- **Migration note:** the ceiling is read **only** from `core.handling.ceiling`. A
  `handling` block placed under `lake` (as one might do migrating from an older
  external-lake model) is **ignored** — the instance boots at Public. Put the ceiling
  under `core`.

### 1.2 What the three binaries read from the environment — and what they refuse to

**Read this as a snapshot, not a contract.** The tables below were **measured on
2026-09-19** against `main` at `35897fe` (#318); the `CREDENTIALS_DIRECTORY` and
`XDG_RUNTIME_DIR` rows were re-read against the code for #153 (2026-10-02). Nothing
scans the tree to keep them true: a new environment read added later will not appear here by itself, and **no gate
requires a pull request to re-verify them**. That is a deliberate trade — the
alternative is re-auditing every change — so treat this as a map of the terrain rather
than a guarantee about it. The two mechanisms that *are* enforced are named at the end.

ADR-0005 decision 8 stands and this does not qualify it: **configuration is YAML files,
never ENV values.** Nothing in either table configures Maknae. The first table is what
Maknae *removes* from its own environment; the second is the small set of variables that
are the mechanism by which a shipped feature works.

**Refused — removed in-process before any client exists, on all three binaries**
(`maknae_vault::SCRUBBED_ENV`; `maknaed.service` and `maknae-egress.service` carry the
same list as `UnsetEnvironment=`):

| family | names | what an inherited value would do |
|---|---|---|
| proxy | `HTTP_PROXY` `HTTPS_PROXY` `ALL_PROXY` `NO_PROXY` and the four lowercase spellings | reqwest honours these by default, which would move a connection somewhere the decision never covered. Exactly the same shape as the root-store row below: the client vaultrs builds **does** resolve them at construction, and the client that actually **sends** states `no_proxy()` and is not the one that read them. The scrub is the second line here, not the only one |
| Vault settings | `VAULT_ADDR` `VAULT_TOKEN` `VAULT_SKIP_VERIFY` `VAULT_CACERT` `VAULT_CAPATH` `VAULT_CLIENT_CERT` `VAULT_CLIENT_KEY` `VAULT_NAMESPACE` | `vaultrs` fills unset settings from these. `VAULT_TOKEN` is the one that was reachable: it became the daemon's client token and rode on the AppRole login |
| root store | `SSL_CERT_FILE` `SSL_CERT_DIR` | these **replace** the trust store the platform verifier builds, so setting either changes who Maknae will trust. On Linux all three binaries read them when a Vault client is constructed; nothing is exposed on that leg, because the CA-pinned client replaces the constructed one before any request. Live and unmediated on the deputy's provider leg. The exact chain, and why the scrub still earns its place, is stated once in `maknae_vault::env`'s module documentation rather than repeated here |

**You do not configure any of these.** The Vault address comes from `vault.addr` in
`maknae.yaml` (the daemon), `vault.addr` in `egress-bounds.yaml` (the deputy), or
`--vault-addr` (`maknae enroll`) — all three **required**, none defaulted. Who authenticates to Vault, and how:

- **`maknaed` is the only AppRole holder** (`AuthMethod` has one variant, `AppRole`): it logs in with its RoleID artifact plus a sealed SecretID.
- **Each user authenticates with userpass through `maknae login`** (`bins/maknae/src/login.rs`), which prompts for the password without echo, logs in as the local account name on the `vault.user_auth` mount (§6.1.2), and stores only the returned token (§2).
- **The Egress Daemon has no Vault identity** (ADR-0028 decision 6). It calls only `sys/wrapping/lookup` (unauthenticated, with the wrapping token in the request body) and `sys/wrapping/unwrap` (authenticated by that single-use wrapping token, which a user sealed to it) (`bins/maknae-egress/src/main.rs`, `opener.rs`; `crates/maknae-vault/src/wrap.rs`, `api_request.rs`).
- The operator's own token appears only during `maknae enroll`, supplied by `--token-file` or a no-echo prompt.

An exported `VAULT_ADDR` or `VAULT_TOKEN` is for **your** `vault` CLI, as `docs/runbook.md` uses it; it never reaches ours.

**Relied on — never scrubbed** (`maknae_vault::NEVER_SCRUB_ENV`). The scope is *every variable any workspace code these three binaries link reads, plus those their child processes need* — `LC_MESSAGES`/`LANG` are read in `maknae-msgs` and `HOSTNAME` in `maknae-kernel`, not in the binaries' own source, so the narrower phrasing would have let a future crate-level read look out of scope — `XDG_RUNTIME_DIR` is on the list for the second reason, not the first. A fourth binary, `maknae-spifc`, is a scaffold stub that reads nothing and is not covered here:


| variable | who reads it | why removing it would break something |
|---|---|---|
| `CREDENTIALS_DIRECTORY` | `maknaed`, `maknae-egress` | the directory systemd decrypts sealed credentials into: `maknaed`'s SecretID, and the deputy's seal key `maknae-egress-seal-key` (`maknae-egress.service`'s `LoadCredentialEncrypted=`). Without it the deputy looks for the macOS keychain pointer instead (`egress/maknae-egress-secret-id.keychain`); with neither, it refuses to start |
| `LISTEN_FDS` `LISTEN_PID` `LISTEN_FDNAMES` | `maknae-egress` | socket activation — the listening fd itself, read *after* the scrub runs |
| `MAKNAE_CONFIG_DIR` | `maknae` | relocates the CLI's config directory; documented operator workflow |
| `XDG_RUNTIME_DIR` | `maknae login`'s token store; `maknae enroll`'s helper | `systemd-creds --user` locates the user runtime directory through it. `maknae login`'s token store runs it from a `maknae` process that has run the scrub; for enroll's helper, the parent *constructs* the variable for the child (`sudo -u <operator> env XDG_RUNTIME_DIR=/run/user/<uid>`) rather than passing its own through |
| `HOME` | `maknae` | the config-directory fallback. Note it degrades to `.` when unset |
| `SUDO_UID` `SUDO_USER` | `maknae enroll` | the operator identity enroll provisions **for**, cross-checked against `passwd` and refused on mismatch. Without them every enroll fails preflight |
| `LC_MESSAGES` `LANG` | `maknae`, `maknaed` | message locale (en-US / ko-KR) |
| `PATH` | `maknae`, `maknae enroll` | selects which `systemd-creds`, `setfacl`, `apparmor_parser` … actually runs, including on the CLI's credential-read path. **That dependency is a defect, tracked as #327** — the fix is to stop relying on `PATH`, not to scrub it |
| `HOSTNAME` | `maknaed` | the AU-3c host label, which is correlation only and falls back to `maknaed`. Listed so inheriting it is a decision rather than an oversight |

**The two things that are enforced,** as opposed to documented here:

- the two lists are held **disjoint** by a test, so a name cannot be added to the scrub
  list if a binary depends on it; and
- both shipped systemd units are held **equal** to the scrub list by a test, so adding a
  name in one place and forgetting the other is a red build.

**macOS carries a real delta.** `UnsetEnvironment=` is a systemd directive with no
launchd equivalent, and launchd offers no way to *remove* inherited variables at all. On
macOS the in-process scrub is therefore the **whole** control; `io.maknae.maknaed.plist`
records that in place.

---

## 2. Directory layout

The host side, `<config-dir>` (`/etc/maknae` when packaged):

```
<config-dir>/
├── maknae.yaml           # the base file (required)
├── authz.yaml            # the authorization policy — a SEPARATE document, not a section
├── egress-bounds.yaml    # required WHEN any provider is authorized (§6.1.3); written by `maknae enroll`, 0644 root:root
├── egress/               # 0750 root:_maknae-egress, created by the package; files written by `maknae enroll`
│   ├── vault-ca.crt      # 0640 root:_maknae-egress — the deputy's Vault TLS anchor
│   └── maknae-egress-secret-id.keychain   # macOS only: points at the System-keychain item holding the deputy's seal key
├── private/
│   └── maknae-egress-seal-key.cred        # Linux only: the deputy's seal key, sealed by systemd-creds, 0400 root:root
└── config.d/             # optional overlay directory of SECTION files
    ├── 10-provider.yaml  # the `providers` section (§6.1, worked example in §9.3)
    └── …
```

The tree shows the files this reference covers; `maknae enroll` also writes `maknaed`'s own credential and TLS files (`tls/`, `maknaed-approle-id`, the rest of `private/`).

The macOS pointer is named `maknae-egress-secret-id.keychain` although it now names the seal key, not a SecretID; the name is a named residual (`KeychainPlane::Egress.pointer_file()`).

The host-wide **`seal.pub`** — the Egress Daemon's public key, which each user's client seals to — is written by `maknae enroll`, root-owned, file `0644` in a `0755` directory, at one of three paths (`crates/maknae-vault/src/seal_pub_store.rs`):

| Host | Path |
|---|---|
| Red Hat family | `/etc/pki/maknae/seal.pub` |
| Debian family | `/etc/ssl/maknae/seal.pub` |
| macOS | `/Library/Application Support/Maknae/pki/seal.pub` |

The user side, `~/.maknae` (or `$MAKNAE_CONFIG_DIR`):

```
~/.maknae/
├── maknae.yaml                 # written by `maknae enroll`: core.deployment_id, the user `vault` block (§6.1.2), and on macOS transport.socket_path
├── providers.yaml              # written by the user: the providers they use (§6.1.1)
├── maknae-vault-token.cred     # Linux, systemd 256 or later: the `maknae login` token, a `systemd-creds --user` file
└── maknae-vault-token          # Linux, older systemd: the same token in a 0600 file
```

On macOS `maknae login` keeps the token in the default keychain instead (service `maknae-cli`, account `maknae-vault-token`), and neither token file exists (`crates/maknae-vault/src/token_record.rs`, `keychain_policy.rs`).

**Sections versus standalone documents.** `maknae.yaml` and `config.d/*.yaml` contribute **registered sections** and are merged section-by-section by this loader. `authz.yaml` and `egress-bounds.yaml` are **standalone documents with their own readers**: each is opened by path (`<config-dir>/authz.yaml`, `<config-dir>/egress-bounds.yaml`), never merged, never shadowed, and putting either inside `config.d/` does not work. `providers.yaml` is likewise a standalone document, read by the CLI from its own directory.

- **`maknae.yaml`** — the **base** file. Required: it is the deployment's anchor, the
  one file that must exist even if empty. A missing base is an error. An empty base is
  valid (you may put everything in `config.d/`).
- **`config.d/`** — an **optional** overlay directory of additional section files.
  Absent `config.d/` is fine (base only).

### 2.1 `config.d/` rules

- **Non-recursive.** Only the *immediate* entries of `config.d/` are read.
- **Extensions `*.yaml` and `*.yml`** (case-insensitive) are loaded. Any other regular
  file (e.g. `README.md`) is **ignored**.
- **Dotfiles are skipped** (a name beginning with `.`). Editor lock/temp files such as
  `.#10-provider.yaml` or `.10-provider.yaml.swp` do not trip an error.
- A `config.d/` entry that is a **subdirectory or a symlink** is an **error**, not
  ignored. `config.d/` itself must be a real directory, not a symlink.
- Files are read in **lexical order** by filename.

### 2.2 File and directory permissions (Unix)

The configuration can carry policy, so it must not be world-accessible. On Unix, every
path involved is checked: **no world/other permission bits at all** (`mode & 0o007 == 0`
— no world read, write, *or* execute).

For a file carrying no root-required section the **only** check is
`mode & 0o007 == 0` — *any* mode with no world/other bit is valid (`600`, `640`, `660`,
`440`, `750`, `770`, `700`, …); the modes below are **recommended examples**, not an
exhaustive allowlist.

**A root-required section is held to more.** `providers` (§6.1) is one: the file contributing it, and `<config-dir>` and `config.d/` themselves, must additionally be **root-owned** and **not group-writable** (`mode & 0o022 == 0`), so **`660` and `770` are refused** there even though they pass the universal rule — `loader.rs`'s `ROOT_ARTIFACT` versus `CONFIG_ARTIFACT`. The refusal is `SectionNotRootOwned`, naming the path that failed: `section 'providers' must come from a root-owned, non-group/other-writable source; <path> is not`. See §9.3 for the worked example and the full table.

| Path | Recommended modes | Rejected |
|---|---|---|
| Config files (`maknae.yaml`, `config.d/*.yaml`, `~/.maknae/providers.yaml`) | `640`, `660`, `600` (`640` or `600`, root-owned, for the file carrying `providers`) | anything with a world/other bit (e.g. `644`) — **except `egress-bounds.yaml`, a root artifact that is `0644` by design (§6.1.3)** |
| Directories (`<config-dir>`, `config.d/`) | `750`, `770`, `700` | anything with a world/other bit (e.g. `775`, world-writable `0o772`) |

Additional file rules:

- **Symlinks inside the config tree are refused** — the base file `maknae.yaml`, the
  `config.d/` directory, and every loaded `config.d/` entry must be real, not symlinks.
  The **top-level `<config-dir>` itself may be a symlink**: it is canonicalized first,
  then its (real) target is permission-checked. Symlink rejection applies to the
  *contents* (the injection surface), not to the operator-chosen root path.
- A config file that is **not a regular file** (FIFO, socket, device, directory) is
  refused *before* it is opened.
- The group is a **trusted boundary** (group-readable/writable `660`/`770` are valid) —
  only *world* access is refused. **Not covered by this rule at all:** `egress-bounds.yaml`
  is read through the root-artifact requirement (root-owned, not group- or other-
  writable — no world-read rule), is read by two accounts, and is `0644` by design —
  see §6.1.3 before "fixing" its mode.
- **Non-Unix platforms** refuse to load (the permission model is unavailable there;
  Maknae fails closed rather than run unchecked).

> **Honest limits.** POSIX ACLs are invisible to the mode bits, and the integrity of
> the *ancestor* directories (e.g. `/etc`) is an assumed-trusted precondition. Keep the
> config tree free of world ACLs and on a trusted path.

---

## 3. Sections and precedence

> **Every section with a parser refuses a key it does not read** (#210), naming the token and the level: `unknown key 'jsonl_pth' in 'audit'`. An ignored key would silently substitute the default for what you wrote — `jsonl_pth` would quietly move the audit sink to `<config-dir>/audit.jsonl`, and `handlng` would hide the whole classification-ceiling block so the instance came up at the system's lowest level — and the direction is not always weaker: `max_connections` defaults to 64 against a ceiling of 4096, so a typo'd raise would land stricter. No single section of this reference lists every key, so the closed sets are listed here (§4 does not enumerate all of `core`; it omits `deployment_id`, which is on every enrolled host):
>
> | section | every key its parser reads |
> |---|---|
> | `core` (own level) | `schema_version`, `deployment_id`, `identity`, `handling` |
> | `core.handling` | `ceiling`, `accreditation_ref`, `policy` |
> | `transport` | `socket_path`, `max_connections`, `prompt_max_bytes`, `handshake_timeout_ms`, `read_timeout_ms` |
> | `audit` | `jsonl_path`, `siem`, `au3_1` |
> | `principal` | `name`, `uid`, `home` |
> | `vault` | `addr`, `approle_mount`, `pki_int_mount`, `deployment_id`, `insecure_plaintext_secret_path`, `user_auth`, `kv_mount`, `user_prefix` (`crates/maknae-vault/src/config.rs`). In the **root** `maknae.yaml`, `kv_mount` and `user_prefix` refuse boot — `vault.kv_mount in the root maknae.yaml is not read by maknaed: set kv_mount in egress-bounds.yaml` (likewise `user_prefix`), shadowed `config.d/` blocks included — because the host's copy lives in `egress-bounds.yaml` (§6.1.3); they belong in each user's `maknae.yaml` (§6.1.2) |
> | `vault.user_auth` | `type`, `mount` |
> | `providers` (each entry) | `name`, `endpoint`, `models`, `reasoning_effort`, `output_tokens_field` (§6.1) |
> | `egress` | `socket_path`, `deadline_ms` (§6.2) |
>
> The CLI's own `maknae.yaml` registers `vault`, `transport` and `agent` only (`bins/maknae/src/cli.rs`), so any other section there — a `provider:` block included — refuses every CLI verb with `UnknownSection`. Standalone documents close their keys the same way: `egress-bounds.yaml` (§6.1.3), `providers.yaml` (§6.1.1) and `authz.yaml`.
>
> **Two places are deliberately still open** and a key there continues to load: `lake`, which is registered for a forthcoming subsystem and has no parser, and `core.identity`, left as it is by maintainer direction. **Three limits, stated so the note is not read as more than it is.** (1) This closes wrong key NAMES. A key with the right name and the wrong SHAPE is handled per field and NOT uniformly: the bounded numeric and typed fields refuse (`transport: { max_connections: nope }` is `InvalidTransport`), while the shape-TOLERANT ones — `audit.jsonl_path`, `audit.siem`, and `vault`'s `get_str` keys — silently default that one field. That tolerance is a deliberate decision recorded in the parsers. (2) `core`'s own level is checked where the DAEMON consumes it, so a `core` typo in a CLI-side `maknae.yaml` is not caught by this at all — it may surface later as a missing-key refusal, or not at all: an extra `handlng` beside a valid `deployment_id` is simply ignored there, and even a misspelled `deployment_id` can be masked by the supported `vault.deployment_id` fallback. (3) A `core` that is present but not a MAP still boots at the system's lowest level, as `ceiling_from_core` has always documented and a test pins — the sibling sections refuse a non-map, `core` does not, and changing that is a decision nobody has taken. **The check applies to the contribution that WINS precedence** — a `config.d/` member replaces a whole section, so a key in a shadowed block is never read and is not refused (the plaintext-key scan of `providers` and the root `vault` check above are the exceptions: both read shadowed blocks too).

A configuration file is a YAML **mapping** whose top-level keys are **sections**. Each
section is owned by one subsystem; a section's value is *conventionally* a mapping, but
**the config loader is schema-agnostic** — it carries whatever `Value` the section
holds and does **not** enforce its shape. The **owning subsystem** validates the
section when it reads it. So a wrong-shaped section (e.g. `core: 1`, `lake: false`)
*loads*; it is caught — or, per §4.1 for a non-map `core`, treated as the Public
baseline — only when its consumer reads it.

- **`core`** is owned by `maknae-config` itself (§4). A non-map `core` value yields no
  `handling` block → the Public baseline (§4.1).
- Every other section is an **extension** owned by a subsystem, which must be
  **registered** before load. An **unregistered** top-level key is a hard error
  (`UnknownSection`) — a typo'd or unknown section never loads silently. (The section's
  *shape* is still the subsystem's to validate.)

### 3.1 Merge and precedence

- **`config.d/` overrides the base**, section by section. For a given section, a
  `config.d/` definition **wins** over the `maknae.yaml` definition.
- **Whole-section replacement, never deep merge.** A winning source supplies the
  *entire* section value; keys are not partially merged. What you read in the winning
  file is the whole section.
- **Ambiguity is an error, not last-wins.** The same section defined in **two
  `config.d/` files** is a hard error (`DuplicateSection`).
- **`core` is base-only.** The `core` section may be defined **only** in `maknae.yaml`;
  a `config.d/` file that defines `core` is a hard error (`CoreOverride`). A dropped-in
  overlay file can never lower the ingest ceiling.
- Overrides are **recorded** (available to the caller for auditing which source won
  each section).

---

## 4. The `core` section

`core` holds Maknae-wide settings. Today the security-bearing piece — the
**classification ceiling** — is typed and validated; the rest of `core` is carried
verbatim for its consumers.

```yaml
core:
  schema_version: 1
  identity:
    instance_id: "maknae-prod-1"
    name: "Maknae — Prod"
    domain: "DoD DevSecOps"
    urn_root: "urn:maknae"
  handling:
    ceiling:
      classification: "UNCLASSIFIED"
      sci: false
      releasable_to: []
      cui_permitted: false
      cui_categories_permitted: []
      dissemination_permitted: ["Distribution Statement A"]
    accreditation_ref: null
    policy: US
```

- **`schema_version`**, **`identity`** (`instance_id`, `name`, `domain`, `urn_root`) —
  carried as-is (the shape is shared with, and inherited by, the lake — see §5). Not
  yet type-validated by Maknae.
- **`handling`** — the classification ceiling (§4.1), the one block Maknae type-reads.

### 4.1 The classification ceiling (`core.handling`)

The ceiling governs the coarse **ingest gate**: whether this Maknae instance may reach
past the *public* gate. The vocabulary is reused **verbatim** from the lake
(`lake.yaml` / `lake.schema.json`), so the lake and the optional DCS classification
backend read the same declaration — plus one key of Maknae's own, `handling.policy`,
which names the **classification system** the enclave operates under (ADR-0022).

> **How it is read.** Loading the config *directory* carries the `core` section
> verbatim (like any section) — the directory load does **not** itself validate the
> ceiling. At startup the kernel first reads `handling.policy` and selects that system
> from the ones **compiled into the build** (`US`, the default; `AUS`); then it
> validates the ceiling **through the selected system** (`ceiling_from_core`). A name
> the build does not carry refuses boot (`UnknownClassificationPolicy`); config names a
> system, it never adds one. The rule and errors below describe that read; the ceiling
> is then enforced on every content request (the box at the end of this section).

**The rule** (applied when the ceiling is read):

- **Absent → Public.** If `core`, or `core.handling`, is absent, the instance runs at
  the **Public baseline** — reach and ingest *publicly available* information only.
  This is the default deployment state; **you do not need to write it down.**
- **Present → validated.** If `core.handling` is present, it is validated **strictly**
  (below). A conformant block is accepted.
- **Present but invalid → refused.** A present-but-malformed `handling` block is
  rejected when the ceiling is read (`InvalidCeiling`) — the read fails, and the kernel
  refuses to start. It is **not** clamped or guessed. Omit the block for Public; write
  it *completely and correctly* for anything above Public.

**The ingest gate** is a single coarse bit derived from the ceiling:

| Posture | When |
|---|---|
| **`Public`** (reach-only) | the ceiling's **parsed values** equal the baseline |
| **`Gated`** *(the INGEST gate's bit — it has no bearing on the per-request ceiling operand, which reads the level only; see the box below)* | the ceiling differs from the baseline in **any** way — higher, lower, or lateral (e.g. a higher level, CUI, SCI, a releasability set, a non-public *or empty* dissemination, or an accreditation reference) |

The comparison is on the **parsed ceiling values**, not the source text — cosmetic YAML
differences (quoting, whitespace, key order, flow vs. block) that parse to the same
values are still `Public`. The gate is `Public` **iff** the parsed ceiling equals the
baseline; **any** value deviation reads as `Gated` — including a
more-*restrictive*-looking one (an empty `dissemination_permitted`, say). The coarse
bit only answers "is this the wide-open Public default, or has the operator declared
*something else*?"; interpreting *what* was declared (fine-grained lattice/dominance)
is the optional DCS backend's job. The only way to reach `Gated` is a **valid, present**
ceiling whose values differ from the baseline; no absence, typo, wrong type, or unknown
key can widen the gate.

#### `core.handling` fields

The `handling` block is **strict**: exactly the keys below, all required when the block
is present, exact types (this matches the lake's `lake.schema.json`).

| Key | Type | Baseline (Public) | Notes |
|---|---|---|---|
| `handling.ceiling.classification` | string | the selected system's lowest level (`"UNCLASSIFIED"` for `US`) | A **bare level name** of the selected system (below), matched case-insensitively. Not a marking: no caveats after `//`, and `CUI` (a marking's spelling of UNCLASSIFIED) is not a level. |
| `handling.ceiling.sci` | bool | `false` | |
| `handling.ceiling.releasable_to` | list of strings | `[]` | Releasability caveats (e.g. `["REL FVEY"]`). Opaque here; interpreted by DCS. |
| `handling.ceiling.cui_permitted` | bool | `false` | The primary "private-network" switch. |
| `handling.ceiling.cui_categories_permitted` | list of strings | `[]` | Opaque CUI category strings. |
| `handling.ceiling.dissemination_permitted` | list of strings | `["Distribution Statement A"]` | e.g. Distribution Statements. |
| `handling.accreditation_ref` | string or `null` | `null` | Accreditation pointer (ATO reference, etc.). |
| `handling.policy` | string | `"US"` (may be omitted) | The classification **system**: one of the names this build carries. Optional — the one `handling` key that is. |

Recognized **`classification`** values are the selected system's ladder, lowest first
(CUI is the separate `cui_permitted` dimension, not a classification level):

| `policy` | Ladder | Baseline (unmarked) |
|---|---|---|
| `US` (default; shipped in the kernel) | `UNCLASSIFIED` · `CONFIDENTIAL` · `SECRET` · `TOP SECRET` | `UNCLASSIFIED` |
| `AUS` (`maknae-classification-aus`; PSPF Release 2025) | `UNOFFICIAL` · `OFFICIAL` · `"OFFICIAL: SENSITIVE"` · `PROTECTED` · `SECRET` · `TOP SECRET` | `UNOFFICIAL` |

`OFFICIAL: Sensitive` contains a colon, so in YAML it **must be quoted**
(`classification: "OFFICIAL: Sensitive"`); unquoted, the YAML parser refuses the file
before any ceiling code runs (`mapping values are not allowed in this context`).

The kernel maps **nothing** between systems: `PROTECTED` boots an `AUS` enclave and
refuses a `US` one. An `AUS` enclave declares both keys:

```yaml
core:
  handling:
    ceiling:
      classification: PROTECTED
      sci: false
      releasable_to: []
      cui_permitted: false
      cui_categories_permitted: []
      dissemination_permitted: ["Distribution Statement A"]
    accreditation_ref: null
    policy: AUS
```

A level the selected system does not rank — a typo, a caveat-bearing marking, another
system's level — is **invalid** and refuses the load. It never silently becomes `Gated`.
Case variants such as `secret` are accepted.

> **What the ceiling does at runtime (#148 / #154, 2026-09-06).** The declared **level**,
> in the declared **system**, is a mandatory operand of the authorization composition
> (ADR-0008 decision 1; ADR-0022), evaluated on **every** request beside the RBAC baseline,
> deny-overrides. Control-plane verbs (`admin.*`, `liveness.*`, `kernel.*`) are unaffected.
> For every other verb (today `fs.*`, `session.*`, `terminal.*`, `mcp.*`, and any namespace
> added later): content whose marking's **first token** ranks **at or below** the declared
> level flows; content marked **above** it is refused (the deny reason names the operand:
> `ceiling: …`). Caveats after `//` are opaque here and belong to the DCS library. A first
> token of **another** compiled-in system is refused **by name** (`PROTECTED` under a `US`
> enclave: *"a level of the AUS system, not US"*) — the kernel maps nothing between
> systems. **Unmarked content is the system's lowest level** (`UNCLASSIFIED`;
> `UNOFFICIAL` under `AUS`) — at or below every ceiling — so a HomeLab with no `handling`
> block, a small business that declares CUI, and an enterprise that declares SECRET all
> serve their unmarked content out of the box; no labeler is needed for any tier to
> function. A labeler ([#229](https://github.com/darkhonor/maknae/issues/229)) only makes
> *higher* markings expressible. Only `classification` is consulted here: `sci`,
> `releasable_to`, the CUI fields and `accreditation_ref` have **no bearing** on this
> operand (an ATO is a US-government artifact; most deployments will never have one).
> The boot trail records what will be enforced: the `authz` boot record's reason reads
> `authorization composition: maknae-authz-basic+maknae-ceiling; system: US; ceiling: SECRET`.

---

## 5. The `lake` section

The **`lake`** section configures **Maknae's own** long-term-memory subsystem — a
forthcoming Maknae feature, informed by the design of the standalone knowledge lake but
a **separate product**. Maknae has no `~/knowledgebase`; it does not clone, mount, or
read the standalone lake at runtime — that lake is **prior-art reference only**. This
document is the authority for Maknae's `lake` section.

- Its **classification ceiling** and **identity** come from **`core`** (§4) — one
  declaration.
- Its **lake-specific** settings live in a **`lake`** section:

```yaml
lake:
  in_scope_domains: [...]
  corpus_topology: {...}
  framework: {...}
```

Today the `lake` section is **registered (reserved, inert)** at boot: a present `lake`
block loads and is carried in the document (available to a consumer via the section
accessor), but **nothing reads it yet** — neither the keys nor the shape are validated,
and nothing is forwarded anywhere. The memory subsystem that consumes it lands in a
following cycle; its `in_scope_domains`, `corpus_topology`, and `framework` keys will be
documented in full **in this reference** as that subsystem is built.

`core` is recognized **internally** and must **not** be registered — registering it is
a `ReservedSection` error. The `lake` section, like any extension (§3), is **registered
by the caller** (the kernel, when it is wired); an unregistered `lake` section would be
an `UnknownSection` error.

---

## 6. Extension sections

A section the daemon does not register is `ConfigError::UnknownSection`, which **refuses boot** and names the file it came from: `unknown config section '<section>' in '<path>' (no registered spec)`. The registered set is `crates/maknae-kernel/src/boot.rs`'s `boot_specs()` — `lake`, `vault`, `transport`, `audit`, `principal`, `providers`, `egress`, plus `core` — so every row below marked Forthcoming or Withdrawn stops the daemon if written, rather than being ignored. Of the extension sections, `providers` (§6.1) and `egress` (§6.2) can be configured today.

| Section | Owner | Status |
|---|---|---|
| `authz` | authorization policy *(the config-section registration; the `/etc/maknae/authz.yaml` policy FILE is separate and is enforced per request — see the runbook)* | Forthcoming |
| `providers` | the model providers this host authorizes (ADR-0028 decision 1) — **see §6.1** | **Shipped** |
| `egress` | where `maknaed` finds the egress deputy, and the outer bound on one provider call (#240) — **see §6.2** | **Shipped** |
| `provider` | the single registered provider, replaced by `providers` (#153) | Withdrawn — **writing it refuses boot** |
| `llm` | LLM-provider authentication, replaced by `provider` and then `providers` | Withdrawn — **writing it refuses boot** |
| `channels` | channel/comms adapters (Discord, Matrix, …) | Forthcoming |
| `dcs` | optional DCS classification backend | Forthcoming |

### 6.1 The `providers` section

The OpenAI-compatible model providers this host authorizes, and the models each may be asked for (ADR-0028 decision 1). Each user then chooses, per request, among these in their own `providers.yaml` (§6.1.1); the kernel admits a request only for a provider in this list and a model on that provider's list. Which roles may send content to a provider is decided separately in `authz.yaml` (`roles:` and `destinations:`, destination id `provider:<name>`), see the runbook, Chapter 3 §7.

```yaml
providers:
  - name: openai
    endpoint: https://api.openai.com/v1/chat/completions
    models: [gpt-5.6-luna, gpt-5.6]
    reasoning_effort: none
    output_tokens_field: max_completion_tokens
  - name: local
    endpoint: http://127.0.0.1:8080/v1/chat/completions
    models: [llama]
    output_tokens_field: max_tokens
```

The value is a list of at most **32** entries, and each `name` may appear once (`providers[<i>].name '<name>' is listed more than once`). Each entry has exactly the keys `name`, `endpoint`, `models`, `reasoning_effort` and `output_tokens_field`; any other key refuses with `unknown key '<key>' in 'providers'` — including the singular block's `model`, `key_vault_path` and `key_field` (`crates/maknae-config/src/providers.rs`).

| Key | Required | Accepted |
|---|---|---|
| `name` | yes | 1 to 32 bytes of ASCII letters, digits, `-`, `_` and `.`. It is written into every egress audit record, and the user's `providers.yaml` names it. |
| `endpoint` | yes | `https://`, or `http://` **to loopback only** (`localhost`, a loopback IPv4 literal, or a bracketed loopback IPv6). Refused: any other scheme, an uppercase `HTTPS://` (the scheme match is case-sensitive), whitespace anywhere, **userinfo** (`user:pw@host`), an `http://` to a routable address, a port outside 1–65535 or with a leading zero, and a malformed host such as `256.256.256.256` or `api..example.com`. |
| `models` | yes | a list of 1 to 32 model identifiers, each 1 to 128 printable ASCII characters with no whitespace, none listed twice. |
| `reasoning_effort` | no | 1 to 16 lowercase ASCII letters. When set, it is sent as `reasoning_effort` on every request to this provider; when absent, nothing is sent. It is not checked against any provider's list of levels, which differ between providers: a level the provider does not know comes back as the provider's own error. Some models need it: `gpt-5.6-luna` refuses function tools on `/v1/chat/completions` unless it is `none`, answering `400` (#242). |
| `output_tokens_field` | no | `max_completion_tokens` (the default, and OpenAI's current name) or `max_tokens` (the older name, which some OpenAI-compatible servers still require). It names the request field the deputy sends a user's `output_tokens` under (§6.1.1); without one, neither field is sent. A provider that rejects the name answers `400`, and the deputy's journal carries the provider's reason (§6.2). |

A malformed entry refuses boot with `InvalidProvider`, which reads `invalid provider config: <reason>` and names the entry by index, for example `invalid provider config: providers[0].endpoint must be an https:// URL (http:// is permitted to loopback only)`.

- **No providers is a valid state.** An absent section, or `providers: []`, boots, and `egress-bounds.yaml` is then not read. Every prompt is then refused by the kernel: the administrator's `jq` over the audit trail shows the reason `no model access: no providers are authorized on this host`, while the user sees only `maknae agent: stopped: ` followed by the CLI's generic refusal text (§6.1.1). A `providers:` key with no value (YAML `null`) is not the same thing and refuses boot: `invalid provider config: providers must be a sequence of provider entries`.
- **Values are taken as written.** Nothing is trimmed; a value with surrounding whitespace fails its own shape rule.
- **No key is ever in this file.** A key named `key`, `api_key`, `apikey`, `token`, `secret`, `secret_key` or `bearer` (case-insensitive) in any entry refuses boot before any other defect in the section is reported (ownership and classification checks run earlier in boot): `provider config carries a plaintext credential under '<field>': each user's key lives in Vault under their own login, never in the config` (`ProviderPlaintextKey`). The scan covers every entry and **every contribution** to the section, including a base block that a `config.d/` member shadows. It is a field-name check only, not a general secret scanner: a secret pasted as the *value* of `name` is not detected.
- **Who may write the section.** The file that contributes `providers` — `maknae.yaml` **or a `config.d/` member** — must be **root-owned and not group/other-writable**, and so must the **config directory and `config.d/` themselves** (a subject who owns the directory could otherwise choose between root-authored candidates by renaming one out of the scan); otherwise boot refuses with `SectionNotRootOwned` (§2.2). The packaged `/etc/maknae` (`root:_maknae 0640` under `0750`) satisfies this; the subject the loop runs as cannot authorize a destination. A dev-shape `~/.maknae/maknae.yaml` owned by the operator does not, by design.
- **Authorized providers make `/etc/maknae/egress-bounds.yaml` mandatory** (§6.1.3), and `maknaed` resolves the deputy's account at boot (§6.2).
- **The daemon's `transport.prompt_max_bytes`** defaults to 1 MiB and may be raised to 16 MiB (#372), so a user's declared context window can be carried whole. Raise it to at least the cap a user's loop derives (§6.1.1).
- **Disclosure.** `admin.config.show` shows `providers[].name`, `providers[].endpoint`, `providers[].models` (and each `models[]` entry), `providers[].reasoning_effort` and `providers[].output_tokens_field` in the clear (`ci/gates/config-disclosure-manifest.txt`). None of them is a credential.
- `admin.provider.list` / `.set` / `.disable` are **not built**; authorization is this section, the bounds file, and the `authz.yaml` grant.

### 6.1.1 Each user's `providers.yaml`

Each user lists the providers they use in `providers.yaml` in their own configuration directory (`~/.maknae/providers.yaml`, or under `$MAKNAE_CONFIG_DIR`). The file is the user's, written by the user, held to the same file rules as any config file (§2.2), and read by `maknae agent` only (`crates/maknae-config/src/user_providers.rs`, `user_providers_io.rs`).

```yaml
# ~/.maknae/providers.yaml
providers:
  - label: work-luna
    provider: openai
    model: gpt-5.6-luna
    key:
      subpath: openai/personal
      field: api_key
    context_tokens: 128000
    output_tokens: 16000
    default: true
  - label: home
    provider: local
    model: llama
    key:
      subpath: local
      field: api_key
    context_tokens: 32000
```

The top-level key is `providers` only, a list of at most **32** entries. Each entry has exactly the keys below; any other key refuses with `unknown key '<key>' in 'providers.yaml/providers'` (and inside `key`, `unknown key '<key>' in 'providers.yaml/providers/key'`).

| Key | Required | Accepted |
|---|---|---|
| `label` | yes | 1 to 32 bytes of ASCII letters, digits, `-`, `_` and `.`; unique in the file (`providers[<i>].label '<label>' is used more than once`). |
| `provider` | yes | the `name` of a provider the host authorizes (§6.1); same grammar as `label`. |
| `model` | yes | 1 to 128 printable ASCII characters with no whitespace; it must be on that provider's `models` list. |
| `key` | yes | a map of exactly `subpath` and `field` — where your API key is in Vault, never the key itself. `subpath`: at most 256 bytes, `/`-separated segments of `[A-Za-z0-9._-]`, with no empty, `.`, `..` or `data` segment and no leading or trailing `/`. `field`: 1 to 64 printable ASCII characters with no whitespace — the field name inside your Vault secret. |
| `context_tokens` | yes | the model's context window in tokens, at most 16,777,216. |
| `output_tokens` | no | the reply cap sent with every request: at least 1, and `context_tokens` less `output_tokens` must exceed the 1,536-token preamble allowance. |
| `default` | no | `true` or `false` (default `false`). |

**How the CLI prints these.** `maknae agent` prints every setup refusal after `maknae: ` and exits 1 (`bins/maknae/src/cli.rs`); `maknae login` prints its own after `maknae login: ` (`bins/maknae/src/login.rs`). The texts below are quoted without the prefix.

Every refusal of this file reads `providers.yaml: <reason>` (`UserProviders`), for example `providers.yaml: providers[0].context_tokens is required: declare the model's context window in tokens`. Two worth knowing:

- Writing `key:` as a string refuses with `providers.yaml: providers[<i>].key must be a map of subpath and field; the API key itself is stored only in Vault, never in this file`. Another spelling, such as `api_key:`, refuses as an unknown key.
- `maknae agent` checks the budget before it sends anything, prefixed by the entry's label: `provider entry <label>: context_tokens <N> is above the 16777216 ceiling`, `provider entry <label>: output_tokens must be at least 1`, or `provider entry <label>: context_tokens less output_tokens must exceed the 1536-token preamble allowance` (`crates/maknae-agent/src/budget.rs`). The smallest window accepted is therefore 1,537.

**Which entry a turn uses.**

- With one entry, it is used. With two or more, exactly one must be `default: true`, or the file refuses: `providers.yaml: <N> entries and none is marked default: true; mark exactly one (labels: <labels>)`, or `providers.yaml: more than one entry is marked default: true (<labels>)`.
- `maknae agent --provider <label> "<prompt>"` uses the entry with that label instead. An unknown label refuses with `providers.yaml: no entry is labelled '<label>' (labels: <labels>)`; a value that is not a valid label refuses with `providers.yaml: the requested provider is not a valid label (1 to 32 bytes of ASCII letters, digits, '-', '_' and '.')`.
- An absent file, an empty document, or a document with no `providers` key means no model access: `maknae agent` stops before contacting anything with `no model access: no providers are defined in <path>`.

**Where the key is.** Each turn, `maknae agent` reads the entry's key from Vault with the user's own `maknae login` token, at

```
<kv_mount>/data/<user_prefix>/<username>/<subpath>
```

field `<field>`, where `kv_mount` and `user_prefix` come from the user's `vault` block (§6.1.2) and `<username>` is the local account name of the uid running the CLI, never a value from any file (ADR-0028 decision 3). The account name must be 1 to 32 bytes of `[a-z0-9._-]`, starting and ending with `[a-z0-9_]`, and must not be `data`. With enroll's defaults (`maknae-kv`, `maknae/users`), user `alice` and the first entry above, that is `maknae-kv/data/maknae/users/alice/openai/personal`, field `api_key`. The read is response-wrapped: Vault answers with a single-use wrapping token, which the CLI seals to the Egress Daemon's `seal.pub` (§2) and sends; the kernel admits the request on metadata alone and never sees the key (ADR-0028 §5). Loading the key into Vault is `docs/first-provider.md`'s step U2.

**What the user sees when the kernel refuses.** A kernel refusal reaches the user only as `maknae agent: stopped: the kernel refused the exchange — whether the prompt reached the provider is in the host's audit trail (ask your administrator); if it did not, check that your providers.yaml names a provider and model your administrator has authorized for your role and the key subpath and field of your own Vault secret, that your maknae.yaml vault block matches the host's, and that your login is current (maknae login)`. The reason — for example `provider not in the authorized set` or `model not on the authorized provider's list` — is what the administrator's `jq` over the audit trail shows (`crates/maknae-kernel/src/provider_choice.rs`).

**How the loop meters the window.**

- **The prompt budget** is `context_tokens` less `output_tokens`. When `output_tokens` is set, it rides on every `session.prompt`; the kernel bounds it, records it on the egress intent, and the deputy sends it under the name the provider's `output_tokens_field` gives (§6.1). A reply is capped at 1 MiB whatever this says, so above about 250,000 tokens the cap no longer limits the visible reply; on a reasoning model it still bounds the hidden reasoning tokens.
- Before each turn the loop projects the conversation's size in tokens: the provider's last reported `prompt_tokens`, plus the bytes added since at the bytes-per-token ratio it has observed (clamped to 1–4). Before the provider has reported usage, it counts bytes at 4 per token plus the preamble allowance. The projection is never lower than the conversation's bytes at 4 per token, so a provider that under-reports usage cannot switch the meter off; against such a provider the stop can come later than the model's real window, because that floor counts neither the preamble nor text denser than 4 bytes per token. **Dense text overshoots by one turn.** Bytes the provider has not yet measured are counted at the observed ratio, or at 4 bytes per token before there are two measurements, so text that tokenizes denser — base64, minified data, many non-English scripts — is undercounted until the next reply's usage corrects the ratio. Measured on `.42` (2026-09-28): an 8 KB base64 read projected 2,861 tokens, and the provider counted 6,429. Declare the window with that margin in mind. It warns on stderr once at 80% and once at 95% — `warning: this conversation is at 82% of the declared context budget (104,960 of 128,000 tokens)`, with ` — estimated from bytes; the provider has not reported usage` appended when it has nothing better. It does not send a turn projected past the budget: it prints `stopped: the conversation has reached the declared context budget; compaction arrives with #171` and exits 2. Nothing is sent and nothing is recorded for the turn it stops.
- **The loop's byte cap follows the window:** `context_tokens × 6` bytes, clamped to 65,536..=16,777,216 — or, when the user's `maknae.yaml` sets `transport.prompt_max_bytes` explicitly, the smaller of the two. `maknae fs write` keeps the configured `transport.prompt_max_bytes`, 1 MiB by default, so it accepts up to 1 MiB unless the configuration sets it lower.
- **The agent's `write_file` is bounded per call, not by `prompt_max_bytes`.** Its arguments, as JSON with the file's content escaped, may be at most 61,440 bytes, a bound chosen with a margin so that a call at this size, alone in a reply, fits the smallest `transport.prompt_max_bytes` an operator can set (65,536). A reply carrying a longer call is refused whole, the agent stops, and nothing is written. Several large calls in one reply, or one beside long text, can together exceed a small daemon `prompt_max_bytes` and are refused the same way; the tool's description tells the model to send a large write as the only call in its reply. The agent cannot write a file larger than one call yet. The written content also rides every later turn back to the model, so with a loop cap near 65,536 a near-limit write leaves little room for the rest of the conversation. A near-limit write is roughly 15,000–20,000 output tokens, so an `output_tokens` below that cuts the call off before it is complete.
- **The daemon's `transport.prompt_max_bytes` must be at least the user's derived cap, or the daemon refuses the frame and the loop stops with a transport error.** The daemon's default, 1 MiB, covers a window of about 174,000 tokens; its ceiling is 16 MiB.
- **Where to find a model's window:** the provider's documentation, or models.dev. Maknae reads neither; the number declared here is the number the loop uses.

### 6.1.2 The user `vault` block

Each user's `~/.maknae/maknae.yaml` carries a `vault` block, written by `sudo maknae enroll` (`bins/maknae/src/enroll/mod.rs`) and parsed by the same `VaultConfig` as the daemon's (`crates/maknae-vault/src/config.rs`). Beside `addr` and `pki_int_mount` it carries the keys a user's turn needs:

```yaml
# ~/.maknae/maknae.yaml (the vault block, as enroll writes it with its defaults)
vault:
  addr: https://vault.example:8200
  pki_int_mount: maknae-pki-int
  user_auth:
    type: userpass
    mount: maknae-userpass
  kv_mount: maknae-kv
  user_prefix: maknae/users
```

- **`kv_mount` and `user_prefix`** are required by `maknae agent`, and enroll writes them from `--kv-mount` (default `maknae-kv`) and `--user-prefix` (default `maknae/users`). Each is at most 256 bytes of `[A-Za-z0-9._/-]`, with no empty, `.`, `..` or `data` segment and no leading or trailing `/`. When one is missing, `maknae agent` stops with ``vault.kv_mount is not set in your maknae.yaml: `sudo maknae enroll` writes it`` (likewise `vault.user_prefix`). Only `maknae agent` requires them, but every CLI verb parses the `vault` block, so a malformed value refuses every verb.
- **`user_auth { type, mount }`** says how `maknae login` authenticates. An absent block means userpass on `maknae-userpass`. When the block is present, `type` is required and must be `userpass`; anything else refuses with ``vault.user_auth.type "<type>" is not supported: the only method is `userpass` ``. `mount` defaults to `maknae-userpass` and is a bare mount name: a leading `auth` segment refuses (`invalid Vault mount: vault.user_auth.mount starts with 'auth' — the auth/ prefix is composed by the client; write the bare mount name as Terraform declares it`), as does a character outside `[A-Za-z0-9._/-]`, whitespace, or an empty, `.` or `..` segment. Keys other than `type` and `mount` refuse with `unknown key '<key>' in 'vault.user_auth'`. The root `maknae.yaml` may carry the same block.
- **They must match the host.** A user whose `kv_mount` or `user_prefix` differs from the host's `egress-bounds.yaml` (§6.1.3) seals a key the Egress Daemon cannot open: the deputy refuses before any provider I/O, and `maknaed` records every such turn `Failed` (ADR-0028 §5, amended, and §6). The user sees only the generic refusal text (§6.1.1). Keep both files written from the same enroll flags.

### 6.1.3 `egress-bounds.yaml`

`/etc/maknae/egress-bounds.yaml` declares, for the host, where user keys live and where the Egress Daemon reaches Vault. `maknaed` composes each user's key path beneath it per request, and the deputy checks each frame's path against it at use (`crates/maknae-config/src/bounds.rs`). `maknae enroll` writes it from `--vault-addr`, `--kv-mount` and `--user-prefix`:

```yaml
vault:
  addr: https://vault.example:8200
kv_mount: maknae-kv
user_prefix: maknae/users
```

- **Exactly three keys**: `kv_mount`, `user_prefix` and `vault`, and `vault` holds exactly `addr`. Any other key refuses with `unknown key '<key>' in 'egress-bounds.yaml'` (or `in 'egress-bounds.yaml/vault'`) — including the retired `key_vault_path_prefix` and `approle_mount`.
- **The fragment grammar.** `kv_mount` and `user_prefix` are each required, a string, at most 256 bytes, in `[A-Za-z0-9._/-]`, with no whitespace, no empty, `.`, `..` or `data` segment, and no leading or trailing `/`. `vault.addr` is required, non-empty, without whitespace, at most 256 bytes, and must be `https://` (checked at boot).
- **Required only when providers are authorized.** With an empty or absent `providers` section the file is not read. With providers authorized, a file that cannot be read refuses boot with `providers are authorized but egress-bounds.yaml could not be read: <reason>`, and one that was read but refused — by its parser or by the boot gate's own `user_prefix` and `vault.addr` checks — refuses with `providers are authorized but the egress bounds were refused — <reason>` (`crates/maknae-kernel/src/boot_gate.rs`). A parser refusal's reason reads `egress-bounds.yaml: <reason>` (`InvalidEgressBounds`).
- **Mode `0644 root:root`, by design.** It is read through the root-artifact rule — root-owned, not group- or other-writable — by both `maknaed` and `_maknae-egress`, so it is owned by neither and editable by neither; it is world-readable because nothing in it is a secret and because the deputy is in neither `root` nor `_maknae`. To reach it, the deputy has a POSIX ACL `u:_maknae-egress:rx` on `/etc/maknae` (`r` as well as `x`, because the anchored reader opens the directory `O_RDONLY|O_DIRECTORY`), set by the package's `postinst`/`%post` and re-asserted by `maknae enroll`. A write-granting ACL would raise the group bits into the loader's `0o022` mask and be refused, so the root-artifact check is not weakened.
- **Not in `config.d/`.** It is a standalone document with its own reader, never merged or shadowed.
- **The same address appears twice, independently.** `vault.addr` here is where the deputy unwraps; `maknae.yaml`'s `vault.addr` is `maknaed`'s. The two are never compared.
- On an SELinux host, run `restorecon -R /etc/maknae` after creating the file by hand or after enroll creates `egress/`: a new file or directory inherits `maknae_etc_t`, and the deputy is granted the file's own type (`maknae_egress_bounds_t`) and the directory's (`maknae_egress_etc_t`, `packaging/common/maknae.fc`), not the parent's.

---

### 6.2 The `egress` section (#240)

Where `maknaed` finds the egress deputy, and how long one `session.prompt` send may take.
Both keys are optional and default to what the packaging ships, so a deployment on the
packaged Linux layout needs no `egress` block at all.

```yaml
egress:
  socket_path: /run/maknae-egress/egress.sock   # the deputy's activation socket (maknae-egress.socket)
  deadline_ms: 280000                            # the outer bound on one send to the deputy; 1000..=600000
```

- **`socket_path`** — the Unix socket the deputy accepts on. Linux packaging creates it by
  socket activation at the default path; on macOS the deputy binds
  `/usr/local/var/run/maknae-egress/egress.sock` itself (its launchd job's `--bind`), and
  enroll writes that path here, beside the daemon's own `transport.socket_path`
  (`/usr/local/var/run/maknae/maknaed.sock`). So on macOS `/etc/maknae/maknae.yaml` already
  has an `egress:` block: put `deadline_ms` under it, because a second `egress:` key
  refuses the whole file with `duplicate config key 'egress' at LINE:COL`. A non-string or
  empty value refuses boot (`InvalidEgress`).
- **`deadline_ms`** — the kernel's outer bound on one send to the deputy. It replaced
  `transport.read_timeout_ms` in that role: five seconds was a frame read timeout, never
  a provider deadline. The CLI waits for a prompt reply for 690 s: this bound's 600 s
  maximum, the 60 s transport maximum for the reply write, and 30 s for the group
  lookup, the PDP decision and the audit appends. So it does not stop a turn the daemon
  would still answer, unless an audit append stalls, since those have no time bound.
  Every other reply is still bounded by `transport.read_timeout_ms`. The default, 280000,
  covers the deputy's worst-case wall time on one request with room to spare: per turn
  the deputy makes one wrapping lookup and one unwrap at Vault, each bounded at 30 s,
  then the provider call, bounded at 120 s — 180 s. There is no boot probe and no key
  cache. If this bound expired first, the kernel would record delivery-unknown for a
  call the deputy answered. A slower provider needs the deputy's bound raised and this
  one with it. Out of range refuses boot by name. Shutdown waits
  for a send in flight: the daemon's handler drain is bounded by one connection's whole
  work — the handshake, the group lookup, the frame read and the response write (each at
  its `transport` timeout), the PDP decision and the verb's own blocking step, this
  deadline, the close, and a ten-second margin for the audit appends — so the outcome
  record is written, and the shipped units' stop timeouts (`TimeoutStopSec=885`, launchd
  `ExitTimeOut`) cover that drain at BOTH ceilings (60 s transport timeouts, 600 s
  deadline) plus every other term of the shutdown chain — the stop record's append, the
  credential supervisor's abort and reap, the reap of aborted handlers, the audit drain,
  the plane client's bounded lock wait and token revoke, and the runtime teardown — and
  a kernel test holds the unit values to that chain, two-sided. At the defaults the
  chain is 396 s; a stop with nothing in flight exits in milliseconds. One more bound at
  the ceiling: the deputy's request cap is 16,842,752 bytes — 16 MiB and a 64 KiB margin
  for the re-wrap — so a prompt that fills `transport.prompt_max_bytes` at its own 16
  MiB maximum still reaches the deputy.
- **A provider's error reaches the deputy's journal** (#372). When the provider answers
  non-2xx, the deputy reads at most 4 KiB of the body, masks the provider key wherever it
  appears, escapes everything outside printable ASCII and writes one line:
  `maknae-egress: provider answered 400 (conversation c…): <body>`. On Linux that is
  `journalctl -u maknae-egress`; on macOS it is the deputy's stderr file,
  `/usr/local/var/log/maknae-egress/maknae-egress.err`, which nothing rotates. Neither the
  trail nor the subject's terminal carries the body. **The logged line can carry
  conversation content:** some OpenAI-compatible servers quote the offending request in a
  `400`/`422` body, so up to 4 KiB of the prompt — including file content the agent read —
  may be written to the journal, outside the trail's never-the-content rule. Treat the
  deputy's journal as holding conversation content, and limit who can read it (on Linux,
  root and the `systemd-journal`, `adm` and — on Enterprise Linux — `wheel` groups; on
  macOS, root and the `_maknae-egress` group, through the file's `_maknae-egress:_maknae-egress
  0750` directory). A journal forwarded to syslog (`/var/log/messages` through rsyslog's
  `imjournal`) or to a remote collector carries the content too.
- **What the section changes at boot.** With providers authorized, `maknaed` resolves
  the deputy's account (`_maknae-egress`) ONCE, before the Vault mint, and refuses to start
  by name if the account does not exist (`providers are authorized but the egress deputy's
  account '_maknae-egress' does not exist on this host`) or cannot be looked up — the macOS
  package creates it (`preinstall`). With no providers the backend is `Unavailable`, the account is never
  looked up, and the section is parsed but idle. Whether the deputy's socket exists is
  checked per request (`egress backend not ready` in the trail), not at boot: the socket
  unit and the daemon start independently — and **nothing enables the socket unit for
  you**: `sudo systemctl enable --now maknae-egress.socket` once `egress-bounds.yaml` is
  complete, or every permitted prompt is refused as not ready (the install READMEs and
  enroll's closing hint carry the step). On macOS, a job that is not yet loaded is started
  with `sudo launchctl enable system/io.maknae.maknae-egress && sudo launchctl bootstrap
  system /Library/LaunchDaemons/io.maknae.maknae-egress.plist`; a second `bootstrap` of a
  loaded job errors, so [first-provider step 5](first-provider.md#5-start)'s loop checks
  first and restarts a loaded job instead.
- Both keys are disclosed by `admin.config.show`; neither is a credential.

## 7. Accepted YAML

Maknae parses a **restricted, reject-exotic** subset of YAML. The intent is that a
config file means exactly one thing, with no surprising YAML features on a
security-relevant input.

**Accepted:**

- Mappings, sequences, and scalars. Mapping key order is preserved.
- Scalar typing follows the YAML 1.2 core schema: `null`/`~`, `true`/`false`,
  integers, floats, and strings. A **quoted** scalar is always a string (`"1"` is the
  string `1`, `1` is the integer).
- A single leading byte-order mark (BOM) is stripped.

**Rejected (each refuses the load with a hard error — see §8 for the exact variant):**

- **Duplicate mapping keys** — never last-wins (a `DuplicateKey` error, not `Parse`).
- **Aliases** (`*anchor`) and **tags** (`!!str`, `!foo`). An anchor definition on its
  own is inert (the value builds), but *referencing* it via an alias is rejected.
- **Multiple documents** (`---` separators).
- **Non-string mapping keys** (e.g. `1: a`, `true: a`) and **container keys**.
- **Non-finite floats** (`.inf`, `.nan`, `1e999`) and integers too large for a 64-bit
  signed integer (no silent lossy conversion).
- **Nesting deeper than 128 levels.**

Malformed input always fails closed to a hard error (the exact variant per §8) — no
partial or wrong value is ever produced.

---

## 8. Validation and errors (fail-closed catalogue)

Every failure below refuses the operation. The names are the config crate's error
variants. Most are raised by the **directory load** itself; `InvalidCeiling` is raised
by the **typed ceiling read** (`ceiling_from_core`, §4.1), and `UnknownKey` by the
individual **section parsers**, two of which live outside `maknae-config` (`vault`'s in
`maknae-vault`, `core`'s own level in `maknae-kernel`'s boot). `egress-bounds.yaml` is
not part of the directory load at all and is read by the DEPUTY as well as the daemon,
and `providers.yaml` is read by the CLI. Two names below are not the config crate's:
`UnknownRole` is `maknae-authz-basic`'s, and `RootVaultKeyRefused` is `maknae-kernel`'s
boot gate (`crates/maknae-kernel/src/boot_gate.rs`).

| Condition | Error |
|---|---|
| Missing `maknae.yaml`, unreadable file, invalid UTF-8, or a non-regular file (FIFO/socket/device/directory) | `Io` |
| Malformed / rejected YAML (see §7) | `Parse` |
| Duplicate mapping key within a file | `DuplicateKey` |
| A config file or directory with world/other permission bits | `InsecurePermissions` |
| A config file or `config.d/` that is a symlink | `Symlink` |
| Non-Unix platform (permission model unavailable) | `PermissionsUnsupported` |
| A config file whose root is not a mapping | `NotAMap` |
| A top-level key matching no registered section | `UnknownSection` |
| The same section in two `config.d/` files | `DuplicateSection` |
| A required section absent from every source | `MissingSection` |
| `core` defined in a `config.d/` file | `CoreOverride` |
| A caller registering a reserved name (`core`) | `ReservedSection` |
| A duplicate section name in the registration | `DuplicateSpec` |
| `egress-bounds.yaml` read but refused: a missing `vault` block or key, a fragment outside `[A-Za-z0-9._/-]` or with an empty, `.`, `..` or `data` segment, a value over 256 bytes (§6.1.3). Reads `egress-bounds.yaml: <reason>`; an unknown key such as `key_vault_path_prefix` or `approle_mount` is `UnknownKey` | `InvalidEgressBounds` |
| The `egress` section (§6.2): a non-map section, a value of the wrong type or out of range (#240) | `InvalidEgress` |
| **A key no parser reads** — in `maknae.yaml`'s `core` (own level), `transport`, `audit`, `principal`, each `providers` entry, `egress`, `vault` and `vault.user_auth`; in `core.handling` and `core.handling.ceiling`; in `egress-bounds.yaml` and its `vault` block (`egress-bounds.yaml/vault`); in `providers.yaml` at its top level (`providers.yaml`), each entry (`providers.yaml/providers`) and each entry's `key` (`providers.yaml/providers/key`); and at `authz.yaml`'s four map levels (the document, `permissions`, and each role body under `roles:`/`destinations:` — a mistyped ROLE NAME is `UnknownRole`, not this). **Not** `lake` or `core.identity`, which are deliberately open (§3) (#210) | **`UnknownKey`** |
| A present-but-malformed `core.handling` ceiling | `InvalidCeiling` |
| `transport.prompt_max_bytes` outside 65536..=16777216 (default 1048576 since #372; it bounds prompt-class frames only, and control and attempt frames have fixed caps) | `InvalidTransport` |
| The `providers` section (§6.1): not a list (a null `providers:` included), more than 32 entries, a duplicate `name`, an entry that is not a map, a missing or malformed `name`, `endpoint` or `models`, a malformed `reasoning_effort`, an `output_tokens_field` other than `max_completion_tokens` or `max_tokens`. Reads `invalid provider config: <reason>` | `InvalidProvider` |
| A key named `key`, `api_key`, `apikey`, `token`, `secret`, `secret_key` or `bearer` in any `providers` contribution, shadowed ones included: `provider config carries a plaintext credential under '<field>': each user's key lives in Vault under their own login, never in the config` | `ProviderPlaintextKey` |
| The file contributing `providers`, `<config-dir>` or `config.d/` not root-owned, or group/other-writable: `section 'providers' must come from a root-owned, non-group/other-writable source; <path> is not` | `SectionNotRootOwned` |
| `core.handling.policy` names a system the build does not carry: `core.handling.policy names a classification system this build does not carry: '<name>'` | `UnknownClassificationPolicy` |
| `providers.yaml` (§6.1.1) malformed, or no entry selectable: `providers.yaml: <reason>` | `UserProviders` |
| `vault.kv_mount` or `vault.user_prefix` in the root `maknae.yaml`, shadowed `config.d/` blocks included: `vault.kv_mount in the root maknae.yaml is not read by maknaed: set kv_mount in egress-bounds.yaml` | `RootVaultKeyRefused` (kernel) |

---

## 9. Examples

### 9.1 Minimal — Public (the default)

The smallest useful config. No `handling` block, so the instance runs at the Public
baseline (reach and ingest publicly available information only).

`maknae.yaml`:

```yaml
core:
  schema_version: 1
  identity:
    instance_id: "maknae-lab-1"
    name: "Maknae — Lab"
    domain: "DoD DevSecOps"
    urn_root: "urn:maknae"
```

An even smaller config is a valid **empty** `maknae.yaml` — the instance still runs at
the Public baseline.

### 9.2 CUI — a private-network deployment

To reach beyond the public gate, declare a **complete** `handling` block. This example
authorizes CUI (the ingest gate reads as `Gated`):

`maknae.yaml`:

```yaml
core:
  schema_version: 1
  identity:
    instance_id: "maknae-enclave-1"
    name: "Maknae — Enclave"
    domain: "DoD DevSecOps"
    urn_root: "urn:maknae"
  handling:
    ceiling:
      classification: "UNCLASSIFIED"
      sci: false
      releasable_to: []
      cui_permitted: true
      cui_categories_permitted: ["SP-PRVCY"]
      dissemination_permitted: ["Distribution Statement C"]
    accreditation_ref: "ATO-2026-0042"
```

> Remember: the whole block is required and strict. Setting only `cui_permitted: true`
> without the other five ceiling fields is **invalid** and refuses the load.

### 9.3 Authorizing providers in `config.d/`

Extension sections belong in `config.d/` (or inline in the base). `config.d/` files override the base **section by section**. A host that authorizes two providers:

```
/etc/maknae/                 # 0750 root:_maknae
├── maknae.yaml              # 0640 root:_maknae — core (+ inline sections)
├── egress-bounds.yaml       # 0644 root:root (root:wheel on macOS) — written by enroll; NOT a config.d member
└── config.d/                # 0750 root:_maknae
    └── 10-provider.yaml     # 0640 root:_maknae — the `providers` section (§6.1)
```

`config.d/10-provider.yaml`:

```yaml
providers:
  - name: openai
    endpoint: https://api.openai.com/v1/chat/completions
    models: [gpt-5.6-luna, gpt-5.6]
    reasoning_effort: none
  - name: local
    endpoint: http://127.0.0.1:8080/v1/chat/completions
    models: [llama]
    output_tokens_field: max_tokens
```

`/etc/maknae/egress-bounds.yaml`, as `sudo maknae enroll --vault-addr https://vault.example:8200` writes it with the default `--kv-mount` and `--user-prefix` (§6.1.3):

```yaml
vault:
  addr: https://vault.example:8200
kv_mount: maknae-kv
user_prefix: maknae/users
```

A user's `~/.maknae/providers.yaml`, choosing from that set (§6.1.1):

```yaml
providers:
  - label: work-luna
    provider: openai
    model: gpt-5.6-luna
    key:
      subpath: openai
      field: api_key
    context_tokens: 128000
    output_tokens: 16000
    default: true
  - label: home
    provider: local
    model: llama
    key:
      subpath: local
      field: api_key
    context_tokens: 32000
```

#### Permissions — stricter than §2.2 for this section

§2.2's universal rule is "no world/other bits" (`mode & 0o007 == 0`), which admits `660` and `770`. **A root-required section is held to more than that.** `providers` is one, so the file that contributes it **and** `<config-dir>` **and** `config.d/` must each be **root-owned** and **not writable by group or other** (`mode & 0o022 == 0`) — `loader.rs`'s `ROOT_ARTIFACT` (`owner: Some(0)`, `mode_mask: 0o022`) rather than `CONFIG_ARTIFACT` (`owner: None`, `mode_mask: 0o007`).

| Path | Valid with a `providers` section | Refused |
|---|---|---|
| The file carrying `providers` | `640`, `600`, `440` — root-owned | **`660`** (group-writable), any world bit, any non-root owner |
| `<config-dir>`, `config.d/` | `750`, `700` — root-owned | **`770`** (group-writable), any world bit, any non-root owner |
| `egress-bounds.yaml` | `644` — root-owned | any group or other write bit, any non-root owner |
| `~/.maknae/providers.yaml` | `600`, `640` — the user's own | any world bit |

The failure names the path that failed (`SectionNotRootOwned`, §2.2). The packaged `/etc/maknae` (`root:_maknae 0640` under `0750`) satisfies this as shipped. **A dev-shape `~/.maknae/maknae.yaml` owned by the operator does not, by design** — the subject the loop runs as must not be able to authorize a destination for its own content. `config.d/` itself is checked as well as the file, because a subject who can write the directory could otherwise hide a root-authored override and hand the win to the base file.

#### The key is never in a file

No configuration file holds a provider key — not the root `providers` section (a key-named field refuses boot with `ProviderPlaintextKey`, §6.1), and not `providers.yaml` (an entry's `key` is a map naming where the key is; a string refuses, §6.1.1). Each user's key lives in Vault under their own login, at `<kv_mount>/data/<user_prefix>/<username>/<subpath>`, and the user loads it there themselves with their own `maknae login` identity: `docs/first-provider.md`, step U2. Each turn the CLI reads it response-wrapped and seals the wrapping token to the Egress Daemon, so neither `maknaed` nor any file on the host ever holds it (ADR-0028 §5).

#### `config.d/` mechanics that apply here (§2.1)

Only immediate entries are read; only `*.yaml` / `*.yml` (case-insensitive); dotfiles are skipped, so an editor's `.10-provider.yaml.swp` is harmless; a subdirectory or a **symlink** in `config.d/` is an **error**, not ignored; files are read in **lexical order**, which is why the example is named `10-provider.yaml`.

#### Verifying it loaded

- `maknaed` boots: a defect in `providers`, a missing or refused `egress-bounds.yaml`, or a missing `_maknae-egress` account refuses start by name (§6.1, §6.1.3, §6.2).
- `admin.config.show` shows each provider's `name`, `endpoint`, `models`, `reasoning_effort` and `output_tokens_field` in the clear (§6.1).
- The deputy's socket unit is enabled (`sudo systemctl enable --now maknae-egress.socket`, §6.2), or every permitted prompt is refused as not ready.
- Which roles may send content to a provider is a separate decision, made in `authz.yaml` (`roles:` and `destinations:`, destination `provider:<name>`) — see the runbook, Chapter 3 §7. An authorized provider is reachable by nobody until that grant exists.
- A user's first turn (`maknae login`, then `maknae agent "<prompt>"`) is `docs/first-provider.md`'s walk-through.
