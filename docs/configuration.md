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
daemon loads `authz.yaml` and `bindings.yaml` (§2.3), boots its kernel graph store
from `bindings.yaml`'s identity layer, builds its
authorization composition — the RBAC baseline, compiled from the store and
`authz.yaml` into a snapshot, and the classification ceiling, both non-removable
(ADR-0008 decision 1; §4.1) — records the composition, the selected system and the
ceiling level in the audit trail, mints its plane credential, binds the client socket
and **serves**: every request is decided through that composition until a shutdown
signal, and the process exits with the outcome the accept loop stopped on. A `SIGHUP`
re-reads `authz.yaml` and `bindings.yaml` together and recompiles the snapshot
(runbook, "Reload the policy"). A boot that fails any of those
steps exits non-zero, and a step after the credential mint retires the credential on
the way out.

What a start runs is the **accepted baseline** (§3.2), not the files as they stand.
`maknaed` reads `maknae.yaml` and `config.d/`, then the accepted baseline from its
kernel graph store, and runs the accepted baseline with the files' `vault`, `audit`
and `deployment` sections in place of its own. Any other difference between the files and
the accepted baseline is a pending change that waits for `maknae baseline-accept`;
a restart never applies it. The first start of this version, and the first start of
a fresh install, takes the files as the accepted baseline with no accept.

- A `core`-less `maknae.yaml` boots at the **Public baseline** (§4.1). An empty one
  refuses to start (exit 1), because the `deployment` section is required (§6.5).
- An **absent config directory or a missing `maknae.yaml`** **fails closed** (exit 1)
  when there is no accepted baseline yet — a fresh install with no `/etc/maknae` does
  not come up. Over an accepted baseline, the start keeps the accepted baseline and
  records the files as an invalid change (§3.2).
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
| `PATH` | the helpers `maknae` and `maknae enroll` spawn | selects no program Maknae runs: each one is named by absolute path (`maknae_io::program`). It is kept because the helpers inherit it |
| `HOSTNAME` | `maknaed` | the AU-3c host label, which is correlation only and falls back to `maknaed`. Listed so inheriting it is a decision rather than an oversight |
| `KUBERNETES_SERVICE_HOST` `container` | `maknaed` | corroborating container markers for the boot check of `deployment.mode` (§6.5). They can let `container` start; they never refuse `linux-host` |

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
├── bindings.yaml         # who holds which role, and who is contained — a SEPARATE document (§2.3)
├── sensitive.yaml        # paths no file verb may reach, whatever is granted — a SEPARATE document (§2.5)
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
├── sensitive.yaml              # optional, written by the user: paths of their own to protect (§2.5)
├── maknae-vault-token.cred     # Linux, systemd 256 or later: the `maknae login` token, a `systemd-creds --user` file
└── maknae-vault-token          # Linux, older systemd: the same token in a 0600 file
```

On macOS `maknae login` keeps the token in the default keychain instead (service `maknae-cli`, account `maknae-vault-token`), and neither token file exists (`crates/maknae-vault/src/token_record.rs`, `keychain_policy.rs`).

**Sections versus standalone documents.** `maknae.yaml` and `config.d/*.yaml` contribute **registered sections** and are merged section-by-section by this loader. `authz.yaml`, `bindings.yaml`, `sensitive.yaml` and `egress-bounds.yaml` are **standalone documents with their own readers**: each is opened by path (`<config-dir>/authz.yaml`, `<config-dir>/bindings.yaml`, `<config-dir>/sensitive.yaml`, `<config-dir>/egress-bounds.yaml`), never merged, never shadowed, and putting any of them inside `config.d/` does not work. `providers.yaml` and the personal `sensitive.yaml` are likewise standalone documents, read by the CLI from its own directory.

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

**`maknaed` holds every source to more.** `maknae.yaml`, every `config.d/` member (a shadowed one included), and `<config-dir>` and `config.d/` themselves must be **root-owned** and **not writable by group or other** (`mode & 0o022 == 0`, on top of the no-world-bits rule), so **`660` and `770` are refused** — `loader.rs`'s `ROOT_ARTIFACT`. Valid examples: `640`, `600`, `440` for a file, `750`, `700` for a directory. The refusal is `SourceNotRootOwned`, naming the path that failed: `<path> must be owned by root and not group- or world-writable, as must every maknae.yaml and config.d source and the directories that hold them`. See §9.3 for the worked example and the full table.

| Path | Recommended modes | Rejected |
|---|---|---|
| `maknae.yaml`, `config.d/*.yaml` | `640`, `600`, root-owned | not owned by root, or group- or other-writable (e.g. `660`), or any world/other bit (e.g. `644`) |
| `~/.maknae/providers.yaml`, `~/.maknae/sensitive.yaml` | `600`, `640`, the user's own | anything with a world/other bit — **`egress-bounds.yaml` is a root artifact that is `0644` by design (§6.1.3)** |
| `<config-dir>` | `750`, owned by root (`root:_maknae 0750` as packaged) | not owned by root, or group- or other-writable (e.g. `770`, `775`) |
| `config.d/` | `750`, `700`, owned by root | not owned by root, or group- or other-writable (e.g. `770`, `775`) |

Additional file rules:

- **Symlinks inside the config tree are refused** — the base file `maknae.yaml`, the
  `config.d/` directory, and every loaded `config.d/` entry must be real, not symlinks.
  The **top-level `<config-dir>` itself may be a symlink**: it is canonicalized first,
  then its (real) target is permission-checked. Symlink rejection applies to the
  *contents* (the injection surface), not to the operator-chosen root path.
- A config file that is **not a regular file** (FIFO, socket, device, directory) is
  refused *before* it is opened.
- The group may **read** the config tree; it may not write it, and *world* access is
  refused. **Not covered by this rule at all:** `egress-bounds.yaml`
  is read through the root-artifact requirement (root-owned, not group- or other-
  writable — no world-read rule), is read by two accounts, and is `0644` by design —
  see §6.1.3 before "fixing" its mode.
- **Non-Unix platforms** refuse to load (the permission model is unavailable there;
  Maknae fails closed rather than run unchecked).

> **Honest limits.** POSIX ACLs are invisible to the mode bits, and the integrity of
> the *ancestor* directories (e.g. `/etc`) is an assumed-trusted precondition. Keep the
> config tree free of world ACLs and on a trusted path.

### 2.3 `bindings.yaml`

`<config-dir>/bindings.yaml` says who holds which role on this host and who is contained (#496). `authz.yaml` holds the grants, the denies and the roles, and refuses a `bindings:` key with ``authz.yaml no longer carries `bindings:`; move the block unchanged to bindings.yaml in the same directory`` (exit 3 at start, a refused reload; see [upgrading](upgrading.md#bindings-move-to-bindingsyaml-496)). The package installs `bindings.yaml` `root:_maknae 0640`, holding `schema_version: 1` and commented examples only.

```yaml
schema_version: 1
bindings:
  admin: ["alice"]
  user: ["bob"]
  guest: []
  adversary:
    - "mallory"     # an account on this host
    - uid: 4242     # an id, contained even before an account has it
```

- **Keys.** The top level holds `schema_version`, which must be `1`, and `bindings`, and nothing else. `bindings:` maps the roles `admin`, `user`, `guest` and `adversary` to lists. An entry is a username; quote it, because an unquoted number is refused. Under `adversary` only, an entry may also be `uid: <n>`, with `n` from 0 to 4294967294, which contains that id whether or not an account has it.
- **Absent versus empty.** `sudo maknae enroll` writes this file with a `bindings:` key listing the enrolling user under `admin` (a re-enroll adds the user if absent and removes nothing). With no `bindings:` key, as in the file the package ships and on a host not yet re-enrolled, bindings are absent: the enrolled principal holds `admin` and nobody else holds a role, and `maknae contain` is refused with `no-explicit-bindings`. A missing `bindings.yaml` means the same, unless the store holds explicit bindings (below). Once a `bindings:` key exists, only the entries it lists hold a role, so list yourself under `admin`. `bindings: {}` binds nobody, the enrolled principal included.
- **Ownership and mode.** As for `authz.yaml`: a regular file, not a symlink, owned by root, with `mode & 0o027 == 0` (no world access and no group write; `0640` as shipped). `<config-dir>` itself must be owned by root and not group- or other-writable (the packages create `/etc/maknae` `root:_maknae 0750`), or both policy files are refused, naming the directory: `the directory <config-dir> holding authz.yaml must be owned by root (uid 0) and not group- or other-writable` (`holding bindings.yaml` for the other file). Only a missing file inside such a directory reads as absent; a missing directory, a symlink, the wrong owner or mode, an empty file and a read error each refuse.
- **Deleting is not resetting.** Once the store holds bindings from a `bindings:` key, a `bindings.yaml` that is missing or has no `bindings:` key changes nothing at a start or a reload: every binding and containment stands, the loss is recorded as `graph.sync` `lost: …`, `maknae status` shows `bindings.yaml lost`, and `sudo maknae policy sync` restores the file. Returning to principal-as-admin takes `sudo maknae reseed` over a `bindings.yaml` with no `bindings:` key. The one exception is the first start of this version over a store that has no merge state yet, which refuses (exit 3) instead ([runbook](runbook.md#the-kernel-graph-store-refuses-to-start)). No package upgrade recreates a deleted `bindings.yaml`: dpkg does not reinstall a conffile you removed, and the RPM and macOS packages install the shipped file only when no kernel graph store exists.
- **Merged with live state.** `maknaed` does not take the file as it stands: at each start and reload it merges the file entry by entry with the bindings it enforces, which may hold live edits not yet in the file, and an entry changed differently on both sides fails closed ([runbook](runbook.md#how-bindingsyaml-and-live-state-merge)).
- **Live containment.** `maknae contain` and `maknae release` ([runbook](runbook.md#contain-a-subject-over-the-wire)) change the enforced bindings without touching this file. A live containment appears here as `- uid: <n>` under `adversary` after `sudo maknae policy sync`, and never with its reason. A release removes every `adversary` entry that claims the uid, including a name listed here; its removal reaches this file only through a sync run at a terminal.
- **Grants.** `authz.yaml`'s `roles.admin.allow` holds the administrative terms. The shipped file grants `admin.status`, `admin.subject.list`, `admin.baseline.show`, `admin.baseline.accept`, `admin.release` and the five conversation terms (§2.4). `admin.contain` is grantable but not granted, so add it deliberately. `admin.contain` and `admin.release` are grantable to `admin` only: a grant of either to `user`, `guest` or `adversary` refuses at load.
- **A synced file.** `sudo maknae policy sync` writes this file from the bindings `maknaed` enforces, in the grammar above, `root:_maknae 0640`. The installed file starts with one comment line, `# installed by sudo maknae policy sync from maknaed's mirror at revision <n>`, lists each role's entries one per line, quoted, with `- uid: <n>` for an id, and keeps no other comment ([runbook](runbook.md#sync-live-identity-changes-back-to-bindingsyaml)).

**What refuses the whole file.** A defect in the file itself refuses the whole load: the start refuses with exit 3, and a reload is refused with the running policy left as it was. The defects are: YAML that does not parse or has the wrong shape, a missing or unknown `schema_version`, an unknown top-level key, an unknown role key (`bindings names unknown role '<key>'`), the same entry twice in one list (`identity '<name>' listed twice in one role`), a `uid:` entry outside `adversary`, an unquoted number in a list, a name that is empty or contains `:`, `,` or a control character, and the ownership and mode failures above. An account lookup that fails, as distinct from one that finds no such user, also refuses the whole load: `looking up '<name>' failed (errno <n>); nothing was changed`. On macOS this includes an account whose passwd record is larger than 4 KiB, which refuses every load while it is named in the file (#501).

**What is decided per subject.** The outcome of resolving a name affects only that subject, and the rest of the policy loads:

| The file says | Result |
|---|---|
| A name under `admin`, `user` or `guest` with no account on this host | That name holds no role. |
| A name under `adversary` with no account on this host | The name contains nothing. A `- uid: <n>` entry contains an id whether or not it has an account. |
| One uid under `adversary` and under another role, by the same name, by two names, or by a `uid:` entry | The uid is contained. Containment wins. |
| One uid under two of `admin`, `user` and `guest`, by the same name or by two names | That uid holds no role. |
| A name under `adversary` that the store holds as contained and that no longer resolves | The uid it last resolved to stays contained (carried forward) until you remove the name from `adversary:`. The store keeps every name under `adversary` with its own last uid, so this holds for each of two names for one account, whether or not the other still resolves. If that uid now belongs to another name in the file, it stays contained, and the record says which binding it overrides. A containment ends only when no name still under `adversary` claims its uid. |

Each of these is a `graph.identity` audit record and a journal line, such as `maknaed: identity: 'bob' under user has no account on this host; it holds no role`. A start records every problem; a reload records only the problems the previous load did not have. `maknae status` prints the counts by kind, and `maknae subject-list` lists each subject with its uid, a label and its state ([runbook](runbook.md#bind-a-user-contain-a-subject)). Two names with one uid under the same role are one subject. A subject that holds no role is decided like any uid the file does not list: the RBAC baseline has no rule for it, which denies in the default build (an ABAC operand may still permit on its own predicate, ADR-0008). A contained subject is denied by a mandatory decision that nothing overrides.

**When the user directory is unavailable.** When sssd or LDAP is down, the C library usually reports a directory account as "no such user", which Maknae cannot tell from a deleted account. On macOS a failed lookup cannot be told from a missing account at all. So, during an outage:

- a name already contained stays contained (carried forward, as above, until you remove it from `adversary:`);
- a name that never resolved is not contained;
- a role binding to a directory name holds no role until the directory returns and you reload.

To contain an id independently of the directory, list it as `- uid: <n>`. On Linux `maknaed.service` is ordered after `nss-user-lookup.target`, so it starts after the local lookup services that pull the target in (such as sssd) have started; it does not wait for the directory server to be reachable, and on a host with no such service the ordering does nothing. launchd has no such ordering. So on both platforms carry-forward and `uid:` entries are the controls for an outage, and after an outage at boot or at a reload, reload once the directory is back.

**When an edit applies.** At the next reload or restart (runbook, "Reload the policy"), merged with the live state as above. A reload reads `authz.yaml` and `bindings.yaml` together as one policy: if either is refused, neither edit applies and the running policy stands.

### 2.4 Conversations (#170)

The kernel records each conversation a loop opens: an owner, the working directory it was opened in, a hash chain over the request turns, the digest of the reply last bound to it, and counts of turns and bytes. It never stores turn content. Records live in the `conversations/` directory beside the kernel graph store, sealed under the same key (`/var/lib/maknae/conversations` on Linux, `/usr/local/var/db/maknae/state/conversations` on macOS).

**The five terms.** `authz.yaml` grants a role these by name, never as `session.*`:

| Term | Effect |
|---|---|
| `session.new` | open a conversation |
| `session.prompt` | send turns on an active conversation the subject owns |
| `session.list` | list the subject's own conversations |
| `session.close` | close an active conversation the subject owns |
| `session.delete` | delete an active conversation the subject owns. For an id the kernel does not hold, the kernel names the caller as its owner, so the grant alone permits it; the outcome reads `conversation deleted; the kernel held no record` |

The shipped file grants all five to `admin` and to `user`. It has no `destinations:` key, so a prompt is refused at the destination check until you add one ([first provider](first-provider.md#4-allow-the-prompt)). Agents are refused `session.new` unless an agent `policy.yaml` grants it.

**The working directory is recorded, not decided.** `session.new` is decided by the grant alone; only once the grant permits does the kernel check the client's descriptor. It records the directory the descriptor resolves to, as the kernel reports it, and neither decides it as a read nor confines the conversation to it. A symlinked directory is recorded as its target. What bounds each `fs.*` request is the OS's own permissions, the `permissions:` entries of `authz.yaml`, the classification ceiling, and `sensitive.yaml` (the host list and the conversation's personal list); `fs.*` is not confined to the home (ADR-0034).

**The pairing rule.** In `authz.yaml`, a role or a `subjects:` entry whose effective grant (allow minus deny, after family expansion) holds `session.prompt` without `session.new` refuses the whole file at load. An agent's `policy.yaml` is exempt.

**Bounds.**

- A conversation idle for 24 hours is closed, audited with reason `idle`, at its owner's next `session.new` or `session.list`; closing frees its slot. No other request closes it.
- An owner may hold at most 32 active conversations (`OWNER_MAX_ACTIVE`). A `session.new` past that is refused after the grant is permitted.
- A conversation holds at most 256 MiB, counting its request turns and the replies bound to it.
- A `session.list` page holds at most 12 conversations.

**Known limits.**

- A retry after a delivered reply is sent to the provider again, which answers anew.
- Idle expiry reads the wall clock, so a clock change moves it.
- A loop ended by SIGHUP, SIGQUIT or a panic leaves its conversation open until the idle sweep closes it.
- A store write or removal the host does not confirm reached the disk is answered `Unauthorized` and audited `outcome unknown`: the record may hold the change, or lose it after a crash, so an open conversation can hold a slot until the idle sweep closes it.
- A corrupt record is never counted, listed, closed or deleted, and stays so.
- An unreadable record is audited again on each scan that meets it, and a failed idle-sweep scan records nothing.
- Each scan reads the whole store, so its cost grows with every owner's conversations (#616).
- `session.delete` of an id the kernel does not hold is permitted, so it tells the caller whether an id is held; ids are 128 random bits.
- A prompt's chain advance is written before its egress intent, so after a crash the record can cover a request whose only audit record is a deny, or none; the loop's retry is admitted.
- When marking a conversation full fails, or the reply binding never starts within its bound, its owner can be billed again for a reply the kernel then refuses; each attempt is audited.

**Single host.** The store admits one `maknaed` per state directory: the directory is locked exclusively while the daemon runs. Sharing it between hosts is not supported (#616).

**From the CLI.** `maknae session list [--cwd <dir>]` lists the caller's conversations, optionally those opened in one directory. `maknae session close <id>` closes one by its 32-character id. The loop opens a conversation at start and closes it on exit and on Ctrl-C.

### 2.5 `sensitive.yaml` (#617)

`sensitive.yaml` lists paths that no file verb may reach (`fs.read`, `fs.write`, `fs.delete`, `fs.mkdir`, `fs.stat`, `fs.list`). An entry refuses every one of them on that path, for every role, `admin` included, whatever `authz.yaml` grants. It is a mandatory operand of the authorization composition, beside the `authz.yaml` baseline and the classification ceiling (ADR-0034), so no grant can waive it. It never grants anything.

There are two lists, and a request is refused when either one matches.

| | Host list | Personal list |
|---|---|---|
| Path | `/etc/maknae/sensitive.yaml` | `~/.maknae/sensitive.yaml` (`$MAKNAE_CONFIG_DIR/sensitive.yaml` when that is set) |
| Read by | `maknaed`, at start and at each reload | the CLI, when it opens a conversation |
| Ownership and mode | as `authz.yaml`: a regular file owned by root, `mode & 0o027 == 0` (`0640` as shipped, `root:_maknae`), in a root-owned directory no group or other can write | as `providers.yaml`: the user's own, no world bits (`0600` or `0640`) |
| Absent | `maknaed` refuses to start | no personal entries |
| Malformed | `maknaed` refuses to start (exit 3); a reload is refused and the enforced list stands | the CLI refuses to open the conversation, naming the file and the cause |
| Applies to | every file request: the loop's, an agent's, and your own `maknae read`, `write`, `delete` and `mkdir` | only requests that cite a conversation you own (below) |
| Shipped | yes, by every package, with the defaults below | no |

The packages install the host file `root:_maknae 0640`. An upgrade keeps an edited file: it is a deb conffile and an rpm `%config(noreplace)` file, and the macOS package installs it only when it is absent.

```yaml
schema_version: 1
sensitive:
  - "~/.ssh/**"
  - "/etc/shadow*"
  - "/opt/vendor/license.key"
```

**Grammar.**

- The document holds `schema_version`, which must be `1`, and `sensitive`, and nothing else. An unknown key refuses: `sensitive.yaml: unknown key '<key>' in 'sensitive.yaml'`.
- `sensitive:` is required. A file with no `sensitive:` key refuses (`` `sensitive` is required (write `sensitive: []` for none) ``), so an empty list is written `sensitive: []`.
- Each entry is a quoted string (``every `sensitive` entry must be a quoted string``) in the path language of `authz.yaml`'s `permissions:`, without the `Read(...)`/`Write(...)` wrapper: an absolute path or one that starts with `~/`. `*` matches within one path component, `**` matches any number of components, and `X/**` also matches `X` itself. `*` and `**` match names that start with a dot.
- `~` is the requesting user's home, the same home `~` means in a grant. Another account's files are bounded by the OS's permissions, exactly as they are outside Maknae. To cover every account's files, list them by absolute pattern in `/etc/maknae/sensitive.yaml`, for example `/home/*/.ssh/**` on Linux or `/Users/*/.ssh/**` on macOS. `~name` is refused, as are a relative path and a `.` or `..` component: ``entry '<entry>' must be an absolute path or start with `~/`, without `.` or `..` components (`~name` is refused)``.
- **Never write `/**`, and on macOS never write `/System/Volumes/Data/**`.** Matching strips a leading `/System/Volumes/Data` on macOS (below), so that entry becomes `/**`, and either one refuses every file request on the host.

**How a path matches.** An entry is matched against the path the kernel reports for the object the request opened, so a symlink is decided as its target and a file with a second hard link is refused before any match (ADR-0034 decision 2).

- **Linux:** byte for byte, case-sensitively.
- **macOS:** case-insensitively and normalization-insensitively (the entry, the path and the home are each compared in NFC under full Unicode case folding, so a composed `é` and a decomposed `é` match, and so do `ß` and `ss`, `ſ` and `s`, or the Kelvin sign and `k`). A leading `/System/Volumes/Data` is removed, and a leading `/private/etc`, `/private/tmp` or `/private/var` is read as `/etc`, `/tmp` or `/var`, on the entry and on the path. Write each entry once, in either spelling.
- **A directory delete** (`fs.delete`, recursive or not) is refused when any entry could match the path or anything beneath it, whether or not the directory is empty, so a protected file cannot be removed by removing its parent and the answer does not say whether a protected child exists.
- An entry for a path the host does not have is harmless.

**What the model and the user are told.**

- **A protected path answers `Protected`.** The kernel matches the path the request asks for against both lists before it opens anything, so the answer is the same whether or not the file exists. The CLI prints `maknae: <path> is protected by <list> (<entry>). Maknae will not touch it; run this outside Maknae.`, where `<list>` is `/etc/maknae/sensitive.yaml` or `~/.maknae/sensitive.yaml`. When the model's tool call is refused this way, `maknae agent` prints the same notice on stderr. The model sees only `protected by policy — ask the user to do this outside Maknae`, which names no list and no entry.
- **Every other refusal of a file verb reads the same to the model:** `unavailable — do not retry`. That covers a missing file, a path no grant covers, a refusal by the OS or the ceiling, a descriptor check (a second hard link, the wrong kind), a request whose asked path is not listed but whose target is (a symlink into `~/.ssh`), and transport and capacity faults. The model cannot tell from the answer whether the file exists. The standing prompt tells it that some files are withheld this way and that it must not infer state from them or ask you to paste a credential.
- **A listing shows only what may be seen.** The model's `list_directory` releases only the entries whose own `Read` is permitted: an entry a list, a grant or the ceiling withholds is absent, exactly as a name that does not exist, and the listing carries no count or total. That holds up to the 65,536-name bound: a call decides at most 65,536 names, so a directory that reaches the bound before a full page is permitted answers `unavailable`, and enough withheld names can turn a page into that answer; entries past the 65,536th name cannot be reached with the cursor. A page holds up to 1024 entries, fewer when names are long. `maknae agent` prints `maknae: <n> entries not released`, `maknae: <n> entries with a non-UTF-8 name not listed` and `maknae: <n> entries changed while being listed and not listed` on stderr for you; the model never sees these lines. `stat_path` returns a path's kind, size and modification time and nothing else.
- **The trail says which.** A refusal by either list is audited with the reason `sensitive: host <entry>` or `sensitive: personal <entry>`; every other cause keeps its own reason.

**The personal list.**

- **A snapshot.** The CLI reads `~/.maknae/sensitive.yaml` when it opens a conversation and sends the entries with `session.new`. The kernel checks each entry with the same parser, refuses the whole `session.new` if one fails, and stores them on the conversation. An edit takes effect in the next conversation, not the open one.
- **It binds only requests that cite the conversation.** The loop's tool calls cite it. Your own direct commands (`maknae read`, `write`, `delete`, `mkdir`) cite none, and get the host list only. It is not a control against a loop that declines to cite: an altered client can leave the citation off, and such a client can already read anything as you. Put a path that must hold against every request in the host list.
- **Owned conversations only.** A request that cites a conversation someone else owns gets nothing from that conversation's list.
- **Refusals.** A malformed file stops the CLI before the conversation opens, naming the file: `maknae: ~/.maknae/sensitive.yaml: <cause>`. So does an entry longer than 4096 bytes, and a list too large to send in one request (`~/.maknae/sensitive.yaml is too large to send (<n> bytes; the limit is 65536)`).
- An entry can only refuse. The worst a wrong entry does is hide one of your own files from your own model.

**Three rules for every file request.**

- **When your home cannot be looked up**, every `fs.*` request is refused before any list is consulted, with the trail reason `requester home unavailable: <cause>`, where the cause is `unresolvable`, `timed out`, `at capacity for this requester` or `at capacity`. A listed path then reads `unavailable — do not retry` to the model, not `Protected`. Other verbs are unaffected.
- **A write needs `Read` as well as `Write`.** Every `fs.write`, creating a file or replacing one, is permitted only when `authz.yaml` permits both `Read` and `Write` on the path, so a `Write`-only grant permits no write, for your own `maknae write` as for the model. The trail reason of a write refused for want of `Read` is `fs.write needs fs.read: <the read's reason>`.
- **`fs.stat` and `fs.list` are decided by the `fs.read` grant.** They are not separate grants: the `Read` entry of `authz.yaml`'s `permissions:` that decides a read of a path decides a stat of it and a listing of it, and each listed entry is decided as a read of that entry. An `actions:` limit, in an `authz.yaml` `subjects:` entry or an agent's `policy.yaml`, limits them by its `fs.read` entry. Naming `fs.stat` or `fs.list` in either list is refused at load: ``authz: `fs.stat` is decided as `fs.read` (#161 M15) and no list may name it; name `fs.read` `` (`fs.list` likewise).

**The shipped host list.** The defaults were built from the paths that hold credentials and system secrets on Debian 13, Rocky 9, a STIG'd Rocky 10 and macOS 26. Each group in the file carries a comment saying why it is there:

- accounts and password hashes (`/etc/passwd*`, `/etc/shadow*`, `/etc/group*`, `/etc/gshadow*`, `/etc/security/opasswd`);
- who may become root (`/etc/sudoers`, `/etc/sudoers.d/**`, sudo's own configuration, polkit rules);
- host identity and service secrets (SSH host keys and `sshd_config`, `krb5.keytab`, IPsec, `crypttab`, systemd credentials, NetworkManager and wpa_supplicant connections, sssd, Samba, `/etc/fstab` for CIFS `credentials=`);
- private keys (`/etc/pki/**/private/**`, `/etc/ssl/private/**`);
- defensive configuration: audit, AIDE, fapolicyd, USBGuard, the firewall, cron, the boot loader and `sysctl.d`;
- root's home, cloud-init user-data and the systemd credential key;
- Maknae's own configuration (`/etc/maknae/**`, `~/.maknae/**`);
- process and runtime secrets: `/proc/*/environ`, `cmdline` and `mem` (and their `task/*` and `thread-self` forms), `/run/user/*/**`, `/tmp/krb5cc_*`, `/run/secrets/**`, `/var/run/secrets/**`;
- macOS: `/etc/master.passwd`, `/var/db/dslocal/**`, `/var/db/sudo/**`, `/var/root/**`, `/Library/Keychains/**`;
- each user's credentials: SSH and GnuPG keys, cloud and cluster logins (AWS, Azure, gcloud, kube), registry and package-index tokens (Docker, containers, npm, PyPI, Cargo, RubyGems, Maven, Gradle), `.netrc` and git credentials, the GitHub CLI, Vault and Terraform tokens, database passwords, password stores and keyrings, 1Password and rclone, AI-tool logins (Claude, Codex, Gemini), browser and mail profiles, and shell and editor history;
- each user's credentials on macOS: keychains, cookies, Mail, Messages, the privacy (TCC) database, and Chrome and Firefox profiles.

The shipped `authz.yaml` carries no denies of its own: its `deny:` list is empty, and the credential paths it once denied are in this file. Edit the host file to add or remove entries, then [reload](runbook.md#edit-and-reload-the-host-sensitive-list). Entries that would help every installation are welcome upstream.

### 2.6 Tasks (#628)

The kernel stores each task given to an enrolled agent in the `tasks/` directory beside the kernel graph store, sealed under the same key: `/var/lib/maknae/tasks` on Linux (`StateDirectory=maknae maknae/conversations maknae/tasks`), `/usr/local/var/db/maknae/state/tasks` on macOS, both `_maknae 0700`. Each task is one `<id>.task` file, and `counters.task` holds the sequence numbers already issued. A record holds the signed task with its prompt, its follow-ups and its report, so the directory holds task content. Tasks survive a restart.

**At start.** A record whose submission was never confirmed is discarded, and an unreadable or oversized one is renamed `<id>.task.quarantine` and never read again; each is recorded first ([runbook: Tasks](runbook.md#tasks)). A missing, unreadable or lagging `counters.task` beside stored tasks refuses the start. Every working task's 15-minute lease begins again, and the tasks of an agent that is no longer enrolled are closed.

**Bounds.**

- An agent holds at most 256 open (queued or working) tasks.
- A tasker holds at most 32 open tasks with one agent, and at most 256 records over every agent, counting open tasks, reports and closes not yet collected.
- A prompt, a follow-up and a report are each at most `transport.prompt_max_bytes`. A task takes at most 32 follow-ups, together at most `prompt_max_bytes`.
- A report or close not collected in 30 days expires and is removed.
- A `list` page holds at most 32 tasks. A `collect` page holds at most 32 reports, as many as fit one frame, and always at least one.

**The frame margin.** `transport.prompt_max_bytes` bounds the text; the frames carry more. A prompt-class request frame may be `prompt_max_bytes + 4096` bytes, so a submission, follow-up or report of the full size fits its envelope. A prompt-class response frame may be 32 KiB more again, so a full task delivered with its kernel signature fits. The daemon bounds its own task answers by the largest `prompt_max_bytes` it may be set to, 16 MiB, not by the current value, so lowering `prompt_max_bytes` never strands a stored report or a queued prompt. A client that reads task answers must accept the same size, whatever its own `prompt_max_bytes`; otherwise one large report would stop it collecting.

**Partitions.** An agent works each task in a directory of its home chosen by the tasker at the root of the task's chain:

| Root tasker | Partition |
|---|---|
| a person, by uid | `<agent home>/tasks/users/<uid>` |
| an agent starting a chain of its own | `<agent home>/tasks/agents/<id>` |

A sub-task, one an agent gives while it works a task, works in its root's partition. The kernel names the partition, relative to the agent's home, when it hands the task out; the agent process creates it (#629). The fourth mandatory operand, `maknae-partition`, decides every file request an agent makes, whatever its role and `policy.yaml` grant:

- inside the partition of the task the request cites, and anywhere outside `<agent home>/tasks`, the other operands decide;
- `<agent home>/tasks`, `tasks/users` and `tasks/agents` may be listed, statted and created, and nothing more; a listing of them shows only the cited task's own partition;
- anything else under `tasks/` is refused: another tasker's partition, and every partition when the request cites no task;
- a delete of a directory that holds `tasks/` is refused;
- `fs.move`, `fs.link`, `fs.chmod` and `fs.chown` from an agent are refused.

A refusal is the model's uniform `not authorized`, with the reason `partition: …` in the trail. The operand bounds what the kernel releases to the model, not the agent process, whose account owns its whole home; confining the process is #629. People are not affected: the operand abstains for every request off the agent channel.

**Single host.** Like the conversation store, the task store admits one `maknaed` per state directory.

---

## 3. Sections and precedence

> **Every section with a parser refuses a key it does not read** (#210), naming the token and the level: `unknown key 'jsonl_pth' in 'audit'`. An ignored key would silently substitute the default for what you wrote — `jsonl_pth` would quietly move the audit sink to `<config-dir>/audit.jsonl`, and `handlng` would hide the whole classification-ceiling block so the instance came up at the system's lowest level — and the direction is not always weaker: `max_connections` defaults to 64 against a ceiling of 4096, so a typo'd raise would land stricter. No single section of this reference lists every key, so the closed sets are listed here (§4 does not enumerate all of `core`; it omits `deployment_id`, which is on every enrolled host):
>
> | section | every key its parser reads |
> |---|---|
> | `core` (own level) | `schema_version`, `deployment_id`, `identity`, `handling` |
> | `core.handling` | `ceiling`, `accreditation_ref`, `policy` |
> | `transport` | `socket_path`, `agent_socket_path`, `max_connections`, `prompt_max_bytes`, `handshake_timeout_ms`, `read_timeout_ms`. `agent_socket_path` is where a host-mode `maknaed` accepts enrolled agents: `/run/maknae-agent/maknaed.sock` on Linux, `/usr/local/var/run/maknae-agent/maknaed.sock` on macOS. A value in the directory of `socket_path` refuses the configuration. |
> | `audit` | `jsonl_path`, `siem`, `au3_1`, `readers` (§6.3) |
> | `principal` | `name`, `uid` |
> | `vault` | `addr`, `approle_mount`, `pki_int_mount`, `deployment_id`, `insecure_plaintext_secret_path`, `user_auth`, `kv_mount`, `user_prefix`, `plane_key` (`crates/maknae-vault/src/config.rs`). In the **root** `maknae.yaml`, `kv_mount` and `user_prefix` refuse boot — `vault.kv_mount in the root maknae.yaml is not read by maknaed: set kv_mount in egress-bounds.yaml` (likewise `user_prefix`), shadowed `config.d/` blocks included — because the host's copy lives in `egress-bounds.yaml` (§6.1.3); they belong in each user's `maknae.yaml` (§6.1.2) |
> | `vault.user_auth` | `type`, `mount` |
> | `providers` (each entry) | `name`, `endpoint`, `models`, `reasoning_effort`, `output_tokens_field` (§6.1) |
> | `egress` | `socket_path`, `deadline_ms` (§6.2) |
> | `deployment` | `mode`, `account_source` (§6.5) |
>
> The CLI's own `maknae.yaml` registers `vault`, `transport` and `agent` only (`bins/maknae/src/cli.rs`), so any other section there — a `provider:` block included — refuses every CLI verb with `UnknownSection`. Standalone documents close their keys the same way: `egress-bounds.yaml` (§6.1.3), `providers.yaml` (§6.1.1) and `authz.yaml`.
>
> **Two places are deliberately still open** and a key there continues to load: `lake`, which is registered for a forthcoming subsystem and has no parser, and `core.identity`, left as it is by maintainer direction. **Three limits, stated so the note is not read as more than it is.** (1) This closes wrong key NAMES. A key with the right name and the wrong SHAPE is handled per field and NOT uniformly: the bounded numeric and typed fields refuse (`transport: { max_connections: nope }` is `InvalidTransport`), while the shape-TOLERANT ones — `audit.jsonl_path`, `audit.siem`, and `vault`'s `get_str` keys — silently default that one field. That tolerance is a deliberate decision recorded in the parsers. (2) `core`'s own level is checked where the DAEMON consumes it, so a `core` typo in a CLI-side `maknae.yaml` is not caught by this at all — it may surface later as a missing-key refusal, or not at all: an extra `handlng` beside a valid `deployment_id` is simply ignored there, and even a misspelled `deployment_id` can be masked by the supported `vault.deployment_id` fallback. (3) A `core` that is present but not a MAP still boots at the system's lowest level, as `ceiling_from_core` has always documented and a test pins — the sibling sections refuse a non-map, `core` does not, and changing that is a decision nobody has taken. **The check applies to the contribution that WINS precedence** — a `config.d/` member replaces a whole section, so a key in a shadowed block is never read and is not refused. Three checks are the exceptions and read shadowed blocks too: the plaintext-key scan of `providers`, the root `vault` check above, and `principal`, where a shadowed block must not carry an unknown key such as `home`.

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

### 3.2 The baseline

Everything in `maknae.yaml` and `config.d/` is the **baseline**: every section, `core` included. `maknaed` keeps the accepted baseline in its kernel graph store, one canonical-JSON value per section with a digest over all of them, and compares the files with it at every start, every applied reload, every `maknae baseline-show` and every `maknae baseline-accept`. A start runs the accepted baseline, never the files as they stand.

**The first start takes the files.** On a fresh install, and on the first start of this version over an existing store, there is no accepted baseline yet: the start takes the files as the accepted baseline with no accept, and records it (`graph.baseline`, reason `baseline seeded from maknae.yaml and config.d (no accepted baseline yet)`). A file that does not validate then refuses to start, as it always has: exit 1 with nothing written to the audit trail, or exit 3 for a `principal` defect and exit 4 for an audit offload refusal, each recorded.

**`vault`, `audit` and `deployment` follow the file at start.** The start runs the accepted baseline with the files' `vault`, `audit` and `deployment` sections in their place, except `audit.readers`, which keeps its accepted value, and records each section that changed (`graph.baseline`, `vault follows maknae.yaml at start`, `audit follows maknae.yaml at start`, `deployment follows maknae.yaml at start`). `audit.readers` changes only by an accept, where each account is resolved (§6.3); a readers difference stays in the pending change set, and no restart, a package upgrade's included, folds it into the accepted baseline. That combination is validated as a whole first; if it does not validate, or it moves the audit trail to a file that is not prepared (§6.3), the start runs the accepted baseline unchanged and the files are an invalid change. A reload never applies any of the three.

**Every other difference is a pending change set.** There is one set per source, and today the only source is the files (`root-file`). The set is the whole difference between the files and the accepted baseline, recomputed every time it is read, so a further edit changes the same set rather than adding another; it is never persisted, and a restart never applies it. It applies only when a granted operator accepts it:

```bash
maknae baseline-show                 # the changed settings, how they apply, and the set's hash
maknae baseline-accept <hash>        # the 64-character hash baseline-show printed
```

`admin.baseline.show` renders each changed setting as `<section>.<path>: <old> -> <new>`, through the same rules as `maknae config-show`: a masked value renders `<value set>`, a missing side `<absent>`, and every change under a withheld setting (`core.handling`, `audit.au3_1`, `lake`, `vault.insecure_plaintext_secret_path`) collapses into one line, `a suppressed setting changed (not disclosed)`. The hash binds the accepted baseline and the proposed one, so an accept names exactly the set that was shown: after any edit, or any other accept, the old hash is refused (`baseline accept refused: stale; run maknae baseline-show`) and nothing changes. The full hash appears only in `maknae baseline-show`'s reply; the audit trail carries its first 12 hex digits, and `maknae status` prints only `baseline: 1 pending (live)`, `(restart)` or `(invalid)`, as of the last start, applied reload or accept. `maknae baseline-show` always reads the files afresh.

**An accept runs the start's checks.** The proposed baseline is validated as a start validates it, and in addition each account in `audit.readers` is resolved in the account database (§6.3), a changed `transport.socket_path` is bound and removed again, and, when providers are authorized, a changed `egress.socket_path` is connected to and closed. Any failure refuses the accept, and nothing is written. An accept is refused while a reload holds its turn for more than 5 seconds (`busy; a reload holds the turn`) and while the daemon is stopping or already restarting into an earlier accept.

**What applies live, and what applies by restart.**

| Changed | Applies |
|---|---|
| `principal`, and `providers` while it stays non-empty | **live**: the next decision uses it |
| `audit.readers` | **live**: no restart; `maknaed` reads nothing from it. The grant follows the file: the packages and the runbook's "Grant the declared readers" block read `maknae.yaml`, and the accept records the list and resolves each account (§6.3) |
| everything else, including all of `core.handling`: adding the block, the ceiling and its level, `accreditation_ref` and `policy` (the classification system); every other `core` key, `vault`, `deployment`, `transport`, `egress`, `lake`, the other `audit` keys, `providers` going from empty to non-empty or back, and a section added or removed | **by restart** |

A set that contains any restart change applies by restart as a whole. A live accept is persisted, then installed in one step once the decisions in flight have finished; no decision sees part of it. A restart accept is persisted and checkpointed, then `maknaed` stops admitting connections (each is closed unserved, recorded as `connect` denied `draining to apply an accepted baseline`), lets the requests in flight finish under the old baseline, and exits **6**. systemd (`Restart=on-failure`) and launchd (`KeepAlive` with `SuccessfulExit` false) start it again, and the new process runs the accepted baseline. A live accept whose install fails after the persist applies by restart in the same way. A restart accept whose persist fails after admission stopped exits 1, and the supervisor restarts the daemon on the unchanged baseline, with the set still pending.

**An invalid file over an accepted baseline.** The daemon keeps running the accepted baseline, records the files as an invalid change (`graph.baseline`, deny, `baseline change refused: invalid (cause in the journal)`), and refuses to accept it. The validator's cause can quote any configured value, a suppressed one included, so only the journal carries it, verbatim (`baseline change refused: root-file invalid: <cause>`). The same holds for an accept refused as invalid (trail: `baseline accept refused: invalid (cause in the journal)`) and for an accepted baseline that cannot start (trail: `accepted baseline cannot start (cause in the journal)`). A start refused before any baseline was accepted still records the validator's text in the trail. `maknae baseline-show` prints `state invalid` and does not repeat the cause, because its reply reaches every grantee of `admin.baseline.show`. Fix the files; the next start, applied reload or `maknae baseline-show` sees the change.

**An accepted baseline that no longer starts.** If the accepted baseline itself stops validating on this host (an account, a socket directory or `egress-bounds.yaml` changed under it), the start refuses with `accepted baseline cannot start: <cause>` in the journal; the trail's record of it omits the cause. Root replaces the accepted baseline from the files with a reseed: runbook, "The accepted baseline cannot start".

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
> `authorization composition: maknae-authz-basic+maknae-ceiling+maknae-sensitive+maknae-partition; system: US; ceiling: SECRET; sensitive: <n> host entries`,
> where `<n>` is the number of entries in `/etc/maknae/sensitive.yaml`.

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

A section the daemon does not register is `ConfigError::UnknownSection`, which **refuses boot** and names the file it came from: `unknown config section '<section>' in '<path>' (no registered spec)`. The registered set is `crates/maknae-kernel/src/boot.rs`'s `boot_specs()` — `lake`, `vault`, `transport`, `audit`, `principal`, `providers`, `egress`, `deployment`, plus `core` — so every row below marked Forthcoming or Withdrawn stops the daemon if written, rather than being ignored. Of the extension sections, `providers` (§6.1), `egress` (§6.2), `audit` (§6.3) and `deployment` (§6.5) can be configured today.

| Section | Owner | Status |
|---|---|---|
| `authz` | authorization policy *(the config-section registration; the policy FILES `/etc/maknae/authz.yaml` and `/etc/maknae/bindings.yaml` (§2.3) are separate and are enforced per request from a snapshot compiled at start and at `SIGHUP` reload — see the runbook)* | Forthcoming |
| `providers` | the model providers this host authorizes (ADR-0028 decision 1) — **see §6.1** | **Shipped** |
| `egress` | where `maknaed` finds the egress deputy, and the outer bound on one provider call (#240) — **see §6.2** | **Shipped** |
| `deployment` | the kind of host `maknaed` runs on, and the account-state source it asks (#115) — **see §6.5** | **Shipped**; required |
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
- **Who may write the section.** The file that contributes `providers` — `maknae.yaml` **or a `config.d/` member** — must be **root-owned and not group/other-writable**, and so must the **config directory and `config.d/` themselves** (a subject who owns the directory could otherwise choose between root-authored candidates by renaming one out of the scan); otherwise boot refuses with `SourceNotRootOwned` (§2.2). The packaged `/etc/maknae` (`root:_maknae 0640` under `0750`) satisfies this; the subject the loop runs as cannot authorize a destination. A dev-shape `~/.maknae/maknae.yaml` owned by the operator does not, by design.
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
| `output_tokens` | no | the reply cap sent with every request: at least 1, and `context_tokens` less `output_tokens` must exceed the 2,304-token preamble allowance. |
| `default` | no | `true` or `false` (default `false`). |

**How the CLI prints these.** `maknae agent` prints every setup refusal after `maknae: ` and exits 1 (`bins/maknae/src/cli.rs`); `maknae login` prints its own after `maknae login: ` (`bins/maknae/src/login.rs`). The texts below are quoted without the prefix.

Every refusal of this file reads `providers.yaml: <reason>` (`UserProviders`), for example `providers.yaml: providers[0].context_tokens is required: declare the model's context window in tokens`. Two worth knowing:

- Writing `key:` as a string refuses with `providers.yaml: providers[<i>].key must be a map of subpath and field; the API key itself is stored only in Vault, never in this file`. Another spelling, such as `api_key:`, refuses as an unknown key.
- `maknae agent` checks the budget before it sends anything, prefixed by the entry's label: `provider entry <label>: context_tokens <N> is above the 16777216 ceiling`, `provider entry <label>: output_tokens must be at least 1`, or `provider entry <label>: context_tokens less output_tokens must exceed the 2304-token preamble allowance` (`crates/maknae-agent/src/budget.rs`). The smallest window accepted is therefore 2,305.

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
- **The agent's `write_file` is bounded per call, not by `prompt_max_bytes`.** Its arguments, as JSON with the file's content escaped, may be at most 61,440 bytes, a bound chosen with a margin so that a call at this size, alone in a reply, fits the smallest `transport.prompt_max_bytes` an operator can set (65,536). A longer call is not run: the model is told its size and the limit, the other calls in the reply run, and the trail lists the refused call under `refused_tool_calls`. Several large calls in one reply, or one beside long text, can together exceed a small daemon `prompt_max_bytes` and are refused whole, and nothing in the reply runs; the tool's description tells the model to send a large write as the only call in its reply. The agent cannot write a file larger than one call yet. The written content also rides every later turn back to the model, so with a loop cap near 65,536 a near-limit write leaves little room for the rest of the conversation. A near-limit write is roughly 15,000–20,000 output tokens, so an `output_tokens` below that cuts the call off before it is complete.
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
- **`user_auth { type, mount }`** says how `maknae login` authenticates. An absent block means userpass on `maknae-userpass`. When the block is present, `type` is required and must be `userpass`; anything else refuses with ``vault.user_auth.type "<type>" is not supported: the only method is `userpass` ``. `mount` defaults to `maknae-userpass` and is a bare mount name: a leading `auth` segment refuses (`invalid Vault mount: vault.user_auth.mount starts with 'auth' — the auth/ prefix is composed by the client; write the bare mount name`), as does a character outside `[A-Za-z0-9._/-]`, whitespace, or an empty, `.` or `..` segment. Keys other than `type` and `mount` refuse with `unknown key '<key>' in 'vault.user_auth'`. The root `maknae.yaml` may carry the same block.
- **`plane_key`** (`ml-dsa-87`, `ecdsa-p384-sha384` or `ecdsa-p521-sha512`; absent means `ml-dsa-87`) is the key algorithm this plane mints its identity with. It must equal the key type of the Vault PKI roles (with `deploy/vault-pki`, its `plane_key_algorithm`), in the root `maknae.yaml` (the daemon's plane) and in each user's (the CLI's plane): Vault refuses a CSR of another key type or size, and a refusal whose message concerns the key adds a hint naming both settings. `ml-dsa-87` needs a Vault 2.2.0+ PKI. Any other value refuses with ``vault.plane_key `<value>` is not one of ml-dsa-87, ecdsa-p384-sha384, ecdsa-p521-sha512``. `maknae enroll` writes it into both files from `--plane-key` (default `ml-dsa-87`), so a deployment that keeps EC passes `--plane-key ecdsa-p384-sha384` (or `ecdsa-p521-sha512`) on every enroll. `admin.status` reports the value the daemon booted with, and the boot trail's posture record names it. `admin.config.show` reports the accepted configuration snapshot, which an edit changes only once the baseline is accepted (§6.4); the plane uses the new value only after a restart.
- **They must match the host.** A user whose `kv_mount` or `user_prefix` differs from the host's `egress-bounds.yaml` (§6.1.3) seals a key the Egress Daemon cannot open: the seal binds the key path from the user's copy, the deputy opens it under the path from the host's, so it refuses with `OpenFailed(Seal)` before any Vault request or provider I/O; `maknaed` records every such turn `Failed` (ADR-0028 §5, amended, and §6). The user sees only the generic refusal text (§6.1.1). Keep both files written from the same enroll flags.

### 6.1.3 `egress-bounds.yaml`

`/etc/maknae/egress-bounds.yaml` declares, for the host, where user keys live and where the Egress Daemon reaches Vault. `maknaed` composes each user's key path beneath it per request, and the deputy checks each frame's path against it at use (`crates/maknae-config/src/bounds.rs`). `maknae enroll` writes it from `--vault-addr`, `--kv-mount` and `--user-prefix`:

```yaml
vault:
  addr: https://vault.example:8200
kv_mount: maknae-kv
user_prefix: maknae/users
agent_prefix: maknae/agents   # optional
call_timeout_ms: 120000   # optional
```

- **Three required keys and two optional**: `kv_mount`, `user_prefix` and `vault` (holding exactly `addr`), and `agent_prefix` and `call_timeout_ms`. Any other key refuses with `unknown key '<key>' in 'egress-bounds.yaml'` (or `in 'egress-bounds.yaml/vault'`) — including the retired `key_vault_path_prefix` and `approle_mount`.
- **`agent_prefix`** (optional): where Agent Daemon keys live below `kv_mount`, each agent's under `<agent_prefix>/<id>/`. It follows the same fragment grammar as `user_prefix`, and must not equal `user_prefix` or contain it or lie inside it at a `/` boundary (`maknae/users2` beside `maknae/users` is accepted); an overlap refuses with `'agent_prefix' overlaps 'user_prefix'`. Without it agents have no model access: `maknaed` refuses an agent's prompt before deciding it, and `maknae enroll agent` refuses (§6.4). `maknae enroll` does not write it. `maknaed` builds an agent's key path from the agent id on its verified certificate, never from the request, and the Egress Daemon accepts a key path within either prefix and refuses any other (ADR-0028 decision 3, amended).
- **The fragment grammar.** `kv_mount` and `user_prefix` are each required, a string, at most 256 bytes, in `[A-Za-z0-9._/-]`, with no whitespace, no empty, `.`, `..` or `data` segment, and no leading or trailing `/`. `vault.addr` is required, non-empty, without whitespace, at most 256 bytes, and must be `https://` (checked at boot).
- **Required only when providers are authorized.** With an empty or absent `providers` section the file is not read. With providers authorized, a file that cannot be read refuses boot with `providers are authorized but egress-bounds.yaml could not be read: <reason>`, and one that was read but refused — by its parser or by the boot gate's own `user_prefix`, `agent_prefix`, `vault.addr` and `call_timeout_ms` checks — refuses with `providers are authorized but the egress bounds were refused — <reason>` (`crates/maknae-kernel/src/boot_gate.rs`). A parser refusal's reason reads `egress-bounds.yaml: <reason>` (`InvalidEgressBounds`).
- **Mode `0644 root:root`, by design.** It is read through the root-artifact rule — root-owned, not group- or other-writable — by both `maknaed` and `_maknae-egress`, so it is owned by neither and editable by neither; it is world-readable because nothing in it is a secret and because the deputy is in neither `root` nor `_maknae`. To reach it, the deputy has a POSIX ACL `u:_maknae-egress:rx` on `/etc/maknae` (`r` as well as `x`, because the anchored reader opens the directory `O_RDONLY|O_DIRECTORY`), set by the package's `postinst`/`%post` and re-asserted by `maknae enroll`. A write-granting ACL would raise the group bits into the loader's `0o022` mask and be refused, so the root-artifact check is not weakened.
- **`call_timeout_ms`** (optional, default `120000`, `1000..=440000`): how long the deputy waits for one provider answer, end to end; the call is not streamed. Raise it for a self-hosted model that is slow to begin answering on a long, uncached context, or that writes long replies. Boot refuses a value that does not fit `egress.deadline_ms` (§6.2), so raise both together; 440000 is the most that fits the 600000 ceiling. The deputy reads this file when it starts and `maknaed` checks it at boot, so restart both after changing it; until both are restarted, the deputy refuses any request whose deadline (sent by `maknaed` with each request) its timeout does not fit, and the kernel records that request as failed. `maknae enroll` rewrites the file without it.
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
  A file action's reply waits `transport.read_timeout_ms` plus 5 s, the daemon's bound on
  resolving the requester's home. `admin.contain` and `admin.release` wait
  `transport.read_timeout_ms` plus 60 s and `admin.baseline.accept` plus 65 s: the
  daemon's sequential 5 s stages (the decision, the audit appends, the account lookup,
  the reload turn, the binding resolution and the checks) and a 10 s margin, so a `busy`
  or a committed change is answered rather than reported as no response. Every other
  reply is bounded by `transport.read_timeout_ms`. The default, 280000,
  covers the deputy's worst-case wall time on one request with room to spare: per turn
  the deputy makes one wrapping lookup and one unwrap at Vault, each bounded at 30 s,
  then the provider call, bounded by `call_timeout_ms` in `egress-bounds.yaml` (§6.1.3,
  default 120 s) — 180 s at defaults. There is no boot probe and no key cache. If this
  bound expired first, the kernel would record delivery-unknown for a call the deputy
  answered, so with providers authorized boot refuses a `deadline_ms` below
  `60000 + call_timeout_ms + 100000` (two Vault calls and a 100 s margin), naming both
  values. The bound holds per request: the deputy serves up to 36 requests at once (four
  more than the daemon admits), and answers one past that at once as refused before any
  provider I/O, so no request spends its deadline queued behind another. Out of range
  refuses boot by name. Shutdown waits
  for a send in flight: the daemon's handler drain is bounded by one connection's whole
  work — the handshake, the frame read and the response write (each at
  its `transport` timeout), the session-fact lookups at connect and at the request and the admission audit append (each a fixed 5 s), the requester home's resolution, the PDP decision and the verb's own blocking step, this
  deadline, the close, and a ten-second margin for the audit appends — so the outcome
  record is written, and the shipped units' stop timeouts (`TimeoutStopSec=902`, launchd
  `ExitTimeOut`) cover that drain at BOTH ceilings (60 s transport timeouts, 600 s
  deadline) plus every other term of the shutdown chain — the bounded wait for a policy reload's turn, the stop record's append, the
  credential supervisor's abort and reap, the reap of aborted handlers, the audit drain,
  the plane client's bounded lock wait and token revoke, the runtime teardown and the diagnostics flush — and
  a kernel test holds the unit values to that chain, two-sided. At the defaults the
  chain is 417 s; a stop with nothing in flight exits in milliseconds. One more bound at
  the ceiling: the deputy's request cap is 16,842,752 bytes — 16 MiB and a 64 KiB margin
  for the re-wrap — so a prompt that fills `transport.prompt_max_bytes` at its own 16
  MiB maximum still reaches the deputy.
- **A provider's error reaches the deputy's journal** (#372). When the provider answers
  non-2xx, the deputy reads at most 4 KiB of the body, masks the provider key wherever it
  appears, escapes everything outside printable ASCII and writes one line:
  `maknae-egress: provider answered 400 (conversation c…): <body>`. On Linux that is
  `journalctl -u maknae-egress`; on macOS it is the deputy's stderr file,
  `/usr/local/var/log/maknae-egress/maknae-egress.err`, which nothing rotates. The
  trail records the turn `LandedUndelivered` with a closed reason (`reply unusable:
  provider-rejected`, or `provider-auth`, `provider-rate-limit`, `provider-error`), and
  the subject sees a fixed line for that class. Neither the trail nor the subject's
  terminal carries the body. **The logged line can carry
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

### 6.3 The `audit` section

```yaml
audit:
  jsonl_path: /var/log/maknae/audit.jsonl   # as packaged
  readers: [vector]                          # accounts that may read the trail (#500)
```

`maknaed` refuses to start without an `audit:` section. Its keys are `jsonl_path`, the trail `maknaed` appends to; `siem` and `au3_1` (ADR-0019); and `readers`. Like `vault`, the section follows the file at start (§3.2), except that the accepted `readers` changes only by an accept (the OS grant itself follows the file, below); an accept that changes anything in it other than `readers` applies by restart.

**`readers`** lists the accounts that may read the trail, by account name only, never a group. Each name must match `^[a-z_][a-z0-9_-]{0,30}[$]?$` and appear once (`audit.readers entry "<name>" is not a portable account name`, `audit.readers names <name> twice`); that is checked at every load. `maknaed` never reads the list to decide anything. The grant follows the file: the packages and the runbook's "Grant the declared readers" block apply the list in `/etc/maknae/maknae.yaml` as ACL entries, through `sudo maknae audit-readers`, which prints the validated names one per line, so a reader added to the file can be granted access before any accept. The accept records the list in the accepted baseline and runs the account check below. That helper, and an accept that changes `audit.readers`, also resolve each name in the account database and refuse the whole list, naming the account (`audit.readers <name>: <why>`), when the account does not exist or the lookup fails (`_maknae`'s primary group having no group entry included), is `root`, `nobody`, `_maknae` or `_maknae-egress`, has a uid below 100 or uid 65534 (or -2 on macOS), shares a uid with a Maknae service account, has `_maknae`'s group as its primary or a supplementary group, or is returned by the directory under any other spelling. A start checks the grammar only, so an account-directory outage does not stop the daemon over a list it never reads. `maknae config-show` renders the list `<value set>`: naming the readers names who to target for the trail.

**Moving the trail.** A start that finds a different `jsonl_path` in the file moves the trail to it, as does the restart after an accepted change to it. The new path must name a file in the same directory as the current trail, and that file must already exist, prepared by root: a regular file with one link, owned by the daemon account, not group-writable and with no world access, carrying the append-only flag only root can clear (`chattr +a` on Linux, `chflags sappnd` on macOS; `uappnd` is refused). `maknaed` never creates it. The move records the new path as the last record of the old trail (`audit trail moves to <path> at start`), opens the new trail with a back-link (`audit trail continues from <old path>; last checkpoint revision <n>`), checks the kernel graph store against the newer checkpoint of the two trails, and records `audit trail moved from <old> to <new>` with the start's store transition. A target that is not a sibling (`the audit trail may move only within <directory>`) or is not prepared (`<path> is not append-only; prepare it with chattr +a (Linux) or chflags sappnd (macOS) as root`) leaves the current trail in use and makes the files an invalid change. The runbook's "Move the audit trail" prepares the file. Once an accepted baseline exists, `maknaed` never creates any trail: a missing one refuses to start, naming that runbook section.

### 6.4 Enrolling an Agent Daemon

`sudo maknae enroll agent` places an Agent Daemon's standing AppRole SecretID in OS custody, bound to the host's address (ADR-0006 decision 9).

**Prerequisites.**

- The host is enrolled (`sudo maknae enroll`).
- `/etc/maknae/egress-bounds.yaml` sets `agent_prefix` (§6.1.3). Enrollment copies it, with `kv_mount`, into the agent's `agent.yaml`, and refuses before any Vault request when it is absent. When `agent_prefix` in `egress-bounds.yaml` changes, enroll the agent again: an `agent.yaml` whose copy differs seals its key at a path the Egress Daemon does not authorize, and every turn is refused before provider I/O (`OpenFailed(Seal)` or `OpenFailed(WrongPath)`).
- The agent's Vault objects exist: the AppRole role `agent-<id>` on the agent mount, and the entity `maknae-agent-<id>` with an alias on that mount whose name is the role's RoleID (`deploy/vault-pki` is one way to create them; how they are made is the deployment's choice). Enrollment refuses before it mints anything when any of them is missing.
- For the agent to mint its plane leaf, two more Vault objects, which enrollment does not check: the policy `maknae-agent-<id>` on the role, granting `update` on `<pki_int_mount>/sign/maknae-agent-<id>` with the `not_after` parameter denied and no `revoke` path, and the PKI role `maknae-agent-<id>` on the intermediate mount, client-only and `no_store`, admitting only the URI-SAN `spiffe://<deployment_id>/plane/agent/<id>`, with a TTL no longer than the plane leaves' (`deploy/vault-pki` sets the agent leaf to 1 hour by default). The agent's token must have a `token_max_ttl` (never 0); the residuals below are bounded by it.
- An operator Vault token carrying the `maknae-enroll-agent` policy, supplied by `--token-file` or a no-echo prompt. The policy grants, on the agent mount only: reading a role's RoleID, creating SecretIDs, listing and destroying SecretID accessors; and `read` and `update` on `identity/entity/name/maknae-agent-*`, where `update` may set only the `disabled` field.
- A dedicated service account for the agent: it is not root, it is not the enrolling principal's account, its shell is one of the non-login shells `/usr/sbin/nologin`, `/sbin/nologin`, `/usr/bin/nologin`, `/bin/false` or `/usr/bin/false`, it is outside the `maknae` group and a member of the `maknae-agents` group (enroll prints the `usermod -aG` or `dseditgroup` command and changes nothing), it is not bound in `bindings.yaml` under `admin`, `user` or `guest`, by name or uid (`adversary` contains it), it is not a Maknae daemon account and is not a member (primary or supplementary) of the `_maknae` or `_maknae-egress` group, and no other agent is enrolled to it. Enrollment refuses any other account.
- The agent id is enrolled on this host only. Each agent id is enrolled on exactly one host: enrolling or rotating the same id on another host destroys this host's SecretID, because every enrollment retires every other SecretID on `agent-<id>`.
- Linux: a usable TPM2. There is no plaintext fallback.
- macOS: `/usr/local/bin/maknae-agentd` installed and Developer ID-signed, and the running `maknae` binary itself root-installed and Developer ID-signed. Enrollment refuses until both are.

```bash
sudo maknae enroll agent <id> --account <service-account> --bind-cidr <cidr> [--bind-cidr <cidr>…] \
  --provider <provider> --model <model> --key-subpath <subpath> --key-field <field> \
  --context-tokens <n> [--output-tokens <n>] [--persona admin|self] \
  [--role user|guest] [--approle-mount <mount>] [--token-file <file>] [--verbose]
sudo maknae enroll agent <id> --refresh-access [--verbose]
```

The provider flags name the agent's one model: the authorized provider, the model, where its API key sits in Vault (`<kv_mount>/data/<agent_prefix>/<id>/<subpath>`, field `<field>`), and its context window and answer bound in tokens, under the grammar of a `providers.yaml` entry (§6.1.1). `--persona` defaults to `admin`: the agent's persona is `/etc/maknae/agents/<id>/persona.md`, written by root. `self` lets the agent keep its own. Enroll checks that the `agent.yaml` it will write loads before it mints a SecretID.

`--role` defaults to `user`; `admin` is not a choice. Before minting a SecretID, enroll reads the Vault entity `maknae-agent-<id>` and refuses, with no side effect, when it is absent or has no alias on the agent mount named by the role's RoleID. A disabled entity is re-enabled as the last step, and only when every earlier SecretID of the role was destroyed; if any destroy failed, the entity stays disabled until a `--rotate` retires them all. Enroll ends by telling you to reload `maknaed`.

Re-enabling an entity makes the tokens issued before it was disabled usable again until they reach `agent_token_max_ttl`. Disabling does not revoke them.

`--bind-cidr` is required, once per address range. The SecretID is minted with `cidr_list` and `token_bound_cidrs` set to those ranges, so Vault refuses it, and any token it yields, from a source address outside them. Vault sees the address after any NAT, so behind NAT bind the translated address. A prefix is plain decimal digits with no leading zero, an IPv4-mapped IPv6 range (`::ffff:a.b.c.d/n`) is taken as its IPv4 range, and enrollment refuses `0.0.0.0/0`, `::/0`, or any set of ranges that together covers every IPv4 or every IPv6 address. `--approle-mount` defaults to `maknae-agent-approle`; it may use only `A-Z`, `a-z`, `0-9`, `.`, `_`, `/` and `-`, and must differ from `maknaed`'s AppRole mount, which must use the same characters so the two can be compared.

**Files written.**

| Path | Contents |
|---|---|
| `/etc/maknae/private/agent-<id>-secret-id.cred` (Linux) | the SecretID, a TPM2-bound `systemd-creds` credential named `maknae-agent-secret-id` |
| System keychain (macOS) | an item with service `io.maknae.maknae-agentd` and account `<id>`, trusted only to `/usr/local/bin/maknae-agentd` |
| `/etc/maknae/private/agent-<id>-enroll-state.yaml` | the mount, the role, and the `live`, `pending` and `retiring` SecretID accessors |
| `/etc/maknae/agents/<id>/enrollment.yaml` | the agent's id, account, uid, mount, AppRole role, RoleID, bound CIDRs, bound role and custody source (directory `root:_maknae 0750`) |
| `/etc/maknae/agents/<id>/agent.yaml` (`root:_maknae 0640`) | what the Agent Daemon reads to log in and reach `maknaed`: `vault` (`addr`, `approle_mount`, `role_id`, `pki_int_mount`, `plane_key`, `kv_mount`, `agent_prefix`), `trust_domain`, `agent_socket_path`, `provider` and `persona`. The RoleID is not a secret; the SecretID never appears in it |

**What the agent account may read.** As its last step, after the SecretID is sealed and the earlier ones are retired, enrollment gives the agent's account read access, and nothing more, to exactly these, and reads each entry back: `/etc/maknae`, `/etc/maknae/agents`, `/etc/maknae/agents/<id>` and `/etc/maknae/tls` (`r-x`: the reader opens each directory), and `agent.yaml`, `enrollment.yaml`, `persona.md` when present, and `tls/maknae-root-ca.crt`, `tls/maknae-int-ca.crt` and `tls/vault-ca.crt` (`r`). Nothing is granted on `/etc/maknae/private`, and no entry follows a symbolic link: a path that is a link fails its read-back.

- **Linux:** POSIX ACL entries for the account's uid, `u:<uid>:r-x` and `u:<uid>:r--`, written with `setfacl -P -n -m` and read back with `getfacl -P -p -n`. `-n` leaves the ACL mask as it is, so the grant never widens another named entry the mask holds back. An entry the existing mask limits does not read back, and the grant refuses.
- **macOS:** ACEs `user:<account> allow list,search` and `user:<account> allow read`, written with `chmod -h +a` and read back with `ls -led`. Enrollment refuses an account name outside `A-Z`, `a-z`, `0-9`, `.`, `_` and `-`, or one starting with `-`, before it writes any ACE.

When an entry cannot be written or does not read back, the agent is enrolled but cannot read its configuration. Fix the cause and run `sudo maknae enroll agent <id> --refresh-access`. It first admits the account `enrollment.yaml` names again, with every check enrollment runs (the account still exists with the recorded uid, is still in `maknae-agents`, is not root, the principal, a Maknae daemon account, a person bound in `bindings.yaml` or another agent's account), and refuses, granting nothing, when one fails: `agent <id> was enrolled for account <account> with uid <n>, but <account> now has uid <m>` names a changed uid. Then it grants the same list again, reading each entry back. It makes no Vault request, writes no file, and refuses an id with no `enrollment.yaml`. An entry is lost when its file is replaced, so run it after installing or replacing `persona.md`.

**Named residuals.**

- On macOS, the loaders' mode checks read only the POSIX mode bits, so they cannot see an ACE root adds to a configuration file or directory. A wider ACE added by hand is not refused at load.
- On macOS, an existing `deny` ACE for the account, listed before the ACE enrollment adds, wins. The grant reads back, but the Agent Daemon's read is refused at run time and it fails closed at start, naming the file it cannot read. Remove the deny ACE and run `--refresh-access`.


**Rotating.** `sudo maknae enroll agent <id> --account <service-account> --bind-cidr <cidr>… <provider flags> --rotate` takes the same `--account` and mount as the enrollment, and `--bind-cidr` and the provider flags again; it rewrites `agent.yaml` and grants the agent's read access again. It mints and seals the new SecretID before destroying the old one, and an accessor stays recorded in the state file until its destroy succeeds. Every enrollment, first or rotating, also lists the role's SecretID accessors in Vault after sealing and retires each one except the new SecretID's, so a SecretID that an interrupted earlier run minted but never recorded is destroyed too. That includes a SecretID another host holds for the same id, which is why an agent id is enrolled on one host only. A different account or mount means de-enrolling first.

**What `maknaed` reads.** At every start and reload `maknaed` reads `/etc/maknae/agents/` with `authz.yaml` and `bindings.yaml`, as one policy. The directory and every file in it must be owned by root, not group- or world-writable and not world-readable, and each file must be a regular file with one link and at most 64 KiB. For each `agents/<id>/` that holds an `enrollment.yaml`, it runs the same account checks enrollment ran (above) and also refuses an enrollment whose recorded uid now names another account or whose account `bindings.yaml` binds under `admin`, `user` or `guest`. An enrollment that fails is ignored: the account keeps whatever role `bindings.yaml` gives it and the client socket as before, it is never admitted on the agent socket, and a `graph.identity` record says `agent '<id>' (uid <n>) is not enrolled: <why>`. The exception refuses the whole reload, and the running policy stands: an account that passes every other check but that `bindings.yaml` binds under `admin`, by name or `uid:` entry (``authz agents: the service account <account> of agent `<id>` is bound to admin in bindings.yaml; an agent never holds admin``). The same binding made by a live edit is refused the same way. `bindings.yaml` may list an enrolled agent's account under `adversary`, which contains it.

Each agent accepted is recorded as `agent '<id>' (uid <n>) is enrolled`, and one that is gone as `agent '<id>' (uid <n>) is no longer enrolled` (both `graph.identity`, `graph.anchor:"enrolling"`). A directory with no `enrollment.yaml`, a name that is not an agent id, or an entry that is not a directory is skipped and recorded as `agents/<entry> is skipped: <why>`. An `enrollment.yaml` or `policy.yaml` that does not parse, or an `enrollment.yaml` whose `agent_id` is not its directory's name, refuses the reload. A `policy.yaml` without an `enrollment.yaml` beside it is not read. `maknae status` counts these problems, and `maknae subject-list` lists each enrolled agent with its id; when `bindings.yaml` has no `bindings:` key it also lists the principal as `admin`, marked as the principal.

**The agent's policy (`policy.yaml`).** `/etc/maknae/agents/<id>/policy.yaml` is written by hand, as root, and holds this agent's limits; they never live in `authz.yaml`, and an `authz.yaml` `subjects:` entry that names an enrolled agent's account refuses the reload. Its keys are `schema_version: 1` and, each optional, the three keys of an `authz.yaml` `subjects:` entry (`permissions`, `actions` and `models`, with the grammar and rules of the runbook's Chapter 3 §7 and ADR-0032: the site `deny` is a floor, deny beats allow, and a limit never grants) and `taskers`:

```yaml
schema_version: 1
permissions:
  allow:
    - "Read(~/notes/**)"
    - "Write(~/notes/**)"
actions:
  allow:
    - "fs.read"
    - "fs.write"
    - "fs.mkdir"
    - "session.prompt"
models:
  allow:
    - "local/llama"
taskers:
  - "alice"
  - "uid:1001"
  - "agent:hobi"
```

- An agent with no `policy.yaml`, or one without `permissions`, holds no file access through Maknae's tools.
- `actions` limits `fs.stat` and `fs.list` by its `fs.read` entry; naming either refuses the reload (§2.5).
- `admin.*` is always refused to an agent, except `admin.whoami`; no file can grant it.
- `session.new` is refused to an agent unless its `actions.allow` holds it (`session.new` or `session.*`) and its `actions.deny` does not. It still needs the role's grant, which no role holds yet.
- `taskers` names who may task this agent with `session.task`: account names, `uid:<n>` entries and `agent:<id>` entries. Without the key, only people may task it; another agent may task it only when listed. `taskers: []` admits nobody. Each tasker also needs `session.task` from its own role; the shipped `authz.yaml` grants it to `admin` and `user`. How tasks are stored and bounded, and the partition each works in, are in §2.6.
- Unknown keys, and any `schema_version` other than `1`, refuse the reload.

**De-enrolling.**

```bash
sudo maknae enroll remove-agent <id> [--token-file <file>] [--verbose]
```

It takes the same operator token as enrollment (`--token-file` or a no-echo prompt, never an argument) and runs in this order:

1. It removes the read access enrollment gave the agent's account from every entry on the grant list whose file still exists, and confirms each entry is gone; an entry the account does not hold is skipped. On Linux it removes the entry by uid, without recalculating the mask, so one left by an account deleted since enrollment goes too. On macOS an ACE names the account, so when the account no longer exists it warns that its ACEs are left in place (they grant nothing until an account of that name exists again) and continues. When an entry cannot be removed, it stops before removing anything else. A run whose `enrollment.yaml` is already gone has no account to remove access for.
2. It removes `/etc/maknae/agents/<id>/agent.yaml` and then `enrollment.yaml`, so the next reload of `maknaed` drops the agent whatever Vault does. A file or directory that is already gone counts as removed, so a run after a failed one completes from the state file.
3. It reads the agent's Vault role. When the role read errors for any reason other than not-found, it refuses. When the role is not found, it reads the entity `maknae-agent-<id>` (which does not depend on the mount): if the entity exists too, it refuses, saying the role was not found on the mount while the entity still exists (the recorded mount may be wrong), and changes nothing in Vault or locally beyond steps 1 and 2. If both are not found, Vault holds neither, so it skips the disable and the destroys, removes the sealed SecretID and the state file, and says the Vault role and entity were already absent. When the role exists, it reads the entity; if the entity is absent or has no alias on the agent mount named by the role's RoleID, it stops before changing anything in Vault and names what remains: the sealed SecretID and state file that exist, and the recorded accessors. Restore the entity and run it again, or clean Vault by hand.
4. It disables the entity.
5. It destroys every SecretID accessor of `agent-<id>` that the state file records or Vault lists. An accessor whose destroy fails stays recorded, the command exits non-zero, and running it again retries.
6. When no accessor remains, it removes the sealed SecretID (the `.cred` file on Linux, the keychain item on macOS) and the state file.

It ends by telling you to reload `maknaed`. The agent's `policy.yaml`, `persona.md` and its directory are left in place, and the entity stays disabled. Disabling does not revoke tokens already issued, and `remove-agent` cannot revoke them because no token accessor is recorded: a login token the agent already holds stays valid until `agent_token_max_ttl`.

### 6.5 The `deployment` section

```yaml
deployment:
  mode: linux-host          # linux-host, macos-host or container
  account_source: userdb    # userdb or none; linux-host only
```

`maknaed` refuses to start without it. `maknae enroll` writes it: `mode: macos-host` on macOS; on Linux `mode: linux-host` and `account_source: userdb`, or `account_source: none` with a warning when the host has no `systemd-userdbd.socket` unit (el9 ships none). It follows the file at start (§3.2); a reload never applies it. `admin.config.show` discloses both keys.

**`mode`** names the host, and the daemon checks it against the host at boot, refusing (exit 1) when they disagree. It never infers the mode from what it finds.

| `mode` | Required at boot | Refused when |
|---|---|---|
| `linux-host` | a Linux build, `/run/systemd/system` present | a container file marker is present: `/var/run/secrets/kubernetes.io/serviceaccount`, `/run/.containerenv` or `/.dockerenv` |
| `macos-host` | a macOS build | — |
| `container` | a Linux build, and a container file marker or a non-empty `KUBERNETES_SERVICE_HOST` or `container` variable | no marker is present |

A marker that cannot be examined refuses the boot. The check applies to the baseline the start runs (§3.2): over an accepted baseline whose mode the host confirms, a file whose mode it contradicts is recorded as an invalid change and the accepted mode runs. The environment variables only ever let `container` start; they never refuse `linux-host`. On `linux-host` and `macos-host` the daemon binds the client socket and checks every session as the runbook's "Session checks" describes. On `container` it binds no client socket at all and logs `maknaed: deployment.mode is container; no client listener is bound`; the human path in a container deployment is the gateway (#117).

**`account_source`** is where the daemon asks a local account's state on every request. `userdb` (the default on `linux-host`) asks `systemd-userdbd` (`/run/systemd/userdb/io.systemd.Multiplexer`) about each account listed in `/etc/passwd`; a locked, expired or not-yet-valid account is refused, and a userdbd that does not answer refuses every local account. `none` checks no account state, and each admission record says so (`admitted (account: not-checked:configured)`). Set `none` only on a host without `systemd-userdbd`, and set `userdb` once it is installed. On `macos-host` only `none` is accepted (omit the key); `container` mode checks no account state, so on `container` the key may not be set at all. A directory-backed account (SSSD, LDAP, AD) is never asked; its admission record reads `not-checked:directory` (#117).

---

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
| `egress-bounds.yaml` read but refused: a missing `vault` block or key, a fragment outside `[A-Za-z0-9._/-]` or with an empty, `.`, `..` or `data` segment, a value over 256 bytes, a `call_timeout_ms` that is not an integer or is outside `1000..=440000` (§6.1.3). Reads `egress-bounds.yaml: <reason>`; an unknown key such as `key_vault_path_prefix` or `approle_mount` is `UnknownKey` | `InvalidEgressBounds` |
| The `egress` section (§6.2): a non-map section, a value of the wrong type or out of range (#240) | `InvalidEgress` |
| **A key no parser reads** — in `maknae.yaml`'s `core` (own level), `transport`, `audit`, `principal`, each `providers` entry, `egress`, `deployment`, `vault` and `vault.user_auth`; in `core.handling` and `core.handling.ceiling`; in `egress-bounds.yaml` and its `vault` block (`egress-bounds.yaml/vault`); in `providers.yaml` at its top level (`providers.yaml`), each entry (`providers.yaml/providers`) and each entry's `key` (`providers.yaml/providers/key`); and at `authz.yaml`'s map levels (the document, `permissions`, each role body under `roles:`/`destinations:`, each `subjects:` entry, and its `permissions`, `actions` and `models` maps — a mistyped ROLE NAME is `UnknownRole`, not this). **Not** `lake` or `core.identity`, which are deliberately open (§3) (#210) | **`UnknownKey`** |
| A present-but-malformed `core.handling` ceiling | `InvalidCeiling` |
| `transport.prompt_max_bytes` outside 65536..=16777216 (default 1048576 since #372; it bounds prompt-class frames only, and control and attempt frames have fixed caps) | `InvalidTransport` |
| The `providers` section (§6.1): not a list (a null `providers:` included), more than 32 entries, a duplicate `name`, an entry that is not a map, a missing or malformed `name`, `endpoint` or `models`, a malformed `reasoning_effort`, an `output_tokens_field` other than `max_completion_tokens` or `max_tokens`. Reads `invalid provider config: <reason>` | `InvalidProvider` |
| A key named `key`, `api_key`, `apikey`, `token`, `secret`, `secret_key` or `bearer` in any `providers` contribution, shadowed ones included: `provider config carries a plaintext credential under '<field>': each user's key lives in Vault under their own login, never in the config` | `ProviderPlaintextKey` |
| `maknae.yaml`, any `config.d/` member, `<config-dir>` or `config.d/` not root-owned, or group/other-writable: `<path> must be owned by root and not group- or world-writable, as must every maknae.yaml and config.d source and the directories that hold them` | `SourceNotRootOwned` |
| `core.handling.policy` names a system the build does not carry: `core.handling.policy names a classification system this build does not carry: '<name>'` | `UnknownClassificationPolicy` |
| `providers.yaml` (§6.1.1) malformed, or no entry selectable: `providers.yaml: <reason>` | `UserProviders` |
| `sensitive.yaml` (§2.5), host or personal: a missing `sensitive:` key, a `schema_version` other than `1`, an entry that is not a quoted string, or an entry that is relative, uses `~name`, or has a `.` or `..` component. An unknown key reads `sensitive.yaml: unknown key '<key>' in 'sensitive.yaml'`, and every other cause `sensitive.yaml: <reason>`. A missing host file is `NotFound` and refuses start | `InvalidSensitive` |
| `vault.kv_mount` or `vault.user_prefix` in the root `maknae.yaml`, shadowed `config.d/` blocks included: `vault.kv_mount in the root maknae.yaml is not read by maknaed: set kv_mount in egress-bounds.yaml` | `RootVaultKeyRefused` (kernel) |
| `audit.readers` not a list of strings, an entry outside `^[a-z_][a-z0-9_-]{0,30}[$]?$`, or a name listed twice (§6.3) | `InvalidAudit` |
| The `deployment` section (§6.5) absent or not a map, `mode` missing, not a string or not one of the three: `invalid deployment config: deployment.mode: <what was found>; it must be one of linux-host, macos-host, container`. An `account_source` other than `userdb` or `none`, `userdb` on `macos-host`, or any `account_source` on `container`: `invalid deployment config: deployment.account_source: <reason>` | `InvalidDeployment` |
| At an accept or in `sudo maknae audit-readers`: an `audit.readers` account that is missing or refused (§6.3): `audit.readers <name>: <why>` | `InvalidAudit` |

The baseline (§3.2) adds refusals of its own. At a start over an accepted baseline, a file that fails any row above is not a refusal: the daemon keeps the accepted baseline and records the files as an invalid change. A trail move (§6.3) to a file outside the current trail's directory is `the audit trail may move only within <directory>`, and to a file root has not prepared, the open's own refusal, for example `<path> is not append-only; prepare it with chattr +a (Linux) or chflags sappnd (macOS) as root`; at a start either leaves the current trail in use. Once an accepted baseline exists, a missing trail refuses to start (exit 1): `the audit trail <path> is missing; prepare it as the runbook's "Move the audit trail" step does, then start`. An accepted baseline that no longer validates refuses to start with `accepted baseline cannot start: <cause>` in the journal, at the exit code of the row that failed; the trail records `accepted baseline cannot start (cause in the journal)`.

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
deployment:
  mode: linux-host
```

`deployment` cannot be dropped (§6.5): without it, an empty `maknae.yaml` included, the
daemon refuses to start, naming `deployment.mode`. Without `core` it still runs at the
Public baseline.

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
deployment:
  mode: linux-host
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

As §2.2 states for every section, `maknae.yaml`, every `config.d/` member **and** `<config-dir>` **and** `config.d/` must each be **root-owned** and **not writable by group or other** (`mode & 0o022 == 0`) — `loader.rs`'s `ROOT_ARTIFACT` (`owner: Some(0)`, `mode_mask: 0o022`). The file carrying `providers` is held to exactly that rule.

| Path | Valid | Refused |
|---|---|---|
| The file carrying `providers` | `640`, `600`, `440` — root-owned | **`660`** (group-writable), any world bit, any non-root owner |
| `<config-dir>`, `config.d/` | `750`, `700` — root-owned | **`770`** (group-writable), any world bit, any non-root owner |
| `egress-bounds.yaml` | `644` — root-owned | any group or other write bit, any non-root owner |
| `~/.maknae/providers.yaml` | `600`, `640` — the user's own | any world bit |

The failure names the path that failed (`SourceNotRootOwned`, §2.2). The packaged `/etc/maknae` (`root:_maknae 0640` under `0750`) satisfies this as shipped. **A dev-shape `~/.maknae/maknae.yaml` owned by the operator does not, by design** — the subject the loop runs as must not be able to authorize a destination for its own content. `config.d/` itself is checked as well as the file, because a subject who can write the directory could otherwise hide a root-authored override and hand the win to the base file.

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
