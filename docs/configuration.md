# Maknae Configuration Reference

This is the reference for Maknae's configuration language: where the config lives,
the file/directory layout, the accepted YAML subset, and every section and key that
is defined today. It is **fail-closed** by design — when a control cannot be applied
or a value cannot be validated, Maknae refuses to load rather than run with a guessed
or weakened configuration.

> **Status.** The configuration backbone is built in cycles. This document covers
> what exists today: the **loading core**, the **document/registry model**, the
> **`core` section's classification ceiling**, and the **`provider` section** (§6.1).
> Sections owned by subsystems not yet built (`authz`, `channels`, `dcs`) are marked
> **Forthcoming**, and `llm` is **Withdrawn** (superseded by `provider`, 2026-09-07).
> **Writing any of them refuses boot** — an unregistered section is
> `ConfigError::UnknownSection`, not a warning — so treat every Forthcoming row as "do
> not write this yet", never as "ignored until it lands" *(clarified 2026-09-13, after a
> worked example in this file shipped an `llm` block)*. This reference is updated by
> every cycle that changes the configuration language.

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
any config error. *(Corrected 2026-09-06, #233: this paragraph said "there is no run loop
yet, so `maknaed` is boot-check-only" — stale since #77.)* After the config is read the
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

---

## 2. Directory layout

```
<config-dir>/
├── maknae.yaml           # the base file (required)
├── authz.yaml            # the authorization policy — a SEPARATE document, not a section
├── egress-bounds.yaml    # required WHEN a `provider` section is registered (§6.1)
└── config.d/             # optional overlay directory of SECTION files
    ├── 10-provider.yaml  # the `provider` section (§6.1, worked example in §9.3)
    └── …
```

**Sections versus standalone documents** — the distinction the old tree blurred.
`maknae.yaml` and `config.d/*.yaml` contribute **registered sections** and are merged
section-by-section by this loader. `authz.yaml` and `egress-bounds.yaml` are **standalone
documents with their own readers**: each is opened by path (`<config-dir>/authz.yaml`,
`<config-dir>/egress-bounds.yaml`), never merged, never shadowed, and putting either
inside `config.d/` does not work.

> **Corrected 2026-09-13.** This tree used to list `config.d/authz.yaml` and
> `config.d/llm.yaml`. Both were unloadable examples, for the reason §6 now states up
> front: a section the daemon does not register **refuses boot** with
> `ConfigError::UnknownSection` rather than being ignored, and neither `authz` nor `llm`
> is in `boot_specs()` — `llm` is Withdrawn outright (superseded by `provider`). The
> `authz` name was doubly misleading: `/etc/maknae/authz.yaml` **is** a real file, but it
> is a **standalone policy document with its own reader**, not a `config.d/` member and
> not a registered section, so putting it in `config.d/` is wrong twice over. The tree
> now names only what loads today. *(Found in review after §9.3's copy of the same
> defect was fixed — the sweep should have been the whole file the first time.)*

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
  `.#10-provider.yaml` or `.10-provider.yaml.swp` do not trip an error. *(Corrected
  2026-09-13: this named `.#authz.yaml`, which reads as though `authz.yaml` were a
  `config.d/` member — it is a standalone document, see §2.)*
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

> **Scoped 2026-09-13.** This paragraph read "The **only** check is
> `mode & 0o007 == 0`" without qualification, which is wrong for a **root-required
> section** and would send an operator to a mode that is refused. `provider` (§6.1) is
> such a section: the file contributing it, and `<config-dir>` and `config.d/`
> themselves, must additionally be **root-owned** and **not group-writable**
> (`mode & 0o022 == 0`), so **`660` and `770` are REFUSED** there even though they pass
> the universal rule — `loader.rs`'s `ROOT_ARTIFACT` versus `CONFIG_ARTIFACT`. The
> refusal is `SectionNotRootOwned` and it names the path that failed. See §9.3 for the
> worked example and the full table.

| Path | Recommended modes | Rejected |
|---|---|---|
| Config files (`maknae.yaml`, `config.d/*.yaml`) | `640`, `660`, `600` | anything with a world/other bit (e.g. `644`) |
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
  only *world* access is refused.
- **Non-Unix platforms** refuse to load (the permission model is unavailable there;
  Maknae fails closed rather than run unchecked).

> **Honest limits.** POSIX ACLs are invisible to the mode bits, and the integrity of
> the *ancestor* directories (e.g. `/etc`) is an assumed-trusted precondition. Keep the
> config tree free of world ACLs and on a trusted path.

---

## 3. Sections and precedence

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
> system, it never adds one. The rule and errors below describe that read. *(Corrected
> 2026-09-06, #148: the ceiling is enforced on every content request — see the box at
> the end of this section — not merely read at boot.)*

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
(Corrected 2026-09-06: case variants such as `secret` are accepted; earlier text made
them a refusal, which was the live bug #148's sibling.)

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

## 6. Extension sections (Forthcoming)

These sections are owned by subsystems not yet built. Each is documented here as it
lands; until then, registering one and providing its content is not yet supported.

**What "not yet supported" means concretely**, because it is stronger than it sounds: a
section the daemon does not register is `ConfigError::UnknownSection`, which **refuses
boot** and names the file it came from. The registered set is
`crates/maknae-kernel/src/boot.rs`'s `boot_specs()` — `lake`, `vault`, `transport`,
`audit`, `principal`, `provider`, plus `core` — so every row below marked Forthcoming or
Withdrawn will stop the daemon if written, rather than being ignored. Only `provider`
(§6.1) can be configured today. *(Added 2026-09-13: §9.3's worked example used to be a
`llm` block, which is Withdrawn, and would have done exactly this to anyone who copied
it.)*

| Section | Owner | Status |
|---|---|---|
| `authz` | authorization policy *(the config-section registration; the `/etc/maknae/authz.yaml` policy FILE is separate and is enforced per request as of #77 — see the runbook)* | Forthcoming |
| `provider` | the one registered model provider (#243, milestone Cooky) — **see §6.1** | **Shipped** |
| `llm` | LLM-provider authentication *(superseded by `provider`, 2026-09-07)* | Withdrawn — **writing it refuses boot**, see §9.3 |
| `channels` | channel/comms adapters (Discord, Matrix, …) | Forthcoming |
| `dcs` | optional DCS classification backend | Forthcoming |

### 6.1 The `provider` section (#243)

The **one** OpenAI-compatible model provider the runtime loop may reach (ADR-0023). Exactly four keys, all required when the block is present; the block is optional, and a deployment without it boots with a loop that has nothing to prompt. Which roles may send content to this provider is decided in `authz.yaml` (`roles:` and `destinations:`), see the runbook, Chapter 3 §7.

> **Corrected 2026-09-13 — the `key_vault_path` example below was not usable.** It read `maknae/provider/openai`, which the config parser accepts (it only requires a relative, whitespace-free string) and the boot bounds gate compares as a string — but `maknae_vault::split_kv_path` **refuses a path with no `/data/` segment** (`"is not a KV v2 path"`), so the value failed at the moment the deputy tried to read it. `key_vault_path` is the **full KV v2 API path**, `<mount>/data/<secret path>`; with `deploy/vault-pki`'s default `maknae-kv` mount that is `maknae-kv/data/…`. Two further requirements that were absent from this section entirely are added below: a `provider` block makes **`/etc/maknae/egress-bounds.yaml` mandatory**, and **no Vault client is wired yet**, so a real call cannot succeed today. Read from the code, not from the prose it replaces.

```yaml
provider:
  name: openai                          # operator's label; appears in the audit trail; <=32 bytes, [A-Za-z0-9-_.]
  endpoint: https://api.openai.com/v1   # https://, or http:// to loopback only (the hermetic stub); no userinfo; port 1-65535
  model: gpt-5
  key_vault_path: maknae-kv/data/maknae/provider/openai  # FULL KV v2 path: <mount>/data/<path>; never disclosed
```

- **The key is never in the config.** A key under `key`, `api_key`, `apikey`, `token`, `secret`, `secret_key` or `bearer` refuses the load (`ProviderPlaintextKey`) before any other defect **in the provider block** is reported (ownership and classification checks run earlier in boot) — in **whichever file** the `provider` block appears, including a base block that a `config.d/` member shadows. This is a field-name check on the `provider` block only; it is not a general secret scanner, and a secret pasted as the *value* of `name` or `key_vault_path` is not detected by it. The key lives in Vault at the path `key_vault_path` names — which already **includes** the mount and the `data/` segment (see the `key_vault_path` bullet below) — readable by the `maknae-egress` principal only.
- **Who may write the block.** The file that contributes the `provider` section — `maknae.yaml` **or a `config.d/` member** — must be **root-owned and not group/other-writable**, and so must the **config directory and `config.d/` themselves** (a subject who owns the directory could otherwise choose between root-authored candidates by renaming one out of the scan); otherwise boot refuses (`SectionNotRootOwned`, naming the file or directory that failed). The packaged `/etc/maknae` (`root:_maknae 0640` under `0750`) satisfies this; the subject the loop runs as cannot register a destination. A dev-shape `~/.maknae/maknae.yaml` owned by the operator does not, by design.
- **Disclosure.** `admin.config.show` shows `name`, `endpoint` and `model` in the clear and omits `key_vault_path`.
- **`key_vault_path` is a FULL KV v2 path**, `<mount>/data/<secret path>` — `maknae-kv/data/maknae/provider/openai`, not `maknae/provider/openai`. The parser checks only that it is relative (a leading `/` refuses) and whitespace-free; the **`/data/` segment is required by the reader**, and the FIRST `/data/` is the mount boundary, deliberately, so a secret whose own path contains `data` cannot move the split. An empty mount, an empty secret path, or a `.`/`..`/empty segment refuses.
- **A `provider` block makes `/etc/maknae/egress-bounds.yaml` MANDATORY.** That file has exactly one key, `key_vault_path_prefix`, and boot refuses if it is absent or unreadable (`EgressBoundsRefusal::Undeclared`) or if `provider.key_vault_path` is not **strictly beneath** the prefix (`OutsideBounds`, naming both). "Strictly beneath" means at least one further segment: a path *equal* to the prefix is outside it, and the comparison is segment-aware, so `…/providers-evil/x` is not within `…/providers`. The same prefix is granted to the deputy by `deploy/vault-pki` (`kv_mount_path` defaults to `maknae-kv`) and re-checked by the deputy at use — a mismatch is a **boot refusal**, not a 403 at request time, which is the point of checking at boot.
- **No Vault client is constructed yet.** `bins/maknae-egress/src/main.rs` uses `NoCredentialSource`, so an otherwise-valid registration still refuses at the credential layer with a named error, and the field name inside the secret is not fixed in production code (only a test names `api_key`). Configuring this block is therefore correct and checkable end-to-end **up to the credential read**; a real provider call needs the remaining wiring, tracked on [#240](https://github.com/darkhonor/maknae/issues/240).
- `admin.provider.list` / `.set` / `.disable` are **not built** in Cooky; registration is this block plus Vault.

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
variants. All but the last are raised by the **directory load** itself; `InvalidCeiling`
is raised by the **typed ceiling read** (`ceiling_from_core`, §4.1), which the kernel
performs after the load.

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
| A present-but-malformed `core.handling` ceiling | `InvalidCeiling` |

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

### 9.3 A `provider` in `config.d/` — the worked extension example

> **Corrected 2026-09-13.** This section used to build its example around the **`llm`** section, describing it as a "Forthcoming subsystem, §6". Both halves were wrong, and the second one was not merely stale — it was **unloadable**. §6's own table marks `llm` **Withdrawn** (superseded by `provider`, 2026-09-07), and `llm` is not among the sections the daemon registers (`crates/maknae-kernel/src/boot.rs`, `boot_specs()`: `lake`, `vault`, `transport`, `audit`, `principal`, `provider`, with `core` read directly). An unregistered section is `ConfigError::UnknownSection` (`crates/maknae-config/src/loader.rs`), which is **returned, not warned** — so an operator who copied the old example got a fail-closed boot refusal naming their own file. The example now uses `provider`, the one extension section that is Shipped, and the old `660`/`770` permission advice below is corrected too: for a section like `provider` those modes are **refused**. Every rule stated here was read from the code, not from the prose above it.

Extension sections belong in `config.d/` (or inline in the base). `config.d/` files
override the base **section-by-section**. Example directory:

```
/etc/maknae/                 # 750, root-owned
├── maknae.yaml              # 640, root-owned — core (+ inline sections)
├── egress-bounds.yaml       # 640, root-owned — NOT a config.d member; read by the deputy
└── config.d/                # 750, root-owned
    └── 10-provider.yaml     # 640, root-owned — the `provider` section (§6.1)
```

`egress-bounds.yaml` sits beside `maknae.yaml`, **not** inside `config.d/`: it is a
separate document with its own reader, not a registered section, so it is neither merged
nor shadowed. It is held to the same root-owned, not-group-writable requirement, and for
a reason worth knowing: **both `maknaed` and `_maknae-egress` read it, so it is owned by
neither and editable by neither.**

`config.d/10-provider.yaml`:

```yaml
provider:
  name: openai                          # <=32 bytes; [A-Za-z0-9-_.] only
  endpoint: https://api.openai.com/v1   # https://, or http:// to loopback only
  model: gpt-5
  key_vault_path: maknae-kv/data/maknae/provider/openai   # FULL KV v2 path
```

**And `/etc/maknae/egress-bounds.yaml`, which a `provider` block makes mandatory**
(`640`, root-owned — it is read by the deputy, not by this loader):

```yaml
key_vault_path_prefix: maknae-kv/data/maknae/provider
```

The `provider` path must be **strictly beneath** that prefix — at least one further
segment, compared segment-aware — or boot refuses with `OutsideBounds` naming both. A
missing or unreadable bounds file refuses with `Undeclared`. The same prefix is what
`deploy/vault-pki` grants the deputy a read on, so **these three places must agree**:
the Terraform variable, `egress-bounds.yaml`, and `provider.key_vault_path`.

Then put the key in Vault, never in a config file:

```
vault kv put maknae-kv/maknae/provider/openai <field>=sk-…
```

Note the shape difference, which is a Vault CLI convention rather than a Maknae one:
the **CLI** path omits `data/` (`vault kv put maknae-kv/maknae/provider/openai`), while
`key_vault_path` is the **API** path and includes it
(`maknae-kv/data/maknae/provider/openai`). Both name the same secret.

> **`<field>` is not settled yet, and this is the one thing you cannot finish today.**
> `bins/maknae-egress/src/main.rs` still uses `NoCredentialSource`: no Vault client is
> constructed, so nothing reads a field, and the only place a name appears is a test
> (`api_key`). Everything above is checkable now — the block parses, the bounds gate
> runs at boot, the ownership and permission rules apply — but the credential read
> itself refuses with a named error until the wiring lands ([#240](https://github.com/darkhonor/maknae/issues/240)).
> Choose `api_key` if you want to pre-seed the secret; treat the name as provisional.

#### Permissions — stricter than §2.2 for this section

§2.2's universal rule is "no world/other bits" (`mode & 0o007 == 0`), which admits
`660` and `770`. **A root-required section is held to more than that.** `provider` is
one, so the file that contributes it **and** `<config-dir>` **and** `config.d/` must each
be **root-owned** and **not writable by group or other** (`mode & 0o022 == 0`) —
`loader.rs`'s `ROOT_ARTIFACT` (`owner: Some(0)`, `mode_mask: 0o022`) rather than
`CONFIG_ARTIFACT` (`owner: None`, `mode_mask: 0o007`).

| Path | Valid with a `provider` block | Refused |
|---|---|---|
| The file carrying `provider` | `640`, `600`, `440` — root-owned | **`660`** (group-writable), any world bit, any non-root owner |
| `<config-dir>`, `config.d/` | `750`, `700` — root-owned | **`770`** (group-writable), any world bit, any non-root owner |

The failure names the path that failed (`SectionNotRootOwned`). The packaged
`/etc/maknae` (`root:_maknae 0640` under `0750`) satisfies this as shipped. **A dev-shape
`~/.maknae/maknae.yaml` owned by the operator does not, by design** — the subject the
loop runs as must not be able to register a destination for its own content.

`config.d/` itself is checked as well as the file, because a subject who can write the
directory could otherwise hide a root-authored override and hand the win to the base
file.

#### What the parser accepts (`crates/maknae-config/src/provider.rs`)

**Exactly four keys, all required, no others** — a fifth key refuses with
`provider: unknown key '<name>'`.

- **`name`** — at most **32 bytes** (it is written into every egress audit record's
  `object`), and only ASCII letters, digits, `-`, `_` and `.`. A space or a `/` refuses.
- **`endpoint`** — `https://`, or `http://` **to loopback only** (`localhost`, a
  loopback IPv4 literal, or a bracketed loopback IPv6). Refused: any other scheme, an
  uppercase `HTTPS://` (the scheme match is **case-sensitive**), a bare host with no
  scheme, whitespace anywhere, **userinfo** (`user:pw@host` — a credential in a
  disclosed field, and the trick that made `localhost:pw@remote` read as loopback), an
  `http://` to a routable address, a port outside `1–65535` or with a leading zero, and
  a malformed literal such as `256.256.256.256` or `api..example.com`.
- **`model`** — any non-empty string; sent verbatim on every request.
- **`key_vault_path`** — the **full KV v2 API path**, `<mount>/data/<secret path>`, e.g.
  `maknae-kv/data/maknae/provider/openai`. The *parser* requires only that it be
  relative (a leading `/` refuses) and whitespace-free, so a value missing `/data/`
  loads and then fails later — `maknae_vault::split_kv_path` refuses it as "not a KV v2
  path" when the deputy reads it. The **first** `/data/` is the mount boundary,
  deliberately, so a secret whose own path contains `data` cannot move the split; an
  empty mount, an empty secret path, or a `.`, `..` or empty segment refuses. Read by
  the **`maknae-egress`** principal only, under its own Vault policy.

Values are trimmed, and an empty-after-trim value is refused as missing.

#### The key must not be in the file

A field named `key`, `api_key`, `apikey`, `token`, `secret`, `secret_key` or `bearer`
refuses the load with `ProviderPlaintextKey`, naming the field. Three details worth
knowing before you write the file:

- **Case-insensitive** on the field name — `API_KEY` and `Token` refuse too.
- It is checked on **every contribution** to the section, including a base block that
  a `config.d/` member shadows. Moving the key into a file that loses the override does
  not hide it.
- It is reported **before any other defect in the provider block**, so if you pasted a
  key next to a typo you hear about the key first. (Ownership and classification checks
  run earlier in boot and can still speak first.)

It is a **field-name check on the `provider` block only** — not a general secret
scanner. A secret pasted as the *value* of `name` or `key_vault_path` is not detected.

#### `config.d/` mechanics that apply here (§2.1)

Only immediate entries are read; only `*.yaml` / `*.yml` (case-insensitive); dotfiles
are skipped, so an editor's `.10-provider.yaml.swp` is harmless; a subdirectory or a
**symlink** in `config.d/` is an **error**, not ignored; files are read in **lexical
order**, which is why the example is named `10-provider.yaml`.

#### Verifying it loaded

`admin.config.show` shows `name`, `endpoint` and `model` in the clear and **omits
`key_vault_path`**. `admin.provider.list` / `.set` / `.disable` are **not built** in
Cooky — registration is this block plus Vault, and nothing else.

Which roles may send content to this provider is a separate decision, made in
`authz.yaml` (`roles:` and `destinations:`) — see the runbook, Chapter 3 §7. A
registered provider is reachable by nobody until that grant exists.
