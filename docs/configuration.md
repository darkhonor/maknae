# Maknae Configuration Reference

This is the reference for Maknae's configuration language: where the config lives,
the file/directory layout, the accepted YAML subset, and every section and key that
is defined today. It is **fail-closed** by design — when a control cannot be applied
or a value cannot be validated, Maknae refuses to load rather than run with a guessed
or weakened configuration.

> **Status.** The configuration backbone is built in cycles. This document covers
> what exists today: the **loading core**, the **document/registry model**, and the
> **`core` section's classification ceiling**. Sections owned by subsystems not yet
> built (`authz`, `llm`, `channels`, `dcs`) are marked **Forthcoming** and are
> documented as they land. This reference is updated by every cycle that changes the
> configuration language.

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
argument, defaulting to **`/etc/maknae`** — loads it, reads `core.handling.ceiling`
into the runtime **ingest posture**, and **refuses to start (exit 1)** on any config
error. A successful boot exits 0; there is **no run loop yet**, so `maknaed` is
boot-check-only for now (under a `Type=simple` supervisor this reads as "started then
exited" — expected until the run loop lands).

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
├── maknae.yaml        # the base file (required)
└── config.d/          # optional overlay directory
    ├── authz.yaml
    ├── llm.yaml
    └── …
```

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
  `.#authz.yaml` or `.authz.yaml.swp` do not trip an error.
- A `config.d/` entry that is a **subdirectory or a symlink** is an **error**, not
  ignored. `config.d/` itself must be a real directory, not a symlink.
- Files are read in **lexical order** by filename.

### 2.2 File and directory permissions (Unix)

The configuration can carry policy, so it must not be world-accessible. On Unix, every
path involved is checked: **no world/other permission bits at all** (`mode & 0o007 == 0`
— no world read, write, *or* execute).

The **only** check is `mode & 0o007 == 0` — *any* mode with no world/other bit is
valid (`600`, `640`, `660`, `440`, `750`, `770`, `700`, …); the modes below are
**recommended examples**, not an exhaustive allowlist.

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
```

- **`schema_version`**, **`identity`** (`instance_id`, `name`, `domain`, `urn_root`) —
  carried as-is (the shape is shared with, and inherited by, the lake — see §5). Not
  yet type-validated by Maknae.
- **`handling`** — the classification ceiling (§4.1), the one block Maknae type-reads.

### 4.1 The classification ceiling (`core.handling`)

The ceiling governs the coarse **ingest gate**: whether this Maknae instance may reach
past the *public* gate. The vocabulary is reused **verbatim** from the lake
(`lake.yaml` / `lake.schema.json`), so the lake and the optional DCS classification
backend read the same declaration.

> **How it is read.** Loading the config *directory* carries the `core` section
> verbatim (like any section) — the directory load does **not** itself validate the
> ceiling. The ceiling is validated when Maknae **reads** it, through the typed reader
> `ceiling_from_core`, which the kernel invokes at startup. The rule and errors below
> describe that read. (Kernel wiring is forthcoming; until it lands, the reader exists
> but nothing invokes it end-to-end.)

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
| **`Gated`** | the ceiling differs from the baseline in **any** way — higher, lower, or lateral (e.g. a higher level, CUI, SCI, a releasability set, a non-public *or empty* dissemination, or an accreditation reference) |

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
| `handling.ceiling.classification` | string | `"UNCLASSIFIED"` | One of the four recognized levels (below), **case-sensitive**. |
| `handling.ceiling.sci` | bool | `false` | |
| `handling.ceiling.releasable_to` | list of strings | `[]` | Releasability caveats (e.g. `["REL FVEY"]`). Opaque here; interpreted by DCS. |
| `handling.ceiling.cui_permitted` | bool | `false` | The primary "private-network" switch. |
| `handling.ceiling.cui_categories_permitted` | list of strings | `[]` | Opaque CUI category strings. |
| `handling.ceiling.dissemination_permitted` | list of strings | `["Distribution Statement A"]` | e.g. Distribution Statements. |
| `handling.accreditation_ref` | string or `null` | `null` | Accreditation pointer (ATO reference, etc.). |

Recognized **`classification`** values (the standard ladder, case-sensitive exact —
CUI is the separate `cui_permitted` dimension, not a classification level):

`UNCLASSIFIED` · `CONFIDENTIAL` · `SECRET` · `TOP SECRET`

An unrecognized level — including a wrong-case one like `secret` — is **invalid** and
refuses the load. It never silently becomes `Gated`.

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

| Section | Owner | Status |
|---|---|---|
| `authz` | authorization policy *(the config-section registration; the `/etc/maknae/authz.yaml` policy FILE is separate and is enforced per request as of #77 — see the runbook)* | Forthcoming |
| `llm` | LLM-provider authentication | Forthcoming |
| `channels` | channel/comms adapters (Discord, Matrix, …) | Forthcoming |
| `dcs` | optional DCS classification backend | Forthcoming |

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

### 9.3 An extension in `config.d/`

Extension sections belong in `config.d/` (or inline in the base). `config.d/` files
override the base section-by-section. Example directory:

```
/etc/maknae/            # 750
├── maknae.yaml         # 640 — core (+ inline sections)
└── config.d/           # 750
    └── llm.yaml        # 640 — the `llm` section (Forthcoming subsystem)
```

`config.d/llm.yaml`:

```yaml
llm:
  # keys defined by the llm subsystem when it lands (Forthcoming, §6)
  provider: "…"
```

Set config files to `640` (or `660`) and directories to `750` (or `770`) — any
world/other permission bit refuses the load (§2.2).
