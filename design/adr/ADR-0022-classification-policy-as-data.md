# ADR-0022: A `ClassificationPolicy` seam — the kernel ships the US system, `maknae-classification-aus` ships PSPF, `rust-dcs` brings the lattice, and one non-public switch governs egress *(narrowed 2026-09-26: decision 10 adds sensitivity categories beside the switch)*

- **Status:** Accepted (operator-ratified 2026-09-06 at PR B, as a snapshot to work from — "we can adjust as needed later"; proposed and settled in discussion the same day; landed via two PRs, #230 and #231 — see Consequences). The `rust-dcs` references stand deliberately: this is the boundary both projects must delineate, and it is recorded on both sides.
- **Date:** 2026-09-06
- **Deciders:** Alex Ackerman (operator)
- **Amended:** 2026-09-26 — decision 10 added; Context 2 and decision 9 narrowed in place. Maintainer-directed; ratified by the maintainer's merge.

> **Amendment (2026-09-26) — sensitivity categories enter the base build, fail-closed at egress for validated detections.** What was wrong: Context 2 and decision 9 put *all* of the lattice's non-hierarchical half — categories included — in `rust-dcs`, so the base build's label vocabulary was one level and one `non_public` boolean. That shape cannot carry the sensitivity every tier actually holds: a homelab's tax returns, a small business's customer card numbers, an enterprise's health records, and everybody's credentials. Those are **categories**, not levels, and none of them is government classification. A seam, audit record and file label that cannot carry categories from the first release leave `rust-dcs`, or any later handler, nothing to enforce over: every record written before it arrives is unlabeled history, and the primitives it must compose with never knew the label existed. Maknae is not a multilevel secure system; it is a system that must keep sensitive data away from the destinations not permitted to receive it. **Decision 10** adds sensitivity categories to the base build as a primitive: always carried and recorded; declared and region categories and validated detections enforced by default against a destination that has not been permitted them; lower-confidence detections recorded only. Decision 9 now keeps only the *rich* lattice out of the kernel, and decision 6's single non-public switch, named in this ADR's title, becomes one of the egress controls beside the category set. The other decisions are unchanged.

## Context

#148 found the configured classification ceiling parsed at boot and never consulted. Enforcing it per request (operator ruling: *"a boot time only detection is not zero trust"*) forced questions the first drafts got wrong before the operator settled them on 2026-09-06:

1. **What a ceiling is.** The first drafts compared a marking for *equality* with the declared level and treated an unmarked object above baseline as "unknown, so deny" — which made any tuned deployment inert until a labeler existed and turned an accreditation reference into a deny-all. Ruling: **a ceiling is a ceiling — content at or below the declared level flows, content marked above it is refused; unmarked content is UNCLASSIFIED; an ATO has no bearing.** SECRET environments hold UNCLASSIFIED, CUI and SECRET documents side by side, each marked, with handling that gets less restrictive as the level drops. **Clearance is satisfied by holding an account at all; need-to-know is RBAC.** Neither is the kernel's to model.

2. **Where the line is against `rust-dcs`.** *(Narrowed 2026-09-26: sensitivity categories are a base-build primitive under decision 10; the rest of this list stays in `rust-dcs`, and "nothing of it moves here" now reads as the rest.)* The lattice — ~~categories,~~ releasability, caveats, compilation floors, need-to-know, roll-up, banner semantics, cross-system equivalence — lives in [`darkhonor/rust-dcs`](https://github.com/darkhonor/rust-dcs) (paid, external; its ADR-0001 is the lattice, its ADR-0002 forbids US structure in engine code). Nothing of it moves here.

3. **Foreign systems.** An AUS enclave runs under the PSPF ladder, which after the 2018 reform has no CONFIDENTIAL and no RESTRICTED and has different meanings at every rung. A Rust enum of the four US levels — the shape the #148 prototype first built — is exactly the US-structure-in-engine-code that `rust-dcs` split off to avoid. And the first foreign system Maknae must understand is not a paid feature: it is an in-repo crate, still on `maknae-authz-basic` and RBAC, aware of a different system's markings.

4. **The operator's closing caveat.** *"Consider the impact of configuration changes once rust-dcs is compiled in and we have to configure Maknae to understand a rich lattice."* A naïve "policy as data" makes a second vocabulary and a migration on that day. The operator's answer, adopted here: **an interface** — the kernel ships a basic implementation; `rust-dcs`, or any other handler, brings an implementation the kernel already knows how to use.

## Decision

### 1. `ClassificationPolicy` is a seam contract in `maknae-security`, beside `Authorizer`

```rust
/// One classification SYSTEM: how markings rank within it. Level and
/// sensitivity only -- never the lattice.
pub trait ClassificationPolicy: Send + Sync {
    fn name(&self) -> &str;                                   // "US", "AUS", a SPIF's policy id
    fn level_of(&self, marking: &str) -> Option<Level>;       // None: not a marking THIS system understands
    fn unmarked(&self) -> Level;                              // the default for unmarked content
    fn dominates(&self, ceiling: &Level, content: &Level) -> Option<bool>; // at-or-below; None across systems
    fn non_public(&self, marking: &str) -> bool;              // decision 6
}
```

`Level` is `{ policy, name, rank }` — the shape `rust-dcs`'s `Classification { policy, name }` has, deliberately, so the seam speaks the same language when DCS arrives. The trait is general-security vocabulary, not DCS vocabulary (rust-dcs's own optionality rule: *"the seam must speak general security, or the optionality is fake"*). It is level-and-sensitivity only: `dominates` answers the level question and nothing else.

### 2. The kernel ships the US system and nothing foreign — ever

`maknae-config`'s `BasicPolicy` implements the trait for the US system: the ladder `UNCLASSIFIED < CONFIDENTIAL < SECRET < TOP SECRET` (the lake's `_ceiling.py` vocabulary, matched case-insensitively — a stated divergence from that file; separators not normalized), `unmarked() = UNCLASSIFIED`, `level_of` by the marking's **first token** with everything after the first `//` opaque (`SECRET//NOFORN` → `SECRET`), and `non_public` from the US markers: `CUI` as the first token (aliased to UNCLASSIFIED, so a CUI-marked document ranks), `FOUO`/`SBU`/`CUI` as a caveat segment, or a distribution statement other than A anywhere in the marking. *(Corrected 2026-09-06: the earlier text listed bare `FOUO`; a bare legacy `FOUO`/`SBU` first token is refused as unrankable. Operator ruling 2026-09-06: refuse — `FOUO` as a first token was never legal; `CUI` is the authorized first-token state, so only `CUI` is aliased.)* `Classification` stops being a four-variant enum; it is a `Level` in a declared policy. The US system is in the kernel because it is the config's default vocabulary, not because it is special.

### 3. `maknae-classification-aus` ships the PSPF system, in-repo, as the seam's first non-kernel implementation

A new crate depending on `maknae-security` only, implementing the trait for the Australian Protective Security Policy Framework: `UNOFFICIAL < OFFICIAL < OFFICIAL: Sensitive < PROTECTED < SECRET < TOP SECRET` (post-2018 reform: no CONFIDENTIAL, no RESTRICTED), `unmarked() = UNOFFICIAL`, `OFFICIAL: Sensitive` sets `non_public`, `AUSTEO`/`AGAO` are national caveats and are opaque after the `//`. **Authority:** PSPF Release 2025, Attorney-General's Department, as recorded in `rust-dcs`'s `design/references/dcs-schema-migration.md` §13.1 — the crate's module doc cites it; a ladder without an authority does not ship. **Other foreign systems (ROK, …) are separate crates, each when its authority is in hand** — the operator sources them; `rust-dcs` holds the research. One crate per system keeps `p1-manifest-lint`, `coverage-tiers.toml` and `deny.toml` honest about what is present.

### 4. A registry of compiled-in systems, keyed by name; config names the SYSTEM, never the engine

The kernel registers `US`; `maknae-classification-aus` registers `AUS`; `rust-dcs` registers its SPIF-backed systems through the same registry when compiled in. `core.handling.policy` names one (`US` is the default): **deployment data — which system this enclave operates under** — and an unknown name refuses boot. The implementation set is fixed at build; no configuration key selects or replaces an implementation, which keeps the static TCB (ADR-0002) and the authz drift gate's "no config key names the PDP" rule intact. **A policy is always present**: the ceiling operand (PR B) takes a `P: ClassificationPolicy` the way the composition takes a `B: Baseline`; there is no `None`.

### 5. Cross-system markings are RECOGNIZED and REFUSED; equivalence is `rust-dcs`'s

A coalition enclave sees other systems' markings — a US `SECRET//REL AUS` document arriving in an AUS enclave. The registry asks every compiled system `level_of`, so the refusal names whose marking it is (*"US marking in an AUS enclave"*) rather than *"unrecognized"*; that is what "aware of different system markings" buys. The kernel never maps one system's level onto another's — *US SECRET ≈ AUS SECRET?* is treaty data (`rust-dcs` §13.1 keeps such a table) and the kernel refuses where DCS would decide. A first token no compiled system understands is malformed and refused (ADR-0008 decision 4).

### 6. One non-public switch: `cui_permitted` IS it, and the reader sets one `non_public` flag

*(Narrowed 2026-09-26: the switch stays, and is no longer the only egress control. Decision 10 adds a per-destination category set beside it, enforced at the same egress decision, and a read-time check against the egress floor.)*

CUI and "non-public" imply the same thing (operator). Each policy's `non_public` sets a single boolean from its own markers; **`cui_permitted` on a ceiling governs it** — the field keeps its name for lake parity, its meaning is *non-public content permitted*, with CUI as the US spelling and `OFFICIAL: Sensitive` as the AUS one. It is a flag, not a level.

**Where it bites: egress, not internal serving.** Cloud models connected to a SECRET enclave are IL6-accredited or there is no ATC — the level is not the egress risk; **sensitivity leaving to a destination not cleared for it** is: CUI to a non-GovCloud model, anything non-public to GitHub or a public LLM. The lake is held at unclassified because its two destinations are cleared for public only. Egress is therefore a **destination ceiling** — the same `handling` shape declared per destination (`cui_permitted: false` for GitHub and a public model, `true` for a GovCloud model, a SECRET level for an IL6 one) — checked with the same `dominates` plus the `non_public` flag. That is #147's design; this ADR hands it the foundation.

### 7. No `handling` field changes meaning when `rust-dcs` is compiled in — fields go from RECORDED to ENFORCED

The lake's `handling` block already carries `sci`, `releasable_to`, `cui_permitted`, `cui_categories_permitted`, `dissemination_permitted`. The base build enforces the level (via the policy) and the non-public switch (at egress) and records the rest; a DCS build enforces the same declaration as a full label ceiling. An operator who tuned a `handling` block on day one does not rewrite it. **Adding a `handling` field whose meaning differs between builds is the regression this decision exists to prevent.**

### 8. Compiling in `rust-dcs` is additive at the seam

Its SPIF-backed policy registers under decision 4 and the ceiling operand uses it through the trait; its `dcs-label` decides what `RESOURCE_CLASSIFICATION` carries for it (a full banner, since its `level_of` parses one); its lattice operand joins the composition (ADR-0008) over its own rich label key. Nothing existing is unwired or reconfigured. *(The earlier form of this ADR kept a kernel-side ladder cross-checked against the SPIF at boot; the interface makes that unnecessary — there is no second ladder to drift.)*

### 9. What the kernel never does

Model clearance (account provisioning does), model need-to-know (RBAC does), interpret anything after `//`, map levels across systems, hold the rich lattice (compartments, releasability, caveats, need-to-know, portion and banner semantics), or ship a foreign ladder. *(Narrowed 2026-09-26: this said "hold a lattice", which kept sensitivity categories out of the base build. They are in it now: decision 10.)* Deployments without `rust-dcs` are not expected to hold SECRET-and-above documents (operator); in them the level check is a spillage guard and the non-public switch at egress is the live control.

### 10. Sensitivity categories are a base-build primitive: carried always, enforced at egress, detected opportunistically, raised only (2026-09-26)

**Why the base build.** A label has to exist in the primitives from the first release: the seam's request attributes, the audit record, the per-file label, and the destination's accreditation. An extension compiled in later can enforce a richer label over those primitives; it cannot retrofit a label onto primitives that never carried one. The sensitivity that matters from homelab to enterprise is mostly non-hierarchical (health, financial, credentials, identity), and its main risk is **where the data goes**, not who reads up. In Maknae, the path to a model provider that the kernel brokers is the decided `session.prompt` egress frame, so the decisive check there is whether the categories in that frame are permitted at its destination.

**Categories ride beside the marking, never inside it.** `RESOURCE_CLASSIFICATION` keeps its contract and its provenance rule unchanged: a bare level token, stamped by the trust plane from the object's own label, never from anything a client can supply. Categories get a seam key of their own when this is built, carrying a set of categories and where each came from. The shape, not yet the signature (the `maknae-security` contract changes when this is built, and the consumers named in Consequences with it):

```rust
CategorySet(Vec<(Category, Provenance)>)
enum Provenance {
    Declared,                      // the trust plane: an operator-set per-file label
    Region,                        // the policy: a path region declared with categories
    Detected { detector: String, tier: Tier },
}
```

**Categories are data, and they name the data, not the law.** Classification and labelling of information are ISO/IEC 27001:2022 controls A.5.12 and A.5.13; here the vocabulary is operator-defined deployment data, as classification systems are under decision 4. The base build ships a starter set; an operator may add categories. A category describes what the content *is*; which legal regime a destination satisfies is a property of the **destination**. `HEALTH`, not `PHI`: HIPAA applies to covered entities and their business associates (45 CFR 160.102; definitions in 160.103), not to a homeowner's own records, while a provider under a business associate agreement is a destination permitted `HEALTH`.

| Category | Covers |
|---|---|
| `CREDENTIAL` | API keys and tokens, private keys, `.env` secrets, TOTP seeds, recovery codes, password-manager exports |
| `CRYPTO_WALLET` | seed phrases and wallet keys. Separate from `CREDENTIAL` because theft is irreversible |
| `FINANCIAL` | card numbers, bank account and routing numbers, IBANs, tax and mortgage documents |
| `GOV_ID` | SSN, ITIN, passport, driver's licence, Medicare and VA identifiers |
| `HEALTH` | medical records, prescriptions, lab results |
| `IDENTITY` | date of birth, full address, phone, email, name |
| `LOCATION` | GPS coordinates in image metadata, location-history exports |
| `HOME_SECURITY` | alarm, door and garage codes, camera and router credentials, Wi-Fi keys |
| `MINOR` | children's school, medical and identity records |
| `LEGAL` | wills, powers of attorney, custody and divorce documents |

**The default is fail-closed, as decision 6's is.** A destination's `handling` gains the set of categories it may receive, and an undeclared set is **empty**, the same default `cui_permitted: false` gives the non-public switch today (`Ceiling::baseline_for`). Categories are always carried and always recorded. What is **enforced** by default is every `Declared` and `Region` category and every `Validated` detection; `Contextual` and `Pattern only` detections are recorded and enforced only when the operator raises them. **This changes the behaviour of a deployment that declares nothing:** a frame carrying a Luhn-valid card number, a Vault token or a seed phrase is refused to every destination until the operator permits that category there. That is the intended default (there is rarely a valid reason for those to reach a model), and it is the only behaviour change this decision makes to an undeclared deployment. Unmarked content is still the system's lowest level (the 2026-09-06 ruling stands); it carries only the categories a detector finds. Because the loop re-sends the whole transcript every call, a refused category that enters a transcript refuses every later frame of that conversation. That is the fail-closed outcome; the relief is a new conversation, or redaction (open, below).

**Category decisions are mandatory.** Categories are decided by a mandatory (MAC-type) operand in the non-removable composition (ADR-0008 decision 1), whether the ceiling operand or a named sibling is a build decision. Its `Deny` is not waivable by any discretionary `Permit` under deny-overrides (ADR-0020 decision 3, ADR-0008 decision 3), and no role, admin included, sends a refused category to a destination (ADR-0020 decision 4). Like the ceiling operand, it never `Permit`s.

**Where categories are decided.**
- **At egress: the enforcement point.** The kernel decides every `session.prompt`, and the frame it hands the egress deputy carries both the destination and the whole transcript (the loop is stateless and re-sends it every call; ADR-0023 decision 7). The frame is therefore the one place where the trust plane holds every byte about to leave *and* knows where it is going, with no conversation state needed. Detectors run over the frame, and the categories found must be permitted at its destination. Which trust-plane process runs them (the kernel or the egress deputy) is open: it is content inspection inside the trust plane, which is TCB surface (ADR-0002), not a file read.
- **At read, against the egress floor.** A read carries no destination: the conversation identifier on the wire is informational and never decided on, and the destination is chosen per egress request. So `Declared` and `Region` categories are enforced at read against the **intersection** of the configured destinations' permitted sets, the egress floor. That check is the one that stays sound without knowing the destination: an object is readable only if every destination may receive its categories. With no destination configured the floor is **empty**, never the vacuous everything. The floor applies to **every** read, whether or not it carries a conversation identifier, because that field is optional and client-chosen. So it also refuses the human's own `maknae read` of such an object: the human and the agent share a uid (ADR-0024) and the kernel cannot tell them apart. A region an operator declares and permits to no destination is readable outside Maknae only. A `Validated` detection by the supported client at read withholds release in that client, a supported-client property. Keying read decisions to one destination needs a kernel-bound conversation identity, which today's wire deliberately lacks; that is open.
- **By region.** A policy may declare a path region's categories (`~/medical/**: [HEALTH]`). A region label cannot be lost on a copy made inside the region, and it is how most homelab and small-business content will be labeled.

**What is guaranteed, and what is not.** Every frame on the brokered egress path is decided against its destination, and `Validated` detectors over the frame bound non-adversarial leakage: the credential a careless read pulls into a prompt. Detection in the client during a read attempt (#365, #371) is a **supported-client property**. The residual is named: file bytes are read under the subject's own uid and are never in the trust plane, and the loop is untrusted and authors the transcript. An adversarial or prompt-injected loop can evade frame detection by encoding content (base64, splitting a number across turns), can move `Declared` or `Region` content that no detector recognises (six of the starter categories have no `Validated` detector), and can reach the network by a path the kernel does not broker (ADR-0023's banner, correction 6). Against that loop the read-time floor is the control, for reads the kernel decides, and it binds only reads made through Maknae.

**Raise-only provenance.** An untrusted source may add a category; only the trust plane may remove or lower one. This is principle 2 applied to labels: content informs, never authorizes, and a proposal that can only restrict does not authorize anything. A client detector that misses something falls back to the egress detectors and the region and declared labels; one that over-matches only over-restricts. A `user.*` extended attribute is admissible as a **client-reported** hint: only the subject can read it (it needs read permission on the file, which the daemon does not hold), and the agent removing it lowers nothing the trust plane set.

**Confidence tiers.** A detector's tier bounds what its finding may do by default:

| Tier | Basis | Default effect |
|---|---|---|
| **Validated** | a checksum or a vendor-fixed structure | enforced |
| **Contextual** | a pattern plus a nearby keyword | recorded; enforced if the operator raises it |
| **Pattern only** | a shape alone | recorded |

Several `Pattern only` findings of different kinds in one object (a date, a name and an address) escalate together to `Contextual`; the threshold is operator data. A date alone is noise; a date of birth beside a name and an address is an identity: ZIP code, date of birth and sex together identify most of the US population (Sweeney, 2000). This is why dates are not enforced by default: legitimate uses are everywhere, and the operator who wants stricter handling raises the tier while the trail has recorded them throughout.

Starter detectors:

| Detector | Category | Tier |
|---|---|---|
| HashiCorp Vault tokens: `hvs.`, `hvb.`, `hvr.` prefixes (Vault 1.10 and later) | `CREDENTIAL` | Validated |
| `vault operator init` output (`Unseal Key N:`, `Initial Root Token:`) | `CREDENTIAL` | Validated |
| Legacy Vault service tokens (`s.` + 24 characters) near `VAULT_TOKEN` / `X-Vault-Token` | `CREDENTIAL` | Contextual |
| AppRole `secret_id` (a UUID near `secret_id`) | `CREDENTIAL` | Contextual |
| PEM private-key blocks, `otpauth://` URIs, password-manager export headers, AWS access-key IDs (`AKIA`, `ASIA`; not secret themselves, they mark a key pair) | `CREDENTIAL` | Validated |
| Prefixes without a fixed structure (`sk-` and similar) near a key-like assignment | `CREDENTIAL` | Contextual |
| BIP-39 seed phrases (12, 15, 18, 21 or 24 list words with a valid checksum) | `CRYPTO_WALLET` | Validated |
| Card numbers (Luhn, ISO/IEC 7812-1), US routing numbers (check digit), IBANs (mod 97, ISO 13616) | `FINANCIAL` | Validated |
| SSNs outside the never-issued values (area 000, 666, 900–999; group 00; serial 0000) | `GOV_ID` | Contextual |
| ITINs (the 9xx area with the ITIN group ranges) | `GOV_ID` | Contextual |
| GPS coordinates in image metadata | `LOCATION` | Validated |
| Dates of birth (a date near `DOB` / `born` / `birth`) | `IDENTITY` | Contextual |
| Any date, name, address, phone or email | `IDENTITY` | Pattern only |

**The per-file label is `security.maknae.*` on Linux.** Measured 2026-09-26 on Rocky 10.2 (kernel 6.12, XFS, SELinux enforcing), Rocky 9.8 (kernel 5.14, XFS, SELinux enforcing) and Debian 13 (kernel 6.12, ext4, no SELinux), with identical results on all three:
- The subject can set, overwrite and remove a `user.*` attribute, so it cannot hold a trust-plane label.
- The subject **cannot** set, overwrite or remove `security.maknae.*`; root can. The gate is the kernel's capability check, not SELinux: it held on Debian with no SELinux labels.
- `security.*` reads without read permission on the file; `user.*` does not. The daemon can read the label under #365's no-content-access rule.
- `fgetxattr` on an `O_PATH` descriptor fails `EBADF`; `getxattr` on `/proc/self/fd/N` succeeds; `getxattrat` (Linux 6.13) is absent on all three kernels.

Setting a declared label therefore needs a privileged labeler, and whether that is a trust-plane verb, a setup-plane tool or both is a TCB decision this amendment does not make. **macOS has no attribute namespaces**: apart from SIP-protected `com.apple.*` attributes, anyone who can write a file can change its attributes, so a per-file declared label there needs a separate mechanism (Endpoint Security's authorization events are the candidate). It is a gap on a supported platform, not a reduced profile.

**Copies lose per-file labels, and that is a named residual.** On all three hosts the label survived in-place writes, a same-filesystem `mv` and `vi`, and was lost to `sed -i`, write-then-rename saves, `cp`, `tar`, and `cp -a` / `cp --preserve=xattr` run by the subject, which cannot write `security.*`. What still governs a copy: a region label on the path it lands in, and egress detection when its content is sent. A lost `Declared` label on content no detector recognises is not recovered. A human's copy outside Maknae is the human's own data under the human's own credentials and is outside the reference monitor. A deployment that needs labels to survive any copy uses a data-centric format that seals the label with the content (TDF), which is `rust-dcs` territory.

**The boundary with `rust-dcs` after this amendment.** The base build carries the category set and its provenance and enforces as above. `rust-dcs` keeps SPIFs, compartments, releasability, caveats, need-to-know, portion and banner semantics, cross-system equivalence and TDF. When compiled in, it may map these categories into its own label; it does not change what a base-build category means (decision 7). Its own lattice categories are a different vocabulary, and the name overlap is reconciled on that side.

## Consequences

- **Two PRs, deliberately.** **PR A — the classification system:** the trait; `BasicPolicy` (US); `maknae-classification-aus`; the registry; `core.handling.policy` (registered with the #162 disclosure classification and gate); the **boot path as the consumer** — the ceiling's `classification` is validated through the selected system (an AUS enclave boots on `PROTECTED`; a US one refuses it; an unknown system name refuses); `ingest_posture()` becomes policy-relative; `admin.status` carries the system name. *(Corrected 2026-09-06, at PR A: the boot record moves to PR B — the system name belongs on the composition evidence record PR B introduces, beside the ceiling level it ranks; PR A adds no boot record of its own.)* Golden matrices for both ladders, T1. **It ships no enforcement and says so** — #148's defect was "parsed, never consulted," and a classification system with no consumer would be that defect with a nicer type; the boot path is the consumer. **PR B — enforcement:** the non-removable composition (ADR-0008 decision 1, #154), the ceiling operand holding the registry's `&'static dyn ClassificationPolicy` *(corrected 2026-09-06 at PR B: a trait object from the fixed-at-build registry, not a generic `P`)*, `build_pdp`, the drift gate, the boot evidence record (composition, system name, ceiling level). *(Corrected 2026-09-06 at PR B: the seam-key WRITER is not PR B's — nothing populates `RESOURCE_CLASSIFICATION` until #229 (or `dcs-label` with DCS installed); PR B ships the reader and its contract.)* Closes #148 and #154.
- **The three deployment tiers function with `-basic` and the kernel's system alone** — HomeLab (no `handling`; US; UNCLASSIFIED), small business (`cui_permitted: true`; the first tier where content has meaning), enterprise (`SECRET`; UNCLASSIFIED, CUI and SECRET documents with handling per marking; a document marked above the ceiling refused). An AUS enclave adds one crate and one config line. None needs a labeler, an ATO or `rust-dcs`.
- **Supersedes, in place and dated:** `ceiling.rs`'s "stores the level; does NOT order them" (a policy ranks within its own system); the #148 prototype's `Ord`-derived enum and its per-request-equality operand (revisions 1–7 of its plan).
- **Decision 10 (2026-09-26) is built as its own work, not by this amendment.** It adds a category seam key to the `maknae-security` contract, and changes its consumers with it: the mandatory operand in the composition, the destination `handling` shape in `maknae-config`, the egress decision over the `session.prompt` frame, the audit record, the kernel's read decision, and the client read path. #229 remains the per-file label reader; destination category sets belong to #147. Open and undecided: which trust-plane process runs the egress detectors (TCB surface); a kernel-bound conversation identity, without which reads are decided against the egress floor rather than one destination; the privileged labeler (a TCB decision); macOS per-file labels; redaction as an alternative to refusal (a card's last four digits, an age for a date of birth), for which the destination shape should leave room; whether the category vocabulary aligns with the CUI Registry's categories for deployments that also declare CUI.
- **Open, owned by named work:** egress destination ceilings (#147); the marking reader's stamping point (#229, PR B); ROK and other systems (operator-sourced authorities, one crate each); how `dcs-label` and the ceiling operand share `RESOURCE_CLASSIFICATION` (decision 8 permits either shape; the composition is unaffected). ~~`admin.audit.tail` / `admin.config.show` staying control plane (open operator question)~~ *(struck 2026-09-06, #233: never open — the operator ruled at the start of #148 that control-plane verbs carry zero classified data, so every `admin.*` term abstains, which the ceiling operand has done from its first commit; the whole-vocabulary partition test in `handler.rs` pins it).*

## References

- [ADR-0004](ADR-0004-modular-authorization-architecture.md) — modular by contract where a real substitution axis exists; this ADR is that pattern applied to classification. [ADR-0020](ADR-0020-access-control-model-and-vocabulary.md) — vocabulary; MAC/ABAC; deny-overrides. [ADR-0008](ADR-0008-authorization-composition-contract.md) — the non-removable composition PR B's operand joins. [ADR-0002](ADR-0002-kernel-is-rust.md) — static TCB: implementations by build, never by config. [ADR-0019](ADR-0019-audit-record-model.md) — the boot record that carries the system name.
- `darkhonor/rust-dcs` — ADR-0001 (lattice), ADR-0002 (foreign systems as data), `dcs-model::Classification { policy, name }`, `Spif::rank`, `design/references/dcs-schema-migration.md` §13.1 (PSPF; the equivalence table the kernel does NOT implement).
- PSPF Release 2025 (Australian Attorney-General's Department) — the AUS ladder's authority, via the reference above.
- Decision 10's external references, each for the fact cited beside it: 45 CFR 160.102 and 160.103 (HIPAA's applicability and definitions); L. Sweeney, *Simple Demographics Often Identify People Uniquely*, Carnegie Mellon University, Data Privacy Working Paper 3, 2000; HashiCorp Vault token prefixes (https://developer.hashicorp.com/vault/docs/concepts/tokens); ISO/IEC 7812-1 (the Luhn check); ISO 13616 (IBAN); BIP-39 (mnemonic seed phrases); ISO/IEC 27001:2022 Annex A 5.12 and 5.13 (classification and labelling of information).
- #148, #154, #147, #229, the maintainer's earlier Knowledge Lake `_ceiling.py` (private) (the US ladder's origin). Operator rulings 2026-09-06, quoted in Context.
