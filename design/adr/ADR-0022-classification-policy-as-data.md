# ADR-0022: A `ClassificationPolicy` seam — the kernel ships the US system, `maknae-classification-aus` ships PSPF, `rust-dcs` brings the lattice, and one non-public switch governs egress

- **Status:** Accepted (operator-ratified 2026-09-06 at PR B, as a snapshot to work from — "we can adjust as needed later"; proposed and settled in discussion the same day; landed via two PRs, #230 and #231 — see Consequences). The `rust-dcs` references stand deliberately: this is the boundary both projects must delineate, and it is recorded on both sides.
- **Date:** 2026-09-06
- **Deciders:** Alex Ackerman (operator)

## Context

#148 found the configured classification ceiling parsed at boot and never consulted. Enforcing it per request (operator ruling: *"a boot time only detection is not zero trust"*) forced questions the first drafts got wrong before the operator settled them on 2026-09-06:

1. **What a ceiling is.** The first drafts compared a marking for *equality* with the declared level and treated an unmarked object above baseline as "unknown, so deny" — which made any tuned deployment inert until a labeler existed and turned an accreditation reference into a deny-all. Ruling: **a ceiling is a ceiling — content at or below the declared level flows, content marked above it is refused; unmarked content is UNCLASSIFIED; an ATO has no bearing.** SECRET environments hold UNCLASSIFIED, CUI and SECRET documents side by side, each marked, with handling that gets less restrictive as the level drops. **Clearance is satisfied by holding an account at all; need-to-know is RBAC.** Neither is the kernel's to model.

2. **Where the line is against `rust-dcs`.** The lattice — categories, releasability, caveats, compilation floors, need-to-know, roll-up, banner semantics, cross-system equivalence — lives in [`darkhonor/rust-dcs`](https://github.com/darkhonor/rust-dcs) (paid, external; its ADR-0001 is the lattice, its ADR-0002 forbids US structure in engine code). Nothing of it moves here.

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

CUI and "non-public" imply the same thing (operator). Each policy's `non_public` sets a single boolean from its own markers; **`cui_permitted` on a ceiling governs it** — the field keeps its name for lake parity, its meaning is *non-public content permitted*, with CUI as the US spelling and `OFFICIAL: Sensitive` as the AUS one. It is a flag, not a level.

**Where it bites: egress, not internal serving.** Cloud models connected to a SECRET enclave are IL6-accredited or there is no ATC — the level is not the egress risk; **sensitivity leaving to a destination not cleared for it** is: CUI to a non-GovCloud model, anything non-public to GitHub or a public LLM. The lake is held at unclassified because its two destinations are cleared for public only. Egress is therefore a **destination ceiling** — the same `handling` shape declared per destination (`cui_permitted: false` for GitHub and a public model, `true` for a GovCloud model, a SECRET level for an IL6 one) — checked with the same `dominates` plus the `non_public` flag. That is #147's design; this ADR hands it the foundation.

### 7. No `handling` field changes meaning when `rust-dcs` is compiled in — fields go from RECORDED to ENFORCED

The lake's `handling` block already carries `sci`, `releasable_to`, `cui_permitted`, `cui_categories_permitted`, `dissemination_permitted`. The base build enforces the level (via the policy) and the non-public switch (at egress) and records the rest; a DCS build enforces the same declaration as a full label ceiling. An operator who tuned a `handling` block on day one does not rewrite it. **Adding a `handling` field whose meaning differs between builds is the regression this decision exists to prevent.**

### 8. Compiling in `rust-dcs` is additive at the seam

Its SPIF-backed policy registers under decision 4 and the ceiling operand uses it through the trait; its `dcs-label` decides what `RESOURCE_CLASSIFICATION` carries for it (a full banner, since its `level_of` parses one); its lattice operand joins the composition (ADR-0008) over its own rich label key. Nothing existing is unwired or reconfigured. *(The earlier form of this ADR kept a kernel-side ladder cross-checked against the SPIF at boot; the interface makes that unnecessary — there is no second ladder to drift.)*

### 9. What the kernel never does

Model clearance (account provisioning does), model need-to-know (RBAC does), interpret anything after `//`, map levels across systems, hold a lattice, or ship a foreign ladder. Deployments without `rust-dcs` are not expected to hold SECRET-and-above documents (operator); in them the level check is a spillage guard and the non-public switch at egress is the live control.

## Consequences

- **Two PRs, deliberately.** **PR A — the classification system:** the trait; `BasicPolicy` (US); `maknae-classification-aus`; the registry; `core.handling.policy` (registered with the #162 disclosure classification and gate); the **boot path as the consumer** — the ceiling's `classification` is validated through the selected system (an AUS enclave boots on `PROTECTED`; a US one refuses it; an unknown system name refuses); `ingest_posture()` becomes policy-relative; `admin.status` carries the system name. *(Corrected 2026-09-06, at PR A: the boot record moves to PR B — the system name belongs on the composition evidence record PR B introduces, beside the ceiling level it ranks; PR A adds no boot record of its own.)* Golden matrices for both ladders, T1. **It ships no enforcement and says so** — #148's defect was "parsed, never consulted," and a classification system with no consumer would be that defect with a nicer type; the boot path is the consumer. **PR B — enforcement:** the non-removable composition (ADR-0008 decision 1, #154), the ceiling operand holding the registry's `&'static dyn ClassificationPolicy` *(corrected 2026-09-06 at PR B: a trait object from the fixed-at-build registry, not a generic `P`)*, `build_pdp`, the drift gate, the boot evidence record (composition, system name, ceiling level). *(Corrected 2026-09-06 at PR B: the seam-key WRITER is not PR B's — nothing populates `RESOURCE_CLASSIFICATION` until #229 (or `dcs-label` with DCS installed); PR B ships the reader and its contract.)* Closes #148 and #154.
- **The three deployment tiers function with `-basic` and the kernel's system alone** — HomeLab (no `handling`; US; UNCLASSIFIED), small business (`cui_permitted: true`; the first tier where content has meaning), enterprise (`SECRET`; UNCLASSIFIED, CUI and SECRET documents with handling per marking; a document marked above the ceiling refused). An AUS enclave adds one crate and one config line. None needs a labeler, an ATO or `rust-dcs`.
- **Supersedes, in place and dated:** `ceiling.rs`'s "stores the level; does NOT order them" (a policy ranks within its own system); the #148 prototype's `Ord`-derived enum and its per-request-equality operand (revisions 1–7 of its plan).
- **Open, owned by named work:** egress destination ceilings (#147); the marking reader's stamping point (#229, PR B); ROK and other systems (operator-sourced authorities, one crate each); how `dcs-label` and the ceiling operand share `RESOURCE_CLASSIFICATION` (decision 8 permits either shape; the composition is unaffected). ~~`admin.audit.tail` / `admin.config.show` staying control plane (open operator question)~~ *(struck 2026-09-06, #233: never open — the operator ruled at the start of #148 that control-plane verbs carry zero classified data, so every `admin.*` term abstains, which the ceiling operand has done from its first commit; the whole-vocabulary partition test in `handler.rs` pins it).*

## References

- [ADR-0004](ADR-0004-modular-authorization-architecture.md) — modular by contract where a real substitution axis exists; this ADR is that pattern applied to classification. [ADR-0020](ADR-0020-access-control-model-and-vocabulary.md) — vocabulary; MAC/ABAC; deny-overrides. [ADR-0008](ADR-0008-authorization-composition-contract.md) — the non-removable composition PR B's operand joins. [ADR-0002](ADR-0002-kernel-is-rust.md) — static TCB: implementations by build, never by config. [ADR-0019](ADR-0019-audit-record-model.md) — the boot record that carries the system name.
- `darkhonor/rust-dcs` — ADR-0001 (lattice), ADR-0002 (foreign systems as data), `dcs-model::Classification { policy, name }`, `Spif::rank`, `design/references/dcs-schema-migration.md` §13.1 (PSPF; the equivalence table the kernel does NOT implement).
- PSPF Release 2025 (Australian Attorney-General's Department) — the AUS ladder's authority, via the reference above.
- #148, #154, #147, #229, the maintainer's earlier Knowledge Lake `_ceiling.py` (private) (the US ladder's origin). Operator rulings 2026-09-06, quoted in Context.
