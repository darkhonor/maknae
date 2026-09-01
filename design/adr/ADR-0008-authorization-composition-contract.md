# ADR-0008: Authorization composition contract — a non-removable baseline, extensions that decide by their own model, and no operand that fails open

- **Status:** Accepted (operator-ratified 2026-08-29)
- **Date:** 2026-08-29
- **Deciders:** Alex Ackerman (operator)

## Context

[ADR-0004](ADR-0004-modular-authorization-architecture.md) established modular authorization: a stable, versioned contract (`maknae-security`) with swappable `maknae-authz-*` implementations behind it. [ADR-0020](ADR-0020-access-control-model-and-vocabulary.md) established the access-control vocabulary and deny-overrides composition. PR #146 wired the per-request PDP: `crates/maknae-kernel/src/run.rs` composes `combine(vec![guarded_decide(&*a, &sec_req)])` and finalizes.

Three things were true and unrecorded:

1. **The composition has exactly one operand, and the baseline's presence is a property of the code path rather than a guarantee.** `boot_gate.rs` returns a concrete `BasicAuthorizer`; `run.rs` takes `Arc<P>` monomorphized at the call site; no configuration selects a backend. Issue [#154](https://github.com/darkhonor/maknae/issues/154) recorded the observation. Nothing is exploitable today — there is no mechanism to substitute a backend — but the guard must exist *before* one is added, not after.

2. **What an extension is permitted to do was never decided**, only implied by `combine`'s fold rules.

3. **What any operand must do with input it cannot evaluate was never decided**, only emergent: `class_of()` returns `None` for an unrecognized action, `decide_loaded` maps it to `NotApplicable`, and `finalize` converts that to `Deny { "no applicable authorizer (fail-closed)" }`. The outcome is correct; it is reached by abstention rather than by an explicit refusal, and its audit reason cannot distinguish *"this term does not exist"* from *"you lack the role."* *(No longer current — closed by the 2026-09-02 amendment below, #181: absences now carry audit-only testimony and the trail distinguishes all four refusal classes. Kept as the context that motivated decision 5.)*

**The failure that motivates this ADR.** In the design discussion that produced it, the agent twice derived *"extensions may only ever add denials"* from ADR-0020's *"a mandatory Deny is never waivable by a discretionary Permit."* **That reading is wrong.** ADR-0020 constrains what an extension can **undo**, not what it can **do**. Issue #154's own body carries the same error in its phrasing (*"it may only ever add denials"*), which is where the agent took it from.

The operator's correction, verbatim (2026-08-29):

> Your understanding of DCS is flawed. It ABSOLUTELY can specify a grant based on attributes. It's never a deny only additions. If an extension adds a capability basic doesn't know about (aka N/A) and the extension authorizes it based on conditions it should be permitted. **To think `-basic` will have all knowing knowledge of the entire universe is flawed.**

> Extensions can grant on whatever they are designed to grant for. Could be attributes, could be whatever. They cannot override a `-basic` Deny. But they can grant or deny based on whatever their extension models. Combine handles the composition where 1 deny is a deny no matter what the other resulting conditions are.

A deny-only extension model would have deleted the extensibility ADR-0004 exists for. The error is easy to repeat from a partial reading of ADR-0020, which is why the contract is recorded here rather than left implicit in a doc comment.

## Decision

### 1. `maknae-authz-basic` is always an operand — non-removable by construction, not by configuration

The baseline is **structurally** present. Four layers, in order of strength:

- **Type-level.** The composition holds the baseline as a **named field**, not as an element of the operand vector:

  ```rust
  pub struct Composition {
      baseline: BasicAuthorizer,            // a named field — not a vec element
      extensions: Vec<Box<dyn Authorizer>>,
  }
  ```

  A `Composition` **cannot be constructed without a baseline.** This is stronger than a defaulted configuration value, which can be omitted; here the absent state is not expressible. It matches the `maknae-io` idiom already in the tree: callers name what they require, and `None` is a named, greppable value rather than a silent absence.

- **Configuration vocabulary.** There is **no config key that names the baseline.** Configuration expresses *extensions*; it has no way to refer to, replace, or omit `maknae-authz-basic`. **Adding such a key in future is the regression this ADR exists to prevent.**

- **A drift gate** over the composition root, in the family of `std-fs-drift`, asserting the baseline is constructed unconditionally — so the refactor that introduces a selection key fails CI rather than shipping.

- **Boot-time evidence.** The daemon records in the audit trail that its composition included the baseline, and which extensions were loaded. The property becomes auditable **at runtime**, not only at build time.

### 2. Every operand decides by its own model, and may grant — including mandatory operands

An extension is **not** restricted to denials, and **not** restricted to attributes. It grants or denies according to whatever it models. **Extensions add to the authorized vocabulary.**

`-basic` is not expected to model the universe. A capability `-basic` does not know about is one `-basic` abstains on (`NotApplicable`), and an extension that does model it and authorizes it under its own conditions **is permitted to grant it**.

**This includes mandatory (MAC) operands, and it amends [ADR-0020](ADR-0020-access-control-model-and-vocabulary.md) §3.** That ADR required a mandatory operand to be *constraint-only* — `Deny` or `NotApplicable`, **never `Permit`** — on the reasoning that "granting is the discretionary layer's job."

**That reasoning assumed permit-by-default with mandatory controls subtracting. Maknae is deny-by-default: grants authorize, and denials carve out for cause** (lost clearance, invalid account, biometric failure, revocation). Operator ruling, 2026-08-29:

> I hadn't realized as written 20 assumes you are permitted by default and only removed otherwise. Which is backwards. We deny by default and only authorize with grants. We can carve denials out as well for use cases.

**The worked case that breaks constraint-only.** An Australian national with SECRET clearance requesting a `SECRET//REL USA, FVEY` object. Releasability is not expressible in the capability grammar, so `maknae-authz-basic` returns `NotApplicable`. A constraint-only mandatory operand also returns `NotApplicable` — the clearance is sufficient, so there is nothing to deny. `combine` folds to `NotApplicable`, `finalize` returns **`Deny`**, and **an entitled subject is refused with no configuration able to fix it.** The only operand competent to evaluate `AUS ∈ FVEY ∧ clearance ≥ SECRET` was forbidden from ever saying yes.

Constraint-only could be made to "work" only by having `-basic` grant broadly over objects whose releasability it cannot evaluate — that is, by making the **discretionary** layer fail open, which decision 4 below forbids. It also contradicted ADR-0020 §2's own claim that `maknae-authz-dcs` "provides full ABAC": a decision model that can only deny is not a decision model.

**The corrected rule — a mandatory operand may `Permit` only on a COMPLETE evaluation of its own predicate.** Clearance **and** releasability **and** compartments **and** need-to-know, as its model defines. It returns `NotApplicable` when it cannot fully evaluate, and `Deny` when the predicate fails. **Clearance alone is never a grant.**

**What ADR-0020 keeps, unchanged:** mandatory operands are **always composed** (never silently absent — this was always the separate, load-bearing half of §3); they **fail closed**; and **deny-overrides** means no operand's `Permit` can override a peer's `Deny`. **ADR-0020 decision 4 — no clearance bypass for any subject, admin or kernel — is unaffected**, because it rests on `Deny` winning, not on `Permit` being forbidden.

ADR-0020 §3's original worry — *"a mandatory `Permit` could turn a default-deny `NotApplicable` into `Permit`"* — was correct; the remedy was too blunt. It is now carried by **decision 4 below**: an operand that cannot fully evaluate returns `NotApplicable`, never `Permit`.

### 2a. Grants authorize; carved denials revoke for cause — both halves are structural

Maknae is **deny-by-default**. Two mechanisms move a subject off that default, and they are not symmetric in kind:

- **A grant authorizes.** Any operand may grant, per decision 2, within whatever it models.
- **A carved denial revokes for cause** — lost clearance, invalid account, biometric failure, revocation, operator judgment. Operator ruling 2026-08-29: *"We deny by default and only authorize with grants. We can carve denials out as well for use cases … This is why the `.contain` verbs are key. They implement the carved denials."*

**Containment is therefore part of the access model, not an incident-response convenience.** It is implemented by the `admin.contain` / `admin.release` / `kernel.contain` terms ([#165](https://github.com/darkhonor/maknae/issues/165)), and it has **exactly one sanctioned spelling** — `admin.subject.bind`/`.unbind` refuse the `adversary` role precisely so the carve mechanism stays the single auditable path. A second route into containment makes "denied for cause" unreconstructable.

**A carve is scoped.** A bare carve is **total** (the `adversary` role, deny-all); a scoped carve is a **subject-scoped deny list** reusing the policy's own deny vocabulary. Total containment is the degenerate case where the scope is everything. Because a carve is expressed in the deny grammar, **the whole-vocabulary deny requirement in Consequences below is what makes scoped carves possible at all.**

**A carve is never waivable, only liftable.** No `Permit` from any operand composes past it — including a **mandatory operand's `Permit`**, now that decision 2 allows one. `combine` rule 1 gives this for free; #165 asserts it rather than assuming it.

**Distinguish a carve from a per-request predicate denial.** A mandatory operand that denies on its own predicate every request — insufficient releasability, clearance absent at decision time — needs no carve; that is the normal decision path. **Carves are for persistent, cause-attributed state** that survives across requests and remains visible whether or not the attribute engine is loaded.

### 3. No operand may waive a Deny — `combine` as ratified is the whole composition contract

`crates/maknae-security/src/compose.rs::combine`, unchanged:

1. any `Deny` → `Deny`
2. else any `Indeterminate` → `Deny` (never masked by a peer `Permit`)
3. else any `Permit` → `Permit` with the union of Permit obligations; a `(id, params)` conflict → `Deny`
4. else (all `NotApplicable`, or empty) → `NotApplicable` → `Deny` at `finalize` *(amended 2026-09-02, #181: the surviving absence carries the FIRST annotated operand's note — the kernel passes the baseline first, so baseline testimony outranks. Notes are audit-only; the classification here is untouched)*

One `Deny` is a Deny regardless of what any peer concluded. That single rule *is* the non-waivability guarantee; no additional mechanism is required, and **`combine` is not to be modified to implement this ADR.** *(Amended 2026-09-02, #181: `combine` WAS modified once, for rule 4's note-carry only — testimony selection, not classification. No fold rule changed; the classification-invariance rows in `golden.rs` pin that a note can never alter which branch fires.)* `guarded_decide`'s panic boundary already converts a hostile or buggy operand into `Indeterminate`, and rule 2 converts that to `Deny`.

### 4. No operand may fail open

For input an operand cannot evaluate, it returns **`Deny` or `Indeterminate`** — never `Permit`, and never a silent pass-through. **`NotApplicable` is reserved for a term the operand recognizes but has no rule for**, and is the correct signal for "not mine — let the owner decide."

This is the operand-internal contract and applies to `maknae-authz-basic` and to every extension equally.

### 5. Unknown vocabulary denies, evaluated at the composition layer over the composed union

The authorized vocabulary is **core terms ∪ terms declared by loaded extensions**.

- A request whose action is **outside that union** is **Denied** — explicitly, with its own audit reason, before any operand is consulted.
- A request **inside the union** that a given operand does not own produces `NotApplicable` from that operand, so the owning operand decides.

**The check is hoisted to `Composition`, not duplicated per operand.** One uniform refusal, and no operand needs to know the others' terms.

**The alternative was considered and rejected:** if each operand denied every term outside *its own* vocabulary, deny-overrides would mean `-basic` blocks every extension-contributed term on every request — extensions could never grant anything, contradicting decision 2.

**An extension declares the terms it contributes**, and that declaration is what extends the union.

### 6. The guarantee's scope is this binary

A fork that rewrites the composition root is a different product, and this ADR makes no claim about it. **The guarantee is "this binary," not "any binary"** — which means it rests on artifact integrity, not on authorization design. See [#96](https://github.com/darkhonor/maknae/issues/96) (artifacts ship unsigned) and [#88](https://github.com/darkhonor/maknae/issues/88) (persistent vTPM prerequisite). Stating the scope is part of the decision: an assessor asking *"what if someone modifies it"* is answered by supply-chain and measured-boot controls, not by this contract.

## Consequences

- **`combine` is unchanged** in its classification semantics. *(Corrected 2026-09-02, #181: rule 4 now selects which absence NOTE survives — see the amendment. Every Permit/Deny/Indeterminate outcome is byte-identical.)* The composition semantics were already correct; what was missing was the record of why, and the structural guarantee that the baseline is present to exercise them.

- **The `Composition` type is the implementation.** `ConjunctionAuthorizer` already exists in `compose.rs` (a `Vec<Box<dyn Authorizer>>` folding through `combine`) and is unused at the real call site; it is the starting point, but it **does not** satisfy decision 1 as written, because its operands are homogeneous — the baseline must become a named field.

- **The deny grammar must span the whole action vocabulary — this is the operator's veto and it is currently absent.** If extensions grant into `NotApplicable` space, then `-basic` must be able to deny a term it does not itself implement, or there is no floor under exactly the space extensions operate in. Today the deny grammar is `Read(...)` only: `deny Write(~/.ssh/**)` is not expressible, and `deny terminal.create` is not expressible at all. Tracked with the `Read`→`Write` deny-pairing gate in [#158](https://github.com/darkhonor/maknae/issues/158).

- **The audit record must name the deciding operand.** `Verdict::Permit { obligations }` carries no operand identity, so *"which authorizer granted this?"* is unanswerable from the trail. With one operand that is moot; with two it is the first question asked about a decision an extension made on a model `-basic` cannot see. An ADR-0019 obligation.

- **Extension identity and integrity are TCB facts.** A loaded extension decides authorization. Which extension, what version, and how it was verified are recorded at boot and carried in the trail.

- **The vocabulary is no longer a compile-time closed set.** #67's drift gate asserts a closed 59-term vocabulary. Under decision 5 the **core** vocabulary stays closed and gate-checked; the **composed** vocabulary is core plus declared extension terms and resolves at boot. The gate covers the core set and the declaration mechanism — not the union.

- **Unknown-vocabulary denial needs its own audit reason.** *(LANDED 2026-09-02 via #181 — the reason-enrichment mechanism shipped once, complete: see the amendment below. The reason string for THIS case is pinned there; its membership check awaits the first second-operand integration.)*

- **The whole-vocabulary deny grammar is load-bearing twice over.** It is the operator's floor under attribute-native grants (below), **and** it is what a scoped carve's scope is written in (decision 2a). Until it exists, a carve can only be total. Tracked in [#158](https://github.com/darkhonor/maknae/issues/158); [#165](https://github.com/darkhonor/maknae/issues/165) depends on it for scoped carves and can land total containment without it.

- **The capability deny list is not the complete statement of what is reachable.** Under decision 2, a subject can reach an attribute-native object with **no `-basic` grant at all**. That is ABAC working as ADR-0020 §2 already says it should, but it means the operator's real floor over such objects is the **whole-vocabulary deny grammar** (#158), not the capability `allow`/`deny` lists. Intend this; do not discover it.

- **#154's framing is superseded.** Its body states an extension *"may only ever add denials."* That is corrected by decision 2; the issue's remaining substance — structural non-removability, defining the baseline precisely, and a negative test observed failing — stands.

- **Decision logic implementing this ADR is T1** (95% region floor, zero missed mutants) per [ADR-0016](ADR-0016-risk-tiered-test-coverage.md), and the `negative-control` gate must be **observed failing** with the baseline removed.

## References

- [ADR-0004](ADR-0004-modular-authorization-architecture.md) — modular authorization; the seam this contract governs
- [ADR-0020](ADR-0020-access-control-model-and-vocabulary.md) — deny-overrides and the access-control vocabulary. **Decision 2 above corrects a misreading of its "never waivable" clause AND amends its §3 constraint-only rule** (mandatory operands may now `Permit` on a complete predicate); ADR-0020 carries the reciprocal correction in place, dated
- [ADR-0005](ADR-0005-enforcement-locus-tcb-boundary.md) — sole PDP, TCB boundary
- [ADR-0019](ADR-0019-audit-record-model.md) — audit record model; operand attribution is an obligation against it
- `crates/maknae-security/src/compose.rs` — `combine`, `guarded_decide`, `ConjunctionAuthorizer`
- `crates/maknae-kernel/src/run.rs` (composition call site), `boot_gate.rs` (baseline construction)
- [#154](https://github.com/darkhonor/maknae/issues/154), [#158](https://github.com/darkhonor/maknae/issues/158), [#164](https://github.com/darkhonor/maknae/issues/164), [#181](https://github.com/darkhonor/maknae/issues/181), [#182](https://github.com/darkhonor/maknae/issues/182)
- Operator rulings, 2026-08-29 — quoted verbatim in Context

## Amendment 2026-09-02 (#181): absences carry testimony; the record is true

**What changed and why.** #181 found the vocabulary's recorded contract asserting behaviour that does not occur (54, later 51, manifest rows claiming `NotImplemented` answers; `NoBehaviour` documented as reachable with no operand able to permit it) and four operationally distinct refusals collapsing to one audit string. Three operator rulings (2026-09-01/02) resolved it; this amendment records the contract they produced.

1. **`Verdict::NotApplicable` carries an optional, audit-only note** — testimony the abstaining operand may volunteer about WHY. `None` composes and renders exactly as the historical bare variant (the fallback string is byte-pinned). The note is never an input: no note may influence which branch `combine` takes (pinned by the classification-invariance rows in `golden.rs`), and no note reaches the wire — the wire answer for every refusal stays the static `Unauthorized`.
2. **Ruling R1, scoped:** an UNPERMITTED unbuilt term is wire-indistinguishable from an unauthorized request (the roadmap is not a disclosure surface); a PERMITTED unbuilt term — reachable only via an extension grant under decision 2 — keeps its ratified NOOP answer (`NotImplemented`, posture `not-implemented`). The two rulings compose; neither overturns the other.
3. **The absence-survivor rule:** when all operands abstain, the first annotated absence's note survives; the kernel (the only production composer) passes the baseline's verdict first, so baseline testimony outranks an extension's. When ADR-0008 D1's named-field `Composition` lands, the baseline's note is selected by its field position.
4. **The five annotations `-basic` produces** (role/term tokens only, never paths): `subject resolves to no role`; `role {role}: no rule for {term}` (role-reach, which outranks build-state for non-admin roles); `term enumerated, not implemented: {term}` (admin-visible build-state); `role {role}: no capability entry for {term}` (a grammar absence, distinct from "no rule" — a rule for the term exists, no entry matched).
5. **The unknown-vocabulary reason is pinned here, and the check is deferred with a named owner:** `unknown to the composed vocabulary: {term}`, an explicit **`Deny` at the composition layer, before any operand is consulted** (decision 5 — never a note). It has no carrier while `-basic` is the sole operand (an unknown term cannot decode into `Verb`; ADR-0010 load-refuses unknown grant names). **The first second-operand integration owns building it**, referencing this amendment.
