# ADR-0004: Modular authorization architecture — the `maknae-security` contract and its pluggable `maknae-authz-*` backends

- **Status:** Accepted (operator-directed 2026-08-22; lands via the `docs/adr-registry-cleanup` PR)
- **Date:** 2026-08-22
- **Deciders:** Alex Ackerman (operator)
- **Supersedes:** ADR-0003 (Cedar as the policy engine — *demoted*, not eliminated)
- **Relates to:** ADR-0002 (kernel is Rust — static TCB, extensibility surface = attack surface); ADR-0005 (enforcement locus — `maknaed` is the sole PDP; the caller-supplied attribute bag originates in the untrusted plane); ADR-0020 (access-control model & vocabulary — the RBAC/ABAC/deny-overrides model this contract realizes); ADR-0016 (risk-tiered coverage — the seam and its backends are T1).
- **Amended:** 2026-08-29 by [ADR-0008](ADR-0008-authorization-composition-contract.md) (operator-ratified) — the backend requirement below that a mandatory (MAC) operand be *constraint-only* and **never `Permit`** is **superseded**. See the corrected bullet in Decision.
- **Source spec:** the CR-converged *Authorization Seam — design* (memory store, 2026-08-09). That spec planned to land as "ADR-0018"; the number 0018 was instead reused for the local-plane-authorization decision, so the seam decision never got its ADR. This is that ADR.

> **Number-reuse note.** ADR numbers are assigned at authoring and freed numbers are reused (registry convention, 2026-08-22). `0004` previously held a *docket reservation* for a storage/label-integrity decision that was never authored; that topic is now tracked as issue #2. The filename and the registry topic are the identity — the bare number is only a handle.

> **Amendment (2026-08-26, operator-ratified — the #85 v0.1 supersessions).** `maknae-authz-basic` now exists, and its v0.1 deliberately supersedes parts of this ADR for the MVP north star (single-operator deployment; schema stays 1; spec: `2026-08-26-maknae-authz-basic-design.md`, memory store). Clause-by-clause: **(a)** §5's signed Tier-0 `policy/baseline.yaml` + audited `grants.d/` overlay, the `ask` tier, `subjects:` conjunctive matchers, `when:` clauses, and the starter-policy tool/egress vocabulary → ONE unsigned schema-1 `authz.yaml` carrying the existing `Read`/`Bash` grammar plus a role→member `bindings:` key (proximity/usability ruling: role membership lives beside the grants it references). §5's fuller shape remains the growth target. **(b)** §2's `role`/`destination` basic-backend subject keys → **`uid`** (the authenticated datum, per ADR-0018's "the per-request authorization principal is that uid") plus the reserved subject-name token `agent` for the runtime. **(c)** §3's "deterministic" MUST is scoped: the decision core is deterministic w.r.t. (policy-bytes, request); the composed `decide()` re-reads the policy file per request by operator ruling (Zero Trust — a containment edit bites on the next request), so verdicts vary across policy edits by design. **(d)** §5's "grammar owned by this backend" → the grammar and `bindings` *parse* live in `maknae-config` (its grammar-not-decision boundary); the backend owns role semantics and the verdict. **(e)** The role vocabulary is four shipped, code-defined roles — `admin`/`user`/`guest`/`adversary` (`adversary` = on-demand containment: deny-all; `guest` = liveness-only) — with yaml-defined custom roles deferred post-v1.0. **Retained in full:** the non-removable `audit` obligation on every `Permit`; the §3 matcher invariant (missing attribute = failed-to-evaluate → `Indeterminate`, golden-vectored in the backend); the seam contract itself, unchanged. **ADR-0018 reconciliation:** its "per-uid allowlist is not adopted" decision governs *connection admission*, which is unchanged; uid-keyed request `bindings` are the per-request authorization its own §Scope boundary explicitly defers to this work. The Consequences bullet and the AC-6/AU-2 control-mapping row below are edited to match this amendment.

## Context

Maknae is going open-source, and the DCS classification engine was in-housed to a separate private library (`rust-dcs`, ADR-0008/0017 relocated) so that Maknae depends on it **optionally**. That optionality has to be real, not aspirational: a build with no classification machinery in the tree must still be a functional, secure-by-default agent platform, and a `--features dcs` build must route the *same* enforcement calls to the classification engine without the open surface ever learning a DCS-shaped concept.

The broader intent this ADR records: **authorization in Maknae is engine-agnostic and third-party-extensible.** A third party integrating Maknae into their own agent environment must be able to **replace or add** an authorization backend — Cedar, OPA, a bespoke evaluator, their own classification engine — behind a single, stable contract, without touching Maknae's core or the seam. The contract is the only sacred surface.

The failure this forecloses: leaving "Cedar decides everything" (ADR-0003) on the books while the implementation moved to a native, pluggable seam invites exactly the currency drift — and the single-oracle correlated-failure risk — that the design reviews flagged. The engine choice and the module boundaries are a security-relevant architecture decision (ADR-0002: every extensibility surface is attack surface) and must be recorded as one, self-contained enough that an **external author** can implement against it without access to Maknae's private design notes.

## Decision

### 1. A narrow-waist seam, not an engine

`maknae-security` is a tiny, zero-dependency crate (`std`-only, `#![forbid(unsafe_code)]`, ADR-0016 T1) that defines the authorization contract in **general security vocabulary only**. It is the one crate everything depends on and that depends on nothing. The kernel (`maknaed`, the sole PDP per ADR-0005) holds a backend behind this seam and composes verdicts; it never embeds a policy language.

**Acceptance test for the seam surface (the openness invariant):** no DCS-shaped concept — lattice, clearance, releasability, tetragraph — may appear on it. If one does, optionality is broken. The seam owns the *container*; a backend owns the *vocabulary*.

### 2. The contract (normative — what any backend implements)

```rust
pub trait Authorizer {
    fn decide(&self, req: &Request) -> Verdict;   // object-safe, total
}
```

- **Inputs — `Request { subject, resource, action, context }`.** `subject`/`resource`/`context` are opaque **typed attribute bags** (`AttrValue = Str | Int | Bool | Set<String>`); `action` is a name. Keys are general strings; only the backend knows domain keys exist (`role`/`destination` for basic; `classification`/`rel_to` for DCS). Type-safety on domain attributes is recovered *inside* the backend — that is the price of agnosticism.
- **Output — the four-valued `Verdict`:** `Permit { obligations } | Deny { reason } | NotApplicable | Indeterminate`. `Default` is `NotApplicable`, which finalizes to `Deny` — a defaulted verdict is never a fail-open.
- **Composition — deny-overrides + indeterminate-blocks + `NotApplicable`-identity** (`compose::combine`, order-independent):
  1. any `Deny` → `Deny`;
  2. else any `Indeterminate` → `Deny` — **never masked by a peer `Permit`** (deliberately stronger than XACML deny-overrides, which would fail open here);
  3. else any `Permit` → `Permit` with the **union** of Permit obligations, deduped by full `(id, params)`; a same-`id`/different-`params` conflict → `Deny` (opaque tokens are unrankable at the seam);
  4. else (all `NotApplicable` / empty) → `NotApplicable`.
- **Finalization is fail-closed:** at the kernel→PEP boundary `finalize` collapses anything not `Permit` to `Deny`. The public decision is binary `Permit | Deny`; verdict richness is internal to composition.
- **Obligations are opaque `{id, params}` tokens.** The seam never interprets them; the PEP holds a handler registry keyed by `id`, and an **unrecognized or undischargeable obligation ⟹ the PEP fails closed.** Obligations are never advisory.
- **The host guards the boundary:** a backend that panics is caught (`guarded_decide`) and converted to `Indeterminate → Deny`, so a buggy or hostile backend can neither crash the PDP nor bypass composition.

### 3. Requirements for a backend author (the guide)

A conforming `impl Authorizer` — bundled, feature-gated, or third-party — **MUST**:

- **Be total and deterministic.** Always return a `Verdict`; never leave ambiguity as "allow." Backend error, missing/indeterminate attributes, or an unresolvable predicate → `Deny` (or `Indeterminate`, which finalizes to `Deny`). Do not rely on the host panic-guard for correctness — treat it as a backstop, not a control-flow path.
- **If it is a mandatory (MAC) operand, fail closed, be always composed, and grant only on a COMPLETE predicate** — return `Deny` when its predicate fails (clearance absent or insufficient, releasability not satisfied, need-to-know absent), `NotApplicable` when it **cannot fully evaluate**, and `Permit` **only when its whole predicate is satisfied**. **Clearance alone is never a grant.** These are invariants `combine` cannot structurally enforce (its `Vec<Verdict>` cannot tell which operand was mandatory), so they are backend construction guarantees held by the acceptance tests. What "add the DCS backend and no decision gets weaker" means is that **no peer `Deny` can be overridden** (ADR-0020 §3, deny-overrides) — not that no `Permit` can be introduced.

  **Corrected 2026-08-29 by [ADR-0008](ADR-0008-authorization-composition-contract.md) (operator-ratified).** This bullet previously required a mandatory operand to be *constraint-only* and **never `Permit`**, on the reasoning that "granting is the discretionary layer's job." **That reasoning assumed permit-by-default with mandatory controls subtracting, which is backwards for a deny-by-default system.** It made an **attribute-native grant** undecidable by any operand: a cleared FVEY national reading `SECRET//REL USA, FVEY` gets `NotApplicable` from `maknae-authz-basic` (releasability is not expressible in the capability grammar) and `NotApplicable` from a constraint-only mandatory operand, composing to a `Deny` of an entitled subject. See ADR-0008 decision 2 and ADR-0020's amendment banner for the full case. The guard against granting on **partial** evaluation is now ADR-0008 decision 4, **no operand may fail open**.
- **Honor the matcher invariant:** a *missing* attribute is a **failed-to-evaluate**, never a false non-match. A matcher that silently returns "false" on absent input re-opens a deny-suppression fail-open. Golden vectors MUST exercise a missing-attribute input, not only an unresolvable reference.
- **Keep the seam clean:** emit only opaque obligation ids the deployment's PEP registry can discharge; never leak domain vocabulary onto the seam surface.
- **Meet ADR-0016 T1** (95% production-region coverage + mutation-clean); the fail-closed edge catalogue (source spec §15.4) is the language-neutral golden-vector set.

### 4. The backend family is open — `maknae-authz-*`, backend-plural

The waist is deliberately plural: additional backends slot in behind the *same* `Box<dyn Authorizer>` seam with **no seam change**. The kernel composes whatever is present (`ConjunctionAuthorizer` folds N operands: `DCS_MAC ∧ OS_MAC ∧ DAC`).

| Crate | Role | Compiled |
|---|---|---|
| `maknae-security` | the seam (contract + types), zero-dep | always |
| **`maknae-authz-basic`** | bundled default — RBAC/allowlist, owns its YAML grammar | **always** — the `dac` operand in *both* builds |
| `maknae-authz-dcs` | adapter over the external `rust-dcs` engine (ABAC/classification) | `dcs` feature |
| `maknae-authz-cedar` | *optional* Cedar backend — for deployments wanting its language / static analysis / formal verification | opt-in |
| `maknae-authz-selinux` | *optional* OS-MAC oracle (SELinux/MLS), degrades to `NotApplicable` off-SELinux | detect / opt-in |
| **any third-party `impl Authorizer`** | **whatever engine an integrator wants to build into their agent environment** | their choice |

This is the intent in one line: **a third party can replace the default backend or add their own, using any engine, and Maknae's core does not change.** The bundled default is `maknae-authz-basic`; everything else — including Maknae's own DCS adapter — is just another consumer of the same contract.

### 5. `maknae-authz-basic` — the reference design (guides #85's build and outside authors)

`maknae-authz-basic` is the always-compiled, secure-by-default DAC backend and the worked example every other author can read:

- **Deny is the ground state.** Unknown subject, unmatched action, malformed config → deny. "Functional" ≠ "allow-by-default."
- **A signed baseline + audited overlay.** `policy/baseline.yaml` (Tier-0, signed, immutable — changes arrive as signed commits) whose **denies are an absolute ceiling** over an append-only, audited `policy/grants.d/` overlay of learned "always" grants. Precedence: `deny (baseline ∪ overlay) → ask-unresolved → allow/grant → default-deny`.
- **YAML grammar (owned by this backend, loaded fail-closed via `maknae-config`):** the atom is `action(specifier)` sorted into `allow`/`deny`/`ask`; `subjects:` conjunctively match to flat `roles:` (no match → no roles → deny); **global deny-overrides, order-independent, no admin bypass**; a `when: { attr: matcher }` clause covers the relational/ABAC cases (`resource.owner: "${subject.id}"`); obligations attach to `allow`/`ask` and union with a non-removable `audit`.
- **Secure-by-default starter policy** (least-privilege, standards-shaped — OWASP LLM Top 10 esp. LLM06 Excessive Agency, NIST AC-6): the owner gets a *named minimal* tool set (never `tools: *`), **egress default-deny** with an explicit host allowlist, and the non-removable `audit` obligation.
- **`ask` is not a third decision** — it resolves to `Permit { require-approval(scope) }`, an obligation discharged by an async human-approval loop *below* the seam (the seam stays synchronous and total); no channel / no approver / timeout ⟹ undischargeable ⟹ deny.
- **Learning is DAC-under-MAC:** in a non-DCS build an "always" grant may live-persist to the overlay (audited); under `--features dcs`, runtime overlay writes are disabled entirely — every change is a propose→authority-ratify→signed-commit, and every grant is re-checked against live MAC at each use.

### 6. The contract is version-controlled

`maknae-security` is a **semver-versioned crate**, and the contract it publishes — the `Authorizer` trait plus the `Request` / `Verdict` / `Obligation` / `AttrValue` types — is its public API under that semver. A breaking change to the contract is a **major version bump and a compatibility event**, held to the same discipline as the `maknaed`↔`maknae` protocol (AGENTS.md, *protocol/daemon-contract discipline*): third parties **pin a contract version**, and the narrow waist exists precisely to keep major bumps rare. The **§2** attribute-value enum (`AttrValue`) is the surface most likely to move — it is a revisable starting point; a change there is at minimum a minor bump and triggers a re-check of the obligation model, whose params ride on that same enum (also §2). The intent is explicit: **stop the goalposts moving** — an external backend author builds against a pinned, stable contract version, not a shifting surface.

## Consequences

- **Positive:** Maknae open-sources with DCS strictly optional; the base build is a functional, fail-closed agent platform with zero classification machinery; **third parties bring their own authorization engine** behind a stable contract; the TCB stays minimal (the seam is a trivially-auditable T1 waist); and the single-oracle correlated-failure risk is dissolved — independence is structural (independent backends composed deny-overrides), not generated from one compiler.
- **ADR-0003 → Superseded (demotion).** Cedar is no longer *the* engine; the bundled default is a native-Rust evaluator over the `maknae-authz-basic` YAML grammar (§5). Cedar is **preserved** as an optional pluggable `maknae-authz-cedar` backend for deployments whose complexity/verification needs justify it. Superseded as default, not forbidden.
- **`maknae-authz-basic` is BUILT (#85, 2026-08-26)** against this ADR as amended above (v0.1 supersessions recorded in the Amendment block); #77 wires the per-request PDP that calls it *(as-built 2026-08-28: the request path landed — per-request `combine`+`finalize` through the seam, with the read PEP; #77 closed with that PR)*. §5's baseline/overlay/`ask`/`subjects:`/`when:` shape remains the growth target, not the shipped v0.1.
- **The pattern generalizes.** The seam contract is version-controlled (Decision §6). And this *stable, versioned contract + swappable implementation* shape is Maknae's **template wherever a component has a genuine substitution axis** — other components adopt the same modular, seam-based approach **where appropriate** (a standing preference guiding design, not a mandate to modularize everything). If this graduates to a cross-cutting rule, its home is AGENTS.md core principles.
- **Negative / accepted:** more crates and a seam to maintain; a stringly-keyed attribute boundary (type-safety recovered inside each backend); `maknae-authz-cedar` / `maknae-authz-selinux` are named-but-unbuilt slots (reservations of intent, not code).

## Scope boundary

This ADR fixes the authorization **decision** architecture: the seam contract, the backend family, the reference-backend design, and the requirements for an external author. It does **not** cover the **at-rest / data-layer** enforcement (that is issue #2, the storage/label-integrity decision), the exhaustive `maknae-authz-basic` grammar and action→identity catalog (a follow-on backend spec), or the OS-MAC mapping detail (a follow-on `maknae-authz-selinux` spec). It composes *under* ADR-0020 (which fixes the vocabulary and the no-clearance-bypass invariant) — this ADR realizes that model as crates.

## Security control mapping (informative; per ADR-0001)

| Property | NIST SP 800-53 rev 5 |
|---|---|
| Policy-agnostic seam; sole PDP composes backends; non-bypassable | AC-3; AC-25 (reference monitor) |
| Optional feature-gated backends; base runs least-functionality (no DCS) | CM-7; SA-8 (fail-secure) |
| Deny-overrides; mandatory precedence; no clearance bypass | AC-3(3), AC-3(15) (realizes ADR-0020) |
| Secure-by-default shipped policy (least-privilege deny-list; non-removable audit obligation on every Permit; starter-policy tool/egress vocabulary deferred per the 2026-08-26 amendment) | AC-6; AU-2 |
| Extensibility surface as a conscious, minimal, auditable contract | SA-8, SA-17 (via ADR-0002) |
| Backend panic-guard; fail-closed totality | SI-11; SA-8 |

## References

Internal: ADR-0002 (Rust kernel / static TCB), ADR-0005 (enforcement locus / sole PDP), ADR-0020 (access-control model & vocabulary), ADR-0016 (risk-tiered coverage). Code: `crates/maknae-security/src/{authorizer,verdict,obligation,request,value,compose}.rs` (the contract as built) and its `tests/golden.rs`. Source spec: *Authorization Seam — design* (memory store, 2026-08-09, CR-converged). External: `darkhonor/rust-dcs` (the native DCS engine reached only through `maknae-authz-dcs`; its doc reconciliation is rust-dcs#22). Issues: #85 (build `maknae-authz-basic`), #77 (wire the per-request PDP). Supersedes ADR-0003 (Cedar policy engine).

> **Amendment (2026-08-29, #67) — the `Bash` capability is retired from the grammar.** The 2026-08-26 amendment's clause **(a)** names "the existing `Read`/`Bash` grammar"; the grammar is now **`Read` only**. `Bash(argv)` parsed and loaded but was inert (`maknae_config::Request::Bash` was never constructed), making it a second way to express execution authority in competition with #67's `terminal.*` action class — which is itself blocked on the parked execution-isolation ruling. Retiring rather than freezing it collapses the two-vocabulary problem instead of managing it, and argv matching is a categorically harder and more dangerous matching problem than the path globs this grammar was built for. **Consequence:** a policy carrying `Bash(...)` is now a fail-closed boot refusal. Nothing shipped uses it (`packaging/common/authz.yaml` carries `Read` patterns only), so the break costs nothing at this point in the project's life and is deliberately taken pre-1.0. The non-resource capability form that #67's D3 requires for individually-decidable `admin.*` authority will add to this grammar; `Request`/`Pattern` therefore remain enums rather than collapsing to structs.
