# ADR-0004: Modular authorization architecture — the `maknae-security` contract and its pluggable `maknae-authz-*` backends

- **Status:** Accepted (operator-directed 2026-08-22; lands via the `docs/adr-registry-cleanup` PR)
- **Date:** 2026-08-22
- **Deciders:** Alex Ackerman (operator)
- **Supersedes:** ADR-0003 (Cedar as the policy engine — *demoted*, not eliminated)
- **Relates to:** ADR-0002 (kernel is Rust — static TCB, extensibility surface = attack surface); ADR-0005 (enforcement locus — `maknaed` is the sole PDP; the caller-supplied attribute bag originates in the untrusted plane); ADR-0020 (access-control model & vocabulary — the RBAC/ABAC/deny-overrides model this contract realizes); ADR-0016 (risk-tiered coverage — the seam and its backends are T1).
- **Source spec:** the CR-converged *Authorization Seam — design* (memory store, 2026-08-09). That spec planned to land as "ADR-0018"; the number 0018 was instead reused for the local-plane-authorization decision, so the seam decision never got its ADR. This is that ADR.

> **Number-reuse note.** ADR numbers are assigned at authoring and freed numbers are reused (registry convention, 2026-08-22). `0004` previously held a *docket reservation* for a storage/label-integrity decision that was never authored; that topic is now tracked as issue #2. The filename and the registry topic are the identity — the bare number is only a handle.

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
- **If it is a mandatory (MAC) operand, be constraint-only and fail closed** — return `Deny` for insufficient/absent authority, otherwise `NotApplicable`, and **never `Permit`.** Granting is the discretionary layer's job. This is the invariant `combine` cannot structurally enforce (its `Vec<Verdict>` cannot tell which operand was mandatory), so it is a backend construction guarantee held by the acceptance tests — and it is what makes "add the DCS backend and no decision gets weaker" true by construction (ADR-0020).
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

## Consequences

- **Positive:** Maknae open-sources with DCS strictly optional; the base build is a functional, fail-closed agent platform with zero classification machinery; **third parties bring their own authorization engine** behind a stable contract; the TCB stays minimal (the seam is a trivially-auditable T1 waist); and the single-oracle correlated-failure risk is dissolved — independence is structural (independent backends composed deny-overrides), not generated from one compiler.
- **ADR-0003 → Superseded (demotion).** Cedar is no longer *the* engine; the bundled default is a native-Rust evaluator over the §8 YAML grammar. Cedar is **preserved** as an optional pluggable `maknae-authz-cedar` backend for deployments whose complexity/verification needs justify it. Superseded as default, not forbidden.
- **`maknae-authz-basic` is unbuilt (#85);** this ADR is its design authority — #85 implements against §5 here, and #77 wires the per-request PDP that calls it.
- **The seam is a compatibility surface.** Because third parties pin it, a change to the `Authorizer` trait / `Request` / `Verdict` / `Obligation` types is a compatibility event — the narrow waist exists precisely so it can stay stable; the `§4` attribute-value enum is the one part marked a revisable starting point, and a change there triggers a re-check of the obligation model.
- **Negative / accepted:** more crates and a seam to maintain; a stringly-keyed attribute boundary (type-safety recovered inside each backend); `maknae-authz-cedar` / `maknae-authz-selinux` are named-but-unbuilt slots (reservations of intent, not code).

## Scope boundary

This ADR fixes the authorization **decision** architecture: the seam contract, the backend family, the reference-backend design, and the requirements for an external author. It does **not** cover the **at-rest / data-layer** enforcement (that is issue #2, the storage/label-integrity decision), the exhaustive `maknae-authz-basic` grammar and action→identity catalog (a follow-on backend spec), or the OS-MAC mapping detail (a follow-on `maknae-authz-selinux` spec). It composes *under* ADR-0020 (which fixes the vocabulary and the no-clearance-bypass invariant) — this ADR realizes that model as crates.

## Security control mapping (informative; per ADR-0001)

| Property | NIST SP 800-53 rev 5 |
|---|---|
| Policy-agnostic seam; sole PDP composes backends; non-bypassable | AC-3; AC-25 (reference monitor) |
| Optional feature-gated backends; base runs least-functionality (no DCS) | CM-7; SA-8 (fail-secure) |
| Deny-overrides; mandatory precedence; no clearance bypass | AC-3(3), AC-3(15) (realizes ADR-0020) |
| Secure-by-default starter policy (least-privilege, egress default-deny, non-removable audit) | AC-6; AU-2 |
| Extensibility surface as a conscious, minimal, auditable contract | SA-8, SA-17 (via ADR-0002) |
| Backend panic-guard; fail-closed totality | SI-11; SA-8 |

## References

Internal: ADR-0002 (Rust kernel / static TCB), ADR-0005 (enforcement locus / sole PDP), ADR-0020 (access-control model & vocabulary), ADR-0016 (risk-tiered coverage). Code: `crates/maknae-security/src/{authorizer,verdict,obligation,request,value,compose}.rs` (the contract as built) and its `tests/golden.rs`. Source spec: *Authorization Seam — design* (memory store, 2026-08-09, CR-converged). External: `darkhonor/rust-dcs` (the native DCS engine reached only through `maknae-authz-dcs`; its doc reconciliation is rust-dcs#22). Issues: #85 (build `maknae-authz-basic`), #77 (wire the per-request PDP). Supersedes ADR-0003 (Cedar policy engine).
