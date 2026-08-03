# ADR-0008: Classification lattice & dominance engine — typed categories, intersection releasability, fail-closed reference monitor

- **Status:** Proposed (implemented in `crates/maknae-dcs-core`; awaiting operator ratification)
- **Date:** 2026-08-04
- **Deciders:** Alex Ackerman (operator), Byeori (Claude Fable 5, pair)
- **Addresses:** review issue github.com/darkhonor/maknae#6 (lattice definition — releasability join), raised by an independent reviewer
- **Source spec:** `~/claude-memory/maknae/specs/2026-08-03-adr-0008-classification-lattice-design.md` (converged through the team's critical-review loop: 5 rounds on the spec, 8 rounds on the implementation plan)
- **Grounded in:** STANAG 4774 (ADatP-4774 confidentiality label syntax; category typing per §4.2/Table 7 — the dominance-boolean provenance derives from this typing plus the Security-MCP `adr-004` layered-enforcement analysis; ADatP-4774.1 citation-hardening is a recorded follow-up), the DoD/NATO policy stack (E.O. 13526, DoDM 5200.01, DoDI 5200.48, ICD 710), Bell-LaPadula for the formal frame.

## Context

Issue #6 identified that a naive Bell-LaPadula treatment of releasability is *inverted*: combining `REL AUS` and `REL KOR` material must produce something MORE restrictive than either (releasable to the origin alone), not the union `REL AUS, KOR`. The lattice definition is the semantic foundation every enforcement surface (kernel hooks, RLS, egress screen) consumes; getting its polarity wrong once propagates everywhere.

## Decision

One STANAG-4774-shaped label per resource: one ordinal `Classification` + **typed categories** + releasability + caveats + compilation-level + need-to-know. The engine is `maknae-dcs-core`: std-only (zero dependencies), pure/total/side-effect-free, `#![forbid(unsafe_code)]`.

1. **Typed categories decide the satisfaction rule.** The SPIF (a consumed Tier-0 input; generation is #18/sibling scope) declares each tag `Restrictive` (containment: read-ins ⊇ values), `RestrictivePredicate` (attribute predicate; LDC closed list = {FEDCON, FED_ONLY}, unknown → deny — resolves spec §11 Q3), `Permissive`, or `Informative` (ignored). Category *kind* lives in the SPIF, not on the label — labels carry bare tag→values maps and cannot self-assert their satisfaction rule (a deliberate divergence from the spec-§5 sketch; value-domain structure is likewise collapsed into the SPIF, with SCI hierarchy as path-encoded opaque nodes where exactness *is* the rule — `SI` does not contain `SI//G` — resolving spec §11 Q2).
2. **Releasability join = intersection; origin always a member.** `⊤` = explicit `REL ∅` (deny-all incl. origin); `⊥` = `REL ALL`/public (join identity); absent marking → computed `REL {origin}` — NOFORN is national-relative (a US official cannot read AUSTEO; affiliation is not nationality). Eligible **nations** and eligible **coalitions** (non-decomposable tetragraphs like NKIC) are structurally separate namespaces: asserting a trigraph as a coalition membership grants nothing. Canonicalization is unique (`from_eligible`); it is marking-lossy for decomposable tetragraphs (`REL CFCK` derives to `REL KOR`-shaped grants — semantics-preserving; display/serialization form deferred with spec §10). The component-wise ∩ is strictly stronger than `permits(A) ∧ permits(B)` on mixed nation/coalition grants — conservative, fail-closed, deliberate.
3. **`decide(subject, resource, action, purpose, spif)` is a fail-closed conjunction** of gates (policy, level-with-compilation-floor, categories, releasability, action, need-to-know). Degenerate inputs never default open: an unknown level/tag, malformed origin, empty category value-set, or Permissive tag in a label denies (`Indeterminate`); an unregistered REL token is DROPPED from the eligible set (grants nothing — the origin remains eligible, everyone else denies `Releasability`); a SPIF tetragraph expansion is member-shape-validated at build (non-trigraph members are filtered so they can never enter the nations namespace and widen a derivation). **No role or administrative bypass exists.** The principal is polymorphic: human or LLM endpoint, identical treatment.
4. **Compilation-as-floor:** an OCA compilation determination raises the enforced rank (`max(level, compilation)`); it survives derivation (`(Some, None) → Some`, `(Some, Some) → max`).
5. **Derivation-join `∨` is the least upper bound** of the restriction order `⊑` (max rank, ∪ categories, ∩ releasability, ∪ caveats, max compilation). Proven exhaustively over a 576-label universe: reflexivity, antisymmetry, transitivity, commutativity, associativity, idempotence, absorption, upper-bound, leastness, dominance monotonicity (`r1 ⊑ r2 ∧ Permit(r2) ⟹ Permit(r1)`), and releasability-never-widens — with anti-vacuity guards on the implication-shaped laws (transitivity, leastness, monotonicity). Honesty note: the suite's semantic equality (`sem_eq`) is definitionally the mutual-`⊑` quotient — deliberate; it catches quantifier-direction and polarity bugs, not antisymmetry per se, which is near-definitional under a self-consistent `⊑`. `⊑`/`∨` fail closed (`None`) on the same dimensions `decide()` denies: cross-policy, cross-origin (derivation deferred), malformed origin, unregistered/Permissive/empty-valued tags.
6. **Ingest validation:** `validate_rel` rejects duplicative REL sets (`REL TO USA, GBR, FVEY` invalid — GBR ∈ FVEY) with the origin exempt (`REL TO USA, FVEY` valid, per the DCS reference). The tetragraph-vs-tetragraph overlap clause is **Maknae-local strictness beyond the DCS reference**, computed on `expansion ∖ {origin}`; non-decomposable tokens are excluded (membership unknowable ⇒ duplication undetectable). The JOINT co-owner exception is out of MVP scope. This crate provides the predicate; the enforcement locus is kernel ingest / `maknae-spifc`. A `validate_categories` sibling (empty-value-set ingest check) is a recorded kernel-ingest follow-up.
7. **Label origination (spec §2.7, in-scope per the topology ADR):** per entry path — retrieval takes the lake authority-map default; operator conversational input inherits a session floor **bounded above by the operator's own attributes** (a meet/clamp, not a join — explicitly KERNEL-side; this crate ships the derivation-join only); import without signed classification is refused/quarantined. **Labels only rise via join; there is no automated downgrade** — lowering is an out-of-band, signed, audited authority action (closes the `downgrade-path-unspecified` disposition).

### Recorded MVP simplifications (open questions)

- `DisplayOnly` permits `Read`/`Display` and blocks only `Export`; for an LLM-endpoint principal, read-into-context is a copy — revisit.
- Scalar `need_to_know` join keeps self's token on conflict (non-commutative for differing tokens; a set-valued NTK is the follow-up).
- `NoEgress`/`OperatorOnly` are carried (∪-joined), enforced by kernel hooks, not the read decision.
- No ingest-time nations registry: a typo'd trigraph fails closed at decide time only.
- `restrictive_dominates` is exported with vacuous-⊇ empty-required semantics; callers outside `decide()` must precheck (the gate-3 pattern).

### Issue #6 disposition

Closes the two lattice findings (`releasability-antitone-dominance`, `dominance-vs-membership-conflation`) and brings the label-origination model in-scope (§2.7 above). `downgrade-path-unspecified` is closed by the no-automated-downgrade invariant; `floating-label-creep` relocates to the write-path/HWM sibling ADR. Hence **Refs #6**, not Closes.

## Consequences

- Every enforcement surface consumes ONE tested lattice instead of re-implementing dominance (the RL#2 correlated-failure finding is answered by exhaustive verification of the single source, with per-consumer golden-vector suites as the diversity layer).
- Correctness preconditions and owners: authentic inputs → ADR-0014/kernel; correct SPIF → governance; write-path/*-property → sibling ADR. This engine is only as good as its inputs; those boundaries are named, not hidden.
- Serialization, STANAG-4778 binding, SPIF generation, and cross-origin derivation are deferred (spec §10) and gate later component work.

## Security control mapping (informative; per ADR-0001)

Assessor framing: the engine upgrades the evidence class for access-enforcement from procedural attestation to mechanized proof — the lattice laws and fail-closed totality are exhaustively machine-checked in CI (`cargo test --workspace`). The mutation gate (spec §6.5, surviving mutants are release blockers) is run locally at release points and is OWED as a wired CI step — recorded follow-up, not yet an in-place CI control.

| Concern | Engine property | NIST SP 800-53 rev 5 | Authoritative guidance |
|---|---|---|---|
| Access enforcement | `decide()` deny-by-default conjunction; no bypass | AC-3; AC-3(11) (restrict access per security attributes) | Bell-LaPadula; DoD ZT RA v2.0 |
| Information flow | Releasability ∩-join; derivation labels only rise | AC-4; AC-4(1) (security attributes); AC-4(3) | STANAG 4774; E.O. 13526 §1.7 compilation |
| Security attributes | STANAG-4774-shaped label; SPIF-owned category kinds | AC-16; AC-16(6) (attribute association) | ADatP-4774 §4.2/Table 7 |
| Reference monitor | Pure/total/side-effect-free; exhaustively law-checked | AC-25 (always invoked, tamper-resistant, small enough to analyze) | NIST SP 800-53; DoD ZT RA |
| Transmission of attributes | Label carried with resource through derivation | SC-16; SC-16(1) | STANAG 4778 (binding → ADR-0007) |
| Verification | 576-label exhaustive law suite + golden vectors (CI); mutation triage local-only, CI wiring owed | SA-11; SA-11(1) | The crate's `tests/` + `.github/workflows/ci.yml` |

The full control matrix belongs in the RMF package, not this ADR.

## References

Source spec (memory store) §2, §3, §5, §6, §9, §10, §11; `design/references/dcs-schema-migration.md` (REL TO validation, UNCK membership); Security-MCP `adr-004-layered-enforcement-model`; ADR-0005 (enforcement locus), ADR-0007 (binding, owed), ADR-0014 (subject context, owed); issues #6, #15, #18.
