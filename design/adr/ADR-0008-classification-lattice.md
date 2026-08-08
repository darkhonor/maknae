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
2. **Releasability join = intersection; origin always a member.** `⊤` (most restrictive authorable state) = `REL {owners}` = `NoMarking`/NOFORN (origin-only); `⊥` = `REL ALL`/public (join identity); `REL ∅`/absolute-denial is NOT a valid marking (the originator always holds what it created) — `Empty` is retained only as a fail-closed deny-all sentinel (`from_eligible` precondition-violation), never authorable or a lattice point (#51); absent marking → computed `REL {origin}` — NOFORN is national-relative (a US official cannot read AUSTEO; affiliation is not nationality). Eligible **nations** and eligible **coalitions** (non-decomposable tetragraphs like NKIC) are structurally separate namespaces: asserting a trigraph as a coalition membership grants nothing. Canonicalization is unique (`from_eligible`); it is marking-lossy for decomposable tetragraphs (`REL CFCK` derives to `REL KOR`-shaped grants — semantics-preserving; display/serialization form deferred with spec §10). The component-wise ∩ is strictly stronger than `permits(A) ∧ permits(B)` on mixed nation/coalition grants — conservative, fail-closed, deliberate.
3. **`decide(subject, resource, action, purpose, spif)` is a fail-closed conjunction** of gates (policy, level-with-compilation-floor, categories, releasability, action, need-to-know). Degenerate inputs never default open: an unknown level/tag, malformed origin, empty category value-set, or Permissive tag in a label denies (`Indeterminate`); an unregistered REL token is DROPPED from the eligible set (grants nothing — the origin remains eligible, everyone else denies `Releasability`); a SPIF tetragraph expansion is member-shape-validated at build (non-trigraph members are filtered so they can never enter the nations namespace and widen a derivation). **No role or administrative bypass exists.** The principal is polymorphic: human or LLM endpoint, identical treatment.
4. **Compilation-as-floor:** an OCA compilation determination raises the enforced rank (`max(level, compilation)`); it survives derivation (`(Some, None) → Some`, `(Some, Some) → max`).
5. **Derivation-join `∨` is the least upper bound** of the restriction order `⊑` (max rank, ∪ categories, ∩ releasability, ∪ caveats, max compilation). *(The specific universe sizes below are the Stage-1 figures; the current size is 960 — see the #27 and #51 amendments. Reconciling this section's counts is part of the pending ADR consolidation review.)* The §6.1 law suite runs over a 576-label universe with a precise coverage split assessors can rely on: the unary/diagonal laws (reflexivity, idempotence) are checked over all 576 and the pairwise laws (antisymmetry, commutativity, absorption, upper-bound, dominance monotonicity `r1 ⊑ r2 ∧ Permit(r2) ⟹ Permit(r1)`, releasability-never-widens) EXHAUSTIVELY over the full 576²; the triple-quantified laws (transitivity, associativity, leastness) run over a stride-13, 45-label subsample whose full-axis coverage is asserted (the assertions, not the stride, are the guarantee) — with anti-vacuity guards on the implication-shaped laws. Honesty note: the suite's semantic equality (`sem_eq`) is a structural equality that models the mutual-`⊑` quotient — a decidable proxy for it, not literally `le(a,b) ∧ le(b,a)`; it catches quantifier-direction and polarity bugs, not antisymmetry per se, which is near-definitional under a self-consistent `⊑`. `⊑`/`∨` fail closed (`None`) on the same dimensions `decide()` denies: cross-policy, cross-origin (derivation deferred), malformed origin, unregistered/Permissive/empty-valued tags — plus, for `∨` only, differing need-to-know (no upper bound; `⊑` instead compares such pairs `Some(false)`, since they lie inside its domain, per the total-∨/partial-derive split below).
6. **Ingest validation:** `validate_rel` rejects duplicative REL sets (`REL TO USA, GBR, FVEY` invalid — GBR ∈ FVEY) with the origin exempt (`REL TO USA, FVEY` valid, per the DCS reference). The tetragraph-vs-tetragraph overlap clause is **Maknae-local strictness beyond the DCS reference**, computed on `expansion ∖ {origin}`; non-decomposable tokens are excluded (membership unknowable ⇒ duplication undetectable). The JOINT co-owner exception is out of MVP scope. This crate provides the predicate; the enforcement locus is kernel ingest / `maknae-spifc`. A `validate_categories` sibling (empty-value-set ingest check) is a recorded kernel-ingest follow-up.
7. **Label origination (spec §2.7, in-scope per the topology ADR):** per entry path — retrieval takes the lake authority-map default; operator conversational input inherits a session floor **bounded above by the operator's own attributes** (a meet/clamp, not a join — explicitly KERNEL-side; this crate ships the derivation-join only); import without signed classification is refused/quarantined. **Labels only rise via join; there is no automated downgrade** — lowering is an out-of-band, signed, audited authority action (closes the `downgrade-path-unspecified` disposition).

### Recorded MVP simplifications (open questions)

- `DisplayOnly` permits `Read`/`Display` and blocks only `Export`; for an LLM-endpoint principal, read-into-context is a copy — revisit.
- Scalar `need_to_know`: equal tokens join; DIFFERING tokens fail the join closed (`None`) — a scalar cannot represent both requirements, and keeping either would grant access to the other source's material and break the upper-bound property (codex finding, remediated). A set-valued NTK is the follow-up that would make such joins representable.
- `NoEgress`/`OperatorOnly` are carried (∪-joined), enforced by kernel hooks, not the read decision.
- No ingest-time nations registry: a typo'd trigraph fails closed at decide time only.
- `restrictive_dominates` is exported with vacuous-⊇ empty-required semantics; callers outside `decide()` must precheck (the gate-3 pattern).

### Issue #6 disposition

Closes the two lattice findings (`releasability-antitone-dominance`, `dominance-vs-membership-conflation`) and brings the label-origination model in-scope (§2.7 above). `downgrade-path-unspecified` is closed by the no-automated-downgrade invariant; `floating-label-creep` relocates to the write-path/HWM sibling ADR. Hence **Refs #6**, not Closes.

## Consequences

- Every enforcement surface consumes ONE tested lattice instead of re-implementing dominance (the RL#2 correlated-failure finding is answered by exhaustive verification of the single source, with per-consumer golden-vector suites as the diversity layer).
- Correctness preconditions and owners: authentic inputs → ADR-0014/kernel; correct SPIF → governance; write-path/*-property → sibling ADR. This engine is only as good as its inputs; those boundaries are named, not hidden.
- Serialization, STANAG-4778 binding, SPIF generation, and cross-origin derivation are deferred (spec §10) and gate later component work.

## Amendment — EPIC #33 Stage 1: marking-completeness vocabulary (2026-08-05)

The Lake marking-policy sweep showed the v1 model (single `origin`, one
releasability relation, bare Permit/Deny, 3-variant `Affiliation`) is
insufficient across five axes; all are Day-1 (operator directive). Stage 1
lands the SHARED VOCABULARY (spec `~/claude-memory/maknae/specs/2026-08-04-marking-completeness-design.md`,
CR-converged round 11 + operator-reviewed); the six issues extend it in later
stages. Status stays **Proposed** pending the full Day-1 slate.

- **Ownership axis (#25):** `origin: String` → `Ownership` enum, 3 variants
  Day-1: `Owned{owner}`, `Joint{owners}` (≥2), `ConcealedForeign{custodian}`
  (the `//FGI` no-codes form; custodian-implicit baseline per V2 §4.e). The
  earlier `ConcealedAsUs` variant is DROPPED (operator Q1): wholly-US-marked
  data reaches the engine as `Owned{USA}`. Stage 1 wires only `Owned` at
  `decide()`; Joint/ConcealedForeign fail closed (Indeterminate) until Stage 5.
- **Dual-relation disclosure (#26/#27):** `Disclosure{release, display:Option, exclusions}`
  subsumes v1 releasability; `display ⊇ release`; NAF exclusions (#26) carried
  Day-1, enforced Stage 2.
- **Controls product-of-chains lattice (#27):** closed `ControlMarking` enum +
  `Controls` (four 3-element precedence chains × powerset). This AXIS operation
  (`Controls::join`) is unconditionally total, associative, and
  **validity-agnostic** — it never returns `Option`; mutual-exclusion rejection
  lives in `validate_label`, never in `∨`.
- **Total-∨ / partial-derive split (the hard-won result) — stated precisely for
  assessors (per lattice-math review):** the per-axis join operations
  (`Controls::join`, `Disclosure::join`, releasability `∩`) are unconditionally
  total. The composite `ResourceLabel::join` (`∨`) is **partial**, and its
  `None` arises from two mathematically distinct sources assessors should not
  conflate:
  - **Frame boundary (policy, ownership).** Policy and ownership partition the
    label space: same-policy and same-ownership are equivalence relations, so
    distinct policies or owners are elements of *different* lattice frames with
    no join between them. `∨` returns `None` here as a DOMAIN-of-definition
    refusal — mirroring v1's cross-origin refusal — not a validity check.
    Within a fixed frame `∨` is total, which is what §5's law suite sweeps.
  - **No upper bound (need-to-know).** NTK is deliberately NOT described as a
    frame axis, because it is not one: NTK-compatibility is not transitive
    (`None ∨ OPLAN` and `None ∨ CONPLAN` both resolve, yet `OPLAN ∨ CONPLAN`
    does not), so it cannot partition the space into equivalence classes, and
    `⊑` carries no NTK guard — cross-NTK pairs sit *inside* the order's domain
    and compare as `Some(false)`, where cross-policy / cross-ownership poison
    `⊑` to `None`. Cross-NTK `∨` returns `None` because a scalar NTK token
    cannot hold two differing requirements at once: the pair has **no upper
    bound**, so `None` is the unique correct result — the textbook partial
    join-semilattice case, provable directly from the token algebra (a stronger
    claim than any frame narrative).
  The distinct **VALIDITY** result stands apart from both: validity refusals
  (exclusion pairs, §2.6 couplings) must live in `validate_label` / `derive`,
  never inside `∨` — a validity-`None` inside a binary `∨` is absorbing and
  would break associativity; neither a frame-boundary `None` nor a
  no-upper-bound `None` does. `derive = validate_label ∘ ∨` is where every
  `None` surfaces (the frame and no-upper-bound `None` originating in `join`,
  the validity `None` in `validate_label`); `decide()` consumes only `derive`.
- **Decision-with-obligations (#27):** `Decision::PermitWithObligations`;
  closed `Obligation` enum + `⊑_obl` refinement order (type shell Day-1;
  emission Stage 3, when `Caveat` retires into `Obligation`).
- **Subject employment (#29):** `Employment` (5 variants) is the public
  attribute; `Affiliation` remains internal predicate currency until Stage 5.
  `Subject` gains `list_memberships` (#30).
- **List-control (#30):** `CategoryKind::ListControlled` (gate-3 →
  Indeterminate Day-1; list semantics Stage 5). `Legal Privilege` is a data
  CATEGORY (CUI Registry), NOT an `ATTORNEY_*` access predicate.
- **SPIF constraints + offline CUI registry (#31 / spec §6):** `Spif` gains
  `home_nation`, `expandable_for_rollup`, and an optional loaded `CuiRegistry`.
  The registry is a dated, provenance-stamped, line-oriented **`.tsv`**
  snapshot (zero-dep; JSON avoided) the binary carries via `include_str!` for
  the air-gapped target — the engine never fetches; a maintenance tool
  refreshes it. ENUM-VS-DATA line: algebra-bearing controls are the closed
  `ControlMarking` enum; the ~125 Registry-delegated CUI categories + LDC
  strings are DATA. Stage 1 lands the loader + `is_known_*` API + the loader's
  fail-closed (empty/malformed → `Err`); `validate_label` enforcement is
  Stage 4. Grounded in EO 13556 + 32 CFR § 2002.16/§ 2002.4 (Lake).
- **Proof:** the v1 576-label law suite is preserved (migrated; now 960 — see #27/#51 amendments); a v2-axes
  sweep (controls × display × exclusions) checks the pairwise laws over the full
  168² and associativity `(a∨b)∨c ≈ a∨(b∨c)` over a coverage-asserted stride
  subsample, establishing `∨` total AND associative over the fixed-ownership
  sublattice (sweep operands carry singleton/empty controls; multi-atom control
  sets arise only as join outputs — per-chain max + set-union is associative by
  construction); plus `derive` fail-closed targeted vectors.
- **Coverage:** `ownership.rs`, `controls.rs`, `registry.rs` join the T1 tier +
  ratchet cohort (ADR-0016).

### Stage-1 scope: what this crate decides, and what is staged

**The engine is an adjudicator, not a classifier.** `maknae-dcs-core` renders a
permit/deny decision over a label it is handed and the requesting subject's
attributes; it never assigns, rewrites, or infers a label's markings. Its only
judgment about the label itself is well-formedness for the system it represents.
Origin is taken faithfully from the source data — the engine assumes no primary
nation and no US-first releasability posture. A `SECRET // {JPN origin} //
REL JPN, AUS` label is ordinary, and a US subject is denied against it as the
plain result of the release set, not a special case. Effective releasability and
access vectors are computed internally to reach a decision and are never returned
or attached to the resource; how a label is carried on or parsed from a resource
— frontmatter, a first-line-of-text string, any other carrier — is other crates'
concern.

**Staged enforcement — this PR lands the vocabulary; named issues implement it:**

- **Control axis → #27.** The `ControlMarking` product-of-chains axis is landed
  vocabulary that `decide()` does not yet consult. Access-affecting controls are
  enforced through the paths `decide()` already reads — the `Caveat`
  action-blockers and releasability — which are authoritative until #27 wires
  control-axis enforcement and retires `Caveat` into `Obligation`. A control
  expressed only on the `ControlMarking` axis is not yet an enforced access
  constraint; authors must not rely on it for a decision until #27. DISPLAY ONLY
  in particular is not a single blocked action but a constraint on who may
  *operate* a terminal holding the data versus who may only *view* it under
  accompaniment by an owner or releasee — its model is #27's to define.
- **Co-ownership → #40.** A `Joint` (multi-origin) label validates as well-formed,
  but `decide()` fails closed on it today (gate 4 denies any non-`Owned`
  ownership, with a pinning test), and the disclosure algebra over co-owners is
  superseded wholesale by #40. There is no live false-permit for co-owned data;
  the honest multi-origin evaluation — each co-owner eligible to data it
  co-produced, unioned with the release set — is #40's work.
- **Second eligibility relation (Display) → #27.** `Action::Display` is gated by
  release eligibility today; the distinct display-eligibility relation
  (`display ⊇ release`) lands with #27.

Each of these is a fail-closed or explicitly documented boundary, never an open
default.

## Amendment — EPIC #33 Stage 2: NOT AUTHORIZED FOR enforcement (#26, 2026-08-06)

Stage 1 carried the NAF exclusion vocabulary decide-inert; Stage 2 makes it LIVE
releasability policy (spec `~/claude-memory/maknae/specs/2026-08-05-issue-26-not-authorized-for-exclusions-design.md`,
CR-converged). The engine implements POLICY (DoDM 5200.01 V2 §e, IC Register 2016,
CJCSI 2015.01A) — never the interpreted `dcs-schema-migration.md`. Status stays
**Proposed** pending the full Day-1 slate.

- **Expand-or-deny releasability (§3).** Every coalition tetragraph is decomposed
  to its member nation trigraphs IN-MEMORY from a global versioned registry, or
  the request is `Deny`. The engine has a COMPLETE world view: a trigraph that is
  not an ISO-3166 nation, or a non-trigraph that is not a registered coalition, is
  `InvalidElement` — the engine never adjudicates on an element it does not
  recognize. Decomposition is domain-specific and never leaves the engine (the
  protective measure); eligibility is decided by `nationality ∈ (resolved ∖ X)`.
- **Removal of the coalition-credential arm.** `EligibleNations` collapses to a
  SINGLE nation namespace; `permits` takes only a nationality. A subject's asserted
  coalition memberships are no longer consulted — coalition eligibility is resolved
  at expansion time, not by a held credential.
- **Subtraction, not a lattice axis.** NAF exclusions are subtracted from the
  RESOLVED release set inside `eligible_release` (release-relation only;
  `eligible_display(None)` tracks the subtracted release; an explicit display grant
  is untouched — display-side NAF is #27). The retained-exclusions axis of
  `Disclosure::le`/`join` is REMOVED: two disclosures with equal resolved release/
  display are `⊑` both ways regardless of raw exclusion markings, and `join`
  consumes the subtraction into the narrower release (joined exclusions = ∅).
- **Two-locus enforcement (§5).** `validate_label` is the ingest predicate
  (`Result<(), LabelInvalidity{Element,Label}>`, for ALL ownership incl. Joint) and
  `decide()` gate-4 re-runs it as defense-in-depth (single-origin `Owned`; Joint/
  ConcealedForeign already short-circuit to `Indeterminate`). New `DenyReason`
  variants `InvalidElement`/`InvalidLabel`; reasons stay existence-agnostic.
- **Owner never excluded (§6).** An owner/co-owner in the exclusion set is
  `InvalidLabel`, asserted on single-origin AND multi-origin Joint labels.
- **Versioned `data/*.json` registries.** ISO-3166 nations, coalition tetragraphs
  (UNCK = CJCSI 2015.01A + Germany = 18, FVEY, NATO), and the FULL DoD CUI registry
  (archives.gov), each with its own JSON Schema, compiled into the binary by one
  `build.rs` (source-only; a malformed source FAILS THE BUILD — the cross-validation
  of every coalition member against ISO-3166 supersedes the runtime widen-guard).
- **AuditRecord + classified-coalition non-disclosure (§8).** A pure `audit()`
  returns a record carrying the UNEXPANDED presented label and the existence-
  agnostic decision — no expanded-roster field exists to leak, so membership (or
  lack thereof) in a classified coalition is structurally undisclosable; no secure
  channel is needed.

**Policy basis — a NAF's validity is NOT gated on classification LEVEL (settled; do not re-litigate).**
`validate_label` requires a NAF exclusion to accompany a NAMED (`Grant`) release
— an exclusion needs a positive grant to except a member from; a restriction on
`Public`/`Empty`/`NoMarking` (an all/none/origin marking) is structurally
contradictory. It deliberately does NOT require the resource to be a classified
LEVEL, because the governing policy does not support that for the #26 release
relation:
- **`REL TO` applies to CUI as well as classified.** DoDI 5200.48 (`520048p.md:728,746`):
  "REL TO … [applies] to information properly categorized as CUI … (b) DoD
  operational CUI (not related to intelligence) may be marked as REL TO." CUI
  (unclassified) legitimately carries dissemination controls — 32 CFR 2002.4(dd)
  (`:466`) defines Limited Dissemination Controls as CUI-EA-approved controls for
  CUI dissemination. So a release-side NAF (which subtracts from a `REL TO` grant)
  is valid on CUI; a classification-level gate would WRONGLY reject valid CUI NAF
  labels (this was a reverted implementation over-reach — codex-r1 proposed it,
  codex-r2 caught the unsound "rank 0 = unclassified" heuristic; `Spif::levels`
  promises only low→high ordering, so rank cannot identify "classified").
- **The classified-only level restriction belongs to DISPLAY ONLY (#27), not #26.**
  DoDM 5200.01 V2 §e (`520001m_vol2.md:5494,5503`): DISPLAY ONLY "identifies
  CLASSIFIED information …" and "may be used with TOP SECRET, SECRET or
  CONFIDENTIAL." When #27 lands the display relation, its DISPLAY ONLY validity
  MUST gate on classification ∈ {CONFIDENTIAL, SECRET, TOP_SECRET} — which is an
  explicit level set, NOT a rank heuristic, and therefore needs `Spif` support to
  declare which levels are classified (an unclassified-floor / classified-set
  declaration the model does not yet carry — a #27 dependency). **RESOLVED by #27
  (below):** `SpifBuilder::classified_floor` + `Spif::is_classified` (US floor =
  CONFIDENTIAL); the equivalence of `rank ≥ floor` to the explicit set holds under
  the top-contiguity of US classified levels, and fail-closed-on-unknown-rank is
  the safety net — NOT the reverted rank heuristic (this is a within-SPIF floor
  test on the resource's own classification, not a cross-releasability comparison).
- **"NOT AUTHORIZED FOR" is not a CAPCO/IC-Register formal marking** (operator-
  confirmed); it is Maknae's subtractive qualifier on a `REL TO`/`DISPLAY ONLY`
  grant, so its classification scope is INHERITED from the control it qualifies
  (REL TO → classified+CUI; DISPLAY ONLY → classified-only), never intrinsic.

**Supersessions of the Stage-1 record (four):**
1. RETRACT the §2 mixed-grant "nation ∩ coalition" intersection claim (`:19`): there
   is one nation namespace; coalitions decompose to nations before any `∩`.
2. SUPERSEDE the §3 unknown-token-DROP simplification (`:20`): an unknown/
   unexpandable token is now `Deny` (`InvalidElement`) at both loci, not a silent
   drop.
3. SUPERSEDE the "nation/coalition namespaces structurally separate" clause (`:19`):
   the credential arm is removed; there is a single namespace.
4. SUPERSEDE the "NAF carried Day-1, enforced Stage 2 / no ingest registry"
   simplification (`:31`, `:59-61`): the CUI `.tsv` + `CuiRegistry`/`is_known_*` +
   the per-SPIF `Spif.registry` are RETIRED for the compiled `data/*.json`
   registries; NAF is now enforced.

## Amendment — EPIC #33: multi-origin (JOINT co-ownership) evaluation (#40, 2026-08-07)

Stage 1 recognized co-ownership as a well-formed marking but failed closed on it
(`decide()` denied `Indeterminate`; the lattice ops refused `None`). #40 makes
co-owned labels EVALUABLE.

- **Co-owner-union eligibility.** The resolved eligible nation set for a co-owned
  label is `(release-expansion) ∪ (all co-owners)` minus NAF exclusions (#26,
  release relation only). Each co-owner is eligible to data it co-produced, in
  addition to the release set. Flagship: `JOINT SECRET USA, KOR // REL FVEY` →
  `{USA, KOR, AUS, GBR, CAN, NZL}`.
- **Origin-as-a-set.** `Releasability::eligible`/`from_eligible` take the OWNER SET
  (`&BTreeSet<String>`), replacing the single-origin scalar; `Disclosure::origin_of`
  (the `|base| ≠ 1 → deny-all` guard) is RETIRED at the `Releasability::eligible`
  layer — any non-empty owner set resolves there. `decide()` gate 4 then enforces
  ownership WELL-FORMEDNESS per variant: `Owned` = exactly 1, `Joint` = ≥2
  co-owners (its documented invariant); a directly-constructed singleton/empty
  `Joint` is malformed → `Deny(Indeterminate)` (fail closed, as every `Joint` did
  before #40). Single-owner is the exact special case `owners = {origin}`, so every
  v1 single-owner law/vector is unchanged.
- **`Joint` un-gated at `decide()` gate 4.** Gate 4 evaluates `Owned` AND `Joint`
  (`ownership.base_set()`); `ConcealedForeign` still fails closed (Stage-5,
  custodian-routed / OwnerConsent semantics deferred). The two-locus `validate_label`
  is owner-set-aware, so co-owner-in-NAF is `InvalidLabel` at BOTH ingest and decide
  (owner-never-excluded now reaches decide for Joint).
- **Co-owned lattice proof.** The exhaustive law suite gains a co-owned frame sweep
  (`Joint{USA,KOR}`, 168²). Its NAF axis names only NON-OWNER nations — a NAF on a
  co-owner is `InvalidLabel`, not a lattice point; sweeping it would make
  `from_eligible`'s `owners ⊆ nations` map lossy and break idempotence/associativity
  (the same "validity-invariant → not a lattice point" discipline as #26's SF2). A
  machine-checked guard asserts no swept label NAFs a co-owner.

- **`validate_rel` co-owner exemption (#25 closeout).** The ingest anti-duplication
  predicate generalizes `origin: &str` → the owner SET: both clauses compute on
  `expansion ∖ owners`, so a CO-OWNER may appear in `REL TO` even when a listed
  tetragraph covers it (`REL TO USA, KOR, FVEY` on `JOINT{USA,KOR}` is valid),
  un-deferring the JOINT co-owner exception. Single-owner is `owners = {origin}`.

**Supersessions:** the Stage-1 `|base| ≠ 1 → deny-all` posture and the "Joint fails
closed until Stage 5" notes are superseded — `Joint` is now evaluated; only
`ConcealedForeign` remains Stage-5. With this + PR #46, the full **#25** JOINT
co-ownership deliverable (model + evaluation + validate_rel) has landed.

## Amendment — EPIC #33: DISPLAY ONLY + Obligation unification (#27, 2026-08-07)

Stage 1 landed the display relation and the `Obligation` type-shell decide-inert;
#27 makes DISPLAY ONLY a LIVE decision and retires the entire v1 `Caveat` concept
into a single, unified handling vocabulary.

- **DISPLAY ONLY is the display-eligibility RELATION, not a carried marking.** The
  display-only band = `display-eligible ∖ release-eligible` (nations that may VIEW
  but not RECEIVE). The `decide()` release/display matrix: release-eligible →
  full access; display-only band → `PermitWithObligations{DisplayOnly}` on
  `Display`, `Deny(Releasability)` on `Read`/`Export`; neither → `Deny`. The owner
  is always release-eligible (owners-always-member, #40), so it is STRUCTURALLY
  never in the display-only band — satisfying the IC-Register "USA is not on the
  DISPLAY ONLY list" rule with no extra check.
- **PDP/PEP + deny-biased contract.** The engine (PDP) EMITS the obligation; the
  normative deny-biased contract (a PEP that cannot enforce an obligation MUST
  treat the decision as `Deny`) is how the autonomous-agent case resolves to deny
  at the PEP. The engine stays principal-agnostic.
- **`Caveat` retired into one `Obligation` vocabulary.** The `Caveat` enum, the
  `ResourceLabel.caveats` field, `decide()` gate-5 (`DisplayOnly`+`Export` →
  `ActionForbidden`), and `DenyReason::ActionForbidden` are all REMOVED.
  `ResourceLabel.obligations: BTreeSet<Obligation>` now carries the handling
  markings `{NoEgress, OperatorOnly}` (kernel-hook-enforced, passed through to the
  emitted set); `DisplayOnly` is DECISION-DERIVED, never carried — `validate_label`
  enforces the carriable allow-list at both loci. The obligation model relocated
  to the `label` layer (co-located with `ResourceLabel`) for the eventual #44
  label-crate extraction (`decide` depends on `label`, not the reverse).
- **Obligations lattice axis.** The v1 caveats subset-axis of `⊑`/`∨` moves to the
  `⊑_obl` refinement order (`obligations_refine`): `self ⊑ other` iff self's
  carried obligations are weaker-or-equal to other's; `∨` = the ⊑_obl LUB
  (set-union for the carried atoms). The exhaustive law universe grows to 1152 (→ 960
  under #51, which drops the non-authorable `REL ∅` from the rel axis) over
  the `{∅, {NoEgress}, {OperatorOnly}, {both}}` axis; antisymmetry is proven over
  this atom-only universe (raw-`BTreeSet` `⊑_obl` is not antisymmetric once
  `OriginatorControlled{scope}` enters — #48 must canonicalize first).
- **`classified_floor` (per-SPIF).** `SpifBuilder::classified_floor` +
  `Spif::is_classified` (fail-closed on undeclared floor / floor-not-a-level /
  unknown rank). A non-empty display-only band requires `is_classified(level) ==
  Some(true)` (DoDM V2 §e — DISPLAY ONLY is classified-only); the release-side NAF
  remains level-agnostic (#26). No policy literal in `is_classified` — it reads the
  per-SPIF floor.
- **Initial state + extensible architecture (the distinguishing element).** This
  implementation — and every current EPIC #33 issue — is US-classification-system
  ONLY. The core is policy-parameterized: levels, categories, coalition rosters,
  the classified floor, and the very EXISTENCE of a marking like DISPLAY ONLY are
  supplied as consumed SPIF/registry DATA, with no policy constant in a decision
  path. Other national systems are future DATA (#41 cross-system floors, #45
  cross-system correlation), NEVER a core rewrite. Both the US-initial state AND
  this data-parameterized extensibility are recorded here as the engine's
  distinguishing (potentially patentable) characteristic.

**Supersessions:** the Stage-1 "`Caveat` retires into `Obligation` at Stage 3 /
gate-5 `DisplayOnly`-blocks-`Export` stays live" notes (`:97-99`, `:145-149`) and
the "classified floor is a #27 dependency the model does not carry" note (`:227-234`)
are superseded — the retirement and the floor are landed.

**Deferred:** ORCON obligation emission → #48; cross-system correlation → #45;
`ConcealedForeign` decide semantics → Stage-5; document-marking-string
interpretation → the #44 interpretation/carrier crate.

## Amendment — releasability ⊤ correction (#51, 2026-08-08)

The original #6 design assigned the releasability ⊤ to `REL ∅` ("releasable to
none, including the origin" — absolute denial) to obtain a bounded lattice. That
is not a valid state in any information-security policy: the originator always
holds what it created. Under the **origin-always-member** invariant (`owners ⊆ E`
for every valid eligible set), the most-restrictive *reachable* state is
`{owners}` = `NoMarking`/NOFORN — the true ⊤. `REL ∅` is never authorable and
never derivable (intersection of owner-containing sets retains the owners).

- **⊤ corrected** to `{owners}` (`NoMarking`); ⊥ unchanged (`Public`).
- **`Empty` demoted** to a fail-closed deny-all sentinel — the value
  `from_eligible` returns on a precondition violation (an eligible set missing an
  owner). Not authorable: `validate_label` rejects `release == Empty` /
  `display == Some(Empty)` at both loci (`InvalidLabel`). Not removed (the
  fail-closed path needs a deny-all `Releasability` more restrictive than
  `NoMarking`; a pure/total function cannot panic — same "valid computational
  value, invalid authored label" discipline as the frame/validity split).
- **Law universe** drops `Empty` (1152→960); the rel-axis ⊤ is `NoMarking`.

**Supersedes** Decision item 2's original "`⊤` = explicit `REL ∅`" (corrected in
place above). ADR-0008 is Proposed / not final; this is pre-approval refinement.
This targeted fix is NOT the pending ADR consolidation review (separate task).

## Amendment — ORCON obligation emission (#48, 2026-08-08)

PR #39 landed the `ControlMarking`/`Controls` vocabulary but deliberately did not
wire the control axis into `decide()`. #48 wires it (US classification system only;
policy-parameterized). Validated against the Lake (IC Register 2016; DoDM 5200.01-V2).

- **Emission (decision-derived).** `decide()` reads the canonical `resource.controls`
  and emits `Obligation::OriginatorControlled { scope }`: `Orcon` → `scope: None`;
  `OrconUsGov` → `scope: Some(RedisseminationScope::UsGov)`. `OriginatorControlled`
  is **decision-derived** (emitted, like `DisplayOnly`), NEVER carried — so the
  carried-obligations lattice axis is unchanged (stays atom-only), and the #27
  antisymmetry caveat ("`⊑_obl` non-antisymmetric once `OriginatorControlled{scope}`
  enters a carried set") is **resolved by construction**: it never enters a carried
  set, and canonical `Controls` holds ≤1 ORCON-family marking so the emitted set has
  ≤1 `OriginatorControlled`. ORCON emission is **action-independent** (unlike
  `DisplayOnly`). Composes with `DisplayOnly` + carried obligations in one set.
- **Precedence.** `ORCON > ORCON-USGOV` (IC Register :7229/:7392/:7407) is the
  existing `CHAINS` entry `(Orcon, OrconUsGov)` (Orcon dominant); `Controls`
  canonicalization reduces a commingled set to `{Orcon}` → emits `scope: None`.
- **Validity (`validate_label`, both loci).** ORCON/ORCON-USGOV are **incompatible
  with RELIDO** → `InvalidLabel` (Register :7225/:7388 — "May not be used with
  RELIDO"; RELIDO delegates release to an SFDRA, ORCON reserves it to the
  originator). ORCON/ORCON-USGOV are **classified-only** → `InvalidLabel` when
  `!is_classified` (Register :7222; DoDM :5323 — TS/S/C), reusing #27's per-SPIF
  `classified_floor` (fail-closed; no US constant).
- **`RedisseminationScope::UsGov` scope (Register :7341).** Pre-approved further
  dissemination WITHOUT originator approval to US Government Executive Branch
  departments/agencies (unconditional); and to congressional Intelligence
  Committees ONLY for disseminated analytic products (DAPs — not raw/unevaluated
  intelligence), per originating-agency/OLA consultation. Other US recipients still
  require originator approval. The engine emits the scope token; the PEP honors the
  precise contours (deny-biased: cannot obtain originator approval → Deny).
- **System-residency resolved as PEP handling, NOT an engine obligation.** ORCON-USGOV
  "may not reside in / transit unclassified systems" (Register :7423) is stated as a
  property of the marked information; the issue's Boundary lists "system gating" as
  *how a PEP honors an obligation*. The engine — a pure PDP with no knowledge of the
  execution system's classification — emits `OriginatorControlled{Some(UsGov)}`
  (which represents the whole ORCON-USGOV marking); the PEP that honors it MUST
  satisfy the system-residency constraint (deny-biased). A machine-explicit
  no-unclassified-systems obligation is a possible future refinement, out of #48.

**Deferred / flagged:** `ControlMarking::{NoEgress, OperatorOnly}` duplicate
`Obligation::{NoEgress, OperatorOnly}` (PR #39 controls vocabulary vs #27 carried
obligations) — `decide()` emits these from the carried `obligations` field; the
`ControlMarking` variants are vestigial for emission. Out of #48 scope; candidate
cleanup. RELIDO emits nothing (read only for the ORCON exclusion). US-initial +
extensible reaffirmed. ADR-0008 remains **Proposed / not final** (no consolidation
until the whole epic is done).

## Security control mapping (informative; per ADR-0001)

Assessor framing: the engine upgrades the evidence class for access-enforcement from procedural attestation to mechanized proof — the lattice laws and fail-closed totality are exhaustively machine-checked in CI (`cargo test --workspace`). The mutation gate (spec §6.5, surviving mutants are release blockers) is a WIRED CI CONTROL as of ADR-0016: the change-gated mutation job runs `cargo mutants` on this crate for every PR touching it and unconditionally on merge to main.

| Concern | Engine property | NIST SP 800-53 rev 5 | Authoritative guidance |
|---|---|---|---|
| Access enforcement | `decide()` deny-by-default conjunction; no bypass | AC-3; AC-3(11) (restrict access per security attributes) | Bell-LaPadula; DoD ZT RA v2.0 |
| Information flow | Releasability ∩-join; derivation labels only rise | AC-4; AC-4(1) (security attributes); AC-4(3) | STANAG 4774; E.O. 13526 §1.7 compilation |
| Security attributes | STANAG-4774-shaped label; SPIF-owned category kinds | AC-16; AC-16(6) (attribute association) | ADatP-4774 §4.2/Table 7 |
| Reference monitor | Pure/total/side-effect-free; exhaustively law-checked | AC-25 (always invoked, tamper-resistant, small enough to analyze) | NIST SP 800-53; DoD ZT RA |
| Transmission of attributes | Label carried with resource through derivation | SC-16; SC-16(1) | STANAG 4778 (binding → ADR-0007) |
| Verification | Exhaustive law suite (currently **960**-label — see #27/#51 amendments; was 576 at Stage 1) + golden vectors (CI); mutation gate wired in CI (ADR-0016 change-gated job, zero missed) | SA-11; SA-11(1) | The crate's `tests/` + `.github/workflows/ci.yml` `mutation` job |

The full control matrix belongs in the RMF package, not this ADR.

## References

Source spec (memory store) §2, §3, §5, §6, §9, §10, §11; `design/references/dcs-schema-migration.md` (REL TO validation, UNCK membership); Security-MCP `adr-004-layered-enforcement-model`; ADR-0005 (enforcement locus), ADR-0007 (binding, owed), ADR-0014 (subject context, owed); issues #6, #15, #18.
