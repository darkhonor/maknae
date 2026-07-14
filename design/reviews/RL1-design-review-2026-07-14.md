# Maknae Design Corpus — Convergent Review Loop RL#1 (audit mode)

| | |
|---|---|
| **Reviewer** | Rook (orchestrator) — external audit for @darkhonor, operator-steered by @ChukusMooticus |
| **Mode** | Audit (read-only; findings + hand-off recommendations, no edits to the corpus) |
| **Date** | 2026-07-14 |
| **Scope** | `README.md`, `design/knowledge-lifecycle-contract.md` (KLC v0.2), `design/container-architecture.md`, `design/reference-implementation-autopsy.md`, `design/adr/ADR-0001..0003` |
| **Method** | 9-dimension parallel fan-out → dedup → adversarial per-finding verification. Dimensions: 7 Claude lenses (trust-model, MLS/BLP, lifecycle, cross-doc, control-map, lake-alignment, feasibility) + **Codex** (cross-model) + **baseline-xcheck** (against the operator's two independent hardened-baseline repos for the same upstreams). Each surviving finding attacked by an independent skeptic tasked to refute. |
| **Corpus commit** | `5e76b96` (HEAD at review time) |

> This is **RL#1**. It is not a convergence claim — see §6. In audit mode the loop bottoms out at *"hand-off recommendation complete,"* and the next round fires only after the author responds to the redesign recommendations, not against the unchanged corpus.

---

## 1. Executive summary

The corpus is a genuinely strong piece of security architecture — the deny-by-default thesis, the DCS-labels-travel-with-data model, the autopsy's evidence discipline, and the assessor-honest control-mapping framing are all doing real work. The review nonetheless surfaced **72 confirmed findings** (22 blocker, 44 should-fix, 5 discussion, 1 nit; 5 findings refuted, 7 nits passed through). That count is not 72 independent problems. The adversarial verifiers, working blind to each other, kept naming the **same two structural root-cause classes** in different words. Everything actionable collapses into them:

- **Class A — Enforcement asserted without a trust-plane locus** (22 findings, **11 blockers**). The contract repeatedly names a security property but the mechanism that would enforce it either lives in the **untrusted plane** or is not specified. This is the load-bearing finding of the review.
- **Class B — Two-representations drift** (25 findings, 7 blockers). The same rule or fact is stated in more than one place — the KLC §10 hook table vs the §15 invariants vs the surrounding prose; ADR status vs README prose; SVG captions vs resolved text; maknae's summary of the lake model vs the actual ADR-0004 — and the copies have diverged. This is precisely the "two representations that must agree" divergence class.

Both are **redesign classes, not patch lists**: you do not fix 22 instances of Class A by hardening 22 spots; you kill the class by making the kernel the integrity root for all label/tier state and moving every disclosure/derivation decision into the trust plane. You do not fix Class B by re-syncing copies; you kill it by declaring a single source of truth for each fact and pointing everything else at it.

The remaining families (MLS/BLP label-model gaps, key/signature model, control-mapping accuracy, scope realism, missing failure-mode/threat register) are genuine and mostly targeted fixes, several of them ADR-worthy.

**One positive result worth recording:** the baseline-xcheck dimension **corroborated every checkable autopsy §2–§5 claim** about the two upstreams' trust models and the overlay ceiling, against two *independent* hardening efforts (finding #71). The autopsy argues from evidence, and the evidence holds — with one sharpening: the overlay *floor* the baselines actually achieved is higher than the §5 record alone implies, which narrows maknae's true differentiator to the **semantic/epistemic governance layer** (tiers, corroboration, provenance) rather than the mechanical hardening layer. That is an argument *for* the project, precisely scoped.

---

## 2. Root-cause Class A — enforcement asserted without a trust-plane locus

The architecture's whole claim is *"a small, auditable trust plane mediates every action … with the agent runtime treated as untrusted by design"* (README §1) and *"the runtime plane cannot perform a transition, only request one"* (KLC §3). Class A is every place the corpus states a property the kernel must guarantee while the *actual data path or write path lives in the untrusted plane, or is unspecified.* The whack-a-mole tell: the verifiers independently relocated 22 distinct findings to one of a handful of synonymous phrasings — *"enforcement stated without a locus," "kernel-attributed enforcement whose data path executes in the untrusted plane," "PDP decision inputs sourced from less-trusted planes without kernel verification," "trusted-plane gates conditioned on untrusted-plane semantic judgments."*

The sharpest instances (blocker IDs from the docket, §4):

- **B1 — the corpus's own volume table encodes the bypass.** `container-architecture.md §4`: `lake-data | lake (rw), dreamer (rw), kernel (label verification, ro)`. Both writers are "Untrusted by design" (§2); the kernel is *read-only* on the files whose YAML frontmatter **is** the tier state. Signatures are required only for `tier ≤ 1` (KLC §6), so a compromised lake edits `tier: 3 → 2` in frontmatter — gaining "may inform work" standing — with no hook transit, no audit event, and no signature to fail. The authority-config volume got the D17a "directory boundary IS the control" treatment (`changes arrive as signed commits, not writes`); the governed corpus, whose tier labels are policy-bearing hook-B inputs, did not.
- **B2 — the core BLP disclosure gate runs in the untrusted lake.** `§3.5` gives the untrusted lake "per-subject filtered context assembly"; `§6.3` lets the hook-B hot path run as "local bindings" inside it. The mechanism behind *"content the subject cannot see never enters the context serving them"* is a runtime-plane container holding all data at all classifications. This is the exact placement both hardened baselines rejected (*"Nothing inside the agent process constitutes containment"*).
- **B3 — skill execution without hook F.** The runtime's `ro` mount on `skill-registry` prevents modification, not disclosure or execution: it can read and run skill code without transiting hook F.
- **B4 — the gateway is a third architecture-defeating container.** It asserts operator identity for the entire ABAC/BLP model and is externally connected, yet principle 1 names only kernel + egress-proxy as architecture-defeating. Gateway compromise = subject impersonation = total bypass.
- **B21 / B22 — the derived-only lock has a forgeable input, and the promotion gate rubber-stamps the untrusted requester.** `issuance_type` (half the key that derives `nature` → `tier_ceiling`) is "authored at ingest" with no map binding, a self-served ceiling raise that honors the lock in letter. Several §9 promotion criteria ("agrees," "dedup complete," "confirmed across sessions") are semantic judgments only the untrusted dreamer can make, so hook D's "criteria of §9 met" is unimplementable by the kernel without an attestation model.

**Redesign recommendation (kills the class):** adopt a single principle and thread it through every hook — *the kernel is the integrity root for all label/tier/classification state, at every tier, and no trust-plane property may depend on state the untrusted plane can write undetected or on a judgment the untrusted plane self-asserts.* Concretely:

1. **Kernel-anchored label integrity at all tiers** — kernel-signed/HMAC'd frontmatter or a kernel-held tier ledger/hash index, stamped at every A/C/D transition and verified at every B/C/D read, so a runtime-plane frontmatter edit is *detected as forgery* (not just prevented by a mount that isn't there). Or remove the `rw` mounts and broker all lake/dreamer writes through a kernel API.
2. **Disclosure and execution gates in the trust plane** — kernel bulk-decision with verify-on-delivery, or a trusted retrieval broker with the lake demoted to a dumb store; "local bindings" reclassified as a *performance pre-filter whose output the kernel re-verifies.* Skills retrieved through the kernel with hook F before content reaches the runtime.
3. **Attestation model for semantic gate criteria** — partition every §9 criterion into kernel-verifiable vs dreamer-attested; attested claims must carry kernel-checkable evidence (corroboration claims name the corroborating object IDs so the kernel mechanically verifies issuer-distinctness and lineage-disjointness); attestation-only Tier-1 promotions fall back to operator sign-off.
4. **Bound gateway trust** — either admit it to the TCB and review it to trust-plane standard (amending principle 1), or make operator credentials kernel-verifiable so gateway compromise degrades to DoS + channel exposure, with an authentication-strength floor as a function of the deployment lattice.

This is **ADR-0004 (storage/label integrity model)** plus **ADR-0005 (enforcement-locus / TCB boundary)** in the docket below. It is the single highest-value change in the review.

---

## 3. Root-cause Class B — two-representations drift

The corpus's own doctrine (autopsy's convergent-review lineage) is *read reality, don't reconstruct it; two representations that must agree ARE the divergence class.* The document set violates it internally. The dominant sub-pattern is the **KLC §10 hook table vs §15 invariants vs §6 prose** stating derivation rules three times and disagreeing:

- **B13** — hook C's normative row omits the classification high-water-mark stamp and handling-caveat propagation that §6 and §15 assign to it. An implementer coding from the hook table ships without the confidentiality half of derivation and launders `no-egress` caveats.
- **B20 / #19** — the 2→1 corroboration rule is stated twice with different bars (§9.1 requires a ceiling-1 corroborator; §11.2 accepts any "authorized source"), and §9.1 cites §14 Q8 as an "independence definition" while Q8 is an **explicitly unresolved open question** ("Operator: undecided").
- **B16** — `all_new_knowledge_enters_at_tier: 3` is contradicted by Tier-0 authoring (§7) and §12 signed-tier import, with no stated exemption.

The **cross-document** and **lake-alignment** instances are the same class at document scale:

- **#42 / #45 / #46 / #47** — decision status desynced: the autopsy still lists the kernel language as open ("Rust/Go candidates") while ADR-0002 (Accepted) and README §4 ratify Rust; container-architecture marks the egress-proxy "Proposed" while ADR-0002 ratifies it; the Q5 spike shape drifts across four docs; Cedar "Python bindings" are stated as existing in one doc and absent in the ADR that doc cites.
- **#43** — the `tier-state-machine.svg` caption, embedded directly under the KLC §5 resolution callout, still carries the v0.1 instruction *"Tier names are placeholders — align with Knowledge Lake authority hierarchy during review"* — instructing the exact action the resolution rejected.
- **#55 / #56 / #57 / #58** — maknae's summary of the inherited lake model has drifted from the real ADR-0004 (available locally): the `(band,nature) → tier_ceiling` projection is presented as inherited but ADR-0004 defines **no ceiling concept** (it is maknae's own bridge invention, unmarked); "distinct controlling natures stack" misstates ADR-0004 D9 (stacking is between *registers*, not natures); the cross-peer surfacing predicate is quoted in its **pre-amendment** form (ADR-0004's #297 amendment replaced "no connecting edge" with connected-component semantics); the README calls the lake a "four-tier authority hierarchy" — the superseded ladder ADR-0004 explicitly replaced with a peer DAG.

**Redesign recommendation (kills the class):** declare a single normative source for each fact and make every other mention a pointer, not a copy.

1. **The KLC §10 hook table + §15 invariants are the canonical enforcement spec.** §6 prose and §11 guardrails *point at* them; they never restate rules. Every rule the guardrails describe must appear as a hook-table row and a §15 invariant, and nowhere else in imperative form. (Fixes B13, B16, B20, and the whole "guardrail-prose vs gate-table" cluster.)
2. **ADRs own decision status; README/KLC/autopsy prose references the ADR, never restates the ruling.** A living document (the autopsy) states open items *by pointing at the ADR's Status field*, so "Accepted" in one place cannot coexist with "open" in another. (Fixes #42, #45, #46, #47.)
3. **Diagrams regenerate from a source that lives beside the doc they annotate**, so a resolved decision can't survive in an SVG caption. (Fixes #43.)
4. **Every claim about the inherited lake model cites the ADR-0004 element it inherits, and every place maknae *extends* the model says so explicitly** ("maknae extension, not inherited"). The ceiling projection is the flagship example — it is a fine idea, but it is maknae's, and presenting it as inherited is the drift. (Fixes #55–#58.)

This is **ADR-0006 (single-source-of-truth doctrine for the corpus)** in the docket.

---

## 4. Blocker docket (22)

Root-cause class in brackets: **[A]** enforcement-locus, **[B]** two-representations, **[D]** MLS/BLP model, **[E]** key/sig, **[L]** lifecycle logic.

| # | Loc | Class | One-line |
|---|---|---|---|
| B1 | container-arch §4 / §3.6 | A | Untrusted lake/dreamer hold `rw` on the corpus whose frontmatter is the tier state → label forgery with no hook, no audit, no sig to fail |
| B2 | container-arch §3.5 / §6.3 | A | Hook-B non-disclosing disclosure gate runs inside the untrusted lake ("local bindings") |
| B3 | container-arch §4 skill-registry | A | Runtime `ro` mount → skill read + execute without hook F |
| B4 | container-arch §3.3 gateway | A | Gateway asserts identity for the whole ABAC model + externally connected → 3rd architecture-defeating container, contradicts principle 1 |
| B5 | KLC §6 / §10 B,E | A/D | `no-egress` specified as content-match over composed payloads (paraphrase defeats it); handling caveats have no taint/propagation/combination model |
| B6 | KLC §4/§6/§9.1 | L | Internal-origin objects (memories, self-gen skills) fit neither hook A nor C; no issuer → no derivable ceiling; `min(inputs)` undefined over empty lineage |
| B7 | KLC §6 / §9.2 / §12 | E | Detached-signature payload undefined on mutable frontmatter → sigs break on every transition *or* can't attest tiers; stale signed states replayable at import (tier resurrection) |
| B8 | KLC §10 hook E | A | Undefined "task-scoped allowlist" = second egress authority that can bypass the Tier-0 map (no minting authority, signer, ceiling, or creation hook) |
| B9 | KLC §8.3 / §10 E,F | A | Quarantine "inform but not authorize" has no enforceable semantics — hooks track classification taint but not integrity/epistemic-tier taint → confused-deputy residual |
| B10 | KLC §6 / §15 | D | Releasability categories order *opposite* to compartments; uniform max/union high-water rule silently widens REL of derivatives = automated write-down |
| B11 | KLC §10 E / §6 | D | No-write-down has no rule on replies to operators; shared-channel context fork/merge unspecified |
| B12 | KLC §6 / §12 | D | No component specified as the trusted authority that *mints* classification labels; operator input + sneakernet import unlabeled |
| B13 | KLC §10 hook C | B/D | Hook C row omits the classification HWM stamp + handling propagation §6/§15 assign it |
| B14 | KLC §9.1 memory 2→1 | L | 3 sessions each reading the same poisoned doc satisfy "≥3 independent sessions" → single-source poisoning path §11.2 claims to close |
| B15 | KLC §8.3 vs §10 B | L | "Task's minimum tier" floor makes quarantine-informs-current-task unfulfillable for exactly the learning-loop tasks |
| B16 | KLC §15 vs §7/§12 | B/L | `enters_at_tier:3` contradicted by Tier-0 authoring and signed-tier import, no exemption stated |
| B17 | KLC §9.1 skill 2→1 | L | Gate requires N supervised executions the contract forbids (Tier-2 can't authorize privileged action, execution is privileged, not yet signed) → no skill can legally reach Tier 1 |
| B18 | KLC §9.2 contradicted | L/B | Demotion ranks precedence by tier number (forbidden by `precedence_outside_typed_edges:never`); undefined "below Tier 3"; auto-resolves conflicts the lake model says must surface; adjudicated by the untrusted dreamer |
| B19 | KLC §9.1/§11.2/§14 Q8 | B/L | Corroboration "independence" has no floor and Q8 is unresolved while §9.1 cites it as a definition |
| B20 | KLC §11.2 vs §9.1 | B | 2→1 corroboration stated twice with different bars → ceiling-2 blog can corroborate into Tier 1 |
| B21 | KLC §6 / §7.1–7.2 | A | `issuance_type` "authored at ingest," not map-bound → self-served ceiling raise honoring the derived-only lock in letter |
| B22 | KLC §10 hook D | A | §9 semantic criteria only the untrusted dreamer can judge; kernel rubber-stamps the assertion (no attestation model) |

Full evidence, per-finding recommendations, and the adversarial verifier's reasoning for each are in the machine-readable digest accompanying this review. The should-fix set (44) and discussion set (5) are catalogued there by the same class scheme; the highest-value should-fix items are the **key-infrastructure gap (#25)** — the entire architecture rests on signatures and no document defines the key model — and the **missing fail-closed / startup-precondition semantics (#41)**, the single most recurring defect class in *both* hardened baselines and absent from maknae.

---

## 5. Proposed ADR docket

45 findings were flagged ADR-candidate. They do **not** warrant 45 ADRs — they collapse to a small foundational set. Recommended, in dependency order:

| ADR | Title | Resolves | Kind |
|---|---|---|---|
| **0004** | Storage & label-integrity model — the kernel is the integrity root for tier/label/classification state at all tiers | B1, B3, B21 + the `rw`-mount cluster | Redesign (Class A) |
| **0005** | Enforcement-locus & TCB boundary — which decisions run in the trust plane; gateway trust posture; disclosure/execution gates | B2, B4, B22 + hook-coverage gaps (#26, #27, #32) | Redesign (Class A) |
| **0006** | Corpus single-source-of-truth doctrine — hook table + §15 canonical; ADRs own decision status; diagrams regenerate; inherited-vs-extended labelling | B13, B16, B20 + all cross-doc/lake-align drift (#42–58) | Redesign (Class B) |
| **0007** | Key & signature model — signed-payload canonicalization, key provisioning/rotation/revocation, trust anchors for §12 import, what verifies the kernel | B7, #25 | New (foundational) |
| **0008** | Classification lattice definition — level/compartment/**releasability** join rules (antitone REL), dominance, encoded in `maknae-dcs-core` + conformance vectors | B10, B12, #36 | New (foundational; MLS correctness) |
| **0009** | Output-interface MLS model — no-write-down on replies to operators; shared-channel floor labels; context fork/merge | B11 | New |
| **0010** | Quarantine integrity-taint model — hook F context-integrity input; epistemic-tier taint distinct from classification taint | B5, B9, B15 (+ §14 Q6) | New (Class A adjacent) |
| **0011** | Internal-origin lifecycle — synthetic issuers, ceiling derivation, and mediating hook for memories & self-generated skills | B6, B17, B14, B19, B22 | New (lifecycle) |
| **0012** | Failure-mode & threat-model register — fail-closed behavior on trust-plane unavailability; startup preconditions; accepted-residuals register; AI-implementation meta-threat-model | #41, #66, #68 | New (from baseline lessons) |

Two of these — **0004/0005 (enforcement locus)** and **0008/0010 (MLS + taint)** — are the ones where getting the design wrong is expensive to unwind after implementation starts, and are the strongest candidates for an adversarial advisor pass before ratification.

---

## 6. RL convergence status — honest read

**RL#1 is not converged, and could not be.** The convergence guard requires (a) no unresolved defeats from either reviewer dimension, (b) findings shallower/different-class than the prior round, and (c) a clean confirming round. RL#1 is the base case (no prior round), and it surfaced **22 blockers concentrated in two redesign-classes** — the opposite of a shallow tail. Both reviewer dimensions (Claude in-model + Codex cross-model) fired live: 29 of the 72 confirmed findings carry a Codex co-signature, and the Codex-only set (7 findings) is real signal the in-model lenses missed — notably B3 (skill-registry execution) and several control-mapping scope errors.

**The redesign-vs-patch decision is already made by the data.** The class does not resolve by patching instances; it resolves by the two redesigns in §2–§3 (kernel integrity root + enforcement-locus discipline; single-source-of-truth). That is the RL doctrine's whack-a-mole tell — *N places that must stay in sync* (Class B) and *invariants asserted over state the untrusted plane can write* (Class A) — answered by killing the class, not the symptom.

**Because this is audit mode, the loop now hands off.** I cannot edit @darkhonor's design, so re-running RL#2 against the *unchanged* corpus would surface the same set — no new information. The productive next round fires **after the author responds**: RL#2 should re-review the *revised* corpus (or the ADR drafts for 0004/0005/0006) and check whether the redesign **killed** the class or merely **relocated** it to a new seam (e.g., a kernel-brokered write API that reintroduces a trust boundary at the API surface, or a single-source hook table that a diagram still shadows). The `relocated_class` field is wired into the review schema precisely to catch that on the next pass.

**External-floor candidates to watch (do not over-redesign):** two residuals are likely *correctly bounded* rather than fixable — the baselines' documented irreducible residuals (an injected agent can exercise everything policy permits; authorized content can still exfiltrate to an accredited endpoint). Those terminate against the architecture's own threat model and should be *accepted + documented in the §5 residual register (ADR-0012)*, not chased with a redesign. That determination itself needs the cross-model dimension to challenge the floor claim before it's accepted — flagged for RL#2, not asserted here.

---

## 7. What was refuted (kept honest)

Five findings were struck by the adversarial pass and are **not** defects: a claimed "second egress point" via the gateway (misread — §3.2 explicitly enumerates channel egress through the proxy); a "zero-denial rewards denial-avoidance" inversion (dissolves once skills-as-subjects denial semantics are read in context); a claimed HobiBot-scope inter-doc divergence (the language originates in the autopsy's own §6.4); and two "(verify)" lake-dependency doubts that **verified true** against the live knowledgebase repo (#280/#284 and the #201 build-out exist as claimed — the misattribution in #55–58 is about the *ceiling concept and D9 phrasing*, not the existence of the work). The 7 unverified nits (version-string references, SVG-caption polish, diagram-vs-prose wording) are logged in the digest for a cleanup pass, not gated.

---

*Review provenance: Rook (Claude Fable 5, orchestrator), operator-steered (@ChukusMooticus), with Codex as the cross-model dimension. Method: 9-dimension fan-out (7 Claude lenses + Codex + baseline-xcheck against hermes-agent-hardened-baseline and openclaw-hardened-baseline) at xhigh, dedup, adversarial per-finding refutation with root-cause/relocation probe — RL#1 of a convergent review loop, audit mode (hand-off, not converged). Grounded in the maknae corpus at 5e76b96 and the local knowledgebase ADR-0004. — Rook*
