# Maknae — Convergent Review Loop: running convergence ledger

> **Living document.** One row per root-cause class, updated each round — *not* rewritten. The point of a convergence loop is the **trend across rounds**, so this ledger is the artifact that makes the trend visible: a class that keeps resurfacing after a redesign has been *relocated*, not killed, and that distinction decides whether the next round patches or redesigns.
>
> Format follows the operator's knowledgebase RL practice (mpe-es/knowledgebase #422): per-class status plus explicitly named **residuals**, so "adopted" never silently swallows what is still open.

| | |
|---|---|
| **Subject** | darkhonor/maknae design corpus |
| **Mode** | Audit (external review; findings + hand-off recommendations, never edits to the corpus) |
| **Rounds run** | RL#1 (2026-07-14, corpus `5e76b96`) · RL#2 (2026-07-20 UTC / 07-21 KST, corpus `9c715d7`) |
| **Tracking** | Issues #1–#10 · PR #11 (merged) |

---

## 1. Convergence guard — exit conditions

The loop exits only when **all three** hold. Tracked honestly each round:

| # | Condition | RL#1 | RL#2 |
|---|---|---|---|
| (a) | No unresolved defeats from **any** reviewer dimension (Claude **and** every cross-model dimension that ran) | ✗ — 22 blockers open | ✗ — 24 blockers; all three families dissenting |
| (b) | This round's findings **shallower / lesser class** than the prior round's | n/a — base case (vacuous) | ✗ — **same classes, new seams**; 0 killed |
| (c) | A clean confirming round validates the latest fix held *(audit mode: that the hand-off recommendations are complete)* | ✗ | ✗ — not attempted; nothing to confirm yet |

**Round-over-round posture:** RL#1 = NOT converged (hand-off). RL#2 = **NOT converged — continue.** Grok's design probe: *"Do not exit on partial state-store progress or unproven external floors."*

---

## 2. Class ledger

Status vocabulary: **killed** (class eliminated at the root) · **relocated** (symptom addressed, same structural shape at a new seam — *treat as the SAME class, redesign the root*) · **partially-killed** · **open** (untouched) · **external floor** (terminates against an invariant outside the system — accept + document, do NOT redesign again).

### Class A — Enforcement asserted without a trust-plane locus

*A security property is named but the enforcing mechanism lives in the untrusted plane, or is unspecified.*

| Round | Status | Evidence / movement |
|---|---|---|
| **RL#1** | **Open** — 22 findings, 11 blockers | Volume table gives untrusted `lake`/`dreamer` `rw` on the corpus whose frontmatter *is* the tier state, kernel `ro`; hook-B disclosure runs inside the untrusted lake; skill read+execute bypasses hook F; gateway asserts identity for the whole ABAC model yet is not named architecture-defeating |
| **RL#2** | **Open** — untouched, and re-instantiated at new seams | **Crucial framing: the ABAC/DCS work was authored concurrently with RL#1** (branched from the same base `5e76b96`, ~20 min after the issues posted) — it was never a response, so "open" is the arithmetic of disjoint surfaces, not ignored feedback. B1 is open and *byte-identical*; B2 open (§7.2 lake hot path *"unchanged"*). **New Class-A instances introduced by the new architecture:** nothing verifies the signed subject context before the `SET LOCAL` GUCs are trusted; the RLS generator/migration runner is an unclassified trusted component (no container, no trust level, no signed output, no DDL credential model); `untrusted-adjacent` is a third trust category defined nowhere; environment attributes are *"supplied by the requesting plane"*. Grok probe verdict: **`CLASS_A \| open`** |

**Residuals (carried):**

- RL#1 B1/B2/B3/B4/B21/B22 remain open and un-adjudicated — the new architecture did not touch those surfaces.
- **Trust loci to pin (new):** who applies the GUCs and what verifies the context first; who holds Layer-2 PEPs; the subject-context envelope (§17 Q4, still undecided); Tier-0 materialization parity (materialized copies get no boot-parity contract, unlike RLS).
- **Cached-authorization window:** TTL-scoped subject contexts make enforcement a function of TTL/revalidation correctness rather than continuous binding, contradicting the doc's own "no cached-allow" doctrine. No max-TTL bound, drift detection, or revocation path specified.
- **Vendor-substrate trust locus:** `FORCE RLS` / no `BYPASSRLS` / pool-safe `SET LOCAL` / superuser absence are architecture-grade claims resting on PostgreSQL role and pooler topology — outside the Rust trust-plane binaries (§7.3, §17 Q3).

### Class B — Two-representations drift

*The same rule or fact stated in more than one place; the copies diverged. Doctrine: read reality, don't reconstruct it — prefer a pointer over a second copy.*

| Round | Status | Evidence / movement |
|---|---|---|
| **RL#1** | **Open** — 25 findings, 7 blockers | Hook table vs §15 invariants vs §6 prose disagree on derivation; corroboration rule stated twice with different bars; ADR status desynced from README/autopsy prose; diagram caption still instructs a rejected action; inherited lake-model summary drifted from the real ADR-0004 |
| **RL#2** | **Relocated** — killed at the SPIF seam, re-expressed as *correlated failure* | KLC unmodified, so RL#1's instances stay **open**. At the new seam, single-source generation genuinely removes the N-copies-that-must-agree shape — but replaces it with the **opposite** shape: *one representation governing N enforcement surfaces*, whose failure mode is correlated rather than divergent. A generator or SPIF-semantics bug yields the same wrong allow on Cedar, the PEP, and RLS **simultaneously**, defeating §1 doctrine 1 (*"Disclosure requires multiple independent, independently tested layers to fail identically"*) and §7.3's *"implemented independently"* — which is executor diversity (Cedar vs PostgreSQL), not **policy-oracle** independence. §12's vectors are a single spine over the same engine, so CI proves self-consistency, not multi-oracle agreement. Residual literal drift persists: projection count stated **three ways** ("two physical projections" §6.2/D8 · "three enforcement surfaces" §6.4 · "a fourth projection" container-arch §6), and *(Grok-only)* the Layer-2 `injectABACClause` predicates are a **third hand-ported encoding of dominance** outside all three compile targets, the boot parity check, and the vectors. Grok probe verdict: **`CLASS_B \| relocated`** |

**Residuals (carried):**

- **The independence claim must be reconciled**, one of two ways: diversify the oracles so layers *can* fail differently (e.g. an independently-derived RLS test oracle), or weaken §1 doctrine 1 / §7.3 to what the mechanism actually delivers and add compensating controls. Currently the text claims more than the design provides.
- **Conformance vectors do not test the cross-surface property** — ∀(subject, resource): Cedar decision ≡ PEP predicate ≡ RLS visibility. Identical golden vectors give agreement only on the vector set.
- Projection count must be stated **once**, canonically, and every other mention made a pointer.
- `injectABACClause` must either become a SPIF compile target or be removed as an independent encoding.

### Supporting families (targeted-fix, not redesign classes)

| Family | RL#1 | RL#2 | Home |
|---|---|---|---|
| MLS/BLP label model underspecified (REL antitone join, label origination, downgrade path) | 8 findings, 3 blockers | open — KLC unmodified | ADR-0008, #6 |
| Key / signature / attestation model undefined | 4 findings, 1 blocker | open + **worsened**: subject-context envelope undecided (§17 Q4) adds a new unsigned-credential surface | ADR-0007, #5 |
| Lifecycle & promotion logic (internal-origin objects, corroboration, gate deadlock) | 9 findings | open — KLC unmodified | ADR-0011, #9 |
| Quarantine integrity-taint | 5 findings | open — KLC unmodified | ADR-0010, #8 |
| Control-mapping accuracy / claim discipline | 4 findings | new instances in abac §15 (AC-16(6) error repeated; IA-2 double-use) | #4, #10 |
| Failure-mode / threat-model / residual register | 1 finding | **partially addressed** — §9.1 boot validation + §9.2 fail-closed matrix now exist for this subsystem; completeness gaps found | ADR-0012, #10 |
| Scope & feasibility realism | 3 findings | worsened — full DCS schema port + RLS-in-CI + a from-scratch Rust OpenTDF SDK for upstream submission | ADR-0012, #10 |

---

## 3. Per-round record

### RL#1 — 2026-07-14 · corpus `5e76b96` · audit mode

| | |
|---|---|
| **Dimensions** | 9 — 7 Claude lenses + **Codex** (cross-model) + baseline-xcheck against `hermes-agent-hardened-baseline` / `openclaw-hardened-baseline` |
| **Method** | Parallel fan-out → dedup → adversarial per-finding refutation with root-cause/relocation probe |
| **Result** | 120 raw → 84 clusters → **72 confirmed** (22 blocker / 44 should-fix / 5 discussion / 1 nit), 5 refuted, 7 nits unverified |
| **Cross-model signal** | 29 of 72 confirmed carried a Codex co-signature; 7 were **Codex-only** (incl. the skill-registry execution blocker) |
| **Convergence call** | **Not converged** — findings concentrated in two redesign-classes, the opposite of a shallow tail. Audit mode → hand-off |
| **Positive evidence** | Baseline cross-check **corroborated every checkable autopsy §2–§5 claim**; sharpening: the overlay floor the baselines achieved is *higher* than the autopsy implies, narrowing maknae's differentiator to the semantic-governance layer |
| **Output** | Issues #1–#10 (ADR docket 0004–0012); PR #11 (merged `9c715d7`) |

### RL#2 — 2026-07-20 UTC / 07-21 KST · corpus `9c715d7` · audit mode · COMPLETE

| | |
|---|---|
| **Trigger** | Author redesign: `abac-dcs-architecture.md` (new, 383L), `container-architecture.md` edits, 3 imported reference docs (334KB) |
| **Dimensions** | 12 — 6 Claude lenses + **Codex** + **5 Grok** (relocation probe, **blind** review, multi-representation, identity/RLS, imported-refs) |
| **Method** | Find (Claude ∥ Codex ∥ Grok-serial) → merge with `model_families` tagging → verify (Claude refuters + **6 paired Grok refuters** on top blocker/relocation clusters) → dual design probe (opus + Grok) |
| **Central question** | Did the redesign **kill** Class A/B, **relocate** it, or leave it open — and did it introduce new instances? |
| **Blind exposure control** | One Grok dimension receives the corpus with **no prior findings**. Independent re-derivation of the same classes = strong evidence they are properties of the design, not reviewer echo |
| **Disclosed cap** | Paired cross-model refutation applied to the **top 6** clusters by severity/relocation rank; remaining verified clusters get Claude-only refutation. Not silent |
| **Result** | 204 raw → 104 clusters → **85 confirmed** (24 blocker / 54 should-fix / 6 discussion / 1 nit), 18 refuted |
| **Disposition** | **44 open · 22 new · 19 relocated · 0 killed · 0 external floors** |
| **Cross-model yield** | Grok participated in **61 of 104** clusters and found **26 no Claude lens caught** — including the blocker that `injectABACClause` is a third hand-ported dominance encoding. Claude-only 41 · Grok-only 26 · Claude+Grok 23 · all-three 11 · other 3 |
| **Convergence call** | **NOT converged — continue.** Guard fails (a), (b), and (c) |
| **Run integrity** | Workflow errored at its tail (paired-Grok chain, agent #3 exhausted structured-output retries). 116/117 agents completed; all find/merge/verify results recovered from the journal. **Paired cross-model refutation reached 2 of 6** intended clusters — disclosed, not silent. The Grok design probe was re-run directly after a staging file (`bundle-core.txt`) was clobbered mid-run by a runner, which had left an earlier probe executing against a 2.7KB corpus stub |
| **Count note** | The comment posted to issue #1 cited 84 confirmed; re-deriving the verdict↔cluster join for the digest yields **85**. One finding recovered by the join, not a changed judgment |

---

## 4. External-floor watch

Residuals that may terminate against an invariant **outside** the system rather than a patchable seam. An external-floor exit is the easiest to game, so a claim here is **not** accepted on orchestrator judgment alone: it must be verified against an authoritative source AND specifically challenged by the cross-model dimensions before acceptance.

| Candidate | Raised | Status |
|---|---|---|
| An injected agent can fully exercise everything policy permits (confused-deputy residual within authorized scope) | RL#1 (from the hardened baselines' residual register) | **Still unadjudicated** — RL#2 confirmed 0 external floors among *its own* findings but did not close out the RL#1 pair; carry to RL#3 |
| Authorized content can still exfiltrate to a legitimately accredited endpoint | RL#1 (same) | **Still unadjudicated** — carry to RL#3 |
| PostgreSQL as the RLS substrate | RL#2 | **REJECTED as a floor** — a *chosen substrate*, not an unreachable threat |
| OpenTDF Rust SDK gap | RL#2 | **REJECTED as a floor** — *deferred work* |
| Unread NIST SP 800-162/205, ACP 240, STANAG full texts | RL#2 | **REJECTED as a floor** — *acquisition gap* |
| External IdP federation boundary | RL#2 | **REJECTED as a floor** — chosen architecture |

**RL#2 floor ruling (Grok design probe, verbatim):** *"NONE. No residual requires violating an invariant outside system control… not unreachable threats. Round-2's 0 external floors stands; do not accept+document any of the above as floors."* The cross-model dimension was specifically tasked to challenge floor claims and rejected every candidate — the anti-gaming guard functioning as designed.

---

## 4b. New root-cause classes introduced by the ABAC/DCS architecture

Named by the RL#2 design probes; these are **not** relocations of Class A/B but new shapes:

| # | Class | Substance |
|---|---|---|
| **C** | **False multi-layer independence / correlated allow** | Shared SPIF→N projections + a shared vector spine as the disclosure backstop. Distinct failure mode from drift: layers fail *together*, not apart. (See Class B residuals.) |
| **D** | **Cached subject-context privilege window** | §7.2/D9 kernel-minted TTL snapshots move enforcement from continuous binding to TTL/revalidation correctness. Revocation latency = TTL; no bound, no drift detection, no revocation path, envelope undecided (§17 Q4) |
| **E** | **Vendor-substrate trust locus** | `FORCE RLS`, absence of `BYPASSRLS`, pool-safe `SET LOCAL`, non-superuser roles are architecture-grade guarantees resting on PostgreSQL role/pooler topology — outside the Rust trust-plane binaries yet asserted as load-bearing |
| **F** | **Authority-materialization shadow** | Tier-0 stays signed-git, but the state store "may hold a materialized copy for joins" (§3.1) with no boot-parity contract of the kind RLS receives (§9.1) |

---

## 5. Method notes carried between rounds

- **Grok is serial-only.** Concurrent invocations contend on `~/.grok/leader.sock` and return `Cancelled`. The Grok chain is therefore the wall-clock critical path; runners must block until the process exits *and* the JSON parses non-empty (a redirect creates the file instantly — existence is not completion).
- **Runner-fidelity guard** on every cross-model runner: extract findings verbatim, never filter or judge, `GROK-ERROR`/sentinel on failure, and never fall back to self-review. Empty findings without evidence the CLI output was consumed is a runner *error*, not a clean pass.
- **Epoch pinning.** Each round records the corpus commit it reviewed. A finding's citation is checkable against its epoch rather than "current main" — the lesson from knowledgebase #422, where a review ran its facts sweep against a stale checkout.
- **Audit-mode loop semantics.** The reviewer cannot edit the corpus, so a round cannot "fix and re-test". The loop bottoms out at *hand-off recommendation complete*; the next round fires against the **revised** corpus, never against an unchanged one.

---

## 6. Next round (RL#3) — required targets

From the RL#2 design probes, in priority order:

1. **Adjudicate the correlated-failure vs. independence claim** (Class C) — diversify oracles, or weaken the doctrine text and add compensating controls. This is the round's highest-value open decision.
2. **Re-adjudicate the untouched RL#1 Class A blockers** — lake `rw`/tier-label integrity, hook-B disclosure locus, skill-registry execution, gateway trust posture. The architecture did not touch them; they are not stale, merely un-addressed.
3. **Pin the trust loci** — GUC application, Layer-2 holders, subject-context envelope, Tier-0 materialization parity.
4. **Resolve the three-vs-four projection discrepancy** and bring `injectABACClause` inside the generated set or remove it.
5. **Close out the two RL#1 external-floor candidates** still carried unadjudicated (§4).

RL#3 must NOT exit on partial state-store progress or on any of the RL#2-rejected floor candidates.

---

*Ledger maintained by Rook (orchestrator), operator-steered (@ChukusMooticus). Updated per round; rows are appended and amended, never rewritten.*
