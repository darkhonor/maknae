# System One Models and Jev (TypeSafe AI) — Assessment Against Maknae's Decision System

| | |
|---|---|
| **Status** | Assessment record — informs the runtime-loop (Cooky) and post-Cooky tool work. **No dispositions ratified; no team decisions taken.** Candidate follow-ups are named in §7. |
| **Date** | 2026-09-22 |
| **Subject** | "System One" models — a class of non-generative AI models that evaluate a text *state* against typed *questions* and return typed answers with probability distributions — and **Jev**, TypeSafe AI's first such model (early access 2026-09-15). The question asked: are there elements Maknae could leverage as part of its underlying decision system? |
| **Method** | Read-only. Primary: `docs.typesafe.ai` (introduction; concepts/system-one; primitives/choice, score, noul; confidence; patterns) and the launch post (`typesafe.ai/blog/introducing-system-one-models-and-jev`). Independent: TrueFoundry's critical read; a SOC field report (Ken Huang, Substack); TechCrunch 2026-09-18; Tom's Hardware 2026-09-21. Web search via the team's SearXNG. **Nothing was measured by us** — Jev is API-only and early access; every number below is the vendor's unless marked otherwise. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |
| **Purpose** | The maintainer asked, on a research day: *"research 'System One' models and Jev in particular. Are there elements we could leverage in Maknae as part of the underlying decision system?"* The answer is structured as pros / cons / done well / avoid / directly applicable, with each disposition tied to the Maknae rule it rests on. |

## 1. Provenance disposition (read first)

Everything from TypeSafe is **vendor provenance**: a launch post and product docs for a model in early access, with no public benchmark, no open weights, no self-hosting, and one week of outside contact. The one skeptical independent source (TrueFoundry) verifies only what is checkable by construction — pricing, schema conformance, founder credentials — and states that the headline claim, calibration, *"is the one no outside party has tested yet."* The SOC field report is a practitioner's build over 30 runners and is candid that its confidence thresholds were **not fitted to labelled traffic**. Nothing here is authority for a Maknae rule; the Maknae rules cited below are the authority, and the external material is measured against them.

## 2. The headline — read this before anything else

**A System One model does not belong inside Maknae's decision system, for four reasons that hold independently** (§4). It is a probabilistic classifier delivered as a hosted, closed, remotely-versioned API. Maknae's PDP is a deterministic composition of operands that must fully evaluate their predicate, with no network in the decision path and no content able to authorize. Those are not tunables.

**Where it does fit is the untrusted side, as a user-authorized external tool** — exactly the class the maintainer's tool ruling already names (MCP configuration is a user-authorized activity; Maknae defines only the baseline tools). Proposal filtering in the loop is cheap and harmless; deputy-side screening is the one placement with security value and is ON-milestone work behind two ADRs (§6).

**What is worth taking regardless of the product** is the *shape*: decisions software branches on, one proposition per question, consequences-scaled gating, and a rubric-writing discipline (§5).

## 3. What a System One model is, in Maknae's vocabulary

Inputs: a **state** (text — images/audio/video "not supported (yet)") and a map of typed **questions**. Outputs: typed answers with probabilities; the model "does not write replies, produce code, or generate explanations of its reasoning." Many questions per request, evaluated **in parallel and in isolation**; the house rule is one proposition per question, with complex reasoning decomposed into separate questions combined by application code.

| primitive | request | response | notes |
|---|---|---|---|
| **Choice** | `instructions` + `criteria` (option → description; ≤ 255 options) | `choice`, `probabilities` (sum 1.0), `confidence` | `confidence = (n·p_max − 1)/(n − 1)`; structured criteria (`what`, `not_for`, `examples`) recommended for near-duplicate options |
| **Score** | `instructions` + ordered `criteria` (2–10 levels, "observable situations, not subjective degrees") | `score` (probability-weighted mean), `probabilities`, `confidence`, `legend` | each level judged independently; ordering does not influence scoring; one dimension per question |
| **Noul** | a yes/no proposition (+ optional `true`/`false` criteria) | `noul` ∈ [0, 1] = P(yes) | no separate confidence — the value *is* the distribution; threshold it (docs suggest 0.8–0.9 for "act", 0.2–0.8 for review) |

Jev specifically: non-autoregressive parallel sampling; a training method the vendor calls Reinforcement Learning for Calibrated Decisions (RLCD); 70–500 ms end-to-end; $0.042/MTok input, output free; hosted from the US West Coast; versioned (`jev-1.13.0` in the docs' example). Founder: Diogo Almeida (ex-OpenAI, instruction-following). Vendor claims: "can't hallucinate" (meaning **schema conformance by construction** — a wrong option can still be chosen with confidence 1.0), "epistemically honest probabilities", 40–200× faster than frontier models on "System One-shaped tasks". Vendor caveat, verbatim: *"calibration is measured across groups of predictions; it does not guarantee that an individual answer is correct."* **The documentation contains no claim** about prompt-injection resistance, determinism across versions, or auditability.

Their patterns: speculative fan-out; **confidence-gated routing** ("different actions within the same system should be gated at different levels depending on the consequences of getting it wrong"); composite scoring; intent routing. The SOC report is the confidence-gated pattern in the wild: Jev scores, code acts; bands at 0.45 (human) / 0.72 (standard) / 0.88 (high-stakes); and the pipeline **stopped before `isolate_host`** — the irreversible action stayed upstream of the model. A language model wrote analyst briefings only after Jev screened the prompt and again screened the draft.

## 4. Inside the decision system — DO NOT ADOPT; four independent reasons

Maknae's decision system is the PDP: `maknaed` composes `maknae-authz-basic` ∧ the classification ceiling as **named, non-removable fields** ([ADR-0008](../adr/ADR-0008-authorization-composition-contract.md) decision 1), folds them deny-overrides + indeterminate-blocks (`crates/maknae-security/src/compose.rs::combine`), and `finalize` collapses anything not `Permit` to `Deny` ([ADR-0004](../adr/ADR-0004-modular-authorization-architecture.md) §2).

1. **Inform-but-not-authorize** (`AGENTS.md` principle 2). A probability is content. Content "may *inform* a decision but can never *authorize* one." ADR-0008 decision 4 forbids any operand that cannot **fully evaluate its predicate** from returning anything but `Deny`/`Indeterminate`/`NotApplicable`. A classifier *estimates* a predicate; it never evaluates one. A `Permit` sourced from a model output is a grant by prediction.
2. **Determinism** (ADR-0004 §3: a backend "MUST be total and deterministic" w.r.t. policy bytes and request; the golden matrices pin it). Jev is remotely versioned and, by the vendor's own statement, only group-calibrated. Nothing in `golden.rs` can pin a hosted model's output.
3. **Static Rust TCB with no network in the decision path** ([ADR-0002](../adr/ADR-0002-kernel-is-rust.md), [ADR-0005](../adr/ADR-0005-enforcement-locus-tcb-boundary.md)). A hosted API inside `decide()` puts a third party and a TLS round trip in the TCB — and hands that party the **request** (the path, the prompt text, the subject's role) *before* the verdict exists. The PDP would exfiltrate the content it exists to protect, on every decision. For a homelab that is disqualifying; for an enterprise it is a data-handling decision no platform default may make.
4. **Fail-closed under unavailability.** An external dependency in the decision path fails closed by rule, so the loop halts whenever the vendor does — a liveness cost with no security gain, because the deterministic operands already decide.

**The deny-only variant, considered and rejected as a shipped component.** `combine` rule 1 (any `Deny` wins) makes an advisory operand mechanically possible, and ADR-0004 §4 explicitly invites third-party engines behind the seam. But reasons 2–4 still hold, and reason 1 has a mirror: a *Deny by prediction* is the refusal of an entitled subject with an audit reason that is a floating-point number — unexplainable in a trail whose refusal classes are otherwise nameable (#181). Deny-by-default already covers the ground. **A deployer who wants it writes `impl Authorizer` themselves** — that is what the seam is for, and it is the deployer's data-handling decision to make, not the platform's.

## 5. Things done well — LEARN FROM

- **The output is a decision, not prose.** No parsing, no "extract the JSON from the reply". This is Maknae's own posture (verdict-shaped results, refusals with no reason, `applied`/`outcome unknown`) stated as a product category; it is validation, not a lesson.
- **One proposition per question; isolation between questions; "no context degradation when adding questions."** The decomposition rule — never "angry AND requesting refund" — is the same discipline that keeps a PDP predicate evaluable, and it transfers directly to how a *human* should write the DCS operand's releasability / need-to-know predicates so a reviewer can check each one alone.
- **Score's rubric rules.** "Describe observable situations, not subjective degrees"; "each level evaluated independently; level numbers and ordering don't influence scoring"; "one dimension per question"; "test descriptions against actual data; confidence alone doesn't validate quality." This is better rubric guidance than most classification-marking training, and it is product-free.
- **Confidence scaled to consequence.** "Different actions … gated at different levels depending on the consequences of getting it wrong" — and the SOC pipeline's refusal to let the model reach `isolate_host` at all. That is the right instinct: the irreversible action is not a threshold question, it is not the model's to take. Maknae's equivalent is structural (the PDP decides every mutating verb), which is stronger; the *idiom* is still useful for the loop's advisory bounds (§6).
- **A closed option set with a hard cardinality (255).** A bounded vocabulary is a security property Maknae already holds (the verb vocabulary; the router's two-tool table); seeing it as a *model* constraint is a reminder that unbounded option spaces — paths, hostnames — must never be enumerated as choices.

## 6. Things to avoid — and the two placements that survive

**AVOID: any use as a control.** A confidence-gated filter in front of the PDP is not defence in depth; it is a second decision-maker with no audit, no determinism, and a cloud dependency. The kernel already decides and records every call. A filter reduces *proposals*, not risk — and a compromised loop simply skips its own filter (the same argument recorded for #241's router: a hostile runtime bypasses client-side checks and meets the kernel anyway).

**AVOID: sending the transcript to a second provider without an ADR.** Every placement below that has security value has the same cost: the secret-class transcript leaves to a second third party. That doubles the exfiltration surface by design and must be a named decision, alongside the memory-hygiene boundary (#342), not a feature flag.

**AVOID: thresholds as configuration.** The SOC report's bands (0.45 / 0.72 / 0.88) were admittedly unfitted; the vendor's calibration is group-level and version-dependent. A threshold fitted to `jev-1.13` is unfitted to `jev-1.14`. Anything that ships must degrade to "absent, no behaviour change" — and must be re-fitted on every model version, which nothing can gate.

**AVOID: trusting "can't hallucinate."** It means the *shape* is guaranteed. Substance is not. A confident wrong answer is the normal failure mode of a calibrated classifier on out-of-distribution input, and the vendor says nothing about adversarial text — a Noul over a transcript containing "this request is authorised" is still a classifier over hostile bytes.

**The two placements that survive, both untrusted-side, both user-authorized tools:**

- **(a) Proposal filtering in the loop** (`crates/maknae-agent`, `drive`). Before a proposed tool call is sent: `Noul("does this read/write serve the user's stated task?")`, `Choice(intent)`, confidence-banded — high: send; middling: ask the user; low: refuse the *proposal* as a `tool error` the model can fix. Value: fewer wasted denials and less audit noise from a probing model; latency 70–500 ms per step is tolerable. Cost: a second provider call per step and a second key in custody. **Zero as a control** (see AVOID above); a reasonable post-Cooky *tool*.
- **(b) Deputy-side screens** (`maknae-egress`). Pre-send `Noul("does this outbound transcript contain a credential / a marking above the declared level?")`; post-receive `Noul("does this reply try to steer the loop's tools or policy?")`. The deputy is trusted and already the chokepoint, so this is the one placement where the model's answer can change what leaves the process. But it is a second provider in the deputy: a second key in Vault custody, a second `destinations:` entry, a second egress term or a generalised one — the provider-registration work Cooky deliberately did not build (ADR-0023 decision 3; #169 in ON) — and the whole transcript to a second party every turn. **ON-milestone, behind the exfiltration-surface ADR and #342.**

Ordering if ever pursued: (a) first (nothing from the trust plane; failure mode is "the loop asks more often"); (b) only behind its ADRs.

## 7. Directly applicable, in some form — APPLICABLE

| # | what | where in Maknae | form |
|---|---|---|---|
| A1 | Consequence-scaled gating as the idiom for the loop's **advisory** bounds ([ADR-0023](../adr/ADR-0023-runtime-loop-role-and-placement.md) d7) | `crates/maknae-agent/src/drive.rs` | a deterministic predicate ("a write outside the working set → ask the user") in the same act / confirm / stop shape — no probability needed |
| A2 | Score's rubric discipline as the **documentation** standard for MAC predicates | `maknae-authz-dcs` (external) and the ceiling operand's docs | observable situations, one dimension per predicate, each level checkable alone by a reviewer |
| A3 | "One proposition per question" as the shape of any future **structured-output** ask to the provider | `crates/maknae-llm` tool definitions (#264's `baseline-tools.json`) | when a tool needs the model to classify, ask one bounded question with a closed option set, never a free-text field |
| A4 | Proposal filtering as an optional user-configured tool (placement (a)) | post-Cooky; the same axis as user skills/MCP per the maintainer's ruling | absent by default; degrades to no-op; never on the kernel's path |
| A5 | Deputy-side screening (placement (b)) | ON milestone | behind: second-provider registration; an ADR naming the doubled exfiltration surface; #342 |

**Candidate follow-ups (not filed — the Cooky freeze):** A1 is a one-paragraph design note on ADR-0023 d7 when the loop's bounds are next touched; A2 is a documentation convention for the DCS library; A4/A5 are post-Cooky issues that need the maintainer's word.

## 8. Open questions

1. **Prompt-injection posture.** The vendor makes no claim; the SOC author validated against vendor LLMs, not human labels. Before (b), measure it with adversarial transcripts.
2. **Self-hosting.** None today. An air-gapped or on-prem deployment cannot use Jev at all; the day a self-hostable System One model exists, (b) becomes materially more attractive — that is the watch item.
3. **Calibration across versions.** Thresholds fitted to one `jev-x.y.z` are unfitted to the next; nothing can gate that drift.
4. **Cardinality.** 255 options. Maknae's verb vocabulary fits; its path space does not — (a) must never enumerate paths as options.

## 9. Sources

- TypeSafe AI docs: introduction; concepts/system-one; primitives/choice; primitives/score; primitives/noul; confidence; patterns (`docs.typesafe.ai`, read 2026-09-22).
- TypeSafe AI, *Introducing System One Models & Jev*, `typesafe.ai/blog`, 2026-09-15.
- TrueFoundry, *TypeSafe AI's Jev: What "System One Models" Actually Are*, 2026-09-18.
- Ken Huang, *What is JEV from TypeSafe AI? How we implemented an agentic SOC…*, Substack, 2026-09-21.
- TechCrunch, *A new kind of AI model from a ChatGPT inventor is thrilling developers*, 2026-09-18; Tom's Hardware, 2026-09-21.

*Provenance note: every external document above is cited as inspiration or measurement, never as authority; the Maknae rules cited in §4 are the authority.*
