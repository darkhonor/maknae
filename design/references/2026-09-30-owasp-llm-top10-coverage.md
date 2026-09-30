# OWASP Top 10 for LLM Applications (2025) — How Maknae Addresses Each Risk

| | |
|---|---|
| **Status** | Assessment record. It maps Maknae's built, planned and candidate controls to each OWASP LLM 2025 risk, and it synthesizes six supporting assessments of guard tools and architectural defenses. It creates no roadmap commitment and supersedes no ADR. Everything marked **new** below is an idea for maintainer decision, not a design. |
| **Date** | 2026-09-30 |
| **Subject** | The [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/) (fetched 2026-09-30), set against Maknae at `main` `dc364cb`. |
| **Method** | Four deep dives and one landscape survey. Each read its subject's source, model cards and licenses from read-only mirrors pinned to a commit or model revision. Nothing was built, installed or executed, and no weights were downloaded. Maknae claims were checked against the tree at `dc364cb`. Public web material is context, not evidence. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |

## 1. The answer, in brief

**No single tool covers the OWASP LLM Top 10. None can.**
- **Coverage:** across the open-source and managed guard tools surveyed ([landscape](2026-09-30-guardrails-landscape-assessment.md) §1), none reaches full coverage on more than two of the ten rows. Every standalone model covers at most prompt injection plus a partial row or two.
- **Robustness:** independent work defeats the model-based detectors at scale:
  - above 90% attack success for adaptive attacks against Prompt Guard when the detector's score is fed back to the attacker (75% against a GPT-5 Mini target; Nasr, Carlini et al., arXiv 2510.09023). Maknae never returning the score removes that precondition, but not the attack class;
  - 65–73% against NVIDIA's jailbreak detector (Hackett et al., arXiv 2504.11168).
- **OWASP's own position** on LLM01 is that "it is unclear if there are fool-proof methods of prevention for prompt injection".

**Six of the ten rows are architectural. No content filter can address them:**
- LLM03 Supply Chain
- LLM04 Data and Model Poisoning
- LLM06 Excessive Agency
- LLM08 Vector and Embedding Weaknesses
- LLM10 Unbounded Consumption
- LLM07 System Prompt Leakage, in substance

**OWASP's remedies for these are Maknae's founding design:**
- **LLM06, "complete mediation":** "Implement authorization in downstream systems rather than relying on an LLM to decide if an action is allowed or not."
- **LLM07:** "the system prompt should not be considered a secret, nor should it be used as a security control."

**Maknae therefore addresses these risks in five layers, strongest first.** A content filter is the fourth layer and the weakest:
1. **Policy in the kernel (the PDP), deciding on metadata.** Deterministic, with no added latency. Its decisions never inspect content. The kernel never opens or reads a subject's file (#365). But what the agent reads still transits `maknaed` inside the next prompt turn, because prompt text is relayed through it today; removing that is a feasibility question (#417).
2. **Native tool constraints.** Misuse is made structurally impossible rather than detected.
3. **Supply-chain and data integrity.** Settled at build and install time, not at runtime.
4. **A content filter as a weak signal.** It informs the kernel and never authorizes (a PIP, not a PDP).
5. **Detection and response.** Write-ahead audit and kernel-initiated containment.

**The single most valuable new idea is provenance taint in the kernel, after Meta's "Agents Rule of Two" (§4.1).** It stops the damage of a successful injection without detecting the injection at all, which is the property every filter lacks.

## 2. The coverage map

**Legend:**
- **Built:** in the tree at `dc364cb`, with evidence.
- **Planned:** an open issue or accepted design.
- **New:** proposed by this assessment set; not decided.

| OWASP 2025 | Layer(s) | Built today | Planned | New (this set) |
|---|---|---|---|---|
| **LLM01 Prompt Injection** | 1, 2, 4 | Mediation of every action the shipped loop takes through the plane, whatever the model was told (`maknaed` is the sole PDP, ADR-0005). The loop's own direct I/O is not mediated (ADR-0023 d6). Deny-by-default. The loop is untrusted (ADR-0023 d2). Read-before-write (#388). Tool results are data in a field (`read_file` returns `content` in JSON; a forged `"next"` is inert, #372). | Labels on content (#229). Destination zones (#147). The ceiling rises on ingest (#172 §4). | **Provenance taint / Rule of Two** (§4.1). Integrity labels (§4.2). Normalization + invisible-text check. An optional injection classifier as a weak signal (§4.4). |
| **LLM02 Sensitive Information Disclosure** | 1, 4 | The shipped deny list (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.vault-token`, `~/.netrc`, `~/.git-credentials`, `~/.docker/config.json`, `~/.maknae`; `packaging/common/authz.yaml`). The shipped policy allows `Read(~/**)`, so the deny list is the home directory's confidentiality boundary. The MAC classification-ceiling operand (ADR-0008, ADR-0022), which refuses nothing yet: nothing is marked above the lowest level until #229. Per-role `destinations:` for model egress. On a packaged install the provider key is held only through the Egress Daemon's own custody (ADR-0023 d3), within stated limits: the operator's enroll token can mint an Egress Daemon SecretID, and the dev shape has no custody ([OpenShell assessment](2026-09-29-openshell-assessment.md) §8). The kernel never opens a subject's file (#365), though read content transits it in the next prompt turn. Zeroizing secret buffers (ADR-0026). | Content labels (#229). Zones (#147). Subject-scoped credentials (#168). | Taint: "sensitive read + new sink" refusable (§4.1). Integrity labels (§4.2). Flow rules over tool-call sequences (§6 row 8). **Secret and PII patterns in both directions** in a helper beside the Egress Daemon (§4.4). |
| **LLM03 Supply Chain** | 3 | `deny.toml` supply-chain gate. Documented pins. `cargo auditable` SBOMs. Checksummed rpm/deb with optional GPG signing (the default build is unsigned, #96). A Developer ID–signed, notarized macOS `.pkg` built by hand (CI signs ad-hoc). 100% Rust TCB with `unsafe` confined to `maknae-sys` (ADR-0002, ADR-0027). | Signed Linux packages by default (#96). Signed CI release builds (#188, #200). Tool-image provenance (Rabbithole #420 decision 12, open). | **Hash-pinned model weights** for any guard model. Prefer weights with publisher signatures (Granite Guardian 4.1 ships a Sigstore bundle, [landscape](2026-09-30-guardrails-landscape-assessment.md) §2.2). |
| **LLM04 Data and Model Poisoning** | 3 | — (Maknae trains no model) | Lake quarantine and gated promotion; authority tiers ([KLC](../knowledge-lifecycle-contract.md)). | Never load a guard model from an unpinned source; no runtime downloads (every candidate assessed downloads at runtime by default). |
| **LLM05 Improper Output Handling** | 2, 4 | The Egress Daemon refuses a reply that proposes a tool it did not offer (`crates/maknae-llm/src/wire.rs`, `UnknownTool`), or whose tool call exceeds its declared bounds (`proposed_tool_call_is_acceptable`, `crates/maknae-proto/src/wire.rs`). Model output is never executed by the kernel. Writes are performed subject-side under a grant (#369). | The tool model is an open Rabbithole decision (#420 decision 3); named operations rather than argv are the leading candidate. | **Schema-validated typed tool arguments** (the #423 write bound becomes an explicit schema limit). **YARA-X rules** on output that feeds a tool (code, SQL, template injection; [NeMo](2026-09-30-nemo-guardrails-assessment.md) §10). |
| **LLM06 Excessive Agency** | 1, 2 | Deny-by-default RBAC plus the MAC ceiling, composed deny-overrides (ADR-0008). Step and tool-call caps (`agent.max_steps` default 8, max 64; `max_tool_calls_per_step` default 4, max 16; `bins/maknae/src/agent.rs`). Every action the shipped loop takes through the plane is audited before it happens. | Open decisions in Rabbithole (#420, vision; no ADR, no code): task classes, separate grants for outbound side effects, workspace confinement, the Agent Daemon. Containment (#165, #149). | Rule of Two session bits (§4.1). Validated tool-argument schemas (§4.3). **Flow rules over tool-call sequences on metadata** (after Invariant, [landscape](2026-09-30-guardrails-landscape-assessment.md) §2.5). |
| **LLM07 System Prompt Leakage** | 1 (by design), 4 | Prompts carry no authority: every decision is the kernel's. Tool definitions and core-prompt security bindings are compiled in as reviewable text (#264), holding no secrets. | — | **Canary tokens:** a nonce in the system prompt, checked for in egress output, with no model needed ([landscape](2026-09-30-guardrails-landscape-assessment.md) §2.6). |
| **LLM08 Vector and Embedding Weaknesses** | 1, 3 | — (no vector store yet) | Lake authority tiers, provenance and quarantine (KLC). | Labels on retrieved chunks feed the same taint (§4.2). Partition by subject in the store. |
| **LLM09 Misinformation** | (application) | Out of the kernel's scope. The trail records a digest and length of what was sent, the reply's length and token usage; it keeps no content. | — | Optional groundedness check as a weak signal. Not a kernel concern. |
| **LLM10 Unbounded Consumption** | 1 | Frame caps (`transport.prompt_max_bytes`). The context budget: the agent warns at 80% and 95% and stops before a turn would exceed the declared context budget (#372). Egress deadline (`egress.deadline_ms`). Step and tool-call caps. Usage tokens recorded per prompt in the trail. | — | **Per-subject and per-task token and call quotas as policy**, decided on the usage the trail already records. |

**Reading the map:**
- **Layer 1 (the PDP) appears in six of the ten rows. Layer 4 (a filter) appears in four,** and in each as a supplement.
- The single idea that reaches the most rows (LLM01, LLM02, LLM06 and LLM08) is provenance taint. It is metadata-only.

## 3. Why a filter cannot be the headline

The four deep dives agree on four points:
- **Scope.**
  - [Prompt Guard 2](2026-09-30-prompt-guard-assessment.md) detects only explicit "ignore previous instructions" phrasing; Meta dropped its broader injection label as "too broad".
  - [Llama Guard](2026-09-30-llama-guard-assessment.md) is a harm-content classifier. An independent ACL 2025 study measured at most 39% accuracy on injected documents.
- **Robustness.**
  - Adaptive attacks exceed 90% success against Prompt Guard when the attacker sees its score.
  - Character smuggling (invisible Unicode, variation selectors, homoglyphs) and word-level perturbation defeat [LLM Guard's](2026-09-30-llm-guard-assessment.md) classifier (67.87%) and NVIDIA's jailbreak model (65–73%).
  - Scores returned to an agent become an oracle for the attacker.
- **Operations.**
  - Every candidate is a Python stack (torch, transformers, often spaCy or onnxruntime).
  - Every candidate downloads models at runtime by default.
  - NeMo Guardrails sends usage telemetry to NVIDIA by default and fails open on its jailbreak rails.
  - LLM Guard is archived; its URL-reachability scanner is an SSRF and exfiltration channel.
- **Licenses.**
  - Meta's Llama licenses incorporate an Acceptable Use Policy, by URL and changeable. Its prohibited uses include activities "that present a risk of death or bodily harm to individuals, including use of Llama 4 related to the following: Military, warfare, nuclear industries or applications, espionage", and ITAR-subject materials (Prompt Guard 2 `USE_POLICY.md`). Read conservatively, that bars a DoD deployment without written clarification from Meta; this is not legal advice. Meta's 2024 national-security announcement is not in the license text.
  - NVIDIA's Open Model License carries a unilateral-update clause.
  - Apache-2.0 alternatives exist: Protect AI's injection classifier; IBM Granite Guardian, whose weights are also Sigstore-signed; Qwen3Guard.

**Latency.** A model-based check costs about 100 ms per 128-token window and several hundred ms per 512-token window on a CPU for the 86M-class classifiers (the 22M-class model is 3–5× cheaper), and scales with the length of a tool result. Content-safety LLMs cost seconds on a CPU. The kernel's own checks add nothing per call.

## 4. The layers in detail

### 4.1 Provenance taint in the PDP (new; highest value)

Meta's "Agents Rule of Two" (Meta AI, 2025-10-31):

> "agents must satisfy no more than two of the following three properties within a session… [A] An agent can process untrustworthy inputs [B] An agent can have access to sensitive systems or private data [C] An agent can change state or communicate externally."

**In Maknae,** A, B and C are properties of what the kernel has already mediated in a session, not of any content:
- **A:** the session has ingested data from outside a trusted set, such as a tool result, a fetched page or an MCP resource.
- **B:** the session holds or has used a grant to an object marked sensitive.
- **C:** the session holds or would use a write, outbound side-effect or egress grant.

**The mechanism:**
- The kernel keeps a monotone three-bit set per session.
- It refuses the action that would complete all three, or requires a separately granted approval for it.
- Sticky, monotone session state is exactly what a reference monitor holds well.
- It adds no latency and needs no model.

**What it buys:** it defeats injections no filter catches, because it does not care what the injected text says.

**Its bound, stated plainly:** the kernel decides every verb the loop sends through the plane, but the loop itself is unconfined. Its own direct I/O, outside the plane, is not mediated (ADR-0023 decisions 2 and 6). Rule of Two in the kernel therefore constrains what the loop does *through Maknae*. It closes the gap only together with confining the loop (Rabbithole #420 decision 9). Sessions (ADR-0023 decision 7, #170) are also a prerequisite: today `maknaed` has no session identity to hang the bits on. It also reuses what Maknae is already building:
- the session model (#170);
- labels (#229) and zones (#147);
- #172 §4's "the ceiling rises on ingest", which is already a monotone high-water mark on the confidentiality axis.

**Open design questions:**
- the task-class vs session grain;
- what counts as a trusted source;
- whether the third property is denied outright or approval-gated.

### 4.2 Integrity labels beside confidentiality labels (new)

**The precedent:** Microsoft's FIDES (arXiv 2505.23643) and Google DeepMind's CaMeL (arXiv 2503.18813) both label data with **confidentiality** (who may read it) and **integrity** (trusted or not), and enforce policy at sinks.
- FIDES's follow-on gateway evaluates those labels as metadata in Rego, via `regorus`, Microsoft's Rust engine.

**Where Maknae stands:**
- Maknae's MAC classification-ceiling operand already decides on a confidentiality marking without reading the content. Today, though, nothing stamps markings above the system's lowest level (#229), so the operand sees only unmarked content.
- An **integrity** axis is the natural second one, e.g. "this value came from an untrusted tool result". It would let the kernel refuse "low-integrity data drives a consequential action" as policy.

**Caveat, from the [landscape](2026-09-30-guardrails-landscape-assessment.md) §3.2–3.3:**
- The *decision* is metadata-only.
- *Propagating* labels through the model's reasoning needs trusted code that handles the content.
- In Maknae the loop is untrusted, so the kernel can only track coarse, per-session or per-object labels from its own mediated flows, unless a trusted interpreter is added. That is a TCB decision.

### 4.3 Native tool constraints (partly built, partly Rabbithole)

**Already built:**
- read-before-write and change detection (#388);
- paged reads carrying the object's label (#372);
- results as data in a field;
- bounded, offered-only tool calls.

**Planned in Rabbithole (#420):**
- named tool operations instead of argv;
- workspace confinement;
- a per-tool network allowlist;
- separate grants for side effects.

**New:**
- Make every tool's argument schema explicit and validated before the kernel decides. #423's 4 KiB write bound becomes a stated schema limit that the model is told about, with a result it can recover from.

### 4.4 A content filter as a weak signal (layer 4)

**Placement and ordering.** ADR-0023 decision 3 fixes the order: `maknaed` decides `session.prompt` and durably records the intent *before* the Egress Daemon receives the turn. A content verdict therefore has value only if it reaches `maknaed` **before** that decision.
- **Placement:**
  - The filter runs in an **unprivileged helper process**.
  - It never runs in the key-holding Egress Daemon itself, because ADR-0002 holds the egress process to Rust and torch, onnxruntime and libyara are C or C++. It never runs in `maknaed` either.
  - `maknaed` consults the helper, or receives its verdict, before deciding.
- **Cost:** a helper beside the Egress Daemon would see content only after the decision, so consulting one is a new channel and an extra round trip on the decision path. That is a real latency cost on every prompt turn, and it is paid only by the checks in §4.4.
- **Latency cannot be hidden by concurrency:**
  - Running the check alongside the model call means content leaves before the verdict exists.
  - The same argument rules out NeMo's speculative generation ([NeMo](2026-09-30-nemo-guardrails-assessment.md) §9).
- **Reply-leg scanning is not possible today:**
  - In Cooky the reply's release verdict is computed before the reply exists (ADR-0023 decision 3).
  - Scanning model replies needs the `session.update` relay leg to become a real decision (#172, #229).
- The kernel weighs the verdict **alongside taint**. The score is **never** returned to the agent.

**In order of value per cost:**
1. **Unicode normalization and a corrected invisible-text check**, in front of everything. This narrows the invisible-character and variation-selector channel that defeated Prompt Guard and the NVIDIA and Protect AI classifiers tested by Hackett et al. It does not address homoglyph substitution. It must cover:
   - variation selectors U+FE00–FE0F and U+E0100–E01EF, which LLM Guard's check misses;
   - tag characters U+E0000–E007F;
   - zero-width and bidi characters;
   - fillers.

   It is pure Rust and runs in microseconds.
2. **Secret and PII patterns in both directions**, in memory with zeroizing buffers.
   - LLM Guard's 94 provider regexes are MIT, and detect-secrets' built-ins are Apache-2.0.
   - It never writes a temp file: LLM Guard's scanner does, with `delete=False`.
3. **Canary tokens** against system-prompt leakage (LLM07).
4. **YARA-X rules** on model output that feeds a tool (LLM05). NeMo's rules are Apache-2.0, and YARA-X is VirusTotal's pure-Rust engine.
5. **Optionally, a DeBERTa injection classifier in pure Rust.** candle's `DebertaV2SeqClassificationModel`, or `tract` at a release containing the July 2026 DeBERTa fixes. Loading details:
   - weights loaded from pinned safetensors;
   - tokenizer via the `tokenizers` crate built without its C features;
   - overlapping 512-token windows, never truncation. Every framework surveyed truncates by default.

   The license-clean choice is Protect AI's Apache-2.0, ungated model, with two caveats: it is archived and unmaintained, and an independent benchmark reports heavy over-defense on benign text that discusses injection (InjecGuard, under 60%). PIGuard (MIT, same base architecture; [landscape](2026-09-30-guardrails-landscape-assessment.md) §2.10) is the alternative to evaluate. Meta's Prompt Guard 2 is stronger on vendor numbers but carries the Llama AUP, so it should be at most an operator-supplied, hash-pinned option. Golden-vector parity tests against the reference model are required.

**Latency budget.** Items 1–4 cost microseconds to milliseconds. Item 5 costs about 100 ms per 128-token window and several hundred ms per 512-token window on a CPU (3–5× less with the 22M-class model), and must complete before the kernel's decision (above). That makes it a per-turn cost to be justified by measurement (§4.5), and a reason to scan only content newly entering the conversation.

### 4.5 Detection and response

- **Built:** the write-ahead audit trail.
- **Planned:** kernel-initiated containment (#149) and the operator stop button (#165).
- **New:** a filter hit, a taint violation or a quota breach can contain a session automatically.

**Test-time tools**, for measuring what the layers actually stop ([landscape](2026-09-30-guardrails-landscape-assessment.md) §2.19):
- NVIDIA garak (Apache-2.0);
- Microsoft PyRIT (MIT);
- promptfoo (MIT, now owned by OpenAI).

A filter's false-negative rate should be a measured number, not a vendor's.

## 5. The candidates at a glance

| Tool | Kind | Code / weights licence | Language | Air-gap as shipped | Verdict for Maknae |
|---|---|---|---|---|---|
| [Meta Prompt Guard 2](2026-09-30-prompt-guard-assessment.md) | DeBERTa injection classifier | MIT (LlamaFirewall wrapper) / Llama 4 Community License + AUP | Python | Partly (gated; runtime download) | Adapt: pure-Rust path, operator-supplied weights only |
| [Meta Llama Guard 3/4](2026-09-30-llama-guard-assessment.md) | Harm-content LLM classifier | MIT / Llama 3.1, 3.2 or 4 License + AUP | Python | Partly | Learn from (taxonomy, first-token scoring); avoid |
| [NVIDIA NeMo Guardrails](2026-09-30-nemo-guardrails-assessment.md) | Orchestration framework (mostly LLM-judged rails) | Apache-2.0 / NVIDIA Open Model License | Python | No (telemetry and cloud endpoints by default) | Learn from; adapt YARA rules, taxonomy, JailbreakDetect design |
| [Protect AI LLM Guard](2026-09-30-llm-guard-assessment.md) | Scanner library | MIT / Apache-2.0 (injection model) | Python | No (runtime downloads) | Archived. Port InvisibleText (fixed), Secrets regexes, the injection model |
| [LlamaFirewall and others](2026-09-30-guardrails-landscape-assessment.md) | Survey of 20+ tools and three architectural defenses | varies | mostly Python | varies | Architectural defenses win; see §4.1–4.2 |

## 6. Recommendations, for maintainer decision

Each is a candidate, ranked by coverage per unit cost. None is scheduled.

| # | Recommendation | OWASP rows | Layer | Latency | Rough size |
|---|---|---|---|---|---|
| 1 | Provenance taint / Rule of Two session bits in the kernel | 01, 02, 06, 08 | 1 | none | M–L (needs sessions #170, labels #229) |
| 2 | Unicode normalization + corrected invisible-text check | 01 | 4 | µs | S |
| 3 | Secret/PII patterns, both directions, in a helper beside the Egress Daemon | 02 | 4 | ms | S–M |
| 4 | Explicit, validated tool-argument schemas (folds in #423) | 05, 06 | 2 | none | M |
| 5 | Per-subject and per-task token and call quotas as policy | 10 | 1 | none | M |
| 6 | Canary tokens | 07 | 4 | µs | S |
| 7 | Integrity labels as a second MAC axis | 01, 02, 08 | 1 | none | L (ADR) |
| 8 | Flow rules over tool-call sequences (metadata) | 06, 02 | 1 | none | M |
| 9 | YARA-X rules on tool-bound output | 05 | 4 | ms | S |
| 10 | Pure-Rust DeBERTa injection signal (Apache-2.0 weights) | 01 | 4 | ~100 ms per 128 tokens, concurrent | L |
| 11 | garak / PyRIT / promptfoo suites against the running system | all (measurement) | test | n/a | M |

## 7. Open questions for the maintainer

1. **Rule of Two:** deny the third property outright, or require a separately granted approval? At what grain: session, task or task class?
2. **Integrity labels:** a second MAC axis in the kernel (an ADR), or coarse per-session taint only?
3. **Guard helper process:** `maknaed` must have the verdict before it decides (§4.4). Is a new unprivileged helper that `maknaed` consults on each prompt turn acceptable, given the extra round trip on the decision path? Or should the cheap deterministic checks (items 1–4) run somewhere already on that path? Which of items 1–5 in §4.4 go first?
4. **Guard models:** is any guard model wanted at all? If so, is Apache-2.0-only a rule, which would rule out Meta's models for the DoD target?
5. **Red-team harness:** should one run in CI, and against which provider?

## 8. Sources

**The assessment set:**
- [Meta Prompt Guard](2026-09-30-prompt-guard-assessment.md)
- [Meta Llama Guard](2026-09-30-llama-guard-assessment.md)
- [NVIDIA NeMo Guardrails](2026-09-30-nemo-guardrails-assessment.md)
- [Protect AI LLM Guard](2026-09-30-llm-guard-assessment.md)
- [Guardrails landscape and architectural defenses](2026-09-30-guardrails-landscape-assessment.md)

Each pins its subjects to a commit or model revision and carries its own sources.

**OWASP:**
- [LLM Top 10 2025](https://genai.owasp.org/llm-top-10/)
- [LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- [LLM07](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/)

All fetched 2026-09-30.

**Architectural defenses:**
- Meta, ["Agents Rule of Two: A Practical Approach to AI Agent Security"](https://ai.meta.com/blog/practical-ai-agent-security/) (2025-10-31)
- Debenedetti et al., CaMeL, [arXiv 2503.18813](https://arxiv.org/abs/2503.18813)
- Costa et al., FIDES, [arXiv 2505.23643](https://arxiv.org/abs/2505.23643)

**Independent evaluations** (context):
- Nasr, Carlini et al., [arXiv 2510.09023](https://arxiv.org/abs/2510.09023)
- Hackett et al., [arXiv 2504.11168](https://arxiv.org/abs/2504.11168)
- Chen et al., [ACL 2025](https://aclanthology.org/2025.acl-long.890.pdf)
- Li et al., InjecGuard, [arXiv 2410.22770](https://arxiv.org/abs/2410.22770)

**Maknae evidence** (at `dc364cb`):
- `packaging/common/authz.yaml`
- `bins/maknae/src/agent.rs`
- `crates/maknae-llm/src/wire.rs`
- `crates/maknae-proto/src/wire.rs`
- ADR-0002, ADR-0005, ADR-0008, ADR-0022, ADR-0023, ADR-0026, ADR-0027
- the [Knowledge Lifecycle Contract](../knowledge-lifecycle-contract.md)
