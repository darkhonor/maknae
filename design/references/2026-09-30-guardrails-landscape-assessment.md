# Runtime LLM Guard Tools and Architectural Defenses — Landscape Assessment Against Maknae

| | |
|---|---|
| **Status** | Assessment record. It informs the OWASP LLM coverage work. It creates no roadmap commitment and supersedes no ADR. |
| **Date** | 2026-09-30 |
| **Subject** | A survey of 20+ runtime guard tools, managed services and red-team scanners, plus three architectural defenses (Meta's Agents Rule of Two, Google DeepMind's CaMeL, Microsoft's FIDES), set against the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/). Each subject is pinned to a commit, model revision or dated document in §5. Licenses vary per tool and are stated in §2. |
| **Method** | A survey, not a deep dive. Two repositories were mirrored outside this tree and **read only** (`guardrails-ai/guardrails` at `06d0ff2c`, `invariantlabs-ai/invariant` at `2340fe2d`), together with the READMEs and model cards of the other subjects at their pinned revisions. Nothing was built, installed or executed, and no weight files were downloaded. Evidence labels: **[code]** read at the pinned commit or revision; **[card]** a model card or vendor documentation at the pinned revision or date, documented by the vendor and not measured; **[web]** public web material (press, blogs, search snippets), context not evidence; **[inferred]** reasoning. Public web material is context only and is marked as such. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |

This assessment is the landscape survey behind the synthesis [`2026-09-30-owasp-llm-top10-coverage.md`](2026-09-30-owasp-llm-top10-coverage.md). Four candidates have their own deep-dive assessments and appear here only as cross-references: [Meta Prompt Guard](2026-09-30-prompt-guard-assessment.md), [Meta Llama Guard](2026-09-30-llama-guard-assessment.md), [NVIDIA NeMo Guardrails](2026-09-30-nemo-guardrails-assessment.md) and [Protect AI LLM Guard](2026-09-30-llm-guard-assessment.md).

**The Maknae context.** Maknae is evaluating a content and prompt-injection filter as a Policy Information Point (PIP), never a Policy Decision Point (PDP). Under ADR-0023's write-ahead order its verdict must reach `maknaed` before the `session.prompt` decision, which is made before the Egress Daemon (`maknae-egress`) receives the turn: `maknaed` stays the sole PDP (ADR-0005), and content informs but never authorizes (AGENTS.md core principle 2). This survey asks two questions: which OWASP rows any runtime filter can cover at all, and which defenses are architectural, so that the kernel could decide them on metadata.

## 0. The OWASP list itself

The 2025 list was verified at <https://genai.owasp.org/llm-top-10/>, fetched 2026-09-30. The page lists "LLM TOP 10 FOR 2025" with these IDs, in this order:

| ID | Name |
|---|---|
| LLM01:2025 | Prompt Injection |
| LLM02:2025 | Sensitive Information Disclosure |
| LLM03:2025 | Supply Chain |
| LLM04:2025 | Data and Model Poisoning |
| LLM05:2025 | Improper Output Handling |
| LLM06:2025 | Excessive Agency |
| LLM07:2025 | System Prompt Leakage |
| LLM08:2025 | Vector and Embedding Weaknesses |
| LLM09:2025 | Misinformation |
| LLM10:2025 | Unbounded Consumption |

The list examined matches this exactly.

OWASP's own risk pages carry three statements that are load-bearing for this survey. All were fetched 2026-09-30.

- **LLM01** (<https://genai.owasp.org/llmrisk/llm01-prompt-injection/>): "it is unclear if there are fool-proof methods of prevention for prompt injection". Its mitigations include "Enforce privilege control and least privilege access … handle these functions in code rather than providing them to the model."
- **LLM06** (<https://genai.owasp.org/llmrisk/llm062025-excessive-agency/>), mitigation 7, "Complete mediation": "Implement authorization in downstream systems rather than relying on an LLM to decide if an action is allowed or not."
- **LLM07** (<https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/>): "the system prompt should not be considered a secret, nor should it be used as a security control."

**Taxonomy gap.** The 2025 Top 10 has **no "harmful / toxic content" row**. Content-safety classifiers (ShieldGemma, most of Llama Guard, the Granite Guardian harm criteria) therefore map weakly to it, although they are the bulk of the guard-model market.

## 1. Coverage matrix: runtime only

**How to read the matrix:**

- **✓** means a documented, purpose-built runtime detector or control for that row.
- **partial** means one of three things:
  - it detects a symptom of the row, but not the row;
  - it works only when configured with bring-your-own criteria or policy;
  - it is scan-time only, with no runtime component.
- **—** means no runtime coverage.

Ratings are **[inferred]** from **[code]** or **[card]** evidence cited in §2.

### 1.1 Self-hostable / open

| Tool | 01 PI | 02 SID | 03 SC | 04 Pois | 05 Out | 06 Agency | 07 SPL | 08 Vec | 09 Misinfo | 10 Cons |
|---|---|---|---|---|---|---|---|---|---|---|
| Meta LlamaFirewall | ✓ | partial | — | — | partial | partial | — | — | — | — |
| IBM Granite Guardian 4.1 / 3.x | partial | partial | — | — | — | partial | — | partial | partial | — |
| Google ShieldGemma (1 and 2) | — | — | — | — | — | — | — | — | — | — |
| Guardrails AI (+ validators) | partial | ✓ | — | — | ✓ | — | partial | — | partial | — |
| Invariant Guardrails (Snyk) | partial | ✓ | — | — | partial | ✓ | — | — | — | — |
| Snyk Agent Scan (ex-mcp-scan) | — | — | partial | — | — | — | — | — | — | — |
| Vigil (deadbits) | partial | — | — | — | — | — | partial | — | — | — |
| Rebuff (Protect AI) — **archived** | partial | — | — | — | — | — | partial | — | — | — |
| WhyLabs LangKit | partial | partial | — | — | — | — | — | — | partial | — |
| Arthur Engine | partial | ✓ | — | — | — | — | — | — | partial | — |
| deepset deberta-v3-base-injection | partial | — | — | — | — | — | — | — | — | — |
| Qwen3Guard (Gen / Stream) | partial | partial | — | — | — | — | — | — | — | — |
| OpenAI gpt-oss-safeguard | partial | partial | — | — | — | — | partial | — | — | — |
| Cisco Foundation-sec-8B | — | — | — | — | — | — | — | — | — | — |
| NVIDIA OpenShell (Open Agent Safety Platform) | — | partial | — | — | — | ✓ | — | — | — | partial |

The OpenShell row describes an architectural runtime, not a filter. Its **LLM10** cell is inferred from the runtime's resource confinement, which was not verified in detail.

### 1.2 Cross-references to the deep-dive assessments

For these rows, the individual assessments are authoritative.

| Tool | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| [Meta Prompt Guard 2](2026-09-30-prompt-guard-assessment.md) | ✓ | — | — | — | — | — | — | — | — | — |
| [Meta Llama Guard 4](2026-09-30-llama-guard-assessment.md) | partial | partial | — | — | partial | — | — | — | — | — |
| [NVIDIA NeMo Guardrails](2026-09-30-nemo-guardrails-assessment.md) | ✓ | ✓ | — | — | partial | partial | partial | — | partial | — |
| [Protect AI LLM Guard](2026-09-30-llm-guard-assessment.md) | ✓ | ✓ | — | — | partial | — | — | — | partial | partial |

These cells are a rough placement only. Defer to the individual assessments; in particular, the Llama Guard assessment finds that Llama Guard is not a prompt-injection detector at all, which is why its LLM01 cell is only partial.

### 1.3 Managed services

These are listed for completeness. They are proprietary, and two of them have a self-hosted edition (§2.16–2.18).

| Service | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| Lakera Guard → "Check Point AI Guardrails" | ✓ | ✓ | — | — | partial | — | — | — | — | — |
| Azure AI Content Safety: Prompt Shields | ✓ | — | — | — | — | — | — | — | partial | — |
| Google Model Armor | ✓ | ✓ | — | — | partial | — | — | — | — | — |
| AWS Bedrock Guardrails | ✓ | ✓ | — | — | — | — | — | — | partial | — |
| Cisco AI Defense | ✓ | ✓ | partial | — | — | — | — | — | — | — |

**Notes on the managed rows:**

- **Azure:** the LLM09 cell comes from the separate groundedness-detection API in Content Safety.
- **Bedrock:** the LLM09 cell comes from contextual grounding and Automated Reasoning checks.
- **Cisco:** the LLM03 cell comes from the model-validation half of the product. That half is pre-deployment testing, not runtime.

### 1.4 Red-team scanners

These are test-time tools, not runtime tools. None of them enforces anything at runtime. §2.19 describes what each would test.

## 2. Per-tool notes

### 2.1 Meta LlamaFirewall

**Correction to a commonly repeated claim:** LlamaFirewall is more than Prompt Guard plus AlignmentCheck. It is Prompt Guard 2 + AlignmentCheck + CodeShield + a regex scanner + a hidden-ASCII scanner + an experimental PII check.

- **Owner and provenance:** Meta. It lives in `meta-llama/PurpleLlama/LlamaFirewall`.
  - Paper: arXiv 2505.03574 (May 2025) **[web]**.
  - No ownership change.
- **Pin:** PurpleLlama @ `172c1074069eb88ec834124272c1b1c4f8893445` (2026-09-29).
  - The last commit touching `LlamaFirewall/` is `4be64c3a` (2026-08-18, lint-only).
  - PyPI `llamafirewall` 1.0.3 was uploaded 2025-05-29 and has not been re-released since.
  - Not archived. The code is maintained, but releases are stale. **[code]**
- **License:**
  - **Code:** `LlamaFirewall/LICENSE` and `CodeShield/LICENSE` are **MIT**. The repository-root `LICENSE` is the **Llama 3.2 Community License**, which is why GitHub reports `NOASSERTION`.
  - **Weights:** the Prompt Guard 2 weights are under the Llama 4 Community License. See the [Prompt Guard assessment](2026-09-30-prompt-guard-assessment.md) §2.
  - **AlignmentCheck:** ships no weights. By default it calls a hosted LLM. **[code]**
- **Scanners** (under `LlamaFirewall/src/llamafirewall/scanners/`) **[code]**:
  - `prompt_guard_scanner.py`: Prompt Guard 2.
  - `experimental/alignmentcheck_scanner.py`: an LLM-as-judge over the **full trace** (`require_full_trace = True`). It inherits from `custom_check_scanner.py:35-37`, whose defaults are `model_name="meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8"`, `api_base_url="https://api.together.xyz/v1"` and `TOGETHER_API_KEY`.
  - `experimental/piicheck_scanner.py:46-48`: an LLM-as-judge on `Llama-3.3-70B-Instruct-Turbo` via Together.
  - `regex_scanner.py:21-28`: six default patterns. The only injection pattern is `ignore previous instructions|ignore all instructions`; the others match email, phone, card and SSN.
  - `hidden_ascii_scanner.py`: flags and decodes Unicode tag characters U+E0000–E007F.
  - `code_shield_scanner.py`: CodeShield, which runs Semgrep and regex over 8 languages. `CodeShield/pyproject.toml` depends on `semgrep>1.68`.
- **Language and runtime:** Python. It depends on torch, transformers, huggingface_hub, openai and codeshield (`LlamaFirewall/pyproject.toml`). By default it downloads models from Hugging Face (`LlamaFirewall/README.md:141`).
- **Self-hostable and air-gap-capable:** yes, but only partly.
  - Prompt Guard, regex, hidden-ASCII and CodeShield are local. Semgrep is an OCaml binary.
  - AlignmentCheck and PIICheck need an OpenAI-compatible endpoint. Pointing them at a local Llama model is possible **[inferred]**, but it is an extra 17B–70B-class model to serve.
- **OWASP coverage:**
  - **LLM01** ✓: Prompt Guard for direct and indirect injection, AlignmentCheck for goal hijack across the trace, and tag-character smuggling.
  - **LLM02** partial: PII regex plus the LLM check.
  - **LLM05** partial: insecure generated code (CodeShield).
  - **LLM06** partial: AlignmentCheck flags misaligned actions, but grants and denies nothing.
- **Rust reuse:** port the hidden-ASCII and regex scanners trivially (S). CodeShield's Semgrep rules could be evaluated by a Rust Semgrep subset, which is not trivial. Prompt Guard: see its [assessment](2026-09-30-prompt-guard-assessment.md) §10. The AlignmentCheck *prompt* (`alignmentcheck_scanner.py:134-240`) is reusable text under MIT.

### 2.2 IBM Granite Guardian

- **Owner:** IBM, org `ibm-granite`. No ownership change.
- **Versions on Hugging Face** **[code: HF API]**:
  - hap-38m and hap-125m (2024-09)
  - 3.0-2b and 3.0-8b (2024-10)
  - 3.1-2b and 3.1-8b (2024-12)
  - 3.2-5b and 3.2-3b-a800m (2025-01/02)
  - 3.3-8b (2025-06)
  - 3.2-5b LoRAs for harm-categories and harm-correction (2025-08)
  - 3.2-8b factuality-detection (2025-11)
  - `granitelib-guardian-r1.0` (2026-02)
  - 4.0-3b-toxicity-ja (2026-04)
  - **4.1-8b (2026-04-16, current)**, plus GGUF builds
- **Pins:**
  - `granite-guardian-4.1-8b` @ `ab01ccca5dcfb80246369a086a4a87a29198f5af`
  - `granite-guardian-3.3-8b` @ `b3421eda`
  - `granite-guardian-hap-38m` @ `faf92911`
  - GitHub `ibm-granite/granite-guardian` @ `9698a428` (2026-08-26)
- **License:** **Apache-2.0 for both code and weights** (HF tag, and the 4.1-8b model card `README.md:45`). The weights are **not gated**.
  - The weights are safetensors.
  - 4.1 ships **`model.sig`, a Sigstore bundle** (`application/vnd.dev.sigstore.bundle.v0.3+json`, certificate dated 2026-08-27) **[code]**. This is the only candidate in this survey with signed weights.
- **What it is:**
  - 4.1 is an 8B decoder (a fine-tune of `granite-4.1-8b`) run as a yes/no judge, with a `<think>` mode and a `<no-think>` mode.
  - **Pre-baked criteria** (4.1-8b model card `README.md:125-140`):
    - Harm, with the sub-criteria Social Bias, **Jailbreaking**, Violence, Profanity and Unethical Behavior
    - RAG: **Context Relevance** and **Groundedness**
    - Agentic: **Function Calling Hallucination**, meaning a call that does not match the tool schema or is inconsistent with the query
  - It also accepts **Bring Your Own Criteria** (BYOC).
  - "only trained and tested on English data" (4.1-8b model card `README.md:458`).
  - **The commonly cited criteria list is confirmed:** harm, jailbreak, groundedness/hallucination and function-call hallucination.
  - HAP-38M is a RoBERTa sequence classifier (38M parameters) for hate, abuse and profanity only.
- **Language and runtime:** transformers or vLLM on Python. GGUF builds exist for llama.cpp.
- **Self-hostable and air-gap-capable:** yes. The weights are Apache-2.0 and ungated.
- **OWASP coverage:**
  - **LLM01** partial: a jailbreak criterion, not trained for indirect injection. BYOC can express that, but it is unmeasured.
  - **LLM02** partial: via BYOC only.
  - **LLM06** partial: function-call hallucination catches *malformed or unrequested* calls, not unauthorized ones.
  - **LLM08** partial: context relevance.
  - **LLM09** partial: groundedness is relative to the supplied documents only.
- **Rust reuse:**
  - HAP-38M: RoBERTa via `candle` or `tract` (S–M).
  - 8B judge: `candle` can run Granite/Llama-family decoders **[inferred]**, but an 8B judge on every call contradicts the latency constraint (L).
  - The criterion texts are Apache-2.0 and reusable.

### 2.3 Google ShieldGemma

- **Owner:** Google.
  - **ShieldGemma 1:** 2B, 9B and 27B, on Gemma 2, released 2024-07.
  - **ShieldGemma 2:** 4B, on Gemma 3, released 2025-03. It is an **image** safety classifier (ShieldGemma 2 model card).
- **Pins:** `google/shieldgemma-2b` @ `d1dffc9c8c9237a90aab09c61383791e718ef9e8` and `google/shieldgemma-2-4b-it` @ `eaf60452`. **No new ShieldGemma has shipped since 2025-04 [web: ai.google.dev/gemma/docs/releases].**
- **License:** HF tag `license:gemma`, with **gated=manual**.
  - The Gemma Terms of Use (<https://ai.google.dev/gemma/terms>, "Last modified: April 1, 2026") still list ShieldGemma and ShieldGemma 2 in the Appendix.
  - **Gemma 4 moved to Apache-2.0 (2026-04) [web], but ShieldGemma did not.**
  - Terms that matter for Maknae:
    - **§3.1:** redistribution must include the §3.2 use restrictions as an enforceable provision, give recipients a copy of the Agreement, and mark modified files.
    - **§3.2:** the **Prohibited Use Policy is incorporated by reference**, and "Google reserves the right to restrict (remotely or otherwise) usage of any of the Gemma Services that Google reasonably believes are in violation."
  - **[inferred; not legal advice]** Redistribution inside an air-gapped package appears permitted, provided those pass-through obligations are met. The remote-restriction clause has no technical mechanism on an air-gapped host **[inferred]**, but it is a contractual risk.
- **What it is:** a decoder LLM run in scoring mode, returning P(Yes) against a policy text. It has four harm policies: Sexually Explicit, Dangerous Content, Hate and Harassment (model card, updated 2025-02-25). It is English-only, and there is **no injection or jailbreak policy**.
- **OWASP coverage:** none directly. It is content safety, which is off-taxonomy.
- **Rust reuse:** Gemma-2 in `candle` is feasible (M). The license and the lack of any injection capability make it a poor fit. **Learn from:** the policy-as-prompt scoring pattern.

### 2.4 Guardrails AI

**Correction to a commonly repeated claim:** that validators are fetched from a private registry is out of date as of 0.11.0.

- **Owner:** Guardrails AI, Inc. No acquisition found.
- **Pin:** `guardrails-ai/guardrails` @ `06d0ff2c5f9bcb493d976b76f885e37e41ce845d`, release v0.11.0 (2026-08-14). `guardrails-api` @ `14a9fe16` (GitHub reports its license as NOASSERTION; not examined further).
- **License:** `pyproject.toml:8` is "Apache License 2.0". Each validator is its own repository, and all the ones checked are Apache-2.0.
  - Checked: `detect_prompt_injection` @ `f76a208e`, `detect_jailbreak` @ `b3451714` and `detect_system_prompt_leakage` @ `2a09e2b6`.
  - The models *they* wrap carry their own licenses.
- **How validators are fetched** **[code: `docs/migration_guides/hub-to-public-pypi.md`]**:
  - As of 0.11.0, Guardrails-owned validators moved from the token-gated private index `pypi.guardrailsai.com` to **public PyPI** as `guardrails-ai-<name>`.
  - `guardrails hub install` is deprecated, and removal is planned for the next major release.
  - Validators that "ship local models" need a post-install step, which fetches the models.
- **Telemetry (important for an air-gapped deployment)** **[code]**:
  - `guardrails/classes/rc.py:17`: `enable_metrics: Optional[bool] = True`, so telemetry is on by default.
  - `guardrails/utils/hub_telemetry_utils.py:50-51` exports OTLP spans to `https://hty0gc1ok3.execute-api.us-east-1.amazonaws.com/v1/traces`.
  - `use_remote_inferencing` defaults to False (`rc.py:18`). When it is on, `validator_base.py` POSTs content to the Guardrails remote-inference service with a hub JWT.
- **What it is:** a validation framework, with Pydantic/JSON-schema structured-output validation, re-ask and fix-up. It is not a detector itself. Relevant validators:
  - `detect_prompt_injection`: **the Rebuff library, which needs Pinecone and OpenAI**. It is not air-gap-capable.
  - `detect_jailbreak`: wraps `jackhhao/jailbreak-classifier`.
  - `detect_system_prompt_leakage`: a `rapidfuzz` fuzzy match of the output against the system prompt.
  - `detect_pii` and `guardrails_pii`: Presidio, GLiNER.
  - `secrets_present`, `valid_sql`, `exclude_sql_predicates`, `web_sanitization`, `provenance_llm` and `provenance_embeddings`.
- **Self-hostable and air-gap-capable:** yes, with care. Turn metrics off, keep remote inferencing off, pre-stage wheels and models, and avoid the Rebuff-based validator.
- **OWASP coverage:**
  - **LLM05** ✓: output schema and type validation is its core purpose.
  - **LLM02** ✓: PII and secrets.
  - **LLM01** partial.
  - **LLM07** partial: string similarity only.
  - **LLM09** partial: provenance validators.
- **Rust reuse:** the *pattern*, "a typed validator chain with on-fail actions", maps directly onto a Rust trait (S–M). `serde` plus JSON-schema validation of model output is native (S). Fuzzy system-prompt-echo detection is S (the `strsim` or `rapidfuzz` crates).

### 2.5 Invariant Labs: Invariant Guardrails and MCP-scan (now Snyk)

**Corrections to commonly repeated claims:**

- **Acquirer:** Snyk is confirmed. Snyk announced the acquisition of Invariant Labs, an ETH Zürich spin-off, on **2025-06-24** **[web: snyk.io/news/snyk-acquires-invariant-labs…; inf.ethz.ch 2025-06-25]**.
- **Rename:** `invariantlabs-ai/mcp-scan` now redirects to **`snyk/agent-scan`**, "Snyk Agent Scan".

**Invariant Guardrails** (`invariantlabs-ai/invariant`)

- **Pin:** @ `2340fe2d9cd619f73d5b67fa05bf8a08c7cad515`, last commit 2026-01-12.
  - PyPI `invariant-ai` 0.3.5 was released 2025-07-28.
  - Not archived, but **dormant for about 9 months**.
- **License:** Apache-2.0.
- **What it is:** a Python-like **rule DSL over agent traces**. Its rules can match *sequences* of tool calls, for example "`get_inbox` → `send_email` to an external address" (README).
- **Built-in detectors** (under `invariant/analyzer/runtime/utils/`) **[code]**:
  - `prompt_injections.py:7`: `protectai/deberta-v3-base-prompt-injection-v2`.
  - `moderation.py:6`: `KoalaAI/Text-Moderation`.
  - `pii.py`: Presidio.
  - `secrets.py`: regexes copied from Yelp detect-secrets.
  - `code.py:194-196`: Semgrep with `r/python.lang.security` / `r/bash`, which are **registry rule packs fetched from semgrep.dev** at run time.
- **Remote by default** **[code]:**
  - `invariant/analyzer/policy.py:189`: `Policy = LocalPolicy if os.getenv("LOCAL_POLICY","0")=="1" else RemotePolicy`.
  - `invariant/analyzer/remote_policy.py:24-30`: "the default policy runs remotely" at `https://explorer.invariantlabs.ai`.
  - `LocalPolicy` works offline, but only when used explicitly.
- **OWASP coverage:**
  - **LLM06** ✓: trace-level flow rules on tool calls. This is the closest thing in the survey to a policy over *actions*.
  - **LLM02** ✓: PII and secrets.
  - **LLM01** partial: a DeBERTa classifier.
  - **LLM05** partial: Semgrep over code.
- **Rust reuse:** the **flow-rule idea** (a pattern over the sequence of tool calls and data provenance) is the most transferable asset. `maknaed` already decides every verb the loop sends through the plane, so it could express such rules over **metadata** with no content inspection. It would be a native DSL or Rego via `regorus` (M).

**Snyk Agent Scan** (ex-mcp-scan)

- **Pin:** `snyk/agent-scan` @ `2d244047643decb874a197bc64cbe6fc3e586f2a`, v0.6.8, 2026-09-29.
- **License:** Apache-2.0.
- **Releases:** the release binaries are GPG-signed, with an SBOM (`README.md:73`, `:220-228`).
- **What it is:** a **scanner** that discovers agent configs, MCP servers and skills, and checks them for tool poisoning, prompt injection in descriptions, and similar.
  - It **requires a `SNYK_TOKEN`** (`README.md:77-80`) and uses Snyk's analysis API (`2026-07-10`).
  - It is **not air-gap-capable** and not runtime.
  - The older mcp-scan "proxy/guardrails" runtime mode is not in the current README.
- **OWASP coverage:** **LLM03** partial, at scan time.

### 2.6 Vigil (deadbits/vigil-llm)

**Not archived, but abandoned.**

- **Pin:** @ `f2b4c134d060bae81d29fad07003f3c657e63fc8`. The last commit was 2024-01-31. The last release is v0.10.3-alpha (2023-12-31). Not on PyPI.
- **License:** Apache-2.0.
- **Maturity:** the README calls itself "**alpha** … experimental / for research purposes" (`README.md:8`).
- **Scanners:**
  - YARA heuristics, which need libyara (C).
  - A vector-DB similarity scanner.
  - A transformer classifier.
  - **Canary tokens**.
  - Sentiment.
- **OWASP coverage:**
  - **LLM01** partial.
  - **LLM07** partial: a canary token placed in the system prompt reveals leakage when it is echoed.
- **Rust reuse:** the **canary-token technique** is S and worth taking. It is a nonce in the system prompt, checked for in egress output, and it needs no model. YARA signatures could run on `yara-x`, VirusTotal's Rust rewrite **[inferred; not verified here]**.

### 2.7 Rebuff (protectai/rebuff)

**Archived: confirmed.**

- **Pin:** GitHub `archived: true`. The last commit is `4d2fe064abf164e7381556d23e48e210080f8afa` (2024-01-25). v0.1.1 was released 2024-01-20.
- **License:** Apache-2.0.
- **Owner:** Protect AI, which Palo Alto Networks acquired; the acquisition completed 2025-07-22 **[web: paloaltonetworks.com press]**.
- **Mechanism:** heuristics, an LLM judge (OpenAI), a vector DB (Pinecone or Chroma) and canary tokens.
- **Air gap:** not as shipped.
- **OWASP coverage:** **LLM01** partial and **LLM07** partial (canary).
- **Rust reuse:** the canary idea only. **Avoid** the code.

### 2.8 WhyLabs LangKit

- **Owner:** WhyLabs. **Apple acquired WhyLabs (reported as January 2025); the commercial platform was discontinued and open-sourced [web: third-party sources only, unconfirmed by a primary source].**
- **Pin:** `whylabs/langkit` @ `5d6cab1e2ff32181ba5c514aaa2a4473421dc413`, last commit 2024-11-22. v0.0.35 was released 2024-11-06.
- **License:** Apache-2.0. Not archived, but dormant.
- **Modules** **[code: tree]**:
  - `injections.py`: embedding similarity to known attacks
  - `themes.py`: jailbreak and refusal themes
  - `regexes.py` / `pii.py`
  - `toxicity.py`
  - `response_hallucination.py`: an LLM consistency check
  - `sentiment.py`, `textstat.py`, `topics.py`
- **Design intent:** it is **observability** (whylogs metrics), not enforcement.
- **OWASP coverage:** **LLM01**, **LLM02** and **LLM09**, all partial.
- **Rust reuse:** the regex sets and the embedding-similarity approach (S–M). Low value.

### 2.9 Arthur Engine (arthur-ai/arthur-engine)

- **Owner:** Arthur AI. It was open-sourced on 2025-03-31 **[web: arthur.ai blog]**.
- **Pin:** @ `0bc34e0b28d7a0ca319f0f1620295e82f59c2835` (2026-09-29).
- **License:** MIT. Active.
- **What it is:** a guardrail and evaluation service (FastAPI). Its checks **[code]** are:
  - **Prompt injection:** `ProtectAI/deberta-v3-base-prompt-injection-v2` (`utils/model_load.py:217,330`).
  - **Toxicity:** `s-nlp/roberta_toxicity_classifier` plus `tarekziade/pardonmyai` ONNX.
  - **PII:** GLiNER (`urchade/gliner_multi_pii-v1`) plus Presidio.
  - **Hallucination:** a claim classifier. A committed **`.pth` pickle** exists at `scorer/checks/hallucination/claim_classifier/354ec0a4….pth`, and there is an LLM judge (OpenAI or Azure).
  - **Sensitive data:** an LLM judge (`sensitive_data/custom_examples.py:7`, `ChatOpenAI`/`AzureChatOpenAI`).
  - Keyword and regex checks.
  - Models are fetched from Hugging Face.
- **Supply-chain notes:**
  - The pickle file.
  - The README (around `README.md:101-114`) contains instructions addressed to AI coding agents: fetch SKILL.md files from `raw.githubusercontent.com` and save them into the agent's skills directory. They were treated as data and not followed. This is an injection-shaped pattern in a security vendor's README.
- **OWASP coverage:**
  - **LLM02** ✓.
  - **LLM01** partial: the same DeBERTa model as LLM Guard.
  - **LLM09** partial.
- **Rust reuse:** nothing unique beyond what the [LLM Guard assessment](2026-09-30-llm-guard-assessment.md) §10 already covers.

### 2.10 deepset deberta-v3-base-injection

- **Pin:** HF `deepset/deberta-v3-base-injection` @ `80dda00d0b0d9a03917a7685e2ddbcd28e04dbb1`. It was created 2023-05 and last modified 2024-10.
- **License:** MIT.
- **Model:** DeBERTa-v3-base, about 184M parameters. Not gated.
- **What it is:** a binary injection classifier trained on the small `deepset/prompt-injections` set. It is an early 2023 model, superseded in practice by the ProtectAI v2 model, Prompt Guard 2 and PIGuard (`leolee99/PIGuard`, MIT, 2025, same base).
- **OWASP coverage:** **LLM01** partial.
- **Rust reuse:** DeBERTa-v2/v3 in `candle` is possible (it has a `debertav2` model) **[inferred]**. ONNX export plus `tract` also works (M). Weights are MIT-redistributable.

### 2.11 Qwen3Guard (Alibaba Qwen)

A 2025 entrant, added to the list examined.

- **Pins:** `Qwen/Qwen3Guard-Gen-0.6B` @ `fada3b2f` and `Qwen/Qwen3Guard-Stream-4B` @ `0e281784` (modified 2026-09-27). GitHub `QwenLM/Qwen3Guard` @ `6a52eca9`.
- **License:** Apache-2.0 weights, not gated.
- **Sizes:** Gen comes in 0.6B, 4B and 8B.
- **Stream:** attaches **token-level classification heads**, so output can be moderated *while it streams*.
- **Labels:** three tiers, Safe, Controversial and Unsafe.
- **Categories:** Violent, Non-violent Illegal Acts, Sexual, **PII**, Suicide & Self-Harm, Unethical Acts, Politically Sensitive Topics, Copyright Violation and **Jailbreak** (model card `README.md:48`).
- **Languages:** 119.
- **OWASP coverage:** **LLM01** partial (jailbreak, not indirect injection) and **LLM02** partial.
- **Rust reuse:** Qwen3 is supported by `candle` **[inferred]**. The 0.6B model is the smallest generative guard in this survey. The streaming-head design would matter to Maknae only if the Egress Daemon streamed replies. It does not today: the provider call is a single non-streaming chat completion (`stream: false`, `crates/maknae-llm/src/wire.rs:35-37` at `dc364cb`). (M–L.)

### 2.12 OpenAI gpt-oss-safeguard

A 2025 entrant, added to the list examined.

- **Pin:** `openai/gpt-oss-safeguard-20b` @ `8a11e17b`. GitHub `openai/gpt-oss-safeguard` @ `7ec06bb9`.
- **License:** Apache-2.0 plus the gpt-oss usage policy **[card; web: openai.com 2025-10-29]**.
- **Sizes:** 20B and 120B MoE.
- **What it is:** a **bring-your-own-policy** reasoning classifier.
- **OWASP coverage:** partial for any row expressible as a written policy (LLM01, LLM02, LLM07).
- **Fit:** far too heavy for per-call inline use.

### 2.13 Cisco Foundation AI

**Correction to a commonly repeated claim: Cisco Foundation AI is not a guard model.**

- **Models:** Foundation-sec-8B, plus its Instruct, Reasoning and 1.1 variants, are **general cybersecurity LLMs** on Llama 3.1 8B. Examples include threat intelligence and CVE reasoning.
- **Pins:** `fdtn-ai/Foundation-Sec-8B` @ `9e6bb1f7` is tagged Apache-2.0. `Foundation-Sec-8B-Instruct` @ `aa13cb99` is tagged `license:other` / `llama`.
  - The Llama 3.1 base implies that the Llama 3.1 Community License terms may flow through **[inferred; not resolved]**.
- **New gated model:** `fdtn-ai/antares-1b` / `antares-350m` (2026-07, a Granite-4.0 fine-tune, Apache-2.0 tag, gated). **Its purpose is unverified** because the card is gated.
- **OWASP coverage:** none as a runtime filter.

### 2.14 NVIDIA Open Agent Safety Platform (announced 2026-09-28)

**Pieces verified** **[web: nvidianews.nvidia.com/news/open-agent-safety-platform, 2026-09-28]**:

- **NVIDIA OpenShell**, open-source software. It is "a secure runtime boundary that traces all actions and enforces policy".
- **NVIDIA Sentry**, a **reference system design**. It is "an out-of-band watchdog that runs on NVIDIA BlueField-4 DPUs… can quarantine agents".

**It is not a content filter.** The press release names no new guard model. For content safety NVIDIA continues to point at NeMo Guardrails and NemoGuard, which are covered by the [NeMo Guardrails assessment](2026-09-30-nemo-guardrails-assessment.md).

**OpenShell:**

- **Pin:** `NVIDIA/OpenShell` @ `5c0c9e446ed3b11e21198058873b0c6adfee6b4e`. Release v0.1.2 was 2026-09-28.
- **License and language:** Apache-2.0, **Rust**.
- **Mechanism** (`README.md:23-26`):
  - Kernel-level sandboxing of file access, syscalls and network connections.
  - Credentials are injected only for approved endpoints.
  - Formal verification of policy changes.
- **Platforms:** Linux, macOS on Apple Silicon, and WSL2 (experimental).
- **Telemetry:** anonymous telemetry is **on by default**. It is disabled with `OPENSHELL_TELEMETRY_ENABLED=false` or compiled out (`README.md:85`).
- **Prior assessment:** Maknae has already assessed OpenShell in depth: the [OpenShell assessment](2026-09-29-openshell-assessment.md) (#416), which pins OpenShell at the earlier commit `1358941`.
- **Sentry:** hardware-bound (BlueField-4). It is not software a home lab can run.
- **OWASP coverage:**
  - **LLM06** ✓: architectural.
  - **LLM02** partial: secrets never enter the sandbox.
  - **LLM10** partial [inferred].

### 2.15 Meta Prompt Guard, Llama Guard, NeMo Guardrails, LLM Guard

See their assessments: [Prompt Guard](2026-09-30-prompt-guard-assessment.md), [Llama Guard](2026-09-30-llama-guard-assessment.md), [NeMo Guardrails](2026-09-30-nemo-guardrails-assessment.md), [LLM Guard](2026-09-30-llm-guard-assessment.md). Cross-reference facts from this survey:

- **ProtectAI's `deberta-v3-base-prompt-injection-v2`** is the de facto shared injection model. It is embedded in **LLM Guard, Invariant Guardrails and Arthur Engine**. A weakness in it propagates to all three.
- **Protect AI, the owner of LLM Guard and Rebuff, is now part of Palo Alto Networks.** The acquisition completed 2025-07-22 **[web]**.

### 2.16–2.18 Managed services

All five are proprietary, and none offers code or weights.

| Service | Owner and provenance | Deployment | Air gap |
|---|---|---|---|
| **Lakera Guard** | **Check Point acquired Lakera, announced 2025-09-16 [web: checkpoint.com press]**. The product is now documented as "Check Point AI Guardrails". | SaaS, **or a self-hosted container / Helm chart with an Enterprise license**. The docs state: "Air-gapped: Full offline deployment support… Containers can be exported and loaded without internet access" **[card: docs.lakera.ai/docs/selfhosting, fetched 2026-09-30]**. | **Yes, commercially.** This corrects the commonly repeated "hosted API only". |
| **Azure AI Content Safety Prompt Shields** | Microsoft | A hosted API, **plus a Docker container (preview)**, `mcr.microsoft.com/azure-cognitive-services/contentsafety/promptshields`. It requires CUDA, and `Billing=`/`ApiKey=` metering in connected mode. **Disconnected containers** are sold under an approved commitment plan **[card: learn.microsoft.com …/prompt-shields-container, 2026-02-05]**. | **Conditionally.** Needs the disconnected-container approval. Covers "User Prompt Attacks" and "Document Attacks", that is, direct and indirect injection. |
| **Google Model Armor** | Google Cloud | A hosted Cloud API. Covers prompt injection and jailbreak, Sensitive Data Protection, and malicious URLs **[card: docs.cloud.google.com/model-armor/overview]**. | No self-hosted edition found. GDC air-gapped exists, but no Model Armor on it was found. |
| **AWS Bedrock Guardrails** | AWS | A hosted API (`ApplyGuardrail` works for non-Bedrock models, but it is still an AWS call). Covers content filters, prompt attacks, denied topics, sensitive-info/PII, contextual grounding and Automated Reasoning **[card: aws.amazon.com/bedrock/guardrails]**. | No. |
| **Cisco AI Defense** | Cisco (built on the Robust Intelligence acquisition, 2024 [web]) | "The standard AI Defense deployment is a SaaS deployment"; **a hybrid mode is in beta** (Cisco docs, 2026-09-18) **[web: search snippet; the page is JS-rendered and the full text was not read]**. | Not as a standard offering. The hybrid-beta details are unverified. |

### 2.19 Red-team scanners (test-time)

| Tool | Pin | License | Provenance | What it would test for Maknae |
|---|---|---|---|---|
| **NVIDIA garak** | `NVIDIA/garak` @ `8d1259ef` · v0.17.0 (2026-09-09) | Apache-2.0 | NVIDIA | Probe the model behind the Egress Daemon, and any candidate filter, with `promptinject`, `latentinjection` (indirect / XPIA), encoding, DAN and leakage probes. Its detector results give a *measured* false-negative rate for a filter. |
| **Microsoft PyRIT** | `microsoft/PyRIT` @ `8f549326` · v1.1.0 (2026-09-04) | MIT | Microsoft AI Red Team | Multi-turn, orchestrated attacks (crescendo, tree-of-attacks, XPIA via documents) against the whole agent loop. This tests whether the kernel's decisions hold when the model is subverted. **Note:** `Azure/PyRIT` is an **archived** stub; the canonical repository is `microsoft/PyRIT`. |
| **promptfoo** | `promptfoo/promptfoo` @ `4f573002` · 0.123.1 (2026-09-18) | MIT | **OpenAI acquired Promptfoo (announced 2026-03-09) [web: openai.com; promptfoo.dev blog "will remain open source"]** | Declarative red-team suites (OWASP LLM Top 10 presets, excessive-agency, tool-misuse, PII-leak plugins) run in CI. It is the most convenient regression harness for "does the guard plus kernel still refuse X". The provenance change is worth tracking. |

## 3. Architectural defenses

These are designs, not filters. The OWASP rows follow the matrix conventions above.

**A Maknae caveat that applies to all three.** Each defense below needs a mediator that sees every relevant flow. `maknaed` decides every verb the loop sends through the plane: each `fs.read`, each `fs.write`, each `session.prompt` turn. But the loop itself runs unconfined as the subject's uid, so its direct I/O is not mediated and is invisible to the trail (ADR-0023 decisions 2 and 6; the [OpenShell assessment](2026-09-29-openshell-assessment.md) §1). Session state derived from mediated flows is therefore complete only for flows that go through the plane, until the loop is confined.

### 3.1 Meta: "Agents Rule of Two"

**The name, date, source and wording commonly cited are verified.**

- **Citation:** "Agents Rule of Two: A Practical Approach to AI Agent Security", Meta AI blog, **October 31, 2025**. URL: <https://ai.meta.com/blog/practical-ai-agent-security/>, fetched 2026-09-30.
  - The page carries no author byline. Simon Willison (2025-11-02) notes it "doesn't list authors but it was shared on Twitter by Meta AI security researcher Mick Ayzenberg" **[web]**.
  - The blog says it was inspired by Chromium's Rule of 2 and by Willison's "lethal trifecta".
- **Exact wording:** "until robustness research allows us to reliably detect and refuse prompt injection, agents must satisfy no more than two of the following three properties within a session…
  - [A] An agent can process untrustworthy inputs
  - [B] An agent can have access to sensitive systems or private data
  - [C] An agent can change state or communicate externally"

  "If an agent requires all three without starting a new session (i.e., with a fresh context window), then the agent should not be permitted to operate autonomously and at a minimum requires supervision — via human-in-the-loop approval or another reliable means of validation."
- **OWASP coverage:**
  - **LLM01**: impact containment, not detection.
  - **LLM02**: exfiltration needs B and C.
  - **LLM06**: primary.
- **Metadata-only PDP?** **Yes, fully.** A, B and C are properties of the *session's capability set and provenance*, not of content:
  - **A:** did the session ingest data from a source outside the trusted set?
  - **B:** does it hold a grant to sensitive objects?
  - **C:** does it hold an egress or write grant?

  `maknaed` already decides every read, write and egress the loop requests through the plane. So it can keep a per-session A/B/C bit-set and deny the third property, or require approval for it. This is exactly the kind of sticky, monotone session state a reference monitor is good at **[inferred]**. Two Maknae-specific limits apply: the bits are complete only for mediated flows (see the caveat above), and `maknaed` has no conversation or session identity yet (ADR-0023 decision 7), which such state needs.

### 3.2 Google DeepMind: CaMeL, "Defeating Prompt Injections by Design"

- **Citation:** Edoardo Debenedetti, Ilia Shumailov, Tianqi Fan, Jamie Hayes, Nicholas Carlini, Daniel Fabian, Christoph Kern, Chongyang Shi, Andreas Terzis and Florian Tramèr. arXiv **2503.18813**, v1 2025-03-24, v2 2025-06-24 (arXiv API).
  - Code: `google-research/camel-prompt-injection` @ `f083b6b3`, Apache-2.0.
  - The README says it is "a research artifact… might not be fully secure", and "not an officially supported Google product".
- **Mechanism:**
  1. A privileged LLM sees only the trusted user query. It emits a program (restricted Python) that fixes the **control and data flow** up front.
  2. A quarantined LLM parses untrusted data. It has no tool access, and its outputs are values only.
  3. A custom interpreter executes the program and attaches **capabilities** (provenance, allowed readers) to every value.
  4. **Security policies are checked at each tool call** against the capabilities of its arguments.
  5. Result: "solving 77% of tasks with provable security (compared to 84% with an undefended system) in AgentDojo" (abstract). This is author-reported, not independent.
- **OWASP coverage:**
  - **LLM01**: untrusted data cannot alter control flow.
  - **LLM02**: exfiltration is blocked by the reader capabilities.
  - **LLM06**: policy on every tool call.
  - **LLM05** partial: typed values rather than raw text reach sinks.
- **Metadata-only PDP?** **The decision, yes; the propagation, no.**
  - The per-tool-call policy check is a pure function of the capability labels, so it can live in a PDP that sees only labels.
  - But **label propagation requires a trusted interpreter that executes the plan and tracks every value**, and so handles the content. In Maknae the agent runtime is untrusted. That interpreter would therefore have to be trusted code, a new TCB component, or the kernel would have to fall back to coarse per-session or per-object taint derived from its own mediated flows **[inferred]**.

### 3.3 Microsoft: FIDES, "Securing AI Agents with Information-Flow Control"

- **Citation:** Manuel Costa, Boris Köpf, Aashish Kolluri, Andrew Paverd, Mark Russinovich, Ahmed Salem, Shruti Tople, Lukas Wutschitz and Santiago Zanella-Béguelin. arXiv **2505.23643**, v1 2025-05-29, v2 2025-09-03.
  - Tutorial: `microsoft/fides` @ `669c046c` (MIT, a notebook).
  - Follow-on: **`microsoft/fides-gateway`** @ `3f39af1b` (MIT, 2026-06). A research-prototype MCP proxy that carries IFC labels in `_meta["com.github.ifc/labels"]` and evaluates **OPA Rego via `regorus`**, Microsoft's **Rust** Rego engine, with an `ifc.label()` extension.
  - Referenced in MSRC's 2025-07-29 post on indirect prompt injection **[web]**.
- **Mechanism:**
  1. A planner tracks **confidentiality** labels (who may read) and **integrity** labels (trusted or untrusted) on every tool result, joined up a lattice as data mixes.
  2. **Policies are enforced deterministically at sinks.** For example, no low-integrity data may drive a consequential action, and no high-confidentiality data may flow to a public sink.
  3. The paper characterizes the class of properties that dynamic taint tracking can enforce.
  4. It adds primitives that **hide** untrusted values from the planner LLM behind variables, inspected only by a constrained sub-query, so that the whole context is not tainted.
  5. It is evaluated on AgentDojo (author-reported).
- **OWASP coverage:**
  - **LLM01** and **LLM02**: primary.
  - **LLM06**: sink policy.
  - **LLM08** partial: labels on retrieved chunks.
- **Metadata-only PDP?** **Yes, for the decision.** The labels travel beside the data, and fides-gateway literally ships them as sidecar metadata to a Rego PDP. The propagation caveat is the same as for CaMeL: whoever joins the labels must be trusted.
  - For Maknae specifically, the confidentiality half is already present in kind: the **classification-ceiling operand**, a mandatory (MAC) operand, decides on a marking without reading the content (ADR-0022). Nothing stamps a marking above the system's lowest level yet (#229), and content the loop reads returns to the trust plane unmarked (ADR-0023 §8). An integrity label ("this came from an untrusted tool result") is the natural second axis **[inferred]**.

## 4. Conclusion

**Is there any single filter that covers the whole Top 10? No.**

- No tool in this survey, open or managed, reaches ✓ on more than two rows. Most reach ✓ on at most one.
- **The widest runtime coverage comes from frameworks** (NeMo Guardrails, Guardrails AI, LlamaFirewall, Invariant). They get it by **composing several detectors**, not from one model.
- **Almost every single model** (Prompt Guard, ShieldGemma, Qwen3Guard, the DeBERTa classifiers) **covers at most LLM01 plus a partial row or two**. Granite Guardian, a bring-your-own-criteria judge, is the exception in breadth: partial on five rows, full on none.
- Even on LLM01, OWASP itself states that no fool-proof prevention is known.

**Rows that are inherently architectural, where no content filter can address the risk itself:**

- **LLM03 Supply Chain.** It concerns the provenance and integrity of models, packages and plugins. It is settled at build and install time by signing, SBOMs and pinning (compare Granite Guardian's Sigstore `model.sig` and Snyk's signed binaries), not by reading prompts.
- **LLM04 Data and Model Poisoning.** This is a training-time and fine-tune-time risk. A runtime filter at most sees a symptom.
- **LLM06 Excessive Agency.** OWASP's own remedy is least privilege plus **complete mediation** "in downstream systems rather than relying on an LLM". This is a reference-monitor job. Filters (AlignmentCheck, Granite's function-call check) can only *inform* it.
- **LLM08 Vector and Embedding Weaknesses.** The core remedies are access control and tenant partitioning on the vector store, plus provenance of ingested documents.
- **LLM10 Unbounded Consumption.** This is solved by quotas, rate limits, timeouts and budgets at the mediation point.
- **LLM07 System Prompt Leakage is architectural in substance.** OWASP: the system prompt "should not be … used as a security control." Filters (canary tokens, fuzzy echo match) only *detect* leakage. The fix is to keep secrets and authorization out of the prompt.

**Where content filters genuinely earn their place:** LLM01 (as a signal), LLM02 (PII and secrets in egress), LLM05 (structural validation of output before it reaches a sink), and, weakly, LLM09 (groundedness against supplied context).

**Implication for Maknae [inferred]:**

- The strongest controls in this survey that fit Maknae are the *architectural* ones, and their decisions are expressible on metadata alone: the Rule of Two session bits, FIDES/CaMeL-style integrity and confidentiality labels, and Invariant-style flow rules over tool-call sequences. They fit a `maknaed` whose decisions never inspect content (it relays prompt content to the Egress Daemon today, but decides on the subject, the verb, the object and its marking), and they use the mandatory-operand machinery that the classification-ceiling operand already has. Their reach is bounded by the mediation caveat at the head of §3.
- A content filter remains a PIP producing one more attribute. For outbound content, `maknaed` must receive it before it decides (see the [coverage map](2026-09-30-owasp-llm-top10-coverage.md) §4.4). The cheapest pure-Rust wins surfaced here need no model, and split by where they act:
  - **Before the decision (preventive):** Unicode tag-character / hidden-ASCII detection, and secrets regexes on the outbound turn.
  - **On replies (detective until the relay leg becomes a decision, #172/#229):** canary tokens, secrets regexes on the reply, and output checks beyond the shape validation of tool calls that Maknae already performs (`UnknownTool` in `crates/maknae-llm/src/wire.rs`; `admitted_reply` in `crates/maknae-kernel/src/egress.rs`, at `dc364cb`).

## 5. Sources (pinned)

| Tool / document | Pin |
|---|---|
| OWASP LLM Top 10 2025 | <https://genai.owasp.org/llm-top-10/> (fetched 2026-09-30); risk pages `llm01-prompt-injection`, `llm062025-excessive-agency`, `llm072025-system-prompt-leakage` |
| LlamaFirewall / CodeShield | [github.com/meta-llama/PurpleLlama @ `172c1074069eb88ec834124272c1b1c4f8893445`](https://github.com/meta-llama/PurpleLlama/tree/172c1074069eb88ec834124272c1b1c4f8893445); PyPI llamafirewall 1.0.3 (2025-05-29) |
| Granite Guardian | [HF ibm-granite/granite-guardian-4.1-8b @ `ab01ccca5dcfb80246369a086a4a87a29198f5af`](https://huggingface.co/ibm-granite/granite-guardian-4.1-8b/tree/ab01ccca5dcfb80246369a086a4a87a29198f5af); 3.3-8b @ `b3421eda4ba6fc9f9a71121d7e62de08827469a4`; hap-38m @ `faf9291163c7363d4a7ba7fc1dc72243214af931`; github ibm-granite/granite-guardian @ `9698a42800e9e6e840f908eecc7c730865dd2176` |
| ShieldGemma | HF google/shieldgemma-2b @ `d1dffc9c8c9237a90aab09c61383791e718ef9e8`; shieldgemma-2-4b-it @ `eaf60452b5fc41a911338a022e628b0c15283897`; Gemma ToU "Last modified April 1, 2026" <https://ai.google.dev/gemma/terms>; model card <https://ai.google.dev/gemma/docs/shieldgemma/model_card> (updated 2025-02-25) |
| Guardrails AI | [github guardrails-ai/guardrails @ `06d0ff2c5f9bcb493d976b76f885e37e41ce845d`](https://github.com/guardrails-ai/guardrails/tree/06d0ff2c5f9bcb493d976b76f885e37e41ce845d) (v0.11.0); guardrails-api @ `14a9fe1645b035963899d8ffd6b764e283d5c545`; validators detect_prompt_injection @ `f76a208e`, detect_jailbreak @ `b3451714`, detect_system_prompt_leakage @ `2a09e2b6` |
| Invariant Guardrails | [github invariantlabs-ai/invariant @ `2340fe2d9cd619f73d5b67fa05bf8a08c7cad515`](https://github.com/invariantlabs-ai/invariant/tree/2340fe2d9cd619f73d5b67fa05bf8a08c7cad515); Snyk press release 2025-06-24 |
| Snyk Agent Scan | [github snyk/agent-scan @ `2d244047643decb874a197bc64cbe6fc3e586f2a`](https://github.com/snyk/agent-scan/tree/2d244047643decb874a197bc64cbe6fc3e586f2a) (v0.6.8) |
| Vigil | [github deadbits/vigil-llm @ `f2b4c134d060bae81d29fad07003f3c657e63fc8`](https://github.com/deadbits/vigil-llm/tree/f2b4c134d060bae81d29fad07003f3c657e63fc8) |
| Rebuff | [github protectai/rebuff @ `4d2fe064abf164e7381556d23e48e210080f8afa`](https://github.com/protectai/rebuff/tree/4d2fe064abf164e7381556d23e48e210080f8afa) (archived) |
| LangKit | [github whylabs/langkit @ `5d6cab1e2ff32181ba5c514aaa2a4473421dc413`](https://github.com/whylabs/langkit/tree/5d6cab1e2ff32181ba5c514aaa2a4473421dc413) |
| Arthur Engine | [github arthur-ai/arthur-engine @ `0bc34e0b28d7a0ca319f0f1620295e82f59c2835`](https://github.com/arthur-ai/arthur-engine/tree/0bc34e0b28d7a0ca319f0f1620295e82f59c2835) |
| deepset injection | [HF deepset/deberta-v3-base-injection @ `80dda00d0b0d9a03917a7685e2ddbcd28e04dbb1`](https://huggingface.co/deepset/deberta-v3-base-injection/tree/80dda00d0b0d9a03917a7685e2ddbcd28e04dbb1); PIGuard @ `dd78b24e` |
| Qwen3Guard | HF Qwen/Qwen3Guard-Gen-0.6B @ `fada3b2f655b89601929198343c94cd2f64d93cc`; Qwen3Guard-Stream-4B @ `0e281784acd1370a2527aece964bcb267927f799`; github QwenLM/Qwen3Guard @ `6a52eca94b3d2aedb8aebd36baa353828d4166f1` |
| gpt-oss-safeguard | HF openai/gpt-oss-safeguard-20b @ `8a11e17b25c973a24099d4016bf2e17dd7ec1574`; github openai/gpt-oss-safeguard @ `7ec06bb91dbd368c5c33e3fe93fbe5ddfb98c471` |
| Cisco Foundation AI | HF fdtn-ai/Foundation-Sec-8B @ `9e6bb1f70b402e55bbf68cfd7abf88458daf09b3`; Foundation-Sec-8B-Instruct @ `aa13cb996e7fc700e7efd6b7367992f14cf349c0`; antares-1b @ `10417eb3` (gated) |
| NVIDIA OASP / OpenShell | nvidianews.nvidia.com/news/open-agent-safety-platform (2026-09-28); [github NVIDIA/OpenShell @ `5c0c9e446ed3b11e21198058873b0c6adfee6b4e`](https://github.com/NVIDIA/OpenShell/tree/5c0c9e446ed3b11e21198058873b0c6adfee6b4e) (v0.1.2) |
| Lakera / Check Point | docs.lakera.ai/docs/selfhosting (fetched 2026-09-30); checkpoint.com press 2025-09-16 |
| Azure Prompt Shields | learn.microsoft.com/en-us/azure/ai-services/content-safety/how-to/containers/prompt-shields-container (2026-02-05) |
| Model Armor | docs.cloud.google.com/model-armor/overview |
| Bedrock Guardrails | aws.amazon.com/bedrock/guardrails/ |
| Cisco AI Defense | securitydocs.cisco.com/docs/ai-def/user/170184.dita and 130141.dita (2026-09-18; search snippet only) |
| garak | [github NVIDIA/garak @ `8d1259ef310e4803cf5a4cc77267fdfdc24434ec`](https://github.com/NVIDIA/garak/tree/8d1259ef310e4803cf5a4cc77267fdfdc24434ec) (v0.17.0) |
| PyRIT | [github microsoft/PyRIT @ `8f5493265a10fe5ab77ee764063ed6738e814043`](https://github.com/microsoft/PyRIT/tree/8f5493265a10fe5ab77ee764063ed6738e814043) (v1.1.0) |
| promptfoo | [github promptfoo/promptfoo @ `4f573002d4664fb49ab0dd862301874eb6c03918`](https://github.com/promptfoo/promptfoo/tree/4f573002d4664fb49ab0dd862301874eb6c03918) (0.123.1); openai.com/index/openai-to-acquire-promptfoo (2026-03-09) |
| Agents Rule of Two | <https://ai.meta.com/blog/practical-ai-agent-security/> (2025-10-31); simonwillison.net/2025/Nov/2/new-prompt-injection-papers/ |
| CaMeL | arXiv 2503.18813v2; [github google-research/camel-prompt-injection @ `f083b6b396399d3b3c7f2ddaf613a5945eaf32d8`](https://github.com/google-research/camel-prompt-injection/tree/f083b6b396399d3b3c7f2ddaf613a5945eaf32d8) |
| FIDES | arXiv 2505.23643v2; [github microsoft/fides @ `669c046c4adbc56ee49c9672fdd30c54937ea062`](https://github.com/microsoft/fides/tree/669c046c4adbc56ee49c9672fdd30c54937ea062); [microsoft/fides-gateway @ `3f39af1b38a9b6883064b3f79b6bb32661fa72af`](https://github.com/microsoft/fides-gateway/tree/3f39af1b38a9b6883064b3f79b6bb32661fa72af) |
