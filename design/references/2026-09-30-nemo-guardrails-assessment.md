# NVIDIA NeMo Guardrails — Assessment Against Maknae

| | |
|---|---|
| **Status** | Assessment record. It informs the OWASP LLM coverage work. It creates no roadmap commitment and supersedes no ADR. |
| **Date** | 2026-09-30 |
| **Subject** | [`NVIDIA-NeMo/Guardrails`](https://github.com/NVIDIA-NeMo/Guardrails) (formerly `NVIDIA/NeMo-Guardrails`, which redirects) at commit [`83d03ad`](https://github.com/NVIDIA-NeMo/Guardrails/tree/83d03ad529d2be1399f1dede24be59d4381ee42e) on `develop` (2026-09-29, "feat: add tool_safety_check LLM-judged per-tool rail (#2386)"), with the model cards and configs of the NemoGuard models it calls (§12). A Python orchestration framework for input, output, dialog, retrieval and tool rails; framework code Apache-2.0, model weights under the NVIDIA Open Model License (and, for the 8B safety models, also the Llama 3.1 Community License). |
| **Method** | The repository was mirrored with `git clone --depth 1` outside this tree and **read only**: nothing was built, installed or executed. Only model cards and configs were fetched, never weights: [`nvidia/NemoGuard-JailbreakDetect`](https://huggingface.co/nvidia/NemoGuard-JailbreakDetect/tree/cc8b97e2bd6c1667c31476eedaa9a75b4d7ed282) at `cc8b97e`, [`nvidia/llama-3.1-nemoguard-8b-content-safety`](https://huggingface.co/nvidia/llama-3.1-nemoguard-8b-content-safety/tree/ef1f9de54f760180f70b517dd10362d9463ddc58) at `ef1f9de`, [`nvidia/llama-3.1-nemoguard-8b-topic-control`](https://huggingface.co/nvidia/llama-3.1-nemoguard-8b-topic-control/tree/5ce438e7119061c809e9da819beb5b9287104230) at `5ce438e` (metadata only), [`Snowflake/snowflake-arctic-embed-m-long`](https://huggingface.co/Snowflake/snowflake-arctic-embed-m-long/tree/92d97331f1f4b6a366c1f161354b9f3390cc219f) at `92d9733` (metadata only), and the NVIDIA Open Model License PDF (June 2024; SHA-256 `396d7de2…f607`). Evidence labels: **[code]** read at the pinned commit; **[vendor-doc]** NVIDIA documentation or model card, not independent; **[third-party]** a published paper; **[web-context]** press or web search, context not evidence; **[inferred]** reasoning; **[measured]** a measurement taken during this assessment, with what it was taken by stated. Public web material is context only and is marked as such. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |

This assessment is one of a set of four guard-model assessments ([Prompt Guard](2026-09-30-prompt-guard-assessment.md), [Llama Guard](2026-09-30-llama-guard-assessment.md), NeMo Guardrails, [LLM Guard](2026-09-30-llm-guard-assessment.md)) whose synthesis is [`2026-09-30-owasp-llm-top10-coverage.md`](2026-09-30-owasp-llm-top10-coverage.md).

**Citation shorthand.** All `path:line` citations are to commit `83d03ad` unless marked otherwise. Paths beginning `library/`, `actions/`, `embeddings/`, `rails/`, `guardrails/`, `llm/` and `telemetry.py` are under the `nemoguardrails/` package. Within `library/jailbreak_detection/`, `models.py` is `model_based/models.py`, and `checks.py` is `model_based/checks.py` or `heuristics/checks.py` as named. `jailbreak-protection.mdx`, `content-safety.mdx` and `self-check.mdx` are under `docs/configure-rails/guardrail-catalog/`; `runtime-security-faq.mdx` is under `docs/resources/`. "JailbreakDetect card" is `README.md` of `nvidia/NemoGuard-JailbreakDetect` at HF revision `cc8b97e`; "content-safety card" is `README.md` of `nvidia/llama-3.1-nemoguard-8b-content-safety` at `ef1f9de`. "OML" is the NVIDIA Open Model License (June 2024).

## 0. Disposition (read first)

**The proposed use.** Maknae is evaluating a content and prompt-injection filter that inspects prompt text, tool results (file content the loop read, which returns to the trust plane in the next `session.prompt` turn) and model replies, and gives the kernel a recommendation. The filter would be a Policy Information Point (PIP), never a Policy Decision Point (PDP): `maknaed` stays the sole PDP (ADR-0005), and the content informs but never authorizes (AGENTS.md core principle 2). The candidate placement is beside the Egress Daemon (`maknae-egress`), which already receives prompt content from `maknaed` today, but only after the kernel has decided and recorded the turn (ADR-0023 decision 3); §9 states what that order costs a filter. The maintainer does not want latency added on top of the policy check.

**NeMo Guardrails is an orchestration framework, not a classifier.** Its strong rails are mostly additional LLM calls, which add a model round trip each and can be prompt-injected by the content they judge. Its local jailbreak rails are evadable per independent work and **fail open** by design. It ships default-on telemetry to NVIDIA, default cloud endpoints, runtime model downloads, `trust_remote_code`, and onnxruntime (C++) as a core dependency.

**Verdict: learn from, and adapt narrowly; avoid as-is.** The full verdict is §11.

## 1. Identity and provenance

- **Owner.** NVIDIA Corporation. The repository is `NVIDIA-NeMo/Guardrails`, created 2023-04-18 (GitHub API).
  - **Organization move.** The repository moved from the `NVIDIA` org to the `NVIDIA-NeMo` org, and the old URL redirects. This is an organizational move, not an acquisition. No ownership change was found.
  - **Top committers (GitHub contributors API):**

    | Login | Commits |
    |---|---|
    | drazvan | 1125 |
    | Pouyanpi | 773 |
    | schuellc-nvidia | 741 |
    | abhijitpal1247 | 252 |
    | tgasser-nv | 121 |
    | trebedea | 102 |
    | erickgalinkin | 41 |

  - Erick Galinkin is the author of the YARA rules and of the JailbreakDetect paper.
  - There is no GOVERNANCE or MAINTAINERS file. `CONTRIBUTING.md:54-110` states that maintainers assign issues and lead refactors.
- **Releases and maturity.**
  - First release `0.1.0` on 2023-04-25 (`CHANGELOG.md:1230`). Current release `v0.24.1` on 2026-09-16. `pyproject.toml:3` says `0.25.0.dev0`.
  - Cadence is roughly one minor release every 1–2 months: 0.21.0 on 2026-03-12, 0.22.0 on 05-22, 0.23.0 on 07-01, 0.24.0 on 08-25.
  - The project is still **pre-1.0**. Its classifier is "Development Status :: 4 - Beta" (`pyproject.toml:13`).
- **Activity.** Last push 2026-09-29, 249 open issues and PRs (GitHub's `open_issues_count`, which counts both), 7.2k stars, not archived (GitHub API, 2026-09-30).
- **Contribution rules.**
  - DCO, via `Signed-off-by` or GPG-signed commits (`CONTRIBUTING.md:228-236`).
  - An AI-usage policy requires AI disclosure, forbids agent-filed issues and forbids AI co-authors (`AI_POLICY.md`).
  - CodeQL and zizmor workflows are present (`.github/workflows/codeql.yml`, `zizmor.yml`).
- **Release signing and attestation.**
  - The approval-gated PyPI publish uses OIDC trusted publishing (`id-token: write`) with PEP 740 attestations (`.github/workflows/publish-pypi-approval.yml:22,81-85`).
  - A second, manually dispatched workflow publishes with a long-lived `PYPI_API_TOKEN` (`.github/workflows/publish-wheel.yml:30-33`). So not every release path is attested.
  - Third-party actions are **not** consistently pinned by SHA. For example, `actions/checkout@v7.0.1` and `actions/setup-python@v7` are tag-pinned (`.github/workflows/_test.yml:48,53`).
  - Model files on Hugging Face carry no signatures.
- **Relation to NVIDIA's other safety pieces.**
  - **NemoGuard / Nemotron safety NIMs.** These are separate model artefacts that the framework calls over HTTP, or in-process for JailbreakDetect. They have different licenses (§2).
    - JailbreakDetect: a random forest over Snowflake embeddings.
    - Llama-3.1-NemoGuard-8B ContentSafety: a LoRA on Llama-3.1-8B-Instruct, now branded "Llama Nemotron Safety Guard V2" (content-safety card `README.md:19`).
    - TopicControl: also a LoRA.
  - **OpenShell / Open Agent Safety Platform (announced 2026-09-28).**
    - The Guardrails tree contains **no code reference to OpenShell** (`grep -ri openshell` returns nothing).
    - Maknae's own [OpenShell assessment](2026-09-29-openshell-assessment.md) does not mention Guardrails.
    - Press coverage [web-context: WIRED 2026-09-28; storagereview.com; nvidia.com/en-us/ai/nemoclaw] describes the platform as OpenShell (runtime sandbox and egress), Sentry, and BlueField-4.
    - One syndicated post lists "NeMo Guardrails" and "Nemotron Content Safety" as platform components, in pre-deployment evaluation and runtime content checks.
    - So Guardrails appears to be **marketed as the content-policy layer beside OpenShell's enforcement layer**, but there is no code-level coupling. This is unverified beyond press.

## 2. License

- **Framework code: Apache-2.0.**
  - `LICENSE.md:1-2` has the SPDX header `Apache-2.0`, with the full text in `LICENSE-Apache-2.0.txt`. `pyproject.toml:5` also declares `license = "Apache-2.0"`.
  - GitHub reports `NOASSERTION` only because of the dual license files.
  - `LICENCES-3rd-party` lists bundled third-party notices.
- **NemoGuard JailbreakDetect weights: NVIDIA Open Model License** (JailbreakDetect card `README.md:8-9`).
- **Llama-3.1-NemoGuard-8B ContentSafety and TopicControl LoRA adapters:** the NVIDIA Open Model License, **plus** the Llama 3.1 Community License, because the base is `meta-llama/Meta-Llama-3.1-8B-Instruct` (content-safety card `README.md:23-27,206,228`; its `adapter_config.json:4`). The Llama 3.1 license carries:
  - Meta's Acceptable Use Policy;
  - a 700M-MAU clause;
  - a "Built with Llama" attribution requirement;
  - gated download of the Meta base weights.
- **What the NVIDIA Open Model License (June 2024) permits and requires** (OML §§2–3):
  - It is perpetual, worldwide, no-charge and commercial.
  - **Redistribution is permitted in any medium.** A copy of the agreement and a "Notice" file reading "Licensed by NVIDIA Corporation under the NVIDIA Open Model License" must be included (§3.1).
  - Two caveats:
    1. The license is **revocable** on patent or copyright litigation (§2.1).
    2. "**NVIDIA may update this Agreement to comply with legal and regulatory requirements at any time and You agree to either comply with any updated license or cease Your copying, use, and distribution of the Model and any Derivative Model**" (§2.1). The update right is limited to legal and regulatory compliance, which is narrower than an unrestricted unilateral-change clause, but the licensee must still comply with the updated terms or stop using the model. A DoD SCRM reviewer will still flag it.
  - There is no MAU cap and no guardrail-bypass termination clause in this version.
- **Snowflake arctic-embed-m-long** (JailbreakDetect's embedder): Apache-2.0 (HF API `cardData.license`).
- **NIM containers.** They are governed separately, by the NVIDIA software license and AI product terms [vendor-doc: NGC catalog page]. Production use of NIM requires an NVIDIA AI Enterprise subscription [vendor-doc: docs.api.nvidia.com/nim/docs/product; forums.developer.nvidia.com/t/nim-question/364032].
- **Air-gap redistribution.**
  - The framework code and the JailbreakDetect RF plus Snowflake embedder **can** be packaged offline, subject to the Notice file.
  - The 8B content-safety model can be packaged too, but it drags in the Llama 3.1 terms, and Meta's base download is gated.
  - Hugging Face access is not gated for the NVIDIA repositories (`gated: false`).

## 3. What it is and how it works

**It is an orchestration framework, not a classifier.**

- **Rails.** Rails run at several points: input, output, dialog, retrieval, and tool-input / tool-output (`runtime-security-faq.mdx:27-28`).
- **Language and engines.** Rails are expressed in the **Colang** DSL (v1 and 2.x, parsed with `lark`) plus YAML config. There are two engines:
  - `LLMRails`, the Colang event-driven runtime;
  - `IORails`, a newer, leaner input/output engine that supports speculative generation (`CHANGELOG.md`, 0.22.0).
- **Pluggable actions.** Each rail is a Python "action" in `nemoguardrails/library/<name>/`. There are 30 built-in integrations (`docs/telemetry.mdx`, "Possible Values for Built-In Features").

Which rails need an LLM or model call, and which are purely local, **[code]**:

| Rail | Mechanism | Needs LLM or remote model? | Source |
|---|---|---|---|
| `self check input` / `self check output` / `self check facts` | Renders a prompt template that the operator supplies ("Should the user message be blocked (Yes or No)?") and asks an LLM, by default the **main** LLM | **Yes:** one LLM round trip per rail | `library/self_check/*/actions.py`; `examples/bots/abc/prompts.yml:1-38` |
| `content safety check input/output $model=…` | Aegis-2.0 23-category prompt to an 8B safety LLM, JSON verdict, `max_tokens: 50` | **Yes:** an 8B LLM call, as a NIM or any OpenAI-compatible endpoint | `examples/configs/nemoguards/prompts.yaml:1-45`; `library/content_safety/` |
| `topic safety check input` | TopicControl 8B LLM | **Yes** | `library/topic_safety/` |
| `llama guard check input/output` | Llama Guard LLM | **Yes** | `library/llama_guard/` |
| `tool_safety_check` (new at the pinned commit) | LLM-judged per-tool check | **Yes** | `library/tool_safety_check/actions.py:31-91`; `actions/llm_judge.py:49-86` |
| `jailbreak detection heuristics` | Length/perplexity and prefix/suffix perplexity from **GPT-2-large** (a local LM forward pass, not an LLM "call") | Local model (~774M params [inferred: public GPT-2-large size]), in-process or a separate server | `library/jailbreak_detection/heuristics/checks.py:21-103` |
| `jailbreak detection model` | Snowflake arctic-embed-m-long (137M params; `safetensors.total = 136,731,648` from the HF API) giving a 768-d CLS embedding, fed to a **random forest** (ONNX) that outputs a label and probability | Local model, or the JailbreakDetect NIM / hosted API | `library/jailbreak_detection/model_based/models.py:21-71`; `model_based/checks.py:24-95` |
| `injection detection` | **YARA** rules (4 files, 132 lines) for code, SQLi, XSS and template injection, run on the **bot output**. This is *not* prompt injection. | Local, via `yara-python` (C libyara) | `library/injection_detection/flows.co:1-5`; `library/injection_detection/yara_rules/*.yara` |
| `regex` | Operator-supplied Python `re` patterns on input, output or retrieval | Local | `library/regex/rail_config.py` |
| `sensitive data detection` | Microsoft Presidio with spaCy `en_core_web_lg` | Local (spaCy model) | `library/sensitive_data_detection/actions.py:81-85` |
| `hf_classifier`, `gliner` | Generic HF `transformers` pipeline; GLiNER PII server | Local model, or a server | `library/hf_classifier/backends.py`; `library/gliner/` |
| 15+ vendor integrations: ActiveFence, Cisco AI Defense, CrowdStrike, F5, Pangea, Prompt Security, Trend Micro, PrivateAI, Clavata, … | Remote SaaS API | **Yes (vendor cloud)** | `nemoguardrails/library/` |
| Dialog rails (Colang canonical forms) | Embedding kNN (FastEmbed `all-MiniLM-L6-v2` by default) followed by LLM intent / next-step generation | **Yes:** often 1–3 LLM calls per turn, or 1 with `single_llm_call` | `embeddings/basic.py:53`; `self-check.mdx:339` |

- **JailbreakDetect model details.**
  - **Input limit.** The tokenizer truncates at `max_length=2048` tokens (`model_based/models.py:48`). Text beyond 2048 tokens is **silently ignored** by the classifier.
  - **Output.** The output is `{"jailbreak": bool, "score": ±prob}` (`model_based/models.py:62-71`; `model_based/checks.py:93-95`).
  - **Loading.** The embedder is loaded with `trust_remote_code=True` (`model_based/models.py:34-43`). The NomicBert architecture code comes from the HF repository's `auto_map`.
- **Heuristics details.**
  - Decision rule: `len(chars)/perplexity >= 89.79`, or prefix/suffix 19-word perplexity `>= 1845.65`.
  - Vendor figure for the length/perplexity threshold: "31.19% of jailbreaks being detected with a false positive rate of 7.44%" on NVIDIA's dataset (`jailbreak-protection.mdx:79`) [vendor-doc].
  - Strings shorter than 20 words skip the second check (`heuristics/checks.py:64-103`; defaults in `library/jailbreak_detection/rail_config.py:39-42`).
  - The perplexity window is GPT-2's 1024 positions with stride 512 (`heuristics/checks.py:36-57`).
- **Output shape at the framework level.** The framework outputs `RailOutcome.allow()` / `.block()` / transform (`actions/rail_outcome.py`). It is a verdict, with the score discarded in most rails. The LLM judge deliberately returns **only the verdict**, not the reason (`actions/llm_judge.py:81-86`).

## 4. What it detects, and what it does not

- **Categories.**
  - Jailbreak: heuristics plus the RF model.
  - Content safety: the Aegis 2.0 taxonomy, S1–S23. It covers violence, sexual content, criminal planning, weapons, controlled substances, self-harm, sexual content involving minors, hate, PII/privacy, harassment, threat, profanity, needs-caution, other, manipulation, fraud, malware, high-risk government decision-making, political misinformation, copyright, unauthorized advice, illegal activity and unethical content (`examples/configs/nemoguards/prompts.yaml:7-31`).
  - Topic control.
  - PII: Presidio, GLiNER and PrivateAI.
  - Output code-injection patterns: YARA.
  - Hallucination and fact-checking.
  - Tool-call safety.
  - Anything an operator writes into a self-check prompt.
- **Prompt injection specifically.**
  - No built-in local rail targets **indirect prompt injection in tool results or retrieved content** as such.
  - What exists is:
    - JailbreakDetect, trained on exactly three open jailbreak datasets: AdvBench, WildJailbreak and jackhhao/jailbreak-classification, with jailbreak data augmented by garak (JailbreakDetect card `README.md:48-80`);
    - self-check LLM prompts that can be pointed at retrieval or tool-output rails;
    - vendor SaaS integrations.
  - The `injection_detection` rail is about *code* injection in model **output** (`library/injection_detection/flows.co:1-5`), not prompt injection.
- **Languages.**
  - The heuristics are English-only, and "will yield significantly more false positives on non-English text, including code" (`jailbreak-protection.mdx:85`, repeated at `:98`) [vendor-doc].
  - The content-safety models are multilingual in the v3 variant [vendor-doc: HF `Llama-3.1-Nemotron-Safety-Guard-8B-v3`].
- **Vendor accuracy for JailbreakDetect** [vendor-doc; not independent]: on JailbreakHub, F1 0.9601, false-positive rate 0.0042, false-negative rate 0.0435 (JailbreakDetect card `README.md:90-93`).
- **Published bypass (Hackett et al., 2025)** [third-party]: "Bypassing Prompt Injection and Jailbreak Detection in LLM Guardrails", arXiv:2504.11168v1 (Mindgard).
  - Baseline detection of adversarial jailbreak samples: NeMo Guard Jailbreak Detect, 87.17% (Table A.1).
  - Character injection (emoji smuggling, homoglyphs, zero-width characters and similar) reached an **attack success rate (ASR) of 72.54%** against it on jailbreaks.
  - Adversarial-ML word perturbation achieved an average ASR of **65.22%**, which the paper calls "**the highest susceptibility to jailbreak evasion**" among the six guardrails tested. That ranking is for adversarial-ML jailbreak evasion only: under character injection, Vijil Prompt Injection was the most susceptible (87.95% / 91.67%), and NeMo's detector was evaluated on jailbreaks only, not prompt injection.
- **Structural critiques** [inferred, with code support]:
  1. **LLM-as-judge is itself injectable.** The self-check template interpolates untrusted text directly into the judge prompt (`User message: "{{ user_input }}"`, `examples/bots/abc/prompts.yml:18`). Content that instructs the judge to answer "No" is the obvious attack.
  2. **Fail-open by design** on the jailbreak rails.
     - Connection failure, timeout or error returns `allow` (`library/jailbreak_detection/actions.py:95-98,157-165,182-186`).
     - This is documented: "Jailbreak detection fails open … a detector outage removes this protection without a visible signal" (`jailbreak-protection.mdx:112-119`).
     - There is no library-wide failure policy (`runtime-security-faq.mdx:113-117`).
     - The LLM-judge path *does* raise on truncated or unparseable output, so the engine records a failure (`actions/llm_judge.py:72-80`).
  3. The 2048-token truncation means long tool results are only partly classified.

## 5. Language, runtime and dependencies

- **Runtime.** Python `>=3.10,<3.14` (`pyproject.toml:8`), asyncio-based.
- **Core dependencies.** There are 18 direct dependencies (`pyproject.toml:22-44`), and they include:
  - **`onnxruntime`** (C++), a *direct* core dependency (`pyproject.toml:27-28`), also required by FastEmbed;
  - `fastembed`, `aiohttp`, `httpx`, `jinja2`, `lark`, `pydantic`, `numpy`, `protobuf`, `simpleeval`, `typer`, `rich`, `prompt-toolkit`.
- **Transitive counts [measured].** Computed from the pinned `uv.lock` (276 packages locked) by walking its dependency graph with an independent script, not the candidate's code:

  | Install | Packages |
  |---|---|
  | core | **66** |
  | `[jailbreak]` (adds `yara-python`) | 67 |
  | `[sdd]` (Presidio) | 92 |
  | `[server]` | 81 |
  | `[all]` | **212** |

  The core closure includes `huggingface-hub`, `hf-xet`, `tokenizers`, `onnxruntime`, `pillow`, `pydantic-core` (Rust), `rpds-py` (Rust) and `py-rust-stemmers`.
- **LangChain.** LangChain was **demoted from core to dev** in 0.22.0 (`CHANGELOG.md:225,231`). It is now only in the `test_integration` group (`pyproject.toml:141-145`).
- **Local model rails need more:**
  - `torch` and `transformers`;
  - the jailbreak server additionally needs `torch>=2.9`, `torchvision`, `transformers>=5.3`, `onnxruntime`, `einops`, `huggingface_hub` and `fastapi`/`uvicorn` (`library/jailbreak_detection/requirements.txt`);
  - Presidio needs spaCy `en_core_web_lg`.
- **GPU.**
  - Not required for the framework itself.
  - Effectively required for acceptable heuristic latency (§6) and for the 8B safety models.
- **Serving modes.** A Python library (`LLMRails` / `IORails` / `Guardrails`), a FastAPI server (`[server]`), a CLI, and separate Docker servers for jailbreak detection and GLiNER (`library/jailbreak_detection/Dockerfile`, `Dockerfile-GPU`).

## 6. Performance and footprint

| Item | Number | Source |
|---|---|---|
| Jailbreak heuristics, CPU, Docker | **2057 ms** average (10 prompts, 5–2048 tokens) | [vendor-doc] `jailbreak-protection.mdx:148-158` |
| Jailbreak heuristics, CPU, in-process | **3227 ms** | [vendor-doc] same |
| Jailbreak heuristics, GPU, Docker / in-process | **115 ms / 157 ms** | [vendor-doc] same |
| GPT-2-large on disk | ~3 GB fp32 (774M params) | [inferred: public model size] |
| JailbreakDetect RF (`snowflake.onnx`) | **43.9 MB** (`x-linked-size: 43948411`) | [measured: an HTTP HEAD request to the pinned HF file] |
| Snowflake arctic-embed-m-long | 137M params (~550 MB fp32) | [HF API safetensors total; size inferred] |
| JailbreakDetect latency | Not published on the card; test hardware listed as RTX A6000 / A100 | [vendor-doc] JailbreakDetect card `README.md:95-99` |
| JailbreakDetect latency estimate | Tens of ms per short input on CPU. Cost rises superlinearly with length (attention is quadratic in sequence length), so a full 2048-token input costs well over 4× a 512-token one; bound it by scanning fixed-size windows. | [inferred: 137M encoder plus RF] |
| Content-safety 8B LLM rail | No latency published in the repository docs. One 8B prefill plus up to 50 output tokens. | [inferred] |
| Content-safety 8B LLM rail, estimate | ~100–400 ms on a datacentre GPU; seconds on CPU | [inferred] |
| Self-check rails | One full round trip to the configured LLM per rail. The repository's evaluation config *examples* use `fixed_latency: 0.3 s` / `0.25 s` per call. These are illustrative config values, not measurements. | [vendor-doc] `docs/evaluation/evaluate-configuration.mdx:133-144` |
| Language detection (fast-langdetect) | ~9–12 µs per call; the default model **downloads 125 MB on first use** | [vendor-doc] `content-safety.mdx:223,238-247` |
| Parallelism | Rails can run in parallel (`rails.input.parallel`). `IORails` speculative generation overlaps input rails with the main LLM call, but does not remove the cost of the underlying calls. | [vendor-doc] `runtime-security-faq.mdx:27,59` |

Throughput is not published for any local rail.

## 7. Strengths

- **Breadth.** It is a well-documented catalogue of rail types at every interception point, including tool-input / tool-output and retrieval rails, which map directly onto Maknae's "prompt, tool result, model reply" surfaces.
- **A clean verdict abstraction.** `RailOutcome` is allow / block / transform. The judge returns only the verdict, not quoted content, so flagged PII does not leak into logs (`actions/llm_judge.py:81-86`).
- **Fail-closed on unparseable judge output.** Truncated or unparseable judge output fails closed (`actions/llm_judge.py:72-80`), and streaming output rails fail closed on action failure (`docs/about/release-notes.mdx:144`).
- **Honest documentation of hazards.** The fail-open behaviour, the English-only heuristic and the default-on telemetry are all explicit in the docs.
- **Reusable artefacts:**
  - the Aegis 2.0 taxonomy;
  - the well-tuned prompt templates;
  - the JailbreakDetect design (a small embedder plus an RF), which is cheap, simple and redistributable;
  - the perplexity heuristic, which is a published, simple, model-agnostic GCG-suffix detector.
- **Supply chain.** An accountable US vendor, DCO, CodeQL and zizmor, and PEP 740 attestations on the approval-gated PyPI path.

## 8. Weaknesses

- **False negatives and bypasses.**
  - Independent work shows JailbreakDetect is the *most* evadable of six guardrails tested under adversarial-ML word perturbation on jailbreaks (65.22% ASR, §4). Under character injection it reached 72.54%, but Vijil Prompt Injection was worse there (87.95% on prompt injection, 91.67% on jailbreaks). NeMo's detector was tested on jailbreaks only.
  - Self-check judges are injectable by the content they judge.
  - Classification stops at the 2048-token truncation.
- **False positives.** The heuristics over-fire on non-English text and on code (`jailbreak-protection.mdx:85,98`). Code is exactly what an agent reads in tool results.
- **Fail-open.**
  - Jailbreak rails fail open silently (`library/jailbreak_detection/actions.py:95-98,157-165,182-186`).
  - The failure policy differs per integration (`runtime-security-faq.mdx:113-117`).
  - This is contrary to Maknae's core principle 4 (fail closed, everywhere).
- **Telemetry is ON by default.**
  - Constructing `LLMRails`, `IORails` or `Guardrails` sends an anonymous usage event to **`https://events.telemetry.data.nvidia.com/v1.1/events/json`** (`telemetry.py:41`).
  - It also starts a **heartbeat every 600 s** (`telemetry.py:96-114`), using `urllib.request.urlopen` with a 5 s timeout (`telemetry.py:783`).
  - Call sites: `rails/llm/llmrails.py:478-480` and `guardrails/iorails.py:785-788`.
  - It also writes a local audit file, `~/.config/nemoguardrails/usage_stats.json` (`telemetry.py:77-81`).
  - Opt-out is any one of:
    - `NEMO_GUARDRAILS_NO_USAGE_STATS=1`;
    - `DO_NOT_TRACK=1` (either variable alone disables it);
    - a `~/.config/nemoguardrails/do_not_track` file;
    - `CI` or pytest being present (`telemetry.py:346-383`).
  - The payload is deployment metadata: version, platform, CPU architecture, LLM engine names and feature list (`telemetry.py:687-757`; `docs/telemetry.mdx`). It excludes prompts, per the vendor.
  - Telemetry was added around 0.22.0 (2026-05). It is a new default network egress for a library that previously had none.
- **Default endpoints go to NVIDIA or OpenAI clouds.**
  - `engine: nim` with no `base_url` resolves to `https://integrate.api.nvidia.com/v1`, and `openai` to `https://api.openai.com/v1` (`llm/frameworks/default.py:28-33`; `guardrails/model_engine.py:80-81`).
  - The shipped `nemoguards` example points jailbreak detection at `https://ai.api.nvidia.com` (`examples/configs/nemoguards/config.yml`).
  - So the FAQ line "No prompts or responses are sent to NVIDIA" (`runtime-security-faq.mdx`) is true of telemetry, but **not** of a default-NIM configuration.
- **Runtime downloads.** All of these break the air gap unless they are pre-staged:
  - the JailbreakDetect RF, via `hf_hub_download` (`model_based/checks.py:28-42`);
  - the Snowflake embedder and GPT-2-large, via `from_pretrained` (`heuristics/checks.py:23-24`; `model_based/models.py:34-43`);
  - the FastEmbed MiniLM embedding model;
  - the fast-langdetect model (125 MB);
  - spaCy `en_core_web_lg`.
- **Remote code and pickle.**
  - The embedder loads with **`trust_remote_code=True`** (`model_based/models.py:36,40`), which executes Python from the HF repository.
  - The JailbreakDetect HF repository also ships **`snowflake.pkl`** (an sklearn pickle; its `config.json` has `model_format: pickle`). The framework loads the `.onnx` file instead (`model_based/checks.py:24`).
- **A heavy C/C++ surface.** `onnxruntime` is a *core* dependency. It sits beside `torch`, libyara and spaCy's compiled extensions.
- **Maintenance risk.**
  - The project is pre-1.0 and has breaking changes in minor releases, such as the LangChain demotion and the engine split into LLMRails and IORails.
  - There are 249 open issues and PRs.
  - Heuristics are unsupported on `IORails` (`jailbreak-protection.mdx:122-133`).
- **Licensing friction.** The model weights carry the Open Model License's unilateral-update clause. The 8B safety models also carry the Llama 3.1 terms, and NIM production use needs NVIDIA AI Enterprise.

## 9. Integration into Maknae as-is

- **Shape.** The only viable shape is a **separate Python sidecar service**, the FastAPI server or a thin wrapper. It would run under its own account beside `maknae-egress` and be called over a Unix socket. The kernel would treat its verdict as PIP input.
- **Where the verdict must arrive: ADR-0023's write-ahead order.** ADR-0023 decision 3 fixes the order of a turn: the kernel decides `session.prompt`, appends the write-ahead record, and only then hands the turn to `maknae-egress`. A PIP that sits beside the Egress Daemon and scans what it receives therefore sees the content only after the decision, and its verdict informs nothing. For a verdict on input content to count, it must reach `maknaed` **before** the `session.prompt` decision. With the scanner beside the Egress Daemon, that means a new channel from `maknaed` to the scanner, or an extra round trip before the decision. That cost is on the critical path of every turn, on top of the scan time itself. Running the scan asynchronously, or pipelined with the model call, is not a latency fix for inputs: it sends the content before the verdict exists, which is the objection this assessment raises (§9, below) against IORails speculative generation. Replies are harder still. In the shipped design the reply-leg release verdict is the `session.prompt` verdict, computed before the model output exists (ADR-0023 decision 3, "The response leg is a release"), so no content-dependent check on a reply can bind until that release is un-collapsed into a decided `session.update`, for which #229 landing is a named trigger.
- **TCB.** It must be **outside** the TCB: a Python runtime, 66–212 packages, onnxruntime, torch and libyara, none of which ADR-0002 admits into the kernel or the egress process. (Maknae's egress process already links native code, per `cargo tree -p maknae-egress`: the AWS-LC crypto module (`aws-lc-fips-sys`, with the non-FIPS `aws-lc-sys` also in the tree), and, on macOS, Security.framework and CoreFoundation through FFI (`rustls-platform-verifier` → `security-framework-sys` / `core-foundation-sys`, reached through `reqwest`). A model runtime is a different order of native code from either.) That is acceptable only if its output is strictly advisory. It still becomes a new supply-chain surface that DoD SCRM must assess: pip wheels, CUDA if a GPU is used, and HF artefacts.
- **FIPS.** No FIPS relevance for local classification. However, the sidecar's HTTP clients (`aiohttp`, `httpx`, `urllib`) use Python's OpenSSL, not AWS-LC. That matters if it ever reaches a NIM over TLS.
- **Air gap.** Achievable only with all of the following:
  - pre-staging every model (§8);
  - setting `HF_HUB_OFFLINE=1` / `TRANSFORMERS_OFFLINE=1`;
  - `NEMO_GUARDRAILS_NO_USAGE_STATS=1` or `DO_NOT_TRACK=1` (either suffices; set both as belt and braces), with the absence of the heartbeat confirmed by egress observation;
  - pinning `engine` base URLs to local endpoints;
  - vendoring the Snowflake remote code, which still executes arbitrary repository Python at load.
- **macOS (Apple Silicon).**
  - The framework runs.
  - The jailbreak Docker images and NIMs are Linux/NVIDIA-GPU oriented. The JailbreakDetect card lists only x86/x64 hardware (JailbreakDetect card `README.md:34-36`).
  - Local torch on MPS is possible but untested by the vendor. The 8B safety LLMs have no supported macOS serving path from NVIDIA.
  - macOS is a production target for Maknae, so these are supported-platform gaps, not footnotes.
- **Latency.** Maknae wants no delay added on top of the policy check.
  - This is bad for the LLM-backed rails: +1 model round trip per rail per direction.
  - It is marginal for the heuristics: 2–3 s on CPU.
  - Only the JailbreakDetect RF path, at tens of ms per short window (inferred; superlinear in length), is plausibly in budget, and it still pays the pre-decision round trip.
  - `IORails` speculative generation hides input-rail latency only by sending the prompt to the provider *before* the verdict. That contradicts Maknae's rule that the kernel decides, and records the decision, before content leaves (ADR-0023 decision 3: `session.prompt` is write-ahead egress).
- **Complexity: XL.**
  - It adds a new Python service with its own packaging for Linux and macOS, model staging and telemetry suppression.
  - Fail-open behaviour has to be wrapped fail-closed on the Maknae side.
  - It needs a new PIP protocol.
  - The resulting detection quality is shown by independent work to be weak for the jailbreak model and injectable for the LLM judges.

## 10. Taking the interesting parts and reimplementing them natively in Rust

**Portable pieces:**

1. **JailbreakDetect: embedder plus random forest.**
   - Weights: the RF is under the NVIDIA Open Model License, which is redistributable with the Notice file. The Snowflake embedder is Apache-2.0.
   - Embedder: a NomicBert-architecture encoder (rotary embeddings, SwiGLU, 2048-token context) running in `candle`, which is pure Rust. candle at `5ba5d5b` already ships it (`candle-transformers/src/models/nomic_bert.rs`), so the work is loading the Snowflake weights into it and proving parity, not a port. The alternative is `tract` running an ONNX export of the embedder.
   - Tokenizer: the `tokenizers` crate reading `tokenizer.json`. That crate is Rust, but it pulls `onig` (C) by default unless built with `default-features = false, features = ["fancy-regex"]` [inferred].
   - Random forest:
     - Avoid the pickle entirely.
     - Either run the RF ONNX (`ai.onnx.ml` `TreeEnsembleClassifier`) in `tract`, whose ONNX-ML op coverage should be verified;
     - or, better, convert it once, offline, to a static table of decision trees. That table needs about 100 lines of evaluator code and is trivially auditable [inferred].
   - Avoid `ort`: it brings onnxruntime C++ into the process, which ADR-0002 rules out for the kernel and the egress process.
   - Fidelity risk:
     - Floating-point drift in the embedding can flip RF splits near thresholds.
     - Validate the Rust output against the Python reference on JailbreakHub plus a Maknae corpus, requiring label agreement ≥99.9%.
   - Remaining weakness: the published evasion rate (§4) is a property of the model, not of the port. Treat its score as a weak signal. Unicode normalization and stripping of invisible characters before classification would address the character-injection half of Hackett et al. [inferred].
   - **Complexity: S–M** (the encoder exists in candle; the work is the RF conversion and parity testing).
2. **Perplexity heuristics.**
   - The *logic* is ~40 lines (`heuristics/checks.py:27-103`), and the thresholds are published with their derivation (`jailbreak-protection.mdx:66,93`).
   - It needs a causal LM. GPT-2-large (MIT-licensed [inferred]) is 2–3 s on CPU, so it is out of budget.
   - A smaller LM (distilgpt2 / gpt2-small) in candle would need **re-derived thresholds**, and fidelity to the vendor defaults is lost.
   - It is useful mainly against GCG-style gibberish suffixes.
   - **Complexity: M** (S for the logic, M for the LM plus recalibration).
3. **YARA output-injection rules.**
   - 132 lines of rules for code, SQLi, XSS and template injection (`library/injection_detection/yara_rules/*.yara`, Apache-2.0).
   - They can be evaluated with **YARA-X** (VirusTotal's pure-Rust YARA engine) or rewritten as `regex`-crate patterns.
   - They are relevant to model replies that feed tools, not to prompt injection.
   - **Complexity: S.**
4. **Prompts and taxonomy.**
   - The Aegis 2.0 S1–S23 taxonomy and the self-check and content-safety prompt templates (`examples/configs/nemoguards/prompts.yaml`, `examples/bots/abc/prompts.yml`) are Apache-2.0 text.
   - They could define Maknae's label vocabulary for a PIP verdict, or a judge prompt if Maknae ever adds an LLM-judge PIP via the Egress Daemon.
   - Such a judge would be an extra model round trip, and injectable.
   - **Complexity: S.**
5. **Colang as a concept.** Not worth porting. Maknae's decisions are made by the reference monitor, `maknaed`, over a static policy path (ADR-0002, ADR-0005). Colang is a conversational-flow DSL whose semantics depend on LLM intent generation, so it is non-deterministic and unfit for a static TCB.
6. **The 8B content-safety LoRA.**
   - Portable in principle: candle supports Llama 3.1, and the LoRA can be merged offline.
   - It is an 8B model with the Llama 3.1 license terms and seconds of CPU latency.
   - **Complexity: L.** Not recommended for the hot path.

**Overall Rust-native complexity for items 1, 3 and 4: S–M.** candle already has NomicBert, so most of the work is the random-forest conversion and the equivalence testing.

## 11. Verdict for Maknae

**Learn from, and adapt narrowly. Avoid as-is.**

- **Why not as-is.** NeMo Guardrails is a Python orchestration framework whose strong rails are mostly *additional LLM calls*. Those add a full model round trip each, and the judge can be prompt-injected by the content it judges. Its local jailbreak model is the most evadable of six guardrails under adversarial-ML jailbreak evasion (65.22% ASR) and reached 72.54% under character injection, per independent work, and its jailbreak rails **fail open** by design. It also ships default-on telemetry to NVIDIA with a 10-minute heartbeat, default cloud endpoints, runtime model downloads, `trust_remote_code`, and onnxruntime C++ as a core dependency. Each of these conflicts with ADR-0002, the air gap and fail-closed requirements.
- **What is worth taking**, all under Apache-2.0 or redistributable terms:
  - the JailbreakDetect *design* (a 137M encoder plus a random forest, reimplemented in pure Rust with candle/tract and a flattened tree table, never the pickle), as one low-weight PIP signal;
  - the YARA output-injection rules, via YARA-X;
  - the Aegis 2.0 taxonomy as a verdict vocabulary;
  - the documented perplexity heuristic, as a candidate cheap GCG-suffix check if a small LM is recalibrated.
- **Operational lessons worth copying:**
  - verdict-only judge output;
  - fail-closed on unparseable verdicts.
- **What to reject:**
  - its silent fail-open;
  - speculative generation that sends the prompt before the decision.

## 12. Sources

Pinned repository evidence (commit [`83d03ad`](https://github.com/NVIDIA-NeMo/Guardrails/tree/83d03ad529d2be1399f1dede24be59d4381ee42e)):

- `pyproject.toml`, `uv.lock`, `LICENSE.md`, `CONTRIBUTING.md`, `AI_POLICY.md`, `CHANGELOG.md`
- [`nemoguardrails/telemetry.py`](https://github.com/NVIDIA-NeMo/Guardrails/blob/83d03ad529d2be1399f1dede24be59d4381ee42e/nemoguardrails/telemetry.py)
- [`nemoguardrails/llm/frameworks/default.py`](https://github.com/NVIDIA-NeMo/Guardrails/blob/83d03ad529d2be1399f1dede24be59d4381ee42e/nemoguardrails/llm/frameworks/default.py)
- [`nemoguardrails/actions/llm_judge.py`](https://github.com/NVIDIA-NeMo/Guardrails/blob/83d03ad529d2be1399f1dede24be59d4381ee42e/nemoguardrails/actions/llm_judge.py)
- `nemoguardrails/library/{jailbreak_detection,injection_detection,self_check,content_safety,regex,sensitive_data_detection,tool_safety_check}/`
- `docs/telemetry.mdx`, `docs/configure-rails/guardrail-catalog/{jailbreak-protection,content-safety,self-check}.mdx`, `docs/resources/runtime-security-faq.mdx`
- `examples/configs/nemoguards/{config.yml,prompts.yaml}`, `examples/bots/abc/prompts.yml`
- `.github/workflows/{publish-pypi-approval,publish-wheel,_test}.yml`

Pinned model artefacts (cards and configs only):

- JailbreakDetect: [`nvidia/NemoGuard-JailbreakDetect@cc8b97e2bd6c1667c31476eedaa9a75b4d7ed282`](https://huggingface.co/nvidia/NemoGuard-JailbreakDetect/tree/cc8b97e2bd6c1667c31476eedaa9a75b4d7ed282) (`README.md`, `config.json`)
- Content safety: [`nvidia/llama-3.1-nemoguard-8b-content-safety@ef1f9de54f760180f70b517dd10362d9463ddc58`](https://huggingface.co/nvidia/llama-3.1-nemoguard-8b-content-safety/tree/ef1f9de54f760180f70b517dd10362d9463ddc58) (`README.md`, `adapter_config.json`)
- Topic control: [`nvidia/llama-3.1-nemoguard-8b-topic-control@5ce438e7119061c809e9da819beb5b9287104230`](https://huggingface.co/nvidia/llama-3.1-nemoguard-8b-topic-control/tree/5ce438e7119061c809e9da819beb5b9287104230)
- Snowflake embedder: [`Snowflake/snowflake-arctic-embed-m-long@92d97331f1f4b6a366c1f161354b9f3390cc219f`](https://huggingface.co/Snowflake/snowflake-arctic-embed-m-long/tree/92d97331f1f4b6a366c1f161354b9f3390cc219f)
- [NVIDIA Open Model License (June 2024)](https://developer.download.nvidia.com/licenses/nvidia-open-model-license-agreement-june-2024.pdf) (SHA-256 `396d7de220f6b0e6fcfe33836f1b99a9943769b97c56330444f8efe1b441f607`)

Papers:

- Galinkin & Sablotny, "Improved Large Language Model Jailbreak Detection via Pretrained Embeddings", [arXiv:2412.01547](https://arxiv.org/abs/2412.01547) [vendor-authored]
- Hackett et al., "Bypassing Prompt Injection and Jailbreak Detection in LLM Guardrails", [arXiv:2504.11168v1](https://arxiv.org/html/2504.11168v1) [third-party]

Public context, which is not evidence for any code claim above:

- NIM licensing [vendor-doc, web-context]: [docs.api.nvidia.com/nim/docs/product](https://docs.api.nvidia.com/nim/docs/product); [NIM offerings](https://docs.nvidia.com/nim/large-language-models/latest/about-nim-llm/nim-offerings.html)
- Open Agent Safety Platform:
  - [WIRED](https://www.wired.com/story/nvidias-answer-to-rogue-agents-is-an-open-source-ai-security-system/)
  - [StorageReview](https://www.storagereview.com/news/nvidia-open-agent-safety-platform-openshell-sentry-bluefield-4)
  - [NVIDIA NemoClaw](https://www.nvidia.com/en-us/ai/nemoclaw/)
- Maknae's [OpenShell assessment](2026-09-29-openshell-assessment.md), which pins OpenShell at `1358941`
