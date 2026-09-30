# Protect AI LLM Guard — Assessment Against Maknae

| | |
|---|---|
| **Status** | Assessment record. It informs the OWASP LLM coverage work. It creates no roadmap commitment and supersedes no ADR. |
| **Date** | 2026-09-30 |
| **Subject** | [`protectai/llm-guard`](https://github.com/protectai/llm-guard) at commit [`168c103`](https://github.com/protectai/llm-guard/tree/168c1034ffdb33837e7ae6fd6a16b80567c1be03) (2026-07-08T23:58:39Z, "Archiving Project (#355)"), with its default injection model [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/tree/90c9989b1a342275dd0d1a95aad283c04e075671) at HF revision `90c9989` (HEAD, a README-only archive notice dated 2026-07-09). A Python library of independent input and output scanners; code MIT, the injection model Apache-2.0. **Archived upstream.** |
| **Method** | The repository and the model's card, configs and tokenizer files were mirrored outside this tree and **read only**: nothing was built, installed or executed from the candidate, and no weight files were downloaded. Evidence labels: **[code]** read in the pinned source; **[card]** vendor model card or docs (documented by the vendor); **[measured]** measured during this assessment, and only with Python's standard-library `unicodedata` module, never the candidate's code; **[inferred]** reasoning; **[web]** public web, context not evidence. Public web material is context only and is marked as such. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |

This assessment is one of a set of four guard-model assessments ([Prompt Guard](2026-09-30-prompt-guard-assessment.md), [Llama Guard](2026-09-30-llama-guard-assessment.md), [NeMo Guardrails](2026-09-30-nemo-guardrails-assessment.md), LLM Guard) whose synthesis is [`2026-09-30-owasp-llm-top10-coverage.md`](2026-09-30-owasp-llm-top10-coverage.md).

**Citation shorthand.** Code paths are at commit `168c103`; `util.py` is `llm_guard/util.py`, `model.py` is `llm_guard/model.py`, `prompt_injection.py`, `secrets.py`, `invisible_text.py` and the other input scanners are under `llm_guard/input_scanners/`, and `url_reachabitlity.py` (upstream's spelling) and the other output scanners are under `llm_guard/output_scanners/`. "Model card" and the model's `config.json`, `tokenizer.json` and `tokenizer_config.json` are at HF revision `90c9989`; `onnx/…` files are in the same repository. "candle" is [`huggingface/candle`](https://github.com/huggingface/candle/tree/5ba5d5b468b5b1df40e82dd3d556987bedeea041) at `5ba5d5b`.

**Model pins.** LLM Guard's code pins the older model revision `89b085cd330414d3e7d9dd787870f315957e1e9f` (`prompt_injection.py:39-51`). The LFS weight object IDs are unchanged since `69d3788a…` (2024-04-22, "Add ONNX version of the model"). The files read were `README.md`, `config.json`, `tokenizer_config.json`, `tokenizer.json`, `special_tokens_map.json`, `added_tokens.json`, `onnx/config.json` and `onnx/tokenizer_config.json` at `90c9989`, and `README.md` at `89b085c` for the diff.

## 0. Disposition (read first)

**The proposed use.** Maknae is evaluating a content and prompt-injection filter that inspects prompt text, tool results (file content the loop read, which returns to the trust plane in the next `session.prompt` turn) and model replies, and gives the kernel a recommendation. The filter would be a Policy Information Point (PIP), never a Policy Decision Point (PDP): `maknaed` stays the sole PDP (ADR-0005), and the content informs but never authorizes (AGENTS.md core principle 2). The candidate placement is beside the Egress Daemon (`maknae-egress`), which already receives prompt content from `maknaed` today, but only after the kernel has decided and recorded the turn (ADR-0023 decision 3); §9 states what that order costs a filter. The maintainer does not want latency added on top of the policy check.

**LLM Guard is archived** (July 2026) after Protect AI's acquisition by Palo Alto Networks (completed 2025-07-22). It is a Python/torch/Presidio stack that pulls models and NLP data at runtime, and two of its scanners are actively hostile to a trust plane: URLReachability fetches attacker-chosen URLs, and Secrets spills prompts to temporary files. Its worthwhile parts are small and portable.

**Verdict: learn from, and adapt the pieces; avoid adopting it as-is.** The full verdict is §11.

## 1. Identity and provenance

- **Owner:** Protect AI (originally Laiyer AI, which Protect AI acquired in early 2024 **[web]**). The main author is `asofter` (405 commits), then `dependabot[bot]` (76) and `CandiedCode` (8) (GitHub contributors API). The core of the project is essentially one maintainer.
- **Timeline:**
  - Repository created 2023-07-27. First PyPI release 0.0.1 on 2023-08-07 (`docs/changelog.md:393`).
  - Latest and last release **0.3.16, 2025-05-19** (`docs/changelog.md:22`). `[Unreleased] - 0.3.17` is an empty stub (`docs/changelog.md:8-19`).
  - Cadence: roughly monthly through 2024, then about one release a year.
- **Activity:**
  - The last functional commit was `9e007675b9` on 2025-09-03 (a placeholder fix).
  - The repository is **archived** (read-only; GitHub API `archived: true`, `pushed_at 2026-07-08T23:58:40Z`). The last commit, `168c103` "Archiving Project (#355)", is dated 2026-07-08T23:58:39Z (UTC), and the matching archive notice on the HF model card is commit `90c9989`, dated 2026-07-09; the archive date is taken as 2026-07-08/09. There are 38 open issues and PRs frozen (GitHub's `open_issues_count`, which counts both), 3,213 stars and 462 forks.
  - `README.md:1-4`: "THIS PROJECT HAS BEEN ARCHIVED. This project and its associated models on Hugging Face are no longer under active development or maintained." The HF model card carries the same banner (model card `README.md:31-34`).
- **Ownership change:**
  - Palo Alto Networks announced its intent to acquire Protect AI on 2025-04-28 and **completed the acquisition on 2025-07-22** [web: PANW press releases]. Protect AI's technology was folded into **Prisma AIRS** [web].
  - The open-source repository went quiet about 6 weeks after closing (last functional commit 2025-09-03) and was archived about 12 months after closing. **[inferred]:** the open-source project was wound down in favour of the commercial product.
- **Signing and attestation:**
  - There are no GitHub releases (the releases API returns empty).
  - PyPI has no provenance or attestation for `llm_guard-0.3.16-py3-none-any.whl` ("No provenance available", PyPI integrity API).
  - HF model files are verifiable only by LFS SHA-256, for example `model.safetensors` `6521cb8d…0424` and `onnx/model.onnx` `f0ea7f23…228c`. There are no signatures.

## 2. License

- **Code:** MIT ("The MIT License (MIT) Copyright (c) Protect AI", `LICENSE:1-3`). `llm_guard_api` is also MIT (`llm_guard_api/pyproject.toml` classifier).
- **Model `deberta-v3-base-prompt-injection-v2`:** **Apache-2.0** (card front-matter, model card `README.md:2`; a full Apache 2.0 `LICENSE` file was added in HF commit `e6535ca4`, 2024-05-28). The base model `microsoft/deberta-v3-base` is MIT **[web]**.
- **Not gated:** HF API `gated: False`. By contrast, the **small** v2 variant *is* gated: "This is gated model, which requires our approval" (`prompt_injection.py:53-71`, `kwargs={"token": True}`).
- **Air-gap redistribution:**
  - Apache-2.0 permits redistributing the weights inside an air-gapped package, with the LICENSE/NOTICE carried.
  - There is no AUP, no MAU cap and no "Built with" clause.
- **Caveats [card]:**
  - The card says the training data is a mix of 22 public datasets with mixed licenses, including CC-BY-3.0 (`VMware/open-instruct`) and CC-BY-4.0 (`xstest`), plus "6 datasets" labelled "No License (public domain)" (model card `README.md:73-80`).
  - "No license" is **not** public domain. That is an upstream data-provenance weakness, not a weights-license restriction. **[inferred]:** acceptable for a home lab. A DoD SCRM reviewer may flag it.
- **The other scanners' models have their own licenses,** which were not individually verified. Examples: `unitary/unbiased-toxic-roberta`, `papluca/xlm-roberta-base-language-detection`, the Isotonic ai4privacy PII models and the `MoritzLaurer` zero-shot models. The ai4privacy lineage in particular should be checked before any redistribution.

## 3. What it is and how it works

**LLM Guard** is a Python library: a bag of independent `Scanner` classes, each with `scan(prompt[, output]) -> (sanitized_text, is_valid, risk_score)`. It has no orchestration engine and no LLM-as-judge. There is an optional FastAPI server (`llm_guard_api/`).

- `risk_score` is mapped to [-1, 1] around the scanner threshold (`util.py:134-144`).
- Several scanners **mutate** the text (redaction, anonymization, invisible-character stripping), not just score it.

**The PromptInjection scanner** (`llm_guard/input_scanners/prompt_injection.py`):

- **Default model:** V2 (`prompt_injection.py:145-146`), loaded through a `transformers` text-classification `pipeline` (`prompt_injection.py:159-164`) with `max_length=512, truncation=True` (`prompt_injection.py:46-50`).
- **Default threshold:** 0.92 (`prompt_injection.py:129`). The docs example uses 0.5 (`docs/input_scanners/prompt_injection.md:55`).
- **Score:** `score` if the label is `INJECTION`, else `1-score`, rounded to 2 dp (`prompt_injection.py:176-179`). It returns on the first segment over the threshold (`prompt_injection.py:184-191`).
- **Match types** (`prompt_injection.py:74-116`):
  - `FULL` (default): the whole text, **silently truncated to 512 tokens**. The HF fast tokenizer's `truncation.direction` is `Right` (`tokenizer.json`: `truncation: {max_length: 512, strategy: LongestFirst, direction: Right}`), so **everything after roughly token 510 is never seen**.
  - `SENTENCE`: an NLTK `punkt_tab` sentence split. It calls `nltk.download("punkt_tab")` **at runtime** if missing (`util.py:152-160`).
  - `CHUNKS`: **character** windows of 256 characters with 25 characters of overlap (`PROMPT_CHARACTERS_LIMIT=256`, `prompt_injection.py:22`, `:92-99`; `util.py:163-189`, despite the "word" in its name).
  - `TRUNCATE_TOKEN_HEAD_TAIL`: head 128 + tail 382 tokens (`util.py:192-197`; the code comment at `prompt_injection.py:77` says "126 head", the code says 128). **The middle is unscanned.**
  - `TRUNCATE_HEAD_TAIL`: the first and last 126 characters joined by "..." (`prompt_injection.py:108-114`).

**The model** (`config.json`):

- `DebertaV2ForSequenceClassification`: 12 layers, hidden 768, 12 heads, intermediate 3072.
- Relative attention with `position_buckets: 256`, `max_position_embeddings: 512`, vocab 128,100, float32.
- Labels `{0: SAFE, 1: INJECTION}`.
- Parameter count: about 184M (DeBERTa-v3-base, per the Hackett et al. paper **[web]**). `model.safetensors` is 737,719,272 bytes (fp32; consistent with about 184M params × 4 B).
- `onnx/config.json` is identical except for `_name_or_path`.

**The tokenizer** (`tokenizer.json`):

- SentencePiece **Unigram**, 128,000 pieces (`spm.model`, 2.46 MB, is also present).
- Normalizer `Sequence[Strip, Precompiled(charsmap), Replace]`; pre-tokenizer `Metaspace(▁, prepend_scheme=always)`; a `TemplateProcessing` post-processor (`[CLS] … [SEP]`).
- `do_lower_case=false`, `split_by_punct=false`, `model_max_length` effectively unbounded (`tokenizer_config.json:47-55`). The ONNX tokenizer config adds `max_length: 512` (`onnx/tokenizer_config.json:50`).

**ONNX variants:**

- `onnx/model.onnx` (738,563,188 B, fp32) in the same repository, pinned at the same revision by LLM Guard (`prompt_injection.py:42-45`).
- A separate `protectai/llm-guard-models-onnx-gpu-optimized` repository also exists (now archived) **[web]**.
- The ONNX path is used only via `optimum.onnxruntime.ORTModelForSequenceClassification` (`llm_guard/transformers_helpers.py:43-65`).

## 4. What it detects, and what it does not

### 4.1 Full scanner catalog (pinned source)

Classification key: **ML** = HF transformer model; **RX** = regex, heuristic or lexicon; **EXT** = makes external network calls at scan time.

**Input scanners** (`llm_guard/input_scanners/`, 16):

| Scanner | Class | Mechanism (file:line) |
|---|---|---|
| Anonymize | ML + RX | Presidio analyzer + spaCy `en_core_web_sm` (**downloaded at runtime** if absent, `anonymize_helpers/analyzer.py:100-102`) + an HF NER recognizer (default Isotonic DeBERTa-ai4privacy-v2, `anonymize.py:113-114`) + 18 custom regex patterns (`anonymize_helpers/regex_patterns.py`) + optional Faker; stores originals in a `Vault` |
| BanCode | ML | `vishnun/codenlbert-sm` / `-tiny` (`ban_code.py:14-28`) |
| BanCompetitors | ML | `guishe/nuner-v1_orgs` NER (`ban_competitors.py:17`) |
| BanSubstrings | RX | substring/word match |
| BanTopics | ML | zero-shot NLI; default `MoritzLaurer/roberta-base-zeroshot-v2.0-c` (`ban_topics.py:80-83,124`); options include deberta-v3-large and bge-m3 |
| Code | ML | `philomath-1209/programming-language-identification` (`code.py:14-18`) |
| EmotionDetection | ML | `SamLowe/roberta-base-go_emotions` |
| Gibberish | ML | `madhurjindal/autonlp-Gibberish-Detector-492513457` (`gibberish.py:13-17`) |
| InvisibleText | RX | Unicode general category ∈ {Cf, Co, Cn} → strip and flag (`invisible_text.py:21-42`) |
| Language | ML | `papluca/xlm-roberta-base-language-detection` (`language.py:13-17`) |
| PromptInjection | ML | DeBERTa-v3-base v2 (§3) |
| Regex | RX | user patterns (Presidio `TextReplaceBuilder` for redaction) |
| Secrets | RX | `detect-secrets` (`bc-detect-secrets==1.5.43`) with **112 plugins**: 94 custom `RegexBasedDetector` files in `secrets_plugins/` + 18 built-ins, including Base64 entropy (limit 4.5) and Hex entropy (limit 3.0) (`secrets.py:20-416`) |
| Sentiment | RX | NLTK VADER lexicon; **`nltk.download(lexicon)` at init** (`sentiment.py:27-28`) |
| TokenLimit | RX | `tiktoken` `cl100k_base` (the BPE file is fetched from the network on first use unless cached **[inferred from tiktoken behaviour]**) |
| Toxicity | ML | `unitary/unbiased-toxic-roberta` (`toxicity.py:13-17`), threshold 0.5 |

**Output scanners** (`llm_guard/output_scanners/`, 22):

| Scanner | Class | Mechanism |
|---|---|---|
| BanCode, BanCompetitors, BanSubstrings, BanTopics, Code, EmotionDetection, Gibberish, Language, Regex, Sentiment, Toxicity | as the input versions | wrappers over the input scanners |
| Bias | ML | `valurank/distilroberta-bias` (`bias.py:14`) |
| Deanonymize | RX | vault lookup + `fuzzysearch` (`deanonymize.py:79-84`) |
| FactualConsistency | ML | NLI via deberta-v3-base zero-shot (`factual_consistency.py:5`) |
| JSON | RX | parse + `json_repair` |
| LanguageSame | ML | the language model on prompt vs output |
| MaliciousURLs | ML | `DunnBC22/codebert-base-Malicious_URLs` on regex-extracted URLs (`malicious_urls.py:11-13`) |
| NoRefusal | ML | `ProtectAI/distilroberta-base-rejection-v1` (`no_refusal.py:15`) |
| ReadingTime | RX | word count |
| Relevance | ML | BGE embeddings (`relevance.py:16-34`) |
| Sensitive | ML + RX | the same Presidio/NER stack as Anonymize (`sensitive.py:3-24`) |
| **URLReachability** | **EXT** | `requests.get(url, timeout=5)` on **every URL the model emitted** (`url_reachabitlity.py:33-41,44`) |

The URL extractor is `http[s]?://…` only (`util.py:200-209`). Its character class `[$-_@.&+]` is an accidental `$`–`_` range, so it is broad but http(s)-only. It misses bare domains, other schemes and obfuscated URLs.

There are no LLM- or API-backed scanners. The only EXT at scan time is URLReachability. There are also **runtime downloads** from the HF Hub (every ML scanner on first use), NLTK, spaCy and tiktoken.

### 4.2 The injection model's coverage

- **Direct and indirect:**
  - The docs frame the scanner as covering both (`docs/input_scanners/prompt_injection.md:9-37`).
  - It is a single-text binary classifier with no notion of instruction vs data channel. **[inferred]:** indirect injection is covered only insofar as the injected text "looks like" an injection within the scanned window.
- **Not jailbreaks, English only [card]:** "It does not detect jailbreak attacks or handle non-English prompts" (model card `README.md:59-60`).
- **Not system prompts [card]:** "we do not recommend using this scanner for system prompts, as it produces false-positives" (model card `README.md:62`, added in the 2026 revision).
- **Vendor accuracy [card]:**
  - Post-training evaluation on 20k prompts from "untrained datasets": accuracy 95.25%, precision 91.59%, recall 99.74%, F1 95.49% (model card `README.md:91-96`).
  - The training-evaluation figures of 99.9% are in-distribution. Neither is independent.
- **Independent critiques [web — context]:**
  - Hackett et al., "Bypassing Prompt Injection and Jailbreak Detection in LLM Guardrails", arXiv:2504.11168 (2025), evaluated Protect AI v2 directly:
    - baseline detection 84.15% on their adversarial prompt-injection set;
    - average character-injection attack success rate (ASR) 20.26%, "only heavily bypassed by Emoji and Unicode tag Smuggling";
    - adversarial-ML word-perturbation ASR 67.87% (TextFooler most effective);
    - v2 was also used as a white-box surrogate to transfer attacks to Azure Prompt Shield.
  - InjecGuard / NotInject, arXiv:2410.22770: ProtectAI v2 suffers "significant over-defense… over-defense accuracy falling below 60%", keying on trigger words such as "ignore". This is a false-positive problem for benign text that discusses injection, which is exactly what security docs, code review and agent tool output contain.
  - PIDS-Bench (IEEE Access, 2026) likewise reports substantial false positives on externally sourced prompts [web; not read in full].

### 4.3 Code-level bypasses found in the pinned source

- **[code]** In FULL mode, anything past about 510 tokens is never classified (right truncation), so padding with benign text defeats it. In the head/tail modes the middle is unscanned.
- **[measured, with Python's standard-library `unicodedata` module, not the candidate's code]** InvisibleText flags only Cf/Co/Cn. It catches zero-width characters (U+200B–200D, 2060, FEFF), **Unicode tag characters** (U+E0000–E007F are Cf), bidi overrides (U+202E), the soft hyphen and U+180E. It **misses**:
  - **variation selectors** U+FE00–FE0F and U+E0100–E01EF (category **Mn**): the "emoji smuggling" channel Hackett et al. found most effective;
  - U+034F (Mn);
  - U+3164 / U+115F Hangul fillers (Lo);
  - U+2800 Braille blank (So).
- **[inferred]** Therefore a stack of InvisibleText + PromptInjection is bypassable by variation-selector smuggling end to end. This was not run; it follows from the two facts above.
- **[code]** InvisibleText also **strips ZWJ/ZWNJ**, which breaks emoji sequences and legitimately required joiners in Persian and Indic scripts. It flags any Private-Use character as an attack. Pure-ASCII input returns early (`invisible_text.py:24-29`).

## 5. Language, runtime and dependencies

- **Python 3.10–3.12** (`pyproject.toml` `requires-python`).
- **Hard dependencies** (`pyproject.toml`): `torch>=2.4.0`, `transformers==4.51.3`, `presidio-analyzer`/`presidio-anonymizer==2.2.358` (which pull in **spaCy**), `bc-detect-secrets==1.5.43`, `nltk`, `tiktoken`, `faker`, `fuzzysearch`, `json-repair`, `regex`, `structlog`.
- **ONNX is optional only in name:**
  - The `onnxruntime` extra adds `optimum[onnxruntime]==1.25.2`.
  - **torch is still a hard dependency, and is still imported on the ONNX path:** `Model.__post_init__` calls `device()` (`model.py:35-40`), which `lazy_load_dep("torch")`s (`util.py:103-111`).
  - The tokenizer is always loaded via `transformers.AutoTokenizer` (`llm_guard/transformers_helpers.py:14-26`).
  - So an ONNX deployment still carries torch + transformers + onnxruntime (C++) + optimum.
- **The API server** adds FastAPI, uvicorn, slowapi and a full OpenTelemetry stack, including AWS X-Ray/EC2 resource detection (`llm_guard_api/pyproject.toml`; `llm_guard_api/app/otel.py:1-60`). The OTel exporters are config-driven, not on by default **[code]**.
- **GPU:** not required. It uses CUDA or Apple MPS automatically if present (`util.py:104-111`).
- **Serving modes:** an in-process Python library, or a FastAPI HTTP service (`llm_guard_api/`, with Dockerfiles for CPU and CUDA).

## 6. Performance and footprint

- **On disk:** `model.safetensors` 737.7 MB fp32; `onnx/model.onnx` 738.6 MB fp32; `tokenizer.json` 8.6 MB; `spm.model` 2.5 MB (HF tree API). No quantized variant is in this repository.
- **Latency [card: `docs/input_scanners/prompt_injection.md:73-97`; 384-character input, 5 runs; not independent]:**

| Hardware | PyTorch average | ONNX average |
|---|---|---|
| AWS m5.xlarge (4 vCPU) | 212.87 ms | 104.21 ms |
| AWS r6a.xlarge | 205.05 ms | 103.21 ms |
| Azure D4as_v4 | 421.46 ms | 177.30 ms |
| AWS g5.xlarge GPU | 81.01 ms | **7.65 ms** |

  The "QPS" column in that table (for example 3,684 QPS at 104 ms) is arithmetically inconsistent with a single stream, so treat it as characters per second or ignore it **[inferred]**.
- **candle reference timing [3p: the candle project's example README]:** the candle `debertav2` example runs **exactly this model**, `protectai/deberta-v3-base-prompt-injection-v2`, on one short sentence: "Inferenced inputs in" 123.78 ms with `--cpu` (CPU model not stated) and 100.01 ms on CUDA (candle `candle-examples/examples/debertav2/README.md:113-132`).
- **Longer inputs [3p]:** tract, pure Rust, measured a DeBERTa-v3-base classifier at about 132 ms for 128 tokens and 344 ms for 256 tokens, single-threaded on an Apple M4 Pro (sonos/tract PR #2531; see the [Prompt Guard assessment](2026-09-30-prompt-guard-assessment.md) §6). Cost grows superlinearly with length.
- **Memory:**
  - **[inferred]** about 0.75 GB of weights resident in fp32, plus torch/transformers runtime overhead. A Python process with torch + Presidio + spaCy is typically multi-GB.
  - Each additional ML scanner adds its own model (BanTopics' deberta-large alone is about 1.7 GB **[inferred from architecture]**).
- **Throughput:** `batch_size` defaults to 1 (`model.py:36-38`). CHUNKS/SENTENCE mode multiplies calls per text, so latency scales with document length.
- **[inferred] for Maknae:**
  - The vendor's ~100–200 ms CPU figures are for a 384-character input (roughly 100 tokens), not a 512-token window; a full 512-token window costs more, extrapolating from tract's 344 ms at 256 tokens.
  - A 50 KB tool result in CHUNKS mode (256-character windows with a 25-character overlap) is about 216 windows. At ~100 ms each that is **about 20 s of CPU per blob**.
  - That is incompatible with the maintainer's requirement that no latency be added on top of the policy check. The verdict must reach the kernel before the decision (§9), so the scan cannot be run asynchronously; it can only be made cheaper (a quantized model, token-based windows, fewer windows) or skipped.

## 7. Strengths

- A clean, well-documented **taxonomy** of input and output checks. It is a useful checklist even if none of the code is used.
- The injection model is **Apache-2.0 and ungated**, with safetensors and a prebuilt ONNX export. It is the most permissively licensed of the widely cited open prompt-injection classifiers.
- It is small enough (184M) for CPU inference. Its architecture is directly supported by candle (`DebertaV2SeqClassificationModel`, candle `candle-transformers/src/models/debertav2.rs:1269-1312`).
- Model revisions are pinned by commit hash throughout the code, which is good discipline.
- The Secrets plugin set (94 provider-specific regexes, gitleaks-style) is a ready-made, MIT-licensed regex corpus.

## 8. Weaknesses

- **Maintenance risk: terminal.**
  - The code and models are archived (July 2026). The last release was 2025-05-19. The owner was acquired (Palo Alto Networks, completed 2025-07-22), and the capability moved into the proprietary Prisma AIRS.
  - There will be no fixes for new bypasses, no retraining and no CVE response.
- **False positives:**
  - Over-defense on trigger words (InjecGuard, NotInject <60% **[web]**).
  - The vendor warns against using it on system prompts.
  - It will misfire on security documentation and code that discuss injection. For Maknae, whose tool results are often source code and documentation, that is the dominant case **[inferred]**.
- **False negatives:**
  - Truncation beyond 512 tokens [code].
  - Variation-selector / emoji smuggling [web + the measured gap in InvisibleText].
  - Word-level adversarial perturbation (67.87% ASR [web]).
  - Non-English text and jailbreaks [card].
- **Supply chain:**
  - Weights are safetensors (no pickle on the default path). `training_args.bin` in the HF repository *is* a torch pickle but is not loaded by `from_pretrained` **[inferred]**.
  - `trust_remote_code` is not used anywhere [code, grep].
  - **Runtime network fetches:** the HF Hub model and tokenizer (`from_pretrained`, `llm_guard/transformers_helpers.py:22-25,88-93`), `nltk.download` (`util.py:158`, `sentiment.py:28`), `spacy.cli.download` (`anonymize_helpers/analyzer.py:102`), and the tiktoken BPE.
  - All of these break in an air gap unless pre-cached and forced offline (`HF_HUB_OFFLINE=1`, and so on). Several fail open to a download attempt rather than failing closed.
  - There is no signing or provenance on the PyPI wheel or the model files.
- **Dangerous behaviours for a trust-plane component:**
  - **URLReachability performs SSRF on attacker-controlled input:** it issues GET requests to every URL in model output (`url_reachabitlity.py:38`). For an agent that is a ready-made **data-exfiltration channel** (data encoded in the URL's query string) and an internal-network probe.
  - **Secrets writes the full prompt to a temporary file with `delete=False`** (`secrets.py:466-468`). The prompt reaches disk on every scan, the happy path included: `os.remove` (`secrets.py:494`) unlinks the file but does not wipe its blocks, and on an exception the file is not removed at all, leaving plaintext secrets in place. ADR-0026 requires every Maknae-owned buffer holding secret-class bytes, which include prompt text, to be zeroizing from allocation; a plaintext copy persisted to disk is well outside that rule, so the behaviour could not be carried into a Maknae process.
  - Secrets' `REDACT_HASH` uses unsalted MD5 (`secrets.py:451`). Redaction uses `prompt.find`, so only the first occurrence of a repeated secret is located (`secrets.py:482`).

## 9. Integration into Maknae as-is

- **Shape:**
  - Only a **Python sidecar service** is practical: the `llm_guard_api` FastAPI server, or a custom gRPC/UDS wrapper, under its own account next to `maknae-egress`.
  - It would receive each prompt, tool result and reply over a local socket and return `(is_valid, risk_score)` per scanner.
  - The kernel treats the result as a PIP input (inform, never authorize).
  - **Where the verdict must arrive: ADR-0023's write-ahead order.** ADR-0023 decision 3 fixes the order of a turn: the kernel decides `session.prompt`, appends the write-ahead record, and only then hands the turn to `maknae-egress`. A PIP that sits beside the Egress Daemon and scans what it receives therefore sees the content only after the decision, and its verdict informs nothing. For a verdict on input content to count, it must reach `maknaed` **before** the `session.prompt` decision. With the scanner beside the Egress Daemon, that means a new channel from `maknaed` to the scanner, or an extra round trip before the decision. That cost is on the critical path of every turn, on top of the scan time itself. Running the scan asynchronously, or pipelined with the model call, is not a latency fix for inputs: it sends the content before the verdict exists, which is the objection the [NeMo Guardrails assessment](2026-09-30-nemo-guardrails-assessment.md) raises against IORails speculative generation. Replies are harder still. In the shipped design the reply-leg release verdict is the `session.prompt` verdict, computed before the model output exists (ADR-0023 decision 3, "The response leg is a release"), so no content-dependent check on a reply can bind until that release is un-collapsed into a decided `session.update`, for which #229 landing is a named trigger.
- **TCB:**
  - If the sidecar is advisory only and fail-closed on timeout or error, it can sit **outside** the TCB as an untrusted PIP. But then an attacker who can make it crash or stall can deny service, and a sidecar that answers "valid" wrongly is only as bad as no filter.
  - It cannot live *inside* `maknae-egress` without violating ADR-0002, which requires the egress process to be 100% Rust (Python, and the C/C++ extensions in torch, onnxruntime, spaCy and tokenizers). (Maknae's egress process already links native code, per `cargo tree -p maknae-egress`: the AWS-LC crypto module (`aws-lc-fips-sys`, with the non-FIPS `aws-lc-sys` also in the tree), and, on macOS, Security.framework and CoreFoundation through FFI (`rustls-platform-verifier` → `security-framework-sys` / `core-foundation-sys`, reached through `reqwest`). A model runtime is a different order of native code from either.)
- **FIPS:** not directly relevant (no cryptography on the path, apart from MD5 in the redaction mode). The sidecar's own Python/OpenSSL would be a separate, non-AWS-LC crypto module if it served TLS **[inferred]**.
- **Air gap:** feasible only with a pre-populated HF cache, NLTK data and the spaCy model baked into the package, plus offline environment flags. **URLReachability must be disabled.** The HF/NLTK/spaCy download-on-miss paths need to be made fatal.
- **macOS on Apple Silicon:** torch, transformers, spaCy and Presidio install on Apple Silicon, and `device()` picks MPS automatically. But this is a Python-plus-wheels distribution to ship and keep patched on a production platform, and it is **unmaintained upstream** **[inferred]**.
- **Latency:** adds the pre-decision round trip plus the scan: about 100–200 ms of CPU per ~100-token input (the vendor's 384-character figures), more for longer windows, and about 20 s for a 50 KB tool result in CHUNKS mode (§6). Scanning every tool result before the decision would dominate request latency.
- **Complexity: L.** A Python runtime and a multi-GB dependency set to package offline for two operating systems and two architectures, lifecycle and health management, pinning and a CVE watch on torch, transformers and Presidio carried by Maknae (upstream is dead), and a fail-closed protocol design. All of this for a component with known bypasses.

## 10. Taking the interesting parts and reimplementing them natively in Rust

| Piece | Port cost | Notes |
|---|---|---|
| **InvisibleText** | **S** | About 30 lines: `char::general_category` via `unicode-general-category` or a static table. Port it **fixed**: add variation selectors (U+FE00–FE0F, U+E0100–E01EF), U+034F, the Hangul fillers, U+2800, and tag characters explicitly. Report rather than strip; allow ZWJ/ZWNJ inside valid emoji and script contexts to avoid false positives. Pure Rust, no model. Sub-microsecond per KB **[inferred]**. |
| **Secrets regexes** | **S–M** | The 94 provider regexes in `secrets_plugins/*.py` are MIT and portable to the `regex` crate (RE2-style, linear time; check for any look-around, which the `regex` crate lacks, and use `fancy-regex` only if needed). Add Shannon-entropy detectors for base64 and hex (limits 4.5 / 3.0, `secrets.py:414-415`) and the ~16 detect-secrets built-ins (AWS, Stripe, JWT, private key and so on; Apache-2.0 upstream). Keep matching in memory, with zeroizing buffers per ADR-0026, and never write to temporary files. |
| **URL checks** | **S** | Port only extraction and static checks (a scheme allow-list, a host allow/deny list, IP-literal and private-range detection, punycode/IDN homoglyph flags) with the `url` crate. **Do not port URLReachability** (SSRF and exfiltration). The MaliciousURLs CodeBERT model is optional and of low value. |
| **PromptInjection classifier** | **M** | Weights: Apache-2.0, so redistribution in an offline bundle is permitted. See the options and details below. |
| **Anonymize / Sensitive (Presidio + spaCy NER)** | **XL** — do not port | Presidio's recognizer registry, context enhancers and spaCy pipelines have no Rust equivalent. The portable subset is only the 18 regex patterns (`anonymize_helpers/regex_patterns.py`: email, credit card, IP, SSN, phone and so on), which is **S**. Transformer NER (ai4privacy DeBERTa) could run through the same candle DeBERTa path, but that is a second 700 MB model and the license lineage is unverified. |
| **Other ML scanners** (BanTopics, Toxicity, Gibberish, Language, Code, Bias, Relevance, FactualConsistency, NoRefusal) | **M each, low value** | Each is another BERT-family model to vendor, license-check and keep. None is a security control for Maknae's threat model; skip them. |
| **Taxonomy and heuristics** | **S** | The scanner list itself (input vs output, redact vs flag, the risk-score normalization) is a useful design reference. |

**PromptInjection classifier options:**

- **`candle` (pure Rust):** `candle-transformers::models::debertav2` has `DebertaV2SeqClassificationModel` (candle `candle-transformers/src/models/debertav2.rs:1269`), which loads `config.json` + `model.safetensors` directly. No conversion is needed. **Preferred:** it adds no C or C++ to the process (ADR-0002's 100% Rust rule; for the native code the egress process already links, see §9), and it works on Linux amd64/arm64 and macOS (CPU, optionally Metal). candle contains `unsafe` internally; ADR-0027 confines `unsafe` only in Maknae's own workspace members, so a dependency's `unsafe` is a review matter, not a gate result.
- **`tract` (pure-Rust ONNX):** would consume `onnx/model.onnx`. DeBERTa's disentangled relative-attention graph uses Gather/bucket ops. Operator coverage is **unverified**: test it before relying on it.
- **`ort`:** brings the onnxruntime C++ into the process. It violates ADR-0002 in the kernel or the egress process; it is acceptable only in a separate untrusted sidecar.
- **Tokenizer:** the `tokenizers` crate loads `tokenizer.json` (Unigram + Metaspace + Precompiled normalizer + TemplateProcessing, all supported). It pulls in `onig` (C) only if the `onig` feature is on; use `default-features=false` with the `fancy-regex` feature to stay pure Rust **[inferred; verify with `cargo tree`]**.

**Fidelity risk:**

- Parity must be proven on a golden set: logits within about 1e-4 of the reference PyTorch output. candle's DeBERTa-v2 port is community-contributed (2025).
- The `position_buckets=256` / `share_att_key` / `norm_rel_ebd` paths must match. The Strip + Precompiled normalizer must match exactly, because a tokenizer mismatch silently degrades accuracy.
- Port **CHUNKS** (overlapping windows over the full text), never FULL-with-truncation, so that nothing past 512 tokens goes unscanned. Prefer token-based windows (for example 512 with 64 overlap) over 256-character windows.

**Performance:**

- fp32 on CPU: candle's own example measures 123.78 ms for one short sentence with this model (§6); a full 512-token window costs more, extrapolating from tract's 344 ms at 256 tokens **[inferred]**.
- Options to reduce it: int8/fp16 quantization via candle, or distillation.
- The model is frozen and archived, so any retraining (non-English, jailbreaks, over-defense) falls to Maknae.

**Overall complexity:**

- **S** for InvisibleText + Secrets + URL static checks together.
- **M–L** adding the classifier, including the golden-parity harness, model packaging (a 0.74 GB artifact with a pinned SHA-256), windowing and a latency budget.

## 11. Verdict for Maknae

**Learn from, and adapt the pieces; avoid adopting it as-is.** LLM Guard is archived (July 2026) after Protect AI's acquisition by Palo Alto Networks (2025-07-22). It is a Python/torch/Presidio stack that pulls models and NLP data at runtime, and it contains two behaviours that are actively hostile to a trust plane:

- URLReachability fetches attacker-chosen URLs;
- Secrets spills prompts to temporary files.

Running it as-is means an unmaintained multi-GB sidecar outside the TCB, with known bypasses: 512-token truncation, variation-selector smuggling and word-perturbation attacks. The worthwhile parts are small and portable:

- a corrected InvisibleText check;
- the MIT Secrets regex corpus plus entropy detectors;
- static URL checks;
- optionally, the Apache-2.0 DeBERTa-v3 injection classifier, run natively through `candle` + `tokenizers` over overlapping windows.

That classifier is useful only as a low-weight advisory signal (a PIP) with strict golden-parity tests, given its documented over-defense and bypass rates.

## 12. Sources

**Pinned:**

- Code: [`protectai/llm-guard@168c1034ffdb33837e7ae6fd6a16b80567c1be03`](https://github.com/protectai/llm-guard/tree/168c1034ffdb33837e7ae6fd6a16b80567c1be03)
- Model: [`protectai/deberta-v3-base-prompt-injection-v2@90c9989b1a342275dd0d1a95aad283c04e075671`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/tree/90c9989b1a342275dd0d1a95aad283c04e075671) (the code-pinned revision is `89b085cd330414d3e7d9dd787870f315957e1e9f`; weights unchanged since `69d3788a68e9d6c64b43e78284380a31182651d5`)
- candle DeBERTa-v2: [`candle-transformers/src/models/debertav2.rs`](https://github.com/huggingface/candle/blob/5ba5d5b468b5b1df40e82dd3d556987bedeea041/candle-transformers/src/models/debertav2.rs) and [`candle-examples/examples/debertav2/README.md`](https://github.com/huggingface/candle/blob/5ba5d5b468b5b1df40e82dd3d556987bedeea041/candle-examples/examples/debertav2/README.md) at `5ba5d5b`

**Metadata APIs** (queried 2026-09-30):

- GitHub: `api.github.com/repos/protectai/llm-guard`, plus its `/commits`, `/releases` and `/contributors`
- PyPI: `pypi.org/pypi/llm-guard/json`, `pypi.org/integrity/llm-guard/0.3.16/…/provenance`
- HF: `huggingface.co/api/models/protectai/deberta-v3-base-prompt-injection-v2` (plus `/commits/main` and `/tree/<rev>`)

Public context, which is not evidence for any code claim above:

- Palo Alto Networks, ["Palo Alto Networks Completes Acquisition of Protect AI"](https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-completes-acquisition-of-protect-ai), 2025-07-22; the [investor release](https://investors.paloaltonetworks.com/news-releases/news-release-details/palo-alto-networks-completes-acquisition-protect-ai)
- Palo Alto Networks, ["Palo Alto Networks Announces Intent to Acquire Protect AI…"](https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-announces-intent-to-acquire-protect-ai--a-game-changing-security-for-ai-company), 2025-04-28
- Hackett, Birch, Trawicki et al., "Bypassing Prompt Injection and Jailbreak Detection in LLM Guardrails", [arXiv:2504.11168](https://arxiv.org/html/2504.11168v1)
- Li et al., "InjecGuard: Benchmarking and Mitigating Over-defense in Prompt Injection Guardrail Models", [arXiv:2410.22770](https://arxiv.org/html/2410.22770v1)
- [PIDS-Bench](https://ieeexplore.ieee.org/iel8/6287639/11323511/11670335.pdf) (IEEE Access, 2026; search snippet only, not read in full)
- StationX, ["LLM Guard Review: A Dead Tool That Still Works"](https://app.stationx.net/articles/llm-guard) (2026-08-04; archive-date corroboration only)
