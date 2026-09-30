# Meta Prompt Guard 1 and Llama Prompt Guard 2 — Assessment Against Maknae

| | |
|---|---|
| **Status** | Assessment record. It informs the OWASP LLM coverage work. It creates no roadmap commitment and supersedes no ADR. |
| **Date** | 2026-09-30 |
| **Subject** | Meta's Prompt Guard classifiers, pinned by Hugging Face (HF) revision: [`meta-llama/Prompt-Guard-86M`](https://huggingface.co/meta-llama/Prompt-Guard-86M/tree/1209add6ca7d9c1d815171b8e5571587fe3e7b03) at `1209add`, [`meta-llama/Llama-Prompt-Guard-2-86M`](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M/tree/a8ded8e697ce7c355e395a0df51f94adb4a2fd27) at `a8ded8e`, and [`meta-llama/Llama-Prompt-Guard-2-22M`](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M/tree/11614a155199674a0a95e6602d6ab0417b790ed0) at `11614a1`; with the wrapper code in [`meta-llama/PurpleLlama`](https://github.com/meta-llama/PurpleLlama/tree/172c1074069eb88ec834124272c1b1c4f8893445) at commit `172c107`. Small DeBERTa encoder classifiers for prompt-injection and jailbreak text; weights under the Llama 3.1 (PG1) and Llama 4 (PG2) Community Licenses, wrapper code MIT. |
| **Method** | Model cards, license files, configs and tokenizer files were mirrored outside this tree and **read only**: nothing was built, installed or executed, and no weight files were downloaded. The official configs are gated, so they were read from ungated third-party mirrors whose file sizes and weight/tokenizer SHA-256 values match the official ones (§1). Evidence labels: **[file]** read from a pinned file; **[vendor]** Meta's own claim; **[3p]** a third party's claim or measurement (context, not independent verification unless stated); **[inferred]** reasoning, not tested. No latency or accuracy figure here was measured for this assessment. Public web material is context only and is marked as such. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |

This assessment is one of a set of four guard-model assessments (Prompt Guard, [Llama Guard](2026-09-30-llama-guard-assessment.md), [NeMo Guardrails](2026-09-30-nemo-guardrails-assessment.md), [LLM Guard](2026-09-30-llm-guard-assessment.md)) whose synthesis is [`2026-09-30-owasp-llm-top10-coverage.md`](2026-09-30-owasp-llm-top10-coverage.md).

**Citation shorthand.** "PG1 card" is `README.md` of `meta-llama/Prompt-Guard-86M` at HF revision `1209add`. "PG2 card" is `README.md` of `meta-llama/Llama-Prompt-Guard-2-86M` at HF revision `a8ded8e` (the 22M card is identical). "PurpleLlama" paths are at commit `172c107`. "LlamaFirewall" paths are under `PurpleLlama/LlamaFirewall/src/llamafirewall/scanners/` at the same commit. "Cookbook" is [`meta-llama/llama-cookbook`](https://github.com/meta-llama/llama-cookbook/blob/2f22a9eb030f92d0e99227e57e9a1123af1f9532/getting-started/responsible_ai/prompt_guard/inference.py) at `2f22a9e`, file `getting-started/responsible_ai/prompt_guard/inference.py`.

## 0. Disposition (read first)

**The proposed use.** Maknae is evaluating a content and prompt-injection filter that inspects prompt text, tool results (file content the loop read, which returns to the trust plane in the next `session.prompt` turn) and model replies, and gives the kernel a recommendation: a score, a label or a verdict. The filter would be a Policy Information Point (PIP), never a Policy Decision Point (PDP): `maknaed` stays the sole PDP (ADR-0005), and the content informs but never authorizes (AGENTS.md core principle 2). The candidate placement is beside the Egress Daemon (`maknae-egress`), which already receives prompt content from `maknaed` today, but only after the kernel has decided and recorded the turn (ADR-0023 decision 3); §9 states what that order costs a filter. The maintainer does not want latency added on top of the policy check.

**Verdict: adapt, cautiously. Learn from Prompt Guard and keep the model optional; do not adopt it as a default or bundled component.**

- PG2 is the most practical off-the-shelf small detector to run in pure Rust today (§10).
- The model is weak where Maknae needs it: it detects only explicit instruction-override phrasing, a published adaptive attack reaches 75–99% evasion when the detector's score is fed back to the attacker (a precondition Maknae can deny by never exposing the score), and its 512-token window makes whole-file scanning cost seconds on CPU (§4, §6).
- A verdict can only inform the kernel if it arrives before the `session.prompt` decision, which a scanner beside the Egress Daemon cannot do without a new channel or an extra round trip (§9).
- The license is a blocker-level question for the DoD target: the Acceptable Use Policy (AUP), on its face, prohibits military, warfare and ITAR uses (§2).

The full verdict is §11.

## 1. Identity and provenance

**Owner.** Meta Platforms, Inc. / Meta Platforms Ireland Ltd (the licensor, per the license preamble). The models are published under the `meta-llama` org on Hugging Face and in the `meta-llama/PurpleLlama` GitHub repository. The contact is `llamafirewall@meta.com` (`PurpleLlama/LlamaFirewall/pyproject.toml:10`). No individual maintainers are named for the models. The LlamaFirewall paper authors (Chennabasappa, Nikolaidis, Song, Molnar et al., arXiv 2505.03574) are the de facto owners.

**Releases.**

| Model | HF repo created | HF last modified | HF revision pinned |
|---|---|---|---|
| Prompt Guard 1, 86M (PG1) | 2024-07-21 | 2025-11-12 | `1209add6ca7d9c1d815171b8e5571587fe3e7b03` |
| Llama Prompt Guard 2, 86M (PG2-86M) | 2025-04-28 | 2025-04-29 | `a8ded8e697ce7c355e395a0df51f94adb4a2fd27` |
| Llama Prompt Guard 2, 22M (PG2-22M) | 2025-04-28 | 2025-04-29 | `11614a155199674a0a95e6602d6ab0417b790ed0` |

- PG1 was released with Llama 3.1 in July 2024. PG2 was released 2025-04-29 alongside LlamaFirewall and Llama Guard 4 (PurpleLlama commit `cd9fe65792`).
- The PurpleLlama README marks PG1 as superseded (`PurpleLlama/Prompt-Guard/README.md:2`).
- **Cadence:** one model generation in about 14 months, and no PG2 weight revision since release. The HF commit history is gated, so whether the PG1 weights were changed after the July 2024 bypass report could not be seen. The weight SHA-256 matches the `Niansuh/Prompt-Guard-86M` mirror, which is a copy of the weights as first published; that suggests they were not changed [inferred].

**Activity.**

- `meta-llama/PurpleLlama` is not archived. It has 90 open issues and PRs (GitHub's `open_issues_count`, which counts both) and 4.4k stars, and the last push was 2026-09-29 (GitHub API).
- The PG2 model-card directory was last touched 2025-05-08 (`7a47e8460a`).
- The LlamaFirewall PromptGuard scanner code was last touched 2026-03-26 (`9a3d175ade`); the previous change was 2026-01-16 (`fix_mistral_regex=True`, #163).
- The model is maintained on paper, but in practice the weights are frozen.

**Signing and attestation.**

- There is **no cryptographic signing** (no Sigstore, no GPG).
- PG1 ships an MD5 list (`Prompt-Guard-20240715180000.md5`), and PG2 ships `checklist.chk` (both are gated).
- Useful for the air gap: the **public, ungated** HF API (`/api/models/<id>?blobs=true`) exposes the git-LFS SHA-256 of each weight file even without accepting the license. That gives an out-of-band integrity pin:

| File | SHA-256 |
|---|---|
| PG1 `model.safetensors` | `1771712866662626517f2d85057de2d7078389a4c1f0bc93e461bdc4fdae4bd5` |
| PG2-86M `model.safetensors` | `e72017dbbe89c1232dcbc4a74ce0c389db5b468c42afd05850347b2a8c5f6b09` |
| PG2-22M `model.safetensors` | `5120e30bcd536ce285345d9ec104bea6bd6e8f94365b99a340c764f417ea5fa1` |
| PG2-86M `tokenizer.json` | `3e7e96867c2acdd575f0862c74822e05d1d15b93d9d9a4a2144b1ce83ae3339f` |
| PG1 `tokenizer.json` | `7dbb7b63c76007984d0e58a90ee901ceb5b16c8e78252d36ddcde748b3474a1a` |

The PG2-22M `tokenizer.json` is not LFS-tracked, so no hash is exposed; only its size (8,657,051 bytes) is public.

**Ownership changes.** None. Meta has owned the models throughout. The PG1 bypass researcher's firm (Robust Intelligence) was acquired by Cisco, which is not relevant to the model.

**Pinned sources.**

- PurpleLlama `172c1074069eb88ec834124272c1b1c4f8893445` (2026-09-29).
- llama-models `0e0b8c519242d5833d8c11bffc1232b77ad7f301`.
- llama-cookbook `2f22a9eb030f92d0e99227e57e9a1123af1f9532`.
- HF revisions as in the table above.
- The official `config.json` and `tokenizer_config.json` are gated (HTTP 401 was returned when fetched). They were read from ungated third-party mirrors whose file sizes match the official listing byte for byte, and whose weight and tokenizer LFS SHA-256 values match the official ones:
  - `project-free-llama/Llama-Prompt-Guard-2-86M@43882965632dcb7b20299530f6436ac759d07fd9`
  - `project-free-llama/Llama-Prompt-Guard-2-22M@98f241c60b7999ba67eb8603f548461b577b3bc9`
  - `Niansuh/Prompt-Guard-86M@a66611375a83f28f75f1c4b685e1e09e353c69ee`
  - Treat config contents as **very likely identical, not proven**: small JSON files are not LFS-hashed.

## 2. License

**Weights and model materials.**

- **PG1: "Llama 3.1 Community License Agreement"**, version release date July 23, 2024 (PG1 `LICENSE:1-2` on HF; card front-matter `license: llama3.1`, PG1 card `README.md:11`).
  - Inconsistency: the PurpleLlama README table lists Prompt Guard under the **Llama 3.2** Community License (`PurpleLlama/README.md:42`), and the repository-root `LICENSE` is Llama 3.2.
  - The license file distributed with the weights on HF is 3.1. The substance is the same.
- **PG2 (both sizes): "Llama 4 Community License Agreement"**, effective April 5, 2025 (`PurpleLlama/Llama-Prompt-Guard-2/86M/LICENSE:1-2`; HF `license: other`, `license_name: llama4`).
  - The AUP is the Llama 4 AUP (`PurpleLlama/Llama-Prompt-Guard-2/86M/USE_POLICY.md`).

**Code.**

- LlamaFirewall (the scanner and PromptGuard wrapper) is **MIT** (LlamaFirewall `promptguard_utils.py:1-4`).
- The HF `transformers` usage is Apache-2.0.
- There is no separate Prompt Guard runtime code: the model is a stock `DebertaV2ForSequenceClassification`.

**What the Llama 4 license demands** (clause numbers refer to `PurpleLlama/Llama-Prompt-Guard-2/86M/LICENSE`; the Llama 3.1 terms are the same in substance):

- **§1.b.i.** Anyone who distributes the materials, or a product that contains them, must:
  - (A) provide a copy of the Agreement;
  - (B) "prominently display 'Built with Llama' on a related website, user interface, blogpost, about page, or product documentation."
  - A model created, trained, fine-tuned or otherwise improved using the materials or their outputs, and then distributed, must have a name beginning with "Llama". A fine-tuned Maknae guard would have to be called "Llama-…".
- **§1.b.iii.** A "Notice" text file with the exact line "Llama 4 is licensed under the Llama 4 Community License, Copyright © Meta Platforms, Inc. All Rights Reserved."
- **§1.b.iv.** Compliance with the AUP, which is **incorporated by reference from a URL** (`llama.com/llama4/use-policy`). The AUP itself says "the most recent copy … can be found at" that URL. **Meta can change the terms unilaterally.** That makes it a moving compliance target.
- **§2.** A 700M monthly-active-user (MAU) cap. Licensees above it, measured on the release date, need a separate grant. Irrelevant to Maknae and to DoD in practice.
- **§5.a.** No trademark license, except "Llama" for the naming and "Built with" obligations. Meta's brand guidelines apply.
- **§5.c.** Termination if the licensee sues Meta for IP infringement over the Llama Materials, plus **an indemnity to Meta** for third-party claims arising from the licensee's use or distribution.
- **§6.** Meta may terminate for any breach; the licensee must then delete the materials.
- **§7.** California law, exclusive California venue. That is a known sticking point for US government contracting, where federal law and the Contract Disputes Act and Anti-Deficiency Act issues around open-ended indemnities apply [inferred; needs counsel].

**The AUP clause that matters for DoD.** AUP §2.1 (`PurpleLlama/Llama-Prompt-Guard-2/86M/USE_POLICY.md:41`) prohibits use "related to … **Military, warfare, nuclear industries or applications, espionage, use for materials or activities that are subject to the International Traffic Arms Regulations (ITAR)** …".

- On 2024-11-04 Meta announced it is "making Llama available to U.S. government agencies and contractors working on national security applications" (about.fb.com, Nick Clegg) [3p/vendor statement].
- That announcement is **not reflected in the AUP text that ships with PG2** (April 2025).
- No published license amendment was found. The mechanism appears to be separate arrangements with Meta and its partners.
- **For a DoD deployment, the license text on its face prohibits military use.** A press release is not a license. Written confirmation from Meta or counsel is needed before any DoD use [inferred recommendation].
- A home-lab deployment is unaffected.

**Redistribution inside an air-gapped package.** This is permitted (§1.a grants the right to "distribute, copy") if Maknae ships:

- the Agreement;
- the Notice file;
- a "Built with Llama" statement in its documentation;

and binds its users to the AUP. §1.b.ii exempts recipients of "an integrated end user product" from §2 (the MAU clause) only, not from the AUP.

**The cleaner design** [inferred]: **Maknae does not redistribute the weights.** The operator obtains them under their own license acceptance. Maknae ships only the loader and hash pins (§1) and verifies the file at load time. Maknae is then not a distributor of Llama Materials and carries no "Built with Llama" obligation. The operator's own use still carries the AUP.

**Gated access.**

- All three repositories are `gated: manual`.
- The gate form requires full legal name, date of birth, country, affiliation and job title, and records IP geolocation (`geo: ip_location`). The data is shared under the Meta Privacy Policy (PG2 card `README.md:69-91`).
- Approval is manual and can be refused.
- Even `config.json` is gated (HTTP 401 observed).
- Ungated third-party mirrors exist (several are listed in §1). Using them sidesteps the gate but not the license, which binds "by using or distributing" (PG2 card `README.md:36`). Mirror provenance is only as good as the SHA-256 comparison.

## 3. What it is and how it works

**Architecture.**

- A single fine-tuned encoder classifier: `DebertaV2ForSequenceClassification`, `model_type: deberta-v2`.
- No LLM, no rules, no orchestration.
- LlamaFirewall is a separate Python framework that wraps it.

**Config details** [file, via the mirrors in §1]:

| | PG1 86M | PG2 86M | PG2 22M |
|---|---|---|---|
| Base | mDeBERTa-v3-base | mDeBERTa-v3-base | DeBERTa-v3-xsmall (English-only pretraining) |
| hidden / layers / heads | 768 / 12 / 12 | 768 / 12 / 12 | 384 / 12 / 6 |
| intermediate | 3072 | 3072 | 1536 |
| vocab | 251,000 | 251,000 | 128,100 |
| Total params (F32) | 278,811,651 | 278,810,882 | 70,830,722 |
| `model.safetensors` bytes | 1,115,271,284 | 1,115,268,200 | 283,347,432 |
| Relative attention | yes, `position_buckets: 256`, `pos_att_type: [p2c, c2p]`, `share_att_key: true`, `norm_rel_ebd: layer_norm` | same | same |
| `max_position_embeddings` | 512 | 512 | 512 |
| Labels (`id2label`) | `0 BENIGN, 1 INJECTION, 2 JAILBREAK` | **absent from config** | **absent from config** |

- The "86M" name counts backbone parameters only. About 192M more are word embeddings (PG1 card `README.md:425-426`). That is why the 86M file is 1.1 GB in FP32.
- The PG2 model card has an error: it links "mDeBERTa-base" to `microsoft/deberta-base` (`PurpleLlama/Llama-Prompt-Guard-2/86M/MODEL_CARD.md`; PG2 card `README.md:158`).

**Output.**

- PG1: a three-way softmax.
  - The "jailbreak score" is P[2].
  - The "indirect injection score" is P[1] + P[2] (PG1 card `README.md:354-385`).
- PG2: binary, "benign" or "malicious" (PG2 card `README.md:113`).
  - The config carries no `id2label`, so `transformers` would print `LABEL_1` rather than the `MALICIOUS` the card shows [inferred from config].
  - LlamaFirewall takes `probabilities[0, -1]` (`promptguard_utils.py:128-129`), and third-party ONNX exports add `BENIGN/MALICIOUS` themselves.
- Scores are uncalibrated softmax values with optional temperature. LlamaFirewall blocks at ≥ 0.9 (`prompt_guard_scanner.py:24`).

**Context window and truncation.**

- **512 tokens.** Meta says to "split longer inputs into segments and scan them in parallel" (PG2 card `README.md:119`).
- `tokenizer.json` sets truncation to `max_length 512, Right`, while `tokenizer_config.json` has `model_max_length: 1e30`. Behaviour therefore depends on which path the caller uses.
- **LlamaFirewall does not chunk.** It calls `tokenizer(..., truncation=True, max_length=512)` (`promptguard_utils.py:112-114`), so **everything after the first ~510 tokens is silently not scanned**. That is a fail-open on long tool outputs [file].
- The Cookbook `inference.py:145-187` does chunk:
  - non-overlapping 512-token slices;
  - decoded back to text, then re-tokenized;
  - scored as the maximum over chunks.
- Non-overlapping chunks can split an injection across a boundary [inferred]. A Maknae implementation should use overlapping windows (for example a 512-token window with a 256-token stride) and take the maximum.

**Tokenizer** [file, `tokenizer.json`]:

- SentencePiece **Unigram**, with the pipeline:
  - normalizer: `Strip` → `Precompiled` (the SentencePiece nmt-NFKC charsmap) → `Replace / {2,}/ → " "`;
  - pre-tokenizer: `Metaspace("▁", prepend always)`;
  - a `TemplateProcessing` post-processor: `[CLS] A [SEP]`.
- **PG2 adds** `Replace " " → ""` then `NFKC`. In PG2-86M the pair appears **twice**; in PG2-22M it appears once.
- In other words, **PG2 deletes every ASCII space before tokenizing.** This is the "adversarial-resistant tokenization" the card describes (PG2 card `README.md:112` and `:157`). The vocabulary is unchanged: 250,101 identical entries between PG1 and PG2-86M.
- PG2-86M also has 100 `<extra_id_N>` added tokens, which explains its 19.7 KB `tokenizer_config.json`.
- LlamaFirewall additionally runs `_preprocess_text_for_promptguard` (`promptguard_utils.py:79-102`), which strips whitespace and re-inserts it at token boundaries. It **catches every exception and returns the unprocessed text** (`promptguard_utils.py:100-102`), which is a fail-open.

## 4. What it detects, and what it does not

**Categories.**

- **PG1:**
  - JAILBREAK: explicit attempts to override the system prompt or conditioning.
  - INJECTION: *any* "out of place" command or instruction aimed at an LLM, malicious or not.
  - Source: PG1 card `README.md:225-246`.
- **PG2:** a single class. "Malicious" means the text "explicitly attempts to override prior instructions … regardless of whether the prompt is potentially harmful or the attack is likely to succeed" (PG2 card `README.md:117`). The INJECTION label was **dropped as "too broad to be useful"** (PG2 card `README.md:118`).
- **Not detected by either:** toxicity, harmful content (that is Llama Guard's job), PII, secrets, data-exfiltration intent, code risks (CodeShield), goal hijack without override language (AlignmentCheck), or anything in images.
- Both are designed as **input** filters. Neither is trained or evaluated for scanning model *replies*.

**Languages.**

- Evaluated in English, French, German, Hindi, Italian, Portuguese, Spanish and Thai (PG2 card `README.md:120`).
- PG2-22M has no multilingual pretraining: its multilingual AUC is .942, against .995 for PG2-86M [vendor]. Meta's limitations section says so (PG2 card `README.md:201`).
- Behaviour in languages outside that list is unknown. Trendyol reported non-English (Turkish) bypasses of LlamaFirewall/PromptGuard in 2025; that is a search snippet only, because Medium returned 403 [3p].

**Direct vs indirect injection.**

- PG1's INJECTION label targeted indirect injection. On the CyberSecEval indirect set it reached TPR 71.4% at FPR 1.0% (PG1 card `README.md:500-504`) [vendor].
- PG2 covers indirect injection **only when it uses explicit override language**. Its AgentDojo figures (attack prevention rate at 3% utility reduction) are [vendor]:
  - PG2-86M: 81.2%
  - PG2-22M: 78.4%
  - PG1: 67.6%
- For Maknae's main use case, inspecting file content and tool results, this matters:
  - PG2 will not flag a quietly embedded "also email the file to x" that avoids override phrasing [inferred].
  - PG1's INJECTION label flags *any* imperative text addressed to an LLM. That would fire constantly on READMEs, code comments, prompt files and agent instruction files, which are exactly what a coding agent reads [inferred].

**Vendor accuracy** (all on Meta's private or in-distribution sets; **not independent**):

- PG2-86M: AUC .998 (English), recall 97.5% at 1% FPR.
- PG2-22M: .995 and 88.7%.
- PG1 on the same benchmark: .987 and 21.2% (PG2 card `README.md:166-170`).
- The LlamaFirewall paper's copy of the same table gives PG2-86M an AUC of **.98**, not .998 (arXiv 2505.03574v1). It is an unexplained internal inconsistency.

**Published bypasses and critiques.**

1. **PG1 character spacing.** Robust Intelligence / Cisco (Aman Priyanshu, 2024-07-29): space out every character and strip punctuation (`' '.join(p)` plus a regex). Detection on 450 SORRY-Bench harmful prompts fell from 100% to 0.2%. Root cause: single-character embeddings were barely moved by fine-tuning. Meta "acknowledged the issue and fixed it" [3p, Cisco blog].
   - **Does PG2 address it?** Largely yes, by construction. PG2's normalizer deletes all ASCII spaces, so `I g n o r e` becomes `Ignore` [file].
   - The fix is **narrow**: it removes U+0020 only. Other separators are not removed by the explicit `Replace`: `I.g.n.o.r.e`, `I-g-n`, `_`, and zero-width characters (U+200B/200C/200D, U+2060).
   - Whether the Precompiled nmt-NFKC charsmap drops zero-width characters or maps tabs, newlines or NBSP to spaces is **untested** [inferred; needs a tokenizer parity test].
   - PG2-22M applies the space-delete/NFKC pair only once. Any space that NFKC *produces* (for example from U+00A0 or U+2000–U+200A, if the charsmap does not already fold them) would survive into the Metaspace pre-tokenizer on 22M but not on 86M [inferred; test it].
   - Removing spaces also discards word boundaries. The model was trained that way, so this costs nothing on the vendor benchmarks, but it is a design trade.
2. **Hackett et al., "Bypassing Prompt Injection and Jailbreak Detection in LLM Guardrails"**, arXiv 2504.11168 (April 2025), against **PG1** [3p]:
   - Character-injection attacks: 70.44% attack success rate (ASR) on prompt injection, 73.08% on jailbreaks. The paper's results text attributes these two figures to "Meta Prompt Shield", a naming slip for Prompt Guard; its abstract names "Meta's Prompt Guard".
   - Word-level adversarial-ML (AML) attacks: 2.76% (prompt injection) and 12.66% (jailbreaks). PG1 was the most robust of six systems against those.
   - Techniques included homoglyphs, diacritics, zero-width characters and Unicode tag smuggling.
3. **Nasr, Carlini et al., "The Attacker Moves Second"**, arXiv 2510.09023 (October 2025) [3p, multi-lab academic/industry: authors from Google DeepMind, OpenAI, Anthropic and ETH Zürich; Google's Model Armor was among the targets]:
   - A search-based adaptive attack, **with the detector's confidence score and detection flag fed back to the attacker**, reached **> 90% ASR against PromptGuard** (as well as ProtectAI and Model Armor) with Gemini-2.5 Pro as the base model. Per base model, the PromptGuard figures are 94% (Gemini-2.5 Pro), 75% (GPT-5 Mini), 99% (Llama-3.3 70B) and 95% (MetaSecAlign 70B).
   - The headline depends on that feedback. Maknae's own recommendation below (never return the score to the agent) removes that precondition, though not the attack class: the paper's human red-team challenge also produced successful injections against PromptGuard.
   - In their human red-team challenge with **PG2-86M** as the AgentDojo defense (Slack suite), ASR with PromptGuard was sometimes *higher* than the undefended baseline. For gemini-2.5-flash it went from 9.3% to 23.8% (Table 3).
   - Meta's PG2 card concedes that "adversaries may develop sophisticated attacks specifically to bypass detection" (PG2 card `README.md:199`); the PG1 card says Prompt Guard "is not immune to adaptive attacks" (PG1 card `README.md:438`).
   - Implication for Maknae: **never expose the score to the agent** (it is a gradient-free oracle for the attacker), and treat the verdict as a weak signal [inferred].
4. **Trendyol** (Medium, 2025-07-11) [3p, snippet only]: a LlamaFirewall/PromptGuard bypass via non-English prompts and invisible Unicode, reported to Meta 2025-05-07.
5. **Quantization fragility** [3p]: gravitee-io's ONNX export reports PG2-86M int8 AUC falling from .95 to .745 on `jackhhao/jailbreak-classification`, while 22M int8 was nearly lossless. Do not quantize 86M without re-validation.

## 5. Language, runtime and dependencies

**As shipped**, Python only:

- `transformers` (≥ 4.51.3 for LlamaFirewall), `torch` (≥ 2.4.1) and `huggingface_hub` (`PurpleLlama/LlamaFirewall/pyproject.toml:14-22`).
- LlamaFirewall also pulls `codeshield`, `openai`, `pydantic`, `typer` and `numpy`.
- torch plus transformers is a multi-GB C++/CUDA stack with hundreds of transitive packages [inferred order of magnitude].

**GPU.** Not required. Meta: "small enough to be deployed or fine-tuned without any GPUs" (PG1 card `README.md:427-428`).

**Serving mode.**

- A library: an in-process model inside the caller's Python.
- There is no Meta-provided server or API.
- Llama Stack exposes it as a "shield".
- Third parties publish ONNX exports, including gravitee-io (with `model.quant.onnx`), sinatras and prompt-security.

## 6. Performance and footprint

**Disk:** 1.115 GB (86M, FP32) and 283 MB (22M, FP32) [file, HF API sizes]. Third-party int8 ONNX files are 281 MB and 72.5 MB (gravitee-io) [3p].

**Memory:** roughly weights plus activations. That is about 1.2–1.5 GB resident for 86M and about 350–450 MB for 22M in FP32 [inferred]. The 86M embedding table alone is 251,000 × 768 × 4 B ≈ 771 MB.

**Latency:**

| Source | Model | Setting | Latency |
|---|---|---|---|
| [vendor] PG2 card `README.md:166` | PG1 / PG2-86M | A100 GPU, 512 tokens | 92.4 ms |
| [vendor] | PG2-22M | A100, 512 tokens | 19.3 ms ("75% less compute") |
| [3p] tract PR #2532 (simon0191, merged 2026-07-29) | **PG2-86M** | tract, pure Rust, seq 128, 1 thread, optimized graph (CPU not stated) | ~102 ms |
| [3p] tract PR #2531 (merged 2026-07-29) | "DeBERTa-v3-base classifier, 86M" | tract, Apple M4 Pro, 1 thread | 132 ms (seq 128); 344 ms (seq 256). About 1.5–1.75× faster on 8 threads (Graviton3) |
| [3p] candle `debertav2` example README (`candle-examples/examples/debertav2/README.md:113-132` at `5ba5d5b`) | `protectai/deberta-v3-base-prompt-injection-v2` (DeBERTa-v3-base, the same architecture class as PG2-86M) | one short sentence; `--cpu` (CPU model not stated), and CUDA | 123.78 ms CPU; 100.01 ms CUDA |
| [3p, competitor marketing] StackOne | "Meta PG v2" | T4 GPU | 43 ms |

**Inferred for Maknae:**

- **PG2-86M on CPU, single-threaded, costs about 100–130 ms per 128-token window and 344 ms per 256-token window (the tract figures above); a full 512-token window extrapolates to roughly 0.7–1 s.** Attention and relative-position cost grow superlinearly with length.
- PG2-22M should be roughly 3–5× cheaper.
- A 20 KB file read, about 5k tokens, is about 10 non-overlapping or 20 overlapping 512-token windows: roughly **7–20 s single-threaded** on 86M, and still several seconds on 8 threads (tract measured only a 1.5–1.75× gain from 8 threads).
- This conflicts directly with the maintainer's requirement that no latency be added on top of the policy check. Because the verdict must reach the kernel before the decision (§9), the scan is on the critical path; it can be made cheaper, not hidden. The levers are:
  - limiting it to 22M;
  - or bounding it (the first N windows plus sampling), which is itself a bypass surface.

**Throughput:** batching helps on GPU. On CPU it is compute-bound; no measured numbers are available.

## 7. Strengths

- A tiny, well-understood, **standard architecture**: stock DeBERTa-v2, no custom code, no `auto_map` or `trust_remote_code`, and **safetensors only** (no pickle files in any of the three repositories) [file].
- The strongest *vendor-reported* high-precision numbers among small open detectors: PG2-86M recall 97.5% at 1% FPR. The energy-based out-of-distribution (OOD) loss specifically targets false positives on benign out-of-distribution text [vendor].
- Two sizes give a latency/accuracy knob. 86M is genuinely multilingual across 8 evaluated languages.
- PG2 fixed a concrete, published tokenizer bypass with a declarative, inspectable normalizer change that a Rust tokenizer can reproduce exactly.
- Pure-Rust inference is **realistic today**: candle ships a DeBERTa-v2 sequence-classification model, and tract was patched in July 2026 specifically so that PG2-86M runs and runs fast (§10).
- Public LFS hashes let an air-gapped operator verify weights without trusting a mirror.

## 8. Weaknesses

**False positives and negatives.**

- **Narrow scope (PG2):** it only catches explicit override attempts. That means false negatives on subtle indirect injection, which is Maknae's main threat for file and tool content.
- **PG1's INJECTION label** is the broad alternative, and would be false-positive-heavy on developer content [inferred].
- **Adaptive attacks** reach 75–99% ASR when the score is fed back to the attacker (Nasr, Carlini et al.), and the paper's human red-teamers also succeeded.
- Character-level evasions other than ASCII spaces are not demonstrably handled.
- The 512-token limit needs careful chunking. Meta's own framework truncates silently.
- Not trained for output (reply) scanning.

**Maintenance risk.**

- The weights have been frozen since April 2025 and there is no stated update cadence.
- Meta's safeguards line is product-driven: PG1 was superseded after 9 months, and the INJECTION label was abandoned.
- Configs are missing `id2label`.
- The model card has errors: the wrong base-model link, and the .998 vs .98 AUC mismatch.
- **The license and AUP can change by URL.**

**Supply-chain risk.**

- Weights: safetensors, which is good.
- Not signed (MD5 only).
- A gated repository pushes users toward unverified mirrors.
- The LlamaFirewall loader **downloads from HF at first use and calls an interactive `huggingface_hub.login()`** when no token exists (`promptguard_utils.py:53-69`). That is a runtime network dependency and a credential prompt; it must be disabled (`HF_HUB_OFFLINE=1`, `HF_HUB_DISABLE_TELEMETRY=1`) or the loader bypassed entirely.
- The preprocessing step fails open on exceptions (`promptguard_utils.py:100-102`).
- **Legal:** the AUP's military/ITAR prohibition, unilateral AUP changes, the indemnity, California venue, and "Built with Llama" branding. These are material for a DoD target.

## 9. Integration into Maknae as-is

**How it would run.** A Python sidecar under its own UNIX account. It would load `transformers`, `torch` and the local weights with HF offline mode forced, and expose a Unix-socket RPC that returns `{score, label, model_sha256, window_count}`, which `maknaed` takes as a PIP input and decides on.

**Where the verdict must arrive: ADR-0023's write-ahead order.** ADR-0023 decision 3 fixes the order of a turn: the kernel decides `session.prompt`, appends the write-ahead record, and only then hands the turn to `maknae-egress`. A PIP that sits beside the Egress Daemon and scans what it receives therefore sees the content only after the decision, and its verdict informs nothing. For a verdict on input content to count, it must reach `maknaed` **before** the `session.prompt` decision. With the scanner beside the Egress Daemon, that means a new channel from `maknaed` to the scanner, or an extra round trip before the decision. That cost is on the critical path of every turn, on top of the scan time itself. Running the scan asynchronously, or pipelined with the model call, is not a latency fix for inputs: it sends the content before the verdict exists, which is the objection the [NeMo Guardrails assessment](2026-09-30-nemo-guardrails-assessment.md) raises against IORails speculative generation. Replies are harder still. In the shipped design the reply-leg release verdict is the `session.prompt` verdict, computed before the model output exists (ADR-0023 decision 3, "The response leg is a release"), so no content-dependent check on a reply can bind until that release is un-collapsed into a decided `session.update`, for which #229 landing is a named trigger.

**TCB.** The sidecar must be **outside** the TCB. It is a PIP, not a PDP, so its compromise can only corrupt a recommendation. It must not run inside `maknae-egress`: that process holds the provider key, and ADR-0002 requires the egress process, like the kernel, to be 100% Rust. Putting torch (C++) into it would put C++ into a process holding a secret. (Maknae's egress process already links native code, per `cargo tree -p maknae-egress`: the AWS-LC crypto module (`aws-lc-fips-sys`, with the non-FIPS `aws-lc-sys` also in the tree), and, on macOS, Security.framework and CoreFoundation through FFI (`rustls-platform-verifier` → `security-framework-sys` / `core-foundation-sys`, reached through `reqwest`). A model runtime is a different order of native code from either.) The sidecar needs:

- a separate account;
- no network (sandbox it; `HF_HUB_OFFLINE`);
- a read-only weight path.

**FIPS.** Not directly implicated: there is no cryptography in inference. But the Python stack drags in OpenSSL, via urllib3 and requests from `huggingface_hub`, outside the AWS-LC posture [inferred].

**Air gap.** Workable: vendor wheels for torch and transformers, plus weights verified by the published SHA-256 values. The operator must obtain the weights through the gate (or Maknae redistributes them with the Agreement, the Notice and "Built with Llama").

**macOS on Apple Silicon.** torch and transformers support it (CPU or MPS) [inferred]. macOS is a production target for Maknae, so this is a shipping-platform requirement, not a convenience.

**Latency.** Python and torch on CPU is comparable to or worse than the tract numbers in §6, plus IPC and serialization, plus the pre-decision round trip above. A full 512-token window costs roughly 0.7–1 s single-threaded on 86M [inferred, extrapolated from tract].

**Complexity: M–L.** The M part is the mechanics: the sidecar, the RPC, chunking and aggregation, and offline packaging of a multi-GB Python/torch runtime for two operating systems and two architectures. What makes it L is the licensing review and a Python runtime in a project that is otherwise Rust.

## 10. Taking the interesting parts and reimplementing them natively in Rust

**Portable parts.**

- **Weights:** portable if the license is acceptable (§2). Loading safetensors directly means no conversion step for candle.
- **Tokenizer:** fully declarative (`tokenizer.json`): Unigram + Precompiled charsmap + one trivial regex (` {2,}`) + string replace + NFKC + Metaspace + a `[CLS]/[SEP]` template. Everything is reproducible.
- **Chunking policy:** the maximum over windows. Improve it with overlap.
- **Label semantics and thresholds:** block at 0.9 in LlamaFirewall; PG1's P1+P2 "injection" composite.
- **The whitespace-deletion normalization idea:** worth applying in front of *any* detector.
- There are **no rules, regexes or prompts** to port beyond these. The intelligence is entirely in the weights.

**Rust stack.**

- **Tokenizer: the HF `tokenizers` crate** (Apache-2.0). Unigram, Precompiled (via the pure-Rust `spm_precompiled`), NFKC, Replace, Metaspace and TemplateProcessing are all supported. Caveats:
  - **0.23.2** (latest stable, 2026-09-03) has the default features `["progressbar", "onig", "esaxx_fast"]`. `onig` is C (Oniguruma) and `esaxx_fast` is C++. A pure-Rust build sets `default-features = false` and enables `fancy-regex`, which is an optional dependency and therefore an implicit feature. candle at `5ba5d5b` does exactly this: `tokenizers = { version = "0.23.1", default-features = false }` in the workspace (`Cargo.toml:95`) and `features = ["fancy-regex"]` in `candle-core/Cargo.toml:40`. It is a two-line manifest setting.
  - **1.0.0-rc.2** (2026-09-21) restructured the crate: `onig` is gone from the default path, and there is a `regex = ["tk-encode/fancy-regex"]` feature. That is cleaner, but it is a release candidate (the repository was read at `bbccb0513ff9afda385ca5c85c66eddb1318cfc7`).
  - Alternative, optional: a **bespoke inference-only tokenizer** of a few hundred lines (Unigram Viterbi + the `spm_precompiled` charsmap + NFKC via `unicode-normalization` + hand-coded space rules). It would remove the regex engine and the crate's wider dependency set and is easy to audit, but it is not needed to stay pure Rust, and it takes on the parity risk the crate already carries [inferred, M].
- **Model, option (a): `candle`** (MIT/Apache-2.0; `huggingface/candle` at `5ba5d5b468b5b1df40e82dd3d556987bedeea041`, v0.11.0):
  - `candle-transformers/src/models/debertav2.rs` (1,444 lines) implements DeBERTa-v2/v3 disentangled attention (c2p/p2c, `position_buckets`, `share_att_key`, `norm_rel_ebd`) and `DebertaV2SeqClassificationModel` with its `ContextPooler` (`debertav2.rs:1269-1345`).
  - An example (`candle-examples/examples/debertav2`) already runs text classification on DeBERTa-v3 prompt-injection classifiers on CPU.
  - The CPU backend (the `gemm` crate) is pure Rust. `mkl`, `accelerate`, `cuda` and `metal` are all opt-in features, so a default build contains no C.
  - candle and gemm contain `unsafe` internally. ADR-0027 confines `unsafe` in Maknae's own workspace members to `maknae-sys`; it does not reach third-party crates, and nothing in the repository measures `unsafe` in dependencies (ADR-0002, 2026-09-28 amendment). A reviewer will note it.
  - **The most direct path; it loads the official safetensors unchanged.**
- **Model, option (b): `tract`** (MIT/Apache; pure-Rust ONNX):
  - Needs a one-time offline ONNX export in Python. The exported file is a derivative of the Llama Materials. Pin its hash.
  - DeBERTa support is **very recent**. Before PR #2533 (merged 2026-07-30), tract's `Sign` was float-only, and "every DeBERTa-family model hits it", so DeBERTa could not run at all.
  - PRs #2531 (the GatherElements fast path used by relative-position attention) and #2532 (a const-folding regression found *on PG2-86M specifically*) landed 2026-07-29.
  - Merge commits: `a1baa9abaf35935524571c3902ed231c2aa86953` (#2531) and `7ff6ecfbecf3c25299208dd684a27e1172670d62` (#2532).
  - Pin a tract release that contains all three. About 100 ms at seq 128, single thread, as measured by the PR author [3p].
  - Advantage: tract's optimized graph folds the constant relative-position tables when input shapes are frozen (for example to a fixed 512).
- **`ort` (onnxruntime)** brings C++ into the process. It is **disqualified** in-process under ADR-0002 and undesirable even out of process on shipping platforms.

**Fidelity risk.** Moderate. The places to check:

- DeBERTa's log-bucketed relative positions (`make_log_bucket_position`);
- the scaled-attention factor with c2p/p2c;
- GELU (exact vs tanh approximation);
- `layer_norm_eps = 1e-7`;
- the pooler (`ContextPooler`: token 0 → dense → GELU);
- tokenizer parity, especially the PG2 space deletion, NFKC ordering and unknown-character handling.

Mitigations:

- Generate **golden vectors once, offline**, from the reference PyTorch model: token IDs plus logits for a corpus covering several languages, attack strings, Unicode edge cases, whitespace variants and 512-boundary cases.
- Commit them as test fixtures and assert that token IDs are exactly equal and logits agree within 1e-4.
- This follows AGENTS.md core principle 5 (test the real path, not a stand-in). Do **not** quantize 86M without repeating this; see the gravitee AUC drop (§4).

**Complexity: L.**

- The model port is S–M: candle already has it, so the work is wiring plus golden tests.
- The tokenizer is S with the `tokenizers` crate (a manifest setting plus parity tests), or M if the bespoke alternative is chosen.
- What makes it L:
  - windowing and aggregation, with overlap and a bounded per-request budget;
  - process isolation (a separate PIP daemon, or a crate inside a non-key-holding process);
  - latency engineering (22M by default, threading, frozen shapes);
  - the licensing and operator-supplied-weights workflow.
- Fine-tuning on Maknae's own domain (the vendor recommends it) would be XL, and would trigger the "Llama…" naming requirement.

## 11. Verdict for Maknae

**Adapt, cautiously: learn from it and keep the model optional; do not adopt it as a default or bundled component.**

- **Architecture: a good fit.** PG2 is the most practical off-the-shelf small detector to run in **pure Rust** today:
  - stock DeBERTa-v2 in safetensors;
  - a declarative tokenizer;
  - candle's existing `DebertaV2SeqClassificationModel`;
  - tract patched in July 2026 specifically for PG2-86M.

  An isolated, non-key-holding PIP process could score content windows without C in the process, and the pattern is model-agnostic. Its verdict must reach `maknaed` before the `session.prompt` decision to count (§9).
- **The model itself is weak where Maknae needs it:**
  - PG2 detects only *explicit* instruction-override phrasing and dropped indirect-injection coverage.
  - A published adaptive attack reaches 75–99% evasion when the score is fed back to the attacker.
  - Its 512-token window makes whole-file scanning cost seconds on CPU for 86M, on the critical path before the decision, which conflicts with the latency requirement.
- **The license is a blocker-level question for the DoD target:**
  - The Llama 4 Community License's AUP, on its face, prohibits military, warfare and ITAR uses.
  - The AUP can change by URL.
  - It demands "Built with Llama" branding and "Llama"-prefixed names for derivatives, carries an indemnity, and sets California venue.
  - Meta's 2024 national-security announcement is not in the license text.

**Recommendation:**

- Build the Rust DeBERTa scoring path as a generic, weight-agnostic advisory PIP. Use PG2-22M or PG2-86M only as an **operator-supplied, hash-pinned, non-default model**, where the operator accepts Meta's license and Maknae neither redistributes it nor depends on it.
- Borrow the space-deleting/NFKC normalization and the max-over-overlapping-windows aggregation for whatever detector is chosen.
- Never let the detector's verdict gate alone, and never return its score to the agent.

## 12. Sources

**Hugging Face** (gated; READMEs and LICENSE files are publicly fetchable; metadata via `https://huggingface.co/api/models/<id>?blobs=true`):

- [`meta-llama/Prompt-Guard-86M@1209add6ca7d9c1d815171b8e5571587fe3e7b03`](https://huggingface.co/meta-llama/Prompt-Guard-86M/tree/1209add6ca7d9c1d815171b8e5571587fe3e7b03): `README.md`, `LICENSE`
- [`meta-llama/Llama-Prompt-Guard-2-86M@a8ded8e697ce7c355e395a0df51f94adb4a2fd27`](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M/tree/a8ded8e697ce7c355e395a0df51f94adb4a2fd27): `README.md`, `LICENSE`
- [`meta-llama/Llama-Prompt-Guard-2-22M@11614a155199674a0a95e6602d6ab0417b790ed0`](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M/tree/11614a155199674a0a95e6602d6ab0417b790ed0): README identical to the 86M one (a diff shows no change)

**Ungated mirrors** (configs and tokenizers; hashes checked against the official LFS values):

- [`project-free-llama/Llama-Prompt-Guard-2-86M@43882965632dcb7b20299530f6436ac759d07fd9`](https://huggingface.co/project-free-llama/Llama-Prompt-Guard-2-86M/tree/43882965632dcb7b20299530f6436ac759d07fd9)
- [`project-free-llama/Llama-Prompt-Guard-2-22M@98f241c60b7999ba67eb8603f548461b577b3bc9`](https://huggingface.co/project-free-llama/Llama-Prompt-Guard-2-22M/tree/98f241c60b7999ba67eb8603f548461b577b3bc9)
- [`Niansuh/Prompt-Guard-86M@a66611375a83f28f75f1c4b685e1e09e353c69ee`](https://huggingface.co/Niansuh/Prompt-Guard-86M/tree/a66611375a83f28f75f1c4b685e1e09e353c69ee)
- [`gravitee-io/Llama-Prompt-Guard-2-22M-onnx@da68d0f6023c7aeaf6b256eec549de295d5e8740`](https://huggingface.co/gravitee-io/Llama-Prompt-Guard-2-22M-onnx/tree/da68d0f6023c7aeaf6b256eec549de295d5e8740)
- [`gravitee-io/Llama-Prompt-Guard-2-86M-onnx@45a05fbd5337a864edc608f994911f009c37ca57`](https://huggingface.co/gravitee-io/Llama-Prompt-Guard-2-86M-onnx/tree/45a05fbd5337a864edc608f994911f009c37ca57)

**GitHub:**

- [`meta-llama/PurpleLlama@172c1074069eb88ec834124272c1b1c4f8893445`](https://github.com/meta-llama/PurpleLlama/tree/172c1074069eb88ec834124272c1b1c4f8893445):
  - `README.md:28-43`
  - `Prompt-Guard/README.md`
  - `Llama-Prompt-Guard-2/{README.md, 86M/LICENSE, 86M/USE_POLICY.md, 86M/MODEL_CARD.md}`
  - `LlamaFirewall/pyproject.toml`
  - `LlamaFirewall/src/llamafirewall/scanners/{promptguard_utils.py, prompt_guard_scanner.py}`
- [`meta-llama/llama-models@0e0b8c519242d5833d8c11bffc1232b77ad7f301`](https://github.com/meta-llama/llama-models/tree/0e0b8c519242d5833d8c11bffc1232b77ad7f301): `models/llama4/LICENSE`, `USE_POLICY.md`, `models/llama3_1/LICENSE`
- [`meta-llama/llama-cookbook@2f22a9eb030f92d0e99227e57e9a1123af1f9532`](https://github.com/meta-llama/llama-cookbook/tree/2f22a9eb030f92d0e99227e57e9a1123af1f9532): `getting-started/responsible_ai/prompt_guard/inference.py`
- [`huggingface/candle@5ba5d5b468b5b1df40e82dd3d556987bedeea041`](https://github.com/huggingface/candle/tree/5ba5d5b468b5b1df40e82dd3d556987bedeea041): `candle-transformers/src/models/debertav2.rs`, `candle-examples/examples/debertav2/README.md`, `candle-core/Cargo.toml`
- [`huggingface/tokenizers@bbccb0513ff9afda385ca5c85c66eddb1318cfc7`](https://github.com/huggingface/tokenizers/tree/bbccb0513ff9afda385ca5c85c66eddb1318cfc7), plus crates.io metadata for `tokenizers` 0.23.2 and 1.0.0-rc.2
- sonos/tract PRs [#2531](https://github.com/sonos/tract/pull/2531), [#2532](https://github.com/sonos/tract/pull/2532) and [#2533](https://github.com/sonos/tract/pull/2533) (merged 2026-07-29/30)

Public context, which is not evidence for any code claim above:

- Cisco / Robust Intelligence, ["Bypassing Meta's LLaMA Classifier: A Simple Jailbreak"](https://blogs.cisco.com/security/bypassing-metas-llama-classifier-a-simple-jailbreak) (2024-07-29)
- Hackett et al., [arXiv 2504.11168v1](https://arxiv.org/html/2504.11168v1)
- Nasr, Carlini et al., ["The Attacker Moves Second", arXiv 2510.09023v1](https://arxiv.org/html/2510.09023v1)
- LlamaFirewall paper, [arXiv 2505.03574v1](https://arxiv.org/html/2505.03574v1)
- Meta, ["Open Source AI Can Help America Lead in AI and Strengthen Global Security"](https://about.fb.com/news/2024/11/open-source-ai-america-global-security/) (2024-11-04)
- Trendyol, ["Bypassing Meta's Llama Firewall"](https://medium.com/trendyol-tech/bypassing-metas-llama-firewall-a-case-study-in-prompt-injection-vulnerabilities-fb552b93412b) (2025-07-11; snippet only, the page returned 403)
- The Register, [coverage of the PG1 bypass](https://www.theregister.com/software/2024/07/29/metas-ai-safety-system-defeated-by-the-space-bar/1126303) (2024-07-29)
