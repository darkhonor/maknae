# Agent Deck (dot-agent-deck) — External Framework Assessment

| | |
|---|---|
| **Status** | Assessment record — informs roadmap and engineering-process design. **No dispositions ratified; no issues opened; no team decisions taken.** The assessment is the only activity. |
| **Date** | 2026-08-21 |
| **Subject** | [`vfarcic/dot-agent-deck`](https://github.com/vfarcic/dot-agent-deck) — Rust terminal dashboard (TUI + daemon) for monitoring and orchestrating multiple AI coding-agent sessions. MIT. Author: Viktor Farcic (DevOps Toolkit), Spain. Docs: `agent-deck.devopstoolkit.ai`. |
| **Method** | **Local clone, read-only survey.** Operator authorized the clone (EU/Spain author, favorable provenance — see §1). Read: `README.md`, `Cargo.toml`, the full 15-rule `CLAUDE.md`, `CONTRIBUTING.md`, PRD #20 (`prds/20-multi-agent-support.md`), `docs/orchestration.md`, and the `src/`/`docs/`/`prds/` directory structure. **Did NOT build, run, or execute the binary; no dependency install; no implementation or security audit.** See §4. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |
| **Purpose** | Capture what a disciplined peer project has *identified and solved* that Maknae has not yet closed — so the lessons are on the shelf when we reach those seams, and this evaluation is not re-run from scratch. |

## 1. Provenance disposition (read first)

Agent Deck's provenance is **favorable**, and deliberately contrasts with the DeepSeek record (2026-08-14):

- **Individual EU-origin author, permissive license, cloning authorized.** Viktor Farcic is a well-known DevOps educator based in Spain; the project is MIT. The operator explicitly cleared cloning for review. There is no PRC-origin SCRM bar here, and this assessment was done against a real working tree rather than the REST API alone.
- **But artifact adoption is still off the table — for a different reason than DeepSeek.** DeepSeek's code was foreclosed by *provenance*. Agent Deck's is foreclosed by **domain mismatch and trust-model inversion**: it is a TUI/PTY orchestrator (`ratatui`/`crossterm`/`portable-pty`/`vt100`) that Maknae has no component-shaped need for, and it is built on the **opposite** threat model — it *trusts* its host and the agents it spawns, whereas Maknae treats the runtime as untrusted by design. Importing its code would import an incompatible security posture. **None of its crates enter Maknae's dependency tree; no fork or vendored-component reuse is contemplated** — unlike the OpenClaw/Hermes autopsy, where reuse genuinely was on the table.
- **Ideas, patterns, and engineering process are safe to learn from.** An architecture and a set of well-reasoned `CLAUDE.md` rules are not a dependency. The value here is almost entirely **process and design discipline**, not features or code.

## 2. Where Agent Deck sits (center of gravity)

Against the reference set already on record:

| | Center of gravity |
|---|---|
| **OpenClaw** | Breadth of **channels** + native mobile/voice; single-user, local-first control plane. |
| **Hermes** | The **learning loop** — skills-from-experience, memory, session search, user-modeling. |
| **DeepSeek Harness** | The **architecture itself** — a plugin tree where everything, including the agent loop, is hot-swappable. "No privileged core." |
| **Agent Deck** | **Two things.** (a) An *outside-in* posture — it is not an agent framework at all but a **meta-tool that observes and orchestrates other agents** from a trusted perch (daemon + TUI, orchestrator/worker pipelines, worktree dispatch, remote environments, scheduled tasks, a curated multi-agent adapter registry). (b) **Engineering-process rigor as a first-class artifact** — a measured, self-correcting `CLAUDE.md` decision-log, doc-first PRDs, and a risk-tiered PTY test harness. |

**The inversion is the lens for everything below.** Agent Deck orchestrates *trusted-to-it* agents from a *trusted* host; Maknae governs an *untrusted-by-design* agent from a *trusted kernel*. They sit back-to-back. That is why the deck's feature machinery mostly lands on the wrong side of Maknae's trust boundary, while its **process discipline** — which is threat-model-agnostic — is the real prize.

## 3. Findings and dispositions

Dispositions below are **proposed characterizations only** — nothing is decided, scheduled, or ticketed.

### 3.1 The `CLAUDE.md` as a measured, self-correcting decision-log — LEARN FROM (highest ROI; Maknae has no `CLAUDE.md` at all).
This is the single most transferable artifact. Every rule in the deck's `CLAUDE.md` is written not as "do X" but as a decision record: the **exact failure that motivated it** (e.g. a deliberate `E0308` injected into an e2e test that *passed* a vacuously-green lint gate), the **measurement** (`~0.2s warm`; `1657 vs 1705 tests selected`), **dated corrections** ("Corrected 2026-07-30: this rule previously claimed X — all three claims were wrong, measured on #286"), and the discipline of **"this is a reason, not a precedent."**
- **Problem it solves that Maknae will hit:** an AI agent re-introducing a bug that was already fixed, because the *rationale* was not captured at the point of change. The rule format keeps the "why" adjacent to the "what."
- **Fit to Maknae:** the DNA already exists in the ADRs (ADR-0016's line-drawing rule is exactly this instinct), but ADRs are decision-point snapshots; the deck captures **drift and correction over time**. Adopting the "corrected on DATE, here is what was wrong and how it was measured" pattern — and standing up a Maknae `CLAUDE.md` in this style — is the recommended first move if any activity follows.

### 3.2 Daemon↔client protocol-contract discipline (their Rule 12) — LEARN FROM / candidate for `maknae-proto`.
> **Maknae has ruled the opposite, 2026-08-31.** Nothing is a breaking change while we are still building; break-notes are not written here and the two that existed are deleted. This paragraph describes what the DECK requires and is retained as provenance only — per the registry's authority rule, an external project's practice is never authoritative for Maknae. Do not adopt it.

The deck requires that **any change to the daemon or TUI↔daemon protocol** either bump `PROTOCOL_VERSION` or add a `.breaking.md` fragment, **plus** a manual old-daemon/new-client cross-version test — and it explicitly counts a **semantic break behind a stable wire** (a field whose *meaning* shifts under an unchanged shape) as breaking.
- **Problem it solves that Maknae will hit:** Maknae has `maknaed` + `maknae` CLI + `maknae-proto`. A re-interpreted protocol field on a policy path is precisely the kind of silent semantic break that could turn a deny into a permit while every type-check stays green. The deck names and gates exactly this hazard.

### 3.3 Curated, compiled-in adapter registry + finite integration "strategies" (PRD #20) — LEARN FROM, with a security reframing.
The deck models every agent as **one registry entry** (label, badge, detection pattern, default command, integration strategy) keyed by a **typed identity**, routed through a small finite set of strategies (native-hooks / plugin / stdout-wrapper / log-watcher). **Runtime/user extensibility is an explicit non-goal** — adding an agent requires a recompile-and-release, which is accepted.
- **Fit to Maknae:** Maknae hosts personas and integrates HobiBot/TaeBot/Security-MCP as PIPs; the "typed identity into a registry, no free-form string" seam fits the gateway/PIP boundary well.
- **The reframing:** for the deck, "no runtime extensibility" is *maintainer ergonomics*. For Maknae it is **attack-surface reduction** — a stronger, more citable justification. Same pattern, better warrant.

### 3.4 Risk-tiered testing with real-agent e2e + `reproduce-first` — LEARN FROM (reinforces the mutation-proofing thesis).
Two coupled disciplines: (a) test the feature **as the user actually sees it** — a live agent visibly working on a *cheap real model* (Haiku) with a uniquely-named **sentinel file** so the assertion survives LLM phrasing variance — not a `cat`/print-mode stand-in; and (b) **reproduce-first**: a reported bug becomes a failing test *for the reporter's reason*, observed failing, before any fix — "an assertion never observed failing is not evidence that it covers anything."
- **Problem it solves that Maknae will hit:** Maknae's README §4 already commits to the test suite doubling as **mutation-proofing for AI-implemented segments**. The deck shows the operational form of that thesis: exercise the *real* decision path (for Maknae, the actual PDP verdict), not a mock, and prove every assertion can go red.

### 3.5 Cargo pin rationale-in-comments — LEARN FROM (natural fit for FIPS / SCRM).
Every dependency pin in the deck's `Cargo.toml` documents the **exact failure it prevents** (the `crossterm` C0-decoder inverse, the `portable-pty` ConPTY stall, `reqwest`'s rustls-feature churn across patch releases).
- **Fit to Maknae:** for a FIPS-140-3 / DoD-SCRM project on `aws-lc-rs` with a `deny.toml` already in place, a pin without a documented reason is an *unreviewed control*. The convention turns the workspace `Cargo.toml` into supply-chain evidence.

### 3.6 The "vacuously-green gate" war story — LEARN FROM (field validation of the fail-closed coverage contract).
The deck's Rules 2/5 document a real incident: `clippy`/`nextest` were silently type-checking and asserting over **zero** test files (and entire `xtask` members) until `--all-targets --features e2e --workspace` were all present — a green gate that measured nothing.
- **Fit to Maknae:** this is external evidence for the exact instinct `coverage-tiers.toml` / ADR-0016 already encode ("unclassified = hard failure"). Worth keeping as a cited case study for *why* the coverage universe must be fail-closed and exhaustive.

### 3.7 Orchestrator/worker independent-review rationale — LEARN FROM (ammunition for blind-review governance).
The deck's `docs/orchestration.md` argues plainly: "an agent reviewing its own code is a developer reviewing their own PR — the same assumptions, the same blind spots," so review runs as a separate agent in a fresh context, ideally a different model family.
- **Fit to Maknae:** this is the written justification for Maknae's **multi-AI blind-review** discipline and a clean assurance argument that blind review is rigor, not overhead.

### 3.8 In-repo-everything (their Rule 13) — DO NOT ADOPT; record as a deliberate contrast.
The deck mandates that **all** project knowledge lives in-repo ("no global/user memory"), justified by portability across contributors. This is the **direct opposite** of Maknae's operator-mandated hard rule (specs, plans, SDD workspaces → `~/claude-memory/<project>/`, never the repo).
- **Disposition:** learn the *intent* — decision provenance must be captured and portable — and reject the *location*. Note the boundary: this class of record (external-framework assessments, autopsies, ADRs, the KLC contract) **is** legitimate committed design documentation and correctly lives in `design/`; process artifacts (specs/plans/workspaces) do not.

### 3.9 The governance model (owner admin-bypass, Renovate auto-merge lane, advisory-only bot review) — DO NOT ADOPT; validating contrast for the enclave posture.
The deck **deliberately** accepts an owner admin-bypass of required checks, a zero-human-approval Renovate auto-merge path, and treats its review bot (Greptile) as advisory. Reasonable for a single-owner productivity tool.
- **Disposition:** in a DoD RMF / cATO posture this is a **separation-of-duties finding**, not a convenience. Maknae's enclave needs the inverse — no bypass actors, enforced dual review, the reviewer gate *is* a gate. The deck's own reasoning ("the four required checks are *objective*, so owner bypass is tolerable") is a clean articulation of the boundary Maknae must draw differently.

### 3.10 Threat-model inversion & presentation-only feature flags — DO NOT ADOPT in the trust plane; documented threat-model contrast.
The deck trusts host and agents; its "security" surface is supply-chain (`cargo audit`, a required `security` CI job) and branch protection — there is no PDP, no DCS, no classification, no deny-by-default. Its Rule 9 feature flag is explicitly a **presentation switch** ("never branch business logic / daemon protocol / hook handling on the flag").
- **Disposition:** do not import the "it's just presentation" mental model into Maknae's kernel — a flag that gates policy behavior is a control-relevant configuration item, not cosmetic. Like DeepSeek's "no privileged core," the deck's trusting design is most useful to Maknae as a **clean articulation of the posture the trust plane deliberately rejects.** (Supply-chain gating via `cargo audit`/`cargo-deny` *does* align and is already present in Maknae.)

### 3.11 Doc-first PRDs with explicit Rescope / Validation-refresh sections — LEARN FROM.
The deck's PRDs are living scope documents: PRD #20 carries a dated "Rescope (2026-06-22)" and a "Validation refresh (2026-06-14) — here is what the original draft got wrong." This complements ADRs (which record decisions) by recording **how and why scope changed**, and would sit naturally in Maknae's `~/claude-memory/maknae/specs/` per the hard rule.

## 4. Scope and limits of this assessment (honesty)

Read in full against a live clone: `README.md`, `Cargo.toml`, the complete `CLAUDE.md` (15 permanent rules), `CONTRIBUTING.md`, PRD #20, `docs/orchestration.md`, and the top-level `src/` / `docs/` / `prds/` structure. Read at title/structure level only: the remaining 47 PRDs, the `docs/develop/*` design records, and the `src/` implementation (daemon protocol, PTY plumbing, platform backends). **The binary was never built or run; no dependency was installed; no implementation or security audit was performed, and none is planned** — the domain mismatch and trust-model inversion (§1) make a deeper code audit unwarranted for reuse purposes. Conclusions are drawn from published/committed design docs and rules, not from verified runtime behavior. Star counts and adoption metrics were not captured and are intentionally not asserted.
