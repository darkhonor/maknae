# FrontierAgent — External Framework Assessment

| | |
|---|---|
| **Status** | Assessment record — informs runtime, sandbox, agent-team, skill, artifact, and SCRM design |
| **Date** | 2026-08-28 |
| **Subject** | [`ApodexAI/FrontierAgent`](https://github.com/ApodexAI/FrontierAgent) at commit [`76ac16b`](https://github.com/ApodexAI/FrontierAgent/tree/76ac16b6a88c2bb6ae45095b4896fdfc643519cb) — Python agent runtime, terminal product, multi-agent workflow, and evaluation suite; Apache-2.0; v0.1.0 |
| **Method** | **Read-only** survey through the GitHub API and published web material. No clone, package install, container pull, model download, build, or execution. See §§1 and 5. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |

## 1. Executive disposition and provenance caveat (load-bearing — read first)

FrontierAgent is worth studying and **not suitable for direct adoption into Maknae's dependency or execution supply chain**. Its highest-value contributions are engineering patterns: one runtime shared by the product and benchmark harness, task-scoped workspaces, explicit tool registries, bounded agent-team spawning, manifest-aware output publication, symlink-aware path authorization, SSRF-resistant fetches, and operator-visible approval/diff/recovery UX. Its central security limitation is equally instructive: the authorization, observer, skill, and tool controls execute inside the same Python process as the untrusted agent runtime, while the interactive product can run commands natively with the invoking user's host permissions. These are useful PEP and usability patterns; they are not a trusted reference monitor.

The supply-chain posture requires elevated caution:

- **Mixed U.S./Singapore corporate surface; opaque ownership and funding.** Apodex says its product is developed in the [United States and Singapore](https://www.apodex.com/blog/apodex), and its [institutional agreement](https://www.apodex.com/policies/pilot-institutional-user-agreement) identifies Apodex US, Inc., a Delaware corporation. [A Singapore corporate-data provider](https://companieshouse.sg/apodex-202629735H) also indexes APODEX PTE. LTD.; that provider expressly says it is not the government registry, so the entry is supporting rather than dispositive evidence. No `FUNDING.yml`, `CODEOWNERS`, ownership statement, sponsor register, SBOM, signed release provenance, or governance document was found in the inspected pinned tree. The absence does not prove hidden control; it means this survey cannot establish beneficial ownership, funding sources, maintainer succession, or separation of duties from primary evidence.
- **Prominent contributor's self-disclosed nationality and Singapore affiliation.** The repository's dominant contributor at the pinned commit, and the author attached to the pinned main-tip commit, is Handuo Zhang (`zhanghanduo`; 26 attributed commits in the GitHub contributor record). His publicly posted [CV](https://handuo.top/uploads/handuo_CV.pdf) explicitly states “Nationality: Chinese (SG PR)” and describes employment at Shanda Group AI Research Institute in Singapore. This is self-disclosed evidence; the assessment does not infer a project role, control relationship, or present jurisdiction from it, and names are not used as nationality proxies.
- **Other developer nationalities are mostly unestablished; affiliations still matter.** Liangcai Su publicly identifies as an Apodex research scientist intern and documents education at Xidian and Tsinghua, a University of Hong Kong Ph.D., and prior Tencent and Tongyi Lab work on his [personal page](https://liangcaisu.github.io/). Zhaopeng Feng's [public résumé](https://fzp0424.github.io/_pages/includes/Resume-EN.pdf) documents degrees at Harbin Institute of Technology (Shenzhen) and Zhejiang University followed by a National University of Singapore Ph.D. These are institutional and employment nexuses, **not proof of nationality**. Nationality was not established for the other named contributors and is not guessed.
- **Founder/leadership association is material but sponsorship and control are unverified.** Public profiles and reporting connect Apodex to Shanda founder Tianqiao Chen; Chen's [public profile](https://www.linkedin.com/in/tianqiao-chen) lists Apodex and Shanda, and Apodex leadership profiles describe building the company with him. A [historical U.S. securities filing](https://chsnet.gcs-web.com/static-files/4dace728-6ac9-47da-b926-ae09f567a66d) identifies Chen's citizenship as the People's Republic of China. This establishes a publicly represented association, not sponsorship, beneficial ownership, present control, or current citizenship. The inspected repository and Apodex pages provide no primary ownership or funding table, so no current cap table or funding amount is claimed.
- **The recommended model lineage is directly PRC-origin.** The published [`Apodex-1.1-mini`](https://huggingface.co/apodex/Apodex-1.1-mini) model card identifies `Qwen/Qwen3.5-35B-A3B-Base` as its base; [Qwen's publisher profile](https://huggingface.co/Qwen) identifies the family with Alibaba Cloud. FrontierAgent is model-provider-neutral at the protocol layer, but its first-party performance story, compatibility configuration, and deployment guidance are coupled to Apodex/Qwen checkpoints.

As checked on 2026-08-28, [15 CFR 791.4](https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-E/part-791/subpart-A/section-791.4) names the People's Republic of China, including Hong Kong and Macau, as a foreign adversary solely for the Commerce Department ICTS rule and related rules under the executive order. The [NIST-hosted ICT-SCRM threat-overlay briefing](https://csrc.nist.gov/csrc/media/Presentations/2024/ict-scrm-overlay/20240917_TOR-2023-00502-Rev%20A%20-%20ICT-SCRM%20Control%20Overlay%20-%20A%20Threat%20Based%20Approach.pdf) is explanatory, not the controlling authority. **Nationality by itself is not disqualifying and is not a vulnerability, and this assessment does not claim that the ICTS rule directly prohibits FrontierAgent.** The decision-relevant SCRM combination is the documented PRC connections and model provenance, unclear ownership/funding, a very young project, and unsigned governance/provenance gaps.

**Disposition:** learn from published designs only. Do not import FrontierAgent code, Python packages, containers, hosted services, Apodex/Qwen weights, prompts, skills, or benchmark judges into Maknae or a sensitive development environment without a separately authorized SCRM review, source/dependency audit, artifact provenance verification, and legal/export-control review. Any adopted idea should be independently implemented behind Maknae's existing Rust trust boundary. This assessment itself followed that rule: API/document reading only, with no artifact execution.

## 2. Where FrontierAgent sits (center of gravity)

Against Maknae's reference set:

| | Center of gravity |
|---|---|
| **OpenClaw** | Channel breadth, local-first control plane, and native mobile/voice surfaces. |
| **Hermes** | Learning from experience: generated skills, memory, session retrieval, and user modeling. |
| **DeepSeek Harness** | A hot-swappable plugin architecture with no privileged core. |
| **Agent Deck** | Outside-in orchestration of other agents plus unusually disciplined engineering-process artifacts. |
| **FrontierAgent** | A **working-agent laboratory**: the same long-horizon ReAct and asynchronous Agent Team runtime drives a TUI product and a broad evaluation harness, with strong task-workspace, artifact, path, network-fetch, budget, and recovery machinery. |

FrontierAgent is closer to the runtime plane Maknae eventually needs than Agent Deck, and more operationally complete than the architectural DeepSeek Harness. The resemblance is precisely why the boundary matters: FrontierAgent treats the agent runtime's in-process controls, human approvals, and optional OS sandbox as the security model. Maknae treats that entire runtime as untrusted and places authorization in `maknaed`.

## 3. Findings and dispositions

The dispositions below are assessment recommendations only. They do not create roadmap commitments, approve dependencies, or supersede the KLC or an ADR.

### 3.1 One runtime for interactive work and evaluation — LEARN FROM (highest engineering ROI)

FrontierAgent deliberately separates framework, tools, workflows, product UI, and benchmarks while routing both the interactive TUI and benchmark runner through the same ReAct/Agent Team engine. CI includes a framework-only import smoke, then installs the evaluation layer and checks the larger symbol closure. This is a strong answer to a common agent-platform failure: benchmarks exercise a toy loop while users run a different product path.

**Pinned evidence:** [`README.md`](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/README.md), [framework architecture](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/docs/framework.md), and [CI workflow](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/.github/workflows/ci.yml).

**Maknae consideration:** preserve the same decision-path principle more strictly. Tests and evaluations should traverse the real `maknaed` PDP, actual protocol, audit-obligation composition, and scoped task identity. A benchmark-only policy shim is the authorization equivalent of a vacuously green test. Keep evaluation datasets and judges outside the TCB, and do not let a benchmark package pull its large optional dependency graph into the kernel.

### 3.2 Task-scoped filesystem and manifest-aware publication — LEARN FROM / candidate runtime-plane pattern

The reusable framework gives each task `/inputs` (read-only), `/workspace` (working state), and `/outputs` (persistent deliverables). Only declared publishers may finalize outputs; sub-agents receive scoped workspaces; scratch output is distinguished from final publication. This is better than treating a shared checkout as an undifferentiated agent home.

**Pinned evidence:** [framework sandbox/publication contract](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/docs/framework.md) and [deliverable policy](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/plugins/tools/_deliverable_policy.py).

**Maknae consideration:** model “publish artifact” as a distinct authorized action, not merely a successful file write. The kernel should decide subject × action × destination × labels, preserve the task high-water classification on output, attach provenance/lineage, and audit the publication. FrontierAgent's directory convention is reusable as runtime ergonomics; its in-process manifest is not the authority.

### 3.3 Bounded asynchronous Agent Team and structured fan-in — LEARN FROM, with identity carried through every edge

`AgentBus`, `SpawnGuard`, the task board, structured reports, cancellation, depth limits, token reservations, parallelism bounds, wall-clock guards, and explicit report collection form a coherent multi-agent contract. Particularly good is the measured correction behind the 90-minute sub-agent ceiling: the source records that a prior ceiling killed 52.8% of sub-agents in one run and attributes most elapsed time to queued model latency rather than tools. That is the measured, self-correcting style Maknae values.

**Pinned evidence:** [`AgentBus`](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/frontier_agent/components/agent_bus/bus.py), [`SpawnGuard`](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/frontier_agent/components/agent_bus/spawn_guard.py), and [task-board tooling](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/plugins/tools/task_board.py).

**Maknae consideration:** each spawned worker must be a scoped subject, not an extension of its parent prompt. Delegation may narrow attributes and capabilities but never widen them; reports are untrusted inputs that may inform but not authorize; shared context and final fan-in inherit the classification high-water mark. Cancellation, budget exhaustion, and partial reports must produce auditable terminal states rather than silently disappearing.

### 3.4 Observer interventions are a clean extension seam — LEARN FROM outside the TCB; DO NOT ADOPT as authorization

Observers can inspect LLM attempts, streaming deltas, responses, tool calls, tool results, turn ends, and cancellation, returning interventions that stop, retry, or replace content. The framework documentation says authorization observers must fail closed while cleanup and telemetry remain best-effort. This separation is thoughtful and useful for runtime policy enforcement points, observability, compaction, and human intervention.

**Pinned evidence:** [observer contract](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/docs/framework.md), [loop intervention types](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/frontier_agent/core/loop_types.py), and [terminal observers](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/apodex/observers.py).

The trap is locus: observers are dynamically composed Python callbacks in the same process as the agent loop. They can alter model content and tool flow, but they are not isolated from the code they constrain. A missing, misordered, disabled, or compromised observer can erase the control.

**Maknae consideration:** use an observer/event contract for runtime telemetry and UX, but require a versioned request to `maknaed` for every consequential decision. The observer may be a PEP; only `maknaed` is the PDP. Authorization failure, protocol failure, or missing subject context remains `Indeterminate`/deny, never “continue without consuming the turn budget.”

### 3.5 Path authorization and SSRF defenses — LEARN FROM (strong implementation detail)

FrontierAgent does several difficult things well:

- resolves symlinks before authorization and blocks the classic “link a workspace path to `~/.ssh`” escape;
- distinguishes read and write prefixes, task inputs, spill stores, skill resources, and isolated workspaces;
- vets web targets as public HTTP(S), rejects credentials in URLs, requires every resolved address to be global, pins requests to the vetted address, and strips credentials on cross-origin redirects;
- caps fetch sizes, blocks archive-like downloads in the fetch path, and adds memory, file-size, and execution budgets;
- keeps a hard command deny layer beneath the interactive approval UI.

**Pinned evidence:** [path authorization](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/plugins/tools/_path_auth.py), [bounded-fetch/SSRF checks](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/plugins/tools/_bounded_fetch.py), and [sandboxed shell policy](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/plugins/tools/bash.py).

These are useful negative-test seeds for Maknae's runtime and gateway. They do not replace `maknae-io`: FrontierAgent's controls are path-string and Python-process gates, while `maknae-io` pins the checked inode to the used file descriptor and rejects symlink traversal per component.

### 3.6 The interactive “sandbox” splits into two materially different security postures — TRAP TO AVOID

The framework's sandbox documentation says `auto`/`bwrap` fail if isolation is unavailable and that there is no unisolated fallback. The terminal product says something different: Linux defaults to **native**, macOS without Docker falls back to **native**, `--no-sandbox` is available, and native commands run with the current user's permissions. The top-level README nevertheless highlights “Sandboxed file work.” The detailed documentation discloses the limitation, but the product-level label can cause operators to overestimate the boundary.

**Pinned evidence:** [framework sandbox contract](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/docs/framework.md), [terminal execution modes and safety](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/apodex/README.md), and [native shell implementation](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/apodex/local_tools.py).

The approval gate, command-pattern denylist, path checks, journaling, and `/revert` reduce accidents. They do not contain an adversarial shell process, prevent same-user credential access, undo arbitrary shell side effects, or survive an in-process compromise. The documentation itself admits that shell-write scanning cannot reliably revert concurrent edits.

**Maknae consideration:** name every execution mode by its actual boundary and refuse to call native execution a sandbox. The enclave/default path must have no host-native fallback. If a development-only unsafe mode ever exists, it must be build-time excluded from accredited artifacts, visibly non-equivalent, and incapable of weakening `maknaed` decisions.

### 3.7 Human approval, diff preview, typed destructive confirmation, and revert — LEARN FROM as UX; NEVER TREAT AS AUTHORIZATION

FrontierAgent starts approvals on “No,” rejects when no TTY can ask, previews diffs, requires typed confirmation for destructive operations, supports persistent per-command allow/deny rules, records traces, and offers session revert. Those are good operator affordances and superior to a generic “Allow tool?” modal.

**Pinned evidence:** [approval observer](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/apodex/observers.py), [persistent permission rules](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/apodex/permissions.py), and [workspace journal/revert](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/apodex/changes.py).

The traps are `--yes`, session-global auto-approve, persisted prefix rules, best-effort permission-store load/save that swallows errors, and a lexical command classifier operating above host-native execution. Even a perfect human confirmation proves intent at one moment; it does not prove clearance, role entitlement, resource label compatibility, or safe downstream effects.

**Maknae consideration:** retain preview, target visibility, typed destructive confirmation, and recoverability as PEP UX. The PDP decision remains independent, deny-overrides, authenticated, attributed to the real operator/task subject, and non-waivable by an “admin” or auto-approve switch.

### 3.8 Web access has strong transport hygiene but permissive authority semantics — LEARN FROM THE MECHANICS; REJECT THE POLICY MODEL

`web_fetch` has unusually careful SSRF, redirect, credential, size, rendering, and cache handling. At the same time, web search/fetch are classified as read-only and auto-run, sandbox `bash` permits network access, and the network guard is primarily a per-connection download cap whose telemetry failures deliberately fail open. A prompt-injected URL may therefore be technically safe to fetch while still being epistemically unauthorized, operationally sensitive, or an egress-policy violation.

**Pinned evidence:** [terminal tool risk classes](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/apodex/agent_tools.py), [bounded fetch](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/plugins/tools/_bounded_fetch.py), [network guard](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/plugins/tools/_net_guard.py), and [sandboxed shell networking](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/plugins/tools/bash.py).

**Maknae consideration:** borrow SSRF and bounded-fetch test cases, but put every fetch through KLC hook A/E and the signed authority map. “Public IP” is not “authorized source”; “read-only HTTP” is still egress; returned content begins at Tier 3, carries derived issuer/authority labels, and may inform but never authorize.

### 3.9 Skills are explicitly allowlisted but lack a governed trust lifecycle — LEARN FROM THE LOADER SHAPE; APPLY THE KLC INSTEAD

FrontierAgent's skill loader discovers `SKILL.md`, parses safe YAML frontmatter, records scripts/resources and `allowed-tools`, supports an explicit allowlist wrapper, and injects skill metadata only for roles enabled to load skills. No skills ship in the repository at the pinned commit, which limits immediate attack surface.

**Pinned evidence:** [filesystem skill loader](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/frontier_agent/components/skills/file_system_loader.py), [allowlist wrapper](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/frontier_agent/components/skills/allowlist_loader.py), and [skill-injection middleware](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/frontier_agent/components/middleware/llm/skill_injection.py). No `plugins/skills/` payload was found in the inspected pinned tree.

However, skills are filesystem content injected into the model context, enabled through mutable extension configuration. There is no signature requirement, authority tier, provenance chain, promotion history, capability-minimization gate, classification label, or kernel-enforced binding between `allowed-tools` metadata and the ultimate authorization decision. Parse failures can degrade to empty metadata, and discovery failures warn and continue.

**Maknae consideration:** the loader ergonomics are useful, but the KLC already supplies the missing security contract. New/generated skills start at Tier 3, and Hook F permits execution only when a skill is signed, is at an executable tier, declares capabilities within the persona and task whitelist, and meets the host-sandbox requirement. Capability manifests are enforced by the PDP rather than trusted as prose, and runtime mutation may propose but never self-promote.

### 3.10 Tracing, checkpoints, and trajectories are operationally strong but not audit evidence — LEARN FROM / DO NOT CONFUSE

Interactive runs group `session.json`, `trace.jsonl`, engine logs, trajectories, workspace, and outputs under a stable session directory; timestamps retain canonical UTC; resume and fork are first-class. This is useful incident-reconstruction and long-horizon continuity design.

**Pinned evidence:** [run-artifact layout](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/docs/run-artifacts.md), [session implementation](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/apodex/session.py), and [OSS event-store stub](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/frontier_agent/state/event_store/sqlite.py).

The framework event store in the trimmed OSS distribution is explicitly an in-memory no-op, and local JSONL/session files are same-user mutable. There is no authenticated subject model, AU-3-complete record contract, hash chain, signed/external anchor, non-repudiation, retention policy, or deny-on-audit-sink-failure guarantee.

**Maknae consideration:** keep the run-artifact layout outside the TCB and correlate it with the canonical audit id. Maknae's audit record and append path remain authoritative; runtime traces are PIP evidence and debugging material, never the security log of record.

### 3.11 Supply-chain hygiene has good beginnings but is not sufficient for Maknae — LEARN FROM / DO NOT ADOPT ARTIFACTS

Positive signals include Apache-2.0 licensing, a committed `uv.lock` with hashes, CI using `uv sync --locked`, explicit security floors for vulnerable transitive packages, an unprivileged container user for tool execution, Ruff/Pyright/test gates, Dependabot participation, and a vulnerability-reporting address with response targets.

**Pinned evidence:** [`pyproject.toml`](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/pyproject.toml), [`uv.lock`](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/uv.lock), [CI](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/.github/workflows/ci.yml), [container build](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/Dockerfile), and [security policy](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/SECURITY.md).

Material gaps for Maknae's context include a broad Python/Node/container dependency surface, floating GitHub Action major tags, `pip install uv` during image build, and an optional plugin/evaluation graph far larger than the core runtime. No repository SBOM/VEX, `SLSA`/Sigstore attestation, CODEOWNERS, funding disclosure, signed release policy, stated FIPS posture, or reproducible-build claim was found during this pinned, read-only survey. GitHub repository metadata recorded a creation date of 2026-08-22—six days before this assessment—so security-policy prose and a substantial committed test surface are positive, but operating history is necessarily thin.

**Disposition:** no package, image, model, prompt, or code reuse. If a future team wants any artifact despite this assessment, require a separate assess-only/SCRM package review pinned by digest, complete transitive inventory, maintainer/ownership disclosure, build provenance, malware/static review, and isolation from Maknae's development and deployment credentials.

### 3.12 Verification-first agent teams are promising, but self-review is not blind review — LEARN FROM WITH A GOVERNANCE CORRECTION

FrontierAgent emphasizes planner/coordinator decomposition, reporter review, evidence collection, deterministic artifact validation, and benchmark-specific judges. The separation of solver and verifier contexts is better than asking one transcript to “double-check itself.” Reusable deterministic validators are especially valuable.

**Pinned evidence:** [top-level workflow/evaluation description](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/README.md), [benchmark registry](https://github.com/ApodexAI/FrontierAgent/blob/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/benchmarks/README.md), and [public judge implementations](https://github.com/ApodexAI/FrontierAgent/tree/76ac16b6a88c2bb6ae45095b4896fdfc643519cb/benchmarks/public/judges).

But the same vendor publishes the model, harness, workflows, reported benchmark results, and much of the evaluation machinery. Agent Team reviewers may share the same model family, prompts, dependencies, and organizational assumptions. This is not evidence of manipulation; it is correlated-error risk and a reason not to equate verifier separation with independent assurance.

**Maknae consideration:** preserve fresh-context and, where practical, different-model-family review; separate authorship from acceptance; keep deterministic gates independently inspectable; pin benchmark definitions; and record conflicts of interest. The actual PDP verdict and negative controls remain the evidence, not a verifier agent's confidence.

## 4. Concrete Maknae considerations

If FrontierAgent influences later requirements work, the useful questions are:

1. **Artifact publication contract:** should Maknae define a first-class `publish` action and manifest before the runtime/file-deliverable phase, including label inheritance and declared publisher identity?
2. **Scoped task identity propagation:** what exact attributes, delegation chain, high-water label, budgets, and audit correlation must cross coordinator → worker → report → finalizer?
3. **Runtime observer protocol:** which events are informative runtime callbacks, and which require a synchronous versioned `maknaed` decision before continuation?
4. **Execution-mode truthfulness:** what named isolation levels ship, which are permitted per deployment profile, and how does boot fail closed when the promised boundary is unavailable?
5. **Fetch mechanics:** which FrontierAgent SSRF, redirect, DNS pinning, credential stripping, size-cap, and archive-rejection negatives should become gateway/runtime acceptance tests beneath the KLC authority decision?
6. **Run evidence correlation:** how do untrusted runtime traces and task artifacts reference the canonical append-only audit record without being mistaken for it?
7. **Evaluation separation:** how do we ensure the same path serves product and evaluation while keeping datasets, judges, and model-vendor claims outside the TCB and independently reproducible?

These are requirements prompts, not decisions. Any choice that constrains the protocol, TCB, audit schema, or artifact semantics belongs in an ADR when made.

## 5. Scope and limits of this assessment (honesty)

Read in full or at implementation-relevant depth at pinned commit `76ac16b`: repository metadata and tree; `README.md`; `SECURITY.md`; `CONTRIBUTING.md`; `pyproject.toml`; `uv.lock` structure; CI and Docker configuration; framework and terminal documentation; run-artifact layout; tool permission context; terminal risk/approval rules; native and reusable sandbox paths; path authorization; bounded fetch/network guard; skill discovery/allowlisting/injection; AgentBus spawn budgeting; and the OSS event-store stub. Contributor counts came from the GitHub contributors endpoint at assessment time.

Public provenance sources reviewed: Apodex product and legal pages, contributor-maintained profiles/CVs, the Apodex model card, and public corporate/profile material described in §1. Nationality is stated only where a person explicitly disclosed it or a public filing recorded citizenship. Education, employer, residence, ethnicity, language, and names were not treated as nationality. No attempt was made to identify private individuals, obtain non-public records, or infer protected traits.

Not performed: clone, checkout, build, tests, dependency resolution, package installation, container pull, binary/static malware scan, model download, prompt execution, network capture, penetration test, benchmark reproduction, cryptographic provenance verification, corporate beneficial-ownership search, export-control legal opinion, or full line-by-line security audit. GitHub and web content are mutable; the source assessment is pinned to the commit above, while corporate/provenance observations are current only as of 2026-08-28.

The repository was created on 2026-08-22 and was under rapid development. Findings characterize the inspected state, not future releases. Reported performance and security properties are publisher claims unless the assessment explicitly identifies inspected implementation evidence; none was independently executed or reproduced.
