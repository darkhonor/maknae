# Reference Implementation Autopsy and Build Scope

| | |
|---|---|
| **Status** | Living document — informs KLC review and roadmap sequencing |
| **Date** | 2026-07-14 |
| **Method** | Full-source survey of both upstream mirrors and both live deployment configurations, conducted 2026-07-14 |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |

## 1. Purpose

Maknae's origin story claims the fork premise died on inspection. This document is the inspection. It records, with file-level evidence, why neither upstream can host a deny-by-default trust plane; what each contributes conceptually; what the two live deployments prove about hardening-as-overlay; and what all of this means for the build scope of a three-person team. It exists so the team argues from evidence, not vibes — and so the rationale survives into the public repo.

Both upstreams are MIT-licensed (verified against the local mirrors), so selective code reuse is available wherever concept inheritance alone is not enough.

## 2. The load-bearing finding

Both upstreams, independently, state that nothing inside the agent process is a security boundary:

- **Hermes** (`SECURITY.md` §2.2): *"The only security boundary against an adversarial LLM is the operating system. Nothing inside the agent process constitutes containment."* Every in-process check is a self-declared heuristic; bypassing one is explicitly not a vulnerability.
- **Hermes** (`tools/skill_manager_tool.py:102`), on why the skill-install guard is off by default: *"the agent can already execute the same code paths via terminal() with no gate, so the scan adds friction without meaningful security."*
- **OpenClaw** (`SECURITY.md`, Operator Trust Model): security boundaries "come from host/config trust, auth, tool policy, sandboxing, exec approvals" — i.e., operator configuration, not architecture. Prompt-injection-only findings are out of scope.

The Hermes comment is the crux of the whole project: **partial gates are theater; gating becomes meaningful only when deny-by-default is total.** Hermes is right, given its architecture. Maknae exists to change the architecture. Both platforms' engineers understand security — they made a deliberate, documented trade the other way. Maknae is not smarter than them; it is optimizing a different objective.

## 3. OpenClaw — the layered-control hyung

### 3.1 Reject (trust model, architectural)

| Decision | Evidence | Why it fights a kernel |
|---|---|---|
| Ambient full-operator scope on authentication | `SECURITY.md` Operator Trust Model; narrower `x-openclaw-scopes` ignored on the shared-secret path | Every downstream permissive default inherits from this one decision. A kernel needs per-request least-privilege scoping; OpenClaw actively collapses scopes. |
| In-process plugins with full host privileges | `SECURITY.md` Plugin Trust Boundary: "same trust level as local code" | A kernel cannot mediate code in its own address space. |
| Default-allow exec on the host | `exec.security: full` default (`src/config/types.tools.ts:319`); sandbox `off` by default | The shipped default is arbitrary host command execution without prompts. |
| Capability-free, unsigned skills | No manifest, no signing; registry verdicts and heuristic scanners are advisory | Nothing exists to attach a capability contract to. |
| Normalized break-glass | ~15 `dangerously*` flags, `/elevated full` | Kernel exceptions must be mediated and audited, not free config booleans. |
| Trust boundary per host, not per principal | "One trusted operator per gateway"; isolation = separate gateways/OS users | Retrofitting per-principal deny-by-default fights the premise. |

### 3.2 Inherit

- **Descriptor-driven tool planner** (`src/tools/types.ts`, `availability.ts`): owner/executor/availability cleanly separated, one plan across core/plugin/channel/MCP. Keep the descriptor shape; replace availability (visibility) with authorization (capability grant) as the gate.
- **Layered decoupling**: model transport / reusable agent core (`packages/agent-core`, framework-agnostic) / thin runtime facade / tools / skills, with SDK-barrel-only boundaries and manifest-declared resources.
- **Versioned metadata-only audit contract** (`src/audit/`): typed events, worker-backed writer, `blocked` status already modeled. Kernel denial events map directly onto it.
- **Exec-approval binding machinery** (`docs/tools/exec-approvals.md`): exact-argv + pinned-executable + file-snapshot binding, stricter-of merge, deny on drift. This is Hook F's primitive, sitting on an allow-by-default floor. Invert the floor and it is a capability check.
- **SKILL.md as the portable skill format** — add the signed execution manifest the KLC requires.
- **Config-migration discipline** (`doctor --fix`, no silent compat aliases).

## 4. Hermes — the learning-first hyung

### 4.1 Reject (trust model, architectural)

| Decision | Evidence | Why it fights a kernel |
|---|---|---|
| Skills execute arbitrary Python at import time, in-process | `SECURITY.md` §2.4 | The extension model IS ungated code execution. Hardest single conflict. |
| Self-generated skills → immediate execution, no gate | `background_review.py` writes straight to the skill store; guard off by default | The learning loop's value proposition is framed as gate-freedom. Maknae inverts this with quarantine + promotion (KLC §8–9). |
| Allowlisted callers are equally trusted; no per-caller capabilities | `SECURITY.md` §2.6 | Nothing to deny against. |
| Cron jobs inherit full profile authority | `cron/jobs.py`: profile env, credentials, skills | Maknae requires scoped task identities. |
| MCP trust = presence in config | `mcp_servers:` in `config.yaml`; sampling on by default | No per-server capability model. |
| Ambient egress | default `network_mode: host`; isolation is operator compose overrides | Deny-by-default egress requires reversing the default. |
| Provenance-free memory writes | `MEMORY.md`/`USER.md` chunk appends, no on-disk origin or authorization | A kernel gating writes by origin has no enforced origin signal to key on. |

### 4.2 Inherit

- **The closed learning loop shape**: experience trigger → forked reviewer with a restricted toolset → decoupled procedural store → idle-time curator consolidation. Maknae's contribution is the gate between generate and execute.
- **Origin tagging via ContextVar** (`tools/skill_provenance.py`): `background_review` vs `foreground` write origin. Used only for curation scope upstream; generalizes directly to Hook C lineage stamping and self-generated-content quarantine.
- **Memory-provider interface** (`agent/memory_provider.py`, `MemoryManager`): standing-context injection / per-turn recall / write-back cleanly separated, pluggable backends. Add provenance and authorization at the write boundary.
- **Curator invariants**: never delete (archive, recoverable); pinned items bypass automation; only touch agent-created artifacts.
- **Skills Guard's trust-tier × risk-class table** (`builtin/trusted/community/agent-created` × `safe/caution/dangerous`): the right table, wrong enforcement. Make it block, on by default.
- **Per-profile isolation layout** (`~/.hermes/profiles/<name>/`) as a store primitive, subsumed under a real trust plane.
- **OpenShell integration pattern**: per-session declarative sandbox, L7 egress policy, credentials injected from a provider store that never touches the sandbox filesystem. The one place Hermes gestures at the posture Maknae makes foundational.
- **SECURITY.md candor as a genre**: Maknae writes the inverse document — the boundary in the architecture — but that is the template.

## 5. Deployment evidence — the overlay ceiling, measured

The HobiBot (OpenClaw, VM, maximalist runbook) and TaeBot (Hermes/OpenClaw dual-runtime, Pi, codified engine) deployments are the empirical record of hardening-as-overlay:

1. **The hardening the platform most needs is the hardening it cannot accept.** HobiBot's runbook documents systemd `ProtectSystem=strict` / `NoNewPrivileges` / bounded capabilities as a "real tension" that breaks OpenClaw, and `NOPASSWD: ALL` sudo that cannot be scoped down because LLM-arbitrary-command structurally fights least privilege. The VM boundary was chosen *because* the in-process controls could not be trusted. This is the retrofit ceiling, measured.
2. **Persona/workspace must be first-class platform structure.** The TaeBot Hermes port lossily flattens the multi-file identity/soul/user/memory workspace into a single `HERMES.md` because Hermes loads only one context file. Maknae's kernel treats the persona bundle as native structure, never runtime-flattened.
3. **Fail-closed access control at every gateway.** Hermes refuses to start with an empty caller allowlist — the one trust decision it gets structurally right. Maknae generalizes it.
4. **Declarative runtime contract, no "confirm on the box."** The TaeBot engine carries apply-time-confirm unknowns (installer flags, CA env vars, tool-filter globs) because Hermes' surface is not knowable from config. Maknae's runtime contract must be fully declarative.
5. **Hardening tiers are host properties, selectively applied.** TaeBot deliberately drops auditd/fail2ban/CNSA crypto on the Pi and relocates controls (host userns-remap → distroless non-root image; raw AppRole → Vault Agent sidecar → tmpfs sink, env-scrubbed exec). This validates Hook F's attested sandbox-strength model and argues for declared host hardening profiles platform-wide.
6. **Least privilege at the boundary, not the prompt.** Both deployments enforce MCP tool filters and read-only RBAC at the gateway layer and explicitly reject "relying on the model to refrain." This is the kernel thesis in operational miniature.

## 6. Build scope — what a three-person team actually builds

### 6.1 The scale asymmetry, stated honestly

OpenClaw and Hermes are large codebases with active contributor communities. Maknae is three security-paranoid engineers with day jobs. Attempting feature parity is the losing move and is not the plan. Two facts make the project tractable:

1. **Most upstream mass is breadth Maknae defers.** The bulk of both codebases is channel adapters (Discord/Slack/Telegram/WhatsApp/Signal/email), native companion apps, dozens of LLM provider integrations, and UX polish. None of that is the differentiator, and MCP + a single channel cover the MVP.
2. **The differentiator is deliberately small.** The trust plane kernel is required to be small-and-auditable — that is a scope ceiling, not just a security property. The kernel decides behind a policy-agnostic seam with pluggable backends ([ADR-0004](adr/ADR-0004-modular-authorization-architecture.md)) — a simple native-Rust RBAC default (no general policy *language* written from scratch), with Cedar or another engine available as an optional backend where complexity justifies it — enforces the label schema, and emits audit events. It is measured in thousands of lines, not hundreds of thousands.

### 6.2 Do not build — leverage

| Need | Leverage | Cost avoided |
|---|---|---|
| Policy engine | Pluggable `maknae-authz-*` backends behind the seam (ADR-0004); simple native RBAC default, Cedar/others optional | Building a general policy *language* |
| Secrets | Vault (AppRole + Agent sidecar → tmpfs sink, the TaeBot pattern) | Building secret delivery |
| Authority compiler, typed edges, precedence queries | The Knowledge Lake #201 build-out (identity spine, edge graph, families, query contracts) — already built and gate-tested in the knowledgebase repo | The entire authority-basis engine |
| Memory + dreaming | The operator's claude-memory system and consolidation doctrine | A memory subsystem |
| Tool ecosystem | MCP (native protocol support, Hermes-style) | Per-tool integrations |
| Agent loop plumbing | Both upstreams' patterns; `@openclaw/agent-core` (MIT, framework-agnostic) is directly vendorable *if* the runtime component lands on TypeScript — otherwise it is the design reference, not the dependency | An agent runtime from zero |
| STIG/compliance skill domain | Security MCP server (live OAuth 2.1 + ABAC gateway — also PDP prior art) and the stig-remediation-loop gate designs | The first skill domain's content and its promotion-gate patterns |
| Deployment hardening | The TaeBot engine (idempotent phases, Makefile, bats) as the installer doctrine | Deployment tooling from zero |

### 6.3 The irreducible new work

In dependency order, matching the README roadmap: the kernel skeleton (policy-engine integration, label-schema enforcement, audit events, the six hooks); the quarantine/promotion pipeline; the skill manifest + signing format and verification gate; the gated learning loop; the authority-map onboarding wizard (CLI first — the web UI is a known time sink and comes later); one gateway channel; personas last.

### 6.4 Effort realism

**The development model, stated openly as disciplined practice:** the three team members are systems/security architects, not hands-on programmers — implementation is AI-driven under human architectural direction, through the operator's established gauntlet (spec → critical review → plan → review → TDD implementation → adversarial multi-AI review → human merge; the stig-remediation-loop is the in-house reference). This changes the effort calculus in both directions: code throughput rises sharply, and **review becomes the honest rate limiter** — every hour saved typing is spent (properly) at the spec, test, and review layers where the architects' judgment is the scarce input. The KLC's machine-readable invariants (§15) are load-bearing here: they are the acceptance suite for the AI workforce, and the TDD pattern's test volume is the mutation shield that makes delegating large segments (including to HobiBot at will) safe. Language choices double down on this model — the Rust kernel's compiler and type-encoded invariants verify AI-written code mechanically, shrinking the human review surface to the type and contract layer.

Assumptions: three architect-reviewers directing AI implementation, nights-and-weekends cadence, scope held to the roadmap, breadth deferred. Under those assumptions the honest shape is: the kernel skeleton and lake integration are a few months of part-time work precisely because the policy engine and authority engine are leveraged; the learning-loop MVP is the largest novel block; a usable single-channel MVP (kernel + lake + gated learning + CLI onboarding + one gateway) is plausibly a year-scale effort, not a quarter-scale one. The two scope killers to guard against, in order: **channel/provider breadth creep** (the upstream mass Maknae exists to not rebuild) and **the web UI before the CLI is proven**. Every phase must end in an artifact that is useful standalone — the kernel + lake instance is a governed personal knowledge system even before any persona moves in.

### 6.5 Team leverage — the hyung works on the maknae

HobiBot (the operator's OpenClaw agent) participates as directed labor with a review-and-evidence portfolio, which its ADR-0004 record already validates (it caught the D9 enum-completeness gap the fan-out missed):

- **RFC red team**: adversarial review passes on the KLC and each design doc before human team review.
- **Upstream evidence gathering**: it runs on OpenClaw natively; tasked file-level verification of claims in this document and monitoring of upstream changes that affect inheritance decisions.
- **Sample-profile drafting**: the USG "easy mode" profile and the homelab profile against the KLC §7 schema, operator-reviewed.
- **Documentation labor**: onboarding walkthroughs, diagram source, public-repo README polish.
- Kept **off** Tier 0 decisions by construction: all its output enters review as proposals; the operator signs.

## 7. Open items

1. §5/§14 terminology collision: the KLC's lifecycle-tier names ("Authority tiers," "Authoritative") now collide with the lake's authority vocabulary after the v0.2 orthogonal-axes resolution — rename candidate for team review.
2. License due diligence beyond the top-level MIT files if any code (not just concepts) is vendored: header scans, NOTICE obligations, and the Hermes model-weights question are out of scope for concept inheritance but required before vendoring.
3. Component language selection is an open decision, per layer. The multi-container architecture composes components over network/IPC contracts, so each picks the language that fits its job (kernel: Rust/Go candidates; runtime, gateway, lake tooling: undecided). Everything in §3–§4 marked "inherit" is a pattern inheritance and survives any language choice; only direct vendoring (e.g., `agent-core`) is language-conditional.
4. KLC §14 Q8 (corroboration independence) and Q9 (generation pressure) remain open for team review.
