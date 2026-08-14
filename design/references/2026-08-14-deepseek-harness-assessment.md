# DeepSeek Harness — External Framework Assessment

| | |
|---|---|
| **Status** | Assessment record — informs roadmap (ACP), config design, and the integrity-taint docket |
| **Date** | 2026-08-14 |
| **Subject** | [`deepseek-ai/deepseek-harness`](https://github.com/deepseek-ai/deepseek-harness) (`dsh`) — TypeScript agent harness, MIT, ~40k★, developer preview |
| **Method** | **Read-only** survey via the GitHub REST API only (repo metadata, README, `docs/architecture.md`, `packages/guard/README.md`, `packages/acp/README.md`, and the `.agents/notes/` decision log entries cited below). **No clone, no `npm`/`pnpm` install, no dependency pull, no code execution** — see §1. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |

## 1. Provenance caveat (load-bearing — read first)

DeepSeek is a **PRC-origin** vendor (`deepseek-ai`). For a DoD-context, security-first platform this governs everything below:

- **Their code and dependencies are a supply-chain non-starter for Maknae**, MIT license notwithstanding. `@deepseek-ai/dsh`, the [Cordis](https://github.com/cordiverse/cordis) framework it is built on, and its ~50 workspace packages are foreign-origin dependencies squarely inside SCRM scope. **None of it enters Maknae's dependency tree**, and `npx @deepseek-ai/dsh …` (which executes their code, homepage `deepseek.com`) is not run on any sensitive host. The licensing is permissive; the *provenance* is the bar, and it forecloses code reuse independent of license — a deliberate contrast with the OpenClaw/Hermes autopsy, where MIT reuse *was* on the table.
- **Ideas and published design patterns are safe to learn from.** An architecture document is not a dependency. This assessment was conducted entirely by reading published docs read-only, precisely to keep the interaction at the "learn from the design" boundary and never at "adopt the artifact."

This record exists so we do not re-run this evaluation from scratch, and so the provenance disposition is not silently re-litigated.

## 2. Where the three frameworks actually differ

| | Center of gravity |
|---|---|
| **OpenClaw** | Breadth of **channels** (20+ messaging platforms) + native mobile/voice/Canvas; single-user, local-first; "the gateway is just the control plane." |
| **Hermes** | The **learning loop** — skills-from-experience, memory nudges, FTS5 session search, Honcho user-modeling; serverless-persistence terminal backends. |
| **DeepSeek Harness** | The **architecture itself**, not user features: a Cordis dependency-injection plugin tree where *everything is a plugin* — model adapter, tool registry, session log, and **the agent loop itself**. *"There is no privileged core to patch."* Runtime composition is layered **profiles/bundles**, patchable top-down, with reversible registrations that unwind on plugin unload. |

## 3. Findings and dispositions

**3.1 ACP (Agent Client Protocol) — ADOPT (as an open standard, evaluate the spec, not their code).**
`dsh` exposes agents over ACP (`packages/acp`, `subagent-acp`); Hermes also implements it (`acp_adapter`/`acp_registry`); OpenClaw does not obviously. ACP is an **open interoperability standard**, so aligning to it sidesteps the provenance concern entirely — we evaluate the published spec, not DeepSeek's implementation. **Disposition:** adopt ACP as the basis for the gateway / verb-vocabulary work and the subagent interop model, so Maknae is interoperable and community-adoptable rather than bespoke. *Team decision, 2026-08-14: concur — issue #67 updated to target the ACP spec.*

**3.2 `--dump-config` (effective composed-config introspection) — ADOPT AS IDEA, with a hard security requirement.**
`dsh --dump-config` prints the fully-composed effective config tree. This is genuinely valuable for Maknae **because our YAML config composes from multiple files** (`core`/`vault`/`audit`/`principal`/`authz` + `config.d/` layering), and an operator otherwise cannot see the effective merged result. **Requirement (team decision, 2026-08-14; tracked as issue #86):** in Maknae this MUST be a **privileged, authenticated, audited operation**, not an open CLI verb — a full effective-config dump exposes the complete security posture and potentially sensitive composed values, so it is gated the same way as other privileged operations (authenticated principal + AU-3 audit of the dump event + a redaction policy for secret-bearing values). Not an anonymous convenience command; unauthenticated invocation fails closed.

**3.3 The Cordis "no privileged core" composability model — DO NOT ADOPT in the trust plane; record as a validating contrast.**
"Hot-swap any part, including the agent loop, from config" is the **opposite** of a fail-closed TCB — a dynamically patchable core is attack surface, and reversible-from-config registration undermines a static trusted computing base. Maknae's static Rust microkernel with compile-time capability isolation and a reference monitor is a deliberate rejection of exactly this. **Disposition:** their design is a clean articulation of *why* Maknae's trust plane stays static; the non-privileged interaction plane could borrow a plugin model, the trust plane must not. Useful as a documented threat-model contrast, not a template.

**3.4 `guard` — NOT an authorization model (avoids a naming trap).**
`packages/guard` is **loop-hygiene** (repeat-tool reminders, per-call timeout budgets), *not* access control. There is **no authorization/PDP pattern to borrow** there for Maknae's DAC-enforcement gaps (#77/#85), despite the suggestive name. Recorded so a future reader does not chase it.

**3.5 Context injection — they do NOT defend against it; this validates Maknae's structural approach.**
This is the most security-relevant finding. DeepSeek's own decision notes:

- `.agents/notes/implemented/simplification/2026-07-20-unwrap-injected-content-envelopes.md` **removed** the `<steering>`/`<context source=…>` envelopes that marked injected content as not-the-user. Their stated reasoning: *"No model is trained on these tags… the framing adds tokens without a reliable effect and can actively mislead."* Decision, verbatim: *"Injected session content projects verbatim; the caller owns any framing… Mid-turn steering and injected context reach the model with the same weight as an ordinary user prompt. The transcript no longer distinguishes injected content from a user message."* Attribution (`source`) is kept in the durable log but **does not render to the model.**
- Tellingly, the *bug they were fixing* was a transcript where **"the model refused steering as third-party metadata"** — i.e., the model correctly treated injected content as untrusted, and they classified that as a failure mode to eliminate. They *wanted* the injected instruction followed. That is the inverse of a fail-closed integrity posture.
- What they actually rely on is downstream and human-in-the-loop: an **approval seam** for tool execution (`approval-seam`, `web-permission-and-approval`, `gui-full-access-confirmation`, `subagent-approval-pinned-never`) and **UI disclosure** of injected context (`web-context-injection-disclosure`). These gate *consequences* and give the *human* visibility; neither prevents the model from being steered. (Characterized from the note titles + `docs/architecture.md`; the approval-seam and `api-browser-trust-boundary` implementations were **not** read.)

**Lesson for Maknae (reinforces the RL#1 docket — #7/#8/#9):** a prompt-level "this is untrusted" marker must **never** be a control. If injected / tool / retrieved content can reach the model, the guarantee that it cannot *authorize* anything must be enforced **structurally** — in the reference monitor, the capability boundaries, and "inform-but-not-authorize" — because the model will treat that content as user-weight input, exactly as `dsh` now deliberately does. DeepSeek's engineering is field evidence for the threat Maknae's integrity-taint architecture is designed to survive.

## 4. Scope and limits of this assessment (honesty)

Read in full: repo metadata, README, `docs/architecture.md`, `packages/guard/README.md`, `packages/acp/README.md`, and the two content-injection decision notes (§3.5). Read at title/structure level only: the `identity`/`credentials`/`sandbox` package internals, the approval-seam and `api-browser-trust-boundary` implementations, and the Cordis framework itself. **No implementation audit and no security audit was performed**, and none is planned — the provenance disposition (§1) makes a deeper code audit unwarranted. Conclusions above are drawn from published design docs, not from verified runtime behavior.
