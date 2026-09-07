# ADR-0023: Maknae's runtime loop is the ACP Agent and the kernel is the Client — a Rust loop on the untrusted side, model egress brokered by the trust plane

- **Status:** Proposed (operator-directed 2026-09-07, issue #239; milestone Cooky, epic Begin #244)
- **Date:** 2026-09-07
- **Deciders:** Alex Ackerman (operator)

## Context

Everything the kernel decides is, today, decided on behalf of a subject that types `maknae read` at a shell. #238 gave the kernel its first mutating verbs and the README described them as "filesystem development commands" — a human tutorial. The operator's question that produced this ADR (2026-09-07): *"How does giving the CLI these commands help a user using Maknae with an LLM as an agentic platform?"* The honest answer was that it does not, yet: the vocabulary is the kernel half of an agent's tools, and the agent — the loop that orchestrates a model and executes its tool calls — has no code and no line on the roadmap. The operational goal has always been what OpenClaw and Hermes Agent *are* ([reference-implementation-autopsy](../reference-implementation-autopsy.md)): an agent, with the one structural inversion that its tools do not touch the OS. **Cooky's MVP is that agent, minimal: configure a model with an OpenAI-compatible endpoint and key, and function as an agent** (operator direction, 2026-09-07).

Three questions had no recorded answer and would otherwise be settled by whoever wrote the first loop:

1. **Which ACP role is the loop?** The [ACP assessment](../references/2026-08-28-acp-protocol-assessment.md) §2 rules that Maknae is the **Client** — the host that provides `fs.*` and decides every call. It did not say who the Agent is, because at the time the answer could have been "any conforming ACP Agent". §5 recorded the trust-model divergence: ACP v2 assumes the Agent is trusted to execute; Maknae's core principle 1 holds the agent runtime untrusted.
2. **Where does the loop run, in what language?** [container-architecture](../container-architecture.md) §3.4 proposes a Python `runtime` container — *proposed*, never ratified — for velocity reasons that assume a broad LLM/MCP SDK footprint the MVP does not need.
3. **Who makes the model call?** `maknae-llm`'s stub says "maknaed-linked; egress terminates there"; `session.prompt`'s doc in `wire.rs` says "send content to an agent runtime … toward a model endpoint", which conflates the user→loop hop with the loop→model hop; and #172 specifies `session.prompt` as write-ahead egress whose destination is a provider from #153/#169.

A wrong first answer to any of these is expensive: a loop that holds the key, or a loop the kernel does not stand between and the model, is OpenClaw with a nicer README.

## Decision

### 1. Maknae ships its OWN agent. It is the ACP Agent; the trust plane is the ACP Client.

The loop is Maknae's runtime in the ACP **Agent** role — the process that holds a conversation, presents tools to the model, and executes the model's tool calls. The kernel is the ACP **Client** — the host that provides every capability the Agent uses and decides every use. This is not a third-party Agent plugged into a Maknae host; it is Maknae, and the OpenClaw/Hermes operational goal stated in the project's own protocol vocabulary. A conforming external Agent remains possible later (the assessment's positioning consequence stands); it is not what Cooky builds.

### 2. The loop is UNTRUSTED and holds no key, no policy and no durable state.

Core principle 1 and container-architecture §1.3 and §1.5, applied without exception: the loop runs with the **subject's uid**, on the untrusted side of the plane socket, and reaches the kernel only through `maknae-plane`'s client. It never sees the provider credential. Its transcript is in-memory for the life of one run (a "working set", §1.5); the kernel's audit trail is the durable record. The session model that would let a conversation outlive a process is Velveteen's, not Cooky's.

### 3. The model call is a capability the trust plane provides to the Agent — brokered egress, decided per turn.

Because the Agent is untrusted and holds no key, it cannot make the model call itself. It asks the kernel to: each turn, the loop sends **`session.prompt`** with the messages and the tool schemas; the kernel decides (the grant, the subject, the destination — #172's contract), appends the write-ahead record, calls the provider through `maknae-llm` (egress terminates in `maknaed`, as the crate's design says), records the outcome, and returns the model's reply — text or tool calls — as the response payload. **This is the ACP v2 divergence in §5 of the assessment, made concrete:** the Agent does not execute the egress; the Client does, on the Agent's request, under a verdict. `session.prompt` therefore has one destination in Cooky, the registered provider (#243), and one issuer, the loop.

*Corrected in place, dated 2026-09-07:* `session.prompt`'s doc in `wire.rs` reads "send content to an agent runtime … toward a model endpoint". The hop it governs is the **loop → model** hop. The user → loop hop is inside one untrusted process in Cooky (the user types to the loop); the interaction plane that will one day stand between a user and the loop is the gateway (Spinebreaker), and its verbs are its own.

### 4. Tool calls are executed by the Agent as the subject, through the kernel's verbs — never by the kernel on the Agent's behalf.

When the model asks for `read_file`, the loop sends **`fs.read`** the way the CLI does today (the subject opens, the descriptor is delegated, the kernel verifies the object and decides — ADR-0009). When it asks for `write_file`, the loop sends **`fs.write`** the way #238 shipped it (durable intent, subject-side execution, client-reported outcome). Tool results are **verdict-shaped**: a refusal reaches the model as a refusal carrying the audit reason's closed-vocabulary text; an incomplete client-reported outcome reaches the model as incomplete and the loop does not retry uncertain work. The model's text can never authorize anything (core principle 2): it can only ask, and every ask is a request the kernel decides.

### 5. The MVP loop is Rust, a subcommand of the existing untrusted binary: `maknae agent`.

Operator ruling 2026-09-07. The reasons, recorded so the decision can be revisited on evidence rather than taste:

- **Every client-side piece already exists in Rust** — the plane connector, mTLS, the CBOR frames, descriptor delegation, the subject-side write path. A Python loop would have to reimplement the plane client before it could send its first verb; a Rust loop reuses `bins/maknae`'s.
- **The packaging surface does not grow.** `maknae` is already the unprivileged binary in [`packaging/isolation-contract.md`](../../packaging/isolation-contract.md)'s matrix; a subcommand adds no row, no image, no SELinux domain. The Python `runtime` container of §3.4 would add all three before the first conversation.
- **The loop's guarantees are not load-bearing** (§1.3), so Rust is not chosen for safety here; it is chosen because it is the shortest path to a measured MVP with the project's existing gates (tiers, mutants, drift) applying unchanged.

**What this does not decide:** the language of the *eventual* runtime container. §3.4's Python rationale — SDK breadth, learning-loop concepts from Hermes — is about capabilities Cooky does not build (MCP client integrations, gap detection, dreaming). That decision is **re-taken on evidence after Cooky**, and the evidence that would move it is named: the first capability whose implementation cost in Rust exceeds the cost of a Python plane client plus a second packaging surface. §3.4 carries a dated note pointing here.

### 6. Exactly two tools, in order: `read_file` first, then `write_file`.

Operator ruling 2026-09-07. `read_file` → `fs.read`; `write_file` → `fs.write`. `fs.delete` and `fs.mkdir` exist in the kernel and are deliberately **not** presented to the model in Cooky: the demonstration is "reads a file, changes a file, answers", and every additional tool is additional attack surface a review must cover. Presenting a tool the kernel does not decide is impossible by construction — the loop has no other way to touch the filesystem.

### 7. Bounds are configuration, fail closed, and belong to the kernel's side where they can be enforced.

Steps per prompt, tool calls per step, and the egress deadline are YAML configuration (ADR-0005 decision 8). The egress deadline is enforced in `maknaed` (#172 item 6: bounded, non-blocking, **no automatic retry** — a retried egress that already landed is a duplicate disclosure). The step and tool-call bounds are enforced in the loop *and* observable in the trail (every turn is a `session.prompt` record), so a loop that ignored its bound would be visible, not merely wrong.

### 8. What Cooky deliberately does not answer

- **#209** — the model as an untrusted caller: what Maknae bounds structurally and what it cannot. This ADR assumes the model is adversarial and lets the kernel decide every ask; it does not claim that is containment.
- **#147** — destination governance beyond the single registered provider; the `egress-proxy` container stays proposed, and the MVP's destination check is "the registered provider" inside `maknaed`. The trigger to revisit: a second destination of any kind.
- **#151** — MCP tools presented to the model; **Velveteen** — sessions that outlive a process; **Spinebreaker** — a user reaching the loop from anywhere but the local shell.
- **#153's remainder** — several providers, per-user model configuration, capability differences (vision, audio, embeddings), OAuth subscription mode. The MVP registers one OpenAI-compatible endpoint (#243).

## Consequences

- **Cooky's shape follows directly:** #243 (one provider, key via Vault) → #169 and #172 (the verbs) → #240 (`maknae-llm` gets a body: chat completions with tool calling, called only from the `session.prompt` path) → #241 (`maknae agent`) → #242 (acceptance: hermetic end-to-end against a stub provider in CI on both lanes, plus an operator-run conversation with a real key on macOS and Rocky; the audit trail — boot composition record, `session.prompt` write-ahead pair per turn, `fs.read` verdict, `fs.write` intent and outcome — is the artifact).
- **The README roadmap gains the runtime milestone** (it currently jumps from the kernel to the lake), and the "Filesystem development commands" section is reframed as what it is: the kernel half of the agent's file tools, with the CLI as the reference subject-side executor.
- **`session.prompt`'s wire doc is corrected in place** (decision 3); no wire shape changes and `PROTOCOL_VERSION` is untouched.
- **Supersedes, in place and dated:** container-architecture §3.4's "Python" for the MVP loop only (the container-level decision is deferred, not reversed); the framing, offered and withdrawn in discussion on 2026-09-07, that the loop's tool surface should be an MCP server.

## References

- [ACP assessment](../references/2026-08-28-acp-protocol-assessment.md) §2 (Maknae is the Client), §5 (the trust-model divergence this ADR makes concrete). [container-architecture](../container-architecture.md) §1 principles 3 and 5, §3.4. [reference-implementation-autopsy](../reference-implementation-autopsy.md) — the operational goal.
- [ADR-0005](ADR-0005-enforcement-locus-tcb-boundary.md) (sole PDP; configuration is YAML). [ADR-0009](ADR-0009-subject-side-os-dac-evaluation.md) (the read path the loop's `read_file` uses). [ADR-0008](ADR-0008-authorization-composition-contract.md) and [ADR-0022](ADR-0022-classification-policy-as-data.md) (every ask is decided by the composition). [ADR-0019](ADR-0019-audit-record-model.md) (write-ahead for `session.prompt`).
- Issues: #239 (this ADR), #244 (epic Begin), #172, #169, #153, #243, #240, #241, #242; #209, #147, #151 (not answered here).
