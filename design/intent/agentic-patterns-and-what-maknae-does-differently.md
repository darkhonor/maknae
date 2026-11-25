# Agentic patterns, and what Maknae does differently

> ⛔ **NOT AUTHORITATIVE.** See [`README.md`](README.md). Do not cite this document as a requirement, a decision, or a reason to accept or reject a change. It exists so people can locate Maknae in the field and see what it does differently. Authority is the code → the KLC contract → current ADRs → the gates.

**Date opened:** 2026-09-14. **Originator:** Alex Ackerman ([@darkhonor](https://github.com/darkhonor)) — the observation that the project lacked a common framework, and the ruling that documents of this class are non-authoritative.

## Why this exists

The agentic-AI field has converged on a small vocabulary. Maknae implements most of it and refuses part of it, and until now nothing said so — so a reader could not tell whether an absence was a decision or an oversight. This document maps the industry's names onto Maknae's constructs, **names the deciding ADR and the proving gate for each**, and leaves the unfillable rows visibly empty, because those are the honest gaps.

## The field's vocabulary, and where it came from

Two independent taxonomies, from two competing labs, that agree:

| Anthropic, *Building Effective Agents* | OpenAI, *A Practical Guide to Building Agents* |
|---|---|
| prompt chaining | single-agent loop, tools added incrementally |
| routing | — |
| parallelisation | — |
| orchestrator-workers | **manager** (agents-as-tools) |
| evaluator-optimiser | — |
| agents | multi-agent |
| — | **decentralised / handoffs** (execution transfers) |

**Both lead with the same instruction: start with one agent, add tools, and escalate only when it demonstrably improves outcomes.** Two competitors arriving independently at *"don't do the complicated thing"* is the strongest evidence in the field, and it is the opposite of what popular summaries sell.

Their justification method is worth noting: Anthropic cites working with dozens of teams plus principle; OpenAI publishes guides. **Neither publishes architecture decision records.** Of the major agent platforms surveyed — OpenClaw, Hermes Agent (Nous Research), LangGraph, CrewAI, AutoGen — only [Microsoft Semantic Kernel](https://github.com/microsoft/semantic-kernel/tree/main/docs/decisions) keeps them: 73+ ADRs in MADR format, with Status, Deciders, Consulted/Informed, **Considered options**, approval captured by PR review, and explicit supersession.

## The map

Each row: the industry's name, Maknae's construct, the artifact that **decided** it, and the gate that **proves** it. An empty decision cell is an unmade decision. An empty proof cell is an unproven claim.

| Industry pattern | Maknae's construct | Decided by | Proven by |
|---|---|---|---|
| **Tool use / ReAct** | `fs.read` / `fs.write` verbs, each a decided crossing; the loop is #241 | ADR-0005 (sole PDP), ADR-0009 (subject-side fd delegation) | golden matrices; `negative-control` |
| **Routing** | `authz.yaml`'s `destinations:` — a per-**role** allowlist of `provider:<name>`, deny-by-default | #172 | `authz-composition-drift`; golden tests |
| **Parallelisation** | one connection per request; `Egress` is `Send + Sync`, so fan-out needs no demuxer and re-runs the peer check per request | #240a D2 | `egress_socket` tests |
| **Evaluator-optimiser / reflection** | **blind review as a control**, with a *grounded* oracle: gates, mutation, negative controls — never a model grading itself | core principle 6; ADR-0016 | the gate suite itself; `negative-control` proves the gates fail |
| **Orchestrator-workers / manager** | the model's `task_agent` tool: an agent gives a sub-task to another agent whose `policy.yaml` names it in `taskers:`, waits for its report, and keeps control. The task moves, never authority: a task reaches only what both its tasker and its agent can reach, a sub-task's bindings are limited to its parent's, and the partition operand bounds it by the chain's root tasker. A sub-task ends with its parent, and no agent waits on itself | ADR-0033 (`taskers:`; chain rulings 2026-11-16), ADR-0037 decision 7, ADR-0023 decision 6, ADR-0008 (partition operand) | `crates/maknae-kernel/src/task.rs` sub-task tests; `crates/maknae-kernel/tests/task_loop.rs`, `agent_daemon.rs` |
| **Guardrails** | the PDP, in a **separate process under a separate uid**, outside the runtime it guards | ADR-0005, ADR-0008 | `authz-composition-drift`; P1/P2 witnesses |
| **Prompt chaining** | deliberately **not modelled**: step and tool-call limits inside the loop are *advisory*, because a bound inside an untrusted loop cannot fail closed | ADR-0023 d7 | — (the kernel-enforced bound is the request deadline) |
| **Memory / sessions** | **not in Cooky** — no session identity; the reply returns on the prompt's response leg | ADR-0023 d7 | — |
| **Handoffs / decentralised** | **NOT MODELLED — and this is a real gap, not a decision** | — | — |

### The handoff gap, stated plainly

OpenAI's decentralised pattern **transfers control of the conversation**: the receiving agent owns it. In Maknae a task moves between agents without authority, so a transfer of control is not something a tasked agent can receive: every hop would be its own decision, and so would the return. The **manager** shape is built (`task_agent`, ADR-0033); this one is not.

OpenAI's own documentation names the sharp edge: **input guardrails apply only to the first agent in a chain, output guardrails only to the last.** Everything between runs unguarded. That is a coherent design when the guardrail lives inside the runtime and the runtime is trusted. Under Maknae's model it is the exact failure the architecture exists to prevent, and Maknae currently has nothing to say about it.

## Proposal: ephemeral sub-agents (the manager shape, without enrolling the workers)

**Status: proposal, opened 2026-11-25 by the maintainer. Not decided.** It would amend ADR-0033's chain rulings, so the decision belongs in an ADR.

**The gap.** Today an agent works one task at a time, and no agent waits on itself (ADR-0033, chain rulings 2026-11-16, rules 3 and 1). So an agent that wants help gives a sub-task to *another enrolled agent* whose `taskers:` names it. Enrolling workers puts the sizing burden on the instance owner: they must decide ahead of time how many agents the host can run at once.

**The shape wanted.** It is how coding harnesses run sub-agents. A parent agent starts a child for one piece of work, possibly on a different model. The child gets the same tools or fewer, works in a fresh conversation, reports back and ends. The parent keeps control throughout. How many children run at once follows the work and the host's capacity, not an enrollment count.

**Constraints a design must keep.**

- **A child never exceeds its parent.** It reaches only what both the task's tasker and the parent agent can reach (ADR-0037 decision 7), and the parent may narrow it further but never widen it. Narrowing is a request the kernel decides, never a grant.
- **The task moves, never authority.** The child acts on the task's intent (ADR-0037 decision 1). Nothing the parent writes into the child's task authorizes anything (inform-but-not-authorize).
- **Every request a child makes is decided in full** by the kernel, like any agent request (ADR-0037 decision 10). The partition operand bounds it by the chain's root tasker.
- **Children end with their parent** (ADR-0033 rule 1), and a child's report is written into the parent's partition before it is acknowledged (rule 5).
- **Concurrency is the kernel's, not the owner's.** How many children run at once comes from the agent's capacity share (#611), not from a count of enrolled agents. Two children writing one file, or two high-side-effect steps such as commits, never run at once (`design/plan-as-graph.md`).
- **Each child may run on a different model**, chosen from the parent's root-written set of models. The kernel admits only that set (#723). The choice is deterministic and informed by the work-type registry (#724).
- **Every child is recorded** under its parent and task: who started it, its narrowing, its model, what it did, and how it ended.

**Authorizations a design must name.**

- Who may start children at all: a term in the agent's `policy.yaml`, absent meaning no.
- The most children an agent may hold at once, and how that relates to its capacity share.
- Which models in the parent's set a child may use.
- How deep children may nest. A first cut: children may not start children.

**Identity: the open question.** Two candidates.

1. **The child runs under the parent's identity, with a narrower scope.** Same uid and plane credential, tracked by the kernel as a concurrent task of the parent. This is simple. But on one uid the OS cannot stop a child from reading the parent's credential or a sibling's files, and with the credential the child can act as its parent with full scope. The narrowing then holds only against a well-behaved child.
2. **The child has its own ephemeral identity, generated and tracked by the kernel, internal to Maknae** (preferred by the maintainer). The kernel creates an internal child identity, such as `<agent>/<child-id>`, binds a short-lived credential scoped to the child to it, decides every request under it, and retires it when the child ends. No OS account is created.
   - An internal identity separates children in the kernel's decisions, records and revocation.
   - It is a security boundary only if the child **cannot reach its parent's credential**. That needs OS separation.
   - The candidate is the same confinement ADR-0036 uses for tools: each child's loop runs in its own rootless container. Its processes run under a subordinate uid from the agent's own range, with mounts limited to the child's task directory. The kernel tracks those uids, and no real account is ever created.

**Open questions.**

- What the child's credential is: a narrowed plane certificate, or a kernel-issued capability bound to the child's connection. How it is delivered into the container without the parent being able to copy it.
- Whether the child's model call goes out through the parent's Vault identity or through a narrowed key grant.
- How the macOS path works, since ADR-0036 decision 20 records macOS tool containers as a staged gap.
- Whether this replaces ADR-0033 rule 3 ("each agent works one task at a time") for children only, or in general.

## What Maknae does differently

Three structural claims. Each is checkable; none is a matter of taste.

### 1. The guardrail is outside the thing it guards

In the SDKs surveyed, guardrails are a feature *of the agent runtime* — they execute in the same process, in parallel with the agent, and fail fast. That is real engineering and it stops real mistakes.

It also means **the guardrail's integrity depends on the integrity of the thing being guarded.** A runtime that can be steered can, in principle, be steered around its own checks.

Maknae's decision point is `maknaed`: a separate process, a separate uid, reached over a peercred-authenticated socket, holding the only credential. **The agent runtime is untrusted by design** — not distrusted after an incident, but *architecturally incapable* of being the thing that decides. That is core principle 1, ADR-0005's enforcement locus, and the P1/P2 capability-separation gates that prove the untrusted binary cannot even *link* the privileged crates.

### 2. Refusal is the normal path, not the error path

Every industry pattern diagram shows work succeeding. Boxes, arrows, a result. **Maknae's interesting behaviour is what happens when the answer is no** — and "no" is the default, since an absent grant, an absent coverage classification, an absent credential and an unknown vocabulary term all deny.

This has a consequence for how Maknae is drawn, and it is the reason this document exists alongside a diagram convention: **a picture of Maknae with no refusal path in it depicts a different system.** `design/diagrams/knowledge-lifecycle.svg` shows the correction: it was once five boxes in a straight line with **no branch and no denial anywhere**, describing the single most security-relevant flow in the product as though nothing is ever refused. It now draws three intake routes, a refusal for content above the instance ceiling, and a review hold that informs nothing.

### 3. The claim and its proof ship together

The field publishes guides. Frontier labs publish **system cards** and a **Preparedness Framework** — living documents with explicit thresholds, a named decider, and evidence released alongside the artifact. That practice is a good one and Maknae already has its pieces: risk-tiered coverage floors, a zero-missed mutation contract, an isolation contract, negative controls that prove a gate fails when it should. What it has lacked is an index that gathers them.

**The artifact class is NOT a system card**, though that was the first suggestion and it was wrong. System cards now cover agent *products* — ChatGPT agent, Operator, Deep Research all have one — but every one is a model-bearing system published by the lab that trained the model, assessed against frontier-risk categories (CBRN, cybersecurity, persuasion, model autonomy). **Maknae ships no model**; it governs whichever model an operator registers, and its risks are containment, custody and provenance. The fitting artifact is a **control-evidence index** in the shape of a NIST SP 800-18 system security plan or a Common Criteria security target: per claimed control, what implements it, what proves it, and what is not yet established. Maknae already cites the controls (SC-13, AU-3, AU-5, AC-12, SC-10, ASD STIG APSC-DV-001860) and already produces the evidence; what is missing is the index.

**That index would not belong in this directory.** Assembled from gate output it is *derived*, not intent, and should be **generated** with `check_evidence` refusing a control row whose citation does not resolve — authoritative precisely because it is computed. Scoping it is the maintainer's.

## What we want these diagrams to show

**Descriptive, not a rule — reworded 2026-09-14 on review.** This section previously called
itself a *"diagram contract"* and said a diagram was *"not acceptable unless"* it satisfied five
mandatory criteria. That is an acceptance rule, and an acceptance rule cannot live in a directory
whose own banner says nothing here may be cited as a reason to accept or reject a change. The
contradiction was the finding; the wording below is the fix. **Nothing here gates anything.** If
these turn out to be worth enforcing, they belong in `design/diagrams/README.md` or an ADR, and
ratifying them there is the maintainer's call.

What we have found makes a desired-state or pattern diagram *useful*, and what tends to be missing
when one is not:

1. **The trust boundary, drawn** — a reader cannot see which side is untrusted unless the diagram
   says so.
2. **Every crossing, labelled with the verb that carries it.** An unlabelled arrow leaves the
   reader guessing at the mechanism.
3. **The deny path for each crossing.** This is the one the field's diagrams almost always omit,
   and it is the one that distinguishes Maknae — a crossing drawn without its refusal tells half
   the story.
4. **What is recorded** — a crossing that produces no audit record reads very differently from one
   that does, and the picture should not flatten them together.
5. **Provenance for desired elements** — naming the ADR or ruling behind a *desired* element is
   what separates a plan from someone's assumption.

UML 2.5.1 **activity diagrams with partitions** (§15.6) suit this well and are already in the
catalog's conformance table: a partition means *"who performs this action"*, which is precisely the
trust question. Nothing new needs inventing.

**Desired-state views carry this document's banner**, and the reason is the distinction this whole directory turns on: the derived catalog is generated from the repository and is evidence, whereas a desired-state view is intent. What follows from that is stated once, in [`README.md`](README.md), and is not restated as a rule here — a non-authoritative document repeating a directive in its own voice is how the contradiction this section already had to fix gets reintroduced.

## Sources

- Anthropic, *Building Effective Agents* — https://www.anthropic.com/engineering/building-effective-agents
- OpenAI, *A Practical Guide to Building Agents* — https://openai.com/business/guides-and-resources/a-practical-guide-to-building-ai-agents/
- OpenAI Agents SDK (agents, tools, handoffs, guardrails) — https://openai.github.io/openai-agents-python/
- OpenAI Preparedness Framework — https://openai.com/index/updating-our-preparedness-framework/
- Microsoft Semantic Kernel ADRs (MADR) — https://github.com/microsoft/semantic-kernel/tree/main/docs/decisions
- OpenClaw — https://github.com/openclaw/openclaw
- Hermes Agent (Nous Research) documentation — https://github.com/mudrii/hermes-agent-docs
