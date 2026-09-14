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
| **Orchestrator-workers / manager** | *delegation transmits intent, never authority* — the child is decided as if the user typed the task, on its own conduit; the return hop is a release decision | **candidate only** — `model-conduit-policy.md` Q11, explicitly not ratified | — |
| **Guardrails** | the PDP, in a **separate process under a separate uid**, outside the runtime it guards | ADR-0005, ADR-0008 | `authz-composition-drift`; P1/P2 witnesses |
| **Prompt chaining** | deliberately **not modelled**: step and tool-call limits inside the loop are *advisory*, because a bound inside an untrusted loop cannot fail closed | ADR-0023 d7 | — (the kernel-enforced bound is the request deadline) |
| **Memory / sessions** | **not in Cooky** — no session identity; the reply returns on the prompt's response leg | ADR-0023 d7 | — |
| **Handoffs / decentralised** | **NOT MODELLED — and this is a real gap, not a decision** | — | — |

### The handoff gap, stated plainly

OpenAI's decentralised pattern **transfers control of the conversation**: the receiving agent owns it. Under *delegation transmits intent, never authority*, that is not delegation — it is a release decision on every hop, and the return is another. `model-conduit-policy.md` Q11 covers the **manager** shape and does not obviously cover this one.

OpenAI's own documentation names the sharp edge: **input guardrails apply only to the first agent in a chain, output guardrails only to the last.** Everything between runs unguarded. That is a coherent design when the guardrail lives inside the runtime and the runtime is trusted. Under Maknae's model it is the exact failure the architecture exists to prevent, and Maknae currently has nothing to say about it.

## What Maknae does differently

Three structural claims. Each is checkable; none is a matter of taste.

### 1. The guardrail is outside the thing it guards

In the SDKs surveyed, guardrails are a feature *of the agent runtime* — they execute in the same process, in parallel with the agent, and fail fast. That is real engineering and it stops real mistakes.

It also means **the guardrail's integrity depends on the integrity of the thing being guarded.** A runtime that can be steered can, in principle, be steered around its own checks.

Maknae's decision point is `maknaed`: a separate process, a separate uid, reached over a peercred-authenticated socket, holding the only credential. **The agent runtime is untrusted by design** — not distrusted after an incident, but *architecturally incapable* of being the thing that decides. That is core principle 1, ADR-0005's enforcement locus, and the P1/P2 capability-separation gates that prove the untrusted binary cannot even *link* the privileged crates.

### 2. Refusal is the normal path, not the error path

Every industry pattern diagram shows work succeeding. Boxes, arrows, a result. **Maknae's interesting behaviour is what happens when the answer is no** — and "no" is the default, since an absent grant, an absent coverage classification, an absent credential and an unknown vocabulary term all deny.

This has a consequence for how Maknae is drawn, and it is the reason this document exists alongside a diagram convention: **a picture of Maknae with no refusal path in it depicts a different system.** `design/diagrams/knowledge-lifecycle.svg` is the worked example of the problem — five boxes in a straight line, *task gap → authorized fetch → quarantine → consolidation → trusted retrieval*, with **no branch and no denial anywhere** — describing the single most security-relevant flow in the product as though nothing is ever refused.

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
