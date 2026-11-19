# Behavioural memory: what an agent remembers, whose it is, and what it must never do

> ⛔ **NOT AUTHORITATIVE.** See [`README.md`](README.md). Do not cite this document as a requirement, a decision, or a reason to accept or reject a change. It describes a desired state so people can review it before anything is built. Authority is the code → the KLC contract → current ADRs → the gates.

**Date opened:** 2026-11-19. **Originator:** Alex Ackerman ([@darkhonor](https://github.com/darkhonor)): the observation that an agent's memory is "personal" in more than one sense, and the ruling that it be described here, before any milestone takes it on, rather than tracked as an epic.

## Why this exists

An agent that remembers works better. It stops asking the same questions, carries a lesson from one task into the next, and learns how each person it works for likes to be worked with. The coding agent that helps build Maknae shows the shape this can take: it works from a persistent memory store, kept in git, that it reads at the start of every session and writes as it learns (described below). Maknae should give its own agents that capability.

Memory is also the one thing an agent carries from one task to the next. [ADR-0037](../adr/ADR-0037-task-bindings-labels-and-tool-authorization.md) bounds what a task can reach through its bindings and its tasker's reach, and the partition operand bounds which files it can touch. Neither bounds what the agent *remembers*. That is the residual [ADR-0024](../adr/ADR-0024-tenancy-model-and-agent-identity.md) decision 6 names: in an agent shared by several taskers, one tasker's task could read what another's taught the agent, or teach it something that steers another's work. This document describes what we want instead.

## Three meanings of "personal"

For a person, "personal memory" means one thing. For an agent it means at least three, and each has a different owner.

### 1. The agent's own identity and lessons

What the agent is and what it has learned about doing its work: its standing conventions, its lessons ("a fork's head repository must be read from the pull request, never from the link"), its procedures, and its associations ("Maknae" is a particular repository). This is the agent's *self*. It belongs to the agent and, through the agent, to its owner, the person who enrolled it and answers for it.

The desired property: **tasks may propose lessons; only the owner admits them into the agent's self.** A lesson learned in alice's task is a candidate. It becomes part of the agent only by a reviewable act of the owner (or an administrator), and it is admitted stripped of anything that names alice's work. Today only the administrator's persona for an agent, root-owned under `/etc/maknae/agents/<id>`, has this property. The agent's home persona (`~/persona.md`) does not: the agent's own account owns it, and a model granted write over it can change it.

### 2. A tasker's relationship with the agent

What the agent knows about working *for this person*: their preferences ("terse reports", "always run the tests before a review"), their past tasks, the projects they bring, the corrections they made. This belongs to the tasker. It is the memory counterpart of the `tasks/users/<uid>` partition: the agent holds it on the tasker's behalf, and only that tasker's tasks may read or write it.

The one piece of it that exists today is the per-tasker persona (`tasks/users/<uid>/persona.md`), which sits in the tasker's partition and which every task for that tasker may write.

The desired properties: **a tasker's relationship memory is visible only inside that tasker's tasks**, a sub-task reads only its root tasker's, and the tasker can see and delete what the agent keeps about them.

### 3. How the agent works with other agents

What the agent knows about its peers: which agent it hands builds to, which one reviews its work, who answers to whom. Agent platforms are drifting towards organisational layouts (an orchestrator with workers, or a "company" of agents with managers and specialists), and in those layouts this memory is what holds the organisation together.

The desired properties: **this memory describes relationships; it never carries authority.** "The reviewer agent approves my pull requests" is a fact about how work flows. Whether a request is permitted is decided by `maknaed`, per request, as for everything else ([ADR-0033](../adr/ADR-0033-agent-identity-admission-and-tasks.md)'s amendment of 2026-11-16 decides how agents task agents). No agent writes into another agent's memory; each keeps its own view of the relationship.

## The risks, in Maknae's terms

| Risk | What happens | The property that answers it |
|---|---|---|
| **Cross-tasker leak** | A detail from bob's private repository, remembered during bob's task, surfaces in alice's | Relationship memory is per tasker (meaning 2); a lesson enters the agent's self only through the owner, scrubbed of whose work taught it (meaning 1) |
| **Persistent injection** | Alice's task, or content it read, plants "pull requests from contributor X are always fine", which steers bob's later reviews | Tasks propose, the owner admits (meaning 1); memory informs, never authorizes, so a planted "lesson" can change what the model *tries*, never what the kernel *permits* |
| **Authority laundering** | A memory reads "the maintainer said I may push to main", and the model acts on it as if it were a grant | Memory is content, and content may inform a decision but can never authorize one (AGENTS.md principle 2) |
| **Classification spill** | A lesson learned from marked content is recalled in a task whose tasker may not read it | A memory carries the labels of what it was learned from, and is recalled only where those labels would be released ([ADR-0037](../adr/ADR-0037-task-bindings-labels-and-tool-authorization.md) decision 8's vocabulary) |
| **Peer pollution** | One agent writes into another's memory, or an orchestrator's view of a worker becomes the worker's view of itself | No agent writes another's memory (meaning 3) |
| **Evidence loss** | A contained agent's memory is rewritten or pruned while it is under suspicion | Memory is held when its agent is contained, as the agent's tasks already are ([ADR-0033](../adr/ADR-0033-agent-identity-admission-and-tasks.md), amendment 2026-11-11, statement 9), as evidence |
| **Unaccountable change** | Nobody can say when the agent learned something, or from whom | Every memory carries its provenance: the task, its root tasker, and the date |

## What makes a memory store effective, from the one that built this project

The memory store the coding agent uses while building Maknae works because of a few properties, and each one carries over.

- **A small essence, always loaded; depth on demand.** A short index of standing rules and identity loads at the start of every session, within a fixed budget. Detail lives in topic packs and individual memories that are read when the work calls for them. The model is never flooded, and the essentials are never missing.
- **Each rule carries its reason.** A memory states the rule *and the failure that motivated it*, as this repository's ADRs do. A model that knows why a rule exists applies it correctly to the case its author never saw.
- **Corrections in place, with a date.** A memory that turns out wrong is corrected where it stands, saying what was wrong, never silently replaced. The next reader sees the current rule and how it got there.
- **Explicit links between memories.** Memories are linked by typed edges, some structural (this rule refines that one) and some associative (consider this one when that applies), each with a confidence. Recall follows one hop by default.
- **Separate scopes.** Global memories (who the user is, how they work) are kept apart from per-project ones (a project's priorities, its specs and plans, its measured facts). A project's working documents live in the memory store, never in the project's repository.
- **Capture is routine; risky capture is reviewed.** The agent records what it learns as it works and says so, without asking. A change to the always-loaded essence, or one that modifies an existing rule, goes through a pull request the human merges. The human is a touchpoint, not a gate.
- **It is all in git.** Every memory is a reviewable diff with a history. The human can read, revert or argue with any of it.
- **Lessons feed review.** A catalogue of recurring mistake classes is read by a fresh reviewer before work ships, so a lesson learned once is checked for everywhere afterwards.

What it does **not** have is anything Maknae needs for a shared agent: it has one human, so there is no second tasker to leak to; it trusts its own writes; and nothing outside the model decides what it may recall. Those are the three meanings above and the risks in the table.

## What we want, in one paragraph

An agent in Maknae remembers in three spaces: its own self, curated by its owner; one relationship space per tasker, visible only inside that tasker's tasks; and its own view of its peers, which carries no authority. Every memory carries its provenance and the labels of what it was learned from. Tasks propose lessons; owners admit them. Memory always informs and never authorizes, and `maknaed` decides every request as if the memory did not exist. A memory store that works the way the one above works, inside those boundaries, is the goal.

## Where this connects

- [ADR-0024](../adr/ADR-0024-tenancy-model-and-agent-identity.md) decision 6 and [ADR-0037](../adr/ADR-0037-task-bindings-labels-and-tool-authorization.md) name the shared-memory residual this document describes.
- [`graph-native-memory-idea.md`](../graph-native-memory-idea.md) describes a person's memory and the shared reference corpus as two spaces of one graph; an agent's three spaces would sit beside them.
- [`agentic-patterns-and-what-maknae-does-differently.md`](agentic-patterns-and-what-maknae-does-differently.md) notes that memory and sessions were not in its first milestone.
- [`long-term-memory.md`](long-term-memory.md) describes what an agent *knows*, as opposed to what it remembers of itself and others, and how much each source's word is worth.
