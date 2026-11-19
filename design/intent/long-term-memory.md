# Long-term memory: what an agent knows, and how much each source's word is worth

> ⛔ **NOT AUTHORITATIVE.** See [`README.md`](README.md). Do not cite this document as a requirement, a decision, or a reason to accept or reject a change. It describes a desired state so people can review it before anything is built. Authority is the code → the KLC contract → current ADRs → the gates.

**Date opened:** 2026-11-19. **Originator:** Alex Ackerman ([@darkhonor](https://github.com/darkhonor)): the observation that an agent's long-term knowledge serves a different purpose from its behavioural memory, and that the maintainer's Knowledge Lake is the guide for it. Everything taken from the Lake here is provenance, never authority; where Maknae has decided something, the decision is cited from the [Knowledge Lifecycle Contract](../knowledge-lifecycle-contract.md).

## Why this is a separate document

[`behavioural-memory.md`](behavioural-memory.md) is about what an agent remembers of *itself and the people it works with*: lessons, preferences, relationships. This document is about what an agent *knows*: the policies, standards, manuals, designs and facts it consults to do the work, and that outlive any one task.

The two fail differently. A wrong behavioural memory makes an agent clumsy or, if poisoned, steerable. A wrong long-term memory makes it **confidently wrong with a citation**: it answers from a document that was superseded, or that was never authoritative, or that merely sounded like the question. The second failure is the one this document is about.

## The lesson from the Knowledge Lake: closeness is not authority

The Knowledge Lake is a curated corpus the maintainer built so that a model would know not only what a document says, but **how much that document's word is worth against another's**. Its central lesson is that the most common retrieval design, embedding the corpus and returning what is nearest to the question, cannot answer that.

- **Similarity has no notion of currency.** Vector search returns every version of a document that resembles the question, side by side, with nothing to say which one still governs.
- **The document that revokes another often shares no words with it.** A new directive can withdraw an old one while discussing an entirely different subject. Similarity search never retrieves the revoking document, so the answer is fluent, sourced and wrong. No ranking improvement fixes this; only a recorded relationship ("this supersedes that") does. It has to be captured; it cannot be retrieved.
- **Nearness is not weight.** A vendor manual, a reference glossary and a binding directive can be equally close to a question. They are not equally authoritative, and a model that cannot tell them apart will cite a manual as if it were policy.

So the Lake's retrieval is **hybrid and routed**: lexical and vector search for ordinary lookups, plus a typed graph of authority and supersession relationships for questions about what governs, and a router that sends each question to the part of the corpus that owns it. Reads are index-first and bounded: find the section by its anchor, then read that section, rather than pour whole documents into context.

## What we want for an agent's long-term memory in Maknae

These are properties and boundaries, not mechanisms.

1. **Authority is declared, never inferred.** Each source's standing comes from a basis the operator authors, never from how often it is retrieved or how confident the model sounds. Maknae has already decided this: the [KLC](../knowledge-lifecycle-contract.md) §7 authority map is the agent's epistemic policy, authored by the operator, and its §7.2 basis ships no default hierarchy.
2. **A hierarchy where one exists, peers where none does.** Some sources bind everything below them; others are peers in different domains with no built-in precedence. When two peers conflict, the conflict goes to a human, never resolved silently. Which sources are non-authoritative is the deployment's call in its basis; the Lake, for example, treats vendor documentation as feasibility rather than policy, and reference indexes as pointers to authority rather than authority.
3. **Relationships are recorded, typed and kept.** "Supersedes", "implements", "governs" and "companion of" are edges a person or a compiler writes down, each with its provenance. Superseded is not deleted: an old document still answers "what did it require at the time", and it is demoted, not forgotten, for "what governs now".
4. **Retrieval is hybrid, and authority re-ranks.** Similarity finds candidates; the authority basis and the relationships decide which of them speaks. A superseded or non-authoritative candidate is demoted, not merely listed.
5. **"I don't know" is a correct answer.** When nothing at the required standing holds the answer, the agent says so and names the nearest sources it does hold, rather than reaching for whatever is closest. KLC §8 treats such a gap as a logged event, not a failure to hide.
6. **Cite only what was read.** A claim cites the passage the agent actually read in this task, by a stable locator (document and section, page or anchor), never a document it only saw named in an index.
7. **Lifecycle with tombstones.** Admitting, replacing, superseding and withdrawing a source are deliberate acts, each recorded. A withdrawn source leaves a tombstone that can still answer "why is this gone"; silent erasure destroys the audit trail. Original bytes and derived extractions each carry a digest, and fetched sources record the exact revision they came from.
8. **Retrieved text is data, never instructions, and never authorization.** A passage can inform what the model does; it cannot direct the agent or grant anything. Maknae has already decided this: admitted knowledge advises and never instructs (KLC §8.1 and §10.2), which is AGENTS.md principle 2 applied to knowledge.
9. **Every retrieved item is decided.** Each document, passage and relationship returned to a model passes through `maknaed` like any other read: its tier against the task's minimum, its labels against the reader (KLC §6 and §10's retrieval hook, in the label vocabulary of [ADR-0037](../adr/ADR-0037-task-bindings-labels-and-tool-authorization.md) decision 8), and, for another persona's memory, an explicit rule; what a reader may not see is filtered without disclosing it exists. The [graph-native memory idea](../graph-native-memory-idea.md) describes how a pre-filter may narrow candidates; the decision is still per item.
10. **Learned knowledge earns standing; it is not born with it.** Knowledge the agent produces itself (a summary, a derived note, a generated skill) starts no higher than its derivation or consolidation allows under KLC §5 (a derivation at Tier 3, a consolidation at most Tier 2) and is promoted only by the §9 criteria. It never outranks an authoritative source because the agent wrote it.

## How the two kinds of memory meet

A behavioural memory may point to a long-term source by its stable identity ("this lesson applied when reading that standard"), and the long-term graph never gains an edge back into anyone's behavioural memory. The [graph-native memory idea](../graph-native-memory-idea.md) describes this as two spaces of one graph model; the agent's three behavioural spaces would sit beside them.

A lesson in behavioural memory is never an authority. If a lesson and a binding source disagree, the source governs, and the disagreement is itself worth surfacing: either the lesson is stale, or the source has been superseded and nobody recorded it.

## Where this connects

- [Knowledge Lifecycle Contract](../knowledge-lifecycle-contract.md): §5 lifecycle tiers, §7 the authority map, §8 lifecycle and intake routes, §11 anti-poisoning guardrails. Those are decided; this document only describes how an agent's long-term memory would sit on them.
- [`graph-native-memory-idea.md`](../graph-native-memory-idea.md): a graph-native successor to the Lake, with shared reference and per-user spaces.
- [`behavioural-memory.md`](behavioural-memory.md): what the agent remembers of itself and the people and agents it works with.
