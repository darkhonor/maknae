# `design/intent/` — documents for humans, never for authority

> # ⛔ NOTHING IN THIS DIRECTORY IS AUTHORITATIVE
>
> **Do not cite any document here as a requirement, a decision, an approval, or a reason to accept or reject a change.** These documents exist so that people can communicate and understand *intent* — goals, objectives, desired states, and how Maknae relates to the wider field. They state what we are trying to build and why it is different. They do not state what is true.
>
> **Authority lives elsewhere, in this order** (the [`AGENTS.md`](../../AGENTS.md) currency guard): **the code → the [Knowledge Lifecycle Contract](../knowledge-lifecycle-contract.md) → current [ADRs](../adr/) → everything else.** The gates decide whether something ships.
>
> **If a document here disagrees with any of those, this document is wrong.** Fix it or flag it; never follow it.

## Why the directory exists at all

The maintainer's rule, 2026-09-14, and it is the whole reason for the banner above:

> *"for reviewers to quote goals and objectives as authoritative is an easy guardrail to the reviewer: ignore this set of documents. They are for humans to communicate and understand."*

The failure it prevents is specific and has happened in this repository. A reviewer — human or agent — reads a document describing a *desired* state, reasonably mistakes it for a *decided* one, and blocks or demands work on the strength of an aspiration. The register already separates ratified ADRs from open-discussion notes; this directory makes the third category explicit, so the rule a reviewer needs is one sentence long: **the path says `intent/`, so it is not evidence.**

## What belongs here

- **Desired-state descriptions** — where a subsystem is going, before an ADR decides it.
- **Orientation documents** — how Maknae relates to the wider field, what it does differently, and why.
- **System cards** — the per-milestone evidence summary, assembled from artifacts that *are* authoritative, and clearly marking what is not yet established.

## What does NOT belong here

- Anything a gate reads. A document a gate parses is a contract, not intent.
- Anything asserting a mechanism for something unbuilt. That is the [ADR-0023](../adr/ADR-0023-runtime-loop-role-and-placement.md) lesson: *an ADR states decisions and properties; mechanisms for unbuilt things belong in their issues*. Intent documents state **properties and boundaries**, never mechanisms.
- Decisions. If it decides, it is an ADR.

## The one exception to non-authority

A **system card** may *quote* authoritative evidence — a gate's output, a coverage floor, a mutation result — and that quotation carries exactly the authority of its source, no more. The card is a cover page over evidence, not evidence. **A quotation that cannot be traced to a gate, an ADR, or a measured run does not belong in a card.**
