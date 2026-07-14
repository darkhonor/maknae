# ADR-0001: Adopt Architecture Decision Records

- **Status:** Accepted
- **Date:** 2026-07-14
- **Deciders:** Alex Ackerman (operator)

## Context

Maknae is built by three architects directing AI implementation, with large segments delegated (autopsy §6.4). Decisions made in conversation are lost to future contributors — human and AI — unless recorded durably with their rationale. The Knowledge Lake's ADR practice (knowledgebase `design/adr/`, ADR-0001) has proven the format keeps multi-party, multi-agent efforts aligned: agreed-to schemas, decision records, and guides are the coordination substrate.

## Decision

Architecture decisions of record live in `design/adr/`, numbered sequentially, one decision per file. Format follows the lake convention: Status / Date / Deciders / Context / Decision / Consequences, with amendments appended (append-only) rather than rewritten — a ratified ADR is point-in-time prose; live contracts (schemas, config) supersede it where they diverge, and an amendment records the divergence.

Statuses: `Proposed` (awaiting team review or a confirming spike), `Accepted` (operator- or team-ratified), `Superseded by ADR-NNNN`.

## Consequences

- Operator rulings from design sessions get promoted into ADRs when they are architectural (language calls, engine selections, trust-model commitments); the KLC remains the governance contract and is not duplicated into ADRs.
- New contributors (and AI agents) read `design/adr/` after the README orientation protocol; disagreement with an Accepted ADR is raised as a proposed superseding ADR, not an ad-hoc revert.
