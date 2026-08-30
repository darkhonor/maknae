# ADR-0001: Adopt Architecture Decision Records

- **Status:** Accepted
- **Date:** 2026-07-14
- **Deciders:** Alex Ackerman (operator)

## Context

Maknae is built by three architects directing AI implementation, with large segments delegated (autopsy §6.4). Decisions made in conversation are lost to future contributors — human and AI — unless recorded durably with their rationale. *(Provenance, never authority: the operator's Knowledge Lake ADR practice — knowledgebase `design/adr/`, that project's ADR-0001 — informed this decision.)* That practice has shown the format keeps multi-party, multi-agent efforts aligned: agreed-to schemas, decision records, and guides are the coordination substrate.

## Decision

Architecture decisions of record live in `design/adr/`, numbered sequentially, one decision per file. Format follows the lake convention: Status / Date / Deciders / Context / Decision / Consequences, with amendments appended (append-only) rather than rewritten — a ratified ADR is point-in-time prose; live contracts (schemas, config) supersede it where they diverge, and an amendment records the divergence.

Statuses: `Proposed` (awaiting team review or a confirming spike), `Accepted` (operator- or team-ratified), `Superseded by ADR-NNNN`.

**ADRs address secure-design concerns, not preferences** (operator direction, 2026-07-14): every ADR whose decision touches the security posture includes a **Security control mapping (informative)** section citing the specific NIST SP 800-53 rev 5 controls and authoritative guidance the decision serves, framed assessor-honest — the decision *implements or strengthens* control implementations; it never "satisfies" a control by existing. An ADR that cannot name the concern it addresses is a preference and does not get written.

## Consequences

- Operator rulings from design sessions get promoted into ADRs when they are architectural (language calls, engine selections, trust-model commitments); the KLC remains the governance contract and is not duplicated into ADRs.
- New contributors (and AI agents) read `design/adr/` after the README orientation protocol; disagreement with an Accepted ADR is raised as a proposed superseding ADR, not an ad-hoc revert.

## Security control mapping (informative; added 2026-07-14 at operator direction)

The ADR practice is itself a secure-design control implementation, not project hygiene: this platform is built by architects directing AI implementation, so the decision record IS the design-rationale evidence an assessor will ask for.

| Concern | ADR practice property | NIST SP 800-53 rev 5 | Authoritative guidance |
|---|---|---|---|
| Design rationale captured and current | Numbered, dated, statused decisions with context and consequences; rationale survives contributor and session turnover | PL-8 (security architecture — including the rationale for it); SA-5 (system documentation); SA-17 (developer security architecture and design — the design spec's "why") | NIST SP 800-160 Vol 1 (systems security engineering — capturing design decisions and rationale is an engineering-process requirement, not a courtesy) |
| Disciplined change to the design baseline | Append-only amendments; supersession by new ADR, never ad-hoc revert; Proposed/Accepted gates | CM-3 (change control applied to architecture decisions); SA-10 (developer configuration management) | — |
| Assessment-ready evidence | ADRs are the primary artifact an assessor reads to reconstruct why the trust plane is shaped as it is; control mappings inline take reconstruction cost to near zero | CA-2 (control assessments — evidence quality); supports the SSP's architecture description | Operator's SCA practice: the package that explains itself assesses fastest |

Boundary on the claim: an ADR documents; it does not enforce. Enforcement lives in the KLC hooks, the CI gates, and the conformance vectors — the ADRs are why those exist in the shape they do.

## Amendment 2026-08-04 — editability clarification (landed with ADR-0016)

Clarifies (does not change) the append-only rule: the practice above scopes
append-only amendment to a **ratified** ADR ("a ratified ADR is point-in-time
prose"), and the control-mapping row's "Append-only amendments" carries the
same scope. The converse is now explicit: a **`Proposed`** ADR — not yet
ratified — is editable in place; an **`Accepted`** ADR changes only by
appended amendment such as this one.
