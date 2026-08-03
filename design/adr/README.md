# Architecture Decision Records — registry

This directory holds Maknae's ADRs (practice established by ADR-0001). Numbers are **allocated, not sequential-by-authoring-date**: the RL#1 design review (2026-07-14, `design/reviews/`) pre-assigned a stable number to each owed decision, mapped to its review issue, so cross-references in the docket, specs, and issues stay valid regardless of the order the work lands. **A gap in the sequence is a reserved slot, not a lost number.**

## Allocation

| # | Decision | Review issue | Status |
|---|---|---|---|
| 0001 | Adopt architecture decision records | — | Accepted |
| 0002 | Kernel is Rust | — | Accepted |
| 0003 | Cedar policy engine | — | Accepted (re-decision pending D17/native-Rust pivot — see topology spec) |
| 0004 | Storage / label integrity model | docket | Proposed (docket) |
| 0005 | Enforcement locus & TCB boundary | #3 | Accepted (operator-ratified 2026-08-03) |
| 0006 | Single-source-of-truth doctrine for the corpus | docket | Proposed (docket) |
| 0007 | Key & signature model (STANAG 4778 binding) | #5 | Proposed (docket) — first among the remaining semantic ADRs |
| 0008 | Classification lattice & dominance engine | #6 | Proposed (implemented in `maknae-dcs-core`; ratification gated on EPIC #33 Day-1 marking completeness) |
| 0009 | Output-interface MLS | #7 | Proposed (docket) |
| 0010 | Quarantine taint | #8 | Deferred (moot at MVP — consumer-only lake; re-validated at constellation) |
| 0011 | Promotion | #9 | Deferred (moot until constellation) |
| 0012 | Residual-risk register | docket | Proposed (docket) |
| 0013 | Oracle independence / SELinux lane / D4-collapse remediation | #18 | Proposed (docket) |
| 0014 | Subject-context envelope (max-TTL, revocation) | docket | Proposed (docket) |
| 0015 | Vendor substrate / `untrusted-adjacent` | #20 | Proposed (docket) |

Claiming a new number: next unallocated integer, recorded here in the same commit that adds the ADR (or that reserves the slot with a `Proposed (docket)` row and its driving issue). Statuses use the ADR-0001 vocabulary: `Proposed` (awaiting team review or a confirming spike), `Accepted` (operator- or team-ratified), plus `Proposed (docket)`/`Deferred` for allocated-but-unwritten slots. A docket slot's `Proposed` is weaker than a written ADR's `Proposed`: the RL#1 docket SUGGESTED these decisions — the review generated proposed content, not validated content — and each slot's problem statement is re-validated against the current corpus when its work cycle arrives. A number is a bookmark, not a commitment; slots may be collapsed, merged, or struck at validation.

## Authority rule: external ADRs are not authoritative here

**Operator-directed doctrine (2026-08-04):** an ADR in another project — the Knowledge Lake (`knowledgebase`), Security-MCP, Microkosmos, or any other — is **not authoritative for Maknae**, however relevant it appears. If a decision made elsewhere matters here, **we make it here**, as a Maknae ADR, on its own merits and with its own rationale.

- External documents may be cited as **provenance or inspiration** ("informed by", "derived from") — never as the **authority** a Maknae rule rests on. Any load-bearing rule must be restated and decided in a Maknae ADR.
- **Numbering namespaces never cross projects.** The Lake has its own ADR-0004 (authority-line model) and Security-MCP its own adr-004 (layered enforcement); neither is Maknae's ADR-0004, and the collision is coincidental. Maknae documents must qualify any external ADR reference with its project name and must not treat it as a slot in this table.
- Known citation sites that predate this rule are tracked for in-housing — see the in-housing sweep issue (#34).
