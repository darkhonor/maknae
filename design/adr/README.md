# Architecture Decision Records — registry

This directory holds Maknae's ADRs (practice established by ADR-0001).

**Numbering (operator rule, 2026-08-22): an ADR is assigned a number when it is created — only then, never before.** There are no pre-reserved, "docketed," or aspirational slots. If we see the need for a decision to ensure consistent design and attention to detail, we create the ADR, assign it a number, and add it here — at that point, not ahead of it. Decisions not yet made live as tracked **issues**, not as reserved numbers.

Because this is a single-operator private project and every ADR carries its **topic in both its filename and this registry**, a number is only a stable handle — the topic is the identity. **Freed numbers are reused**: when an ADR is superseded-into-nonexistence or a former reservation is struck, its number returns to the pool and a later, unrelated decision may take it. A gap in the sequence is simply an available number.

## Allocation

| # | Decision | Status |
|---|---|---|
| 0001 | Adopt architecture decision records | Accepted |
| 0002 | Kernel is Rust | Accepted |
| 0003 | Cedar as the policy engine (leading candidate) | **Superseded by 0004** (demoted to an optional backend) |
| 0004 | Modular authorization architecture — the `maknae-security` contract and its pluggable `maknae-authz-*` backends | Accepted (operator-directed 2026-08-22) |
| 0005 | Enforcement locus & TCB boundary — split-kernel, mTLS plane transport, plane-cert identity | Accepted (finalized 2026-08-10) |
| 0006 | Client authentication (AuthN) model — sole trust-plane door; boundary-native factors (peer-cred local, OIDC remote); uniform bounded sessions; X.509 is machine identity only | Accepted (operator-ratified 2026-08-22) — **target model**; code convergence #114/#115/#116 |
| 0007 | Key & signature model (non-DCS core) | Accepted (2026-08-10) |
| 0016 | Risk-tiered test coverage — tiers, mutation, fail-closed gate | Accepted (2026-08-04) |
| 0018 | Local-plane authorization & deployment model — group+cert gate, `maknae enroll`, periodic-token continuous operation | Accepted (2026-08-11) |
| 0019 | Audit record model — AU-3-complete content now, crypto integrity/non-repudiation deferred to ADR-0007 | Accepted (2026-08-11) |
| 0020 | Access-control model & vocabulary — CNSSI 4009-aligned RBAC/ABAC over DAC/MAC, deny-overrides, no clearance bypass | Accepted (2026-08-21) |

A number not in this table is available. The registry lists **written ADRs only** — no reservations.

### Requirements tracked as issues (not reserved numbers)

Decisions we may still need, carried as issues until (if) they are authored — at which point each gets an ADR and a number then:

- storage / label-integrity model (#2)
- output-interface MLS — no-write-down on replies (#7)
- quarantine integrity-taint — "inform but not authorize" (#8)
- internal-origin lifecycle & promotion (#9)
- gateway / remote-client boundary — OIDC federation, enrolled subjects, gateway-held sessions, gateway machine identity (#117)
- subject-context envelope — max-TTL / revocation (#19)
- vendor-substrate trust locus / `untrusted-adjacent` (#20)

### Relocated (not Maknae ADRs)

The classification lattice/dominance engine and the SPIF schema (once docketed here as 0008 / 0017) moved to the external private DCS library `darkhonor/rust-dcs` and carry their own ADR numbering there — they are not slots in this table. Maknae reaches that engine only through the `maknae-security` seam (ADR-0004, `maknae-authz-dcs`).

## Authority rule: external ADRs are not authoritative here

**Operator-directed doctrine (2026-08-04):** an ADR in another project — the Knowledge Lake (`knowledgebase`), Security-MCP, Microkosmos, `rust-dcs`, or any other — is **not authoritative for Maknae**, however relevant it appears. If a decision made elsewhere matters here, **we make it here**, as a Maknae ADR, on its own merits and with its own rationale.

- External documents may be cited as **provenance or inspiration** ("informed by", "derived from") — never as the **authority** a Maknae rule rests on. Any load-bearing rule must be restated and decided in a Maknae ADR.
- **Numbering namespaces never cross projects.** The Lake has its own ADR-0004 and Security-MCP its own adr-004; `rust-dcs` has its own ADR numbering; none is Maknae's. Maknae documents must qualify any external ADR reference with its project name.
- Known citation sites that predate this rule are tracked for in-housing — see the in-housing sweep issue (#34).
