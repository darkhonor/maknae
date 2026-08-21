# ADR-0020: Access-control model & vocabulary — CNSSI 4009-aligned RBAC/ABAC over DAC/MAC, deny-overrides composition, no clearance bypass

- **Status:** Accepted (operator-ratified 2026-08-21; lands via PR #107)
- **Date:** 2026-08-21
- **Deciders:** Alex Ackerman (operator)

> **Amendment (2026-08-22, via [ADR-0004](ADR-0004-modular-authorization-architecture.md) — Accepted).** Where the Scope boundary and References below defer engine selection to "the Cedar spike, ADR-0003," read that as **ADR-0004**: the concrete authorization architecture is the policy-agnostic `maknae-security` seam with pluggable `maknae-authz-*` backends, which *realize* this ADR's RBAC/ABAC vocabulary and deny-overrides composition. Cedar is one *optional* backend (`maknae-authz-cedar`), not a pending spike; ADR-0003 is superseded.

## Context

Maknae's documentation and code have used the terms *DAC*, *MAC*, *RBAC*, *ABAC*, and *DCS* loosely and inconsistently. The cost has been real and recurring: the README described a "Data-Centric Security" design extension the code had already externalized; a refresh over-corrected to "a generic **DAC** access policy," conflating the code's operand name (`DAC`, the `Read`/`Bash` capability grammar in `maknae-config/authz.rs`) with traditional OS file-permission DAC; and reviewers repeatedly flagged apparent contradictions that were really vocabulary drift. A single authoritative vocabulary is needed before the docs harden around the wrong words.

Maknae targets **NSS Classified Information Overlay** accreditation (CNSSI 1253), so the authoritative glossary is **CNSSI 4009**. Per the registry's authority rule (ADR-0001; operator doctrine 2026-08-04), an external glossary is **provenance, not authority**: we cite CNSSI 4009 and NIST, and we **decide the model here**.

CNSSI 4009 (sourcing NIST SP 800-53 Rev 5 for DAC/MAC/RBAC and NIST SP 800-162 for ABAC) fixes four terms across **two orthogonal axes**:

- **Policy-type axis — DAC vs MAC.** *DAC*: a subject granted access **may re-delegate** it — pass information on, grant its privileges, change security attributes, or change the access rules (subject discretion). *MAC*: **uniformly enforced**; a subject is **constrained from** re-delegating, and it "is considered a type of **nondiscretionary** access control." Trusted subjects *may* be exempted from some constraints.
- **Decision-model axis — RBAC vs ABAC.** *RBAC*: access authorizations keyed to **roles**. *ABAC*: decisions from **assigned attributes of the subject and object, environment conditions, and attribute-expressed policy** — of which role is one attribute.

These axes are independent: a control can be role-based *and* discretionary, or attribute-based *and* mandatory. Conflating them is the root cause of the drift above.

## Decision

1. **Adopt the CNSSI 4009 definitions** (condensed above; the source is authoritative for the full text) as Maknae's binding vocabulary for DAC, MAC, RBAC, and ABAC, understood as the two orthogonal axes above. All Maknae docs and code comments use the terms only in this sense.

2. **ABAC is Maknae's unifying decision model; RBAC is its role-only degenerate case.** ABAC is not ignorant of roles — role is one required attribute, and ABAC *enriches* the policy with the additional required attributes (clearance, classification, releasability, need-to-know, environment) so appropriate access is enforced throughout. The in-repo default backend **`maknae-authz-basic`** provides RBAC; the optional **`maknae-authz-dcs`** backend (the external private DCS library, reached through the authorization seam) provides full ABAC. Both implement the object-safe `Authorizer` trait defined by `maknae-security` (the seam; spec §13). A non-DCS build (RBAC only) is a first-class configuration.

3. **The reference monitor composes operands deny-overrides, and mandatory constraints are never waivable by a discretionary permit.** `maknae-security/compose.rs::combine` is the authority: any `Deny` → `Deny`; any `Indeterminate` → `Deny` (never masked by a peer `Permit`); a `Permit` requires that **no** operand `Deny` or is `Indeterminate` (`NotApplicable` operands are identity — dropped). Mandatory (MAC) operands — classification/clearance and SELinux — are always composed, and a discretionary (DAC/RBAC) `Permit` can **never** override a mandatory `Deny`. This is the precedence rule of **NIST AC-3(3)** (its discussion: *"mandatory access control policies take precedence over the less rigorous constraints of AC-3(4)"*); enforcing a mandatory *and* a discretionary policy **simultaneously** is **AC-3(15)**, which this composition also satisfies. For this to hold, a mandatory operand is **constraint-only and fails closed**: it returns `Deny` when clearance is absent or insufficient, and otherwise `NotApplicable` — it **never** returns `Permit` (granting is the discretionary layer's job). Otherwise a discretionary `Permit` could compose through a missing operand, or a mandatory `Permit` could turn a default-deny `NotApplicable` into `Permit`. Every mandatory `Authorizer` backend must guarantee this; `combine` alone cannot (its `Vec<Verdict>` cannot even ensure a mandatory operand was included).

4. **No clearance bypass for any subject — administrative role and TCB/kernel privilege grant management authority, not read-up.** Maknae **declines** the CNSSI 4009 MAC "trusted subject" exemption *for clearance*: an "Admin" is constrained from information they are not cleared for, and the all-seeing kernel is itself constrained — it enforces policy but holds no clearance-bypass. The deny-overrides composition of (3) makes this structural *once a mandatory `Deny` is present*; that a mandatory operand is always composed and is constraint-only/fail-closed are the backend/kernel construction invariants (held by the acceptance tests) that complete it — not convention.

5. **Name the layered controls precisely** (each mapped to its enforcement locus and owning ADR):

   | Control | Axis | Locus | Code / ADR |
   |---|---|---|---|
   | Capability policy (`Read`/`Bash` grants) | **DAC**, decided by **RBAC** default | trust plane (PDP) | `maknae-config/authz.rs` operand `DAC`; `maknae-authz-basic` |
   | Classification / clearance | **MAC**, decided by **ABAC** | trust plane (PDP), external engine | `DCS_MAC`; `maknae-authz-dcs` (external, ADR-0008/0017 relocated) |
   | SELinux type enforcement | **MAC** | OS | `OS_MAC` |
   | File permissions / ownership | **DAC** | OS | OS-enforced (not an `Authorizer` operand) |
   | Hardware root of trust | *not access control* — trust anchor | hardware | TPM 2.0 / Secure Enclave (ADR-0018) |

   `DCS_MAC` / `OS_MAC` / `DAC` are the **conceptual operand labels** from `compose.rs`'s composition doc comment, not code symbols; the concrete symbols are the `Authorizer` trait (`maknae-security`) and the backend crates.

## Security criteria / acceptance tests

- An Admin-role subject whose RBAC/DAC operand returns `Permit` but whose clearance is insufficient (classification MAC operand returns `Deny`) receives a composed **`Deny`** — no build, role, or privilege changes this.
- No configuration exempts any subject, including the kernel/TCB, from a mandatory clearance `Deny`.
- The default non-DCS build enforces RBAC; adding the `maknae-authz-dcs` backend enriches decisions to ABAC **without weakening any decision** — because a mandatory operand is constraint-only and fails closed (next bullet), composing it can only *add* a `Deny`, never introduce a `Permit`.
- The mandatory (classification/clearance) operand is **constraint-only and fails closed**: it returns `Deny` for absent or insufficient clearance and otherwise `NotApplicable`, **never `Permit`**; and a mandatory operand is **always composed** into the request. Absent these, deny-overrides alone is not sufficient — a missing operand lets a discretionary `Permit` through, and a mandatory `Permit` could grant on a default-deny `NotApplicable`. Every mandatory backend and the kernel's request construction must guarantee this.

## Scope boundary

This ADR fixes vocabulary, the composition rule, and the no-bypass invariant. It does **not**: define the classification lattice or dominance engine (ADR-0008, **relocated** to the external DCS library) or the SPIF schema (ADR-0017, **relocated**); change the enforcement locus — the kernel remains the sole PDP (ADR-0005); or select the concrete policy engine (the Cedar spike, ADR-0003). Whether to *disambiguate* the code's **DAC** terminology — `maknae-config/authz.rs` names its policy the "DAC authz policy schema", which collides with OS-DAC — is a tracked follow-up; this ADR binds the meaning in the interim.

## Consequences

- README and AGENTS.md adopt this vocabulary: no "generic DAC access policy"; instead RBAC-default / ABAC-via-DCS over the `maknae-security` seam, with mandatory clearance never waivable.
- **The bare-metal path requires a hardware root of trust.** Because ADR-0018 seals the bare-metal bootstrap credential to an HRoT (TPM 2.0 / Secure Enclave), a Raspberry Pi with no TPM is not a bare-metal target. The Kubernetes path uses platform identity (Vault Kubernetes auth) with no secret at rest and needs no HRoT — so this consequence is scoped to bare-metal, not all deployments.
- Positive: a precise, NSS-aligned vocabulary that maps cleanly to NIST AC-3 enhancements. The no-bypass invariant is testable: `combine` structurally enforces mandatory *precedence* once a mandatory `Deny` is present, while the remaining conditions — that a mandatory operand is always composed, and that it fails closed — are kernel/backend construction invariants the acceptance tests hold (`combine`'s untyped `Vec<Verdict>` cannot enforce them on its own).
- Negative / accepted: the code's **DAC** terminology (`authz.rs`'s "DAC authz policy schema") collides with OS-DAC until the follow-up disambiguation; the collision's meaning is documented here so it does not mislead.

## Security control mapping (informative; per ADR-0001)

| Maknae property | NIST SP 800-53 Rev 5 | Driver |
|---|---|---|
| Capability policy, role-keyed | AC-3(4) Discretionary Access Control; AC-3(7) Role-Based Access Control | — |
| Classification/clearance, attribute-keyed | AC-3(3) Mandatory Access Control; AC-3(13) Attribute-Based Access Control; AC-16 Security and Privacy Attributes | NSS Classified Overlay (CNSSI 1253) |
| MAC precedence over DAC (deny-overrides, no bypass) | AC-3(3) Mandatory Access Control (precedence rule); AC-3(15) Discretionary and Mandatory Access Control (simultaneous enforcement) | NSS Classified Overlay |
| Admin/kernel constrained; privilege ≠ clearance | AC-6 Least Privilege | NSS Classified Overlay |
| Single decision point, non-bypassable | AC-3 Access Enforcement; AC-25 Reference Monitor | DoD Zero Trust RA v2.0 (ADR-0005) |

## References

Provenance (not authority, per ADR-0001): CNSSI 4009 (National Information Assurance Glossary, 6 Dec 2021) — DAC/MAC/RBAC/ABAC definitions; NIST SP 800-53 Rev 5 — AC-3(3)/(4)/(7)/(13)/(15), AC-6, AC-16, AC-25; NIST SP 800-162 — ABAC; CNSSI 1253 / NSS Classified Information Overlay.

Internal: ADR-0005 (enforcement locus & TCB boundary); ADR-0008 / ADR-0017 (classification engine / SPIF — relocated to the external DCS library); ADR-0018 (local-plane authorization & HRoT); ADR-0003 (policy engine spike). Code: `crates/maknae-security/src/compose.rs` (`combine`, deny-overrides), `crates/maknae-security/src/authorizer.rs` (the `Authorizer` seam), `crates/maknae-config/src/authz.rs` (the capability grammar).
