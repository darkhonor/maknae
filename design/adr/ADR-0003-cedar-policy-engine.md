# ADR-0003: Cedar as the policy engine — leading candidate

- **Status:** **Superseded by [ADR-0004](ADR-0004-modular-authorization-architecture.md)** (operator-directed 2026-08-22). Cedar is **demoted, not eliminated**: the bundled default backend is a native-Rust evaluator over the `maknae-authz-basic` YAML grammar, and Cedar is preserved as an *optional* pluggable `maknae-authz-cedar` backend behind the `maknae-security` seam for deployments whose policy complexity, static analysis, or formal-verification needs justify it. The original lean (below) is retained for the record.
- **Date:** 2026-07-14
- **Deciders:** Alex Ackerman (operator lean); team spike pending

## Context

KLC §14 Q5 requires a policy-language selection evaluated against the six enforcement hooks (KLC §10) as the acceptance test. The candidates are Cedar and OPA/Rego. ADR-0002 (Rust kernel) makes the pairing non-neutral: Cedar is Rust-native (`cedar-policy` crate); OPA is Go-native and embeds in Rust only via compiled Wasm or a sidecar.

## Decision

Cedar is the leading candidate. Evidence of record:

- **Formally verified core** — the `cedar-spec` project proves the evaluator against a Lean specification with differential testing against the production Rust implementation. For an accreditation-bound trust plane, this is the strongest assurance signal available in this class of tooling.
- **Rust-native** — first-class integration with the ADR-0002 kernel; no FFI/Wasm boundary inside the trust plane.
- **Cross-language official implementations** — `cedar-policy` (Rust) and `cedar-go` (github.com/cedar-policy) cover the two compiled-language containers; the absence of an official Python library is non-blocking by architecture: Python containers are PEPs that never evaluate policy (container-architecture §6).
- **Production provenance and governance** — runs at scale inside AWS Verified Permissions; CNCF Sandbox acceptance provides neutral governance.
- **Decision model fit** — Cedar's (principal, action, resource, context) authorization shape maps directly onto the KLC's (subject, action, resource labels, context) hook signature.

Known concerns, recorded honestly: community adoption is modest (the operator would have liked more GitHub stars), and CNCF Sandbox projects can stall. Mitigation: the engine sits behind a kernel-internal trait; the six hooks are the acceptance tests; a future swap is a bounded refactor, not a rewrite. The kernel marries the hook contract, never the engine.

## Consequences

- The Q5 spike proceeds as designed — Cedar first, evaluated against all six hooks; OPA is evaluated only if Cedar fails a hook or the team overturns the lean.
- Acceptance: this ADR moves to Accepted when the spike demonstrates all six hooks expressible and testable in Cedar, with the KLC §15 invariants encoded as Cedar policy tests or kernel-side type guarantees.
- The authority map and operator-attribute configuration compile to Cedar entities/policies at kernel load; schema for that compilation is part of the kernel skeleton work.

## Security control mapping (informative; added 2026-07-14 at operator direction)

Same framing as ADR-0002: the engine choice satisfies no control — it determines the *assurance class* of the access-enforcement implementation at the heart of the platform. Full matrix belongs in the RMF package.

| Concern | Cedar property | NIST SP 800-53 rev 5 | Authoritative guidance |
|---|---|---|---|
| Access enforcement, deny-by-default | A dedicated, single-purpose authorization engine implementing the PDP; default-deny with explicit permits; forbid overrides permit | AC-3 (access enforcement); AC-6 (least privilege); CM-7 (least functionality — capability whitelisting as the decision model) | NIST SP 800-207 (Zero Trust — the PDP/PEP separation this kernel implements) |
| Attribute/label-based decisions | Native (principal, action, resource, context) evaluation over typed entities and attributes — symbol-for-symbol the KLC hook signature; carries the DCS label and operator-attribute model without translation | AC-16 (security and privacy attributes — policy bound to attributes); AC-4 (information flow enforcement — hook E decisions) | NIST SP 800-162 (ABAC — Cedar's model is the guide's model) |
| Formal assurance of the decision core | The `cedar-spec` project: evaluator semantics specified and proven in Lean, differential-tested against the production Rust implementation | SA-17(1) (formal policy model — implemented, not approximated); differential testing is evidence *toward* SA-17(3) formal correspondence, claimed only as that | `cedar-spec` (github.com/cedar-policy/cedar-spec) |
| Policy quality as a testable artifact | Schema-based policy validation (malformed or ill-typed policies rejected before load); policies are data, testable in CI against the KLC §15 conformance vectors | SA-11 (developer testing applied to policy-as-code); SI-10 (validity checking on the policy inputs the kernel loads) | — |
| Decision auditability | Deterministic, reproducible decisions with structured diagnostics (which policies determined the outcome) — the kernel's hook audit events carry engine-grade rationale | AU-2 (event logging — decision events with determining-policy detail); AU-10 (supports non-repudiation of the decision record, claimed as support only) | — |

Boundaries on the claim: (1) Cedar's formal verification covers the *evaluator*, not the operator's authored policies — bad policy is still bad policy, which is what the §15 conformance vectors and the spike's hook tests exist to catch; (2) the mapping is contingent on this ADR reaching Accepted — if the spike overturns the lean, the successor engine must re-earn every row of this table before adoption.
