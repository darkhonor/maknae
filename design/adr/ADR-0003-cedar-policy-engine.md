# ADR-0003: Cedar as the policy engine — leading candidate

- **Status:** Proposed (operator lean 2026-07-14; the KLC §14 Q5 spike against the six hooks confirms or overturns)
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
