# ADR-0002: The kernel is 100% Rust

- **Status:** Accepted (operator-ratified 2026-07-14)
- **Date:** 2026-07-14
- **Deciders:** Alex Ackerman (operator)

## Context

The trust plane kernel mediates every decision (all six KLC §10 hooks); a memory-safety defect there is not a bug but a trust-plane compromise — the one failure the architecture cannot absorb. The team's development model is AI implementation under architect direction, which shifts the language question from "what can the team write?" to "what best verifies code the humans did not write?"

## Decision

The kernel container (and the egress-proxy, per container-architecture §3.2) is written in 100% Rust.

Rationale of record:

1. **Memory safety as a citable control** — NSA/CISA memory-safe-language guidance alignment enters the RMF story directly.
2. **Invariants in types** — KLC §15 invariants are encoded so illegal states are unrepresentable (a `tier_ceiling` automation cannot raise; a downgrade constructible only by consuming a signed authorization). The human review surface shrinks to the type/contract layer, where the architects operate.
3. **The compiler reviews AI-written code** mechanically and tirelessly — load-bearing under the AI-driven development model.
4. **In-house precedent** — Microkosmos: FIPS 140-3 via `aws-lc-rs`, hardened static binaries into distroless images, toolchain already proven on the team's platforms.

## Consequences

- Policy engine selection interacts with this ADR (Cedar is Rust-native; see ADR-0003).
- `maknae-dcs-core` (shared lattice/label crate, container-architecture §6) is Rust, seeded by the Microkosmos extraction.
- No other container inherits a Rust obligation — language-per-action stands (container-architecture §1.2).
