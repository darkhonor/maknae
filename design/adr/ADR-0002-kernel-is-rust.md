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
- Kernel crates carry `#![forbid(unsafe_code)]`; `unsafe` is confined to vetted dependencies (e.g., the `aws-lc-rs` FFI boundary) and tracked via `cargo-geiger` / `cargo-deny` policy in CI. This commitment is load-bearing for the control mapping below — Rust's guarantees are claims about *safe* Rust, and this is what makes that claim auditable.

## Security control mapping (informative; added 2026-07-14 at operator direction)

Assessor framing, stated plainly: **a language choice does not satisfy any control.** It makes specific control implementations structurally cheaper, and — more valuable to an assessor — it upgrades the *evidence class* for those implementations from procedural attestation ("we run a scanner, here is the report") to structural guarantee ("this defect class does not compile"). The mapping below identifies where that upgrade lands; the full control matrix belongs in the RMF package, not this ADR.

| Concern | Rust property | NIST SP 800-53 rev 5 | Authoritative guidance |
|---|---|---|---|
| Memory safety | Compile-time elimination of memory-corruption defect classes (use-after-free, buffer overflow, data races in safe Rust); `#![forbid(unsafe_code)]` makes the boundary auditable | SI-16 (Memory Protection — complements, at the source level, the runtime protections the control contemplates); SA-8 (security engineering principles — inherently secure design); SI-2 (flaw remediation — the remediation burden for the eliminated classes goes to zero) | NSA CSI *Software Memory Safety* (Nov 2022); CISA et al., *The Case for Memory Safe Roadmaps* (Dec 2023) |
| SDLC | The compiler + clippy as always-on static analysis in every build (not a pipeline stage that can be skipped); TDD + property tests + scheduled mutation testing (container-architecture §5); KLC §15 invariants encoded in the type system — illegal states unrepresentable | SA-3 (security integrated into the SDLC); SA-11 and SA-11(1) (developer testing; static code analysis); SA-15 (development process, standards, and tools — the language and toolchain ARE the documented tool standard); SA-17(1) (formal policy model — type-encoded invariants and the ADR-0003 formally verified policy core implement its intent) | DoD Enterprise DevSecOps Reference Design (the pipeline gates this replaces/strengthens) |
| Supply chain | `Cargo.lock` cryptographic checksum pinning of the full dependency tree; `cargo-audit` / `cargo-deny` against the RustSec advisory database in CI; fully vendorable dependencies for air-gapped builds; static binary into distroless/from-scratch images (no runtime package surface) | SR-3 (supply chain controls and processes); SR-4 (provenance — the lockfile is a machine-verifiable provenance record); SR-11 (component authenticity); SI-7 (software integrity — checksum verification on every build); RA-5 (vulnerability monitoring of components); CM-7 (least functionality — the empty base image) | DoD Container Hardening Process Guide (the TaeBot image pattern is the in-house implementation) |
| Cryptography | `aws-lc-rs` — FIPS 140-3 validated module, proven in-house by Microkosmos | SC-13 (cryptographic protection — FIPS-validated mechanisms) | CMVP validation record for the AWS-LC module |

Two honest boundaries on the claim, so the mapping survives a hostile read: (1) the guarantees are per-language, not per-system — the Python and Go containers make no equivalent claim, which is exactly why the trust plane is confined to the two Rust containers (container-architecture §2); (2) logic errors, policy errors, and unsound `unsafe` in dependencies remain in scope — that is what the SA-11 test doctrine, the KLC §15 conformance vectors, and the dependency-vetting policy are for. The language closes a defect class; the SDLC closes the rest.
