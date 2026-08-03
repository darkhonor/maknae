# ADR-0005: Enforcement-locus & TCB boundary — all-Rust workspace, split-kernel MVP

- **Status:** Accepted (operator-ratified 2026-08-03)
- **Date:** 2026-08-03
- **Deciders:** Alex Ackerman (operator), Byeori (Claude Fable 5, pair)
- **Addresses:** review issue github.com/darkhonor/maknae#3 (Enforcement-locus & TCB boundary), raised by an independent reviewer
- **Supersedes:** Extends ADR-0002 (kernel is Rust) to all Maknae-authored components. Full container-architecture / abac supersession list is in the source spec header.
- **Source spec:** `~/claude-memory/maknae/specs/2026-08-03-maknae-rust-workspace-topology-design.md` (v6.1; converged through the team's critical-review loop + operator review)

## Context

A Multi-Level Secure system must be able to answer "where does enforcement actually live?" — the reference-monitor question (NIST SP 800-53 AC-25; DoD Zero Trust Reference Architecture's policy-decision/enforcement split). Enforcement that is only a function call inside a single address space has no locus a defender can point at: one memory-safety defect or dependency compromise in the untrusted agent loop reaches the decision logic directly. Maknae is therefore built as a native, all-Rust application (RPM/DEB/macOS + OCI) so the **process boundary can *be* the trust boundary**.

(An independent design review is running against this corpus on the repo issue tracker; those are the reviewers' findings, tracked separately. This ADR records the operator's architecture decision on its own terms.)

## Decision

1. **All-Rust** for every Maknae-authored component; **one monorepo, one Cargo virtual workspace** (`resolver = "3"`, no `default-members`). Repo split only on external-consumer lifecycle.
2. **Split kernel from birth (Approach B):** `maknaed` (trust plane) and `maknae` (CLI, untrusted interaction plane) are separate processes over a Unix socket, mutually authenticated with **mTLS (Vault-issued plane certs) + peer-creds**.
3. **Structural capability separation (P1/P2):** privileged capabilities (`maknae-kernel`, `-subject-ctx-mint`, `-audit-append`, `-spif-compile`) live in separate crates the untrusted CLI cannot depend on; CI proves absence three ways (invert-tree resolver witness, shipped-artifact symbol/inventory witness, synthesized-fixture negative controls) and proves the gates fire.
4. **Dual Vault-client identity (Microkosmos ADR 0006 + Consul-mesh):** both planes authenticate to the same Vault with their own AppRole + matching per-plane policy scoped to `pki/sign/<plane-role>`; keypairs generated locally, memory-only, fail-closed with no file fallback.
5. **Consumer-only lake:** Maknae mounts a read-only, externally-curated lake; the only MVP gate is a boot-time classification-match check (lake ceiling must be dominated by Maknae's authorization). No ingest at MVP.
6. **Single session label, computed once** at hook C, reused for RLS and the hook-E egress screen; MVP labels are conservative/lake-wide (per-object derivation is DCS-engine work).
7. **`maknae-spifc`** is setup-only tooling; the daemon holds no DDL credentials.
8. **Configuration is YAML files, never ENV values;** dual-target packaging from one source tree; OpenAI-compatible model endpoints with per-endpoint dominance ceilings; MCP-client OAuth held in the trust plane.

## Consequences

- Enforcement has a physical locus a defender can point at (the `maknaed` process boundary), which is what the reference-monitor / TCB-boundary property requires.
- The near-term posture is honestly *weaker* than the ratified end-state (D4 Layer-2 collapse: at MVP the PDP and sole PEP are one process); this is stated, not hidden, and the ratified shape returns at constellation.
- Semantic contracts (lattice ADR-0008, keys ADR-0007, subject-context ADR-0014, GUC/write-path, audit) remain owed and gate later component work; this ADR fixes only topology and the trust boundary.
- This deliverable is the **scaffold**: every crate is a documented stub. Component bodies land in later spec→plan→implement cycles.

## Security control mapping (informative; per ADR-0001)

Assessor framing: the topology does not *satisfy* a control; it gives the enforcement locus a physical, auditable boundary and upgrades the evidence class for the access-enforcement controls from procedural attestation to structural guarantee (a privileged capability the untrusted binary cannot link does not exist in it).

| Concern | Topology property | NIST SP 800-53 rev 5 | Authoritative guidance |
|---|---|---|---|
| Enforcement locus / reference monitor | Trust boundary = process boundary; `maknaed` is the only PDP; every consequential act transits it | AC-3 (access enforcement); AC-4 (information flow — hook E egress); AC-25 (reference monitor — always-invoked, tamper-resistant, small enough to analyze) | DoD Zero Trust Reference Architecture v2.0 (policy-decision/enforcement split) |
| Least privilege / capability separation | Privileged crates unlinkable from the untrusted CLI; per-plane Vault policy scopes each identity to its own role | AC-6 (least privilege); AC-6(9)/(10) (privileged functions); CM-7 (least functionality) | NSA/CISA memory-safe + least-privilege guidance |
| Security-function isolation | Trust plane (`maknaed`) vs untrusted interaction plane (`maknae`) as separate processes, mutually authenticated (mTLS + peer-creds) | SC-3 (security function isolation); SC-7 (boundary protection — the UDS/mTLS channel) | DoD Enterprise DevSecOps Reference Design |
| Architecture & assurance | All-Rust, static binaries, structural capability separation proven by CI | SA-8 (security engineering principles); SA-17 (developer security architecture) | ADR-0002 (kernel is Rust) control mapping |
| Verification of the control itself | CI proves privileged-crate absence three ways + negative-control fixtures prove the gates fire | SA-11 (developer testing); SA-11(1) (static analysis); SA-15 (development tools/standards) | The scaffold's `ci/gates/` suite |
| Cryptographic identity | Vault-issued CNSA 1.0 plane certs; keys generated locally, memory-only, fail-closed no-fallback (Microkosmos ADR 0006) | IA-9 (service identification); IA-5 / IA-5(2) (authenticator / PKI); SC-12 (key management); SC-17 (PKI certs) | HashiCorp Vault PKI; Consul-as-Vault-Connect-CA; CNSSI 1300 / CNSA Suite |

The full control matrix belongs in the RMF package, not this ADR.

## References

Source spec (memory store) §3, §4, §5, §9, §10; Microkosmos ADR 0006 + Vault server-configuration; HashiCorp Consul-as-Vault-Connect-CA; issues #3, #18.
