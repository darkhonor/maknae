# ADR-0005: Enforcement locus & TCB boundary — split-kernel, mTLS plane transport, plane-cert identity

- **Status:** Accepted (finalized 2026-08-10; originally operator-ratified 2026-08-03)
- **Date:** 2026-08-03 (scaffold) · **finalized** 2026-08-10
- **Deciders:** Alex Ackerman (operator), Claude (pair)
- **Addresses:** review issue #3 (Enforcement-locus & TCB boundary)
- **Relates to:** ADR-0002 (kernel is Rust); ADR-0007 (key & signature model — the object/audit/release signing this ADR defers); the merged Vault PKI (`deploy/vault-pki/`) that provisions the plane certs; the topology source spec.
- **Source specs:** `~/claude-memory/maknae/specs/2026-08-03-maknae-rust-workspace-topology-design.md` (topology, v6.1) and `~/claude-memory/maknae/specs/2026-08-10-adr-0005-0007-crypto-foundation.md` (this finalization).

> **Finalization note (2026-08-10).** This ADR was ratified in scaffold form on 2026-08-03 (topology + trust boundary only, with the concrete transport "owed"). It is now finalized: decisions **2** (mTLS plane transport) and **4** (plane-cert identity) are upgraded from topology-level to **locked, concrete criteria** now that the Vault PKI (`deploy/vault-pki/`, merged) provisions the fields; the `maknae-vault` crate contract and the mTLS acceptance tests are added; and the 2026-08-10 embedded-config amendment is folded inline (decision 5). The enforcement-locus substance is unchanged.

## Context

A Multi-Level Secure system must answer "where does enforcement actually live?" — the reference-monitor question (NIST SP 800-53 AC-25; DoD Zero Trust Reference Architecture's policy-decision/enforcement split). Enforcement that is only a function call inside a single address space has no locus a defender can point at: one memory-safety defect or dependency compromise in the untrusted agent loop reaches the decision logic directly. Maknae is therefore a native, all-Rust application (RPM/DEB/macOS + OCI) so the **process boundary can *be* the trust boundary** — and that boundary is enforced with **mTLS from the start** (no insecure-channel default ever exists).

## Decision

1. **All-Rust** for every Maknae-authored component; **one monorepo, one Cargo virtual workspace** (`resolver = "3"`, no `default-members`). Repo split only on external-consumer lifecycle.

2. **Split kernel from birth, mTLS from the start (Approach B).** `maknaed` (privileged trust plane, runs as `_maknae`) and `maknae` (CLI, operator uid) are separate processes over a Unix domain socket. The CLI is a permanent, untrusted client; the daemon decides. The channel is **rustls TLS 1.3 over the UDS + `SO_PEERCRED`/`LOCAL_PEERCRED`**:
   - **The cert binds the *plane*; the peer-cred binds the *principal*.** Two different identity facts, **not** independent oracles — on a single host both fall to operator-uid compromise; this is stated, not oversold.
   - mTLS provides real-time channel **authentication + integrity**, not durable non-repudiable signatures (it is not an AU-10 mechanism; durable non-repudiation, where wanted, is an ADR-0007 audit control, not the channel).
   - **Single-operator principal model:** principal = peer-cred uid resolved against the single Tier-0 operator record; any other uid is denied + audited. Multi-operator resolution arrives with the gateway (owed).

3. **Structural capability separation (P1/P2).** Privileged capabilities (`maknae-kernel`, `-subject-ctx-mint`, `-audit-append`, `-spif-compile`) live in separate crates the untrusted CLI cannot depend on — directly or transitively, and never as an `optional` dependency. CI proves absence three ways (invert-tree resolver witness, shipped-artifact symbol/inventory witness, synthesized-fixture negative controls) and proves the gates fire.

4. **Plane-cert identity (Vault-issued, the merged PKI as locked inputs).** Both planes authenticate to the same Vault with their own AppRole + per-plane policy scoped to their own `pki/sign/<plane-role>`; keypairs are generated locally, **memory-only, fail-closed, no file fallback**. Concretely, from `deploy/vault-pki/`:
   - **EC P-384 / CNSA 1.0** everywhere; leaf **URI-SAN `maknae://<deployment_id>/plane/{kernel,cli}`** is the whole identity (every other SAN channel closed on the roles).
   - Each plane **pins the Maknae CA bundle** — baked into its `/etc/maknae` config (a config-time pin, **not** fetched-and-trusted at runtime; the policy's `issuer/default/json` read is for chain retrieval / rotation, not for establishing the trust root) — and verifies the peer two ways: rustls/webpki validates the *chain*, and **the one consciously-owned verifier** matches the peer's URI-SAN plane identity — `maknaed` requires `plane/cli`, the CLI requires `plane/kernel`.
   - **Custody is by secret-absence, not code-absence** (the Consul-mesh property): both planes legitimately link the shared `maknae-vault` crate (each is a Vault client); isolation rests on each plane holding only *its own* AppRole SecretID via its own Vault policy.
   - **Honest residual:** Vault's `revoke` is mount-wide (no per-role revoke path), so either plane can revoke the other's live cert — a cross-plane cert-revocation **DoS** (never an identity forgery; revocation denies service, it cannot mint identity). The target serial is exposed in the mTLS handshake, so it is not a meaningful bound between two planes that have already exchanged leaves. Accepted at MVP; documented in `deploy/vault-pki/README.md`.

   **The `maknae-vault` crate contract (what a developer building either plane must honor):** AppRole auth via **RoleID (from config/output) + out-of-band single-use response-wrapped SecretID**; a local keypair with an **empty-subject, URI-SAN-only CSR** (the Vault roles enforce `require_cn=false`, `use_csr_common_name=false`, all non-URI SAN channels off — a DNS/other-SAN-bearing CSR is *rejected*, and a CN in the CSR is *dropped, never adopted*, so the leaf subject is always empty); `pki/sign` against its own role; **memory-only** cert+key, **fail-closed** on any error; **revoke-on-shutdown**; **background token renewal → fail-closed** at `token_max_ttl` (re-auth with a fresh SecretID); CA-bundle pin + the URI-SAN peer verifier. The crate is linked by **both** binaries and is **non-privileged** (must not depend on any privileged crate).

5. **Embedded config; no external lake read.** Maknae reads **only its own config** (`/etc/maknae`); the standalone knowledge lake is prior-art reference — **never cloned, mounted, or read at runtime**. The instance's authorization is `core.handling.ceiling` (`maknae-config` cycle ②c), read at boot into a coarse `Public`/`Gated` ingest posture; any config error → `maknaed` exits non-zero (fail-closed). Cross-object / cross-file classification **dominance** is deferred to the DCS scalpel (external library, reached through the authorization seam). *(This supersedes the scaffold's "consumer-only lake + boot classification-match" mechanism, retired 2026-08-10.)*

6. **Single session label, computed once** at hook C, reused for RLS and the hook-E egress screen; MVP labels are conservative/instance-wide (per-object derivation is DCS-engine work).

7. **`maknae-spifc`** is setup-only tooling; the daemon holds no DDL credentials.

8. **Configuration is YAML files, never ENV values;** dual-target packaging from one source tree; OpenAI-compatible model endpoints with per-endpoint dominance ceilings; MCP-client OAuth held in the trust plane.

## Security criteria / acceptance tests

The mTLS plane boundary is defendable only if its failure modes are proven to fail closed. Required:
- **mTLS negative suite** — each plane rejects: the peer's wrong/absent plane URI-SAN, an expired cert, an absent client cert, and a uid mismatch — all fail closed with audit events.
- **Per-plane Vault-policy scope test** — a plane's SecretID can sign only its own `plane/<name>` role, not the other's.
- **`maknae-vault` is in the mutation-gate set** (the consciously-owned URI-SAN verifier + the CSR/cert path); surviving mutants in that surface are release blockers.

## Scope boundary

This ADR covers the **plane-to-plane channel and plane-cert identity**. It does **not** cover the object/data/audit/release signing model — that is **ADR-0007** (key & signature model, non-DCS core) — nor authoritative classification/label binding, which is delegated to the **DCS library** (STANAG 4778, rust-dcs). Subject-context minting (ADR-0014), GUC/write-path, and the gateway remain owed.

## Consequences

- Enforcement has a physical locus a defender can point at (the `maknaed` process boundary) — the reference-monitor / TCB-boundary property.
- The near-term posture is honestly *weaker* than the ratified end-state (D4 Layer-2 collapse: at MVP the PDP and sole PEP are one process); stated, not hidden; the ratified shape returns at constellation.
- This ADR fixes topology, the trust boundary, and now the concrete mTLS transport + plane-cert identity + `maknae-vault` contract. Component bodies (the Rust `maknae-vault` client, the transport, the run loop, the CLI) land in following spec→plan→implement cycles.

## Security control mapping (informative; per ADR-0001)

Assessor framing: the topology does not *satisfy* a control; it gives the enforcement locus a physical, auditable boundary and upgrades the evidence class for access-enforcement controls from procedural attestation to structural guarantee (a privileged capability the untrusted binary cannot link does not exist in it).

| Concern | Property | NIST SP 800-53 rev 5 | Authoritative guidance |
|---|---|---|---|
| Enforcement locus / reference monitor | Trust boundary = process boundary; `maknaed` is the only PDP; every consequential act transits it | AC-3; AC-4 (hook-E egress); AC-25 (reference monitor) | DoD Zero Trust Reference Architecture v2.0 |
| Least privilege / capability separation | Privileged crates unlinkable from the CLI; per-plane Vault policy scopes each identity to its own role | AC-6, AC-6(9)/(10); CM-7 | NSA/CISA memory-safe + least-privilege guidance |
| Security-function isolation | Trust plane vs untrusted plane as separate processes, mutually authenticated (mTLS + peer-creds) | SC-3; SC-7 (the UDS/mTLS channel) | DoD Enterprise DevSecOps Reference Design |
| Architecture & assurance | All-Rust, static binaries, structural capability separation proven by CI | SA-8; SA-17 | ADR-0002 control mapping |
| Verification of the control | CI proves privileged-crate absence three ways + negative-control fixtures + the mTLS negative suite | SA-11, SA-11(1); SA-15 | `ci/gates/` suite |
| Cryptographic identity | Vault-issued CNSA 1.0 (EC P-384) plane certs; URI-SAN plane identity; keys memory-only, fail-closed, no fallback (merged Vault PKI) | IA-9; IA-5 / IA-5(2); SC-12; SC-17 | HashiCorp Vault PKI; CNSSI 1300 / CNSA Suite |

The full control matrix belongs in the RMF package, not this ADR.

## References

Source specs (memory store): topology design §3/§4/§5/§9/§10; crypto-foundation design (2026-08-10). Merged Vault PKI: `deploy/vault-pki/`. Microkosmos ADR 0006 + Vault server-configuration; HashiCorp Consul-as-Vault-Connect-CA; CNSA Suite. Issues #3, #18.
