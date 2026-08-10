# ADR-0007: Key & signature model (non-DCS core)

- **Status:** Accepted (operator-ratified 2026-08-10)
- **Date:** 2026-08-10
- **Deciders:** Alex Ackerman (operator), Claude (pair)
- **Addresses:** review issue #5 (Key & signature model — the undefined foundation)
- **Relates to:** ADR-0005 (the mTLS plane transport that carries the communication-signing load); the merged Vault PKI (`deploy/vault-pki/`); the DCS library (rust-dcs) — which owns authoritative classification/label signing.
- **Source spec:** `~/claude-memory/maknae/specs/2026-08-10-adr-0005-0007-crypto-foundation.md`.

> **Slot note.** Registry slot 0007 was allocated as "Key & signature model (STANAG 4778 binding)". On finalizing, the STANAG 4778 **label-binding** half — authoritative, tamper-evident binding of a classification label to a data object — is DCS classification-semantics and is **Relocated to the DCS library** (rust-dcs #21). Slot 0007 is renamed + reused for the **non-DCS core** key/signature model below.

## Context

Maknae's architecture rests on signatures, but the base (non-DCS) product must have a coherent, defendable key & signature model *without* pulling in the DCS classification machinery. The guiding decision: **in a Zero Trust design you sign the *communications*, not the *content*.** mTLS already signs the channel (ADR-0005); content gets integrity **hashes** (SHA-256, already present in the lake corpus), not authoritative per-reference signatures. Authoritative classification/label signing is a **DCS-library** concern, delegated out.

## Decision

**Governing principle:** ADR-0007 defines the key & signature model for what **non-DCS Maknae core actually signs** — communications (mTLS) and integrity (hashes / chains) — plus release provenance. Anything requiring authoritative classification signing is delegated to the DCS library's own design, not built here.

**The must / could / shouldn't taxonomy:**

| Tier | What | Mechanism | Home |
|---|---|---|---|
| **MUST — sign/bind** | Plane↔plane communications | mTLS (Vault plane certs + peer-creds) | ADR-0005 (done) |
| **MUST — integrity** | Lake / memory content | SHA-256 hashes (change-detect, request/sample-validate) | already exists |
| **MUST — integrity** | Audit trail tamper-evidence | **hash-chain** the records (AU-9) | this ADR |
| **MUST — provenance** | Git tags & releases | **GPG-signed** with the operator's GitHub-noreply key | this ADR + project requirement |
| **COULD — sign** | Audit checkpoints (non-repudiation, AU-10) | periodic signed checkpoint | this ADR (accreditation-driven, optional) |
| **COULD — sign** | Release / container / policy bundle beyond tags | supply-chain verification at deploy | this ADR (deferred) |
| **SHOULDN'T (core)** | Individual content / paragraph refs | hash is sufficient | — |
| **SHOULDN'T (→ DCS library)** | Classification / tier / caveat attestation; §12 signed-tier cross-site import; classification downgrade authorization; STANAG 4778 label-binding | authoritative label signing | DCS library (rust-dcs) |

**Key model (narrow — core's real signing surface):**
- **mTLS plane certs** — Vault-issued (PKI, done). Custody: memory-only, fail-closed, per-plane AppRole (ADR-0005 / `maknae-vault`).
- **Audit-signing key** (if signed checkpoints are adopted) — same Vault memory-only / fail-closed custody pattern; trust-plane only.
- **GPG release/tag key** — the operator's **self-published GitHub-noreply GPG key** (the Microkosmos key). It is a **project requirement** to sign annotated tags and releases with it. Self-published keys are sufficient here — standard for a non-organization OSS project without a corporate sponsor; no org PKI dependency.
- **Out of scope (→ DCS / gateway / later):** operator conversational-signature keys, web-ui signature production, a "CI key" that signs skills/Tier-1 promotions, §12 cross-site trust anchors, STANAG 4778 label-binding.

**Audit hash-chain — AU-9 threat-model precondition (honesty):** a bare hash-chain gives tamper-evidence only against an adversary who *cannot recompute the whole chain*. A trust-plane compromise can rewrite record K and recompute the tail, defeating a pure chain. Full AU-9 tamper-evidence therefore needs an **externalized anchor** — a periodically signed/exported checkpoint (the COULD control), or a prior-hash copy a verifier holds independently. The MUST hash-chain alone is honestly scoped to "detects post-hoc single-record edits by an adversary without whole-chain recompute," not "irrefutable against a trust-plane compromise."

**Release/tag signing — provenance scope (honesty):** GPG-signed annotated tags + the committed provider lock deliver **SR-4 source/producer provenance** (a registry checksum verifies bytes, not producer; a signed tag establishes the producer and source commit). They do **not** by themselves deliver **SR-11 authenticity of the *shipped* artifact** (the RPM/DEB/OCI a consumer installs) — that needs signing the release *artifacts* / a build attestation (the deferred COULD row). "Signed releases" here means the annotated **tag/release object**; GitHub releases have no native attached-artifact signature mechanism.

## Consequences

- The base product's crypto/trust surface is tractable: mTLS (done), content hashes (exist), audit hash-chain (this ADR), GPG release/tag signing (this ADR). No DCS classification-signing machinery is pulled into core.
- Non-repudiation (AU-10) and shipped-artifact authenticity (SR-11) are honestly **partial/deferred**, not claimed complete.
- The DCS-delegated concerns (STANAG 4778 label-binding, classification/tier signing) are tracked in the DCS library (rust-dcs), re-entering when the DCS module is designed.

## Security control mapping (informative; per ADR-0001)

| Concern | Property | NIST SP 800-53 rev 5 | Notes |
|---|---|---|---|
| Channel authentication/integrity | mTLS plane certs | SC-8; SC-8(1); IA-9 | not AU-10 (no durable non-repudiation) |
| Content integrity | SHA-256 hashes | SI-7 | change-detection, not authoritative signing |
| Audit integrity | hash-chained audit records (+ optional signed checkpoints) | AU-9 (partial); AU-9(3) *full only with the externalized anchor*; AU-10 (COULD) | bare chain = partial AU-9 (recomputable by a trust-plane compromise); the signed/exported checkpoint completes AU-9(3) tamper-evidence (see the anchoring precondition above) |
| Supply-chain provenance | GPG-signed tags/releases + committed provider lock | SR-4 | SR-11 shipped-artifact authenticity is partial/deferred |

The full control matrix belongs in the RMF package, not this ADR.

## References

Source spec (memory store): crypto-foundation design (2026-08-10) §3/§4. Merged Vault PKI: `deploy/vault-pki/`. rust-dcs #21 (STANAG 4778 label-binding). CNSA Suite; NIST SP 800-53 rev 5. Issue #5.
