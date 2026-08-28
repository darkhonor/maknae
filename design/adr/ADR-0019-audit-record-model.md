# ADR-0019: Audit record model — AU-3-complete content now, cryptographic integrity/non-repudiation deferred to ADR-0007

- **Status:** Accepted (operator-ratified 2026-08-11)
- **Date:** 2026-08-11
- **Deciders:** Alex Ackerman (operator), Claude (pair)
- **Addresses:** the audit trail the `maknaed` trust plane emits — its record content, sinks, compliance posture, and the boundary between what an open-source project can ship and what a National Security System deployer supplies.
- **Relates to:** ADR-0005 (the mTLS negative suite requires fail-closed rejections to emit audit events); ADR-0007 (key & signature model — owns the audit hash-chain / signing this ADR defers to); ADR-0018 (the authorization decisions these records capture); ADR-0016 (tiering).
- **Source spec:** `~/claude-memory/maknae/specs/2026-08-11-maknae-stage3a-it-responds.md`.

## Context

ADR-0005's negative suite requires every fail-closed rejection to emit an audit event, and the operator's target posture is an audit trail **compliant with the public DoD/CNSS audit requirements** for an HHH National Security System with the Classified Information Overlay. A review of the authoritative public references (NIST SP 800-53r5 AU family; NIST SP 800-53B HIGH baseline; CNSSI 1253 (2022); the Classified Information Overlay) established three facts that shape this decision:

1. **The Classified Information Overlay is silent on audit-record *content*.** It adds only AU-6/AU-12/AU-14/AU-16 (insider-threat monitoring). Record *content*, *timestamps*, *protection*, and *non-repudiation* are governed by the **800-53B HIGH baseline + CNSSI 1253**, not by an overlay-pinned field list — and the overlay does **not** mandate a classification-marking field inside audit records.
2. **AU-9(3) (cryptographic integrity) and AU-10 (non-repudiation) are HIGH-baseline requirements** that mandate audit records be cryptographically integrity-protected and non-repudiably bound to the acting identity — i.e., signed. This is the ADR-0007 "key & signature model" domain.
3. **The concrete NSS event catalog and AU-3(1) additional-field list live in CNSSI No. 1015 — which is CUI.** An open-source project can neither ingest it nor embed requirements derived from it.

## Decision

**1. Audit-record content is AU-3 / AU-3(1)-complete against the *public* standards, now.** Every generated record carries the six mandatory AU-3 elements plus the AU-3(1) additional information drawn from the *public* AU-3(1) discussion:

| Field | AU-3 element |
|---|---|
| `ts` — RFC 3339 UTC (or explicit offset), sub-second (ms) | AU-3b + AU-8 |
| `event` — event type/description | AU-3a |
| `where` — host, component, socket | AU-3c |
| `source` — peer plane URI-SAN, uid/gid/pid | AU-3d |
| `subject` — resolvable identity (uid → user, plane URI-SAN) | AU-3f |
| `action` — verb | AU-3a |
| `outcome` — result + reason + resulting posture | AU-3e |
| `session_id`, `seq` — connection correlation, ordering | AU-12(1) |

Because ADR-0018 authorizes on **group membership**, logging the specific uid/user within the group *is* AU-3(1)'s "individual identities of group-account users," and `outcome.reason` *is* the "access-control rule invoked" — the public AU-3(1) intent is satisfied natively.

**2. Cryptographic integrity (AU-9(3)) and non-repudiation (AU-10) are deferred to ADR-0007 — as a tracked gap, and one whose closure is *not yet a committed obligation*.** Each record reserves an `integrity: { prev_hash, sig }` envelope; the record schema is canonicalizable so an audit-signing capability (hash-chain + signature) bolts on **without a format break**. Until it ships, the deployment is **not** AU-9(3)/AU-10-complete. Honesty on the deferral target: **ADR-0007 today mandates only a bare audit hash-chain** (partial AU-9 — it detects single-record edits, and is explicitly *not* irrefutable against a trust-plane compromise) and scopes the externalized/signed anchor that actually completes AU-9(3)/AU-10 as **accreditation-driven / optional (a "COULD")**. So the `integrity.sig` producer **does not yet exist as a committed requirement** — closing this gap for a real NSS ATO requires a committed **amendment to ADR-0007** upgrading that anchor from optional to a tracked MUST-for-NSS. This ADR flags that dependency rather than implying ADR-0007 already owns it as a MUST.

**3. Two sinks now; SIEM offload as a config seam (AU-9(2)).** Records are written to a dedicated **`_maknae`-owned append-only JSONL file** **and** mirrored to **journald/syslog** (the macOS unified log as the equivalent). A `maknae.yaml` `audit:` section is the declared seam for an **external SIEM collector**, satisfying AU-9(2) (store on a physically separate system) **when configured** (the default two sinks are same-host). **AU-5 posture applies during operation, not only at startup:** if the primary sink cannot be opened at boot **or** a write to it fails at runtime, the daemon **fails closed**. (The journald/syslog mirror is best-effort and does not by itself relieve the fail-closed requirement on the primary sink.)

**Ordering — so "fail closed" is actually realizable.** A post-hoc audit-write failure cannot un-apply a side effect, so the fail-closed guarantee depends on record *ordering* relative to execution:
- **Stage 3a's verbs are read-only (`whoami`/`ping`).** The record is written and **durably flushed to the primary sink before the response is released** (audit-then-respond); a write failure withholds the response — fail closed, with no side effect to undo.
- **Mutating verbs (issue #67, Stage 3b+) cannot be made fail-closed by a post-hoc write.** They require **two-phase** audit — a pre-execution *decision/intent* record durably written **before** the side effect (the operation is refused if it cannot be), plus a post-execution *completion* record capturing the outcome. That pattern is **owed when mutating verbs land** and is out of Stage-3a scope; ADR-0019's schema already carries `seq`/`session_id` to correlate the two phases.

**4. The OSS-vs-CUI boundary is explicit.** Maknae ships requirements derived only from **public** standards. The **CNSSI-1015-specific** NSS event list and AU-3(1) field set are **not** ingested or embedded. A downstream NSS integrator (who holds CNSS/CNSSI-1015 access) supplies those fields via the record's **`au3_1` extension area**, configured in `maknae.yaml` — Maknae provides the *mechanism*, never the CUI *content*.

## Security criteria / acceptance tests

- Every connection decision (accept/deny) and every request (verb/outcome) emits a record carrying all AU-3 elements + the AU-3(1) fields above; a fail-closed rejection is audited (ADR-0005 negative suite).
- Timestamps are UTC (or carry an explicit offset), sub-second.
- The JSONL sink and the journald/syslog mirror both receive the record; a `maknae.yaml`-configured SIEM endpoint receives it when set.
- Inability to open the primary audit sink at startup → the daemon fails closed; a runtime write failure to the primary sink → the offending request is not served (fail closed).
- The reserved `integrity` envelope round-trips (present, empty) and the record canonicalizes deterministically (so ADR-0007 signing is a clean add).
- No CUI-derived field list or event catalog appears in the source tree; `au3_1` is populated only from config.

## Scope boundary

This ADR covers audit **content, sinks, and compliance posture** for Stage 3a. It does **not** cover: the **cryptographic** audit integrity/non-repudiation mechanism (AU-9(3)/AU-10 → **ADR-0007**); audit **review/reduction/reporting** (AU-6/AU-7 — later); **retention** policy (AU-11 — deployment); or the CNSSI-1015 NSS specifics (deployer-supplied via `au3_1`).

## Consequences

- **Positive:** a public-standards-compliant audit *content* schema from day one, crypto-ready and SIEM-ready; the OSS/CUI boundary keeps the project clean of controlled content; the group-based-authz ↔ AU-3(1) alignment is a natural fit.
- **Negative / accepted:** the deployment is not AU-9(3)/AU-10-complete, and — per Decision 2 — its closure is **not yet a committed obligation** (it needs a not-yet-existing amendment upgrading ADR-0007's optional signed anchor to a MUST-for-NSS). A **known, tracked** compliance gap that blocks a real ATO until closed. Journald/macOS-unified-log mirroring is best-effort operational persistence, not the tamper-evident trail (that is AU-9(3), pending that ADR-0007 amendment).

## Security control mapping (informative; per ADR-0001)

| Concern | Property | NIST SP 800-53 rev 5 | Authoritative guidance |
|---|---|---|---|
| Content of audit records | Six AU-3 elements + public AU-3(1) additional info on every record | AU-3, AU-3(1) | NIST SP 800-53B HIGH baseline |
| Event logging | Connection decisions + requests + fail-closed rejections logged | AU-2; AU-12, AU-12(1) | CNSSI 1253 (public) |
| Time stamps | UTC / explicit offset, sub-second, correlatable | AU-8 | — |
| Protection of audit information | `_maknae`-owned append-only sink; SIEM offload to a separate system *when configured* | AU-9; AU-9(2) | — |
| Cryptographic integrity / non-repudiation | Reserved `integrity` envelope; signing deferred to ADR-0007 (**tracked gap**, whose closure needs a not-yet-existing ADR-0007 amendment — see Decision 2) | AU-9(3); AU-10 | ADR-0007 |
| Response to logging failure | Fail closed if the primary sink cannot be opened **or** a runtime write fails | AU-5 | — |
| Identity preservation | Resolvable subject identity; specific group-member identity captured | AU-3f | Classified Information Overlay (insider-threat, public) |
| OSS-vs-CUI boundary | Public-standard fields shipped; CNSSI-1015 specifics via deployer `au3_1` config | (governance) | CNSSI 1253 → CNSSI 1015 (CUI, not ingested) |

## References

- NIST SP 800-53r5 (AU-2/AU-3/AU-3(1)/AU-8/AU-9/AU-10/AU-12) and SP 800-53B (HIGH baseline) — public. CNSSI 1253 (2022) and the Classified Information Overlay — public. **CNSSI No. 1015 — CUI, deliberately not ingested.**
- ADR-0005 (negative-suite audit requirement); ADR-0007 (audit signing / hash-chain); ADR-0018 (the authorization decisions recorded).

## Amendment (2026-08-28, #77 — the read verb, the object element, the disclosure invariant, the action vocabulary)

Dated as-built amendment; one statement, four coupled deltas (rides the #77 PR):

1. **The record gains an optional `object` element** (AU-3 "objects involved"): the canonical decided resource path for resource-bearing verbs (`fs.read`); absent for resource-free verbs — additive for them. Without it, two denied paths under one deny pattern were indistinguishable in the trail.
2. **The `action` field's value domain changes** (NOT additive): it now carries the PDP action-class name — `liveness.ping`, `admin.whoami`, `fs.read` — instead of the bare verb (`ping`/`whoami`). Scope: VERB-DECIDED request records only; the transport/boot pseudo-actions (`connect`, `read`, `decode`, `authz`, `posture`) are not PDP actions and keep their names. Decision and record share one vocabulary; the AU-3(1) reason/action pairing follows it.
3. **The ordering invariant generalizes: no DISCLOSURE without a durable record.** The verb enumeration above ("read-only (`whoami`/`ping`)") is superseded: `Read` joins Stage 3a's read-only set, and its dispatch (an anchored open + bounded read — an observable access) happens BEFORE the record, because the outcome (content/oversize/refusal) is only knowable after the open. The frame still gates on the durable append: content read into daemon memory whose record cannot append is dropped (zeroized) undisclosed. Internal access before the record is accepted; **audit-before-MUTATE (two-phase, write-ahead) remains #84's obligation exactly as stated above** — this amendment deliberately does not claim it.
4. **Deny reasons are audit-only** (restating #85's spec §4.4 as record contract): the PDP's reason (including matched deny-pattern source text) appears in `outcome.reason` and never on the wire; the wire carries fixed generic strings.

## Amendment (2026-08-29, #67) — the action vocabulary drops the `acp.` prefix

**The `action` field's value domain changes again (NOT additive).** `acp.fs.read` → `fs.read`, and the class vocabulary becomes `liveness` / `admin` / `session` / `fs` / `terminal` / `mcp` / `kernel`.

**Rationale.** The `acp.` prefix bound capability domains to a protocol version. ACP v2 removes the Client filesystem and terminal surfaces entirely and delegates them to client-provided MCP servers (`design/references/2026-08-28-acp-protocol-assessment.md`, pinned at upstream `9f40e01`), so a class name carrying that prefix asserts a mapping that upstream no longer has. `session` keeps its name because it exists in both ACP versions; `fs` and `terminal` are capability domains that outlive whichever protocol carries them.

**Trail continuity.** Records written before this amendment carry `acp.fs.read`. An auditor querying filesystem reads across the boundary must union the old and new names. No migration of existing records is performed — the trail is append-only by design, and rewriting it would be a worse defect than the discontinuity.

**The `outcome` value domain is PINNED by this amendment.** It was never enumerated, and the record types the fields as free-form strings, so R8 had nothing to govern until now: `result` ∈ {`permit`, `deny`}; `posture` ∈ {`authorized`, `unauthorized`, `unavailable`, `refused-oversize`, `refused-outside-root`, **`not-implemented`**}. The new value carries #67 D7's requirement that a record distinguish **decided-and-not-performed** from decided-and-done — an enumerated term that is permitted and then answered `NotImplemented` records `result: permit` with `posture: not-implemented`, so a Permit-then-NOOP can never read as a completed action.

**Scope.** Verb-decided request records only, as with the previous amendment. The boot posture record carries `hrot_sealed` / `plaintext_degraded` / `unverified` and is deliberately OUTSIDE this domain. The transport/boot pseudo-actions (`connect`, `read`, `decode`, `authz`, `posture`) are not PDP actions and keep their names. **No verb's action string may equal a pseudo-action** — nothing structural enforces this now that the `acp.` prefix is gone, so it is a test obligation.
