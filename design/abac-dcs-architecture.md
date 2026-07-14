# ABAC / DCS Architecture

| | |
|---|---|
| **Status** | Draft — rough architecture for team review; ratified decisions marked in the decision log (§16) |
| **Date** | 2026-07-15 |
| **Scope** | Attribute-Based Access Control and Data-Centric Security across all Maknae planes: subject attributes, identity, resource labels, enforcement layers, storage, audit, testing |
| **Audience** | Human reviewers and AI agents (dual-audience document) |
| **Depends on** | [`knowledge-lifecycle-contract.md`](knowledge-lifecycle-contract.md) (KLC — label schema, hooks, invariants), [`container-architecture.md`](container-architecture.md) (plane model, one-engine DCS strategy), [`adr/ADR-0002-kernel-is-rust.md`](adr/ADR-0002-kernel-is-rust.md), [`adr/ADR-0003-cedar-policy-engine.md`](adr/ADR-0003-cedar-policy-engine.md) |
| **Prior art** | Security MCP Server (`~/Development/MCP/security-mcp-server`) — working four-dimensional ABAC gateway, DCS schema, OAuth 2.1 compliance record |
| **Companion references (in-repo)** | [`references/dcs-schema-migration.md`](references/dcs-schema-migration.md) — the full DCS schema design (imported snapshot; the rationale this document cites instead of re-arguing); [`references/oauth-compliance.md`](references/oauth-compliance.md) — the 13-RFC OAuth 2.1 compliance matrix behind §5; [`references/nato-dcra-acp240-findings.md`](references/nato-dcra-acp240-findings.md) — NATO DCRA v2 / ACP 240 findings extract |

---

## 1. Purpose and doctrine

This document defines how Maknae decides and enforces *who may touch what data, under which labels, through which layers*. It composes the KLC's label schema and enforcement hooks with a concrete ABAC decomposition, an identity architecture, a platform state store, and a three-layer enforcement stack, harvesting the operator's Security MCP Server as the semantic reference implementation.

Doctrine, extending KLC §2:

1. **Breaches are cut off at the design stage** — not in an adverse kernel library file. Disclosure requires multiple independent, independently tested layers to fail identically. We do not disclose.
2. **Fail closed, everywhere.** Absence of a rule, an attribute, a label, a signature, or a reachable decision point is a denial. There is no grace mode, no cached-allow, no "starting with warnings."
3. **The lattice bottom is frictionless.** The default population of data is Open / Public / UNCLASSIFIED / UNRESTRICTED with no handling caveats — it needs no protection and gets no ceremony. Nothing is ever *silently assumed* open; everything is *cheaply declared* open: external content declares its label at ingest (declaring the bottom is one line; unlabeled content is rejected, KLC §6), and internally born data computes its label by construction (high-water mark of inputs — all-unrestricted inputs yield an unrestricted object). Protection effort scales with the label.
4. **One decision engine, N enforcement points, one at-rest floor.** The kernel is the only PDP. Every other surface enforces or backstops; none decides.

## 2. Standards base and conformance posture

### 2.1 Zero Trust / ABAC policy stack

Verified against the operator's knowledge lake (2026-07-15), not model memory:

| Authority | What it requires | How this architecture answers |
|---|---|---|
| NIST SP 800-207 (Zero Trust Architecture) | PE/PA/PEP separation; trust-algorithm inputs include a subject database of attributes; "privileges should be assigned to a subject on an individual basis and not simply because they may fit into a particular role" | Kernel = PE; PEPs throughout; per-request evaluation; roles grant administrative verbs only (§4 rule 2) |
| DoDI 8520.04 (Access Management, Sep 2024) | "Dynamic access": authorization at request time from digital policy rules over user + environment attributes, no provisioned entitlements; attributes only from authoritative attribute services (§3.4, §4.3) | Maknae is dynamic-access-native from birth; the Tier-0 signed attribute store + kernel binding is the authoritative attribute service; self-asserted claims are never an attribute source |
| DoD Enterprise ICAM Reference Design | Authorization = entity attributes × resource labels × policy; each attribute managed at a single authoritative source; self-asserted attributes are low-assurance | Single Tier-0 source per attribute; label-bound policy; no self-assertion |
| NIST SP 800-162 (ABAC), SP 800-205, NISTIR 8112 | ABAC definition, attribute considerations, attribute metadata | Cited through the ICAM RD's normative references; **full texts pending lake ingestion (§14)** — final design re-walks them |
| ICTS UIAS v2.1 (IC Unified Identity Attribute Set) | IC-standard subject attribute vocabulary | Cited as a **mapping profile**, not the base schema (§4). Note: UIAS is Intelligence Community vocabulary (per CNSSI 4009 sourcing); the DoD ICAM RD's own "Core Authorization Attributes" section is *reserved for a future version* — no DoD enterprise authorization attribute set exists yet to conform to |
| STANAG 4774 / 4778 / 5636, ACP 240 | Confidentiality labels, metadata binding, coalition DCS | Schema-ready at MVP (ported `label_id` placeholder); binding lands with OpenTDF (§11); ACP 240 conformance claimed only after the document is in hand (§14) |
| OpenTDF (github.com/opentdf) | Open-standard Trusted Data Format: ZTDF/nanoTDF, attribute-based key access | **Named implementation standard** for cryptographic label binding and object protection, adopted at MVP close (§11) |

### 2.2 Prior art: the Security MCP Server

The MCP is the working reference for every semantic in this document. Specific artifacts harvested:

| Artifact | Path (in the MCP repo) | What Maknae takes |
|---|---|---|
| Subject claims model | `containers/security-gateway/internal/middleware/claims.go` | Attribute dimensions (clearance, nationality, CUI/SCI/SAP as independent axes) |
| SPIF lattice | `containers/security-gateway/internal/labeling/spif.go` | Deployment-declared classification lattice concept (§6.4) |
| PEP entry point | `containers/security-query/internal/handlers/abac.go` | Subject-context pattern; the `NormalizeClearance()` taxonomy-mismatch lesson (§4 rule 4) |
| SQL-injection PEP | `containers/security-query/internal/database/repository.go` (`injectABACClause`) | Layer-2 enforcement pattern (§7.2) |
| ABAC test suites | `abac_test.go`, `abac_handlers_test.go`, SPIF tests | Seed corpus for the conformance vectors (§12) |
| DCS schema | `docs/design/dcs-schema-migration.md` — **imported in-repo as [`references/dcs-schema-migration.md`](references/dcs-schema-migration.md)** for reviewers without MCP repo access | Full label vocabulary port (§6.1); design rationale imported by reference, not re-argued |
| OAuth 2.1 compliance record | `docs/security/OAUTH-COMPLIANCE.md` — **imported in-repo as [`references/oauth-compliance.md`](references/oauth-compliance.md)** | The 13-RFC identity baseline (§5.1) and its operational scar tissue |

The structural upgrade over the MCP, stated plainly: the MCP fuses PDP and PEP inside `security-query` — its WHERE clause *is* the policy — and delivers subject attributes as IdP-asserted JWT claims. Maknae splits decision from enforcement (Cedar decides; PEPs enforce; RLS backstops) and moves attribute binding out of the token entirely (§5.3). The MCP also consciously deferred PostgreSQL RLS; Maknae builds it from birth on empty tables — the MCP migration doc's own "cost if deferred" analysis is the argument.

## 3. ABAC decomposition and container mapping

The classic NIST AC-3/AC-4 decomposition, mapped deliberately so anyone who knows the MCP reads Maknae, and vice versa:

| ABAC role | Security MCP (prior art) | Maknae |
|---|---|---|
| PIP — subject attributes | `security-gateway` extracts UIAS claims from the JWT | `gateway` asserts operator identity; **kernel binds attributes** from the Tier-0 signed store |
| PIP — resource attributes | `security-parser` stamps markings at ingest | `lake` stamps labels at ingest as directed by kernel decisions (hook A); state-store rows are born labeled (§6.3) |
| PDP | `security-query` (fused with PEP) | **`kernel` only** (Cedar, ADR-0003) |
| PEP | `security-query` WHERE-clause injection | Every container enforcing a kernel decision: `egress-proxy` (hook E), data-access layers (hook B), skill sandbox (hook F) |
| At-rest backstop | Deferred (RLS planned, never built) | **PostgreSQL Row-Level Security**, built from birth (§7.3) |
| Presentation | `security-ui` displays, never enforces | `web-ui` — identical doctrine |

### 3.1 Container inventory change: the state store

**`state-store` (PostgreSQL, vendor image + Maknae migrations) joins the container inventory as container #9** — data plane, untrusted-adjacent like `lake`: its RLS *enforces*, but it never *decides*; policy arrives as generated predicates from trust-plane tooling. Volume: `state-data` (pgdata).

Rationale — knowledge and state are different data:

- **Governed knowledge** (documents, skills, memory content) lives in the Lake: markdown, YAML frontmatter labels, KLC lifecycle, git-distributed. Unchanged by this document. The Lake is the agent's long-term learned resource, built up over time; it is deliberately secondary to the platform.
- **Operational state** is what an agent *platform* generates by running: per-operator session/conversation state (which carries the high-water mark of everything retrieved into it, KLC §6), scheduler task definitions (label-bearing by KLC ruling), the memory recall index (FTS), and audit events. These are labeled, subject-scoped, mutable rows — they need a governed home with labels traveling in the schema.

**The runtime plane is stateless by declared design** (new principle for container-architecture §1): untrusted containers hold no durable state; working sets are checked in and out through kernel-mediated access to the state store. Compromise of the runtime leaks only its current working set; a crash loses nothing; "no read up" is enforceable at rest, not merely at retrieval time. In the MCP, the database made sense because the LLM never touches it; in Maknae the same property is achieved by construction — the runtime touches state only through the kernel's decisions.

Boundaries that keep the store honest: Tier-0 configuration (authority map, operator attributes, lattice/SPIF, endpoint registrations) stays signed-git as the source of truth — the state store may hold a materialized copy for joins, never the authority. And the Lake stays markdown — the state store never becomes a shadow knowledge base.

## 4. Subject attribute model

Every request resolves to an authenticated **operator** carrying a kernel-bound attribute set. Scoped task identities (scheduler, dreamer) are just subjects with narrow attribute sets. The schema generalizes the MCP's claims model beyond the government case:

```yaml
operator: alex                        # stable subject id
attributes:
  clearance: unclass                  # point in the deployment lattice (level)
  communities: []                     # category/releasability sets, e.g. [REL-AUS, REL-KOR]
  nationality: USA                    # GENC trigraph; drives releasability dominance
  handling_grants: [health-self, finance-self]   # civilian regimes: which handling
                                                 # domains this operator may touch
  roles: [owner]                      # administrative verbs ONLY — never data access
```

**Environment attributes** are the third input class (per SP 800-207 and DoDI 8520.04), named explicitly: time, network location, host/sandbox posture (already an attested policy input at hook F), channel origin. They ride in Cedar's `context`, supplied by the requesting plane and attested where the platform can attest them.

Load-bearing rules:

1. **Attributes live in the Tier-0 signed store** (`authority-config` volume), materialized into the state store for joins but never authoritative there. The gateway authenticates *who*; only the kernel binds *what they are*. No self-asserted attributes.
2. **Roles grant administrative verbs, never data width** — the MCP's "I'm an admin, but it doesn't matter" model, and SP 800-207's stated position, ported verbatim. An administrator without `health-self` cannot read health rows; an administrator without a community cannot read that community's rows.
3. **Scoped task identities re-evaluate at fire time.** A recurring task carries labels bounded by its creator's attributes at creation; attribute or registration drift at fire time fails the task closed (KLC-settled).
4. **The taxonomy mismatch is unrepresentable.** The MCP needed `NormalizeClearance()` because personnel-clearance vocabulary (TS_SCI) and data-classification vocabulary (TOP_SECRET) diverged. Maknae declares **one lattice per deployment; subject attributes and resource labels are both points in it.** The SPIF (§6.4) is the single vocabulary source.

**Attribute vocabulary is deployment-configurable** (the KLC portability rule: no baked-in hierarchy). The base schema above is the platform contract; an **ICTS UIAS v2.1 mapping profile** ships for IC/enclave deployments, and civilian profiles (health, financial, development) ship as samples. Maknae cites UIAS as a profile, not as its base standard — see §2.1 for the provenance note.

## 5. Identity architecture

Identity is the authentication front door that feeds §4. The design rule learned from the MCP: get the OAuth RFC set right up front.

### 5.1 Inherited RFC baseline

Adopted wholesale from the MCP's compliance record (in-repo companion: [`references/oauth-compliance.md`](references/oauth-compliance.md), 13/13 RFCs implemented — per-RFC requirements, evidence, and NIST mappings live there):

- **OAuth 2.1 consolidated requirements** — PKCE S256 mandatory for all clients; implicit and resource-owner-password grants prohibited; refresh token rotation; exact redirect URI matching; bearer tokens via `Authorization` header only (RFC 6750)
- **RFC 8707 Resource Indicators** — audience binding on every token; the critical anti-replay control; validation is mandatory and construction-guarded
- **RFC 8414 / RFC 9728** — AS metadata and protected-resource metadata discovery
- **RFC 9068** — structured JWT access tokens
- **RFC 7591 DCR + CIMD** (`draft-ietf-oauth-client-id-metadata-document`) — dynamic client registration with policy fences (consent required, full-scope disabled, scope allowlists, client caps, TTL cleanup)
- **JOSE (RFC 7515/7517/7518) with a FIPS algorithm allowlist** — RS256/384/512, ES256/384 only; HS*/PS*/EdDSA/none rejected; enforced twice (parser config + post-parse check); `aws-lc-rs` in Maknae's Rust perimeter rather than the MCP's BoringCrypto
- **RFC 9110/9111** — HTTPS-only OAuth URLs, validated at startup
- Operational patterns: JWKS caching with automatic rotation; zero-PII identity hashing (§10); STIG-aligned session lifetimes

### 5.2 Three OAuth surfaces (the MCP had one)

1. **Inbound — operators authenticating to Maknae** (web-ui, API surfaces, any future MCP-server surface). Maknae is the Resource Server. **Maknae is never the Authorization Server**: identity is not the platform's business, and DoDI 8520.04 wants authoritative sources. The operator federates an external OIDC/OAuth 2.1 IdP (Keycloak, Authentik, Dex, or a CAC/PIV-backed enterprise IdP at the north star). Maknae requires of the IdP exactly what the baseline requires: RFC 8414 discovery, PKCE S256, RFC 9068 tokens, FIPS-listed algorithms. The platform marries the RFC contract, never the IdP product — the MCP's Keycloak-removal effort is the baked-in cautionary tale.
2. **Outbound — Maknae as OAuth client**: model-provider subscription auth (MVP item 1) and MCP client connections (Security MCP first). Token acquisition lives in `gateway`/`runtime`; tokens are stored only in Vault, transit only the `egress-proxy`, and every outbound token use is a hook E decision. Maknae implements CIMD correctly as a client against servers that support it.
3. **Internal — the seam that feeds ABAC.** The token asserts **identity only** (`iss`+`sub`, session, client scopes). At the gateway boundary, identity resolves to an operator record; **the kernel binds attributes from the Tier-0 store — claims in the JWT are never the attribute source.** This is the deliberate divergence from the MCP (where `uias_*` claims ride in the token, making the IdP the attribute PIP). **Scopes gate what a client application may request; attributes gate what an operator may see. Two axes, never conflated.**

## 6. Resource label model

### 6.1 Full DCS schema port

The complete `dcs` schema from the MCP ports as Maknae's label vocabulary — this is a port of a built artifact, not a new design. Inventory: classification ENUM (5-level, orderable for RLS), CUI columns (categories, specified flag, the complete NARA LDC vocabulary, DI-block fields), classified dissemination controls, `rel_to_nations` / `display_only_nations` (GENC trigraphs + coalition tetragraph tables), the `noforn` fast-predicate boolean, JOINT/FGI ownership (`document_type`, `owner_nations`, `fgi_source_nations`, concealed-source support), distribution statements (DoDI 5230.24 A–F), marking abbreviation registry, the 14-framework international classification systems registry, the 16-law data privacy frameworks registry, `classification_confidence` (spillage detection), atomic-energy/SAP/SCI and declassification fields (Phase B `confidentiality_labels`), and the STANAG 4774 `label_id` placeholder. Design rationale imports by reference to the in-repo companion [`references/dcs-schema-migration.md`](references/dcs-schema-migration.md) §4–§22; this document does not re-argue it.

### 6.2 One logical schema, two physical projections

- **YAML frontmatter** on lake objects (KLC §6 — already specified)
- **DCS columns** on state-store rows (sessions, tasks, memory index, audit)

Same vocabulary, same lattice, both projections generated from `maknae-dcs-core`'s types (container-architecture §6: schema-first; per-language types generated, never hand-rolled). A label crossing from a lake document into a session row survives the projection change bit-for-bit.

### 6.3 What Maknae adds to the MCP schema

The fields that make this an *agent* platform:

- **KLC lifecycle axis** — `tier`, `tier_ceiling`, provenance/lineage, freshness — orthogonal to classification (KLC §5 ruling: lifecycle answers "how trusted is this object"; the lattice answers "who may see it")
- **`subject` ownership** — operator-owned rows (health, financial, personal memory) join against `handling_grants`; cross-subject access is an explicit grant, deny by default
- **Handling caveats** — `no-egress`, `operator-only`, enforced at hooks B/E
- **Certification-gate state** (§6.5)
- **High-water-mark derivation** — session/context rows are born labeled at the join (lattice max) of everything retrieved into them (hook C); internally born state is never unlabeled

### 6.4 The SPIF: one vocabulary source, three enforcement surfaces

The deployment's lattice declaration — levels, category sets, releasability communities, handling domains, equivalency maps — is a Tier-0 artifact (port of the MCP's `labeling/spif.go` concept into signed configuration, STANAG 4774-shaped). It compiles three ways from one file at kernel load:

1. **Cedar entities/policies** (the PDP's vocabulary)
2. **RLS predicates** (the at-rest backstop, §7.3)
3. **Label validators** (ingest and write-path schema enforcement)

One vocabulary, three surfaces, zero drift by construction — divergence is a boot failure (§9.1), not a runtime discovery.

### 6.5 Restricted-category certification gate

The schema supports every category from birth; certification is a separate, explicit state:

1. **Undeclared category** → ingest refused (hook A dominance check against the instance ceiling; KLC-settled, cannot be weakened without violating KLC §15).
2. **Operator-declared but uncertified** → ingest and processing proceed, and every touch of that data stamps a persistent, un-silenceable **"NOT CERTIFIED for [category]"** warning into logs, UI banners, and audit events. Conscious opt-in, loud until certified.
3. **Certified** → a certification reference (accreditation artifact) recorded in Tier-0 config silences the warning. No code changes.

The base deployment ships with zero certified restricted categories. GDPR/PII/PHI regimes are the expected first users of this gate — deferred from MVP as *certifications*, present from birth as *schema*.

## 7. Enforcement architecture: three layers

Ratified approach (2026-07-14): decision, enforcement, and at-rest layers, each of which independently denies.

### 7.1 Layer 1 — Decision (kernel, Cedar)

All six KLC hooks are Cedar evaluations over (principal = operator or task identity, action, resource = labels, context = environment attributes). The SPIF and the operator attribute store compile to Cedar entities at kernel load (ADR-0003's compilation contract). Deny by default; forbid overrides permit.

### 7.2 Layer 2 — Enforcement (PEPs)

For the state store: the port of the MCP's `injectABACClause` pattern. Every data-access method takes a **kernel-minted subject context** — a short-lived, signed attribute snapshot — and injects label predicates into its queries. The subject context is issued once per session/task and re-validated on TTL expiry or attribute drift, keeping the kernel off the per-query hot path (mirroring the MCP's per-request rather than per-row stamping). An expired or absent subject context is a denial.

The lake's per-subject retrieval filtering — the identified hot path — uses either a kernel bulk-decision API or local `maknae-dcs-core` bindings; the choice is made by measurement, and both run the same crate against the same vectors (container-architecture §6, unchanged).

### 7.3 Layer 3 — At-rest backstop (PostgreSQL RLS)

RLS policies are **generated from the SPIF**, never hand-written: dominance predicate over the classification ordinal + releasability array containment + `noforn` + `subject`/`handling_grants` join. The plumbing that makes RLS real rather than decorative:

- Subject attributes arrive as **per-transaction `SET LOCAL` GUCs** — pool-safe; no attribute bleed between pooled connections
- All policies created with **`FORCE ROW LEVEL SECURITY`** — the table owner is constrained too
- Service roles are non-superuser with no `BYPASSRLS`
- **Deny-all default policy** — an unconfigured or unpoliced table returns zero rows
- Label columns are `NOT NULL` — an unlabeled row is unrepresentable at the type level

RLS failure mode is always *fewer* rows. Disclosure requires Layer 2 and Layer 3 to fail identically — and they are implemented independently and tested against identical vectors (§12).

## 8. Worked data flows

### 8.1 Civilian: health assistant (TaeBot-class deployment)

Operator asks their health-assistant persona for a training summary: operator authenticates (OAuth 2.1, §5) → kernel binds attributes (`handling_grants: [health-self]`) → runtime requests retrieval (hook B) → lake and state store filter per-subject; RLS backstops the state-store query → context assembles, labeled at the high-water mark of its inputs (here: `health` handling, unrestricted classification) → model routing (hook E) requires an endpoint whose labels dominate the payload mark — health-labeled context routes only to endpoints the operator's deployment authorized for health data → egress-proxy enforces; any `no-egress` content is blocked at the body → response rendered; audit events at every hop. A second operator on the same instance without a grant to this subject's health data retrieves *nothing* — non-disclosing filtering: for them, the data does not exist.

### 8.2 Coalition: notional Mission Partner Environment deployment

A combined task force enclave — deliberately notional, no real systems named — running the same kernel at **SECRET//REL** to a three-nation coalition, air-gap-capable (KLC §12), every model endpoint local and accredited:

- The instance ceiling declares SECRET + the coalition releasability set; ingest above or outside it refuses on import regardless of the sending site's accreditation (KLC-settled).
- Partner-nation operators are attribute-bearing subjects: nationality + communities drive releasability dominance. An operator from nation B retrieving mission knowledge marked REL to nations A and C gets non-disclosing filtering — no residue, no "access denied" leakage about what exists.
- A scheduled analysis task created by a nation-A operator carries REL labels bounded by its creator's attributes; if the endpoint registration or the operator's attributes drift before fire time, the task fails closed and logs for operator review.
- NOFORN-marked rows never join a payload routed to any endpoint — the `noforn` predicate is enforced at Layers 2 and 3, and hook E's dominance check makes a non-eligible endpoint unreachable for the payload regardless.
- Audit review is itself ABAC-filtered (§10): a partner-nation auditor sees exactly the audit slice their attributes dominate.

Nothing in this deployment is a special mode: it is §8.1's kernel with a richer lattice and a stricter map.

## 9. Failure modes

### 9.1 Boot-time validation — the Microkosmos model

The kernel refuses to start on invalid security configuration, period (in-house precedent: Microkosmos's fail-on-bad-config startup). Process exits nonzero; no degraded mode. Boot-blocking checks:

1. SPIF lattice well-formed (a valid partial order; category sets internally consistent)
2. Authority map: schema-valid and operator-signature-verified
3. Operator attribute store: schema-valid and signature-verified
4. Cedar policy set: schema validation passes; conformance vectors (§12) pass against the loaded policy set
5. Generated RLS predicates match deployed database policies (parity hash) — drift is a boot failure
6. FIPS module self-checks pass
7. Instance ceiling present and dominated by the declared lattice

A trust plane that boots on a bad configuration is a breach with extra steps.

### 9.2 Runtime fail-closed matrix

Each row is a testable acceptance criterion (§12):

| Failure | Behavior |
|---|---|
| Kernel unreachable | Every PEP denies. No cached-allow; a subject context past TTL is a denial |
| Attribute/registration drift at task fire time | Task fails closed; logged for operator review |
| Object missing required labels at ingest | Rejected, never defaulted (KLC §6; declaring the lattice bottom is the cheap, explicit path) |
| State-store row without labels | Unrepresentable: `NOT NULL` label columns + deny-all default RLS policy |
| PEP bug / predicate omission | RLS backstop returns fewer rows; single-layer failure discloses nothing |
| Egress-proxy policy failure | Destination denied; allowlist-shaped screening means unknown = blocked |
| Vault sealed / secret unavailable | Service refuses to start; no plaintext fallback exists |
| Uncertified-category data touched | Operation proceeds (category was operator-declared) with the un-silenceable NOT-CERTIFIED warning (§6.5) |

## 10. Audit

Kernel-owned, append-only (existing `audit-log` volume; state-store audit tables are the structured query surface over the same events). Three ports from the MCP plus one MLS upgrade:

1. **Zero-PII identity hashing** — SHA-512(subject + session salt); attributes logged, `sub` never stored in cleartext (the MCP's PT-2/AU-10 pattern verbatim)
2. **Determining-policy diagnostics** — every decision event records which Cedar policies determined the outcome; the audit answers *which policy*, not just *what happened*
3. **Before/after labels** on every lifecycle transition (KLC §15: `every_transition: audited`)
4. **Audit records are themselves labeled rows** — an audit event describing a SECRET//REL retrieval inherits that label; audit review is ABAC-filtered like everything else. Audit is not a side channel around the lattice.

**Spillage response:** `classification_confidence` flags suspect rows; response is the existing KLC demotion machinery — quarantine, purge with retained audit record — plus an operator incident event. No automated downgrade, ever (KLC §15).

## 11. OpenTDF: the label-binding implementation standard

**OpenTDF (github.com/opentdf) is the named open-standard implementation for cryptographic label binding and object protection**, adopted at MVP close (Phase B entry, §13). It converges four threads:

- **STANAG 4778 metadata binding** — cryptographic binding of the confidentiality label to the object, which schema columns alone cannot provide
- **The ported `label_id` placeholder** — the MCP schema's STANAG 4774 hook gets a concrete format instead of a someday
- **Attribute-based key access** — TDF's key-access model (KAS) is ABAC applied to key release, the same (subject attributes × data labels) decision this architecture already centralizes
- **Ecosystem interoperability** — IC-EDH/ZTDF alignment; labeled objects survive transit between Maknae instances and third-party DCS tooling with labels cryptographically attached (the KLC §12 replication story, strengthened)

Scope discipline: MVP ships the schema, RLS, and signed-git label integrity; OpenTDF lands immediately after as the binding/wrapping layer for objects that leave the platform boundary (egress, replication, sneakernet bundles) and as the candidate at-rest format for restricted-category payloads. Open design questions — KAS placement (in-kernel vs. trust-plane sidecar), nanoTDF for small payloads, and how far TDF wrapping extends inside the boundary — are Phase B design work (§17), informed by the operator's OpenTDF/DSP operational experience.

## 12. Testing and conformance

**Conformance vectors are the single spine.** Language-neutral golden vectors (KLC §15 invariants + lattice dominance cases + releasability/handling/NOFORN cases), seeded by harvesting the MCP's ABAC and SPIF test suites — they encode adjudicated real-world semantics, not invented examples. Every surface that touches labels passes the *identical* vectors in CI:

1. `maknae-dcs-core` (Rust) and its PyO3 bindings
2. The Cedar policy set (policies are data; tested per ADR-0003)
3. **The generated RLS policies** — vectors execute against real PostgreSQL in CI (containerized): insert labeled rows, set subject GUCs, assert exact row visibility

If the kernel and the database ever disagree about who sees a row, CI fails before a human could.

**Property tests** (`proptest`): dominance is a partial order (reflexive, antisymmetric, transitive); high-water-mark derivation is a lattice join; generated RLS predicates are monotone (adding a category never widens visibility). **Mutation testing** gates the tests themselves; surviving mutants in trust-plane label code are release blockers (container-architecture §5).

**Negative testing is first-class:** every row of the §9.2 matrix becomes a test; the §8 worked flows become end-to-end acceptance tests including their adversarial variants (REL drift at fire time, cross-subject health query, NOFORN payload at an eligible-but-foreign endpoint, boot with tampered SPIF).

## 13. Growth path

| Phase | Scope |
|---|---|
| **A (MVP)** | Full schema present (§6.1); core lattice + handling + subject scoping enforced at all three layers; RLS live with generated policies; boot-time validation; certification gate warning loudly; conformance vectors in CI |
| **B (MVP close / post-MVP)** | OpenTDF binding layer (§11); STANAG 4774 `confidentiality_labels` + 4778 binding tables activated; KAS placement decided; ACP 240 gap analysis once the document is in hand |
| **C** | Coalition apparatus fully exercised (JOINT/FGI/tetragraph workflows); certification workflow tooling; cross-instance labeled replication at MLS |

Phasing mirrors the MCP's migration strategy: schema early on empty tables, apparatus activated when the consuming code exists.

## 14. References required before final design

Rough design binds to none of these documents' unread details; final design review re-walks each. Tracked here so the gap is explicit:

| Reference | Status | Feeds |
|---|---|---|
| ACP 240 | Findings extract in-repo ([`references/nato-dcra-acp240-findings.md`](references/nato-dcra-acp240-findings.md)); full text acquisition pending (operator) | Coalition DCS conformance (§2.1, §13 Phase B) |
| NIST SP 800-162 (ABAC) | Downloaded; lake ingestion pending | §2.1 conformance claims |
| NIST SP 800-205 / NISTIR 8112 | Downloaded; lake ingestion pending | Attribute metadata/assurance details (§4) |
| ICTS UIAS v2.1 | Not held | The UIAS mapping profile (§4) |
| STANAG 4774 / 4778 / 5636 full texts | Not held | Label/binding formats (§6.4, §11) |
| CNSSI 1253 + Classified Overlay | In lake | North-star categorization (§8.2) |
| OpenTDF platform spec | Public (github.com/opentdf) | §11 design work |

## 15. Security control mapping (informative)

Delta over the KLC §13 and ADR mappings — rows specific to this document:

| Element | NIST SP 800-53 rev 5 |
|---|---|
| Three-layer enforcement (PDP / PEP / RLS backstop) | AC-3, AC-4, AC-6; SC-3 (security function isolation — decision isolated from enforcement) |
| Subject attributes from authoritative signed store; no self-assertion | IA-2, AC-16; DoDI 8520.04 §3.4/§4.3 alignment |
| OAuth 2.1 identity front door (RFC baseline §5.1) | IA-2, IA-5(2), IA-8, SC-8, SC-13, SC-23 |
| Bell-LaPadula dominance at three layers; no automated downgrade | AC-3(3), AC-4, AC-16(6) |
| Labels travel with data (frontmatter + columns); SPIF single source | AC-16, SC-16 |
| RLS backstop; deny-all default policies; FORCE RLS | AC-3, SC-7 (internal boundary), CM-7 |
| Boot-time configuration validation (fail to start) | CM-6, SI-10; SA-8 (fail-secure design principle) |
| Zero-PII audit with determining-policy diagnostics; labeled audit rows | AU-2, AU-3, AU-9, AU-10, PT-2 |
| Certification gate for restricted categories | CM-3, PL-2 (documented deviation with visibility); PT-2 (privacy regimes) |
| OpenTDF cryptographic label binding (Phase B) | SC-13, SC-16(1), SC-28 (at-rest protection for restricted payloads) |
| Conformance vectors + mutation gates on label logic | SA-11, SI-10 |

Full matrix belongs in the RMF package, not this document.

## 16. Decision log

All decisions operator-ratified 2026-07-14/15 during design review:

| # | Decision |
|---|---|
| D1 | PostgreSQL `state-store` joins as container #9 (data plane); Lake unchanged; runtime plane stateless by design |
| D2 | Full DCS schema port from the MCP, including coalition apparatus and privacy frameworks registry |
| D3 | Restricted-category certification gate: undeclared → refused; declared-uncertified → loud persistent warning; certified → silent (§6.5) |
| D4 | Three-layer enforcement (Approach B): Cedar PDP → PEP query injection → generated RLS backstop |
| D5 | Subject attribute schema per §4; roles are administrative verbs only; environment attributes named as the third input class |
| D6 | UIAS cited as an IC mapping profile, not the base standard (provenance: ICTS UIAS v2.1; ICAM RD core authorization attributes reserved) |
| D7 | OAuth 2.1 RFC baseline inherited from the MCP; Maknae is never the Authorization Server; tokens assert identity only — attributes never ride in claims |
| D8 | One logical label schema, two projections (frontmatter, columns), generated from `maknae-dcs-core` types |
| D9 | Kernel-minted subject contexts keep the kernel off the per-query hot path; RLS plumbing: `SET LOCAL` GUCs, `FORCE RLS`, no `BYPASSRLS`, deny-all defaults, `NOT NULL` labels |
| D10 | Fail closed everywhere; lattice bottom (open/unrestricted data) is frictionless — declared, never assumed |
| D11 | Boot-time validation on the Microkosmos model: invalid security config = refusal to start |
| D12 | Audit rows are labeled; audit review is ABAC-filtered; zero-PII identity hashing ported |
| D13 | Use-case trio spans the spectrum: dev/PR agent (proprietary code), health assistant (PHI-class), notional MPE SECRET//REL coalition enclave |
| D14 | OpenTDF named as the label-binding implementation standard, adopted at MVP close |
| D15 | Conformance vectors (including RLS-in-CI against real PostgreSQL) are the single conformance spine |
| D16 | ACP 240 added to normative guidance; §14 required-references list gates final design |

## 17. Open questions

1. **KAS placement** (Phase B): in-kernel, trust-plane sidecar, or vendored OpenTDF platform service? Interacts with the container-architecture trusted-surface count.
2. **Bulk-decision API vs. local crate bindings** for the lake hot path — decided by measurement (container-architecture §6; restated here because the RLS layer changes the calculus for state-store queries specifically).
3. **Connection architecture for the state store** — per-service pools vs. a pooler (pgBouncer) given `SET LOCAL` transaction-scoped attributes; pooler transaction-mode compatibility must be proven in the vectors.
4. **Internal service-to-service credential format** — kernel-minted subject contexts need a concrete envelope (JWT with RFC 8707 audience binding vs. a bespoke signed structure); leans JWT for tooling reuse, decide at kernel-skeleton time.
5. **Audit store ceiling** — does the audit table inherit the instance ceiling, or is a dedicated lower-ceiling audit-export path needed for cross-domain review? North-star question; defer past MVP but leave the schema room.
6. **TDF wrapping scope inside the boundary** — egress/replication only, or also at-rest for restricted-category payloads? Phase B, informed by measured cost.

## 18. Revision history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-07-15 | Initial rough architecture from operator-guided design session: ABAC decomposition, state-store container, subject attribute model + identity architecture, full DCS schema port, three-layer enforcement, fail-closed doctrine, OpenTDF adoption, conformance spine |
| 0.2 | 2026-07-15 | Companion references imported in-repo (`design/references/`): full DCS schema design and NATO DCRA/ACP 240 findings, for reviewers without Security MCP repo access; retention before public release is an open decision. §14 ACP 240 status updated |
| 0.3 | 2026-07-15 | Third companion imported: the OAuth 2.1 13-RFC compliance matrix (`references/oauth-compliance.md`) — the RFC set §5 inherits, now reviewable in-repo |
