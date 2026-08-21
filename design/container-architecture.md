# Container Architecture and Language Calls

| | |
|---|---|
| **Status** | Draft — for team review; language calls are operator-ratified where marked, proposed otherwise |
| **Date** | 2026-07-14 |
| **Scope** | Container decomposition for both deployment models (Compose/Podman stack; full Kubernetes), per-container language selection, trust levels, volumes |
| **Doctrine** | Language targets best fit for the action being done. Kernel is 100% Rust (operator-ratified 2026-07-14). TDD everywhere (§5). |

---

> **Currency note (reconciled 2026-08-22).** This is 2026-07-14 design intent; per the AGENTS.md authority guard, the accepted **ADRs win** wherever they and this doc disagree. **Still current:** the container decomposition and the language-per-action doctrine. **Superseded, and corrected inline below:**
> - **Authorization is modular, not "pick Cedar."** Policy is decided behind the versioned, policy-agnostic **`maknae-security` seam** with pluggable **`maknae-authz-*` backends** ([ADR-0004](adr/ADR-0004-modular-authorization-architecture.md)) — a bundled RBAC default (`maknae-authz-basic`), plus optional DCS / Cedar / SELinux backends. This **supersedes the KLC §14-Q5 "Cedar vs. OPA spike"** framing (§3.1, §6, §7): Cedar is now one *optional* backend ([ADR-0003](adr/ADR-0003-cedar-policy-engine.md), **superseded**), not a spike to be won.
> - **DCS enforcement is external.** The classification lattice, SPIF, dominance engine, and any at-rest label projection **relocated to the private `rust-dcs` library** (ADR-0008/0017 relocated), reached only through the seam. The **PostgreSQL RLS-from-SPIF backstop** described in §2 / §3.9 / §6 ("fourth projection", "Security MCP harvest", "Cedar interaction") is superseded — its "ratified 2026-07-15" status does **not** survive.
> - **The at-rest data store is an open requirement, not settled.** Whether and how operational state is stored and label-enforced at rest is tracked in **#2** (storage / label-integrity) and **#20** (vendor-substrate trust locus); the direction under consideration is **Apache Accumulo** cell-level visibility, *not* the ratified PostgreSQL RLS below.
> - **Locus, lifecycle, audit, vocabulary are fixed by ADRs:** [ADR-0005](adr/ADR-0005-enforcement-locus-tcb-boundary.md) (split-kernel, mTLS, sole PDP), [ADR-0018](adr/ADR-0018-local-plane-authorization-deployment-model.md) (local-plane authz + enrollment), [ADR-0019](adr/ADR-0019-audit-record-model.md) (audit record model), [ADR-0020](adr/ADR-0020-access-control-model-and-vocabulary.md) (RBAC/ABAC over DAC/MAC, deny-overrides, no clearance bypass).

## 1. Principles

1. **One trust plane, few trusted containers.** The kernel and the egress enforcement point are the only containers whose compromise defeats the architecture. Everything else is constrained by them, not trusted alongside them.
2. **Language per action.** Precedent is the operator's Security MCP server (Go gateway/query services, Python parser, Rust proxy, TypeScript UI): pick the language whose ecosystem and guarantees fit the container's job, not a house language. Pattern inheritance from the upstreams is language-independent (autopsy, open item 3).
3. **The runtime plane is untrusted by design** (KLC §3). Its containers get velocity-optimized languages; correctness is enforced at the kernel boundary, not assumed in the runtime.
4. **Both deployment models from birth.** Every container ships with a Compose/Podman definition and a Kubernetes manifest, STIG-default configurations and baselines assumed. Volumes are declared per container (§4); in Kubernetes, kernel-mediated flows become NetworkPolicies; in Compose, internal networks + the egress proxy enforce the same shape (TaeBot's scoped nftables table is the host-level reference).
5. **The runtime plane is stateless by declared design.** Untrusted containers hold no durable state; working sets check in and out through kernel-mediated access to the state store. Compromise of the runtime leaks only its current working set; a crash loses nothing; "no read up" is enforceable at rest, not merely at retrieval time.

## 2. Container inventory

| # | Container | Plane | Trust | Language | Status |
|---|---|---|---|---|---|
| 1 | `kernel` | Trust | **Trusted** | **Rust** | **Ratified** |
| 2 | `egress-proxy` | Trust | **Trusted** | **Rust** | Proposed |
| 3 | `gateway` | Interaction | Security-relevant | **Go** | Proposed |
| 4 | `runtime` | Runtime | Untrusted by design | **Python** | Proposed |
| 5 | `lake` | Runtime (PIP) | Untrusted by design | **Python** | Proposed |
| 6 | `dreamer` | Runtime (scoped identity) | Untrusted by design | **Python** | Proposed |
| 7 | `web-ui` | Interaction | Security-relevant | **TypeScript** | Proposed; post-MVP |
| 8 | `vault-agent` | Cross-cutting | Vendor | n/a (HashiCorp image) | Ratified pattern |
| 9 | `state-store` | Data | Untrusted-adjacent (enforces, never decides) | ~~PostgreSQL + generated RLS~~ — at-rest store is the open **#2 / #20** decision (Accumulo direction) | **Superseded** — the 2026-07-15 ratification does not survive (Currency note) |

MVP builds six images (1–6); `web-ui` is deferred per the roadmap; `vault-agent` is a vendored image. *(The `state-store` row and its "PostgreSQL RLS live from Phase A" claim are **superseded** — see the Currency note; whether/how operational state is stored and label-enforced at rest is the open #2/#20 decision, direction Apache Accumulo, not the ratified PostgreSQL-RLS model.)* Consolidations are deliberate: the scheduler lives inside `gateway`, the skill registry and audit writer live inside `kernel`, and the memory subsystem co-locates with `lake` — each splits out later only under measured pressure, never speculatively.

## 3. Per-container detail

### 3.1 `kernel` — Rust (ratified)

The trust plane: PDP (the sole policy decision point, ADR-0005), label-schema enforcement, all six KLC hooks, skill-registry signature verification, and the append-only audit writer. Rationale for Rust: memory-safety CSI alignment (the language choice is a citable control), KLC §15 invariants encoded in the type system (illegal states unrepresentable — a `tier_ceiling` automation cannot raise, a downgrade constructible only from a consumed signed authorization), FIPS 140-3 via `aws-lc-rs` (Microkosmos precedent), static binary into a distroless/from-scratch image (TaeBot pattern). The kernel reaches policy through the **policy-agnostic `maknae-security` seam** and composes pluggable `maknae-authz-*` backends deny-overrides ([ADR-0004](adr/ADR-0004-modular-authorization-architecture.md), [ADR-0020](adr/ADR-0020-access-control-model-and-vocabulary.md)) — *superseding the KLC §14-Q5 "pick a policy engine" spike; Cedar is now one optional backend, not the engine.*

### 3.2 `egress-proxy` — Rust (proposed)

The single enforcement point for all outbound flows: model-endpoint calls (OAuth subscription + OpenAI-compatible registrations), learning fetches, and channel egress all transit it; the kernel decides, the proxy enforces (PEP). Holds the Hook E data path: destination allowlisting from the authority map, payload label screening, model-endpoint dominance checks as decided by the kernel. Rust for the same reasons as the kernel — this is the one other container whose compromise is architecture-defeating, and it terminates TLS with FIPS requirements. Microkosmos is the in-house precedent for a hardened Rust network data path. In Kubernetes this pairs with NetworkPolicies that force all egress through it; in Compose, internal networks make it the only externally-connected service besides `gateway`.

### 3.3 `gateway` — Go (proposed)

Channel adapter (Discord/Matrix/etc. per the team vote), operator authentication at the channel boundary (fail-closed allowlist — the one Hermes pattern adopted intact), session routing, and the scheduler (scoped task identities minted through the kernel, DCS labels bound at creation per KLC §6). Go rationale: static single binary into distroless images, strong concurrency for fan-out, mature channel SDKs (discordgo, mautrix-go), and team precedent in the Security MCP's Go services. TypeScript is the alternative if the team votes to vendor OpenClaw channel-adapter code; that vote rides with the channel vote. The gateway asserts operator identity; the kernel binds subject attributes and makes every decision — the gateway is security-relevant but never trusted with policy.

### 3.4 `runtime` — Python (proposed)

The agent loop: LLM conversation orchestration, tool invocation (via kernel-mediated grants), MCP client integrations (Security MCP first), gap detection, and learning-loop requests. Python rationale: best fit for the most experimental, fastest-iterating layer — the LLM/MCP SDK ecosystem is Python-first, Hermes' learning-loop concepts port naturally, and the layer is untrusted by design so its language guarantees are not load-bearing. Every privileged act transits the kernel; the runtime requests, never performs, lifecycle transitions.

### 3.5 `lake` — Python (proposed)

The portable Knowledge Lake instance plus the memory subsystem: quarantine ingest, label stamping (as directed by kernel decisions), retrieval serving (per-subject filtered context assembly), FTS-style memory recall. Python is inherited by construction — the lake framework tooling (compilers, gates, edge graph, query contracts from knowledgebase #201) is Python, and Maknae consumes it as the same artifact, not a port. Memory co-locates here at MVP (both are labeled-markdown-plus-index stores with one governance model); splits later if access patterns diverge.

### 3.6 `dreamer` — Python (proposed)

The out-of-band consolidation cycle (KLC §8 step 4): dedup, source revalidation, corroboration checks, memory distillation, skill-candidate refinement, promotion *proposals*. Architecturally separate container — never in-band with the runtime — running under its own scoped identity with no interactive privileges, on a schedule. Same image lineage as `lake` (different entrypoint) to start; the separation that matters is identity and invocation path, not build artifact.

### 3.7 `web-ui` — TypeScript (proposed; post-MVP)

Operator console: onboarding wizard (authority map authoring — emits operator-signed commits, never live mutations), audit review, promotion queue review, operator/attribute administration. TypeScript because the browser is the action; no other container speaks TS. Deferred behind the CLI per the roadmap — the CLI wizard proves the onboarding contract first.

### 3.8 `vault-agent` — vendor image

HashiCorp Vault Agent sidecar per service that needs secrets: AppRole auto-auth, short-TTL token to a tmpfs sink, services consume via native Vault API (no shell-outs, no templated files on disk) — the TaeBot `vault_bootstrap` pattern generalized, per the README's Vault-native ruling. Secrets engines are operator-configured, potentially independent per MLS secret target.

### 3.9 `state-store` — ~~PostgreSQL (ratified 2026-07-15)~~ **Superseded**

> **Superseded (Currency note).** The concept — a labeled operational-state store distinct from the Lake — may survive, but the **engine and enforcement below are not current**: the DCS lattice/SPIF and any at-rest RLS projection relocated to `rust-dcs`, and the at-rest store is the open **#2** (storage/label-integrity) / **#20** (vendor-substrate) decision, with **Apache Accumulo** cell-visibility the direction under consideration, not PostgreSQL RLS. The 2026-07-15 ratification does not survive. Text below is retained as the original design record.

The platform's labeled operational state: per-operator session/conversation state (born at the high-water mark of its inputs), scheduler task definitions, the memory recall (FTS) index, and the structured audit query surface. Knowledge stays in the Lake; Tier-0 config stays signed-git (the store may hold materialized copies for joins, never the authority). Every table carries the full DCS column set; label columns are `NOT NULL`; RLS policies are **generated from the SPIF** by trust-plane tooling and deployed with the migrations — `SET LOCAL` per-transaction subject attributes, `FORCE ROW LEVEL SECURITY`, non-superuser service roles without `BYPASSRLS`, deny-all default policies. Data plane, untrusted-adjacent: RLS *enforces* as the at-rest backstop (layer 3); the kernel remains the only decision-maker. Precedent: the Security MCP's PostgreSQL engine, with the RLS layer that project consciously deferred built here from birth.

## 4. Volumes (both deployment models)

| Volume | Mounted by | Notes |
|---|---|---|
| `lake-data` | lake (rw), dreamer (rw), kernel (label verification, ro) | The governed corpus; git-backed |
| `audit-log` | kernel (append-only) | Export/replication path is a later, kernel-mediated feature |
| `skill-registry` | kernel (rw), runtime (ro via kernel grants) | Signed manifests |
| `authority-config` | kernel (ro) | Tier 0: authority map, operator attributes, lattice + instance ceiling; changes arrive as signed commits, not writes |
| `vault-sink` | per-service tmpfs | Never a named persistent volume |
| `persona-workspace` | runtime (rw), gateway (ro) | Multi-file bundle, first-class (never runtime-flattened — the TaeBot/Hermes lesson) |
| `state-data` | state-store (pgdata) | Labeled operational state. *(The DCS-columns / generated-RLS / `pgdata` specifics are superseded — see §3.9 and the Currency note; the at-rest store is the open #2/#20 decision.)* |

## 5. TDD doctrine — tests as the mutation shield

The operator's established TDD pattern applies to every container, every language, from the first commit. In the AI-driven development model (autopsy §6.4) the test suite is not just correctness verification — **it is the mutation-proofing that makes delegating large implementation segments to AI agents (including HobiBot at will) safe**: a change that silently alters behavior fails a test it did not update, and the review conversation happens at the spec/test layer where the human architects operate.

Per-language toolchain calls:

| Language | Unit/TDD | Property-based | Mutation testing |
|---|---|---|---|
| Rust | `cargo test` | `proptest` | `cargo-mutants` |
| Python | `pytest` | `hypothesis` | `mutmut` |
| Go | `go test` | `rapid` | `go-mutesting` |
| TypeScript | `vitest` | `fast-check` | Stryker |

Two standards on top of volume:

1. **KLC §15 invariants become executable property tests** in every container that touches labels — the machine-readable block is the shared acceptance suite, implemented once per language and run in CI. A contract change without a corresponding test change fails review by definition.
2. **Mutation testing is the gate on the tests themselves.** A metric ton of tests proves nothing if the tests are slop too; mutation runs verify the suite actually kills behavior changes (*cadence superseded by ADR-0016: change-gated per-PR for security-critical crates + unconditional on merge to main — no longer "scheduled, not per-commit"*). Surviving mutants in trust-plane code are release blockers; in runtime-plane code they are backlog items.

## 6. Shared DCS capability strategy — one engine, not eight

The risk: six containers in four languages each growing their own label/lattice/policy logic. The strategy defeats it in three layers, in priority order:

1. **Architecture first: decisions are centralized, not distributed.** The kernel is the only decision-maker (PDP); every other container is a PEP that requests decisions and enforces outcomes. Five of six containers never evaluate policy — most of the duplication risk is eliminated by the plane model itself, not by libraries.
2. **Representation is schema-first.** The label block and the kernel decision request/response protocol are versioned schemas (JSON Schema at MVP); per-language types are generated, never hand-rolled. Every container can *parse and carry* labels; parsing is not evaluating.
3. **Local evaluation is one library with bindings — never a port.** Where a hot path justifies evaluating locally instead of calling the kernel, containers consume a single canonical implementation rather than each growing their own. Maknae's design intent is a **DCS-aware build that depends on the optional external DCS classification library** — consumed natively by the Rust trust-plane containers and via bindings by the Python containers. The identified hot path is the lake's per-subject retrieval filtering; whether it uses a kernel bulk-decision API or local bindings is decided by measurement — both run the same library against the same vectors. That library's implementation and design now live outside this repo (a separate private library); Maknae reaches it only through its own **policy-agnostic authorization seam**, so a non-DCS build — improving OpenClaw/Hermes without DCS awareness — stays a first-class configuration.

**Conformance vectors are the enforcement.** KLC §15 invariants plus label-dominance cases ship as language-neutral golden test vectors; every implementation that touches labels — the kernel, every binding, any future port — must pass the identical vectors in CI. Bindings prevent re-implementation; vectors catch divergence anyway.

**~~The state store's RLS predicates are a fourth projection…~~ — Superseded** (Currency note): the SPIF and any at-rest label projection relocated to `rust-dcs`, and the at-rest store itself is the open **#2 / #20** decision (Apache Accumulo direction), not the PostgreSQL-RLS-from-SPIF model described here.

**Security MCP harvest:** the Go ABAC gateway's *decision/label* semantics seeded the DCS engine, which **now lives in the external `rust-dcs` library** — that harvest is rust-dcs work, not in-repo (the Maknae-side issue closed as relocated). Its gateway *code* remains candidate vendoring for the Go `gateway` container (same language, same enforcement/identity-assertion job); decisions move to the kernel regardless.

**~~Cedar interaction~~ — Superseded:** there is no "Cedar wins the spike" branch. Cedar is an optional `maknae-authz-cedar` backend behind the seam ([ADR-0004](adr/ADR-0004-modular-authorization-architecture.md)) where a deployment's complexity or formal-verification needs justify it — never the platform's policy engine.

## 7. Open items

1. ~~Cedar vs. OPA spike (KLC §14 Q5).~~ **Resolved** — superseded by [ADR-0004](adr/ADR-0004-modular-authorization-architecture.md): authorization is the modular `maknae-security` seam + bundled `maknae-authz-basic` (RBAC) default, with Cedar an *optional* backend. No spike.
2. Channel vote decides `gateway` SDK details and whether the TypeScript alternative is live (§3.3).
3. Kubernetes profile specifics (PSA levels, NetworkPolicy set, operator vs. plain manifests) — after the Compose stack proves the shape.
4. Whether `egress-proxy` and `kernel` share an image with distinct entrypoints or build separately — decide at kernel-skeleton time; trust-plane review treats them as one surface either way.
5. ~~Maknae's authorization seam … is the next in-repo build.~~ **Done** — the seam is built (`crates/maknae-security`, [ADR-0004](adr/ADR-0004-modular-authorization-architecture.md)); the DCS library itself is external. Next in-repo build is the bundled `maknae-authz-basic` backend (#85) plus wiring per-request evaluation (#77).
