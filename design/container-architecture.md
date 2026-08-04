# Container Architecture and Language Calls

| | |
|---|---|
| **Status** | Draft — for team review; language calls are operator-ratified where marked, proposed otherwise |
| **Date** | 2026-07-14 |
| **Scope** | Container decomposition for both deployment models (Compose/Podman stack; full Kubernetes), per-container language selection, trust levels, volumes |
| **Doctrine** | Language targets best fit for the action being done. Kernel is 100% Rust (operator-ratified 2026-07-14). TDD everywhere (§5). |

## 1. Principles

1. **One trust plane, few trusted containers.** The kernel and the egress enforcement point are the only containers whose compromise defeats the architecture. Everything else is constrained by them, not trusted alongside them.
2. **Language per action.** Precedent is the operator's Security MCP server (Go gateway/query services, Python parser, Rust proxy, TypeScript UI): pick the language whose ecosystem and guarantees fit the container's job, not a house language. Pattern inheritance from the upstreams is language-independent (autopsy, open item 3).
3. **The runtime plane is untrusted by design** (KLC §3). Its containers get velocity-optimized languages; correctness is enforced at the kernel boundary, not assumed in the runtime.
4. **Both deployment models from birth.** Every container ships with a Compose/Podman definition and a Kubernetes manifest, STIG-default configurations and baselines assumed. Volumes are declared per container (§4); in Kubernetes, kernel-mediated flows become NetworkPolicies; in Compose, internal networks + the egress proxy enforce the same shape (TaeBot's scoped nftables table is the host-level reference).
5. **The runtime plane is stateless by declared design** ([abac-dcs-architecture §3.1](abac-dcs-architecture.md)). Untrusted containers hold no durable state; working sets check in and out through kernel-mediated access to the state store. Compromise of the runtime leaks only its current working set; a crash loses nothing; "no read up" is enforceable at rest, not merely at retrieval time.

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
| 9 | `state-store` | Data | Untrusted-adjacent (enforces, never decides) | n/a (PostgreSQL vendor image + Maknae-owned SQL migrations) | **Ratified 2026-07-15** (abac-dcs-architecture D1) |

MVP builds six images (1–6); `web-ui` is deferred per the roadmap; `vault-agent` and `state-store` are vendored images (the state store ships with Maknae-owned migrations and generated RLS policies, and is part of the MVP stack — RLS is live from Phase A). Consolidations are deliberate: the scheduler lives inside `gateway`, the skill registry and audit writer live inside `kernel`, and the memory subsystem co-locates with `lake` — each splits out later only under measured pressure, never speculatively.

## 3. Per-container detail

### 3.1 `kernel` — Rust (ratified)

The trust plane: PDP (policy engine), label-schema enforcement, all six KLC hooks, skill-registry signature verification, and the append-only audit writer. Rationale for Rust: memory-safety CSI alignment (the language choice is a citable control), KLC §15 invariants encoded in the type system (illegal states unrepresentable — a `tier_ceiling` automation cannot raise, a downgrade constructible only from a consumed signed authorization), FIPS 140-3 via `aws-lc-rs` (Microkosmos precedent), static binary into a distroless/from-scratch image (TaeBot pattern). Policy engine integration is the KLC §14 Q5 spike — **noting Cedar is Rust-native (`cedar-policy` crate, formally verified core) while OPA embeds via Wasm or sidecars; the pairing is not neutral and the spike must weigh it.**

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

### 3.9 `state-store` — PostgreSQL (vendor image; ratified 2026-07-15)

The platform's labeled operational state: per-operator session/conversation state (born at the high-water mark of its inputs), scheduler task definitions, the memory recall (FTS) index, and the structured audit query surface. Knowledge stays in the Lake; Tier-0 config stays signed-git (the store may hold materialized copies for joins, never the authority). Every table carries the full DCS column set; label columns are `NOT NULL`; RLS policies are **generated from the SPIF** by trust-plane tooling and deployed with the migrations — `SET LOCAL` per-transaction subject attributes, `FORCE ROW LEVEL SECURITY`, non-superuser service roles without `BYPASSRLS`, deny-all default policies. Data plane, untrusted-adjacent: RLS *enforces* as the at-rest backstop (layer 3); the kernel remains the only decision-maker. Full design: [abac-dcs-architecture.md](abac-dcs-architecture.md) §3.1, §7.3. Precedent: the Security MCP's PostgreSQL engine, with the RLS layer that project consciously deferred built here from birth.

## 4. Volumes (both deployment models)

| Volume | Mounted by | Notes |
|---|---|---|
| `lake-data` | lake (rw), dreamer (rw), kernel (label verification, ro) | The governed corpus; git-backed |
| `audit-log` | kernel (append-only) | Export/replication path is a later, kernel-mediated feature |
| `skill-registry` | kernel (rw), runtime (ro via kernel grants) | Signed manifests |
| `authority-config` | kernel (ro) | Tier 0: authority map, operator attributes, lattice + instance ceiling; changes arrive as signed commits, not writes |
| `vault-sink` | per-service tmpfs | Never a named persistent volume |
| `persona-workspace` | runtime (rw), gateway (ro) | Multi-file bundle, first-class (never runtime-flattened — the TaeBot/Hermes lesson) |
| `state-data` | state-store (pgdata) | Labeled operational state; DCS columns + generated RLS travel with the data; no other container mounts it — access is SQL through layer-2 PEPs only |

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
2. **Representation is schema-first.** The `dcs_label` block and the kernel decision request/response protocol are versioned schemas (JSON Schema at MVP); per-language types are generated, never hand-rolled. Every container can *parse and carry* labels; parsing is not evaluating.
3. **Local evaluation is one Rust crate with bindings — never a port.** `maknae-dcs-core` (label types, lattice math, dominance checks) is the single canonical implementation: consumed natively by `kernel` and `egress-proxy`, and via PyO3/maturin wheels by the Python containers where a hot path justifies local evaluation. The identified hot path is the lake's per-subject retrieval filtering; whether it uses a kernel bulk-decision API or local bindings is decided by measurement — both are permitted because both run the same crate against the same vectors.

**Conformance vectors are the enforcement.** KLC §15 invariants plus lattice dominance cases ship as language-neutral golden test vectors in this repo; every implementation that touches labels — the kernel, every binding, any future port — must pass the identical vectors in CI. Bindings prevent re-implementation; vectors catch divergence anyway.

**The state store's RLS predicates are a fourth projection of the same engine, not a new implementation:** generated from the SPIF by trust-plane tooling (never hand-written SQL), parity-checked at kernel boot, and run against the identical conformance vectors on a real PostgreSQL in CI (abac-dcs-architecture §6.4, §7.3, §12).

**Provenance of the crate:** `maknae-dcs-core` is seeded by extracting the DCS-relevant elements from Microkosmos in two derisked steps: (a) convert the microkosmos repo to a Cargo workspace and factor the elements into an in-repo lib crate — binary behavior unchanged, existing suite proves it; (b) lift the crate to its shared home once the public API stabilizes (Cargo git dependencies; no registry needed while private). A survey of which Microkosmos elements are genuinely DCS versus server-specific precedes step (a) — a bounded, delegable task.

**Security MCP harvest:** its Go ABAC gateway is the semantic reference — attribute schemas, gating semantics, and test cases port into kernel policy and the conformance vectors. Its gateway code is candidate vendoring for the Go `gateway` container (same language, same function); its decision logic is deliberately NOT linked as a library — decisions move to the kernel, and the Go code's job becomes enforcement and identity assertion.

**Cedar interaction:** if Cedar wins the Q5 spike, the policy language itself becomes cross-language shared capability (official Rust core, official Go implementation, Python bindings) with upstream conformance testing — a further weight the spike must record.

## 7. Open items

1. Cedar vs. OPA spike (KLC §14 Q5) — Cedar is the leading candidate per ADR-0003 (Rust-native pairing §3.1, cross-language implementations §6, formally verified core); the spike confirms or overturns.
2. Channel vote decides `gateway` SDK details and whether the TypeScript alternative is live (§3.3).
3. Kubernetes profile specifics (PSA levels, NetworkPolicy set, operator vs. plain manifests) — after the Compose stack proves the shape.
4. Whether `egress-proxy` and `kernel` share an image with distinct entrypoints or build separately — decide at kernel-skeleton time; trust-plane review treats them as one surface either way.
5. Microkosmos DCS-element survey (pre-extraction scoping for `maknae-dcs-core`, §6) — bounded and delegable.
