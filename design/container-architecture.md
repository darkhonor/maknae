# Container Architecture and Language Calls

| | |
|---|---|
| **Status** | Draft — for team review; language calls are operator-ratified where marked, proposed otherwise |
| **Date** | 2026-07-14 (revised 2026-08-22) |
| **Scope** | Container decomposition for both deployment models (Compose/Podman stack; full Kubernetes), per-container language selection, trust levels, volumes |
| **Doctrine** | Language targets best fit for the action being done. Kernel is 100% Rust (operator-ratified 2026-07-14). TDD everywhere (§5). |

> **Authority.** Authorization, enforcement locus, audit, and the access-control model are governed by the ADRs, not this doc: [ADR-0004](adr/ADR-0004-modular-authorization-architecture.md) (the modular `maknae-security` seam + pluggable `maknae-authz-*` backends), [ADR-0005](adr/ADR-0005-enforcement-locus-tcb-boundary.md) (split-kernel, mTLS, sole PDP), [ADR-0018](adr/ADR-0018-local-plane-authorization-deployment-model.md) (local-plane authz + enrollment), [ADR-0019](adr/ADR-0019-audit-record-model.md) (audit record model), [ADR-0020](adr/ADR-0020-access-control-model-and-vocabulary.md) (RBAC/ABAC over DAC/MAC). The DCS classification engine is external (an optional external library), reached only through the seam *(clarified 2026-09-06, #148/#154: the SCALPEL is external; a level CEILING over the declared system's level order (ADR-0022; US = the four-level EO 13526 order, AUS = the six-rung PSPF ladder) is in-repo, a non-removable operand of the kernel's `Composition`)*. Where this doc and an ADR disagree, the ADR wins.

## 1. Principles

1. **One trust plane, few trusted containers.** The kernel and the egress enforcement point are the only containers whose compromise defeats the architecture. Everything else is constrained by them, not trusted alongside them.
2. **Language per action.** Precedent is the operator's Security MCP server (Go gateway/query services, Python parser, Rust proxy, TypeScript UI): pick the language whose ecosystem and guarantees fit the container's job, not a house language. Pattern inheritance from the upstreams is language-independent (autopsy, open item 3).
3. **The runtime plane is untrusted by design** (KLC §3). Its containers get velocity-optimized languages; correctness is enforced at the kernel boundary, not assumed in the runtime.
4. **Both deployment models from birth.** Every container ships with a Compose/Podman definition and a Kubernetes manifest, STIG-default configurations and baselines assumed. Volumes are declared per container (§4); in Kubernetes, kernel-mediated flows become NetworkPolicies; in Compose, internal networks + the egress proxy enforce the same shape (TaeBot's scoped nftables table is the host-level reference).
5. **The runtime plane is stateless by declared design.** Untrusted containers hold no durable state; working sets check in and out through kernel-mediated durable storage. Compromise of the runtime leaks only its current working set; a crash loses nothing; "no read up" is enforceable at rest, not merely at retrieval time.

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

MVP builds six images (1–6); `web-ui` is deferred per the roadmap; `vault-agent` is a vendored sidecar image. Consolidations are deliberate: the scheduler lives inside `gateway`, the skill registry and audit writer live inside `kernel`, and the memory subsystem co-locates with `lake` — each splits out later only under measured pressure, never speculatively.

Durable **operational-state storage** (per-operator session state, scheduler tasks, the memory-recall index) is an **open decision** — engine and at-rest enforcement are not yet chosen (§7).

## 3. Per-container detail

### 3.1 `kernel` — Rust (ratified)

The trust plane: PDP (the sole policy decision point, ADR-0005), label-schema enforcement, all six KLC hooks, skill-registry signature verification, and the append-only audit writer. Rationale for Rust: memory-safety CSI alignment (the language choice is a citable control), KLC §15 invariants encoded in the type system (illegal states unrepresentable — a `tier_ceiling` automation cannot raise, a downgrade constructible only from a consumed signed authorization), FIPS 140-3 via `aws-lc-rs` (Microkosmos precedent), static binary into a distroless/from-scratch image (TaeBot pattern). The kernel reaches policy through the **policy-agnostic `maknae-security` seam** and composes pluggable `maknae-authz-*` backends deny-overrides ([ADR-0004](adr/ADR-0004-modular-authorization-architecture.md), [ADR-0020](adr/ADR-0020-access-control-model-and-vocabulary.md)).

### 3.2 `egress-proxy` — Rust (proposed)

> **Dated note 2026-09-07 ([ADR-0023](adr/ADR-0023-runtime-loop-role-and-placement.md) decision 3, milestone Cooky):** this lands first as a **process**, `maknae-egress`, under its own service account, reached by `maknaed` over a local socket — the model call, the provider credential, outbound TLS and response validation live there, never in the PDP. It becomes this container when a second destination or the Kubernetes model arrives. A host proxy (Traefik) was considered and rejected: non-Rust, non-FIPS, and it would not take response parsing out of `maknaed`.

The single enforcement point for all outbound flows: model-endpoint calls (OAuth subscription + OpenAI-compatible registrations), learning fetches, and channel egress all transit it; the kernel decides, the proxy enforces (PEP). Holds the Hook E data path: destination allowlisting from the authority map, payload label screening, model-endpoint dominance checks as decided by the kernel. Rust for the same reasons as the kernel — this is the one other container whose compromise is architecture-defeating, and it terminates TLS with FIPS requirements. Microkosmos is the in-house precedent for a hardened Rust network data path. In Kubernetes this pairs with NetworkPolicies that force all egress through it; in Compose, internal networks make it the only externally-connected service besides `gateway`.

### 3.3 `gateway` — Go (proposed)

Channel adapter (Discord/Matrix/etc. per the team vote), operator authentication at the channel boundary (fail-closed allowlist — the one Hermes pattern adopted intact), session routing, and the scheduler (scoped task identities minted through the kernel, labels bound at creation per KLC §6). Go rationale: static single binary into distroless images, strong concurrency for fan-out, mature channel SDKs (discordgo, mautrix-go), and team precedent in the Security MCP's Go services. TypeScript is the alternative if the team votes to vendor OpenClaw channel-adapter code; that vote rides with the channel vote. The gateway asserts operator identity; the kernel binds subject attributes and makes every decision — the gateway is security-relevant but never trusted with policy.

### 3.4 `runtime` — Python (proposed)

> **Dated note 2026-09-07 ([ADR-0023](adr/ADR-0023-runtime-loop-role-and-placement.md), milestone Cooky):** the MVP loop is **Rust**, a subcommand of the existing untrusted `maknae` binary (`maknae agent`) — it reuses the plane client that already exists and adds no packaging surface. The Python proposal below is for the *eventual* runtime container and is re-decided on evidence after Cooky; the evidence that would move it is named in the ADR. The loop is the ACP **Agent**; the kernel is the ACP **Client**; the model call is decided per turn by the kernel and executed by the `maknae-egress` process (§3.2 note) on the Agent's request — which reverses ACP's own direction for `session/prompt` (an agent method the Client calls); ADR-0023 decision 3 owns that reversal.

The agent loop: LLM conversation orchestration, tool invocation (via kernel-mediated grants), MCP client integrations, gap detection, and learning-loop requests. Python rationale: best fit for the most experimental, fastest-iterating layer — the LLM/MCP SDK ecosystem is Python-first, Hermes' learning-loop concepts port naturally, and the layer is untrusted by design so its language guarantees are not load-bearing. Every privileged act transits the kernel; the runtime requests, never performs, lifecycle transitions.

### 3.5 `lake` — Python (proposed)

The portable Knowledge Lake instance plus the memory subsystem: quarantine ingest, label stamping (as directed by kernel decisions), retrieval serving (per-subject filtered context assembly), FTS-style memory recall. Python is inherited by construction — the lake framework tooling (compilers, gates, edge graph, query contracts from knowledgebase #201) is Python, and Maknae consumes it as the same artifact, not a port. Memory co-locates here at MVP (both are labeled-markdown-plus-index stores with one governance model); splits later if access patterns diverge.

### 3.6 `dreamer` — Python (proposed)

The out-of-band consolidation cycle (KLC §8 step 4): dedup, source revalidation, corroboration checks, memory distillation, skill-candidate refinement, promotion *proposals*. Architecturally separate container — never in-band with the runtime — running under its own scoped identity with no interactive privileges, on a schedule. Same image lineage as `lake` (different entrypoint) to start; the separation that matters is identity and invocation path, not build artifact.

### 3.7 `web-ui` — TypeScript (proposed; post-MVP)

Operator console: onboarding wizard (authority map authoring — emits operator-signed commits, never live mutations), audit review, promotion queue review, operator/attribute administration. TypeScript because the browser is the action; no other container speaks TS. Deferred behind the CLI per the roadmap — the CLI wizard proves the onboarding contract first.

### 3.8 `vault-agent` — vendor image

HashiCorp Vault Agent sidecar per service that needs secrets: AppRole auto-auth, short-TTL token to a tmpfs sink, services consume via native Vault API (no shell-outs, no templated files on disk) — the TaeBot `vault_bootstrap` pattern generalized, per the README's Vault-native ruling. Secrets engines are operator-configured, potentially independent per MLS secret target.

## 4. Volumes (both deployment models)

| Volume | Mounted by | Notes |
|---|---|---|
| `lake-data` | kernel (rw), lake (ro), dreamer (ro) | The governed corpus; git-backed. **Corrected 2026-08-30 per [KLC](knowledge-lifecycle-contract.md) §6.1 (issue #2):** the frontmatter *is* the tier state, so the untrusted containers previously held `rw` on label state while the only trusted container was read-only. Writes are brokered through a kernel API |
| `audit-log` | kernel (append-only) | Export/replication path is a later, kernel-mediated feature |
| `skill-registry` | kernel (rw), runtime (ro via kernel grants) | Signed manifests |
| `authority-config` | kernel (ro) | Tier 0: authority map, operator attributes, lattice + instance ceiling; changes arrive as signed commits, not writes |
| `vault-sink` | per-service tmpfs | Never a named persistent volume |
| `persona-workspace` | runtime (rw), gateway (ro) | Multi-file bundle, first-class (never runtime-flattened — the TaeBot/Hermes lesson) |

Durable operational-state storage (§2) will add its own volume once that decision lands (§7).

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
2. **Mutation testing is the gate on the tests themselves.** A metric ton of tests proves nothing if the tests are slop too; mutation runs verify the suite actually kills behavior changes (cadence per [ADR-0016](adr/ADR-0016-risk-tiered-test-coverage.md): change-gated per-PR for security-critical crates + unconditional on merge to main). Surviving mutants in trust-plane code are release blockers; in runtime-plane code they are backlog items.

## 6. Shared DCS capability strategy — one engine, not eight

The risk: six containers in four languages each growing their own label/lattice/policy logic. The strategy defeats it in three layers, in priority order:

1. **Architecture first: decisions are centralized, not distributed.** The kernel is the only decision-maker (PDP); every other container is a PEP that requests decisions and enforces outcomes. Five of six containers never evaluate policy — most of the duplication risk is eliminated by the plane model itself, not by libraries.
2. **Representation is schema-first.** The label block and the kernel decision request/response protocol are versioned schemas (JSON Schema at MVP); per-language types are generated, never hand-rolled. Every container can *parse and carry* labels; parsing is not evaluating.
3. **Local evaluation is one library, reached through the seam — never a per-container port.** Where a hot path justifies evaluating locally instead of calling the kernel, containers consume a single canonical implementation. An attribute-keyed classification engine, where a deployment installs one, is reached only through the policy-agnostic `maknae-security` seam ([ADR-0004](adr/ADR-0004-modular-authorization-architecture.md)) — consumed natively by the Rust trust-plane containers and via bindings by the Python containers. The identified hot path is the lake's per-subject retrieval filtering (kernel bulk-decision API vs. local bindings — decided by measurement, same library either way). A **non-DCS build** — improving OpenClaw/Hermes without DCS awareness — stays a first-class configuration, because the seam speaks general security vocabulary, not DCS.

**Conformance vectors are the enforcement.** The label/authorization golden vectors ship as language-neutral test vectors; every implementation that touches them — the kernel, each backend, every binding — must pass the identical vectors in CI. One implementation plus vectors, not eight re-implementations.

## 7. Open items

1. **Operational-state storage** — whether and how per-operator session state, scheduler tasks, and the memory-recall index are stored and label-enforced *at rest*. Open decision tracked in #2 (storage / label-integrity) and #20 (vendor-substrate trust locus); the direction under consideration is Apache Accumulo cell-level visibility.
2. Channel vote decides `gateway` SDK details and whether the TypeScript alternative is live (§3.3).
3. Kubernetes profile specifics (PSA levels, NetworkPolicy set, operator vs. plain manifests) — after the Compose stack proves the shape.
4. Whether `egress-proxy` and `kernel` share an image with distinct entrypoints or build separately — decide at kernel-skeleton time; trust-plane review treats them as one surface either way.
