# Maknae (막내)

> A security-hardened personal AI agent platform. Secure by Design and by Default — not as configuration, but as architecture.

| | |
|---|---|
| **Status** | Early implementation. Trust-plane crates, the `maknaed` daemon, the DAC authorization schema, and local-plane enrollment are landing; pre-MVP. |
| **Domain** | https://maknae.io (registered, Cloudflare; holding page pending) |
| **Core spec** | [`design/knowledge-lifecycle-contract.md`](design/knowledge-lifecycle-contract.md) — read this first |
| **Contributor guide** | [`AGENTS.md`](AGENTS.md) — core principles and conventions (`CLAUDE.md` is a symlink to it) |
| **Team** | Alex (architect/owner) + two engineers |
| **License** | TBD (MIT leaning, pending team decision) |

---

## What Maknae is

Maknae is a personal AI agent platform built around a **security kernel**. Where existing agent platforms treat security as configuration sprinkled on top of a capable runtime, Maknae inverts the relationship: a small, auditable **trust plane** mediates every action, every piece of knowledge, and every network flow, with the agent runtime treated as untrusted by design. Deny by default, everywhere, always.

The platform's defining feature is a **governed learning loop**: the agent is permitted to learn — generating skills from experience and ingesting documents into its own local Knowledge Lake when tasked work reveals a gap — but every piece of acquired knowledge flows through a single authority-tiered, provenance-stamped promotion pipeline before it can be trusted. The operator does not fill the agent's knowledge base; **the agent fills it himself, from operator-authorized sources only**, learning the "official way" to do things as defined by a signed authority map.

Deployment targets are Raspberry Pi (arm64), x64 Linux, and macOS hosts. It is container-based and targets two deployment models: a **Docker Compose stack** (or Podman equivalent) and a **full Kubernetes deployment**, both on STIG default baselines. Single-binary is *not* a goal; small-and-auditable is.

The north-star deployment is a classified, multinational, air-gapped enclave — partner operators as attribute-bearing subjects, a full Bell-LaPadula classification lattice with releasability categories, and every model endpoint local and accredited. That is not a special mode: it is the same kernel with a richer lattice and a stricter authority map, which a homelab runs with a trivial lattice at zero ceremony.

## Why Maknae exists

Maknae began as a survey project — fork-and-merge the best of two open-source agent platforms the operator runs in production:

- **OpenClaw** (running as *HobiBot*) — the layered-control school: decoupled model layer, core runtime, explicit skills, atomic tool abstractions. Discipline.
- **Hermes Agent** (Nous Research; running as *TaeBot*) — the learning-first school: self-improving skills from experience, decoupled memory, multi-channel gateways, native MCP, scheduling. Growth.

The fork premise died on inspection: **both projects make architectural decisions that treat security as configuration, not structure.** Retrofitting a deny-by-default trust plane into either codebase would fight its architecture forever. So Maknae is a **greenfield platform with two reference implementations** — it adopts Hermes' learning-loop and scheduling concepts and OpenClaw's explicit-control discipline, governed by a kernel neither of them has.

Three ideas set it apart from both upstreams:

1. **Policy-bound authorization.** A deny-by-default Discretionary Access Control (DAC) access policy requires every consequential action to transit a single reference monitor. Data-Centric Security (DCS) — labels binding to knowledge objects rather than the perimeter — is available as an *optional external layer* for classified and multi-level deployments, plugged into the same policy-agnostic seam.
2. **Zero Trust.** Every decision evaluates the tuple (subject, action, resource, context). Freshly retrieved content is an untrusted principal until it is promoted — it can *inform* a decision but never *authorize* one.
3. **Unified knowledge lifecycle.** Skills (procedural), lake documents (declarative), and memories (episodic/semantic) all flow through one authority-tiered promotion pipeline. See the contract.

## Architecture

Three planes — this describes the design; see **Status & roadmap** below for what has actually landed:

- **Interaction plane** — gateway, web UI, and a scheduler with scoped task identities. Accepts work; trusts nothing.
- **Trust plane** — the kernel, and the *only* trusted code. It holds the reference monitor (`maknaed` is the sole policy decision point), the deny-by-default DAC access policy, the signed and tiered skill registry, and the append-only audit log. Nothing touches anything without transiting it.
- **Runtime plane** — the agent runtime with the gated learning loop, plus integrations acting as policy information points. Does the work, under constraint.

**The kernel is 100% Rust** ([ADR-0002](design/adr/ADR-0002-kernel-is-rust.md)): memory-safety guidance makes the language choice a citable control, the contract's invariants encode into the type system, and the operator's [Microkosmos](https://github.com/mpe-es/microkosmos) webserver supplies the in-house FIPS 140-3 Rust precedent. Authorization is evaluated behind a **policy-agnostic seam** ([`crates/maknae-security`](crates/maknae-security)); the concrete policy engine is a deliberate open question — **Cedar is the leading candidate** ([ADR-0003](design/adr/ADR-0003-cedar-policy-engine.md), Rust-native), pending a spike against the enforcement hooks. The DAC capability grammar operators write policy against ships and is validated ahead of that evaluation ([`crates/maknae-config`](crates/maknae-config)). Every other container picks the language best suited to its job — see [`design/container-architecture.md`](design/container-architecture.md) — with rigor calibrated to the layer, affordable precisely because the kernel, not the runtime's good behavior, is the control.

Test-driven development applies to every container in every language; because segments are AI-implemented, the suite doubles as mutation-proofing, and coverage rigor scales with how security-critical the code is ([ADR-0016](design/adr/ADR-0016-risk-tiered-test-coverage.md)). Architecture diagrams live in [`design/diagrams/`](design/diagrams/).

## The name

**Maknae (막내)** is the generic Korean kinship word for the youngest member of any group. It was chosen deliberately:

- **The lore.** HobiBot and TaeBot are the hyungs (older brothers); Maknae is the youngest — born last, raised by the older two, inheriting the best of both. A "golden maknae" is a youngest member who is inexplicably good at everything, which is precisely this project's best-of-both-worlds thesis.
- **The IP posture.** The word is generic Korean vocabulary — not coined, not trademarked, no corporate association. A 2026-07 namespace survey confirmed it clean on PyPI, npm, and crates.io. The personal meaning is real; the public name is unclaimable.
- **The convention.** In the operator's ecosystem, hosts get World of Warcraft names, agent *personas* get their own names, and standalone *projects* get culturally-generic names. Maknae the platform hosts personas; the personas are runtime configuration, never the product identity.

## Status & roadmap

Maknae is pre-MVP but no longer paper: the trust-plane crates, the `maknaed` daemon (with STIG-baselined packaging and SELinux/AppArmor profiles), the DAC authorization schema, and the local-plane enrollment model ([ADR-0018](design/adr/ADR-0018-local-plane-authorization-deployment-model.md)) are landing. The phased plan:

1. **Governance baseline** — Knowledge Lifecycle Contract review; authority basis aligned to the Knowledge Lake's authority-line model; the open questions resolved with rationale.
2. **Policy engine spike** — Cedar vs. alternatives evaluated against the enforcement hooks as the acceptance test ([ADR-0003](design/adr/ADR-0003-cedar-policy-engine.md)).
3. **Trust-plane kernel** — policy engine, the authorization seam, and audit events *(underway)*.
4. **Lake integration** — a portable lake instance, authority map v0.1 (egress allowlist plus authority basis), and the quarantine ingest path.
5. **Learning loop MVP** — gap detection → authorized fetch → quarantine → out-of-band consolidation ("dreaming") → gated promotion.
6. **Gateway and web UI** — an onboarding wizard (CLI and web) for authority configuration, and the scheduler with scoped task identities.
7. **Persona layer** — the hyungs move in.

Two capabilities are first-class *by design* from the start (design intent, not yet shipped). **Model-layer registration is dual-mode**: OAuth subscription authentication *and* OpenAI-compatible endpoint registration (including self-hosted and air-gapped inference), with provider endpoints as kernel-allowlisted egress destinations and credentials delivered via Vault, never plaintext. **Task-class model routing** is a policy decision that weighs task cost, content sensitivity (in classified deployments, no-egress or classified context may reach only endpoints authorized for it), and subject attributes — the model endpoint is itself an attribute-gated resource carrying operator-signed labels (jurisdiction, sanctioning authority, handling ceiling), so an operator's attributes constrain which models may serve them and data sovereignty holds even for unattended, scheduled work. One persona per instance is the proven deployment pattern (multi-persona is deferred behind a feature gate), while a single agent serving **multiple operators** — each with their own attribute set — is designed in from the start.

## Repository layout

```
.
├── AGENTS.md                # contributor/agent guidance (CLAUDE.md → symlink)
├── Cargo.toml               # Rust workspace
├── coverage-tiers.toml      # risk-tiered coverage contract (ADR-0016)
├── deny.toml                # supply-chain gate (cargo-deny)
├── bins/                    # maknae (CLI), maknaed (daemon), maknae-spifc (SPIF compiler)
├── crates/                  # trust-plane kernel, authz, audit, SPIF, MCP, vault, subject-context
├── ci/gates/                # fail-closed CI gates (coverage, negative-control, isolation-contract)
├── packaging/               # STIG-baselined deb / rpm / macos / oci packaging
├── deploy/                  # deployment assets (Vault PKI, …)
├── docs/                    # configuration and operator runbook
└── design/
    ├── knowledge-lifecycle-contract.md   # the governance spec — read first
    ├── container-architecture.md         # container decomposition + language choices
    ├── reference-implementation-autopsy.md
    ├── adr/                              # architecture decision records
    ├── references/                       # external-framework assessments
    └── diagrams/
```

## Working in this repo

Start with [`AGENTS.md`](AGENTS.md) — it carries the core principles and conventions for everyone working on Maknae, human or AI, and points at the load-bearing detail. In short: deny-by-default applies to designs too (absence of a permission is a denial); nothing self-promotes (no content, skill, or config gains authority without transiting the promotion pipeline); verify through the fail-closed gates in [`ci/gates/`](ci/gates/); and record decisions as ADRs. The [Knowledge Lifecycle Contract](design/knowledge-lifecycle-contract.md) invariants are acceptance criteria — violating one is a wrong answer even if the code works.

## Lineage & related work

Maknae's two reference implementations are the operator's production agents — study their architecture, inherit their concepts, not their trust models:

- **OpenClaw** — https://github.com/openclaw/openclaw (layered-control reference)
- **Hermes Agent** — https://github.com/NousResearch/hermes-agent (learning-first reference)

It also builds on the operator's prior work: the [**Knowledge Lake**](https://github.com/mpe-es/knowledgebase) (authority-tiered, deterministic markdown retrieval — the architecture Maknae's lake is a portable instance of), [**Claude Memory**](https://github.com/darkhonor/claude-memory) (the shared memory system with out-of-band "dreaming" consolidation), the **Security MCP Server** (a live OAuth 2.1 + ABAC gateway — prior art for the kernel's decision point), and [**Microkosmos**](https://github.com/mpe-es/microkosmos) (the FIPS 140-3 Rust precedent). Assessments of comparable third-party platforms live in [`design/references/`](design/references/).

## License

To be determined (MIT leaning), pending team decision.

---

*The youngest one, raised by the best of both. 막내 화이팅.*
