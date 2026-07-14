# Maknae (막내)

> A security-hardened personal AI agent platform. Secure by Design and by Default — not as configuration, but as architecture.

| | |
|---|---|
| **Status** | Pre-implementation. Architecture and governance specs under team review. |
| **Domain** | https://maknae.io (registered, Cloudflare; holding page pending) |
| **Core spec** | [`knowledge-lifecycle-contract.md`](knowledge-lifecycle-contract.md) — read this first |
| **Team** | Alex (architect/owner) + two engineers |
| **License** | TBD (MIT leaning, pending team decision) |

---

## 1. What Maknae is

Maknae is a personal AI agent platform built around a **security kernel**. Where existing agent platforms treat security as configuration sprinkled on top of a capable runtime, Maknae inverts the relationship: a small, auditable **trust plane** mediates every action, every piece of knowledge, and every network flow, with the agent runtime treated as untrusted by design. Deny by default, everywhere, always.

The platform's defining feature is a **governed learning loop**: the agent is permitted to learn — generating skills from experience and ingesting documents into its own local Knowledge Lake when tasked work reveals a gap — but every piece of acquired knowledge flows through a single authority-tiered, provenance-stamped promotion pipeline before it can be trusted. The operator does not fill the agent's knowledge base; **the agent fills it himself, from operator-authorized sources only**, learning the "official way" to do things as defined by a signed authority map.

Deployment targets: Raspberry Pi (arm64), x64 Linux, and macOS hosts. Container-first with an OS-install path. STIG-hardened baselines. Single-binary is *not* a requirement; small-and-auditable is.

## 2. Origin story

Maknae began as a survey project: fork-and-merge the best of two open-source agent platforms the operator runs in production —

- **OpenClaw** (running as *HobiBot*, J-Hope persona, Discord/Slack) — the layered-control school: decoupled model layer, core runtime, explicit skills, atomic tool abstractions. Discipline.
- **Hermes Agent** (Nous Research; running as *TaeBot*, V persona) — the learning-first school: self-improving skills from experience, four-layer decoupled memory, multi-channel gateways, native MCP, scheduling. Growth.

The fork premise died on inspection: **both projects make architectural decisions that are not "Ack Compliant"** — the operator's term for Secure by Design and by Default as a structural property rather than an optional configuration item. Retrofitting a deny-by-default trust plane into either codebase would fight their architecture forever. So Maknae is a **greenfield platform with two reference implementations**, adopting Hermes' learning-loop and scheduling concepts and OpenClaw's explicit-control discipline, governed by a kernel neither of them has.

Design extensions beyond both upstreams:

1. **Data Centric Security (DCS)** — security labels travel with every knowledge object (tier, provenance, classification, handling caveats) and policy binds to the labels, not the perimeter.
2. **Zero Trust** — every decision evaluates (subject, action, resource labels, context). Freshly retrieved content is an untrusted principal until promoted.
3. **Unified knowledge lifecycle** — skills (procedural), lake documents (declarative), and memories (episodic/semantic) all flow through one promotion pipeline. See the contract.

## 3. Naming rationale

**Maknae (막내)** is the generic Korean kinship word for the youngest member of any group — family, team, or otherwise. It was chosen deliberately:

- **The lore:** HobiBot and TaeBot are the hyungs (older brothers). Maknae is the youngest — born last, raised by the older two, inheriting the best of both. In Korean pop-culture usage, a "golden maknae" is a youngest member who is inexplicably good at everything, which is precisely this project's best-of-both-worlds thesis. The BTS resonance is intentional but remains the operator's private layer.
- **The IP posture:** the word is generic Korean vocabulary — not a coined term, not trademarked, no corporate association. Namespace survey (2026-07) confirmed the name clean on PyPI, npm, and crates.io, with no significant GitHub collisions. This follows the same play as the operator's *Microkosmos* webserver (a Bartók piano cycle and Greek word long before it was anything else): the personal meaning is real, the public name is unclaimable.
- **The convention:** in the operator's ecosystem, hosts get World of Warcraft names, agent *personas* get BTS member names, and standalone *projects* get culturally-generic names with private resonance. Maknae the platform will host personas; the personas are runtime configuration, never the product identity.

## 4. Architecture in one paragraph

Three planes. The **interaction plane** (gateway + web UI, multi-channel, scheduler with scoped task identities) accepts work. The **trust plane** — the kernel, and the only trusted code — holds the policy engine (deny-by-default PDP), the signed/tiered skill registry, and the append-only audit log; nothing touches anything without transiting it. The **runtime plane** (agent runtime with the gated learning loop, plus integrations acting as PIPs) does the work under constraint. Kernel candidates favor Rust/Go with a policy language (Cedar vs. OPA — open question); the runtime plane is free to be TypeScript/Python for velocity because the kernel, not the runtime's good behavior, is the control. Diagrams live in [`diagrams/`](diagrams/).

## 5. Related projects — REQUIRED exploration for AI agents

Maknae does not stand alone. It is the integration point for several of the operator's active projects. **Before proposing designs or correlating overlap, review each of these at the paths below.**

### 5.1 Reference implementations — the hyungs

Both upstreams are mirrored locally as siblings of this project folder. Study their architecture; inherit their concepts, not their trust models.

| Project | Upstream | Local mirror | Role |
|---|---|---|---|
| **OpenClaw** (runs as *HobiBot*) | https://github.com/openclaw/openclaw | `../openclaw` | Layered-control reference: explicit skills, atomic tools, decoupled runtime |
| **Hermes Agent** (runs as *TaeBot*) | https://github.com/NousResearch/hermes-agent | `../hermes-agent` | Learning-first reference: self-improving skills, four-layer memory, gateways, scheduling, MCP |

The live deployment configurations for both personas are also on this system and are **required reading alongside the upstream code** — they show how the operator hardens each platform in practice:

| Deployment | Location | What to study |
|---|---|---|
| **HobiBot** (OpenClaw) | `~/Development/HomeLab/Systems/hobibot` | Vault AppRole secret delivery, Docker userns-remap, auditd, fail2ban — the hardening overlay Maknae must make native |
| **TaeBot** (Hermes) | `~/Development/HomeLab/Systems/taebot` | Same hardening pattern applied to a learning-loop platform; where the overlay strains against Hermes' architecture is exactly where Maknae's kernel must differ |

### 5.2 Operator projects — integration and pattern sources

| Project | Location | What it is | What Maknae takes from it |
|---|---|---|---|
| **Knowledge Lake** | `~/knowledgebase` | Authority-tiered, deterministic markdown retrieval platform (anti-RAG, progressive disclosure, git-distributed, FIPS 140-3, portable architecture). Four-tier authority hierarchy, YAML frontmatter provenance, brain/organ/soul → PDP/PIP/authority.yaml model. | Maknae's lake IS a portable instance of this architecture, self-populated by the agent. Tier vocabulary must align (open question #1 in the contract). The Tier 0/1/2 router pattern applies to retrieval. |
| **Claude Memory** | `~/claude-memory` | The operator's own shared memory system (not a vendor product), with Lamis Mukta-style out-of-band "dreaming" consolidation. | Maknae's memory IS this system, wrapped in an LLM-efficient read path (bounded working set, FTS-style recall) — somewhere between Hermes' four-layer model and the operator's design. Trust model stays the operator's. |
| **Security MCP Server** | `~/Development/MCP/security-mcp-server` | Security tooling exposed over MCP (Mozilla Observatory integration planned). | Runtime-plane integration (PIP); also informs kernel policy telemetry. |
| **STIG Remediation Loop** | `~/Development/stig-remediation-loop` | Compliance-ready loop design informed by HuaShu's Orange Book (loop engineering guide) and the operator's GitLab issue standards. | Directly feeds the gated learning loop and skill promotion criteria (contract §9); the compliance-automation skill domain Maknae will learn. |
| **Microkosmos** | `~/Development/Containers/microkosmos` | FIPS 140-3 Rust webserver (`aws-lc-rs`, GET-only, NIST 800-53 aligned, hardened). | The Rust-perimeter precedent and FIPS story for the trust plane; likely serves maknae.io. |
| **Microkosmos Test Sites** | `~/Development/MPE-ES/Capabilities/microkosmos-test-sites` | Test site content and deployment configurations for Microkosmos. | Hardened static-serving and deployment validation patterns; candidate harness for Maknae's web UI hosting. |
| **VM HomeLab** | `~/Development/Containers/vmhomelab` | Microkosmos test site — VM/container homelab deployment environment. | Deployment-target realism: the container/VM patterns Maknae must install cleanly into. |

The HobiBot and TaeBot deployment configurations (§5.1) embody the hardening patterns to preserve; the upstream mirrors are the code to study — including what NOT to inherit.

Operational context that applies platform-wide: HashiCorp Vault for all secrets (AppRole, Agent sidecar templating — no plaintext credentials, ever), Terraform/IaC-first, GitOps via Fleet where applicable, WireGuard mesh across sites, and the operator's GitLab issue standards (audit-grade, NIST control mappings, structured closing protocol).

## 6. Orientation protocol for AI agents (read carefully, Fable 🐰)

1. **Read [`knowledge-lifecycle-contract.md`](knowledge-lifecycle-contract.md) in full.** The machine-readable invariants in §15 are acceptance criteria for anything you build or propose. Violating an invariant is a wrong answer even if the code works.
2. **Explore the related projects (§5) before correlating.** Your task is to map overlap and opportunity across the operator's AI project portfolio; do not reason about them from this README alone.
3. **Deny by default applies to you.** When designing, absence of an explicit permission is a denial. Never propose a "permissive mode," a bypass flag, or a default-allow fallback.
4. **Nothing self-promotes.** Any design where generated content, skills, or configuration gains authority without transiting the promotion pipeline is architecturally rejected.
5. **YAGNI discipline.** The operator prefers small, phased deliverables with explicit acceptance criteria. Propose the minimum that satisfies the contract; flag speculative scope as such.
6. **Open questions are open.** Contract §14 lists seven. Take positions with rationale; do not silently resolve them.

## 7. Repository layout (current)

```
.
├── README.md                          # this file
├── knowledge-lifecycle-contract.md    # KLC v0.1 — governance spec (RFC)
└── diagrams/
    ├── plane-architecture.svg
    ├── knowledge-lifecycle.svg
    └── tier-state-machine.svg
```

## 8. Roadmap sketch (pre-implementation, subject to team review)

1. KLC v0.1 team review → v0.2 with tier vocabulary aligned to Knowledge Lake.
2. Policy language spike: Cedar vs. OPA evaluated against the six enforcement hooks (KLC §10) as the acceptance test.
3. Trust plane kernel skeleton: policy engine + label schema validation + audit events.
4. Lake integration: portable lake instance, authority map v0.1, quarantine ingest path.
5. Learning loop MVP: gap detection → authorized fetch → quarantine → dreaming cycle → gated promotion.
6. Gateway + web UI, scheduler with scoped task identities.
7. Persona layer (the hyungs move in).

---

*The youngest one, raised by the best of both. 막내 화이팅.*
