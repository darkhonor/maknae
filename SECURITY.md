# Security Policy

Maknae is a security-hardened AI agent platform whose entire premise is a deny-by-default trust plane. We take vulnerability reports seriously and handle them privately.

## Supported Versions

Maknae is pre-MVP and has not cut a release. The `main` branch is the only supported line; report against current `main`.

| Version | Supported |
|---------|-----------|
| `main`  | Yes       |
| tagged releases | none yet |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for a security vulnerability.**

Use this repository's **private vulnerability reporting**: [github.com/darkhonor/maknae/security/advisories/new](https://github.com/darkhonor/maknae/security/advisories/new) (GitHub → the repo's **Security** tab → **Report a vulnerability**). This keeps the conversation private between you and the maintainers until a fix is available.

Please include:

1. A description of the vulnerability.
2. The smallest steps or input that reproduce it.
3. A potential impact assessment.
4. Any suggested fix (optional).

You should receive an acknowledgement within **72 hours**, and we will work with you to understand the issue and coordinate a fix and disclosure timeline.

## What we consider high-priority

Given Maknae's threat model — the agent runtime is **untrusted by design** and the trust plane is the control — the following are treated as high severity:

- A mediated action that can **escape the reference monitor** (reach a resource without transiting the deny-by-default PDP).
- A **mandatory constraint that can be bypassed** — an administrative role, a "trusted" subject, or the kernel itself gaining access it is not cleared for (see [ADR-0020](design/adr/ADR-0020-access-control-model-and-vocabulary.md)).
- A **forged or improperly widened label, authority, or capability** — anything that lets untrusted content authorize itself, or a subject widen its own grants.
- **At-rest credential exposure** or a break in the HRoT-sealed bootstrap path (see [ADR-0018](design/adr/ADR-0018-local-plane-authorization-deployment-model.md)).
- Supply-chain or CI integrity weaknesses (dependency, build, or workflow tampering).

## Scope

This policy covers Maknae's own code and artifacts: the trust-plane kernel and `maknaed` daemon, the authorization seam and policy schema, the audit path, the enrollment/credential flow, the packaging, and the CI/build integrity of this repository.

It does **not** cover vulnerabilities in upstream dependencies (report those to their maintainers — e.g. the Rust toolchain, HashiCorp Vault, the container runtime) or in the external private classification (DCS) library, though a report of how Maknae *composes* or *invokes* a dependency insecurely is in scope.
