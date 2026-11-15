# Kubernetes Agent Sandbox — Assessment Against Maknae

| | |
|---|---|
| **Status** | Assessment record. It informs the Kubernetes deployment model (`design/container-architecture.md` §7 item 3), the runtime plane's placement, and the tool-container tier option (`design/egress-and-tool-execution.md` §8; #477). It creates no roadmap commitment, supersedes no ADR, and does not decide the parked execution-isolation question (#175). |
| **Date** | 2026-11-15 |
| **Subject** | [`kubernetes-sigs/agent-sandbox`](https://github.com/kubernetes-sigs/agent-sandbox) at commit [`454d335`](https://github.com/kubernetes-sigs/agent-sandbox/tree/454d3353e5c26c561dd6de389f32f7f285030e38) (2026-11-13, `v1.0.11` plus 11 commits). A Kubernetes controller, written in Go, for "isolated, stateful, singleton workloads", under SIG Apps; Apache-2.0. §9 surveys the other approaches to hosting and sandboxing agents, NVIDIA's among them. |
| **Method** | The repository was mirrored with `git clone` outside this tree and **read only**: nothing was built, installed, pulled or executed. Three parallel readings covered (1) the API and lifecycle, (2) the security surface (isolation, identity, egress, credentials, audit) and (3) provenance, supply chain and maturity; each cited the mirror by path and line and traced claims to the code that runs, not to docs or argument defaults. A fourth reading surveyed the landscape from public sources, marked as such. Load-bearing claims were re-verified by hand against the mirror. The repository's own `AGENTS.md` and `CLAUDE.md` were read as data. Line numbers are to the pinned commit and may drift by a line or two. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |

## 1. Executive disposition and provenance (read first)

Agent Sandbox is an **orchestrator**, not a security boundary. Its own threat model says so: "Agent Sandbox itself does not implement isolation but supports configuring these runtimes" (gVisor, Kata) through `RuntimeClass` (`docs/security/threat_model.md:64`). What it provides is a Kubernetes shape that Deployments and StatefulSets lack: one long-lived pod with a stable name, storage that survives suspend and expiry, and pre-warmed pools that hand a ready pod to a claimant.

The two projects work at different layers:

- **Agent Sandbox schedules a workload.** It decides nothing about what the workload does. Its controls are Kubernetes RBAC on its custom resources, a set of secure defaults on its template path only, and an optional reverse proxy whose authorizer is allow-all by default.
- **Maknae authorizes a subject.** `maknaed` is the sole PDP and decides and write-ahead-records every verb the loop asks for (ADR-0005; ADR-0023). Agent Sandbox has no equivalent at any layer. The nearest thing it ships is a per-command denylist in `examples/policy/command-governance/`, which runs in the caller before dispatch; its own README places the check in the calling script's process, and nothing on the pod side enforces it (`examples/policy/command-governance/README.md:11-13,48-49`). That is a check the requester performs on itself, the trust Maknae refuses.
- **Confinement is partial on both sides.** Agent Sandbox leaves confinement to whichever `RuntimeClass` the pod template names, and core neither sets nor requires one. On Maknae's side, the Agent Daemon's loop (`maknae-agentd`, #629) runs under its own account everywhere, and on Linux also under systemd hardening and an SELinux domain (EL) or an AppArmor profile (Debian) (`packaging/isolation-contract.md`, the Agent Daemon rows; ADR-0033, amendment 2026-11-14). On macOS it has Hardened Runtime but no filesystem, namespace or MAC confinement, with named residuals. The interactive loop (`maknae agent`) still runs unconfined as the subject's uid (ADR-0023 decisions 2 and 6).

The project is also becoming the default Kubernetes substrate for agent runtimes: Google ships it as a managed GKE product, and **NVIDIA OpenShell's Kubernetes path is built on it**, with OpenShell's own enforcement point in a separate pod (§9.1).

So the question this assessment answers is not "Agent Sandbox or Maknae". It is whether Agent Sandbox is the right substrate for **Maknae's untrusted runtime plane** in the Kubernetes deployment `container-architecture.md` §1.4 commits to, and what it would take to make it safe there. The short answer: **a reasonable candidate for scheduling the untrusted side, under constraints Maknae would impose itself (§5.1), and a source of several lessons in what not to do (§6).** The harder problem is Maknae's own: its ADRs define no channel by which a loop in its own pod could use the kernel's file verbs or carry a human's authority (§5.1, §8). Agent Sandbox does not solve that, and nothing else in the landscape does either (§9).

**Provenance.**

- **Owner and license.** The `kubernetes-sigs` organization, under SIG Apps (`README.md:17`). Apache-2.0 only (`LICENSE`).
- **Governance.**
  - Four root approvers (`OWNERS:3-7`) and three security contacts (`SECURITY_CONTACTS`). No OWNERS or doc file states an employer.
  - Contributions need the Kubernetes CLA, not a DCO (`CONTRIBUTING.md:11,19`). Vulnerabilities go to the Kubernetes Security Response Committee (`SECURITY.md:7-10`). No GitHub security advisories have been published.
  - **Commit concentration.** Of 1,307 non-merge commits from 197 authors, 38.9% come from `google.com` addresses (41.3% excluding Dependabot), and 9 of the top 15 human authors commit from `google.com`. Other employer domains include `docker.com` (74 commits, the first on 2026-09-30) and `redhat.com` (27). Many commits come from `noreply` and personal webmail addresses, which hide affiliation, so the Google share is a floor. Affiliation was read from commit email domains only, never inferred from names.
- **Maturity.**
  - First commit 2025-08-12; 1,372 commits at the pin.
  - `v1.0.0` shipped 2026-08-28 **on a `v1beta1`-only API**; `v1alpha1` was removed in it, and its conversion webhook left orphaned objects to delete by hand (`docs/api-migration-guide.md:1-55`). There is no GA API, no deprecation policy and no support window of the project's own (`SECURITY.md:12-15` defers to Kubernetes).
  - Since `v1.0.0` a scheduled workflow cuts a patch release **every Thursday** (`.github/workflows/release.yml:5-6`, cron `0 17 * * 4`), so `v1.0.x` numbers track the calendar, not the significance of the fixes. `RELEASE.md:12` says releases are "as-needed", which the cron contradicts.
- **Release provenance.**
  - Images are built by Google Cloud Build and promoted to `registry.k8s.io` through a reviewed pull request to `kubernetes/k8s.io`, the standard Kubernetes image-promoter path. All GitHub Actions are pinned by SHA.
  - The repository's own pipeline has **no** signing, SBOM or SLSA provenance step (no cosign, sigstore, syft, SPDX or CycloneDX reference outside docs and examples). Whatever the promoter adds is outside this repository and was not verified.
  - Release manifests, Helm values and the `Dockerfile`'s `FROM` lines reference images **by tag, not digest**. Release assets are YAML only, with no checksums.
  - The release job authenticates to Google Cloud with a **long-lived service-account JSON key**, with a `TODO` to move to workload identity, and uses three personal access tokens (`GH_AUTOMATION_PAT`, `K8S_IO_PAT`, `FORK_K8S_IO_PAT`; `.github/workflows/release.yml:41,70,136`).
  - The Python SDK is published to PyPI with OIDC trusted publishing. The TypeScript SDK is private and unpublished.
- **Size and dependencies.** About 24,000 lines of production Go in the controller, router and in-pod daemon (`api`, `cmd`, `controllers`, `extensions`, `internal`, `packages`, `sandbox-router`; tests and generated code excluded), about 76,000 lines of Go tests, 32 direct and 59 indirect Go module requirements, one of them (`gorilla/websocket`) pinned to an untagged pseudo-version.
- **Telemetry.** None found. OpenTelemetry tracing is opt-in and off by default (`cmd/agent-sandbox-controller/main.go:106`).

**The SCRM facts that decide posture** for a DoD-adjacent audience are the unsigned, tag-referenced release artifacts and the long-lived cloud key in the release job. Neither disqualifies the project as a *deployment* dependency of a Kubernetes profile, where a deployer pins by digest and admits images by policy; both mean a deployer, not this project, carries the provenance burden.

**Disposition.**

- **Learn** from its lifecycle model and from the specific mistakes in its defaults (§4, §6).
- **Compose** only outside Maknae's trust boundary, as the scheduler for untrusted runtime pods, with Maknae's own admission, identity and network constraints around it (§5).
- **Do not** take a code dependency on it, and do not route any Maknae trust-plane traffic through its router or its in-pod daemons.

## 2. What Agent Sandbox is

**The core.** One custom resource, `Sandbox` (`agents.x-k8s.io/v1beta1`), and its controller.

- The spec is a full `PodSpec` template, optional `volumeClaimTemplates`, an optional headless `Service`, a `failedPodPolicy` (`Retain` by default, or `Recreate`), an absolute `shutdownTime` with a `shutdownPolicy`, and an `operatingMode` of `Running` or `Suspended` (`api/v1beta1/sandbox_types.go:217-404`).
- **Stable identity comes from naming.** The pod is named after the Sandbox (`controllers/sandbox_controller.go:2029`), the optional headless Service shares that name, and PVCs are named `<template>-<sandbox>`. The controller sets no `hostname` or `subdomain`.
- **Singleton.** The controller refuses to choose or create when it finds more than one owned pod (`:1696-1735`).
- **Persistence.** PVCs are owned by the Sandbox and kept through suspend and expiry. They are garbage-collected only when the Sandbox object is deleted.
- **Suspend and resume.** `Suspended` deletes the pod and keeps the Sandbox and its PVCs; resume creates a new pod from the *current* template. There is no `replicas` field; automatic suspend on idle is on the roadmap only (`roadmap.md:17-18`).
- **No finalizers, no webhooks.** Validation is the CRD schema plus four CEL rules, none of which constrains the pod spec (`sandbox_types.go:227,309,340,450`).

**The extensions.**

- `SandboxTemplate`: an administrator-owned blueprint, with a generated NetworkPolicy and policies for what a claimant may inject (`extensions/api/v1beta1/sandboxtemplate_types.go:99-159`).
- `SandboxWarmPool`: a pool of ready Sandboxes built from a template, with a scale subresource for autoscaling (`sandboxwarmpool_types.go:40-141`).
- `SandboxClaim`: a request for a Sandbox from a named pool. A warm Sandbox is **adopted** by the claim: ownership moves to the claim and labels are rewritten, but the Sandbox and pod keep their pool-generated names (`extensions/controllers/sandboxclaim_controller.go:1482-1577`). A claim may change only allowlisted metadata, and environment variables and volume templates where the template allows them; either of the last two forces a cold start.

**The optional data path.**

- `sandbox-router`: an HTTP reverse proxy that routes SDK and external traffic to a sandbox pod by request headers.
- `sandboxd`: an in-pod daemon serving process execution (gRPC) and file operations (REST) (`packages/sandboxd`). The legacy `python-runtime-sandbox` example plays the same role on port 8888.
- SDKs in Go and Python (published) and TypeScript (private).

**What is only proposed.** The "Portable Backend" that would decouple the API from pods (KEPs #597 and #747) exists only as roadmap links marked "In Progress" (`roadmap.md:11-12`). The protobufs in the tree define `sandboxd`'s interface (KEP-539.2), not a backend abstraction; no controller code references them. Claim-time identity association and claim-time NetworkPolicy attachment are "Planned" (roadmap, Networking section).

## 3. The comparison table

The verdicts are:

- **OVERLAP**: both do it, and they converge.
- **LEARN**: Agent Sandbox does it well, and Maknae should take the idea.
- **INTEGRATE**: compose the two at an edge.
- **AVOID**: do not follow Agent Sandbox here.
- **MAKNAE STRONGER**: Maknae's current ADRs already do this better.
- **GAP**: Maknae is weaker today.

| # | Dimension | Agent Sandbox | Maknae (current ADRs and code) | Verdict |
|---|---|---|---|---|
| 1 | Core premise | A lifecycle orchestrator. "Does not implement isolation" (`threat_model.md:64`). Trust boundary: the controller and router are trusted, pods are not (`threat_model.md:48-54`). | The agent runtime is untrusted by design; `maknaed` is the sole PDP (ADR-0005; ADR-0023 decision 2). | **Different layers.** INTEGRATE (§5.1) |
| 2 | What is decided | Nothing per request. Kubernetes RBAC decides who may create the custom resources. | Every verb the loop asks for is decided and write-ahead-recorded (ADR-0009; ADR-0019; ADR-0023). | **MAKNAE STRONGER** |
| 3 | Containment of a compromised agent | Delegated to a `RuntimeClass` named in the pod template. Core neither sets nor requires one (`controllers/sandbox_controller.go:2011-2034`). The shipped Claude Code example runs on the default `runc` (`examples/claude-code-sandbox/template.yaml:20-26`). | On Linux, the Agent Daemon's loop is confined by systemd hardening and an SELinux domain (EL) or an AppArmor profile (Debian) (#629; `packaging/isolation-contract.md`); on macOS, only by its own account and Hardened Runtime. The interactive loop runs unconfined as the subject's uid (ADR-0023 decisions 2 and 6). Execution isolation is parked (#175). The isolation contract's Kubernetes cells are all `deferred`. | **A partial gap on both sides.** INTEGRATE: in Kubernetes, a pinned `RuntimeClass` is an obvious candidate (§5.1) |
| 4 | Admission of the workload's shape | The core controller copies the user's `PodSpec` and creates the pod under its own cluster-wide role (`controllers/sandbox_controller.go:2011-2040`; `k8s/rbac.generated.yaml:6-19`). Whoever may create a `Sandbox` gets an arbitrary pod in that namespace, with any ServiceAccount there, without holding `create pods`. Only Pod Security Admission and any policy engine still see the pod. No webhook or admission policy ships; secure policies exist only under `examples/policy/`. | No container launch exists today. The proposed launch shape is fixed and decided per invocation, with a parity test proving the spawned container matches the decision (#477; `egress-and-tool-execution.md` §8). | **AVOID** the broker without admission (§6.1) |
| 5 | When policy is enforced | Claim restrictions run in the reconciler **after** admission and surface as status conditions; the object already exists (`sandboxclaim_controller.go:1783-1910`). | Decide, record, then act; an `Indeterminate` blocks (ADR-0008; ADR-0019 audit-then-respond). | **AVOID** / **MAKNAE STRONGER** |
| 6 | Workload identity | A claim's identity is a label and an annotation (`agents.x-k8s.io/claim-uid`, `claim-name`). Warm-pool pods share the template's ServiceAccount, so every claim from one pool has the same Kubernetes identity. The docs say the metadata "alone does not authenticate a caller" (`docs/configuration.md:314-317`). | The principal is derived from a verified credential, never from the request: the uid locally, the IdP token's subject remotely (ADR-0006 decision 11), an enrolled agent's leaf on the agent channel (ADR-0006 decision 9). Persona is never an authorization input (ADR-0024 decision 4). | **MAKNAE STRONGER**; a real constraint on composition (§5.2) |
| 7 | Remote access to the workload | `sandbox-router`: plain HTTP, mTLS off and the authorizer **allow-all by default** (`sandbox-router/config/config.go:371-384`; Helm `values.yaml:44`). `tokenreview` mode authenticates only, and lets tokenless requests through unless told otherwise (`authz/tokenreview.go:166-176`). A caller-supplied `X-Sandbox-Pod-IP` makes the router dial any non-link-local address and port it can reach (`proxy/headers.go:194-208`; `proxy/resolve.go:92-94`). | The remote door is the gateway (#117): OIDC at the channel boundary, with `maknaed` verifying the IdP token itself (ADR-0006 decision 11). | **AVOID** the defaults; **LEARN** the scoped token (§4.3) |
| 8 | Execution inside the workload | `sandboxd` executes any argv it is sent; authentication is an optional single static token, off by default; its "execution policy" is time and byte limits only (`packages/sandboxd/cmd/sandboxd/main.go:69-74,125-128`; `pkg/server/process.go:103-109`). The Python example server runs `/bin/sh -c` on port 8888 with no authentication. | No execution verb exists (`terminal.*` unbuilt; #175 parked). Tools run through the kernel's verbs as the subject (ADR-0023 decision 4). | **AVOID** (§6.3) |
| 9 | Network egress | A NetworkPolicy is generated only for a template in `Managed` mode: ingress from the router only; egress to **all public addresses on all ports**, excluding RFC 1918, link-local and IPv6 ULA but **not** `100.64.0.0/10` (`extensions/controllers/sandboxtemplate_controller.go:196-252`). When that default policy is in force and the template leaves `dnsPolicy` unset, DNS defaults to `8.8.8.8` and `1.1.1.1` (`extensions/controllers/utils.go:33-46`). A bare `Sandbox` gets no policy. FQDN control appears only in Cilium and network-policy-api examples. | Model egress is decided per turn and executed by the Egress Daemon (ADR-0023 decision 3; ADR-0028). For the loop's own sockets, at most best-effort host rules (`packaging/isolation-contract.md`). `maknae-proxy` is proposed (`egress-and-tool-execution.md` §6). | **GAP** for Maknae's loop; **AVOID** the public resolvers (§6.4) |
| 10 | Credentials | The examples put provider keys into the agent as environment variables from Secrets, readable by the agent and anything it runs (`examples/claude-code-sandbox/template.yaml:46-50`; about two dozen example manifests use `secretKeyRef`). No proxy-side injection in core. | Kernel-blind: the key stays in Vault under the subject's own path; for each turn a response-wrapped token is sealed to the Egress Daemon, and the PDP never holds it (ADR-0028 decisions 3-5). **But any process running as the subject, the loop included, can read the subject's key**: accepted by ruling, with each read visible in Vault's audit log under the subject's identity (ADR-0028, Consequences). | **Neither keeps the key from the agent.** MAKNAE STRONGER on custody at the decision point and on auditability of a read; **GAP** against Docker Sandboxes and OpenShell, which keep it out of the workload (§9) |
| 11 | Audit | No record of what ran in a sandbox: `sandboxd` logs no commands or file operations; the router access log omits the caller's identity (`sandbox-router/observability/access_log.go:150-166`). The apiserver audit log records changes to the custom resources. | Audit-then-respond to an append-only sink, fail closed on a write failure (ADR-0019). | **MAKNAE STRONGER** |
| 12 | Lifecycle and persistence | A singleton with a stable name; storage kept across suspend and expiry; suspend and resume; warm pools that cut claim latency to "seconds, not image-pull minutes" (`examples/claude-code-sandbox/README.md`). | No runtime orchestration. The runtime plane is stateless by declared design: the transcript is in memory for one run (ADR-0023 decision 2; `container-architecture.md` §1.5). | **LEARN** / INTEGRATE (§4.1) |
| 13 | Drift between decision and running state | The running pod's spec is never compared or enforced (`controllers/sandbox_controller.go:1942`, `// TODO - Do we enforce (change) spec if a pod exists ?`). Warm-pool staleness depends on a hand-maintained comparison, kept in step by a comment (`api/v1beta1/sandbox_types.go:273-276`). | Proposed: a parity test between the launch decision and what is spawned (#477; #420 decision 10). For security enums, AGENTS.md already requires a `match` with no `_` arm, so a new variant fails to compile until someone decides it. | **AVOID** (§6.5) |
| 14 | Supply chain | Actions pinned by SHA. No signing, SBOM or provenance in the repository's pipeline; images referenced by tag; a long-lived cloud key in the release job; calendar patch releases on a beta API (§1). | `cargo deny --locked check` as the supply-chain gate, with every pin documented (AGENTS.md conventions). | **AVOID** the release practices; neither side is assessed further here |
| 15 | Telemetry | None. OTLP export goes only where the operator points it. | None. | **OVERLAP** |
| 16 | Platforms | Kubernetes (1.29 or later recommended; tested against the newest only, `README.md:91-95`). | Host packages on Linux and native macOS today; a Kubernetes deployment is target model (ADR-0006 container mode; `container-architecture.md`). | **Different targets**; complementary for the Kubernetes profile |

## 4. What Agent Sandbox does well — LEARN FROM

### 4.1 A singleton workload with a stable name and storage that outlives the pod

The `Sandbox` resource captures a shape that neither a Deployment nor a one-replica StatefulSet expresses cleanly: exactly one pod, named predictably, whose storage survives suspension and expiry and is removed only by an explicit delete. The `Suspended` mode separates "not running" from "gone".

**For Maknae:** this is the right shape for an Agent Daemon if it ever runs in pods. An Agent Daemon is a long-lived subject with its own identity (ADR-0024 decision 6, added 2026-10-22); it is built today as a host service, one instance per enrolled agent (#629; ADR-0033). Its Kubernetes form is target model only: ADR-0006 decision 9 specifies a TCP machine channel across pods with the agent's leaf as the only factor, and a first Vault credential from Vault's Kubernetes auth method; what #609 built binds no agent listener in container mode. In pods it would be one stable instance, never a replica set, and suspension should not destroy what it is allowed to keep. The interactive loop is different: it holds nothing durable (ADR-0023 decision 2), so a pool of identical, disposable loop pods would fit it, subject to §5.1 and §5.2.

### 4.2 Pre-warmed pools and claim latency as a measured target

The project treats time-to-ready as a requirement: warm pools, claim adoption that avoids a cold start, and a roadmap target for claim latency (200 ms, then 100, then 50) and for time to first instruction (`roadmap.md`, Scale section).

**For Maknae:** if the runtime plane moves into pods, start-up latency becomes a user-visible property of every conversation. It should be measured and gated from the first Kubernetes slice, the way coverage and mutation are (ADR-0016), rather than discovered.

### 4.3 A capability token bound to the exact object and operation

The router's `scoped-token` v2 mode signs, with Ed25519, a token over the namespace, the Sandbox name **and its UID**, the port, the HTTP method, the path and an expiry, and refuses the caller-supplied IP header when it is in use (`sandbox-router/authz/scopedtoken_v2.go:39-43`; `authz/scopedtoken.go:241-293`). Binding the object's UID means a deleted and re-created sandbox with the same name does not inherit an old token.

Two caveats narrow it. A v2 token with the `sandbox` scope authorizes every port, method and path of that Sandbox (`authz/scopedtoken_v2.go:44-47`; `authz/scopedtoken.go:279-281`). And legacy v1 tokens, which bind only the namespace, the name and an expiry with no UID, are still accepted beside v2.

**For Maknae:** the narrow v2 form is the same binding discipline as ADR-0028's sealed wrapping token, whose associated data binds the conversation, provider, model and full Vault path. It is a confirmation, not something new. The caveats are the lesson: a broad scope and an accepted legacy form each undo the narrow binding. The router also has no revocation; its tokens are limited only by expiry.

### 4.4 Reserved labels the user cannot set

The controller strips every key under `agents.x-k8s.io/` and `extensions.agents.x-k8s.io/` from user-supplied templates, so a tenant cannot set the label the headless Service selects on and hijack another sandbox's traffic (`controllers/sandbox_controller.go:1246-1257`; `threat_model.md:80-120`). This is the one threat in its model with a detailed, code-backed control.

**For Maknae:** the same principle as deriving the Vault path's owner segment from the authenticated subject and never from the request (ADR-0028 decision 3). **OVERLAP.** The residual the reading found is instructive: a principal who can create pods directly can still set the label, and a 32-bit FNV-1a hash of the name is the selector, so two names that collide in a namespace would merge their endpoints (`:1221-1240`). Identity that matters should not rest on a short hash.

### 4.5 A threat model that states its own gaps

The threat model says plainly that the router's default authorizer is allow-all "for Python client compatibility" and that its IP-class check "is currently the *only* SSRF defense" (`threat_model.md:75`), and that WebSocket and connection limits are not implemented (`:76`). The project's defaults are weak, but it does not hide them.

**For Maknae:** the same honest-conformance standard the OpenShell assessment credits (its §4.7). Nothing new to adopt; worth citing when a deployer asks why Maknae will not route through the router.

### 4.6 Ready-made admission policies for a hardened profile

`examples/policy/vap/secure-sandbox-policy.yaml` is a `ValidatingAdmissionPolicy` that requires the gVisor `RuntimeClass`, no host networking, no service-account token automount, no privileged containers, all capabilities dropped, resource limits and a non-root user. Kyverno, Gatekeeper and Sigstore policy-controller variants sit beside it.

**For Maknae:** a starting point for the Pod Security Admission levels and admission set that `container-architecture.md` §7 item 3 leaves open. They are examples, not shipped controls, and would be Maknae's to own and test.

## 5. Where the two can be composed — INTEGRATE

### 5.1 Agent Sandbox as the scheduler for Maknae's untrusted runtime plane

In a Kubernetes deployment, the split `container-architecture.md` §1 draws maps onto Agent Sandbox directly:

- **The trust plane stays out of it.** `maknaed` and the Egress Daemon run as ordinary workloads that Agent Sandbox does not manage. Their identity, storage and network policy are Maknae's.
- **The runtime plane is scheduled by it.** The interactive loop, an Agent Daemon, and any tool container from #477's tier option run as Sandboxes created only from administrator-owned `SandboxTemplate`s.

Composition is safe only under constraints Agent Sandbox does not impose by default:

1. **No one but the deployment's own controller may create a bare `Sandbox`.** RBAC grants claim creation, not Sandbox creation, because the bare path gets none of the template path's defaults and the controller creates whatever pod it is given (§3 row 4).
2. **An admission policy pins the shape,** in the spirit of §4.6: the confining `RuntimeClass`, no host namespaces, no privilege, no token automount, non-root. It is the deployer's control, tested with a negative control as Maknae's gates are.
3. **The router and `sandboxd` are not deployed.** Nothing reaches into a runtime pod to execute commands. How the loop reaches `maknaed` is the open problem below, not something this constraint settles.
4. **Egress from a runtime pod is denied except to `maknaed`, the Egress Daemon and the cluster's DNS.** The managed NetworkPolicy's "all public addresses" default and its public resolvers are replaced, which Agent Sandbox allows (`sandboxtemplate_controller.go:104-121`).
5. **Images are referenced by digest,** whatever the upstream manifests do.

**What does not carry over: the loop's channel to the kernel.** Maknae's ADRs do not yet define how a loop in its own pod would talk to `maknaed`, and the gap is structural:

- **The file verbs are local-lane only.** On the local lane the client process is the subject: `maknaed` takes its uid from the socket's peer credentials, and the client opens the object itself and hands the descriptor over the socket with `SCM_RIGHTS` (ADR-0009 decision 1). Filesystem attempts are local-lane only (decision 8), and the remote lane's equivalent is unsolved and out of scope (decision 11), owed by #195. A loop in another pod, over TCP, has neither a peer uid nor a descriptor to delegate.
- **No channel carries a human's authority from an untrusted pod.** The interactive loop holds no identity of its own and acts within the invoking human's delegation (ADR-0024 decision 2). Off-host, the principal is the IdP token's subject, verified by `maknaed` through the gateway's channel (ADR-0006 decision 11; #117). No ADR lets an untrusted runtime pod present a human's principal.
- **The Agent Daemon's planned pod channel authenticates the agent but carries no file verbs.** ADR-0006 decision 9 specifies it as target model (TCP across pods, the leaf as the only factor), unbuilt: what #609 built binds no agent listener in container mode. Like any lane without peer credentials and descriptor passing, it cannot serve ADR-0009's file verbs as designed. The two accepted ADRs do not contradict each other, but together, ADR-0006 decision 9's container mode and ADR-0009 decisions 8 and 11 leave a containerized Agent Daemon with no file verbs, persona writes included. Closing that gap would amend one of them.

One option worth recording: `maknaed` as a sidecar in each runtime pod, sharing a Unix socket on a pod-local volume, which would keep the local-lane model. It would also put the trust plane inside the same pod, and under gVisor or Kata inside the same sandbox kernel or VM, as the untrusted loop, which is the opposite of the separation the rest of this section draws. Neither option is assessed further here (§10).

**There is a precedent for the shape, though not for this channel.** NVIDIA OpenShell's Kubernetes path has this shape (§9.1): Agent Sandbox creates the workload pod, the enforcement point runs in a separate pod outside it, and a NetworkPolicy denies connections the workload initiates. Its driver documentation states constraint 1 independently.

Once the channel exists, this would give the loop an outer fence and a kernel boundary in that profile. **It does not decide #175.** Execution isolation stays parked by maintainer ruling; this records a Kubernetes-specific option as research input, as the OpenShell assessment did for the host case (its §4.1 and §5.1).

### 5.2 Per-agent identity and warm pools do not mix today

ADR-0006 decision 9 specifies, as target model, that an Agent Daemon in container mode takes its first Vault credential from Vault's Kubernetes auth method, as ADR-0018 decision 4 does for the trust-plane daemon. Its Vault role is then keyed on its pod's ServiceAccount. Agent Sandbox's warm-pool pods all share their template's ServiceAccount, and a claim cannot change it (§3 row 6). So:

- **A per-agent pod identity rules out shared pools.** Each agent would need a cold-started Sandbox of its own, from a per-agent template with a per-agent ServiceAccount. An Agent Daemon is long-lived, so the cold start costs little.
- **A warm pool fits only a runtime that carries no identity of its own,** and that runtime still needs the channel §5.1 says does not exist.
- The project's planned "Sandbox / pod identity association at claim time" (roadmap, Networking section) would change this. Until it ships and is assessed, Maknae should assume pod identity is per template.

### 5.3 Maknae as the authority on what may be launched

A further, speculative composition: an admission webhook backed by `maknaed` that decides whether a subject may claim a runtime of a given template, and records the decision. It would put sandbox creation under the same PDP and trail as every other verb, and give #477's parity test a decision to compare against. It would also make the API server's admission path depend on `maknaed`'s availability. Recorded as an open question (§10), not a recommendation.

## 6. What to avoid — AVOID

### 6.1 A controller that creates whatever pod it is handed

The core controller holds cluster-wide `create` on pods and copies the requester's `PodSpec` into a pod it creates under its own identity. Kubernetes RBAC on `pods` no longer applies to the requester; only Pod Security Admission and any policy engine still see the pod. **For Maknae:** any component that launches containers for a subject decides the launch shape itself and holds the decision, as #477 proposes. It never relays a shape the requester wrote.

### 6.2 Security defaults on one path only

The template path defaults service-account token automount off and generates a NetworkPolicy; the bare `Sandbox` path does neither (`extensions/controllers/utils.go:24-48` is called only from the claim and pool controllers). A control that applies on one path and not its sibling is a bypass with documentation. **For Maknae:** one path, or the same control on every path, which is what `maknae-io` and `program::command` already enforce for I/O and process launch (AGENTS.md conventions).

### 6.3 Unauthenticated execution endpoints and allow-all defaults

`sandboxd` and the Python example server execute what they are sent, unauthenticated by default, bound to every interface. The router allows everything by default and will dial an address the caller names. Their own comment says containment comes "from pod isolation and NetworkPolicy, not loopback binding" (`packages/sandboxd/cmd/sandboxd/main.go:25-27`), and a bare Sandbox has no NetworkPolicy. **For Maknae:** deny by default, everywhere (core principle 1). There is nothing to adopt here.

### 6.4 Hard-coded public resolvers

The managed defaults set the pod's DNS to `8.8.8.8` and `1.1.1.1` (`extensions/controllers/utils.go:45`). In an enclave they are unreachable; anywhere, they are an exfiltration channel that bypasses the cluster's own resolver and its logging. **For Maknae:** name resolution for a runtime pod goes to the deployment's resolver, and to nothing else.

### 6.5 Drift detection kept in step by a comment

Two drift checks rest on discipline: the running pod's spec is never reconciled (the `TODO` at `controllers/sandbox_controller.go:1942`), and warm-pool staleness depends on a function a comment asks contributors to update whenever a blueprint field changes (`api/v1beta1/sandbox_types.go:273-276`). **For Maknae:** the same reasoning AGENTS.md applies to security enums (a `match` with no `_` arm, so a new variant fails to compile until someone decides it) applies to a field comparison: destructure the struct exhaustively, so a new field fails to compile until someone decides how to compare it.

### 6.6 Release practices

Calendar-driven patch releases on a beta API, unsigned and tag-referenced artifacts, and a long-lived cloud key in the release job (§1). **For Maknae:** nothing to adopt, and a deployer composing with Agent Sandbox pins its images by digest and verifies what it can.

## 7. Where Maknae is stronger under its current ADRs

- **Per-request decision and record.** Every verb is decided by one PDP and recorded before it acts (ADR-0005; ADR-0019). Agent Sandbox decides only at the API server, on object creation.
- **Identity from a verified credential.** The principal never comes from the request (ADR-0006; ADR-0028 decision 3); Agent Sandbox's per-claim identity is a label.
- **Credential custody at the decision point.** The PDP never holds a key, and every read of one is a wrapped read in Vault's audit log under the reader's identity: the subject's own, or, for an agent's key, an administrator holding `maknae-admin-agent-credentials`, which ADR-0028 accepts (decision 3, amended 2026-11-13). Agent Sandbox's examples put keys in environment variables, with no record of their use. This is not custody from the agent (§8).
- **Mandatory controls.** A classification ceiling and the `sensitive.yaml` operand that no role bypasses (ADR-0008; ADR-0034). Agent Sandbox has no notion of data, only of pods.
- **Audit.** Audit-then-respond and fail closed (ADR-0019), against no record of what ran.

## 8. Where Maknae is weaker — honest gaps

- **There is no Kubernetes profile yet.** Container builds are shelved until #117 (ADR-0006, container mode); `container-architecture.md` §7 item 3 leaves the profile open, and the isolation contract's Kubernetes cells are all `deferred`. Agent Sandbox ships one, however permissive.
- **Confinement is partial.** The interactive loop is unconfined (ADR-0023 decisions 2 and 6). The Agent Daemon's loop is confined on Linux (#629); on macOS, a production platform, it has no filesystem, namespace or MAC confinement and no `NoNewPrivileges`, and the isolation contract names the routes that leaves to a person's terminal and mailbox (`packaging/isolation-contract.md`, the Agent Daemon report-path row). In Kubernetes, a `RuntimeClass` would be the cheapest outer fence available; on hosts, the OpenShell assessment's §4.1 applies.
- **The agent can read its own provider key.** By ruling, any process running as the subject, the loop included, can make a wrapped read of the subject's key and call the provider without `maknaed`; the read is visible in Vault's audit log, and correlating those reads with Maknae's trail is #429, not yet built (ADR-0028, Consequences). Docker Sandboxes and OpenShell keep the key out of the workload entirely (§9).
- **The verb model has no remote lane for files.** The file verbs depend on the local socket's peer credentials and descriptor passing (ADR-0009), so a runtime in its own pod cannot use them as designed (§5.1).
- **Start-up latency is unmeasured.** No Maknae gate measures time to first instruction.
- **A stateless, scalable `maknaed` meets durable state the ADRs place in the daemon.** A stateless kernel that scales is the maintainer's stated direction for the Kubernetes deployment (2026-11-15); `container-architecture.md` §1 declares only the *runtime* plane stateless. The PDP decides each request from a snapshot, which scales. But ADR-0029 gives `maknaed` an encrypted enforcement-state store with live transitions, and anchors rollback detection to the daemon's own audit trail (decisions 8 and 9); ADR-0019's primary sink is a local append-only JSONL file. Several replicas would each hold a store and a trail. Running `maknaed` as a scaled Deployment needs a decision on where the store and the trail live, and on how a rollback anchor works across replicas. This is the largest design question the Kubernetes profile raises, and Agent Sandbox does not help with it: it schedules the untrusted side, not the trusted one.

## 9. The landscape: other approaches to hosting and sandboxing agents

This section is from public material read on 2026-11-15, plus `gh api` reads of public repositories. It is context, not code-level assessment. "Documented" means the vendor's documentation describes the mechanism; "claimed" means only marketing or a blog asserts it.

**The axis that matters for Maknae** is whether a component outside the agent decides each of the agent's actions at the time of the action, and records the result. A static allowlist at a proxy is "network only".

| Approach | Owner, license | Isolation boundary | Where it runs | Credentials | Per-action decision | Status at 2026-11-15 |
|---|---|---|---|---|---|---|
| Agent Sandbox (this record) | Kubernetes SIG Apps, Apache-2.0 | Whatever `RuntimeClass` the pod names | Any Kubernetes | Out of scope | **No** | `v1.0.11`, `v1beta1` API |
| NVIDIA OpenShell | NVIDIA, accepted as a CNCF Sandbox project; Apache-2.0 | Landlock, seccomp and a network namespace in a container or pod; a microVM driver; on Kubernetes, the pod's `RuntimeClass` | Self-hosted: Docker, Podman, microVM, **Kubernetes on Agent Sandbox**, OpenShift | Held by the supervisor; placeholders swapped at L7 | **Yes, for network, HTTP and MCP tool names**, OPA-based (Cedar announced, open pull requests only) | Alpha, `v0.1.8` (2026-11-10) |
| NVIDIA NemoClaw | NVIDIA, Apache-2.0 | Inherits OpenShell | Self-hosted; an Agent Sandbox example | Inherits OpenShell | Inherits OpenShell | Alpha, `v1.0.0-rc1` tag (2026-10-20) |
| NVIDIA Sentry on BlueField-4 | NVIDIA, proprietary | Out-of-band, on the DPU | On-premises hardware | Claimed | Claimed only | Announced 2026-09-28; no SKU or ship date found |
| Docker Sandboxes (`sbx`) | Docker, proprietary CLI | A microVM per sandbox, with its own kernel and Docker daemon | Desktop; Docker-managed cloud (2026-09-24). No Kubernetes or self-hosted server | Documented: a host proxy swaps a placeholder for the real credential, which never enters the VM | Network only, with interactive approval of unknown hosts in its "balanced" preset | `sbx` `v0.53.0` (2026-11-11) |
| GKE Agent Sandbox | Google, managed | gVisor; Kata pluggable | GKE | Workload Identity | **No** | GA (2026-05-21) |
| Agent Substrate | Google-led, CNCF Sandbox, Apache-2.0 | gVisor or a Cloud Hypervisor microVM per worker | Kubernetes, tuned for GKE | Per-actor scoped snapshot credentials | **No** | `v1.0.0` (2026-11-05) |
| Alibaba OpenSandbox | `opensandbox-group`, Apache-2.0 | Container plus Kata, or Firecracker; gVisor documented as unsupported for its egress enforcement | Docker; its own Kubernetes operator (not Agent Sandbox) | Documented: a credential vault in the egress sidecar | Network only, with operator floors user policy cannot override, fail-closed start | `release-1.2.1` (2026-11-13) |
| E2B | E2B, Apache-2.0 SDK and infrastructure | Firecracker microVM | SaaS; bring-your-own-cloud; self-host via Terraform | Claimed: resolved at egress | Network only | Active |
| Modal Sandboxes | Modal, proprietary | gVisor | SaaS | A secret-holding sidecar is a documented pattern, not a platform feature | Network only | GA |
| Cloudflare Sandbox SDK | Cloudflare, proprietary platform | A container in VM-isolated Containers | SaaS | Documented: an outbound Worker holds secrets outside the sandbox | **HTTP(S) only, programmable**: customer code runs on every outbound request; other ports bypass it | GA (2026-04-13) |
| Azure Container Apps dynamic sessions | Microsoft, proprietary | Hyper-V per session | Azure | Entra role gates the pool | **No** | GA |
| Hyperlight | Microsoft, CNCF Sandbox, Apache-2.0 | A micro-VM with no guest OS; the guest reaches the host only through functions the embedder exposes | Embedded; Kubernetes through a `RuntimeClass` | Through host functions | Structurally possible at the host-function boundary; no policy engine ships | Active |
| AWS Bedrock AgentCore Runtime and Code Interpreter | AWS, proprietary | microVM per session | AWS | IAM; the developer maps sessions to users | **No** | GA |
| AWS AgentCore Policy | AWS, proprietary | n/a (a gateway) | AWS | n/a | **Yes, for tool calls**: Cedar, deny by default, at the AgentCore Gateway | GA (2026-03-03) |
| AWS Nitro Sandboxes for EKS | AWS, proprietary | A Nitro VM per pod, with an attested confidential mode | EKS, as a `RuntimeClass` | KMS release gated on attestation (confidential mode) | **No** | Launched 2026-11-09 |
| gVisor, Kata Containers, Firecracker | Google, OpenInfra, AWS; Apache-2.0 | User-space kernel, VM per pod, microVM | Under every self-hosted entry above | n/a | **No** | Each released within the last month |

### 9.1 NVIDIA

NVIDIA's offer to enterprises has four layers. What is shipped and what is announced differ:

1. **OpenShell is shipped, alpha and open source,** and was assessed on 2026-09-29 (`2026-09-29-openshell-assessment.md`). Since then, six releases (`v0.1.3` to `v0.1.8`), acceptance as a CNCF Sandbox project, and a move toward a neutral organization. Of the changes, the ones that bear on Maknae:
   - **Its Kubernetes path is built on Agent Sandbox.** The setup guide makes the Agent Sandbox controller and CRDs a prerequisite: "OpenShell uses the Agent Sandbox Kubernetes SIG project to provision sandbox pods" (`docs/kubernetes/setup.mdx:50`). The gateway's driver creates a `Sandbox` resource **and a separate supervisor pod**; Agent Sandbox creates the workload pod from the resource; a NetworkPolicy "allows only supervisor ingress to the workload's boundary port and denies new workload-initiated connections", and the supervisor decides and opens every approved upstream connection (`setup.mdx:21-32`).
   - **Its driver states the trust Agent Sandbox needs.** "Only the driver and its trusted Agent Sandbox controller may administer the sandbox namespace, Sandbox CRs, sandbox pods, or configured sandbox ServiceAccount", and its namespace allowlist "is not a tenant isolation boundary" (`crates/openshell-driver-kubernetes/README.md:56-64`). That is §5.1 constraint 1, reached independently.
   - The gateway now refuses to start without OIDC, mutual TLS or a gateway JWT (`v0.1.6`), and audit is OCSF 1.8.0 only (`v0.1.7`). Cedar is announced; in code it is an open RFC and open pull requests, and the shipped engine is OPA-based.
   - The setup guide installs Agent Sandbox from `releases/latest` (`setup.mdx:55`), unpinned.
2. **NemoClaw is shipped and alpha.** A reference stack running OpenClaw, Hermes or LangChain Deep Agents inside OpenShell, with inference routed to NVIDIA's hosted endpoints by default. Agent Sandbox's own example (`examples/nemoclaw-sandbox`) installs OpenShell's gateway with unauthenticated users allowed and TLS off, pinned to chart `0.0.116`, older than the release that made authentication mandatory (`examples/nemoclaw-sandbox/README.md:44-46`).
3. **The Secure Agent Workspace Reference Design (2026-06-29) is a published design, not a product.** OpenShell on Red Hat OpenShift Virtualization on premises, or on Azure; single-sign-on workspaces; each agent registered to a sponsor with a delegation record; a credential proxy; signed policy bundles distributed by GitOps; OCSF to a SIEM. This is the clearest statement of what NVIDIA proposes to enterprises.
4. **Sentry on BlueField-4 is announced.** Its page offers only the DOCA SDK; no SKU, price, ship date or Kubernetes integration was found.

No NVIDIA AI Enterprise, NIM, Run:ai or Blueprint offering that packages agent sandboxing was found.

### 9.2 What the landscape says

- **The hosting layer does not decide.** Agent Sandbox, GKE Agent Sandbox, Agent Substrate, Nitro Sandboxes, Azure dynamic sessions, E2B and Modal provide isolation and lifecycle. None decides an agent's actions.
- **Decisions appear in three places,** all outside the sandbox: OpenShell's supervisor (network, HTTP and MCP tool names), AWS AgentCore Policy (tool calls, AWS only) and Cloudflare's outbound Workers (HTTP only). Docker comes closest on the desktop with interactive approval of unknown hosts.
- **None has what Maknae's PDP has:** a mandatory classification ceiling, a deny-overrides composition of mandatory and discretionary operands, or a request-time decision over file operations. OpenSandbox's operator floors that user policy cannot override are the nearest structural relative, and they apply to egress only.
- **Credentials held outside the sandbox are now the norm:** Docker, OpenShell, OpenSandbox and Cloudflare document it, and Modal documents it as a pattern. Maknae is behind the field here: under ADR-0028 the loop can read its subject's key, by ruling. It differs in one respect the others do not claim: the decision point (`maknaed`) never holds the key.
- **Agent Sandbox is becoming the Kubernetes primitive.** GKE ships it as a managed product and OpenShell builds on it. A Maknae Kubernetes profile that uses it would compose with the same substrate as the nearest comparable system.
- **Standards are early.** No sandbox API standard is ratified. Docker's Sandbox Kit specification (Apache-2.0, with stated intent to give it to the CNCF) standardizes what an agent image declares it needs, not the decision.
- **A provenance note:** Daytona's public repository was archived after development moved private in 2026-06; anyone self-hosting it is on a frozen fork.

**Landscape sources (read 2026-11-15).**

- OpenShell: [releases](https://github.com/NVIDIA/OpenShell/releases); [Kubernetes setup](https://github.com/NVIDIA/OpenShell/blob/main/docs/kubernetes/setup.mdx); [Kubernetes driver README](https://github.com/NVIDIA/OpenShell/blob/main/crates/openshell-driver-kubernetes/README.md); [CNCF donation note](https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-11-09-donated-openshell-to-cncf/); [NVIDIA KubeCon blog](https://blogs.nvidia.com/blog/open-source-openshell-infrastructure/)
- NVIDIA: [Secure Agent Workspace Reference Design](https://developer.nvidia.com/blog/how-to-govern-autonomous-agents-in-enterprise-ai-factories/); [Sentry](https://www.nvidia.com/en-us/networking/products/software/sentry/); [Open Agent Safety Platform](https://nvidia.com/en-us/solutions/ai/agent-safety); [NemoClaw](https://github.com/NVIDIA/NemoClaw)
- Docker: [security](https://docs.docker.com/ai/sandboxes/security/); [architecture](https://docs.docker.com/ai/sandboxes/architecture/); [Cloud Sandboxes](https://www.docker.com/blog/introducing-cloud-sandboxes/); [Sandbox Kit spec](https://docker.com/blog/docker-sandbox-kit-spec-cncf)
- Google: [GKE Agent Sandbox and Agent Substrate](https://cloud.google.com/blog/products/containers-kubernetes/bringing-you-agent-sandbox-on-gke-and-agent-substrate); [Agent Substrate](https://github.com/agent-substrate/substrate)
- [OpenSandbox egress design](https://github.com/opensandbox-group/OpenSandbox/blob/main/docs/architecture/network/egress.md); [E2B](https://e2b.dev/enterprise); [Daytona](https://github.com/daytonaio/daytona); [Modal networking](https://modal.com/docs/guide/sandbox-networking); [Cloudflare outbound traffic](https://developers.cloudflare.com/sandbox/guides/outbound-traffic/)
- Microsoft: [Azure dynamic sessions](https://learn.microsoft.com/en-us/azure/container-apps/sessions); [Hyperlight](https://www.cncf.io/blog/2026/11/09/run-linux-applications-in-hypervisor-isolated-micro-vms-with-hyperlight/)
- AWS: [AgentCore Runtime sessions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-sessions.html); [AgentCore Policy GA](https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available); [Nitro Sandboxes for EKS](https://aws.amazon.com/blogs/containers/aws-nitro-sandboxes-hardware-enforced-workload-isolation-on-amazon-eks/)

## 10. Open questions for the maintainer

1. **The Kubernetes runtime-plane substrate.** Should the Kubernetes profile schedule the runtime plane with Agent Sandbox under §5.1's constraints, or with plain Deployments and StatefulSets that Maknae owns end to end? (`container-architecture.md` §7 item 3.)
2. **A `RuntimeClass` as input to #175.** In the Kubernetes profile, is a pinned gVisor or Kata `RuntimeClass` an acceptable answer to the loop's confinement, recorded as research input only while the ruling stands?
3. **`maknaed` at scale.** Where do ADR-0029's store and ADR-0019's primary sink live when `maknaed` runs as more than one replica, and what anchors rollback detection then (§8)?
4. **The loop's channel in pods.** This is the containerized form of #195. Should a runtime pod reach `maknaed` through a remote lane whose file model does not depend on peer credentials and descriptor passing (#195's question), or through a `maknaed` sidecar on a pod-local socket, accepting that the trust plane then shares the untrusted pod (§5.1)?
5. **Agent identity in pods.** ADR-0006 decision 9 gives an Agent Daemon in container mode its first Vault credential through Kubernetes auth, and its de-enrollment removes "the agent's Kubernetes auth role", which implies one role per agent. Does #472's layout carry that role, and is one cold-started Sandbox and one ServiceAccount per agent (§5.2) the intended shape?
6. **Launch under the PDP.** Should creating a runtime pod be a decided and recorded verb, through an admission webhook backed by `maknaed` (§5.3), and how would the API server degrade when `maknaed` is unavailable?
7. **SCRM ownership.** If any composition goes ahead, who owns the evaluation of Agent Sandbox's unsigned, tag-referenced artifacts for a given deployment?

## 11. Sources

**Primary (the mirror, at `454d335`).** Paths cited inline are relative to the repository root.

- `README.md`, `roadmap.md`, `RELEASE.md`, `SECURITY.md`, `SECURITY_CONTACTS`, `OWNERS`, `CONTRIBUTING.md`, `LICENSE`
- `docs/security/threat_model.md`, `docs/configuration.md`, `docs/api-migration-guide.md`, `docs/keps/`
- `api/v1beta1/sandbox_types.go`, `controllers/sandbox_controller.go`, `k8s/rbac.generated.yaml`, `k8s/hardening/networkpolicy.yaml`
- `extensions/api/v1beta1/`, `extensions/controllers/` (`utils.go`, `sandboxtemplate_controller.go`, `sandboxwarmpool_controller.go`, `sandboxclaim_controller.go`)
- `sandbox-router/` (`config/config.go`, `cmd/main.go`, `authz/`, `proxy/`, `observability/access_log.go`, `helm/values.yaml`, `deploy/`)
- `packages/sandboxd/`, `examples/python-runtime-sandbox/`, `examples/claude-code-sandbox/`, `examples/docker-sbx/`, `examples/policy/`
- `.github/workflows/release.yml`, `.github/workflows/pypi-publish.yml`, `cloudbuild.yaml`, `Dockerfile`, `go.mod`
- `git shortlog -sn --no-merges`, `git log --format=%ae`, `git tag --sort=creatordate`; `gh api repos/kubernetes-sigs/agent-sandbox` and its `releases`, `contributors` and `security-advisories` endpoints (read 2026-11-15)

**Landscape (public material, context only).** Listed at the end of §9.2.

**Maknae.** ADR-0005, ADR-0006, ADR-0008, ADR-0009, ADR-0016, ADR-0018, ADR-0019, ADR-0023, ADR-0024, ADR-0028, ADR-0029, ADR-0033, ADR-0034; `design/container-architecture.md`; `design/egress-and-tool-execution.md`; `packaging/isolation-contract.md`; `design/references/2026-09-29-openshell-assessment.md`; issues #117, #175, #195, #420, #429, #472, #477, #609, #629.
