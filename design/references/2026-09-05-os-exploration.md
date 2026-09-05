# OS Exploration — Maknae and a Managed Agent Operating Environment

| | |
|---|---|
| **Status** | Exploratory reference — candidate directions, not an accepted architecture or implementation commitment |
| **Date** | 2026-09-05 |
| **Origin** | Operator discussion: Maknae's TCB increasingly resembles parts of an operating system; would an OS surrounding it improve secure agentic work? |
| **Additional operator input** | Consider routing agent execution through Maknae-spawned, managed containers with specific file/project mounts and a container runtime capable of running as non-root; Maknae owns their lifecycle. |
| **Method** | Review of current code, ADRs, open issues, and upstream runtime documentation. No runtime installation, container execution, or feasibility benchmark was performed. |

## 1. Assessment

There is a substantial potential benefit in a purpose-built operating environment around Maknae: it could enforce the boundaries of an agent's assigned work beneath the agent itself. That benefit does not, by itself, establish a need to write a new OS kernel. A managed execution layer on existing hosts, a minimal Linux appliance, a system built on an established microkernel, and a new Rust OS are distinct directions with different costs and assurance claims.

The operator's managed-container idea is a concrete reason to explore this progression. Maknae could authorize an execution scope and construct an environment exposing only the resources needed for that scope. Descendant processes would remain inside that environment. The resulting security property would concern what the workload can actually reach, including when a shell script or dependency behaves maliciously.

**Working assessment:** investigate managed rootless execution as a possible capability of the portable Maknae core; evaluate a controlled OS image where host variability prevents reliable enforcement. Consider replacing the underlying kernel only against a specific security property that an established foundation cannot adequately provide. This is an assessment, not a sequencing decision.

Execution isolation remains an operator decision. [Issue #175](https://github.com/darkhonor/maknae/issues/175) records it as deliberately undecided; this document captures the operator's subsequent exploration without selecting a runtime or superseding that ruling. It is a shipped reference document, not a development spec or plan.

## 2. Why Maknae resembles an OS

| Existing element | OS-like responsibility | Boundary of the analogy |
|---|---|---|
| `maknaed` and the closed action vocabulary | Privileged service interface | Maknae verbs are application operations, not CPU/kernel syscalls. Many enumerated verbs remain unimplemented. |
| `maknae-security` and authorization composition | Reference monitor | Maknae governs mediated requests; host isolation must prevent other paths around it. |
| Subject identity and credential custody | Authority management | A subject's identity, the launcher identity, and a container's UID mapping are separate facts. |
| `maknae-io` and delegated file descriptors | Controlled object access | The host kernel supplies descriptor, permission, and pathname semantics. |
| Audit ordering and proposed containment | Accountability and supervisory control | Container lifecycle, descendant termination, and crash recovery still need their own implementation. |

The [current request path](../../crates/maknae-kernel/src/run.rs) composes and finalizes authorization decisions; the [dispatch implementation](../../crates/maknae-kernel/src/handler.rs) distinguishes implemented operations from terms with no behavior. The [delegated-descriptor code](../../crates/maknae-io/src/delegated.rs) establishes the subject's OS access without having the daemon impersonate that subject. These are concrete foundations, not evidence that a general OS is already implemented.

Crate boundaries constrain dependencies and provide type/module encapsulation. They do not isolate memory between crates linked into one process. [ADR-0005](../adr/ADR-0005-enforcement-locus-tcb-boundary.md) supplies a process trust boundary; the OS enforces it. The [daemon service](../../packaging/common/maknaed.service) also relies on OS restrictions. The whole-system assurance argument therefore includes the host kernel and relevant platform services, beyond Maknae's Rust TCB.

Maknae's distinctive contribution remains the meaning of an action: which subject may use which information for which operation and destination. OS isolation supplies the mechanisms that bound reachable resources. Neither layer substitutes for the other.

## 3. Candidate feature: Maknae-managed execution containers

### 3.1 Scope and terminology

The operator's phrase “every system call (shell script, tool calls etc)” is captured here as **all agent-initiated executable work runs through a Maknae-managed execution boundary**. A shell script or tool invocation produces many literal syscalls. An ordinary OCI container does not send each syscall back to Maknae for a fresh PDP verdict: the workload makes syscalls against the shared Linux kernel, which applies the configured restrictions. Syscall filtering and application authorization are different controls. The [OCI Linux configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md) describes the underlying isolation mechanisms.

Three scopes need separate treatment:

- **Local executable work:** shells, build scripts, subprocesses, and locally hosted tool/MCP servers could run within the assigned container boundary.
- **Remote tool calls:** containerizing the client does not confine a remote server's execution or narrow its credentials. Maknae still needs destination and subject-scoped credential policy.
- **Trusted control-plane operations:** Maknae and its launcher need host/runtime operations to create and supervise containers. “Every operation” cannot mean that this bootstrap authority is supplied by the untrusted container it is creating. Its placement and allowed operations need an explicit boundary.

For the intended guarantee, all execution paths available to the managed agent must use the boundary. Confining shell tools while leaving an untrusted agent runtime able to read the host or open arbitrary sockets would leave bypasses. This is a scoping condition to investigate, not a finding that such an execution path is shipped today.

### 3.2 Candidate operating model

Maknae would own creation, execution admission, supervision, termination, and cleanup. The model under consideration would require an installed and configured runtime capable of non-root operation. The workload would receive a Maknae-authorized environment rather than direct control over runtime options.

An illustrative task could see:

| Container path/resource | Proposed access | Purpose |
|---|---|---|
| `/workspace/project` | Read-only project snapshot or explicitly authorized writable project mount | Assigned source material |
| `/output` | Writable task-specific storage | Generated artifacts |
| `/tmp` | Private, bounded writable storage | Temporary execution data |
| Reference material | Explicit read-only mounts | Additional context needed for the task |
| Other projects, host home, credentials, runtime socket | Not exposed | Keep unrelated resources outside the assigned scope |
| Network | Absent or explicitly governed | Avoid an independent route around destination policy |

These are examples, not selected paths or defaults. A writable host bind mount immediately permits modification of the exposed host files, subject to OS permissions; it is not a review queue. A snapshot with separately authorized publication offers a different workflow and cost. A read-only mount prevents writes through that mount but does not prevent disclosure of readable content through another allowed channel.

Mount authorization must consider the actual resource, subject authority, read/write mode, aliases, nested mounts, and changes between validation and runtime use. A previously validated path string is not sufficient evidence that the runtime later mounted the same object. Proposed runtime bundle construction, mount handoff, and image extraction would need to reconcile with the repository's `maknae-io` convention, including any contract gaps.

### 3.3 Lifecycle responsibilities

If adopted, Maknae's lifecycle ownership would need to cover the following, including partial failures:

1. Bind the execution to a subject, task/project scope, authorized image, mounts, network policy, and resource budget.
2. Verify the required host/runtime protections are available before admitting the workload; absence must not silently fall back to unrestricted host execution.
3. Prepare the environment and record authorization and execution intent before starting consequential work, consistent with the audit-before-mutate direction in [#84](https://github.com/darkhonor/maknae/issues/84).
4. Supervise execution, bound output and resource use, and authorize new tool actions or requested scope changes. Decide whether containers are per invocation, task, or session; reuse must not accumulate stale authority.
5. On cancellation, expiry, or containment, revoke broker access and terminate the workload's descendants, rather than merely killing its initial shell. Define what happens to running work when Maknae or the runtime becomes unavailable.
6. Collect outcomes, govern artifact publication, release mounts and storage, and reconcile orphaned workloads after restart without confusing old container IDs with new ownership.

Removing a mount is not a reliable way to revoke all existing open handles. Termination cannot undo writes already made to a host mount, recall bytes already disclosed, or cancel a remote side effect that has completed. Lifecycle guarantees must distinguish preventing further activity from reversing past effects.

## 4. Pros, cons, and OS directions

| Direction | Pros | Cons | Main roadblocks |
|---|---|---|---|
| **Managed rootless containers on supported hosts** | Restricts filesystem exposure; contains descendants; gives tasks reproducible tools and explicit resource scopes; preserves deployment on existing systems | Shares the Linux kernel; introduces runtime/image dependencies; rootless host features and access differ across deployments | Launcher identity, secure mounts, egress, runtime API custody, cgroup delegation, recovery, and macOS support |
| **Minimal Linux-based Maknae appliance** | Controls kernel configuration, runtime, service policy, boot/update path, and recovery; reduces installation and test variability | Adds OS release engineering, patch distribution, hardware/VM support, and operational ownership | Defining a supported platform baseline and proving it materially improves the workload boundary |
| **Established microkernel-based system** | Potentially stronger compartmentalization and a more explicit assurance foundation | Requires OS services, drivers, tool support, and careful placement of Linux-compatible workloads | Hardware support, application ecosystem, performance, and proving the whole configuration rather than assuming kernel proofs cover it |
| **New Rust kernel and OS** | Full control of resource primitives and interfaces | Largest implementation and verification surface; substantial opportunity cost; a new kernel is not inherently safer | Memory management, scheduling, drivers, storage, networking, boot, updates, tooling, and sustainable assurance |

A managed-container layer can both reduce and strengthen the case for an appliance: it may provide sufficient confinement on ordinary hosts, or expose recurring platform prerequisites that are easier to deliver as a controlled image. It does not logically require a new kernel.

There are relevant precedents rather than selected dependencies. [Bottlerocket](https://bottlerocket.dev/) demonstrates a minimal Linux OS with immutable system files and image-oriented updates. [Firecracker](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md) provides a microVM approach to workload isolation; its [production guidance](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md) still requires host and guest patching and constrained VMM execution. A microVM boundary could be evaluated if sharing the host kernel is insufficient, with additional launch, storage, and supervision cost. [seL4's proof assumptions](https://sel4.systems/Verification/assumptions.html) explain why a verified microkernel does not automatically verify surrounding services or eliminate hardware, DMA, and side-channel assumptions.

## 5. Roadblocks for managed rootless execution

### 5.1 Runtime selection and deployment prerequisites

`runc` and `containerd` are different integration levels. `runc` is a low-level OCI runtime that runs prepared bundles; using it directly leaves Maknae or another component responsible for image acquisition/unpacking and higher-level management. `containerd` supplies a broader daemon/service layer, but also adds an API, state, configuration, and supporting components to operate. Both have documented rootless operation; neither is selected here. See the [runc README](https://github.com/opencontainers/runc#rootless-containers) and [containerd rootless documentation](https://github.com/containerd/containerd/blob/main/docs/rootless.md).

Non-root steady-state execution is distinct from installation requiring no administration. User namespaces, subordinate UID/GID allocations, helper programs, service setup, storage drivers, and networking may require host provisioning. Rootless resource enforcement also depends on delegation: [runc's cgroup v2 documentation](https://github.com/opencontainers/runc/blob/main/docs/cgroup-v2.md) and [nerdctl's rootless guidance](https://github.com/containerd/nerdctl/blob/main/docs/rootless.md) describe relevant prerequisites and limits. Supported configurations need measured capability checks; merely discovering a runtime executable would not establish confinement.

### 5.2 Launcher authority and the existing daemon boundary

> **Clarified 2026-09-05 — operator:** the `maknae` CLI, the user's interface, already runs as that user's UID. The earlier discussion overemphasized `_maknae`'s inability to access private projects without making this existing user-side execution context explicit. “Maknae spawns containers” does not necessarily mean that `maknaed` spawns them directly.

The local deployment therefore already has two contexts: **`maknae` runs as the user; `maknaed` runs as `_maknae`** ([ADR-0005](../adr/ADR-0005-enforcement-locus-tcb-boundary.md)). A user-side rootless launcher could use the user's existing project permissions without granting the daemon access to their home or making it impersonate them. The [CLI's current file-read path](../../bins/maknae/src/cli.rs) already opens the requested file as the user for delegation under [ADR-0009](../adr/ADR-0009-subject-side-os-dac-evaluation.md). Container launch placement remains a candidate choice, not an implemented extension of that mechanism.

The daemon's `NoNewPrivileges`, empty capability bounding set, `RestrictNamespaces`, and `ProtectControlGroups` matter if launch is placed directly inside its service; they are not a blanket obstacle to user-side rootless execution. A user-side launcher still needs the runtime prerequisites in §5.1 and a way to access the authorized project under the chosen UID mapping and mount configuration.

The architectural question is **how the daemon's authorization and Maknae's lifecycle ownership are enforced across the user-side execution boundary**. The CLI remains an untrusted client and `maknaed` remains the sole PDP. A launcher receiving a proposed command or mount list from the CLI cannot treat it as authorization. A future design must establish what component enforces the authorized scope, how the agent is excluded from general runtime control, and how supervision and cleanup survive CLI exit. A per-user runtime can carry the user's wider host authority even when a particular workload is meant to receive only one project; the workload must not inherit that management authority.

The existing subject-opened descriptor mechanism establishes local file-read authority; it does not by itself define recursive volume delegation or container lifecycle control. Remote subjects also have no corresponding local CLI process on the daemon host; [issue #195](https://github.com/darkhonor/maknae/issues/195) captures that separate authority question.

Container UID 0 can map to an unprivileged host UID. That limits host privilege; it does not make all resources available to that host UID safe to expose. Similarly, using a non-root UID inside a container controlled by a rootful host daemon would not satisfy the proposed rootless-runtime requirement.

### 5.3 Mounts constrain reach, not every operation within a project

A whole-project mount may expose `.git`, repository-local credentials, sockets, generated content, and executable configuration. A malicious script can damage any writable content in its scope or plant a change that a later host process executes. Shared writable caches create additional paths between otherwise separate tasks. Mount granularity and artifact publication therefore matter as much as the project name.

An in-container read of a mounted file does not automatically pass through Maknae's `fs.read` PEP. An authorized writable mount similarly gives a class of write authority instead of a separate verdict for each write. The design would need to choose which resources permit scoped bulk access and which require a broker or stronger mediation. Containerization alone cannot be described as enforcing every existing Maknae file-level decision on every syscall.

### 5.4 Network, tools, and runtime control

Filesystem isolation does not constrain network destinations. A permitted process can disclose any readable information over an available channel. Network namespaces alone do not express Maknae's destination policy; DNS, proxy bypasses, host services, metadata endpoints, and direct sockets need consideration under the eventual egress design. Relevant work includes [#147](https://github.com/darkhonor/maknae/issues/147), [#151](https://github.com/darkhonor/maknae/issues/151), and [#153](https://github.com/darkhonor/maknae/issues/153).

The untrusted workload must not receive a general-purpose runtime control socket, arbitrary OCI configuration authority, or equivalent launcher credentials. Otherwise it could request wider mounts or new containers outside its assigned scope. Build workflows that expect Docker/containerd socket access are a concrete compatibility roadblock requiring a constrained alternative or an explicit unsupported outcome.

### 5.5 Platform, supply chain, and operations

Linux OCI containers on macOS require a Linux execution environment, typically a VM. That adds guest provisioning, host-to-guest file sharing, UID translation, and recovery behavior to the deployment. Native Linux and macOS would therefore have different assurance and installation paths. GPU/device access and large model workloads may also require capabilities absent from a minimal rootless profile; their support is unestablished here.

Runtime binaries, helpers, image parsers, snapshotters, network components, and images add dependencies that need provenance, update, and offline-distribution treatment. Writable layers and retained task state also consume disk and can cross contamination boundaries. Package installation, image pulls, and shared caches need an authority model rather than an implicit exception for setup.

The host kernel remains shared and trusted for isolation. A kernel vulnerability, exposed device, unintended inherited descriptor, or poorly constrained mount can defeat the intended boundary. Evidence should distinguish configured controls from observed enforcement. Running Rust in the trust plane does not make these external components part of an all-Rust system.

## 6. Influence on upcoming Maknae work

| Work | Influence of managed execution |
|---|---|
| [Terminal execution #175](https://github.com/darkhonor/maknae/issues/175) and [terminal lifecycle/output #176](https://github.com/darkhonor/maknae/issues/176) | Where commands run, stdin authority, descendant ownership, output handling, and container reuse |
| [Filesystem mutation #158](https://github.com/darkhonor/maknae/issues/158) and [audit-before-mutate #84](https://github.com/darkhonor/maknae/issues/84) | Direct mounted writes versus brokered operations or staged publication; audit granularity |
| [MCP #151](https://github.com/darkhonor/maknae/issues/151) | Local server placement, tool credentials, remote side effects, and bypass paths |
| [Egress #147](https://github.com/darkhonor/maknae/issues/147) and [model endpoints #153](https://github.com/darkhonor/maknae/issues/153) | Required network mediation and whether model traffic is brokered outside the workload |
| [Containment #165](https://github.com/darkhonor/maknae/issues/165) and [model trust #209](https://github.com/darkhonor/maknae/issues/209) | Termination scope, surviving descendants, remote effects, and which recovery authority survives containment |
| [Device posture #112](https://github.com/darkhonor/maknae/issues/112) | Runtime/host capability evidence and refusal when the requested boundary is unavailable |
| [Gateway #117](https://github.com/darkhonor/maknae/issues/117) and [remote authority #195](https://github.com/darkhonor/maknae/issues/195) | Binding remote subjects to execution resources without granting the gateway local impersonation authority |
| [OCI packaging #81](https://github.com/darkhonor/maknae/issues/81) | Distinguish packaging Maknae itself in OCI from Maknae managing workload containers; nested deployment adds separate runtime-access questions |

The [KLC execute hook](../knowledge-lifecycle-contract.md) already makes required sandbox strength a policy input. Managed containers would need evidence for a specific supported protection profile; “container present” would not be an adequate strength claim. Authorization remains RBAC by default, optionally enriched to ABAC through the external classification library, with deny-overrides composition. Neither mounts nor runtime self-description can authorize an operation independently of that policy.

## 7. Questions that determine the OS direction

- Is the desired protection against a malicious agent and its dependencies, another local subject, a compromised runtime, or a compromised host OS? These require different boundaries.
- What is the unit of execution and retained authority: one tool call, one task, one project, or one session?
- Which work can use bulk mounted access, and which needs per-operation authorization or controlled publication?
- How does a launcher in the local user's existing execution context enforce daemon-authorized project scope and lifecycle control, and what separate mechanism serves remote subjects?
- Which network, credential, storage, and resource guarantees must remain enforceable after a component crashes?
- Which supported hosts can establish those guarantees, and would a maintained appliance remove enough variability to justify its operating cost?
- What specific property would require a microVM, a microkernel-based system, or a new kernel beyond what the managed-container environment supplies?

Useful future evidence would include refusal of access to an unmounted sentinel project, resistance to mount-path substitution, blocked unauthorized egress, no workload access to runtime control, enforcement of resource limits, termination of descendants, and safe reconciliation after a supervisor crash. These are evaluation criteria for the idea, not claims of current test coverage or a prescribed implementation sequence.

An OS surrounding Maknae earns its place if it makes those properties more reliable and demonstrable. The container proposal gives the exploration a concrete workload boundary to evaluate while leaving the kernel and runtime choices open.
