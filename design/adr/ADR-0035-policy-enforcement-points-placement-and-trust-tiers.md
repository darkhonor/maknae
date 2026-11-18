# ADR-0035: Policy enforcement points — placement and trust tiers; `maknaed` the sole PDP, every PEP claimed only for what it proves

- **Status:** Accepted (maintainer-ruled 2026-11-18)
- **Date:** 2026-11-18
- **Deciders:** Alex Ackerman (maintainer)
- **Raised by:** [#420](https://github.com/darkhonor/maknae/issues/420) (decision 3, the tool model), [#477](https://github.com/darkhonor/maknae/issues/477)
- **Amends:** [ADR-0005](ADR-0005-enforcement-locus-tcb-boundary.md) (the MVP collapse of the PDP and the sole PEP into one process); [ADR-0006](ADR-0006-client-authentication-model.md) decision 10 (the front ends' role)

## Context

[ADR-0005](ADR-0005-enforcement-locus-tcb-boundary.md) puts the reference monitor in one process and says so as a limitation: "at MVP the PDP and sole PEP are one process", with "the ratified shape" to return later. The shape was never written down. Every enforcement point Maknae has today lives inside `maknaed`: the `fs.*` verbs' delegated-descriptor checks, the egress screen, the audit obligation.

The tool model ([ADR-0036](ADR-0036-the-tool-model.md), decided the same day) cannot be enforced that way. The kernel authorizes each tool invocation and never executes one; the process that asked runs it. So the thing that turns a decision into a container with the decided image, mounts and network is a process outside the TCB: `maknae` for an operator, `maknae-agentd` for an agent. The same holds for the egress proxy that decides each outbound connection, for a front end on another host, and on Kubernetes for the runtime and admission control.

Two wrong conclusions were available. One is that an untrusted process cannot enforce anything, which would forbid the tool model. The other is that a front end Maknae ships can be trusted, which [ADR-0006](ADR-0006-client-authentication-model.md) decision 10 already rules out: a client binary "runs as the user, so any secret it holds the user can extract." This ADR records where enforcement points may live and what each one may be claimed to enforce.

During the design session an identity scheme was proposed: a hash built into each Maknae binary and sent with every message, so the kernel could tell a genuine Maknae program from anything else. It was dropped. The hash is a constant in a file the uid can read, so any process of that uid can send it; and a compromised front end *is* the genuine binary, so it sends the right hash. Decision 4 records what replaces it.

## Decision

1. **`maknaed` is the sole PDP. Policy enforcement points (PEPs) may live outside the TCB.** A PEP is meaningful when it sits between a subject and a resource and the subject cannot route around it. Being untrusted to *decide* does not disqualify a process from *enforcing* toward a subject it stands in front of. A front end stands between the model and the host: the model cannot run anything except through it. So a front end is a PEP for the model's tool calls, while it remains, toward its own user, the untrusted client of ADR-0006 decision 10.

2. **PEPs fall into trust tiers, and each is claimed only for what it can prove** (the rule of ADR-0006 decision 10, applied to enforcement):

   | Tier | Examples | Enforces toward | Does not hold against | Built? |
   |---|---|---|---|---|
   | Kernel-internal | the `fs.*` verbs' checks in `maknaed`; the audit obligation | every subject | an external root compromise (ADR-0006 assumption 3) | yes |
   | Local front end | `maknae`, `maknae-agentd` | the model's tool calls | the front end's own compromise | no (the tool path) |
   | Remote workload | `maknae-agentd` on another host, by its workload certificate (ADR-0006 decision 9) | the model's tool calls on that host | its own compromise; the custody of its key on its host | no |
   | Runtime and infrastructure | the Maknae RuntimeClass on Kubernetes (below); Kubernetes admission; SELinux domain confinement; the host network rule keyed on uid | everything inside it, a compromised front end included | root on the node | partly: the Agent Daemon's SELinux domain `maknae_agentd_t` ships (#639); its confinement of container launches, the uid network rule, admission and the RuntimeClass do not |
   | Network | `maknae-proxy` | every outbound connection of a launched tool | a route that bypasses it, which the runtime tier closes | no |

3. **A Permit may carry obligations, and a PEP that cannot carry one out must deny.** This is the obligation rule already in force inside the kernel, extended to PEPs outside it. The tool model's launch shape travels this way ([ADR-0036](ADR-0036-the-tool-model.md) decision 6). The `Obligation {id, params}` type in `crates/maknae-security/src/obligation.rs` is opaque and already sufficient, so the `Authorizer` contract and its types do not change for obligations (the tool model's workspace decision does add a filesystem operation, [ADR-0036](ADR-0036-the-tool-model.md) decision 5) ([ADR-0004](ADR-0004-modular-authorization-architecture.md)). Two kernel-side additions are needed, and neither is built:
   - carrying an obligation to the front end is a new, additive field on the wire (`maknae-proto`); obligations do not reach the wire today. `PROTOCOL_VERSION` does not change;
   - `maknaed`'s own discharge of obligations (`discharge_plan` in `crates/maknae-kernel/src/handler.rs`) today treats an obligation with no registered handler as unhonorable, and so denies. It gains a "forward to the requesting PEP" class for named obligation ids. It stays fail-closed: an id that is neither handled nor named for forwarding still denies.

4. **A PEP's identity is the kernel's observation of the peer, never what the message says.** A secret carried in the message or embedded in the binary proves nothing, for the reasons in the Context. What the kernel can observe, by platform:

   | Platform | Peer identity observed | Built? |
   |---|---|---|
   | All | the peer uid (`SO_PEERCRED`, `LOCAL_PEERCRED`) | yes |
   | Enterprise Linux with Maknae's SELinux policy | the peer's SELinux label (`getpeercon`), for example the `maknae_agentd_t` domain that only the labelled binary runs in | the domain ships (#639); `maknaed`'s label check does not |
   | macOS | the peer's code signature, through its audit token, against the signing identifier ADR-0006 fixes (`io.maknae.maknae-agentd`) | no |
   | Debian and Ubuntu (AppArmor) | the peer's executable path; weaker, since another process of the same uid can attach to the genuine binary unless the host restricts ptrace | no |

   The guarantee is stated per platform. No document may claim the strongest row's property for a platform that has only a weaker one.

5. **Every connection is decided.** A network PEP asks `maknaed` about each connection it carries; for `maknae-proxy` that is each `CONNECT` tunnel. Pushing a per-invocation grant to the proxy, so it could decide connections on its own, was considered and rejected: it is a cache of a decision, and [#147](https://github.com/darkhonor/maknae/issues/147) ruling 1 requires egress to be evaluated at every request. The connection's data never passes through the kernel; only the decision does.

6. **The PEP is wherever the resource is.** A front end on another host is a PEP there, identified by its workload certificate. On Kubernetes, admission control is a PEP that a front end cannot bypass, and the runtime is another. This placement rule is the same on one host, across hosts and in a cluster; only the tier changes.

## Consequences

- **The tool model can be enforced, and its residual is named.** A front end enforces toward the model. Toward a compromised front end only the tiers beneath it enforce: the host network rule on agent accounts (over the account's uid and subordinate range, or its SELinux type) and SELinux confinement on hosts, admission control and the RuntimeClass on Kubernetes; none of them is built for container launches yet. [ADR-0036](ADR-0036-the-tool-model.md) records this as its residual.
- **The Maknae RuntimeClass is the direction for the runtime tier on Kubernetes.** It is an existing VM sandbox (Kata) with Maknae at its boundaries, not a new isolation runtime: the host-side file server (`virtiofsd`) asks `maknaed` on every open, create, unlink and mkdir; the guest's only network route is a virtual socket to `maknae-proxy` or the Egress Daemon; and the runtime attests which sandbox a connection came from. Not built.
- **Two kernel additions are owed** (decision 3): the additive wire field and the forward class in `discharge_plan`.
- **ADR-0005 and ADR-0006 are amended in place,** with dated banners: ADR-0005's single-process collapse now points here; ADR-0006 decision 10's table gains the front end's role as a PEP.

## References

- [ADR-0036](ADR-0036-the-tool-model.md) (the tool model); [ADR-0005](ADR-0005-enforcement-locus-tcb-boundary.md) (amended); [ADR-0006](ADR-0006-client-authentication-model.md) decisions 9 and 10 (amended); [ADR-0004](ADR-0004-modular-authorization-architecture.md) (the `Authorizer` contract; obligations unchanged, one filesystem operation added by ADR-0036); [ADR-0008](ADR-0008-authorization-composition-contract.md) (the composition); [ADR-0020](ADR-0020-access-control-model-and-vocabulary.md) (vocabulary)
- `crates/maknae-security/src/obligation.rs`; `crates/maknae-kernel/src/handler.rs` (`discharge_plan`)
- [#147](https://github.com/darkhonor/maknae/issues/147) ruling 1; [#420](https://github.com/darkhonor/maknae/issues/420); [#477](https://github.com/darkhonor/maknae/issues/477)
- `design/egress-and-tool-execution.md` §6 (`maknae-proxy`)
