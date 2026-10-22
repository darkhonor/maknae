# ADR-0024: Maknae is multi-tenant — several humans, several agent personas, one kernel; the interactive agent runtime holds no identity of its own, and the Agent Daemon holds its own

- **Status:** Accepted (operator-ratified 2026-09-10)
- **Date:** 2026-09-10
- **Deciders:** Alex Ackerman (operator)
- **Supersedes, in [ADR-0018](ADR-0018-local-plane-authorization-deployment-model.md), decision 1's *"multi-user hardening collapses into the Kubernetes/gateway case"* AND the Context fact it rests on (*"multi-user only arises on shared infrastructure…"*, ADR-0018 §Context 1).** *(Corrected 2026-09-10, #276: this said "one clause"; there are two statements of the same assumption.)* Its anti-friction rationale stands; see Consequences.
- **Amended 2026-10-22 ([#471](https://github.com/darkhonor/maknae/issues/471)): decision 2 is scoped, decision 6 is added, and the title is amended.** The title said *"an agent holds no identity of its own"*, without exception. That rule now applies to the interactive runtime, the loop a human starts. The Agent Daemon is a subject with its own identity (decision 6), and decision 2's rule that every subject is uid-derived applies to it unchanged.

## Context

Maknae has been built without a stated position on **who it serves**. The question surfaced while resolving [#276](https://github.com/darkhonor/maknae/issues/276) (the reserved `agent` subject token) because the answer determines whether an agent runtime needs an identity at all — and it turned out to be load-bearing for [#241](https://github.com/darkhonor/maknae/issues/241), [#117](https://github.com/darkhonor/maknae/issues/117) and [#195](https://github.com/darkhonor/maknae/issues/195) as well.

**The field does not answer it.** The [Jarvis-class survey](../references/2026-09-08-jarvis-class-survey.md) assessed twelve shipped agent systems across eight axes — who decides, credential custody, egress governance, memory-to-authority — and **has no tenancy axis at all**, because for a *personal* assistant the question does not arise: the agent is the user. Three separate assessments describe the field leader identically, *"single-user, local-first."* Two partial exceptions are instructive rather than decisive:

- **Home Assistant** (the survey's *"only relative"*) is genuinely multi-user — a household — and resolves it by **separating roles, not identities**: an admin curates an exposure list; the model reaches only what is exposed and performs *"no administrative tasks."* The agent has no identity; it has a curated surface.
- **NanoClaw** keeps credentials out of the agent entirely, injecting them per request from outside, and routes self-modification to a human. Again the agent is a bounded process, not a subject.

**Neither made the agent a subject.** Both made it a *scope*, and kept identity with the humans.

**Maknae's target is the case the field skipped.** The operator's stated intent (2026-09-10): two humans on one system — the operator and a second, non-technical person — each served by their own agent persona, with the kernel between both and everything they touch. That is not a personal assistant. It is precisely the deployment in which placing the authorization decision *outside* the agent process stops being an architectural preference and becomes the only thing that separates two people's authority.

**And most deployments will still have one subject.** The operator's qualifier the same day: on a single-subject install *"it feels like a single user; the multi-tenancy is dormant and unused."* Both are requirements. A model that serves two people but taxes one is the wrong model, which is why decision 1 states dormancy as a property rather than leaving it to be inferred.

**One ratified clause assumed the opposite.** ADR-0018 decision 1 declined a per-uid allowlist because *"on a single-user host it is friction with no benefit, and multi-user hardening collapses into the Kubernetes/gateway case."* The first half is no longer true of the target deployment, and the second half deferred a case that is now the primary one.

## Decision

### 1. Maknae is multi-tenant by design, on a single host — and DORMANT when it is not used

Several humans may be served by one `maknaed`, and the local plane must separate their authority on the same machine. This is not something that begins only at the gateway.

**But multi-tenancy is structural, never ceremonial.** A deployment with one enrolled subject must *feel* like a single-subject system: no additional configuration, no additional ceremony, no per-subject bookkeeping to maintain. The capability is present and unused, the way a second seat in a car is present and unused — it costs the driver nothing.

This is achievable because the mechanism is **already** the per-request uid principal ([ADR-0018](ADR-0018-local-plane-authorization-deployment-model.md)). One subject and three subjects are the same code path decided on different values; nothing switches on the count. **ADR-0018's instinct against friction is therefore honoured, not overturned** — that ADR declined a per-uid *allowlist* because it was friction with no benefit on a single-user host, and this ADR adds no allowlist and no equivalent. What changes is only its second clause, the assumption that multi-user hardening is deferred to the Kubernetes/gateway case: the local plane owns it now, at no cost to a deployment that never exercises it.

**The test for any future mechanism claimed under this ADR:** if a single-subject deployment has to do something it would not otherwise do, the mechanism is wrong.

### 2. Every subject is uid-derived. The interactive agent runtime holds no identity of its own

> **Scoped 2026-10-22 ([#471](https://github.com/darkhonor/maknae/issues/471)):** this decision said an agent runtime holds no identity of its own, without exception. That was written before the Agent Daemon ([#420](https://github.com/darkhonor/maknae/issues/420)) existed as a design: a long-lived runtime under its own account, tasked by others, acting under its own outbound identity. The heading said "an agent runtime"; the rule below now governs **the interactive runtime**, the loop a human starts. **The Agent Daemon is decided by decision 6.** The first sentence's rule, that every subject is uid-derived, applies to the Agent Daemon unchanged. On-behalf-of mode ([#539](https://github.com/darkhonor/maknae/issues/539)) is an *outbound* identity at an external system, not a kernel subject: the Agent Daemon's kernel subject is still its own uid there, and only the identity it presents to the destination is the tasker's. #539 designs that mode, within this decision's narrowing discipline.

[ADR-0018](ADR-0018-local-plane-authorization-deployment-model.md)'s rule — the per-request authorization principal is the **uid** (local) or the gateway-asserted OIDC principal (remote) — applies **uniformly, with no exception for the agent runtime**.

An agent acts **within a delegation from the human who invoked it**. Its authority is that human's, **narrowed and never widened** — the discipline the [FrontierAgent assessment](../references/2026-08-28-frontieragent-assessment.md) states for spawned workers, applied to the runtime itself: *"each spawned worker must be a scoped subject, not an extension of its parent prompt. Delegation may narrow attributes and capabilities but never widen them."*

**Consequence for the trail — and a distinction this ADR initially got wrong (corrected 2026-09-10, pre-merge review):** every record answers *whose authority was used*, because `source.uid` and `subject.user` are the invoking human's ([ADR-0019](ADR-0019-audit-record-model.md), amended 2026-09-10). **That is the authorization subject. It is NOT the request's origin.**

An earlier revision of this decision said an agent's action *"is that human's action, attributed to them,"* and claimed AU-3 coverage on that basis. That conflates two different facts:

- **Authorization subject** — whose authority the decision was made on. The uid. Decided by the PDP.
- **Request origin (actor provenance)** — whether the request came from a human at a client, or from the **explicitly untrusted** agent runtime acting under that human's delegation. **Audit-only, never an authorization input.**

Collapsing them makes an agent-originated action indistinguishable from a direct human one — which is worst precisely in the compromised-runtime case this ADR's own trust model assumes, where the trail would read as the human acting directly and incident reconstruction would have nothing to key on. It would also make two personas operating for the same subject indistinguishable from each other.

**Keeping personas out of the PDP does not require deleting provenance from the trail.** Decision 4 forbids persona from reaching the *decision*; it says nothing about the *record*, and provenance in the record is the same inform-but-not-authorize shape the kernel already applies to injected content.

**The mechanism does not exist yet, and this ADR does not claim it.** `source.plane_uri_san` is the natural carrier — it is on every record already — but the `Plane` vocabulary is `Kernel | Cli` (`crates/maknae-vault/src/plane.rs`), with no value meaning "runtime". A runtime connecting today would be indistinguishable from the CLI. **Recorded as an auditability gap, owned by [#241](https://github.com/darkhonor/maknae/issues/241)** — the issue that first creates a second origin, and therefore the first point at which the gap is reachable rather than theoretical. *(Corrected 2026-10-22: #241 closed without addressing the gap, and `Plane` is still `Kernel | Cli`. The gap is now owned by [#549](https://github.com/darkhonor/maknae/issues/549).)*

*(Refined 2026-09-10, #276: the carrier is not un-designed. [ADR-0006](ADR-0006-client-authentication-model.md) §Out-of-scope (b) already names it — "the runtime's own uid is **not** an operator identity, and per-operator attribution through the runtime needs **the subject-context envelope**" — which agrees with decision 2 above. *(2026-10-22: for the Agent Daemon, decision 6 makes the runtime's own uid the authorization subject; per-tasker attribution on the intake record is owed by #475. ADR-0006 (b) is annotated to match.)* `maknae-subject-ctx` and `maknae-subject-ctx-mint` exist as scaffold stubs gated on ADR-0014. So the mechanism has a name and a home; what it does not have is a body.)* Until it closes, AU-3(d) coverage for *origin* is not claimed here.

### 3. The reserved `agent` subject token is STRUCK

A single reserved runtime-subject token **cannot express two agents**. Two personas acting under one token is a confused deputy by construction: the kernel could not tell which human an action was for, and `bindings:` could not grant them different authority. It is removed rather than namespaced, because there is no correct value for it — the right number of reserved runtime identities is zero.

This is not a hardening of [#276](https://github.com/darkhonor/maknae/issues/276)'s hazard; it removes the hazard's precondition.

### 4. A persona is presentation. It is NEVER an authorization concept

Two humans may be served by agents with different names, voices and dispositions. **None of that reaches the PDP.** Personas live entirely in the untrusted runtime; the kernel sees a uid, a role and a verb, exactly as it does for a human at a shell.

Stated as a prohibition because the failure is attractive and quiet: an authorization model that keys on personality is one where changing a name changes what may be done, and where a compromised runtime widens its own authority by renaming itself.

### 5. Administration is separable from use

The person who **curates** authority need not be the person who **uses** an agent. A non-technical subject must be able to work without ever authoring policy: an operator binds roles and grants; the subject's agent operates within them.

This is Home Assistant's household model and NanoClaw's admin-card model, held at the kernel rather than at an integration layer. It is already expressible — `bindings:` maps identities to roles and `roles:`/`destinations:` grant terms — and it needs no new mechanism, only the acknowledgement that the two need not be the same person.

### 6. The Agent Daemon is a subject with its own identity, and a resource its taskers may task *(added 2026-10-22, [#471](https://github.com/darkhonor/maknae/issues/471))*

**What its identity is.** An Agent Daemon runs under its own OS account, so its authorization subject is that account's **uid** (decision 2's rule). It is not a reserved token: decision 3 stands, and two Agent Daemons are two accounts. Each one has:
- its own role, through `bindings:`, exactly as a human has;
- its own Vault identity: AppRole, with a literal policy on its own account's subtree ([ADR-0028](ADR-0028-per-user-model-providers-and-kernel-blind-credentials.md) decision 4, which deferred its standing as a subject to this decision);
- its own model-provider configuration, reached through the Egress Daemon like any subject's;
- its own outbound identity per destination, where an administrator chooses the agent's own identity mode (HomeLab: HobiBot's own GitHub account). Its custody and use are [#168](https://github.com/darkhonor/maknae/issues/168)'s.

None of this is built. This decision fixes what the identity is; the slices that provision it are #168's and [#420](https://github.com/darkhonor/maknae/issues/420)'s.

**Not decided here: how the Agent Daemon authenticates to `maknaed`.** [ADR-0006](ADR-0006-client-authentication-model.md) decision 4 admits a local client only from a live *human* login session (`Class=user`), and refuses a service by design. ADR-0006 §Out-of-scope (b) and (c) leave non-human runtimes to their own decision. That decision is [#550](https://github.com/darkhonor/maknae/issues/550). **The refusal is not built yet:** today `maknaed` admits a local client on peer-cred uid plus `maknae`-group membership alone, and the human-session check is [#115](https://github.com/darkhonor/maknae/issues/115). So an Agent Daemon account placed in the `maknae` group would be admitted on its own uid today, with no ratified authentication factor. **Ordering constraint:** the Agent Daemon service ([#472](https://github.com/darkhonor/maknae/issues/472)) does not ship before #550's factor is decided and enforced, and #115 enforces the human-session refusal for everything else.

**It is also a resource.** Policy decides which subjects may task which Agent Daemon, and with which task class.

**How the tasker's authority composes with the agent's: at intake, then the agent's own role.**
1. **Intake decides the tasker.** The kernel decides `agent.task` ([#475](https://github.com/darkhonor/maknae/issues/475)): whether this subject may task this agent, with this task class and these parameters. The outcome binds the task's envelope: the task class, its parameters, and any resource bound drawn from the tasker's own reach (#168's repository intersection is the first, and today the only one).
2. **Execution decides the agent.** Each in-task decision is made on **the agent's own role**, inside the bound envelope. A task never runs on the tasker's role, and never on the union of the two.
3. **A policy change during a task re-decides intake in full.** Authority is not carried forward from the first decision ([#420](https://github.com/darkhonor/maknae/issues/420) decision 11). A refused re-decision ends the task; how that stop holds without the agent's cooperation is [#481](https://github.com/darkhonor/maknae/issues/481).

**What is never widened, and where that is not yet true.**
- **The tasker cannot push the agent beyond the agent's role,** because every in-task decision is made on that role. This holds for every resource.
- **The agent cannot use a task to reach what its tasker could not, *for each resource class the envelope bounds from the tasker's reach*.** Today that is GitHub repositories (#168).
- **Residual: a resource class the envelope does not bound is decided on the agent's role alone.** In shared mode the agent's role reaches every tasker's workspace and its shared behavioural memory, so tasker A could steer a task into tasker B's workspace. Closing it is owed to the task-class grammar ([#474](https://github.com/darkhonor/maknae/issues/474)), which must bound every resource class a task class touches, shared memory included, and to per-tasker workspace uids ([#476](https://github.com/darkhonor/maknae/issues/476)) for workspaces. Until both land, decision 2's *"narrowed and never widened"* is claimed for the Agent Daemon only for bounded resource classes.

**Rejected: deciding every in-task request on the agent's role intersected with the tasker's.** A tasker's role does not cover the agent's own workspace, provider or accounts, so every agent grant would have to be mirrored into every tasker's role. It would also make a task's authority depend on who sent it, decision by decision, rather than on an envelope fixed and audited at intake.

**Not decided here: an Agent Daemon action outside any task.** It has no intake and no envelope. Whether it is permitted, and on what authority, is owed to the service slice, #472.

**What does not change:**
- A persona is still presentation (decision 4). The identity is the account, never the name or the voice.
- Dormancy (decision 1): a deployment with no Agent Daemon enrolled configures nothing and does nothing new.
- The interactive runtime is still governed by decision 2.

## Consequences

- **ADR-0018 is superseded in two places** *(corrected 2026-09-10, #276 — this previously said "only in its second clause")*: decision 1's second clause, and the §Context "Deployment reality" fact it rests on. The clause in question is — *"multi-user hardening collapses into the Kubernetes/gateway case."* The local plane owns that case now. Its **first** clause stands and is reinforced: a per-uid allowlist remains unadopted, and nothing here reintroduces one. Its *mechanism* is unchanged and already sufficient — the `maknae` group is the outer fence, the per-request uid is the principal that distinguishes two members of it, and `bindings:` already maps uids to roles. **No new mechanism is required by this ADR**, which is what makes dormancy possible.
- **[#276](https://github.com/darkhonor/maknae/issues/276) resolves to deletion, not hardening.** The reserved token, the `agent`-excluded branch in `resolve_uid_map`, the reserved-name arm of `role_for`, and the `SUBJECT_NAME` request attribute all go. #275's compile-time `Verb` regression pin retires with them, since the hazard it guards ceases to exist.
- **[#241](https://github.com/darkhonor/maknae/issues/241)'s runtime identity is settled before it is built:** the loop authenticates as the human who started it and carries no identity of its own.
- **[#117](https://github.com/darkhonor/maknae/issues/117) (gateway) and [#195](https://github.com/darkhonor/maknae/issues/195) (remote-lane DAC) are the multi-user *remote* half** and are unaffected in direction; this ADR settles the *local* half they were deferring to.
- **The audit trail satisfies the *subject* half and not the *origin* half.** `subject.user` and `subject.role` (2026-09-10) name the human and the role every decision was made on, and no record change is owed for that. **A record change IS owed for origin** — see decision 2 — and is #241's, because that is when a second origin first exists. *(Corrected 2026-10-22: #241 closed without it; the owner is [#549](https://github.com/darkhonor/maknae/issues/549).)*
- **An Agent Daemon's records will name the agent, and its intake record will name the tasker** *(added 2026-10-22, #471)*. The subject is the agent's account, so its actions are distinguishable from a human's by uid once it can connect (#550). Recording the tasker and the bound envelope on the `agent.task` intake record, and linking each in-task record to its task, is owed by #475; neither exists yet. When both land, the *origin* gap closes for Agent Daemon actions. The interactive runtime's records still read as the human acting directly ([#549](https://github.com/darkhonor/maknae/issues/549)).
- **What this ADR does NOT decide.** *(Narrowed 2026-10-22, #471: a tasked Agent Daemon action, with no human at the keyboard, is decided on the agent's own role inside the envelope bound at intake (decision 6). An untasked Agent Daemon action is still undecided (#472). The paragraph below still holds for any other runtime.)* Whether an agent may act *unprompted*, and what authority such an action carries, is out of scope here — an unprompted action has no human at the keyboard at the moment of decision, which is a narrower grant question the verb vocabulary does not yet express. Maknae's own future development by an agent is likewise out of scope and is a design discussion, not a decision: see `design/self-development.md`.

## Control mapping

| Property | How | Control |
|---|---|---|
| Two subjects on one host are separately authorized | Per-request uid principal; `bindings:` uid→role; deny-overrides composition | AC-2, AC-3 |
| The interactive runtime cannot exceed the human it acts for | Delegation narrows, never widens; no runtime identity to grant to (scoped 2026-10-22 to the interactive runtime; the Agent Daemon is the rows below) | AC-6 (least privilege) |
| Whose **authority** every action used is attributable | `source.uid` + `subject.user` + `subject.role` on every record | AU-3(f), AU-3(1) |
| The **origin** of a request — human client vs agent runtime — is distinguishable | **NOT YET for the interactive runtime.** `Plane` is `Kernel \| Cli`; no value means "runtime". Gap owned by #549 (corrected 2026-10-22: was #241, closed without it). For the **Agent Daemon**, the subject will be its own uid (decision 6), but it cannot yet connect (#550) and its task linkage is unbuilt (#475) | AU-3(d) — **gap** (both) |
| The Agent Daemon is separately identified and authorized | Its own uid and `bindings:` role; no reserved token (decision 6, added 2026-10-22). Not built: its Vault AppRole is #168; its authentication to `maknaed` is #550 | IA-9 — **gap** (#550); AC-2, AC-3 |
| A task cannot widen the agent beyond its role | In-task decisions on the agent's own role, inside the intake-bound envelope (decision 6) | AC-6, AC-3 |
| A task cannot reach what its tasker could not | **Only for resource classes the envelope bounds from the tasker's reach** (today: GitHub repositories, #168). Other classes, including shared-mode workspaces and memory, are a named residual owned by #474 and #476 | AC-6 — **partial** |
| A non-technical subject need not hold administrative authority | Administration separable from use (decision 5) | AC-5 (separation of duties), AC-6 |
