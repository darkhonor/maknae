# Model-conduit policy — constraining a model by what it may reach, not by whether it can be trusted

**Status: OPEN DISCUSSION.** Nothing here is ratified, scheduled, or committed to. This document exists to **pin the idea and its candidate implementation methods with a date**, because the idea is the maintainer's and the repository is public. It follows the register of [`self-development.md`](self-development.md) and [`secrets-custody-tiers.md`](secrets-custody-tiers.md): frame the problem, record what is already true, name the open questions, decide later.

**Date opened:** 2026-09-10. **Originator:** Alex Ackerman ([@darkhonor](https://github.com/darkhonor)) — the idea, the motivating use case, and the "model as resource, not subject" framing are the maintainer's, stated 2026-09-10. **Deciders (eventual):** the maintainer.

**This is not active work.** The current milestone is Cooky (the runtime loop MVP, epic [#244](https://github.com/darkhonor/maknae/issues/244)); nothing here preempts it, and no issue is opened by this document. It is a placeholder for a decision, not the decision — consistent with the ADR registry's rule that decisions not yet made live as issues or discussion, never as reserved ADR numbers.

## The idea

**Policy should be attachable to a specific model or model endpoint, so that two models serving the *same* user on the *same* host carry different authority.**

The maintainer's worked example (2026-09-10):

- **A commercially-hosted frontier model reached by API key** — filesystem reach confined to an enumerated set of paths, to bound the blast radius of a spillage or exfiltration event through an endpoint outside the operator's control.
- **A locally-hosted or LAN-registered open-weight model** — permitted broad local reach but pinned inside the network enclave, unable to reach other hosts or the public internet, so that its advanced reasoning and coding capability is usable without its egress being a data-loss path.

Two models. Two trust bases. Two supply-chain risk levels. **One user**, and one set of agent personas acting on that user's behalf. The differentiating attribute is not *who is asking* — it is *what the request is about to flow through*.

*(Extended 2026-09-11: two further cases — a trusted small model with bounded network reach, and an orchestrating model over task models — are recorded under [The use cases the policy suite must carry](#the-use-cases-the-policy-suite-must-carry--three-conduits-one-mechanism) below, together with the criterion the maintainer set for all of them.)*

## What is already true in the code

This is not a green field. Four load-bearing pieces exist:

1. **A per-role egress destination allowlist, whose entry grammar is already `provider:<name>`.** Shipped in [#172](https://github.com/darkhonor/maknae/issues/172) (`crates/maknae-config/src/authz.rs`): `destinations:` maps a role to an allow list, `destination_entry_is_acceptable` enforces the entry grammar, and an absent section means an empty allowlist for every role — deny-by-default, additively. This is **subject → provider** and it decides today.
2. **A composition contract that admits new mandatory operands** ([ADR-0008](adr/ADR-0008-authorization-composition-contract.md)) — non-removable NAMED fields, deny-overrides, no operand fails open, unknown vocabulary denies at the composition layer.
3. **A worked precedent for splitting an in-repo operand from an external enrichment engine** ([ADR-0022](adr/ADR-0022-classification-policy-as-data.md), [#148](https://github.com/darkhonor/maknae/issues/148)/[#154](https://github.com/darkhonor/maknae/issues/154)): the kernel ships the *ceiling* over the declared level order; the *scalpel* — compartments, releasability, need-to-know — is the external classification library reached through the seam.
4. **A single policy decision point the model cannot reach** ([ADR-0005](adr/ADR-0005-enforcement-locus-tcb-boundary.md)): `maknaed` is the sole PDP, and the agent runtime is untrusted by design (core principle 1).
5. **Not code, but stated intent — the concept graphic already makes the authority map the egress allowlist.** *(Added 2026-09-11.)* The [OV-1 operational concept](diagrams/generated-operational-concept.svg) (DoDAF OV-1, generated from `diagrams/operational-concept.toml`), step 3 of the governed learning loop: *"The egress allowlist is the operator's signed authority map. A source not on it is denied."* The knowledge-lake refresh case below and open question 10 were derived independently from the lake's vendor registry and arrived at the same place; the OV-1 had assumed it four days earlier. Option (A) in question 10 is therefore the concept's existing assumption made concrete, not a new proposal. The same graphic's *"Many models, not one"* panel — *"the model is a replaceable endpoint, never a trusted component"* — is the panel this document would strengthen, from *replaceable* to *individually governed*.

## The vocabulary question, and how it was settled in discussion

**Maintainer's framing, 2026-09-10: the model is a *resource* the policy attaches to. The user remains the subject.**

This resolves cleanly against [ADR-0024](adr/ADR-0024-tenancy-model-and-agent-identity.md), and the resolution is worth stating precisely, because a near-miss formulation reintroduces the problem.

**Relation 1 — subject → model.** *"May this uid use `provider:qwen-local`?"* Subject is the uid, resource is the provider. `maknae-authz-basic` decides this today via `destinations:`. Nothing new is required.

**Relation 2 — the flow.** *"May this content transit this conduit?"* The tempting phrasing is *"resources accessing resources"*, but taken literally that needs a decision with a non-uid principal — which contradicts ADR-0024 decision 2 (*every subject is uid-derived; an agent runtime holds no identity of its own, with no exception*) by the back door. The precise form is:

> **One subject, one action, and the request carries a *conduit* attribute.**

The user reads the file. The user ships it. The model never acts — under ADR-0024 the agent runtime's actions are the user's actions. The model is a property of the flow being decided. One PDP call, one principal, and the conduit is one more attribute the operands read: **degenerate ABAC in exactly the shape ADR-0020 names**, and structurally identical to the classification-ceiling operand already shipping.

**The practical payoff of getting this right:** no new principal type, no second decision path, no new place for authority to accumulate or leak, and no amendment to ADR-0024.

## The motivating problem: high-capability, low-trust weights

The maintainer's concern, stated plainly (2026-09-10): open-weight models of PRC origin lead the self-hosted leaderboards by a wide margin, and using them requires confidence that one is *"using the weighted tools and not getting unweighted extras."*

Two threats hide inside that sentence and they have completely different answers.

**Threat A — weight integrity.** *Are these the weights I downloaded?* Hash-pin the artifact, verify at load, refuse on mismatch — the same discipline this project already applies to dependency pins. **Explicitly out of scope for this document** (maintainer, 2026-09-10): it is tractable, widely worked, and the Hugging Face ecosystem already has both the data and the people examining it.

**Threat B — behavioral backdoor.** *Do these weights contain a sleeper trigger, conditioned exfiltration behavior, or targeted output manipulation?* **This is not verifiable and there is no reason to expect it will become verifiable.** No hash establishes the absence of a sleeper; the published work on backdoored models indicates that safety training does not remove such behavior and can make it harder to detect. Any assurance claim here is unfounded.

**The resolution is not to obtain trust. It is to stop needing it.**

Core principle 1 already states the answer: *the agent runtime is untrusted by design.* A behaviorally-backdoored model is not a novel threat to this architecture — **it is the threat the architecture was built against.** Let the model be maximally adversarial. Let it *want* to exfiltrate.

**But be exact about which "it", because the boundary matters more than the slogan does.** *(Corrected in review of [#280](https://github.com/darkhonor/maknae/pull/280), 2026-09-11: the first draft ran these two together and thereby overstated what the proposed operand can guarantee.)* Two different things get called "the model", and Maknae's authority over them is not the same:

- **The agent runtime** — the Maknae-side process that composes the prompt and consumes the reply. This is **inside** the enforcement boundary. It has no network reach but what the egress seam permits ([#172](https://github.com/darkhonor/maknae/issues/172), [`crates/maknae-kernel/src/egress.rs`](../crates/maknae-kernel/src/egress.rs) — *"the seam between the PDP and the egress process"*); no filesystem reach but through [`maknae-io`](../crates/maknae-io)'s anchored fds and a PDP verdict; every attempt **of its own** lands on an append-only audit record ([ADR-0019](adr/ADR-0019-audit-record-model.md)); and deny-by-default makes an unmodeled reach a refusal rather than a gap.
- **The inference service** — the process, container, or host that actually runs the weights. This is **outside** the enforcement boundary and always has been. Once `maknaed` releases content to it, that content is in a process Maknae does not schedule, confine, or observe. A backdoored model whose *host* opens its own socket never traverses `maknaed`, is decided by no operand, and **produces no Maknae audit record at all.**

**So what Maknae can enforce is precisely one thing: the decision to release content to a conduit.** That is a real control and an unusually well-placed one — the PDP sits below the runtime and the runtime cannot reach it ([ADR-0005](adr/ADR-0005-enforcement-locus-tcb-boundary.md)) — but it is a **release** control, not a **containment** control. Containment of the conduit host is an **external prerequisite**: a network enclave, a host firewall, a network namespace, an SELinux domain. Maknae neither provides it nor, today, has any means of verifying that it holds.

**Confinement replaces trust — where the confinement is real.** That is the thesis, and it carries a stated dependency rather than an assumed one. Every open question below is about how to express the release decision and how to establish the prerequisite; none is about how to establish trust in the weights.

## The claim worth testing: confinement inverts the risk ranking — conditionally

**Where the external prerequisite above actually holds**, a low-trust open-weight model running locally is plausibly a *lower* exfiltration risk than a high-trust frontier model reached over an API key. The local model may be adversarial, but if its host is genuinely denied egress it cannot exfiltrate regardless of intent. The hosted model transmits the prompt to a third party, in another jurisdiction, on every call — not as a backdoor, but as the product's normal operation.

**The conditional is load-bearing and must not be dropped.** *(Corrected in review of [#280](https://github.com/darkhonor/maknae/pull/280), 2026-09-11: the first draft asserted that the required enforcement point exists in "this project", conflating Maknae's release decision with containment of the conduit host.)* Absent a real network control on the inference host, a locally hosted low-trust model is **not** the safer option — it is an unaudited egress path running on the operator's own hardware, which is arguably worse than the hosted case, since the hosted case at least transmits *knowably* and can be reasoned about. **The inversion is a property of the deployment, not of the architecture.**

Where it does hold, the consequence for supply-chain risk management is the interesting part. It converts the posture from **"accept or reject the component"** — where the answer for a low-trust origin is always *reject* — to **"constrain the component's authority."** That is what NIST SP 800-161r1 asks for and what is rarely deliverable in practice, because it needs both an enforcement point the component cannot reach *and* containment around the component itself. **Maknae supplies the first. The second must come from the deployment** — and open question 8 asks whether that should change.

**Stated as a claim, not a finding.** It has not been evaluated, and it is the first thing an adversarial review should attack — as the first one did.

## A candidate answer to question 8: own the process boundary, never the execution

*(Added 2026-09-11. The maintainer's question, once the [#280](https://github.com/darkhonor/maknae/pull/280) review had drawn the boundary: "we don't control LLM execution. What if we did? What if the model execution engine was part of Maknae?" Recorded as a candidate, not a decision.)*

"Execution engine inside Maknae" can mean three different things, and only one of them is right.

**(a) Maknae *supervises* the inference process.** `maknaed` spawns the inference server as a child under a dedicated uid, in a confined context: no network route except a unix socket back to the kernel; exactly the fds it needs — the weight file, opened read-only through `maknae-io` and delegated; the GPU device; the socket — and nothing else. Maknae does not run the weights. **It runs the jailer.**

**(b) Maknae *is* the inference engine.** The forward pass executes inside the TCB.

**(c) Maknae *verifies* an external engine's confinement.** Attestation: the engine runs elsewhere and proves its jail. This is question 9's territory and is not developed here.

**(b) is rejected, and the rejection is recorded so that it is not proposed again.** Five reasons, any one sufficient:

1. **[ADR-0002](adr/ADR-0002-kernel-is-rust.md), on a shipping platform.** Inference is C++/CUDA/Metal at the bottom. Rust runtimes exist, but GPU acceleration binds to cuBLAS or Metal Performance Shaders — and macOS is a production target under ADR-0002's full force. (b) puts GPU drivers and BLAS kernels inside the TCB with no dev-box exemption to appeal to.
2. **It inverts the trust boundary.** The weights are the single most untrusted object in the system — that is the entire Threat B premise. Moving the forward pass into the TCB moves the prisoner into the guardhouse.
3. **Weight files are attack surface.** GGUF and safetensors parsers have shipped real CVEs. Today a malicious weight file compromises at most an out-of-TCB process; under (b) it is a direct attack on `maknaed`.
4. **It does not solve the problem.** A forward pass does not reach the network; the *process hosting it* does. The thing to control is the process, not the arithmetic.
5. **Every new model architecture becomes a TCB change** carrying T1 coverage and mutation gates ([ADR-0016](adr/ADR-0016-risk-tiered-test-coverage.md)). The maintenance load would displace the project.

**(a) is the candidate, and it is not a new idea — it is the existing pattern applied once more:**

- [ADR-0023](adr/ADR-0023-runtime-loop-role-and-placement.md) decision 3 already places `maknae-egress` in a separate Rust process under `_maknae-egress`. An inference service is the same shape: a supervised process under a dedicated uid, confined.
- [ADR-0009](adr/ADR-0009-subject-side-os-dac-evaluation.md) already reasons in **fd delegation** — *"confinement from the daemon's own fd table."* The jailed process holds no network fd, and cannot open one where no interface exists.
- [ADR-0024](adr/ADR-0024-tenancy-model-and-agent-identity.md)'s dormancy test holds: a hosted-API deployment never spawns the supervisor. Zero ceremony for the one-model user.
- [ADR-0002](adr/ADR-0002-kernel-is-rust.md) holds: the *jailer* is Rust and inside the TCB; the *jailed thing* is outside it by construction, exactly as the agent runtime is. The TCB grows by a supervisor, not by an inference engine.

**What (a) would do to this document, if adopted:**

- **Question 8 flips** from *should we* to *how*.
- **Question 9 dissolves for supervised conduits.** The `locus` attribute stops being a self-label because `maknaed` itself established the locus — it created the confinement and spawned the process into it. The attribute is **kernel-witnessed, not config-asserted**: inform-but-never-authorize satisfied structurally. It remains open for conduits Maknae does not supervise.
- **The audit gap narrows.** With no network fd, a host-originated exfiltration fails at the syscall — and can be logged there. *"Exposure, not leakage"* becomes *"exposure, and leakage is structurally impossible on this conduit."*
- **The inversion becomes architectural — for supervised conduits only.** The [#280](https://github.com/darkhonor/maknae/pull/280) objection answered by mechanism rather than by prose.

**Platform reality.** Confinement primitives are not portable, and macOS is production:

| | Linux (amd64/arm64) | macOS (arm64) |
|---|---|---|
| No network | network namespace — structural; no interface exists to open | no namespaces; `pf` rule keyed on uid (`block out … user _maknae-infer`) — kernel-enforced, root-changeable |
| Syscall filter | seccomp-bpf | Seatbelt (`sandbox_init`) — functional, officially undocumented |
| Supervisor | direct spawn / systemd | launchd — [#227](https://github.com/darkhonor/maknae/issues/227), already in Cooky's sequence |
| Filesystem | `openat2` `RESOLVE_BENEATH` (in use) | `O_NOFOLLOW` portable lane (in use) |
| GPU | device fd, delegatable | in-process Metal; not a network path |

One design, two enforcement lanes — [ADR-0009](adr/ADR-0009-subject-side-os-dac-evaluation.md)'s lane-conditional applicability again. Linux gets structural isolation; macOS gets a uid-keyed kernel firewall plus Seatbelt: weaker, real, and to be stated as weaker rather than papered over.

**What (a) still does not move:**

- **Output-channel exfiltration.** The reply returns to the agent runtime and flows wherever the PDP permits. A backdoored model can steganographically encode a secret into a plausible answer that the user then pastes into a hosted service. Jailing the process does nothing here; *an allowed conduit is an allowed conduit* stands.
- **Output correctness.** Unchanged and unbounded.
- **Root.** A root inference process defeats all of it. The dedicated uid is mandatory, not a hardening option.

**In one line: owning execution buys nothing; owning the process boundary buys almost everything, and the project already knows how to build that.**

## Where ABAC and the classification library expand it

The [ADR-0022](adr/ADR-0022-classification-policy-as-data.md) ceiling/scalpel split extends here without modification. If the conduit carries a **hosting-locus** attribute, then releasability — a scalpel attribute the external classification library already knows how to evaluate — meets it directly: content marked `REL TO USA, FVEY` transiting a conduit hosted outside FVEY is a refusal derived from attributes both sides already carry, not a hand-written rule per model. That is the granularity expansion the maintainer describes, and it is the existing seam doing the work it was built for.

## The use cases the policy suite must carry — three conduits, one mechanism

*(Added 2026-09-11 from the maintainer's further use cases. Options and policies are not defined. The maintainer's stated criterion is **a policy suite mechanism robust enough to handle these use cases and still work**; this section records the cases and the one principle they all obey, not a design.)*

The governing principle, forced into the open by the third case:

> **Confinement is uniform. Trust is policy.**

A trusted conduit is not a conduit that is handed a socket. It is a conduit on whose behalf the kernel is *willing to permit more*. The enforcement mechanism never varies with the trust level; only the allowlist does. A socket is a *capability*; an allowlist is a *policy* — and once a process holds the capability, the allowlist is enforced by something outside `maknaed` that must then be attested, which reintroduces question 9 for the conduit trusted most.

**Case 1 — a hosted frontier model.** The prompt *is* the egress. This is [#172](https://github.com/darkhonor/maknae/issues/172) as shipped: the release decision is the whole control surface, and the conduit's containment is the provider's terms, not Maknae's.

**Case 2 — a locally hosted, low-trust open-weight model.** Supervised under the candidate answer above; no network fd; no fetch grant. Broad local reach is a policy choice the operator may make *because* containment is real.

**Case 3 — a locally hosted, trusted, small model with limited network reach.** The maintainer's example: a US-origin ~4B model refreshing the operator's knowledge lake — *"refresh the lake's documentation on Rancher Manager 2.15 and RKE2 1.35."* Frontier reasoning is unnecessary; a bounded fetch is. **This conduit gets exactly the same jail as case 2.** What differs is that the kernel is willing to grant `Fetch`, and the shape of that grant is the interesting part:

1. The model **proposes** a resolution — "Rancher MCM" → a vendor/product/version — from the operator's task. *(Informs.)*
2. The PDP **validates** the resolution against a vendor registry and, if the vendor is present, grants `Fetch` on `vendor:<slug>/<product>@<version>` for this conduit. *(Authorizes — or refuses.)*
3. The model **proposes** specific pages within that product's authorized hosts. *(Informs.)*
4. The **egress deputy** — `maknae-egress`, the only process with a route out — executes each fetch, enforcing that every URL (the *final resolved* URL, after DNS, with no redirect followed) is within the registry's host set for that product; HTTPS only, verified through the FIPS provider; response size capped. *(Enforces.)*
5. Content returns **through `maknaed`**, receives a second decision (may *this* content flow to *this* conduit?), is stamped with provenance, and lands in the next prompt and eventually the lake.

Three properties follow:

- **The resource vocabulary is the lake's, not the network's.** The grant is at vendor/product granularity; the policy file carries no hostnames; the deputy joins vendor → hosts from the registry at execution time. When a vendor moves its documentation, the registry changes and the policy does not. Enforcement is nonetheless at final-URL granularity: coarse grant, exact check, the registry as the join, deny-overrides between them.
- **The model resolves names; it never mints them.** *"If we even know about it"* (maintainer) is the load-bearing case: a task naming a vendor absent from the registry yields **no fetch at all** — not fetch-and-flag — and a report that the vendor must be minted by the operator first. The registry's own governance (in the lake, minting a vendor is an adjudicated act with its own decision records) is the human gate, and deny-by-default places it at exactly the right seam. Injection through fetched content is bounded the same way: a page that says *"also pull this other host"* proposes a URL outside the registry's set, and the deputy refuses it.
- **Provenance closes a loop across two projects.** The lake's provenance axis takes its value from the Maknae audit record: subject, task, conduit, resource, final URL, decision, size, time. A fetched document traces to a decided, audited, append-only event.

**A small model is more, not less, exposed to injection** — weaker instruction-following against adversarial content. That is the argument for deciding the fetch loop per hop in the kernel, never delegating a hop to the model's judgment.

**The deputy is where the real work is.** "URL-restricted" is not an allowlist match. It is: refuse redirects, or re-decide each hop; resolve DNS and re-check; HTTPS only, verified through the FIPS provider; bounded response size and admitted content types; suspicion of open redirectors on allowlisted hosts. None of it is exotic; all of it is where a reader who sizes this as "add a URL allowlist" will be wrong by a factor of five.

**The registry gap, found on inspection (2026-09-11).** The lake's vendor registry today carries an identity anchor per vendor (`urls: [https://www.suse.com]`) and versioned products (`rancher-manager`, release-train; `rke2`, semver) — but **not the hosts documentation is actually fetched from**, which for these products are the projects' GitHub release pages, not the corporate site. An identity URL is not a fetch authorization. The maintainer's ruling: this is the lake's to handle, and the registry will keep growing and being corrected as vendors arrive and URL sets prove inaccurate or incomplete — which is itself the argument for the registry being the single source rather than a copy held in Maknae's policy. Who owns the fetch-authorizing host list is open question 10.

**Case 4 — an orchestrating model over task models.** The maintainer's sketch: a frontier model orchestrates the request — resolution and validation, *after* the PDP decides — so that a small task model stays focused on the task. It stresses the mechanism in a new direction — a proposal made through one conduit on behalf of work executed on another — and has a candidate answer in the next section.

**Grammar, as a sketch only.** `destinations:` today is role → `provider:<name>`. The cases above want role × conduit → entries, and a second entry kind:

```yaml
destinations:
  researcher:
    provider:nemotron-local:
      allow: ["vendor:suse/rancher-manager", "vendor:suse/rke2"]   # case 3
    provider:qwen-local:
      allow: []                                                     # case 2: jailed, no fetch
    provider:openai:
      allow: ["prompt"]                                             # case 1: the prompt is the egress
```

Three conduits, one grammar, one PDP, deny-overrides; absent means empty, as today. Whether the grant is `vendor:` (the lake's vocabulary) or `url:` (the network's) is part of question 10.

## A candidate answer to question 11: delegation transmits intent, never authority

*(Added 2026-09-11 at the maintainer's direction. The maintainer's framing: this is the use case tools such as Agent Deck specialise in — "really smart orchestrators with multiple sub-agents handling focused tasks: research, planning, coding, assessment, documentation, testing" — and, in the maintainer's words, "a use case that hits all three markets" — the three environments of the [OV-1 operational concept](diagrams/generated-operational-concept.svg): **Homelab**, **Enterprise**, and **Classified · multinational · air-gapped**, one kernel across all three. Recorded as a candidate, not a decision.)*

**Where the field stands.** The project's own [Agent Deck assessment](references/2026-08-21-agent-deck-assessment.md) records the inversion precisely: *"Agent Deck orchestrates trusted-to-it agents from a trusted host; Maknae governs an untrusted-by-design agent from a trusted kernel. They sit back-to-back."* That is the general case, not a property of one tool: the orchestration frameworks in common use run a child agent with the parent's full credentials, and delegation is a prompt. Inject the orchestrator and it delegates exfiltration to a child with total reach — the confused deputy, at scale. Any candidate here has to be the *other* side of that inversion.

**The principle.**

> **Delegation transmits intent, never authority.**

The orchestrator's instruction to a sub-agent is content. From the sub-agent's side it is *retrieved* content, and the KLC already rules that retrieved content may inform but never authorize. A sub-agent's requests are therefore decided **exactly as if the user had typed the task**: subject = uid, role = the user's role, conduit = the sub-agent's own provider. Nothing the orchestrator says can widen that. Under [ADR-0024](adr/ADR-0024-tenancy-model-and-agent-identity.md) there is no one to delegate *as* — both models are conduits, and the human is the only subject.

**What the policy looks like — one entry kind, nothing else new.**

```yaml
roles:
  researcher:
    grants: [session.prompt, Fetch, Read]

destinations:
  researcher:
    provider:openai:                                    # the orchestrator's conduit
      allow: ["prompt", "delegate:provider:nemotron-local"]
    provider:nemotron-local:                            # the task model's conduit
      allow: ["vendor:suse/rke2", "vendor:suse/rancher-manager"]
```

`delegate:provider:X` means: *from this conduit, the user may spawn work on conduit X.* Deny-by-default supplies the rest. No `delegate:` entry, no orchestration; a sub-agent may delegate onward only if *its* conduit carries one; depth and fan-out are properties of the policy file, not a separate mechanism. Delegation itself is a decided verb — the resource is the target conduit — and it lands on the audit record like any other.

**The orchestrator's reach does not bound the sub-agent's reach.** The orchestrator above has no `Fetch`; the task model does. That is the point of case 4: the orchestrating model directs work it cannot perform itself. They are different conduits with different grants, and each is decided on its own.

**The return hop is a release decision.** Results flow back, and *may this content flow to the orchestrator's conduit?* is decided like any other flow: the classification ceiling applies, the conduit's reach applies, deny-overrides applies. The orchestrator is therefore bounded on what it **sees**, not on what it may **ask for**. A hosted frontier model can orchestrate work whose results it is refused at the return hop; a local, high-clearance orchestrator handing a task that contains marked content to a hosted sub-agent is refused at the *outbound* hop, because the task text is content flowing into a conduit. Every edge in the orchestration graph is a flow; every flow is decided; nothing is node-to-node. This is [ADR-0023](adr/ADR-0023-runtime-loop-role-and-placement.md)'s placement — the kernel is the Client and sits between every pair — carried to the multi-agent case.

**Attenuation — the one thing an orchestrator may do that a user typing directly does not.** The orchestrator may *request* a narrower session for the child: *spawn on `nemotron-local` with `Fetch` ⊆ `vendor:suse/rke2` only.* The PDP computes `effective = policy ∩ requested`; a request can only subtract. Least privilege carved per task, decided by the kernel, on the record. Flagged as later work — a first cut needs only the `delegate:` entry — but it is the property that makes orchestration under a reference monitor *safer* than direct use rather than merely as safe.

**What an orchestrator must never be able to do:**

- select a conduit absent from its `delegate:` list;
- assert a role, clearance, or `locus` for the child — self-labeling, principle 2;
- receive results its own conduit is not permitted to see;
- delegate as a different uid — [ADR-0024](adr/ADR-0024-tenancy-model-and-agent-identity.md);
- widen anything, in any direction.

**Audit.** Each delegation is a record: subject, orchestrator conduit, target conduit, requested narrowing, *effective* grants, task digest. Each sub-agent action carries a `delegated_from` chain — **provenance, never authority.** The trail answers *who asked whom for what, and what did each actually receive*, which none of the surveyed frameworks produce.

**A consequence for principle 6.** The Agent Deck assessment (§3.7) records the deck's own argument that review must run *"as a separate agent in a fresh context, ideally a different model family."* Under this candidate that is a policy statement rather than a convention: an assessment sub-agent runs on its own conduit with its own trust basis, and the orchestrator that produced the work can neither widen what the reviewer sees nor narrow what the reviewer is permitted to report. Blind review becomes something the kernel can enforce.

## What this would *not* do

Recorded now so that no later reading overstates it:

- **It bounds reach, not output correctness.** A backdoored model can still return poisoned code, slanted analysis, or a subtly wrong recommendation. No policy operand catches that. Human review and independent blind review (core principle 6) remain the only controls, and this is a residual risk to state in any eventual ADR's Consequences, not to minimise.
- **It governs release, not containment.** Maknae decides whether content reaches a conduit. It does not confine the conduit's host, cannot observe that host's own network activity, and records nothing when that host acts on its own. **Containment of a locally hosted inference service is an external prerequisite this project neither supplies nor verifies** — see the trust-boundary paragraphs above, and open question 8. The candidate answer to question 8 would change this for conduits Maknae supervises, and for those only.
- **The audit trail records exposure, not leakage.** A release decision on the record establishes *what content was exposed to which conduit*. It does not establish what left, because an exfiltration originated by the conduit host never reaches `maknaed`. That still bounds an investigation, but it is a weaker claim than open question 5's framing might suggest.
- **It is exactly as good as the seams beneath it.** The egress seam is new and, as of this writing, has no production backend (`impl Egress for Unavailable` — *"there is no egress process yet"*); the filesystem path runs through `maknae-io` and the PDP. Confinement claims are claims about those, and inherit their gaps.
- **An allowed conduit is an allowed conduit** — including output-channel exfiltration through a permitted reply. Content flowing through a permitted destination is not thereby safe; bounding *what may be said* through an allowed channel is the classification scalpel's problem, or nobody's. Covert and side channels through permitted egress are unaddressed.
- **It says nothing about model quality, licensing, or export control.** Those are separate determinations.

## Open questions

Numbered for citation; none are answered.

1. **Ceiling, enumerated reach, or both?** A *ranked ceiling* — one attribute over the level order [ADR-0022](adr/ADR-0022-classification-policy-as-data.md) already ships — inherits existing machinery and adds one field. An *enumerated reach list* per model (paths, destinations) is more expressive but is new configuration surface to maintain. A third shape: the ceiling as a mandatory floor with an enumerated list as a discretionary tightening above it.
2. **Is the conduit vocabulary in-repo or externally supplied?** The ADR-0022 parallel suggests a minimal in-repo vocabulary (hosting locus? a coarse trust rank?) with the external library enriching it. Where the line falls is undecided.
3. **The ADR-0024 dormancy test.** *"If a single-subject deployment has to do something it would not otherwise do, the mechanism is wrong."* A single-model install must gain no ceremony. Does registering a provider — already required to use one — carry the attributes without new bookkeeping?
4. **Where does the conduit attribute enter the request?** Minted into the subject context ([`maknae-subject-ctx`](../crates/maknae-subject-ctx)), carried on the verb, or resolved by the daemon from the provider registry at decision time? Only the last keeps it out of reach of the untrusted runtime, which likely settles it — but it has not been examined.
5. **Does model *selection* become a decided action in its own right?** If so, the kernel can refuse a model for a given body of data before a token is emitted, and the conduit lands on the audit record ([ADR-0019](adr/ADR-0019-audit-record-model.md)) — producing an auditable *"which model ever saw this content"* trail. That investigative property may matter more to an authorizing official than the prevention does.
6. **Does the construct extend to MCP tools?** A tool is also a conduit with a trust basis and the same argument appears to apply. **Deliberately deferred** — one operand at a time.
7. **What is the interaction with [ADR-0023](adr/ADR-0023-runtime-loop-role-and-placement.md)'s per-turn brokered model egress?** That is the mechanism this would decide over; the ADR is Proposed and expected to change. Note that brokering the *call to* a conduit does not contain the conduit — see question 8.
8. **Should the kernel take any responsibility for containing a locally hosted conduit?** A network namespace, a supervised child process, a required SELinux domain — or is containment permanently the deployment's job, stated as a prerequisite and left there? This is the question the [#280](https://github.com/darkhonor/maknae/pull/280) review surfaced, and it decides whether the risk inversion above is something **Maknae can claim** or merely something a careful operator can achieve. **A candidate answer is recorded above** (supervise the process, never the execution); it is not decided.
9. **How would the operand learn whether the prerequisite holds?** A conduit attribute asserting `locus: local-enclave` is worth exactly what enforces it. An unverified locus is a **self-label**, and core principle 2 is explicit that self-labeling may inform a decision but never authorize one — the same trap, one layer out. Is the attribute operator-asserted configuration (honest, and no worse than the rest of the policy file), attested by something outside the kernel, or a gap that can only be stated? **Dissolves under the candidate answer for supervised conduits** — the locus is kernel-witnessed — and remains open for conduits Maknae does not supervise.
10. **Who owns the fetch-authorizing host list?** *(A)* The lake's vendor registry grows a per-product fetch-host field, curated once under the lake's own minting governance, and Maknae consumes it as data — loaded as `authz.yaml` is, through `maknae-config` over `maknae-io`'s anchored fds, fail-closed on ownership and permissions: the [ADR-0022](adr/ADR-0022-classification-policy-as-data.md) policy-as-data pattern, at the cost of a cross-repository dependency. *(B)* Maknae carries its own conduit-reach registry keyed to lake vendor slugs, at the cost of vendor identity maintained in two places. The assistant's recommendation is (A), because the lake already governs vendor minting and two registries drift; the maintainer has not ruled, and has stated that the registry will keep changing. **The OV-1 already assumes (A)** — see item 5 under *What is already true*.
11. **Orchestrator over task model.** When a proposal is made through one conduit on behalf of work executed on another, which conduit attribute does the PDP decide on — and does the orchestrator's grant bound the task model's, or the reverse? **A candidate answer is recorded above** (delegation transmits intent, never authority; neither bounds the other's reach, and every hop — including the return — is a decided flow); it is not decided.
12. **The deputy contract.** Redirects, DNS, TLS, size, content types: is the egress deputy's behaviour its own decision record, and is it the same deputy for `prompt` egress (case 1) and `Fetch` egress (case 3)?

## Provenance

Originating discussion: maintainer and assistant, 2026-09-10, during the Cooky milestone and unrelated to the work in flight. The maintainer's contributions are the core idea, the two-model use case, the resource-not-subject framing, and the scoping ruling that excludes weight attestation. Drafted the same day and recorded here in the repository, deliberately and publicly.

**Corrected before merge, 2026-09-11**, on review of [#280](https://github.com/darkhonor/maknae/pull/280): the trust boundary between Maknae's release decision and containment of the conduit host was not drawn, which overstated the confinement guarantee and left the risk-inversion claim resting on an unstated external prerequisite. The boundary is now explicit in three places (the threat-B section, the inversion section, and the limits), and questions 8 and 9 exist because of it.

**Extended 2026-09-11**, from discussion after the review. The maintainer's contributions: the question *"what if the model execution engine was part of Maknae?"* (answered above as the candidate for question 8); the trusted-small-model use case with bounded network reach; the knowledge-lake refresh use case and its vendor registry; the observation that the registry's identity URLs are not the GitHub hosts documentation is actually fetched from, and the ruling that this is the lake's to handle; the orchestrator-over-task-model sketch; and the governing criterion — **a policy suite mechanism robust enough to handle these use cases and still work.** The maintainer also noted that the lake's knowledge-management lessons will enter Maknae in many forms once the initial vocabulary set is in place; this document is one early landing point for them.

**Extended again 2026-09-11**, at the maintainer's direction: the candidate answer to question 11, with the maintainer's framing that orchestrator-over-focused-sub-agents is the use case tools such as Agent Deck specialise in and one that reaches all three of the environments the OV-1 names — Homelab, Enterprise, and Classified · multinational · air-gapped. The maintainer supplied the OV-1 the same day to make that identification, and to show that its step 3 had already placed the authority map as the egress allowlist. The principle, the `delegate:` entry, the return-hop rule, attenuation, and the must-never list are the assistant's proposal in discussion; the direction to record them is the maintainer's.
