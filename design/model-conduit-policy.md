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

## What is already true in the code

This is not a green field. Four load-bearing pieces exist:

1. **A per-role egress destination allowlist, whose entry grammar is already `provider:<name>`.** Shipped in [#172](https://github.com/darkhonor/maknae/issues/172) (`crates/maknae-config/src/authz.rs`): `destinations:` maps a role to an allow list, `destination_entry_is_acceptable` enforces the entry grammar, and an absent section means an empty allowlist for every role — deny-by-default, additively. This is **subject → provider** and it decides today.
2. **A composition contract that admits new mandatory operands** ([ADR-0008](adr/ADR-0008-authorization-composition-contract.md)) — non-removable NAMED fields, deny-overrides, no operand fails open, unknown vocabulary denies at the composition layer.
3. **A worked precedent for splitting an in-repo operand from an external enrichment engine** ([ADR-0022](adr/ADR-0022-classification-policy-as-data.md), [#148](https://github.com/darkhonor/maknae/issues/148)/[#154](https://github.com/darkhonor/maknae/issues/154)): the kernel ships the *ceiling* over the declared level order; the *scalpel* — compartments, releasability, need-to-know — is the external classification library reached through the seam.
4. **A single policy decision point the model cannot reach** ([ADR-0005](adr/ADR-0005-enforcement-locus-tcb-boundary.md)): `maknaed` is the sole PDP, and the agent runtime is untrusted by design (core principle 1).

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

Core principle 1 already states the answer: *the agent runtime is untrusted by design.* A behaviorally-backdoored model is not a novel threat to this architecture — **it is the threat the architecture was built against.** Let the model be maximally adversarial. Let it *want* to exfiltrate:

- it has no network reach but what the egress seam permits ([#172](https://github.com/darkhonor/maknae/issues/172));
- it has no filesystem reach but through [`maknae-io`](../crates/maknae-io)'s anchored fds and a PDP verdict;
- every attempt lands on an append-only audit record ([ADR-0019](adr/ADR-0019-audit-record-model.md));
- deny-by-default means an unmodeled reach is a refusal, not a gap.

**Confinement replaces trust.** That is the thesis, and every open question below is a question about how to express the confinement, not about how to establish the trust.

## The claim worth testing: confinement inverts the risk ranking

Under real confinement, **a low-trust open-weight model running locally is a *lower* exfiltration risk than a high-trust frontier model reached over an API key.** The local model may be adversarial but is physically contained: if the enclave denies egress, it cannot exfiltrate regardless of intent. The hosted model transmits the prompt to a third party, in another jurisdiction, on every call — not as a backdoor but as the product's normal operation.

If that holds, the consequence for supply-chain risk management is the interesting part. It converts the posture from **"accept or reject the component"** — where the answer for a low-trust origin is always *reject* — to **"constrain the component's authority."** That is what NIST SP 800-161r1 asks for and what is rarely deliverable in practice, because it requires an enforcement point the component cannot reach. This project has one.

**Stated as a claim, not a finding.** It has not been evaluated, and it is the first thing an adversarial review should attack.

## Where ABAC and the classification library expand it

The [ADR-0022](adr/ADR-0022-classification-policy-as-data.md) ceiling/scalpel split extends here without modification. If the conduit carries a **hosting-locus** attribute, then releasability — a scalpel attribute the external classification library already knows how to evaluate — meets it directly: content marked `REL TO USA, FVEY` transiting a conduit hosted outside FVEY is a refusal derived from attributes both sides already carry, not a hand-written rule per model. That is the granularity expansion the maintainer describes, and it is the existing seam doing the work it was built for.

## What this would *not* do

Recorded now so that no later reading overstates it:

- **It bounds reach, not output correctness.** A backdoored model can still return poisoned code, slanted analysis, or a subtly wrong recommendation. No policy operand catches that. Human review and independent blind review (core principle 6) remain the only controls, and this is a residual risk to state in any eventual ADR's Consequences, not to minimise.
- **It is exactly as good as the seams beneath it.** The egress seam is new; the filesystem path runs through `maknae-io` and the PDP. Confinement claims are claims about those, and inherit their gaps.
- **An allowed conduit is an allowed conduit.** Content flowing through a permitted destination is not thereby safe; bounding *what may be said* through an allowed channel is the classification scalpel's problem, or nobody's. Covert and side channels through permitted egress are unaddressed.
- **It says nothing about model quality, licensing, or export control.** Those are separate determinations.

## Open questions

Numbered for citation; none are answered.

1. **Ceiling, enumerated reach, or both?** A *ranked ceiling* — one attribute over the level order [ADR-0022](adr/ADR-0022-classification-policy-as-data.md) already ships — inherits existing machinery and adds one field. An *enumerated reach list* per model (paths, destinations) is more expressive but is new configuration surface to maintain. A third shape: the ceiling as a mandatory floor with an enumerated list as a discretionary tightening above it.
2. **Is the conduit vocabulary in-repo or externally supplied?** The ADR-0022 parallel suggests a minimal in-repo vocabulary (hosting locus? a coarse trust rank?) with the external library enriching it. Where the line falls is undecided.
3. **The ADR-0024 dormancy test.** *"If a single-subject deployment has to do something it would not otherwise do, the mechanism is wrong."* A single-model install must gain no ceremony. Does registering a provider — already required to use one — carry the attributes without new bookkeeping?
4. **Where does the conduit attribute enter the request?** Minted into the subject context ([`maknae-subject-ctx`](../crates/maknae-subject-ctx)), carried on the verb, or resolved by the daemon from the provider registry at decision time? Only the last keeps it out of reach of the untrusted runtime, which likely settles it — but it has not been examined.
5. **Does model *selection* become a decided action in its own right?** If so, the kernel can refuse a model for a given body of data before a token is emitted, and the conduit lands on the audit record ([ADR-0019](adr/ADR-0019-audit-record-model.md)) — producing an auditable *"which model ever saw this content"* trail. That investigative property may matter more to an authorizing official than the prevention does.
6. **Does the construct extend to MCP tools?** A tool is also a conduit with a trust basis and the same argument appears to apply. **Deliberately deferred** — one operand at a time.
7. **What is the interaction with [ADR-0023](adr/ADR-0023-runtime-loop-role-and-placement.md)'s per-turn brokered model egress?** That is the mechanism this would decide over; the ADR is Proposed and expected to change.

## Provenance

Originating discussion: maintainer and assistant, 2026-09-10, during the Cooky milestone and unrelated to the work in flight. The maintainer's contributions are the core idea, the two-model use case, the resource-not-subject framing, and the scoping ruling that excludes weight attestation. Drafted the same day and recorded here in the repository, deliberately and publicly.
