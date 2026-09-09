# Maknae developing Maknae — a design discussion, not a decision

**Status: OPEN DISCUSSION.** Nothing here is ratified. This document exists because the intent is stated and the shape is not yet settled, and because the alternative — letting it accrete as habit — is how an unexamined governance model gets built by accident. It follows the register of [`container-architecture.md`](container-architecture.md) and [`secrets-custody-tiers.md`](secrets-custody-tiers.md): frame the problem, record what is already true, name the open questions, decide later.

**Date opened:** 2026-09-10. **Deciders (eventual):** Alex Ackerman (operator).

## The intent

The operator's stated goal (2026-09-10): an agent persona takes on **future development of Maknae itself** — the kernel that authorizes it.

This is not a hypothetical. Every ADR, plan, gate and commit in this repository since inception has been produced by an AI agent under operator direction. The question is not *whether* an agent develops Maknae; it is **what governs that, when the direction becomes less frequent and less specific.**

## What is already true, and is the seed of the answer

**The operator never lets the agent land its own change.** Every commit reaches `main` through a pull request the operator merges. The agent proposes, measures, argues, and revises; it does not decide. This has held without exception and without a written rule.

That is already the governing principle, unstated:

> **An agent may propose changes to Maknae. It may never be the authority that lands them.**

**The field flinched at exactly this point.** The [Jarvis-class survey](references/2026-09-08-jarvis-class-survey.md) found NanoClaw — the surveyed project with the strongest isolation — permits its agent nearly everything inside its container and routes **self-modification** to a human, by direct message, as the one act it will not allow unsupervised. The same survey records OpenClaw's 2026 hardening that approvals *"stay attached to the exact request, command, session, and person"* and that *"script-backed commands recheck the bytes that were reviewed before they run."*

**The existing pipeline is a control, not a workflow.** Spec → plan → adversarial review to convergence → implement → blind review → external review → measurement on every supported host → one push → a pull request a human merges. It is worth naming that this is *already* a self-development governance model; the open question is which parts of it are load-bearing when direction thins.

## The open questions

These are the questions this document exists to hold. None is answered here.

### 1. What is the unit of authorization for unprompted work?

Maknae's verb vocabulary expresses *what* may be done, keyed to a subject and a role. It has no way to express **"this action was not asked for."** An agent acting on its own initiative has no human at the keyboard at the moment of decision, so every safeguard that depends on someone noticing — reading the diff, catching the odd command — is absent. That argues an unprompted action should carry a *narrower* grant than the same action taken in response to a request, and the vocabulary cannot currently say so.

Is initiative an attribute of the request, a distinct lane, or a property of the session? Unresolved.

### 2. What may an agent change about the thing that authorizes it?

There is a gradient, and the ends are obvious while the middle is not:

- Clearly permissible with review: implementation behind an existing contract, tests, documentation.
- Clearly not: the PDP's own decision path, the gates that prove the PDP works, the audit record model, the ADRs that constrain all three.
- **Unclear:** a new verb. A new gate. A change to the review pipeline itself. An ADR amendment. Anything that changes what *future* review will catch.

The sharpest form: **an agent that can weaken the review process can weaken every later safeguard**, and it need not do so deliberately — a plausible simplification is enough.

### 3. What is the human's minimum viable involvement?

Merging every PR is the current answer and it does not scale to the stated intent. But the merge is not the only candidate control point: design agreement, ADR ratification, and the gate set are all places a human decision is load-bearing. Which of them are *sufficient*, and which are merely *habitual*, has not been tested.

### 4. How does dreaming relate to this?

Reflection over past and pending work — see below — is deliberately **not** an authorization surface, because it produces disposition rather than action. But the boundary needs stating: at what point does "a better way to approach this" become "a change I am making"? The transition from reflection to proposal to action is where the control belongs, and it is not currently named.

### 5. What happens when the agent is wrong in a way the gates do not catch?

The gates catch a large and growing class — this repository's history is substantially a record of gates added after something escaped. They do not catch design error, and design error is exactly what an under-directed agent produces most. The reviewer of last resort is currently a human reading a PR body. That is a real control and it has a bandwidth limit.

## Dreaming — settled in shape, and deliberately not an authorization surface

The operator's framing (2026-09-10), which resolves an earlier concern rather than deferring it:

> *"You dream over what you have done and what work is before you. You dream over ways you could have solved a problem differently to assess if it could be done better. It doesn't change the outcome of how a past problem was done. But it shapes how you look at future problems."*

**The mechanism already exists**: the shared memory store, its capture discipline, and the standing-rule and lessons-learned memories that accumulate from completed work. Dreaming in this sense is *reflective, not actuating* — its output is memory and disposition, never an action taken.

That distinction is load-bearing and should survive into whatever this document eventually decides. An agent that reflects is not an agent that acts unprompted; conflating the two would put an authorization question where there is none, and — worse — would invite the real one to be smuggled in beside it.

## What would close this discussion

An ADR, once the questions in §2 and §3 have concrete answers, stating: the classes of change an agent may originate; the control points a human holds; and how an unprompted action is expressed in the vocabulary so that it can be authorized *as* unprompted. Until then this file is the record that the question is open and known.
