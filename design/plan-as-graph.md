# Graph-driven activity — a design discussion, not a decision

**Status: OPEN DISCUSSION.** Nothing here is ratified and nothing here is a requirement. It follows the register of [`self-development.md`](self-development.md): frame the problem, record what was measured, name the open questions, decide later. It sits outside [`design/intent/`](intent/README.md) deliberately — it is assembled from measurements, and that directory's rule is that evidence-bearing documents do not belong there.

**Date opened:** 2026-09-25. **Deciders (eventual):** Alex Ackerman (maintainer). Maintainer rulings are marked where they appear; everything unmarked is analysis, not decision.

**Origin.** The [Jive assessment](references/2026-09-25-jive-assessment.md) §2 named the graph-call primitive as that project's one transferable idea: separate *deciding the shape of the work* from *doing the work*, so the model is consulted when the shape must change rather than when the next step must be looked up. This document takes the half Maknae can use without adopting any of Jive's execution posture, and follows where it led.

---

## 1. The objective

**Keep the model on the task at hand.** The target is prose *about* the task, not prose *for* it:

- **Prose for the task** — the code to write, the ADR text to produce, the command to run, the interface a later task consumes. The deliverable. A graph carries it unchanged.
- **Prose about the task** — narration, justification, restatement of a decision already made, a reminder to act later, an argument aimed at a reviewer. **A graph has no field for it, which is the point.**

A plan that argues its own case invites the executor to re-litigate it. A plan that states activities does not. The recorded objection to this author's output has consistently been tokens spent on the second kind, and a schema with nowhere to put it removes the failure structurally rather than by instruction.

**Context economy is a real secondary consideration, not the reason.** A 27B-class local model has a materially smaller window and less tolerance for distractor text than a frontier model, so progressive disclosure matters more there. But a design optimised only for that would be a different design.

## 2. What is settled

Recorded so a reader knows what is not open. Maintainer rulings, 2026-09-25.

| | ruling |
|---|---|
| 1 | **Policy always takes priority over profile.** A profile may enforce local development discipline; it may never authorize an activity policy denies. |
| 2 | **We define the vocabulary; the organisation defines the profile.** Profiles are an artifact handed to an enterprise to author for itself. |
| 3 | **Agents may author and ingest** — the Jarvis model, *scoped to the Lake only*. Per-user graphs stay per-user; the platform does not infer between users across them. |
| 4 | **Provenance is needed exactly where authorship is delegated.** |
| 5 | **The design takes from neither the KLC nor the Lake's model whole.** Both were built over time against different problems. *"Life sucks at absolutes."* |

## 3. The shape of the idea

A plan is already a graph: tasks depend on tasks, steps depend on steps, steps touch files. Markdown flattens it into a document that must be re-read whole to answer any question about it.

**Two layers.** A **shape layer** carrying node ids, activity classes and edges; a **payload layer** carrying each node's deliverable, addressed by id. A reader loads the shape for a few hundred tokens and pulls only the payloads it needs.

**Authored, never converted.** Plans are generated as graphs from birth. A retrofitting parser over prose is a measurement instrument, not an architecture — §4 is the evidence for that, and it is the strongest result in this document.

**Activity class is a set, not a label.** A step that runs both `cargo test` and `fmt`/`clippy`/`mutants` is both a test and a gate. Single-labelling manufactures false findings.

## 4. What was measured

Two real plans from the out-of-repo plan store, converted by a throwaway parser. `o200k_base` tokens.

| plan | tasks / steps | markdown | shape | payload | shape as % | two-layer total vs md |
|---|---|---:|---:|---:|---:|---:|
| `#148/#154` ceiling composition (code-heavy) | 9 / 56 | 54,710 | **991** | 58,089 | **1.8%** | **108%** |
| `#276` strike reserved agent token (docs/ADR) | 6 / 24 | 4,637 | **451** | 3,529 | 9.7% | 86% |

Per-node payload on the code-heavy plan: min 46, median 193, p90 2,801, max 5,561. Shape plus the single heaviest node is 6,552 — **12% of re-reading the markdown**.

### 4.1 Compression is not the win

The two-layer form is **8% larger** than the markdown on the code-heavy plan: JSONL escaping of fenced code costs more than raw fences. By payload field, prose is **11%** of that plan against **83% code**; on the docs plan prose is 59%, but most of it *is* the deliverable. **Deleting every word of justification leaves the total near parity.**

State disclosure cost (what a reader loads) and keep it separate from storage cost (what the plan weighs). They move in opposite directions on code-heavy plans. The 1.8% shape layer is the real number.

### 4.2 Payload weight is skewed, and the skew is the design

Median 193 against max 5,561 is a 29× spread, so "load the node" is not a uniform cost. This argues for splitting payload further — instruction, deliverable, expected output — so an executor deciding whether a step applies never pays for a diff it has not chosen to apply.

### 4.3 What the graph form makes checkable

Eight structural checks ran against the shape layer. These are properties invisible to a prose reader at 2,610 lines and cheap in a graph:

| property | markdown | shape layer |
|---|---|---|
| orphan / unreachable step | read all 2,610 lines | one traversal |
| dependency cycle | effectively undetectable by eye | topological sort |
| write-before-test across 56 steps | hold 9 tasks in your head at once | one query |
| commit with no gate before it | as above | one query |
| step touching a file outside its declared scope | grep and cross-reference by hand | set difference |
| two unordered steps conflicting on a file | not expressible — markdown has no "unordered" | reachability + scope intersection (§4.7) |

All of it against **991 tokens** — which makes the checks affordable on *every* plan, a different claim from being possible at all.

### 4.4 Inferred typing is not worth building on

**23–33% of steps classified as nothing at all** (13 of 56; 8 of 24). Of the five warnings raised, **two verified true and three false**:

- **True, convention-dependent.** Two commits with no gate before them in their task — a correct structural fact whose *disposition* depends on the plan batching gates into a final task, which it does.
- **False — a noun read as a verb.** A step classified `commit` because its prose says *"retire them in the same commit as their subject."* It commits nothing.
- **False — the check's scope was wrong.** Two steps flagged for naming files their task never declared, where the task is the final sweep and legitimately inherits scope from earlier tasks; one of the files appears only as a *pre-existing coverage violation the gate is expected to report*.

Two converter defects surfaced mid-experiment, both of which produced confident wrong output first: a missing key made "task with no commit" fire on 9 of 9 tasks, and single-label classification manufactured the gate warnings. A task whose one action was not `**Step N:**`-shaped parsed to **zero steps** and became a silently empty node.

**The conclusion, and the reason authoring beats conversion:** a regex over prose cannot distinguish an action from a reference to an action. Written as a graph, *"in the same commit as"* is not prose — it is a `commit-with` edge. The ambiguity is not reduced, it is structurally absent.

### 4.5 What born-as-graph does not fix

Hand-converting the misread step: **49 tokens against 68 — 72%.** The saving is modest because identifiers dominate. **The gain was never tokens; it is that `:commit-with` is a fact a query can trust.**

And two findings survive the change of birth format:

- **The scope false positive.** A rule asking the wrong question is not fixed by a better input format. Scope is plan-level as well as task-level, and file intent (`touches` vs `expects-in-output`) is a distinct field.
- **Conventions that lived in prose.** The gate-batching convention a human reader absorbs must become a declared field (`gates-deferred-to`) or its check reports a defect forever.

**The general form: prose is lossy for machines and lossless for humans, and removing it converts an implicit obligation into an explicit schema field.** Schema completeness is then the only thing standing between a structural check and a confident wrong answer — the same finding as before, relocated from the parser to the vocabulary.

### 4.6 Parallelism — the straight line is an artifact of the format

A markdown plan is a numbered list, and a numbered list implies sequence whether or not the work requires it. **The conversion shows this starkly: every graph this experiment produced is a strict chain** — `t1 → t2 → … → t9`, each step depending on exactly the one printed above it — because document order was the only dependency information the source contained.

Measured against what the plans actually declare:

| plan | tasks with declared files | task pairs | **file-disjoint pairs** |
|---|---:|---:|---:|
| ceiling | 8 of 9 | 28 | **25 (89%)** |
| strike | 4 of 6 | 6 | **6 (100%)** |

**The linear structure came from the format, not from the work.** Tasks with no dependency between them can be dispatched concurrently to subagents; only where one task's outcome feeds another does ordering matter at all.

**The honest bound:** file-disjointness is *necessary but not sufficient*. The ceiling plan has genuine ordering that no file overlap reveals — Task 5 wires a composition root that Task 1's normalizer feeds, an **interface** dependency with no shared file. So 89% is the candidate set after eliminating write conflicts, not a schedule; the real parallelism is lower and is only computable from declared interface edges. That is precisely what the authoring skills' `Interfaces: Consumes / Produces` block was trying to express in prose, and it becomes a typed edge.

**Three consequences, and the second is the one that matters.**

1. **Real parallelism requires declared edges, not inferred order.** Another argument for authoring over conversion: a retrofit cannot recover a dependency the source never stated, so it must assume the worst and serialize everything.
2. **A missing edge is now a correctness bug, not a documentation gap.** Under sequential execution, an omitted dependency is invisible — document order silently supplies it. Under parallel dispatch, two subagents race on the same file. **Declared file scope stops being a convenience for checking and becomes load-bearing for safety**, and it yields a structural check that only exists because of parallelism: *two nodes with no ordering path between them must not declare overlapping write scope.* That belongs in the floor (§6.1), not in an organisation's profile.
3. **The critical path becomes measurable.** With real edges the longest path through the graph is the minimum achievable wall-clock, and the difference between it and the node count is how much a plan's sequencing is costing. Prose gives no such number.

**It also interacts with the execution model.** Each subagent is another instance of the untrusted runtime, so parallel branches are several untrusted runtimes against one kernel — which the PDP already handles, since it decides per request. What gets harder is everything with a shared budget or a total order: retry counts (§6.3 constraint 3) across concurrent branches, escalation when two branches fail independently, and audit ordering under [ADR-0019](adr/ADR-0019-audit-record-model.md) when events no longer arrive in plan order.

### 4.7 The validator rule, stated precisely

The positive case is the point: **five files needing edits are five activities that can run simultaneously on different agents, converging where testing across them matters.** Fan out from the task root, fan in at the validating node. That is the canonical parallel unit, and a profile can require its shape rather than leaving it to an author's discretion.

**"Editing the same file" is only one of three hazards, and the rule needs the operation, not just the path.** Classic dependency analysis applies unchanged — for two nodes with no ordering path between them:

| overlap | hazard | verdict |
|---|---|---|
| write ∩ write | lost update | **must be ordered** |
| write ∩ read | the reader sees one state or the other | **must be ordered** |
| read ∩ read | none | **free** |

The `op` on a declared file (`create` / `modify` / `read`) is what makes this decidable, which is a second reason that field is not decoration.

**File granularity is correct, and deliberately so.** Two agents editing different functions in one file is safe in principle and unsafe in practice: the edit mechanism is line-based read-modify-write, so concurrent writes lose updates regardless of how disjoint the intent was. A later refinement to symbol granularity would introduce exactly the race this check exists to prevent.

**The join node's scope is derived, not authored.** A validating node that fans in must read the union of the write scopes reaching it — otherwise the test does not test what changed. The validator computes that union; an author declaring something narrower is an error rather than a preference.

**Two things the fan-in breaks, and the first has no obvious answer.**

1. **"On failure, return to the prior activity" is ambiguous at a join.** With one predecessor the retry target is unambiguous; with five it is not. Returning to all five re-runs work that succeeded; returning to none loses the failure's cause. The likely answer is that a validating node's failure names *which* predecessors it implicates, which means the pass condition has to be finer than a single exit status — and that is a real cost of parallelism, not a detail.
2. **Partial completion is a state the graph must be able to hold.** If one branch of five fails permanently, four have already written. The structure already prevents the worst outcome — `commit` is downstream of the join and the join is downstream of every branch, so an unreachable join makes the commit unreachable — but the working tree is left mid-change, and whether that is cleaned up or left for inspection is a decision the profile should carry rather than an executor's habit.

*(The maintainer's related observation, recorded without re-litigating it: a lifecycle described as a straight line has the same problem as a plan described as one — the linearity may be in the description rather than in the thing.)*

---

## 5. The graphs Maknae would manage

There is not one graph. **The axis that decides the mitigations is who may write and what a false entry costs**, not purpose.

| graph | writer | trust | lifetime | a false entry causes |
|---|---|---|---|---|
| kernel activity | the kernel alone | **trusted** (TCB) | host lifetime | loss of system integrity |
| governance / profile | operator or organisation, at boot | **trusted** config | boot to boot | wrong enforcement posture, silently |
| user plan | the agent | **untrusted** — authored by the untrusted runtime | ephemeral; retention declared | a bad plan, caught by validation |
| lake knowledge | agent-authored from **external reference sources** | **untrusted data**; edges quarantined at birth | long-lived, shared | wrong knowledge informs a decision |

The kernel's graph reaches host state and policy-granted restricted areas — and does not bypass policy to do it. [Core principle 2](../AGENTS.md): *no role or privilege, not even the kernel, bypasses clearance*, which applies to the kernel's own graph as to everything else.

**The governance graph is schema-level, not a fourth instance.** A profile is a *predicate over graphs* — *"a node of kind `write` must have an adjacent node of kind `verify`"* is a subgraph pattern matched against a plan. Expressible as a graph of required patterns, but a schema artifact rather than an instance. **Three instance graphs and one pattern artifact** is the cleaner count.

**Shared substrate, separate vocabularies.** `(write) --verifies--> (test)` and `(stig-rule) --implements--> (vendor-paragraph)` have nothing in common at vocabulary level, and one vocabulary spanning both would fit neither. What they share is the *substrate*: node identity, typed edges, provenance fields, versioning, serialization.

### 5.1 The crossings are the design; the graphs are the easy part

**Information crosses up the trust gradient only through validation; authority only ever flows down.**

- **lake → plan.** Knowledge informs planning under measured access; legitimate, because the plan is still validated against its profile afterwards. **But the validator must never consult the Lake** — that would let ingested content decide what counts as a valid plan, which is untrusted data setting policy.
- **plan → kernel activity.** One-way. The kernel may read a plan to execute its verify nodes; a plan may never write the kernel's graph.
- **profile → plan.** Constrains; never populates. A profile that supplies nodes is authoring plans, not judging them.
- **plan → shared knowledge.** **No content; demand crosses.** A task hitting a knowledge gap becomes a *request*, and what enters the Lake is an external document from an authorized source — never the user's work product. See §8.

### 5.2 Unattended activity is a second consumer

The same model tracks activities the platform itself runs — scheduled work of the kind OpenClaw or Hermes Agent perform outside an operator engagement. It stresses the design differently:

- **Long-lived and partially executed.** Node state (pending / running / succeeded / failed / escalated) is part of the artifact, must survive restart, and is what an operator inspects on return.
- **Nobody is watching.** Platform-executed validation matters more, not less, and bounded retry with an escalation terminal stops being pedantic: an unattended back-edge with no bound is an unattended infinite loop.
- **State transitions over a validated graph are an audit trail by construction**, aligning with [ADR-0019](adr/ADR-0019-audit-record-model.md) rather than requiring a parallel record.

**It is also where two-phase authorization earns its shape.** A scheduled graph may outlive the profile and policy that validated it. Phase one validated the *shape* at authoring; phase two evaluates each node **against policy at the moment of execution**. A node authorized last week is not authorized now by having been authorized then.

### 5.3 One conflict to resolve

Plan graphs are ephemeral with declared retention; their node-state transitions are an audit trail under ADR-0019. **Both cannot govern the same artifact** — a user declaring zero retention would otherwise delete the record of what the agent did on their behalf. Either the execution record is a separate kernel-retained object referencing the plan, or the plan is audit-retained and only its payload is subject to user retention. Maintainer call.

---

## 6. Schema and profile — and validation as an activity

Two artifacts are being defined, with different authority and different change rates. Collapsing them into one "graph format" is how the thing becomes unbuildable. **There is no third artifact for proving work happened** — see §6.3.

### 6.1 Schema — the vocabulary

What node kinds and edge kinds exist and what fields each carries. Compiled in. Changes rarely; breaking it invalidates every stored graph.

**The schema carries a floor: elements no profile may drop.** Otherwise "the organisation defines the profile" includes defining one that requires nothing, and the mechanism silently becomes optional. The construction is already in hand — ADR-0008 decision 1 makes the ceiling operand a **named, non-removable field** of the `Composition` rather than something configuration opts into.

### 6.2 Profile — the required-elements set

What a graph must contain to be correct. `tdd` requires a `verify` node between every test and the implementation it constrains, and a gate before every commit or a declared deferral. `straight` requires far less and is a legitimate choice. `docs-only` requires neither tests nor gates but does require a citation on every claim-bearing node.

**One vocabulary, several policies over it, deny-by-default: a graph with no declared profile does not validate.** This is the separation the kernel already makes between the seam's vocabulary and the policy evaluated across it — and the policy is the part that legitimately varies, which is [ADR-0004](adr/ADR-0004-modular-authorization-architecture.md)'s test for when to modularize at all.

**A profile is a well-formedness contract, not an authorization input.** It is [core principle 2](../AGENTS.md)'s *inform-but-not-authorize* one layer up: a profile can make a plan **invalid**; it can never make a node **permitted**. A graph may satisfy its profile completely and still have every node denied at execution. **Validity is necessary and never sufficient**, and the two surfaces must not collapse, or a locally-authored file becomes a path to a grant.

**Where a profile lives.** `config.d/` — not `conf.d`; nothing scans the latter. The existing custody rule is why that surface is right: a `config.d/` member must be **root-owned and not group/other-writable, and so must the directory**, or boot refuses with `SectionNotRootOwned`. A profile inherits the property it needs — **the subject a plan executes as cannot choose the profile it is judged against.** Per-role assignment is then an ordinary `maknae-authz-basic` binding.

**The split follows [ADR-0022](adr/ADR-0022-classification-policy-as-data.md)'s precedent: schema compiled in, profile boot-selected** — as the level order ships in the kernel while the declared system is chosen at boot. [ADR-0002](adr/ADR-0002-kernel-is-rust.md)'s no-runtime-patchable-policy rule is untouched: a boot-read profile is configuration in the sense `authz.yaml` already is.

**Profiles validate at boot, against policy.** Two failure classes, and the second earns the check:

1. A profile that does not parse — ordinary configuration refusal.
2. A profile that is well-formed but requires an activity policy denies — a genuine conflict between two authored artifacts, caught at startup rather than at 2am.

*Recommendation, not a ruling:* **refuse boot on any invalid profile, not only the last one standing.** A partially-loaded set makes the enforcement posture depend on which file happened to be malformed, and an operator who fixes one typo gets a posture they do not believe they have. The counter-argument is real — in a many-profile organisation, all-or-nothing boot creates pressure to disable validation — and the decision is the maintainer's.

**Profiles are typed by task** — `company-TDD` for a coding task, `company-PP` for a slide deck. **The selection step is where a hole opens: if the agent declares its own task type, the agent selects the profile it is judged against.** That is the `config.d/` custody rule reopened at point of use, and it is what principle 2 already forbids in another form — *access is decided by the reference monitor, not by prompt-level markers or content self-labeling.* **A task declaring its own type is self-labeling.** The mapping is configuration on the trusted side, and an unmapped task type fails closed rather than falling back to the least restrictive profile.

**Bins — take Jev's approach, invert its failure direction.** Classifying an incoming task to select the enforcement shape is sound. The hazard is documented in this repository: the [Jev assessment](references/2026-09-22-system-one-models-jev-assessment.md) found a hosted, closed, remotely-versioned probabilistic classifier whose calibration claim no outside party has tested. A classifier choosing which profile applies means a misclassification **silently changes how much rigor is enforced** — self-labeling again, with a model standing in for the agent.

The inversion: **a classifier may propose a bin; it may never relax one.** A bin resolves to a profile only when the mapping is configured and confidence clears a declared floor; otherwise the task takes the **most** restrictive profile available. **A classification failure must cost rigor, never remove it.** A misclassified slide deck is then merely annoying; a misclassified coding task cannot quietly escape the organisation's TDD profile. The failure direction, not the accuracy, is what makes an untested classifier tolerable in the loop.

### 6.3 Validation is an activity in the graph, not a record about one

**A verifying activity node sits directly downstream of the activity it verifies.** The guarantee is not *"produce proof you did it"* — it is *"you cannot reach the next node without traversing this one."*

**This deliberately replaces a per-node evidence record.** A captured command, expected result and actual output, bound to each node, is the negative-test harness with a schema on it — and that harness is tolerated today only because agents have been caught reporting actions they did not take. Remove the self-report and the harness has no job. Structure does what evidence was being asked to do.

**Two properties are needed together, and either alone fails:**

1. **Adjacency makes the activity unskippable.** The graph does not permit reaching the next node without the validating one.
2. **The platform executes the validating node, not the agent.** Adjacency alone proves *traversal*, never *honesty* — if the agent runs the check and announces the outcome, the arrow changes nothing and this is the markdown checkbox with an edge drawn on it. When the platform executes it and the exit status drives traversal, the agent is not party to the decision. **Failure does not travel back along an edge** — see §6.5.

**This is where the graph-call primitive from the [Jive assessment](references/2026-09-25-jive-assessment.md) stops being a token optimisation and becomes load-bearing** — a runtime that walks the graph without returning to the model is what makes property 2 true.

Property 2 has independent support from a direction unrelated to security — see §12: the loop-engineering literature reaches the same conclusion from quality, and reports that **making the generator more self-critical does not work** where a separate skeptical evaluator does. *"A loop without a real check is, at bottom, an agent repeatedly reaching consensus with itself."*

**The trust regress terminates at the TCB, as it already does.** At some point the platform resolves to OS primitives that have been permitted; risk surface cannot be removed entirely. This is [ADR-0005](adr/ADR-0005-enforcement-locus-tcb-boundary.md)'s boundary, not a new one. What matters is that validation executes on the trusted side of a line this project already draws: [core principle 1](../AGENTS.md) holds the agent runtime untrusted by design, so **an agent-executed validation asks the untrusted side to attest to itself.**

**One constraint for expressibility:** the verifying relation is **its own edge kind**. If any edge satisfies "the validation is connected to the activity", an ordinary `write → commit` dependency satisfies it trivially. A `verifies` edge names its subject.

*(Two further constraints appeared in an earlier draft — that retry needs a distinct edge kind excluded from the acyclicity pass, and that the back-edge needs a bound and a terminal. Both are superseded by §6.5: **there is no back-edge.**)*

**"A single edge" reads as adjacency, not cardinality.** Adjacency forbids `set-permissions → commit → check-permissions`, where the validation is real but arrives after the irreversible step. Cardinality remains *at least one*: one `cargo test` legitimately verifies several writes.

### 6.5 Recovery is per-node state, not a graph edge

Reading [SGH](https://arxiv.org/abs/2604.11378) in full replaced this document's retry design with a better one. **The failure path is not an edge.** Each node carries a recovery state, `pristine → retried → patched`, and a **three-level escalation ladder**:

| level | action | precondition |
|---|---|---|
| 1 | **local retry** | node is `pristine` |
| 2 | **local patch** — re-run with adjusted configuration | node is at least `retried` |
| 3 | **request replan** — a new plan *version* | **every** failed node is at least `patched` |

**Skipping levels is prohibited, and the prohibition is mechanical rather than normative.** The recovery layer exposes exactly three entry points and enforces the order as an API precondition — `attempt_patch` is rejected unless the node is `retried`, `request_replan` is rejected unless all failed nodes are `patched`. An implementation that respects the API boundary cannot violate the invariant; one that mutates node state directly is outside the guarantees, *"analogous to unsafe blocks in type-safe languages."*

**Three things this fixes here.**

- **The DAG stays a DAG.** No retry edge kind, no exclusion from the acyclicity pass, no rule-one-contradicts-rule-two. A cleaner design that removes machinery rather than adding it.
- **The fan-in ambiguity dissolves rather than being solved.** §4.7 asked which of five predecessors a failing join returns to. The answer is *none*: an `all_of` join becomes ready only when every predecessor reaches `executed`, and a failed predecessor climbs its **own** ladder locally. Recovery is local to the node; the join simply waits.
- **Level 2 is the rung this document had missed entirely.** It had retry and escalate-to-human. Without *patch*, every non-transient failure jumps to replan — which is precisely the "premature replanning" the survey reports alongside infinite retry as the two observed failure modes.

**And the control §15.4 needed.** The diagnoser that classifies a failure operates on a **diagnostic context, not the execution context** — *"diagnostic reasoning does not leak into the execution path, a property that is critical for auditability."* That is context separation between deciding-what-went-wrong and doing-the-work, and it maps directly onto Maknae's trust split. Re-planning stops being an open door: it is Level 3, gated on an exhausted ladder, producing a new plan version rather than mutating a running graph.

A diagnosis is recorded as `(observed failure, root-cause hypothesis, recommended action, confidence)` — the confidence term connecting to §6.2's bin floor.

### 6.6 Side-effect classification — the property this design lacked entirely

SGH's fourth principle, and it is the most useful thing read this session: **classify every node by side-effect profile, and let the scheduler respect the classification.** *"A read-only API call can be freely retried; a database write cannot."*

This document treated all nodes as equally retryable and equally parallelisable. They are not, and the consequences are two:

1. **Retry budgets differ by side-effect class.** Re-running a `read` is free. Re-running a half-completed `write` is a second, different edit — which is exactly §15.3's non-idempotency problem, and side-effect classification is the mechanism that contains it rather than merely naming it.
2. **High-side-effect nodes may not be speculatively dispatched in parallel** — a constraint **orthogonal to §4.7's file-conflict rule**. Two `commit` nodes with disjoint file scope still must not run concurrently. File conflict and side-effect class are two independent gates, and §4.7 only described the first.

**The vocabulary is nearly free.** The activity classes already proposed — `read`, `write`, `test`, `verify`, `gate`, `commit` — map almost directly onto a side-effect profile, so this is a floor property (§6.1) rather than new machinery. It should be in the floor and not in an organisation's profile: irreversibility is not a discipline preference.

### 6.7 State the expressiveness boundary

SGH publishes what its design gives up — competitive parallelism, recursive sub-graph expansion, dynamic topology change, parent-chain rollback — and argues the boundary is appropriate rather than universal. **This document should do the same, and a reviewer will ask for it.** Notably it excludes speculative "first of" joins for the reason §4.7 raised independently: cancelling losers mid-execution requires compensation protocols for partial results. They declined the feature rather than solving it, which is a live option here too.

### 6.8 The two phases

**Phase one reads schema + profile** — is this graph well-formed, and does it satisfy its declared discipline. **Phase two runs at execution** — each node is authorized against policy at the moment it is reached, and the validating nodes the profile required are executed by the platform as the graph is walked.

---

## 7. The knowledge graph

Two bodies of work bear on it, and neither transfers whole (ruling 5). Both are cited as **provenance, never authority** — the Lake is a separate project and its decisions do not bind this repository, per the [ADR README doctrine](adr/README.md). The in-repo rule either must satisfy is *inform-but-not-authorize*, which stands on its own.

**The [KLC](knowledge-lifecycle-contract.md) governs objects. The Lake's shipped model governs relationships.** The KLC is not current here — it predates having an edge model, so it has no answer to *who may assert a relationship*. The Lake has no answer to *a classified corpus*.

| dimension | KLC (in-repo, object layer) | Lake graph model (shipped, relationship layer) |
|---|---|---|
| unit of governance | the **object** — tier, label, provenance, hash, per document | the **edge**, a first-class authored artifact with its own schema |
| vocabulary | authority tiers, domains, bands, natures | six relationship types |
| who may write | the agent **may** ingest: gap → fetch → quarantine at tier 3 | the agent writes **nothing**; one operator-authored surface |
| provenance | stamped per object at ingest, with hash | **none per edge** — the tracked file and its git history |
| enforcement point | policy hooks at retrieval and output | schema validation and compiler rejection at build time |
| integrity construction | the kernel is the integrity root for label state | `writer == checker`: the committed artifact byte-equals a fresh compile |
| classification | MLS, ceilings, no-read-up / no-write-down, high-water marks | **absent** — an unclassified corpus |

**Three things fall out.**

1. **They disagree about agent authorship.** Ruling 3 settles it toward the KLC's posture — agents may author and ingest, scoped to the Lake.
2. **Provenance is needed exactly where authorship is delegated** (ruling 4). The Lake needs no per-edge field because it removes the antecedent: edges never arrive from outside. Under ruling 3 Maknae cannot, so **per-edge provenance is mandatory here** — who asserted it, from what source, at what authority basis, when. *"The git history is the provenance"* stops working when the author is not a human making a reviewed commit.
3. **A knowledge graph under a classification ceiling needs labels on nodes *and* edges**, because a relationship between two unclassified documents can itself be classified. That is the aggregation problem, and neither source document addresses it.

### 7.1 What the Lake's model gets right, and is worth copying

From `references/lake/edges.yaml`, `edges.schema.json` v1 and `lib/lake/_edge_graph.py`:

- **A closed edge vocabulary of six:** `supersedes`, `implements`, `governs` (directional), `companion`, `relates_to` (symmetric), `delegates_to`. `additionalProperties: false` and a `const` `schema_version` throughout — fail-closed, not advisory. A seventh type was **YAGNI-deferred by census**, not by taste: one case in the corpus did not earn a vocabulary entry.
- **Targets are opaque UUIDs and the pattern enforces it.** The regex *structurally rejects* a filename-valued target. The sharpest transferable idea in the model: **the schema forbids the wrong thing rather than documenting that it is wrong.** This is not taste — see §12, finding F9: four published KG-RAG systems key nodes on surface forms and none imposes a stable identifier at index time, and the Lake itself already retired one filename for the same document, which would have silently dangled any edge targeting it.
- **One authored direction; the compiler materializes the typed inverse.** Symmetric edges are authored once on a **deterministic canonical side**. An authored surface that cannot express one fact two ways cannot drift between them.
- **Derived artifacts are drift-gated by byte equality** (`writer == checker`) — the construction this repository already uses for content-keyed drift gates.
- **Deterministic ids:** `uuid5(NAMESPACE_URL, "urn:lake:external:<slug>")`, so independent builds agree on identity.
- **External stub nodes** let an edge point at an authority the corpus does not hold, `source_url` required — a reference that does not pretend to be a holding.
- **The compiler rejects self-loops and duplicate authored edges** at build time.

**The disciplined exception to "a graph has no field for prose":** `delegates_to` **requires** a `scope_note` of at least 8 characters. Exactly one edge type — the one whose relationship is meaningless without saying what was delegated — carries a mandatory note. **That is the shape to copy: not "no prose ever", but prose only where the schema makes it non-optional.**

Under ruling 3 the `writer == checker` gate does not survive unchanged: with a growing agent-authored set the invariant becomes *a recompile of the current authored set is deterministic*, not *matches a committed golden*. Still a real gate, a different one.

### 7.2 Where the model needs extending

*"This STIG rule is implemented by this vendor product at this paragraph"* is an `implements` edge, but the shipped model keys edges to **document ids**, not to a paragraph within one. Sub-document anchors are a real extension and a hard one, because an anchor must survive the document being reissued.

---

## 8. The governed learning loop

Ruling 3 permits agent authorship into the Lake. The [OV-1](diagrams/generated-operational-concept.svg) states how, in six steps:

| | step | plane | what it establishes |
|---|---|---|---|
| 1 | tasked work | runtime, **untrusted** | the agent hits a knowledge gap while doing real work |
| 2 | **request, never act** | **trust plane** | *"The runtime cannot perform a lifecycle transition. It may only ASK for one."* |
| 3 | **fetch — authorized sources only** | **trust plane** | *"The egress allowlist is the operator's signed authority map. A source not on it is denied."* |
| 4 | quarantine | Tier 3 | all new knowledge — ingested, generated or demoted; may inform work, may not authorize a privileged action |
| 5 | promote, one tier per gate | trust plane | 3 → 2 → 1 on corroboration or operator sign-off; **automation can never raise a ceiling, and there is no path from Quarantine to Doctrine** |
| 6 | authoritative | Tier 1 | applied to the next task |

**Step 2 is why the demand crossing in §5.1 is safe**, and it is the same boundary relied on everywhere else. The untrusted runtime does not fetch. It asks; the trust plane decides and acts. A user's task can therefore drive ingestion into a shared corpus without the user's graph ever being a content source.

**Step 5 answers how an agent-authored edge is confirmed:** corroboration or operator sign-off, one tier at a time, never to Tier 0.

**A pre-authorized source list does three jobs, not one.** The Lake's `references/lake/vendors.yaml` is the worked example — per-vendor authorized URLs, `apache` → `apache.org`, `httpd.apache.org`, `tomcat.apache.org`:

1. **Security** — a search can be steered to attacker-controlled content; an allowlist keyed to the vendor's own domain cannot.
2. **Legal exposure** — a search can land an *automated* fetcher on a trap or illegal site. An allowlist is the only form of this control that works without a human reading each result.
3. **Authority basis** — the source determines how far content may be promoted. *"Found on the web"* has no tier.

**One channel remains, named honestly:** gap detection fires during a user's task, so which document gets fetched is shaped by that user's work. The content is public; the fetch pattern is not necessarily. That is traffic analysis rather than content leakage — and because step 3 puts the egress in the trust plane against a signed allowlist, it runs through the one place designed to observe and bound it.

**The implication for the plan graph.** The allowlist is a profile rule with a natural home: a plan node that fetches must name its source, and **a fetch node whose source is not allowlisted is an invalid graph** — refused at validation, before execution. Phase-one authorization doing exactly the work it was proposed for, composing with the runtime check rather than replacing it.

**The OV-1's own status line belongs here:** the trust plane is **BUILT**; the Lake, skill registry, tier state machine and promotion pipeline are **NOT YET**. *"The kernel that makes the loop safe is substantially real. The loop is not."*

---

## 9. What this means for skills

### 9.1 The mechanics, observed

The harness scans the skill directories, injects **only** each skill's `name` and `description` as a menu, and injects a full body **only after the model calls the skill tool**. The body is markdown that nothing validates and nothing executes. Its entire effect is that a model reads it and chooses to comply.

**Evidence that the format is convention, not capability:** this workstation carries the same skill set under `~/.claude/skills/` and `~/.codex/skills/` — copied directories, identical `SKILL.md` shape, running unmodified under two independent vendors' harnesses. That portability exists precisely *because* nothing enforces the format.

| layer | owner | available to Maknae |
|---|---|---|
| file format, discovery | harness | fully — define anything |
| injection: when, how much, in what order | harness | fully, and a large lever |
| **selection** — which skill applies | **model** | the soft spot |
| **compliance** — whether it is followed | **model** | the crux |

**Both holes in the graph design already exist in `SKILL.md`; they are simply unnamed there.** Selection-by-model is the same self-labeling hole as task-type-declared-by-agent. Compliance-by-model is the unchecked checkbox.

**What the labs control is the prior, not the protocol.** Any format can be defined and served; what cannot be done is make a model fluent in a format it has never seen. Models are tuned toward conventions in circulation, so a radically novel encoding is followed *worse* even when better designed. **Let the graph be the enforcement artifact and render it to the model in a shape models are already fluent in** — the platform validates the graph; what reaches the context window may still be ordinary imperative text generated from it.

### 9.2 A skill is two artifacts wearing one file

- **Knowledge** — what a Fleet bundle is, an RE2 relabeling idiom, how CNSSI 4009 separates policy type from decision model. Prose is correct; there is nothing to enforce.
- **Obligations** — "write the test first", "watch it fail", "commit". **Profile rules in prose clothing.**

The authoring skills are already a profile, written in English with no enforcement:

| skill prose | the graph element it is |
|---|---|
| "Run it to make sure it fails" / "MANDATORY. Never skip." | a required `verify` node between test and implementation |
| "Expected: FAIL with 'function not defined'" | the validating node's pass condition |
| "**Files:** Create / Modify / Test" | declared file scope, with intent |
| "**Interfaces:** Consumes / Produces" | typed edges between task nodes |
| "No Placeholders — no TBD, no 'add error handling'" | a validator rule rejecting empty-deliverable nodes |
| "Each step is one action (2–5 minutes)" | a node-granularity constraint |
| "one at a time, test each" | an ordering constraint |

**Every one is prose whose only function is to make an agent take an activity later — which makes it an activity node, or a rule about one.** It also explains a property of those files: they are long, repetitive and heavily capitalised because **prose has no enforcement and compensates with volume**. A rule that is checked does not need to shout.

The split is forced rather than tidy: principle 1 holds the agent runtime untrusted, so **an obligation enforced by the agent is not enforced.** The answer to *"LLM or platform?"* follows from the posture already adopted — **the platform enforces obligations; the model consumes knowledge.**

---

## 10. What follows for post-Cooky work

1. **Plans are authored as graphs, not converted into them.** The fix for §4.4 is not a better parser — it is that the prose the parser was reading should never have been written.
2. **The schema is the artifact.** The node contract: id, activity class set, dependencies, **declared file scope with intent**, **declared plan-level conventions**, an issue citation in place of justification, and a payload split into instruction / deliverable / expected output.
3. **Scope rules belong to the plan, not only the task.** A check that knows one and not the other is wrong at every boundary.
4. **Do not claim size reduction.** Disclosure cost and storage cost move in opposite directions on code-heavy plans.
5. **The consumers are distinct and must not be conflated.** A plan graph for the development process is a Claude Code authoring concern. A task graph inside Maknae's runtime loop is a kernel-authorization concern under [ADR-0023](adr/ADR-0023-runtime-loop-role-and-placement.md), where the planner is untrusted by design and a node's activity class is a PDP input rather than a reader's convenience. This experiment gathered no evidence for the second.

## 11. If this becomes a Claude Code skill

The skill's job is **authoring plans into the schema against a declared profile**, not converting them afterwards: emit the shape layer as the plan is written, require an explicit activity-class set per step, require each task to declare its file scope, reject a step that parses to nothing rather than emitting an empty node, and run the structural checks as a self-review gate before the plan reaches the maintainer. The checks that earned their place are cycles, orphans, TDD ordering, and plan-scoped file references. Gate-before-commit belongs to the profile rather than the checker.

A cheap partial answer to validity-versus-correctness, taken from BatchDAG: **probe before fan-out.** Execute one instance of a parallel group and check its result before dispatching the rest, so an incorrect plan costs one branch rather than five.

**The harder half is execution.** A skill that only *emits* a conformant graph has moved the checkbox, not removed it. The validating nodes have to be run by the platform walking the graph, not by the agent reporting on itself — and that half is a Maknae concern, not a skill-authoring one.

## 12. What the research corpus supports, and what it does not

The Knowledge Lake's `research/` corpus holds twenty ingested papers and industry guides with a findings synthesis (`design/research-retrieval-architecture.md`, F1–F13). It is **tier-less and non-authoritative by its own declaration** — it binds nothing and is excluded from that project's authority map. Cited here as evidence and as provenance, never as authority.

**The honest scope first: most of this corpus is about *retrieval* graphs, not activity graphs.** It bears directly on §7 and only by analogy on §4–§6 — which is the same caveat the synthesis carries about its own domain transfer. The one exception is the loop-engineering material, which is directly on point.

### Supports the knowledge graph (§7)

- **F5 — typed first-class edges are required, and generic graph structure is not enough.** VersionRAG: *"version transitions are not explicit relationships that can be extracted from text; they must be modeled as first-class citizens."* Generic GraphRAG scored ~10% on implicit supersession detection against a purpose-built version-aware graph's ~60%. **The synthesis's own caveat travels with this and must not be dropped: those magnitudes are self-reported on a 100-question author-built benchmark. The structural claim is independent of the contested numbers; the numbers are not settled.**
- **F4 — similarity-only retrieval structurally fails on supersession**, reaching 58–64% on version-sensitive questions because it has no temporal-validity or authority check and returns several versions at once. This is the Maknae use case exactly: STIG revisions and reissued DoD policy.
- **F9 — the opaque-identifier rule is an evidence-based correction, not a preference.** GraphRAG, HippoRAG, HippoRAG 2 and LightRAG all key nodes on LLM-extracted surface forms; none imposes a stable opaque id at index time, and all treat name-based merging as an acknowledged unsolved problem. The Lake retired `DoDI-8140-02.md` in favour of `814002p.md` for the same document — any filename-targeted edge would have dangled silently. §7.1 praised the uuid regex as good instinct; it is better than that.
- **F1–F3 — graphs are not universally better, and a discipline this document has been missing.** Vector retrieval wins single-hop and detail questions; graph wins multi-hop; **hybrid routing beats either alone**, and GraphRAG-Bench exists partly to document where graph retrieval *underperforms*. Nothing here argues for graph-always, and the knowledge graph should be a routing decision rather than a replacement.
- **F10** — in the closest domain analog (regulatory-compliance KG-RAG), graph re-ranking was the single largest quality contributor.

### Supports the execution model (§6.3), and from an unrelated direction

The Orange Book's **generator-and-evaluator** chapter reaches this document's conclusion from quality rather than from security, which makes it genuine corroboration rather than the same argument restated:

- An Anthropic engineer's finding, quoted there: agents asked to evaluate their own output *"tend to respond by confidently praising the work — even when, to a human observer, the quality is obviously mediocre."*
- **And the attempted fix that failed:** making the generator more self-critical did not work; *"tuning a standalone evaluator to be skeptical turns out to be far more tractable."* **So the remedy is structural, not behavioural** — which is precisely §6.3's property 2, arrived at independently.
- *"A loop without a real check is, at bottom, an agent repeatedly reaching consensus with itself."*

Its **four costs** map onto decisions already taken here, with one that is not:

| cost | the guide's guard | where it lands |
|---|---|---|
| verification debt | *install an evaluator that isn't the one doing the work* | §6.3 property 2 — platform-executed validation |
| token blowout | *nail down budget and retry caps **before shipping*** | §6.3 constraint 3 — and "before shipping" argues the bound belongs in the **floor** (§6.1), not an organisation's profile |
| cognitive surrender | *execution can be outsourced, deciding can't* | [`self-development.md`](self-development.md)'s standing ruling, unchanged |
| **comprehension rot** | *read the output regularly; can't explain it means update it* | **a cost this proposal adds to, and does not yet answer** |

**Comprehension rot is the honest one.** §1's objective is to delete prose *about* the task, and a graph of activities is by construction less readable to a human skimming for *why*. The design's answer is the issue citation in place of justification (§10.2) and the `delegates_to` pattern of one mandatory note where the relation is unreadable without it (§7.1) — but that is an argument, not a measurement, and the guide's warning is that this cost sounds no alarm while the loop is running.

### Converges with the shape/payload split from a third direction

Gorilla, ToolLLM and RAG-MCP all reach *"retrieve the relevant tools rather than registering all of them"* from the tool-selection side. **The 1.8% shape layer is the plan-graph instance of a pattern that literature already validated elsewhere** — which is mild independent support that progressive disclosure is the right axis, and none at all for any particular encoding.

### What it does not support

- **No evidence here bears on activity or plan graphs as such.** The transfer from retrieval graphs to §4–§6 is by analogy.
- **No evidence on the authoring mechanism.** The synthesis's own open question 2 asks whether authored-edges-compiled-into-a-graph is endorsed over LLM-extracted edges; the literature validates explicit edges over inferred ones but does not evaluate *who authors them*. Ruling 3 is therefore a decision, not a finding.
- **No storage-backend guidance.** Explicitly under-evidenced in the synthesis, and flagged there as needing dedicated follow-up.
- **SoL-Pi's caution transfers directly to profiles:** an evolved harness can **overfit the tasks used during search**, which is why held-out evaluation is load-bearing. A profile tuned on one team's plans is a harness tuned on one task set.

## 13. Where the labs are

Asked directly, because it decides how much of this is ours to invent.

**No lab has published a position on graph-structured plan governance.** What exists is product and pattern guidance:

- **Anthropic** is the nearest thing to a stated position. [*Building effective agents*](https://www.anthropic.com/engineering/building-effective-agents) names five composable patterns — prompt chaining, routing, parallelization (sectioning and voting), orchestrator-workers, and **evaluator-optimizer** — and draws the distinction this document has been circling: **workflows are systems where LLMs and tools are orchestrated through *predefined code paths*; agents are systems where the model directs its own process.** A validated plan graph is squarely the first. **And the guidance cuts against us:** the finding is that the most successful implementations used *simple composable patterns rather than frameworks*. We are proposing a framework.
- **OpenAI** ships AgentKit and Agent Builder — visual workflow graphs — and an orchestration spec. Product, not position.
- **Google** ships an orchestration surface in Antigravity 2.0. Product, not position.
- **The intellectual work is academic and framework-side.** LangGraph is the de facto standard implementation, and the 2026 arXiv literature carries the reasoning: [*From Agent Loops to Structured Graphs*](https://arxiv.org/abs/2604.11378) (scheduler-theoretic, position paper, no empirics), [*Atomic Task Graph*](https://arxiv.org/pdf/2607.01942), [*Plan-over-Graph*](https://arxiv.org/pdf/2502.14563), [*BatchDAG*](https://arxiv.org/abs/2607.18241), [*Architecting Resilient LLM Agents*](https://arxiv.org/pdf/2509.08646), and a survey of the shift [*From Static Templates to Dynamic Runtime Graphs*](https://arxiv.org/pdf/2603.22386).

**The takeaway is not comfortable: the field is converging on graph-structured execution, the labs are selling it as tooling rather than arguing for it, and the one lab that has argued anything cautions against the framework we are designing.** The governance layer — profiles, floors, validation as authorization — is genuinely ours, which means it also has the least external support.

## 14. What holds up

Recorded before the adversarial read so the document is not mistaken for a retraction. Three tiers, by what supports each.

### 14.1 Independently confirmed by outside work

- **Typed, first-class edges beat inferred relationships.** The best-supported claim in this document and the foundation of both graph families. F5's structural finding — *"version transitions are not explicit relationships that can be extracted from text"* — is independent of its contested magnitudes, and F4 puts a number on the failure it prevents: similarity-only retrieval reaches 58–64% on version-sensitive questions. Our `verifies` and `commit-with` edges are the same argument applied to activities.
- **Stable opaque identifiers, not surface forms.** Not merely correct — correct *where the state of the art is not*. GraphRAG, HippoRAG, HippoRAG 2 and LightRAG all key on LLM-extracted surface forms and all treat name-based merging as unsolved (F9). The Lake imposed opaque ids anyway and has a concrete near-miss proving the point.
- **Separating the evaluator from the generator.** **Two independent derivations converge here, which is the strongest support available short of a benchmark.** This document reached it from security — the agent runtime is untrusted, so it cannot attest to itself. Anthropic reached it from quality — agents confidently praise their own output, and *making the generator more self-critical did not work* where a separate skeptical evaluator did. Anthropic also names **evaluator-optimizer** as one of five composable patterns.
- **Parallelism from declared dependencies.** Plan-over-Graph [R4], LLMCompiler [R10] and BatchDAG [R2] all do exactly this; the maintainer identified it independently while reading a draft. §15.5 disputes the *magnitude* transferring to our workload — it does not dispute the structure, which is field-standard.
- **The category itself.** Anthropic's distinction — *workflows are LLMs orchestrated through predefined code paths; agents direct their own process* — is precisely what a validated plan graph is. We are not inventing a category, and the field is moving this way: a 2026 survey is titled *From Static Templates to Dynamic Runtime Graphs*.
- **Plan-then-execute is a real security property, correctly bounded.** Separating planning from execution gives control-flow integrity against indirect prompt injection. Our caveat that it is insufficient alone is also the source's caveat, and Maknae already supplies the defence in depth it asks for at phase two.
- **Progressive disclosure over loading everything.** Gorilla, ToolLLM and RAG-MCP converge on *retrieve the relevant tools rather than registering all of them*. The 1.8% shape layer is that pattern applied to plans.

### 14.2 Established by our own measurement

Weak provenance (§16.1) — but these are real results, and **the experiment earned its keep by refuting rather than confirming.** A measurement that only agreed with its author would deserve less trust, not more.

- **The shape layer is 1.8% of the markdown**, and shape-plus-heaviest-node is 12%. Progressive disclosure at that ratio makes whole-plan structural checks affordable on every plan.
- **Compression is not the win** — it refuted the obvious first claim, which was mine.
- **Inferred typing is not worth building on** — 23–33% unclassified and three false positives in five warnings. This is the result that produced the document's central design decision.
- **The straight line was an artifact of the format**, not of the work: 89% of ceiling's task pairs touch disjoint files while the conversion produced a strict chain.
- **Two of five warnings were true structural facts** about real plans — gaps a prose reviewer had not caught.

### 14.3 Correct because it reuses settled doctrine rather than inventing

The security reasoning in this document is largely *not new*, and that is the point in its favour: deny-by-default, **policy over profile**, inform-but-not-authorize, the TCB as the terminus of the trust regress, the `config.d/` custody rule making a subject unable to choose its own profile, and ADR-0022's compiled-in/boot-selected split. **No new security model was invented for graphs.** Where this document does invent — the profile and floor construction (§16.2) — is exactly where it has the least support, and the two facts are related.

## 15. Adversarial read: what we are proud of that may be a pitfall

### 15.1 Fail-closed validation, on a checker measured wrong 60% of the time

Fail-closed is a core principle and it is right. But **the only structural checks ever run in this project produced three false positives out of five warnings** (§4.4). Fail-closed multiplied by an unreliable checker converts a checker bug into a work stoppage — and the failure is silent in the flattering direction, because a false positive looks exactly like discipline. In CI that is tolerable. For an interactive agent it is not. **Nothing in this document proposes how the checker itself earns trust**, and the negative-control gate's own logic applies: a validator that has never been observed wrongly rejecting a good plan proves nothing about its false-positive rate.

### 15.2 The structural guarantee is only as strong as the mediation — and it differs by consumer

*"You cannot reach the next node without traversing this one"* holds **only if the graph is the only execution path.** In Maknae it nearly is: every request transits the reference monitor. **In a Claude Code skill it is not at all** — the agent has a shell and can do the work outside the graph, then walk the nodes.

This document has been written as though one idea serves both consumers. It does not. **The same design is load-bearing in the kernel and decorative in the harness**, and §11 should be read with that discount applied. A skill can make a plan *checkable*; it cannot make an obligation *enforced*.

### 15.3 Retry back-edges were the anti-pattern — confirmed, and replaced

Read in full, [SGH](https://arxiv.org/abs/2604.11378) is stronger than the summary suggested. Its survey of **70 agent systems** found Agent Loop implementations *"commonly lacked any formal bounds on recovery attempts,"* producing two observed failure modes: **infinite retry** when the model insists on a failing approach, and **premature abandonment** when a transient error triggers an unnecessary replan. This document's design had the first hazard bounded and the second unguarded, because it had no Level 2.

**Resolved, not merely flagged:** §6.5 adopts the per-node recovery ladder and §6.6 the side-effect classification. The back-edge is gone.

**Its standing as evidence, unchanged:** a single-author position paper with **no empirical results** — it says so itself, offering *"a theoretical framework, a design analysis, and an experimental protocol—not a production implementation."* What it does have is a formal state machine with termination and soundness arguments and a 70-system survey, which is more than an opinion and less than a finding. **It is adopted here because its design is better reasoned than ours was, not because it is validated.**

### 15.4 Plan-then-execute's security value evaporates at the re-plan, and we never said who may author one

The control-flow-integrity argument — a validated plan resists indirect prompt injection because the actions are fixed in advance — holds while the plan is fixed. **Every failure path designed here involves retry or escalation, and none of them says who authors the revision.** If the untrusted runtime may re-plan, the injection surface reopens exactly when the system is already degraded. [*Architecting Resilient LLM Agents*](https://arxiv.org/pdf/2509.08646) states plainly that plan-then-execute alone is insufficient and requires defence in depth; Maknae has that at phase two, but **the re-plan authorship question is ours and is unanswered.**

### 15.5 The parallelism speedup is measured on work unlike ours

LLMCompiler's **3.7×** [R10] is on **I/O-bound** steps — web searches and API calls. A Maknae plan is Rust edits and `cargo test`, where the build serializes on the target-directory lock. Parallel branches would need separate worktrees or target directories, which is infrastructure nobody here has built. **§4.6's 89% file-disjointness is a real measurement; a speedup does not follow from it**, and this document should not be read as promising one.

### 15.6 A closed schema forbids the unanticipated case too

*"The schema forbids the wrong thing rather than documenting it"* (§7.1) is the right instinct and has a cost. The Lake kept its vocabulary minimal by **census** — a human counted the cases. Under agent authoring (ruling 3) there is no census, and the seventh edge type nobody anticipated becomes an authoring failure rather than a schema request.

## 16. Where we have little grounded fact

Listed so nothing here is mistaken for evidence.

1. **This experiment does not meet the standard this repository applied to Jive.** The [Jive assessment](references/2026-09-25-jive-assessment.md) §1 refused to treat that project's numbers as evidence because they were one author's runs of his own tasks against his own agent. **Every number in §4 is one author's conversion of his own plans, by a parser he wrote, checked by checks he wrote, n=2, no repetition, no independent review.** The same verdict applies: usable for a design read, disqualified as evidence.
2. **The profile and floor construction has no external support at all.** It is reasoned by analogy from the kernel's `Composition`. No published system governs plan graphs this way, successfully or otherwise.
3. **Agent authorship of knowledge edges is explicitly unevaluated** — the Lake synthesis's own open question 2 notes the literature validates explicit edges over inferred ones but does not evaluate *who authors them*. Ruling 3 is a decision, not a finding.
4. **Validity is not correctness, and only validity is checkable — now settled by reading the paper.** BatchDAG's 98.8% means **structural and schema validity**: 255 of 258 plans *"produced valid, executable DAGs"*, and the three failures *"contained schema errors (referencing non-existent columns)."* Nothing about answering the question correctly. Three further details matter and none is in the abstract:
   - **The denominator is conditioned.** 42 of 300 calls failed on API errors and were excluded. End-to-end the rate is 255/300 = **85%**.
   - **Validity degrades with structural complexity.** 100% on SQL-only and search-only categories; *"all three failures occurred on complex fan-out queries requiring multi-source joins."* Maknae's plans are the complex kind.
   - **Their limitations section states this document's §16.4 verbatim:** *"if the planner generates an incorrect DAG, the system executes the full fan-out before the error becomes apparent."* It is a real operational problem, not a theoretical worry — and they propose the mitigation §11 should adopt: **a probe phase that validates on a single batch first.** Run one instance of a fan-out and check the result before dispatching the rest.

   Provenance: single author, Brevian.ai, production self-report, n=12 queries, LLM-assisted drafting acknowledged. The architectural conclusion — *"for cross-entity analytical workloads, the LLM should plan, not execute"*, with four of six operation types requiring zero LLM calls — is independent support for §6.3's property 2.
5. **The typed-edge magnitudes are contested.** F5's 10%-versus-60% is self-reported on a 100-question author-built benchmark. The structural claim survives; the size of the effect does not.
6. **Comprehension rot is unmeasured** (§12), as is whether progressive disclosure actually reduces execution-time context (§17).
7. **No storage-backend evidence** for a structured graph layer, air-gapped or otherwise.

## 17. Open questions

- Does the payload split (instruction / deliverable / expected output) hold on a plan with large expected-output blocks, or does it just move the p90?
- Is an S-expression shape layer worth it over JSON once a schema exists? It won on tokens here; a schema-validated form may not need the margin.
- What is the minimum activity-class vocabulary? Seven were used ad hoc (`read`, `write`, `test`, `verify`, `gate`, `commit`, `decide`). Authoring at birth answers the fall-through rate; it does not answer whether seven suffice without a `misc` escape hatch — and a `misc` node is an unclassified node wearing a badge.
- Does a structurally-assessed plan actually reduce execution-time context, or does the executor load most payloads anyway? Unmeasured.
- How much of the 89% file-disjointness survives interface-dependency analysis? The measured figure is an upper bound on candidate parallelism, not a schedule, and the real number is unmeasured.
- Under parallel dispatch, is the retry bound per-branch or per-graph? Per-branch multiplies the worst case by the branch count; per-graph makes one unlucky branch starve the others.
- At a fan-in, how does a failing validating node name which predecessors it implicates? A single exit status cannot, and without it the retry target is ambiguous (§4.7).
- How many profiles are needed, and who authors one? A profile per team is governance; a profile per plan is a loophole.
- Where does a bin's confidence floor come from, and who may set it? A floor the classifier's vendor sets is not a floor.
- Does a long-lived scheduled graph hold node state **in** the artifact (no longer immutable) or **beside** it (the two can disagree)?
- If obligations move out of `SKILL.md` into a profile, what stops a skill restating them in prose anyway? A rule with two homes drifts — the failure this repository already records for comments and issue bodies.
- Should the knowledge graph be a routing decision rather than a default (F1–F3)? Nothing in this document currently asks *when not to use the graph*.
- A profile is a harness tuned on a task set. What is the held-out evaluation that stops it overfitting one team's plans?
- Comprehension rot: how is it measured? The design argues the issue citation carries the *why*; nothing tests whether a maintainer reading only graphs can still reconstruct it.
- §5.3's retention conflict.

*The plans measured are `2026-09-06-148-154-ceiling-composition.md` and `2026-09-10-276-strike-reserved-agent-token.md` in the maintainer's out-of-repo plan store, per the AGENTS.md rule that specs and plans never live in this repository. The conversion artifacts were throwaway and are not committed.*

---

## 18. References

**Why this section exists:** every claim above that rests on outside work is cited here with its holding location, licence and **reading state**. The next reader — human or agent — should not repeat a search that has already been done, and should be able to see at a glance which sources were actually read.

**Nothing here is authority.** Per the [ADR README doctrine](adr/README.md), external work is provenance. Sources marked *abstract only* have not been read beyond their abstract and must not be cited as though they had been.

### Held for this document

`~/claude-memory/maknae/references/_raw/` — study copies, SHA-256 anchored, index at `2026-09-25-graph-driven-activity-sources.md`.

| # | source | licence | read | cited in |
|---|---|---|---|---|
| **R1** | Hu Wei. *From Agent Loops to Structured Graphs: A Scheduler-Theoretic Framework for LLM Agent Execution.* [arXiv:2604.11378](https://arxiv.org/abs/2604.11378), 13 Apr 2026. **Position paper; no empirical results**; 70-system survey; formal state machine. | arXiv non-excl. | **full** | §6.5, §6.6, §6.7, §15.3 |
| **R2** | Anupreet Walia (Brevian.ai). *BatchDAG: LLM-Planned Execution Graphs for Scalable Ad-Hoc Analysis Over Enterprise Data.* [arXiv:2607.18241](https://arxiv.org/abs/2607.18241), 17 Apr 2026. Production self-report, n=12 queries. | **CC BY 4.0** | **full** | §11, §14.1, §16.4 |
| **R3** | Del Rosario, Krawiecka, Schroeder de Witt. *Architecting Resilient LLM Agents: A Guide to Secure Plan-then-Execute Implementations.* [arXiv:2509.08646](https://arxiv.org/abs/2509.08646). | arXiv non-excl. | summary | §14.1, §15.4 |
| **R4** | Zhang, Ma, Cao, Zhang, Zhao. *Plan-over-Graph: Towards Parallelable LLM Agent Schedule.* [arXiv:2502.14563](https://arxiv.org/abs/2502.14563), 20 Feb 2025. | arXiv non-excl. | abstract only | §4.6, §14.1 |
| **R5** | Zhang, Chen, Huang, Cui, Ji, Wang. *Atomic Task Graph: A Unified Framework for Agentic Planning and Execution.* [arXiv:2607.01942](https://arxiv.org/abs/2607.01942). | arXiv non-excl. | abstract only | §14.1 |
| **R6** | Feng, Xiang, Yang, Ma, Chen, Zhang, Huang, et al. *Graph Engineering in the Era of LLM Agents: From Individual Intelligence to System Intelligence.* [arXiv:2608.21156](https://arxiv.org/abs/2608.21156). | **CC BY 4.0** | abstract only | §13 |
| **R7** | Yue, Bhandari, Ko, Patel, Lin, Zhou, et al. *From Static Templates to Dynamic Runtime Graphs: A Survey of Workflow Optimization for LLM Agents.* [arXiv:2603.22386](https://arxiv.org/abs/2603.22386). | arXiv non-excl. | abstract only | §13, §14.1 |
| **R8** | Bei, Zhang, Wang, Chen, Zhou, Chen, Li, et al. *Graphs Meet AI Agents: Taxonomy, Progress, and Future Opportunities.* [arXiv:2506.18019](https://arxiv.org/abs/2506.18019). | arXiv non-excl. | abstract only | §13 |
| **R9** | Anthropic. *[Building effective agents](https://www.anthropic.com/engineering/building-effective-agents)* (engineering blog). Five composable patterns; the workflows-versus-agents distinction. | © Anthropic | **full** | §9.1, §13, §14.1 |
| **R10** | Kim, Moon, Tabrizi, Lee, Mahoney, Keutzer, Gholami. *An LLM Compiler for Parallel Function Calling.* [arXiv:2312.04511](https://arxiv.org/abs/2312.04511), 7 Dec 2023. Reports up to **3.7× latency**, 6.7× cost, ~9% accuracy over ReAct. | arXiv non-excl. | abstract only | §4.6, §15.5 |

### Held in the Knowledge Lake

Full text at `knowledgebase/research/`, with the findings synthesis at `knowledgebase/design/research-retrieval-architecture.md` (F1–F13). Read via that synthesis, not line-by-line, except where noted.

| # | source | cited in |
|---|---|---|
| **L1** | Huwiler, Stockinger, Fürst (ZHAW). *VersionRAG.* [arXiv:2510.08109](https://arxiv.org/abs/2510.08109). **F5/F4** — typed first-class edges required; 58–64% ceiling for similarity-only on version-sensitive questions. *Magnitudes self-reported on a 100-question author-built benchmark.* | §12, §14.1 |
| **L2** | Xiang et al. *When to use Graphs in RAG (GraphRAG-Bench).* [arXiv:2506.05690](https://arxiv.org/abs/2506.05690), ICLR 2026. **F3** — when graph retrieval underperforms. | §12 |
| **L3** | Han, Ma, Wang, Aggarwal, Tang, et al. *RAG vs. GraphRAG.* [arXiv:2502.11371](https://arxiv.org/abs/2502.11371). **F1–F2** — hybrid routing beats either alone. | §12 |
| **L4** | Edge et al. (Microsoft). *From Local to Global: A Graph RAG Approach.* [arXiv:2404.16130](https://arxiv.org/abs/2404.16130). **F9** — surface-form keying. | §12 |
| **L5** | Jiménez Gutiérrez et al. (OSU NLP). *HippoRAG* [arXiv:2405.14831]; *HippoRAG 2* [arXiv:2502.14802]. **F9**. | §12 |
| **L6** | Guo et al. (HKUDS). *LightRAG.* [arXiv:2410.05779](https://arxiv.org/abs/2410.05779). **F9**. | §12 |
| **L7** | Guo, Wu, Yiu. *ComplianceNLP.* [arXiv:2604.23585](https://arxiv.org/abs/2604.23585). **F10** — graph re-ranking the largest single quality lift in the closest domain analog. | §12 |
| **L8** | HuaShu (花叔). *Loop Engineering: The Complete Guide* (Orange Book, June 2026). Industry guide. Generator-and-evaluator; the four costs. **Read directly for this document.** | §12, §14.1 |
| **L9** | Liu, Ye, Gao, et al. (NVIDIA/NTU/MIT). *SoL-Pi.* [arXiv:2609.20519](https://arxiv.org/abs/2609.20519). Harness overfitting caution. Held in `claude-memory`, referenced-not-ingested by the lake. | §12 |
| **L10** | Patil et al. *Gorilla* [arXiv:2305.15334]; Qin et al. *ToolLLM* [arXiv:2307.16789]; *RAG-MCP* [arXiv:2505.03275] *(preprint, pedigree unverified)*. Retrieve tools rather than register all. | §12 |

### In-repository

| source | cited in |
|---|---|
| [`AGENTS.md`](../AGENTS.md) — core principles 1 and 2; the standing rulings | throughout |
| [ADR-0002](adr/ADR-0002-kernel-is-rust.md) static Rust TCB · [ADR-0004](adr/ADR-0004-modular-authorization-architecture.md) modular authorization · [ADR-0005](adr/ADR-0005-enforcement-locus-tcb-boundary.md) TCB boundary · [ADR-0008](adr/ADR-0008-authorization-composition-contract.md) composition · [ADR-0019](adr/ADR-0019-audit-record-model.md) audit records · [ADR-0022](adr/ADR-0022-classification-policy-as-data.md) policy as data · [ADR-0023](adr/ADR-0023-runtime-loop-role-and-placement.md) runtime loop | §5–§6, §15 |
| [`design/diagrams/generated-operational-concept.svg`](diagrams/generated-operational-concept.svg) — the OV-1 and the governed learning loop | §8 |
| [`references/2026-09-25-jive-assessment.md`](references/2026-09-25-jive-assessment.md) — the graph-call primitive; the provenance standard this document is held to | §Origin, §6.3, §16.1 |
| [`references/2026-09-22-system-one-models-jev-assessment.md`](references/2026-09-22-system-one-models-jev-assessment.md) — untested classifier calibration | §6.2 |
| [`design/knowledge-lifecycle-contract.md`](knowledge-lifecycle-contract.md) — object-layer governance; **not current on edges** | §7 |
| [`design/self-development.md`](self-development.md) — PRs are human-gated | §12 |
| Knowledge Lake `references/lake/edges.yaml`, `schemas/edges.schema.json` v1, `lib/lake/_edge_graph.py`, `references/lake/vendors.yaml` | §7.1, §8 |

### Searched and deliberately not pursued

Recorded so the search is not repeated: **OpenAI** (AgentKit, Agent Builder, the Symphony orchestration spec) and **Google** (Antigravity orchestration surface) ship graph-shaped agent tooling but publish no position on plan governance — product, not argument (§13). **LangGraph** is the de facto framework implementation and was not evaluated here. **Classical workflow engines** (Airflow, Luigi, Prefect) are surveyed in R1 §2.8 rather than read directly.
