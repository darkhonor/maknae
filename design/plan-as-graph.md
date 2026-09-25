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

- **lake → plan.** Knowledge informs planning under measured access — this is the intended and load-bearing path, and §6.6 sets which tiers may shape a plan's *structure* versus only its *content*. It is legitimate because the plan is still validated against its profile afterwards. **But the validator must never consult the Lake** — informing what a plan says is not the same as deciding what counts as a valid plan, and only the second would be untrusted data setting policy.
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
2. **The platform executes the validating node, not the agent.** Adjacency alone proves *traversal*, never *honesty* — if the agent runs the check and announces the outcome, the arrow changes nothing and this is the markdown checkbox with an edge drawn on it. When the platform executes it and the exit status drives traversal, the agent is not party to the decision. **Failure does not travel back along an edge** — see §6.4.

**This is where the graph-call primitive from the [Jive assessment](references/2026-09-25-jive-assessment.md) stops being a token optimisation and becomes load-bearing** — a runtime that walks the graph without returning to the model is what makes property 2 true.

Property 2 has independent support from a direction unrelated to security — see §12: the loop-engineering literature reaches the same conclusion from quality, and reports that **making the generator more self-critical does not work** where a separate skeptical evaluator does. *"A loop without a real check is, at bottom, an agent repeatedly reaching consensus with itself."*

**The trust regress terminates at the TCB, as it already does.** At some point the platform resolves to OS primitives that have been permitted; risk surface cannot be removed entirely. This is [ADR-0005](adr/ADR-0005-enforcement-locus-tcb-boundary.md)'s boundary, not a new one. What matters is that validation executes on the trusted side of a line this project already draws: [core principle 1](../AGENTS.md) holds the agent runtime untrusted by design, so **an agent-executed validation asks the untrusted side to attest to itself.**

**One constraint for expressibility:** the verifying relation is **its own edge kind**. If any edge satisfies "the validation is connected to the activity", an ordinary `write → commit` dependency satisfies it trivially. A `verifies` edge names its subject.

*(Two further constraints appeared in an earlier draft — that retry needs a distinct edge kind excluded from the acyclicity pass, and that the back-edge needs a bound and a terminal. Both are superseded by §6.4: **there is no back-edge.**)*

**"A single edge" reads as adjacency, not cardinality.** Adjacency forbids `set-permissions → commit → check-permissions`, where the validation is real but arrives after the irreversible step. Cardinality remains *at least one*: one `cargo test` legitimately verifies several writes.

### 6.4 Recovery is per-node state, not a graph edge

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

### 6.5 Side-effect classification — the property this design lacked entirely

SGH's fourth principle, and it is the most useful thing read this session: **classify every node by side-effect profile, and let the scheduler respect the classification.** *"A read-only API call can be freely retried; a database write cannot."*

This document treated all nodes as equally retryable and equally parallelisable. They are not, and the consequences are two:

1. **Retry budgets differ by side-effect class.** Re-running a `read` is free. Re-running a half-completed `write` is a second, different edit — which is exactly §15.3's non-idempotency problem, and side-effect classification is the mechanism that contains it rather than merely naming it.
2. **High-side-effect nodes may not be speculatively dispatched in parallel** — a constraint **orthogonal to §4.7's file-conflict rule**. Two `commit` nodes with disjoint file scope still must not run concurrently. File conflict and side-effect class are two independent gates, and §4.7 only described the first.

**The vocabulary is nearly free.** The activity classes already proposed — `read`, `write`, `test`, `verify`, `gate`, `commit` — map almost directly onto a side-effect profile, so this is a floor property (§6.1) rather than new machinery. It should be in the floor and not in an organisation's profile: irreversibility is not a discipline preference.

### 6.6 Two rules taken from the security literature

**The planner reads trusted information — and the Lake is the trusted-information store, not a threat to planning.**

ACE's rule [R11] is that the abstract plan is built from **trusted information only**, and ControlValve [R12] observes the same property protects its planning stage: *"the planning stage is not exposed to untrusted content, so there is less of a risk of prompt injection."* **The boundary those papers draw is attacker-controllability, not externality.** Their threat is a malicious third-party app description, or tool output arriving mid-execution and rewriting control flow — content an adversary can author. A curated, tier-labelled, provenance-stamped corpus fetched from an operator-signed allowlist (§8) is the *opposite* of that: it is the trusted information ACE says planning should be built from.

**This matters operationally, not just definitionally.** Planning against the Lake — applicable requirements, vendor guidance, example source, the controls that apply — is what has produced more secure and more compliant plans in this project over months of use. A rule that cut planning off from it would make plans worse in exactly the dimension the platform exists to serve, in exchange for mitigating a threat the Lake's own governance already addresses.

**The rule that does transfer, and the tier model already implements it:**

| planning input | disposition |
|---|---|
| Tier 0 doctrine, Tier 1 authoritative, curated vendor corpus | **trusted** — read freely; this is the intended planning substrate |
| Tier 3 quarantine, freshly fetched material | may inform *reasoning*; **must not shape the graph's structure** |
| tool output, MCP/app descriptions, retrieved web content arriving during execution | **untrusted at planning time** — this is ACE's actual threat |

**And the two-layer split (§3) gives a cleaner boundary than either source has.** The *shape* layer — which activities, in what order, with what dependencies — is control flow, and control flow is derived from trusted tiers only. The *payload* layer may draw on lower-tier material, with its mark travelling (§7). An attacker who poisons a Tier-3 document can then influence what a step's content says; they cannot add a node, remove a gate, or reorder a commit. That is the property ACE is protecting, achieved without blinding the planner.

**Structural validation does not protect the data flowing between nodes.** [R3] §2.2 states it plainly: an attacker who controls a source can inject a payload that rides the plan's own data flow — the agent *"would correctly follow its plan"* while carrying malicious content into a later step. **This document has node authorization and no data-plane taint model at all.** ACE's answer is to verify concrete plans against **user-specified secure information-flow constraints**. Named here as a gap rather than solved — but with one warning about the obvious fix.

**The obvious fix is monotone taint, and monotone taint is known to fail on agent workflows.** APPA [R13] states it: conventional IFC *"relies on monotone taint tracking that either over-blocks benign operations or permanently strands downstream execution once an agent ingests unvetted data."* **This matters directly here because the KLC's high-water-mark rule — a derived object takes the maximum of its inputs — is monotone taint.** Applied across a long-running plan it does exactly what APPA describes: one Tier-3 read early in a graph raises the mark for everything downstream, and the plan strands. APPA's alternative is a **dual-phase reference monitor** — prospective evaluation before tool dispatch, then validation of realised outputs before they are admitted to context — turning IFC from an abort-only barrier into a policy-governed recovery. Whatever Maknae adopts, a naive high-water mark over a plan graph is the wrong starting point.

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

## 12. What the literature establishes

Fourteen sources read in full (§19). This section reports what they measure, including where they contradict this document.

### 12.1 The validation gap — the most important result for this design

SGH [R1] Theorem 6.3. Let `p_v` be the probability that node *v*'s contract validation correctly identifies a passing output. If all nodes pass and validation errors are independent:

> **Pr[all outputs correct] ≥ ∏ p_v**

**Correctness is the *product* of per-node validation reliability, so it decays geometrically with plan length.** A 56-node plan at `p_v` = 0.95 bounds at **5.7%**; at 0.99, **57%**. The paper distinguishes two regimes: **syntactic validation** (field existence, types, format) performed by deterministic code, where `p_v ≈ 1`; and **semantic validation** ("is the fix correct?"), where test suites are good and *"LLM-based validation depends on model capability and task difficulty."*

**This is the quantified case for code-based validation.** For Maknae developing Maknae the validating nodes are `cargo test`, `cargo clippy`, `cargo mutants` and `ci/gates/*.sh` — code, with `p_v` near 1. **For a user's plan there is no cargo, and §12.12 works out what the platform can evaluate instead.** A design in which a model judges whether each step succeeded degrades multiplicatively with plan length, and at our plan sizes it degrades to nothing. **Use code-based validation or keep plans short; there is no third option.**

SGH's own mitigations are worth taking: require code-based validation on high-side-effect nodes, provide a `waiting_human` node state for critical steps, and rely on downstream contract failures to catch upstream semantic errors at the next dependency boundary.

### 12.2 Graph comprehension collapses with node count — and our plans are larger than anything tested

Plan-over-Graph [R4] Table 1, Llama-3.1-8B-Instruct finding shortest paths on random graphs:

| nodes | success rate | optimal rate |
|---:|---:|---:|
| 10 | 79% | 29% |
| 30 | 35% | 16% |
| 50 | **10%** | **6%** |

Corroborated as a *"comprehension collapse"* phenomenon in two further studies the paper cites. **And the benchmarks are small:** WorFBench graphs are *"in the range of 2 to 10 steps"*; AsyncHow's `|V| + |E|` is mostly 10–20. **The ceiling plan converted in §4 is 65 nodes.**

Two qualifications, then the conclusion. This is an 8B model on shortest-path *optimisation*, which is harder than traversing a validated plan; frontier models do better. And in this design **the model does not traverse the graph — the platform computes the ready set.** So comprehension collapse bites at **authoring**, not execution. That is still the exposed step: nothing else produces the graph.

### 12.3 Planner error rates, by model — and the local-model story is the casualty

Plan-over-Graph [R4] Table 5, proportion of test cases exhibiting each error:

| model | invalid subtask (hallucinated) | unavailable source (dependency error) |
|---|---:|---:|
| Claude 3.5 Sonnet | **0.4%** | 9.6% |
| GPT-4o | 4.7% | **44.0%** |
| Llama-3.1-8B-Instruct | 17.6% | 30.1% |
| Llama-3.1-8B *trained* | 11.6% | 4.8% |
| Qwen2.5-7B-Instruct | **60.7%** | 26.1% |
| Qwen2.5-7B *trained* | 19.9% | 4.3% |

**An untrained 7B model hallucinates invalid subtasks in 61% of cases.** Training on synthetic task graphs cuts it to 20% and nearly eliminates dependency errors — but the authors state plainly that *"the hallucination of invalid subtasks is currently the performance bottleneck"* even after training. §1's secondary objective is a smaller local model; **this table says an untrained small model cannot author a valid task graph, and that authoring must either run on a frontier model or on a model fine-tuned for the schema.**

### 12.4 The parallelism speedup, measured in the right regime

§15.5 doubted that LLMCompiler's number transfers. Reading both papers settles it in both directions.

LLMCompiler [R10] reports up to 3.7×, and its benchmarks are HotpotQA, Movie Recommendation, ParallelQA, Game of 24 and WebShop — **search and QA workloads, I/O-bound fan-out.** Plan-over-Graph [R4] Table 4 measures parallel-to-sequential execution-time ratio on **dependency-constrained task graphs**:

| nodes | ratio (random topology) | ratio (tree topology) |
|---:|---:|---:|
| 10 | 0.88 | 0.92 |
| 30 | 0.74 | 0.75 |
| 50 | 0.68 | 0.62 |

**1.1× at 10 nodes, at best 1.8× at 50.** And SGH [R1] §9.3.2 estimates from its 70-project survey that only **30–40% of agent tasks exhibit natural parallelism** at all. §4.6's 89% file-disjointness is a measure of *potential*, and the achievable figure is materially lower.

### 12.5 What graph validation cannot catch

SGH [R1] §3.7 enumerates five planning failures and, crucially, which survive validation:

| failure | caught? | cost |
|---|---|---|
| missing dependency | **yes** — at runtime, as a contract violation on the starved node | recovery protocol engages |
| spurious dependency | **no** — the DAG is structurally valid | lost parallelism; time, not correctness |
| wrong join semantics (`all_of` where `any_of` was meant) | **no** | repeated retry, escalation, eventual replan |
| over-decomposition | **no** | overhead scales with node count; no automatic merge |
| under-decomposition | **no** | lost parallelism and unattributable errors |

**Four of five are invisible to structural validation.** This is the precise, enumerated form of §16 item 4: a structurally perfect plan that is a bad plan passes every check, and only the *missing dependency* case is caught — and then at runtime, not at validation.

### 12.6 A graph alone does not buy controllability — the survey says the opposite

SGH's 70-project survey (Table 7) classifies systems by primary execution pattern:

| category | share | expressiveness | controllability | implementability |
|---|---:|---|---|---|
| Agent Loop | 60% | Low | Low | High |
| Event-driven | 15% | Low | Medium | High |
| State-machine | 10% | Medium | **High** | Medium |
| **Graph / flow orchestration** | 5% | **High** | **Low** | Low |
| Hybrid | 10% | Medium | Medium | Medium |

And qualitatively: failure-loop behaviour was observed in **3 of 4** graph/flow projects and **0 of 7** state-machine projects (the authors flag this as subjective and unquantified).

**Existing graph orchestration systems have the *worst* controllability of any category.** This document has been treating "graph" as a synonym for "controllable." It is not. **The controllability comes from the restrictions** — immutable plan versions, deterministic policy, bounded recovery — not from the graph. A graph without them is the least controllable option in the survey.

### 12.7 Narrow the runtime check, and give the checker no discretion

ControlValve [R12] breaks LlamaFirewall-style alignment checks across Llama, o4-mini, 4o and 4o-mini, and explains why its own check survives:

> *"Alignment checks try to determine whether an action is aligned with the overall task, which is difficult and error-prone. By contrast, ControlValve only checks if an action corresponds to an edge in a graph and satisfies the edge-specific rules."*

And the rule that follows from the failure analysis: **the judge is not asked to determine the merits of the rules or justifications for violating them** — *"this is how alignment checks in LlamaFirewall fail."*

**A checker that can be reasoned with can be reasoned out of.** Phase two must ask "is this node permitted by the graph and its rules," never "is this a good idea." That is the reference-monitor posture Maknae already holds, arrived at from an attack paper rather than from doctrine.

Two further parameters worth copying: ControlValve generates **at most three contextual rules per edge**, explicitly *"to avoid over-constraining executions and preventing legitimate tasks from being completed"* — a concrete answer to §15.1's false-positive hazard — and it caps re-planning at **three attempts**, with outcomes limited to permit / reject / re-plan. It also provides for *"organization-specific rules… added, if needed"*, which is §6.2's profile with a different name.

### 12.8 Mechanisms worth adopting

- **Two gates per call, not one** (APPA [R13]): a **pre-dispatch** gate judges the label the call *would* produce — so a composite read-and-send is checked *before* the read — and an **admission** gate re-checks the realised return before it folds into context. Their measured cost: **64–91% utility, zero observed attacks across 1,320 guarded episodes** of 6,600.
- **Disposable confined branches** (APPA): untrusted content is inspected in a child branch that absorbs taint locally and exits through a shape-bounded channel, rather than poisoning the parent context. This is a better answer than quarantine-by-tier for the case where a plan genuinely must read Tier-3 material.
- **Lattice-based information-flow verification** (ACE [R11]): concrete plans are verified against a lattice policy and rejected when they violate flow constraints. **Maknae already has the lattice** — the ceiling operand's level order plus the DCS library's compartments and releasability. §6.6's taint gap has a mechanism that is half-built here already.
- **Interface-preserving recursive compilation and minimal-subgraph repair** (ATG [R5]): decompose recursively while preserving each parent node's input/output interface, keeping a coarse-to-fine graph *sequence*; on failure, freeze validated regions and repair only the smallest affected subgraph. It also runs a **pre-execution "thought experiment"** — consistency, missing-step, tool-appropriateness, dependency and constraint checks — which is a more complete phase-one list than §4.3's. Evaluated on 7B–8B backbones.
- **Template / realized graph / trace** [R7]: the survey's three-way distinction, which disentangles this document's own vocabulary — a reusable design, the per-run graph, and the execution record are three artifacts. It also notes the representation axis that matters is **validatability**, not token count: DSL/JSON/YAML *"varies in how easily it can be validated"*, against graph IRs with *"typed operators or constrained schemas."* That answers §18's S-expression question on the right axis.

### 12.9 Measured gains from adjacent systems

Reported by their authors, not independently verified: **Routine** improved multi-step tool-calling accuracy **41% → 96%** in enterprise settings via structured planning scripts; **TDP** cut token consumption **up to 82%** using DAG sub-goals with scoped contexts; **DynTaskMAS** reduced execution time **21–33%**; **WorFBench** found a **15% gap between sequence-planning and graph-planning capability even in GPT-4** — models are measurably worse at producing graphs than sequences.

### 12.10 The ablation protocol this document lacks

SGH [R1] §8 specifies a seven-group design that isolates each contribution — and **G0 is "a state-of-the-art prompt-augmented Agent Loop (e.g., Claude Code, OpenAI Codex agent mode)"**, included because *"without it, improvements attributed to graph structure might merely reflect the benefit of providing the system with richer task information."*

| group | scheduler | structure | recovery |
|---|---|---|---|
| G0 SOTA Loop | single-ready-unit | planner prompt + reflection | inline replan |
| G1 Naive Loop | single | none | context continuation |
| G2 Planner Loop | single | none | context + replan |
| G3 Structured Loop | single | scaffold | scaffold recovery |
| G4 GH-Core | **multi** | static DAG | retry only |
| G5 GH+Patch | multi | static DAG | retry + patch |
| G6 GH+Replan | multi | static DAG | full ladder |

Gains decompose as `G_plan`, `G_scaffold`, `G_graph`, `G_patch`, `G_replan`. **This is the experiment §17 says is missing, already specified, with our own harness named as the baseline to beat.** Their stated biases are ours too: task-selection bias inflating `G_graph` if the task set over-represents parallelisable work, and LLM non-determinism requiring repeated runs.

### 12.11 Where a static DAG is the wrong tool

SGH [R1] §9.5 names three task classes the design does not serve: exploratory tasks where sub-tasks are unknown until intermediate results are seen; **dynamic goal evolution — *"investigate the outage and fix whatever is broken"***; and creative generation where revision structure depends on content. **The middle one is a real Maknae workload**, and the honest answer is that it belongs to an agent loop with inline replanning, not to a validated plan graph.

## 12.12 What the platform actually evaluates — and the correctness bound as a gate

§12.1's conclusion was stated too narrowly: *"Maknae's validating nodes are `cargo test`, clippy, mutants and `ci/gates`."* **That is Maknae developing Maknae.** A user's plan — remediate a STIG finding, configure a device, produce a compliance report — has no cargo and no repository test suite. The platform must run deterministic checks against an agent-authored graph during an **evaluation phase** between planning and execution, and those checks cannot assume a domain.

Three tiers, and only the first is domain-independent.

### Tier 1 — graph-level checks, deterministic and domain-free

These are graph algorithms, not judgments, so `p ≈ 1` by construction and they apply to any plan in any domain:

| check | what it rejects |
|---|---|
| acyclicity, reachability | cycles; orphan nodes unreachable from any root |
| join consistency | an `all_of`/`any_of` whose predecessor set is malformed |
| conflict analysis (§4.7) | unordered nodes with write∩write or write∩read overlap |
| side-effect class vs dispatch (§6.5) | high-side-effect nodes eligible for speculative parallel dispatch |
| profile conformance (§6.2) | a required node kind absent; a required adjacency missing |
| scope containment | a node touching files no task in the plan declared |
| egress allowlist (§8) | a fetch node whose source is not on the operator-signed list |
| schema and type validation | a node whose declared inputs cannot be produced by its predecessors |

ATG's [R5] pre-execution *"thought experiment"* adds four more of the same character — consistency, missing-step detection, tool-appropriateness, dependency validation — and is the closest published list to what this tier should contain.

**This tier is the bulk of the tooling and it is buildable today.** It needs no model, no domain corpus, and no per-user configuration beyond the profile.

### Tier 2 — node output contracts, deterministic where the domain supplies one

SGH's contract validation [R1] guards the `running → executed` transition: a node enters `executed` only if its realised output satisfies its contract `κ_v`. **The contract is authored at planning time, before the node runs** — which is what makes it a check rather than a post-hoc rationalisation.

A contract is deterministic when it is structural: an exit status, schema conformance, a file existing with an expected mode and owner, an idempotent re-read returning expected state, a value present in a response. **The domain supplies these, not the platform** — and for the maintainer's domain a great many already ship as published artifacts. A STIG rule carries its own check content, and where SCAP/OVAL definitions exist that check is machine-evaluable without an LLM in the loop. *(Not all of them: a substantial fraction of STIG rules are manual-review only, and those nodes fall to Tier 3.)*

**The general rule this yields: a `verify` node's contract must name a check the platform can evaluate, and the plan declares which.** Where a domain publishes machine-checkable verification content, the plan graph should cite it rather than restate it.

### Tier 3 — nodes with no deterministic contract, and the gate that falls out of the theorem

Where no structural contract exists, validation is a judgment and `p_v < 1`. §12.1's theorem then bites: the plan's correctness bound is `∏ p_v` over every node, so a handful of judgment-validated nodes in a long plan drives the bound toward zero.

**This yields a phase-one check that nothing in the surveyed literature performs: reject the plan because its validation bound is too weak.** If every node declares its contract *class* — `deterministic` (exit status, schema, state re-read), `test-suite`, `published-check` (SCAP/OVAL and similar), `human` (the `waiting_human` state), or `model-judgment` — the evaluator can compute the plan's bound from declared classes alone, before anything executes, and the **profile sets the floor**. A plan that cannot reach the floor is refused with the specific nodes named, and the author's options are to strengthen a contract, split the plan, or route a node to human review.

This makes the validation gap **an authored property of the graph rather than an emergent property of execution**, which is the same move the rest of this design makes everywhere else: state the obligation in the artifact, check it before it runs.

**Two honest limits.** The per-node reliabilities are estimates, not measurements — a declared class is a claim about a check's character, and calibrating `p` per class needs data this project does not have. And the theorem assumes independent validation errors, which correlated failures (one bad model, one wrong assumption threaded through several nodes) violate in the unfavourable direction.

## 13. Where the labs are

Asked directly, because it decides how much of this is ours to invent.

**No lab has published a position on graph-structured plan governance.** What exists is product and pattern guidance:

- **Anthropic** is the nearest thing to a stated position. [*Building effective agents*](https://www.anthropic.com/engineering/building-effective-agents) names five composable patterns — prompt chaining, routing, parallelization (sectioning and voting), orchestrator-workers, and **evaluator-optimizer** — and draws the distinction this document has been circling: **workflows are systems where LLMs and tools are orchestrated through *predefined code paths*; agents are systems where the model directs its own process.** A validated plan graph is squarely the first. **And the guidance cuts against us:** the finding is that the most successful implementations used *simple composable patterns rather than frameworks*. We are proposing a framework.
- **OpenAI** ships AgentKit and Agent Builder — visual workflow graphs — and an orchestration spec. Product, not position.
- **Google** ships an orchestration surface in Antigravity 2.0. Product, not position.
- **The intellectual work is academic and framework-side.** LangGraph is the de facto standard implementation, and the 2026 arXiv literature carries the reasoning: [*From Agent Loops to Structured Graphs*](https://arxiv.org/abs/2604.11378) (scheduler-theoretic, position paper, no empirics), [*Atomic Task Graph*](https://arxiv.org/pdf/2607.01942), [*Plan-over-Graph*](https://arxiv.org/pdf/2502.14563), [*BatchDAG*](https://arxiv.org/abs/2607.18241), [*Architecting Resilient LLM Agents*](https://arxiv.org/pdf/2509.08646), and a survey of the shift [*From Static Templates to Dynamic Runtime Graphs*](https://arxiv.org/pdf/2603.22386).

**The field also has a name for it, and a 32-author survey placing it.** [R6] calls this **Graph Engineering** and sets it after Prompt, Context, Harness and Loop Engineering in the same progression — the move from *individual* to *system* intelligence, motivated by tasks requiring *"heterogeneous expertise, interdependent subtasks, parallel execution, independent verification, and persistent state."* Its decomposition maps onto §5's taxonomy closely enough to be worth adopting as vocabulary: **task organization** (what to do), **agent coordination** (who works), **runtime state management** (how the system operates), and **system evolution**.

**The takeaway is not comfortable: the field is converging on graph-structured execution, the labs are selling it as tooling rather than arguing for it, and the one lab that has argued anything cautions against the framework we are designing.** The governance layer — profiles, floors, validation as authorization — is genuinely ours, which means it also has the least external support.

## 14. What holds up

Recorded before the adversarial read so the document is not mistaken for a retraction. Three tiers, by what supports each.

### 14.1 Independently confirmed by outside work

- **Typed, first-class edges beat inferred relationships.** The best-supported claim in this document and the foundation of both graph families. F5's structural finding — *"version transitions are not explicit relationships that can be extracted from text"* — is independent of its contested magnitudes, and F4 puts a number on the failure it prevents: similarity-only retrieval reaches 58–64% on version-sensitive questions. Our `verifies` and `commit-with` edges are the same argument applied to activities.
- **Stable opaque identifiers, not surface forms.** Not merely correct — correct *where the state of the art is not*. GraphRAG, HippoRAG, HippoRAG 2 and LightRAG all key on LLM-extracted surface forms and all treat name-based merging as unsolved (F9). The Lake imposed opaque ids anyway and has a concrete near-miss proving the point.
- **Separating the evaluator from the generator.** **Two independent derivations converge here, which is the strongest support available short of a benchmark.** This document reached it from security — the agent runtime is untrusted, so it cannot attest to itself. Anthropic reached it from quality — agents confidently praise their own output, and *making the generator more self-critical did not work* where a separate skeptical evaluator did. Anthropic also names **evaluator-optimizer** as one of five composable patterns.
- **Parallelism from declared dependencies.** Plan-over-Graph [R4], LLMCompiler [R10] and BatchDAG [R2] all do exactly this; the maintainer identified it independently while reading a draft. §15.5 disputes the *magnitude* transferring to our workload — it does not dispute the structure, which is field-standard.
- **The two-phase design is published, peer-reviewed, and named — twice, independently.** This is the single strongest support in the document and it was found only by reading the security literature properly:
  - **ControlValve** [R12] (ICLR 2026, Cornell + Microsoft) is our design: *"(1) generates permitted control-flow graphs for multi-agent systems, and (2) enforces that all executions comply with these graphs, along with contextual rules … for each agent invocation."* A permitted graph plus per-invocation rules **is** phase one plus phase two.
  - **ACE — Abstract-Concrete-Execute** [R11] (NDSS 2026, Northeastern) formalises the trusted-planning half: planning is decoupled into an **abstract plan built from trusted information only**, then mapped to a concrete plan whose implementations are **verified against secure information-flow constraints** before execution. It was built after breaking IsolateGPT, a prior isolation-based defence.
  - The pattern also has a name in the practitioner literature: [R3] calls it **Plan-Validate-Execute**, with the verifier *"instantiated as another LLM, a rule-based engine, or a symbolic checker"*, independent of both planning and execution.
- **LLM-judged alignment is not a control, which is why the platform must validate.** ControlValve's first result is *breaking* alignment-check defences — LlamaFirewall-style checks performed by Llama, o4-mini, 4o and 4o-mini were all evaded. §6.3's property 2 is not merely preferable; the alternative is measured to fail.
- **A validated graph answers a threat per-request authorization structurally cannot.** ACP [R14] measures it: *"autonomous agents can produce harmful behavioral patterns from individually valid requests — a threat class that per-request policy evaluation cannot address, because stateless engines evaluate each request in isolation and cannot enforce properties that depend on execution history."* Under a 500-request workload where **every request is individually valid**, a stateless engine approves all 500. **A plan graph is the execution history, available before execution** — so sequence properties that no per-request PDP can see are checkable at phase one. This is an argument for the design that this document had not made, and it is a strong one.
- **The category itself.** Anthropic's distinction — *workflows are LLMs orchestrated through predefined code paths; agents direct their own process* — is precisely what a validated plan graph is. We are not inventing a category, and the field is moving this way: a 2026 survey is titled *From Static Templates to Dynamic Runtime Graphs*.
- **Plan-then-execute is a real security property, correctly bounded.** Separating planning from execution gives control-flow integrity against indirect prompt injection. Our caveat that it is insufficient alone is also the source's caveat, and Maknae already supplies the defence in depth it asks for at phase two.
- **Code-based validation over model judgment, now quantified.** SGH's validation-gap theorem (§12.1) bounds whole-plan correctness by the *product* of per-node validation reliability. Maknae's validating nodes are `cargo test`, the clippy and mutants gates and `ci/gates/*.sh` — deterministic code, `p_v ≈ 1`. The alternative, an LLM judging each step, degrades geometrically and at 56 nodes degrades to nothing. This was house doctrine; it is now a theorem with a number attached.
- **Progressive disclosure over loading everything.** Gorilla, ToolLLM and RAG-MCP converge on *retrieve the relevant tools rather than registering all of them*. The 1.8% shape layer is that pattern applied to plans.

### 14.2 Established by our own measurement

Weak provenance (§16 item 1) — but these are real results, and **the experiment earned its keep by refuting rather than confirming.** A measurement that only agreed with its author would deserve less trust, not more.

- **The shape layer is 1.8% of the markdown**, and shape-plus-heaviest-node is 12%. Progressive disclosure at that ratio makes whole-plan structural checks affordable on every plan.
- **Compression is not the win** — it refuted the obvious first claim, which was mine.
- **Inferred typing is not worth building on** — 23–33% unclassified and three false positives in five warnings. This is the result that produced the document's central design decision.
- **The straight line was an artifact of the format**, not of the work: 89% of ceiling's task pairs touch disjoint files while the conversion produced a strict chain.
- **Two of five warnings were true structural facts** about real plans — gaps a prose reviewer had not caught.

### 14.3 Correct because it reuses settled doctrine rather than inventing

The security reasoning in this document is largely *not new*, and that is the point in its favour: deny-by-default, **policy over profile**, inform-but-not-authorize, the TCB as the terminus of the trust regress, the `config.d/` custody rule making a subject unable to choose its own profile, and ADR-0022's compiled-in/boot-selected split. **No new security model was invented for graphs.** Where this document does invent — the profile and floor construction (§16 item 2) — is exactly where it has the least support, and the two facts are related.

## 15. Adversarial read: what we are proud of that may be a pitfall

### 15.1 Fail-closed validation, on a checker measured wrong 60% of the time

Fail-closed is a core principle and it is right. But **the only structural checks ever run in this project produced three false positives out of five warnings** (§4.4). Fail-closed multiplied by an unreliable checker converts a checker bug into a work stoppage — and the failure is silent in the flattering direction, because a false positive looks exactly like discipline. In CI that is tolerable. For an interactive agent it is not. **Nothing in this document proposes how the checker itself earns trust**, and the negative-control gate's own logic applies: a validator that has never been observed wrongly rejecting a good plan proves nothing about its false-positive rate.

### 15.2 The structural guarantee is only as strong as the mediation — and it differs by consumer

*"You cannot reach the next node without traversing this one"* holds **only if the graph is the only execution path.** In Maknae it nearly is: every request transits the reference monitor. **In a Claude Code skill it is not at all** — the agent has a shell and can do the work outside the graph, then walk the nodes.

This document has been written as though one idea serves both consumers. It does not. **The same design is load-bearing in the kernel and decorative in the harness**, and §11 should be read with that discount applied. A skill can make a plan *checkable*; it cannot make an obligation *enforced*.

### 15.3 Retry back-edges were the anti-pattern — confirmed, and replaced

Read in full, [SGH](https://arxiv.org/abs/2604.11378) is stronger than the summary suggested. Its survey of **70 agent systems** found Agent Loop implementations *"commonly lacked any formal bounds on recovery attempts,"* producing two observed failure modes: **infinite retry** when the model insists on a failing approach, and **premature abandonment** when a transient error triggers an unnecessary replan. This document's design had the first hazard bounded and the second unguarded, because it had no Level 2.

**Resolved, not merely flagged:** §6.4 adopts the per-node recovery ladder and §6.5 the side-effect classification. The back-edge is gone.

**Its standing as evidence, unchanged:** a single-author position paper with **no empirical results** — it says so itself, offering *"a theoretical framework, a design analysis, and an experimental protocol—not a production implementation."* What it does have is a formal state machine with termination and soundness arguments and a 70-system survey, which is more than an opinion and less than a finding. **It is adopted here because its design is better reasoned than ours was, not because it is validated.**

### 15.4 Plan-then-execute's security value evaporates at the re-plan, and we never said who may author one

The control-flow-integrity argument — a validated plan resists indirect prompt injection because the actions are fixed in advance — holds while the plan is fixed. **Every failure path designed here involves retry or escalation, and none of them says who authors the revision.** If the untrusted runtime may re-plan, the injection surface reopens exactly when the system is already degraded. [R3] states plainly that plan-then-execute alone is insufficient and requires defence in depth; Maknae has that at phase two.

**Reading the security literature answered it, and the field disagrees with itself in a way worth recording.** [R3] §7.1 recommends an LLM **re-planner node after every execution step**, given the objective, the original plan and all outcomes, with cyclic graphs routing back to the executor. [R1] forbids exactly that: plans immutable per version, replan only as Level 3 of an enforced ladder. **ControlValve [R12] settles which to prefer for this posture** — it names *"the fundamental conflict between safety and functionality when re-planning in response to errors"* as one of three root sources of control-flow hijacking, and its attacks land precisely there. An LLM re-planner reading execution outcomes is reading untrusted content and then rewriting control flow.

**So Maknae takes [R1]'s ladder, and now for a stated reason rather than by accident:** re-planning is the attack surface, so it is the last rung, gated on an exhausted ladder, producing a new plan version, with diagnosis on a separate context (§6.4) and the planner unexposed to untrusted content (§6.6). The residual — who authors the Level-3 replan — is still ours to decide, but it is now one bounded question rather than an open door.

### 15.5 The parallelism speedup is measured on work unlike ours

Settled by §12.4: LLMCompiler's 3.7× [R10] is on search and QA workloads. On dependency-constrained task graphs the measured parallel-to-sequential ratio is **0.88 at 10 nodes and 0.62–0.68 at 50** [R4] — **1.1× to 1.8×** — and only **30–40% of agent tasks have natural parallelism** at all [R1]. A Maknae plan additionally serializes on the cargo target-directory lock, so parallel branches need separate worktrees that nobody here has built. **§4.6's 89% file-disjointness measures potential; the achievable figure is materially lower and this document should not be read as promising a large speedup.**

### 15.6 A validated graph can be complied with and still be malicious — and this has 20 years of prior art

The sharpest criticism a reviewer will level, raised here first because ControlValve [R12] raises it against itself:

> *"the graph may be too lax (i.e., an over-approximation of the legitimate executions) and thus potentially permit executions that should not happen. In CFI research, there is a large body of work on evasion attacks that compromise programs while complying with the statically computed CFG. It is an open question whether similar CFH attacks are possible in multi-agent systems."*

**Control-flow integrity is a twenty-year-old defence with a twenty-year-old literature on defeating it while remaining CFG-compliant.** Everything this document proposes inherits that literature. §15.2 (mediation) and §16 item 4 (validity is not correctness) are the same hazard seen from two other angles; this is its name, and the prior art is Abadi et al. 2005 onward.

It also sets the honest ceiling on the claim. **A validated plan graph raises the cost of an attack and bounds its shape. It does not make one impossible**, and a proposal that implies otherwise will be dismissed by anyone who has read the CFI literature.

### 15.7 The planning phase has costs this document never measured

[R3] §7.4 names three, and this document measured none of them because it measured the *artifact* and not the *act of producing it*:

- **Time-to-first-action.** The whole plan must be generated before anything happens.
- **Planning-call token cost of roughly 3,000–4,500 tokens**, *"more than a ReAct agent might use for an entire simple task."* §1 argues graphs keep the model focused; that argument is about execution, and the planning call is a separate bill this document never put on the table.
- **Wasted effort when a plan is flawed**, which compounds with §16 item 4.

Their mitigation is worth taking: **hierarchical sub-planners** — a high-level blueprint decomposed into milestones, each planned independently and in parallel. Lower upfront token cost, and *"a natural failure containment boundary: if one sub-plan is flawed or requires re-planning, only that segment needs regeneration."* That maps onto the task/step hierarchy already present and bounds the blast radius of a Level-3 replan (§6.4).

### 15.8 Phase two is per-request, which is the thing ACP breaks

The finding above cuts both ways, and the second edge is aimed at us. **Maknae's PDP is a per-request evaluator, and phase two as described here is per-node authorization** — stateless with respect to what the graph has already done. ACP [R14] is precisely a demonstration that this is insufficient against sequences of individually-valid actions, and it proposes history-aware admission (risk accumulation, cooldown, escalation after *n* actions, denial after *m*) behind a ledger abstraction that separates decision logic from state.

**Phase one covers part of this and not all of it.** A validated graph bounds the *planned* sequence, so behaviour that emerges from a plan the validator approved is still unbounded at run time — retries, fan-out cardinality, and anything a Level-2 patch changes are all post-validation.

Two cautions from the same paper before adopting anything: they found and fixed a **cross-context interference** bug in their own v2.0, where high-frequency benign work in one context elevated risk in an unrelated one, *"producing false denials that a stateless engine would never generate"* — which is §15.1's false-positive hazard in a new place. And they show an adversary who knows the risk formula can suppress the behavioural signal to zero while every request stays compliant. **History-aware admission is not a substitute for the structural bound; it is another layer with its own evasion.**

*(Provenance: a draft standard from a single author, but the most rigorously evidenced item in this corpus — TLA+ model-checked with 11 invariants and 4 temporal properties over 4.29 billion states, 73 signed conformance vectors, and its own negative results reported.)*

### 15.9 We treated "graph" as a synonym for "controllable"; the survey says the opposite

§12.6 is the finding this document was least prepared for. In SGH's 70-project survey, **graph/flow orchestration systems score *lowest* on controllability of any category** — high expressiveness, low controllability, low implementability — and failure-loop behaviour appeared in 3 of 4 of them against 0 of 7 state-machine systems.

**The controllability does not come from the graph.** It comes from the restrictions layered on it: immutable plan versions, a deterministic dispatch policy, bounded recovery, contract validation. A graph without those is, empirically, the least controllable option available. Every argument in §5 and §6 that leans on "because it is a graph" should be read as leaning on the restrictions instead — and a reviewer will make that substitution whether or not this document does.

### 15.10 A closed schema forbids the unanticipated case too

*"The schema forbids the wrong thing rather than documenting it"* (§7.1) is the right instinct and has a cost. The Lake kept its vocabulary minimal by **census** — a human counted the cases. Under agent authoring (ruling 3) there is no census, and the seventh edge type nobody anticipated becomes an authoring failure rather than a schema request.

## 16. Where we have little grounded fact

Listed so nothing here is mistaken for evidence.

1. **This experiment does not meet the standard this repository applied to Jive.** The [Jive assessment](references/2026-09-25-jive-assessment.md) §1 refused to treat that project's numbers as evidence because they were one author's runs of his own tasks against his own agent. **Every number in §4 is one author's conversion of his own plans, by a parser he wrote, checked by checks he wrote, n=2, no repetition, no independent review.** The same verdict applies: usable for a design read, disqualified as evidence.
2. **The profile and floor construction is less unsupported than it looked, and the reason is the strongest positioning argument available.** ControlValve [R12] generates its control-flow graphs **and its per-edge rules with an LLM**, and names that as its own weakness: *"because control-flow graphs and edge-specific rules in ControlValve are created by LLMs, they can be incorrect, too permissive, or too restrictive… if the LLM makes a mistake creating the graph or the rules, the defense can fail."* **Maknae's profile is operator-authored, boot-validated and custody-protected (§6.2); the floor is compiled in (§6.1).** The published state of the art's acknowledged weak link is precisely the thing this design does not delegate to a model. **And the shape has direct precedent in two places.** ControlValve [R12] provides for *"organization-specific rules… added, if needed"* alongside its generated edge rules — a per-deployment layer over a common mechanism, which is §6.2 under another name. And [R6] §5.2 argues an ontology for these systems *"should be layered and modular — a core ontology can define concepts shared across systems, while specialized modules describe goals and values, agents and capabilities, observations and evidence, actions and states, and evaluation criteria… without requiring every system or domain to adopt a single monolithic model."* **That is the vocabulary-plus-floor with per-organisation profiles, stated as the field's next step.** What remains genuinely unsupported is not the shape but the *enforcement posture* — a boot-validated, custody-protected profile that can refuse startup — which no surveyed system attempts.
3. **Agent authorship of knowledge edges is explicitly unevaluated** — the Lake synthesis's own open question 2 notes the literature validates explicit edges over inferred ones but does not evaluate *who authors them*. Ruling 3 is a decision, not a finding.
4. **Validity is not correctness, and only validity is checkable — now settled by reading the paper.** BatchDAG's 98.8% means **structural and schema validity**: 255 of 258 plans *"produced valid, executable DAGs"*, and the three failures *"contained schema errors (referencing non-existent columns)."* Nothing about answering the question correctly. Three further details matter and none is in the abstract:
   - **The denominator is conditioned.** 42 of 300 calls failed on API errors and were excluded. End-to-end the rate is 255/300 = **85%**.
   - **Validity degrades with structural complexity.** 100% on SQL-only and search-only categories; *"all three failures occurred on complex fan-out queries requiring multi-source joins."* Maknae's plans are the complex kind.
   - **Their limitations section states this document's §16 item 4 verbatim:** *"if the planner generates an incorrect DAG, the system executes the full fan-out before the error becomes apparent."* It is a real operational problem, not a theoretical worry — and they propose the mitigation §11 should adopt: **a probe phase that validates on a single batch first.** Run one instance of a fan-out and check the result before dispatching the rest.

   Provenance: single author, Brevian.ai, production self-report, n=12 queries, LLM-assisted drafting acknowledged. The architectural conclusion — *"for cross-entity analytical workloads, the LLM should plan, not execute"*, with four of six operation types requiring zero LLM calls — is independent support for §6.3's property 2.
5. **The typed-edge magnitudes are contested.** F5's 10%-versus-60% is self-reported on a 100-question author-built benchmark. The structural claim survives; the size of the effect does not.
6. **Comprehension rot is unmeasured** (§12), as is whether progressive disclosure actually reduces execution-time context (§17).
7. **No storage-backend evidence** for a structured graph layer, air-gapped or otherwise.

## 17. The limitation the field states, which is this document's deferred item

[R6] §5.1 names the boundary of the whole approach, and it is the thing the maintainer deferred at the outset of this work:

> *"Graph Engineering makes relationships among tasks, agents, and runtime states explicit, but explicit structures do not ensure that system components interpret them consistently. Agents may still disagree about what constitutes task completion, sufficient evidence, valid state, or authorized action."*

**A graph fixes structure and not meaning.** Two agents can traverse the same validated plan and disagree about whether a `verify` node passed. The survey's answer is **Ontology Engineering** — *"a shared, machine-interpretable model… which entities exist, what their relations mean, which constraints must hold, and what conclusions can be derived"* — and it is explicit that this is a semantic foundation *connecting* Graph Engineering to something larger, not a solution to every system-level problem.

This is the standardised schema deferred when this work began. It is not a refinement of the graph; it is the layer the graph rests on.

### And the evaluation this document would need

**The protocol exists and is specified (§12.10).** SGH's seven-group design isolates `G_plan`, `G_scaffold`, `G_graph`, `G_patch` and `G_replan`, and names Claude Code as the G0 baseline precisely so that structural gains are not confused with the gain from richer prompting. Running G0 / G3 / G4 alone — a prompt-augmented loop, a structured single-ready-unit loop, and a multi-ready-unit graph over the same task set — would answer whether the structure does any work. **Nothing in §4 is that experiment.**



[R6] §5.1 also states why the measurements in §4 cannot carry the claim, more precisely than §16 item 1 does:

> *"End-task success alone is insufficient… Performance gains may result from a stronger foundation model, longer context, additional reasoning samples, or greater computational cost rather than more effective task organization."*

What it asks for instead — **intervention studies, structural ablations, and execution-trace analysis**, over tasks including *"incomplete objectives, concurrent workloads, distributed information, component failures, and environmental changes"* — is the protocol that would turn this proposal from a design into a finding. **Nothing in §4 is an ablation.** Proving the graph does the work, rather than a better model doing it, requires running the same tasks with the structure removed.

## 18. Open questions

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

## 19. References

**Why this section exists:** every claim above that rests on outside work is cited here with its holding location, licence and **reading state**. The next reader — human or agent — should not repeat a search that has already been done, and should be able to see at a glance which sources were actually read.

**Nothing here is authority.** Per the [ADR README doctrine](adr/README.md), external work is provenance. **Reading state is recorded per source and is part of the citation.** *full* = read end to end; *key sections* / *key sections in full* = the sections bearing on this document, read in full; *abstract + mechanism* = abstract plus the mechanism section; *full text held; skimmed* = held locally and skimmed, not studied. A claim may not lean harder than its source's reading state supports.

### Held for this document

`~/claude-memory/maknae/references/_raw/` — study copies, SHA-256 anchored, index at `2026-09-25-graph-driven-activity-sources.md`.

| # | source | licence | read | cited in |
|---|---|---|---|---|
| **R1** | Hu Wei. *From Agent Loops to Structured Graphs: A Scheduler-Theoretic Framework for LLM Agent Execution.* [arXiv:2604.11378](https://arxiv.org/abs/2604.11378), 13 Apr 2026. **Position paper; no empirical results**; 70-system survey; formal state machine. | arXiv non-excl. | **full** | §6.4, §6.5, §6.6, §15.3 |
| **R2** | Anupreet Walia (Brevian.ai). *BatchDAG: LLM-Planned Execution Graphs for Scalable Ad-Hoc Analysis Over Enterprise Data.* [arXiv:2607.18241](https://arxiv.org/abs/2607.18241), 17 Apr 2026. Production self-report, n=12 queries. | **CC BY 4.0** | **full** | §11, §14.1, §16 item 4 |
| **R3** | Del Rosario, Krawiecka, Schroeder de Witt. *Architecting Resilient LLM Agents: A Guide to Secure Plan-then-Execute Implementations.* [arXiv:2509.08646](https://arxiv.org/abs/2509.08646). | arXiv non-excl. | **full** | §6.6, §14.1, §15.4, §15.7 |
| **R4** | Zhang, Ma, Cao, Zhang, Zhao. *Plan-over-Graph: Towards Parallelable LLM Agent Schedule.* [arXiv:2502.14563](https://arxiv.org/abs/2502.14563), 20 Feb 2025. | **full** | §4.6, §14.1 |
| **R5** | Zhang, Chen, Huang, Cui, Ji, Wang. *Atomic Task Graph: A Unified Framework for Agentic Planning and Execution.* [arXiv:2607.01942](https://arxiv.org/abs/2607.01942). | **full** | §14.1 |
| **R6** | Feng, Xiang, Yang, Ma, Chen, Zhang, Huang, et al. *Graph Engineering in the Era of LLM Agents: From Individual Intelligence to System Intelligence.* [arXiv:2608.21156](https://arxiv.org/abs/2608.21156). | **CC BY 4.0** | **key sections** | §13 |
| **R7** | Yue, Bhandari, Ko, Patel, Lin, Zhou, et al. *From Static Templates to Dynamic Runtime Graphs: A Survey of Workflow Optimization for LLM Agents.* [arXiv:2603.22386](https://arxiv.org/abs/2603.22386). | **full** | §13, §14.1 |
| **R8** | Bei, Zhang, Wang, Chen, Zhou, Chen, Li, et al. *Graphs Meet AI Agents: Taxonomy, Progress, and Future Opportunities.* [arXiv:2506.18019](https://arxiv.org/abs/2506.18019). | **full** | §13 |
| **R9** | Anthropic. *[Building effective agents](https://www.anthropic.com/engineering/building-effective-agents)* (engineering blog). Five composable patterns; the workflows-versus-agents distinction. | © Anthropic | **full** | §9.1, §13, §14.1 |
| **R10** | Kim, Moon, Tabrizi, Lee, Mahoney, Keutzer, Gholami. *An LLM Compiler for Parallel Function Calling.* [arXiv:2312.04511](https://arxiv.org/abs/2312.04511), 7 Dec 2023. Reports up to **3.7× latency**, 6.7× cost, ~9% accuracy over ReAct. | **full** | §4.6, §15.5 |

| **R11** | Li, Mallick, Rose, Robertson, Oprea, Nita-Rotaru (Northeastern). *ACE: A Security Architecture for LLM-Integrated App Systems.* [arXiv:2504.20984](https://arxiv.org/abs/2504.20984), **NDSS 2026 — peer-reviewed**. Abstract-Concrete-Execute; abstract plan from trusted information only; concrete plans verified against secure information-flow constraints. Breaks IsolateGPT. | **full** | §6.6, §14.1 |
| **R12** | Jha, Triedman, Wagle, Shmatikov (Cornell + Microsoft). *Breaking and Fixing Defenses Against Control-Flow Hijacking in Multi-Agent Systems.* [arXiv:2510.17276](https://arxiv.org/abs/2510.17276), **ICLR 2026 — peer-reviewed**. Breaks LlamaFirewall-style alignment checks; proposes CONTROLVALVE (permitted control-flow graphs + per-invocation contextual rules). **The closest published prior art to this proposal.** | **full** | §14.1, §15.4, §15.6, §16 item 2 |
| **R13** | Kravchenko, Liventsev, Konstantinov, Iskhakov, Kukuy (Archestra AI). *APPA: Recoverable Information-Flow Control for Real-World LLM Agents.* [arXiv:2607.24625](https://arxiv.org/abs/2607.24625). Dual-phase reference monitor; monotone taint over-blocks or strands. | **full** | §6.6 |
| **R14** | Marcelo Fernandez (TraslaIA). *Agent Control Protocol v1.30: Admission Control for Agent Actions.* [arXiv:2603.18829](https://arxiv.org/abs/2603.18829), draft standard, Apr 2026. History-aware admission; TLA+ model-checked over 4.29e9 states; reports its own v2.0 vulnerability and an evasion against its own risk formula. | **full** | §14.1, §15.8 |

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
| [`references/2026-09-25-jive-assessment.md`](references/2026-09-25-jive-assessment.md) — the graph-call primitive; the provenance standard this document is held to | §Origin, §6.3, §16 item 1 |
| [`references/2026-09-22-system-one-models-jev-assessment.md`](references/2026-09-22-system-one-models-jev-assessment.md) — untested classifier calibration | §6.2 |
| [`design/knowledge-lifecycle-contract.md`](knowledge-lifecycle-contract.md) — object-layer governance; **not current on edges** | §7 |
| [`design/self-development.md`](self-development.md) — PRs are human-gated | §12 |
| Knowledge Lake `references/lake/edges.yaml`, `schemas/edges.schema.json` v1, `lib/lake/_edge_graph.py`, `references/lake/vendors.yaml` | §7.1, §8 |

### Searched and deliberately not pursued

Recorded so the search is not repeated: **OpenAI** (AgentKit, Agent Builder, the Symphony orchestration spec) and **Google** (Antigravity orchestration surface) ship graph-shaped agent tooling but publish no position on plan governance — product, not argument (§13). **LangGraph** is the de facto framework implementation and was not evaluated here. **Classical workflow engines** (Airflow, Luigi, Prefect) are surveyed in R1 (its §2.8) rather than read directly.
