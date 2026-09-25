# A plan as a graph — a design discussion, not a decision

**Status: OPEN DISCUSSION.** Nothing here is ratified and nothing here is a requirement. It follows the register of [`self-development.md`](self-development.md): frame the problem, record what was measured, name the open questions, decide later. It is placed outside [`design/intent/`](intent/README.md) deliberately — it is assembled from measurements, and that directory's placement rule says a document assembled from evidence does not belong there.

**Date opened:** 2026-09-25. **Deciders (eventual):** Alex Ackerman (maintainer).

**Origin.** The [Jive assessment](references/2026-09-25-jive-assessment.md) §2 identified the graph-call primitive as the one transferable idea in that project: separate *deciding the shape of the work* from *doing the work*, so the model is consulted when the shape must change rather than when the next step must be looked up. This document records an experiment on the half of that idea Maknae can use without adopting any of Jive's execution posture — **representing an approved plan as a graph** — and the constraints the experiment found.

***Corrected 2026-09-25 (maintainer): the experiment measured the wrong artifact.*** It converted plans that were **born as prose**, so every constraint below that blames *inference* is really a constraint on *retrofitting*. The maintainer's correction is that a plan generated as a graph from birth has no prose to infer from — it states activities to take, not decisions to explain. §"What born-as-graph actually changes" re-measures against that, and it removes two of the three false positives outright while leaving the size finding intact and creating a new obligation the prose was silently carrying.

## The idea in one paragraph

An implementation plan is already a graph: tasks depend on tasks, steps depend on steps, steps touch files. Markdown flattens that graph into a linear document that must be re-read whole to answer any question about it. Splitting the representation in two — a **shape layer** carrying only node ids, activity classes and edges, and a **payload layer** carrying each node's full prose and code, addressed by id — lets a reader load the shape for a few hundred tokens and pull only the payloads it needs. Two properties follow: progressive disclosure during execution, and mechanical queryability of the plan as a whole.

## What was measured

Two real plans from the maintainer's out-of-repo plan store were converted by a throwaway parser, into an S-expression shape layer and a JSONL payload layer. Token counts are `o200k_base`.

| plan | tasks / steps | markdown | shape | payload | shape as % of md | two-layer total vs md |
|---|---|---:|---:|---:|---:|---:|
| `#148/#154` ceiling composition (code-heavy) | 9 / 56 | 54,710 | **991** | 58,089 | **1.8%** | **108%** |
| `#276` strike reserved agent token (docs/ADR) | 6 / 24 | 4,637 | **451** | 3,529 | **9.7%** | **86%** |

Per-node payload on the code-heavy plan: min 46, median 193, p90 2,801, max 5,561 tokens. Shape plus the single heaviest node is 6,552 — **12% of re-reading the markdown**.

### Constraint 1 — the win is disclosure, not size

***Corrected 2026-09-25 (maintainer): the win is neither, primarily — it is focus.*** This section and the table above argue about tokens because tokens are what the experiment could measure. The stated objective is different and it reorders everything below it: **keep the model on the task at hand.** Context economy is a real secondary consideration, and a sharper one for smaller local models than for a frontier model with a large window, but it is not the reason to do this. See §"What the objective actually is".

**For the code-heavy plan the two-layer form is 8% *larger* than the markdown it replaces.** JSONL escaping of fenced code costs more than the raw fences. Any claim that graph representation compresses a plan is false for exactly the plans that most need help. The real number to quote is 1.8% for the shape and ~12% for shape-plus-one-node, and both describe *what you read*, not *what you store*.

### Constraint 2 — payload weight is skewed, and the skew is the design

Median 193 against max 5,561 is a 29× spread. A uniform "load the node" policy is therefore not uniform in cost. This is an argument for splitting payload further — the *instruction* for a step separate from its *code block* and its *expected output* — so an executor deciding whether a step applies never pays for the diff it has not yet chosen to apply.

## What the graph form buys that prose does not

Eight structural checks were run against both graphs: TDD ordering, gate-before-commit, task-without-commit, orphan steps, dependency cycles, unclassified nodes, steps naming files their task never declared, and verify-step placement. These are properties that are *invisible to a prose reader at plan scale and cheap in a graph*:

| property | markdown | shape layer |
|---|---|---|
| orphan / unreachable step | read all 2,610 lines | one traversal |
| dependency cycle | effectively undetectable by eye | topological sort |
| write-before-test across 56 steps | hold 9 tasks in your head at once | one query |
| commit with no gate before it | as above | one query |
| step touching a file outside its task's declared scope | grep and cross-reference by hand | set difference |

All of it runs against **991 tokens**. That is the substantive gain: these checks become cheap enough to run on *every* plan, which is a different claim from being possible at all.

**This is the first half of the two-phase authorization shape the maintainer described (2026-09-25):** an approved plan is assessed *as a whole* for invalid transitions and invalid node activities at authorization time, then each node is re-evaluated against policy *at the moment of execution*. The shape layer is what phase one reads. Nothing here decides that Maknae will do this — [ADR-0023](adr/ADR-0023-runtime-loop-role-and-placement.md) governs the runtime loop and says nothing about graphs — but the experiment says phase one is affordable.

## Constraint 3 — the binding limit is typing quality, and it is severe

**Every check is only as good as the activity class on the node, and inferred classes were wrong often enough to matter.**

Unclassified nodes: **13 of 56** on the ceiling plan (23%), **8 of 24** on strike (33%). An unclassified node is a hole in every query simultaneously — the pass cannot reason about it, and does not say so at the call site.

Of the warnings the checks did raise, verification against the source plans found **two true and three false**:

- **True, but convention-dependent.** Ceiling `t2s3` and `t8s10` are commits with no gate step before them in their task. That is a correct structural fact; whether it is a *defect* depends on the plan batching its gates into Task 9, which it does. The graph found the fact; the judgement needed a convention the graph does not hold.
- **False — a noun read as a verb.** Strike `t3s1` was classified `commit` because its prose says *"retire them in the same commit as their subject."* The step does not commit anything. A regex over prose cannot distinguish an action from a reference to an action.
- **False — the check's scope was wrong, not the plan's.** Ceiling `t9s1`/`t9s5` were flagged for naming files their task never declared. Task 9 is the full documentation-and-gate sweep; it legitimately names files declared by Tasks 1–8, and `maknae-io/src/delegated.rs` appears only as a *pre-existing coverage violation the gate is expected to report*. The rule should have been "no task in the plan declared it," and a file named in expected gate output is not a file touched.
- **Invisible, not false.** Strike's Task 4b parsed to **zero steps** because its single action is a bullet without a `**Step N:**` prefix. It became an empty task node, and the "task with no commit" note on it is an artifact of that. A parser that silently yields an empty node is worse than one that fails.

Two converter defects were also found and fixed mid-experiment, both of which had produced confident wrong output first: a missing key made "task with no commit" fire on 9 of 9 tasks, and single-label classification made `"Green + gates"` — a step that runs both `cargo test` and `fmt`/`clippy`/`mutants` — count as `test` only, which manufactured the gate warnings. **Activity class is a set, never a label.**

## What born-as-graph actually changes

The maintainer's framing: if plans are generated as graphs from birth, the prose never exists, and the plan carries activities rather than arguments. Measured against the same two plans, by payload field:

| plan | prose (`text`) | code / deliverable | structure + names + files | prose share |
|---|---:|---:|---:|---:|
| ceiling (code-heavy) | 5,805 | 44,635 | 3,207 | **11%** |
| strike (docs/ADR) | 2,005 | 0 | 1,388 | **59%** |

**This does not rescue the size finding, and that is the first thing to say.** On the code-heavy plan the prose is 11% of the payload; **83% is code blocks**, which a born-as-graph plan still has to carry byte for byte. Deleting every word of justification leaves the two-layer total at roughly parity with the markdown, not below it. On the docs plan prose is 59%, but most of that prose *is the deliverable* — ADR text to be written — and is therefore code by another name. **The disclosure win (1.8% shape) stands; the compression claim stays dead either way.**

**What it does remove is the typing failure, which was the binding constraint.** Both of these were inference artifacts and cannot occur in a declared-at-birth node:

- **23–33% unclassified.** There is nothing to classify: the node *is* its activity class.
- **The noun-as-verb false positive.** Strike `t3s1` was misread as a commit because its prose said *"retire them in the same commit as their subject."* Written as a graph node, that sentence is not prose at all — it is an **edge**: `:commit-with t3c1`. The ambiguity is not reduced, it is structurally absent.

Hand-converting that one node is instructive about where the gain is and is not:

```
markdown  68 tokens  - [ ] **Step 1:** Delete the whole-`Verb` `SUBJECT_NAME` regression
                       test and `every_verb_for_test`. **Retire them in the same commit
                       as their subject** — a guard that outlives its reason becomes a
                       puzzle for the next reader, and #276's body says so explicitly.

graph     49 tokens  (delete t3s1 :file "crates/maknae-kernel/tests/subject_identity.rs"
                      :items (test:SUBJECT_NAME fn:every_verb_for_test)
                      :commit-with t3c1 :cite #276)
```

**72% of the tokens for 100% of the machine-checkable content.** The saving is modest because identifiers dominate. The actual change is that `:commit-with` is a fact a query can trust and *"in the same commit as"* was a fact a query got wrong.

**This is the maintainer's own cardinal rule applied one level up.** The standing ruling on comments is that the default is no comment and the reasoning lives in the ADR, the issue or the commit message. A plan node obeys the same rule: it states the activity and cites `#276`; the argument for retiring the guard lives in `#276`, where it already did.

### The obligation this creates

**Every judgement the prose was silently carrying has to become a declared field, or the check that needed it becomes unanswerable.** This is the one place born-as-graph makes the problem harder, and it is visible in the two findings it does *not* fix:

- **The gate-before-commit warnings** (ceiling `t2s3`, `t8s10`) were true structural facts whose *disposition* depended on a convention — that this plan batches its gates into Task 9. That convention lived in prose a human reader absorbed. In a graph it must be declared (`:gates-deferred-to t9`) or the check reports a defect that is not one, forever.
- **The `t9` file-scope false positive** is untouched. It was the check confusing task-local scope with plan-global scope, and a file named in *expected gate output* with a file *touched*. No amount of birth-format fixes a rule that asks the wrong question. Scope and file-intent (`:touches` vs `:expects-in-output`) are declared fields too.

The general form: **prose is lossy for machines but lossless for humans, and removing it converts an implicit obligation into an explicit schema field.** The schema's completeness is now the only thing standing between a structural check and a confident wrong answer — which is the same finding as before, relocated from the parser to the vocabulary.

## Schema, profile, witness — three artifacts, not one

*(Added 2026-09-25 from the maintainer's framing: the model defines not only a schema but **required elements** — nodes and edges that must be present for a graph to be declared correct.)*

Collapsing these into one "graph format" is how the thing becomes unbuildable. They have different authority and different change rates.

**The schema is the vocabulary.** What node kinds and edge kinds exist and what fields each carries. It changes rarely, and breaking it invalidates every stored graph.

**The profile is the required-elements set** — what a graph must contain to be correct. `tdd` requires a `verify-red` node between every test node and the implementation it constrains, a gate before every commit (or a declared deferral), and a witness on every verify. `straight` requires far less and is a legitimate choice for someone not yet working that way. `docs-only` requires neither tests nor gates but does require a citation on every claim-bearing node. **One vocabulary, several policies over it, deny-by-default: a graph with no declared profile does not validate.** This is the same separation the kernel already makes between the seam's vocabulary and the policy evaluated across it, and it is worth making for the same reason — the policy is the part that legitimately varies.

**The witness is what was actually observed.** A required node is not an observed node, and this is the distinction the whole idea stands on. A validator can prove a `verify-red` node *exists*; it cannot prove anyone ran it and saw red. Stop at the profile and the result is the markdown checkbox with better syntax — and the checkbox is precisely what fails today, because an agent ticks it. So a node carries the command, the expected result, and the captured actual, bound back to the node at execution time. This is [`ci/gates/negative-control.sh`](../ci/gates/) applied one level up: *a green run that was never observed failing proves nothing.*

Mapped onto the two-phase authorization shape: **phase one reads schema + profile** (is this graph well-formed and does it satisfy its declared discipline), **phase two reads the witness** (did this node's activity actually occur, and is it permitted now).

### The skills are already a profile, written in prose

The strongest evidence that the profile is the right artifact is that one already exists — as English, in the authoring skills, with no enforcement:

| skill prose | the graph element it is | 
|---|---|
| "Run it to make sure it fails" / "MANDATORY. Never skip." | a required `verify-red` node between test and implementation |
| "Expected: FAIL with 'function not defined'" | that node's expected-witness field |
| "**Files:** Create / Modify / Test" | declared file scope, with intent |
| "**Interfaces:** Consumes / Produces" | typed edges between task nodes |
| "No Placeholders — no TBD, no 'add error handling'" | a validator rule rejecting empty-deliverable nodes |
| "Each step is one action (2–5 minutes)" | a node-granularity constraint |
| "one at a time, test each" | an ordering constraint |

**Every one of those is prose whose only function is to make an agent take an activity later — which means it is an activity node, or a rule about one.** In a graph it is present or the graph fails validation; it is not text an executor can skim.

This also explains a property of those skills worth naming: they are long, repetitive and heavily capitalised because **prose has no enforcement and compensates with volume**. A profile needs neither. The reduction is not a side benefit — a rule that is checked does not need to shout.

## Where a profile lives, and how the witness stops being a harness

*(Added 2026-09-25 from the maintainer's design: profiles configured instance-wide, and a witness that is structural rather than evidentiary.)*

### Profiles are configuration, not code

**The directory is `config.d/`, not `conf.d/`** — `docs/configuration.md` §"Who may write the block". Nothing scans a `conf.d`.

The reason the existing surface is the right one is the custody rule already attached to it: a `config.d/` member must be **root-owned and not group/other-writable, and so must the directory**, or boot refuses with `SectionNotRootOwned`. A profile file inherits that property, and it is exactly the property a profile needs — **the subject a plan executes as cannot choose the profile it is judged against.** A home user sets their standard as root; an enterprise ships one in the image. Per-role assignment is then an ordinary `maknae-authz-basic` binding rather than a new mechanism.

**The split follows [ADR-0022](adr/ADR-0022-classification-policy-as-data.md)'s precedent exactly: the schema is compiled in, the profile is boot-selected** — as the level order ships in the kernel while the declared system is chosen at boot. That keeps [ADR-0002](adr/ADR-0002-kernel-is-rust.md)'s "no runtime-patchable policy path" intact: a boot-read profile is configuration in the sense `authz.yaml` already is, not a patchable policy surface.

### The witness is an edge, not a receipt

The maintainer's shape, and it is better than the evidentiary one above: a graph is correct when a verifying activity node sits **directly downstream** of the activity it verifies. The guarantee stops being *"produce proof you did it"* and becomes *"you cannot reach the next node without traversing this one."* That removes the negative-test harness rather than formalising it — and the harness is only tolerated today because agents have been caught reporting actions they did not take.

**The condition that makes it sound: the verify node must be executed by the runtime, not reported by the agent.** The edge proves the node was *traversed*; it cannot prove the result was *honest*. If the agent runs the check and announces the outcome, the arrow changes nothing and this is the checkbox with better syntax — the same failure, restated. If the runtime executes the node and its exit status drives the traversal, the agent is not party to the decision and cannot misreport it. **This is the point at which the graph-call primitive from the [Jive assessment](references/2026-09-25-jive-assessment.md) §2 stops being a token optimisation and becomes load-bearing:** the runtime walking the DAG without returning to the model is what makes a structural witness mean anything.

### Three constraints the shape needs to be expressible

1. **The verifying relation must be its own edge kind.** If any edge satisfies "the verify is connected to the activity," then an ordinary dependency — `write → commit` — satisfies it trivially. A `verifies` edge names its subject and is distinct from sequencing.
2. **"On failure, return to the prior activity" is a cycle, and the acyclicity check rejects it.** As run in this experiment, the cycle check would fail every correctly-formed plan under this design. Retry must be a distinct edge kind excluded from the acyclicity pass, or rule one contradicts rule two.
3. **A back-edge needs a bound and a terminal.** Unbounded retry is a loop: a maximum attempt count on the retry edge and an escalate-to-human terminal node, the same shape the egress budget's retry decisions took in #295.

**On "a single edge":** read as *adjacency* rather than cardinality. Adjacency is the useful constraint — it forbids `set-permissions → commit → check-permissions`, where the verification is real but arrives after the irreversible step. Cardinality should remain *at least one*, because a single `cargo test` legitimately verifies several writes.

### We define the vocabulary; they define the profile

*(Added 2026-09-25, maintainer: the profile is an artifact handed to an enterprise to author for itself.)*

This is [ADR-0004](adr/ADR-0004-modular-authorization-architecture.md)'s shape applied to plan governance — a stable vocabulary with the locally-variable part behind it — and the substitution axis is real, because development discipline genuinely differs between a home user and a regulated enterprise while the set of things a plan node can *be* does not.

**The load-bearing constraint, in the maintainer's terms: a profile cannot authorize an activity that violates policy; it can only enforce local policy on development activities.** Stated in this repository's existing vocabulary, a profile is a **well-formedness contract, not an authorization input** — it is [core principle 2](../AGENTS.md)'s *inform-but-not-authorize* one layer up. A profile can make a plan **invalid**; it can never make a node **permitted**. A graph may satisfy its profile completely and still have every node denied at execution, because validity is decided over graph structure and authorization is decided by the PDP over the activity. **Validity is necessary and never sufficient**, and the two surfaces must not be allowed to collapse into one, or a locally-authored file becomes a path to a grant.

That asymmetry means an enterprise-authored profile can only ever tighten. Which exposes the piece the design still needs:

**The vocabulary must carry a floor — elements no profile may drop.** Otherwise "they define the profile" includes defining one that requires nothing, and the mechanism silently becomes optional. The precedent is directly in hand: ADR-0008 decision 1 makes the ceiling operand a **named, non-removable field** of the `Composition` rather than something a configuration chooses to include. The same construction applies here — a small set of graph elements present in every profile by construction, with everything above the floor left to the authoring organisation.

A profile that demands the impossible is then the organisation's own error, and it fails closed and loudly at validation rather than degrading quietly. That is the correct behaviour, not a gap.

### The trust regress terminates at the TCB, as it already does

*(Maintainer, 2026-09-25, answering "what verifies the runtime?": at some point the platform or the OS is the baseline we resolve to. If verification happens in the platform, it uses OS primitives that have been permitted. Risk surface cannot be removed completely.)*

This is not a new boundary — it is [ADR-0005](adr/ADR-0005-enforcement-locus-tcb-boundary.md)'s, and the answer is that the regress was always going to terminate somewhere and the TCB is where. **What matters is that the verify node executes on the trusted side of a boundary this project already draws**: [core principle 1](../AGENTS.md) says the kernel/trust plane is the only trusted code and *the agent runtime is untrusted by design*. So "the runtime executes the verify node, not the agent" is not an extra control invented for plan graphs — it is the existing TCB boundary applied to one more decision. An agent-executed verification asks the untrusted side to attest to itself, which the architecture already refuses everywhere else.

### Profiles validate at boot, against policy

*(Maintainer: profiles validate at system start; a profile dictating an activity policy denies fails to load, and policy always takes priority over profile.)*

This is the house pattern rather than a new mechanism — `SectionNotRootOwned`, `EgressBoundsRefusal::Undeclared` and the boot bounds gate already refuse at startup and name the file that failed. Two failure classes are worth separating, because the second is the one that earns the boot-time check:

1. **A profile that does not parse.** Ordinary configuration refusal.
2. **A profile that is well-formed but requires an activity policy denies.** A genuine conflict between two authored artifacts, detected at startup rather than at the moment a task runs. This is the valuable half: the operator learns at boot, not at 2am.

**One recommendation against the maintainer's "maybe fails to start if it is the only profile": refuse boot on *any* invalid profile, not only the last one standing.** A partially-loaded profile set means the enforcement posture depends on which file happened to be malformed, and an operator who fixes one typo gets a different posture than the one they believe they have. Silent degradation of *enforcement* is the thing fail-closed exists to prevent, and the cost — a named refusal identifying the offending file, as the existing gates do — is the cost already paid everywhere else in this system. The counter-argument is real and should be recorded: in an organisation with many profiles, an all-or-nothing boot creates pressure to disable validation. That is a maintainer decision, not an agent's.

### Profiles are typed by task, and the type must not come from the agent

*(Maintainer: profiles come per organisation with a type driven by task — `company-TDD` for a coding task, `company-PP` for a slide deck.)*

The selection step is where a hole opens. **If the agent declares its own task type, the agent selects the profile it is judged against** — which is the custody hole the `config.d/` ownership rule closed for the file, reopened at the point of use. It is also precisely what [core principle 2](../AGENTS.md) already forbids in another form: *access is decided by the reference monitor, not by prompt-level markers or content self-labeling.* **A task declaring its own type is self-labeling.**

So the task-type → profile mapping is configuration, held on the same trusted side as the profiles themselves, and **an unmapped task type fails closed rather than falling back to the least restrictive profile.**

### "Bins" — take Jev's approach, and invert its failure direction

*(Maintainer: tasks given to the agent platform have bins that modify the schema or profile used — the useful part of models like Jev is the approach, not the implementation.)*

The approach is sound: classify the incoming task, let the bin select the enforcement shape. The hazard is specific, and this repository already documented it — the [Jev assessment](references/2026-09-22-system-one-models-jev-assessment.md) found a hosted, closed, remotely-versioned probabilistic classifier whose calibration claim no outside party has tested. **A probabilistic classifier choosing which enforcement profile applies means a misclassification silently changes how much rigor is enforced**, which is self-labeling again with a model standing in for the agent.

The inversion that keeps the useful part: **a classifier may propose a bin; it may never relax one.** Concretely — a bin resolves to a profile only when the mapping is configured and confidence clears a declared floor; otherwise the task takes the **most** restrictive profile available, not the loosest. **A classification failure must cost rigor, never remove it.** Under that rule a misclassified slide deck is merely annoying (it gets asked for tests), while a misclassified coding task cannot quietly escape the organisation's TDD profile — and the failure direction, not the accuracy, is what makes an untested classifier tolerable in the loop at all.

## What the objective actually is

*(Maintainer, 2026-09-25, and it reorders the constraints above: this was never fully about context savings.)*

**The target is prose *about* the task, not prose *for* the task.** The distinction is the whole design:

- **Prose for the task** — the code to write, the ADR text to produce, the command to run, the interface a later task consumes. This is the deliverable. A graph carries it unchanged.
- **Prose about the task** — narration, justification, restatement of a decision already made, a reminder to do a thing later, an argument aimed at a reviewer. **A graph has no field for it, which is the point.**

The measurement in §"What born-as-graph actually changes" reads differently under this framing and supports it better than it supported the size argument. Prose is **11%** of the code-heavy plan's payload against 83% code. That 11% is almost entirely prose-about-the-task — and the reason to remove it is not the 11% of tokens, it is **what those tokens do to attention**. A plan that argues its own case invites the executor to re-litigate it; a plan that states activities does not. The maintainer's recorded objection to this author's output has consistently been tokens spent on prose *about* a task rather than prose *for* it, and a schema with nowhere to put the former removes the failure structurally rather than by instruction.

**The secondary consideration is real and should not be dropped:** a 27B-class local model has a materially smaller window and less tolerance for distractor text than a frontier model. Progressive disclosure at 1.8% for the shape layer matters much more there. But it is the second reason, not the first, and a design optimised only for it would be a different design.

## Scheduled and unattended activity — the second consumer

*(Maintainer: the same graph is useful for tracking activities the platform itself runs — cron jobs and scheduled work of the kind OpenClaw or Hermes Agent perform outside a direct operator engagement.)*

This is a genuine second consumer and it stresses the model in ways an authored plan does not:

- **A plan graph is authored, validated, executed, done.** A scheduled-activity graph is **long-lived and partially executed**: node state (pending / running / succeeded / failed / escalated) is part of the artifact, must survive restart, and is the thing an operator inspects when they return.
- **No operator is watching.** The witness matters more here, not less, and the bounded-retry and escalate-to-human terminal stop being pedantic: an unattended back-edge with no bound is an unattended infinite loop.
- **State transitions over a validated graph are an audit trail by construction**, which lines up with [ADR-0019](adr/ADR-0019-audit-record-model.md)'s record model rather than requiring a parallel one.

**And it is where the two-phase authorization earns its shape.** A scheduled graph may outlive the profile and the policy that validated it — authored last month, still executing today, with `authz.yaml` changed in between. Phase one validated the *shape* at authoring; phase two evaluates each node **against policy at the moment of execution**. A node authorized last week is not authorized now by having been authorized then. For unattended work that is not a refinement, it is the only safe reading.

## What a skill is, mechanically — and which half of it belongs in a graph

*(Recorded because it decides what Maknae can define for itself and what it inherits from the model labs.)*

**Observed mechanics.** The harness scans the skill directories, injects **only** each skill's `name` and `description` from its YAML frontmatter as a menu, and injects a full body **only after the model calls the skill tool**. The body is markdown that nothing validates and nothing executes. Its entire effect is that a model reads it and chooses to comply.

**Evidence that the format is convention, not capability:** this workstation carries the same skill set under `~/.claude/skills/` and `~/.codex/skills/` — copied directories, identical `SKILL.md` shape, running unmodified under two independent vendors' harnesses. That portability exists precisely *because* no part of the format is enforced anywhere.

| layer | owner | available to Maknae |
|---|---|---|
| file format, discovery | harness | fully — define anything |
| injection: when, how much, in what order | harness | fully, and a large lever |
| **selection** — which skill applies | **model** | the soft spot |
| **compliance** — whether it is followed | **model** | the crux |

**Both holes in the graph design already exist in `SKILL.md`; they are simply unnamed there.** Selection-by-model is the same self-labeling hole as task-type-declared-by-agent. Compliance-by-model is the unwitnessed checkbox.

**What the labs actually control is the prior, not the protocol.** Any format can be defined and served; what cannot be done is make a model fluent in a format it has never seen. Models are tuned toward conventions in circulation, so a radically novel encoding is followed *worse* even when better designed. The practical consequence for Maknae: **let the graph be the enforcement artifact and render it to the model in a shape models are already fluent in.** The platform validates the graph; what reaches the context window may still be ordinary imperative text generated from it.

### Therefore: a skill is two artifacts wearing one file

- **Knowledge** — what a Fleet bundle is, an RE2 relabeling idiom, how CNSSI 4009 separates policy type from decision model. Prose is correct here; there is nothing to enforce.
- **Obligations** — "write the test first", "watch it fail", "commit". These are **profile rules in prose clothing**.

Today's `SKILL.md` conflates them, and that conflation explains a property of those files worth naming: the TDD skill is long, repetitive and heavily capitalised **because shouting is the only enforcement prose has**. Split on that seam and the obligations move to the profile, where they are checked, and the knowledge stays prose, where it belongs.

The split is forced rather than merely tidy: [core principle 1](../AGENTS.md) holds that the agent runtime is untrusted by design, so **an obligation enforced by the agent is not enforced.** The answer to "LLM or platform?" follows from the posture already adopted — **the platform enforces obligations; the model consumes knowledge.**

## There is not one graph — there are four, and they differ by writer

*(Maintainer, 2026-09-25, naming the set: a kernel-maintained activity graph; ephemeral per-user plan graphs; graphs that govern agent behaviour; and the long-term knowledge graph over the Knowledge Lake.)*

**The useful axis is not purpose but who may write and what a false entry costs.** On that axis the four split two and two, and the two untrusted ones are untrusted for different reasons — which matters, because the mitigations are different.

| graph | writer | trust | lifetime | a false entry causes |
|---|---|---|---|---|
| kernel activity | the kernel alone | **trusted** (TCB) | host lifetime | loss of system integrity |
| governance / profile | operator or organisation, at boot | **trusted** config | boot to boot | wrong enforcement posture, silently |
| user plan | the agent | **untrusted** — authored by the untrusted runtime | ephemeral; retention user-declared | a bad plan, caught by validation |
| lake knowledge | agent-authored and ingested from **external reference sources** (STIGs, NIST, vendor docs) — never from user work product | **untrusted data**; edges quarantined at birth | long-lived, shared | wrong knowledge informs a decision |

The kernel's graph reaching host state and policy-granted restricted areas is consistent with the existing posture, **including the part the maintainer flagged in passing**: the kernel does not bypass policy to do it. [Core principle 2](../AGENTS.md) — *no role or privilege, not even the kernel, bypasses clearance* — applies to the kernel's own graph as it does to everything else.

### The knowledge graph — the KLC and the Lake's shipped model, compared

***Scoped 2026-09-25 (maintainer): the [KLC](knowledge-lifecycle-contract.md) is not current on this; read it against the Knowledge Lake's shipped graph models rather than in place of them.*** An earlier draft of this section rested its claims on the KLC alone, and a first correction replaced it with the Lake's model alone. **Both were wrong in the same way** — the two documents answer different questions and the contrast between them is the finding. **Provenance, never authority** — the Lake is a separate project and its decisions do not bind this repository, per the [ADR README doctrine](adr/README.md); the in-repo rule either model must satisfy is [core principle 2](../AGENTS.md)'s *inform-but-not-authorize*, which stands on its own.

**The KLC governs objects. The Lake's shipped model governs relationships.** That is why the KLC reads stale here rather than wrong: it was written before there was an edge model, so it has no answer to *who may assert a relationship* — and the Lake has no answer to *what happens when the corpus is classified*.

| dimension | KLC (in-repo, object layer) | Lake graph model (shipped, relationship layer) |
|---|---|---|
| unit of governance | the **object** — tier, label, provenance, hash, per document | the **edge**, a first-class authored artifact with its own schema |
| vocabulary | authority tiers, domains, bands, natures — an *authority* vocabulary | six relationship types — a *relational* vocabulary |
| who may write | the agent **may** ingest: gap detection → fetch → quarantine at tier 3 | the agent writes **nothing**; one operator-authored surface |
| provenance | stamped per object at ingest, with hash | **none per edge** — the tracked file and its git history are the provenance |
| enforcement point | policy hooks at retrieval and output | schema validation and compiler rejection at build time |
| integrity construction | the kernel is the integrity root for label state (§6.1) | `writer == checker`: the committed artifact must byte-equal a fresh compile |
| classification | MLS, ceilings, no-read-up / no-write-down, high-water marks | **absent** — an unclassified corpus |

**Three things fall out of the contrast, and they are the reason not to adopt either wholesale.**

1. **The two documents disagree about agent authorship, and Maknae has to choose.** The KLC's learning loop *permits* agent-initiated ingest under quarantine; the Lake's edge model permits **no** agent authoring at all. Those are different answers to the same question, and the difference is not a detail — it decides whether per-edge provenance is required.
2. **Provenance is needed exactly where authorship is delegated.** This resolves a claim this document made two sections ago — that provenance belongs on the edge. It does, *if* an untrusted party may author one. The Lake needs no per-edge field because it removes the antecedent: edges never arrive from outside. **The stronger mitigation is not to let the untrusted party author edges**, and per-edge provenance is the fallback for when that is impossible.
3. **Neither model is sufficient for Maknae on its own.** The Lake's relational layer is the better-engineered artifact and has nothing to say about classification; the KLC has the classification machinery and nothing to say about edges. A knowledge graph in a system with a classification ceiling needs **labels on nodes and on edges** — because a relationship between two unclassified documents can itself be classified, which is the aggregation problem, and neither document addresses it.

### What the Lake's model gets right, and is worth copying verbatim

The authored edge surface (`references/lake/edges.yaml`, schema `edges.schema.json` v1, compiler `lib/lake/_edge_graph.py`) is a working answer to most of what this document has been circling, and it is worth reading before anything is designed here:

- **A closed edge vocabulary of six, and no more:** `supersedes`, `implements`, `governs` (directional), `companion`, `relates_to` (symmetric), `delegates_to`. `additionalProperties: false` and a `const` `schema_version` throughout — the schema is fail-closed, not advisory. A seventh type (`contained_by`) was **YAGNI-deferred by census**, not by taste: one case in the corpus did not earn a vocabulary entry.
- **Targets are opaque UUIDs only, and the pattern enforces it.** The schema's `uuid` regex *structurally rejects* a filename-valued target. This is the sharpest transferable idea in the model: **the schema forbids the wrong thing rather than documenting that it is wrong.**
- **One authored direction; the compiler materializes the typed inverse.** `DIRECTIONAL_INVERSES` derives the reverse edge, and symmetric edges are authored exactly once on a **deterministic canonical side** (lexicographically smaller id). An authored surface that cannot express the same fact two ways cannot drift between them.
- **Derived artifacts are drift-gated by byte equality** — the vendor graph's contract states *the committed artifact must byte-equal a fresh compile (writer == checker)*. The same construction as this repository's content-keyed drift gates.
- **Ids are deterministic, not random:** `uuid5(NAMESPACE_URL, "urn:lake:external:<slug>")`, so two independent builds agree on identity.
- **External stub nodes** let an edge point at an authority the corpus does not hold, with `source_url` required — a reference that does not pretend to be a holding.
- **The compiler rejects self-loops and duplicate authored edges** at build time.

**And the disciplined exception to "a graph has no field for prose":** `delegates_to` **requires** a `scope_note` of at least 8 characters. Exactly one edge type, the one whose relationship is meaningless without saying what was delegated, carries a mandatory note. That is the shape a plan graph should copy — not "no prose ever", but *prose only where the schema makes it non-optional because the edge is unreadable without it.*

For Maknae, finding 2 above reads directly: an agent may *propose* a knowledge edge; the authored surface stays operator-gated, and per-edge provenance is only required if that gate is ever opened.

**Where the maintainer's own example exceeds the current model, honestly:** *"this STIG rule can be implemented by this vendor product in their security document paragraph here"* is an `implements` edge, but the shipped model keys edges to **document ids**, not to a paragraph within one. Sub-document anchors are a real extension, not a configuration — and they are where an id scheme gets hard, because a paragraph anchor must survive the document being reissued.

### Shared substrate, separate vocabularies

`(write t1s3) --verifies--> (test t1s4)` and `(stig-rule) --implemented-by--> (vendor-paragraph)` have nothing in common at the vocabulary level, and forcing one vocabulary across them would produce a vocabulary that fits neither. **What they can share is the substrate**: node identity, typed edges, provenance fields, versioning, and the serialization. That distinction keeps "we define the vocabulary, they define the profile" from becoming ambiguous about *which* vocabulary — there is one substrate and several vocabularies over it, and a profile constrains exactly one of them.

### The governance graph is schema-level, not a fourth instance

The maintainer hedged here (*"likely driven by the profiles specifically — or something else entirely"*), and the hedge is warranted. A profile is a **predicate over graphs**, not a graph of activities: *"a node of kind `write` must have an adjacent node of kind `verify`"* is a subgraph pattern matched against a plan graph. It can legitimately be expressed as a graph — of required patterns — but it is the schema-level artifact, not an instance alongside the other three. **Three instance graphs and one pattern artifact** is the cleaner count.

### The crossings are the design; the graphs are the easy part

Four graphs that never touch would need no thought. Every risk is at a boundary, and the general rule is the standard one: **information may cross up the trust gradient only through validation; authority only ever flows down.**

- **lake → plan.** Knowledge informs planning, under measured access; legitimate, because the plan is still validated against its profile afterwards. **But the validator must never consult the Lake** — that would let ingested content change what counts as a valid plan, which is untrusted data setting policy.
- **plan → kernel activity.** One-way. The kernel may read a plan to execute its verify nodes; a plan may never write the kernel's graph.
- **profile → plan.** Constrains; never populates. A profile that supplies nodes is authoring plans, not judging them.
- **plan → lake.** **Nothing.** *(Corrected 2026-09-25 with the ruling-1 scoping: this said an executed plan "proposes" knowledge to the Lake. It does not propose either — a user's graph is a sink for shared knowledge, never a source of it. What the agent may ingest into the Lake comes from external reference sources, not from user work product.)*

### One conflict to resolve: the plan graph has two retention authorities

The maintainer's model has plan graphs ephemeral, in a per-user store, with **user-declared retention**. The previous section recorded that node state transitions over a validated graph are an audit trail by construction ([ADR-0019](adr/ADR-0019-audit-record-model.md)). **Both cannot govern the same artifact.** A user who declares zero retention would otherwise delete the audit record of what the agent did on their behalf.

Two resolutions, and this is a maintainer call: either the execution record is a separate kernel-retained object that references the plan, or the plan is retained under the audit policy and only its *payload* is subject to user retention. The second is cheaper; the first is cleaner about what an audit record is.

## Maintainer rulings on the knowledge graph (2026-09-25)

**1. Agents may author and ingest.** The stated model is Jarvis: *learn what you do not know and bring it back for use by others.* This settles the disagreement the comparison surfaced — Maknae takes the KLC's posture, not the Lake's operator-gated one.

**2. Provenance is needed exactly where authorship is delegated.** Concurred.

**3. The graph takes from neither model whole.** Concurred, with the maintainer's reason recorded because it is the useful part: *"I built both over time, I've learned and changed opinions as I've experienced both — life sucks at absolutes."* The Lake's relational engineering and the KLC's classification machinery were each right for what they were built against; the composite is what Maknae needs, and neither source is authority for it.

### What rulings 1 and 2 require when composed

They are not independent. **Agents author ⇒ authorship is delegated ⇒ per-edge provenance is mandatory in Maknae's model.** The Lake's answer — *the git history is the provenance* — stops working the moment the author is not a human making a reviewed commit. Five consequences follow, and they are the cost of ruling 1 rather than arguments against it:

1. **Every edge carries who asserted it, from what source, at what authority basis, and when.** The Lake needs no such field; Maknae does, and it is not optional.
2. **An agent-authored edge is born quarantined.** The KLC already has this shape for objects — tier 3, usable to inform the current task's reasoning, never to authorize a privileged action. Applied at edge granularity it is the same *inform-but-not-authorize* line, and it means a freshly-learned relationship can shape retrieval on the turn it is learned without ever deciding anything.
3. **Edges need promotion and demotion, as objects already do.** A path from agent-asserted to operator-confirmed, and a path back when the source is superseded. An edge whose endpoint was superseded is a stale assertion, and nothing currently retires it.
4. **The Lake's `writer == checker` byte-equality gate does not survive unchanged.** It holds because the authored set is human-curated and static between commits. With a growing agent-authored set the invariant becomes *a recompile of the current authored set is deterministic*, not *matches a committed golden* — still a real gate, a different one.
5. **An agent-authored edge is a derived object and takes the high-water mark of its inputs.** The KLC's rule for derived objects already covers this if an edge is treated as one, which it should be.

### Scope of ruling 1, and the flow rules that follow

***Corrected 2026-09-25 (maintainer): this section claimed Jarvis learning creates a cross-user inference channel. It does not, because the architecture forbids the flow that would create one.*** The draft read ruling 1 as platform-wide and concluded that one user's task teaches the system something another user reads. **The Jarvis reference is to the Lake only** — the shared long-term memory for reference material: NIST control sets, STIGs, vendor documentation. Per-user graphs stay per-user, and the platform cannot infer between users across their individual graphs.

**The flows, stated as rules:**

- **external reference sources → Lake.** This is the Jarvis loop, and it is where agent authoring and ingest are permitted. The corpus is reference material, not user work product.
- **Lake → per-user graph.** *Measured* access: shared knowledge informs a user's plan graph, mediated by the kernel.
- **per-user graph → shared.** **No content, but demand crosses** — *(corrected 2026-09-25: this read simply "never", which is wrong and deletes the governed learning loop.)* A task hitting a knowledge gap becomes a **request**, and what subsequently enters the Lake is an external document fetched from an authorized source, never the user's work product. See §"The governed learning loop" below; the distinction that keeps it safe is that the user graph supplies the *demand*, never the *content*.
- **kernel graph → everything.** It constrains all of the above, and **no user sees it or can manipulate it.**

The five consequences of ruling 1 above are unaffected — they concern agent authorship into the Lake, which stands. Three things this scoping changes or sharpens:

1. **Consequence 5 resolves rather than looming.** An agent-inferred edge between two public documents can still take a mark above the Lake's own level, because a relationship can be classified where its endpoints are not. Under these flow rules the answer is not a new mechanism: **an inferred edge whose mark exceeds the Lake's level does not enter the Lake — it stays in the user's graph.** The Lake holds only what flows at its own level, which is the ceiling operand applied to knowledge rather than to a request.
2. **"Measured access" is load-bearing and is the kernel graph's job.** A shared corpus read by subjects at different clearances is a filtered read, not an open one. That is existing machinery pointed at retrieval.
3. **Per-user isolation is a property that must be enforced, not assumed.** "The platform cannot infer between users" is true by construction only if something constructs it. The channels that would break it are ordinary engineering ones rather than exotic: a shared embedding or retrieval index over both users' graphs, a shared cache keyed loosely, or model context carrying residue across turns. **This is what the kernel graph is for**, and it is worth stating as a positive requirement rather than as the absence of an edge.

### The governed learning loop, from [`generated-operational-concept.svg`](diagrams/generated-operational-concept.svg)

*(Maintainer, 2026-09-25, pointing at steps 2 and 3. This is the use case the "never" above deleted.)*

The OV-1 states the loop in six steps, and **step 2 is the control this document had missed**:

| | step | plane | what it establishes |
|---|---|---|---|
| 1 | tasked work | runtime, **untrusted** | the agent hits a knowledge gap while doing real work |
| 2 | **request, never act** | **trust plane** | *"The runtime cannot perform a lifecycle transition. It may only ASK for one."* |
| 3 | **fetch — authorized sources only** | **trust plane** | *"The egress allowlist is the operator's signed authority map. A source not on it is denied."* |
| 4 | quarantine | Tier 3 | all new knowledge — ingested, generated or demoted; may inform work, may not authorize a privileged action |
| 5 | promote, one tier per gate | trust plane | 3 → 2 → 1 on corroboration or operator sign-off; **automation can never raise a ceiling, and there is no path from Quarantine to Doctrine** |
| 6 | authoritative | Tier 1 | applied to the next task |

**Step 2 is why the demand crossing is safe, and it is the same boundary this document has been relying on everywhere else.** The untrusted runtime does not fetch. It asks. The trust plane decides and acts. So a user's task can legitimately drive ingestion into a shared corpus without the user's graph ever being a content source — the runtime contributes a *request*, and the trust plane contributes the *action*.

**Step 3 answers the traffic-analysis channel this section previously flagged, and better than by mitigating it.** The egress is performed in the trust plane against a signed allowlist, so the fetch is decided, constrained and auditable at the point where it happens. The channel is real — a gap detected during a user's task shapes which document gets fetched — but it runs through the one place in the system designed to observe and bound it, rather than out of an untrusted runtime.

**A pre-authorized source list does three jobs, not one**, and the Lake's [`references/lake/vendors.yaml`](https://github.com/mpe-es/knowledgebase/blob/main/references/lake/vendors.yaml) is the worked example — per-vendor authorized URLs, `adobe` → `adobe.com`, `apache` → `apache.org`/`httpd.apache.org`/`tomcat.apache.org`:

1. **Security** — an internet search can be steered to attacker-controlled content; an allowlist keyed to the vendor's own domain cannot.
2. **Legal exposure** — the maintainer's point, and it is not a footnote: a search can land an automated fetcher on a trap or illegal site. An allowlist is the only form of this control that works without a human looking at each result.
3. **Authority basis** — the source determines how far the content may be promoted. This is the axis a search result simply does not have; "found on the web" has no tier.

**This closes an open question this document raised earlier** — *what confirms an agent-authored edge for promotion?* The OV-1's answer is **corroboration or operator sign-off, one tier per gate, automation never raising a ceiling, and no path at all from Quarantine to Doctrine (Tier 0).**

**And the honesty the diagram itself carries, which belongs here too:** it marks the trust plane as BUILT and the entire knowledge lifecycle — Lake, skill registry, tier state machine, promotion pipeline — as NOT YET. *"The kernel that makes the loop safe is substantially real. The loop is not."* Everything in this section constrains what gets built; none of it describes what runs.

### Implication for the plan graph, which is what this document is about

The allowlist is a **profile rule with a natural home**: a plan node that fetches must name its source, and **a fetch node whose source is not on the allowlist is an invalid graph** — rejected at validation, before execution, rather than denied at egress. That is phase-one authorization doing exactly the work it was proposed for, and it composes with the runtime check rather than replacing it: the graph is refused if it *plans* to fetch from an unauthorized source, and the fetch is refused again at the seam if it somehow reaches it.

## What this implies for post-Cooky work

1. **Plans are authored as graphs, not converted into them.** *(Rewritten 2026-09-25 after the maintainer's correction; this read "activity class must be declared at authoring time, not inferred at conversion time," which named the symptom and left conversion on the table as a fallback. It is not a fallback.)* Inferred typing was 67–77% complete and produced three false positives out of five warnings; a structural authorization pass built on that is an authorization pass that lies. The fix is not a better parser — it is that the prose the parser was reading should never have been written. A plan node states the activity, the files, the edges, and cites the issue where the argument lives.
2. **The schema is the artifact, not the converter.** A retrofitting parser over existing markdown is a measurement instrument and should be thrown away — this one was. What survives is the node contract, and the correction above extends it: id, activity class, dependencies, **declared file scope with intent** (`touches` vs `expects-in-output`), **declared plan-level conventions** (where gates run), an issue citation in place of justification, and a payload split into instruction / deliverable / expected-output.
3. **Scope rules belong to the plan, not the task.** The `t9` false positive is the general case: a plan has task-local scope and plan-global scope, and a check that knows only one of them is wrong at every boundary.
4. **Do not claim size reduction.** State disclosure cost (what a reader loads) and keep it separate from storage cost (what the plan weighs). They move in opposite directions on code-heavy plans.
5. **The two consumers have different requirements and must not be conflated.** A plan graph for *our development process* is a Claude Code authoring concern. A task graph inside Maknae's runtime loop is a kernel-authorization concern under ADR-0023, where the planner is untrusted by design and a node's activity class would be an input to a PDP decision rather than a convenience for a reader. Evidence gathered for the first does not transfer to the second, and this experiment gathered none for the second.

## If this becomes a Claude Code skill

The skill's job is **authoring plans into the schema against a declared profile**, not converting them afterwards. Concretely: emit the shape layer as the plan is written, require an explicit activity-class set per step, require each task to declare its file scope, reject a step that parses to nothing rather than emitting an empty node, and run the structural checks as a self-review gate before the plan reaches the maintainer. The checks that earned their place in this experiment are cycles, orphans, TDD ordering, and plan-scoped file references. Gate-before-commit belongs to the profile rather than the checker, because the ceiling plan's batched-gate convention is legitimate and a hard-coded check cannot see it.

The harder half is the witness. A skill that only *emits* a conformant graph has moved the checkbox, not removed it; the executor side has to bind observed output back to the node it claims to satisfy, and a node whose witness is absent is not a passed node.

## Open questions

- Does the payload split (instruction / code / expected output) hold up on a plan with large expected-output blocks, or does it just move the p90?
- Is the shape layer worth an S-expression over JSON once a schema exists? S-expression won on tokens here; a schema-validated form may not need the margin.
- What is the minimum activity-class vocabulary? Seven were used ad hoc (`read`, `write`, `test`, `verify`, `gate`, `commit`, `decide`). The 23–33% fall-through was a parsing gap and is answered by authoring at birth; what is **not** answered is whether seven classes are enough to express a real plan without a `misc` escape hatch — and a `misc` node is an unclassified node wearing a badge.
- Does a structurally-assessed plan actually reduce execution-time context, or does the executor load most payloads anyway? Unmeasured.
- How many profiles are actually needed, and who authors one? A profile per team is governance; a profile per plan is a loophole.
- Where does the bin's confidence floor come from, and who may set it? A floor the classifier's own vendor sets is not a floor.
- A long-lived scheduled graph accumulates node state. Is that state in the graph or beside it? In it, and the artifact is no longer immutable; beside it, and the two can disagree.
- If obligations move out of `SKILL.md` into a profile, what stops a skill from re-stating them in prose anyway? A rule with two homes drifts, which is the failure this repository already records for comments and issue bodies.
- Does a `verifies` edge need to assert *what* was verified, or only *that* verification ran? Naming the subject makes the check stronger and the authoring burden higher.

*Artifacts from this experiment were throwaway and are not committed. The plans measured are `2026-09-06-148-154-ceiling-composition.md` and `2026-09-10-276-strike-reserved-agent-token.md` in the maintainer's out-of-repo plan store, per the AGENTS.md rule that specs and plans never live in this repository.*
