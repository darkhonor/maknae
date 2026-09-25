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
- Does a `verifies` edge need to assert *what* was verified, or only *that* verification ran? Naming the subject makes the check stronger and the authoring burden higher.

*Artifacts from this experiment were throwaway and are not committed. The plans measured are `2026-09-06-148-154-ceiling-composition.md` and `2026-09-10-276-strike-reserved-agent-token.md` in the maintainer's out-of-repo plan store, per the AGENTS.md rule that specs and plans never live in this repository.*
