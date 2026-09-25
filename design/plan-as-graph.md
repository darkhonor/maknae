# A plan as a graph — a design discussion, not a decision

**Status: OPEN DISCUSSION.** Nothing here is ratified and nothing here is a requirement. It follows the register of [`self-development.md`](self-development.md): frame the problem, record what was measured, name the open questions, decide later. It is placed outside [`design/intent/`](intent/README.md) deliberately — it is assembled from measurements, and that directory's placement rule says a document assembled from evidence does not belong there.

**Date opened:** 2026-09-25. **Deciders (eventual):** Alex Ackerman (maintainer).

**Origin.** The [Jive assessment](references/2026-09-25-jive-assessment.md) §2 identified the graph-call primitive as the one transferable idea in that project: separate *deciding the shape of the work* from *doing the work*, so the model is consulted when the shape must change rather than when the next step must be looked up. This document records an experiment on the half of that idea Maknae can use without adopting any of Jive's execution posture — **representing an approved plan as a graph** — and the constraints the experiment found.

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

## What this implies for post-Cooky work

1. **Activity class must be declared at authoring time, not inferred at conversion time.** This is the whole finding. Inferred typing was 67–77% complete and produced three false positives out of five warnings; a structural authorization pass built on that is an authorization pass that lies. A plan that wants to be assessed structurally must be *written* with its node types, which means the schema comes before the tooling, not after it.
2. **The schema is the artifact, not the converter.** A retrofitting parser over existing markdown is a measurement instrument and should be thrown away — this one was. What survives is the node contract: id, activity class *set*, dependencies, declared file scope, and a payload split into instruction / code / expected-output.
3. **Scope rules belong to the plan, not the task.** The `t9` false positive is the general case: a plan has task-local scope and plan-global scope, and a check that knows only one of them is wrong at every boundary.
4. **Do not claim size reduction.** State disclosure cost (what a reader loads) and keep it separate from storage cost (what the plan weighs). They move in opposite directions on code-heavy plans.
5. **The two consumers have different requirements and must not be conflated.** A plan graph for *our development process* is a Claude Code authoring concern. A task graph inside Maknae's runtime loop is a kernel-authorization concern under ADR-0023, where the planner is untrusted by design and a node's activity class would be an input to a PDP decision rather than a convenience for a reader. Evidence gathered for the first does not transfer to the second, and this experiment gathered none for the second.

## If this becomes a Claude Code skill

The skill's job is **authoring plans into the schema**, not converting them afterwards. Concretely: emit the shape layer as the plan is written, require an explicit activity-class set per step, require each task to declare its file scope, reject a step that parses to nothing rather than emitting an empty node, and run the structural checks as a self-review gate before the plan reaches the maintainer. The checks that earned their place in this experiment are cycles, orphans, TDD ordering, and plan-scoped file references. Gate-before-commit should be configurable per plan, because the ceiling plan's batched-gate convention is legitimate and the check as written cannot see it.

## Open questions

- Does the payload split (instruction / code / expected output) hold up on a plan with large expected-output blocks, or does it just move the p90?
- Is the shape layer worth an S-expression over JSON once a schema exists? S-expression won on tokens here; a schema-validated form may not need the margin.
- What is the minimum activity-class vocabulary? Seven classes were used ad hoc (`read`, `write`, `test`, `verify`, `gate`, `commit`, `decide`) and 23–33% of steps still fell through — is that a vocabulary gap or a parsing gap?
- Does a structurally-assessed plan actually reduce execution-time context, or does the executor load most payloads anyway? Unmeasured.

*Artifacts from this experiment were throwaway and are not committed. The plans measured are `2026-09-06-148-154-ceiling-composition.md` and `2026-09-10-276-strike-reserved-agent-token.md` in the maintainer's out-of-repo plan store, per the AGENTS.md rule that specs and plans never live in this repository.*
