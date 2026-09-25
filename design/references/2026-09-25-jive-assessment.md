# Jive — Assessment Against Maknae's Runtime Loop

| | |
|---|---|
| **Status** | Assessment record — informs the runtime loop (#241, merged) and post-Cooky tool work. **No dispositions ratified; no team decisions taken.** Candidate follow-ups are named in §7. |
| **Date** | 2026-09-25 |
| **Subject** | [`merijjeyn/jive`](https://github.com/merijjeyn/jive) — a terminal coding agent that replaces the LLM→tool-call loop with an LLM→**graph**-call loop: the planner emits a DAG of `bash` and `jev` nodes, and the runtime executes it without returning to the LLM between steps. MIT, TypeScript/Bun, single author, first commit **2026-09-18** (one week old at time of reading). |
| **Method** | Read-only. Cloned at `c88105f` (2026-09-24, 50 commits, one contributor) and read the source, `DESIGN.md`, `docs/GRAPH_CONTRACT.md`, `docs/USAGE.md`, the `taskground` harness and the test tree. **Nothing was executed and nothing was measured by us**; every performance number below is the author's. |
| **Audience** | Maknae team (dual-audience: human reviewers and AI agents) |
| **Purpose** | The maintainer asked for a survey: what Jive did well, where its approach is flawed, and what Maknae can learn. |

## 1. Provenance disposition (read first)

**One author, one week, zero external validation.** No third-party review, no independent benchmark, no users beyond the author. The benchmark table in the README is the author's own runs of the author's own task definitions against the author's own agent. That is not disqualifying for a design read — it is disqualifying for treating any number in it as evidence.

Jive also sits on top of **Jev**, which this repository already assessed on 2026-09-22 (`design/references/2026-09-22-system-one-models-jev-assessment.md`). That assessment's finding holds and is load-bearing here: Jev is a hosted, closed, remotely-versioned probabilistic classifier whose headline calibration claim no outside party has tested. Everything Jive attributes to "System One decisions" inherits that provenance.

## 2. The headline

**The graph-call primitive is the real idea and it is a good one. Everything Jive builds around it is the opposite of Maknae's posture, and correctly so for what Jive is.**

Jive's insight: in a conventional agent loop, most LLM turns are not reasoning — they are *bookkeeping*, the model re-reading a plan it already made to decide which step comes next. Jive makes the planner emit the whole conditional program once, then executes it. On the author's `product_matching` task that is **9 LLM calls for 299 tool calls**; a conventional agent spent 48 LLM calls on 47 tool calls.

That ratio is the contribution. It is independent of Jev, independent of TypeScript, and independent of every security property Jive lacks.

## 3. What Jive does well — LEARN FROM

- **Separating "decide the shape of the work" from "do the work."** One planner turn produces a DAG; the runtime walks it. The LLM is consulted when the *shape* must change, not when the next step must be looked up. This is the single transferable idea.
- **Editing a plan by pointer rather than resending it.** `execute_graph_mod` edits a saved graph by JSON pointer and re-executes, so fixing one node in a 300-node graph does not cost a 300-node re-emission. A cheap, obvious win that most agent frameworks do not have.
- **Streaming commit of graph entries.** Each fully-closed root entry commits while the tool arguments are still streaming, with dependency-ordered commit and whole-graph validation at the end. Execution starts before the planner has finished speaking.
- **A reusable, in-repo comparison harness.** `taskground/` defines eleven tasks with fresh workspaces and runs Jive, Codex and Claude Code through the same definitions. Shipping the harness rather than only the numbers is better practice than most projects that publish benchmarks — see §4 for why it still does not make the numbers evidence.
- **Honest framing of its own limits.** The README says plainly that it is "fighting the model's training," that other agents are better at some tasks, and "I'm not sure if this is it." That is more calibrated than the "Agent 2.0" banner suggests.
- **30 test files / 5,667 lines against ~98k lines of source, in week one.** Including offline fixture-only tests that need no API keys.

## 4. Flaws in the approach — AVOID

**The benchmark numbers are not evidence.** `taskground/task_runs/` is **empty** — the published table is not reproducible from the repository. There is no repetition count, no variance, no median, no n. Single runs of LLM-driven agents on tasks authored by the same person who authored the agent, with wall-clock as the headline metric. The harness is genuinely reusable; the numbers in the README are an anecdote with a table around it.

**The trust model is "none," and it is not stated as a decision.** `src/core/process.ts:25` is `spawn("bash", ["-c", script], { env: { ...process.env, ... } })` — the planner's text becomes a shell command with the operator's full environment inherited. There is no approval prompt, no allowlist, no sandbox, no confirmation path anywhere in the tree. The single occurrence of the word "sandbox" in the repository is `docs/USAGE.md:236` stating that extractors are **not** sandboxed.

**Extractors are the sharp edge.** By design (`DESIGN.md`): extractors "may run commands and access the network," and "adding an extractor should be easy enough for the agent itself to write one during a task and then use it." So the agent authors new unsandboxed code at runtime, from model output, and executes it. In Maknae's vocabulary this is content authorizing its own execution — the exact inversion of inform-but-not-authorize.

**A hard dependency on one closed hosted API.** `src/jev/client.ts:79` posts to `https://api.typesafe.ai/v1/systemone`. There is no local model path and no offline decision path. The "think fast" half of "think fast and slow" is a paid remote call to a single vendor's early-access endpoint, in the execution path of every graph that uses it.

**The premise is bet on an unvalidated class of model.** The README's forward argument is that the gap widens "as models get better, and System One Models get better, and we slowly get into the training set." Two of those three are outside the author's control and the second rests on a calibration claim nobody has independently tested.

**Failure semantics are shallow for something executing 299 commands unattended.** A failed node blocks its dependents while independent branches finish, and a failed Jev decision returns to the planner by default. There is no transactional boundary, no compensation, and no dry-run. A graph that is half-applied to a filesystem is simply half-applied.

## 5. Where Jive and Maknae are structurally incompatible

| | Jive | Maknae |
|---|---|---|
| Trust boundary | none — planner output reaches `bash -c` directly | the agent runtime is untrusted by design; `maknaed` is the sole PDP ([ADR-0005](../adr/ADR-0005-enforcement-locus-tcb-boundary.md)) |
| Decision authority | model output selects and executes | content may inform, never authorize |
| Decision path | network call to a hosted classifier | deterministic composition of operands, no network |
| Extensibility | agent writes and runs new plugins mid-task | extensibility surfaces are attack surface; adding one is a security decision ([ADR-0002](../adr/ADR-0002-kernel-is-rust.md)) |
| Failure | fail-open with partial application | deny-by-default, fail closed everywhere |

**None of this means Jive is badly built.** It is a local single-operator developer CLI with the same posture as Codex or Claude Code, and for that audience the posture is defensible. It means the *architecture* is separable from the *primitive*, and only the primitive travels.

## 6. What transfers to Maknae — APPLICABLE

**A. Batch the plan, not the step — subject to the PDP on every action.** Maknae's runtime loop (#241) is a conventional turn loop today. A graph-shaped turn would let one model turn describe many actions, cutting round-trips on exactly the bulk work Jive is fastest at. **The precondition is absolute: every node still goes through `combine`+`finalize` at execution time.** A graph is a *proposal*, and a batched proposal must not become a batched authorization. This is the one idea worth a design discussion; it is also the one where getting it wrong would be a TCB defect rather than a performance regression.

**B. Plan edit by reference.** If Maknae ever emits multi-step proposals, editing by pointer rather than resending is free efficiency with no security content.

**C. The ratio as an instrument, not a target.** LLM-calls-per-action is a useful diagnostic for the runtime loop. Worth measuring on Maknae's own traces; not worth optimising toward, because the PDP call per action is not the cost being removed.

**D. Ship the harness with the numbers.** `taskground`'s shape — task definitions, fresh workspaces per run, the same definitions across agents — is a decent model for anything Maknae publishes comparatively. With `n`, variance and recorded runs, which Jive omits.

## 7. Open questions

1. Does a graph-shaped turn survive per-action PDP evaluation without the PDP becoming the new bottleneck it was meant to avoid? Unknown; measurable once #241's loop has traces.
2. Is there any Maknae analogue of a "fast" decision that is *not* a network call and *not* a model? The classification-ceiling operand already is one — deterministic, in-kernel, one attribute. That is closer to what Jive wants from Jev than Jev is.
3. Would a batched proposal change the audit record's shape, and does the append-only sink still give one entry per decision?

## 8. Sources

- `merijjeyn/jive` @ `c88105f`, read 2026-09-25: `README.md`, `DESIGN.md`, `docs/GRAPH_CONTRACT.md`, `docs/USAGE.md`, `docs/CONTEXT.md`, `src/core/process.ts`, `src/jev/client.ts`, `taskground/`, `tests/`.
- `design/references/2026-09-22-system-one-models-jev-assessment.md` — the Jev provenance finding this assessment rests on.
