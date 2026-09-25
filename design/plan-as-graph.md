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
2. **The platform executes the validating node, not the agent.** Adjacency alone proves *traversal*, never *honesty* — if the agent runs the check and announces the outcome, the arrow changes nothing and this is the markdown checkbox with an edge drawn on it. When the platform executes it and the exit status drives traversal, the agent is not party to the decision. On failure the traversal returns to the prior activity node; it passes or it does not.

**This is where the graph-call primitive from the [Jive assessment](references/2026-09-25-jive-assessment.md) stops being a token optimisation and becomes load-bearing** — a runtime that walks the graph without returning to the model is what makes property 2 true.

**The trust regress terminates at the TCB, as it already does.** At some point the platform resolves to OS primitives that have been permitted; risk surface cannot be removed entirely. This is [ADR-0005](adr/ADR-0005-enforcement-locus-tcb-boundary.md)'s boundary, not a new one. What matters is that validation executes on the trusted side of a line this project already draws: [core principle 1](../AGENTS.md) holds the agent runtime untrusted by design, so **an agent-executed validation asks the untrusted side to attest to itself.**

**Three constraints for expressibility:**

1. **The verifying relation is its own edge kind.** If any edge satisfies "the validation is connected to the activity", an ordinary `write → commit` dependency satisfies it trivially. A `verifies` edge names its subject.
2. **"On failure, return to the prior activity" is a cycle.** An acyclicity check would reject every correctly-formed plan. Retry is a distinct edge kind excluded from that pass, or rule one contradicts rule two.
3. **A back-edge needs a bound and a terminal** — a maximum attempt count and an escalate-to-human node, the shape #295's retry decisions took. Unattended work (§5.2) is where this stops being pedantic.

**"A single edge" reads as adjacency, not cardinality.** Adjacency forbids `set-permissions → commit → check-permissions`, where the validation is real but arrives after the irreversible step. Cardinality remains *at least one*: one `cargo test` legitimately verifies several writes.

### 6.4 The two phases

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
- **Targets are opaque UUIDs and the pattern enforces it.** The regex *structurally rejects* a filename-valued target. The sharpest transferable idea in the model: **the schema forbids the wrong thing rather than documenting that it is wrong.**
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

**The harder half is execution.** A skill that only *emits* a conformant graph has moved the checkbox, not removed it. The validating nodes have to be run by the platform walking the graph, not by the agent reporting on itself — and that half is a Maknae concern, not a skill-authoring one.

## 12. Open questions

- Does the payload split (instruction / deliverable / expected output) hold on a plan with large expected-output blocks, or does it just move the p90?
- Is an S-expression shape layer worth it over JSON once a schema exists? It won on tokens here; a schema-validated form may not need the margin.
- What is the minimum activity-class vocabulary? Seven were used ad hoc (`read`, `write`, `test`, `verify`, `gate`, `commit`, `decide`). Authoring at birth answers the fall-through rate; it does not answer whether seven suffice without a `misc` escape hatch — and a `misc` node is an unclassified node wearing a badge.
- Does a structurally-assessed plan actually reduce execution-time context, or does the executor load most payloads anyway? Unmeasured.
- How many profiles are needed, and who authors one? A profile per team is governance; a profile per plan is a loophole.
- Where does a bin's confidence floor come from, and who may set it? A floor the classifier's vendor sets is not a floor.
- Does a long-lived scheduled graph hold node state **in** the artifact (no longer immutable) or **beside** it (the two can disagree)?
- If obligations move out of `SKILL.md` into a profile, what stops a skill restating them in prose anyway? A rule with two homes drifts — the failure this repository already records for comments and issue bodies.
- §5.3's retention conflict.

*The plans measured are `2026-09-06-148-154-ceiling-composition.md` and `2026-09-10-276-strike-reserved-agent-token.md` in the maintainer's out-of-repo plan store, per the AGENTS.md rule that specs and plans never live in this repository. The conversion artifacts were throwaway and are not committed.*
