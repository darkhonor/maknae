# Maknae architecture diagrams

The visual catalog. Every diagram here answers **one named question, for one named
reader, in a notation with a citable specification** — so a reader can check the claim
rather than take our word for the notation.

Issue [#196](https://github.com/darkhonor/maknae/issues/196) carries the requirement.

## Regenerate

```bash
python3 design/diagrams/generate.py                                  # all of them
python3 design/diagrams/generate.py generated-agentic-patterns.svg   # just one
```

> **Corrected 2026-09-14 (#314), and this is the correction that matters.** This block used
> to begin with `cargo auditable build … --release` for four binaries, because `dep_closure()`
> — then named `linkage()`, renamed on the second review because the old name asserted an
> artifact read it no longer performs — read `rust-audit-info` off `target/release/<bin>` and
> `sys.exit`ed when one was absent.
> That made **every** diagram — including ones whose only inputs are a TOML file and a git
> sha — require a release build of the whole shipping set. On this project that is a **FIPS
> cryptographic module build**, and on a host whose gcc the module's delocate step cannot
> handle it is not merely slow, it is impossible.
>
> **The code does not require a binary to map.** These diagrams map what the crates deliver
> and where; that question is answered by `cargo metadata`'s resolve graph, from source.
> `dep_closure()` walks `resolve.nodes` from each bin over normal-kind edges only, filtered to
> the host triple. No compilation, no artifacts. **A diagram is not mission-critical code and
> must never inherit its build.**
>
> **This is not the same closure the artifact read produced, and the wording that said so has
> been struck (2026-09-14, second review).** A host-triple resolve is not the per-build
> resolution of a specific release artifact — features, target and profile can differ. It is the
> *intended* source graph, which is what a diagram should show; it is not a substitute for
> per-artifact evidence. See the note under the source-of-truth table for where that evidence
> lives.
>
> The proof this was real rather than theoretical: `maknae-egress` landed in #288 and had
> **never** appeared in the crate×binary matrix, because it had never been compiled on the
> box that last regenerated. Deriving from source put it there immediately.

Python 3 and nothing else — no Mermaid, no Graphviz, no npm, no `xtask`, **and no build**.
`cargo metadata` reads the manifests and the lockfile; it compiles nothing.

Generated diagrams are refreshed **on demand** and **at release, alongside the
documentation site**, so a published image is current as of the release it ships with.
Between releases, the `inputs at <sha>` stamp rendered on each generated diagram tells
you what state it was derived from.

> **The stamp names the INPUTS, not `HEAD`.** `inputs at <sha>` is the last commit that
> touched `ci/gates/lib.sh` or a manifest — the things these diagrams actually read.
> Unrelated commits do not move it, **regeneration is idempotent**, and a reviewer can
> verify by regenerating and getting byte-identical files back.
>
> A `HEAD`-based stamp cannot work here: the commit that *carries* an SVG is always one
> later than the one that produced it, so the stamp chases itself and "regenerate, then
> diff" never comes back clean. `+UNCOMMITTED-INPUTS` means an input was edited but not
> committed — the artifact then came from a state that exists nowhere in history, and
> must not be committed.

## Conformance

| Standard | Version | Release |
|---|---|---|
| UML | 2.5.1 (formal/2017-12-05) | https://www.omg.org/spec/UML/2.5.1/ |
| DoDAF | 2.02 Change 1 | https://dodcio.defense.gov/library/dod-architecture-framework/ |
| IDEF1X | ISO/IEC/IEEE 31320-2:2012 | originally FIPS PUB 184 (withdrawn) |
| Access-control matrix | B. W. Lampson, "Protection" (1971; ACM SIGOPS OSR 8(1), 1974) | https://doi.org/10.1145/775265.775268 |

**Colour is styling, never notation.** UML specifies shapes, line styles and
arrowheads; it says nothing about palette. Nothing in these diagrams requires a
project-private key to read.

**Where Maknae needs something UML does not model, it uses UML's own extension
mechanism.** `«gate:P1»` on a relationship means *a CI gate refuses this*, which is a
different fact from *this does not happen today* — and the gate name greps straight back
to `ci/gates/`. A stereotype is readable by anyone who knows UML; a bespoke glyph is not.

## The catalog

| File | Notation | Question it answers | Reader | Kind |
|---|---|---|---|---|
| `generated-tcb-components.svg` | UML component | *What is in the TCB and where does the boundary run?* | security assessor | generated |
| `generated-crate-binary-matrix.svg` | UML deployment / DoDAF SV-6 matrix | *What can each shipped artifact reach through its dependency graph, and what do the gates refuse?* | security assessor, release reviewer | generated |
| `generated-standards-profile.svg` | DoDAF StdV-1 | *Which technical standards does this claim, and what enforces each?* | security assessor, accreditor | generated |
| `generated-workspace-packages.svg` | UML package | *How do the crates fit together, and what does each pull in?* | contributor, security assessor | generated |
| `generated-read-path.svg` | UML sequence (≈ DoDAF SV-10c) | *Where does a read cross a trust boundary, and by what mechanism?* | security assessor, contributor | generated |
| `generated-credential-path.svg` | UML sequence (≈ DoDAF SV-10c) | *What can each hop see of a user's model key on one turn, and what enforces it?* | security assessor, accreditor | generated |
| `generated-isolation-matrix.svg` | access-control matrix (Lampson 1974) | *Which subject can read, carry or unwrap which user's credential, and by what control?* | security assessor, accreditor | generated |
| `generated-decision-cycle.svg` | UML activity (decision nodes) | *How does each `maknae-authz-*` backend layer into one decision, and in what order?* | security assessor, contributor | generated |
| `generated-data-model.svg` | IDEF1X | *What is the shape of the data we record and enforce?* | security assessor, contributor | generated |
| `generated-system-interfaces.svg` | DoDAF SV-1 | *What talks to what, across which interfaces — and which of them actually exist?* | security assessor, accreditor | generated |
| `generated-operational-concept.svg` | DoDAF OV-1 | *What is this system for?* | stakeholder, newcomer | generated |
| `generated-service-architecture.svg` | UML 2.5.1 deployment view | *What runs on the host, under which account, in which trust plane, and what may talk to what?* | contributor, security assessor | generated — solid is built, dashed is proposed or post-MVP, dotted is **vision: no ADR, no code** (see [below](#the-service-architecture-built-and-vision)) |
| `generated-agentic-patterns.svg` | UML activity partitions | *For each published agentic pattern, what does the trust boundary insert — and where is the deny path the field's diagrams omit?* | contributor, reviewer new to the project | generated — **intent, NOT authoritative** (see [`../intent/`](../intent/)) |
| `plane-architecture.svg` | UML component | *How do the three planes relate?* | onboarding, reviewer | authored |
| `knowledge-lifecycle.svg` | conceptual | *By which route does knowledge enter, and where is it refused or held?* | onboarding | authored |
| `knowledge-position-cards.svg` | bespoke, self-describing | *For a given document and subject: can the agent use it, who must follow it, how much should we believe it — and so what is it good for?* | maintainer, reviewer | authored — **exploratory, not a decision** |
| `tier-state-machine.svg` | UML state machine | *How does an object enter, move between tiers and review hold, and leave?* | reviewer | authored |
| `action-vocabulary-map.svg` | bespoke, self-describing | *What are the supported verbs, which component serves each, and what depends on what?* | contributor, reviewer | authored |

### The Service Architecture: built and vision

`generated-service-architecture.svg` draws Maknae as it installs: host packages (rpm, deb and the macOS .pkg) running as system services under dedicated accounts, `maknaed` as `_maknae` and `maknae-egress` as `_maknae-egress`, under systemd on Linux and launchd on macOS. The only containers in it are tool invocations. A containerized deployment (Compose or Kubernetes) is a possible future option, designed in [`../container-architecture.md`](../container-architecture.md); this view is the baseline it would build from.

Every node, artifact and flow carries a status, and its line style is that status:

- **Solid, built:** the `maknae` CLI, `maknaed`, `maknae-egress`, Vault, `/etc/maknae` and the `/var/log/maknae` audit trail. The CLI is drawn «untrusted»: the same binary runs the MVP agent loop, `maknae agent`, under the operator's uid, who must be in the `maknae` group to reach the `0660` socket. `maknaed` logs in to Vault with its AppRole for its plane certificate; each user's CLI logs in with userpass (`maknae login`) and mints its cli leaf with the user's token; the Egress Daemon has no Vault identity. Shipped code still relays prompt content through `maknaed`, which forwards each `session.prompt` turn to `maknae-egress`.
- **Dashed, proposed or post-MVP:** designed in an ADR, `design/container-architecture.md` or an issue, with no code: the gateway and remote tasker (#117), the lake, the dreamer, skills and lake data. The web UI is post-MVP. The OCI Dockerfiles in `packaging/oci` are a deferred stub (#81), not a deployment.
- **Dotted, vision:** **no ADR and no code.** These elements are unratified: a direction for future capability, not a design that exists. They are the Agent Daemon, tool containers, per-tasker workspaces, the TUI, direct prompt-content delivery to the Egress Daemon, and shared and dedicated modes. No ADR is cited as ratifying them. ADR-0023 (Proposed) decides that the loop is untrusted and is `maknae agent`, and that a separate Rust egress process under `_maknae-egress` makes the model call at the kernel's direction. None of its decisions ratifies the Agent Daemon, tool containers, per-tasker workspaces, the TUI, direct prompt delivery, or shared/dedicated modes.

### Planned

| Product | Notation | Question |
|---|---|---|

## Three kinds, and the rule for each

**Generated** — derived from a source of truth, regenerable, conforms to a cited
notation. Never edit by hand; your edit is lost on the next run.

**Authored, standard-conforming** — hand-drawn because it encodes *intent*, which no
manifest holds. That a descriptor crosses `SCM_RIGHTS` carrying **authority but not
identity** is a design decision, not a derivable fact.

**Bespoke, self-describing** — permitted **only when the diagram carries its own legend
and its subject is enumerable rather than structural**. The test: *can a reader who has
never seen this project understand it without leaving the image?*
`action-vocabulary-map.svg` passes — it names every verb, groups them by the component
they serve, and shows their dependencies. A trust-boundary diagram with private colour
semantics would fail, which is why the TCB view is UML and this one need not be.

## What the generated diagrams derive from

Every rendered fact comes from something that **enforces** it, never from something that
merely describes it:

| Content | Source | Deliberately not |
|---|---|---|
| TCB membership | `ci/gates/lib.sh` — the list P1 polices | `packaging/isolation-contract.md`, a mirror that can agree with itself while both drift |
| Binary dependency reachability | `cargo metadata`'s resolve graph — normal-kind edges, host triple, transitive | a hand-kept list, and `cargo depgraph`'s *declared* (non-transitive) edges |
| Members, binaries | `cargo metadata` | a hardcoded list |
| Standards claims | `standards-profile.toml` — curated, reviewable, every row citing evidence | prose scattered across ADRs |

> **What the matrix claims, and what it does not — narrowed 2026-09-14 on #314 review.** The
> cells are **source-level dependency reachability**: the crate is in that binary's resolved
> dependency closure. They are **not** evidence that the linker retained it. Dead-code
> elimination and features that resolve on but contribute nothing mean a reachable crate may
> put no bytes in the shipped artifact. The stronger claim — what a specific built binary
> actually links — requires `rust-audit-info` on that artifact, and this generator
> deliberately no longer makes it, because no diagram may require a FIPS cryptographic module
> build to draw.
>
> **This costs the assessor nothing, because the matrix was never the enforcement surface.**
> The refused cells come from `TRUST_CONSUMER_ALLOW` in [`ci/gates/lib.sh`](../../ci/gates/lib.sh),
> and that allowlist is policed by [`p1-manifest-lint.sh`](../../ci/gates/p1-manifest-lint.sh) —
> the sole consumer of it — on every run. The adjacent isolation claim, that no
> `PRIVILEGED_CRATES` member is reachable from `UNTRUSTED_BIN`, is decided by
> [`p2-invert-tree.sh`](../../ci/gates/p2-invert-tree.sh).
>
> **Worth noting, because it settles the question rather than conceding it:** `p2-invert-tree.sh`
> reaches its verdict with `cargo tree -i -e normal,build` — *source-level reachability*, failing
> closed on any cargo error. The gate that actually enforces privileged-crate isolation already
> reasons exactly the way this matrix now does. Deriving the picture from the resolve graph brings
> it into agreement with its own enforcement surface; the artifact read was the odd one out.
> **What none of these decide, stated plainly because the earlier wording of this note got it
> wrong (2026-09-14, second review):** neither P1 nor `p2-invert-tree.sh` decides what the linker
> retained. P1 polices manifest membership; P2 runs `cargo tree`. Both are source-level, like this
> matrix. Sending a reader to them "for the linker-level fact" was wrong, and it quietly
> reintroduced the equivalence the rest of this note disclaims.
>
> **Per-artifact evidence has its own path:** [`p2-artifact-witness.sh`](../../ci/gates/p2-artifact-witness.sh),
> run in CI right after the auditable builds. It builds `UNTRUSTED_BIN` with
> `CARGO_PROFILE_RELEASE_STRIP=false`, requires a non-empty `rust-audit-info` inventory
> (fail-closed if absent), and asserts the inventory names no `PRIVILEGED_CRATES` member — plus a
> symbol scan its own comment marks **best-effort and not load-bearing**, because release
> optimization can strip a symbol.
>
> **And even that is resolver metadata**, as the gate's own comment says — embedded at build time
> and optimization-proof *because* it is not a symbol table. So nothing in this repository asserts
> linker retention as such. What `p2-artifact-witness.sh` adds over this matrix is that its
> inventory belongs to **one specific built artifact**, with that build's features and target,
> rather than a host-triple resolve. That is the real difference, and it is the reason the
> per-artifact gate exists alongside the source-level ones. The earlier row in this table asserted
> the opposite and
> was wrong the moment the implementation changed; a source-of-truth table that disagrees with
> its generator is the precise drift this catalog exists to prevent.

### Generation is a manual step, by standing operator decision

Nothing in CI runs `generate.py`, and nothing should. These are built **on demand** —
before a release, or when an input changes — not on every pipeline run. The consequence
is understood and accepted: `check_evidence` and byte-stable regeneration fire for
whoever regenerates, so a stale diagram can be committed and no gate will object.
Regenerate with the command above and commit the result; that is the whole contract.

### Ten products are curated, not derived

`standards-profile.toml`, `read-path.toml`, `credential-path.toml`, `isolation-matrix.toml`, `decision-cycle.toml`, `data-model.toml`,
`system-interfaces.toml`, `operational-concept.toml`, `service-architecture.toml` and `agentic-patterns.toml` are hand-maintained inputs.
A conformance claim, a call sequence, an access-control matrix, a precedence ladder, a normalization judgement,
an interface register, a statement of intent and a deployment inventory are none of them readable out of a
manifest, so all ten are kept as reviewable data files in which **every row names
something a reader can check**.

None of the ten is part of the provenance stamp, deliberately. The stamp names the last
commit to touch an *enforcing* input (`ci/gates/lib.sh`, the manifests); a curated file
travels in the same commit as the SVG it produces, so including it would make the stamp
chase itself and break `regenerate → diff` — the failure [#202](https://github.com/darkhonor/maknae/pull/202)
fixed. The footer of each diagram names its own source file and content hash instead.

### The standards profile is curated, not derived

`generated-standards-profile.svg` renders `standards-profile.toml`. Conformance is a
**claim**, not a fact a manifest holds — no file states that Maknae targets NIST SP
800-53 Rev. 5. Keeping the claims in one reviewable data file, rendered consistently,
beats both prose scattered across sixteen ADRs and a picture nobody can check.

Two rules the file enforces on itself:

- **`status` separates what is mechanically checked from what is merely implemented.**
  `enforced` means CI or the runtime refuses a violation; `adopted` means implemented
  and relied upon but unchecked; `emerging` means the surface is not built yet;
  `excluded` means deliberately out of scope with the decision recorded. **A profile
  that blurs those is a wish list.**
- **`evidence` must name a file, gate or ADR a reader can open.** A claim with no
  evidence does not belong in the profile.

## Adding a diagram

1. Decide which of the three kinds it is, and be honest — "bespoke" needs to pass the
   test above, not merely be easier.
2. If generated: derive it from an enforcing source, and add it to `generate.py`.
3. Add a catalog row: file, notation **and version**, question, reader, kind.
4. Keep the filename stable. These become URLs on the documentation site; renaming one
   breaks published links, so the catalog row — not the filename — is where a changing
   description belongs.
