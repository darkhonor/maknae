# Maknae architecture diagrams

The visual catalog. Every diagram here answers **one named question, for one named
reader, in a notation with a citable specification** — so a reader can check the claim
rather than take our word for the notation.

Issue [#196](https://github.com/darkhonor/maknae/issues/196) carries the requirement.

## Regenerate

```bash
cargo auditable build -p maknaed -p maknae -p maknae-spifc --release
python3 design/diagrams/generate.py
```

Python 3 and nothing else — no Mermaid, no Graphviz, no npm, no `xtask`. The build step
is what `rust-audit-info` reads; both tools are already CI tooling
(`.github/workflows/ci.yml`).

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
| `generated-crate-binary-matrix.svg` | UML deployment / DoDAF SV-6 matrix | *What does each shipped artifact actually link, and what do the gates refuse?* | security assessor, release reviewer | generated |
| `generated-standards-profile.svg` | DoDAF StdV-1 | *Which technical standards does this claim, and what enforces each?* | security assessor, accreditor | generated |
| `plane-architecture.svg` | UML component | *How do the three planes relate?* | onboarding, reviewer | authored |
| `knowledge-lifecycle.svg` | conceptual | *How does knowledge move through the lifecycle?* | onboarding | authored |
| `tier-state-machine.svg` | UML state machine | *How does a skill move between tiers?* | reviewer | authored |
| `action-vocabulary-map.svg` | bespoke, self-describing | *What are the supported verbs, which component serves each, and what depends on what?* | contributor, reviewer | authored |

### Planned

| Product | Notation | Question |
|---|---|---|
| workspace + key externals | UML package | *How do the crates fit together; what do we depend on?* |
| runtime boundary crossings | UML sequence (≈ DoDAF SV-10c) | *Where does data cross a trust boundary, by what mechanism?* |
| audit / policy / config schemas | IDEF1X | *What is the shape of the data we record and enforce?* |
| system interfaces | DoDAF SV-1 | *What talks to what, across which interfaces?* |
| operational concept | DoDAF OV-1 | *What is this system for?* |

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
| Binary linkage | `rust-audit-info` on the built artifact — the real transitive closure | `cargo depgraph` — declared dependencies are not what a binary links |
| Members, binaries | `cargo metadata` | a hardcoded list |
| Standards claims | `standards-profile.toml` — curated, reviewable, every row citing evidence | prose scattered across ADRs |

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
