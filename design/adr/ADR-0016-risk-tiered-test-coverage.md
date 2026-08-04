# ADR-0016: Risk-tiered test coverage — objective, fail-closed evidence that security-critical code is tested

- **Status:** Accepted (operator-ratified 2026-08-04)
- **Date:** 2026-08-04
- **Deciders:** Alex Ackerman (operator), Byeori (Claude Fable 5, pair)
- **Addresses:** issue #24 (risk-tiered coverage policy), operator-directed
- **Source spec:** `~/claude-memory/maknae/specs/2026-08-04-coverage-tiers-design.md` (v18; converged through 17 critical-review rounds, 48 criticals remediated)
- **Provenance (never authority, per the ADR README doctrine):** the operator's prior standards in MPE-ES (tiered-testing model) and Microkosmos (runner-readiness "verify before run") informed this design; every rule below is decided here.

## Context

Maknae's catastrophic failure mode is not a crash — it is a **fail-open access decision or a silently widened label**: false assurance. A flat coverage number lets a healthy project average sit on top of an under-tested reference monitor. Coverage rigor must scale with how security-critical the code is, and the evidence must be objective and mechanically collected: our proof that this codebase is not AI slop is the testing. Where something genuinely cannot be tested, that is documented, anchored, and justified — never silently skipped (operator directive).

## Decision

**The line-drawing rule** (the authority for tier assignment — never a file's crate or directory):

> If this code silently breaks, can the engine return `Permit` for an access policy denies, derive a label less restrictive than its sources, or emit false assurance? Yes → T1.

**Tiers and bars** (enforced by `ci/gates/coverage-tiers.sh` + `ci/gates/coverage_check.py` against the machine-readable contract `coverage-tiers.toml` at the repo root):

| Tier | Bar |
|---|---|
| T1 security-critical | ≥95% **production-region** coverage per file + crate mutation gate: `cargo mutants` **zero missed** (TIMEOUT = investigate-failure, never ignored) |
| T2 standard | ≥90% production-region per file + cohort ratchet |
| T3 report-only | No floor; membership per-file with a written justification, never a blanket glob. T3 exempts a file from floors — not its crate from mutation |

**Mutation testing is risk-based and exists for external provability** (operator, 2026-08-04): MLS/DCS/security-critical crates (`mutants_crates`, initially `maknae-dcs-core`) must be provable to external third parties as fail-closed and policy-exact. Coverage says the code ran; killed mutants say the tests would notice if it lied.

**The metric, precisely.** Region coverage from `cargo llvm-cov --workspace --all-features --json` on the pinned toolchain, schema-asserted (export type/major-version/arity), bucketed per file via `file_id`, deduplicated by region tuple, merged any-nonzero, `kind == 0` only. **Production-region** = regions before the file's single column-0 `#[cfg(test)] mod` marker (which must extend to end-of-file; multiple/misplaced markers and zero-production files are hard failures) — Rust's in-file unit tests otherwise inflate the denominator 1.6–5×, letting production sit at 88% while the file reports 97%. This gate metric intentionally diverges from `cargo llvm-cov`'s per-file summary (which dedups function records); the baseline table shows all three numbers so nothing is conflated. Branch coverage is **omitted from the gate entirely**: `--branch` is nightly-only and a stable run emits a false `branches: 0%`; the mutation gate is the stronger semantic instrument, and chasing branch arms mutation proves behavior-inert produces valueless tests. Recorded as a revisit point, not a permanent stance.

**The fail-closed partition.** Every git-tracked `*.rs` file in the repository, outside the segment-aware instrument excludes (member-level `tests/`, `benches/`, `examples/`, `build.rs`), must resolve to exactly one tier. Unclassified, stale, double-classified, or (non-T3) absent-from-coverage = hard failure — new code cannot silently dodge the gate.

**The cohort ratchet.** The project floor applies to an explicitly recorded cohort (currently the four `maknae-dcs-core` T1 files), production regions only — a raw aggregate over a growing mixed-tier set would spuriously block the first conforming T2 landing. Re-baselining is deliberate, with mandatory typed provenance (`value/date/lane/command` — real TOML keys the gate validates). Floors move up freely; a deletion-consequential recompute is exempt from ceremony; **discretionary lowering requires an amendment to this ADR**. The gate mechanically enforces provenance *shape*; distinguishing consequential from discretionary lowering is a human review-time control — stated as such.

**Documented exceptions** (documented-not-tested): a line span may leave a file's denominator only via an anchored `[[exception]]` entry with a non-empty `Why`-equivalent; the gate fails closed on zero/multi-match anchors, non-instrumentable (zero-region) anchors, and stale (all-covered) spans, and prints the removed-region count so reviewers see the carve-out size. Never a dodge for testable logic.

**Runner readiness** (decided here; Microkosmos/MPE-ES provenance): verify-then-run. Every readiness item is a presence/version check — never a stage's own work — stage-scoped to what the invocation selects, with copy-paste install commands on failure and advisory-only lines for unselected stages (the opt-in pre-push hook must not hard-fail a developer over a tool for a stage it doesn't run). CI provisions, then verifies the same way.

**Environment-dependent coverage:** signal-interpretation logic must be unit-testable against synthetic fixtures and counts toward the floor (testing your own logic on invented data is not gaming; asserting real-world facts from fake data is, and is forbidden). Real-environment integration tests are env-gated and skip cleanly. Genuinely un-instrumentable-on-CI code uses the `env_bound` discriminator (closed grammar, native-lane-enforced) — never a silent carve-out. The authoritative measurement lane is CI (ubuntu-latest); other hosts get an advisory.

**Enforcement surfaces:** the gate runs in CI (fixture suite first — 87 fixtures: 81 forced-failure modes with mode-identifying assertions plus 6 pass-path/positive cases, including four live-root modes and per-exclude-glob positive/near-miss pairs — then the live gate), as an **opt-in** pre-push hook (`git config core.hooksPath ci/hooks`; "lead a horse to water" — CI is the enforcement of record), and the change-gated mutation job (always starts, SKIPs unless `MUTANTS_PATHS` paths changed, unconditional on push to `main`). The workflow-sync check makes contract↔workflow drift a gate failure.

**Resolved decisions recorded:** opt-in pre-push (operator); risk-based mutation scope (operator); runner-readiness model (operator); pinned-toolchain/branch-omission (operator); scaffold stubs = T3 with per-file justification, re-tiered at body landing (`bins/maknaed/src/main.rs` and the privileged-capability crates are named T1 candidates). Editing rule: per the ADR-0001 amendment landed with this change (cited, not declared here) — a `Proposed` ADR is editable in place; an `Accepted` ADR is append-only.

## Consequences

- The coverage step adds a second full instrumented build+test run to CI plus tool installs (~minutes); the fixture suite's live-root modes add three small instrumented builds; the mutation job pulls its own toolchain when triggered. Accepted: the gate is the SA-11 evidence. A binstall/tool-cache optimization, the isolation-contract negative-control gap, and line-level diff coverage are **named follow-ons**.
- The workspace coverage build does NOT establish isolation (the same caveat ci.yml records for `cargo test --workspace`).
- **Marking the mutation job a required status check is an operator repo-settings action outside this deliverable.**
- Supersessions: `design/container-architecture.md` "mutation runs are scheduled, not per-commit" and ADR-0002's "scheduled mutation testing" control-mapping phrase (amended append-only) are superseded by the change-gated per-PR + unconditional-on-main model; `design/abac-dcs-architecture.md` mutation-gating references now point here. ADR-0008's "mutation gate owed as a wired CI step" is CLOSED by this deliverable (both sites updated). Issue #24's "dogfooded to its own bar" phrasing is superseded: the gate tooling is verified by forced-failure fixtures (stronger evidence for a ~200-line helper than a percentage), and sits outside the Rust coverage universe — stated, not silent.
- A test-only module in its own file (`src/tests.rs`-shaped, no marker) would read as production; the tier-assignment review must catch that shape (review-time rule).

## Baseline of record

Refresh rule: re-measure on the CI lane and update this table + the toml provenance when coverage materially changes; every column carries value/date/lane/command provenance. Initial adoption baseline — **measured on the authoritative CI lane (ubuntu-latest, adoption PR #37, actions run 30872039077, 2026-08-04)**; every column from the same gate invocation (`bash ci/gates/coverage-tiers.sh --root .` in `build-and-gate`): production-region and gate-full-file computed by `coverage_check.py`; llvm summary from the coverage JSON's `files[]` summaries. The darwin/aarch64 dev host measured identically (no `cfg(target_os)` code exists yet):

| File (T1) | Production-region (record) | Gate full-file | llvm summary |
|---|---|---|---|
| `crates/maknae-dcs-core/src/decide.rs` | 98.85% (86/87) | 99.78% (462/463) | 99.35% (460/463) |
| `crates/maknae-dcs-core/src/label.rs` | 96.72% (383/396) | 97.62% (1190/1219) | 97.21% (1185/1219) |
| `crates/maknae-dcs-core/src/policy.rs` | 100.00% (95/95) | 97.02% (228/235) | 97.02% (228/235) |
| `crates/maknae-dcs-core/src/subject.rs` | 100.00% (17/17) | 100.00% (51/51) | 100.00% (51/51) |

Cohort ratchet: 581/595 = 97.65% → floor **97**. Mutation gate (`maknae-dcs-core`): **zero missed at adoption — 104 mutants, 91 caught, 13 unviable (darwin/aarch64 dev host, `bash ci/gates/coverage-tiers.sh --root . --mutants-all`, 2026-08-04)**; the authoritative ubuntu run of the same obligation lands on the post-merge push to `main`.

## Security control mapping (informative; per ADR-0001)

Assessor framing: the gate upgrades access-enforcement testing evidence from procedural attestation to mechanically-collected, AO-inspectable artifacts — the coverage JSON is uploaded on every CI run that reaches the coverage step (red or green at that step; an earlier-step failure means no coverage ran to upload), and the fixture suite proves every failure mode of the gate itself fires.

| Concern | Property | NIST SP 800-53 rev 5 | Evidence |
|---|---|---|---|
| Developer testing | Tiered floors + fail-closed partition + forced-failure fixtures | SA-11, SA-11(1) | `ci/gates/coverage-tiers.sh` + CI `coverage-json` artifact |
| Test-the-tests | Risk-based mutation, zero missed, change-gated + unconditional on main | SA-11(5) analog | mutation job logs |
| Baseline configuration | Pinned toolchain + readiness verify-then-run + tool version pins | CM-2, CM-6 | `rust-toolchain.toml`, readiness output |
| Config-as-contract | `coverage-tiers.toml` single machine-readable tier authority + workflow-sync | CM-6 | the contract + sync check |
| Secure development | SSDF PW.8 (test executable code); ASVS L1-L3 tiering analog | SA-15 | this ADR + gate |

The full control matrix belongs in the RMF package, not this ADR.

## References

Source spec (memory store); issue #24; `ci/gates/coverage-tiers.sh`, `ci/gates/coverage_check.py`, `ci/gates/tests/coverage-tiers/`; `coverage-tiers.toml`; ADR-0001 (+ its append-only amendment), ADR-0002 amendment, ADR-0008 §control-mapping; MPE-ES tiered-testing standard + Microkosmos runner-readiness (provenance only).
