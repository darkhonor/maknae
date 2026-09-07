# Contributing to Maknae

Thanks for your interest in contributing to Maknae — a security-hardened personal AI agent platform built around a deny-by-default trust plane. This is the **human contributor guide**: onboarding, the development workflow, and the conventions this repository follows. AI agents and tools working in this repo read [`AGENTS.md`](AGENTS.md) instead (`CLAUDE.md` is a symlink to it) — its **core principles apply to your work too**, so read it once before you start; this file is the human process around them.

Maknae is pre-MVP and its posture is DoD DevSecOps (deny-by-default, fail-closed, RMF/STIG/FIPS-aware). Contributions are held to that bar — the discipline is the point, not an afterthought.

## Code of Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). By participating you agree to uphold it. Report conduct concerns to `conduct@maknae.io`. There is no place here for harassment or hate in any form.

## Where the guidance lives

- [`AGENTS.md`](AGENTS.md) — the **core principles and conventions** (deny-by-default, nothing self-promotes, fail-closed testing, the access-control vocabulary). They bind human and AI work alike.
- [`design/knowledge-lifecycle-contract.md`](design/knowledge-lifecycle-contract.md) — the governance spec (KLC). Its invariants are acceptance criteria: violating one is a wrong answer even if the code works.
- [`design/adr/`](design/adr/) — architecture decision records. A choice that constrains future work is recorded as an ADR (see the registry and the measured style in `AGENTS.md`).
- [`design/references/`](design/references/) — assessments of comparable platforms we've surveyed.

## Asking for help vs. filing an issue

- **Design or usage questions** — start with the KLC contract and the ADRs; if they don't answer it, file an issue framed as a docs gap.
- **Bug** (something behaves differently from what the spec/ADR says) — file a bug (see below).
- **Security vulnerability** — do **not** open a public issue; see [Reporting a security vulnerability](#reporting-a-security-vulnerability).

## Reporting a bug

A bug report's most useful contents are the ones that let a maintainer *reproduce* it: what you did, what happened, what the spec/ADR led you to expect, and the smallest input that triggers it.

**Reported bugs start with a failing test.** Before a fix, the first deliverable is a test that fails *for the reporter's reason* — then the fix makes that same test pass. Assert at the altitude the reporter is looking at it: a file on disk, an audit line, or a policy verdict can each be correct while the surface is wrong. Confirm you have *seen the test fail* before trusting it, and after fixing, revert the fix once to watch it go red again — an assertion never observed failing is not evidence. Prefer the reporter's real configuration over a convenient stand-in: a stub proves the plumbing and hides everything else; where a stand-in is unavoidable, say so in the test and name what it stands in for. (This is the `reproduce-first` discipline; `AGENTS.md` carries it as a core principle.)

## Reporting a security vulnerability

**Do not file a public issue for a vulnerability.** Use this repository's **private vulnerability reporting** — GitHub → the repo's **Security** tab → **Report a vulnerability** (private Security Advisories) — so the conversation stays private until a fix ships. See [`SECURITY.md`](SECURITY.md) for the full policy, scope, and what counts as high-priority. Given Maknae's threat model — the agent runtime is untrusted by design and the trust plane is the control — a report that a mediated action can escape the reference monitor, that a mandatory constraint can be bypassed, or that a label/authority can be forged is high-priority; include the smallest reproducing case you can.

## Suggesting an enhancement

File an issue with a summary, the use case, and a proposed approach. Call out any STIG / NIST 800-53 or KLC-invariant implications — Maknae's whole value is that security is structural, so an enhancement's effect on the trust plane is first-class context, not a footnote.

## Development setup

### Prerequisites

Maknae is a Rust workspace. The toolchain version is pinned via [`rust-toolchain.toml`](rust-toolchain.toml) and installed automatically by [`rustup`](https://rustup.rs/) on first build (`cargo`, `rustc`, `clippy`, `rustfmt` come with it).

The pre-push gates need a few cargo subcommands and helpers beyond rustup. **Derive the authoritative list from [`.github/workflows/ci.yml`](.github/workflows/ci.yml)** — it installs exactly what the gate runs, so it stays current as the gate evolves. As of this writing that is `cargo-deny` (supply-chain policy, against [`deny.toml`](deny.toml)), `cargo-llvm-cov` + the `llvm-tools` component (coverage), `cargo-mutants` (the mutation gate), and `python3` / `bash` for the `ci/gates/*` scripts. Install the cargo subcommands with `cargo install <name>` using the versions in CI; for reproducible mutation results use `cargo install cargo-mutants --version 27.1.0 --locked`.

### Cloning on Windows — turn symlinks on *first*

This repository tracks `CLAUDE.md` as a **symlink** to `AGENTS.md`. Git materializes it as a real link only when `core.symlinks` is on — on Windows that means **Developer Mode is enabled** (Settings → System → For developers) or git ran elevated. Otherwise git writes `CLAUDE.md` as a plain ~9-byte text file containing the string `AGENTS.md`, silently, and any tool that reads `CLAUDE.md` for the project's conventions gets *no guidance at all*.

So enable Developer Mode (or `git config --global core.symlinks true`) **before** cloning, and confirm on a fresh clone:

```bash
readlink CLAUDE.md   # must print: AGENTS.md
```

If it prints nothing and `CLAUDE.md` is a tiny text file, the clone came out wrong — re-clone with symlinks enabled.

### Clone and build

```bash
git clone git@github.com:darkhonor/maknae.git
cd maknae
cargo build --workspace
```

## The pre-push gate

CI (`.github/workflows/ci.yml`) classifies every PR and main push with `ci/affected.py`. Source changes run the complete `build-and-gate` coverage contract; mutation and Darwin jobs select complete affected packages, including reverse dependencies. Explicitly allowlisted documentation-only changes skip Rust builds, coverage, mutation, and Darwin runners. The lightweight job always runs external-authority and isolation-contract lint, including on documentation-only updates. The allowlist covers the existing packaging READMEs and isolation contract, deployment README, and hook README as well as root/design/docs prose; unknown Markdown fixtures and packaging configuration are still build inputs. Unknown inputs or missing history select all; unreadable selection authority fails. **Run the applicable checks locally before you push.** *"CI will run it"* is not a substitute: a CI failure is something you should have caught before pushing, and the gates are cheap warm.

For Rust changes, before committing:

```bash
cargo fmt --all --check
for p in maknaed maknae maknae-spifc maknae-security maknae-config maknae-kernel maknae-vault maknae-proto maknae-audit-append maknae-msgs; do
  cargo clippy -p "$p" --all-targets -- -D warnings
done
cargo test --workspace
```

For documentation-only changes, run these checks without compiling Rust:

```bash
bash ci/gates/external-authority-lint.sh
bash ci/gates/isolation-contract-lint.sh
```

For source changes, run the applicable heavier gates before pushing (derive the current, authoritative set from `ci.yml`):

```bash
cargo deny check
ci/gates/p1-manifest-lint.sh
ci/gates/p2-invert-tree.sh
ci/gates/p2-artifact-witness.sh
ci/gates/build-invocation-lint.sh
ci/gates/isolation-contract-lint.sh
ci/gates/negative-control.sh
bash ci/gates/coverage-tiers.sh --root .            # risk-tiered coverage (ADR-0016)
```

Enable the local hook with `git config core.hooksPath ci/hooks`. It reads the incoming pre-push ref updates (remote old SHA to local new SHA), so it works with any remote name and checks merge pushes correctly. It runs aggregate coverage for source changes. Mutations are opt-in with `MAKNAE_PRE_PUSH_MUTANTS=1 git push`; a push of a ref other than the current checkout is refused because local gates cannot attest to that ref's contents.

CI also caches the cargo-deny, cargo-auditable, rust-audit-info, and cargo-llvm-cov executables using exact version pins from the passing #235 merge run, keyed by OS, architecture, and Rust toolchain. Update a tool's version in the workflow to invalidate its cache. An exact cache miss compiles the pinned tool with `--locked`; the LLVM component is installed independently of cache hits. Coverage and mutation results are always regenerated. The #235 merge run spent 191 seconds installing the three build-gate tools and 70 seconds on coverage tooling, so a warm cache can avoid most of that 261-second cost, less cache transfer overhead. Cold runs still pay the installation cost; hosted savings must be confirmed from subsequent warm runs.

Inspect the same selection before running expensive work (Python 3.11 or newer):

```bash
python3 ci/affected.py --event pull_request --base=main --head=HEAD
# Use actual endpoint SHAs and --event push to inspect a merge/push update.
# Copy the reported mutation package names into:
bash ci/gates/coverage-tiers.sh --root . --mutants maknae-io maknae-config
# Use --mutants-all when selection widens to every mutation package.
```

Selection is whole-crate mutation, never changed-line-only mutation. All dependency kinds, including target-specific dev/build dependencies, participate in reverse closure. Manifest, lockfile, toolchain, CI/gate, mutation configuration, unknown path, and uncertain dependency changes widen to all packages. Empty diffs also widen rather than claiming assurance over nothing. Coverage remains a complete report for every source change: the per-file floors and cohort ratchet cannot safely consume partial reports. This deliberately retains the expensive aggregate coverage boundary while avoiding repeated unrelated mutation and macOS work within the 3000 hosted-minute monthly budget. CI pins cargo-mutants to 27.1.0 and caches only its executable by OS, architecture, toolchain and version; mutation results are freshly measured each run. Native macOS mutation debugging remains local; CI adds no hosted macOS mutation job. The #126 serial measurement on the four-vCPU Rocky 9 host was 86.62 seconds for the prior I/O gate and 153.92 seconds for the revised gate: about 67 additional seconds. This is a local comparison, not a hosted billing guarantee. The cold all-package job previously approached 30 minutes, so its job ceiling is 35 minutes; per-mutant timeouts are unchanged. Native syscall mutation runs and individual flag-removal experiments belong on the development hosts before pushing, so repeated debugging does not consume hosted minutes.

Two gates deserve a note:

- **`negative-control.sh`** exists to prove a passing gate actually *fails when it should*. A green run that was never observed failing proves nothing — respect it, and never weaken it to make a run go green.
  **It is also the closest thing to a check that the gates work on YOUR machine.** CI runs the **gate scripts** on Linux only (there is a `macos-26` job, but it runs `cargo test`, not a single `ci/gates/*.sh` — that gap is [#200](https://github.com/darkhonor/maknae/issues/200)). The gates *intend* to run on BSD userland (macOS) too: the external utilities they call (`sed`, `grep`, `awk`) are held to the **common BSD/GNU subset**, which is not the same as literal POSIX — `grep -r`, `grep -o` and `\b` in an ERE are extensions both userlands happen to share, and the gates use them freely. The shell is not POSIX either; `coverage-tiers.sh` deliberately requires bash ≥ 4.

  **Nothing enforces the intent**, so `negative-control.sh`'s own count is the signal — but only where a probe covers the affected control. A dialect difference is invisible wherever it isn't probed, which is exactly how #217 survived: the count dropped to 87/89 only because two fixtures happened to exercise the *consequence*, and the remediation had to add a probe for the cause. So: if your local run reports fewer than the full count while CI is green, treat it as a portability defect in a gate **until you have ruled out an environment gap** — several probes shell out to `cargo` (a host with no rustup default produces a sub-total count) and **four are skipped under `root`**, which can read a `chmod 000` file and so cannot make the tool fail. The summary line reports how many were skipped. Investigate rather than trusting CI; and a *full* count is not proof of portability, only the absence of a covered failure.

  The worked example is [#217](https://github.com/darkhonor/maknae/issues/217): a `sed` label loop written `":a; s/…//; ta"` is GNU-only (POSIX reads the whole line as one label), so BSD `sed` ran no substitution and **still exited 0**, which `set -euo pipefail` cannot see. It was not quiet about it — it printed `unused label` once per row, 31 times a run — but the diagnostics went to stderr, which no harness and no reader was looking at, so a fail-closed check stopped checking on every Mac and the gate stayed green. Hence: prefer `-e ':a' -e '…' -e 'ta'`, keep `sed -i.bak`'s suffix, **never let a check's correctness depend on a human noticing stderr**, and give any check that rests on a tool's output a post-condition that fails loudly when the tool does nothing. *(Corrected 2026-09-04, [#219](https://github.com/darkhonor/maknae/issues/219): this said two gates did not hold the rule yet and named #219 as open. They hold it now, and the sweep found two more. `build-invocation-lint.sh` and `external-authority-lint.sh` read every scanner's exit status and no longer discard its stderr; `p1-manifest-lint.sh` reads `cargo metadata`'s status and no longer swallows its stderr — it used to die on a Python traceback with no `FAIL` line at all; `isolation-contract-lint.sh` has no scanner but had the same zero-input hole. A reshaped table and a `members = []` workspace each reported `ok` having examined nothing. All four now refuse a scan that examined nothing and report the count they did examine, and `negative-control` cross-checks each reported count against a set derived by a **different** mechanism — `git ls-files` against a gate that walks with `find`, `awk` over the contract against a gate that reads it line by line. That catches a shrink, an addition that goes unscanned, and a prune or filter that quietly changes what the gate walks; a baked number would catch none of the last two and would churn on ordinary work. The sharper statement of the rule: **a present file is not a scanned file**. The distinction that decides which gates need it: a gate that DISCOVERS its input set needs a floor — including when the discovery is `cargo metadata` rather than `find`, which is how `p1-manifest-lint` was mis-classified as safe on the first pass — while one handed a code constant has no zero-input case.)*
- **`coverage-tiers.sh`** is the **fail-closed** coverage contract ([ADR-0016](design/adr/ADR-0016-risk-tiered-test-coverage.md), [`coverage-tiers.toml`](coverage-tiers.toml)): every tracked `.rs` file resolves to exactly one tier, and unclassified / stale / (non-T3) uncovered code is a hard failure, not a warning. If you add a source file, classify it.

## Testing discipline

- **TDD** — write the failing test first, then the implementation. Because much of the code is AI-implemented, the suite doubles as **mutation-proofing** (`cargo-mutants` runs in CI): prove each assertion can go red.
- **Test the real decision path**, not a mock — a genuine policy verdict with a uniquely-named fixture, not a stubbed authorizer. A stand-in proves the plumbing and hides everything else.
- **Reproduce-first for bugs** — see [Reporting a bug](#reporting-a-bug).

## Commit conventions

This repo uses [Conventional Commits](https://www.conventionalcommits.org/). The type (and optional scope) feeds `git log` scanning and future changelog tooling. Real examples from this repo:

```
fix(selinux): el9 socket bind — grant maknaed_t var_run_t dir/sock_file ops
docs(adr): add ADR-0020 access-control model & vocabulary
fix(apparmor): maknaed crashes on fresh AppArmor install
docs(readme): agent-guidance labeling + name all four surveys
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`. Reference issues with `Refs #NN` / `Closes #NN`.

**AI-assisted commits carry a co-author trailer** for provenance, naming the actual model used:

```
Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

## Pull requests

`main` is protected: every change lands through a pull request that a maintainer reviews.

1. **Branch from `main`** — `git checkout -b <type>/<short-name>` (e.g. `fix/enroll-rotate`). Do not commit to `main` directly.
2. **Make the change with tests**, run the pre-push gate locally, and keep commits Conventional-Commit-formatted.
3. **Open the PR** and reference related issues in the description. Say what changed and why; note any trust-plane, protocol, or ADR impact.
4. **Wait for review.** `hobibot` reviews PRs; address every finding — fix it, or say why not. A green CI check is not the review; read the review comments before expecting a merge.
5. **The project owner merges.** Merging (like tag pushes and any direct write to `main`) is an operator-driven action, not delegated — do not merge your own PR.

## Decisions become ADRs

A choice that constrains future work — an interface, a security property, a vocabulary — is recorded as an ADR under [`design/adr/`](design/adr/), allocated in the registry, and written in the measured, self-correcting style described in `AGENTS.md` (state the decision, the failure that motivated it, and date any later correction). External ADRs (from other projects) are provenance, never authority — if a decision matters here, we make it here.

## Code style

- **`cargo fmt`** — strict; the CI gate rejects unformatted code.
- **`cargo clippy --all-targets -- -D warnings`** — clippy lints are errors. If you must silence one, do it inline with `#[allow(...)]` and a comment saying why.
- **Small, focused files** — if a file grows past a couple hundred lines, that's usually a signal to split by responsibility.
- **Doc comments on public items**, and reference the STIG ID or NIST control inline where code implements a specific control — the code is its own evidence.

## What not to do

- **No specs or plans in the repo** — development-process artifacts live outside it (see the rule in `AGENTS.md`); ask the operator for the location if you don't have one.
- **Nothing self-promotes** — no content, skill, or config gains authority without transiting the promotion pipeline.
- **No permissive or bypass modes** — deny-by-default applies to designs too; absence of an explicit permission is a denial.

### Filesystem mutation checks across credentials

Issue #158 includes an opt-in test using two existing non-root development accounts. Build `cargo test -p maknae-io --test subject_mutations --no-run`, then run the emitted test binary as root with `MAKNAE_TEST_SUBJECT` and `MAKNAE_TEST_SERVICE` set, selecting `--ignored --exact distinct_credentials_preserve_os_authority --nocapture`. On the Rocky development hosts these are `byeori` and `_maknae`. The test creates and removes only its unique temporary fixture; child processes run via `sudo -u` with each account's actual groups.

It transfers real descriptors between the subject and service, checks replacement through the subject's writable descriptor, and verifies that the directory descriptor confers no namespace permission on the service. The subject then creates, deletes, and makes a directory in a write/search-only project directory. This developmental test is excluded from ordinary CI account provisioning; run it on both approved Rocky hosts before pushing changes to this boundary. The ordinary composed-policy, audit, report, and filesystem suites remain in CI.
