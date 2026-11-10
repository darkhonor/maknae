# Opt-in local hooks (ADR-0016)

Enable per-clone (one time):

```sh
git config core.hooksPath ci/hooks
```

**Warning:** `core.hooksPath` repoints ALL git hooks for this clone to this
directory — any hooks you had under `.git/hooks` stop firing. This is the
deliberate opt-in shape ("you can lead a horse to water"); CI remains the
enforcement of record either way.

`pre-push` checks the actual incoming ref endpoints. It always runs external-authority and isolation-contract lint for ref updates, then skips Rust gates for allowlisted documentation-only changes. Source or unknown inputs run the unsafe-confinement gate (ADR-0027) and the complete coverage gate (partition + coverage + ratchet + workflow-sync); set `MAKNAE_PRE_PUSH_MUTANTS=1` to additionally run mutation testing over each ref update's diff (`coverage-tiers.sh --in-diff`, passed every `[t1].mutants_crates` crate; the gate mutates only each crate's changed lines, never a whole crate, and a tracked path with a newline or control character, or a symlink in a mutation crate or leaving the repository, fails the push until you rename the file or remove the symlink), and `MAKNAE_PRE_PUSH_LINUX_CLIPPY=1` to additionally run the Linux clippy lane (`ci/gates/clippy-all.sh --linux`) in a container. That second one sets `MAKNAE_REQUIRE_LINUX_CLIPPY=1` for you, so an unreachable container engine fails the push instead of printing `SKIP` — you asked for the lane, so not running it is an error, not a pass. Ref deletions require no checks. A new remote branch has no previous endpoint, so its build and coverage selection is conservatively full. Mutation does not use the push range or the package selection at all: with `MAKNAE_PRE_PUSH_MUTANTS=1`, every ref update with a base invokes the gate over the merge base of its mutation base and `HEAD`, even when the push is documentation-only, so the gate's refusals run on every push, and a diff with no `.rs` change SKIPs.

The mutation run diffs an existing branch against its old remote tip, and a new branch against `refs/remotes/<remote>/HEAD`. If that ref is not set (`git remote set-head origin --auto` sets it), the push fails and names `MAKNAE_PRE_PUSH_MUTANTS_BASE`. Set `MAKNAE_PRE_PUSH_MUTANTS_BASE=<rev>` to choose the base yourself; when set, it applies to every ref in the push, new or existing. The run diffs `HEAD` against the merge base of that base and `HEAD`, not the push's `remote_oid..HEAD`. After a rebase, a force-push diffs against the merge base with the old remote tip, so the run also mutates `main`'s intervening commits. That costs time but fails safe; set `MAKNAE_PRE_PUSH_MUTANTS_BASE=origin/main` to narrow it. If `--mutants` omits a crate whose Rust files the diff changes, the gate FAILs (`changed crate <c> not selected by --mutants`).

Mutation testing is in-diff by default: `coverage-tiers.sh --mutants <crate>...` needs `--in-diff <rev>` and FAILs without one. A whole-crate run happens only on an explicit `coverage-tiers.sh --root . --mutants-all`, never as a default or as the remedy for a refusal.

With `MAKNAE_PRE_PUSH_MUTANTS=1`, the hook first runs `coverage-tiers.sh --in-diff-preflight`, which refuses a symlinked or case-variant config path before anything reads one, then `ci/affected.py --check-history` and fails the push if the repository has grafts, is shallow, or has any ref under `refs/replace/`, because each of those can bend the merge base that decides what the mutation run diffs. It does this before the first selection. Without the opt-in, the hook does not check, since the push-range selection compares two trees and none of these change it; a shallow clone still pushes. The gate lists and mutates a snapshot of `HEAD` written from the object store, never your working tree, so index flags such as `--assume-unchanged` and untracked or ignored files cannot change what runs; commit first, as the dirty-tree check says. Because the hook passes every mutation crate, the gate builds nothing to find which crate owns a changed `.rs` file. No change widens the run to a whole crate: embedded data, build inputs, manifests and scope files get no mutation, and a test-only change runs nothing. A non-`.rs` target path or a case-variant `.rs` suffix in a mutation crate, or a listed file that is not a byte-exact tracked path, fails the push until it is renamed.

For a documentation-only change, the same local checks are:

```sh
bash ci/gates/external-authority-lint.sh
bash ci/gates/isolation-contract-lint.sh
```

Local coverage prerequisites (derive current versions from `.github/workflows/ci.yml`; the gate's readiness step prints install guidance if missing):

```sh
cargo install cargo-llvm-cov --locked --version 0.8.7
python3 --version   # >= 3.11 (stdlib tomllib)
```
