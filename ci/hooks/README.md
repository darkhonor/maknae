# Opt-in local hooks (ADR-0016)

Enable per-clone (one time):

```sh
git config core.hooksPath ci/hooks
```

**Warning:** `core.hooksPath` repoints ALL git hooks for this clone to this
directory — any hooks you had under `.git/hooks` stop firing. This is the
deliberate opt-in shape ("you can lead a horse to water"); CI remains the
enforcement of record either way.

`pre-push` checks the actual incoming ref endpoints. It always runs external-authority and isolation-contract lint for ref updates, then skips Rust gates for allowlisted documentation-only changes. Source or unknown inputs run the unsafe-confinement gate (ADR-0027) and the complete coverage gate (partition + coverage + ratchet + workflow-sync); set `MAKNAE_PRE_PUSH_MUTANTS=1` to additionally run mutation testing over each ref update's diff (`coverage-tiers.sh --in-diff`, passed every `[t1].mutants_crates` crate; the gate decides which run: a crate whose mutation scope changed runs whole, a crate with a build script runs whole on any change, documentation included, and a tracked path with a newline or control character, or a symlink in a mutation crate or leaving the repository, fails the push until you run it whole without `--in-diff`), and `MAKNAE_PRE_PUSH_LINUX_CLIPPY=1` to additionally run the Linux clippy lane (`ci/gates/clippy-all.sh --linux`) in a container. That second one sets `MAKNAE_REQUIRE_LINUX_CLIPPY=1` for you, so an unreachable container engine fails the push instead of printing `SKIP` — you asked for the lane, so not running it is an error, not a pass. Ref deletions require no checks. A new remote branch has no previous endpoint, so its build and coverage selection is conservatively full. Mutation does not use the push range or the package selection at all: with `MAKNAE_PRE_PUSH_MUTANTS=1`, every ref update with a base invokes the gate over the merge base of its mutation base and `HEAD`, even when the push is documentation-only, because a documentation file can be compiled in (`include_str!("../../../README.md")`).

The mutation run diffs an existing branch against its old remote tip, and a new branch against `refs/remotes/<remote>/HEAD`. If that ref is not set (`git remote set-head origin --auto` sets it), the push fails and names `MAKNAE_PRE_PUSH_MUTANTS_BASE`. Set `MAKNAE_PRE_PUSH_MUTANTS_BASE=<rev>` to choose the base yourself; when set, it applies to every ref in the push, new or existing. The run diffs `HEAD` against the merge base of that base and `HEAD`, not the push's `remote_oid..HEAD`. After a rebase, a force-push diffs against the merge base with the old remote tip, so the run also mutates `main`'s intervening commits. That costs time but fails safe; set `MAKNAE_PRE_PUSH_MUTANTS_BASE=origin/main` to narrow it. If `--mutants` omits a crate whose Rust files the diff changes, the gate FAILs (`changed crate <c> not selected by --mutants`).

With `MAKNAE_PRE_PUSH_MUTANTS=1`, the hook first runs `ci/affected.py --check-history` and fails the push if the repository has grafts, is shallow, or has any ref under `refs/replace/`, because each of those can bend the merge base that decides what the mutation run diffs. It does this before the first selection. Without the opt-in, the hook does not check, since the push-range selection compares two trees and none of these change it; a shallow clone still pushes. The gate lists and mutates a snapshot of `HEAD` written from the object store, never your working tree, so index flags such as `--assume-unchanged` and untracked or ignored files cannot change what runs; commit first, as the dirty-tree check says. The gate builds each mutation crate's production targets (`cargo check`) and reads their dep-info, and it consults that dep-info before any exemption. A changed file a crate compiles runs that crate whole when it is the literal target of an `include_str!`/`include_bytes!` in that crate, found by a workspace-wide scan (even if it is also a module), when any production file in the workspace uses those macros indirectly (an alias, a re-export, a `macro_rules!` wrapper, a non-literal argument; every mutation crate then runs whole), when it walks a source not ending in `.rs`, or when cargo-mutants does not walk it (include data of any suffix, a `README.md` production code embeds, a file from another crate, an excluded file). A dep-info entry that does not resolve to a file fails the push. A test-only change runs nothing, a crate manifest runs its crate whole, and a scope file (the workspace manifest, `.cargo/` config, the toolchain file, the workflow, the mutation gate's own files) runs every mutation crate whole. `Cargo.lock`, dependency-table-only manifest edits and comment-only manifest edits are exempt. That makes such a push's mutation run long; it is paid only when you opt in.

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
