# Opt-in local hooks (ADR-0016)

Enable per-clone (one time):

```sh
git config core.hooksPath ci/hooks
```

**Warning:** `core.hooksPath` repoints ALL git hooks for this clone to this
directory — any hooks you had under `.git/hooks` stop firing. This is the
deliberate opt-in shape ("you can lead a horse to water"); CI remains the
enforcement of record either way.

`pre-push` checks the actual incoming ref endpoints. It always runs external-authority and isolation-contract lint for ref updates, then skips Rust gates for allowlisted documentation-only changes. Source or unknown inputs run the complete coverage gate (partition + coverage + ratchet + workflow-sync); set `MAKNAE_PRE_PUSH_MUTANTS=1` to additionally run mutation testing for the selected whole crates, and `MAKNAE_PRE_PUSH_LINUX_CLIPPY=1` to additionally run the Linux clippy lane (`ci/gates/clippy-all.sh --linux`) in a container. That second one sets `MAKNAE_REQUIRE_LINUX_CLIPPY=1` for you, so an unreachable container engine fails the push instead of printing `SKIP` — you asked for the lane, so not running it is an error, not a pass. Ref deletions require no checks. A new remote branch has no previous endpoint, so it conservatively receives full selection.

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
