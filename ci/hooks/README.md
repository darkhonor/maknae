# Opt-in local hooks (ADR-0016)

Enable per-clone (one time):

```sh
git config core.hooksPath ci/hooks
```

**Warning:** `core.hooksPath` repoints ALL git hooks for this clone to this
directory — any hooks you had under `.git/hooks` stop firing. This is the
deliberate opt-in shape ("you can lead a horse to water"); CI remains the
enforcement of record either way.

`pre-push` runs `bash ci/gates/coverage-tiers.sh --root "$(git rev-parse --show-toplevel)"`
— the default stage set (partition + coverage + ratchet + workflow-sync),
never the mutation stage. Local prerequisites (the gate's readiness step
prints copy-paste installs if missing):

```sh
cargo install cargo-llvm-cov --locked --version "^0.8"
python3 --version   # >= 3.11 (stdlib tomllib)
```
