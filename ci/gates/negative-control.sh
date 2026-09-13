#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# ONE gate-owned scratch root, released on EVERY exit path (#302).
#
# This gate materializes SIXTY throwaway workspaces per run and used to remove
# none of them — the only one of the seven scratch-allocating gates without a
# cleanup path (the other six pair `mktemp -d` with a `trap` on the same line or
# a `trap cleanup EXIT`). 17,667 trees (1.5 GiB) had accumulated in /tmp since
# Aug 30 on the maintainer's host.
#
# THE LEAK DISABLED A DIFFERENT GATE, which is why this is a trap and not a
# tidiness note: /tmp (5.0 GiB) filled, every `cargo mutants` scratch build then
# failed with `No space left on device`, and cargo-mutants classifies a mutant
# that fails to BUILD as `unviable` — so a run reporting `41 unviable` exited 0
# and coverage-tiers.sh, whose only oracle is the exit status, passed the
# zero-missed contract having tested nothing (#301).
#
# Named, so leaked debris is attributable to this gate rather than indis-
# tinguishable from every other program's mktemp output — which is how it went
# unnoticed for two weeks. Every allocation below is a child of this root, so the
# single trap covers all sixty.
NC_TMP="$(mktemp -d -t maknae-negctl.XXXXXXXX)"
trap 'rm -rf -- "$NC_TMP"' EXIT INT TERM
# Materialize contaminated workspaces in temp dirs and assert the REAL gate scripts reject each
# (root-override arg). A gate that cannot be shown to fire is not a control (spec §3 P2c).
pass=0; total=0; skipped=0
expect_reject() { # <label> <cmd...> — require a genuine rejection (a printed FAIL), not merely a non-zero exit
  local label="$1"; shift; total=$((total+1))
  local out rc
  # `if out=$(...)` keeps the expected non-zero exit out of set -e's reach.
  if out="$("$@" 2>&1)"; then rc=0; else rc=$?; fi
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'FAIL'; then
    echo "neg-ok: [$label] gate rejected"; pass=$((pass+1))
  elif [ "$rc" -eq 0 ]; then
    echo "NEG-FAIL: [$label] gate did NOT reject the fixture"
  else
    echo "NEG-FAIL: [$label] gate exited $rc without a FAIL line (crash, not a rejection): $out"
  fi
}

expect_reject_because() { # <label> <expected-FAIL-substring> <cmd...>
  # `expect_reject` accepts ANY printed FAIL, so a probe that rejects for a
  # reason its label does not name still scores neg-ok. Live instance: two
  # depth probes APPENDED a field to a struct whose SURFACE count is exact, so
  # the count check fired first and the depth check they were written for had
  # zero coverage -- the gate's central claim, unprobed, with the harness
  # printing neg-ok. Use this wherever an earlier check could plausibly fire.
  local label="$1" why="$2"; shift 2; total=$((total+1))
  local out rc
  if out="$("$@" 2>&1)"; then rc=0; else rc=$?; fi
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "FAIL" && printf '%s' "$out" | grep -qF -- "$why"; then
    echo "neg-ok: [$label] gate rejected, for '$why'"; pass=$((pass+1))
  elif [ "$rc" -eq 0 ]; then
    echo "NEG-FAIL: [$label] gate did NOT reject the fixture"
  elif printf '%s' "$out" | grep -q "FAIL"; then # rejected, but not for `$why`
    echo "NEG-FAIL: [$label] gate rejected for the WRONG reason (wanted '$why'): $out"
  else
    echo "NEG-FAIL: [$label] gate exited $rc without a FAIL line (crash, not a rejection): $out"
  fi
}

expect_reported_count() { # <label> <prefix-before-the-count> <expected> <cmd...>
  # For gates that REPORT how much they examined. `$expected` is DERIVED at call
  # time by a mechanism DIFFERENT from the one the gate uses -- `git ls-files`
  # against a gate that walks with `find`, `awk` over the contract against a
  # gate that reads it line-by-line -- so this is a cross-check, not a
  # restatement.
  #
  # It is deliberately NOT a baked constant, and not a `>=` floor either. Both
  # were written first and both were wrong for the same reason: a number
  # measured once asserts that a fact held at one moment, which churns on
  # ordinary work and trains a thoughtless bump, and a floor cannot see an
  # ADDITION that goes unscanned -- the exact defect #219 is about. A derived
  # equality catches a shrink, an unscanned addition, AND a prune or filter
  # that silently changes what the gate walks, and it never needs editing when
  # the corpus legitimately grows.
  local label="$1" prefix="$2" expected="$3"; shift 3; total=$((total+1))
  local out rc n
  if out="$("$@" 2>&1)"; then rc=0; else rc=$?; fi
  n="$(printf '%s' "$out" | sed -n "s/.*${prefix}\([0-9][0-9]*\).*/\1/p" | head -1)"
  if [ "$rc" -eq 0 ] && [ -n "$n" ] && [ "$n" = "$expected" ]; then
    echo "pos-ok: [$label] gate accepted, examined $n (independently derived: $expected)"; pass=$((pass+1))
  elif [ "$rc" -ne 0 ]; then
    echo "POS-FAIL: [$label] gate rejected a CLEAN fixture (exit $rc): $out"
  elif [ -z "$n" ]; then
    echo "POS-FAIL: [$label] gate passed but reported no count after '$prefix': $out"
  else
    echo "POS-FAIL: [$label] gate examined $n but the independent derivation says $expected — the gate is walking a different set than it should: $out"
  fi
}

expect_accept() { # <label> <expected-stdout-substring> <cmd...> — a gate must also PASS a clean fixture
  local label="$1" want="$2"; shift 2; total=$((total+1))
  local out rc
  if out="$("$@" 2>&1)"; then rc=0; else rc=$?; fi
  if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "$want"; then
    echo "pos-ok: [$label] gate accepted"; pass=$((pass+1))
  elif [ "$rc" -ne 0 ]; then
    echo "POS-FAIL: [$label] gate rejected a CLEAN fixture (exit $rc): $out"
  else
    echo "POS-FAIL: [$label] gate passed but did not report '$want': $out"
  fi
}

# Fixture A — optional privileged dep → must trip p1-manifest-lint.sh
tmpA="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpA/crates/shared/src" "$tmpA/crates/maknae-kernel/src" "$tmpA/bins"
cat > "$tmpA/Cargo.toml" <<'EOF'
[workspace]
resolver = "3"
members = ["crates/shared", "crates/maknae-kernel"]
EOF
cat > "$tmpA/crates/maknae-kernel/Cargo.toml" <<'EOF'
[package]
name = "maknae-kernel"
version = "0.0.0"
edition = "2021"
EOF
echo '' > "$tmpA/crates/maknae-kernel/src/lib.rs"
cat > "$tmpA/crates/shared/Cargo.toml" <<'EOF'
[package]
name = "maknae-config"
version = "0.0.0"
edition = "2021"
[dependencies]
maknae-kernel = { path = "../maknae-kernel", optional = true }
EOF
echo '' > "$tmpA/crates/shared/src/lib.rs"
expect_reject_because "p1/optional-priv-dep" "as OPTIONAL" "$here/p1-manifest-lint.sh" "$tmpA"

# Fixture A2 — TABLE-form optional privileged dep (`[dependencies.<crate>]`) → must also trip p1.
tmpA2="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpA2/crates/shared/src" "$tmpA2/crates/maknae-kernel/src"
cat > "$tmpA2/Cargo.toml" <<'EOF'
[workspace]
resolver = "3"
members = ["crates/shared", "crates/maknae-kernel"]
EOF
cat > "$tmpA2/crates/maknae-kernel/Cargo.toml" <<'EOF'
[package]
name = "maknae-kernel"
version = "0.0.0"
edition = "2021"
EOF
echo '' > "$tmpA2/crates/maknae-kernel/src/lib.rs"
cat > "$tmpA2/crates/shared/Cargo.toml" <<'EOF'
[package]
name = "maknae-config"
version = "0.0.0"
edition = "2021"

[dependencies.maknae-kernel]
path = "../maknae-kernel"
optional = true
EOF
echo '' > "$tmpA2/crates/shared/src/lib.rs"
expect_reject_because "p1/optional-priv-dep-TABLE-form" "as OPTIONAL" "$here/p1-manifest-lint.sh" "$tmpA2"

# Fixture B — P2a reachability. The fixture carries a stub for EVERY crate in
# PRIVILEGED_CRATES, because the gate iterates all of them and fails CLOSED on a
# cargo-tree error. Both probes previously shipped a workspace with ONE
# privileged crate, so the first four iterations rejected with "did not match
# any packages" and the reachability grep -- the check the probes are named for,
# and #85's whole claim -- was never exercised. Deleting that grep from the gate
# left negative-control fully green; removing the linked crate from
# PRIVILEGED_CRATES did too.
source "$here/lib.sh"
p2_fixture() { # <crate-to-link-from-the-CLI, or empty for the clean case>
  local linked="${1:-}" fixture members c
  fixture="$(mktemp -d -p "$NC_TMP")"
  members=''
  for c in "${PRIVILEGED_CRATES[@]}"; do
    mkdir -p "$fixture/crates/$c/src"
    printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2021"\n' "$c" \
      > "$fixture/crates/$c/Cargo.toml"
    echo 'pub const M: &str = "x";' > "$fixture/crates/$c/src/lib.rs"
    members="$members\"crates/$c\", "
  done
  mkdir -p "$fixture/bins/maknae/src"
  printf '[workspace]\nresolver = "3"\nmembers = [%s"bins/maknae"]\n' "$members" \
    > "$fixture/Cargo.toml"
  {
    printf '[package]\nname = "maknae"\nversion = "0.0.0"\nedition = "2021"\n'
    printf '[[bin]]\nname = "maknae"\npath = "src/main.rs"\n[dependencies]\n'
    [ -n "$linked" ] && printf '%s = { path = "../../crates/%s" }\n' "$linked" "$linked"
  } > "$fixture/bins/maknae/Cargo.toml"
  if [ -n "$linked" ]; then
    echo "fn main(){ println!(\"{}\", ${linked//-/_}::M); }" > "$fixture/bins/maknae/src/main.rs"
  else
    echo 'fn main(){}' > "$fixture/bins/maknae/src/main.rs"
  fi
  echo "$fixture"
}
tmpB="$(p2_fixture maknae-kernel)"
expect_reject_because "p2/cli-links-privileged" \
  "privileged 'maknae-kernel' is reachable from 'maknae' (P2a)" \
  "$here/p2-invert-tree.sh" "$tmpB"

# Fixture B2 — #85: `maknae-authz-basic` is privileged; the untrusted client
# must never carry the decision engine.
tmpB2="$(p2_fixture maknae-authz-basic)"
expect_reject_because "p2/cli-links-authz-basic" \
  "privileged 'maknae-authz-basic' is reachable from 'maknae' (P2a)" \
  "$here/p2-invert-tree.sh" "$tmpB2"

# ACCEPT: the same workspace with NOTHING linked. Without it, both rejections
# above stay green against a gate that refuses every fixture -- which is very
# nearly what was happening.
expect_accept "p2/clean-workspace-passes" "p2-invert-tree: ok" \
  "$here/p2-invert-tree.sh" "$(p2_fixture)"

# ---- isolation-contract-lint (#219): a PRESENT file is not a SCANNED file ----
# This gate had no probe at all before #219, because it resolved its root from
# the CWD and could not be pointed at a fixture. It checks the contract file
# EXISTS, then lints only table rows with exactly five columns -- so collapsing
# every row to four columns left the whole property x profile enforcement matrix
# unexamined and the gate reported `ok` at rc 0. Verified against the pre-change
# gate on the REAL contract.
ic_fixture() { # <table-row> — a tree holding a contract file with one table row
  local fixture; fixture="$(mktemp -d -p "$NC_TMP")"
  mkdir -p "$fixture/packaging"
  { printf '# Isolation contract\n\n'
    printf '| Property | A | B | C | D |\n'
    printf '|---|---|---|---|---|\n'
    printf '%s\n' "$1"
  } > "$fixture/packaging/isolation-contract.md"
  echo "$fixture"
}
expect_accept "isolation-contract/populated-table-passes" "isolation-contract-lint: ok" \
  "$here/isolation-contract-lint.sh" "$(ic_fixture '| seccomp | ✓ | ✓ | deferred | ✓ |')"

expect_reject_because "isolation-contract/blank-cell-is-refused" \
  "is EMPTY" \
  "$here/isolation-contract-lint.sh" "$(ic_fixture '| seccomp | ✓ | ✓ |  | ✓ |')"

# The #219 case: the file is there, the table this gate reads is not.
expect_reject_because "isolation-contract/zero-rows-linted-is-refused" \
  "linted ZERO rows" \
  "$here/isolation-contract-lint.sh" "$(ic_fixture '| seccomp | ✓ | ✓ | ✓ |')"

# REJECT: the contract is present but UNREADABLE. `done < "$f"` made bash print
# its own `Permission denied` and exit 1 with no FAIL line -- a mute failure,
# and unprobeable by `expect_reject` until the root override above made this
# gate fixturable at all. SKIPPED FOR root, which reads a 000 file regardless.
if [ "$(id -u)" -eq 0 ]; then
  echo "neg-skip: [isolation-contract/unreadable-contract-is-refused] running as root; chmod 000 cannot make the read fail"
  skipped=$((skipped+1))
else
  fx_ic="$(ic_fixture '| seccomp | ✓ | ✓ | deferred | ✓ |')"
  chmod 000 "$fx_ic/packaging/isolation-contract.md"
  expect_reject_because "isolation-contract/unreadable-contract-is-refused" \
    "is not readable" \
    "$here/isolation-contract-lint.sh" "$fx_ic"
  chmod 644 "$fx_ic/packaging/isolation-contract.md"
fi

# ---- p1-manifest-lint (#219): a resolved manifest is not a scanned one -------
# (the gate's other probes are the two Fixture A cases far above)
#
# REJECT: a workspace that resolves to ZERO packages (#219). `p1-manifest-lint`
# looked like a constant-input gate but is not: `p1_check.py` iterates whatever
# `cargo metadata` discovers, so `members = []` gave zero iterations and `ok` at
# rc 0 -- a clean bill of health for a dependency graph nobody looked at. Found
# while writing the sweep's discover-vs-constant rule, which had mis-classified
# this gate.
tmpP0="$(mktemp -d -p "$NC_TMP")"
printf '[workspace]\nresolver = "3"\nmembers = []\n' > "$tmpP0/Cargo.toml"
expect_reject_because "p1-manifest/zero-packages-is-refused" \
  "resolved ZERO packages" \
  "$here/p1-manifest-lint.sh" "$tmpP0"

# REJECT: `cargo metadata` itself fails. Its stderr went to /dev/null and python
# then died on empty stdin with a JSONDecodeError traceback, so the gate exited 1
# printing no FAIL line -- mute, and unprobeable by `expect_reject`, which needs
# one. The diagnostic now quotes cargo.
tmpP1="$(mktemp -d -p "$NC_TMP")"
printf '[workspace]\nresolver = "3"\nmembers = ["nope"]\n' > "$tmpP1/Cargo.toml"
expect_reject_because "p1-manifest/metadata-failure-is-not-silent" \
  "cargo metadata failed" \
  "$here/p1-manifest-lint.sh" "$tmpP1"

# Fixture C — bare workspace build in a workflow → must trip build-invocation-lint.sh
tmpC="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpC/.github/workflows"
printf 'jobs:\n  b:\n    steps:\n      - run: cargo build --workspace --release\n' > "$tmpC/.github/workflows/bad.yml"
expect_reject "build-invocation/workspace-build" "$here/build-invocation-lint.sh" "$tmpC"

# Fixture C2 — MULTILINE (backslash-continued) workspace build → must also trip build-invocation-lint.
tmpC2="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpC2/.github/workflows"
printf 'jobs:\n  b:\n    steps:\n      - run: |\n          cargo build \\\n            --workspace --release\n' > "$tmpC2/.github/workflows/bad.yml"
expect_reject "build-invocation/multiline-workspace-build" "$here/build-invocation-lint.sh" "$tmpC2"

# ACCEPT: a clean tree with a well-formed build must PASS, and must report what
# it scanned. Without this the rejections above stay green against a gate that
# refuses every fixture -- the hazard this file names for p2, and which a newly
# added FLOOR is exactly the kind of change that could introduce.
tmpC0="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpC0/.github/workflows"
printf 'jobs:\n  b:\n    steps:\n      - run: cargo build -p maknaed --release\n' > "$tmpC0/.github/workflows/good.yml"
expect_accept "build-invocation/clean-tree-passes" "build-invocation-lint: ok" \
  "$here/build-invocation-lint.sh" "$tmpC0"

# REJECT: ZERO scanned files (#219). An empty tree reported `ok` at rc 0 --
# nothing examined, nothing found, indistinguishable from a clean scan. This is
# the rc-0-with-no-matches case `find` reports as SUCCESS, which is why a floor
# is needed in addition to reading the status.
expect_reject_because "build-invocation/zero-files-scanned-is-refused" \
  "scanned ZERO files" \
  "$here/build-invocation-lint.sh" "$(mktemp -d -p "$NC_TMP")"

# REJECT: the scan itself errors (#219). A nonexistent root printed NOTHING at
# all -- find's message went to /dev/null and its exit status died inside a
# process substitution -- and reported `ok`.
expect_reject_because "build-invocation/scan-error-is-not-a-clean-tree" \
  "the file scan errored" \
  "$here/build-invocation-lint.sh" "$(mktemp -d -p "$NC_TMP")/nope"

# REJECT: a file `find` listed but `awk` could not read (#219). find needs
# permission on the DIRECTORY, not on the file, so an unreadable file was listed,
# awk failed with `can't open file`, the process substitution swallowed the
# status, the inner loop saw no lines, and a file carrying a REAL violation was
# scanned as clean at `ok` / rc 0. Verified against the pre-change gate.
#
# SKIPPED FOR root, which reads a 000 file regardless, so the branch would never
# fire and the probe would report NEG-FAIL for a property of the runner rather
# than of the gate.
if [ "$(id -u)" -eq 0 ]; then
  echo "neg-skip: [build-invocation/unreadable-file-is-not-cleared] running as root; chmod 000 cannot make awk fail"
  skipped=$((skipped+1))
else
  tmpC3="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpC3/.github/workflows"
  printf 'jobs:\n  b:\n    steps:\n      - run: cargo build --workspace --release\n' > "$tmpC3/.github/workflows/bad.yml"
  chmod 000 "$tmpC3/.github/workflows/bad.yml"
  expect_reject_because "build-invocation/unreadable-file-is-not-cleared" \
    "could not read" \
    "$here/build-invocation-lint.sh" "$tmpC3"
  chmod 644 "$tmpC3/.github/workflows/bad.yml"
fi

# REJECT: `cargo build` with NO `-p` at all -- the most likely violation of the
# "exactly one -p" rule, and the one that could not be probed before #219.
# Under `pipefail` the zero-match `grep -oE '-p'` failed the pipeline, the
# assignment failed, and `set -e` killed the script BEFORE the FAIL printed:
# rc 1 with nothing on stdout OR stderr. `expect_reject` requires a printed
# FAIL, so the gate's central assertion had no coverage for its commonest case.
tmpC4="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpC4/.github/workflows"
printf 'jobs:\n  b:\n    steps:\n      - run: cargo build --release\n' > "$tmpC4/.github/workflows/nop.yml"
expect_reject_because "build-invocation/zero-p-is-refused" \
  "exactly one -p (got 0)" \
  "$here/build-invocation-lint.sh" "$tmpC4"

# The `ci/gates` prune is this gate's one deliberate blind spot, and it was
# unprobed: nothing showed that a `cargo build --workspace` string UNDER
# `ci/gates/` is skipped rather than flagged, nor that the prune is scoped to
# `ci/gates` and not to `ci/` wholesale. Both halves, one fixture each.
tmpC5="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpC5/.github/workflows" "$tmpC5/ci/gates"
printf 'jobs:\n  b:\n    steps:\n      - run: cargo build -p maknaed --release\n' > "$tmpC5/.github/workflows/good.yml"
printf 'cargo build --workspace --release\n' > "$tmpC5/ci/gates/fixture-strings.sh"
expect_accept "build-invocation/ci-gates-is-pruned" "build-invocation-lint: ok" \
  "$here/build-invocation-lint.sh" "$tmpC5"

tmpC6="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpC6/.github/workflows" "$tmpC6/ci"
printf 'jobs:\n  b:\n    steps:\n      - run: cargo build -p maknaed --release\n' > "$tmpC6/.github/workflows/good.yml"
printf 'cargo build --workspace --release\n' > "$tmpC6/ci/other.sh"
expect_reject_because "build-invocation/prune-does-not-cover-all-of-ci" \
  "workspace/all build" \
  "$here/build-invocation-lint.sh" "$tmpC6"

# Fixture D — artifact INVENTORY witness (the reliable P2b half): a CLI that links a privileged
# crate must be caught by p2-artifact-witness via the cargo-auditable inventory. CI-gated: the
# inventory needs cargo-auditable + rust-audit-info; skipped locally (matches the witness itself).
if command -v rust-audit-info >/dev/null 2>&1 && cargo auditable --version >/dev/null 2>&1; then
  tmpD="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpD/crates/maknae-kernel/src" "$tmpD/bins/maknae/src"
  cat > "$tmpD/Cargo.toml" <<'EOF'
[workspace]
resolver = "3"
members = ["crates/maknae-kernel", "bins/maknae"]
EOF
  cat > "$tmpD/crates/maknae-kernel/Cargo.toml" <<'EOF'
[package]
name = "maknae-kernel"
version = "0.0.0"
edition = "2021"
EOF
  echo 'pub const M: &str = "x";' > "$tmpD/crates/maknae-kernel/src/lib.rs"
  cat > "$tmpD/bins/maknae/Cargo.toml" <<'EOF'
[package]
name = "maknae"
version = "0.0.0"
edition = "2021"
[[bin]]
name = "maknae"
path = "src/main.rs"
[dependencies]
maknae-kernel = { path = "../../crates/maknae-kernel" }
EOF
  echo 'fn main(){ println!("{}", maknae_kernel::M); }' > "$tmpD/bins/maknae/src/main.rs"
  expect_reject "p2/artifact-inventory-witness" "$here/p2-artifact-witness.sh" "$tmpD"
else
  echo "neg-skip: [p2/artifact-inventory-witness] deferred to CI (needs cargo-auditable + rust-audit-info)"
  skipped=$((skipped+1))
fi

# --- Fixture E: coverage-tiers gate (ADR-0016) — unclassified file must FAIL.
# Injection contract (both required vars + --injection; env-prefixed argv is
# the pinned shape for this, the first env-prefixed fixture in this file).
tmpE="$(mktemp -d -p "$NC_TMP")"
mkdir -p "$tmpE/crates/x/src"
printf 'pub fn a() -> u32 { 1 }\n' > "$tmpE/crates/x/src/core.rs"
printf 'crates/x/src/core.rs\ncrates/x/src/rogue.rs\n' > "$tmpE/files.list"
cat > "$tmpE/cov.json" <<EOF
{"type":"llvm.coverage.json.export","version":"3.0.1","data":[{"functions":[
 {"filenames":["$tmpE/crates/x/src/core.rs"],"regions":[[1,1,1,20,5,0,0,0]]}],"files":[]}]}
EOF
cat > "$tmpE/coverage-tiers.toml" <<'EOF'
[universe]
exclude = []
[t1]
floor_production_region = 95
files = ["crates/x/src/core.rs"]
mutants_crates = []
[t2]
floor_production_region = 90
files = []
[project]
ratchet_floor = 0
ratchet_cohort = []
[project.ratchet_provenance]
value = 0.0
date = "2026-08-04"
lane = "fixture"
command = "fixture"
EOF
expect_reject "coverage-tiers/unclassified-file" \
  env COVERAGE_TIERS_JSON="$tmpE/cov.json" COVERAGE_TIERS_FILELIST="$tmpE/files.list" \
      "$here/coverage-tiers.sh" --root "$tmpE" --injection

tmpF="$(mktemp -d -p "$NC_TMP")"
mkdir -p "$tmpF/ci/gates" "$tmpF/crates/x/src"
cp "$here/std-fs-drift.sh" "$tmpF/ci/gates/"
: > "$tmpF/ci/gates/std-fs-allowlist.txt"
printf 'pub fn bad(p: &std::path::Path) { let _ = std::fs::read(p); }\n' > "$tmpF/crates/x/src/lib.rs"
git -C "$tmpF" init -q
git -C "$tmpF" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/lib.rs
expect_reject "std-fs-drift/production-call" "$tmpF/ci/gates/std-fs-drift.sh" "$tmpF"

std_fs_reject() {
  local label="$1" source="$2" fixture
  fixture="$(mktemp -d -p "$NC_TMP")"
  mkdir -p "$fixture/ci/gates" "$fixture/crates/x/src"
  cp "$here/std-fs-drift.sh" "$fixture/ci/gates/"
  : > "$fixture/ci/gates/std-fs-allowlist.txt"
  printf '%b' "$source" > "$fixture/crates/x/src/lib.rs"
  git -C "$fixture" init -q
  git -C "$fixture" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/lib.rs
  expect_reject "std-fs-drift/$label" "$fixture/ci/gates/std-fs-drift.sh" "$fixture"
}

# Literal-source variants: the fixture text is read verbatim from stdin (heredoc), so char
# literals and backslash escapes survive without printf %b or shell-quoting mangling.
std_fs_reject_literal() { # <label> — fixture source on stdin
  local label="$1" fixture
  fixture="$(mktemp -d -p "$NC_TMP")"
  mkdir -p "$fixture/ci/gates" "$fixture/crates/x/src"
  cp "$here/std-fs-drift.sh" "$fixture/ci/gates/"
  : > "$fixture/ci/gates/std-fs-allowlist.txt"
  cat > "$fixture/crates/x/src/lib.rs"
  git -C "$fixture" init -q
  git -C "$fixture" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/lib.rs
  expect_reject "std-fs-drift/$label" "$fixture/ci/gates/std-fs-drift.sh" "$fixture"
}

std_fs_accept_literal() { # <label> — fixture source on stdin; gate must stay green
  local label="$1" fixture
  fixture="$(mktemp -d -p "$NC_TMP")"
  mkdir -p "$fixture/ci/gates" "$fixture/crates/x/src"
  cp "$here/std-fs-drift.sh" "$fixture/ci/gates/"
  : > "$fixture/ci/gates/std-fs-allowlist.txt"
  cat > "$fixture/crates/x/src/lib.rs"
  git -C "$fixture" init -q
  git -C "$fixture" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/lib.rs
  total=$((total+1))
  if "$fixture/ci/gates/std-fs-drift.sh" "$fixture" >/dev/null 2>&1; then
    echo "neg-ok: [std-fs-drift/$label] clean fixture permitted"; pass=$((pass+1))
  else
    echo "NEG-FAIL: [std-fs-drift/$label] clean fixture was rejected"
  fi
}

std_fs_reject "grouped-import" 'use std::{fs};\npub fn bad() { let _ = fs::copy("a", "b"); }\n'
std_fs_reject "unlisted-operation" 'pub fn bad() { let _ = std::fs::copy("a", "b"); }\n'
std_fs_reject "whitespace-qualified" 'pub fn bad() { let _ = std :: fs :: read("a"); }\n'
std_fs_reject "production-after-test" '#[cfg(test)]\nmod tests {}\npub fn bad() { let _ = std::fs::read("a"); }\n'
std_fs_reject "async-production-after-test" '#[cfg(test)]\nmod tests {}\npub async fn bad() { let _ = std::fs::read("a"); }\n'
std_fs_reject "std-module-alias" 'use std as platform;\npub fn bad() { let _ = platform::fs::read("a"); }\n'
std_fs_reject "absolute-std-module-alias" 'use ::std as platform;\npub fn bad() { let _ = platform::fs::read("a"); }\n'
std_fs_reject "absolute-fs-module-alias" 'use ::std::fs as disk;\npub fn bad() { let _ = disk::read("a"); }\n'
std_fs_reject "grouped-std-self-alias" 'use std::{self as platform};\npub fn bad() { let _ = platform::fs::read("a"); }\n'
std_fs_reject "unqualified-import" 'use std::fs::read;\npub fn bad() { let _ = read("a"); }\n'
std_fs_reject "commented-crate-test-attribute" '// #![cfg(test)]\npub fn bad() { let _ = std::fs::read("a"); }\n'
std_fs_reject "string-crate-test-attribute" 'const S: &str = "#![cfg(test)]";\npub fn bad() { let _ = std::fs::read("a"); }\n'

# Issue #130 — a glob import of std makes `fs::` resolvable with no `std::fs` token anywhere.
std_fs_reject "glob-import" 'use std::*;\npub fn bad(p: &path::Path) { let _ = fs::read(p); }\n'
std_fs_reject "absolute-glob-import" 'use ::std::*;\npub fn bad(p: &path::Path) { let _ = fs::read(p); }\n'
std_fs_reject "grouped-glob-import" 'use std::{path, *};\npub fn bad(p: &path::Path) { let _ = fs::read(p); }\n'
std_fs_reject "grouped-only-glob-import" 'use std::{*};\npub fn bad(p: &path::Path) { let _ = fs::read(p); }\n'
std_fs_reject "fs-glob-import" 'use std::fs::*;\npub fn bad(p: &std::path::Path) { let _ = read(p); }\n'

# Issue #131 — an escaped char literal must not desync the lexer into string state and mask
# the production std::fs call that follows it.
std_fs_reject_literal "char-escape-double-quote" <<'FIXTURE'
pub fn q() -> char { '\"' }
pub fn bad(p: &std::path::Path) { let _ = std::fs::read(p); }
FIXTURE

std_fs_reject_literal "char-escape-single-quote" <<'FIXTURE'
pub fn q() -> char { '\'' }
pub fn bad(p: &std::path::Path) { let _ = std::fs::read(p); }
FIXTURE

std_fs_reject_literal "char-escape-backslash" <<'FIXTURE'
pub fn q() -> char { '\\' }
pub fn bad(p: &std::path::Path) { let _ = std::fs::read(p); }
FIXTURE

# Positive control for the same lexer: lifetimes must never be mistaken for char literals, and a
# plain 3-byte char literal must still mask, so a cfg(test)-only std::fs call stays permitted.
std_fs_accept_literal "lifetimes-and-char-literals" <<'FIXTURE'
pub struct Holder<'a> { pub name: &'a str }
impl<'a> Holder<'a> {
    pub fn name(&self) -> &'a str { self.name }
}
pub fn sep() -> char { 'x' }
pub fn anon(h: &Holder<'_>) -> usize { h.name.len() }
#[cfg(test)]
mod tests {
    fn fixture(p: &std::path::Path) { let _ = std::fs::read(p); }
}
FIXTURE

# Issue #132 — the requirement-free-read inventory. The field-name arms (`owner: None`,
# `mode_mask: None`) only ever saw the STRUCT-LITERAL spelling, so a requirement passed
# positionally or through a variable slipped past — `read_secure_required(path, None,
# Some(0o007))` was the live example. maknae-io now names those requirements
# (`AnchorRequired::OS_DAC`, `DescendantRequired::OS_DAC`, `TargetRequired::OS_DAC_REGULAR`)
# and the gate inventories the IDENTIFIER, so an unlisted requirement-free read is caught
# whichever spelling it uses. Both spellings get a control; neither may go quiet.
std_fs_reject "requirement-anchor-identifier" 'pub fn bad() -> R { open(AnchorRequired::OS_DAC) }\n'
std_fs_reject "requirement-descendant-identifier" 'pub fn bad() -> R { scan(maknae_io::DescendantRequired::OS_DAC) }\n'
std_fs_reject "requirement-target-identifier" 'pub fn bad() -> R { read(maknae_io::TargetRequired::OS_DAC_REGULAR) }\n'
std_fs_reject "requirement-struct-literal-owner" 'pub fn bad() -> R { read(T { owner: None, mode_mask: Some(0o007) }) }\n'
std_fs_reject "requirement-struct-literal-mode" 'pub fn bad() -> R { read(T { owner: Some(0), mode_mask: None }) }\n'

# Positive control for the identifier arm: `\b` must not fire on an unrelated identifier
# that merely CONTAINS the token, or every rename becomes an allowlist event.
std_fs_accept_literal "requirement-identifier-substring" <<'FIXTURE'
pub const OS_DAC_UNRELATED_SUFFIX: u32 = 1;
pub fn fine() -> u32 { NOT_OS_DAC + OS_DAC_UNRELATED_SUFFIX }
FIXTURE

tmpF_alias="$(mktemp -d -p "$NC_TMP")"
mkdir -p "$tmpF_alias/ci/gates" "$tmpF_alias/crates/x/src"
cp "$here/std-fs-drift.sh" "$tmpF_alias/ci/gates/"
: > "$tmpF_alias/ci/gates/std-fs-allowlist.txt"
printf 'use std::fs as disk;\npub fn bad(p: &std::path::Path) { let _ = disk::read(p); }\n' > "$tmpF_alias/crates/x/src/lib.rs"
git -C "$tmpF_alias" init -q
git -C "$tmpF_alias" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/lib.rs
expect_reject "std-fs-drift/module-alias" "$tmpF_alias/ci/gates/std-fs-drift.sh" "$tmpF_alias"

tmpF_stale="$(mktemp -d -p "$NC_TMP")"
mkdir -p "$tmpF_stale/ci/gates" "$tmpF_stale/crates/x/src"
cp "$here/std-fs-drift.sh" "$tmpF_stale/ci/gates/"
printf 'crates/x/src/lib.rs:1|use std::fs::File;\n' > "$tmpF_stale/ci/gates/std-fs-allowlist.txt"
printf 'pub fn clean() {}\n' > "$tmpF_stale/crates/x/src/lib.rs"
git -C "$tmpF_stale" init -q
git -C "$tmpF_stale" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/lib.rs
expect_reject "std-fs-drift/stale-exemption" "$tmpF_stale/ci/gates/std-fs-drift.sh" "$tmpF_stale"

tmpF2="$(mktemp -d -p "$NC_TMP")"
mkdir -p "$tmpF2/ci/gates" "$tmpF2/crates/x/src"
cp "$here/std-fs-drift.sh" "$tmpF2/ci/gates/"
: > "$tmpF2/ci/gates/std-fs-allowlist.txt"
printf '#[cfg(test)]\nmod tests { fn fixture(p: &std::path::Path) { let _ = std::fs::read(p); } }\n' > "$tmpF2/crates/x/src/lib.rs"
git -C "$tmpF2" init -q
git -C "$tmpF2" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/lib.rs
if ! "$tmpF2/ci/gates/std-fs-drift.sh" "$tmpF2" >/dev/null; then
  echo "NEG-FAIL: [std-fs-drift/test-only] test fixture was rejected"
  exit 1
fi
echo "neg-ok: [std-fs-drift/test-only] test fixture permitted"

tmpF3="$(mktemp -d -p "$NC_TMP")"
mkdir -p "$tmpF3/ci/gates" "$tmpF3/crates/x/src/tests"
cp "$here/std-fs-drift.sh" "$tmpF3/ci/gates/"
: > "$tmpF3/ci/gates/std-fs-allowlist.txt"
printf 'pub fn bad() { let _ = std::fs::read("a"); }\n' > "$tmpF3/crates/x/src/tests/bad.rs"
git -C "$tmpF3" init -q
git -C "$tmpF3" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/tests/bad.rs
expect_reject "std-fs-drift/src-tests-production" "$tmpF3/ci/gates/std-fs-drift.sh" "$tmpF3"

tmpF4="$(mktemp -d -p "$NC_TMP")"
mkdir -p "$tmpF4/ci/gates" "$tmpF4/crates/x/src"
cp "$here/std-fs-drift.sh" "$tmpF4/ci/gates/"
: > "$tmpF4/ci/gates/std-fs-allowlist.txt"
printf 'pub fn fixture() { let _ = std::fs::read("a"); }\n' > "$tmpF4/crates/x/src/transport_tests.rs"
git -C "$tmpF4" init -q
git -C "$tmpF4" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/transport_tests.rs
expect_reject "std-fs-drift/external-test-lost-cfg" "$tmpF4/ci/gates/std-fs-drift.sh" "$tmpF4"

# --- Fixture G: feature-resolution-pin (#77) — a production binary whose
# NORMAL dependency enables hermetic-test-seam must be rejected. Synthetic
# path-deps-only workspace (the pin needs a full cargo resolve, unlike p1's
# --no-deps metadata): "maknaed" normally-depends on a "maknae-config" that
# declares the feature, WITH the feature enabled.
tmpG="$(mktemp -d -p "$NC_TMP")"
mkdir -p "$tmpG/crates/maknae-config/src" "$tmpG/bins/maknaed/src" "$tmpG/bins/maknae/src" "$tmpG/bins/maknae-spifc/src"
cat > "$tmpG/Cargo.toml" <<'EOF_G'
[workspace]
resolver = "3"
members = ["crates/maknae-config", "bins/maknaed", "bins/maknae", "bins/maknae-spifc"]
EOF_G
cat > "$tmpG/crates/maknae-config/Cargo.toml" <<'EOF_G'
[package]
name = "maknae-config"
version = "0.0.0"
edition = "2021"
[features]
hermetic-test-seam = []
EOF_G
echo '' > "$tmpG/crates/maknae-config/src/lib.rs"
for b in maknaed maknae maknae-spifc; do
  cat > "$tmpG/bins/$b/Cargo.toml" <<EOF_G
[package]
name = "$b"
version = "0.0.0"
edition = "2021"
[dependencies]
maknae-config = { path = "../../crates/maknae-config" }
EOF_G
  echo 'fn main() {}' > "$tmpG/bins/$b/src/main.rs"
done
# The violation: maknaed's NORMAL dep enables the seam feature.
cat > "$tmpG/bins/maknaed/Cargo.toml" <<'EOF_G'
[package]
name = "maknaed"
version = "0.0.0"
edition = "2021"
[dependencies]
maknae-config = { path = "../../crates/maknae-config", features = ["hermetic-test-seam"] }
EOF_G
expect_reject "feature-resolution-pin/normal-dep-enables-seam" "$here/feature-resolution-pin.sh" "$tmpG"


# ---- verb-vocabulary-drift (#67): the action vocabulary vs its manifest ----
# Durable fixtures, not a one-off manual proof: a gate is only trusted once it
# has been OBSERVED failing, and that observation must be re-run on every PR.
vocab_fixture() { # <manifest-body> — builds a minimal repo the gate can read
  local fixture
  fixture="$(mktemp -d -p "$NC_TMP")"
  mkdir -p "$fixture/ci/gates" "$fixture/crates/maknae-kernel/src" \
           "$fixture/crates/maknae-config/src" "$fixture/crates/maknae-authz-basic/src"
  cp "$here/verb-vocabulary-drift.sh" "$fixture/ci/gates/"
  # Unquoted heredoc (#172): the body is `$`-free Rust, and `$3` is an optional
  # extra `verb_to_action` arm (default empty) for probes that carry a term.
  cat > "$fixture/crates/maknae-kernel/src/handler.rs" <<FIX
pub const KERNEL_ACTIONS: [&str; 1] = ["kernel.contain"];
pub fn verb_to_action(verb: &Verb) -> &'static str {
    match verb {
        Verb::Ping => "liveness.ping",
        Verb::AdminStatus => "admin.status",
${3:-}
    }
}
FIX
  cat > "$fixture/crates/maknae-config/src/authz.rs" <<'FIX'
fn parse_pattern(spec: &str) -> Result<Pattern, AuthzError> {
    match capability {
        "Read" => Ok(Pattern::Read(g)),
        _ => Err(bad()),
    }
}
FIX
  # The spelling here must MATCH production exactly -- `pub(crate)`, one line --
  # or the control exercises a different anchor than the one that ships.
  # $2 overrides the grantable constant, for the subset control below.
  printf '%s\n' "${2:-pub(crate) const GRANTABLE_ACTIONS: [&str; 4] = [\"admin.status\", \"admin.config.show\", \"admin.subject.list\", \"session.prompt\"];}" \
    > "$fixture/crates/maknae-authz-basic/src/decide.rs"
  printf '%s' "$1" > "$fixture/ci/gates/verb-manifest.txt"
  echo "$fixture"
}

# REJECT: admin.status exists in the code but has no recorded disposition.
fx="$(vocab_fixture 'action	liveness.ping	granted	shipped
kernel-action	kernel.contain	not-granted	no Verb variant
capability	Read	granted	the only capability
grantable	admin.status	grantable-not-granted	per-role via roles:
grantable	admin.config.show	grantable-not-granted	per-role via roles:
grantable	admin.subject.list	grantable-not-granted	per-role via roles:
')"
expect_reject_because "verb-vocabulary-drift/term-with-no-disposition" \
  "+action	admin.status" "$fx/ci/gates/verb-vocabulary-drift.sh"

# REJECT: a stale manifest entry for a term the code no longer has.
fx="$(vocab_fixture 'action	liveness.ping	granted	shipped
action	admin.status	not-granted	enumerated
action	admin.retired	not-granted	STALE — no such term
kernel-action	kernel.contain	not-granted	no Verb variant
capability	Read	granted	the only capability
grantable	admin.status	grantable-not-granted	per-role via roles:
grantable	admin.config.show	grantable-not-granted	per-role via roles:
grantable	admin.subject.list	grantable-not-granted	per-role via roles:
')"
expect_reject_because "verb-vocabulary-drift/stale-manifest-entry" \
  "-action	admin.retired" "$fx/ci/gates/verb-vocabulary-drift.sh"

# REJECT: a grammar capability with no recorded disposition — R7 covers BOTH
# closed vocabularies, so a capability added to the grammar must be inventoried.
fx="$(vocab_fixture 'action	liveness.ping	granted	shipped
action	admin.status	not-granted	enumerated
kernel-action	kernel.contain	not-granted	no Verb variant
grantable	admin.status	grantable-not-granted	per-role via roles:
grantable	admin.config.show	grantable-not-granted	per-role via roles:
grantable	admin.subject.list	grantable-not-granted	per-role via roles:
')"
expect_reject_because "verb-vocabulary-drift/capability-with-no-disposition" \
  "+capability	Read" "$fx/ci/gates/verb-vocabulary-drift.sh"

# REJECT: a GRANTABLE term with no recorded disposition (#162). The grantable
# list is a fourth closed vocabulary — a term an operator can write into
# `roles:` must carry a decision like any other.
fx="$(vocab_fixture 'action	liveness.ping	granted	shipped
action	admin.status	not-granted	enumerated
kernel-action	kernel.contain	not-granted	no Verb variant
capability	Read	granted	the only capability
grantable	admin.status	grantable-not-granted	per-role via roles:
' 'pub(crate) const GRANTABLE_ACTIONS: [&str; 2] = ["admin.status", "admin.config.show"];')"
expect_reject_because "verb-vocabulary-drift/grantable-with-no-disposition" \
  "+grantable	admin.config.show" "$fx/ci/gates/verb-vocabulary-drift.sh"

# ACCEPT: the clean fixture passes, and reports the full count. Without this
# every control above would still report neg-ok against a gate that rejects
# EVERYTHING — including a correct repo. The count is asserted with its
# leading ": " and trailing " terms," because a bare `7 terms` also matches
# `17 terms`.
# The grantable set is narrowed to the fixture's OWN action vocabulary. The
# shared handler.rs heredoc defines two actions, so admin.status is the only
# grantable term that has an action behind it -- and the subset rule added for
# #162 means a fixture claiming the other two is not clean. It caught this
# fixture the moment it was written, which is the control working.
# Five = 2 actions + kernel.contain + Read + 1 grantable.
# Rationales carry the #181 clause vocabulary: the clause check runs LAST in
# the gate, so a CLEAN fixture must satisfy it (the five reject fixtures above
# keep short rationales because the inventory/subset checks fire first).
CLEAN_VOCAB='action	liveness.ping	granted	shipped; the fixture liveness term
action	admin.status	not-granted	unbuilt — answers Unauthorized like every refusal
kernel-action	kernel.contain	not-granted	no Verb variant
capability	Read	granted	the only grammar capability
grantable	admin.status	grantable-not-granted	operator MAY grant per-role via `roles:`
'
fx="$(vocab_fixture "$CLEAN_VOCAB" 'pub(crate) const GRANTABLE_ACTIONS: [&str; 1] = ["admin.status"];')"
expect_accept "verb-vocabulary-drift/clean-fixture-passes" ": 5 terms," "$fx/ci/gates/verb-vocabulary-drift.sh"

# REJECT (#172): the code says session.prompt is grantable (a real action, decided, dispatched);
# the manifest carries its action row but no grantable row. Every row carries its clause, so
# the ONLY inconsistency is the missing row and the gate fires for that reason and no other.
PROMPT_ACTION_ROW='action	session.prompt	not-granted-but-grantable	Ungranted by default; operator MAY grant per-role; the fixture egress term'
PROMPT_GRANTABLE_ROW='grantable	session.prompt	grantable-not-granted	operator MAY grant per-role via `roles:`'
PROMPT_CONST='pub(crate) const GRANTABLE_ACTIONS: [&str; 2] = ["admin.status", "session.prompt"];'
PROMPT_ARM='        Verb::SessionPrompt { .. } => "session.prompt",'
fx="$(vocab_fixture "${CLEAN_VOCAB}${PROMPT_ACTION_ROW}
" "$PROMPT_CONST" "$PROMPT_ARM")"
expect_reject_because "verb-vocabulary-drift/grantable-term-with-no-grantable-row" \
  "+grantable	session.prompt" "$fx/ci/gates/verb-vocabulary-drift.sh"

# ACCEPT (#172, the reversing control): the same fixture WITH the grantable row passes.
fx="$(vocab_fixture "${CLEAN_VOCAB}${PROMPT_ACTION_ROW}
${PROMPT_GRANTABLE_ROW}
" "$PROMPT_CONST" "$PROMPT_ARM")"
expect_accept "verb-vocabulary-drift/prompt-rows-consistent" ": 7 terms," "$fx/ci/gates/verb-vocabulary-drift.sh"

# REJECT (#181, durable): a row whose disposition and rationale DISAGREE — the
# rationale lacks its (kind, disposition) clause. The one-time capture of the
# real 51-row defect is evidence in the PR; THIS fixture is the control that
# re-runs on every PR (the repo's own negative-control discipline: a one-off
# observation is not a control).
fx="$(vocab_fixture "$(printf '%s' "$CLEAN_VOCAB" | sed 's/unbuilt — answers Unauthorized like every refusal/enumerated, decided/')" \
  'pub(crate) const GRANTABLE_ACTIONS: [&str; 1] = ["admin.status"];')"
expect_reject_because "verb-vocabulary-drift/rationale-lacks-its-clause" \
  "rationale lacks its clause" "$fx/ci/gates/verb-vocabulary-drift.sh"

# REJECT (#181, durable): a THREE-field row. Before the arity check, a row
# with no disposition and no rationale passed green — `cut -f1,2` never read
# fields 3-4 — so the arity assertion is new coverage with its own control.
fx="$(vocab_fixture "$(printf '%s' "$CLEAN_VOCAB" | sed 's/^action	admin.status	not-granted	.*$/action	admin.status	not-granted/')" \
  'pub(crate) const GRANTABLE_ACTIONS: [&str; 1] = ["admin.status"];')"
expect_reject_because "verb-vocabulary-drift/three-field-row" \
  "without exactly four non-empty fields" "$fx/ci/gates/verb-vocabulary-drift.sh"

# REJECT (#181, durable): a FIVE-field row — a TAB inside a rationale. This is
# the arity check's UNIQUE coverage: a three-field row is also caught by the
# clause check (index("", clause)==0), so with the arity block deleted the
# three-field probe merely rejects for the wrong reason — but a tab-bearing
# rationale sails through everything else (observed: the arity-deleted gate
# ACCEPTS it at EXIT=0). The clause table's parsing assumes exactly four
# fields; this is the probe that makes that assumption enforced.
fx="$(vocab_fixture "$(printf '%s' "$CLEAN_VOCAB" | sed 's/^\(action	admin.status	not-granted	.*\)$/\1	extra-field/')" \
  'pub(crate) const GRANTABLE_ACTIONS: [&str; 1] = ["admin.status"];')"
expect_reject_because "verb-vocabulary-drift/five-field-row" \
  "without exactly four non-empty fields" "$fx/ci/gates/verb-vocabulary-drift.sh"

# REJECT (#181, durable): an INVENTED disposition. The clause table fails
# closed — a (kind, disposition) pair outside the six-pair table must never
# pass by falling off it.
fx="$(vocab_fixture "$(printf '%s' "$CLEAN_VOCAB" | sed 's/^action	admin.status	not-granted	.*$/action	admin.status	pending	someone will decide later/')" \
  'pub(crate) const GRANTABLE_ACTIONS: [&str; 1] = ["admin.status"];')"
expect_reject_because "verb-vocabulary-drift/invented-disposition" \
  "unrecognized (kind, disposition)" "$fx/ci/gates/verb-vocabulary-drift.sh"

# REJECT: a grantable term with no matching `action` term (#162). Manifest
# exactness alone does NOT catch this -- both kinds carry their own rows and
# agree with the code. The failure it prevents: an operator writes a grant that
# parses, validates and boots, for an action no request will ever carry.
fx="$(vocab_fixture 'action	liveness.ping	granted	shipped
action	admin.status	not-granted	enumerated
kernel-action	kernel.contain	not-granted	no Verb variant
capability	Read	granted	the only capability
grantable	admin.status	grantable-not-granted	per-role via roles:
grantable	session.ghost	grantable-not-granted	NO action term behind it
' 'pub(crate) const GRANTABLE_ACTIONS: [&str; 2] = ["admin.status", "session.ghost"];')"
expect_reject_because "verb-vocabulary-drift/grantable-not-a-real-action" \
  "no matching action term" "$fx/ci/gates/verb-vocabulary-drift.sh"


# ---- config-disclosure-drift (#162): the admin.config.show surface ----
# Five review rounds found this control's completeness resting on prose, and
# found the prose wrong twice. The gate replaced it -- and then the FIRST gate
# repeated the mistake, extracting parser keys with a regex over assumed call
# shapes that matched zero of the real multi-line `bounded_*` sites. These
# fixtures are the probes that defeated that version.
cfg_manifest() { # <drop-regex-or-empty> <appended-rows...> -- compose CFG_OK safely
  # `$(printf '%s' "$CFG_OK" | grep -v ...)ROW` LOSES the trailing newline:
  # command substitution strips ALL of them, so the appended row is GLUED onto
  # the last surviving one. Live instance: the `always<TAB>status` probe below
  # produced `...not oursalways<TAB>status<TAB>...` as a single line, so the row
  # it was written to test DID NOT EXIST in the fixture. It scored neg-ok
  # anyway, because `grep -v` had removed four rows and check 4b fired on the
  # fields they used to decide -- and deleting the control under test from the
  # gate left negative-control at 78/78.
  local drop="$1"; shift
  local body="$CFG_OK"
  [ -n "$drop" ] && body="$(printf '%s' "$body" | grep -v "$drop")"$'\n'
  printf '%s' "$body"
  local row
  for row in "$@"; do printf '%s\n' "$row"; done
}

cfg_fixture() { # <manifest> [extra-transport-field] [extra-disclosable-entry] [extra-wire-field] [read_timeout_ms-type] [members-type]
  # 5 and 6 RETYPE an existing field instead of adding one. Depth probes must
  # be count-NEUTRAL or the exact-count check rejects first and the depth
  # check under test is never reached.
  local fixture
  fixture="$(mktemp -d -p "$NC_TMP")"
  mkdir -p "$fixture/ci/gates" "$fixture/crates/maknae-config/src" \
           "$fixture/crates/maknae-vault/src" "$fixture/crates/maknae-kernel/src" \
           "$fixture/crates/maknae-proto/src"
  # `StatusView` is the second disclosure surface (admin.status returns it
  # whole); the gate's SURFACE table names it, so a fixture needs it too.
  cat > "$fixture/crates/maknae-proto/src/wire.rs" <<FIX
pub struct StatusView {
    pub version: String,
    pub protocol_version: u16,
    pub listener: String,
    pub authz_backend: String,
    pub classification_policy: String,
}

pub struct RoleBindingView {
    pub role: String,
    pub members: ${6:-Vec<String>},
    ${4:-}
}

pub struct WhoamiView {
    pub peer_plane_uri_san: String,
    pub peer_uid: u32,
}

pub enum Payload {
    Pong,
    Whoami(WhoamiView),
    ReadContent(crate::Bytes),
    ConfigView(std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>),
    Status(StatusView),
    SubjectList(Vec<RoleBindingView>),
    MutationComplete,
    MutationAttempt(crate::MutationGrant),
    PromptReply(PromptReply),
}
FIX
  cp "$here/mutation-disclosure.py" "$fixture/ci/gates/"
  cp "$here/mutation-disclosure-manifest.txt" "$fixture/ci/gates/"
  cp "$here/../../crates/maknae-proto/src/mutation.rs" "$fixture/crates/maknae-proto/src/"
  # The gate cross-checks its SURFACE list against the section registry, so a
  # fixture needs one.
  cat > "$fixture/crates/maknae-kernel/src/boot.rs" <<'FIX'
const LAKE_SECTION: &str = "lake";
const VAULT_SECTION: &str = "vault";
const TRANSPORT_SECTION: &str = "transport";
const AUDIT_SECTION: &str = "audit";
const PRINCIPAL_SECTION: &str = "principal";
const PROVIDER_SECTION: &str = "provider";
    let specs = [
        SectionSpec { name: LAKE_SECTION.to_string(), required: false },
        SectionSpec { name: VAULT_SECTION.to_string(), required: false },
        SectionSpec { name: TRANSPORT_SECTION.to_string(), required: false },
        SectionSpec { name: AUDIT_SECTION.to_string(), required: false },
        SectionSpec { name: PRINCIPAL_SECTION.to_string(), required: false },
        SectionSpec { name: PROVIDER_SECTION.to_string(), required: false },
    ];
FIX
  cp "$here/config-disclosure-drift.sh" "$fixture/ci/gates/"
  cat > "$fixture/crates/maknae-config/src/document.rs" <<FIX
const DISCLOSABLE: &[&str] = &[
    "transport",
    "provider.name",
    "provider.endpoint",
    "provider.model",
    "vault.addr",
    "vault.approle_mount",
    "vault.pki_int_mount",
    "vault.deployment_id",
    "audit.jsonl_path",
    "principal",
    ${3:-}
];
const SUPPRESSED: &[&str] = &[
    "vault.insecure_plaintext_secret_path",
    "core.handling",
    "audit.au3_1",
    "provider.key_vault_path",
];
FIX
  # The field is declared MULTI-LINE-parser style deliberately: the shape that
  # defeated the regex extraction is exactly what must be covered now.
  cat > "$fixture/crates/maknae-config/src/transport.rs" <<FIX
pub struct TransportConfig {
    pub socket_path: PathBuf,
    pub max_connections: u32,
    pub frame_max_bytes: usize,
    pub handshake_timeout_ms: u64,
    pub read_timeout_ms: ${5:-u64},
    ${2:-}
}
FIX
  # Each stub carries at least one field: the gate now REFUSES a surface entry
  # that contributes nothing, so an empty struct is not a valid fixture.
  cat > "$fixture/crates/maknae-config/src/audit_cfg.rs" <<'FIX'
pub struct AuditConfig {
    pub jsonl_path: PathBuf,
    pub siem: Option<String>,
    pub au3_1: serde_json::Value,
}
FIX
  cat > "$fixture/crates/maknae-config/src/principal.rs" <<'FIX'
pub struct Principal {
    pub name: String,
    pub uid: u32,
    pub home: PathBuf,
}
FIX
  # #243: the provider registration -- three disclosed leaves and one omitted.
  cat > "$fixture/crates/maknae-config/src/provider.rs" <<'FIX'
pub struct ProviderConfig {
    pub name: String,
    pub endpoint: String,
    pub model: String,
    pub key_vault_path: String,
}
FIX
  cat > "$fixture/crates/maknae-config/src/ceiling.rs" <<'FIX'
pub struct Ceiling {
    pub classification: String,
    pub sci: bool,
    pub releasable_to: Vec<String>,
    pub cui_permitted: bool,
    pub cui_categories_permitted: Vec<String>,
    pub dissemination_permitted: Vec<String>,
    pub accreditation_ref: Option<String>,
}
FIX
  cat > "$fixture/crates/maknae-vault/src/config.rs" <<'FIX'
pub struct VaultConfig {
    pub addr: String,
    pub approle_mount: String,
    pub pki_int_mount: String,
    pub deployment_id: String,
    pub insecure_plaintext_secret_path: Option<PathBuf>,
}
FIX
  printf '%s' "$1" > "$fixture/ci/gates/config-disclosure-manifest.txt"
  echo "$fixture"
}

TABCH="$(printf '\t')"
CFG_OK='disclose	transport	transport shape, all fields
disclose	vault.addr	where vault is
mask	audit.siem	endpoint, no schema
omit	audit.au3_1	deployer-authored, unenumerable
disclose	vault.approle_mount	mount name
disclose	vault.pki_int_mount	mount name
disclose	vault.deployment_id	fallback spelling
disclose	principal	readable via getpwuid anyway
disclose	provider.name	the registered provider label
disclose	provider.endpoint	where the loop content goes
disclose	provider.model	the model identifier
omit	provider.key_vault_path	secret-store layout
disclose	audit.jsonl_path	the log the operator is looking for
omit	vault.insecure_plaintext_secret_path	presence is the finding
omit	core.handling	presence says an above-baseline ceiling is configured
always	status.version	ships by construction
always	status.protocol_version	ships by construction
always	status.listener	ships by construction
always	status.authz_backend	ships by construction
always	status.classification_policy	ships by construction
always	binding.role	ships by construction
always	binding.members	ships by construction
always	whoami.peer_plane_uri_san	ships by construction
always	whoami.peer_uid	ships by construction
mask	lake	the Knowledge Lake schema, not ours
'

# REJECT: a NEW config struct field with no recorded decision. This is the miss
# the whole loop kept finding, and the shape the regex extraction could not see.
fx="$(cfg_fixture "$CFG_OK" 'pub debug_core_dump_path: PathBuf,')"
expect_reject_because "config-disclosure-drift/config-struct-field-changes-the-count" \
  "yielded 6 field(s), expected 5" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: check 4b -- a counted field with no manifest decision. Named
# `struct-field-with-no-decision` and probed by APPENDING a field, this fired on
# the field COUNT and never reached 4b at all; under the fixture's bare
# `disclose<TAB>transport` prefix row the new field was decided by prefix, so
# 4b could not have fired even if reached. The gate's CENTRAL claim -- that an
# undecided field fails the build -- therefore had no negative control on the
# config surface, while the harness printed neg-ok. Bump the SURFACE count so
# the field is legitimately counted, and decide the transport fields
# INDIVIDUALLY (as the real manifest does) so the new one is genuinely undecided.
fx="$(cfg_fixture "$(printf '%s' "$CFG_OK" | sed "s|^disclose${TABCH}transport${TABCH}.*|disclose${TABCH}transport.socket_path${TABCH}shape\ndisclose${TABCH}transport.max_connections${TABCH}shape\ndisclose${TABCH}transport.frame_max_bytes${TABCH}shape\ndisclose${TABCH}transport.handshake_timeout_ms${TABCH}shape\ndisclose${TABCH}transport.read_timeout_ms${TABCH}shape|")" \
  'pub debug_core_dump_path: PathBuf,')"
python3 - "$fx" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
g = root / "ci/gates/config-disclosure-drift.sh"
s = g.read_text()
old = "TransportConfig|transport|5|config"
assert s.count(old) == 1, "fixture count anchor moved"
g.write_text(s.replace(old, "TransportConfig|transport|6|config"))
# The CODE side must itemize too, or check 3 (DISCLOSABLE-vs-manifest
# agreement) fires first and 4b is again never reached.
d = root / "crates/maknae-config/src/document.rs"
t = d.read_text()
assert t.count('    "transport",\n') == 1, "fixture DISCLOSABLE anchor moved"
d.write_text(t.replace('    "transport",\n', "".join(
    '    "transport.%s",\n' % f for f in
    ("socket_path", "max_connections", "frame_max_bytes",
     "handshake_timeout_ms", "read_timeout_ms"))))
PY
expect_reject_because "config-disclosure-drift/struct-field-with-no-decision" \
  "NO recorded disclosure decision" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a path classified in code with no manifest row -- and it is HYPHENATED,
# because the first gate's charset filter dropped such entries silently instead
# of surfacing them.
fx="$(cfg_fixture "$CFG_OK" '' '"vault.pki-int-alias",')"
expect_reject "config-disclosure-drift/hyphenated-entry-with-no-decision" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a manifest row carrying a path but no rationale. "Decide it" is what
# the gate's own failure text demands; a bare path is not a decision.
fx="$(cfg_fixture "${CFG_OK}disclose	core.undecided
")"
expect_reject "config-disclosure-drift/manifest-row-with-no-rationale" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: two contradictory decisions for one path.
fx="$(cfg_fixture "${CFG_OK}mask	vault.addr	contradicts the row above
")"
expect_reject "config-disclosure-drift/duplicate-contradictory-decision" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a SURFACE entry whose struct no longer exists under that name.
# THE FAIL-OPEN THAT SURVIVED TWO EXTRACTION REWRITES. A missing anchor yields
# zero rows and a green gate: renaming TransportConfig silently removed five
# fields from the decision requirement while the gate still printed "all
# decided". Note the asymmetry that hid it -- renaming a CODE-side anchor
# (DISCLOSABLE) fails CLOSED through the 4a diff, so only the safe half had
# ever been probed.
fx="$(cfg_fixture "$CFG_OK")"
sed -i.bak 's/^pub struct TransportConfig {/pub struct TransportSettings {/' \
  "$fx/crates/maknae-config/src/transport.rs"
expect_reject "config-disclosure-drift/struct-anchor-not-found" "$fx/ci/gates/config-disclosure-drift.sh"

# ACCEPT: a rustfmt-COLLAPSED const array still extracts. `cargo fmt --check`
# is itself a CI gate, so a short list WILL be collapsed onto one line; an
# anchored, first-literal-only reader emitted zero rows for it and then told
# the reader to delete manifest rows that were correct.
fx="$(cfg_fixture "$CFG_OK")"
cat > "$fx/crates/maknae-config/src/document.rs" <<'FIX'
const DISCLOSABLE: &[&str] = &["transport", "provider.name", "provider.endpoint", "provider.model", "vault.addr", "vault.approle_mount", "vault.pki_int_mount", "vault.deployment_id", "audit.jsonl_path", "principal"];
const SUPPRESSED: &[&str] = &["vault.insecure_plaintext_secret_path", "core.handling", "audit.au3_1", "provider.key_vault_path"];
FIX
expect_accept "config-disclosure-drift/rustfmt-collapsed-array-still-read" ": 25 paths decided" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a section registered in boot.rs with no SURFACE entry. THE THIRD
# fail-open, and the one that closes the PROPERTY rather than an instance: the
# previous two fixes asked "does this anchor match?" and never "is the anchor
# list right, and is it all of them?". A new config section shipped both its
# field names on the wire with nobody asked the omit-vs-mask question.
fx="$(cfg_fixture "$CFG_OK")"
cat >> "$fx/crates/maknae-kernel/src/boot.rs" <<'FIX'
const ENCLAVE_SECTION: &str = "enclave";
    let more = [
        SectionSpec { name: ENCLAVE_SECTION.to_string(), required: false },
    ];
FIX
expect_reject "config-disclosure-drift/registered-section-with-no-surface-entry" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a pub(crate) field. Visibility is irrelevant to disclosure -- flatten
# walks the parsed Value, not the struct -- and `pub(crate)` is live house
# style here, so the old `pub [a-z0-9_]+:` regex left such a field unclassified
# while the count stayed put.
fx="$(cfg_fixture "$CFG_OK" 'pub(crate) session_token_path: PathBuf,')"
expect_reject_because "config-disclosure-drift/pub-crate-field-not-counted" \
  "yielded 6 field(s), expected 5" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a raw-identifier field. `type` is a Rust keyword and an entirely
# ordinary YAML key.
fx="$(cfg_fixture "$CFG_OK" 'pub r#type: String,')"
expect_reject_because "config-disclosure-drift/raw-identifier-field-not-counted" \
  "yielded 6 field(s), expected 5" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a SectionSpec registered with a STRING LITERAL name. boot.rs's own
# grammar accepts it, and keying the cross-check on `[A-Z_]+_SECTION` const
# NAMES could not see it -- exit 0 over an uncovered section, with the pinned
# counts unchanged so nothing else fired either.
fx="$(cfg_fixture "$CFG_OK")"
cat >> "$fx/crates/maknae-kernel/src/boot.rs" <<'FIX'
    let specs = [
        SectionSpec { name: "enclave".to_string(), required: false },
    ];
FIX
expect_reject "config-disclosure-drift/string-literal-section-registration" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a NON-pub struct field. Visibility is irrelevant to disclosure --
# `flatten` walks the parsed Value, not the struct -- and the regex kept
# keying on it, so a bare `session_token_path: PathBuf,` contributed zero rows
# and no count change. This sits beside the pub(crate) fixture deliberately:
# the two are the same property, one keyword apart.
fx="$(cfg_fixture "$CFG_OK" 'session_token_path: PathBuf,')"
expect_reject_because "config-disclosure-drift/private-field-not-counted" \
  "yielded 6 field(s), expected 5" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a scalar field turned into a config STRUCT. The silent variant of
# the depth-blind tally: the field count does not change, so nothing else in
# the gate fires, while the nested field NAMES reach the wire undecided.
# document.rs itself anticipates this exact change for `audit.siem`.
fx="$(cfg_fixture "$CFG_OK")"
python3 - "$fx" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "crates/maknae-config/src/audit_cfg.rs"
s = p.read_text()
s = s.replace("pub struct AuditConfig {",
              "pub struct SiemConfig {\n    pub url: String,\n    pub auth_token_path: PathBuf,\n}\n\npub struct AuditConfig {", 1)
s = s.replace("    pub siem: Option<String>,", "    pub siem: SiemConfig,", 1)
p.write_text(s)
PY
expect_reject_because "config-disclosure-drift/struct-typed-field-is-a-subtree" "SUBTREE" \
  "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a SectionSpec whose `name:` operand the extractor cannot resolve.
# Round 9's headline control, previously unprobed: the resolved-count tally is
# what turns an unreadable registration form into a hard failure instead of a
# silent gap, and AGENTS.md is explicit that a gate never observed failing
# proves nothing.
fx="$(cfg_fixture "$CFG_OK")"
cat >> "$fx/crates/maknae-kernel/src/boot.rs" <<'FIX'
    let more = [
        SectionSpec { name: principal_section_name(), required: false },
    ];
FIX
expect_reject "config-disclosure-drift/unresolvable-section-operand" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a SectionSpec block the operand scan misses entirely -- here because
# `required:` precedes `name:`. The resolved-vs-registered tally is the only
# thing that catches it; the coverage loop alone would see one fewer section
# and pass.
fx="$(cfg_fixture "$CFG_OK")"
cat >> "$fx/crates/maknae-kernel/src/boot.rs" <<'FIX'
    let more = [
        SectionSpec { required: false, nome: LAKE_SECTION.to_string() },
    ];
FIX
expect_reject "config-disclosure-drift/section-block-with-unreadable-name" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a NO_STRUCT_SECTIONS entry with no manifest row. Struct-less means
# the keys are carried verbatim, not that the disclosure is undecided.
fx="$(cfg_fixture "$(printf '%s' "$CFG_OK" | grep -v "^mask	lake")")"
expect_reject "config-disclosure-drift/no-struct-section-without-a-decision" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a subtree whose struct is declared `pub(crate)`. The depth check was
# anchored `^pub struct` and so re-introduced, eighty lines below the fix, the
# exact visibility mistake the FIELD extractor had already been corrected for
# twice. `pub(crate) struct` is live house style in this workspace.
fx="$(cfg_fixture "$CFG_OK")"
python3 - "$fx" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "crates/maknae-config/src/audit_cfg.rs"
s = p.read_text()
s = s.replace("pub struct AuditConfig {",
              "pub(crate) struct SiemConfig {\n    pub(crate) url: String,\n}\n\npub struct AuditConfig {", 1)
s = s.replace("    pub siem: Option<String>,", "    pub(crate) siem: SiemConfig,", 1)
p.write_text(s)
PY
expect_reject_because "config-disclosure-drift/pub-crate-struct-subtree" "SUBTREE" \
  "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a field typed with THIS CRATE'S OWN `Value`. It is a map-bearing
# enum (`value.rs`: `Map(Vec<(String, Value)>)`), so `pub extra: Value` is an
# open-ended deployer-authored subtree -- and `use crate::Value` is already in
# scope in every file SURFACE reads. It sat on the scalar skip list, where it
# was DEAD for its apparent purpose: `serde_json::Value` is intercepted by the
# map case first, so the entry was live only for the hazardous spelling.
fx="$(cfg_fixture "$CFG_OK" '' '' '' 'Value')"
expect_reject_because "config-disclosure-drift/crate-value-field-is-a-subtree" "dynamic-key MAP" \
  "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a repeated entry in DISCLOSABLE. Harmless at runtime -- `classify` is
# boolean membership -- but the classification inventory is the artifact a
# reviewer reads to answer "what does this disclose", and a list that repeats
# itself is a list nobody has checked. The manifest side has refused duplicates
# since it was written; the code side did not, because the `sort -u` that makes
# the 4a diff work also hid them.
fx="$(cfg_fixture "$CFG_OK" '' '"vault.addr",')"
expect_reject "config-disclosure-drift/duplicate-code-entry" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: an unrecognised disposition token. The closed set was added because
# a nonsense value was being accepted as "a recorded decision" -- and the
# round-2 predicate change had removed, by accident, the check that used to
# catch it.
# On a CONFIG path, where the closed set is the ONLY rule that can fire. The
# original probe put `masc` on `status.version` -- a WIRE path, where the
# "by-construction fields ship whole" rule rejects independently -- so deleting
# the closed-set check left the harness fully green while `masc` on a config
# mask path passed at EXIT=0.
fx="$(cfg_fixture "$(cfg_manifest "^mask${TABCH}audit\.siem${TABCH}" \
  "masc${TABCH}audit.siem${TABCH}endpoint, no schema")")"
expect_reject_because "config-disclosure-drift/unknown-disposition-token" \
  "unknown disposition" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: `mask` on a by-construction surface. `StatusView` is serialized WHOLE
# and never passes through `classify`, so a masked row there would ship the
# value in the clear while the manifest said it was withheld.
fx="$(cfg_fixture "${CFG_OK}mask${TABCH}status.vault_addr${TABCH}value withheld
")"
expect_reject "config-disclosure-drift/mask-on-a-by-construction-surface" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: the BARE PREFIX spelling of the same thing. Requiring `status.` let
# `mask<TAB>status` through, and prefix rows are the idiom this manifest
# already uses -- so it is the spelling a maintainer reaches for. It re-opened
# the hole the closed set closed.
fx="$(cfg_fixture "${CFG_OK}mask${TABCH}status${TABCH}cover the whole surface
")"
expect_reject "config-disclosure-drift/mask-on-a-bare-by-construction-prefix" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a new field on a WIRE disclosure struct. TWO independent controls stop
# it -- the exact field count, and 4b once the count is bumped -- and this probe
# deliberately asserts neither in isolation, because either one alone is
# sufficient and a maintainer going green passes through both. The label says
# `is-stopped` rather than naming a check: an earlier label claimed check 4b, a
# later comment claimed "it actually fires the COUNT", and neither was
# demonstrated -- disabling the count check leaves this fixture rejecting at 4b.
# The count check has its own isolating probes (`*-not-counted`); 4b has
# `struct-field-with-no-decision`. This one pins the OUTCOME.
fx="$(cfg_fixture "$CFG_OK" '' '' 'pub clearance: String,')"
expect_reject "config-disclosure-drift/wire-struct-field-is-stopped" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a BARE surface token as an `always` row. Round 4 made bare prefixes
# count as the surface so `mask<TAB>status` would reject -- and that same change
# legalized `always<TAB>status`, which then covers every field under it by
# prefix. One row, whole struct, and a new sensitive field ships with nothing
# but a count edit.
fx="$(cfg_fixture "$(cfg_manifest "^always${TABCH}status\." \
  "always${TABCH}status${TABCH}cover the whole surface")")"
expect_reject_because "config-disclosure-drift/bare-surface-token-is-not-a-decision" \
  "a bare surface token is not a per-field decision" \
  "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: `always` on a CONFIG path. `always` asserts "ships by construction on
# a non-allowlist surface"; on a config path the value goes through `classify`
# and may be masked, so the row would claim a disclosure the code does not make.
# Unprobed until now: deleting the check left negative-control fully green.
fx="$(cfg_fixture "$(cfg_manifest "" \
  "always${TABCH}transport.socket_path${TABCH}claims by-construction on a classified surface")")"
expect_reject_because "config-disclosure-drift/always-on-a-config-path" \
  "always is only for by-construction surfaces" \
  "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a field whose type reduces to a token carrying a regex metacharacter
# (a tuple here). `$bare` is interpolated into a `grep -rqE`, and an invalid
# pattern makes grep error -- which `|| continue` scores as LEAF. Fail-open on
# the check whose entire job is to refuse leaves that are not leaves. Note the
# guard refuses METACHARACTERS only: `Vec<String>` on a config surface reduces
# to `Vec<String` legitimately (the documented exemption) and must still pass,
# which the clean-fixture probe below holds.
fx="$(cfg_fixture "$CFG_OK" '' '' '' '(u32, String)')"
expect_reject_because "config-disclosure-drift/metacharacter-type-is-not-a-leaf" \
  "regex metacharacter" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a SURFACE prefix carrying whitespace. `wire_prefixes` is space-joined
# and split on " ", so such a prefix becomes two phantom surfaces and
# `byconstruction` matches on half a name.
fx="$(cfg_fixture "$CFG_OK")"
python3 - "$fx" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "ci/gates/config-disclosure-drift.sh"
s = p.read_text()
old = "|StatusView|status|5|wire"
assert s.count(old) == 1, "fixture prefix anchor moved"
p.write_text(s.replace(old, "|StatusView|status view|5|wire"))
PY
expect_reject_because "config-disclosure-drift/whitespace-bearing-surface-prefix" \
  "whitespace-bearing prefix" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a FOURTH `*View` struct in wire.rs with no SURFACE row. The config
# half of SURFACE is cross-checked against boot.rs's section registry; the wire
# half was hand-maintained with no closing rule, so a new disclosure struct --
# probed with a field literally named `vault_token` -- shipped at unchanged
# counts and EXIT=0. The naming-convention inventory closes both directions.
fx="$(cfg_fixture "$CFG_OK")"
cat >> "$fx/crates/maknae-proto/src/wire.rs" <<'FIX'
pub struct AuditTailView {
    pub jsonl_path: String,
    pub vault_token: String,
}
FIX
expect_reject_because "config-disclosure-drift/uninventoried-wire-view-struct" \
  "wire disclosure structs and the SURFACE table disagree" \
  "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a NEW Payload variant with no disposition row -- codex round-11's P1,
# in its own shape: an INLINE map payload is a disclosure surface with no
# struct at all, so the *View inventory above cannot see it, and `ConfigView`
# proves the wire format permits it. The variant table is what forces the
# classification moment.
fx="$(cfg_fixture "$CFG_OK")"
python3 - "$fx" <<'PY'
import pathlib, sys
w = pathlib.Path(sys.argv[1]) / "crates/maknae-proto/src/wire.rs"
s = w.read_text()
a = "    SubjectList(Vec<RoleBindingView>),\n"
assert s.count(a) == 1, "fixture Payload anchor moved"
w.write_text(s.replace(a, a + "    Secrets(std::collections::BTreeMap<String, String>),\n"))
PY
expect_reject_because "config-disclosure-drift/payload-variant-with-no-disposition" \
  "Payload variants and the disposition table disagree" \
  "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a disposition row whose named struct is not what the variant carries.
# Without the operand cross-check the table can quietly lie about the type and
# the gate keeps certifying the OLD struct's decisions for a NEW payload.
fx="$(cfg_fixture "$CFG_OK")"
python3 - "$fx" <<'PY'
import pathlib, sys
w = pathlib.Path(sys.argv[1]) / "crates/maknae-proto/src/wire.rs"
s = w.read_text()
a = "    Status(StatusView),"
assert s.count(a) == 1, "fixture Status variant anchor moved"
w.write_text(s.replace(a, "    Status(std::collections::BTreeMap<String, String>),"))
PY
expect_reject_because "config-disclosure-drift/payload-disposition-table-lies" \
  "the table is lying about the type" \
  "$fx/ci/gates/config-disclosure-drift.sh"


# REJECT: a wire-struct field whose type becomes Vec<WorkspaceStruct>. `Vec` is
# a leaf for a CONFIG document (`flatten` never recurses into `Value::Seq`) and
# is NOT for a wire struct, which serde serializes whole -- the exemption is a
# fact about the consumer, and it was inherited unexamined when three wire
# structs joined SURFACE.
fx="$(cfg_fixture "$CFG_OK" '' '' '' '' 'Vec<MemberEntry>')"
cat >> "$fx/crates/maknae-proto/src/wire.rs" <<'FIX'
pub struct MemberEntry {
    pub uid: u32,
    pub home: String,
}
FIX
expect_reject_because "config-disclosure-drift/wire-vec-of-struct-is-a-subtree" "SUBTREE" \
  "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: the same defeat, with the SURFACE array REORDERED so a `config` row is
# last. The per-surface `Vec` rule read `$sec` -- a variable left over from the
# extraction loop, holding the LAST entry -- so the rule every row got was
# whatever happened to sit at the bottom of the table. Grouping the entries by
# crate, a plausible tidy-up, restored the defeat above at identical counts and
# EXIT=0. The kind is now an explicit column carried per row; this is what
# proves it.
fx="$(cfg_fixture "$CFG_OK" '' '' '' '' 'Vec<MemberEntry>')"
cat >> "$fx/crates/maknae-proto/src/wire.rs" <<'FIX'
pub struct MemberEntry {
    pub uid: u32,
    pub home: String,
}
FIX
python3 - "$fx" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "ci/gates/config-disclosure-drift.sh"
s = p.read_text()
row = '  "crates/maknae-vault/src/config.rs|VaultConfig|vault|5|config"\n'
last = '  "crates/maknae-proto/src/wire.rs|WhoamiView|whoami|2|wire"\n'
assert s.count(row) == 1 and s.count(last) == 1, "fixture reorder anchors moved"
p.write_text(s.replace(row, "").replace(last, last + row))
PY
expect_reject_because "config-disclosure-drift/surface-order-does-not-decide-the-vec-rule" "SUBTREE" \
  "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: the wrapper strip itself stops working. The two probes above catch it
# only through its CONSEQUENCE (a subtree read as a leaf), and only where a
# fixture supplies a wrapped struct -- so on the real repo, where every wrapped
# type happens to bottom out in a scalar, a dead strip changes no verdict and no
# count. That is exactly how #217 survived its own review: the one-line `:a; ...; ta`
# sed form is GNU-only, BSD sed ran NO substitution, printed `unused label`, and
# EXITED 0, so `pipefail` saw nothing and every gate run on a Mac was green with
# its depth check silently gone.
#
# The mutation is the STRIP STAGE replaced by `cat`, not the sed dialect
# reverted: reverting would probe the host's sed rather than the gate, passing
# on BSD and failing on GNU. Neutering the stage fails identically on both, so
# this probe pins the post-condition on every platform.
fx="$(cfg_fixture "$CFG_OK")"
python3 - "$fx" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "ci/gates/config-disclosure-drift.sh"
s = p.read_text()
# Anchor on the wrapper-strip EXPRESSION alone, not the whole pipeline: it is
# one short line, it is what this probe is about, and neutering only it leaves
# the qualifier normalisation running -- so the probe cannot pass for the
# unrelated reason that qualifiers stopped being stripped.
strip = """-e "s/^${wrappers}<//\""""
dead = """-e 's/^__NO_WRAPPER_EVER__<//'"""
assert s.count(strip) == 1, "the wrapper-strip anchor moved"
p.write_text(s.replace(strip, dead))
PY
expect_reject_because "config-disclosure-drift/dead-wrapper-strip-is-refused" \
  "still LEADS with a wrapper" \
  "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: the same dead strip, reaching the WIRE branch. `$tmp/fields` is
# sort -u'd, so the probe above always trips on `audit.siem` (config) and the
# `(Option|Box|Arc|Vec)` spelling of the post-condition -- the one that needs
# `Vec` present -- is never evaluated. Retyping `siem` to a scalar makes every
# config row scalar, so the first offender becomes `binding.members`
# (`Vec<String>`, wire) and the wire arm is the one under test.
fx="$(cfg_fixture "$CFG_OK")"
python3 - "$fx" <<'PY'
import pathlib, sys
d = pathlib.Path(sys.argv[1])
g = d / "ci/gates/config-disclosure-drift.sh"
s = g.read_text()
strip = """-e "s/^${wrappers}<//\""""
dead = """-e 's/^__NO_WRAPPER_EVER__<//'"""
assert s.count(strip) == 1, "the wrapper-strip anchor moved"
g.write_text(s.replace(strip, dead))
a = d / "crates/maknae-config/src/audit_cfg.rs"
t = a.read_text()
assert t.count("pub siem: Option<String>,") == 1, "the siem anchor moved"
a.write_text(t.replace("pub siem: Option<String>,", "pub siem: String,"))
PY
expect_reject_because "config-disclosure-drift/dead-wrapper-strip-is-refused-on-the-wire-arm" \
  "'binding.members' has type 'Vec<String>', which reduced to 'Vec<String'" \
  "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a field declaration the extractor cannot read. The awk emits a row
# with an EMPTY type column, and the shell cannot see it -- `IFS=$'\t' read`
# treats tab as IFS whitespace, so the run of tabs collapses and the row
# arrives as fpath + kind-in-fty + empty kind. An in-loop guard is unreachable;
# worse, the emptied kind used to fall through `case` to the CONFIG wrapper set,
# applying the wrong per-row rule at unchanged counts and EXIT=0. Validated
# before the loop with `awk -F'\t'`, which does not collapse separators.
fx="$(cfg_fixture "$CFG_OK")"
python3 - "$fx" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "crates/maknae-config/src/transport.rs"
s = p.read_text()
old = "    pub read_timeout_ms: u64,\n"
new = "    pub read_timeout_ms:\n        u64,\n"
assert s.count(old) == 1, "the transport field anchor moved"
p.write_text(s.replace(old, new))
PY
expect_reject_because "config-disclosure-drift/unreadable-field-declaration" \
  "malformed extracted field row" \
  "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: the OTHER line-wrap shape, which is the one that walks past an
# emptiness test. Breaking inside the generic leaves the extractor a NON-empty
# truncation (`Option<`), which then reduces to the empty string in the strip
# and was swallowed by the scalar skip list's `''` arm -- a subtree scored a
# leaf at unchanged counts and EXIT=0. Probed on BOTH surface kinds because
# `Option<` empties on either wrapper set while `Vec<` empties only on the wire
# arm, so a config-only probe would leave the wire arm's truncation uncovered.
for _w in config wire; do
  fx="$(cfg_fixture "$CFG_OK")"
  python3 - "$fx" "$_w" <<'PY'
import pathlib, sys
d, which = pathlib.Path(sys.argv[1]), sys.argv[2]
if which == "config":
    p = d / "crates/maknae-config/src/transport.rs"
    old, new = "    pub read_timeout_ms: u64,\n", "    pub read_timeout_ms: Option<\n        Principal,\n    >,\n"
else:
    p = d / "crates/maknae-proto/src/wire.rs"
    old, new = "    pub members: Vec<String>,\n", "    pub members: Vec<\n        WhoamiView,\n    >,\n"
s = p.read_text()
assert s.count(old) == 1, "the %s wrap anchor moved" % which
p.write_text(s.replace(old, new))
PY
  expect_reject_because "config-disclosure-drift/open-angle-wrapped-declaration-$_w" \
    "malformed extracted field row" \
    "$fx/ci/gates/config-disclosure-drift.sh"
done

# REJECT: the struct lookup ERRORS rather than simply not matching. `|| continue`
# could not tell grep's no-match (1) from its error (2), and `2>/dev/null` threw
# the evidence away, so an unreadable tree scored every field a leaf with the
# gate green -- #217's shape one stage later in the same loop. An unreadable
# file under the fixture's `crates/` makes the lookup for `Vec<String` (which
# matches nothing) return 2.
#
# SKIPPED FOR root: `chmod 000` does not stop uid 0 reading the file, so grep
# returns 1 (no match, no error) instead of 2, the branch never fires, and the
# probe would report NEG-FAIL for a reason that is about the runner rather than
# the gate. CI is an unprivileged `ubuntu-latest` runner, but this project ships
# a container surface where root is ordinary.
if [ "$(id -u)" -eq 0 ]; then
  echo "neg-skip: [config-disclosure-drift/struct-lookup-error-is-not-a-leaf] running as root; chmod 000 cannot make grep error"
  skipped=$((skipped+1))
else
  fx="$(cfg_fixture "$CFG_OK")"
  printf 'unreadable\n' > "$fx/crates/maknae-config/src/locked.rs"
  chmod 000 "$fx/crates/maknae-config/src/locked.rs"
  expect_reject_because "config-disclosure-drift/struct-lookup-error-is-not-a-leaf" \
    "ERRORED (grep" \
    "$fx/ci/gates/config-disclosure-drift.sh"
  chmod 644 "$fx/crates/maknae-config/src/locked.rs"
fi

# ACCEPT: a FULLY-QUALIFIED wrapper is a scalar leaf, not a dead strip. The
# post-condition above rejects a value that still leads with a strippable
# wrapper, and `std::sync::Arc<String>` reaches that shape only if qualifiers
# are trimmed AFTER the loop -- which is what the pipeline used to do. On `main`
# there was no post-condition, so `std::sync::Arc<String>` reduced to
# `Arc<String` and was accepted as a leaf SILENTLY; the danger appeared only
# once the post-condition was added against the old trim order, where this
# spelling (live house style: `std::ops::RangeInclusive` in transport.rs, `Arc<`
# 60+ times across crates/) hard-failed the gate while telling the maintainer to
# go check a sed flag. This probe pins the corrected order.
fx="$(cfg_fixture "$CFG_OK" '' '' '' 'std::sync::Arc<String>')"
expect_accept "config-disclosure-drift/qualified-wrapper-is-a-leaf" \
  ": 25 paths decided" "$fx/ci/gates/config-disclosure-drift.sh"

# ACCEPT: the config-surface `Vec` exemption holds for the QUALIFIED spelling
# too. Under the old post-loop `s/.*:://`, `Vec<crate::Principal>` reduced to
# `Principal` and was rejected as a subtree on a surface where `Vec` is a leaf
# by the documented exemption -- a live defect the strip reorder fixes, and one
# the unqualified `config-vec-of-struct-is-a-leaf` probe below cannot see.
fx="$(cfg_fixture "$CFG_OK" '' '' '' 'Vec<crate::Principal>')"
expect_accept "config-disclosure-drift/qualified-config-vec-is-still-a-leaf" \
  ": 25 paths decided" "$fx/ci/gates/config-disclosure-drift.sh"

# ACCEPT: the mirror image. `Vec<WorkspaceStruct>` on a CONFIG surface is a
# LEAF -- `flatten` never recurses into `Value::Seq` and `render` masks the
# sequence whole -- so demanding coverage there would block legitimate work.
# Unprobed, the exemption was free to not exist: under the leaked variable it
# did not, and every config row was silently held to the wire rule.
fx="$(cfg_fixture "$CFG_OK" '' '' '' 'Vec<Principal>')"
expect_accept "config-disclosure-drift/config-vec-of-struct-is-a-leaf" \
  ": 25 paths decided" "$fx/ci/gates/config-disclosure-drift.sh"

# ACCEPT: the clean fixture passes and reports both counts. Without this every
# rejection above would stay green against a gate that refuses everything.
fx="$(cfg_fixture "$CFG_OK")"
expect_accept "config-disclosure-drift/clean-fixture-passes" ": 25 paths decided, 36 struct fields covered" "$fx/ci/gates/config-disclosure-drift.sh"


# ACCEPT, against the REAL repo: each gate's reported examined-set is
# CROSS-CHECKED against an independent derivation. Not a baked number -- a
# number measured once asserts only that a fact held at one moment; it churns on
# ordinary work, trains a thoughtless bump, and cannot see an ADDITION that goes
# unscanned, which is the defect this issue is about. Each expectation below is
# computed here by a DIFFERENT mechanism than the gate uses, so the two can only
# agree when the gate is walking the set it is supposed to walk.
repo_root="$(cd "$here/../.." && pwd)"

# The two `git ls-files` derivations need a real checkout. That is a legitimate
# dependency -- tracked-vs-untracked is exactly what they cross-check, and this
# file already has probes that need `cargo` -- but it must SKIP, not abort:
# without this guard the whole run died mid-way with `fatal: not a git
# repository` on a tree exported without `.git`, taking every later probe and
# the summary line with it. Caught on the Linux test host.
if git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  # `git ls-files` against a gate that walks with `find`: tracked files only, so
  # this also pins that the walk does not wander into untracked trees. It walked
  # the gitignored `.claude/worktrees/` before #219 and reported 14 from the main
  # checkout where a worktree reported 7 -- a count that was a property of the
  # developer's filesystem rather than of the repository.
  exp_bi="$(cd "$repo_root" && git ls-files -- '*.sh' '*.mk' 'Makefile' 'makefile' 'GNUmakefile' \
              'justfile' 'Justfile' 'Dockerfile*' '*/Dockerfile*' \
              '.github/workflows/*.yml' '.github/workflows/*.yaml' \
            | grep -v '^ci/gates/' | sort -u | wc -l | tr -d ' ')"
  expect_reported_count "build-invocation/examined-set-matches-git" "ok (" "$exp_bi" \
    "$here/build-invocation-lint.sh" "$repo_root"

  # The gate's OWN exemption pattern is extracted rather than restated, so the
  # derivation cannot drift from the rule it checks.
  ea_exempt="$(sed -n "s/^EXEMPT_RE='\(.*\)'$/\1/p" "$here/external-authority-lint.sh")"
  exp_ea="$(cd "$repo_root" && { git ls-files -- 'design/*.md' 'design/**/*.md'; \
              git ls-files -- AGENTS.md README.md; } \
            | sort -u | grep -Ev "$ea_exempt" | wc -l | tr -d ' ')"
  expect_reported_count "external-authority-lint/examined-set-matches-git" "ok (" "$exp_ea" \
    "$here/external-authority-lint.sh"
else
  echo "neg-skip: [build-invocation/examined-set-matches-git] not a git checkout; the tracked-set derivation needs one"
  echo "neg-skip: [external-authority-lint/examined-set-matches-git] not a git checkout; the tracked-set derivation needs one"
  skipped=$((skipped+2))
fi

# These two derive from files on disk, so they need no checkout.
# `awk` over the table against a gate that reads it line-by-line.
exp_ic="$(cd "$repo_root" && awk -F'|' 'NF-2==5' packaging/isolation-contract.md \
          | grep -cvE '\|[[:space:]]*(Property|:?-{3,})')"
expect_reported_count "isolation-contract/linted-rows-match-the-table" "ok (" "$exp_ic" \
  "$here/isolation-contract-lint.sh" "$repo_root"

# Member manifests on disk against what `cargo metadata` resolved.
exp_p1="$(cd "$repo_root" && ls -d crates/*/Cargo.toml bins/*/Cargo.toml 2>/dev/null | wc -l | tr -d ' ')"
expect_reported_count "p1-manifest/packages-match-the-workspace" "ok (" "$exp_p1" \
  "$here/p1-manifest-lint.sh" "$repo_root"

# ACCEPT, against the REAL repo: config-disclosure-drift's own summary counts.
# Round 8's probes all showed up first as a silent change to these two numbers
# (23 -> 18 struct fields, EXIT=0). A count nobody asserts is a log line, not a
# control; asserting it here means any future silent shrink is a red build.

expect_accept "config-disclosure-drift/real-repo-counts-pinned" \
  ": 37 paths decided, 36 struct fields covered" "$here/config-disclosure-drift.sh"


# #158: a grant's own disclosure inventory must reject new data and type changes.
for change in field variant type; do
  fx="$(cfg_fixture "$CFG_OK")"
  python3 - "$fx" "$change" <<'PYFIX'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "crates/maknae-proto/src/mutation.rs"
s = p.read_text()
old, new = {
    "field": ("pub struct MutationGrant {", "pub struct MutationGrant {\n    pub credential: String,"),
    "variant": ("pub enum MutationScope {", "pub enum MutationScope {\n    Secret { token: String },"),
    "type": ("pub max_effects: u32,", "pub max_effects: String,"),
}[sys.argv[2]]
assert s.count(old) == 1
p.write_text(s.replace(old, new))
PYFIX
  expect_reject_because "mutation-disclosure/new-$change" \
    "mutation grant disclosure inventory differs" "$fx/ci/gates/config-disclosure-drift.sh"
done
fx="$(cfg_fixture "$CFG_OK")"
python3 - "$fx" <<'PYFIX'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "crates/maknae-proto/src/wire.rs"
s = p.read_text()
p.write_text(s.replace("MutationAttempt(crate::MutationGrant)", "MutationAttempt(String)"))
PYFIX
expect_reject_because "mutation-disclosure/wrong-payload-type" \
  "authorized-attempt must carry crate::MutationGrant" "$fx/ci/gates/config-disclosure-drift.sh"

# ---- external-authority-lint (#34): no Maknae rule rests on a foreign ADR ----
# The wording IS the control here, so the fixture is a wording fixture.
ea_fixture() { # <line> — a dir (not a repo) holding one normative doc + the root docs
  local fixture; fixture="$(mktemp -d -p "$NC_TMP")"
  mkdir -p "$fixture/ci/gates" "$fixture/design"
  cp "$here/external-authority-lint.sh" "$fixture/ci/gates/"
  printf '# doc\n\n%s\n' "$1" > "$fixture/design/some-design.md"
  # AGENTS.md / README.md are REQUIRED by the gate (#219): AGENTS.md carries the
  # authority doctrine it enforces, so their absence must fail rather than
  # quietly shrink the corpus. The fixture supplies them so the requirement is
  # enforced and still probeable -- previously their absence here was the whole
  # reason the gate tolerated missing root docs.
  printf '# agents\n' > "$fixture/AGENTS.md"
  printf '# readme\n' > "$fixture/README.md"
  echo "$fixture"
}
fx="$(ea_fixture "Following the Knowledge Lake ADR-0004 authority model, the map separates two concerns.")"
expect_reject "external-authority-lint/unqualified-foreign-adr" "$fx/ci/gates/external-authority-lint.sh"
fx="$(ea_fixture "Microkosmos ADR 0006 defines the dual-client identity pattern used here.")"
expect_reject "external-authority-lint/unqualified-microkosmos-adr" "$fx/ci/gates/external-authority-lint.sh"

# ACCEPT: a QUALIFIED citation passes, and the gate reports what it scanned.
# Same argument as the build-invocation accept probe: two rejections alone
# cannot tell a working gate from one that refuses everything, and this file
# just gained a floor that could make it the latter.
fx="$(ea_fixture "Provenance, never authority: the Knowledge Lake ADR-0004 model informed this.")"
expect_accept "external-authority-lint/qualified-citation-passes" \
  "external-authority-lint: ok" "$fx/ci/gates/external-authority-lint.sh"

# REJECT: the corpus is MISSING (#219). `find design … 2>/dev/null` with a
# trailing `|| true` discarded the error text, the exit status AND the empty
# case at once, so a tree with no `design/` reported `ok` -- clearing every rule
# in the repo by default, in the gate whose entire subject is wording.
fx_nodesign="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$fx_nodesign/ci/gates"
cp "$here/external-authority-lint.sh" "$fx_nodesign/ci/gates/"
expect_reject_because "external-authority-lint/missing-corpus-is-refused" \
  "could not list design/" \
  "$fx_nodesign/ci/gates/external-authority-lint.sh"

# REJECT: the corpus collapses to nothing through an OVER-BROAD EXEMPTION.
# `find` reports zero matches as SUCCESS, so reading its status cannot catch an
# empty corpus and the floor is what does. Now that the root documents are
# required, an empty `design/` alone can no longer reach the floor (that is the
# `missing-root-document` probe above) -- the reachable cause is an exemption
# pattern that swallows everything, which is what this mutates the fixture's own
# gate copy to produce. Probing the floor through the path it can actually be
# reached by, rather than one an earlier check now intercepts.
fx_empty="$(ea_fixture "Provenance, never authority: the Knowledge Lake ADR-0004 model informed this.")"
python3 - "$fx_empty" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "ci/gates/external-authority-lint.sh"
s = p.read_text()
old = "EXEMPT_RE='^(design/reference-implementation-autopsy\\.md|design/reviews/|design/adr/README\\.md)'"
assert s.count(old) == 1, "the EXEMPT_RE anchor moved"
p.write_text(s.replace(old, "EXEMPT_RE='.'"))
PY
expect_reject_because "external-authority-lint/zero-files-scanned-is-refused" \
  "scanned ZERO files" \
  "$fx_empty/ci/gates/external-authority-lint.sh"

# REJECT: a required root document is gone (#219). `AGENTS.md` carries the
# authority doctrine this gate enforces; losing it used to shrink the corpus
# silently because `ls … 2>/dev/null || true` tolerated its absence.
fx="$(ea_fixture "Provenance, never authority: the Knowledge Lake ADR-0004 model informed this.")"
rm -f "$fx/AGENTS.md"
expect_reject_because "external-authority-lint/missing-root-document-is-refused" \
  "required root document(s) absent" \
  "$fx/ci/gates/external-authority-lint.sh"

# REJECT: a corpus file `find` listed but `grep` cannot read (#219). `< <(grep …
# || true)` collapsed grep's ERROR (2) into its no-match (1), so an unreadable
# doc carrying a real unqualified citation was cleared at rc 0 -- while the
# success line counted it as scanned. SKIPPED FOR root, which reads a 000 file
# regardless.
if [ "$(id -u)" -eq 0 ]; then
  echo "neg-skip: [external-authority-lint/unreadable-doc-is-not-cleared] running as root; chmod 000 cannot make grep fail"
  skipped=$((skipped+1))
else
  fx="$(ea_fixture "Provenance, never authority: the Knowledge Lake ADR-0004 model informed this.")"
  printf '# hidden\n\nFollowing the Knowledge Lake ADR-0004 authority model, this rests on it.\n' \
    > "$fx/design/unreadable.md"
  chmod 000 "$fx/design/unreadable.md"
  expect_reject_because "external-authority-lint/unreadable-doc-is-not-cleared" \
    "could not read" \
    "$fx/ci/gates/external-authority-lint.sh"
  chmod 644 "$fx/design/unreadable.md"
fi

# ---------------------------------------------------------------------------
# authz-composition-drift (ADR-0008 decision 1; #154 / #148). A gate whose whole
# purpose is "the baseline cannot be removed" must be SEEN rejecting each way of
# removing it. One minimal fixture, at least one corruption per `fail(` CALL
# SITE the gate has, and two clean accepts. DERIVED, not counted by hand (round
# 4 found the hand count wrong twice): the gate has 21 `fail(` sites; the
# 29 probes below map onto every one of them by their `why` substring
# (a probe's `why` is a literal substring of exactly the message it targets),
# and the two parameterized sites -- `missing <file>` and `missing <base>/` --
# are probed once per parameter value (3 files, 2 bases). A probe whose `why`
# matches no site, or a site no probe matches, is the failure this note is
# guarding against; re-derive after any edit to either file.
composition_fixture() { # -> prints the fixture root; a MINIMAL tree the gate accepts
  local f; f="$(mktemp -d -p "$NC_TMP")"
  mkdir -p "$f/ci/gates" "$f/crates/maknae-kernel/src" "$f/crates/maknae-authz-basic/src" "$f/crates/maknae-config/src" "$f/crates/maknae-vault/src" "$f/bins/maknaed/src"
  cp "$here/authz-composition-drift.sh" "$f/ci/gates/"
  cat > "$f/crates/maknae-kernel/src/run.rs" <<'RS'
fn boot() {
    let (authorizer, principal) = match authz_boot_gate(dir, p) { Ok(x) => x, Err(e) => return };
    // from the gate's own return value; a `;` in a comment is not a boundary
    let authorizer = crate::composition::build_pdp(&boot, authorizer);
    let composition_rec = make_record(
        "boot",
        &host,
        "authz",
        None,
        "permit",
        &format!("authorization composition: {name}; system: {sys}; ceiling: {lvl}"),
        "authorized",
    );
    if let Err(e) = sink.emit(&composition_rec).await { eprintln!("{e}"); }
}
#[cfg(test)]
mod tests {}
RS
  cat > "$f/crates/maknae-kernel/src/composition.rs" <<'RS'
pub struct Composition<B: Baseline> {
    baseline: B,
    ceiling: CeilingAuthorizer,
}
#[cfg(test)]
mod tests {}
RS
  printf 'const LAKE_SECTION: &str = "lake";\n' > "$f/crates/maknae-kernel/src/boot.rs"
  # The defining file for the ceiling operand: its own `new` is exempt BY PATH (check 6).
  printf 'pub struct CeilingAuthorizer;\nimpl CeilingAuthorizer { pub fn new() -> Self { CeilingAuthorizer } }\nfn own() { let _ = CeilingAuthorizer::new(); }\n#[cfg(test)]\nmod tests {}\n' > "$f/crates/maknae-kernel/src/ceiling_authz.rs"
  cat > "$f/crates/maknae-authz-basic/src/lib.rs" <<'RS'
pub trait Baseline: Authorizer + sealed::Sealed + Send + Sync + 'static {}
mod sealed { pub trait Sealed {} }
impl sealed::Sealed for BasicAuthorizer {}
impl Baseline for BasicAuthorizer {}
RS
  printf 'const SECTION: &str = "audit";\n' > "$f/crates/maknae-config/src/lib.rs"
  printf 'pub const VAULT_SECTION: &str = "vault";\n' > "$f/crates/maknae-vault/src/config.rs"
  printf 'fn main() {}\n' > "$f/bins/maknaed/src/main.rs"
  printf '%s' "$f"
}
composition_reject() { # <label> <expected-FAIL-substring> <python-patch-over-fixture>
  local label="$1" why="$2" patch="$3" f
  f="$(composition_fixture)"
  python3 - "$f" <<PY
import sys, pathlib, re
root = pathlib.Path(sys.argv[1])
$patch
PY
  expect_reject_because "authz-composition-drift/$label" "$why" "$f/ci/gates/authz-composition-drift.sh" "$f"
}
# check 1 -- construction
composition_reject "conditional-construction" "construction must be unconditional" \
  'p=root/"crates/maknae-kernel/src/run.rs"; p.write_text(p.read_text().replace("let authorizer = crate::composition::build_pdp(", "let authorizer = if cfg.use_basic { crate::composition::build_pdp("))'
composition_reject "baseline-from-config-not-gate" "the boot gate's \`authorizer\` binding" \
  'p=root/"crates/maknae-kernel/src/run.rs"; p.write_text(p.read_text().replace("build_pdp(&boot, authorizer)", "build_pdp(&boot, selected_backend)"))'
composition_reject "ceiling-not-from-boot" "fed \`&boot\`" \
  'p=root/"crates/maknae-kernel/src/run.rs"; p.write_text(p.read_text().replace("build_pdp(&boot, authorizer)", "build_pdp(&some_other_config, authorizer)"))'
composition_reject "direct-construction-in-run" "must go through \`build_pdp\`" \
  'p=root/"crates/maknae-kernel/src/run.rs"; p.write_text(p.read_text().replace("#[cfg(test)]", "fn other() { let _ = crate::composition::Composition::new(a, b); }\n#[cfg(test)]"))'
composition_reject "two-call-sites" "expected exactly ONE production" \
  'p=root/"crates/maknae-kernel/src/run.rs"; p.write_text(p.read_text().replace("#[cfg(test)]", "fn other() { let x = build_pdp(&b, a); }\n#[cfg(test)]"))'
composition_reject "gate-does-not-precede" "does not precede the composition" \
  'p=root/"crates/maknae-kernel/src/run.rs"; p.write_text(p.read_text().replace("match authz_boot_gate(dir, p)", "match some_other_source(dir, p)"))'
# check 2 -- the fields
composition_reject "optional-baseline-field" "absent state expressible" \
  'p=root/"crates/maknae-kernel/src/composition.rs"; p.write_text(p.read_text().replace("baseline: B,", "baseline: Option<B>,"))'
composition_reject "vector-baseline" "absent state expressible" \
  'p=root/"crates/maknae-kernel/src/composition.rs"; p.write_text(p.read_text().replace("baseline: B,", "baseline: Vec<Box<dyn Authorizer>>,"))'
composition_reject "no-baseline-bound" "no \`pub struct Composition<B: Baseline>" \
  'p=root/"crates/maknae-kernel/src/composition.rs"; p.write_text(p.read_text().replace("Composition<B: Baseline>", "Composition<B>"))'
composition_reject "baseline-field-removed" "no named \`baseline\` field" \
  'p=root/"crates/maknae-kernel/src/composition.rs"; p.write_text(p.read_text().replace("    baseline: B,\n", ""))'
composition_reject "optional-ceiling-field" "must be the bare \`CeilingAuthorizer\`" \
  'p=root/"crates/maknae-kernel/src/composition.rs"; p.write_text(p.read_text().replace("ceiling: CeilingAuthorizer,", "ceiling: Option<CeilingAuthorizer>,"))'
composition_reject "composition-file-missing" "missing crates/maknae-kernel/src/composition.rs" \
  '(root/"crates/maknae-kernel/src/composition.rs").unlink()'
composition_reject "ceiling-field-removed" "no named \`ceiling\` field" \
  'p=root/"crates/maknae-kernel/src/composition.rs"; p.write_text(p.read_text().replace("    ceiling: CeilingAuthorizer,\n", ""))'
# check 3 -- the sealed trait
composition_reject "unsealed-trait" "not bounded by" \
  'p=root/"crates/maknae-authz-basic/src/lib.rs"; p.write_text(p.read_text().replace("Authorizer + sealed::Sealed +", "Authorizer +"))'
composition_reject "foreign-baseline-impl" "outside the owning crate" \
  'p=root/"crates/maknae-kernel/src/composition.rs"; p.write_text(p.read_text()+"impl Baseline for VendorPdp {}\n")'
composition_reject "third-impl-in-owning-crate" "not one of the two permitted baselines" \
  'p=root/"crates/maknae-authz-basic/src/lib.rs"; p.write_text(p.read_text()+"impl Baseline for LenientAuthorizer {}\n")'
composition_reject "basic-impl-absent" "impl Baseline for BasicAuthorizer\` is absent" \
  'p=root/"crates/maknae-authz-basic/src/lib.rs"; p.write_text(p.read_text().replace("impl Baseline for BasicAuthorizer {}\n", ""))'
# check 4 -- config vocabulary, INSIDE and OUTSIDE maknae-config. The second
# probe appends a section CONSTANT to kernel boot.rs; what the gate matches is
# its "backend" literal -- the probe proves the SCAN REACHES that file, not that
# the gate understands section registration.
composition_reject "config-names-the-pdp" "configuration expresses extensions only" \
  'p=root/"crates/maknae-config/src/lib.rs"; p.write_text(p.read_text()+"const K: &str = \"authz_backend\";\n")'
composition_reject "section-const-outside-config-crate" "configuration expresses extensions only" \
  'p=root/"crates/maknae-kernel/src/boot.rs"; p.write_text(p.read_text()+"const AUTHZ_BACKEND_SECTION: &str = \"backend\";\n")'
# check 5 -- boot-time evidence
composition_reject "evidence-emit-removed" "constructed but never EMITTED" \
  'p=root/"crates/maknae-kernel/src/run.rs"; p.write_text(p.read_text().replace("    if let Err(e) = sink.emit(&composition_rec).await { eprintln!(\"{e}\"); }\n", ""))'
composition_reject "run-file-missing" "missing crates/maknae-kernel/src/run.rs" \
  '(root/"crates/maknae-kernel/src/run.rs").unlink()'
composition_reject "basic-lib-missing" "missing crates/maknae-authz-basic/src/lib.rs" \
  '(root/"crates/maknae-authz-basic/src/lib.rs").unlink()'
composition_reject "bin-names-the-pdp" "configuration expresses extensions only" \
  'p=root/"bins/maknaed/src/main.rs"; p.write_text(p.read_text()+"const K: &str = \"pdp\";\n")'
composition_reject "crates-dir-missing" "missing crates/ -- the production scan" \
  'import shutil; shutil.rmtree(root/"crates")'
composition_reject "bins-dir-missing" "missing bins/" \
  'import shutil; shutil.rmtree(root/"bins")'
composition_reject "evidence-reason-lacks-system-and-ceiling" "must carry '; system:" \
  'p=root/"crates/maknae-kernel/src/run.rs"; p.write_text(p.read_text().replace("; system: {sys}; ceiling: {lvl}", ""))'
# check 6 -- constructor call sites outside the defining files
composition_reject "composition-new-in-another-kernel-module" "calls \`Composition::new(\` outside its defining file" \
  'p=root/"crates/maknae-kernel/src/boot.rs"; p.write_text(p.read_text()+"fn shadow() { let _ = crate::composition::Composition::new(a, b); }\n")'
composition_reject "ceiling-new-in-a-bin" "calls \`CeilingAuthorizer::new(\` outside its defining file" \
  'p=root/"bins/maknaed/src/main.rs"; p.write_text(p.read_text()+"fn shadow() { let _ = maknae_kernel::CeilingAuthorizer::new(c, p); }\n")'
composition_reject "evidence-record-removed" "boot composition evidence record" \
  'p=root/"crates/maknae-kernel/src/run.rs"; p.write_text(re.sub(r"    let composition_rec = make_record\(.*?\n    \);\n", "", p.read_text(), flags=re.S))'
f="$(composition_fixture)"; expect_accept "authz-composition-drift/clean-fixture" "authz-composition-drift: ok" "$f/ci/gates/authz-composition-drift.sh" "$f"
# A commented-out or test-module construction is NOT a site (comments blanked; production half only).
f="$(composition_fixture)"; python3 - "$f" <<'PYFIX'
import sys, pathlib
p = pathlib.Path(sys.argv[1]) / "crates/maknae-kernel/src/boot.rs"
p.write_text(p.read_text() + "// let _ = Composition::new(a, b);\n/* CeilingAuthorizer::new(c, p) */\n#[cfg(test)]\nmod tests { fn t() { let _ = crate::composition::Composition::new(a, b); } }\n")
PYFIX
expect_accept "authz-composition-drift/commented-or-test-construction-is-not-a-site" "authz-composition-drift: ok" "$f/ci/gates/authz-composition-drift.sh" "$f"
expect_accept "authz-composition-drift/real-repo" "authz-composition-drift: ok" "$here/authz-composition-drift.sh" "$here/../.."


# ---- clippy-all (#74): a DERIVED input set is not a scanned one --------------
# This gate discovers BOTH its package set and its feature passes from `cargo
# metadata`, which is the discover-vs-constant class CONTRIBUTING.md:126 names.
# Everything below probes the DISCOVERY and the REPORTING, because a lint of
# nothing exits 0 and would otherwise print a confident success line.

# REJECT: a workspace that resolves to ZERO packages. Same defect as
# p1-manifest-lint's, same cause: the loop just doesn't iterate.
tmpQ0="$(mktemp -d -p "$NC_TMP")"
printf '[workspace]\nresolver = "3"\nmembers = []\n' > "$tmpQ0/Cargo.toml"
printf '[toolchain]\nchannel = "1.98.1"\n' > "$tmpQ0/rust-toolchain.toml"
expect_reject_because "clippy-all/zero-packages-is-refused" \
  "resolved ZERO packages" \
  "$here/clippy-all.sh" --root "$tmpQ0" --check-inputs

# REJECT: `cargo metadata` itself fails. Its stderr is captured separately for
# exactly this -- a gate that dies mute is unprobeable by `expect_reject`.
tmpQ1="$(mktemp -d -p "$NC_TMP")"
printf '[workspace]\nresolver = "3"\nmembers = ["nope"]\n' > "$tmpQ1/Cargo.toml"
printf '[toolchain]\nchannel = "1.98.1"\n' > "$tmpQ1/rust-toolchain.toml"
expect_reject_because "clippy-all/metadata-failure-is-not-silent" \
  "cargo metadata failed" \
  "$here/clippy-all.sh" --root "$tmpQ1" --check-inputs

# REJECT: no rust-toolchain.toml. The channel is BOTH the container tag and the
# lint compiler; absent it, the lane would lint whatever rustc happened to be on
# PATH and call it the pinned toolchain.
tmpQ2="$(mktemp -d -p "$NC_TMP")"
printf '[workspace]\nresolver = "3"\nmembers = []\n' > "$tmpQ2/Cargo.toml"
expect_reject_because "clippy-all/missing-toolchain-file-is-refused" \
  "missing" \
  "$here/clippy-all.sh" --root "$tmpQ2" --check-inputs

# REJECT: a toolchain file with no channel key.
tmpQ3="$(mktemp -d -p "$NC_TMP")"
printf '[workspace]\nresolver = "3"\nmembers = []\n' > "$tmpQ3/Cargo.toml"
printf '[toolchain]\ncomponents = ["clippy"]\n' > "$tmpQ3/rust-toolchain.toml"
expect_reject_because "clippy-all/no-channel-is-refused" \
  "no [toolchain] channel" \
  "$here/clippy-all.sh" --root "$tmpQ3" --check-inputs

# REJECT: an UNPINNED channel. `stable` and `nightly-<date>` are rustup
# spellings, not Docker Official Images tags -- guessing one would lint a
# compiler the project does not pin, on a lane whose whole value is that it
# matches CI's.
for ch in stable nightly nightly-2026-01-01 beta; do
  tmpQ4="$(mktemp -d -p "$NC_TMP")"
  printf '[workspace]\nresolver = "3"\nmembers = []\n' > "$tmpQ4/Cargo.toml"
  printf '[toolchain]\nchannel = "%s"\n' "$ch" > "$tmpQ4/rust-toolchain.toml"
  expect_reject_because "clippy-all/unpinned-channel-$ch-is-refused" \
    "is not a pinned release" \
    "$here/clippy-all.sh" --root "$tmpQ4" --check-inputs
done

# REJECT: an unknown flag. `clippy-all.sh --linux` must never be read as a root
# path, and a typo'd flag must not silently degrade to a narrower run.
expect_reject_because "clippy-all/unknown-argument-is-refused" \
  "unknown argument" \
  "$here/clippy-all.sh" --lnux

# REJECT: two mode flags. Last-wins would let `--linux --check-inputs` report a
# Linux lane that never ran -- and the PR template asks the author to ATTEST
# that lane ran and passed.
expect_reject_because "clippy-all/conflicting-mode-flags-are-refused" \
  "conflicting mode flags" \
  "$here/clippy-all.sh" --linux --check-inputs

# REJECT: a --root that cannot be entered. `[ -d ]` passes on a mode-000
# directory; `cd "$root" && run_lints` then skipped the lints and the script
# exited 0, because `cd` is not the last command of an AND-OR list.
tmpQ5="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpQ5/inner"; chmod 000 "$tmpQ5/inner"
if [ "$(id -u)" -ne 0 ]; then   # root ignores the mode bits
  expect_reject_because "clippy-all/unenterable-root-is-refused" \
    "cannot enter --root '$tmpQ5/inner'" \
    "$here/clippy-all.sh" --root "$tmpQ5/inner" --check-inputs
else
  skipped=$((skipped+1)); echo "skip: [clippy-all/unenterable-root-is-refused] running as root"
fi
chmod 755 "$tmpQ5/inner" 2>/dev/null || true

# REJECT: a FAILING clippy must print a FAIL line, not just exit non-zero.
# `expect_reject` scores a rejection only on a printed FAIL. This probe proves
# the FAIL line EXISTS -- and only that. An earlier comment here claimed it
# proved the success line is not printed before the work; codex showed a gate
# that printed `ok` first still passed this probe. The ordering claim is
# carried by `a-failing-lint-never-prints-the-ok-line` in the lint block below.
tmpQ6="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpQ6/bin"
{ printf '#!/usr/bin/env bash\n'; printf 'REAL_CARGO=%q\n' "$(command -v cargo)"; cat; } > "$tmpQ6/bin/cargo" <<'SHIM'
# `metadata` and `--version` pass through so the gate reaches its clippy
# invocation; everything else fails.
case "${1:-}" in metadata|--version) exec "$REAL_CARGO" "$@" ;; esac
echo "error: simulated clippy failure" >&2
exit 101
SHIM
chmod +x "$tmpQ6/bin/cargo"
expect_reject_because "clippy-all/failing-clippy-prints-FAIL" \
  "clippy failed on the base" \
  env REAL_CARGO="$(command -v cargo)" PATH="$tmpQ6/bin:$PATH" \
  "$here/clippy-all.sh" --root "$here/../.."

# REJECT: the pin must be ENFORCED, not merely printed. `RUSTUP_TOOLCHAIN` in
# the environment overrides `rust-toolchain.toml`; the gate used to read the
# file, print its channel, and let rustup run whatever the env said -- measured
# as `toolchain 1.98.1` on the OK line while `clippy 0.1.94` linted. A cargo
# shim that reports a fake version is hermetic: it needs no second toolchain
# installed, so this probe runs identically on every host and in CI.
tmpQ7="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpQ7/bin"
{ printf '#!/usr/bin/env bash\n'; printf 'REAL_CARGO=%q\n' "$(command -v cargo)"; cat; } > "$tmpQ7/bin/cargo" <<'SHIM'
if [ "${1:-}" = --version ]; then echo "cargo 1.0.0 (fake 2000-01-01)"; exit 0; fi
exec "$REAL_CARGO" "$@"
SHIM
chmod +x "$tmpQ7/bin/cargo"
expect_reject_because "clippy-all/toolchain-mismatch-is-refused" \
  "toolchain mismatch" \
  env REAL_CARGO="$(command -v cargo)" PATH="$tmpQ7/bin:$PATH" \
  "$here/clippy-all.sh" --root "$here/../.." --check-inputs

# The pin is enforced against a SUBSTITUTED compiler too (found on the darwin
# gate: cargo 1.98.1 drove a 1.94.1 rustc and printed the pin). Same guard in
# both gates, so the same two probes in both blocks.
expect_reject_because "clippy-all/rustc-override-is-refused" \
  "RUSTC is set" \
  env RUSTC=/usr/bin/false \
  "$here/clippy-all.sh" --root "$here/../.." --check-inputs
expect_reject_because "clippy-all/rustc-wrapper-is-refused" \
  "RUSTC_WRAPPER is set" \
  env RUSTC_WRAPPER=/usr/bin/env \
  "$here/clippy-all.sh" --root "$here/../.." --check-inputs
for v in RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER; do
  expect_reject_because "clippy-all/$v-is-refused" \
    "$v is set" \
    env "$v=/usr/bin/env" \
    "$here/clippy-all.sh" --root "$here/../.." --check-inputs
done

# And the seventh door, a file: `.cargo/config.toml` `[build] rustc-wrapper` in
# the linted root. Env beats config; the gate exports an empty RUSTC_WRAPPER,
# so the file-configured wrapper must never run. Clean two-crate fixture; the
# wrapper logs every invocation.
tmpQ9="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpQ9/crates/a/src" "$tmpQ9/.cargo" "$tmpQ9/bin"
printf '[workspace]\nresolver = "3"\nmembers = ["crates/a"]\n' > "$tmpQ9/Cargo.toml"
cp "$here/../../rust-toolchain.toml" "$tmpQ9/rust-toolchain.toml"
printf '[package]\nname = "a"\nversion = "0.0.0"\nedition = "2021"\n' > "$tmpQ9/crates/a/Cargo.toml"; printf 'pub fn a() -> u8 { 1 }\n' > "$tmpQ9/crates/a/src/lib.rs"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s/wrapper.log"\nexec "$@"\n' "$tmpQ9" > "$tmpQ9/bin/wrap"; chmod +x "$tmpQ9/bin/wrap"
( cd "$tmpQ9" && cargo generate-lockfile --offline >/dev/null 2>&1 )
# Config written AFTER the lockfile (the fixture's own generate-lockfile runs
# `rustc -vV`, which an earlier version recorded as a gate residue -- it was
# the fixture's). Liveness first: a plain cargo check must go through it.
printf '[build]\nrustc-wrapper = "%s/bin/wrap"\n' "$tmpQ9" > "$tmpQ9/.cargo/config.toml"
total=$((total+1))
( cd "$tmpQ9" && cargo check --locked >/dev/null 2>&1 || true )
if grep -q -- '--crate-name' "$tmpQ9/wrapper.log" 2>/dev/null; then
  echo "neg-ok: [clippy-all/config-file-wrapper-fixture-is-live] a plain cargo check went through the config wrapper"; pass=$((pass+1))
else
  echo "NEG-FAIL: [clippy-all/config-file-wrapper-fixture-is-live] the config wrapper was never invoked by a plain cargo check — the fixture is inert"
fi
rm -f "$tmpQ9/wrapper.log"; rm -rf "$tmpQ9/target"
expect_accept "clippy-all/config-file-rustc-wrapper-is-neutralised" "clippy-all: ok" "$here/clippy-all.sh" --root "$tmpQ9"
total=$((total+1))
if [ ! -e "$tmpQ9/wrapper.log" ]; then
  echo "neg-ok: [clippy-all/config-file-rustc-wrapper-never-ran-under-the-gate] no wrapper.log after the gate run"; pass=$((pass+1))
else
  echo "NEG-FAIL: [clippy-all/config-file-rustc-wrapper-never-ran-under-the-gate] the config-file wrapper ran under the gate: $(tr '\n' ';' < "$tmpQ9/wrapper.log" | cut -c1-120)"
fi

# REJECT, NOT MUTE: a cargo that cannot answer `--version` must produce a FAIL
# line. Under `pipefail` the version capture used to exit 101 with nothing on
# either stream -- found by the failing-clippy probe above, whose shim at the
# time answered only `metadata`.
tmpQ8="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpQ8/bin"
{ printf '#!/usr/bin/env bash\n'; printf 'REAL_CARGO=%q\n' "$(command -v cargo)"; cat; } > "$tmpQ8/bin/cargo" <<'SHIM'
if [ "${1:-}" = metadata ]; then exec "$REAL_CARGO" "$@"; fi
exit 101
SHIM
chmod +x "$tmpQ8/bin/cargo"
expect_reject_because "clippy-all/unanswerable-cargo-version-is-not-mute" \
  "cannot determine the active cargo version" \
  env REAL_CARGO="$(command -v cargo)" PATH="$tmpQ8/bin:$PATH" \
  "$here/clippy-all.sh" --root "$here/../.." --check-inputs

# REJECT: macOS system bash (3.2) must be refused, not silently obeyed. Two
# bash-3.2 behaviours stacked into the worst possible outcome: `"${arr[@]}"` on
# an EMPTY array is fatal under `set -u` before bash 4.4, and 3.2 lets an EXIT
# trap's last command overwrite the shell's status -- so `--linux` printed a
# success line and exited 0 having started no container, on the one platform
# this lane exists for, while PULL_REQUEST_TEMPLATE.md asks the author to
# attest it "ran and PASSED".
if [ -x /bin/bash ] && /bin/bash -c '[ "${BASH_VERSINFO[0]}" -lt 4 ]' 2>/dev/null; then
  expect_reject_because "clippy-all/system-bash-3.2-is-refused" \
    "bash >= 4 required" \
    /bin/bash "$here/clippy-all.sh" --linux
else
  skipped=$((skipped+1)); echo "skip: [clippy-all/system-bash-3.2-is-refused] no bash < 4 at /bin/bash"
fi

# ACCEPT: --check-inputs must NOT claim to have linted. It reports the derived
# inputs and then says, in words, that it ran nothing.
expect_accept "clippy-all/check-inputs-does-not-claim-a-lint" \
  "ran NO lints" \
  "$here/clippy-all.sh" --root "$here/../.." --check-inputs

# ACCEPT, WITH THE COUNT CROSS-CHECKED. The gate derives its package set from
# `cargo metadata`; this derives the SAME number by a different mechanism --
# parsing `[package] name` out of the manifests on disk -- so it is a
# cross-check, not a restatement. A crate added to `members` but unlinted, or a
# filter that silently narrows what the gate walks, both fail here. The virtual
# root manifest carries no `[package]`, so it drops out on its own.
clippy_expected_pkgs="$(
  find "$here/../.." -maxdepth 3 -name Cargo.toml \
    -not -path '*/target/*' -not -path '*/.git/*' -not -path '*/.claude/*' 2>/dev/null \
  | sort | while read -r m; do
      sed -n '/^\[package\]/,/^\[/{s/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p;}' "$m" | head -1
    done | sed '/^$/d' | sort -u | wc -l | tr -d ' ')"
expect_reported_count "clippy-all/real-repo-package-count" \
  "clippy-all: inputs (" "$clippy_expected_pkgs" \
  "$here/clippy-all.sh" --root "$here/../.." --check-inputs

# ---- clippy-all (#74): LINT sentinels -- the gate must CATCH a planted lint ---
# Every probe above stops at `--check-inputs`, BEFORE any lint runs, so none of
# them observes the clippy invocation itself -- the thing the gate exists to
# do. Codex proved the consequence with a mutation harness: replacing
# `--workspace` with `-p maknae`, dropping `--all-targets`, dropping
# `-D warnings`, feeding the feature loop an empty string, and printing `ok`
# BEFORE `run_lints` each survived all seventeen probes at 17/17 green. The
# probes proved the GUARDS fire and their comments claimed they proved lint
# COVERAGE. They did not. These do: a two-crate workspace small enough to lint
# in about a second, with a real `clippy::len_zero` planted where each mutation
# would stop looking.
expect_reject_without() { # <label> <expected-FAIL-substring> <forbidden-substring> <cmd...>
  # `expect_reject_because` PLUS a string that must NOT appear. A success line
  # printed before the work is the exact defect: the gate fails, and its stdout
  # still says `ok`.
  local label="$1" why="$2" forbid="$3"; shift 3; total=$((total+1))
  local out rc
  if out="$("$@" 2>&1)"; then rc=0; else rc=$?; fi
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "FAIL" && printf '%s' "$out" | grep -qF -- "$why" \
     && ! printf '%s' "$out" | grep -qF -- "$forbid"; then
    echo "neg-ok: [$label] gate rejected for '$why' and never said '$forbid'"; pass=$((pass+1))
  elif [ "$rc" -eq 0 ]; then
    echo "NEG-FAIL: [$label] gate did NOT reject the fixture"
  elif printf '%s' "$out" | grep -qF -- "$forbid"; then
    echo "NEG-FAIL: [$label] gate rejected but its output ALSO carries '$forbid': $out"
  else
    echo "NEG-FAIL: [$label] gate exited $rc without the expected rejection (wanted '$why'): $out"
  fi
}

lint_fixture() { # <clean|test-sentinel|feature-sentinel|dep-profile|bootstrap> -> prints the fixture root
  # `root` depends on `leaf`. Under `-p root --all-targets`, leaf's LIB is
  # linted (path dep, RUSTC_WORKSPACE_WRAPPER) but leaf's TEST targets are not,
  # and under `--workspace` without `--all-targets` no test target is. So a
  # sentinel inside leaf's `#[cfg(test)]` is visible ONLY to the exact
  # invocation the gate claims to run. The feature variant hides it further,
  # behind a feature nothing in the workspace enables.
  local variant="$1" d
  d="$(mktemp -d -p "$NC_TMP")"
  mkdir -p "$d/crates/root/src" "$d/crates/leaf/src"
  # dep-profile: `leaf` is a path dependency EXCLUDED from the workspace, so a
  # member-named profile pin never reaches it (codex r8).
  case "$variant" in
    dep-profile) printf '[workspace]\nresolver = "3"\nmembers = ["crates/root"]\nexclude = ["crates/leaf"]\n' > "$d/Cargo.toml" ;;
    *) printf '[workspace]\nresolver = "3"\nmembers = ["crates/root", "crates/leaf"]\n' > "$d/Cargo.toml" ;;
  esac
  # The REAL pin, so the gate's toolchain check agrees with the toolchain that
  # actually runs, and the fixture never rots when the pin is bumped.
  cp "$here/../../rust-toolchain.toml" "$d/rust-toolchain.toml"
  printf '[package]\nname = "root"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\nleaf = { path = "../leaf" }\n' > "$d/crates/root/Cargo.toml"
  printf 'pub fn r() -> u8 { leaf::l() }\n' > "$d/crates/root/src/lib.rs"
  printf '[package]\nname = "leaf"\nversion = "0.0.0"\nedition = "2021"\n[features]\ndark = []\n' > "$d/crates/leaf/Cargo.toml"
  {
    # An inner attribute must come first.
    case "$variant" in bootstrap) printf '#![feature(never_type)]\n' ;; esac
    printf 'pub fn l() -> u8 { 7 }\n'
    # `v.len() == 0` is `clippy::len_zero`: WARN by default, an error only
    # under `-D warnings` -- so dropping `-D warnings` lets it through.
    case "$variant" in
      test-sentinel)
        printf '#[cfg(test)]\nmod t { #[test] fn s() { let v: Vec<u8> = Vec::new(); assert!(v.len() == 0); } }\n' ;;
      feature-sentinel)
        printf '#[cfg(all(feature = "dark", test))]\nmod t { #[test] fn s() { let v: Vec<u8> = Vec::new(); assert!(v.len() == 0); } }\n' ;;
      bootstrap)
        printf 'pub fn x() -> Option<!> { None }\n' ;;
      dep-profile)
        # A rustc error, not a lint: a non-member dependency is compiled by
        # rustc, never clippy-driver, so a lint there would not fire anyway.
        printf '#[cfg(debug_assertions)]\ncompile_error!("REAL_ERROR_BEHIND_DEBUG_ASSERTIONS");\n' ;;
      clean) : ;;
      *) echo "lint_fixture: unknown variant '$variant'" >&2; return 1 ;;
    esac
  } > "$d/crates/leaf/src/lib.rs"
  # The gate passes `--locked`, which refuses to CREATE a lock file. Path-only
  # deps resolve offline.
  ( cd "$d" && cargo generate-lockfile --offline >/dev/null 2>&1 )
  printf '%s' "$d"
}

# ACCEPT: the clean fixture lints, and the OK line counts the passes actually
# RUN -- one base pass plus one per declared feature (`leaf/dark`). Kills
# `-p <nonexistent>` (cargo errors, the gate FAILs a clean tree), bare `cargo
# clippy` at a virtual root (same), and any regression that stops counting.
fx_clean="$(lint_fixture clean)"
expect_reported_count "clippy-all/clean-fixture-runs-base-plus-one-per-declared-feature" \
  "packages linted, " 2 \
  "$here/clippy-all.sh" --root "$fx_clean"

# REJECT: a lint in an UNSELECTED crate's TEST target must be caught by the
# base pass. Kills `--workspace` -> `-p root` (leaf's tests unlinted),
# dropping `--all-targets` (no tests linted), and dropping `-D warnings`
# (`len_zero` stays a warning). The reason is pinned to the BASE pass so a
# gate that only catches it on a later feature pass does not score.
fx_test="$(lint_fixture test-sentinel)"
expect_reject_because "clippy-all/unselected-crate-test-target-lint-is-caught-by-the-base-pass" \
  "clippy failed on the base" \
  "$here/clippy-all.sh" --root "$fx_test"

# REJECT ×2: rustflags must not silence the lints. `--cap-lints=allow` turns
# every lint into a no-op regardless of `-D warnings`; it reaches the build
# through RUSTFLAGS or a config file. The gate's explicit empty
# CARGO_ENCODED_RUSTFLAGS outranks both.
expect_reject_because "clippy-all/RUSTFLAGS-cap-lints-cannot-silence-the-lint" \
  "clippy failed on the base" \
  env RUSTFLAGS='--cap-lints=allow' \
  "$here/clippy-all.sh" --root "$fx_test"
fx_capcfg="$(lint_fixture test-sentinel)"; mkdir -p "$fx_capcfg/.cargo"
printf '[build]\nrustflags = ["--cap-lints=allow"]\n' > "$fx_capcfg/.cargo/config.toml"
expect_reject_because "clippy-all/config-file-rustflags-cannot-silence-the-lint" \
  "clippy failed on the base" \
  "$here/clippy-all.sh" --root "$fx_capcfg"

# REJECT ×2: `[env] CLIPPY_ARGS = { value = "", force = true }` in the linted
# root's config REPLACED clippy's generated arguments -- the gate printed `ok`
# over the sentinel. `--config env.CLIPPY_ARGS.force=false` outranks the file.
# And the profile door: `[profile.dev] debug-assertions = false` hides a lint
# behind cfg(debug_assertions); the profile is pinned the same way.
fx_cargs="$(lint_fixture test-sentinel)"; mkdir -p "$fx_cargs/.cargo"
printf '[env]\nCLIPPY_ARGS = { value = "", force = true }\n' > "$fx_cargs/.cargo/config.toml"
expect_reject_because "clippy-all/forced-CLIPPY_ARGS-cannot-remove-the-lint-enforcement" \
  "clippy failed on the base" \
  "$here/clippy-all.sh" --root "$fx_cargs"
fx_dalint="$(lint_fixture clean)"; mkdir -p "$fx_dalint/.cargo"
printf '#[cfg(debug_assertions)]\npub fn da() -> bool { let v: Vec<u8> = Vec::new(); v.len() == 0 }\n' >> "$fx_dalint/crates/leaf/src/lib.rs"
printf '[profile.dev]\ndebug-assertions = false\n' > "$fx_dalint/.cargo/config.toml"
expect_reject_because "clippy-all/profile-config-cannot-hide-a-lint-behind-debug-assertions" \
  "clippy failed on the base" \
  "$here/clippy-all.sh" --root "$fx_dalint"
# ...and the per-package form in the ROOT MANIFEST, which the `"*"` glob does
# not reach; and RUSTC_BOOTSTRAP from the environment.
fx_dapkg="$(lint_fixture clean)"
printf '#[cfg(debug_assertions)]\npub fn da() -> bool { let v: Vec<u8> = Vec::new(); v.len() == 0 }\n' >> "$fx_dapkg/crates/leaf/src/lib.rs"
printf '[profile.dev.package.leaf]\ndebug-assertions = false\n' >> "$fx_dapkg/Cargo.toml"
expect_reject_because "clippy-all/per-package-profile-in-the-manifest-cannot-hide-a-lint" \
  "clippy failed on the base" \
  "$here/clippy-all.sh" --root "$fx_dapkg"
expect_reject_because "clippy-all/RUSTC_BOOTSTRAP-is-refused" \
  "RUSTC_BOOTSTRAP is set" \
  env RUSTC_BOOTSTRAP=1 "$here/clippy-all.sh" --root "$here/../.." --check-inputs
# ...and cargo's OTHER nightly switch, which unlocks `[unstable]` (and with it
# `[profile.<p>] rustflags`, a fourth rustflags source) on the pinned stable.
expect_reject_because "clippy-all/cargo-channel-override-is-refused" \
  "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS is set" \
  env __CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly "$here/clippy-all.sh" --root "$here/../.." --check-inputs
# ...and the panic strategy: a lint behind cfg(panic = "unwind") hidden by
# `[profile.dev] panic = "abort"` in config. On THIS gate the pin is defence
# in depth: `--all-targets` also lints the TEST target, where cargo ignores
# `panic = "abort"`, so the lint surfaces there and the mutation "drop the
# clippy panic pin" survives (measured: 74/76 with only the darwin probes
# red). Kept because the lib target is what ships; recorded as unobserved.
fx_panlint="$(lint_fixture clean)"; mkdir -p "$fx_panlint/.cargo"
printf '#[cfg(panic = "unwind")]\npub fn pu() -> bool { let v: Vec<u8> = Vec::new(); v.len() == 0 }\n' >> "$fx_panlint/crates/leaf/src/lib.rs"
printf '[profile.dev]\npanic = "abort"\n' > "$fx_panlint/.cargo/config.toml"
expect_reject_because "clippy-all/profile-config-cannot-hide-a-lint-behind-the-panic-strategy" \
  "clippy failed on the base" \
  "$here/clippy-all.sh" --root "$fx_panlint"

# REJECT: a lint behind a declared feature that NOTHING enables must be caught
# by that feature's own pass, and the FAIL must NAME the feature. Kills an
# empty or skipped feature loop -- on the real repo the loop's two passes are
# redundant with the base pass, so this fixture is the only place the loop is
# ever observed doing work.
fx_feat="$(lint_fixture feature-sentinel)"
expect_reject_because "clippy-all/dark-feature-lint-is-caught-by-its-own-pass" \
  "clippy failed on feature pass 'leaf/dark'" \
  "$here/clippy-all.sh" --root "$fx_feat"

# REJECT: `[alias] clippy = ["test", "--no-run"]` in the linted root. An alias
# cannot shadow a BUILT-IN, but `clippy` is an external subcommand, so `cargo
# clippy` ran `cargo test --no-run`, linted nothing and printed `ok`
# (measured). The gate invokes the resolved `cargo-clippy` binary by path;
# aliases never enter.
fx_alias="$(lint_fixture test-sentinel)"; mkdir -p "$fx_alias/.cargo"
printf '[alias]\nclippy = ["test", "--no-run"]\n' > "$fx_alias/.cargo/config.toml"
expect_reject_because "clippy-all/a-config-alias-cannot-replace-clippy" \
  "clippy failed on the base" \
  "$here/clippy-all.sh" --root "$fx_alias"

# REJECT (codex r9): invoking `cargo-clippy` by path made it obey an inherited
# `CARGO` -- `/usr/bin/true` linted nothing and printed `ok`. Under the
# allowlist the variable is absent; the sentinel is caught.
expect_reject_because "clippy-all/an-inherited-CARGO-is-inert-under-the-allowlist" \
  "clippy failed on the base" \
  env CARGO=/usr/bin/true "$here/clippy-all.sh" --root "$fx_test"

# REJECT (both reviewers, round 9): WARM REPLAY on this gate too. A workspace
# primed under RUSTC_BOOTSTRAP=1 linted `ok` warm and failed E0554 cold; the
# gate now wipes its own cache before every pass. The primer must succeed
# first, or the FAIL below proves nothing.
fx_wrc="$(lint_fixture bootstrap)"
wrc_rc=0
# The primer mirrors the gate's own compiler selection (`RUSTC` by path):
# with the proxy `rustc` instead, cargo's fingerprint differs and the
# "replay" never happens -- the no-wipe mutant then FAILs for the wrong reason.
( cd "$fx_wrc" && RUSTC_BOOTSTRAP=1 RUSTC="$(rustup which rustc)" CARGO_TARGET_DIR="$fx_wrc/target/clippy-all" CARGO_BUILD_BUILD_DIR="$fx_wrc/target/clippy-all" CARGO_ENCODED_RUSTFLAGS='' \
    "$(rustup which cargo-clippy)" clippy --locked --workspace --all-targets -- -D warnings >/dev/null 2>&1 \
  && RUSTC_BOOTSTRAP=1 RUSTC="$(rustup which rustc)" CARGO_TARGET_DIR="$fx_wrc/target/clippy-all" CARGO_BUILD_BUILD_DIR="$fx_wrc/target/clippy-all" CARGO_ENCODED_RUSTFLAGS='' \
    "$(rustup which cargo-clippy)" clippy --locked --workspace --all-targets --features leaf/dark -- -D warnings >/dev/null 2>&1 ) || wrc_rc=$?
total=$((total+1))
if [ "$wrc_rc" -eq 0 ] && ls "$fx_wrc"/target/clippy-all/debug/deps/libleaf-*.rmeta >/dev/null 2>&1; then
  echo "pos-ok: [clippy-all/the-replay-primer-produced-a-unit] bootstrap-on primer succeeded and left leaf's rmeta"; pass=$((pass+1))
else
  echo "POS-FAIL: [clippy-all/the-replay-primer-produced-a-unit] primer rc=$wrc_rc or no leaf rmeta — the replay probe below would prove nothing"
fi
expect_reject_because "clippy-all/a-primed-target-dir-is-not-replayed" \
  "clippy failed on the base" \
  "$here/clippy-all.sh" --root "$fx_wrc"

# REJECT (codex r10): TMPDIR pointing INSIDE the linted tree used to put the
# gate's "outside" cwd back under the tree's `.cargo/`; the cwd now lives
# under $HOME. The dep-profile config fixture is the tree-config door.
fx_tmpin="$(lint_fixture dep-profile)"; mkdir -p "$fx_tmpin/.cargo" "$fx_tmpin/tmpinside"
printf '[profile.dev.package.leaf]\ndebug-assertions = false\n' > "$fx_tmpin/.cargo/config.toml"
expect_reject_because "clippy-all/the-tree-config-is-not-read-even-with-TMPDIR-inside-the-tree" \
  "clippy failed on the base" \
  env TMPDIR="$fx_tmpin/tmpinside" "$here/clippy-all.sh" --root "$fx_tmpin"

# REJECT (codex r10): the resolved rustc BINARY is version-checked, not the
# PATH proxy (a directory override made them differ). Same shim as the darwin
# block: `rustup which rustc` names a rustc that compiles with the real one but
# reports 1.0.0.
tmpQ12="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpQ12/bin"
{ printf '#!/usr/bin/env bash\n'; printf 'REAL_RUSTC=%q\n' "$(cd "$here/../.." && rustup which rustc)"; cat; } > "$tmpQ12/bin/lying-rustc" <<'SHIM'
case " $* " in *" --version "*|*" -vV "*|*" -V "*) exec "$REAL_RUSTC" "$@" | sed 's/^rustc [0-9.]*/rustc 1.0.0/' ;; esac
exec "$REAL_RUSTC" "$@"
SHIM
{ printf '#!/usr/bin/env bash\n'; printf 'REAL_RUSTUP=%q\nLYING=%q\n' "$(command -v rustup)" "$tmpQ12/bin/lying-rustc"; cat; } > "$tmpQ12/bin/rustup" <<'SHIM'
if [ "${1:-}" = which ] && [ "${2:-}" = rustc ]; then echo "$LYING"; exit 0; fi
exec "$REAL_RUSTUP" "$@"
SHIM
chmod +x "$tmpQ12/bin/lying-rustc" "$tmpQ12/bin/rustup"
expect_reject_because "clippy-all/the-resolved-rustc-binary-is-version-checked" \
  "toolchain mismatch" \
  env PATH="$tmpQ12/bin:$PATH" "$here/clippy-all.sh" --root "$here/../.." --check-inputs

# REJECT + PERSIST: one run per checkout; a refused contender leaves the
# owner's lock (codex r10: an unconditional cleanup removed it).
mkdir -p "$fx_clean/target/clippy-all.lock"
expect_reject_because "clippy-all/a-held-lock-refuses-a-second-run" \
  "another run holds" \
  "$here/clippy-all.sh" --root "$fx_clean" --check-inputs
total=$((total+1))
if [ -d "$fx_clean/target/clippy-all.lock" ]; then
  echo "pos-ok: [clippy-all/a-refused-contender-leaves-the-owners-lock] lock still held after the refusal"; pass=$((pass+1))
else
  echo "POS-FAIL: [clippy-all/a-refused-contender-leaves-the-owners-lock] the refused run removed a lock it never owned"
fi
rmdir "$fx_clean/target/clippy-all.lock"

# REJECT ×2 (codex r8): a NAMED per-package override for a dependency that is
# NOT a member outranks the `"*"` pin, and the member-named pins never
# mentioned it (measured: `ok`, both spellings). Every resolved package is now
# pinned by name through one `--config` file.
fx_depc="$(lint_fixture dep-profile)"; mkdir -p "$fx_depc/.cargo"
printf '[profile.dev.package.leaf]\ndebug-assertions = false\n' > "$fx_depc/.cargo/config.toml"
expect_reject_because "clippy-all/named-profile-override-for-a-non-member-dependency-in-config-cannot-hide-an-error" \
  "clippy failed on the base" \
  "$here/clippy-all.sh" --root "$fx_depc"
fx_depm="$(lint_fixture dep-profile)"
printf '[profile.dev.package.leaf]\ndebug-assertions = false\n' >> "$fx_depm/Cargo.toml"
expect_reject_because "clippy-all/named-profile-override-for-a-non-member-dependency-in-the-manifest-cannot-hide-an-error" \
  "clippy failed on the base" \
  "$here/clippy-all.sh" --root "$fx_depm"

# REJECT, AND NEVER SAY OK: a failing lint's stdout must not carry the success
# line. The first version of this gate printed `clippy-all: ok (...)` before
# running clippy; the `failing-clippy-prints-FAIL` probe above cannot see that,
# because it only checks that a FAIL line exists somewhere.
expect_reject_without "clippy-all/a-failing-lint-never-prints-the-ok-line" \
  "clippy failed on the base" "clippy-all: ok" \
  "$here/clippy-all.sh" --root "$fx_test"


# ---- darwin-cross-check (#198): every member checked for macOS, one at a time,
# ---- cargo deciding what is SDK-blocked -- and the check observed catching a
# ---- darwin-only compile failure ---------------------------------------------
# The job existed since #199 but consumed `DARWIN_CRATES`, a hand-written 7
# whose own comment said "NOT gate-verified against any manifest"; 17 members
# check clean from Linux, so ten were compiled for macOS by nothing. The first
# cut of the gate DERIVED the set from a metadata closure; two reviewers broke
# the derivation in the bad direction (members silently excluded), so the gate
# now runs cargo per member and READS the outcome. These probes need the
# `aarch64-apple-darwin` target (CI's `build-and-gate` adds it; locally:
# `rustup target add aarch64-apple-darwin`); the guard probes below the target
# block do not.
#
# On the mutation harness: "drop `--target`" is observable on ANY host -- cargo
# writes a target-triple build to `target/<triple>/`, a host build to
# `target/debug/` -- and the clean-fixture probe asserts that directory. An
# earlier comment here called the mutation "unobservable on a darwin host by
# physics". Both reviewers showed it was an excuse.

darwin_fixture() { # <variant> [sdk-name] -> prints the fixture root
  # `root` depends on `leaf`. Variants:
  #   clean                    -- both check.
  #   linux-only-item          -- leaf uses an item that exists only under
  #                               cfg(target_os = "linux") -- the #72/#275
  #                               shape; E0425 on darwin, no dependency needed.
  #   linux-only-item-in-tests -- same, reachable only from a test target.
  #   sdk-blocked <name>       -- a path crate NAMED <name> (ring, aws-lc-sys,
  #                               aws-lc-fips-sys) whose build.rs PANICS. Cargo
  #                               reports "failed to run custom build command
  #                               for `<name> v0.0.0`" -- exactly the shape the
  #                               gate classifies as SDK-blocked -- so `root`
  #                               (which depends on it) must be reported
  #                               blocked and `leaf` checked. Hermetic: no
  #                               network, no real SDK crate.
  #   other-build-failure      -- the same panicking build.rs in a crate named
  #                               `notsdk`, whose panic text QUOTES cargo's
  #                               sentence naming `ring`: this MUST be a FAIL,
  #                               proving the classification is keyed on the
  #                               three names, ANCHORED at column 0, and fails
  #                               closed for anything else.
  #   stale-lock               -- Cargo.lock generated BEFORE a member was
  #                               added, so `--locked` must refuse.
  #   two-sdk                  -- `a` depends on a panicking `aws-lc-sys`,
  #                               `b` on a panicking `ring`: each evidence
  #                               line must name ITS crate (an accumulating
  #                               log would attribute a's failure to b).
  #   case-sdk                 -- the panicking crate is named `Ring`: crate
  #                               names are case-sensitive, so this is NOT an
  #                               SDK crate and must be a FAIL.
  #   unbuilt-dep-after        -- like devdep-sdk-plus-real-error, but `root`
  #                               ALSO normal-depends on `zdep`, a crate that
  #                               sorts AFTER it and so is unbuilt when `root`
  #                               is checked. Without `--keep-going` cargo
  #                               cancels root's lib compile the moment ring's
  #                               build script fails, the real error is never
  #                               produced, and the gate said "blocked", `ok`.
  #   warning-in-blocked       -- sdk-blocked, plus an unused variable in
  #                               `leaf` (a spanned WARNING in root's log).
  #                               Must still be "blocked", not a FAIL.
  #   config-rustflags         -- linux-only-item, plus `.cargo/config.toml`
  #                               with `[build] rustflags` forging
  #                               `target_os="linux"`. Must still FAIL.
  #   config-target-rustflags  -- the same, via `[target.aarch64-apple-darwin]
  #                               rustflags`.
  #   required-features-bin    -- `root` is a BIN-only member whose sole target
  #                               carries `required-features = ["hidden"]`
  #                               (default off) and a compile_error!. Cargo
  #                               says "no targets matched; this is a no-op",
  #                               exits 0, compiles NOTHING. Must be a FAIL:
  #                               a member counts only if cargo emitted a
  #                               compiler artifact OF it.
  #   debug-assertions-gated   -- `leaf` fails only under
  #                               cfg(all(target_os = "macos", debug_assertions)).
  #                               `[profile.dev] debug-assertions = false` (or
  #                               the env spelling) hid it; the profile is
  #                               pinned on the command line.
  #   debug-assertions-config  -- the same, with the config file present.
  #   pkg-profile-config       -- debug-assertions-gated, plus `.cargo/config.toml`
  #                               `[profile.dev.package.leaf] debug-assertions = false`.
  #   pkg-profile-manifest     -- the same override in the workspace ROOT Cargo.toml.
  #   bootstrap-gated          -- `leaf` needs a nightly feature gate on darwin:
  #                               E0554 on stable; `ok` under RUSTC_BOOTSTRAP=1.
  #   bootstrap-config         -- the same, with `[env] RUSTC_BOOTSTRAP` forced
  #                               in `.cargo/config.toml`.
  #   panic-gated              -- `leaf` fails only under
  #                               cfg(all(not(test), panic = "unwind")) -- the
  #                               default; `[profile.dev] panic = "abort"` or
  #                               CARGO_PROFILE_DEV_PANIC=abort hid it.
  #   panic-config             -- the same, with the config file present.
  #   proc-macro-member        -- `leaf` is a proc-macro crate: cargo compiles
  #                               it for the HOST; it must be reported host-only
  #                               and counted neither checked nor blocked.
  #   config-wrapper           -- clean, plus `.cargo/config.toml` with
  #                               `[build] rustc-wrapper = <logging shim>`.
  #                               The gate's exported empty RUSTC_WRAPPER must
  #                               beat it: the shim's log must NOT exist after.
  #   lock-deleting-build      -- `leaf`'s build.rs deletes the workspace
  #                               Cargo.lock; the member checked AFTER it must
  #                               be refused by `--locked` on the CHECK (the
  #                               resolving metadata call ran before the
  #                               deletion), not silently regenerated.
  #   devdep-sdk-plus-real-error -- `root` DEV-depends on a panicking `ring`
  #                               AND calls an undeclared fn in its lib (an
  #                               E-coded `error[E0425]`, so the `\[E…\]`
  #                               alternative of the exclusivity regex is
  #                               exercised). Under `--all-targets` both land
  #                               in one log; the member must be a FAIL.
  #   multiline-fake-line      -- `root` DEV-depends on a panicking `ring` (so
  #                               (a) and (d) are honestly satisfied) and its
  #                               lib carries a MULTI-LINE compile_error!
  #                               whose first line is cargo's sentence; rustc
  #                               renders a whitespace-only continuation line
  #                               that a blank-terminated error block took as
  #                               its end, hiding the ` --> ` span from (b).
  #   fake-cargo-line          -- `root` has NO SDK crate in its graph and a
  #                               `compile_error!` whose text is cargo's exact
  #                               sentence naming `ring`. rustc renders it at
  #                               column 0; a text-only classifier called that
  #                               "blocked". Must be a FAIL: no ` --> ` span
  #                               may accompany a blocked line, and `ring` is
  #                               not in root's tree.
  #   dep-profile-config       -- `leaf` is EXCLUDED from the workspace (a path
  #                               dependency, not a member) and carries the
  #                               debug-assertions-gated error; `.cargo/config.toml`
  #                               `[profile.dev.package.leaf] debug-assertions =
  #                               false`. The member-named pins never reached it
  #                               (codex r8: `ok`, both gates). Must FAIL naming
  #                               `root`, the member being checked.
  #   dep-profile-manifest     -- the same override in the ROOT manifest.
  #   channel-override         -- linux-only-item, plus `[unstable]
  #                               profile-rustflags` and `[profile.dev] rustflags`
  #                               forging `target_os="linux"` -- live only when
  #                               cargo's channel is overridden, so the probe sets
  #                               `__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS`
  #                               and expects the refusal; with the token dropped
  #                               from the refusal list this fixture prints `ok`.
  #   progress-config          -- sdk-blocked, plus `[term] progress.when =
  #                               "always"` / `progress.width = 80`: cargo then
  #                               writes `\r` before `error:` (codex r8) and the
  #                               column-0 anchor misses it. Must still be
  #                               "blocked": env outranks config, and the gate
  #                               exports CARGO_TERM_PROGRESS_WHEN=never.
  #   feature-gated-linux-item -- `leaf` declares feature `dark`; the Linux-only
  #                               use sits behind `cfg(feature = "dark")`. The
  #                               base pass is clean; the feature pass must FAIL
  #                               naming `leaf` and `dark`.
  #   clean-with-feature       -- `leaf` declares `dark` and gates nothing: the
  #                               OK line must count ONE feature pass.
  #   feature-fake             -- `root` declares `dark`; behind it, a
  #                               compile_error! QUOTING cargo's SDK sentence.
  #                               The round-10 feature pass had a one-line grep
  #                               classifier and printed `ok` (codex r9 and the
  #                               fresh-context reviewer, independently).
  #   feature-real             -- `dark = ["devshim/sdk"]`: a DEV-dependency's
  #                               feature pulls an optional panicking `ring`,
  #                               and root's own lib carries a real error
  #                               behind `dark`. `--keep-going` emits both; the
  #                               masking shape of round 3, on the new path.
  #   feature-blocked          -- feature-real without the real error: a
  #                               feature pass that is GENUINELY SDK-blocked is
  #                               reported as such and NOT counted as a pass.
  #   proc-macro-feature       -- proc-macro-member whose `dark` feature hides
  #                               a compile error: host-only or not, a feature
  #                               pass still runs and still FAILs.
  #   env-build-script         -- `leaf` has a build.rs that emits
  #                               `cargo:rustc-cfg=forged` when MAKNAE_FORGE is
  #                               in ITS environment, and a Linux-only use behind
  #                               `cfg(not(forged))`. The variable is on no
  #                               refusal list and no pin names it: only the
  #                               allowlist keeps it from the build script.
  #   config-env-build-script  -- the same, with `[env] MAKNAE_FORGE = "1"` in
  #                               the tree's config: only the outside cwd keeps
  #                               it from the build script (cargo's `[env]`
  #                               table is delivered to build scripts).
  #   portable-feature         -- `root` depends on an EXCLUDED path crate
  #                               `ring` whose build.rs needs an SDK unless its
  #                               `portable` feature is on; root declares
  #                               `portable = ["ring/portable"]` and hides an
  #                               error behind it. The base pass is genuinely
  #                               blocked; the feature pass is buildable and
  #                               must still run and FAIL (codex r10).
  #   build-dir-config         -- clean, plus `[build] build-dir` in the tree's
  #                               config (codex r9: a false FAIL when it was
  #                               read). From outside the tree it is not read.
  local variant="$1" sdk="${2:-ring}" d ws_extra=""
  d="$(mktemp -d -p "$NC_TMP")"
  mkdir -p "$d/crates/root/src" "$d/crates/leaf/src"
  local members='"crates/root", "crates/leaf"' extra_dep=""
  case "$variant" in
    two-sdk)
      for nm in aws-lc-sys ring; do
        mkdir -p "$d/crates/$nm/src"
        printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n' "$nm" > "$d/crates/$nm/Cargo.toml"
        printf 'fn main() { panic!("needs SDK"); }\n' > "$d/crates/$nm/build.rs"; : > "$d/crates/$nm/src/lib.rs"
      done
      mkdir -p "$d/crates/a/src" "$d/crates/b/src"
      printf '[package]\nname = "a"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\naws-lc-sys = { path = "../aws-lc-sys" }\n' > "$d/crates/a/Cargo.toml"; : > "$d/crates/a/src/lib.rs"
      printf '[package]\nname = "b"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\nring = { path = "../ring" }\n' > "$d/crates/b/Cargo.toml"; : > "$d/crates/b/src/lib.rs"
      members='"crates/root", "crates/leaf", "crates/a", "crates/b", "crates/aws-lc-sys", "crates/ring"' ;;
    case-sdk)
      mkdir -p "$d/crates/Ring/src"
      printf '[package]\nname = "Ring"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n' > "$d/crates/Ring/Cargo.toml"
      printf 'fn main() { panic!("needs SDK"); }\n' > "$d/crates/Ring/build.rs"; : > "$d/crates/Ring/src/lib.rs"
      members='"crates/root", "crates/leaf", "crates/Ring"'
      extra_dep='Ring = { path = "../Ring" }' ;;
    lock-deleting-build)
      printf '[package]\nname = "leaf"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n' > "$d/crates/leaf/Cargo.toml"
      printf 'fn main() { let _ = std::fs::remove_file(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock")); }\n' > "$d/crates/leaf/build.rs" ;;
    unbuilt-dep-after)
      mkdir -p "$d/crates/ring/src" "$d/crates/zdep/src"
      printf '[package]\nname = "ring"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n' > "$d/crates/ring/Cargo.toml"
      printf 'fn main() { panic!("needs SDK"); }\n' > "$d/crates/ring/build.rs"; : > "$d/crates/ring/src/lib.rs"
      printf '[package]\nname = "zdep"\nversion = "0.0.0"\nedition = "2021"\n' > "$d/crates/zdep/Cargo.toml"
      # Big enough that rustc has not finished it before ring's build script fails.
      python3 -c 'print("".join(f"pub fn f{i}() -> u64 {{ {i} }}" + chr(10) for i in range(6000)))' > "$d/crates/zdep/src/lib.rs"
      members='"crates/root", "crates/leaf", "crates/ring", "crates/zdep"'
      extra_dep='zdep = { path = "../zdep" }' ;;
    warning-in-blocked)
      mkdir -p "$d/crates/ring/src"
      printf '[package]\nname = "ring"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n' > "$d/crates/ring/Cargo.toml"
      printf 'fn main() { panic!("needs SDK"); }\n' > "$d/crates/ring/build.rs"; : > "$d/crates/ring/src/lib.rs"
      members='"crates/root", "crates/leaf", "crates/ring"'
      extra_dep='ring = { path = "../ring" }' ;;
    pkg-profile-config)
      mkdir -p "$d/.cargo"; printf '[profile.dev.package.leaf]\ndebug-assertions = false\n' > "$d/.cargo/config.toml" ;;
    dep-profile-config|dep-profile-manifest)
      members='"crates/root"'; ws_extra=$'exclude = ["crates/leaf"]\n'
      [ "$variant" = dep-profile-config ] && { mkdir -p "$d/.cargo"; printf '[profile.dev.package.leaf]\ndebug-assertions = false\n' > "$d/.cargo/config.toml"; } ;;
    bootstrap-config)
      mkdir -p "$d/.cargo"; printf '[env]\nRUSTC_BOOTSTRAP = { value = "1", force = true }\n' > "$d/.cargo/config.toml" ;;
    panic-config)
      mkdir -p "$d/.cargo"; printf '[profile.dev]\npanic = "abort"\n' > "$d/.cargo/config.toml" ;;
    proc-macro-member)
      printf '[package]\nname = "leaf"\nversion = "0.0.0"\nedition = "2021"\n[lib]\nproc-macro = true\n' > "$d/crates/leaf/Cargo.toml" ;;
    proc-macro-feature)
      printf '[package]\nname = "leaf"\nversion = "0.0.0"\nedition = "2021"\n[lib]\nproc-macro = true\n[features]\ndark = []\n' > "$d/crates/leaf/Cargo.toml" ;;
    portable-feature)
      mkdir -p "$d/deps/ring/src"; ws_extra=$'exclude = ["deps/ring"]\n'
      printf '[package]\nname = "ring"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n[features]\nportable = []\n' > "$d/deps/ring/Cargo.toml"
      printf 'fn main() { if !cfg!(feature = "portable") { panic!("needs SDK"); } }\n' > "$d/deps/ring/build.rs"; : > "$d/deps/ring/src/lib.rs"
      extra_dep='ring = { path = "../../deps/ring" }' ;;
    env-build-script|config-env-build-script)
      printf '[package]\nname = "leaf"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n' > "$d/crates/leaf/Cargo.toml"
      printf 'fn main() { println!("cargo:rustc-check-cfg=cfg(forged)"); if std::env::var_os("MAKNAE_FORGE").is_some() { println!("cargo:rustc-cfg=forged"); } }\n' > "$d/crates/leaf/build.rs" ;;
    feature-real|feature-blocked)
      mkdir -p "$d/crates/ring/src" "$d/crates/devshim/src"
      printf '[package]\nname = "ring"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n' > "$d/crates/ring/Cargo.toml"
      printf 'fn main() { panic!("needs SDK"); }\n' > "$d/crates/ring/build.rs"; : > "$d/crates/ring/src/lib.rs"
      printf '[package]\nname = "devshim"\nversion = "0.0.0"\nedition = "2021"\n[features]\nsdk = ["dep:ring"]\n[dependencies]\nring = { path = "../ring", optional = true }\n' > "$d/crates/devshim/Cargo.toml"; : > "$d/crates/devshim/src/lib.rs"
      members='"crates/root", "crates/leaf", "crates/ring", "crates/devshim"' ;;
    required-features-bin)
      rm -rf "$d/crates/root/src"; mkdir -p "$d/crates/root/src"
      printf 'compile_error!("HIDDEN_BIN_REAL_ERROR");\nfn main() {}\n' > "$d/crates/root/src/main.rs" ;;
    debug-assertions-config)
      mkdir -p "$d/.cargo"; printf '[profile.dev]\ndebug-assertions = false\n' > "$d/.cargo/config.toml" ;;
    config-rustflags)
      mkdir -p "$d/.cargo"
      printf '[build]\nrustflags = ["--cfg", "target_os=\\"linux\\"", "-Aexplicit_builtin_cfgs_in_flags"]\n' > "$d/.cargo/config.toml" ;;
    config-target-rustflags)
      mkdir -p "$d/.cargo"
      printf '[target.aarch64-apple-darwin]\nrustflags = ["--cfg", "target_os=\\"linux\\"", "-Aexplicit_builtin_cfgs_in_flags"]\n' > "$d/.cargo/config.toml" ;;
    config-wrapper)
      mkdir -p "$d/bin"
      printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s/wrapper.log"\nexec "$@"\n' "$d" > "$d/bin/wrap"; chmod +x "$d/bin/wrap" ;;
    devdep-sdk-plus-real-error|silent-rustc-death|multiline-fake-line)
      mkdir -p "$d/crates/ring/src"
      printf '[package]\nname = "ring"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n' > "$d/crates/ring/Cargo.toml"
      printf 'fn main() { panic!("needs SDK"); }\n' > "$d/crates/ring/build.rs"
      : > "$d/crates/ring/src/lib.rs"
      members='"crates/root", "crates/leaf", "crates/ring"' ;;
    sdk-blocked|other-build-failure|progress-config)
      local nm="$sdk"; [ "$variant" = other-build-failure ] && nm="notsdk"
      mkdir -p "$d/crates/$nm/src"
      printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n' "$nm" > "$d/crates/$nm/Cargo.toml"
      # The panic text QUOTES cargo's own sentence, naming a real SDK crate. With
      # an UNANCHORED classifier that quoted line (cargo prints build-script
      # stderr indented, never at column 0) flipped a FAIL into a green
      # "blocked"; the anchored `^error: ` form ignores it. This is what makes
      # the `notsdk` probe below exercise the anchor. Codex showed the round-3
      # "inert" claim was overstated: `compile_error!("error: failed to run
      # custom build command for ...")` rendered `error: error: failed ...` --
      # matched unanchored, not anchored -- and exclusivity alone let it
      # through. Since round 4 the span-line and tree corroborations refuse
      # that case with or without the anchor, so the anchor is now the FIRST
      # filter of four rather than a control on its own.
      printf 'fn main() { panic!("simulated SDK failure: failed to run custom build command for `ring v0.17.14` (quoted)"); }\n' > "$d/crates/$nm/build.rs"
      : > "$d/crates/$nm/src/lib.rs"
      members="\"crates/root\", \"crates/leaf\", \"crates/$nm\""
      extra_dep="$(printf '%s = { path = "../%s" }\n' "$nm" "$nm")" ;;
  esac
  printf '[workspace]\nresolver = "3"\nmembers = [%s]\n%s' "$members" "$ws_extra" > "$d/Cargo.toml"
  [ "$variant" = pkg-profile-manifest ] && printf '[profile.dev.package.leaf]\ndebug-assertions = false\n' >> "$d/Cargo.toml"
  cp "$here/../../rust-toolchain.toml" "$d/rust-toolchain.toml"
  if [ "$variant" = required-features-bin ]; then
    printf '[package]\nname = "root"\nversion = "0.0.0"\nedition = "2021"\n[features]\nhidden = []\n[dependencies]\nleaf = { path = "../leaf" }\n[[bin]]\nname = "root"\npath = "src/main.rs"\nrequired-features = ["hidden"]\n' > "$d/crates/root/Cargo.toml"
  else
  {
    printf '[package]\nname = "root"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\nleaf = { path = "../leaf" }\n'
    [ -n "$extra_dep" ] && printf '%s\n' "$extra_dep"
    case "$variant" in devdep-sdk-plus-real-error|silent-rustc-death|unbuilt-dep-after|multiline-fake-line) printf '[dev-dependencies]\nring = { path = "../ring" }\n' ;; esac
    case "$variant" in
      feature-fake) printf '[features]\ndark = []\n' ;;
      portable-feature) printf '[features]\nportable = ["ring/portable"]\n' ;;
      feature-real|feature-blocked) printf '[features]\ndark = ["devshim/sdk"]\n[dev-dependencies]\ndevshim = { path = "../devshim" }\n' ;;
    esac
  } > "$d/crates/root/Cargo.toml"
  fi
  case "$variant" in
    required-features-bin) : ;;   # main.rs written above; no lib
    devdep-sdk-plus-real-error)
      printf 'pub fn r() -> u8 { leaf::l() }\npub fn boom() -> u8 { undeclared_fn_real_darwin_error() }\n' > "$d/crates/root/src/lib.rs" ;;
    unbuilt-dep-after)
      printf 'pub fn r() -> u64 { zdep::f1() + leaf::l() as u64 }\npub fn boom() -> u8 { undeclared_fn_real_darwin_error() }\n' > "$d/crates/root/src/lib.rs" ;;
    fake-cargo-line)
      printf 'pub fn r() -> u8 { leaf::l() }\ncompile_error!("failed to run custom build command for `ring v0.17.14`");\n' > "$d/crates/root/src/lib.rs" ;;
    multiline-fake-line)
      printf 'pub fn r() -> u8 { leaf::l() }\ncompile_error!("failed to run custom build command for `ring v0.0.0`\\n\\nthe real darwin error is hidden below");\n' > "$d/crates/root/src/lib.rs" ;;
    proc-macro-member|proc-macro-feature)
      printf 'pub fn r() -> u8 { 7 }\n' > "$d/crates/root/src/lib.rs" ;;
    feature-fake)
      printf 'pub fn r() -> u8 { leaf::l() }\n#[cfg(feature = "dark")]\ncompile_error!("failed to run custom build command for `ring v0.0.0`");\n' > "$d/crates/root/src/lib.rs" ;;
    feature-real)
      printf 'pub fn r() -> u8 { leaf::l() }\n#[cfg(feature = "dark")]\ncompile_error!("REAL_DARWIN_ERROR_BEHIND_DARK");\n' > "$d/crates/root/src/lib.rs" ;;
    portable-feature)
      printf 'pub fn r() -> u8 { leaf::l() }\n#[cfg(feature = "portable")]\ncompile_error!("PORTABLE_DARWIN_SENTINEL");\n' > "$d/crates/root/src/lib.rs" ;;
    *)
      printf 'pub fn r() -> u8 { leaf::l() }\n' > "$d/crates/root/src/lib.rs" ;;
  esac
  case "$variant" in
    lock-deleting-build|proc-macro-member|proc-macro-feature|env-build-script|config-env-build-script) : ;;
    feature-gated-linux-item|clean-with-feature) printf '[package]\nname = "leaf"\nversion = "0.0.0"\nedition = "2021"\n[features]\ndark = []\n' > "$d/crates/leaf/Cargo.toml" ;;
    *) printf '[package]\nname = "leaf"\nversion = "0.0.0"\nedition = "2021"\n' > "$d/crates/leaf/Cargo.toml" ;;
  esac
  {
    # An inner attribute must come FIRST: printed after an item it is a syntax
    # error, and the bootstrap probes were then green for the wrong reason
    # (measured: the neutraliser mutation survived).
    case "$variant" in bootstrap-gated|bootstrap-config) printf '#![cfg_attr(target_os = "macos", feature(never_type))]\n' ;; esac
    case "$variant" in proc-macro-member|proc-macro-feature) : ;; *) printf 'pub fn l() -> u8 { 7 }\n' ;; esac
    [ "$variant" = warning-in-blocked ] && printf 'pub fn w() { let unused_var_makes_a_spanned_warning = 3; }\n'
    case "$variant" in
      proc-macro-member)
        printf 'use proc_macro::TokenStream;\n#[proc_macro]\npub fn noop(i: TokenStream) -> TokenStream { i }\n' ;;
      proc-macro-feature)
        printf 'use proc_macro::TokenStream;\n#[proc_macro]\npub fn noop(i: TokenStream) -> TokenStream { i }\n#[cfg(feature = "dark")]\ncompile_error!("PROC_MACRO_FEATURE_ERROR");\n' ;;
      panic-gated|panic-config)
        printf '#[cfg(all(not(test), panic = "unwind"))]\ncompile_error!("REAL_DARWIN_ERROR_BEHIND_PANIC_UNWIND");\n' ;;
      debug-assertions-gated|debug-assertions-config|pkg-profile-config|pkg-profile-manifest|dep-profile-config|dep-profile-manifest)
        printf '#[cfg(all(target_os = "macos", debug_assertions))]\ncompile_error!("REAL_DARWIN_ERROR_BEHIND_DEBUG_ASSERTIONS");\n' ;;
      linux-only-item|config-rustflags|config-target-rustflags|channel-override)
        printf '#[cfg(target_os = "linux")]\nfn linux_only() -> u8 { 1 }\npub fn uses_it() -> u8 { linux_only() }\n' ;;
      feature-gated-linux-item)
        printf '#[cfg(target_os = "linux")]\nfn linux_only() -> u8 { 1 }\n#[cfg(feature = "dark")]\npub fn uses_it() -> u8 { linux_only() }\n' ;;
      env-build-script|config-env-build-script)
        printf '#[cfg(target_os = "linux")]\nfn linux_only() -> u8 { 1 }\n#[cfg(not(forged))]\npub fn uses_it() -> u8 { linux_only() }\n' ;;
      linux-only-item-in-tests)
        printf '#[cfg(target_os = "linux")]\nfn linux_only() -> u8 { 1 }\n#[cfg(test)]\nmod t { #[test] fn s() { assert_eq!(super::linux_only(), 1); } }\n' ;;
    esac
  } > "$d/crates/leaf/src/lib.rs"
  ( cd "$d" && cargo generate-lockfile --offline >/dev/null 2>&1 )
  # Also written AFTER the lockfile: `[unstable]` / `[profile.dev] rustflags`
  # (stable cargo warns on them; the fixture's own generate-lockfile need not
  # see them), the progress bar, and the root-manifest profile override.
  case "$variant" in
    channel-override) mkdir -p "$d/.cargo"; printf '[unstable]\nprofile-rustflags = true\n[profile.dev]\nrustflags = ["--cfg", "target_os=\\"linux\\"", "-Aexplicit_builtin_cfgs_in_flags"]\n' > "$d/.cargo/config.toml" ;;
    progress-config) mkdir -p "$d/.cargo"; printf '[term]\nprogress.when = "always"\nprogress.width = 80\n' > "$d/.cargo/config.toml" ;;
    dep-profile-manifest) printf '[profile.dev.package.leaf]\ndebug-assertions = false\n' >> "$d/Cargo.toml" ;;
    build-dir-config) mkdir -p "$d/.cargo"; printf '[build]\nbuild-dir = "target/separate"\n' > "$d/.cargo/config.toml" ;;
    config-env-build-script) mkdir -p "$d/.cargo"; printf '[env]\nMAKNAE_FORGE = "1"\n' > "$d/.cargo/config.toml" ;;
  esac
  # Written AFTER the lockfile: the fixture's own `generate-lockfile` runs
  # `rustc -vV` and, with the config already present, that call landed in the
  # wrapper log and was recorded as a gate residue. It was the fixture's.
  if [ "$variant" = config-wrapper ]; then
    mkdir -p "$d/.cargo"; printf '[build]\nrustc-wrapper = "%s/bin/wrap"\n' "$d" > "$d/.cargo/config.toml"
  fi
  if [ "$variant" = stale-lock ]; then
    # Add a member AFTER the lock was written; `--locked` must now refuse.
    mkdir -p "$d/crates/late/src"
    printf '[package]\nname = "late"\nversion = "0.0.0"\nedition = "2021"\n' > "$d/crates/late/Cargo.toml"; : > "$d/crates/late/src/lib.rs"
    printf '[workspace]\nresolver = "3"\nmembers = ["crates/root", "crates/leaf", "crates/late"]\n' > "$d/Cargo.toml"
  fi
  printf '%s' "$d"
}

# ---------------------------------------------------------------- guard probes
# The gate carries the same guards as clippy-all.sh. Each has a probe there
# and, until this block, none here -- so the toolchain pin, for one, was
# enforced and unproven. Same fixtures, same FAIL strings, darwin labels.
tmpD0="$(mktemp -d -p "$NC_TMP")"
printf '[workspace]\nresolver = "3"\nmembers = []\n' > "$tmpD0/Cargo.toml"
cp "$here/../../rust-toolchain.toml" "$tmpD0/rust-toolchain.toml"
expect_reject_because "darwin-cross-check/zero-members-is-refused" \
  "resolved ZERO" \
  "$here/darwin-cross-check.sh" --root "$tmpD0" --check-inputs

tmpD1="$(mktemp -d -p "$NC_TMP")"
printf '[workspace]\nresolver = "3"\nmembers = ["nope"]\n' > "$tmpD1/Cargo.toml"
cp "$here/../../rust-toolchain.toml" "$tmpD1/rust-toolchain.toml"
expect_reject_because "darwin-cross-check/metadata-failure-is-not-silent" \
  "cargo metadata failed" \
  "$here/darwin-cross-check.sh" --root "$tmpD1" --check-inputs

tmpD2="$(mktemp -d -p "$NC_TMP")"
printf '[workspace]\nresolver = "3"\nmembers = []\n' > "$tmpD2/Cargo.toml"
expect_reject_because "darwin-cross-check/missing-toolchain-file-is-refused" \
  "missing" \
  "$here/darwin-cross-check.sh" --root "$tmpD2" --check-inputs

tmpD3="$(mktemp -d -p "$NC_TMP")"
printf '[workspace]\nresolver = "3"\nmembers = []\n' > "$tmpD3/Cargo.toml"
printf '[toolchain]\ncomponents = ["clippy"]\n' > "$tmpD3/rust-toolchain.toml"
expect_reject_because "darwin-cross-check/no-channel-is-refused" \
  "no [toolchain] channel" \
  "$here/darwin-cross-check.sh" --root "$tmpD3" --check-inputs

for ch in stable nightly-2026-01-01 1garbage.2whatever; do
  tmpD4="$(mktemp -d -p "$NC_TMP")"
  printf '[workspace]\nresolver = "3"\nmembers = []\n' > "$tmpD4/Cargo.toml"
  printf '[toolchain]\nchannel = "%s"\n' "$ch" > "$tmpD4/rust-toolchain.toml"
  expect_reject_because "darwin-cross-check/unpinned-channel-$ch-is-refused" \
    "is not a pinned release" \
    "$here/darwin-cross-check.sh" --root "$tmpD4" --check-inputs
done

expect_reject_because "darwin-cross-check/unknown-argument-is-refused" \
  "unknown argument" \
  "$here/darwin-cross-check.sh" --chek-inputs

expect_reject_because "darwin-cross-check/conflicting-mode-flags-are-refused" \
  "conflicting mode flags" \
  "$here/darwin-cross-check.sh" --check-inputs --check-inputs

expect_reject_because "darwin-cross-check/unenterable-root-is-refused" \
  "cannot enter --root '/nonexistent-198'" \
  "$here/darwin-cross-check.sh" --root /nonexistent-198 --check-inputs

# The pin is ENFORCED against BOTH tools. A cargo shim reporting a fake version
# is hermetic (no second toolchain needed); the RUSTC override is the case
# codex found: cargo 1.98.1 happily drives a 1.94.1 rustc and reports the pin.
tmpD5="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpD5/bin"
{ printf '#!/usr/bin/env bash\n'; printf 'REAL_CARGO=%q\n' "$(command -v cargo)"; cat; } > "$tmpD5/bin/cargo" <<'SHIM'
if [ "${1:-}" = --version ]; then echo "cargo 1.0.0 (fake 2000-01-01)"; exit 0; fi
exec "$REAL_CARGO" "$@"
SHIM
chmod +x "$tmpD5/bin/cargo"
# ...and the rustc half of the pin, independently: a `rustc` shim that answers
# `--version` with a fake and passes everything else through. Deleting the
# rustc query survived every other probe.

expect_reject_because "darwin-cross-check/toolchain-mismatch-is-refused" \
  "toolchain mismatch" \
  env REAL_CARGO="$(command -v cargo)" PATH="$tmpD5/bin:$PATH" \
  "$here/darwin-cross-check.sh" --root "$here/../.." --check-inputs
expect_reject_because "darwin-cross-check/rustc-override-is-refused" \
  "RUSTC is set" \
  env RUSTC=/usr/bin/false \
  "$here/darwin-cross-check.sh" --root "$here/../.." --check-inputs
expect_reject_because "darwin-cross-check/rustc-wrapper-is-refused" \
  "RUSTC_WRAPPER is set" \
  env RUSTC_WRAPPER=/usr/bin/env \
  "$here/darwin-cross-check.sh" --root "$here/../.." --check-inputs
# ...and the four other spellings cargo honours. Measured with a logging
# wrapper: each drove every compile while the gate printed the pin.
for v in RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER; do
  expect_reject_because "darwin-cross-check/$v-is-refused" \
    "$v is set" \
    env "$v=/usr/bin/env" \
    "$here/darwin-cross-check.sh" --root "$here/../.." --check-inputs
done

tmpD6="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpD6/bin"
{ printf '#!/usr/bin/env bash\n'; printf 'REAL_CARGO=%q\n' "$(command -v cargo)"; cat; } > "$tmpD6/bin/cargo" <<'SHIM'
if [ "${1:-}" = metadata ]; then exec "$REAL_CARGO" "$@"; fi
exit 101
SHIM
chmod +x "$tmpD6/bin/cargo"
expect_reject_because "darwin-cross-check/unanswerable-cargo-version-is-not-mute" \
  "cannot determine the active cargo version" \
  env REAL_CARGO="$(command -v cargo)" PATH="$tmpD6/bin:$PATH" \
  "$here/darwin-cross-check.sh" --root "$here/../.." --check-inputs

if [ -x /bin/bash ] && /bin/bash -c '[ "${BASH_VERSINFO[0]}" -lt 4 ]' 2>/dev/null; then
  expect_reject_because "darwin-cross-check/system-bash-3.2-is-refused" \
    "bash >= 4 required" \
    /bin/bash "$here/darwin-cross-check.sh" --check-inputs
else
  skipped=$((skipped+1)); echo "skip: [darwin-cross-check/system-bash-3.2-is-refused] no bash < 4 at /bin/bash"
fi

# A missing darwin target is a FAIL naming the fix, never a skip. (Placed
# BEFORE the target-gated block so it runs everywhere.)
tmpD7="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpD7/bin"
{ printf '#!/usr/bin/env bash\n'; printf 'REAL_RUSTUP=%q\n' "$(command -v rustup)"; cat; } > "$tmpD7/bin/rustup" <<'SHIM'
if [ "${1:-}" = target ]; then exit 0; fi
exec "$REAL_RUSTUP" "$@"
SHIM
chmod +x "$tmpD7/bin/rustup"
expect_reject_because "darwin-cross-check/missing-target-is-a-FAIL-not-a-skip" \
  "rustup target add aarch64-apple-darwin" \
  env REAL_RUSTUP="$(command -v rustup)" PATH="$tmpD7/bin:$PATH" \
  "$here/darwin-cross-check.sh" --root "$here/../.." --check-inputs

# ACCEPT: the target check is scoped to `$root`, not the caller's cwd. A rustup
# shim that reports the target ONLY when RUSTUP_TOOLCHAIN equals the pin --
# the gate runs every toolchain call from a cwd OUTSIDE the tree and carries
# the pin in its allowlisted environment; "drop the pin" is caught here
# `cd "$root" &&`. No second toolchain needed -- an earlier comment claimed
# this could not be probed hermetically; it can.
tmpD10="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpD10/bin"
{ printf '#!/usr/bin/env bash\n'; printf 'REAL_RUSTUP=%q\n' "$(command -v rustup)"; printf 'EXPECT_CHANNEL=%q\n' "$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$here/../../rust-toolchain.toml")"; cat; } > "$tmpD10/bin/rustup" <<'SHIM'
if [ "${1:-}" = target ]; then [ "${RUSTUP_TOOLCHAIN:-}" = "$EXPECT_CHANNEL" ] && echo aarch64-apple-darwin; exit 0; fi
exec "$REAL_RUSTUP" "$@"
SHIM
chmod +x "$tmpD10/bin/rustup"
expect_accept "darwin-cross-check/target-check-is-scoped-to-root-not-cwd" \
  "ran NO check" \
  env REAL_RUSTUP="$(command -v rustup)" EXPECT_CHANNEL="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$here/../../rust-toolchain.toml")" PATH="$tmpD10/bin:$PATH" \
  bash -c 'cd /tmp && exec "$0" "$@"' "$here/darwin-cross-check.sh" --root "$here/../.." --check-inputs

# ------------------------------------------------- the check itself, observed
# The number of probes inside the target-gated block. Hand-counted, and then
# CHECKED: when the block runs, the probes it added to `$total` must equal this
# constant, so a probe added without bumping it is a harness failure on every
# host that has the target -- rather than a silently wrong skip count on every
# host that does not (which is how 17 stood for 20 after round 3 added three
# -- and how 24 stood for 23 the first time this check ran, and 38 for 39
# the third).
darwin_block_probes=77
# The oracle walk, shared by the real-repo probe and the proc-macro fixture
# probe below. Members, minus host-only (proc-macro-only) ones; from each,
# normal+dev edges, then normal only; a member reaching an SDK crate is
# expected blocked unless the host is darwin.
darwin_oracle_py=$(cat <<'PYO'
import json, sys
host_is_darwin = sys.argv[1] == "aarch64-apple-darwin"
m = json.load(sys.stdin)
def host_only(p):
    # proc-macro-only members compile for the HOST; the gate reports them
    # host-only and counts them as neither (codex r8: the oracle said 2 where
    # the gate correctly said 1).
    kinds = {k for t in p["targets"] for k in t["kind"]}
    return bool(kinds) and kinds <= {"proc-macro", "custom-build"}
members = set(m["workspace_members"])
ws = {p["id"] for p in m["packages"] if p["id"] in members and not host_only(p)}
name = {p["id"]: p["name"] for p in m["packages"]}
edges = {}
for n in m["resolve"]["nodes"]:
    for d in n["deps"]:
        kinds = {(k.get("kind") or "normal") for k in d["dep_kinds"]}
        edges.setdefault(n["id"], []).append((d["pkg"], kinds))
SDK = {"aws-lc-sys", "aws-lc-fips-sys", "ring"}
def reaches_sdk(start):
    seen = set(); frontier = [(start, True)]
    while frontier:
        node, is_root = frontier.pop()
        if node in seen: continue
        seen.add(node)
        if name[node] in SDK: return True
        for dep, kinds in edges.get(node, []):
            if "normal" in kinds or (is_root and "dev" in kinds):
                frontier.append((dep, False))
    return False
checked_ids = [pid for pid in ws if host_is_darwin or not reaches_sdk(pid)]
feats = {p["id"]: sorted(f for f in p.get("features", {}) if f != "default") for p in m["packages"]}
# "<checked> <feature passes>": one darwin pass per declared feature of a checked member.
print(len(checked_ids), sum(len(feats[pid]) for pid in checked_ids))
PYO
)
if rustup target list --installed 2>/dev/null | grep -q '^aarch64-apple-darwin$'; then
  darwin_block_total_before=$total
  # Since round 11 the gates run cargo hermetically (env -i + an outside cwd),
  # so the env-spelling and tree-config fixtures below observe THOSE TWO
  # MECHANISMS, not the individual pins their comments name; the `--config`
  # pins are observed only by the root-MANIFEST fixtures (pkg-profile-manifest,
  # dep-profile-manifest). Recorded (critical-review r10), not re-litigated.
  #
  # On a host whose triple IS the target the gate refuses any SDK block (the
  # SDK is present; a build-script failure there is real) while still echoing
  # the classification. These two helpers assert the classification on BOTH
  # hosts and the verdict per host: rc 0 elsewhere, the host-rule FAIL here.
  darwin_host=0; [ "$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')" = aarch64-apple-darwin ] && darwin_host=1
  expect_blocked() { # <label> <must-contain> <cmd...>
    local label="$1" want="$2"; shift 2; total=$((total+1)); local out rc
    if out="$("$@" 2>&1)"; then rc=0; else rc=$?; fi
    if [ "$darwin_host" = 1 ]; then
      if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'FAIL: on a host whose triple IS the target' && printf '%s' "$out" | grep -q -- "$want"; then
        echo "neg-ok: [$label] classified, refused on a darwin host, and reported '$want'"; pass=$((pass+1))
      else
        echo "NEG-FAIL: [$label] on a darwin host: wanted the host-rule FAIL plus '$want' (rc=$rc): $out"
      fi
    elif [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q -- "$want"; then
      echo "pos-ok: [$label] gate accepted and reported '$want'"; pass=$((pass+1))
    else
      echo "POS-FAIL: [$label] (rc=$rc) wanted '$want': $out"
    fi
  }
  expect_blocked_count() { # <label> <prefix> <expected> <cmd...>
    local label="$1" prefix="$2" expected="$3"; shift 3; total=$((total+1)); local out rc n
    if out="$("$@" 2>&1)"; then rc=0; else rc=$?; fi
    n="$(printf '%s' "$out" | sed -n "s/.*${prefix}\([0-9][0-9]*\).*/\1/p" | head -1)"
    if [ "$darwin_host" = 1 ]; then
      if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'FAIL: on a host whose triple IS the target' && [ "$n" = "$expected" ]; then
        echo "neg-ok: [$label] classified ($prefix$n), then refused on a darwin host"; pass=$((pass+1))
      else
        echo "NEG-FAIL: [$label] on a darwin host: wanted the host-rule FAIL with $prefix$expected, got rc=$rc, '$n': $out"
      fi
    elif [ "$rc" -eq 0 ] && [ "$n" = "$expected" ]; then
      echo "pos-ok: [$label] gate accepted, examined $n (expected $expected)"; pass=$((pass+1))
    else
      echo "POS-FAIL: [$label] (rc=$rc) examined '$n' but expected $expected: $out"
    fi
  }
  expect_accept "darwin-cross-check/check-inputs-does-not-claim-a-check" \
    "ran NO check" \
    "$here/darwin-cross-check.sh" --root "$here/../.." --check-inputs

  tmpD5r="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpD5r/bin"
  { printf '#!/usr/bin/env bash\n'; printf 'REAL_RUSTC=%q\n' "$(cd "$here/../.." && rustup which rustc)"; cat; } > "$tmpD5r/bin/rustc" <<'SHIM'
  if [ "${1:-}" = --version ]; then echo "rustc 1.0.0 (fake 2000-01-01)"; exit 0; fi
  exec "$REAL_RUSTC" "$@"
SHIM
  chmod +x "$tmpD5r/bin/rustc"
  # ACCEPT: a `rustc` shim on PATH never reaches the check. (In the target-
  # dependent block since round 13: `--check-inputs` needs the target too, and
  # this probe used to leak past the skip on hosts without it — PR review.) The compiler is
  # resolved by PATH under the pin (`rustup which rustc`) and the resolved BINARY
  # is version-checked (rounds 11-12); the PATH `rustc` itself is never run.
  # (Until round 11 this probe expected a mismatch FAIL from the proxy check;
  # the proxy is no longer what runs, and the live route -- `rustup which` --
  # is probed by the-resolved-rustc-binary-is-version-checked.)
  expect_accept "darwin-cross-check/a-PATH-rustc-shim-never-reaches-the-check" \
    "ran NO check" \
    env PATH="$tmpD5r/bin:$PATH" \
    "$here/darwin-cross-check.sh" --root "$here/../.." --check-inputs

  # ACCEPT, AND THE TARGET DIR EXISTS: the clean fixture checks both members,
  # and the GATE-OWNED `target/darwin-cross-check/aarch64-apple-darwin/` is
  # present afterwards -- which is what a
  # `--target` build leaves and a host build does not, on ANY host. Kills
  # "drop --target" everywhere, and "check only the first member" (count).
  fx_dc="$(darwin_fixture clean)"
  expect_reported_count "darwin-cross-check/clean-fixture-checks-every-member" \
    "cross-checked " 2 \
    "$here/darwin-cross-check.sh" --root "$fx_dc"
  total=$((total+1))
  if [ -d "$fx_dc/target/darwin-cross-check/aarch64-apple-darwin" ]; then
    echo "pos-ok: [darwin-cross-check/the-check-really-targets-darwin] target/darwin-cross-check/aarch64-apple-darwin/ exists after the run"; pass=$((pass+1))
  else
    echo "POS-FAIL: [darwin-cross-check/the-check-really-targets-darwin] no target/darwin-cross-check/aarch64-apple-darwin/ after the run — the check built for the HOST or into an unowned dir: $(ls -R "$fx_dc/target" 2>/dev/null | head -5 | tr '\n' ' ')"
  fi

  # REJECT: a Linux-only item used unconditionally fails the darwin check, and
  # the FAIL names the member and says it was NOT an SDK failure.
  fx_dl="$(darwin_fixture linux-only-item)"
  expect_reject_because "darwin-cross-check/linux-only-item-fails-the-darwin-check" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    "$here/darwin-cross-check.sh" --root "$fx_dl"

  # REJECT ×3: rustflags must not forge the target. `--cfg target_os="linux"`
  # (with the builtin-cfg lint allowed) made this same fixture PASS the darwin
  # check through every source cargo honours -- RUSTFLAGS, the encoded form,
  # and `[build] rustflags` in a config file. The gate's explicit empty
  # CARGO_ENCODED_RUSTFLAGS outranks all three.
  expect_reject_because "darwin-cross-check/RUSTFLAGS-cannot-forge-the-target" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    env RUSTFLAGS='--cfg target_os="linux" -Aexplicit_builtin_cfgs_in_flags' \
    "$here/darwin-cross-check.sh" --root "$fx_dl"
  expect_reject_because "darwin-cross-check/CARGO_ENCODED_RUSTFLAGS-cannot-forge-the-target" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    env CARGO_ENCODED_RUSTFLAGS="$(printf -- '--cfg\x1ftarget_os="linux"\x1f-Aexplicit_builtin_cfgs_in_flags')" \
    "$here/darwin-cross-check.sh" --root "$fx_dl"
  expect_reject_because "darwin-cross-check/target-specific-RUSTFLAGS-cannot-forge-the-target" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    env CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS='--cfg target_os="linux" -Aexplicit_builtin_cfgs_in_flags' \
    "$here/darwin-cross-check.sh" --root "$fx_dl"
  fx_cr="$(darwin_fixture config-rustflags)"
  expect_reject_because "darwin-cross-check/config-file-rustflags-cannot-forge-the-target" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    "$here/darwin-cross-check.sh" --root "$fx_cr"
  fx_ctr="$(darwin_fixture config-target-rustflags)"
  expect_reject_because "darwin-cross-check/config-file-target-rustflags-cannot-forge-the-target" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    "$here/darwin-cross-check.sh" --root "$fx_ctr"

  # REJECT: the same item reachable only from a TEST target -- kills dropping
  # `--all-targets`.
  fx_dt="$(darwin_fixture linux-only-item-in-tests)"
  expect_reject_because "darwin-cross-check/linux-only-item-in-a-test-target-fails-the-darwin-check" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    "$here/darwin-cross-check.sh" --root "$fx_dt"

  # REJECT, AND NEVER SAY OK.
  expect_reject_without "darwin-cross-check/a-failing-check-never-prints-the-ok-line" \
    "cross-check failed for aarch64-apple-darwin" "darwin-cross-check: ok" \
    "$here/darwin-cross-check.sh" --root "$fx_dl"

  # ACCEPT, WITH THE CLASSIFICATION OBSERVED, FOR EACH OF THE THREE NAMES: a
  # build script that fails inside a crate named <sdk> makes its dependant
  # `root` SDK-blocked -- reported, named, and NOT a FAIL -- while `leaf` is
  # checked. Kills narrowing the name set (an earlier suite let `{"ring"}`
  # alone survive) and kills dropping the package selection (a `-p`-less run
  # would build the panicking crate and FAIL the whole fixture).
  for sdk in ring aws-lc-sys aws-lc-fips-sys; do
    fx_ds="$(darwin_fixture sdk-blocked "$sdk")"
    expect_blocked_count "darwin-cross-check/$sdk-build-failure-is-classified-blocked-not-failed" \
      "cross-checked " 1 \
      "$here/darwin-cross-check.sh" --root "$fx_ds"
    expect_blocked "darwin-cross-check/$sdk-blocked-member-is-named" \
      "SDK-blocked from .*: $sdk root" \
      "$here/darwin-cross-check.sh" --root "$fx_ds"
    # ...and the WHY is echoed per blocked crate, so a CI reader sees the
    # cargo line that produced the classification, not just a name.
    # (No closing backtick in the pattern: for a PATH dependency cargo prints
    # `ring v0.0.0 (/abs/path/crates/ring)` before it closes the quote.)
    expect_blocked "darwin-cross-check/$sdk-blocked-member-shows-its-evidence" \
      "blocked: root — error: failed to run custom build command for \`$sdk v0.0.0" \
      "$here/darwin-cross-check.sh" --root "$fx_ds"
  done

  # REJECT: the SAME failing build script in a crate NOT named as an SDK crate
  # is a real failure. This is the fail-closed half of the classification.
  fx_do="$(darwin_fixture other-build-failure)"
  expect_reject_because "darwin-cross-check/non-sdk-build-failure-is-a-FAIL" \
    "not solely an SDK build-script failure" \
    "$here/darwin-cross-check.sh" --root "$fx_do"

  # REJECT: an SDK build-script failure must not MASK a real error. `root`
  # dev-depends on a panicking `ring` and carries a compile_error! in its lib;
  # under --all-targets both land in the same log. Presence-of-one-line called
  # this "blocked" and printed nothing.
  fx_dm="$(darwin_fixture devdep-sdk-plus-real-error)"
  expect_reject_because "darwin-cross-check/sdk-failure-does-not-mask-a-real-error" \
    "not solely an SDK build-script failure" \
    "$here/darwin-cross-check.sh" --root "$fx_dm"
  # (The `\[E…\]` alternative in the exclusivity regex is, like the tree
  # check, shadowed by the span-line check on this fixture: `error[E0425]`
  # always carries ` --> `, so removing the alternative survives (measured:
  # 45/45). Kept for the same reason; recorded as unobserved.)
  # ...and the co-occurrence is ASSERTED, not assumed: the printed log must
  # carry BOTH the real error and the SDK line, else this probe has quietly
  # become a duplicate of the plain compile-failure one (measured: on a fresh
  # target dir cargo cancels the pending build script once the lib fails; the
  # lines co-occur here only because `ring` sorts before `root` and its build
  # script is already compiled by the time `root` is checked).
  total=$((total+1))
  dm_out="$("$here/darwin-cross-check.sh" --root "$fx_dm" 2>&1 || true)"
  if printf '%s' "$dm_out" | grep -q 'undeclared_fn_real_darwin_error' && printf '%s' "$dm_out" | grep -Eq 'failed to run custom build command for `ring v'; then
    echo "neg-ok: [darwin-cross-check/masking-fixture-really-co-locates-both-errors] both the real error and the SDK line are in the log"; pass=$((pass+1))
  else
    echo "NEG-FAIL: [darwin-cross-check/masking-fixture-really-co-locates-both-errors] the two errors did not co-occur — the masking probe proves nothing: $dm_out"
  fi

  # REJECT: a member with NO SDK crate in its graph whose own source renders
  # cargo's sentence at column 0 (`compile_error!`) is a FAIL. Three of the
  # gate's corroborations refuse it INDEPENDENTLY -- the span line, the
  # exclusivity check (its `could not compile` line), the tree check -- so
  # dropping any one survives the suite (measured: 50/50 each) and dropping
  # all three is caught. Recorded rather than claimed one-by-one.
  fx_fk="$(darwin_fixture fake-cargo-line)"
  expect_reject_because "darwin-cross-check/a-rendered-diagnostic-quoting-cargo-is-not-blocked" \
    "not solely an SDK build-script failure" \
    "$here/darwin-cross-check.sh" --root "$fx_fk"

  # REJECT: a multi-line rendered diagnostic whose first line is cargo's
  # sentence, in a member that DOES have `ring` in its tree. (a) and (d) are
  # honestly satisfied; (c) refuses via `could not compile`; and (b) must
  # refuse too now that an error block runs to the next header rather than to
  # the whitespace-only continuation line rustc renders.
  fx_ml="$(darwin_fixture multiline-fake-line)"
  expect_reject_because "darwin-cross-check/a-multiline-rendered-diagnostic-is-not-blocked" \
    "not solely an SDK build-script failure" \
    "$here/darwin-cross-check.sh" --root "$fx_ml"

  # REJECT: a rustc that dies with NO diagnostic (the SIGKILL / OOM / ENOSPC
  # shape) leaves only `error: could not compile` beside the SDK line. An
  # exemption for that summary line called this "blocked". A `rustc` shim on
  # PATH that passes `--version`/`-vV` through and exits 1 silently for root's
  # lib reproduces it hermetically; must be a FAIL.
  fx_sr="$(darwin_fixture silent-rustc-death)"
  # The gate exports RUSTC from `rustup which rustc` (so a PATH rustc shim no
  # longer reaches cargo -- that is the config-door fix working). The hermetic
  # route is therefore a `rustup` shim whose `which rustc` names the fake:
  # `--version`/`-vV`/`--print` pass through; root's lib exits 1 silently.
  tmpD9="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpD9/bin"
  { printf '#!/usr/bin/env bash\n'; printf 'REAL_RUSTC=%q\n' "$(cd "$here/../.." && rustup which rustc)"; cat; } > "$tmpD9/bin/fake-rustc" <<'SHIM'
case " $* " in *" --version "*|*" -vV "*|*" -V "*|*" --print "*) exec "$REAL_RUSTC" "$@" ;; esac
case " $* " in *" --crate-name root "*) exit 1 ;; esac
exec "$REAL_RUSTC" "$@"
SHIM
  { printf '#!/usr/bin/env bash\n'; printf 'REAL_RUSTUP=%q\n' "$(command -v rustup)"; printf 'FAKE_RUSTC=%q\n' "$tmpD9/bin/fake-rustc"; cat; } > "$tmpD9/bin/rustup" <<'SHIM'
if [ "${1:-}" = which ] && [ "${2:-}" = rustc ]; then echo "$FAKE_RUSTC"; exit 0; fi
exec "$REAL_RUSTUP" "$@"
SHIM
  chmod +x "$tmpD9/bin/fake-rustc" "$tmpD9/bin/rustup"
  expect_reject_because "darwin-cross-check/silent-rustc-death-is-not-blocked" \
    "not solely an SDK build-script failure" \
    env REAL_RUSTC="$(cd "$here/../.." && rustup which rustc || { echo "harness: rustup which rustc failed" >&2; exit 1; })" REAL_RUSTUP="$(command -v rustup)" FAKE_RUSTC="$tmpD9/bin/fake-rustc" PATH="$tmpD9/bin:$PATH" \
    "$here/darwin-cross-check.sh" --root "$fx_sr"

  # REJECT: `--locked` is really passed. A lock file that predates a member
  # must be refused by cargo, and the gate must surface that as a FAIL. This is
  # caught by the gate's RESOLVING `cargo metadata --locked`, which runs in
  # every mode before any check. The per-member `cargo check --locked` behind
  # it is NOT inert (round 3 said it was): a build script can rewrite the lock
  # AFTER metadata resolved it, and only the check's own `--locked` refuses
  # that -- see `a-build-script-that-rewrites-the-lock...` below.
  fx_sl="$(darwin_fixture stale-lock)"
  expect_reject_because "darwin-cross-check/stale-lock-is-refused-by---locked" \
    "--locked was passed" \
    "$here/darwin-cross-check.sh" --root "$fx_sl" --check-inputs

  # ACCEPT, EVIDENCE PER CRATE: two members blocked by DIFFERENT SDK crates
  # must each be attributed to their own — an accumulating log (`>>`) would
  # carry a's `aws-lc-sys` line into b's classification.
  fx_2s="$(darwin_fixture two-sdk)"
  expect_blocked "darwin-cross-check/evidence-names-each-members-own-sdk-crate-a" \
    "blocked: a — error: failed to run custom build command for \`aws-lc-sys v0.0.0" \
    "$here/darwin-cross-check.sh" --root "$fx_2s"
  expect_blocked "darwin-cross-check/evidence-names-each-members-own-sdk-crate-b" \
    "blocked: b — error: failed to run custom build command for \`ring v0.0.0" \
    "$here/darwin-cross-check.sh" --root "$fx_2s"

  # REJECT: crate names are case-sensitive. A panicking build script in a
  # crate named `Ring` is not an SDK failure; a case-insensitive classifier
  # would call it one.
  fx_cs="$(darwin_fixture case-sdk)"
  expect_reject_because "darwin-cross-check/Ring-is-not-ring" \
    "not solely an SDK build-script failure" \
    "$here/darwin-cross-check.sh" --root "$fx_cs"

  # REJECT: cargo's SCHEDULER must not decide whether a real error exists.
  # `root` has a real error in its lib AND a dependency (`zdep`) that is still
  # unbuilt when `root` is checked; `ring`'s build script fails first. Without
  # `--keep-going` cargo cancels root's lib and the log holds only the SDK
  # line -- "blocked", `ok`, rc 0 (reviewer-measured, default parallelism and
  # again with CARGO_BUILD_JOBS=1 on the plain masking fixture).
  fx_ub="$(darwin_fixture unbuilt-dep-after)"
  # Under CARGO_BUILD_JOBS=1 as well, so the mutation kill is deterministic:
  # at default parallelism the scheduler sometimes compiles root's lib before
  # ring's build script fails, and the mutant survives (measured 3 of 5).
  expect_reject_because "darwin-cross-check/a-cancelled-lib-compile-does-not-hide-a-real-error" \
    "not solely an SDK build-script failure" \
    env CARGO_BUILD_JOBS=1 "$here/darwin-cross-check.sh" --root "$fx_ub"
  expect_reject_because "darwin-cross-check/a-cancelled-lib-compile-does-not-hide-a-real-error-jobs1" \
    "not solely an SDK build-script failure" \
    env CARGO_BUILD_JOBS=1 "$here/darwin-cross-check.sh" --root "$fx_dm"

  # ACCEPT: a spanned WARNING in a blocked member's graph is not an error.
  # The span test is scoped to error blocks; whole-log it turned this into a
  # FAIL that invited loosening the classifier.
  fx_wb="$(darwin_fixture warning-in-blocked)"
  expect_blocked_count "darwin-cross-check/a-warning-in-a-blocked-members-graph-is-still-blocked" \
    "cross-checked " 1 \
    "$here/darwin-cross-check.sh" --root "$fx_wb"

  # ACCEPT, AND THE FILE-CONFIGURED WRAPPER WAS NEVER INVOKED: `.cargo/
  # config.toml` `[build] rustc-wrapper` is the seventh compiler-substitution
  # door; env beats config, and the gate exports an empty RUSTC_WRAPPER. The
  # shim logs every invocation; the log must not exist afterwards.
  fx_cw="$(darwin_fixture config-wrapper)"
  expect_accept "darwin-cross-check/config-file-rustc-wrapper-is-neutralised" \
    "cross-checked 2 crates" \
    "$here/darwin-cross-check.sh" --root "$fx_cw"
  # LIVENESS first: a plain `cargo check` in the fixture (no exports) MUST go
  # through the config wrapper, else a green below would only mean the config
  # never took. Then the log is cleared and the gate must leave it absent --
  # not "no compiles", ABSENT: with the config written after the fixture's own
  # lockfile generation, the gate is the only thing that could write it.
  total=$((total+1))
  ( cd "$fx_cw" && cargo check --locked >/dev/null 2>&1 || true )
  if grep -q -- '--crate-name' "$fx_cw/wrapper.log" 2>/dev/null; then
    echo "neg-ok: [darwin-cross-check/config-file-wrapper-fixture-is-live] a plain cargo check went through the config wrapper ($(grep -c -- '--crate-name' "$fx_cw/wrapper.log") compiles)"; pass=$((pass+1))
  else
    echo "NEG-FAIL: [darwin-cross-check/config-file-wrapper-fixture-is-live] the config wrapper was never invoked by a plain cargo check — the fixture is inert and the probe below proves nothing"
  fi
  rm -f "$fx_cw/wrapper.log"; rm -rf "$fx_cw/target"
  "$here/darwin-cross-check.sh" --root "$fx_cw" >/dev/null 2>&1 || true
  total=$((total+1))
  if [ ! -e "$fx_cw/wrapper.log" ]; then
    echo "neg-ok: [darwin-cross-check/config-file-rustc-wrapper-never-ran-under-the-gate] no wrapper.log after the gate run"; pass=$((pass+1))
  else
    echo "NEG-FAIL: [darwin-cross-check/config-file-rustc-wrapper-never-ran-under-the-gate] the config-file wrapper ran under the gate: $(tr '\n' ';' < "$fx_cw/wrapper.log" | cut -c1-120)"
  fi

  # REJECT: a member whose every target is gated by `required-features` is
  # a cargo NO-OP ("no targets matched"), exit 0, nothing compiled. It was
  # counted as checked. Now a member counts only if cargo emitted a
  # compiler artifact attributed to its manifest.
  fx_rf="$(darwin_fixture required-features-bin)"
  expect_reject_because "darwin-cross-check/a-member-with-no-matched-target-is-not-counted-as-checked" \
    "compiled NO aarch64-apple-darwin target of it" \
    "$here/darwin-cross-check.sh" --root "$fx_rf"

  # REJECT ×2: the PROFILE must not forge conditional compilation. An error
  # behind cfg(debug_assertions) vanished under `[profile.dev]
  # debug-assertions = false` and under CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false;
  # the gate pins the profile with `--config`, which outranks both.
  fx_da="$(darwin_fixture debug-assertions-gated)"
  expect_reject_because "darwin-cross-check/profile-env-cannot-forge-debug-assertions" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    env CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false "$here/darwin-cross-check.sh" --root "$fx_da"
  fx_dac="$(darwin_fixture debug-assertions-config)"
  expect_reject_because "darwin-cross-check/profile-config-cannot-forge-debug-assertions" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    "$here/darwin-cross-check.sh" --root "$fx_dac"

  # REJECT ×2: per-package profile overrides -- in config and in the ROOT
  # MANIFEST -- reach workspace members that cargo's `"*"` glob does not; a
  # named pin per member closes both.
  fx_ppc="$(darwin_fixture pkg-profile-config)"
  expect_reject_because "darwin-cross-check/per-package-profile-in-config-cannot-forge-debug-assertions" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    "$here/darwin-cross-check.sh" --root "$fx_ppc"
  fx_ppm="$(darwin_fixture pkg-profile-manifest)"
  expect_reject_because "darwin-cross-check/per-package-profile-in-the-manifest-cannot-forge-debug-assertions" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    "$here/darwin-cross-check.sh" --root "$fx_ppm"

  # REJECT ×2: RUSTC_BOOTSTRAP unlocks nightly gates on the pinned stable
  # compiler; refused from the environment, neutralised from `[env]`.
  fx_bs="$(darwin_fixture bootstrap-gated)"
  expect_reject_because "darwin-cross-check/RUSTC_BOOTSTRAP-is-refused" \
    "RUSTC_BOOTSTRAP is set" \
    env RUSTC_BOOTSTRAP=1 "$here/darwin-cross-check.sh" --root "$fx_bs"
  fx_bsc="$(darwin_fixture bootstrap-config)"
  expect_reject_because "darwin-cross-check/config-env-RUSTC_BOOTSTRAP-cannot-unlock-nightly-gates" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    "$here/darwin-cross-check.sh" --root "$fx_bsc"

  # REJECT ×2: the PANIC STRATEGY is conditional compilation. An error behind
  # cfg(panic = "unwind") vanished under `[profile.dev] panic = "abort"` and
  # under CARGO_PROFILE_DEV_PANIC=abort; the gate pins unwind.
  fx_pg="$(darwin_fixture panic-gated)"
  expect_reject_because "darwin-cross-check/profile-env-cannot-forge-the-panic-strategy" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    env CARGO_PROFILE_DEV_PANIC=abort "$here/darwin-cross-check.sh" --root "$fx_pg"
  fx_pc="$(darwin_fixture panic-config)"
  expect_reject_because "darwin-cross-check/profile-config-cannot-forge-the-panic-strategy" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    "$here/darwin-cross-check.sh" --root "$fx_pc"

  # ACCEPT, host-only reported: a proc-macro member is compiled for the HOST;
  # it must be neither counted as darwin-checked nor blocked, and named. The
  # kind check classifies it before the counter runs, so the counter's own
  # `/<triple>/` filename filter is defence in depth behind it -- the
  # mutation "drop the filename filter" survives (measured: 75/75). Recorded,
  # not claimed; the filter stays because it is independent of how the kind
  # is declared.
  fx_pm="$(darwin_fixture proc-macro-member)"
  expect_reported_count "darwin-cross-check/a-proc-macro-member-is-not-counted-as-darwin-checked" \
    "cross-checked " 1 \
    "$here/darwin-cross-check.sh" --root "$fx_pm"
  expect_accept "darwin-cross-check/a-proc-macro-member-is-reported-host-only" \
    "host-only (proc-macro): leaf" \
    "$here/darwin-cross-check.sh" --root "$fx_pm"

  # The ORACLE must not count a host-only member either (codex r8: it predicted
  # two checked on this fixture; the gate correctly says one).
  total=$((total+1))
  pm_oracle="$( (cd "$fx_pm" && cargo metadata --format-version 1 --locked --filter-platform aarch64-apple-darwin 2>/dev/null) | python3 -c "$darwin_oracle_py" "$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')" 2>/dev/null)" || pm_oracle="walk failed"
  if [ "${pm_oracle%% *}" = 1 ]; then
    echo "pos-ok: [darwin-cross-check/the-oracle-excludes-host-only-members] oracle predicts 1 on the proc-macro fixture, as the gate reports"; pass=$((pass+1))
  else
    echo "POS-FAIL: [darwin-cross-check/the-oracle-excludes-host-only-members] oracle predicts '$pm_oracle' on the proc-macro fixture; the gate reports 1"
  fi

  # REJECT ×2 (codex r8): a NAMED per-package override for a dependency that is
  # NOT a workspace member outranks the `"*"` pin, and the member-named pins
  # never mentioned it -- measured `ok` on both gates, both spellings. Every
  # resolved package is now pinned by name through one `--config` file.
  fx_dpc="$(darwin_fixture dep-profile-config)"
  expect_reject_because "darwin-cross-check/named-profile-override-for-a-non-member-dependency-in-config-cannot-forge-debug-assertions" \
    "cross-check failed for aarch64-apple-darwin: member 'root'" \
    "$here/darwin-cross-check.sh" --root "$fx_dpc"
  fx_dpm="$(darwin_fixture dep-profile-manifest)"
  expect_reject_because "darwin-cross-check/named-profile-override-for-a-non-member-dependency-in-the-manifest-cannot-forge-debug-assertions" \
    "cross-check failed for aarch64-apple-darwin: member 'root'" \
    "$here/darwin-cross-check.sh" --root "$fx_dpm"

  # REJECT: cargo's OTHER nightly switch. `__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_
  # USE_THIS=nightly` unlocks `[unstable] profile-rustflags`, and `[profile.dev]
  # rustflags` is a fourth rustflags source that outranks the pinned encoded
  # value (measured: this fixture printed `ok`). Refused like RUSTC_BOOTSTRAP.
  # The fixture carries the live config, so "drop the token" turns this probe
  # into a green `ok` rather than a refusal for some other reason.
  fx_co="$(darwin_fixture channel-override)"
  expect_reject_because "darwin-cross-check/cargo-channel-override-is-refused" \
    "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS is set" \
    env __CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly "$here/darwin-cross-check.sh" --root "$fx_co"

  # ACCEPT, STILL BLOCKED (codex r8): `[term] progress.when = "always"` in the
  # checked root's config makes cargo write a carriage return before `error:`,
  # which the column-0 anchor misses -- a correctly blocked member became a
  # FAIL. Env outranks config; the gate exports CARGO_TERM_PROGRESS_WHEN=never.
  fx_prg="$(darwin_fixture progress-config)"
  expect_blocked_count "darwin-cross-check/config-progress-bar-does-not-break-classification" \
    "cross-checked " 1 \
    "$here/darwin-cross-check.sh" --root "$fx_prg"

  # REJECT: one extra pass per feature the member declares. `-p leaf` from
  # Linux resolves `maknae-authz-basic` with NO features (its only enabler is
  # kernel's dev-dep, and kernel is SDK-blocked there), so feature-gated code
  # was cross-checked by nothing. The FAIL must NAME the feature; the clean
  # variant proves the pass is COUNTED (kills an empty loop, and a loop that
  # runs but never reports).
  fx_fg="$(darwin_fixture feature-gated-linux-item)"
  expect_reject_because "darwin-cross-check/a-linux-only-item-behind-a-declared-feature-is-caught-by-the-feature-pass" \
    "member 'leaf' with feature 'dark'" \
    "$here/darwin-cross-check.sh" --root "$fx_fg"
  fx_cf="$(darwin_fixture clean-with-feature)"
  expect_reported_count "darwin-cross-check/declared-features-are-counted-as-passes" \
    "aarch64-apple-darwin + " 1 \
    "$here/darwin-cross-check.sh" --root "$fx_cf"

  # REJECT: WARM-DIR REPLAY. The pins bind only what cargo RECOMPILES. Prime
  # the gate-owned target dir with the bootstrap fixture compiled under
  # RUSTC_BOOTSTRAP=1 -- same target, same (default) profile, so the
  # fingerprint matches -- and a gate that does not wipe replays the unit as
  # fresh and prints `ok` (measured: the no-wipe mutant does exactly that).
  # The gate wipes `target/darwin-cross-check` at start, so this must FAIL.
  # The priming is checked first: an unprimed dir would make the FAIL below
  # prove nothing about the wipe.
  fx_wr="$(darwin_fixture bootstrap-gated)"
  primer_rc=0
  ( cd "$fx_wr" && for pm in leaf root; do
      CARGO_TARGET_DIR="$fx_wr/target/darwin-cross-check" RUSTC_BOOTSTRAP=1 RUSTC="$(rustup which rustc)" RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER='' CARGO_ENCODED_RUSTFLAGS='' CARGO_TERM_COLOR=never \
        cargo check --locked --keep-going -p "$pm" --target aarch64-apple-darwin --all-targets --color never >/dev/null 2>&1 || exit 1
    done ) || primer_rc=$?
  total=$((total+1))
  # The priming must have SUCCEEDED and left leaf's darwin rmeta: cargo creates
  # the directory layout before compiling, so "the dir exists" passed on a
  # failed primer too (both reviewers, round 9).
  if [ "$primer_rc" -eq 0 ] && ls "$fx_wr"/target/darwin-cross-check/aarch64-apple-darwin/debug/deps/libleaf-*.rmeta >/dev/null 2>&1; then
    echo "pos-ok: [darwin-cross-check/the-replay-primer-produced-a-darwin-unit] bootstrap-on primer succeeded and left leaf's darwin rmeta"; pass=$((pass+1))
  else
    echo "POS-FAIL: [darwin-cross-check/the-replay-primer-produced-a-darwin-unit] primer rc=$primer_rc or no leaf rmeta — the replay probe below would prove nothing"
  fi
  expect_reject_because "darwin-cross-check/a-primed-target-dir-is-not-replayed" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    "$here/darwin-cross-check.sh" --root "$fx_wr"

  # REJECT ×2 (codex r9 and the fresh-context reviewer, independently): the
  # round-10 feature pass classified "blocked" from ONE grep -- none of
  # (b)/(c)/(d) -- and the round-3 impersonation and masking shapes came back
  # on that path. One classifier now serves every pass, with (d) corroborated
  # under the pass's own feature selection.
  fx_ff="$(darwin_fixture feature-fake)"
  expect_reject_because "darwin-cross-check/an-impersonated-sdk-line-behind-a-feature-is-a-FAIL" \
    "member 'root' with feature 'dark'" \
    "$here/darwin-cross-check.sh" --root "$fx_ff"
  fx_fr="$(darwin_fixture feature-real)"
  expect_reject_because "darwin-cross-check/a-real-error-beside-an-sdk-block-on-a-feature-pass-is-a-FAIL" \
    "member 'root' with feature 'dark'" \
    "$here/darwin-cross-check.sh" --root "$fx_fr"
  # ACCEPT, REPORTED, NOT COUNTED: a feature pass that is genuinely SDK-blocked
  # is named on the OK line and is not a pass -- a member whose feature code
  # was never compiled is not fully checked.
  fx_fb="$(darwin_fixture feature-blocked)"
  expect_blocked "darwin-cross-check/a-blocked-feature-pass-is-reported" \
    "feature pass(es) SDK-blocked: devshim/sdk root/dark" \
    "$here/darwin-cross-check.sh" --root "$fx_fb"
  expect_blocked_count "darwin-cross-check/a-blocked-feature-pass-is-not-counted-as-a-pass" \
    "aarch64-apple-darwin + " 0 \
    "$here/darwin-cross-check.sh" --root "$fx_fb"
  # REJECT: a proc-macro member's feature passes still run (for the host) and
  # still FAIL; only their SUCCESS is kept out of the darwin count.
  fx_pf="$(darwin_fixture proc-macro-feature)"
  expect_reject_because "darwin-cross-check/a-proc-macro-member-feature-error-is-a-FAIL" \
    "member 'leaf' with feature 'dark'" \
    "$here/darwin-cross-check.sh" --root "$fx_pf"
  # ACCEPT: `[build] build-dir` in the tree's config split cargo's artifacts
  # away from the exact-prefix filter and made a clean member a FAIL (codex
  # r9). The gate runs from OUTSIDE the tree, so the tree's config is not read.
  fx_bd="$(darwin_fixture build-dir-config)"
  expect_reported_count "darwin-cross-check/tree-config-build-dir-is-not-read" \
    "cross-checked " 2 \
    "$here/darwin-cross-check.sh" --root "$fx_bd"
  # REJECT ×2: THE TWO MECHANISMS, each observed by a knob nothing else pins.
  # (1) A caller's variable that a BUILD SCRIPT reads (`MAKNAE_FORGE=1` makes
  # leaf's build.rs forge `cfg(forged)`, which removes the Linux-only use) is
  # on no refusal list -- the class the refusals cannot enumerate. Only the
  # allowlist keeps it out; "run cargo in the caller's environment" turns
  # this into a green `ok` (measured). (2) The same variable from the tree's
  # `[env]` table: cargo delivers `[env]` to build scripts, no `--config` pin
  # names it, and only the outside cwd keeps the file unread -- "run from
  # inside the tree" turns this into `ok` (measured). (An earlier version of
  # these probes used `CARGO_BUILD_RUSTFLAGS` and `[build] build-dir`, both
  # ALSO covered by an explicit pin, so both survived removal of the
  # mechanism they claimed to observe.)
  fx_ue="$(darwin_fixture env-build-script)"
  expect_reject_because "darwin-cross-check/a-caller-variable-does-not-reach-a-build-script" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    env MAKNAE_FORGE=1 "$here/darwin-cross-check.sh" --root "$fx_ue"
  fx_ce="$(darwin_fixture config-env-build-script)"
  expect_reject_because "darwin-cross-check/the-tree-config-env-table-does-not-reach-a-build-script" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    "$here/darwin-cross-check.sh" --root "$fx_ce"
  # ...and with TMPDIR pointing INSIDE the tree (codex r10: the "outside" cwd
  # was a mktemp under TMPDIR, so this fixture went `ok`). The cwd now lives
  # under $HOME and is canonicalised against the root.
  mkdir -p "$fx_ce/tmpinside"
  expect_reject_because "darwin-cross-check/the-tree-config-is-not-read-even-with-TMPDIR-inside-the-tree" \
    "cross-check failed for aarch64-apple-darwin: member 'leaf'" \
    env TMPDIR="$fx_ce/tmpinside" "$here/darwin-cross-check.sh" --root "$fx_ce"

  # REJECT (codex r10): the compiler used to be resolved from the ROOT under
  # the CALLER's environment, before the pin existed -- a rustup directory
  # override selected 1.94.1 while the proxy, asked under the pin, said 1.98.1.
  # Now resolved under the pinned environment, and the resolved BINARY is
  # version-checked. A `rustup` shim whose `which rustc` names a rustc that
  # compiles with the real one but REPORTS 1.0.0 must be a mismatch FAIL.
  tmpD12="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpD12/bin"
  { printf '#!/usr/bin/env bash\n'; printf 'REAL_RUSTC=%q\n' "$(cd "$here/../.." && rustup which rustc)"; cat; } > "$tmpD12/bin/lying-rustc" <<'SHIM'
case " $* " in *" --version "*|*" -vV "*|*" -V "*) exec "$REAL_RUSTC" "$@" | sed 's/^rustc [0-9.]*/rustc 1.0.0/' ;; esac
exec "$REAL_RUSTC" "$@"
SHIM
  { printf '#!/usr/bin/env bash\n'; printf 'REAL_RUSTUP=%q\nLYING=%q\n' "$(command -v rustup)" "$tmpD12/bin/lying-rustc"; cat; } > "$tmpD12/bin/rustup" <<'SHIM'
if [ "${1:-}" = which ] && [ "${2:-}" = rustc ]; then echo "$LYING"; exit 0; fi
exec "$REAL_RUSTUP" "$@"
SHIM
  chmod +x "$tmpD12/bin/lying-rustc" "$tmpD12/bin/rustup"
  expect_reject_because "darwin-cross-check/the-resolved-rustc-binary-is-version-checked" \
    "toolchain mismatch" \
    env PATH="$tmpD12/bin:$PATH" "$here/darwin-cross-check.sh" --root "$fx_dc" --check-inputs

  # REJECT (codex r10): a feature can REMOVE the SDK dependency; a blocked
  # base pass used to `continue` past every feature pass.
  fx_pt="$(darwin_fixture portable-feature)"
  expect_reject_because "darwin-cross-check/a-feature-that-removes-the-sdk-dependency-is-still-checked" \
    "member 'root' with feature 'portable'" \
    "$here/darwin-cross-check.sh" --root "$fx_pt"

  # REJECT + PERSIST: one run per checkout. A pre-existing lock refuses the
  # run -- and the refused contender must NOT remove the owner's lock (codex
  # r10: an unconditional cleanup did, and the next contender walked in).
  mkdir -p "$fx_dc/target/darwin-cross-check.lock"
  expect_reject_because "darwin-cross-check/a-held-lock-refuses-a-second-run" \
    "another run holds" \
    "$here/darwin-cross-check.sh" --root "$fx_dc" --check-inputs
  total=$((total+1))
  if [ -d "$fx_dc/target/darwin-cross-check.lock" ]; then
    echo "pos-ok: [darwin-cross-check/a-refused-contender-leaves-the-owners-lock] lock still held after the refusal"; pass=$((pass+1))
  else
    echo "POS-FAIL: [darwin-cross-check/a-refused-contender-leaves-the-owners-lock] the refused run removed a lock it never owned"
  fi
  rmdir "$fx_dc/target/darwin-cross-check.lock"
  # REJECT, INTRA-RUN (codex r9): an EARLIER member's build script re-plants
  # bootstrap-primed units for a LATER member after the start-of-run wipe.
  # `a-builder`'s build.rs untars z-victim's primed darwin units into the
  # gate-owned dir; the gate wipes before EVERY pass, so z-victim recompiles
  # cold and fails E0554. (A wipe at start only: `ok`, two checked -- measured.)
  fx_ir="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$fx_ir/crates/a-builder/src" "$fx_ir/crates/z-victim/src"
  cp "$here/../../rust-toolchain.toml" "$fx_ir/rust-toolchain.toml"
  printf '[workspace]\nresolver = "3"\nmembers = ["crates/a-builder", "crates/z-victim"]\n' > "$fx_ir/Cargo.toml"
  printf '[package]\nname = "a-builder"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n' > "$fx_ir/crates/a-builder/Cargo.toml"; : > "$fx_ir/crates/a-builder/src/lib.rs"
  printf '[package]\nname = "z-victim"\nversion = "0.0.0"\nedition = "2021"\n' > "$fx_ir/crates/z-victim/Cargo.toml"
  printf '#![cfg_attr(target_os = "macos", feature(never_type))]\npub fn x() {}\n' > "$fx_ir/crates/z-victim/src/lib.rs"
  printf 'fn main() {}\n' > "$fx_ir/crates/a-builder/build.rs"
  ( cd "$fx_ir" && cargo generate-lockfile --offline >/dev/null 2>&1 )
  ir_rc=0
  ( cd "$fx_ir" && CARGO_TARGET_DIR="$fx_ir/target/darwin-cross-check" RUSTC_BOOTSTRAP=1 RUSTC="$(rustup which rustc)" RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER='' CARGO_ENCODED_RUSTFLAGS='' CARGO_TERM_COLOR=never \
      cargo check --locked --keep-going -p z-victim --target aarch64-apple-darwin --all-targets --color never >/dev/null 2>&1 \
    && tar -cf units.tar -C target/darwin-cross-check aarch64-apple-darwin && rm -rf target ) || ir_rc=$?
  total=$((total+1))
  if [ "$ir_rc" -eq 0 ] && [ -s "$fx_ir/units.tar" ]; then
    echo "pos-ok: [darwin-cross-check/the-intra-run-primer-produced-a-darwin-unit] bootstrap-on units archived"; pass=$((pass+1))
  else
    echo "POS-FAIL: [darwin-cross-check/the-intra-run-primer-produced-a-darwin-unit] primer rc=$ir_rc — the injection probe below would prove nothing"
  fi
  cat > "$fx_ir/crates/a-builder/build.rs" <<'RS'
fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let dir = root.join("target/darwin-cross-check");
    let _ = std::fs::create_dir_all(&dir);
    let st = std::process::Command::new("tar").args(["-xf"]).arg(root.join("units.tar")).arg("-C").arg(&dir).status().unwrap();
    assert!(st.success());
}
RS
  expect_reject_because "darwin-cross-check/a-build-script-cannot-replant-cached-units-for-a-later-member" \
    "cross-check failed for aarch64-apple-darwin: member 'z-victim'" \
    "$here/darwin-cross-check.sh" --root "$fx_ir"

  # REJECT, NOT MUTE: an artifact counter that dies must produce a FAIL. A
  # `python3` shim that fails only when invoked as `python3 -` (the counter's
  # shape) and passes every other call through.
  tmpD11="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpD11/bin"
  { printf '#!/usr/bin/env bash\n'; printf 'REAL_PY=%q\n' "$(command -v python3)"; cat; } > "$tmpD11/bin/python3" <<'SHIM'
if [ "${1:-}" = - ]; then echo "simulated counter crash" >&2; exit 3; fi
exec "$REAL_PY" "$@"
SHIM
  chmod +x "$tmpD11/bin/python3"
  expect_reject_because "darwin-cross-check/a-dying-artifact-counter-is-not-mute" \
    "the artifact counter failed" \
    env REAL_PY="$(command -v python3)" PATH="$tmpD11/bin:$PATH" "$here/darwin-cross-check.sh" --root "$fx_dc"

  # ACCEPT: inherited colour must not break the classifier. With
  # CARGO_TERM_COLOR=always the ANSI escapes made a correctly blocked member a
  # FAIL; the gate pins colour off.
  fx_col="$(darwin_fixture sdk-blocked ring)"
  expect_blocked_count "darwin-cross-check/inherited-colour-does-not-break-classification" \
    "cross-checked " 1 \
    env CARGO_TERM_COLOR=always "$here/darwin-cross-check.sh" --root "$fx_col"

  # REJECT: `--locked` on the CHECK itself is observable after all. `leaf`'s
  # build script deletes the workspace Cargo.lock; the resolving metadata call
  # already ran, so only the per-member `cargo check --locked` can refuse the
  # member checked after `leaf` — without it cargo would regenerate the lock
  # and pass. (Round-3 called this mutation inert; codex built this fixture.)
  fx_ld="$(darwin_fixture lock-deleting-build)"
  expect_reject_because "darwin-cross-check/a-build-script-that-rewrites-the-lock-is-caught-by-the-checks-own---locked" \
    "--locked was passed" \
    "$here/darwin-cross-check.sh" --root "$fx_ld"

  # REJECT: every member blocked -> refuse. (Only member depends on a
  # panicking `ring`; `ring` itself fails its own build script.)
  tmpD8="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$tmpD8/crates/only/src" "$tmpD8/crates/ring/src"
  printf '[workspace]\nresolver = "3"\nmembers = ["crates/only", "crates/ring"]\n' > "$tmpD8/Cargo.toml"
  cp "$here/../../rust-toolchain.toml" "$tmpD8/rust-toolchain.toml"
  printf '[package]\nname = "ring"\nversion = "0.0.0"\nedition = "2021"\nbuild = "build.rs"\n' > "$tmpD8/crates/ring/Cargo.toml"
  printf 'fn main() { panic!("needs SDK"); }\n' > "$tmpD8/crates/ring/build.rs"; : > "$tmpD8/crates/ring/src/lib.rs"
  printf '[package]\nname = "only"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\nring = { path = "../ring" }\n' > "$tmpD8/crates/only/Cargo.toml"; : > "$tmpD8/crates/only/src/lib.rs"
  ( cd "$tmpD8" && cargo generate-lockfile --offline >/dev/null 2>&1 )
  expect_reject_because "darwin-cross-check/all-members-blocked-is-refused" \
    "every member is SDK-blocked" \
    "$here/darwin-cross-check.sh" --root "$tmpD8"

  # ACCEPT, CROSS-CHECKED ON THE REAL REPO, BY A DIFFERENT MECHANISM. The gate
  # lets cargo decide per member. The oracle is a metadata walk: from each
  # member follow its own normal+dev edges, then normal edges only (a
  # dependency's dev-deps are not inherited; build-deps compile for the HOST),
  # over `--filter-platform aarch64-apple-darwin`; a member reaching an SDK
  # crate is expected blocked. It FAILS CLOSED: a metadata error is a
  # POS-FAIL, never "no SDK found". On a darwin host the gate blocks nothing,
  # so the oracle's expected count is all members there and members-minus-
  # blocked elsewhere. The two disagree exactly where the derivation was wrong
  # (a build-dep on ring; a dep's dev-dep on ring; a sibling-enabled feature;
  # a proc-macro dep on ring, which cargo compiles for the HOST)
  # -- none of which the repo has today; if one appears, this probe surfaces
  # the disagreement for a human instead of either side quietly winning.
  oracle_out="$(cd "$here/../.." && cargo metadata --format-version 1 --locked --filter-platform aarch64-apple-darwin 2>/dev/null)" || oracle_out=""
  if [ -z "$oracle_out" ]; then
    total=$((total+1)); echo "POS-FAIL: [darwin-cross-check/real-repo-count-matches-the-oracle] the oracle's cargo metadata failed — refusing to guess"
  else
    host_triple="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
    if ! darwin_expected="$(printf '%s' "$oracle_out" | python3 -c "$darwin_oracle_py" "$host_triple")"; then
      # The walk itself failed: a POS-FAIL, never a mute death of the suite.
      total=$((total+1)); echo "POS-FAIL: [darwin-cross-check/real-repo-count-matches-the-oracle] the oracle walk failed — refusing to guess"
    else
      # ONE cold run of the real repo (~2.5 min on Apple Silicon), BOTH fields
      # checked against the oracle: `cross-checked N` and `+ M feature pass(es)`.
      # (Two expect_reported_count calls would run the gate twice for nothing.)
      total=$((total+1))
      if oracle_run="$("$here/darwin-cross-check.sh" --root "$here/../.." 2>&1)"; then
        got_n="$(printf '%s' "$oracle_run" | sed -n 's/.*cross-checked \([0-9][0-9]*\).*/\1/p' | head -1)"
        got_f="$(printf '%s' "$oracle_run" | sed -n 's/.*aarch64-apple-darwin + \([0-9][0-9]*\).*/\1/p' | head -1)"
        if [ "$got_n" = "${darwin_expected%% *}" ] && [ "$got_f" = "${darwin_expected##* }" ]; then
          echo "pos-ok: [darwin-cross-check/real-repo-counts-match-the-oracle] gate reports $got_n checked + $got_f feature passes (independently derived: ${darwin_expected%% *} + ${darwin_expected##* })"; pass=$((pass+1))
        else
          echo "POS-FAIL: [darwin-cross-check/real-repo-counts-match-the-oracle] gate reports '$got_n' checked + '$got_f' feature passes but the oracle derives ${darwin_expected%% *} + ${darwin_expected##* } — the gate is walking a different set than it should: $oracle_run"
        fi
      else
        echo "POS-FAIL: [darwin-cross-check/real-repo-counts-match-the-oracle] gate rejected the real repo: $(printf '%s' "$oracle_run" | tail -3)"
      fi
    fi
  fi
  darwin_block_ran=$((total - darwin_block_total_before))
  total=$((total+1))
  if [ "$darwin_block_ran" -eq "$darwin_block_probes" ]; then
    echo "pos-ok: [darwin-cross-check/skip-count-matches-the-block] $darwin_block_ran probes ran, constant says $darwin_block_probes"; pass=$((pass+1))
  else
    echo "POS-FAIL: [darwin-cross-check/skip-count-matches-the-block] $darwin_block_ran probes ran but darwin_block_probes=$darwin_block_probes — fix the constant (it is what the skip line reports on hosts without the target)"
  fi
else
  # The skip count feeds the summary line CONTRIBUTING tells readers to
  # compare; `darwin_block_probes` above is checked against reality on every
  # host that runs the block.
  # +1: the self-check probe itself is counted into $total when the block runs
  # and is therefore also skipped here.
  skipped=$((skipped+darwin_block_probes+1)); echo "skip: [darwin-cross-check/<$((darwin_block_probes+1)) check probes>] aarch64-apple-darwin target not installed (rustup target add aarch64-apple-darwin)"
fi
# ---- scratch-leak controls ---------------------------------------------------
# #302: the gates leaked mktemp scratch — 17,667 trees (1.5 GiB) had accumulated
# in /tmp since Aug 30 on the maintainer's host. That is not housekeeping: the
# volume filled, every `cargo mutants` scratch build then failed with
# `No space left on device`, cargo-mutants classifies a mutant that fails to
# BUILD as `unviable`, and the run exited 0 — so the zero-missed contract passed
# having tested nothing (#301). A GATE THAT CANNOT CLEAN UP AFTER ITSELF
# EVENTUALLY DISABLES A DIFFERENT GATE.
#
# Each check below runs a gate with a PRIVATE, empty TMPDIR and requires it
# empty afterwards. Without them the leak returns the next time a probe is
# added, silently, exactly as it arrived.
expect_no_leak() { # <label> <cmd...> — the gate must leave its TMPDIR as it found it
  local label="$1"; shift; total=$((total+1))
  local td n
  td="$(mktemp -d -p "$NC_TMP")"
  TMPDIR="$td" "$@" >/dev/null 2>&1 || true
  n="$(find "$td" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$n" -eq 0 ]; then
    echo "pos-ok: [$label] gate left no scratch behind"; pass=$((pass+1))
  else
    echo "POS-FAIL: [$label] gate leaked $n scratch entr(y|ies) into its TMPDIR (#302): $(find "$td" -mindepth 1 -maxdepth 1 | head -3 | tr '\n' ' ')"
  fi
}

# The control on the control: a script that DOES leak must be caught, or the
# checks above are satisfied by a helper that can only ever print pos-ok.
leaker="$NC_TMP/leaker.sh"
printf '#!/bin/sh\nmktemp -d >/dev/null\nmktemp >/dev/null\nexit 0\n' > "$leaker"
chmod +x "$leaker"
total=$((total+1))
leak_td="$(mktemp -d -p "$NC_TMP")"
TMPDIR="$leak_td" "$leaker" >/dev/null 2>&1 || true
if [ "$(find "$leak_td" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" -eq 2 ]; then
  echo "neg-ok: [leak-check/self-test] the leak check sees a deliberate leaker"; pass=$((pass+1))
else
  echo "NEG-FAIL: [leak-check/self-test] a script that leaked two entries was not observed — the leak checks below prove nothing"
fi

expect_no_leak "leak/p1-manifest-lint"        "$here/p1-manifest-lint.sh"
expect_no_leak "leak/verb-vocabulary-drift"   "$here/verb-vocabulary-drift.sh"
expect_no_leak "leak/build-invocation-lint"   "$here/build-invocation-lint.sh"
expect_no_leak "leak/config-disclosure-drift" "$here/config-disclosure-drift.sh"
expect_no_leak "leak/std-fs-drift"            "$here/std-fs-drift.sh"
expect_no_leak "leak/external-authority-lint" "$here/external-authority-lint.sh"
expect_no_leak "leak/isolation-contract-lint" "$here/isolation-contract-lint.sh"
expect_no_leak "leak/p2-invert-tree"          "$here/p2-invert-tree.sh"
expect_no_leak "leak/feature-resolution-pin"  "$here/feature-resolution-pin.sh"
expect_no_leak "leak/packaged-binaries"       "$here/packaged-binaries.sh"

# ---- mutation-oracle: the mutation run's oracle beyond its exit status -------
# #301: an all-unviable `cargo mutants` run exits 0, so coverage-tiers.sh — whose
# only oracle was that status — passed the zero-missed contract having tested
# NOTHING. These probe the two halves of the replacement against crafted
# fixtures, so the checks themselves are shown to fire without a 45-minute
# mutation run.
mo="$here/mutation-oracle.sh"

# JUDGE: a run that measured nothing must be refused, however it exited.
mo_none="$(mktemp -d -p "$NC_TMP")"
printf '{"total_mutants": 41, "missed": 0, "caught": 0, "timeout": 0, "unviable": 41}\n' \
  > "$mo_none/outcomes.json"
expect_reject_because "mutation-oracle/all-unviable-measured-nothing" "ZERO viable" \
  bash "$mo" judge "$mo_none" maknae-kernel

# JUDGE: an environment failure is NOT unviability. This is the exact log line
# from the live incident, so the signature is the observed one and not a guess.
mo_enospc="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$mo_enospc/log"
printf '{"total_mutants": 41, "missed": 0, "caught": 31, "timeout": 0, "unviable": 10}\n' \
  > "$mo_enospc/outcomes.json"
printf 'error: incremental compilation: could not create session directory lock file: No space left on device (os error 28)\n' \
  > "$mo_enospc/log/crates__maknae-kernel__src__egress.rs_line_359_col_35.log"
expect_reject_because "mutation-oracle/enospc-is-not-unviability" "ENVIRONMENT failure" \
  bash "$mo" judge "$mo_enospc" maknae-kernel

# JUDGE: no outcomes.json at all — the run cannot be judged, so it is refused
# rather than assumed fine (the #301 failure mode is a MISSING measurement).
mo_empty="$(mktemp -d -p "$NC_TMP")"
expect_reject_because "mutation-oracle/no-outcomes-cannot-be-judged" "wrote no outcomes.json" \
  bash "$mo" judge "$mo_empty" maknae-kernel

# JUDGE positive control: a real run must still be ACCEPTED. Without this the
# three probes above are satisfied by a check that refuses everything.
mo_good="$(mktemp -d -p "$NC_TMP")"
printf '{"total_mutants": 302, "missed": 0, "caught": 234, "timeout": 0, "unviable": 68}\n' \
  > "$mo_good/outcomes.json"
expect_accept "mutation-oracle/a-real-run-is-accepted" "234 viable" \
  bash "$mo" judge "$mo_good" maknae-kernel

# JUDGE: the NESTED layout. `cargo mutants --output DIR` writes DIR/mutants.out/,
# one level below what coverage-tiers.sh names, and reading the wrong level made
# this check refuse every real run rather than only the vacuous ones. Probed at
# both spellings so the resolution itself is a control, not a comment.
mo_nested="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$mo_nested/mutants.out"
printf '{"total_mutants": 41, "missed": 0, "caught": 0, "timeout": 0, "unviable": 41}\n' \
  > "$mo_nested/mutants.out/outcomes.json"
expect_reject_because "mutation-oracle/nested-output-layout-is-found" "ZERO viable" \
  bash "$mo" judge "$mo_nested" maknae-kernel

mo_nested_ok="$(mktemp -d -p "$NC_TMP")"; mkdir -p "$mo_nested_ok/mutants.out"
printf '{"total_mutants": 302, "missed": 0, "caught": 234, "timeout": 0, "unviable": 68}\n' \
  > "$mo_nested_ok/mutants.out/outcomes.json"
expect_accept "mutation-oracle/nested-output-layout-accepts-a-real-run" "234 viable" \
  bash "$mo" judge "$mo_nested_ok" maknae-kernel

# JUDGE: THE COUNTS THEMSELVES MUST BE TRUSTWORTHY BEFORE THEY ARE BELIEVED.
# Review finding on the very commit that closed #301: the judge mapped each
# missing or non-integer field to 0 and rejected only on `total and viable == 0`,
# so `{}`, `{"outcomes": []}`, a renamed or retyped counter, an unbalanced set
# and a genuine zero-mutant run were ALL accepted and printed as
# "0 viable ... of 0". Every one of those is a no-measurement state. An oracle
# that fails open on absent data is not an oracle — so each shape gets its own
# probe with its own expected reason, and none of them may pass.
mo_shape() { # <label> <expected-FAIL-substring> <json>
  local d; d="$(mktemp -d -p "$NC_TMP")"
  printf '%s\n' "$3" > "$d/outcomes.json"
  expect_reject_because "mutation-oracle/$1" "$2" bash "$mo" judge "$d" maknae-kernel
}
mo_shape "counts-empty-object"      "has no 'total_mutants'" '{}'
mo_shape "counts-outcomes-only"     "has no 'total_mutants'" '{"outcomes":[]}'
mo_shape "counts-key-absent"        "has no 'unviable'" \
  '{"total_mutants":41,"caught":0,"missed":0,"timeout":0}'
mo_shape "counts-mistyped-string"   "not a non-negative integer" \
  '{"total_mutants":41,"caught":"31","missed":0,"timeout":0,"unviable":10}'
# `isinstance(True, int)` is True in Python: a bool must not read as a count.
mo_shape "counts-mistyped-bool"     "not a non-negative integer" \
  '{"total_mutants":1,"caught":true,"missed":0,"timeout":0,"unviable":0}'
mo_shape "counts-negative"          "not a non-negative integer" \
  '{"total_mutants":41,"caught":-1,"missed":0,"timeout":0,"unviable":42}'
mo_shape "counts-do-not-balance"    "do not balance" \
  '{"total_mutants":302,"caught":100,"missed":0,"timeout":0,"unviable":68}'
mo_shape "counts-zero-mutants"      "ZERO mutants" \
  '{"total_mutants":0,"caught":0,"missed":0,"timeout":0,"unviable":0}'
mo_shape "counts-not-an-object"     "not a JSON object" '[]'

# SCRATCH: a volume without room must be refused BEFORE the run, not discovered
# as a wall of 'unviable' afterwards. The floor is raised via the documented
# override so the probe does not depend on this host's free space.
expect_reject_because "mutation-oracle/scratch-too-small" "below the" \
  env MUTATION_ORACLE_MIN_KIB=999999999999 bash "$mo" scratch "$NC_TMP"

# SCRATCH: and a volume that does have room must pass, for the same reason the
# judge probe above has a positive control.
expect_accept "mutation-oracle/scratch-with-room-passes" "KiB free" \
  env MUTATION_ORACLE_MIN_KIB=1 bash "$mo" scratch "$NC_TMP"

# SCRATCH: a path that does not exist is fail-closed, never "assume room".
expect_reject_because "mutation-oracle/scratch-missing-dir" "does not exist" \
  bash "$mo" scratch "$NC_TMP/definitely-not-here"

# The skip count is REPORTED, because `$total` is environment-dependent: probes
# that need `cargo-auditable`, and the root-guarded ones, drop out silently and
# a bare `N/N` then looks identical to a full run. CONTRIBUTING tells readers to
# compare their local number against the full count; this is what makes that
# comparison possible.
if [ "${skipped:-0}" -gt 0 ]; then
  echo "negative-control: $pass/$total gates proven to fire (${skipped} skipped in this environment)"
else
  echo "negative-control: $pass/$total gates proven to fire"
fi
[ "$pass" = "$total" ]
