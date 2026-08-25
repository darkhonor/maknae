#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# Materialize contaminated workspaces in temp dirs and assert the REAL gate scripts reject each
# (root-override arg). A gate that cannot be shown to fire is not a control (spec §3 P2c).
pass=0; total=0
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

# Fixture A — optional privileged dep → must trip p1-manifest-lint.sh
tmpA="$(mktemp -d)"; mkdir -p "$tmpA/crates/shared/src" "$tmpA/crates/maknae-kernel/src" "$tmpA/bins"
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
expect_reject "p1/optional-priv-dep" "$here/p1-manifest-lint.sh" "$tmpA"

# Fixture A2 — TABLE-form optional privileged dep (`[dependencies.<crate>]`) → must also trip p1.
tmpA2="$(mktemp -d)"; mkdir -p "$tmpA2/crates/shared/src" "$tmpA2/crates/maknae-kernel/src"
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
expect_reject "p1/optional-priv-dep-TABLE-form" "$here/p1-manifest-lint.sh" "$tmpA2"

# Fixture B — CLI normally links a privileged crate → must trip p2-invert-tree.sh
tmpB="$(mktemp -d)"; mkdir -p "$tmpB/crates/maknae-kernel/src" "$tmpB/bins/maknae/src"
cat > "$tmpB/Cargo.toml" <<'EOF'
[workspace]
resolver = "3"
members = ["crates/maknae-kernel", "bins/maknae"]
EOF
cat > "$tmpB/crates/maknae-kernel/Cargo.toml" <<'EOF'
[package]
name = "maknae-kernel"
version = "0.0.0"
edition = "2021"
EOF
echo 'pub const M: &str = "x";' > "$tmpB/crates/maknae-kernel/src/lib.rs"
cat > "$tmpB/bins/maknae/Cargo.toml" <<'EOF'
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
echo 'fn main(){ println!("{}", maknae_kernel::M); }' > "$tmpB/bins/maknae/src/main.rs"
expect_reject "p2/cli-links-privileged" "$here/p2-invert-tree.sh" "$tmpB"

# Fixture C — bare workspace build in a workflow → must trip build-invocation-lint.sh
tmpC="$(mktemp -d)"; mkdir -p "$tmpC/.github/workflows"
printf 'jobs:\n  b:\n    steps:\n      - run: cargo build --workspace --release\n' > "$tmpC/.github/workflows/bad.yml"
expect_reject "build-invocation/workspace-build" "$here/build-invocation-lint.sh" "$tmpC"

# Fixture C2 — MULTILINE (backslash-continued) workspace build → must also trip build-invocation-lint.
tmpC2="$(mktemp -d)"; mkdir -p "$tmpC2/.github/workflows"
printf 'jobs:\n  b:\n    steps:\n      - run: |\n          cargo build \\\n            --workspace --release\n' > "$tmpC2/.github/workflows/bad.yml"
expect_reject "build-invocation/multiline-workspace-build" "$here/build-invocation-lint.sh" "$tmpC2"

# Fixture D — artifact INVENTORY witness (the reliable P2b half): a CLI that links a privileged
# crate must be caught by p2-artifact-witness via the cargo-auditable inventory. CI-gated: the
# inventory needs cargo-auditable + rust-audit-info; skipped locally (matches the witness itself).
if command -v rust-audit-info >/dev/null 2>&1 && cargo auditable --version >/dev/null 2>&1; then
  tmpD="$(mktemp -d)"; mkdir -p "$tmpD/crates/maknae-kernel/src" "$tmpD/bins/maknae/src"
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
fi

# --- Fixture E: coverage-tiers gate (ADR-0016) — unclassified file must FAIL.
# Injection contract (both required vars + --injection; env-prefixed argv is
# the pinned shape for this, the first env-prefixed fixture in this file).
tmpE="$(mktemp -d)"
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

tmpF="$(mktemp -d)"
mkdir -p "$tmpF/ci/gates" "$tmpF/crates/x/src"
cp "$here/std-fs-drift.sh" "$tmpF/ci/gates/"
: > "$tmpF/ci/gates/std-fs-allowlist.txt"
printf 'pub fn bad(p: &std::path::Path) { let _ = std::fs::read(p); }\n' > "$tmpF/crates/x/src/lib.rs"
git -C "$tmpF" init -q
git -C "$tmpF" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/lib.rs
expect_reject "std-fs-drift/production-call" "$tmpF/ci/gates/std-fs-drift.sh" "$tmpF"

std_fs_reject() {
  local label="$1" source="$2" fixture
  fixture="$(mktemp -d)"
  mkdir -p "$fixture/ci/gates" "$fixture/crates/x/src"
  cp "$here/std-fs-drift.sh" "$fixture/ci/gates/"
  : > "$fixture/ci/gates/std-fs-allowlist.txt"
  printf '%b' "$source" > "$fixture/crates/x/src/lib.rs"
  git -C "$fixture" init -q
  git -C "$fixture" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/lib.rs
  expect_reject "std-fs-drift/$label" "$fixture/ci/gates/std-fs-drift.sh" "$fixture"
}

std_fs_reject "grouped-import" 'use std::{fs};\npub fn bad() { let _ = fs::copy("a", "b"); }\n'
std_fs_reject "unlisted-operation" 'pub fn bad() { let _ = std::fs::copy("a", "b"); }\n'
std_fs_reject "whitespace-qualified" 'pub fn bad() { let _ = std :: fs :: read("a"); }\n'
std_fs_reject "production-after-test" '#[cfg(test)]\nmod tests {}\npub fn bad() { let _ = std::fs::read("a"); }\n'

tmpF_alias="$(mktemp -d)"
mkdir -p "$tmpF_alias/ci/gates" "$tmpF_alias/crates/x/src"
cp "$here/std-fs-drift.sh" "$tmpF_alias/ci/gates/"
: > "$tmpF_alias/ci/gates/std-fs-allowlist.txt"
printf 'use std::fs as disk;\npub fn bad(p: &std::path::Path) { let _ = disk::read(p); }\n' > "$tmpF_alias/crates/x/src/lib.rs"
git -C "$tmpF_alias" init -q
git -C "$tmpF_alias" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/lib.rs
expect_reject "std-fs-drift/module-alias" "$tmpF_alias/ci/gates/std-fs-drift.sh" "$tmpF_alias"

tmpF_stale="$(mktemp -d)"
mkdir -p "$tmpF_stale/ci/gates" "$tmpF_stale/crates/x/src"
cp "$here/std-fs-drift.sh" "$tmpF_stale/ci/gates/"
printf 'crates/x/src/lib.rs:1|use std::fs::File;\n' > "$tmpF_stale/ci/gates/std-fs-allowlist.txt"
printf 'pub fn clean() {}\n' > "$tmpF_stale/crates/x/src/lib.rs"
git -C "$tmpF_stale" init -q
git -C "$tmpF_stale" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/lib.rs
expect_reject "std-fs-drift/stale-exemption" "$tmpF_stale/ci/gates/std-fs-drift.sh" "$tmpF_stale"

tmpF2="$(mktemp -d)"
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

echo "negative-control: $pass/$total gates proven to fire"
[ "$pass" = "$total" ]
