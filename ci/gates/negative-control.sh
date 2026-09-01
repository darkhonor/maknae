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
expect_reject_because "p1/optional-priv-dep" "as OPTIONAL" "$here/p1-manifest-lint.sh" "$tmpA"

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
  fixture="$(mktemp -d)"
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

# Literal-source variants: the fixture text is read verbatim from stdin (heredoc), so char
# literals and backslash escapes survive without printf %b or shell-quoting mangling.
std_fs_reject_literal() { # <label> — fixture source on stdin
  local label="$1" fixture
  fixture="$(mktemp -d)"
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
  fixture="$(mktemp -d)"
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

tmpF3="$(mktemp -d)"
mkdir -p "$tmpF3/ci/gates" "$tmpF3/crates/x/src/tests"
cp "$here/std-fs-drift.sh" "$tmpF3/ci/gates/"
: > "$tmpF3/ci/gates/std-fs-allowlist.txt"
printf 'pub fn bad() { let _ = std::fs::read("a"); }\n' > "$tmpF3/crates/x/src/tests/bad.rs"
git -C "$tmpF3" init -q
git -C "$tmpF3" add ci/gates/std-fs-drift.sh ci/gates/std-fs-allowlist.txt crates/x/src/tests/bad.rs
expect_reject "std-fs-drift/src-tests-production" "$tmpF3/ci/gates/std-fs-drift.sh" "$tmpF3"

tmpF4="$(mktemp -d)"
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
tmpG="$(mktemp -d)"
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
  fixture="$(mktemp -d)"
  mkdir -p "$fixture/ci/gates" "$fixture/crates/maknae-kernel/src" \
           "$fixture/crates/maknae-config/src" "$fixture/crates/maknae-authz-basic/src"
  cp "$here/verb-vocabulary-drift.sh" "$fixture/ci/gates/"
  cat > "$fixture/crates/maknae-kernel/src/handler.rs" <<'FIX'
pub const KERNEL_ACTIONS: [&str; 1] = ["kernel.contain"];
pub fn verb_to_action(verb: &Verb) -> &'static str {
    match verb {
        Verb::Ping => "liveness.ping",
        Verb::AdminStatus => "admin.status",
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
  printf '%s\n' "${2:-pub(crate) const GRANTABLE_ACTIONS: [&str; 3] = [\"admin.status\", \"admin.config.show\", \"admin.subject.list\"];}" \
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
# `17 terms`. Seven = 2 actions + kernel.contain + Read + 3 grantable.
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
action	admin.status	not-granted	unbuilt — answers Unauthorized to an unpermitted caller
kernel-action	kernel.contain	not-granted	no Verb variant
capability	Read	granted	the only grammar capability
grantable	admin.status	grantable-not-granted	operator MAY grant per-role via `roles:`
'
fx="$(vocab_fixture "$CLEAN_VOCAB" 'pub(crate) const GRANTABLE_ACTIONS: [&str; 1] = ["admin.status"];')"
expect_accept "verb-vocabulary-drift/clean-fixture-passes" ": 5 terms," "$fx/ci/gates/verb-vocabulary-drift.sh"

# REJECT (#181, durable): a row whose disposition and rationale DISAGREE — the
# rationale lacks its (kind, disposition) clause. The one-time capture of the
# real 51-row defect is evidence in the PR; THIS fixture is the control that
# re-runs on every PR (the repo's own negative-control discipline: a one-off
# observation is not a control).
fx="$(vocab_fixture "$(printf '%s' "$CLEAN_VOCAB" | sed 's/unbuilt — answers Unauthorized to an unpermitted caller/enumerated, decided/')" \
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
  fixture="$(mktemp -d)"
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
}
FIX
  # The gate cross-checks its SURFACE list against the section registry, so a
  # fixture needs one.
  cat > "$fixture/crates/maknae-kernel/src/boot.rs" <<'FIX'
const LAKE_SECTION: &str = "lake";
const VAULT_SECTION: &str = "vault";
const TRANSPORT_SECTION: &str = "transport";
const AUDIT_SECTION: &str = "audit";
const PRINCIPAL_SECTION: &str = "principal";
    let specs = [
        SectionSpec { name: LAKE_SECTION.to_string(), required: false },
        SectionSpec { name: VAULT_SECTION.to_string(), required: false },
        SectionSpec { name: TRANSPORT_SECTION.to_string(), required: false },
        SectionSpec { name: AUDIT_SECTION.to_string(), required: false },
        SectionSpec { name: PRINCIPAL_SECTION.to_string(), required: false },
    ];
FIX
  cp "$here/config-disclosure-drift.sh" "$fixture/ci/gates/"
  cat > "$fixture/crates/maknae-config/src/document.rs" <<FIX
const DISCLOSABLE: &[&str] = &[
    "transport",
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
disclose	audit.jsonl_path	the log the operator is looking for
omit	vault.insecure_plaintext_secret_path	presence is the finding
omit	core.handling	presence says an above-baseline ceiling is configured
always	status.version	ships by construction
always	status.protocol_version	ships by construction
always	status.listener	ships by construction
always	status.authz_backend	ships by construction
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
const DISCLOSABLE: &[&str] = &["transport", "vault.addr", "vault.approle_mount", "vault.pki_int_mount", "vault.deployment_id", "audit.jsonl_path", "principal"];
const SUPPRESSED: &[&str] = &["vault.insecure_plaintext_secret_path", "core.handling", "audit.au3_1"];
FIX
expect_accept "config-disclosure-drift/rustfmt-collapsed-array-still-read" ": 20 paths decided" "$fx/ci/gates/config-disclosure-drift.sh"

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
old = "|StatusView|status|4|wire"
assert s.count(old) == 1, "fixture prefix anchor moved"
p.write_text(s.replace(old, "|StatusView|status view|4|wire"))
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

# ACCEPT: the mirror image. `Vec<WorkspaceStruct>` on a CONFIG surface is a
# LEAF -- `flatten` never recurses into `Value::Seq` and `render` masks the
# sequence whole -- so demanding coverage there would block legitimate work.
# Unprobed, the exemption was free to not exist: under the leaked variable it
# did not, and every config row was silently held to the wire rule.
fx="$(cfg_fixture "$CFG_OK" '' '' '' 'Vec<Principal>')"
expect_accept "config-disclosure-drift/config-vec-of-struct-is-a-leaf" \
  ": 20 paths decided" "$fx/ci/gates/config-disclosure-drift.sh"

# ACCEPT: the clean fixture passes and reports both counts. Without this every
# rejection above would stay green against a gate that refuses everything.
fx="$(cfg_fixture "$CFG_OK")"
expect_accept "config-disclosure-drift/clean-fixture-passes" ": 20 paths decided, 31 struct fields covered" "$fx/ci/gates/config-disclosure-drift.sh"


# ACCEPT, against the REAL repo: the gate's own summary counts are pinned.
# Round 8's probes all showed up first as a silent change to these two numbers
# (23 -> 18 struct fields, EXIT=0). A count nobody asserts is a log line, not a
# control; asserting it here means any future silent shrink is a red build.
expect_accept "config-disclosure-drift/real-repo-counts-pinned" \
  ": 32 paths decided, 31 struct fields covered" "$here/config-disclosure-drift.sh"


# ---- external-authority-lint (#34): no Maknae rule rests on a foreign ADR ----
# The wording IS the control here, so the fixture is a wording fixture.
ea_fixture() { # <line> — a bare dir (not a repo) holding one normative doc
  local fixture; fixture="$(mktemp -d)"
  mkdir -p "$fixture/ci/gates" "$fixture/design"
  cp "$here/external-authority-lint.sh" "$fixture/ci/gates/"
  printf '# doc\n\n%s\n' "$1" > "$fixture/design/some-design.md"
  echo "$fixture"
}
fx="$(ea_fixture "Following the Knowledge Lake ADR-0004 authority model, the map separates two concerns.")"
expect_reject "external-authority-lint/unqualified-foreign-adr" "$fx/ci/gates/external-authority-lint.sh"
fx="$(ea_fixture "Microkosmos ADR 0006 defines the dual-client identity pattern used here.")"
expect_reject "external-authority-lint/unqualified-microkosmos-adr" "$fx/ci/gates/external-authority-lint.sh"

echo "negative-control: $pass/$total gates proven to fire"
[ "$pass" = "$total" ]
