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

# Fixture B2 — CLI links the PDP backend (#85: maknae-authz-basic is privileged;
# the untrusted client must never carry the decision engine) → must trip p2.
tmpB2="$(mktemp -d)"; mkdir -p "$tmpB2/crates/maknae-authz-basic/src" "$tmpB2/bins/maknae/src"
cat > "$tmpB2/Cargo.toml" <<'EOF'
[workspace]
resolver = "3"
members = ["crates/maknae-authz-basic", "bins/maknae"]
EOF
cat > "$tmpB2/crates/maknae-authz-basic/Cargo.toml" <<'EOF'
[package]
name = "maknae-authz-basic"
version = "0.0.0"
edition = "2021"
EOF
echo 'pub const M: &str = "x";' > "$tmpB2/crates/maknae-authz-basic/src/lib.rs"
cat > "$tmpB2/bins/maknae/Cargo.toml" <<'EOF'
[package]
name = "maknae"
version = "0.0.0"
edition = "2021"
[[bin]]
name = "maknae"
path = "src/main.rs"
[dependencies]
maknae-authz-basic = { path = "../../crates/maknae-authz-basic" }
EOF
echo 'fn main(){ println!("{}", maknae_authz_basic::M); }' > "$tmpB2/bins/maknae/src/main.rs"
expect_reject "p2/cli-links-authz-basic" "$here/p2-invert-tree.sh" "$tmpB2"

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
expect_reject "verb-vocabulary-drift/term-with-no-disposition" "$fx/ci/gates/verb-vocabulary-drift.sh"

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
expect_reject "verb-vocabulary-drift/stale-manifest-entry" "$fx/ci/gates/verb-vocabulary-drift.sh"

# REJECT: a grammar capability with no recorded disposition — R7 covers BOTH
# closed vocabularies, so a capability added to the grammar must be inventoried.
fx="$(vocab_fixture 'action	liveness.ping	granted	shipped
action	admin.status	not-granted	enumerated
kernel-action	kernel.contain	not-granted	no Verb variant
grantable	admin.status	grantable-not-granted	per-role via roles:
grantable	admin.config.show	grantable-not-granted	per-role via roles:
grantable	admin.subject.list	grantable-not-granted	per-role via roles:
')"
expect_reject "verb-vocabulary-drift/capability-with-no-disposition" "$fx/ci/gates/verb-vocabulary-drift.sh"

# REJECT: a GRANTABLE term with no recorded disposition (#162). The grantable
# list is a fourth closed vocabulary — a term an operator can write into
# `roles:` must carry a decision like any other.
fx="$(vocab_fixture 'action	liveness.ping	granted	shipped
action	admin.status	not-granted	enumerated
kernel-action	kernel.contain	not-granted	no Verb variant
capability	Read	granted	the only capability
grantable	admin.status	grantable-not-granted	per-role via roles:
' 'pub(crate) const GRANTABLE_ACTIONS: [&str; 2] = ["admin.status", "admin.config.show"];')"
expect_reject "verb-vocabulary-drift/grantable-with-no-disposition" "$fx/ci/gates/verb-vocabulary-drift.sh"

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
fx="$(vocab_fixture 'action	liveness.ping	granted	shipped
action	admin.status	not-granted	enumerated
kernel-action	kernel.contain	not-granted	no Verb variant
capability	Read	granted	the only capability
grantable	admin.status	grantable-not-granted	per-role via roles:
' 'pub(crate) const GRANTABLE_ACTIONS: [&str; 1] = ["admin.status"];')"
expect_accept "verb-vocabulary-drift/clean-fixture-passes" ": 5 terms," "$fx/ci/gates/verb-vocabulary-drift.sh"

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
expect_reject "verb-vocabulary-drift/grantable-not-a-real-action" "$fx/ci/gates/verb-vocabulary-drift.sh"


# ---- config-disclosure-drift (#162): the admin.config.show surface ----
# Five review rounds found the completeness of this control resting on a prose
# instruction, and found that instruction wrong twice. These fixtures are why
# the gate replaced it.
cfg_fixture() { # <manifest-body> [extra-vault-parser-line] — a minimal repo
  local fixture
  fixture="$(mktemp -d)"
  mkdir -p "$fixture/ci/gates" "$fixture/crates/maknae-config/src" \
           "$fixture/crates/maknae-vault/src"
  cp "$here/config-disclosure-drift.sh" "$fixture/ci/gates/"
  cat > "$fixture/crates/maknae-config/src/document.rs" <<'FIX'
const DISCLOSABLE: &[&str] = &[
    "vault.addr",
];
const SUPPRESSED: &[&str] = &[
    "vault.insecure_plaintext_secret_path",
];
FIX
  : > "$fixture/crates/maknae-config/src/transport.rs"
  : > "$fixture/crates/maknae-config/src/audit_cfg.rs"
  : > "$fixture/crates/maknae-config/src/principal.rs"
  cat > "$fixture/crates/maknae-vault/src/config.rs" <<FIX
fn f() {
    let a = get_str(vault, "addr");
    let b = get_str(vault, "insecure_plaintext_secret_path");
    ${2:-}
}
FIX
  printf '%s' "$1" > "$fixture/ci/gates/config-disclosure-manifest.txt"
  echo "$fixture"
}

# REJECT: a path classified in code with no recorded decision.
fx="$(cfg_fixture 'disclose	vault.addr	where vault is
omit	vault.insecure_plaintext_secret_path	presence is the finding
disclose	vault.undeclared	NOT in the code
')"
expect_reject "config-disclosure-drift/code-and-manifest-disagree" "$fx/ci/gates/config-disclosure-drift.sh"

# REJECT: a parser reads a key nobody classified. THIS is the miss the review
# loop kept finding — deny-by-default masks the VALUE and does nothing about a
# key whose presence is itself the disclosure, so "it fails safe" is false here.
fx="$(cfg_fixture 'disclose	vault.addr	where vault is
omit	vault.insecure_plaintext_secret_path	presence is the finding
' '    let c = get_str(vault, "hsm_pin_path");')"
expect_reject "config-disclosure-drift/parser-key-with-no-decision" "$fx/ci/gates/config-disclosure-drift.sh"

# ACCEPT: the clean fixture passes and reports its count. Without this every
# rejection above would stay green against a gate that refuses everything.
fx="$(cfg_fixture 'disclose	vault.addr	where vault is
omit	vault.insecure_plaintext_secret_path	presence is the finding
')"
expect_accept "config-disclosure-drift/clean-fixture-passes" ": 2 paths, all decided" "$fx/ci/gates/config-disclosure-drift.sh"


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
