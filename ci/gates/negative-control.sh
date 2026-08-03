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

echo "negative-control: $pass/$total gates proven to fire"
[ "$pass" = "$total" ]
