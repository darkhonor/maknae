#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; source "$here/lib.sh"
root="${1:-$(git rev-parse --show-toplevel)}"; fail=0

grep -qE '^[[:space:]]*resolver[[:space:]]*=[[:space:]]*"3"' "$root/Cargo.toml" || { echo "FAIL: root Cargo.toml missing resolver = \"3\""; fail=1; }
grep -qE '^[[:space:]]*default-members' "$root/Cargo.toml" && { echo "FAIL: root Cargo.toml declares default-members (forbidden, spec §3)"; fail=1; }

# Dependency checks via `cargo metadata` — normalizes inline AND table TOML forms.
# No optional privileged dep anywhere; only trust-plane consumers (lib.sh TRUST_CONSUMERS)
# and the privileged crates themselves may depend on a privileged crate.
if ! cargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1 2>/dev/null \
     | python3 "$here/p1_check.py" "${PRIVILEGED_CRATES[*]}" "${TRUST_CONSUMERS[*]}"; then
  fail=1
fi

[ "$fail" -eq 0 ] && echo "p1-manifest-lint: ok"
exit "$fail"
