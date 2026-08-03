#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; source "$here/lib.sh"
root="${1:-$(git rev-parse --show-toplevel)}"; fail=0   # arg override for the negative-control
# [[:space:]] not \s — BSD grep (macOS) treats \s as a literal 's'.

grep -qE '^[[:space:]]*resolver[[:space:]]*=[[:space:]]*"3"' "$root/Cargo.toml" || { echo "FAIL: root Cargo.toml missing resolver = \"3\""; fail=1; }
grep -qE '^[[:space:]]*default-members' "$root/Cargo.toml" && { echo "FAIL: root Cargo.toml declares default-members (forbidden, spec §3)"; fail=1; }

while IFS= read -r manifest; do
  for p in "${PRIVILEGED_CRATES[@]}"; do
    if grep -qE "^[[:space:]]*${p}[[:space:]]*=.*optional[[:space:]]*=[[:space:]]*true" "$manifest"; then
      echo "FAIL: $manifest declares privileged crate '$p' as optional (defeats absence-based reasoning)"; fail=1
    fi
  done
done < <(find "$root/crates" "$root/bins" -name Cargo.toml 2>/dev/null)

while IFS= read -r manifest; do
  cname="$(grep -m1 -E '^name[[:space:]]*=' "$manifest" | sed -E 's/.*"(.*)".*/\1/')"
  printf '%s\n' "${PRIVILEGED_CRATES[@]}" | grep -qx "$cname" && continue
  for p in "${PRIVILEGED_CRATES[@]}"; do
    grep -qE "^[[:space:]]*${p}[[:space:]]*=" "$manifest" && { echo "FAIL: unprivileged '$cname' directly depends on privileged '$p'"; fail=1; }
  done
done < <(find "$root/crates" -name Cargo.toml 2>/dev/null)

[ "$fail" -eq 0 ] && echo "p1-manifest-lint: ok"
exit "$fail"
