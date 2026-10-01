#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; source "$here/lib.sh"
ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"
if ! tree_out="$(cargo tree --workspace --all-features -i "$SEAL_CRATE" -e normal,build --target all --prefix none 2>&1)"; then
  echo "FAIL: seal-confinement: cargo tree errored for '$SEAL_CRATE' — failing closed: $tree_out"
  exit 1
fi
fail=0
for p in "${SEAL_FORBIDDEN_CONSUMERS[@]}"; do
  if grep -qE "^${p} " <<<"$tree_out"; then
    echo "FAIL: seal-confinement: '$SEAL_CRATE' is reachable from '$p'"
    fail=1
  fi
done
[ "$fail" -eq 0 ] && echo "seal-confinement: ok"
exit "$fail"
