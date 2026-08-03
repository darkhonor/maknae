#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; source "$here/lib.sh"
ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"
fail=0
for p in "${PRIVILEGED_CRATES[@]}"; do
  # Invert form + --prefix none (default output prefixes reverse-deps with box glyphs, so a
  # `^${UNTRUSTED_BIN} ` anchor never matches). Fail CLOSED on any cargo-tree error.
  if ! tree_out="$(cargo tree --workspace -i "$p" -e normal,build --prefix none 2>&1)"; then
    echo "FAIL: cargo tree errored for '$p' — failing closed: $tree_out"; fail=1; continue
  fi
  echo "$tree_out" | grep -qE "^${UNTRUSTED_BIN} " \
    && { echo "FAIL: privileged '$p' is reachable from '$UNTRUSTED_BIN' (P2a)"; fail=1; }
done
[ "$fail" -eq 0 ] && echo "p2-invert-tree: ok"
exit "$fail"
