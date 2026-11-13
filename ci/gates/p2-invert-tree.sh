#!/usr/bin/env bash
set -euo pipefail
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_LITERAL_PATHSPECS GIT_NOGLOB_PATHSPECS GIT_GLOB_PATHSPECS GIT_ICASE_PATHSPECS GIT_GRAFT_FILE
export GIT_NO_REPLACE_OBJECTS=1
here="$(cd "$(dirname "$0")" && pwd)"; source "$here/lib.sh"
ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"
fail=0
# Invert form + --prefix none (default output prefixes reverse-deps with box glyphs, so a
# `^<crate> ` anchor never matches). Fail CLOSED on any cargo-tree error.
dependents() { cargo tree --workspace -i "$1" -e normal,build --prefix none 2>&1; }
for p in "${PRIVILEGED_CRATES[@]}"; do
  if ! tree_out="$(dependents "$p")"; then
    echo "FAIL: cargo tree errored for '$p' — failing closed: $tree_out"; fail=1; continue
  fi
  for b in "${UNTRUSTED_BINS[@]}"; do
    echo "$tree_out" | grep -qE "^${b} " \
      && { echo "FAIL: privileged '$p' is reachable from '$b' (P2a)"; fail=1; }
  done
done
for l in "${LOOP_CRATES[@]}"; do
  if ! tree_out="$(dependents "$l")"; then
    echo "FAIL: cargo tree errored for '$l' — failing closed: $tree_out"; fail=1; continue
  fi
  for t in "${TRUSTED_ROOTS[@]}"; do
    echo "$tree_out" | grep -qE "^${t} " \
      && { echo "FAIL: untrusted loop crate '$l' is reachable from '$t' (P2-loop)"; fail=1; }
  done
done
[ "$fail" -eq 0 ] && echo "p2-invert-tree: ok"
exit "$fail"
