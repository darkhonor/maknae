#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; source "$here/lib.sh"
ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"
if ! tree_out="$(cargo tree --workspace --all-features -i "$SEAL_CRATE" -e normal,build --target all --prefix none 2>&1)"; then
  echo "FAIL: seal-confinement: cargo tree errored for '$SEAL_CRATE' — failing closed: $tree_out"
  exit 1
fi
meta_err="$(mktemp "${TMPDIR:-/tmp}/maknae-seal-confinement.XXXXXXXX")"; trap 'rm -f "$meta_err"' EXIT
if ! meta_out="$(cargo metadata --no-deps --format-version 1 2>"$meta_err")"; then
  echo "FAIL: seal-confinement: cargo metadata errored — failing closed: $(cat "$meta_err")"
  exit 1
fi
if ! members="$(python3 -c 'import json,sys; print("\n".join(p["name"] for p in json.load(sys.stdin)["packages"]))' <<<"$meta_out")"; then
  echo "FAIL: seal-confinement: cargo metadata output did not parse"
  exit 1
fi
fail=0
for p in "${SEAL_FORBIDDEN_CONSUMERS[@]}"; do
  if ! grep -qxF "$p" <<<"$members"; then
    echo "FAIL: seal-confinement: forbidden consumer '$p' is not a workspace package"
    fail=1
  fi
done
if [ "$fail" -ne 0 ]; then exit 1; fi
for p in "${SEAL_FORBIDDEN_CONSUMERS[@]}"; do
  if grep -qE "^${p} " <<<"$tree_out"; then
    echo "FAIL: seal-confinement: '$SEAL_CRATE' is reachable from '$p'"
    fail=1
  fi
done
[ "$fail" -eq 0 ] && echo "seal-confinement: ok"
exit "$fail"
