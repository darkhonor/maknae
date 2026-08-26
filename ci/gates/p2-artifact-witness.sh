#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; source "$here/lib.sh"
root="${1:-$(git rev-parse --show-toplevel)}"   # arg override lets the negative-control point at a fixture
cd "$root"
bin="$root/target/release/$UNTRUSTED_BIN"
out="$(mktemp)"; trap 'rm -f "$out"' EXIT
fail=0

CARGO_PROFILE_RELEASE_STRIP=false cargo auditable build -p "$UNTRUSTED_BIN" --release
[ -f "$bin" ] || { echo "FAIL: $bin not produced"; exit 1; }

# LOAD-BEARING witness: the cargo-auditable inventory reliably lists every linked crate (it is
# embedded resolver metadata, optimization-proof). Must EXIST and be non-empty (fail CLOSED), and
# must name no privileged crate.
if ! rust-audit-info "$bin" >"$out" 2>/dev/null || [ ! -s "$out" ]; then
  echo "FAIL: no cargo-auditable inventory in $bin (fail-closed)"; exit 1
fi
for p in "${PRIVILEGED_CRATES[@]}"; do
  grep -q "\"$p\"" "$out" && { echo "FAIL: inventory lists privileged '$p'"; fail=1; }
done
# BEST-EFFORT defense-in-depth: a symbol scan. NOT load-bearing — release optimization can strip a
# linked crate's marker string, so absence is not proof of absence; presence is proof of a leak.
for m in PRIVILEGED_MAKNAE_KERNEL PRIVILEGED_MAKNAE_SUBJECT_CTX_MINT PRIVILEGED_MAKNAE_AUDIT_APPEND PRIVILEGED_MAKNAE_SPIF_COMPILE PRIVILEGED_MAKNAE_AUTHZ_BASIC; do
  strings -a "$bin" | grep -q "$m" && { echo "FAIL: privileged marker '$m' in $UNTRUSTED_BIN binary"; fail=1; }
done
[ "$fail" -eq 0 ] && echo "p2-artifact-witness: ok"
exit "$fail"
