#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; source "$here/lib.sh"
root="$(git rev-parse --show-toplevel)"
bin="$root/target/release/$UNTRUSTED_BIN"
out="$(mktemp)"; trap 'rm -f "$out"' EXIT
fail=0

CARGO_PROFILE_RELEASE_STRIP=false cargo auditable build -p "$UNTRUSTED_BIN" --release
[ -f "$bin" ] || { echo "FAIL: $bin not produced"; exit 1; }

# (1) Inventory must EXIST and be non-empty (fail CLOSED on missing — spec §3 P2b).
if ! rust-audit-info "$bin" >"$out" 2>/dev/null || [ ! -s "$out" ]; then
  echo "FAIL: no cargo-auditable inventory in $bin (fail-closed)"; exit 1
fi
# (2) Inventory names no privileged crate (expects JSON: "name":"maknae-kernel").
for p in "${PRIVILEGED_CRATES[@]}"; do
  grep -q "\"$p\"" "$out" && { echo "FAIL: inventory lists privileged '$p'"; fail=1; }
done
# (3) Linker-truth symbol scan (markers are #[used] statics so this is meaningful now; stub tree: clean).
for m in PRIVILEGED_MAKNAE_KERNEL PRIVILEGED_MAKNAE_SUBJECT_CTX_MINT PRIVILEGED_MAKNAE_AUDIT_APPEND PRIVILEGED_MAKNAE_SPIF_COMPILE; do
  strings -a "$bin" | grep -q "$m" && { echo "FAIL: privileged marker '$m' in $UNTRUSTED_BIN binary"; fail=1; }
done
[ "$fail" -eq 0 ] && echo "p2-artifact-witness: ok"
exit "$fail"
