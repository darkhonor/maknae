#!/usr/bin/env bash
# feature-resolution-pin (#77): production binaries must resolve maknae-config
# and maknae-authz-basic WITHOUT `hermetic-test-seam` — the seam parameterizes
# the hardened-load requirement, and a production build that selected it would
# be a claim-vs-control gap on the authz door.
#
# Soundness precondition (documented, load-bearing): per-package `-e normal`
# resolution is authoritative ONLY because build-invocation-lint.sh forbids
# --workspace/--all release builds and requires exactly one -p — a
# workspace-unified build could compile the feature in (dev-dep unification)
# despite a clean per-package tree.
#
# The maknae-spifc arm is currently VACUOUS (it reaches neither crate) — kept
# as cheap defense-in-depth, not evidence of a live risk.
set -euo pipefail
root="${1:-$(git rev-parse --show-toplevel)}"
fail=0

for bin in maknaed maknae maknae-spifc; do
  out="$(cd "$root" && cargo tree -p "$bin" -e normal -f '{p} {f}' 2>/dev/null)" || {
    echo "FAIL: cargo tree -p $bin failed"
    fail=1
    continue
  }
  # tree lines carry glyph prefixes (└──); match the crate token + version.
  if printf '%s\n' "$out" | grep -E '(maknae-config|maknae-authz-basic) v[0-9]' | grep -q 'hermetic-test-seam'; then
    echo "FAIL: $bin's normal resolution enables hermetic-test-seam (production must never select the weaker authz-load requirement)"
    fail=1
  fi
done

[ "$fail" -eq 0 ] && echo "feature-resolution-pin: ok"
exit "$fail"
