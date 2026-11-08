#!/usr/bin/env bash
# feature-resolution-pin (#77): production binaries must resolve maknae-config,
# maknae-authz-basic, maknae-state and maknae-kernel WITHOUT `hermetic-test-seam` — the seam
# parameterizes the hardened-load requirement (and, in maknae-state, the reseed
# marker's owner), and a production build that selected it would be a
# claim-vs-control gap. Since #609 the same holds for the test-only `test-support`
# features of maknae-vault (test PKI, `PlaneIdentity` from parts) and maknae-crypto
# (the `rcgen` re-export, ADR-0030).
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
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_LITERAL_PATHSPECS GIT_NOGLOB_PATHSPECS GIT_GLOB_PATHSPECS GIT_ICASE_PATHSPECS GIT_GRAFT_FILE
export GIT_NO_REPLACE_OBJECTS=1
root="${1:-$(git rev-parse --show-toplevel)}"
fail=0

for bin in maknaed maknae maknae-egress maknae-spifc; do
  out="$(cd "$root" && cargo tree -p "$bin" -e normal -f '{p} {f}' 2>/dev/null)" || {
    echo "FAIL: cargo tree -p $bin failed"
    fail=1
    continue
  }
  # tree lines carry glyph prefixes (└──); match the crate token + version.
  if printf '%s\n' "$out" | grep -E '(maknae-config|maknae-authz-basic|maknae-state|maknae-kernel) v[0-9]' | grep -q 'hermetic-test-seam'; then
    echo "FAIL: $bin's normal resolution enables hermetic-test-seam (production must never select the weaker authz-load requirement)"
    fail=1
  fi
  for crate in maknae-vault maknae-crypto; do
    if printf '%s\n' "$out" | grep -E "(^|[^a-z-])$crate v[0-9]" | grep -q 'test-support'; then
      echo "FAIL: $bin's normal resolution enables $crate/test-support (a test-only feature)"
      fail=1
    fi
  done
done

[ "$fail" -eq 0 ] && echo "feature-resolution-pin: ok"
exit "$fail"
