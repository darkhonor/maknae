#!/usr/bin/env bash
set -euo pipefail
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_LITERAL_PATHSPECS GIT_NOGLOB_PATHSPECS GIT_GLOB_PATHSPECS GIT_ICASE_PATHSPECS GIT_GRAFT_FILE
export GIT_NO_REPLACE_OBJECTS=1
here="$(cd "$(dirname "$0")" && pwd)"; source "$here/lib.sh"
root="${1:-$(git rev-parse --show-toplevel)}"   # arg override lets the negative-control point at a fixture
cd "$root"
out="$(mktemp "${TMPDIR:-/tmp}/maknae-p2-artifact-witness.XXXXXXXX")"; trap 'rm -f "$out"' EXIT
fail=0

for b in "${UNTRUSTED_BINS[@]}"; do
  bin="$root/target/release/$b"
  CARGO_PROFILE_RELEASE_STRIP=false cargo auditable build -p "$b" --release
  [ -f "$bin" ] || { echo "FAIL: $bin not produced"; exit 1; }

  # LOAD-BEARING witness: the cargo-auditable inventory reliably lists every linked crate (it is
  # embedded resolver metadata, optimization-proof). Must EXIST and be non-empty (fail CLOSED), and
  # must name no privileged crate.
  if ! rust-audit-info "$bin" >"$out" 2>/dev/null || [ ! -s "$out" ]; then
    echo "FAIL: no cargo-auditable inventory in $bin (fail-closed)"; exit 1
  fi
  for p in "${PRIVILEGED_CRATES[@]}"; do
    grep -q "\"$p\"" "$out" && { echo "FAIL: $b's inventory lists privileged '$p'"; fail=1; }
  done
  # BEST-EFFORT defense-in-depth: a symbol scan. NOT load-bearing — release optimization can strip a
  # linked crate's marker string, so absence is not proof of absence; presence is proof of a leak.
  for m in PRIVILEGED_MAKNAE_KERNEL PRIVILEGED_MAKNAE_SUBJECT_CTX_MINT PRIVILEGED_MAKNAE_AUDIT_APPEND PRIVILEGED_MAKNAE_SPIF_COMPILE PRIVILEGED_MAKNAE_AUTHZ_BASIC; do
    strings -a "$bin" | grep -q "$m" && { echo "FAIL: privileged marker '$m' in $b binary"; fail=1; }
  done
done
[ "$fail" -eq 0 ] && echo "p2-artifact-witness: ok"
exit "$fail"
