#!/usr/bin/env bash
# THE MUTATION RUN'S EXIT STATUS IS NOT A SUFFICIENT ORACLE (#301).
#
# `cargo mutants` builds each mutant in a scratch copy under $TMPDIR and
# classifies a mutant that fails to BUILD as `unviable`. A build that fails for
# a reason having nothing to do with the mutation — a full scratch volume, a
# lock file it cannot create — is therefore counted as unviability, and
# cargo-mutants exits 0. Measured 2026-09-13 with cargo-mutants 27.1.0: an
# all-unviable run exits 0. coverage-tiers.sh read only that status, so the
# zero-missed contract passed having tested NOTHING while cargo-mutants printed
# `WARN No mutants were viable` that nothing consumed.
#
# It is not hypothetical. /tmp on the maintainer's host (5.0 GiB) had filled
# with 17,667 leaked gate scratch trees (#302); every mutant build failed with
# `No space left on device`; the lane reported `41 unviable` and exited 0.
#
# A separate script, like mutation-platform.sh, so negative-control.sh can probe
# these decisions against crafted fixtures WITHOUT a 45-minute mutation run — a
# check that cannot be shown to fire is not a control (spec §3 P2c).
#
# Usage:
#   mutation-oracle.sh scratch <dir>            — room to run at all, BEFORE the run
#   mutation-oracle.sh judge <outdir> <crate>   — did it measure anything, AFTER
set -euo pipefail

# MEASURED 2026-09-13, sampling the scratch tree during a maknae-kernel mutant
# run: peak 2.9 GiB (3,053,740 KiB), for a workspace whose tracked sources are
# 5.7 MiB — the cost is the build, not the copy. /tmp had 3.0 GiB free when #301
# happened, i.e. it failed right at the edge. The floor is twice the measured
# kernel peak, to cover the crates that compile aws-lc-fips-sys and to leave a
# margin rather than sit on the boundary that already bit once.
MIN_SCRATCH_KIB=${MUTATION_ORACLE_MIN_KIB:-$((6 * 1024 * 1024))}

usage() { printf 'FAIL: usage: mutation-oracle.sh scratch <dir> | judge <outdir> <crate>\n'; exit 2; }

scratch() {
  local dir="${1:?}" avail
  if [ ! -d "$dir" ]; then
    printf 'FAIL: mutation scratch dir does not exist: %s\n' "$dir"; return 1
  fi
  # POSIX `df -Pk`: KiB on both lanes (macOS df otherwise reports 512b blocks).
  if ! avail="$(df -Pk "$dir" 2>/dev/null | awk 'NR==2 {print $4}')" || \
     ! printf '%s' "$avail" | grep -Eq '^[0-9]+$'; then
    printf 'FAIL: cannot determine free space on the mutation scratch volume: %s\n' "$dir"; return 1
  fi
  if [ "$avail" -lt "$MIN_SCRATCH_KIB" ]; then
    printf 'FAIL: mutation scratch volume %s has %sKiB free, below the %sKiB a mutant build needs — every mutant would fail to build and be reported '"'"'unviable'"'"' with exit 0 (#301)\n' \
      "$dir" "$avail" "$MIN_SCRATCH_KIB"; return 1
  fi
  printf 'mutation scratch %s: %sKiB free\n' "$dir" "$avail"
}

judge() {
  local out="${1:?}" cname="${2:?}" rc=0 hit
  # `cargo mutants --output DIR` writes DIR/mutants.out/ — the results are one
  # level below what the caller named. Accept either spelling so a caller may
  # pass the --output dir or the mutants.out dir itself; the layout belongs to
  # cargo-mutants, not to us, and guessing it wrong once already made this check
  # refuse every real run instead of only the vacuous ones.
  if [ -f "$out/mutants.out/outcomes.json" ]; then
    out="$out/mutants.out"
  fi

  # An ENVIRONMENT failure is not an unviable mutant; it is the gate's own
  # footing giving way, and must be named rather than inflating the count.
  if [ -d "$out/log" ]; then
    hit="$(grep -rlE 'No space left on device|could not create session directory lock file|Permission denied \(os error 13\)|Too many open files' "$out/log" 2>/dev/null | head -3 || true)"
    if [ -n "$hit" ]; then
      printf 'FAIL: %s: the mutation run hit an ENVIRONMENT failure, not unviable mutants — the build could not run. Logs: %s\n' \
        "$cname" "$(printf '%s' "$hit" | tr '\n' ' ')"
      rc=1
    fi
  fi

  if [ ! -f "$out/outcomes.json" ]; then
    printf 'FAIL: %s: cargo mutants wrote no outcomes.json — the run cannot be judged (#301)\n' "$cname"
    return 1
  fi
  python3 - "$out/outcomes.json" "$cname" <<'PYEOF' || rc=1
import json, sys
path, cname = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        d = json.load(f)
except (OSError, ValueError) as e:
    print(f"FAIL: {cname}: unreadable mutation outcomes: {e}")
    sys.exit(1)
if not isinstance(d, dict):
    print(f"FAIL: {cname}: mutation outcomes is not an object")
    sys.exit(1)
def n(k):
    v = d.get(k) or 0
    return v if isinstance(v, int) else 0
total, unviable = n("total_mutants"), n("unviable")
caught, missed, timeout = n("caught"), n("missed"), n("timeout")
viable = caught + missed + timeout
# A run with zero viable mutants proves nothing, whatever it exits with.
if total and viable == 0:
    print(f"FAIL: {cname}: {total} mutants, {unviable} unviable, ZERO viable — "
          "the mutation lane measured nothing and would otherwise pass the "
          "zero-missed contract (#301)")
    sys.exit(1)
print(f"mutants[{cname}]: {viable} viable ({caught} caught, {missed} missed, "
      f"{timeout} timeout), {unviable} unviable of {total}")
PYEOF
  return $rc
}

case "${1:-}" in
  scratch) shift; [ $# -eq 1 ] || usage; scratch "$1";;
  judge)   shift; [ $# -eq 2 ] || usage; judge "$1" "$2";;
  *) usage;;
esac
