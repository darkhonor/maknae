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
    print(f"FAIL: {cname}: mutation outcomes is not a JSON object, it is a "
          f"{type(d).__name__} — the run cannot be judged (#301)")
    sys.exit(1)

# EVERY count must be PRESENT and well-typed before any of them is believed.
# The failure this replaces, caught in review of the very commit that closed
# #301: a tolerant reader mapped each missing or non-integer field to 0, and the
# only rejection was `if total and viable == 0` — so `{}`, `{"outcomes": []}`, a
# schema drift that renamed or retyped the counters, and a genuine zero-mutant
# run were all ACCEPTED, printed as "0 viable ... of 0". Those are every one of
# them a no-measurement state, which is precisely what this oracle exists to
# refuse. An oracle that fails open on absent data is not an oracle.
KEYS = ("total_mutants", "caught", "missed", "timeout", "unviable")
v = {}
for k in KEYS:
    if k not in d:
        print(f"FAIL: {cname}: mutation outcomes has no '{k}' — the counts this "
              f"gate judges are ABSENT, so the run cannot be judged. Either the "
              f"run did not complete or cargo-mutants' schema moved (#301)")
        sys.exit(1)
    x = d[k]
    # `isinstance(True, int)` is True in Python, so bools are excluded by name:
    # `{"caught": true}` must not be read as one caught mutant.
    if isinstance(x, bool) or not isinstance(x, int) or x < 0:
        print(f"FAIL: {cname}: mutation outcomes '{k}' is {x!r}, not a "
              f"non-negative integer — the counts cannot be trusted (#301)")
        sys.exit(1)
    v[k] = x

total = v["total_mutants"]
viable = v["caught"] + v["missed"] + v["timeout"]
accounted = viable + v["unviable"]

# Internal consistency, verified against real cargo-mutants 27.1.0 output before
# being enforced: 234+0+0+68 == 302 and 0+0+0+6 == 6. If this ever stops holding
# the gate fails CLOSED and a human reads the numbers, which is the right
# direction for an assurance claim — a silently rebalanced set of counters is
# indistinguishable from a partial run.
if accounted != total:
    print(f"FAIL: {cname}: mutation counts do not balance — "
          f"caught {v['caught']} + missed {v['missed']} + timeout {v['timeout']} "
          f"+ unviable {v['unviable']} = {accounted}, but total_mutants is "
          f"{total}. The run is partial or the schema changed (#301)")
    sys.exit(1)

# A run over zero mutants measured nothing, however cheerfully it exited. It is
# also how an empty or drifted outcomes.json presents itself.
if total == 0:
    print(f"FAIL: {cname}: the mutation run reports ZERO mutants — nothing was "
          f"generated, so nothing was measured, and the zero-missed contract "
          f"would pass vacuously (#301)")
    sys.exit(1)

if viable == 0:
    print(f"FAIL: {cname}: {total} mutants, {v['unviable']} unviable, ZERO "
          f"viable — the mutation lane measured nothing and would otherwise "
          f"pass the zero-missed contract (#301)")
    sys.exit(1)

print(f"mutants[{cname}]: {viable} viable ({v['caught']} caught, "
      f"{v['missed']} missed, {v['timeout']} timeout), {v['unviable']} unviable "
      f"of {total}")
PYEOF
  return $rc
}

case "${1:-}" in
  scratch) shift; [ $# -eq 1 ] || usage; scratch "$1";;
  judge)   shift; [ $# -eq 2 ] || usage; judge "$1" "$2";;
  *) usage;;
esac
