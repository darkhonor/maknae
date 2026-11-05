#!/usr/bin/env bash
# Risk-tiered coverage gate (ADR-0016, issue #24). Spec authority:
# 2026-08-04-coverage-tiers-design.md (out-of-repo design spec) (v18).
#
# Usage: coverage-tiers.sh [--root <path>] [--injection]
#                          [--mutants <crate>... [--in-diff <rev>] | --mutants-all | --readiness-check]
#
# Injection contract (named, not a backdoor — CI never sets these):
#   COVERAGE_TIERS_JSON      coverage JSON (replaces the cargo llvm-cov run)
#   COVERAGE_TIERS_FILELIST  universe list (replaces git ls-files)
#   COVERAGE_TIERS_CRATE_DIRS  name=dir pairs (replaces cargo metadata for sync)
# --injection is REQUIRED to honor them and is REFUSED inside a git work tree.
set -euo pipefail
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  printf 'FAIL: bash >= 4 required (declare -A/mapfile); macOS system bash is 3.2 — install via brew\n'
  exit 1
fi

in_diff_git_env=(-u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_OBJECT_DIRECTORY -u GIT_COMMON_DIR
  -u GIT_ALTERNATE_OBJECT_DIRECTORIES -u GIT_LITERAL_PATHSPECS -u GIT_NOGLOB_PATHSPECS
  -u GIT_GLOB_PATHSPECS -u GIT_ICASE_PATHSPECS -u GIT_GRAFT_FILE GIT_NO_REPLACE_OBJECTS=1)
in_diff_generate() { # <base> <out> [<head>]
  env -u GIT_DIFF_OPTS -u GIT_EXTERNAL_DIFF "${in_diff_git_env[@]}" \
    git -C "$root" -c diff.noprefix=false -c diff.mnemonicPrefix=false -c diff.suppressBlankEmpty=false \
    -c core.quotePath=true diff --text --no-ext-diff --no-textconv --no-color --unified=3 \
    --src-prefix=a/ --dst-prefix=b/ --find-renames "$1" "${3:-HEAD}" -- '*.rs' >"$2"
}
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_LITERAL_PATHSPECS GIT_NOGLOB_PATHSPECS GIT_GLOB_PATHSPECS GIT_ICASE_PATHSPECS GIT_GRAFT_FILE
export GIT_NO_REPLACE_OBJECTS=1

here="$(cd "$(dirname "$0")" && pwd)"

fail_n=0
fail() { printf 'FAIL: %s\n' "$1"; fail_n=$((fail_n + 1)); }

# ---- argv ------------------------------------------------------------------
root=""
injection=0
readiness_only=0
mutants_mode=""      # "", "all", "list"
mutant_crates=()
in_diff=""
preflight=0
while [ $# -gt 0 ]; do
  case "$1" in
    --root)
      shift
      if [ $# -eq 0 ] || [ -z "${1:-}" ]; then fail "--root needs a path"; exit 1; fi
      root="$1";;
    --injection) injection=1;;
    --readiness-check) readiness_only=1;;
    --mutants-all) mutants_mode="all";;
    --mutants)
      mutants_mode="list"; shift
      while [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; do
        if ! printf '%s' "$1" | grep -Eq '^[A-Za-z0-9_-]+$'; then
          fail "invalid crate name for --mutants: $1"; exit 1
        fi
        mutant_crates+=("$1"); shift
      done
      continue;;
    --in-diff-preflight) preflight=1;;
    --in-diff)
      shift
      if [ $# -eq 0 ] || [ -z "$1" ] || [ "${1#-}" != "$1" ]; then fail "--in-diff needs a revision"; exit 1; fi
      in_diff="$1";;
    *) fail "unknown argument: $1"; exit 1;;
  esac
  shift
done
if [ "$preflight" -eq 1 ] && { [ -n "$in_diff" ] || [ -n "$mutants_mode" ] || [ "$injection" -eq 1 ] || [ "$readiness_only" -eq 1 ]; }; then
  fail "--in-diff-preflight takes only --root"; exit 1
fi
if [ -n "$in_diff" ]; then
  if [ "$mutants_mode" = "all" ]; then fail "--in-diff cannot be combined with --mutants-all"; exit 1; fi
  if [ "$mutants_mode" != "list" ]; then fail "--in-diff needs --mutants"; exit 1; fi
  if [ "$injection" -eq 1 ]; then fail "--in-diff cannot be combined with --injection"; exit 1; fi
fi

# ---- unrecognized-var scan (FIRST; zero-match tolerant; presence semantics) -
for v in $(compgen -v | grep '^COVERAGE_TIERS_' || true); do
  case "$v" in
    COVERAGE_TIERS_JSON|COVERAGE_TIERS_FILELIST|COVERAGE_TIERS_CRATE_DIRS) :;;
    *) fail "unrecognized COVERAGE_TIERS var: $v";;
  esac
done
if [ "$injection" -eq 0 ]; then
  for v in COVERAGE_TIERS_JSON COVERAGE_TIERS_FILELIST COVERAGE_TIERS_CRATE_DIRS; do
    if [ -n "${!v+x}" ]; then fail "$v is set without --injection (never silently ignored)"; fi
  done
fi
[ "$fail_n" -gt 0 ] && exit 1

# ---- root resolution --------------------------------------------------------
if [ -z "$root" ]; then
  if ! root="$(env -u GIT_DIR -u GIT_WORK_TREE git rev-parse --show-toplevel 2>/dev/null)"; then
    fail "cannot resolve --root (not in a git repo and no --root given)"; exit 1
  fi
fi

if { [ -n "$in_diff" ] || [ "$preflight" -eq 1 ]; } && ! root="$(CDPATH='' cd -P -- "$root" && pwd -P)"; then
  fail "--in-diff: --root does not resolve to a directory"; exit 1
fi
if { [ -n "$in_diff" ] || [ "$preflight" -eq 1 ]; } &&
   ! problem="$(python3 "$here/mutation-diff.py" config-guard "$root" HEAD 2>&1)"; then
  printf '%s\n' "${problem:-FAIL: --in-diff: the config guard printed nothing}"; exit 1
fi
if [ "$preflight" -eq 1 ]; then
  echo "PASS: --in-diff preflight"; exit 0
fi

# ---- injection-in-work-tree refusal ----------------------------------------
if [ "$injection" -eq 1 ]; then
  if ! command -v git >/dev/null 2>&1; then
    fail "git missing at the injection refusal check (fail closed)"; exit 1
  fi
  if [ "$(env -u GIT_DIR -u GIT_WORK_TREE git -C "$root" rev-parse --is-inside-work-tree 2>/dev/null || true)" = "true" ]; then
    fail "--injection refused: $root is inside a git work tree"; exit 1
  fi
  if [ -z "${COVERAGE_TIERS_JSON+x}" ] || [ -z "${COVERAGE_TIERS_FILELIST+x}" ]; then
    fail "--injection requires COVERAGE_TIERS_JSON and COVERAGE_TIERS_FILELIST together"; exit 1
  fi
  if [ "$mutants_mode" != "" ] && [ -z "${COVERAGE_TIERS_CRATE_DIRS+x}" ]; then
    fail "mutation stage under --injection requires COVERAGE_TIERS_CRATE_DIRS (the name oracle)"; exit 1
  fi
fi

# ---- CRATE_DIRS pair grammar ------------------------------------------------
declare -A crate_dir_map=()
if [ -n "${COVERAGE_TIERS_CRATE_DIRS+x}" ]; then
  IFS=',' read -r -a _pairs <<<"$COVERAGE_TIERS_CRATE_DIRS"
  for pair in "${_pairs[@]}"; do
    if ! printf '%s' "$pair" | grep -Eq '^[A-Za-z0-9_-]+=[^,]+$'; then
      fail "malformed COVERAGE_TIERS_CRATE_DIRS element: $pair"; continue
    fi
    name="${pair%%=*}"; dir="${pair#*=}"
    if [ -n "${crate_dir_map[$name]+x}" ]; then fail "duplicate name in COVERAGE_TIERS_CRATE_DIRS: $name"; fi
    crate_dir_map["$name"]="$dir"
  done
  [ "$fail_n" -gt 0 ] && exit 1
fi

# ---- readiness (presence/version only; stage-scoped; verify-then-run) -------
need_default=1
[ "$mutants_mode" != "" ] && need_default=0     # --mutants* selects EXCLUSIVELY
readiness_fail=0
r_fail() { fail "readiness: $1"; readiness_fail=1; }

check_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    r_fail "python3 missing — install python3 >= 3.11"; return
  fi
  if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' 2>/dev/null; then
    r_fail "python3 < 3.11 (stdlib tomllib needed) — install python3 >= 3.11"
  fi
}

if [ "$need_default" -eq 1 ]; then
  # partition: git presence (suppressed when FILELIST injected)
  if [ -z "${COVERAGE_TIERS_FILELIST+x}" ] && ! command -v git >/dev/null 2>&1; then
    r_fail "git missing — install git"
  fi
  # coverage tools (suppressed when JSON injected)
  if [ -z "${COVERAGE_TIERS_JSON+x}" ]; then
    if [ ! -f "$root/rust-toolchain.toml" ]; then
      r_fail "no $root/rust-toolchain.toml (pinned toolchain probe) — add a rust-toolchain.toml pinning the channel"
    else
      want="$(grep -E '^channel' "$root/rust-toolchain.toml" | sed 's/.*"\(.*\)".*/\1/' || true)"
      if [ -z "$want" ]; then
        r_fail "cannot parse channel from $root/rust-toolchain.toml (an empty want would match ANY toolchain — fail closed)"
        want="__UNPARSEABLE__"
      fi
      active="$(cd "$root" && RUSTUP_AUTO_INSTALL=0 rustup show active-toolchain 2>/dev/null || true)"
      case "$active" in
        "$want"*) :;;
        *) r_fail "active toolchain '$active' != pinned '$want' — rustup toolchain install $want";;
      esac
      if ! (cd "$root" && rustup component list 2>/dev/null | grep -Eq '^llvm-tools.*\(installed\)'); then
        r_fail "llvm-tools component missing — rustup component add llvm-tools"
      fi
    fi
    if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
      r_fail "cargo-llvm-cov missing — cargo install cargo-llvm-cov --locked --version '^0.8'"
    fi
  fi
  # sync: cargo presence on live roots only
  if [ "$injection" -eq 0 ] && ! command -v cargo >/dev/null 2>&1; then
    r_fail "cargo missing (workflow-sync name oracle) — install rustup/cargo"
  fi
  check_python
else
  if ! command -v cargo-mutants >/dev/null 2>&1; then
    r_fail "cargo-mutants missing — cargo install cargo-mutants --locked"
  fi
  if [ "$mutants_mode" = "all" ] || [[ " ${mutant_crates[*]} " == *" maknae-io "* ]]; then
    nextest_out="$(cd "$root" && cargo nextest --version 2>&1 || true)"
    nextest_v="$(printf '%s\n' "$nextest_out" | grep -m1 '^cargo-nextest ' || true)"
    case "$nextest_v" in
      "cargo-nextest 0.9.146"|"cargo-nextest 0.9.146 "*) :;;
      "") r_fail "cargo-nextest missing (cargo nextest --version: $(printf '%s' "$nextest_out" | head -1)) — install cargo-nextest 0.9.146 (the version CI pins)";;
      *) r_fail "'$nextest_v' is not cargo-nextest 0.9.146 (the version CI pins)";;
    esac
  fi
  if [ "$injection" -eq 0 ] && ! command -v cargo >/dev/null 2>&1; then
    r_fail "cargo missing (mutation name oracle) — install rustup/cargo"
  fi
  check_python
fi
if [ "$readiness_fail" -eq 1 ]; then exit 1; fi
if [ "$readiness_only" -eq 1 ]; then echo "PASS: readiness"; exit 0; fi

toml="$root/coverage-tiers.toml"
if [ ! -f "$toml" ]; then fail "missing contract: $toml"; exit 1; fi

# ---- env_bound lane resolution (spec §5: rustc -vV host triple, mapped) -----
# Runs ONLY when the contract has env_bound users — a contract without them
# never invokes rustc (injection roots stay cargo/rustc-free at adoption).
has_env_bound=0
if grep -q 'env_bound' "$toml"; then has_env_bound=1; fi
export COVERAGE_LANE_OS=""
if [ "$has_env_bound" -eq 1 ]; then
  if ! command -v rustc >/dev/null 2>&1; then
    fail "env_bound entries present but rustc missing (lane resolution) — install rustup"
  else
    host_line="$(rustc -vV 2>/dev/null | grep '^host:' || true)"
    if [ -z "$host_line" ]; then
      fail "cannot read host triple from rustc -vV (lane resolution)"
    else
      case "$host_line" in
        *-apple-darwin*)            COVERAGE_LANE_OS="macos";;
        *-linux-gnu*|*-linux-musl*) COVERAGE_LANE_OS="linux";;
        *-windows-*)                COVERAGE_LANE_OS="windows";;
        *) fail "unmapped host triple for env_bound lane resolution: ${host_line#host: } (a floor-bearing env_bound file must never become silently never-enforced)";;
      esac
    fi
  fi
  [ "$fail_n" -gt 0 ] && { printf '%d violation(s).\n' "$fail_n"; exit 1; }
fi

# ---- name oracle + sync helper ---------------------------------------------
resolve_crate_dirs() { # [<workspace dir>]
  # populates crate_dir_map from cargo metadata on live roots (injection map already loaded)
  [ "$injection" -eq 1 ] && return 0
  local meta ws="${1:-$root}"
  if ! meta="$(cd "$ws" && cargo metadata --manifest-path "$ws/Cargo.toml" --no-deps --format-version 1)"; then
    return 1
  fi
  local parsed
  if ! parsed="$(printf '%s' "$meta" | python3 -c '
import json, os, sys
m = json.load(sys.stdin)
root = os.path.realpath(sys.argv[1])
for p in m["packages"]:
    d = os.path.relpath(os.path.realpath(os.path.dirname(p["manifest_path"])), root)
    print(p["name"] + "\t" + d)
' "$ws")"; then
    return 1
  fi
  while IFS=$'\t' read -r name dir; do
    [ -n "$name" ] && crate_dir_map["$name"]="$dir"
  done <<<"$parsed"
  return 0
}

toml_mutants_crates() {
  python3 - "$toml" <<'PYEOF'
import sys, tomllib
try:
    with open(sys.argv[1], "rb") as f:
        c = tomllib.load(f)
except (OSError, tomllib.TOMLDecodeError) as e:
    print(f"unparseable: {e}", file=sys.stderr)
    sys.exit(1)
mc = c.get("t1", {}).get("mutants_crates")
if not isinstance(mc, list) or not all(isinstance(x, str) for x in mc):
    print("mutants_crates missing or not a list of strings", file=sys.stderr)
    sys.exit(1)
for name in mc:
    print(name)
PYEOF
}

# mutants_features contract validation (#77) — in the PROLOGUE deliberately:
# the default and --mutants-all lanes are mutually exclusive, and each lane's
# other checks are lane-local, so this is the one region BOTH execute. Oracle
# is toml-self-contained (no cargo metadata — the synthetic fixtures in
# ci/gates/tests/coverage-tiers/ carry no crate map): every key must appear in
# [t1].mutants_crates; every value must be a list of strings; absent is legal.
if ! python3 - "$toml" <<'PYEOF'
import sys, tomllib
try:
    with open(sys.argv[1], "rb") as f:
        c = tomllib.load(f)
except (OSError, tomllib.TOMLDecodeError):
    # Parse validity is owned by each lane's own reader (with its own
    # message); this contract check only speaks about a PARSEABLE table.
    sys.exit(0)
t1 = c.get("t1", {})
mf = t1.get("mutants_features")
if mf is None:
    sys.exit(0)
if not isinstance(mf, dict):
    print("FAIL: [t1].mutants_features must be a table of crate -> feature list")
    sys.exit(1)
mc = set(t1.get("mutants_crates") or [])
rc = 0
for k, v in mf.items():
    if k not in mc:
        print(f"FAIL: mutants_features names '{k}', which is not in [t1].mutants_crates")
        rc = 1
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        print(f"FAIL: mutants_features['{k}'] must be a list of strings")
        rc = 1
sys.exit(rc)
PYEOF
then
  fail "mutants_features contract violated (see FAIL lines above)"
  exit 1
fi

toml_mutants_features_for() { # crate-name -> newline-separated features (may be empty)
  python3 - "$toml" "$1" <<'PYEOF'
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    c = tomllib.load(f)
for feat in (c.get("t1", {}).get("mutants_features") or {}).get(sys.argv[2], []):
    print(feat)
PYEOF
}

# ---- default stages ---------------------------------------------------------
if [ "$need_default" -eq 1 ]; then
  # universe
  if [ -n "${COVERAGE_TIERS_FILELIST+x}" ]; then
    universe_file="$COVERAGE_TIERS_FILELIST"
  else
    # Released on EVERY exit path, including the two `exit 1`s below and the
    # fail-closed exits further down (#302). This leaked one temp file per run
    # — small individually, and it is how the class of problem starts: /tmp
    # filling is what silently turned this gate's own mutation stage into a
    # vacuous pass (#301). Only set when WE allocate; an injected
    # COVERAGE_TIERS_FILELIST belongs to the caller and must not be deleted.
    universe_file="$(mktemp "${TMPDIR:-/tmp}/maknae-covtiers.XXXXXXXX")"
    trap 'rm -f -- "$universe_file"' EXIT INT TERM
    if ! env -u GIT_DIR -u GIT_WORK_TREE git -C "$root" ls-files '*.rs' >"$universe_file"; then
      fail "git ls-files failed enumerating the universe"; exit 1
    fi
  fi
  if [ ! -s "$universe_file" ]; then fail "empty universe file-list"; exit 1; fi

  # coverage json
  if [ -n "${COVERAGE_TIERS_JSON+x}" ]; then
    cov_json="$COVERAGE_TIERS_JSON"
    run_helper=1
  else
    rm -f "$root/target/coverage.json"
    if (cd "$root" && cargo llvm-cov --locked --workspace --all-features --json --output-path target/coverage.json); then
      cov_json="$root/target/coverage.json"
      run_helper=1
    else
      fail "coverage run failed"
      run_helper=0
    fi
  fi

  if [ "$run_helper" -eq 1 ]; then
    if ! python3 "$here/coverage_check.py" "$toml" "$cov_json" "$root" <"$universe_file"; then
      fail "coverage tier evaluation failed (see FAIL lines above)"
    fi
  fi

  # workflow-sync stage
  wf="$root/.github/workflows/ci.yml"
  run_sync=0
  if [ "$injection" -eq 1 ]; then
    if [ -n "${COVERAGE_TIERS_CRATE_DIRS+x}" ] && [ -f "$wf" ]; then run_sync=1; fi
  else
    if [ ! -f "$wf" ]; then
      fail "missing $wf on a live root (deleting/renaming ci.yml must not disable the sync check)"
    else
      run_sync=1
      if ! resolve_crate_dirs; then
        fail "cannot resolve mutants_crates dirs"
        run_sync=0
      fi
    fi
  fi
  if [ "$run_sync" -eq 1 ]; then
    mapfile -t mp_lines < <(grep -E '^[[:space:]]*MUTANTS_PATHS:' "$wf" || true)
    if [ "${#mp_lines[@]}" -eq 0 ]; then
      fail "MUTANTS_PATHS: line absent from $wf while the sync stage runs (zero-match)"
    elif [ "${#mp_lines[@]}" -gt 1 ]; then
      fail "multiple MUTANTS_PATHS: lines in $wf"
    else
      raw="${mp_lines[0]#*MUTANTS_PATHS:}"
      raw="$(printf '%s' "$raw" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^"//; s/"$//')"
      declared="$(printf '%s' "$raw" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | sort -u)"
      expected=""
      while IFS= read -r cname; do
        [ -z "$cname" ] && continue
        if [ -z "${crate_dir_map[$cname]+x}" ]; then
          fail "unknown crate in mutants_crates: $cname"
        else
          expected="$expected${crate_dir_map[$cname]}"$'\n'
        fi
      done < <(toml_mutants_crates)
      expected="$(printf '%s' "$expected" | sed '/^$/d' | sort -u)"
      if [ "$declared" != "$expected" ]; then
        fail "MUTANTS_PATHS drift: workflow declares [$(printf '%s' "$declared" | tr '\n' ' ')] but mutants_crates derive [$(printf '%s' "$expected" | tr '\n' ' ')]"
      fi
    fi
  fi
fi

# ---- mutation stage ---------------------------------------------------------
# The mutation run's exit status is not a sufficient oracle: an all-unviable run
# exits 0, so this gate once passed the zero-missed contract having tested
# nothing (#301). `mutation-oracle.sh` carries both halves of the answer — room
# to run before, and did-it-measure-anything after — as a separate script so
# negative-control.sh can probe them without a 45-minute mutation run.
oracle="$here/mutation-oracle.sh"
terminated_list="$here/mutation-terminated.txt"

# A mutant whose test phase has a nextest TIMEOUT and no failure status was caught
# only by termination; it passes only when an entry for this `uname -s` names it.
terminated_only() { # <mutants --output dir> <crate>
  local base="$1"
  [ -f "$base/mutants.out/outcomes.json" ] && base="$base/mutants.out"
  python3 - "$terminated_list" "$base" "$2" "$(uname -s)" <<'PYEOF'
import json, os, re, sys
from collections import Counter
listing, base, cname, system = sys.argv[1:]
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
STATUS = re.compile(r"\s*(?:TRY \d+ )?([A-Z][A-Z-]*)(?: \+ LEAK)?\s+\[[^\]]*\]\s*(.*)")
CAPTURED = re.compile(r"\s+(?:stdout|stderr|output) ───")
rc = 0
entries = []
try:
    with open(listing) as f:
        rows = f.read().splitlines()
except OSError as e:
    print(f"FAIL: {cname}: cannot read the reviewed terminated-mutant list: {e}")
    sys.exit(1)
for n, row in enumerate(rows, 1):
    if not row.strip() or row.startswith("#"):
        continue
    fields = row.split("\t")
    where = f"FAIL: {listing}:{n}:"
    if (len(fields) != 5 or fields[0] not in ("Linux", "Darwin")
            or not all(x.strip() for x in fields[1:])):
        print(f"{where} expected <Linux|Darwin>\\t<file>\\t<function>\\t<replacement-regex>\\t<reason>")
    else:
        try:
            entries.append((fields[0], fields[1], fields[2], re.compile(fields[3]), row))
            continue
        except re.error as e:
            print(f"{where} bad regex: {e}")
    rc = 1
try:
    with open(os.path.join(base, "outcomes.json")) as f:
        d = json.load(f)
    outcomes = d["outcomes"]
    viable = d["caught"] + d["missed"] + d["timeout"]
    ran = Counter(o["scenario"]["Mutant"]["name"] for o in outcomes if o["scenario"] != "Baseline")
    with open(os.path.join(base, "mutants.json")) as f:
        planned = Counter(m["name"] for m in json.load(f))
except (OSError, ValueError, KeyError, TypeError) as e:
    print(f"FAIL: {cname}: cannot read the outcomes in outcomes.json and the plan in mutants.json: {e!r}")
    sys.exit(1)
if ran != planned:
    print(f"FAIL: {cname}: outcomes.json covers {sum(ran.values())} mutants but mutants.json plans "
          f"{sum(planned.values())} (differing: {sorted(((ran - planned) + (planned - ran)).elements())[:3]}), "
          f"so termination cannot be judged")
    sys.exit(1)
found, tested, judged = [], 0, 0
for o in outcomes:
    try:
        m = None if o["scenario"] == "Baseline" else o["scenario"]["Mutant"]
        name = "baseline" if m is None else m["name"]
        phases = [r["phase"] for r in o["phase_results"]]
        path = os.path.join(base, o["log_path"])
    except (KeyError, TypeError) as e:
        print(f"FAIL: {cname}: malformed outcome {o!r:.200}: {e!r}")
        rc = 1
        continue
    if "Test" not in phases:
        continue
    judged += 1
    header = summary = timeout = failed = captured = False
    testing = False
    failed_tests, timed_out_tests = set(), set()
    try:
        with open(path, errors="replace") as f:
            for raw in f:
                line = ANSI.sub("", raw)
                if line.startswith("*** "):
                    testing = " nextest run " in line and "--no-run" not in line
                    header |= testing
                    continue
                if not testing:
                    continue
                captured |= CAPTURED.match(line) is not None
                if re.match(r"\s*Summary \[", line):
                    summary = line
                    continue
                st = STATUS.match(line)
                if st:
                    status, test = st.group(1), st.group(2).rstrip()
                    timeout |= status == "TIMEOUT"
                    failed |= status in ("FAIL", "ABORT", "LEAK-FAIL") or (
                        status.startswith("SIG") and status not in ("SIGTERM", "SIGKILL"))
                    if status == "TIMEOUT":
                        timed_out_tests.add(test)
                    elif status in ("FAIL", "ABORT", "LEAK-FAIL") or status.startswith("SIG"):
                        failed_tests.add(test)
    except OSError as e:
        print(f"FAIL: {cname}: {name}: cannot read its log: {e}")
        rc = 1
        continue
    if not (header and summary):
        print(f"FAIL: {cname}: {name}: its test phase has no nextest run header or no "
              f"Summary line in {path}, so termination cannot be judged")
        rc = 1
        continue
    if captured:
        print(f"FAIL: {cname}: {name}: captured test output in {path}; the nextest "
              f"`mutants` profile was not applied, so status lines cannot be trusted")
        rc = 1
        continue
    reported = {kind: int(n.group(1)) if n else 0 for kind in ("failed", "timed out")
                for n in [re.search(r"(\d+) " + kind + r"\b", summary)]}
    shortfall = [f"{reported[k]} {k} but {len(seen)} such status lines"
                 for k, seen in (("failed", failed_tests), ("timed out", timed_out_tests))
                 if len(seen) < reported[k]]
    if shortfall:
        print(f"FAIL: {cname}: {name}: its Summary reports {'; '.join(shortfall)} in {path}")
        rc = 1
        continue
    if m is None and (reported["failed"] or reported["timed out"]):
        print(f"FAIL: {cname}: baseline: its Summary reports {reported['failed']} failed and "
              f"{reported['timed out']} timed out in {path}")
        rc = 1
        continue
    if o.get("summary") == "CaughtMutant" and not (failed or timeout):
        print(f"FAIL: {cname}: {name}: caught, but its test phase has no failure or timeout "
              f"status line in {path}")
        rc = 1
        continue
    tested += 1
    if timeout and not failed:
        found.append(m)
if judged != viable + 1:
    print(f"FAIL: {cname}: judged {judged} test phases, but outcomes.json counts {viable} viable "
          f"mutants plus the baseline, so termination cannot be judged")
    rc = 1
fired = set()
for m in found:
    if m is None:
        print(f"FAIL: {cname}: the baseline was caught only by termination")
        rc = 1
        continue
    fn = (m.get("function") or {}).get("function_name")
    hits = [row for p, file, func, rx, row in entries
            if p == system and file == m.get("file") and func == fn
            and rx.fullmatch(m.get("replacement") or "")]
    fired.update(hits)
    print(f"terminated-only[{cname}]: {m['name']} ({'reviewed' if hits else 'UNREVIEWED'})")
    if not hits:
        print(f"FAIL: {cname}: {m['name']} was caught only by termination and matches no {system} entry")
        rc = 1
for p, _, _, _, row in entries:
    if p == system and row not in fired:
        print(f"terminated-only[{cname}]: entry {row!r} not observed")
print(f"terminated-only[{cname}]: {len(found)} of {tested} tested outcomes")
sys.exit(rc)
PYEOF
}

if [ "$mutants_mode" != "" ]; then
  if [ "$mutants_mode" = "all" ]; then
    # contract-shape validation of the key this stage reads (fail closed:
    # unparseable toml, non-list, or EMPTY mutants_crates must never yield a
    # green mutation job doing nothing)
    if ! crates_out="$(toml_mutants_crates)"; then
      fail "cannot read mutants_crates from $toml (unparseable contract)"
      printf '%d violation(s).\n' "$fail_n"; exit 1
    fi
    mapfile -t mutant_crates <<<"$crates_out"
    if [ "${#mutant_crates[@]}" -eq 0 ] || [ -z "${mutant_crates[0]}" ]; then
      fail "mutants_crates is empty or missing — the mutation gate would be a no-op claiming assurance"
      printf '%d violation(s).\n' "$fail_n"; exit 1
    fi
  fi
  oracle_ok=1
  if [ "$injection" -eq 0 ]; then
    if ! resolve_crate_dirs; then
      fail "cannot resolve mutants_crates package names (mutation stage)"
      oracle_ok=0
    fi
  fi
  if ! mut_tmp="$(mktemp -d "${TMPDIR:-/tmp}/maknae-mutants.XXXXXXXX")"; then
    fail "cannot create the mutation scratch dir under ${TMPDIR:-/tmp}"
    printf '%d violation(s).\n' "$fail_n"; exit 1
  fi
  # Tests killed by nextest never run their TempDir drops, and some leave mode-000 dirs.
  trap 'chmod -R u+rwx -- "$mut_tmp" 2>/dev/null || true; rm -rf -- "$mut_tmp"' EXIT
  mut_pid=""
  stop_run() { # <signal> <status>
    if [ -n "$mut_pid" ]; then kill -s "$1" "$mut_pid" 2>/dev/null || true; wait "$mut_pid" 2>/dev/null || true; fi
    exit "$2"
  }
  trap 'stop_run INT 130' INT
  trap 'stop_run TERM 143' TERM
  # Stop before the loop when the scratch volume cannot hold a build (#301): whenever real
  # builds run, and under --injection only when a fixture declares MUTATION_ORACLE_MIN_KIB.
  if [ "$injection" -eq 0 ] || [ -n "${MUTATION_ORACLE_MIN_KIB:-}" ]; then
    if ! out="$(bash "$oracle" scratch "$mut_tmp" 2>&1)"; then
      fail "mutation scratch volume unusable: $out"
      printf '%d violation(s).\n' "$fail_n"; exit 1
    fi
  fi
  declare -A in_scope=()
  in_diff_file=""
  mut_dir="$root"
  if [ -n "$in_diff" ]; then
    in_git() { env "${in_diff_git_env[@]}" git -C "$root" "$@"; }
    toplevel="$(in_git rev-parse --show-toplevel 2>/dev/null || true)"
    if [ -z "$toplevel" ] || [ "$(cd -P "$toplevel" && pwd)" != "$(cd -P "$root" && pwd)" ]; then
      printf 'FAIL: --in-diff needs --root at the git toplevel (%s is not)\n' "$root"; exit 1
    fi
    if ! problem="$(python3 "$here/mutation-diff.py" history "$root" 2>&1)"; then
      printf 'FAIL: --in-diff: %s\n' "${problem:-the history check printed nothing}"; exit 1
    fi
    if ! rev_oid="$(in_git rev-parse --verify --quiet --end-of-options "$in_diff^{commit}")" || [ -z "$rev_oid" ]; then
      printf 'FAIL: --in-diff: %s is not a commit\n' "$in_diff"; exit 1
    fi
    if ! head_oid="$(in_git rev-parse --verify --quiet 'HEAD^{commit}')" || [ -z "$head_oid" ]; then
      printf 'FAIL: --in-diff: HEAD is not a commit\n'; exit 1
    fi
    if ! base="$(in_git merge-base --end-of-options "$rev_oid" "$head_oid")" || [ -z "$base" ]; then
      printf 'FAIL: --in-diff: no merge base between %s and HEAD\n' "$in_diff"; exit 1
    fi
    if ! dirty="$(in_git status --porcelain --untracked-files=all)"; then
      printf 'FAIL: --in-diff: git status failed in %s\n' "$root"; exit 1
    fi
    if [ -n "$dirty" ]; then
      printf 'FAIL: --in-diff attests to HEAD; uncommitted or untracked: %s\n' \
        "$(printf '%s\n' "$dirty" | cut -c4- | tr '\n' ' ')"; exit 1
    fi
    snap="$mut_tmp/snapshot"
    if ! out="$(python3 "$here/mutation-diff.py" snapshot "$root" "$head_oid" "$snap" 2>&1)"; then
      printf 'FAIL: --in-diff: cannot snapshot HEAD: %s\n' "$out"; exit 1
    fi
    attested=(coverage-tiers.toml)
    if [ "$(cd -P "$here" && pwd)" = "$(cd -P "$root" && pwd)/ci/gates" ]; then
      attested+=(ci/affected.py ci/gates/coverage-tiers.sh ci/gates/mutation-oracle.sh
                 ci/gates/mutation-platform.sh ci/gates/mutation-diff.py ci/gates/mutation-terminated.txt)
    fi
    for rel in "${attested[@]}"; do
      if { [ -e "$root/$rel" ] || [ -e "$snap/$rel" ]; } && ! cmp -s -- "$root/$rel" "$snap/$rel"; then
        printf 'FAIL: --in-diff: %s in the working tree is not HEAD'"'"'s\n' "$rel"; exit 1
      fi
    done
    toml="$snap/coverage-tiers.toml"
    mut_dir="$snap"
    crate_dir_map=()
    if resolve_crate_dirs "$snap"; then oracle_ok=1; else oracle_ok=0; fi
    in_diff_file="$mut_tmp/in.diff"
    if ! in_diff_generate "$base" "$in_diff_file" "$head_oid"; then
      printf 'FAIL: --in-diff: git diff %s HEAD failed\n' "$base"; exit 1
    fi
    if ! changed_paths="$(python3 "$here/mutation-diff.py" paths "$root" "$base" "$in_diff_file" "$head_oid" 2>&1)"; then
      printf 'FAIL: --in-diff: the diff does not name the changed Rust files: %s\n' "$changed_paths"; exit 1
    fi
    if ! scope="$(python3 "$here/mutation-diff.py" scope "$root" "$base" "$head_oid" "$snap" 2>"$mut_tmp/scope.err")" ||
       ! scope_lines="$(printf '%s' "$scope" | python3 -c '
import json, sys
crates = json.load(sys.stdin)
if not (isinstance(crates, list) and all(isinstance(c, str) for c in crates)):
    sys.exit(1)
print("\n".join(crates))' 2>/dev/null)"; then
      printf 'FAIL: --in-diff: mutation scope cannot be computed: %s %s\n' "$scope" "$(cat "$mut_tmp/scope.err")"; exit 1
    fi
    while IFS= read -r c; do [ -n "$c" ] && in_scope["$c"]=1; done <<<"$scope_lines"
    if ! crates_out="$(toml_mutants_crates)"; then
      printf 'FAIL: --in-diff: cannot read mutants_crates from %s\n' "$toml"; exit 1
    fi
    declare -A selected=() contract=()
    while IFS= read -r c; do [ -n "$c" ] && contract["$c"]=1; done <<<"$crates_out"
    for c in "${mutant_crates[@]}"; do
      if [ -z "${contract[$c]+x}" ]; then
        printf 'FAIL: --in-diff: --mutants names %s, which is not in [t1].mutants_crates\n' "$c"; exit 1
      fi
      selected["$c"]=1
    done
    for c in "${!in_scope[@]}"; do
      if [ -z "${selected[$c]+x}" ]; then
        printf 'FAIL: --in-diff: scope crate %s not selected by --mutants\n' "$c"; exit 1
      fi
    done
    if [ "$oracle_ok" -ne 1 ]; then
      printf 'FAIL: --in-diff: changed files cannot be mapped to crates without cargo metadata\n'; exit 1
    fi
    if ! problem="$(python3 "$here/mutation-diff.py" unmappable "$root" "$head_oid" "$snap" 2>&1)"; then
      printf '%s\n' "${problem:-FAIL: --in-diff: the unmappable-shape check printed nothing}"; exit 1
    fi
    compiled_file="$mut_tmp/compiled.json"
    if ! python3 "$here/mutation-diff.py" compiled "$root" "$base" "$head_oid" "$snap" "$mut_tmp/depinfo" \
         >"$compiled_file" 2>"$mut_tmp/compiled.err" ||
       ! owned_lines="$(python3 -c '
import json, sys
crates = json.load(open(sys.argv[1]))
if not (isinstance(crates, dict) and all(isinstance(c, str) for c in crates)):
    sys.exit(1)
print("\n".join(sorted(crates)))' "$compiled_file" 2>/dev/null)"; then
      printf 'FAIL: --in-diff: compiled inputs cannot be computed: %s\n' "$(cat "$mut_tmp/compiled.err")"; exit 1
    fi
    embeds_file="$mut_tmp/embeds.json"
    if ! python3 "$here/mutation-diff.py" embeds "$root" "$base" "$head_oid" "$snap" "$mut_tmp/depinfo" \
         >"$embeds_file" 2>"$mut_tmp/embeds.err"; then
      printf 'FAIL: --in-diff: include sites cannot be scanned: %s\n' "$(cat "$mut_tmp/embeds.err")"; exit 1
    fi
    if ! indirect="$(python3 -c '
import json, sys
data = json.load(open(sys.argv[1]))
if not (isinstance(data, dict) and (data.get("indirect") is None or isinstance(data["indirect"], str))):
    sys.exit(1)
print(data["indirect"] or "")' "$embeds_file" 2>/dev/null)"; then
      printf 'FAIL: --in-diff: unreadable include-site list %s\n' "$embeds_file"; exit 1
    fi
    declare -A touched=()
    while IFS= read -r c; do
      [ -z "$c" ] && continue
      if [ -z "${selected[$c]+x}" ]; then
        printf 'FAIL: --in-diff: changed crate %s not selected by --mutants\n' "$c"; exit 1
      fi
      touched["$c"]=1
    done <<<"$owned_lines"
    if [ ! -s "$in_diff_file" ] && [ "${#in_scope[@]}" -eq 0 ] && [ "${#touched[@]}" -eq 0 ] && [ -z "$indirect" ]; then
      printf 'SKIP: in-diff: no Rust change between %s and HEAD\n' "$base"
      mutant_crates=()
    fi
  fi
  if ! mkdir -p -- "$root/target"; then
    fail "cannot create $root/target for the mutation output"
    printf '%d violation(s).\n' "$fail_n"; exit 1
  fi
  for cname in "${mutant_crates[@]}"; do
    [ -z "$cname" ] && continue
    if [ -z "${crate_dir_map[$cname]+x}" ]; then
      if [ "$oracle_ok" -eq 1 ]; then
        fail "unknown crate in mutants_crates: $cname"
      fi
      continue
    fi
    # Crates carrying feature-gated seam code (#85/#77): under default
    # features it is compiled OUT, so its mutants land in dead code and are
    # UNKILLABLE MISSED (the 2026-08-27 main-red). The per-crate feature list
    # is DECLARED in [t1].mutants_features (validated in the prologue) — the
    # in-crate tests are the killers; prove-it-can-go-red, never an exclusion.
    extra_mutants_flags=()
    while IFS= read -r feat; do
      [ -n "$feat" ] && extra_mutants_flags+=(--features "$feat")
    done < <(toml_mutants_features_for "$cname")
    if [ "$cname" = "maknae-io" ] || [ "$cname" = "maknae-sys" ]; then
      if ! native_exclusion="$(bash "$here/mutation-platform.sh")"; then
        fail "cannot select native syscall mutants"; continue
      fi
      extra_mutants_flags+=(--exclude-re "$native_exclusion")
    fi
    run_env=()
    if [ "$cname" = "maknae-io" ]; then
      extra_mutants_flags+=(--minimum-test-timeout 60 --test-tool nextest)
      for v in $(compgen -e | grep '^NEXTEST_' || true); do run_env+=(-u "$v"); done
      run_env+=(-u CLICOLOR_FORCE NEXTEST_PROFILE=mutants CARGO_TERM_COLOR=never NEXTEST_RETRIES=0
                NEXTEST_STATUS_LEVEL=fail NEXTEST_FINAL_STATUS_LEVEL=fail)
    fi
    run_env+=(TMPDIR="$mut_tmp")
    diff_flags=()
    judge_flags=()
    if [ -n "$in_diff" ]; then
      whole=0
      if [ -n "$indirect" ]; then
        printf 'whole: %s: include_str/include_bytes used indirectly in %s\n' "$cname" "$indirect"
        whole=1
      elif [ -n "${in_scope[$cname]+x}" ]; then
        printf 'whole: %s: mutation scope changed\n' "$cname"
        whole=1
      elif [ -n "${touched[$cname]+x}" ]; then
        if ! (cd "$mut_dir" && exec env "${run_env[@]}" cargo mutants --package "$cname" --list-files --json "${extra_mutants_flags[@]}") >"$mut_tmp/files.json"; then
          fail "cargo mutants --list-files --package $cname failed"
          continue
        fi
        if ! walked="$(python3 "$here/mutation-diff.py" unlisted "$cname" "$mut_tmp/files.json" "$compiled_file" "$mut_dir" "$embeds_file" 2>&1)"; then
          printf '%s\n' "${walked:-FAIL: $cname: mutation-diff.py unlisted printed nothing}"
          fail_n=$((fail_n + 1))
          continue
        fi
        case "$walked" in
          "") ;;
          "whole: $cname: changed "* | "whole: $cname: include_str/include_bytes used indirectly in "* | \
          "whole: $cname: walked source "*)
            printf '%s\n' "$walked"; whole=1;;
          *) fail "$cname: mutation-diff.py unlisted printed no verdict: $walked"; continue;;
        esac
      fi
      if [ "$whole" -eq 1 ]; then
        :
      elif [ ! -s "$in_diff_file" ]; then
        printf 'SKIP: %s: no Rust change between %s and HEAD\n' "$cname" "$base"
        continue
      else
        if ! (cd "$mut_dir" && exec env "${run_env[@]}" cargo mutants --package "$cname" --list --json "${extra_mutants_flags[@]}") >"$mut_tmp/whole.json" ||
           ! (cd "$mut_dir" && exec env "${run_env[@]}" cargo mutants --package "$cname" --in-diff "$in_diff_file" --list --json "${extra_mutants_flags[@]}") >"$mut_tmp/indiff.json"; then
          fail "cargo mutants --list --package $cname failed"
          continue
        fi
        if ! verdict="$(python3 "$here/mutation-diff.py" classify "$cname" "$in_diff_file" "$mut_tmp/whole.json" "$mut_tmp/indiff.json")"; then
          printf '%s\n' "${verdict:-FAIL: $cname: mutation-diff.py classify printed nothing}"
          fail_n=$((fail_n + 1))
          continue
        fi
        case "$verdict" in
          "RUN $cname: "*) printf '%s\n' "$verdict";;
          "SKIP: $cname: "*) printf '%s\n' "$verdict"; continue;;
          *) fail "$cname: mutation-diff.py classify printed no verdict: $verdict"; continue;;
        esac
        listed_n="${verdict#"RUN $cname: "}"
        listed_n="${listed_n%% *}"
        diff_flags=(--in-diff "$in_diff_file")
        judge_flags=(--in-diff --expect "$listed_n")
      fi
    fi
    # A per-crate output dir, so each crate's outcomes.json and per-mutant logs
    # survive for the two checks below instead of being overwritten by the next
    # crate in the loop.
    mut_out="$root/target/mutants-$cname"
    rm -rf "$mut_out"
    (cd "$mut_dir" && exec env "${run_env[@]}" cargo mutants --package "$cname" --output "$mut_out" "${diff_flags[@]}" "${extra_mutants_flags[@]}") &
    mut_pid=$!
    if ! wait "$mut_pid"; then
      fail "cargo mutants --package $cname reported missed/timeout mutants"
    fi
    mut_pid=""
    # The exit status above answers "were any mutants missed?". This answers
    # "did the run measure anything at all, and was it the mutations that failed
    # to build or the environment?" — a green exit code answers neither (#301).
    if ! out="$(bash "$oracle" judge "${judge_flags[@]}" "$mut_out" "$cname" 2>&1)"; then
      fail "mutation run for $cname cannot be trusted: $out"
    else
      printf '%s\n' "$out"
    fi
    if [ "$cname" = "maknae-io" ] && ! terminated_only "$mut_out" "$cname"; then
      fail "mutation run for $cname fails the terminated-mutant review (see FAIL lines above)"
    fi
  done
fi

if [ "$fail_n" -gt 0 ]; then
  printf '%d violation(s).\n' "$fail_n"
  exit 1
fi
echo "PASS: coverage-tiers gate"
