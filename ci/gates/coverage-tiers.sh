#!/usr/bin/env bash
# Risk-tiered coverage gate (ADR-0016, issue #24). Spec authority:
# 2026-08-04-coverage-tiers-design.md (out-of-repo design spec) (v18).
#
# Usage: coverage-tiers.sh [--root <path>] [--injection]
#                          [--mutants <crate>... | --mutants-all | --readiness-check]
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
here="$(cd "$(dirname "$0")" && pwd)"

fail_n=0
fail() { printf 'FAIL: %s\n' "$1"; fail_n=$((fail_n + 1)); }

# ---- argv ------------------------------------------------------------------
root=""
injection=0
readiness_only=0
mutants_mode=""      # "", "all", "list"
mutant_crates=()
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
    *) fail "unknown argument: $1"; exit 1;;
  esac
  shift
done

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
resolve_crate_dirs() {
  # populates crate_dir_map from cargo metadata on live roots (injection map already loaded)
  [ "$injection" -eq 1 ] && return 0
  local meta
  if ! meta="$(cd "$root" && cargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1)"; then
    return 1
  fi
  local parsed
  if ! parsed="$(printf '%s' "$meta" | python3 -c '
import json, os, sys
m = json.load(sys.stdin)
root = os.path.realpath(sys.argv[1])
for p in m["packages"]:
    d = os.path.relpath(os.path.dirname(p["manifest_path"]), root)
    print(p["name"] + "\t" + d)
' "$root")"; then
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
    universe_file="$(mktemp)"
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
    if (cd "$root" && cargo llvm-cov --workspace --all-features --json --output-path target/coverage.json); then
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
    if [ "$cname" = "maknae-io" ]; then
      if ! native_exclusion="$(bash "$here/mutation-platform.sh")"; then
        fail "cannot select native syscall mutants"; continue
      fi
      extra_mutants_flags+=(--exclude-re "$native_exclusion")
      # #238: eight independent five-second subprocess watchdogs reject a
      # nonadvancing write loop. With two libtest threads the suite takes ~23s
      # to fail, so the default 20s mutant timeout killed it before libtest could
      # return failure. Allow serial scheduling plus headroom; each child still
      # dies after five seconds, and missed/timeout outcomes still fail the gate.
      extra_mutants_flags+=(--minimum-test-timeout 60)
    fi
    if ! (cd "$root" && cargo mutants --package "$cname" "${extra_mutants_flags[@]}"); then
      fail "cargo mutants --package $cname reported missed/timeout mutants"
    fi
  done
fi

if [ "$fail_n" -gt 0 ]; then
  printf '%d violation(s).\n' "$fail_n"
  exit 1
fi
echo "PASS: coverage-tiers gate"
