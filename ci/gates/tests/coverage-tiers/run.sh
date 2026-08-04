#!/usr/bin/env bash
# Fixture suite for ci/gates/coverage-tiers.sh (ADR-0016 §7).
# Drives the REAL gate through every failure mode with MODE-IDENTIFYING
# assertions; the pass path asserts exit 0 + the exact (covered/total) row.
# One mktemp -d per fixture; fixture .rs trees materialized at run time;
# .json templates carry __FIXTURE_ROOT__ (substituted); filelists are
# repo-relative (never substituted). Every git invocation env -u guarded.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
gate="$here/../../coverage-tiers.sh"
repo_root="$(env -u GIT_DIR -u GIT_WORK_TREE git rev-parse --show-toplevel)"

pass_n=0; fail_n=0
ok()  { printf 'fixture-ok: %s\n' "$1"; pass_n=$((pass_n+1)); }
bad() { printf 'FIXTURE-FAIL: %s\n' "$1"; fail_n=$((fail_n+1)); }

newroot() { # one mktemp per fixture; must not sit inside a work tree
  local r; r="$(mktemp -d)"
  if [ "$(env -u GIT_DIR -u GIT_WORK_TREE git -C "$r" rev-parse --is-inside-work-tree 2>/dev/null || true)" = "true" ]; then
    echo "ABORT: TMPDIR is inside a git work tree — fixtures cannot run" >&2; exit 1
  fi
  printf '%s' "$r"
}

# expect <label> <expected-substring> <expected-rc(0|nonzero)> -- cmd...
expect() {
  local label="$1" want="$2" rc_kind="$3"; shift 3; [ "$1" = "--" ] && shift
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  if [ "$rc_kind" = "0" ]; then
    if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -qF "$want"; then ok "$label"; else
      bad "$label (rc=$rc)"; printf '%s\n' "$out" | tail -5; fi
  else
    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qF "$want"; then ok "$label"; else
      bad "$label (rc=$rc, wanted substring: $want)"; printf '%s\n' "$out" | tail -5; fi
  fi
}

# ---------- synthetic-universe builders (injection mode) ---------------------
# A minimal happy universe: one T1 file fully covered, contract conforming.
mk_json() { # mk_json <root> <file-rel> <covered0|1 per region line-start list...>
  local r="$1" rel="$2"; shift 2
  local regs="" first=1
  for spec in "$@"; do # spec = line:count
    local line="${spec%%:*}" cnt="${spec##*:}"
    [ "$first" -eq 0 ] && regs="$regs,"
    regs="$regs[$line,1,$line,20,$cnt,0,0,0]"
    first=0
  done
  cat >"$r/cov.json" <<EOF
{"type":"llvm.coverage.json.export","version":"3.0.1","data":[{"functions":[
 {"filenames":["__FIXTURE_ROOT__/$rel"],"regions":[$regs]}],"files":[]}]}
EOF
  python3 - "$r/cov.json" "$r" <<'PYEOF'
import sys
p, root = sys.argv[1], sys.argv[2]
s = open(p).read().replace("__FIXTURE_ROOT__", root)
open(p, "w").write(s)
PYEOF
}

mk_base() { # mk_base <root>  — happy injection fixture: t1 file 2/2 covered
  local r="$1"
  mkdir -p "$r/crates/x/src"
  cat >"$r/crates/x/src/core.rs" <<'EOF'
pub fn a() -> u32 { 1 }
pub fn b() -> u32 { 2 }
EOF
  printf 'crates/x/src/core.rs\n' >"$r/files.list"
  mk_json "$r" "crates/x/src/core.rs" "1:5" "2:7"
  cat >"$r/coverage-tiers.toml" <<'EOF'
[universe]
exclude = []
[t1]
floor_production_region = 95
files = ["crates/x/src/core.rs"]
mutants_crates = []
[t2]
floor_production_region = 90
files = []
[project]
ratchet_floor = 0
ratchet_cohort = []
[project.ratchet_provenance]
value = 0.0
date = "2026-08-04"
lane = "fixture"
command = "fixture"
EOF
}

inj() { # inj <root> [extra env pairs...] -- gate args...
  local r="$1"; shift
  local envs=(COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list")
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  env "${envs[@]}" "$gate" --root "$r" --injection "$@"
}

# ---------- pass path --------------------------------------------------------
r="$(newroot)"; mk_base "$r"
expect "pass-path (exit 0 + exact covered/total row)" "100.00% (2/2)" 0 -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" \
      "$gate" --root "$r" --injection

# ---------- partition modes --------------------------------------------------
r="$(newroot)"; mk_base "$r"; printf 'crates/x/src/extra.rs\n' >>"$r/files.list"
expect "unclassified file" "unclassified" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
python3 - "$r" <<'PYEOF'
import sys
r = sys.argv[1]
p = f"{r}/coverage-tiers.toml"
s = open(p).read().replace('files = ["crates/x/src/core.rs"]',
 'files = ["crates/x/src/core.rs", "crates/x/src/ghost.rs"]', 1)
open(p, "w").write(s)
PYEOF
expect "stale contract entry" "stale contract entry" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
python3 - "$r" <<'PYEOF'
import sys
r = sys.argv[1]
p = f"{r}/coverage-tiers.toml"
s = open(p).read().replace('[t2]\nfloor_production_region = 90\nfiles = []',
 '[t2]\nfloor_production_region = 90\nfiles = ["crates/x/src/core.rs"]', 1)
open(p, "w").write(s)
PYEOF
expect "double-classified file" "more than one tier" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"; : >"$r/files.list"
expect "empty universe" "empty universe" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

# excluded glob positive + near-miss pair
r="$(newroot)"; mk_base "$r"
python3 - "$r" <<'PYEOF'
import sys
r = sys.argv[1]
p = f"{r}/coverage-tiers.toml"
s = open(p).read().replace('exclude = []', 'exclude = ["crates/*/tests/**"]', 1)
open(p, "w").write(s)
PYEOF
printf 'crates/x/tests/it.rs\n' >>"$r/files.list"      # positive: excluded, no tier needed
expect "exclude glob positive (excluded test file needs no tier)" "PASS: coverage tiers" 0 -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection
printf 'crates/x/src/tests/nested.rs\n' >>"$r/files.list"  # near-miss: src-nested, NOT excluded
expect "exclude glob near-miss (src-nested tests/ hard-fails unclassified)" "unclassified" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

# ---------- floor modes ------------------------------------------------------
r="$(newroot)"; mk_base "$r"; mk_json "$r" "crates/x/src/core.rs" "1:5" "2:0"  # 1/2 = 50%
expect "sub-floor T1" "< T1 floor" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
python3 - "$r" <<'PYEOF'
import sys
r = sys.argv[1]
p = f"{r}/coverage-tiers.toml"
s = open(p).read()
s = s.replace('files = ["crates/x/src/core.rs"]\nmutants_crates = []', 'files = []\nmutants_crates = []', 1)
s = s.replace('[t2]\nfloor_production_region = 90\nfiles = []',
 '[t2]\nfloor_production_region = 90\nfiles = ["crates/x/src/core.rs"]', 1)
open(p, "w").write(s)
PYEOF
mk_json "$r" "crates/x/src/core.rs" "1:5" "2:0"
expect "sub-floor T2" "< T2 floor" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
sed -i.bak 's/ratchet_floor = 0/ratchet_floor = 99/; s/ratchet_cohort = \[\]/ratchet_cohort = ["crates\/x\/src\/core.rs"]/; s/value = 0.0/value = 99.0/' "$r/coverage-tiers.toml"
mk_json "$r" "crates/x/src/core.rs" "1:5" "2:7" "3:0" "4:0"  # 2/4 = 50% < 99
expect "cohort ratchet regression" "cohort ratchet" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
sed -i.bak 's/ratchet_floor = 0/ratchet_floor = 97.5/' "$r/coverage-tiers.toml"
expect "ratchet_floor float (int-only)" "must be an int" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
sed -i.bak 's/floor_production_region = 95/floor_production_region = 195/' "$r/coverage-tiers.toml"
expect "floor out of range" "0-100" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
sed -i.bak 's/ratchet_floor = 0/ratchet_floor = 50/' "$r/coverage-tiers.toml"  # floor>0, empty cohort
expect "floor-cohort emptiness violation" "empty ratchet_cohort" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

# ---------- provenance modes -------------------------------------------------
r="$(newroot)"; mk_base "$r"
python3 - "$r" <<'PYEOF'
import sys
r = sys.argv[1]
p = f"{r}/coverage-tiers.toml"
s = open(p).read()
s = s[:s.index("[project.ratchet_provenance]")]
open(p, "w").write(s)
PYEOF
expect "missing provenance table" "ratchet_provenance] table is required" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
sed -i.bak 's/lane = "fixture"/lane = ""/' "$r/coverage-tiers.toml"
expect "blank provenance field" "ratchet_provenance.lane" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
sed -i.bak 's/date = "2026-08-04"/date = 2026-08-04/' "$r/coverage-tiers.toml"  # unquoted TOML date
expect "mis-typed provenance field (TOML date, no traceback)" "ratchet_provenance.date" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
sed -i.bak 's/ratchet_floor = 0/ratchet_floor = 50/; s/ratchet_cohort = \[\]/ratchet_cohort = ["crates\/x\/src\/core.rs"]/; s/value = 0.0/value = 40.0/' "$r/coverage-tiers.toml"
expect "provenance value < floor" "< ratchet_floor" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

# ---------- exception modes --------------------------------------------------
mk_exc() { # mk_exc <root> <anchor-line-content-file> — adds exception to toml
  local r="$1" anchor="$2" extra="${3:-}"
  cat >>"$r/coverage-tiers.toml" <<EOF
[[exception]]
path = "crates/x/src/core.rs"
anchor = "$anchor"
$extra
why = "fixture rationale"
EOF
}
r="$(newroot)"; mk_base "$r"; mk_exc "$r" "no_such_text"
expect "zero-match anchor" "matches 0 lines" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"; mk_exc "$r" "pub fn"
expect "multi-match anchor" "matches 2 lines" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
printf '// bare comment line\n' >>"$r/crates/x/src/core.rs"
printf '\n' >>"$r/crates/x/src/core.rs"
mk_exc "$r" "bare comment line"
expect "zero-region anchor (non-instrumentable)" "ZERO regions" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"; mk_exc "$r" "pub fn a"
expect "all-covered (stale) exception" "COVERED (stale exception)" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"; mk_exc "$r" "pub fn a" 'end_anchor = "no_such_end"'
expect "invalid end_anchor" "end_anchor" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
cat >>"$r/coverage-tiers.toml" <<'EOF'
[[exception]]
path = "crates/x/src/core.rs"
anchor = "pub fn a"
why = ""
EOF
expect "blank exception why" "why must be non-empty" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

# exception on a t3/excluded file
r="$(newroot)"; mk_base "$r"
cat >>"$r/coverage-tiers.toml" <<'EOF'
[[t3]]
path = "crates/x/src/aux.rs"
why = "fixture t3"
[[exception]]
path = "crates/x/src/aux.rs"
anchor = "whatever"
why = "should fail"
EOF
printf 'crates/x/src/aux.rs\n' >>"$r/files.list"
mkdir -p "$r/crates/x/src"; printf '// aux\n' >"$r/crates/x/src/aux.rs"
expect "exception on t3 file" "no floor to excuse" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

# ---------- t3/env_bound modes -----------------------------------------------
r="$(newroot)"; mk_base "$r"
cat >>"$r/coverage-tiers.toml" <<'EOF'
[[t3]]
path = "crates/x/src/aux.rs"
why = ""
EOF
printf 'crates/x/src/aux.rs\n' >>"$r/files.list"
printf '// aux\n' >"$r/crates/x/src/aux.rs"
expect "blank t3 why" "why must be non-empty" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
cat >>"$r/coverage-tiers.toml" <<'EOF'
[[env_bound_override]]
path = "crates/x/src/core.rs"
env_bound = "target_os:solaris"
why = "bad grammar"
EOF
expect "env_bound bad syntax" "target_os:(linux|macos|windows)" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
cat >>"$r/coverage-tiers.toml" <<'EOF'
[[env_bound_override]]
path = "crates/x/src/ghost.rs"
env_bound = "target_os:linux"
why = "resolves to nothing"
EOF
expect "env_bound override resolves to zero" "exactly one existing t1/t2 entry" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
cat >>"$r/coverage-tiers.toml" <<'EOF'
[[env_bound_override]]
path = "crates/x/src/core.rs"
env_bound = "target_os:linux"
why = "one"
[[env_bound_override]]
path = "crates/x/src/core.rs"
env_bound = "target_os:linux"
why = "two"
EOF
expect "duplicate env_bound override" "more than one override" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
cat >>"$r/coverage-tiers.toml" <<'EOF'
[[t3]]
path = "crates/x/src/aux.rs"
why = "t3 with illegal env_bound"
env_bound = "target_os:linux"
EOF
printf 'crates/x/src/aux.rs\n' >>"$r/files.list"
printf '// aux\n' >"$r/crates/x/src/aux.rs"
expect "literal env_bound key on t3" "illegal on t3" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

# env_bound absence split: native absent = FAIL, non-native absent = advisory+0
this_os="$(python3 -c 'import sys; print({"darwin":"macos"}.get(sys.platform, "linux" if sys.platform.startswith("linux") else "windows"))')"
other_os="linux"; [ "$this_os" = "linux" ] && other_os="macos"
r="$(newroot)"; mk_base "$r"
cat >>"$r/coverage-tiers.toml" <<EOF
[[env_bound_override]]
path = "crates/x/src/core.rs"
env_bound = "target_os:$this_os"
why = "native-lane fixture"
EOF
python3 - "$r" <<'PYEOF'
import json, sys
r = sys.argv[1]
p = f"{r}/cov.json"
d = json.load(open(p)); d["data"][0]["functions"] = []   # file absent from coverage
json.dump(d, open(p, "w"))
PYEOF
expect "env_bound NATIVE-lane absent = FAIL" "absent from coverage JSON" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
cat >>"$r/coverage-tiers.toml" <<EOF
[[env_bound_override]]
path = "crates/x/src/core.rs"
env_bound = "target_os:$other_os"
why = "non-native fixture"
EOF
python3 - "$r" <<'PYEOF'
import json, sys
r = sys.argv[1]
p = f"{r}/cov.json"
d = json.load(open(p)); d["data"][0]["functions"] = []
json.dump(d, open(p, "w"))
PYEOF
expect "env_bound non-native absent = advisory + exit 0" "advisory:" 0 -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

# ---------- split-marker modes ----------------------------------------------
mk_marker_file() { # <root> <body>
  local r="$1"; shift
  printf '%s\n' "$1" >"$r/crates/x/src/core.rs"
}
r="$(newroot)"; mk_base "$r"
cat >"$r/crates/x/src/core.rs" <<'EOF'
pub fn a() -> u32 { 1 }
#[cfg(test)]
mod tests {
    fn t() {}
}
#[cfg(test)]
mod more {
    fn u() {}
}
EOF
mk_json "$r" "crates/x/src/core.rs" "1:5"
expect "multiple split markers" "more than one column-0" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
cat >"$r/crates/x/src/core.rs" <<'EOF'
pub fn a() -> u32 { 1 }
#[cfg(test)]
use std::fmt;
EOF
mk_json "$r" "crates/x/src/core.rs" "1:5"
expect "marker not followed by mod" "not followed by \`mod \`" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
cat >"$r/crates/x/src/core.rs" <<'EOF'
#[cfg(test)]
mod tests {
    fn t() {}
}
EOF
mk_json "$r" "crates/x/src/core.rs" "3:1"
expect "zero production regions" "production-region count == 0" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
cat >"$r/crates/x/src/core.rs" <<'EOF'
pub fn a() -> u32 { 1 }
#[cfg(test)]
mod tests {
    fn t() {}
}
pub fn emergency_permit() -> bool { true }
EOF
mk_json "$r" "crates/x/src/core.rs" "1:5" "6:0"
expect "production code after test module (emergency_permit dodge)" "column-0 code after the test module (line 6)" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

# ---------- coverage-JSON schema modes ---------------------------------------
r="$(newroot)"; mk_base "$r"
python3 - "$r" <<'PYEOF'
import json, sys
r = sys.argv[1]
p = f"{r}/cov.json"
d = json.load(open(p)); d["version"] = "4.0.0"
json.dump(d, open(p, "w"))
PYEOF
expect "schema assertion (bumped major version)" "major version must be 3" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
python3 - "$r" <<'PYEOF'
import json, sys
r = sys.argv[1]
p = f"{r}/cov.json"
d = json.load(open(p))
del d["data"][0]["functions"][0]["regions"][0]  # keep valid but drop a region
d["data"][0]["functions"][0]["regions"][0] = [2,1,2,20,7,0,0]  # arity 7
json.dump(d, open(p, "w"))
PYEOF
expect "region arity violation" "arity" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"
python3 - "$r" <<'PYEOF'
import json, sys
r = sys.argv[1]
p = f"{r}/cov.json"
d = json.load(open(p))
core = "crates/x/src/core.rs"
python_missing = [f for f in [core]]
d["data"][0]["functions"] = []
json.dump(d, open(p, "w"))
PYEOF
expect "classified T1 absent from coverage JSON" "absent from coverage JSON" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" "$gate" --root "$r" --injection

# ---------- argv/env contract modes ------------------------------------------
r="$(newroot)"; mk_base "$r"
expect "unrecognized COVERAGE_TIERS var" "unrecognized COVERAGE_TIERS var" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" COVERAGE_TIERS_TYPO=x \
      "$gate" --root "$r" --injection
expect "closed-set var without --injection" "without --injection" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" "$gate" --root "$r"
expect "--injection with JSON but not FILELIST" "FILELIST together" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" "$gate" --root "$r" --injection
expect "--injection refused inside a work tree" "inside a git work tree" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" \
      "$gate" --root "$repo_root" --injection
expect "mutation under --injection without CRATE_DIRS" "requires COVERAGE_TIERS_CRATE_DIRS" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" \
      "$gate" --root "$r" --injection --mutants-all
expect "malformed CRATE_DIRS pair grammar" "malformed COVERAGE_TIERS_CRATE_DIRS" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" \
      COVERAGE_TIERS_CRATE_DIRS="crates/x" "$gate" --root "$r" --injection

# ---------- workflow-sync modes (injection + CRATE_DIRS + synthetic ci.yml) --
mk_wf() { # <root> <mutants-paths-value or SKIP or DUP>
  local r="$1" v="$2"
  mkdir -p "$r/.github/workflows"
  case "$v" in
    NONE) printf 'name: x\njobs: {}\n' >"$r/.github/workflows/ci.yml";;
    DUP)  printf 'env:\n  MUTANTS_PATHS: "a"\n  MUTANTS_PATHS: "b"\n' >"$r/.github/workflows/ci.yml";;
    *)    printf 'env:\n  MUTANTS_PATHS: "%s"\n' "$v" >"$r/.github/workflows/ci.yml";;
  esac
}
sync_base() { # adds a mutants crate to the fixture toml
  local r="$1"
  sed -i.bak 's/mutants_crates = \[\]/mutants_crates = ["xcore"]/' "$r/coverage-tiers.toml"
}
r="$(newroot)"; mk_base "$r"; sync_base "$r"; mk_wf "$r" "crates/xcore"
expect "workflow-sync pass" "PASS: coverage-tiers gate" 0 -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" \
      COVERAGE_TIERS_CRATE_DIRS="xcore=crates/xcore" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"; sync_base "$r"; mk_wf "$r" "crates/other"
expect "workflow-sync mismatch" "MUTANTS_PATHS drift" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" \
      COVERAGE_TIERS_CRATE_DIRS="xcore=crates/xcore" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"; sync_base "$r"; mk_wf "$r" "crates/xcore-extra"
expect "workflow-sync near-miss dir" "MUTANTS_PATHS drift" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" \
      COVERAGE_TIERS_CRATE_DIRS="xcore=crates/xcore" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"; sync_base "$r"; mk_wf "$r" DUP
expect "workflow-sync multi-line" "multiple MUTANTS_PATHS" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" \
      COVERAGE_TIERS_CRATE_DIRS="xcore=crates/xcore" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"; sync_base "$r"; mk_wf "$r" NONE
expect "workflow-sync zero-match" "absent from" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" \
      COVERAGE_TIERS_CRATE_DIRS="xcore=crates/xcore" "$gate" --root "$r" --injection

r="$(newroot)"; mk_base "$r"; sync_base "$r"; mk_wf "$r" "crates/xcore"
expect "unknown crate in CRATE_DIRS map (sync)" "unknown crate in mutants_crates" nonzero -- \
  env COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" \
      COVERAGE_TIERS_CRATE_DIRS="other=crates/other" "$gate" --root "$r" --injection

# mutation-path unknown-crate (stub cargo-mutants shim; injection name oracle)
r="$(newroot)"; mk_base "$r"; sync_base "$r"
shim="$(newroot)"; cat >"$shim/cargo-mutants" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$shim/cargo-mutants"
expect "mutation-stage unknown crate (name oracle)" "cannot resolve mutants_crates package names (mutation stage)" nonzero -- \
  env PATH="$shim:$PATH" COVERAGE_TIERS_JSON="$r/cov.json" COVERAGE_TIERS_FILELIST="$r/files.list" \
      COVERAGE_TIERS_CRATE_DIRS="other=crates/other" "$gate" --root "$r" --injection --mutants-all

# ---------- readiness modes --------------------------------------------------
shimdir="$(newroot)"
for t in bash git python3 grep sed tr sort mktemp dirname basename env sh uname; do
  p_real="$(command -v "$t" || true)"; [ -n "$p_real" ] && ln -s "$p_real" "$shimdir/$t"
done
r="$(newroot)"; mk_base "$r"
expect "readiness: cargo-llvm-cov missing" "cargo-llvm-cov missing" nonzero -- \
  env PATH="$shimdir" "$gate" --root "$r" --readiness-check
expect "readiness: cargo-mutants missing (mutation stage)" "cargo-mutants missing" nonzero -- \
  env PATH="$shimdir" "$gate" --root "$r" --readiness-check --mutants-all

# ---------- live-root modes (git init; real cargo workspace) -----------------
mk_live() { # <root> — genuine live root passing readiness + partition
  local r="$1"
  ( cd "$r"
    env -u GIT_DIR -u GIT_WORK_TREE git init -q
    cp "$repo_root/rust-toolchain.toml" .
    mkdir -p member/src
    cat >Cargo.toml <<'EOF'
[workspace]
resolver = "2"
members = ["member"]
EOF
    cat >member/Cargo.toml <<'EOF'
[package]
name = "xcore"
version = "0.0.0"
edition = "2021"
EOF
    printf '// stub\n' >member/src/lib.rs
    cat >coverage-tiers.toml <<'EOF'
[universe]
exclude = []
[t1]
floor_production_region = 95
files = []
mutants_crates = ["xcore"]
[t2]
floor_production_region = 90
files = []
[project]
ratchet_floor = 0
ratchet_cohort = []
[project.ratchet_provenance]
value = 0.0
date = "2026-08-04"
lane = "fixture"
command = "fixture"
[[t3]]
path = "member/src/lib.rs"
why = "live-root fixture stub"
EOF
    mkdir -p .github/workflows
    printf 'env:\n  MUTANTS_PATHS: "member"\n' >.github/workflows/ci.yml
    env -u GIT_DIR -u GIT_WORK_TREE git add -A
  )
}

# Mode A: delete ci.yml → missing-workflow FAIL
r="$(newroot)"; mk_live "$r"; rm "$r/.github/workflows/ci.yml"
expect "live mode A: missing ci.yml on live root" "missing $r/.github/workflows/ci.yml" nonzero -- \
  "$gate" --root "$r"

# Mode B: shim cargo — metadata exits 1, everything else forwards
r="$(newroot)"; mk_live "$r"
shimB="$(newroot)"
real_cargo="$(command -v cargo)"
cat >"$shimB/cargo" <<EOF
#!/bin/sh
if [ "\$1" = "metadata" ]; then exit 1; fi
exec "$real_cargo" "\$@"
EOF
chmod +x "$shimB/cargo"
expect "live mode B: nonzero cargo metadata (sync)" "cannot resolve mutants_crates dirs" nonzero -- \
  env PATH="$shimB:$PATH" "$gate" --root "$r"

# Mode C: syntax-error stub → coverage run failed
r="$(newroot)"; mk_live "$r"
printf 'this is not rust\n' >"$r/member/src/lib.rs"
expect "live mode C: coverage run failed" "coverage run failed" nonzero -- \
  "$gate" --root "$r"

# Mode D: mutation-path nonzero name oracle (metadata shim + stub cargo-mutants)
r="$(newroot)"; mk_live "$r"
shimD="$(newroot)"
cat >"$shimD/cargo" <<EOF
#!/bin/sh
if [ "\$1" = "metadata" ]; then exit 1; fi
exec "$real_cargo" "\$@"
EOF
cat >"$shimD/cargo-mutants" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$shimD/cargo" "$shimD/cargo-mutants"
expect "live mode D: mutation-path name-oracle failure" "cannot resolve mutants_crates package names (mutation stage)" nonzero -- \
  env PATH="$shimD:$PATH" "$gate" --root "$r" --mutants-all

# ---------- summary ----------------------------------------------------------
printf '\n%d fixture(s) passed, %d failed.\n' "$pass_n" "$fail_n"
[ "$fail_n" -eq 0 ] || exit 1
echo "PASS: coverage-tiers fixture suite"
