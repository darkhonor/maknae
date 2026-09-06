#!/usr/bin/env bash
# authz-composition-drift (ADR-0008 decision 1; #154 / #148).
#
# The authorization baseline must be a NON-REMOVABLE operand of the composition
# -- by construction, not by configuration. This gate asserts the shape that
# makes the absent state inexpressible, so the refactor that introduces a
# backend-selection key fails CI rather than shipping.
#
# CONTENT-KEYED, never line-keyed (#224). Every check anchors on a declaration's
# text; nothing here fires because an unrelated line moved, and check 1 finds
# its statement by its boundary (`;` / `{` / `}`), not by the previous newline,
# so a rustfmt re-wrap cannot fire it either.
#
# Five checks, mapped to ADR-0008 decision 1's four layers:
#   1. (type-level) The production PDP is built UNCONDITIONALLY, from the
#      BOOTED config and the boot gate's own return value: one plain
#      `let authorizer = ...build_pdp(&boot, authorizer)` statement in run.rs,
#      outside cfg(test). `build_pdp` lives in composition.rs (T1, mutated),
#      where the wiring `boot.ceiling()` -> operand is held by a test.
#   2. (type-level) `Composition`'s baseline is a NAMED FIELD bounded by the
#      sealed `Baseline` trait -- not `Option<..>`, `Vec<..>` or `Box<dyn ..>` --
#      and `ceiling` is a named `CeilingAuthorizer` field.
#   3. (type-level) `Baseline` is SEALED and implemented for exactly the two
#      permitted types, only in the owning crate.
#   4. (config vocabulary) None of the six spellings a PDP-selection key would
#      most plausibly take ("authz_backend", "authz.backend", "backend",
#      "baseline", "authorizer", "pdp") appears as a string literal in
#      PRODUCTION code -- scanned across every crate's and bin's `src/`, because
#      section constants live outside maknae-config too (`VAULT_SECTION`,
#      `LAKE_SECTION`). A net, not a proof: a key spelled `engine` or `decider`
#      passes it. Integration tests, benches and examples are NOT scanned (they
#      have no column-0 `#[cfg(test)]`, so the whole file would count as
#      production). Comment blanking (check 1) runs over string literals too: a
#      `//` or `*/` inside a string can only REMOVE candidate sites, never add
#      one, so it can produce a spurious FAIL after an unrelated edit but not a
#      false pass.
#   5. (boot-time evidence) run.rs CONSTRUCTS the boot composition record --
#      one `make_record(` call carrying "boot", "authz", "permit" and a reason
#      that starts "authorization composition: " and carries the SYSTEM and
#      the ceiling LEVEL (`; system: {..}; ceiling: {..}`) -- AND EMITS it
#      (`sink.emit(&composition_rec)`), both in the production half. Its VALUE is
#      asserted by the root-only boot test on a test host.
#
# WHAT THIS GATE DOES NOT HOLD, stated so it is not over-read: checks 1-3 pin
# the composition's SHAPE. That the ceiling is actually CONSULTED -- that
# `Composition::operands()` returns both fields -- is held by
# `composition::tests` and `tests/enforce_loop.rs` (the red-proof, MEASURED:
# swapping the ceiling for a second baseline turns 1 enforce_loop test (the
# composed-name status test) + 5 composition tests red -- the name test, the
# subjects test (two baselines make compose_subjects return None), the MAC-wins
# test, the abstaining-baseline test and the build_pdp test -- while this gate
# stays green). Check 1 asserts the FIRST argument is the binding NAMED `authorizer`
# and that `authz_boot_gate(` precedes it -- a name check, not a provenance
# check: a `let authorizer = BasicAuthorizer::new(other_policy, ..)` rebinding
# between the gate and the composition would pass. The sealed trait bounds the
# TYPE; the construction's policy source is held by review.
# Check 1 blanks BOTH `//` line comments and `/* */` block comments
# before searching, so neither a `;` inside a comment nor a commented-out call
# can move the statement boundary or count as a site.
set -euo pipefail
root="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"

python3 - "$root" <<'PY'
import re, sys
from pathlib import Path
root = Path(sys.argv[1])
fails = []
def fail(msg): fails.append(msg)

def production_half(src: str) -> str:
    """Everything before the first column-0 `#[cfg(test)]` (the same split
    coverage_check.py uses; it hard-fails on a malformed one, so this never
    sees a test module in the production half)."""
    m = re.search(r"^#\[cfg\(test\)\]", src, re.M)
    return src[: m.start()] if m else src

def must_read(rel: str) -> str:
    p = root / rel
    if not p.is_file():
        fail(f"missing {rel}"); return ""
    return p.read_text(errors="replace")

# 1. Unconditional construction at the one production site.
run = production_half(must_read("crates/maknae-kernel/src/run.rs"))
if run:
    # Comments are blanked (same length, so offsets hold): a `;` or brace inside
    # a comment is not a statement boundary -- the real run.rs has "return
    # value;" in the comment right above the call, which is what the first
    # draft of this check tripped on.
    def blank(m):  # same length, so every offset still points at the same char
        return "".join("\n" if c == "\n" else " " for c in m.group(0))
    code = re.sub(r"/\*.*?\*/", blank, run, flags=re.S)
    code = re.sub(r"//[^\n]*", blank, code)
    sites = list(re.finditer(r"build_pdp\s*\(", code))
    if len(sites) != 1:
        fail(f"run.rs: expected exactly ONE production `build_pdp(` call site, found {len(sites)}")
    else:
        s = sites[0].start()
        # The STATEMENT start: the last `;`, `{` or `}` before the call. Then
        # the statement must be a plain binding fed by the BOOTED config and
        # the boot gate's own `authorizer`, nothing conditional in between.
        stmt_start = max(code.rfind(c, 0, s) for c in ";{}") + 1
        stmt_code = code[stmt_start: sites[0].end()]
        if not re.match(r"\s*let\s+authorizer\s*=\s*(crate::composition::)?build_pdp\s*\(\s*$", stmt_code, re.S):
            fail("run.rs: `build_pdp(` is not a plain `let authorizer = ...` binding -- construction must be unconditional")
        args = code[sites[0].end(): sites[0].end() + 200]
        if not re.match(r"\s*&\s*boot\s*,\s*authorizer\s*\)", args):
            fail("run.rs: `build_pdp` must be fed `&boot` (the BOOTED config) and the boot gate's `authorizer` binding, in that order")
        if "authz_boot_gate(" not in code[:s]:
            fail("run.rs: `authz_boot_gate(` does not precede the composition -- the baseline must be the gate's return")
    if "Composition::new(" in code:
        fail("run.rs: constructs a `Composition` directly -- production must go through `build_pdp`, where the wiring is mutation-tested")

# 2. Named, non-optional, trait-bounded baseline field; named ceiling field.
comp = production_half(must_read("crates/maknae-kernel/src/composition.rs"))
if comp:
    m = re.search(r"pub struct Composition<\s*B\s*:\s*Baseline\s*>\s*\{(.*?)\n\}", comp, re.S)
    if not m:
        fail("composition.rs: no `pub struct Composition<B: Baseline> { .. }` declaration")
    else:
        body = m.group(1)
        f = re.search(r"\n\s*baseline\s*:\s*([^,\n]+)\s*,", body)
        if not f:
            fail("composition.rs: `Composition` has no named `baseline` field")
        elif f.group(1).strip() != "B":
            fail(f"composition.rs: `baseline` must be the bare `B: Baseline` type, found `{f.group(1).strip()}` -- an Option/Vec/Box makes the absent state expressible")
        c = re.search(r"\n\s*ceiling\s*:\s*([^,\n]+)\s*,", body)
        if not c:
            fail("composition.rs: `Composition` has no named `ceiling` field (a mandatory operand is ALWAYS composed, ADR-0020 §3)")
        elif c.group(1).strip() != "CeilingAuthorizer":
            fail(f"composition.rs: `ceiling` must be the bare `CeilingAuthorizer`, found `{c.group(1).strip()}`")

# 3. Sealed trait, exactly the permitted impls, all in the owning crate.
basic = must_read("crates/maknae-authz-basic/src/lib.rs")
# Production sources only: `<crate>/src/**`. `tests/`, `benches/` and
# `examples/` have no column-0 `#[cfg(test)]`, so production_half() would return
# them whole and a harmless literal in an integration test would fail CI.
for base in ("crates", "bins"):
    if not (root/base).is_dir():
        fail(f"missing {base}/ -- the production scan would silently cover less than it claims")
all_rs = sorted(p for base in ("crates", "bins") if (root/base).is_dir()
                for p in (root/base).rglob("*.rs")
                if len(p.relative_to(root/base).parts) > 2 and p.relative_to(root/base).parts[1] == "src")
if basic:
    if not re.search(r"pub trait Baseline\s*:[^{]*\bsealed::Sealed\b", basic):
        fail("authz-basic: `Baseline` is not bounded by `sealed::Sealed`")
    allowed = {"BasicAuthorizer", "HermeticAuthorizer"}
    names = set()
    for p in all_rs:
        rel = str(p.relative_to(root))
        for mm in re.finditer(r"impl\s+(?:maknae_authz_basic::)?Baseline\s+for\s+([A-Za-z_][A-Za-z0-9_]*)", p.read_text(errors="replace")):
            names.add(mm.group(1))
            if not rel.endswith("crates/maknae-authz-basic/src/lib.rs"):
                fail(f"{rel}: `impl Baseline for {mm.group(1)}` outside the owning crate -- the trait must stay sealed")
            elif mm.group(1) not in allowed:
                fail(f"authz-basic: `impl Baseline for {mm.group(1)}` is not one of the two permitted baselines")
    if "BasicAuthorizer" not in names:
        fail("authz-basic: `impl Baseline for BasicAuthorizer` is absent")

# 4. None of the six plausible PDP-selection spellings appears in production.
for p in all_rs:
    text = production_half(p.read_text(errors="replace"))
    # Attribute lines are NOT skipped: nothing in the tree needs it (no serde
    # rename of these names exists), and a selection mechanism written as
    # `#[cfg(feature = "backend")]` is exactly what this net is for.
    for mm in re.finditer(r'"(authz_backend|authz\.backend|backend|baseline|authorizer|pdp)"', text):
        fail(f"{p.relative_to(root)}: production vocabulary names the PDP/baseline ({mm.group(0)}) -- configuration expresses extensions only (ADR-0008 decision 1)")

# 5. The boot-time evidence record is emitted.
if run:
    calls = [m for m in re.finditer(r"make_record\s*\((.*?)\n\s*\)\s*;", run, re.S)]
    evidence = [c for c in calls if '"boot"' in c.group(1) and '"authz"' in c.group(1) and '"permit"' in c.group(1) and 'authorization composition: ' in c.group(1)]
    # The record's VALUE half (critical-review round 1 of PR B): the reason must
    # carry the classification SYSTEM and the ceiling LEVEL -- the two values
    # the operand enforces -- or the trail says which operands compose but not
    # what they will refuse. Content-keyed on the format string's fixed parts.
    for c in evidence:
        if '; system: {' not in c.group(1) or '; ceiling: {' not in c.group(1):
            fail("run.rs: the boot composition evidence record's reason must carry '; system: {..}; ceiling: {..}' -- the values the operand enforces")
    if len(evidence) != 1:
        fail(f"run.rs: expected exactly ONE boot composition evidence record (make_record with \"boot\", \"authz\", \"permit\" and an 'authorization composition: ' reason), found {len(evidence)}")
    if "sink.emit(&composition_rec)" not in run:
        fail("run.rs: the boot composition evidence record is constructed but never EMITTED (no `sink.emit(&composition_rec)`)")

if fails:
    for f in fails: print(f"FAIL: {f}")
    sys.exit(1)
print("authz-composition-drift: ok (5 checks over ADR-0008 decision 1's four layers)")
PY
