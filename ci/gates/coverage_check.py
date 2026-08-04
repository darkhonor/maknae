#!/usr/bin/env python3
"""Risk-tiered coverage evaluation (ADR-0016, issue #24).

Contract: coverage_check.py <coverage-tiers.toml> <coverage.json> <repo-root>
with the universe file-list (repo-relative POSIX paths, one per line) on stdin.

Every violation prints a line starting `FAIL:`; all stage violations are
reported before the nonzero exit; typed-field rules mean malformed input is a
FAIL:, never a traceback. The ADR baseline table is emitted even when the run
fails (a red CI run must still yield the CI-lane numbers).

Spec authority: ~/claude-memory/maknae/specs/2026-08-04-coverage-tiers-design.md
(v18, converged). Where this file and the spec disagree, the spec wins.
"""

import json
import re
import sys
import tomllib
from pathlib import Path

ENV_BOUND_RE = re.compile(r"^target_os:(linux|macos|windows)$")
CRATE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
FAILS: list[str] = []


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    FAILS.append(msg)


def die_usage() -> None:
    print("FAIL: usage: coverage_check.py <tiers.toml> <coverage.json> <repo-root> < universe-list")
    sys.exit(2)


# ---------------------------------------------------------------- glob engine
def seg_match(pattern: str, path: str) -> bool:
    """Segment-aware glob: `*` matches within ONE path segment; `**` matches
    zero or more whole segments. Anchored full-path match, POSIX separators."""
    psegs = pattern.split("/")
    fsegs = path.split("/")

    def rec(pi: int, fi: int) -> bool:
        if pi == len(psegs):
            return fi == len(fsegs)
        seg = psegs[pi]
        if seg == "**":
            return any(rec(pi + 1, k) for k in range(fi, len(fsegs) + 1))
        if fi == len(fsegs):
            return False
        # translate one segment's * into a regex fragment (no / crossing)
        rx = "^" + re.escape(seg).replace(r"\*", "[^/]*") + "$"
        if not re.match(rx, fsegs[fi]):
            return False
        return rec(pi + 1, fi + 1)

    return rec(0, 0)


# ------------------------------------------------------------- contract load
def typed_num(v, field: str, int_only: bool = False):
    if isinstance(v, bool):
        fail(f"{field} must be a number, got bool")
        return None
    if int_only and not isinstance(v, int):
        fail(f"{field} must be an int (it is floor(measured) by construction)")
        return None
    if not isinstance(v, (int, float)):
        fail(f"{field} must be a number, got {type(v).__name__}")
        return None
    if not (0 <= v <= 100):
        fail(f"{field} must be in 0-100, got {v}")
        return None
    return v


def typed_str(v, field: str):
    if not isinstance(v, str) or not v.strip():
        fail(f"{field} must be a non-empty string")
        return None
    return v


def main() -> int:
    if len(sys.argv) != 4:
        die_usage()
    toml_path, json_path, root = sys.argv[1], sys.argv[2], sys.argv[3]
    root_real = str(Path(root).resolve())

    universe = [ln.strip() for ln in sys.stdin.read().splitlines() if ln.strip()]
    if not universe:
        fail("empty universe file-list (git failure or missing injection)")
        return finish(None)

    try:
        with open(toml_path, "rb") as f:
            contract = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        fail(f"cannot parse contract {toml_path}: {e}")
        return finish(None)

    # ---- contract shape --------------------------------------------------
    uni_cfg = contract.get("universe", {})
    excludes = uni_cfg.get("exclude", [])
    if not isinstance(excludes, list) or not all(isinstance(x, str) for x in excludes):
        fail("[universe].exclude must be a list of strings")
        return finish(None)

    t1 = contract.get("t1", {})
    t2 = contract.get("t2", {})
    t1_files = t1.get("files", [])
    t2_files = t2.get("files", [])
    t1_floor = typed_num(t1.get("floor_production_region"), "t1.floor_production_region")
    t2_floor = typed_num(t2.get("floor_production_region"), "t2.floor_production_region")
    mutants_crates = t1.get("mutants_crates", [])
    if not isinstance(mutants_crates, list):
        fail("t1.mutants_crates must be a list")
        mutants_crates = []
    for name in mutants_crates:
        if not isinstance(name, str) or not CRATE_NAME_RE.match(name):
            fail(f"malformed mutants_crates entry: {name!r}")
    for lst, nm in ((t1_files, "t1.files"), (t2_files, "t2.files")):
        if not isinstance(lst, list) or not all(isinstance(x, str) for x in lst):
            fail(f"{nm} must be a list of strings")
        elif len(set(lst)) != len(lst):
            fail(f"{nm} contains duplicate paths")

    def table_list(key: str) -> list:
        """Codex P2: a [t3] (single table) or scalar where [[t3]] (array of
        tables) is expected must FAIL:, never AttributeError."""
        v = contract.get(key, [])
        if not isinstance(v, list) or not all(isinstance(e, dict) for e in v):
            fail(f"[[{key}]] must be an array of tables (got a malformed shape)")
            return []
        return v

    t3_entries = table_list("t3")
    t3_files: dict[str, str] = {}
    for ent in t3_entries:
        pth = ent.get("path")
        why = ent.get("why")
        if not isinstance(pth, str) or not pth:
            fail("t3 entry missing path")
            continue
        if not isinstance(why, str) or not why.strip():
            fail(f"t3 entry {pth}: why must be non-empty")
        if "env_bound" in ent:
            fail(f"t3 entry {pth}: env_bound is illegal on t3 (t3 is already report-only)")
        if pth in t3_files:
            fail(f"t3 entry {pth}: duplicate")
        t3_files[pth] = why or ""

    # env_bound overrides (t1/t2 only; not tier memberships)
    overrides: dict[str, str] = {}
    for ent in table_list("env_bound_override"):
        pth = ent.get("path")
        eb = ent.get("env_bound")
        why = ent.get("why")
        if not isinstance(pth, str) or not pth:
            fail("env_bound_override missing path")
            continue
        if pth in overrides:
            fail(f"env_bound_override {pth}: more than one override for the same path")
            continue
        if not isinstance(eb, str) or not ENV_BOUND_RE.match(eb):
            fail(f"env_bound_override {pth}: env_bound must match ^target_os:(linux|macos|windows)$")
            continue
        if not isinstance(why, str) or not why.strip():
            fail(f"env_bound_override {pth}: why must be non-empty")
        if pth not in t1_files and pth not in t2_files:
            fail(f"env_bound_override {pth}: must resolve to exactly one existing t1/t2 entry")
            continue
        overrides[pth] = eb

    # exceptions (not tier memberships; must resolve to a t1/t2 entry)
    exceptions = []
    for ent in table_list("exception"):
        pth, anchor, why = ent.get("path"), ent.get("anchor"), ent.get("why")
        end_anchor = ent.get("end_anchor")
        if not isinstance(pth, str) or not pth or not isinstance(anchor, str) or not anchor:
            fail("exception entry missing path/anchor")
            continue
        if not isinstance(why, str) or not why.strip():
            fail(f"exception {pth}: why must be non-empty")
            continue
        if pth not in t1_files and pth not in t2_files:
            fail(f"exception {pth}: must resolve to exactly one existing t1/t2 entry (t3/excluded = no floor to excuse)")
            continue
        exceptions.append((pth, anchor, end_anchor, why))

    # project ratchet + provenance
    project = contract.get("project", {})
    ratchet_floor = typed_num(project.get("ratchet_floor"), "project.ratchet_floor", int_only=True)
    cohort = project.get("ratchet_cohort", [])
    if not isinstance(cohort, list) or not all(isinstance(x, str) for x in cohort):
        fail("project.ratchet_cohort must be a list of strings")
        cohort = []
    if ratchet_floor is not None:
        if ratchet_floor > 0 and not cohort:
            fail("project.ratchet_floor > 0 with empty ratchet_cohort")
        if ratchet_floor == 0 and cohort:
            fail("project.ratchet_cohort non-empty with ratchet_floor == 0")
    prov = project.get("ratchet_provenance")
    if not isinstance(prov, dict):
        fail("[project.ratchet_provenance] table is required")
    else:
        pv = prov.get("value")
        if isinstance(pv, bool) or not isinstance(pv, (int, float)):
            fail("ratchet_provenance.value must be a number (bool rejected)")
        elif ratchet_floor is not None and pv < ratchet_floor:
            fail(f"ratchet_provenance.value {pv} < ratchet_floor {ratchet_floor}")
        for k in ("date", "lane", "command"):
            typed_str(prov.get(k), f"ratchet_provenance.{k}")

    # ---- partition -------------------------------------------------------
    excluded = [p for p in universe if any(seg_match(g, p) for g in excludes)]
    subject = [p for p in universe if p not in excluded]
    tier_of: dict[str, str] = {}
    for pth in t1_files:
        tier_of[pth] = "t1"
    for pth in t2_files:
        if pth in tier_of:
            fail(f"{pth}: classified in more than one tier")
        tier_of[pth] = "t2"
    for pth in t3_files:
        if pth in tier_of:
            fail(f"{pth}: classified in more than one tier")
        tier_of[pth] = "t3"
    for pth in tier_of:
        if pth not in universe:
            fail(f"{pth}: stale contract entry (not in the tracked universe)")
    for pth in cohort:
        if pth not in universe:
            fail(f"{pth}: stale path in ratchet_cohort")
        if tier_of.get(pth) not in ("t1", "t2"):
            fail(f"{pth}: ratchet_cohort entry must be a t1/t2 file")
    for pth in subject:
        if pth not in tier_of:
            fail(f"{pth}: unclassified (every tracked .rs file must resolve to exactly one tier)")
    for pth in excluded:
        if pth in tier_of:
            fail(f"{pth}: classified but excluded by [universe].exclude")

    # ---- coverage JSON ---------------------------------------------------
    try:
        with open(json_path, "rb") as f:
            cov = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        fail(f"cannot parse coverage JSON {json_path}: {e}")
        return finish(None)
    if cov.get("type") != "llvm.coverage.json.export":
        fail(f"coverage JSON type is {cov.get('type')!r}, expected llvm.coverage.json.export")
        return finish(None)
    ver = str(cov.get("version", ""))
    if not ver.startswith("3."):
        fail(f"coverage JSON export major version must be 3, got {ver!r}")
        return finish(None)
    data = cov.get("data", [])
    if len(data) != 1:
        fail(f"coverage JSON data has {len(data)} exports, expected exactly 1")
        return finish(None)

    # llvm's own per-file summary (files[] uses function-record dedup — the
    # third baseline column; synthetic fixtures have empty files[] -> n/a)
    llvm_summary: dict[str, str] = {}
    for fentry in data[0].get("files", []):
        rel = normalize(fentry.get("filename", ""), root_real)
        if rel is None:
            continue
        summ = fentry.get("summary", {}).get("regions", {})
        cnt, cov_n = summ.get("count"), summ.get("covered")
        if isinstance(cnt, int) and isinstance(cov_n, int) and cnt:
            llvm_summary[rel] = f"{100.0 * cov_n / cnt:.2f}% ({cov_n}/{cnt})"

    # per-file region buckets via functions[].filenames[region.file_id]
    buckets: dict[str, dict[tuple, bool]] = {}
    for fn in data[0].get("functions", []):
        filenames = fn.get("filenames", [])
        for reg in fn.get("regions", []):
            if len(reg) != 8:
                fail(f"region tuple arity {len(reg)} != 8 (format bump?)")
                return finish(None)
            file_id, kind = reg[5], reg[7]
            if kind != 0:
                continue  # only code regions count
            try:
                fname = filenames[file_id]
            except (IndexError, TypeError):
                fail("region file_id out of range for its function's filenames")
                return finish(None)
            rel = normalize(fname, root_real)
            if rel is None:
                continue  # outside the repo (e.g. registry deps)
            key = (reg[0], reg[1], reg[2], reg[3], kind)
            b = buckets.setdefault(rel, {})
            covered = reg[4] > 0  # any-nonzero merge across instances
            b[key] = b.get(key, False) or covered

    # apply universe excludes to the coverage math too
    for rel in list(buckets):
        if any(seg_match(g, rel) for g in excludes):
            del buckets[rel]

    # ---- per-file evaluation --------------------------------------------
    results: dict[str, dict] = {}
    lane_os = detect_lane_os()
    for pth, tier in sorted(tier_of.items()):
        if tier == "t3":
            if pth in buckets:
                m = file_metrics(pth, buckets[pth], root_real, exceptions, report_only=True)
                if m is not None:
                    results[pth] = m
            continue
        eb = overrides.get(pth)
        if eb is not None and lane_os is None:
            fail(f"{pth}: env_bound present but the running lane is unresolved (gate must supply COVERAGE_LANE_OS from rustc -vV)")
            continue
        if pth not in buckets:
            if eb is not None and not eb.endswith(":" + lane_os):
                print(f"advisory: {pth} absent from coverage on non-native lane ({eb}) — report-only here")
                continue
            fail(f"{pth}: classified {tier.upper()} but absent from coverage JSON")
            continue
        m = file_metrics(pth, buckets[pth], root_real, exceptions)
        if m is None:
            continue
        results[pth] = m
        floor = t1_floor if tier == "t1" else t2_floor
        if floor is None:
            continue
        if eb is not None and not eb.endswith(":" + lane_os):
            print(f"advisory: {pth} is env_bound ({eb}) — floor report-only on this lane")
            continue
        if m["prod_pct"] < floor:
            fail(f"{pth}: production-region {m['prod_pct']:.2f}% < {tier.upper()} floor {floor}%")

    # ---- ratchet ---------------------------------------------------------
    if ratchet_floor is not None and cohort:
        cov_sum = tot_sum = 0
        ok = True
        for pth in cohort:
            m = results.get(pth)
            if m is None:
                fail(f"{pth}: ratchet_cohort member has no evaluated metric — the floor was NOT evaluated")
                ok = False
                continue
            cov_sum += m["prod_cov"]
            tot_sum += m["prod_tot"]
        if ok and tot_sum:
            agg = 100.0 * cov_sum / tot_sum
            print(f"cohort aggregate: {cov_sum}/{tot_sum} = {agg:.2f}% (floor {ratchet_floor})")
            if agg < ratchet_floor:
                fail(f"cohort ratchet: aggregate {agg:.2f}% < floor {ratchet_floor}%")

    return finish(results, llvm_summary)


def normalize(fname: str, root_real: str) -> str | None:
    try:
        real = str(Path(fname).resolve())
    except OSError:
        real = fname
    if not real.startswith(root_real + "/"):
        return None
    return real[len(root_real) + 1:]


def detect_lane_os() -> str | None:
    """Lane comes from the GATE (rustc -vV host-triple mapping, spec §5) via
    COVERAGE_LANE_OS; the helper never guesses from sys.platform. Absent env
    (no env_bound users needed it) -> None; the caller fails closed on use."""
    import os
    lane = os.environ.get("COVERAGE_LANE_OS", "")
    return lane if lane in ("linux", "macos", "windows") else None


def file_metrics(pth: str, bucket: dict, root_real: str, exceptions: list,
                 report_only: bool = False) -> dict | None:
    """Production split + exceptions for one file. `report_only` (T3) demotes
    every marker hard-fail to silence — T3 has no floor to protect."""
    def hardfail(msg: str) -> None:
        if not report_only:
            fail(msg)
    src = Path(root_real, pth)
    try:
        lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        hardfail(f"{pth}: cannot read source for production split")
        return None

    # split marker: column-0 #[cfg(test)] whose next non-blank line begins `mod `
    markers = []
    bad_marker = False
    for i, ln in enumerate(lines):
        if ln.startswith("#[cfg(test)]"):
            nxt = next((l for l in lines[i + 1:] if l.strip()), "")
            if nxt.startswith("mod "):
                markers.append(i + 1)  # 1-based marker line
            else:
                hardfail(f"{pth}: column-0 #[cfg(test)] not followed by `mod ` (line {i+1}) — restructure the idiom")
                bad_marker = True
    if len(markers) > 1:
        hardfail(f"{pth}: more than one column-0 #[cfg(test)] mod marker")
        return None
    if bad_marker:
        return None
    marker = markers[0] if markers else None
    if marker is not None:
        # test module must extend to EOF: after the marker, only the mod line,
        # the closing }, and comment lines may sit at column 0
        seen_mod = False
        for j in range(marker, len(lines)):  # lines after the marker line
            ln = lines[j]
            if not ln or ln[0] in (" ", "\t"):
                continue
            if not seen_mod and ln.startswith("mod "):
                seen_mod = True
                continue
            if ln.startswith("}") or ln.startswith("//") or ln.startswith("/*"):
                continue
            hardfail(f"{pth}: column-0 code after the test module (line {j+1}) leaves the production denominator")
            return None

    # exception spans for this file
    exc_lines: set[int] = set()
    for (epth, anchor, end_anchor, _why) in exceptions:
        if epth != pth:
            continue
        hits = [i + 1 for i, ln in enumerate(lines) if anchor in ln]
        if len(hits) != 1:
            fail(f"{pth}: exception anchor {anchor!r} matches {len(hits)} lines (need exactly 1)")
            continue
        start = hits[0]
        end = start
        if end_anchor:
            ehits = [i + 1 for i, ln in enumerate(lines) if end_anchor in ln]
            if len(ehits) != 1 or ehits[0] < start:
                fail(f"{pth}: exception end_anchor {end_anchor!r} invalid")
                continue
            end = ehits[0]
        span = set(range(start, end + 1))
        marker_line = markers[0] if markers else None
        span_regs = [(k, c) for k, c in bucket.items()
                     if k[0] in span and (marker_line is None or k[0] < marker_line)]
        if not span_regs:
            fail(f"{pth}: exception anchor {anchor!r} carries ZERO regions (non-instrumentable line)")
            continue
        if all(c for _k, c in span_regs):
            fail(f"{pth}: exception anchor {anchor!r} — all removed regions are COVERED (stale exception)")
            continue
        print(f"exception {pth} {anchor!r}: removing {len(span_regs)} region(s) from the denominator")
        exc_lines |= span

    full_tot = len(bucket)
    full_cov = sum(1 for c in bucket.values() if c)
    prod = {k: c for k, c in bucket.items()
            if (marker is None or k[0] < marker) and k[0] not in exc_lines}
    prod_tot = len(prod)
    prod_cov = sum(1 for c in prod.values() if c)
    if marker is not None and prod_tot == 0:
        hardfail(f"{pth}: production-region count == 0 (marker misplacement?)")
        return None
    return {
        "prod_tot": prod_tot, "prod_cov": prod_cov,
        "prod_pct": (100.0 * prod_cov / prod_tot) if prod_tot else 100.0,
        "full_tot": full_tot, "full_cov": full_cov,
        "full_pct": (100.0 * full_cov / full_tot) if full_tot else 100.0,
    }


def finish(results, llvm_summary=None) -> int:
    llvm_summary = llvm_summary or {}
    if results:
        print()
        print("| File | Production-region (record) | Gate full-file | llvm summary |")
        print("|---|---|---|---|")
        for pth, m in sorted(results.items()):
            print(f"| `{pth}` | {m['prod_pct']:.2f}% ({m['prod_cov']}/{m['prod_tot']}) "
                  f"| {m['full_pct']:.2f}% ({m['full_cov']}/{m['full_tot']}) "
                  f"| {llvm_summary.get(pth, 'n/a (synthetic fixture)')} |")
        print()
    if FAILS:
        print(f"{len(FAILS)} violation(s).")
        return 1
    print("PASS: coverage tiers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
