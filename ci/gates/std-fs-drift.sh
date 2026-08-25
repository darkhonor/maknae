#!/usr/bin/env bash
set -euo pipefail
root="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
allow="$root/ci/gates/std-fs-allowlist.txt"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

python3 - "$root" >"$tmp" <<'PY'
from pathlib import Path
import re, subprocess, sys
root = Path(sys.argv[1])
files = subprocess.check_output(
    ["git", "-C", str(root), "ls-files", "*.rs"], text=True
).splitlines()
excluded_parts = {"tests", "benches", "examples"}
fs_pattern = re.compile(
    r"std\s*::\s*fs|use\s+std\s*::\s*\{[\s\S]{0,500}?\bfs\b|"
    r"\bFile\s*::\s*\w+|\bOpenOptions\s*::\s*\w+|"
    r"\b(?:use|extern\s+crate)\s+std\s+as\s+\w+"
)
requirements_pattern = re.compile(r"owner:\s*None|mode_mask:\s*None")
# This external module is compiled only by `#[cfg(test)] mod transport_tests;` in
# maknae-vault/lib.rs. Keep the exemption exact rather than exempting src/*_tests.rs.
test_only_files = {"crates/maknae-vault/src/transport_tests.rs"}
found = set()

def mask_noncode(source):
    """Blank comments and literals while preserving byte offsets and newlines."""
    out = list(source)
    i, state, raw_hashes = 0, "code", 0
    while i < len(source):
        if state == "code":
            if source.startswith("//", i):
                out[i:i+2] = "  "; i += 2; state = "line"
            elif source.startswith("/*", i):
                out[i:i+2] = "  "; i += 2; state = "block"
            elif source[i] == '"':
                out[i] = " "; i += 1; state = "string"
            elif source[i] == "'" and i + 2 < len(source) and source[i+2] == "'":
                out[i:i+3] = "   "; i += 3
            else:
                raw = re.match(r'r(#+)?"', source[i:])
                if raw:
                    raw_hashes = len(raw.group(1) or "")
                    width = raw.end(); out[i:i+width] = " " * width
                    i += width; state = "raw"
                else:
                    i += 1
        elif state == "line":
            if source[i] == "\n": state = "code"
            else: out[i] = " "
            i += 1
        elif state == "block":
            if source.startswith("*/", i):
                out[i:i+2] = "  "; i += 2; state = "code"
            else:
                if source[i] != "\n": out[i] = " "
                i += 1
        elif state == "string":
            if source[i] == "\\":
                out[i] = " "; i += 1
                if i < len(source):
                    if source[i] != "\n": out[i] = " "
                    i += 1
            else:
                if source[i] == '"': state = "code"
                if source[i] != "\n": out[i] = " "
                i += 1
        else:
            end = '"' + ('#' * raw_hashes)
            if source.startswith(end, i):
                out[i:i+len(end)] = " " * len(end); i += len(end); state = "code"
            else:
                if source[i] != "\n": out[i] = " "
                i += 1
    return "".join(out)

def production_only(source):
    """Remove exactly items carrying cfg(test), retaining all later production items."""
    code = mask_noncode(source)
    removed = list(source)
    attrs = list(re.finditer(r'(?m)^[ \t]*#\[cfg\((?:test|all\(test,[^\n]*\))\)\]', code))
    for attr in reversed(attrs):
        start, cursor = attr.start(), attr.end()
        brace = code.find("{", cursor)
        semi = code.find(";", cursor)
        if semi != -1 and (brace == -1 or semi < brace):
            end = semi + 1
        elif brace != -1:
            depth, end = 0, None
            for pos in range(brace, len(code)):
                if code[pos] == "{": depth += 1
                elif code[pos] == "}":
                    depth -= 1
                    if depth == 0:
                        end = pos + 1; break
            if end is None:
                raise SystemExit(f"FAIL: unterminated cfg(test) item at offset {start}")
        else:
            raise SystemExit(f"FAIL: unrecognized cfg(test) item at offset {start}")
        for pos in range(start, end):
            if removed[pos] != "\n": removed[pos] = " "
    return "".join(removed)

for rel in files:
    p = Path(rel)
    if rel.startswith("crates/maknae-io/") or p.name == "build.rs" or rel in test_only_files:
        continue
    if excluded_parts.intersection(p.parts):
        continue
    source = (root / rel).read_text()
    lines = source.splitlines()
    if any("#![cfg(test)]" in line for line in lines[:5]):
        continue
    scan_source = production_only(source)
    scan_lines = ["" if line.lstrip().startswith("//") else line for line in scan_source.splitlines()]
    fs_source = "\n".join(scan_lines)
    for match in fs_pattern.finditer(fs_source):
        number = fs_source.count("\n", 0, match.start()) + 1
        found.add(f"{rel}:{number}|{lines[number - 1].strip()}")
    for number, line in enumerate(scan_source.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        if requirements_pattern.search(stripped):
            found.add(f"{rel}:{number}|{stripped}")
if found:
    print("\n".join(sorted(found)))
PY

reviewed="$(mktemp)"
trap 'rm -f "$tmp" "$reviewed"' EXIT
awk '!/^#/ && NF' "$allow" | sort >"$reviewed"
if ! diff -u "$reviewed" "$tmp" >/dev/null; then
  echo "FAIL: production std::fs inventory differs from the exact reviewed allowlist"
  diff -u "$reviewed" "$tmp" || true
  exit 1
fi
echo "std-fs-drift: exact production inventory matches reviewed allowlist"
