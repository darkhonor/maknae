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
fs_pattern = re.compile(
    r"(?:::)?\bstd\s*::\s*fs\b|use\s+(?:::)?std\s*::\s*\{[^}]{0,500}?\bfs\b|"
    r"\bFile\s*::\s*\w+|\bOpenOptions\s*::\s*\w+|"
    r"\b(?:use|extern\s+crate)\s+std\s+as\s+\w+"
)
# A requirement-free read is inventoried by BOTH spellings it can take (issue #132).
# The field-name arms only ever saw a struct literal, so a requirement handed over
# positionally or through a variable was invisible — `read_secure_required(path, None,
# Some(0o007))` was the live example. maknae-io now NAMES those requirements
# (`AnchorRequired::OS_DAC`, `DescendantRequired::OS_DAC`, `TargetRequired::OS_DAC_REGULAR`)
# precisely so the absence is greppable, and the identifier arm inventories every use.
# `\b` on both sides keeps unrelated identifiers that merely contain the token
# (`NOT_OS_DAC`, `OS_DAC_UNRELATED`) out of the inventory.
requirements_pattern = re.compile(
    r"owner:\s*None|mode_mask:\s*None|\bOS_DAC(?:_REGULAR)?\b"
)
# A Rust char literal: `'` + (one non-escape char | a backslash escape) + `'`. Anchoring on the
# closing quote is what keeps lifetimes out — `'a`, `'static`, `'_` and loop labels are never
# followed by a closing quote, so they fall through and are left as code (issue #131).
char_literal_pattern = re.compile(
    r"'(?:\\(?:u\{[0-9a-fA-F_]{1,6}\}|x[0-9a-fA-F]{2}|.)|[^\\'])'", re.DOTALL
)
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
            elif source[i] == "'" and char_literal_pattern.match(source, i):
                end = char_literal_pattern.match(source, i).end()
                for pos in range(i, end):
                    if source[pos] != "\n":
                        out[pos] = " "
                i = end
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
    # Cargo's package-root integration-test targets never enter a production library
    # or binary. A `src/tests/` path is deliberately not covered.
    if any(part == "tests" and "src" not in p.parts[:i]
           for i, part in enumerate(p.parts)):
        continue
    source = (root / rel).read_text()
    lines = source.splitlines()
    masked = mask_noncode(source)
    if re.search(r"(?m)\A(?:[ \t]*\n)*[ \t]*#!\[cfg\(test\)\]", masked):
        continue
    scan_source = production_only(source)
    fs_source = mask_noncode(scan_source)
    forbidden_import = re.compile(
        r"\b(?:use|extern\s+crate)\s+(?:::)?std\s+as\s+\w+|"
        r"\buse\s+(?:::)?std\s*::\s*fs\s+as\s+\w+|"
        r"\buse\s+(?:::)?std\s*::\s*fs\s*::\s*(?!File\s*;|OpenOptions\s*;)|"
        r"\buse\s+(?:::)?std\s*::\s*\{[^}]{0,500}?\b(?:fs\b|self\s+as\b)|"
        # A glob import of std makes `fs::` resolvable with no `std::fs` token in the file
        # (issue #130). Covers `use std::*;`, `use ::std::*;` and grouped forms whose list
        # carries a top-level glob (`use std::{*}`, `use std::{path, *}`); a nested glob such
        # as `use std::{io::*}` does not bring `fs` into scope and is deliberately not matched.
        r"\buse\s+(?:::)?std\s*::\s*(?:\*|(?=\{)[^;]{0,500}?[{,]\s*\*\s*[,}])"
    )
    match = forbidden_import.search(fs_source)
    if match:
        number = fs_source.count("\n", 0, match.start()) + 1
        found.add(f"__VIOLATION__ {rel}:{number}: aliased or unqualified std::fs import is forbidden")
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

if grep -q '^__VIOLATION__' "$tmp"; then
  echo "FAIL: production std::fs aliases and unqualified imports are forbidden"
  grep '^__VIOLATION__' "$tmp"
  exit 1
fi

reviewed="$(mktemp)"
trap 'rm -f "$tmp" "$reviewed"' EXIT
awk '!/^#/ && NF' "$allow" | sort >"$reviewed"
if ! diff -u "$reviewed" "$tmp" >/dev/null; then
  echo "FAIL: production std::fs inventory differs from the exact reviewed allowlist"
  diff -u "$reviewed" "$tmp" || true
  exit 1
fi
echo "std-fs-drift: exact production inventory matches reviewed allowlist"
