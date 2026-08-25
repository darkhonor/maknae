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
    r"\bFile\s*::\s*\w+|\bOpenOptions\s*::\s*\w+"
)
requirements_pattern = re.compile(r"owner:\s*None|mode_mask:\s*None")
# This external module is compiled only by `#[cfg(test)] mod transport_tests;` in
# maknae-vault/lib.rs. Keep the exemption exact rather than exempting src/*_tests.rs.
test_only_files = {"crates/maknae-vault/src/transport_tests.rs"}
found = set()
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
    marker = next((i for i, line in enumerate(lines) if line.startswith("#[cfg(test)]") or line.startswith("#[cfg(all(test,")), None)
    if marker is not None:
        depth = 0
        started = False
        item_end = marker
        for j in range(marker + 1, len(lines)):
            line = lines[j]
            if not started and ";" in line:
                item_end = j
                break
            opens, closes = line.count("{"), line.count("}")
            if opens:
                started = True
            depth += opens - closes
            if started and depth == 0:
                item_end = j
                break
        production_item = re.compile(
            r"^(?:pub(?:\([^)]*\))?\s+|fn\s+|impl\b|struct\s+|enum\s+|"
            r"const\s+|static\s+|type\s+|use\s+|extern\s+|macro_rules!)"
        )
        for number, line in enumerate(lines[item_end + 1:], item_end + 2):
            if production_item.match(line):
                found.add(f"__VIOLATION__ {rel}:{number}: production code after cfg(test) marker")
        scan_source = "\n".join(lines[:marker])
    else:
        scan_source = source
    scan_lines = ["" if line.lstrip().startswith("//") else line for line in scan_source.splitlines()]
    fs_source = "\n".join(scan_lines)
    for match in fs_pattern.finditer(fs_source):
        number = fs_source.count("\n", 0, match.start()) + 1
        found.add(f"{rel}:{number}|{lines[number - 1].strip()}")
    for number, line in enumerate(lines[:marker] if marker is not None else lines, 1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        if requirements_pattern.search(stripped):
            found.add(f"{rel}:{number}|{stripped}")
if found:
    print("\n".join(sorted(found)))
PY

if grep -q '^__VIOLATION__' "$tmp"; then
  echo "FAIL: cfg(test) module is not terminal; production scanning would be ambiguous"
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
