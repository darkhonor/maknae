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
pattern = re.compile(
    r"std::fs::(?:read|read_to_string|write|remove_file|create_dir|create_dir_all|"
    r"set_permissions|symlink_metadata|metadata|OpenOptions)|use std::fs::|"
    r"\bFile::(?:open|create)|\bOpenOptions::"
)
found = set()
for rel in files:
    p = Path(rel)
    if rel.startswith("crates/maknae-io/") or p.name == "build.rs":
        continue
    if excluded_parts.intersection(p.parts):
        continue
    lines = (root / rel).read_text().splitlines()
    if any("#![cfg(test)]" in line for line in lines[:5]):
        continue
    for line in lines:
        if line.startswith("#[cfg(test)]") or line.startswith("#[cfg(all(test,"):
            break
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        if pattern.search(stripped):
            found.add(f"{rel}|{stripped}")
if found:
    print("\n".join(sorted(found)))
PY

if ! diff -u "$allow" "$tmp" >/dev/null; then
  echo "FAIL: production std::fs inventory differs from the exact reviewed allowlist"
  diff -u "$allow" "$tmp" || true
  exit 1
fi
echo "std-fs-drift: exact production inventory matches reviewed allowlist"
