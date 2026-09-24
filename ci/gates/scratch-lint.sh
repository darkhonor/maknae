#!/usr/bin/env bash
# Every mktemp call in the gates and hooks must name its parent directory:
# an explicit "${TMPDIR:-/tmp}/…" template, or -p. macOS mktemp ignores
# TMPDIR for a bare `mktemp`, `mktemp -d` and `-t name` (measured on 26.6.2),
# which put negative-control.sh's leak checks out of reach of every gate they
# watch. Exact inventory: every call site is inspected, comments stripped.
set -euo pipefail
root="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
fail_n=0
for f in "$root"/ci/gates/*.sh "$root"/ci/hooks/*; do
  [ -f "$f" ] || continue
  n=0
  while IFS= read -r raw; do
    n=$((n+1))
    line="$raw"
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    line="${line%%[[:space:]]#*}"
    rest="$line"
    while [[ "$rest" == *mktemp* ]]; do
      before="${rest%%mktemp*}"; after="${rest#*mktemp}"; rest="$after"
      # command position: after `$(`, at line start, or after ; | &
      [[ "$before" =~ (\$\(|^|[\;\|\&])[[:space:]]*$ ]] || continue
      [[ "$after" == "" || "$after" == [[:space:]]* || "$after" == ")"* ]] || continue
      call="mktemp${after%%)*}"
      case "$call" in
        *" -p "*|*/*) ;;
        *) echo "FAIL: ${f#"$root"/}:$n: mktemp without an explicit parent: $call"; fail_n=$((fail_n+1));;
      esac
    done
  done < "$f"
done
if [ "$fail_n" -gt 0 ]; then
  echo "FAIL: scratch-lint: $fail_n mktemp call(s) without an explicit parent"; exit 1
fi
echo "scratch-lint: every mktemp names its parent"
