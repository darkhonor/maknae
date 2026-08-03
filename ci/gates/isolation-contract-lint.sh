#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
f="$root/packaging/isolation-contract.md"
[ -f "$f" ] || { echo "FAIL: $f missing"; exit 1; }
fail=0
while IFS= read -r line; do
  case "$line" in
    \|*Property*|\|*---*|\|*:---*) continue ;;
    \|*) : ;;
    *) continue ;;
  esac
  # Only lint the property × profile table (5 columns → NF-2 == 5). Skip the crate × binary matrix.
  ncols=$(echo "$line" | awk -F'|' '{print NF-2}')
  [ "$ncols" = "5" ] || continue
  IFS='|' read -r _ _prop c1 c2 c3 c4 _ <<< "$line"
  i=0
  for cell in "$c1" "$c2" "$c3" "$c4"; do
    i=$((i+1))
    echo "$cell" | grep -q "deferred" && continue
    echo "$cell" | grep -q "✓" && continue
    [ -z "$(echo "$cell" | tr -d ' ')" ] && continue
    echo "FAIL: cell $i has neither a ✓check nor 'deferred': ${cell}"; fail=1
  done
done < "$f"
[ "$fail" -eq 0 ] && echo "isolation-contract-lint: ok"
exit "$fail"
