#!/usr/bin/env bash
set -euo pipefail
# Root override, matching p1-manifest-lint / p2-invert-tree / build-invocation-lint
# / feature-resolution-pin. Added by #219 for one reason: without it this gate
# resolves its own root from the CWD and therefore cannot be pointed at a
# fixture, which is why it was the only gate in this directory with NO
# negative-control probe at all. A floor nobody can probe is not a control.
root="${1:-$(git rev-parse --show-toplevel)}"
f="$root/packaging/isolation-contract.md"
[ -f "$f" ] || { echo "FAIL: $f missing"; exit 1; }
# READABLE, not merely present. `done < "$f"` on an unreadable file made bash
# print its own `Permission denied` and exit 1 with NO `FAIL` line -- a mute
# failure, and unprobeable by `expect_reject`, which requires a printed FAIL.
[ -r "$f" ] || { echo "FAIL: $f is not readable — a file that cannot be read has not been linted"; exit 1; }
fail=0
# Rows actually LINTED, not rows read. The file-exists check above proves the
# document is there; it says nothing about the table inside it still being the
# shape this gate reads. Found by #219's sweep: collapse every row to four
# columns and the `ncols = 5` filter below skips all of them, so the whole
# property x profile enforcement matrix goes unexamined and the gate reports
# `ok` at rc 0. A present file is not a scanned file.
linted=0
while IFS= read -r line; do
  case "$line" in
    \|*Property*|\|*---*|\|*:---*) continue ;;
    \|*) : ;;
    *) continue ;;
  esac
  # Only lint the property × profile table (5 columns → NF-2 == 5). Skip the crate × binary matrix.
  ncols=$(echo "$line" | awk -F'|' '{print NF-2}')
  [ "$ncols" = "5" ] || continue
  linted=$((linted+1))
  IFS='|' read -r _ _prop c1 c2 c3 c4 _ <<< "$line"
  i=0
  for cell in "$c1" "$c2" "$c3" "$c4"; do
    i=$((i+1))
    echo "$cell" | grep -q "deferred" && continue
    echo "$cell" | grep -q "✓" && continue
    # A blank cell is NOT acceptable — that would silently drop an enforcement requirement.
    if [ -z "$(echo "$cell" | tr -d ' ')" ]; then echo "FAIL: cell $i is EMPTY (must carry a ✓check or 'deferred')"; fail=1; continue; fi
    echo "FAIL: cell $i has neither a ✓check nor 'deferred': ${cell}"; fail=1
  done
done < "$f"
# FLOOR (#219). The loop above runs in THIS shell (`done < "$f"`, not a pipe),
# so the counter survives it.
if [ "$linted" -eq 0 ]; then
  echo "FAIL: linted ZERO rows of the property × profile table in $f."
  echo "  The file is present but the table this gate reads is not: a renamed"
  echo "  header, a reshaped row, or a column added or removed. Nothing was"
  echo "  examined, so 'every cell carries a check or deferred' is not a finding."
  exit 1
fi
[ "$fail" -eq 0 ] && echo "isolation-contract-lint: ok ($linted rows linted)"
exit "$fail"
