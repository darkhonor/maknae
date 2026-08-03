#!/usr/bin/env bash
set -euo pipefail
root="${1:-$(git rev-parse --show-toplevel)}"; fail=0   # arg override for the negative-control
# Scan the WORKING TREE (find), not `git ls-files`, so uncommitted files are linted.
while IFS= read -r f; do
  while IFS= read -r line; do
    echo "$line" | grep -qE 'cargo[[:space:]]+(build|rustc|auditable[[:space:]]+build|deb|generate-rpm)' || continue
    echo "$line" | grep -qE '(--workspace|--all)([[:space:]]|$)' && { echo "FAIL($f): workspace/all build: $line"; fail=1; continue; }
    # Count the -p FLAG (not the token after it) so `-p "$p"` in a for-loop counts as one.
    n=$(echo "$line" | grep -oE '(^|[[:space:]])-p([[:space:]]|=)' | wc -l | tr -d ' ')
    [ "$n" = "1" ] || { echo "FAIL($f): build-family invocation must carry exactly one -p (got $n): $line"; fail=1; }
  done < "$f"
done < <(find "$root" -type d -name target -prune -o -type f \
           \( -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' \
              -o -name 'Dockerfile*' -o -name 'justfile' -o -name 'Justfile' -o -path '*/packaging/*.sh' \) -print 2>/dev/null)
[ "$fail" -eq 0 ] && echo "build-invocation-lint: ok"
exit "$fail"
