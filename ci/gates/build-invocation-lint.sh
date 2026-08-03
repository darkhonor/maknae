#!/usr/bin/env bash
set -euo pipefail
root="${1:-$(git rev-parse --show-toplevel)}"; fail=0   # arg override for the negative-control
# Scan the WORKING TREE (find). Join backslash line-continuations first, so a cargo build split
# across lines cannot hide its flags from a line-by-line scan (Codex hardening).
while IFS= read -r f; do
  # awk: strip a trailing "\" and buffer the line, emitting one LOGICAL line per shell command.
  while IFS= read -r line; do
    echo "$line" | grep -qE 'cargo[[:space:]]+(build|rustc|auditable[[:space:]]+build|deb|generate-rpm)' || continue
    echo "$line" | grep -qE '(--workspace|--all)([[:space:]]|$)' && { echo "FAIL($f): workspace/all build: $line"; fail=1; continue; }
    n=$(echo "$line" | grep -oE '(^|[[:space:]])-p([[:space:]]|=)' | wc -l | tr -d ' ')
    [ "$n" = "1" ] || { echo "FAIL($f): build-family invocation must carry exactly one -p (got $n): $line"; fail=1; }
  done < <(awk '{ if (sub(/\\[[:space:]]*$/,"")) { buf = buf $0 " " } else { print buf $0; buf = "" } } END { if (buf != "") print buf }' "$f")
# Comprehensive scan of build/release entry points: all workflows, Dockerfiles, Makefiles,
# justfiles, and every shell script — anywhere in the tree. Prune `target/` and, deliberately,
# `ci/gates/` itself: the capability-separation harness is the ENFORCEMENT + its negative-control
# fixtures legitimately embed `cargo build --workspace` strings; it is not a build entry point and
# scanning it would self-false-positive. Any real build path (workflows/Dockerfiles/Makefile/
# packaging or other ci scripts) is covered.
done < <(find "$root" -type d \( -name target -o -path '*/ci/gates' \) -prune -o -type f \
           \( -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' \
              -o -name 'Dockerfile*' -o -name 'justfile' -o -name 'Justfile' \
              -o -name 'Makefile' -o -name 'makefile' -o -name 'GNUmakefile' -o -name '*.mk' \
              -o -name '*.sh' \) -print 2>/dev/null)
[ "$fail" -eq 0 ] && echo "build-invocation-lint: ok"
exit "$fail"
