#!/usr/bin/env bash
set -euo pipefail
root="${1:-$(git rev-parse --show-toplevel)}"; fail=0   # arg override for the negative-control
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# THE SCAN'S OWN SOUNDNESS, established before its result is trusted (#219).
# This was `find … 2>/dev/null` inside a process substitution, which discarded
# BOTH the error text and the exit status: a nonexistent `$root` printed nothing
# at all and reported `ok`, and an unreadable directory scanned what it could and
# reported `ok`. `find` separates the two cases cleanly (measured on this repo's
# userlands): rc 0 with zero matches is a legitimate empty result, rc != 0 is a
# bad root or a directory it could not read. Only the second is an error, and
# stderr is no longer thrown away.
#
# Comprehensive scan of build/release entry points: all workflows, Dockerfiles, Makefiles,
# justfiles, and every shell script — anywhere in the tree. Prune `target/` and, deliberately,
# `ci/gates/` itself: the capability-separation harness is the ENFORCEMENT + its negative-control
# fixtures legitimately embed `cargo build --workspace` strings; it is not a build entry point and
# scanning it would self-false-positive. The filter covers the file CLASSES named above --
# workflows, Dockerfiles, Makefiles/justfiles/`*.mk`, and `*.sh`. It does NOT cover
# `packaging/rpm/maknae.spec`'s `%build`, `ci/hooks/pre-push`, or the extension-less deb
# maintainer scripts; none carries a cargo invocation today, so the gap is latent rather than
# live, and the sentence says what is matched rather than claiming every build path.
#
# `.claude/` is pruned because it holds NESTED CHECKOUTS. The project's own
# worktree tooling creates full working trees under `.claude/worktrees/`, and
# `find` does not consult `.gitignore`, so without this the gate lints every
# sibling branch's tree as if it were this one: the scanned count becomes a
# function of how many worktrees a developer happens to have open (7 in a clean
# checkout, 14 with one worktree), and an in-flight `cargo build --workspace` on
# another branch fails the main checkout's gate. Sharpened by this change --
# the awk-status check below turns a `chmod 000` fixture left behind in a
# sibling worktree into a hard failure where the old `2>/dev/null` shrugged.
if ! find "$root" -type d \( -name target -o -name '.claude' -o -path '*/ci/gates' \) -prune -o -type f \
        \( -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' \
           -o -name 'Dockerfile*' -o -name 'justfile' -o -name 'Justfile' \
           -o -name 'Makefile' -o -name 'makefile' -o -name 'GNUmakefile' -o -name '*.mk' \
           -o -name '*.sh' \) -print > "$tmp/files"; then
  echo "FAIL build-invocation-lint: the file scan errored under '$root' (see above)."
  echo "  A partial scan cannot show the ABSENCE of a bad build invocation."
  exit 1
fi

# FLOOR. Zero scanned files is not a clean tree, it is no tree: a wrong `$root`,
# an over-matching prune, or a filter that stopped matching anything. Every real
# checkout carries workflows, and every negative-control fixture EXPECTED to
# reach the scan holds one workflow file (two fixtures deliberately hold none --
# they exist to prove this floor and the scan-error branch fire), so one is the
# legitimate minimum on every input this gate is meant to pass.
scanned=$(grep -c . < "$tmp/files" || true)
if [ "$scanned" -eq 0 ]; then
  echo "FAIL build-invocation-lint: scanned ZERO files under '$root'."
  echo "  Nothing was examined, so 'no bad invocation found' is not a finding."
  echo "  Wrong root, an over-matching prune, or a filter that matches nothing."
  exit 1
fi

# Scan the WORKING TREE (find). Join backslash line-continuations first, so a cargo build split
# across lines cannot hide its flags from a line-by-line scan (Codex hardening).
while IFS= read -r f; do
  # awk: strip a trailing "\" and buffer the line, emitting one LOGICAL line per shell command.
  #
  # Its status is READ, for the same reason as the find above. `find` lists a
  # file it cannot read (it needs permission on the DIRECTORY, not the file), so
  # `awk` then failed with `can't open file`, the process substitution swallowed
  # the status, the inner loop saw no lines, and a file carrying a REAL violation
  # was scanned as clean at `ok` / rc 0 -- verified before this change (#219).
  if ! awk '{ if (sub(/\\[[:space:]]*$/,"")) { buf = buf $0 " " } else { print buf $0; buf = "" } } END { if (buf != "") print buf }' \
       "$f" > "$tmp/logical"; then
    # No `--` guard here, deliberately: this awk treats `--` as a FILENAME, not
    # an end-of-options marker, and adding it made the gate fail on its first
    # real file. `$root` is absolute on every invocation (the default is
    # `git rev-parse --show-toplevel`; the override is passed absolute), so no
    # path reaching this line can begin with a dash.
    echo "FAIL build-invocation-lint: could not read '$f' (see above)."
    echo "  A file that cannot be read has not been cleared."
    exit 1
  fi
  while IFS= read -r line; do
    echo "$line" | grep -qE 'cargo[[:space:]]+(build|rustc|auditable[[:space:]]+build|deb|generate-rpm)' || continue
    echo "$line" | grep -qE '(--workspace|--all)([[:space:]]|$)' && { echo "FAIL($f): workspace/all build: $line"; fail=1; continue; }
    # The `|| true` is load-bearing, not defensive noise. Under `pipefail` a
    # ZERO-match `grep` fails the whole pipeline, the assignment fails, and
    # `set -e` killed the script BEFORE the FAIL below could print -- so the
    # most likely violation of all, `cargo build --release` with no `-p` at
    # all, exited 1 having printed nothing on stdout or stderr. The `got $n`
    # diagnostic was dead code for n=0, and because `expect_reject` requires a
    # printed FAIL the branch was structurally unprobeable. Measured before this
    # change (#219). `grep -o | wc -l` counts OCCURRENCES; `grep -c` counts
    # matching lines and would score `-p a -p b` as 1.
    n=$(echo "$line" | { grep -oE '(^|[[:space:]])-p([[:space:]]|=)' || true; } | wc -l | tr -d ' ')
    [ "$n" = "1" ] || { echo "FAIL($f): build-family invocation must carry exactly one -p (got $n): $line"; fail=1; }
  done < "$tmp/logical"
done < "$tmp/files"
[ "$fail" -eq 0 ] && echo "build-invocation-lint: ok ($scanned files scanned)"
exit "$fail"
