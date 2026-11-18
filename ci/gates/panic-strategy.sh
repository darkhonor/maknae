#!/usr/bin/env bash
# The panic strategy stays unwind (#544): the catch_unwind boundaries depend on it.
# usage: panic-strategy.sh [--root R] [--release-proof]
set -euo pipefail
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_LITERAL_PATHSPECS GIT_NOGLOB_PATHSPECS GIT_GLOB_PATHSPECS GIT_ICASE_PATHSPECS GIT_GRAFT_FILE
export GIT_NO_REPLACE_OBJECTS=1
here="$(cd "$(dirname "$0")" && pwd)"; source "$here/lib.sh"

root=""; proof=0
while [ $# -gt 0 ]; do
  case "$1" in
    --root) root="${2:?--root needs a path}"; shift 2;;
    --release-proof) proof=1; shift;;
    *) echo "FAIL panic-strategy: unknown argument: $1"; exit 2;;
  esac
done
if [ -z "$root" ] && ! root="$(git rev-parse --show-toplevel)"; then
  echo "FAIL panic-strategy: not in a git checkout and no --root given"; exit 1
fi
root="$(cd "$root" && pwd -P)"

if [ "$proof" -eq 1 ]; then
  exec python3 "$here/panic_check.py" proof "$root"
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/maknae-panic-strategy.XXXXXXXX")"; trap 'rm -rf "$tmp"' EXIT
if ! build_surface_files "$root" "$tmp/files" \
       -o -path '*/.github/actions/*' -o -path '*/ci/hooks/*' -o -name '*.spec'; then
  echo "FAIL panic-strategy: the build-surface scan errored under '$root' (see above)."; exit 1
fi
: > "$tmp/surfaces.tsv"; n=0
while IFS= read -r f; do
  n=$((n+1))
  if ! join_continuations "$f" "$tmp/joined.$n"; then
    echo "FAIL panic-strategy: could not read '$f' (see above)."; exit 1
  fi
  printf '%s\t%s\n' "${f#"$root"/}" "$tmp/joined.$n" >> "$tmp/surfaces.tsv"
done < "$tmp/files"
python3 "$here/panic_check.py" static "$root" "$tmp/surfaces.tsv"
echo "panic-strategy: ok ($n build-surface files scanned)"
