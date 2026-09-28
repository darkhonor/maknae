#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; source "$here/lib.sh"
usage="usage: unsafe-confinement.sh [--root <dir>]"
root=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root)
      if [ "$#" -lt 2 ]; then echo "FAIL: unsafe-confinement: --root needs a directory; $usage"; exit 2; fi
      root="$2"; shift 2 ;;
    *) echo "FAIL: unsafe-confinement: unknown argument '$1'; $usage"; exit 2 ;;
  esac
done
if [ -z "$root" ] && ! root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "FAIL: unsafe-confinement: not inside a git work tree and no root given; nothing was examined"
  exit 1
fi
py="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
case "$py" in
  3.1[1-9]|3.[2-9][0-9]|[4-9].*) ;;
  *) echo "FAIL: unsafe-confinement: python >= 3.11 required (found '${py:-none}')"; exit 1 ;;
esac
tmp="$(mktemp -d "${TMPDIR:-/tmp}/maknae-unsafe-confinement.XXXXXXXX")"; trap 'rm -rf "$tmp"' EXIT
if ! cargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1 \
     > "$tmp/meta.json" 2> "$tmp/meta.err"; then
  echo "FAIL: cargo metadata failed under '$root'; nothing was examined. cargo said:"
  head -5 < "$tmp/meta.err" | sed 's/^/    /'
  exit 1
fi
if ! git -C "$root" ls-files -z > "$tmp/files" 2> "$tmp/files.err"; then
  echo "FAIL: git ls-files failed under '$root'; no source was examined. git said:"
  head -5 < "$tmp/files.err" | sed 's/^/    /'
  exit 1
fi
python3 "$here/unsafe_check.py" "$root" "$SYS_CRATE" "${SYS_CONSUMER_ALLOW[*]}" "$tmp/meta.json" "$tmp/files"
