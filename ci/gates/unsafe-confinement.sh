#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; source "$here/lib.sh"
root="${1:-$(git rev-parse --show-toplevel)}"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/maknae-unsafe-confinement.XXXXXXXX")"; trap 'rm -rf "$tmp"' EXIT
if ! cargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1 \
     > "$tmp/meta.json" 2> "$tmp/meta.err"; then
  echo "FAIL: cargo metadata failed under '$root'; nothing was examined. cargo said:"
  head -5 < "$tmp/meta.err" | sed 's/^/    /'
  exit 1
fi
if ! git -C "$root" ls-files -z -- '*.rs' > "$tmp/files" 2> "$tmp/files.err"; then
  echo "FAIL: git ls-files failed under '$root'; no source was examined. git said:"
  head -5 < "$tmp/files.err" | sed 's/^/    /'
  exit 1
fi
if ! git -C "$root" ls-files -z -- '.cargo/config' '.cargo/config.toml' '*/.cargo/config' '*/.cargo/config.toml' > "$tmp/configs" 2> "$tmp/configs.err"; then
  echo "FAIL: git ls-files failed under '$root' listing cargo configs. git said:"
  head -5 < "$tmp/configs.err" | sed 's/^/    /'
  exit 1
fi
python3 "$here/unsafe_check.py" "$root" "$SYS_CRATE" "${SYS_CONSUMER_ALLOW[*]}" "$tmp/meta.json" "$tmp/files" "$tmp/configs"
