#!/usr/bin/env bash
# Shared helper: read packaging/common/packaged-binaries.txt, and PROVE the
# manifest is real.
#
# The manifest states intent (which binaries ship). `cargo metadata` is used
# here to VALIDATE that intent — every named binary must be a real bin target
# of this workspace — rather than to derive it. That is the correct direction:
# metadata cannot know that maknae-spifc is deliberately unshipped, but it can
# catch a typo or a binary that no longer exists.
set -euo pipefail

packaged_binaries() {
    local root="$1" manifest="$1/packaging/common/packaged-binaries.txt"
    [ -s "$manifest" ] || { echo "ERROR: $manifest is absent or empty" >&2; return 1; }
    local names
    names="$(grep -vE '^[[:space:]]*(#|$)' "$manifest")"
    [ -n "$names" ] || { echo "ERROR: $manifest declares no binaries" >&2; return 1; }

    # Every declared binary must be a real bin TARGET of this workspace.
    local targets
    targets="$(cargo metadata --no-deps --format-version 1 --locked \
        --manifest-path "$root/Cargo.toml" \
      | python3 -c "import json,sys
m=json.load(sys.stdin)
print('\n'.join(sorted({t['name'] for p in m['packages'] for t in p['targets'] if 'bin' in t['kind']})))")"
    [ -n "$targets" ] || { echo "ERROR: derived no bin targets from cargo metadata" >&2; return 1; }

    local b
    for b in $names; do
        printf '%s\n' "$targets" | grep -qx -- "$b" || {
            echo "ERROR: packaged binary '$b' is not a bin target of this workspace" >&2
            return 1
        }
    done
    printf '%s\n' $names
}
