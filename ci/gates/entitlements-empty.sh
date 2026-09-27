#!/usr/bin/env bash
# ADR-0018 decision 6: every Developer ID signature of the plane binaries carries an EMPTY entitlement set.
set -euo pipefail
command -v plutil >/dev/null 2>&1 || { echo "FAIL: plutil unavailable (macOS only)"; exit 2; }
[ "$#" -gt 0 ] || { echo "FAIL: no entitlements files given"; exit 1; }
rc=0
for f in "$@"; do
    json="$(plutil -convert json -o - -- "$f" 2>/dev/null)" || { echo "FAIL: $f is not a readable plist"; rc=1; continue; }
    if [ "$json" != "{}" ]; then
        echo "FAIL: $f declares entitlements: $json"
        rc=1
    fi
done
[ "$rc" -eq 0 ] && echo "entitlements-empty: ok"
exit "$rc"
