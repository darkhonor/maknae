#!/bin/bash
signed_entitlements_empty() {
    local out
    out="$(codesign -d --entitlements - --xml "$1" 2>/dev/null)" || return 1
    [ -z "$out" ] && return 0
    [ "$(printf '%s' "$out" | plutil -convert json -o - - 2>/dev/null)" = "{}" ]
}
signed_hardened_runtime() {
    local out flags
    out="$(codesign -dv --verbose=4 "$1" 2>&1)" || return 1
    flags="$(printf '%s\n' "$out" | sed -n 's/^CodeDirectory .*flags=\([^ ]*\).*/\1/p' | head -1)"
    case "$flags" in
        *runtime*) return 0 ;;
        *) return 1 ;;
    esac
}
