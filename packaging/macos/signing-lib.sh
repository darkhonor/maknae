#!/bin/bash
signed_entitlements_empty() {
    local out
    out="$(codesign -d --entitlements - --xml "$1" 2>/dev/null)" || return 1
    [ -z "$out" ] && return 0
    [ "$(printf '%s' "$out" | plutil -convert json -o - - 2>/dev/null)" = "{}" ]
}
