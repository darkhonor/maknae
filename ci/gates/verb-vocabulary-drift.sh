#!/usr/bin/env bash
# Exact-inventory gate over the action vocabulary (#67, spec R7).
#
# Three closed vocabularies must each match the manifest exactly, BOTH
# directions: a term with no manifest entry fails, and a manifest entry with no
# term fails. The gate asserts a DECISION WAS RECORDED for every term — it never
# asserts a grant exists; "not-granted" is a valid and usually correct entry.
set -euo pipefail
cd "$(dirname "$0")/../.."

HANDLER=crates/maknae-kernel/src/handler.rs
AUTHZ=crates/maknae-config/src/authz.rs
DECIDE=crates/maknae-authz-basic/src/decide.rs
MANIFEST=ci/gates/verb-manifest.txt

# $DECIDE joins this loop, not just the input list: without the existence
# check a missing file makes awk abort under `set -euo pipefail` with exit 2
# and no FAIL line, which expect_reject reports as "crash, not a rejection".
for f in "$HANDLER" "$AUTHZ" "$DECIDE" "$MANIFEST"; do
  [ -f "$f" ] || { echo "FAIL: missing $f"; exit 1; }
done

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# 1. action strings — the arms of verb_to_action
awk '/^pub fn verb_to_action/{f=1} f && /=> "/{ if (match($0, /"[a-z0-9_.]+"/)) { s=substr($0,RSTART+1,RLENGTH-2); print "action\t" s } } f && /^}/{f=0}' \
  "$HANDLER" | sort -u > "$tmp/code"

# 2. kernel actions — the KERNEL_ACTIONS constant
awk '/^pub const KERNEL_ACTIONS/{ while (match($0, /"[a-z0-9_.]+"/)) { print "kernel-action\t" substr($0,RSTART+1,RLENGTH-2); $0=substr($0,RSTART+RLENGTH) } }' \
  "$HANDLER" | sort -u >> "$tmp/code"

# 3. grammar capabilities — the arms of parse_pattern
awk '/fn parse_pattern/{f=1} f && /^        "[A-Z]/{ if (match($0, /"[A-Za-z]+"/)) { s=substr($0,RSTART+1,RLENGTH-2); print "capability\t" s } } f && /^}/{f=0}' \
  "$AUTHZ" | sort -u >> "$tmp/code"

# 4. grantable action terms — the GRANTABLE_ACTIONS constant (#162)
#
# The anchor ESCAPES the parens: awk is ERE, so an unescaped `(crate)` is a
# group and would match `pubcrate`, never the real constant. Unanchored
# `/GRANTABLE_ACTIONS/` is also wrong — it picks up the const-pin's own
# `admin.whoami` literal and inventories a term that is deliberately NOT
# grantable. The constant carries #[rustfmt::skip] and is declared on one
# line because this reads terms only off the matched line.
awk '/^pub\(crate\) const GRANTABLE_ACTIONS/{ while (match($0, /"[a-z0-9_.]+"/)) { print "grantable\t" substr($0,RSTART+1,RLENGTH-2); $0=substr($0,RSTART+RLENGTH) } }' \
  "$DECIDE" | sort -u >> "$tmp/code"

sort -u "$tmp/code" -o "$tmp/code"
grep -v '^#' "$MANIFEST" | grep -v '^[[:space:]]*$' | cut -f1,2 | sort -u > "$tmp/manifest"

if ! diff -u "$tmp/manifest" "$tmp/code" > "$tmp/diff"; then
  echo "FAIL: the action vocabulary and ci/gates/verb-manifest.txt disagree."
  echo "  '-' = in the manifest, not in the code (stale entry: a retired term)"
  echo "  '+' = in the code, not in the manifest (a term with NO recorded disposition)"
  echo "  Every term needs an entry. 'not-granted' is a valid disposition — the"
  echo "  gate requires a DECISION, not a grant."
  sed -n '3,$p' "$tmp/diff"
  exit 1
fi

echo "verb-vocabulary-drift: $(wc -l < "$tmp/code" | tr -d ' ') terms, manifest exact"
