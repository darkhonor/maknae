#!/usr/bin/env bash
# Exact-inventory gate over the action vocabulary (#67, spec R7).
#
# Four closed vocabularies must each match the manifest exactly, BOTH
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

# grantable MUST be a subset of `action` (#162). A grantable term with no Verb
# variant behind it is a grant an operator can write, that validates, that boots
# -- and that decides nothing, because no request ever carries that action. The
# manifest exactness above does NOT catch it: both kinds would simply carry
# their own rows and agree with the code.
awk -F'\t' '$1=="grantable"{print $2}' "$tmp/code" | sort -u > "$tmp/grantable"
awk -F'\t' '$1=="action"{print $2}' "$tmp/code" | sort -u > "$tmp/actions"
if [ -s "$tmp/grantable" ] && ! orphans=$(comm -23 "$tmp/grantable" "$tmp/actions") || [ -n "${orphans:-}" ]; then
  echo "FAIL: grantable term(s) with no matching action term:"
  printf '  %s\n' $orphans
  echo "  A grantable term must name a real action, or an operator can grant"
  echo "  something no request will ever carry."
  exit 1
fi

# --- #181: the RECORD is checkable, not just present. Both checks run LAST,
# deliberately: the inventory diff and the subset check above fire first, so
# their negative-control fixtures keep their short rationales and reject for
# their OWN reasons. Order is load-bearing — moving these earlier makes five
# probes reject on clause text instead of the checks they exist to prove.

# ARITY first: exactly four non-empty TAB-separated fields per data row. New
# coverage in itself — before this, a row with no disposition and no rationale
# passed green (`cut -f1,2` never read fields 3-4) — and it rules out
# tab-bearing rationales by construction, which the clause table relies on.
bad_arity=$(awk -F'	' '!/^#/ && NF && !(NF==4 && $1!="" && $2!="" && $3!="" && $4!="")' "$MANIFEST")
if [ -n "$bad_arity" ]; then
  echo "FAIL: manifest row(s) without exactly four non-empty fields:"
  printf '%s
' "$bad_arity" | sed 's/^/  /'
  echo "  kind<TAB>name<TAB>disposition<TAB>rationale — a row missing its"
  echo "  disposition or rationale is not a recorded decision."
  exit 1
fi

# Then the (kind, disposition) → clause table. `index()` CONTAINMENT, never
# regex (two clauses carry parens — an ERE false-accepts `a(b)` against `ab`)
# and never field-equality (the true rows carry the clause inside longer
# text). An UNRECOGNIZED pair FAILS — fail-closed includes this gate: a row
# `action<TAB>x<TAB>pending<TAB>...` matching no rule must never pass by
# falling off the table (#181; the rationale-accuracy defect this closes was
# 51 rows asserting behaviour that does not occur).
bad_clause=$(awk -F'	' '
  BEGIN {
    clause["action|granted"]            = "shipped;"
    clause["capability|granted"]        = "the only grammar capability"
    clause["action|not-granted"]        = "answers Unauthorized to an unpermitted caller"
    clause["kernel-action|not-granted"] = "no Verb variant"
    clause["action|not-granted-but-grantable"]  = "Ungranted by default; operator MAY grant per-role"
    clause["grantable|grantable-not-granted"]   = "operator MAY grant per-role via `roles:`"
  }
  /^#/ || !NF { next }
  {
    key = $1 "|" $3
    if (!(key in clause)) { print "unrecognized (kind, disposition): " $0; next }
    if (index($4, clause[key]) == 0) { print "rationale lacks its clause (" clause[key] "): " $0 }
  }
' "$MANIFEST")
if [ -n "$bad_clause" ]; then
  echo "FAIL: manifest disposition/rationale disagreement(s):"
  printf '%s
' "$bad_clause" | sed 's/^/  /'
  echo "  Each (kind, disposition) pair requires its clause in the rationale,"
  echo "  so the record cannot assert behaviour that does not occur (#181)."
  exit 1
fi

echo "verb-vocabulary-drift: $(wc -l < "$tmp/code" | tr -d ' ') terms, manifest exact"
