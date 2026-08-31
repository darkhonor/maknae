#!/usr/bin/env bash
# Exact-inventory gate over the `admin.config.show` disclosure surface (#162).
#
# WHY THIS EXISTS, AND WHY IT LOOKS LIKE THIS.
#
# The completeness of this control first rested on a prose instruction naming
# which artifact to consult, and a review loop found that instruction wrong
# twice (parsers only -> missed `core.*`, which no parser names; then
# docs/configuration.md only -> that documents `core` and `lake` and is silent
# on the four other live sections). So it was replaced by a gate.
#
# The FIRST version of this gate then repeated the same mistake one layer out:
# it extracted parser keys with a regex over `get(`/`get_str(`/`bounded_u32(`
# call shapes, written against assumed shapes and never run against the real
# files. Every `bounded_*` call in transport.rs is MULTI-LINE, and `grep -oE`
# is line-based, so the gate's own named accessor matched ZERO call sites in
# the whole tree -- four of five transport keys could be deleted from every
# decision record and it still printed "all decided".
#
# So the extraction is inverted: it reads the config STRUCT FIELDS, which ARE
# the parsed key set. A field cannot be added without appearing here, whatever
# accessor shape or line wrapping the parser uses.
#
# The gate asserts a DECISION WAS RECORDED for every path. It never asserts a
# path is disclosed: `mask` and `omit` are valid, and `mask` is the common one.
set -euo pipefail
cd "$(dirname "$0")/../.."

DOC=crates/maknae-config/src/document.rs
MANIFEST=ci/gates/config-disclosure-manifest.txt

# file | struct | section prefix for its fields. A file may appear twice with
# two structs; the section is DECLARED, never inferred from the basename --
# maknae-vault/src/config.rs reads keys from both `vault` and `core`.
SURFACE=(
  "crates/maknae-config/src/transport.rs|TransportConfig|transport"
  "crates/maknae-config/src/audit_cfg.rs|AuditConfig|audit"
  "crates/maknae-config/src/principal.rs|Principal|principal"
  "crates/maknae-vault/src/config.rs|VaultConfig|vault"
  "crates/maknae-config/src/ceiling.rs|Ceiling|core.handling.ceiling"
)

for f in "$DOC" "$MANIFEST"; do
  [ -f "$f" ] || { echo "FAIL: missing $f"; exit 1; }
done
for entry in "${SURFACE[@]}"; do
  f="${entry%%|*}"
  [ -f "$f" ] || { echo "FAIL: missing $f (declared in SURFACE)"; exit 1; }
done

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# 1. What the CODE classifies. `"[^"]+"` deliberately, NOT a charset: the first
#    version used /"[a-z0-9_.]+"/ with the print INSIDE the match, so an entry
#    containing a capital or a hyphen -- both idiomatic in YAML -- produced no
#    row and was invisible to the diff below. A non-conforming path must SURFACE
#    as a mismatch, never be silently skipped.
awk '/^const DISCLOSABLE/{f=1} f && /^    "/{ if (match($0, /"[^"]+"/)) print "disclose\t" substr($0,RSTART+1,RLENGTH-2) } f && /^\];/{f=0}' \
  "$DOC" | sort -u > "$tmp/code"
awk '/^const SUPPRESSED/{f=1} f && /^    "/{ if (match($0, /"[^"]+"/)) print "omit\t" substr($0,RSTART+1,RLENGTH-2) } f && /^\];/{f=0}' \
  "$DOC" | sort -u >> "$tmp/code"
sort -u "$tmp/code" -o "$tmp/code"

# 2. Every config STRUCT FIELD, as a dotted path.
: > "$tmp/fields"
for entry in "${SURFACE[@]}"; do
  IFS='|' read -r f st sec <<< "$entry"
  awk -v s="pub struct $st {" -v p="$sec" '
    index($0, s) { f=1; next }
    f && /^}/ { f=0 }
    f && match($0, /pub [a-z0-9_]+:/) { print p "." substr($0, RSTART+4, RLENGTH-5) }
  ' "$f" >> "$tmp/fields"
done
sort -u "$tmp/fields" -o "$tmp/fields"

# 3. The manifest. Every row needs three tab fields with a non-empty rationale:
#    a bare path is not a decision, and the gate's own advice says "decide it".
if awk -F'\t' '!/^#/ && NF && (NF < 3 || $3 ~ /^[[:space:]]*$/) { print; bad=1 } END { exit bad?1:0 }' \
     "$MANIFEST" > "$tmp/badrows"; then :; else
  echo "FAIL: manifest row(s) with no rationale — a bare path is not a decision:"
  sed 's/^/  /' "$tmp/badrows"; exit 1
fi
grep -v '^#' "$MANIFEST" | grep -v '^[[:space:]]*$' > "$tmp/man_raw"
cut -f2 "$tmp/man_raw" | sort > "$tmp/man_paths_dup"
sort -u "$tmp/man_paths_dup" > "$tmp/man_paths"
if ! dupes=$(comm -23 "$tmp/man_paths_dup" "$tmp/man_paths") || [ -n "${dupes:-}" ]; then
  echo "FAIL: duplicate manifest path(s) — two decisions for one path:"
  printf '  %s\n' $dupes; exit 1
fi
awk -F'\t' '$1!="mask"{print $1 "\t" $2}' "$tmp/man_raw" | sort -u > "$tmp/man_code"

# 4a. The code's two lists must match the manifest's non-mask rows exactly.
if ! diff -u "$tmp/man_code" "$tmp/code" > "$tmp/d1"; then
  echo "FAIL: DISCLOSABLE/SUPPRESSED and $MANIFEST disagree."
  echo "  '-' = recorded in the manifest, absent from the code"
  echo "  '+' = in the code, with NO recorded decision"
  sed -n '3,$p' "$tmp/d1"
  exit 1
fi

# 4b. Every struct field must be DECIDED — by an exact row, or by a manifest
#     path that is a PREFIX of it, because `classify` in document.rs suppresses
#     by prefix (`core.handling` covers every leaf beneath it). An exact-match
#     comparison here would demand rows for leaves the prefix already governs.
undecided=""
while read -r path; do
  [ -n "$path" ] || continue
  ok=""
  while read -r m; do
    [ -n "$m" ] || continue
    case "$path" in "$m"|"$m".*) ok=1; break;; esac
  done < "$tmp/man_paths"
  [ -n "$ok" ] || undecided="$undecided $path"
done < "$tmp/fields"
if [ -n "$undecided" ]; then
  echo "FAIL: config field(s) with NO recorded disclosure decision:"
  printf '  %s\n' $undecided
  echo "  Add a row to $MANIFEST. 'mask' is a valid decision — but decide it:"
  echo "  deny-by-default masks a VALUE and does NOT hide a KEY whose presence"
  echo "  is itself the disclosure."
  exit 1
fi

echo "config-disclosure-drift: $(wc -l < "$tmp/man_paths" | tr -d ' ') paths decided, $(wc -l < "$tmp/fields" | tr -d ' ') struct fields covered"
