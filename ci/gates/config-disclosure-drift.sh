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
  # NOTE: `Ceiling` spans TWO YAML levels. Six fields sit under
  # `core.handling.ceiling`, but `accreditation_ref` is a SIBLING of `ceiling`
  # (`parse_handling` accepts exactly those two keys), so the synthesised
  # `core.handling.ceiling.accreditation_ref` is a path no config can contain.
  # That is harmless ONLY because `core.handling` is suppressed by prefix, which
  # covers both spellings -- and the check below enforces that precondition
  # rather than leaving it as an assumption.
  "crates/maknae-config/src/ceiling.rs|Ceiling|core.handling.ceiling"
)
# The Ceiling entry's approximate paths are safe only under this suppression.
CEILING_REQUIRES_SUPPRESSED="core.handling"

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
# Every quoted literal on every line of the range, not just the first, and not
# only lines matching `^    "`. rustfmt collapses a short const array onto one
# line -- and `cargo fmt --check` is itself a CI gate -- so an anchored,
# first-literal-only reader emits ZERO rows for a collapsed list and never sees
# its `];` terminator either, leaking state into the rest of the file. It then
# reports the paths as "recorded in the manifest, absent from the code" and
# instructs the reader to DELETE manifest rows that are in fact correct.
extract() { # <const-name> <kind>
  awk -v want="const $1" -v kind="$2" '
    index($0, want) == 1 { f=1 }
    # Skip comment lines: these lists carry their rationale inline, and the
    # rationale contains quoted prose ("carried as-is", "SCIF-B7"). Dropping
    # the old `^    "` anchor to tolerate a rustfmt-collapsed array meant
    # picking those up as paths.
    f && /^[[:space:]]*\/\// { next }
    f { line=$0
        while (match(line, /"[^"]+"/)) {
          print kind "\t" substr(line, RSTART+1, RLENGTH-2)
          line = substr(line, RSTART+RLENGTH)
        }
      }
    f && /\];/ { f=0 }
    f && /^const / && index($0, want) != 1 { f=0 }
  ' "$DOC"
}
{ extract DISCLOSABLE disclose; extract SUPPRESSED omit; } | sort -u > "$tmp/code"
sort -u "$tmp/code" -o "$tmp/code"

# 2. Every config STRUCT FIELD, as a dotted path.
: > "$tmp/fields"
for entry in "${SURFACE[@]}"; do
  IFS='|' read -r f st sec <<< "$entry"
  before=$(wc -l < "$tmp/fields")
  awk -v s="pub struct $st {" -v p="$sec" '
    index($0, s) { f=1; next }
    f && /^}/ { f=0 }
    f && match($0, /pub [a-z0-9_]+:/) { print p "." substr($0, RSTART+4, RLENGTH-5) }
  ' "$f" >> "$tmp/fields"
  # A SURFACE entry that contributes NOTHING must FAIL, never pass quietly.
  # This is the fail-open the previous two extractions both had: a missing
  # anchor yields zero rows and a green gate. Renaming `TransportConfig` to
  # `TransportSettings` silently dropped all five transport fields from the
  # decision requirement and the gate still exited 0 -- after which a new
  # field could be added with no manifest row and CI stayed green. Note the
  # asymmetry that hid it: renaming a CODE-side anchor (`DISCLOSABLE`) fails
  # CLOSED via the 4a diff, so only the safe half had ever been probed.
  if [ "$(wc -l < "$tmp/fields")" -eq "$before" ]; then
    echo "FAIL: SURFACE entry '$entry' matched no 'pub struct $st {' in $f."
    echo "  Renamed, moved, made generic, or turned into a tuple struct?"
    echo "  A surface that contributes no fields is not a covered surface."
    exit 1
  fi
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

if ! grep -qP "^omit\t$CEILING_REQUIRES_SUPPRESSED\t" "$MANIFEST"; then
  echo "FAIL: '$CEILING_REQUIRES_SUPPRESSED' is no longer omitted."
  echo "  The Ceiling SURFACE entry synthesises approximate paths (its"
  echo "  accreditation_ref field is a YAML sibling of \`ceiling\`, not a child),"
  echo "  which is only safe while that whole subtree is prefix-suppressed."
  echo "  Re-derive the Ceiling entry's paths before changing this."
  exit 1
fi

echo "config-disclosure-drift: $(wc -l < "$tmp/man_paths" | tr -d ' ') paths decided, $(wc -l < "$tmp/fields" | tr -d ' ') struct fields covered"
