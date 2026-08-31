#!/usr/bin/env bash
# Exact-inventory gate over the `admin.config.show` disclosure surface (#162).
#
# WHY THIS EXISTS. The completeness of this security control rested on a prose
# instruction telling the next author which artifact to consult, and a five-round
# review loop found that instruction WRONG TWICE:
#   - built from the Rust parsers alone -> missed `core.schema_version` and
#     `core.identity.*`, which no parser names because they are carried verbatim;
#   - then re-pointed at docs/configuration.md alone -> that documents `core` and
#     `lake` only, and is silent on the four other live sections holding most of
#     the allowlist and the one suppression the mechanism exists for.
# The surface is a UNION of several artifacts, so no single "read this file"
# instruction can be right. This enumerates it instead.
#
# The gate asserts a DECISION WAS RECORDED for every config path. It never
# asserts a path is disclosed: `mask` and `omit` are valid, and `mask` is the
# common answer.
set -euo pipefail
cd "$(dirname "$0")/../.."

DOC=crates/maknae-config/src/document.rs
MANIFEST=ci/gates/config-disclosure-manifest.txt
PARSERS=(
  crates/maknae-config/src/transport.rs
  crates/maknae-config/src/audit_cfg.rs
  crates/maknae-config/src/principal.rs
  crates/maknae-vault/src/config.rs
)

for f in "$DOC" "$MANIFEST" "${PARSERS[@]}"; do
  [ -f "$f" ] || { echo "FAIL: missing $f"; exit 1; }
done

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# 1. What the CODE classifies. Both lists are `&[&str]` of dotted paths; the
#    awk ranges stop at the closing `];` so the withheld PROSE block below
#    DISCLOSABLE is not scanned (it is commentary, not a classification).
awk '/^const DISCLOSABLE/{f=1} f && /^    "/{ if (match($0, /"[a-z0-9_.]+"/)) print "disclose\t" substr($0,RSTART+1,RLENGTH-2) } f && /^\];/{f=0}' \
  "$DOC" | sort -u > "$tmp/code"
awk '/^const SUPPRESSED/{f=1} f && /^    "/{ if (match($0, /"[a-z0-9_.]+"/)) print "omit\t" substr($0,RSTART+1,RLENGTH-2) } f && /^\];/{f=0}' \
  "$DOC" | sort -u >> "$tmp/code"
sort -u "$tmp/code" -o "$tmp/code"

# 2. What the PARSERS read. A key a parser consumes but nobody classified is
#    the miss this gate exists to catch — it masks by default, which is safe
#    for a VALUE and NOT safe for a key whose presence is the disclosure.
: > "$tmp/parsed"
for f in "${PARSERS[@]}"; do
  sec=$(basename "$f" .rs)
  case "$sec" in
    transport) sec=transport ;;
    audit_cfg) sec=audit ;;
    principal) sec=principal ;;
    config)    sec=vault ;;
  esac
  # `|| true` on both greps: a parser file with NO matching key makes grep exit
  # 1, which under `set -euo pipefail` aborts the gate SILENTLY -- exit 1 with
  # no FAIL line, which `expect_reject` correctly reports as "crash, not a
  # rejection". Every real parser has matches, so this was invisible until the
  # negative-control fixture (which stubs three of them empty) ran.
  { grep -oE '(get|get_str|bounded_u32)\([a-z_]+, "[a-z0-9_]+"' "$f" || true; } \
    | { grep -oE '"[a-z0-9_]+"' || true; } | tr -d '"' | sed "s|^|$sec.|" >> "$tmp/parsed"
done
sort -u "$tmp/parsed" -o "$tmp/parsed"

grep -v '^#' "$MANIFEST" | grep -v '^[[:space:]]*$' > "$tmp/man_raw"
cut -f1,2 "$tmp/man_raw" | sort -u > "$tmp/man_all"
awk -F'\t' '$1!="mask"{print $1 "\t" $2}' "$tmp/man_raw" | sort -u > "$tmp/man_code"
cut -f2 "$tmp/man_raw" | sort -u > "$tmp/man_paths"

# 3a. The code's two lists must match the manifest's non-mask rows exactly.
if ! diff -u "$tmp/man_code" "$tmp/code" > "$tmp/d1"; then
  echo "FAIL: DISCLOSABLE/SUPPRESSED and $MANIFEST disagree."
  echo "  '-' = recorded in the manifest, absent from the code"
  echo "  '+' = in the code, with NO recorded decision"
  sed -n '3,$p' "$tmp/d1"
  exit 1
fi

# 3b. Every key a parser reads must carry a recorded decision.
if ! missing=$(comm -23 "$tmp/parsed" "$tmp/man_paths") || [ -n "${missing:-}" ]; then
  echo "FAIL: config key(s) a parser reads with NO recorded disclosure decision:"
  printf '  %s\n' $missing
  echo "  Add a row to $MANIFEST. 'mask' is a valid decision — but decide it,"
  echo "  because deny-by-default masks a VALUE and does not hide a KEY whose"
  echo "  presence is itself the disclosure."
  exit 1
fi

echo "config-disclosure-drift: $(wc -l < "$tmp/man_paths" | tr -d ' ') paths, all decided"
