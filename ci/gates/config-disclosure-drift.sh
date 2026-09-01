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
# file | struct | section prefix | EXPECTED FIELD COUNT.
#
# The count is the point. Three consecutive review rounds found a fail-open in
# this gate, and each fix closed the instance that was named while preserving
# the property: an anchor that yields no rows yields a green gate. R6 changed
# WHAT was matched; R7 added a floor at zero rows per entry. Neither asked the
# prior question -- is the anchor list right, and is it ALL of them? A count
# per entry answers it: a dropped field, a dropped entry, or a field the
# extractor cannot see all change a number a human must edit deliberately.
SURFACE=(
  "crates/maknae-config/src/transport.rs|TransportConfig|transport|5|config"
  "crates/maknae-config/src/audit_cfg.rs|AuditConfig|audit|3|config"
  "crates/maknae-config/src/principal.rs|Principal|principal|3|config"
  # NOTE: `Ceiling` spans TWO YAML levels. Six fields sit under
  # `core.handling.ceiling`, but `accreditation_ref` is a SIBLING of `ceiling`
  # (`parse_handling` accepts exactly those two keys), so the synthesised
  # `core.handling.ceiling.accreditation_ref` is a path no config can contain.
  # That is harmless ONLY because `core.handling` is suppressed by prefix, which
  # covers both spellings -- and the check below enforces that precondition
  # rather than leaving it as an assumption.
  "crates/maknae-config/src/ceiling.rs|Ceiling|core.handling.ceiling|7|config"
  # `admin.status` is a SECOND disclosure surface. `StatusView` carries
  # `transport.socket_path` (as `listener`), and `admin.status` /
  # `admin.config.show` are INDEPENDENT grants -- a role granted only the
  # former receives it without the latter, so the argument that "config.show
  # discloses it anyway" does not cover this path. Adding `au3_1`,
  # `vault.addr` or `principal.home` to this struct later would otherwise pass
  # every gate here. Prefix `status.` so its fields carry their own decisions.
  "crates/maknae-proto/src/wire.rs|StatusView|status|4|wire"
  # The SIBLING disclosure struct, added in the same commit for the same
  # feature. Inventorying one of a matched pair is how the pair's second member
  # ships unreviewed: adding `home` or `clearance` to this struct changes no
  # count, needs no row, and reaches every `admin.subject.list` grant-holder --
  # who may be the untrusted agent runtime, since `bindings: {admin:["agent"]}`
  # is now correctly reported.
  "crates/maknae-proto/src/wire.rs|RoleBindingView|binding|2|wire"
  # The THIRD wire disclosure struct. Its two fields are the caller's OWN peer
  # facts rather than deployment config, which is a defensible reason to scope
  # it out -- but that rule was nowhere written, `RoleBindingView` (policy-file
  # state, not maknae.yaml) is already inside, and `admin.whoami` is the only
  # payload reachable with NO `roles:` grant at all. Inventorying two of three
  # is how the third ships unreviewed, which is this table's own argument.
  "crates/maknae-proto/src/wire.rs|WhoamiView|whoami|2|wire"
  "crates/maknae-vault/src/config.rs|VaultConfig|vault|5|config"
)

# Sections with NO config struct: their keys are carried verbatim for their
# consumers. Each still needs a manifest row -- struct-less means the keys pass
# through, not that the disclosure is undecided.
#
# `core` is listed for completeness of the record, not because the coverage
# loop reaches it: `loader.rs::validate_specs` REJECTS `core` as a SectionSpec,
# so it is never in `registered`. Its rows are held by the 4a code-vs-manifest
# diff instead.
NO_STRUCT_SECTIONS="core lake"
# The Ceiling entry's approximate paths are safe only under this suppression.
CEILING_REQUIRES_SUPPRESSED="core.handling"

for f in "$DOC" "$MANIFEST"; do
  [ -f "$f" ] || { echo "FAIL: missing $f"; exit 1; }
done
# --- The WIRE half of SURFACE is exact-inventory too. The config half is
# cross-checked against boot.rs's SectionSpec registry, so an unlisted section
# fails closed; the wire rows were hand-maintained with NO closing rule, so a
# FOURTH `pub struct FooView` in wire.rs shipped with unchanged counts, no
# manifest row, and every one of its fields undecided -- demonstrated with a
# struct carrying a field literally named `vault_token`. The table's own
# comments ("inventorying two of three is how the third ships unreviewed")
# asserted the property; nothing enforced it. The closing rule is the file's
# own naming convention, both directions: every `pub struct <Name>View` in the
# wire file has a SURFACE row, and every wire SURFACE row names such a struct.
WIRE_FILE="crates/maknae-proto/src/wire.rs"
wire_declared="$(grep -oE '^(pub([[:space:]]|\([^)]*\)[[:space:]]))?struct [A-Za-z0-9_]+View\b' "$WIRE_FILE" \
  | awk '{print $NF}' | sort -u)"
# `if`, NOT an `[ ... ] && ...` AND-list: when the LAST SURFACE row is a
# config row the AND-list fails, the loop's status is 1, and under
# `set -euo pipefail` the gate dies with no FAIL line -- the same
# last-row-decides bug as R7's leaked `$sec`, in the check written to close it.
# Caught by the reorder probe, which is the only fixture with a config row last.
wire_listed="$(for entry in "${SURFACE[@]}"; do
  IFS='|' read -r f st _ _ k <<< "$entry"
  if [ "$k" = "wire" ] && [ "$f" = "$WIRE_FILE" ]; then echo "$st"; fi
done | sort -u)"
if [ "$wire_listed" != "$wire_declared" ]; then
  echo "FAIL: wire disclosure structs and the SURFACE table disagree:"
  echo "  SURFACE lists: $(echo $wire_listed)"
  echo "  wire.rs declares: $(echo $wire_declared)"
  echo "  A *View struct in $WIRE_FILE is a disclosure payload; give it a"
  echo "  SURFACE row (kind wire) and decide every field, or remove it."
  exit 1
fi

for entry in "${SURFACE[@]}"; do
  f="${entry%%|*}"
  [ -f "$f" ] || { echo "FAIL: missing $f (declared in SURFACE)"; exit 1; }
done

# --- The SURFACE inventory itself must cover every registered section. A new
# `maknae.yaml` section with a new config struct was previously invisible: the
# gate exited 0 and both its field names shipped on the wire with nobody ever
# asked the omit-vs-mask question. `std-fs-drift` sets the precedent -- an
# exact-inventory gate rejects stale exemptions as well as new calls.
# EVERY EXTRACTION IS COUNTED AGAINST AN INDEPENDENT TALLY. That is the rule
# this gate kept failing: an anchor a legitimate declaration form can omit
# yields no rows, no count change, and a green build. Keying on `[A-Z_]+_SECTION`
# const NAMES was defeated three ways -- a `name: "enclave".to_string()` string
# literal (the form boot.rs's own grammar accepts), a digit in the const name
# (`ENCLAVE2_SECTION`), and a renamed const -- each exiting 0 over an
# uncovered section whose key names then ship on the wire.
#
# So: read each SectionSpec's `name:` operand, resolve identifiers through the
# const table and take string literals verbatim, then assert the number
# resolved equals the number of SectionSpec blocks. A `name:` form this cannot
# read is now a HARD FAILURE, not a silent zero.
BOOT=crates/maknae-kernel/src/boot.rs
spec_count=$(grep -c 'SectionSpec {' "$BOOT" || true)
[ "$spec_count" -gt 0 ] || { echo "FAIL: no SectionSpec blocks found in $BOOT"; exit 1; }
operands=$(sed -n '/SectionSpec {/,/}/p' "$BOOT" | grep -oE 'name:[[:space:]]*[^,]+' | sed 's/name:[[:space:]]*//' || true)
registered=""
resolved=0
while read -r op; do
  [ -n "$op" ] || continue
  case "$op" in
    \"*\"*)  sec=$(printf '%s' "$op" | grep -oE '"[^"]+"' | head -1 | tr -d '"') ;;
    *)        c=$(printf '%s' "$op" | grep -oE '^[A-Za-z0-9_]+' | head -1)
              sec=$(grep -rhoE "const $c: &str = \"[^\"]+\"" crates/ 2>/dev/null | grep -oE '"[^"]+"' | tr -d '"' | head -1 || true) ;;
  esac
  if [ -z "$sec" ]; then
    echo "FAIL: cannot resolve SectionSpec name operand: $op"
    echo "  Every registered section must be resolvable to a section name, or"
    echo "  the gate is silently covering fewer sections than boot.rs registers."
    exit 1
  fi
  registered="$registered $sec"
  resolved=$((resolved+1))
done <<< "$operands"
if [ "$resolved" -ne "$spec_count" ]; then
  echo "FAIL: resolved $resolved section name(s) from $spec_count SectionSpec block(s) in $BOOT."
  echo "  A registration form this gate cannot read is an uncovered section."
  exit 1
fi
for sec in $registered; do
  covered=""
  for entry in "${SURFACE[@]}"; do
    IFS='|' read -r _ _ p _ <<< "$entry"
    case "$p" in "$sec"|"$sec".*) covered=1;; esac
  done
  case " $NO_STRUCT_SECTIONS " in
    *" $sec "*)
      # Declaring a section struct-less is not a way to silence it: it must
      # still carry a decision. Without this the list is an escape hatch.
      if ! awk -F'\t' -v s="$sec" '$2==s || index($2, s ".")==1 {found=1} END{exit found?0:1}' "$MANIFEST"; then
        echo "FAIL: section '$sec' is on NO_STRUCT_SECTIONS but has no manifest row."
        echo "  Struct-less means its keys are carried verbatim, not that its"
        echo "  disclosure is undecided."
        exit 1
      fi
      covered=1 ;;
  esac
  if [ -z "$covered" ]; then
    echo "FAIL: section '$sec' is registered in boot.rs but has no SURFACE entry"
    echo "  and is not on NO_STRUCT_SECTIONS. Every registered section's fields"
    echo "  must be enumerated, or the section declared struct-less with a reason."
    exit 1
  fi
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
    index($0, want ":") == 1 { f=1 }
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
    f && /^const / && index($0, want ":") != 1 { f=0 }
  ' "$DOC"
}
# RAW first, deduped second. The `sort -u` is what makes the 4a diff work and
# it is also what hides a repeated entry, so the duplicate check has to see the
# extraction BEFORE it -- writing the check after the deduping pipeline is a
# check that cannot fail, which is a mistake this branch has made before.
{ extract DISCLOSABLE disclose; extract SUPPRESSED omit; } > "$tmp/code_raw"
sort -u "$tmp/code_raw" > "$tmp/code"
# CODE-SIDE DUPLICATES, before the sort hides them. `sort -u` is what makes the
# 4a diff work, and it is also what makes a repeated DISCLOSABLE entry
# invisible -- the manifest side has refused duplicates since it was written,
# and the code side did not. Harmless at runtime (`classify` is boolean
# membership) but the classification inventory is the artifact a reviewer reads
# to answer "what does this disclose", and a list that repeats itself is a list
# nobody has checked.
if ! dupes=$(sort "$tmp/code_raw" | uniq -d) || [ -n "${dupes:-}" ]; then
  echo "FAIL: duplicate entr(ies) in DISCLOSABLE/SUPPRESSED:"
  printf '%s\n' "$dupes" | sed 's/^/  /'
  exit 1
fi
sort -u "$tmp/code" -o "$tmp/code"

# 2. Every config STRUCT FIELD, as a dotted path.
: > "$tmp/fields"
for entry in "${SURFACE[@]}"; do
  IFS='|' read -r f st sec want kind <<< "$entry"
  case "$kind" in
    wire|config) ;;
    *) echo "FAIL: SURFACE entry '$entry' declares no kind (wire|config)"; exit 1 ;;
  esac
  # `wire_prefixes` is a space-joined string that awk splits on " ", so a prefix
  # containing whitespace would silently become two phantom surfaces -- and
  # `byconstruction` would then match on half a name.
  case "$sec" in
    *[[:space:]]*|'') echo "FAIL: SURFACE entry '$entry' has an empty or whitespace-bearing prefix"; exit 1 ;;
  esac
  before=$(wc -l < "$tmp/fields")
  # Fields with ANY visibility or none: `pub`, `pub(crate)`, `pub(super)`, or
  # bare. Raw identifiers, capitals, and every field on a line.
  #
  # Visibility is IRRELEVANT to disclosure -- `flatten` walks the parsed
  # `Value`, not the struct -- and the regex kept keying on it anyway. It was
  # widened from `pub` to `pub(...)` for the instance one review named, which
  # left a bare `session_token_path: PathBuf,` contributing zero rows and no
  # count change. The prefix is optional now, which is what the rationale
  # already said it should be.
  # The STRUCT anchor takes any visibility too, matching the type lookup below.
  # It was `pub struct` and fails CLOSED (zero rows trips the exact count), but
  # the zero-row diagnostic never mentioned visibility -- so a maintainer who
  # declared a new SURFACE struct `pub(crate)`, which is house style here, got a
  # correct refusal with the wrong cause. Two anchors for one property should
  # not disagree; that disagreement is how the last recurrence happened.
  awk -v st="$st" -v p="$sec" -v k="$kind" '
    $0 ~ ("^(pub([[:space:]]|\\([^)]*\\)[[:space:]]))?struct " st "[[:space:]]*[<{]") { f=1; next }
    f && /^}/ { f=0 }
    # Comment skip is REQUIRED now that the visibility prefix is optional:
    # doc-comment prose containing `something:` would otherwise be read as a
    # field. `extract()` above already needed the same guard for the same
    # reason -- the asymmetry between the two extractors is how this recurred.
    f && /^[[:space:]]*\/\// { next }
    f { line=$0
        while (match(line, /(pub(\([^)]*\))?[[:space:]]+)?(r#)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*:/)) {
          tok = substr(line, RSTART, RLENGTH)
          rest = substr(line, RSTART+RLENGTH)
          sub(/^pub(\([^)]*\))?[[:space:]]+/, "", tok)
          sub(/[[:space:]]*:$/, "", tok)
          sub(/^r#/, "", tok)
          # `::` is a PATH separator, not a field. Dropping the mandatory `pub`
          # prefix made `serde_json::Value` match as a field named
          # `serde_json` -- caught immediately by the exact field count, which
          # is the whole argument for counting the yield rather than trusting
          # the pattern.
          # Emit `path<TAB>type`. The type matters: a field whose type is
          # itself a config struct is a SUBTREE, not a leaf, and counting it as
          # one row is the depth-blind tally -- `pub siem: SiemConfig` would
          # keep the count at 3 while `siem.url` and `siem.auth_token_path`
          # both reach the wire undecided.
          if (rest !~ /^:/) {
            ty = rest
            sub(/^[[:space:]]*/, "", ty)
            # Cut at the first comma or brace at ANGLE-BRACKET DEPTH ZERO.
            # A flat `sub(/[,{].*$/)` truncated `BTreeMap<String, SiemConfig>`
            # to `BTreeMap<String`, which matched no type and hid a subtree.
            depth = 0; cut = length(ty) + 1
            for (i = 1; i <= length(ty); i++) {
              ch = substr(ty, i, 1)
              if (ch == "<") depth++
              else if (ch == ">") depth--
              else if ((ch == "," || ch == "{") && depth <= 0) { cut = i; break }
            }
            ty = substr(ty, 1, cut - 1)
            gsub(/[[:space:]]+$/, "", ty)
            print p "." tok "\t" ty "\t" k
          }
          line = rest
        }
      }
  ' "$f" >> "$tmp/fields"
  # A SURFACE entry that contributes NOTHING must FAIL, never pass quietly.
  # This is the fail-open the previous two extractions both had: a missing
  # anchor yields zero rows and a green gate. Renaming `TransportConfig` to
  # `TransportSettings` silently dropped all five transport fields from the
  # decision requirement and the gate still exited 0 -- after which a new
  # field could be added with no manifest row and CI stayed green. Note the
  # asymmetry that hid it: renaming a CODE-side anchor (`DISCLOSABLE`) fails
  # CLOSED via the 4a diff, so only the safe half had ever been probed.
  got=$(( $(wc -l < "$tmp/fields") - before ))
  # EXACT, not "at least one". A nonzero-ness test measures "did this entry
  # contribute anything", never "did it contribute everything" -- so a
  # partially-extracted struct passed silently, which is how `pub(crate)` and
  # raw-identifier fields went unclassified.
  if [ "$got" -ne "$want" ]; then
    echo "FAIL: SURFACE entry '$entry' yielded $got field(s), expected $want."
    if [ "$got" -eq 0 ]; then
      echo "  Zero: renamed, moved, made generic, or turned into a tuple struct?"
      echo "  (Visibility is NOT the cause — any visibility, or none, is matched.)"
    else
      echo "  Fields were added or removed. Classify each one in $MANIFEST,"
      echo "  then update the count in this entry — deliberately, not to go green."
    fi
    exit 1
  fi
done
sort -u "$tmp/fields" -o "$tmp/fields"


# --- DEPTH. A field whose type is a config struct declared in this workspace
# is a subtree: its own fields become real YAML paths. Counting it as one leaf
# is the fifth instance of the same fail-open -- and the SILENT variant, since
# turning a scalar into a struct (`pub siem: Option<String>` -> `SiemConfig`,
# which document.rs itself anticipates) changes NO count at all.
#
# Precedent already in the table: `Ceiling` has its own SURFACE entry. Nothing
# enforced that it must.
while IFS=$'\t' read -r fpath fty fkind; do
  [ -n "$fty" ] || continue
  # Strip wrappers to FIXPOINT: a single pass left `Option<Box<SiemConfig>>` as
  # `Box<SiemConfig` and matched nothing.
  #
  # `Vec` IS stripped on the by-construction (wire) surfaces and is NOT on the
  # config surfaces, because the exemption is a fact about the CONSUMER, not
  # about the type. For a config document, `flatten` never recurses into
  # `Value::Seq` and `render` masks it whole, so a sequence genuinely is a leaf
  # and demanding coverage would block legitimate work. A wire struct is
  # serialized WHOLE by serde, which recurses into `Vec<T>` -- so turning
  # `members: Vec<String>` into `Vec<MemberView>` shipped four new fields
  # (including `home` and a token path) with IDENTICAL gate counts. That is the
  # silent variant this depth check exists to catch, inherited unexamined when
  # three wire structs joined SURFACE.
  # PER-ROW, from the field's OWN emitted kind. This read `$sec` -- a variable
  # left over from the extraction loop above, which by then held the LAST
  # SURFACE entry, so every one of the 31 rows saw `whoami`. The documented
  # config-surface exemption therefore did not exist, and reordering the SURFACE
  # array (a plausible grouping edit) silently restored the defeat this check
  # was added to close, at identical counts and EXIT=0.
  case "$fkind" in
    wire) wrappers='(Option|Box|Arc|Vec)' ;;
    *)    wrappers='(Option|Box|Arc)' ;;
  esac
  bare=$(printf '%s' "$fty" | sed -E ":a; s/^${wrappers}<//; ta" | sed -E 's/>+$//' | sed 's/.*:://')
  # A dynamic-key map is a subtree whose keys nobody can enumerate -- the same
  # structural condition that moved `audit.au3_1` from mask to omit. Demand the
  # same coverage rather than letting a typed map ship its deployer-authored
  # key names.
  case "$fty" in
    *HashMap\<*|*BTreeMap\<*|*serde_json::Value*|*Map\<*) bare="__DYNAMIC_MAP__" ;;
  esac
  # THIS CRATE'S OWN `Value` IS A MAP-BEARING ENUM, not a scalar
  # (`value.rs`: `Map(Vec<(String, Value)>)`), so a `pub extra: Value`
  # pass-through block is an unenumerable deployer-authored subtree -- the
  # identical condition that moved `audit.au3_1` and then `lake` to SUPPRESSED.
  # It was on the scalar skip list below, where it was DEAD for its apparent
  # purpose: `serde_json::Value` is intercepted by the map case above and never
  # reaches that list, so the entry was live only for the hazardous native
  # spelling. `crate::Value` and `maknae_config::Value` reduce to the same token.
  case "$bare" in
    Value) bare="__DYNAMIC_MAP__" ;;
  esac
  case "$bare" in
    ''|bool|u8|u16|u32|u64|usize|i8|i16|i32|i64|isize|f32|f64|String|PathBuf|str) continue ;;
  esac
  # ANY visibility, or none -- `pub(crate) struct` and bare `struct` are live
  # house style in this workspace, including inside the very crate SURFACE
  # reads (`loader.rs::Registry`, `builder.rs::Builder`). This anchor was
  # written `^pub struct` and so re-introduced, eighty lines below the fix, the
  # exact mistake the FIELD extractor had already been corrected for twice.
  # Visibility is irrelevant to disclosure at both levels, for one reason:
  # `flatten` walks the parsed `Value`, not the Rust item.
  # `$bare` is interpolated into an ERE below. A type that reduces to an
  # unbalanced bracket or paren -- a tuple or array field -- makes `grep` error,
  # and `|| continue` would then treat it as a LEAF: fail-open, on the check
  # whose whole job is to refuse leaves that are not. Unreachable today (no such
  # field exists on any SURFACE struct); refused rather than left to a future
  # one, because the failure is silent.
  # Only ERE METACHARACTERS are refused, not every non-identifier. On a CONFIG
  # surface `Vec<String>` reduces to `Vec<String` by design -- `Vec` is not
  # stripped there, and the residue is a leaf under the documented exemption --
  # so demanding a plain identifier here rejected five live fields. A `(`, `[`
  # or `{` is different: it makes the ERE invalid, grep errors, and `|| continue`
  # scores the field a LEAF.
  case "$bare" in
    *[\(\)\[\]\{\}\\*+?^\$.\|]*)
      echo "FAIL: '$fpath' has type '$fty', which reduces to '$bare' —"
      echo "  that carries a regex metacharacter, so the subtree grep below"
      echo "  cannot be trusted to answer (an invalid pattern reads as 'leaf')."
      echo "  Give it a SURFACE entry, an 'omit' manifest row, or a named type."
      exit 1 ;;
  esac
  if [ "$bare" != "__DYNAMIC_MAP__" ]; then
    # `struct` OR `enum`: an enum can carry a map variant just as a struct can
    # carry map fields, and matching only `struct` would leave every
    # workspace enum a leaf by default.
    grep -rqE "^(pub([[:space:]]|\([^)]*\)[[:space:]]))?(struct|enum) $bare([[:space:]<{(]|$)" crates/ 2>/dev/null || continue
  fi
  covered=""
  for entry in "${SURFACE[@]}"; do
    IFS='|' read -r _ _ p _ <<< "$entry"
    [ "$p" = "$fpath" ] && covered=1
  done
  while read -r m; do
    [ -n "$m" ] || continue
    case "$fpath" in "$m"|"$m".*) covered=1; break;; esac
  done < <(awk -F'\t' '$1=="omit"{print $2}' "$MANIFEST")
  if [ -z "$covered" ]; then
    if [ "$bare" = "__DYNAMIC_MAP__" ]; then
      echo "FAIL: '$fpath' is a dynamic-key MAP — a subtree whose keys nobody can enumerate."
    else
      echo "FAIL: '$fpath' has struct type '$bare' — it is a SUBTREE, not a leaf."
    fi
    echo "  Its own fields become config paths and none of them is decided."
    echo "  Give it a SURFACE entry with prefix '$fpath', or an 'omit' manifest"
    echo "  row covering it. Counting a subtree as one field is how a scalar"
    echo "  turning into a struct passes with no count change at all."
    exit 1
  fi
done < "$tmp/fields"
cut -f1 "$tmp/fields" | sort -u > "$tmp/fieldpaths"

# 3. The manifest. Every row needs three tab fields with a non-empty rationale:
#    a bare path is not a decision, and the gate's own advice says "decide it".
if awk -F'\t' '!/^#/ && NF && (NF < 3 || $3 ~ /^[[:space:]]*$/) { print; bad=1 } END { exit bad?1:0 }' \
     "$MANIFEST" > "$tmp/badrows"; then :; else
  echo "FAIL: manifest row(s) with no rationale — a bare path is not a decision:"
  sed 's/^/  /' "$tmp/badrows"; exit 1
fi
grep -v '^#' "$MANIFEST" | grep -v '^[[:space:]]*$' > "$tmp/man_raw"

# The disposition column is a CLOSED SET, and each value is bound to the surface
# it can mean something on. Before this, `masc` was accepted as "a recorded
# decision" and `mask` was accepted on `status.*` -- where masking does not
# exist, because `StatusView` is serialized WHOLE and never passes through
# `document.rs::classify`. A `mask status.vault_addr` row would have shipped the
# value in the clear while the audit record said it was withheld: the exact
# failure the StatusView entry was added to close, through a disposition a
# maintainer would plausibly pick.
#
# Round-2 note: the old `$1!="mask"` predicate caught a bad token by ACCIDENT
# (it fell into the code-backed set and failed the 4a diff). Narrowing that
# predicate removed the accident without replacing it. This is the replacement.
# The by-construction prefixes, DERIVED from the SURFACE table's `wire` rows.
# They were hand-inventoried in three places (bare_surface, byconstruction, and
# the wrappers switch) with no cross-check -- so a FOURTH wire struct would be
# rejected for `always` and silently accepted for `mask`, shipping a field whose
# manifest says "withheld" while serde serializes it in the clear. That is the
# failure the closed set exists to close, in the shape this gate keeps producing.
wire_prefixes=""
for entry in "${SURFACE[@]}"; do
  IFS='|' read -r _ _ p _ k <<< "$entry"
  # `if`, not `[ ... ] && ...` -- defensively: the FATAL form is a loop ending
  # in a failed AND-list *inside a pipeline or command substitution*, where
  # pipefail turns the loop status into the assignment's status and set -e
  # kills the gate with no FAIL line (the wire inventory above -- caught by the
  # reorder probe, the one fixture with a config row last). At plain statement
  # position, as here and at the `covered=1` match in the subtree loop below,
  # bash does NOT exit on it -- verified, not assumed. The `if` form is kept at
  # this site anyway so the file has one shape instead of a rule with footnotes.
  if [ "$k" = "wire" ]; then wire_prefixes="$wire_prefixes $p"; fi
done

bad_disp=$(awk -F'\t' -v wires="$wire_prefixes" '
  # The BARE prefix counts as the surface, not just `<surface>.`. Requiring the
  # dot left `mask<TAB>status` accepted -- and PREFIX rows are the idiom this
  # manifest already uses (`omit audit.au3_1 (prefix)`, `omit lake (prefix)`),
  # so it is the spelling a maintainer reaches for. It re-opened the exact hole
  # the closed set was written to close: every StatusView field then matched by
  # prefix at check 4b, and `mask` rows never enter the 4a diff.
  function bare_surface(p,  i,n,a) { n=split(wires,a," "); for(i=1;i<=n;i++) if(p==a[i]) return 1; return 0 }
  function byconstruction(p,  i,n,a) {
    if (bare_surface(p)) return 1
    n=split(wires,a," "); for(i=1;i<=n;i++) if (index(p, a[i] ".")==1) return 1
    return 0
  }
  $1!="disclose" && $1!="mask" && $1!="omit" && $1!="always" { print "unknown disposition: " $0; next }
  # `always` means "ships by construction on a non-allowlist surface".
  $1=="always" && !byconstruction($2) { print "always is only for by-construction surfaces: " $0 }
  # A BARE surface token is not a per-field decision. Round 4 made bare
  # prefixes count as the surface so `mask<TAB>status` would be rejected -- and
  # that same change LEGALIZED `always<TAB>status`, which then covers every
  # field under it by prefix at check 4b. One row, whole struct, and a new
  # sensitive field ships with nothing but a count edit -- which is exactly the
  # "edit the number to go green" move the count exists to prevent. Same defeat
  # round 4 demonstrated, surviving in the disposition round 4 added.
  $1=="always" && bare_surface($2) { print "a bare surface token is not a per-field decision; name the field: " $0 }
  # masking is meaningful only where a classifier renders the value.
  $1=="mask" && byconstruction($2) { print "mask is meaningless on a by-construction surface: " $0 }
  $1!="always" && byconstruction($2) { print "by-construction fields ship whole; the only valid disposition is `always`: " $0 }
' "$tmp/man_raw")
if [ -n "$bad_disp" ]; then
  echo "FAIL: manifest disposition(s) not valid for their surface:"
  printf '%s\n' "$bad_disp" | sed 's/^/  /'
  exit 1
fi
cut -f2 "$tmp/man_raw" | sort > "$tmp/man_paths_dup"
sort -u "$tmp/man_paths_dup" > "$tmp/man_paths"
if ! dupes=$(comm -23 "$tmp/man_paths_dup" "$tmp/man_paths") || [ -n "${dupes:-}" ]; then
  echo "FAIL: duplicate manifest path(s) — two decisions for one path:"
  printf '  %s\n' $dupes; exit 1
fi
# Only `disclose`/`omit` are CODE-BACKED -- they must appear in DISCLOSABLE /
# SUPPRESSED. `mask` is the default and appears in neither. `always` is a
# fourth disposition for a field that ships BY CONSTRUCTION on a different
# surface (`StatusView`, which `admin.status` returns whole) -- there is no
# allowlist entry to match, but the field still needs a recorded decision, and
# check 4b still forces one for every struct field.
awk -F'\t' '$1=="disclose" || $1=="omit"{print $1 "\t" $2}' "$tmp/man_raw" | sort -u > "$tmp/man_code"

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
done < "$tmp/fieldpaths"
if [ -n "$undecided" ]; then
  echo "FAIL: config field(s) with NO recorded disclosure decision:"
  printf '  %s\n' $undecided
  echo "  Add a row to $MANIFEST. 'mask' is a valid decision — but decide it:"
  echo "  deny-by-default masks a VALUE and does NOT hide a KEY whose presence"
  echo "  is itself the disclosure."
  exit 1
fi

if ! grep -qF -- "$(printf 'omit\t%s\t' "$CEILING_REQUIRES_SUPPRESSED")" "$MANIFEST"; then
  echo "FAIL: '$CEILING_REQUIRES_SUPPRESSED' is no longer omitted."
  echo "  The Ceiling SURFACE entry synthesises approximate paths (its"
  echo "  accreditation_ref field is a YAML sibling of \`ceiling\`, not a child),"
  echo "  which is only safe while that whole subtree is prefix-suppressed."
  echo "  Re-derive the Ceiling entry's paths before changing this."
  exit 1
fi

echo "config-disclosure-drift: $(wc -l < "$tmp/man_paths" | tr -d ' ') paths decided, $(wc -l < "$tmp/fieldpaths" | tr -d ' ') struct fields covered"
