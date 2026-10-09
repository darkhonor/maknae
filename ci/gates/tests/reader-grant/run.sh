#!/usr/bin/env bash
# Drives grant_reader_traverse from the deb postinst, the rendered RPM %post and
# the macOS postinstall (#500) with a stub `maknae audit-readers` and a recording
# setfacl/chmod, over one case table; then proves the table fails a copy whose
# name check is removed.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../../../.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/maknae-reader-grant.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT INT TERM

pass_n=0; fail_n=0
ok()  { printf 'fixture-ok: %s\n' "$1"; pass_n=$((pass_n+1)); }
bad() { printf 'FIXTURE-FAIL: %s\n' "$1"; fail_n=$((fail_n+1)); }

extract() { # $1=file: the function's lines, from its header to the closing brace
  awk '/^grant_reader_traverse\(\) \{$/ {on=1} on {print} on && /^}$/ {exit}' "$1"
}

render_rpm() {
  sed -e 's/%%/%/g' -e 's#%{_bindir}#/usr/bin#g' -e 's#%{_localstatedir}#/var#g'
}

printf '#!/bin/sh\nprintf "%%s" "$MK_OUT"\necho helper-said-no >&2\nexit "$MK_RC"\n' >"$scratch/maknae"
chmod 0755 "$scratch/maknae"

# $1=label $2=shell $3=function text $4=helper path in it $5=grant tool
# $6=helper stdout $7=helper exit $8=grant exit $9=timeout exit (0 = none)
run_case() {
  local fn="${3//"$4"/$scratch/maknae}"
  rm -f "$scratch/granted" "$scratch/err"
  MK_OUT="$6" MK_RC="$7" MK_GRANT="$8" MK_TIMEOUT="$9" GRANTED="$scratch/granted" \
    "$2" -c "
      $5() { echo \"\$*\" >>\"\$GRANTED\"; return \"\$MK_GRANT\"; }
      timeout() { [ \"\$MK_TIMEOUT\" = 0 ] || return \"\$MK_TIMEOUT\"; shift; \"\$@\"; }
      $fn
      export MK_OUT MK_RC
      grant_reader_traverse
    " 2>"$scratch/err"
}

# $1=label $2=shell $3=function $4=helper path $5=grant tool $6=has timeout
table() {
  local l="$1" sh="$2" fn="$3" hp="$4" tool="$5" bounded="$6" rc out
  local -a refused=($'alice\n\nbob' $'alice\r' 'alice bob' $'alice\tbob' '*' '-r' 'aé' 'Alice' 'x$y'
                    'abcdefghijklmnopqrstuvwxyzabcdefg' $'alice\n-r')
  for valid in $'alice\nbob\n' $'alice\nbob' 'alice$' '_vector'; do
    rc=0; run_case "$l" "$sh" "$fn" "$hp" "$tool" "$valid" 0 0 0 || rc=$?
    out="$(sed -E 's/.* (u|user):([^: ]+).*/\2/' "$scratch/granted" 2>/dev/null | tr '\n' ' ' || true)"
    want="$(printf '%s\n' "$valid" | sed '/^$/d' | tr '\n' ' ')"
    [ "$rc" -eq 0 ] && [ "$out" = "$want" ] \
      && ok "$l: ${valid//$'\n'/\\n} grants exactly the listed names" \
      || bad "$l: ${valid//$'\n'/\\n} -> rc=$rc granted='$out' want='$want'"
  done
  for name in "${refused[@]}"; do
    rc=0; run_case "$l" "$sh" "$fn" "$hp" "$tool" "$name" 0 0 0 || rc=$?
    [ "$rc" -eq 0 ] && [ ! -e "$scratch/granted" ] && grep -q 'unexpected name' "$scratch/err" \
      && ok "$l: $(printf '%q' "$name") grants no one" \
      || bad "$l: $(printf '%q' "$name") -> rc=$rc granted='$(cat "$scratch/granted" 2>/dev/null)'"
  done
  for empty in '' $'\n\n'; do
    rc=0; run_case "$l" "$sh" "$fn" "$hp" "$tool" "$empty" 0 0 0 || rc=$?
    [ "$rc" -eq 0 ] && [ ! -e "$scratch/granted" ] \
      && ok "$l: $(printf '%q' "$empty") grants no one" || bad "$l: $(printf '%q' "$empty") -> rc=$rc"
  done
  rc=0; run_case "$l" "$sh" "$fn" "$hp" "$tool" 'alice' 3 0 0 || rc=$?
  [ "$rc" -eq 0 ] && [ ! -e "$scratch/granted" ] && grep -q 'not applied: helper-said-no' "$scratch/err" \
    && ok "$l: a helper exiting 3 grants no one and reports it" || bad "$l: helper exit 3 -> rc=$rc"
  rc=0; run_case "$l" "$sh" "$fn" "$hp" "$tool" 'alice' 0 1 0 || rc=$?
  [ "$rc" -ne 0 ] && ok "$l: a failed $tool fails the grant" || bad "$l: a failed $tool returned 0"
  if [ "$bounded" = yes ]; then
    rc=0; run_case "$l" "$sh" "$fn" "$hp" "$tool" 'alice' 0 0 124 || rc=$?
    [ "$rc" -eq 0 ] && [ ! -e "$scratch/granted" ] && grep -q 'not applied: .*within 60s' "$scratch/err" \
      && ok "$l: a helper that times out grants no one and says so" || bad "$l: timeout -> rc=$rc"
  fi
}

deb="$(extract "$repo/packaging/deb/postinst")"
rpm="$(extract "$repo/packaging/rpm/maknae.spec" | render_rpm)"
mac="$(extract "$repo/packaging/macos/scripts/postinstall")"
for f in deb rpm mac; do
  [ -n "${!f}" ] || { echo "ABORT: no grant_reader_traverse found for $f" >&2; exit 1; }
done
grep -q 'timeout 60 /usr/bin/maknae audit-readers' <<<"$deb" || bad "deb: the helper is not bounded"
grep -q 'timeout 60 /usr/bin/maknae audit-readers' <<<"$rpm" || bad "rpm: the helper is not bounded"

table deb bash "$deb" /usr/bin/maknae setfacl yes
table rpm sh "$rpm" /usr/bin/maknae setfacl yes
table macos bash "$mac" /usr/local/bin/maknae chmod no

# The table must fail a function whose name check is gone.
unchecked="$(sed 's/\[ "\$rc" -ne 1 \]/false/' <<<"$deb")"
[ "$unchecked" != "$deb" ] || { echo "ABORT: the name check was not found to remove" >&2; exit 1; }
before=$fail_n; passed=$pass_n
table deb-unchecked bash "$unchecked" /usr/bin/maknae setfacl yes >/dev/null
if [ "$fail_n" -gt "$before" ]; then
  fail_n=$before; pass_n=$passed; ok "the table fails a grant whose name check is removed"
else
  bad "the table passed a grant whose name check is removed"
fi

echo "reader-grant: $pass_n ok, $fail_n failed"
[ "$fail_n" -eq 0 ]
