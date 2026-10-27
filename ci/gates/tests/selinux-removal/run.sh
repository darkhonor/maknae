#!/usr/bin/env bash
# Drives the rendered RPM %preun (#584) through the shipped port helper, with a
# stub semanage holding the local port labels and a stub semodule that refuses
# while a maknae_vault_port_t label remains, as the real one does.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../../../.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/maknae-selinux-removal.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT INT TERM

pass_n=0; fail_n=0
ok()  { printf 'fixture-ok: %s\n' "$1"; pass_n=$((pass_n+1)); }
bad() { printf 'FIXTURE-FAIL: %s\n' "$1"; fail_n=$((fail_n+1)); }

preun() { # $1=spec: the %preun body, rendered
  awk '/^%preun$/ {on=1; next} on && /^%[a-z_]+$/ {exit} on {print}' "$1" \
    | sed -e 's/^%systemd_preun .*/:/' -e 's/%%/%/g' \
          -e "s#%{_libexecdir}/maknae/maknae-selinux-ports.sh#$scratch/ports.sh#g"
}

cp "$repo/packaging/common/maknae-selinux-ports.sh" "$scratch/ports.sh"
mkdir "$scratch/bin"
cat >"$scratch/bin/semanage" <<'EOF'
#!/bin/bash
case "$1 $2" in
  "port -l")
    if [ "${3:-}" = -C ]; then cat "$LABELS"; else cat "$LABELS"; echo "http_port_t tcp 80, 443"; fi ;;
  "port -d")
    port="${@: -1}"
    awk -v p="$port" '{ n=split($0,f,/[ ,]+/); out=""; for (i=3;i<=n;i++) if (f[i]!=p && f[i]!="") out=out (out==""?"":", ") f[i]; if (out!="") print f[1], f[2], out }' "$LABELS" >"$LABELS.new"
    mv "$LABELS.new" "$LABELS"; echo "port -d $port" >>"$CALLS" ;;
  *) exit 9 ;;
esac
EOF
cat >"$scratch/bin/semodule" <<'EOF'
#!/bin/bash
[ "$1 $2" = "-r maknae" ] || exit 9
[ "$SEMODULE_RC" = 0 ] || exit "$SEMODULE_RC"
if grep -q '^maknae_vault_port_t ' "$LABELS"; then
  echo "libsepol.context_from_record: type maknae_vault_port_t is not defined" >&2
  exit 1
fi
echo "semodule -r maknae" >>"$CALLS"
EOF
chmod 0755 "$scratch/bin/"* "$scratch/ports.sh"

# $1=spec $2=initial labels $3=$1 for %preun $4=semodule's forced exit (0 = real behaviour)
run_case() {
  printf '%s' "$2" >"$scratch/labels"; : >"$scratch/calls"
  local body; body="$(preun "$1")"
  LABELS="$scratch/labels" CALLS="$scratch/calls" SEMODULE_RC="$4" PATH="$scratch/bin:$PATH" \
    bash -c "set -- $3; $body" 2>"$scratch/err"
}

table() { # $1=label $2=spec
  local l="$1" spec="$2" rc
  for labels in $'maknae_vault_port_t tcp 8200\n' $'maknae_vault_port_t tcp 8200, 9200\n' ''; do
    rc=0; run_case "$spec" "$labels" 0 0 || rc=$?
    [ "$rc" -eq 0 ] && grep -qx 'semodule -r maknae' "$scratch/calls" \
      && ! grep -q '^maknae_vault_port_t ' "$scratch/labels" && [ ! -s "$scratch/err" ] \
      && ok "$l: erase with labels '${labels//$'\n'/}' removes them and the module" \
      || bad "$l: erase with labels '${labels//$'\n'/}' -> rc=$rc calls='$(tr '\n' ';' <"$scratch/calls")' err='$(head -c 200 "$scratch/err")'"
  done
  rc=0; run_case "$spec" $'maknae_vault_port_t tcp 8200\n' 1 0 || rc=$?
  [ "$rc" -eq 0 ] && [ ! -s "$scratch/calls" ] && grep -q '^maknae_vault_port_t tcp 8200$' "$scratch/labels" \
    && ok "$l: upgrade touches neither the labels nor the module" \
    || bad "$l: upgrade -> rc=$rc calls='$(tr '\n' ';' <"$scratch/calls")'"
  rc=0; run_case "$spec" '' 0 1 || rc=$?
  [ "$rc" -eq 0 ] && grep -q 'semodule -r maknae' "$scratch/err" \
    && ok "$l: a module removal that fails is reported and does not fail the erase" \
    || bad "$l: failing semodule -> rc=$rc err='$(head -c 200 "$scratch/err")'"
}

table rpm "$repo/packaging/rpm/maknae.spec"
[ "$fail_n" -eq 0 ] || { echo "FAIL: selinux-removal: $fail_n case(s) failed"; exit 1; }
cases=$pass_n

grep -q 'maknae-selinux-ports.sh remove' "$repo/packaging/rpm/maknae.spec" \
  || { echo "FAIL: selinux-removal: the spec no longer removes the port labels through the helper"; exit 1; }
sed 's#%{_libexecdir}/maknae/maknae-selinux-ports.sh remove "\$p"#:#' \
  "$repo/packaging/rpm/maknae.spec" >"$scratch/broken.spec"
before=$fail_n; table broken "$scratch/broken.spec" >/dev/null
[ "$fail_n" -gt "$before" ] \
  || { echo "FAIL: selinux-removal: the table passes a spec that never removes the port labels"; exit 1; }

echo "PASS: selinux-removal: $cases cases, and the table fails a spec that skips the labels"
