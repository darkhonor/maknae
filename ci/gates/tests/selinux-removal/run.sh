#!/usr/bin/env bash
# The rendered RPM %postun and the port helper's is-ours guard (#584), over stub semanage and semodule.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../../../.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/maknae-selinux-removal.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT INT TERM

pass_n=0; fail_n=0
ok()  { printf 'fixture-ok: %s\n' "$1"; pass_n=$((pass_n+1)); }
bad() { printf 'FIXTURE-FAIL: %s\n' "$1"; fail_n=$((fail_n+1)); }

# The uninstall macro as selinux-policy 38.1 expands it, reduced to its semodule call.
uninstall_macro='if [ $1 -eq 0 ]; then semodule -n -X 200 -s targeted -r maknae \&> \/dev\/null || : ; fi'
postun() { # $1=spec: the %postun body, rendered
  awk '/^%postun$/ {on=1; next} on && /^%[a-z_]+$/ {exit} on {print}' "$1" \
    | sed -e 's/^%systemd_postun.*/:/' -e 's/%{selinuxtype}/targeted/g' \
          -e "s/^%selinux_modules_uninstall -s targeted maknae\$/$uninstall_macro/" \
          -e 's/%%/%/g'
}

mkdir "$scratch/bin"
cat >"$scratch/bin/semanage" <<'STUB'
#!/bin/bash
args="$*"
case "$args" in
  "port -l -C") cat "$LABELS" ;;
  "port -l") cat "$LABELS"; echo "http_port_t tcp 80, 443" ;;
  "port -d "*)
    [ "${PORT_D_RC:-0}" = 0 ] || exit "$PORT_D_RC"
    port="${@: -1}"; proto=""
    while [ $# -gt 0 ]; do [ "$1" = -p ] && proto="$2"; shift; done
    awk -v p="$port" -v pr="$proto" '
      { out=""; for (i = 3; i <= NF; i++) { t=$i; sub(",", "", t); if (!($2==pr && t==p)) out=out (out==""?"":", ") t }
        if (out!="") print $1, $2, out }' "$LABELS" >"$LABELS.new"
    mv "$LABELS.new" "$LABELS"; echo "port -d $proto $port" >>"$CALLS" ;;
  "port -a -t maknae_vault_port_t -p tcp "*)
    port="${@: -1}"
    awk -v p="$port" '$2=="tcp" { for (i = 3; i <= NF; i++) { t=$i; sub(",", "", t); if (t==p) f=1 } } END { exit !f }' "$LABELS" && exit 1
    echo "maknae_vault_port_t tcp $port" >>"$LABELS"; echo "port -a $port" >>"$CALLS" ;;
  *) echo "stub semanage: unexpected: $args" >&2; exit 9 ;;
esac
STUB
cat >"$scratch/bin/semodule" <<'STUB'
#!/bin/bash
case "$*" in
  "-l") [ -e "$LOADED" ] && echo maknae; echo other_module ;;
  "-n -X 200 -s targeted -r maknae")
    [ "${SEMODULE_RC:-0}" = 0 ] || exit "$SEMODULE_RC"
    if grep -q '^maknae_vault_port_t ' "$LABELS"; then
      echo "libsepol.context_from_record: type maknae_vault_port_t is not defined" >&2
      exit 1
    fi
    rm -f "$LOADED"; echo "semodule -r maknae" >>"$CALLS" ;;
  *) echo "stub semodule: unexpected: $*" >&2; exit 9 ;;
esac
STUB
printf '#!/bin/sh\nexit 0\n' >"$scratch/bin/selinuxenabled"
printf '#!/bin/sh\nexit 0\n' >"$scratch/bin/fapolicyd-cli"
cp "$repo/packaging/common/maknae-selinux-ports.sh" "$scratch/ports.sh"
chmod 0755 "$scratch/bin/"* "$scratch/ports.sh"

# $1=spec $2=initial labels $3=$1 for %postun $4=semodule exit $5=port -d exit
run_postun() {
  printf '%s' "$2" >"$scratch/labels"; : >"$scratch/calls"; : >"$scratch/loaded"
  local body; body="$(postun "$1")"
  LABELS="$scratch/labels" CALLS="$scratch/calls" LOADED="$scratch/loaded" SEMODULE_RC="$4" PORT_D_RC="$5" \
    PATH="$scratch/bin:$PATH" bash -c "set -- $3; $body" 2>"$scratch/err"
}

# $1=initial labels, then the helper's arguments
run_helper() {
  printf '%s' "$1" >"$scratch/labels"; : >"$scratch/calls"; shift
  LABELS="$scratch/labels" CALLS="$scratch/calls" PATH="$scratch/bin:$PATH" "$scratch/ports.sh" "$@" 2>"$scratch/err"
}

calls() { tr '\n' ';' <"$scratch/calls"; }
show() { printf '%s' "${1//$'\n'/ | }"; }

table() { # $1=label $2=spec
  local l="$1" spec="$2" rc
  local foreign=$'http_cache_port_t tcp 8443\n'
  for labels in $'maknae_vault_port_t tcp 8200\n' \
                $'maknae_vault_port_t tcp 8200, 9200\n' \
                $'maknae_vault_port_t tcp 8200-8210, 9200\n' \
                $'maknae_vault_port_t udp 8200\nhttp_port_t tcp 8200\n' \
                '' "$foreign"; do
    rc=0; run_postun "$spec" "$labels$foreign" 0 0 0 || rc=$?
    [ "$rc" -eq 0 ] && grep -qx 'semodule -r maknae' "$scratch/calls" && [ ! -e "$scratch/loaded" ] \
      && ! grep -q '^maknae_vault_port_t ' "$scratch/labels" && [ ! -s "$scratch/err" ] \
      && grep -qx 'http_cache_port_t tcp 8443' "$scratch/labels" \
      && { [[ "$labels" != *"http_port_t tcp 8200"* ]] || grep -qx 'http_port_t tcp 8200' "$scratch/labels"; } \
      && ok "$l: erase over '$(show "$labels")' removes our labels and the module, and keeps foreign ones" \
      || bad "$l: erase over '$(show "$labels")' -> rc=$rc calls='$(calls)' left='$(show "$(cat "$scratch/labels")")' err='$(head -c 200 "$scratch/err")'"
  done
  rc=0; run_postun "$spec" $'maknae_vault_port_t tcp 8200\n' 1 0 0 || rc=$?
  [ "$rc" -eq 0 ] && [ ! -s "$scratch/calls" ] && [ -e "$scratch/loaded" ] \
    && grep -qx 'maknae_vault_port_t tcp 8200' "$scratch/labels" \
    && ok "$l: upgrade touches neither the labels nor the module" \
    || bad "$l: upgrade -> rc=$rc calls='$(calls)'"
  rc=0; run_postun "$spec" '' 0 1 0 || rc=$?
  [ "$rc" -eq 0 ] && [ -e "$scratch/loaded" ] && grep -q 'module was not removed' "$scratch/err" \
    && ok "$l: a module removal that fails is reported and does not fail the erase" \
    || bad "$l: failing semodule -> rc=$rc err='$(head -c 200 "$scratch/err")'"
  rc=0; run_postun "$spec" $'maknae_vault_port_t tcp 8200\n' 0 0 1 || rc=$?
  [ "$rc" -eq 0 ] && [ -e "$scratch/loaded" ] && grep -q 'cannot delete the port label tcp/8200' "$scratch/err" \
    && grep -q 'module was not removed' "$scratch/err" \
    && ok "$l: a label removal that fails is reported, and so is the module it keeps loaded" \
    || bad "$l: failing port -d -> rc=$rc calls='$(calls)' err='$(head -c 200 "$scratch/err")'"
}

helper_table() {
  local rc
  for labels in $'maknae_vault_port_t tcp 8200-8210\n' $'maknae_vault_port_t udp 8200\nhttp_port_t tcp 8200\n' \
                $'maknae_vault_port_t tcp 18200\n' $'maknae_vault_port_t tcp 820\n'; do
    rc=0; run_helper "$labels" remove 8200 || rc=$?
    [ "$rc" -eq 0 ] && [ ! -s "$scratch/calls" ] \
      && ok "helper: remove 8200 leaves '$(show "$labels")' alone" \
      || bad "helper: remove 8200 over '$(show "$labels")' -> rc=$rc calls='$(calls)'"
  done
  rc=0; run_helper $'maknae_vault_port_t tcp 9200, 8200\n' remove 8200 || rc=$?
  [ "$rc" -eq 0 ] && [ "$(calls)" = 'port -d tcp 8200;' ] && grep -qx 'maknae_vault_port_t tcp 9200' "$scratch/labels" \
    && ok "helper: remove 8200 deletes exactly its tcp record" \
    || bad "helper: remove 8200 -> rc=$rc calls='$(calls)'"
  rc=0; run_helper $'maknae_vault_port_t tcp 8200\n' add 8200 || rc=$?
  [ "$rc" -eq 0 ] && [ ! -s "$scratch/calls" ] && ok "helper: add over our own label is a no-op" \
    || bad "helper: add over our own label -> rc=$rc calls='$(calls)'"
  rc=0; run_helper $'maknae_vault_port_t udp 8200\nhttp_port_t tcp 8200\n' add 8200 || rc=$?
  [ "$rc" -eq 3 ] && [ ! -s "$scratch/calls" ] && ok "helper: add over a foreign tcp label is refused" \
    || bad "helper: add over a foreign tcp label -> rc=$rc calls='$(calls)'"
}

spec="$repo/packaging/rpm/maknae.spec"
grep -qx '%selinux_modules_uninstall -s %{selinuxtype} maknae' "$spec" \
  || { echo "FAIL: selinux-removal: %postun no longer uses %selinux_modules_uninstall as this fixture renders it"; exit 1; }
table rpm "$spec"
helper_table
[ "$fail_n" -eq 0 ] || { echo "FAIL: selinux-removal: $fail_n case(s) failed"; exit 1; }
cases=$pass_n

grep -q 'semanage port -d -p' "$spec" \
  || { echo "FAIL: selinux-removal: the spec's %postun no longer deletes the port labels"; exit 1; }
sed 's/semanage port -d -p .*/:/' "$spec" >"$scratch/broken.spec"
before=$fail_n; table broken "$scratch/broken.spec" >/dev/null
[ "$fail_n" -gt "$before" ] \
  || { echo "FAIL: selinux-removal: the table passes a spec that never removes the port labels"; exit 1; }

echo "PASS: selinux-removal: $cases cases, and the table fails a spec that skips the labels"
