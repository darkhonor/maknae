#!/usr/bin/env bash
# The packages stop every maknae-agent@ instance on erase and restart them on upgrade (#629):
# the deb prerm and postinst, and the rendered RPM %preun and %postun, over stub systemctl.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../../../.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/maknae-agent-instances.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT INT TERM

pass_n=0; fail_n=0
ok()  { printf 'fixture-ok: %s\n' "$1"; pass_n=$((pass_n+1)); }
bad() { printf 'FIXTURE-FAIL: %s\n' "$1"; fail_n=$((fail_n+1)); }

mkdir "$scratch/bin"
for tool in systemctl apparmor_parser semanage semodule fapolicyd-cli; do
  printf '#!/bin/sh\necho "%s $*" >>"$CALLS"\n' "$tool" >"$scratch/bin/$tool"
done
printf '#!/bin/sh\nexit 1\n' >"$scratch/bin/selinuxenabled"
chmod 0755 "$scratch/bin/"*

section() { # $1=spec $2=section name: its body, rendered
  awk -v s="%$2" '$0 == s {on=1; next} on && /^%[a-z_]+$/ {exit} on {print}' "$1" \
    | sed -e 's/^%systemd_preun /systemctl preun-macro /' -e 's/^%systemd_postun_with_restart .*/:/' \
          -e 's/^%systemd_postun .*/:/' -e 's/^%selinux_modules_uninstall .*/:/' \
          -e 's/%{selinuxtype}/targeted/g' -e 's/%%/%/g'
}
extract() { # $1=file $2=function name
  awk -v f="$2() {" '$0 == f {on=1} on {print} on && /^}$/ {exit}' "$1"
}

# $1=script text $2..=its arguments
run() {
  local body="$1"; shift
  : >"$scratch/calls"
  CALLS="$scratch/calls" PATH="$scratch/bin:$PATH" bash -c "$body" _ "$@" >/dev/null 2>"$scratch/err"
}
calls() { tr '\n' ';' <"$scratch/calls"; }
line_of() { grep -nxF "$1" "$scratch/calls" | head -1 | cut -d: -f1 || true; }

table() { # $1=label $2=prerm $3=postinst $4=spec
  local l="$1" prerm="$2" postinst="$3" spec="$4" rc a m
  rc=0; run "$(cat "$prerm")" remove || rc=$?
  a="$(line_of "systemctl stop maknae-agent@*.service")"; m="$(line_of "systemctl stop maknaed.service")"
  [ "$rc" -eq 0 ] && [ -n "$a" ] && [ -n "$m" ] && [ "$a" -lt "$m" ] \
    && grep -qxF "apparmor_parser -R /etc/apparmor.d/usr.bin.maknae-agentd" "$scratch/calls" \
    && ok "$l: deb remove stops every agent instance before maknaed and unloads the agent profile" \
    || bad "$l: deb remove -> rc=$rc calls='$(calls)'"
  rc=0; run "$(cat "$prerm")" upgrade 1.0 || rc=$?
  [ "$rc" -eq 0 ] && [ ! -s "$scratch/calls" ] && ok "$l: deb upgrade stops nothing" \
    || bad "$l: deb upgrade -> rc=$rc calls='$(calls)'"
  rc=0; run "$(extract "$postinst" restart_agent_instances); restart_agent_instances" || rc=$?
  [ "$rc" -eq 0 ] && [ "$(calls)" = "systemctl try-restart maknae-agent@*.service;" ] \
    && ok "$l: deb restart_agent_instances try-restarts every instance" \
    || bad "$l: deb restart_agent_instances -> rc=$rc calls='$(calls)'"
  rc=0; run "$(section "$spec" preun)" 0 || rc=$?
  a="$(line_of "systemctl stop maknae-agent@*.service")"; m="$(grep -n '^systemctl preun-macro maknaed.service' "$scratch/calls" | cut -d: -f1 || true)"
  [ "$rc" -eq 0 ] && [ -n "$a" ] && [ -n "$m" ] && [ "$a" -lt "$m" ] \
    && ok "$l: rpm erase stops every agent instance before maknaed" || bad "$l: rpm %preun 0 -> rc=$rc calls='$(calls)'"
  rc=0; run "$(section "$spec" preun)" 1 || rc=$?
  [ "$rc" -eq 0 ] && ! grep -q 'maknae-agent@' "$scratch/calls" \
    && ok "$l: rpm upgrade %preun stops no agent instance" || bad "$l: rpm %preun 1 -> rc=$rc calls='$(calls)'"
  rc=0; run "$(section "$spec" postun)" 1 || rc=$?
  [ "$rc" -eq 0 ] && grep -qxF "systemctl try-restart maknae-agent@*.service" "$scratch/calls" \
    && ok "$l: rpm upgrade %postun try-restarts every agent instance" || bad "$l: rpm %postun 1 -> rc=$rc calls='$(calls)'"
  rc=0; run "$(section "$spec" postun)" 0 || rc=$?
  [ "$rc" -eq 0 ] && ! grep -q 'maknae-agent@' "$scratch/calls" \
    && ok "$l: rpm erase %postun restarts no agent instance" || bad "$l: rpm %postun 0 -> rc=$rc calls='$(calls)'"
}

grep -q 'restart_agent_instances$' "$repo/packaging/deb/postinst" \
  || { echo "FAIL: agent-instances: postinst never calls restart_agent_instances"; exit 1; }
awk '/if \[ -n "\$\{2:-\}" \]; then/ {on=1} on && /restart_agent_instances$/ {f=1} on && /^        fi$/ {exit} END {exit !f}' \
  "$repo/packaging/deb/postinst" \
  || { echo "FAIL: agent-instances: postinst calls restart_agent_instances outside its upgrade branch"; exit 1; }

table shipped "$repo/packaging/deb/prerm" "$repo/packaging/deb/postinst" "$repo/packaging/rpm/maknae.spec"
[ "$fail_n" -eq 0 ] || { echo "FAIL: agent-instances: $fail_n case(s) failed"; exit 1; }
cases=$pass_n

sed "/maknae-agent@/d" "$repo/packaging/deb/prerm" >"$scratch/prerm"
sed "/maknae-agent@/d" "$repo/packaging/rpm/maknae.spec" >"$scratch/spec"
before=$fail_n; table broken "$scratch/prerm" "$repo/packaging/deb/postinst" "$scratch/spec" >/dev/null
[ $((fail_n - before)) -ge 3 ] \
  || { echo "FAIL: agent-instances: the table passes packages that never stop or restart an agent"; exit 1; }

echo "PASS: agent-instances: $cases cases, and the table fails packages that skip the agent instances"
