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

# Each mutant stays valid shell and fails its own named case.
mutant() { # $1=label $2=prerm $3=postinst $4=spec $5=the case its failure must name
  local out
  for f in "$2" "$3"; do bash -n "$f" || { echo "FAIL: agent-instances: mutant $1 is not valid shell ($f)"; exit 1; }; done
  for sec in preun postun; do
    bash -n <(section "$4" "$sec") || { echo "FAIL: agent-instances: mutant $1's %$sec is not valid shell"; exit 1; }
  done
  out="$(table "$1" "$2" "$3" "$4" || true)"
  printf '%s\n' "$out" | grep -qF "FIXTURE-FAIL: $1: $5 ->" \
    || { echo "FAIL: agent-instances: mutant $1 did not fail '$5'"; printf '%s\n' "$out"; exit 1; }
  echo "mutant-ok: $1 fails '$5'"
}
prerm="$repo/packaging/deb/prerm"; postinst="$repo/packaging/deb/postinst"; spec="$repo/packaging/rpm/maknae.spec"

sed "s|^    systemctl stop 'maknae-agent@\*.service'.*|    :|" "$prerm" >"$scratch/prerm.nostop"
cmp -s "$prerm" "$scratch/prerm.nostop" && { echo "FAIL: agent-instances: prerm mutant changed nothing"; exit 1; }
mutant prerm-nostop "$scratch/prerm.nostop" "$postinst" "$spec" "deb remove"

awk '/^        stop_agent_instances$/ {next} {print} /^        systemctl stop maknaed.service/ {print "        stop_agent_instances"}' "$prerm" >"$scratch/prerm.late"
grep -qx '        stop_agent_instances' "$scratch/prerm.late" || { echo "FAIL: agent-instances: late-stop mutant lost the call"; exit 1; }
mutant prerm-late "$scratch/prerm.late" "$postinst" "$spec" "deb remove"

sed "s|^    systemctl try-restart 'maknae-agent@\*.service'.*|    :|" "$postinst" >"$scratch/postinst.norestart"
cmp -s "$postinst" "$scratch/postinst.norestart" && { echo "FAIL: agent-instances: postinst mutant changed nothing"; exit 1; }
mutant postinst-norestart "$prerm" "$scratch/postinst.norestart" "$spec" "deb restart_agent_instances"

sed "s|^    systemctl stop 'maknae-agent@\*.service'.*|    :|" "$spec" >"$scratch/spec.nostop"
cmp -s "$spec" "$scratch/spec.nostop" && { echo "FAIL: agent-instances: %preun mutant changed nothing"; exit 1; }
mutant spec-nostop "$prerm" "$postinst" "$scratch/spec.nostop" "rpm %preun 0"

sed "s|^    systemctl try-restart 'maknae-agent@\*.service'.*|    :|" "$spec" >"$scratch/spec.norestart"
cmp -s "$spec" "$scratch/spec.norestart" && { echo "FAIL: agent-instances: %postun mutant changed nothing"; exit 1; }
mutant spec-norestart "$prerm" "$postinst" "$scratch/spec.norestart" "rpm %postun 1"

awk '/^%preun$/ {print; getline; getline; getline; getline; print "%systemd_preun maknaed.service maknae-egress.service maknae-egress.socket maknae-policy-sync.path maknae-policy-sync.service"; print "if [ $1 -eq 0 ]; then"; print "    systemctl stop '"'"'maknae-agent@*.service'"'"' 2>/dev/null || :"; print "fi"; getline; next} {print}' "$spec" >"$scratch/spec.late"
mutant spec-late "$prerm" "$postinst" "$scratch/spec.late" "rpm %preun 0"

echo "PASS: agent-instances: $cases cases, and 6 mutants each fail their own case"
