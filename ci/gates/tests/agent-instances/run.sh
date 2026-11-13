#!/usr/bin/env bash
# The packages stop every maknae-agent@ instance on erase and restart them on upgrade, and
# disable each instance and remove its drop-in on purge and erase (#629): the deb prerm,
# postinst and postrm, and the rendered RPM %preun and %postun, over stub systemctl.
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

units="$scratch/root/etc/systemd/system"
# Every /etc and /var path, so a script that takes the purge branch acts only on the scratch tree.
rooted() { sed -E "s#/(etc|var)/#$scratch/root/\1/#g"; }
plant() { # each enrolled instance's drop-in and link, and units that are not agents'
  rm -rf "$scratch/root"; mkdir -p "$units/multi-user.target.wants" "$units/maknaed.service.d"
  mkdir "$units/maknae-agent@hobi.service.d" "$units/maknae-agent@jin.service.d"
  : >"$units/maknae-agent@hobi.service.d/account.conf"; : >"$units/maknaed.service.d/local.conf"
  for u in maknae-agent@hobi maknae-agent@jin maknae-agent@suga maknaed; do
    ln -s "/usr/lib/systemd/system/$u.service" "$units/multi-user.target.wants/$u.service"
  done
}
planted() { (cd "$units" && find . -mindepth 1 | LC_ALL=C sort | tr '\n' ' '); }
cleared='./maknaed.service.d ./maknaed.service.d/local.conf ./multi-user.target.wants ./multi-user.target.wants/maknaed.service '
disabled='systemctl disable maknae-agent@hobi.service;systemctl disable maknae-agent@jin.service;systemctl disable maknae-agent@suga.service;systemctl daemon-reload;'

line_of() { grep -nxF "$1" "$scratch/calls" | head -1 | cut -d: -f1 || true; }

table() { # $1=label $2=prerm $3=postinst $4=spec $5=postrm
  local l="$1" prerm="$2" postinst="$3" spec="$4" postrm="$5" rc a m before
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

  plant; rc=0; run "$(extract "$postrm" disable_agent_instances | rooted); disable_agent_instances" || rc=$?
  [ "$rc" -eq 0 ] && [ "$(calls)" = "${disabled%systemctl daemon-reload;}" ] && [ "$(planted)" = "$cleared" ] \
    && ok "$l: deb disable_agent_instances disables every instance and removes its drop-in and link" \
    || bad "$l: deb disable_agent_instances -> rc=$rc calls='$(calls)' left='$(planted)'"
  awk '/^    purge\)$/ {on=1} on && /^        disable_agent_instances$/ {f=1} on && /^        ;;$/ {exit} END {exit !f}' "$postrm" \
    && [ "$(grep -c '^ *disable_agent_instances$' "$postrm")" -eq 1 ] \
    && ok "$l: deb purge, and only purge, calls disable_agent_instances" \
    || bad "$l: deb postrm purge wiring -> $(grep -n 'disable_agent_instances' "$postrm" | tr '\n' ';')"
  for arg in remove upgrade; do
    plant; before="$(planted)"; rc=0; run "$(rooted <"$postrm")" "$arg" || rc=$?
    [ "$rc" -eq 0 ] && ! grep -q 'maknae-agent@' "$scratch/calls" && [ "$(planted)" = "$before" ] \
      && ok "$l: deb postrm $arg leaves every instance enabled with its drop-in" \
      || bad "$l: deb postrm $arg -> rc=$rc calls='$(calls)' left='$(planted)'"
  done
  plant; rc=0; run "$(section "$spec" preun | rooted)" 0 || rc=$?
  a="$(line_of "systemctl stop maknae-agent@*.service")"; m="$(line_of "systemctl disable maknae-agent@hobi.service")"
  [ "$rc" -eq 0 ] && [ -n "$a" ] && [ -n "$m" ] && [ "$a" -lt "$m" ] && [ "$(planted)" = "$cleared" ] \
    && grep -qxF "systemctl daemon-reload" "$scratch/calls" \
    && [ "$(grep -c '^systemctl disable maknae-agent@' "$scratch/calls")" -eq 3 ] \
    && ok "$l: rpm erase disables every stopped instance and removes its drop-in and link" \
    || bad "$l: rpm %preun 0 disable -> rc=$rc calls='$(calls)' left='$(planted)'"
  plant; before="$(planted)"; rc=0; run "$(section "$spec" preun | rooted)" 1 || rc=$?
  [ "$rc" -eq 0 ] && [ "$(planted)" = "$before" ] && ! grep -q '^systemctl disable maknae-agent@' "$scratch/calls" \
    && ok "$l: rpm upgrade %preun leaves every instance enabled with its drop-in" \
    || bad "$l: rpm %preun 1 disable -> rc=$rc calls='$(calls)' left='$(planted)'"
}

grep -q 'restart_agent_instances$' "$repo/packaging/deb/postinst" \
  || { echo "FAIL: agent-instances: postinst never calls restart_agent_instances"; exit 1; }
awk '/if \[ -n "\$\{2:-\}" \]; then/ {on=1} on && /restart_agent_instances$/ {f=1} on && /^        fi$/ {exit} END {exit !f}' \
  "$repo/packaging/deb/postinst" \
  || { echo "FAIL: agent-instances: postinst calls restart_agent_instances outside its upgrade branch"; exit 1; }

table shipped "$repo/packaging/deb/prerm" "$repo/packaging/deb/postinst" "$repo/packaging/rpm/maknae.spec" "$repo/packaging/deb/postrm"
[ "$fail_n" -eq 0 ] || { echo "FAIL: agent-instances: $fail_n case(s) failed"; exit 1; }
cases=$pass_n

# Each mutant stays valid shell and fails its own named case.
mutant() { # $1=label $2=prerm $3=postinst $4=spec $5=postrm $6=the case its failure must name
  local out
  for f in "$2" "$3" "$5"; do bash -n "$f" || { echo "FAIL: agent-instances: mutant $1 is not valid shell ($f)"; exit 1; }; done
  for sec in preun postun; do
    bash -n <(section "$4" "$sec") || { echo "FAIL: agent-instances: mutant $1's %$sec is not valid shell"; exit 1; }
  done
  out="$(table "$1" "$2" "$3" "$4" "$5" || true)"
  printf '%s\n' "$out" | grep -qF "FIXTURE-FAIL: $1: $6 ->" \
    || { echo "FAIL: agent-instances: mutant $1 did not fail '$6'"; printf '%s\n' "$out"; exit 1; }
  echo "mutant-ok: $1 fails '$6'"
  mutants=$((mutants+1))
}
mutants=0
prerm="$repo/packaging/deb/prerm"; postinst="$repo/packaging/deb/postinst"; spec="$repo/packaging/rpm/maknae.spec"
postrm="$repo/packaging/deb/postrm"
stub() { # $1=source $2=out $3=the exact line to replace with `:`
  awk -v l="$3" '$0 == l {sub(/[^ ].*/, ":"); n++} {print} END {exit n != 1}' "$1" >"$2" \
    || { echo "FAIL: agent-instances: no single line '$3' to stub in $1"; exit 1; }
}

sed "s|^    systemctl stop 'maknae-agent@\*.service'.*|    :|" "$prerm" >"$scratch/prerm.nostop"
cmp -s "$prerm" "$scratch/prerm.nostop" && { echo "FAIL: agent-instances: prerm mutant changed nothing"; exit 1; }
mutant prerm-nostop "$scratch/prerm.nostop" "$postinst" "$spec" "$postrm" "deb remove"

awk '/^        stop_agent_instances$/ {next} {print} /^        systemctl stop maknaed.service/ {print "        stop_agent_instances"}' "$prerm" >"$scratch/prerm.late"
grep -qx '        stop_agent_instances' "$scratch/prerm.late" || { echo "FAIL: agent-instances: late-stop mutant lost the call"; exit 1; }
mutant prerm-late "$scratch/prerm.late" "$postinst" "$spec" "$postrm" "deb remove"

sed "s|^    systemctl try-restart 'maknae-agent@\*.service'.*|    :|" "$postinst" >"$scratch/postinst.norestart"
cmp -s "$postinst" "$scratch/postinst.norestart" && { echo "FAIL: agent-instances: postinst mutant changed nothing"; exit 1; }
mutant postinst-norestart "$prerm" "$scratch/postinst.norestart" "$spec" "$postrm" "deb restart_agent_instances"

sed "s|^    systemctl stop 'maknae-agent@\*.service'.*|    :|" "$spec" >"$scratch/spec.nostop"
cmp -s "$spec" "$scratch/spec.nostop" && { echo "FAIL: agent-instances: %preun mutant changed nothing"; exit 1; }
mutant spec-nostop "$prerm" "$postinst" "$scratch/spec.nostop" "$postrm" "rpm %preun 0"

sed "s|^    systemctl try-restart 'maknae-agent@\*.service'.*|    :|" "$spec" >"$scratch/spec.norestart"
cmp -s "$spec" "$scratch/spec.norestart" && { echo "FAIL: agent-instances: %postun mutant changed nothing"; exit 1; }
mutant spec-norestart "$prerm" "$postinst" "$scratch/spec.norestart" "$postrm" "rpm %postun 1"

awk '/^%preun$/ {on=1} on && /^    systemctl stop '"'"'maknae-agent@\*\.service'"'"'/ {print "    :"; next} {print} on && /^%systemd_preun / {print "if [ $1 -eq 0 ]; then"; print "    systemctl stop '"'"'maknae-agent@*.service'"'"' 2>/dev/null || :"; print "fi"; on=0}' "$spec" >"$scratch/spec.late"
grep -c "maknae-agent@\*.service' 2>/dev/null" "$scratch/spec.late" | grep -qx 2 || { echo "FAIL: agent-instances: late-stop %preun mutant lost the call"; exit 1; }
mutant spec-late "$prerm" "$postinst" "$scratch/spec.late" "$postrm" "rpm %preun 0"

disable_line='        systemctl disable "$u" 2>/dev/null || :'
stub "$postrm" "$scratch/postrm.nodisable" "$disable_line"
mutant postrm-nodisable "$prerm" "$postinst" "$spec" "$scratch/postrm.nodisable" "deb disable_agent_instances"
stub "$postrm" "$scratch/postrm.keepdropin" '        rm -rf "/etc/systemd/system/$u.d"'
mutant postrm-keepdropin "$prerm" "$postinst" "$spec" "$scratch/postrm.keepdropin" "deb disable_agent_instances"
stub "$postrm" "$scratch/postrm.nopurgecall" '        disable_agent_instances'
mutant postrm-nopurgecall "$prerm" "$postinst" "$spec" "$scratch/postrm.nopurgecall" "deb postrm purge wiring"
awk '{print} /^    remove\)$/ {print "        disable_agent_instances"}' "$postrm" >"$scratch/postrm.onremove"
mutant postrm-onremove "$prerm" "$postinst" "$spec" "$scratch/postrm.onremove" "deb postrm remove"
stub "$spec" "$scratch/spec.nodisable" "$disable_line"
mutant spec-nodisable "$prerm" "$postinst" "$scratch/spec.nodisable" "$postrm" "rpm %preun 0 disable"
stub "$spec" "$scratch/spec.keeplink" '        rm -f "/etc/systemd/system/multi-user.target.wants/$u"'
mutant spec-keeplink "$prerm" "$postinst" "$scratch/spec.keeplink" "$postrm" "rpm %preun 0 disable"
awk '/^%preun$/ {on=1} on && /^    for d in / {print "fi"; print "if :; then"} {print} /^%postun$/ {on=0}' "$spec" >"$scratch/spec.onupgrade"
mutant spec-onupgrade "$prerm" "$postinst" "$scratch/spec.onupgrade" "$postrm" "rpm %preun 1 disable"

echo "PASS: agent-instances: $cases cases, and $mutants mutants each fail their own case"
