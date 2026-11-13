#!/usr/bin/env bash
# The packages stop every maknae-agent@ instance on erase and restart them on upgrade, and
# disable each instance and remove its drop-in on purge and erase (#629): the deb prerm,
# postinst and postrm, and the rendered RPM %preun and %postun, over stub systemctl and
# apparmor_parser. A failed stop, profile load or restart is never reported as success.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../../../.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/maknae-agent-instances.XXXXXXXX")"
trap 'rm -rf -- "${scratch:?}"' EXIT INT TERM

pass_n=0; fail_n=0
ok()  { printf 'fixture-ok: %s\n' "$1"; pass_n=$((pass_n+1)); }
bad() { printf 'FIXTURE-FAIL: %s\n' "$1"; fail_n=$((fail_n+1)); }

mkdir "$scratch/bin"
for tool in semanage semodule fapolicyd-cli; do
  printf '#!/bin/sh\necho "%s $*" >>"$CALLS"\n' "$tool" >"$scratch/bin/$tool"
done
# SC_FAIL and AA_FAIL list the argument strings that fail, as a|b. list-units prints SC_LIST,
# or SC_AFTER once an agent instance has been stopped.
cat >"$scratch/bin/systemctl" <<'STUB'
#!/bin/sh
echo "systemctl $*" >>"$CALLS"
case "|${SC_FAIL:-}|" in *"|$*|"*) echo "stub systemctl: $* failed" >&2; exit 1 ;; esac
if [ "$1" = list-units ]; then
  if grep -q '^systemctl stop maknae-agent@' "$CALLS"; then printf '%b' "${SC_AFTER:-}"; else printf '%b' "${SC_LIST:-}"; fi
fi
exit 0
STUB
cat >"$scratch/bin/apparmor_parser" <<'STUB'
#!/bin/sh
echo "apparmor_parser $*" >>"$CALLS"
case "|${AA_FAIL:-}|" in *"|$1|"*) echo "AA-DIAG: syntax error in profile" >&2; exit 1 ;; esac
exit 0
STUB
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

root="${scratch:?}/root"
units="$root/etc/systemd/system"
# One pass, so the scratch path (under /var on macOS) is never rewritten again.
rooted() { sed -E "s#/(etc|var|usr|run|Library|sys)/#$root/\1/#g"; }

# $1=script text $2..=its arguments. Every root path in the text is moved into scratch first,
# and a text that still names one is never run.
run() {
  local body; body="$(printf '%s\n' "$1" | rooted)"; shift
  if printf '%s\n' "$body" | sed "s#$root/##g" | grep -Eq '/(etc|var|usr|run|Library|sys)/'; then
    echo "FAIL: agent-instances: a script still names a root path after the rewrite; not run" >&2
    exit 1
  fi
  : >"$scratch/calls"
  CALLS="$scratch/calls" PATH="$scratch/bin:$PATH" bash -c "$body" _ "$@" >/dev/null 2>"$scratch/err"
}
calls() { tr '\n' ';' <"$scratch/calls"; }
err() { tr '\n' ' ' <"$scratch/err"; }
line_of() { grep -nxF "$1" "$scratch/calls" | head -1 | cut -d: -f1 || true; }
line_in() { grep -nxF -- "$2" "$1" | head -1 | cut -d: -f1 || true; }

plant() { # each enrolled instance's drop-in and link, and units that are not agents'
  rm -rf -- "${root:?}"; mkdir -p "$units/multi-user.target.wants" "$units/maknaed.service.d"
  mkdir "$units/maknae-agent@hobi.service.d" "$units/maknae-agent@jin.service.d"
  : >"$units/maknae-agent@hobi.service.d/account.conf"; : >"$units/maknaed.service.d/local.conf"
  for u in maknae-agent@hobi maknae-agent@jin maknae-agent@suga maknaed; do
    ln -s "/usr/lib/systemd/system/$u.service" "$units/multi-user.target.wants/$u.service"
  done
  mkdir -p "$root/sys/module/apparmor/parameters"
  echo Y >"$root/sys/module/apparmor/parameters/enabled"
}
planted() { (cd "$units" && find . -mindepth 1 | LC_ALL=C sort | tr '\n' ' '); }
cleared='./maknaed.service.d ./maknaed.service.d/local.conf ./multi-user.target.wants ./multi-user.target.wants/maknaed.service '
disabled='systemctl disable maknae-agent@hobi.service;systemctl disable maknae-agent@jin.service;systemctl disable maknae-agent@suga.service;'
two='maknae-agent@hobi.service loaded active running x\nmaknae-agent@jin.service loaded active running x\n'
hobi='maknae-agent@hobi.service loaded active running x\n'
unloads_agentd() { grep -q '^apparmor_parser -R .*/etc/apparmor.d/usr.bin.maknae-agentd$' "$scratch/calls"; }

table() { # $1=label $2=prerm $3=postinst $4=spec $5=postrm
  local l="$1" prerm="$2" postinst="$3" spec="$4" postrm="$5" rc a m before
  plant
  rc=0; SC_LIST="$hobi" run "$(cat "$prerm")" remove || rc=$?
  a="$(line_of "systemctl stop maknae-agent@hobi.service")"; m="$(line_of "systemctl stop maknaed.service")"
  [ "$rc" -eq 0 ] && [ -n "$a" ] && [ -n "$m" ] && [ "$a" -lt "$m" ] && unloads_agentd \
    && ok "$l: deb remove stops every agent instance before maknaed and unloads the agent profile" \
    || bad "$l: deb remove -> rc=$rc calls='$(calls)'"
  rc=0; SC_LIST="$hobi" SC_FAIL='stop maknae-agent@hobi.service' run "$(cat "$prerm")" remove || rc=$?
  [ "$rc" -ne 0 ] && ! unloads_agentd && ! grep -qxF "systemctl stop maknaed.service" "$scratch/calls" \
    && grep -q '(maknae-agent@hobi.service); removal is aborted' "$scratch/err" \
    && ok "$l: deb remove with a failed stop aborts with the agent profile loaded" \
    || bad "$l: deb remove with a failed stop -> rc=$rc calls='$(calls)' err='$(err)'"
  rc=0; SC_LIST="$hobi" SC_AFTER="$hobi" run "$(cat "$prerm")" remove || rc=$?
  [ "$rc" -ne 0 ] && ! unloads_agentd && grep -q '(maknae-agent@hobi.service); removal is aborted' "$scratch/err" \
    && ok "$l: deb remove with an instance still running aborts, naming it" \
    || bad "$l: deb remove with a running instance -> rc=$rc calls='$(calls)' err='$(err)'"
  rc=0; run "$(cat "$prerm")" remove || rc=$?
  [ "$rc" -eq 0 ] && ! grep -q '^systemctl stop maknae-agent@' "$scratch/calls" && unloads_agentd \
    && ok "$l: deb remove with no instance stops none and proceeds" \
    || bad "$l: deb remove with no instance -> rc=$rc calls='$(calls)' err='$(err)'"
  rc=0; run "$(cat "$prerm")" upgrade 1.0 || rc=$?
  [ "$rc" -eq 0 ] && [ ! -s "$scratch/calls" ] && ok "$l: deb upgrade stops nothing" \
    || bad "$l: deb upgrade -> rc=$rc calls='$(calls)'"

  rc=0; SC_LIST="$two" run "$(extract "$postinst" restart_agent_instances); restart_agent_instances" || rc=$?
  [ "$rc" -eq 0 ] && [ "$(grep -c '^systemctl try-restart maknae-agent@' "$scratch/calls")" -eq 2 ] \
    && grep -qxF "systemctl try-restart maknae-agent@jin.service" "$scratch/calls" \
    && ok "$l: deb restart_agent_instances try-restarts every running instance" \
    || bad "$l: deb restart_agent_instances -> rc=$rc calls='$(calls)'"
  rc=0; SC_LIST="$two" SC_FAIL='try-restart maknae-agent@jin.service' \
    run "$(extract "$postinst" restart_agent_instances); restart_agent_instances" || rc=$?
  [ "$rc" -ne 0 ] && grep -qxF "systemctl try-restart maknae-agent@hobi.service" "$scratch/calls" \
    && grep -q 'did not restart onto the new binary: maknae-agent@jin.service' "$scratch/err" \
    && ok "$l: deb restart_agent_instances fails, naming the instance that did not restart" \
    || bad "$l: deb restart_agent_instances failure -> rc=$rc calls='$(calls)' err='$(err)'"
  a="$(line_in "$postinst" '            load_agent_profile || exit 1')"; m="$(line_in "$postinst" '            restart_agent_instances || exit 1')"
  [ -n "$a" ] && [ -n "$m" ] && [ "$a" -lt "$m" ] \
    && [ "$(grep -c 'load_agent_profile || exit 1$' "$postinst")" -eq 1 ] \
    && [ "$(grep -c 'restart_agent_instances || exit 1$' "$postinst")" -eq 1 ] \
    && awk '/if \[ -n "\$\{2:-\}" \]; then/ {on=1} on && /restart_agent_instances \|\| exit 1$/ {f=1} on && /^        fi$/ {exit} END {exit !f}' "$postinst" \
    && ok "$l: deb postinst fails on the agent profile before any restart, and restarts only on upgrade" \
    || bad "$l: deb postinst wiring -> load=$a restart=$m"
  plant; rc=0; AA_FAIL=-r run "$(extract "$postinst" load_agent_profile); load_agent_profile" || rc=$?
  [ "$rc" -ne 0 ] && grep -q 'did not load, so no agent instance is restarted: AA-DIAG' "$scratch/err" \
    && ok "$l: deb load_agent_profile fails with the parser's diagnostic" \
    || bad "$l: deb load_agent_profile failure -> rc=$rc calls='$(calls)' err='$(err)'"
  plant; rc=0; run "$(extract "$postinst" load_agent_profile); load_agent_profile" || rc=$?
  a="$(calls)"; echo N >"$root/sys/module/apparmor/parameters/enabled"
  m=0; run "$(extract "$postinst" load_agent_profile); load_agent_profile" || m=$?
  [ "$rc" -eq 0 ] && [ "$m" -eq 0 ] && [ "$a" = "apparmor_parser -r $root/etc/apparmor.d/usr.bin.maknae-agentd;" ] \
    && [ ! -s "$scratch/calls" ] \
    && ok "$l: deb load_agent_profile loads the profile, and skips a kernel without AppArmor" \
    || bad "$l: deb load_agent_profile -> rc=$rc/$m calls='$a' then '$(calls)'"

  plant; rc=0; SC_LIST="$hobi" run "$(section "$spec" preun)" 0 || rc=$?
  a="$(line_of "systemctl stop maknae-agent@hobi.service")"; m="$(grep -n '^systemctl preun-macro maknaed.service' "$scratch/calls" | cut -d: -f1 || true)"
  [ "$rc" -eq 0 ] && [ -n "$a" ] && [ -n "$m" ] && [ "$a" -lt "$m" ] \
    && ok "$l: rpm erase stops every agent instance before maknaed" || bad "$l: rpm %preun 0 -> rc=$rc calls='$(calls)'"
  plant; before="$(planted)"; rc=0; SC_LIST="$hobi" SC_FAIL='stop maknae-agent@hobi.service' run "$(section "$spec" preun)" 0 || rc=$?
  [ "$rc" -ne 0 ] && [ "$(planted)" = "$before" ] && ! grep -q '^systemctl \(disable\|preun-macro\)' "$scratch/calls" \
    && grep -q '(maknae-agent@hobi.service); the erase is aborted' "$scratch/err" \
    && ok "$l: rpm erase with a failed stop aborts before disabling anything" \
    || bad "$l: rpm %preun 0 failed stop -> rc=$rc calls='$(calls)' err='$(err)'"
  plant; before="$(planted)"; rc=0; SC_LIST="$hobi" SC_AFTER="$hobi" run "$(section "$spec" preun)" 0 || rc=$?
  [ "$rc" -ne 0 ] && [ "$(planted)" = "$before" ] && ! grep -q '^systemctl \(disable\|preun-macro\)' "$scratch/calls" \
    && grep -q '(maknae-agent@hobi.service); the erase is aborted' "$scratch/err" \
    && ok "$l: rpm erase with an instance still running aborts, naming it" \
    || bad "$l: rpm %preun 0 running instance -> rc=$rc calls='$(calls)' err='$(err)'"
  rc=0; run "$(section "$spec" preun)" 1 || rc=$?
  [ "$rc" -eq 0 ] && ! grep -q 'maknae-agent@' "$scratch/calls" \
    && ok "$l: rpm upgrade %preun stops no agent instance" || bad "$l: rpm %preun 1 -> rc=$rc calls='$(calls)'"
  rc=0; SC_LIST="$two" run "$(section "$spec" postun)" 1 || rc=$?
  [ "$rc" -eq 0 ] && [ "$(grep -c '^systemctl try-restart maknae-agent@' "$scratch/calls")" -eq 2 ] \
    && ok "$l: rpm upgrade %postun try-restarts every running agent instance" || bad "$l: rpm %postun 1 -> rc=$rc calls='$(calls)'"
  rc=0; SC_LIST="$two" SC_FAIL='try-restart maknae-agent@hobi.service' run "$(section "$spec" postun)" 1 || rc=$?
  [ "$rc" -eq 0 ] && grep -qxF "systemctl try-restart maknae-agent@jin.service" "$scratch/calls" \
    && grep -q 'maknae: maknae-agent@hobi.service did not restart onto the new binary' "$scratch/err" \
    && ok "$l: rpm upgrade %postun warns of each instance that did not restart, and goes on" \
    || bad "$l: rpm %postun 1 failed restart -> rc=$rc calls='$(calls)' err='$(err)'"
  rc=0; run "$(section "$spec" postun)" 0 || rc=$?
  [ "$rc" -eq 0 ] && ! grep -q 'maknae-agent@' "$scratch/calls" \
    && ok "$l: rpm erase %postun restarts no agent instance" || bad "$l: rpm %postun 0 -> rc=$rc calls='$(calls)'"

  plant; rc=0; run "$(extract "$postrm" disable_agent_instances); disable_agent_instances" || rc=$?
  [ "$rc" -eq 0 ] && [ "$(calls)" = "$disabled" ] && [ "$(planted)" = "$cleared" ] \
    && ok "$l: deb disable_agent_instances disables every instance and removes its drop-in and link" \
    || bad "$l: deb disable_agent_instances -> rc=$rc calls='$(calls)' left='$(planted)'"
  awk '/^    purge\)$/ {on=1} on && /^        disable_agent_instances$/ {f=1} on && /^        ;;$/ {exit} END {exit !f}' "$postrm" \
    && [ "$(grep -c '^ *disable_agent_instances$' "$postrm")" -eq 1 ] \
    && ok "$l: deb purge, and only purge, calls disable_agent_instances" \
    || bad "$l: deb postrm purge wiring -> $(grep -n 'disable_agent_instances' "$postrm" | tr '\n' ';')"
  for arg in remove upgrade; do
    plant; before="$(planted)"; rc=0; run "$(cat "$postrm")" "$arg" || rc=$?
    [ "$rc" -eq 0 ] && ! grep -q 'maknae-agent@' "$scratch/calls" && [ "$(planted)" = "$before" ] \
      && ok "$l: deb postrm $arg leaves every instance enabled with its drop-in" \
      || bad "$l: deb postrm $arg -> rc=$rc calls='$(calls)' left='$(planted)'"
  done
  plant; rc=0; SC_LIST="$hobi" run "$(section "$spec" preun)" 0 || rc=$?
  a="$(line_of "systemctl stop maknae-agent@hobi.service")"; m="$(line_of "systemctl disable maknae-agent@hobi.service")"
  [ "$rc" -eq 0 ] && [ -n "$a" ] && [ -n "$m" ] && [ "$a" -lt "$m" ] && [ "$(planted)" = "$cleared" ] \
    && grep -qxF "systemctl daemon-reload" "$scratch/calls" \
    && [ "$(grep -c '^systemctl disable maknae-agent@' "$scratch/calls")" -eq 3 ] \
    && ok "$l: rpm erase disables every stopped instance and removes its drop-in and link" \
    || bad "$l: rpm %preun 0 disable -> rc=$rc calls='$(calls)' left='$(planted)'"
  plant; before="$(planted)"; rc=0; run "$(section "$spec" preun)" 1 || rc=$?
  [ "$rc" -eq 0 ] && [ "$(planted)" = "$before" ] && ! grep -q '^systemctl disable maknae-agent@' "$scratch/calls" \
    && ok "$l: rpm upgrade %preun leaves every instance enabled with its drop-in" \
    || bad "$l: rpm %preun 1 disable -> rc=$rc calls='$(calls)' left='$(planted)'"
}

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
stub() { # $1=source $2=out $3=the exact line to replace with `:` [$4=the exact line it follows]
  L="$3" ST="${4:-}" awk 'ENVIRON["ST"] == "" || $0 == ENVIRON["ST"] {on=1} on && $0 == ENVIRON["L"] {sub(/[^ ].*/, ":"); n++; on=0} {print} END {exit n != 1}' "$1" >"$2" \
    || { echo "FAIL: agent-instances: no single line '$3' to stub in $1"; exit 1; }
}

stop_line="    printf '%s\\n' \"\$units\" | xargs -r systemctl stop || rc=1"
spec_stop_line="    printf '%%s\\n' \"\$units\" | xargs -r systemctl stop || rc=1"
units_line="    units=\"\$(systemctl list-units --plain --no-legend 'maknae-agent@*.service')\" || rc=1"
list_line="    left=\"\$(systemctl list-units --plain --no-legend --state=active,activating,deactivating,reloading 'maknae-agent@*.service')\" || rc=1"
stub "$prerm" "$scratch/prerm.nostop" "$stop_line"
mutant prerm-nostop "$scratch/prerm.nostop" "$postinst" "$spec" "$postrm" "deb remove"
swallow() { # $1=source $2=out $3=line: the same line with its failure discarded
  L="$3" awk '$0 == ENVIRON["L"] {sub(/\|\| rc=1$/, "|| :"); n++} {print} END {exit n != 1}' "$1" >"$2" \
    || { echo "FAIL: agent-instances: no single line '$3' to swallow in $1"; exit 1; }
}
swallow "$prerm" "$scratch/prerm.stopswallow" "$stop_line"
mutant prerm-stopfail-ignored "$scratch/prerm.stopswallow" "$postinst" "$spec" "$postrm" "deb remove with a failed stop"
stub "$prerm" "$scratch/prerm.nolist" "$list_line"
mutant prerm-nolist "$scratch/prerm.nolist" "$postinst" "$spec" "$postrm" "deb remove with a running instance"
stub "$prerm" "$scratch/prerm.nounits" "$units_line"
mutant prerm-nounits "$scratch/prerm.nounits" "$postinst" "$spec" "$postrm" "deb remove"
awk '/^        stop_agent_instances \|\| exit 1$/ {next} {print} /^        systemctl stop maknaed.service/ {print "        stop_agent_instances || exit 1"}' "$prerm" >"$scratch/prerm.late"
grep -qx '        stop_agent_instances || exit 1' "$scratch/prerm.late" || { echo "FAIL: agent-instances: late-stop mutant lost the call"; exit 1; }
mutant prerm-late "$scratch/prerm.late" "$postinst" "$spec" "$postrm" "deb remove"

stub "$postinst" "$scratch/postinst.norestart" '        systemctl try-restart "$u" || failed="$failed $u"'
mutant postinst-norestart "$prerm" "$scratch/postinst.norestart" "$spec" "$postrm" "deb restart_agent_instances"
sed 's/^        systemctl try-restart "\$u" || failed="\$failed \$u"$/        systemctl try-restart "$u" || :/' "$postinst" >"$scratch/postinst.swallow"
cmp -s "$postinst" "$scratch/postinst.swallow" && { echo "FAIL: agent-instances: swallow mutant changed nothing"; exit 1; }
mutant postinst-swallow "$prerm" "$scratch/postinst.swallow" "$spec" "$postrm" "deb restart_agent_instances failure"
stub "$postinst" "$scratch/postinst.noload" '            load_agent_profile || exit 1'
mutant postinst-noload "$prerm" "$scratch/postinst.noload" "$spec" "$postrm" "deb postinst wiring"
stub "$postinst" "$scratch/postinst.norestartcall" '            restart_agent_instances || exit 1'
mutant postinst-norestartcall "$prerm" "$scratch/postinst.norestartcall" "$spec" "$postrm" "deb postinst wiring"
stub "$postinst" "$scratch/postinst.loadswallow" '    return 1' 'load_agent_profile() {'
mutant postinst-loadswallow "$prerm" "$scratch/postinst.loadswallow" "$spec" "$postrm" "deb load_agent_profile failure"
stub "$postinst" "$scratch/postinst.noskip" '    [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ] || return 0'
mutant postinst-noskip "$prerm" "$scratch/postinst.noskip" "$spec" "$postrm" "deb load_agent_profile"

stub "$spec" "$scratch/spec.nostop" "$spec_stop_line"
mutant spec-nostop "$prerm" "$postinst" "$scratch/spec.nostop" "$postrm" "rpm %preun 0"
swallow "$spec" "$scratch/spec.stopswallow" "$spec_stop_line"
mutant spec-stopfail-ignored "$prerm" "$postinst" "$scratch/spec.stopswallow" "$postrm" "rpm %preun 0 failed stop"
stub "$spec" "$scratch/spec.nolist" "$list_line"
mutant spec-nolist "$prerm" "$postinst" "$scratch/spec.nolist" "$postrm" "rpm %preun 0 running instance"
stub "$spec" "$scratch/spec.nounits" "$units_line"
mutant spec-nounits "$prerm" "$postinst" "$scratch/spec.nounits" "$postrm" "rpm %preun 0"
stub "$spec" "$scratch/spec.noabort" '        exit 1' '    if [ "$rc" -ne 0 ] || [ -n "$left" ]; then'
mutant spec-noabort "$prerm" "$postinst" "$scratch/spec.noabort" "$postrm" "rpm %preun 0 failed stop"
spec_restart='        systemctl try-restart "$u" || echo "maknae: $u did not restart onto the new binary: run systemctl restart $u" >&2'
stub "$spec" "$scratch/spec.norestart" "$spec_restart"
mutant spec-norestart "$prerm" "$postinst" "$scratch/spec.norestart" "$postrm" "rpm %postun 1"
mutant spec-restart-unwarned "$prerm" "$postinst" "$scratch/spec.norestart" "$postrm" "rpm %postun 1 failed restart"
STOP="$spec_stop_line" awk '/^%preun$/ {on=1} on && $0 == ENVIRON["STOP"] {print "    :"; next} {print} on && /^%systemd_preun / {print "if [ $1 -eq 0 ]; then"; print ENVIRON["STOP"]; print "fi"; on=0}' "$spec" >"$scratch/spec.late"
[ "$(grep -cxF -- "$spec_stop_line" "$scratch/spec.late")" -eq 1 ] && grep -qx '    :' "$scratch/spec.late" || { echo "FAIL: agent-instances: late-stop %preun mutant lost the call"; exit 1; }
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
stub "$spec" "$scratch/spec.keeplink" '        rm -f "/etc/systemd/system/multi-user.target.wants/$u" || exit 1'
mutant spec-keeplink "$prerm" "$postinst" "$scratch/spec.keeplink" "$postrm" "rpm %preun 0 disable"
awk '/^%preun$/ {on=1} on && /^    for d in / {print "fi"; print "if :; then"} {print} /^%postun$/ {on=0}' "$spec" >"$scratch/spec.onupgrade"
mutant spec-onupgrade "$prerm" "$postinst" "$scratch/spec.onupgrade" "$postrm" "rpm %preun 1 disable"

echo "PASS: agent-instances: $cases cases, and $mutants mutants each fail their own case"
