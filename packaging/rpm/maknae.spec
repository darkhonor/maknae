%global debug_package %{nil}

Name:           maknae
# Version injected by build-rpm.sh via --define "_pkgversion X.Y.Z" so the git
# tag is the single source of truth. Building without it fails loudly.
Version:        %{_pkgversion}
Release:        1%{?dist}
Summary:        Trust-plane daemon and operator CLI for a local AI-agent platform
License:        Apache-2.0
URL:            https://github.com/darkhonor/maknae

# Pre-built binaries (container/host build pipeline) + packaging assets.
Source0:        maknaed
Source1:        maknae
Source2:        maknaed.service
Source3:        maknae.sysusers
Source4:        maknae.te
Source5:        maknae.fc
Source6:        maknae.fapolicyd.trust
Source7:        maknae-selinux-ports.sh
Source8:        authz.yaml
Source9:        maknae.yaml
# #240a: the egress deputy — binary, unit, and the socket unit that lets the
# init system own the socket (no chgrp, no CAP_CHOWN in the deputy).
Source10:       maknae-egress
Source11:       maknae-egress.service
Source12:       maknae-egress.socket
Source13:       bindings.yaml
Source14:       maknae-policy-sync.path
Source15:       maknae-policy-sync.service
Source16:       80-maknae.preset

ExclusiveArch:  x86_64

# SELinux policy compilation
BuildRequires:  checkpolicy
BuildRequires:  selinux-policy-devel
# sysusers-dir / unit-dir macros + sysusers_create_compat / systemd_* scriptlets.
BuildRequires:  systemd-rpm-macros

Requires:       systemd
Requires:       tpm2-tss
Requires:       policycoreutils-python-utils
Requires:       selinux-policy-targeted
# enroll re-asserts the deputy's /etc/maknae ACL and removes the legacy
# _maknae home ACL (#365) with setfacl/getfacl.
Requires:       acl
# #240b, #500: %post runs setfacl and timeout, so acl and coreutils must be installed BEFORE this package's
# scriptlet, which a plain Requires does not order.
Requires(post): acl coreutils
Requires:       fapolicyd
Requires(pre):  systemd
Requires(post): systemd policycoreutils selinux-policy-targeted e2fsprogs
Requires(preun):  systemd
Requires(postun): systemd policycoreutils

%description
Maknae is a security-first, local AI-agent platform. This package installs the
privileged trust-plane daemon (maknaed) and the non-privileged operator CLI
(maknae), a hardened systemd unit with TPM2-sealed credential loading, an
SELinux Type Enforcement policy, a fapolicyd trust fragment, the shipped
RBAC authorization policy and its role-bindings file — for deployment on
hardened RHEL/Rocky systems.

A fresh install is not runnable until `sudo maknae enroll` provisions the
daemon credential and the operator principal (the daemon refuses to start
until then). See the install guide.

%build
# Compile the SELinux policy via the refpolicy devel Makefile so the M4 macros
# in maknae.te/.fc (policy_module, init_daemon_domain, gen_context, ...) expand
# before checkmodule runs. A bare `checkmodule -m` does not preprocess M4.
cp %{SOURCE4} maknae.te
cp %{SOURCE5} maknae.fc
make -f /usr/share/selinux/devel/Makefile maknae.pp

%install
# Binaries
install -D -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/maknaed
install -D -m 0755 %{SOURCE1} %{buildroot}%{_bindir}/maknae
install -D -m 0755 %{SOURCE10} %{buildroot}%{_bindir}/maknae-egress

# systemd unit
install -D -m 0644 %{SOURCE2} %{buildroot}%{_unitdir}/maknaed.service
install -D -m 0644 %{SOURCE11} %{buildroot}%{_unitdir}/maknae-egress.service
install -D -m 0644 %{SOURCE12} %{buildroot}%{_unitdir}/maknae-egress.socket
install -D -m 0644 %{SOURCE14} %{buildroot}%{_unitdir}/maknae-policy-sync.path
install -D -m 0644 %{SOURCE15} %{buildroot}%{_unitdir}/maknae-policy-sync.service
install -D -m 0644 %{SOURCE16} %{buildroot}%{_presetdir}/80-maknae.preset

# sysusers.d
install -D -m 0644 %{SOURCE3} %{buildroot}%{_sysusersdir}/maknae.conf

# SELinux policy module
install -D -m 0644 maknae.pp %{buildroot}%{_datadir}/selinux/packages/maknae.pp

# Vault-port label helper
install -D -m 0750 %{SOURCE7} %{buildroot}%{_libexecdir}/maknae/maknae-selinux-ports.sh

# fapolicyd trust fragment
install -D -m 0644 %{SOURCE6} %{buildroot}%{_sysconfdir}/fapolicyd/trust.d/maknae

# Config tree (final ownership set via %attr in %files)
install -D -m 0640 %{SOURCE8} %{buildroot}%{_sysconfdir}/maknae/authz.yaml
install -D -m 0640 %{SOURCE9} %{buildroot}%{_sysconfdir}/maknae/maknae.yaml
install -D -m 0644 %{SOURCE13} %{buildroot}%{_datadir}/maknae/bindings.yaml
install -d -m 0750 %{buildroot}%{_sysconfdir}/maknae/private
# #240b: the deputy's credential set dir (files written by `maknae enroll`).
install -d -m 0750 %{buildroot}%{_sysconfdir}/maknae/egress
install -d -m 0755 %{buildroot}%{_sysconfdir}/pki/maknae
install -d -m 0700 %{buildroot}%{_localstatedir}/log/maknae
install -d -m 0700 %{buildroot}%{_localstatedir}/lib/maknae
# audit.jsonl is not a payload file and not package-owned: %post creates it, so
# erase keeps the trail and an upgrade never replaces the append-only inode.

%pre
# Create the _maknae and _maknae-egress accounts and the maknae operator group
# BEFORE payload unpack so rpm -V never sees owner drift.
%sysusers_create_compat %{SOURCE3}

%post
%systemd_post maknaed.service maknae-egress.service maknae-egress.socket
# Root-held until the audit lifecycle below hands it back to _maknae.
d=%{_localstatedir}/log/maknae
if [ ! -d "$d" ] || [ -h "$d" ] || ! chown 0:0 "$d" || ! setfacl -P -b "$d" || ! chmod 0700 "$d" \
    || [ "$(stat -c '%%u %%g %%a' "$d")" != "0 0 700" ] || ! acl="$(getfacl -P -s -p "$d")" || [ -n "$acl" ]; then
    echo "maknae: cannot hold $d as root:root 0700 with no ACL; it is left root-owned" >&2
    exit 1
fi
# SELinux module + contexts
semodule -i %{_datadir}/selinux/packages/maknae.pp 2>/dev/null || :
# Fresh install only (no store yet): a bindings.yaml root removed stays removed;
# maknaed keeps enforcing the bindings it holds and `maknae policy sync` restores the file.
B=%{_sysconfdir}/maknae/bindings.yaml
if [ ! -e "$B" ] && [ ! -h "$B" ] && [ ! -e %{_localstatedir}/lib/maknae/kernel.graph ]; then
    if ! install -m 0640 -o root -g _maknae %{_datadir}/maknae/bindings.yaml "$B"; then
        echo "maknae: cannot create $B" >&2
        exit 1
    fi
fi
restorecon -Rv %{_bindir}/maknaed %{_bindir}/maknae-egress %{_sysconfdir}/maknae %{_sysconfdir}/pki/maknae %{_localstatedir}/log/maknae %{_localstatedir}/lib/maknae 2>/dev/null || :
# #240b (D3): the egress deputy is in neither root nor _maknae, and the config
# loader refuses any world bit on /etc/maknae, so it reaches the dir by a user
# ACL granting `rx` — `r` because maknae-io opens the directory
# O_RDONLY|O_DIRECTORY, `x` for traversal, never `w` (the loader's 0o022 mask).
# Requires: acl. Re-asserted on every %post and by `maknae enroll`.
setfacl -m u:_maknae-egress:rx %{_sysconfdir}/maknae 2>/dev/null || \
    echo "maknae: setfacl failed — grant _maknae-egress rx on %{_sysconfdir}/maknae or the egress deputy cannot start" >&2
# #240: /run/maknae-egress is the socket unit's, 0751; a directory left by the
# earlier service-unit shape (0750) is untraversable by _maknae until re-created.
[ -d /run/maknae-egress ] && chmod 0751 /run/maknae-egress 2>/dev/null || :
# fapolicyd trust (never restart mid-transaction; the rpm plugin handles it)
fapolicyd-cli --update 2>/dev/null || :
# Audit file: created when absent, then append-only; a failure fails %post. Not
# package-owned, so erase keeps the trail. FILE-level only: a +a directory would
# block rpm from managing /var/log/maknae.
AUDIT=%{_localstatedir}/log/maknae/audit.jsonl
if [ ! -e "$AUDIT" ] && [ ! -h "$AUDIT" ]; then
    install -m 0640 -o _maknae -g _maknae /dev/null "$AUDIT"
    restorecon "$AUDIT" 2>/dev/null || :
fi
if [ -h "$AUDIT" ] || [ ! -f "$AUDIT" ] || [ "$(stat -c %%h "$AUDIT")" != 1 ] \
    || [ "$(stat -c %%U:%%G "$AUDIT")" != _maknae:_maknae ]; then
    echo "maknae: $AUDIT is not a regular, single-link _maknae:_maknae file; %{_localstatedir}/log/maknae is left root-owned" >&2
    exit 1
fi
if ! chattr +a "$AUDIT" || ! lsattr -d "$AUDIT" | cut -d' ' -f1 | grep -q a; then
    echo "maknae: cannot set the append-only attribute on $AUDIT (filesystem: $(stat -f -c %%T "$AUDIT" 2>/dev/null || echo unknown)); %{_localstatedir}/log/maknae is left root-owned" >&2
    exit 1
fi
# The traverse entry for each reader maknae.yaml declares (#500), restored after the
# hold strips the directory's ACL. The trail files' own entries are never touched here.
grant_reader_traverse() {
    rc=0
    errf="$(mktemp)" || return 1
    readers="$(timeout 60 %{_bindir}/maknae audit-readers 2>"$errf")" || rc=$?
    if [ "$rc" -ne 0 ]; then
        [ "$rc" -ne 124 ] || echo "the account lookup did not finish within 60s" >>"$errf"
        echo "maknae: audit.readers not applied: $(cat "$errf")" >&2
        rm -f "$errf"
        return 0
    fi
    rm -f "$errf"
    [ -n "$readers" ] || return 0
    printf '%%s\n' "$readers" | LC_ALL=C grep -Evx '[a-z_][a-z0-9_-]{0,30}[$]?' >/dev/null || rc=$?
    if [ "$rc" -ne 1 ]; then
        echo "maknae: audit.readers printed an unexpected name; not applied" >&2
        return 0
    fi
    for r in $readers; do setfacl -P -m "u:$r:x" %{_localstatedir}/log/maknae || return 1; done
}
if ! grant_reader_traverse; then
    echo "maknae: cannot apply audit.readers to %{_localstatedir}/log/maknae; it is left root-owned" >&2
    exit 1
fi
chown -h _maknae:_maknae %{_localstatedir}/log/maknae

%preun
%systemd_preun maknaed.service maknae-egress.service maknae-egress.socket maknae-policy-sync.path maknae-policy-sync.service
if [ $1 -eq 0 ]; then
    # Full removal only. The audit trail and its append-only attribute are kept.
    semodule -r maknae 2>/dev/null || :
    # NOTE: the operator's Vault port label is intentionally NOT auto-removed here
    # (%preun cannot know the port; a default-8200 removal would orphan/clobber).
    # Run `maknae-selinux-ports.sh remove <port>` before uninstall if desired.
fi

%postun
# /run/maknae-egress is the socket unit's RuntimeDirectory= (#240); an existing
# directory keeps the old (0750) mode until re-created, so the mode is asserted
# in %post too. One transaction: systemd orders the socket before its service
# from maknae-egress.service's Requires=/After=, not from this argv.
%systemd_postun_with_restart maknaed.service maknae-egress.socket maknae-egress.service
%systemd_postun maknae-policy-sync.path maknae-policy-sync.service
if [ $1 -eq 0 ]; then
    fapolicyd-cli --update 2>/dev/null || :
fi

%files
%{_bindir}/maknaed
%{_bindir}/maknae
%{_bindir}/maknae-egress
%{_unitdir}/maknaed.service
%{_unitdir}/maknae-egress.service
%{_unitdir}/maknae-egress.socket
%{_unitdir}/maknae-policy-sync.path
%{_unitdir}/maknae-policy-sync.service
%{_presetdir}/80-maknae.preset
%{_sysusersdir}/maknae.conf
%{_datadir}/selinux/packages/maknae.pp
%{_libexecdir}/maknae/maknae-selinux-ports.sh
%dir %{_datadir}/maknae
%{_datadir}/maknae/bindings.yaml
%config(noreplace) %{_sysconfdir}/fapolicyd/trust.d/maknae
%dir %attr(0750,root,_maknae) %{_sysconfdir}/maknae
%config(noreplace) %attr(0640,root,_maknae) %{_sysconfdir}/maknae/authz.yaml
%config(noreplace) %attr(0640,root,_maknae) %{_sysconfdir}/maknae/maknae.yaml
%dir %attr(0750,root,_maknae) %{_sysconfdir}/maknae/private
%dir %attr(0750,root,_maknae-egress) %{_sysconfdir}/maknae/egress
%dir %attr(0755,root,root) %{_sysconfdir}/pki/maknae
%dir %attr(0700,_maknae,_maknae) %{_localstatedir}/log/maknae
%dir %attr(0700,_maknae,_maknae) %{_localstatedir}/lib/maknae

%changelog
* Mon Aug 17 2026 Alex Ackerman <developer@maknae.io> - 0.1.0-1
- Initial Tokki PR-T1 packaging: maknaed/maknae binaries, hardened systemd unit
  with TPM2 LoadCredentialEncrypted, SELinux TE policy (NNP process2 transition,
  credential-read, mandatory Vault egress via operator-labeled port, append-only
  audit), fapolicyd trust fragment, two-group sysusers, shipped authz.yaml DAC
  default + maknae.yaml skeleton.
