%global debug_package %{nil}

Name:           maknae
# Version injected by build-rpm.sh via --define "_pkgversion X.Y.Z" so the git
# tag is the single source of truth. Building without it fails loudly.
Version:        %{_pkgversion}
Release:        1%{?dist}
Summary:        Maknae trust-plane daemon and CLI (local AI-agent platform)
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

ExclusiveArch:  x86_64

# SELinux policy compilation
BuildRequires:  checkpolicy
BuildRequires:  selinux-policy-devel
# sysusers-dir / unit-dir macros + %sysusers_create_compat / %systemd_* scriptlets.
BuildRequires:  systemd-rpm-macros

Requires:       systemd
Requires:       tpm2-tss
Requires:       policycoreutils-python-utils
Requires:       selinux-policy-targeted
Requires:       fapolicyd
Requires(pre):  systemd
Requires(post): systemd policycoreutils selinux-policy-targeted
Requires(preun):  systemd
Requires(postun): systemd policycoreutils

%description
Maknae is a security-first, local AI-agent platform. This package installs the
privileged trust-plane daemon (maknaed) and the non-privileged operator CLI
(maknae), a hardened systemd unit with TPM2-sealed credential loading, an
SELinux Type Enforcement policy, a fapolicyd trust fragment, and the shipped
DAC authorization policy — for deployment on hardened RHEL/Rocky systems.

A fresh install is not runnable until `sudo maknae enroll` provisions the
daemon credential and the operator principal (the shipped authz.yaml fail-closes
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

# systemd unit
install -D -m 0644 %{SOURCE2} %{buildroot}%{_unitdir}/maknaed.service

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
install -d -m 0750 %{buildroot}%{_sysconfdir}/maknae/private
install -d -m 0700 %{buildroot}%{_localstatedir}/log/maknae
# audit.jsonl is NOT a payload file — it is %ghost, created first-install-only in
# %post (a payload file under the chattr +a dir would fail to replace on upgrade).

%pre
# Create _maknae user + maknae operator group BEFORE payload unpack so rpm -V
# never sees owner drift.
%sysusers_create_compat %{SOURCE3}

%post
%systemd_post maknaed.service
# SELinux module + contexts
semodule -i %{_datadir}/selinux/packages/maknae.pp 2>/dev/null || :
restorecon -Rv %{_bindir}/maknaed %{_sysconfdir}/maknae %{_localstatedir}/log/maknae 2>/dev/null || :
# fapolicyd trust (never restart mid-transaction; the rpm plugin handles it)
fapolicyd-cli --update 2>/dev/null || :
# Audit-file lifecycle — first-install-only AND only if absent, then append-only.
# %ghost + this guard means upgrades never truncate the trail or fight chattr +a.
if [ $1 -eq 1 ] && [ ! -e %{_localstatedir}/log/maknae/audit.jsonl ]; then
    install -m 0640 -o _maknae -g _maknae /dev/null %{_localstatedir}/log/maknae/audit.jsonl
    chattr +a %{_localstatedir}/log/maknae/audit.jsonl 2>/dev/null || :
fi
chattr +a %{_localstatedir}/log/maknae 2>/dev/null || :

%preun
%systemd_preun maknaed.service
if [ $1 -eq 0 ]; then
    # Full removal only: clear append-only, then unload the SELinux module.
    chattr -a %{_localstatedir}/log/maknae/audit.jsonl 2>/dev/null || :
    chattr -a %{_localstatedir}/log/maknae 2>/dev/null || :
    semodule -r maknae 2>/dev/null || :
    # NOTE: the operator's Vault port label is intentionally NOT auto-removed here
    # (%preun cannot know the port; a default-8200 removal would orphan/clobber).
    # Run `maknae-selinux-ports.sh remove <port>` before uninstall if desired.
fi

%postun
%systemd_postun_with_restart maknaed.service
if [ $1 -eq 0 ]; then
    fapolicyd-cli --update 2>/dev/null || :
fi

%files
%{_bindir}/maknaed
%{_bindir}/maknae
%{_unitdir}/maknaed.service
%{_sysusersdir}/maknae.conf
%{_datadir}/selinux/packages/maknae.pp
%{_libexecdir}/maknae/maknae-selinux-ports.sh
%{_sysconfdir}/fapolicyd/trust.d/maknae
%dir %attr(0750,root,_maknae) %{_sysconfdir}/maknae
%config(noreplace) %attr(0640,root,_maknae) %{_sysconfdir}/maknae/authz.yaml
%config(noreplace) %attr(0640,root,_maknae) %{_sysconfdir}/maknae/maknae.yaml
%dir %attr(0750,root,_maknae) %{_sysconfdir}/maknae/private
%dir %attr(0700,_maknae,_maknae) %{_localstatedir}/log/maknae
%ghost %attr(0640,_maknae,_maknae) %{_localstatedir}/log/maknae/audit.jsonl

%changelog
* Sun Aug 17 2026 Alex Ackerman <developer@maknae.io> - 0.1.0-1
- Initial Tokki PR-T1 packaging: maknaed/maknae binaries, hardened systemd unit
  with TPM2 LoadCredentialEncrypted, SELinux TE policy (NNP process2 transition,
  credential-read, mandatory Vault egress via operator-labeled port, append-only
  audit), fapolicyd trust fragment, two-group sysusers, shipped authz.yaml DAC
  default + maknae.yaml skeleton.
