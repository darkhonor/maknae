# RPM packaging

Native `rpmbuild` package (`maknae.spec` + `build-rpm.sh`) for RHEL / Rocky. It
installs the `maknaed` daemon and `maknae` CLI, the hardened `maknaed.service`
system unit, the sysusers.d definition (`_maknae` service account + `maknae`
operator group), the shipped default YAMLs (`authz.yaml` / `maknae.yaml`; `bindings.yaml` ships as
`/usr/share/maknae/bindings.yaml`, and `%post` copies it to `/etc/maknae` only
when neither that file nor `/var/lib/maknae/kernel.graph` exists), the
SELinux module (compiled to `maknae.pp` at build time), the fapolicyd trust
fragment, and the Vault-port label helper. The `%post` sets `chattr +a` on the
audit **file** only (`/var/log/maknae/audit.jsonl`) — not the directory, which
would block rpm from managing `/var/log/maknae` on upgrade — beside SELinux's
append-only rule, and fails if the file system does not support the attribute.

> There is **no CLI user unit** — the `maknae` CLI is operator-invoked, not a
> systemd service. (Supersedes the earlier scaffold note; Jackrabbit §9.7.)

## Build

```bash
# From the repo root, with the maknaed/maknae binaries already built into place.
packaging/rpm/build-rpm.sh <version>        # e.g. 0.1.0
```

Output lands in `dist/` (e.g. `dist/maknae-0.1.0-1.el10.x86_64.rpm`). Build **on
the target OS**: the SELinux `.pp` is compiled against the host's refpolicy, so
build the el10 rpm on Rocky 10 and the el9 rpm on Rocky 9 (each compiles its own
policy-matched module). Requires `rpm-build`, `checkpolicy`,
`selinux-policy-devel`, and `systemd-rpm-macros`.

Checksum / sign the artifact with `packaging/sign.sh` (see `packaging/README.md`).

## Install

```bash
sudo dnf install ./maknae-<ver>-1.el10.x86_64.rpm
```

## Install → enroll → start rule

The package installs the software fail-closed; it does not start the daemon. The
boot gate requires the `principal` section (#77: a daemon that can authorize no
one refuses to start), so the daemon refuses to serve until `enroll` writes it. Run, **in order**:

```bash
# SELinux hosts: label the Vault port (else name_connect to Vault is denied).
sudo /usr/libexec/maknae/maknae-selinux-ports.sh add <vault-tcp-port>   # default 8200
sudo maknae enroll --deployment-id <id>
# re-login so your shell joins the `maknae` group
sudo systemctl enable --now maknaed
# with providers authorized (`providers:` in maknae.yaml), the deputy's socket
# unit too — it is preset-disabled, and without it every permitted prompt is
# refused as not ready
sudo systemctl enable --now maknae-egress.socket
# each user, before any maknae command
maknae login
```

**Upgrades follow the same order** — enroll (if not already) before restarting the
daemon; a restarted daemon also refuses to start without the `principal` section. The
append-only `/var/log/maknae/audit.jsonl` trail is preserved across upgrades.

**RHEL 9:** installs; enroll is expected to complete now that the `systemd-creds --user`
step is gone (#73), but it has not yet been run live there, nor has enroll → serve. `maknae login` keeps the
token in the `0600` residual file on el9. Full flow proven on RHEL 10.

See `packaging/README.md` for the full install guide, GPG verification, and the
SELinux `bin_t` tool-domain honest limit.

## Removal

`rpm -e` / `dnf remove` stops and disables the units, unloads the SELinux module,
and keeps the audit trail: `/var/log/maknae/audit.jsonl` is created by `%post`,
not owned by the package, so erase leaves it in place with its append-only
attribute. Upgrading from a package that predates #498, which owned the trail as a `%ghost` file that never carried `+a`, has a residual: if the new `%post` refuses, rpm still deletes the old package's `%ghost` entry, and that trail is lost. Keep a copy before such an upgrade. To remove a kept trail, see
[Remove a kept trail](../../docs/runbook.md#remove-a-kept-trail): with `maknaed`
gone, hold the directory as root (`root:root 0700`, no ACL entry, verified), clear `+a` on its regular single-link files
(`chattr -a`), then `rm -rf /var/log/maknae`.
