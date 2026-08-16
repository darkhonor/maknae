# RPM packaging

Native `rpmbuild` package (`maknae.spec` + `build-rpm.sh`) for RHEL / Rocky. It
installs the `maknaed` daemon and `maknae` CLI, the hardened `maknaed.service`
system unit, the sysusers.d definition (`_maknae` service account + `maknae`
operator group), the shipped default YAMLs (`authz.yaml` / `maknae.yaml`), the
SELinux module (compiled to `maknae.pp` at build time), the fapolicyd trust
fragment, and the Vault-port label helper. The `%post` sets `chattr +a` on the
audit dir and file.

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
shipped `authz.yaml` uses `~` patterns that are inert until an operator principal
exists, so the daemon refuses to serve until `enroll` writes it. Run, **in order**:

```bash
# SELinux hosts: label the Vault port (else name_connect to Vault is denied).
sudo /usr/libexec/maknae/maknae-selinux-ports.sh add <vault-tcp-port>   # default 8200
sudo maknae enroll --deployment-id <id>
# re-login so your shell joins the `maknae` group
sudo systemctl enable --now maknaed
```

**Upgrades follow the same order** — enroll (if not already) before restarting the
daemon; the fail-closed `~` default applies to a restarted daemon too. The
append-only `/var/log/maknae/audit.jsonl` trail is preserved across upgrades.

**RHEL 9:** installs and the daemon can seal its credential, but operator `enroll`
needs systemd ≥ 256 (`systemd-creds --user`); el9 ships 252. RHEL 9 is packaging +
daemon-seal only this release — operator enroll is deferred to #73. Full flow works
on RHEL 10.

See `packaging/README.md` for the full install guide, GPG verification, and the
SELinux `bin_t` tool-domain honest limit.
