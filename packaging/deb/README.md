# Debian package (`.deb`)

Native `dpkg-deb` packaging for `maknae` on Debian 13 (Trixie) and compatible
derivatives. Ships the `maknaed` daemon + `maknae` CLI, the hardened systemd
unit, an **AppArmor** confinement profile, the two-group `sysusers.d`, and the
shipped `/etc/maknae` defaults.

This is the Debian analog of `packaging/rpm/`. The security-critical install
lifecycle (sysusers, §4.6 ownership convergence, audit-sink pre-creation +
`chattr +a`, AppArmor load, conffile-ownership fix) lives in the hand-written
maintainer scripts (`postinst`/`prerm`/`postrm`).

## Contents

| Payload path | Source | Mode / owner |
|---|---|---|
| `/usr/bin/maknaed`, `/usr/bin/maknae` | built binaries | `0755 root:root` |
| `/usr/lib/systemd/system/maknaed.service` | `common/maknaed.service` | `0644` |
| `/usr/lib/sysusers.d/maknae.conf` | `common/maknae.sysusers` | `0644` |
| `/etc/apparmor.d/usr.bin.maknaed` | `deb/apparmor/usr.bin.maknaed` | `0644` |
| `/usr/libexec/maknae/maknae-selinux-ports.sh` | `common/maknae-selinux-ports.sh` | `0750` |
| `/etc/maknae/authz.yaml`, `/etc/maknae/maknae.yaml` | `common/` (conffiles) | `root:_maknae 0640` (set in postinst) |
| `/var/log/maknae/audit.jsonl` | created in postinst, not payload | `_maknae:_maknae 0640`, `chattr +a` |

Directories created by `postinst` at their §4.6 modes: `/etc/maknae`
(`root:_maknae 0750`), `/etc/maknae/private` (`root:_maknae 0750`),
`/var/log/maknae` (`_maknae:_maknae 0700`).

### AppArmor, not SELinux

Debian confinement is **AppArmor** (`Depends: apparmor, apparmor-utils`), not
SELinux. The rpm's SELinux `.pp` and fapolicyd trust fragment are **not** shipped
in the deb — both are SELinux-N/A here. The path-attached profile
(`apparmor/usr.bin.maknaed`) mirrors the `.te`: read-only `/etc/maknae/**`,
**append-only** (`a`, never `w`) on `/var/log/maknae/**`, `rw` on the
`/run/maknae` UDS, read of the systemd-decrypted credential under
`/run/credentials/maknaed.service/`, and TCP for Vault egress. A discrete
`maknae_tool` profile is declared (structure-now, near-empty) as the `px`
transition target for the future tool-exec increment; it is inert today (the
daemon spawns no subprocess).

The Vault-port helper (`maknae-selinux-ports.sh`) is shipped for layout parity
with the rpm but is a **SELinux-only no-op on Debian/AppArmor hosts** — AppArmor
does not label ports, so no port step is required before enabling the unit here.

## Build

```bash
# from the repo root, with maknaed + maknae already built into target/release/
bash packaging/deb/build-deb.sh 0.1.0            # -> dist/maknae_0.1.0-1_amd64.deb
bash packaging/deb/build-deb.sh 0.1.0 path/to/bins   # optional explicit bindir
```

`build-deb.sh` fails loudly if either binary is missing. Static verification
(no Debian target host needed):

```bash
lintian dist/maknae_0.1.0-1_amd64.deb
apparmor_parser -Q packaging/deb/apparmor/usr.bin.maknaed   # -Q = parse only
```

`-Q` parse-checks the profile without loading it into the kernel; the load +
enforce-clean run is owed on the Debian 13 host (spec §9).

## Install → enroll → start (in that order)

A fresh install is **not runnable**, so `postinst` neither enables nor starts the
unit — it only runs `systemctl daemon-reload` (and, on upgrade, `try-restart`s a
daemon the operator had already started). **You** enable and start it in the
`systemctl enable --now` step below, *after* `maknae enroll`: the shipped
`authz.yaml` uses `~` patterns and the DAC gate fail-closes until enroll writes
the `principal`. The order is load-bearing:

```bash
sudo apt install -y ./dist/maknae_0.1.0-1_amd64.deb   # pulls apparmor, apparmor-utils
sudo maknae enroll --deployment-id <id>               # provisions daemon cred + principal
# re-login so the operator picks up the `maknae` group membership
sudo systemctl enable --now maknaed.service
maknae ping     # -> pong
maknae whoami   # -> maknae://<id>/plane/cli
```

On **upgrade**, re-run `maknae enroll` before restarting the daemon if the
shipped `maknae.yaml`/`authz.yaml` changed — the same install→enroll→(re)start
rule applies, because the shipped defaults are fail-closed until enrollment.

## Removal

`prerm` clears the append-only bit (file + dir), unloads the AppArmor profile,
and stops/disables the unit. `postrm purge` removes `/etc/maknae` and
`/var/log/maknae` (after clearing `+a`). The accumulated audit trail is
preserved across upgrades (the file is guarded on non-existence and never
shipped as payload).
