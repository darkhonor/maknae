# Maknae Linux packaging — install & operations guide

This directory builds signed Linux packages that install the `maknaed` trust-plane
daemon and the `maknae` operator CLI, the hardened systemd unit, the MAC policies
(SELinux on RHEL/Rocky, AppArmor on Debian), the fapolicyd trust fragment, and the
shipped `/etc/maknae` config defaults.

| Layout | Purpose |
|---|---|
| `common/` | Shared assets both formats install (unit, sysusers, SELinux `.te`/`.fc`, AppArmor, fapolicyd trust, shipped `authz.yaml`/`maknae.yaml`, `maknae-selinux-ports.sh`). |
| `rpm/` | `maknae.spec` + `build-rpm.sh` → `dist/maknae-<ver>-1.<dist>.x86_64.rpm` (RHEL/Rocky). |
| `deb/` | `control` + maintainer scripts + AppArmor profile + `build-deb.sh` → `dist/maknae_<ver>-1_amd64.deb` (Debian). |
| `sign.sh` | Checksums (`SHA256SUMS`) + optional GPG signing (see [Verifying artifacts](#verifying-artifacts)). |
| `isolation-contract.md` | Normative isolation contract (property × profile). |

**Scope this release:** Linux only. macOS packaging (#76), OCI images (#81), and the
Compose/Podman profile are deferred.

---

## Supported targets

| Target | systemd | MAC | Status this release |
|---|---|---|---|
| Debian 13 | 257 | AppArmor | **Full** — install → enroll → serve |
| RHEL / Rocky 10 | 257 | SELinux | **Full** — install → enroll → serve |
| RHEL / Rocky 9 | 252 | SELinux | **Packaging + daemon-seal only** — operator `enroll` deferred to #73 (see [RHEL 9 caveat](#rhel-9-caveat)) |

---

## Install

### RPM (RHEL / Rocky)

```bash
sudo dnf install ./maknae-<ver>-1.el10.x86_64.rpm
```

Installing runs the maintainer scriptlets, which:

- create the `_maknae` service account and the `maknae` operator group (sysusers),
- lay down `/etc/maknae`, `/etc/maknae/private`, and `/var/log/maknae` at their
  normative ownership/modes,
- load the SELinux module (`semodule -i`) and relabel the tree (`restorecon`),
- register the fapolicyd trust fragment (`fapolicyd-cli --update`),
- pre-create the append-only `/var/log/maknae/audit.jsonl`.

### DEB (Debian)

```bash
sudo apt install ./maknae_<ver>-1_amd64.deb
```

The `postinst` performs the equivalent setup and loads the AppArmor profile
(`apparmor_parser -r /etc/apparmor.d/usr.bin.maknaed`).

---

## The mandatory install flow

The package installs the software but does **not** put the daemon into service. The
daemon ships **fail-closed**: the shipped `authz.yaml` uses `~` (home-relative)
patterns that have no meaning until an operator principal exists, so the daemon
refuses to serve until `enroll` writes that principal. Run the full flow, **in this
order**:

```bash
# 1. Install (above).

# 2. SELinux/RHEL hosts ONLY — label your Vault TCP port so the daemon may reach it.
sudo /usr/libexec/maknae/maknae-selinux-ports.sh add <vault-tcp-port>   # default 8200

# 3. Enroll this deployment (writes the sealed daemon credential + the principal).
sudo maknae enroll --deployment-id <id>

# 4. Re-login so your shell picks up the new `maknae` group membership.
#    (Log out/in, or `exec su - $USER`. `id` should now list the `maknae` group.)

# 5. Enable and start the daemon.
sudo systemctl enable --now maknaed
```

### Why step 2 (the Vault port label) is required on SELinux hosts

The SELinux policy grants the daemon `name_connect` **only to a port labeled
`maknae_vault_port_t`** — Vault egress is mandatory but least-privilege, restricted
to the one port you declare. Vault's default `8200` is *not* labeled that way out of
the box, so under enforcement the daemon's connection to Vault is **denied** and it
cannot AppRole-authenticate. The helper labels your port; run it **before**
`systemctl enable --now maknaed`. It is idempotent, and removal is operator-invoked:

```bash
sudo /usr/libexec/maknae/maknae-selinux-ports.sh remove <vault-tcp-port>
```

On Debian/AppArmor hosts the helper is shipped for layout parity but is a no-op —
AppArmor has no port-label model — so step 2 is skipped there.

### Why step 4 (re-login) is required

The UDS the daemon binds is group-`maknae`, mode `0660`. Membership in `maknae` is
what authorizes an operator to talk to the socket, and group membership is only
applied to **new** login sessions. Without re-login your current shell is not yet in
`maknae` and `maknae ping` is refused by socket permissions.

---

## Upgrades

Upgrade with the same tool (`dnf upgrade` / `apt install ./…deb`). **The ordering
rule is identical to a fresh install: enroll (if not already enrolled) before you
restart the daemon.** The shipped `authz.yaml` still carries the `~` patterns, and
the daemon still fail-closes without a `principal`, so a daemon restarted before a
principal exists refuses to serve. The accumulated audit trail in
`/var/log/maknae/audit.jsonl` is preserved across upgrades (it is never replaced by
the package).

---

## Verifying artifacts

Builds are checksummed, and optionally GPG-signed with the published Maknae/Microkosmos
key, by `packaging/sign.sh`. Every build produces `dist/SHA256SUMS`; signed builds add
embedded RPM signatures, a detached `.asc` per `.deb`, and `dist/SHA256SUMS.asc`.

```bash
# 1. Checksums (always present):
cd dist && sha256sum -c SHA256SUMS

# 2. RPM embedded signature (signed builds) — import the public key first:
sudo rpm --import <maknae-public-key.asc>
rpm -Kv maknae-<ver>-1.el10.x86_64.rpm        # expect "digests signatures OK"

# 3. DEB detached signature (signed builds):
gpg --verify maknae_<ver>-1_amd64.deb.asc maknae_<ver>-1_amd64.deb

# 4. Signed checksum manifest (signed builds):
gpg --verify SHA256SUMS.asc SHA256SUMS
```

Unattended builds default to unsigned (`SHA256SUMS` only) so CI never blocks on a
key; see `sign.sh --help`.

---

## RHEL 9 caveat

**On RHEL / Rocky 9 the package installs and the daemon can seal its credential, but
`maknae enroll` cannot complete.** The operator CLI seal uses `systemd-creds --user`,
which requires systemd ≥ 256; RHEL 9 ships systemd 252. RHEL 9 is therefore
**packaging + daemon-seal only this release — operator enroll is deferred to #73.**
The rpm installs cleanly, the SELinux policy loads and runs enforce-clean, and the
daemon's own TPM2 seal works; what is *not* available on el9 is the operator
enroll → serve round-trip. **Debian 13 and RHEL 10 support the full enroll flow.**

---

## Honest limits

- **SELinux tool domain (bin_t):** the tool-exec domain is keyed on `bin_t`, which
  the kernel cannot use to distinguish *which* binary is being executed (`gh` looks
  like any other `bin_t` file). MAC therefore gates only *that* a tool ran, not
  *which* — the DAC layer (`authz.yaml`) is what decides which tool is permitted.
  Per-binary MAC separation is a future tool-exec increment.
- **RHEL 9 operator enroll** — deferred to #73 (see above).
- **macOS / OCI / Compose-Podman** — deferred (#76 / #81 / TBD).
