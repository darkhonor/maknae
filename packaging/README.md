# Maknae Linux packaging — install & operations guide

This directory builds Linux packages (checksummed; optionally GPG-signed — the
default build is UNSIGNED, see [Signing](#verifying-signatures)) that install the `maknaed` trust-plane
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
| Debian 13 | 257 | AppArmor | **Packaging + AppArmor-load only** — deb builds/installs, both AppArmor profiles load, §4.6 ownership verified; full enroll → serve → AppArmor-enforce-clean **not yet validated** (#94) |
| RHEL / Rocky 10 | 257 | SELinux | **Full — install → enroll → serve, PROVEN LIVE** (SELinux enforcing, zero AVCs, hands-free reboot) |
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
restart the daemon.** The daemon's boot gate still
requires the `principal` section (#77), so a daemon restarted before a
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
The rpm installs cleanly, the SELinux policy loads and runs enforce-clean (re-validation after #77's home-read vectors: operator pre-merge checklist), and the
daemon's own TPM2 seal works; what is *not* available on el9 is the operator
enroll → serve round-trip. **RHEL 10 supports the full enroll flow (proven live,
enforcing).** Debian 13's `--user` CLI seal works (systemd 257), but its full
enroll → serve → AppArmor-enforce-clean cycle is **not yet validated — deferred to #94**.

---

## Honest limits

- **SELinux tool domain (bin_t):** the tool-exec domain is keyed on `bin_t`, which
  the kernel cannot use to distinguish *which* binary is being executed (`gh` looks
  like any other `bin_t` file). MAC therefore gates only *that* a tool ran, not
  *which* — the discretionary policy layer (`authz.yaml`, decided by the RBAC PDP)
  will decide which tool is permitted when the tool-exec increment lands (#84);
  today it governs the read path (#77). Per-binary MAC separation is a future
  tool-exec increment.
- **#77 home-read relaxation is syntax-validated, not yet serve-time-validated** — four MAC/isolation artifacts changed (`maknaed.service` ProtectHome, `maknae.te` home vectors, the AppArmor profile + local include, the enroll ACL). The .te builds clean under el9 refpolicy and the profile parses clean on trixie; the enforce-clean home-read/home-write-refused acceptance is the operator's pre-merge checklist item.
- **RHEL 9 operator enroll** — deferred to #73 (see above).
- **Debian 13 full enroll → serve → AppArmor-enforce-clean** — deb builds/installs and
  both AppArmor profiles load, but the daemon has not been run under the AppArmor
  profile with a live credential, so serve-time `apparmor="DENIED"` cleanliness is
  **unproven** (the profile may need iteration exactly as the SELinux `.te` did).
  Deferred to #94.
- **SELinux credential-read breadth** — because refpolicy exposes no
  `systemd_read_credentials` interface, `maknaed_t` is granted read over the broad
  `var_run_t` / `init_var_run_t` runtime labels to reach its systemd-decrypted
  credential (not just its own file). Empirically required; narrowing via a private
  credential type + explicit transition is future hardening.
- **Daemon TCP `bind`** — the `.te` grants `maknaed_t` `self:tcp_socket bind` +
  generic-node bind (needed by the Vault client connect as proven on Rocky 10);
  tightening this egress-only daemon to drop listen-capability is future hardening.
- **macOS / OCI / Compose-Podman** — deferred (#76 / #81 / TBD).
