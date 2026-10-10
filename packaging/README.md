# Maknae packaging — install & operations guide

This directory builds Linux packages (checksummed; optionally GPG-signed — the
default build is UNSIGNED, see [Verifying artifacts](#verifying-artifacts)) that install the `maknaed` trust-plane
daemon, the `maknae` operator CLI and the `maknae-egress` egress deputy, their hardened systemd
units (`maknaed.service`, `maknae-egress.service`, `maknae-egress.socket`), the opt-in
sync-back units (`maknae-policy-sync.path`, `maknae-policy-sync.service`, shipped
disabled, see [Sync back](#sync-back-opt-in)), the MAC policies
(SELinux on RHEL/Rocky, AppArmor on Debian), the fapolicyd trust fragment, and the
shipped `/etc/maknae` config defaults. `packaging/macos/` builds the Apple Silicon `.pkg` under its own
lifecycle; see [packaging/macos/README.md](macos/README.md) for the macOS lifecycle: config
defaults first-install-only, both jobs ship `launchctl disable`d, and the operator runs
`sudo maknae enroll` (which writes `/etc/maknae/egress-bounds.yaml`), then starts both jobs.

| Layout | Purpose |
|---|---|
| `common/` | Shared assets both formats install (units, sysusers, SELinux `.te`/`.fc`, fapolicyd trust, shipped `authz.yaml`/`bindings.yaml`/`maknae.yaml`, `maknae-selinux-ports.sh`). |
| `rpm/` | `maknae.spec` + `build-rpm.sh` → `dist/maknae-<ver>-1.<dist>.x86_64.rpm` (RHEL/Rocky). |
| `deb/` | `control` + maintainer scripts + AppArmor profile + `build-deb.sh` → `dist/maknae_<ver>-1_amd64.deb` (Debian). |
| `sign.sh` | Checksums (`SHA256SUMS`) + optional GPG signing (see [Verifying artifacts](#verifying-artifacts)). |
| `isolation-contract.md` | Normative isolation contract (property × profile). |

**Scope this release:** Linux (deb, rpm) and macOS on Apple Silicon (a `.pkg`,
`packaging/macos/`; install → enroll → serve proven on a notarized Developer ID package). OCI
images (#81) and the Compose/Podman profile are deferred.

---

## Supported targets

| Target | systemd | MAC | Status this release |
|---|---|---|---|
| Debian 13 | 257 | AppArmor | **Packaging + AppArmor-load only** — deb builds/installs, both AppArmor profiles load, §4.6 ownership verified; full enroll → serve → AppArmor-enforce-clean **not yet validated** (#94) |
| RHEL / Rocky 10 | 257 | SELinux | **Full — install → enroll → serve, PROVEN LIVE** (SELinux enforcing, zero AVCs, hands-free reboot) |
| RHEL / Rocky 9 | 252 | SELinux | **Packaging; enroll expected, not yet run live** — enroll no longer needs `systemd-creds --user` (#73) (see [RHEL 9 caveat](#rhel-9-caveat)) |
| macOS 26, Apple Silicon | — (launchd) | none | **Full — install → enroll → serve, PROVEN LIVE** on a notarized Developer ID package — smoke phase 1 on the `macos-26` runner, smoke phase 2 with 0 failures, and the first-provider walkthrough passed with `transport.read_timeout_ms: 60000` (#413). See [packaging/macos/README.md](macos/README.md) |

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
daemon ships **fail-closed**: its boot gate requires the `principal` section (#77),
so the daemon refuses to start until `enroll` writes that principal. Run the full
flow, **in this order**:

```bash
# 1. Install (above).

# 2. SELinux/RHEL hosts ONLY — label your Vault TCP port so the daemon may reach it.
sudo /usr/libexec/maknae/maknae-selinux-ports.sh add <vault-tcp-port>   # default 8200

# 3. Enroll this deployment (writes the sealed daemon credential, the Egress
#    Daemon's sealed seal key and its published seal.pub, egress-bounds.yaml
#    and the principal).
sudo maknae enroll --deployment-id <id>

# 4. Re-login so your shell picks up the new `maknae` group membership.
#    (Log out/in, or `exec su - $USER`. `id` should now list the `maknae` group.)

# 5. Enable and start the daemon.
sudo systemctl enable --now maknaed

# 6. With providers authorized (the `providers:` section of maknae.yaml): the
#    egress deputy's SOCKET unit is preset-disabled, and without it every
#    permitted prompt is refused as "egress backend not ready".
sudo systemctl enable --now maknae-egress.socket

# 7. Each user logs in to Vault (userpass) before any `maknae` command.
maknae login
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
the package). On a host enrolled before #440, the upgraded daemon refuses to start until `principal.home` is removed; see
[runbook §3b](../docs/runbook.md#3b-upgrading-a-host-whose-principal-carries-home).

---

## Sync back (opt-in)

`maknaed` keeps a mirror of the bindings it enforces in its state directory
(`/var/lib/maknae/bindings.mirror.yaml`; macOS
`/usr/local/var/db/maknae/state/bindings.mirror.yaml`). `sudo maknae policy sync`
installs it as `/etc/maknae/bindings.yaml`; `--check` reports what it would change.
Run by hand, it never signals the daemon: reload `maknaed` afterwards.

Both packages install a watcher that does this automatically, and ship it
**disabled**. The deb and rpm install `maknae-policy-sync.path` and
`maknae-policy-sync.service` with a preset
(`/usr/lib/systemd/system-preset/80-maknae.preset`) that disables both, and never
enable them. The macOS package installs the launchd job `io.maknae.policy-sync`
and `launchctl disable`s it on a fresh install and on an upgrade that adds it.
The watcher installs only tightenings, a removed role binding or an added
containment; a grant or a release exits 5, fails the run and needs
`sudo maknae policy sync` on a terminal. Roles are independent, so moving
an entry from `admin` to `user` is a grant of `user`. The watcher restores
`bindings.yaml` only when it is missing; a file with no `bindings:` key, the
shipped file included, exits 5 and needs a manual sync on a terminal. To opt in:

```bash
sudo systemctl enable --now maknae-policy-sync.path          # Linux
sudo launchctl enable system/io.maknae.policy-sync && \
  sudo launchctl bootstrap system /Library/LaunchDaemons/io.maknae.policy-sync.plist   # macOS
```

When the mirror changes, the watcher runs `maknae policy sync` as root and, after
an install, reloads `maknaed` (`systemctl reload maknaed.service`; on macOS
`launchctl kill SIGHUP system/io.maknae.maknaed`) so the daemon adopts the file.
That reload also applies any `authz.yaml` edit not yet reloaded. A sync with
nothing to install does not reload, and a refused sync (a conflict included, since
the watcher has no terminal to prompt on) fails the run without reloading. The CLI
runs unconfined, as `reseed` does (a dedicated confinement policy is #510).

The shipped preset disables both units, so `systemctl preset-all` or
`systemctl preset maknae-policy-sync.path` turns a Linux opt-in back off. To keep
it, add a preset that sorts earlier, for example
`/etc/systemd/system-preset/50-maknae-local.preset` holding
`enable maknae-policy-sync.path`. The macOS job logs to
`/Library/Logs/maknae-policy-sync.log` and runs `/usr/local/bin/maknae`; without
the CLI each run exits 127 and installs nothing. See the
[runbook](../docs/runbook.md#sync-live-identity-changes-back-to-bindingsyaml) for
the merge, the exit codes and the refusals.

Removing `/etc/maknae/bindings.yaml`, or its `bindings:` key, does not reset the
bindings: `maknaed` keeps enforcing the bindings it holds, and `maknae policy sync`
restores the file. Returning to the shipped default (the enrolled administrator as
the only `admin`) takes `sudo maknae reseed`.

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

**On RHEL / Rocky 9 `maknae enroll` is expected to complete now that the
`systemd-creds --user` step is gone, but it has not yet been run live, and neither has
the enroll → serve round trip.** Enroll seals the daemon's SecretID and the Egress Daemon's seal
key with the system `systemd-creds` (TPM2), which systemd 252 provides; the
`systemd-creds --user` step that needs systemd ≥ 256 served only the CLI SecretID,
which no longer exists (#73). On el9 `maknae login` keeps the user's Vault token in
the `0600` file `~/.maknae/maknae-vault-token`, written through `maknae-io`, because
`systemd-creds --user` is unavailable there. The rpm installs cleanly and the SELinux
policy loads and runs enforce-clean (the #365 home-access policy is measured on el10).
**RHEL 10 supports the full enroll flow (proven live, enforcing).** Debian 13's full
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
- **Home access (#365)** — the daemon holds `getattr` and receipt-only `ioctl` over home content (`maknae.te`), no AppArmor home rule, and no ACL; `ProtectHome=read-only`. Serve-time enforce-clean on Rocky 10 (SELinux enforcing, a `0700` home, each kept permission shown load-bearing). On Debian 13 a probe confined by the shipped profile showed AppArmor does not mediate these operations; a full AppArmor serve is the Debian bullet below.
- **RHEL 9 enroll → serve** — enroll expected to complete (#73), neither run live yet (see above).
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
- **OCI / Compose-Podman** — deferred (#81 / TBD). macOS's platform deltas are stated in
  [packaging/macos/README.md](macos/README.md).

## Shipping the audit trail to a SIEM

Maknae performs **no off-host audit egress** ([ADR-0019](../design/adr/ADR-0019-audit-record-model.md), amended 2026-09-05). The daemon writes two local sinks — the `_maknae`-owned append-only JSONL and a best-effort system-log mirror (journald on Linux, the unified log on macOS) — and off-host offload is the deployer's log agent tailing the JSONL.

This satisfies AU-9(2), which requires audit storage on a physically separate system, **not** that Maknae be the transport. A home-lab deployment therefore needs no SIEM at all: zero configuration, zero cost.

### Granting the agent read access

The audit directory is **`0700 _maknae:_maknae`** and the file is `0640 _maknae:_maknae`. **No group membership grants access** — no group can traverse a `0700` directory — and `maknae` is the *operator* group for the daemon's UDS, not a log-reader group. [`maknae.sysusers`](common/maknae.sysusers) forbids on-disk cross-membership between the two identities, so do **not** add your agent to `maknae`.

The lockdown is deliberate. Your agent is granted exactly what it needs, with POSIX ACL entries, and the accounts that get them are declared by root in `maknae.yaml`, never chosen by the package:

```yaml
audit:
  readers: [vector]
```

`audit.readers` names accounts only, never groups. `sudo maknae audit-readers` reads `/etc/maknae/maknae.yaml`, not the accepted baseline, and prints the validated list, one name per line; the grant therefore follows the file, and a reader added there is granted by the next package hold or the runbook block before any `maknae baseline-accept`, which records the list and runs the same account check. It refuses the whole list, naming the account, if any entry is missing from the directory, is `root` or uid 0, has a uid below 100, is `nobody` (65534, or -2 on macOS), is `_maknae` or `_maknae-egress`, or has `_maknae`'s group as a primary or supplementary group.

Each reader needs two entries: `x` on the directory and `r` on each trail file.

- **The directory entry** is applied by the package on every install, configure and upgrade. The package holds the directory as root, which removes every ACL entry on it, and then restores `u:<reader>:x` for each declared reader before it hands the directory back. It does this with `maknaed` still running. If `maknae audit-readers` refuses, the package grants no one, prints the reason, and the install still succeeds. On Debian and the Red Hat family the package gives the helper 60 seconds (`timeout`), so an account directory that does not answer cannot hold the install, and the directory, indefinitely; an elapsed helper is handled as a refusal. macOS has no `timeout` by default, so there the helper is not bounded. On the Red Hat family, a granted reader makes the directory's group bits show the ACL mask, so `rpm -V maknae` reports `M` on `/var/log/maknae` for as long as a reader is granted; that is expected. `rpm -V maknae` also reports `M` on `/etc/maknae`, because the package grants the egress account read on it. Do not "fix" it with `rpm --setperms` or `rpm --restore`: either resets the mode to `0700`, which leaves the reader's entry listed but ineffective until the next package `%post` restores it.
- **The file entry** is applied by the block below, with `maknaed` stopped. The package never touches it. A trail file is append-only (`chattr +a`), and the kernel refuses any write-xattr operation on an append-only inode: `setfacl` returns `Operation not permitted`, and `CAP_LINUX_IMMUTABLE` does not bypass it. So the flag must be lifted while the entry is granted. On Debian nothing else keeps the trail append-only while the flag is lifted, and a running daemon holds the file open for writing.

So stop `maknaed` first. Then hold the directory as root, so that the daemon account cannot swap a trail for a link to another file while root acts on it, and so that `maknaed` cannot start and open a trail until the block hands the directory back. Holding it means taking it to `root:root`, removing every ACL entry and setting `0700`, and checking all three before acting: ownership alone keeps any ACL entry or write bit the daemon account left. `maknae audit-readers --stopped` refuses while `maknaed` runs. The block grants every declared reader read access to every regular, single-link `*.jsonl` in the directory, which covers a moved trail as well as `audit.jsonl`:

```bash
sudo systemctl stop maknaed.service
sudo bash -eu <<'GRANT'
d=/var/log/maknae
[ -d "$d" ] && [ ! -h "$d" ] || { echo "$d is not a directory" >&2; exit 1; }
chown root:root "$d"
setfacl -P -b "$d"
chmod 0700 "$d"
acl="$(getfacl -P -s -p "$d")"
[ "$(stat -c '%u %g %a' "$d")" = "0 0 700" ] && [ -z "$acl" ] || { echo "$d is not root:root 0700 with no ACL; it is left root-owned" >&2; exit 1; }
readers="$(/usr/bin/maknae audit-readers --stopped)" || { echo "audit.readers not applied; $d is left root-owned" >&2; exit 1; }
for f in "$d"/*.jsonl; do
    [ -f "$f" ] && [ ! -h "$f" ] && [ "$(stat -c %h "$f")" = 1 ] || continue
    chattr -a "$f"
    for r in $readers; do setfacl -P -m "u:$r:r" "$f" || { chattr +a "$f"; exit 1; }; done
    chattr +a "$f"
    lsattr -d "$f" | cut -c6 | grep -qx a || { echo "$f is not append-only; $d is left root-owned" >&2; exit 1; }
done
for r in $readers; do setfacl -P -m "u:$r:x" "$d"; done
chown -h _maknae:_maknae "$d"
GRANT
sudo systemctl start maknaed.service
```

On macOS the block clears and restores the flag the trail carries: `sappnd` on a moved trail, `uappnd` on the default `audit.jsonl` (#414):

```bash
sudo launchctl bootout system/io.maknae.maknaed
sudo bash -eu <<'GRANT'
d=/var/log/maknae
[ -d "$d" ] && [ ! -L "$d" ] || { echo "$d is not a directory" >&2; exit 1; }
chown 0:0 "$d"
chmod -N "$d"
chmod 0700 "$d"
[ "$(stat -f '%u %g %Lp' "$d")" = "0 0 700" ] && [ "$(ls -led "$d" | wc -l)" -eq 1 ] || { echo "$d is not root 0700 with no ACL; it is left root-owned" >&2; exit 1; }
readers="$(/usr/local/bin/maknae audit-readers --stopped)" || { echo "audit.readers not applied; $d is left root-owned" >&2; exit 1; }
for f in "$d"/*.jsonl; do
    [ -f "$f" ] && [ ! -L "$f" ] && [ "$(stat -f %l "$f")" = 1 ] || continue
    case "$(stat -f %Sf "$f")" in
        *sappnd*) flag=sappnd ;;
        *uappnd*) flag=uappnd ;;
        *) echo "$f is not append-only; $d is left root-owned" >&2; exit 1 ;;
    esac
    chflags "no$flag" "$f"
    for r in $readers; do chmod +a "user:$r allow read" "$f" || { chflags "$flag" "$f"; exit 1; }; done
    chflags "$flag" "$f"
    stat -f %Sf "$f" | grep -q "$flag" || { echo "$f is not flagged $flag; $d is left root-owned" >&2; exit 1; }
done
for r in $readers; do chmod +a "user:$r allow search" "$d"; done
chown -h _maknae:_maknae "$d"
GRANT
sudo launchctl bootstrap system /Library/LaunchDaemons/io.maknae.maknaed.plist
```

`setfacl -P` never follows a symbolic link, and the block refuses unless each trail carries its append-only flag again. If the block refuses, the directory stays root-owned and `maknaed` cannot open its trail; do not start it until you have worked through [The package refuses the audit trail](../docs/runbook.md#the-package-refuses-the-audit-trail).

This grants read and nothing else: no write, no directory listing beyond traversal, and the `0700` default stays in place for everyone else. Run the block again after you add a reader to `audit.readers`.

**Verify access, not the ACL entry:**

```bash
sudo -u vector test -r /var/log/maknae/audit.jsonl && echo "agent can read"
```

That distinction is not pedantry. The package restores the directory entry on every upgrade, but if `maknae audit-readers` refused, the directory has no entry for the reader. The entry on the file is still there, but the reader cannot reach the file:

```
after the grant           : /var/log/maknae  user:vector:--x   -> test -r  READ OK
after a refused re-grant  : /var/log/maknae  (no ACL entries)  -> test -r  READ DENIED
```

So `getfacl` on the file looks correct on a grant that no longer works. **Troubleshoot with `getfacl … | grep effective` and the `test -r` probe above**, never with "the entry is there, so DAC is fine."

**Two things that will bite you if you skip them:**

- **The ACL does not survive the file being recreated.** The package creates `audit.jsonl` only when it is absent. A restore or manual rotation that recreates it drops the ACL — re-apply it with the same procedure.
- **On an SELinux host, DAC is necessary but not sufficient.** The sink is typed `maknae_audit_t` via `logging_log_file()` ([`maknae.te`](common/maknae.te)), i.e. a generic log-file type. A *confined* agent domain reads it only if its own policy calls `logging_read_generic_logs()`; an unconfined agent is unaffected. Check `ausearch -m AVC` **only after** `test -r` confirms DAC is granted.

### Agent configurations

**Vector** — `/etc/vector/vector.yaml`:
```yaml
sources:
  maknae_audit:
    type: file
    include: ["/var/log/maknae/audit.jsonl"]
transforms:
  parse:
    type: remap
    inputs: ["maknae_audit"]
    source: '. = parse_json!(.message)'
```

**Fluent Bit** — `/etc/fluent-bit/fluent-bit.conf`:
```ini
[INPUT]
    Name    tail
    Path    /var/log/maknae/audit.jsonl
    Parser  json
    Tag     maknae.audit
```

**rsyslog** (`imfile`) — `/etc/rsyslog.d/maknae.conf`:
```
module(load="imfile")
input(type="imfile"
      File="/var/log/maknae/audit.jsonl"
      Tag="maknae-audit"
      Severity="info")
```

### Or ship the journal instead — zero configuration, with one cost (LINUX ONLY)

The mirror needs no filesystem access at all (the standard `systemd-journal` reader story), and carries the full canonical record in `MAKNAE_RECORD`:

```bash
journalctl -t maknaed MAKNAE_OUTCOME=deny -o json --all
```

Filterable fields: `MAKNAE_ACTION`, `MAKNAE_OUTCOME`, `MAKNAE_SUBJECT`, `MAKNAE_PRIMARY`. (`--all` matters: systemd renders fields at or over 4096 bytes as `null` without it, and `au3_1` is deployer-controlled.)

`MAKNAE_PRIMARY` names which primary-sink condition produced the mirrored copy. `ok` means the record is durable in the JSONL. `write-unconfirmed` means the write may have landed, so check the JSONL. `refused-breaker-open` and `refused-at-capacity` mean the primary never attempted the write, so nothing was written and a trail reconstructed from the JSONL alone is incomplete for those entries. `write-failed` means the write or its durability sync failed, so the record (or partial bytes) may be present but is not confirmed durable.

> **On macOS this section does not apply.** The mirror there is a `syslog(3)` line in the **unified log**, whose store (`/var/db/diagnostics`) is `drwxr-x--- root:admin`. A log agent would need `admin` to read it — a grant not to recommend for a log tailer — so there is no "ship the journal" path on darwin. That restriction is a **security property, not a limitation**: `_maknae` can write to the unified log and can never read or modify it, so the daemon cannot rewrite the trail it emitted. **On macOS the JSONL under the ACL procedure above is the offload path, and the unified-log copy is a tamper-resistant second record rather than a shipping surface.** One further asymmetry to carry into any tooling: the macOS line is undelimited, so it must be **parsed** — the structured prefix, then everything after the FIRST `MAKNAE_RECORD=` — never grepped whole the way `journalctl MAKNAE_OUTCOME=deny` matches a real field (ADR-0019, #222 amendment statement 5).

> **The journald mirror is best-effort and drops records under backpressure** (a full journald buffer returns `EAGAIN` and the record is discarded). It is an operational convenience, **not** the AU-9(2) offload path — that is the durable JSONL, read via the ACL above. Do not rest a compliance claim on the journal copy.

> **`audit.siem` is not implemented.** The key is reserved for a future native export seam ([#223](https://github.com/darkhonor/maknae/issues/223)). Setting it makes `maknaed` **refuse to start**, with exit code 4 — deliberately: a control an operator believes is running is worse than one they know is absent. Use a log agent, as above.
