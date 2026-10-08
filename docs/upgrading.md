# Upgrading Maknae

Each release that needs an action from you lists it here, newest first. Read every entry between your installed version and the new one, and do what each says.

---

## Bindings move to `bindings.yaml` (#496)

Who holds which role, and who is contained, now lives in its own file, `/etc/maknae/bindings.yaml` ([configuration §2.3](configuration.md#23-bindingsyaml)). `authz.yaml` keeps the grants, the denies and the roles, and no longer accepts a `bindings:` key. The deb installs `/etc/maknae/bindings.yaml`, `root:_maknae 0640`, holding `schema_version: 1` and commented examples only. The RPM and the macOS package install that file only on a host with no kernel graph store yet, so **an upgrade of a host that has a store leaves `/etc/maknae/bindings.yaml` absent on RPM and macOS**. Create it before you restart or reload (`/etc/maknae` is root-owned, so nothing else needs holding while you do):

```bash
# RHEL / Rocky
sudo install -m 0640 -o root -g _maknae /usr/share/maknae/bindings.yaml /etc/maknae/bindings.yaml
sudo restorecon /etc/maknae/bindings.yaml
# macOS
sudo install -m 0640 -o root -g _maknae /usr/local/share/maknae/defaults/bindings.yaml /etc/maknae/bindings.yaml
```

While it is absent and the store holds bindings from `authz.yaml`, the daemon refuses to start (exit 3) with `the store holds explicit bindings from authz.yaml; paste the bindings: block into /etc/maknae/bindings.yaml`, once `authz.yaml` no longer carries the block. With no explicit bindings in the store, an absent file is bindings absent and the daemon starts.

**If your `authz.yaml` has no `bindings:` block,** there is nothing to do. The first start records one `graph.transition` (`root-file`) and a `graph.checkpoint` (`transitioned`) at the next store revision, because the store now names `bindings.yaml` as the source of its bindings. Every host writes this pair once.

**If your `authz.yaml` has a `bindings:` block, move it right after upgrading.** The package restarts `maknaed` (RPM `%systemd_postun_with_restart`, the deb's `postinst` `try-restart`, `launchctl kickstart -k` on macOS), and while the block is still in `authz.yaml` the new daemon refuses to start with exit 3:

```text
maknaed: refusing to start: maknae daemon refused to start: the authorization policy could not be loaded: authz policy load refused: authz.yaml no longer carries `bindings:`; move the block unchanged to bindings.yaml in the same directory (docs/upgrading.md)
```

systemd and launchd retry every 5 seconds, and each attempt writes a denied `authz` record to the audit trail, until you move the block. A reload of a daemon that is already running the new release refuses with the same cause, and the running policy stands. To move it:

1. On RPM and macOS, create `/etc/maknae/bindings.yaml` with the commands above if it is absent. Open both files: `sudoedit /etc/maknae/authz.yaml /etc/maknae/bindings.yaml`.
2. Cut the whole `bindings:` block from `authz.yaml` and paste it, unchanged, under `schema_version: 1` in `bindings.yaml`. Save both.
3. Restart: `sudo systemctl restart maknaed` (Linux) or `sudo launchctl kickstart -k system/io.maknae.maknaed` (macOS).

The first start then records one `graph.transition` (`root-file`) and a `graph.checkpoint` (`transitioned`) at the next store revision. Every containment stays, and nothing is released. `policy_sha256` is unchanged, because the block's canonical form is the same in either file.

**Do not delete the block without pasting it.** If you remove it from `authz.yaml` and `bindings.yaml` still has no `bindings:` key, the new daemon refuses to start (exit 3) rather than release every containment and make the enrolled principal admin:

```text
maknaed: refusing to start: maknae daemon refused to start: the authorization policy could not be loaded: the store holds explicit bindings from authz.yaml; paste the bindings: block into /etc/maknae/bindings.yaml
```

Paste the block and start again. Once the store's bindings come from `bindings.yaml`, an edit that leaves `bindings.yaml` without a `bindings:` key is allowed: every binding is dropped and the enrolled principal becomes admin. The edit is recorded as a `graph.identity` record, `uid <n>, the enrolled principal, now holds admin: bindings.yaml has no bindings: key`, plus one release per containment it ends. A `bindings.yaml` deleted over explicit bindings refuses instead ([configuration §2.3](configuration.md#23-bindingsyaml)).

**Do not remove the block from `authz.yaml` and reload the old daemon before upgrading.** To the old daemon that means no bindings: the enrolled principal becomes admin and every containment is released.

**A `bindings.yaml` you created before this release is kept.** dpkg asks whether to keep it, and keeping it is the default; RPM and macOS keep it without asking. Check that it has `schema_version: 1` and is `root:_maknae 0640`.

**Keep your `bindings.yaml` when dpkg asks, on this and every later upgrade.** Answering "install the package maintainer's version" replaces your file with the shipped one, which has no `bindings:` key, and the package then restarts `maknaed`. That is the keyless edit described above: every binding is dropped, the enrolled principal becomes admin, and every containment is released. The start records it (`now holds admin`, and `is no longer contained` for each containment). If it happens, restore your file from dpkg's `bindings.yaml.dpkg-old` and reload.

**A `bindings.yaml` you delete stays deleted across upgrades.** dpkg does not reinstall a conffile you removed, and the RPM and macOS packages create the file only on a host with no kernel graph store. Over explicit bindings the daemon then keeps refusing until you restore the file ([configuration §2.3](configuration.md#23-bindingsyaml)).

**`/etc/maknae` itself is now checked.** Both policy files are read through their directory, which must be owned by root and not group- or other-writable. The packages create it `root:_maknae 0750`, and earlier releases did not check it. A directory changed since then refuses to start (exit 3), naming the directory:

```text
maknaed: refusing to start: maknae daemon refused to start: the authorization policy could not be loaded: authz policy load refused: the directory /etc/maknae holding authz.yaml must be owned by root (uid 0) and not group- or other-writable
```

Restore it with `sudo chown root:_maknae /etc/maknae && sudo chmod 0750 /etc/maknae`, then start again.

**What changes in behaviour.** Three cases that refused the whole policy now affect only one subject. Each is recorded as a `graph.identity` record, counted in `maknae status` and listed in `maknae subject-list`, and the rest of the policy loads:

- a name with no account on the host holds no role (under `adversary`, the name contains nothing);
- a subject listed under a role and under `adversary` is contained;
- one uid under two names in two roles holds no role, unless one of them is `adversary`, when it is contained.

A failed account lookup, as distinct from one that finds no such user, still refuses the whole load. `adversary:` also accepts a numeric id, `- uid: <n>`, which contains that id whether or not an account has it. A reload now reads `authz.yaml` and `bindings.yaml` together, and an invalid `bindings.yaml` refuses the whole reload, including an `authz.yaml` edit made with it. On Linux `maknaed` now starts after `nss-user-lookup.target`.

**Downgrading** to a release before this one: that release reads `bindings:` only from `authz.yaml`. Move the block back into `authz.yaml` before you downgrade, or the downgraded daemon starts with no bindings, makes the enrolled principal admin and releases every containment. That release also refuses the whole policy (exit 3) on what this one decides per subject, so before moving the block back remove every `- uid: <n>` entry, every name with no account on the host, every name listed under a role and under `adversary`, and every uid reached by names in two roles.

---

## Policy edits apply at reload (#489)

Edits to the policy no longer take effect on the next request. `maknaed` now decides from a snapshot of `/etc/maknae/authz.yaml` and `/etc/maknae/bindings.yaml` compiled when it starts, and an edit applies when you reload or restart it:

```bash
sudo systemctl reload maknaed                          # Linux
sudo launchctl kill SIGHUP system/io.maknae.maknaed    # macOS
```

A reload re-reads `authz.yaml` and `bindings.yaml`, and resolves every username in `bindings.yaml`, so adding a user needs no restart. A reload of a file that does not validate is refused, and the running policy stands; the journal and the audit trail name the cause. An invalid policy file at start refuses to start, with exit 3. The [runbook](runbook.md#reload-the-policy) has the details.

The first start after this upgrade migrates the kernel graph store, with no action from you. The trail shows a `graph.migrate` record, the store at its revision + 1, and a `graph.checkpoint`. If you have a `bindings:` block (in `bindings.yaml` since #496), a second transition follows: a `graph.transition` record that seeds those bindings into the store, at revision + 2, and another `graph.checkpoint` ([upgrades migrate the store](runbook.md#upgrades-migrate-the-store)).

---

## Kernel graph store (#488)

`maknaed` now keeps its enforcement state in an encrypted store, and will not start without the key that encrypts it.

**After upgrading, run `sudo maknae enroll` once**, with the same arguments you enrolled with ([runbook Chapter 4 step 3](runbook.md#3-enroll)). It creates the kernel graph key, and only when no key is present: it never rotates an existing one, because a new key cannot read the existing store. Like every re-enroll, it also rotates `maknaed`'s SecretID. Then restart the daemon:

```bash
sudo systemctl restart maknaed                          # Linux
sudo launchctl kickstart -k system/io.maknae.maknaed    # macOS
```

Until you enroll, the daemon does not start, and each platform says so differently.

- **Linux.** systemd refuses the unit before `maknaed` runs, because the unit loads a credential that does not exist yet. `systemctl status maknaed` shows `status=243/CREDENTIALS`, and the journal (`journalctl -u maknaed`) says:

  ```text
  Failed to set up credentials: Protocol error
  Failed at step CREDENTIALS spawning /usr/bin/maknaed
  ```

  Neither line names the file. The missing credential is `/etc/maknae/private/maknaed-graph-key.cred`.
- **macOS.** `maknaed` exits with code 5, and `/usr/local/var/log/maknae/maknaed.err` holds:

  ```text
  maknaed: refusing to start: kernel graph key: no kernel graph key ($CREDENTIALS_DIRECTORY is unset and no keychain pointer is enrolled): run `sudo maknae enroll`
  maknaed: run `sudo maknae enroll` to create the kernel graph key
  ```

**Where the key and the store live:**

| | Linux | macOS |
|---|---|---|
| Key | `/etc/maknae/private/maknaed-graph-key.cred`, a systemd encrypted credential sealed to the TPM2 | System-keychain item `io.maknae.maknaed.graph`, readable only by `/usr/local/bin/maknaed` |
| Store | `/var/lib/maknae/kernel.graph` | `/usr/local/var/db/maknae/state/kernel.graph` |

The first start after enrolling seeds the store from the bindings in `/etc/maknae/bindings.yaml` and records it on the audit trail. If the daemon refuses to start for any other graph-store reason, see [the kernel graph store refuses to start](runbook.md#the-kernel-graph-store-refuses-to-start).

Uninstalling on macOS keeps the store and its keychain item, as it keeps `/etc/maknae` and the audit trail. A Debian purge removes `/var/lib/maknae`.

---

## `principal.home` is no longer accepted

A host enrolled before #440 may still carry a `home:` line under `principal:` in `/etc/maknae/maknae.yaml`. Current `maknaed` refuses to start while any configuration file carries it, `maknae.yaml` or a `config.d/` member, and exits with code 3. The journal holds:

```text
maknaed: refusing to start: maknae daemon refused to start: the authorization policy could not be loaded: unknown key 'home' in 'principal'
```

Delete the `home:` line from the file that carries it, then restart `maknaed`. The [runbook](runbook.md#3b-upgrading-a-host-whose-principal-carries-home) has the details.
