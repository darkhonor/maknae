# Upgrading Maknae

Each release that needs an action from you lists it here, newest first. Read every entry between your installed version and the new one, and do what each says.

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

The first start after enrolling seeds an empty store and records it on the audit trail. If the daemon refuses to start for any other graph-store reason, see [the kernel graph store refuses to start](runbook.md#the-kernel-graph-store-refuses-to-start).

Uninstalling on macOS keeps the store and its keychain item, as it keeps `/etc/maknae` and the audit trail. A Debian purge removes `/var/lib/maknae`.

---

## `principal.home` is no longer accepted

A host enrolled before #440 may still carry a `home:` line under `principal:` in `/etc/maknae/maknae.yaml`. Current `maknaed` refuses to start while any configuration file carries it, `maknae.yaml` or a `config.d/` member, and exits with code 3. The journal holds:

```text
maknaed: refusing to start: maknae daemon refused to start: the authorization policy could not be loaded: unknown key 'home' in 'principal'
```

Delete the `home:` line from the file that carries it, then restart `maknaed`. The [runbook](runbook.md#3b-upgrading-a-host-whose-principal-carries-home) has the details.
