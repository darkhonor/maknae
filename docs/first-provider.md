# Your first model provider

This walkthrough connects Maknae to one model provider, so that `maknae agent` can hold a conversation: read a file, write a file, and answer you. Every step of that conversation is decided by the kernel and recorded before it happens.

It is written for a person doing this for the first time. For every key and every rule, see the [configuration reference](configuration.md) (§6.1 and §9.3). For the full acceptance procedure, including custody and SELinux checks, see [runbook Chapter 4](runbook.md).

The macOS steps are written from the shipped package; the walkthrough on a Mac is pending the macOS walkthrough acceptance (#242). On a default macOS home (`0750`), the daemon resolves your home via `getattrlist`, which needs no permission on the home itself (measured with a `000` directory the caller owns); resolving and booting on a default home as `_maknae` is pending the macOS acceptance run (#76).

## What you need first

- **A Linux host with the Maknae package installed and enrolled** (`sudo maknae enroll`; runbook Chapter 4, steps 1–3). Run enroll from a direct login whose `id -Z` shows `unconfined_u`, not from `sudo su` out of a confined account.
- **Or a Mac on Apple Silicon** with the **Developer ID-signed** Maknae `.pkg` installed (`sudo installer -pkg Maknae-<version>-arm64.pkg -target /`) and enrolled with `sudo maknae enroll` (the same flags as Linux; runbook Chapter 4, step 3). The release workflow's package is ad-hoc signed. The repository documents no signed-build procedure, and no signed release exists yet; [packaging/macos/README.md](../packaging/macos/README.md#building-a-signed-package) *Building a signed package* states what such a build requires.
  - **What enroll checks.** Enroll refuses unless `maknae`, `maknaed` and `maknae-egress` are root-installed and signed with Developer ID by one team, with Hardened Runtime and no entitlements (ADR-0018 decision 6).
  - **The development-build refusals.** A `maknae` built with `cargo` and run from your own `target/` directory is refused first, at the root-install check: enroll prints `Enrollment preflight check failed`, then `Enrollment failed: <path> could be replaced by a non-root user (…); the keychain item would trust whatever sits there`. An installed ad-hoc package passes that check and is refused at the Developer ID check, on `maknae` itself: enroll prints `Enrollment preflight check failed`, then `Enrollment failed: /usr/local/bin/maknae is not a Developer ID release build of this team (no team identifier); the keychain item would trust it (ADR-0018 decision 6)`.
  - **`--insecure-plaintext-secret`** is refused on macOS.
  - **Afterwards,** log out and back in.
- **An API key** for an OpenAI-compatible endpoint.
- **A Vault** with a KV v2 mount that the `maknae-egress` role can read. The defaults this walkthrough uses come from `deploy/vault-pki`: mount `maknae-kv`, keys under `maknae/providers`. If your Vault uses other names, use yours everywhere below. Nothing checks that they match until the first prompt.

## 1. Put the key in Vault

On a machine whose Vault token may write the path, not on the Maknae host:

```bash
read -rsp 'API key: ' KEY && echo && [ -n "$KEY" ] && printf %s "$KEY" | vault kv put maknae-kv/maknae/providers/openai api-key=-; unset KEY
```

The key never touches the Maknae host's disk. Only the egress deputy reads it, from Vault, under its own identity. `printf %s` keeps a trailing newline out of the stored value.

## 2. Tell the deputy where keys live

```bash
sudo tee /etc/maknae/egress-bounds.yaml >/dev/null <<'EOF'
kv_mount: maknae-kv
key_vault_path_prefix: maknae/providers
vault:
  addr: https://vault.example.net:8200
EOF
sudo chown root:root /etc/maknae/egress-bounds.yaml
sudo chmod 0644 /etc/maknae/egress-bounds.yaml
sudo restorecon -v /etc/maknae/egress-bounds.yaml
```

On macOS: the same `sudo tee`, then:

```bash
sudo chown root:wheel /etc/maknae/egress-bounds.yaml
sudo chmod 0644 /etc/maknae/egress-bounds.yaml
```

There is no `restorecon`: macOS has no SELinux. The file must be owned by root and not writable by group or other; its group is not checked.

The prefix bounds every key path the deputy will read: a provider whose path is not beneath it is refused at boot.

## 3. Register the provider

```bash
sudo install -d -m 0750 -o root -g _maknae /etc/maknae/config.d
sudo tee /etc/maknae/config.d/10-provider.yaml >/dev/null <<'EOF'
provider:
  name: openai
  endpoint: https://api.openai.com/v1/chat/completions
  model: gpt-5.6-luna
  key_vault_path: maknae/providers/openai
  key_field: api-key
  reasoning_effort: none
EOF
sudo chown root:_maknae /etc/maknae/config.d/10-provider.yaml
sudo chmod 0640 /etc/maknae/config.d/10-provider.yaml
sudo restorecon -Rv /etc/maknae
```

On macOS: the same commands without `restorecon`:

```bash
sudo install -d -m 0750 -o root -g _maknae /etc/maknae/config.d
# then the same `sudo tee` as above, and:
sudo chown root:_maknae /etc/maknae/config.d/10-provider.yaml
sudo chmod 0640 /etc/maknae/config.d/10-provider.yaml
```

- **`endpoint`** is the full chat-completions URL, sent exactly as written.
- **`key_vault_path`** is relative to the mount, with no `data/`, and must sit beneath the prefix from step 2.
- **`key_field`** is the field name inside the Vault secret.
- **`reasoning_effort`** is optional. Some models need it: `gpt-5.6-luna` refuses the agent's tools unless it is `none`. Leave it out if your model does not need it.
- **Root owns this file** on purpose. The agent runs as you, so you cannot redirect where its content goes by editing your own files.
- **The daemon's prompt cap**, `transport.prompt_max_bytes` in `/etc/maknae/maknae.yaml`, defaults to 1 MiB. That carries a context window of up to about 174,000 tokens. For a larger window, raise it to `context_tokens × 6` (at most 16 MiB). `sudo maknae enroll` rewrites this file, so after any re-enroll, set it again.
- **On macOS, `/etc/maknae/maknae.yaml` already has a `transport:` block:** enroll writes `transport.socket_path` there. If you raise `transport.prompt_max_bytes` here, add it under that existing block, not as a second `transport:` key — a repeated top-level key refuses the whole file to load with `duplicate config key 'transport' at LINE:COL`, and `maknaed` restarts every 5 s without starting.

Then declare the model's context window in **your own** configuration. `maknae agent` will not start without it:

```bash
cat >> ~/.maknae/maknae.yaml <<'EOF'
provider:
  context_tokens: 128000   # your model's context window, in tokens
  output_tokens: 16000     # optional: the reply cap
EOF
```

- **`sudo maknae enroll` rewrites this file;** after any re-enroll, append this block again.
- **On macOS, enroll also writes a `transport:` block into it** (the daemon's socket path). Put any other `transport` key, such as `prompt_max_bytes`, under that block: a second `transport:` key makes the whole file refuse to load.

Use the window your provider documents for your model. The agent warns at 80% and 95% of it and stops before a turn would exceed it. `docs/configuration.md` §6.1.1 has the details.

## 4. Allow the prompt

Nothing may reach a model until policy says so. Append a grant to the policy:

```bash
sudo tee -a /etc/maknae/authz.yaml >/dev/null <<'EOF'
roles:
  admin:
    allow: ["session.prompt"]
destinations:
  admin:
    allow: ["provider:openai"]
EOF
```

The enrolled operator resolves to the `admin` role when the policy has no `bindings:`. `provider:openai` is `provider:` followed by the `name` from step 3. The policy is re-read on every request.

## 5. Start

```bash
sudo systemctl enable --now maknae-egress.socket
sudo systemctl restart maknaed
maknae ping          # pong
```

Restart the daemon, not just enable it: the provider is registered at boot.

On macOS, both jobs ship `launchctl disable`d. This start works whether or not you already followed the hints enroll printed:

```bash
for label in io.maknae.maknae-egress io.maknae.maknaed; do
  if sudo launchctl print "system/$label" >/dev/null 2>&1; then
    sudo launchctl kickstart -k "system/$label"
  else
    sudo launchctl enable "system/$label"
    sudo launchctl bootstrap system "/Library/LaunchDaemons/$label.plist"
  fi
done
sleep 5
sudo launchctl print system/io.maknae.maknaed | grep -E 'state =|last exit code'
maknae ping          # pong
```

- **Why the loop checks first.** `launchctl print` exits 0 for a loaded job and 113 for an unknown one; the package's own uninstall and install scripts rely on that convention, and it was not re-measured for this page. A second `bootstrap` of a loaded job errors: that is known launchctl behaviour, not measured here. `kickstart -k` restarts a loaded job, which is how the daemon picks up the provider.
- **The home check comes first.** `maknaed` checks the operator's home before it reads the keychain or records posture (`authz_boot_gate`, ahead of the credential read). It resolves the home via `getattrlist`, which needs search permission on the directories above the home and none on the home itself (measured with a `000` directory the caller owns); resolving and booting on a default home (`0750`, group `staff`) as `_maknae` is pending the macOS acceptance run (#76).
- **`pong`.** `maknae ping` printing `pong` is pending the macOS acceptance run (#76).
- **The posture record.** On a boot that gets past the home check, the boot's posture record reads `code_bound`:
  ```bash
  sudo jq -c 'select(.action=="posture") | .outcome.posture' /var/log/maknae/audit.jsonl | tail -n 1
  ```
  `jq` ships at `/usr/bin/jq` on macOS 26 (measured on macOS 26.6.2).
- **The posture warning.** On a boot that reaches the credential read, `maknaed.err` also gets `maknaed: warning: this boot's credential posture is not hardware-root-of-trust sealed`. That is expected on macOS: the System keychain is not a hardware root of trust (ADR-0018 decision 6).
- **A refused boot** restarts every 5 seconds without end, so read `last exit code` rather than waiting for the job to stop.

## 6. Talk to it

Paths must be absolute, and the shipped policy lets the agent write only under `~/projects/`:

```bash
mkdir -p ~/projects/hello
printf 'Maknae is a security kernel for AI agents.\n' > ~/projects/hello/input.txt
maknae agent "Read $HOME/projects/hello/input.txt, write a one-sentence summary of it to $HOME/projects/hello/output.txt, then tell me what you wrote."
cat ~/projects/hello/output.txt
```

The answer arrives with exit `0`. A stop prints `maknae agent: stopped: …` and exits `2`.

To run it again, first `rm ~/projects/hello/output.txt`. The agent may replace only a file it has read in the same conversation, so a re-run that meets the first run's `output.txt` is told to read it first: it reads it, then writes, and §7 shows one extra `fs.read` and one `fs.write` ending `ReportedPathChanged` with no effect (and more records than §7's list, so widen its `tail`).

## 7. See what it did

```bash
sudo jq -c 'select(.action=="session.prompt" or .action=="fs.read" or .action=="fs.write") | {ts, action, object, result: .outcome.result, status: (.egress.status // .mutation.status)}' /var/log/maknae/audit.jsonl | tail -n 12
```

The query is the same on macOS.

A read-then-write conversation shows:
- a `session.prompt` pair (`IntentOnly`, then `Sent`) for each model turn;
- an `fs.read` intent, then its reported completion;
- an `fs.write` intent, then its reported completion.

The intent is written before the action, every time. `content_length` on each prompt intent is exactly how much left the host.

## When it does not work

Where a row below names `systemctl` or `journalctl`, it also gives the macOS form. The daemon writes to `/usr/local/var/log/maknae/maknaed.err` (`sudo tail /usr/local/var/log/maknae/maknaed.err`) and the deputy to `/usr/local/var/log/maknae-egress/maknae-egress.err`. `sudo` is required: their directories are `root:_maknae 0750` and `root:_maknae-egress 0750`, and the operator is in neither group.

| What you see | Why | Fix |
|---|---|---|
| In the trail, `session.prompt` is denied with reason `egress backend not ready` | the deputy's socket is not running | `sudo systemctl enable --now maknae-egress.socket`; on macOS, step 5's loop |
| In the trail, `session.prompt` is denied with reason `no provider registered for session.prompt` | the daemon booted before the provider file existed | `sudo systemctl restart maknaed`; on macOS, `sudo launchctl kickstart -k system/io.maknae.maknaed` |
| In the trail, `session.prompt` is denied with reason `role admin: no capability entry for session.prompt` | the policy has no grant | step 4 |
| `maknaed` will not start: `section 'provider' must come from a root-owned, non-group/other-writable source` | the provider file or its directory is writable by someone other than root | step 3's owner and mode |
| `maknaed` will not start: `… is outside the egress grant prefix …` | `key_vault_path` is not beneath `key_vault_path_prefix` | make the path sit under the prefix |
| The agent stops; the prompt outcome is `OutcomeUnknown`; `journalctl -u maknae-egress` (on macOS, `sudo tail /usr/local/var/log/maknae-egress/maknae-egress.err`) shows `provider credential unavailable` | the deputy could not read the key from Vault: wrong mount, path or field, or its Vault policy does not allow the read | check steps 1–3 against your Vault |
| The agent stops; `journalctl -u maknae-egress` (on macOS, `sudo tail /usr/local/var/log/maknae-egress/maknae-egress.err`) shows `provider answered 400 (conversation …): …` | the provider rejected the request's shape | the text after the colon is the provider's own reason, with the key masked. For `gpt-5.6-luna` it is the missing `reasoning_effort: none`; a server that names `max_completion_tokens` as unsupported needs `output_tokens_field: max_tokens` in step 3's file |
| `maknae agent` will not start: `provider.context_tokens is required by maknae agent` | your own configuration does not declare the window, or a re-enroll rewrote it | step 3's `~/.maknae` block (append it again after any re-enroll) |
| `maknae agent: stopped: the conversation has reached the declared context budget; compaction arrives with #171` | the next turn would exceed the window you declared | start a new conversation, or declare the larger window your model has |
| `maknae agent: stopped:` with a connection error, on a long conversation | the daemon's prompt cap is below your loop's, so the daemon refused the frame and closed the connection | raise the daemon's `transport.prompt_max_bytes` (step 3; on macOS, under the existing `transport:` block — a second `transport:` key refuses the file with `duplicate config key 'transport' at LINE:COL`) |
| `maknae agent: stopped: the conversation has reached the platform's frame bound` | your own `transport.prompt_max_bytes` in `~/.maknae` is smaller than your window needs; or, with none set, the conversation's framing outgrew the margin in `context_tokens × 6` bytes (very many small turns: the meter counts text, not framing) | remove the setting, and the loop derives its cap from `context_tokens`; otherwise start a new conversation |
| `journalctl -u maknae-egress` (on macOS, `maknae-egress.err`) shows file or prompt text after `provider answered …` | some servers quote the rejected request in their error body | expected: the journal can hold up to 4 KiB of conversation content; limit who reads it (`docs/configuration.md` §6.2). On macOS the `.err` file holds the same content, and nothing rotates it |

### On macOS

The daemon's and the deputy's rows. Each message is quoted exactly; in each refusal row the `.err` line also carries the process's own prefix (`maknaed: refusing to start: `, or `maknae-egress: refusing to start: egress credential: `), so those rows say "contains".

| What you see | Why | Fix |
|---|---|---|
| `maknaed.err` contains `principal.home could not be resolved to its canonical form: principal.home "/Users/<you>": …` | boot could not resolve your home. It resolves the home via `getattrlist`, which needs search permission on every directory above the home (`/Users` is `0755`) and none on the home itself (measured with a `000` directory the caller owns), and it refuses a path that does not exist or is not a directory (from the code). Resolving a default home as `_maknae` is pending the macOS acceptance run (#76); an autofs or NFS home is unmeasured. This check runs before the keychain read, so none of the rows below are reached until it passes | check that `principal.home` names an existing directory and that `_maknae` can search every directory above it |
| `maknaed.err` or `maknae-egress.err` contains `keychain read refused (-25293): the keychain is locked, or this binary is not the Developer ID-signed one the item was enrolled for (an ad-hoc or re-signed build)` | the running binary is not the Developer ID build the item was enrolled for: an ad-hoc build of the same code is refused this way in a user or root session (measured, ADR-0018 decision 6); under launchd an untrusted binary was instead refused `-25308`, next row. The System keychain is unlocked by the system, so a locked keychain is not the cause here | reinstall the signed package; after changing the signing identity, re-enroll |
| … contains `keychain read needs user interaction, which is disabled (-25308): the calling program is not one the item trusts, in a context that cannot prompt (measured: a launchd daemon); run the Developer ID-signed build the item was enrolled for` | the program reading the item is not one the item trusts; in a launchd daemon that read is refused with `-25308` and no dialog (measured, ADR-0018 decision 6) | reinstall the signed package; after changing the signing identity, re-enroll |
| … contains `` no keychain item (-25300): not enrolled; run `sudo maknae enroll` `` | the pointer file names an item that no longer exists, typically after `packaging/macos/uninstall.sh` (which deletes the items but keeps `/etc/maknae` and its pointer files) and a reinstall | `sudo maknae enroll` |
| … contains `refusing the keychain read: running as uid N, not as _maknae` (or `_maknae-egress`) | the binary was started outside its launchd job | start it only through step 5 |
| … contains `keychain pointer: …` | the pointer under `/etc/maknae/private` or `/etc/maknae/egress` was edited | `sudo maknae enroll` |
| `maknaed.err` shows `maknaed: warning: this boot's credential posture is not hardware-root-of-trust sealed` | expected on every macOS boot that reaches the credential read: the posture is `code_bound`, not `hrot_sealed` | nothing to fix |

The CLI's rows. `maknae ping` and `maknae agent` print these. The CLI's item lives in the operator's default keychain, usually the login keychain (enroll writes it there), so each "Why" is about that keychain.

| What you see | Why | Fix |
|---|---|---|
| `maknae` contains `` no keychain item (-25300): not enrolled; run `sudo maknae enroll` `` | your default keychain has no `maknae-cli` item. Typically: you deleted it after an uninstall (as [packaging/macos/README.md](../packaging/macos/README.md) says to) and reinstalled without re-enrolling; or you changed your default keychain after enroll, which wrote the item into the default keychain you had then (usually login). (A user who never enrolled fails earlier, on the missing configuration in `~/.maknae` — or under `MAKNAE_CONFIG_DIR`, if that is set.) | `sudo maknae enroll`, as the operator the CLI runs as; or switch back to the default keychain you enrolled with |
| `maknae` contains `keychain read refused (-25293): …` | your default keychain is locked, or this `maknae` is not the Developer ID-signed binary that enrolled (a replaced or re-signed build): in a user session, a locked default keychain returns `-25293`, and so does a binary the item does not trust (inferred); pending the macOS acceptance run (#76) | unlock your default keychain (`security unlock-keychain`), or reinstall the signed package and `sudo maknae enroll`; enroll replaces your keychain item |
| `sudo maknae enroll` ends with an `Enrollment failed: enroll-helper provision failed: …` line that contains `keychain open default failed: status N: …` | the operator's default keychain could not be opened (for example, none exists yet for a fresh account) | as that user, create a default keychain and unlock it (`security create-keychain login.keychain`, then `security default-keychain -s login.keychain`, then `security unlock-keychain login.keychain`), then re-enroll |
| … that contains `keychain delete failed: status N: …` | inferred: the old CLI item's access list does not trust this `maknae` (typically after a re-sign) | as that user, `security delete-generic-password -s maknae-cli -a maknae-secret-id`, then re-enroll |
| … that contains `keychain add failed: status -25299: …` | only if another process adds the item between enroll's delete and add: enroll deletes any old CLI item first, then refuses a duplicate rather than silently keeping its access list | as that user, `security delete-generic-password -s maknae-cli -a maknae-secret-id`, then re-enroll |
| … that contains `keychain verify failed: …` | enroll's read-back of the item it just added failed, or returned a value different from what it wrote | re-run `sudo maknae enroll`; if it persists, confirm the default keychain is unlocked and not corrupt |

## What stays true

- **Your key stays in Vault.** Only the egress deputy holds it, in memory. You and the daemon cannot read its credentials.
- **Every action is decided before it happens and recorded.** That covers each prompt, read and write, and it holds for refusals too.
- **The deny list holds.** Reads under `~/.ssh`, `~/.aws` and similar are refused by policy, and nothing from them reaches the model.
- **On macOS the daemon's and the deputy's Vault SecretIDs are System-keychain items that only their own signed binaries can read.** That a signed daemon and deputy read their items on a real install is pending the macOS acceptance run (#76). They are bound to code identity under a root-held key, not to hardware. An administrator can approve a read in a console session (measured), and root can copy the keychain and its key and decrypt them off the host (inferred). See ADR-0018 decision 6.
- **What you did not ask for does not leave.** Only the conversation leaves the host, including file contents the agent was allowed to read.
