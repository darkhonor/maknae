# Your first model provider

This walkthrough connects Maknae to one model provider, so that `maknae agent` can hold a conversation: read a file, write a file, and answer you. Every step of that conversation is decided by the kernel and recorded before it happens.

It is written for a person doing this for the first time. The administrator authorizes a provider for the host; each user logs in, stores their own API key in Vault under their own login, and chooses among the authorized providers. For every key and every rule, see the configuration reference: [the `providers` section](configuration.md#61-the-providers-section) (§6.1), [each user's `providers.yaml`](configuration.md#611-each-users-providersyaml) (§6.1.1), [the user `vault` block](configuration.md#612-the-user-vault-block) (§6.1.2), [`egress-bounds.yaml`](configuration.md#613-egress-boundsyaml) (§6.1.3) and [the worked example](configuration.md#93-authorizing-providers-in-configd) (§9.3). For the full acceptance procedure, including custody and SELinux checks, see [runbook Chapter 4](runbook.md).

The single-user path passed on Rocky 10.2 and on macOS 26.6.2 with a Developer ID-signed, not notarized, package (#434). The earlier walkthrough, before the switch to per-user providers, passed on a notarized package with `transport.read_timeout_ms: 60000` (#413). The per-user steps were not run as one walkthrough, and the second-user steps are not yet measured. On a default macOS home (`0750`), the daemon resolves the requesting user's home via `getattrlist` for each file action, which needs no permission on the home itself (measured with a `000` directory the caller owns); the daemon, running as `_maknae`, booted on a default home.

## What you need first

- **A Linux host with the Maknae package installed** (runbook Chapter 4, steps 1–2). You enroll it in step 2 below.
- **Or a Mac on Apple Silicon** with the **Developer ID-signed** Maknae `.pkg` installed (`sudo installer -pkg Maknae-<version>-arm64.pkg -target /`). The release workflow's package is ad-hoc signed. The repository documents no signed-build procedure, and no signed release exists yet; [packaging/macos/README.md](../packaging/macos/README.md#building-a-signed-package) *Building a signed package* states what such a build requires.
  - **What enroll checks.** Enroll refuses unless `maknae`, `maknaed` and `maknae-egress` are root-installed and signed with Developer ID by one team, with Hardened Runtime and no entitlements (ADR-0018 decision 6).
  - **The development-build refusals.** A `maknae` built with `cargo` and run from your own `target/` directory is refused first, at the root-install check: enroll prints `Enrollment preflight check failed`, then `Enrollment failed: <path> could be replaced by a non-root user (…); the keychain item would trust whatever sits there`. An installed ad-hoc package passes that check and is refused at the Developer ID check, on `maknae` itself: enroll prints `Enrollment preflight check failed`, then `Enrollment failed: /usr/local/bin/maknae is not a Developer ID release build of this team (no team identifier); the keychain item would trust it (ADR-0018 decision 6)`.
  - **`--insecure-plaintext-secret`** is refused on macOS.
- **A Vault set up from `deploy/vault-pki`** (its Terraform applied), and an administrator Vault token that may run enroll and set user passwords. The defaults this walkthrough uses come from `deploy/vault-pki`: the userpass mount `maknae-userpass`, the KV v2 mount `maknae-kv`, and each user's keys under `maknae/users/<username>/`. If your Vault uses other names, use yours everywhere below.
- **The `vault` CLI** on the host, for the administrator's step 1 and each user's step U2.
- **An API key** for an OpenAI-compatible endpoint. Each user stores their own.

## Administrator

The administrator is the account that runs `sudo maknae enroll`. That account is also a user: it logs in and stores a key like everyone else.

### 1. Create the user in Vault

Every person who will use `maknae agent`, the administrator included, is a Vault userpass user. List each local account name in Terraform's `maknae_users` input (`deploy/vault-pki/variables.tf`) and apply:

```hcl
maknae_users = {
  alice = { password_version = 1 }
}
```

Each key is the local account name: 1 to 32 bytes of `[a-z0-9._-]`, starting and ending with `[a-z0-9_]`, and not `data`. Terraform creates the user with a random password that nobody learns; it is in neither the plan nor the state. Incrementing `password_version` replaces that user's password with a new random one. See `deploy/vault-pki/README.md` *Users and passwords* for what else resets a password.

Then set the user's real password, with your administrator token, in the same shell:

zsh (macOS), measured:

```zsh
read -rs "PW?New password: " && echo && printf %s "$PW" | vault write auth/maknae-userpass/users/<username>/password password=- && unset PW
```

bash (Linux), not yet measured:

```bash
read -rsp "New password: " PW && echo && printf %s "$PW" | vault write auth/maknae-userpass/users/<username>/password password=- && unset PW
```

- **`read -s`** does not echo: the password never appears on screen or in shell history.
- **`printf %s`** sends no trailing newline. Typing the password into a bare `password=-` prompt stores the Enter key as part of the password, so every login fails with `invalid username or password` (measured), and the terminal echoes it.
- **The administrator token** sets it: Vault's password endpoint does not ask for the old password.

To check the password without replacing your administrator token: `vault login -method=userpass -path=maknae-userpass -no-store username=<username>`.

### 2. Enroll the host

```bash
sudo maknae enroll \
  --deployment-id <id> \
  --vault-addr https://<vault-host>:8200 \
  --vault-ca /path/to/vault-ca.pem
```

Enroll prompts for your administrator Vault token (`--token-file <path>` reads it from a file instead). Runbook Chapter 4, step 3, explains every flag. On Linux, run enroll from a direct login whose `id -Z` shows `unconfined_u`, not from `sudo su` out of a confined account. On macOS, the flags are the same.

Three flags name the Vault layout for user keys, and each **must equal** its Terraform input:

| Enroll flag | Default | Terraform input |
|---|---|---|
| `--userpass-mount` | `maknae-userpass` | `userpass_mount` |
| `--kv-mount` | `maknae-kv` | `kv_mount_path` |
| `--user-prefix` | `maknae/users` | `user_prefix` |

Enroll writes them into `/etc/maknae/egress-bounds.yaml` (`root:root 0644`), into the `vault` block of your own `~/.maknae/maknae.yaml`, and `--userpass-mount` into the root `maknae.yaml`. You do not write `egress-bounds.yaml` by hand.

Enroll also generates the Egress Daemon's sealing key pair and publishes the public key, `seal.pub`, where every user's CLI reads it: `/etc/pki/maknae/seal.pub` on the Red Hat family, `/etc/ssl/maknae/seal.pub` on the Debian family, and `/Library/Application Support/Maknae/pki/seal.pub` on macOS. On the first enroll it prints:

> Generated the Egress Daemon's sealing key and published its public key at {path}. An Egress Daemon that is already running still holds the previous key: restart it with \`sudo {restart}\`

where `{restart}` is `systemctl try-restart maknae-egress.service` on Linux and `launchctl kickstart -k system/io.maknae.maknae-egress` on macOS. On a re-enroll it keeps the pair and prints `Kept the Egress Daemon's sealing key and its published public key; pass --rotate-seal-key to replace them`.

It closes with `` Log out and back in (or run `newgrp maknae`), then run `maknae login` before using the CLI ``. Do that: the CLI's socket is reachable only by the `maknae` group, and every CLI verb needs a stored login (step 5).

### 3. Authorize the provider

```bash
sudo install -d -m 0750 -o root -g _maknae /etc/maknae/config.d
sudo tee /etc/maknae/config.d/10-provider.yaml >/dev/null <<'EOF'
providers:
  - name: openai
    endpoint: https://api.openai.com/v1/chat/completions
    models: [gpt-5.6-luna]
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

- **`name`** is what users name in their `providers.yaml` and what `authz.yaml` grants, as `provider:<name>` (step 4).
- **`endpoint`** is the full chat-completions URL, sent exactly as written.
- **`models`** lists the models users may ask this provider for. A request for any other model is refused.
- **`reasoning_effort`** is optional. Some models need it: `gpt-5.6-luna` refuses the agent's tools unless it is `none`. Leave it out if your model does not need it.
- **No key goes in this file.** A field named like a key (`api_key`, `token`, `secret` and others) refuses boot. Each user's key lives in Vault under their own login (step U2).
- **Root owns this file** on purpose. The agent runs as the user, so a user cannot redirect where their content goes by editing their own files.
- **The daemon's prompt cap**, `transport.prompt_max_bytes` in `/etc/maknae/maknae.yaml`, defaults to 1 MiB. That carries a context window of up to about 174,000 tokens. For a larger window, raise it to `context_tokens × 6` (at most 16 MiB), where `context_tokens` is what users declare in step U3. `sudo maknae enroll` rewrites this file, so after any re-enroll, set it again.
- **On macOS, `/etc/maknae/maknae.yaml` already has a `transport:` block:** enroll writes `transport.socket_path` there. If you raise `transport.prompt_max_bytes` here, add it under that existing block, not as a second `transport:` key — a repeated top-level key refuses the whole file to load with `duplicate config key 'transport' at LINE:COL`, and `maknaed` restarts every 5 s without starting.

### 4. Allow the prompt

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

The enrolled administrator resolves to the `admin` role when the policy has no `bindings:`. `provider:openai` is `provider:` followed by the `name` from step 3. The policy is re-read on every request; the one exception is a new name in `bindings:`, which needs a restart (step 4a).

### 4a. Add another local user

Enroll writes `~/.maknae` only for the account that ran it. Each further local user needs four things from you.

**A second user works in their own home.** For each request the kernel resolves the requesting user's home from the kernel-verified peer ID, confines file actions to it, and `~` in `authz.yaml` means that home for every role. The shipped `Read(~/.maknae/**)` deny therefore protects each user's own `~/.maknae`. A grant for a folder that does not exist yet permits once the folder is created, with no restart. The home is resolved only for a file action, after the request arrives. If it cannot be used, conversation turns, `whoami`, liveness and admin commands still work, and file actions are refused. The user sees only `not authorized`; the cause is in the audit record's reason, `requester home unavailable: <cause>`, which the administrator reads with the `jq` query in [runbook step 11](runbook.md#11-quote-the-audit-trail). The cause is `unresolvable` when the home does not exist, is not a directory, is `/` or is not valid UTF-8; `timed out` when it does not resolve within the time limit, as on a hung network mount; `at capacity for this requester` when that user already has a resolution in progress; and `at capacity` when every resolution slot is busy. Each user can have at most one home resolution and one file-action preparation running at a time, so a stalled home delays only that user's file actions, and a file action from a user whose previous one is still being prepared or decided is refused with `mutation worker budget exhausted for this requester`. Other users are affected only when as many users as there are slots (16) are stalled at once. What a second user's file actions do was read from the code, not yet measured.

**On a multi-user host, other local users can read a running `maknae agent`'s prompt and `--provider` from its command line** (#436, undecided).

1. **Create the account and add it to the `maknae` group.** The daemon's socket is `0660`, group `maknae`.

   On Linux:

   ```bash
   sudo useradd -m <user>
   sudo passwd <user>
   sudo usermod -aG maknae <user>
   ```

   On macOS (not yet measured), create the account in System Settings or with `sysadminctl`, which prompts for the password; the account must exist before `dseditgroup` can add it:

   ```bash
   sudo sysadminctl -addUser <user> -password -
   sudo dseditgroup -o edit -a <user> -t user maknae
   ```

   The user then logs out and in, in a real login session. On Linux, `maknae login` keeps the token through `systemd-creds --user`, which reads `XDG_RUNTIME_DIR`; `sudo -iu` or `su -` may not set it, or may carry the administrator's. On macOS, the token lives in the user's default keychain, which a graphical login creates.

2. **Build the user's `~/.maknae` by copying yours.** Nothing in your enroll-written `maknae.yaml` is specific to you: it holds `core.deployment_id`, the `vault` block and, on macOS, `transport.socket_path`. The CLI needs all three: without `deployment_id` it refuses to load, and a macOS file without `transport` points at the wrong socket. Copy it and the three CA files byte for byte, with the owners and modes enroll uses (`0700` directories, `0600` files). Run this as the administrator; `sudo` reads your `0700` directory:

   ```bash
   NEW=<user>
   NEW_HOME=/home/<user>          # on macOS: /Users/<user>
   NEW_GROUP=$(id -gn "$NEW")
   sudo install -d -m 0700 -o "$NEW" -g "$NEW_GROUP" "$NEW_HOME/.maknae"
   sudo install -d -m 0700 -o "$NEW" -g "$NEW_GROUP" "$NEW_HOME/.maknae/tls"
   sudo install -m 0600 -o "$NEW" -g "$NEW_GROUP" "$HOME/.maknae/maknae.yaml" "$NEW_HOME/.maknae/maknae.yaml"
   for f in vault-ca.crt maknae-root-ca.crt maknae-int-ca.crt; do
     sudo install -m 0600 -o "$NEW" -g "$NEW_GROUP" "$HOME/.maknae/tls/$f" "$NEW_HOME/.maknae/tls/$f"
   done
   ```

   Create each directory with `install -d` as shown. Do not use `install -D` to create the parents: it makes them `root`-owned and `0755`.

3. **Bind the user to the `user` role.** Edit `/etc/maknae/authz.yaml` in place (`sudoedit /etc/maknae/authz.yaml`); do not append with `tee -a`, because a second `roles:` key refuses the whole document. Once a `bindings:` block exists, only the names it lists have a role, so list yourself under `admin` too. `user` is the only other role that may be granted `session.prompt`, and each role needs its own action grant and its own destination; without them the user's prompts are denied with `role user: no rule for session.prompt` in the trail, and the user sees only the generic refusal (`PROMPT_REFUSED`, below). The complete file, with the shipped `permissions:` unchanged and the administrator `alice` and the user `bob`:

   ```yaml
   schema_version: 1
   permissions:
     allow:
       - "Read(~/**)"
       - "Write(~/projects/**)"
     deny:
       - "Read(~/.ssh/**)"
       - "Read(~/.gnupg/**)"
       - "Read(~/.aws/**)"
       - "Read(~/.vault-token)"
       - "Read(~/.netrc)"
       - "Read(~/.git-credentials)"
       - "Read(~/.kube/**)"
       - "Read(~/.docker/config.json)"
       - "Read(~/.maknae/**)"
       - "Write(~/.ssh/**)"
       - "Write(~/.gnupg/**)"
       - "Write(~/.aws/**)"
       - "Write(~/.vault-token)"
       - "Write(~/.netrc)"
       - "Write(~/.git-credentials)"
       - "Write(~/.kube/**)"
       - "Write(~/.docker/config.json)"
       - "Write(~/.maknae/**)"
   bindings:
     admin: ["alice"]
     user: ["bob"]
   roles:
     admin:
       allow: ["session.prompt"]
     user:
       allow: ["session.prompt"]
   destinations:
     admin:
       allow: ["provider:openai"]
     user:
       allow: ["provider:openai"]
   ```

   **Restart `maknaed` immediately after saving** (`sudo systemctl restart maknaed`; on macOS, `sudo launchctl kickstart -k system/io.maknae.maknaed`). The policy is re-read on every request, but the map from names in `bindings:` to uids is built when the daemon starts. Until the restart, a name it did not know at start makes every request indeterminate, which is a deny for everyone, you included. A name with no account on the host refuses the restart: `identity '<name>' has no resolvable uid on this host`.

4. **Add the user to `maknae_users`** and set their password (step 1).

The user then follows [You (the user)](#you-the-user).

## 5. Start

```bash
sudo systemctl enable --now maknae-egress.socket maknaed
sudo systemctl restart maknaed
maknae login         # see step U1
maknae ping          # pong
```

These are the units enroll's closing hints name. Restart the daemon as well as enabling it: `enable --now` does not restart a daemon that is already running, and the authorized provider set is read at boot. Every CLI verb, `maknae ping` included, needs a stored login; without one it fails with `` no Vault token is stored: run `maknae login` ``.

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
maknae login         # see step U1
maknae ping          # pong
```

- **Why the loop checks first.** `launchctl print` exits 0 for a loaded job and 113 for an unknown one; the package's own uninstall and install scripts rely on that convention, and it was not re-measured for this page. A second `bootstrap` of a loaded job errors: that is known launchctl behaviour, not measured here. `kickstart -k` restarts a loaded job, which is how the daemon picks up the provider.
- **`pong`.** `maknae ping` uses the Vault token `maknae login` stored to obtain its client certificate, then reaches the daemon's socket.
- **The posture record.** The boot's posture record reads `code_bound`:
  ```bash
  sudo jq -c 'select(.action=="posture") | .outcome.posture' /var/log/maknae/audit.jsonl | tail -n 1
  ```
  `jq` ships at `/usr/bin/jq` on macOS 26 (measured on macOS 26.6.2).
- **The posture warning.** On a boot that reaches the credential read, `maknaed.err` also gets `maknaed: warning: this boot's credential posture is not hardware-root-of-trust sealed`. That is expected on macOS: the System keychain is not a hardware root of trust (ADR-0018 decision 6).
- **A refused boot** restarts every 5 seconds without end, so read `last exit code` rather than waiting for the job to stop.

## You (the user)

These steps are the same for the administrator and for every other user. Each runs as you, in your own login session.

### U1. Log in

```bash
maknae login
```

It needs a terminal and refuses to run as root (`` run `maknae login` as your own user, not root ``). It asks `Vault password for <name> (will be hidden): `, where `<name>` is your local account name, and on success prints:

```
maknae: logged in to Vault as <name>; the token is held in <custody> and is valid for <lifetime>
```

`<lifetime>` reads like `8h 0m`.

`<custody>` is `your default keychain (usually login)` on macOS; on Linux it is `a systemd-creds user credential` where `systemd-creds --user` is available (systemd 256 or later), and otherwise `a 0600 file (systemd-creds --user is unavailable here)`. Only the token is stored, never the password.

The token lasts 8 hours (Terraform's `token_ttl`, with a 24-hour `token_max_ttl`, `deploy/vault-pki/main.tf`), and Maknae never renews it: log in again when it expires. `maknae logout` revokes it at Vault and erases it.

### U2. Store your key in Vault

You store your own key, with your own Vault login. In the shell you will use, point the `vault` CLI at the same Vault and CA your Maknae configuration uses; without these it talks to `https://127.0.0.1:8200` and trusts the system store:

```bash
export VAULT_ADDR=https://<vault-host>:8200        # vault.addr from ~/.maknae/maknae.yaml
export VAULT_CACERT=~/.maknae/tls/vault-ca.crt
```

Get a Vault token for your login, without replacing any token the `vault` CLI already holds:

```bash
vault login -method=userpass -path=maknae-userpass -token-only username=<username>
```

It prints the token. Then store the key, pasting that token at the first prompt and your API key at the second. The path is `<kv_mount>/data/<user_prefix>/<username>/<subpath>`; with enroll's defaults and the subpath `openai`, that is `maknae-kv/data/maknae/users/<username>/openai`.

zsh (macOS), measured:

```zsh
read -rs "VT?Maknae user token: " && echo && read -rs "KEY?OpenAI API key: " && echo && printf '{"data":{"api_key":"%s"}}' "$KEY" | VAULT_TOKEN="$VT" vault write -wrap-ttl=60s <kv_mount>/data/<user_prefix>/<username>/<subpath> - ; unset VT KEY
```

bash (Linux), not yet measured:

```bash
read -rsp "Maknae user token: " VT && echo && read -rsp "OpenAI API key: " KEY && echo && printf '{"data":{"api_key":"%s"}}' "$KEY" | VAULT_TOKEN="$VT" vault write -wrap-ttl=60s <kv_mount>/data/<user_prefix>/<username>/<subpath> - ; unset VT KEY
```

- **`read -s`** keeps the token and the key off the screen and out of shell history.
- **`printf`** is a shell builtin, so the key never appears in the process list.
- **`vault write <kv_mount>/data/…` with `-`** writes the KV v2 data path directly, so there is no `vault kv` preflight against `sys/internal/ui/mounts`, which your user token (it has no `default` policy) may not be allowed.
- **`-wrap-ttl=60s`** is required: the user policy's `min_wrapping_ttl` applies to writes too. An unwrapped write of a user key was refused (measured on a throwaway Vault 2.0.0 with the shipped Terraform, #434).
- **`unset`** clears both from the shell.

The field name, `api_key` here, and the subpath are what your `providers.yaml` names in step U3.

Vault answers with a wrapping token around the write's metadata (its `wrapping_token_creation_path` is your key's path). It holds nothing secret; ignore it.

**Never paste a wrapping token from a read.** A wrapped *read* of your key returns a wrapping token that wraps the key itself: anyone who unwraps it within its TTL has your key. An unwrapped read of your own key is refused with a plain `403 permission denied` (measured): that is the policy's `min_wrapping_ttl` working, not a broken grant. Another user's key is refused the same way, wrapped or not (measured).

### U3. Choose your provider

Write `~/.maknae/providers.yaml`. Enroll does not write it and does not touch it. With one entry, no `default` is needed:

```bash
cat > ~/.maknae/providers.yaml <<'EOF'
providers:
  - label: openai
    provider: openai
    model: gpt-5.6-luna
    key:
      subpath: openai
      field: api_key
    context_tokens: 128000   # your model's context window, in tokens
    output_tokens: 16000     # optional: the reply cap
EOF
chmod 0600 ~/.maknae/providers.yaml
```

- **`provider`** and **`model`** must be a `name` and one of its `models` from the administrator's step 3, and your role must be granted `provider:<name>` (step 4).
- **`key`** says where your key is in Vault, never the key itself: `subpath` and `field` from step U2.
- **`context_tokens`** is required. Use the window your provider documents for your model. The agent warns at 80% and 95% of it and stops before a turn would exceed it. [Configuration §6.1.1](configuration.md#611-each-users-providersyaml) has the details.

With two or more entries, mark exactly one `default: true`, and choose another per run with `--provider <label>`:

```yaml
providers:
  - label: luna
    provider: openai
    model: gpt-5.6-luna
    key:
      subpath: openai
      field: api_key
    context_tokens: 128000
    default: true
  - label: local
    provider: local
    model: llama
    key:
      subpath: local
      field: api_key
    context_tokens: 32000
```

```bash
maknae agent --provider local "<prompt>"
```

The second entry works only once `local` is authorized like `openai`: its own entry in step 3's `providers:` list (with `llama` in its `models`), a `provider:local` destination for your role in step 4 (step 4a for a second user), and your key stored at subpath `local` in step U2. Without the step 3 entry or the grant, the turn is refused: you see the refusal line ([When it does not work](#when-it-does-not-work)), and your administrator's audit shows `provider not in the authorized set` (no step 3 entry) or `destination not allowlisted for role <role>: provider:local` (no grant). Without the key, the CLI stops with `no key is stored in Vault for provider entry local: store it, then retry`.

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

Each turn, `maknae agent` makes a wrapped read of your key with your own login, seals the wrapping token to the Egress Daemon's `seal.pub`, and sends it with the prompt. The kernel admits the turn on the provider, the model and your account name; it never sees the key.

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

Where a row below names `systemctl` or `journalctl`, it also gives the macOS form. The daemon writes to `/usr/local/var/log/maknae/maknaed.err` (`sudo tail /usr/local/var/log/maknae/maknaed.err`) and the deputy to `/usr/local/var/log/maknae-egress/maknae-egress.err`. `sudo` is required: their directories are `_maknae:_maknae 0750` and `_maknae-egress:_maknae-egress 0750`, and the administrator is in neither group.

A kernel refusal reaches you only as one line, `PROMPT_REFUSED` below; the reason is in the audit trail, which only your administrator can read. `PROMPT_REFUSED` is this whole line, exit 2:

> maknae agent: stopped: the kernel refused the exchange — whether the prompt reached the provider is in the host's audit trail (ask your administrator); if it did not, check that your providers.yaml names a provider and model your administrator has authorized for your role and the key subpath and field of your own Vault secret, that your maknae.yaml vault block matches the host's, and that your login is current (maknae login)

**Refused by the kernel.** You see `PROMPT_REFUSED`. In the trail, `session.prompt` is denied with the reason below; for the admission reasons the posture is `unauthorized` and the record has no `egress` block.

| Your administrator's audit shows | Why | Fix |
|---|---|---|
| `session.prompt carries no provider choice` | the request named no provider; the shipped CLI always names one, so another client sent it | use the shipped `maknae agent` |
| `no model access: no providers are authorized on this host` | the host authorizes no provider, or the daemon booted before step 3's file existed | step 3, then restart: `sudo systemctl restart maknaed`; on macOS, `sudo launchctl kickstart -k system/io.maknae.maknaed` |
| `provider not in the authorized set` | your entry's `provider` is not a `name` in step 3's list | correct `provider` in `providers.yaml`, or ask for it to be authorized |
| `model not on the authorized provider's list` | your entry's `model` is not on that provider's `models` | correct `model`, or ask for it to be added |
| `local account has no name usable as a key path segment` | your account name is not 1 to 32 bytes of `[a-z0-9._-]` starting and ending with `[a-z0-9_]`, or it is `data` | use an account with such a name |
| `key subpath malformed` | the request's `key.subpath` failed the kernel's check | the CLI checks it first, so another client sent it |
| `key field malformed` | the request's `key.field` failed the kernel's check | as above |
| `role <role>: no rule for session.prompt` | the policy has no `session.prompt` grant for your role | step 4 (step 4a for a second user) |
| `destination not allowlisted for role <role>: provider:<name>` | your role may prompt, but not to that provider | add `provider:<name>` to your role's `destinations` (step 4, 4a) |
| `egress backend not ready` | the deputy's socket is not running | `sudo systemctl enable --now maknae-egress.socket`; on macOS, step 5's loop |

**Refused by the CLI before sending.** These print before anything reaches the daemon; the CLI prefixes them `maknae: `, or `maknae agent: stopped: ` once the conversation has begun.

| What you see | Why | Fix |
|---|---|---|
| `` maknae: no Vault token is stored: run `maknae login` `` | you have not logged in on this account | step U1 |
| `` maknae: your Vault token has expired or expires within 60 s: run `maknae login` `` | the 8-hour login ran out | step U1 |
| `` maknae agent: stopped: your Vault login expired: run `maknae login` `` | the login ran out during the conversation | step U1, then start the conversation again |
| `maknae: no model access: no providers are defined in <path>` | `providers.yaml` is absent, empty, or has no `providers` key | step U3 |
| `maknae: providers.yaml: <N> entries and none is marked default: true; mark exactly one (labels: <labels>)`, or `… more than one entry is marked default: true (<labels>)` | two or more entries need exactly one default | mark exactly one `default: true` |
| `maknae: providers.yaml: no entry is labelled '<label>' (labels: <labels>)` | `--provider` names no entry | use one of the listed labels |
| `maknae: providers.yaml: providers[0].key.subpath has a '.' or '..' segment` (likewise `has a 'data' segment`) | the subpath must be `/`-separated `[A-Za-z0-9._-]` segments with no empty, `.`, `..` or `data` segment | correct `key.subpath` |
| `maknae: providers.yaml: providers[0].context_tokens is required: declare the model's context window in tokens` | the entry declares no window | add `context_tokens` (step U3) |
| `` maknae: vault.kv_mount is not set in your maknae.yaml: `sudo maknae enroll` writes it `` (likewise `vault.user_prefix`) | your `~/.maknae/maknae.yaml` predates per-user keys, or was copied incompletely | re-run step 2 for the administrator, step 4a's copy for anyone else |
| `` maknae: no Egress Daemon public key is published on this host: ask your administrator to run `sudo maknae enroll` `` | `seal.pub` is missing | step 2 |
| `maknae: Egress Daemon public keys are published at both <first> and <second>, and exactly one is expected: ask your administrator to remove the stale one` | both Linux `seal.pub` paths exist | remove the one that does not match this distribution's family |
| `maknae: the Egress Daemon public key at <path> was refused (…): it must be a regular file with one link, owned by root, not writable by group or others, in a directory only root can write; ask your administrator` | `seal.pub` or its directory has the wrong owner, mode or link count | re-run step 2 |
| `maknae: the Egress Daemon public key at <path> could not be used (…): ask your administrator`, or `` maknae: the Egress Daemon public key published on this host is not usable (…): ask your administrator to run `sudo maknae enroll` `` | `seal.pub` is not a usable key | rotate it (below) |
| `` maknae agent: stopped: Vault refused to read the key for provider entry <label> (HTTP 403): the key is outside your Vault policy, or your login was revoked: run `maknae login` `` | the path is not under your own `<user_prefix>/<username>/`, or your login no longer works | check `key.subpath`; step U1 |
| `maknae agent: stopped: no key is stored in Vault for provider entry <label>: store it, then retry` | nothing is stored at that subpath | step U2, with the same subpath |

**Refused by the Egress Daemon.** You see `PROMPT_REFUSED`; the trail records the prompt `Failed` (refused before anything was sent); and `journalctl -u maknae-egress` (on macOS, `sudo tail /usr/local/var/log/maknae-egress/maknae-egress.err`) shows `maknae-egress: connection refused: OpenFailed(<reason>)`. For `Vault`, a line `maknae-egress: the Vault unwrap failed: …` gives Vault's own answer.

| `OpenFailed(…)` | Meaning | Fix |
|---|---|---|
| `Seal` | the sealed key does not match this request. After a seal-key rotation, it means the running deputy still holds the previous key. Otherwise, your `vault.kv_mount` or `vault.user_prefix` likely differs from the host's `egress-bounds.yaml`: the CLI binds the key path from your copy into the seal, and the deputy opens it under the path from the host's, so the seal does not open and Vault is never asked | after a rotation, restart the Egress Daemon: `sudo systemctl try-restart maknae-egress.service`; on macOS, `sudo launchctl kickstart -k system/io.maknae.maknae-egress`. Otherwise, make your `vault` block match the host's (step 2, 4a) |
| `WrongPath` | the seal opened, but Vault's lookup reports the wrapping token was created at a different path than the request names. The `maknae` installed with the host's package does not produce it: its wrapped read refuses a token for any other path before it seals. It means a client sealed a token for another path, such as another user's | send your administrator the journal line and the trail record |
| `Request` | the request cannot name a Vault key path | send your administrator the journal line |
| `Token` | the sealed key does not hold a wrapping token | use the `maknae` installed with the host's package |
| `Ttl` | the wrapping token's TTL is outside the allowed bound | use the `maknae` installed with the host's package |
| `Invalid` | the wrapping token is expired, already used, or not a wrapping token | retry the turn |
| `Field` | the key field is absent from the secret | make `key.field` match the field stored in step U2 |
| `Vault` | the Vault unwrap failed | read the `the Vault unwrap failed:` line |

**Other stops.**

| What you see | Why | Fix |
|---|---|---|
| `maknaed` will not start: `section 'providers' must come from a root-owned, non-group/other-writable source; <path> is not` | the provider file or its directory is writable by someone other than root | step 3's owner and mode |
| The agent stops; `journalctl -u maknae-egress` (on macOS, `sudo tail /usr/local/var/log/maknae-egress/maknae-egress.err`) shows `provider answered 400 (conversation …): …` | the provider rejected the request's shape | the text after the colon is the provider's own reason, with the key masked. For `gpt-5.6-luna` it is the missing `reasoning_effort: none`; a server that names `max_completion_tokens` as unsupported needs `output_tokens_field: max_tokens` in step 3's entry |
| `maknae agent: stopped: the conversation has reached the declared context budget; compaction arrives with #171` | the next turn would exceed the window you declared | start a new conversation, or declare the larger window your model has |
| `maknae agent: stopped:` with a connection error, on a long conversation | the daemon's prompt cap is below your loop's, so the daemon refused the frame and closed the connection | raise the daemon's `transport.prompt_max_bytes` (step 3; on macOS, under the existing `transport:` block — a second `transport:` key refuses the file with `duplicate config key 'transport' at LINE:COL`) |
| `maknae agent: stopped: no response from daemon within 690000ms (stalled?)`, exit 2 | the agent waits for a model reply for as long as the daemon could take at its ceilings (the 600 s `egress.deadline_ms` maximum, the 60 s transport maximum and a 30 s margin), and the daemon never answered: it is wedged: the only unbounded step on that path is an audit append, so check for a stalled audit filesystem first | check `maknaed`'s state, its log and the audit filesystem, then restart it |
| `PROMPT_REFUSED`; `journalctl -u maknae-egress` (on macOS, `maknae-egress.err`) shows `provider reply is not admissible: tool call 'write_file' exceeds a declared bound` | the model tried to write more than one call carries: `write_file`'s arguments may be at most 61,440 bytes (`docs/configuration.md` §6.1.1), and nothing was written. With a small daemon `transport.prompt_max_bytes`, several calls that are each within the bound can also be refused together; the trail then records the reply as `LandedUndelivered` and the journal shows no such line | ask for a smaller file, or for the content in several files |
| `maknae agent: stopped: the conversation has reached the platform's frame bound` | your own `transport.prompt_max_bytes` in `~/.maknae` is smaller than your window needs; or, with none set, the conversation's framing outgrew the margin in `context_tokens × 6` bytes (very many small turns: the meter counts text, not framing) | remove the setting, and the loop derives its cap from `context_tokens`; otherwise start a new conversation |
| `journalctl -u maknae-egress` (on macOS, `maknae-egress.err`) shows file or prompt text after `provider answered …` | some servers quote the rejected request in their error body | expected: the journal can hold up to 4 KiB of conversation content; limit who reads it (`docs/configuration.md` §6.2). On macOS the `.err` file holds the same content, and nothing rotates it |

**Rotating the seal key.** Run the full enroll again with `--rotate-seal-key`; it needs your administrator Vault token, as in step 2:

```bash
sudo maknae enroll \
  --deployment-id <id> \
  --vault-addr https://<vault-host>:8200 \
  --vault-ca /path/to/vault-ca.pem \
  --rotate-seal-key
```

Then restart the Egress Daemon with the command enroll prints; until then every turn is refused with `OpenFailed(Seal)`. A re-enroll also rotates `maknaed`'s own Vault SecretID, rewrites the root `maknae.yaml` (set any raised `transport.prompt_max_bytes` again) and rewrites the `vault` block of your own `~/.maknae/maknae.yaml`. It does not touch `providers.yaml` or any other user's files.

## On macOS

The daemon's and the deputy's rows. Each message is quoted exactly; in each refusal row the `.err` line also carries the process's own prefix (`maknaed: refusing to start: `, or `maknae-egress: refusing to start: egress seal key: `), so those rows say "contains". The deputy's System-keychain item (service `io.maknae.maknae-egress`) holds its sealing private key, as hexadecimal.

| What you see | Why | Fix |
|---|---|---|
| `maknaed.err` or `maknae-egress.err` contains `keychain read refused (-25293): the keychain is locked, or this binary is not the Developer ID-signed one the item was enrolled for (an ad-hoc or re-signed build)` | the running binary is not the Developer ID build the item was enrolled for: an ad-hoc build of the same code is refused this way in a user or root session (measured, ADR-0018 decision 6); under launchd an untrusted binary was instead refused `-25308`, next row. The System keychain is unlocked by the system, so a locked keychain is not the cause here | reinstall the signed package; after changing the signing identity, re-enroll |
| … contains `keychain read needs user interaction, which is disabled (-25308): the calling program is not one the item trusts, in a context that cannot prompt (measured: a launchd daemon); run the Developer ID-signed build the item was enrolled for` | the program reading the item is not one the item trusts; in a launchd daemon that read is refused with `-25308` and no dialog (measured, ADR-0018 decision 6) | reinstall the signed package; after changing the signing identity, re-enroll |
| … contains `` no keychain item (-25300): not enrolled; run `sudo maknae enroll` `` | the pointer file names an item that no longer exists, typically after `packaging/macos/uninstall.sh` (which deletes the items but keeps `/etc/maknae` and its pointer files) and a reinstall | `sudo maknae enroll` |
| … contains `refusing the keychain read: running as uid N, not as _maknae` (or `_maknae-egress`) | the binary was started outside its launchd job | start it only through step 5 |
| … contains `keychain pointer: …` | the pointer under `/etc/maknae/private` or `/etc/maknae/egress` was edited | `sudo maknae enroll` |
| `maknaed.err` shows `maknaed: warning: this boot's credential posture is not hardware-root-of-trust sealed` | expected on every macOS boot that reaches the credential read: the posture is `code_bound`, not `hrot_sealed` | nothing to fix |

The CLI's rows. `maknae login` keeps your Vault token in your default keychain, usually the login keychain, as service `maknae-cli`, account `maknae-vault-token`; enroll writes no keychain item for you.

| What you see | Why | Fix |
|---|---|---|
| `maknae` contains `` no Vault token is stored: run `maknae login` `` | your default keychain has no `maknae-cli` / `maknae-vault-token` item: you have not logged in, you logged out, or you changed your default keychain since | `maknae login` |
| `maknae` contains `` the stored Vault token could not be read (keychain status -25293): run `maknae login` `` | your default keychain is locked, or this `maknae` is not a binary the item trusts (a replaced or re-signed build) (inferred; neither case was measured) | unlock your default keychain (`security unlock-keychain`), then `maknae login` |

## What stays true

- **`maknaed` never sees your key.** It admits each turn on the provider, the model and your account name, and passes on a sealed wrapping token it cannot open.
- **The Egress Daemon sees your key for one call.** It unwraps the token for that turn's provider call; it has no key cache.
- **Your own processes can read your own key.** Your Vault login can read it, so any process running as you can, outside any turn. This is a named residual (ADR-0028); detecting such reads is #429.
- **Another user cannot read your key.** Vault's policy limits each login to its own `<user_prefix>/<username>/`, and the kernel derives the key path from the uid that connected, never from a file.
- **Every action is decided before it happens and recorded.** That covers each prompt, read and write, and it holds for refusals too.
- **The deny list holds.** Reads under `~/.ssh`, `~/.aws` and similar are refused by policy, and nothing from them reaches the model.
- **On macOS the daemon's Vault SecretID and the deputy's sealing key are System-keychain items that only their own signed binaries can read.** The signed daemon read its item on a real install (measured); the deputy's read is inferred from the successful provider turns. They are bound to code identity under a root-held key, not to hardware. An administrator can approve a read in a console session (measured), and root can copy the keychain and its key and decrypt them off the host (inferred). See ADR-0018 decision 6.
- **What you did not ask for does not leave.** Only the conversation leaves the host, including file contents the agent was allowed to read.
