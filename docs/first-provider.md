# Your first model provider

This walkthrough connects Maknae to one model provider, so that `maknae agent` can hold a conversation: read a file, write a file, and answer you. Every step of that conversation is decided by the kernel and recorded before it happens.

It is written for a person doing this for the first time. For every key and every rule, see the [configuration reference](configuration.md) (§6.1 and §9.3). For the full acceptance procedure, including custody and SELinux checks, see [runbook Chapter 4](runbook.md).

## What you need first

- **A Linux host with the Maknae package installed and enrolled** (`sudo maknae enroll`; runbook Chapter 4, steps 1–3). Run enroll from a direct login whose `id -Z` shows `unconfined_u`, not from `sudo su` out of a confined account. macOS cannot run this yet: its enroll is not finished (#76).
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

- **`endpoint`** is the full chat-completions URL, sent exactly as written.
- **`key_vault_path`** is relative to the mount, with no `data/`, and must sit beneath the prefix from step 2.
- **`key_field`** is the field name inside the Vault secret.
- **`reasoning_effort`** is optional. Some models need it: `gpt-5.6-luna` refuses the agent's tools unless it is `none`. Leave it out if your model does not need it.
- **Root owns this file** on purpose. The agent runs as you, so you cannot redirect where its content goes by editing your own files.
- **The daemon's prompt cap**, `transport.prompt_max_bytes` in `/etc/maknae/maknae.yaml`, defaults to 1 MiB. That carries a context window of up to about 174,000 tokens. For a larger window, raise it to `context_tokens × 6` (at most 16 MiB).

Then declare the model's context window in **your own** configuration. `maknae agent` will not start without it:

```bash
cat >> ~/.maknae/maknae.yaml <<'EOF'
provider:
  context_tokens: 128000   # your model's context window, in tokens
  output_tokens: 16000     # optional: the reply cap
EOF
```

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

## 6. Talk to it

Paths must be absolute, and the shipped policy lets the agent write only under `~/projects/`:

```bash
mkdir -p ~/projects/hello
printf 'Maknae is a security kernel for AI agents.\n' > ~/projects/hello/input.txt
maknae agent "Read $HOME/projects/hello/input.txt, write a one-sentence summary of it to $HOME/projects/hello/output.txt, then tell me what you wrote."
cat ~/projects/hello/output.txt
```

The answer arrives with exit `0`. A stop prints `maknae agent: stopped: …` and exits `2`.

## 7. See what it did

```bash
sudo jq -c 'select(.action=="session.prompt" or .action=="fs.read" or .action=="fs.write") | {ts, action, object, result: .outcome.result, status: (.egress.status // .mutation.status)}' /var/log/maknae/audit.jsonl | tail -n 12
```

A read-then-write conversation shows:
- a `session.prompt` pair (`IntentOnly`, then `Sent`) for each model turn;
- an `fs.read` intent, then its reported completion;
- an `fs.write` intent, then its reported completion.

The intent is written before the action, every time. `content_length` on each prompt intent is exactly how much left the host.

## When it does not work

| What you see | Why | Fix |
|---|---|---|
| In the trail, `session.prompt` is denied with reason `egress backend not ready` | the deputy's socket is not running | `sudo systemctl enable --now maknae-egress.socket` |
| In the trail, `session.prompt` is denied with reason `no provider registered for session.prompt` | the daemon booted before the provider file existed | `sudo systemctl restart maknaed` |
| In the trail, `session.prompt` is denied with reason `role admin: no capability entry for session.prompt` | the policy has no grant | step 4 |
| `maknaed` will not start: `section 'provider' must come from a root-owned, non-group/other-writable source` | the provider file or its directory is writable by someone other than root | step 3's owner and mode |
| `maknaed` will not start: `… is outside the egress grant prefix …` | `key_vault_path` is not beneath `key_vault_path_prefix` | make the path sit under the prefix |
| The agent stops; the prompt outcome is `OutcomeUnknown`; `journalctl -u maknae-egress` shows `provider credential unavailable` | the deputy could not read the key from Vault: wrong mount, path or field, or its Vault policy does not allow the read | check steps 1–3 against your Vault |
| The agent stops; `journalctl -u maknae-egress` shows `provider answered 400 (conversation …): …` | the provider rejected the request's shape | the text after the colon is the provider's own reason, with the key masked. For `gpt-5.6-luna` it is the missing `reasoning_effort: none`; a server that names `max_completion_tokens` as unsupported needs `output_tokens_field: max_tokens` in step 3's file |
| `maknae agent` will not start: `provider.context_tokens is required by maknae agent` | your own configuration does not declare the window | step 3's `~/.maknae` block |
| `maknae agent: stopped: the conversation has reached the declared context budget; compaction arrives with #171` | the next turn would exceed the window you declared | start a new conversation, or declare the larger window your model has |
| `maknae agent: stopped:` with a connection error, on a long conversation | the daemon's prompt cap is below your loop's, so the daemon refused the frame and closed the connection | raise the daemon's `transport.prompt_max_bytes` (step 3) |
| `maknae agent: stopped: the conversation has reached the platform's frame bound` | your own `transport.prompt_max_bytes` in `~/.maknae` is smaller than your window needs; or, with none set, the conversation's encoded size outgrew `context_tokens × 6` bytes (many small turns, or text denser than 6 bytes per token) | remove the setting, and the loop derives its cap from `context_tokens`; otherwise start a new conversation |
| `journalctl -u maknae-egress` shows file or prompt text after `provider answered …` | some servers quote the rejected request in their error body | expected: the journal can hold up to 4 KiB of conversation content; limit who reads it (`docs/configuration.md` §6.2) |

## What stays true

- **Your key stays in Vault.** Only the egress deputy holds it, in memory. You and the daemon cannot read its credentials.
- **Every action is decided before it happens and recorded.** That covers each prompt, read and write, and it holds for refusals too.
- **The deny list holds.** Reads under `~/.ssh`, `~/.aws` and similar are refused by policy, and nothing from them reaches the model.
- **What you did not ask for does not leave.** Only the conversation leaves the host, including file contents the agent was allowed to read.
