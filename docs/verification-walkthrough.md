# Verification walkthrough

This page is for a verification event: an assessor at the keyboard, with the administrator beside them, checking that one user's model access and key stay apart from another's. Each claim below names the control that enforces it, the command that shows it, and what the command prints, copied from the code. Each claim also has a **Measured** line. It cites existing evidence or the named tests, or it says "not yet measured". Nothing on this page has been run end to end as one session.

Controls are cited two ways. A pair such as `cli_b × key_a` is a cell of the isolation matrix: a subject (`cli_a`, `cli_b`, `agentd`, `kernel`, `egress`, `vault`, `model`) against an object (`key_a`, `key_b`, `wrap`, `sealed`, `prompt`, `meta`). A step label in code type, such as `open the seal under this request's AAD`, names a step of the credential-path sequence diagram. Both diagrams are in `design/diagrams/`.

| ID | Claim | Measured |
|---|---|---|
| C1 | A's turn works | yes, single-user, on Rocky 10.2 and macOS 26.6.2 |
| C2 | B cannot read A's key in Vault | yes, one login against another user's path |
| C3 | An unwrapped read of your own key is refused | yes |
| C4 | B cannot redirect the kernel to A's key | by tests; the live CLI refusal is not yet measured |
| C5 | A wrapping token for A's path is refused when carried in B's turn | by tests |
| C6 | `maknaed` never links the seal | by CI; not yet measured on a host |
| C7 | An unlisted model is refused before any egress | yes, on Rocky 10.2 and macOS 26.6.2 |
| C8 | Revoking B's token stops B's next run and leaves A unaffected | not yet measured |
| C9 | Withdrawing a user's model access takes host authority, not their `providers.yaml` | not yet measured |
| C10 | Seal-key rotation fails closed until restart | yes, on Rocky 10.2; on macOS 26.6.2 without the deputy's log line |

## Before you start

**Two local users, A and B.** A is the administrator who ran `sudo maknae enroll`. B was added by [first-provider step 4a](first-provider.md#4a-add-another-local-user). Both are:

- listed in Terraform's `maknae_users` with a password set ([step 1](first-provider.md#1-create-the-user-in-vault));
- bound to a role in `/etc/maknae/authz.yaml` that is granted `session.prompt` and `provider:openai` (step 4a, part 3);
- logged in, each in their own login session ([U1](first-provider.md#u1-log-in));
- holding their own key at subpath `openai`, field `api_key` ([U2](first-provider.md#u2-store-your-key-in-vault));
- holding their own `~/.maknae/providers.yaml` with one entry for `openai` and `gpt-5.6-luna` ([U3](first-provider.md#u3-choose-your-provider)).

Below, `<A>` and `<B>` are their account names. `<kv>` is the KV v2 mount and `<prefix>` the user prefix (enroll's defaults: `maknae-kv` and `maknae/users`).

**B's prompts need no tools.** The kernel confines file actions to the enrolled administrator's home, so every read or write tool call B makes is refused. This is a known defect, #435 (step 4a). Give B prompts that need no file, such as `"Reply with one word: hello."`.

**B's prompt is visible to other local users.** On a multi-user host, other local users can read a running `maknae agent`'s prompt and `--provider` from its command line (#436, undecided).

**The `vault` CLI, in every shell that runs a `vault` command.** Point it at the Vault and CA your Maknae configuration uses:

```bash
export VAULT_ADDR=https://<vault-host>:8200        # vault.addr from ~/.maknae/maknae.yaml
export VAULT_CACERT=~/.maknae/tls/vault-ca.crt
```

Get a user token without replacing any token the `vault` CLI already holds, as in [U2](first-provider.md#u2-store-your-key-in-vault):

```bash
vault login -method=userpass -path=maknae-userpass -token-only username=<user>
```

Read it into the shell without echoing it. The commands below pass it as `VAULT_TOKEN="$VT"`.

zsh:

```zsh
read -rs "VT?Maknae user token: " && echo
```

bash (not yet measured):

```bash
read -rsp "Maknae user token: " VT && echo
```

Run `unset VT` when you are done.

**Never paste a wrapping token from a successful read.** A wrapped read of a key returns a token that wraps the key itself. None of the commands below asks for one.

**Where refusals show.** A kernel refusal reaches the user only as one line, exit 2: `maknae agent: stopped: ` followed by the `PROMPT_REFUSED` text (`bins/maknae/src/agent.rs:93`, printed at `:572`). That text begins `the kernel refused the exchange — whether the prompt reached the provider is in the host's audit trail`, and it is quoted in full in [When it does not work](first-provider.md#when-it-does-not-work). The kernel's reason is only in the audit trail, which the administrator reads with `sudo jq`. The CLI's own setup refusals print after `maknae: ` and exit 1 (`bins/maknae/src/cli.rs:735`).

The administrator's audit query for every claim below (the same on macOS):

```bash
sudo jq -c 'select(.action=="session.prompt") | {ts, user: .subject.user, object, result: .outcome.result, reason: .outcome.reason, status: .egress.status, model: .egress.model}' /var/log/maknae/audit.jsonl | tail -n 4
```

## C1. A's turn works

**Claim.** A, logged in with A's own key, gets a reply, and the trail records A, the provider and the model.

**Control.** `cli_a × key_a` (A's wrapped read of A's own key), `kernel × sealed` (the kernel passes the sealed blob on without opening it), `egress × key_a` (the Egress Daemon holds the key for one call) and `model × key_a`. Credential-path steps: `wrapped read of <kv>/data/<prefix>/<user>/<subpath>, X-Vault-Wrap-TTL: 60s`, `admit (peer-uid username, set, model, subpath, field), PDP, destination stamp: metadata only`, `lookup (creation_path, TTL), then unwrap` and `provider call, key as bearer`.

**Command.** As A:

```bash
maknae agent "Reply with one word: hello."
```

**Expected.** A reply on standard output, exit 0. In the administrator's audit query, a `session.prompt` pair for A: `status` `"IntentOnly"`, then `"Sent"`, each with `"user":"<A>"`, `"object":"provider:openai"` and `"model":"gpt-5.6-luna"`. The object is `provider:` followed by the provider's `name` (`crates/maknae-kernel/src/run.rs:1425`).

**Measured.** Single-user, 2026-10-02, on Rocky 10.2 (`.42`, RPM) as `byeori`: the reply `Hello hello hello hello hello`, and a `Sent` record with `subject.user` `byeori`, object `provider:openai`, `egress.model` `gpt-5.6-luna`. On macOS 26.6.2 (Wrathion, signed `.pkg`) as `aackerman`: the reply `Hello there, friend, nice to meet.`, and a `Sent` record with user `aackerman`, object `provider:openai`, model `gpt-5.6-luna`. The `IntentOnly` record was not noted on macOS. On both hosts a scan of the recent records found no `maknae/users`, `api_key`, `hvs.`, `openai/` or `subpath`. Two users on one host: not yet measured.

## C2. B cannot read A's key in Vault

**Claim.** B's Vault login cannot read A's key, wrapped or not.

**Control.** `cli_b × key_a`: the `maknae-user` policy grants each login only `<kv>/data/<prefix>/<its own userpass name>/*` (`deploy/vault-pki/main.tf:207`). Credential-path step: `wrapped read of <kv>/data/<prefix>/<user>/<subpath>, X-Vault-Wrap-TTL: 60s`.

**Command.** As B, with B's token in `VT`:

```bash
VAULT_TOKEN="$VT" vault read -wrap-ttl=60s <kv>/data/<prefix>/<A>/openai
```

**Expected.** Vault refuses with HTTP 403, `permission denied`. No wrapping token is returned.

**Measured.** 2026-10-02 on Wrathion (macOS 26.6.2): the login `aackerman` making a wrapped read of `byeori`'s key was answered 403 `permission denied`. In PR 4, on a throwaway Vault 2.0.0 with the shipped Terraform, another user's key was denied (#434, Verification). That was one login read against another user's path. From a second local account on one host: not yet measured.

## C3. An unwrapped read of your own key is refused

**Claim.** A direct, unwrapped KV read of A's own key is refused: Vault hands the key out only inside a wrapping token. This does not keep the key from A. A can make a wrapped read and redeem the token at `sys/wrapping/unwrap`, which returns the plaintext key, so any process running as A can read A's key. That is ADR-0028's accepted residual (#429), and this claim does not test it.

**Control.** `cli_a × key_a`: the `maknae-user` policy sets `min_wrapping_ttl = "1s"` on the key path (`deploy/vault-pki/main.tf:209`). The CLI also refuses a reply that carries the key instead of a wrapping token (`crates/maknae-vault/src/wrap.rs::an_unwrapped_response_is_refused`). Credential-path step: `wrapping token (a reply carrying the key is refused)`.

**Command.** As A, with A's token in `VT`:

```bash
VAULT_TOKEN="$VT" vault read <kv>/data/<prefix>/<A>/openai
```

**Expected.** HTTP 403, `permission denied`. Vault reports a `min_wrapping_ttl` violation as a plain permission denied, not as a wrapping error. It is the policy working, not a broken grant. The 403 shows only that the unwrapped read is refused.

**Measured.** 2026-10-02 on Wrathion (macOS 26.6.2) as `aackerman`: 403 `permission denied`. In PR 4, on a throwaway Vault 2.0.0 with the shipped Terraform, both an unwrapped read and an unwrapped write of a user key were refused (#434, Verification).

## C4. B cannot redirect the kernel to A's key

**Claim.** B cannot make the kernel name A's key path, whatever B writes in `providers.yaml`.

**Control.** `cli_b × key_a` and `cli_b × sealed`, and `kernel × meta`: the kernel builds the key path from the username of the uid that connected. It passes that username to `admit_choice` as a parameter (`crates/maknae-kernel/src/run.rs:862-865`, `provider_choice.rs:62`). The request has no username field (`ProviderChoice`, `crates/maknae-proto/src/wire.rs:254-260`). The kernel refuses a subpath with a `.`, `..` or `data` segment. The user sees only the `PROMPT_REFUSED` line. The administrator's audit query shows `"result":"deny"` with `"reason":"key subpath malformed"`. Credential-path step: `admit (peer-uid username, set, model, subpath, field), PDP, destination stamp: metadata only`.

**Command, part 1: the CLI's own refusal.** As B, point the entry's key at A's:

```bash
cp ~/.maknae/providers.yaml ~/.maknae/providers.yaml.orig
cat > ~/.maknae/providers.yaml <<'EOF'
providers:
  - label: openai
    provider: openai
    model: gpt-5.6-luna
    key:
      subpath: ../<A>/openai
      field: api_key
    context_tokens: 128000
EOF
maknae agent "Reply with one word: hello."
mv ~/.maknae/providers.yaml.orig ~/.maknae/providers.yaml
```

**Expected, part 1.** Exit 1, before any Vault or kernel contact:

```
maknae: providers.yaml: providers[0].key.subpath has a '.' or '..' segment
```

(`crates/maknae-config/src/providers.rs:105`; the `providers.yaml: ` prefix is `crates/maknae-config/src/error.rs:206`.)

**Command, part 2: the kernel's own refusal.** The CLI is untrusted, so its check proves nothing about the kernel. The kernel's check is shown by its tests. On a build host with the repository checked out:

```bash
cargo test -p maknae-kernel a_subpath_that_climbs_out_or_names_the_kv_artifact_is_refused
cargo test -p maknae-kernel an_admitted_choice_carries_the_sets_entry_the_choices_model_and_field_and_the_peers_path
```

**Expected, part 2.** Both tests pass. The first gives the kernel subpaths such as `../bob/openai` and `openai/../../bob` and expects `MalformedSubpath` for each. The second passes the username `alice` to `admit_choice` directly, standing in for the peer's name, and expects the admitted path `maknae/users/alice/openai/personal`.

**Measured.** By the named tests, which CI runs on every pull request (`cargo test --locked --workspace`, `.github/workflows/ci.yml`). The live CLI refusal: not yet measured. As two real users on one host: not yet measured.

## C5. A wrapping token for A's path is refused when carried in B's turn

**Claim.** If a wrapping token for A's key reached B's turn, it would be refused before it is unwrapped.

**Control.** `cli_b × wrap`, `cli_b × sealed` and `egress × wrap`. First, the seal's AAD binds the conversation, provider, model, key path and field, so a blob moved to another request does not open. Second, before it unwraps, the Egress Daemon looks the token up and refuses it unless its `creation_path` is the path this request was admitted for. Credential-path steps: `seal the wrapping token to seal.pub; AAD = conversation, provider, model, path, field`, `open the seal under this request's AAD` and `lookup (creation_path, TTL), then unwrap`.

**Command.** The shipped CLI cannot carry another user's token without changing code, so this claim is shown by tests. On a build host with the repository checked out:

```bash
cargo test -p maknae-vault another_users_token_is_refused_before_it_is_unwrapped
cargo test -p maknae-seal a_blob_retargeted_to_another_request_fails_to_open
```

**Expected.** Both tests pass. The first (`crates/maknae-vault/src/wrap.rs`) runs the real lookup check on a token created at `bob`'s path against a request for `alice`'s. It expects `WrapMismatch::CreationPath`, after one call, `lookup`, and no `unwrap`. The second (`crates/maknae-seal/src/seal.rs`) seals a token for one request, then changes each AAD part in turn: the conversation, provider, model, path (to `bob`'s) and field. The blob opens under none of them.

**Measured.** By the named tests, which CI runs on every pull request (`cargo test --locked --workspace`, `.github/workflows/ci.yml`).

## C6. `maknaed` never links the seal

**Claim.** The kernel cannot open a sealed key, because it does not contain the code that opens one.

**Control.** `kernel × key_a` and `kernel × sealed`. The gate fails if `maknae-seal` is reachable from `maknaed` or `maknae-kernel` (`ci/gates/lib.sh:12-13`). Credential-path step: `admit (peer-uid username, set, model, subpath, field), PDP, destination stamp: metadata only`.

**Command.** On a build host with the repository checked out:

```bash
bash ci/gates/seal-confinement.sh
```

**Expected.**

```
seal-confinement: ok
```

(`ci/gates/seal-confinement.sh:33`.) A failure prints `FAIL: seal-confinement: 'maknae-seal' is reachable from '<package>'` and exits 1.

**Measured.** CI runs the gate on every pull request (`.github/workflows/ci.yml`, step "Seal confinement — the kernel never links the unseal path (#153)"). On a host for this walkthrough: not yet measured.

## C7. An unlisted model is refused before any egress

**Claim.** A model that is not on the authorized provider's `models` list never leaves the host.

**Control.** `kernel × meta`: admission checks the model against the root-owned provider set before any send (`crates/maknae-kernel/src/provider_choice.rs:75-77`). Credential-path steps: `admit (peer-uid username, set, model, subpath, field), PDP, destination stamp: metadata only` and `PromptReply, or "not authorized"`.

**Command.** As A, with a model the administrator has not listed (`gpt-5.6` was used when this was measured):

```bash
cp ~/.maknae/providers.yaml ~/.maknae/providers.yaml.orig
cat > ~/.maknae/providers.yaml <<'EOF'
providers:
  - label: openai
    provider: openai
    model: <a model not in the root list>
    key:
      subpath: openai
      field: api_key
    context_tokens: 128000
EOF
maknae agent "Reply with one word: hello."
mv ~/.maknae/providers.yaml.orig ~/.maknae/providers.yaml
```

**Expected.** A sees `maknae agent: stopped: the kernel refused the exchange — …` (the full `PROMPT_REFUSED` line), exit 2. In the administrator's audit query: `"result":"deny"`, `"reason":"model not on the authorized provider's list"` (`provider_choice.rs:52`), with `object`, `status` and `model` all `null`. The record has no `egress` block, so nothing was sent.

**Measured.** 2026-10-02 on Rocky 10.2 (`.42`) and on macOS 26.6.2 (Wrathion), with `gpt-5.6`: the `PROMPT_REFUSED` line and exit 2. The trail showed `deny` with `model not on the authorized provider's list`, no object and no egress block.

## C8. Revoking B's token stops B's next run and leaves A unaffected

**Claim.** Once the administrator revokes B's Vault token, B gets no more model calls, and A carries on.

**Control.** No matrix cell is keyed to token validity, so the control is cited by credential-path step. Every run mints its client certificate with the stored token (`bins/maknae/src/agent.rs:535`), and every turn makes its own wrapped read of the key with that token (`agent.rs:373`). Credential-path steps: `load the user token; choose the providers.yaml entry` and `wrapped read of <kv>/data/<prefix>/<user>/<subpath>, X-Vault-Wrap-TTL: 60s`. A's unaffected run rests on `cli_a × key_a`, A's own identity.

`maknae agent` runs one prompt per invocation (`bins/maknae/src/cli.rs:146-151`). So "mid-conversation" means between the loop steps of one run, and B's file tools are refused (#435), which leaves no reliable window inside a run. This claim therefore uses fresh runs.

**Command.**

1. B completes one turn: `maknae agent "Reply with one word: hello."`
2. The administrator, with an administrator Vault token, finds every token issued to B's login and revokes it. `maknae login` keeps B's token in B's own custody and never prints it or its accessor, so B cannot hand it over. Listing accessors needs a token with `sudo` on `auth/token/accessors`. This step is not yet measured. Matching on `.data.meta.username` is inferred from a test fixture (`crates/maknae-vault/src/user_login.rs:164`), not observed on a real token:

   ```bash
   for a in $(vault list -format=json auth/token/accessors | jq -r '.[]'); do
     if [ "$(vault token lookup -format=json -accessor "$a" | jq -r '.data.meta.username // empty')" = "<B>" ]; then
       vault token revoke -accessor "$a"
     fi
   done
   ```

   The same loop works in zsh and bash. An alternative, also not yet measured, is `vault token revoke -mode=path auth/maknae-userpass/login/<B>`. It needs `sudo` on `sys/leases/revoke-prefix`. It is a prefix match, so it also revokes the tokens of any user whose name begins with `<B>`.
3. B runs a fresh `maknae agent "Reply with one word: hello."`.
4. A runs `maknae agent "Reply with one word: hello."`.

**Expected.** In step 3, B's run stops before it reaches the daemon, exit 1, with a line that begins:

```
maknae: pki/sign rejected: 
```

followed by Vault's answer (`crates/maknae-vault/src/error.rs:176`, printed at `bins/maknae/src/cli.rs:735`). The CLI checks only the token's recorded expiry, not whether it was revoked (`bins/maknae/src/login.rs:90-101`), so the refusal comes from Vault at the certificate mint. In step 4, A gets a reply.

A run that is already past its mint would stop at its next turn's key read. That read gets a 403, printed as `` maknae agent: stopped: Vault refused to read the key for provider entry <label> (HTTP 403): the key is outside your Vault policy, or your login was revoked: run `maknae login` `` (`agent.rs:99-104`). This is from the code path, not shown live.

After the claim, B runs `maknae login` again.

**Measured.** Not yet measured.

## C9. Withdrawing a user's model access takes host authority

**Claim.** B's model access is withdrawn by host authority: B's role grant or destination in `/etc/maknae/authz.yaml`, the provider's entry in the root `providers:` set, or B's Vault access. B's own `~/.maknae/providers.yaml` is not an authorization control. Removing it only stops the shipped CLI.

**Control.** `kernel × meta`: the kernel admits each prompt against the root-owned provider set and the policy, never against the user's `providers.yaml`, which it does not read. `admit_choice` refuses a prompt with no provider choice, an empty set, or a provider outside the set (`crates/maknae-kernel/src/provider_choice.rs:68-74`). The PDP then refuses a destination that is not on the role's list, with the reason `destination not allowlisted for role <role>: provider:<name>` (`crates/maknae-authz-basic/src/decide.rs:297-302`; test `crates/maknae-authz-basic/src/decide.rs::prompt_with_the_grant_but_an_unlisted_destination_is_a_deny_naming_it`). `cli_b × key_b`: Vault policy and B's own login decide B's key read. Credential-path step: `admit (peer-uid username, set, model, subpath, field), PDP, destination stamp: metadata only`.

**Not a control.** Without a `providers.yaml`, the shipped CLI stops before it reads a key or contacts the daemon (`bins/maknae/src/agent.rs:77-89`; test `bins/maknae/src/agent.rs::the_entry_is_the_default_or_the_named_label_and_no_entries_means_no_model_access`). Credential-path step: `load the user token; choose the providers.yaml entry`. That is the CLI's own behaviour. A client that is not the shipped CLI can still send a valid provider choice, and the kernel admits it on host authority alone.

**Command.** The administrator removes `provider:openai` from B's role's `destinations` in `/etc/maknae/authz.yaml` (`sudoedit /etc/maknae/authz.yaml`; B's role is `user` in step 4a). Do not edit `bindings:`, so no restart is needed: the policy is re-read on every request ([step 4a](first-provider.md#4a-add-another-local-user)). Then, as B:

```bash
maknae agent "Reply with one word: hello."
```

The administrator then restores the line. Separately, to see the shipped CLI's behaviour, as B:

```bash
mv ~/.maknae/providers.yaml ~/.maknae/providers.yaml.aside
maknae agent "Reply with one word: hello."
mv ~/.maknae/providers.yaml.aside ~/.maknae/providers.yaml
```

**Expected.** With the destination removed, B sees the `PROMPT_REFUSED` line, exit 2. In the administrator's audit query: `"result":"deny"`, `"reason":"destination not allowlisted for role user: provider:openai"`, with no `egress` block. If A shares B's role, A is refused the same way until the line is restored.

Without the file, exit 1:

```
maknae: no model access: no providers are defined in <B's home>/.maknae/providers.yaml
```

(`agent.rs:83-86`.) The last command restores the file.

**Measured.** Not yet measured.

## C10. Seal-key rotation fails closed until restart

**Claim.** After the seal key is rotated, an Egress Daemon still holding the old key refuses every turn. It does not fall back to anything, and a restart recovers.

**Control.** `egress × sealed` and `egress × wrap`: a blob sealed to the new public key does not open under the old private key (`crates/maknae-seal/src/seal.rs::a_blob_sealed_to_another_key_fails_to_open`), and an opener failure is answered `RefusedBeforeSend` (`bins/maknae-egress/src/serve.rs::an_opener_failure_is_answered_refused_before_send`). Credential-path steps: `open the seal under this request's AAD` and `content, or RefusedBeforeSend → Failed`.

**Command.**

1. The administrator runs the full enroll from [runbook](runbook.md) Chapter 4, step 3, with `--rotate-seal-key` added. It needs the administrator Vault token. It also rotates `maknaed`'s own SecretID and rewrites the root `maknae.yaml`, so set any raised `transport.prompt_max_bytes` again afterwards:

   ```bash
   sudo maknae enroll \
     --deployment-id <id> \
     --vault-addr https://<vault-host>:8200 \
     --vault-ca /path/to/vault-ca.pem \
     --rotate-seal-key
   ```

   Do not restart the Egress Daemon yet.
2. A runs `maknae agent "Reply with one word: hello."`.
3. The administrator restarts the Egress Daemon with the command enroll printed: `sudo systemctl try-restart maknae-egress.service`, or on macOS `sudo launchctl kickstart -k system/io.maknae.maknae-egress`.
4. A runs the same prompt again.

**Expected.** In step 2, A sees the `PROMPT_REFUSED` line, exit 2. In the audit query: `"result":"deny"`, `"reason":"send failed"` (`crates/maknae-kernel/src/egress.rs:577`), `"status":"Failed"`. The deputy's journal (`sudo journalctl -u maknae-egress`; on macOS, `sudo tail /usr/local/var/log/maknae-egress/maknae-egress.err`) shows:

```
maknae-egress: connection refused: OpenFailed(Seal)
```

(`bins/maknae-egress/src/main.rs:157`.) In step 4, A gets a reply.

**Measured.** 2026-10-02 on Rocky 10.2 (`.42`): after `enroll --rotate-seal-key`, the prompt was refused, with the journal showing `OpenFailed(Seal)` and the trail `deny` `send failed`, `Failed`. After `systemctl try-restart maknae-egress.service`, the prompt got the reply `Hi there`. On macOS 26.6.2 (Wrathion): after `enroll --rotate-seal-key`, the prompt was refused, with the trail status `Failed`, `send failed`. After `launchctl kickstart -k system/io.maknae.maknae-egress`, the prompt got the reply `Hi there`. The `OpenFailed(Seal)` line in `maknae-egress.err` on macOS: not yet measured.

## Afterwards

These clean-up steps are not yet measured.

- B runs `maknae login` again (C8).
- Check that A's and B's `~/.maknae/providers.yaml` are their originals and that no `providers.yaml.orig` or `providers.yaml.aside` is left (C4, C7, C9).
- Run `unset VT` in every shell that read a token.
- If the event added B only for this check, remove B from `bindings:` in `/etc/maknae/authz.yaml` and restart `maknaed` (step 4a, part 3), then remove B from `maknae_users` and apply.
