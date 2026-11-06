# Verification walkthrough

This page is for a verification event: an assessor at the keyboard, with the administrator beside them, checking that one user's model access and key stay apart from another's (C1 to C10), and that every client session is re-checked against the host (C11 to C16). Each claim below names the control that enforces it, the command that shows it, and what the command prints, copied from the code. Each claim also has a **Measured** line. It cites existing evidence or the named tests, or it says "not yet measured". Nothing on this page has been run end to end as one session.

Controls are cited two ways. A pair such as `cli_b × key_a` is a cell of the isolation matrix: a subject (`cli_a`, `cli_b`, `agentd`, `kernel`, `egress`, `vault`, `model`) against an object (`key_a`, `key_b`, `wrap`, `sealed`, `prompt`, `meta`). A step label in code type, such as `open the seal under this request's AAD`, names a step of the credential-path sequence diagram. Both diagrams are in `design/diagrams/`.

| ID | Claim | Measured |
|---|---|---|
| C1 | A's turn works | yes, single-user, on Rocky 10.2 and macOS 26.6.2 |
| C2 | B cannot read A's key in Vault | yes, one login against another user's path |
| C3 | An unwrapped read of your own key is refused | yes |
| C4 | B cannot redirect the kernel to A's key | by tests; the live CLI refusal is not yet measured |
| C5 | A wrapping token for A's path is refused when carried in B's turn | by tests |
| C6 | Only the Egress Daemon holds the seal private key | by tests on macOS; not yet measured on a host |
| C7 | An unlisted model is refused before any egress | yes, on Rocky 10.2 and macOS 26.6.2 |
| C8 | Revoking B's token stops B's next run and leaves A unaffected | not yet measured |
| C9 | Withdrawing a user's model access takes host authority, not their `providers.yaml` | not yet measured |
| C10 | Seal-key rotation fails closed until restart | yes, on Rocky 10.2; on macOS 26.6.2 without the deputy's log line |
| C11 | A process left behind by a logout is refused | by tests; not yet measured on a host |
| C12 | Removing a user from `maknae` refuses their next request | by tests; not yet measured on a host |
| C13 | An expired local account is refused | by tests; not yet measured on a host |
| C14 | A connection handed to another uid is refused (Linux) | by tests; not yet measured on a host |
| C15 | A `deployment.mode` the host contradicts does not run | by tests; not yet measured on a host |
| C16 | `deployment.mode: container` binds no client socket | by tests; not yet measured on a host |

## Before you start

**Two local users, A and B.** A is the administrator who ran `sudo maknae enroll`. B was added by [first-provider step 4a](first-provider.md#4a-add-another-local-user). Both are:

- listed in Terraform's `maknae_users` with a password set ([step 1](first-provider.md#1-create-the-user-in-vault));
- bound in `/etc/maknae/bindings.yaml` to a role that `/etc/maknae/authz.yaml` grants `session.prompt` and `provider:openai` (step 4a, part 3);
- logged in, each in their own login session ([U1](first-provider.md#u1-log-in));
- holding their own key at subpath `openai`, field `api_key` ([U2](first-provider.md#u2-store-your-key-in-vault));
- holding their own `~/.maknae/providers.yaml` with one entry for `openai` and `gpt-5.6-luna` ([U3](first-provider.md#u3-choose-your-provider)).

Below, `<A>` and `<B>` are their account names. `<kv>` is the KV v2 mount and `<prefix>` the user prefix (enroll's defaults: `maknae-kv` and `maknae/users`).

**B's tools work in B's home.** The kernel confines B's file actions to B's own home, so B's reads and writes are decided against B's `~`, not A's.

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

**Where refusals show.** A kernel refusal reaches the user only as one line, exit 2: `maknae agent: stopped: ` followed by the `PROMPT_REFUSED` text (`bins/maknae/src/agent.rs:95`, printed by `print_end`, `:349`). That text begins `the kernel refused the exchange — whether the prompt reached the provider is in the host's audit trail`, and it is quoted in full in [When it does not work](first-provider.md#when-it-does-not-work). The kernel's reason is only in the audit trail, which the administrator reads with `sudo jq`. The CLI's own setup refusals print after `maknae: ` and exit 1 (`bins/maknae/src/cli.rs:931`).

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

## C6. Only the Egress Daemon holds the seal private key

**Claim.** The kernel cannot open a sealed key, because the private key that opens it is delivered only to the Egress Daemon's process.

**Control.** `kernel × key_a` and `kernel × sealed`. On Linux, systemd decrypts the `maknae-egress-seal-key` credential (`/etc/maknae/private/maknae-egress-seal-key.cred`, `root:root 0400`) into the `$CREDENTIALS_DIRECTORY` of `maknae-egress.service`, which runs as `_maknae-egress`; `maknaed.service` loads no such credential. On macOS, the key is the System keychain item `io.maknae.maknae-egress`, whose ACL trusts only `/usr/local/bin/maknae-egress`, and the Egress Daemon refuses to read it unless it runs as `_maknae-egress` (`crates/maknae-vault/src/seal_key_io.rs:9`). Credential-path step: `admit (peer-uid username, set, model, subpath, field), PDP, destination stamp: metadata only`.

**Command, Linux.** On the host:

```bash
systemctl cat maknae-egress.service | grep '^LoadCredentialEncrypted='
systemctl cat maknaed.service | grep -c 'maknae-egress-seal-key'
sudo stat -c '%U:%G %a' /etc/maknae/private/maknae-egress-seal-key.cred
```

**Expected, Linux.**

```
LoadCredentialEncrypted=maknae-egress-seal-key:/etc/maknae/private/maknae-egress-seal-key.cred
0
root:root 400
```

(`packaging/common/maknae-egress.service:18`, `packaging/common/maknaed.service:44-45`, `bins/maknae/src/enroll/artifact_table.rs:222-228`.)

**Command, macOS.** The keychain ACL and the account check are shown by tests, on a macOS build host with the repository checked out:

```bash
cargo test -p maknae-vault an_untrusted_binary_is_refused_by_the_acl
cargo test -p maknae-vault a_pointer_reaches_the_keychain_read_only_as_the_egress_account
```

**Expected, macOS.** Both tests pass. The first reads an item whose ACL does not trust the test binary and expects the keychain's refusal (status `-25293`). The second reads the egress item as an account other than `_maknae-egress` and expects `WrongAccount`.

**Measured.** The macOS tests run on every pull request (`cargo test --locked --workspace` on the `darwin-native` job, `.github/workflows/ci.yml`). The Linux commands on a host: not yet measured.

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

**Control.** No matrix cell is keyed to token validity, so the control is cited by credential-path step. Every turn makes its own wrapped read of the key with the stored token (`bins/maknae/src/agent.rs:268`), and Vault refuses that read once the token is revoked. The CLI also mints its plane leaf with the token first (`bins/maknae/src/agent.rs:443`); until #116 the CLI refuses to connect when that mint fails, so a revoked token also stops B's CLI there. The daemon requests no client certificate and admits B by its kernel-attested uid and `maknae`-group membership, which a token revocation does not touch. Credential-path steps: `load the user token; choose the providers.yaml entry` and `wrapped read of <kv>/data/<prefix>/<user>/<subpath>, X-Vault-Wrap-TTL: 60s`. A's unaffected run rests on `cli_a × key_a`, A's own identity.

`maknae agent` runs one prompt per invocation (`bins/maknae/src/cli.rs:146-151`). So "mid-conversation" means between the loop steps of one run. This claim therefore uses fresh runs.

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
maknae: pki/sign rejected: <Vault's answer>
```

where `<Vault's answer>` is Vault's own text (`crates/maknae-vault/src/error.rs:194`, printed at `bins/maknae/src/cli.rs:735`). The CLI checks only the token's recorded expiry, not whether it was revoked (`bins/maknae/src/login.rs:90-101`), so the refusal comes from Vault at the certificate mint. In step 4, A gets a reply.

A run that is already past its mint would stop at its next turn's key read. That read gets a 403, printed as `` maknae agent: stopped: Vault refused to read the key for provider entry <label> (HTTP 403): the key is outside your Vault policy, or your login was revoked: run `maknae login` `` (`agent.rs:99-104`). This is from the code path, not shown live.

After the claim, B runs `maknae login` again.

**Measured.** Not yet measured.

## C9. Withdrawing a user's model access takes host authority

**Claim.** B's model access is withdrawn by host authority: B's role grant or destination in `/etc/maknae/authz.yaml`, the provider's entry in the root `providers:` set, or B's Vault access. B's own `~/.maknae/providers.yaml` is not an authorization control. Removing it only stops the shipped CLI.

**Control.** `kernel × meta`: the kernel admits each prompt against the root-owned provider set and the policy, never against the user's `providers.yaml`, which it does not read. `admit_choice` refuses a prompt with no provider choice, an empty set, or a provider outside the set (`crates/maknae-kernel/src/provider_choice.rs:68-74`). The PDP then refuses a destination that is not on the role's list, with the reason `destination not allowlisted for role <role>: provider:<name>` (`crates/maknae-authz-basic/src/decide.rs:297-302`; test `crates/maknae-authz-basic/src/decide.rs::prompt_with_the_grant_but_an_unlisted_destination_is_a_deny_naming_it`). `cli_b × key_b`: Vault policy and B's own login decide B's key read. Credential-path step: `admit (peer-uid username, set, model, subpath, field), PDP, destination stamp: metadata only`.

**Not a control.** Without a `providers.yaml`, the shipped CLI stops before it reads a key or contacts the daemon (`bins/maknae/src/agent.rs:77-89`; test `bins/maknae/src/agent.rs::the_entry_is_the_default_or_the_named_label_and_no_entries_means_no_model_access`). Credential-path step: `load the user token; choose the providers.yaml entry`. That is the CLI's own behaviour. A client that is not the shipped CLI can still send a valid provider choice, and the kernel admits it on host authority alone.

**Command.** The administrator removes `provider:openai` from B's role's `destinations` in `/etc/maknae/authz.yaml` (`sudoedit /etc/maknae/authz.yaml`; B's role is `user` in step 4a). Then reload the policy (`sudo systemctl reload maknaed`; on macOS, `sudo launchctl kill SIGHUP system/io.maknae.maknaed`): an edit applies at reload, not on the next request ([runbook](runbook.md#reload-the-policy)). Then, as B:

```bash
maknae agent "Reply with one word: hello."
```

The administrator then restores the line and reloads again. Separately, to see the shipped CLI's behaviour, as B:

```bash
mv ~/.maknae/providers.yaml ~/.maknae/providers.yaml.aside
maknae agent "Reply with one word: hello."
mv ~/.maknae/providers.yaml.aside ~/.maknae/providers.yaml
```

**Expected.** With the destination removed, B sees the `PROMPT_REFUSED` line, exit 2. In the administrator's audit query: `"result":"deny"`, `"reason":"destination not allowlisted for role user: provider:openai"`, with no `egress` block. If A shares B's role, A is refused the same way until the line is restored and the policy reloaded.

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

## Session checks (C11 to C16)

These use B, logged in over SSH. The administrator's audit query for them:

```bash
sudo jq -c 'select(.event=="connection" or .event=="session" or (.event=="request" and .outcome.result=="deny")) | {ts, event, action, session: .session_id, user: .subject.user, result: .outcome.result, reason: .outcome.reason}' /var/log/maknae/audit.jsonl | tail -n 6
```

A refusal at connect gets no answer, so the CLI exits non-zero without a daemon reply. A refusal at a request prints `maknae: daemon refused: Unauthorized: not authorized`. The reason is only in the trail ([runbook, Session checks](runbook.md#session-checks)).

## C11. A process left behind by a logout is refused

**Claim.** A process whose login session has ended is refused, even though its uid is enrolled.

**Control.** ADR-0006 decision 4 (iii), T11: the connecting process's own logind session must be `CLASS=user` and `active` or `online`; on macOS the audit session and a `utmpx` record or the console. Tests: `a_logged_out_process_is_refused_at_the_request`, `a_closing_record_is_not_active`, `a_process_outside_a_session_scope_has_no_session` (`crates/maknae-kernel`).

**Command.** As B, over SSH, with no other login for B on the host:

```bash
nohup sh -c 'sleep 30; maknae ping' > /tmp/maknae-c11.out 2>&1 &
exit
```

After 30 seconds, log in again and read `/tmp/maknae-c11.out`.

**Expected.** The file shows a failure, not `pong`. The trail has a `connection` / `connect` record for B with `"result":"deny"`, `"reason":"logout"`. The CLI reads B's stored login before it connects; if that read fails once B's session has ended, no record is written and the run does not count. On macOS, a GUI or second SSH login for B would let it through (the uid-scoped residual in ADR-0006 decision 4).

**Measured.** Not yet measured.

## C12. Removing a user from `maknae` refuses their next request

**Claim.** Group membership is read at every connect and every request, so de-enrollment needs no new login to take effect.

**Control.** ADR-0006 decision 4 (ii); T3. Tests: `a_member_de_enrolled_before_the_request_is_refused_at_the_request`, `a_non_member_is_refused_at_connect`.

**Command.** B keeps an SSH shell open. The administrator removes B: `sudo gpasswd -d <B> maknae` (macOS: `sudo dseditgroup -o edit -d <B> -t user maknae`). In B's open shell, whose groups still include `maknae`:

```bash
maknae ping
```

Then the administrator adds B back (`sudo usermod -aG maknae <B>`; macOS: `sudo dseditgroup -o edit -a <B> -t user maknae`).

**Expected.** `maknae ping` fails. The trail has a `connection` / `connect` deny with `"reason":"not-member"`. On an SSSD host the result waits on the host's cache (runbook, Session checks).

**Measured.** Not yet measured.

## C13. An expired local account is refused

**Claim.** On Linux with `deployment.account_source: userdb`, a local account `systemd-userdbd` reports expired, locked or not yet valid is refused.

**Control.** ADR-0006 decision 11, as corrected 2026-11-06. Tests: `a_locked_local_account_is_refused` (`crates/maknae-kernel/tests/accept_loop.rs`) and the record-mapping tests in `crates/maknae-kernel/src/session_facts/userdb.rs`. No host command makes a classic `/etc/passwd` account `locked` in userdb (`usermod -L` is not detected), so only expiry is checked live.

**Command.** B keeps an SSH shell open. The administrator expires B's account: `sudo chage -E "$(date -d yesterday +%F)" <B>`. In B's open shell:

```bash
maknae ping
```

Then the administrator restores it: `sudo chage -E -1 <B>`.

**Expected.** `maknae ping` fails, and the trail has a `connection` / `connect` deny with `"reason":"account-expired"`. On el9 (`account_source: none`) the request is served and the admission record reads `admitted (account: not-checked:configured)`.

**Measured.** Not yet measured.

## C14. A connection handed to another uid is refused (Linux)

**Claim.** Bytes written over a connection by any process other than the one that connected are refused; passing the descriptor carries no identity.

**Control.** ADR-0006 decision 4, T13: `SO_PASSCRED` on the listener and a per-read `SCM_CREDENTIALS` check. Tests: `a_mismatched_sender_is_refused_during_the_handshake` (`crates/maknae-vault`), `a_foreign_uid_is_refused` (`crates/maknae-plane`), `a_sender_mismatch_read_is_refused` (`crates/maknae-kernel`).

**Command.** B, in one shell, waits for a descriptor and writes into it:

```bash
python3 -c '
import os, socket
p = "/tmp/maknae-c14.sock"
s = socket.socket(socket.AF_UNIX); s.bind(p); os.chmod(p, 0o777); s.listen(1)
c, _ = s.accept()
_, fds, _, _ = socket.recv_fds(c, 1, 1)
os.write(fds[0], b"\x16\x03\x01\x00\x01\x00")
'
```

A, in another shell, connects to the daemon and hands B the connection:

```bash
python3 -c '
import socket, time
d = socket.socket(socket.AF_UNIX); d.connect("/run/maknae/maknaed.sock")
c = socket.socket(socket.AF_UNIX); c.connect("/tmp/maknae-c14.sock")
socket.send_fds(c, [b"x"], [d.fileno()]); time.sleep(10)
'
```

Remove `/tmp/maknae-c14.sock` afterwards.

**Expected.** The trail has a `connection` / `connect` deny for A's uid with `"reason":"sender-mismatch"`. macOS has no per-message sender credentials; there the record reads `tls handshake failed`, and the residual is bounded by the visit clock (ADR-0006 decision 4).

**Measured.** Not yet measured.

## C15. A `deployment.mode` the host contradicts does not run

**Claim.** The daemon verifies its declared mode against the host at every start and never runs a mode the host contradicts.

**Control.** ADR-0006 decision 4, boot self-verification. Tests: `a_linux_host_needs_systemd_and_no_file_marker`, `a_probe_that_cannot_answer_refuses` (`crates/maknae-kernel/src/deployment.rs`), `the_deployment_is_validated_and_carried`.

**Command.** On a Linux host, the administrator sets `mode: container` under `deployment:` in `/etc/maknae/maknae.yaml` and runs `sudo systemctl restart maknaed`, then `sudo journalctl -u maknaed -n 20`. Then restores `mode: linux-host` and restarts.

**Expected.** On a host that has run before, the daemon keeps running the accepted `linux-host` mode, and the trail has a `graph.baseline` deny, `baseline change refused: invalid (cause in the journal)`; the journal names the cause, `deployment.mode is container, but no container marker is present`. On a freshly enrolled host before its first start, the start itself is refused (exit 1) with the same cause.

**Measured.** Not yet measured.

## C16. `deployment.mode: container` binds no client socket

**Claim.** In container mode there is no client socket to reach, so a shell inside the container has nothing to connect to.

**Control.** ADR-0006 decision 4 §Platform scope, T12. Test: `only_a_container_binds_no_client_listener` (`crates/maknae-kernel/src/deployment.rs`).

**Command.** On a Linux test host, the administrator gives the unit a corroborating marker with `sudo systemctl edit maknaed` (`[Service]` and `Environment=container=c16`), sets `mode: container`, restarts `maknaed`, and runs `maknae ping` as A. Then removes the drop-in, restores `mode: linux-host` and restarts.

**Expected.** The journal has `maknaed: deployment.mode is container; no client listener is bound`, `/run/maknae/maknaed.sock` does not exist, and `maknae ping` fails to connect. The daemon writes no record for the attempt: there is nothing daemon-side to refuse it.

**Measured.** Not yet measured.

## Afterwards

These clean-up steps are not yet measured.

- B runs `maknae login` again (C8).
- Check that A's and B's `~/.maknae/providers.yaml` are their originals and that no `providers.yaml.orig` or `providers.yaml.aside` is left (C4, C7, C9).
- Run `unset VT` in every shell that read a token.
- If the event added B only for this check, remove B from `bindings:` in `/etc/maknae/bindings.yaml` and reload `maknaed` (step 4a, part 3), then remove B from `maknae_users` and apply.
