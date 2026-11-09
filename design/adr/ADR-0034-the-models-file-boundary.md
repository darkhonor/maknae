# ADR-0034: The model's file boundary — no home confinement; the OS, the grants, the ceiling and `sensitive.yaml` bound every `fs.*` path

- **Status:** Accepted (maintainer-ruled 2026-11-08 and 2026-11-09)
- **Date:** 2026-11-09
- **Deciders:** Alex Ackerman (maintainer)
- **Raised by:** [#617](https://github.com/darkhonor/maknae/issues/617), with [#161](https://github.com/darkhonor/maknae/issues/161) (`fs.stat`, `fs.list`) built on the same boundary
- **Amends:** [ADR-0009](ADR-0009-subject-side-os-dac-evaluation.md) decisions 3, 4, 5 and 7, in place, with dated banners

## Context

Maknae's `fs.*` verbs (`fs.read`, `fs.write`, `fs.delete`, `fs.mkdir`, and with #161 `fs.stat` and `fs.list`) are how the model touches files. Until this ADR the kernel confined every one of them to the requester's home, whatever `authz.yaml` granted: `maknae_io::verify_delegated` refused any descriptor whose kernel-reported path was not beneath `DelegatedRequired::confined_beneath`, and refused a home any non-owner could write (`root_required`, a `stat` of the home). That broke real hosts. On the maintainer's development host the source tree is `/opt/Development`, and no grant could open it. The maintainer ruled (2026-11-08, #170 amendment 12): *the only file system restrictions are those the OS imposes; the kernel should not be restricting conversations to only home.*

The confinement also did a second job nobody had written down: it kept the model away from everything sensitive outside the home, such as `/etc/passwd`, `/proc/*/environ` and `/run/user/*`. Removing it without a replacement would open all of these. Users also keep secrets wherever their account can write (`~/.openrouter-api-key`, `~/.vcenter-login-creds` are real names on the maintainer's machine). Maknae cannot police the user, but it can ship a protective default and let each user add to it.

## Decision

### 1. Four bounds on a model's file request, and no home root

A file request is bounded by exactly four things, all of which must allow it:

1. **The OS's DAC on the delegated descriptor.** The subject opens the object under its own credentials (ADR-0009 decisions 1 and 2), so the OS has already answered, with ACLs, supplementary groups, SELinux and AppArmor all applied.
2. **The `authz.yaml` grants**, decided by `maknae-authz-basic` on the kernel-reported path.
3. **The classification ceiling** (ADR-0022), a mandatory operand.
4. **`sensitive.yaml`** (decision 5), a mandatory operand.

There is no home root. `maknae_io::DelegatedRequired` names only its target checks; `MutationRequired` is gone, and `verify_mutation_directory` takes only the descriptor. A grant beyond `~` (`Read(/opt/Development/**)`) reaches beyond the home, which is the point. A path outside the home without such a grant is refused by the PDP with its own reason (`no capability entry for fs.read`), not at preparation.

*Why one verification function and not a second, "unconfined" one:* ADR-0009 made the unconfined state inexpressible because confinement was a proof every caller needed. With no confined caller left, a second function name would be dead code. The intent that survives is that a caller names what it verifies, and `None` never stands in for a root. `TargetRequired`'s named fields carry that.

### 2. The path the kernel reports is the decided path; a single link makes deciding on it sound

Every decision is made on the path the kernel reports for the open object (`/proc/self/fd/N` on Linux, `F_GETPATH` on macOS), read from the daemon's own fd table (ADR-0009 decisions 4 and 6). That is unchanged.

`nlink_exactly_one` (ADR-0009 decision 5) changes job. It used to make prefix-checking a sound containment proof. Now it makes path *matching* sound. A file with a second name could be reached under a path no grant, no deny and no `sensitive.yaml` entry names: `~/proj/x` as a hard link to a protected file. With exactly one link the kernel reports *the* path, not *a* path. That makes the requirement load-bearing for `sensitive.yaml` and the deny list, and it may not be relaxed without superseding this decision. Its other two jobs (refusing hard-link aliases, detecting deletion through `nlink == 0`) are unchanged.

### 3. The home's soundness check is removed, and nothing replaces it one-for-one

ADR-0009 decision 7 kept the anchor *requirement* after dropping the anchor *open*: a `stat` of the home, refusing one that any non-owner could write ("a root any non-principal can write is not a boundary"). With no root there is nothing for it to check. A group-writable home no longer refuses a read.

Nothing takes its place directly, because what it guarded is now covered by the facts that were always the real proof:

- **A planted symlink** resolves to its target, and the decision is made on the target's path (ADR-0009 decision 6).
- **A planted hard link** is refused by `nlink_exactly_one` (decision 2).
- **What the subject can open at all** is the OS's answer to the subject's own `open(2)`.

The one case left is a rename by someone who can write the directory. That is ADR-0009's existing rename residual ("resolving the name defeats aliases, not renames"), and this ADR does not widen it.

### 4. The home stays a pattern anchor, and an unresolvable home still refuses every `fs.*` request

`~` in a grant or a `sensitive.yaml` entry is still the requester's canonical home, resolved per request and bound through the kernel-stamped `SUBJECT_HOME` attribute (ADR-0009 decision 4, amended 2026-10-04). The home is now an anchor for patterns, not a fence.

**A home that cannot be resolved (any `HomeUnavailable` cause: `unresolvable`, `timed out`, `at capacity for this requester`, `at capacity`) refuses every `fs.*` request before the PDP, as it did before this ADR.** That includes a request for an absolute path no `~` pattern needs. This is fail-closed: an operand that skipped the `~` entries during a passwd-lookup outage would open `~/.ssh` by absolute path. It supersedes the design's earlier sentence that "a request whose matching needs no home is decided without one" (plan review, spec amendment A2). The `sensitive` operand's `Unbound → Indeterminate` answer stays as defence in depth for any caller that reaches the PDP without a home. During such an outage a host-protected path gets the uniform answer (decision 7), not `Protected` (decision 8), because the refusal comes before the site that would say `Protected`.

`prepare()`'s own `home == "/"` refusal is removed. It existed only because `/` as a root confines nothing. A `/` home is still refused upstream: `maknae_io::canonical_home` returns no home for `/`, which is `requester home unavailable: unresolvable` (ADR-0009 decision 4's 2026-10-04 cause list). A `/` home would also make `~/**` mean `/**`.

**Deleting the requester's home, or a directory that contains it, is refused** (`cannot delete the requester's home`), whatever the grants say. Before this ADR the root made that impossible by construction. The refusal now names the home and every ancestor of it, so `fs.delete -r` of the home's parent does not remove the home. The check compares the kernel-reported path with the canonical home byte-wise, which leaves two **named residuals**: on macOS a case variant of the home's leaf (`/Users/ALICE` for `/Users/alice`) on a case-insensitive volume, and on Linux a same-device bind-mount alias of the home, each pass it. Either needs write permission on the home's parent and a grant broad enough to cover the alias. The OS's DAC still applies to the subject's own namespace syscalls, and the recursive walk's `same_path` check still confines it to the tree it was granted.

### 5. `sensitive.yaml`: a mandatory operand that never permits

A list of path patterns that never reach the model, in two files:

| | Host | Personal |
|---|---|---|
| Path | `/etc/maknae/sensitive.yaml` | `<config dir>/sensitive.yaml` (default `~/.maknae`) |
| Read by | `maknaed`, through `maknae-io` | the client, through `maknae-io` |
| Ownership | root, mode as `authz.yaml` (owner 0, mask `0o027`), in a root-owned directory that is not group- or other-writable | the user's own (`CONFIG_ARTIFACT`, mask `0o007`) |
| Absent | `maknaed` refuses to start | no personal entries |
| Malformed | refuses start; a reload that fails keeps the enforced list | the client refuses to open the conversation and names the file and the cause |

The grammar is `schema_version: 1` and `sensitive:`, a list of `PathGlob` strings: absolute or `~`-anchored, `**` for any depth, `*` within one component. `~name` is refused, unknown keys are refused, and so are `.`/`..` components and a missing `sensitive:` key. There is no `Read(...)`/`Write(...)` wrapper. An entry covers every file verb, writes included, for every role, `admin` included. **`~` is the requesting user's home** (maintainer ruling 2026-11-09). Another account's files are bounded by the OS's permissions, exactly as outside Maknae, and the shipped defaults carry no per-account twins; an administrator who wants every account covered lists the absolute pattern (`/home/*/.ssh/**`, `/Users/*/.ssh/**`) in `/etc/maknae/sensitive.yaml`.

The list is decided by a third named, non-removable field of `Composition`, beside the baseline and the ceiling. In ADR-0020's vocabulary it is a mandatory (MAC-type) operand. For `fs.read`, `fs.write`, `fs.delete`, `fs.mkdir`, `fs.stat` and `fs.list` it answers `Deny` when the kernel-reported path matches an entry of the host list or of the request's personal list, and `NotApplicable` otherwise. It never `Permit`s. Every other `fs.*` action (`fs.move`, `fs.link`, `fs.chmod`, `fs.chown`) gets `Indeterminate`, so a file action this operand does not yet decide fails closed; every non-file action gets `NotApplicable`. `combine` is deny-overrides, so a match denies whatever the baseline grants. A `DeleteTree` is denied when any entry could match beneath its root, so a protected file cannot be removed by removing its parent. The audit reason names the list and the entry: `sensitive: host <entry>` or `sensitive: personal <entry>`.

The host list and the baseline's grants are taken from one snapshot per decision batch, so a reload can never pair one snapshot's grants with another snapshot's list.

A file request the operand cannot evaluate is `Indeterminate`, which `finalize` denies. That is the whole list: no path, or a path that is not a string; a path that is not canonical; a home that is not a string; a personal value that is not a set, or a personal entry that does not parse; an `fs_operation` that is not a string or names no known operation; or a `~` entry with no home when no other entry matches. An `fs.delete` that names no operation is decided as a tree.

**Path forms.** A deny that misses because the same file has a different spelling is a permit, so matching folds every form the kernel can report for one object:

- **macOS:** case-insensitive, by Unicode lowercase (`str::to_lowercase`) of the entry, the path and the home that anchors `~`. A leading `/System/Volumes/Data` is stripped, and a leading `/private/etc`, `/private/tmp` or `/private/var` is mapped to `/etc`, `/tmp` or `/var`, on both the entry and the path. An entry written either way therefore matches what `F_GETPATH` reports, and no entry needs a `/private` twin. APFS is also normalization-insensitive. An entry and a path that differ only in NFC versus NFD are a **named residual**: such an entry can miss.
- **Linux:** byte-wise and case-sensitive, as `PathGlob` already is. **Measured 2026-11-09 on Rocky 9** with a receiver under `systemd-run -p PrivateTmp=yes -p ProtectHome=read-only` (the shipped `maknaed.service` sandbox) given `O_PATH` descriptors over `SCM_RIGHTS`: `/proc/self/fd/N` reads the host path for `/tmp/krb5cc_1001`, `/run/user/1001/sensitive-probe` and `/tmp/maknae-probe-1001`. The shipped `/tmp` and `/run/user` entries therefore bind on the reported path under that sandbox, and no extra spellings are needed. Two Linux spellings are **named residuals**: a bind mount reports the path it is reached through, so an entry misses a protected file reached through a bind-mount alias that no entry names; and a case-insensitive mount (ext4 `casefold`, `ciopfs`) accepts a case variant the byte-wise match does not fold. Either needs an operator to have set up the mount.

**One list, not two; the defaults ship.** The credential denies the shipped `authz.yaml` carried (`Read(...)` and `Write(...)` of `~/.ssh/**`, `~/.gnupg/**`, `~/.aws/**`, `~/.vault-token`, `~/.netrc`, `~/.git-credentials`, `~/.kube/**`, `~/.docker/config.json` and `~/.maknae/**`, 18 entries) moved into the shipped `sensitive.yaml`. The shipped `authz.yaml` keeps its two allows and an empty `deny:`; `deny:` stays in the grammar for denies one role holds and another does not. Every package (rpm, deb, macOS) installs `/etc/maknae/sensitive.yaml` `root:_maknae 0640`, keeps an operator's edit across an upgrade, and the egress deputy's AppArmor profile denies it. The shipped entries come from a read-only survey of Debian 13, Rocky 9, a STIG'd Rocky 10 and macOS 26 (2026-11-09), grouped and commented in the file: account and password files, sudo and polkit, host identity and service secrets, private keys, defensive configuration (audit, AIDE, fapolicyd, USBGuard, the firewall, cron, the boot loader), root's home and system secret state, Maknae's own configuration, `/proc/*/{environ,cmdline,mem}` with their `task/*` and `thread-self` forms, `/run/user/*/**`, Kerberos caches, mounted secrets, the macOS account database and keychains, and each user's credential, browser, mail and history files. `/etc/passwd` and `/etc/group` are on the list although they are world-readable and some legitimate work reads them; the maintainer named both. **Upgrade residual.** A host that already holds a hand-written `/etc/maknae/sensitive.yaml`, such as `sensitive: []` from an intermediate build, keeps that file on upgrade: rpm leaves the shipped one as `.rpmnew`, deb keeps the local conffile, and the macOS package installs only when the file is absent. An unedited `authz.yaml` on the same host is replaced and loses its 18 denies, so those paths are unprotected until the operator merges the shipped defaults into the kept file. No released package is affected. The effective decisions of the two shipped files through the `Composition` are pinned in `crates/maknae-kernel/src/testdata/shipped-effective-decisions.txt`, and the baseline operand's alone in `crates/maknae-authz-basic/src/testdata/shipped-decisions.txt`.

### 6. The personal list protects conversations; the host list protects every request

The kernel never reads a home directory (#365). The client reads the personal file and sends its entries in `session.new`. The kernel validates each entry with the same parser, refuses the whole `session.new` if one fails, and stores the entries on the conversation record. The list is a **snapshot**: an edit takes effect in the next conversation.

The personal list applies to a request only when that request **cites a conversation the requester owns**. A cited conversation owned by someone else contributes nothing. **The personal list therefore binds only requests that cite the conversation. It is not a control against a loop that declines to cite.** An altered client or loop can leave the citation off. That client can already read anything as the user, which is ADR-0009's existing untrusted-client residual, not a new one. An entry can only deny, so the worst a wrong or hostile personal entry does is hide the user's own file from the user's own model.

The host list binds **every** file request, conversation or not, including the user's own direct CLI commands (`maknae read`, `write`, `delete`, `mkdir`) and requests on the agent channel (`SUBJECT_AGENT` set). The kernel cannot tell the user's direct command from the untrusted loop's, so exempting requests that cite no conversation would let a tampered loop drop the citation and reach `~/.ssh`. Agent-channel tasks get the host list only.

### 7. One answer for every refusal

The model does not learn that a refused file exists. Every refusal of a file verb reaches the model as one constant, `unavailable — do not retry`, whatever the cause: missing, unarmable, denied by a grant, refused by the OS, refused by the ceiling, refused by `sensitive.yaml`, or refused by a descriptor check (multiple links, wrong kind). The same text also covers transport and capacity faults, so it names no cause. The standing prompt (`crates/maknae-llm/prompt/core-prompt.txt`) says what it can mean: some files are withheld by policy and look exactly like missing ones, so the model must not infer state (logged in, configured, installed) from a credential or configuration file it could not read, must check that state with the tool that owns it, and must never ask the user to paste a credential, key or token. The prompt names no file and no list.

A few answers stay distinct because they reveal nothing about a path: `outcome unknown` for a write whose effect may have landed, a malformed tool call, and the step budget. **The write rule is certainty of no effect.** A write that certainly had no effect gets the uniform answer: a refusal in place of the grant, which the kernel sends only before any effect, and, inside a granted attempt, any failure decided before a write syscall was attempted (the subject's open for writing refused by the OS, as for a mode `0000` file, a changed object, or a stale base the subject cannot read back). A write that may have had an effect, because a write syscall was attempted or the outcome was lost, stays `outcome unknown`. `maknae_io::MutationFailure::before_write` marks the first kind.

**Writes need `Read` as well as `Write`** (spec amendment A4). Every `fs.write`, creating or replacing, is permitted only when the PDP permits both `Write` and `Read` on the same path. Otherwise a `Write`-only grant would create a missing file but refuse an existing one, and the difference would tell the model the file exists. **A `Write`-only grant now permits nothing**, for the user's direct CLI as for the model. `not written — the file exists and you have not read it` (`WriteBase::Unread`) and the stale-base answer are released only when the loop's own read-open of the file succeeds; otherwise the write certainly had no effect and gets the uniform answer.

The audit trail distinguishes every cause. A write refused by its `Read` half is recorded with the reason `fs.write needs fs.read: ` followed by the read's own reason. ADR-0019's rule of no disclosure without a durable record is unchanged.

### 8. A protected path answers `Protected`, decided on the asked path

Decision 7 hides *existence*. Whether a *path* is protected is a different fact: the shipped list is public, and saying "this path is protected" stops the model from guessing that it is not logged in, or from asking the user for a credential.

- For every file verb the kernel matches the path the request **asks for** (after the lexical pre-gate) against both lists, **before** it looks at any descriptor. A match is refused with the additive error code `Protected`, whether or not the file exists, so the answer depends only on the path. An unarmed request for a protected path answers `Protected` too. The client renders `Protected` before it considers whether the request was armed, so an unarmed protected request reads exactly like an armed one.
- Enforcement still runs on the kernel-reported path (decision 5). A request whose asked path is not protected but whose descriptor resolves to a protected object, such as a symlink, is refused with the uniform answer, not `Protected`.
- The user is told precisely. The CLI prints the path, the list and the matching entry, and says to run the command outside Maknae; `maknae agent` prints the same notice on stderr for the refused tool call. The model is told only `protected by policy — ask the user to do this outside Maknae`, which names no entry. The wire refusal carries the list and entry for the client, which never passes them to the model.
- **What it reveals:** that a path is on a list. For the host list that is public. For the personal list it says the user listed the path, never that the file exists. This is accepted, because it is the user's own list protecting the user's own file.

### 9. Shipped grants do not widen

The shipped `authz.yaml` allows `Read(~/**)` and `Write(~/projects/**)` site-wide, and no shipped role grants any `fs.*` term. With no root, each of those still matches only beneath the requester's home. A symlink in the home that resolves outside it is decided on the target's path, which `~/**` does not match. No shipped grant matches a wider set of paths after this ADR than before it, and only an operator-written grant beyond `~` reaches outside the home. What does widen is decision 3's removal: a request beneath a home that any non-owner can write is no longer refused for that reason, so a read the shipped `Read(~/**)` matches in a group-writable home is now served.

### 10. Obligation on any future command verb

Maknae has no command verb (`Bash` was retired). When it gives the model a way to run commands, those commands must honour both `sensitive.yaml` lists, or the file block is cosmetic: `cat ~/.docker/config.json` through a shell reaches what `fs.read` cannot. Honouring both lists is a precondition on that verb. A command verb that does not honour them may not ship.

## Consequences

- **Outside-home work becomes possible.** `Read(/opt/Development/**)` serves `/opt/Development/...`, and the same path without the grant is refused by the PDP with its own reason.
- **Refusal reasons move.** A request outside the home used to be refused at preparation with `read evidence refused: escapes the anchor` or `namespace location evidence refused: escapes the anchor`. It is now decided, and refused, by the PDP with its reason, such as `role user: no capability entry for fs.write`. `EscapesAnchor` is no longer produced for a delegated descriptor.
- **The 0700 property survives.** No step opens or traverses the home. Matching `~` needs only the canonical home string, and the decided path comes from the daemon's own fd table, so a STIG `0700` home stays servable (#194).
- **macOS trail gap until [#368](https://github.com/darkhonor/maknae/issues/368).** On macOS the subject's regular-file descriptor is `O_RDONLY|O_NONBLOCK`, not a no-access descriptor. A file the subject cannot open yields no descriptor whether it is missing or OS-refused, so the macOS trail records both as `unarmed`. Tests that distinguish the two causes in the trail run on Linux. A `stat` of the user's own unreadable (`0200`) file therefore fails the subject's open on macOS and gets the uniform answer, where Linux `O_PATH` returns its metadata.
- **`DelegatedMeta`** (size, mtime, kind) is taken from the same `fstat` the target checks run on, with no second syscall. `fs.stat` returns those fields and nothing else: never uid, gid, mode, inode or link count.
- **The KLC has no home-confinement text**, so there is nothing to amend there.

## References

- [ADR-0009](ADR-0009-subject-side-os-dac-evaluation.md) decisions 3, 4, 5, 7 (amended in place); [ADR-0008](ADR-0008-authorization-composition-contract.md) (the composition); [ADR-0019](ADR-0019-audit-record-model.md); [ADR-0020](ADR-0020-access-control-model-and-vocabulary.md); [ADR-0022](ADR-0022-classification-policy-as-data.md)
- `crates/maknae-io/src/delegated.rs::{DelegatedRequired, verify_delegated, DelegatedMeta}`, `crates/maknae-io/src/mutation.rs::verify_mutation_directory`, `crates/maknae-kernel/src/handler.rs::delegated_plan`, `crates/maknae-kernel/src/mutation.rs::prepare`
- `crates/maknae-config/src/sensitive.rs` (grammar and matching), `crates/maknae-kernel/src/sensitive_authz.rs` (the operand), `packaging/common/sensitive.yaml` (the shipped defaults)
