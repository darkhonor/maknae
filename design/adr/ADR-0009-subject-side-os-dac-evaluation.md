# ADR-0009: Subject-side OS DAC evaluation — fd delegation on the local lane, confinement from the daemon's own fd table, and lane-conditional applicability

- **Status:** Accepted (operator-ratified 2026-08-30)
- **Date:** 2026-08-30
- **Deciders:** Alex Ackerman (operator)

## Context

[ADR-0020](ADR-0020-access-control-model-and-vocabulary.md) §5 makes `maknae-authz-basic` the **DAC layer** of the access model. Operator ruling 2026-08-29: *"`-basic` should leverage OS DAC controls on whichever supported OS it's running on."* A DAC decision that ignores the operating system's own discretionary controls is not a complete DAC decision, and [#186](https://github.com/darkhonor/maknae/issues/186) filed the gap.

**This is a violation of a ratified trust assumption, not merely an incomplete feature.** [ADR-0006](ADR-0006-client-authentication-model.md) trust assumption 8 (2026-08-22) states: *"No Maknae component performs an action on a client's behalf that exceeds that client's own authority on the host or in the policy model … Any design change that would have the trust plane act with its own privileges **for** a client is a security decision requiring an ADR, not a convenience."* The shipped `fs.read` path does exactly that — it resolves a client-supplied name with `_maknae`'s credentials. **This ADR is the discharge of that clause**, and decision 1 *restores* the assumption rather than carving an exception into it.

**What is true today.** The `fs.read` path enforces DAC by **confinement at the anchor**, not by evaluating the subject's access to the target:

- `crates/maknae-kernel/src/run.rs::read_pep(home, owner_uid, path, budget)` is called with `owner_uid = principal.uid` — the *enrolled principal*, never `peer_uid`.
- `crates/maknae-kernel/src/handler.rs::read_plan` names `TargetRequired { owner: None, mode_mask: None, .. }`.
- `crates/maknae-kernel/src/handler.rs::build_authz_request(verb, peer_uid)` stamps `subject.uid` and `resource.path` — the only two uses of `peer_uid` in the decision.

Nothing anywhere calls `access(2)`, `faccessat(2)`, `seteuid`, or `setfsuid`. **The subject's identity never reaches the filesystem access decision.** The daemon resolves a name supplied by the client and opens it with its own credentials — the confused-deputy shape, general to `fs.read` rather than specific to `admin.config.show` ([#162](https://github.com/darkhonor/maknae/issues/162)).

### The failure that motivates this ADR: the privilege gradient was recorded backwards

#186's worked example reads: *"root writes `/home/alex/.hidden` mode `0600` owned by `root` … the daemon opens it **with its own privilege** and returns the content."* It prescribes the remedy accordingly — *"`faccessat2` with `AT_EACCESS` against the subject's credentials."*

**Both halves are wrong, and the measured deployment is why.** `packaging/common/maknaed.service`:

```
User=_maknae
SupplementaryGroups=maknae
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectHome=read-only
```

1. **The daemon is not more privileged than the subject — it is differently privileged, and mostly less.** `_maknae` gets `EACCES` on a root-owned `0600` file exactly as `alex` does. **The issue's own worked example does not reproduce.** The real asymmetry is credential *difference* (`_maknae` + group `maknae` versus `alex` + `alex`'s groups), and the residual divergence is narrow: a root-planted file grouped to `_maknae` and unreadable by the subject.

2. **The prescribed mechanism cannot be built.** `access(2)` and its relatives answer for the *calling* process; there is no syscall that asks "could uid X read this inode." Answering for another subject requires assuming that subject's credentials — `setfsuid`/`setfsgid`/`setgroups` — which needs `CAP_SETUID`/`CAP_SETGID`. The unit file drops **all** capabilities and sets `NoNewPrivileges=yes`. This is not difficult; it is **structurally foreclosed, deliberately**, by the daemon's best hardening.

The remaining option the issue itself forbids: *"Do **not** put `owner`, `mode`, and `gid` on the request and have `-basic` recompute the mode algebra. ACLs, supplementary groups, and — on the shipped platforms — SELinux and AppArmor mean a hand-rolled calculation is **not** equivalent to what the kernel decides."* That prohibition stands and this ADR does not weaken it.

### A second measured fact: the daemon cannot traverse a STIG'd home at all

`crates/maknae-io/src/syscall.rs::open_parent_by_path` opens the anchor with `O_RDONLY | O_DIRECTORY | O_CLOEXEC` — **read**, not search. [ADR-0021](ADR-0021-fail-closed-storage-io-tightenings.md) decision 3 states this deliberately: *"A plain `open(2)` of the file needed only search (`x`) permission on the directory; the anchor open needs read (`r`)."*

A STIG'd home is `0700`, owned by the subject. `_maknae` therefore fails `open_anchor_resolved("/home/alex", …)` with `EACCES` → `ReadRefusal::Unavailable`. **`fs.read` is already non-functional against a STIG'd home**, today, before any change in this ADR. The anchor *requirement* (`mode_mask: Some(0o022)`) happily admits `0700`; the anchor *open* cannot. That contradiction is shipped, and it is filed as [#194](https://github.com/darkhonor/maknae/issues/194).

Any design in which the daemon resolves a name beneath the subject's home inherits this. A passed directory fd does not help: `openat`/`fstatat` still check `MAY_EXEC` on each component **against the caller's credentials** — a dirfd anchors where a walk starts, it confers no traversal rights.

### The remote lane has no uid at all

[ADR-0006](ADR-0006-client-authentication-model.md) decision 5: *"the remote client **never reaches `maknaed`** — its session is `client↔gateway`."* The gateway validates OIDC and asserts the principal over a separate internal mutual-mTLS machine channel. Decision 7: locally the principal is the `SO_PEERCRED` uid; remotely it is *"the validated OIDC principal (and its claims → subject attributes)."*

A remote subject therefore has no process, no uid, and no file descriptors on the Maknae host. **OS DAC is a local-lane control.** Any design that treats it as universal either fabricates an answer remotely or — under [ADR-0008](ADR-0008-authorization-composition-contract.md) decision 4's *unknown → Deny* — denies every remote read the day the gateway lands.

## Decision

### 1. The subject's OS access is established by the subject's own `open(2)`. The daemon never assumes credentials.

On the local lane the client process **is** the subject — that is where `SO_PEERCRED` gets its uid. The client opens the file itself and delegates the resulting file descriptor to the daemon over `SCM_RIGHTS` ancillary data on the existing UDS.

An open file descriptor is not a name; it is an **unforgeable record of a completed authorization**. The permission check happens exactly once, at `open(2)`, and the kernel evaluates the whole stack for that subject — DAC bits, POSIX ACLs, supplementary groups, SELinux/AppArmor labels, mount flags. Nothing is reimplemented, nothing is approximated, and no capability is required of the daemon.

**The fd's existence is the OS's answer.** It follows that **#186's first owed bullet is superseded: `TargetRequired { owner, mode_mask }` are NOT to be populated on this path.** They remain `None`, and that is now correct and intentional rather than a gap — evaluating them daemon-side is precisely the mode-algebra reimplementation the operator forbade.

### 2. A `Read` that arrives with no delegated fd is a `Deny`, not a client-side error

The client that cannot open the file **still sends the request**, without an fd. The daemon stamps the failure and the PDP returns a real `Deny` with an OS-DAC reason.

This is #186's *"it produces a verdict instead of a failure"* requirement, and it is what keeps the denial in the AU-3 trail ([ADR-0019](ADR-0019-audit-record-model.md)). A client that silently failed locally would leave the refusal unrecorded.

The daemon cannot distinguish *"the client could not open it"* from *"the client chose to send no fd."* **It does not need to: both deny**, and a client that denies itself is not a threat.

### 3. Access and confinement are separate proofs. Both are required.

| Proof | Established by | Guarantees |
|---|---|---|
| the delegated fd | the subject's own `open(2)` | the subject genuinely has OS access to this object |
| the confinement check | the daemon, on its own fd table | the object lies beneath the enrolled home |

Neither substitutes for the other. The fd says nothing about *where*; confinement says nothing about *who*. Confinement remains a **Maknae** control — the `~/**` grant — independent of what OS DAC permits, so a subject reading its own world-readable file outside the home is still refused.

### 4. Confinement is established from the daemon's own fd table, never by daemon-side path resolution

The daemon asks the kernel where the received fd points, using its **own** `/proc` entry:

- **Linux:** `readlink("/proc/self/fd/N")`
- **macOS:** `fcntl(fd, F_GETPATH)`

Neither touches the subject's directories, so **no permission on the home is required at any level and STIG `0700` homes work unchanged.** Containment then reduces to the component-wise prefix check `read_plan` already performs (never `str::strip_prefix` — `/home/opx` is a string-prefix of `/home/op`).

This decision is what removes `open_anchor_resolved` from the read path, and it is the only reason a `0700` home is servable.

### 5. `nlink_exactly_one` is load-bearing for confinement and may not be relaxed without superseding this ADR

The existing requirement now does **triple duty**:

1. it refuses hard-link aliases (its original purpose);
2. it guarantees the kernel reports *the* path rather than *a* path — with exactly one link, `d_path` is unambiguous, which is what makes prefix-checking a sound containment proof;
3. it detects deletion for free — an unlinked file has `nlink == 0` and fails the requirement, on both platforms, with no special handling of Linux's `" (deleted)"` suffix or macOS's silent stale path.

Without it, an object could be linked both inside and outside the home and containment would prove nothing. **A future change relaxing `nlink` for an unrelated good reason would silently delete this proof.** That is why the coupling is recorded here rather than left in a doc comment.

### 6. The PDP decides on the kernel-reported path, not the client-supplied string

`resource.path` is stamped from the **kernel's answer** for the delegated fd. The client-supplied string is recorded in the trail as *what was asked*, and is not the basis of the decision.

**This is a strict improvement in the deny list's reach.** Today the shipped deny list matches a string the client chose. Under this decision it matches ground truth: a symlink `~/innocent → ~/.ssh/id_rsa` is denied because the deny list evaluates `.ssh/id_rsa`, the path the object actually has.

**Consequent behavior change, stated for the removed-behavior audit ([ADR-0021](ADR-0021-fail-closed-storage-io-tightenings.md)).** Today the read path refuses **every** symlink via `O_NOFOLLOW`. Under this decision symlinks resolve and the policy decides on the resolved path. A legitimate in-home symlink (`~/current → ~/versions/v3`) begins to work where it previously failed. **This is a deliberate loosening**, and it applies the operator's standing correction on `fs.move`/`fs.link` — *"Moving and linking are valid actions in the proper context"* — rather than refusing a valid filesystem feature. The malicious case is not weakened: it is denied by the deny list, on the true path, which is strictly better than a blanket refusal that never consulted policy at all.

The existing suite's `a_symlink_alias_of_a_denied_file_is_refused` stays green, for a better reason.

### 7. The home's owner and mode requirement is retained — enforced by `stat`, not by opening

Dropping the anchor **open** does not drop the anchor **requirement**. `AnchorRequired { owner: Some(principal.uid), mode_mask: Some(0o022) }` — *"THE alias-planting boundary"*, refusing a home any non-principal can write — is preserved by a plain `stat` of the home path, which requires only search (`x`) on `/home` (universally `0755`) and **no permission on the home itself**.

For each thing the anchor open enforced: inode pinning is replaced by the delegated fd (a stronger pin — an open file description cannot change identity); owner and mode are re-established by `stat` as above; symlink refusal at intermediate components is superseded by decision 6, deliberately.

### 8. OS DAC is lane-conditional, and the lane is derived from the accepting listener

The request carries two attributes:

- **`resource.os_accessible`** — `AttrValue::Bool`, stamped **only** when the OS answered.
- **`context.dac_lane`** — `AttrValue::Str("local" | "remote")`, always stamped, derived from **which listener accepted the connection** (#114's per-listener split).

`maknae-authz-basic` decides, **code-defined and unconfigurable** — in the same class as `Role::Adversary`'s deny-all, and **no `authz.yaml` key enables, disables, or overrides it**:

| `dac_lane` | `os_accessible` | Result |
|---|---|---|
| `local` | `true` | the DAC operand is satisfied; the rest of the policy decides |
| `local` | `false` | **`Deny`** — OS DAC refuses this subject this object |
| `local` | *absent* | **`Deny`** — unknown; the daemon should have been able to ask and could not ([ADR-0008](ADR-0008-authorization-composition-contract.md) decision 4, no operand fails open) |
| `remote` | *absent* | **not applicable** — OS DAC is structurally not the control here; the operand contributes nothing and the rest of the policy carries the decision |
| *absent or unrecognized* | any | **`Deny`** — fail closed |

The lane is the **only** thing distinguishing *"absent means Deny"* from *"absent means not applicable."* It must therefore be un-spoofable: **it is derived from the accepting listener and never from a request field, header, session claim, or anything else a client can influence.** Anything that lets a local request present as remote escapes OS DAC entirely — this is the single most important control in this ADR.

### 9. The composed decision is never more permissive on the remote lane than on the local lane for the same object

Recorded now, before the gateway exists to violate it. Without it, a subject with access to both lanes has an escalation path consisting of choosing the more permissive door.

### 10. The gateway is not granted `CAP_SETUID` to map OIDC principals onto local uids

The tempting way to give the remote lane an OS DAC story is to have the gateway open files as a local uid per enrolled subject. **This is foreclosed.** [ADR-0006](ADR-0006-client-authentication-model.md) assumption 5 bounds gateway compromise to *"impersonation of enrolled remote subjects + the gateway's own scoped machine credential"* and explicitly *"never local principals."* `CAP_SETUID` on a network-facing component extends that blast radius to arbitrary local uid impersonation.

Choosing that route requires **amending ADR-0006**, not merely implementing #117. Whether the gateway uses a single service uid (no OS-level subject separation — policy carries the whole weight, and that must be stated rather than implied) or some other model is [#117](https://github.com/darkhonor/maknae/issues/117)'s decision, not this one.

### 11. The remote lane's DAC-equivalent is unsolved and out of scope

Naming the gap is part of the decision, so that nobody reads decision 8's *"not applicable"* as *"handled elsewhere."* It is not handled anywhere yet. Tracked as [#195](https://github.com/darkhonor/maknae/issues/195), a sub-issue of [#117](https://github.com/darkhonor/maknae/issues/117), which is unbuilt — so there is no live hole, only an owed design.

## Consequences

- **[ADR-0021](ADR-0021-fail-closed-storage-io-tightenings.md) decision 3 narrows; it is not overturned.** Parent-directory *readability* remains the contract precondition for anchored I/O over **daemon-owned artifacts** — config, vault CA pins, credentials, the audit sink. It no longer governs **subject-owned homes**, because `fs.read` leaves the anchored path entirely. ADR-0021 carries the reciprocal note in place, dated.

- **`peer_uid` acquires a third use.** Today it is stamped as `subject.uid` and used to build the anchor requirement. It now also authenticates the *sender of the fd*: [ADR-0006](ADR-0006-client-authentication-model.md) decision 4 already specifies `SO_PASSCRED` with per-message `SCM_CREDENTIALS` matching the session's bound uid, to close T13. **That control, already designed and not yet built, is exactly what makes fd delegation safe** — a connection fd handed to another uid does not let that uid present its own fds as the session subject's authority.

- **macOS carries a documented weaker attribution.** It has no per-message sender-credential facility (`LOCAL_PEERCRED`/`LOCAL_PEERTOKEN` are connection-scoped). ADR-0006 already books this as a T4-class voluntary-credential-sharing residual bounded by the visit clock. Fd delegation sharpens it from *"someone else can drive your session"* to *"someone else's fd can be presented as your authority"* — the same class, restated here because the consequence is now about object access rather than session control.

- **An owed measurement, not an assertion: the `ProtectHome=` / `d_path` interaction.** `d_path` is computed against the reading process's mount namespace. `ProtectHome=read-only` keeps the real `/home` mount visible and `readlink` should resolve; `ProtectHome=yes` masks `/home` with a tmpfs and may render the dentry unreachable. **The unit file therefore keeps `read-only` and must NOT be tightened to `yes`.** This has not been measured — it is owed on the Rocky 10 acceptance host before the implementation is relied on, in the style of ADR-0006's measured-evidence notes.

- **New syscalls go through [`maknae-io`](../../crates/maknae-io).** `readlink`/`F_GETPATH`, `fstat` on a delegated fd, `fcntl(F_GETFL)`, and the `stat` of decision 7 are security-critical and belong behind a named requirement. The exact-inventory `std-fs-drift` gate refuses direct production calls.

- **Delegated fds are a resource the daemon must bound.** Received descriptors count against `RLIMIT_NOFILE`. A per-message cap, `MSG_CMSG_CLOEXEC`, `MSG_CTRUNC` handling, and close-on-drop **on every error path** are requirements, not hygiene — the classic failure is leaking fds on the refusal path, which is the path an attacker controls.

- **A delegated fd must be proved to be a readable regular file.** `fstat` for regular-file and `nlink`, `fcntl(F_GETFL)` for access mode. A fd to a FIFO, socket, TTY, or device would otherwise block the read or stream unboundedly.

- **Stale authority is accepted and named.** The kernel never re-checks an open fd, so a client that opened at `0644` and sends the fd after a `chmod 0600` presents authority it no longer holds. This is **not** an escalation — it is identical to having read the bytes before the change — and it is unavoidable under any fd-delegation design. **It supersedes #186's expected-test 5e** (*"`maknae-io` re-enforces at open"*): there is no second open to re-enforce at. The honest property is the delegated fd plus `nlink == 1`, not a re-check.

- **[#162](https://github.com/darkhonor/maknae/issues/162) is not solved by this ADR.** Fd delegation works only where the client can open the object; a client cannot open `/etc/maknae/maknae.yaml`, which is the whole point of that issue. Stated so that no one reads this decision as covering it.

- **The mutating verbs inherit the mechanism, not the design.** [#158](https://github.com/darkhonor/maknae/issues/158), [#159](https://github.com/darkhonor/maknae/issues/159), [#160](https://github.com/darkhonor/maknae/issues/160) will delegate an `O_WRONLY` fd on the same shape — and `ProtectHome=read-only` stops constraining them, because the client performs the open. Their own semantics (atomicity, `O_TRUNC`, partial writes, `fs.chmod`/`fs.chown` where no fd is opened at all) are **not** decided here.

- **The audit reason must distinguish denied-by-OS-DAC from denied-by-policy**, and both from unknown-lane and confinement failure. Same reason-enrichment work already owed by [#84](https://github.com/darkhonor/maknae/issues/84), [#181](https://github.com/darkhonor/maknae/issues/181), and ADR-0008 decision 5 — **land it once.**

- **The trail records both paths.** What the client asked for and what the kernel reported the fd to be. Decision 6 makes them potentially different by design, and a trail that recorded only one would be unreconstructable.

- **Pre-release, so no compatibility event.** The `Read` verb's CBOR shape is unchanged and the fd rides as out-of-band ancillary data, but a `Read` without an fd now denies — a semantic change behind a stable wire, ordinarily the exact class AGENTS.md flags. **No client is deployed, so no break-note and no `PROTOCOL_VERSION` bump is required** (and none is proposed — that remains operator-only under the standing rule). The discipline applies again the moment anything ships.

- **Decision logic implementing this ADR is T1** (95% region floor, zero missed mutants) per [ADR-0016](ADR-0016-risk-tiered-test-coverage.md), and the `negative-control` gate must be extended and **observed failing**.

## References

- [#186](https://github.com/darkhonor/maknae/issues/186) — the filing issue. **Its threat model and prescribed mechanism are corrected by this ADR**, in its body, dated
- [ADR-0020](ADR-0020-access-control-model-and-vocabulary.md) §5 — `-basic` is the DAC layer
- [ADR-0008](ADR-0008-authorization-composition-contract.md) — decision 4 (no operand fails open) is what makes *unknown → Deny*; decision 5's compose-layer refusal is the pattern decision 8 follows
- [ADR-0006](ADR-0006-client-authentication-model.md) — decision 4 (`SO_PASSCRED`/T13, the control that secures fd delegation; the macOS residual), decision 5 and 7 (the remote lane has no uid), assumption 5 / T10 (the gateway blast-radius bound decision 10 preserves), **assumption 8 (Maknae is never the privilege-escalation vector — the invariant this ADR restores)**
- [ADR-0021](ADR-0021-fail-closed-storage-io-tightenings.md) — decision 3 narrows per Consequences; its removed-behavior obligation governs decision 6
- [ADR-0005](ADR-0005-enforcement-locus-tcb-boundary.md) — `maknaed` is the sole PDP
- [ADR-0019](ADR-0019-audit-record-model.md) — the trail obligations above
- `packaging/common/maknaed.service` — the measured capability posture that forecloses credential switching
- `crates/maknae-io/src/syscall.rs::open_parent_by_path` (`O_RDONLY|O_DIRECTORY` — read, not search), `crates/maknae-io/src/anchor.rs::open_anchor_resolved`
- `crates/maknae-kernel/src/handler.rs::read_plan`, `::build_authz_request`; `crates/maknae-kernel/src/run.rs::read_pep`
- [#195](https://github.com/darkhonor/maknae/issues/195) — the remote-lane DAC gap (decisions 8, 9, 10, 11), a sub-issue of [#117](https://github.com/darkhonor/maknae/issues/117), the gateway epic
- [#194](https://github.com/darkhonor/maknae/issues/194) — `fs.read` cannot serve a STIG'd `0700` home; fixed as a consequence of decision 4
- [#114](https://github.com/darkhonor/maknae/issues/114) — the per-listener split decision 8's lane derivation rests on
- Operator rulings, 2026-08-29 and 2026-08-30
