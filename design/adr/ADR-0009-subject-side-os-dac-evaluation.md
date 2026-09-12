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

### Mutation extension (2026-09-07, #158) — subject-side namespace attempts

The operator confirmed that namespace mutations must work within the OS's actual permission-check timing. An existing parent-directory descriptor identifies a location; it does **not** pre-authorize creation, unlink, or mkdir by another process. For these operations Maknae may authorize a **subject-side attempt** after the composed PDP permits its intended paths and the primary audit sink durably records intent. The supported CLI then performs the operation under the subject's own credentials, where the OS accepts or refuses it. Completion is explicitly **client-reported**; neither an attempt authorization nor a client report is evidence that the daemon performed or independently verified the effect. A disconnect leaves an incomplete operation, never an implied rollback or permission to replay.

This extends the existing-object proof below without changing its meaning: reads and replacement through an already-open writable file descriptor retain descriptor-backed OS access and daemon-side execution. Namespace preparation instead verifies an existing directory descriptor and constructs intended paths from its kernel-reported location and validated child components. Directory verification has its own type requirement; the regular-file `nlink_exactly_one` rule is not applicable to directories. A parent descriptor must never produce `os_accessible=true` for the intended mutation. Users and admins have identical filesystem authority, bounded by universal path policy, mandatory composition, and actual subject OS permissions.

The shipped policy permits `Write(~/projects/**)` independently of `Read(~/**)` and pairs the sensitive Read denies with Write denies. Replacement and single-entry deletion decide the verified object or parent-plus-leaf; recursive deletion requires a provable whole-subtree Write grant with no potentially intersecting deny. `mkdir --parents` decides every prospective prefix. Root deletion, malformed components, unexpected descriptor kinds, and unsupported remote execution refuse. Namespace directory acquisition uses Linux `O_PATH` or macOS `O_SEARCH`, so a directory that the user may write/search need not be listable. Enumeration still requires read permission. Symlink entries can be deleted without following their targets, and recursive descent refuses symlinks and detected cross-filesystem transitions.

The guarantee for namespace operations is authorization issuance and attributed reporting. An altered CLI can ignore authorization or falsify a report; the daemon does not enforce every filesystem effect of a process that already possesses the user's OS authority. This extension does not introduce a privileged subject executor or resolve the separately parked execution-isolation work.

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
- **macOS:** `fcntl(fd, F_GETPATH)` — **VERIFIED 2026-08-30** on a `macos-26` runner, the full delegated suite (18 tests) green. `F_GETPATH` and not `F_GETPATH_NOFIRMLINK`: on APFS `/Users` is a firmlink to `/System/Volumes/Data/Users` and the two calls return the two forms; the user-visible form is what an operator writes in `principal.home` and what `realpath` reports, so it is what the confinement prefix-check compares against. *(Corrected 2026-09-04, #216: `principal.home` is not operator-written — `maknae enroll` takes it verbatim from `getpwuid` and re-derives it on every run, with no canonicalization at enroll or load. The `F_GETPATH` choice stands on the form `getpwuid` actually returns on macOS — `/Users/alex`, the firmlink-side name — being the form `F_GETPATH` reports; `realpath` agrees but is nowhere on the path. Where the passwd form and the kernel-reported form differ, every read denies fail-closed, which #216 tracks.)* If that is wrong the failure is **fail-closed** — a form mismatch makes `strip_prefix` fail, which denies — never a bypass.

Neither touches the subject's directories, so **no permission on the home is required at any level and STIG `0700` homes work unchanged.** Containment then reduces to the component-wise prefix check `read_plan` already performs (never `str::strip_prefix` — `/home/opx` is a string-prefix of `/home/op`).

This decision is what removes `open_anchor_resolved` from the read path, and it is the only reason a `0700` home is servable.

### 5. `nlink_exactly_one` is load-bearing for confinement and may not be relaxed without superseding this ADR

The existing requirement now does **triple duty**:

1. it refuses hard-link aliases (its original purpose);
2. it guarantees the kernel reports *the* path rather than *a* path — with exactly one link, `d_path` is unambiguous, which is what makes prefix-checking a sound containment proof;
3. it detects deletion for free — an unlinked file has `nlink == 0` and fails the requirement, on both platforms, with no special handling of Linux's `" (deleted)"` suffix or macOS's silent stale path.

**Measured 2026-08-30 (RHEL 10.2):** an unlinked-but-open descriptor reports `nlink = 0` *and* a `" (deleted)"` suffix on `d_path` — so the `nlink` requirement catches it first and the suffix never needs parsing. A hard-linked object reports `nlink = 2`, so a second name inside or outside the home is refused before confinement is even consulted. *(Corrected 2026-09-04, found by the #216 review: that ordering is not the one `verify_delegated` has. It checks confinement — root soundness, then `strip_prefix` — BEFORE `check_target`, where `nlink_exactly_one` is evaluated. So a descriptor whose kernel-reported name is OUTSIDE the home is refused by confinement, and one whose reported name is INSIDE it passes confinement and is then refused by `nlink` — which branch fires depends on the name the kernel reports for the fd, and with `nlink != 1` item 2 concedes that is *a* name, not *the* name. On the local lane both branches deny, on the same descriptor, before any `Permit`, so item 2's soundness argument holds; the sentence as first written described the design's intent, not the code's order. Tests that assert only an `os dac`-attributed refusal cannot tell the two branches apart — the `a_hardlink_alias_of_a_denied_file_is_refused` case was passing vacuously on darwin until #216, refused at confinement because the fixture's confinement ROOT was in a non-canonical form, never reaching nlink; it was never vacuous on Linux.)*

Without it, an object could be linked both inside and outside the home and containment would prove nothing. **A future change relaxing `nlink` for an unrelated good reason would silently delete this proof.** That is why the coupling is recorded here rather than left in a doc comment.

### 6. The PDP decides on the kernel-reported path, not the client-supplied string

`resource.path` is stamped from the **kernel's answer** for the delegated fd. The client-supplied string is recorded in the trail as *what was asked*, and is not the basis of the decision.

**This is a strict improvement in the deny list's reach.** Today the shipped deny list matches a string the client chose. Under this decision it matches ground truth: a symlink `~/innocent → ~/.ssh/id_rsa` is denied because the deny list evaluates `.ssh/id_rsa`, the path the object actually has.

**Measured 2026-08-30 (RHEL 10.2), because the decision rests on it:** opening `home/innocent` (a symlink to `.ssh/id_rsa`) yields `d_path = …/home/.ssh/id_rsa` — the kernel reports the **resolved** path, not the link. Opening `home/current → versions/v3` likewise reports `…/home/versions/v3`. The deny list therefore sees the object, not the alias.

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

- **MEASURED 2026-08-30 (RHEL 10.2, systemd 257, `systemd-run --user`): `d_path` is unaffected by `ProtectHome=`, in every mode.** The concern was that `d_path` is computed against the reading process's mount namespace, so a masked `/home` might render a received descriptor unreachable. It does not. An fd opened outside the sandbox and inherited into a unit resolved to `/home/operator/dpath-probe.txt` and read its bytes correctly under `read-only`, under `yes` (where `ls /home` is `Permission denied`), and under `tmpfs` (where `/home` is replaced outright). The reason is that `ProtectHome` **overmounts** `/home`; it does not detach the mount the descriptor was opened on, and `d_path` walks that mount.

  **The macOS condition, and how it was DISCHARGED (corrected 2026-08-30, same day it was written).** macOS is a **deployment target**, not a dev convenience — `packaging/isolation-contract.md` said otherwise and was corrected in place after that framing was used, on this very ADR, to argue an unverified lane was acceptable.

  The condition as first written said verification could happen on **Wrathion** (the operator's Apple Silicon host) *and nowhere else*, because CI was `ubuntu-latest` only and all three standing test hosts are Linux. **That is no longer true and the condition is met.** A `macos-26` CI job now runs the delegated suite on every PR touching the covered crates, and **Wrathion runs macOS 26 on Apple Silicon — so the runner has both OS-version and architecture parity with it.** CI verification here is equivalent to a Wrathion run, not a weaker stand-in, and it repeats on every change rather than once.

  **What parity does NOT extend to:** `maknae-vault` and above. `aws-lc-fips-sys` and `ring` need a macOS SDK their build scripts cannot get on a hosted runner, so the FIPS surface is still unbuilt there and **Wrathion remains the only lane for it**. Whether `aws-lc-fips` is FIPS-140-3 *validated* on macOS arm64 — as opposed to merely compiling — remains open. *(Sharpened 2026-09-12, #227: the question is now precisely stated. macOS necessarily runs the **dynamic** module — upstream refuses a static FIPS build outside Linux (`aws-lc/CMakeLists.txt:842`) — so the applicable validation line there is **#5298**, not the #5314 this repository cited. What remains open is the #200 version mapping, which applies to #5298 exactly as to #5314, plus the operational-environment question; macOS on Apple Silicon appears on neither certificate's tested-environment table. Separately, and a packaging obligation rather than a compliance one: the module is a **dylib** that must be shipped and pinned by absolute install name, or an unresolved `@rpath` can bind a non-validated `libcrypto` — see `packaging/macos/README.md`.)* *(Corrected 2026-09-11, #198: this was true while `darwin-native` inherited the Linux cross-check's SDK-free crate list. The `macos-26` hosted runner HAS the SDK; the native lane now runs `cargo test --locked --workspace`, FIPS crates included, on every Rust change, and is CI evidence for the FIPS surface. What remains true: those crates cannot be **cross-checked from Linux**, and whether `aws-lc-fips` is FIPS-140-3 **validated** on macOS arm64 is a separate, open question. Wrathion is no longer the only lane once that first hosted run is green; until then the sentence above describes the state before #198.)* *(Resolved 2026-09-11, #200: that hosted run is green, and the validation question is answered — macOS arm64 is NOT a tested operational environment of CMVP certificate #5314 — the module line is ported there, not validated — and whether Maknae's pinned build (source 3.6.0) is even inside #5314's scope (validated at 3.1.0) is itself open, #200. Maintainer ruling and the certificate's OE table are recorded in `packaging/isolation-contract.md`.)*

  **Both layers earned their place on their first runs.** The cross-compile check caught `RecvFlags::CMSG_CLOEXEC` not existing on darwin, which meant `recv_delegated` did not compile there at all. `MSG_CMSG_CLOEXEC` is a Linux extension, so off Linux a received descriptor arrives **without close-on-exec** and `FD_CLOEXEC` is set explicitly instead — leaving a real window between the `recvmsg` and the `fcntl`. That is a **security-relevant platform delta**, and a Linux-only CI would never have surfaced it.

  **Consequence — this is available hardening, not a constraint.** Once fd delegation lands the daemon never traverses a home at all, so `ProtectHome=` may be tightened from `read-only` to `yes` or `tmpfs` without breaking the read path. Not done in this ADR (it belongs with the implementation and its own removed-behavior note), but the door the earlier draft nailed shut is open. *Residual, stated: measured on the user manager; a system unit applies the same namespace directives through the same mechanism.*

  **ACCEPTANCE, 2026-08-30 — the owed confirmation, done better than promised.** Rather than a `ProtectHome` re-measurement, the whole premise was proven end to end on the Rocky 10.2 acceptance host (Rocky 10.2, el10 kernel 6.12, **SELinux enforcing**, fapolicyd active, STIG'd) across a **real privilege boundary between two real users** — the case no unit test can express, because a test process cannot be two uids at once:

  ```
  daemon euid=991 | home 0o700 owner=1006
  daemon opens by NAME: EACCES   |   traverses the home: EACCES
  subject delegated its descriptor
  kernel-reported path: /home/maksubj/notes
  fstat: nlink=1 size=43 owner=1006 regular=True
  bytes read THROUGH the descriptor: b'SUBJECT-SECRET: only maksubj may read this\n'
  RESULT: PASS
  ```

  A service-account daemon that can neither open the object by name **nor list the directory containing it** learns the object's path from its own descriptor table and reads the bytes. That is decision 4 and [#194](https://github.com/darkhonor/maknae/issues/194) demonstrated in the target environment, not inferred from a `0000`-directory unit test. Test users and their homes were removed afterwards.

  **Cross-host suite runs, same day:** Rocky 9.8 (el9, kernel 5.14, SELinux enforcing) — full `--all-features` FIPS workspace, **48 suites, 0 failures**. Debian 13 (kernel 6.12) — pure-Rust crates, **0 failures**. Together with RHEL 10 locally that is three kernels and three distributions.

- **New syscalls go through [`maknae-io`](../../crates/maknae-io).** `readlink`/`F_GETPATH`, `fstat` on a delegated fd, `fcntl(F_GETFL)`, and the `stat` of decision 7 are security-critical and belong behind a named requirement. The exact-inventory `std-fs-drift` gate refuses direct production calls.

- **MEASURED 2026-08-30 (RHEL 10.2): the local channel is TLS 1.3 over the UDS, so a delegated descriptor must be collected BENEATH the TLS layer or it is silently destroyed.** `maknae_vault::AuthenticatedStream` wraps a `TlsStream` over `tokio::net::UnixStream` ([ADR-0006](ADR-0006-client-authentication-model.md) decision 4). `SCM_RIGHTS` is ancillary data on the raw socket and is not part of any byte stream, so rustls never sees it — and tokio's `UnixStream::poll_read` uses `read(2)`, which **discards attached ancillary data with no error at all**. Measured: a `recv()` of 5 bytes destroyed the descriptor outright; the following `recvmsg` returned the remaining frame bytes with **zero** ancillary fds, and the process fd count was unchanged because the kernel had closed it.

  **The failure mode of getting this wrong is fail-closed, not a bypass.** A destroyed descriptor is an absent descriptor, and decision 2 makes an absent descriptor a `Deny`. A naive implementation denies every read; it cannot permit anything it should not.

  **The mechanism therefore splits along the seam AGENTS.md already draws, and the split is not cosmetic.** *(Corrected 2026-08-30 by operator ruling: an earlier draft of this bullet placed the whole collector in `maknae-vault` and cited [#66](https://github.com/darkhonor/maknae/issues/66) as its eventual home. Both were wrong. #66 is the **Vault-credential-custody vs. mTLS-channel** split triggered by the gateway — it is about remote comms, not descriptor I/O — and putting the collector there would have left the security-relevant syscall outside the crate that exists to audit exactly this.)*

  - **`maknae-io` owns the syscall**, because *"file and directory I/O goes through `maknae-io`"* and a delegated **file descriptor** is a file handle. `recv_delegated` performs the `recvmsg`, sets `CMSG_CLOEXEC`, bounds descriptors per message, and returns them as **owned** handles — so it sits beside `verify_delegated` as one mechanism rather than one split across two crates, and the exact-inventory `std-fs-drift` gate keeps covering it.
  - **The async adapter gets its own crate, `maknae-plane`** (operator ruling, 2026-08-30). It cannot live in `maknae-io`, which is deliberately synchronous with a minimal dependency surface — its manifest moved a single `nix` *feature* to dev-dependencies rather than compile unused surface into *"the crate AGENTS.md holds up as the minimal-TCB I/O primitive"*, and `tokio` with `net` + `io-util` is a far larger expansion than the one that comment refused. It cannot live in `maknae-kernel`: `RawPlaneConn` deliberately keeps `tokio::net` out of that crate. And it does not belong in `maknae-vault`, which **is about talking to the Vault server** — piling client-plane transport there deepens exactly the coupling [#66](https://github.com/darkhonor/maknae/issues/66) exists to unwind. `maknae-plane` is therefore the home that transport is growing into, and #66's migration of `PlaneListener` / `PlaneConnector` / `AuthenticatedStream` lands in it.

    *Named `plane` and deliberately **not** `channel`: this codebase already uses "channel" for the interaction-plane chat adapters (Discord/Slack/Telegram/email — `design/reference-implementation-autopsy.md`, and the plane-architecture diagram's "Channels, chat, API"), so a `maknae-channel` crate would have read as a chat integration. "Plane" is the existing vocabulary — `plane/kernel` URI-SANs, `PlaneListener`, `RawPlaneConn`, "local plane".*

    The adapter carries **no security decision** — it calls the primitive inside tokio's readiness machinery and queues what comes back — which is why it is **T2**, not T1: if it silently breaks, descriptors are *lost*, and an absent descriptor is a `Deny` (decision 2). It cannot yield a `Permit` for an access policy denies. The queue is per-connection, so a mis-ordered take stays within one subject, and the PDP decides on the path of whichever descriptor is actually used (decision 6) — the verdict follows the object rather than diverging from it. What is at stake there is availability and descriptor exhaustion.

  **`unsafe_code = "forbid"` is workspace-wide and shaped this.** `nix`'s `ControlMessageOwned::ScmRights` yields bare `RawFd`s whose conversion to `OwnedFd`/`BorrowedFd` is `unsafe` in every form std offers, and `forbid` cannot be locally overridden. The alternatives were introducing the workspace's **first** `unsafe` block into the minimal-TCB I/O crate, or holding bare `RawFd`s with hand-rolled close-on-drop — the exact leak-on-the-refusal-path hazard this ADR names. `rustix`'s `RecvAncillaryMessage::ScmRights(AncillaryIter<'_, OwnedFd>)` yields owned descriptors safely, so **the workspace still contains zero `unsafe`**. It was already resolved at 1.1.4 in `Cargo.lock` via `tempfile`, so this promotes a vetted edge rather than widening the graph; the pin carries the reasoning in `Cargo.toml`, per the standing dependency rule.

- **Correlation is FIFO. Sound on Linux, measured — and NOT the same on macOS.**

  **Linux (measured 2026-08-30):** the kernel does not merge ancillary data across `sendmsg` boundaries. With two pipelined requests each carrying a descriptor, a 4096-byte `recvmsg` returned only the first message's 8 bytes and its single fd; the second read returned the second. Descriptors arrive in the order of the frames they accompanied, so taking the oldest unconsumed descriptor per fd-bearing request is correct **even under pipelining**.

  **macOS (measured 2026-08-30 on a `macos-26` runner, and it corrects the above):** an earlier revision of this bullet stated the non-merging property as though it were general. It is not. macOS **coalesced two writes into one stream segment** — the first `recvmsg` consumed both frames' bytes together with the single descriptor, and the second returned `EAGAIN`. The test that caught it had been green on three Linux distributions.

  **What that does and does not mean.** For a **single** fd-bearing request per connection — today's CLI, which is per-invocation — nothing changes: the descriptor still arrives with or before the bytes of the frame it accompanied, never after, so the FIFO take is correct. What is **not** characterised is what macOS does with a *second* message's ancillary data when it coalesces the first message's payload past its boundary. Until that is measured, **pipelined fd-bearing requests are not proven safe on macOS**, and the plausible failure is a silently dropped descriptor — a spurious `Deny`, which is fail-closed, not a bypass.

  ADR-0006 decision 4 explicitly designs for long-lived clients, so this becomes live the moment one exists. **Owed: characterise macOS ancillary delivery under pipelining before any client holds a connection across requests.** A client that attaches descriptors out of order only denies itself, on either platform.

- **Delegated fds are a resource the daemon must bound.** Received descriptors count against `RLIMIT_NOFILE`. A per-message cap, `MSG_CMSG_CLOEXEC`, `MSG_CTRUNC` handling, and close-on-drop **on every error path** are requirements, not hygiene — the classic failure is leaking fds on the refusal path, which is the path an attacker controls.

- **A delegated fd must be proved to be a readable regular file.** `fstat` for regular-file and `nlink`, `fcntl(F_GETFL)` for access mode. A fd to a FIFO, socket, TTY, or device would otherwise block the read or stream unboundedly.

- **Stale authority is accepted and named.** The kernel never re-checks an open fd, so a client that opened at `0644` and sends the fd after a `chmod 0600` presents authority it no longer holds. This is **not** an escalation — it is identical to having read the bytes before the change — and it is unavoidable under any fd-delegation design. **It supersedes #186's expected-test 5e** (*"`maknae-io` re-enforces at open"*): there is no second open to re-enforce at. The honest property is the delegated fd plus `nlink == 1`, not a re-check.

- **[#162](https://github.com/darkhonor/maknae/issues/162) is not solved by this ADR.** Fd delegation works only where the client can open the object; a client cannot open `/etc/maknae/maknae.yaml`, which is the whole point of that issue. Stated so that no one reads this decision as covering it.

- **The mutating verbs inherit the mechanism, not the design.** [#158](https://github.com/darkhonor/maknae/issues/158), [#159](https://github.com/darkhonor/maknae/issues/159), [#160](https://github.com/darkhonor/maknae/issues/160) will delegate an `O_WRONLY` fd on the same shape — and `ProtectHome=read-only` stops constraining them, because the client performs the open. Their own semantics (atomicity, `O_TRUNC`, partial writes, `fs.chmod`/`fs.chown` where no fd is opened at all) are **not** decided here.

- **The audit reason must distinguish denied-by-OS-DAC from denied-by-policy**, and both from unknown-lane and confinement failure. Same reason-enrichment work already owed by [#84](https://github.com/darkhonor/maknae/issues/84), [#181](https://github.com/darkhonor/maknae/issues/181), and ADR-0008 decision 5 — **land it once.**

- **The trail records both paths, and the divergence is itself a signal.** `object` carries the path the decision was made on; `object_requested` carries the client's string **only when the two differ**, so its presence — not its value — is what a reviewer or a future detection rule keys on. Emitting it always would dilute exactly that property. Decision 6 makes divergence legitimate and expected, so a trail carrying only one of them is unreconstructable.

- **Resolving the name defeats ALIASES, not RENAMES — and decision 6 must not be over-read.** The deny list evaluates the object a descriptor actually points at, which closes symlink aliasing. It does **not** close renaming: a subject owns its home, so it can `open("~/.ssh/id_rsa")`, `rename` it to `~/notes`, and send the descriptor; `d_path` then reports `~/notes` and the deny glob misses.

  **This is not a regression** — the previous design matched policy against the client-supplied string, so the identical rename defeated it identically — and it is inherent to *path-glob policy over a tree the subject can mutate*. The real closures are inode-keyed policy or a protected subtree the subject cannot rename within; neither is in scope here. Stated so that "the deny list evaluates ground truth" is read as *ground truth about which object this descriptor is*, never as *ground truth about what that object was a moment ago*.
- **Pre-release, so no compatibility event.** The `Read` verb's CBOR shape is unchanged and the fd rides as out-of-band ancillary data, but a `Read` without an fd now denies. **No client is deployed, so nothing is required here** — and no `PROTOCOL_VERSION` bump is proposed; that remains operator-only under the standing rule.

  > **Updated 2026-08-31.** This bullet previously cited AGENTS.md's *protocol/daemon-contract discipline* as "the exact class AGENTS.md flags" and spoke of a break-note. **That section no longer exists**: by operator ruling, nothing is a breaking change while Maknae is still building, break-notes are not written here, and the two that had been written are deleted. The operator is sole governance on protocol and wire semantics. The citation is removed rather than repointed.

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
