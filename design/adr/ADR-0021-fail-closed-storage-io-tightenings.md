# ADR-0021: Fail-closed storage I/O tightenings under maknae-io adoption — symlink refusal on storage reads, parent-directory readability precondition

- **Status:** Accepted (operator-ratified 2026-08-26)
- **Date:** 2026-08-26
- **Deciders:** Alex Ackerman (operator)

## Context

PR #128 migrated config loading, root-controlled posture evidence, and Vault storage reads through `maknae-io` (the anchor-relative secure I/O crate, #120). The post-merge security review found that the migration changed two observable behaviors without a recorded decision:

1. **Symlink refusal on storage reads ([#134](https://github.com/darkhonor/maknae/issues/134)).** CA-pin (`maknae-vault/src/ca.rs::first_cert_der`), approle-id (`client.rs::read_trimmed`), and `$CREDENTIALS_DIRECTORY` credential (`secret_io.rs::read_sealed_trimmed`) reads previously used `std::fs::read`, which follows a symlinked final component. Through `maknae_io::read_absolute` the final component is opened `O_NOFOLLOW` and must be a regular file. Deployment layouts that materialize these files as symlinks — Kubernetes secret/projected volumes (the `..data` indirection), certbot-style `live/ → archive/` farms — worked before the migration and refuse to start after it. `read_sealed_trimmed`'s doc comment still described the pre-migration stance ("the OS credential mechanism, not this process's view of the file, is the trust boundary"), contradicting the enforced behavior.

2. **Parent-directory readability precondition ([#136](https://github.com/darkhonor/maknae/issues/136)).** Every anchored read opens the target's parent directory with `O_RDONLY|O_DIRECTORY` (`maknae-io/src/syscall.rs::open_parent_by_path`) to pin the directory inode. A plain `open(2)` of the file needed only search (`x`) permission on the directory; the anchor open needs read (`r`). A hardened install with `/etc/maknae` or `/etc/maknae/private` at `0710` — stricter than the shipped layout but previously functional — now fails the anchor open (boot refused for authz, silent posture downgrade for the marker, `VaultError::Io` for vault reads).

Both are tightenings, not regressions of enforcement — but an undocumented tightening is indistinguishable from an accident, and the next migration would be free to loosen it just as silently. The failure that motivates this ADR: a security-relevant behavior delta shipped with green gates, green mutation, and two approving reviews, because every control verified what the new code *does*, not what the old code *stopped doing*.

## Decision

1. **Keep both tightenings. Fail closed is the default posture for the storage plane, and these are its correct expression.**

2. **Symlinked storage artifacts are refused, deliberately.** The checked-inode-equals-used-inode property is the point of `maknae-io`; a followed final symlink reopens the door the crate exists to close. Supported deployment layouts must materialize CA pins, approle-ids, and credentials as regular files (systemd credentials do; the shipped `/etc/maknae` layout does). Kubernetes projected-volume and symlink-farm layouts are **out of scope** for Stage 1. If such a deployment materializes, the path in is a *named, contract-level* follow-final-symlink read in `maknae-io` — a new decision with its own ADR — never a caller-side `std::fs` fallback.

3. **Parent-directory readability is a contract precondition of anchored I/O.** Directories holding maknae-managed artifacts must grant read (not merely search) permission to the reading principal.

   > **Narrowed 2026-08-30 by [ADR-0009](ADR-0009-subject-side-os-dac-evaluation.md) — this precondition governs DAEMON-OWNED artifacts only.** As written it read as universal, and applied to the `fs.read` path it is unsatisfiable: a STIG'd home is `0700` and owned by the subject, so `_maknae` cannot open it at all (`open_parent_by_path` uses `O_RDONLY|O_DIRECTORY`) and `fs.read` fails `Unavailable` before any decision is reached. ADR-0009 removes `fs.read` from the anchored path entirely — the subject delegates an already-open fd and the daemon proves confinement from its own fd table — so **no permission on a subject's home is required at any level**. What remains in force here is the original scope: config, Vault CA pins and credentials, and the audit sink — artifacts the daemon owns, where requiring read on the holding directory is a real and kept tightening. The alias-planting owner/mode requirement on a home is *not* dropped; ADR-0009 decision 7 re-establishes it by `stat`, which needs only search on `/home`. This is documented on `maknae_io::open_anchor` / `open_anchor_resolved` as part of the crate contract. An `O_PATH`-based lane restoring search-only compatibility is possible on Linux but is **not** built speculatively; it becomes contract work only if a real hardened-layout deployment requires it.

4. **Doc text that contradicts enforced behavior is a defect.** `read_sealed_trimmed`'s trust-boundary comment is corrected to state the enforced contract (regular file, no symlink, requirement-free mode/owner because the OS mechanism vouches for the *content*, while `maknae-io` still vouches for the *inode identity*).

## Consequences

- Operators get a boot-time refusal, not a silent read, when a storage artifact is a symlink or its parent directory is unreadable. Both failure modes are now documented here and in the crate docs, so a refused boot is diagnosable by design rather than by archaeology.
- The review finding that surfaced this ("removed-behavior audit") earns a place in the review checklist for any security refactor: verify what the old code *stopped doing*, not only what the new code does.
- Issues #134 and #136 close as decided-and-documented; loosening either behavior in the future requires superseding this ADR.

## References

- PR #128 (maknae-io adoption); post-merge security review findings 6 and 8 (2026-08-26)
- [#134](https://github.com/darkhonor/maknae/issues/134), [#136](https://github.com/darkhonor/maknae/issues/136)
- `crates/maknae-io/src/syscall.rs::open_parent_by_path` (`O_RDONLY|O_DIRECTORY`); `crates/maknae-io/src/anchor.rs::open_anchor_resolved`
- AGENTS.md § Conventions — "File and directory I/O goes through maknae-io"
