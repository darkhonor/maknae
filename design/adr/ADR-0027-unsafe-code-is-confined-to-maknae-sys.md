# ADR-0027: Unsafe code is confined to `maknae-sys`

- **Status:** Accepted (maintainer-ruled 2026-09-28)
- **Date:** 2026-09-28
- **Deciders:** Alex Ackerman (maintainer)
- **Raised by:** [#400](https://github.com/darkhonor/maknae/issues/400), for the home half of [#368](https://github.com/darkhonor/maknae/issues/368)

## Context

Every workspace member inherits `[workspace.lints.rust] unsafe_code = "forbid"`, and before this decision no member's source contained `unsafe`.

#368 needs a call that no safe crate in the tree offers. On macOS, `maknaed` must resolve the operator's home to the exact string that `F_GETPATH` reports for descriptors under it, without holding permission on the home: a default home is `0750`, and `_maknae` is not in its group.

Two calls were measured on macOS 26.6 (Apple Silicon, 2026-09-28), with a `000` directory that the caller owns standing in for "no permission on the target":

- `open(O_SEARCH)` needs search permission on the directory itself, and was refused with `EACCES`.
- `getattrlist(ATTR_CMN_FULLPATH)` needs search permission on the ancestors only, and succeeded. In every case where both calls succeeded, it returned the same string as `F_GETPATH`, byte for byte. Those cases included `/tmp` → `/private/tmp`, a final-component symlink, and a case-mismatched name.

The real case, `_maknae` resolving another user's `0750` home, is pending the macOS acceptance run (#76).

`nix` 0.31 does not wrap `getattrlist`. `libc` declares it, and calling it is `unsafe`.

`forbid` cannot be lifted by an `#[allow]` inside a crate that inherits it, so the call cannot live in `maknae-io`. The maintainer ruled on 2026-09-28 that all `unsafe` code goes in one crate, which is tested and vetted until its interface is safe, and which is never exposed directly outside.

[ADR-0002](ADR-0002-kernel-is-rust.md) said `unsafe` was "tracked via `cargo-geiger`" in CI, but no CI job ran it. Nothing checked that a member kept `[lints] workspace = true`, so a member that omitted it would have compiled with `unsafe` permitted.

## Decision

1. **`maknae-sys` is the only workspace member whose source may contain `unsafe`.** Every other member declares `[lints] workspace = true`, and so inherits `unsafe_code = "forbid"`.
2. **Its lints.** `maknae-sys` does not inherit the workspace lints. Its own `[lints]` table sets exactly these four levels:
   - `rust.unsafe_code = "deny"`
   - `rust.unsafe_op_in_unsafe_fn = "forbid"`
   - `clippy.undocumented_unsafe_blocks = "forbid"`
   - `clippy.multiple_unsafe_ops_per_block = "forbid"`

   `unsafe_code` is `deny`, not `forbid`, so that each item holding an `unsafe` block can carry `#[allow(unsafe_code)]`. The other three are `forbid`, so an in-source `#[allow]` of them is a compile error (E0453, "incompatible with previous forbid"), not a silent opt-out. Every `unsafe` block sits in a non-module item that carries `#[allow(unsafe_code)]`, performs exactly one unsafe operation, and carries a `// SAFETY:` argument. An inner or module-level allow of `unsafe_code` is refused (decision 6).
3. **Its public surface is safe functions only.** No `pub unsafe fn`, raw pointer or raw file descriptor crosses its API. The function derives each pointer and length it passes to the OS from values it owns, so a caller cannot make them disagree. Anything the OS returns is parsed by safe Rust over byte slices, and that parser is compiled and tested on every platform. The "no `pub unsafe fn`, no raw pointer or descriptor in the API" rule is enforced by review, not by a gate. It defines no macro (no `macro_rules!`), and no tracked crate in the repository, `maknae-sys` included, is a proc-macro crate. rustc's `forbid` covers `unsafe` written in a member's own code and in files it includes; a macro-exported `macro_rules!` body, or a proc-macro's output, would escape it in consumers, because the lint does not fire on another crate's macro expansion. So the gate refuses `macro_export` in every member, and these rules are gate-enforced (decision 6).
4. **The obligations on each function.** A function lands in `maknae-sys` with all of these:
   - a `// SAFETY:` argument on each block;
   - a byte-for-byte test against a trusted kernel reference where one exists (for `full_path`, the reference is `F_GETPATH` on an `O_SEARCH` descriptor);
   - bounds tests on any parser, showing that every malformed reply is refused without a panic or an out-of-bounds read;
   - T1 coverage ([ADR-0016](ADR-0016-risk-tiered-test-coverage.md));
   - membership of `mutants_crates`, with zero missed mutants.

   Consequences below says which lane enforces each of these.
5. **Who may depend on it.** Only the packages listed in `SYS_CONSUMER_ALLOW` in `ci/gates/lib.sh`. Today that is `maknae-io`. Adding a consumer is a reviewed change to that list. No crate may re-export `maknae_sys`, which would widen the reach beyond the list. The gate refuses any `pub use` or `pub extern crate` statement whose text contains the token `maknae_sys`, lists included (decision 6). Aliasing (`use maknae_sys as m; pub use m::…`, `extern crate … as`), a renamed dependency (`package = "maknae-sys"` under another name) and macro-generated re-exports in a listed consumer are review-enforced; only a listed consumer can declare the dependency at all.
6. **The gates.** `ci/gates/unsafe-confinement.sh` runs in CI (`build-and-gate`) and in the pre-push hook. It fails if:
   - the root no longer sets `unsafe_code = "forbid"`;
   - any member other than `maknae-sys` lacks `[lints] workspace = true`, or any member's edition, or any of its targets' editions, as `cargo metadata` resolves them, is below 2021;
   - the `[lints]` table of `maknae-sys` differs from decision 2;
   - a tracked `.rs` file (extension matched case-insensitively) that does not belong to the `maknae-sys` package contains the token `unsafe` outside comments and literals. Ownership comes from the package manifest directories `cargo metadata` reports, and any other member nested under `maknae-sys`'s directory fails;
   - a package outside `SYS_CONSUMER_ALLOW` depends on `maknae-sys`;
   - any workspace package has a target whose `cargo metadata` kind is `proc-macro`, or any tracked `Cargo.toml`, member or not, declares `proc-macro = true`, `proc_macro = true` or a `crate-type` containing `proc-macro` (which covers a crate reached through `[workspace] exclude`, `[patch]` or a cargo-config `paths` override); a tracked `Cargo.toml` that does not parse also fails;
   - any tracked `.rs` file, in any member, contains the token `macro_export` outside comments and literals, in any attribute position including `cfg_attr`;
   - a tracked `.rs` file of `maknae-sys` contains `macro_rules!` outside comments and literals, an inner attribute (`#![…]`) that allows, expects or warns `unsafe_code`, or an outer attribute that does so, directly or through `cfg_attr`, on a `mod` item. `unsafe_code` may be allowed only on non-module items;
   - any tracked `.rs` file, `maknae-sys`'s included, contains, outside comments and literals, any of these spellings, each of which can compile a file the scan does not list: an attribute whose body starts `path =`, or a `cfg_attr(…)` with a `path =` item; the identifier `r#path`; a macro fragment anywhere in an attribute (`$` in an attribute body, so `#[$m]`, `#![$m]` and `#[cfg_attr(all(), $m)]`); or the identifier `include` (so `include!`, `r#include`, `use core::include as …` and `include` passed to a macro). `include_str` and `include_bytes` stay allowed. This is a lexical check and does not claim completeness: an include or path route produced by macro expansion the scan cannot model is a named residual, and the file it brings in is still compiled under the compiled-code `forbid`, which is the primary control;
   - any tracked `.rs` file has a `pub use` or `pub extern crate` statement containing the token `maknae_sys` (decision 5);
   - a tracked cargo config file (a path ending `.cargo/config` or `.cargo/config.toml`, matched case-insensitively, because macOS's default file system is case-insensitive and cargo reads a case variant there) has a top-level `include` key (the included file would not be checked), sets `rustflags` at any level, passes `--cap-lints` in any string, sets `build.rustc`, `build.rustc-wrapper` or `build.rustc-workspace-wrapper`, has an `[alias]` with a token starting `--cap-lints`, `-A`, `--allow`, `-C` or `--config`, or sets `[env]` `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `RUSTDOCFLAGS`, `RUSTC` or any `RUSTC_*` key. Each of these could weaken the lint levels without touching a manifest.

   It also fails, with a `FAIL:` line, when given any argument other than `--root <dir>`, when Python is older than 3.11, when it runs outside a git work tree without `--root`, when `cargo metadata` or `git ls-files` fails, when metadata resolves zero packages, and when it scans zero `.rs` files outside `maknae-sys`.

   The token scan is a defence-in-depth layer; the primary control is the compiled-code `forbid`, which covers `unsafe` written in a member's own code and in files it includes, however the file was brought in. It does not cover `unsafe` arriving through another crate's macro expansion, which is why `macro_export` and proc-macro crates are refused outright. The scan is deliberately conservative. It models line and nested block comments, and string, raw-string and char literals. A raw-string prefix (`r`, `br`, `cr`) opens a raw string only when no identifier character precedes it, as edition 2021 lexes it; that is why editions below 2021 are refused. Its one known false positive is the raw identifier `r#unsafe`, which it reports as `unsafe`. A false positive fails the build and is resolved by rewording; a false negative weakens the layer, so false positives are the preferred failure.

   Named residual: doctests. rustdoc compiles each doctest as its own crate, without the member's lints, and the token scan masks doc comments, so `unsafe` in a doctest is outside both controls. Doctests are never linked into a shipped artifact.

   Named residual: lint-weakening flags or a compiler wrapper set in any workflow's `env:` (`RUSTFLAGS`, `RUSTC_WRAPPER` and the like in `.github/workflows/ci.yml` or `release.yml`) are outside the gate. Workflow changes are maintainer-reviewed, and no workflow sets any of them today. A `[toolchain] path` in `rust-toolchain.toml` is also outside the gate: it points rustup at an arbitrary toolchain directory; `clippy-all.sh` requires a pinned `channel` and pins `RUSTUP_TOOLCHAIN` for its own lane, but the build, test and `darwin-native` lanes honour the file as written.

   On the `darwin-native` lane, where the crate's `unsafe` compiles, CI also runs `cargo clippy --locked -p maknae-sys --all-targets -- -D warnings`. With decision 2's `forbid` levels, that step makes the SAFETY and one-operation rules hard failures. `darwin-native` is a required status check on `main` (branch protection's required checks are `build-and-gate`, `darwin-cross` and `darwin-native`, read on 2026-09-28 with `gh api repos/darkhonor/maknae/branches/main/protection/required_status_checks`), so the step is enforcing.

   `ci/gates/negative-control.sh` proves three things: each failure of `unsafe-confinement.sh` fires; a clean tree passes; and the four lint levels, as the crate's manifest states them, make clippy reject an undocumented block and a two-operation block, and refuse an in-source `#[allow(clippy::undocumented_unsafe_blocks)]`.
7. **The first function** is `full_path(&Path) -> io::Result<PathBuf>`, on macOS only. It calls `getattrlist` requesting `ATTR_CMN_OBJTYPE | ATTR_CMN_FULLPATH`, without `FSOPT_NOFOLLOW`, so a final symlink is followed. It passes the kernel's errno through when `getattrlist` fails, and otherwise:
   - `ENOTDIR` unless the object is a directory;
   - `EINVAL` for a path that contains a NUL;
   - for a reply that does not parse, including a path field longer than `PATH_MAX`, an `io::Error` of kind `InvalidData` that carries no errno.

   `maknae_io` maps an error with no errno, which only the parser produces, to `IoError::FdPathUnavailable`, and every kernel errno through `map_open_errno`, as on Linux.

   `maknae_io::resolve_dir` calls it on macOS. The Linux path (`O_PATH` and `/proc/self/fd`) does not change.

## Consequences

- #368's home half: on macOS, `resolve_dir` needs no permission on the directory it resolves. The regular-file descriptor half of #368 is separate and still open.
- A real `_maknae` boot against a `0750` home, and an autofs or NFS home, are unmeasured; both are checked at the macOS acceptance run (#76). `open(O_DIRECTORY)` triggers an automount, and whether `getattrlist` does is not known.
- On macOS, `resolve_dir` and `verify_delegated` now reach the kernel's path by two different calls. Their agreement is held by the test `full_path_agrees_with_f_getpath_byte_for_byte`, not by the two sharing one resolver. That test runs on the `darwin-native` CI lane, which runs whenever Rust changes.
- The untrusted `maknae` CLI links `maknae-sys` through `maknae-io` on macOS, because `maknae enroll` calls `resolve_dir`. Its only surface there is the safe path query `full_path`; the CLI gains no other entry point into `unsafe` code.
- **What CI enforces for `macos.rs`.** `darwin-native` runs its tests, checks that they were collected, and runs clippy under decision 2's levels. Its T1 coverage floor is enforced only where `coverage-tiers.sh` runs on a macOS host: the opt-in pre-push hook and local runs. The CI coverage lane is Linux, where the file does not compile, and `coverage-tiers.sh` cannot be scoped to one crate. Mutation testing of `macos.rs` is local only: the CI mutation lane is paused project-wide and runs on Linux, where the file is excluded. The zero-missed evidence is reported in the PR that changes it. The parser, `reply.rs`, is T1-enforced on the Linux CI lane and mutated on the Linux lane when that lane runs.
- **Removal roadmap.** [#401](https://github.com/darkhonor/maknae/issues/401) and [#402](https://github.com/darkhonor/maknae/issues/402) replace `listenfd` and the production `rustix` dependency with `maknae-sys` functions, each its own change under decision 4. [#403](https://github.com/darkhonor/maknae/issues/403) replaces `rpassword` with `nix`'s termios API, which is safe, so it needs no `maknae-sys` function.
- `unsafe` inside dependencies, including code expanded from a dependency's macros, is outside this ADR. `cargo-deny` checks dependencies against the RustSec advisory database, and with `[advisories] unsound = "all"` a published advisory, including a published unsoundness advisory, fails CI for every dependency built for a supported target (`deny.toml` `[graph] targets`), direct or transitive. Nothing in the repository measures unreported `unsafe` in dependencies. This ADR governs Maknae's own source.
- **Every `[advisories] ignore` entry in `deny.toml` carries a comment giving its reachability justification: why the unsound or vulnerable code is not reachable from Maknae.** An ignore without one is an unreviewed control, as an undocumented pin is under AGENTS.md's "document every dependency pin" rule. `deny.toml` has no `ignore` entries today.

## Security control mapping (informative; per ADR-0001)

The decision implements or strengthens these control implementations. It does not satisfy any control by existing.

| Concern | Property | NIST SP 800-53 rev 5 | Authoritative guidance |
|---|---|---|---|
| Memory safety | The compiler refuses `unsafe` written in the source of every member but one. The exception is named and small, and a CI gate proves the boundary holds. rustc's `forbid` covers `unsafe` written in a member's own code and in files it includes; a macro-exported `macro_rules!` body or a proc-macro's output would escape it in consumers, so the gate refuses `macro_export` in every member and any tracked proc-macro crate, and `maknae-sys` defines no macro. Doctests are compiled by rustdoc without the member's lints and are never linked into a shipped artifact; they are a named residual. `unsafe` in dependencies, including their macro expansions, is covered only by `cargo-deny`'s RustSec advisory check, which fails CI on a published advisory, unsoundness included, for every dependency built for a supported target; nothing in the repository measures unreported `unsafe` in dependencies. | SI-16 (memory protection, at the source level); SA-8 (security engineering principles: least privilege applied to language features) | NSA CSI *Software Memory Safety* (Nov 2022); CISA et al., *The Case for Memory Safe Roadmaps* (Dec 2023) |
| Assurance of the one `unsafe` boundary | Each block has a SAFETY argument, which clippy enforces on macOS in CI. The result is checked against the kernel's own answer. The parser is bounds-tested and mutation-tested. `negative-control` proves that the gate and the lint levels fire. | SA-11 and SA-11(1) (developer testing; static analysis) | NSA CSI *Software Memory Safety* (Nov 2022) |
