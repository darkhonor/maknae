#!/usr/bin/env bash
# Lint EVERY workspace crate with `-D warnings`, on this host or on Linux.
#
# WHY THIS EXISTS (#74). Clippy on the dev OS is structurally incapable of
# validating a different OS's `-D warnings` gate. #72 failed CI on a Linux-only
# `dead_code`; this week #275 shipped a `#[cfg(target_os = "macos")]` helper that
# landed between the attribute and the function it guarded -- macOS built clean,
# Rocky failed with `cannot find function macos_log_messages`.
#
# WHY IT LINTS EVERYTHING -- stated as MEASURED, because the first version of
# this comment was wrong in a way that would have misled the next reader.
# `ci.yml` named 13 packages by hand; the workspace has 21. It does NOT follow
# that the other eight were unlinted: `cargo clippy` sets
# `RUSTC_WORKSPACE_WRAPPER`, so a selected package's workspace PATH DEPENDENCIES
# are linted too, and `-- -D warnings` applies to them. Measured: a `dead_code`
# item planted in `maknae-plane`'s lib failed `cargo clippy -p maknae-vault
# --all-targets -- -D warnings` (maknae-vault path-depends on maknae-plane and
# was one of the 13). All eight unnamed members' libs were reachable that way.
#
# The REAL gap, measured the same run, is narrower and about TARGETS, not
# crates: `--all-targets` applies only to SELECTED packages, so an unselected
# path dep's test targets are linted by nothing. A `clippy::len_zero` planted
# inside `#[cfg(test)]` in `maknae-plane` produced ZERO hits under
# `-p maknae-vault --all-targets`, and errored immediately under `--workspace
# --all-targets`. Of the eight unnamed members only `maknae-plane` has any test
# code at all -- `src/fd.rs` and `src/send.rs`, TWO files carrying `cfg(test)`;
# the other seven have none. (An earlier revision said three. That count was
# taken in the scratch copy where I had just planted a `#[cfg(test)]` probe into
# `lib.rs` -- I measured my own fixture and wrote it down as a property of the
# repo.) So the concrete hole this closes is maknae-plane's test targets, plus every
# future crate's, since the set is DERIVED and a new member is picked up
# automatically. Operator ruling 2026-09-10: stubs compile, so clippy validates
# them, so scan everything.
#
# WHY `--workspace` AND NOT A PER-PACKAGE LOOP. Measured: `maknae-kernel`'s
# dev-dependencies enable `maknae-config/hermetic-test-seam`, so a per-package
# build never compiles `maknae-config`'s seam test target and
# `crates/maknae-config/src/authz.rs:1879` is linted by nothing. #74 asked for
# `--workspace`. `feature-resolution-pin.sh`'s per-package precondition governs
# RELEASE BUILDS (`build-invocation-lint.sh`'s regex has no `clippy` arm); for a
# lint, unification lints MORE, not less.
#
# ARCH, HONESTLY. `nlink_t` is `u64` on x86_64-linux and `u32` on aarch64-linux
# (locked libc 0.2.189), so an arm64 container on an Apple-Silicon dev host is
# NOT equivalent to CI's amd64 for cast-family lints. `maknae-io/src/syscall.rs`
# does NOT currently record that split: `:27-38` is the `mode_bits`/`mode_t`
# block, which is `u32` on ALL Linux and therefore arch-invariant, and
# `nlink_count` at `:41-47` documents only the Linux-vs-darwin difference.
# (An earlier revision of this comment cited `:27-38` as evidence of the split;
# it is not.) **Rocky 9 (x86_64, native) is the authoritative Linux lane; this
# container is fast local feedback.**
#
# NETWORK. With the repo mounted, rustup honours `rust-toolchain.toml`'s
# `components` and downloads clippy. `RUSTUP_HOME` is a named volume so that is
# a COLD-run cost only; without that volume it recurred on every run, because
# the official image ships neither clippy nor rustfmt.
set -euo pipefail

# bash 3.2 is fatal here, not merely limiting, and the failure is SILENT-GREEN:
# `"${arr[@]}"` on an empty array is an unbound-variable error under `set -u`
# before bash 4.4, and bash 3.2 lets an EXIT trap's last command overwrite the
# shell's status -- so `--linux` printed `ok` and exited 0 having started no
# container. macOS ships 3.2.57 and macOS is this lane's entire audience, while
# `.github/PULL_REQUEST_TEMPLATE.md` asks the author to attest the lane "ran and
# PASSED". Same guard, same reason, as `coverage-tiers.sh:14-17`.
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  printf 'FAIL: bash >= 4 required (empty-array expansion under set -u; EXIT-trap status masking); macOS system bash is 3.2 — install via brew\n'
  exit 1
fi

root=""
mode=""
usage() { echo "usage: clippy-all.sh [--root <path>] [--linux | --check-inputs]" >&2; exit 2; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# Flags, not positional: `clippy-all.sh --linux` must not be read as a root.
# (`coverage-tiers.sh:29-49` is the in-repo shape for a gate with flags.) A
# SECOND mode flag is refused rather than last-wins: `--linux --check-inputs`
# silently becoming `check` would report a lane that never ran.
set_mode() {
  [ -z "$mode" ] || fail "conflicting mode flags: already '--$mode', then '$1'"
  mode="$2"
}
while [ $# -gt 0 ]; do
  case "$1" in
    --root) [ $# -ge 2 ] || usage; root="$2"; shift 2 ;;
    --linux) set_mode "$1" linux; shift ;;
    --check-inputs) set_mode "$1" check; shift ;;
    -h|--help) echo "usage: clippy-all.sh [--root <path>] [--linux | --check-inputs]"; exit 0 ;;
    *) echo "FAIL: unknown argument '$1'" >&2; usage ;;
  esac
done
[ -n "$mode" ] || mode="host"

if [ -z "$root" ]; then
  root="$(env -u GIT_DIR -u GIT_WORK_TREE git rev-parse --show-toplevel)"
fi
# ABSOLUTE, and entering it is checked. A relative `--root` made `-v
# "$root:/work"` create a NAMED VOLUME rather than a bind mount, so the
# container linted an empty /work and died `No such file or directory` at rc
# 127 with no FAIL line -- the same mute death the metadata branch below was
# built to avoid.
# Resolved into a NEW name: assigning back to `root` clobbered it with the empty
# substitution before `fail` ran, so the diagnostic read `--root ''`.
root_abs="$(cd "$root" 2>/dev/null && pwd -P)" || fail "cannot enter --root '$root'"
root="$root_abs"

command -v python3 >/dev/null 2>&1 || fail "python3 is required to read cargo metadata"

# --- toolchain -------------------------------------------------------------
tc="$root/rust-toolchain.toml"
[ -f "$tc" ] || fail "missing $tc (the image tag and the lint toolchain both come from it)"
channel="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$tc" | head -1)"
[ -n "$channel" ] || fail "no [toolchain] channel in $tc"
# Accept a pinned release only. `stable`/`nightly-<date>` are rustup spellings,
# not Docker Official Images tags, and guessing one would lint a compiler the
# project does not pin.
# A COMPLETE numeric release, anchored. The earlier glob `[0-9]*.[0-9]*`
# accepted `1garbage.2whatever` -- `*` is unrestricted in a shell glob, so it
# validated almost nothing.
if ! printf '%s' "$channel" | grep -Eq '^[0-9]+\.[0-9]+(\.[0-9]+)?$'; then
  fail "channel '$channel' is not a pinned release; refusing to guess a container tag"
fi

# ENFORCE the pin, do not merely REPORT it. `RUSTUP_TOOLCHAIN` in the
# environment overrides `rust-toolchain.toml`, and reading the file does not
# change what rustup selects -- measured: `RUSTUP_TOOLCHAIN=1.94.1` made this
# gate print `toolchain 1.98.1` at exit 0 while `clippy 0.1.94` did the linting.
# That is a false attestation on a gate the PR checklist asks authors to sign.
#
# DETECTED rather than silently overridden, deliberately: exporting
# RUSTUP_TOOLCHAIN="$channel" here would make the two agree by construction and
# leave this guard unreachable by any fixture -- the dead-control shape this
# file already had to fix once, at the package floor.
# `|| true` inside the substitution: under `pipefail` a cargo that cannot even
# answer `--version` made this assignment exit 101 MUTE -- caught by the
# `failing-clippy-prints-FAIL` probe, whose shim answered only `metadata`.
# `RUSTC` / `RUSTC_WRAPPER` swap the compiler under a cargo that still reports
# the pinned version (found on the darwin gate: cargo 1.98.1 drove a 1.94.1
# rustc and printed the pin). Refused, not accommodated -- all six spellings
# cargo honours. `cargo clippy` sets RUSTC_WORKSPACE_WRAPPER itself in the
# CHILD it spawns; one already present in THIS environment is a substitution
# and is refused like the others.
for v in RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER RUSTC_BOOTSTRAP __CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS; do
  [ -z "${!v:-}" ] || fail "$v is set (${!v}); this gate attests the pinned compiler and refuses a substituted one — unset it and re-run"
done
# And the config-file door (`.cargo/config.toml` `[build] rustc` /
# `rustc-wrapper`): env beats config, so export the pinned rustc by path and
# an empty `RUSTC_WRAPPER`. `RUSTC_WORKSPACE_WRAPPER` is left to `cargo
# clippy`, which sets it to clippy-driver in the child it spawns -- that child
# env beats any config `rustc-workspace-wrapper` too.
# RUSTC is resolved UNDER the pinned environment (hermetic execution, below).
# The EIGHTH door: rustflags. `RUSTFLAGS='--cfg target_os="linux"
# -Aexplicit_builtin_cfgs_in_flags'` forged the target's conditional
# compilation -- the Linux-only-item fixture PASSED the darwin check -- and
# `CARGO_ENCODED_RUSTFLAGS` and `[build] rustflags` did the same (codex,
# measured). `--cap-lints=allow` is the same door for a lint gate. Cargo's
# precedence is CARGO_ENCODED_RUSTFLAGS > RUSTFLAGS > build.rustflags, so an
# explicit EMPTY encoded value is a reviewed baseline that beats all three
# sources at once. Nothing in CI, the hooks or the gates relies on inherited
# rustflags (coverage passes its own to llvm-cov, not to this).
# (set in GATE_ENV below)
# Same trust boundary as darwin-cross-check.sh (see its header): the linted
# root's config and manifests are untrusted for this attestation. Measured
# open, then pinned: `[env] CLIPPY_ARGS = { value = "", force = true }` in
# `.cargo/config.toml` REPLACED clippy's generated arguments -- the lint gate
# printed `ok` over a `len_zero` sentinel; `[profile.dev] debug-assertions =
# false` hides `cfg(debug_assertions)`-gated code from the lint; ANSI colour in
# the output breaks the FAIL-line contract. `--config` outranks env and file.
# `cargo clippy` is an EXTERNAL subcommand, and cargo resolves `[alias]`
# BEFORE external subcommands: `[alias] clippy = ["test", "--no-run"]` in any
# config cargo reads -- the repo, a parent directory, $CARGO_HOME -- made this
# gate print `ok` having run zero lints (measured). Built-ins (`check`,
# `metadata`, `tree`) cannot be aliased away; so the subcommand binary is
# resolved by path and invoked directly.
# Both fields of the env entry are set: `--config env.CLIPPY_ARGS.force=false`
# ALONE fails to load when no `[env] CLIPPY_ARGS` table exists (measured:
# "could not load config key"), and `--config` refuses inline tables. With
# `force=false` cargo-clippy's own CLIPPY_ARGS in the environment wins over
# the config value, so the empty value is never what clippy sees.
CLIPPY_PIN=(--config 'env.CLIPPY_ARGS.value=""' --config 'env.CLIPPY_ARGS.force=false'
            --config 'env.RUSTC_BOOTSTRAP.value="-1"' --config 'env.RUSTC_BOOTSTRAP.force=true'
            --config 'profile.dev.panic="unwind"'
            --config 'profile.dev.debug-assertions=true' --config 'profile.test.debug-assertions=true'
            --config 'profile.dev.package."*".debug-assertions=true' --config 'profile.test.package."*".debug-assertions=true'
            --color never)
# NOT closed here, named: `[lints.clippy] <lint> = "allow"` in a member
# manifest -- the sanctioned spelling of `#![allow]`, i.e. source-level
# suppression, which a lint gate cannot and should not override.
meta_err="$(mktemp)"
cleanup() {
  rm -f "$meta_err"
  [ -n "${pin_dir:-}" ] && rm -rf "$pin_dir"
  [ -n "${gate_cwd:-}" ] && rm -rf "$gate_cwd"
  [ -n "${gate_lock:-}" ] && rmdir "$gate_lock" 2>/dev/null
  return 0
}
trap cleanup EXIT
# A GATE-OWNED lint cache, WIPED BEFORE EVERY PASS -- the same replay both
# reviewers measured on this gate after the darwin gate closed it: a workspace
# primed under RUSTC_BOOTSTRAP=1 linted `ok` warm and failed E0554 cold. The
# location may be relocated (the container lane mounts the repo read-only and
# points this at a container-local dir); the CONTENT never survives into a
# pass. Measured cost: 90s for base + two feature passes on Apple Silicon.
CARGO_TARGET_DIR="${CLIPPY_ALL_TARGET_DIR:-$root/target/clippy-all}"
[ -n "${CLIPPY_ALL_TARGET_DIR:-}" ] || [ ! -L "$root/target" ] || fail "'$root/target' is a symlink; the gate-owned target dir must live under a real directory"
[ ! -L "$CARGO_TARGET_DIR" ] || fail "'$CARGO_TARGET_DIR' is a symlink; the gate-owned target dir must be a real directory"
fresh_target() { rm -rf "$CARGO_TARGET_DIR" || fail "cannot wipe the gate-owned target dir '$CARGO_TARGET_DIR'"; }
# ONE run per checkout at a time. Two concurrent runs share the owned dir and
# wipe each other's units mid-pass; measured on macOS: a trashed
# aws-lc-fips-sys build was then read as "SDK-blocked: maknaed" -- not a false
# green (the classifier held), but a false report. `mkdir` is the atomic
# test-and-set; a stale lock after a crash names its own remedy.
lock_path="$CARGO_TARGET_DIR.lock"
mkdir -p "$(dirname "$lock_path")" || fail "cannot create '$(dirname "$lock_path")'"
mkdir "$lock_path" 2>/dev/null || fail "another run holds '$lock_path' (a concurrent gate run in this checkout, or a stale lock after a crash: remove it and re-run)"
gate_lock="$lock_path"   # set only once OWNED: cleanup() releases OUR lock, never a contender's (codex r10)
# --- HERMETIC EXECUTION: an allowlist, not a blocklist --------------------
# Nine review rounds closed cargo knobs one name at a time -- RUSTC, six
# wrapper spellings, RUSTFLAGS, RUSTC_BOOTSTRAP, the channel override, the
# terminal settings, the target dir -- and every round found the next one
# (`CARGO`, read by a directly-invoked cargo-clippy, was the tenth). That is a
# blocklist over a surface nobody can enumerate; this project's rule is deny
# by default. So every cargo / rustc / rustup call below runs
#   (1) under `env -i` with the short allowlist here -- a caller's variable
#       that is not named is simply absent; and
#   (2) from a gate-owned EMPTY directory with `--manifest-path`, because
#       cargo discovers `.cargo/config.toml` from the CURRENT DIRECTORY
#       upward, never from the manifest's -- so the linted tree's config
#       (`[alias]`, `[env]`, `[build]`, `[term]`, `[profile]`, `[unstable]`,
#       rustflags, target-dir, build-dir ...) is never read at all.
# Measured: a config that forged `target_os="linux"`, aliased `check`, forced
# RUSTC_BOOTSTRAP and turned the progress bar on printed `ok` from inside the
# tree and was inert from outside; a forged caller env (CARGO=/usr/bin/true,
# RUSTC_BOOTSTRAP=1, RUSTFLAGS, CARGO_BUILD_TARGET_DIR) was inert under the
# allowlist. The named refusals above stay: defence in depth, and the message
# a caller sees. RUSTUP_TOOLCHAIN is set HERE, to the pin, because rustup
# selects a toolchain from the cwd too and the cwd is now outside the tree.
# The cwd is created under $HOME, never under $TMPDIR, and canonicalised: a
# caller's TMPDIR pointing INSIDE the linted tree put the "outside" cwd back
# under the tree's `.cargo/` (codex r10, measured: the config-env fixture went
# from FAIL to `ok` on both gates). TMPDIR is not passed through either.
mkdir -p "$HOME/.cache/maknae-gates" || fail "cannot create '$HOME/.cache/maknae-gates'"
gate_cwd="$(mktemp -d "$HOME/.cache/maknae-gates/clippy-all.XXXXXX")" || fail "cannot create the gate cwd under '$HOME/.cache/maknae-gates'"   # cleanup() removes it
root_real="$(cd "$root" && pwd -P)"; cwd_real="$(cd "$gate_cwd" && pwd -P)"
case "$cwd_real/" in "$root_real/"*) fail "the gate cwd '$cwd_real' lies under the linted root '$root_real'; refusing to run" ;; esac
# No `.cargo/config[.toml]` may sit on the cwd's ancestor chain other than
# $HOME's own (that one IS $CARGO_HOME's config, read regardless): cargo walks
# EVERY ancestor of the cwd, and `/tmp/.cargo/config.toml` on a shared host or
# `$HOME/.cache/.cargo/` would be a config hierarchy nobody audited
# (critical-review r10, measured with an ancestor config).
home_real="$(cd "$HOME" && pwd -P)"; anc="$cwd_real"
while :; do
  anc="$(dirname "$anc")"
  if [ "$anc" != "$home_real" ]; then
    for cfg in "$anc/.cargo/config.toml" "$anc/.cargo/config"; do
      [ -e "$cfg" ] && fail "'$cfg' sits on the gate cwd's ancestor chain and cargo would read it; move or remove it and re-run"
    done
  fi
  [ "$anc" = / ] && break
done
# THE TRUSTED ROOTS. PATH, HOME, CARGO_HOME and RUSTUP_HOME define WHICH
# MACHINE is attesting -- its toolchains, its registry, its native tools --
# and a gate cannot bootstrap trust from nothing: a caller who controls them
# controls the machine (codex r10 measured a `cc` shim on PATH steering a
# build script's capability probe; that is the machine's C compiler, not the
# tree's). Everything else in the caller's environment is dropped.
BASE_ENV=(env -i "PATH=$PATH" "HOME=$HOME" "RUSTUP_TOOLCHAIN=$channel")
# CARGO_BUILD_JOBS changes SCHEDULING, never a verdict; the harness sets it to
# 1 so the `--keep-going` negative control is deterministic (dropping it made
# that probe probabilistic -- critical-review r10).
for v in CARGO_HOME RUSTUP_HOME LANG LC_ALL SSL_CERT_FILE SSL_CERT_DIR CARGO_BUILD_JOBS; do
  [ -z "${!v:-}" ] || BASE_ENV+=("$v=${!v}")
done
benv() { (cd "$gate_cwd" && "${BASE_ENV[@]}" "$@"); }
# The compiler is resolved UNDER that environment, and the resolved BINARY is
# version-checked below -- not the PATH proxy. Resolved from the root under the
# caller's environment, a rustup DIRECTORY OVERRIDE for the root selected an
# installed 1.94.1 while the proxy, asked under the pin, answered 1.98.1 (codex
# r10: `ok, toolchain 1.98.1` with a 1.94.1 rustc doing the work).
which_err="$(mktemp)"
if ! RUSTC="$(benv rustup which rustc 2>"$which_err")"; then
  sed 's/^/  /' "$which_err" >&2; rm -f "$which_err"
  fail "cannot resolve the pinned rustc (rustup which rustc failed — see above)"
fi
rm -f "$which_err"; [ -x "$RUSTC" ] || fail "resolved rustc '$RUSTC' is not executable"
GATE_ENV=("${BASE_ENV[@]}" "RUSTC=$RUSTC" "RUSTC_WRAPPER=" "RUSTC_WORKSPACE_WRAPPER=" "CARGO_ENCODED_RUSTFLAGS="
          "CARGO_TERM_COLOR=never" "CARGO_TERM_PROGRESS_WHEN=never"
          "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" "CARGO_BUILD_BUILD_DIR=$CARGO_TARGET_DIR")
genv() { (cd "$gate_cwd" && "${GATE_ENV[@]}" "$@"); }
gcargo() { genv cargo "$@"; }
[ -z "${RUSTUP_TOOLCHAIN:-}" ] || [ "$RUSTUP_TOOLCHAIN" = "$channel" ] || fail "toolchain mismatch: $tc pins '$channel' but RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN is overriding the pin — unset it and re-run"
actual_tc="$( (gcargo --version 2>/dev/null || true) | awk '{print $2}')"
[ -n "$actual_tc" ] || fail "cannot determine the active cargo version (cargo --version failed)"
# And the resolved rustc BINARY (the one cargo-clippy's driver sits beside),
# not the PATH proxy: a directory override made them differ (codex r10).
actual_rc="$( ("$RUSTC" --version 2>/dev/null || true) | awk '{print $2}')"
[ -n "$actual_rc" ] || fail "cannot determine the resolved rustc version ($RUSTC --version failed)"
for pair in "cargo:$actual_tc" "rustc:$actual_rc"; do
  case "${pair#*:}" in
    "$channel"|"$channel".*) : ;;
    *) fail "toolchain mismatch: $tc pins '$channel' but the active ${pair%%:*} is '${pair#*:}'${RUSTUP_TOOLCHAIN:+ (RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN is overriding the pin)}" ;;
  esac
done

# --- the input set, WITH A FLOOR -------------------------------------------
# CONTRIBUTING.md:126: "a gate that DISCOVERS its input set needs a floor --
# including when the discovery is `cargo metadata` rather than `find`, which is
# how p1-manifest-lint was mis-classified as safe on the first pass." Streams are
# captured separately so a metadata failure prints a FAIL line rather than dying
# mute -- `expect_reject` needs one.
#
# ONE metadata call, `--no-deps`. It SUCCEEDS on `members = []` and returns
# zero packages, which is what keeps the floor below reachable by a fixture;
# the full-resolve call errors on that same fixture and would have turned the
# floor into dead code no negative control could fire.
if ! meta="$(gcargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1 --locked 2>"$meta_err")"; then
  echo "FAIL: cargo metadata failed:" >&2; sed 's/^/  /' "$meta_err" >&2; exit 1
fi

count="$(printf '%s' "$meta" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["packages"]))')"
[ "$count" -gt 0 ] || fail "cargo metadata resolved ZERO packages; refusing to report a lint of nothing"
# The lint binary, the resolving call and the pin file are needed by the
# host and check paths only; `--linux` re-runs this script INSIDE the
# container, which builds its own (a host without clippy or a warm registry
# must still be able to drive the container lane).
if [ "$mode" != linux ]; then
which_err="$(mktemp)"
if ! CARGO_CLIPPY_BIN="$(benv rustup which cargo-clippy 2>"$which_err")"; then
  sed 's/^/  /' "$which_err" >&2; rm -f "$which_err"
  fail "cannot resolve the pinned cargo-clippy (rustup which cargo-clippy failed — see above)"
fi
rm -f "$which_err"; [ -x "$CARGO_CLIPPY_BIN" ] || fail "resolved cargo-clippy '$CARGO_CLIPPY_BIN' is not executable"
# Per-package profile overrides -- `[profile.dev.package.<name>]` in the linted
# root's config OR its root manifest -- outrank the `"*"` glob pin above for
# members AND for every dependency (codex, round 8: a debug_assertions-gated
# error in a path dependency EXCLUDED from the workspace went from FAIL to
# `ok`; the earlier pins named only the members). Every RESOLVED package gets
# a named pin, in ONE `--config <file>` (CLI precedence). The resolving call
# sits AFTER the floor so `members = []` still reaches the floor, not this.
if ! resolved_meta="$(gcargo metadata --manifest-path "$root/Cargo.toml" --format-version 1 --locked 2>"$meta_err")"; then
  echo "FAIL: cargo metadata (resolving, --locked) failed — the lock file is stale or the graph cannot resolve:" >&2; sed 's/^/  /' "$meta_err" >&2; exit 1
fi
pin_dir="$(mktemp -d)"   # cleanup() removes it
pin_file="$pin_dir/profile-pins.toml"
printf '%s' "$resolved_meta" | python3 -c 'import json, sys
for n in sorted({p["name"] for p in json.load(sys.stdin)["packages"]}):
    q = json.dumps(n)
    print("[profile.dev.package." + q + "]\ndebug-assertions = true\n[profile.test.package." + q + "]\ndebug-assertions = true")' > "$pin_file"
[ -s "$pin_file" ] || fail "the per-package profile pin file is empty; refusing to lint without it"
CLIPPY_PIN+=(--config "$pin_file")
fi

# Feature passes: ONE PER DECLARED NON-DEFAULT FEATURE, redundant or not.
#
# This block has been through three shapes, and the history is the reason for
# the current one. (1) The first cut did exactly this, and REPORTED it as
# "2 feature pass(es)" -- implying coverage added, when both were no-ops:
# `crates/maknae-kernel/Cargo.toml:37,42` dev-depend on `hermetic-test-seam`,
# `--workspace` unifies features across members including dev-deps, so the
# feature was already live in the base pass (measured: 0.12s/0.14s cache hits
# against a 58.9s base; a `len_zero` behind that `cfg` caught by the base pass
# alone). (2) The second cut got clever: derive the DARK set as
# `declared - resolve.nodes[].features` and pass only those. Codex broke it
# with two resolver-3 fixtures where metadata's feature UNION is not what the
# base pass COMPILES -- a Windows-only dev-dependency running on macOS, and a
# build-dependency used by a real `build.rs`. In both, metadata said "enabled",
# the gate said 0 passes and `ok`, and an explicit `--features a/dark` caught
# the planted lint at rc 101. Metadata collapses platform-inactive edges and
# the separate build-dep feature context; the derivation therefore produced
# FALSE NEGATIVES -- features whose test targets went unlinted.
#
# (3) So: back to one pass per declared feature, which codex confirmed catches
# every case, and which is REDUNDANT rather than WRONG when the feature is
# already unified. Fail-closed prefers redundant. The redundant pass costs a
# cache hit; the clever derivation cost a missed lint. What changed from (1) is
# only the REPORT: the OK line counts passes RUN and says they are per declared
# feature -- it no longer implies each one added coverage.
# Post-condition: a python3 that dies here would otherwise mean "no feature
# passes" and `ok` (the darwin gate fixed the same shape in round 9).
if ! feats="$(printf '%s' "$meta" | python3 -c '
import json, sys
for p in json.load(sys.stdin)["packages"]:
    for f in sorted(p.get("features", {})):
        if f != "default":
            print(p["name"] + "/" + f)' 2>"$meta_err" | sort)"; then
  sed 's/^/  /' "$meta_err" >&2; fail "cannot derive the declared features from cargo metadata (see above); refusing to report feature passes"
fi
featc="$(printf '%s\n' "$feats" | sed '/^$/d' | wc -l | tr -d ' ')"

# The INPUTS line is not the OK line. The first version printed `clippy-all: ok
# (...)` here, BEFORE any lint ran, so a gate whose clippy failed had `ok` as
# its only stdout, and `--check-inputs` printed a success line for zero passes.
echo "clippy-all: inputs (${count} workspace packages, ${featc} declared feature(s), toolchain ${channel}, mode ${mode})"
if [ "$mode" = "check" ]; then
  echo "clippy-all: ok (inputs only; --check-inputs ran NO lints)"
  exit 0
fi

# `ran` counts passes that actually COMPLETED, so the OK line reports work done
# rather than work intended.
ran=0
run_lints() {
  fresh_target
  genv "$CARGO_CLIPPY_BIN" clippy --locked --manifest-path "$root/Cargo.toml" --workspace --all-targets "${CLIPPY_PIN[@]}" -- -D warnings \
    || fail "clippy failed on the base --workspace pass"
  ran=$((ran + 1))
  while IFS= read -r pf; do
    [ -n "$pf" ] || continue
    # One pass per declared feature, redundant where already unified -- see the
    # block above for why redundant beats derived.
    fresh_target
    genv "$CARGO_CLIPPY_BIN" clippy --locked --manifest-path "$root/Cargo.toml" --workspace --all-targets --features "$pf" "${CLIPPY_PIN[@]}" -- -D warnings \
      || fail "clippy failed on feature pass '$pf'"
    ran=$((ran + 1))
  done <<< "$feats"
}

if [ "$mode" = "host" ]; then
  cd "$root" || fail "cannot enter '$root'"
  run_lints
  echo "clippy-all: ok (${count} workspace packages linted, ${ran} clippy pass(es) RUN = 1 base + ${featc} per declared feature, toolchain ${channel}, mode host)"
  exit 0
fi

# --- linux mode ------------------------------------------------------------
engine=""
for e in podman docker; do
  command -v "$e" >/dev/null 2>&1 || continue
  # REACHABILITY, not presence: `command -v docker` succeeding while the daemon
  # is down is the case that turns an intended SKIP into a hard error on the
  # push path. Bounded, because `podman info` against a hung machine VM blocks
  # forever on exactly that path.
  "$e" info >/dev/null 2>&1 &
  probe=$!
  waited=0
  while kill -0 "$probe" 2>/dev/null && [ "$waited" -lt 30 ]; do
    sleep 1; waited=$((waited + 1))
  done
  if kill -0 "$probe" 2>/dev/null; then
    kill -9 "$probe" 2>/dev/null || true
    wait "$probe" 2>/dev/null || true
    echo "note: '$e' did not answer 'info' within 30s; treating as unreachable" >&2
    continue
  fi
  if wait "$probe"; then engine="$e"; break; fi
done
if [ -z "$engine" ]; then
  msg="no reachable container engine (podman/docker). This is a LANE GAP, not a pass: the Linux lints did not run."
  if [ "${MAKNAE_REQUIRE_LINUX_CLIPPY:-0}" = 1 ]; then fail "$msg"; fi
  echo "SKIP: $msg Set MAKNAE_REQUIRE_LINUX_CLIPPY=1 to make this a hard failure."
  exit 0
fi

# Seeded non-empty so the expansion is never an empty array (see the bash guard).
run_args=(run --rm)
[ -n "${MAKNAE_LINUX_CLIPPY_PLATFORM:-}" ] && run_args+=(--platform "$MAKNAE_LINUX_CLIPPY_PLATFORM")
# `:ro,z` (SHARED relabel), never `:ro,Z`. `Z` applies a container-PRIVATE
# label (an MCS category pair) recursively to the bind source, which on Rocky 9
# -- SELinux enforcing, and the host CONTRIBUTING names as the authoritative
# Linux lane -- locks other containers and host services out of the developer's
# own checkout. `z` still relabels, honestly: measured after a run the tree is
# `container_file_t:s0`, shared type and NO categories. Reversible with
# `restorecon -R`; not a no-op, but not exclusive either.
mnt=":ro"; [ "$engine" = podman ] && mnt=":ro,z"
"$engine" volume create maknae-clippy-cargo  >/dev/null 2>&1 || true
# RUSTUP_HOME too: the official image ships neither clippy nor rustfmt, so
# without this volume rustup re-downloaded the components on EVERY run, not
# only a cold one.
"$engine" volume create maknae-clippy-rustup >/dev/null 2>&1 || true
run_args+=(
  -v "$root:/work${mnt}" -w /work
  -e CLIPPY_ALL_TARGET_DIR=/ctarget
  -v maknae-clippy-cargo:/ccargo   -e CARGO_HOME=/ccargo
  -v maknae-clippy-rustup:/crustup -e RUSTUP_HOME=/crustup
  "rust:${channel}"
)
# The container runs THIS SCRIPT in host mode against the mounted repo. One code
# path for both lanes -- marshalling the lint loop into the container instead
# would be a second copy of the thing this gate exists to have one of (and the
# image's /bin/sh is dash, which cannot take a bash function).
cleanup   # `exec` never returns, so the EXIT trap would not fire.
exec "$engine" "${run_args[@]}" \
  bash -c 'set -e
    # A bind mount that did not take leaves /work EMPTY, and the script below
    # then dies "No such file or directory" at rc 127 with no FAIL line.
    if [ ! -f /work/ci/gates/clippy-all.sh ]; then
      echo "FAIL: /work does not contain the repo — the bind mount did not take" >&2
      exit 1
    fi
    # aws-lc-fips-sys needs cmake + go to build; the official rust image has
    # neither, and without them the lane dies on a BUILD failure that has
    # nothing to do with lints. (Same constraint the Debian test host has:
    # "no cmake -> cannot build anything pulling aws-lc-fips-sys".)
    if ! command -v cmake >/dev/null || ! command -v go >/dev/null; then
      apt-get update -qq && apt-get install -y -qq --no-install-recommends cmake golang-go >/dev/null
    fi
    exec bash /work/ci/gates/clippy-all.sh --root /work'
