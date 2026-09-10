#!/usr/bin/env bash
# Cross-compile check for macOS (Apple Silicon) from any host: every workspace
# member, checked ONE AT A TIME for `aarch64-apple-darwin`; a member whose
# build fails inside an SDK crate's build script is classified SDK-BLOCKED FROM
# THIS HOST and named; any other failure is a FAIL.
#
# WHY THIS EXISTS (#198). macOS is a production target (AGENTS.md) and CI is
# Linux-first. Adding `--target aarch64-apple-darwin` locally, once, caught
# `RecvFlags::CMSG_CLOEXEC` not existing on darwin -- `maknae-io::recv_delegated`
# did not compile there AT ALL, and off Linux a received descriptor arrives
# without close-on-exec, a security-relevant delta in a T1 crate. The
# `darwin-cross` job has run this check since #199. What it consumed until
# this gate was `DARWIN_CRATES`, a hand-written list of SEVEN whose own comment
# said "NOT gate-verified against any manifest". Measured from Rocky 9 (no
# SDK), SEVENTEEN members check clean; ten crates, `maknae-authz-basic` among
# them, were compiled for macOS by nothing. Same defect class as #74.
#
# WHY CARGO DECIDES, NOT A DERIVATION. The first cut of this gate DERIVED the
# checkable set by walking `cargo metadata --filter-platform` for members whose
# closure reached an SDK crate. Two reviewers broke it in the bad direction --
# members silently EXCLUDED that an individual darwin check passes: a
# build-dependency on `ring` (build scripts compile for the HOST, not the
# target); a dependency whose own DEV-dependency is `ring` (dev-deps are not
# inherited by consumers); an optional `ring` feature enabled by a DIFFERENT
# member (metadata's resolve is the workspace UNION, so the edge appears
# though `-p member` alone never activates it). Each reported `ok` having
# skipped a member. That is the metadata-union-is-not-what-cargo-compiles class
# #74 already hit once. So: no model of cargo's resolution. Run cargo, per
# member, with the exact flags the check uses, and READ what happened.
#
# WHAT "SDK-BLOCKED" MEANS, MEASURED. `aws-lc-sys`, `aws-lc-fips-sys` and
# `ring` have build scripts that need a macOS SDK. From Rocky 9:
#   error: failed to run custom build command for `aws-lc-fips-sys v0.13.17`
#   CMake Error ... CMakeDetermineCCompiler   (rc 101)
# That exact shape -- cargo's "failed to run custom build command for `<one of
# the three>`" -- is the ONLY failure this gate classifies as blocked. A build
# script of any OTHER crate failing, or any compile error, is a FAIL. On a
# darwin host nothing is blocked and every member is checked; "blocked" is a
# statement about THIS host, and the report says so.
#
# THIS IS A CHECK, NOT VERIFICATION. It proves the code BUILDS for darwin, not
# that `F_GETPATH` returns what ADR-0009 expects. `darwin-native` on `macos-26`
# is the verification lane, and it tests the WHOLE workspace, SDK crates
# included -- the runner has the SDK.
set -euo pipefail

# bash >= 4: arrays under `set -u` (see clippy-all.sh for the 3.2 failure).
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  printf 'FAIL: bash >= 4 required; macOS system bash is 3.2 — install via brew\n' >&2
  exit 1
fi

TARGET="aarch64-apple-darwin"   # the ONLY macOS target (AGENTS.md: no x86 macOS)
SDK_CRATES='aws-lc-sys|aws-lc-fips-sys|ring'
root=""
mode=""
usage() { echo "usage: darwin-cross-check.sh [--root <path>] [--check-inputs]" >&2; exit 2; }
fail() { echo "FAIL: $*" >&2; exit 1; }
set_mode() {
  [ -z "$mode" ] || fail "conflicting mode flags: already '--$mode', then '$1'"
  mode="$2"
}
while [ $# -gt 0 ]; do
  case "$1" in
    --root) [ $# -ge 2 ] || usage; root="$2"; shift 2 ;;
    --check-inputs) set_mode "$1" check; shift ;;
    -h|--help) echo "usage: darwin-cross-check.sh [--root <path>] [--check-inputs]"; exit 0 ;;
    *) echo "FAIL: unknown argument '$1'" >&2; usage ;;
  esac
done
[ -n "$mode" ] || mode="check-run"

if [ -z "$root" ]; then
  root="$(env -u GIT_DIR -u GIT_WORK_TREE git rev-parse --show-toplevel)"
fi
# Resolved into a NEW name: assigning back to `root` clobbered it with the empty
# substitution before `fail` ran, so the diagnostic read `--root ''`.
root_abs="$(cd "$root" 2>/dev/null && pwd -P)" || fail "cannot enter --root '$root'"
root="$root_abs"
command -v python3 >/dev/null 2>&1 || fail "python3 is required to read cargo metadata"

# --- toolchain: read the pin, ENFORCE it ---------------------------------------
# `RUSTUP_TOOLCHAIN` in the environment overrides `rust-toolchain.toml`, and
# `RUSTC` / `RUSTC_WRAPPER` swap the compiler under a cargo that still reports
# the pinned version -- measured: `RUSTC=<1.94.1 rustc>` with cargo 1.98.1
# compiled the whole check and printed `toolchain 1.98.1`. This gate attests
# the PINNED compiler's result, so an override is refused, not accommodated.
tc="$root/rust-toolchain.toml"
[ -f "$tc" ] || fail "missing $tc"
channel="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$tc" | head -1)"
[ -n "$channel" ] || fail "no [toolchain] channel in $tc"
if ! printf '%s' "$channel" | grep -Eq '^[0-9]+\.[0-9]+(\.[0-9]+)?$'; then
  fail "channel '$channel' is not a pinned release"
fi
# All six spellings cargo honours for substituting the compiler. Measured with a
# logging wrapper on a clean fixture: each of `RUSTC_WORKSPACE_WRAPPER`,
# `CARGO_BUILD_RUSTC`, `CARGO_BUILD_RUSTC_WRAPPER` and
# `CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER` was invoked 14 times while the gate
# printed `ok ... toolchain 1.98.1`. The workspace wrapper is the worst of them
# here: cargo applies it to PRIMARY packages only -- exactly the attested set.
# RUSTC_BOOTSTRAP unlocks nightly feature gates on the pinned STABLE compiler
# -- `#![cfg_attr(target_os = "macos", feature(never_type))]` went from E0554
# to `ok` under it (measured). rustc reads it from its own process env, so
# unlike RUSTFLAGS the config `[env]` table delivers it too; that form is
# neutralised below with the CLIPPY_ARGS pattern.
# `__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly` is cargo's OTHER
# nightly switch: it unlocks `[unstable] profile-rustflags`, and
# `[profile.dev] rustflags` is a FOURTH rustflags source that outranks the
# pinned encoded value (measured: the Linux-only-item fixture passed the
# darwin check). Refused like RUSTC_BOOTSTRAP; the profile source stays shut
# only because cargo's channel stays stable.
for v in RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER RUSTC_BOOTSTRAP __CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS; do
  [ -z "${!v:-}" ] || fail "$v is set (${!v}); this gate attests the pinned compiler and refuses a substituted one — unset it and re-run"
done
# The SEVENTH door is a file: `.cargo/config.toml` `[build] rustc = ...` /
# `rustc-wrapper = ...` in the checked root, any parent, or $CARGO_HOME drives
# every compile with no env var set -- measured: `[build] rustc = <1.94.1>`
# compiled the tree while this gate printed `toolchain 1.98.1`, and a logging
# `rustc-wrapper` was invoked 14 times. `cargo config get` is nightly-only, so
# the file cannot be read on stable; but ENV BEATS CONFIG, so the gate exports
# its own: the pinned toolchain's rustc by absolute path (which also pins the
# compiler against a config `rustc`), and EMPTY wrappers, which cargo treats
# as "none". (`CARGO_BUILD_RUSTC=""` is NOT a neutraliser -- cargo tries to
# exec "" -- so the rustc path is set, not blanked.)
# RUSTC is resolved UNDER the pinned environment (HERMETIC EXECUTION, below).
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
# TRUST BOUNDARY, stated once. For the purpose of this attestation the checked
# root's `.cargo/config.toml`, its manifests and the caller's environment are
# UNTRUSTED. Two MECHANISMS carry that (HERMETIC EXECUTION, below): every
# cargo call runs under `env -i` with a short allowlist, so the caller's
# environment is absent rather than filtered; and from a cwd outside the
# tree with `--manifest-path`, so the tree's config is never read. The
# `--config` pins cover what those cannot: the root manifest's `[profile]`
# and the machine's `$CARGO_HOME/config.toml`. The doors below were each
# measured open and closed one at a time BEFORE the two mechanisms existed;
# they are listed because each has a probe that still proves the outcome: RUSTUP_TOOLCHAIN;
# RUSTC / RUSTC_WRAPPER / RUSTC_WORKSPACE_WRAPPER / CARGO_BUILD_RUSTC*;
# `[build] rustc`/`rustc-wrapper`; RUSTFLAGS / CARGO_ENCODED_RUSTFLAGS /
# `[build] rustflags` / target-specific spellings; `[profile.dev]
# debug-assertions` and its per-package overrides -- members and
# every resolved dependency, by name, in one `--config` file (flip
# `cfg(debug_assertions)`); the panic strategy (`cfg(panic)`); RUSTC_BOOTSTRAP
# and `__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS` (env and `[env]`; the
# latter also unlocks `[profile.<p>] rustflags`, a fourth rustflags source);
# CARGO_TERM_COLOR and CARGO_TERM_PROGRESS_WHEN (ANSI and carriage returns in
# the log the classifier reads); CARGO_TARGET_DIR / `[build] target-dir` and
# warm-dir replay (gate-owned dir, wiped); cargo's "no targets matched"
# no-op; a proc-macro member's host artifact counted as darwin evidence.
# NOT closed here, named: build scripts and proc-macros, which EXECUTE
# ARBITRARY HOST CODE as this gate's user during the check -- a malicious
# build.rs can forge the very streams this classifier reads, and no
# log-reading gate can defend against that; the per-pass wipe closes the one
# demonstrated shape (re-planting cached units for a later pass), the control
# for a build.rs change is review; `$CARGO_HOME/config.toml`, the machine's
# (needed for the registry; pinned only where the CLI pins name a knob);
# `[source]`/`[patch]` replacement (tracked
# separately); `[lints]` in a member manifest, the sanctioned spelling of
# `#![allow]` (source-level, not this gate's to override); and the member
# list itself -- "cargo decides" means the root
# manifest's `[workspace] members` decides, so a crate dropped from it is
# checked by nothing (the backstop is coverage-tiers' `git ls-files`
# universe, which fails closed on an uncovered tracked `.rs`).
# A GATE-OWNED target dir, WIPED BEFORE EVERY CARGO PASS. The pins bind only
# what cargo decides to recompile: a unit primed in a shared `target/` with
# RUSTC_BOOTSTRAP=1 was replayed as fresh and counted as checked (measured),
# and a wipe at start alone was not enough -- codex (round 9) had an earlier
# member's build script re-plant primed units for a later member inside one
# run. Cold before every pass is the only state in which "the pinned compiler
# produced this" is true by construction; measured cost 148s for the whole
# repo on Apple Silicon (50s with one wipe). A wipe that cannot happen is a
# FAIL, not a mute death. The dir must sit under a REAL directory: `rm -rf`
# through an attacker-chosen `target` symlink would reach outside the root.
meta_err="$(mktemp)"
# ONE cleanup for every temp this script makes. Later temps used to re-set the
# EXIT trap with their own `rm -f` list, and the list never learned about the
# pin dir -- measured: six of eight runs left `profile-pins.toml` behind.
cleanup() {
  local f
  for f in "${meta_err:-}" "${log:-}" "${json:-}" "${tree_err:-}"; do [ -n "$f" ] && rm -f "$f"; done
  [ -n "${pin_dir:-}" ] && rm -rf "$pin_dir"
  [ -n "${gate_cwd:-}" ] && rm -rf "$gate_cwd"
  [ -n "${gate_lock:-}" ] && rmdir "$gate_lock" 2>/dev/null
  return 0
}
trap cleanup EXIT
[ ! -L "$root/target" ] || fail "'$root/target' is a symlink; the gate-owned target dir must live under a real directory"
CARGO_TARGET_DIR="$root/target/darwin-cross-check"   # into GATE_ENV below
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
# No wipe here: run_pass wipes before every pass, and `--check-inputs` must not
# touch the cache (critical-review r10).
# Profile knobs that alter conditional compilation, pinned to the dev-profile
# defaults a fresh checkout compiles with. `--config` beats env and file.
# The top-level pin alone was half a door: `[profile.dev.package.<member>]
# debug-assertions = false` -- in `.cargo/config.toml` OR the workspace root
# Cargo.toml -- still hid the error, and cargo's `"*"` package glob EXCLUDES
# workspace members, so the wildcard form does not reach them either. The pin
# is therefore emitted three ways: top level, `"*"` (dependencies), and one
# NAMED entry per workspace member (the member list is already in hand).
PROFILE_PIN=(--config 'profile.dev.debug-assertions=true' --config 'profile.test.debug-assertions=true'
             --config 'profile.dev.package."*".debug-assertions=true' --config 'profile.test.package."*".debug-assertions=true'
             --config 'env.RUSTC_BOOTSTRAP.value="-1"' --config 'env.RUSTC_BOOTSTRAP.force=true'
             --config 'profile.dev.panic="unwind"')
# `-1` is rustc's explicit "bootstrap OFF", forced so it wins even over a
# `[env]` entry that forces "1" (the env var itself is refused above, so the
# forced config value never collides with a legitimate setting). And the
# PANIC STRATEGY is conditional compilation too: `[profile.dev] panic =
# "abort"` or CARGO_PROFILE_DEV_PANIC=abort flipped `cfg(panic = "unwind")`
# and hid gated code -- the repo's CI grep for `panic = "abort"` covers
# manifests, not the env or config spellings. Pinned to unwind, which the
# workspace requires anyway (maknae-config's catch_unwind boundary). The test
# profile's panic setting is ignored by cargo, so only dev is pinned.
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
#       upward, never from the manifest's -- so the checked tree's config
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
# caller's TMPDIR pointing INSIDE the checked tree put the "outside" cwd back
# under the tree's `.cargo/` (codex r10, measured: the config-env fixture went
# from FAIL to `ok` on both gates). TMPDIR is not passed through either.
mkdir -p "$HOME/.cache/maknae-gates" || fail "cannot create '$HOME/.cache/maknae-gates'"
gate_cwd="$(mktemp -d "$HOME/.cache/maknae-gates/darwin-cross-check.XXXXXX")" || fail "cannot create the gate cwd under '$HOME/.cache/maknae-gates'"   # cleanup() removes it
root_real="$(cd "$root" && pwd -P)"; cwd_real="$(cd "$gate_cwd" && pwd -P)"
case "$cwd_real/" in "$root_real/"*) fail "the gate cwd '$cwd_real' lies under the checked root '$root_real'; refusing to run" ;; esac
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
# RUSTUP_TOOLCHAIN from the caller is dropped by the allowlist and re-set to
# the pin; a caller who set it to something ELSE meant it, and is told.
[ -z "${RUSTUP_TOOLCHAIN:-}" ] || [ "$RUSTUP_TOOLCHAIN" = "$channel" ] || fail "toolchain mismatch: $tc pins '$channel' but RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN is overriding the pin — unset it and re-run"
actual_tc="$( (gcargo --version 2>/dev/null || true) | awk '{print $2}')"
[ -n "$actual_tc" ] || fail "cannot determine the active cargo version (cargo --version failed)"
actual_rc="$( ("$RUSTC" --version 2>/dev/null || true) | awk '{print $2}')"   # the resolved BINARY, not the proxy
[ -n "$actual_rc" ] || fail "cannot determine the active rustc version (rustc --version failed)"
for pair in "cargo:$actual_tc" "rustc:$actual_rc"; do
  case "${pair#*:}" in
    "$channel"|"$channel".*) : ;;
    *) fail "toolchain mismatch: $tc pins '$channel' but the active ${pair%%:*} is '${pair#*:}'${RUSTUP_TOOLCHAIN:+ (RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN is overriding the pin)}" ;;
  esac
done

# --- the member set, WITH A FLOOR (CONTRIBUTING.md: a gate that DISCOVERS its
# --- input set needs one) -----------------------------------------------------
if ! meta="$(gcargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1 --locked 2>"$meta_err")"; then
  echo "FAIL: cargo metadata failed:" >&2; sed 's/^/  /' "$meta_err" >&2; exit 1
fi
members_line="$(printf '%s' "$meta" | python3 -c 'import json,sys; print(" ".join(sorted(p["name"] for p in json.load(sys.stdin)["packages"])))')"
# name -> manifest_path, so a compiler artifact can be attributed to THE member
# being checked (a bin-only member with `required-features` makes cargo say
# "no targets matched; this is a no-op", exit 0, and compile NOTHING).
declare -A manifest_of
while IFS=$'\t' read -r nm mp; do manifest_of["$nm"]="$mp"; done < <(printf '%s' "$meta" | python3 -c 'import json,sys
for p in json.load(sys.stdin)["packages"]: print(p["name"] + "\t" + p["manifest_path"])')
read -r -a members <<< "$members_line"
nmem="${#members[@]}"
[ "$nmem" -gt 0 ] || fail "cargo metadata resolved ZERO packages; refusing to report a check of nothing"
# Per-package profile pins are built from the RESOLVING metadata call below
# (every package in the graph, not only these members): see `pin_file`.
# name -> its declared non-default features, one darwin pass each (the #74
# rule: "fail-closed prefers redundant"). Measured: `-p maknae-authz-basic`
# resolves with NO features from Linux -- the only edge enabling its
# `hermetic-test-seam` is `maknae-kernel`'s dev-dep, and kernel is SDK-blocked
# there -- so seven `cfg(feature = "hermetic-test-seam")` sites were
# cross-checked for darwin by nothing.
declare -A features_of
# A failing process substitution does not trip `set -e`; an empty map here
# would silently mean "no feature passes" and `ok`. Status captured, FAIL on
# error (the post-condition rule CONTRIBUTING sets for every tool-derived set).
if ! features_tsv="$(printf '%s' "$meta" | python3 -c 'import json,sys
for p in json.load(sys.stdin)["packages"]:
    fs = sorted(f for f in p.get("features", {}) if f != "default")
    print(p["name"] + "\t" + " ".join(fs))' 2>"$meta_err")"; then
  sed 's/^/  /' "$meta_err" >&2; fail "cannot derive the declared features from cargo metadata (see above); refusing to report feature passes"
fi
while IFS=$'\t' read -r nm fl; do [ -n "$nm" ] && features_of["$nm"]="$fl"; done <<< "$features_tsv"
# Which members are proc-macro-only: cargo compiles those for the HOST, so an
# artifact of theirs proves nothing about darwin. They are reported as
# host-only, counted neither as checked nor as blocked.
declare -A procmacro_only
while IFS= read -r nm; do [ -n "$nm" ] && procmacro_only["$nm"]=1; done < <(printf '%s' "$meta" | python3 -c 'import json,sys
for p in json.load(sys.stdin)["packages"]:
    kinds = {k for t in p["targets"] for k in t["kind"]}
    if kinds and kinds <= {"proc-macro", "custom-build"}: print(p["name"])')
# The lock is an INPUT, and `--no-deps` does not validate it (measured: a
# Cargo.lock written before a member was added passes `metadata --no-deps
# --locked`). A resolving call does, so `--check-inputs` sees a stale lock too
# rather than leaving it for the first `cargo check` to trip over.
if ! resolved_meta="$(gcargo metadata --manifest-path "$root/Cargo.toml" --format-version 1 --locked 2>"$meta_err")"; then
  echo "FAIL: cargo metadata (resolving, --locked) failed — the lock file is stale or the graph cannot resolve:" >&2; sed 's/^/  /' "$meta_err" >&2; exit 1
fi
# Per-package profile overrides -- `[profile.dev.package.<name>]` in the
# checked root's config OR its root manifest -- outrank the `"*"` glob pin
# above for members AND for every dependency. Codex (round 8) measured it: a
# debug_assertions-gated darwin error in a path dependency EXCLUDED from the
# workspace went from FAIL to `ok` under `[profile.dev.package.leaf]
# debug-assertions = false`, both spellings, both gates; the round-7 pins named
# only the members. So every RESOLVED package -- the unfiltered graph, all
# platforms -- gets a named pin, written to ONE `--config <file>` (CLI
# precedence, the same as KEY=VALUE; 256 names on this repo would otherwise
# be ~1000 argv entries). Names are quoted: TOML bare keys refuse what cargo
# accepts. Measured on the real graph: no unmatched-spec or ambiguous-spec
# diagnostic for names resolved at several versions (`syn` x3).
pin_dir="$(mktemp -d)"   # cleanup() removes it
pin_file="$pin_dir/profile-pins.toml"
printf '%s' "$resolved_meta" | python3 -c 'import json, sys
for n in sorted({p["name"] for p in json.load(sys.stdin)["packages"]}):
    q = json.dumps(n)
    print("[profile.dev.package." + q + "]\ndebug-assertions = true\n[profile.test.package." + q + "]\ndebug-assertions = true")' > "$pin_file"
[ -s "$pin_file" ] || fail "the per-package profile pin file is empty; refusing to check without it"
PROFILE_PIN+=(--config "$pin_file")

# --- the target: a FAIL naming the fix, never a skip ---------------------------
# A gate that skips on the push path is a false green (#74). A gate that
# installs things is a side effect nobody asked for. So: refuse, and say how.
# Queried under the pinned RUSTUP_TOOLCHAIN like every other toolchain call:
# rustup's selection is directory-scoped and the cwd is outside the tree, so
# the pin is carried in the environment. Probed: a `rustup` shim that reports
# the target only when RUSTUP_TOOLCHAIN equals the pin catches "drop the pin"
# with no second toolchain.
if ! genv rustup target list --installed 2>/dev/null | grep -q "^${TARGET}\$"; then
  fail "the ${TARGET} target is not installed; run: rustup target add ${TARGET}"
fi

host="$( (genv rustc -vV 2>/dev/null) | sed -n 's/^host: //p')"
echo "darwin-cross-check: inputs (${nmem} members, target ${TARGET}, host ${host:-unknown}, toolchain ${channel}, mode ${mode})"
if [ "$mode" = check ]; then
  echo "darwin-cross-check: ok (inputs only; --check-inputs ran NO check)"
  exit 0
fi

# --- the check, ONE MEMBER AT A TIME -----------------------------------------
# Per member, not `-p a -p b ...` in one call, so each member's feature
# resolution is exactly what `cargo check -p member` gives -- no unification
# from a sibling turning a feature on or off -- and so a blocked member cannot
# abort the check of an unblocked one. The target dir is shared, so the
# dependency graph compiles once; the rest are incremental.
checked=(); blocked=(); hostonly=(); feature_blocked=(); feature_passes=0
log="$(mktemp)"; json="$(mktemp)"   # cleanup() removes them
cd "$root" || fail "cannot enter '$root'"
# Classification is CORROBORATED, not read off one line. Three rounds of review
# each broke a text-only classifier: an unanchored regex let a build script that
# QUOTED cargo's sentence flip a FAIL into "blocked"; anchoring it at column 0
# was answered by `compile_error!("failed to run custom build command for
# `ring v0.17.14`")` -- rustc renders user text at column 0 too, so "cargo has
# one emitter" was true and insufficient; and an exemption for `error: could
# not compile` (added so the summary line would not count as a second error)
# let a rustc that died with NO diagnostic -- SIGKILL, OOM, ENOSPC -- register
# as blocked, because that summary line was the only error left. Each one
# printed `ok` while a member did not build for darwin: the exact defect class
# this gate exists to end.
#
# So "blocked" now requires ALL of:
#   (a) cargo's build-script line at column 0 naming an SDK crate;
#   (b) NO ` --> ` span line anywhere -- every rustc diagnostic carries one,
#       cargo's build-script error never does (measured on a real blocked
#       member from Rocky 9: zero span lines, zero `could not compile` lines);
#   (c) no OTHER `error` line at column 0 -- and no exemption for `could not
#       compile`, which a real blocked log never contains and a silent rustc
#       death always does;
#   (d) the named SDK crate is actually IN the member's darwin dependency
#       graph -- a member with no `ring` in its tree cannot be blocked by
#       `ring`, whatever its source text says.
# Anything else is a FAIL with the log printed. The classifying line is echoed
# per blocked crate so the report shows WHY.
#
# Diagnostic-format attacks via RUSTFLAGS / CARGO_BUILD_RUSTFLAGS
# (`--error-format=short`, which would drop the span line and the column-0
# `error:`) are closed by rustc itself: the flag collides with cargo's own
# `--error-format=json` and rustc prints `error: Option 'error-format' given
# more than once` at column 0, which (c) refuses. Measured; recorded so the
# next reviewer need not re-derive it.
#
# WHAT THE HARNESS OBSERVES, honestly. (a) is observed by every blocked
# fixture; (c) by the silent-rustc-death probe (a rustc that exits 1 with no
# diagnostic leaves only `could not compile`, which (c) refuses and the
# round-3 exemption did not). On the impersonation fixture (`compile_error!`
# quoting cargo's sentence) (b), (c) and (d) each refuse INDEPENDENTLY, so
# removing any ONE of them survives the suite (measured: 50/50 each) while
# removing all three is caught. The redundancy is deliberate: (b) rests on
# how rustc renders, (c) on cargo's summary line, (d) on the dependency
# graph -- three different things would have to change together.
sdk_re="^error: failed to run custom build command for \`(${SDK_CRATES}) v"
# ONE cargo pass -- a fresh cache, then `cargo check` for one member, with one
# feature or none. stdout (the JSON stream) -> $json, stderr (rendered
# diagnostics) -> $log. Returns cargo's status.
run_pass() { # <member> <feature-or-empty>
  local m="$1" f="$2"; local -a fa=()
  [ -z "$f" ] || fa=(--features "$f")
  fresh_target
  gcargo check --locked --keep-going --manifest-path "$root/Cargo.toml" -p "$m" ${fa[@]+"${fa[@]}"} --target "$TARGET" --all-targets --color never "${PROFILE_PIN[@]}" \
    --message-format=json-render-diagnostics >"$json" 2>"$log"
}
# Counted: an artifact attributed to THIS member's manifest, not a build
# script, and emitted for the DARWIN target (its filenames live under the
# gate-owned `<target-dir>/<triple>/`) -- a proc-macro's host artifact would
# otherwise pass. Prints the count; a counter that dies is a printed FAIL and
# a non-zero status (the caller exits), never a mute death.
count_artifacts() { # <member>
  local m="$1" n
  counter_err="$(mktemp)"
  if ! n="$(python3 - "${manifest_of[$m]}" "$json" "$CARGO_TARGET_DIR/$TARGET/" 2>"$counter_err" <<'PYA'
import json, sys
mp, tgt, n = sys.argv[1], sys.argv[3], 0
for line in open(sys.argv[2]):
    try: msg = json.loads(line)
    except ValueError: continue
    if msg.get("reason") == "compiler-artifact" and msg.get("manifest_path") == mp \
       and "custom-build" not in msg.get("target", {}).get("kind", []) \
       and any(f.startswith(tgt) for f in msg.get("filenames", [])):
        n += 1
print(n)
PYA
)"; then
    sed 's/^/  /' "$counter_err" >&2; rm -f "$counter_err"
    fail "the artifact counter failed for member '$m' (see above); refusing to guess whether anything was checked"
  fi
  rm -f "$counter_err"; printf '%s' "$n"
}
# THE classifier, one for every pass (the round-10 feature pass had its own
# one-line grep, and codex plus the fresh-context reviewer each showed the
# round-3 impersonation and masking shapes back on that path). On a
# non-zero pass: "blocked" requires (a)-(d) above -- (d) corroborated with
# the pass's own feature selection -- and is printed; anything else is a FAIL
# naming the pass.
classify_blocked() { # <member> <feature-or-empty> <what>
  local m="$1" f="$2" what="$3" sdk_line err_blocks named tree_out; local -a fa=()
  [ -z "$f" ] || fa=(--features "$f")
  sdk_line="$(grep -Em1 "$sdk_re" "$log" || true)"
  # (b) is scoped to ERROR blocks -- an `^error` header through the next
  # `^error`/`^warning` header, NOT to the next blank line: rustc renders a
  # multi-line message with a whitespace-only continuation line (measured),
  # and a spanned WARNING elsewhere in a blocked member's graph must not turn
  # a correct "blocked" into a FAIL.
  err_blocks="$(awk '/^error/{p=1; print; next} /^warning/{p=0} p' "$log")"
  tree_err="$(mktemp)"   # cleanup() removes it
  if [ -n "$sdk_line" ] \
     && ! printf '%s\n' "$err_blocks" | grep -Eq '^[[:space:]]*--> ' \
     && ! grep -Eq '^error(\[E[0-9]+\])?: ' <(grep -Ev "$sdk_re" "$log") \
     && { named="$(printf '%s' "$sdk_line" | sed -E "s/^error: failed to run custom build command for \`(${SDK_CRATES}) v.*/\1/")";
          if ! tree_out="$(gcargo tree --locked --manifest-path "$root/Cargo.toml" -p "$m" ${fa[@]+"${fa[@]}"} --target "$TARGET" -e normal,build,dev --prefix none 2>"$tree_err")"; then
            sed 's/^/  /' "$tree_err" >&2; rm -f "$tree_err"
            fail "cargo tree failed for $what while corroborating an SDK-blocked classification (see above)"
          fi
          rm -f "$tree_err"; printf '%s\n' "$tree_out" | grep -Eq "^${named} v"; }; then
    echo "  blocked: $m${f:+/$f} — $sdk_line" >&2
  else
    cat "$log" >&2
    fail "cross-check failed for ${TARGET}: $what (not solely an SDK build-script failure — see above)"
  fi
}
for m in "${members[@]}"; do
  if run_pass "$m" ""; then
    if [ -n "${procmacro_only[$m]:-}" ]; then
      # Compiled for the host by definition; say so, count it as neither.
      hostonly+=("$m"); echo "  host-only (proc-macro): $m" >&2
    else
      n_art="$(count_artifacts "$m")" || exit 1
      if [ "${n_art:-0}" -gt 0 ]; then checked+=("$m"); else
        cat "$log" >&2
        fail "member '$m' exited 0 but cargo compiled NO ${TARGET} target of it (\"no targets matched\" -- e.g. every target gated by required-features); a member is counted only when something of it was checked for darwin"
      fi
    fi
  else
    classify_blocked "$m" "" "member '$m'"; blocked+=("$m")
    # NO `continue`: a feature can REMOVE the SDK dependency (codex r10:
    # `portable = ["ring/portable"]` made `ring` build without an SDK, and a
    # sentinel behind `portable` was never compiled). The base outcome is not
    # evidence about the feature outcome; every declared feature gets its own
    # cold pass and the same classifier, blocked base or not.
  fi
  # One extra pass per feature THIS member declares, so feature-gated code is
  # cross-checked where it is live (measured: `-p maknae-authz-basic` from
  # Linux resolves with NO features). A proc-macro member's feature passes run
  # too -- for the host, so their success is not darwin evidence and is not
  # counted -- because a feature-gated error there is still an error. A pass
  # that is SDK-blocked is reported as such and NOT counted as a pass: a member
  # whose feature code was never compiled is not fully checked, and the OK
  # line says so. `read -a`, not word-splitting: no glob expansion.
  read -r -a flist <<< "${features_of[$m]:-}"
  for f in ${flist[@]+"${flist[@]}"}; do
    if run_pass "$m" "$f"; then
      if [ -z "${procmacro_only[$m]:-}" ]; then
        n_art="$(count_artifacts "$m")" || exit 1
        [ "${n_art:-0}" -gt 0 ] || { cat "$log" >&2; fail "member '$m' with feature '$f' exited 0 but cargo compiled NO ${TARGET} target of it; a feature pass counts only when something of the member was checked for darwin"; }
        feature_passes=$((feature_passes + 1))
      fi
    else
      classify_blocked "$m" "$f" "member '$m' with feature '$f'"; feature_blocked+=("$m/$f")
    fi
  done
done
nchk="${#checked[@]}"; nblk="${#blocked[@]}"
[ "$nchk" -gt 0 ] || fail "every member is SDK-blocked from this host (${blocked[*]}); an empty cross-check set is a refusal, not a pass"
# On a host whose triple IS the target the SDK is present, so an SDK build-
# script failure is a REAL failure -- cmake missing, disk full, two runs
# trashing one cache (measured on the maintainer's Mac: "blocked: maknaed",
# `ok`; critical-review r10 named it). The classifier still ran and echoed its
# evidence above; the VERDICT is a FAIL that carries the same counts the OK
# line would, so the harness asserts the classification on both hosts and the
# verdict per host. Unobservable where host != target -- recorded.
if [ "$host" = "$TARGET" ] && { [ "$nblk" -gt 0 ] || [ "${#feature_blocked[@]}" -gt 0 ]; }; then
  fail "on a host whose triple IS the target (${host}) nothing may be SDK-blocked — the SDK is present, so a build-script failure inside an SDK crate is a real failure: ${nblk} SDK-blocked from ${host}: ${blocked[*]:-none}, ${#feature_blocked[@]} feature pass(es) SDK-blocked: ${feature_blocked[*]:-none} (cross-checked ${nchk} crates for ${TARGET} + ${feature_passes} feature pass(es))"
fi
echo "darwin-cross-check: ok (cross-checked ${nchk} crates for ${TARGET} + ${feature_passes} feature pass(es), ${nblk} SDK-blocked from ${host:-this host}: ${blocked[*]:-none}, ${#feature_blocked[@]} feature pass(es) SDK-blocked: ${feature_blocked[*]:-none}, ${#hostonly[@]} host-only proc-macro: ${hostonly[*]:-none}, toolchain ${channel})"
