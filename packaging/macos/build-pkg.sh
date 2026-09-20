#!/bin/bash
# Build the macOS .pkg from source. Mirrors packaging/deb/build-deb.sh's contract:
# non-interactive, hermetic, deterministic output name.
#
#   build-pkg.sh <version>        e.g. build-pkg.sh 0.1.0
#
# Output: dist/Maknae-<version>-arm64.pkg  (+ the component pkgs, kept in dist/ so
# smoke.sh can inspect them without re-running this script)
#
# Apple Silicon ONLY (AGENTS.md). Signing defaults to AD-HOC and is DECLARED, never
# inferred (#227 item 3):
#
#   MAKNAE_SIGN_IDENTITY      Developer ID Application  -> binaries + FIPS dylib
#   MAKNAE_INSTALLER_IDENTITY Developer ID Installer    -> productsign the .pkg
#   MAKNAE_NOTARY_PROFILE     notarytool keychain profile -> submit + staple
#
# Unset means ad-hoc, exactly as before. SET-BUT-ABSENT REFUSES: a named identity
# that silently fell back to ad-hoc would ship an artifact the operator believes is
# signed, and the difference is invisible until first launch on another Mac.
set -euo pipefail

VERSION="${1:?usage: build-pkg.sh <version>}"
if ! printf '%s' "$VERSION" | grep -qE '^[0-9][0-9A-Za-z.~+_-]*$'; then
    echo "ERROR: invalid version '$VERSION' (allowed: ^[0-9][0-9A-Za-z.~+_-]*\$)" >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DIST="$REPO/dist"
TARGET="aarch64-apple-darwin"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

[ "$(uname -m)" = "arm64" ] || { echo "ERROR: Apple Silicon host required" >&2; exit 1; }

# REFUSE on missing tooling; never skip silently. The embedded SBOM is an SCRM
# control and CONTRIBUTING.md names rust-audit-info as pre-push tooling, so its
# absence means the control cannot be attested — a stop, not a shrug.
command -v rust-audit-info >/dev/null 2>&1 || {
    echo "REFUSED: rust-audit-info not installed; the embedded-SBOM control cannot be attested." >&2
    exit 2
}

# --- build, one package at a time -------------------------------------------
# Built through `cargo auditable`, never a plain unaudited invocation: CI ships
# release binaries that way (ci.yml:145) and the embedded dependency SBOM is an
# SCRM control.
#
# NOTE for whoever edits this comment: ci/gates/build-invocation-lint.sh scans
# EVERY logical line, comments included, for the build-family pattern
# `cargo (build|rustc|auditable build|deb|generate-rpm)` and requires exactly one
# `-p`. Writing that pattern in prose here fails the gate (and POS-FAILs
# negative-control's clean-fixture probe). Describe the invocation without
# spelling it out.
# build-invocation-lint accepts either spelling, so the gate will not catch a
# regression here — this comment is the guard.
#
# RUSTFLAGS carries the embedded __TEXT,__info_plist section, per-package because
# each binary needs its OWN Info.plist. It lives HERE and not in a
# .cargo/config.toml: whether this repo should have one at all is a deliberately
# held open question (UNFORMALIZED.md, 2026-09-12). COST, accepted knowingly:
# RUSTFLAGS is a whole-graph fingerprint input, so the two builds do not share a
# cache and aws-lc-fips-sys compiles twice.
build_one() {
    local pkg="$1" info="$2"
    ( cd "$REPO" && RUSTFLAGS="-C link-arg=-Wl,-sectcreate,__TEXT,__info_plist,$HERE/$info" \
        cargo auditable build --release --locked --target "$TARGET" -p "$pkg" )
}
build_one maknaed Info.maknaed.plist
build_one maknae  Info.maknae.plist

BIN="$REPO/target/$TARGET/release"
for b in maknaed maknae; do
    [ -x "$BIN/$b" ] || { echo "ERROR: missing binary $BIN/$b" >&2; exit 1; }
done

# --- the FIPS module is a DYLIB on macOS, and it must be pinned --------------
# Upstream REQUIRES shared linkage here: aws-lc/CMakeLists.txt:842 refuses a static
# FIPS build outside Linux, and aws-lc-fips-sys/README.md:143 calls shared "the
# required form for FIPS on macOS and Windows". The binaries therefore load
# @rpath/libaws_lc_fips_*.dylib, and cargo only makes that work by injecting DYLD_*.
#
# The hazard is FAIL-OPEN, not fail-closed. Upstream warns that an unresolved
# @rpath means "a different libcrypto may be loaded" — it SEARCHES. Running on a
# crypto module nobody chose, self-tested or shipped, while the posture claims
# otherwise, is far worse than a clean startup failure.
#
# So pin it by ABSOLUTE install name and ship no rpath at all — the pattern Cisco
# AnyConnect uses for its own crypto on this platform (/opt/cisco/anyconnect/lib/...,
# zero LC_RPATH). One file, no search order, nothing to hijack.
FIPS_LIBDIR="/usr/local/lib/maknae"
FIPS_DYLIB="$(find "$REPO/target/$TARGET/release/build" -name 'libaws_lc_fips_*_crypto.dylib' \
                   -type f 2>/dev/null | head -1)"
[ -n "$FIPS_DYLIB" ] || {
    echo "ERROR: no libaws_lc_fips_*_crypto.dylib under target/$TARGET/release/build" >&2
    exit 1
}
FIPS_BASE="$(basename "$FIPS_DYLIB")"
cp "$FIPS_DYLIB" "$STAGE/$FIPS_BASE"
chmod u+w "$STAGE/$FIPS_BASE"

install_name_tool -id "$FIPS_LIBDIR/$FIPS_BASE" "$STAGE/$FIPS_BASE"
for b in maknaed maknae; do
    install_name_tool -change "@rpath/$FIPS_BASE" "$FIPS_LIBDIR/$FIPS_BASE" "$BIN/$b"
done

# REFUSE to package a binary that still carries an unresolved @rpath. This gate is
# what keeps the fail-open hazard out of a shipped artifact.
for b in maknaed maknae; do
    if otool -L "$BIN/$b" | grep -q '@rpath/'; then
        echo "ERROR: $b still references an @rpath dylib after install_name_tool:" >&2
        otool -L "$BIN/$b" | grep '@rpath/' >&2
        exit 1
    fi
done

# --- sign: ad-hoc, WITH Hardened Runtime ------------------------------------
# AFTER install_name_tool — rewriting a load command invalidates any signature.
# Sign the dylib first, then the executables that load it.
# `--options runtime` is accepted by ad-hoc signing, so the HARDENING lands today
# and only the IDENTITY waits on a Developer ID; notarization then cannot fail on a
# missing runtime flag, the usual first rejection.
# THE IDENTITY IS DECLARED, NEVER DETECTED. Auto-selecting from the keychain is how
# a build signs with whatever happens to be installed; a release states its intent.
#
# MEASURED 2026-09-19 on Apple Silicon: Hardened Runtime enables library validation,
# which requires the process and the loaded dylib to carry the SAME Team ID. One
# Developer ID over BOTH satisfies it with NO entitlement (verified: clean start);
# ad-hoc over both fails rc 134, "different Team IDs" (negative control, observed).
# So the dylib is signed from the SAME variable as the binaries — signing the
# executables alone produces an artifact that only fails once installed.
SIGN_ID="${MAKNAE_SIGN_IDENTITY:-}"
if [ -n "$SIGN_ID" ]; then
    # CAPTURE then match. `security ... | grep -q` SIGPIPEs the writer, and under
    # `set -o pipefail` the pipeline returns 141 precisely when the match SUCCEEDS
    # (the same trap smoke.sh documents at its otool checks).
    _ids="$(security find-identity -v -p codesigning 2>/dev/null || true)"
    case "$_ids" in
        *"$SIGN_ID"*) ;;
        *) echo "REFUSED: signing identity not in the keychain: $SIGN_ID" >&2
           echo "  A named-but-absent identity must never fall back to ad-hoc." >&2
           exit 2 ;;
    esac
    CODESIGN_ARGS=(--sign "$SIGN_ID" --options runtime --timestamp)
else
    CODESIGN_ARGS=(--sign - --options runtime --timestamp=none)
fi

codesign --force "${CODESIGN_ARGS[@]}" "$STAGE/$FIPS_BASE"
for b in maknaed maknae; do
    codesign --force "${CODESIGN_ARGS[@]}" \
        --entitlements "$HERE/${b}.entitlements" "$BIN/$b"
    codesign --verify --strict --verbose=2 "$BIN/$b"
done
for b in maknaed maknae; do
    rust-audit-info "$BIN/$b" >/dev/null || { echo "ERROR: no embedded SBOM in $b" >&2; exit 1; }
done

# --- component: daemon -------------------------------------------------------
# NOTE what is NOT here: /etc/maknae. A payload's BOM is authoritative and would
# land ./etc/maknae as 0755 root:wheel, CLOBBERING preinstall's 0750 root:_maknae;
# and a payload always overwrites, which would revert an enrolled maknae.yaml on
# every upgrade. Defaults go to /usr/local/share and postinstall installs them only
# if absent. (/etc is also a symlink to private/etc, which a payload would have to
# model.)
D="$STAGE/daemon"
install -d "$D/usr/local/bin" "$D/Library/LaunchDaemons" \
           "$D/usr/local/share/maknae/defaults" "$D$FIPS_LIBDIR"
install -m 0755 "$BIN/maknaed" "$D/usr/local/bin/maknaed"
install -m 0755 "$STAGE/$FIPS_BASE" "$D$FIPS_LIBDIR/$FIPS_BASE"
install -m 0644 "$HERE/io.maknae.maknaed.plist" "$D/Library/LaunchDaemons/io.maknae.maknaed.plist"
# Apple ships plists in binary1. Convert the INSTALLED copy; the repo keeps XML so
# the unit stays reviewable in a diff.
plutil -convert binary1 "$D/Library/LaunchDaemons/io.maknae.maknaed.plist"
install -m 0644 "$REPO/packaging/common/authz.yaml"  "$D/usr/local/share/maknae/defaults/authz.yaml"
install -m 0644 "$REPO/packaging/common/maknae.yaml" "$D/usr/local/share/maknae/defaults/maknae.yaml"
# The shipped skeleton is LINUX-SHAPED and would be wrong here if left alone:
# maknae.yaml carries no `transport:` section, and maknae-config's compiled default
# is /run/maknae/maknaed.sock (crates/maknae-config/src/transport.rs:15, no darwin
# cfg) — a path that does not exist on macOS at all. `maknae enroll` writes the
# correct value (bins/maknae/src/enroll/mod.rs:1432), but the skeleton must not ship
# a path this platform cannot host in the meantime.
cat >> "$D/usr/local/share/maknae/defaults/maknae.yaml" <<'MACOS_TRANSPORT'

transport:
  # macOS only. maknae-config's compiled default is /run/maknae/maknaed.sock, and
  # /run does not exist on macOS. `maknae enroll` rewrites this file and sets the
  # same value; it is pinned here so an un-enrolled read never names a path this
  # platform cannot host. The PARENT directory's group is load-bearing — see
  # packaging/macos/scripts/preinstall.
  socket_path: /usr/local/var/run/maknae/maknaed.sock
MACOS_TRANSPORT

# Strip what CAN be stripped, then VERIFY BY RE-READING — never by exit status.
#
# CORRECTED 2026-09-20 (#332). This previously read "Strip xattrs BEFORE pkgbuild
# ... — measured", and trusted `xattr -rc` alone. That line is INERT for
# com.apple.provenance: measured at the syscall, removexattr(2) returns
# rc=0/errno=0 and leaves the attribute in place, so NO exit status anywhere can
# detect the failure. It is kept because it still clears genuinely removable
# attributes (quarantine and the like); it is simply no longer believed.
#
# The attribute is attached per-write by the RESPONSIBLE APPLICATION of the
# writing process — not by macOS 26, not by APFS, not by pkgbuild. A build driven
# by launchd, CI or Terminal.app writes an untagged payload; one driven by an
# agent session, an editor's integrated terminal, or a third-party terminal tags
# every file and directory it writes, and pkgbuild then serialises each as an
# AppleDouble `._name` sibling INTO the payload, where it becomes a real
# installed file that uninstall.sh knows nothing about. See
# ci/gates/payload-xattr-clean.sh for the full measurement trail.
#
# The gate REFUSES rather than warns: a package shipping `._` entries into
# /usr/local is worse than a build that stops.
xattr -rc "$D" 2>/dev/null || true
"$REPO/ci/gates/payload-xattr-clean.sh" "$D"

# Scripts are STAGED, not passed from the repo. Two reasons, both load-bearing:
#   1. pkgbuild reads --scripts IN PLACE, so the repo files' OWN attributes end up
#      in the Scripts archive — and that archive is NOT in the BOM, so smoke.sh's
#      exact-payload assertion is structurally blind to a `._postinstall` there.
#      Copying makes the staged tree inherit THIS build's cleanliness instead of
#      whatever historically tagged the working copy.
#   2. The old `chmod +x "$HERE/scripts"/*` mutated the working tree on every
#      build. Staging keeps the repo read-only here.
S="$STAGE/scripts"
install -d "$S"
# Hermetic: do not rely on a fresh clone carrying git's exec bit.
install -m 0755 "$HERE/scripts"/* "$S/"
xattr -rc "$S" 2>/dev/null || true
"$REPO/ci/gates/payload-xattr-clean.sh" "$S"

pkgbuild --root "$D" --identifier io.maknae.daemon --version "$VERSION" \
         --scripts "$S" --install-location / "$STAGE/maknae-daemon.pkg"

# --- component: cli ----------------------------------------------------------
C="$STAGE/cli"
install -d "$C/usr/local/bin"
install -m 0755 "$BIN/maknae" "$C/usr/local/bin/maknae"
xattr -rc "$C" 2>/dev/null || true
"$REPO/ci/gates/payload-xattr-clean.sh" "$C"
pkgbuild --root "$C" --identifier io.maknae.cli --version "$VERSION" \
         --install-location / "$STAGE/maknae-cli.pkg"

# --- distribution ------------------------------------------------------------
mkdir -p "$DIST"
OUT="$DIST/Maknae-${VERSION}-arm64.pkg"
productbuild --distribution "$HERE/distribution.xml" --package-path "$STAGE" \
             --version "$VERSION" "$OUT"
cp "$STAGE/maknae-daemon.pkg" "$STAGE/maknae-cli.pkg" "$DIST/"

# --- productsign: a DIFFERENT certificate from the binaries -------------------
# Developer ID *Installer* signs the .pkg; Developer ID *Application* signs code.
# They are not interchangeable, and notarization refuses an unsigned installer.
INST_ID="${MAKNAE_INSTALLER_IDENTITY:-}"
if [ -n "$INST_ID" ]; then
    _iids="$(security find-identity -v 2>/dev/null || true)"
    case "$_iids" in
        *"$INST_ID"*) ;;
        *) echo "REFUSED: installer identity not in the keychain: $INST_ID" >&2; exit 2 ;;
    esac
    productsign --sign "$INST_ID" --timestamp "$OUT" "$OUT.signed"
    mv "$OUT.signed" "$OUT"
    SIGNED_PKG=yes
else
    SIGNED_PKG=no
fi

# --- notarize + staple -------------------------------------------------------
# Stapling is what makes FIRST LAUNCH work OFFLINE; without the ticket attached,
# Gatekeeper needs the network to reach Apple and an air-gapped install fails.
NOTARY="${MAKNAE_NOTARY_PROFILE:-}"
if [ -n "$NOTARY" ]; then
    # REFUSE rather than submit something that cannot pass. Notarization requires
    # Developer ID code signatures AND a Developer ID Installer signature; an
    # ad-hoc submission is rejected by Apple after a slow round trip.
    [ -n "$SIGN_ID" ] || { echo "REFUSED: notarization needs MAKNAE_SIGN_IDENTITY (binaries are ad-hoc)" >&2; exit 2; }
    [ "$SIGNED_PKG" = yes ] || { echo "REFUSED: notarization needs MAKNAE_INSTALLER_IDENTITY (the .pkg is unsigned)" >&2; exit 2; }
    xcrun notarytool submit "$OUT" --keychain-profile "$NOTARY" --wait
    xcrun stapler staple "$OUT"
    xcrun stapler validate "$OUT"
fi

echo "Built: $OUT"
echo "FIPS module: $FIPS_BASE -> $FIPS_LIBDIR (absolute install name, no rpath)"
if [ -n "$SIGN_ID" ]; then
    echo "Code signature: $SIGN_ID (Hardened Runtime, timestamped; dylib signed to match)"
else
    echo "Code signature: AD-HOC (set MAKNAE_SIGN_IDENTITY for Developer ID)"
fi
echo "Installer signature: ${INST_ID:-none}"
# NOT a ${x:+a}${x:-b} pair: when x is SET, :+ emits a AND :- emits x's VALUE, so
# both arms fire and the line reads "...profile 'maknae'maknae". Observed 2026-09-19.
if [ -n "$NOTARY" ]; then
    echo "Notarization: submitted and stapled via profile '$NOTARY'"
else
    echo "Notarization: not requested"
fi
