#!/bin/bash
# Build the macOS .pkg from source. Mirrors packaging/deb/build-deb.sh's contract:
# non-interactive, hermetic, deterministic output name.
#
#   build-pkg.sh <version>        e.g. build-pkg.sh 0.1.0
#
# Output: dist/Maknae-<version>-arm64.pkg  (+ the component pkgs, kept in dist/ so
# smoke.sh can inspect them without re-running this script)
#
# Apple Silicon ONLY (AGENTS.md). Signing is AD-HOC: Developer ID signing and
# notarization are out of scope (#227 item 3) and no seam is written for them.
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
# `cargo auditable`, not bare `cargo build`: CI ships release binaries this way
# (ci.yml:145) and the embedded dependency SBOM is an SCRM control.
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
# NON-VALIDATED crypto module while the posture claims otherwise is far worse than
# a clean startup failure.
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
codesign --force --sign - --options runtime --timestamp=none "$STAGE/$FIPS_BASE"
for b in maknaed maknae; do
    codesign --force --sign - --options runtime --timestamp=none \
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

# Strip xattrs BEFORE pkgbuild. Files here carry com.apple.provenance; `install`
# preserves them, and pkgbuild then serialises each as an AppleDouble `._name`
# sibling INTO the payload — measured. Those become real installed files.
xattr -rc "$D"
# Hermetic: do not rely on a fresh clone carrying git's exec bit.
chmod +x "$HERE/scripts"/*

pkgbuild --root "$D" --identifier io.maknae.daemon --version "$VERSION" \
         --scripts "$HERE/scripts" --install-location / "$STAGE/maknae-daemon.pkg"

# --- component: cli ----------------------------------------------------------
C="$STAGE/cli"
install -d "$C/usr/local/bin"
install -m 0755 "$BIN/maknae" "$C/usr/local/bin/maknae"
xattr -rc "$C"
pkgbuild --root "$C" --identifier io.maknae.cli --version "$VERSION" \
         --install-location / "$STAGE/maknae-cli.pkg"

# --- distribution ------------------------------------------------------------
mkdir -p "$DIST"
OUT="$DIST/Maknae-${VERSION}-arm64.pkg"
productbuild --distribution "$HERE/distribution.xml" --package-path "$STAGE" \
             --version "$VERSION" "$OUT"
cp "$STAGE/maknae-daemon.pkg" "$STAGE/maknae-cli.pkg" "$DIST/"

echo "Built: $OUT"
echo "FIPS module: $FIPS_BASE -> $FIPS_LIBDIR (absolute install name, no rpath)"
echo "UNSIGNED distribution (ad-hoc component binaries only) — Developer ID signing"
echo "and notarization are out of scope (#227 item 3)."
