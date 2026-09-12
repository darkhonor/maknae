#!/bin/bash
# Build the maknae .deb from pre-built binaries + packaging/ assets.
# CI-ready: non-interactive, hermetic, deterministic output name. Can run on any
# host with dpkg-deb (no Debian target host required for the build itself).
#
#   build-deb.sh <version> [<bindir>]
#     <version>  e.g. 0.1.0  (required — becomes the deb Version <version>-1)
#     <bindir>   dir holding the pre-built `maknaed` + `maknae` (default: target/release)
#
# Output: dist/maknae_<version>-1_amd64.deb
#
# NOTE (vs the rpm): Debian gets the AppArmor profile, NOT the SELinux .pp or the
# fapolicyd trust fragment — both are SELinux-N/A on Debian and are deliberately
# skipped here. The Vault-port helper IS shipped for layout parity but is a no-op
# on AppArmor hosts (documented SELinux-only in the README).
set -euo pipefail

VERSION="${1:?usage: build-deb.sh <version> [<bindir>]}"
# Validate VERSION before it lands in control/changelog/sed/paths: a crafted
# value could inject Debian control fields or arbitrary output paths.
if ! printf '%s' "$VERSION" | grep -qE '^[0-9][0-9A-Za-z.~+_-]*$'; then
    echo "ERROR: invalid version '$VERSION' (allowed: ^[0-9][0-9A-Za-z.~+_-]*\$)" >&2
    exit 2
fi
BINDIR="${2:-target/release}"
ARCH="amd64"
DEBVER="${VERSION}-1"

HERE="$(cd "$(dirname "$0")" && pwd)"          # packaging/deb
REPO="$(cd "$HERE/../.." && pwd)"              # repo root
COMMON="$REPO/packaging/common"
DIST="$REPO/dist"

for b in maknaed maknae maknae-egress; do
    [ -x "$BINDIR/$b" ] || { echo "ERROR: missing binary $BINDIR/$b" >&2; exit 1; }
done

PKG_ROOT="$(mktemp -d)"
trap 'rm -rf "$PKG_ROOT"' EXIT

# --- DEBIAN control directory ---------------------------------------------------
mkdir -p "$PKG_ROOT/DEBIAN"
# Stamp Version (and Architecture, for safety) from the CLI so the git tag is the
# single source of truth.
sed -e "s/^Version:.*/Version: ${DEBVER}/" \
    -e "s/^Architecture:.*/Architecture: ${ARCH}/" \
    "$HERE/control" > "$PKG_ROOT/DEBIAN/control"

install -m 0755 "$HERE/postinst" "$PKG_ROOT/DEBIAN/postinst"
install -m 0755 "$HERE/prerm"    "$PKG_ROOT/DEBIAN/prerm"
install -m 0755 "$HERE/postrm"   "$PKG_ROOT/DEBIAN/postrm"

# conffiles — the two shipped YAML defaults dpkg must preserve across upgrades.
# (Their ownership is re-asserted root:_maknae 0640 in postinst on every configure;
# dpkg records conffiles root:root and tracks CONTENT only.)
cat > "$PKG_ROOT/DEBIAN/conffiles" <<'CONF'
/etc/maknae/authz.yaml
/etc/maknae/maknae.yaml
/etc/apparmor.d/usr.bin.maknaed
/etc/apparmor.d/usr.bin.maknae-egress
CONF

# --- Binaries -------------------------------------------------------------------
install -D -m 0755 "$BINDIR/maknaed" "$PKG_ROOT/usr/bin/maknaed"
install -D -m 0755 "$BINDIR/maknae"  "$PKG_ROOT/usr/bin/maknae"
install -D -m 0755 "$BINDIR/maknae-egress" "$PKG_ROOT/usr/bin/maknae-egress"
# Strip debug symbols (lintian: unstripped-binary-or-object) — best-effort.
strip --strip-unneeded "$PKG_ROOT/usr/bin/maknaed" "$PKG_ROOT/usr/bin/maknae" \
    "$PKG_ROOT/usr/bin/maknae-egress" 2>/dev/null || true

# --- systemd unit ---------------------------------------------------------------
install -D -m 0644 "$COMMON/maknaed.service" \
    "$PKG_ROOT/usr/lib/systemd/system/maknaed.service"
# #240a: the deputy's unit AND its socket. The socket unit is what lets the
# init system own the socket, so the deputy needs no chgrp and no CAP_CHOWN.
install -D -m 0644 "$COMMON/maknae-egress.service" \
    "$PKG_ROOT/usr/lib/systemd/system/maknae-egress.service"
install -D -m 0644 "$COMMON/maknae-egress.socket" \
    "$PKG_ROOT/usr/lib/systemd/system/maknae-egress.socket"

# --- sysusers.d -----------------------------------------------------------------
install -D -m 0644 "$COMMON/maknae.sysusers" \
    "$PKG_ROOT/usr/lib/sysusers.d/maknae.conf"

# --- AppArmor profile -----------------------------------------------------------
install -D -m 0644 "$HERE/apparmor/usr.bin.maknaed" \
    "$PKG_ROOT/etc/apparmor.d/usr.bin.maknaed"

# --- Vault-port label helper (layout parity; SELinux-only no-op on Debian) ------
install -D -m 0750 "$COMMON/maknae-selinux-ports.sh" \
    "$PKG_ROOT/usr/libexec/maknae/maknae-selinux-ports.sh"

# --- Shipped config defaults (conffiles) ----------------------------------------
# Payload mode 0640; final ownership (root:_maknae) is set in postinst since
# dpkg-deb --root-owner-group records root:root.
install -D -m 0640 "$COMMON/authz.yaml"  "$PKG_ROOT/etc/maknae/authz.yaml"
install -D -m 0640 "$COMMON/maknae.yaml" "$PKG_ROOT/etc/maknae/maknae.yaml"

# NOTE: /var/log/maknae/audit.jsonl is NOT a payload file — it is created
# first-install-only (and guarded on non-existence) in postinst, then chattr +a.
# Shipping it as payload would collide with the append-only inode on upgrade.

# --- Debian Policy 12.5: copyright ----------------------------------------------
install -D -m 0644 "$HERE/copyright" \
    "$PKG_ROOT/usr/share/doc/maknae/copyright"

# --- Debian Policy 4.4: changelog (non-native → changelog.Debian.gz) -------------
install -d "$PKG_ROOT/usr/share/doc/maknae"
cat > "$PKG_ROOT/usr/share/doc/maknae/changelog.Debian" <<CHLOG
maknae (${VERSION}-1) stable; urgency=medium

  * Tokki PR-T1 initial packaging: maknaed/maknae, hardened systemd unit
    (TPM2 LoadCredentialEncrypted), AppArmor profile, two-group sysusers,
    shipped authz.yaml DAC default + maknae.yaml skeleton.

 -- Alex Ackerman <developer@maknae.io>  Mon, 17 Aug 2026 00:00:00 +0000
CHLOG
gzip -9n "$PKG_ROOT/usr/share/doc/maknae/changelog.Debian"

# --- Build the .deb -------------------------------------------------------------
mkdir -p "$DIST"
OUT="$DIST/maknae_${DEBVER}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$PKG_ROOT" "$OUT"

echo "Built: $OUT"
