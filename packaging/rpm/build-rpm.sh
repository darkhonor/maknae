#!/bin/bash
# Build the maknae rpm from pre-built binaries + packaging/ assets.
# CI-ready: non-interactive, hermetic, deterministic. Runs on the TARGET OS
# (the SELinux .pp is compiled against the host's refpolicy version).
#
#   build-rpm.sh <version> [<bindir>]
#     <version>  e.g. 0.1.0  (required — becomes %{_pkgversion})
#     <bindir>   dir holding the pre-built `maknaed`, `maknae` and `maknae-egress` (default: ./target/release)
#
# Output: dist/maknae-<version>-1.<dist>.x86_64.rpm
set -euo pipefail

VERSION="${1:?usage: build-rpm.sh <version> [<bindir>]}"
BINDIR="${2:-target/release}"

# Validate VERSION before it reaches an rpm --define: rpm macro constructs like
# %() would turn a crafted CI tag into build-host command execution. Accept only
# a strict version grammar (digits, dots, and a limited safe set) — no `%`,
# whitespace, or control chars.
if ! printf '%s' "$VERSION" | grep -qE '^[0-9][0-9A-Za-z.~+_-]*$'; then
    echo "ERROR: invalid version '$VERSION' (allowed: ^[0-9][0-9A-Za-z.~+_-]*\$)" >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"          # packaging/rpm
REPO="$(cd "$HERE/../.." && pwd)"              # repo root
COMMON="$REPO/packaging/common"
DIST="$REPO/dist"

for b in maknaed maknae maknae-egress; do
    [ -x "$BINDIR/$b" ] || { echo "ERROR: missing binary $BINDIR/$b" >&2; exit 1; }
done

TOP="$(mktemp -d)"
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{SOURCES,SPECS,BUILD,RPMS,SRPMS}

# Stage numbered sources (must match Source0..N in the spec).
install -m 0755 "$BINDIR/maknaed"                 "$TOP/SOURCES/maknaed"
install -m 0755 "$BINDIR/maknae"                  "$TOP/SOURCES/maknae"
install -m 0644 "$COMMON/maknaed.service"         "$TOP/SOURCES/"
install -m 0644 "$COMMON/maknae.sysusers"         "$TOP/SOURCES/"
install -m 0644 "$COMMON/maknae.te"               "$TOP/SOURCES/"
install -m 0644 "$COMMON/maknae.fc"               "$TOP/SOURCES/"
install -m 0644 "$COMMON/maknae.fapolicyd.trust"  "$TOP/SOURCES/"
install -m 0755 "$COMMON/maknae-selinux-ports.sh" "$TOP/SOURCES/"
install -m 0644 "$COMMON/authz.yaml"              "$TOP/SOURCES/"
install -m 0644 "$COMMON/maknae.yaml"             "$TOP/SOURCES/"
# #240a — Source10..12. Staging must match Source0..N in the spec exactly, or
# rpmbuild fails on a missing source rather than silently shipping without it.
install -m 0755 "$BINDIR/maknae-egress"           "$TOP/SOURCES/maknae-egress"
install -m 0644 "$COMMON/maknae-egress.service"   "$TOP/SOURCES/"
install -m 0644 "$COMMON/maknae-egress.socket"    "$TOP/SOURCES/"

cp "$HERE/maknae.spec" "$TOP/SPECS/maknae.spec"

rpmbuild --define "_topdir $TOP" \
         --define "_pkgversion $VERSION" \
         --target x86_64 \
         -bb "$TOP/SPECS/maknae.spec"

mkdir -p "$DIST"
find "$TOP/RPMS" -name '*.rpm' -exec cp -v {} "$DIST/" \;
echo "OK: rpm(s) in $DIST/"
