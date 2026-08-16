#!/bin/bash
# Build the maknae rpm from pre-built binaries + packaging/ assets.
# CI-ready: non-interactive, hermetic, deterministic. Runs on the TARGET OS
# (the SELinux .pp is compiled against the host's refpolicy version).
#
#   build-rpm.sh <version> [<bindir>]
#     <version>  e.g. 0.1.0  (required — becomes %{_pkgversion})
#     <bindir>   dir holding the pre-built `maknaed` + `maknae` (default: ./target/release)
#
# Output: dist/maknae-<version>-1.<dist>.x86_64.rpm
set -euo pipefail

VERSION="${1:?usage: build-rpm.sh <version> [<bindir>]}"
BINDIR="${2:-target/release}"

HERE="$(cd "$(dirname "$0")" && pwd)"          # packaging/rpm
REPO="$(cd "$HERE/../.." && pwd)"              # repo root
COMMON="$REPO/packaging/common"
DIST="$REPO/dist"

for b in maknaed maknae; do
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

cp "$HERE/maknae.spec" "$TOP/SPECS/maknae.spec"

rpmbuild --define "_topdir $TOP" \
         --define "_pkgversion $VERSION" \
         --target x86_64 \
         -bb "$TOP/SPECS/maknae.spec"

mkdir -p "$DIST"
find "$TOP/RPMS" -name '*.rpm' -exec cp -v {} "$DIST/" \;
echo "OK: rpm(s) in $DIST/"
