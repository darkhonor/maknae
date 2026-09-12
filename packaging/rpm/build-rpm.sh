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

# The binaries this package SHIPS, from the shared manifest — NOT derived from
# `cargo metadata`. The workspace builds maknae-spifc and this package does not
# ship it, so a metadata-derived set selects a binary that never lands in the
# payload (reviewed finding, #293). The helper validates in the other
# direction: every named binary must be a real bin target.
. "$REPO/ci/gates/packaged-binaries.sh"
BINS="$(packaged_binaries "$REPO")"
for b in $BINS; do
    [ -x "$BINDIR/$b" ] || { echo "ERROR: missing binary $BINDIR/$b" >&2; exit 1; }
done

TOP="$(mktemp -d)"
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{SOURCES,SPECS,BUILD,RPMS,SRPMS}

# Stage numbered sources (must match Source0..N in the spec).
# ONE list drives the existence check above AND the staging here.
for b in $BINS; do
    install -m 0755 "$BINDIR/$b" "$TOP/SOURCES/$b"
done
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
install -m 0644 "$COMMON/maknae-egress.service"   "$TOP/SOURCES/"
install -m 0644 "$COMMON/maknae-egress.socket"    "$TOP/SOURCES/"

# --- Spec %files vs manifest: what the rpm SHIPS is what was declared --------
# The rpm's equivalent of the deb payload check. rpmbuild builds the payload
# from the spec, so the spec's %{_bindir} entries ARE the shipped set. Compared
# as SETS: a binary staged but not shipped, or shipped but not declared, fails.
spec_bins="$(grep -oE '^%\{_bindir\}/\S+' "$HERE/maknae.spec" | sed 's|^%{_bindir}/||' | sort)"
want_bins="$(printf '%s\n' $BINS | sort)"
[ "$spec_bins" = "$want_bins" ] || {
    echo "ERROR: maknae.spec %files does not match the packaged-binaries manifest" >&2
    echo "  manifest: $(echo $want_bins)" >&2
    echo "  spec:     $(echo $spec_bins)" >&2
    exit 1
}
echo "spec check: $(echo $spec_bins | wc -w) binary/binaries match the manifest"

# --- Declaration vs staging: every Source in the spec MUST be staged --------
# The rpm's equivalent of the deb payload check, and derived from the spec for
# the same reason: a hand cross-reference is what let the egress AppArmor
# profile be DECLARED and never shipped on the deb side. rpmbuild fails on a
# missing source, but it fails late and opaquely; this names the file.
#
# Fail closed on zero: a spec we cannot read declares nothing, and nothing
# checked must never read as success.
declared="$(grep -oE '^Source[0-9]+:[[:space:]]+\S+' "$HERE/maknae.spec" | awk '{print $2}')"
[ -n "$declared" ] || { echo "ERROR: no Source declarations found in maknae.spec" >&2; exit 1; }
n=0
for src in $declared; do
    [ -f "$TOP/SOURCES/$src" ] || {
        echo "ERROR: Source '$src' is declared in maknae.spec but not staged" >&2
        exit 1
    }
    n=$((n + 1))
done
echo "source check: $n declared source(s) staged"

cp "$HERE/maknae.spec" "$TOP/SPECS/maknae.spec"

rpmbuild --define "_topdir $TOP" \
         --define "_pkgversion $VERSION" \
         --target x86_64 \
         -bb "$TOP/SPECS/maknae.spec"

mkdir -p "$DIST"
find "$TOP/RPMS" -name '*.rpm' -exec cp -v {} "$DIST/" \;
echo "OK: rpm(s) in $DIST/"
