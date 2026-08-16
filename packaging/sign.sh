#!/bin/bash
# packaging/sign.sh — checksum + (optional) GPG signing of the built artifacts.
#
# Jackrabbit §9.9: the published Microkosmos GPG key signs everything —
#   * RPM embedded signature (`rpmsign --addsign`, verified with `rpm -K`)
#   * detached ASCII-armored `.asc` per `.deb`
#   * a signed `SHA256SUMS` manifest (`SHA256SUMS.asc`)
# Artifacts land in a versioned `dist/`; the install guide carries the
# verification commands this script prints.
#
# Parameterized so unattended (CI) builds never block on a key:
#   * default (no `--sign`)   -> emit `dist/SHA256SUMS` only, print UNSIGNED.
#   * `--sign` (+ $GPG_KEY_ID) -> embed-sign rpms, detach-sign debs, sign the
#                                 manifest. Fully non-interactive (batch +
#                                 loopback pinentry) — never prompts.
#
# Usage:
#   packaging/sign.sh              # UNSIGNED: SHA256SUMS only (default)
#   packaging/sign.sh --no-sign    # explicit unsigned (same as default)
#   GPG_KEY_ID=<keyid> packaging/sign.sh --sign
#
# Env:
#   GPG_KEY_ID   required with --sign; the signing key (fingerprint / uid / email).
#   DIST_DIR     override the artifact directory (default: <repo>/dist).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST="${DIST_DIR:-${REPO_ROOT}/dist}"

SIGN=0
for arg in "$@"; do
  case "$arg" in
    --sign)    SIGN=1 ;;
    --no-sign) SIGN=0 ;;
    -h|--help)
      grep '^#' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "sign.sh: unknown argument: $arg" >&2; exit 2 ;;
  esac
done

[ -d "$DIST" ] || { echo "sign.sh: dist dir not found: $DIST (build artifacts first)" >&2; exit 1; }

# Portable sha256: coreutils `sha256sum` on Linux build hosts, `shasum -a 256`
# as a fallback (e.g. a dev Mac running the unsigned path).
if command -v sha256sum >/dev/null 2>&1; then
  SHA_GEN() { sha256sum "$@"; }
  SHA_VERIFY_CMD="sha256sum -c SHA256SUMS"
else
  SHA_GEN() { shasum -a 256 "$@"; }
  SHA_VERIFY_CMD="shasum -a 256 -c SHA256SUMS"
fi

cd "$DIST"

# Collect the artifacts (rpm + deb). Exclude any prior manifest / signatures.
shopt -s nullglob
artifacts=()
for f in *.rpm *.deb; do
  artifacts+=("$f")
done
shopt -u nullglob

[ "${#artifacts[@]}" -gt 0 ] || { echo "sign.sh: no *.rpm / *.deb artifacts in $DIST" >&2; exit 1; }

# --- SHA256SUMS manifest (both paths) ------------------------------------------
SHA_GEN "${artifacts[@]}" > SHA256SUMS
echo "sign.sh: wrote $DIST/SHA256SUMS (${#artifacts[@]} artifact(s))"

if [ "$SIGN" -eq 0 ]; then
  echo "sign.sh: UNSIGNED (SHA256SUMS only)"
  echo
  echo "Operator verification (unsigned build):"
  echo "  cd $DIST && ${SHA_VERIFY_CMD}"
  exit 0
fi

# --- Signed path ---------------------------------------------------------------
: "${GPG_KEY_ID:?--sign requires GPG_KEY_ID (the Microkosmos signing key)}"
command -v gpg     >/dev/null 2>&1 || { echo "sign.sh: gpg not found" >&2; exit 1; }
command -v rpmsign >/dev/null 2>&1 || echo "sign.sh: WARNING rpmsign not found — skipping rpm embed-signing" >&2

# RPM: embedded signature. rpmsign reads the key from the `_gpg_name` macro; we
# pass it explicitly so the key need not be baked into ~/.rpmmacros. Loopback
# pinentry keeps it non-interactive.
shopt -s nullglob
rpms=(*.rpm)
shopt -u nullglob
if [ "${#rpms[@]}" -gt 0 ] && command -v rpmsign >/dev/null 2>&1; then
  rpmsign \
    --define "_gpg_name ${GPG_KEY_ID}" \
    --define "_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback" \
    --addsign "${rpms[@]}"
  echo "sign.sh: embed-signed ${#rpms[@]} rpm(s)"
fi

# DEB: detached ASCII-armored signature per package (dpkg has no embedded sig).
shopt -s nullglob
debs=(*.deb)
shopt -u nullglob
for deb in "${debs[@]}"; do
  rm -f "${deb}.asc"
  gpg --batch --yes --pinentry-mode loopback \
      --local-user "${GPG_KEY_ID}" \
      --detach-sign --armor --output "${deb}.asc" "${deb}"
  echo "sign.sh: detach-signed ${deb} -> ${deb}.asc"
done

# Manifest: signed detached `.asc` over SHA256SUMS.
rm -f SHA256SUMS.asc
gpg --batch --yes --pinentry-mode loopback \
    --local-user "${GPG_KEY_ID}" \
    --detach-sign --armor --output SHA256SUMS.asc SHA256SUMS
echo "sign.sh: signed SHA256SUMS -> SHA256SUMS.asc"

echo
echo "sign.sh: SIGNED with key ${GPG_KEY_ID}"
echo
echo "Operator verification (signed build):"
echo "  # 1. RPM embedded signature (import the public key into the rpm keyring first):"
echo "  rpm --import <maknae-public-key.asc>"
for r in "${rpms[@]:-}"; do [ -n "$r" ] && echo "  rpm -Kv $r      # expect: 'digests signatures OK'"; done
echo "  # 2. DEB detached signature:"
for d in "${debs[@]:-}"; do [ -n "$d" ] && echo "  gpg --verify ${d}.asc ${d}"; done
echo "  # 3. Manifest signature + checksums:"
echo "  gpg --verify SHA256SUMS.asc SHA256SUMS"
echo "  ${SHA_VERIFY_CMD}"
