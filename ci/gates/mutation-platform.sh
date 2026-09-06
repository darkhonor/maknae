#!/usr/bin/env bash
# cargo-mutants discovers cfg-inactive functions too. Names are deliberately
# distinct in syscall.rs so this cannot exclude the active platform's twin.
# The gate calls this without an override; the argument is for fixture tests.
set -euo pipefail
case "${1:-$(uname -s)}" in
  Linux) absent='macos_fd_path|unsupported_fd_path|portable_probe_openat2';;
  Darwin) absent='linux_fd_path|linux_probe_openat2|openat2_resolve|unsupported_fd_path';;
  *) echo 'FAIL: unsupported native mutation host' >&2; exit 1;;
esac
printf '^crates/maknae-io/src/syscall\.rs:[0-9]+:[0-9]+: .* (%s)( ->|$)\n' "$absent"
