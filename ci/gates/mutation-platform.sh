#!/usr/bin/env bash
# cargo-mutants discovers cfg-inactive functions too. Names are deliberately
# distinct in syscall.rs so this cannot exclude the active platform's twin.
# The gate calls this without an override; the argument is for fixture tests.
set -euo pipefail
case "${1:-$(uname -s)}" in
  Linux) absent='macos_mutation_directory_flags|macos_fd_path|unsupported_fd_path|portable_probe_openat2|macos_path_delegation_flags|macos_reopen_writable|macos_confers_no_write|macos_reopen_readable|macos_dir_kernel_form|macos_full_path_error'
         inactive_files='|^crates/maknae-sys/src/macos\.rs:'
         root_only='';;
  Darwin) absent='linux_mutation_directory_flags|linux_fd_path|linux_probe_openat2|openat2_resolve|unsupported_fd_path|linux_path_delegation_flags|linux_reopen_writable|linux_confers_no_write|linux_reopen_readable|linux_dir_kernel_form'
          inactive_files='|^crates/maknae-sys/src/linux\.rs:'
          # Only a file root flagged sappnd yields true; the compensating control is the
          # root-only agrees_with_stat_on_a_file_flagged_sappnd. Linux mutates this function.
          root_only='|^crates/maknae-sys/src/flags\.rs:[0-9]+:[0-9]+: replace is_append_only -> io::Result<bool> with Ok\(false\)$';;
  *) echo 'FAIL: unsupported native mutation host' >&2; exit 1;;
esac
printf '^crates/maknae-io/src/syscall\.rs:[0-9]+:[0-9]+: (replace (%s)( ->| with )|.* in (%s)$)%s%s\n' "$absent" "$absent" "$inactive_files" "$root_only"
