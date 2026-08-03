# RPM packaging (stub)
Tool: `cargo-generate-rpm`, consuming single-package auditable artifacts (spec §3).
Contents (spec §6): bins, systemd units (incl. CLI user unit), sysusers.d `_maknae`,
default YAMLs, install-time `chattr +a` on the audit dir, SELinux module (stub → grows).
Not yet implemented — this deliverable is scaffold structure only.
