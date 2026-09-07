#!/usr/bin/env python3
"""Native filters checked against cargo-mutants' actual source inventory."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "ci/gates/mutation-platform.sh"
INVENTORY = subprocess.check_output([
    "cargo", "mutants", "--no-config", "-p", "maknae-io", "--file",
    "crates/maknae-io/src/syscall.rs", "--list",
], cwd=ROOT, text=True).splitlines()
assert INVENTORY, "empty mutation inventory is not assurance"


class PlatformSelection(unittest.TestCase):
    def exclusion(self, system):
        return subprocess.check_output(["bash", str(SCRIPT), system], text=True).strip()

    def selected(self, system):
        regex = self.exclusion(system)
        return "\n".join(m for m in INVENTORY if not re.search(regex, m))

    def test_linux(self):
        selected = self.selected("Linux")
        for active in ("linux_fd_path", "linux_probe_openat2", "openat2_resolve", "linux_mutation_directory_flags"):
            self.assertIn(active, selected)
        for absent in ("macos_fd_path", "portable_probe_openat2", "unsupported_fd_path", "macos_mutation_directory_flags"):
            self.assertNotIn(absent, selected)
        self.assertIn(" in open_read_target", selected)

    def test_macos(self):
        selected = self.selected("Darwin")
        for active in ("macos_fd_path", "portable_probe_openat2", "macos_mutation_directory_flags"):
            self.assertIn(active, selected)
        for absent in ("linux_fd_path", "linux_probe_openat2", "openat2_resolve",
                       "unsupported_fd_path", "linux_mutation_directory_flags"):
            self.assertNotIn(absent, selected)
        self.assertIn(" in open_read_target", selected)

    def test_nearby_names_and_files_are_not_excluded(self):
        for system in ("Linux", "Darwin"):
            regex = self.exclusion(system)
            excluded = [m for m in INVENTORY if re.search(regex, m)]
            self.assertTrue(excluded)
            for mutant in excluded:
                self.assertIsNone(re.search(regex, mutant.replace("syscall.rs:", "other.rs:")))
                # A similarly named future function is not covered by this rule.
                altered = re.sub(r"(fd_path|probe_openat2|openat2_resolve|mutation_directory_flags)( ->|$)",
                                 r"\1_extra\2", mutant)
                self.assertNotEqual(altered, mutant)
                self.assertIsNone(re.search(regex, altered))

    def test_unknown_fails(self):
        result = subprocess.run(["bash", str(SCRIPT), "Plan9"], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported native mutation host", result.stderr)

    def test_config_excludes_only_the_equivalent_syscall_family(self):
        configured = subprocess.check_output([
            "cargo", "mutants", "-p", "maknae-io", "--file",
            "crates/maknae-io/src/syscall.rs", "--list",
        ], cwd=ROOT, text=True).splitlines()
        xor_mutants = {m for m in INVENTORY if "replace | with ^ in " in m}
        reviewed = {"open_parent_by_path", "open_dir_at", "open_read_target",
                    "openat2_resolve", "open_temp_excl", "open_append",
                    "macos_mutation_directory_flags", "linux_mutation_directory_flags", "open_mutation_directory_at",
                    "open_writable_delegation"}
        equivalent = {m for m in xor_mutants if m.rsplit(" in ", 1)[1] in reviewed}
        self.assertEqual(len(equivalent), 28, "review the disjoint-union inventory when it changes")
        # Both production platforms have native evidence plus executable bit proofs.
        self.assertEqual(xor_mutants - equivalent, set())
        self.assertEqual(set(configured), set(INVENTORY) - equivalent)
        patterns = tomllib.loads((ROOT / ".cargo/mutants.toml").read_text())["exclude_re"]
        # A new function or another file has no equivalence review yet.
        for mutant in equivalent:
            for nearby in (mutant.replace("syscall.rs:", "other.rs:"),
                           mutant.rsplit(" in ", 1)[0] + " in future_open"):
                self.assertFalse(any(re.search(pattern, nearby) for pattern in patterns))

    def test_audit_equivalence_excludes_only_the_six_reviewed_xors(self):
        args = ["cargo", "mutants", "-p", "maknae-io", "--file",
                "crates/maknae-io/src/audit_append.rs", "--list"]
        inventory = subprocess.check_output(args + ["--no-config"], cwd=ROOT, text=True).splitlines()
        configured = subprocess.check_output(args, cwd=ROOT, text=True).splitlines()
        equivalent = {m for m in inventory if "replace | with ^ in flags" in m}
        self.assertEqual(len(equivalent), 6)
        self.assertEqual(set(configured), set(inventory) - equivalent)
        patterns = tomllib.loads((ROOT / ".cargo/mutants.toml").read_text())["exclude_re"]
        for mutant in equivalent:
            for nearby in (mutant.replace("audit_append.rs:", "other.rs:"),
                           mutant.rsplit(" in ", 1)[0] + " in future_flags"):
                self.assertFalse(any(re.search(pattern, nearby) for pattern in patterns))

    def test_gate_passes_native_filter_as_one_argument(self):
        # The real gate, with its documented injection fixture interface. This
        # proves CLI wiring, independently of what the filter script prints.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            (root / "coverage-tiers.toml").write_text(
                '[t1]\nmutants_crates = ["maknae-io"]\n'
            )
            recorder = tools / "cargo"
            recorder.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$MUTATION_ARGS"\n')
            recorder.chmod(0o755)
            (tools / "cargo-mutants").symlink_to(recorder)
            arguments = root / "args"
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"],
                       MUTATION_ARGS=str(arguments), COVERAGE_TIERS_JSON=str(root / "unused"),
                       COVERAGE_TIERS_FILELIST=str(root / "unused"),
                       COVERAGE_TIERS_CRATE_DIRS="maknae-io=crates/maknae-io")
            result = subprocess.run([
                "bash", str(ROOT / "ci/gates/coverage-tiers.sh"), "--root", str(root),
                "--injection", "--mutants", "maknae-io",
            ], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            expected = subprocess.check_output(["bash", str(SCRIPT)], text=True).strip()
            self.assertEqual(arguments.read_text().splitlines(),
                             ["mutants", "--package", "maknae-io", "--exclude-re", expected,
                              "--minimum-test-timeout", "60"])


if __name__ == "__main__":
    unittest.main()
