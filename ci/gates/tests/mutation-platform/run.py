#!/usr/bin/env python3
"""Native filters checked against cargo-mutants' actual source inventory."""
import importlib.util
from pathlib import Path
import re
import subprocess
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "ci/gates/mutation-platform.sh"
_spec = importlib.util.spec_from_file_location("platform_gated", ROOT / "ci/gates/platform-gated.py")
platform_gated = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(platform_gated)
DERIVED = platform_gated.derive(ROOT)
FILTERED = sorted(platform_gated.filtered(ROOT))
CRATE_INVENTORY = {
    crate: subprocess.check_output(["cargo", "mutants", "--no-config", "-p", crate, "--list"],
                                   cwd=ROOT, text=True).splitlines()
    for crate in FILTERED
}
assert all(CRATE_INVENTORY.values()), "empty mutation inventory is not assurance"
NO_MUTANTS = frozenset()
INVENTORY = subprocess.check_output([
    "cargo", "mutants", "--no-config", "-p", "maknae-io", "--file",
    "crates/maknae-io/src/syscall.rs", "--list",
], cwd=ROOT, text=True).splitlines()
assert INVENTORY, "empty mutation inventory is not assurance"
SYS_INVENTORY = subprocess.check_output([
    "cargo", "mutants", "--no-config", "-p", "maknae-sys", "--list",
], cwd=ROOT, text=True).splitlines()
assert SYS_INVENTORY, "empty maknae-sys mutation inventory is not assurance"


class PlatformSelection(unittest.TestCase):
    def exclusion(self, system):
        return subprocess.check_output(["bash", str(SCRIPT), system], text=True).strip()

    def attributed(self, item):
        lines = CRATE_INVENTORY[item.crate]
        if item.kind == "mod-file":
            return [m for m in lines if m.startswith(item.file + ":")]
        name = re.escape(item.name)
        shape = re.compile(rf": replace ({name} ->|{name} with |<impl .*>::{name} )|.* in {name}$")
        return [m for m in lines if m.startswith(item.file + ":") and shape.search(m)]

    def test_every_derived_item_is_excluded_exactly_where_inactive(self):
        regex = {p: self.exclusion(u) for p, u in platform_gated.UNAME.items()}
        covered, empty = set(), []
        self.assertTrue(DERIVED)
        for item in DERIVED:
            lines = self.attributed(item)
            if not lines:
                empty.append(f"{item.file} {item.kind} {item.name}")
            covered.update(lines)
            for platform, pattern in regex.items():
                for mutant in lines:
                    if platform in item.active:
                        self.assertNotRegex(mutant, pattern, f"active on {platform}")
                    else:
                        self.assertRegex(mutant, pattern, f"inactive on {platform}")
        self.assertEqual(sorted(empty), sorted(NO_MUTANTS), "a derived item without mutants must be reviewed into NO_MUTANTS")
        for crate, lines in CRATE_INVENTORY.items():
            for mutant in set(lines) - covered:
                for pattern in regex.values():
                    self.assertNotRegex(mutant, pattern, "excluded but not derived as platform-gated")

    def test_nearby_names_and_files_are_not_excluded(self):
        names = "|".join(sorted({g.name for g in DERIVED if g.kind == "fn"}, key=len, reverse=True))
        for system in ("Linux", "Darwin"):
            regex = self.exclusion(system)
            excluded = [m for m in INVENTORY if re.search(regex, m)]
            self.assertTrue(excluded)
            for mutant in excluded:
                self.assertIsNone(re.search(regex, mutant.replace("syscall.rs:", "other.rs:")))
                altered = re.sub(rf"\b({names})( ->| with |$)", r"\1_extra\2", mutant)
                self.assertNotEqual(altered, mutant)
                self.assertIsNone(re.search(regex, altered))

    def test_match_guard_naming_an_inactive_fn_is_not_excluded(self):
        for system, name in (("Linux", "macos_fd_path"), ("Darwin", "linux_fd_path")):
            near = f"crates/maknae-io/src/syscall.rs:1:1: replace match guard a == {name} with true in open_read_target"
            self.assertNotRegex(near, self.exclusion(system))

    def test_maknae_sys_platform_file_is_excluded_only_where_inactive(self):
        linux, darwin = self.exclusion("Linux"), self.exclusion("Darwin")
        macos_file = [m for m in SYS_INVENTORY if m.startswith("crates/maknae-sys/src/macos.rs:")]
        portable = [m for m in SYS_INVENTORY if m.startswith("crates/maknae-sys/src/reply.rs:")]
        self.assertTrue(macos_file)
        self.assertTrue(portable)
        self.assertEqual(len(macos_file) + len(portable), len(SYS_INVENTORY))
        for mutant in macos_file:
            self.assertRegex(mutant, linux)
            self.assertNotRegex(mutant, darwin)
            self.assertNotRegex(mutant.replace("src/macos.rs:", "src/other.rs:"), linux)
        for mutant in portable:
            self.assertNotRegex(mutant, linux)
            self.assertNotRegex(mutant, darwin)

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
                    "open_existing", "linux_path_delegation_flags", "macos_path_delegation_flags"}
        equivalent = {m for m in xor_mutants if m.rsplit(" in ", 1)[1] in reviewed}
        self.assertEqual(len(equivalent), 32, "review the disjoint-union inventory when it changes")
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


if __name__ == "__main__":
    unittest.main()
