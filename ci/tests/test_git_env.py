"""Every ci/ script that runs git clears the variables that redirect the repository or change pathspecs."""
from pathlib import Path
import re
import unittest

CI = Path(__file__).resolve().parents[1]
CLEARED = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR",
           "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_LITERAL_PATHSPECS", "GIT_NOGLOB_PATHSPECS",
           "GIT_GLOB_PATHSPECS", "GIT_ICASE_PATHSPECS")
SHELL_GIT = re.compile(r"""(?:^|[\s($`|;&])git\s+(?:-C|-c|rev-parse|ls-files|diff|show|status|"""
                       r"""merge-base|log|cat-file|ls-tree|for-each-ref)\b""")
ARGV_GIT = re.compile(r"""\[\s*["']git["']""")


def runs_git(text):
    code = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    return any(SHELL_GIT.search(line) or ARGV_GIT.search(line) for line in code)


def scripts():
    for path in sorted(CI.rglob("*")):
        rel = path.relative_to(CI).as_posix()
        if not path.is_file() or rel.startswith(("tests/", "gates/tests/")):
            continue
        if rel == "gates/negative-control.sh" or path.suffix not in (".sh", ".py", ""):
            continue
        yield rel, path.read_text(errors="replace")


class GitEnv(unittest.TestCase):
    def test_the_scan_finds_the_known_git_callers(self):
        found = {rel for rel, text in scripts() if runs_git(text)}
        for rel in ("affected.py", "hooks/pre-push", "gates/coverage-tiers.sh",
                    "gates/mutation-diff.py", "gates/std-fs-drift.sh", "gates/unsafe-confinement.sh"):
            self.assertIn(rel, found)

    def test_every_git_caller_clears_the_whole_set(self):
        for rel, text in scripts():
            if not runs_git(text):
                continue
            with self.subTest(rel):
                self.assertEqual([v for v in CLEARED if not re.search(rf"\b{v}\b", text)], [])


if __name__ == "__main__":
    unittest.main()
