"""Every ci/ script that runs git clears the variables that redirect the repository or change
pathspecs, and disables replacement objects, in code that takes effect."""
import ast
from pathlib import Path
import re
import unittest

CI = Path(__file__).resolve().parents[1]
CLEARED = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR",
           "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_LITERAL_PATHSPECS", "GIT_NOGLOB_PATHSPECS",
           "GIT_GLOB_PATHSPECS", "GIT_ICASE_PATHSPECS", "GIT_GRAFT_FILE")
NO_REPLACE = "GIT_NO_REPLACE_OBJECTS=1"
SHELL_GIT = re.compile(r"""(?:^|[\s($`|;&])git\s+(?:-C|-c|rev-parse|ls-files|diff|show|status|"""
                       r"""merge-base|log|cat-file|ls-tree|for-each-ref)\b""")
ARGV_GIT = re.compile(r"""\[\s*["']git["']""")
ENV_ARRAY = re.compile(r"""\benv(?:\s+-u\s+\w+)*\s+"\$\{(\w+)\[@\]\}"\s+git\b""")


def runs_git(text):
    code = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    return any(SHELL_GIT.search(line) or ARGV_GIT.search(line) for line in code)


def shell_statements(text):
    lines = [re.sub(r"(^|\s)#.*$", "", line) for line in text.splitlines()
             if not line.lstrip().startswith("#")]
    statements, current = [], ""
    for line in lines:
        if line.endswith("\\"):
            current += line[:-1] + " "
            continue
        statements.append(current + line)
        current = ""
    if current:
        statements.append(current)
    return statements


def clears(words):
    unset = {w for w in words if not w.startswith("-")}
    flagged = {words[i + 1] for i, w in enumerate(words[:-1]) if w == "-u"}
    return set(CLEARED) <= (unset | flagged)


def shell_violations(text):
    statements = shell_statements(text)
    arrays = {m.group(1): m.group(2).split()
              for m in re.finditer(r"(?m)^(\w+)=\(([^)]*)\)", "\n".join(statements))}
    safe_arrays = {name for name, words in arrays.items() if clears(words) and NO_REPLACE in words}
    unset_at = export_at = None
    problems = []
    for index, statement in enumerate(statements):
        words = statement.split()
        if unset_at is None and statement.startswith("unset ") and clears(words[1:]):
            unset_at = index
        if export_at is None and statement.startswith("export ") and NO_REPLACE in words[1:]:
            export_at = index
        if not SHELL_GIT.search(statement):
            continue
        if any(name in safe_arrays for name in ENV_ARRAY.findall(statement)):
            continue
        if unset_at is None or export_at is None:
            problems.append(statement.strip())
    return problems


def python_violations(text):
    tree = ast.parse(text)
    problems = []
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Tuple):
            names[node.targets[0].id] = {e.value for e in node.value.elts
                                         if isinstance(e, ast.Constant)}
    helper = next((n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == "git_env"), None)
    if helper is None:
        problems.append("no git_env()")
    else:
        body = ast.get_source_segment(text, helper) or ""
        excluded = re.findall(r"not in (\w+)", body)
        if not excluded or not set(CLEARED) <= names.get(excluded[0], set()):
            problems.append("git_env() does not drop every cleared variable")
        if not re.search(r"""\[["']GIT_NO_REPLACE_OBJECTS["']\]\s*=\s*["']1["']""", body):
            problems.append("git_env() does not set GIT_NO_REPLACE_OBJECTS=1")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args or not isinstance(node.args[0], ast.List):
            continue
        first = node.args[0].elts[:1]
        if not (first and isinstance(first[0], ast.Constant) and first[0].value == "git"):
            continue
        env = next((k.value for k in node.keywords if k.arg == "env"), None)
        if not (isinstance(env, ast.Call) and isinstance(env.func, ast.Name)
                and env.func.id == "git_env"):
            problems.append(f"line {node.lineno}: git call without env=git_env()")
    return problems


def violations(rel, text):
    return python_violations(text) if rel.endswith(".py") else shell_violations(text)


def scripts():
    for path in sorted(CI.rglob("*")):
        rel = path.relative_to(CI).as_posix()
        if not path.is_file() or rel.startswith(("tests/", "gates/tests/")):
            continue
        if rel == "gates/negative-control.sh" or path.suffix not in (".sh", ".py", ""):
            continue
        yield rel, path.read_text(errors="replace")


GOOD_SHELL = ("#!/usr/bin/env bash\nunset " + " ".join(CLEARED[:5]) + " \\\n  "
              + " ".join(CLEARED[5:]) + "\nexport GIT_NO_REPLACE_OBJECTS=1\ngit status\n")
GOOD_PYTHON = (f"GIT_ENV = {CLEARED!r}\n"
               "def git_env():\n"
               "    env = {k: v for k, v in os.environ.items() if k not in GIT_ENV}\n"
               "    env['GIT_NO_REPLACE_OBJECTS'] = '1'\n"
               "    return env\n"
               "subprocess.run(['git', 'status'], env=git_env())\n")


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
                self.assertEqual(violations(rel, text), [])

    def test_the_guard_accepts_effective_clearing(self):
        self.assertEqual(shell_violations(GOOD_SHELL), [])
        self.assertEqual(python_violations(GOOD_PYTHON), [])
        array = ("in_env=(" + " ".join(f"-u {v}" for v in CLEARED) + "\n  " + NO_REPLACE + ")\n"
                 "f() { env \"${in_env[@]}\" git status; }\n")
        self.assertEqual(shell_violations(array), [])

    def test_the_guard_refuses_a_comment_only_script(self):
        text = "#!/usr/bin/env bash\ngit status\n# " + " ".join(CLEARED) + " " + NO_REPLACE + "\n"
        self.assertTrue(runs_git(text))
        self.assertEqual(shell_violations(text), ["git status"])

    def test_the_guard_refuses_ineffective_shell(self):
        cases = {
            "inline comment": "git status # unset " + " ".join(CLEARED) + "\n",
            "clear after git": "git status\n" + GOOD_SHELL,
            "no export": GOOD_SHELL.replace("export GIT_NO_REPLACE_OBJECTS=1\n", ""),
            "partial unset": GOOD_SHELL.replace(" GIT_ICASE_PATHSPECS", ""),
            "echo, not unset": GOOD_SHELL.replace("unset ", "echo "),
            "array without no-replace": "a=(" + " ".join(f"-u {v}" for v in CLEARED) + ")\n"
                                        "env \"${a[@]}\" git status\n",
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.assertNotEqual(shell_violations(text), [])

    def test_the_guard_refuses_ineffective_python(self):
        cases = {
            "no env": GOOD_PYTHON.replace(", env=git_env()", ""),
            "ambient env": GOOD_PYTHON.replace("env=git_env()", "env=os.environ"),
            "no replace flag": GOOD_PYTHON.replace("    env['GIT_NO_REPLACE_OBJECTS'] = '1'\n", ""),
            "partial set": GOOD_PYTHON.replace(", 'GIT_ICASE_PATHSPECS'", ""),
            "names only in a comment": "# " + " ".join(CLEARED) + "\nsubprocess.run(['git', 'status'])\n",
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.assertNotEqual(python_violations(text), [])


if __name__ == "__main__":
    unittest.main()
