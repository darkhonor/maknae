#!/usr/bin/env python3
"""mutation-diff.py: changed-line parsing, per-package classification, scope attribution."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "ci/gates/mutation-diff.py"
spec = importlib.util.spec_from_file_location("mutation_diff", SCRIPT)
md = importlib.util.module_from_spec(spec)
spec.loader.exec_module(md)

F = "crates/a/src/x.rs"


def diff(body, path=F, header=None):
    head = header if header is not None else f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
    return head + body


def mutant(name, file, start, end=None, package="p"):
    line = {"line": start}
    return {"name": name, "package": package, "file": file,
            "span": {"start": line, "end": {"line": end if end is not None else start}}}


def run_cli(*args, env=None):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True,
                          env=env)


class ChangedLines(unittest.TestCase):
    def test_changed_lines_new_side_only(self):
        text = diff("@@ -36,3 +36,3 @@\n ctx\n-old\n+new\n ctx\n")
        self.assertEqual(md.changed_lines(text), {F: {36, 37}})

    def test_replacement_marks_the_line_before_not_after(self):
        text = diff("@@ -4,6 +4,4 @@\n a4\n-b\n-c\n-d\n+n5\n e6\n f7\n")
        self.assertEqual(md.changed_lines(text), {F: {4, 5}})

    def test_non_rs_files_ignored(self):
        text = diff("@@ -1 +1 @@\n-a\n+b\n", path="README.md")
        self.assertEqual(md.changed_lines(text), {})

    def test_rename_keys_new_path(self):
        text = ("diff --git a/a.rs b/b.rs\nsimilarity index 90%\nrename from a.rs\nrename to b.rs\n"
                "--- a/a.rs\n+++ b/b.rs\n@@ -1,2 +1,2 @@\n x\n-y\n+z\n")
        self.assertEqual(md.changed_lines(text), {"b.rs": {1, 2}})

    def test_deletion_maps_to_its_neighbours(self):
        text = diff("@@ -190,3 +190,2 @@\n ctx190\n-gone\n ctx191\n")
        self.assertEqual(md.changed_lines(text), {F: {190, 191}})

    def test_deletion_at_hunk_start_maps_to_next_line(self):
        text = diff("@@ -1,3 +1,2 @@\n-gone\n a\n b\n")
        self.assertEqual(md.changed_lines(text), {F: {1}})

    def test_deletion_at_end_of_file_maps_to_previous_line(self):
        text = diff("@@ -8,3 +8,2 @@\n a8\n b9\n-gone\n")
        self.assertEqual(md.changed_lines(text), {F: {9}})

    def test_deleted_file_ignored(self):
        text = ("diff --git a/x.rs b/x.rs\ndeleted file mode 100644\n--- a/x.rs\n+++ /dev/null\n"
                "@@ -1,2 +0,0 @@\n-a\n-b\n")
        self.assertEqual(md.changed_lines(text), {})

    def test_unrecognised_header_fails(self):
        text = diff("@@ -1 +1 @@\n-a\n+b\n", header=f"diff --git a/{F} b/{F}\n--- {F}\n+++ {F}\n")
        with self.assertRaises(md.DiffError):
            md.changed_lines(text)
        path = self.write(text)
        result = run_cli("changed-lines", path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL:", result.stderr)

    def test_nonempty_diff_with_no_files_fails(self):
        with self.assertRaises(md.DiffError):
            md.changed_lines("@@ -1 +1 @@\n-a\n+b\n")

    def test_hunk_count_mismatch_fails(self):
        for body in ("@@ -1,3 +1,3 @@\n a\n-b\n+c\n", "@@ -1,1 +1,1 @@\n a\n-b\n+c\n"):
            with self.assertRaises(md.DiffError):
                md.changed_lines(diff(body))

    def test_malformed_hunk_header_fails(self):
        with self.assertRaises(md.DiffError):
            md.changed_lines(diff("@@ nonsense @@\n a\n"))

    def test_omitted_counts_parse(self):
        self.assertEqual(md.changed_lines(diff("@@ -421 +436 @@\n-a\n+b\n")), {F: {435, 436}})
        text = diff("@@ -0,0 +1 @@\n+fn x() {}\n", header=f"diff --git a/{F} b/{F}\nnew file mode 100644\n--- /dev/null\n+++ b/{F}\n")
        self.assertEqual(md.changed_lines(text), {F: {1}})

    def test_no_newline_marker_counts_toward_neither_side(self):
        text = diff("@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n")
        self.assertEqual(md.changed_lines(text), {F: {1, 2}})

    def test_pure_rename_has_no_lines_and_passes(self):
        text = "diff --git a/a.rs b/b.rs\nsimilarity index 100%\nrename from a.rs\nrename to b.rs\n"
        self.assertEqual(md.changed_lines(text), {})

    def test_mode_only_change_passes(self):
        text = "diff --git a/a.rs b/a.rs\nold mode 100644\nnew mode 100755\n"
        self.assertEqual(md.changed_lines(text), {})

    def test_zero_context_deletion_still_counts(self):
        self.assertEqual(md.changed_lines(diff("@@ -7 +6,0 @@\n-gone\n")), {F: {6, 7}})

    def test_empty_diff_is_empty(self):
        self.assertEqual(md.changed_lines(""), {})

    def test_additions_in_two_files(self):
        text = (diff("@@ -1,2 +1,3 @@\n a\n+n\n b\n")
                + diff("@@ -5,2 +5,3 @@\n a\n b\n+z\n", path="crates/b/src/y.rs"))
        self.assertEqual(md.changed_lines(text), {F: {2}, "crates/b/src/y.rs": {7}})

    def test_binary_files_line_fails(self):
        text = f"diff --git a/{F} b/{F}\nindex 1111111..2222222 100644\nBinary files a/{F} and b/{F} differ\n"
        with self.assertRaises(md.DiffError):
            md.changed_lines(text)
        result = run_cli("changed-lines", self.write(text))
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL:", result.stderr)

    def test_git_binary_patch_fails(self):
        text = f"diff --git a/{F} b/{F}\nindex 1111111..2222222 100644\nGIT binary patch\nliteral 3\nKcmZ?\n\n"
        with self.assertRaises(md.DiffError):
            md.changed_lines(text)

    def test_form_feed_inside_an_added_line(self):
        for sep in ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"):
            with self.subTest(repr(sep)):
                text = diff(f"@@ -1,2 +1,3 @@\n ctx\n-a\n+b{sep}+c\n+d\n")
                self.assertEqual(md.changed_lines(text), {F: {1, 2, 3}})

    def test_carriage_return_inside_an_added_line_read_from_a_file(self):
        path = self.write(diff("@@ -1,2 +1,3 @@\n ctx\n-a\n+b\r+c\x0c+e\n+d\n"))
        result = run_cli("changed-lines", path)
        self.assertEqual((result.returncode, result.stdout), (0, json.dumps({F: [1, 2, 3]}) + "\n"),
                         result.stderr)

    def test_missing_final_newline_still_parses(self):
        self.assertEqual(md.changed_lines(diff("@@ -1 +1 @@\n-a\n+b")), {F: {1}})

    def write(self, text):
        handle = tempfile.NamedTemporaryFile("w", suffix=".diff", delete=False, newline="")
        self.addCleanup(os.unlink, handle.name)
        handle.write(text)
        handle.close()
        return handle.name


class Classify(unittest.TestCase):
    def test_classify_run(self):
        whole = [mutant("m1", F, 37), mutant("m2", F, 38)]
        self.assertEqual(md.classify("p", {F: {37, 38}}, whole, whole), ("RUN p: 2 in-diff mutants", 0))

    def test_classify_skip_no_overlap(self):
        line, status = md.classify("p", {F: {37}}, [mutant("m", F, 50)], [])
        self.assertEqual((line, status), ("SKIP: p: no mutant on a changed line", 0))

    def test_classify_mapping_failure(self):
        line, status = md.classify("p", {F: {37}}, [mutant("m", F, 37, 37)], [])
        self.assertEqual(status, 1)
        self.assertTrue(line.startswith("FAIL: p: 1 listed mutants on changed lines in "))
        self.assertIn(F, line)
        self.assertTrue(line.endswith("but the in-diff listing found none"))

    def test_multiline_span_overlap_hits(self):
        _, status = md.classify("p", {F: {35}}, [mutant("m", F, 30, 40)], [])
        self.assertEqual(status, 1)

    def test_span_boundaries_are_inclusive(self):
        for line in (30, 40):
            self.assertEqual(md.classify("p", {F: {line}}, [mutant("m", F, 30, 40)], [])[1], 1)
        for line in (29, 41):
            self.assertEqual(md.classify("p", {F: {line}}, [mutant("m", F, 30, 40)], [])[1], 0)

    def test_classify_other_package_ignored(self):
        whole = [mutant("m", F, 37, package="q")]
        self.assertEqual(md.classify("p", {F: {37}}, whole, [])[0], "SKIP: p: no mutant on a changed line")

    def test_classify_excluded_file_skips(self):
        self.assertEqual(md.classify("p", {F: {37}}, [], [])[1], 0)

    def test_classify_partial_mapping_failure(self):
        x, y = "crates/a/src/x.rs", "crates/a/src/y.rs"
        whole = [mutant("x1", x, 3), mutant("y1", y, 4)]
        line, status = md.classify("p", {x: {3}, y: {4}}, whole, [whole[0]])
        self.assertEqual(status, 1)
        self.assertIn("y1", line)
        self.assertNotIn("x1", line)

    def test_classify_same_file_dropped_mutant_fails(self):
        whole = [mutant("a1", F, 3), mutant("d1", F, 17)]
        line, status = md.classify("p", {F: {3, 17}}, whole, [whole[1]])
        self.assertEqual(status, 1)
        self.assertIn("a1", line)
        self.assertIn("dropped 1 mutants", line)

    def test_dropped_names_are_capped_at_three(self):
        whole = [mutant(f"m{n}", F, n) for n in range(1, 6)] + [mutant("kept", F, 9)]
        line, _ = md.classify("p", {F: {1, 2, 3, 4, 5, 9}}, whole, [whole[-1]])
        self.assertIn("dropped 5 mutants", line)
        self.assertIn("m3", line)
        self.assertNotIn("m4", line)

    def write(self, text):
        handle = tempfile.NamedTemporaryFile("w", delete=False)
        self.addCleanup(os.unlink, handle.name)
        handle.write(text)
        handle.close()
        return handle.name

    def test_empty_list_file_is_empty_list(self):
        patch = self.write(diff("@@ -1 +1 @@\n-a\n+b\n"))
        for content in ("", " \n\t\n"):
            empty = self.write(content)
            result = run_cli("classify", "p", patch, empty, empty)
            self.assertEqual((result.returncode, result.stdout), (0, "SKIP: p: no mutant on a changed line\n"))

    def test_garbage_list_file_fails(self):
        patch = self.write(diff("@@ -1 +1 @@\n-a\n+b\n"))
        good = self.write("[]")
        for content in ("not json", '{"a": 1}', '[{"name": "x"}]'):
            bad = self.write(content)
            result = run_cli("classify", "p", patch, bad, good)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, f"FAIL: p: unreadable mutant list {bad}\n")

    def test_cli_run_prints_one_line(self):
        patch = self.write(diff("@@ -1 +1 @@\n-a\n+b\n"))
        listing = self.write(json.dumps([mutant("m", F, 1)]))
        result = run_cli("classify", "p", patch, listing, listing)
        self.assertEqual((result.returncode, result.stdout), (0, "RUN p: 1 in-diff mutants\n"))

    def test_bad_argv_exits_one(self):
        self.assertEqual(run_cli("classify").returncode, 1)
        self.assertEqual(run_cli().returncode, 1)


class Paths(unittest.TestCase):
    def test_paths_name_each_new_side_file(self):
        text = (diff("@@ -1 +1 @@\n-a\n+b\n")
                + "diff --git a/a.rs b/b.rs\nsimilarity index 100%\nrename from a.rs\nrename to b.rs\n"
                + "diff --git a/m b.rs b/m b.rs\nold mode 100644\nnew mode 100755\n"
                + "diff --git a/e.rs b/e.rs\nnew file mode 100644\nindex 0000000..e69de29\n"
                + "diff --git a/g.rs b/g.rs\ndeleted file mode 100644\nindex e69de29..0000000\n"
                + "diff --git a/x.rs b/x.rs\ndeleted file mode 100644\n--- a/x.rs\n+++ /dev/null\n"
                + "@@ -1 +0,0 @@\n-+++ b/fake.rs\n")
        self.assertEqual(md.diff_paths(text), {F, "b.rs", "m b.rs", "e.rs"})

    def test_paths_unnameable_header_fails(self):
        with self.assertRaises(md.DiffError):
            md.diff_paths('diff --git "a/\\303.rs" "b/\\303.rs"\nold mode 100644\nnew mode 100755\n')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for args in (("init", "-q"), ("config", "user.email", "t@example.com"),
                     ("config", "user.name", "t"), ("config", "commit.gpgsign", "false")):
            self.git(*args)
        for name in ("a.rs", "src/b.rs", "gone.rs", "notes.md"):
            self.put(name, "x\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")
        self.put("a.rs", "y\n")
        self.put("src/b.rs", "y\n")
        self.put("notes.md", "y\n")
        (self.root / "gone.rs").unlink()
        self.git("add", "-A")
        self.git("commit", "-qm", "head")

    def git(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        return subprocess.run(["git", "-C", str(self.root), *args], env=env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def put(self, name, text):
        (self.root / name).parent.mkdir(parents=True, exist_ok=True)
        (self.root / name).write_text(text)

    def paths(self, text, env=None):
        patch = self.root.parent / (self.root.name + ".diff")
        self.addCleanup(lambda: patch.unlink(missing_ok=True))
        patch.write_text(text)
        return run_cli("paths", str(self.root), self.base, str(patch),
                       env=dict(os.environ, **(env or {})))

    def real_diff(self):
        return self.git("diff", "--no-color", self.base, "HEAD", "--", "*.rs") + "\n"

    def test_paths_agree_with_name_only(self):
        result = self.paths(self.real_diff())
        self.assertEqual((result.returncode, result.stdout), (0, "a.rs\nsrc/b.rs\n"), result.stderr)

    def test_paths_missing_a_changed_file_fails(self):
        text = self.real_diff()
        text = text[:text.index("diff --git a/src/b.rs")]
        result = self.paths(text)
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL:", result.stderr)
        self.assertIn("src/b.rs", result.stderr)

    def test_paths_empty_diff_with_rust_changes_fails(self):
        result = self.paths("")
        self.assertEqual(result.returncode, 1)
        self.assertIn("a.rs", result.stderr)

    def test_paths_naming_an_unchanged_file_fails(self):
        result = self.paths(self.real_diff() + diff("@@ -1 +1 @@\n-a\n+b\n", path="other.rs"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("other.rs", result.stderr)

    def test_paths_ignore_pathspec_and_repository_env(self):
        bogus = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, bogus)
        for var in ("GIT_LITERAL_PATHSPECS", "GIT_NOGLOB_PATHSPECS", "GIT_GLOB_PATHSPECS",
                    "GIT_ICASE_PATHSPECS", "GIT_COMMON_DIR", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
            with self.subTest(var):
                result = self.paths(self.real_diff(), env={var: bogus if "DIR" in var else "1"})
                self.assertEqual((result.returncode, result.stdout), (0, "a.rs\nsrc/b.rs\n"),
                                 result.stderr)

    def test_paths_ignore_replace_refs(self):
        text = self.real_diff()
        self.git("replace", self.base, self.git("commit-tree", "HEAD^{tree}", "-m", "fake"))
        self.assertEqual(self.git("diff", self.base, "HEAD"), "")
        result = self.paths(text)
        self.assertEqual((result.returncode, result.stdout), (0, "a.rs\nsrc/b.rs\n"), result.stderr)


MANIFEST = '[package]\nname = "{n}"\nversion = "0.1.0"\nedition = "2021"\n{extra}'
TIERS = '[t1]\nmutants_crates = ["alpha", "beta"]\n'
ALL = ["alpha", "beta"]


class Scope(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.com")
        self.git("config", "user.name", "t")
        self.git("config", "commit.gpgsign", "false")
        (self.root / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/*"]\nresolver = "2"\n')
        for name in ("alpha", "beta", "gamma"):
            self.put(f"crates/{name}/Cargo.toml", MANIFEST.format(n=name, extra=""))
            self.put(f"crates/{name}/src/lib.rs", "")
        self.put("coverage-tiers.toml", TIERS)
        self.put(".cargo/mutants.toml", 'exclude_globs = ["crates/alpha/src/skip.rs"]\n')
        self.put("rust-toolchain.toml", '[toolchain]\nchannel = "1.99.1"\n')
        self.put(".github/workflows/ci.yml", "run: cargo install cargo-mutants --version 27.1.0 --locked\n")
        self.put("ci/gates/mutation-terminated.txt",
                 "# header\nLinux\tcrates/alpha/src/a.rs\tf\t\\*=\twhy\n")
        self.commit("base")

    def git(self, *args, env=None):
        done = subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, text=True,
                              env=env)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.strip()

    def put(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def scope(self, env=None, workspace=None):
        base = self.git("rev-parse", "HEAD~1")
        full = dict(os.environ, **(env or {}))
        result = run_cli("scope", str(self.root), base, "HEAD", *([str(workspace)] if workspace else []),
                         env=full)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def change(self, path, text):
        self.put(path, text)
        self.commit("head")

    def assertScope(self, cases):
        for path, text, expected in cases:
            with self.subTest(path=path, text=text):
                self.change(path, text)
                try:
                    self.assertEqual(self.scope(), expected)
                finally:
                    self.git("reset", "-q", "--hard", "HEAD~1")

    def test_scope_documentation_is_empty(self):
        self.assertScope([("README.md", "x", []), ("packaging/README.md", "x", []),
                          ("design/notes.md", "x", [])])

    def test_scope_rust_in_a_crate_target_dir_is_left_to_the_diff(self):
        self.assertScope([(f"crates/beta/{d}/x.rs", "fn x() {}\n", [])
                          for d in ("src", "tests", "benches", "examples")])

    def test_scope_non_rust_input_in_a_crate_is_that_crate(self):
        self.assertScope([("crates/beta/src/prompt.txt", "data\n", ["beta"]),
                          ("crates/beta/build_rule.rs", "pub fn emit() {}\n", ["beta"]),
                          ("crates/beta/build.rs", "fn main() {}\n", ["beta"]),
                          ("crates/beta/README.md", "could be include_str data\n", ["beta"]),
                          ("crates/beta/tests/data/case.json", "{}\n", ["beta"]),
                          ("crates/beta/Cargo.toml", MANIFEST.format(n="beta", extra='\n[lib]\npath = "src/x.rs"\n'),
                           ["beta"])])

    def test_scope_an_input_owned_by_no_crate_is_all(self):
        root = (self.root / "Cargo.toml").read_text()
        self.assertScope([("Cargo.toml", root + "\n[profile.release]\nopt-level = 1\n", ALL)]
                         + [(path, "x = 1\n", ALL) for path in (
            ".cargo/config.toml", ".cargo/mutants.toml",
            "rust-toolchain.toml", ".config/nextest.toml", ".github/workflows/ci.yml",
            "ci/gates/mutation-terminated.txt", "ci/gates/coverage-tiers.sh", "ci/affected.py",
            "tools/gen.rs", ".gitattributes")])

    def test_scope_lockfile_is_empty(self):
        self.assertScope([("Cargo.lock", "version = 4\n", [])])

    def test_scope_dependency_tables_only_are_empty(self):
        deps = ('\n[dependencies]\ngamma = { path = "../gamma" }\n'
                '\n[dev-dependencies]\nx = "1"\n\n[build-dependencies]\ny = "1"\n'
                '\n[target.\'cfg(unix)\'.dependencies]\nz = "1"\n'
                '\n[target.\'cfg(unix)\'.dev-dependencies]\nw = "1"\n'
                '\n[target.\'cfg(unix)\'.build-dependencies]\nv = "1"\n')
        root = (self.root / "Cargo.toml").read_text()
        self.assertScope([("crates/beta/Cargo.toml", MANIFEST.format(n="beta", extra=deps), []),
                          ("Cargo.toml", root + '\n[workspace.dependencies]\nx = "1"\n', [])])

    def test_scope_manifest_comment_or_format_is_empty(self):
        root = (self.root / "Cargo.toml").read_text()
        self.assertScope([("crates/beta/Cargo.toml",
                           '# note\n[package]\nname    = "beta"\nversion = "0.1.0"\nedition = "2021"\n', []),
                          ("Cargo.toml", "# note\n" + root.replace(" = ", "   =   "), [])])

    def test_scope_dependency_and_other_table_still_widens(self):
        root = (self.root / "Cargo.toml").read_text()
        self.assertScope([("crates/beta/Cargo.toml",
                           MANIFEST.format(n="beta", extra='\n[dependencies]\nx = "1"\n\n[features]\nf = []\n'),
                           ["beta"]),
                          ("Cargo.toml", root + '\n[workspace.dependencies]\nx = "1"\n\n[profile.dev]\nopt-level = 1\n',
                           ALL)])

    def test_scope_an_added_or_once_unparseable_manifest_still_widens(self):
        self.assertScope([("crates/alpha/sub/Cargo.toml", MANIFEST.format(n="sub", extra=""), ["alpha"])])
        self.put("crates/beta/Cargo.toml", "[package\n")
        self.commit("break")
        self.change("crates/beta/Cargo.toml", MANIFEST.format(n="beta", extra=""))
        self.assertEqual(self.scope(), ["beta"])

    def test_scope_a_crate_outside_the_mutation_contract_is_empty(self):
        self.assertScope([("crates/gamma/src/prompt.txt", "data\n", []),
                          ("crates/gamma/src/lib.rs", "fn x() {}\n", [])])

    def test_scope_a_nested_crate_owns_its_own_paths(self):
        self.put("Cargo.toml", '[workspace]\nmembers = ["crates/*", "crates/beta/inner"]\nresolver = "2"\n')
        self.put("crates/beta/inner/Cargo.toml", MANIFEST.format(n="inner", extra=""))
        self.put("crates/beta/inner/src/lib.rs", "")
        self.commit("nest")
        self.assertScope([("crates/beta/inner/data.txt", "x\n", []),
                          ("crates/beta/data.txt", "x\n", ["beta"])])

    def test_scope_a_deletion_is_a_change(self):
        self.put("crates/beta/src/prompt.txt", "data\n")
        self.commit("add")
        (self.root / "crates/beta/src/prompt.txt").unlink()
        self.commit("remove")
        self.assertEqual(self.scope(), ["beta"])

    def test_scope_tiers_contract_change_is_all_of_head(self):
        self.change("coverage-tiers.toml", '[t1]\nmutants_crates = ["alpha", "beta", "gamma"]\n')
        self.assertEqual(self.scope(), ["alpha", "beta", "gamma"])
        self.git("reset", "-q", "--hard", "HEAD~1")
        self.change("coverage-tiers.toml", '[t1]\nmutants_crates = ["alpha"]\n')
        self.assertEqual(self.scope(), ["alpha"])

    def test_scope_unparseable_tiers_is_every_workspace_crate(self):
        self.change("coverage-tiers.toml", "[t1\n")
        self.assertEqual(self.scope(), ["alpha", "beta", "gamma"])

    def test_scope_build_script_inside_src_is_that_crate(self):
        self.change("crates/beta/Cargo.toml", MANIFEST.format(n="beta", extra='build = "src/build.rs"\n'))
        self.change("crates/beta/src/build.rs", "fn main() {}\n")
        self.assertEqual(self.scope(), ["beta"])

    def test_scope_any_change_under_a_build_scripts_directory_is_that_crate(self):
        self.change("crates/beta/build.rs", "mod src {\n    mod helper;\n}\nfn main() {}\n")
        self.assertScope([("crates/beta/src/helper.rs", "pub fn x() {}\n", ["beta"]),
                          ("crates/beta/tests/t.rs", "fn t() {}\n", ["beta"]),
                          ("crates/alpha/src/x.rs", "fn x() {}\n", [])])

    def test_scope_a_named_build_script_directory_bounds_the_widening(self):
        self.change("crates/beta/Cargo.toml",
                    MANIFEST.format(n="beta", extra='build = "build/main.rs"\n'))
        self.change("crates/beta/build/main.rs", "fn main() {}\n")
        self.assertScope([("crates/beta/build/rule.rs", "fn r() {}\n", ["beta"]),
                          ("crates/beta/src/x.rs", "fn x() {}\n", [])])

    def test_scope_a_disabled_build_script_does_not_widen(self):
        self.change("crates/beta/Cargo.toml", MANIFEST.format(n="beta", extra="build = false\n"))
        self.change("crates/beta/build.rs", "fn main() {}\n")
        self.assertScope([("crates/beta/src/x.rs", "fn x() {}\n", [])])

    def test_scope_reads_crate_directories_from_the_workspace_given(self):
        self.change("crates/beta/src/prompt.txt", "data\n")
        snapshot = Path(tempfile.mkdtemp()) / "snap"
        self.addCleanup(shutil.rmtree, snapshot.parent)
        md.snapshot(self.root, "HEAD", snapshot)
        self.put("Cargo.toml", '[workspace]\nmembers = ["crates/alpha"]\nresolver = "2"\n')
        self.assertEqual(self.scope(), ALL)
        self.assertEqual(self.scope(workspace=snapshot), ["beta"])

    def test_scope_git_env_is_ignored(self):
        self.change("crates/beta/src/prompt.txt", "data\n")
        bogus = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, bogus)
        self.assertEqual(self.scope({"GIT_DIR": bogus, "GIT_INDEX_FILE": bogus + "/idx",
                                     "GIT_LITERAL_PATHSPECS": "1"}), ["beta"])

    def test_scope_ignores_replace_refs(self):
        self.change("crates/beta/src/prompt.txt", "data\n")
        fake = self.git("commit-tree", "HEAD^{tree}", "-m", "fake")
        self.git("replace", self.git("rev-parse", "HEAD~1"), fake)
        self.assertEqual(self.git("diff", "HEAD~1", "HEAD"), "")
        self.assertEqual(self.scope(), ["beta"])

    def test_scope_unresolvable_revision_exits_one(self):
        result = run_cli("scope", str(self.root), "no-such-rev", "HEAD")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL:", result.stderr)

    def test_scope_option_like_revision_is_data(self):
        result = run_cli("scope", str(self.root), "--help", "HEAD")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL:", result.stderr)


class Unmappable(unittest.TestCase):
    setUp, git, put, commit = Scope.setUp, Scope.git, Scope.put, Scope.commit

    def check(self, env=None):
        return run_cli("unmappable", str(self.root), "HEAD", str(self.root),
                       env=dict(os.environ, **(env or {})))

    def assertRefused(self, *texts):
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for text in texts:
            self.assertIn(text, result.stdout)

    def assertAccepted(self):
        result = self.check()
        self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)

    def link(self, path, target):
        (self.root / path).symlink_to(target)
        self.commit("link")

    def test_unmappable_plain_workspace_is_accepted(self):
        self.assertAccepted()

    def test_unmappable_symlink_inside_a_mutation_crate_is_refused(self):
        self.put("crates/beta/src/real.rs", "")
        self.link("crates/beta/src/alias.rs", "real.rs")
        self.assertRefused("FAIL: --in-diff: symlink crates/beta/src/alias.rs in mutation crate beta; "
                           "in-diff mapping cannot follow aliases — use the whole-package run")

    def test_unmappable_symlink_aliasing_a_mutation_crate_is_refused(self):
        for target in ("crates/alpha/src", "crates", "."):
            with self.subTest(target=target):
                self.link("alias", target)
                try:
                    self.assertRefused("FAIL: --in-diff: symlink alias in mutation crate alpha;")
                finally:
                    self.git("reset", "-q", "--hard", "HEAD~1")

    def test_unmappable_symlink_outside_every_mutation_crate_is_accepted(self):
        self.put("AGENTS.md", "x\n")
        self.link("CLAUDE.md", "AGENTS.md")
        self.put("crates/gamma/src/real.rs", "")
        self.link("crates/gamma/src/alias.rs", "real.rs")
        self.assertAccepted()

    def test_unmappable_build_script_in_a_mapped_directory_is_refused(self):
        for script in ("src/build.rs", "./tests/build.rs", "benches/b/build.rs", "examples/build.rs",
                       "../alpha/src/build.rs", "/abs/build.rs", "../../../build.rs"):
            with self.subTest(script=script):
                self.put("crates/beta/Cargo.toml", MANIFEST.format(n="beta", extra=f'build = "{script}"\n'))
                self.commit("build")
                try:
                    result = self.check()
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertRegex(result.stdout, r"^FAIL: --in-diff: build script \S+ of mutation "
                                     r"crate beta lies inside a diff-mapped directory — use the "
                                     r"whole-package run\n$")
                finally:
                    self.git("reset", "-q", "--hard", "HEAD~1")
        self.put("crates/beta/Cargo.toml", MANIFEST.format(n="beta", extra='build = "src/build.rs"\n'))
        self.commit("build")
        self.assertRefused("build script crates/beta/src/build.rs of mutation crate beta")

    def test_unmappable_build_script_outside_mapped_directories_is_accepted(self):
        cases = {"build.rs": "", "build/main.rs": 'build = "build/main.rs"\n',
                 "src/build.rs": "build = false\n", "srcs/build.rs": 'build = "srcs/build.rs"\n'}
        for script, extra in cases.items():
            with self.subTest(script=script):
                self.put("crates/beta/Cargo.toml", MANIFEST.format(n="beta", extra=extra))
                self.put(f"crates/beta/{script}", "fn main() {}\n")
                self.commit("build")
                try:
                    self.assertAccepted()
                finally:
                    self.git("reset", "-q", "--hard", "HEAD~1")

    def test_unmappable_build_script_in_a_non_mutation_crate_is_ignored(self):
        self.put("crates/gamma/Cargo.toml", MANIFEST.format(n="gamma", extra='build = "src/build.rs"\n'))
        self.commit("build")
        self.assertAccepted()

    def test_unmappable_reads_heads_tree_not_the_working_tree(self):
        self.put("crates/beta/src/real.rs", "")
        (self.root / "crates/beta/src/alias.rs").symlink_to("real.rs")
        self.assertAccepted()

    def test_unmappable_git_env_is_ignored(self):
        self.put("crates/beta/src/real.rs", "")
        self.link("crates/beta/src/alias.rs", "real.rs")
        bogus = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, bogus)
        result = self.check({"GIT_DIR": bogus, "GIT_INDEX_FILE": bogus + "/idx"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("symlink crates/beta/src/alias.rs", result.stdout)


class Snapshot(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "repo"
        self.root.mkdir()
        self.git("init", "-q", "-b", "main")
        for name, text in FILES.items():
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
            (self.root / name).write_text(text)
        (self.root / "run.sh").chmod(0o755)
        os.symlink("src/lib.rs", self.root / "link.rs")
        self.git("add", "-A")
        self.git("-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
                 "commit", "-qm", "base")
        self.dest = self.tmp / "snap"

    def git(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        return subprocess.run(["git", "-C", str(self.root), *args], env=env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def tree(self, root):
        return {p.relative_to(root).as_posix(): (p.is_symlink(), os.readlink(p) if p.is_symlink()
                                                  else p.read_bytes(), p.lstat().st_mode & 0o777)
                for p in sorted(root.rglob("*")) if p.is_symlink() or p.is_file()}

    def test_snapshot_is_heads_raw_tree(self):
        result = run_cli("snapshot", str(self.root), "HEAD", str(self.dest))
        self.assertEqual(result.returncode, 0, result.stderr)
        got = self.tree(self.dest)
        self.assertEqual(sorted(got), sorted([*FILES, "link.rs"]))
        for name, text in FILES.items():
            self.assertEqual(got[name][1], text.encode(), name)
        self.assertEqual(got["run.sh"][2], 0o755)
        self.assertEqual(got["src/lib.rs"][2], 0o644)
        self.assertEqual(got["link.rs"][:2], (True, "src/lib.rs"))

    def test_snapshot_ignores_local_state(self):
        (self.root / ".git/info").mkdir(exist_ok=True)
        (self.root / ".git/info/attributes").write_text(
            "src/lib.rs export-ignore\nnotes.txt export-subst\n*.rs text eol=crlf\n")
        self.git("update-index", "--assume-unchanged", "src/lib.rs")
        (self.root / "src/lib.rs").write_text("// local\n")
        (self.root / "untracked.rs").write_text("fn u() {}\n")
        result = run_cli("snapshot", str(self.root), "HEAD", str(self.dest))
        self.assertEqual(result.returncode, 0, result.stderr)
        got = self.tree(self.dest)
        self.assertEqual(got["src/lib.rs"][1], FILES["src/lib.rs"].encode())
        self.assertEqual(got["notes.txt"][1], FILES["notes.txt"].encode())
        self.assertNotIn("untracked.rs", got)

    def test_snapshot_ignores_replace_refs(self):
        blob = subprocess.run(["git", "-C", str(self.root), "hash-object", "-w", "--stdin"],
                              input="// replaced\n", capture_output=True, text=True, check=True).stdout.strip()
        self.git("replace", "-f", self.git("rev-parse", "HEAD:src/lib.rs"), blob)
        self.assertEqual(self.git("show", "HEAD:src/lib.rs"), "// replaced")
        result = run_cli("snapshot", str(self.root), "HEAD", str(self.dest))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.dest / "src/lib.rs").read_text(), FILES["src/lib.rs"])

    def test_snapshot_refuses_a_submodule(self):
        commit = self.git("rev-parse", "HEAD")
        self.git("update-index", "--add", "--cacheinfo", f"160000,{commit},vendor/sub")
        self.git("-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
                 "commit", "-qm", "sub")
        result = run_cli("snapshot", str(self.root), "HEAD", str(self.dest))
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL: HEAD has a commit at vendor/sub", result.stderr)

    def test_snapshot_refuses_an_existing_destination(self):
        self.dest.mkdir()
        result = run_cli("snapshot", str(self.root), "HEAD", str(self.dest))
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL:", result.stderr)


FILES = {"src/lib.rs": "pub fn a() -> u32 {\n    1\n}\n", "notes.txt": "$Format:%H$\n",
         "run.sh": "#!/bin/sh\n", "Cargo.toml": '[package]\nname = "s"\nversion = "0.1.0"\n'}


class History(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "repo"
        self.root.mkdir()
        self.git("init", "-q", "-b", "main")
        for n in (1, 2):
            (self.root / "f").write_text(f"{n}\n")
            self.git("add", "-A")
            self.git("-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
                     "commit", "-qm", str(n))

    def git(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        return subprocess.run(["git", "-C", str(self.root), *args], env=env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def history(self, root=None, env=None):
        return run_cli("history", str(root or self.root), env=dict(os.environ, **(env or {})))

    def test_history_clean_passes(self):
        result = self.history()
        self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)

    def test_history_refuses_substitution(self):
        clone = self.tmp / "clone"
        subprocess.run(["git", "clone", "-q", "--depth", "1", "--no-local", f"file://{self.root}", str(clone)],
                       check=True, capture_output=True)
        result = self.history(clone)
        self.assertEqual(result.returncode, 1)
        self.assertIn("the repository is shallow", result.stdout)
        (self.root / ".git/info").mkdir(exist_ok=True)
        (self.root / ".git/info/grafts").write_text(self.git("rev-parse", "HEAD") + "\n")
        result = self.history()
        self.assertEqual(result.returncode, 1)
        self.assertIn("the repository has grafts", result.stdout)
        (self.root / ".git/info/grafts").unlink()
        self.git("replace", self.git("rev-parse", "HEAD~1"), self.git("rev-parse", "HEAD"))
        result = self.history(env={"GIT_NO_REPLACE_OBJECTS": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("the repository has replace refs (refs/replace/", result.stdout)

    def test_history_ignores_graft_file_env(self):
        grafts = self.tmp / "grafts"
        grafts.write_text(self.git("rev-parse", "HEAD") + "\n")
        result = self.history(env={"GIT_GRAFT_FILE": str(grafts)})
        self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)


if __name__ == "__main__":
    unittest.main()
