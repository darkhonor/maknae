#!/usr/bin/env python3
"""mutation-diff.py: changed-line parsing, per-package classification, scope attribution."""
import importlib.util
import json
import os
from pathlib import Path
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

    def write(self, text):
        handle = tempfile.NamedTemporaryFile("w", suffix=".diff", delete=False)
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


MANIFEST = '[package]\nname = "{n}"\nversion = "0.1.0"\nedition = "2021"\n{extra}'
TIERS = '[t1]\nmutants_crates = ["alpha", "beta"]\n'


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

    def scope(self, env=None):
        base = self.git("rev-parse", "HEAD~1")
        full = dict(os.environ, **(env or {}))
        result = run_cli("scope", str(self.root), base, "HEAD", env=full)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def change(self, path, text):
        self.put(path, text)
        self.commit("head")

    def test_scope_no_change_is_empty(self):
        self.put("README.md", "x")
        self.commit("head")
        self.assertEqual(self.scope(), [])

    def test_scope_comment_only_mutants_toml_is_empty(self):
        self.change(".cargo/mutants.toml", '# note\nexclude_globs = ["crates/alpha/src/skip.rs"]\n')
        self.assertEqual(self.scope(), [])

    def test_scope_mutants_toml_attributed(self):
        self.change(".cargo/mutants.toml",
                    'exclude_globs = ["crates/alpha/src/skip.rs", "crates/beta/src/new.rs"]\n')
        self.assertEqual(self.scope(), ["beta"])

    def test_scope_unattributable_mutants_toml_is_all(self):
        self.change(".cargo/mutants.toml",
                    'exclude_globs = ["crates/alpha/src/skip.rs"]\nexclude_re = ["some::thing"]\n')
        self.assertEqual(self.scope(), ["alpha", "beta"])

    def test_scope_other_key_change_is_all(self):
        self.change(".cargo/mutants.toml",
                    'exclude_globs = ["crates/alpha/src/skip.rs"]\nexamine_globs = ["x"]\n')
        self.assertEqual(self.scope(), ["alpha", "beta"])

    def test_scope_unparseable_base_is_all(self):
        self.put(".cargo/mutants.toml", "exclude_globs = [\n")
        self.commit("break")
        self.put(".cargo/mutants.toml", 'exclude_globs = ["crates/alpha/src/skip.rs"]\n')
        self.commit("fix")
        self.assertEqual(self.scope(), ["alpha", "beta"])

    def test_scope_toolchain_is_all(self):
        self.change("rust-toolchain.toml", '[toolchain]\nchannel = "1.99.2"\n')
        self.assertEqual(self.scope(), ["alpha", "beta"])

    def test_scope_cargo_mutants_pin_is_all(self):
        self.change(".github/workflows/ci.yml", "run: cargo install cargo-mutants --version 27.2.0 --locked\n")
        self.assertEqual(self.scope(), ["alpha", "beta"])

    def test_scope_gate_script_is_all(self):
        for name in ("mutation-oracle.sh", "coverage-tiers.sh", "mutation-diff.py"):
            self.change(f"ci/gates/{name}", "x\n")
            self.assertEqual(self.scope(), ["alpha", "beta"], name)
            self.git("reset", "-q", "--hard", "HEAD~1")

    def test_scope_added_crate(self):
        self.change("coverage-tiers.toml", '[t1]\nmutants_crates = ["alpha", "beta", "gamma"]\n')
        self.assertEqual(self.scope(), ["gamma"])

    def test_scope_removed_crate_is_not_selected(self):
        self.change("coverage-tiers.toml", '[t1]\nmutants_crates = ["alpha"]\n')
        self.assertEqual(self.scope(), [])

    def test_scope_features_change(self):
        self.change("coverage-tiers.toml",
                    TIERS + 'mutants_features = { beta = ["x"] }\n')
        self.assertEqual(self.scope(), ["beta"])

    def test_scope_crate_features_is_that_crate(self):
        self.change("crates/beta/Cargo.toml", MANIFEST.format(n="beta", extra='\n[features]\nx = []\n'))
        self.assertEqual(self.scope(), ["beta"])

    def test_scope_crate_manifest_without_feature_change_is_empty(self):
        self.change("crates/beta/Cargo.toml", MANIFEST.format(n="beta", extra='description = "d"\n'))
        self.assertEqual(self.scope(), [])

    def test_scope_unparseable_tiers_is_all(self):
        self.change("coverage-tiers.toml", "[t1\n")
        self.assertEqual(self.scope(), ["alpha", "beta", "gamma"])

    def test_scope_terminated_entry(self):
        self.change("ci/gates/mutation-terminated.txt",
                    "# header\nLinux\tcrates/alpha/src/a.rs\tf\t\\*=\twhy\nLinux\tcrates/beta/src/b.rs\tg\t.*\twhy\n")
        self.assertEqual(self.scope(), ["beta"])

    def test_scope_terminated_unsplittable_or_unmapped_is_all(self):
        self.change("ci/gates/mutation-terminated.txt",
                    "# header\nLinux\tcrates/alpha/src/a.rs\tf\t\\*=\twhy\nbroken line\n")
        self.assertEqual(self.scope(), ["alpha", "beta"])
        self.git("reset", "-q", "--hard", "HEAD~1")
        self.change("ci/gates/mutation-terminated.txt",
                    "# header\nLinux\tcrates/alpha/src/a.rs\tf\t\\*=\twhy\nLinux\tcrates/nowhere/x.rs\tg\t.*\twhy\n")
        self.assertEqual(self.scope(), ["alpha", "beta"])

    def test_scope_nextest_profile_is_io_and_sys(self):
        self.put("crates/io/Cargo.toml", MANIFEST.format(n="maknae-io", extra=""))
        self.put("crates/io/src/lib.rs", "")
        self.put("crates/sys/Cargo.toml", MANIFEST.format(n="maknae-sys", extra=""))
        self.put("crates/sys/src/lib.rs", "")
        self.put("coverage-tiers.toml", '[t1]\nmutants_crates = ["alpha", "beta", "maknae-io", "maknae-sys"]\n')
        self.commit("add io and sys")
        self.change(".config/nextest.toml", "x = 1\n")
        self.assertEqual(self.scope(), ["maknae-io", "maknae-sys"])

    def test_scope_git_env_is_ignored(self):
        self.change("coverage-tiers.toml", '[t1]\nmutants_crates = ["alpha", "beta", "gamma"]\n')
        bogus = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, bogus)
        self.assertEqual(self.scope({"GIT_DIR": bogus, "GIT_INDEX_FILE": bogus + "/idx"}), ["gamma"])

    def test_scope_unresolvable_revision_exits_one(self):
        result = run_cli("scope", str(self.root), "no-such-rev", "HEAD")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL:", result.stderr)

    def test_scope_option_like_revision_is_data(self):
        result = run_cli("scope", str(self.root), "--help", "HEAD")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL:", result.stderr)


if __name__ == "__main__":
    unittest.main()
