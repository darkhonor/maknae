#!/usr/bin/env python3
"""The mutation gate's wiring, driven through fake cargo tools; needs no cargo-mutants."""
import collections
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import tempfile
import time
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "ci/gates/mutation-platform.sh"
CHANNEL = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
REAL_CARGO = shutil.which("cargo")


class MutationGate(unittest.TestCase):
    def run_gate(self, crate, *, nextest="0.9.146", logs=None, total=None, reviewed=None,
                 path=None, mode="list", fake_exit=0, litter=False, extra_env=None,
                 failing_chmod=False, term=False, planned_extra=0, phase="Test", plan=True,
                 home_nextest=None, baseline=None):
        # The real gate, with its documented injection fixture interface. This
        # proves CLI wiring, independently of what the filter script prints.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            try:
                return self._run_gate(root, crate, nextest, logs, total, reviewed, path, mode,
                                      fake_exit, litter, extra_env or {}, failing_chmod, term,
                                      planned_extra, phase, plan, home_nextest, baseline)
            finally:
                subprocess.run(["chmod", "-R", "u+rwx", str(root)])

    def _run_gate(self, root, crate, nextest, logs, total, reviewed, path, mode, fake_exit,
                  litter, extra_env, failing_chmod, term, planned_extra, phase, plan,
                  home_nextest, baseline):
        tools = root / "tools"
        tools.mkdir()
        gate = ROOT / "ci/gates/coverage-tiers.sh"
        if reviewed is not None:
            gates = root / "gates"
            gates.mkdir()
            for name in ("coverage-tiers.sh", "mutation-platform.sh", "mutation-oracle.sh"):
                shutil.copy(ROOT / "ci/gates" / name, gates / name)
            if reviewed is not MISSING:
                (gates / "mutation-terminated.txt").write_text(reviewed)
            gate = gates / "coverage-tiers.sh"
        (root / "coverage-tiers.toml").write_text(f'[t1]\nmutants_crates = ["{crate}"]\n')
        payload = root / "payload"
        write_payload(payload, CAUGHT_LOGS if logs is None else logs, total, planned_extra, phase, plan,
                      baseline)
        outer_tmp = root / "tmp"
        outer_tmp.mkdir()
        cargo_home = root / "cargo-home"
        cargo_home.mkdir()
        if home_nextest:
            (cargo_home / "bin").mkdir()
            fake_nextest(cargo_home / "bin", home_nextest)
        fake_cargo(tools)
        if failing_chmod:
            (tools / "chmod").write_text(f'#!/bin/sh\n"{shutil.which("chmod")}" "$@"\nexit 1\n')
            (tools / "chmod").chmod(0o755)
        if nextest:
            fake_nextest(tools, nextest)
        search = str(tools) + os.pathsep + (path or os.environ["PATH"])
        arguments = root / "args"
        env = {k: v for k, v in os.environ.items() if not k.startswith("NEXTEST_")}
        env.update(PATH=search, MUTATION_ARGS=str(arguments), FAKE_PAYLOAD=str(payload),
                   FAKE_EXIT=str(fake_exit), FAKE_LITTER="1" if litter else "0",
                   FAKE_SLEEP="1" if term else "0", REAL_CARGO=REAL_CARGO,
                   CARGO_HOME=str(cargo_home), RUSTUP_TOOLCHAIN=CHANNEL,
                   TMPDIR=str(outer_tmp), COVERAGE_TIERS_JSON=str(root / "unused"),
                   COVERAGE_TIERS_FILELIST=str(root / "unused"),
                   COVERAGE_TIERS_CRATE_DIRS=f"{crate}=crates/{crate}", **extra_env)
        selection = ["--mutants-all"] if mode == "all" else ["--mutants", crate]
        argv = [BASH, str(gate), "--root", str(root), "--injection", *selection]
        if term:
            result = self.terminate_during_run(argv, env, Path(str(arguments) + ".pid"))
        else:
            result = subprocess.run(argv, env=env, text=True, capture_output=True)

        def read(suffix):
            f = Path(str(arguments) + suffix)
            return f.read_text().splitlines() if f.exists() else None
        return Run(result, read(""), read(".env"), read(".tmpdir"), read(".litter"),
                   sorted(os.listdir(outer_tmp)), root)

    def terminate_during_run(self, argv, env, pidfile):
        gate = subprocess.Popen(argv, env=env, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        deadline = time.monotonic() + 30
        while not pidfile.exists() or not pidfile.read_text().strip():
            self.assertLess(time.monotonic(), deadline, "fake cargo never started")
            time.sleep(0.05)
        child = int(pidfile.read_text())
        started = time.monotonic()
        gate.send_signal(signal.SIGTERM)
        try:
            stdout, stderr = gate.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            gate.kill()
            os.kill(child, signal.SIGKILL)
            gate.communicate()
            raise
        self.assertLess(time.monotonic() - started, 10, "the gate did not stop promptly")
        with self.assertRaises(ProcessLookupError, msg="the cargo child outlived the gate"):
            os.kill(child, 0)
        return subprocess.CompletedProcess(argv, gate.returncode, stdout, stderr)

    def gate_argv(self, crate, **kwargs):
        run = self.run_gate(crate, **kwargs)
        self.assertEqual(run.result.returncode, 0, run.result.stdout + run.result.stderr)
        # `--output` is the gate's: each crate gets its own results dir so the
        # run can be judged afterwards (#301).
        self.assertEqual(run.argv[:3], ["mutants", "--package", crate])
        self.assertEqual(run.argv[3], "--output")
        self.assertEqual(run.argv[4], str(run.root / "target" / f"mutants-{crate}"))
        return run

    def test_gate_creates_the_output_parent_on_a_fresh_tree(self):
        run = self.gate_argv("maknae-kernel")
        self.assertIn("mutants[maknae-kernel]:", run.result.stdout)

    def test_gate_passes_native_filter_as_one_argument(self):
        expected = subprocess.check_output(["bash", str(SCRIPT)], text=True).strip()
        run = self.gate_argv("maknae-io", extra_env=AMBIENT)
        self.assertEqual(run.argv[5:], ["--exclude-re", expected, "--minimum-test-timeout", "60",
                                        "--test-tool", "nextest"])
        self.assertEqual(run.env, sorted(PINNED))

    def test_gate_passes_the_native_filter_to_maknae_sys(self):
        expected = subprocess.check_output(["bash", str(SCRIPT)], text=True).strip()
        run = self.gate_argv("maknae-sys", extra_env=AMBIENT)
        self.assertEqual(run.argv[5:], ["--exclude-re", expected])
        self.assertEqual(Path(run.tmpdir[0]).parent, run.root / "tmp")
        self.assertEqual(run.leftover, [])
        self.assertEqual(run.env, sorted(f"{k}={v}" for k, v in AMBIENT.items()))

    def test_maknae_io_runs_in_a_scratch_tmpdir_that_is_removed(self):
        for fake_exit in (0, 3):
            run = self.run_gate("maknae-io", litter=True, fake_exit=fake_exit)
            self.assertEqual(run.result.returncode != 0, fake_exit != 0, run.result.stdout)
            self.assertEqual(run.litter, ["littered"])
            self.assertEqual(Path(run.tmpdir[0]).parent, run.root / "tmp")
            self.assertEqual(run.leftover, [], f"exit {fake_exit}")

    def test_scratch_tmpdir_is_removed_when_chmod_fails(self):
        run = self.run_gate("maknae-io", litter=True, failing_chmod=True)
        self.assertEqual(run.litter, ["littered"])
        self.assertEqual(run.leftover, [])

    def test_terminated_gate_stops_its_run_promptly_and_cleans_up(self):
        run = self.run_gate("maknae-io", litter=True, term=True)
        self.assertEqual(run.result.returncode, 143, run.result.stdout + run.result.stderr)
        self.assertEqual(run.litter, ["littered"])
        self.assertEqual(run.leftover, [])

    def test_gate_fails_closed_without_cargo_nextest(self):
        system_path = "/usr/bin:/bin"
        self.assertIsNone(shutil.which("cargo-nextest", path=system_path))
        for crate, mode in (("maknae-io", "list"), ("maknae-sys", "all")):
            run = self.run_gate(crate, nextest=None, path=system_path, mode=mode)
            self.assertNotEqual(run.result.returncode, 0, mode)
            self.assertIn("cargo-nextest missing", run.result.stdout)
            self.assertIsNone(run.argv)

    def test_gate_fails_closed_on_another_nextest_version(self):
        run = self.run_gate("maknae-io", nextest="0.9.145")
        self.assertNotEqual(run.result.returncode, 0)
        self.assertIn("'cargo-nextest 0.9.145 (fixture)' is not cargo-nextest 0.9.146", run.result.stdout)
        self.assertIsNone(run.argv)

    def test_readiness_checks_the_nextest_cargo_runs(self):
        run = self.run_gate("maknae-io", home_nextest="0.9.145")
        self.assertNotEqual(run.result.returncode, 0)
        self.assertIn("'cargo-nextest 0.9.145 (fixture)' is not cargo-nextest 0.9.146", run.result.stdout)
        self.assertIsNone(run.argv)

    def assertGate(self, ok, logs, reviewed=None, *, contains=(), **kwargs):
        run = self.run_gate("maknae-io", logs=logs, **kwargs,
                            reviewed=REVIEWED_HEADER if reviewed is None else reviewed)
        out = run.result.stdout + run.result.stderr
        self.assertEqual(run.result.returncode == 0, ok, out)
        for text in contains:
            self.assertIn(text, out)
        return out

    def test_terminated_only_mutant_without_review_fails(self):
        self.assertGate(False, [TERMINATED], contains=(TERMINATED["name"], "caught only by termination"))

    def test_sigterm_from_fail_fast_is_termination_not_a_failure(self):
        self.assertGate(False, [TERMINATED_SIGTERM], contains=("caught only by termination",))

    def test_coloured_timeout_is_still_a_timeout(self):
        self.assertGate(False, [COLOURED], contains=("caught only by termination",))

    def test_retried_timeout_is_still_a_timeout(self):
        self.assertGate(False, [RETRIED], contains=("caught only by termination",))

    def test_summary_timeout_without_a_timeout_line_fails(self):
        self.assertGate(False, [mutant("e", "", summary=summary_line(0, 1))],
                        contains=(MUTANT_PREFIX + "e", "Summary reports 1 timed out"))

    def test_caught_mutant_without_a_status_line_fails(self):
        self.assertGate(False, [mutant("i", "", summary=summary_line(0, 0))],
                        contains=(MUTANT_PREFIX + "i", "no failure or timeout status line"))

    def test_summary_counting_more_failures_than_status_lines_fails(self):
        self.assertGate(False, [mutant("f", FAIL_LINE + "\n" + TIMEOUT_LINE, summary=summary_line(2, 1))],
                        contains=(MUTANT_PREFIX + "f", "Summary reports 2 failed"))

    def test_summary_counting_more_timeouts_than_status_lines_fails(self):
        self.assertGate(False, [mutant("g", FAIL_LINE + "\n" + TIMEOUT_LINE, summary=summary_line(1, 2))],
                        contains=(MUTANT_PREFIX + "g", "2 timed out"))

    def test_repeated_final_status_lines_count_once(self):
        self.assertGate(False, [mutant("h", FAIL_LINE, summary=summary_line(2, 0) + "\n" + FAIL_LINE)],
                        contains=(MUTANT_PREFIX + "h", "Summary reports 2 failed"))

    def test_baseline_with_failures_fails(self):
        self.assertGate(False, [TIMEOUT_AND_FAIL], baseline=summary_line(1, 0),
                        contains=("baseline", "Summary reports 1 failed"))

    def test_signal_alongside_a_timeout_is_caught(self):
        self.assertGate(True, [SIGABRT_AND_TIMEOUT])

    def test_timeout_alongside_a_failure_is_caught(self):
        self.assertGate(True, [TIMEOUT_AND_FAIL])

    def test_test_phase_without_status_lines_or_summary_fails(self):
        self.assertGate(False, [mutant("a", "", summary=False)], contains=(MUTANT_PREFIX + "a",))

    def test_test_phase_without_summary_fails(self):
        self.assertGate(False, [mutant("b", FAIL_LINE, summary=False)], contains=("Summary", MUTANT_PREFIX + "b"))

    def test_tested_outcome_without_a_test_phase_header_fails(self):
        self.assertGate(False, [mutant("c", FAIL_LINE, header=False)], contains=(MUTANT_PREFIX + "c",))

    def test_missing_log_fails(self):
        self.assertGate(False, [mutant("d", FAIL_LINE, log=False)], contains=(MUTANT_PREFIX + "d",))

    def test_outcomes_not_covering_every_planned_mutant_fails(self):
        self.assertGate(False, [TIMEOUT_AND_FAIL], planned_extra=1, contains=("mutants.json",))

    def test_missing_plan_fails(self):
        self.assertGate(False, [TIMEOUT_AND_FAIL], plan=False, contains=("mutants.json",))

    def test_judging_fewer_test_phases_than_viable_mutants_fails(self):
        self.assertGate(False, [TIMEOUT_AND_FAIL], phase="Testing", contains=("test phases",))

    def test_captured_test_output_fails(self):
        self.assertGate(False, [CAPTURED], contains=("captured test output",))

    def test_reviewed_entry_covers_this_platform(self):
        self.assertGate(True, [TERMINATED], REVIEWED_HEADER + entry(platform.system()),
                        contains=(TERMINATED["name"],))

    def test_reviewed_entry_matches_file_function_and_whole_replacement(self):
        system = platform.system()
        for label, row in {"replacement prefix": entry(system, regex="\\*"),
                           "other function": entry(system, fn="grow_pag"),
                           "other file": entry(system, file="crates/maknae-io/src/other.rs")}.items():
            with self.subTest(label):
                self.assertGate(False, [TERMINATED], REVIEWED_HEADER + row,
                                contains=("caught only by termination",))

    def test_permissive_replacement_regex_exempts_only_its_own_function(self):
        for regex in ("x|.*", "(?:x)?.*"):
            with self.subTest(regex):
                row = REVIEWED_HEADER + entry(platform.system(), regex=regex)
                self.assertGate(True, [TERMINATED], row)
                self.assertGate(False, [TERMINATED, TERMINATED_SHRINK], row,
                                contains=(TERMINATED_SHRINK["name"] + " was caught only by termination",
                                          TERMINATED["name"] + " (reviewed)"))

    def test_reviewed_entry_for_the_other_platform_does_not_cover_this_one(self):
        other = {"Linux": "Darwin", "Darwin": "Linux"}[platform.system()]
        self.assertGate(False, [TERMINATED], REVIEWED_HEADER + entry(other),
                        contains=("caught only by termination",))

    def test_unobserved_reviewed_entry_is_reported_not_failed(self):
        self.assertGate(True, [TIMEOUT_AND_FAIL], REVIEWED_HEADER + entry(platform.system()),
                        contains=("not observed",))

    def test_invalid_reviewed_rows_fail(self):
        system = platform.system()
        rows = {
            "bad platform": entry("Plan9"),
            "invalid regex": entry(system, regex="("),
            "missing reason": entry(system).replace("\tfixture", "\t "),
            "empty regex": entry(system, regex=""),
            "empty file": entry(system, file=""),
            "empty function": entry(system, fn=""),
            "old three-field row": f"{system}\tcrates/maknae-io/src/page.rs: replace .* in grow_page\tfixture\n",
        }
        for label, row in rows.items():
            with self.subTest(label):
                self.assertGate(False, [TIMEOUT_AND_FAIL], REVIEWED_HEADER + row,
                                contains=("mutation-terminated.txt:2",))

    def test_unreadable_reviewed_list_fails(self):
        self.assertGate(False, [TIMEOUT_AND_FAIL], MISSING, contains=("reviewed terminated-mutant list",))


class InDiff(unittest.TestCase):
    """`--in-diff <rev>` on a real git fixture, real `cargo metadata`, and a fake cargo-mutants."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: (subprocess.run(["chmod", "-R", "u+rwx", str(self.tmp)]),
                                 shutil.rmtree(self.tmp, ignore_errors=True)))
        self.aux = self.tmp / "aux"
        for name in ("tools", "tmp", "cargo-home", "payload"):
            (self.aux / name).mkdir(parents=True)
        fake_cargo(self.aux / "tools")

    def in_diff_repo(self, changes, *, names=("a", "b"), base_crates=None, features="",
                     config=None, base_files=None, links=None):
        repo = self.tmp / "repo"
        crates = list(base_crates or names)
        files = {
            "Cargo.toml": '[workspace]\nmembers = ["crates/a", "crates/b"]\nresolver = "2"\n',
            "crates/a/Cargo.toml": package_toml(names[0]) + "\n[features]\nextra = []\n",
            "crates/a/src/lib.rs": LIB_A,
            "crates/b/Cargo.toml": package_toml(names[1]),
            "crates/b/src/lib.rs": "pub fn b(x: u32) -> u32 {\n    x + 2\n}\n",
            "coverage-tiers.toml": tiers_toml(crates, features),
            ".gitignore": "/target\nCargo.lock\n",
            "ci/gates/mutation-terminated.txt": "",
            **(base_files or {}),
        }
        for name in ("coverage-tiers.sh", "mutation-oracle.sh", "mutation-platform.sh",
                     "mutation-diff.py"):
            files[f"ci/gates/{name}"] = (ROOT / "ci/gates" / name).read_text()
        files["ci/affected.py"] = (ROOT / "ci/affected.py").read_text()
        write_tree(repo, files)
        for name, target in (links or {}).items():
            (repo / name).symlink_to(target)
        git(repo, "init", "-q", "-b", "main")
        for key, value in (config or {}).items():
            git(repo, "config", key, value)
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "base")
        git(repo, "tag", "base")
        write_tree(repo, changes)
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "--allow-empty", "-m", "head")
        return repo

    def gate(self, repo, *args, crates=("a", "b"), whole=(), indiff=(), extra_env=None,
             missed=0, fake_exit=0, root=None, total=None):
        payload = self.aux / "payload"
        shutil.rmtree(payload)
        write_payload(payload, CAUGHT_LOGS, len(indiff) if indiff else total, missed=missed)
        self.args = self.aux / "args"
        for f in self.aux.glob("args*"):
            f.unlink()
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("NEXTEST_", "COVERAGE_TIERS_", "GIT_"))}
        env.update(PATH=str(self.aux / "tools") + os.pathsep + os.environ["PATH"],
                   MUTATION_ARGS=str(self.args), FAKE_PAYLOAD=str(payload),
                   FAKE_EXIT=str(fake_exit), REAL_CARGO=REAL_CARGO,
                   CARGO_HOME=str(self.aux / "cargo-home"), RUSTUP_TOOLCHAIN=CHANNEL,
                   TMPDIR=str(self.aux / "tmp"), MUTATION_ORACLE_MIN_KIB="1",
                   LLVM_COV="", LLVM_PROFDATA="",
                   FAKE_WHOLE_LIST=json.dumps(list(whole)) if whole else "",
                   FAKE_INDIFF_LIST=json.dumps(list(indiff)) if indiff else "",
                   **(extra_env or {}))
        argv = [BASH, str(repo / "ci/gates/coverage-tiers.sh"), "--root", str(root or repo)]
        argv += list(args) if args else ["--mutants", *crates, "--in-diff", "base"]
        result = subprocess.run(argv, env=env, text=True, capture_output=True)
        return result, result.stdout + result.stderr

    def invocations(self):
        log = Path(str(self.args) + ".log")
        return [line.rstrip("\t").split("\t") for line in log.read_text().splitlines()] \
            if log.exists() else []

    def runs(self):
        return [argv for argv in self.invocations() if "--list" not in argv]

    def assertFails(self, result, out, *texts):
        self.assertEqual(result.returncode, 1, out)
        for text in texts:
            self.assertIn(text, out)

    def test_in_diff_passes_flag_to_cargo_mutants(self):
        repo = self.in_diff_repo(EDIT_A, features='mutants_features = { a = ["extra"] }\n')
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("RUN a: 2 in-diff mutants", out)
        self.assertIn("SKIP: b: no mutant on a changed line", out)
        self.assertIn("mutants[a]:", out)
        [run] = self.runs()
        self.assertEqual(run[:4], ["mutants", "--package", "a", "--output"])
        self.assertIn("--in-diff", run)
        self.assertEqual(Path(run[run.index("--in-diff") + 1]).name, "in.diff")
        self.assertEqual(run[run.index("--features") + 1], "extra")
        lists = [argv for argv in self.invocations() if "--list" in argv and "a" in argv]
        self.assertEqual(len(lists), 2)
        for argv in lists:
            self.assertEqual(argv[argv.index("--features") + 1], "extra")

    def test_in_diff_survivor_fails(self):
        repo = self.in_diff_repo(EDIT_A)
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2], missed=1,
                                fake_exit=2)
        self.assertFails(result, out, "RUN a: 2 in-diff mutants",
                         "cargo mutants --package a reported missed/timeout mutants")

    def test_in_diff_mapping_failure_fails(self):
        repo = self.in_diff_repo(EDIT_A)
        result, out = self.gate(repo, whole=WHOLE_EDIT)
        self.assertFails(result, out, "FAIL: a: 2 listed mutants on changed lines in "
                         "crates/a/src/lib.rs but the in-diff listing found none")
        self.assertEqual(self.runs(), [])

    def test_in_diff_docs_only_skips(self):
        repo = self.in_diff_repo({"README.md": "docs\n"})
        result, out = self.gate(repo, whole=WHOLE_EDIT)
        self.assertEqual(result.returncode, 0, out)
        self.assertRegex(out, r"SKIP: in-diff: no Rust change between [0-9a-f]{40} and HEAD")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_test_module_change_skips(self):
        repo = self.in_diff_repo(TEST_MOD_A)
        result, out = self.gate(repo, whole=WHOLE_EDIT)
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("SKIP: a: no mutant on a changed line", out)
        self.assertEqual(self.runs(), [])
        self.assertTrue(self.invocations())

    def test_in_diff_one_package(self):
        repo = self.in_diff_repo(EDIT_A)
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("RUN a: 2 in-diff mutants", out)
        self.assertIn("SKIP: b: no mutant on a changed line", out)
        self.assertEqual([run[2] for run in self.runs()], ["a"])

    def test_in_diff_scope_change_runs_whole(self):
        repo = self.in_diff_repo({"coverage-tiers.toml": tiers_toml(["a", "b"], "")},
                                 base_crates=["a"])
        result, out = self.gate(repo, whole=WHOLE_EDIT)
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("whole: a: mutation scope changed", out)
        self.assertIn("whole: b: mutation scope changed", out)
        runs = self.invocations()
        self.assertEqual([run[:3] for run in runs], [["mutants", "--package", "a"],
                                                     ["mutants", "--package", "b"]])
        for run in runs:
            self.assertNotIn("--in-diff", run)

    def test_in_diff_bad_rev_fails(self):
        repo = self.in_diff_repo(EDIT_A)
        result, out = self.gate(repo, "--mutants", "a", "--in-diff", "no-such-rev")
        self.assertFails(result, out, "FAIL: --in-diff: no-such-rev is not a commit")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_no_merge_base_fails(self):
        repo = self.in_diff_repo(EDIT_A)
        tree = git(repo, "mktree", input="")
        git(repo, "tag", "unrelated", git(repo, "commit-tree", tree, "-m", "unrelated"))
        result, out = self.gate(repo, "--mutants", "a", "--in-diff", "unrelated")
        self.assertFails(result, out, "FAIL: --in-diff: no merge base between unrelated and HEAD")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_dirty_tree_fails(self):
        repo = self.in_diff_repo(EDIT_A)
        (repo / "crates/a/src/lib.rs").write_text(LIB_A + "\n")
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertFails(result, out, "FAIL: --in-diff attests to HEAD; uncommitted or untracked:",
                         "crates/a/src/lib.rs")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_untracked_test_file_fails(self):
        repo = self.in_diff_repo(EDIT_A)
        write_tree(repo, {"crates/a/tests/extra.rs": "#[test]\nfn t() {}\n"})
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertFails(result, out, "FAIL: --in-diff attests to HEAD; uncommitted or untracked:",
                         "crates/a/tests/extra.rs")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_noprefix_config_still_fails_on_mapping_failure(self):
        repo = self.in_diff_repo(DELETE_A, config={
            "diff.noprefix": "true", "diff.mnemonicPrefix": "true",
            "diff.suppressBlankEmpty": "true", "diff.context": "0"})
        result, out = self.gate(repo, whole=WHOLE_DELETE, extra_env={"GIT_DIFF_OPTS": "-u0"})
        self.assertFails(result, out, "FAIL: a: 1 listed mutants on changed lines in "
                         "crates/a/src/lib.rs but the in-diff listing found none")
        self.assertNotIn("unrecognised", out)
        self.assertThreeLineContext()

    def test_in_diff_git_diff_opts_mixed_change(self):
        repo = self.in_diff_repo(MIXED_A)
        result, out = self.gate(repo, whole=WHOLE_DELETE, indiff=WHOLE_DELETE[1:2],
                                extra_env={"GIT_DIFF_OPTS": "-u0"})
        self.assertFails(result, out, "FAIL: a: in-diff listing dropped 1 mutants on changed "
                         "lines: " + WHOLE_DELETE[0]["name"])
        self.assertThreeLineContext()
        self.assertEqual(self.runs(), [])

    def assertThreeLineContext(self):
        text = Path(str(self.args) + ".in.diff").read_text()
        self.assertTrue(text.startswith("diff --git a/crates/a/src/lib.rs b/crates/a/src/lib.rs\n"),
                        text)
        hunks = re.findall(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@", text, re.M)
        self.assertTrue(hunks, text)
        for old, new in hunks:
            self.assertGreater(int(old or 1), 1, text)
            self.assertGreater(int(new or 1), 1, text)

    def test_in_diff_root_not_toplevel_fails(self):
        repo = self.in_diff_repo({"sub/coverage-tiers.toml": tiers_toml(["a"], "")})
        result, out = self.gate(repo, "--mutants", "a", "--in-diff", "base", root=repo / "sub")
        self.assertFails(result, out, "FAIL: --in-diff needs --root at the git toplevel")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_git_env_is_ignored(self):
        other = self.tmp / "other"
        write_tree(other, {"x.rs": "fn x() {}\n"})
        git(other, "init", "-q")
        git(other, "add", "-A")
        git(other, "commit", "-qm", "other")
        repo = self.in_diff_repo(EDIT_A)
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2], extra_env={
            "GIT_DIR": str(other / ".git"), "GIT_WORK_TREE": str(other),
            "GIT_INDEX_FILE": str(other / ".git/index"),
            "GIT_OBJECT_DIRECTORY": str(other / ".git/objects"),
            "GIT_COMMON_DIR": str(other / ".git"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(other / ".git/objects")})
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("RUN a: 2 in-diff mutants", out)

    def test_in_diff_scope_failure_stops_the_gate(self):
        repo = self.in_diff_repo(EDIT_A)
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2],
                                extra_env={"FAKE_METADATA_FAIL": "1"})
        self.assertFails(result, out, "FAIL: --in-diff: mutation scope", "cargo metadata failed")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_new_scope_file_runs_whole(self):
        names = ("a", "maknae-sys")
        repo = self.in_diff_repo({".config/nextest.toml": "[profile.mutants]\n"}, names=names)
        result, out = self.gate(repo, crates=names, whole=WHOLE_EDIT)
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("whole: a: mutation scope changed", out)
        self.assertIn("whole: maknae-sys: mutation scope changed", out)
        whole_a, whole_sys = self.invocations()
        self.assertEqual(whole_a[:3], ["mutants", "--package", "a"])
        self.assertEqual(whole_sys[:3], ["mutants", "--package", "maknae-sys"])
        self.assertNotIn("--in-diff", whole_sys)
        self.assertIn("--exclude-re", whole_sys)

    def test_in_diff_usage_errors(self):
        repo = self.in_diff_repo(EDIT_A)
        cases = {
            ("--mutants", "a", "--in-diff"): "--in-diff needs a revision",
            ("--mutants", "a", "--in-diff", "-x"): "--in-diff needs a revision",
            ("--in-diff", "--mutants", "a"): "--in-diff needs a revision",
            ("--mutants-all", "--in-diff", "base"): "--in-diff cannot be combined with --mutants-all",
            ("--in-diff", "base"): "--in-diff needs --mutants",
            ("--injection", "--mutants", "a", "--in-diff", "base"):
                "--in-diff cannot be combined with --injection",
        }
        for args, text in cases.items():
            with self.subTest(args):
                result, out = self.gate(repo, *args)
                self.assertFails(result, out, "FAIL: " + text)
                self.assertEqual(self.invocations(), [])

    def test_in_diff_scope_crate_not_selected_fails(self):
        repo = self.in_diff_repo({"coverage-tiers.toml": tiers_toml(["a", "b"], "")},
                                 base_crates=["a"])
        result, out = self.gate(repo, crates=("a",), whole=WHOLE_EDIT)
        self.assertFails(result, out, "FAIL: --in-diff: scope crate b not selected by --mutants")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_unknown_mutants_name_fails_on_an_empty_diff(self):
        repo = self.in_diff_repo({"README.md": "docs\n"})
        for crates in (("a", "zz"), ("a", "b", "zz")):
            with self.subTest(crates):
                result, out = self.gate(repo, crates=crates, whole=WHOLE_EDIT)
                self.assertFails(result, out, "FAIL: --in-diff: --mutants names zz, which is not "
                                 "in [t1].mutants_crates")
                self.assertEqual(self.invocations(), [])

    def test_in_diff_empty_stdout_is_empty_list(self):
        repo = self.in_diff_repo(EDIT_A)
        result, out = self.gate(repo, whole=WHOLE_EDIT[2:])
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("SKIP: a: no mutant on a changed line", out)
        self.assertIn("SKIP: b: no mutant on a changed line", out)
        self.assertEqual(self.runs(), [])
        self.assertEqual(len(self.invocations()), 4)

    def test_in_diff_fresh_tree_without_target_runs(self):
        repo = self.in_diff_repo(EDIT_A)
        self.assertFalse((repo / "target").exists())
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("mutants[a]:", out)

    def test_in_diff_rs_diff_attribute_still_classifies(self):
        attributes = {".gitattributes": "*.rs -diff\n"}
        for where in ("committed", "info", "attributesFile"):
            with self.subTest(where):
                shutil.rmtree(self.tmp / "repo", ignore_errors=True)
                repo = self.in_diff_repo(EDIT_A, base_files=attributes if where == "committed" else None)
                if where == "info":
                    (repo / ".git/info").mkdir(exist_ok=True)
                    (repo / ".git/info/attributes").write_text("*.rs -diff\n")
                elif where == "attributesFile":
                    (self.aux / "attributes").write_text("*.rs -diff\n")
                    git(repo, "config", "core.attributesFile", str(self.aux / "attributes"))
                result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
                self.assertEqual(result.returncode, 0, out)
                self.assertIn("RUN a: 2 in-diff mutants", out)
                result, out = self.gate(repo, whole=WHOLE_EDIT)
                self.assertFails(result, out, "FAIL: a: 2 listed mutants on changed lines in "
                                 "crates/a/src/lib.rs but the in-diff listing found none")
                self.assertNotIn("Binary files", Path(str(self.args) + ".in.diff").read_text())

    def test_in_diff_pathspec_env_is_ignored(self):
        repo = self.in_diff_repo(EDIT_A)
        for var in ("GIT_LITERAL_PATHSPECS", "GIT_NOGLOB_PATHSPECS", "GIT_GLOB_PATHSPECS",
                    "GIT_ICASE_PATHSPECS"):
            with self.subTest(var):
                result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2],
                                        extra_env={var: "1"})
                self.assertEqual(result.returncode, 0, out)
                self.assertIn("RUN a: 2 in-diff mutants", out)
                result, out = self.gate(repo, whole=WHOLE_EDIT, extra_env={var: "1"})
                self.assertFails(result, out, "the in-diff listing found none")

    def test_in_diff_changed_crate_not_selected_fails(self):
        repo = self.in_diff_repo({"crates/b/src/lib.rs": "pub fn b(x: u32) -> u32 {\n    x + 3\n}\n"})
        result, out = self.gate(repo, crates=("a",), whole=WHOLE_EDIT)
        self.assertFails(result, out, "FAIL: --in-diff: changed crate b not selected by --mutants")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_run_count_must_match_the_listing(self):
        repo = self.in_diff_repo(EDIT_A)
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertEqual(result.returncode, 0, out)
        payload = self.aux / "payload/outcomes.json"
        self.assertEqual(json.loads(payload.read_text())["total_mutants"], 2)
        fake = self.aux / "tools/cargo"
        original = fake.read_text()
        self.addCleanup(fake.write_text, original)
        fake.write_text(original.replace(
            'cp -R "$FAKE_PAYLOAD/." "$out/mutants.out/"\n',
            'cp -R "$FAKE_PAYLOAD/." "$out/mutants.out/"\n'
            'python3 -c "import json,sys; p=sys.argv[1]; d=json.load(open(p)); '
            'd[\'total_mutants\']+=1; d[\'caught\']+=1; json.dump(d, open(p, \'w\'))" '
            '"$out/mutants.out/outcomes.json"\n'))
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertFails(result, out, "mutation run for a cannot be trusted",
                         "total_mutants is 3 but the in-diff listing has 2")

    def test_in_diff_native_filter_reaches_both_listings(self):
        native = subprocess.run([BASH, str(ROOT / "ci/gates/mutation-platform.sh")],
                                capture_output=True, text=True, check=True).stdout.strip()
        fake_nextest(self.aux / "tools", "0.9.146")
        for crate in ("maknae-io", "maknae-sys"):
            with self.subTest(crate):
                shutil.rmtree(self.tmp / "repo", ignore_errors=True)
                repo = self.in_diff_repo(EDIT_A, names=(crate, "b"))
                listed_a = [dict(m, package=crate) for m in WHOLE_EDIT[2:3]]
                result, out = self.gate(repo, crates=(crate, "b"), whole=listed_a)
                self.assertEqual(result.returncode, 0, out)
                self.assertIn(f"SKIP: {crate}: no mutant on a changed line", out)
                lists = [argv for argv in self.invocations() if "--list" in argv and crate in argv]
                self.assertEqual(len(lists), 2, self.invocations())
                self.assertEqual(sum("--in-diff" in argv for argv in lists), 1)
                for argv in lists:
                    self.assertEqual(argv[argv.index("--exclude-re") + 1], native)

    def test_in_diff_replace_refs_fail(self):
        repo = self.in_diff_repo(EDIT_A)
        fake = git(repo, "commit-tree", git(repo, "rev-parse", "HEAD^{tree}"), "-m", "fake")
        git(repo, "replace", git(repo, "rev-parse", "base"), fake)
        self.assertEqual(git(repo, "diff", "base", "HEAD"), "")
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertFails(result, out, "FAIL: --in-diff: the repository has replace refs (refs/replace/")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_graft_file_env_is_ignored(self):
        repo = self.in_diff_repo(EDIT_A)
        grafts = self.aux / "grafts"
        grafts.write_text(f'{git(repo, "rev-parse", "base")} {git(repo, "rev-parse", "HEAD")}\n')
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2],
                                extra_env={"GIT_GRAFT_FILE": str(grafts)})
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("RUN a: 2 in-diff mutants", out)

    def cwds(self):
        log = Path(str(self.args) + ".cwd")
        return log.read_text().splitlines() if log.exists() else []

    def assertSnapshotOnly(self, repo):
        cwds = self.cwds()
        self.assertTrue(cwds)
        for cwd in cwds:
            self.assertEqual(Path(cwd).name, "snapshot", cwds)
            self.assertEqual(Path(cwd).parent.parent, (self.aux / "tmp").resolve(), cwds)
            self.assertNotEqual(Path(cwd), repo.resolve())

    def test_in_diff_lists_and_runs_from_a_snapshot_of_head(self):
        repo = self.in_diff_repo(EDIT_A)
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertEqual(result.returncode, 0, out)
        self.assertEqual(len(self.cwds()), 5, self.invocations())
        self.assertSnapshotOnly(repo)
        [run] = self.runs()
        self.assertEqual(run[run.index("--output") + 1], str(repo / "target/mutants-a"))
        self.assertFalse(list((self.aux / "tmp").iterdir()))

    def hidden_module_repo(self):
        base_lib = "pub mod decision;\n\n" + LIB_A
        decision = "pub fn decide(x: u32) -> bool {\n    x > 3\n}\n"
        repo = self.in_diff_repo({DECISION: decision.replace("x > 3", "x > 4")},
                                 base_files={A_RS: base_lib, DECISION: decision})
        return repo, base_lib

    def test_in_diff_index_flags_cannot_hide_a_module(self):
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag):
                shutil.rmtree(self.tmp / "repo", ignore_errors=True)
                repo, base_lib = self.hidden_module_repo()
                git(repo, "update-index", flag, A_RS)
                (repo / A_RS).write_text(base_lib.replace("pub mod decision;\n", ""))
                self.assertEqual(git(repo, "status", "--porcelain", "--untracked-files=all"), "")
                result, out = self.gate(repo, whole=WHOLE_DECISION, indiff=WHOLE_DECISION)
                self.assertEqual(result.returncode, 0, out)
                self.assertIn("RUN a: 1 in-diff mutants", out)
                self.assertEqual([run[2] for run in self.runs()], ["a"])
                self.assertSnapshotOnly(repo)
                result, out = self.gate(repo, whole=WHOLE_DECISION)
                self.assertFails(result, out, "FAIL: a: 1 listed mutants on changed lines in "
                                 f"{DECISION} but the in-diff listing found none")

    def test_in_diff_ignored_untracked_config_has_no_effect(self):
        repo = self.in_diff_repo(EDIT_A)
        (repo / ".git/info").mkdir(exist_ok=True)
        (repo / ".git/info/exclude").write_text(".cargo/\n")
        write_tree(repo, {".cargo/mutants.toml": f'exclude_globs = ["{A_RS}"]\n'})
        self.assertEqual(git(repo, "status", "--porcelain", "--untracked-files=all"), "")
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("RUN a: 2 in-diff mutants", out)
        self.assertSnapshotOnly(repo)

    def test_in_diff_hidden_working_tree_contract_fails(self):
        for rel in ("coverage-tiers.toml", "ci/gates/mutation-terminated.txt", "ci/affected.py"):
            with self.subTest(rel):
                shutil.rmtree(self.tmp / "repo", ignore_errors=True)
                repo = self.in_diff_repo(EDIT_A)
                git(repo, "update-index", "--assume-unchanged", rel)
                with (repo / rel).open("a") as f:
                    f.write("\n# local\n")
                result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
                self.assertFails(result, out, f"FAIL: --in-diff: {rel} in the working tree is not HEAD's")
                self.assertEqual(self.invocations(), [])

    def test_in_diff_include_str_data_runs_that_crate_whole(self):
        repo = self.in_diff_repo({"crates/a/src/prompt.txt": "be terse\n"},
                                 base_files={"crates/a/src/prompt.txt": "be brief\n"})
        self.assertEqual(git(repo, "diff", "--name-only", "base", "HEAD"), "crates/a/src/prompt.txt")
        result, out = self.gate(repo, whole=WHOLE_EDIT)
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("whole: a: mutation scope changed", out)
        self.assertIn("SKIP: b: no Rust change", out)
        [run] = self.invocations()
        self.assertEqual(run[:3], ["mutants", "--package", "a"])
        self.assertNotIn("--in-diff", run)
        self.assertSnapshotOnly(repo)

    def test_in_diff_build_helper_module_runs_that_crate_whole(self):
        build = "mod build_rule;\nfn main() {\n    build_rule::emit();\n}\n"
        rule = 'pub fn emit() {\n    println!("cargo:rustc-cfg=fast");\n}\n'
        repo = self.in_diff_repo({"crates/a/build_rule.rs": rule.replace("fast", "slow")},
                                 base_files={"crates/a/build.rs": build, "crates/a/build_rule.rs": rule})
        result, out = self.gate(repo, whole=WHOLE_EDIT)
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("whole: a: mutation scope changed", out)
        self.assertIn("SKIP: b: no mutant on a changed line", out)
        whole = [run for run in self.runs() if run[2] == "a"]
        self.assertEqual(len(whole), 1)
        self.assertNotIn("--in-diff", whole[0])

    def test_in_diff_unowned_input_runs_every_crate_whole(self):
        repo = self.in_diff_repo({"ci/gates/other.sh": "echo\n"})
        result, out = self.gate(repo, whole=WHOLE_EDIT)
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("whole: a: mutation scope changed", out)
        self.assertIn("whole: b: mutation scope changed", out)

    def test_in_diff_grafts_fail(self):
        repo = self.in_diff_repo(EDIT_A)
        (repo / ".git/info").mkdir(exist_ok=True)
        (repo / ".git/info/grafts").write_text(
            f'{git(repo, "rev-parse", "base")} {git(repo, "rev-parse", "HEAD")}\n')
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertFails(result, out, "FAIL: --in-diff: the repository has grafts")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_shallow_clone_fails(self):
        repo = self.in_diff_repo(EDIT_A)
        clone = self.tmp / "clone"
        git(self.tmp, "clone", "-q", "--depth", "1", "--no-local", f"file://{repo}", str(clone))
        git(clone, "tag", "base", "HEAD")
        self.assertEqual(git(clone, "rev-parse", "--is-shallow-repository"), "true")
        result, out = self.gate(clone, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertFails(result, out, "FAIL: --in-diff: the repository is shallow")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_lib_path_change_runs_that_crate_whole(self):
        repo = self.in_diff_repo(
            {"crates/a/Cargo.toml": package_toml("a")
             + '\n[features]\nextra = []\n\n[lib]\npath = "src/dormant.rs"\n'},
            base_files={"crates/a/src/dormant.rs": "pub fn a(x: u32) -> u32 {\n    x * 7\n}\n"})
        self.assertEqual(git(repo, "diff", "--name-only", "base", "HEAD"), "crates/a/Cargo.toml")
        result, out = self.gate(repo, whole=WHOLE_EDIT)
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("whole: a: mutation scope changed", out)
        self.assertNotIn("whole: b", out)
        [run] = self.invocations()
        self.assertEqual(run[:3], ["mutants", "--package", "a"])
        self.assertNotIn("--in-diff", run)

    def test_in_diff_symlinked_source_fails(self):
        real = "crates/a/src/real.rs"
        repo = self.in_diff_repo({real: GATE_RS.replace("10", "20")},
                                 base_files={A_RS: LIB_A + "pub mod alias;\n", real: GATE_RS},
                                 links={"crates/a/src/alias.rs": "real.rs"})
        alias = "crates/a/src/alias.rs"
        result, out = self.gate(repo, whole=[listed(f"{alias}:2:7: replace > with == in allowed",
                                                    "a", alias, 2)])
        self.assertFails(result, out, "FAIL: --in-diff: symlink crates/a/src/alias.rs in mutation "
                         "crate a; in-diff mapping cannot follow aliases — use the whole-package run")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_symlink_into_a_mutation_crate_fails(self):
        repo = self.in_diff_repo(EDIT_A, links={"alias": "crates/a/src"})
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertFails(result, out, "FAIL: --in-diff: symlink alias in mutation crate a;")
        self.assertEqual(self.invocations(), [])

    def test_in_diff_symlink_outside_every_mutation_crate_is_accepted(self):
        repo = self.in_diff_repo(EDIT_A, base_files={"AGENTS.md": "guidance\n"},
                                 links={"CLAUDE.md": "AGENTS.md"})
        result, out = self.gate(repo, whole=WHOLE_EDIT, indiff=WHOLE_EDIT[:2])
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("RUN a: 2 in-diff mutants", out)

    def test_in_diff_build_script_inside_src_fails(self):
        helper = "crates/a/src/helper.rs"
        for script in ("src/build.rs", "tests/build.rs", "benches/build.rs", "examples/build.rs"):
            with self.subTest(script=script):
                shutil.rmtree(self.tmp / "repo", ignore_errors=True)
                manifest = package_toml("a") + f'build = "{script}"\n\n[features]\nextra = []\n'
                repo = self.in_diff_repo({helper: BUILD_HELPER.replace("fast", "slow")},
                                         base_files={"crates/a/Cargo.toml": manifest,
                                                     f"crates/a/{script}": BUILD_MAIN,
                                                     helper: BUILD_HELPER})
                result, out = self.gate(repo, whole=WHOLE_EDIT)
                self.assertFails(result, out, f"FAIL: --in-diff: build script crates/a/{script} of "
                                 "mutation crate a lies inside a diff-mapped directory — use the "
                                 "whole-package run")
                self.assertEqual(self.invocations(), [])

    def test_in_diff_root_build_script_helper_runs_that_crate_whole(self):
        cases = {"crates/a/helper.rs": BUILD_MAIN,
                 "crates/a/src/helper.rs": BUILD_MAIN.replace("mod helper;", "mod src {\n    pub mod helper;\n}")
                 .replace("helper::emit", "src::helper::emit")}
        for helper, script in cases.items():
            with self.subTest(helper=helper):
                shutil.rmtree(self.tmp / "repo", ignore_errors=True)
                repo = self.in_diff_repo({helper: BUILD_HELPER.replace("fast", "slow")},
                                         base_files={"crates/a/build.rs": script, helper: BUILD_HELPER})
                result, out = self.gate(repo, whole=WHOLE_EDIT)
                self.assertEqual(result.returncode, 0, out)
                self.assertIn("whole: a: mutation scope changed", out)
                whole = [run for run in self.runs() if run[2] == "a"]
                self.assertEqual(len(whole), 1)
                self.assertNotIn("--in-diff", whole[0])

def git(repo, *args, input=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=fixture", "-c",
                           "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                           "-c", "tag.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                          env=env, check=True, capture_output=True, text=True,
                          input=input).stdout.strip()


def write_tree(root, files):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def package_toml(name):
    return f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2021"\n'


def tiers_toml(crates, features):
    return f"[t1]\nmutants_crates = {json.dumps(list(crates))}\n{features}"


def listed(name, package, file, start, end=None):
    return {"name": name, "package": package, "file": file,
            "span": {"start": {"line": start, "column": 5},
                     "end": {"line": start if end is None else end, "column": 6}}}


LIB_A = ("pub fn a(x: u32) -> u32 {\n"
         "    let y = x + 1;\n"
         "    let z = y * 2;\n"
         "    z - 3\n"
         "}\n"
         "\n"
         "pub fn d(x: u32) -> u32 {\n"
         "    x * 5\n"
         "}\n"
         "\n"
         "#[cfg(test)]\n"
         "mod tests {\n"
         "    #[test]\n"
         "    fn t() {\n"
         "        assert_eq!(super::a(1), 1);\n"
         "    }\n"
         "}\n")
A_RS = "crates/a/src/lib.rs"
EDIT_A = {A_RS: LIB_A.replace("y * 2", "y * 4")}
DELETE_A = {A_RS: LIB_A.replace("    let z = y * 2;\n", "")}
MIXED_A = {A_RS: DELETE_A[A_RS].replace("x * 5", "x * 6")}
TEST_MOD_A = {A_RS: LIB_A.replace("super::a(1), 1", "super::a(1), 2")}
WHOLE_EDIT = [listed(f"{A_RS}:2:5: replace a -> u32 with 0", "a", A_RS, 2, 4),
              listed(f"{A_RS}:3:15: replace * with + in a", "a", A_RS, 3),
              listed(f"{A_RS}:8:5: replace d -> u32 with 0", "a", A_RS, 8),
              listed("crates/b/src/lib.rs:2:5: replace b -> u32 with 0", "b", "crates/b/src/lib.rs", 2)]
GATE_RS = "pub fn allowed(x: u32) -> bool {\n    x > 10\n}\n"
BUILD_MAIN = "mod helper;\nfn main() {\n    helper::emit();\n}\n"
BUILD_HELPER = 'pub fn emit() {\n    println!("cargo:rustc-cfg=fast");\n}\n'
DECISION = "crates/a/src/decision.rs"
WHOLE_DECISION = [listed(f"{DECISION}:2:7: replace > with == in decide", "a", DECISION, 2)]
WHOLE_DELETE = [listed(f"{A_RS}:2:5: replace a -> u32 with 0", "a", A_RS, 2, 3),
                listed(f"{A_RS}:7:5: replace d -> u32 with 0", "a", A_RS, 7)]

Run = collections.namedtuple("Run", "result argv env tmpdir litter leftover root")
MISSING = object()
BASH = shutil.which("bash")
AMBIENT = {"NEXTEST_PROFILE": "default", "NEXTEST_STATUS_LEVEL": "all",
           "NEXTEST_HIDE_PROGRESS_BAR": "1", "CLICOLOR_FORCE": "1", "CARGO_TERM_COLOR": "always"}
PINNED = ["NEXTEST_PROFILE=mutants", "CARGO_TERM_COLOR=never", "NEXTEST_RETRIES=0",
          "NEXTEST_STATUS_LEVEL=fail", "NEXTEST_FINAL_STATUS_LEVEL=fail"]
PAGE = "crates/maknae-io/src/page.rs"
MUTANT_PREFIX = PAGE + ":9:9: replace "
FAIL_LINE = "        FAIL [   5.011s] (169/247) maknae-io page::tests::c"
TIMEOUT_LINE = "     TIMEOUT [  20.003s] (172/247) maknae-io page::tests::a"


def mutant(suffix, test_lines, *, summary=True, header=True, log=True):
    cargo = "/toolchain/bin/cargo nextest run"
    text = (f"\n*** {MUTANT_PREFIX}{suffix}\n\n*** mutation diff:\n-a\n+b\n\n"
            f"*** {cargo} --no-run --verbose --package=maknae-io@0.0.0\n\n*** result: Success\n\n")
    if header:
        text += f"*** {cargo} --verbose --package=maknae-io@0.0.0\n"
    text += test_lines + "\n"
    if summary is True:
        clean = re.sub(r"\x1b\[[0-9;]*m", "", test_lines)
        failed = len(re.findall(r"(?m)^\s*(?:TRY \d+ )?(?:FAIL|SIG[A-Z]+|ABORT)\b", clean))
        timed_out = len(re.findall(r"(?m)^\s*(?:TRY \d+ )?TIMEOUT\b", clean))
        summary = summary_line(failed, timed_out)
    if summary:
        text += "────────────\n" + summary + "\n"
    shape = re.fullmatch(r"\S+ with (\S+) in (\w+)", suffix)
    return {"name": MUTANT_PREFIX + suffix, "file": PAGE,
            "function": {"function_name": shape[2] if shape else suffix},
            "replacement": shape[1] if shape else "", "text": text + "*** result: Failure(100)\n" if log else None}


def summary_line(failed, timed_out):
    parts = [f"{247 - failed - timed_out} passed", f"{failed} failed"]
    if timed_out:
        parts.append(f"{timed_out} timed out")
    return f"     Summary [   5.012s] 247 tests run: {', '.join(parts)}, 0 skipped"


def entry(system, *, file=None, fn="grow_page", regex="\\*="):
    return f"{system}\t{PAGE if file is None else file}\t{fn}\t{regex}\tfixture\n"


LIST_FILTER = """import fnmatch, json, os, re, sys, tomllib


def discovered(mutant):
    file = mutant["file"]
    if not os.path.isfile(file):
        return False
    crate, sep, name = file.rpartition("/src/")
    if not sep or name == "lib.rs" or "/" in name:
        return True
    try:
        with open(os.path.join(crate, "src/lib.rs")) as f:
            lib = f.read()
    except OSError:
        return False
    return re.search(r"\\bmod " + re.escape(name[:-3]) + r"\\s*;", lib) is not None


try:
    with open(".cargo/mutants.toml", "rb") as f:
        globs = tomllib.load(f).get("exclude_globs", [])
except OSError:
    globs = []
print(json.dumps([m for m in json.load(sys.stdin) if m["package"] == sys.argv[1] and discovered(m)
                  and not any(fnmatch.fnmatch(m["file"], g) for g in globs)]))
"""


def fake_cargo(tools):
    recorder = tools / "cargo"
    recorder.write_text(
        '#!/bin/sh\n'
        'if [ "$1" != mutants ]; then\n'
        # mutation-diff.py's `scope` is the only caller that spells `metadata --no-deps` first.
        '  [ "$1 $2 ${FAKE_METADATA_FAIL-}" = "metadata --no-deps 1" ] && exit 1\n'
        '  exec "$REAL_CARGO" "$@"\n'
        'fi\n'
        '{ printf "%s\\t" "$@"; echo; } >> "$MUTATION_ARGS.log"\n'
        'pwd -P >> "$MUTATION_ARGS.cwd"\n'
        'pkg= indiff= list=0\n'
        'for a in "$@"; do\n'
        '  case "$prev" in --package) pkg="$a";; --in-diff) indiff="$a";; esac\n'
        '  [ "$a" = --list ] && list=1\n'
        '  prev="$a"\n'
        'done\n'
        'if [ "$list" = 1 ]; then\n'
        '  if [ -n "$indiff" ]; then cp "$indiff" "$MUTATION_ARGS.in.diff"; json="${FAKE_INDIFF_LIST-}"\n'
        '  else json="${FAKE_WHOLE_LIST-}"; fi\n'
        '  [ -n "$json" ] && printf "%s" "$json" | python3 "$(dirname "$0")/list_filter.py" "$pkg"\n'
        '  exit "${FAKE_LIST_EXIT:-0}"\n'
        'fi\n'
        'env | grep -E "^(NEXTEST_[A-Z_]*|CLICOLOR_FORCE|CARGO_TERM_COLOR)=" | sort > "$MUTATION_ARGS.env"\n'
        'printf "%s\\n" "${TMPDIR-}" > "$MUTATION_ARGS.tmpdir"\n'
        'printf "%s\\n" "$@" > "$MUTATION_ARGS"\n'
        'out=.\n'
        'while [ $# -gt 0 ]; do\n'
        '  [ "$1" = "--output" ] && { out="$2"; break; }\n'
        '  shift\n'
        'done\n'
        '[ -d "$(dirname "$out")" ] || { echo "Error: create output directory $out: No such file or directory" >&2; exit 1; }\n'
        'mkdir -p "$out/mutants.out"\n'
        'cp -R "$FAKE_PAYLOAD/." "$out/mutants.out/"\n'
        'if [ "$FAKE_LITTER" = 1 ]; then\n'
        '  mkdir -p "$TMPDIR/.tmpKILLED/inner" && touch "$TMPDIR/.tmpKILLED/inner/f" "$TMPDIR/stray"\n'
        '  chmod 000 "$TMPDIR/.tmpKILLED/inner" "$TMPDIR/.tmpKILLED"\n'
        '  echo littered > "$MUTATION_ARGS.litter"\n'
        'fi\n'
        'if [ "$FAKE_SLEEP" = 1 ]; then echo $$ > "$MUTATION_ARGS.pid"; exec sleep 60; fi\n'
        'exit "$FAKE_EXIT"\n'
    )
    recorder.chmod(0o755)
    (tools / "list_filter.py").write_text(LIST_FILTER)
    (tools / "cargo-mutants").symlink_to(recorder)


def fake_nextest(directory, version):
    tool = directory / "cargo-nextest"
    tool.write_text(f"#!/bin/sh\nprintf 'cargo-nextest {version} (fixture)\\nrelease: {version}\\n'\n")
    tool.chmod(0o755)


def write_payload(payload, logs, total, planned_extra=0, phase="Test", plan=True, baseline=None,
                  missed=0):
    (payload / "log").mkdir(parents=True)
    (payload / "log" / "baseline.log").write_text(
        "\n*** baseline\n\n*** /toolchain/bin/cargo nextest run --verbose\n"
        + (baseline or "     Summary [   3.5s] 247 tests run: 247 passed, 2 skipped") + "\n")
    tested = [{"phase": "Build", "process_status": "Success"},
              {"phase": phase, "process_status": {"Failure": 100}}]
    outcomes = [{"scenario": "Baseline", "summary": "Success", "log_path": "log/baseline.log",
                 "phase_results": tested}]
    planned = []
    for index, m in enumerate(logs):
        log = f"log/mutant_{index:03}.log"
        if m["text"] is not None:
            (payload / log).write_text(m["text"])
        scenario = {k: v for k, v in m.items() if k != "text"}
        planned.append(scenario)
        outcomes.append({"scenario": {"Mutant": scenario}, "summary": "CaughtMutant",
                         "log_path": log, "phase_results": tested})
    planned += [{"name": f"{PAGE}:1:1: replace never_run -> u8 with {n}"} for n in range(planned_extra)]
    if plan:
        (payload / "mutants.json").write_text(json.dumps(planned))
    count = len(logs) if total is None else total
    (payload / "outcomes.json").write_text(json.dumps({
        "outcomes": outcomes, "total_mutants": count, "caught": count - missed,
        "missed": missed, "timeout": 0, "unviable": 0}))


TERMINATED = mutant("+= with *= in grow_page", TIMEOUT_LINE)
TERMINATED_SIGTERM = mutant("+= with *= in grow_page",
                            TIMEOUT_LINE + "\n     SIGTERM [   0.004s] (173/247) maknae-io page::tests::b")
COLOURED = mutant("+= with *= in grow_page",
                  "\x1b[1;35m     TIMEOUT\x1b[0m [  20.003s] (172/247) maknae-io page::tests::a")
RETRIED = mutant("+= with *= in grow_page", "  TRY 2 TIMEOUT [  20.003s] (172/247) maknae-io page::tests::a")
SIGABRT_AND_TIMEOUT = mutant("+= with /= in grow_page",
                             "     SIGABRT [   0.410s] (2/3) maknae-io page::tests::d\n" + TIMEOUT_LINE)
TERMINATED_SHRINK = mutant("+= with *= in shrink_page", TIMEOUT_LINE)
CAPTURED = mutant("+= with *= in grow_page",
                  TIMEOUT_LINE + "\n  stdout ───\n    FAIL [   0.001s] printed by a test")
TIMEOUT_AND_FAIL = mutant("+= with -= in grow_page", FAIL_LINE + "\n" + TIMEOUT_LINE)
CAUGHT_LOGS = [mutant(f"+= with -= in grow_{n}", FAIL_LINE) for n in range(3)]
REVIEWED_HEADER = "# platform\tfile\tfunction\treplacement-regex\treason\n"


if __name__ == "__main__":
    unittest.main()
