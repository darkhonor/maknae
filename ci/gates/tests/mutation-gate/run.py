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
        recorder = tools / "cargo"
        recorder.write_text(
            '#!/bin/sh\n'
            '[ "$1" = mutants ] || exec "$REAL_CARGO" "$@"\n'
            'env | grep -E "^(NEXTEST_[A-Z_]*|CLICOLOR_FORCE|CARGO_TERM_COLOR)=" | sort > "$MUTATION_ARGS.env"\n'
            'printf "%s\\n" "${TMPDIR-}" > "$MUTATION_ARGS.tmpdir"\n'
            'printf "%s\\n" "$@" > "$MUTATION_ARGS"\n'
            'out=.\n'
            'while [ $# -gt 0 ]; do\n'
            '  [ "$1" = "--output" ] && { out="$2"; break; }\n'
            '  shift\n'
            'done\n'
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
        (tools / "cargo-mutants").symlink_to(recorder)
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


def fake_nextest(directory, version):
    tool = directory / "cargo-nextest"
    tool.write_text(f"#!/bin/sh\nprintf 'cargo-nextest {version} (fixture)\\nrelease: {version}\\n'\n")
    tool.chmod(0o755)


def write_payload(payload, logs, total, planned_extra=0, phase="Test", plan=True, baseline=None):
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
        "outcomes": outcomes, "total_mutants": count, "caught": count,
        "missed": 0, "timeout": 0, "unviable": 0}))


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
