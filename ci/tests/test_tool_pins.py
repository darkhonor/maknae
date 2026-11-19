"""Each pinned tool version has one owner, and every copy agrees with it (#641).

Copies, in any tracked file:
- a workflow or composite-action `env` entry named in ENV_KEYS;
- an assignment of an ENV_KEYS name: `KEY=value`, or a Dockerfile `ENV KEY value`;
- the version in a cargo install command for an owned tool: `--version v`, `--vers v`, `tool@v`.
An install of an owned tool must carry a version this test can read; one it
cannot read is a disagreement. The version may name the tool's own ENV_KEYS
variable (`$KEY`, `${KEY}`, `${{ env.KEY }}`) only in a workflow or composite
action, where that env entry is itself checked, or in a file that assigns KEY.
"""

import functools
import pathlib
import re
import subprocess
import tomllib
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
WORKFLOWS = ".github/workflows/"
ACTIONS = ".github/actions/"
CONFORMANCE = "ci/gates/tests/mutation-diff/conformance.py"
CARGO_INSTALL = "cargo" + " install"
AUDITABLE_IS = "CARGO_AUDITABLE_VERSION" + "="

ENV_KEYS = {
    "CARGO_DENY_VERSION": "cargo-deny",
    "CARGO_AUDITABLE_VERSION": "cargo-auditable",
    "RUST_AUDIT_INFO_VERSION": "rust-audit-info",
    "CARGO_LLVM_COV_VERSION": "cargo-llvm-cov",
    "CARGO_MUTANTS_VERSION": "cargo-mutants",
    "NEXTEST_VERSION": "cargo-nextest",
}
KEY_OF = {tool: key for key, tool in ENV_KEYS.items()}
INSTALL = re.compile(r"\bcargo(?:\s+\+\S+)?\s+install\b(.*)")
VERSION_FLAG = re.compile(r"--vers(?:ion)?(?:\s+|=)[\"']?([^\s\"']+)")
ASSIGN = re.compile(r"\b(" + "|".join(ENV_KEYS) + r")=[\"']?([^\s\"']*)")
ENV_SPACE = re.compile(r"^\s*ENV\s+(" + "|".join(ENV_KEYS) + r")\s+[\"']?([^\s\"'=]*)")
ENV_EXPRESSION = re.compile(r"\$\{\{\s*env\.(\w+)\s*\}\}")
UNREAD = "no version this test can read"


def nextest_pin(text):
    pin = tomllib.loads(text)["nextest-version"]
    return pin["required"] if isinstance(pin, dict) else pin


def owners(files):
    ci = yaml.safe_load(files[f"{WORKFLOWS}ci.yml"])["env"]
    mutation = yaml.safe_load(files[f"{WORKFLOWS}mutation.yml"])["jobs"]["mutation"]["env"]
    return {
        "cargo-deny": ci["CARGO_DENY_VERSION"],
        "cargo-auditable": ci["CARGO_AUDITABLE_VERSION"],
        "rust-audit-info": ci["RUST_AUDIT_INFO_VERSION"],
        "cargo-llvm-cov": ci["CARGO_LLVM_COV_VERSION"],
        "cargo-mutants": mutation["CARGO_MUTANTS_VERSION"],
        "cargo-nextest": nextest_pin(files[".config/nextest.toml"]),
    }


def is_yaml(path):
    return path.startswith((WORKFLOWS, ACTIONS)) and path.endswith((".yml", ".yaml"))


def env_blocks(doc):
    yield doc.get("env")
    for job in (doc.get("jobs") or {}).values():
        job = job or {}
        yield job.get("env")
        container = job.get("container")
        if isinstance(container, dict):
            yield container.get("env")
        for service in (job.get("services") or {}).values():
            yield (service or {}).get("env")
        for step in job.get("steps") or []:
            yield (step or {}).get("env")
    for step in (doc.get("runs") or {}).get("steps") or []:
        yield (step or {}).get("env")


def yaml_copies(path, text):
    for env in env_blocks(yaml.safe_load(text) or {}):
        for key, value in (env or {}).items():
            if key in ENV_KEYS:
                yield ENV_KEYS[key], str(value), f"{path}: {key}"


def logical_lines(text):
    number = 1
    for line in re.sub(r"\\\n", " \x00", text.replace("\r\n", "\n")).split("\n"):
        yield number, line.replace("\x00", "")
        number += 1 + line.count("\x00")


def install_versions(args):
    flag = VERSION_FLAG.search(args)
    words = [word.strip("\"'") for word in args.split()]
    for tool in ENV_KEYS.values():
        for word in words:
            if word == tool:
                yield tool, flag.group(1) if flag else UNREAD
            elif word.startswith(f"{tool}@"):
                yield tool, word.split("@", 1)[1]


def assignments(line):
    yield from ASSIGN.findall(line)
    yield from ENV_SPACE.findall(line)


def text_copies(path, text):
    lines = list(logical_lines(text))
    assigned = {key for _, line in lines for key, _ in assignments(line)}
    for number, line in lines:
        if is_yaml(path):
            line = ENV_EXPRESSION.sub(r"$\1", line)
        for command in re.split(r"&&|\|\||;|\||`", line):
            install = INSTALL.search(command)
            if install:
                for tool, version in install_versions(install.group(1)):
                    key = KEY_OF[tool]
                    if version in (f"${key}", f"${{{key}}}") and (is_yaml(path) or key in assigned):
                        continue
                    yield tool, version, f"{path}:{number}: {CARGO_INSTALL} {tool}"
        for key, value in assignments(line):
            yield ENV_KEYS[key], value, f"{path}:{number}: {key}="


def conformance_copies(text):
    found = re.search(r'^VERSION = "cargo-mutants ([^"]+)"$', text, re.MULTILINE)
    yield "cargo-mutants", found.group(1) if found else None, f"{CONFORMANCE}: VERSION"


@functools.cache
def copies(path, text):
    found = list(text_copies(path, text))
    if is_yaml(path):
        found += yaml_copies(path, text)
    if path == CONFORMANCE:
        found += conformance_copies(text)
    return tuple(found)


def steps_with_env(doc):
    for job_id, job in (doc.get("jobs") or {}).items():
        job = job or {}
        outer = set(doc.get("env") or {}) | set(job.get("env") or {})
        for index, step in enumerate(job.get("steps") or []):
            yield f"jobs.{job_id}.steps[{index}]", step or {}, outer | set((step or {}).get("env") or {})
    for index, step in enumerate((doc.get("runs") or {}).get("steps") or []):
        yield f"runs.steps[{index}]", step or {}, set((step or {}).get("env") or {})


def owner_references(text):
    for _, line in logical_lines(ENV_EXPRESSION.sub(r"$\1", text)):
        for command in re.split(r"&&|\|\||;|\||`", line):
            install = INSTALL.search(command)
            if install:
                for tool, version in install_versions(install.group(1)):
                    if version in (f"${KEY_OF[tool]}", f"${{{KEY_OF[tool]}}}"):
                        yield tool


@functools.cache
def binding_problems(path, text):
    if not is_yaml(path):
        return ()
    found = []
    for where, step, env in steps_with_env(yaml.safe_load(text) or {}):
        for tool in owner_references(str(step.get("run") or "")):
            if KEY_OF[tool] not in env:
                found.append(f"{path}: {where} installs {tool} from {KEY_OF[tool]}, which its step does not set")
        if not str(step.get("uses") or "").startswith("actions/cache@"):
            continue
        key = str((step.get("with") or {}).get("key") or "")
        for entry in str((step.get("with") or {}).get("path") or "").split():
            tool = entry.rsplit("/", 1)[-1]
            if tool not in KEY_OF:
                continue
            if not re.search(r"\benv\." + KEY_OF[tool] + r"\b", key):
                found.append(f"{path}: {where} caches {tool} under a key without env.{KEY_OF[tool]}")
            elif KEY_OF[tool] not in env:
                found.append(f"{path}: {where} caches {tool} under {KEY_OF[tool]}, which its step does not set")
    return tuple(found)


def disagreements(files):
    pins = owners(files)
    found = [f"{where} is {version}, but the pin is {pins[tool]}"
             for path, text in sorted(files.items())
             for tool, version, where in copies(path, text)
             if version != pins[tool]]
    return found + [problem for path, text in sorted(files.items()) for problem in binding_problems(path, text)]


def tracked_files():
    names = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], check=True,
                           capture_output=True).stdout.decode().split("\0")
    files = {}
    for name in filter(None, names):
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            continue
        try:
            files[name] = path.read_text()
        except UnicodeDecodeError:
            continue
    files[str(pathlib.Path(__file__).resolve().relative_to(ROOT))] = pathlib.Path(__file__).read_text()
    return files


class ToolPins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = tracked_files()
        cls.pins = owners(cls.files)

    def with_file(self, path, text):
        return disagreements({**self.files, path: text})

    def assertOneDisagreement(self, path, text, where):
        found = self.with_file(path, text)
        self.assertEqual(len(found), 1, found)
        self.assertIn(where, found[0])

    def test_repository_copies_agree_with_their_owners(self):
        self.assertEqual(disagreements(self.files), [])

    def test_every_owned_tool_has_a_checked_copy(self):
        tools = {tool for path, text in self.files.items() for tool, _, _ in copies(path, text)}
        self.assertEqual(tools, set(ENV_KEYS.values()))

    def test_install_command_forms_on_another_version_fail(self):
        for line in (f"RUN {CARGO_INSTALL} cargo-auditable --locked --version 0.0.1",
                     f"RUN {CARGO_INSTALL} cargo-auditable --version=0.0.1",
                     f"RUN {CARGO_INSTALL} cargo-auditable@0.0.1 --locked",
                     f"RUN cargo +stable {CARGO_INSTALL[6:]} cargo-auditable --version 0.0.1",
                     f"RUN {CARGO_INSTALL} cargo-auditable \\\n  --version 0.0.1",
                     f"RUN true && {CARGO_INSTALL} cargo-auditable --version '0.0.1'",
                     f"RUN {CARGO_INSTALL} cargo-auditable --version $OTHER_VERSION",
                     f"RUN {CARGO_INSTALL} cargo-auditable --vers 0.0.1",
                     f"RUN {CARGO_INSTALL} cargo-auditable \\\r\n  --version 0.0.1",
                     f"RUN {CARGO_INSTALL} cargo-auditable --locked",
                     f"RUN {CARGO_INSTALL} cargo-auditable --version $CARGO_AUDITABLE_VERSION"):
            with self.subTest(line=line):
                self.assertOneDisagreement("packaging/oci/Dockerfile.x", line + "\n",
                                           f"packaging/oci/Dockerfile.x:1: {CARGO_INSTALL} cargo-auditable")

    def test_install_command_forms_on_the_pinned_version_pass(self):
        pin = self.pins["cargo-auditable"]
        for line in (f"RUN {CARGO_INSTALL} cargo-auditable --locked --version {pin}",
                     f"RUN {CARGO_INSTALL} cargo-auditable --version={pin}",
                     f"RUN {CARGO_INSTALL} cargo-auditable --vers {pin}",
                     f"RUN {CARGO_INSTALL} cargo-auditable@{pin} --locked",
                     f"RUN {CARGO_INSTALL} cargo-auditable \\\n  --version {pin}",
                     f"RUN {CARGO_INSTALL} cargo-auditable \\\r\n  --version {pin}"):
            with self.subTest(line=line):
                self.assertEqual(self.with_file("packaging/oci/Dockerfile.x", line + "\n"), [])

    def test_chained_installs_are_judged_separately(self):
        line = f"{CARGO_INSTALL} cargo-deny --version 0.0.1 && {CARGO_INSTALL} cargo-auditable@{self.pins['cargo-auditable']}\n"
        found = self.with_file("x.sh", line)
        self.assertEqual(found, [f"x.sh:1: {CARGO_INSTALL} cargo-deny is 0.0.1, "
                                 f"but the pin is {self.pins['cargo-deny']}"])

    def test_an_assignment_on_another_version_fails(self):
        self.assertOneDisagreement("packaging/oci/Dockerfile.x",
                                   f"ARG {AUDITABLE_IS}0.0.1\n"
                                   f"RUN {CARGO_INSTALL} cargo-auditable --version ${{CARGO_AUDITABLE_VERSION}}\n",
                                   f"packaging/oci/Dockerfile.x:1: {AUDITABLE_IS} is 0.0.1")

    def test_a_command_that_reads_the_owner_is_not_a_copy(self):
        auditable = self.pins["cargo-auditable"]
        for path, text in ((f"{WORKFLOWS}x.yml", f'run: {CARGO_INSTALL} cargo-deny --version "$CARGO_DENY_VERSION"\n'),
                           (f"{WORKFLOWS}x.yml", f"run: {CARGO_INSTALL} cargo-deny --version ${{{{ env.CARGO_DENY_VERSION }}}}\n"),
                           ("x.sh", f"{AUDITABLE_IS}{auditable}\n{CARGO_INSTALL} cargo-auditable --version \"$CARGO_AUDITABLE_VERSION\"\n"),
                           ("Dockerfile.x", f"ARG {AUDITABLE_IS}{auditable}\n"
                                            f"RUN {CARGO_INSTALL} cargo-auditable --version ${{CARGO_AUDITABLE_VERSION}}\n")):
            with self.subTest(path=path, text=text):
                self.assertEqual(self.with_file(path, text), [])

    def test_a_folded_install_whose_version_is_on_another_line_fails(self):
        doc = f"run: >-\n  {CARGO_INSTALL} cargo-deny\n  --version 0.0.1\n"
        self.assertOneDisagreement(f"{WORKFLOWS}x.yml", doc, f"{CARGO_INSTALL} cargo-deny is {UNREAD}")

    def test_a_dockerfile_env_on_another_version_fails(self):
        self.assertOneDisagreement("Dockerfile.x", "EN" + "V CARGO_DENY_VERSION 0.0.1\n",
                                   "Dockerfile.x:1: CARGO_DENY_VERSION" + "= is 0.0.1")

    def test_a_release_job_on_another_audit_info_version_fails(self):
        doc = yaml.safe_load(self.files[f"{WORKFLOWS}release.yml"])
        doc["jobs"]["macos-package"]["env"]["RUST_AUDIT_INFO_VERSION"] = "0.0.1"
        found = self.with_file(f"{WORKFLOWS}release.yml", yaml.safe_dump(doc))
        self.assertEqual(found, [f"{WORKFLOWS}release.yml: RUST_AUDIT_INFO_VERSION is 0.0.1, "
                                 f"but the pin is {self.pins['rust-audit-info']}"])

    def test_a_quoted_tool_name_is_still_a_copy(self):
        self.assertOneDisagreement("x.sh", f'{CARGO_INSTALL} "cargo-mutants" --version 0.0.1 --locked\n',
                                   f"x.sh:1: {CARGO_INSTALL} cargo-mutants is 0.0.1")

    def test_a_workflow_install_must_read_a_variable_its_step_sets(self):
        doc = {"jobs": {"j": {"steps": [{"run": f'{CARGO_INSTALL} cargo-mutants --version "$CARGO_MUTANTS_VERSION"'}]}}}
        path = f"{WORKFLOWS}x.yml"
        self.assertEqual(self.with_file(path, yaml.safe_dump(doc)),
                         [f"{path}: jobs.j.steps[0] installs cargo-mutants from CARGO_MUTANTS_VERSION, "
                          "which its step does not set"])
        doc["jobs"]["j"]["env"] = {"CARGO_MUTANTS_VERSION": self.pins["cargo-mutants"]}
        self.assertEqual(self.with_file(path, yaml.safe_dump(doc)), [])

    def test_a_tool_cache_must_be_keyed_by_that_tools_pin(self):
        text = self.files[f"{WORKFLOWS}mutation.yml"]
        moved = text.replace("${{ env.CARGO_MUTANTS_VERSION }}", "${{ env.CARGO_DENY_VERSION }}")
        self.assertNotEqual(moved, text)
        found = self.with_file(f"{WORKFLOWS}mutation.yml", moved)
        self.assertEqual(found, [f"{WORKFLOWS}mutation.yml: jobs.mutation.steps[4] caches cargo-mutants "
                                 "under a key without env.CARGO_MUTANTS_VERSION"])

    def test_a_tool_cache_key_must_read_a_variable_its_step_sets(self):
        step = {"uses": "actions/cache@x", "with": {"path": "~/.cargo/bin/cargo-deny",
                                                     "key": "k-${{ env.CARGO_DENY_VERSION }}"}}
        path = f"{WORKFLOWS}x.yml"
        self.assertEqual(self.with_file(path, yaml.safe_dump({"jobs": {"j": {"steps": [step]}}})),
                         [f"{path}: jobs.j.steps[0] caches cargo-deny under CARGO_DENY_VERSION, "
                          "which its step does not set"])
        doc = {"env": {"CARGO_DENY_VERSION": self.pins["cargo-deny"]}, "jobs": {"j": {"steps": [step]}}}
        self.assertEqual(self.with_file(path, yaml.safe_dump(doc)), [])

    def test_container_service_and_action_env_on_another_version_fail(self):
        for path, doc in ((f"{WORKFLOWS}x.yml", {"jobs": {"j": {"container": {"env": {"CARGO_DENY_VERSION": "0.0.1"}}}}}),
                          (f"{WORKFLOWS}x.yaml", {"jobs": {"j": {"services": {"s": {"env": {"CARGO_DENY_VERSION": "0.0.1"}}}}}}),
                          (f"{ACTIONS}x/action.yml", {"runs": {"steps": [{"env": {"CARGO_DENY_VERSION": "0.0.1"}}]}})):
            with self.subTest(path=path):
                self.assertOneDisagreement(path, yaml.safe_dump(doc), f"{path}: CARGO_DENY_VERSION is 0.0.1")

    def test_a_nextest_download_on_another_version_fails(self):
        text = self.files[f"{WORKFLOWS}mutation.yml"]
        pin = self.pins["cargo-nextest"]
        found = self.with_file(f"{WORKFLOWS}mutation.yml",
                               text.replace(f'NEXTEST_VERSION: "{pin}"', 'NEXTEST_VERSION: "0.0.1"'))
        self.assertEqual(found, [f"{WORKFLOWS}mutation.yml: NEXTEST_VERSION is 0.0.1, but the pin is {pin}"])

    def test_moving_the_nextest_owner_alone_fails(self):
        for owner in ('nextest-version = { required = "0.0.1" }\n', 'nextest-version = "0.0.1"\n'):
            with self.subTest(owner=owner):
                found = self.with_file(".config/nextest.toml", owner)
                self.assertIn(f"{WORKFLOWS}mutation.yml: NEXTEST_VERSION is {self.pins['cargo-nextest']}, "
                              "but the pin is 0.0.1", found)

    def test_a_conformance_check_on_another_mutants_version_fails(self):
        text = re.sub(r'^VERSION = .*$', 'VERSION = "cargo-mutants 0.0.1"', self.files[CONFORMANCE],
                      flags=re.MULTILINE)
        self.assertOneDisagreement(CONFORMANCE, text, f"{CONFORMANCE}: VERSION is 0.0.1")


if __name__ == "__main__":
    unittest.main()
