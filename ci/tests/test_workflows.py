"""Required status checks come only from runs that executed them (#408).

A job skipped by its `if:` reports success under its name, and branch
protection reads the newest check run of each name. So a workflow that runs
on any event other than a `main` push or a default-type `pull_request` must
not define a required job. REQUIRED is the list from
`gh api repos/darkhonor/maknae/branches/main/protection/required_status_checks`.
"""

import pathlib
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
REQUIRED = {"build-and-gate", "darwin-cross", "darwin-native"}
DEFAULT_PR_TYPES = {"opened", "synchronize", "reopened"}
HOME = "ci.yml"


def triggers(doc):
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {event: None for event in on}
    return dict(on or {})


def unsafe_events(on):
    unsafe = []
    for event, spec in on.items():
        spec = spec or {}
        if event == "push":
            if set(spec) != {"branches"} or spec["branches"] != ["main"]:
                unsafe.append("push other than branches: [main]")
        elif event == "pull_request":
            if set(spec) - {"types"} or not set(spec.get("types", [])) <= DEFAULT_PR_TYPES:
                unsafe.append("pull_request beyond the default types")
        else:
            unsafe.append(event)
    return unsafe


def check_names(jobs):
    return {job_id: str((job or {}).get("name", job_id)) for job_id, job in (jobs or {}).items()}


def violations(workflows):
    found = []
    homes = {}
    for file, text in workflows.items():
        doc = yaml.safe_load(text) or {}
        names = check_names(doc.get("jobs"))
        unsafe = unsafe_events(triggers(doc))
        for job_id, name in names.items():
            if "${{" in name:
                found.append(f"{file}: job {job_id} has a computed name")
            if name not in REQUIRED:
                continue
            homes.setdefault(name, []).append(file)
            if unsafe:
                found.append(f"{file}: required job {name} under {', '.join(unsafe)}")
    for name in sorted(REQUIRED):
        files = homes.get(name, [])
        if files != [HOME]:
            found.append(f"required job {name} is defined in {files or 'no workflow'}, not only {HOME}")
    return found


def workflow(on, jobs):
    return yaml.safe_dump({"on": on, "jobs": jobs})


def ci_with(on):
    return workflow(on, {name: {"runs-on": "x"} for name in REQUIRED})


SAFE_ON = {"pull_request": {"types": sorted(DEFAULT_PR_TYPES)}, "push": {"branches": ["main"]}}


class WorkflowEvents(unittest.TestCase):
    def test_repository_workflows_have_no_violations(self):
        files = sorted(WORKFLOWS.glob("*.y*ml"))
        self.assertIn(HOME, [f.name for f in files])
        self.assertEqual(violations({f.name: f.read_text() for f in files}), [])

    def test_safe_fixture_passes(self):
        self.assertEqual(violations({HOME: ci_with(SAFE_ON)}), [])

    def test_labeled_type_with_required_job_fails(self):
        on = {"pull_request": {"types": ["opened", "labeled"]}}
        self.assertTrue(any("pull_request beyond" in v for v in violations({HOME: ci_with(on)})))

    def test_push_without_branch_filter_fails(self):
        on = {"pull_request": None, "push": None}
        self.assertTrue(any("push other than" in v for v in violations({HOME: ci_with(on)})))

    def test_push_with_branches_ignore_fails(self):
        on = {"push": {"branches": ["main"], "branches-ignore": ["x"]}}
        self.assertTrue(any("push other than" in v for v in violations({HOME: ci_with(on)})))

    def test_unlisted_event_fails(self):
        for event in ("workflow_dispatch", "merge_group", "pull_request_target", "schedule"):
            on = {"pull_request": None, event: None}
            self.assertTrue(any(event in v for v in violations({HOME: ci_with(on)})), event)

    def test_required_job_in_second_workflow_fails(self):
        other = workflow(SAFE_ON, {"darwin-cross": {"runs-on": "x"}})
        got = violations({HOME: ci_with(SAFE_ON), "other.yml": other})
        self.assertTrue(any("darwin-cross is defined in" in v for v in got))

    def test_required_name_via_name_key_fails(self):
        other = workflow({"pull_request": {"types": ["labeled"]}}, {"x": {"name": "darwin-cross"}})
        got = violations({HOME: ci_with(SAFE_ON), "other.yml": other})
        self.assertTrue(any("other.yml: required job darwin-cross" in v for v in got))

    def test_computed_name_fails(self):
        other = workflow(SAFE_ON, {"x": {"name": "${{ matrix.n }}"}})
        got = violations({HOME: ci_with(SAFE_ON), "other.yml": other})
        self.assertTrue(any("computed name" in v for v in got))

    def test_missing_required_name_fails(self):
        jobs = {name: {"runs-on": "x"} for name in REQUIRED - {"darwin-native"}}
        got = violations({HOME: workflow(SAFE_ON, jobs)})
        self.assertTrue(any("darwin-native is defined in no workflow" in v for v in got))

    def test_on_parsed_as_true_is_read(self):
        text = "on:\n  pull_request:\n    types: [labeled]\njobs:\n  darwin-cross: {}\n"
        self.assertIs(next(iter(yaml.safe_load(text))), True)
        self.assertTrue(any("pull_request beyond" in v for v in violations({HOME: text})))


if __name__ == "__main__":
    unittest.main()
