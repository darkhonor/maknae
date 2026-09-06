"""Real history fixtures: selective CI must never turn uncertainty into a skip."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SELECTOR = Path(__file__).resolve().parents[1] / 'affected.py'


class AffectedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git('init', '-q')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Fixture')
        self.write('Cargo.toml', '[workspace]\nmembers=["crates/a", "crates/b", "crates/c"]\n')
        self.write('coverage-tiers.toml', '[t1]\nmutants_crates=["a", "b", "c"]\n')
        for name in 'abc':
            self.write(f'crates/{name}/Cargo.toml', f'[package]\nname="{name}"\nversion="0.1.0"\n')
            self.write(f'crates/{name}/src/lib.rs', '// initial\n')
        with (self.root / 'crates/b/Cargo.toml').open('a') as f:
            f.write('[target.\'cfg(unix)\'.dev-dependencies]\nrenamed={package="a",path="../a"}\n')
        self.write('README.md', 'initial\n')
        self.base = self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, text=True).strip()

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def select(self, base=None, event='pull_request'):
        proc = subprocess.run([sys.executable, str(SELECTOR), '--root', str(self.root),
                               '--base=' + (base or self.base), '--head', 'HEAD', '--event', event,
                               '--darwin', 'a', 'b'], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_docs_pr_and_push(self):
        self.write('README.md', 'updated\n')
        self.commit()
        for event in ('pull_request', 'push'):
            self.assertEqual(self.select(event=event)['build'], False)

    def test_operational_docs_skip_rust_on_pr_and_push(self):
        for path in ('packaging/README.md', 'packaging/rpm/README.md',
                     'packaging/deb/README.md', 'packaging/macos/README.md',
                     'packaging/isolation-contract.md', 'ci/hooks/README.md',
                     'deploy/vault-pki/README.md'):
            with self.subTest(path=path):
                self.git('reset', '--hard', self.base)
                self.write(path, 'documentation update\n')
                self.commit()
                for event in ('pull_request', 'push'):
                    result = self.select(event=event)
                    self.assertFalse(result['build'], result)
                    self.assertEqual(result['mutants'], [])
                    self.assertEqual(result['darwin'], [])

    def test_operational_docs_do_not_hide_code_or_unknown_inputs(self):
        for path in ('packaging/common/authz.yaml', 'packaging/fixture.md',
                     'ci/hooks/pre-push', 'deploy/vault-pki/fixture.md'):
            with self.subTest(path=path):
                self.git('reset', '--hard', self.base)
                self.write('packaging/README.md', 'docs\n')
                self.write(path, 'changed\n')
                self.commit()
                self.assertEqual(self.select()['mutants'], ['a', 'b', 'c'])
        self.git('reset', '--hard', self.base)
        self.write('packaging/README.md', 'docs\n')
        self.write('crates/a/src/lib.rs', '// changed\n')
        self.commit()
        self.assertEqual(self.select()['mutants'], ['a', 'b'])

    def test_docs_only_merge_after_main_code_change_skips_rust(self):
        self.git('checkout', '-qb', 'docs')
        self.write('packaging/README.md', 'docs\n')
        self.commit()
        self.git('checkout', '-q', '-')
        self.write('crates/c/src/lib.rs', '// main changed\n')
        before_merge = self.commit()
        self.git('merge', '--no-ff', '-qm', 'merge docs', 'docs')
        self.assertFalse(self.select(base=before_merge, event='push')['build'])

    def test_docs_only_workflow_still_rejects_invalid_isolation_contract(self):
        contract = 'packaging/isolation-contract.md'
        self.write(contract, '| descriptor | ✓ | ✓ | ✓ | ✓ |\n')
        self.base = self.commit()
        # Real gate accepts the starting contract, then rejects an empty cell.
        gate = SELECTOR.parent / 'gates/isolation-contract-lint.sh'
        good = subprocess.run(['bash', str(gate), str(self.root)],
                              capture_output=True, text=True)
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        self.write(contract, '| descriptor | ✓ | | ✓ | ✓ |\n')
        self.commit()
        bad = subprocess.run(['bash', str(gate), str(self.root)],
                             capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn('EMPTY', bad.stdout)
        self.assertFalse(self.select()['build'])
        workflow = (SELECTOR.parent.parent / '.github/workflows/ci.yml').read_text()
        affected = workflow.split('  affected:\n', 1)[1].split('\n  build-and-gate:', 1)[0]
        self.assertIn('run: ci/gates/isolation-contract-lint.sh', affected)
        self.assertNotIn('        if:', affected)
        self.assertEqual(workflow.count('run: ci/gates/isolation-contract-lint.sh'), 1)

    def test_source_and_test_changes_include_reverse_dev_dependencies(self):
        for path in ('crates/a/src/lib.rs', 'crates/a/tests/a test\ncase.rs'):
            self.write(path, '// changed\n')
            self.commit()
            result = self.select()
            self.assertTrue(result['build'])
            self.assertEqual(result['mutants'], ['a', 'b'])
            self.assertEqual(result['darwin'], ['a', 'b'])

    def test_shared_and_unknown_changes_select_all(self):
        for path in ('Cargo.lock', 'rust-toolchain.toml', '.cargo/mutants.toml',
                     '.github/workflows/ci.yml', 'ci/gates/a.sh', 'unknown.md',
                     'crates/a/build.rs', 'crates/a/Cargo.toml'):
            with self.subTest(path=path):
                self.git('reset', '--hard', self.base)
                if path.endswith('Cargo.toml'):
                    with (self.root / path).open('a') as f:
                        f.write('# changed\n')
                else:
                    self.write(path, '# changed\n')
                self.commit()
                self.assertEqual(self.select()['mutants'], ['a', 'b', 'c'])

    def test_deletion_and_rename_preserve_old_owner(self):
        self.git('mv', 'crates/a/src/lib.rs', 'README-renamed.md')
        self.commit()
        self.assertEqual(self.select()['mutants'], ['a', 'b', 'c'])
        self.git('reset', '--hard', self.base)
        self.git('rm', 'crates/a/src/lib.rs')
        self.commit()
        self.assertEqual(self.select()['mutants'], ['a', 'b'])

    def test_empty_and_invalid_history_widen(self):
        for base in (self.base, 'missing-ref', '0' * 40, '--help'):
            self.assertEqual(self.select(base=base)['mutants'], ['a', 'b', 'c'])

    def test_merge_push_compares_endpoints(self):
        self.git('checkout', '-qb', 'topic')
        self.write('README.md', 'topic\n')
        self.commit()
        self.git('checkout', '-q', '-')
        self.write('crates/c/src/lib.rs', '// main changed\n')
        before_merge = self.commit()
        self.git('merge', '--no-ff', '-qm', 'merge docs', 'topic')
        self.assertFalse(self.select(base=before_merge, event='push')['build'])

    def test_pr_uses_merge_base(self):
        self.git('checkout', '-qb', 'topic')
        self.write('crates/a/src/lib.rs', '// topic\n')
        self.commit()
        self.git('checkout', '-q', '-')
        self.write('crates/c/src/lib.rs', '// main\n')
        other = self.commit()
        self.git('checkout', '-q', 'topic')
        self.assertEqual(self.select(base=other)['mutants'], ['a', 'b'])

    def test_unknown_path_dependency_widens(self):
        with (self.root / 'crates/c/Cargo.toml').open('a') as f:
            f.write('[build-dependencies]\nexternal={path="../../external"}\n')
        self.base = self.commit()
        self.write('crates/a/src/lib.rs', '// changed\n')
        self.commit()
        self.assertEqual(self.select()['mutants'], ['a', 'b', 'c'])

    def test_transitive_workspace_and_build_dependencies(self):
        with (self.root / 'Cargo.toml').open('a') as f:
            f.write('[workspace.dependencies]\nrenamed={package="b",path="crates/b"}\n')
        with (self.root / 'crates/c/Cargo.toml').open('a') as f:
            f.write('[build-dependencies]\nrenamed={workspace=true}\n')
        self.base = self.commit()
        self.write('crates/a/src/lib.rs', '// changed\n')
        self.commit()
        self.assertEqual(self.select()['mutants'], ['a', 'b', 'c'])

    def test_crate_docs_are_unknown_build_inputs(self):
        self.write('crates/c/README.md', 'could be include_str data\n')
        self.commit()
        self.assertEqual(self.select()['mutants'], ['a', 'b', 'c'])

    def test_invalid_authority_fails_instead_of_empty_assurance(self):
        for contract in ('[t1]\nmutants_crates=[]\n', '[t1]\nmutants_crates=["unknown"]\n'):
            self.write('coverage-tiers.toml', contract)
            proc = subprocess.run([sys.executable, str(SELECTOR), '--root', str(self.root),
                                   '--base=' + self.base, '--event', 'push'],
                                  capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn('FAIL: cannot establish', proc.stderr)

    def test_missing_workspace_member_fails(self):
        with (self.root / 'Cargo.toml').open('w') as f:
            f.write('[workspace]\nmembers=["crates/a", "missing"]\n')
        # Keep a valid mutation cohort to expose silent member-discovery loss.
        self.write('coverage-tiers.toml', '[t1]\nmutants_crates=["a"]\n')
        proc = subprocess.run([sys.executable, str(SELECTOR), '--root', str(self.root),
                               '--base=' + self.base, '--event', 'push'],
                              capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('FAIL: cannot establish', proc.stderr)

    def test_docs_only_workflow_still_rejects_external_authority(self):
        self.write('AGENTS.md', 'Local authority.\n')
        self.write('design/contract.md', 'Local decision.\n')
        self.base = self.commit()
        self.write('design/contract.md', 'Follow Knowledge Lake ADR-0001.\n')
        self.commit()
        self.assertFalse(self.select()['build'])
        workflow = (SELECTOR.parent.parent / '.github/workflows/ci.yml').read_text()
        affected = workflow.split('  affected:\n', 1)[1].split('\n  build-and-gate:', 1)[0]
        # This wiring assertion is load-bearing: the real lint below must run
        # in the job that docs-only updates cannot skip, before Rust jobs.
        self.assertIn('run: ci/gates/external-authority-lint.sh', affected)
        self.assertNotIn('        if:', affected)
        gate = SELECTOR.parent / 'gates/external-authority-lint.sh'
        self.write('ci/gates/external-authority-lint.sh', gate.read_text())
        proc = subprocess.run(['bash', 'ci/gates/external-authority-lint.sh'],
                              cwd=self.root, capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('design/contract.md:1 cites an external', proc.stdout)


    def hook(self, base, mutations=False, invalid_contract=False):
        # A recording shell gate proves invocation/selection, not coverage itself.
        self.write('ci/affected.py', SELECTOR.read_text())
        hook = SELECTOR.parent / 'hooks/pre-push'
        self.write('ci/hooks/pre-push', hook.read_text())
        self.write('ci/gates/coverage-tiers.sh', '#!/bin/sh\nprintf "%s\\n" "$*" >> "$RECORD"\n')
        for name in ('external-authority-lint.sh', 'isolation-contract-lint.sh'):
            self.write('ci/gates/' + name, (SELECTOR.parent / 'gates' / name).read_text())
        self.write('design/contract.md', 'Local authority.\n')
        self.write('AGENTS.md', 'Local authority.\n')
        self.write('packaging/isolation-contract.md',
                   '| descriptor | ✓ | | ✓ | ✓ |\n' if invalid_contract else
                   '| descriptor | ✓ | ✓ | ✓ | ✓ |\n')
        record = self.root / 'invocations'
        proc = subprocess.run(['bash', 'ci/hooks/pre-push'], cwd=self.root,
                              input=f'refs/heads/topic {self.git("rev-parse", "HEAD")} refs/heads/topic {base}\n',
                              env={**os.environ, 'RECORD': str(record),
                                   'MAKNAE_PRE_PUSH_MUTANTS': '1' if mutations else '0'},
                              capture_output=True, text=True)
        if invalid_contract:
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn('EMPTY', proc.stdout)
            self.assertFalse(record.exists(), 'Rust gate ran after invalid documentation')
            return
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return record.read_text().splitlines() if record.exists() else []

    def test_hook_skips_docs_using_actual_remote_endpoint(self):
        self.write('README.md', 'docs\n')
        self.commit()
        self.assertEqual(self.hook(self.base, mutations=True), [])

    def test_hook_rejects_invalid_docs_without_running_rust(self):
        self.write('packaging/isolation-contract.md', '| descriptor | ✓ | | ✓ | ✓ |\n')
        self.commit()
        self.hook(self.base, mutations=True, invalid_contract=True)

    def test_hook_runs_coverage_and_optional_selected_mutation(self):
        self.write('crates/a/src/lib.rs', '// changed\n')
        self.commit()
        invocations = self.hook(self.base, mutations=True)
        self.assertEqual(len(invocations), 2)
        self.assertNotIn('--mutants', invocations[0])
        self.assertTrue(invocations[1].endswith('--mutants a b'), invocations)

    def test_hook_default_does_not_force_mutation(self):
        self.write('crates/c/src/lib.rs', '// changed\n')
        self.commit()
        invocations = self.hook(self.base)
        self.assertEqual(len(invocations), 1)
        self.assertNotIn('--mutants', invocations[0])


if __name__ == '__main__':
    unittest.main()
