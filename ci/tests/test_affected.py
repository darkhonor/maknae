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

    def select(self, base=None, event='pull_request', env=None):
        proc = subprocess.run([sys.executable, str(SELECTOR), '--root', str(self.root),
                               '--base=' + (base or self.base), '--head', 'HEAD', '--event', event],
                              capture_output=True, text=True,
                              env={**os.environ, **(env or {})})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_ambient_git_env_does_not_change_selection(self):
        self.write('crates/c/src/lib.rs', '// changed\n')
        self.commit()
        bogus = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, bogus)
        for var, value in (('GIT_LITERAL_PATHSPECS', '1'), ('GIT_NOGLOB_PATHSPECS', '1'),
                           ('GIT_GLOB_PATHSPECS', '1'), ('GIT_ICASE_PATHSPECS', '1'),
                           ('GIT_DIR', bogus), ('GIT_WORK_TREE', bogus),
                           ('GIT_INDEX_FILE', bogus + '/index'), ('GIT_OBJECT_DIRECTORY', bogus),
                           ('GIT_COMMON_DIR', bogus), ('GIT_ALTERNATE_OBJECT_DIRECTORIES', bogus)):
            with self.subTest(var):
                for event in ('pull_request', 'push'):
                    result = self.select(event=event, env={var: value, 'GIT_LITERAL_PATHSPECS': '1'})
                    self.assertEqual((result['mutants'], result['reason']),
                                     (['c'], 'changed packages and reverse dependencies'))

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


    def hook(self, base, mutations=False, invalid_contract=False, refs=('refs/heads/topic',),
             env=None, remote_head=None, selector=None, expect_fail=False):
        # A recording shell gate proves invocation/selection, not coverage itself.
        self.write('ci/affected.py', selector or SELECTOR.read_text())
        hook = SELECTOR.parent / 'hooks/pre-push'
        self.write('ci/hooks/pre-push', hook.read_text())
        self.write('ci/gates/coverage-tiers.sh',
                   '#!/bin/sh\nprintf "%s\\n" "$*" >> "$RECORD"\n'
                   'case " $* " in *" --in-diff "*) cat >> "$RECORD.stdin";; esac\n')
        self.write('ci/gates/unsafe-confinement.sh',
                   '#!/bin/sh\nprintf "unsafe-confinement %s\\n" "$*" >> "$RECORD"\n')
        for name in ('external-authority-lint.sh', 'isolation-contract-lint.sh'):
            self.write('ci/gates/' + name, (SELECTOR.parent / 'gates' / name).read_text())
        self.write('design/contract.md', 'Local authority.\n')
        self.write('AGENTS.md', 'Local authority.\n')
        self.write('packaging/isolation-contract.md',
                   '| descriptor | ✓ | | ✓ | ✓ |\n' if invalid_contract else
                   '| descriptor | ✓ | ✓ | ✓ | ✓ |\n')
        if remote_head:
            self.git('update-ref', 'refs/remotes/origin/main', remote_head)
            self.git('symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main')
        record = self.root / 'invocations'
        for stale in (record, self.root / 'invocations.stdin'):
            stale.unlink(missing_ok=True)
        head = self.git('rev-parse', 'HEAD')
        proc = subprocess.run(['bash', 'ci/hooks/pre-push', 'origin', 'https://example.invalid/r.git'],
                              cwd=self.root,
                              input=''.join(f'{ref} {head} {ref} {base}\n' for ref in refs),
                              env={**os.environ, 'RECORD': str(record),
                                   'MAKNAE_PRE_PUSH_MUTANTS': '1' if mutations else '0',
                                   **(env or {})},
                              capture_output=True, text=True)
        if invalid_contract:
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn('EMPTY', proc.stdout)
            self.assertFalse(record.exists(), 'Rust gate ran after invalid documentation')
            return
        invocations = record.read_text().splitlines() if record.exists() else []
        if expect_fail:
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            return proc, invocations
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return invocations

    def mutation_calls(self, invocations):
        return [line for line in invocations if '--mutants' in line]

    def change_c(self):
        self.write('crates/c/src/lib.rs', '// changed\n')
        self.commit()

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
        self.assertEqual(len(invocations), 3)
        self.assertEqual(invocations[0], 'unsafe-confinement --root ' + self.git('rev-parse', '--show-toplevel'))
        self.assertNotIn('--mutants', invocations[1])
        self.assertTrue(invocations[2].endswith('--mutants a b --in-diff ' + self.base), invocations)

    def test_hook_default_does_not_force_mutation(self):
        self.write('crates/c/src/lib.rs', '// changed\n')
        self.commit()
        invocations = self.hook(self.base)
        self.assertEqual(len(invocations), 2)
        self.assertEqual(invocations[0], 'unsafe-confinement --root ' + self.git('rev-parse', '--show-toplevel'))
        self.assertNotIn('--mutants', invocations[1])

    def test_hook_existing_ref_passes_remote_oid(self):
        self.change_c()
        calls = self.mutation_calls(self.hook(self.base, mutations=True))
        self.assertEqual(calls, ['--root ' + self.git('rev-parse', '--show-toplevel')
                                 + ' --mutants c --in-diff ' + self.base])

    def test_hook_new_ref_without_base_fails(self):
        self.change_c()
        proc, invocations = self.hook(ZERO, mutations=True, expect_fail=True)
        self.assertIn('FAIL: pre-push: new ref refs/heads/topic has no base; set '
                      'MAKNAE_PRE_PUSH_MUTANTS_BASE=<rev>', proc.stderr)
        self.assertEqual(invocations, [])

    def test_hook_new_ref_without_opt_in_does_not_fail(self):
        self.change_c()
        invocations = self.hook(ZERO)
        self.assertEqual(len(invocations), 2, invocations)
        self.assertEqual(self.mutation_calls(invocations), [])

    def test_hook_docs_only_new_ref_needs_a_mutation_base(self):
        # An empty push selection no longer skips mutation: the merge-base selection
        # decides, and a new ref needs <remote>/HEAD or the override to compute it.
        self.write('README.md', 'docs\n')
        self.commit()
        stub = 'import json\nprint(json.dumps({"build": False, "mutants": [], "reason": "stub"}))\n'
        proc, invocations = self.hook(ZERO, mutations=True, selector=stub, expect_fail=True)
        self.assertIn('MAKNAE_PRE_PUSH_MUTANTS_BASE=<rev>', proc.stderr)
        self.assertEqual(invocations, [])
        self.assertEqual(self.hook(ZERO, mutations=True, selector=stub, remote_head=self.base), [])

    def test_hook_mutation_runs_after_build_gates(self):
        self.change_c()
        invocations = self.hook(self.base, mutations=True,
                                refs=('refs/heads/topic', 'refs/heads/other'))
        self.assertEqual(len(invocations), 4, invocations)
        self.assertTrue(invocations[0].startswith('unsafe-confinement '), invocations)
        self.assertNotIn('--mutants', invocations[1])
        self.assertEqual(len(self.mutation_calls(invocations[2:])), 2, invocations)

    def test_hook_mutation_stdin_is_not_the_ref_list(self):
        self.change_c()
        self.hook(self.base, mutations=True, refs=('refs/heads/topic', 'refs/heads/other'))
        self.assertEqual((self.root / 'invocations.stdin').read_text(), '')

    def test_hook_new_ref_uses_remote_head(self):
        self.change_c()
        calls = self.mutation_calls(self.hook(ZERO, mutations=True, remote_head=self.base))
        self.assertEqual(len(calls), 1, calls)
        self.assertTrue(calls[0].endswith(' --in-diff ' + self.base), calls)

    def test_hook_new_ref_base_override(self):
        self.change_c()
        override = {'MAKNAE_PRE_PUSH_MUTANTS_BASE': 'v-base'}
        for base, head in ((ZERO, None), (ZERO, self.base), (self.base, None)):
            with self.subTest(base=base, remote_head=head):
                calls = self.mutation_calls(self.hook(base, mutations=True, env=override,
                                                      remote_head=head))
                self.assertEqual(len(calls), 1, calls)
                self.assertTrue(calls[0].endswith(' --in-diff v-base'), calls)

    def test_hook_existing_ref_override_selects_over_the_diff_range(self):
        self.write('crates/a/src/lib.rs', '// branch\n')
        old_tip = self.commit()
        self.git('reset', '-q', '--hard', self.base)
        self.change_c()
        main = self.git('rev-parse', 'HEAD')
        self.write('crates/a/src/lib.rs', '// branch\n')
        self.commit()
        override = {'MAKNAE_PRE_PUSH_MUTANTS_BASE': main}
        calls = self.mutation_calls(self.hook(old_tip, mutations=True, env=override))
        self.assertEqual(calls, ['--root ' + self.git('rev-parse', '--show-toplevel')
                                 + ' --mutants a b --in-diff ' + main])

    def test_hook_rebased_ref_selects_over_the_merge_base(self):
        self.write('crates/a/src/lib.rs', '// branch\n')
        old_tip = self.commit()
        self.git('reset', '-q', '--hard', self.base)
        self.change_c()
        self.write('crates/a/src/lib.rs', '// branch\n')
        self.commit()
        calls = self.mutation_calls(self.hook(old_tip, mutations=True))
        self.assertEqual(calls, ['--root ' + self.git('rev-parse', '--show-toplevel')
                                 + ' --mutants a b c --in-diff ' + old_tip])

    def test_hook_rebase_with_docs_only_push_range_still_mutates_the_branch(self):
        self.write('crates/a/src/lib.rs', '// branch\n')
        old_tip = self.commit()
        self.git('reset', '-q', '--hard', self.base)
        self.write('README.md', 'main moved\n')
        self.commit()
        self.write('crates/a/src/lib.rs', '// branch\n')
        self.commit()
        invocations = self.hook(old_tip, mutations=True)
        self.assertEqual(invocations, ['--root ' + self.git('rev-parse', '--show-toplevel')
                                       + ' --mutants a b --in-diff ' + old_tip])

    def test_hook_without_opt_in_runs_no_mutation(self):
        self.change_c()
        for base in (self.base, ZERO):
            with self.subTest(base=base):
                self.assertEqual(self.mutation_calls(self.hook(base)), [])


ZERO = '0' * 40

if __name__ == '__main__':
    unittest.main()
