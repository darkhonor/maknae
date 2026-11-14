"""Real history fixtures: selective CI must never turn uncertainty into a skip."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SELECTOR = Path(__file__).resolve().parents[1] / 'affected.py'



def contract_table(row):
    return '| Property | A | B | C | D |\n|---|---|---|---|---|\n' + row + '\n'

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
                           ('GIT_COMMON_DIR', bogus), ('GIT_ALTERNATE_OBJECT_DIRECTORIES', bogus),
                           ('GIT_GRAFT_FILE', bogus + '/grafts')):
            with self.subTest(var):
                for event in ('pull_request', 'push'):
                    result = self.select(event=event, env={var: value, 'GIT_LITERAL_PATHSPECS': '1'})
                    self.assertEqual((result['mutants'], result['reason']),
                                     (['c'], 'changed packages and reverse dependencies'))

    def test_replace_refs_do_not_change_selection(self):
        self.write('crates/c/src/lib.rs', '// changed\n')
        changed = self.commit()
        self.write('README.md', 'updated\n')
        self.commit()
        self.git('replace', self.base, self.git('commit-tree', changed + '^{tree}', '-m', 'fake'))
        result = self.select(event='push')
        self.assertEqual((result['mutants'], result['reason']),
                         (['c'], 'changed packages and reverse dependencies'))
        self.assertRefused(self.base, 'the repository has replace refs (refs/replace/')

    def assertRefused(self, base, text, root=None):
        proc = subprocess.run([sys.executable, str(SELECTOR), '--root', str(root or self.root),
                               '--base=' + base, '--head', 'HEAD', '--event', 'pull_request'],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn('FAIL: cannot establish affected-package authority: ' + text, proc.stderr)
        self.assertEqual(proc.stdout, '')

    def graft_onto_docs_ancestor(self):
        self.write('crates/c/src/lib.rs', '// changed\n')
        head = self.commit()
        tree = self.git('rev-parse', 'HEAD^{tree}')
        self.write('README.md', 'older\n')
        self.git('add', '.')
        ancestor = self.git('commit-tree', self.git('write-tree'), '-m', 'synthetic')
        self.git('reset', '-q', '--hard', head)
        self.assertEqual(self.git('rev-parse', 'HEAD^{tree}'), tree)
        grafts = self.root / '.git/info/grafts'
        grafts.parent.mkdir(exist_ok=True)
        grafts.write_text(f'{self.base} {ancestor}\n{head} {ancestor}\n')
        return head

    def test_grafted_history_is_refused_for_a_merge_base(self):
        self.graft_onto_docs_ancestor()
        self.assertRefused(self.base, 'the repository has grafts (')
        self.assertEqual(self.select(event='push')['mutants'], ['c'])

    def test_shallow_history_is_refused_for_a_merge_base(self):
        self.change_c()
        clone = self.root.parent / (self.root.name + '-shallow')
        self.addCleanup(subprocess.run, ['rm', '-rf', str(clone)])
        subprocess.run(['git', 'clone', '-q', '--depth', '1', '--no-local', f'file://{self.root}',
                        str(clone)], check=True, capture_output=True)
        head = subprocess.check_output(['git', '-C', str(clone), 'rev-parse', 'HEAD'], text=True).strip()
        self.assertRefused(head, 'the repository is shallow', root=clone)

    def test_check_history_mode(self):
        proc = subprocess.run([sys.executable, str(SELECTOR), '--root', str(self.root), '--check-history'],
                              capture_output=True, text=True)
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, '', ''))
        self.graft_onto_docs_ancestor()
        proc = subprocess.run([sys.executable, str(SELECTOR), '--root', str(self.root), '--check-history'],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1)
        self.assertIn('FAIL: history cannot be trusted for a merge-base selection: the repository has grafts',
                      proc.stderr)

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
        self.write(contract, contract_table('| descriptor | ✓ | ✓ | ✓ | ✓ |'))
        self.base = self.commit()
        # Real gate accepts the starting contract, then rejects an empty cell.
        gate = SELECTOR.parent / 'gates/isolation-contract-lint.sh'
        good = subprocess.run(['bash', str(gate), str(self.root)],
                              capture_output=True, text=True)
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        self.write(contract, contract_table('| descriptor | ✓ | | ✓ | ✓ |'))
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
                   contract_table('| descriptor | ✓ | | ✓ | ✓ |') if invalid_contract else
                   contract_table('| descriptor | ✓ | ✓ | ✓ | ✓ |'))
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
        invocations = record.read_text().splitlines() if record.exists() else []
        if mutations:
            preflight = '--root ' + self.git('rev-parse', '--show-toplevel') + ' --in-diff-preflight'
            self.assertEqual(invocations[:1], [preflight], 'the in-diff preflight did not run first')
            invocations = invocations[1:]
        if invalid_contract:
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn('EMPTY', proc.stdout)
            self.assertEqual(invocations, [], 'Rust gate ran after invalid documentation')
            return
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
        self.assertEqual(self.hook(self.base), [])

    def test_hook_opted_in_passes_every_mutation_crate_even_for_docs_only(self):
        self.write('README.md', 'docs\n')
        self.commit()
        self.assertEqual(self.hook(self.base, mutations=True),
                         ['--root ' + self.git('rev-parse', '--show-toplevel')
                          + ' --mutants a b c --in-diff ' + self.base])

    def test_hook_opted_in_refuses_an_unreadable_mutation_contract(self):
        self.write('crates/a/src/lib.rs', '// changed\n')
        self.write('coverage-tiers.toml', '[t1]\nmutants_crates=[]\n')
        self.commit()
        proc, invocations = self.hook(self.base, mutations=True, expect_fail=True)
        self.assertIn('FAIL: pre-push: [t1].mutants_crates is not a non-empty list', proc.stderr)
        self.assertEqual(invocations, [])

    def test_hook_rejects_invalid_docs_without_running_rust(self):
        self.write('packaging/isolation-contract.md', contract_table('| descriptor | ✓ | | ✓ | ✓ |'))
        self.commit()
        self.hook(self.base, mutations=True, invalid_contract=True)

    def test_hook_runs_coverage_and_optional_selected_mutation(self):
        self.write('crates/a/src/lib.rs', '// changed\n')
        self.commit()
        invocations = self.hook(self.base, mutations=True)
        self.assertEqual(len(invocations), 3)
        self.assertEqual(invocations[0], 'unsafe-confinement --root ' + self.git('rev-parse', '--show-toplevel'))
        self.assertNotIn('--mutants', invocations[1])
        self.assertTrue(invocations[2].endswith('--mutants a b c --in-diff ' + self.base), invocations)

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
                                 + ' --mutants a b c --in-diff ' + self.base])

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
        self.assertEqual(self.mutation_calls(self.hook(ZERO, mutations=True, selector=stub,
                                                       remote_head=self.base)),
                         ['--root ' + self.git('rev-parse', '--show-toplevel')
                          + ' --mutants a b c --in-diff ' + self.base])

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
                                 + ' --mutants a b c --in-diff ' + main])

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
                                       + ' --mutants a b c --in-diff ' + old_tip])

    def test_hook_refuses_grafted_history_before_any_selection(self):
        self.graft_onto_docs_ancestor()
        proc, invocations = self.hook(self.base, mutations=True, expect_fail=True)
        self.assertIn('FAIL: history cannot be trusted for a merge-base selection: '
                      'the repository has grafts', proc.stderr)
        self.assertNotIn('"build"', proc.stdout)
        self.assertEqual(invocations, [])
        self.assertEqual(len(self.hook(self.base)), 2)

    def symlinked_contract(self):
        for name in ('coverage-tiers.sh', 'mutation-diff.py'):
            self.write('ci/gates/' + name, (SELECTOR.parent / 'gates' / name).read_text())
        record = self.root / 'invocations'
        self.write('ci/affected.py', 'import os, sys\nopen(os.environ["RECORD"], "a").write("affected\\n")\n')
        self.write('contract/tiers.toml', '[t1\nmutants_crates = [\n')
        (self.root / 'coverage-tiers.toml').unlink()
        (self.root / 'coverage-tiers.toml').symlink_to('contract/tiers.toml')
        self.write('crates/a/src/lib.rs', '// changed\n')
        self.commit()
        return record

    def assertGuardFailedFirst(self, proc, record):
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('FAIL: --in-diff: coverage-tiers.toml is a symlink; config inputs must be regular files',
                      proc.stdout + proc.stderr)
        self.assertNotIn('TOMLDecodeError', proc.stdout + proc.stderr)
        self.assertFalse(record.exists(), 'a config consumer ran before the preflight')

    def test_hook_preflight_refuses_a_symlinked_contract_before_reading_it(self):
        record = self.symlinked_contract()
        self.write('ci/hooks/pre-push', (SELECTOR.parent / 'hooks/pre-push').read_text())
        head = self.git('rev-parse', 'HEAD')
        proc = subprocess.run(['bash', 'ci/hooks/pre-push', 'origin', 'https://example.invalid/r.git'],
                              cwd=self.root, input=f'refs/heads/topic {head} refs/heads/topic {self.base}\n',
                              env={**os.environ, 'RECORD': str(record), 'MAKNAE_PRE_PUSH_MUTANTS': '1'},
                              capture_output=True, text=True)
        self.assertGuardFailedFirst(proc, record)

    def test_mutation_workflow_selection_preflight_refuses_a_symlinked_contract_before_reading_it(self):
        record = self.symlinked_contract()
        workflow = (SELECTOR.parent.parent / '.github/workflows/mutation.yml').read_text()
        step = workflow.split('      - name: Select mutation packages', 1)[1].split('\n      - name:', 1)[0]
        body = step.split('        run: |\n', 1)[1]
        script = ''.join(line[10:] + '\n' for line in body.splitlines())
        output = self.root / 'github-output'
        proc = subprocess.run(['bash', '-e', '-c', script], cwd=self.root, capture_output=True, text=True,
                              env={**os.environ, 'RECORD': str(record), 'EVENT_NAME': 'pull_request',
                                   'MUTATION_IN_CI': '', 'PACKAGES': '', 'GITHUB_OUTPUT': str(output)})
        self.assertGuardFailedFirst(proc, record)
        self.assertFalse(output.exists())

    def test_hook_without_opt_in_runs_no_mutation(self):
        self.change_c()
        for base in (self.base, ZERO):
            with self.subTest(base=base):
                self.assertEqual(self.mutation_calls(self.hook(base)), [])


ZERO = '0' * 40

if __name__ == '__main__':
    unittest.main()
