#!/usr/bin/env python3
"""Conservative whole-package selection; aggregate coverage is never partial.

Python 3.11+. Unknown inputs widen; unreadable package/contract authority fails.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

GIT_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR",
           "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_LITERAL_PATHSPECS", "GIT_NOGLOB_PATHSPECS",
           "GIT_GLOB_PATHSPECS", "GIT_ICASE_PATHSPECS", "GIT_GRAFT_FILE")


def git_env():
    env = {k: v for k, v in os.environ.items() if k not in GIT_ENV}
    env['GIT_NO_REPLACE_OBJECTS'] = '1'
    return env


def untrusted_history(root):
    def git(*args):
        done = subprocess.run(['git', '-C', str(root), *args], capture_output=True, env=git_env(),
                              check=False)
        return done.returncode, done.stdout.decode(errors='replace').strip(), \
            done.stderr.decode(errors='replace').strip()

    code, shallow, err = git('rev-parse', '--is-shallow-repository')
    if code != 0 or shallow not in ('true', 'false'):
        return 'cannot tell whether the repository is shallow: ' + err
    if shallow == 'true':
        return 'the repository is shallow; the merge base cannot be trusted'
    code, grafts, _ = git('rev-parse', '--git-path', 'info/grafts')
    if code != 0 or not grafts:
        return f'cannot locate info/grafts in {root}'
    grafts = Path(grafts) if os.path.isabs(grafts) else Path(root) / grafts
    if grafts.exists() or grafts.is_symlink():
        return f'the repository has grafts ({grafts}); history cannot be trusted'
    code, replaced, err = git('for-each-ref', '--format=%(refname)', 'refs/replace/')
    if code != 0:
        return 'cannot list replace refs: ' + err
    replaced = replaced.split()
    if replaced:
        return f'the repository has replace refs ({replaced[0]}); history cannot be trusted'
    return None


def read_toml(path):
    with path.open('rb') as stream:
        return tomllib.load(stream)


def workspace(root):
    ws = read_toml(root / 'Cargo.toml')['workspace']
    packages = {}
    manifests = {}
    for member in ws['members']:
        directories = list(root.glob(member))
        if not directories:
            raise ValueError('workspace member matched nothing: ' + member)
        for directory in directories:
            manifest = read_toml(directory / 'Cargo.toml')
            name = manifest['package']['name']
            if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_-]*', name) or name in packages:
                raise ValueError('invalid or duplicate package name')
            packages[name] = directory.resolve()
            manifests[name] = manifest
    if not packages:
        raise ValueError('empty workspace')
    reverse = {name: set() for name in packages}
    uncertain = False
    for name, manifest in manifests.items():
        tables = [manifest, *manifest.get('target', {}).values()]
        for table in tables:
            for kind in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                for alias, value in table.get(kind, {}).items():
                    if not isinstance(value, dict):
                        continue
                    inherited = value.get('workspace', False)
                    if inherited:
                        value = ws.get('dependencies', {}).get(alias)
                        if not isinstance(value, dict):
                            # A workspace string dependency cannot be a local path.
                            continue
                    dependency = value.get('package', alias)
                    if 'path' in value:
                        anchor = root if inherited else packages[name]
                        location = (anchor / value['path']).resolve()
                        if dependency not in packages or packages[dependency] != location:
                            uncertain = True
                        else:
                            reverse[dependency].add(name)
                    elif dependency in packages:
                        # Same-name registry/git override cannot prove independence.
                        uncertain = True
    return packages, reverse, uncertain


def docs_only(path):
    # Deliberate allowlist, not '*.md': fixtures/configs can be Markdown too.
    return path in {'README.md', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md',
                    'SECURITY.md', 'AGENTS.md', 'CLAUDE.md', 'LICENSE',
                    'packaging/README.md', 'packaging/rpm/README.md',
                    'packaging/deb/README.md', 'packaging/macos/README.md',
                    'packaging/isolation-contract.md', 'ci/hooks/README.md',
                    'deploy/vault-pki/README.md'} or (
        path.startswith(('design/', 'docs/')) and path.endswith(('.md', '.png', '.svg')))


def select(root, base, head, event):
    packages, reverse, uncertain = workspace(root)
    mutants = read_toml(root / 'coverage-tiers.toml')['t1']['mutants_crates']
    if (not isinstance(mutants, list) or not mutants
            or not all(isinstance(n, str) and n in packages for n in mutants)):
        raise ValueError('empty or unknown mutation package authority')

    def result(selected, reason, build=True):
        return {'build': build, 'mutants': sorted(set(mutants) & selected), 'reason': reason}

    def full(reason):
        return result(set(packages), reason)

    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE,
                                       env=git_env())

    if event == 'pull_request':
        problem = untrusted_history(root)
        if problem:
            raise ValueError(problem)
    try:
        # Resolve first: even a user-supplied '--help' is data, never an option.
        base_id = git('rev-parse', '--verify', '--end-of-options', base + '^{commit}').decode().strip()
        head_id = git('rev-parse', '--verify', '--end-of-options', head + '^{commit}').decode().strip()
        if event == 'pull_request':
            base_id = git('merge-base', base_id, head_id).decode().strip()
        paths = git('diff', '--no-renames', '--name-only', '-z', base_id, head_id, '--').decode().split('\0')[:-1]
    except (subprocess.CalledProcessError, UnicodeError):
        return full('unavailable history')
    if uncertain or not paths:
        return full('ambiguous dependencies or empty diff')
    changed = set()
    for path in paths:
        if docs_only(path):
            continue
        owner = next((name for name, directory in packages.items()
                      if (root / path).is_relative_to(directory)), None)
        # Every non-source package input may influence builds or discovery.
        if owner is None or Path(path).name in {'Cargo.toml', 'build.rs'} or not path.endswith('.rs'):
            return full('shared or unknown input: ' + path)
        changed.add(owner)
    if not changed:
        return result(set(), 'documentation only', False)
    selected = set(changed)
    pending = list(changed)
    while pending:
        for dependent in reverse[pending.pop()] - selected:
            selected.add(dependent)
            pending.append(dependent)
    return result(selected, 'changed packages and reverse dependencies')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--base')
    parser.add_argument('--head', default='HEAD')
    parser.add_argument('--event', choices=('pull_request', 'push'))
    parser.add_argument('--github-output', type=Path)
    parser.add_argument('--check-history', action='store_true')
    args = parser.parse_args()
    if args.check_history:
        problem = untrusted_history(args.root.resolve())
        if problem:
            parser.exit(1, f'FAIL: history cannot be trusted for a merge-base selection: {problem}\n')
        return
    if args.base is None or args.event is None:
        parser.error('--base and --event are required')
    try:
        result = select(args.root.resolve(), args.base, args.head, args.event)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f'FAIL: cannot establish affected-package authority: {exc}\n')
    print(json.dumps(result, sort_keys=True))
    if args.github_output:
        with args.github_output.open('a') as stream:
            stream.write(f"build={str(result['build']).lower()}\n")
            stream.write(f"mutants={' '.join(result['mutants'])}\n")


if __name__ == '__main__':
    main()
