#!/usr/bin/env python3
"""Conservative whole-package selection; aggregate coverage is never partial.

Python 3.11+. Unknown inputs widen; unreadable package/contract authority fails.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tomllib


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


def select(root, base, head, event, darwin):
    packages, reverse, uncertain = workspace(root)
    mutants = read_toml(root / 'coverage-tiers.toml')['t1']['mutants_crates']
    if (not isinstance(mutants, list) or not mutants
            or not all(isinstance(n, str) and n in packages for n in mutants)
            or any(n not in packages for n in darwin)):
        raise ValueError('empty or unknown mutation/Darwin package authority')

    def result(selected, reason, build=True):
        return {'build': build, 'mutants': sorted(set(mutants) & selected),
                'darwin': sorted(set(darwin) & selected), 'reason': reason}

    def full(reason):
        return result(set(packages), reason)

    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE)

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
    parser.add_argument('--base', required=True)
    parser.add_argument('--head', default='HEAD')
    parser.add_argument('--event', choices=('pull_request', 'push'), required=True)
    parser.add_argument('--darwin', nargs='*', default=[])
    parser.add_argument('--github-output', type=Path)
    args = parser.parse_args()
    try:
        result = select(args.root.resolve(), args.base, args.head, args.event, args.darwin)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f'FAIL: cannot establish affected-package authority: {exc}\n')
    print(json.dumps(result, sort_keys=True))
    if args.github_output:
        with args.github_output.open('a') as stream:
            stream.write(f"build={str(result['build']).lower()}\n")
            for key in ('mutants', 'darwin'):
                stream.write(f"{key}={' '.join(result[key])}\n")


if __name__ == '__main__':
    main()
