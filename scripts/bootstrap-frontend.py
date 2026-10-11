#!/usr/bin/env python3
"""Initialize the pinned frontend submodule without replacing local work."""
import argparse
import pathlib
import re
import subprocess


def git(directory, *args, capture=False):
    return subprocess.run(
        ['git', '-C', str(directory), *args], check=True,
        text=True, stdout=subprocess.PIPE if capture else None,
    ).stdout


def pinned_commit(root):
    entry = git(root, 'ls-files', '--stage', '--', 'assets', capture=True).strip()
    match = re.fullmatch(r'160000 ([0-9a-f]{40}|[0-9a-f]{64}) 0\tassets', entry)
    if not match:
        raise SystemExit('Expected one committed frontend submodule entry')
    return match.group(1)


def bootstrap(root):
    expected = pinned_commit(root)
    assets = root / 'assets'
    if (assets / '.git').exists():
        if git(assets, 'status', '--porcelain', capture=True).strip():
            raise SystemExit('Frontend has local changes; preserve them before bootstrap')
        if git(assets, 'rev-parse', 'HEAD', capture=True).strip() != expected:
            raise SystemExit('Unexpected frontend revision; update the submodule explicitly')
        print('Pinned frontend is already restored')
        return
    if assets.exists() and any(assets.iterdir()):
        raise SystemExit('Refusing to initialize a nonempty frontend directory')
    git(root, 'submodule', 'update', '--init', '--', 'assets')
    if git(assets, 'rev-parse', 'HEAD', capture=True).strip() != expected:
        raise SystemExit('Frontend submodule does not match the pinned revision')
    print('Pinned frontend restored and verified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    bootstrap(arguments.root.resolve())
