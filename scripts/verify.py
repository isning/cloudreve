#!/usr/bin/env python3
"""Run release gates; inherited exceptions are explicit, bounded and source-pinned."""
import argparse
import collections
import hashlib
import json
import os
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINE = ROOT / 'verification/upstream-baseline.json'


def run(args, cwd=ROOT, capture=False):
    print('Running: ' + ' '.join(args), flush=True)
    return subprocess.run(args, cwd=cwd, check=True, text=True, stdout=subprocess.PIPE if capture else None).stdout


def diagnostics(output, assets):
    result = collections.Counter()
    matches = list(re.finditer(r'^(.+?)\((\d+),(\d+)\): error (TS\d+): (.+)$', output, re.MULTILINE))
    if len(re.findall(r'\berror TS\d+:', output)) != len(matches):
        raise SystemExit('Unrecognized TypeScript error; compiler failures cannot use source exceptions')
    for match in matches:
        path, line, _, code, message = match.groups()
        source = assets / path
        if not source.is_file():
            raise SystemExit('TypeScript diagnostic references missing source: ' + path)
        lines = source.read_text().splitlines()
        anchor = '\n'.join(lines[max(0, int(line) - 2):int(line) + 1])
        message = re.sub(r"'[^']*?/node_modules/", "'<frontend>/node_modules/", message)
        message = message.replace(str(assets), '<frontend>')
        key = json.dumps([path, code, message, hashlib.sha256(anchor.encode()).hexdigest()], separators=(',', ':'))
        result[key] += 1
    return result


def frontend():
    baseline = json.loads(BASELINE.read_text())
    assets = ROOT / 'assets'
    proc = subprocess.run(['pnpm', 'exec', 'tsc', '--pretty', 'false', '--noEmit'], cwd=assets,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    actual = diagnostics(proc.stdout, assets)
    allowed = collections.Counter(baseline['typescript']['diagnostics'])
    additions = actual - allowed
    if proc.returncode not in (0, 2) or (proc.returncode and not actual):
        print(proc.stdout)
        raise SystemExit('TypeScript execution failed independently of known diagnostics')
    if additions:
        for key, count in additions.items():
            path, code, message, _ = json.loads(key)
            print(f'{path}: {code}: {message} ({count} new)')
        raise SystemExit('New TypeScript diagnostics require a fix, not an automatic baseline update')
    print(f'TypeScript gate passed: {sum(actual.values())} inherited diagnostics; zero additions')


def backend():
    baseline = json.loads(BASELINE.read_text())
    excluded = baseline['go_test']['packages']
    for package, files in excluded.items():
        actual = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in (ROOT / package).glob('*_test.go')}
        if actual != files:
            raise SystemExit('Quarantined upstream tests changed: ' + package)
    run(['go', 'build', './...'])
    packages = run(['go', 'list', './...'], capture=True).splitlines()
    module = run(['go', 'list', '-m'], capture=True).strip()
    selected = [package for package in packages if package.removeprefix(module + '/') not in excluded]
    run(['go', 'test', '-race', '-count=1', '-timeout=10m', *selected])
    run(['go', 'vet', './pkg/oidc', './pkg/auth', './pkg/authpolicy', './pkg/setting',
         './inventory', './application/dependency', './middleware', './routers/controllers',
         './service/user', './service/basic'])
    print('Backend gate passed; only source-pinned legacy test packages are quarantined')


def database():
    if os.environ.get('OIDC_TEST_DRIVER') not in ('postgres', 'mysql') or not os.environ.get('OIDC_TEST_DSN'):
        raise SystemExit('Use an owned disposable DB with OIDC_TEST_DRIVER and OIDC_TEST_DSN')
    run(['go', 'run', './scripts/db-ready'])
    run(['go', 'test', '-race', '-count=1', '-timeout=15m', './routers/controllers', './inventory',
         '-run', 'TestOpenID|TestLogto|TestManagedAccount|TestExternalAuth'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage', required=True, choices=['backend', 'frontend', 'database'])
    arguments = parser.parse_args()
    temporary = ROOT / '.scratch/oidc-pro/tmp'
    temporary.mkdir(parents=True, exist_ok=True)
    os.environ['TMPDIR'] = str(temporary)
    {'backend': backend, 'frontend': frontend, 'database': database}[arguments.stage]()
