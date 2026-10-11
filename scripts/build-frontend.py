#!/usr/bin/env python3
"""Build and package the pinned community frontend without deleting artifacts."""
import argparse
import hashlib
import json
import re
import pathlib
import subprocess
import zipfile
from importlib.util import module_from_spec, spec_from_file_location

root = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--stage', choices=['build', 'package', 'all'], default='all')
parser.add_argument('--version', help='Release version to write into the embedded asset manifest')
args = parser.parse_args()

bootstrap_spec = spec_from_file_location('frontend_submodule', root / 'scripts/bootstrap-frontend.py')
frontend_submodule = module_from_spec(bootstrap_spec)
bootstrap_spec.loader.exec_module(frontend_submodule)

def provenance():
    commit = subprocess.check_output(['git', '-C', str(root / 'assets'), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != frontend_submodule.pinned_commit(root):
        raise SystemExit('Frontend checkout does not match the pinned submodule')
    if subprocess.check_output(['git', '-C', str(root / 'assets'), 'status', '--porcelain'], text=True).strip():
        raise SystemExit('Frontend source has uncommitted changes')
    return {
        'commit': commit,
        'lockfile_sha256': hashlib.sha256((root / 'assets/pnpm-lock.yaml').read_bytes()).hexdigest(),
        'quality_baseline_sha256': hashlib.sha256((root / 'verification/upstream-baseline.json').read_bytes()).hexdigest(),
    }

if args.stage in ('build', 'all'):
    subprocess.run(['python3', str(root / 'scripts/bootstrap-frontend.py')], check=True)
    subprocess.run(['pnpm', 'dlx', 'pnpm@10.34.6', 'install', '--frozen-lockfile', '--ignore-scripts'], cwd=root / 'assets', check=True)
    subprocess.run(['python3', str(root / 'scripts/verify.py'), '--stage', 'frontend'], check=True)
    inputs = provenance()
    subprocess.run(['pnpm', 'dlx', 'pnpm@10.34.6', 'run', 'build'], cwd=root / 'assets', check=True)
    if inputs != provenance():
        raise SystemExit('Frontend inputs changed during the build')
    (root / 'assets/build/build-provenance.json').write_text(json.dumps(inputs, sort_keys=True) + '\n')
if args.stage in ('package', 'all'):
    build = root / 'assets/build'
    if not (build / 'index.html').is_file() or not (build / 'version.json').is_file():
        raise SystemExit('Complete Vite build required before packaging')
    recorded = build / 'build-provenance.json'
    if not recorded.is_file() or json.loads(recorded.read_text()) != provenance():
        raise SystemExit('Frontend build is stale or lacks provenance; rerun --stage build')
    version = json.loads((build / 'version.json').read_text())
    backend = (root / 'application/constants/constants.go').read_text()
    match = re.search(r'BackendVersion\s*=\s*"([^"]+)"', backend)
    if not match:
        raise SystemExit('Backend asset version could not be determined')
    version['version'] = args.version or match.group(1)
    (build / 'version.json').write_text(json.dumps(version) + '\n')
    target = root / 'application/statics/assets.zip'
    temporary = target.with_suffix('.zip.pending')
    with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as archive:
        for source in sorted(build.rglob('*')):
            if source.is_symlink():
                raise SystemExit('Refusing symlink in frontend build')
            if source.is_file():
                info = zipfile.ZipInfo('assets/build/' + source.relative_to(build).as_posix(), (1980, 1, 1, 0, 0, 0))
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, source.read_bytes())
    with zipfile.ZipFile(temporary) as archive:
        if archive.testzip() is not None:
            raise SystemExit('Corrupt frontend package')
    temporary.replace(target)
    print(f'Packaged {target.relative_to(root)}')
