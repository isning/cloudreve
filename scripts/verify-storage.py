#!/usr/bin/env python3
"""Run opt-in native storage gates against owned S3 and disposable databases."""
import argparse
import hashlib
import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATABASE_CASES = [
    'TestStorageLegacyGroupEditsPreserveGrantsAndOrdinarySettings',
    'TestStorageLegacyDefaultChangesRetainOtherGrants',
    'TestStorageConcurrentStartupPreservesPublicBehavior',
    'TestStoragePartialInitializationRecoversAfterRestart',
    'TestStoragePartialRelocationJournalUpgradeRecoversFromV2',
    'TestStorageV3JournalUpgradePreservesUnknownAttempts',
    'TestStorageRelocationSplitsOnlySelectedSharedVersions',
    'TestStorageRelocationTwoWorkersCommitOnlyOnce',
    'TestStorageRelocationExpiredWorkerCannotOverwriteWinningCommit',
    'TestStorageRelocationRestartsAtPlanAndVerifiedBoundaries',
    'TestStorageRelocationRecoversCommittedJournalBeforeTaskProgress',
    'TestStorageRelocationRechecksMissingOrInvalidVerification',
]


def run(stage, shard, count):
    temporary = ROOT / '.scratch/multi-storage/tmp'
    temporary.mkdir(parents=True, exist_ok=True)
    os.environ['TMPDIR'] = str(temporary)
    os.environ['CLOUDREVE_STORAGE_INTEGRATION'] = '1'
    program = pathlib.Path(os.environ.get('CLOUDREVE_S3_TEST_SERVER', ''))
    if not program.is_file():
        raise SystemExit('Provide CLOUDREVE_S3_TEST_SERVER from owned storage-tools.nix or your existing weed')
    if stage == 'database':
        if os.environ.get('OIDC_TEST_DRIVER') not in ('postgres', 'mysql') or not os.environ.get('OIDC_TEST_DSN'):
            raise SystemExit('Provide a disposable owned database driver/DSN; never an application database')
        subprocess.run(['go', 'run', './scripts/db-ready'], cwd=ROOT, check=True)
        cases = DATABASE_CASES
    elif stage == 'browser':
        os.environ['CLOUDREVE_STORAGE_BROWSER'] = '1'
        cases = ['TestStorageRealBrowserTwoBucketWorkflow', 'TestStorageRealBrowserMixedTreeWorkflow']
    elif stage == 'image':
        if not os.environ.get('CLOUDREVE_STORAGE_IMAGE'):
            raise SystemExit('Provide the locally built CLOUDREVE_STORAGE_IMAGE')
        cases = ['TestStorageRuntimeImageWorkflow']
    else:
        listed = subprocess.check_output(['go', 'test', './routers/controllers', '-list', '^TestStorage'], cwd=ROOT, text=True)
        cases = [name for name in listed.splitlines() if name.startswith('TestStorage')
                 and name not in ('TestStorageStartupWorker', 'TestStorageRuntimeImageWorkflow')
                 and not name.startswith('TestStorageRealBrowser')]
        cases = [name for name in cases if int(hashlib.sha256(name.encode()).hexdigest(), 16) % count == shard]
    listed = subprocess.check_output(['go', 'test', './routers/controllers', '-list', '^TestStorage'], cwd=ROOT, text=True).splitlines()
    if set(cases) - set(listed):
        raise SystemExit('Storage gate references missing tests: ' + ', '.join(sorted(set(cases) - set(listed))))
    if not cases:
        raise SystemExit('Storage gate matched no tests')
    print(f'Running {stage}: {len(cases)} top-level native storage cases (shard {shard + 1}/{count})', flush=True)
    subprocess.run(['go', 'test', '-v', '-race', './routers/controllers', '-count=1', '-timeout=30m',
                    '-run', '^(' + '|'.join(cases) + ')$'], cwd=ROOT, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage', required=True, choices=['native', 'database', 'browser', 'image'])
    parser.add_argument('--shard', type=int, default=0)
    parser.add_argument('--shards', type=int, default=1)
    args = parser.parse_args()
    if args.shards < 1 or not 0 <= args.shard < args.shards:
        parser.error('shard must be in [0, shards)')
    run(args.stage, args.shard, args.shards)
