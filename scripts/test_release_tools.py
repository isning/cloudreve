"""Regression tests for fail-closed quality gates using workspace-local fixtures."""
import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('release_gate', ROOT / 'scripts/verify.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class TypeScriptGateTests(unittest.TestCase):
    def setUp(self):
        directory = ROOT / '.scratch/oidc-pro/tmp'
        directory.mkdir(parents=True, exist_ok=True)
        self.root = pathlib.Path(tempfile.mkdtemp(prefix='gate-test-', dir=directory))
        self.assets = self.root / 'assets'
        (self.assets / 'src').mkdir(parents=True)
        self.source = self.assets / 'src/legacy.ts'
        self.source.write_text('const x: number = "old";\n')
        self.output = 'src/legacy.ts(1,7): error TS2322: Type string is not assignable to number.\n'
        self.allowed = gate.diagnostics(self.output, self.assets)
        self.baseline = self.root / 'baseline.json'
        self.baseline.write_text(json.dumps({'typescript': {'diagnostics': dict(self.allowed)}}))

    def check(self, output, code=2):
        with patch.object(gate, 'ROOT', self.root), patch.object(gate, 'BASELINE', self.baseline), \
                patch.object(gate.subprocess, 'run', return_value=types.SimpleNamespace(stdout=output, returncode=code)):
            gate.frontend()

    def test_original_diagnostic_is_accepted(self):
        self.check(self.output)

    def test_global_compiler_error_with_known_diagnostic_is_rejected(self):
        with self.assertRaises(SystemExit):
            self.check(self.output + 'error TS2688: Cannot find type definition file for missing-package.\n')

    def test_duplicate_diagnostic_cannot_hide_in_an_existing_exception(self):
        with self.assertRaises(SystemExit):
            self.check(self.output + self.output)

    def test_changed_source_invalidates_exception(self):
        self.source.write_text('const x: number = "new";\n')
        with self.assertRaises(SystemExit):
            self.check(self.output)

    def test_fatal_compiler_failure_is_rejected(self):
        with self.assertRaises(SystemExit):
            self.check('Unexpected compiler failure', 1)

    def test_removed_diagnostics_pass(self):
        self.check('', 0)


class FrontendBootstrapTests(unittest.TestCase):
    def setUp(self):
        directory = ROOT / '.scratch/oidc-pro/tmp'
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = pathlib.Path(tempfile.mkdtemp(prefix='bootstrap-test-', dir=directory))
        self.origin = self.directory / 'origin'
        self.origin.mkdir()
        self.git(self.origin, 'init')
        self.git(self.origin, 'config', 'user.name', 'Verification fixture')
        self.git(self.origin, 'config', 'user.email', 'fixture@example.invalid')
        (self.origin / 'source.txt').write_text('upstream fixture\n')
        self.git(self.origin, 'add', '.')
        self.git(self.origin, 'commit', '-m', 'Base fixture')
        (self.origin / 'source.txt').write_text('reviewed extension fixture\n')
        self.git(self.origin, 'add', '.')
        self.git(self.origin, 'commit', '-m', 'Extension fixture')
        self.commit = self.git(self.origin, 'rev-parse', 'HEAD').strip()
        self.root = self.directory / 'checkout'
        self.root.mkdir()
        self.git(self.root, 'init')
        self.git(self.root, 'config', 'user.name', 'Verification fixture')
        self.git(self.root, 'config', 'user.email', 'fixture@example.invalid')
        (self.root / '.gitmodules').write_text(
            '[submodule "assets"]\n\tpath = assets\n\turl = ' + self.origin.as_uri() + '\n')
        self.git(self.root, 'add', '.gitmodules')
        self.git(self.root, 'update-index', '--add', '--cacheinfo', '160000,' + self.commit + ',assets')
        self.git(self.root, 'commit', '-m', 'Pinned frontend fixture')

    def git(self, directory, *args):
        result = subprocess.run(['git', '-C', str(directory), *args], check=True,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout

    def bootstrap(self):
        return subprocess.run(['python3', str(ROOT / 'scripts/bootstrap-frontend.py'), '--root', str(self.root)],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env={**os.environ, 'GIT_ALLOW_PROTOCOL': 'file'})

    def test_fresh_checkout_and_rerun_restore_the_exact_commit(self):
        self.assertEqual(self.bootstrap().returncode, 0)
        self.assertEqual(self.git(self.root / 'assets', 'rev-parse', 'HEAD').strip(), self.commit)
        self.assertEqual(self.bootstrap().returncode, 0)

    def test_dirty_source_is_preserved(self):
        self.assertEqual(self.bootstrap().returncode, 0)
        path = self.root / 'assets/source.txt'
        path.write_text('uncommitted user change\n')
        result = self.bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('local changes', result.stderr)
        self.assertEqual(path.read_text(), 'uncommitted user change\n')

    def test_unexpected_local_commit_is_preserved(self):
        self.assertEqual(self.bootstrap().returncode, 0)
        assets = self.root / 'assets'
        self.git(assets, 'config', 'user.name', 'Verification fixture')
        self.git(assets, 'config', 'user.email', 'fixture@example.invalid')
        (assets / 'source.txt').write_text('committed user change\n')
        self.git(assets, 'add', '.')
        self.git(assets, 'commit', '-m', 'User fixture change')
        before = self.git(assets, 'rev-parse', 'HEAD')
        result = self.bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unexpected frontend revision', result.stderr)
        self.assertEqual(self.git(assets, 'rev-parse', 'HEAD'), before)

    def test_nonempty_frontend_directory_is_preserved(self):
        assets = self.root / 'assets'
        assets.mkdir()
        source = assets / 'source.txt'
        source.write_text('untracked user source\n')
        result = self.bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('nonempty frontend directory', result.stderr)
        self.assertEqual(source.read_text(), 'untracked user source\n')
        self.assertFalse((assets / '.git').exists())


if __name__ == '__main__':
    unittest.main()
