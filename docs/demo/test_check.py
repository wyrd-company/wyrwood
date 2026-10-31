# ---
# relationships:
#   verifies: overview
# ---
"""Exercise freshness and link failures without Docker or a browser."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('media_check', Path(__file__).with_name('check.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class MediaCheckTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ('docs/demo', 'docs/user/assets', 'internal/web/frontend/src'):
            (self.root / directory).mkdir(parents=True)
        (self.root / 'docs/user/overview.md').write_text('# Overview\n![UI](assets/web-example.png)\n[Start](#overview)\n')
        (self.root / 'docs/user/docs.yml').write_text('assets:\n  - assets/web-example.png\n')
        (self.root / 'docs/user/assets/web-example.png').write_bytes(b'\x89PNG\r\n\x1a\nfixture')
        self.source = self.root / 'internal/web/frontend/src/app.tsx'
        self.source.write_text('original')
        self.addCleanup(patch.stopall)
        patch.object(check, 'ROOT', self.root).start()
        patch.object(check, 'RECEIPT', self.root / 'docs/demo/screenshots.json').start()
        self.assertEqual(self.run_check('--record'), 0)

    def run_check(self, *args):
        with patch.object(sys, 'argv', ['check.py', *args]), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return check.main()

    def test_record_and_unchanged_check(self):
        self.assertEqual(self.run_check(), 0)

    def test_changed_added_and_removed_source(self):
        self.source.write_text('changed')
        self.assertEqual(self.run_check(), 1)
        self.assertEqual(self.run_check('--record'), 0)
        added = self.source.with_name('new.tsx')
        added.write_text('new page')
        self.assertEqual(self.run_check(), 1)
        self.assertEqual(self.run_check('--record'), 0)
        added.unlink()
        self.assertEqual(self.run_check(), 1)

    def test_test_only_frontend_changes_preserve_receipt(self):
        for name in ('test-setup.ts', 'render-test.tsx', 'example.test.tsx'):
            source = self.source.with_name(name)
            source.write_text('test fixture')
            self.assertEqual(self.run_check(), 0, name)
            self.assertEqual(self.run_check('--record'), 0)
            source.write_text('changed test fixture')
            self.assertEqual(self.run_check(), 0, name)
            source.unlink()
            self.assertEqual(self.run_check(), 0, name)
        self.source.write_text('production page changed')
        self.assertEqual(self.run_check(), 1)

    def test_changed_image(self):
        with (self.root / 'docs/user/assets/web-example.png').open('ab') as image:
            image.write(b'changed')
        self.assertEqual(self.run_check(), 1)

    def test_broken_link_anchor_and_manifest(self):
        page = self.root / 'docs/user/overview.md'
        for content in ('[Missing](absent.md)', '[Missing](#absent)'):
            page.write_text(content)
            self.assertEqual(self.run_check('--record'), 1)
        page.write_text('# Overview')
        (self.root / 'docs/user/docs.yml').write_text('assets:\n  - assets/absent.png')
        self.assertEqual(self.run_check('--record'), 1)


if __name__ == '__main__':
    unittest.main()
