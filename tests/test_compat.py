import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from file_scope import scope_environment
from compat.manager import GitPatches
from compat.git import git
from compat.textconv import MAGIC
from compat.index_watch import IndexWatch
from unittest.mock import patch


class CompatibilityTests(unittest.TestCase):
    def test_process_view_overrides_are_not_forwarded(self):
        with patch.dict(os.environ, {'YT_COMPAT_RAW_CLIENTS': 'git',
                                    'YT_COMPAT_SCRIPT_CLIENTS': 'hg.py'}):
            environment = scope_environment()
        self.assertNotIn('YT_COMPAT_RAW_CLIENTS', environment)
        self.assertNotIn('YT_COMPAT_SCRIPT_CLIENTS', environment)

    def test_repository_patch_refreshes_on_index_change_without_touching_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp)/'repo';repo.mkdir()
            git(repo,'init','-q')
            (repo/'Existing.java').write_bytes(MAGIC+b'cipher sample one')
            git(repo,'add','Existing.java')
            with (Path(tmp)/'compat.log').open('w') as log:
                patcher=GitPatches(os.getuid(),os.getgid(),os.getgroups(),log)
                try:
                    def refresh():
                        deadline=time.monotonic()+10
                        while time.monotonic()<deadline:
                            patcher.tick([repo])
                            if patcher.active is None and patcher.signatures:
                                return
                            time.sleep(.01)
                        self.fail('Compatibility refresh timed out')
                    before=(repo/'.git/index').read_bytes()
                    refresh()
                    self.assertEqual((repo/'.git/index').read_bytes(),before)
                    self.assertIn(b'diff: shit-encryption',git(repo,'check-attr','diff','--','Existing.java'))
                    (repo/'New.java').write_bytes(MAGIC+b'cipher sample two')
                    git(repo,'add','New.java')
                    before=(repo/'.git/index').read_bytes()
                    refresh()
                    self.assertEqual((repo/'.git/index').read_bytes(),before)
                    self.assertIn(b'diff: shit-encryption',git(repo,'check-attr','diff','--','New.java'))
                    with patch('compat.manager.index_signature', side_effect=AssertionError('idle metadata polling')):
                        for _ in range(50): patcher.tick([repo])
                finally: patcher.close()

    def test_watch_detects_atomic_index_replacement_and_ignores_unrelated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp);directory=repo/'.git';directory.mkdir()
            (directory/'index').write_bytes(b'first')
            watch=IndexWatch()
            try:
                self.assertGreaterEqual(watch.fd,0)
                watch.sync([repo])
                (directory/'config').write_text('unrelated')
                self.assertEqual(watch.changed(),set())
                (directory/'index.lock').write_bytes(b'replacement')
                (directory/'index.lock').replace(directory/'index')
                self.assertEqual(watch.changed(),{repo})
                self.assertEqual(watch.changed(),set())
            finally:watch.close()


if __name__=='__main__':unittest.main()
