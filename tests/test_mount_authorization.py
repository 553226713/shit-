import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from yt_client.monitoring import mount_authorization as authorization


class AuthorizationTests(unittest.TestCase):
    def test_only_regular_root_owned_nonwritable_markers_authorize(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'authorized-users'
            directory.mkdir()
            marker = directory / '1000'
            with patch.object(authorization, 'DIRECTORY', directory):
                self.assertFalse(authorization.authorized(1000))
                marker.write_text('')
                info = SimpleNamespace(st_uid=0, st_mode=0o100644)
                def metadata(path):
                    return info if path == marker else SimpleNamespace(st_uid=0, st_mode=0o40755)
                with patch.object(Path, 'lstat', metadata):
                    self.assertTrue(authorization.authorized(1000))
                    self.assertFalse(authorization.authorized(0))
                    for uid, mode in [(1000, 0o100644), (0, 0o100666), (0, 0o120777), (0, 0o40755)]:
                        info.st_uid, info.st_mode = uid, mode
                        self.assertFalse(authorization.authorized(1000))

    def test_remember_is_root_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'authorized-users'
            with patch.object(authorization, 'DIRECTORY', directory), patch.object(os, 'geteuid', return_value=1000):
                with self.assertRaises(PermissionError):
                    authorization.remember(1000)
                self.assertFalse(directory.exists())

    def test_remember_repairs_old_permissions_and_reuses_record(self):
        real_fstat = os.fstat
        def root_metadata(fd):
            info = real_fstat(fd)
            return SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink)
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / 'app'; parent.mkdir(); parent.chmod(0o775)
            directory = parent / 'authorized-users'; directory.mkdir(); directory.chmod(0o775)
            marker = directory / '1000'; marker.write_text('existing approval'); marker.chmod(0o664)
            inode = marker.stat().st_ino
            with patch.object(authorization, 'DIRECTORY', directory), patch.object(os, 'geteuid', return_value=0), patch.object(os, 'fstat', side_effect=root_metadata):
                authorization.remember(1000)
                authorization.remember(1000)
            self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
            self.assertEqual(marker.stat().st_mode & 0o777, 0o644)
            self.assertEqual(marker.read_text(), 'existing approval')
            self.assertEqual(marker.stat().st_ino, inode)

    def test_remember_rejects_symlinks_special_files_and_hardlinks(self):
        real_fstat = os.fstat
        def root_metadata(fd):
            info = real_fstat(fd)
            return SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink)
        for kind in ('symlink', 'fifo', 'hardlink', 'directory'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary) / 'app'; parent.mkdir()
                directory = parent / 'authorized-users'; directory.mkdir()
                target = Path(temporary) / 'untouched'; target.write_text('keep'); target.chmod(0o600)
                marker = directory / '1000'
                if kind == 'symlink': marker.symlink_to(target)
                elif kind == 'fifo': os.mkfifo(marker)
                elif kind == 'hardlink': os.link(target, marker)
                else: marker.mkdir()
                with patch.object(authorization, 'DIRECTORY', directory), patch.object(os, 'geteuid', return_value=0), patch.object(os, 'fstat', side_effect=root_metadata):
                    with self.assertRaises(OSError):
                        authorization.remember(1000)
                self.assertEqual(target.read_text(), 'keep')
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_remember_rejects_non_root_owned_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'authorized-users'
            with patch.object(authorization, 'DIRECTORY', directory), patch.object(os, 'geteuid', return_value=0), patch.object(os, 'fstat', return_value=SimpleNamespace(st_uid=1000)):
                with self.assertRaises(PermissionError):
                    authorization.remember(1000)
            self.assertFalse(directory.exists())

    def test_authorization_checks_parent_ownership(self):
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=1000, st_mode=0o40755)):
            self.assertFalse(authorization.authorized(1000))
