import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import mount_authorization as authorization


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

    def test_remember_is_root_only_and_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'authorized-users'
            with patch.object(authorization, 'DIRECTORY', directory), patch.object(os, 'geteuid', return_value=1000):
                with self.assertRaises(PermissionError):
                    authorization.remember(1000)
                self.assertFalse(directory.exists())
            with patch.object(authorization, 'DIRECTORY', directory), patch.object(os, 'geteuid', return_value=0), patch.object(authorization, 'authorized', return_value=False):
                authorization.remember(1000)
                self.assertTrue((directory / '1000').is_file())
                with self.assertRaises(FileExistsError):
                    authorization.remember(1000)

    def test_authorization_checks_parent_ownership(self):
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=1000, st_mode=0o40755)):
            self.assertFalse(authorization.authorized(1000))
