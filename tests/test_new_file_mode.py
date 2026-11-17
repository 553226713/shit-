import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from yt_client import yt_config


class NewFileModeTests(unittest.TestCase):
    def test_default_and_legacy_settings_create_plain_files(self):
        self.assertEqual(yt_config.default_settings()['encryption']['new_file_mode'], 'plain')
        self.assertEqual(yt_config.normalize_settings({'encryption': {'key': 'test'}})['encryption']['new_file_mode'], 'plain')

    def test_encrypted_mode_persists_and_server_sync_does_not_override_it(self):
        settings = yt_config.normalize_settings({'encryption': {'key': 'local', 'new_file_mode': 'encrypted'}})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'settings.json'
            yt_config.save_settings(settings, path)
            settings = yt_config.load_settings(path)
        effective = yt_config.effective_config(settings, {'encryption_key': 'remote', 'new_file_mode': 'plain'})
        self.assertEqual(effective['encryption']['key'], 'remote')
        self.assertEqual(effective['encryption']['new_file_mode'], 'encrypted')
        text = yt_config.build_sgfs_conf(effective)
        self.assertIn('new_file_mode ==||== encrypted', text)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'sgfs.conf'; path.write_text(text)
            key, programs, _ = yt_config.parse_sgfs_conf(path)
        self.assertEqual(key, 'remote')
        self.assertNotIn('new_file_mode', programs)

    def test_invalid_modes_are_rejected(self):
        for mode in ('unknown', '', None, [], True):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                yt_config.normalize_settings({'encryption': {'new_file_mode': mode}})
