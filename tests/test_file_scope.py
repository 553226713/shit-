import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from file_scope import normalize_scope, scope_environment
import yt_config


class FileScopeTests(unittest.TestCase):
    def test_monitored_roots_have_no_directory_or_file_type_exclusions(self):
        self.assertTrue(all(not values for values in normalize_scope().values()))

    def test_saved_legacy_restrictions_no_longer_exclude_monitored_files(self):
        settings = yt_config.normalize_settings({'file_scope': {
            'excluded_directories': ['tmp', '.git', 'node_modules', 'custom-cache'],
            'included_extensions': ['.java'], 'included_names': ['Customfile']}})
        effective = yt_config.effective_config(settings, None)
        self.assertTrue(all(not values for values in effective['file_scope'].values()))

    def test_runtime_clears_inherited_scope_restrictions(self):
        with patch.dict(os.environ, {'YT_SCOPE_EXCLUDED_DIRS': 'tmp', 'YT_SCOPE_EXTENSIONS': '.java'}):
            env = scope_environment({'excluded_directories': ['tmp']})
        self.assertEqual(env['YT_SCOPE_EXCLUDED_DIRS'], '')
        self.assertEqual(env['YT_SCOPE_EXTENSIONS'], '')
        self.assertEqual(env['YT_SCOPE_NAMES'], '')


if __name__ == '__main__':
    unittest.main()
