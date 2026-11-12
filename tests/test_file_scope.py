import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from file_scope import normalize_scope, scope_environment
import yt_config


class FileScopeTests(unittest.TestCase):
    def test_custom_scope_survives_settings_and_effective_policy(self):
        scope = {'excluded_directories': ['cache-extra'],
                 'included_extensions': ['.JAVA', '.java', '.txt'],
                 'included_names': ['Customfile']}
        settings = yt_config.normalize_settings({'file_scope': scope})
        effective = yt_config.effective_config(settings, None)
        self.assertEqual(effective['file_scope']['included_extensions'], ['.java', '.txt'])
        self.assertEqual(scope_environment(effective['file_scope'])['YT_SCOPE_EXCLUDED_DIRS'], 'cache-extra')

    def test_empty_extensions_allow_all_types_and_defaults_are_independent(self):
        self.assertEqual(scope_environment({'included_extensions': []})['YT_SCOPE_EXTENSIONS'], '')
        first = normalize_scope()
        first['excluded_directories'].clear()
        self.assertIn('node_modules', normalize_scope()['excluded_directories'])

    def test_scope_rejects_paths_and_environment_delimiters(self):
        for entry in ['../src', '.', '..', 'foo,bar', 'bad\0name', 'bad\nname']:
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                normalize_scope({'excluded_directories': [entry]})


if __name__ == '__main__':
    unittest.main()
