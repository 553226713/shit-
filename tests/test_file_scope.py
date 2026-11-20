import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from yt_client.file_scope import (
    DEFAULT_MONITORED_EXTENSIONS, excludes_directory, normalize_monitored_extensions, normalize_scope,
    scope_environment,
)
from yt_client import yt_config


class FileScopeTests(unittest.TestCase):
    def test_monitored_roots_have_no_directory_or_file_type_exclusions(self):
        self.assertTrue(all(not values for values in normalize_scope().values()))

    def test_saved_legacy_restrictions_no_longer_exclude_monitored_files(self):
        settings = yt_config.normalize_settings({'file_scope': {
            'excluded_directories': ['tmp', '.git', 'node_modules', 'custom-cache'],
            'included_extensions': ['.java'], 'included_names': ['Customfile']}})
        effective = yt_config.effective_config(settings, None)
        self.assertTrue(all(not values for values in effective['file_scope'].values()))
        self.assertEqual(effective['monitored_extensions'], list(DEFAULT_MONITORED_EXTENSIONS))

    def test_runtime_clears_inherited_scope_restrictions(self):
        with patch.dict(os.environ, {'YT_SCOPE_EXCLUDED_DIRS': 'tmp', 'YT_SCOPE_EXTENSIONS': '.java',
                                    'YT_EXCLUDED_DIRS': '/inherited'}):
            env = scope_environment()
        self.assertEqual(env['YT_SCOPE_EXCLUDED_DIRS'], '')
        self.assertEqual(env['YT_SCOPE_EXTENSIONS'], '')
        self.assertEqual(env['YT_SCOPE_NAMES'], '')
        self.assertEqual(env['YT_EXCLUDED_DIRS'], '')

    def test_new_file_exclusions_are_absolute_and_scoped_to_the_mount(self):
        settings = yt_config.normalize_settings({'excluded_directories': [
            '/projects/app/node_modules/', '/projects/app/node_modules',
            '/projects/app/缓存目录', '/projects/app-other/build', '/projects/app',
            '/', 'node_modules', '/invalid\npath', None,
        ]})
        effective = yt_config.effective_config(settings, None)
        paths = effective['excluded_directories']
        self.assertEqual(len(paths), 4)
        self.assertEqual(scope_environment(paths, Path('/projects/app'))['YT_EXCLUDED_DIRS'], '/')
        paths = [path for path in paths if path != '/projects/app']
        self.assertEqual(scope_environment(paths, Path('/projects/app'))['YT_EXCLUDED_DIRS'],
                         '/node_modules\n/缓存目录')
        self.assertNotEqual(yt_config.monitor_signature(effective),
                            yt_config.monitor_signature(dict(effective, excluded_directories=[])))

    def test_file_types_are_normalized_and_passed_to_engine(self):
        self.assertEqual(normalize_monitored_extensions('JAVA，.d.ts .java, PY'),
                         ['.d.ts', '.java', '.py'])
        with self.assertRaises(ValueError):
            normalize_monitored_extensions('src/*.java')
        settings = yt_config.normalize_settings({'monitored_extensions': ['PY', '.java']})
        effective = yt_config.effective_config(settings, None)
        extensions = effective['monitored_extensions']
        self.assertEqual(scope_environment(monitored_extensions=extensions)['YT_MONITORED_EXTENSIONS'],
                         '.java\n.py')
        self.assertNotEqual(yt_config.monitor_signature(effective),
                            yt_config.monitor_signature(dict(effective, monitored_extensions=[])))

    def test_default_scope_presets_can_be_disabled_or_cleared(self):
        defaults = yt_config.normalize_settings({})
        self.assertTrue(defaults['use_default_directory_exclusions'])
        self.assertTrue({'.java', '.js', '.py', '.ts'}.issubset(defaults['monitored_extensions']))
        names = scope_environment()['YT_EXCLUDED_DIR_NAMES'].splitlines()
        self.assertTrue({'node_modules', 'target', 'tmp', '__pycache__'}.issubset(names))
        custom = yt_config.normalize_settings({
            'use_default_directory_exclusions': False, 'monitored_extensions': [],
        })
        self.assertEqual(custom['monitored_extensions'], [])
        self.assertFalse(custom['use_default_directory_exclusions'])
        self.assertEqual(scope_environment(use_default_directory_exclusions=False)
                         ['YT_EXCLUDED_DIR_NAMES'], '')
        root = Path('/project')
        self.assertTrue(excludes_directory(root/'app/target', root, (), True))
        self.assertFalse(excludes_directory(root/'app/target-source', root, (), True))
        self.assertFalse(excludes_directory(root/'app/target', root, (), False))
        self.assertTrue(excludes_directory(root/'private/nested', root, ['/project/private'], False))


if __name__ == '__main__':
    unittest.main()
