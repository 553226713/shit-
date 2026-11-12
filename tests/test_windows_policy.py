import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import windows_policy
import yt_config


class WindowsPolicyTests(unittest.TestCase):
    def test_name_matching_ignores_paths_case_and_extensions(self):
        self.assertEqual(yt_config.program_match_name(r'C:\Apps\IDEA64.EXE'), 'idea64')
        self.assertEqual(yt_config.match_windows_program('/opt/bin/Idea', ['IDEA64.EXE', 'IntelliJ IDEA', 'java.exe']), ['IDEA64.EXE', 'IntelliJ IDEA'])
        self.assertEqual(yt_config.match_windows_program('idea64', ['idea.exe']), [])
        self.assertEqual(yt_config.match_windows_program('', ['idea.exe']), [])

    def test_snapshot_merges_configured_policies_without_device_assignment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            path.write_text(json.dumps({'ok': True, 'encryption_keys': ['test-server-key'], 'assigned': [], 'applications': [
                '128', '员工', 'IDEA', 'idea64.exe|IDEA.EXE',
                '129', '管理员', 'IDEA', 'idea.exe',
                '129', '管理员', 'qmake', 'qmake.exe|moc.exe',
            ]}))
            result = windows_policy.read_snapshot(path)
            self.assertEqual(result['encryption_key'], 'test-server-key')
            self.assertEqual(result['windows_policy_ids'], [128, 129])
            self.assertEqual(len(result['windows_applications']), 2)
            self.assertEqual(result['windows_applications'][0]['processes'], ['idea64.exe', 'IDEA.EXE', 'idea.exe'])
            raw = json.loads(path.read_text()); raw['assigned'] = ['129']; path.write_text(json.dumps(raw))
            self.assertEqual(windows_policy.read_snapshot(path)['windows_applications'][0]['processes'], ['idea.exe'])
            raw['ok'] = False; path.write_text(json.dumps(raw))
            with self.assertRaises(ValueError):
                windows_policy.read_snapshot(path)

    def test_missing_or_ambiguous_server_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            for keys in ([], ['one', 'two']):
                path.write_text(json.dumps({'ok': True, 'applications': [], 'encryption_keys': keys}))
                with self.assertRaisesRegex(ValueError, '密钥'):
                    windows_policy.read_snapshot(path)

    def test_desktop_app_and_explicit_process_match_without_scanning_short_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            applications = Path(directory) / 'applications'; applications.mkdir()
            (applications / 'idea.desktop').write_text('[Desktop Entry]\nType=Application\nExec=/opt/bin/idea %f\n')
            with patch.dict('os.environ', {'XDG_DATA_HOME': directory, 'XDG_DATA_DIRS': directory}), patch('yt_config.shutil.which', side_effect=lambda name: name if name in ('/opt/bin/idea', 'qmake') else None):
                matches = yt_config.linux_program_matches(['IntelliJ IDEA', 'qmake.exe', 'solidworks'], [])
            self.assertEqual(set(matches), {'/opt/bin/idea', 'qmake'})
            self.assertNotIn('id', matches)

    def test_local_removal_excludes_derived_linux_match(self):
        settings = yt_config.normalize_settings({'programs': [{'name': 'IDEA', 'command': '/opt/idea', 'enabled': True}], 'trusted_programs': []})
        remote = {'trusted_programs': ['IDEA64.EXE']}
        with patch('yt_config.linux_program_matches', return_value={'/opt/idea': ['IDEA64.EXE']}):
            effective = yt_config.effective_config(settings, remote)
            self.assertIn('/opt/idea', effective['trusted_programs'])
        settings['local_overrides']['removed_server_programs'] = ['IDEA64.EXE']
        with patch('yt_config.linux_program_matches', wraps=yt_config.linux_program_matches):
            effective = yt_config.effective_config(settings, remote)
            self.assertNotIn('/opt/idea', effective['trusted_programs'])


if __name__ == '__main__':
    unittest.main()
