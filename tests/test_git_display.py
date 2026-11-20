import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from yt_client.compat.textconv import convert, MAGIC
from yt_client.compat.git import enable, git, quote_pattern, BEGIN, END


class GitDisplayTests(unittest.TestCase):
    def test_plain_file_passes_through_without_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'plain.java'; data = b'package test;\r\n// plain\n' * 5000
            path.write_bytes(data)
            output = io.BytesIO()
            with patch('yt_client.yt_config.load_settings', side_effect=AssertionError('No policy needed')):
                convert(path, output)
            self.assertEqual(output.getvalue(), data)
            self.assertEqual(path.read_bytes(), data)

    def test_unsupported_and_mismatched_cipher_emit_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'encrypted.java'
            for valid_format in [False, True]:
                data = bytearray(1024); data[:32] = MAGIC
                if valid_format:
                    data[85:89] = (301).to_bytes(4, 'little'); data[-5:] = b'[END]'
                path.write_bytes(data)
                output = io.BytesIO()
                with patch('yt_client.yt_config.load_settings', return_value={}), patch('yt_client.yt_config.load_remote_policy', return_value=None), patch('yt_client.yt_config.effective_config', return_value={'encryption': {'key': 'wrong-policy'}}), self.assertRaises(ValueError):
                    convert(path, output)
                self.assertEqual(output.getvalue(), b'')
                self.assertEqual(path.read_bytes(), data)

    def test_local_attributes_preserve_custom_drivers_and_literal_filenames(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            git(repo, 'init', '-q')
            for name in ['普通 name[1].java', 'custom.java', 'plain.java']:
                (repo / name).write_bytes(MAGIC + b'x' * 1100 if name != 'plain.java' else b'class Plain {}')
            git(repo, 'add', '.')
            info = repo / '.git/info/attributes'
            info.write_text('custom.java diff=existing')
            index = (repo / '.git/index').read_bytes()
            first = enable(repo, '/example/textconv')
            self.assertEqual(first['encrypted_text_files'], 1)
            self.assertEqual(first['existing_diff_rules_preserved'], ['custom.java'])
            attrs = info.read_bytes()
            second = enable(repo, '/example/textconv')
            self.assertEqual(second['encrypted_text_files'], 1)
            self.assertEqual(info.read_bytes(), attrs)
            self.assertEqual((repo / '.git/index').read_bytes(), index)
            self.assertIn(b'diff: shit-encryption', git(repo, 'check-attr', 'diff', '--', '普通 name[1].java'))
            self.assertIn(b'diff: unspecified', git(repo, 'check-attr', 'diff', '--', 'plain.java'))
            self.assertEqual(git(repo, 'config', '--local', '--get', 'diff.shit-encryption.cachetextconv'), b'false\n')
            saved = json.loads(info.with_name('shit-encryption-display-backup.json').read_text())
            self.assertEqual(saved['attributes'], 'custom.java diff=existing')

    def test_managed_entry_updates_without_reconfiguring_with_legacy_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp)/'repo';repo.mkdir()
            config=Path(tmp)/'config';config.mkdir()
            (config/'settings.json').write_text(json.dumps({'file_scope': {'included_extensions': ['.custom']}}))
            git(repo,'init','-q')
            (repo/'Encrypted.custom').write_bytes(MAGIC+b'cipher sample')
            git(repo,'add','Encrypted.custom')
            first=enable(repo,'/first/location',config)
            self.assertEqual(first['encrypted_text_files'],0)
            for directory in ('node_modules', 'local'):
                (repo/directory).mkdir()
                (repo/directory/'Encrypted.custom').write_bytes(MAGIC+b'cipher sample')
            git(repo,'add','node_modules','local')
            (config/'settings.json').write_text(json.dumps({
                'monitored_extensions': ['.custom'],
                'excluded_directories': [str(repo/'local')],
            }))
            self.assertEqual(enable(repo,'/first/location',config)['encrypted_text_files'],1)
            (config/'settings.json').write_text(json.dumps({'monitored_extensions': []}))
            filtered=enable(repo,'/first/location',config)
            self.assertEqual(filtered['encrypted_text_files'],0)
            self.assertIn(b'diff: unspecified',git(repo,'check-attr','diff','--','Encrypted.custom'))
            enable(repo,'/moved/location',config)
            self.assertEqual(git(repo,'config','--get','diff.shit-encryption.textconv'),b'/moved/location\n')
            git(repo,'config','diff.shit-encryption.textconv','/user/custom')
            with self.assertRaises(ValueError):enable(repo,'/other/location',config)


if __name__ == '__main__':
    unittest.main()
