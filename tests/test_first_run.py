import sys
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import yt_config

class FirstRunTests(unittest.TestCase):
    def test_login_success_is_not_lost_when_log_grows(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'files/bin').mkdir(parents=True)
            (root / 'files/log').mkdir()
            def run(command, **kwargs):
                (root / 'files/log/svchost.log').write_text('LoginEnd.\n' + 'subsequent events\n' * 2000)
                return CompletedProcess(command, 124, b'', b'')
            with patch('yt_config.shutil.which', return_value='/usr/bin/bwrap'), patch('windows_policy.prepare_bridge', return_value=root / 'bridge.so'), patch('yt_config.subprocess.run', side_effect=run):
                yt_config.refresh_native_client(root, '127.0.0.1', 20)
            self.assertTrue((root / 'files/bin/sysinfo').is_dir())

    def test_windows_only_server_policy_does_not_require_linux_policy_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'files/bin').mkdir(parents=True)
            policy = yt_config.parse_native_client_root(root, '127.0.0.1')
            self.assertEqual(policy['encryption_key'], '')
            self.assertEqual(policy['server'], '127.0.0.1')
