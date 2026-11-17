import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from yt_client.monitoring import auto_service


class StartupTests(unittest.TestCase):
    def test_switch_persists_independently_from_monitor_start_stop(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(auto_service, 'UNIT_PATH', Path(directory) / 'service'), patch.object(auto_service, 'AUTOSTART_PATH', Path(directory) / 'startup.desktop'), patch.object(auto_service, '_systemctl', return_value=Mock(returncode=0)) as command:
            auto_service.set_autostart(True)
            self.assertTrue(auto_service.autostart_enabled())
            auto_service.stop()
            self.assertTrue(auto_service.autostart_enabled())
            auto_service.set_autostart(False)
            auto_service.start()
            self.assertFalse(auto_service.autostart_enabled())
            auto_service.restart()
            self.assertFalse(auto_service.autostart_enabled())
            self.assertNotIn('--now', [arg for call in command.call_args_list for arg in call.args])


class StatusTests(unittest.TestCase):
    def test_failed_service_reports_exit_even_with_stale_running_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            unit = directory / 'service'; unit.touch()
            for runtime, expected in [
                ({'state': 'running', 'error': None}, '127'),
                ({'state': 'failed', 'error': 'policy cannot be read'}, 'policy cannot be read'),
            ]:
                with self.subTest(runtime=runtime), patch.object(auto_service, 'UNIT_PATH', unit), patch.object(auto_service, '_systemctl', return_value=Mock(stdout='ActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=127\n', stderr='', returncode=0)), patch.object(auto_service.yt_config, 'read_json', return_value=runtime):
                    status = auto_service.status()
                self.assertFalse(status['active'])
                self.assertIn(expected, status['error'])

    def test_clean_stop_does_not_report_old_runtime_failure(self):
        with patch.object(Path, 'exists', return_value=True), patch.object(auto_service, '_systemctl', return_value=Mock(stdout='ActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=1\nExecMainStatus=0\n', stderr='', returncode=0)), patch.object(auto_service.yt_config, 'read_json', return_value={'state': 'failed', 'error': 'old failure'}):
            self.assertIsNone(auto_service.status()['error'])
