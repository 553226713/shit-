import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from yt_client.monitoring import auto_service


class StartupTests(unittest.TestCase):
    def test_terminal_authorization_uses_system_prompt_before_start(self):
        with patch.object(auto_service, 'PACKAGED', True), \
                patch.object(auto_service.sys.stdin, 'isatty', return_value=True), \
                patch.object(auto_service, 'authorized', side_effect=[False, True]), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(auto_service, 'start') as start, \
                patch.object(subprocess, 'run', return_value=Mock(returncode=0)) as run, \
                patch('builtins.print'):
            self.assertEqual(auto_service.authorize_in_terminal(), 0)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], ['/usr/bin/sudo', '--',
                                                str(auto_service.ROOT/'mount-broker'), '--authorize-only'])
        self.assertNotIn('stdin', run.call_args.kwargs)
        self.assertNotIn('capture_output', run.call_args.kwargs)
        start.assert_called_once_with()

    def test_terminal_authorization_rejects_noninteractive_launch(self):
        with patch.object(auto_service, 'PACKAGED', True), \
                patch.object(auto_service.sys.stdin, 'isatty', return_value=False), \
                patch.object(subprocess, 'run') as run, patch('builtins.print'):
            self.assertEqual(auto_service.authorize_in_terminal(), 1)
        run.assert_not_called()

    def test_first_authorization_runs_from_the_desktop_before_starting_service(self):
        environment = {'LD_PRELOAD': '/bad.so', 'LD_LIBRARY_PATH': '/bad',
                       'LD_AUDIT': '/audit.so', 'DISPLAY': ':0',
                       'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/desktop-bus'}
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(auto_service, 'PACKAGED', True), \
                patch.object(auto_service, 'authorized', side_effect=[False, True]), \
                patch.object(auto_service, 'install'), \
                patch.object(subprocess, 'run', side_effect=[
                    subprocess.CompletedProcess([], 0, '', ''),
                    subprocess.CompletedProcess([], 0, '', ''),
                ]) as run:
            auto_service.start()
        first, second = run.call_args_list
        self.assertEqual(first.args[0], ['/usr/bin/pkexec', '--disable-internal-agent',
                                        str(auto_service.ROOT/'mount-broker'), '--authorize-only'])
        self.assertEqual(second.args[0], ['systemctl', '--user', 'start', auto_service.SERVICE])
        for call in (first, second):
            self.assertEqual(call.kwargs['env'], {name: environment[name]
                                                 for name in ('DISPLAY', 'DBUS_SESSION_BUS_ADDRESS')})
        self.assertIn('UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT', auto_service.unit_text())

    def test_saved_authorization_skips_prompt_and_cancellation_stops_start(self):
        with patch.object(auto_service, 'PACKAGED', True), \
                patch.object(auto_service, 'install'), \
                patch.object(auto_service, '_systemctl', return_value=Mock(returncode=0)) as systemctl, \
                patch.object(auto_service, 'authorized', return_value=True) as authorized, \
                patch.object(subprocess, 'run', return_value=Mock(returncode=126)) as pkexec:
            auto_service.start()
            systemctl.assert_called_once_with('start', auto_service.SERVICE)
            pkexec.assert_not_called()
            systemctl.reset_mock()
            authorized.return_value = False
            with self.assertRaisesRegex(RuntimeError, '已取消管理员授权'):
                auto_service.start()
            systemctl.assert_not_called()

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
    def test_successful_status_query_ignores_loader_warning_on_stderr(self):
        with patch.object(Path, 'exists', return_value=True), \
                patch.object(auto_service, '_systemctl', return_value=Mock(
                    stdout='ActiveState=active\nResult=success\n',
                    stderr='ERROR: ld.so: object from LD_PRELOAD cannot be preloaded: ignored.',
                    returncode=0)), \
                patch.object(auto_service.yt_config, 'read_json', return_value={'state': 'running'}):
            status = auto_service.status()
        self.assertTrue(status['active'])
        self.assertIsNone(status['error'])

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
