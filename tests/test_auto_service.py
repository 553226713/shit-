import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import auto_service


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
