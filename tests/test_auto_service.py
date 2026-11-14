import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import auto_service


class StartupTests(unittest.TestCase):
    def test_packaged_service_recovers_without_interactive_authentication(self):
        import xml.etree.ElementTree as ET
        policy = ET.parse(Path(__file__).resolve().parents[1] / 'packaging/com.yangtu.ytconfig.mount.policy')
        action = policy.getroot().find('action')
        self.assertEqual(action.attrib['id'], 'com.yangtu.ytconfig.mount')
        self.assertEqual(action.find('annotate').text, '/usr/lib/shit-encryption/mount-broker')
        self.assertEqual([item.text for item in action.find('defaults')], ['auth_admin', 'auth_admin', 'auth_admin_keep'])
        with patch.object(auto_service, 'PACKAGED', True):
            self.assertIn('Restart=on-failure', auto_service.unit_text())
            self.assertIn('RestartPreventExitStatus=126 127', auto_service.unit_text())

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
