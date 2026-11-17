import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gio, GLib, Gtk
from yt_client.ui.system_tray import SystemTray
from yt_client.ui.yt_control import ClientWindow, YTControl
from yt_client import yt_config
from yt_client.monitoring import auto_service


class TrayTests(unittest.TestCase):
    def setUp(self):
        self.tray = SystemTray.__new__(SystemTray)
        self.tray.activation_token = None
        self.tray.on_open = Mock()
        self.invocation = Mock()

    def item(self, method, parameters):
        self.tray._item_method(None, None, None, None, method, parameters, self.invocation)

    def test_token_and_double_click_timestamp_reach_window(self):
        self.item('ProvideXdgActivationToken', GLib.Variant('(s)', ('wayland-token',)))
        with patch('yt_client.ui.system_tray.GLib.idle_add', side_effect=lambda callback, *args: callback(*args)):
            self.item('XAyatanaSecondaryActivate', GLib.Variant('(u)', (1234,)))
        self.tray.on_open.assert_called_once_with('wayland-token', 1234)
        self.assertIsNone(self.tray.activation_token)

    def test_menu_open_preserves_timestamp(self):
        self.tray.activation_token = 'menu-token'
        with patch('yt_client.ui.system_tray.GLib.idle_add', side_effect=lambda callback, *args: callback(*args)):
            self.tray._menu_method(None, None, None, None, 'Event', GLib.Variant('(isvu)', (2, 'clicked', GLib.Variant('i', 0), 5678)), self.invocation)
        self.tray.on_open.assert_called_once_with('menu-token', 5678)

    def test_tray_open_overrides_hidden_startup(self):
        app = SimpleNamespace(start_hidden=True, activate=Mock())
        YTControl._show_window(app, 'token', 42)
        self.assertFalse(app.start_hidden)
        self.assertEqual(app._activation_token, 'token')
        self.assertEqual(app._activation_timestamp, 42)
        app.activate.assert_called_once()


@unittest.skipUnless(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'), 'requires a graphical session')
class WindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = Gtk.Application(application_id='com.yangtu.ytconfig.tests', flags=Gio.ApplicationFlags.NON_UNIQUE)
        cls.app.register(None)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='yt-window-test-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        settings_path = self.directory / 'settings.json'
        real_load, real_save = yt_config.load_settings, yt_config.save_settings
        real_remote = yt_config.load_remote_policy
        real_save({'encryption': {'key': 'window-test-key'}, 'directories': [],
                   'trusted_programs': [], 'server': {'host': '', 'auto_update': False}}, settings_path)
        patches = [
            patch.dict(os.environ, {'YT_CONTROL_SKIP_MONITOR_START': '1'}),
            patch.object(yt_config, 'STATE_DIR', self.directory / 'state'),
            patch.object(yt_config, 'load_settings', side_effect=lambda: real_load(settings_path)),
            patch.object(yt_config, 'load_remote_policy', side_effect=lambda: real_remote(self.directory / 'remote.json')),
            patch.object(yt_config, 'save_settings', side_effect=lambda value: real_save(value, settings_path)),
            patch('yt_client.monitoring.auto_service.status', return_value={'active': False, 'state': 'inactive', 'runtime': {}}),
            patch.object(ClientWindow, '_engine_ready', return_value=True),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def test_close_hides_and_preserves_unapplied_draft(self):
        window = ClientWindow(self.app)
        window.server_page.server_host.set_text('unapplied.example')
        window.set_visible(True)
        self.assertTrue(window._on_close())
        self.assertFalse(window.get_visible())
        self.assertEqual(yt_config.load_settings()['server']['host'], '')
        self.assertEqual(window.server_page.server_host.get_text(), 'unapplied.example')
        window.destroy()

    def test_directory_edits_persist_without_saving_server_draft(self):
        window = ClientWindow(self.app)
        folder = self.directory / 'monitored'; folder.mkdir()
        window.server_page.server_host.set_text('unapplied.example')
        window._directory_selected(folder)
        self.assertEqual(yt_config.load_settings()['directories'], [{'path': str(folder), 'enabled': True}])
        self.assertEqual(yt_config.load_settings()['server']['host'], '')
        window._delete_directory(str(folder))
        self.assertEqual(yt_config.load_settings()['directories'], [])
        self.assertTrue(folder.is_dir())
        self.assertEqual(window.server_page.server_host.get_text(), 'unapplied.example')
        window.destroy()

    def test_first_sync_starts_monitor_when_server_key_arrives(self):
        window = ClientWindow(self.app)
        settings = yt_config.normalize_settings({'directories': [], 'encryption': {'key': ''}})
        policy = yt_config.normalize_remote_policy({'encryption_key': 'test-server-key'})
        window.auto_running = False
        window._start_monitor_when_ready = True
        with patch('yt_client.ui.yt_control.yt_config.load_settings', return_value=settings), patch('yt_client.ui.yt_control.yt_config.load_remote_policy', return_value=policy), patch.object(window, '_run_auto_action') as action:
            window._policy_updated(policy, None)
            action.assert_called_once_with(auto_service.start)
            action.reset_mock()
            window._start_monitor_when_ready = False
            window._policy_updated(policy, None)
            action.assert_not_called()
        window.destroy()

    def test_directory_changes_coalesce_while_monitor_refreshes(self):
        window = ClientWindow(self.app)
        window._monitor_refresh_running = True
        with patch('yt_client.ui.yt_control.GLib.timeout_add') as schedule:
            window._queue_monitor_refresh()
            window._queue_monitor_refresh()
            schedule.assert_not_called()
            self.assertTrue(window._monitor_refresh_pending)
            window._monitor_refresh_running = False
            window._queue_monitor_refresh()
            schedule.assert_called_once()
        window.destroy()

    def test_new_file_format_saves_without_claiming_inactive_monitor_is_effective(self):
        window = ClientWindow(self.app)
        window.new_encrypted.set_active(True)
        self.assertEqual(yt_config.load_settings()['encryption']['new_file_mode'], 'encrypted')
        self.assertNotEqual(window.creation_feedback.get_text(), '已生效')
        window.destroy()

    def test_failed_monitor_displays_error_instead_of_only_not_running(self):
        window = ClientWindow(self.app)
        status = {'active': False, 'state': 'failed', 'runtime': {},
                  'error': 'policy cannot be read'}
        with patch('yt_client.ui.yt_control.auto_service.status', return_value=status):
            window._refresh_auto_status()
        self.assertIn('policy cannot be read', window.auto_summary.get_text())
        self.assertFalse(window.auto_running)
        window.destroy()



class SyncTests(unittest.TestCase):
    def test_monitor_signature_ignores_sync_metadata_but_tracks_engine_changes(self):
        import copy
        settings = yt_config.normalize_settings({'encryption': {'key': 'test-key'}, 'directories': ['/one']})
        before = yt_config.effective_config(settings, None)
        after = copy.deepcopy(before)
        after['generated_at'] = 'new-sync-time'
        self.assertEqual(yt_config.monitor_signature(before), yt_config.monitor_signature(after))
        after['encryption']['new_file_mode'] = 'encrypted'
        self.assertNotEqual(yt_config.monitor_signature(before), yt_config.monitor_signature(after))
        after = copy.deepcopy(before)
        after['directories'][0]['enabled'] = False
        self.assertNotEqual(yt_config.monitor_signature(before), yt_config.monitor_signature(after))

    def test_policy_sync_preserves_local_edits_during_network_request(self):
        old = yt_config.normalize_settings({'directories': ['/old'], 'trusted_programs': ['old-editor']})
        latest = yt_config.normalize_settings({'directories': ['/new'], 'trusted_programs': ['new-editor'],
                                               'encryption': {'new_file_mode': 'encrypted'}})
        with patch('yt_client.yt_config.fetch_policy', return_value={'trusted_programs': []}), patch('yt_client.yt_config.load_settings', return_value=latest), patch('yt_client.yt_config.save_remote_policy'), patch('yt_client.yt_config.write_effective_runtime_config'), patch('yt_client.yt_config.save_settings') as save:
            yt_config.update_policy(old)
        self.assertEqual(save.call_args.args[0]['directories'], latest['directories'])
        self.assertEqual(save.call_args.args[0]['trusted_programs'], ['new-editor'])
        self.assertEqual(save.call_args.args[0]['encryption']['new_file_mode'], 'encrypted')


if __name__ == '__main__':
    unittest.main()
