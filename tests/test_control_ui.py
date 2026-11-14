import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gio, GLib, Gtk
from system_tray import SystemTray
from yt_control import ClientWindow, YTControl
import yt_config


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
        with patch('system_tray.GLib.idle_add', side_effect=lambda callback, *args: callback(*args)):
            self.item('XAyatanaSecondaryActivate', GLib.Variant('(u)', (1234,)))
        self.tray.on_open.assert_called_once_with('wayland-token', 1234)
        self.assertIsNone(self.tray.activation_token)

    def test_menu_open_preserves_timestamp(self):
        self.tray.activation_token = 'menu-token'
        with patch('system_tray.GLib.idle_add', side_effect=lambda callback, *args: callback(*args)):
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

    def test_close_hides_without_blocking_save(self):
        window = ClientWindow(self.app)
        window.dirty = True
        with patch.object(window, '_save') as save:
            window.set_visible(True)
            self.assertTrue(window._on_close())
            self.assertFalse(window.get_visible())
            save.assert_not_called()
        self.assertIs(window.directory_list.get_root(), window)
        self.assertIsNone(window.stack.get_child_by_name('directories'))
        self.assertIsNotNone(window.stack.get_child_by_name('overview'))
        window.destroy()

    def test_directory_add_delete_persist_and_queue_refresh(self):
        window = ClientWindow(self.app)
        window.settings = yt_config.normalize_settings({'directories': [], 'trusted_programs': []})
        window.remote = None
        with patch('yt_control.yt_config.save_settings', side_effect=lambda settings: settings) as save, patch('yt_control.yt_config.write_effective_runtime_config', side_effect=yt_config.effective_config), patch.object(window, '_queue_monitor_refresh') as refresh:
            window._directory_selected(Path('/tmp/monitor-ui-test'))
            self.assertEqual(window.effective['directories'][0]['path'], '/tmp/monitor-ui-test')
            window._delete_directory('/tmp/monitor-ui-test')
            self.assertEqual(window.effective['directories'], [])
            self.assertEqual(save.call_count, 2)
            self.assertEqual(refresh.call_count, 2)
        window.destroy()

    def test_first_sync_starts_monitor_when_server_key_arrives(self):
        window = ClientWindow(self.app)
        settings = yt_config.normalize_settings({'directories': [], 'encryption': {'key': ''}})
        policy = yt_config.normalize_remote_policy({'encryption_key': 'test-server-key'})
        window.auto_running = False
        with patch('yt_control.yt_config.load_settings', return_value=settings), patch('yt_control.yt_config.load_remote_policy', return_value=policy), patch.object(window, '_run_auto_action') as action:
            window._policy_updated(policy, None)
            action.assert_called_once_with(__import__('auto_service').start)
            action.reset_mock()
            window._start_monitor_when_ready = False
            window._policy_updated(policy, None)
            action.assert_not_called()
        window.destroy()

    def test_directory_changes_coalesce_while_monitor_refreshes(self):
        window = ClientWindow(self.app)
        window._monitor_refresh_running = True
        with patch('yt_control.GLib.timeout_add') as schedule:
            window._queue_monitor_refresh()
            window._queue_monitor_refresh()
            schedule.assert_not_called()
            self.assertTrue(window._monitor_refresh_pending)
            window._monitor_refresh_running = False
            window._queue_monitor_refresh()
            schedule.assert_called_once()
        window.destroy()

    def test_new_file_format_applies_and_refreshes_monitor(self):
        window = ClientWindow(self.app)
        window.settings = yt_config.normalize_settings({'encryption': {'key': 'test-policy'}})
        window.remote = None
        self.assertEqual(window.settings['encryption']['new_file_mode'], 'plain')
        window.new_file_mode.set_selected(1)
        with patch('yt_control.yt_config.save_settings', side_effect=lambda value: value), patch('yt_control.yt_config.write_effective_runtime_config', side_effect=yt_config.effective_config), patch('yt_control.yt_config.load_remote_policy', return_value=None), patch.object(window, '_queue_monitor_refresh') as refresh:
            window._apply_new_file_mode()
            self.assertEqual(window.effective['encryption']['new_file_mode'], 'encrypted')
            refresh.assert_called_once()
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

    def test_policy_sync_preserves_directory_edits_during_network_request(self):
        old = yt_config.normalize_settings({'directories': ['/old']})
        latest = yt_config.normalize_settings({'directories': ['/new']})
        with patch('yt_config.fetch_policy', return_value={'trusted_programs': []}), patch('yt_config.load_settings', return_value=latest), patch('yt_config.save_remote_policy'), patch('yt_config.write_effective_runtime_config'), patch('yt_config.save_settings') as save:
            yt_config.update_policy(old)
        self.assertEqual(save.call_args.args[0]['directories'], latest['directories'])


if __name__ == '__main__':
    unittest.main()
