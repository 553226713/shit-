"""Run inside the disposable Ubuntu package test container."""
import os
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, '/usr/lib/shit-encryption')
import yt_config
from windows_policy import prepare_bridge
from engine2.artifacts import installed_engine, installed_textconv

assert yt_config.PACKAGED
assert str(yt_config.CONFIG_DIR).startswith(str(Path.home()))
settings = yt_config.default_settings()
assert settings['server']['host'] == ''
assert settings['encryption']['key'] == ''
assert settings['directories'] == []
assert not yt_config.REMOTE_POLICY_PATH.exists()
root = yt_config.discover_native_client()
assert root.is_relative_to(yt_config.STATE_DIR)
assert not (root / 'files/bin/LocalSet.ytf').exists()
with patch('subprocess.run', side_effect=AssertionError('Runtime compilation is forbidden')):
    assert prepare_bridge(root / 'files/bin/svchost').is_file()
    assert installed_engine(yt_config.ROOT/'vendor') == yt_config.ROOT/'vendor/ytfs-engine2'
    assert installed_textconv(yt_config.ROOT/'vendor') == yt_config.ROOT/'vendor/ytfs-textconv'

from yt_control import ClientWindow, Gtk, Gio
app = Gtk.Application(application_id='com.yangtu.package.test', flags=Gio.ApplicationFlags.NON_UNIQUE)
app.register(None)
window = ClientWindow(app)
window.server_host.set_text('127.0.0.1')
with patch.object(window, '_queue_monitor_refresh') as restart:
    assert window._save(quiet=True), 'First-run server configuration must save without an encryption key'
    restart.assert_not_called()
assert yt_config.load_settings()['server']['host'] == '127.0.0.1'
window.destroy()
print('PASS: clean user configuration, native client preparation, precompiled components, first-run GTK window and save')
