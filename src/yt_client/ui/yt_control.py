#!/usr/bin/env python3
"""Desktop configuration center and status window for the Linux client."""
from __future__ import annotations

import copy
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

# All supported inputs are local paths. Avoid blocking on remote GVFS monitors.
os.environ["GIO_USE_VFS"] = "local"
os.environ["GIO_USE_VOLUME_MONITOR"] = "unix"

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, Gio, GLib, Gtk, Pango  # noqa: E402

from yt_client import yt_config  # noqa: E402
from yt_client.file_scope import normalize_excluded_directories, normalize_monitored_extensions  # noqa: E402
from yt_client.monitoring import auto_service  # noqa: E402
from yt_client import error_log  # noqa: E402
from yt_client.ui.system_tray import SystemTray  # noqa: E402
from yt_client.runtime_paths import VERSION  # noqa: E402
from yt_client.ui.control_widgets import muted, card, action_button, secondary_button, page_frame, page_heading, badge, set_badge, path_label
from yt_client.ui.control_directories import DirectoriesPage, directory_state
from yt_client.ui.control_programs import ProgramsPage
from yt_client.ui.control_server import ServerPage

ROOT = yt_config.ROOT
APP_ID = "com.yangtu.ytconfig.control" + ("" if yt_config.PACKAGED else ".development")
ICON_THEME = ROOT / "assets/hicolor/scalable/apps"


class ClientWindow(Gtk.ApplicationWindow):
    def __init__(self, application: Gtk.Application, tray_error: str | None = None) -> None:
        super().__init__(application=application, title=f"shit加密 v{VERSION}")
        self.set_default_size(1120, 800)
        self.set_size_request(920, 680)
        self.add_css_class("encryption-client")
        self.settings = yt_config.load_settings()
        self.remote = yt_config.load_remote_policy()
        self.effective = yt_config.effective_config(self.settings, self.remote)
        self.dirty = False
        self.updating = False
        self._sync_error = None
        self._server_draft = False
        self._programs_draft = False
        self._updating_widgets = False
        self.tray_error = tray_error
        self.auto_running = False
        self._service_status = {"active": False, "state": "unknown"}
        self._auto_action_pending = False
        self._auto_action_label = "正在启动监控"
        self._monitor_error = None
        self._creation_error = None
        self._monitor_refresh_source = None
        self._monitor_refresh_running = False
        self._monitor_refresh_pending = False
        self._start_monitor_when_ready = os.environ.get('YT_CONTROL_SKIP_MONITOR_START') != '1'
        self.server_result = "尚未检测连接"
        self._server_result_kind = "neutral"
        self._build_header()
        self._build_body()
        self._install_css()
        self.set_icon_name("ytsysconfig")
        self.engine_ready = self._engine_ready()
        self._load_fields()
        self._refresh_auto_status()
        self._refresh_sources = [
            GLib.timeout_add_seconds(60, self._periodic_policy_check),
            GLib.timeout_add_seconds(30, self._environment_check),
            GLib.timeout_add_seconds(3, self._refresh_auto_status),
            GLib.timeout_add(500, self._startup_policy_check),
        ]
        self.connect("destroy", self._dispose_sources)

    def _dispose_sources(self, _window) -> None:
        context = GLib.MainContext.default()
        for source in self._refresh_sources + [self._monitor_refresh_source]:
            if source and context.find_source_by_id(source) is not None:
                GLib.source_remove(source)
        self._refresh_sources.clear()
        self._monitor_refresh_source = None

    def _build_header(self) -> None:
        header = Gtk.HeaderBar()
        title = Gtk.Box(spacing=12, hexpand=True)
        title.append(Gtk.Image.new_from_icon_name("ytsysconfig"))
        name = Gtk.Label(label="shit加密", xalign=0)
        name.add_css_class("app-title")
        title.append(name)
        title.append(muted(f"v{VERSION}"))
        header.set_title_widget(title)
        self.config_feedback = badge("配置已保存")
        logs_button = secondary_button("查看日志")
        logs_button.connect("clicked", lambda _button: self._open_logs())
        header.pack_end(logs_button)
        header.pack_end(self.config_feedback)
        self.set_titlebar(header)

    def _open_logs(self) -> None:
        try:
            Gio.AppInfo.launch_default_for_uri(error_log.log_directory().as_uri(), None)
        except (OSError, GLib.Error) as error:
            self._show_error("打开日志目录失败", str(error))

    def _build_body(self) -> None:
        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.set_child(body)
        navigation = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        navigation.add_css_class("sidebar")
        navigation.set_size_request(188, -1)
        navigation.append(muted("工作台", margin_top=22, margin_start=22))
        self.sidebar = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE, vexpand=True)
        self.sidebar.add_css_class("navigation-sidebar")
        self._navigation_rows = {}
        for name, title, icon in (
            ("overview", "概览", "view-grid-symbolic"),
            ("directories", "监控目录", "folder-symbolic"),
            ("programs", "程序权限", "application-x-executable-symbolic"),
            ("server", "服务器与策略", "network-server-symbolic"),
        ):
            row = Gtk.ListBoxRow()
            row.set_name(name)
            label = Gtk.Box(spacing=12)
            label.append(Gtk.Image.new_from_icon_name(icon))
            label.append(Gtk.Label(label=title, xalign=0))
            row.set_child(label)
            self.sidebar.append(row)
            self._navigation_rows[name] = row
        navigation.append(self.sidebar)
        help_button = secondary_button("帮助与诊断")
        help_button.add_css_class("flat")
        help_button.set_margin_start(12)
        help_button.set_margin_end(12)
        help_button.set_margin_bottom(16)
        help_button.connect("clicked", lambda _button: self._show_diagnostics())
        navigation.append(help_button)
        body.append(navigation)
        main = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, hexpand=True)
        self.stack = Gtk.Stack(hexpand=True, vexpand=True)
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_transition_duration(120)
        self.directories_page = DirectoriesPage(
            on_add=self._add_directory, on_toggle=self._set_directory_enabled,
            on_remove=self._remove_directory, on_retry=self._retry_directories,
            on_details=self._show_directory_details,
            on_add_exclusion=self._add_exclusion, on_remove_exclusion=self._remove_exclusion,
            on_toggle_default_exclusions=self._set_default_exclusions,
            on_save_file_types=self._save_file_types,
        )
        self.programs_page = ProgramsPage(
            self._apply_program_rules, self._programs_changed, self._show_error,
        )
        self.server_page = ServerPage(
            self._apply_server_settings, self._test_server, self._update_policy,
            self._import_policy_dialog, self._restore_remote_policy, self._server_changed,
        )
        self.stack.add_titled(self._overview_page(), "overview", "概览")
        self.stack.add_titled(self.directories_page, "directories", "监控目录")
        self.stack.add_titled(self.programs_page, "programs", "程序权限")
        self.stack.add_titled(self.server_page, "server", "服务器与策略")
        main.append(self.stack)
        self.status_detail = muted("停止监控只卸载文件视图，不会改写文件内容。", hexpand=True)
        self.status_detail.add_css_class("footer")
        self.status_detail.set_ellipsize(Pango.EllipsizeMode.END)
        main.append(self.status_detail)
        body.append(main)
        self.sidebar.connect("row-selected", self._sidebar_selected)
        self._navigate("overview")

    def _install_css(self) -> None:
        css = b"""
        window.encryption-client { background: #171a20; color: #edf1f8; }
        .encryption-client headerbar { background: #1c2027; color: #edf1f8; border-bottom: 1px solid #343b47; box-shadow: none; }
        .encryption-client .app-title { font-size: 17px; font-weight: 700; }
        .encryption-client .sidebar { background: #1c2027; border-right: 1px solid #343b47; }
        .encryption-client .navigation-sidebar { background: transparent; padding: 0 10px; }
        .encryption-client .navigation-sidebar row { min-height: 0; padding: 13px 14px; border-radius: 8px; margin-bottom: 8px; }
        .encryption-client .navigation-sidebar row:selected { background: #293f60; color: #81b5ff; }
        .encryption-client .hero-title { font-size: 24px; font-weight: 700; }
        .encryption-client .section-title { font-size: 16px; font-weight: 700; }
        .encryption-client .monitor-title { font-size: 24px; font-weight: 700; }
        .encryption-client .monitor-dot { font-size: 27px; padding: 10px; }
        .encryption-client .card { background: #20252d; border: 1px solid #343b47; border-radius: 12px; padding: 20px; }
        .encryption-client .muted { color: #9ca7b8; }
        .encryption-client .footer { padding: 10px 24px 16px; font-size: 12px; }
        .encryption-client button.client-action, .encryption-client .format-choice button { background: #252c36; color: #edf1f8; border: 1px solid #3a4452; border-radius: 7px; padding: 8px 13px; box-shadow: none; text-shadow: none; }
        .encryption-client button.client-action:hover, .encryption-client .format-choice button:hover { background: #303b49; }
        .encryption-client button.suggested-action, .encryption-client .format-choice button:checked { background: #293f60; border-color: #6493d3; color: #a8cdff; }
        .encryption-client button:disabled { opacity: 0.5; }
        .encryption-client button.flat { background: transparent; border-color: transparent; }
        .encryption-client entry, .encryption-client textview text, .encryption-client dropdown button, .encryption-client spinbutton { background: #171a20; color: #edf1f8; border-color: #3a4452; }
        .encryption-client entry { min-height: 28px; border-radius: 7px; }
        .encryption-client list, .encryption-client list row { background: transparent; color: #edf1f8; }
        .encryption-client .list-row { padding: 13px 0; border-bottom: 1px solid #343b47; }
        .encryption-client .table-heading { color: #9ca7b8; padding-bottom: 12px; font-size: 12px; }
        .encryption-client .badge { border-radius: 5px; padding: 5px 9px; font-size: 11px; }
        .encryption-client .badge-neutral { background: #2b323d; color: #b3bdcb; }
        .encryption-client .badge-success { background: #213b35; color: #6bd6a5; }
        .encryption-client .badge-warning { background: #3b3224; color: #eac27a; }
        .encryption-client .badge-error { background: #472e33; color: #ed9292; }
        .encryption-client .badge-accent { background: #293f60; color: #a8cdff; }
        .encryption-client .status-ready { color: #6bd6a5; }
        .encryption-client .status-busy { color: #eac27a; }
        .encryption-client .status-error { color: #ed9292; }
        .encryption-client .empty-state { padding: 18px; color: #9ca7b8; }
        .encryption-client switch { min-width: 36px; min-height: 20px; background: #343b47; border-color: #343b47; }
        .encryption-client switch:checked { background: #293f60; }
        .encryption-client switch slider { min-width: 16px; min-height: 16px; }
        .encryption-client expander title { padding: 5px 0; }
        """
        provider = Gtk.CssProvider()
        provider.load_from_data(css)
        display = Gdk.Display.get_default()
        if display is not None:
            Gtk.IconTheme.get_for_display(display).add_search_path(str(ICON_THEME))
            Gtk.StyleContext.add_provider_for_display(display, provider, Gtk.STYLE_PROVIDER_PRIORITY_USER + 1)
            Gtk.Settings.get_for_display(display).set_property("gtk-application-prefer-dark-theme", True)

    def _overview_page(self) -> Gtk.Widget:
        scroll, content = page_frame()
        content.append(page_heading("概览", "运行状态与文件行为，一处确认。"))
        monitor = Gtk.Box(spacing=16)
        self.status_dot = Gtk.Label(label="●", valign=Gtk.Align.START)
        self.status_dot.add_css_class("monitor-dot")
        monitor.append(self.status_dot)
        labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=9, hexpand=True)
        self.status_primary = Gtk.Label(label="正在读取监控状态…", xalign=0, wrap=True)
        self.status_primary.add_css_class("monitor-title")
        labels.append(self.status_primary)
        self.auto_summary = muted("", wrap=True)
        labels.append(self.auto_summary)
        monitor.append(labels)
        actions = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, valign=Gtk.Align.CENTER)
        self.auto_action = action_button("启用监控")
        self.auto_action.connect("clicked", lambda _button: self._toggle_auto_mode())
        actions.append(self.auto_action)
        self.terminal_authorization_button = secondary_button("终端授权")
        self.terminal_authorization_button.set_visible(yt_config.PACKAGED)
        self.terminal_authorization_button.connect("clicked", lambda _button: self._open_terminal_authorization())
        actions.append(self.terminal_authorization_button)
        self.monitor_details_button = secondary_button("查看原因")
        self.monitor_details_button.connect("clicked", lambda _button: self._show_monitor_details())
        actions.append(self.monitor_details_button)
        self.configure_server_button = secondary_button("配置服务器")
        self.configure_server_button.connect("clicked", lambda _button: self._navigate("server"))
        actions.append(self.configure_server_button)
        monitor.append(actions)
        content.append(card(monitor))
        behavior = Gtk.Box(spacing=18, homogeneous=True)
        creation = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        title = Gtk.Label(label="新建文件格式", xalign=0)
        title.add_css_class("section-title")
        creation.append(title)
        choices = Gtk.Box(spacing=0, homogeneous=True)
        choices.add_css_class("linked")
        choices.add_css_class("format-choice")
        self.new_plain = Gtk.ToggleButton(label="明文")
        self.new_encrypted = Gtk.ToggleButton(label="加密")
        self.new_encrypted.set_group(self.new_plain)
        for button in (self.new_plain, self.new_encrypted):
            button.connect("toggled", self._new_file_mode_changed)
            choices.append(button)
        creation.append(choices)
        self.creation_feedback = badge("正在读取配置")
        self.creation_feedback.set_halign(Gtk.Align.START)
        creation.append(self.creation_feedback)
        creation.append(muted("仅影响之后新建的文件，不批量转换已有文件。", wrap=True))
        behavior.append(card(creation))
        transport = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        title = Gtk.Label(label="Git 提交规则", xalign=0)
        title.add_css_class("section-title")
        transport.append(title)
        transport.append(Gtk.Label(label="明文 → 明文    密文 → 密文", xalign=0, wrap=True))
        transport.append(muted("按文件落盘状态传输，提交时不额外加密或解密。", wrap=True))
        behavior.append(card(transport))
        content.append(behavior)
        directories = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        heading = Gtk.Box(spacing=12)
        title = Gtk.Label(label="监控目录", xalign=0, hexpand=True)
        title.add_css_class("section-title")
        heading.append(title)
        manage = secondary_button("管理目录 →")
        manage.add_css_class("flat")
        manage.connect("clicked", lambda _button: self._navigate("directories"))
        heading.append(manage)
        directories.append(heading)
        self.overview_directories = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        directories.append(self.overview_directories)
        content.append(card(directories))
        startup = Gtk.Box(spacing=12)
        startup.append(muted("登录后自动启动监控", hexpand=True))
        self.autostart_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.autostart_switch.set_active(auto_service.autostart_enabled())
        self.autostart_switch.connect("notify::active", self._toggle_autostart)
        startup.append(self.autostart_switch)
        content.append(startup)
        return scroll

    def _new_file_mode_changed(self, button: Gtk.ToggleButton) -> None:
        if button.get_active() and not self._updating_widgets:
            self._apply_new_file_mode()

    def _navigate(self, name: str) -> None:
        self.sidebar.select_row(self._navigation_rows[name])

    def _show_diagnostics(self) -> None:
        message = self._service_status.get("error") or (self._service_status.get("runtime") or {}).get("error")
        detail = f"{self.status_primary.get_text()}\n{self.auto_summary.get_text()}"
        if message:
            detail += f"\n\n{message}"
        detail += f"\n\n日志目录：{error_log.log_directory()}\n停止监控不会改写文件内容。"
        dialog = Gtk.AlertDialog(message="帮助与诊断", detail=detail)
        dialog.show(self)

    def _show_directory_details(self, path: str, reason: str) -> None:
        Gtk.AlertDialog(message="目录监控详情", detail=f"{path}\n\n{reason}").show(self)

    def _show_monitor_details(self) -> None:
        Gtk.AlertDialog(message=self.status_primary.get_text(), detail=self.auto_summary.get_text()).show(self)

    def _sidebar_selected(self, _listbox: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        if row is not None:
            self.stack.set_visible_child_name(row.get_name())

    def _load_fields(self) -> None:
        self.server_page.load(self.settings, self.remote, self.effective)
        self.programs_page.load(self.settings, self.remote, self.effective)
        self._server_draft = self._programs_draft = False
        self._refresh_dynamic_fields()

    def _server_changed(self) -> None:
        values = self.server_page.values()
        server = self.settings["server"]
        self._server_draft = any(values[key] != server[key] for key in (
            "host", "auto_update", "update_interval_minutes",
        )) or values["use_server_policy"] != self.settings["local_overrides"]["use_server_policy"]
        self.server_page.set_feedback("未应用" if self._server_draft else "已保存", "warning" if self._server_draft else "neutral")
        self._refresh_config_feedback()

    def _programs_changed(self) -> None:
        self._programs_draft = self.programs_page.dirty
        self._refresh_config_feedback()

    def _refresh_config_feedback(self) -> None:
        self.dirty = self._server_draft or self._programs_draft
        set_badge(self.config_feedback, "有未应用修改" if self.dirty else "配置已保存", "warning" if self.dirty else "neutral")

    def _apply_server_settings(self) -> bool:
        if self.updating:
            return False
        values = self.server_page.values()
        candidate = copy.deepcopy(self.settings)
        previous_host = candidate["server"]["host"]
        for key in ("host", "auto_update", "update_interval_minutes"):
            candidate["server"][key] = values[key]
        source = candidate["server"]["policy_source"]
        candidate["server"]["policy_source"] = {
            "type": "native", "value": source["value"] if source["type"] == "native" else "",
            "timeout_seconds": source["timeout_seconds"],
        }
        candidate["local_overrides"]["use_server_policy"] = values["use_server_policy"]
        if not self._save_settings(candidate, "服务器配置已保存"):
            self.server_page.set_feedback("保存失败，修改尚未完整应用", "error")
            return False
        self._server_draft = False
        self.server_page.load(self.settings, self.remote, self.effective)
        if previous_host != values["host"]:
            self.server_result, self._server_result_kind = "地址已修改，尚未检测", "neutral"
        self._refresh_status()
        return True

    def _apply_program_rules(self, rules: list[str], removed: list[str]) -> bool:
        candidate = copy.deepcopy(self.settings)
        candidate["trusted_programs"] = list(rules)
        candidate["local_overrides"]["removed_server_programs"] = list(removed)
        if not self._save_settings(candidate, "程序权限已保存"):
            self.programs_page.set_feedback("保存失败，草稿已保留", "error")
            return False
        self._programs_draft = False
        self.programs_page.load(self.settings, self.remote, self.effective)
        self._refresh_config_feedback()
        return True

    def _apply_new_file_mode(self) -> None:
        mode = "encrypted" if self.new_encrypted.get_active() else "plain"
        if mode == self.settings["encryption"]["new_file_mode"]:
            return
        self._creation_error = None
        candidate = copy.deepcopy(self.settings)
        candidate["encryption"]["new_file_mode"] = mode
        saved = self._save_settings(candidate, "新建文件格式已保存")
        if not saved:
            self._creation_error = self.status_detail.get_text()
        self._refresh_creation_feedback()

    def _save_settings(self, candidate: dict, notice: str) -> bool:
        persisted = False
        try:
            normalized = yt_config.normalize_settings(candidate)
            remote = yt_config.load_remote_policy()
            effective = yt_config.effective_config(normalized, remote)
            changed = yt_config.monitor_signature(effective) != yt_config.monitor_signature(self.effective) or self._monitor_error is not None
            yt_config.save_settings(normalized)
            self.settings, self.remote, self.effective = normalized, remote, effective
            persisted = True
            if effective["encryption"]["key"]:
                yt_config.write_effective_runtime_config(normalized, remote)
            self._creation_error = None
            if changed:
                self._queue_monitor_refresh()
            self._refresh_dynamic_fields()
            self.status_detail.set_text(notice)
            return True
        except (OSError, ValueError, RuntimeError) as error:
            if persisted:
                self._monitor_error = str(error)
            self._show_error("配置应用失败", str(error))
            self._refresh_creation_feedback()
            return False

    def _refresh_dynamic_fields(self) -> None:
        self.server_page.refresh(self.settings, self.remote, self.effective)
        self.programs_page.refresh(self.settings, self.remote, self.effective)
        self._refresh_status()

    def _refresh_status(self) -> None:
        self.server_page.set_connection(self.server_result, self._server_result_kind)
        policy_metadata = dict(self.settings["policy"])
        if self._sync_error:
            policy_metadata["last_error"] = self._sync_error
        self.server_page.set_sync(policy_metadata, self.updating)
        self._refresh_config_feedback()
        self._refresh_creation_feedback()
        self._render_monitor_status()

    def _refresh_creation_feedback(self) -> None:
        mode = self.settings["encryption"]["new_file_mode"]
        self._updating_widgets = True
        try:
            self.new_encrypted.set_active(mode == "encrypted")
            self.new_plain.set_active(mode == "plain")
        finally:
            self._updating_widgets = False
        status = self._service_status
        runtime = status.get("runtime") or {}
        if self._creation_error:
            set_badge(self.creation_feedback, "配置应用失败，请查看原因", "error")
            self.creation_feedback.set_tooltip_text(self._creation_error)
            return
        if self._monitor_error:
            text, kind = "已保存 · 监控更新失败", "error"
        elif self._monitor_refresh_pending or self._monitor_refresh_running:
            text, kind = "已保存 · 正在更新监控", "accent"
        elif not self.effective.get("monitored_extensions"):
            text, kind = "已保存 · 未配置监控文件类型", "neutral"
        elif not self.effective["encryption"]["key"]:
            text, kind = "已保存 · 等待加密密钥", "neutral"
        elif not status.get("active"):
            text, kind = "已保存 · 待启用监控", "neutral"
        elif runtime.get("state") == "running" and runtime.get("new_file_mode") == mode:
            text, kind = "已生效", "success"
        elif runtime.get("state") == "idle":
            text, kind = "已保存 · 等待可用目录", "warning"
        else:
            text, kind = "已保存 · 等待监控确认", "accent"
        set_badge(self.creation_feedback, text, kind)
        self.creation_feedback.set_tooltip_text(self._monitor_error or "点击格式选项即保存；以监控服务报告的实际配置确认生效。")

    def _render_monitor_status(self) -> None:
        status = self._service_status
        runtime = status.get("runtime") or {}
        active = bool(status.get("active"))
        mounts = runtime.get("mounts") or []
        states = [directory_state(item, status) for item in self.effective["directories"]]
        problems = sum(kind in ("warning", "error") for _label, kind, _reason in states)
        self.auto_running = active and runtime.get("state") == "running" and bool(mounts)
        error = status.get("error") or runtime.get("error") or self._monitor_error
        busy = self._auto_action_pending or self._monitor_refresh_pending or self._monitor_refresh_running
        if self._auto_action_pending:
            title, detail, kind = self._auto_action_label, "等待服务返回实际运行结果。", "accent"
        elif (self._monitor_refresh_running or self._monitor_refresh_pending) and active:
            title, detail, kind = "正在更新监控", "配置已保存，等待重新挂载完成。", "accent"
        elif status.get("state") == "activating":
            title, detail, kind = "正在启动监控", "等待授权和目录挂载完成。", "accent"
        elif self.auto_running:
            title = "监控运行中 · 部分目录异常" if problems else "监控运行中"
            detail = f"实际挂载 {len(mounts)} 个目录；按文件原有格式读写。"
            if problems:
                detail += f" {problems} 个配置目录需要处理。"
            kind = "warning" if problems else "success"
        elif error:
            title, detail, kind = "监控异常" if active else "监控启动或运行失败", str(error), "error"
        elif active and runtime.get("state") in (None, "starting", "initializing"):
            title, detail, kind = "正在启动监控", "等待授权和目录挂载完成。", "accent"
        elif active:
            title, detail, kind = "等待可用监控目录", "服务已启动，尚未报告可用挂载；请检查目录页面。", "warning"
        elif not self.effective["encryption"]["key"]:
            title, detail, kind = "等待加密密钥", "请先连接服务器同步策略和密钥，当前未启用监控。", "neutral"
        elif not self.engine_ready:
            title, detail, kind = "运行环境需要检查", "当前未启用监控，请检查 FUSE、安装资源与启动授权。", "error"
        else:
            title, detail, kind = "监控未启动", "文件不会自动加解密；启用后才按目录和程序策略处理。", "neutral"
        self.status_primary.set_text(title)
        self.auto_summary.set_text(detail)
        self.auto_summary.set_tooltip_text(detail)
        for name in ("status-ready", "status-busy", "status-error"):
            self.status_dot.remove_css_class(name)
        if kind != "neutral":
            self.status_dot.add_css_class("status-ready" if kind == "success" else "status-error" if kind == "error" else "status-busy")
        self.auto_action.set_label("停止监控" if active or status.get("state") == "activating" else "启用监控")
        self.auto_action.set_sensitive(not busy and (active or bool(self.effective["encryption"]["key"])))
        has_key = bool(self.effective["encryption"]["key"])
        self.terminal_authorization_button.set_sensitive(not active and has_key)
        if active:
            terminal_help = "监控服务已运行。"
        elif not has_key:
            terminal_help = "同步策略和密钥后可使用终端启动监控。"
        elif status.get("authorization_required"):
            terminal_help = "打开系统终端完成管理员授权并启动监控。"
        else:
            terminal_help = "使用已有授权从系统终端启动监控。"
        self.terminal_authorization_button.set_tooltip_text(terminal_help)
        self.monitor_details_button.set_visible(kind in ("warning", "error"))
        self.configure_server_button.set_visible(not bool(self.effective["encryption"]["key"]))
        self.directories_page.update(self.effective, status, updating=busy)
        self._refresh_overview_directories(states)
        tray = getattr(self.get_application(), "tray", None)
        if tray is not None:
            tray.set_summary(title)

    def _refresh_overview_directories(self, states: list[tuple[str, str, str]]) -> None:
        child = self.overview_directories.get_first_child()
        while child is not None:
            following = child.get_next_sibling()
            self.overview_directories.remove(child)
            child = following
        if not self.effective["directories"]:
            self.overview_directories.append(muted("尚未配置监控目录，请添加文件夹或同步服务器策略。", wrap=True))
            add = secondary_button("添加目录")
            add.set_halign(Gtk.Align.START)
            add.connect("clicked", lambda _button: self._add_directory())
            self.overview_directories.append(add)
        for item, (label, kind, reason) in list(zip(self.effective["directories"], states))[:3]:
            row = Gtk.Box(spacing=12)
            row.add_css_class("list-row")
            row.append(Gtk.Image.new_from_icon_name("folder-symbolic"))
            row.append(path_label(item["path"]))
            state = badge(label, kind)
            state.set_tooltip_text(reason)
            row.append(state)
            self.overview_directories.append(row)
        if len(states) > 3:
            self.overview_directories.append(muted(f"另有 {len(states) - 3} 个目录，前往管理目录查看。"))

    def _engine_ready(self) -> bool:
        if not Path("/dev/fuse").exists() or os.uname().machine != "x86_64":
            return False
        if yt_config.PACKAGED:
            return (ROOT / "mount-broker").is_file()
        sudo = subprocess.run(
            ["sudo", "-n", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return sudo.returncode == 0 and (ROOT / "vendor/cipher301.bin").is_file()

    def _show_file_picker(self, title, action, initial_folder, on_selected, file_filter=None):
        picker = getattr(self, "_file_picker", None)
        if picker is not None:
            picker.present()
            return
        picker = Gtk.FileChooserDialog(
            title=title, transient_for=self, modal=False,
            destroy_with_parent=True, action=action,
        )
        picker.add_button("取消", Gtk.ResponseType.CANCEL)
        picker.add_button("选择", Gtk.ResponseType.ACCEPT)
        picker.set_current_folder(Gio.File.new_for_path(str(initial_folder)))
        if file_filter is not None:
            picker.add_filter(file_filter)
        self._file_picker = picker

        def response(dialog, response_id):
            selected = dialog.get_file() if response_id == Gtk.ResponseType.ACCEPT else None
            self._file_picker = None
            dialog.destroy()
            self.present()
            if selected is not None and selected.get_path():
                on_selected(Path(selected.get_path()))

        picker.connect("response", response)
        picker.present()

    def _add_directory(self) -> None:
        self._show_file_picker(
            "选择支持目录", Gtk.FileChooserAction.SELECT_FOLDER,
            Path.home(), self._directory_selected,
        )

    def _directory_selected(self, folder: Path) -> None:
        path = str(folder)
        if path not in {item["path"] for item in self.settings["directories"]}:
            candidate = copy.deepcopy(self.settings)
            candidate["directories"].append({"path": path, "enabled": True})
            self._save_settings(candidate, "目录已保存")

    def _add_exclusion(self) -> None:
        self._show_file_picker(
            "选择要排除的子目录", Gtk.FileChooserAction.SELECT_FOLDER,
            Path(self.effective["directories"][0]["path"]), self._exclusion_selected,
        )

    def _exclusion_selected(self, folder: Path) -> None:
        try:
            path = folder.resolve()
            roots = [Path(item["path"]).resolve() for item in self.effective["directories"]]
        except (OSError, RuntimeError) as error:
            self._show_error("无法选择排除目录", str(error))
            return
        paths = normalize_excluded_directories([str(path)])
        if not paths or not any(root in path.parents for root in roots):
            self._show_error("无法选择排除目录", "请选择监控目录下的子目录。")
            return
        if paths[0] not in self.settings["excluded_directories"]:
            candidate = copy.deepcopy(self.settings)
            candidate["excluded_directories"].extend(paths)
            self._save_settings(candidate, "排除目录已保存")

    def _remove_exclusion(self, path: str) -> None:
        candidate = copy.deepcopy(self.settings)
        candidate["excluded_directories"].remove(path)
        self._save_settings(candidate, "已移除排除目录")

    def _set_default_exclusions(self, enabled: bool) -> bool:
        candidate = copy.deepcopy(self.settings)
        candidate["use_default_directory_exclusions"] = enabled
        return self._save_settings(candidate, "默认排除目录设置已保存")

    def _save_file_types(self, text: str) -> bool:
        try:
            extensions = normalize_monitored_extensions(text)
        except ValueError as error:
            self._show_error("文件类型无效", str(error))
            return False
        if extensions == self.settings["monitored_extensions"]:
            self.status_detail.set_text("监控文件类型已保存")
            return True
        candidate = copy.deepcopy(self.settings)
        candidate["monitored_extensions"] = extensions
        return self._save_settings(candidate, "监控文件类型已保存")

    def _set_directory_enabled(self, path: str, enabled: bool) -> None:
        candidate = copy.deepcopy(self.settings)
        for item in candidate["directories"]:
            if item["path"] == path:
                item["enabled"] = enabled
                self._save_settings(candidate, "目录状态已保存")
                return

    def _remove_directory(self, path: str) -> None:
        self._confirm_delete("移除目录监控？", f"{path}\n\n只更改本机监控配置，不会删除目录或文件。", lambda: self._delete_directory(path))

    def _delete_directory(self, path: str) -> None:
        candidate = copy.deepcopy(self.settings)
        candidate["directories"] = [item for item in candidate["directories"] if item["path"] != path]
        if self.remote and any(item["path"] == path for item in self.remote["directories"]):
            removed = candidate["local_overrides"]["removed_server_directories"]
            if path not in removed:
                removed.append(path)
        self._save_settings(candidate, "已移除目录监控，文件未删除")

    def _retry_directories(self) -> None:
        if not self.effective["encryption"]["key"]:
            self._navigate("server")
            self._show_error("暂不能启动监控", "请先同步有效的加密密钥。")
            return
        self._start_monitor_when_ready = True
        self._run_auto_action(auto_service.restart if self._service_status.get("active") else auto_service.start)

    def _queue_monitor_refresh(self) -> None:
        self._monitor_refresh_pending = True
        self._monitor_error = None
        if not self._monitor_refresh_running and self._monitor_refresh_source is None:
            self._monitor_refresh_source = GLib.timeout_add(200, self._start_monitor_refresh)

    def _start_monitor_refresh(self) -> bool:
        self._monitor_refresh_source = None
        self._monitor_refresh_pending = False
        self._monitor_refresh_running = True

        def work() -> None:
            try:
                status = auto_service.status()
                if status.get("active") or status.get("state") == "activating":
                    if self.effective["encryption"]["key"]:
                        auto_service.restart()
                    else:
                        auto_service.stop()
                GLib.idle_add(self._monitor_refreshed, None)
            except Exception as error:
                GLib.idle_add(self._monitor_refreshed, str(error))

        threading.Thread(target=work, daemon=True).start()
        return False

    def _monitor_refreshed(self, error: str | None) -> bool:
        self._monitor_refresh_running = False
        self._monitor_error = error
        self._refresh_auto_status()
        if error:
            self._show_error("监控更新失败", error)
        else:
            self.status_detail.set_text("配置已保存，监控状态以服务实际报告为准。")
        if self._monitor_refresh_pending:
            self._queue_monitor_refresh()
        return False

    def _restore_remote_policy(self) -> None:
        if self.dirty:
            self._show_error("请先处理未应用修改", "请先应用程序权限或服务器配置，再恢复服务器策略项。")
            return
        candidate = copy.deepcopy(self.settings)
        candidate["local_overrides"]["removed_server_directories"] = []
        candidate["local_overrides"]["removed_server_programs"] = []
        candidate["local_overrides"]["use_server_policy"] = True
        if self._save_settings(candidate, "服务器策略项已恢复"):
            self.server_page.load(self.settings, self.remote, self.effective)
            self.programs_page.load(self.settings, self.remote, self.effective)






    def _confirm_delete(self, title: str, detail: str, on_confirm) -> None:
        self._confirm_action(title, detail, "删除", on_confirm)

    def _confirm_action(
        self, title: str, detail: str, confirm_label: str, on_confirm
    ) -> None:
        dialog = Gtk.AlertDialog(
            message=title,
            detail=detail,
            buttons=["取消", confirm_label],
            cancel_button=0,
            default_button=0,
        )

        def finished(alert: Gtk.AlertDialog, result: Gio.AsyncResult) -> None:
            try:
                response = alert.choose_finish(result)
            except GLib.Error:
                return
            if response == 1:
                on_confirm()

        dialog.choose(self, None, finished)





    def _environment_check(self) -> bool:
        ready = self._engine_ready()
        if ready != self.engine_ready:
            self.engine_ready = ready
            self._refresh_status()
        return True

    def _refresh_auto_status(self) -> bool:
        try:
            self._service_status = auto_service.status()
        except (OSError, RuntimeError) as error:
            self._service_status = {"active": False, "state": "failed", "error": str(error)}
        self._refresh_status()
        return True

    def _toggle_autostart(self, switch, _param) -> None:
        if not switch.get_sensitive():
            return
        enabled = switch.get_active()
        switch.set_sensitive(False)

        def done(error):
            switch.set_active(auto_service.autostart_enabled())
            switch.set_sensitive(True)
            if error:
                self._show_error("开机启动设置失败", error)
            return False

        def work():
            try:
                auto_service.set_autostart(enabled)
                GLib.idle_add(done, None)
            except Exception as error:
                GLib.idle_add(done, str(error))

        threading.Thread(target=work, daemon=True).start()

    def _toggle_auto_mode(self) -> None:
        if self._service_status.get("active") or self._service_status.get("state") == "activating":
            self._start_monitor_when_ready = False
            self._run_auto_action(auto_service.stop)
        else:
            self._start_monitor_when_ready = True
            self._run_auto_action(auto_service.start)

    def _open_terminal_authorization(self) -> None:
        command = auto_service.terminal_authorization_command()
        try:
            launcher = Gio.AppInfo.create_from_commandline(
                command, "加密目录监控授权", Gio.AppInfoCreateFlags.NEEDS_TERMINAL,
            )
            if not launcher.launch([], self.get_display().get_app_launch_context()):
                raise RuntimeError("找不到可用的桌面终端。")
        except (GLib.Error, RuntimeError) as error:
            self._show_error("无法打开授权终端", f"{error}\n请在本机终端执行：\n{command}")
        else:
            self._monitor_error = None
            self.status_detail.set_text("请在终端完成管理员授权，客户端会随后尝试启动监控。")

    def _run_auto_action(self, action) -> None:
        if self._auto_action_pending:
            return
        self._auto_action_pending = True
        self._monitor_error = None
        self._auto_action_label = "正在停止监控" if action is auto_service.stop else "正在启动监控"
        self._refresh_status()

        def work() -> None:
            try:
                action()
                GLib.idle_add(self._auto_action_done, None)
            except Exception as error:
                GLib.idle_add(self._auto_action_done, str(error))

        threading.Thread(target=work, daemon=True).start()

    def _auto_action_done(self, error: str | None) -> bool:
        self._auto_action_pending = False
        self._monitor_error = error
        self._refresh_auto_status()
        if error:
            self._show_error("自动监控操作失败", error)
        return False

    def _periodic_policy_check(self) -> bool:
        if not self._server_draft and self.settings["server"]["host"] and yt_config.should_auto_update(self.settings) and not self.updating:
            self._update_policy()
        return True

    def _startup_policy_check(self) -> bool:
        if self._start_monitor_when_ready and self.effective["encryption"]["key"]:
            self._run_auto_action(auto_service.start)
        self._periodic_policy_check()
        return False

    def _test_server(self) -> None:
        if self._server_draft:
            self._show_error("服务器配置尚未应用", "请先点击“应用配置”，检测不会自动保存草稿。")
            return
        host = self.settings["server"]["host"]
        if not host:
            self._show_error("缺少服务器地址", "填写服务器地址并应用后再检测。")
            return
        self.server_result, self._server_result_kind = "检测中…", "accent"
        self._refresh_status()

        def work() -> None:
            try:
                ok, message = yt_config.check_server(host)
            except (OSError, RuntimeError, ValueError) as error:
                ok, message = False, str(error)
            GLib.idle_add(self._server_checked, host, ok, message)

        threading.Thread(target=work, daemon=True).start()

    def _server_checked(self, host: str, ok: bool, message: str) -> bool:
        if host != self.settings["server"]["host"]:
            return False
        if not ok:error_log.logger('ui').error('Server check failed: %s', message)
        self.server_result = message
        self._server_result_kind = "success" if ok else "error"
        self._refresh_status()
        return False

    def _update_policy(self) -> None:
        if self.updating:
            return
        if self._server_draft:
            self._show_error("服务器配置尚未应用", "请先应用配置，再同步策略。")
            return
        if self.settings["server"]["policy_source"]["type"] == "none":
            self._show_error("无法更新策略", "请先选择策略来源并填写地址或命令")
            return
        self.updating = True
        self._sync_error = None
        self._refresh_status()
        self.status_detail.set_text("正在同步服务器策略，当前有效策略继续使用。")

        def work() -> None:
            try:
                policy = yt_config.update_policy(self.settings)
                GLib.idle_add(self._policy_updated, policy, None)
            except Exception as error:
                GLib.idle_add(self._policy_updated, None, str(error))

        threading.Thread(target=work, daemon=True).start()

    def _policy_updated(self, policy: dict[str, Any] | None, error: str | None) -> bool:
        if error:error_log.logger('ui').error('Policy refresh failed: %s', error)
        self.updating = False
        self._sync_error = error
        previous_monitor = yt_config.monitor_signature(self.effective)
        self.settings = yt_config.load_settings()
        self.remote = yt_config.load_remote_policy()
        self.effective = yt_config.effective_config(self.settings, self.remote)
        self._refresh_dynamic_fields()
        if error:
            self.status_detail.set_text(f"策略更新失败：{error}")
        else:
            self.status_detail.set_text(
                "服务器策略已更新并完成本地合并" if self.effective["encryption"]["key"] else
                "应用策略已同步；服务器未提供当前密钥，等待密钥就绪后自动启动监控"
            )
            if self._start_monitor_when_ready and self.effective["encryption"]["key"] and not self._service_status.get("active"):
                self._run_auto_action(auto_service.start)
            elif yt_config.monitor_signature(self.effective) != previous_monitor:
                self._queue_monitor_refresh()
        return False

    def _import_policy_dialog(self) -> None:
        policy_filter = Gtk.FileFilter()
        policy_filter.set_name("策略文件（JSON / LinuxJMData.dat）")
        policy_filter.add_pattern("*.json")
        policy_filter.add_pattern("*.dat")
        self._show_file_picker(
            "导入服务器策略", Gtk.FileChooserAction.OPEN,
            yt_config.CONFIG_DIR, self._import_policy_file, policy_filter,
        )

    def _import_policy_file(self, path: Path) -> None:
        try:
            previous_monitor = yt_config.monitor_signature(self.effective)
            if path.suffix.lower() == ".dat":
                policy = yt_config.parse_native_policy(
                    path, server=self.settings["server"]["host"]
                )
            else:
                raw = yt_config.read_json(path)
                if raw is None:
                    raise ValueError("文件不是有效 JSON")
                policy = yt_config.normalize_remote_policy(raw)
                policy["updated_at"] = yt_config._now()
                policy["source"] = f"file:{path}"
            yt_config.save_remote_policy(policy)
            self.settings["policy"]["last_attempt"] = yt_config._now()
            self.settings["policy"]["last_success"] = yt_config._now()
            self.settings["policy"]["last_error"] = None
            yt_config.save_settings(self.settings)
            self.remote = policy
            self._sync_error = None
            self.effective = yt_config.effective_config(self.settings, policy)
            if self.effective["encryption"]["key"]:
                yt_config.write_effective_runtime_config(self.settings, policy)
            if yt_config.monitor_signature(self.effective) != previous_monitor:
                self._queue_monitor_refresh()
            self._refresh_dynamic_fields()
            self.status_detail.set_text(f"已导入策略：{path.name}")
        except (OSError, ValueError, RuntimeError) as error:
            self._show_error("导入策略失败", str(error))

    def _show_error(self, title: str, detail: str) -> None:
        try:error_log.logger('ui').error('%s: %s', title, detail)
        except OSError:pass
        self.status_detail.set_text(f"{title}：{detail}")
        dialog = Gtk.AlertDialog(message=title, detail=detail)
        dialog.show(self)

    def _on_close(self, *_args: Any) -> bool:
        self.set_visible(False)
        return True


class YTControl(Gtk.Application):
    def __init__(self) -> None:
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        self.tray: SystemTray | None = None
        self.tray_error: str | None = None
        self.tray_held = False
        self.window: ClientWindow | None = None
        self._activation_token: str | None = None
        self._activation_timestamp = 0
        self.start_hidden = os.environ.get("YT_CONTROL_START_HIDDEN") == "1"

    def do_activate(self) -> None:
        self._enable_tray()
        if self.window is None:
            self.window = ClientWindow(self, self.tray_error)
            self.window.connect("close-request", self.window._on_close)
            self.window.connect("destroy", self._window_destroyed)
        if self.start_hidden:
            self.start_hidden = False
            return
        if self._activation_token:
            self.window.set_startup_id(self._activation_token)
        self.window.realize()
        surface = self.window.get_surface()
        timestamp = self._activation_timestamp
        x11 = surface.get_display().__gtype__.name == "GdkX11Display"
        if not timestamp and x11:
            # SNI Activate carries coordinates, not an X11 event timestamp.
            # CurrentTime (0) can leave an existing window behind another app.
            gi.require_version("GdkX11", "4.0")
            from gi.repository import GdkX11
            timestamp = GdkX11.x11_get_server_time(surface)
        self.window.unminimize()
        self.window.present_with_time(timestamp or Gdk.CURRENT_TIME)
        if x11:
            surface.focus(timestamp)
        self._activation_token = None
        self._activation_timestamp = 0

    def _enable_tray(self) -> None:
        if self.tray is not None or self.tray_error is not None:
            return
        try:
            self.tray = SystemTray(
                self._show_window,
                self._quit_from_tray,
                self._stop_auto_from_tray,
            )
            self.hold()
            self.tray_held = True
        except (GLib.Error, RuntimeError, OSError) as error:
            self.tray_error = str(error)

    def _quit_from_tray(self) -> None:
        try:
            auto_service.stop()
        except (OSError, RuntimeError) as error:
            print(f"stop auto service before quit: {error}", file=sys.stderr, flush=True)
        if self.tray is not None:
            self.tray.close()
            self.tray = None
        if self.tray_held:
            self.release()
            self.tray_held = False
        self.quit()

    def _show_window(self, token: str | None = None, timestamp: int = 0) -> None:
        self._activation_token = token
        self._activation_timestamp = timestamp
        self.start_hidden = False
        self.activate()

    def _stop_auto_from_tray(self) -> None:
        def work() -> None:
            try:
                auto_service.stop()
                GLib.idle_add(self._tray_auto_stopped, None)
            except (OSError, RuntimeError) as error:
                GLib.idle_add(self._tray_auto_stopped, str(error))

        threading.Thread(target=work, daemon=True).start()

    def _tray_auto_stopped(self, error: str | None) -> bool:
        if self.window is not None:
            self.window._refresh_auto_status()
            self.window._refresh_status()
            if error:
                self.window._show_error("停止自动监控失败", error)
        elif error:
            error_log.logger('ui').error('Stop auto service failed: %s', error)
        return False

    def _window_destroyed(self, _window: Gtk.Window) -> None:
        self.window = None


def register_desktop_entry() -> None:
    if yt_config.PACKAGED:
        return
    # GNOME resolves Wayland window icons via the matching installed desktop ID.
    applications = Path(GLib.get_user_data_dir()) / "applications"
    applications.mkdir(parents=True, exist_ok=True)
    template = (ROOT / 'packaging/com.yangtu.ytconfig.control.desktop').read_text(encoding="utf-8")
    executable = str(ROOT / "start.sh")
    for character in ('\\', '"', '`', '$'):
        executable = executable.replace(character, '\\' + character)
    executable = executable.replace('%', '%%')
    values = {
        "Exec": f'"{executable}"',
        "Path": str(ROOT),
        "Icon": str(ICON_THEME / "ytsysconfig.svg"),
        "StartupWMClass": APP_ID,
    }
    content = "\n".join(
        f"{line.split('=', 1)[0]}={values[line.split('=', 1)[0]]}"
        if line.split('=', 1)[0] in values else line
        for line in template.splitlines()
    ) + "\n"
    destination = applications / f"{APP_ID}.desktop"
    if not destination.exists() or destination.read_text(encoding="utf-8") != content:
        destination.write_text(content, encoding="utf-8")


def main() -> int:
    error_log.install_exception_hooks('ui')
    GLib.set_prgname(APP_ID)
    GLib.set_application_name("shit加密")
    register_desktop_entry()
    app = YTControl()
    return app.run(sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
