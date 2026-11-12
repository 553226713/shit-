#!/usr/bin/env python3
"""Desktop configuration center and status window for the Linux client."""
from __future__ import annotations

import os
import socket
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

import yt_config  # noqa: E402
import auto_service  # noqa: E402
import error_log  # noqa: E402
from system_tray import SystemTray  # noqa: E402
from runtime_paths import VERSION  # noqa: E402

ROOT = yt_config.ROOT
APP_ID = "com.yangtu.ytconfig.control" + ("" if yt_config.PACKAGED else ".development")
ICON_THEME = ROOT / "assets/hicolor/scalable/apps"






def muted(label: str, **kwargs: Any) -> Gtk.Label:
    kwargs.setdefault("xalign", 0)
    widget = Gtk.Label(label=label, **kwargs)
    widget.add_css_class("muted")
    return widget


def card(child: Gtk.Widget) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    box.add_css_class("card")
    box.append(child)
    return box


def action_button(label: str, icon: str | None = None) -> Gtk.Button:
    button = Gtk.Button(label=label)
    if icon:
        button.set_icon_name(icon)
    button.add_css_class("suggested-action")
    return button


def secondary_button(label: str, icon: str | None = None) -> Gtk.Button:
    button = Gtk.Button(label=label)
    if icon:
        button.set_icon_name(icon)
    return button




class ClientWindow(Gtk.ApplicationWindow):
    def __init__(self, application: Gtk.Application, tray_error: str | None = None) -> None:
        super().__init__(application=application, title=f"shit加密 v{VERSION}")
        self.set_default_size(1080, 760)
        self.set_size_request(860, 620)
        self.settings = yt_config.load_settings()
        self.remote = yt_config.load_remote_policy()
        self.effective = yt_config.effective_config(self.settings, self.remote)
        self.dirty = False
        self.updating = False
        self._updating_widgets = False
        self.tray_error = tray_error
        self.auto_running = False
        self._monitor_refresh_source = None
        self._monitor_refresh_running = False
        self._monitor_refresh_pending = False
        self._start_monitor_when_ready = os.environ.get('YT_CONTROL_SKIP_MONITOR_START') != '1'
        self.server_result = "尚未检测"
        self._build_header()
        self._build_body()
        self._build_statusbar()
        self._install_css()
        self.set_icon_name("ytsysconfig")
        self.engine_ready = self._engine_ready()
        self._refresh_auto_status()
        self._load_fields()
        GLib.timeout_add_seconds(60, self._periodic_policy_check)
        GLib.timeout_add_seconds(30, self._environment_check)
        GLib.timeout_add_seconds(3, self._refresh_auto_status)
        GLib.timeout_add(500, self._startup_policy_check)

    def _build_header(self) -> None:
        header = Gtk.HeaderBar()
        title = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER)
        title.append(Gtk.Label(label=f"shit加密 v{VERSION}", xalign=0))
        title.append(muted("配置、策略与会话状态", xalign=0))
        header.set_title_widget(title)
        self.save_button = secondary_button("保存", "document-save-symbolic")
        self.save_button.connect("clicked", lambda _button: self._save())
        header.pack_end(self.save_button)
        minimize = Gtk.Button(icon_name="window-minimize-symbolic")
        minimize.set_tooltip_text("最小化到状态栏")
        minimize.add_css_class("flat")
        minimize.connect("clicked", lambda _button: self.set_visible(False))
        header.pack_end(minimize)
        update = secondary_button("更新策略", "view-refresh-symbolic")
        update.connect("clicked", lambda _button: self._update_policy())
        header.pack_start(update)
        logs = secondary_button("打开日志目录")
        logs.connect("clicked", lambda _button: self._open_logs())
        header.pack_start(logs)
        self.set_titlebar(header)

    def _open_logs(self) -> None:
        try:
            Gio.AppInfo.launch_default_for_uri(error_log.log_directory().as_uri(), None)
        except (OSError, GLib.Error) as error:
            self._show_error("打开日志目录失败", str(error))

    def _build_body(self) -> None:
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.set_child(body)
        self.paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.paned.set_resize_start_child(False)
        self.paned.set_shrink_start_child(False)
        self.paned.set_position(210)
        body.append(self.paned)

        sidebar = Gtk.ListBox()
        sidebar.add_css_class("navigation-sidebar")
        sidebar.set_selection_mode(Gtk.SelectionMode.SINGLE)
        sidebar.set_margin_top(10)
        sidebar.set_margin_bottom(10)
        sidebar.set_margin_start(8)
        sidebar.set_margin_end(8)
        sidebar.set_vexpand(True)
        for title in ["概览", "服务器与策略", "应用与程序名"]:
            row = Gtk.ListBoxRow()
            label = Gtk.Label(label=title, xalign=0)
            label.set_margin_top(10)
            label.set_margin_bottom(10)
            label.set_margin_start(12)
            label.set_margin_end(12)
            row.set_child(label)
            sidebar.append(row)
        self.paned.set_start_child(sidebar)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_hexpand(True)
        self.stack.set_vexpand(True)
        self.stack.add_titled(self._overview_page(), "overview", "概览")
        self.stack.add_titled(self._server_page(), "server", "服务器与策略")
        self.stack.add_titled(self._programs_page(), "programs", "应用与程序名")
        self.paned.set_end_child(self.stack)
        sidebar.connect("row-selected", self._sidebar_selected)
        sidebar.select_row(sidebar.get_row_at_index(0))

    def _build_statusbar(self) -> None:
        parent = self.get_child()
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        bar.add_css_class("statusbar")
        bar.set_margin_top(7)
        bar.set_margin_bottom(7)
        bar.set_margin_start(14)
        bar.set_margin_end(14)
        self.status_dot = Gtk.Label(label="●")
        self.status_dot.add_css_class("status-ready")
        self.status_primary = Gtk.Label(label="正在检查运行环境…", xalign=0)
        self.status_detail = muted("")
        self.status_detail.set_hexpand(True)
        self.status_detail.set_ellipsize(3)
        bar.append(self.status_dot)
        bar.append(self.status_primary)
        bar.append(self.status_detail)
        parent.append(bar)

    def _install_css(self) -> None:
        css = b"""
        .card {
            background: rgba(127, 127, 127, 0.10);
            border-radius: 12px;
            padding: 18px;
        }
        .compact-action { min-width: 24px; min-height: 24px; padding: 4px; }
        .compact-switch { min-width: 32px; min-height: 18px; }
        .compact-switch slider { min-width: 16px; min-height: 16px; }
        .compact-interval text { min-width: 36px; min-height: 24px; padding: 2px 6px; }
        .compact-interval button { min-width: 20px; min-height: 24px; padding: 2px; }
        .hero-title { font-size: 24px; font-weight: 700; }
        .metric-value { font-size: 21px; font-weight: 700; }
        .muted { opacity: 0.66; }
        .statusbar { background: rgba(127, 127, 127, 0.10); }
        .status-ready { color: #2ec27e; }
        .status-busy { color: #f5c211; }
        .status-error { color: #e01b24; }
        .policy-box { background: rgba(53, 132, 228, 0.10); border-radius: 10px; padding: 12px; }
        """
        provider = Gtk.CssProvider()
        provider.load_from_data(css)
        display = Gdk.Display.get_default()
        if display is not None:
            Gtk.IconTheme.get_for_display(display).add_search_path(str(ICON_THEME))
            Gtk.StyleContext.add_provider_for_display(
                display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )

    def _page(self) -> tuple[Gtk.ScrolledWindow, Gtk.Box]:
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        content.set_margin_top(24)
        content.set_margin_bottom(24)
        content.set_margin_start(28)
        content.set_margin_end(28)
        scroll.set_child(content)
        return scroll, content

    def _overview_page(self) -> Gtk.Widget:
        scroll, content = self._page()
        metrics = Gtk.Box(spacing=12, homogeneous=True)
        self.metric_engine = self._metric("加密引擎", "检查中")
        self.metric_policy = self._metric("有效策略", "未加载")
        self.metric_sessions = self._metric("Linux 匹配程序", "0")
        metrics.append(self.metric_engine[0])
        metrics.append(self.metric_policy[0])
        metrics.append(self.metric_sessions[0])
        content.append(metrics)

        auto_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        auto_card.add_css_class("card")
        auto_head = Gtk.Box(spacing=12)
        auto_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        auto_text.set_hexpand(True)
        auto_title = Gtk.Label(label="自动监控模式", xalign=0)
        auto_title.add_css_class("metric-value")
        auto_text.append(auto_title)
        auto_text.append(
            muted(
                "登录后常驻挂载支持目录，任意程序按原路径访问时自动加解密。",
                wrap=True,
            )
        )
        self.auto_action = action_button("启用自动监控", "media-playback-start-symbolic")
        self.auto_action.set_valign(Gtk.Align.CENTER)
        self.auto_action.add_css_class("compact-action")
        self.auto_action.set_tooltip_text("启停自动监控")
        self.auto_action.connect("clicked", lambda _button: self._toggle_auto_mode())
        auto_head.append(auto_text)
        auto_head.append(self.auto_action)
        auto_card.append(auto_head)
        self.auto_summary = muted("正在读取服务状态…")
        self.auto_summary.set_wrap(True)
        auto_card.append(self.auto_summary)
        startup_row = Gtk.Box(spacing=8)
        startup_row.append(Gtk.Label(label="开机启动（登录后自动监控）", xalign=0, hexpand=True))
        self.autostart_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.autostart_switch.set_active(auto_service.autostart_enabled())
        self.autostart_switch.connect("notify::active", self._toggle_autostart)
        startup_row.append(self.autostart_switch)
        auto_card.append(startup_row)
        auto_card.append(self._directory_controls())
        auto_card.append(muted("监控目录内全部文件参与检查，不按子目录名称、文件名或扩展名排除。明文保持明文，密文按程序权限解密。", wrap=True))
        creation_row = Gtk.Box(spacing=8)
        creation_row.append(Gtk.Label(label="新建文件保存格式", xalign=0, hexpand=True))
        self.new_file_mode = Gtk.DropDown.new_from_strings(["明文（默认）", "加密"])
        self.new_file_mode.connect("notify::selected", self._mark_dirty)
        creation_row.append(self.new_file_mode)
        apply_creation = Gtk.Button(label="应用")
        apply_creation.connect("clicked", lambda _button: self._apply_new_file_mode())
        creation_row.append(apply_creation)
        auto_card.append(creation_row)
        auto_card.append(muted("只影响之后新建的文件；已有文件和替换保存保持原格式。加密文件由受信程序读写。", wrap=True))
        content.append(auto_card)

        policy_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        policy_card.add_css_class("policy-box")
        policy_title = Gtk.Label(label="策略合并结果", xalign=0)
        policy_title.add_css_class("metric-value")
        self.policy_summary = muted("")
        self.policy_summary.set_wrap(True)
        policy_card.append(policy_title)
        policy_card.append(self.policy_summary)
        content.append(policy_card)

        return scroll

    def _metric(self, title: str, value: str) -> tuple[Gtk.Box, Gtk.Label]:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.add_css_class("card")
        label = Gtk.Label(label=value, xalign=0)
        label.add_css_class("metric-value")
        box.append(label)
        box.append(muted(title))
        return box, label

    def _server_page(self) -> Gtk.Widget:
        scroll, content = self._page()
        title = Gtk.Label(label="服务器与策略", xalign=0)
        title.add_css_class("hero-title")
        content.append(title)
        content.append(
            muted(
                "服务器是策略底线，本地配置只做追加。服务器中的密钥、目录和受信程序会保留到有效配置中。",
                wrap=True,
            )
        )

        server_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        server_card.append(Gtk.Label(label="服务器地址", xalign=0))
        self.server_host = Gtk.Entry()
        self.server_host.set_placeholder_text("例如：192.168.1.10")
        self.server_host.connect("changed", self._mark_dirty)
        server_card.append(self.server_host)

        server_card.append(muted("策略来源：服务器（同步 Windows 应用和 Linux 配置）", wrap=True))

        auto_row = Gtk.Box(spacing=8)
        self.auto_update = Gtk.Switch()
        self.auto_update.set_halign(Gtk.Align.START)
        self.auto_update.set_valign(Gtk.Align.CENTER)
        self.auto_update.add_css_class("compact-switch")
        self.auto_update.connect("notify::active", self._mark_dirty)
        auto_row.append(self.auto_update)
        auto_row.append(Gtk.Label(label="启动和定时自动更新", xalign=0))
        self.interval = Gtk.SpinButton.new_with_range(1, 1440, 1)
        self.interval.set_valign(Gtk.Align.CENTER)
        self.interval.add_css_class("compact-interval")
        self.interval.set_tooltip_text("自动更新间隔（分钟）")
        self.interval.connect("value-changed", self._mark_dirty)
        auto_row.append(self.interval)
        auto_row.append(muted("分钟"))
        server_card.append(auto_row)

        override_row = Gtk.Box(spacing=8)
        self.use_server_policy = Gtk.Switch()
        self.use_server_policy.set_halign(Gtk.Align.START)
        self.use_server_policy.set_valign(Gtk.Align.CENTER)
        self.use_server_policy.add_css_class("compact-switch")
        self.use_server_policy.connect("notify::active", self._mark_dirty)
        override_row.append(self.use_server_policy)
        override_row.append(Gtk.Label(label="应用服务器同步策略", xalign=0))
        restore = secondary_button("恢复已删除的策略项", "edit-undo-symbolic")
        restore.set_valign(Gtk.Align.CENTER)
        restore.add_css_class("compact-action")
        restore.set_tooltip_text("恢复已删除的服务器策略项")
        restore.connect("clicked", lambda _button: self._restore_remote_policy())
        override_row.append(restore)
        server_card.append(override_row)
        server_card.append(
            muted(
                "关闭后将只使用本地配置；目录和受信程序中的服务器条目也可单独删除。",
                wrap=True,
            )
        )

        buttons = Gtk.Box(spacing=8)
        test = secondary_button("检测网络", "network-transmit-receive-symbolic")
        test.connect("clicked", lambda _button: self._test_server())
        update = action_button("立即更新", "view-refresh-symbolic")
        update.connect("clicked", lambda _button: self._update_policy())
        import_button = secondary_button("导入策略", "document-open-symbolic")
        import_button.set_tooltip_text("导入本地策略文件（不是选择监控目录）")
        import_button.connect("clicked", lambda _button: self._import_policy_dialog())
        buttons.append(test)
        buttons.append(update)
        buttons.append(import_button)
        server_card.append(buttons)
        content.append(card(server_card))

        status_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        status_card.add_css_class("policy-box")
        self.server_status = muted("网络：尚未检测")
        self.policy_status = muted("策略：尚未更新")
        self.policy_source_status = muted("来源：未配置")
        status_card.append(self.server_status)
        status_card.append(self.policy_status)
        status_card.append(self.policy_source_status)
        content.append(status_card)

        received = Gtk.Expander(label="服务器同步原始内容")
        received.set_expanded(True)
        self.remote_policy_details = Gtk.Label(xalign=0, selectable=True, wrap=True)
        received.set_child(self.remote_policy_details)
        content.append(received)

        details = Gtk.Expander(label="策略适配说明")
        details.set_expanded(True)
        details.set_child(
            muted(
                "HTTP 地址应返回本程序约定的 JSON 策略；本机命令应把同一 JSON 写到 stdout。"
                "原生来源在登录后读取 Windows 已配置应用清单，同时保留 Linux 目录和密钥策略。"
                "LinuxJMData.dat 可从客户端运行目录导入，并自动读取同目录的 sgfs.conf 进程规则。"
                "如果更新失败，有效策略保持不变。",
                wrap=True,
            )
        )
        content.append(details)
        return scroll

    def _directory_controls(self) -> Gtk.Widget:
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        head = Gtk.Box(spacing=12)
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        title_box.set_hexpand(True)
        title = Gtk.Label(label="支持目录", xalign=0)
        title.add_css_class("metric-value")
        title_box.append(title)
        title_box.append(muted("选择需要监控的目录；添加、删除或启停后自动保存并更新监控。", wrap=True))
        add = secondary_button("添加目录", "folder-new-symbolic")
        add.set_valign(Gtk.Align.CENTER)
        add.add_css_class("compact-action")
        add.set_tooltip_text("添加监控目录")
        add.connect("clicked", lambda _button: self._add_directory())
        head.append(title_box)
        head.append(add)
        content.append(head)
        self.directory_list = Gtk.ListBox()
        self.directory_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.directory_list.add_css_class("boxed-list")
        content.append(self.directory_list)
        return content

    def _programs_page(self) -> Gtk.Widget:
        scroll, content = self._page()
        head = Gtk.Box(spacing=12)
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        title_box.set_hexpand(True)
        title = Gtk.Label(label="应用与程序名", xalign=0)
        title.add_css_class("hero-title")
        title_box.append(title)
        title_box.append(
            muted(
                "Windows 应用策略自动同步，按去扩展名、转小写后的名称匹配本机 Linux 程序。",
                wrap=True,
            )
        )
        head.append(title_box)
        content.append(head)
        self.remote_program_summary = Gtk.Label(xalign=0, selectable=True, wrap=True)
        content.append(self.remote_program_summary)

        expander = Gtk.Expander(label="受信程序名与通配符")
        expander.set_expanded(True)
        rules_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        rules_box.set_margin_top(12)
        rules_box.append(
            muted(
                "每行一个名称，支持 *。服务器下发的规则始终保留；这里只追加本地规则。",
                wrap=True,
            )
        )
        self.trusted_summary = muted("")
        rules_box.append(self.trusted_summary)
        self.trusted_text = Gtk.TextView()
        self.trusted_text.set_monospace(True)
        self.trusted_text.set_top_margin(8)
        self.trusted_text.set_bottom_margin(8)
        self.trusted_text.set_left_margin(8)
        self.trusted_text.set_right_margin(8)
        self.trusted_text.get_buffer().connect("changed", self._mark_dirty)
        rules_scroll = Gtk.ScrolledWindow()
        rules_scroll.set_min_content_height(220)
        rules_scroll.set_child(self.trusted_text)
        rules_box.append(rules_scroll)
        expander.set_child(rules_box)
        content.append(expander)
        return scroll

    def _sidebar_selected(self, _listbox: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        if row is None:
            return
        names = ["overview", "server", "programs"]
        self.stack.set_visible_child_name(names[row.get_index()])

    def _load_fields(self) -> None:
        server = self.settings["server"]
        self.new_file_mode.set_selected(1 if self.settings["encryption"]["new_file_mode"] == "encrypted" else 0)
        self.server_host.set_text(server["host"])
        self.auto_update.set_active(bool(server["auto_update"]))
        self.interval.set_value(int(server["update_interval_minutes"]))
        self.use_server_policy.set_active(
            bool(self.settings["local_overrides"]["use_server_policy"])
        )
        self._refresh_dynamic_fields()
        self._set_trusted_text()
        self._refresh_status()
        self.dirty = False

    def _collect_fields(self) -> dict[str, Any]:
        source = self.settings["server"]["policy_source"]
        self.settings["encryption"]["new_file_mode"] = "encrypted" if self.new_file_mode.get_selected() == 1 else "plain"
        buffer = self.trusted_text.get_buffer()
        trusted = buffer.get_text(
            buffer.get_start_iter(), buffer.get_end_iter(), True
        ).splitlines()
        self.settings["server"] = {
            "host": self.server_host.get_text().strip(),
            "policy_source": {
                "type": "native",
                "value": source["value"] if source["type"] == "native" else "",
                "timeout_seconds": self.settings["server"]["policy_source"][
                    "timeout_seconds"
                ],
            },
            "auto_update": self.auto_update.get_active(),
            "update_interval_minutes": int(self.interval.get_value()),
        }
        desired = [rule.strip() for rule in trusted if rule.strip()]
        use_server = self.use_server_policy.get_active()
        remote_rules = (
            self.remote["trusted_programs"] if self.remote and use_server else []
        )
        if use_server:
            self.settings["local_overrides"]["removed_server_programs"] = [
                rule for rule in remote_rules if rule not in desired
            ]
        self.settings["trusted_programs"] = [
            rule for rule in desired if rule not in remote_rules
        ]
        self.settings["local_overrides"]["use_server_policy"] = use_server
        return self.settings

    def _apply_new_file_mode(self) -> None:
        if self._save(quiet=True):
            self.status_detail.set_text("新建文件格式已保存，监控运行时将自动更新")

    def _save(self, quiet: bool = False) -> bool:
        try:
            self.settings = yt_config.normalize_settings(self._collect_fields())
            candidate = yt_config.effective_config(self.settings, self.remote)
            yt_config.save_settings(self.settings)
            self.remote = yt_config.load_remote_policy()
            self.effective = candidate
            if candidate["encryption"]["key"]:
                self.effective = yt_config.write_effective_runtime_config(self.settings, self.remote)
                self._queue_monitor_refresh()
            self.dirty = False
            self._refresh_dynamic_fields()
            self._set_trusted_text()
            self._refresh_status(save_ok=True)
            if not quiet:
                self.status_detail.set_text("配置已保存")
            return True
        except (OSError, ValueError, RuntimeError) as error:
            self._show_error("保存配置失败", str(error))
            return False

    def _mark_dirty(self, *_args: Any) -> None:
        if self._updating_widgets:
            return
        self.dirty = True
        self.status_detail.set_text("配置有未保存修改")
        self.status_dot.remove_css_class("status-ready")
        self.status_dot.add_css_class("status-busy")

    def _refresh_dynamic_fields(self) -> None:
        self._refresh_directory_rows()
        remote = self.remote
        remote_text = (
            f"服务器策略：{remote['updated_at']}，{len(remote['trusted_programs'])} 条程序规则"
            if remote
            else "服务器策略：尚未导入"
        )
        self.policy_source_status.set_text(
            f"{remote_text}\n"
            f"服务器下发：Windows 应用 {len(remote.get('windows_applications', [])) if remote else 0} 个、"
            f"目录 {len(remote['directories']) if remote else 0} 个、"
            f"程序 {len(remote['trusted_programs']) if remote else 0} 条、"
            f"文件规则 {len(remote['file_patterns']) if remote else 0} 条；"
            f"密钥 {'已更新' if remote and remote['encryption_key'] else '未更新'}\n"
            f"本地增量：{len(self.settings['directories'])} 个目录；"
            f"已删除服务器项 {len(self.effective['removed_server_directories'])} 个目录、"
            f"{len(self.effective['removed_server_programs'])} 条程序规则"
        )
        if remote:
            removed = set(self.effective["removed_server_programs"])
            program_lines = [
                name + ("（本地已删除）" if name in removed else "")
                for name in remote["trusted_programs"]
            ]
            program_text = "\n".join(program_lines) or "未收到应用/程序名称（0 条）"
            directory_lines = [
                item["path"]
                + ("（本地已删除）" if item["path"] in self.effective["removed_server_directories"] else "")
                + ("（服务器已停用）" if not item["enabled"] else "")
                for item in remote["directories"]
            ]
            self.remote_policy_details.set_text(
                f"来源：{remote['source']}\n更新时间：{remote['updated_at']}\n"
                f"服务器策略：{'已应用' if self.effective['server_policy_applied'] else '本地已停用'}\n"
                "应用/程序名称：\n" + program_text
                + "\n支持目录：\n" + ("\n".join(directory_lines) or "未下发")
                + "\n文件规则：\n" + ("\n".join(remote["file_patterns"]) or "未下发")
            )
            application_text = "\n".join(
                item["name"] + (" · " + " | ".join(item["processes"]) if item["processes"] else "")
                for item in remote.get("windows_applications", [])
            )
            matches_text = "\n".join(
                linux + " → " + " | ".join(windows)
                for linux, windows in self.effective.get("program_matches", {}).items()
            ) or "尚未匹配到本机程序"
            self.remote_program_summary.set_text(
                "Windows 配置应用：\n" + (application_text or program_text)
                + "\n\nLinux 匹配结果：\n" + matches_text
            )
        else:
            self.remote_policy_details.set_text("尚未收到服务器策略。")
            self.remote_program_summary.set_text("服务器应用/程序名称：尚未同步。")
        server_program_count = len(remote["trusted_programs"]) if remote else 0
        self.trusted_summary.set_text(
            f"服务器规则 {server_program_count} 条；"
            f"本地追加 {len(self.settings['trusted_programs'])} 条；"
            f"当前启用 {len(self.effective['trusted_programs'])} 条。"
        )

    def _set_trusted_text(self) -> None:
        buffer = self.trusted_text.get_buffer()
        self._updating_widgets = True
        try:
            explicit = set(self.settings["trusted_programs"])
            if self.remote:
                explicit.update(self.remote["trusted_programs"])
            buffer.set_text("\n".join(
                rule for rule in self.effective["trusted_programs"] if rule in explicit
            ))
        finally:
            self._updating_widgets = False

    def _refresh_directory_rows(self) -> None:
        child = self.directory_list.get_first_child()
        while child is not None:
            next_child = child.get_next_sibling()
            self.directory_list.remove(child)
            child = next_child
        if not self.effective["directories"]:
            row = Gtk.ListBoxRow()
            row.set_child(muted("尚未配置支持目录。", margin_top=18, margin_bottom=18))
            self.directory_list.append(row)
            return
        self._directory_warnings = {}
        for item in self.effective["directories"]:
            row = Gtk.ListBoxRow()
            box = Gtk.Box(spacing=12)
            box.set_margin_top(4)
            box.set_margin_bottom(4)
            box.set_margin_start(12)
            box.set_margin_end(12)
            labels = Gtk.Label(label=item["path"], xalign=0)
            labels.set_hexpand(True)
            labels.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
            labels.set_tooltip_text(item["path"])
            source = muted("服务器" if item["source"] == "server" else "本地")
            enabled = Gtk.Switch()
            enabled.set_valign(Gtk.Align.CENTER)
            enabled.set_active(item["enabled"])
            enabled.set_sensitive(item["source"] == "local")
            enabled.connect(
                "notify::active",
                lambda switch, _param, path=item["path"]: self._set_directory_enabled(
                    path, switch.get_active()
                ),
            )
            remove = Gtk.Button(icon_name="user-trash-symbolic")
            remove.add_css_class("flat")
            remove.add_css_class("compact-action")
            remove.set_valign(Gtk.Align.CENTER)
            remove.set_tooltip_text("删除监控目录")
            remove.connect(
                "clicked",
                lambda _button, path=item["path"]: self._remove_directory(path),
            )
            box.append(labels)
            warning = Gtk.Label(xalign=0)
            warning.add_css_class("warning")
            self._directory_warnings[item["path"]] = warning
            box.append(warning)
            box.append(source)
            box.append(enabled)
            box.append(remove)
            row.set_child(box)
            self.directory_list.append(row)


    def _refresh_status(self, save_ok: bool = False) -> None:
        active = len(self.effective.get("program_matches", {}))
        self.metric_engine[1].set_text(
            "自动监控" if self.auto_running else ("就绪" if self.engine_ready else "需检查")
        )
        self.metric_policy[1].set_text(
            "服务器 + 本地" if self.remote else "仅本地"
        )
        self.metric_sessions[1].set_text(str(active))
        summary = (
            f"文件规则 {self.effective['encryption']['file_pattern']}；"
            f"受信程序 {len(self.effective['trusted_programs'])} 条；"
            f"支持目录 {sum(1 for d in self.effective['directories'] if d['enabled'])} 个；"
            f"密钥来源 {self.effective['encryption']['key_source']}；"
            f"服务器策略{'已应用' if self.effective['server_policy_applied'] else '已停用'}。"
        )
        self.policy_summary.set_text(summary)
        policy = self.settings["policy"]
        if policy.get("last_error"):
            self.policy_status.set_text(f"最近更新失败：{policy['last_error']}")
        elif policy.get("last_success"):
            self.policy_status.set_text(f"最近更新成功：{policy['last_success']}")
        else:
            self.policy_status.set_text("策略：尚未从服务器更新")
        self.server_status.set_text(f"网络：{self.server_result}")
        if self.auto_running:
            self.status_primary.set_text("自动监控运行中")
        else:
            self.status_primary.set_text(
                "文件服务就绪" if self.engine_ready else "运行环境需要检查"
            )
        detail = f"已匹配 {active} 个 Linux 程序"
        if self.tray_error:
            detail += f" · 托盘不可用：{self.tray_error}"
        if save_ok:
            detail += " · 配置已保存"
        self.status_detail.set_text(detail)
        self.status_dot.remove_css_class("status-busy")
        self.status_dot.remove_css_class("status-error")
        self.status_dot.add_css_class(
            "status-ready" if self.engine_ready else "status-error"
        )
        tray = getattr(self.get_application(), "tray", None)
        if tray is not None:
            tray.set_summary(
                f"自动监控{'运行中' if self.auto_running else '未运行'} · 匹配 {active} 个程序"
            )

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
        existing = {item["path"] for item in self.settings["directories"]}
        if path not in existing:
            self.settings["directories"].append({"path": path, "enabled": True})
            self._apply_directory_change()

    def _set_directory_enabled(self, path: str, enabled: bool) -> None:
        for item in self.settings["directories"]:
            if item["path"] == path:
                item["enabled"] = enabled
                self._apply_directory_change()
                return

    def _remove_directory(self, path: str) -> None:
        self._delete_directory(path)

    def _delete_directory(self, path: str) -> None:
        self.settings["directories"] = [
            item for item in self.settings["directories"] if item["path"] != path
        ]
        if self.remote and any(
            item["path"] == path for item in self.remote["directories"]
        ):
            removed = self.settings["local_overrides"]["removed_server_directories"]
            if path not in removed:
                removed.append(path)
        self._apply_directory_change()

    def _apply_directory_change(self) -> None:
        try:
            self.settings = yt_config.save_settings(self.settings)
            self.effective = yt_config.write_effective_runtime_config(self.settings, self.remote)
            self._refresh_dynamic_fields()
            self._queue_monitor_refresh()
            self.status_detail.set_text("目录已保存，正在更新监控…")
        except (OSError, ValueError, RuntimeError) as error:
            self._show_error("目录更新失败", str(error))

    def _queue_monitor_refresh(self) -> None:
        self._monitor_refresh_pending = True
        if not self._monitor_refresh_running and self._monitor_refresh_source is None:
            self._monitor_refresh_source = GLib.timeout_add(200, self._start_monitor_refresh)

    def _start_monitor_refresh(self) -> bool:
        self._monitor_refresh_source = None
        self._monitor_refresh_pending = False
        self._monitor_refresh_running = True

        def work() -> None:
            try:
                status = auto_service.status()
                if status.get("active") or status.get("enabled") or status.get("state") == "activating":
                    auto_service.restart()
                GLib.idle_add(self._monitor_refreshed, None)
            except Exception as error:
                GLib.idle_add(self._monitor_refreshed, str(error))

        threading.Thread(target=work, daemon=True).start()
        return False

    def _monitor_refreshed(self, error: str | None) -> bool:
        self._monitor_refresh_running = False
        self._refresh_auto_status()
        self._refresh_status()
        if error:
            self._show_error("监控目录更新失败", error)
        else:
            self.status_detail.set_text("监控目录已更新")
        if self._monitor_refresh_pending:
            self._queue_monitor_refresh()
        return False

    def _restore_remote_policy(self) -> None:
        self.settings["local_overrides"]["removed_server_directories"] = []
        self.settings["local_overrides"]["removed_server_programs"] = []
        self.settings["local_overrides"]["use_server_policy"] = True
        self.use_server_policy.set_active(True)
        self.dirty = True
        self.effective = yt_config.effective_config(self.settings, self.remote)
        self._refresh_dynamic_fields()
        self._set_trusted_text()






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
            status = auto_service.status()
        except (OSError, RuntimeError) as error:
            self.auto_running = False
            self.auto_summary.set_text(f"自动监控状态读取失败：{error}")
            return True
        runtime = status.get("runtime", {})
        for path, label in getattr(self, "_directory_warnings", {}).items():
            message = ""
            try:
                if not Path(path).is_dir():
                    message = "目录不存在" if not Path(path).exists() else "不是目录"
            except OSError:
                message = "目录不可访问"
            if not message and status.get("active"):
                message = runtime.get("skipped", {}).get(path, "")
            label.set_text("已跳过" if len(message) > 16 else message)
            label.set_tooltip_text(message or None)
            label.set_visible(bool(message))
        active = bool(status.get("active"))
        running = active and runtime.get("state") == "running"
        self.auto_running = running
        if running:
            mounts = runtime.get("mounts", [])
            self.auto_summary.set_text(
                f"状态：运行中；已挂载 {len(mounts)} 个目录："
                + ("、".join(mounts) if mounts else "无")
            )
            self.auto_action.set_label("停止自动监控")
            self.auto_action.set_icon_name("media-playback-stop-symbolic")
        elif active:
            state = runtime.get("state", status.get("substate", "starting"))
            if state == "idle":
                state = "等待可用监控目录"
            error = runtime.get("error")
            self.auto_summary.set_text(
                f"状态：{state}" + (f"；{error}" if error else "")
            )
            self.auto_action.set_label("停止自动监控")
            self.auto_action.set_icon_name("media-playback-stop-symbolic")
        else:
            self.auto_summary.set_text(
                "状态：等待加密密钥，请连接服务器同步密钥。"
                if not self.effective["encryption"]["key"] else
                "状态：未运行。启用后所有程序按原路径透明访问。"
            )
            self.auto_action.set_label("启用自动监控")
            self.auto_action.set_icon_name("media-playback-start-symbolic")
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
        if auto_service.status().get("active"):
            self._start_monitor_when_ready = False
            self._run_auto_action(auto_service.stop)
        else:
            self._start_monitor_when_ready = True
            self._run_auto_action(auto_service.start)

    def _run_auto_action(self, action) -> None:
        self.auto_action.set_sensitive(False)
        self.auto_summary.set_text("正在更新自动监控服务…")

        def work() -> None:
            try:
                action()
                GLib.idle_add(self._auto_action_done, None)
            except Exception as error:
                GLib.idle_add(self._auto_action_done, str(error))

        threading.Thread(target=work, daemon=True).start()

    def _auto_action_done(self, error: str | None) -> bool:
        self.auto_action.set_sensitive(True)
        self._refresh_auto_status()
        self._refresh_status()
        if error:
            self._show_error("自动监控操作失败", error)
        return False

    def _periodic_policy_check(self) -> bool:
        if self.settings["server"]["host"] and yt_config.should_auto_update(self.settings) and not self.updating:
            self._update_policy()
        return True

    def _startup_policy_check(self) -> bool:
        if self._start_monitor_when_ready and self.effective["encryption"]["key"]:
            self._run_auto_action(auto_service.start)
        self._periodic_policy_check()
        return False

    def _test_server(self) -> None:
        if not self._save(quiet=True):
            return
        host = self.settings["server"]["host"]
        self.server_result = "检测中…"
        self._refresh_status()

        def work() -> None:
            ok, message = yt_config.check_server(host)
            GLib.idle_add(self._server_checked, ok, message)

        threading.Thread(target=work, daemon=True).start()

    def _server_checked(self, ok: bool, message: str) -> bool:
        if not ok:error_log.logger('ui').error('Server check failed: %s', message)
        self.server_result = message
        self._refresh_status()
        return False

    def _update_policy(self) -> None:
        if self.updating:
            return
        if not self._save(quiet=True):
            return
        if self.settings["server"]["policy_source"]["type"] == "none":
            self._show_error("无法更新策略", "请先选择策略来源并填写地址或命令")
            return
        self.updating = True
        self.status_dot.remove_css_class("status-ready")
        self.status_dot.add_css_class("status-busy")
        self.status_primary.set_text("正在更新策略")
        self.status_detail.set_text(str(self.settings["server"]["policy_source"]["value"]))

        def work() -> None:
            try:
                policy = yt_config.update_policy(self.settings)
                if auto_service.status().get("active"):
                    auto_service.restart()
                GLib.idle_add(self._policy_updated, policy, None)
            except Exception as error:
                GLib.idle_add(self._policy_updated, None, str(error))

        threading.Thread(target=work, daemon=True).start()

    def _policy_updated(self, policy: dict[str, Any] | None, error: str | None) -> bool:
        if error:error_log.logger('ui').error('Policy refresh failed: %s', error)
        self.updating = False
        self.settings = yt_config.load_settings()
        self.remote = yt_config.load_remote_policy()
        self.effective = yt_config.effective_config(self.settings, self.remote)
        self._refresh_dynamic_fields()
        self._set_trusted_text()
        self._refresh_status()
        if error:
            self.status_detail.set_text(f"策略更新失败：{error}")
            self.status_dot.remove_css_class("status-busy")
            self.status_dot.add_css_class("status-error")
        else:
            self.status_detail.set_text(
                "服务器策略已更新并完成本地合并" if self.effective["encryption"]["key"] else
                "应用策略已同步；服务器未提供当前密钥，等待密钥就绪后自动启动监控"
            )
            if self._start_monitor_when_ready and self.effective["encryption"]["key"] and not self.auto_running:
                self._run_auto_action(auto_service.start)
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
            self.effective = yt_config.write_effective_runtime_config(
                self.settings, policy
            )
            if auto_service.status().get("active"):
                auto_service.restart()
            self._refresh_dynamic_fields()
            self._set_trusted_text()
            self._refresh_status(save_ok=True)
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
        self.window.unminimize()
        self.window.set_visible(True)
        self.window.present_with_time(self._activation_timestamp or Gdk.CURRENT_TIME)
        surface = self.window.get_surface()
        if isinstance(surface, Gdk.Toplevel):
            surface.focus(self._activation_timestamp or Gdk.CURRENT_TIME)
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
    template = (ROOT / 'com.yangtu.ytconfig.control.desktop').read_text(encoding="utf-8")
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
