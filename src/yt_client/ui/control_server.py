"""Server configuration and policy presentation, independent of the controller.

Callbacks own persistence and network work. In particular, testing and syncing
never apply the values currently being edited in this page.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from yt_client.ui.control_widgets import (
    action_button,
    badge,
    card,
    muted,
    page_frame,
    page_heading,
    secondary_button,
    set_badge,
)


class ServerPage(Gtk.Box):
    def __init__(
        self,
        on_apply: Callable[[], bool],
        on_test: Callable[[], None],
        on_sync: Callable[[], None],
        on_import: Callable[[], None],
        on_restore: Callable[[], None],
        on_dirty: Callable[[], None],
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, hexpand=True, vexpand=True)
        self._on_apply = on_apply
        self._on_dirty = on_dirty
        self._loading = False
        self._updating = False

        scroll, content = page_frame()
        self.append(scroll)
        content.append(page_heading(
            "服务器与策略",
            "配置连接、同步策略，并查看服务器与本地设置合并后的实际结果。",
        ))

        connection = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        connection_head = Gtk.Box(spacing=12)
        connection_title = self._title("服务器连接")
        connection_title.set_hexpand(True)
        connection_head.append(connection_title)
        self.feedback = badge("已保存", "success")
        connection_head.append(self.feedback)
        self.apply_button = action_button("应用配置")
        self.apply_button.connect("clicked", self._apply)
        connection_head.append(self.apply_button)
        connection.append(connection_head)
        host_row = Gtk.Box(spacing=10)
        self.server_host = Gtk.Entry(hexpand=True)
        self.server_host.set_placeholder_text("输入服务器主机名或 IP 地址")
        self.server_host.set_tooltip_text("服务器主机名或 IP 地址；修改后需应用配置")
        self.server_host.connect("changed", self._mark_dirty)
        host_row.append(self.server_host)
        self.test_button = secondary_button("检测连接")
        self.test_button.connect("clicked", lambda _button: on_test())
        self.test_button.set_tooltip_text("检测连接不会自动保存未应用的修改；显示实际返回结果")
        host_row.append(self.test_button)
        connection.append(host_row)
        self.connection_status = muted("尚未检测连接", wrap=True, selectable=True)
        connection.append(self.connection_status)
        content.append(card(connection))

        sync = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        sync_head = Gtk.Box(spacing=12)
        sync_title = self._title("策略同步")
        sync_title.set_hexpand(True)
        sync_head.append(sync_title)
        self.sync_button = action_button("立即同步")
        self.sync_button.connect("clicked", lambda _button: on_sync())
        self.sync_button.set_tooltip_text("同步使用已保存配置，不会自动应用当前草稿；失败时保留此前有效策略")
        sync_head.append(self.sync_button)
        sync.append(sync_head)
        auto_row = Gtk.Box(spacing=12)
        auto_label = Gtk.Label(label="启动和定时自动同步", xalign=0, hexpand=True, wrap=True)
        auto_row.append(auto_label)
        self.auto_update = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.auto_update.add_css_class("compact-switch")
        self.auto_update.connect("notify::active", self._mark_dirty)
        auto_row.append(self.auto_update)
        self.interval = Gtk.SpinButton.new_with_range(1, 1440, 1)
        self.interval.set_numeric(True)
        self.interval.set_tooltip_text("自动同步间隔，1–1440 分钟")
        self.interval.connect("value-changed", self._mark_dirty)
        auto_row.append(muted("每"))
        auto_row.append(self.interval)
        auto_row.append(muted("分钟"))
        sync.append(auto_row)
        sync_status_row = Gtk.Box(spacing=12)
        self.sync_state = badge("尚未同步")
        sync_status_row.append(self.sync_state)
        self.last_success = muted("最近成功：尚无成功记录", wrap=True, selectable=True)
        sync_status_row.append(self.last_success)
        sync.append(sync_status_row)
        self.last_attempt = muted("最近尝试：尚无同步记录", wrap=True, selectable=True)
        self.last_error = muted("最近错误：无", wrap=True, selectable=True)
        self.last_error.set_visible(False)
        sync.append(self.last_error)
        content.append(card(sync))

        policy = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        policy.set_tooltip_text("显示已应用配置，不含草稿；仅显示密钥是否存在及来源，不显示密钥内容")
        policy_head = Gtk.Box(spacing=12)
        policy_title = self._title("当前有效策略")
        policy_title.set_hexpand(True)
        policy_head.append(policy_title)
        self.policy_state = badge("尚无服务器策略")
        policy_head.append(self.policy_state)
        policy.append(policy_head)
        self.policy_source = self._description_row(policy, "策略来源")
        self.key_status = self._description_row(policy, "加密密钥")
        self.directory_status = self._description_row(policy, "监控目录")
        self.program_status = self._description_row(policy, "受信程序")
        content.append(card(policy))

        self.raw_expander = Gtk.Expander(label="服务器同步原始内容（不含密钥）")
        self.raw_expander.set_expanded(False)
        self.remote_policy_details = Gtk.Label(xalign=0, wrap=True, selectable=True)
        self.raw_expander.set_child(self.remote_policy_details)
        content.append(card(self.raw_expander))

        self.adaptation_expander = Gtk.Expander(label="策略适配说明")
        self.adaptation_expander.set_expanded(False)
        self.adaptation_details = muted("尚无策略适配信息。", wrap=True, selectable=True)
        self.adaptation_expander.set_child(self.adaptation_details)
        content.append(card(self.adaptation_expander))

        advanced = Gtk.Expander(label="高级策略控制")
        advanced.set_expanded(False)
        advanced_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        advanced_content.append(self.last_attempt)
        self.local_status = self._description_row(advanced_content, "本地配置与覆盖")
        advanced_content.append(muted(
            "服务器策略可整体停用，目录和程序条目也可在对应页面单独删除；"
            "本地配置参与最终合并。检测连接和立即同步不会自动保存草稿。",
            wrap=True,
        ))
        override_row = Gtk.Box(spacing=12)
        override_row.append(Gtk.Label(label="应用服务器同步策略", xalign=0, hexpand=True, wrap=True))
        self.use_server_policy = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.use_server_policy.add_css_class("compact-switch")
        self.use_server_policy.connect("notify::active", self._mark_dirty)
        override_row.append(self.use_server_policy)
        advanced_content.append(override_row)
        advanced_content.append(muted(
            "关闭并应用配置后，只使用本地配置；重新开启不会自动恢复单独删除的服务器条目。",
            wrap=True,
        ))
        advanced_buttons = Gtk.Box(spacing=10)
        self.import_button = secondary_button("导入策略")
        self.import_button.set_tooltip_text("导入 JSON 或 LinuxJMData.dat 策略文件")
        self.import_button.connect("clicked", lambda _button: on_import())
        advanced_buttons.append(self.import_button)
        self.restore_button = secondary_button("恢复已删除的策略项")
        self.restore_button.set_tooltip_text("恢复本地已删除的服务器目录和程序条目，并启用服务器策略")
        self.restore_button.connect("clicked", lambda _button: on_restore())
        advanced_buttons.append(self.restore_button)
        advanced_content.append(advanced_buttons)
        self.removed_status = muted("尚无已删除的服务器策略项。", wrap=True)
        advanced_content.append(self.removed_status)
        advanced.set_child(advanced_content)
        content.append(card(advanced))

    @staticmethod
    def _title(text: str) -> Gtk.Label:
        label = Gtk.Label(label=text, xalign=0)
        label.add_css_class("section-title")
        return label

    @staticmethod
    def _description_row(container: Gtk.Box, title: str) -> Gtk.Label:
        row = Gtk.Box(spacing=12)
        row.add_css_class("list-row")
        label = Gtk.Label(label=title, xalign=0, valign=Gtk.Align.START)
        label.set_size_request(80, -1)
        row.append(label)
        description = muted("尚无数据", wrap=True, selectable=True, hexpand=True)
        row.append(description)
        container.append(row)
        return description

    def _mark_dirty(self, *_args: Any) -> None:
        if self._loading:
            return
        self.set_feedback("未应用", "warning")
        self._on_dirty()

    def _apply(self, _button: Gtk.Button) -> None:
        if self._on_apply():
            self.set_feedback("已保存", "success")

    def load(self, settings: dict, remote: dict | None, effective: dict) -> None:
        """Load saved editable values without emitting the dirty callback."""
        self._loading = True
        try:
            server = settings.get("server", {})
            self.server_host.set_text(str(server.get("host", "")))
            self.auto_update.set_active(bool(server.get("auto_update", True)))
            self.interval.set_value(int(server.get("update_interval_minutes", 30)))
            self.use_server_policy.set_active(bool(
                settings.get("local_overrides", {}).get("use_server_policy", True)
            ))
        finally:
            self._loading = False
        self.refresh(settings, remote, effective)
        self.set_feedback("已保存", "success")

    def values(self) -> dict:
        return {
            "host": self.server_host.get_text().strip(),
            "auto_update": self.auto_update.get_active(),
            "update_interval_minutes": self.interval.get_value_as_int(),
            "use_server_policy": self.use_server_policy.get_active(),
        }

    def set_feedback(self, text: str, kind: str) -> None:
        set_badge(self.feedback, text, kind)

    def set_connection(self, message: str, kind: str) -> None:
        """Present the controller's result verbatim; do not infer connectivity."""
        self.connection_status.set_text(message)
        for name in ("neutral", "success", "warning", "error", "accent"):
            self.connection_status.remove_css_class("badge-" + name)
        self.connection_status.add_css_class("badge-" + kind)

    def set_sync(self, policy_metadata: dict, updating: bool) -> None:
        self._updating = updating
        self.apply_button.set_sensitive(not updating)
        self.server_host.set_sensitive(not updating)
        self.auto_update.set_sensitive(not updating)
        self.interval.set_sensitive(not updating)
        self.use_server_policy.set_sensitive(not updating)
        self.restore_button.set_sensitive(not updating)
        self.sync_button.set_sensitive(not updating)
        self.sync_button.set_label("正在同步…" if updating else "立即同步")
        self.import_button.set_sensitive(not updating)
        success = policy_metadata.get("last_success")
        attempt = policy_metadata.get("last_attempt")
        error = policy_metadata.get("last_error")
        self.last_success.set_text(f"最近成功：{success or '尚无成功记录'}")
        self.last_attempt.set_text(f"最近尝试：{attempt or '尚无同步记录'}")
        self.last_error.set_text(f"最近错误：{error or '无'}")
        self.last_error.set_visible(bool(error))
        if updating:
            set_badge(self.sync_state, "正在同步", "accent")
        elif error:
            set_badge(self.sync_state, "最近同步失败", "error")
        elif success:
            set_badge(self.sync_state, "已同步", "success")
        else:
            set_badge(self.sync_state, "尚未同步", "neutral")

    def refresh(self, settings: dict, remote: dict | None, effective: dict) -> None:
        """Refresh saved-policy descriptions while preserving all draft controls."""
        self.set_sync(settings.get("policy", {}), self._updating)
        applied = bool(effective.get("server_policy_applied"))
        overrides = settings.get("local_overrides", {})
        removed_dirs = effective.get("removed_server_directories", overrides.get("removed_server_directories", []))
        removed_programs = effective.get("removed_server_programs", overrides.get("removed_server_programs", []))
        state = "服务器 + 本地配置" if applied else "仅本地配置"
        set_badge(self.policy_state, state, "accent" if applied else "neutral")
        if remote:
            self.policy_source.set_text(f"服务器策略{'已应用' if applied else '未应用'} · 本地配置参与合并")
            self.policy_source.set_tooltip_text(
                f"来源：{remote.get('source') or '未提供'}\n"
                f"策略更新时间：{remote.get('updated_at') or '未提供'}"
            )
        else:
            self.policy_source.set_text("尚无服务器策略 · 使用本地配置")
            self.policy_source.set_tooltip_text("尚未收到或导入服务器策略")

        encryption = effective.get("encryption", {})
        if encryption.get("key"):
            source = {"server": "服务器", "local": "本地"}.get(encryption.get("key_source"), "未提供")
            self.key_status.set_text(f"已配置 · 来源：{source}（不显示密钥）")
        else:
            self.key_status.set_text("未配置有效密钥；加密监控需等待密钥就绪。")
        directories = effective.get("directories", [])
        server_dirs = sum(item.get("source") == "server" for item in directories)
        local_dirs = sum(item.get("source") == "local" for item in directories)
        enabled_dirs = sum(bool(item.get("enabled")) for item in directories)
        self.directory_status.set_text(
            f"当前有效 {len(directories)} 个（启用 {enabled_dirs} 个） · "
            f"服务器 {server_dirs} 个 / 本地 {local_dirs} 个"
        )
        server_programs = [
            name for name in (remote.get("trusted_programs", []) if remote and applied else [])
            if name not in removed_programs
        ]
        local_programs = settings.get("trusted_programs", [])
        self.program_status.set_text(
            f"有效 {len(effective.get('trusted_programs', []))} 条 · "
            f"服务器 {len(server_programs)} / 本地 {len(local_programs)} 条"
        )
        self.program_status.set_tooltip_text(
            f"Linux 应用匹配 {len(effective.get('program_matches', {}))} 个；重合规则合并去重。"
        )
        self.local_status.set_text(
            f"本地目录 {len(settings.get('directories', []))} 个；"
            f"已删除服务器目录 {len(removed_dirs)} 个、程序 {len(removed_programs)} 条。"
        )
        self.removed_status.set_text(
            f"本地已删除服务器目录 {len(removed_dirs)} 个、程序 {len(removed_programs)} 条。"
            if removed_dirs or removed_programs else "没有已删除的服务器策略项。"
        )
        self._refresh_details(remote, effective, removed_dirs, removed_programs)

    def _refresh_details(
        self, remote: dict | None, effective: dict, removed_dirs: list, removed_programs: list
    ) -> None:
        # Intentionally render an allow-list, never serialize the policy or key.
        if remote:
            program_lines = [
                str(name) + ("（本地已删除）" if name in removed_programs else "")
                for name in remote.get("trusted_programs", [])
            ]
            directory_lines = [
                str(item.get("path", ""))
                + ("（本地已删除）" if item.get("path") in removed_dirs else "")
                + ("（服务器已停用）" if not item.get("enabled", True) else "")
                for item in remote.get("directories", [])
            ]
            application_lines = [
                str(item.get("name", ""))
                + (" · " + " | ".join(item.get("processes", [])) if item.get("processes") else "")
                for item in remote.get("windows_applications", [])
            ]
            self.remote_policy_details.set_text(
                f"来源：{remote.get('source') or '未提供'}\n"
                f"更新时间：{remote.get('updated_at') or '未提供'}\n"
                f"密钥：{'已下发（不显示内容）' if remote.get('encryption_key') else '未下发'}\n\n"
                "Windows 应用：\n" + ("\n".join(application_lines) or "未下发")
                + "\n\n程序规则：\n" + ("\n".join(program_lines) or "未下发")
                + "\n\n目录：\n" + ("\n".join(directory_lines) or "未下发")
                + "\n\n文件规则：\n" + ("\n".join(remote.get("file_patterns", [])) or "未下发")
            )
        else:
            self.remote_policy_details.set_text("尚未收到或导入服务器策略，没有可显示的原始内容。")
        matches = "\n".join(
            linux + " → " + " | ".join(windows)
            for linux, windows in effective.get("program_matches", {}).items()
        ) or "尚未匹配到本机 Linux 程序。"
        self.adaptation_details.set_text(
            "服务器 Windows 应用和进程规则通过现有映射与本机 Linux 程序匹配；"
            "目录、程序规则和密钥按现有配置规则与本地设置合并。\n"
            "可导入 JSON 或 LinuxJMData.dat；导入原生策略时同时读取同目录 sgfs.conf。"
            "同步失败不会清除此前有效策略。\n\nLinux 匹配结果：\n" + matches
        )
