"""Directory configuration and authoritative monitor status for the GTK client."""
from __future__ import annotations

import os
import stat
from collections.abc import Callable
from functools import lru_cache
from time import monotonic

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
    path_label,
    secondary_button,
    set_badge,
)


def _normalized(path: str) -> str:
    # Do not resolve symlinks or touch a potentially disconnected FUSE mount.
    return os.path.normpath(os.path.abspath(os.path.expanduser(path)))


def _covers(parent: str, child: str) -> bool:
    return child == parent or child.startswith(parent.rstrip(os.sep) + os.sep)


@lru_cache(maxsize=256)
def _path_problem(path: str, _interval: int) -> str:
    """Share short-lived probes between the overview and directory page."""
    try:
        info = os.stat(path)
        if not stat.S_ISDIR(info.st_mode):
            return "配置的路径不是目录。"
        if not os.access(path, os.R_OK | os.X_OK):
            return "目录不可访问，请检查读取和进入目录的权限。"
    except FileNotFoundError:
        return "目录不存在，请确认路径或连接包含该目录的存储设备。"
    except OSError as error:
        return f"目录不可访问：{error}"
    return ""


def directory_state(item: dict, status: dict) -> tuple[str, str, str]:
    """Return a display label, badge kind and explanation without claiming readiness.

    Runtime mounts, not enabled configuration or service activation alone, establish
    coverage. A nested configured directory shares its parent's actual mount.
    """
    if not item.get("enabled", True):
        return "已停用", "neutral", "此目录已停用，不参与监控。"

    path = str(item.get("path", ""))
    if not path:
        return "目录异常", "warning", "目录路径为空。"
    normalized = _normalized(path)
    runtime = status.get("runtime") or {}
    active = bool(status.get("active"))
    running = active and runtime.get("state") == "running"
    skipped = runtime.get("skipped") or {}
    exact_reason = next(
        (str(reason) for candidate, reason in skipped.items()
         if _normalized(str(candidate)) == normalized and reason),
        "",
    )
    if exact_reason:
        suffix = "" if active else "；监控服务当前未运行。"
        return "已跳过", "warning", exact_reason + suffix

    historical_coverage = False
    for mount in runtime.get("mounts") or []:
        parent = _normalized(str(mount))
        if _covers(parent, normalized):
            historical_coverage = True
            if running:
                reason = "加密引擎已挂载此目录。" if parent == normalized else (
                    f"由父目录 {mount} 的挂载覆盖，无需重复挂载。"
                )
                return "已挂载", "success", reason

    parent_failures = [
        (str(parent), str(reason)) for parent, reason in skipped.items()
        if reason and _covers(_normalized(str(parent)), normalized)
    ]
    if parent_failures:
        parent, reason = max(parent_failures, key=lambda pair: len(pair[0]))
        suffix = "" if active else "；监控服务当前未运行。"
        return "已跳过", "warning", f"父目录 {parent} 未能挂载：{reason}{suffix}"

    if historical_coverage:
        # An old mount may be disconnected; never stat it to infer readiness.
        error = status.get("error") or runtime.get("error")
        if error:
            return "监控异常", "error", str(error)
        return "未挂载", "neutral", "存在历史挂载记录，但监控服务当前未确认正在运行。"

    # Avoid probing known mounted/skipped paths: a failed FUSE access can block.
    problem = _path_problem(normalized, int(monotonic() // 5))
    if problem:
        return "目录异常", "warning", problem
    service_error = status.get("error") or runtime.get("error")
    if service_error:
        return "监控异常", "error", str(service_error)
    if status.get("state") == "activating" or runtime.get("state") in ("starting", "initializing"):
        return "等待挂载", "neutral", "监控服务正在启动，等待实际挂载结果。"
    if runtime.get("state") == "failed":
        return "挂载失败", "error", "监控运行失败，请检查服务和加密引擎日志。"
    if not active:
        return "未挂载", "neutral", "监控服务未运行，此目录当前未被加密引擎挂载。"
    return "未挂载", "warning", "目录已启用，但运行状态尚未报告覆盖此路径的挂载。"


class DirectoriesPage(Gtk.Box):
    def __init__(
        self,
        *,
        on_add: Callable[[], None],
        on_toggle: Callable[[str, bool], None],
        on_remove: Callable[[str], None],
        on_retry: Callable[[], None],
        on_details: Callable[[str, str], None],
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self._on_add = on_add
        self._on_toggle = on_toggle
        self._on_remove = on_remove
        self._on_retry = on_retry
        self._on_details = on_details
        self._items: list[dict] = []
        self._states: list[tuple[str, str, str]] = []
        self._signature = None
        self._probe_interval = None
        self._filter = ""
        self._updating = False
        self._row_controls: list[tuple[Gtk.Widget, bool]] = []

        scroll, content = page_frame()
        self.append(scroll)
        self.add_button = action_button("添加文件夹")
        self.add_button.connect("clicked", lambda _button: self._on_add())
        content.append(page_heading(
            "监控目录", "管理需要透明加密的文件夹，查看每个目录的实际挂载状态。", self.add_button,
        ))

        summary = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        summary_top = Gtk.Box(spacing=12)
        title = Gtk.Label(label="目录监控状态", xalign=0, hexpand=True)
        title.add_css_class("section-title")
        summary_top.append(title)
        self.summary_badge = badge("尚未配置", "neutral")
        summary_top.append(self.summary_badge)
        summary.append(summary_top)
        self.summary_label = Gtk.Label(xalign=0, wrap=True)
        summary.append(self.summary_label)
        self.diagnostic = muted("", wrap=True)
        summary.append(self.diagnostic)
        self.retry_button = secondary_button("重试异常目录")
        self.retry_button.set_halign(Gtk.Align.START)
        self.retry_button.connect("clicked", lambda _button: self._on_retry())
        summary.append(self.retry_button)
        content.append(card(summary))

        self.search = Gtk.SearchEntry(hexpand=True)
        self.search.set_property("placeholder-text", "搜索目录名称或完整路径")
        self.search.connect("search-changed", self._search_changed)
        content.append(self.search)

        listing = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        heading = Gtk.Box(spacing=12)
        heading.add_css_class("table-heading")
        heading.append(Gtk.Label(label="目录 / 路径", xalign=0, hexpand=True))
        heading.append(muted("来源 · 状态 · 操作"))
        listing.append(heading)
        self.rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        listing.append(self.rows)
        content.append(card(listing))
        content.append(muted(
            "服务器目录由策略管理，不能在此切换启用状态。移除仅更改本机配置，不会删除文件；"
            "已移除的服务器目录可在服务器设置中恢复。", wrap=True,
        ))
        self.update({}, {})

    def update(self, effective: dict, service_status: dict, updating: bool = False) -> None:
        """Render an immutable snapshot; callbacks alone own persistence and retries."""
        runtime = service_status.get("runtime") or {}
        items = [
            {"path": str(item.get("path", "")),
             "enabled": bool(item.get("enabled", True)),
             "source": item.get("source", "local")}
            for item in effective.get("directories", [])
        ]
        # Ignore heartbeats, PIDs and unrelated compatibility diagnostics.
        signature = (
            tuple((item["path"], item["enabled"], item["source"]) for item in items),
            bool(service_status.get("active")), service_status.get("state"),
            service_status.get("error"), runtime.get("state"), runtime.get("error"),
            tuple(str(path) for path in runtime.get("mounts") or []),
            tuple(sorted((str(path), str(reason)) for path, reason in (runtime.get("skipped") or {}).items())),
        )
        self._updating = bool(updating)
        self.add_button.set_sensitive(not self._updating)
        probe_interval = int(monotonic() // 5)
        if signature != self._signature:
            self._signature = signature
            self._items = items
            self._states = [directory_state(item, service_status) for item in items]
            self._update_summary(service_status)
            self._rebuild_rows()
        elif probe_interval != self._probe_interval:
            states = [
                directory_state(item, service_status)
                if item["enabled"] and state[1] != "success" else state
                for item, state in zip(self._items, self._states)
            ]
            if states != self._states:
                self._states = states
                self._update_summary(service_status)
                self._rebuild_rows()
        self._probe_interval = probe_interval
        for widget, permitted in self._row_controls:
            widget.set_sensitive(permitted and not self._updating)
        self.retry_button.set_sensitive(not self._updating)
        self.retry_button.set_label("正在更新监控…" if self._updating else "重试异常目录")

    def _update_summary(self, status: dict) -> None:
        mounted = sum(kind == "success" for _label, kind, _reason in self._states)
        problems = sum(kind in ("warning", "error") for _label, kind, _reason in self._states)
        disabled = sum(not item["enabled"] for item in self._items)
        pending = len(self._items) - mounted - problems - disabled
        self.summary_label.set_text(
            f"已挂载 {mounted} 个 · 异常 {problems} 个 · 已停用 {disabled} 个"
            + (f" · 等待挂载 {pending} 个" if pending else "")
        )
        enabled = len(self._items) - disabled
        if problems:
            set_badge(self.summary_badge, "部分目录异常" if mounted else "需要处理", "warning")
            detail = (
                f"{problems} 个目录未正常挂载；其余 {mounted} 个已挂载目录继续受监控。"
                if mounted else f"{problems} 个目录存在异常，请查看对应原因后重试。"
            )
        elif not self._items:
            set_badge(self.summary_badge, "尚未配置", "neutral")
            detail = "添加一个文件夹，或从服务器同步监控目录。"
        elif not enabled:
            set_badge(self.summary_badge, "已全部停用", "neutral")
            detail = "当前没有启用的目录；启用本地目录或等待服务器策略更新。"
        elif mounted == enabled:
            set_badge(self.summary_badge, "挂载正常", "success")
            detail = "状态依据运行中的加密引擎；嵌套目录可由父目录的挂载统一覆盖。"
        else:
            set_badge(self.summary_badge, "等待挂载", "neutral")
            detail = "监控服务尚未报告所有启用目录的实际挂载，请在总览中检查监控状态。"
        error = status.get("error") or (status.get("runtime") or {}).get("error")
        if error:
            detail += f"\n服务诊断：{error}"
        self.diagnostic.set_text(detail)
        self.retry_button.set_visible(bool(problems))

    def _search_changed(self, entry: Gtk.SearchEntry) -> None:
        query = entry.get_text().strip().casefold()
        if query != self._filter:
            self._filter = query
            self._rebuild_rows()

    def _rebuild_rows(self) -> None:
        child = self.rows.get_first_child()
        while child is not None:
            following = child.get_next_sibling()
            self.rows.remove(child)
            child = following
        self._row_controls = []
        visible = [
            (item, state) for item, state in zip(self._items, self._states)
            if not self._filter or self._filter in item["path"].casefold()
        ]
        if not visible:
            empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            empty.add_css_class("empty-state")
            empty.set_margin_top(28)
            empty.set_margin_bottom(28)
            if self._items:
                empty.append(Gtk.Label(label="没有匹配的目录"))
                empty.append(muted("试试其他名称或路径，或清空搜索查看全部目录。", wrap=True, xalign=0.5))
                clear = secondary_button("清空搜索")
                clear.set_halign(Gtk.Align.CENTER)
                clear.connect("clicked", lambda _button: self.search.set_text(""))
                empty.append(clear)
            else:
                empty.append(Gtk.Label(label="还没有监控目录"))
                empty.append(muted("点击“添加文件夹”开始配置，或在服务器设置中同步策略。", wrap=True, xalign=0.5))
            self.rows.append(empty)
            return
        for item, (label, kind, reason) in visible:
            path = item["path"]
            local = item["source"] == "local"
            row = Gtk.Box(spacing=12)
            row.add_css_class("list-row")
            row.set_margin_top(10)
            row.set_margin_bottom(10)
            labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5, hexpand=True)
            friendly = path_label(os.path.basename(path.rstrip(os.sep)) or path)
            friendly.add_css_class("section-title")
            labels.append(friendly)
            full_path = path_label(path)
            full_path.add_css_class("muted")
            labels.append(full_path)
            row.append(labels)
            row.append(badge("本地追加" if local else "服务器", "neutral" if local else "accent"))
            state_badge = badge(label, kind)
            state_badge.set_tooltip_text(reason)
            row.append(state_badge)
            if kind in ("warning", "error"):
                details = secondary_button("查看原因")
                details.set_valign(Gtk.Align.CENTER)
                details.connect("clicked", lambda _button, p=path, r=reason: self._on_details(p, r))
                row.append(details)
            toggle = Gtk.Switch(valign=Gtk.Align.CENTER)
            toggle.set_active(item["enabled"])
            toggle.set_sensitive(local and not self._updating)
            toggle.set_tooltip_text("启用此目录" if local else "服务器目录的启用状态由策略管理")
            if local:
                toggle.connect(
                    "notify::active",
                    lambda switch, _param, p=path: self._on_toggle(p, switch.get_active()),
                )
            row.append(toggle)
            self._row_controls.append((toggle, local))
            remove = secondary_button("移除配置", "user-trash-symbolic")
            remove.add_css_class("flat")
            remove.set_valign(Gtk.Align.CENTER)
            remove.set_sensitive(not self._updating)
            remove.set_tooltip_text(
                "从本机配置移除此目录，不删除文件" if local else
                "在本机移除此服务器目录，不删除文件；可在服务器设置中恢复"
            )
            remove.connect("clicked", lambda _button, p=path: self._on_remove(p))
            row.append(remove)
            self._row_controls.append((remove, True))
            self.rows.append(row)
