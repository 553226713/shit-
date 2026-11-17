"""Local program-rule editing and read-only server policy inspection."""
from __future__ import annotations

import shlex
from pathlib import Path
from typing import Callable

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gio, GLib, Gtk, Pango

from yt_client import yt_config
from yt_client.ui.control_widgets import (
    action_button, badge, card, muted, page_frame, page_heading,
    secondary_button, set_badge,
)


class ProgramsPage(Gtk.Box):
    """Edit only local rules and local server-rule exclusions.

    ``on_apply(local_rules, removed_server_rules)`` persists both lists and
    returns success. ``refresh`` never replaces a draft; ``load`` does.
    """

    def __init__(
        self,
        on_apply: Callable[[list[str], list[str]], bool],
        on_dirty: Callable[[], None],
        on_error: Callable[[str, str], None],
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self._on_apply = on_apply
        self._on_dirty = on_dirty
        self._on_error = on_error
        self._settings: dict = {}
        self._remote: dict | None = None
        self._effective: dict = {}
        self._removed: list[str] = []
        self._updating = False
        self._dirty = False
        self._baseline_text = ""
        self._baseline_removed: list[str] = []

        scroll, content = page_frame()
        self.append(scroll)
        add = action_button("添加程序")
        add.connect("clicked", self._show_add_dialog)
        content.append(page_heading(
            "程序权限", "管理可读取解密视图的程序规则；服务器策略与本地追加分别显示。", add,
        ))
        summary_row = Gtk.Box(spacing=12)
        self.summary = muted("尚未加载策略", wrap=True, hexpand=True)
        self.feedback = badge("尚未加载")
        summary_row.append(self.summary)
        summary_row.append(self.feedback)
        content.append(summary_row)

        rules = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        filters = Gtk.Box(spacing=12)
        self.search = Gtk.SearchEntry(hexpand=True)
        self.search.set_placeholder_text("搜索程序名称、规则或匹配来源")
        self.search.connect("search-changed", self._filter_changed)
        self.source = Gtk.DropDown.new_from_strings(["全部", "服务器", "本地追加"])
        self.source.set_tooltip_text("规则来源")
        self.source.connect("notify::selected", self._filter_changed)
        filters.append(self.search)
        filters.append(self.source)
        rules.append(filters)
        headings = self._columns()
        for text in ("程序 / 规则", "来源", "当前策略解密状态", "操作"):
            label = Gtk.Label(label=text, xalign=0)
            label.add_css_class("table-heading")
            self._append_column(headings, label)
        rules.append(headings)
        self.rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        rules.append(self.rows)
        self.empty = muted("尚无程序规则", wrap=True)
        self.empty.add_css_class("empty-state")
        rules.append(self.empty)
        policy_note = muted("按已保存策略显示；未保存改动不生效。", wrap=True)
        policy_note.set_tooltip_text(
            "表中状态来自最近一次有效策略，不代表监控已运行或某个文件必然可解密。"
            "解密仍受监控目录、文件规则和密钥约束。"
        )
        rules.append(policy_note)
        content.append(card(rules))
        git_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        title = Gtk.Label(label="Git 使用原始文件字节", xalign=0)
        title.add_css_class("section-title")
        git_box.append(title)
        git_box.append(muted(
            "经系统可执行文件身份核验的 Git 始终使用原始字节，不因受信规则（包括 *git*）"
            "获得解密视图。明文按明文、密文按密文暂存、提交、推送和检出；"
            "只读 textconv 可用于差异和历史显示，不改变传输内容。"
            "此行为不以程序文件名或命令行参数判定，也不改写已有历史。",
            wrap=True,
        ))
        content.append(card(git_box))

        advanced = Gtk.Expander(label="高级：编辑本地追加规则")
        advanced.set_expanded(False)
        editor = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        editor.set_margin_top(12)
        editor.append(muted(
            "只编辑本地追加，每行一条；空行忽略。无 / 的规则匹配可执行文件名，"
            "含 / 的规则匹配可执行文件完整路径，支持 shell 通配符。"
            "这里不包含服务器规则或自动派生的 Linux 匹配项；清空不会删除服务器策略。",
            wrap=True,
        ))
        self.local_editor = Gtk.TextView(monospace=True)
        self.local_editor.set_wrap_mode(Gtk.WrapMode.NONE)
        self.local_editor.set_top_margin(10)
        self.local_editor.set_bottom_margin(10)
        self.local_editor.set_left_margin(10)
        self.local_editor.set_right_margin(10)
        self.local_editor.get_buffer().connect("changed", self._editor_changed)
        editor_scroll = Gtk.ScrolledWindow(hexpand=True)
        editor_scroll.set_min_content_height(180)
        editor_scroll.set_child(self.local_editor)
        editor.append(editor_scroll)
        advanced.set_child(editor)
        content.append(card(advanced))

        actions = Gtk.Box(spacing=12)
        self.apply_button = action_button("应用程序权限")
        self.apply_button.set_sensitive(False)
        self.apply_button.connect("clicked", self._apply)
        actions.append(self.apply_button)
        actions.append(muted("只保存本页的本地规则和服务器规则停用记录。", wrap=True))
        content.append(actions)


        details = Gtk.Expander(label="策略明细：有效规则、Windows 应用与 Linux 匹配")
        details.set_expanded(False)
        detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        detail_box.set_margin_top(12)
        detail_box.append(muted(
            "以下均为当前已加载策略的只读结果，不是本地编辑草稿。"
            "Windows 名称去扩展名并转为小写后，与本机程序名称进行包含匹配；"
            "匹配出的 Linux 可执行项由服务器规则派生，不会写入本地追加列表。"
            "停用派生项需停用其来源服务器规则；其他来源或本地规则仍可能授权同一程序。",
            wrap=True,
        ))
        self.effective_view = self._detail_label()
        self.server_view = self._detail_label()
        self.matches_view = self._detail_label()
        detail_box.append(self.effective_view)
        detail_box.append(self.server_view)
        detail_box.append(self.matches_view)
        details.set_child(detail_box)
        content.append(card(details))

    @staticmethod
    def _detail_label() -> Gtk.Label:
        return Gtk.Label(xalign=0, selectable=True, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR)

    @staticmethod
    def _columns() -> Gtk.Grid:
        return Gtk.Grid(column_spacing=16, row_spacing=6, hexpand=True)

    @staticmethod
    def _append_column(grid: Gtk.Grid, widget: Gtk.Widget) -> None:
        column = 0
        while grid.get_child_at(column, 0) is not None:
            column += 1
        widget.set_hexpand(column in (0, 2))
        if isinstance(widget, Gtk.Label):
            widget.set_wrap(True)
            widget.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        if column == 0:
            widget.set_size_request(180, -1)
        elif column == 1:
            widget.set_size_request(88, -1)
        elif column == 2:
            widget.set_size_request(140, -1)
        else:
            widget.set_size_request(70, -1)
        grid.attach(widget, column, 0, 1, 1)

    def load(self, settings: dict, remote: dict | None, effective: dict) -> None:
        """Replace all draft state with persisted local-only settings."""
        self._settings, self._remote, self._effective = settings, remote, effective
        self._removed = list(settings.get("local_overrides", {}).get("removed_server_programs", []))
        text = "\n".join(settings.get("trusted_programs", []))
        self._updating = True
        try:
            self.local_editor.get_buffer().set_text(text)
        finally:
            self._updating = False
        self._baseline_text = text
        self._baseline_removed = list(self._removed)
        self._dirty = False
        self.apply_button.set_sensitive(False)
        self.set_feedback("已保存", "success")
        self._render()

    def refresh(self, settings: dict, remote: dict | None, effective: dict) -> None:
        """Refresh policy/provenance views without changing unsaved editor text."""
        self._settings, self._remote, self._effective = settings, remote, effective
        self._render()

    @property
    def dirty(self) -> bool:
        return self._dirty

    def set_feedback(self, text: str, kind: str = "neutral") -> None:
        if kind not in {"neutral", "success", "warning", "error", "accent"}:
            kind = "neutral"
        set_badge(self.feedback, text, kind)

    def _text(self) -> str:
        buffer = self.local_editor.get_buffer()
        return buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True)

    @staticmethod
    def _validate_rule(value: str) -> str:
        if any(char in value for char in ("\r", "\n", "\x00", "\u0085", "\u2028", "\u2029")):
            raise ValueError("一条程序规则不能包含换行符或空字符。")
        rule = value.strip()
        if not yt_config.validate_rule_pattern(rule):
            raise ValueError("程序规则不能为空，也不能包含规则分隔符 " + yt_config.RULE_SEPARATOR + "。")
        if rule in {"encryptkey", "new_file_mode"}:
            raise ValueError("此名称是引擎配置指令，不能用作程序规则；请使用可执行文件完整路径。")
        return rule

    def _local_rules(self) -> list[str]:
        rules: list[str] = []
        for index, line in enumerate(self._text().split("\n"), 1):
            if not line.strip() and not any(char in line for char in ("\r", "\x00", "\u0085", "\u2028", "\u2029")):
                continue
            try:
                rule = self._validate_rule(line)
            except ValueError as exc:
                raise ValueError(f"第 {index} 行：{exc}") from exc
            if rule not in rules:
                rules.append(rule)
        return rules

    def _editor_changed(self, _buffer: Gtk.TextBuffer) -> None:
        if not self._updating:
            self._draft_changed()

    def _draft_changed(self) -> None:
        self._dirty = self._text() != self._baseline_text or self._removed != self._baseline_removed
        self.apply_button.set_sensitive(self._dirty)
        self.set_feedback("未保存" if self._dirty else "已保存", "warning" if self._dirty else "success")
        self._on_dirty()
        self._render()

    def _filter_changed(self, *_args) -> None:
        if hasattr(self, "rows"):
            self._render_rows()

    def _labels(self, rule: str) -> str:
        names: list[str] = []
        for program in self._settings.get("programs", []):
            try:
                command = shlex.split(program.get("command", ""))
            except ValueError:
                continue
            if command and rule in (command[0], Path(command[0]).name):
                names.append(program.get("name", rule))
        for app in (self._remote or {}).get("windows_applications", []):
            if rule == app.get("name") or rule in app.get("processes", []):
                names.append(app["name"])
        return " / ".join(dict.fromkeys(names)) or ("通配符规则" if any(c in rule for c in "*?[") else Path(rule.replace("\\", "/")).name)

    def _render(self) -> None:
        remote_rules = (self._remote or {}).get("trusted_programs", [])
        applied = self._effective.get("server_policy_applied", False)
        self.summary.set_text(
            f"服务器 {len(remote_rules)} 条 · 本地已保存 {len(self._settings.get('trusted_programs', []))} 条 · "
            f"有效规则 {len(self._effective.get('trusted_programs', []))} 条 · "
            + ("服务器策略已应用" if applied else "服务器策略未应用")
        )
        effective_rules = self._effective.get("trusted_programs", [])
        pattern = self._effective.get("encryption", {}).get("file_pattern", "未加载")
        self.effective_view.set_text(
            f"当前有效程序规则（文件规则：{pattern}）：\n"
            + ("\n".join(effective_rules) or "无有效程序规则")
        )
        if self._remote:
            applications = self._remote.get("windows_applications", [])
            application_text = "\n".join(
                app["name"] + " → " + (" | ".join(app.get("processes", [])) or "未下发进程名")
                for app in applications
            )
            saved_removed = set(self._settings.get("local_overrides", {}).get("removed_server_programs", []))
            raw = "\n".join(rule + ("（本地已停用）" if rule in saved_removed else "") for rule in remote_rules)
            self.server_view.set_text(
                f"服务器来源：{self._remote.get('source', '未提供')}\n"
                f"更新时间：{self._remote.get('updated_at', '未提供')}\n"
                "Windows 应用 / 进程：\n" + (application_text or "未下发 Windows 应用明细")
                + "\n\n服务器原始程序规则：\n" + (raw or "未下发程序规则")
            )
        else:
            self.server_view.set_text("尚未导入服务器策略。")
        matches = self._effective.get("program_matches", {})
        self.matches_view.set_text(
            "当前服务器派生的 Linux 匹配：\n"
            + ("\n".join(linux + " ← " + " | ".join(sources) for linux, sources in matches.items()) or "无有效 Linux 匹配项")
        )
        self._render_rows()

    def _render_rows(self) -> None:
        while (child := self.rows.get_first_child()) is not None:
            self.rows.remove(child)
        try:
            local = self._local_rules()
        except ValueError:
            local = [line.strip() for line in self._text().split("\n") if line.strip()]
        remote = list((self._remote or {}).get("trusted_programs", []))
        matches = self._effective.get("program_matches", {})
        entries = [(rule, "server", []) for rule in remote]
        entries += [(rule, "derived", list(sources)) for rule, sources in matches.items()]
        entries += [(rule, "local", []) for rule in local]
        query = self.search.get_text().strip().casefold()
        selected = self.source.get_selected()
        count = 0
        saved_rules = set(self._effective.get("trusted_programs", []))
        saved_local = set(self._settings.get("trusted_programs", []))
        saved_removed = set(self._settings.get("local_overrides", {}).get("removed_server_programs", []))
        for rule, origin, sources in entries:
            if (selected == 1 and origin == "local") or (selected == 2 and origin != "local"):
                continue
            label = self._labels(rule)
            if query and query not in " ".join([label, rule, *sources]).casefold():
                continue
            count += 1
            row = self._columns()
            row.add_css_class("list-row")
            identity = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            identity.append(Gtk.Label(label=label, xalign=0, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR))
            identity.append(muted(rule, wrap=True, selectable=True, wrap_mode=Pango.WrapMode.WORD_CHAR))
            if sources:
                identity.append(muted("匹配自：" + " | ".join(sources), wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR))
            self._append_column(row, identity)
            origin_text = {"local": "本地追加", "server": "服务器", "derived": "服务器 · Linux 匹配"}[origin]
            self._append_column(row, badge(origin_text, "accent" if origin == "local" else "neutral"))
            active = rule in saved_rules
            state = "规则生效 · 受文件规则约束" if active else "未生效"
            if origin == "server" and rule in saved_removed:
                state = "本地已停用" + ("；同名有效规则仍存在" if active else "")
            elif origin != "local" and not self._effective.get("server_policy_applied", False):
                state = "服务器策略未应用" + ("；同名有效规则仍存在" if active else "")
            if origin == "local" and rule not in saved_local:
                state += "\n本地追加待保存"
            if origin == "server" and (rule in self._removed) != (rule in saved_removed):
                state += "\n" + ("停用待保存" if rule in self._removed else "恢复待保存")
            if origin == "derived" and sources and all(source in self._removed for source in sources):
                state += "\n来源停用待保存"
            self._append_column(row, muted(state, wrap=True))
            if origin == "local":
                button = secondary_button("删除")
                button.connect("clicked", self._delete_local, rule)
            elif origin == "server":
                button = secondary_button("恢复" if rule in self._removed else "本地停用")
                button.connect("clicked", self._toggle_server, rule)
            else:
                button = secondary_button("停用来源")
                button.set_tooltip_text("仅在本地停用这些来源服务器规则，不修改服务器内容。")
                button.set_sensitive(any(source not in self._removed for source in sources))
                button.connect("clicked", self._disable_sources, sources)
            self._append_column(row, button)
            self.rows.append(row)
        self.empty.set_visible(count == 0)
        self.empty.set_text("没有符合搜索或来源筛选的规则。" if entries else "尚无程序规则。可添加明确的程序名称或可执行文件路径。")

    def _delete_local(self, _button: Gtk.Button, rule: str) -> None:
        lines = [line for line in self._text().split("\n") if line.strip() != rule]
        self.local_editor.get_buffer().set_text("\n".join(lines))

    def _toggle_server(self, _button: Gtk.Button, rule: str) -> None:
        if rule in self._removed:
            self._removed.remove(rule)
        else:
            self._removed.append(rule)
        self._draft_changed()

    def _disable_sources(self, _button: Gtk.Button, sources: list[str]) -> None:
        for source in sources:
            if source not in self._removed:
                self._removed.append(source)
        self._draft_changed()

    def _apply(self, _button: Gtk.Button) -> None:
        try:
            local = self._local_rules()
        except ValueError as exc:
            self.set_feedback("保存失败：规则无效", "error")
            self._on_error("程序规则无效", str(exc))
            return
        try:
            success = self._on_apply(list(local), list(self._removed))
        except Exception as exc:
            self.set_feedback("保存失败", "error")
            self._on_error("无法保存程序权限", str(exc))
            return
        if not success:
            self.set_feedback("保存失败，草稿已保留", "error")
            return
        self._baseline_text = self._text()
        self._baseline_removed = list(self._removed)
        self._dirty = False
        self.apply_button.set_sensitive(False)
        self.set_feedback("已保存", "success")
        self._render()

    def _show_add_dialog(self, _button: Gtk.Button) -> None:
        root = self.get_root()
        dialog = Gtk.Dialog(title="添加程序", modal=True)
        if isinstance(root, Gtk.Window):
            dialog.set_transient_for(root)
        dialog.set_default_size(520, -1)
        dialog.add_button("取消", Gtk.ResponseType.CANCEL)
        dialog.add_button("添加到本地草稿", Gtk.ResponseType.ACCEPT)
        dialog.set_default_response(Gtk.ResponseType.ACCEPT)
        body = dialog.get_content_area()
        body.set_spacing(12)
        for setter in (body.set_margin_top, body.set_margin_bottom, body.set_margin_start, body.set_margin_end):
            setter(18)
        body.append(muted(
            "输入实际可执行程序名或完整路径，也可明确输入通配符规则。"
            "不会自动添加通配符或更改启动程序配置。添加后需应用才生效。", wrap=True,
        ))
        entry = Gtk.Entry(hexpand=True, activates_default=True)
        entry.set_placeholder_text("程序名称、可执行文件路径或规则")
        body.append(entry)
        choose = secondary_button("选择可执行文件…")
        body.append(choose)
        error = muted("", wrap=True)
        error.add_css_class("error")
        body.append(error)

        def choose_file(_choose: Gtk.Button) -> None:
            chooser = Gtk.FileDialog(title="选择程序可执行文件")

            def selected(file_dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
                try:
                    file = file_dialog.open_finish(result)
                    path = file.get_path() if file else None
                    if path:
                        entry.set_text(path)
                except GLib.Error as exc:
                    if not exc.matches(Gtk.dialog_error_quark(), Gtk.DialogError.DISMISSED):
                        error.set_text("无法选择文件：" + exc.message)

            chooser.open(dialog, None, selected)

        def response(_dialog: Gtk.Dialog, response_id: int) -> None:
            if response_id != Gtk.ResponseType.ACCEPT:
                dialog.destroy()
                return
            try:
                rule = self._validate_rule(entry.get_text())
                local = self._local_rules()
                if rule in local:
                    raise ValueError("此规则已存在于本地追加中。")
            except ValueError as exc:
                error.set_text(str(exc))
                return
            text = self._text()
            self.local_editor.get_buffer().set_text(text + ("\n" if text and not text.endswith("\n") else "") + rule)
            dialog.destroy()

        choose.connect("clicked", choose_file)
        dialog.connect("response", response)
        dialog.present()
