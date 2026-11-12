"""Minimal StatusNotifierItem and DBusMenu tray implementation."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

WATCHER_NAME = "org.kde.StatusNotifierWatcher"
WATCHER_PATH = "/StatusNotifierWatcher"
ITEM_PATH = "/StatusNotifierItem"
MENU_PATH = "/StatusNotifierMenu"
ICON_THEME_PATH = Path(__file__).resolve().parent / "assets/hicolor/scalable/apps"

SNI_XML = """
<node>
  <interface name="org.kde.StatusNotifierItem">
    <property name="Category" type="s" access="read"/>
    <property name="Id" type="s" access="read"/>
    <property name="Title" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="WindowId" type="i" access="read"/>
    <property name="IconThemePath" type="s" access="read"/>
    <property name="Menu" type="o" access="read"/>
    <property name="ItemIsMenu" type="b" access="read"/>
    <property name="IconName" type="s" access="read"/>
    <property name="IconPixmap" type="a(iiay)" access="read"/>
    <property name="OverlayIconName" type="s" access="read"/>
    <property name="OverlayIconPixmap" type="a(iiay)" access="read"/>
    <property name="AttentionIconName" type="s" access="read"/>
    <property name="AttentionIconPixmap" type="a(iiay)" access="read"/>
    <property name="AttentionMovieName" type="s" access="read"/>
    <method name="ContextMenu">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="Activate">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="ProvideXdgActivationToken">
      <arg name="token" type="s" direction="in"/>
    </method>
    <method name="SecondaryActivate">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="XAyatanaSecondaryActivate">
      <arg name="timestamp" type="u" direction="in"/>
    </method>
    <method name="Scroll">
      <arg name="delta" type="i" direction="in"/>
      <arg name="orientation" type="s" direction="in"/>
    </method>
  </interface>
</node>
"""

MENU_XML = """
<node>
  <interface name="com.canonical.dbusmenu">
    <property name="Version" type="u" access="read"/>
    <property name="TextDirection" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="IconThemePath" type="as" access="read"/>
    <method name="GetLayout">
      <arg name="parentId" type="i" direction="in"/>
      <arg name="recursionDepth" type="i" direction="in"/>
      <arg name="propertyNames" type="as" direction="in"/>
      <arg name="revision" type="u" direction="out"/>
      <arg name="layout" type="(ia{sv}av)" direction="out"/>
    </method>
    <method name="GetGroupProperties">
      <arg name="ids" type="ai" direction="in"/>
      <arg name="propertyNames" type="as" direction="in"/>
      <arg name="properties" type="a(ia{sv})" direction="out"/>
    </method>
    <method name="GetProperty">
      <arg name="id" type="i" direction="in"/>
      <arg name="name" type="s" direction="in"/>
      <arg name="value" type="v" direction="out"/>
    </method>
    <method name="Event">
      <arg name="id" type="i" direction="in"/>
      <arg name="eventId" type="s" direction="in"/>
      <arg name="data" type="v" direction="in"/>
      <arg name="timestamp" type="u" direction="in"/>
    </method>
    <method name="EventGroup">
      <arg name="events" type="a(isvu)" direction="in"/>
      <arg name="idErrors" type="ai" direction="out"/>
    </method>
    <method name="AboutToShow">
      <arg name="id" type="i" direction="in"/>
      <arg name="needUpdate" type="b" direction="out"/>
    </method>
    <method name="AboutToShowGroup">
      <arg name="ids" type="ai" direction="in"/>
      <arg name="updatesNeeded" type="ai" direction="out"/>
      <arg name="idErrors" type="ai" direction="out"/>
    </method>
  </interface>
</node>
"""


class SystemTray:
    def __init__(
        self,
        on_open: Callable[[str | None, int], None],
        on_quit: Callable[[], None],
        on_stop_auto: Callable[[], None],
    ) -> None:
        self.activation_token: str | None = None
        self.on_open = on_open
        self.on_quit = on_quit
        self.on_stop_auto = on_stop_auto
        self.summary = "文件服务就绪"
        self.revision = 1
        self.item_registration = None
        self.menu_registration = None
        self.connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        if self.connection is None:
            raise RuntimeError("无法连接桌面会话总线")
        self.bus_name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        self._register_bus_name()
        self._export_item()
        self._export_menu()
        self._register_item()

    def close(self) -> None:
        for registration in (self.item_registration, self.menu_registration):
            if registration is not None:
                try:
                    self.connection.unregister_object(registration)
                except GLib.Error:
                    pass
        self.item_registration = None
        self.menu_registration = None

    def set_summary(self, summary: str) -> None:
        if summary == self.summary:
            return
        self.summary = summary
        self.revision += 1
        self._emit_menu_layout()
        self._emit_properties_changed({"Title": GLib.Variant("s", "shit加密 · " + self.summary)})

    def _register_bus_name(self) -> None:
        result = self.connection.call_sync(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "RequestName",
            GLib.Variant("(su)", (self.bus_name, 4)),
            None,
            Gio.DBusCallFlags.NONE,
            -1,
            None,
        )
        reply = result.unpack()[0] if result is not None else 0
        if reply not in {1, 4}:
            raise RuntimeError(f"无法注册托盘总线名称，ReplyName 返回 {reply}")

    def _export_item(self) -> None:
        info = Gio.DBusNodeInfo.new_for_xml(SNI_XML)
        interface = info.lookup_interface("org.kde.StatusNotifierItem")
        self.item_registration = self.connection.register_object(
            ITEM_PATH, interface, self._item_method, self._item_property, None
        )

    def _export_menu(self) -> None:
        info = Gio.DBusNodeInfo.new_for_xml(MENU_XML)
        interface = info.lookup_interface("com.canonical.dbusmenu")
        self.menu_registration = self.connection.register_object(
            MENU_PATH, interface, self._menu_method, self._menu_property, None
        )

    def _register_item(self) -> None:
        self.connection.call_sync(
            WATCHER_NAME,
            WATCHER_PATH,
            "org.kde.StatusNotifierWatcher",
            "RegisterStatusNotifierItem",
            GLib.Variant("(s)", (self.bus_name,)),
            None,
            Gio.DBusCallFlags.NONE,
            -1,
            None,
        )

    def _item_property(self, _connection, _sender, _path, _interface, name):
        values = {
            "Category": GLib.Variant("s", "ApplicationStatus"),
            "Id": GLib.Variant("s", "shit-encryption"),
            "Title": GLib.Variant("s", "shit加密 · " + self.summary),
            "Status": GLib.Variant("s", "Active"),
            "WindowId": GLib.Variant("i", 0),
            "IconThemePath": GLib.Variant("s", str(ICON_THEME_PATH)),
            "Menu": GLib.Variant("o", MENU_PATH),
            "ItemIsMenu": GLib.Variant("b", False),
            "IconName": GLib.Variant("s", "ytsysconfig"),
            "IconPixmap": GLib.Variant("a(iiay)", []),
            "OverlayIconName": GLib.Variant("s", ""),
            "OverlayIconPixmap": GLib.Variant("a(iiay)", []),
            "AttentionIconName": GLib.Variant("s", ""),
            "AttentionIconPixmap": GLib.Variant("a(iiay)", []),
            "AttentionMovieName": GLib.Variant("s", ""),
        }
        return values.get(name)

    def _open_window(self, timestamp: int = 0) -> bool:
        token, self.activation_token = self.activation_token, None
        self.on_open(token, timestamp)
        return False

    def _item_method(
        self, _connection, _sender, _path, _interface, method, parameters, invocation
    ):
        if method == "ProvideXdgActivationToken":
            self.activation_token = parameters.unpack()[0]
        elif method in {"Activate", "SecondaryActivate", "ContextMenu"}:
            GLib.idle_add(self._open_window)
        elif method == "XAyatanaSecondaryActivate":
            GLib.idle_add(self._open_window, parameters.unpack()[0])
        invocation.return_value(None)

    def _menu_property(self, _connection, _sender, _path, _interface, name):
        values = {
            "Version": GLib.Variant("u", 3),
            "TextDirection": GLib.Variant("s", "ltr"),
            "Status": GLib.Variant("s", "normal"),
            "IconThemePath": GLib.Variant("as", []),
        }
        return values.get(name)

    def _menu_item(
        self, item_id: int, label: str, enabled: bool = True, item_type: str = "standard"
    ):
        return (
            item_id,
            {
                "label": GLib.Variant("s", label),
                "enabled": GLib.Variant("b", enabled),
                "visible": GLib.Variant("b", True),
                "type": GLib.Variant("s", item_type),
            },
            [],
        )

    def _layout(self):
        children = [
            GLib.Variant("(ia{sv}av)", item) for item in self._menu_items()
        ]
        return (
            0,
            {"children-display": GLib.Variant("s", "submenu")},
            children,
        )

    def _menu_items(self):
        return [
            self._menu_item(2, "打开 shit加密"),
            self._menu_item(3, self.summary, enabled=False),
            self._menu_item(4, "", item_type="separator"),
            self._menu_item(5, "停止自动监控"),
            self._menu_item(6, "退出并停止自动监控"),
        ]

    def _menu_method(
        self, _connection, _sender, _path, _interface, method, parameters, invocation
    ):
        unpacked = parameters.unpack()
        if method == "GetLayout":
            invocation.return_value(
                GLib.Variant("(u(ia{sv}av))", (self.revision, self._layout()))
            )
        elif method == "GetGroupProperties":
            requested = set(unpacked[0])
            layout = self._layout()
            items = [layout] + self._menu_items()
            values = [(item[0], item[1]) for item in items if item[0] in requested]
            invocation.return_value(GLib.Variant("(a(ia{sv}))", (values,)))
        elif method == "GetProperty":
            item_id, property_name = unpacked
            layout = self._layout()
            items = [layout] + self._menu_items()
            value = next(
                (item[1].get(property_name) for item in items if item[0] == item_id),
                GLib.Variant("s", ""),
            )
            invocation.return_value(GLib.Variant("(v)", (value,)))
        elif method == "Event":
            item_id, event_id, _data, _timestamp = unpacked
            if event_id == "clicked":
                if item_id == 2:
                    GLib.idle_add(self._open_window, _timestamp)
                elif item_id == 5:
                    GLib.idle_add(self.on_stop_auto)
                elif item_id == 6:
                    GLib.idle_add(self.on_quit)
            invocation.return_value(None)
        elif method == "EventGroup":
            for item_id, event_id, _data, _timestamp in unpacked[0]:
                if event_id == "clicked" and item_id == 2:
                    GLib.idle_add(self._open_window, _timestamp)
                elif event_id == "clicked" and item_id == 5:
                    GLib.idle_add(self.on_stop_auto)
                elif event_id == "clicked" and item_id == 6:
                    GLib.idle_add(self.on_quit)
            invocation.return_value(GLib.Variant("(ai)", ([],)))
        elif method == "AboutToShow":
            invocation.return_value(GLib.Variant("(b)", (False,)))
        elif method == "AboutToShowGroup":
            invocation.return_value(GLib.Variant("(aiai)", ([], [])))
        else:
            invocation.return_value(None)

    def _emit_menu_layout(self) -> None:
        try:
            self.connection.emit_signal(
                None,
                MENU_PATH,
                "com.canonical.dbusmenu",
                "LayoutUpdated",
                GLib.Variant("(ui)", (self.revision, 0)),
            )
        except GLib.Error:
            pass

    def _emit_properties_changed(self, changed: dict[str, GLib.Variant]) -> None:
        try:
            self.connection.emit_signal(
                None,
                ITEM_PATH,
                "org.freedesktop.DBus.Properties",
                "PropertiesChanged",
                GLib.Variant(
                    "(sa{sv}as)",
                    ("org.kde.StatusNotifierItem", changed, []),
                ),
            )
        except GLib.Error:
            pass
