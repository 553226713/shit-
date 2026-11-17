"""Small GTK building blocks shared by the configuration pages."""
from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Pango


def muted(label: str, **kwargs) -> Gtk.Label:
    kwargs.setdefault("xalign", 0)
    widget = Gtk.Label(label=label, **kwargs)
    widget.add_css_class("muted")
    return widget


def card(child: Gtk.Widget) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    box.add_css_class("card")
    box.append(child)
    return box


def action_button(label: str, icon: str | None = None) -> Gtk.Button:
    button = Gtk.Button(label=label)
    button.add_css_class("client-action")
    if icon:
        row = Gtk.Box(spacing=7, halign=Gtk.Align.CENTER)
        row.append(Gtk.Image.new_from_icon_name(icon))
        row.append(Gtk.Label(label=label))
        button.set_child(row)
        button.set_tooltip_text(label)
    button.add_css_class("suggested-action")
    return button


def secondary_button(label: str, icon: str | None = None) -> Gtk.Button:
    button = Gtk.Button(label=label)
    button.add_css_class("client-action")
    if icon:
        row = Gtk.Box(spacing=7, halign=Gtk.Align.CENTER)
        row.append(Gtk.Image.new_from_icon_name(icon))
        row.append(Gtk.Label(label=label))
        button.set_child(row)
        button.set_tooltip_text(label)
    return button


def page_frame() -> tuple[Gtk.ScrolledWindow, Gtk.Box]:
    scroll = Gtk.ScrolledWindow(hexpand=True, vexpand=True)
    scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
    content.set_margin_top(22)
    content.set_margin_bottom(24)
    content.set_margin_start(24)
    content.set_margin_end(24)
    scroll.set_child(content)
    return scroll, content


def page_heading(title: str, description: str, action: Gtk.Widget | None = None) -> Gtk.Box:
    row = Gtk.Box(spacing=16)
    labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7, hexpand=True)
    heading = Gtk.Label(label=title, xalign=0)
    heading.add_css_class("hero-title")
    labels.append(heading)
    labels.append(muted(description, wrap=True))
    row.append(labels)
    if action is not None:
        action.set_valign(Gtk.Align.START)
        row.append(action)
    return row


def badge(text: str = "", kind: str = "neutral") -> Gtk.Label:
    label = Gtk.Label()
    label.set_valign(Gtk.Align.CENTER)
    label.add_css_class("badge")
    set_badge(label, text, kind)
    return label


def set_badge(label: Gtk.Label, text: str, kind: str = "neutral") -> None:
    for name in ("neutral", "success", "warning", "error", "accent"):
        label.remove_css_class("badge-" + name)
    label.add_css_class("badge-" + kind)
    label.set_text(text)


def path_label(path: str) -> Gtk.Label:
    label = Gtk.Label(label=path, xalign=0, hexpand=True)
    label.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
    label.set_tooltip_text(path)
    return label
