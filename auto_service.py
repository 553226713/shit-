"""Install and control the per-user transparent mount service."""
from __future__ import annotations

import subprocess
from pathlib import Path

import yt_config
from runtime_paths import MONITOR_DIR, PACKAGED

ROOT = yt_config.ROOT
SERVICE = "shit-encryption-auto.service" if PACKAGED else "ytsysconfig-auto.service"
UNIT_PATH = Path.home() / ".config/systemd/user" / SERVICE
AUTOSTART_PATH = Path.home() / ".config/autostart" / ("shit-encryption.desktop" if PACKAGED else "ytsysconfig-control.desktop")


def unit_text() -> str:
    return f"""[Unit]
Description=shit加密 automatic encrypted directory mounts
After=default.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {ROOT / 'auto_mount.py'}
ExecStop=/usr/bin/python3 {ROOT / 'auto_mount.py'} --stop-broker
Restart={"no" if PACKAGED else "on-failure"}
RestartSec=3
TimeoutStopSec=20
KillMode=control-group

[Install]
WantedBy=default.target
"""


def _systemctl(*arguments: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["systemctl", "--user", *arguments],
        capture_output=True,
        text=True,
        check=check,
    )


def install() -> None:
    UNIT_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    content = unit_text()
    if not UNIT_PATH.exists() or UNIT_PATH.read_text(encoding="utf-8") != content:
        yt_config.atomic_write(UNIT_PATH, content)
    _systemctl("daemon-reload", check=True)


def autostart_enabled() -> bool:
    return AUTOSTART_PATH.exists()


def set_autostart(enabled: bool) -> None:
    install()
    result = _systemctl("enable" if enabled else "disable", SERVICE)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "开机启动设置失败")
    if enabled:
        install_autostart()
    else:
        AUTOSTART_PATH.unlink(missing_ok=True)


def install_autostart() -> None:
    AUTOSTART_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    content = f"""[Desktop Entry]
Type=Application
Name=shit加密
Comment=shit加密托盘与自动监控
Exec=/usr/bin/env YT_CONTROL_START_HIDDEN=1 {ROOT / 'start.sh'}
Icon={ROOT / 'assets/hicolor/scalable/apps/ytsysconfig.svg'}
Terminal=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
"""
    if not AUTOSTART_PATH.exists() or AUTOSTART_PATH.read_text(encoding="utf-8") != content:
        yt_config.atomic_write(AUTOSTART_PATH, content)


def status() -> dict:
    if not UNIT_PATH.exists():
        return {"installed": False, "active": False, "state": "not-installed"}
    result = _systemctl(
        "show",
        SERVICE,
        "--property=ActiveState",
        "--property=SubState",
        "--property=UnitFileState",
    )
    values = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    runtime = yt_config.read_json(MONITOR_DIR / "status.json", {}) or {}
    return {
        "installed": True,
        "active": values.get("ActiveState") == "active",
        "state": values.get("ActiveState", "unknown"),
        "substate": values.get("SubState", ""),
        "enabled": values.get("UnitFileState") == "enabled",
        "runtime": runtime,
        "error": result.stderr.strip() or None,
    }


def start() -> None:
    install()
    result = _systemctl("start", SERVICE)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "自动监控服务启动失败")


def stop() -> None:
    if not UNIT_PATH.exists():
        return
    result = _systemctl("stop", SERVICE)
    if result.returncode and status()["active"]:
        raise RuntimeError(result.stderr.strip() or "自动监控服务停止失败")


def restart() -> None:
    install()
    result = _systemctl("restart", SERVICE)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "自动监控服务重启失败")
