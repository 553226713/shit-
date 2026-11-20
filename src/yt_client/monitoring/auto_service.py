"""Install and control the per-user transparent mount service."""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

from yt_client import yt_config
from yt_client.monitoring.mount_authorization import authorized
from yt_client.runtime_paths import MONITOR_DIR, PACKAGED

ROOT = yt_config.ROOT
SERVICE = "shit-encryption-auto.service" if PACKAGED else "ytsysconfig-auto.service"
UNIT_PATH = Path.home() / ".config/systemd/user" / SERVICE
AUTOSTART_PATH = Path.home() / ".config/autostart" / ("shit-encryption.desktop" if PACKAGED else "ytsysconfig-control.desktop")
LOADER_VARIABLES = ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")


def unit_text() -> str:
    script = str(ROOT / 'src/yt_client/monitoring/auto_mount.py')
    script = (script.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')
              .replace('$', '$$').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t'))
    return f"""[Unit]
Description=shit加密 automatic encrypted directory mounts
After=default.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 "{script}"
ExecStop=/usr/bin/python3 "{script}" --stop-broker
UnsetEnvironment={' '.join(LOADER_VARIABLES)}
Restart=on-failure
RestartPreventExitStatus=126 127
RestartSec=3
TimeoutStopSec=20
KillMode=control-group

[Install]
WantedBy=default.target
"""


def _command_environment() -> dict[str, str]:
    return {name: value for name, value in os.environ.items() if name not in LOADER_VARIABLES}


def _systemctl(*arguments: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["systemctl", "--user", *arguments],
        capture_output=True,
        text=True,
        check=check,
        env=_command_environment(),
    )


def _authorize_monitor() -> None:
    if not PACKAGED or authorized(os.getuid()):
        return
    helper = str(ROOT / "mount-broker")
    # The desktop process is the caller so polkit can reach its session agent.
    try:
        result = subprocess.run(
            ["/usr/bin/pkexec", "--disable-internal-agent", helper, "--authorize-only"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=_command_environment(),
            timeout=60,
        )
    except subprocess.TimeoutExpired as error:
        if authorized(os.getuid()):
            return
        raise RuntimeError("等待桌面管理员授权超时。请在概览中点击“终端授权”。") from error
    if result.returncode == 126:
        raise RuntimeError("已取消管理员授权。再次点击“启用监控”可重试。")
    if result.returncode:
        raise RuntimeError(
            "未完成桌面管理员授权。请在概览中点击“终端授权”，或在本机终端执行：\n"
            + terminal_authorization_command()
            + (f"\n{result.stderr.strip()}" if result.stderr.strip() else "")
        )
    if not authorized(os.getuid()):
        raise RuntimeError("管理员授权完成后未找到有效的本机授权记录。")


def terminal_authorization_command() -> str:
    script = ROOT / "src/yt_client/monitoring/auto_mount.py"
    return shlex.join(["/usr/bin/python3", str(script), "--authorize-in-terminal"])


def authorize_in_terminal() -> int:
    uid = os.getuid()
    if not PACKAGED or not uid or not sys.stdin.isatty():
        print("请以当前普通用户身份在本机终端运行授权命令。", file=sys.stderr)
        return 1
    try:
        if not authorized(uid):
            helper = str(ROOT / "mount-broker")
            command = ["/usr/bin/sudo", "--"] if Path("/usr/bin/sudo").is_file() else ["/usr/bin/pkexec"]
            result = subprocess.run([*command, helper, "--authorize-only"], env=_command_environment())
            if result.returncode or not authorized(uid):
                raise RuntimeError("授权未完成，请检查上方系统提示。")
        start()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        try:
            input("按 Enter 关闭终端。")
        except (EOFError, KeyboardInterrupt):
            pass
        return 1
    print("管理员授权已确认，监控启动请求已提交。")
    return 0


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
    authorization_required = PACKAGED and not authorized(os.getuid())
    if not UNIT_PATH.exists():
        return {"installed": False, "active": False, "state": "not-installed",
                "authorization_required": authorization_required}
    result = _systemctl(
        "show",
        SERVICE,
        "--property=ActiveState",
        "--property=SubState",
        "--property=UnitFileState",
        "--property=Result",
        "--property=ExecMainCode",
        "--property=ExecMainStatus",
    )
    values = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    runtime = yt_config.read_json(MONITOR_DIR / "status.json", {}) or {}
    error = (result.stderr.strip() or "无法查询用户监控服务") if result.returncode else None
    failure = values.get("Result", "")
    if values.get("ActiveState") != "active" and (
        values.get("ActiveState") == "failed" or failure not in ("", "success")
    ):
        if authorization_required and values.get("ExecMainStatus") == "126":
            detail = "尚未完成管理员授权。可在桌面客户端点击“启用监控”或“终端授权”。"
        else:
            detail = runtime.get("error") if runtime.get("state") == "failed" else None
        if not detail:
            exit_kind = "信号" if values.get("ExecMainCode") in ("2", "3") else "退出码"
            detail = f"{failure or 'failed'}，{exit_kind} {values.get('ExecMainStatus', 'unknown')}"
        error = error or f"{detail}；请查看 journalctl --user -u {SERVICE} -n 80 --no-pager"
    return {
        "installed": True,
        "active": values.get("ActiveState") == "active",
        "state": values.get("ActiveState", "unknown"),
        "substate": values.get("SubState", ""),
        "enabled": values.get("UnitFileState") == "enabled",
        "runtime": runtime,
        "error": error,
        "authorization_required": authorization_required,
    }


def start() -> None:
    install()
    _authorize_monitor()
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
    _authorize_monitor()
    result = _systemctl("restart", SERVICE)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "自动监控服务重启失败")
