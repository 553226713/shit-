#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PYTHONPATH="$script_dir/src"
fail() {
    printf '%s\n' "$1" >&2
    if command -v zenity >/dev/null 2>&1; then
        zenity --error --title="shit加密" --text="$1" || :
    fi
    exit 1
}

if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    fail "当前没有图形桌面会话，无法启动配置中心。"
fi

# GTK bindings must use the distribution Python, including after apt installation.
python=/usr/bin/python3
missing_packages() {
    if [ ! -x "$python" ]; then
        printf '%s\n' python3 python3-gi gir1.2-gtk-4.0
    elif ! "$python" -c "import gi; gi.require_version('Gtk', '4.0'); from gi.repository import Gtk, Gdk, Gio, GLib" >/dev/null 2>&1; then
        printf '%s\n' python3-gi gir1.2-gtk-4.0
    fi
    command -v gcc >/dev/null 2>&1 || printf '%s\n' gcc
    command -v g++ >/dev/null 2>&1 || printf '%s\n' g++
    if ! command -v nm >/dev/null 2>&1 || ! command -v ld >/dev/null 2>&1 || ! command -v objcopy >/dev/null 2>&1; then
        printf '%s\n' binutils
    fi
    command -v sudo >/dev/null 2>&1 || printf '%s\n' sudo
    command -v unshare >/dev/null 2>&1 || printf '%s\n' util-linux
    command -v bwrap >/dev/null 2>&1 || printf '%s\n' bubblewrap
    command -v systemctl >/dev/null 2>&1 || printf '%s\n' systemd
}

packages=$(missing_packages)
if [ -n "$packages" ]; then
    command -v apt-get >/dev/null 2>&1 || fail "缺少依赖：$packages。当前系统不支持 apt-get，请通过系统包管理器安装上述依赖。"
    log_dir="$script_dir/state"
    mkdir -p "$log_dir"
    chmod 700 "$log_dir"
    install_log="$log_dir/dependency-install.log"
    printf '%s\n' "正在下载安装缺失依赖：$packages"
    # Keep privileged commands fixed; package names above are internal constants.
    if [ "$(id -u)" -eq 0 ]; then
        elevate=
    elif command -v pkexec >/dev/null 2>&1; then
        elevate=pkexec
    elif command -v sudo >/dev/null 2>&1; then
        elevate=sudo
    else
        fail "自动安装需要管理员权限，但未找到 pkexec 或 sudo。缺少依赖：$packages"
    fi
    # Word splitting intentionally turns the internal package list into arguments.
    if ! $elevate sh -c 'apt-get update && apt-get install -y "$@"' sh $packages >"$install_log" 2>&1; then
        fail "依赖自动安装失败（可能未授权或网络不可用），请查看日志：$install_log"
    fi
    remaining=$(missing_packages)
    [ -z "$remaining" ] || fail "安装后仍缺少依赖：$remaining。请查看日志：$install_log"
fi

if [ "${1:-}" = "--foreground" ]; then
    shift
    exec "$python" -m yt_client "$@"
fi

log_dir="$script_dir/state"
log_file="$log_dir/launcher-ui.log"
mkdir -p "$log_dir"
chmod 700 "$log_dir"

if command -v setsid >/dev/null 2>&1; then
    nohup setsid -f "$python" -m yt_client \
        >>"$log_file" 2>&1 </dev/null
else
    nohup "$python" -m yt_client \
        >>"$log_file" 2>&1 </dev/null &
fi

printf '%s\n' "shit加密 已在后台启动，可从顶部状态栏图标重新打开。"
