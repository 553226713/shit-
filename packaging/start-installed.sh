#!/bin/sh
set -eu
if [ "${1:-}" = "--foreground" ]; then
    shift
    exec /usr/bin/python3 /usr/lib/shit-encryption/yt_control.py "$@"
fi
state_dir="$HOME/.local/state/shit-encryption"
mkdir -p "$state_dir"
chmod 700 "$state_dir"
nohup setsid -f /usr/bin/python3 /usr/lib/shit-encryption/yt_control.py >>"$state_dir/launcher-ui.log" 2>&1 </dev/null
