#!/bin/sh
set -eu
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT
export PYTHONPATH=/usr/lib/shit-encryption/src
if [ "${1:-}" = "--foreground" ]; then
    shift
    exec /usr/bin/python3 -m yt_client "$@"
fi
state_dir="$HOME/.local/state/shit-encryption"
mkdir -p "$state_dir"
chmod 700 "$state_dir"
nohup setsid -f /usr/bin/python3 -m yt_client >/dev/null 2>&1 </dev/null
