#!/bin/sh
# Export committed source only; local configuration and runtime state stay private.
set -eu

source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-"$source_dir/../linux-client-source.tar.gz"}
output=$(realpath -m -- "$output")
case "$output" in
    "$source_dir"/*) printf '%s\n' '压缩包必须放在 linux-client 目录之外。' >&2; exit 1 ;;
esac
if [ -e "$output" ]; then
    printf '目标文件已存在：%s\n' "$output" >&2
    exit 1
fi
temporary=$(mktemp "${output}.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
git -C "$source_dir" archive --format=tar.gz --prefix=linux-client/ HEAD > "$temporary"
chmod 600 "$temporary"
mv -- "$temporary" "$output"
printf '已生成：%s\n' "$output"
