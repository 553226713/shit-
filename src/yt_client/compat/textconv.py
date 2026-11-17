"""Render an encrypted Git input on stdout without changing files or objects."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys

from yt_client.runtime_paths import ROOT, PACKAGED
from yt_client import yt_config

MAGIC = bytes.fromhex('6e7e5a6d0089da16e3b351ea53aafb8bf665ef5aa662a08765f64e627500675c')


def convert(source, output, config_dir=None):
    with source.open('rb') as stream:
        header = stream.read(1024)
        if not header.startswith(MAGIC):
            output.write(header)
            shutil.copyfileobj(stream, output)
            return
        if len(header) != 1024 or int.from_bytes(header[85:89], 'little') != 301 or header[-5:] != b'[END]':
            raise ValueError('不支持的密文格式，未输出解密内容')
        if config_dir:
            yt_config.SETTINGS_PATH = config_dir / 'settings.json'
            yt_config.REMOTE_POLICY_PATH = config_dir / 'remote_policy.json'
        effective = yt_config.effective_config(yt_config.load_settings(), yt_config.load_remote_policy())
        key = effective['encryption']['key'].strip().encode('utf-8')
        if not 0 < len(key) < 30 or b'\0' in key or header[213:213+len(key)+1] != key + b'\0':
            raise ValueError('当前策略与密文不匹配，未输出解密内容')
        if PACKAGED:
            from engine2.artifacts import installed_textconv
            native = installed_textconv(ROOT / 'vendor')
        else:
            from engine2.build import textconv_binary
            native = textconv_binary()
        output.flush()
        process = subprocess.Popen([str(native)], stdin=subprocess.PIPE, stdout=output)
        try:
            try:
                shutil.copyfileobj(stream, process.stdin)
            finally:
                process.stdin.close()
            if process.wait():
                raise ValueError('只读解密失败')
        except BaseException:
            if process.poll() is None:
                process.terminate()
            process.wait()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config-dir', type=Path)
    parser.add_argument('file', type=Path)
    args = parser.parse_args()
    try:
        convert(args.file, sys.stdout.buffer, args.config_dir)
    except (OSError, ValueError) as error:
        print(f'Git 明文显示失败：{error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
