"""Enable read-only Git textconv for indexed encrypted text files, locally."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys

from file_scope import normalize_scope
from compat.textconv import MAGIC
from runtime_paths import ROOT, PACKAGED
from yt_config import atomic_write, atomic_write_json

DRIVER = 'shit-encryption'
BEGIN = '# BEGIN shit-encryption read-only display'
END = '# END shit-encryption read-only display'
BINARY_EXTENSIONS = {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.dwg', '.dxf'}


def git(repo, *args, data=None):
    return subprocess.run(['git', '-C', str(repo), *args], input=data,
                          capture_output=True, check=True).stdout


def quote_pattern(path):
    # Escape glob metacharacters before C-style Git attribute quoting.
    path = ''.join('\\' + ch if ch in '*?[\\' else ch for ch in path)
    if path.startswith('!'):
        path = '\\' + path
    result = '"'
    for byte in path.encode('utf-8', 'surrogateescape'):
        if byte in (34, 92): result += '\\' + chr(byte)
        elif 32 <= byte < 127: result += chr(byte)
        else: result += f'\\{byte:03o}'
    return result + '"'


def encrypted_paths(repo, scope=None):
    scope = normalize_scope(scope)
    extensions = set(scope['included_extensions']) - BINARY_EXTENSIONS
    entries = []
    for entry in git(repo, 'ls-files', '--stage', '-z').split(b'\0'):
        if not entry: continue
        metadata, path = entry.split(b'\t', 1)
        mode, oid, stage = metadata.split()
        name = path.decode('utf-8', 'surrogateescape')
        p = Path(name)
        if stage != b'0' or mode not in (b'100644', b'100755'): continue
        if any(part in scope['excluded_directories'] for part in p.parts[:-1]): continue
        if p.suffix.lower() in BINARY_EXTENSIONS: continue
        if scope['included_extensions'] and p.suffix.lower() not in extensions and p.name not in scope['included_names']: continue
        entries.append((name, oid))
    cache_path = Path(git(repo, 'rev-parse', '--path-format=absolute', '--git-path',
                          'info/shit-encryption-object-headers.json').decode().strip())
    try:
        cache = json.loads(cache_path.read_text())
        if not isinstance(cache, dict): cache = {}
    except (OSError, ValueError):
        cache = {}
    selected = []
    process = subprocess.Popen(['git', '-C', str(repo), 'cat-file', '--batch'],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        for name, oid in entries:
            key = oid.decode('ascii')
            if key in cache and isinstance(cache[key], bool):
                if cache[key]: selected.append(name)
                continue
            process.stdin.write(oid + b'\n'); process.stdin.flush()
            header = process.stdout.readline().split()
            if len(header) != 3 or header[1] != b'blob':
                raise ValueError('无法读取 Git 对象')
            size = int(header[2])
            prefix = process.stdout.read(min(32, size))
            remaining = size - len(prefix)
            while remaining:
                block = process.stdout.read(min(65536, remaining))
                if not block: raise ValueError('Git 对象读取不完整')
                remaining -= len(block)
            if process.stdout.read(1) != b'\n': raise ValueError('Git 对象边界错误')
            cache[key] = prefix == MAGIC
            if cache[key]: selected.append(name)
    finally:
        process.stdin.close(); process.stdout.close()
        if process.wait(): raise ValueError('Git 对象检查失败')
    if cache:
        text = json.dumps(cache, sort_keys=True)
        if not cache_path.exists() or cache_path.read_text() != text:
            atomic_write(cache_path, text)
    return selected


def enable(repo, command=None, config_dir=None):
    repo = Path(git(repo, 'rev-parse', '--show-toplevel').decode().strip())
    if command is None:
        command = '/usr/bin/shit-encryption-textconv' if PACKAGED else shlex.join(
            ['/usr/bin/python3', str(ROOT / 'compat_cli.py'), 'textconv'])
        if config_dir:
            command += ' ' + shlex.join(['--config-dir', str(config_dir)])
    scope = None
    if config_dir:
        from yt_config import read_json
        scope = read_json(Path(config_dir)/'settings.json', {}).get('file_scope')
    selected = encrypted_paths(repo, scope)
    path = Path(git(repo, 'rev-parse', '--path-format=absolute', '--git-path', 'info/attributes').decode().strip())
    previous = path.read_text() if path.exists() else ''
    if (BEGIN in previous) != (END in previous): raise ValueError('Git 属性中的显示配置标记不完整')
    if BEGIN in previous:
        before, _, tail = previous.partition(BEGIN)
        _, _, after = tail.partition(END)
        unmanaged = before.rstrip('\n') + after
    else:
        unmanaged = previous
    # Honor existing user diff drivers and explicit -diff settings. Our own
    # previously managed paths may be refreshed on repeated enable calls.
    attrs = git(repo, 'check-attr', '-z', '--stdin', 'diff',
                data=b''.join(name.encode('utf-8', 'surrogateescape') + b'\0' for name in selected)).split(b'\0') if selected else []
    allowed = []
    skipped = []
    for i in range(0, len(attrs)-1, 3):
        name, _, value = attrs[i:i+3]
        (allowed if value in (b'unspecified', DRIVER.encode()) else skipped).append(name.decode('utf-8', 'surrogateescape'))
    settings = {f'diff.{DRIVER}.textconv': command, f'diff.{DRIVER}.cachetextconv': 'false'}
    state_path = path.with_name('shit-encryption-display-state.json')
    try:
        managed = json.loads(state_path.read_text())
        if not isinstance(managed, dict): managed = {}
    except (OSError, ValueError):
        managed = {}
    existing = {}
    for key, value in settings.items():
        result = subprocess.run(['git', '-C', str(repo), 'config', '--local', '--get-all', key], capture_output=True)
        if result.returncode not in (0, 1): raise ValueError('无法读取 Git 本地配置')
        old = result.stdout.decode().splitlines()
        if old and old != [value] and not (BEGIN in previous and managed.get(key) == old[0] and len(old) == 1):
            raise ValueError(f'Git 配置 {key} 已有其他值，未覆盖')
        existing[key] = old
    backup = path.with_name('shit-encryption-display-backup.json')
    if not backup.exists():
        atomic_write_json(backup, {'attributes_existed': path.exists(), 'attributes': previous,
                                   'config_before': existing})
    for key, value in settings.items():
        if existing[key] != [value]: git(repo, 'config', '--local', key, value)
    block = BEGIN + '\n' + ''.join(quote_pattern(name) + f' diff={DRIVER}\n' for name in allowed) + END + '\n'
    text = unmanaged
    if text and not text.endswith('\n'): text += '\n'
    if text + block != previous:
        atomic_write(path, text + block, mode=0o644)
    if managed != settings:
        atomic_write_json(state_path, settings)
    return {'repository': str(repo), 'encrypted_text_files': len(allowed),
            'existing_diff_rules_preserved': skipped, 'plaintext_cache': False,
            'attributes': str(path), 'backup': str(backup)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repository', type=Path)
    parser.add_argument('--config-dir', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(enable(args.repository, config_dir=args.config_dir), ensure_ascii=False, indent=2))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        from error_log import logger
        logger('compat').exception('Git configuration failed: path=%s', args.repository)
        print(f'启用 Git 明文显示失败：{error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
