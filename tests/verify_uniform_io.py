"""Test the same policy/state rules across tools on an isolated temporary mount.

No writes to real repositories, no network push, no software-name exceptions.
"""
import argparse
import json
import mmap
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from verify_git_roundtrip import broker, MAGIC


def verify(args):
    import yt_config
    yt_config.SETTINGS_PATH = args.config_dir / 'settings.json'
    yt_config.REMOTE_POLICY_PATH = args.config_dir / 'remote_policy.json'
    effective = yt_config.effective_config(yt_config.load_settings(), yt_config.load_remote_policy())
    effective['encryption']['new_file_mode'] = 'plain'
    effective['trusted_programs'] = ['*python*', '*node*', '*cat*', '*bash*', '*git*',
                                     '*tee*', '*dd*', '*perl*', '*sed*', '*awk*']
    def run(*command, data=None):
        return subprocess.run([str(x) for x in command], input=data, capture_output=True,
                              check=True, timeout=20).stdout
    raw = run('git', '-C', args.repo, 'show', 'HEAD:' + args.path)
    assert raw.startswith(MAGIC)
    result = {'version': (ROOT / 'VERSION').read_text().strip(),
              'real_source_modified': False, 'remote_push': False,
              'trusted_readers': [], 'trusted_writers': [], 'operations': []}
    with tempfile.TemporaryDirectory(prefix='shit-uniform-io-') as temporary:
        work = Path(temporary)
        project = work / 'project'; project.mkdir()
        binary = work / 'bin'; binary.mkdir()
        engine = binary / 'ytfs-engine2'; shutil.copy2(args.engine, engine)
        (binary / 'sgfs.conf').write_text(yt_config.build_sgfs_conf(effective))
        (binary / 'sgfs.conf').chmod(0o600)
        cipher = project / 'Encrypted.java'; cipher.write_bytes(raw)
        for name, offset in [('Unsupported.java',85),('WrongPolicy.java',213)]:
            content=bytearray(raw);content[offset]^=1
            (project/name).write_bytes(content)
        plain_file = project / 'Plain.java'; plain_file.write_bytes(b'class Plain {}\n')
        raw_fd = os.open(project, os.O_RDONLY | os.O_DIRECTORY)
        process = subprocess.Popen(['sudo', '-n', sys.executable, str(Path(__file__).resolve()),
                                    '--broker', str(work), str(engine)])
        try:
            deadline = time.monotonic() + 20
            while not (work / 'ready').exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('Temporary mount failed')
                time.sleep(.05)
            def disk(name):
                fd = os.open(name, os.O_RDONLY, dir_fd=raw_fd)
                with os.fdopen(fd, 'rb') as stream: return stream.read()
            def check(expected):
                assert cipher.read_bytes() == expected
                saved = disk('Encrypted.java')
                assert saved.startswith(MAGIC) and len(saved) == len(expected) + 1024
                sample = work / 'raw-saved.java'; sample.write_bytes(saved)
                decoded = run(sys.executable, ROOT / 'compat_cli.py', 'textconv', '--config-dir', args.config_dir, sample)
                assert decoded == expected, (len(decoded), len(expected), next((i for i, pair in enumerate(zip(decoded, expected)) if pair[0] != pair[1]), None))
            plain = cipher.read_bytes()
            assert plain.startswith(b'package com.xtcloud.')
            assert disk('Encrypted.java') == raw
            with cipher.open('rb',buffering=0) as stream:
                for size in [1,7,31,32,33,1023,1024]:
                    stream.seek(0);assert stream.read(size)==plain[:size]
                for offset in [1,511,len(plain)-1]:
                    stream.seek(offset);assert stream.read(7)==plain[offset:offset+7]
            result['operations'].append('small and random cipher reads across signature/header boundaries')
            for name in ['Unsupported.java','WrongPolicy.java']:
                before=disk(name)
                try:(project/name).write_bytes(b'forbidden')
                except OSError:pass
                else:raise AssertionError('Unsupported ciphertext became writable: '+name)
                assert disk(name)==before
            result['operations'].append('unknown format and mismatched policy preserve disk bytes')
            readers = [('cat', ['cat', cipher]),
                       ('bash builtin', ['bash', '-c', 'IFS= read -r -d "" content < "$1"; printf %s "$content"', 'reader', cipher]),
                       ('python', [sys.executable, '-c', 'import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())', cipher]),
                       ('perl', ['perl', '-e', 'open F,"<",$ARGV[0] or die; binmode F; local $/; print <F>', cipher])]
            node = shutil.which('node')
            if node: readers.append(('node', [node, '-e', 'process.stdout.write(require("fs").readFileSync(process.argv[1]))', cipher]))
            for name, command in readers:
                assert run(*command) == plain, name
                result['trusted_readers'].append(name)
            # Git must now obey its configured plaintext policy like every
            # other matched executable; do not write objects or push anything.
            assert run('git', 'hash-object', cipher) == run('git', 'hash-object', '--stdin', data=plain)
            result['trusted_readers'].append('git (policy matched, no exception)')
            assert run('/usr/bin/head', '-c', '32', cipher) == raw[:32]
            # head is not configured; tee, interpreters and shell redirections are.
            writers = [('tee', ['tee', cipher]), ('dd', ['dd', 'of=' + str(cipher), 'status=none']),
                       ('bash redirect', ['bash', '-c', 'cat > "$1"', 'writer', cipher]),
                       ('perl', ['perl', '-e', 'open F,">",$ARGV[0] or die; binmode F; while(read STDIN,$b,4096){print F $b} close F', cipher])]
            if node: writers.append(('node', [node, '-e', 'const f=require("fs");f.writeFileSync(process.argv[1],f.readFileSync(0))', cipher]))
            for name, command in writers:
                expected = plain + ('\n// uniform write ' + name + '\n').encode()
                run(*command, data=expected); check(expected)
                result['trusted_writers'].append(name)
            expected = plain + ('\n// 跨块源码读写\n' * 6000).encode()
            cipher.write_bytes(expected); check(expected)
            result['trusted_writers'].append('python')
            with cipher.open('r+b') as stream:
                os.pwrite(stream.fileno(), b'// random offset\n', 0)
            expected = b'// random offset\n' + expected[len(b'// random offset\n'):]
            check(expected); result['operations'].append('random write and multi-chunk Unicode')
            with cipher.open('ab') as stream: stream.write(b'// append\n')
            expected += b'// append\n'; check(expected)
            result['operations'].append('append')
            with cipher.open('r+b') as stream: stream.truncate(len(expected)+20)
            expected += b'\0' * 20; check(expected)
            result['operations'].append('truncate extension zero-fill')
            stage = cipher.with_name('.save.tmp'); expected = plain + b'\n// atomic save\n'
            stage.write_bytes(expected); stage.replace(cipher)
            assert disk('Encrypted.java') == expected
            assert cipher.read_bytes() == expected
            result['operations'].append('atomic replacement preserves plaintext source')
            # Restore a ciphertext fixture through the backing descriptor for subsequent encrypted I/O checks.
            fd = os.open('Encrypted.java', os.O_WRONLY | os.O_TRUNC, dir_fd=raw_fd)
            with os.fdopen(fd, 'wb') as stream: stream.write(raw)
            cipher.write_bytes(expected); check(expected)
            with cipher.open('r+b') as stream:
                with mmap.mmap(stream.fileno(), 0) as mapping:
                    assert mapping[:] == expected
                    mapping[:2] = b'//'; mapping.flush()
                expected = b'//' + expected[2:]
                check(expected)
                result['operations'].append('mmap shared read/write/flush')
            assert run('/usr/bin/head', '-c', '32', cipher) == MAGIC
            blocked = binary / 'untrusted-writer'
            subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror',
                            str(ROOT/'engine2/file_write_probe.c'), '-o', str(blocked)], check=True)
            before = disk('Encrypted.java')
            denied = subprocess.run([str(blocked), str(cipher)], input=b'forbidden', capture_output=True)
            assert denied.returncode != 0 and disk('Encrypted.java') == before
            result['operations'].append('unmatched reader sees ciphertext; writer cannot truncate it')
            plain_file.write_bytes(b'class PlainUpdated {}\n')
            stage.write_bytes(b'class PlainAtomic {}\n'); stage.replace(plain_file)
            assert disk('Plain.java') == b'class PlainAtomic {}\n'
            new = project / 'New.java'; new.write_bytes(b'class New {}\n')
            assert disk('New.java') == b'class New {}\n'
            result['operations'].append('plain and new files stay plaintext')
            cipher.write_bytes(b''); check(b'')
            result['operations'].append('empty encrypted file retains header')
        finally:
            (work / 'stop').touch()
            try: process.wait(timeout=20)
            finally:
                for log in ['engine2.log', 'engine2-metrics.json']:
                    if (work / log).exists(): shutil.copy2(work / log, ROOT / 'state/engine2' / log)
                os.close(raw_fd)
                subprocess.run(['sudo', '-n', 'rm', '-rf', '--', str(work / 'monitor')], check=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--broker': broker(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        parser=argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--engine',type=Path,default=ROOT/'state/engine2/ytfs-engine2')
        parser.add_argument('--repo',type=Path,required=True)
        parser.add_argument('--path',required=True)
        parser.add_argument('--config-dir',type=Path,required=True)
        parser.add_argument('--output',type=Path,default=ROOT/'state/uniform-io-verification.json')
        verify(parser.parse_args())
