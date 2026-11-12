"""Verify both new-file formats on disposable mounts, including the 301 header."""
import argparse
import json
import mmap
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

from harness import ROOT, policy, session
from verify_editor_saves import MAGIC


def verify(engine):
    key = next(line.split('==||==', 1)[1].strip() for line in policy().splitlines()
               if line.split('==||==', 1)[0].strip() == 'encryptkey').encode()
    old_header = bytearray(1024)
    old_header[:32] = MAGIC
    old_header[85:89] = bytes([45, 1, 0, 0])
    old_header[213:214 + len(key)] = key + b'\0'
    old_header[1019:] = b'[END]'
    results = {}
    sys.path.insert(0, str(ROOT.parent/'linux-client-archive'))
    from probe_cipher import probe
    for mode in ('plain', 'encrypted'):
        def populate(project, binary):
            config = binary/'sgfs.conf'
            config.write_text(config.read_text().replace('new_file_mode ==||== plain',
                                                         'new_file_mode ==||== ' + mode))
            with config.open('a') as stream:
                stream.write('*java*==||==*\n')
            (project/'Existing.java').write_bytes(b'original plain')
            (project/'Cipher.java').write_bytes(old_header)
            if mode == 'encrypted':
                for i in range(8):
                    (project/f'Jvm{i}.java').write_bytes(old_header)
                subprocess.run(['javac', '-d', str(binary), str(ROOT/'engine2/editor_save_probe.java')], check=True)
            subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror',
                            str(ROOT/'engine2/file_write_probe.c'), '-o', str(binary/'untrusted-writer')], check=True)
            shutil.copy2(binary/'untrusted-writer', binary/'git')
        with session('engine2', engine, populate) as (_, project, binary, raw_fd, _):
            def disk(name):
                fd = os.open(name, os.O_RDONLY, dir_fd=raw_fd)
                with os.fdopen(fd, 'rb') as stream:
                    return stream.read()
            def check(path, expected, encrypted=None):
                encrypted = mode == 'encrypted' if encrypted is None else encrypted
                assert path.read_bytes() == expected, (mode, path.name)
                stored = disk(str(path.relative_to(project)))
                if encrypted:
                    assert stored.startswith(MAGIC) and len(stored) == len(expected) + 1024
                    assert stored[213:214 + len(key)] == key + b'\0'
                    assert probe(b'YANGTUFS', stored[1024:], 1024, original_key_setup=True) == expected
                else:
                    assert stored == expected
                return stored
            new = project/'New.custom'
            expected = b'// new file\n' + bytes(range(256)) + '中文\n'.encode()
            new.write_bytes(expected)
            stored = check(new, expected)
            if mode == 'encrypted':
                assert int.from_bytes(stored[65:69], 'little') == 0x03583860
                assert stored[278:300] == b'2020.NewDriver-Pading\0'
                assert stored[1019:1024] == b'[END]'
                assert probe(b'YANGTUFS', stored[32:64], 0, original_key_setup=True) == MAGIC
            with new.open('ab', buffering=0) as stream:
                stream.write(b'append\n')
            expected += b'append\n'; check(new, expected)
            with new.open('r+b', buffering=0) as stream:
                stream.truncate(len(expected) + 17)
            expected += b'\0' * 17; check(new, expected)
            with new.open('r+b', buffering=0) as stream:
                with mmap.mmap(stream.fileno(), 0) as mapped:
                    assert mapped[:] == expected
                    mapped[:2] = b'/*'; mapped.flush()
            expected = b'/*' + expected[2:]; check(new, expected)
            folder = project/'tmp/node_modules/build'; folder.mkdir(parents=True)
            nested = folder/'NoExtension'; nested.write_bytes(b'all paths')
            check(nested, b'all paths')
            empty = project/'Empty.java'
            fd = os.open(empty, os.O_RDONLY | os.O_CREAT | os.O_EXCL, 0o600)
            assert os.read(fd, 1) == b''; os.close(fd)
            check(empty, b'')
            regular = project/'Mknod.java'; os.mknod(regular, stat.S_IFREG | 0o600)
            check(regular, b'')
            writable = project/'WriteOnly.java'
            fd = os.open(writable, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o200)
            os.write(fd, b'write only'); os.close(fd)
            writable.chmod(0o600); check(writable, b'write only')
            existing = project/'Existing.java'
            existing.write_bytes(b'existing plain stays plain')
            check(existing, b'existing plain stays plain', encrypted=False)
            stage = project/'save.tmp'; stage.write_bytes(b'atomic plain replacement')
            stage.replace(existing)
            check(existing, b'atomic plain replacement', encrypted=False)
            cipher = project/'Cipher.java'; cipher.write_bytes(b'original cipher stays encrypted')
            check(cipher, b'original cipher stays encrypted', encrypted=True)
            assert disk(cipher.name)[:1024] == old_header
            stage = project/'cipher-save.tmp'; stage.write_bytes(b'atomic cipher replacement')
            stage.replace(cipher)
            check(cipher, b'atomic cipher replacement', encrypted=True)
            assert disk(cipher.name)[:1024] == old_header
            for temporary, backup_suffix in [('.tmp', '~'), ('___jb_tmp___', '___jb_old___')]:
                stage = project/(cipher.name + temporary)
                backup = project/(cipher.name + backup_suffix)
                stage.write_bytes(b'two-step cipher replacement')
                cipher.rename(backup); stage.replace(cipher); backup.unlink()
                check(cipher, b'two-step cipher replacement', encrypted=True)
                assert disk(cipher.name)[:1024] == old_header
            untrusted = project/'Untrusted.java'
            attempt = subprocess.run([str(binary/'untrusted-writer'), str(untrusted)],
                                     input=b'not trusted', capture_output=True, timeout=5)
            if mode == 'encrypted':
                assert attempt.returncode != 0 and not untrusted.exists()
            else:
                assert attempt.returncode == 0 and disk(untrusted.name) == b'not trusted', (attempt.returncode, attempt.stderr)
            raw = project/'Raw.java'
            subprocess.run([str(binary/'git'), str(raw)], input=b'raw restore',
                           stdout=subprocess.DEVNULL, check=True, timeout=5)
            assert disk(raw.name) == b'raw restore'
            os.mkfifo(project/'pipe')
            assert stat.S_ISFIFO((project/'pipe').stat().st_mode)
            if mode == 'encrypted':
                subprocess.run(['java', '-cp', str(binary), 'EditorSaveProbe', str(project)], check=True, timeout=40)
                for i in range(8):
                    path = project/f'Jvm{i}.java'
                    check(path, (f'// 保存 {i}:7\n'.encode()) * 500)
                    assert disk(path.name)[:1024] == old_header
            results[mode] = 'PASS create/read/write/append/truncate/mmap, nested dirs, permissions, original formats, VCS raw view'
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', type=Path, default=ROOT/'state/engine2/ytfs-engine2')
    verify(parser.parse_args().engine)
