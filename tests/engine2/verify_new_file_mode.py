"""Verify both new-file formats on disposable mounts, including the 301 header."""
import argparse
import errno
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
    for mode in ('plain', 'encrypted'):
        def populate(project, binary):
            config = binary/'sgfs.conf'
            rules = config.read_text()
            config.write_text(rules.replace('new_file_mode ==||== plain',
                                                         'new_file_mode ==||== ' + mode))
            with config.open('a') as stream:
                stream.write('*java*==||==*\n*/svn==||==*\n')
            (project/'Existing.java').write_bytes(b'original plain')
            (project/'Cipher.java').write_bytes(old_header)
            if mode == 'encrypted':
                for i in range(8):
                    (project/f'Jvm{i}.java').write_bytes(old_header)
                subprocess.run(['javac', '-d', str(binary), str(ROOT/'tests/engine2/editor_save_probe.java')], check=True)
            subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror',
                            str(ROOT/'tests/engine2/file_write_probe.c'), '-o', str(binary/'untrusted-writer')], check=True)
            shutil.copy2(binary/'untrusted-writer', binary/'git')
            shutil.copy2(binary/'untrusted-writer', binary/'svn')
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
                excluded = project/'node_modules'
                excluded.mkdir()
                raw_copy = excluded/'Single.java'
                raw_copy.write_bytes(stored)
                assert disk('node_modules/Single.java') == stored
                for name, writes, rejected in [
                    ('Whole.java', [], (0, stored)),
                    ('Split.java', [(0, stored[:16])], (16, stored[16:])),
                    ('OutOfOrder.java', [(16, stored[16:32])], (0, stored[:16])),
                ]:
                    target = project/name
                    with target.open('w+b', buffering=0) as stream:
                        for offset, data in writes:
                            assert os.pwrite(stream.fileno(), data, offset) == len(data)
                        before = disk(name)
                        try:
                            os.pwrite(stream.fileno(), rejected[1], rejected[0])
                        except OSError as error:
                            assert error.errno == errno.EBADMSG, error
                        else:
                            raise AssertionError(f'Accepted nested ciphertext in {name}')
                        assert disk(name) == before
                        stream.seek(0)
                        replacement = b'normal plaintext write after rejection'
                        assert stream.write(replacement) == len(replacement)
                    check(target, replacement)
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
            check(nested, b'all paths', encrypted=False)
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
            check(existing, b'atomic plain replacement')
            cipher = project/'Cipher.java'; cipher.write_bytes(b'original cipher stays encrypted')
            check(cipher, b'original cipher stays encrypted', encrypted=True)
            assert disk(cipher.name)[:1024] == old_header
            stage = project/'cipher-save.tmp'; stage.write_bytes(b'atomic cipher replacement')
            stage.replace(cipher)
            check(cipher, b'atomic cipher replacement', encrypted=True)
            if mode == 'plain':
                assert disk(cipher.name)[:1024] == old_header
            for temporary, backup_suffix in [('.tmp', '~'), ('___jb_tmp___', '___jb_old___')]:
                stage = project/(cipher.name + temporary)
                backup = project/(cipher.name + backup_suffix)
                stage.write_bytes(b'two-step cipher replacement')
                cipher.rename(backup); stage.replace(cipher); backup.unlink()
                check(cipher, b'two-step cipher replacement',
                      encrypted=mode == 'encrypted' and temporary == '.tmp')
            untrusted = project/'Untrusted.java'
            attempt = subprocess.run([str(binary/'untrusted-writer'), str(untrusted)],
                                     input=b'not trusted', capture_output=True, timeout=5)
            if mode == 'encrypted':
                assert attempt.returncode != 0 and not untrusted.exists()
            else:
                assert attempt.returncode == 0 and disk(untrusted.name) == b'not trusted', (attempt.returncode, attempt.stderr)
            named_git = project/'Git.java'
            attempt = subprocess.run([str(binary/'git'), str(named_git)], input=b'ordinary git write',
                                     capture_output=True, timeout=5)
            assert attempt.returncode == 0, attempt.stderr
            # A fake named git follows ordinary trusted creation policy, not
            # the real system Git raw-transport exemption.
            check(named_git, b'ordinary git write')
            named_svn = project/'Svn.java'
            subprocess.run([str(binary/'svn'), str(named_svn)], input=b'authorized svn write',
                           capture_output=True, check=True, timeout=5)
            check(named_svn, b'authorized svn write')
            os.mkfifo(project/'pipe')
            assert stat.S_ISFIFO((project/'pipe').stat().st_mode)
            if mode == 'encrypted':
                subprocess.run(['java', '-cp', str(binary), 'EditorSaveProbe', str(project)], check=True, timeout=40)
                for i in range(8):
                    path = project/f'Jvm{i}.java'
                    # The probe ends with a two-step rename from an unlisted suffix.
                    check(path, (f'// 保存 {i}:7\n'.encode()) * 500, encrypted=False)
            results[mode] = 'PASS create/read/write/append/truncate/mmap, nested dirs, permissions, source-preserving renames, uniform program authorization'
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', type=Path, default=ROOT/'state/engine2/ytfs-engine2')
    verify(parser.parse_args().engine)
