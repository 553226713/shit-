"""Exercise editor save transactions on disposable mounts, never real projects."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from harness import ROOT, session

MAGIC = bytes.fromhex('6e7e5a6d0089da16e3b351ea53aafb8bf665ef5aa662a08765f64e627500675c')


def verify(engine):
    # Empty valid ciphertext needs no external sample or production keys.
    from harness import policy
    key = next(line.split('==||==', 1)[1].strip() for line in policy().splitlines()
               if line.split('==||==', 1)[0].strip() == 'encryptkey').encode()
    header = bytearray(1024)
    header[:32] = MAGIC
    header[85:89] = bytes([45, 1, 0, 0])
    header[213:213 + len(key) + 1] = key + b'\0'
    header[1019:] = b'[END]'
    def populate(project, binary):
        config = binary/'sgfs.conf'
        with config.open('a') as stream:
            stream.write('*java*==||==*.java\n')
        for name in ('Atomic.java', 'Large.java', 'Legacy.java', 'Handle.java',
                     *(f'Jvm{i}.java' for i in range(8))):
            (project/name).write_bytes(header)
        for folder in ('tmp', 'src/tmp', 'temp', 'attempt', 'node_modules', 'build', '.git', 'custom-cache'):
            directory = project/folder
            directory.mkdir(parents=True, exist_ok=True)
            (directory/'Nested.java').write_bytes(header)
            (directory/'Unknown.custom').write_bytes(header)
            (directory/'NoExtension').write_bytes(header)
        os.mkfifo(project/'tmp/pipe')
        (project/'tmp/broken-link').symlink_to('missing')
        subprocess.run(['javac', '-d', str(binary), str(ROOT/'engine2/editor_save_probe.java')], check=True)
    results = {}
    with session('engine2', engine, populate) as (_, project, binary, raw_fd, _):
        def disk(name):
            fd = os.open(name, os.O_RDONLY, dir_fd=raw_fd)
            with os.fdopen(fd, 'rb') as stream:
                return stream.read()
        def check(path, expected):
            stored = disk(str(path.relative_to(project)))
            assert stored[:1024] == header, f'{path.name}: original header lost'
            assert len(stored) == 1024 + len(expected), path.name
            assert path.read_bytes() == expected, path.name
        for folder in ('tmp', 'src/tmp', 'temp', 'attempt', 'node_modules', 'build', '.git', 'custom-cache'):
            path = project/folder/'Nested.java'
            assert path.read_bytes() == b'', folder
            expected = f'class Nested {{ /* {folder} */ }}\n'.encode()
            path.write_bytes(expected)
            check(path, expected)
            for name in ('Unknown.custom', 'NoExtension'):
                extra = project/folder/name
                assert extra.read_bytes() == b'', str(extra)
                extra.write_bytes(expected)
                check(extra, expected)
        results['all_subdirectories_and_file_types_decrypt'] = True
        # Baseline atomic replacement with an existing destination.
        atomic = project/'Atomic.java'
        stage = project/'atomic-save.tmp'
        stage.write_bytes(b'class Atomic {}\n')
        stage.replace(atomic)
        check(atomic, b'class Atomic {}\n')
        results['atomic_replace'] = True
        # Keep a descriptor open across rename to an editor backup name.
        path = project/'Handle.java'
        expected = b'class Handle {}\n'
        path.write_bytes(expected)
        with path.open('r+b', buffering=0) as stream:
            backup = project/'Handle.java~'
            path.rename(backup)
            stream.seek(0)
            results['open_handle_after_backup_rename'] = stream.read() == expected
            stream.seek(0)
            try:
                stream.write(b'//')
                stream.truncate(len(expected))
                stream.seek(0)
                results['write_handle_after_backup_rename'] = stream.read() == b'//' + expected[2:]
            except OSError:
                results['write_handle_after_backup_rename'] = False
            backup.rename(path)
            results['restored_handle_content'] = path.read_bytes() == b'//' + expected[2:]
        for name, temporary, backup_suffix in [('Large.java', '.tmp', '~'),
                                               ('Legacy.java', '___jb_tmp___', '___jb_old___')]:
            path = project/name
            for turn in range(4):
                expected = (f'class Save{turn} {{ /* 中文 */ }}\n'.encode()) * 150
                stage = project/(name + temporary)
                backup = project/(name + backup_suffix)
                stage.write_bytes(expected)
                backup.write_bytes(b'previous plaintext backup')
                path.rename(backup)
                stage.replace(path)
                backup.unlink()
                stored = disk(name)
                results[name] = stored.startswith(MAGIC) and len(stored) == len(expected) + 1024 and path.read_bytes() == expected
                if not results[name]:
                    break
        # Ordinary fresh and plain files must remain plain, even with a stale
        # encrypted backup when the source isn't an editor staging name.
        new = project/'New.java'
        new.write_bytes(b'plain')
        assert disk(new.name) == b'plain'
        stale = project/'Stale.java'
        (project/'Stale.java~').write_bytes(header)
        ordinary = project/'ordinary-stage'
        ordinary.write_bytes(b'ordinary new file')
        ordinary.replace(stale)
        assert disk(stale.name) == b'ordinary new file'
        results['new_files_stay_plain'] = True
        plain = project/'Plain.java'
        plain.write_bytes(b'old plain')
        plain_stage = project/'Plain.java.tmp'
        plain_stage.write_bytes(b'updated plain')
        plain_backup = project/'Plain.java~'
        plain.rename(plain_backup)
        plain_stage.replace(plain)
        assert disk(plain.name) == b'updated plain'
        plain_backup.unlink()
        results['plain_safe_save_stays_plain'] = True
        subprocess.run(['java', '-cp', str(binary), 'EditorSaveProbe', str(project)], check=True, timeout=40)
        for i in range(8):
            expected = (f'// 保存 {i}:7\n'.encode()) * 500
            check(project/f'Jvm{i}.java', expected)
        results['java_nio_parallel_safe_saves_and_mmap'] = True
        fifo = project/'Fifo.java'
        os.mkfifo(fifo)
        stage.write_bytes(b'replace fifo')
        child = subprocess.Popen([sys.executable, '-c',
                                  'import os,sys; os.replace(sys.argv[1], sys.argv[2])',
                                  str(stage), str(fifo)])
        try:
            assert child.wait(timeout=3) == 0
            results['rename_over_fifo_does_not_block'] = disk(fifo.name) == b'replace fifo'
        except subprocess.TimeoutExpired:
            # Release a regressed engine's blocking FIFO open before killing
            # the requester; SIGKILL alone cannot finish a blocked FUSE call.
            fd = os.open(fifo.name, os.O_WRONLY | os.O_NONBLOCK, dir_fd=raw_fd)
            os.close(fd)
            child.kill()
            child.wait(timeout=5)
            results['rename_over_fifo_does_not_block'] = False
    print(json.dumps(results, ensure_ascii=False, indent=2))
    assert all(results.values()), results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', type=Path, default=ROOT/'state/engine2/ytfs-engine2')
    verify(parser.parse_args().engine)
