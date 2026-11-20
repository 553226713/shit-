"""Verify container-style UIDs retain ordinary permissions on a disposable mount."""
import subprocess
import sys
import shutil

from harness import ROOT, session


def populate(project, binary):
    project.parent.chmod(0o755)
    project.chmod(0o777)
    for name, mode in [('redis.conf', 0o664), ('private.conf', 0o600),
                       ('shared.conf', 0o666)]:
        path = project / name
        path.write_text('plain configuration\n')
        path.chmod(mode)
    for name in ('group-only.conf', 'wrong-group.conf'):
        path = project / name
        path.write_text('group configuration\n')
        subprocess.run(['sudo', '-n', 'chown', ':7777', str(path)], check=True)
        path.chmod(0o640)
    (project / 'rename-source').write_text('rename preserves bytes\n')
    (project / 'rename-target').write_text('unreadable target exceeding the signature probe length\n')
    (project / 'rename-target').chmod(0o000)
    for group in (7777, 8888):
        path = project / f'concurrent-{group}'
        path.write_bytes(b'group-specific access')
        subprocess.run(['sudo', '-n', 'chown', f':{group}', str(path)], check=True)
        path.chmod(0o660)


def verify():
    with session('engine2', ROOT / 'state/engine2/ytfs-engine2', populate) as (
        work, project, binary, raw_fd, pid
    ):
        subprocess.run([
            'sudo', '-n', 'setpriv', '--reuid=999', '--regid=999', '--clear-groups',
            sys.executable, '-c', '''
from pathlib import Path
import os
import sys
project = Path(sys.argv[1])
assert os.getuid() == 999
assert (project / 'redis.conf').read_text() == 'plain configuration\\n'
for name, mode in [('private.conf', 'r'), ('redis.conf', 'w')]:
    try:
        with (project / name).open(mode):
            pass
    except PermissionError:
        pass
    else:
        raise AssertionError(f'{name} unexpectedly allowed {mode}')
(project / 'shared.conf').write_text('updated by container\\n')
created = project / 'container-created.conf'
created.write_text('created by container\\n')
assert created.stat().st_uid == 999
assert created.read_text() == 'created by container\\n'
created.unlink()
(project / 'rename-source').replace(project / 'rename-target')
assert (project / 'rename-target').read_text() == 'rename preserves bytes\\n'
try:
    (project / 'wrong-group.conf').read_bytes()
except PermissionError:
    pass
else:
    raise AssertionError('supplementary groups leaked from another request')
''', str(project)], check=True)
        subprocess.run([
            'sudo', '-n', 'setpriv', '--reuid=999', '--regid=999', '--groups=7777',
            sys.executable, '-c', '''
from pathlib import Path
import sys
project = Path(sys.argv[1])
assert (project / 'group-only.conf').read_text() == 'group configuration\\n'
try:
    (project / 'group-only.conf').write_text('forbidden')
except PermissionError:
    pass
else:
    raise AssertionError('group read permission allowed write')
''', str(project)], check=True)
        assert (project / 'redis.conf').read_text() == 'plain configuration\n'
        assert (project / 'shared.conf').read_text() == 'updated by container\n'
        processes = [subprocess.Popen([
            'sudo', '-n', 'setpriv', '--reuid=999', '--regid=999', f'--groups={group}',
            sys.executable, '-c', '''
from pathlib import Path
import sys
path = Path(sys.argv[1])
for _ in range(100):
    with path.open('r+b', buffering=0) as stream:
        assert stream.read() == b'group-specific access'
        stream.seek(0)
        stream.write(b'group-specific access')
''', str(project/f'concurrent-{group}')]) for group in (7777, 8888)]
        for process in processes:
            assert process.wait(timeout=20) == 0
    print('PASS: UID 999 can read, write and create where permitted; protected files remain denied')


def verify_readonly_root():
    def populate_readonly(project, binary):
        (project/'config').write_text('read-only directory\n')
        project.chmod(0o555)
    with session('engine2', ROOT/'state/engine2/ytfs-engine2', populate_readonly) as (
        work, project, binary, raw_fd, pid
    ):
        try:
            assert (project/'config').read_text() == 'read-only directory\n'
            try:
                (project/'new').touch()
            except PermissionError:
                pass
            else:
                raise AssertionError('read-only directory unexpectedly allowed creation')
        finally:
            project.chmod(0o755)
    print('PASS: read-only monitor roots mount successfully and retain directory permissions')


def verify_program_policy():
    from harness import policy
    from verify_editor_saves import MAGIC
    key = next(line.split('==||==', 1)[1].strip() for line in policy().splitlines()
               if line.split('==||==', 1)[0].strip() == 'encryptkey').encode()
    header = bytearray(1024)
    header[:32] = MAGIC
    header[85:89] = bytes([45, 1, 0, 0])
    header[213:214 + len(key)] = key + b'\0'
    header[1019:] = b'[END]'
    for mode in ('plain', 'encrypted'):
        def populate_policy(project, binary):
            config = binary/'sgfs.conf'
            rules = '\n'.join(line for line in config.read_text().splitlines()
                              if line.split('==||==', 1)[0].strip() != '*git*')
            config.write_text(rules.replace('new_file_mode ==||== plain',
                                                         'new_file_mode ==||== ' + mode)
                              + '\n*/svn==||==*\n')
            (project/'cipher.java').write_bytes(header)
            subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror',
                            str(ROOT/'tests/engine2/file_write_probe.c'), '-o', str(binary/'git')], check=True)
            shutil.copy2(binary/'git', binary/'svn')
        with session('engine2', ROOT/'state/engine2/ytfs-engine2', populate_policy) as (
            work, project, binary, raw_fd, pid
        ):
            import os
            def stored(name):
                with os.fdopen(os.open(name, os.O_RDONLY, dir_fd=raw_fd), 'rb') as stream:
                    return stream.read()
            attempt = subprocess.run([str(binary/'git'), str(project/'cipher.java')],
                                     input=b'forbidden', capture_output=True)
            assert attempt.returncode != 0 and stored('cipher.java') == bytes(header)
            for program, trusted in [('git', False), ('svn', True)]:
                name = program + '-created.java'
                attempt = subprocess.run([str(binary/program), str(project/name)],
                                         input=b'configured program policy', capture_output=True)
                if mode == 'encrypted' and not trusted:
                    assert attempt.returncode != 0 and not (project/name).exists()
                else:
                    assert attempt.returncode == 0, attempt.stderr
                    assert (project/name).read_bytes() == b'configured program policy'
                    assert stored(name).startswith(MAGIC) == (mode == 'encrypted')
            source = project/'temporary.java'
            source.write_bytes(b'rename keeps creation mode')
            source.replace(project/'cipher.java')
            assert stored('cipher.java').startswith(MAGIC)
            if mode == 'plain':
                assert stored('cipher.java')[:1024] == header
            assert (project/'cipher.java').read_bytes() == b'rename keeps creation mode'
    print('PASS: program names grant no exemptions; both creation modes and ciphertext write protection work')


if __name__ == '__main__':
    verify()
    verify_readonly_root()
    verify_program_policy()
