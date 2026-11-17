"""Verify ciphertext Git transport on disposable FUSE mounts and local bare remotes.

No source repository, index, remote, production sample, or archived decoder is used
by default. Optional repo/path arguments load a read-only historical sample.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'tests/engine2'))
from harness import session
from verify_editor_saves import MAGIC, synthetic_header


def run(*args, cwd=None, data=None):
    result = subprocess.run(args, cwd=cwd, input=data, capture_output=True,
                            env=dict(os.environ, GIT_TERMINAL_PROMPT='0',
                                     GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null'))
    if result.returncode:
        raise RuntimeError(f'{args!r}: {result.stderr.decode(errors="replace")}')
    return result.stdout


def git(repo, *args, data=None):
    return run(shutil.which('git'), '-C', str(repo), *args, data=data)


def verify(args):
    header = synthetic_header()
    initial = bytes(header)
    relative = args.path or Path('Cipher.java')
    assert not relative.is_absolute() and '..' not in relative.parts
    if args.repo:
        initial = git(args.repo.resolve(), 'show', args.ref + ':' + relative.as_posix())
        assert initial.startswith(MAGIC), 'Historical sample is not ciphertext'
        header = initial[:1024]
    results = {}
    for mode in ('plain', 'encrypted'):
        def populate(project, binary):
            from yt_client import yt_config
            config = binary / 'sgfs.conf'
            key = next(line.split('==||==', 1)[1].strip()
                       for line in config.read_text().splitlines() if line.startswith('encryptkey'))
            settings_path = binary / 'settings.json'
            yt_config.save_settings({'encryption': {'key': key, 'new_file_mode': mode},
                                     'trusted_programs': ['*']}, settings_path)
            settings = yt_config.load_settings(settings_path)
            config.write_text(yt_config.build_sgfs_conf(yt_config.effective_config(settings, None)))
            target = project / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(initial)
            (project / 'ExistingPlain.txt').write_bytes(b'existing plaintext\n')
        with session('engine2', args.engine.resolve(), populate) as (work, project, binary, raw_fd, _):
            def disk(path):
                with os.fdopen(os.open(str(path), os.O_RDONLY, dir_fd=raw_fd), 'rb') as stream:
                    return stream.read()
            file = project / relative
            plain = file.read_bytes()
            assert len(plain) == len(initial) - 1024
            git(project, 'init', '-q')
            git(project, 'config', 'user.name', 'Cipher regression')
            git(project, 'config', 'user.email', 'verification@localhost')
            assert disk('.git/config') == (project / '.git/config').read_bytes()
            assert not disk('.git/config').startswith(MAGIC)
            existing = project / 'ExistingPlain.txt'
            existing.write_bytes(b'updated existing plaintext\n')
            existing_bytes = disk(existing.name)
            assert existing_bytes == existing.read_bytes() == b'updated existing plaintext\n'
            git(project, 'add', '--', relative.as_posix(), existing.name)
            assert git(project, 'show', ':' + existing.name) == existing_bytes
            assert git(project, 'show', ':' + relative.as_posix()) == initial
            git(project, 'commit', '-q', '-m', 'initial ciphertext')
            from yt_client.compat.git import enable
            display = enable(project, args.textconv)
            assert display['encrypted_text_files'] == 1
            assert not disk('.git/info/attributes').startswith(MAGIC)
            assert git(project, 'show', '--textconv', 'HEAD:' + relative.as_posix()) == plain
            expected = plain + b'\n// direct-save verification\n'
            file.write_bytes(expected)
            direct = disk(relative)
            assert direct[:1024] == header and len(direct) == 1024 + len(expected)
            assert file.read_bytes() == expected
            assert b'+// direct-save verification' in git(project, 'diff', '--', relative.as_posix())
            git(project, 'add', '--', relative.as_posix())
            assert git(project, 'show', ':' + relative.as_posix()) == direct
            file.write_bytes(b'uncommitted direct save')
            git(project, 'restore', '--worktree', '--', relative.as_posix())
            assert disk(relative) == direct and file.read_bytes() == expected
            expected += ('// atomic save 中文🙂\n' * 5000).encode()
            stage = file.with_name('.' + file.name + '.tmp')
            stage.write_bytes(expected)
            stage_header = disk(stage.relative_to(project))[:1024]
            stage.replace(file)
            stored = disk(relative)
            assert stored.startswith(MAGIC) and len(stored) == 1024 + len(expected)
            if mode == 'plain':
                assert stored[:1024] == header
            else:
                assert stored[:1024] == stage_header
            assert file.read_bytes() == expected and stored != expected
            assert git(project, 'hash-object', relative.as_posix()) == git(project, 'hash-object', '--stdin', data=stored)
            git(project, 'add', '--', relative.as_posix())
            assert git(project, 'show', ':' + relative.as_posix()) == stored
            created = project / 'NewFile.txt'
            created_text = b'new file selected format\n'
            created.write_bytes(created_text)
            created_bytes = disk(created.name)
            assert created.read_bytes() == created_text
            if mode == 'encrypted':
                assert created_bytes.startswith(MAGIC) and len(created_bytes) == len(created_text) + 1024
            else:
                assert created_bytes == created_text
            git(project, 'add', '--', created.name)
            assert git(project, 'show', ':' + created.name) == created_bytes
            git(project, 'commit', '-q', '-m', 'editor ciphertext')
            assert git(project, 'show', 'HEAD:' + relative.as_posix()) == stored
            display = enable(project, args.textconv)
            assert display['encrypted_text_files'] == (2 if mode == 'encrypted' else 1)
            assert not disk('.git/info/attributes').startswith(MAGIC)
            assert git(project, 'show', '--textconv', 'HEAD:' + relative.as_posix()) == expected
            remote = work / 'remote.git'
            fetched = work / 'fetched.git'
            git(work, 'init', '--bare', '-q', str(remote))
            git(project, 'push', '-q', str(remote), 'HEAD:refs/heads/verification')
            git(work, 'init', '--bare', '-q', str(fetched))
            git(fetched, 'fetch', '-q', '--no-tags', str(remote), 'refs/heads/verification')
            received = git(fetched, 'show', 'FETCH_HEAD:' + relative.as_posix())
            assert received == stored
            assert git(fetched, 'show', 'FETCH_HEAD:' + existing.name) == existing_bytes
            assert git(fetched, 'show', 'FETCH_HEAD:' + created.name) == created_bytes
            received_dir = project / '.git/received'
            git(project, 'checkout-index', '--prefix=' + str(received_dir) + '/', '--', relative.as_posix())
            incoming = received_dir / relative
            # Real Git creates received ciphertext without applying new-file encryption.
            assert disk(incoming.relative_to(project)) == stored
            copy = project / 'Received.java'
            incoming.replace(copy)
            assert disk('Received.java') == stored and copy.read_bytes() == expected
            file.write_bytes(b'uncommitted atomic save')
            git(project, 'checkout', '--', relative.as_posix())
            assert disk(relative) == stored and file.read_bytes() == expected
            git(project, 'checkout', '-q', 'HEAD~1')
            assert disk(relative) == initial and file.read_bytes() == plain
            git(project, 'checkout', '-q', '-')
            assert disk(relative) == stored and file.read_bytes() == expected
            assert disk(existing.name) == existing_bytes
            assert disk(created.name) == created_bytes and created.read_bytes() == created_text
            assert not git(project, 'status', '--porcelain', '--', relative.as_posix())
            results[mode] = dict(direct_save=True, atomic_save=True, ciphertext_transport=True,
                                 independent_fetch=True, editor_plaintext=True, checkout_restore=True,
                                 git_metadata_plain=True, existing_plaintext_preserved=True,
                                 new_file_setting_applied=True, remote_matches_disk=True,
                                 blob_sha256=hashlib.sha256(received).hexdigest())
    if args.output:
        args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repo', type=Path, nargs='?')
    parser.add_argument('path', type=Path, nargs='?')
    parser.add_argument('--ref', default='HEAD', help='Read-only historical sample revision')
    parser.add_argument('--engine', type=Path, default=ROOT / 'state/engine2/ytfs-engine2')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--textconv', help='Optional read-only display command')
    args = parser.parse_args()
    if args.path and not args.repo:
        parser.error('path requires repo')
    verify(args)
