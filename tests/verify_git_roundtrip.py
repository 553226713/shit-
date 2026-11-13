"""Exercise editor saves and policy-controlled Git transport on a disposable FUSE mount.

Requires sudo -n. The source repository and its index are read only. A remote
push is performed only with --remote; the unique verification branch is kept.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
MAGIC = bytes.fromhex('6e7e5a6d0089da16e3b351ea53aafb8bf665ef5aa662a08765f64e627500675c')


def run(*args, cwd=None, data=None):
    result = subprocess.run(args, cwd=cwd, input=data, capture_output=True,
                            env=dict(os.environ, GIT_TERMINAL_PROMPT='0'))
    if result.returncode:
        raise RuntimeError(f'{args!r}: {result.stderr.decode(errors="replace")}')
    return result.stdout


def git(repo, *args):
    return run('git', '-C', str(repo), *args)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def broker(work, engine):
    from engine2.testing import broker as engine_broker
    return engine_broker(work, engine)


def verify(args):
    import yt_config
    if args.config_dir:
        yt_config.SETTINGS_PATH = args.config_dir / 'settings.json'
        yt_config.REMOTE_POLICY_PATH = args.config_dir / 'remote_policy.json'
    effective = yt_config.effective_config(yt_config.load_settings(), yt_config.load_remote_policy())
    # Git follows the configured trusted plaintext view like other programs.
    effective['trusted_programs'] += ['*git*', '*python*']
    effective['encryption']['new_file_mode'] = 'plain'
    source = args.repo.resolve()
    relative = args.path
    assert not relative.is_absolute() and '..' not in relative.parts
    original = git(source, 'show', 'HEAD:' + str(relative))
    assert original.startswith(MAGIC), 'HEAD sample is not ciphertext'
    source_head = git(source, 'rev-parse', 'HEAD').decode().strip()
    source_index = (source / '.git/index').read_bytes()
    # An untrusted utility reads the disk view, independent of Python's policy.
    source_disk = run('/usr/bin/head', '-c', '100000000', str(source / relative))
    assert source_disk.startswith(MAGIC), 'Source disk view is not ciphertext'
    result = {'source_path': str(source / relative), 'base_commit': source_head,
              'source_disk_sha256': digest(source_disk), 'source_index_unchanged': False}
    with tempfile.TemporaryDirectory(prefix='shit-git-roundtrip-') as temporary:
        work = Path(temporary)
        project = work / 'project'; project.mkdir()
        binary = work / 'bin'; binary.mkdir()
        engine = binary / 'ytfs-engine2'
        shutil.copy2(args.engine.resolve(), engine)
        (binary / 'sgfs.conf').write_text(yt_config.build_sgfs_conf(effective))
        (binary / 'sgfs.conf').chmod(0o600)
        git(project, 'init', '-q')
        git(project, 'fetch', '-q', '--no-tags', str(source), 'HEAD')
        git(project, 'update-ref', 'HEAD', source_head)
        git(project, 'read-tree', 'HEAD')
        git(project, 'config', 'user.name', 'shit-encryption verification')
        git(project, 'config', 'user.email', 'verification@localhost')
        file = project / relative; file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(original)
        process = subprocess.Popen(['sudo', '-n', sys.executable, str(Path(__file__).resolve()),
                                    '--broker', str(work), str(engine)])
        index_watch = None
        try:
            deadline = time.monotonic() + 20
            while not (work / 'ready').exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('Disposable mount did not start')
                time.sleep(.05)
            plain = file.read_bytes()
            assert plain.startswith(b'package com.xtcloud.'), 'Editor did not receive Java plaintext'
            assert len(plain) == len(original) - 1024
            if args.textconv:
                from compat.git import enable
                from compat.index_watch import IndexWatch
                index_watch=IndexWatch();index_watch.sync([project])
                display = enable(project, args.textconv)
                assert display['encrypted_text_files'] > 0
                assert git(project, 'show', '--textconv', 'HEAD:' + str(relative)) == plain
            plain_oid = run('git', '-C', str(project), 'hash-object', '--stdin', data=plain).strip()
            assert git(project, 'hash-object', str(relative)).strip() == plain_oid
            # Direct writes preserve encryption; trusted Git stages plaintext.
            file.write_bytes(plain + b'\n// direct-save verification\n')
            assert file.read_bytes() == plain + b'\n// direct-save verification\n'
            if args.textconv:
                assert b'+// direct-save verification' in git(project, 'diff', '--', str(relative))
            git(project, 'add', '--', str(relative))
            if index_watch:
                assert project in index_watch.changed(), 'Atomic index replacement event missing through FUSE'
                result['fuse_index_events_verified'] = True
            direct = git(project, 'show', ':' + str(relative))
            assert direct == plain + b'\n// direct-save verification\n'
            file.write_bytes(b'uncommitted change')
            git(project, 'restore', '--worktree', '--', str(relative))
            assert file.read_bytes() == direct
            # Save like an editor: a plaintext sibling replaces an encrypted target.
            marker = ('\n// shit-encryption ciphertext roundtrip ' + work.name + '\n').encode()
            expected = plain + marker
            if args.textconv:
                expected += ('// 多块只读显示验证🙂\n' * 5000).encode('utf-8')
            stage = file.with_name('.' + file.name + '.tmp')
            stage.write_bytes(expected)
            stage.replace(file)
            assert file.read_bytes() == expected
            git(project, 'add', '--', str(relative))
            staged = git(project, 'show', ':' + str(relative))
            assert staged == expected
            if args.textconv:
                assert marker.strip() in git(project, 'diff', '--cached', '--', str(relative))
                assert b'Binary files' in git(project, 'diff', '--no-textconv', '--cached', '--', str(relative))
            git(project, 'commit', '-q', '-m', 'test: verify encrypted GeoHermeticService Git roundtrip')
            commit = git(project, 'rev-parse', 'HEAD').decode().strip()
            changed = git(project, 'diff-tree', '--no-commit-id', '--name-only', '-r', 'HEAD').decode().splitlines()
            assert changed == [str(relative)], changed
            committed = git(project, 'show', 'HEAD:' + str(relative))
            assert committed == staged
            if args.textconv:
                assert git(project, 'show', '--textconv', 'HEAD:' + str(relative)) == expected
                assert marker.strip() in git(project, 'show', 'HEAD', '--', str(relative))
                assert marker.strip() in git(project, 'log', '-p', '-1', '--', str(relative))
                assert b'\tpackage com.xtcloud.' in git(project, 'blame', '--textconv', '--line-porcelain', '-L', '1,2', 'HEAD', '--', str(relative))
                assert not git(project, 'for-each-ref', '--format=%(refname)', 'refs/notes/textconv')
                result.update(working_diff_plaintext=True, staged_diff_plaintext=True,
                              history_show_log_blame_plaintext=True, multichunk_unicode_display=True,
                              git_objects_follow_plaintext_policy=True, no_textconv_cache_objects=True)
            remote = args.remote
            if not remote:
                remote = str(work / 'remote.git')
                run('git', 'init', '--bare', '-q', remote)
            branch = 'verification/shit-encryption-' + time.strftime('%Y%m%d-%H%M%S') + '-' + work.name.rsplit('-', 1)[-1]
            git(project, 'push', remote, 'HEAD:refs/heads/' + branch)
            # Independent object database fetches the server's actual branch.
            fetched = work / 'fetched.git'
            run('git', 'init', '--bare', '-q', str(fetched))
            git(fetched, 'fetch', '-q', '--no-tags', remote, 'refs/heads/' + branch)
            assert git(fetched, 'rev-parse', 'FETCH_HEAD').decode().strip() == commit
            received = git(fetched, 'show', 'FETCH_HEAD:' + str(relative))
            assert received == staged == expected
            # A fetched copy retains the policy-visible content.
            raw_copy = project / '.git/received.java'
            raw_copy.write_bytes(received)
            fetched_view = project / 'Received.java'
            # Cross-directory rename preserves the incoming source bytes.
            raw_copy.replace(fetched_view)
            assert fetched_view.read_bytes() == expected
            git(project, 'restore', '--source=HEAD', '--worktree', '--', str(relative))
            assert file.read_bytes() == expected
            assert not git(project, 'status', '--porcelain', '--', str(relative))
            result.update(direct_save_preserves_encryption=True, atomic_save_preserves_plain_source=True,
                          git_stage_matches_trusted_view=True, git_checkout_roundtrip=True,
                          remote_verified=True, remote=remote if args.remote else 'disposable local bare repository',
                          branch=branch, commit=commit, changed_paths=changed,
                          remote_blob_sha256=digest(received), remote_blob_size=len(received),
                          plaintext_size=len(expected), history_contains_plaintext=received == expected,
                          fetched_decrypt_matches=True)
        finally:
            if index_watch is not None:index_watch.close()
            (work / 'stop').touch()
            try:
                process.wait(timeout=20)
            finally:
                subprocess.run(['sudo', '-n', 'rm', '-rf', '--', str(work / 'monitor')], check=True)
    assert (source / '.git/index').read_bytes() == source_index, 'Source index changed'
    assert run('/usr/bin/head', '-c', '100000000', str(source / relative)) == source_disk, 'Source file changed'
    result['source_index_unchanged'] = True
    result['source_file_unchanged'] = True
    if args.output:
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--broker':
        broker(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('repo', type=Path)
        parser.add_argument('path', type=Path, help='Encrypted Java path relative to repository')
        parser.add_argument('--engine', type=Path, default=ROOT / 'state/engine2/ytfs-engine2')
        parser.add_argument('--config-dir', type=Path)
        parser.add_argument('--remote', help='Explicit remote URL; omitted for a local bare test')
        parser.add_argument('--output', type=Path)
        parser.add_argument('--textconv', help='Enable and verify this read-only display command')
        verify(parser.parse_args())
