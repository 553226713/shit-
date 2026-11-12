"""Audit excluded directories and real SVN/Mercurial round trips in /tmp only.

--tools points at a temporary dpkg-deb extraction of SVN/Mercurial and their
dependencies; no system installation or real repository writes are required.
"""
import argparse
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
from file_scope import DEFAULT_SCOPE
from verify_git_roundtrip import broker, MAGIC


def verify(args):
    import yt_config
    yt_config.SETTINGS_PATH = args.config_dir / 'settings.json'
    yt_config.REMOTE_POLICY_PATH = args.config_dir / 'remote_policy.json'
    effective = yt_config.effective_config(yt_config.load_settings(), yt_config.load_remote_policy())
    # Reproduce broad policies, including Python-interpreted Mercurial.
    effective['trusted_programs'] = ['*']
    env = dict(os.environ, LD_LIBRARY_PATH=str(args.tools / 'usr/lib/x86_64-linux-gnu'),
               PYTHONPATH=str(args.tools / 'usr/lib/python3/dist-packages'),
               HGRCPATH=os.devnull, HGUSER='encryption verification <verification@localhost>')
    svn, svnadmin, hg = [args.tools / 'usr/bin' / n for n in ['svn', 'svnadmin', 'hg']]

    def run(*command, cwd=None):
        return subprocess.run([str(x) for x in command], cwd=cwd, env=env,
                              capture_output=True, check=True, timeout=30).stdout

    raw = run('git', '-C', args.repo, 'show', 'HEAD:' + args.path)
    assert raw.startswith(MAGIC)
    results = {}
    with tempfile.TemporaryDirectory(prefix='shit-scope-vcs-') as temporary:
        work = Path(temporary)
        project = work / 'project'; project.mkdir()
        binary = work / 'bin'; binary.mkdir()
        engine = binary / 'ytfs-engine2'; shutil.copy2(args.engine, engine)
        (binary / 'sgfs.conf').write_text(yt_config.build_sgfs_conf(effective))
        (binary / 'sgfs.conf').chmod(0o600)
        excluded = DEFAULT_SCOPE['excluded_directories']
        for name in excluded:
            p = project / 'nested' / name / 'Encrypted.java'
            p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(raw)
        for name in ['src/Encrypted.java', 'target-source/Encrypted.JAVA', '.idea/settings.java',
                     '.vscode/settings.java', '.gitignore', 'binary.jar']:
            p = project / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(raw)
        (project / 'cache-alias').symlink_to('nested/.cache', target_is_directory=True)
        svn_server = work / 'svn-server'
        run(svnadmin, 'create', svn_server)
        svn_work = project / 'svn-work'
        run(svn, 'checkout', '-q', svn_server.as_uri(), svn_work)
        (svn_work / 'Encrypted.java').write_bytes(raw)
        run(svn, 'add', 'Encrypted.java', cwd=svn_work)
        run(svn, 'commit', '-q', '-m', 'initial ciphertext', cwd=svn_work)
        hg_work = project / 'hg-work'; hg_work.mkdir()
        run(hg, 'init', hg_work)
        (hg_work / 'Encrypted.java').write_bytes(raw)
        run(hg, 'add', 'Encrypted.java', cwd=hg_work)
        run(hg, 'commit', '-m', 'initial ciphertext', cwd=hg_work)
        process = subprocess.Popen(['sudo', '-n', sys.executable, str(Path(__file__).resolve()),
                                    '--broker', str(work), str(engine)])
        try:
            deadline = time.monotonic() + 20
            while not (work / 'ready').exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('Temporary mount failed')
                time.sleep(.05)
            plain = (project / 'src/Encrypted.java').read_bytes()
            assert plain.startswith(b'package com.xtcloud.')
            reader = 'import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())'
            assert run(sys.executable, '-c', reader, project / 'src/Encrypted.java', hg) == plain
            ordinary = work / 'ordinary.py'; ordinary.write_text(reader)
            assert run(sys.executable, ordinary, project / 'src/Encrypted.java', hg) == plain
            results['ordinary_python_with_hg_argument_still_decrypts'] = True
            for name in excluded:
                p = project / 'nested' / name / 'Encrypted.java'
                assert p.read_bytes() == raw and p.stat().st_size == len(raw), name
                p.write_bytes(b'ordinary cache bytes')
                assert p.read_bytes() == b'ordinary cache bytes', name
            results['excluded_directory_read_write'] = excluded
            for name in ['target-source/Encrypted.JAVA', '.idea/settings.java', '.vscode/settings.java', '.gitignore']:
                assert (project / name).read_bytes() == plain, name
            assert (project / 'binary.jar').read_bytes() == raw
            assert (project / 'cache-alias/Encrypted.java').read_bytes() == b'ordinary cache bytes'
            late = project / 'created-after-mount/.svn/Encrypted.java'
            late.parent.mkdir(parents=True); late.write_bytes(raw)
            assert late.read_bytes() == raw
            results['new_directories_symlinks_extensions_and_lookalikes'] = True
            for name, directory in [('svn', svn_work), ('hg', hg_work)]:
                p = directory / 'Encrypted.java'
                assert p.read_bytes() == plain
                expected = plain + ('\n// ' + name + ' encrypted roundtrip\n').encode()
                tmp = p.with_name('.Encrypted.java.tmp'); tmp.write_bytes(expected); tmp.replace(p)
                assert p.read_bytes() == expected
                if name == 'svn':
                    run(svn, 'commit', '-q', '-m', 'modified ciphertext', cwd=directory)
                    received = run(svn, 'cat', svn_server.as_uri() + '/Encrypted.java')
                    run(svn, 'update', '-q', cwd=directory)
                else:
                    run(hg, 'commit', '-m', 'modified ciphertext', cwd=directory)
                    received = run(hg, 'cat', '-r', 'tip', 'Encrypted.java', cwd=directory)
                encrypted = received.startswith(MAGIC) and len(received) == len(expected) + 1024
                results[name + '_committed_ciphertext'] = encrypted
                if encrypted:
                    (project / (name + '-received.java')).write_bytes(received)
                    assert (project / (name + '-received.java')).read_bytes() == expected
                    p.write_bytes(expected + b'// uncommitted\n')
                    if name == 'svn': run(svn, 'revert', 'Encrypted.java', cwd=directory)
                    else: run(hg, 'revert', '--no-backup', 'Encrypted.java', cwd=directory)
                    assert p.read_bytes() == expected
                    results[name + '_restore_decrypt_matches'] = True
                    if name == 'hg':
                        assert run(sys.executable, '-B', hg, 'cat', '-r', 'tip', 'Encrypted.java', cwd=directory) == received
                        script = work / 'hg.py'; shutil.copy2(hg, script)
                        assert run(sys.executable, '-W', 'ignore', script, 'cat', '-r', 'tip', 'Encrypted.java', cwd=directory) == received
                        results['mercurial_interpreter_options_and_hg_py'] = True
        finally:
            (work / 'stop').touch()
            try: process.wait(timeout=20)
            finally: subprocess.run(['sudo', '-n', 'rm', '-rf', '--', str(work / 'monitor')], check=True)
    args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(results, ensure_ascii=False, indent=2))
    if args.require_ciphertext:
        assert results.get('svn_committed_ciphertext') and results.get('hg_committed_ciphertext'), results


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--broker':
        broker(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--tools', type=Path, required=True)
        parser.add_argument('--engine', type=Path, required=True)
        parser.add_argument('--repo', type=Path, required=True)
        parser.add_argument('--path', required=True)
        parser.add_argument('--config-dir', type=Path, required=True)
        parser.add_argument('--output', type=Path, required=True)
        parser.add_argument('--require-ciphertext', action='store_true')
        verify(parser.parse_args())
