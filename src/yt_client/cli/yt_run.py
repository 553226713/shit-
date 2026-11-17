#!/usr/bin/env python3
"""Launch a client with state-preserving transparent access at original paths.

Examples: PYTHONPATH=src python3 -m yt_client.cli.yt_run cat /absolute/path/File.java
          PYTHONPATH=src python3 -m yt_client.cli.yt_run bash
          PYTHONPATH=src python3 -m yt_client.cli.yt_run zed /absolute/path/project

System directories bypass encryption and are read-only; shared temporary paths
and application caches bypass encryption with their original permissions.
Only this process tree uses the view; no host-wide mount or autostart is added.
Supported ciphertext is detected by its header. Plain and new files stay plain.
"""
import argparse
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


from yt_client import yt_config
from yt_client.runtime_paths import CONFIG_DIR, ENGINE_DIR, PACKAGED, STATE_DIR

STATE = STATE_DIR


def write_session_status(session, state, owner=None, **details):
    payload = dict(state=state, updated_at=yt_config._now(), **details)
    status_path = session / 'status.json'
    yt_config.atomic_write_json(status_path, payload)
    if owner is not None:
        os.chown(status_path, owner[0], owner[1])


def prepare(policy, effective):
    if policy.get('write_mode') != 'preserve_existing_file_state':
        raise ValueError('Only preserve_existing_file_state is implemented')
    if os.uname().machine != 'x86_64':
        raise ValueError('This tested native build supports x86_64 only')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE.chmod(0o700)
    if PACKAGED:
        from engine2.artifacts import installed_engine
        installed_engine(ENGINE_DIR)
    else:
        from engine2.build import build
        build(ENGINE_DIR / 'ytfs-engine2')
    # Generate the native rules from the merged server/local configuration.
    source = yt_config.build_sgfs_conf(effective)
    policy['file_patterns'] = [effective['encryption']['file_pattern']]
    policy['supported_directories'] = effective['directories']
    policy['file_scope'] = effective['file_scope']
    return source


def broker(session):
    from yt_client.monitoring.namespace_view import run_view
    request = json.loads((session / 'request.json').read_text())
    owner = (request['uid'], request['gid'])
    write_session_status(session, 'starting', owner=owner,
                         command=request['command'], cwd=request['cwd'])
    try:
        code = run_view(session, ENGINE_DIR / 'ytfs-engine2', request['policy'],
                        request['uid'], request['gid'], request['groups'], request['home'],
                        request['cwd'], request['command'], request['environment'],
                        policy_path=session/'sgfs.conf')
    except Exception as error:
        write_session_status(session, 'failed', owner=owner, error=str(error))
        raise
    write_session_status(session, 'stopped', owner=owner, exit_code=code)
    return code


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--internal-broker':
        return broker(Path(sys.argv[2]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == '--':
        command = command[1:]
    if not command:
        parser.error('Specify an application or shell')
    if os.environ.get('YT_NATIVE_VIEW_ACTIVE') == '1':
        os.execvp(command[0], command)
    if os.geteuid() == 0:
        parser.error('Launch as your ordinary user; the broker requests privilege separately')
    resolved = shutil.which(command[0])
    if not resolved:
        parser.error(f'Executable not found: {command[0]}')
    command[0] = resolved
    uid, gid = os.getuid(), os.getgid()
    policy = json.loads((CONFIG_DIR / 'global_view_policy.json').read_text())
    settings = yt_config.load_settings()
    remote = yt_config.load_remote_policy()
    if yt_config.should_auto_update(settings):
        try:
            remote = yt_config.update_policy(settings)
        except Exception as error:
            print(f'Policy update failed; using the previous policy: {error}', file=sys.stderr)
        settings = yt_config.load_settings()
    effective = yt_config.write_effective_runtime_config(settings, remote)
    engine_rules = prepare(policy, effective)
    policy['username'] = pwd.getpwuid(uid).pw_name
    # Create reserved cache/config roots before mounting so later application
    # writes cannot accidentally create an unprotected root inside the view.
    for relative in policy['user_passthrough']:
        directory = Path.home() / relative
        if not directory.exists():
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for variable in ['TMPDIR', 'XDG_RUNTIME_DIR', 'XDG_CACHE_HOME',
                     'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME']:
        value = os.environ.get(variable)
        if value and Path(value).is_absolute():
            if not Path(value).exists():
                Path(value).mkdir(mode=0o700, parents=True, exist_ok=True)
            policy['system_passthrough'].append(value)
    if Path(resolved).name == 'zed':
        # A separate foreground instance prevents forwarding file-open requests
        # to a Zed process outside the transparent view.
        profile = STATE / 'zed-data'
        profile.mkdir(mode=0o700, parents=True, exist_ok=True)
        policy['runtime_directories'] = [str(profile)]
        command[1:1] = ['--foreground', '--user-data-dir', str(profile)]
    sessions = STATE / 'sessions'
    sessions.mkdir(exist_ok=True)
    session = Path(tempfile.mkdtemp(prefix='client-', dir=sessions))
    for name in ['root', 'backing']:
        (session / name).mkdir()
    (session / 'fuse.log').touch(mode=0o600)
    request = dict(uid=uid, gid=gid, groups=os.getgroups(), home=str(Path.home()),
                   cwd=os.getcwd(), command=command, policy=policy,
                   environment=dict(os.environ))
    (session / 'request.json').write_text(json.dumps(request, ensure_ascii=False))
    (session / 'request.json').chmod(0o600)
    yt_config.atomic_write(session/'sgfs.conf',engine_rules)
    write_session_status(session, 'preparing', command=command, cwd=os.getcwd())
    argv = ['sudo', '-n', 'unshare', '--mount', '--fork', '--propagation', 'private',
            '/usr/bin/python3', str(Path(__file__).resolve()), '--internal-broker', str(session)]
    return subprocess.run(argv).returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(f'{error}', file=sys.stderr)
        raise SystemExit(1)
