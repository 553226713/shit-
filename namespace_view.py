"""Run an ordinary user process in a private native Yangtu filesystem view."""
import ctypes
import datetime
import json
import os
import signal
import subprocess
import time
import error_log
from pathlib import Path
from file_scope import scope_environment

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_void_p]
LIBC.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]


def mount(source, target, flags, kind=None, options=None):
    data = ctypes.create_string_buffer(options.encode()) if options else None
    rc = LIBC.mount(os.fsencode(source) if source else None, os.fsencode(target),
                    os.fsencode(kind) if kind else None, flags, data)
    if rc:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(target))


def as_user(uid, gid, groups):
    os.setgroups(groups)
    os.setgid(gid)
    os.setuid(uid)
    # Stop the helper if its controlling broker disappears unexpectedly.
    LIBC.prctl(1, signal.SIGTERM, 0, 0, 0)


def mount_view_root(session, policy, home, cwd):
    """Build a session root that only exposes configured project paths."""
    view = session / 'root'
    root = session / 'chroot'
    root.mkdir(mode=0o700, exist_ok=True)
    # The application executes after dropping privileges and must traverse
    # the reduced root. The private session directory remains mode 700.
    root.chmod(0o755)
    mounts = []
    for path in policy['system_read_only']:
        if Path(path).exists():
            mounts.append((path, True))
    for path in policy['system_passthrough']:
        if Path(path).exists():
            mounts.append((path, False))
    for relative in policy['user_passthrough']:
        path = Path(home) / relative
        if path.exists():
            mounts.append((str(path), False))
    seen = {path for path, _read_only in mounts}
    if cwd and cwd not in seen and Path(cwd).exists():
        mounts.append((cwd, False))
        seen.add(cwd)
    for item in policy.get('supported_directories', []):
        path = item.get('path') if isinstance(item, dict) else item
        enabled = item.get('enabled', True) if isinstance(item, dict) else True
        if enabled and path and path not in seen and Path(path).exists():
            mounts.append((str(path), False))
            seen.add(path)
    for path in policy.get('runtime_directories', []):
        if path and path not in seen and Path(path).exists():
            mounts.append((str(path), False))
            seen.add(path)
    for path, _read_only in mounts:
        target = root / str(Path(path)).lstrip('/')
        target.mkdir(mode=0o755, parents=True, exist_ok=True)
    # Preserve the standard merged-/usr aliases inside the reduced root.
    for name in ['bin', 'sbin', 'lib', 'lib64']:
        source = Path('/') / name
        target = root / name
        if source.is_symlink() and not target.exists() and not target.is_symlink():
            target.symlink_to(os.readlink(source))
    for path, _read_only in mounts:
        relative = str(Path(path)).lstrip('/')
        mount(str(view) + str(Path(path)), str(root / relative), 4096 | 16384)
    return root


def run_view(session, executable, policy, uid, gid, groups, home, cwd, command,
             environment=None, policy_path=None):
    """Caller must already be root in a private mount namespace."""
    if os.geteuid() != 0 or uid == 0:
        raise ValueError('Broker requires privilege; application must use a non-root uid')
    if Path('/proc/self/ns/mnt').readlink() == Path('/proc/1/ns/mnt').readlink():
        raise ValueError('Refusing to operate in the host mount namespace')
    if policy_path is None:
        raise ValueError('Engine policy path must be provided separately from its executable')
    backing, view = session / 'backing', session / 'root'
    mount('/', backing, 4096 | 16384)
    fd = os.open('/dev/fuse', os.O_RDWR)
    fuse = application = None
    log = (session / 'fuse.log').open('a')
    protected = []
    try:
        mount('sgfs', view, 2 | 4, 'fuse',
              f'fd={fd},rootmode=40000,user_id={uid},group_id={gid},default_permissions,allow_other')
        def engine_credentials():
            os.setgroups(groups)
            LIBC.prctl(1, signal.SIGTERM, 0, 0, 0)
        fuse = subprocess.Popen(
            [str(executable), str(backing), str(policy_path),
             str(fd), str(session / 'engine2-metrics.json')],
            cwd=backing, pass_fds=(fd,), stdout=log, stderr=subprocess.STDOUT,
            env=error_log.engine_environment(scope_environment(policy.get('file_scope')), uid, gid),
            preexec_fn=engine_credentials)
        os.close(fd)
        fd = None
        for _ in range(100):
            if fuse.poll() is not None:
                raise RuntimeError('Native FUSE exited; inspect the private session log')
            if subprocess.run(['stat', '-c', '%F', str(view)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(.05)
        else:
            raise RuntimeError('Native FUSE initialization timed out')

        def passthrough(path, read_only):
            source = Path(path)
            if not source.exists():
                return
            source = source.resolve()
            destination = str(view) + str(source)
            mount(source, destination, 4096 | 16384)
            if read_only:
                # Recursively protect submounts too (mount_setattr, Linux >=5.12).
                class Attributes(ctypes.Structure):
                    _fields_ = [('set', ctypes.c_uint64), ('clear', ctypes.c_uint64),
                                ('propagation', ctypes.c_uint64), ('userns', ctypes.c_uint64)]
                attributes = Attributes(1, 0, 0, 0)
                rc = LIBC.syscall(ctypes.c_long(442), ctypes.c_int(-100),
                                  ctypes.c_char_p(os.fsencode(destination)),
                                  ctypes.c_uint(0x8000), ctypes.byref(attributes),
                                  ctypes.c_size_t(ctypes.sizeof(attributes)))
                if rc:
                    error = ctypes.get_errno()
                    raise OSError(error, os.strerror(error), destination)
            protected.append(dict(path=str(source), read_only=read_only))

        for path in policy['system_read_only']:
            passthrough(path, True)
        for path in policy['system_passthrough']:
            passthrough(path, False)
        for path in policy['user_passthrough']:
            passthrough(Path(home) / path, False)
        session_root = mount_view_root(session, policy, home, cwd)
        report = session / 'protection.json'
        report.write_text(json.dumps(protected, ensure_ascii=False, indent=2))
        report.chmod(0o600)
        os.chown(report, uid, gid)

        def enter():
            os.chroot(session_root)
            os.chdir(cwd)
            as_user(uid, gid, groups)

        env = dict(environment if environment is not None else os.environ,
                   HOME=home, USER=policy['username'],
                   LOGNAME=policy['username'], YT_NATIVE_VIEW_ACTIVE='1')
        application = subprocess.Popen(command, preexec_fn=enter, env=env)
        status = session / 'status.json'
        status.write_text(json.dumps(dict(
            state='running',
            updated_at=datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
            application_pid=application.pid),
            ensure_ascii=False))
        status.chmod(0o600)
        os.chown(status, uid, gid)
        return application.wait()
    finally:
        if application is not None and application.poll() is None:
            application.terminate()
            try:
                application.wait(timeout=5)
            except subprocess.TimeoutExpired:
                application.kill()
                application.wait()
        LIBC.umount2(os.fsencode(view), 2)
        if fuse is not None and fuse.poll() is None:
            fuse.terminate()
            try:
                fuse.wait(timeout=3)
            except subprocess.TimeoutExpired:
                fuse.kill()
                fuse.wait()
        if fd is not None:
            os.close(fd)
        log.close()
