"""Isolated test broker. Never mounts a configured production directory."""
from contextlib import contextmanager
import os
from pathlib import Path
import pwd
import subprocess
import time



@contextmanager
def mounted(work, executable):
    if os.geteuid() != 0:
        raise RuntimeError('The isolated broker must run through sudo')
    import auto_mount
    auto_mount.STATE = work / 'monitor'
    uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
    item = auto_mount.open_mount(
        work / 'project', uid, gid,
        os.getgrouplist(pwd.getpwuid(uid).pw_name, gid), executable,
        policy_path=executable.parent/'sgfs.conf')
    try:
        yield item.process
    finally:
        auto_mount.close_mount(item)
        import shutil
        for source, name in [(item.backing.parent / 'fuse.log', 'engine2.log'),
                             (item.backing.parent / 'engine2-metrics.json', 'engine2-metrics.json')]:
            if source.exists():
                dest = work / name
                shutil.copy2(source, dest); os.chown(dest, uid, gid)


def broker(work, executable):
    with mounted(work, executable) as process:
        (work / 'worker.json').write_text(__import__('json').dumps({'pid': process.pid}))
        (work / 'ready').touch()
        while not (work / 'stop').exists():
            if process.poll() is not None:
                raise RuntimeError('New FUSE engine exited')
            time.sleep(.05)
