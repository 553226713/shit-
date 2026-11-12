"""Run packaged FUSE tests with /run noexec in a private mount namespace."""
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent


def inside():
    if os.geteuid()!=0:raise RuntimeError('Private test namespace requires sudo')
    uid=int(os.environ['SUDO_UID']);account=pwd.getpwuid(uid)
    subprocess.run(['mount','--bind','/run','/run'],check=True)
    subprocess.run(['mount','-o','remount,bind,noexec,nosuid,nodev','/run'],check=True)
    options=subprocess.check_output(['findmnt','-no','OPTIONS','/run']).decode().strip()
    assert 'noexec' in options.split(',')
    runtime=Path(tempfile.mkdtemp(prefix='yt-package-noexec-',dir='/run'))
    os.chown(runtime,0,account.pw_gid);runtime.chmod(0o750)
    try:
        subprocess.run(['sudo','-n','-u',account.pw_name,'env',
                        'YT_PACKAGE_TEST_RUNTIME='+str(runtime),
                        *(['YT_PACKAGE_TEST_KILL_WORKER=1'] if '--kill-worker' in sys.argv else []),
                        '/usr/bin/python3',
                        str(HERE/'smoke_host.py')],check=True)
        print('PASS: packaged engine executes from installation assets while /run remains noexec',flush=True)
    finally:
        shutil.rmtree(runtime,ignore_errors=True)


if __name__=='__main__':
    if '--inside' in sys.argv:
        inside()
    else:
        subprocess.run(['sudo','-n','unshare','--mount','--propagation','private',
                        '/usr/bin/python3',str(Path(__file__).resolve()),'--inside',
                        *(['--kill-worker'] if '--kill-worker' in sys.argv else [])],check=True)
