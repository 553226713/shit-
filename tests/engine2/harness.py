"""Disposable-mount harness shared by engine correctness and load tests."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'tests'))


def policy():
    from yt_client import yt_config
    yt_config.SETTINGS_PATH = ROOT / 'config/settings.json'
    yt_config.REMOTE_POLICY_PATH = ROOT / 'config/remote_policy.json'
    result = yt_config.effective_config(yt_config.load_settings(), yt_config.load_remote_policy())
    result['encryption']['new_file_mode'] = 'plain'
    result['trusted_programs'] = [f'nonmatching-{i}' for i in range(100)] + [
        '*python*', '*node*', '*cat*', '*bash*', '*git*', '*tee*', '*dd*']
    return yt_config.build_sgfs_conf(result)


@contextmanager
def session(mode, executable, populate):
    with tempfile.TemporaryDirectory(prefix='yt-engine-load-') as temporary:
        work = Path(temporary)
        project = work / 'project'; project.mkdir()
        binary = work / 'bin'; binary.mkdir()
        engine = binary / 'worker'; shutil.copy2(executable, engine)
        (binary / 'sgfs.conf').write_text(policy())
        (binary / 'sgfs.conf').chmod(0o600)
        populate(project, binary)
        raw_fd = os.open(project, os.O_RDONLY | os.O_DIRECTORY)
        process = None
        try:
            if mode != 'native':
                process = subprocess.Popen(['sudo', '-n', sys.executable, str(Path(__file__).resolve()),
                                            '--broker', mode, str(work), str(engine)])
                deadline = time.monotonic() + 20
                while not (work / 'ready').exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('Isolated load mount failed')
                    time.sleep(.03)
                pid = json.loads((work / 'worker.json').read_text())['pid']
            else: pid = os.getpid()
            yield work, project, binary, raw_fd, pid
        finally:
            if process is not None:
                (work / 'stop').touch()
                try: process.wait(timeout=20)
                finally:
                    subprocess.run(['sudo', '-n', 'rm', '-rf', '--', str(work / 'monitor')],check=True)
            os.close(raw_fd)


def metrics(project):
    return json.loads(os.getxattr(project, 'user.ytfs.metrics'))


def usage(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    status = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
    return {'cpu_seconds': (int(fields[11])+int(fields[12])) / os.sysconf('SC_CLK_TCK'),
            'rss_kib': int(status['VmRSS'].split()[0]), 'peak_rss_kib': int(status['VmHWM'].split()[0]),
            'threads': int(status['Threads'])}


if __name__ == '__main__':
    _, _, mode, work, executable = sys.argv
    if mode == 'engine2':
        from testing import broker
    else:
        raise ValueError('Only the new filesystem engine is supported')
    broker(Path(work), Path(executable))
