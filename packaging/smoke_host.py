"""Exercise packaged runtime on disposable, root-owned shared data mounts."""
from contextlib import contextmanager
import json
import mmap
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT.parent / 'dist' / ('shit-encryption_'+(ROOT/'VERSION').read_text().strip()+'_amd64.deb')


def privileged(*args):
    subprocess.run(['sudo','-n',*map(str,args)],check=True)


@contextmanager
def shared_data_mount(project, denied):
    # Access is granted only through a supplementary group when available.
    gid=next((g for g in os.getgroups() if g!=os.getgid()),os.getgid())
    denied.mkdir()
    privileged('chown',f'0:{gid}',project)
    privileged('chmod','2770',project)
    privileged('chown','0:0',denied)
    privileged('chmod','0700',denied)
    mounted=False
    try:
        privileged('mount','--bind',project,project);mounted=True
        assert project.stat().st_uid==0
        yield
    finally:
        if mounted:privileged('umount','--',project)
        privileged('chown',f'{os.getuid()}:{os.getgid()}',project,denied)
        privileged('chmod','0700',project,denied)


def verify():
    with tempfile.TemporaryDirectory(prefix='shit-deb-test-') as tmp:
        base=Path(tmp)
        subprocess.run(['dpkg-deb','-x',str(PACKAGE),str(base/'extract')],check=True)
        app=base/'extract/usr/lib/shit-encryption'
        runtime=Path(os.environ.get('YT_PACKAGE_TEST_RUNTIME',str(base/'monitor')))
        config=base/'config';config.mkdir()
        project=base/'data';project.mkdir()
        denied=base/'no-permission'
        raw=(ROOT/'state/performance-before/Encrypted.java').read_bytes()
        key=raw[213:243].split(b'\0',1)[0].decode()
        encrypted=project/'Encrypted.java';encrypted.write_bytes(raw)
        (config/'settings.json').write_text(json.dumps({
            'encryption':{'key':key},'trusted_programs':['python3','python3.*'],
            'directories':[{'path':str(p),'enabled':True} for p in [project,base/'missing',denied]]}))
        runner=base/'run.py'
        runner.write_text('''import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import runtime_paths as p
p.CONFIG_DIR=Path(sys.argv[2])/"config"
p.STATE_DIR=Path(sys.argv[2])/"state"
p.MONITOR_DIR=Path(sys.argv[3])
from auto_mount import run_broker
raise SystemExit(run_broker())
''')
        raw_fd=os.open(project,os.O_RDONLY|os.O_DIRECTORY)
        def disk():
            fd=os.open('Encrypted.java',os.O_RDONLY,dir_fd=raw_fd)
            with os.fdopen(fd,'rb') as stream:return stream.read()
        try:
            with shared_data_mount(project,denied), (base/'log').open('w') as log:
                process=subprocess.Popen(['sudo','-n','env',f'PKEXEC_UID={os.getuid()}',
                    '/usr/bin/python3','-I','-B',str(runner),str(app),str(base),str(runtime)],
                    stdout=log,stderr=subprocess.STDOUT)
                try:
                    status=runtime/'status.json';deadline=time.monotonic()+20
                    while time.monotonic()<deadline:
                        if process.poll() is not None:raise RuntimeError((base/'log').read_text())
                        if status.exists() and json.loads(status.read_text()).get('state')=='running':break
                        time.sleep(.1)
                    payload=json.loads(status.read_text())
                    assert payload['mounts']==[str(project)],payload
                    assert payload['engine_path']==str(app/'vendor/ytfs-engine2'),payload
                    assert payload['policy_path']==str(runtime/'sgfs.conf'),payload
                    assert not (runtime/'bin').exists()
                    assert str(base/'missing') in payload['skipped'],payload
                    assert '权限' in payload['skipped'][str(denied)],payload
                    file=project/'test.txt';file.write_text('package file access test')
                    assert file.read_text()=='package file access test'
                    file.write_text('updated file');assert file.read_text()=='updated file'
                    expected=subprocess.check_output([str(app/'vendor/ytfs-textconv')],input=raw[1024:])
                    assert encrypted.read_bytes()==expected
                    expected+=b'\n// packaged engine write\n';encrypted.write_bytes(expected)
                    stage=project/'.save.tmp';stage.write_bytes(expected);stage.replace(encrypted)
                    with encrypted.open('r+b') as stream:
                        with mmap.mmap(stream.fileno(),0) as mapped:
                            assert mapped[:]==expected;mapped[:2]=b'//';mapped.flush()
                    expected=b'//'+expected[2:]
                    saved=disk();assert saved[:1024]==raw[:1024]
                    assert subprocess.check_output([str(app/'vendor/ytfs-textconv')],input=saved[1024:])==expected
                    print('PASS: root-owned data mount allowed by supplementary-group access; unreadable/unwritable directory rejected')
                    print('PASS: packaged FUSE: plain/encrypted read/write, atomic save, mmap, original 301 header')
                finally:
                    subprocess.run(['sudo','-n','kill','-TERM',str(process.pid)],check=False)
                    process.wait(timeout=20)
                    privileged('rm','-rf','--',runtime)
                assert file.read_text()=='updated file'
                # The original data-disk bind mount remains after FUSE stops.
                assert any(line.split()[4]==str(project) for line in Path('/proc/self/mountinfo').read_text().splitlines())
                print('PASS: original data mount restored after shutdown; real project directories untouched')
        finally:os.close(raw_fd)


if __name__=='__main__':verify()
