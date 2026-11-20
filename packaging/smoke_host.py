"""Exercise packaged runtime on disposable, root-owned shared data mounts."""
from contextlib import contextmanager
import errno
import json
import mmap
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'dist' / ('shit-encryption_'+(ROOT/'VERSION').read_text().strip()+'_amd64.deb')


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
        key='package-smoke-identity'
        header=bytearray(1024)
        header[:32]=bytes.fromhex('6e7e5a6d0089da16e3b351ea53aafb8bf665ef5aa662a08765f64e627500675c')
        header[85:89]=bytes([45,1,0,0])
        header[213:214+len(key)]=key.encode()+b'\0'
        header[1019:]=b'[END]'
        raw=bytes(header)
        encrypted=project/'Encrypted.java';encrypted.write_bytes(raw)
        excluded=project/'node_modules';excluded.mkdir()
        (excluded/'Existing.java').write_bytes(raw)
        (config/'settings.json').write_text(json.dumps({
            'encryption':{'key':key,'new_file_mode':'encrypted'},
            'trusted_programs':['python3','python3.*'],
            'monitored_extensions':['.java'],
            'directories':[{'path':str(p),'enabled':True} for p in [project,base/'missing',denied]]}))
        runner=base/'run.py'
        runner.write_text('''import sys
from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[1])/"src"))
from yt_client import runtime_paths as p
p.CONFIG_DIR=Path(sys.argv[2])/"config"
p.STATE_DIR=Path(sys.argv[2])/"state"
p.MONITOR_DIR=Path(sys.argv[3])
from yt_client.monitoring import mount_authorization
authorization_state = "terminal-authorization-state" if '--sudo-authorization' in sys.argv else "authorization-state"
mount_authorization.DIRECTORY=Path(sys.argv[2])/authorization_state/"authorized-users"
if '--stop-broker' in sys.argv:
    from yt_client.monitoring.broker_control import request_stop
    request_stop(p.MONITOR_DIR)
elif '--authorize-only' in sys.argv:
    from yt_client.monitoring.auto_mount import packaged_broker_main
    sys.argv[:] = [sys.argv[0], '--authorize-only']
    raise SystemExit(packaged_broker_main())
else:
    from yt_client.monitoring.auto_mount import run_broker
    raise SystemExit(run_broker())
''')
        raw_fd=os.open(project,os.O_RDONLY|os.O_DIRECTORY)
        def disk(name='Encrypted.java'):
            fd=os.open(name,os.O_RDONLY,dir_fd=raw_fd)
            with os.fdopen(fd,'rb') as stream:return stream.read()
        try:
            privileged('env', f'PKEXEC_UID={os.getuid()}', '/usr/bin/python3', '-I', '-B',
                       runner, app, base, runtime, '--authorize-only')
            marker=base/'authorization-state/authorized-users'/str(os.getuid())
            assert marker.is_file() and marker.stat().st_uid==0
            privileged('env', '-u', 'PKEXEC_UID', '/usr/bin/python3', '-I', '-B',
                       runner, app, base, runtime, '--authorize-only', '--sudo-authorization')
            terminal_marker=base/'terminal-authorization-state/authorized-users'/str(os.getuid())
            assert terminal_marker.is_file() and terminal_marker.stat().st_uid==0
            assert not (runtime/'status.json').exists()
            print('PASS: the packaged authorization helper records the calling account for pkexec and sudo without mounting')
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
                    assert set(payload['mounts'])=={str(project),str(denied)},payload
                    assert payload['engine_path']==str(app/'vendor/ytfs-engine2'),payload
                    assert payload['policy_path']==str(runtime/'sgfs.conf'),payload
                    assert not (runtime/'bin').exists()
                    assert str(base/'missing') in payload['skipped'],payload
                    try:list(denied.iterdir())
                    except PermissionError:pass
                    else:raise AssertionError('system permissions were bypassed')
                    file=project/'test.txt';file.write_text('package file access test')
                    assert file.read_text()=='package file access test'
                    file.write_text('updated file');assert file.read_text()=='updated file'
                    assert disk('test.txt')==b'updated file'
                    assert (excluded/'Existing.java').read_bytes()==raw
                    (excluded/'New.java').write_bytes(b'data')
                    assert disk('node_modules/New.java')==b'data'
                    (project/'New.java').write_bytes(b'data')
                    assert disk('New.java').startswith(raw[:32])
                    print('PASS: packaged directory exclusions take priority over the file type allowlist')
                    try:
                        (project/'Duplicate.java').write_bytes((excluded/'Existing.java').read_bytes())
                    except OSError as error:
                        assert error.errno == errno.EBADMSG, error
                        assert len(disk('Duplicate.java')) == 1024
                    else:
                        raise AssertionError('Packaged engine accepted a second encryption layer')
                    print('PASS: packaged engine rejects a second encryption layer')
                    expected=subprocess.check_output([str(app/'vendor/ytfs-textconv')],input=raw[1024:])
                    assert encrypted.read_bytes()==expected
                    expected+=b'\n// packaged engine write\n';encrypted.write_bytes(expected)
                    direct=disk();assert direct[:1024]==raw[:1024]
                    assert subprocess.check_output([str(app/'vendor/ytfs-textconv')],input=direct[1024:])==expected
                    stage=project/'.save.tmp';stage.write_bytes(expected);stage.replace(encrypted)
                    with encrypted.open('r+b') as stream:
                        with mmap.mmap(stream.fileno(),0) as mapped:
                            assert mapped[:]==expected;mapped[:2]=b'//';mapped.flush()
                    expected=b'//'+expected[2:]
                    saved=disk();assert saved[:1024]==raw[:1024]
                    assert subprocess.check_output([str(app/'vendor/ytfs-textconv')],input=saved[1024:])==expected
                    print('PASS: root-owned data mount allowed by supplementary-group access; inaccessible directory retains system permissions')
                    print('PASS: packaged FUSE: plain/encrypted read/write, native atomic replacement, mmap, original 301 header for direct writes')
                    if os.environ.get('YT_PACKAGE_TEST_KILL_WORKER')=='1':
                        selector="from pathlib import Path;import sys;pid=sys.argv[1];children=Path('/proc/'+pid+'/task/'+pid+'/children').read_text().split();print(next(p for p in children if b'ytfs-engine2' in Path('/proc/'+p+'/cmdline').read_bytes()))"
                        child=subprocess.check_output(['sudo','-n','/usr/bin/python3','-c',selector,str(payload['pid'])]).decode().strip()
                        privileged('kill','-KILL',child)
                        deadline=time.monotonic()+5
                        while time.monotonic()<deadline:
                            failed=json.loads(status.read_text())
                            if str(project) in failed.get('worker_failures',{}):break
                            time.sleep(.05)
                        assert failed['worker_failures'][str(project)]['exit_code']==-9,failed
                        assert file.read_text()=='updated file' and disk()==saved
                        print('PASS: forced worker exit recorded signal 9; original directory and ciphertext recovered')

                finally:
                    if process.poll() is None:
                        subprocess.run(['/usr/bin/python3','-I','-B',str(runner),str(app),str(base),str(runtime),'--stop-broker'],check=True,timeout=20)
                    process.wait(timeout=20)
                    assert json.loads(status.read_text())['state']=='stopped'
                    privileged('rm','-rf','--',runtime)
                assert file.read_text()=='updated file'
                # The original data-disk bind mount remains after FUSE stops.
                assert any(line.split()[4]==str(project) for line in Path('/proc/self/mountinfo').read_text().splitlines())
                print('PASS: original data mount restored after shutdown; real project directories untouched')
        finally:
            os.close(raw_fd)
            privileged('rm','-rf','--',base/'authorization-state')
            privileged('rm','-rf','--',base/'terminal-authorization-state')


if __name__=='__main__':verify()
