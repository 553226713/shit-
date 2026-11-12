"""Isolated encrypted-file scale test with a process-local descriptor limit."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time

from harness import ROOT, policy, metrics, usage


def broker(work,engine,limit):
    resource.setrlimit(resource.RLIMIT_NOFILE,(limit,limit))
    from engine2.testing import broker as run
    run(work,engine)


def verify(args):
    raw=args.sample.read_bytes()
    with tempfile.TemporaryDirectory(prefix='yt-scale-') as temporary:
        work=Path(temporary);project=work/'project';project.mkdir();binary=work/'bin';binary.mkdir()
        import shutil
        engine=binary/'worker';shutil.copy2(args.engine,engine)
        (binary/'sgfs.conf').write_text(policy())
        files=[]
        for i in range(args.files):
            folder=project/f'{i//100:04d}';folder.mkdir(exist_ok=True)
            path=folder/f'Encrypted{i}.java';path.write_bytes(raw);files.append(path)
        held=project/'Held.java';held.write_bytes(raw)
        alias=project/'HeldAlias.java';os.link(held,alias)
        process=subprocess.Popen(['sudo','-n',sys.executable,str(Path(__file__).resolve()),
                                  '--broker',str(work),str(engine),str(args.limit)])
        try:
            deadline=time.monotonic()+15
            while not (work/'ready').exists():
                if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Scale mount failed')
                time.sleep(.05)
            pid=json.loads((work/'worker.json').read_text())['pid']
            expected=files[0].read_bytes();assert len(expected)==len(raw)-1024
            pinned=held.open('r+b',buffering=0)
            held.unlink()
            errors={}
            def read(path):
                try:
                    assert path.read_bytes()==expected
                    return True
                except OSError as error:
                    return error.errno
            start=time.monotonic()
            with ThreadPoolExecutor(max_workers=8) as pool:
                for result in pool.map(read,files):
                    if result is not True:errors[str(result)]=errors.get(str(result),0)+1
            report={'files':args.files,'worker_fd_limit':args.limit,'errors':errors,
                    'seconds':time.monotonic()-start,'usage':usage(pid),'metrics':metrics(project)}
            if not args.expect_exhaustion:assert not errors,report
            else:assert errors,report
            if not args.expect_exhaustion:
                with ThreadPoolExecutor(max_workers=8) as pool:
                    assert all(result is True for result in pool.map(read,reversed(files)))
                pinned.seek(0);assert pinned.read()==expected
                pinned.seek(0);pinned.write(b'//');pinned.seek(0)
                assert pinned.read()==b'//'+expected[2:]
                pinned.close()
                assert alias.read_bytes()==b'//'+expected[2:]
                assert subprocess.check_output(['head','-c','32',str(alias)])==raw[:32]
                report['open_unlinked_inode_survives_cache_eviction']=True
                report['second_scan']=metrics(project)
                assert report['second_scan']['fd_reopens']>0
                assert report['second_scan']['cached_node_fds']<=report['second_scan']['fd_cache_budget']+32
            if not pinned.closed:pinned.close()
            args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
        finally:
            (work/'stop').touch()
            try:process.wait(timeout=20)
            finally:subprocess.run(['sudo','-n','rm','-rf','--',str(work/'monitor')],check=True)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--broker':broker(Path(sys.argv[2]),Path(sys.argv[3]),int(sys.argv[4]))
    else:
        p=argparse.ArgumentParser(description=__doc__)
        p.add_argument('--engine',type=Path,default=ROOT/'state/engine2/ytfs-engine2')
        p.add_argument('--sample',type=Path,default=ROOT/'state/performance-before/Encrypted.java')
        p.add_argument('--files',type=int,default=12000);p.add_argument('--limit',type=int,default=512)
        p.add_argument('--expect-exhaustion',action='store_true')
        p.add_argument('--output',type=Path,default=ROOT/'state/engine2/scale.json')
        verify(p.parse_args())
