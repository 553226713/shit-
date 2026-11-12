"""Parallel IDE-like scanning benchmark; no writes to user projects or remote."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import statistics
import time

from harness import ROOT, session, metrics, usage


def exercise(mode, executable, args):
    raw=args.sample.read_bytes(); plain=b'class Plain { /* '+b'x'*4000+b' */ }\n'
    def populate(project,binary):
        for repo in range(8):
            root=project/f'project-{repo}'
            for group in range(10):
                folder=root/('node_modules' if group%2 else 'src')/str(group)
                folder.mkdir(parents=True)
                for i in range(args.files//80):
                    (folder/f'File{i}.java').write_bytes(plain)
            for i in range(16): (root/'src'/f'Encrypted{i}.java').write_bytes(raw)
    with session(mode,executable,populate) as (work,project,binary,raw_fd,pid):
        initial=usage(pid)
        def scan(root):
            total=0
            for folder,dirs,files in os.walk(root):
                for name in files: total+=os.stat(os.path.join(folder,name)).st_size
            return total
        def read(root):
            total=0
            for folder,dirs,files in os.walk(root):
                for name in files:
                    with open(os.path.join(folder,name),'rb') as stream:total+=len(stream.read())
            return total
        roots=[project/f'project-{i}' for i in range(8)]
        result={}
        with ThreadPoolExecutor(max_workers=8) as pool:
            for name,operation in [('metadata_first',scan),('read_first',read),('metadata_warm',scan),('read_warm',read)]:
                start=time.perf_counter(); totals=list(pool.map(operation,roots))
                result[name+'_seconds']=time.perf_counter()-start
                if mode!='native':
                    expected=args.files*len(plain)+128*(len(raw)-1024)
                    assert sum(totals)==expected,(name,sum(totals),expected)
            def rewrite(i):
                file=roots[i]/'src'/'Encrypted0.java'
                original=file.read_bytes()
                for turn in range(8):
                    data=original+b'\n// load-test\n'*200
                    file.write_bytes(data);assert file.read_bytes()==data
            if mode!='native':
                start=time.perf_counter();list(pool.map(rewrite,range(8)))
                result['encrypted_parallel_rw_seconds']=time.perf_counter()-start
        final=usage(pid)
        result.update(worker_cpu_seconds=round(final['cpu_seconds']-initial['cpu_seconds'],4),
                      rss_kib=final['rss_kib'],peak_rss_kib=final['peak_rss_kib'],threads=final['threads'])
        if mode=='engine2':result['metrics']=metrics(project)
        return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline',type=Path,default=ROOT/'state/engine2/benchmark-before-removal.json')
    p.add_argument('--new',type=Path,default=ROOT/'state/engine2/ytfs-engine2')
    p.add_argument('--sample',type=Path,default=ROOT/'state/performance-before/Encrypted.java')
    p.add_argument('--files',type=int,default=8000)
    p.add_argument('--repeat',type=int,default=3)
    p.add_argument('--output',type=Path,default=ROOT/'state/engine2/benchmark.json')
    args=p.parse_args();assert args.files>=80 and args.files%80==0 and 1<=args.repeat<=5
    result={'workload':{'projects':8,'plain_files':args.files,'cipher_files':128,'parallel_workers':8},'runs':{}}
    if args.baseline.is_file():
        baseline=json.loads(args.baseline.read_text())
        if baseline.get('workload')!=result['workload']:raise ValueError('Baseline and current workload must match')
        result['runs']['old']=baseline['runs']['old']
        result['baseline_report']=str(args.baseline)
    for repeat in range(args.repeat):
        # Alternate order to avoid systematically favoring a warmer machine.
        modes=[('engine2',args.new)]
        if repeat%2:modes.reverse()
        if repeat==0:modes.insert(0,('native',args.new))
        for mode,executable in modes:
            print(f'{mode}, repeat {repeat+1}',flush=True)
            run=exercise(mode,executable,args);result['runs'].setdefault(mode,[]).append(run)
            print(json.dumps(run),flush=True)
            args.output.write_text(json.dumps(result,indent=2)+'\n')
    result['median']={mode:{key:statistics.median(r[key] for r in runs) for key in runs[0] if key!='metrics'}
                      for mode,runs in result['runs'].items()}
    old,new=result['median'].get('old',{}),result['median']['engine2']
    result['reduction_percent']={key:round((1-new[key]/old[key])*100,1) for key in old if key.endswith('_seconds') and old[key]}
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result['reduction_percent']),flush=True)
