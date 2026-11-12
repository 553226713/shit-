"""New engine concurrency/cache isolation and kernel-bypass correctness tests."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import mmap
import os
from pathlib import Path
import subprocess
import sys
import time

from harness import ROOT, session, metrics, usage
MAGIC = bytes.fromhex('6e7e5a6d0089da16e3b351ea53aafb8bf665ef5aa662a08765f64e627500675c')


def verify(args):
    raw = args.sample.read_bytes(); assert raw.startswith(MAGIC)
    def populate(project, binary):
        for i in range(16): (project / f'Cipher{i}.java').write_bytes(raw)
        (project / 'Plain.java').write_bytes(b'class Plain {}\n')
        subprocess.run(['cc','-O2','-Wall','-Wextra','-Werror',str(ROOT/'engine2/raw_mmap.c'),
                        '-o',str(binary/'view-probe')],check=True)
    result = {}
    with session('engine2', args.engine, populate) as (work, project, binary, raw_fd, pid):
        def disk(name):
            fd=os.open(name,os.O_RDONLY,dir_fd=raw_fd)
            with os.fdopen(fd,'rb') as stream:return stream.read()
        def raw_mmap(path):
            return subprocess.check_output([str(binary/'view-probe'),str(path)])
        def independently_decode(name):
            saved=work/'cipher-copy';saved.write_bytes(disk(name))
            return subprocess.check_output([sys.executable,str(ROOT/'compat_cli.py'),'textconv',
                                            '--config-dir',str(ROOT/'config'),str(saved)])
        before = metrics(project)
        plain = project/'Plain.java'
        for i in range(200):
            plain.write_bytes(b'plain '+str(i).encode()); assert plain.read_bytes()==b'plain '+str(i).encode()
        after = metrics(project)
        assert after['passthrough_enabled']
        assert after['passthrough_opens']-before['passthrough_opens']==400
        assert after['read_callbacks']==before['read_callbacks']
        assert after['write_callbacks']==before['write_callbacks']
        result['plain_400_opens_no_userspace_data_callbacks']=True
        transition = project/'Transition.java'
        transition.write_bytes(b'ordinary plaintext content ' * 4)
        for _ in range(20):
            assert transition.stat().st_size == 108
        # Change through the raw backing descriptor to bypass FUSE write-side
        # invalidation. The metadata fast path must notice the new signature.
        fd=os.open(transition.name,os.O_WRONLY|os.O_TRUNC,dir_fd=raw_fd)
        with os.fdopen(fd,'wb') as stream:stream.write(raw)
        assert transition.read_bytes()==(project/'Cipher0.java').read_bytes()
        assert raw_mmap(transition)==raw
        assert transition.stat().st_size==len(raw)-1024
        result['metadata_cache_detects_plain_to_cipher_transition']=True
        cipher=project/'Cipher0.java'; original=cipher.read_bytes()
        with cipher.open('r+b',buffering=0) as stream:
            with mmap.mmap(stream.fileno(),0) as decoded:
                assert decoded[:]==original
                assert raw_mmap(cipher)==raw
                decoded[:2]=b'//';decoded.flush()
                expected=b'//'+original[2:]
                stored=raw_mmap(cipher)
                assert stored.startswith(MAGIC) and stored!=expected
                assert independently_decode(cipher.name)==expected
                # Concurrent repeated raw/decrypted lookups must never mix views.
                def alternating(i):
                    return raw_mmap(cipher)==stored if i%2 else cipher.read_bytes()==expected
                with ThreadPoolExecutor(max_workers=8) as pool:
                    assert all(pool.map(alternating,range(160)))
                assert decoded[:]==expected
        result['simultaneous_raw_and_decoded_mmap_isolation']=True
        expected={}
        def transform(i):
            path=project/f'Cipher{i}.java'
            data=(f'// thread {i} 🙂\n'.encode()*2500)+os.urandom(1025+i)
            for turn in range(3):
                path.write_bytes(data)
                assert path.read_bytes()==data
                with path.open('ab') as stream: stream.write(b'// append\n')
                assert path.read_bytes()==data+b'// append\n'
            expected[path.name]=data+b'// append\n'
        with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(transform,range(1,16)))
        for name,data in expected.items():
            assert independently_decode(name)==data
            assert disk(name)[:1024]==raw[:1024]
        result['parallel_301_random_binary_and_unicode_compatible']=True
        sys.path.insert(0,str(ROOT.parent/'linux-client-archive'))
        from probe_cipher import probe
        saved=disk('Cipher3.java'); wanted=expected['Cipher3.java']
        for offset in [1024,1025,1535,1536,2047,2048,2701]:
            part=saved[offset:offset+777]
            assert probe(b'YANGTUFS',part,offset,original_key_setup=True)==wanted[offset-1024:offset-1024+len(part)]
        result['original_windows_dll_random_offsets_compatible']=True
        shared=project/'Cipher1.java';shared.write_bytes(b'')
        def append(i):
            with shared.open('ab',buffering=0) as stream:
                for turn in range(60):stream.write(f'{i:02d}:{turn:03d}\n'.encode())
        with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(append,range(8)))
        lines=shared.read_bytes().splitlines()
        assert len(lines)==480 and len(set(lines))==480
        assert independently_decode(shared.name)==shared.read_bytes()
        result['parallel_append_atomic']=True
        # Converting an encrypted source over a plain destination retains plain.
        (project/'Cipher2.java').replace(plain)
        assert disk(plain.name)==expected['Cipher2.java']
        assert plain.read_bytes()==expected['Cipher2.java']
        result['encrypted_source_over_plain_target_keeps_plain']=True
        # Ordinary filesystem metadata operations remain available.
        folder=project/'folder';folder.mkdir();(folder/'nested').mkdir()
        f=folder/'new.txt';f.write_bytes(b'test');f.chmod(0o640)
        os.setxattr(f,'user.engine2',b'ok');assert os.getxattr(f,'user.engine2')==b'ok'
        os.removexattr(f,'user.engine2')
        alias=folder/'alias.txt';os.link(f,alias);assert alias.stat().st_ino==f.stat().st_ino
        link=folder/'link';link.symlink_to('new.txt');assert link.read_bytes()==b'test'
        renamed=project/'renamed';folder.rename(renamed);assert (renamed/'link').read_bytes()==b'test'
        assert set(p.name for p in renamed.iterdir())=={'nested','new.txt','alias.txt','link'}
        assert os.statvfs(project).f_bsize>0
        result['metadata_links_xattrs_and_directory_rename']=True
        writeonly=project/'write-only.java'
        fd=os.open(writeonly,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o200)
        os.write(fd,b'one');os.write(fd,b'two');os.close(fd)
        writeonly.chmod(0o600);assert disk(writeonly.name)==b'onetwo'
        result['ordinary_write_only_files_keep_native_permissions']=True
        baseline=metrics(project)['live_nodes']
        churn=project/'churn';churn.mkdir()
        for i in range(1000):
            f=churn/f'{i}.java';f.write_bytes(b'plain');f.unlink()
        churn.rmdir()
        for _ in range(50):
            if metrics(project)['live_nodes']<=baseline+16:break
            time.sleep(.02)
        assert metrics(project)['live_nodes']<=baseline+16
        result['1000_create_delete_cycles_release_inode_state']=True
        result['usage']=usage(pid);result['metrics']=metrics(project)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--engine',type=Path,default=ROOT/'state/engine2/ytfs-engine2')
    p.add_argument('--sample',type=Path,default=ROOT/'state/performance-before/Encrypted.java')
    p.add_argument('--output',type=Path,default=ROOT/'state/engine2/concurrency.json')
    verify(p.parse_args())
