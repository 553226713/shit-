"""Verify a running source service and an explicitly authorized live repository.

Temporarily edits clean samples, uses private Git indexes, restores the samples
in finally, and pushes only a unique verification branch. AI editing pauses at
ready-for-ai.json until ai-done exists, allowing the real editor tool to run.
"""
import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from compat.textconv import MAGIC


def digest(data):return hashlib.sha256(data).hexdigest()


def verify(args):
    repo=args.repo.resolve()
    tag=time.strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:6]
    work=ROOT/'state'/('live-verification-'+tag);work.mkdir(mode=0o700)
    (ROOT/'state/live-verification-current.json').write_text(json.dumps({'work':str(work)}))
    def run(*command,data=None,env=None,cwd=None):
        return subprocess.run([str(x) for x in command],input=data,capture_output=True,
                              check=True,timeout=60,cwd=cwd,
                              env=dict(os.environ,GIT_TERMINAL_PROMPT='0',**(env or {}))).stdout
    def git(*command,env=None,data=None):return run('git','-C',repo,*command,env=env,data=data)
    def raw(path):return run('/usr/bin/head','-c','10000000',path)
    service=json.loads((ROOT/'state/auto/status.json').read_text())
    assert service['state']=='running' and any(repo.is_relative_to(p) for p in map(Path,service['mounts'])),service
    engine=ROOT/'state/engine2/ytfs-engine2'
    assert digest(engine.read_bytes())==digest((ROOT/'state/engine2/ytfs-engine2').read_bytes())
    prefix='xtcloud-onemap-service/src/main/java/com/xtcloud/services/onemap/service/'
    names=[prefix+n for n in ['GeoHermeticService.java','GeoFireHermeticService.java',
                              'GeoWaterBarrierService.java','GeoAirDoorService.java']]+['README.md']
    assert not git('diff','--name-only','HEAD','--',*names),'Samples contain existing modifications'
    baseline_status=git('status','--porcelain','-z')
    baseline_entries=git('ls-files','--stage','-z')
    head=git('rev-parse','HEAD').decode().strip()
    originals={name:raw(repo/name) for name in names}
    for name in names[:-1]:
        assert originals[name].startswith(MAGIC)
        assert int.from_bytes(originals[name][85:89],'little')==301
    assert not originals[names[-1]].startswith(MAGIC)
    for i,name in enumerate(names):
        backup=work/f'original-{i}.bin';backup.write_bytes(originals[name]);backup.chmod(0o600)
    restore_env={'GIT_INDEX_FILE':str(work/'restore.index')}
    stage_env={'GIT_INDEX_FILE':str(work/'stage.index')}
    git('read-tree',head,env=restore_env);git('read-tree',head,env=stage_env)
    expected={name:(repo/name).read_bytes() for name in names}
    assert all(expected[name].startswith(b'package com.xtcloud.') for name in names[:-1])
    last_raw={name:digest(originals[name]) for name in names}
    report={'version':(ROOT/'VERSION').read_text().strip(),'repository':str(repo),
            'service_pid':service['pid'],'engine_sha256':digest(engine.read_bytes()),
            'base_commit':head,'preexisting_modified_files':baseline_status.decode().split('\0')[:-1],
            'actors':{},'samples':{},'restored':False}
    def check(name):
        observed=(repo/name).read_bytes();saved=raw(repo/name)
        assert observed==expected[name],name+' plaintext mismatch'
        encrypted=originals[name].startswith(MAGIC)
        if encrypted:
            assert saved[:1024]==originals[name][:1024] and len(saved)==len(observed)+1024
            sample=work/'saved-cipher.bin';sample.write_bytes(saved)
            decoded=run(sys.executable,ROOT/'compat_cli.py','textconv','--config-dir',ROOT/'config',sample)
            assert decoded==observed
        else:assert saved==observed and not saved.startswith(MAGIC)
        last_raw[name]=digest(saved)
    try:
        # Actual terminal builtin file access and redirection.
        name=names[0];path=repo/name
        got=run('/bin/bash','-c','IFS= read -r -d "" content < "$1"; printf %s "$content"','reader',path)
        assert got==expected[name]
        terminal_marker=f'// terminal live verification {tag}'.encode()
        run('/bin/bash','-c','printf "\\n%s\\n" "$2" >> "$1"','writer',path,terminal_marker.decode())
        expected[name]+=b'\n'+terminal_marker+b'\n';check(name)
        assert run('/usr/bin/cat',path)==expected[name]
        report['actors']['terminal']=['bash builtin read','shell append','cat decrypted read']
        print('PASS terminal read/append and ciphertext preservation',flush=True)

        # Node's real fs APIs, including same-directory atomic replacement.
        name=names[1];path=repo/name
        node=shutil.which('node');assert node
        script=work/'node-io.cjs'
        script.write_text('''const fs=require('fs');
const p=process.argv[2],t=process.argv[3];let b=fs.readFileSync(p);
if(!b.toString().startsWith('package com.xtcloud.'))throw Error('ciphertext exposed');
fs.writeFileSync(p,Buffer.concat([b,Buffer.from('\\n// node direct '+t+'\\n')]));
fs.appendFileSync(p,'// node append '+t+'\\n');
let fd=fs.openSync(p,'r+');let peek=Buffer.alloc(4);fs.readSync(fd,peek,0,4,0);
if(peek.toString()!=='pack')throw Error('descriptor read failed');fs.fsyncSync(fd);fs.closeSync(fd);
b=Buffer.concat([fs.readFileSync(p),Buffer.from('// node atomic '+t+'\\n')]);
const q=p+'.live-'+t+'.tmp';fs.writeFileSync(q,b);fs.renameSync(q,p);
''')
        run(node,script,path,tag)
        expected[name]+=f'\n// node direct {tag}\n// node append {tag}\n// node atomic {tag}\n'.encode();check(name)
        report['actors']['node']=['readFileSync','writeFileSync','appendFileSync','descriptor read','fsyncSync','renameSync']
        print('PASS Node internal fs APIs and ciphertext preservation',flush=True)

        # Real JVM file access, not a Python stand-in.
        name=names[2];path=repo/name
        java=work/'LiveFileIO.java'
        java.write_text('''import java.nio.file.*;import java.nio.channels.*;import java.nio.*;import java.util.*;
public class LiveFileIO {
 static byte[] add(byte[] a,String s){byte[] b=s.getBytes(java.nio.charset.StandardCharsets.UTF_8);byte[] c=Arrays.copyOf(a,a.length+b.length);System.arraycopy(b,0,c,a.length,b.length);return c;}
 public static void main(String[] a)throws Exception{Path p=Path.of(a[0]);String t=a[1];byte[] b=Files.readAllBytes(p);
 if(!new String(b,java.nio.charset.StandardCharsets.UTF_8).startsWith("package com.xtcloud."))throw new Exception("ciphertext exposed");
 Files.write(p,add(b,"\\n// java direct "+t+"\\n"));
 Files.write(p,("// java append "+t+"\\n").getBytes(),StandardOpenOption.APPEND);
 try(FileChannel c=FileChannel.open(p,StandardOpenOption.READ,StandardOpenOption.WRITE)){ByteBuffer q=ByteBuffer.allocate(4);c.read(q,0);if(!Arrays.equals(q.array(),"pack".getBytes()))throw new Exception("descriptor read failed");c.force(true);}
 b=add(Files.readAllBytes(p),"// java atomic "+t+"\\n");Path q=p.resolveSibling(p.getFileName()+".live-"+t+".tmp");
 Files.write(q,b);Files.move(q,p,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
 }}
''')
        run('javac','-d',work,java);run('java','-cp',work,'LiveFileIO',path,tag)
        expected[name]+=f'\n// java direct {tag}\n// java append {tag}\n// java atomic {tag}\n'.encode();check(name)
        report['actors']['java']=['Files.readAllBytes','Files.write','APPEND','FileChannel.read','force','atomic Files.move']
        print('PASS Java NIO internal read/write/atomic save',flush=True)

        name=names[3];path=repo/name
        before=expected[name]
        path.write_bytes(before+f'\n// python write {tag}\n'.encode())
        with path.open('ab') as stream:stream.write(f'// python append {tag}\n'.encode())
        staged=path.with_name(path.name+'.live-'+tag+'.tmp')
        value=path.read_bytes()+f'// python atomic {tag}\n// mmap before {tag}\n'.encode()
        staged.write_bytes(value);staged.replace(path)
        with path.open('r+b') as stream:
            with mmap.mmap(stream.fileno(),0) as mapping:
                assert mapping[:]==value
                at=value.index(b'// mmap before');mapping[at:at+14]=b'// mmap after ';mapping.flush()
        expected[name]=value.replace(b'// mmap before',b'// mmap after ',1);check(name)
        report['actors']['python']=['pathlib read/write','append','atomic replace','mmap read/write/flush']
        name=names[4];expected[name]+=f'\n<!-- plaintext live verification {tag} -->\n'.encode()
        (repo/name).write_bytes(expected[name]);check(name)
        print('PASS Python mmap and plaintext README stays plaintext',flush=True)

        ai_marker=f'// AI tool live verification {tag}'
        ready={'work':str(work),'path':str(repo/names[0]),'anchor':terminal_marker.decode(),'ai_marker':ai_marker}
        (work/'ready-for-ai.json').write_text(json.dumps(ready,ensure_ascii=False,indent=2))
        print('READY_FOR_AI_PATCH '+json.dumps(ready,ensure_ascii=False),flush=True)
        deadline=time.monotonic()+240
        while not (work/'ai-done').exists():
            if time.monotonic()>deadline:raise TimeoutError('AI editor verification timed out')
            time.sleep(.2)
        name=names[0];observed=(repo/name).read_bytes()
        assert observed.decode().splitlines()==expected[name].decode().splitlines()+[ai_marker]
        expected[name]=observed;check(name)
        report['actors']['ai_tool']=['actual Codex apply_patch edit','decrypted input','ciphertext output verified']

        # Verify readable diffs/history before committing exact raw bytes.
        diff=git('diff','--',*names)
        assert ai_marker.encode() in diff and b'node direct' in diff and b'java direct' in diff
        git('add','--',*names,env=stage_env)
        for name in names:
            blob=git('show',':'+name,env=stage_env)
            assert blob==raw(repo/name)
            assert blob.startswith(MAGIC)==originals[name].startswith(MAGIC)
        tree=git('write-tree',env=stage_env).decode().strip()
        commit=git('-c','user.name=shit-encryption verification','-c','user.email=verification@localhost',
                   'commit-tree',tree,'-p',head,data=b'test: live service IO and original encryption state\n').decode().strip()
        changed=git('diff-tree','--no-commit-id','--name-only','-r',commit).decode().splitlines()
        assert sorted(changed)==sorted(names)
        assert ai_marker.encode() in git('show',commit,'--',names[0])
        assert git('show','--textconv',commit+':'+names[0])==expected[names[0]]
        assert b'\tpackage com.xtcloud.' in git('blame','--textconv','--line-porcelain','-L','1,2',commit,'--',names[0])
        assert not git('for-each-ref','--format=%(refname)','refs/notes/textconv')
        branch='verification/live-encryption-'+tag
        print('Pushing verified ciphertext/plaintext blobs to '+branch,flush=True)
        git('push',args.remote,commit+':refs/heads/'+branch)
        fetched=work/'fetched.git';run('git','init','--bare','-q',fetched)
        run('git','-C',fetched,'fetch','-q','--no-tags',args.remote,'refs/heads/'+branch)
        assert run('git','-C',fetched,'rev-parse','FETCH_HEAD').decode().strip()==commit
        sys.path.insert(0,str(ROOT.parent/'linux-client-archive'))
        from probe_cipher import probe
        for name in names:
            received=run('git','-C',fetched,'show','FETCH_HEAD:'+name)
            staged_blob=git('show',commit+':'+name)
            assert received==staged_blob
            encrypted=originals[name].startswith(MAGIC)
            assert received.startswith(MAGIC)==encrypted
            if encrypted:
                assert received[:1024]==originals[name][:1024]
                decoded=b''.join(probe(b'YANGTUFS',received[i:i+65536],i,original_key_setup=True)
                                 for i in range(1024,len(received),65536))
                assert decoded==expected[name]
            else:assert received==expected[name]
            report['samples'][name]={'encrypted_before':encrypted,'encrypted_on_server':encrypted,
                'cipher_header_unchanged':encrypted,'server_blob_matches_local':True,
                'independent_windows_decrypt_matches':encrypted,'server_sha256':digest(received),
                'plaintext_sha256':digest(expected[name]),'server_size':len(received)}
        report.update(branch=branch,commit=commit,remote=args.remote,server_verified=True,
                      diff_show_blame_plaintext=True,no_plaintext_textconv_cache=True)
        print('PASS independent server fetch and original-format decryption',flush=True)
    finally:
        restoration_errors=[]
        for name in names:
            try:
                current=raw(repo/name)
                # All modifications in this test contain its unique marker.
                # Do not overwrite a concurrent edit that differs from the last
                # fully verified disk snapshot.
                if digest(current) not in (last_raw[name],digest(originals[name])):
                    raise RuntimeError('Concurrent or unverified edit; original saved in '+str(work))
                git('checkout-index','--force','--',name,env=restore_env)
                assert raw(repo/name)==originals[name]
            except Exception as error:restoration_errors.append(name+': '+str(error))
        report['restoration_errors']=restoration_errors
        report['restored']=not restoration_errors
        report['original_staged_entries_unchanged']=git('ls-files','--stage','-z')==baseline_entries
        report['original_worktree_changes_preserved']=git('status','--porcelain','-z')==baseline_status
        (work/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        (ROOT/'state/live-server-verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        print('REPORT '+str(work/'report.json'),flush=True)
        if restoration_errors:raise RuntimeError('\n'.join(restoration_errors))
    assert report['restored'] and report['original_staged_entries_unchanged']
    print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo',type=Path,required=True);p.add_argument('--remote',required=True)
    p.add_argument('--edit-live-worktree',action='store_true',required=True)
    verify(p.parse_args())
