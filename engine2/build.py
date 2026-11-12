"""Build the only filesystem engine, or its separate streaming cipher adapter."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'state/engine2'


def build(target=None, textconv=False):
    name = 'ytfs-textconv' if textconv else 'ytfs-engine2'
    target = Path(target) if target is not None else OUT / name
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest = json.loads((ROOT / 'vendor/manifest.json').read_text())
    OUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = manifest['cipher301']
    capsule = ROOT / 'vendor/cipher301.bin'
    blob = capsule.read_bytes()
    if os.uname().machine != metadata['architecture']:
        raise RuntimeError('The verified 301 arithmetic requires x86_64')
    if hashlib.sha256(blob).hexdigest() != metadata['sha256']:
        raise RuntimeError('Cipher arithmetic does not match its verified hash')
    start, end = metadata['source_start'], metadata['source_end']
    asm = subprocess.check_output(['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
                                   f'--adjust-vma={start}', str(capsule)], text=True)
    if '(%rip)' in asm:
        raise RuntimeError('Cipher capsule references process globals')
    for line in asm.splitlines():
        if re.search(r'\bcall\b', line):
            address = int(re.search(r'call\s+(?:0x)?([0-9a-f]+)', line)[1], 16)
            if not start <= address < end:
                raise RuntimeError('Cipher capsule calls outside its pure region')
    seed = hashlib.sha256(b'YANGTUFS').digest()[:20]
    generated = ('#pragma once\n#include <cstdint>\ninline constexpr unsigned char cipher_blob[]={'
                 + ','.join(map(str, blob)) + '};\ninline constexpr unsigned char cipher_seed[]={'
                 + ','.join(map(str, seed)) + '};\n')
    header = OUT/'cipher_blob.hpp'
    if not header.is_file() or header.read_text()!=generated:
        with tempfile.NamedTemporaryFile(mode='w',dir=OUT,delete=False) as stream:
            stream.write(generated)
        os.replace(stream.name,header)
    command = ['g++', '-std=c++20', '-O3', '-g', '-fno-omit-frame-pointer',
               '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-pthread',
               '-D_FILE_OFFSET_BITS=64', '-I'+str(OUT)]
    if not textconv:
        system = Path('/usr/include/fuse3')
        sdk = system if (system/'fuse_lowlevel.h').is_file() else ROOT/'state/toolchain/fuse3/usr/include/fuse3'
        if not (sdk/'fuse_lowlevel.h').is_file():
            raise RuntimeError('Install libfuse3-dev >=3.18 or extract its SDK into state/toolchain/fuse3')
        command += ['-I'+str(sdk)]
    command += [str(ROOT/'engine2'/('textconv.cpp' if textconv else 'main.cpp'))]
    if not textconv:
        command += ['-Wl,-l:libfuse3.so.4', '-Wl,-rpath,$ORIGIN/lib']
    # Never truncate a helper that another Git process is executing.
    with tempfile.TemporaryDirectory(prefix='.'+name+'-',dir=target.parent) as temporary:
        temporary = Path(temporary)
        compiled = temporary / name
        if not textconv:
            check = temporary / 'policy-test'
            subprocess.run(['g++','-std=c++20','-O2','-Wall','-Wextra','-Werror',
                            str(ROOT/'engine2/policy_test.cpp'),'-o',str(check)],check=True,cwd=ROOT)
            subprocess.run([str(check),str(temporary/'rules.conf')],check=True)
        subprocess.run(command+['-o',str(compiled)], check=True,cwd=ROOT)
        compiled.chmod(0o755)
        os.replace(compiled,target)
    receipt = {'engine_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
               'original_sha256': manifest['linux_component_sha256'],
               'pure_cipher_sha256': metadata['sha256'], 'pure_cipher_range': [start, end],
               'source_sha256': textconv_sources() if textconv else None}
    with tempfile.NamedTemporaryFile(mode='w',dir=OUT,delete=False) as stream:
        stream.write(json.dumps(receipt,indent=2)+'\n')
    os.replace(stream.name,OUT/('textconv-build.json' if textconv else 'build.json'))
    return target


def textconv_sources():
    digest=hashlib.sha256()
    for name in ['engine2/build.py','engine2/cipher.hpp','engine2/textconv.cpp','vendor/cipher301.bin']:
        digest.update((ROOT/name).read_bytes())
    return digest.hexdigest()


def textconv_binary():
    import fcntl
    target=OUT/'ytfs-textconv'
    OUT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (OUT/'textconv.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        try: receipt=json.loads((OUT/'textconv-build.json').read_text())
        except (OSError,ValueError): receipt={}
        valid=(target.is_file() and os.access(target,os.X_OK)
               and receipt.get('source_sha256')==textconv_sources()
               and receipt.get('engine_sha256')==hashlib.sha256(target.read_bytes()).hexdigest())
        if not valid:build(target,textconv=True)
    return target


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--textconv', action='store_true')
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    print(build(args.output, textconv=args.textconv))
