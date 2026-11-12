#!/usr/bin/env python3
"""Build a clean amd64 package; never copy workstation configuration or state."""
import hashlib
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from engine2.build import build
from windows_policy import NATIVE_SHA256
from yt_config import discover_native_client

VERSION = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
OUTPUT = ROOT / 'dist'
MODULES = ['runtime_paths.py', 'yt_control.py', 'yt_config.py', 'system_tray.py',
           'auto_mount.py', 'auto_service.py', 'namespace_view.py', 'broker_control.py',
           'windows_policy.py', 'file_scope.py', 'error_log.py',
           'compat_cli.py']


def write(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')
    path.chmod(mode)


def main():
    if os.uname().machine != 'x86_64':
        raise SystemExit('This native engine requires an amd64 build host.')
    native = discover_native_client() / 'files/bin/svchost'
    if hashlib.sha256(native.read_bytes()).hexdigest() != NATIVE_SHA256:
        raise SystemExit('Native client hash does not match the reviewed version.')
    OUTPUT.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='shit-encryption-deb-') as temporary:
        staging = Path(temporary)
        app = staging / 'usr/lib/shit-encryption'
        app.mkdir(parents=True)
        for name in MODULES:
            shutil.copy2(ROOT / name, app / name)
        shutil.copytree(ROOT / 'assets', app / 'assets')
        (app/'engine2').mkdir()
        shutil.copy2(ROOT/'engine2/artifacts.py',app/'engine2/artifacts.py')
        shutil.copytree(ROOT / 'compat', app / 'compat', ignore=shutil.ignore_patterns('__pycache__'))
        write(app / 'packaged-runtime', VERSION + '\n')
        vendor = app / 'vendor'; vendor.mkdir()
        for name in ['cipher301.bin', 'manifest.json']:
            shutil.copy2(ROOT / 'vendor' / name, vendor / name)
        build(vendor / 'ytfs-engine2')
        (vendor / 'ytfs-engine2').chmod(0o755)
        build(vendor / 'ytfs-textconv', textconv=True)
        (vendor / 'ytfs-textconv').chmod(0o755)
        # Strip debug paths and ship the required FUSE ABI privately, so the
        # package works on Ubuntu 24.04 without replacing its system FUSE.
        for executable in [vendor/'ytfs-engine2',vendor/'ytfs-textconv']:
            subprocess.run(['strip','--strip-unneeded',str(executable)],check=True)
        library = Path('/usr/lib/x86_64-linux-gnu/libfuse3.so.4').resolve()
        (vendor/'lib').mkdir()
        shutil.copy2(library,vendor/'lib/libfuse3.so.4')
        write(staging/'usr/share/doc/shit-encryption/copyright.libfuse',
              Path('/usr/share/doc/libfuse3-4/copyright').read_text())
        manifest = json.loads((vendor / 'manifest.json').read_text())
        manifest.update(engine2_sha256=hashlib.sha256((vendor/'ytfs-engine2').read_bytes()).hexdigest(),
                        textconv_sha256=hashlib.sha256((vendor/'ytfs-textconv').read_bytes()).hexdigest(),
                        libfuse_sha256=hashlib.sha256((vendor/'lib/libfuse3.so.4').read_bytes()).hexdigest())
        (vendor / 'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        subprocess.run(['g++', '-shared', '-fPIC', '-pthread', '-Wall', '-Wextra', '-Werror',
                        str(ROOT / 'windows_policy.cpp'), '-o', str(vendor / 'windows-policy.so')], check=True)
        subprocess.run(['strip','--strip-unneeded',str(vendor/'windows-policy.so')],check=True)
        native_bin = vendor / 'native-client/files/bin'; native_bin.mkdir(parents=True)
        shutil.copy2(native, native_bin / 'svchost')
        (native_bin / 'svchost').chmod(0o755)
        shutil.copy2(native.parent / 'dotimer.sh', native_bin / 'dotimer.sh')
        write(native_bin / 'local.ini', '[ytstatus]\nversion=2025.02.06\n')
        for source, target in [('start-installed.sh', 'start.sh'), ('mount-broker', 'mount-broker')]:
            shutil.copy2(ROOT / 'packaging' / source, app / target)
            (app / target).chmod(0o755)
        write(staging / 'usr/bin/shit-encryption', '#!/bin/sh\nexec /usr/lib/shit-encryption/start.sh "$@"\n', 0o755)
        for name, module in [('shit-encryption-textconv', 'textconv'),
                             ('shit-encryption-git-display', 'git-configure')]:
            write(staging / 'usr/bin' / name,
                  f'#!/bin/sh\nexec /usr/bin/python3 /usr/lib/shit-encryption/compat_cli.py {module} "$@"\n', 0o755)
        desktop = '''[Desktop Entry]
Type=Application
Name=shit加密
Comment=加密目录监控与服务器策略同步
Exec=/usr/bin/shit-encryption
Icon=ytsysconfig
Terminal=false
Categories=System;Security;
StartupNotify=true
StartupWMClass=com.yangtu.ytconfig.control
'''
        write(staging / 'usr/share/applications/com.yangtu.ytconfig.control.desktop', desktop)
        icon = staging / 'usr/share/icons/hicolor/scalable/apps/ytsysconfig.svg'
        icon.parent.mkdir(parents=True)
        shutil.copy2(ROOT / 'assets/hicolor/scalable/apps/ytsysconfig.svg', icon)
        policy = staging / 'usr/share/polkit-1/actions/com.yangtu.ytconfig.mount.policy'
        policy.parent.mkdir(parents=True)
        shutil.copy2(ROOT / 'packaging/com.yangtu.ytconfig.mount.policy', policy)
        write(staging / 'usr/lib/tmpfiles.d/shit-encryption.conf', 'd /run/shit-encryption 0755 root root -\n')
        doc = staging / 'usr/share/doc/shit-encryption/安装说明.txt'
        doc.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / 'packaging/安装说明.txt', doc)
        size = sum(p.stat().st_size for p in staging.rglob('*') if p.is_file()) // 1024
        write(staging / 'DEBIAN/control', f'''Package: shit-encryption
Version: {VERSION}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: shit encryption maintainers <maintainers@localhost>
Installed-Size: {size}
Depends: python3 (>= 3.10), python3-gi, gir1.2-gtk-4.0 (>= 4.10), bubblewrap, pkexec, polkitd, systemd, util-linux, coreutils, libuuid1, zlib1g, libstdc++6 (>= 13), libgcc-s1, libc6 (>= 2.38), adwaita-icon-theme
Suggests: gnome-shell-extension-appindicator
Description: shit加密 - encrypted directory monitor and policy client
 GTK configuration UI, desktop tray, per-user settings and encrypted
 directory monitoring with a bundled native policy client.
''')
        write(staging / 'DEBIAN/postinst', '''#!/bin/sh
set -e
if [ "$1" = configure ]; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/shit-encryption.conf || true
    if command -v update-desktop-database >/dev/null; then update-desktop-database -q || true; fi
    if command -v gtk-update-icon-cache >/dev/null; then gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true; fi
fi
''', 0o755)
        # New preinst also handles upgrades from releases whose user service
        # could not stop root brokers. Removal/upgrade uses the same root check.
        stopper=(ROOT/'packaging/stop_installed.py').read_text()
        for script,condition in [('preinst','[ "$1" = install ] || [ "$1" = upgrade ]'),
                                 ('prerm','[ "$1" = remove ] || [ "$1" = upgrade ]')]:
            write(staging/'DEBIAN'/script,
                  '#!/bin/sh\nset -e\nif '+condition+"; then\n/usr/bin/python3 - <<'STOP'\n"+stopper+"\nSTOP\nfi\n",0o755)
        for path in staging.rglob('*'):
            if path.is_file() and not os.access(path, os.X_OK):
                path.chmod(0o644)
        subprocess.run(['desktop-file-validate', str(staging / 'usr/share/applications/com.yangtu.ytconfig.control.desktop')], check=True)
        package = OUTPUT / f'shit-encryption_{VERSION}_amd64.deb'
        subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(staging), str(package)], check=True)
        shutil.copy2(ROOT / 'packaging/安装说明.txt', OUTPUT / '安装说明.txt')
        write(OUTPUT / 'SHA256SUMS', hashlib.sha256(package.read_bytes()).hexdigest() + '  ' + package.name + '\n')
        print(package)


if __name__ == '__main__':
    main()
