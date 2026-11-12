"""Refresh repository-local patches without blocking mounted file access."""
import os
from pathlib import Path
import subprocess
import sys
import time

from file_scope import DEFAULT_SCOPE
from runtime_paths import ROOT, CONFIG_DIR
from compat.index_watch import IndexWatch, git_directory


def repositories(roots):
    found = []
    excluded = set(DEFAULT_SCOPE['excluded_directories'])
    for root in roots:
        queue = [(Path(root), 0)]
        while queue:
            path, depth = queue.pop()
            try:
                if (path / '.git').exists():
                    found.append(path)
                    continue
                if depth >= 2: continue
                with os.scandir(path) as items:
                    for item in items:
                        if item.name not in excluded and item.is_dir(follow_symlinks=False):
                            queue.append((Path(item.path), depth+1))
            except OSError:
                continue
    return sorted(set(found))


def index_signature(repo):
    try:
        directory = git_directory(repo)
        if directory is None: return None
        st = (directory / 'index').stat()
        return (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)
    except OSError:
        return None


class GitPatches:
    def __init__(self, uid, gid, groups, log):
        self.uid, self.gid, self.groups, self.log = uid, gid, groups, log
        self.known = []
        self.signatures = {}
        self.retry_after = {}
        self.failures = {}
        self.next_discovery = 0
        self.next_validation = 0
        self.next_fallback = 0
        self.watch = IndexWatch()
        self.dirty = set()
        self.active = None

    def tick(self, roots):
        now = time.monotonic()
        changed = False
        if self.active:
            repo, signature, process, started = self.active
            code = process.poll()
            if code is None and now-started > 60:
                process.terminate()
                try: process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
                code = process.returncode
            if code is None: return False
            if code == 0:
                self.signatures[repo] = signature
                self.failures.pop(str(repo), None)
                self.retry_after.pop(repo, None)
            else:
                self.failures[str(repo)] = f'兼容配置失败，退出码 {code}'
                self.log.error('Git compatibility failed: path=%s exit_code=%s', repo, code)
                self.retry_after[repo] = now+60
            self.active = None
            changed = True
        if now >= self.next_discovery:
            previous = set(self.known)
            self.known = repositories(roots)
            self.dirty.update(set(self.known)-previous)
            self.watch.sync(self.known)
            self.next_discovery = now+30
        self.dirty.update(self.watch.changed())
        if now >= self.next_validation:
            self.dirty.update(self.known)
            self.next_validation = now+60
        if now >= self.next_fallback:
            self.dirty.update(set(self.known)-self.watch.by_repo.keys())
            self.next_fallback = now+5
        self.dirty.update(repo for repo, due in self.retry_after.items() if now >= due)
        for repo in self.known:
            if repo not in self.dirty: continue
            signature = index_signature(repo)
            if signature is None or signature == self.signatures.get(repo) or now < self.retry_after.get(repo, 0):
                self.dirty.discard(repo)
                continue
            from namespace_view import as_user
            def low_priority():
                if os.geteuid() == 0: as_user(self.uid, self.gid, self.groups)
                os.nice(10)
            try:
                process = subprocess.Popen(
                    ['/usr/bin/ionice', '-c', '3', sys.executable, str(ROOT / 'compat_cli.py'), 'git-configure', str(repo),
                     '--config-dir', str(CONFIG_DIR)], stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    preexec_fn=low_priority)
            except (OSError, subprocess.SubprocessError) as error:
                self.log.exception('Git compatibility launch failed: path=%s', repo)
                self.failures[str(repo)] = str(error)
                self.retry_after[repo] = now+60
                self.dirty.discard(repo)
                return True
            self.active = (repo, signature, process, now)
            self.dirty.discard(repo)
            break
        return changed

    def status(self):
        return {'git_repositories': len(self.known), 'git_configured': len(self.signatures),
                'git_pending': str(self.active[0]) if self.active else None,
                'errors': dict(self.failures)}

    def close(self):
        self.watch.close()
        if self.active:
            process = self.active[2]
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
            self.active = None
