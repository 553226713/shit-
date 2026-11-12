"""Watch Git metadata directories, including atomically replaced index files."""
import ctypes
import errno
import os
from pathlib import Path
import struct

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
MASK = 0x4 | 0x8 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800
OVERFLOW = 0x4000
IGNORED = 0x8000


def git_directory(repo):
    directory = repo / '.git'
    if directory.is_file():
        content = directory.read_text().strip()
        if not content.startswith('gitdir: '): return None
        directory = repo / content[len('gitdir: '):]
    return directory


class IndexWatch:
    def __init__(self):
        self.fd = LIBC.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        self.by_repo = {}
        self.by_watch = {}

    def sync(self, repos):
        repos = set(repos)
        for repo in list(self.by_repo):
            if repo not in repos:
                watch = self.by_repo.pop(repo)
                self.by_watch.pop(watch, None)
                LIBC.inotify_rm_watch(self.fd, watch)
        if self.fd < 0: return
        for repo in repos - self.by_repo.keys():
            try:
                directory = git_directory(repo)
                if directory is None: continue
                watch = LIBC.inotify_add_watch(self.fd, os.fsencode(directory), MASK)
                if watch >= 0:
                    self.by_repo[repo] = watch
                    self.by_watch[watch] = repo
            except OSError:
                continue

    def changed(self):
        dirty = set()
        if self.fd < 0: return dirty
        while True:
            try: data = os.read(self.fd, 65536)
            except BlockingIOError: break
            except OSError as error:
                if error.errno == errno.EINTR: continue
                raise
            if not data: break
            at = 0
            while at + 16 <= len(data):
                watch, mask, _, length = struct.unpack_from('iIII', data, at)
                name = data[at+16:at+16+length].split(b'\0', 1)[0]
                at += 16+length
                if mask & OVERFLOW: dirty.update(self.by_repo)
                repo = self.by_watch.get(watch)
                if repo is None: continue
                if name == b'index' or mask & (IGNORED | 0x400 | 0x800): dirty.add(repo)
                if mask & IGNORED:
                    self.by_watch.pop(watch, None)
                    self.by_repo.pop(repo, None)
        return dirty

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        self.by_repo.clear(); self.by_watch.clear()
