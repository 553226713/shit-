"""Bounded exception-only logs. Normal file operations never call this module."""
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import sys
import threading
import time

from runtime_paths import PACKAGED, STATE_DIR, UID

MAX_BYTES = 1024 * 1024
BACKUPS = 3


def log_directory():
    directory = STATE_DIR / 'logs'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if PACKAGED:
        link = directory / 'monitor'
        try:link.symlink_to(Path('/var/log/shit-encryption') / str(UID), target_is_directory=True)
        except FileExistsError:pass
    return directory


def monitor_directory(uid, gid):
    if not PACKAGED:
        return log_directory()
    root = Path('/var/log/shit-encryption')
    root.mkdir(mode=0o755, exist_ok=True)
    directory = root / str(uid)
    directory.mkdir(mode=0o750, exist_ok=True)
    os.chown(directory, 0, gid)
    directory.chmod(0o750)
    return directory


def engine_environment(environment, uid, gid):
    if not PACKAGED:return environment
    path = monitor_directory(uid, gid) / 'engine-errors.log'
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o640)
    try:os.fchown(fd, 0, gid)
    finally:os.close(fd)
    return dict(environment, YT_ENGINE_ERROR_LOG=str(path))


def redact(text):
    text = re.sub(r'(?i)(encryptkey|password|passwd|token|authorization)([\s:=]+)[^\s,;]+',
                  r'\1\2[redacted]', str(text))
    return re.sub(r'(https?://)[^/@\s]+:[^/@\s]+@', r'\1[redacted]@', text)


class ExceptionFormatter(logging.Formatter):
    def format(self, record):
        return redact(super().format(record))[:16384]


class RepeatedErrors(logging.Filter):
    def __init__(self):
        super().__init__()
        self.seen = {}
        self.lock = threading.Lock()

    def filter(self, record):
        if record.levelno < logging.ERROR:return False
        key = (record.msg, redact(record.getMessage())[:1024])
        now = time.monotonic()
        with self.lock:
            previous, count = self.seen.get(key, (-60, 0))
            if now - previous < 60:
                self.seen[key] = (previous, count + 1)
                return False
            if len(self.seen) >= 256:self.seen.clear()
            self.seen[key] = (now, 0)
        if count:
            record.msg = record.getMessage() + f' (suppressed {count} repeats)'
            record.args = ()
        return True


class ErrorFile(RotatingFileHandler):
    def __init__(self, path, gid=None):
        self.gid = gid
        super().__init__(path, maxBytes=MAX_BYTES, backupCount=BACKUPS,
                         encoding='utf-8', delay=True)

    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_APPEND | os.O_CREAT |
                     os.O_CLOEXEC | os.O_NOFOLLOW, 0o640 if self.gid is not None else 0o600)
        if self.gid is not None and os.geteuid() == 0:os.fchown(fd, 0, self.gid)
        return os.fdopen(fd, 'a', encoding='utf-8')


def logger(component, directory=None, gid=None):
    directory = Path(directory) if directory is not None else log_directory()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = logging.getLogger(f'shit-encryption.{component}.{directory}')
    if not result.handlers:
        handler = ErrorFile(directory / f'{component}-errors.log', gid)
        handler.addFilter(RepeatedErrors())
        handler.setFormatter(ExceptionFormatter('%(asctime)s %(levelname)s pid=%(process)d %(message)s'))
        result.addHandler(handler)
        result.setLevel(logging.ERROR)
        result.propagate = False
    return result


def install_exception_hooks(component):
    log = logger(component)
    previous = sys.excepthook
    def uncaught(kind, error, trace):
        if not issubclass(kind, (KeyboardInterrupt, SystemExit)):
            log.error('Unhandled exception', exc_info=(kind, error, trace))
        previous(kind, error, trace)
    sys.excepthook = uncaught
    previous_thread = threading.excepthook
    def thread_error(args):
        if not issubclass(args.exc_type, SystemExit):
            log.error('Background thread exception', exc_info=(args.exc_type, args.exc_value, args.exc_traceback))
        previous_thread(args)
    threading.excepthook = thread_error
