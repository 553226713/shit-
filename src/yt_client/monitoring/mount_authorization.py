"""Remember administrator-approved mount accounts in root-owned system state."""
import os
from pathlib import Path
import pwd
import stat
import sys

DIRECTORY = Path('/var/lib/shit-encryption/authorized-users')


def authorized(uid: int) -> bool:
    if uid <= 0:
        return False
    try:
        for path in (DIRECTORY.parent, DIRECTORY, DIRECTORY / str(uid)):
            info = path.lstat()
            if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
                return False
            if path != DIRECTORY / str(uid) and not stat.S_ISDIR(info.st_mode):
                return False
        return stat.S_ISREG(info.st_mode)
    except OSError:
        return False


def _secure_directory(path: Path) -> None:
    path.mkdir(mode=0o755, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if os.fstat(fd).st_uid != 0:
            raise PermissionError(f'Authorization directory is not root-owned: {path}')
        # Older installations created the parent with the caller's umask.
        os.fchmod(fd, 0o755)
    finally:
        os.close(fd)


def remember(uid: int) -> None:
    if os.geteuid() != 0 or uid <= 0:
        raise PermissionError('Only the authorized root broker may remember an account')
    _secure_directory(DIRECTORY.parent)
    _secure_directory(DIRECTORY)
    marker = DIRECTORY / str(uid)
    # A prior record is reusable, but never follow links or truncate its data.
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    except FileExistsError:
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PermissionError(f'Unsafe authorization record: {marker}')
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)


def main() -> int:
    if len(sys.argv) != 2:
        return 1
    try:
        return 0 if authorized(pwd.getpwnam(sys.argv[1]).pw_uid) else 1
    except KeyError:
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
