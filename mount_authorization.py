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


def remember(uid: int) -> None:
    if os.geteuid() != 0 or uid <= 0:
        raise PermissionError('Only the authorized root broker may remember an account')
    DIRECTORY.mkdir(parents=True, mode=0o755, exist_ok=True)
    # Never follow a preexisting marker symlink or truncate another file.
    if authorized(uid):
        return
    fd = os.open(DIRECTORY / str(uid), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
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
