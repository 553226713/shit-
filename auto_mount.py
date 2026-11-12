#!/usr/bin/env python3
"""Keep configured project directories transparently mounted with sgfs."""
from __future__ import annotations

import hashlib
import errno
import stat
import os
import pwd
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import yt_config
from namespace_view import LIBC, mount
from runtime_paths import PACKAGED, UID, MONITOR_DIR, ENGINE_DIR
from file_scope import scope_environment

ROOT = yt_config.ROOT
STATE = MONITOR_DIR
STATUS = STATE / "status.json"
LOG = STATE / "auto.log"


def runtime_engine() -> Path:
    return ENGINE_DIR / "ytfs-engine2"


def runtime_policy() -> Path:
    return STATE / "sgfs.conf"


@dataclass
class Mount:
    origin: Path
    backing: Path
    fd: int
    process: subprocess.Popen
    log_handle: object = field(repr=False)


def write_status(payload: dict, uid: int, gid: int) -> None:
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = yt_config.read_json(STATUS, {}) or {}
    current.update(payload)
    yt_config.atomic_write_json(STATUS, current)
    os.chown(STATUS, 0 if PACKAGED else uid, gid)
    if PACKAGED:
        STATUS.chmod(0o640)


@contextmanager
def user_permissions(uid: int, gid: int, groups: list[int]):
    """Check paths with the caller's effective UID and supplementary groups."""
    previous_uid, previous_gid = os.geteuid(), os.getegid()
    if previous_uid == uid and previous_gid == gid:
        yield
        return
    previous_groups = os.getgroups()
    try:
        os.setgroups(groups)
        os.setegid(gid)
        os.seteuid(uid)
        yield
    finally:
        os.seteuid(previous_uid)
        os.setegid(previous_gid)
        os.setgroups(previous_groups)


def validate_directory(path: Path, access_path: str | Path | None = None) -> None:
    protected = {'/', '/bin', '/sbin', '/usr', '/etc', '/lib', '/lib64',
                 '/dev', '/proc', '/sys', '/run', '/var', '/tmp', '/home'}
    if str(path) in protected:
        raise ValueError("系统目录不能作为监控根目录")
    if not os.access(access_path or path, os.R_OK | os.W_OK | os.X_OK, effective_ids=True):
        raise PermissionError("当前用户缺少目录读、写或进入权限")


def top_level_directories(effective: dict, skipped: dict | None = None) -> list[Path]:
    paths = []
    for item in effective["directories"]:
        if not item.get("enabled"):
            continue
        path = Path(item["path"])
        try:
            try:
                info = path.stat()
            except OSError as error:
                if error.errno != errno.ENOTCONN or not disconnected_client_mount(path):
                    raise
                if os.geteuid() == 0:
                    if LIBC.umount2(os.fsencode(path), 2):
                        raise RuntimeError(f"无法清理已断开的挂载：{path}")
                else:
                    subprocess.run(["sudo", "-n", "umount", "-l", "--", str(path)], check=True)
                info = path.stat()
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("不是目录")
            resolved = path.resolve()
            validate_directory(resolved)
            paths.append(resolved)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
            if skipped is not None:
                skipped[str(path)] = "目录不存在" if isinstance(error, FileNotFoundError) else str(error)
    paths = sorted(set(paths), key=lambda path: (len(path.parts), str(path)))
    selected: list[Path] = []
    for path in paths:
        if not any(path == parent or parent in path.parents for parent in selected):
            selected.append(path)
    return selected


def disconnected_client_mount(path: Path) -> bool:
    session = STATE / hashlib.sha256(str(path).encode()).hexdigest()[:16]
    if not session.is_dir():
        return False
    escaped = str(path).replace("\\", "\\134").replace(" ", "\\040").replace("\t", "\\011").replace("\n", "\\012")
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        separator = fields.index("-")
        if fields[4] == escaped and fields[separator + 1:separator + 3] == ["fuse", "sgfs"]:
            return True
    return False


def is_mounted(path: Path) -> bool:
    escaped = str(path).replace("\\", "\\134").replace(" ", "\\040").replace("\t", "\\011").replace("\n", "\\012")
    try:
        return any(
            line.split()[4] == escaped
            for line in Path("/proc/self/mountinfo").read_text().splitlines()
        )
    except OSError:
        return False


def open_mount(
    origin: Path,
    uid: int,
    gid: int,
    groups: list[int],
    executable: Path | None = None,
    file_scope: dict | None = None,
    compat_modules: list[str] | None = None,
    policy_path: Path | None = None,
) -> Mount:
    digest = hashlib.sha256(str(origin).encode()).hexdigest()[:16]
    session = STATE / digest
    backing = session / "backing"
    backing.mkdir(mode=0o700, parents=True, exist_ok=True)
    session.chmod(0o750 if PACKAGED else 0o700)
    os.chown(session, 0 if PACKAGED else uid, gid)
    if is_mounted(origin) and disconnected_client_mount(origin):
        raise RuntimeError(f"目录已经启用加密监控: {origin}")
    if is_mounted(backing):
        LIBC.umount2(os.fsencode(backing), 2)
    fd = None
    origin_fd = None
    process = None
    log_handle = None
    mounted_origin = False
    try:
        with user_permissions(uid, gid, groups):
            validate_directory(origin.resolve())
            origin_fd = os.open(origin, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            pinned_origin = f"/proc/self/fd/{origin_fd}"
            validate_directory(Path(os.readlink(pinned_origin)), access_path=pinned_origin)
        mount(pinned_origin, str(backing), 4096 | 16384)
        # Keep the backing view outside the original mount's propagation group.
        mount(None, str(backing), 16384 | 262144)
        fd = os.open("/dev/fuse", os.O_RDWR)
        mount(
            "sgfs",
            pinned_origin,
            2 | 4,
            "fuse",
            f"fd={fd},rootmode=40755,user_id={uid},group_id={gid},"
            "default_permissions,allow_other",
        )
        mounted_origin = True
        log_path = session / "fuse.log"
        log_handle = log_path.open("a", encoding="utf-8")
        log_path.chmod(0o600)
        os.chown(log_path, uid, gid)
        executable = executable or runtime_engine()
        command = [str(executable), str(backing), str(policy_path or runtime_policy()),
                   str(fd), str(session / "engine2-metrics.json"), str(uid)]
        def credentials():
            # Passthrough registration needs CAP_SYS_ADMIN. Request fsuid/fsgid
            # and the configured-user check live in the C++ filesystem engine.
            os.setgroups(groups)
            LIBC.prctl(1, signal.SIGTERM, 0, 0, 0)
        try:
            process = subprocess.Popen(
                command,
                cwd=backing,
                pass_fds=(fd,),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                preexec_fn=credentials,
                env=scope_environment(file_scope, compat_modules),
            )
        except PermissionError as error:
            raise RuntimeError(f"无法执行加密引擎 {executable}：请检查安装目录的执行权限和挂载选项；{error}") from error
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError(f"FUSE 进程提前退出: {origin}")
            time.sleep(0.05)
        os.close(origin_fd)
        origin_fd = None
        return Mount(origin, backing, fd, process, log_handle)
    except Exception:
        if mounted_origin:
            LIBC.umount2(os.fsencode(pinned_origin), 2)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if fd is not None:
            os.close(fd)
        if origin_fd is not None:
            os.close(origin_fd)
        LIBC.umount2(os.fsencode(backing), 2)
        if log_handle is not None:
            log_handle.close()
        raise


def close_mount(item: Mount) -> None:
    LIBC.umount2(os.fsencode(item.origin), 2)
    if item.process.poll() is None:
        item.process.terminate()
        try:
            item.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            item.process.kill()
            item.process.wait()
    os.close(item.fd)
    LIBC.umount2(os.fsencode(item.backing), 2)
    item.log_handle.close()


def prepare_runtime() -> tuple[dict, list[Path], int, int, list[int]]:
    settings = yt_config.load_settings()
    remote = yt_config.load_remote_policy()
    effective = yt_config.write_effective_runtime_config(settings, remote)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    from engine2.build import build
    build(runtime_engine())
    build(textconv=True)
    yt_config.atomic_write(
        runtime_policy(),
        yt_config.build_sgfs_conf(effective),
    )
    uid, gid = os.getuid(), os.getgid()
    groups = os.getgroups()
    return effective, top_level_directories(effective), uid, gid, groups


def run_broker() -> int:
    if PACKAGED and (os.geteuid() != 0 or UID == 0):
        raise ValueError("监控服务需要通过管理员授权启动")
    uid = UID if PACKAGED else int(os.environ.get("SUDO_UID", "0"))
    gid = pwd.getpwuid(uid).pw_gid if PACKAGED else int(os.environ.get("SUDO_GID", "0"))
    if not uid or not gid:
        raise ValueError("自动挂载必须由普通用户的 sudo 启动")
    account = pwd.getpwuid(uid)
    os.environ["HOME"] = account.pw_dir
    os.environ["USER"] = account.pw_name
    os.environ["LOGNAME"] = account.pw_name
    groups = os.getgrouplist(account.pw_name, gid)
    # Ownership alone does not describe access: shared groups and ACLs count.
    with user_permissions(uid, gid, groups):
        settings = yt_config.load_settings()
        remote = yt_config.load_remote_policy()
        effective = yt_config.effective_config(settings, remote)
        skipped = {}
        directories = top_level_directories(effective, skipped)
    STATE.mkdir(mode=0o750 if PACKAGED else 0o700, parents=True, exist_ok=True)
    STATE.chmod(0o750 if PACKAGED else 0o700)
    os.chown(STATE, 0 if PACKAGED else uid, gid)
    if PACKAGED:
        from engine2.artifacts import installed_engine
        installed_engine(ENGINE_DIR)
        yt_config.atomic_write(runtime_policy(), yt_config.build_sgfs_conf(effective), mode=0o640)
        os.chown(runtime_policy(), 0, gid)
    for runtime_file in (
        runtime_policy(),
        yt_config.STATE_DIR / "effective_config.json",
    ):
        if not PACKAGED and runtime_file.exists():
            os.chown(runtime_file, uid, gid)
    log = LOG.open("a", encoding="utf-8")
    LOG.chmod(0o600)
    os.chown(LOG, uid, gid)
    mounts: list[Mount] = []
    compatibility = None
    stopping = False

    def stop(_signum=None, _frame=None):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for directory in directories:
            log.write(f"[{yt_config._now()}] mounting {directory}\n")
            log.flush()
            try:
                mounts.append(open_mount(directory, uid, gid, groups,
                                         file_scope=effective.get("file_scope")))
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
                skipped[str(directory)] = str(error)
                log.write(f"[{yt_config._now()}] skipped {directory}: {error}\n")
                log.flush()
        write_status(
            {
                "state": "running" if mounts else "idle",
                "skipped": skipped,
                "pid": os.getpid(),
                "updated_at": yt_config._now(),
                "mounts": [str(item.origin) for item in mounts],
                "engine": "engine2",
                "engine_path": str(runtime_engine()),
                "policy_path": str(runtime_policy()),
                "error": None,
            },
            uid,
            gid,
        )
        from compat.manager import GitPatches
        compatibility = GitPatches(uid, gid, groups, log)
        while not stopping:
            for item in list(mounts):
                if item.process.poll() is not None:
                    skipped[str(item.origin)] = "FUSE 服务已退出，已跳过"
                    close_mount(item)
                    mounts.remove(item)
                    write_status({"state": "running" if mounts else "idle",
                                  "mounts": [str(m.origin) for m in mounts],
                                  "skipped": skipped, "updated_at": yt_config._now()}, uid, gid)
            if compatibility.tick([item.origin for item in mounts]):
                write_status({'compatibility': compatibility.status()}, uid, gid)
            time.sleep(1)
        return 0
    except Exception as error:
        log.write(f"[{yt_config._now()}] error: {error}\n")
        log.flush()
        write_status(
            {
                "state": "failed",
                "pid": os.getpid(),
                "updated_at": yt_config._now(),
                "error": str(error),
            },
            uid,
            gid,
        )
        return 1
    finally:
        if compatibility is not None:
            compatibility.close()
        for item in reversed(mounts):
            close_mount(item)
        if not stopping:
            write_status(
                {
                    "state": "failed",
                    "updated_at": yt_config._now(),
                },
                uid,
                gid,
            )
        elif not yt_config.read_json(STATUS, {}).get("error"):
            write_status(
                {
                    "state": "stopped",
                    "pid": None,
                    "updated_at": yt_config._now(),
                    "mounts": [],
                    "error": None,
                },
                uid,
                gid,
            )
        log.close()


def main() -> int:
    if "--broker" in sys.argv[1:]:
        return run_broker()
    if PACKAGED:
        os.execvp("pkexec", ["pkexec", str(ROOT / "mount-broker")])
    try:
        effective, directories, _uid, _gid, _groups = prepare_runtime()
        if not directories:
            skipped = {}
            top_level_directories(effective, skipped)
            write_status(
                {"state": "idle", "pid": os.getpid(), "updated_at": yt_config._now(),
                 "mounts": [], "skipped": skipped, "error": None}, os.getuid(), os.getgid(),
            )
            while not directories:
                time.sleep(5)
                directories = top_level_directories(effective)
        STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_status(
            {
                "state": "starting",
                "skipped": {},
                "pid": os.getpid(),
                "updated_at": yt_config._now(),
                "mounts": [],
                "error": None,
            },
            os.getuid(),
            os.getgid(),
        )
        os.execvpe(
            "sudo",
            [
                "sudo",
                "-n",
                sys.executable,
                str(Path(__file__).resolve()),
                "--broker",
            ],
            dict(os.environ),
        )
    except (OSError, ValueError, RuntimeError) as error:
        STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_status(
            {
                "state": "failed",
                "pid": None,
                "updated_at": yt_config._now(),
                "error": str(error),
            },
            os.getuid(),
            os.getgid(),
        )
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
