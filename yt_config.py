"""Configuration, policy import and merge helpers for the Linux client."""
from __future__ import annotations

import configparser
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import struct
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from runtime_paths import ROOT, CONFIG_DIR, STATE_DIR, PACKAGED, HOME as USER_HOME
from file_scope import normalize_scope
SETTINGS_PATH = CONFIG_DIR / "settings.json"
REMOTE_POLICY_PATH = CONFIG_DIR / "remote_policy.json"
VIEW_POLICY_PATH = CONFIG_DIR / "global_view_policy.json"
LEGACY_STATUS_PATH = ROOT.parent / "YTSysConfig.ini"

RULE_SEPARATOR = "==||=="
DEFAULT_FILE_PATTERN = "*"
DEFAULT_TRUSTED_PROGRAMS = [
    "zed",
    "zed-editor",
    "*/zed",
    "*/zed-editor",
    "*codex*",
    "*node*",
    "*python*",
    "*cat*",
    "*rg*",
    "*bash*",
    "*sed*",
    "*awk*",
    "*perl*",
    "*apply_patch*",
    "*java*",
    "*javac*",
    "*idea*",
    "*jetbrains*",
    "*pycharm*",
    "*webstorm*",
    "*goland*",
    "*clion*",
    "*mvn*",
    "*vim*",
    "*nvim*",
]


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def atomic_write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n", mode)


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def _legacy_server_host() -> str:
    parser = configparser.ConfigParser()
    try:
        parser.read(LEGACY_STATUS_PATH, encoding="utf-8")
        return parser.get("YTSTATUS", "ServerIP", fallback="").strip()
    except (configparser.Error, OSError):
        return ""


def _current_sgfs_rules() -> tuple[str, list[str]]:
    key = ""
    programs: list[str] = []
    try:
        lines = (CONFIG_DIR / "sgfs.conf").read_text(encoding="utf-8").splitlines()
    except OSError:
        return key, programs
    for line in lines:
        if RULE_SEPARATOR not in line:
            continue
        program, _pattern = line.split(RULE_SEPARATOR, 1)
        program = program.strip()
        if program == "encryptkey":
            key = _pattern.strip()
        elif program:
            programs.append(program)
    return key, _dedupe(programs)


def default_settings() -> dict[str, Any]:
    view_policy = read_json(VIEW_POLICY_PATH, {}) or {}
    file_patterns = view_policy.get("file_patterns") or [DEFAULT_FILE_PATTERN]
    legacy_key, legacy_programs = _current_sgfs_rules()
    project_dir = USER_HOME / "桌面" / "project"
    directories = []
    if not PACKAGED and project_dir.exists():
        directories.append({"path": str(project_dir), "enabled": True})
    zed = USER_HOME / ".local" / "bin" / "zed"
    programs = [
        {
            "name": "Zed",
            "command": str(zed) if zed.exists() else "zed",
            "arguments": ["{directory}"],
            "terminal": False,
            "enabled": True,
        },
        {
            "name": "加密终端",
            "command": "bash",
            "arguments": [],
            "terminal": True,
            "enabled": True,
        },
    ]
    return {
        "schema": 1,
        "server": {
            "host": _legacy_server_host(),
            "policy_source": {"type": "native", "value": "", "timeout_seconds": 20},
            "auto_update": True,
            "update_interval_minutes": 30,
        },
        "encryption": {
            "key": legacy_key,
            "file_pattern": str(file_patterns[0]) if file_patterns else DEFAULT_FILE_PATTERN,
            "new_file_mode": "plain",
        },
        "trusted_programs": legacy_programs or list(DEFAULT_TRUSTED_PROGRAMS),
        "file_scope": normalize_scope(),
        "directories": directories,
        "programs": programs,
        "local_overrides": {
            "use_server_policy": True,
            "removed_server_directories": [],
            "removed_server_programs": [],
        },
        "policy": {
            "last_attempt": None,
            "last_success": None,
            "last_error": None,
        },
    }


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        if isinstance(item, str) and item.strip():
            result.append(item.strip())
    return _dedupe(result)


def _safe_absolute_path(value: str) -> str:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"目录必须是绝对路径: {value}")
    return str(path.resolve(strict=False))


def normalize_settings(raw: dict[str, Any] | None) -> dict[str, Any]:
    settings = default_settings()
    if not isinstance(raw, dict):
        return settings

    server = raw.get("server")
    if isinstance(server, dict):
        settings["server"]["host"] = str(server.get("host", "")).strip()
        source = server.get("policy_source")
        if isinstance(source, dict):
            source_type = source.get("type", "none")
            source_value = str(source.get("value", "")).strip()
            if source_type == "url" and not source_value:
                # Older settings could select HTTP without entering an URL.
                source_type = "native"
            if source_type not in {"none", "native", "file", "url", "command"}:
                source_type = "none"
            settings["server"]["policy_source"] = {
                "type": source_type,
                "value": source_value,
                "timeout_seconds": max(1, min(120, int(source.get("timeout_seconds", 20)))),
            }
        settings["server"]["auto_update"] = bool(server.get("auto_update", True))
        settings["server"]["update_interval_minutes"] = max(
            1, min(1440, int(server.get("update_interval_minutes", 30)))
        )

    encryption = raw.get("encryption")
    if isinstance(encryption, dict):
        settings["encryption"]["key"] = str(encryption.get("key", "")).strip()
        settings["encryption"]["file_pattern"] = str(
            encryption.get("file_pattern", DEFAULT_FILE_PATTERN)
        ).strip() or DEFAULT_FILE_PATTERN
        mode = encryption.get("new_file_mode", "plain")
        if mode not in ("plain", "encrypted"):
            raise ValueError("新建文件格式必须为明文或加密")
        settings["encryption"]["new_file_mode"] = mode

    if "trusted_programs" in raw:
        settings["trusted_programs"] = _string_list(raw.get("trusted_programs"))
    settings["file_scope"] = normalize_scope(raw.get("file_scope"))

    directories = []
    for item in raw.get("directories", []):
        if isinstance(item, str):
            item = {"path": item, "enabled": True}
        if not isinstance(item, dict) or not str(item.get("path", "")).strip():
            continue
        try:
            path = _safe_absolute_path(str(item["path"]))
        except ValueError:
            continue
        directories.append({"path": path, "enabled": bool(item.get("enabled", True))})
    if "directories" in raw:
        deduped: dict[str, dict[str, Any]] = {}
        for item in directories:
            deduped[item["path"]] = item
        settings["directories"] = list(deduped.values())

    programs = []
    for index, item in enumerate(raw.get("programs", [])):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        command = str(item.get("command", "")).strip()
        if not name or not command:
            continue
        arguments = item.get("arguments", [])
        if isinstance(arguments, str):
            try:
                arguments = shlex.split(arguments)
            except ValueError:
                arguments = []
        programs.append(
            {
                "id": str(item.get("id", f"program-{index}")),
                "name": name,
                "command": command,
                "arguments": _string_list(arguments),
                "terminal": bool(item.get("terminal", False)),
                "enabled": bool(item.get("enabled", True)),
            }
        )
    if "programs" in raw:
        settings["programs"] = programs

    overrides = raw.get("local_overrides")
    if isinstance(overrides, dict):
        removed_directories = []
        for path in _string_list(overrides.get("removed_server_directories")):
            if Path(path).expanduser().is_absolute():
                removed_directories.append(_safe_absolute_path(path))
        settings["local_overrides"] = {
            "use_server_policy": bool(overrides.get("use_server_policy", True)),
            "removed_server_directories": removed_directories,
            "removed_server_programs": _string_list(
                overrides.get("removed_server_programs")
            ),
        }

    policy = raw.get("policy")
    if isinstance(policy, dict):
        for key in ("last_attempt", "last_success", "last_error"):
            value = policy.get(key)
            settings["policy"][key] = str(value) if value else None
    return settings


def load_settings(path: Path = SETTINGS_PATH, create: bool = True) -> dict[str, Any]:
    raw = read_json(path)
    if raw is None and path.exists():
        raise ValueError(f"配置文件不是有效的 JSON: {path}")
    settings = normalize_settings(raw)
    if create and raw is None:
        save_settings(settings, path)
    return settings


def save_settings(settings: dict[str, Any], path: Path = SETTINGS_PATH) -> dict[str, Any]:
    normalized = normalize_settings(settings)
    atomic_write_json(path, normalized)
    return normalized


def load_remote_policy(path: Path = REMOTE_POLICY_PATH) -> dict[str, Any] | None:
    value = read_json(path)
    if value is None:
        return None
    return normalize_remote_policy(value)


def normalize_remote_policy(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("策略内容必须是 JSON 对象")
    file_patterns = raw.get("file_patterns")
    if isinstance(file_patterns, str):
        file_patterns = [file_patterns]
    file_patterns = _string_list(file_patterns)
    trusted = raw.get("trusted_programs", raw.get("programs", []))
    directories = raw.get("directories", [])
    normalized_directories = []
    for item in directories:
        if isinstance(item, str):
            item = {"path": item, "enabled": True}
        if not isinstance(item, dict) or not item.get("path"):
            continue
        try:
            path = _safe_absolute_path(str(item["path"]))
        except ValueError:
            continue
        normalized_directories.append({"path": path, "enabled": bool(item.get("enabled", True))})
    windows_applications = []
    for item in raw.get("windows_applications", []):
        if not isinstance(item, dict) or not item.get("name"):
            continue
        windows_applications.append({
            "name": str(item["name"]),
            "processes": _string_list(item.get("processes", [])),
        })
    updated_at = raw.get("updated_at") or _now()
    return {
        "schema": 1,
        "windows_applications": windows_applications,
        "windows_policy_scope": str(raw.get("windows_policy_scope", "")),
        "windows_policy_ids": [int(value) for value in raw.get("windows_policy_ids", [])],
        "windows_policies": [
            {"id": int(item["id"]), "name": str(item["name"])}
            for item in raw.get("windows_policies", [])
        ],
        "updated_at": str(updated_at),
        "source": str(raw.get("source", "remote")),
        "server": str(raw.get("server", "")),
        "encryption_key": str(raw.get("encryption_key", raw.get("key", ""))).strip(),
        "file_patterns": file_patterns,
        "trusted_programs": _string_list(trusted),
        "directories": normalized_directories,
    }


def parse_sgfs_conf(path: Path) -> tuple[str, list[str], list[str]]:
    key = ""
    programs: list[str] = []
    patterns: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if RULE_SEPARATOR not in line:
            continue
        left, right = line.split(RULE_SEPARATOR, 1)
        left, right = left.strip(), right.strip()
        if left == "encryptkey":
            key = right
        elif left and left != "new_file_mode":
            programs.append(left)
            if right:
                patterns.append(right)
    return key, _dedupe(programs), _dedupe(patterns)


def parse_native_policy(
    policy_path: Path, sgfs_conf: Path | None = None, server: str = ""
) -> dict[str, Any]:
    data = policy_path.read_bytes()
    marker = "enckeylist_unit".encode("utf-16le")
    index = data.lower().find(marker.lower())
    if index < 0:
        raise ValueError("原生策略中未找到 enckeylist_unit")
    # The native policy stores each UTF-16 unit name in a 40-byte slot,
    # followed by a UTF-16 byte length and that many bytes of payload.
    length_offset = index + 40
    if length_offset + 4 > len(data):
        raise ValueError("原生策略的密钥段不完整")
    length = struct.unpack_from("<I", data, length_offset)[0]
    start = length_offset + 4
    end = start + length
    if length <= 0 or end > len(data):
        raise ValueError("原生策略的密钥长度无效")
    try:
        key = data[start:end].decode("utf-16le").rstrip("\0")
    except UnicodeDecodeError as error:
        raise ValueError("原生策略的密钥编码无效") from error
    conf_path = sgfs_conf or policy_path.with_name("sgfs.conf")
    programs: list[str] = []
    patterns: list[str] = []
    conf_key = ""
    if conf_path.exists():
        conf_key, programs, patterns = parse_sgfs_conf(conf_path)
    return normalize_remote_policy(
        {
            "updated_at": dt.datetime.fromtimestamp(
                policy_path.stat().st_mtime, tz=dt.timezone.utc
            ).astimezone().isoformat(timespec="seconds"),
            "source": f"native:{policy_path}",
            "server": server,
            "encryption_key": key or conf_key,
            "file_patterns": patterns,
            "trusted_programs": programs,
        }
    )


def program_match_name(value: str) -> str:
    """Compare executable names across Windows and Linux."""
    name = value.strip().strip('"').replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.rsplit(".", 1)[0] if "." in name else name


def match_windows_program(linux_name: str, windows_names: list[str]) -> list[str]:
    name = program_match_name(linux_name)
    return [item for item in windows_names if name and name in program_match_name(item)]


def linux_program_matches(windows_names: list[str], programs: list[dict[str, Any]]) -> dict[str, list[str]]:
    candidates = set()
    for program in programs:
        if not program.get("enabled", True):
            continue
        try:
            command = shlex.split(program["command"])
        except ValueError:
            continue
        if command:
            candidates.add(command[0])
    # Desktop applications provide Linux executable names such as idea/code.
    data_dirs = [Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))]
    data_dirs += [Path(item) for item in os.environ.get("XDG_DATA_DIRS", "/usr/local/share:/usr/share").split(":") if item]
    for directory in data_dirs:
        for desktop in (directory / "applications").glob("*.desktop"):
            parser = configparser.ConfigParser(interpolation=None, strict=False)
            try:
                parser.read(desktop, encoding="utf-8")
                entry = parser["Desktop Entry"]
                if entry.get("Type", "Application") != "Application" or entry.get("Hidden", "false").lower() == "true":
                    continue
                command = shlex.split(entry.get("TryExec") or entry.get("Exec", ""))
                if command and shutil.which(command[0]):
                    candidates.add(command[0])
            except (OSError, UnicodeError, configparser.Error, KeyError, ValueError):
                continue
    # Also resolve explicit server process names for command-line applications.
    for windows_name in windows_names:
        name = program_match_name(windows_name)
        if name and not any(char in name for char in "*?[]") and shutil.which(name):
            candidates.add(name)
    return {
        candidate: matches
        for candidate in sorted(candidates)
        if (matches := match_windows_program(candidate, windows_names))
    }


def effective_config(
    settings: dict[str, Any], remote: dict[str, Any] | None
) -> dict[str, Any]:
    settings = normalize_settings(settings)
    remote = normalize_remote_policy(remote) if remote else None
    overrides = settings["local_overrides"]
    applied_remote = remote if overrides["use_server_policy"] else None
    removed_programs = set(overrides["removed_server_programs"])
    removed_directories = set(overrides["removed_server_directories"])
    remote_programs = [
        item
        for item in (applied_remote["trusted_programs"] if applied_remote else [])
        if item not in removed_programs
    ]
    remote_patterns = applied_remote["file_patterns"] if applied_remote else []
    remote_dirs = []
    if applied_remote:
        remote_dirs = [
            {"path": item["path"], "enabled": item["enabled"], "source": "server"}
            for item in applied_remote["directories"]
            if item["path"] not in removed_directories
        ]
    local_dirs = [
        {"path": item["path"], "enabled": item["enabled"], "source": "local"}
        for item in settings["directories"]
    ]
    directories: dict[str, dict[str, Any]] = {}
    for item in remote_dirs + local_dirs:
        previous = directories.get(item["path"])
        if previous is None or previous["source"] == "local":
            directories[item["path"]] = item
    key = (
        (applied_remote["encryption_key"] if applied_remote else "")
        or settings["encryption"]["key"]
    )
    file_pattern = (
        remote_patterns[0]
        if remote_patterns
        else settings["encryption"]["file_pattern"]
    )
    program_matches = linux_program_matches(remote_programs, settings["programs"])
    trusted = _dedupe(
        list(program_matches)
        + remote_programs
        + settings["trusted_programs"]
    )
    return {
        "encryption": {
            "key": key,
            "file_pattern": file_pattern or DEFAULT_FILE_PATTERN,
            "new_file_mode": settings["encryption"]["new_file_mode"],
            "key_source": (
                "server" if applied_remote and applied_remote["encryption_key"] else "local"
            ),
        },
        "trusted_programs": trusted,
        "file_scope": normalize_scope(settings.get("file_scope")),
        "program_matches": program_matches,
        "directories": list(directories.values()),
        "remote_updated_at": remote["updated_at"] if remote else None,
        "remote_source": remote["source"] if remote else None,
        "server_policy_applied": bool(applied_remote),
        "removed_server_directories": overrides["removed_server_directories"],
        "removed_server_programs": overrides["removed_server_programs"],
    }


def build_sgfs_conf(effective: dict[str, Any]) -> str:
    key = str(effective["encryption"].get("key", "")).strip()
    if not key:
        raise ValueError("加密密钥为空，无法启动文件服务")
    if "\n" in key or RULE_SEPARATOR in key:
        raise ValueError("加密密钥包含非法字符")
    pattern = str(effective["encryption"].get("file_pattern", DEFAULT_FILE_PATTERN)).strip()
    if not pattern or "\n" in pattern or RULE_SEPARATOR in pattern:
        raise ValueError("文件规则无效")
    mode = effective["encryption"].get("new_file_mode", "plain")
    if mode not in ("plain", "encrypted"):
        raise ValueError("新建文件格式必须为明文或加密")
    lines = [f"encryptkey {RULE_SEPARATOR} {key}", f"new_file_mode {RULE_SEPARATOR} {mode}"]
    for program in effective["trusted_programs"]:
        if "\n" in program or RULE_SEPARATOR in program:
            raise ValueError("受信程序规则包含非法字符")
        if program:
            lines.append(f"{program} {RULE_SEPARATOR} {pattern}")
    return "\n".join(lines) + "\n"


def monitor_signature(effective: dict[str, Any]) -> tuple:
    """Compare only configuration consumed by the mount broker and engine."""
    return (
        build_sgfs_conf(effective) if effective["encryption"].get("key") else None,
        tuple(sorted(item["path"] for item in effective["directories"] if item.get("enabled"))),
    )


def write_effective_runtime_config(
    settings: dict[str, Any], remote: dict[str, Any] | None
) -> dict[str, Any]:
    effective = effective_config(settings, remote)
    runtime_conf = build_sgfs_conf(effective)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic_write(STATE_DIR / "bin" / "effective-sgfs.conf", runtime_conf)
    receipt = dict(
        generated_at=_now(),
        effective=effective,
        sgfs_conf_sha256=hashlib.sha256(runtime_conf.encode()).hexdigest(),
    )
    atomic_write_json(STATE_DIR / "effective_config.json", receipt)
    return effective


def save_remote_policy(policy: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_remote_policy(policy)
    atomic_write_json(REMOTE_POLICY_PATH, normalized)
    return normalized


def _source_description(source: dict[str, Any]) -> str:
    source_type = source.get("type", "none")
    value = source.get("value", "")
    if source_type == "none":
        raise ValueError("尚未配置服务器策略来源")
    if not value and source_type != "native":
        raise ValueError("服务器策略来源为空")
    return str(value)


def discover_native_client(explicit: str = "") -> Path:
    candidates = []
    environment_root = os.environ.get("YT_NATIVE_CLIENT_ROOT", "").strip()
    if environment_root:
        candidates.append(Path(environment_root).expanduser())
    if explicit:
        candidate = Path(explicit).expanduser()
        candidates.append(candidate.parent.parent if candidate.name == "bin" else candidate)
    candidates.extend(
        [
            ROOT / "vendor/native-client",
            Path("/opt/apps/com.yangtu.zdgk.client"),
            ROOT.parent / "linux-client-archive/research/linux_runtime",
            ROOT.parent
            / "linux-client-archive/research/linux_package/extracted/main/apps"
            / "com.yangtu.zdgk.client",
        ]
    )
    for candidate in candidates:
        if (candidate / "files/bin/svchost").is_file():
            if PACKAGED and candidate == ROOT / "vendor/native-client":
                destination = STATE_DIR / "native-client"
                (destination / "files/bin").mkdir(parents=True, exist_ok=True, mode=0o700)
                (destination / "files/log").mkdir(parents=True, exist_ok=True, mode=0o700)
                for name in ("svchost", "local.ini", "dotimer.sh"):
                    shutil.copy2(candidate / "files/bin" / name, destination / "files/bin" / name)
                return destination
            return candidate.resolve()
    raise ValueError(
        "未找到原生服务器客户端。请配置原生客户端目录，"
        "或设置 YT_NATIVE_CLIENT_ROOT"
    )


def parse_native_client_root(root: Path, server: str = "") -> dict[str, Any]:
    bin_dir = root / "files/bin"
    policy_path = bin_dir / "LinuxJMData.dat"
    if policy_path.is_file():
        policy = parse_native_policy(policy_path, bin_dir / "sgfs.conf", server)
    else:
        # A server can supply Windows applications without a Linux key policy.
        policy = normalize_remote_policy({"server": server})
    directories = []
    sysconfig = bin_dir / "sysconfig.dat"
    if sysconfig.is_file():
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(sysconfig.read_text(encoding="utf-8-sig"))
            count = parser.getint("jmdir", "count", fallback=0)
            for index in range(max(0, count)):
                value = parser.get("jmdir", f"dir{index}", fallback="").strip()
                if value:
                    directories.append(value)
        except (configparser.Error, UnicodeError, ValueError):
            directories = []
    policy["directories"] = normalize_remote_policy(
        {"directories": directories}
    )["directories"]
    runtime_ini = bin_dir / "RunTimeIni.ytf"
    server_programs = []
    if runtime_ini.is_file():
        runtime_parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            runtime_parser.read_string(runtime_ini.read_text(encoding="utf-8-sig"))
            received = runtime_parser.get("global", "getpolicy-time", fallback="").strip()
            if received:
                try:
                    policy["updated_at"] = (
                        dt.datetime.strptime(received, "%Y-%m-%d %H:%M:%S")
                        .astimezone()
                        .isoformat(timespec="seconds")
                    )
                except ValueError:
                    pass
            count = runtime_parser.getint("programfilter", "count", fallback=0)
            for index in range(max(0, count)):
                for key in (
                    f"proc{index}",
                    f"program{index}",
                    f"name{index}",
                    f"file{index}",
                ):
                    value = runtime_parser.get(
                        "programfilter", key, fallback=""
                    ).strip()
                    if value:
                        server_programs.append(value)
                        break
        except (configparser.Error, UnicodeError):
            pass
    if server_programs:
        policy["trusted_programs"] = _dedupe(
            server_programs + policy.get("trusted_programs", [])
        )
    policy["server"] = server or policy["server"]
    policy["source"] = f"native:{root}"
    return policy


def refresh_native_client(root: Path, server: str, timeout: int) -> str:
    if not shutil.which("bwrap"):
        raise ValueError("更新原生服务器策略需要 bubblewrap（bwrap）")
    from windows_policy import prepare_bridge

    if not server.strip() or any(character in server for character in "\r\n"):
        raise ValueError("请先填写有效的服务器地址")
    atomic_write(root / "files/bin/ytsysconfig.ytf", f"[ytstatus]\nserverip={server.strip()}\nfileencrypt=1\n")
    bridge = prepare_bridge(root / "files/bin/svchost")
    (root / "files/bin/windows-policy.json").unlink(missing_ok=True)
    for directory in ("sysinfo", "recvpolicy", "tasksendmsg", "clienttask", "temp"):
        (root / "files/bin" / directory).mkdir(parents=True, exist_ok=True, mode=0o700)
    log = root / "files/log/svchost.log"
    log_offset = log.stat().st_size if log.exists() else 0
    client_path = "/opt/apps/com.yangtu.zdgk.client"
    # Login and policy refresh normally complete in 1-3 seconds. The native
    # daemon does not exit by itself, so a short bounded refresh is sufficient.
    seconds = max(6, min(8, timeout))
    command = [
        "timeout",
        "--signal=TERM",
        "--kill-after=2",
        str(seconds),
        "bwrap",
        "--unshare-all",
        "--share-net",
        "--uid",
        "0",
        "--gid",
        "0",
        "--ro-bind",
        "/",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/opt/apps",
        "--bind",
        str(root),
        client_path,
        "--chdir",
        client_path + "/files/bin",
        "--die-with-parent",
        "--setenv", "LD_PRELOAD", str(bridge),
        client_path + "/files/bin/svchost",
        "r",
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            timeout=seconds + 5,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        partial = (error.stdout or b"") + (error.stderr or b"")
        output = partial.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"原生客户端更新超时: {output[-800:]}") from error
    output = (result.stdout + result.stderr).decode(
        "utf-8", errors="replace"
    ).strip()
    if result.returncode not in {0, 124}:
        raise RuntimeError(
            f"原生客户端更新失败 ({result.returncode}): {output[-800:]}"
        )
    log = root / "files/log/svchost.log"
    recent = ""
    if log.is_file():
        with log.open("rb") as stream:
            stream.seek(log_offset)
            recent = stream.read().decode("utf-8", errors="replace")
    if "LoginEnd." not in recent and not (root / "files/bin/windows-policy.json").is_file():
        raise RuntimeError("原生客户端未完成服务器登录")
    return output[-800:]


def fetch_policy(
    source: dict[str, Any], server: str = ""
) -> dict[str, Any]:
    value = _source_description(source)
    source_type = source.get("type", "none")
    timeout = max(1, int(source.get("timeout_seconds", 15)))
    if source_type == "file":
        path = Path(value).expanduser()
        if path.suffix.lower() == ".dat":
            return parse_native_policy(path, server=server)
        raw = read_json(path)
        if raw is None:
            raise ValueError(f"策略文件不存在或不是有效 JSON: {path}")
    elif source_type == "url":
        request = urllib.request.Request(value, headers={"User-Agent": "YTSysConfig/1"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(2 * 1024 * 1024)
        raw = json.loads(body.decode("utf-8"))
    elif source_type == "command":
        environment = dict(os.environ, YT_SERVER_HOST=server)
        result = subprocess.run(
            shlex.split(value),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
            check=False,
        )
        if result.returncode:
            message = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"策略命令失败 ({result.returncode}): {message[:400]}")
        raw = json.loads(result.stdout)
    elif source_type == "native":
        root = discover_native_client(value)
        refresh_native_client(root, server, timeout)
        policy = parse_native_client_root(root, server)
        from windows_policy import read_snapshot

        try:
            policy.update(read_snapshot(root / "files/bin/windows-policy.json"))
        except FileNotFoundError as error:
            raise RuntimeError("服务器登录后未取得 Windows 应用策略，请重试同步") from error
        policy["updated_at"] = _now()
        for application in policy["windows_applications"]:
            policy["trusted_programs"] += [application["name"], *application["processes"]]
        policy["trusted_programs"] = _dedupe(policy["trusted_programs"])
        return normalize_remote_policy(policy)
    else:
        raise ValueError(f"不支持的策略来源: {source_type}")
    policy = normalize_remote_policy(raw)
    policy["server"] = server or policy["server"]
    if not policy["source"] or policy["source"] == "remote":
        policy["source"] = f"{source_type}:{value}"
    if not policy["updated_at"]:
        policy["updated_at"] = _now()
    return policy


def update_policy(settings: dict[str, Any]) -> dict[str, Any]:
    settings["policy"]["last_attempt"] = _now()
    try:
        policy = fetch_policy(settings["server"]["policy_source"], settings["server"]["host"])
        # Directory edits can be saved while the network request is in flight.
        latest = load_settings()
        settings["directories"] = latest["directories"]
        settings["local_overrides"] = latest["local_overrides"]
        save_remote_policy(policy)
        if effective_config(settings, policy)["encryption"]["key"]:
            write_effective_runtime_config(settings, policy)
        settings["policy"]["last_success"] = _now()
        settings["policy"]["last_error"] = None
        save_settings(settings)
        return policy
    except Exception as error:
        latest = load_settings()
        settings["directories"] = latest["directories"]
        settings["local_overrides"] = latest["local_overrides"]
        settings["policy"]["last_error"] = str(error)
        save_settings(settings)
        raise


def check_server(host: str, port: int = 0, timeout: float = 3.0) -> tuple[bool, str]:
    host = host.strip()
    if not host:
        return False, "未配置服务器地址"
    if port:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, f"{host}:{port} 可连接"
        except OSError as error:
            return False, f"{host}:{port} 不可连接: {error}"
    ping = Path("/usr/bin/ping")
    if ping.exists():
        try:
            result = subprocess.run(
                [str(ping), "-c", "1", "-W", str(max(1, int(timeout))), host],
                capture_output=True,
                text=True,
                timeout=timeout + 2,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return False, f"{host} 网络检测失败: {error}"
        if result.returncode == 0:
            return True, f"{host} 网络可达"
        return False, f"{host} 网络不可达"
    try:
        socket.getaddrinfo(host, None)
        return True, f"{host} 地址可解析（未指定端口，未验证登录）"
    except OSError as error:
        return False, f"{host} 地址不可用: {error}"


def policy_age_minutes(settings: dict[str, Any]) -> float | None:
    value = settings.get("policy", {}).get("last_success")
    if not value:
        return None
    try:
        timestamp = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=dt.timezone.utc)
    return (dt.datetime.now().astimezone() - timestamp).total_seconds() / 60


def should_auto_update(settings: dict[str, Any]) -> bool:
    server = settings["server"]
    if not server.get("auto_update"):
        return False
    source = server.get("policy_source", {})
    if source.get("type") == "none" or not source.get("value"):
        return False
    age = policy_age_minutes(settings)
    return age is None or age >= int(server.get("update_interval_minutes", 30))


def mask_secret(value: str) -> str:
    if not value:
        return "未配置"
    if len(value) <= 4:
        return "•" * len(value)
    return value[:2] + "•" * max(4, len(value) - 4) + value[-2:]


def validate_rule_pattern(program: str) -> bool:
    return bool(program and "\n" not in program and RULE_SEPARATOR not in program)


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "session"
