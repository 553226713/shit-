"""Read Windows application policies through the existing native login session."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from runtime_paths import ROOT, STATE_DIR
NATIVE_SHA256 = "b5d801e3ac0ba0116a62687874affa1f76a4a9454784dd56710be33f91e15f48"


def prepare_bridge(native: Path) -> Path:
    if hashlib.sha256(native.read_bytes()).hexdigest() != NATIVE_SHA256:
        raise ValueError("原生客户端版本未经验证，无法读取 Windows 应用策略")
    prebuilt = ROOT / "vendor/windows-policy.so"
    if prebuilt.is_file():
        return prebuilt
    source = ROOT / "windows_policy.cpp"
    destination = STATE_DIR / "bin/windows-policy.so"
    receipt = destination.with_suffix(".sha256")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if destination.is_file() and receipt.is_file() and receipt.read_text() == digest:
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = destination.with_suffix(".tmp.so")
    try:
        subprocess.run(
            ["g++", "-shared", "-fPIC", "-pthread", "-Wall", "-Wextra", "-Werror",
             str(source), "-o", str(temporary)],
            check=True, capture_output=True, text=True,
        )
        temporary.chmod(0o700)
        temporary.replace(destination)
        receipt.write_text(digest)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def read_snapshot(path: Path) -> dict:
    raw = json.loads(path.read_text())
    if not raw.get("ok"):
        raise ValueError("Windows 应用策略读取失败，保留上次成功策略")
    cells = raw.get("applications", [])
    if len(cells) % 4:
        raise ValueError("Windows 应用策略数据不完整")
    keys = list(dict.fromkeys(str(key).strip() for key in raw.get("encryption_keys", []) if str(key).strip()))
    if len(keys) != 1:
        raise ValueError("服务器加密密钥缺失或存在多个密钥，无法确定当前密钥")
    assigned = [int(value) for value in raw.get("assigned", [])]
    available = sorted({int(cells[index]) for index in range(0, len(cells), 4)})
    selected = assigned or available
    policies = {}
    applications = {}
    for offset in range(0, len(cells), 4):
        policy_id, policy_name, name, processes = cells[offset:offset+4]
        policy_id = int(policy_id)
        policies[policy_id] = {"id": policy_id, "name": policy_name}
        if policy_id not in selected:
            continue
        entry = applications.setdefault(name, {"name": name, "processes": []})
        for process in processes.split("|"):
            if process.strip() and process.strip() not in entry["processes"]:
                entry["processes"].append(process.strip())
    return {
        "encryption_key": keys[0],
        "windows_policy_ids": selected,
        "windows_policy_scope": "assigned" if assigned else "configured",
        "windows_policies": list(policies.values()),
        "windows_applications": list(applications.values()),
    }
