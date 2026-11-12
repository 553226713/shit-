"""Read-only installed engine resources; no builds or runtime file copying."""
import hashlib
import json
from pathlib import Path


def _verified(directory: Path, filename: str, field: str, manifest: dict) -> Path:
    path = directory / filename
    expected = manifest.get(field)
    if not expected or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError(f'安装资源校验失败：{path}，请重新安装完整安装包')
    return path


def installed_engine(directory: Path) -> Path:
    manifest = json.loads((directory / 'manifest.json').read_text())
    engine = _verified(directory, 'ytfs-engine2', 'engine2_sha256', manifest)
    _verified(directory, 'lib/libfuse3.so.4', 'libfuse_sha256', manifest)
    return engine


def installed_textconv(directory: Path) -> Path:
    manifest = json.loads((directory / 'manifest.json').read_text())
    return _verified(directory, 'ytfs-textconv', 'textconv_sha256', manifest)
