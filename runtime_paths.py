"""Installed resources stay read-only; each account owns its configuration."""
import os
import pwd
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PACKAGED = (ROOT / 'packaged-runtime').is_file()
VERSION = (ROOT / ('packaged-runtime' if PACKAGED else 'VERSION')).read_text(encoding='utf-8').strip()
UID = int(os.environ.get('PKEXEC_UID', os.environ.get('SUDO_UID', os.getuid()))) if os.geteuid() == 0 else os.getuid()
HOME = Path(pwd.getpwuid(UID).pw_dir)
CONFIG_DIR = HOME / '.config/shit-encryption' if PACKAGED else ROOT / 'config'
STATE_DIR = HOME / '.local/state/shit-encryption' if PACKAGED else ROOT / 'state'
MONITOR_DIR = Path('/run/shit-encryption') / str(UID) if PACKAGED else STATE_DIR / 'auto'

# Executable resources never belong to MONITOR_DIR, which may be noexec.
ENGINE_DIR = ROOT / "vendor" if PACKAGED else STATE_DIR / "engine2"
