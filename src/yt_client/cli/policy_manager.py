#!/usr/bin/env python3
"""Update, import, inspect and merge Linux client policies."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from yt_client import yt_config


def status() -> dict:
    settings = yt_config.load_settings()
    remote = yt_config.load_remote_policy()
    effective = yt_config.effective_config(settings, remote)
    return {
        "server": settings["server"],
        "policy": settings["policy"],
        "remote": remote,
        "effective": {
            "key": yt_config.mask_secret(effective["encryption"]["key"]),
            "key_source": effective["encryption"]["key_source"],
            "file_pattern": effective["encryption"]["file_pattern"],
            "trusted_program_count": len(effective["trusted_programs"]),
            "directories": effective["directories"],
            "remote_updated_at": effective["remote_updated_at"],
            "remote_source": effective["remote_source"],
        },
    }


def import_policy(path: Path, sgfs_conf: Path | None, server: str) -> dict:
    if path.suffix.lower() == ".dat":
        policy = yt_config.parse_native_policy(path, sgfs_conf, server)
    else:
        raw = yt_config.read_json(path)
        if raw is None:
            raise ValueError(f"策略文件不存在或不是有效 JSON: {path}")
        policy = yt_config.normalize_remote_policy(raw)
        policy["server"] = server or policy["server"]
        policy["source"] = f"file:{path}"
        policy["updated_at"] = yt_config._now()
    yt_config.save_remote_policy(policy)
    settings = yt_config.load_settings()
    settings["policy"]["last_attempt"] = yt_config._now()
    settings["policy"]["last_success"] = yt_config._now()
    settings["policy"]["last_error"] = None
    yt_config.save_settings(settings)
    yt_config.write_effective_runtime_config(settings, policy)
    return policy


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("status", help="Show configured and effective policy")
    sub.add_parser("update", help="Fetch policy using the configured source")
    sub.add_parser("show-effective", help="Print the merged effective configuration")
    check = sub.add_parser("check", help="Check server reachability")
    check.add_argument("--port", type=int, default=0)
    import_parser = sub.add_parser("import", help="Import a JSON or native policy")
    import_parser.add_argument("path", type=Path)
    import_parser.add_argument("--sgfs-conf", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "status":
            print(json.dumps(status(), ensure_ascii=False, indent=2))
        elif args.action == "update":
            settings = yt_config.load_settings()
            policy = yt_config.update_policy(settings)
            print(json.dumps(policy, ensure_ascii=False, indent=2))
        elif args.action == "show-effective":
            settings = yt_config.load_settings()
            effective = yt_config.effective_config(
                settings, yt_config.load_remote_policy()
            )
            effective["encryption"]["key"] = yt_config.mask_secret(
                effective["encryption"]["key"]
            )
            print(json.dumps(effective, ensure_ascii=False, indent=2))
        elif args.action == "check":
            settings = yt_config.load_settings()
            ok, message = yt_config.check_server(settings["server"]["host"], args.port)
            print(message)
            return 0 if ok else 1
        elif args.action == "import":
            settings = yt_config.load_settings()
            policy = import_policy(
                args.path.expanduser(), args.sgfs_conf, settings["server"]["host"]
            )
            print(json.dumps(policy, ensure_ascii=False, indent=2))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
