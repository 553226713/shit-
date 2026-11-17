"""Source/installed entry point for isolated compatibility modules."""
import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument('module', choices=['textconv', 'git-configure'])
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        parser.print_help()
        return 0
    args, remaining = parser.parse_known_args()
    sys.argv = [sys.argv[0], *remaining]
    if args.module == 'textconv':
        from yt_client.compat.textconv import main as entry
    else:
        from yt_client.compat.git import main as entry
    return entry()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        from yt_client.error_log import logger
        logger('compat').exception('Compatibility command failed')
        raise
