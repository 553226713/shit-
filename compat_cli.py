"""Source/installed entry point for isolated compatibility modules."""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument('module', choices=['textconv', 'git-configure'])
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        parser.print_help()
        return 0
    args, remaining = parser.parse_known_args()
    sys.argv = [sys.argv[0], *remaining]
    if args.module == 'textconv':
        from compat.textconv import main as entry
    else:
        from compat.git import main as entry
    return entry()


if __name__ == '__main__':
    raise SystemExit(main())
