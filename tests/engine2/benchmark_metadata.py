"""Compare repeated IDE metadata queries in disposable project mounts."""
import argparse
import json
import os
from pathlib import Path
import time

from harness import ROOT, metrics, session, usage


def run(engine, count, rounds):
    def populate(project, binary):
        for folder, suffix in [('node_modules/pkg', '.js'), ('assets', '.bin'), ('src', '.java')]:
            directory = project / folder
            directory.mkdir(parents=True)
            for i in range(count):
                (directory / f'File{i}{suffix}').write_bytes(b'plain content\n' * 4)

    with session('engine2', engine, populate) as (_, project, _, _, pid):
        results = {}
        for folder in ['node_modules/pkg', 'assets', 'src']:
            paths = list((project / folder).iterdir())
            before = metrics(project)
            cpu = usage(pid)['cpu_seconds']
            start = time.perf_counter()
            for _ in range(rounds):
                for path in paths:
                    assert os.stat(path).st_size == 56
            after = metrics(project)
            results[folder] = {
                'seconds': time.perf_counter() - start,
                'worker_cpu_seconds': usage(pid)['cpu_seconds'] - cpu,
                'lookups': after['lookup'] - before['lookup'],
                'fd_reopens': after['fd_reopens'] - before['fd_reopens'],
                'fd_evictions': after['fd_evictions'] - before['fd_evictions'],
                'queries': count * rounds,
            }
        return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, default=ROOT / 'state/engine2/ytfs-engine2')
    parser.add_argument('--files', type=int, default=1000)
    parser.add_argument('--rounds', type=int, default=30)
    parser.add_argument('--output', type=Path, default=ROOT / 'state/engine2/metadata-performance.json')
    args = parser.parse_args()
    report = {}
    for label, engine in [('before', args.before), ('after', args.after)]:
        report[label] = run(engine, args.files, args.rounds)
        print(label, json.dumps(report[label]), flush=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
