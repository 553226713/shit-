"""Installer-only graceful shutdown of verified installed root brokers.

User systemd managers cannot signal root-owned legacy brokers. pidfds prevent
PID reuse from targeting another process; source/development brokers are excluded.
"""
import os
from pathlib import Path
import select
import signal
import time

pending={}
for process in Path('/proc').iterdir():
    if not process.name.isdigit() or int(process.name)==os.getpid():continue
    descriptor=None
    try:
        descriptor=os.pidfd_open(int(process.name))
        argv=(process/'cmdline').read_bytes().split(b'\0')
        command=b' '.join(argv)
        status=(process/'status').read_text()
        uid_line=next(line for line in status.splitlines() if line.startswith('Uid:'))
        if int(uid_line.split()[1])!=0:continue
        marker=(b'"/usr/lib/shit-encryption"' in command or b"'/usr/lib/shit-encryption'" in command)
        if not marker and b'/usr/lib/shit-encryption/auto_mount.py' not in argv:continue
        if b'run_broker' not in command and b'--broker' not in argv:continue
        if not Path(os.fsdecode(argv[0])).name.startswith('python3'):continue
        signal.pidfd_send_signal(descriptor,signal.SIGTERM)
        pending[descriptor]=int(process.name);descriptor=None
    except (OSError,StopIteration,ValueError):pass
    finally:
        if descriptor is not None:os.close(descriptor)

poll=select.poll()
for descriptor in pending:poll.register(descriptor,select.POLLIN)
deadline=time.monotonic()+20
while pending and time.monotonic()<deadline:
    for descriptor,_ in poll.poll(200):
        poll.unregister(descriptor);os.close(descriptor);pending.pop(descriptor,None)
if pending:
    pids=list(pending.values())
    for descriptor in pending:os.close(descriptor)
    raise SystemExit(f'Old encryption brokers did not shut down cleanly: {pids}; stop monitoring and retry installation')
