"""Single-instance broker and authenticated, unprivileged graceful shutdown."""
import fcntl
import json
import os
from pathlib import Path
import socket
import struct
import time


class BrokerControl:
    def __init__(self, directory: Path, uid: int, gid: int):
        self.path=directory/'control.sock'
        self.uid=uid
        self.lock=(directory/'broker.lock').open('a')
        try:fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close()
            raise RuntimeError('当前用户的监控服务已经运行') from None
        self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
            self.path.unlink(missing_ok=True)
            self.socket.bind(str(self.path))
            os.chown(self.path,uid,gid);self.path.chmod(0o600)
            self.socket.setblocking(False)
        except BaseException:
            self.socket.close();self.lock.close();raise

    def stop_requested(self):
        stopped=False
        while True:
            try:data,ancillary,_,_=self.socket.recvmsg(32,socket.CMSG_SPACE(struct.calcsize('3i')))
            except BlockingIOError:return stopped
            for level,kind,credentials in ancillary:
                if level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS:
                    _,uid,_=struct.unpack('3i',credentials[:struct.calcsize('3i')])
                    if uid in {0,self.uid} and data==b'stop':stopped=True

    def close(self):
        self.socket.close()
        self.path.unlink(missing_ok=True)
        self.lock.close()


def request_stop(directory: Path, timeout=15):
    try:before=json.loads((directory/'status.json').read_text())
    except (OSError,ValueError):before={}
    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as client:
        try:client.sendto(b'stop',str(directory/'control.sock'))
        except (FileNotFoundError,ConnectionRefusedError):return
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:status=json.loads((directory/'status.json').read_text())
        except (OSError,ValueError):status={}
        if status.get('state')=='stopped' or (before.get('pid') and status.get('pid')!=before['pid']):return
        time.sleep(.05)
    raise RuntimeError('监控服务未在规定时间内完成卸载，请检查监控日志')
