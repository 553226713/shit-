import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1] / "src"))
from yt_client.monitoring.broker_control import BrokerControl


class BrokerControlTests(unittest.TestCase):
    def test_only_one_broker_owns_a_runtime_directory(self):
        with tempfile.TemporaryDirectory() as t:
            control=BrokerControl(Path(t),os.getuid(),os.getgid())
            try:
                with self.assertRaisesRegex(RuntimeError,'已经运行'):BrokerControl(Path(t),os.getuid(),os.getgid())
            finally:control.close()
            replacement=BrokerControl(Path(t),os.getuid(),os.getgid());replacement.close()

    def test_stop_uses_kernel_credentials_and_requires_correct_command(self):
        with tempfile.TemporaryDirectory() as t:
            control=BrokerControl(Path(t),os.getuid(),os.getgid())
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sender:
                    sender.sendto(b'not-stop',str(control.path));self.assertFalse(control.stop_requested())
                    sender.sendto(b'stop',str(control.path));self.assertTrue(control.stop_requested())
                self.assertFalse(control.stop_requested())
            finally:control.close()
