import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import error_log


class ErrorLogTests(unittest.TestCase):
    def test_normal_events_do_not_create_log_and_duplicate_errors_are_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = error_log.logger('test', Path(temporary))
            path = Path(temporary) / 'test-errors.log'
            log.info('normal read')
            log.warning('expected missing file')
            self.assertFalse(path.exists())
            for _ in range(1000):log.error('disk error errno=%s', 5)
            text = path.read_text()
            self.assertEqual(text.count('disk error'), 1)
            self.assertIn('pid=', text)
            for handler in log.handlers:handler.close()

    def test_rotation_and_secret_redaction(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(error_log, 'MAX_BYTES', 160):
            log = error_log.logger('rotate', Path(temporary))
            for i in range(20):log.error('failure %d password=secret token=private encryptkey=key', i)
            paths = list(Path(temporary).glob('rotate-errors.log*'))
            self.assertLessEqual(len(paths), error_log.BACKUPS + 1)
            self.assertGreater(len(paths), 1)
            for path in paths:
                text = path.read_text()
                self.assertNotIn('secret', text)
                self.assertNotIn('private', text)
                self.assertNotIn('encryptkey=key', text)
                self.assertIn('[redacted]', text)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            for handler in log.handlers:handler.close()

    def test_traceback_is_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = error_log.logger('exception', Path(temporary))
            try:raise OSError('simulated mount failure')
            except OSError:log.exception('Mount failed')
            text = (Path(temporary) / 'exception-errors.log').read_text()
            self.assertIn('Traceback', text)
            self.assertIn('simulated mount failure', text)
            for handler in log.handlers:handler.close()

    def test_open_log_directory_link(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(error_log, 'STATE_DIR', Path(temporary)), patch.object(error_log, 'PACKAGED', True):
            directory = error_log.log_directory()
            self.assertTrue(directory.is_dir())
            self.assertEqual((directory / 'monitor').readlink(), Path('/var/log/shit-encryption') / str(error_log.UID))


if __name__ == '__main__':unittest.main()
