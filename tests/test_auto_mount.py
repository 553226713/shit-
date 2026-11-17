import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from yt_client.monitoring import auto_mount


class AutoMountTests(unittest.TestCase):
    def test_missing_directory_does_not_exclude_available_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            good = Path(directory) / 'good'; good.mkdir()
            missing = Path(directory) / 'missing'
            skipped = {}
            selected = auto_mount.top_level_directories({'directories': [
                {'path': str(missing), 'enabled': True},
                {'path': str(good), 'enabled': True},
            ]}, skipped)
            self.assertEqual(selected, [good])
            self.assertEqual(skipped[str(missing)], '目录不存在')

    def test_configured_directories_need_no_write_permission_or_path_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'read-only'; path.mkdir(); path.chmod(0o555)
            for selected in (path, Path('/tmp')):
                with self.subTest(path=selected), patch.object(auto_mount.os, 'access',
                        side_effect=AssertionError('extra directory access filter')):
                    self.assertEqual(auto_mount.top_level_directories({'directories': [
                        {'path': str(selected), 'enabled': True}]}), [selected.resolve()])

    def test_broker_isolates_mount_failure_and_exited_process(self):
        from contextlib import ExitStack
        for exited in (False, True):
            with self.subTest(exited=exited), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                state = Path(directory)
                effective = {'directories': []}
                bad, good = Path('/bad'), Path('/good')
                healthy = Mock(origin=good); healthy.process.poll.return_value = None
                failed = Mock(origin=bad,backing=state/'bad/backing'); failed.process.poll.return_value = 1
                handlers = {}
                def signal_handler(sig, callback):
                    handlers[sig] = callback
                def sleep(_seconds):
                    handlers[auto_mount.signal.SIGTERM]()
                patches = [
                    patch.object(auto_mount, 'STATE', state),
                    patch.object(auto_mount, 'LOG', state / 'log'),
                    patch.object(auto_mount.yt_config, 'load_settings', return_value={}),
                    patch.object(auto_mount.yt_config, 'load_remote_policy', return_value={}),
                    patch.object(auto_mount.yt_config, 'effective_config', return_value=effective),
                    patch.object(auto_mount, 'top_level_directories', return_value=[bad, good]),
                    patch.dict(auto_mount.os.environ, {'SUDO_UID': '1000', 'SUDO_GID': '1000'}),
                    patch.object(auto_mount.os, 'chown'),
                    patch.object(auto_mount.os, 'getgrouplist', return_value=[1000]),
                    patch.object(auto_mount.signal, 'signal', side_effect=signal_handler),
                    patch.object(auto_mount.time, 'sleep', side_effect=sleep),
                    patch.object(auto_mount.yt_config, 'read_json', return_value={}),
                    patch.object(auto_mount, 'open_mount', side_effect=[failed if exited else OSError('missing'), healthy]),
                ]
                for mocked in patches:
                    stack.enter_context(mocked)
                status = stack.enter_context(patch.object(auto_mount, 'write_status'))
                stack.enter_context(patch.object(auto_mount, 'close_mount'))
                self.assertEqual(auto_mount.run_broker(), 0)
                payloads = [call.args[0] for call in status.call_args_list]
                self.assertTrue(any(p.get('mounts') == ['/good'] and '/bad' in p.get('skipped', {}) for p in payloads))
                self.assertFalse(any(p['state'] == 'failed' for p in payloads))

    def test_compatibility_failure_does_not_exit_mount_broker(self):
        import yt_client.compat.manager as manager
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            directory=Path(temporary);handlers={}
            def sleep(_):handlers[auto_mount.signal.SIGTERM]()
            for item in [patch.object(auto_mount,'STATE',directory),patch.object(auto_mount,'LOG',directory/'log'),
                         patch.object(auto_mount.yt_config,'load_settings',return_value={}),patch.object(auto_mount.yt_config,'load_remote_policy',return_value={}),
                         patch.object(auto_mount.yt_config,'effective_config',return_value={'directories':[]}),patch.object(auto_mount,'top_level_directories',return_value=[]),
                         patch.dict(auto_mount.os.environ,{'SUDO_UID':'1000','SUDO_GID':'1000'}),patch.object(auto_mount.os,'chown'),
                         patch.object(auto_mount.os,'getgrouplist',return_value=[1000]),patch.object(auto_mount.signal,'signal',side_effect=lambda sig,cb:handlers.update({sig:cb})),
                         patch.object(auto_mount.time,'sleep',side_effect=sleep),patch.object(manager.GitPatches,'tick',side_effect=OSError('watcher failure'))]:stack.enter_context(item)
            status=stack.enter_context(patch.object(auto_mount,'write_status'))
            self.assertEqual(auto_mount.run_broker(),0)
            self.assertTrue(any('compatibility' in call.args[0] for call in status.call_args_list))

    def run_recovery_scenario(self, outcomes, stop_at):
        from contextlib import ExitStack
        import yt_client.compat.manager as manager
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            state = Path(temporary)
            directory = state / 'project'; directory.mkdir()
            clock = [0]
            handlers, attempts, closed = {}, [], []
            def sleep(_):
                clock[0] += 1
                if clock[0] >= stop_at:
                    handlers[auto_mount.signal.SIGTERM]()
            def open_mount(*args, **kwargs):
                attempts.append(clock[0])
                outcome = outcomes.pop(0)
                if isinstance(outcome, Exception):
                    raise outcome
                item = Mock(origin=directory, backing=state/'session/backing')
                if isinstance(outcome, list):
                    item.process.poll.side_effect = outcome
                else:
                    item.process.poll.return_value = outcome
                item.process.pid = 123
                return item
            patches = [
                patch.object(auto_mount, 'STATE', state), patch.object(auto_mount, 'LOG', state/'log'),
                patch.object(auto_mount, 'PACKAGED', False),
                patch.object(auto_mount.yt_config, 'load_settings', return_value={}),
                patch.object(auto_mount.yt_config, 'load_remote_policy', return_value={}),
                patch.object(auto_mount.yt_config, 'effective_config', return_value={'directories': []}),
                patch.object(auto_mount, 'top_level_directories', return_value=[directory]),
                patch.dict(auto_mount.os.environ, {'SUDO_UID': '1000', 'SUDO_GID': '1000'}),
                patch.object(auto_mount.os, 'chown'),
                patch.object(auto_mount.os, 'getgrouplist', return_value=[1000]),
                patch.object(auto_mount.signal, 'signal', side_effect=lambda sig, cb: handlers.update({sig: cb})),
                patch.object(auto_mount.time, 'monotonic', side_effect=lambda: clock[0]),
                patch.object(auto_mount.time, 'sleep', side_effect=sleep),
                patch.object(auto_mount, 'open_mount', side_effect=open_mount),
                patch.object(auto_mount, 'close_mount', side_effect=lambda item: closed.append(item)),
                patch.object(manager, 'GitPatches'),
            ]
            for item in patches: stack.enter_context(item)
            status = stack.enter_context(patch.object(auto_mount, 'write_status'))
            self.assertEqual(auto_mount.run_broker(), 0)
            return attempts, [call.args[0] for call in status.call_args_list], closed, str(directory)

    def test_worker_recovers_after_clean_exit_or_signal_and_transient_mount_failure(self):
        for code in (0, -9):
            with self.subTest(code=code):
                attempts, payloads, closed, directory = self.run_recovery_scenario(
                    [code, OSError('temporary mount failure'), None], 5)
                self.assertEqual(attempts, [0, 1, 3])
                recovered = [p for p in payloads if directory in p.get('worker_failures', {})
                             and 'recovered_at' in p['worker_failures'][directory]]
                self.assertTrue(recovered)
                self.assertEqual(recovered[0]['mounts'], [directory])
                self.assertNotIn(directory, recovered[0]['skipped'])
                self.assertEqual(recovered[0]['worker_failures'][directory]['exit_code'], code)
                self.assertEqual(len(closed), 2)

    def test_startup_mount_failure_recovers(self):
        attempts, payloads, _, directory = self.run_recovery_scenario([OSError('busy'), None], 3)
        self.assertEqual(attempts, [0, 1])
        self.assertTrue(any(p.get('mounts') == [directory] and not p['skipped'] for p in payloads))

    def test_repeated_worker_exits_back_off_to_sixty_seconds(self):
        attempts, _, closed, _ = self.run_recovery_scenario([1] * 8, 131)
        self.assertEqual(attempts, [0, 1, 4, 9, 18, 35, 68, 129])
        self.assertEqual(len(closed), 8)

    def test_stop_cancels_pending_mount_recovery(self):
        attempts, payloads, closed, _ = self.run_recovery_scenario([1], 1)
        self.assertEqual(attempts, [0])
        self.assertEqual(len(closed), 1)
        self.assertEqual(payloads[-1]['state'], 'stopped')

    def test_stable_worker_resets_recovery_backoff(self):
        attempts, _, _, _ = self.run_recovery_scenario([1, [None] * 61 + [-9], None], 66)
        self.assertEqual(attempts, [0, 1, 64])

    def test_recovery_only_recognizes_this_clients_fuse_mount(self):
        with patch.object(Path, 'is_dir', return_value=True), patch.object(Path, 'read_text', return_value='1 2 0:1 / /project rw - fuse sgfs rw\n'):
            self.assertTrue(auto_mount.disconnected_client_mount(Path('/project')))
        with patch.object(Path, 'is_dir', return_value=True), patch.object(Path, 'read_text', return_value='1 2 0:1 / /project rw - fuse other rw\n'):
            self.assertFalse(auto_mount.disconnected_client_mount(Path('/project')))

    def test_no_directories_waits_without_failed_service_or_sudo(self):
        with patch.object(auto_mount, 'prepare_runtime', return_value=({'directories': []}, [], 1000, 1000, [])), patch.object(auto_mount, 'write_status') as status, patch.object(auto_mount.time, 'sleep', side_effect=KeyboardInterrupt), patch.object(auto_mount.os, 'execvpe') as execute:
            with self.assertRaises(KeyboardInterrupt):
                auto_mount.main()
            self.assertEqual(status.call_args.args[0]['state'], 'idle')
            self.assertIsNone(status.call_args.args[0]['error'])
            execute.assert_not_called()

    def test_bind_mount_source_does_not_count_as_mounted_target(self):
        with patch.object(Path, 'read_text', return_value='1 2 0:1 /project /backing rw - ext4 disk rw\n'):
            self.assertFalse(auto_mount.is_mounted(Path('/project')))
            self.assertTrue(auto_mount.is_mounted(Path('/backing')))

    def test_fuse_startup_failure_unmounts_both_views(self):
        with tempfile.TemporaryDirectory() as directory:
            origin = Path(directory) / 'project'; origin.mkdir()
            process = Mock(); process.poll.return_value = 1
            with patch.object(auto_mount, 'STATE', Path(directory) / 'state'), patch.object(auto_mount, 'mount'), patch.object(auto_mount, 'is_mounted', return_value=False), patch.object(auto_mount.os, 'chown'), patch.object(auto_mount.os, 'open', side_effect=[41,42]), patch.object(auto_mount.os,'readlink',return_value=str(origin)), patch.object(auto_mount.os,'access',return_value=True), patch.object(auto_mount.os, 'close') as close, patch.object(auto_mount.subprocess, 'Popen', return_value=process), patch.object(auto_mount.LIBC, 'umount2') as unmount:
                with self.assertRaisesRegex(RuntimeError, 'FUSE 进程提前退出'):
                    auto_mount.open_mount(origin, 1000, 1000, [])
                self.assertEqual(unmount.call_count, 2)
                self.assertEqual(unmount.call_args_list[0].args, (b'/proc/self/fd/41', 2))
                self.assertCountEqual([call.args[0] for call in close.call_args_list],[41,42])


if __name__ == '__main__':
    unittest.main()
