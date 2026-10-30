import copy
from concurrent.futures import Future
from pathlib import Path
import tempfile
import contextlib
import io
import json
import os
import subprocess
import time
import unittest
from unittest.mock import Mock, patch

import login
import monitor


def config():
    return {**copy.deepcopy(login.DEFAULTS), "username": "demo", "password": "test123"}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = monitor.MonitorPolicy(config())
        self.policy.change_network(("wifi", "wifi"))
        self.offline = login.NetworkStatus("needs_login", "10.246.6.57")

    def test_continuously_online_never_reauthenticates(self):
        for now in range(0, 3600, 10):
            self.assertFalse(self.policy.observe(login.NetworkStatus("online"), now))

    def test_need_two_consecutive_failures(self):
        self.assertFalse(self.policy.observe(self.offline, 0))
        self.assertTrue(self.policy.observe(self.offline, 10))

    def test_transient_failure_is_reset_by_success(self):
        self.policy.observe(self.offline, 0)
        self.policy.observe(login.NetworkStatus("online"), 10)
        self.assertFalse(self.policy.observe(self.offline, 20))

    def test_hotspot_and_missing_network_never_trigger_authentication(self):
        for state in ("unknown", "waiting"):
            for now in range(0, 100, 10):
                self.assertFalse(self.policy.observe(login.NetworkStatus(state), now))

    def test_success_suppresses_ambiguous_offline_status(self):
        self.policy.completed(0, 10)
        for now in range(20, 400, 10):
            self.assertFalse(self.policy.observe(self.offline, now))

    def test_real_logout_after_success_can_reconnect(self):
        self.policy.completed(0, 0)
        status = login.NetworkStatus("needs_login", explicit_offline=True)
        self.assertFalse(self.policy.observe(status, 10))
        self.assertFalse(self.policy.observe(status, 20))
        self.assertTrue(self.policy.observe(status, 30))

    def test_internet_was_working_then_dropped_can_reconnect(self):
        self.policy.completed(0, 0)
        self.policy.observe(login.NetworkStatus("online"), 10)
        self.assertFalse(self.policy.observe(self.offline, 30))
        self.assertTrue(self.policy.observe(self.offline, 40))

    def test_route_change_removes_success_suppression_and_old_failure_count(self):
        self.policy.completed(0, 0)
        self.policy.change_network(("ethernet", "ethernet"))
        self.assertFalse(self.policy.observe(self.offline, 1))
        self.assertTrue(self.policy.observe(self.offline, 11))

    def test_rejection_waits_five_minutes_and_network_switch_clears_wait(self):
        self.policy.attempted(0)
        self.policy.completed(2, 10)
        for now in (20, 60, 300):
            self.assertFalse(self.policy.observe(self.offline, now))
        self.assertTrue(self.policy.observe(self.offline, 310))
        self.policy.change_network(("wired", "wired"))
        self.assertFalse(self.policy.observe(self.offline, 311))
        self.assertTrue(self.policy.observe(self.offline, 321))

    def test_transient_failures_back_off_to_cap(self):
        self.policy.attempted(0)
        self.assertEqual(self.policy.next_attempt, 30)
        self.policy.attempted(30)
        self.assertEqual(self.policy.next_attempt, 90)
        for now in range(100, 1000, 100):
            self.policy.attempted(now)
        self.assertEqual(self.policy.next_attempt, 1200)


class SupervisorTests(unittest.TestCase):
    def simulate(self, signature, inspect, ticks=60):
        clock = [0.0]
        worker = Mock()
        worker.poll.return_value = 0
        worker.returncode = 0
        def submit(cfg, *, quick=False):
            future = Future()
            future.set_result(inspect(clock[0]))
            return future
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root = Path(directory)
            cfg_path = root / "config.json"
            cfg_path.write_text("{}", encoding="utf-8")
            with patch.object(monitor, "RUNTIME", root), \
                    patch.object(monitor, "configure_logging"), \
                    patch.object(monitor, "LOGGER"), \
                    patch.object(monitor, "load_config", return_value=config()), \
                    patch.object(monitor.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.object(monitor.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                    patch.object(monitor, "network_signature", side_effect=lambda cfg: signature(clock[0])), \
                    patch.object(monitor, "submit_check", side_effect=submit), \
                    patch.object(monitor, "spawn_worker", return_value=worker) as spawn:
                monitor.monitor(cfg_path, max_ticks=ticks)
                calls = list(spawn.call_args_list)
            return calls

    def test_monitor_does_not_relogin_every_thirty_seconds_after_success(self):
        calls = self.simulate(lambda now: ("10.246.6.57", "10.246.6.57"),
                              lambda now: login.NetworkStatus("needs_login", "10.246.6.57"), ticks=100)
        self.assertEqual(len(calls), 1)
        self.assertFalse(calls[0].kwargs["notice"])

    def test_wifi_to_ethernet_opens_one_new_login_window(self):
        calls = self.simulate(
            lambda now: ("wifi", "wifi") if now < 18 else ("wired", "wired"),
            lambda now: login.NetworkStatus("online", "wifi") if now < 18 else
            login.NetworkStatus("needs_login", "wired"))
        self.assertEqual(len(calls), 2)
        self.assertTrue(calls[0].kwargs["notice"])
        self.assertFalse(calls[1].kwargs["notice"])
        self.assertEqual(calls[1].args[1], "wired")

    def test_hotspot_without_internet_never_opens_window(self):
        calls = self.simulate(lambda now: ("hotspot", "hotspot"),
                              lambda now: login.NetworkStatus("unknown", "hotspot"))
        self.assertEqual(calls, [])

    def test_authenticated_with_unreachable_probes_only_shows_initial_notice(self):
        calls = self.simulate(lambda now: ("campus", "campus"),
                              lambda now: login.NetworkStatus("authenticated", "campus"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].kwargs["notice"], "authenticated")

    def test_single_instance_lock_releases_after_exit(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path = Path(directory) / "instance.lock"
            with monitor.FileLock(path):
                with self.assertRaises(monitor.AlreadyRunning):
                    with monitor.FileLock(path):
                        self.fail("second instance acquired lock")
            with monitor.FileLock(path):
                pass


class WindowsProcessTests(unittest.TestCase):
    def test_real_hidden_process_status_and_stop_without_any_network(self):
        source = '''
import sys
from pathlib import Path
import requests
def forbidden(*args, **kwargs):
    raise AssertionError("Network calls forbidden in offline smoke test")
requests.sessions.Session.request = forbidden
import login, monitor
monitor.RUNTIME = Path(sys.argv[1])
monitor.network_signature = lambda cfg: ("fixture", "fixture")
monitor.inspect_network = lambda cfg, **kwargs: login.NetworkStatus("authenticated", "fixture", "OFFLINE_SMOKE")
class CompletedNotice:
    returncode = 0
    def poll(self):
        return 0
monitor.spawn_worker = lambda *args, **kwargs: CompletedNotice()
sys.exit(monitor.monitor(Path(sys.argv[2])))
'''
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            runtime = Path(directory)
            cfg = {**config(), "password_encoding": "plain", "route_check_interval": 0.05,
                   "network_settle_seconds": 0.05, "check_interval": 0.1}
            path = runtime / "config.json"
            path.write_text(json.dumps(cfg), encoding="utf-8")
            options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
            process = subprocess.Popen([monitor.python_executable(windowless=True), "-B", "-c",
                                        source, str(runtime), str(path)], cwd=login.ROOT,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, **options)
            try:
                with patch.object(monitor, "RUNTIME", runtime):
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        if monitor.read_status().get("state") == "authenticated":
                            break
                        if process.poll() is not None:
                            self.fail(f"offline monitor exited early: {process.returncode}")
                        time.sleep(0.05)
                    self.assertTrue(monitor.running())
                    self.assertEqual(monitor.read_status().get("message"), "OFFLINE_SMOKE")
                    captured = io.StringIO()
                    with contextlib.redirect_stdout(captured):
                        self.assertEqual(monitor.manage("status", path), 0)
                        self.assertEqual(monitor.manage("stop", path), 0)
                    self.assertIn("OFFLINE_SMOKE", captured.getvalue())
                    self.assertEqual(process.wait(timeout=5), 0)
                    self.assertFalse(monitor.running())
                    self.assertEqual(monitor.read_status().get("state"), "stopped")
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
