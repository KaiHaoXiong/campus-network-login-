import contextlib
from concurrent.futures import Future
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import requests

import login
import monitor
from test_login import config, response, session_for


class ReconnectRegressionTests(unittest.TestCase):
    def test_manual_check_on_working_hotspot_does_not_request_challenge(self):
        session = session_for(response("Microsoft Connect Test"))
        with patch.object(login, "new_session", return_value=session), \
                patch.object(login, "get_local_ip", return_value="192.168.1.2"):
            result = login.login_once(config())
        self.assertEqual(result.code, 0)
        self.assertEqual(session.get.call_count, 1)
        self.assertIn("msftconnecttest", session.get.call_args.args[0])

    def test_captive_redirect_selects_wired_host_and_ac_id(self):
        session = session_for()

        def get(url, **kwargs):
            if "/cgi-bin/rad_user_info" in url:
                return response('{"error":"not_online"}')
            if "/cgi-bin/get_challenge" in url:
                return response('{"challenge":"synthetic","client_ip":"10.246.9.8"}')
            value = response("", 302)
            value.headers["Location"] = "http://10.110.74.91/srun_portal_pc?ac_id=4&theme=pro"
            return value

        session.get.side_effect = get
        with patch.object(login, "new_session", return_value=session), \
                patch.object(login, "get_local_ip", return_value="10.246.9.8"):
            status = login.inspect_network(config())
        self.assertEqual(status.portal_host, "10.110.74.91")
        self.assertEqual(status.ac_id, "4")

    def test_read_timeout_reports_exact_login_stage_without_secrets(self):
        session = session_for(
            response('{"challenge":"first","client_ip":"10.246.9.8"}'),
            response('{"challenge":"second","client_ip":"10.246.9.8"}'),
            requests.ReadTimeout("secret-url-with-password"))
        with patch.object(login, "inspect_network", return_value=login.NetworkStatus("needs_login", "10.246.9.8")), \
                patch.object(login, "new_session", return_value=session), \
                patch.object(login, "get_local_ip", return_value="10.246.9.8"), \
                patch.object(login, "LOGGER"), contextlib.redirect_stdout(io.StringIO()):
            result = login.login_once(config())
        self.assertEqual(result.code, 1)
        self.assertIn("提交登录", result.message)
        self.assertIn("超时", result.message)
        self.assertNotIn("secret", result.message)

    def test_selected_wired_entry_is_used_for_challenges_checksum_and_login(self):
        status = login.NetworkStatus("needs_login", "10.246.9.8",
                                     portal_host="10.110.74.91", ac_id="4")
        session = session_for(
            response('{"challenge":"first","client_ip":"10.246.9.8"}'),
            response('{"challenge":"second","client_ip":"10.246.9.8"}'),
            response('{"error":"ok"}'))
        with patch.object(login, "inspect_network", return_value=status), \
                patch.object(login, "new_session", return_value=session), \
                patch.object(login, "get_local_ip", return_value="10.246.9.8"), \
                patch.object(login, "internet_available") as external_probe, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(login.login_once(config()).code, 0)
        external_probe.assert_not_called()
        for call in session.get.call_args_list:
            self.assertTrue(call.args[0].startswith("http://10.110.74.91/"))
        parameters = session.get.call_args.kwargs["params"]
        self.assertEqual(parameters["ac_id"], "4")
        self.assertEqual(parameters["chksum"], login.make_checksum(
            "second", "demo@cmcc", login.get_md5("test123", "second"),
            "4", "10.246.9.8", "200", "1", parameters["info"]))
        self.assertEqual(session.get.call_args.kwargs["timeout"], (3, 10))

    def test_quick_route_check_never_waits_for_hostname_probes(self):
        session = session_for()
        seen = []

        def get(url, **kwargs):
            seen.append(url)
            if url.endswith('/v1/srun_portal_detect'):
                return response('{"Redirect":true,"Pc":"http://10.110.74.91/srun_portal_pc?ac_id=4"}')
            if "/cgi-bin/rad_user_info" in url:
                return response('{"error":"not_online"}')
            if "/cgi-bin/get_challenge" in url:
                return response('{"challenge":"synthetic"}')
            value = response("", 302)
            value.headers["Location"] = "http://10.110.74.91/srun_portal_pc?ac_id=4"
            return value

        session.get.side_effect = get
        with patch.object(login, "new_session", return_value=session), \
                patch.object(login, "get_local_ip", return_value="10.246.9.8"):
            self.assertEqual(login.inspect_network(config(), quick=True).state, "needs_login")
        self.assertTrue(seen)
        self.assertTrue(all("msftconnecttest" not in url and "hicloud" not in url for url in seen))

    def test_confirmed_logout_after_route_change_does_not_wait_ten_more_seconds(self):
        policy = monitor.MonitorPolicy(config())
        policy.change_network(("wired", "wired"))
        status = login.NetworkStatus("needs_login", "wired", explicit_offline=True)
        self.assertTrue(policy.observe(status, 1, network_changed=True))

    def test_wireless_dns_hang_does_not_delay_wired_popup_or_future_checks(self):
        clock = [0.0]
        switched_at = 15
        popup_times = []
        quick_times = []
        slow_future = Future()  # 永不返回，模拟旧无线网络的 DNS 卡住。

        def submit(cfg, *, quick=False):
            if not quick:
                return slow_future
            quick_times.append(clock[0])
            future = Future()
            status = (login.NetworkStatus("unknown", "wifi") if clock[0] < switched_at else
                      login.NetworkStatus("needs_login", "wired", explicit_offline=True,
                                          portal_host="10.110.74.91", ac_id="4"))
            future.set_result(status)
            return future

        worker = type("CompletedWorker", (), {"returncode": 0, "poll": lambda self: 0})()

        def spawn(*args, **kwargs):
            popup_times.append((clock[0], kwargs))
            return worker

        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path = Path(directory) / "config.json"
            path.write_text("{}", encoding="utf-8")
            with patch.object(monitor, "RUNTIME", Path(directory)), \
                    patch.object(monitor, "configure_logging"), patch.object(monitor, "LOGGER"), \
                    patch.object(monitor, "load_config", return_value=config()), \
                    patch.object(monitor.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.object(monitor.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                    patch.object(monitor, "network_signature", side_effect=lambda cfg: ("wifi", "wifi") if clock[0] < switched_at else ("wired", "wired")), \
                    patch.object(monitor, "submit_check", side_effect=submit), \
                    patch.object(monitor, "spawn_worker", side_effect=spawn):
                monitor.monitor(path, max_ticks=60)
        self.assertTrue(popup_times)
        self.assertLessEqual(popup_times[0][0] - switched_at, 3)
        self.assertEqual(popup_times[0][1]["portal"], {"portal_host": "10.110.74.91", "ac_id": "4"})
        self.assertGreater(len([value for value in quick_times if value > 20]), 1,
                           "Stale DNS must not block later campus checks")

    def test_portal_parser_rejects_untrusted_redirects(self):
        from portal import portal_from_url
        for url in ("http://192.168.1.1/srun_portal_pc?ac_id=4",
                    "http://example.com/srun_portal_pc?ac_id=4",
                    "http://10.110.74.91/other?ac_id=4",
                    "http://10.110.74.91/srun_portal_pc?ac_id=broken"):
            self.assertIsNone(portal_from_url(url, config()))
