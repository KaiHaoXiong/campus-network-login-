import json
import base64
import copy
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

import login


def config():
    return {**copy.deepcopy(login.DEFAULTS), "username": "demo", "password": "test123"}


def response(text="", status=200):
    value = requests.Response()
    value.status_code = status
    value._content = text.encode("utf-8")
    value.encoding = "utf-8"
    return value


def session_for(*responses):
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    session.get.side_effect = list(responses)
    return session


class ExistingBugTests(unittest.TestCase):
    def test_status_endpoint_can_return_plain_json(self):
        self.assertEqual(login._parse_jsonp('{"error":"ok"}'), {"error": "ok"})

    def test_explicit_plain_password_is_not_base64_decoded(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({
                "username": "demo", "password": "plain-password!",
                "password_encoding": "plain",
            }), encoding="utf-8")
            self.assertEqual(login.load_config(path)["password"], "plain-password!")


class ConfigTests(unittest.TestCase):
    def load(self, changes):
        supplied = {"username": "demo", "password": "test123", "password_encoding": "plain", **changes}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path = Path(directory) / "config.json"
            original = json.dumps(supplied).encode("utf-8")
            path.write_bytes(original)
            try:
                return login.load_config(path)
            finally:
                self.assertEqual(path.read_bytes(), original, "Loading must not rewrite credentials")

    def test_legacy_encoded_config_is_compatible(self):
        encoded = base64.b64encode(b"old-password").decode()
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"username": "demo", "password": encoded}), encoding="utf-8")
            self.assertEqual(login.load_config(path)["password"], "old-password")

    def test_explicit_base64_and_defaults(self):
        loaded = self.load({"password": "dGVzdDEyMw==", "password_encoding": "base64"})
        self.assertEqual(loaded["password"], "test123")
        self.assertEqual(loaded["check_interval"], 10)

    def test_invalid_config_fails_before_starting(self):
        for changes in ({"check_interval": 0}, {"retry_interval": -1},
                        {"offline_confirmations": 1.5}, {"request_timeout": True},
                        {"password_encoding": "guess"}, {"portal_host": "bad/host"},
                        {"connectivity_checks": []}, {"encryption_mode": "unknown"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.load(changes)


class NetworkTests(unittest.TestCase):
    def test_jsonp_json_and_invalid_responses(self):
        self.assertEqual(login._parse_jsonp(' jsonp({"error":"ok"}); '), {"error": "ok"})
        for text in ("<html>login</html>", "[]", "jsonp([])", "jsonp(null)", "jsonp({broken})"):
            self.assertIsNone(login._parse_jsonp(text))

    def test_real_internet_skips_all_portal_requests_on_hotspot(self):
        session = session_for(response("Microsoft Connect Test"))
        with patch.object(login, "get_local_ip", return_value="192.168.1.2"), \
                patch.object(login, "new_session", return_value=session):
            self.assertEqual(login.inspect_network(config()).state, "online")
        self.assertEqual(session.get.call_count, 1)
        self.assertNotIn("10.110", session.get.call_args.args[0])

    def test_captive_html_redirect_and_wrong_body_are_not_online(self):
        for first in (response("<html>Login</html>"), response("", 302)):
            session = session_for(first, response("Login", 200))
            self.assertFalse(login.internet_available(config(), session))
            self.assertFalse(session.get.call_args.kwargs["allow_redirects"])

    def test_one_failed_probe_does_not_hide_second_success(self):
        session = session_for(requests.Timeout(), response("", 204))
        self.assertTrue(login.internet_available(config(), session))

    def test_no_network_does_not_send_requests(self):
        with patch.object(login, "get_local_ip", return_value=""), \
                patch.object(login, "new_session") as new:
            self.assertEqual(login.inspect_network(config()).state, "waiting")
            new.assert_not_called()

    def inspect_portal(self, portal_response, token_response):
        session = session_for(portal_response, token_response)
        with patch.object(login, "get_local_ip", return_value="10.246.6.57"), \
                patch.object(login, "internet_available", return_value=False), \
                patch.object(login, "new_session", return_value=session):
            # 这些测试只覆盖已确认入口后的在线状态及挑战码。
            return login.inspect_network({**config(), "_portal_verified": True}), session

    def test_authenticated_with_failed_external_probe_does_not_relogin(self):
        status, session = self.inspect_portal(response('{"error":"ok"}'), response(""))
        self.assertEqual(status.state, "authenticated")
        self.assertEqual(session.get.call_count, 1)

    def test_campus_requires_valid_challenge_before_relogin(self):
        status, _ = self.inspect_portal(response('{"error":"not_online"}'),
                                      response('jsonp({"challenge":"abc","client_ip":"10.246.6.57"})'))
        self.assertEqual(status.state, "needs_login")
        self.assertTrue(status.explicit_offline)

    def test_hotspot_outage_does_not_trigger_campus_login(self):
        status, _ = self.inspect_portal(requests.Timeout(), requests.Timeout())
        self.assertEqual(status.state, "unknown")

    def test_invalid_portal_html_is_not_evidence_of_campus(self):
        status, _ = self.inspect_portal(response("<html>Login</html>"), response("<html>Login</html>"))
        self.assertEqual(status.state, "unknown")

    def test_unknown_status_with_valid_challenge_is_distinct_from_explicit_logout(self):
        status, _ = self.inspect_portal(response("unknown"), response('{"challenge":"abc"}'))
        self.assertEqual(status.state, "needs_login")
        self.assertFalse(status.explicit_offline)


class LoginTests(unittest.TestCase):
    def test_online_and_unknown_states_never_send_login(self):
        for state, expected in (("online", 0), ("authenticated", 0), ("unknown", 3), ("waiting", 3)):
            with self.subTest(state=state), \
                    patch.object(login, "inspect_network", return_value=login.NetworkStatus(state)), \
                    patch.object(login, "new_session") as new:
                self.assertEqual(login.login_once(config()).code, expected)
                new.assert_not_called()

    def test_route_changed_before_worker_starts_cancels_login(self):
        with patch.object(login, "inspect_network", return_value=login.NetworkStatus("needs_login", "10.0.0.2")), \
                patch.object(login, "new_session") as new:
            self.assertEqual(login.login_once(config(), "10.0.0.1").code, 3)
            new.assert_not_called()

    def run_auth(self, server_text, internet=True, route="10.246.6.57"):
        session = session_for(response('{"challenge":"first","client_ip":"10.246.9.8"}'),
                              response('{"challenge":"second","client_ip":"10.246.9.8"}'),
                              response(server_text))
        captured = io.StringIO()
        with patch.object(login, "inspect_network", return_value=login.NetworkStatus("needs_login", "10.246.6.57")), \
                patch.object(login, "new_session", return_value=session), \
                patch.object(login, "get_local_ip", return_value=route), \
                patch.object(login, "internet_available", return_value=internet), \
                contextlib.redirect_stdout(captured):
            result = login.login_once(config())
        self.assertNotIn("test123", captured.getvalue())
        self.assertNotIn("second", captured.getvalue())
        return result, session

    def test_login_uses_server_ip_for_second_challenge_and_credentials(self):
        result, session = self.run_auth('jsonp({"error":"ok","access_token":"private"})')
        self.assertEqual(result.code, 0)
        calls = session.get.call_args_list
        self.assertEqual(calls[1].kwargs["params"]["ip"], "10.246.9.8")
        self.assertEqual(calls[2].kwargs["params"]["ip"], "10.246.9.8")
        self.assertEqual(calls[2].kwargs["params"]["password"], "{MD5}" + login.get_md5("test123", "second"))

    def test_success_not_revoked_by_unreachable_external_probe(self):
        result, _ = self.run_auth('{"error":"ok"}', internet=False)
        self.assertEqual(result.code, 0)
        self.assertIn("不重复认证", result.message)

    def test_route_change_before_sending_credentials_cancels(self):
        result, session = self.run_auth('{"error":"ok"}', route="192.168.1.5")
        self.assertEqual(result.code, 3)
        self.assertEqual(session.get.call_count, 2)

    def test_rejected_credentials_and_malformed_response_are_distinct(self):
        self.assertEqual(self.run_auth('{"error":"password_error"}')[0].code, 2)
        self.assertEqual(self.run_auth('<html>failure</html>')[0].code, 1)


if __name__ == "__main__":
    unittest.main()
