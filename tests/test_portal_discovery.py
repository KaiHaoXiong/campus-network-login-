from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import requests

import login
import portal
from test_login import config, response, session_for


PAGE = '''<html><script>var CONFIG = {page:'account', ip:"192.0.2.23", portal:{AuthIP:""}};</script>
<script src="/static/js/Portal.js"></script></html>'''


class PortalDiscoveryTests(unittest.TestCase):
    def test_index_page_is_an_ac_entry(self):
        self.assertEqual(portal.portal_from_url("http://10.110.74.99/index_4.html", config()),
                         {"portal_host": "10.110.74.99", "ac_id": "4"})

    def test_meta_refresh_index_relative_url_is_recognized(self):
        value = response('<meta http-equiv="refresh" content="0;URL=index_4.html">')
        self.assertEqual(portal.portal_from_response(value, "http://10.110.74.99/", config()),
                         {"portal_host": "10.110.74.99", "ac_id": "4"})

    def test_actual_school_ac_detect_api_selects_pc_entry(self):
        session = session_for()

        def get(url, **kwargs):
            if url.endswith('/v1/srun_portal_detect'):
                return response('{"code":0,"Redirect":true,"Pc":"http://10.110.74.91/srun_portal_pc?ac_id=4&theme=pro"}')
            raise requests.ConnectionError()

        session.get.side_effect = get
        result = login.discover_portal(config(), session)
        self.assertEqual((result["portal_host"], result["ac_id"]), ("10.110.74.91", "4"))
        self.assertTrue(result["_portal_verified"])

    def test_index_redirect_chain_reaches_final_host(self):
        session = session_for()

        def get(url, **kwargs):
            if url == 'http://10.110.74.99/':
                return response('<script>location.href="/index_4.html";</script>')
            if url == 'http://10.110.74.99/index_4.html':
                value = response('', 302)
                value.headers['Location'] = 'http://10.110.74.91/srun_portal_pc?ac_id=4'
                return value
            if url == 'http://10.110.74.91/srun_portal_pc?ac_id=4':
                return response(PAGE)
            raise requests.ConnectionError()

        session.get.side_effect = get
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory, \
                patch.object(portal, 'CACHE', Path(directory) / 'cache.json'):
            result = login.discover_portal(config(), session)
        self.assertEqual((result['portal_host'], result['ac_id']), ('10.110.74.91', '4'))
        self.assertEqual(result['_portal_client_ip'], '192.0.2.23')

    def test_unknown_entry_never_falls_back_to_old_ac_credentials(self):
        session = session_for()
        session.get.side_effect = lambda url, **kwargs: (
            response('{"error":"not_online"}') if '/rad_user_info' in url else
            response('{"challenge":"synthetic"}') if '/get_challenge' in url else
            response('<html>unrecognized response</html>'))
        with patch.object(login, 'new_session', return_value=session), \
                patch.object(login, 'get_local_ip', return_value='192.0.2.23'), \
                patch.object(login, 'get_token') as token:
            status = login.inspect_network(config(), quick=True)
        self.assertEqual(status.state, 'unknown')
        token.assert_not_called()
