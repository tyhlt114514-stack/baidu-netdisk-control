"""Local Cookie setup validation with synthetic sessions and no real network."""
from __future__ import annotations

import io
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from baidu_netdisk.common import NetdiskError
from baidu_netdisk.pcs_json import PcsJsonReader, _NoRedirect, _PAN_UA, _PCS_UA
from baidu_netdisk.session_import import _TEMPLATE_IDENTITY_BODY, _TEMPLATE_IDENTITY_URL, import_cookie


COOKIE = "BDUSS=synthetic-session; STOKEN=synthetic-stoken; BAIDUID=synthetic-baiduid;"


class Response(io.BytesIO):
    def __init__(self, data):
        super().__init__(data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode("utf-8"))


class Opener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
    def open(self, request, timeout):
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return Response(response)


class SessionImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.private = self.root / "pcs"
        self.source = self.private / "pcs_config.json"

    def tearDown(self):
        self.temp.cleanup()

    def opener(self, identity=None, directory=None):
        return Opener([identity or {"errno": 0, "records": [{"uk": 123, "baidu_name": "本人"}]},
                       directory or {"errno": 0, "list": []}])

    def invoke(self, opener, cookie=COOKIE, *, cancelled=None):
        with patch("baidu_netdisk.session_import.urllib.request.build_opener", return_value=opener):
            return import_cookie(cookie, self.private, cancelled=cancelled)

    def assert_code(self, code, callback):
        with self.assertRaises(NetdiskError) as context:
            callback()
        self.assertEqual(context.exception.code, code)
        return context.exception

    def test_valid_cookie_checks_netdisk_identity_and_read_before_storing(self):
        opener = self.opener()
        result = self.invoke(opener)
        self.assertTrue(result["netdisk_read_verified"])
        self.assertEqual(result["account_id"], "pcs:123")
        self.assertEqual(result["account"], {"uid": "123", "name": "本人"})
        self.assertEqual(result["identity_source"], "netdisk_api_user_getinfo")
        self.assertNotIn("synthetic", json.dumps(result))
        self.assertEqual(len(opener.requests), 2)
        self.assertTrue(opener.requests[0].full_url.startswith("https://pan.baidu.com/api/user/getinfo?"))
        self.assertTrue(opener.requests[1].full_url.startswith("https://pan.baidu.com/api/list?"))
        self.assertNotIn("synthetic", opener.requests[0].full_url)
        self.assertEqual(opener.requests[0].get_header("User-agent"), _PCS_UA)
        self.assertEqual(opener.requests[1].get_header("User-agent"), _PAN_UA)
        self.assertEqual(result["identity_profile"], "pcs_browser_default")
        stored = json.loads(self.source.read_text(encoding="utf-8"))
        self.assertEqual(stored["baidu_active_uid"], 123)
        self.assertEqual(stored["baidu_user_list"][0]["uid"], 123)
        self.assertEqual(stored["baidu_user_list"][0]["bduss"], "synthetic-session")
        self.assertTrue(stored["baidu_user_list"][0]["cookies"].endswith(";"))
        self.assertEqual(PcsJsonReader(self.private).account_identity()["account_id"], result["account_id"])

    def test_existing_other_users_and_options_are_preserved(self):
        self.private.mkdir()
        old = {"uid": 999, "name": "其他账号", "bduss": "other-synthetic-session", "custom_user_field": 9}
        config = {"appid": 266719, "savedir": "custom-location", "max_parallel": 7,
                  "baidu_active_uid": 999, "baidu_user_list": [old], "custom_config_field": {"keep": True}}
        self.source.write_text(json.dumps(config), encoding="utf-8")
        self.invoke(self.opener())
        stored = json.loads(self.source.read_text(encoding="utf-8"))
        self.assertEqual(stored["baidu_user_list"][0], old)
        self.assertEqual(stored["savedir"], "custom-location")
        self.assertEqual(stored["max_parallel"], 7)
        self.assertEqual(stored["custom_config_field"], {"keep": True})
        self.assertEqual(len(stored["baidu_user_list"]), 2)

    def test_initial_go_null_account_list_is_imported_and_options_preserved(self):
        self.private.mkdir()
        for active in ({}, {"baidu_active_uid": 0}):
            with self.subTest(active=active):
                config = {"appid": 266719, "baidu_user_list": None, "savedir": "custom-location",
                          "max_parallel": 7, "custom_config_field": {"keep": True}, **active}
                self.source.write_text(json.dumps(config), encoding="utf-8")
                result = self.invoke(self.opener())
                stored = json.loads(self.source.read_text(encoding="utf-8"))
                self.assertTrue(result["netdisk_read_verified"])
                self.assertEqual(result["account_id"], "pcs:123")
                self.assertEqual(stored["baidu_active_uid"], 123)
                self.assertEqual(len(stored["baidu_user_list"]), 1)
                self.assertEqual(stored["baidu_user_list"][0]["uid"], 123)
                for option in ("appid", "savedir", "max_parallel", "custom_config_field"):
                    self.assertEqual(stored[option], config[option])

    def test_null_account_list_with_selected_or_invalid_active_account_is_preserved(self):
        self.private.mkdir()
        for active in (123, None, False, "0", 0.0):
            with self.subTest(active=active):
                self.source.write_text(json.dumps({"baidu_active_uid": active, "baidu_user_list": None,
                                                   "savedir": "custom-location"}), encoding="utf-8")
                original = self.source.read_bytes()
                exc = self.assert_code("invalid_config", lambda: self.invoke(self.opener()))
                self.assertEqual(exc.details["stage"], "config")
                self.assertEqual(self.source.read_bytes(), original)

    def test_same_user_is_refreshed_without_duplicate_and_keeps_user_options(self):
        self.private.mkdir()
        old = {"uid": 123, "name": "old", "bduss": "old-synthetic-session", "workdir": "/我的文件",
               "sex": "", "age": 1, "accesstoken": "old-synthetic-access", "custom": "keep"}
        self.source.write_text(json.dumps({"baidu_active_uid": 123, "baidu_user_list": [old]}), encoding="utf-8")
        self.invoke(self.opener())
        users = json.loads(self.source.read_text(encoding="utf-8"))["baidu_user_list"]
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["workdir"], "/我的文件")
        self.assertEqual(users[0]["custom"], "keep")
        self.assertEqual(users[0]["bduss"], "synthetic-session")

    def test_identity_username_fallbacks_are_controlled(self):
        for key in ("netdisk_name", "uname", "username"):
            result = self.invoke(self.opener(identity={"errno": 0, "records": [{"uk": 123, key: "本人"}]}))
            self.assertEqual(result["account"]["name"], "本人")
        result = self.invoke(self.opener(identity={"errno": 0, "records": [{"uk": 123}]}))
        self.assertEqual(result["account"]["name"], "网盘用户 123")

    def test_reflected_cookie_value_is_never_returned_as_account_name(self):
        result = self.invoke(self.opener(identity={"errno": 0, "records": [{"uk": 123, "uname": "synthetic-session"}]}))
        self.assertNotIn("synthetic-session", json.dumps(result))
        self.assertEqual(result["account"]["name"], "网盘用户 123")

    def test_cookie_header_prefix_and_quotes_are_normalized(self):
        result = self.invoke(self.opener(), 'Cookie: BDUSS="synthetic-session"; STOKEN=synthetic-stoken;')
        self.assertTrue(result["ok"])
        self.assertEqual(json.loads(self.source.read_text(encoding="utf-8"))["baidu_user_list"][0]["bduss"], "synthetic-session")

    def test_invalid_cookie_does_not_make_requests_or_create_config(self):
        for cookie, code in (("", "invalid_cookie"), ("only-value", "invalid_cookie"), ("BAIDUID=x", "missing_bduss"),
                             ("BDUSS=x\r\nX-Leak: y", "invalid_cookie"), ("BDUSS=one; BDUSS=two;", "invalid_cookie")):
            opener = self.opener()
            exc = self.assert_code(code, lambda: self.invoke(opener, cookie))
            self.assertEqual(exc.details["stage"], "credential_format")
            self.assertFalse(opener.requests)
            self.assertFalse(self.source.exists())

    def test_invalid_identity_never_writes_config(self):
        for data in ({"errno": 0, "records": []}, {"errno": 0, "records": [{"uk": 0}]},
                     {"errno": 0, "records": [{"uk": 1}, {"uk": 2}]}, {"errno": 0, "records": [{"unknown": "SECRET"}]}):
            self.assert_code("invalid_identity", lambda: self.invoke(self.opener(identity=data)))
            self.assertFalse(self.source.exists())

    def test_invalid_netdisk_session_never_writes_config(self):
        opener = self.opener(directory={"errno": -6, "errmsg": "Cookie: SECRET_NEVER_ECHO"})
        exc = self.assert_code("authentication_required", lambda: self.invoke(opener))
        self.assertEqual(exc.details["stage"], "root_list")
        self.assertEqual(exc.details["profile"], "pan_android")
        self.assertNotIn("SECRET_NEVER_ECHO", str(exc.as_dict()))
        self.assertFalse(self.source.exists())

    def test_list_shape_must_be_valid(self):
        self.assert_code("invalid_response", lambda: self.invoke(self.opener(directory={"errno": 0, "wrong": []})))
        self.assertFalse(self.source.exists())

    def test_malformed_json_does_not_echo_cookie(self):
        self.assert_code("invalid_response", lambda: self.invoke(Opener([b"<html>Cookie: SECRET</html>"])))
        self.assertFalse(self.source.exists())

    def test_network_failure_is_safe_and_does_not_write(self):
        opener = Opener([urllib.error.URLError("secret-bearing URL should not be shown")])
        exc = self.assert_code("network_error", lambda: self.invoke(opener))
        self.assertNotIn("secret-bearing", str(exc))
        self.assertEqual(exc.details["stage"], "identity")
        self.assertEqual(exc.details["profile"], "pcs_browser_default")
        self.assertEqual(len(opener.requests), 1)
        self.assertFalse(self.source.exists())

    def test_auth_rejection_tries_only_same_identity_url_with_upstream_empty_ua(self):
        opener = Opener([{"errno": -6, "errmsg": "BDUSS=SECRET_NEVER_ECHO"},
                         {"errno": 0, "records": [{"uk": 123, "baidu_name": "本人"}]},
                         {"errno": 0, "list": []}])
        result = self.invoke(opener, "BDUSS=synthetic-session;")
        self.assertTrue(result["netdisk_read_verified"])
        self.assertEqual(result["identity_profile"], "upstream_empty_pcs_ua")
        self.assertEqual(opener.requests[0].full_url, opener.requests[1].full_url)
        self.assertEqual(opener.requests[0].get_header("Cookie"), opener.requests[1].get_header("Cookie"))
        self.assertEqual(opener.requests[0].get_header("User-agent"), _PCS_UA)
        self.assertEqual(opener.requests[1].get_header("User-agent"), "")
        self.assertEqual(opener.requests[2].get_header("User-agent"), _PAN_UA)
        self.assertEqual(result["identity_attempts"][0]["api_code"], -6)
        self.assertNotIn("SECRET_NEVER_ECHO", json.dumps(result))

    def test_both_identity_profiles_rejected_return_bounded_safe_stage_diagnostic(self):
        opener = Opener([{"errno": -6, "errmsg": "Cookie: SECRET_NEVER_ECHO"},
                         {"errno": -6, "errmsg": "BDUSS=SECRET_NEVER_ECHO"},
                         {"errno": -6, "errmsg": "BDUSS=SECRET_NEVER_ECHO"}])
        exc = self.assert_code("authentication_required", lambda: self.invoke(opener))
        self.assertEqual(exc.details["stage"], "identity")
        self.assertEqual(exc.details["profile"], "pan_template")
        self.assertEqual(len(exc.details["attempts"]), 3)
        self.assertEqual(len(opener.requests), 3)
        self.assertNotIn("SECRET_NEVER_ECHO", json.dumps(exc.as_dict()))
        self.assertNotIn("synthetic-session", json.dumps(exc.as_dict()))
        self.assertFalse(self.source.exists())

    def test_empty_ua_identity_success_still_requires_root_directory_success(self):
        opener = Opener([{"errno": -6}, {"errno": 0, "records": [{"uk": 123}]}, {"errno": -6}])
        exc = self.assert_code("authentication_required", lambda: self.invoke(opener))
        self.assertEqual(exc.details["stage"], "root_list")
        self.assertEqual(exc.details["identity_profile"], "upstream_empty_pcs_ua")
        self.assertEqual(len(opener.requests), 3)
        self.assertFalse(self.source.exists())

    def test_non_authentication_remote_error_does_not_retry_another_profile(self):
        opener = Opener([{"errno": 3, "errmsg": "Cookie: SECRET_NEVER_ECHO"}])
        exc = self.assert_code("remote_error", lambda: self.invoke(opener))
        self.assertEqual(exc.details["stage"], "identity")
        self.assertEqual(len(opener.requests), 1)
        self.assertFalse(self.source.exists())

    def test_legacy_contract_error_uses_fixed_template_post_and_proves_root_read(self):
        for rejected in (urllib.error.HTTPError("https://pan.baidu.com/api/user/getinfo", 400,
                                               "params error SECRET_NEVER_ECHO", None, None),
                         {"errno": 2, "errmsg": "params error SECRET_NEVER_ECHO"}):
            opener = Opener([rejected, {"errno": 0, "result": {"username": "本人", "loginstate": 1, "uk": "123"}},
                             {"errno": 0, "list": []}])
            result = self.invoke(opener)
            self.assertEqual(result["account_id"], "pcs:123")
            self.assertEqual(result["identity_source"], "netdisk_api_gettemplatevariable")
            self.assertEqual(result["identity_profile"], "pan_template")
            self.assertTrue(result["netdisk_read_verified"])
            self.assertEqual(len(opener.requests), 3)
            request = opener.requests[1]
            self.assertEqual(request.full_url, _TEMPLATE_IDENTITY_URL)
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.data, _TEMPLATE_IDENTITY_BODY)
            self.assertEqual(urllib.parse.parse_qs(request.data.decode("ascii")),
                             {"fields": ['["username","loginstate","uk"]']})
            self.assertEqual(request.get_header("Content-type"), "application/x-www-form-urlencoded")
            self.assertEqual(request.get_header("Referer"), "https://pan.baidu.com/disk/home")
            self.assertEqual(request.get_header("Cookie"), opener.requests[0].get_header("Cookie"))
            self.assertEqual(opener.requests[0].get_header("User-agent"), _PCS_UA)
            self.assertEqual(request.get_header("User-agent"), _PAN_UA)
            self.assertEqual(opener.requests[2].get_header("User-agent"), _PAN_UA)
            self.assertNotIn("synthetic", request.full_url)
            self.assertNotIn("synthetic", request.data.decode("ascii"))
            self.assertNotIn("SECRET_NEVER_ECHO", json.dumps(result))

    def test_legacy_auth_rejections_can_use_template_identity(self):
        opener = Opener([{"errno": -6}, {"errno": -6},
                         {"errno": 0, "result": {"loginstate": "1", "uk": 123}}, {"errno": 0, "list": []}])
        result = self.invoke(opener)
        self.assertEqual(result["identity_profile"], "pan_template")
        self.assertEqual(result["account"]["name"], "网盘用户 123")
        self.assertEqual(len(result["identity_attempts"]), 3)
        self.assertEqual(len(opener.requests), 4)
        self.assertEqual(opener.requests[0].get_header("User-agent"), _PCS_UA)
        self.assertEqual(opener.requests[1].get_header("User-agent"), "")
        self.assertEqual(opener.requests[2].get_header("User-agent"), _PAN_UA)
        self.assertEqual(opener.requests[3].get_header("User-agent"), _PAN_UA)

    def test_template_requires_explicit_logged_in_unique_uk_and_success_code(self):
        invalid = [{"errno": 0}, {"errno": 0, "result": []},
                   {"result": {"loginstate": 1, "uk": 123}},
                   {"errno": 0, "result": {"uk": 123}},
                   {"errno": 0, "result": {"loginstate": True, "uk": 123}},
                   {"errno": 0, "result": {"loginstate": "01", "uk": 123}},
                   {"errno": 0, "result": {"loginstate": 1, "uk": True}},
                   {"errno": 0, "result": {"loginstate": 1, "uk": 0}},
                   {"errno": 0, "result": {"loginstate": 1, "uk": 2**64}},
                   {"errno": 0, "result": {"loginstate": 1, "records": [{"uk": 123}]}}]
        for data in invalid:
            with self.subTest(data=data):
                opener = Opener([{"errno": 2}, data])
                exc = self.assert_code("invalid_identity", lambda: self.invoke(opener))
                self.assertEqual(exc.details["profile"], "pan_template")
                self.assertEqual(len(opener.requests), 2)
                self.assertFalse(self.source.exists())

    def test_template_logged_out_state_and_root_failure_never_save(self):
        for state in (0, "0"):
            opener = Opener([{"errno": 2}, {"errno": 0, "result": {"loginstate": state, "uk": 123}}])
            exc = self.assert_code("authentication_required", lambda: self.invoke(opener))
            self.assertEqual(exc.details["profile"], "pan_template")
            self.assertFalse(self.source.exists())
        opener = Opener([{"errno": 2}, {"errno": 0, "result": {"loginstate": 1, "uk": 123}}, {"errno": -6}])
        exc = self.assert_code("authentication_required", lambda: self.invoke(opener))
        self.assertEqual(exc.details["stage"], "root_list")
        self.assertEqual(exc.details["identity_profile"], "pan_template")
        self.assertFalse(self.source.exists())

    def test_template_duplicate_keys_and_reflected_credential_are_not_returned(self):
        opener = Opener([{"errno": 2}, b'{"errno":0,"result":{"loginstate":1,"uk":123,"uk":456}}'])
        self.assert_code("invalid_response", lambda: self.invoke(opener))
        self.assertFalse(self.source.exists())
        opener = Opener([{"errno": 2}, {"errno": 0, "result": {"loginstate": 1, "uk": 123,
                                                               "username": "synthetic-session"}},
                         {"errno": 0, "list": []}])
        result = self.invoke(opener)
        self.assertEqual(result["account"]["name"], "网盘用户 123")
        self.assertNotIn("synthetic-session", json.dumps(result))

    def test_cancelled_contract_fallback_never_sends_template_or_saves(self):
        calls = []
        def cancelled():
            calls.append(True)
            return len(calls) == 2
        opener = Opener([{"errno": 2}])
        self.assert_code("login_cancelled", lambda: self.invoke(opener, cancelled=cancelled))
        self.assertEqual(len(opener.requests), 1)
        self.assertFalse(self.source.exists())

    def test_invalid_existing_config_is_preserved_byte_for_byte(self):
        self.private.mkdir()
        self.source.write_bytes(b"invalid-existing-config SECRET")
        self.assert_code("invalid_config", lambda: self.invoke(self.opener()))
        self.assertEqual(self.source.read_bytes(), b"invalid-existing-config SECRET")

    def test_duplicate_existing_account_is_not_silently_replaced(self):
        self.private.mkdir()
        data = {"baidu_user_list": [{"uid": 123}, {"uid": 123}]}
        self.source.write_text(json.dumps(data), encoding="utf-8")
        self.assert_code("invalid_config", lambda: self.invoke(self.opener()))
        self.assertEqual(json.loads(self.source.read_text(encoding="utf-8")), data)

    def test_invalid_existing_transport_options_do_not_get_overwritten(self):
        self.private.mkdir()
        for option in ({"appid": False}, {"pan_ua": "bad\r\nheader"}):
            config = {"baidu_user_list": [], **option}
            self.source.write_text(json.dumps(config), encoding="utf-8")
            previous = self.source.read_bytes()
            self.assert_code("invalid_config", lambda: self.invoke(self.opener()))
            self.assertEqual(self.source.read_bytes(), previous)

    def test_import_opener_uses_redirect_blocking_handler(self):
        opener = self.opener()
        with patch("baidu_netdisk.session_import.urllib.request.build_opener", return_value=opener) as builder:
            import_cookie(COOKIE, self.private)
        self.assertIsInstance(builder.call_args_list[0].args[0], _NoRedirect)

    def test_invalid_timeout_is_rejected_before_network(self):
        for timeout in (0, True, 301, "60"):
            self.assert_code("invalid_timeout", lambda: import_cookie(COOKIE, self.private, timeout))

    def test_cancelled_event_before_verification_does_not_request_or_save(self):
        cancelled = threading.Event()
        cancelled.set()
        opener = self.opener()
        self.assert_code("login_cancelled", lambda: self.invoke(opener, cancelled=cancelled))
        self.assertFalse(opener.requests)
        self.assertFalse(self.source.exists())

    def test_cancelled_at_final_write_preserves_existing_config(self):
        self.private.mkdir()
        original = b'{"baidu_active_uid":999,"baidu_user_list":[{"uid":999,"name":"original"}]}'
        self.source.write_bytes(original)
        calls = []
        def cancelled():
            calls.append(True)
            # Before requests, after identity, after root list, and under lock
            # immediately before atomic_json. Cancel only the final generation.
            return len(calls) == 4
        opener = self.opener()
        with patch("baidu_netdisk.session_import.atomic_json") as write:
            self.assert_code("login_cancelled", lambda: self.invoke(opener, cancelled=cancelled))
            write.assert_not_called()
        self.assertEqual(len(opener.requests), 2)
        self.assertEqual(self.source.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
