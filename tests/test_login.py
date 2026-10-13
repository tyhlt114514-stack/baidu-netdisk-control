"""Offline login-input/diagnostic tests; no real credentials, UI or login."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cli
from baidu_netdisk.common import NetdiskError
from baidu_netdisk.login import diagnose_login, normalize_cookie, normalize_login_input


class LoginTests(unittest.TestCase):
    def test_explicit_bduss_value_input_builds_cookie_without_echo(self):
        for value in ("fake-session-value", "BDUSS=fake-session-value", '"fake-session-value"', "fakeValue=="):
            with self.subTest(form=value[:5]):
                self.assertTrue(normalize_login_input(value, "bduss").startswith("BDUSS="))
        self.assertEqual(normalize_login_input(" fake-session-value ", "bduss"), "BDUSS=fake-session-value")
        with self.assertRaises(NetdiskError) as caught:
            normalize_login_input("fake-session-value", "cookie")
        self.assertEqual(caught.exception.code, "cookie_missing_bduss")

    def test_bduss_value_mode_rejects_other_fields_partial_values_and_controls(self):
        for value in ("STOKEN=FAKE_SECRET_NOT_PUBLIC", "BDUSS_BFESS=FAKE_SECRET_NOT_PUBLIC",
                      "BDUSS=FAKE_SECRET_NOT_PUBLIC; STOKEN=other", "fake***value", "fake...value",
                      "fake…value", "fake\x00value", "fake\nvalue", "fake value", ""):
            with self.assertRaises(NetdiskError) as caught:
                normalize_login_input(value, "bduss")
            self.assertEqual(caught.exception.code, "invalid_bduss")
            self.assertNotIn("FAKE_SECRET_NOT_PUBLIC", json.dumps(caught.exception.as_dict()))

    def test_cookie_header_prefix_and_outer_quotes_are_normalized(self):
        expected = "BDUSS=fake-bduss; STOKEN=fake-stoken; BAIDUID=fake-id"
        for value in (expected, " Cookie: " + expected + " ", "cookies: " + expected,
                      'Cookie: "' + expected + '"', "'" + expected + "'",
                      '"Cookie: ' + expected + '"'):
            with self.subTest(wrapper=value[:10]):
                self.assertEqual(normalize_cookie(value), expected)

    def test_bduss_bfess_alone_is_explicitly_not_the_required_credential(self):
        with self.assertRaises(NetdiskError) as caught:
            normalize_cookie("BDUSS_BFESS=fake-session; STOKEN=fake-token")
        self.assertEqual(caught.exception.code, "cookie_missing_bduss")
        details = caught.exception.details
        self.assertFalse(details["has_bduss"])
        self.assertTrue(details["has_bduss_bfess"])
        self.assertNotIn("fake-session", json.dumps(caught.exception.as_dict()))
        with self.assertRaises(NetdiskError) as caught:
            normalize_cookie("STOKEN=fake-token")
        self.assertEqual(caught.exception.code, "cookie_missing_bduss")

    def test_ctrl_v_control_and_multiline_headers_are_rejected_without_echo(self):
        for value in ("BDUSS=fake-secret\x16", "BDUSS=fake-secret;\r\nX-Other: fake-secret",
                      "BDUSS=fake-secret\x00", "BDUSS=fake-secret\x7f"):
            with self.assertRaises(NetdiskError) as caught:
                normalize_cookie(value)
            self.assertEqual(caught.exception.code, "invalid_cookie")
            self.assertNotIn("fake-secret", json.dumps(caught.exception.as_dict()))

    def test_diagnostic_categories_have_fixed_safe_hints(self):
        cases = {
            "Permission denied": "configuration_permission",
            "Incorrect Usage": "command_arguments",
            "dial tcp connectex: connection refused": "network",
            "百度需要验证码": "baidu_verification",
            "BDUSS 无效，请重新登录": "session_invalid",
            "FATAL ERROR config file error": "configuration_error",
            "unrecognized backend message": "upstream_login_failed",
        }
        for message, category in cases.items():
            with self.subTest(category=category):
                result = diagnose_login(message, "", 1)
                self.assertEqual(result["category"], category)
                self.assertTrue(result["raw_output_hidden"])
                self.assertTrue(result["hint"])
                self.assertNotIn(message, result["hint"])

    def test_raw_stdout_stderr_never_escape_and_error_codes_are_numeric_only(self):
        secret = "FAKE_SECRET_NOT_PUBLIC"
        raw = (f"BDUSS={secret}\nSTOKEN={secret}\nCookie: BDUSS={secret}\n"
               f"access_token={secret}\nerror_code: -6\n错误码: 31045\nerrno={secret}\n"
               "errno=1234567890123456789\n")
        result = diagnose_login(raw.encode(), ("stderr " + secret).encode(), 1)
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(set(result["error_codes"]), {"-6", "31045"})
        self.assertTrue(all(code.lstrip("-").isdigit() for code in result["error_codes"]))
        self.assertEqual(result["backend_exit_code"], 1)
        self.assertEqual(set(result), {"backend_exit_code", "category", "error_codes", "hint", "raw_output_hidden"})

    def test_cli_failed_native_session_import_outputs_safe_diagnostic_and_returns_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            executable = root / "fake-pcs.exe"
            executable.write_bytes(b"fake-not-executed")
            config = root / "config.json"
            config.write_text(json.dumps({"backend": "pcs", "state_dir": str(root / "state"),
                "allowed_local_roots": [str(root)], "pcs_executable": str(executable)}), encoding="utf-8")
            fake_cookie = "BDUSS=FAKE_SECRET_NOT_PUBLIC; STOKEN=FAKE_STOKEN_NOT_PUBLIC"
            failed = NetdiskError("network_error", "无法连接百度网盘，请检查网络后重新导入会话。",
                                  {"cookie": fake_cookie, "status": 503})
            stream = io.StringIO()
            with patch.object(sys, "argv", ["cli.py", "--config", str(config), "login", "--method", "cookie"]), \
                    patch("cli.getpass.getpass", return_value=fake_cookie), \
                    patch("baidu_netdisk.session_import.import_cookie", side_effect=failed) as invoked, \
                    patch("cli.subprocess.run", side_effect=AssertionError("Credentials must not become process arguments")), \
                    contextlib.redirect_stdout(stream):
                exit_code = cli.main()
            output = stream.getvalue()
            self.assertEqual(exit_code, 1)
            self.assertIn('"error": "network_error"', output)
            self.assertIn('"status": 503', output)
            self.assertNotIn("FAKE_SECRET_NOT_PUBLIC", output)
            self.assertNotIn("FAKE_STOKEN_NOT_PUBLIC", output)
            self.assertEqual(invoked.call_args.args[0], fake_cookie)
            self.assertEqual(invoked.call_args.args[1], root / "state" / "pcs")
            diagnostic = (root / "state" / "login-diagnostic.json").read_text(encoding="utf-8")
            self.assertNotIn("FAKE_SECRET_NOT_PUBLIC", diagnostic)
            self.assertNotIn("FAKE_STOKEN_NOT_PUBLIC", diagnostic)
            self.assertEqual(json.loads(diagnostic)["error"], "network_error")

    def test_cli_native_session_import_success_persists_public_identity_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            executable = root / "fake-pcs.exe"
            executable.write_bytes(b"fake-not-executed")
            config = root / "config.json"
            config.write_text(json.dumps({"backend": "pcs", "state_dir": str(root / "state"),
                "allowed_local_roots": [str(root)], "pcs_executable": str(executable)}), encoding="utf-8")
            fake_cookie = "BDUSS=FAKE_SECRET_NOT_PUBLIC; STOKEN=FAKE_STOKEN_NOT_PUBLIC"
            status = {"ok": True, "account_id": "100", "name": "本地测试身份", "netdisk_read_verified": True}
            stream = io.StringIO()
            with patch.object(sys, "argv", ["cli.py", "--config", str(config), "login", "--method", "cookie"]), \
                    patch("cli.getpass.getpass", return_value=fake_cookie), \
                    patch("baidu_netdisk.session_import.import_cookie", return_value=status) as invoked, \
                    patch("cli.subprocess.run", side_effect=AssertionError("Credentials must not become process arguments")), \
                    contextlib.redirect_stdout(stream):
                exit_code = cli.main()
            self.assertEqual(exit_code, 0)
            self.assertEqual(invoked.call_count, 1)
            output = stream.getvalue()
            self.assertIn('"account_id": "100"', output)
            self.assertNotIn("FAKE_SECRET_NOT_PUBLIC", output)
            self.assertNotIn("FAKE_STOKEN_NOT_PUBLIC", output)
            diagnostic = json.loads((root / "state" / "login-diagnostic.json").read_text(encoding="utf-8"))
            self.assertEqual(diagnostic, status)

    def test_cli_qr_route_verifies_locally_and_persists_public_result(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            executable = root / "fake-pcs.exe"
            executable.write_bytes(b"not-executed")
            config = root / "config.json"
            config.write_text(json.dumps({"backend": "pcs", "state_dir": str(root / "state"),
                "allowed_local_roots": [str(root)], "pcs_executable": str(executable)}), encoding="utf-8")
            status = {"ok": True, "account_id": "pcs:123", "netdisk_read_verified": True}
            def dialog(verify):
                return verify("BDUSS=FAKE_QR_SECRET_NOT_PUBLIC", cancelled=lambda: False)
            stream = io.StringIO()
            with patch.object(sys, "argv", ["cli.py", "--config", str(config), "login", "--method", "qr"]), \
                    patch("baidu_netdisk.qr_login.masked_qr_login_dialog", side_effect=dialog), \
                    patch("baidu_netdisk.session_import.import_cookie", return_value=status) as invoked, \
                    patch("cli.subprocess.run", side_effect=AssertionError("No credential process arguments")), \
                    contextlib.redirect_stdout(stream):
                code = cli.main()
            self.assertEqual(code, 0)
            self.assertFalse(invoked.call_args.kwargs["cancelled"]())
            self.assertNotIn("FAKE_QR_SECRET_NOT_PUBLIC", stream.getvalue())
            self.assertEqual(json.loads((root / "state" / "login-diagnostic.json").read_text(encoding="utf-8")), status)

    def test_cli_qr_failure_records_safe_error_without_import(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            executable = root / "fake-pcs.exe"
            executable.write_bytes(b"not-executed")
            config = root / "config.json"
            config.write_text(json.dumps({"backend": "pcs", "state_dir": str(root / "state"),
                "allowed_local_roots": [str(root)], "pcs_executable": str(executable)}), encoding="utf-8")
            stream = io.StringIO()
            with patch.object(sys, "argv", ["cli.py", "--config", str(config), "login", "--method", "qr"]), \
                    patch("baidu_netdisk.qr_login.masked_qr_login_dialog", side_effect=NetdiskError("qr_creation_failed", "未取得二维码。")), \
                    patch("baidu_netdisk.session_import.import_cookie") as invoked, \
                    contextlib.redirect_stdout(stream):
                code = cli.main()
            self.assertEqual(code, 1)
            invoked.assert_not_called()
            diagnostic = json.loads((root / "state" / "login-diagnostic.json").read_text(encoding="utf-8"))
            self.assertEqual(diagnostic["error"], "qr_creation_failed")


if __name__ == "__main__":
    unittest.main()
