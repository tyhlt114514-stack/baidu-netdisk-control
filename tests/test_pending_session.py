"""Local encrypted retry tests; fixtures contain no real account or credential."""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import cli
from baidu_netdisk.auth import _dpapi
from baidu_netdisk.common import NetdiskError
from baidu_netdisk.pending_session import PendingSession


SECRET = "FAKE_PENDING_BDUSS_NEVER_PUBLIC"
SECOND_SECRET = "FAKE_NEWER_PENDING_BDUSS_NEVER_PUBLIC"
STOKEN = "FAKE_PENDING_STOKEN_NEVER_PUBLIC"
COOKIE = f"BDUSS={SECRET}; STOKEN={STOKEN}"
SECOND_COOKIE = f"BDUSS={SECOND_SECRET}"


@unittest.skipUnless(os.name == "nt", "Pending credentials use current-user Windows DPAPI")
class PendingSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.pending = PendingSession(self.state)

    def assert_safe(self, value):
        text = value if isinstance(value, str) else json.dumps(value)
        for secret in (SECRET, SECOND_SECRET, STOKEN, COOKIE):
            self.assertNotIn(secret, text)

    def assert_failure(self, code, action):
        with self.assertRaises(NetdiskError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        self.assert_safe(caught.exception.as_dict())
        self.assert_safe(str(caught.exception))
        return caught.exception

    def envelope(self):
        return json.loads(self.pending.path.read_text(encoding="utf-8"))

    def write_envelope(self, envelope):
        self.pending.path.parent.mkdir(parents=True, exist_ok=True)
        self.pending.path.write_text(json.dumps(envelope), encoding="utf-8")

    def write_encrypted_record(self, changes):
        self.pending.save(COOKIE, source="qr")
        envelope = self.envelope()
        record = self.pending.load()
        record.update(changes)
        for key in ("generation", "source", "created_at", "expires_at"):
            if key in record:
                envelope[key] = record[key]
        envelope["ciphertext"] = base64.b64encode(_dpapi(json.dumps(record).encode())).decode()
        self.write_envelope(envelope)

    def config(self):
        executable = self.root / "fake-pcs.exe"
        executable.write_bytes(b"offline-fixture-not-executed")
        config = self.root / "config.json"
        config.write_text(json.dumps({"backend": "pcs", "state_dir": str(self.state),
                                     "allowed_local_roots": [str(self.root)],
                                     "pcs_executable": str(executable)}), encoding="utf-8")
        return config

    def test_missing_pending_status_and_clear_never_fabricate_authorization(self):
        self.assertEqual(self.pending.status(), {"available": False})
        self.assert_failure("pending_login_missing", self.pending.load)
        self.pending.clear("0" * 32)
        self.assertFalse(self.pending.path.exists())
        self.assertEqual(self.pending.status(), {"available": False})

    def test_actual_dpapi_roundtrip_and_public_status_contain_no_plain_cookie(self):
        with patch("baidu_netdisk.pending_session.time.time", return_value=1000):
            generation = self.pending.save(COOKIE, source="qr")
            value = self.pending.load()
            status = self.pending.status()
        self.assertEqual(value["cookie"], COOKIE)
        self.assertEqual(value["generation"], generation)
        self.assertEqual(value["expires_at"] - value["created_at"], 1800)
        self.assertEqual(status, {"available": True, "source": "qr", "expires_at": 2800,
                                  "protection": "windows-dpapi-current-user"})
        self.assert_safe(status)
        for file in self.state.iterdir():
            self.assert_safe(file.read_bytes().decode("utf-8", errors="replace"))
        self.assertEqual(list(self.state.glob("*.tmp")), [])
        envelope = self.envelope()
        self.assertEqual(envelope["protection"], "windows-dpapi-current-user")
        self.assertNotIn(SECRET.encode(), base64.b64decode(envelope["ciphertext"]))

    def test_invalid_cookie_and_source_do_not_encrypt_or_create_pending_file(self):
        for cookie, source, code in (("STOKEN=" + STOKEN, "qr", "missing_bduss"),
                                     (COOKIE + "\nX-Other: value", "qr", "invalid_cookie"),
                                     (COOKIE, "unrecognized", "invalid_credential_type")):
            with self.subTest(source=source, code=code), patch("baidu_netdisk.pending_session._dpapi") as encrypt:
                self.assert_failure(code, lambda: self.pending.save(cookie, source=source))
                encrypt.assert_not_called()
                self.assertFalse(self.pending.path.exists())

    def test_exact_expiry_boundary_deletes_cookie_and_cannot_be_reused(self):
        with patch("baidu_netdisk.pending_session.time.time", return_value=1000):
            self.pending.save(COOKIE, source="cookie")
        with patch("baidu_netdisk.pending_session.time.time", return_value=2799.999):
            self.assertEqual(self.pending.load()["cookie"], COOKIE)
        with patch("baidu_netdisk.pending_session.time.time", return_value=2800):
            self.assert_failure("pending_login_expired", self.pending.load)
        self.assertFalse(self.pending.path.exists())
        self.assertEqual(self.pending.status(), {"available": False})
        self.assert_failure("pending_login_missing", self.pending.load)

    def test_future_clock_and_invalid_encrypted_lifetimes_cannot_extend_authorization(self):
        with patch("baidu_netdisk.pending_session.time.time", return_value=1000):
            self.pending.save(COOKIE, source="qr")
        with patch("baidu_netdisk.pending_session.time.time", return_value=900):
            self.assert_failure("credential_storage_error", self.pending.load)
        for changes in ({"created_at": True}, {"expires_at": float("nan")},
                        {"expires_at": float("inf")}, {"expires_at": 1000, "created_at": 1000},
                        {"created_at": 1000, "expires_at": 2801}):
            with self.subTest(changes=changes), patch("baidu_netdisk.pending_session.time.time", return_value=1000):
                self.write_encrypted_record(changes)
                self.assert_failure("credential_storage_error", self.pending.load)

    def test_corrupt_json_oversized_and_duplicate_envelopes_fail_safely(self):
        self.state.mkdir(parents=True, exist_ok=True)
        for raw in ("not-json", "[]", "null", "{}", '{"version":2}',
                    '{"version":1,"version":1}', "x" * 200000):
            with self.subTest(size=len(raw)):
                self.pending.path.write_text(raw, encoding="utf-8")
                self.assert_failure("credential_storage_error", self.pending.load)
                self.assertEqual(self.pending.status(), {"available": False, "error": "credential_storage_error"})
                self.assert_safe(self.pending.status())

    def test_invalid_base64_and_tampered_actual_dpapi_cipher_are_not_used(self):
        self.pending.save(COOKIE, source="bduss")
        original = self.envelope()
        cipher = bytearray(base64.b64decode(original["ciphertext"]))
        cipher[len(cipher) // 2] ^= 1
        for encoded_cipher in ("not base64!", "", base64.b64encode(bytes(cipher)).decode()):
            with self.subTest(length=len(encoded_cipher)):
                envelope = dict(original, ciphertext=encoded_cipher)
                self.write_envelope(envelope)
                self.assert_failure("credential_storage_error", self.pending.load)
                self.assertFalse(self.pending.status()["available"])

    def test_cross_user_dpapi_rejection_is_safe_and_never_returns_cookie(self):
        self.pending.save(COOKIE, source="qr")
        # A different Windows user cannot be launched in this test; simulate the
        # exact DPAPI failure boundary while retaining a real encrypted fixture.
        with patch("baidu_netdisk.pending_session._dpapi", side_effect=NetdiskError(
                "credential_storage_error", "Windows 无法读取或保存此账号的加密凭据。")) as decrypt:
            self.assert_failure("credential_storage_error", self.pending.load)
            self.assertEqual(self.pending.status(), {"available": False, "error": "credential_storage_error"})
            self.assertTrue(decrypt.call_args.kwargs["decrypt"])

    def test_envelope_metadata_cannot_change_authenticated_encrypted_record(self):
        self.pending.save(COOKIE, source="qr")
        original = self.envelope()
        for key, value in (("generation", "1" * 32), ("source", "cookie"),
                           ("created_at", original["created_at"] - 1),
                           ("expires_at", original["expires_at"] + 1800)):
            with self.subTest(field=key):
                self.write_envelope(dict(original, **{key: value}))
                self.assert_failure("credential_storage_error", self.pending.load)

    def test_clear_old_generation_preserves_newer_authorization(self):
        first = self.pending.save(COOKIE, source="qr")
        second = PendingSession(self.state).save(SECOND_COOKIE, source="cookie")
        self.assertNotEqual(first, second)
        self.pending.clear(first)
        self.assertEqual(self.pending.load()["cookie"], SECOND_COOKIE)
        self.pending.clear(second)
        self.assertFalse(self.pending.path.exists())
        self.assertEqual(self.pending.status(), {"available": False})

    def test_relative_and_actual_junction_private_paths_are_rejected(self):
        self.assert_failure("unsafe_config", lambda: PendingSession(Path("relative-state")))
        outside = self.root / "outside"
        outside.mkdir()
        junction = self.root / "state-junction"
        made = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
                              capture_output=True, timeout=10)
        if made.returncode:
            self.skipTest("OS does not permit the test directory junction")
        try:
            self.assert_failure("unsafe_config", lambda: PendingSession(junction))
            self.assertEqual(list(outside.iterdir()), [])
        finally:
            junction.rmdir()

    def test_cli_retry_success_decrypts_only_in_process_and_clears_matching_generation(self):
        config = self.config()
        status = {"ok": True, "account_id": "pcs:123", "netdisk_read_verified": True}
        for replace_pending in (False, True):
            with self.subTest(newer=replace_pending):
                self.pending.save(COOKIE, source="qr")
                def imported(cookie, state, *, timeout):
                    self.assertEqual(cookie, COOKIE)
                    self.assertEqual(state, self.state / "pcs")
                    self.assertTrue(1 <= timeout <= 300)
                    if replace_pending:
                        self.pending.save(SECOND_COOKIE, source="cookie")
                    return status
                stream = io.StringIO()
                with patch.object(sys, "argv", ["cli.py", "--config", str(config), "login-retry"]), \
                        patch("baidu_netdisk.session_import.import_cookie", side_effect=imported) as invoked, \
                        patch("cli.getpass.getpass", side_effect=AssertionError("Retry must not prompt")), \
                        patch("cli.subprocess.run", side_effect=AssertionError("No credential subprocess")), \
                        contextlib.redirect_stdout(stream):
                    code = cli.main()
                self.assertEqual(code, 0)
                invoked.assert_called_once()
                self.assert_safe(stream.getvalue())
                diagnostic = json.loads((self.state / "login-diagnostic.json").read_text(encoding="utf-8"))
                self.assertEqual(diagnostic, status)
                self.assert_safe(diagnostic)
                if replace_pending:
                    self.assertEqual(self.pending.load()["cookie"], SECOND_COOKIE)
                else:
                    self.assertFalse(self.pending.path.exists())

    def test_cli_retry_failures_record_safe_diagnostic_and_never_import_bad_pending(self):
        config = self.config()
        for outcome in ("verification_failed", "expired", "corrupt", "missing"):
            with self.subTest(outcome=outcome):
                self.pending.path.unlink(missing_ok=True)
                if outcome == "expired":
                    with patch("baidu_netdisk.pending_session.time.time", return_value=1000):
                        self.pending.save(COOKIE, source="qr")
                elif outcome == "corrupt":
                    self.pending.path.write_text('{"version":1,"ciphertext":"invalid!"}', encoding="utf-8")
                elif outcome == "verification_failed":
                    self.pending.save(COOKIE, source="qr")
                (self.state / "login-diagnostic.json").write_text('{"ok":true,"account_id":"old"}', encoding="utf-8")
                failure = NetdiskError("network_error", "无法连接百度网盘。", {"cookie": COOKIE})
                stream = io.StringIO()
                with patch.object(sys, "argv", ["cli.py", "--config", str(config), "login-retry"]), \
                        patch("baidu_netdisk.session_import.import_cookie", side_effect=failure) as invoked, \
                        patch("cli.getpass.getpass", side_effect=AssertionError("Retry must not prompt")), \
                        contextlib.redirect_stdout(stream):
                    code = cli.main()
                self.assertEqual(code, 1)
                expected = {"verification_failed": "network_error", "expired": "pending_login_expired",
                            "corrupt": "credential_storage_error", "missing": "pending_login_missing"}[outcome]
                diagnostic = json.loads((self.state / "login-diagnostic.json").read_text(encoding="utf-8"))
                self.assertFalse(diagnostic["ok"])
                self.assertEqual(diagnostic["error"], expected)
                self.assertEqual(diagnostic["pending_session"]["available"], outcome == "verification_failed")
                self.assert_safe(stream.getvalue())
                self.assert_safe(diagnostic)
                if outcome == "verification_failed":
                    invoked.assert_called_once()
                    self.assertEqual(self.pending.load()["cookie"], COOKIE)
                else:
                    invoked.assert_not_called()

    def test_cancelled_qr_before_verification_does_not_encrypt_or_import(self):
        config = self.config()
        def dialog(verify):
            return verify(COOKIE, cancelled=lambda: True)
        stream = io.StringIO()
        with patch.object(sys, "argv", ["cli.py", "--config", str(config), "login", "--method", "qr"]), \
                patch("baidu_netdisk.qr_login.masked_qr_login_dialog", side_effect=dialog), \
                patch("baidu_netdisk.pending_session._dpapi") as encrypt, \
                patch("baidu_netdisk.session_import.import_cookie") as imported, \
                contextlib.redirect_stdout(stream):
            code = cli.main()
        self.assertEqual(code, 1)
        encrypt.assert_not_called()
        imported.assert_not_called()
        self.assertFalse(self.pending.path.exists())
        self.assert_safe(stream.getvalue())

    def test_cancelled_import_clears_only_its_generation_and_preserves_newer_qr(self):
        config = self.config()
        for replaced, failure_code in ((False, "login_cancelled"), (True, "login_cancelled"),
                                       (False, "network_error"), (True, "network_error")):
            with self.subTest(replaced=replaced, error=failure_code):
                self.pending.path.unlink(missing_ok=True)
                stopped = threading.Event()
                def dialog(verify):
                    return verify(COOKIE, cancelled=stopped.is_set)
                def imported(cookie, state, *, timeout, cancelled):
                    self.assertEqual(self.pending.load()["cookie"], COOKIE)
                    if replaced:
                        self.pending.save(SECOND_COOKIE, source="qr")
                    stopped.set()
                    raise NetdiskError(failure_code, "本次授权已取消，未保存会话。")
                stream = io.StringIO()
                with patch.object(sys, "argv", ["cli.py", "--config", str(config), "login", "--method", "qr"]), \
                        patch("baidu_netdisk.qr_login.masked_qr_login_dialog", side_effect=dialog), \
                        patch("baidu_netdisk.session_import.import_cookie", side_effect=imported), \
                        contextlib.redirect_stdout(stream):
                    self.assertEqual(cli.main(), 1)
                self.assert_safe(stream.getvalue())
                if replaced:
                    self.assertEqual(self.pending.load()["cookie"], SECOND_COOKIE)
                else:
                    self.assertFalse(self.pending.path.exists())


if __name__ == "__main__":
    unittest.main()
