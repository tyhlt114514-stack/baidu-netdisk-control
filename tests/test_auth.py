"""Credential storage and OAuth behavior tested without login or network."""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from baidu_netdisk.auth import SecretStore, TokenStore, _dpapi
from baidu_netdisk.common import NetdiskError


class AuthTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "DPAPI is Windows-only")
    def test_dpapi_roundtrip_and_disk_contains_no_plaintext(self):
        payload = {"access_token": "test-access-token-unique", "refresh_token": "test-refresh-token-unique",
                   "client_secret": "test-client-secret-unique", "expires_at": 1234567}
        encrypted = _dpapi(json.dumps(payload).encode())
        self.assertNotIn(b"test-access-token-unique", encrypted)
        self.assertEqual(json.loads(_dpapi(encrypted, decrypt=True)), payload)
        with tempfile.TemporaryDirectory() as temp:
            store = SecretStore(Path(temp))
            self.assertEqual(store.load(), {})
            store.save(payload)
            raw = store.path.read_text(encoding="utf-8")
            for key in ("access_token", "refresh_token", "client_secret"):
                self.assertNotIn(payload[key], raw)
            self.assertEqual(store.load(), payload)

    def test_corrupted_credentials_produce_sanitized_error(self):
        with tempfile.TemporaryDirectory() as temp:
            store = SecretStore(Path(temp))
            for raw in ("bad", "{}", '{"ciphertext":"not valid base64"}'):
                store.path.write_text(raw, encoding="utf-8")
                with self.subTest(raw=raw), self.assertRaises(NetdiskError) as caught:
                    store.load()
                self.assertEqual(caught.exception.code, "credential_storage_error")

    def _token_store(self, temp):
        settings = SimpleNamespace(state_dir=Path(temp), timeout=10, client_id="test-client", redirect_uri="oob")
        store = TokenStore(settings, http=Mock())
        store.secrets = Mock()
        return store

    def test_valid_token_and_status_do_not_expose_credentials(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            store = self._token_store(temp)
            store.secrets.load.return_value = {"access_token": "test-access", "refresh_token": "test-refresh",
                                              "client_secret": "test-secret", "expires_at": time.time() + 3600}
            self.assertEqual(store.access_token(), "test-access")
            store.http.request_json.assert_not_called()
            status = json.dumps(store.status())
            for secret in ("test-access", "test-refresh", "test-secret"):
                self.assertNotIn(secret, status)
            self.assertTrue(store.status()["authorized"])

    def test_expired_token_refresh_is_saved_and_reused(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            store = self._token_store(temp)
            data = {"access_token": "expired", "refresh_token": "refresh", "client_secret": "secret", "expires_at": 0}
            store.secrets.load.return_value = data
            store.http.request_json.return_value = {"access_token": "new-token", "refresh_token": "new-refresh", "expires_in": 3600}
            self.assertEqual(store.access_token(), "new-token")
            params = store.http.request_json.call_args.kwargs["data"]
            self.assertEqual(params["grant_type"], "refresh_token")
            self.assertEqual(params["client_id"], "test-client")
            store.secrets.save.assert_called_once()
            saved = store.secrets.save.call_args.args[0]
            self.assertEqual(saved["client_secret"], "secret")
            self.assertGreater(saved["expires_at"], time.time() + 3500)
            self.assertEqual(store.access_token(), "new-token")
            store.http.request_json.assert_called_once()

    def test_missing_expired_and_env_credentials(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            store = self._token_store(temp)
            for data in ({}, {"access_token": "expired", "expires_at": 0}):
                store.secrets.load.return_value = data
                with self.assertRaises(NetdiskError) as caught:
                    store.access_token()
                self.assertEqual(caught.exception.code, "login_required")
            store.secrets.load.return_value = {}
            with patch.dict(os.environ, {"BAIDU_ACCESS_TOKEN": "temporary-env-token"}):
                self.assertEqual(store.access_token(), "temporary-env-token")
                self.assertTrue(store.status()["authorized"])
                self.assertNotIn("temporary-env-token", json.dumps(store.status()))

    def test_authorization_failure_does_not_save_or_leak_secret(self):
        with tempfile.TemporaryDirectory() as temp:
            store = self._token_store(temp)
            store.http.request_json.return_value = {"error": "invalid_grant", "error_description": "secret-value"}
            with self.assertRaises(NetdiskError) as caught:
                store._exchange({"client_secret": "secret-value"}, {"client_secret": "secret-value"})
            self.assertEqual(caught.exception.code, "authorization_failed")
            self.assertNotIn("secret-value", json.dumps(caught.exception.as_dict()))
            store.secrets.save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
