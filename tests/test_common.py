"""Offline boundary tests for paths, config, redaction and HTTP transport."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import Mock, patch

from baidu_netdisk.common import (NetdiskError, atomic_json, checked_local, file_lock,
                                 normalize_remote, process_alive, redact)
from baidu_netdisk.config import Settings
from baidu_netdisk.http import HttpClient, _BaiduRedirect, trusted_url


class CommonTests(unittest.TestCase):
    def test_remote_normalization_and_invalid_paths(self):
        self.assertEqual(normalize_remote("///文件//子目录/"), "/文件/子目录")
        for path in ("relative", "/a/../b", "/a/./b", "/a\\b", "/a\x00b"):
            with self.subTest(path=path), self.assertRaises(NetdiskError) as caught:
                normalize_remote(path)
            self.assertEqual(caught.exception.code, "invalid_path")
        with self.assertRaises(NetdiskError):
            normalize_remote("/", allow_root=False)

    def test_local_roots_block_traversal_and_sibling_prefixes(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "allowed"
            root.mkdir()
            source = root / "a.txt"
            source.write_text("test", encoding="utf-8")
            self.assertEqual(checked_local(source, [root], must_exist=True), source.resolve())
            for path in (root / ".." / "outside.txt", base / "allowed-sibling" / "a.txt"):
                with self.subTest(path=path), self.assertRaises(NetdiskError) as caught:
                    checked_local(path, [root])
                self.assertEqual(caught.exception.code, "local_path_denied")
            with self.assertRaises(NetdiskError):
                checked_local("relative.txt", [root])
            with self.assertRaises(NetdiskError):
                checked_local(source, [])
            with self.assertRaises(NetdiskError):
                checked_local(root, [root])
            with self.assertRaises(NetdiskError):
                checked_local(source, [root], directory=True)
            with self.assertRaises(NetdiskError) as caught:
                checked_local(root / "missing.txt", [root], must_exist=True)
            self.assertEqual(caught.exception.code, "local_file_missing")

    def test_local_symlink_cannot_escape_allowed_root(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root, outside = base / "allowed", base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "secret.txt").write_text("private", encoding="utf-8")
            link = root / "linked"
            junction = False
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                if os.name != "nt":
                    self.skipTest(f"OS does not permit test symlinks: {type(exc).__name__}")
                # Directory junctions exercise the same escape on Windows without
                # Developer Mode or SeCreateSymbolicLinkPrivilege.
                made = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(link), str(outside)],
                                      capture_output=True, timeout=10)
                if made.returncode:
                    self.skipTest("OS does not permit a test symlink or junction")
                junction = True
            try:
                with self.assertRaises(NetdiskError) as caught:
                    checked_local(link / "secret.txt", [root], must_exist=True)
                self.assertEqual(caught.exception.code, "local_path_denied")
            finally:
                if junction:
                    link.rmdir()
                else:
                    link.unlink()

    def test_credentials_redacted_recursively_and_in_messages(self):
        secret = "UNIQUE_SECRET_DO_NOT_PRINT"
        payload = {"access_token": secret, "rows": [{"text": f"url?access_token={secret}&x=1"}],
                   "authorization": f"Bearer {secret}", "safe": "public"}
        self.assertNotIn(secret, json.dumps(redact(payload)))
        self.assertEqual(redact(payload)["safe"], "public")
        self.assertNotIn(secret, redact(f"Authorization: Bearer {secret}"))
        error = NetdiskError("failure", f"request failed access_token={secret}", {"cookie": secret})
        self.assertNotIn(secret, json.dumps(error.as_dict()))

    def test_atomic_json_and_config_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "nested" / "config.json"
            atomic_json(path, {"backend": "openapi", "allowed_local_roots": [temp], "client_id": "app"})
            settings = Settings.load(path)
            self.assertEqual(settings.backend, "openapi")
            self.assertEqual(settings.allowed_local_roots, [Path(temp).resolve()])
            self.assertEqual(list(path.parent.glob("*.tmp")), [])
            for data in ({"backend": "shell", "allowed_local_roots": [temp]},
                         {"backend": "openapi", "allowed_local_roots": []},
                         {"backend": "openapi"}, [],
                         {"backend": "openapi", "allowed_local_roots": temp},
                         {"backend": "openapi", "allowed_local_roots": ["relative"]},
                         {"backend": "openapi", "allowed_local_roots": [temp], "timeout": -1},
                         {"backend": "openapi", "allowed_local_roots": [temp], "timeout": "nan"}):
                atomic_json(path, data)
                with self.subTest(data=data), self.assertRaises(NetdiskError) as caught:
                    Settings.load(path)
                self.assertEqual(caught.exception.code, "invalid_config")

    def test_cross_process_file_lock_and_process_liveness(self):
        with tempfile.TemporaryDirectory() as temp:
            lock_path = Path(temp) / "operation.lock"
            script = ("import sys,time\nfrom pathlib import Path\n"
                      "from baidu_netdisk.common import file_lock\n"
                      "with file_lock(Path(sys.argv[1])):\n"
                      " print('LOCKED',flush=True)\n time.sleep(10)\n")
            child = subprocess.Popen([getattr(sys, "_base_executable", sys.executable), "-u", "-c", script, str(lock_path)],
                                     cwd=str(Path(__file__).resolve().parents[1]),
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(), "LOCKED")
                self.assertTrue(process_alive(child.pid))
                with self.assertRaises(NetdiskError) as caught:
                    with file_lock(lock_path, timeout=0.15):
                        self.fail("A live process already owns this lock")
                self.assertEqual(caught.exception.code, "backend_busy")
            finally:
                child.terminate()
                child.communicate(timeout=10)
            self.assertFalse(process_alive(child.pid))
            with file_lock(lock_path, timeout=1):
                pass


class HttpTests(unittest.TestCase):
    def test_only_baidu_https_hosts_and_safe_redirects(self):
        for url in ("https://pan.baidu.com/rest", "https://openapi.baidu.com/oauth", "https://d.pcs.baidu.com/x",
                    "https://c1.baidupcs.com/x", "https://baidu.com:443/x"):
            self.assertEqual(trusted_url(url), url)
        for url in ("http://pan.baidu.com/x", "https://baidu.com.evil.test/x", "https://evilbaidu.com/x",
                    "https://baidu.com@evil.test/x", "https://user@pan.baidu.com/x", "https://pan.baidu.com:444/x",
                    "file:///C:/secret.txt", "https://127.0.0.1/x"):
            with self.subTest(url=url), self.assertRaises(NetdiskError) as caught:
                trusted_url(url)
            self.assertEqual(caught.exception.code, "untrusted_url")
        request = urllib.request.Request("https://pan.baidu.com/x?access_token=secret")
        with self.assertRaises(NetdiskError) as caught:
            _BaiduRedirect().redirect_request(request, None, 302, "Found", {}, "https://evil.test/x")
        self.assertEqual(caught.exception.code, "untrusted_url")

    def test_http_errors_do_not_leak_urls_or_response_pages(self):
        client = HttpClient()
        secret = "DO_NOT_PRINT_TOKEN"
        request = urllib.request.Request(f"https://pan.baidu.com/x?access_token={secret}")
        cases = (
            urllib.error.HTTPError(request.full_url, 403, secret, {}, io.BytesIO(secret.encode())),
            urllib.error.URLError(secret),
            TimeoutError(secret),
        )
        for exception in cases:
            with self.subTest(exception=type(exception).__name__):
                client.opener = Mock()
                client.opener.open.side_effect = exception
                with self.assertRaises(NetdiskError) as caught:
                    client._open(request)
                self.assertNotIn(secret, json.dumps(caught.exception.as_dict()))

    def test_json_structure_size_and_invalid_data(self):
        client = HttpClient()
        for raw in (b"not JSON", b"[]", b'"value"', b"x" * (8 * 1024 * 1024 + 1)):
            with self.subTest(length=len(raw)), patch.object(client, "_open", return_value=io.BytesIO(raw)):
                with self.assertRaises(NetdiskError) as caught:
                    client.request_json("https://pan.baidu.com/x")
                self.assertEqual(caught.exception.code, "invalid_response")
        with patch.object(client, "_open", return_value=io.BytesIO(b'{"ok":true}')):
            self.assertEqual(client.request_json("https://pan.baidu.com/x"), {"ok": True})

    def test_download_reports_size_mismatch(self):
        client = HttpClient()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "download.part"
            with patch.object(client, "_open", return_value=io.BytesIO(b"abc")):
                with self.assertRaises(NetdiskError) as caught:
                    client.download("https://c1.baidupcs.com/x", path, expected_size=4)
            self.assertEqual(caught.exception.code, "download_size_mismatch")
            with patch.object(client, "_open", return_value=io.BytesIO(b"abc")):
                self.assertEqual(client.download("https://c1.baidupcs.com/x", path, expected_size=3), {"bytes": 3})


if __name__ == "__main__":
    unittest.main()
