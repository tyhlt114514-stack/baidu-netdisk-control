from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

from baidu_netdisk.api import ApiBackend, MIB
from baidu_netdisk.common import NetdiskError, file_lock


class FakeTokens:
    def access_token(self):
        return "test-access-token"

    def status(self):
        return {"authorized": True}


class FakeHttp:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.calls = []
        self.payload = b"download content"
        self.download_callback = None

    def request_json(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if not self.responses:
            raise AssertionError("Unexpected request: " + str(kwargs.get("params", {}).get("method")))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if callable(response):
            return response(url, kwargs)
        return response

    def download(self, url, destination, headers=None, expected_size=None):
        self.calls.append((url, {"download": True, "headers": headers, "expected_size": expected_size}))
        destination.write_bytes(self.payload)
        if self.download_callback:
            self.download_callback()
        return {"bytes": len(self.payload)}


def part_success(url, kwargs):
    assert url.startswith("https://c3.pcs.baidu.com/rest/2.0/pcs/superfile2")
    body = kwargs["body"]
    boundary = kwargs["headers"]["Content-Type"].split("boundary=", 1)[1]
    payload = body.split(b"\r\n\r\n", 1)[1].rsplit(("\r\n--" + boundary + "--\r\n").encode(), 1)[0]
    return {"md5": hashlib.md5(payload).hexdigest()}


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.settings = SimpleNamespace(state_dir=self.root / "state", allowed_local_roots=[self.root],
                                        remote_root="/apps/测试应用", timeout=30)
        self.remote = "/apps/测试应用/test.bin"

    def tearDown(self):
        self.temp.cleanup()

    def backend(self, responses):
        http = FakeHttp(responses)
        return ApiBackend(self.settings, FakeTokens(), http), http

    def item(self, size=1, fs_id=42, **extras):
        return {"path": self.remote, "fs_id": fs_id, "size": size, "isdir": 0, **extras}

    def locate(self):
        return {"error_code": 0, "servers": [{"server": "https://c3.pcs.baidu.com"}]}

    def assert_code(self, code, action):
        with self.assertRaises(NetdiskError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)

    def test_scope_is_enforced_before_any_request(self):
        backend, http = self.backend([])
        self.assert_code("remote_path_denied", lambda: backend.list_files("/私人资料"))
        self.assert_code("remote_path_denied", lambda: backend.copy(self.remote, "/elsewhere"))
        self.assert_code("app_root_protected", lambda: backend.delete(self.settings.remote_root))
        self.assertEqual(http.calls, [])

    def test_private_state_cannot_be_uploaded_or_downloaded(self):
        self.settings.state_dir.mkdir()
        secret = self.settings.state_dir / "oauth.dpapi.json"
        secret.write_text("private credentials", encoding="utf-8")
        backend, http = self.backend([])
        self.assert_code("private_path_denied", lambda: backend.upload(secret, self.remote))
        self.assert_code("private_path_denied", lambda: backend.download(42, secret, overwrite=True))
        self.assert_code("private_path_denied", lambda: backend.download(42, self.settings.state_dir / "new.json"))
        self.assertEqual(http.calls, [])

    def test_upload_honors_shared_process_lock_before_request(self):
        local = self.root / "locked.bin"
        local.write_bytes(b"X")
        backend, http = self.backend([])
        lock_path = (self.settings.state_dir / "upload-locks" /
                     (hashlib.sha256(self.remote.encode()).hexdigest() + ".lock"))
        with file_lock(lock_path):
            with patch("baidu_netdisk.api.file_lock", side_effect=lambda path: file_lock(path, timeout=0)):
                self.assert_code("backend_busy", lambda: backend.upload(local, self.remote))
        self.assertEqual(http.calls, [])

    def test_server_cannot_return_root_or_outside_paths(self):
        for path in ("/", "/apps/另一个应用/test.bin"):
            backend, _ = self.backend([{"errno": 0, "list": [{"path": path, "fs_id": 42}]}])
            self.assert_code("remote_path_denied", backend.list_files)

    def test_nested_business_error_is_not_http_success(self):
        backend, _ = self.backend([{"errno": 0, "data": {"errno": 20012}}])
        self.assert_code("baidu_20012", backend.list_files)

    def test_missing_business_code_is_not_success(self):
        backend, _ = self.backend([{"total": 100}])
        self.assert_code("invalid_response", backend.quota)

    def test_list_maps_root_and_search_omits_recursion_when_false(self):
        backend, http = self.backend([{"errno": 0, "list": []}, {"errno": 0, "list": []}])
        self.assertEqual(backend.list_files()["path"], self.settings.remote_root)
        backend.search("中文", recursive=False)
        self.assertNotIn("recursion", http.calls[1][1]["params"])
        self.assertEqual(http.calls[1][1]["params"]["num"], 500)

    def test_unknown_id_is_resolved_inside_app_before_metadata(self):
        backend, http = self.backend([{"errno": 0, "list": [self.item()]},
                                     {"errno": 0, "list": [self.item(dlink="sensitive-link")]}])
        result = backend.file_info([42])
        self.assertEqual(http.calls[0][1]["params"]["method"], "list")
        self.assertEqual(json.loads(http.calls[1][1]["data"]["target"]), [self.remote])
        self.assertNotIn("dlink", result["list"][0])

    def test_unknown_id_outside_scope_never_requests_metadata(self):
        backend, http = self.backend([{"errno": 0, "list": []}])
        self.assert_code("file_not_found", lambda: backend.file_info([99]))
        self.assertEqual(len(http.calls), 1)

    def test_partial_manager_error_is_reported(self):
        backend, _ = self.backend([{"errno": 0, "info": [{"path": self.remote, "errno": -9}]}])
        self.assert_code("baidu_-9", lambda: backend.rename(self.remote, "new.bin"))

    def test_manager_without_per_item_code_is_not_complete(self):
        backend, _ = self.backend([{"errno": 0, "info": [{"path": self.remote}]}])
        self.assert_code("invalid_response", lambda: backend.rename(self.remote, "new.bin"))

    def test_async_manager_is_not_reported_complete(self):
        backend, http = self.backend([{"errno": 0, "info": [], "taskid": 123}])
        self.assertFalse(backend.rename(self.remote, "new.bin")["completed"])
        self.assertEqual(http.calls[0][1]["data"]["ondup"], "fail")
        self.assertEqual(http.calls[0][1]["data"]["async"], 0)

    def test_mkdir_uses_directory_parameters_only(self):
        backend, http = self.backend([{"errno": 0, "path": self.remote, "fs_id": 42, "isdir": 1}])
        backend.mkdir(self.remote)
        self.assertEqual(http.calls[0][1]["data"], {"path": self.remote, "isdir": 1, "rtype": 0})

    def test_upload_empty_missing_list_means_first_part_and_verifies(self):
        local = self.root / "source.bin"
        local.write_bytes(b"hello upload")
        size = local.stat().st_size
        backend, http = self.backend([
            {"errno": 0, "list": []},
            {"errno": 0, "path": self.remote, "uploadid": "task", "block_list": []},
            self.locate(), part_success,
            {"errno": 0, **self.item(size)},
            {"errno": 0, "list": [self.item(size, md5="CLOUD_HASH_IS_NOT_REAL_MD5")]},
        ])
        result = backend.upload(local, self.remote)
        self.assertTrue(result["verified"])
        self.assertEqual(result["uploaded_bytes"], size)
        self.assertEqual(result["parts_uploaded"], 1)
        self.assertEqual(http.calls[1][1]["data"]["rtype"], 0)
        self.assertEqual(http.calls[4][1]["data"]["rtype"], 0)
        self.assertEqual(http.calls[2][1]["params"]["appid"], 250528)
        self.assertFalse(list((self.settings.state_dir / "uploads").glob("*.json")))

    def test_upload_resume_uses_server_missing_parts(self):
        local = self.root / "two-parts.bin"
        local.write_bytes(b"A" * (4 * MIB) + b"B")
        size = local.stat().st_size
        backend, http = self.backend([
            {"errno": 0, "list": []},
            {"errno": 0, "uploadid": "existing-task", "block_list": [0, 1]},
            self.locate(), part_success, NetdiskError("network_error", "offline"),
        ])
        self.assert_code("network_error", lambda: backend.upload(local, self.remote))
        state_files = list((self.settings.state_dir / "uploads").glob("*.json"))
        self.assertEqual(len(state_files), 1)
        self.assertEqual(json.loads(state_files[0].read_text(encoding="utf-8"))["completed_parts"], [0])
        http.responses += [{"errno": 0, "list": []},
                           {"errno": 0, "uploadid": "existing-task", "block_list": [1]},
                           self.locate(), part_success, {"errno": 0, **self.item(size)},
                           {"errno": 0, "list": [self.item(size)]}]
        result = backend.upload(local, self.remote)
        self.assertEqual(http.calls[6][1]["data"]["uploadid"], "existing-task")
        self.assertEqual(result["uploaded_bytes"], 1)
        self.assertEqual(result["parts_uploaded"], 1)

    def test_upload_refuses_existing_file_unless_explicit(self):
        local = self.root / "source.bin"
        local.write_bytes(b"X")
        backend, http = self.backend([{"errno": 0, "list": [self.item()]}])
        self.assert_code("file_exists", lambda: backend.upload(local, self.remote))
        self.assertEqual(len(http.calls), 1)

    def test_upload_overwrite_is_explicit_in_both_stages(self):
        local = self.root / "overwrite.bin"
        local.write_bytes(b"X")
        backend, http = self.backend([
            {"errno": 0, "list": [self.item()]},
            {"errno": 0, "uploadid": "task", "block_list": [0]}, self.locate(), part_success,
            {"errno": 0, **self.item()}, {"errno": 0, "list": [self.item()]},
        ])
        backend.upload(local, self.remote, overwrite=True)
        self.assertEqual(http.calls[1][1]["data"]["rtype"], 3)
        self.assertEqual(http.calls[4][1]["data"]["rtype"], 3)

    def test_zero_byte_file_still_uploads_one_verified_part(self):
        local = self.root / "empty.bin"
        local.write_bytes(b"")
        backend, _ = self.backend([
            {"errno": 0, "list": []},
            {"errno": 0, "uploadid": "task", "block_list": [0]}, self.locate(), part_success,
            {"errno": 0, **self.item(0)}, {"errno": 0, "list": [self.item(0)]},
        ])
        result = backend.upload(local, self.remote)
        self.assertEqual(result["parts_total"], 1)
        self.assertEqual(result["local_md5"], hashlib.md5(b"").hexdigest())

    def test_upload_verifies_part_md5_before_create(self):
        local = self.root / "source.bin"
        local.write_bytes(b"X")
        backend, http = self.backend([{"errno": 0, "list": []},
                                     {"errno": 0, "uploadid": "task", "block_list": [0]},
                                     self.locate(), {"md5": "wrong"}])
        self.assert_code("upload_hash_mismatch", lambda: backend.upload(local, self.remote))
        self.assertFalse(any(k["params"]["method"] == "create" for _, k in http.calls))

    def test_upload_rejects_invalid_sequence_and_untrusted_host(self):
        local = self.root / "source.bin"
        local.write_bytes(b"X")
        backend, http = self.backend([{"errno": 0, "list": []},
                                     {"errno": 0, "uploadid": "task", "block_list": [1]}])
        self.assert_code("invalid_response", lambda: backend.upload(local, self.remote))
        self.assertEqual(len(http.calls), 2)
        backend, _ = self.backend([{"errno": 0, "list": []},
                                   {"errno": 0, "uploadid": "task", "block_list": [0]},
                                   {"error_code": 0, "servers": [{"server": "https://baidu.com.evil.test"}]}])
        self.assert_code("invalid_upload_host", lambda: backend.upload(local, self.remote))

    def test_upload_host_uses_returned_expiry_and_rejects_expired_response(self):
        backend, _ = self.backend([{**self.locate(), "expire": 5}])
        host, refresh_after = backend._upload_host(self.remote, "task")
        self.assertEqual(host, "https://c3.pcs.baidu.com")
        self.assertEqual(refresh_after, 4)
        backend, _ = self.backend([{**self.locate(), "expire": 0}])
        self.assert_code("invalid_upload_host", lambda: backend._upload_host(self.remote, "task"))

    def test_download_preserves_signature_and_publishes_checked_bytes(self):
        size = len(b"download content")
        item = self.item(size, dlink="https://d.pcs.baidu.com/file?sign=untouched%2Fsignature")
        backend, http = self.backend([{"errno": 0, "list": [self.item(size)]}, {"errno": 0, "list": [item]}])
        target = self.root / "download.bin"
        result = backend.download(42, target)
        self.assertEqual(target.read_bytes(), http.payload)
        self.assertTrue(result["verified"])
        self.assertIn("sign=untouched%2Fsignature&access_token=test-access-token", http.calls[-1][0])
        self.assertNotIn("dlink", result)

    def test_download_does_not_clobber_file_created_during_transfer(self):
        size = len(b"download content")
        item = self.item(size, dlink="https://d.pcs.baidu.com/file?sign=a")
        backend, http = self.backend([{"errno": 0, "list": [self.item(size)]}, {"errno": 0, "list": [item]}])
        target = self.root / "racing.bin"
        http.download_callback = lambda: target.write_bytes(b"preserve me")
        self.assert_code("file_exists", lambda: backend.download(42, target))
        self.assertEqual(target.read_bytes(), b"preserve me")
        self.assertFalse(list(self.root.glob(".baidu-download-*")))

    def test_download_wrong_size_never_publishes_target(self):
        item = self.item(999, dlink="https://d.pcs.baidu.com/file?sign=a")
        backend, _ = self.backend([{"errno": 0, "list": [self.item(999)]}, {"errno": 0, "list": [item]}])
        target = self.root / "bad-download.bin"
        self.assert_code("download_size_mismatch", lambda: backend.download(42, target))
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob(".baidu-download-*")))

    def test_share_is_explicitly_unsupported(self):
        backend, http = self.backend([])
        self.assert_code("unsupported_share", lambda: backend.share([42]))
        self.assertFalse(backend.status()["share_supported"])
        self.assertEqual(http.calls, [])


if __name__ == "__main__":
    unittest.main()
