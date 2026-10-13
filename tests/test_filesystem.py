"""End-to-end file-view tests against an entirely local fake cloud backend."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import posixpath
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from baidu_netdisk.common import NetdiskError
from baidu_netdisk.config import Settings
from baidu_netdisk.filesystem import CloudFilesystem, sha256_file
from baidu_netdisk.service import NetdiskService


class FakeBackend:
    """Exact metadata/bytes contract, with failures injected at publication edges."""
    def __init__(self, account_id="100", mode="pcs", remote_root="/"):
        self.account_id, self.mode, self.remote_root = account_id, mode, remote_root
        self.entries, self.payloads = {}, {}
        self.downloads, self.uploads, self.created = [], [], []
        self.download_hook = self.upload_hook = None
        self.download_verified = True
        self.add_dir("/")

    def account_identity(self):
        return {"account_id": self.account_id}

    def add_dir(self, path):
        self.entries[path] = {"path": path, "name": posixpath.basename(path) or "/",
            "parent": posixpath.dirname(path) or "/", "is_dir": True, "size": 0,
            "mtime": 100, "md5": None, "fs_id": str(len(self.entries) + 1)}

    def add_file(self, path, data, fs_id="555", mtime=100):
        self.payloads[path] = data
        self.entries[path] = {"path": path, "name": posixpath.basename(path),
            "parent": posixpath.dirname(path) or "/", "is_dir": False, "size": len(data),
            "mtime": mtime, "md5": hashlib.md5(data).hexdigest(), "fs_id": fs_id}

    def stat_entry(self, path):
        if path not in self.entries:
            raise NetdiskError("not_found", "Fake cloud file not found")
        return {"entry": dict(self.entries[path])}

    def list_entries(self, path, start=0, limit=1000):
        entries = sorted((dict(entry) for entry in self.entries.values()
                          if entry["path"] != path and entry["parent"] == path), key=lambda entry: entry["path"])
        page = entries[start:start + limit]
        return {"ok": True, "path": path, "start": start, "limit": limit,
                "account_id": self.account_id, "entries": page,
                "has_more": start + len(page) < len(entries), "next_start": start + len(page)}

    def download_to(self, remote, destination, expected_entry):
        destination = Path(destination)
        if destination.exists():
            raise AssertionError("Materialization must download to a nonexistent staged file")
        self.downloads.append(remote)
        destination.write_bytes(self.payloads[remote])
        if self.download_hook:
            self.download_hook(remote, destination)
        return {"ok": True, "verified": self.download_verified, "size": destination.stat().st_size}

    def mkdir(self, path):
        parent = posixpath.dirname(path) or "/"
        if parent not in self.entries or not self.entries[parent]["is_dir"]:
            raise NetdiskError("parent_missing", "Fake cloud requires existing parent")
        self.created.append(path)
        self.add_dir(path)
        return {"ok": True}

    def upload(self, source, destination, overwrite=False):
        source = Path(source)
        remote = posixpath.join(destination, source.name) if self.mode == "pcs" else destination
        parent = posixpath.dirname(remote) or "/"
        if parent not in self.entries or not self.entries[parent]["is_dir"]:
            raise NetdiskError("parent_missing", "Fake cloud requires existing parent")
        self.uploads.append({"source": str(source), "remote": remote, "overwrite": overwrite})
        self.add_file(remote, source.read_bytes())
        if self.upload_hook:
            self.upload_hook(source, remote)
        return {"ok": True, "verified": True}


class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state, self.cache = self.root / ".private", self.root / "cache"
        self.state.mkdir()
        self.backend = FakeBackend()
        self.fs = CloudFilesystem(self.backend, self.cache, [self.root], self.state, "100", "pcs")
        self.remote = "/资料/项目说明.txt"
        self.backend.add_dir("/资料")
        self.backend.add_file(self.remote, "正文第一行\n正文第二行\n".encode())

    def tearDown(self):
        self.temp.cleanup()

    def source(self, name="source.txt", data=b"local upload fixture"):
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_unicode_file_materializes_once_then_cache_hit(self):
        first = self.fs.materialize(self.remote)
        self.assertTrue(first["verified"])
        self.assertFalse(first["cache_hit"])
        self.assertEqual(Path(first["local_path"]).read_bytes(), self.backend.payloads[self.remote])
        self.assertEqual(first["sha256"], hashlib.sha256(self.backend.payloads[self.remote]).hexdigest())
        second = self.fs.materialize(self.remote)
        self.assertTrue(second["cache_hit"])
        self.assertEqual(second["local_path"], first["local_path"])
        self.assertEqual(self.backend.downloads, [self.remote])

    def test_remote_metadata_and_fsid_change_invalidate_cache(self):
        first = self.fs.materialize(self.remote)
        self.backend.entries[self.remote].update(fs_id="556", mtime=101)
        self.assertIsNone(self.fs.cached(self.remote))
        refreshed = self.fs.materialize(self.remote)
        self.assertFalse(refreshed["cache_hit"])
        self.assertEqual(refreshed["entry"]["fs_id"], "556")
        self.assertEqual(refreshed["local_path"], first["local_path"])
        self.assertEqual(len(self.backend.downloads), 2)

    def test_same_size_local_cache_tampering_is_detected_by_checksum(self):
        result = self.fs.materialize(self.remote)
        local = Path(result["local_path"])
        local.write_bytes(b"x" * local.stat().st_size)
        self.assertIsNone(self.fs.cached(self.remote))
        refreshed = self.fs.materialize(self.remote)
        self.assertEqual(Path(refreshed["local_path"]).read_bytes(), self.backend.payloads[self.remote])
        self.assertEqual(len(self.backend.downloads), 2)

    def test_malformed_receipt_is_cache_miss_and_can_be_rebuilt(self):
        result = self.fs.materialize(self.remote)
        receipt = Path(result["local_path"]).parent / "receipt.json"
        for malformed in ("[]", "12", "bad JSON"):
            receipt.write_text(malformed, encoding="utf-8")
            self.assertIsNone(self.fs.cached(self.remote))
        repaired = self.fs.materialize(self.remote)
        self.assertTrue(repaired["verified"])
        self.assertIsInstance(json.loads(receipt.read_text(encoding="utf-8")), dict)

    def test_equal_remote_path_and_fsid_never_share_cache_across_accounts(self):
        first = self.fs.materialize(self.remote)
        other_backend = FakeBackend("200")
        other_backend.add_file(self.remote, b"other account contents", fs_id="555")
        other = CloudFilesystem(other_backend, self.cache, [self.root], self.state, "200", "pcs")
        second = other.materialize(self.remote)
        self.assertNotEqual(first["local_path"], second["local_path"])
        self.assertEqual(Path(first["local_path"]).read_bytes(), self.backend.payloads[self.remote])
        self.assertEqual(Path(second["local_path"]).read_bytes(), b"other account contents")

    def test_account_switch_during_download_prevents_publication(self):
        self.backend.download_hook = lambda remote, stage: setattr(self.backend, "account_id", "200")
        with self.assertRaises(NetdiskError) as caught:
            self.fs.materialize(self.remote)
        self.assertEqual(caught.exception.code, "account_changed")
        self.assertEqual(list(self.cache.rglob("content.*")), [])
        self.assertEqual(list(self.cache.rglob("receipt.json")), [])

    def test_account_switch_while_checking_cache_prevents_old_account_return(self):
        self.fs.materialize(self.remote)
        original = sha256_file
        def switch_after_hash(path):
            digest = original(path)
            self.backend.account_id = "200"
            return digest
        with patch("baidu_netdisk.filesystem.sha256_file", side_effect=switch_after_hash):
            with self.assertRaises(NetdiskError) as caught:
                self.fs.cached(self.remote)
        self.assertEqual(caught.exception.code, "account_changed")

    def test_remote_change_or_wrong_download_size_never_publishes(self):
        self.backend.download_hook = lambda remote, stage: self.backend.entries[remote].update(mtime=200)
        with self.assertRaises(NetdiskError) as caught:
            self.fs.materialize(self.remote)
        self.assertEqual(caught.exception.code, "remote_changed")
        self.assertEqual(list(self.cache.rglob("content.*")), [])
        self.backend.download_hook = lambda remote, stage: stage.write_bytes(b"bad")
        with self.assertRaises(NetdiskError) as caught:
            self.fs.materialize(self.remote)
        self.assertEqual(caught.exception.code, "download_size_mismatch")
        self.assertEqual(list(self.cache.rglob("content.*")), [])

    def test_unverified_native_download_never_publishes(self):
        self.backend.download_verified = False
        with self.assertRaises(NetdiskError) as caught:
            self.fs.materialize(self.remote)
        self.assertEqual(caught.exception.code, "download_unverified")
        self.assertEqual(list(self.cache.rglob("content.*")), [])

    def test_download_exact_target_and_explicit_overwrite(self):
        target = self.root / "接收" / "新的文件名.txt"
        result = self.fs.download_file(self.remote, target)
        self.assertTrue(result["verified"])
        self.assertEqual(target.read_bytes(), self.backend.payloads[self.remote])
        target.write_bytes(b"existing user file")
        with self.assertRaises(NetdiskError) as caught:
            self.fs.download_file(self.remote, target)
        self.assertEqual(caught.exception.code, "local_file_exists")
        self.assertEqual(target.read_bytes(), b"existing user file")
        self.fs.download_file(self.remote, target, overwrite=True)
        self.assertEqual(target.read_bytes(), self.backend.payloads[self.remote])

    def test_download_race_does_not_clobber_new_local_target(self):
        target = self.root / "race.txt"
        original_link = os.link
        def race(stage, local):
            Path(local).write_bytes(b"file concurrently created by user")
            return original_link(stage, local)
        with patch("baidu_netdisk.filesystem.os.link", side_effect=race):
            with self.assertRaises(NetdiskError) as caught:
                self.fs.download_file(self.remote, target)
        self.assertEqual(caught.exception.code, "local_file_exists")
        self.assertEqual(target.read_bytes(), b"file concurrently created by user")
        self.assertEqual(list(self.root.glob(".netdisk-*.part")), [])

    def test_private_and_traversal_paths_are_rejected_before_transfer(self):
        private = self.state / "pcs_config.json"
        private.write_bytes(b"private credential fixture")
        for operation in (lambda: self.fs.upload_file(private, "/credential.json"),
                          lambda: self.fs.download_file(self.remote, private, overwrite=True),
                          lambda: self.fs.download_file(self.remote, self.root / ".." / "outside.txt"),
                          lambda: self.fs.materialize("/资料/../other.txt")):
            with self.assertRaises(NetdiskError):
                operation()
        self.assertEqual(self.backend.downloads, [])
        self.assertEqual(self.backend.uploads, [])
        self.assertEqual(private.read_bytes(), b"private credential fixture")
        with self.assertRaises(NetdiskError) as caught:
            CloudFilesystem(self.backend, self.state / "cache", [self.root], self.state, "100", "pcs")
        self.assertEqual(caught.exception.code, "invalid_cache_root")

    def test_pcs_upload_supports_new_basename_and_creates_parents_without_cloud_intermediate(self):
        source = self.source("original.txt", "上传内容".encode())
        remote = "/新建目录/二级/不同名称.md"
        result = self.fs.upload_file(source, remote)
        self.assertTrue(result["verified"])
        self.assertEqual(self.backend.created, ["/新建目录", "/新建目录/二级"])
        self.assertEqual([item["remote"] for item in self.backend.uploads], [remote])
        self.assertEqual(Path(self.backend.uploads[0]["source"]).name, "不同名称.md")
        self.assertNotEqual(Path(self.backend.uploads[0]["source"]), source)
        self.assertFalse(Path(self.backend.uploads[0]["source"]).exists())
        self.assertEqual(self.backend.payloads[remote], source.read_bytes())
        self.assertNotIn("/新建目录/二级/original.txt", self.backend.entries)
        self.assertEqual(result["local_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())

    def test_invalid_pcs_target_basename_is_rejected_before_cloud_parent_creation(self):
        source = self.source()
        with patch.object(self.backend, "stat_entry", wraps=self.backend.stat_entry) as metadata:
            for basename in ("CON.txt", "invalid?.txt", "trailing."):
                with self.assertRaises(NetdiskError) as caught:
                    self.fs.upload_file(source, "/new/parent/" + basename)
                self.assertEqual(caught.exception.code, "invalid_remote_name")
            self.assertEqual(metadata.call_args_list, [])
        self.assertEqual(self.backend.created, [])
        self.assertEqual(self.backend.uploads, [])
        self.assertFalse(self.cache.exists())

    def test_upload_existing_destination_and_pcs_overwrite_are_fail_closed(self):
        source = self.source()
        with self.assertRaises(NetdiskError) as caught:
            self.fs.upload_file(source, self.remote)
        self.assertEqual(caught.exception.code, "file_exists")
        with self.assertRaises(NetdiskError) as caught:
            self.fs.upload_file(source, self.remote, overwrite=True)
        self.assertEqual(caught.exception.code, "unsupported_overwrite")
        self.assertEqual(self.backend.uploads, [])

    def test_upload_source_change_or_wrong_remote_size_is_not_verified_success(self):
        source = self.source()
        self.backend.upload_hook = lambda staged, remote: source.write_bytes(b"changed original source")
        with self.assertRaises(NetdiskError) as caught:
            self.fs.upload_file(source, "/first.txt")
        self.assertEqual(caught.exception.code, "source_changed")
        source.write_bytes(b"stable original source")
        self.backend.upload_hook = lambda staged, remote: self.backend.add_file(remote, b"bad")
        with self.assertRaises(NetdiskError) as caught:
            self.fs.upload_file(source, "/second.txt")
        self.assertEqual(caught.exception.code, "upload_unverified")

    def test_openapi_preserves_complete_remote_name_and_overwrite_flag(self):
        backend = FakeBackend(mode="openapi", remote_root="/apps/test")
        backend.add_dir("/apps")
        backend.add_dir("/apps/test")
        fs = CloudFilesystem(backend, self.cache, [self.root], self.state, "100", "openapi")
        source = self.source("original.txt")
        result = fs.upload_file(source, "/apps/test/新父级/new.md", overwrite=True)
        self.assertTrue(result["verified"])
        self.assertEqual(backend.created, ["/apps/test/新父级"])
        self.assertEqual(backend.uploads[0]["remote"], "/apps/test/新父级/new.md")
        self.assertEqual(Path(backend.uploads[0]["source"]), source)
        self.assertTrue(backend.uploads[0]["overwrite"])

    def test_openapi_missing_app_root_stops_without_querying_or_creating_apps(self):
        backend = FakeBackend(mode="openapi", remote_root="/apps/test")
        fs = CloudFilesystem(backend, self.cache, [self.root], self.state, "100", "openapi")
        with patch.object(backend, "stat_entry", wraps=backend.stat_entry) as metadata:
            with self.assertRaises(NetdiskError) as caught:
                fs.mkdir("/apps/test/new/child")
        self.assertEqual(caught.exception.code, "app_root_missing")
        self.assertEqual(backend.created, [])
        self.assertEqual([call.args[0] for call in metadata.call_args_list],
                         ["/apps/test/new/child", "/apps/test/new", "/apps/test"])

    def test_openapi_logical_root_maps_to_app_and_cannot_recurse_forever(self):
        backend = FakeBackend(mode="openapi", remote_root="/apps/test")
        fs = CloudFilesystem(backend, self.cache, [self.root], self.state, "100", "openapi")
        with patch.object(backend, "stat_entry", wraps=backend.stat_entry) as metadata:
            with self.assertRaises(NetdiskError) as caught:
                fs.mkdir("/")
        self.assertEqual(caught.exception.code, "app_root_missing")
        self.assertEqual([call.args[0] for call in metadata.call_args_list], ["/apps/test"])
        backend.add_dir("/apps/test")
        self.assertEqual(fs.mkdir("/")["path"], "/apps/test")
        self.assertEqual(backend.created, [])

    def test_openapi_mkdir_rejects_outside_scope_before_metadata_or_write(self):
        backend = FakeBackend(mode="openapi", remote_root="/apps/test")
        fs = CloudFilesystem(backend, self.cache, [self.root], self.state, "100", "openapi")
        with patch.object(backend, "stat_entry", wraps=backend.stat_entry) as metadata:
            for path in ("/apps", "/apps/test-other/child", "/elsewhere"):
                with self.assertRaises(NetdiskError) as caught:
                    fs.mkdir(path)
                self.assertEqual(caught.exception.code, "remote_path_denied")
            self.assertEqual(metadata.call_args_list, [])
        self.assertEqual(backend.created, [])

    def test_root_mkdir_does_not_return_success_for_different_account(self):
        self.backend.account_id = "200"
        with self.assertRaises(NetdiskError) as caught:
            self.fs.mkdir("/")
        self.assertEqual(caught.exception.code, "account_changed")
        self.assertEqual(self.backend.created, [])

    def test_service_first_read_background_fetch_then_retry_reads_naturally(self):
        service = NetdiskService()
        service._settings = Settings("pcs", self.state, [self.root])
        service._settings.cache_root = self.cache
        service._structured = lambda: self.backend
        service._filesystem = self.fs
        try:
            prepared = service.read_file(self.remote)
            self.assertEqual(prepared["status"], "preparing")
            self.assertIn("job_id", prepared)
            service.jobs.executor.shutdown(wait=True)
            job = service.jobs.get(prepared["job_id"])
            self.assertEqual(job["status"], "succeeded")
            result = service.read_file(self.remote, start_line=2, line_count=1)
            self.assertEqual(result["text"], "正文第二行\n")
            raw = service.read_bytes(self.remote, offset=0, limit=6)
            self.assertEqual(base64.b64decode(raw["data_base64"]), self.backend.payloads[self.remote][:6])
            self.assertEqual(self.backend.downloads, [self.remote])
        finally:
            if service._jobs is not None:
                service._jobs.executor.shutdown(wait=True)


if __name__ == "__main__":
    unittest.main()
