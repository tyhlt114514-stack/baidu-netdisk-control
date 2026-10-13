from __future__ import annotations

import hashlib
import json
import os
import posixpath
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from baidu_netdisk.common import NetdiskError
from baidu_netdisk.tree_transfer import TreeTransfer


class FakeFilesystem:
    account_id = "account-A"
    backend_name = "fake"
    remote_root = "/"

    def __init__(self):
        self.nodes = {"/": self._entry("/", True)}
        self.payloads = {}
        self.calls = []
        self.writes = []
        self.fail_upload = set()
        self.fail_download = set()
        self.fail_mkdir = set()
        self.unverified_upload = set()
        self.list_override = None
        self.after_download = None

    @staticmethod
    def _entry(path, is_dir, size=0, digest=None):
        return {"path": path, "name": posixpath.basename(path), "is_dir": is_dir,
                "size": size, "fs_id": str(int(hashlib.sha256(path.encode()).hexdigest()[:15], 16) + 1),
                "mtime": 1700000000, "ctime": 1600000000, "md5": digest}

    def directory(self, path):
        if path != "/":
            self.directory(posixpath.dirname(path))
        self.nodes[path] = self._entry(path, True)

    def file(self, path, content):
        self.directory(posixpath.dirname(path))
        self.nodes[path] = self._entry(path, False, len(content), hashlib.md5(content).hexdigest())
        self.payloads[path] = content

    def stat(self, path):
        self.calls.append(("stat", path))
        return dict(self.nodes[path]) if path in self.nodes else None

    def list_entries(self, path, start=0, limit=1000):
        self.calls.append(("list", path, start, limit))
        if self.list_override:
            value = self.list_override(path, start, limit)
            if value is not None:
                return value
        children = [dict(value) for key, value in sorted(self.nodes.items())
                    if key != "/" and posixpath.dirname(key) == path]
        entries = children[start:start + limit]
        return {"entries": entries, "start": start, "next_start": start + len(entries),
                "has_more": start + len(entries) < len(children)}

    def mkdir(self, path):
        self.calls.append(("mkdir", path))
        if path in self.fail_mkdir:
            raise NetdiskError("mkdir_failed", "mkdir failed")
        if path not in self.nodes:
            if posixpath.dirname(path) not in self.nodes:
                self.mkdir(posixpath.dirname(path))
            self.writes.append(("mkdir", path))
            self.nodes[path] = self._entry(path, True)
        return {"ok": True, "verified": True}

    def upload_file(self, local, remote, create_parents=True, overwrite=False):
        self.calls.append(("upload", remote, overwrite))
        if remote in self.fail_upload:
            raise NetdiskError("upload_failed", "upload failed access_token=SECRET")
        if remote in self.nodes and not overwrite:
            raise NetdiskError("file_exists", "exists")
        content = Path(local).read_bytes()
        self.writes.append(("upload", remote))
        self.file(remote, content)
        return {"ok": True, "verified": remote not in self.unverified_upload,
                "remote_path": remote, "size": len(content)}

    def download_file(self, remote, local, overwrite=False):
        self.calls.append(("download", remote, str(local), overwrite))
        if remote in self.fail_download:
            raise NetdiskError("download_failed", "download failed")
        local = Path(local)
        if local.exists() and not overwrite:
            raise NetdiskError("local_file_exists", "exists")
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(self.payloads[remote])
        if self.after_download:
            self.after_download(remote)
        return {"ok": True, "verified": True, "remote_path": remote, "size": len(self.payloads[remote])}


class TreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "private"
        self.source = self.root / "source"
        self.source.mkdir()
        self.fs = FakeFilesystem()
        self.transfer = TreeTransfer(self.fs, [self.root], self.state)

    def tearDown(self):
        self.temp.cleanup()

    def manifest(self, result):
        return json.loads(Path(result["manifest_path"]).read_text(encoding="utf-8"))

    def test_upload_preserves_empty_dirs_and_every_file_receipt(self):
        (self.source / "空目录").mkdir()
        (self.source / "子目录").mkdir()
        (self.source / "root.txt").write_bytes(b"ROOT")
        (self.source / "子目录" / "零字节.bin").write_bytes(b"")
        result = self.transfer.upload_tree(self.source, "/backup/tree")
        self.assertTrue(result["ok"])
        self.assertEqual(result["files_succeeded"], 2)
        self.assertEqual(result["files_failed"], 0)
        self.assertEqual(result["directories_succeeded"], 3)
        self.assertIn("/backup/tree/空目录", self.fs.nodes)
        self.assertEqual(self.fs.payloads["/backup/tree/子目录/零字节.bin"], b"")
        files = [item for item in self.manifest(result)["entries"] if item["kind"] == "file"]
        self.assertEqual(len(files), 2)
        self.assertTrue(all(item["receipt"]["verified"] for item in files))
        self.assertTrue(all(item["source_snapshot"]["sha256"] for item in files))

    def test_link_is_found_during_full_preflight_before_any_cloud_write(self):
        safe = self.source / "a-good.txt"
        unsafe = self.source / "z-junction"
        safe.write_bytes(b"GOOD")
        unsafe.mkdir()
        original = Path.lstat

        def marked_reparse(path, *args, **kwargs):
            if path == unsafe:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
            return original(path, *args, **kwargs)

        with patch.object(Path, "lstat", marked_reparse):
            result = self.transfer.upload_tree(self.source, "/backup")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "unsafe_local_path")
        self.assertEqual(self.fs.writes, [])
        self.assertFalse(any(call[0] == "upload" for call in self.fs.calls))

    def test_upload_rejects_state_and_ancestor_of_state(self):
        self.state.mkdir()
        (self.state / "credentials").write_text("secret", encoding="utf-8")
        for candidate in (self.state, self.root):
            with self.assertRaises(NetdiskError) as caught:
                self.transfer.upload_tree(candidate, "/backup")
            self.assertEqual(caught.exception.code, "private_path_denied")
        self.assertEqual(self.fs.writes, [])

    def test_remote_conflict_prevents_all_cloud_mutations(self):
        (self.source / "a.txt").write_bytes(b"NEW A")
        (self.source / "z.txt").write_bytes(b"NEW Z")
        self.fs.file("/dst/z.txt", b"OLD")
        result = self.transfer.upload_tree(self.source, "/dst")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "preflight_failed")
        self.assertEqual(self.fs.writes, [])
        self.assertEqual(self.fs.payloads["/dst/z.txt"], b"OLD")

    def test_remote_ancestor_file_conflict_is_caught_before_mkdir(self):
        (self.source / "file.txt").write_bytes(b"FILE")
        self.fs.file("/parent", b"not a directory")
        result = self.transfer.upload_tree(self.source, "/parent/sub/dst")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "remote_path_conflict")
        self.assertEqual(self.fs.writes, [])

    def test_upload_failure_reports_partial_and_resume_skips_only_verified_unchanged(self):
        (self.source / "a.txt").write_bytes(b"A")
        (self.source / "b.txt").write_bytes(b"B")
        self.fs.fail_upload.add("/dst/b.txt")
        first = self.transfer.upload_tree(self.source, "/dst")
        self.assertFalse(first["ok"])
        self.assertEqual(first["files_succeeded"], 1)
        self.assertEqual(first["files_failed"], 1)
        self.assertNotIn("SECRET", str(first))
        self.fs.fail_upload.clear()
        before = sum(operation == "upload" for operation, path in self.fs.writes)
        second = self.transfer.upload_tree(self.source, "/dst")
        self.assertTrue(second["ok"])
        self.assertEqual(second["files_resumed"], 1)
        self.assertEqual(sum(operation == "upload" for operation, path in self.fs.writes) - before, 1)

    def test_changed_hash_with_same_size_and_mtime_cannot_resume(self):
        local = self.source / "a.txt"
        local.write_bytes(b"OLD")
        self.assertTrue(self.transfer.upload_tree(self.source, "/dst")["ok"])
        original = local.stat()
        local.write_bytes(b"NEW")
        os.utime(local, ns=(original.st_atime_ns, original.st_mtime_ns))
        result = self.transfer.upload_tree(self.source, "/dst")
        self.assertFalse(result["ok"])
        self.assertEqual(result["files_resumed"], 0)
        self.assertEqual(self.fs.payloads["/dst/a.txt"], b"OLD")
        overwritten = self.transfer.upload_tree(self.source, "/dst", overwrite=True)
        self.assertTrue(overwritten["ok"])
        self.assertEqual(self.fs.payloads["/dst/a.txt"], b"NEW")

    def test_unverified_receipt_is_failure_and_is_never_resumed(self):
        (self.source / "a.txt").write_bytes(b"A")
        self.fs.unverified_upload.add("/dst/a.txt")
        first = self.transfer.upload_tree(self.source, "/dst")
        self.assertFalse(first["ok"])
        self.assertEqual(first["files_failed"], 1)
        second = self.transfer.upload_tree(self.source, "/dst")
        self.assertFalse(second["ok"])
        self.assertEqual(second["files_resumed"], 0)

    def test_download_encodes_all_invalid_and_case_colliding_names_without_loss(self):
        names = ["CON", "a:b.txt", "report.", "README.md", "readme.md"]
        for number, name in enumerate(names):
            self.fs.file("/src/" + name, (name + str(number)).encode())
        self.fs.directory("/src/空目录")
        self.fs.file("/src/nested/like?.bin", b"NESTED")
        target = self.root / "download"
        result = self.transfer.download_tree("/src", target)
        self.assertTrue(result["ok"])
        self.assertEqual(result["files_succeeded"], 6)
        self.assertEqual(result["encoded_names"], 6)
        self.assertTrue((target / "空目录").is_dir())
        manifest = self.manifest(result)
        files = [item for item in manifest["entries"] if item["kind"] == "file"]
        self.assertEqual(len({item["local_path"].casefold() for item in files}), 6)
        for item in files:
            self.assertEqual(Path(item["local_path"]).read_bytes(), self.fs.payloads[item["remote_path"]])
            self.assertTrue(TreeTransfer._safe_windows_name(Path(item["local_path"]).name))

    def test_encoded_name_cannot_collide_with_existing_remote_literal_name(self):
        encoded = TreeTransfer._encoded_name("CON")
        self.fs.file("/src/CON", b"DEVICE")
        self.fs.file("/src/" + encoded, b"LITERAL")
        result = self.transfer.download_tree("/src", self.root / "download")
        self.assertTrue(result["ok"])
        files = [item for item in self.manifest(result)["entries"] if item["kind"] == "file"]
        self.assertEqual(len({item["local_path"] for item in files}), 2)
        self.assertEqual({Path(item["local_path"]).read_bytes() for item in files}, {b"DEVICE", b"LITERAL"})

    def test_download_local_conflict_prevents_all_downloads(self):
        self.fs.file("/src/a.txt", b"A")
        self.fs.file("/src/z.txt", b"Z")
        target = self.root / "download"
        target.mkdir()
        (target / "z.txt").write_bytes(b"PRESERVED")
        result = self.transfer.download_tree("/src", target)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "preflight_failed")
        self.assertFalse(any(call[0] == "download" for call in self.fs.calls))
        self.assertEqual((target / "z.txt").read_bytes(), b"PRESERVED")
        self.assertFalse((target / "a.txt").exists())

    def test_download_preserves_existing_case_spelling_and_requires_overwrite(self):
        self.fs.file("/src/FILE.txt", b"NEW")
        target = self.root / "download"
        target.mkdir()
        existing = target / "file.TXT"
        existing.write_bytes(b"OLD")
        rejected = self.transfer.download_tree("/src", target)
        self.assertFalse(rejected["ok"])
        result = self.transfer.download_tree("/src", target, overwrite=True)
        self.assertTrue(result["ok"])
        self.assertEqual(existing.read_bytes(), b"NEW")
        self.assertEqual(len(list(target.iterdir())), 1)
        self.assertEqual(self.manifest(result)["entries"][1]["local_path"], str(existing))

    def test_download_resume_requires_remote_and_local_hashes_unchanged(self):
        self.fs.file("/src/a.txt", b"A")
        self.fs.file("/src/b.txt", b"B")
        self.fs.fail_download.add("/src/b.txt")
        target = self.root / "download"
        first = self.transfer.download_tree("/src", target)
        self.assertFalse(first["ok"])
        self.fs.fail_download.clear()
        second = self.transfer.download_tree("/src", target)
        self.assertTrue(second["ok"])
        self.assertEqual(second["files_resumed"], 1)
        (target / "a.txt").write_bytes(b"X")
        rejected = self.transfer.download_tree("/src", target)
        self.assertFalse(rejected["ok"])
        self.assertEqual((target / "a.txt").read_bytes(), b"X")

    def test_download_missing_remote_hash_does_not_allow_resume_skip(self):
        self.fs.file("/src/a.txt", b"A")
        self.fs.nodes["/src/a.txt"]["md5"] = None
        target = self.root / "download"
        self.assertTrue(self.transfer.download_tree("/src", target)["ok"])
        result = self.transfer.download_tree("/src", target)
        self.assertFalse(result["ok"])
        self.assertEqual(result["files_resumed"], 0)

    def test_remote_change_during_download_is_not_verified(self):
        self.fs.file("/src/a.txt", b"A")
        self.fs.after_download = lambda path: self.fs.nodes[path].update(mtime=1800000000)
        result = self.transfer.download_tree("/src", self.root / "download")
        self.assertFalse(result["ok"])
        self.assertEqual(result["files_failed"], 1)
        self.assertEqual(result["files"][0]["error"]["code"], "remote_changed")

    def test_download_page_failure_creates_no_destination_directory(self):
        self.fs.directory("/src")
        self.fs.list_override = lambda path, start, limit: {"entries": [], "start": 0,
                                                           "next_start": 1, "has_more": False}
        target = self.root / "download"
        result = self.transfer.download_tree("/src", target)
        self.assertFalse(result["ok"])
        self.assertFalse(target.exists())
        self.assertFalse(any(call[0] == "download" for call in self.fs.calls))

    def test_mkdir_failure_marks_branch_files_failed_but_preserves_other_branch(self):
        (self.source / "bad").mkdir()
        (self.source / "bad" / "file.txt").write_bytes(b"BAD")
        (self.source / "good.txt").write_bytes(b"GOOD")
        self.fs.fail_mkdir.add("/dst/bad")
        result = self.transfer.upload_tree(self.source, "/dst")
        self.assertFalse(result["ok"])
        self.assertEqual(result["files_succeeded"], 1)
        self.assertEqual(result["files_failed"], 1)
        self.assertEqual(result["directories_failed"], 1)
        self.assertEqual(self.fs.payloads["/dst/good.txt"], b"GOOD")
        self.assertNotIn("/dst/bad/file.txt", self.fs.payloads)

    def test_manifest_isolated_between_accounts(self):
        (self.source / "a.txt").write_bytes(b"A")
        first = self.transfer.upload_tree(self.source, "/dst")
        other_fs = FakeFilesystem()
        other_fs.account_id = "account-B"
        other = TreeTransfer(other_fs, [self.root], self.state)
        second = other.upload_tree(self.source, "/dst")
        self.assertTrue(first["ok"] and second["ok"])
        self.assertNotEqual(first["manifest_path"], second["manifest_path"])
        self.assertEqual(second["files_resumed"], 0)

    def test_private_download_target_is_rejected(self):
        with self.assertRaises(NetdiskError) as caught:
            self.transfer.download_tree("/src", self.state)
        self.assertEqual(caught.exception.code, "private_path_denied")
        self.assertEqual(self.fs.calls, [])

    def test_manifest_receipt_pages_all_entries_with_validated_identity(self):
        (self.source / "a.txt").write_bytes(b"A")
        (self.source / "empty").mkdir()
        result = self.transfer.upload_tree(self.source, "/dst")
        manifest_id = result["manifest_id"]
        self.assertEqual(len(manifest_id), 64)
        first = self.transfer.get_manifest(manifest_id, limit=1)
        second = self.transfer.get_manifest(manifest_id, offset=first["next_offset"], limit=100)
        self.assertEqual(first["count"], 3)
        self.assertTrue(first["has_more"])
        self.assertFalse(second["has_more"])
        self.assertEqual(len(first["entries"] + second["entries"]), 3)
        self.assertEqual(first["identity"]["account_id"], self.fs.account_id)
        self.assertNotIn("files", first)
        self.assertEqual(first["files_succeeded"], 1)

    def test_manifest_receipt_cannot_read_other_account_or_backend(self):
        result = self.transfer.upload_tree(self.source, "/dst")
        other_fs = FakeFilesystem()
        other_fs.account_id = "account-B"
        other = TreeTransfer(other_fs, [self.root], self.state)
        with self.assertRaises(NetdiskError) as caught:
            other.get_manifest(result["manifest_id"])
        self.assertEqual(caught.exception.code, "manifest_not_found")
        other_fs.account_id = self.fs.account_id
        other_fs.backend_name = "different-backend"
        other = TreeTransfer(other_fs, [self.root], self.state)
        with self.assertRaises(NetdiskError) as caught:
            other.get_manifest(result["manifest_id"])
        self.assertEqual(caught.exception.code, "manifest_not_found")

    def test_manifest_receipt_rejects_traversal_and_tampered_identity_digest(self):
        for value in ("../oauth.dpapi.json", "A" * 64, "0" * 63, "/" + "a" * 64):
            with self.assertRaises(NetdiskError) as caught:
                self.transfer.get_manifest(value)
            self.assertEqual(caught.exception.code, "invalid_manifest_id")
        result = self.transfer.upload_tree(self.source, "/dst")
        manifest = self.manifest(result)
        manifest["identity"]["target"] = "/another-target"
        Path(result["manifest_path"]).write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(NetdiskError) as caught:
            self.transfer.get_manifest(result["manifest_id"])
        self.assertEqual(caught.exception.code, "manifest_invalid")

    def test_api_app_root_upload_does_not_inspect_outside_authorized_scope(self):
        self.fs.remote_root = "/apps/测试应用"
        self.fs.directory(self.fs.remote_root)
        transfer = TreeTransfer(self.fs, [self.root], self.state)
        (self.source / "a.txt").write_bytes(b"A")
        result = transfer.upload_tree(self.source, self.fs.remote_root)
        self.assertTrue(result["ok"])
        for call in self.fs.calls:
            if call[0] in ("stat", "mkdir", "upload"):
                self.assertTrue(call[1] == self.fs.remote_root or call[1].startswith(self.fs.remote_root + "/"))

    def test_source_tree_change_during_remote_preflight_prevents_all_writes(self):
        (self.source / "a.txt").write_bytes(b"A")
        original = self.fs.stat
        mutated = []

        def mutate_on_stat(path):
            if not mutated:
                before = self.source.stat()
                (self.source / "new-after-enumeration.txt").write_bytes(b"NEW")
                os.utime(self.source, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
                mutated.append(True)
            return original(path)

        self.fs.stat = mutate_on_stat
        result = self.transfer.upload_tree(self.source, "/dst")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "source_changed")
        self.assertEqual(self.fs.writes, [])

    def test_preflight_conflict_does_not_destroy_other_verified_resume_receipts(self):
        (self.source / "a.txt").write_bytes(b"OLD")
        (self.source / "b.txt").write_bytes(b"B")
        self.assertTrue(self.transfer.upload_tree(self.source, "/dst")["ok"])
        (self.source / "a.txt").write_bytes(b"NEW")
        rejected = self.transfer.upload_tree(self.source, "/dst")
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["status"], "preflight_failed")
        before = sum(operation == "upload" for operation, path in self.fs.writes)
        resumed = self.transfer.upload_tree(self.source, "/dst", overwrite=True)
        self.assertTrue(resumed["ok"])
        self.assertEqual(resumed["files_resumed"], 1)
        self.assertEqual(sum(operation == "upload" for operation, path in self.fs.writes) - before, 1)
        self.assertEqual(self.fs.payloads["/dst/a.txt"], b"NEW")


if __name__ == "__main__":
    unittest.main()
