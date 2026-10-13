from __future__ import annotations

import copy
import contextlib
import posixpath
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from baidu_netdisk.catalog import Catalog
from baidu_netdisk.common import NetdiskError
from baidu_netdisk.pcs_json import PcsJsonReader, _Session, _PAN_UA, _PCS_UA


def entry(path, fs_id=42, size=12, is_dir=False, **extra):
    return {"path": path, "name": posixpath.basename(path), "is_dir": is_dir,
            "size": size, "fs_id": fs_id, "mtime": 1723456789, "ctime": 1712345678,
            "md5": "preserved-cloud-hash", **extra}


class TreeBackend:
    def __init__(self, tree):
        self.tree = tree
        self.calls = []
        self.override = None

    def list_entries(self, path="/", start=0, limit=1000):
        self.calls.append((path, start, limit))
        if self.override:
            result = self.override(path, start, limit)
            if result is not None:
                return result
        if path not in self.tree:
            raise NetdiskError("remote_missing", "目录已不存在。")
        all_entries = sorted(self.tree[path], key=lambda item: item["path"])
        items = copy.deepcopy(all_entries[start:start + limit])
        return {"entries": items, "start": start, "next_start": start + len(items),
                "has_more": start + len(items) < len(all_entries)}


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = Path(self.temp.name) / "state"
        self.catalog = Catalog(self.state, "pcs", "account-A")
        self.catalog.PAGE_SIZE = 2

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_recursive_scan_preserves_metadata_and_large_ids(self):
        backend = TreeBackend({
            "/": [entry("/目录", 10, is_dir=True), entry("/空目录", 11, is_dir=True), entry("/根文件.txt", 12)],
            "/目录": [entry("/目录/照片_%中文.png", 2 ** 64 - 1, 777), entry("/目录/嵌套", 13, is_dir=True)],
            "/目录/嵌套": [entry("/目录/嵌套/README.md", 14, 99)],
            "/空目录": [],
        })
        receipt = self.catalog.scan(backend)
        self.assertTrue(receipt["complete"])
        self.assertEqual(receipt["entries_seen"], 6)
        self.assertEqual(receipt["dirs_completed"], 4)
        self.assertGreater(receipt["pages_seen"], receipt["dirs_seen"])
        result = self.catalog.query("/目录", recursive=True)
        self.assertTrue(result["complete"])
        self.assertEqual(result["count"], 3)
        photo = next(item for item in result["entries"] if item["name"].endswith(".png"))
        self.assertEqual(photo["fs_id"], str(2 ** 64 - 1))
        self.assertEqual(photo["mtime"], 1723456789)
        self.assertEqual(photo["ctime"], 1712345678)
        self.assertEqual(photo["md5"], "preserved-cloud-hash")
        self.assertEqual(photo["size"], 777)
        self.assertEqual(photo["generation"], receipt["generation"])
        with contextlib.closing(sqlite3.connect(self.catalog.path)) as db:
            self.assertEqual(db.execute("SELECT typeof(fs_id) FROM catalog_files WHERE path=?",
                                        (photo["path"],)).fetchone()[0], "text")
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        stats = self.catalog.stats()
        self.assertEqual(stats["files"], 3)
        self.assertEqual(stats["directories"], 3)
        self.assertEqual(stats["total_bytes"], 12 + 777 + 99)
        self.assertTrue(stats["complete"])

    def test_budget_pause_and_restart_resume_keep_exact_checkpoint(self):
        backend = TreeBackend({"/": [entry("/a", 1), entry("/b", 2), entry("/c", 3)]})
        first = self.catalog.scan(backend, max_entries=1)
        self.assertEqual(first["status"], "paused")
        self.assertFalse(first["complete"])
        self.assertEqual(first["checkpoint"], {"path": "/", "next_start": 1})
        self.assertFalse(self.catalog.query()["complete"])
        restarted = Catalog(self.state, "pcs", "account-A")
        restarted.PAGE_SIZE = 2
        second = restarted.scan(backend)
        self.assertTrue(second["resumed"])
        self.assertEqual(second["scan_id"], first["scan_id"])
        self.assertEqual(second["generation"], first["generation"])
        self.assertEqual(backend.calls[-1], ("/", 1, 2))
        self.assertTrue(second["complete"])
        self.assertEqual(second["entries_seen"], 3)
        self.assertEqual(second["entries_processed"], 2)

    def test_native_pcs_final_none_cursor_and_empty_directory_complete_scan(self):
        # Exercise the actual provider's public pagination contract; only the
        # network and private session load are fixtures. The catalog's smaller
        # page size also forces a nonzero terminal offset.
        reader = PcsJsonReader(self.state / "session")
        session = _Session("7", "fixture", 266719, _PAN_UA, _PCS_UA, "BDUSS=fixture", b"fixture")
        tree = {"/": [
            {"path": "/a.txt", "fs_id": 1, "isdir": 0, "size": 3},
            {"path": "/b.txt", "fs_id": 2, "isdir": 0, "size": 4},
            {"path": "/empty", "fs_id": 3, "isdir": 1, "size": 0}], "/empty": []}
        def response(_session, _url, *, params):
            return {"errno": 0, "list": tree[params["dir"]]}
        with patch.object(reader, "_load_session", return_value=session), patch.object(reader, "_request_json", side_effect=response):
            receipt = self.catalog.scan(reader)
        self.assertTrue(receipt["complete"])
        self.assertEqual(receipt["entries_seen"], 3)
        self.assertEqual(receipt["dirs_completed"], 2)
        self.assertEqual(receipt["pages_seen"], 3)
        self.assertEqual(self.catalog.stats()["files"], 2)
        self.assertTrue(self.catalog.query(recursive=True)["complete"])

    def test_continuing_none_and_boolean_cursors_are_rejected(self):
        for cursor, has_more in ((None, True), (False, False), (True, False)):
            with self.subTest(cursor=cursor, has_more=has_more):
                with self.assertRaises(NetdiskError) as caught:
                    Catalog._validate_page({"entries": [entry("/a", 1)], "start": 0,
                                           "next_start": cursor, "has_more": has_more}, "/", 0, 2)
                self.assertEqual(caught.exception.code, "catalog_page_gap")

    def test_failed_refresh_preserves_stale_until_resumed_completion(self):
        backend = TreeBackend({"/": [entry("/a", 1), entry("/b", 2), entry("/stale", 3)]})
        original = self.catalog.scan(backend)
        backend.tree["/"] = [entry("/a", 1, 100), entry("/c", 4), entry("/d", 5)]

        def fail_last(path, start, limit):
            if start == 2:
                raise NetdiskError("network_error", "connection failed access_token=SECRET")

        backend.override = fail_last
        failed = self.catalog.scan(backend)
        self.assertFalse(failed["ok"])
        self.assertEqual(failed["status"], "failed")
        self.assertNotIn("SECRET", str(failed))
        mixed = self.catalog.query(recursive=True)
        self.assertFalse(mixed["complete"])
        self.assertEqual(mixed["last_complete_at"], original["finished_at"])
        self.assertIn("/stale", [item["path"] for item in mixed["entries"]])
        self.assertIn(original["generation"], [item["generation"] for item in mixed["entries"]])
        self.assertEqual(next(i for i in mixed["entries"] if i["path"] == "/a")["size"], 100)
        backend.override = None
        complete = self.catalog.scan(backend)
        self.assertTrue(complete["resumed"])
        self.assertEqual(complete["scan_id"], failed["scan_id"])
        self.assertTrue(complete["complete"])
        self.assertEqual(complete["stale_removed"], 2)
        self.assertEqual([i["path"] for i in self.catalog.query(recursive=True)["entries"]], ["/a", "/c", "/d"])

    def test_account_and_backend_isolation_and_receipt_access(self):
        own = self.catalog.scan(TreeBackend({"/": [entry("/same", 1, 10)]}))
        other_account = Catalog(self.state, "pcs", "account-B")
        other_backend = Catalog(self.state, "openapi", "account-A")
        other_account.scan(TreeBackend({"/": [entry("/same", 2, 20)]}))
        other_backend.scan(TreeBackend({"/": [entry("/api-only", 3, 30)]}))
        self.assertEqual(self.catalog.query()["entries"][0]["size"], 10)
        self.assertEqual(other_account.query()["entries"][0]["size"], 20)
        self.assertEqual(other_backend.query()["entries"][0]["path"], "/api-only")
        with self.assertRaises(NetdiskError):
            other_account.receipt(own["scan_id"])

    def test_literal_percent_underscore_path_does_not_match_neighbors(self):
        backend = TreeBackend({
            "/": [entry("/100%_", 1, is_dir=True), entry("/100ABCX", 2, is_dir=True)],
            "/100%_": [entry("/100%_/literal.txt", 3), entry("/100%_/sub", 4, is_dir=True)],
            "/100%_/sub": [entry("/100%_/sub/nested.txt", 5)],
            "/100ABCX": [entry("/100ABCX/neighbor.txt", 6)],
        })
        self.assertTrue(self.catalog.scan(backend)["complete"])
        result = self.catalog.query("/100%_", recursive=True)
        self.assertEqual(result["count"], 3)
        self.assertTrue(all(item["path"].startswith("/100%_/") for item in result["entries"]))
        backend.tree["/100%_"] = []
        subscan = self.catalog.scan(backend, remote_root="/100%_")
        self.assertEqual(subscan["stale_removed"], 3)
        self.assertEqual(self.catalog.query("/100ABCX")["count"], 1)

    def test_nonrecursive_scan_only_cleans_direct_children(self):
        backend = TreeBackend({"/": [entry("/dir", 1, is_dir=True)],
                               "/dir": [entry("/dir/kept.txt", 2)]})
        self.catalog.scan(backend)
        backend.tree["/"] = []
        result = self.catalog.scan(backend, recursive=False)
        self.assertTrue(result["complete"])
        self.assertEqual(result["stale_removed"], 1)
        self.assertEqual(self.catalog.query()["count"], 0)
        self.assertEqual(self.catalog.query("/dir")["count"], 1)

    def test_page_gap_fails_without_discarding_old_records(self):
        backend = TreeBackend({"/": [entry("/old", 1)]})
        self.catalog.scan(backend)
        backend.override = lambda path, start, limit: {"entries": [entry("/new", 2)],
                                                     "start": start, "next_start": start + 3, "has_more": False}
        receipt = self.catalog.scan(backend)
        self.assertFalse(receipt["complete"])
        self.assertEqual(receipt["error"]["code"], "catalog_page_gap")
        self.assertEqual(self.catalog.query()["entries"][0]["path"], "/old")

    def test_duplicate_page_is_not_marked_complete(self):
        backend = TreeBackend({"/": [entry("/a", 1), entry("/b", 2), entry("/c", 3)]})
        backend.override = lambda path, start, limit: ({"entries": [entry("/a", 1), entry("/b", 2)],
                                                       "start": start, "next_start": start + 2, "has_more": False}
                                                      if start == 2 else None)
        receipt = self.catalog.scan(backend)
        self.assertEqual(receipt["error"]["code"], "catalog_duplicate_page")
        self.assertFalse(receipt["complete"])
        self.assertEqual(receipt["entries_seen"], 2)

    def test_duplicate_directory_on_same_page_is_rejected(self):
        repeated = entry("/dir", 1, is_dir=True)
        backend = TreeBackend({"/": [repeated, repeated], "/dir": []})
        receipt = self.catalog.scan(backend)
        self.assertEqual(receipt["error"]["code"], "catalog_duplicate_entry")
        self.assertFalse(receipt["complete"])
        self.assertEqual(self.catalog.stats()["entries"], 0)

    def test_duplicate_cross_page_entry_is_rejected(self):
        backend = TreeBackend({"/": [entry("/a", 1), entry("/b", 2), entry("/c", 3)]})
        backend.override = lambda path, start, limit: ({"entries": [entry("/b", 2), entry("/c", 3)],
                                                       "start": 2, "next_start": 4, "has_more": False}
                                                      if start == 2 else None)
        receipt = self.catalog.scan(backend)
        self.assertEqual(receipt["error"]["code"], "catalog_duplicate_entry")
        self.assertFalse(receipt["complete"])

    def test_remote_errno_and_empty_continuation_fail(self):
        backend = TreeBackend({"/": []})
        backend.override = lambda *args: {"errno": 20012, "entries": [], "start": 0,
                                          "next_start": 0, "has_more": False}
        result = self.catalog.scan(backend)
        self.assertEqual(result["error"]["code"], "catalog_remote_error")
        self.assertFalse(result["complete"])
        backend.override = lambda *args: {"entries": [], "start": 0, "next_start": 0, "has_more": True}
        result = self.catalog.scan(backend)
        self.assertEqual(result["error"]["code"], "catalog_page_gap")
        self.assertFalse(result["complete"])

    def test_response_cannot_escape_directory_or_store_transport_credentials(self):
        backend = TreeBackend({"/": [entry("/inside", 1, access_token="not-stored", dlink="signed-url")]})
        self.catalog.scan(backend)
        item = self.catalog.query()["entries"][0]
        self.assertNotIn("access_token", item)
        self.assertNotIn("dlink", item)
        with self.catalog.path.open("rb") as db_file:
            self.assertNotIn(b"not-stored", db_file.read())
        escaped = TreeBackend({"/dir": [entry("/outside", 2)]})
        result = self.catalog.scan(escaped, "/dir")
        self.assertEqual(result["error"]["code"], "catalog_wrong_directory")
        self.assertFalse(result["complete"])

    def test_stable_search_pages_and_filename_globs(self):
        backend = TreeBackend({"/": [entry("/报告ABC.PDF", 1), entry("/报告abc.txt", 2),
                                     entry("/x_%.txt", 3), entry("/报告AbC.md", 4)]})
        self.catalog.scan(backend)
        first = self.catalog.search("ABC", limit=1)
        second = self.catalog.search("ABC", offset=first["next_offset"], limit=2)
        paths = [i["path"] for i in first["entries"] + second["entries"]]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(len(set(paths)), 3)
        self.assertEqual(first["count"], 3)
        self.assertTrue(first["has_more"])
        self.assertFalse(second["has_more"])
        self.assertEqual(self.catalog.query(pattern="*.txt")["count"], 2)
        self.assertEqual(self.catalog.search("_%")["count"], 1)
        self.assertEqual(self.catalog.query(pattern="x_%.txt")["count"], 1)

    def test_newer_scope_scan_prevents_resuming_old_generation(self):
        backend = TreeBackend({"/": [entry("/dir", 1, is_dir=True), entry("/z", 2)],
                               "/dir": [entry("/dir/a", 3)]})
        old = self.catalog.scan(backend, max_entries=1)
        nested = self.catalog.scan(backend, remote_root="/dir")
        self.assertTrue(nested["complete"])
        new = self.catalog.scan(backend, max_entries=1)
        self.assertFalse(new["resumed"])
        self.assertGreater(new["generation"], nested["generation"])
        self.assertNotEqual(new["scan_id"], old["scan_id"])

    def test_network_call_holds_no_database_write_transaction(self):
        other = Catalog(self.state, "pcs", "account-B")
        backend = TreeBackend({"/": [entry("/a", 1)]})
        events = []

        def during_request(*args):
            events.append(self.catalog.query()["scan_status"])
            events.append(other.scan(TreeBackend({"/": [entry("/other", 2)]}))["complete"])

        backend.override = during_request
        result = self.catalog.scan(backend)
        self.assertTrue(result["complete"])
        self.assertEqual(events, ["running", True])

    def test_never_scanned_empty_catalog_is_incomplete(self):
        result = self.catalog.query()
        self.assertEqual(result["count"], 0)
        self.assertFalse(result["complete"])
        self.assertEqual(result["scan_status"], "never_scanned")
        self.assertFalse(self.catalog.stats()["complete"])
        with self.assertRaises(NetdiskError):
            self.catalog.receipt()


if __name__ == "__main__":
    unittest.main()
