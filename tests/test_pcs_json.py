"""Structured PCS pagination and native-file reads, using synthetic credentials."""
from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from baidu_netdisk.common import NetdiskError
from baidu_netdisk.pcs import PcsBackend
from baidu_netdisk.pcs_json import PcsJsonReader, _DownloadRedirect, _NoRedirect, _MAX_JSON, _PAN_UA, _PCS_UA, _trusted_download_url


def entry(path, fs_id=123, size=3, isdir=0, mtime=7):
    return {"path": path, "server_filename": path.rsplit("/", 1)[-1], "fs_id": fs_id,
            "size": size, "isdir": isdir, "server_mtime": mtime, "server_ctime": 5}


class Response(io.BytesIO):
    def __init__(self, value, url="https://pcs.baidu.com/rest/2.0/pcs/file", status=200):
        super().__init__(value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode("utf-8"))
        self.url, self.status = url, status
    def geturl(self):
        return self.url


class Opener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.on_request = None
    def open(self, request, timeout):
        self.requests.append(request)
        if self.on_request:
            self.on_request(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response if isinstance(response, Response) else Response(response)


class StructuredPcsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = self.root / "private"
        self.config.mkdir()
        self.config_file = self.config / "pcs_config.json"
        self.write_config()
        self.reader = PcsJsonReader(self.config)

    def tearDown(self):
        self.temp.cleanup()

    def write_config(self, uid=123, secret="synthetic-session", *, cookies="", force_name=""):
        self.config_file.write_text(json.dumps({"baidu_active_uid": uid, "appid": 266719,
            "force_login_username": force_name, "baidu_user_list": [{"uid": uid, "name": "本人测试账号" + force_name,
            "bduss": secret, "stoken": "synthetic-stoken", "cookies": cookies}]}), encoding="utf-8")

    def assert_code(self, code, callback):
        with self.assertRaises(NetdiskError) as context:
            callback()
        self.assertEqual(context.exception.code, code)
        return context.exception

    def test_identity_never_returns_credentials(self):
        result = self.reader.account_identity()
        self.assertEqual(result["account_id"], "pcs:123")
        self.assertEqual(result["account"]["uid"], "123")
        self.assertNotIn("synthetic", json.dumps(result))

    def test_force_login_synthetic_uid_distinguishes_accounts(self):
        self.write_config(uid=24, force_name="first")
        first = self.reader.account_identity()["account_id"]
        self.write_config(uid=24, force_name="second")
        self.assertNotEqual(first, self.reader.account_identity()["account_id"])

    def test_missing_session_has_actionable_error(self):
        self.config_file.unlink()
        self.assert_code("authentication_required", self.reader.account_identity)

    def test_native_ua_profiles_separate_web_list_from_pcs_meta_and_download(self):
        raw = entry("/file.txt")
        meta = {"error_code": 0, "list": [raw]}
        self.reader._opener = Opener([{"errno": 0, "list": []}, meta, meta, meta])
        self.reader._download_opener = Opener([Response(b"abc")])
        self.reader.list_entries("/")
        result = self.reader.stat_entry("/file.txt")
        self.reader.download_to("/file.txt", self.root / "download.tmp", result["entry"])
        self.assertEqual(self.reader._opener.requests[0].get_header("User-agent"), _PAN_UA)
        for request in self.reader._opener.requests[1:]:
            self.assertEqual(request.get_header("User-agent"), _PCS_UA)
        self.assertEqual(self.reader._download_opener.requests[0].get_header("User-agent"), _PCS_UA)

    def test_explicit_pcs_then_global_ua_options_are_preserved(self):
        config = json.loads(self.config_file.read_text(encoding="utf-8"))
        config.update(pcs_ua="custom-pcs-agent", user_agent="custom-global-agent", pan_ua="custom-pan-agent")
        self.config_file.write_text(json.dumps(config), encoding="utf-8")
        self.assertEqual(self.reader._load_session().pcs_ua, "custom-pcs-agent")
        self.assertEqual(self.reader._load_session().pan_ua, "custom-pan-agent")
        config["pcs_ua"] = ""
        self.config_file.write_text(json.dumps(config), encoding="utf-8")
        self.assertEqual(self.reader._load_session().pcs_ua, "custom-global-agent")

    def test_native_auth_error_reports_safe_api_stage(self):
        self.reader._opener = Opener([{"errno": -6, "errmsg": "Cookie: SECRET_NEVER_ECHO"}])
        exc = self.assert_code("authentication_required", lambda: self.reader.list_entries("/"))
        self.assertEqual(exc.details, {"api_code": -6, "stage": "directory_list"})
        self.assertNotIn("SECRET_NEVER_ECHO", json.dumps(exc.as_dict()))
        self.reader._opener = Opener([{"error_code": 31045}])
        exc = self.assert_code("authentication_required", lambda: self.reader.stat_entry("/file.txt"))
        self.assertEqual(exc.details, {"api_code": 31045, "stage": "file_meta"})

    def test_invalid_config_never_echoes_raw_credentials(self):
        self.config_file.write_text('{"bduss":"SECRET_NEVER_ECHO", broken', encoding="utf-8")
        exc = self.assert_code("invalid_config", self.reader.account_identity)
        self.assertNotIn("SECRET_NEVER_ECHO", str(exc))

    def test_cookie_header_injection_is_rejected(self):
        self.write_config(secret="bad\r\nX-Leak: sensitive")
        self.assert_code("invalid_config", self.reader.account_identity)

    def test_conflicting_cookie_identity_is_rejected(self):
        self.write_config(cookies="BDUSS=different-session;")
        self.assert_code("invalid_config", self.reader.account_identity)

    def test_unicode_and_windows_reserved_remote_names_are_preserved(self):
        raws = [entry("/中文目录/CON.txt", 1), entry("/中文目录/论文 [第1稿] 🌸.pdf", 2),
                entry("/中文目录/目录*字面符号", 3, isdir=1, size=0)]
        self.reader._opener = Opener([{"errno": 0, "list": raws}])
        result = self.reader.list_entries("/中文目录")
        self.assertEqual([item["path"] for item in result["entries"]], [item["path"] for item in raws])
        self.assertTrue(result["complete"])
        self.assertFalse(result["has_more"])
        self.assertIsNone(result["next_start"])
        self.assertEqual(result["entries"][1]["mtime"], 7)
        request = self.reader._opener.requests[0]
        self.assertTrue(request.full_url.startswith("https://pan.baidu.com/api/list?"))
        self.assertNotIn("synthetic", request.full_url)
        self.assertIn("synthetic-session", request.get_header("Cookie"))

    def test_full_page_does_not_claim_end_and_exact_multiple_requires_empty_page(self):
        page = [entry(f"/f{i:04}.txt", i + 1) for i in range(1000)]
        self.reader._opener = Opener([{"errno": 0, "list": page}, {"errno": 0, "list": []}])
        first = self.reader.list_entries("/", start=0, limit=1000)
        self.assertFalse(first["complete"])
        self.assertTrue(first["has_more"])
        self.assertEqual(first["next_start"], 1000)
        second = self.reader.list_entries("/", start=1000, limit=1000)
        self.assertTrue(second["complete"])
        self.assertEqual(second["entries"], [])
        pages = [urllib.parse.parse_qs(urllib.parse.urlsplit(req.full_url).query)["page"][0]
                 for req in self.reader._opener.requests]
        self.assertEqual(pages, ["1", "2"])

    def test_arbitrary_offset_spans_pages_without_losing_files(self):
        first_page = [entry(f"/f{i:04}.txt", i + 1) for i in range(1000)]
        second_page = [entry(f"/f{i:04}.txt", i + 1) for i in range(1000, 1100)]
        self.reader._opener = Opener([{"errno": 0, "list": first_page}, {"errno": 0, "list": second_page}])
        result = self.reader.list_entries("/", start=950, limit=100)
        self.assertEqual(len(result["entries"]), 100)
        self.assertEqual(result["entries"][0]["path"], "/f0950.txt")
        self.assertEqual(result["entries"][-1]["path"], "/f1049.txt")
        self.assertTrue(result["has_more"])
        self.assertEqual(result["next_start"], 1050)
        self.assertEqual(result["pagination"]["api_pages"], [1, 2])

    def test_duplicate_page_items_fail_instead_of_completing_index(self):
        self.reader._opener = Opener([{"errno": 0, "list": [entry("/a", 1), entry("/b", 1)]}])
        self.assert_code("pagination_inconsistent", lambda: self.reader.list_entries("/"))

    def test_short_page_explicitly_marked_incomplete_cannot_finish_index(self):
        self.reader._opener = Opener([{"errno": 0, "list": [entry("/a")], "has_more": 1}])
        self.assert_code("pagination_inconsistent", lambda: self.reader.list_entries("/"))

    def test_overlap_across_pages_inside_one_read_is_detected(self):
        page = [entry(f"/f{i:04}.txt", i + 1) for i in range(1000)]
        self.reader._opener = Opener([{"errno": 0, "list": page}, {"errno": 0, "list": page[:1]}])
        self.assert_code("pagination_inconsistent", lambda: self.reader.list_entries("/", start=999, limit=2))

    def test_account_switch_during_read_does_not_return_rows(self):
        opener = Opener([{"errno": 0, "list": [entry("/a")]}])
        opener.on_request = lambda request: self.write_config(uid=999, secret="other-synthetic-session")
        self.reader._opener = opener
        self.assert_code("account_changed", lambda: self.reader.list_entries("/"))

    def test_logout_during_read_does_not_return_rows(self):
        opener = Opener([{"errno": 0, "list": [entry("/a")]}])
        opener.on_request = lambda request: self.config_file.unlink()
        self.reader._opener = opener
        self.assert_code("account_changed", lambda: self.reader.list_entries("/"))

    def test_same_account_session_replacement_during_read_is_detected(self):
        opener = Opener([{"errno": 0, "list": []}])
        opener.on_request = lambda request: self.write_config(secret="new-synthetic-session")
        self.reader._opener = opener
        self.assert_code("account_changed", lambda: self.reader.list_entries("/"))

    def test_account_switch_between_calls_is_visible(self):
        self.reader._opener = Opener([{"errno": 0, "list": []}, {"errno": 0, "list": []}])
        first = self.reader.list_entries("/")["account_id"]
        self.write_config(uid=999)
        second = self.reader.list_entries("/")["account_id"]
        self.assertNotEqual(first, second)

    def test_api_errors_are_sanitized_and_do_not_return_partial_entries(self):
        for code, expected in ((-6, "authentication_required"), (31045, "authentication_required"),
                               (31066, "not_found"), (-9, "not_found"), (2, "remote_error")):
            self.reader._opener = Opener([{"errno": code, "errmsg": "Cookie: SECRET_NEVER_ECHO", "list": [entry("/a")]}])
            exc = self.assert_code(expected, lambda: self.reader.list_entries("/"))
            self.assertNotIn("SECRET_NEVER_ECHO", str(exc.as_dict()))

    def test_native_meta_404_known_json_missing_codes_become_not_found(self):
        for field, code in (("error_code", 31066), ("errno", -9), ("error_code", "31066")):
            with self.subTest(field=field, code=code):
                body = Response({field: code, "error_msg": "Cookie: SECRET_NEVER_ECHO"})
                error = urllib.error.HTTPError("https://pcs.baidu.com/rest/2.0/pcs/file?secret=SECRET_NEVER_ECHO",
                                               404, "SECRET_NEVER_ECHO", {}, body)
                self.reader._opener = Opener([error])
                exc = self.assert_code("not_found", lambda: self.reader.stat_entry("/new-upload-target.txt"))
                self.assertEqual(exc.details, {"api_code": int(code), "status": 404, "stage": "file_meta"})
                self.assertNotIn("SECRET_NEVER_ECHO", json.dumps(exc.as_dict()))
                self.assertTrue(body.closed)
                self.assertEqual(self.reader._opener.requests[0].get_method(), "POST")

    def test_404_html_malformed_or_other_business_errors_remain_http_error(self):
        values = (b"<html>SECRET_NEVER_ECHO</html>", b"[]", b"null", b"not-json", b"\xff", {},
                  {"error_code": 0}, {"error_code": True}, {"error_code": 31045}, {"error_code": 2},
                  {"error_code": "invalid"}, {"errno": 2, "error_code": 31066},
                  {"errno": -9, "error_code": 31045}, {"errno": -9, "error_code": "invalid"},
                  b'{"error_code":0,"error_code":31066}', b"x" * (_MAX_JSON + 1))
        for value in values:
            with self.subTest(value_type=type(value).__name__, size=len(value)):
                body = Response(value)
                error = urllib.error.HTTPError("https://pcs.baidu.com/rest/2.0/pcs/file", 404,
                                               "SECRET_NEVER_ECHO", {}, body)
                self.reader._opener = Opener([error])
                exc = self.assert_code("http_error", lambda: self.reader.stat_entry("/new-target.txt"))
                self.assertEqual(exc.details, {"status": 404, "stage": "file_meta"})
                self.assertNotIn("SECRET_NEVER_ECHO", json.dumps(exc.as_dict()))
                self.assertTrue(body.closed)

    def test_non_404_http_errors_do_not_infer_missing_target_from_business_body(self):
        for status, code in ((401, "authentication_required"), (403, "authentication_required"),
                             (400, "http_error"), (500, "http_error")):
            with self.subTest(status=status):
                error = urllib.error.HTTPError("https://pcs.baidu.com/rest/2.0/pcs/file", status,
                                               "SECRET_NEVER_ECHO", {}, Response({"error_code": 31066}))
                self.reader._opener = Opener([error])
                exc = self.assert_code(code, lambda: self.reader.stat_entry("/new-target.txt"))
                self.assertEqual(exc.details, {"status": status, "stage": "file_meta"})
                self.assertNotIn("SECRET_NEVER_ECHO", json.dumps(exc.as_dict()))

    def test_html_and_malformed_json_are_sanitized(self):
        for payload in (b"<html>Cookie: SECRET_NEVER_ECHO</html>", b'{"errno":0,"errno":1}', b"[]"):
            self.reader._opener = Opener([Response(payload)])
            self.assert_code("invalid_response", lambda: self.reader.list_entries("/"))

    def test_stat_is_exact_structured_metadata_with_multipart_path(self):
        self.reader._opener = Opener([{"list": [entry("/中文[图]/CON.txt", 999)]}])
        result = self.reader.stat_entry("/中文[图]/CON.txt")
        self.assertEqual(result["entry"]["fs_id"], "999")
        request = self.reader._opener.requests[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertIn('"path":"/中文[图]/CON.txt"', request.data.decode("utf-8"))
        self.assertIn("multipart/form-data", request.get_header("Content-type"))
        self.assertEqual(result["account_id"], "pcs:123")

    def test_wrong_stat_path_and_directory_child_fail_closed(self):
        self.reader._opener = Opener([{"list": [entry("/wrong")]}])
        self.assert_code("invalid_response", lambda: self.reader.stat_entry("/asked"))
        self.reader._opener = Opener([{"errno": 0, "list": [entry("/other/a")]}])
        self.assert_code("invalid_response", lambda: self.reader.list_entries("/dir"))

    def test_invalid_typed_metadata_is_rejected(self):
        for altered in ({"size": -1}, {"isdir": 2}, {"fs_id": 0}, {"size": True}, {"server_filename": "other"}):
            raw = {**entry("/a"), **altered}
            self.reader._opener = Opener([{"errno": 0, "list": [raw]}])
            self.assert_code("invalid_response", lambda: self.reader.list_entries("/"))

    def test_standard_and_known_encoded_md5_are_normalized_in_list_and_meta(self):
        expected = "900150983cd24fb0d6963f7d28e17f72"  # MD5 of fixture bytes b"abc".
        # Independently precomputed inverse of the pinned provider transform.
        encoded = "3df10ad71paa9d7729c23a155f3df292"
        for wire in (expected, expected.upper(), encoded, encoded.upper()):
            with self.subTest(wire=wire):
                raw = {**entry("/a.txt"), "md5": wire}
                self.reader._opener = Opener([{"errno": 0, "list": [raw]}, {"error_code": 0, "list": [raw]}])
                listed = self.reader.list_entries("/")["entries"][0]
                stated = self.reader.stat_entry("/a.txt")["entry"]
                for actual in (listed, stated):
                    self.assertEqual(actual["md5"], expected)
                    self.assertEqual(actual["md5_source"], "server_metadata_unverified")

    def test_encoded_md5_marker_bounds_and_missing_hash_are_explicit(self):
        cases = (("0" * 9 + "g" + "0" * 22, "89abcdef0123456789abcdef01234567"),
                 ("0" * 9 + "v" + "0" * 22, "86abcdef0123456789abcdef01234567"),
                 (None, None), ("", None))
        for wire, expected in cases:
            with self.subTest(wire=wire):
                raw = {**entry("/a.txt"), "md5": wire}
                self.reader._opener = Opener([{"errno": 0, "list": [raw]}])
                actual = self.reader.list_entries("/")["entries"][0]
                self.assertEqual(actual["md5"], expected)
                self.assertEqual(actual["md5_source"], "server_metadata_unverified")

    def test_unknown_md5_formats_and_non_ascii_marker_are_rejected(self):
        values = ("0" * 31, "0" * 33, "0" * 9 + "w" + "0" * 22, "0" * 9 + "z" + "0" * 22,
                  "g" + "0" * 31, "0" * 9 + "\u212a" + "0" * 22, "0" * 9 + "\n" + "0" * 22,
                  "0" * 9 + "-" + "0" * 22, "\u00e9" * 32, 0, False, True, [], {})
        for wire in values:
            with self.subTest(wire_type=type(wire).__name__):
                raw = {**entry("/a.txt"), "md5": wire}
                self.reader._opener = Opener([{"errno": 0, "list": [raw]}])
                exc = self.assert_code("invalid_response", lambda: self.reader.list_entries("/"))
                self.assertEqual(exc.message, "网盘 md5 元信息无效。")

    def test_download_accepts_encoded_list_metadata_and_plain_meta_without_false_change(self):
        plain = "900150983cd24fb0d6963f7d28e17f72"
        encoded_raw = {**entry("/a.txt"), "md5": "3df10ad71paa9d7729c23a155f3df292"}
        plain_raw = {**entry("/a.txt"), "md5": plain}
        self.reader._opener = Opener([{"errno": 0, "list": [encoded_raw]}, {"list": [encoded_raw]}, {"list": [plain_raw]}])
        self.reader._download_opener = Opener([Response(b"abc")])
        expected = self.reader.list_entries("/")["entries"][0]
        target = self.root / "encoded-metadata-download.tmp"
        result = self.reader.download_to("/a.txt", target, expected)
        self.assertEqual(target.read_bytes(), b"abc")
        self.assertEqual(result["entry"]["md5"], plain)
        self.assertEqual(result["entry"]["md5_source"], "server_metadata_unverified")
        self.assertEqual(result["verification"], "size_and_unchanged_remote_metadata")
        self.assertEqual(result["sha256"], hashlib.sha256(b"abc").hexdigest())

    def test_metadata_redirects_are_blocked(self):
        handler = _NoRedirect()
        self.assert_code("redirect_blocked", lambda: handler.redirect_request(
            urllib.request.Request("https://pan.baidu.com/api/list", headers={"Cookie": "fake"}),
            None, 302, "Found", {}, "https://pcs.baidu.com/other"))

    def test_download_redirect_drops_credentials_even_for_baidu_hosts(self):
        request = urllib.request.Request("https://pcs.baidu.com/file", headers={"Cookie": "fake-cookie",
                                            "Authorization": "Bearer fake", "User-Agent": "safe-agent"})
        redirected = _DownloadRedirect().redirect_request(request, None, 302, "Found", {}, "https://d.pcs.baidu.com/signed-file")
        self.assertIsNone(redirected.get_header("Cookie"))
        self.assertIsNone(redirected.get_header("Authorization"))
        self.assertEqual(redirected.get_header("User-agent"), "safe-agent")

    def test_download_untrusted_or_insecure_redirects_are_blocked(self):
        for url in ("http://pcs.baidu.com/a", "https://baidu.com.evil.test/a", "https://evil.test/a",
                    "https://user:pass@pcs.baidu.com/a", "https://pcs.baidu.com:444/a"):
            self.assert_code("untrusted_url", lambda: _trusted_download_url(url))

    def download_setup(self, path="/CON.txt", size=3):
        raw = entry(path, 999, size)
        self.reader._opener = Opener([{"list": [raw]}, {"list": [raw]}])
        expected = {"path": path, "fs_id": "999", "size": size, "is_dir": False, "account_id": "pcs:123"}
        return expected

    def test_native_download_preserves_bytes_at_arbitrary_temp_basename(self):
        expected = self.download_setup()
        self.reader._download_opener = Opener([Response(b"abc", url="https://d.pcs.baidu.com/file")])
        target = self.root / "safe-generated.tmp"
        result = self.reader.download_to("/CON.txt", target, expected)
        self.assertEqual(target.read_bytes(), b"abc")
        self.assertTrue(result["verified"])
        self.assertEqual(result["sha256"], hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(result["local_path"], str(target))
        request = self.reader._download_opener.requests[0]
        self.assertIn("method=download", request.full_url)
        self.assertNotIn("synthetic", request.full_url)
        self.assertNotIn("synthetic", json.dumps(result))

    def test_native_download_supports_empty_files(self):
        expected = self.download_setup("/empty", size=0)
        self.reader._download_opener = Opener([Response(b"")])
        target = self.root / "empty.tmp"
        result = self.reader.download_to("/empty", target, expected)
        self.assertEqual(result["size"], 0)
        self.assertEqual(target.read_bytes(), b"")

    def test_native_download_never_overwrites_existing_file(self):
        target = self.root / "existing.tmp"
        target.write_bytes(b"previous")
        expected = self.download_setup()
        self.assert_code("local_file_exists", lambda: self.reader.download_to("/CON.txt", target, expected))
        self.assertEqual(target.read_bytes(), b"previous")

    def test_native_download_rejects_relative_or_traversal_destination(self):
        expected = self.download_setup()
        for destination in (Path("relative.tmp"), self.root / "child" / ".." / "escape.tmp"):
            self.assert_code("unsafe_local_path", lambda: self.reader.download_to("/CON.txt", destination, expected))

    def test_failed_download_removes_its_own_partial_file(self):
        expected = self.download_setup(size=4)
        self.reader._download_opener = Opener([Response(b"abc")])
        target = self.root / "partial.tmp"
        self.assert_code("download_size_mismatch", lambda: self.reader.download_to("/CON.txt", target, expected))
        self.assertFalse(target.exists())

    def test_oversized_response_does_not_fill_disk(self):
        expected = self.download_setup(size=1)
        self.reader._download_opener = Opener([Response(b"too much")])
        target = self.root / "oversized.tmp"
        self.assert_code("download_size_mismatch", lambda: self.reader.download_to("/CON.txt", target, expected))
        self.assertFalse(target.exists())

    def test_changed_remote_during_download_is_not_published(self):
        expected = self.download_setup()
        self.reader._opener = Opener([{"list": [entry("/CON.txt", 999)]}, {"list": [entry("/CON.txt", 999, mtime=99)]}])
        self.reader._download_opener = Opener([Response(b"abc")])
        target = self.root / "changed.tmp"
        self.assert_code("remote_changed", lambda: self.reader.download_to("/CON.txt", target, expected))
        self.assertFalse(target.exists())

    def test_changed_account_during_download_is_not_published(self):
        expected = self.download_setup()
        downloader = Opener([Response(b"abc")])
        downloader.on_request = lambda request: self.write_config(uid=999)
        self.reader._download_opener = downloader
        target = self.root / "account-changed.tmp"
        self.assert_code("account_changed", lambda: self.reader.download_to("/CON.txt", target, expected))
        self.assertFalse(target.exists())

    def test_expected_entry_for_another_account_is_rejected(self):
        expected = {**self.download_setup(), "account_id": "pcs:999"}
        self.assert_code("account_changed", lambda: self.reader.download_to("/CON.txt", self.root / "x.tmp", expected))

    def test_backend_integration_enforces_allowed_local_root(self):
        exe = self.root / "unused.exe"
        backend = PcsBackend(str(exe), self.config, [self.root])
        backend._json_reader = self.reader
        self.assertEqual(backend.account_identity()["account_id"], "pcs:123")
        self.reader._opener = Opener([{"errno": 0, "list": []}])
        self.assertTrue(backend.list_entries("/")["complete"])
        with self.assertRaises(ValueError):
            backend.download_to("/CON.txt", self.root.parent / "outside.tmp", self.download_setup())
        with self.assertRaises(ValueError):
            backend.download_to("/CON.txt", self.config / "secret.tmp", self.download_setup())


if __name__ == "__main__":
    unittest.main()
