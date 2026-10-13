"""Offline CLI routing and pending-read completion semantics."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import cli


class CliTests(unittest.TestCase):
    def run_cli(self, arguments, service):
        output = io.StringIO()
        with patch.object(sys, "argv", ["cli.py", *arguments]), \
                patch("cli.NetdiskService", return_value=service) as created, \
                patch("cli.time.sleep", return_value=None), contextlib.redirect_stdout(output):
            code = cli.main()
        return code, output.getvalue(), created

    def service(self):
        service = Mock()
        service.jobs.get.return_value = {"job_id": "test-job", "status": "succeeded", "result": {"ok": True}}
        return service

    def test_scan_glob_find_and_index_status_route_range_arguments(self):
        cases = (
            (["scan", "/资料", "--max-entries", "1500"], "start_scan", ("/资料",), {"max_entries": 1500},
             {"job_id": "test-job", "status": "queued"}),
            (["glob", "*.docx", "--path", "/资料", "--offset", "20", "--limit", "30"], "query_index", ("/资料",),
             {"recursive": True, "pattern": "*.docx", "offset": 20, "limit": 30}, {"entries": [], "complete": True}),
            (["find", "模型", "--path", "/资料", "--offset", "7", "--limit", "9"], "search_index", ("模型", "/资料", 7, 9),
             {}, {"entries": [], "complete": True}),
            (["index-status"], "index_status", (), {}, {"stats": {"files": 42}}),
        )
        for arguments, method, positional, keywords, result in cases:
            with self.subTest(command=arguments[0]):
                service = self.service()
                getattr(service, method).return_value = result
                code, _, _ = self.run_cli(arguments, service)
                self.assertEqual(code, 0)
                getattr(service, method).assert_called_once_with(*positional, **keywords)

    def test_put_get_and_tree_routes_preserve_source_destination_and_overwrite(self):
        cases = (
            (["put", "local-source", "/资料/new.md", "--overwrite"], "start_put", ("local-source", "/资料/new.md")),
            (["get", "/资料/source.txt", "local-target", "--overwrite"], "start_get", ("/资料/source.txt", "local-target")),
            (["upload-tree", "local-directory", "/资料/tree", "--overwrite"], "start_tree_transfer", ("upload", "local-directory", "/资料/tree")),
            (["download-tree", "/资料/tree", "local-directory", "--overwrite"], "start_tree_transfer", ("download", "local-directory", "/资料/tree")),
        )
        for arguments, method, positional in cases:
            with self.subTest(command=arguments[0]):
                service = self.service()
                getattr(service, method).return_value = {"job_id": "test-job", "status": "queued"}
                service.jobs.get.return_value["result"]["verified"] = True
                code, output, _ = self.run_cli(arguments, service)
                self.assertEqual(code, 0)
                getattr(service, method).assert_called_once_with(*positional, overwrite=True)
                self.assertIn('"status": "succeeded"', output)
                self.assertIn('"verified": true', output)

    def test_transfer_receipt_routes_page_without_starting_transfer(self):
        service = self.service()
        service.transfer_receipt.return_value = {"ok": True, "rows": [], "offset": 3, "limit": 8}
        code, output, _ = self.run_cli(["transfer-receipt", "manifest-identifier", "--offset", "3", "--limit", "8"], service)
        self.assertEqual(code, 0)
        service.transfer_receipt.assert_called_once_with("manifest-identifier", 3, 8)
        service.jobs.get.assert_not_called()
        self.assertEqual(json.loads(output)["offset"], 3)

    def test_prepare_waits_until_verified_download_is_ready(self):
        service = self.service()
        service.prepare_file.return_value = {"status": "preparing", "job_id": "first"}
        service.jobs.get.side_effect = [
            {"status": "running", "job_id": "first"},
            {"status": "succeeded", "job_id": "first", "result": {"ok": True, "verified": True, "local_path": "materialized.txt"}},
        ]
        code, output, _ = self.run_cli(["prepare", "/资料/notes.txt"], service)
        self.assertEqual(code, 0)
        result = json.loads(output)
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["verified"])
        self.assertEqual(result["local_path"], "materialized.txt")

    def test_read_waits_for_a_second_preparation_and_preserves_user_content(self):
        service = self.service()
        service.read_file.side_effect = [
            {"status": "preparing", "job_id": "first"},
            {"status": "preparing", "job_id": "second"},
            {"ok": True, "status": "text_read", "text": "access_token=USER_DOCUMENT_LITERAL", "untrusted_content": True},
        ]
        service.jobs.get.side_effect = [
            {"status": "succeeded", "job_id": "first", "result": {"ok": True}},
            {"status": "running", "job_id": "second"},
            {"status": "succeeded", "job_id": "second", "result": {"ok": True}},
        ]
        code, output, _ = self.run_cli(["read", "/资料/notes.txt", "--start-line", "4", "--lines", "7"], service)
        self.assertEqual(code, 0)
        result = json.loads(output)
        self.assertEqual(result["status"], "text_read")
        self.assertEqual(result["text"], "access_token=USER_DOCUMENT_LITERAL")
        self.assertEqual(service.read_file.call_count, 3)
        service.read_file.assert_called_with("/资料/notes.txt", 4, 7)
        self.assertNotIn('"preparing"', output)

    def test_read_bytes_retries_pending_until_actual_bytes_are_returned(self):
        service = self.service()
        service.read_bytes.side_effect = [
            {"status": "preparing", "job_id": "first"},
            {"status": "preparing", "job_id": "second"},
            {"ok": True, "content_kind": "bytes", "data_base64": "YWJj", "eof": True},
        ]
        service.jobs.get.side_effect = [
            {"status": "succeeded", "job_id": "first", "result": {"ok": True}},
            {"status": "succeeded", "job_id": "second", "result": {"ok": True}},
        ]
        code, output, _ = self.run_cli(["read-bytes", "/资料/data.bin", "--offset", "12", "--limit", "24"], service)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["data_base64"], "YWJj")
        self.assertEqual(service.read_bytes.call_count, 3)
        service.read_bytes.assert_called_with("/资料/data.bin", 12, 24)

    def test_failed_second_read_preparation_never_reports_read_complete(self):
        service = self.service()
        service.read_file.side_effect = [{"status": "preparing", "job_id": "first"},
                                         {"status": "preparing", "job_id": "second"}]
        service.jobs.get.side_effect = [
            {"status": "succeeded", "job_id": "first", "result": {"ok": True}},
            {"status": "failed", "job_id": "second", "result": {"ok": False, "error": "remote_changed"}},
        ]
        code, output, _ = self.run_cli(["read", "/資料/notes.txt"], service)
        self.assertEqual(code, 1)
        result = json.loads(output)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["result"]["error"], "remote_changed")
        self.assertNotIn("text", result)

    def test_interrupted_preparation_and_failed_transfer_exit_nonzero(self):
        for command in ("prepare", "get"):
            with self.subTest(command=command):
                service = self.service()
                service.jobs.get.return_value = {"status": "interrupted", "job_id": "first", "result": {"ok": False}}
                if command == "prepare":
                    service.prepare_file.return_value = {"status": "preparing", "job_id": "first"}
                    arguments = ["prepare", "/notes.txt"]
                else:
                    service.start_get.return_value = {"status": "queued", "job_id": "first"}
                    arguments = ["get", "/notes.txt", "local-target"]
                code, output, _ = self.run_cli(arguments, service)
                self.assertEqual(code, 1)
                self.assertIn('"status": "interrupted"', output)

    def test_config_path_is_forwarded_to_service_without_default_substitution(self):
        service = self.service()
        service.index_status.return_value = {"stats": {}}
        explicit = Path.cwd() / "explicit-config.json"
        code, _, created = self.run_cli(["--config", str(explicit), "index-status"], service)
        self.assertEqual(code, 0)
        created.assert_called_once_with(explicit)

    def test_terminal_bduss_uses_explicit_normalization_without_secret_process_arguments(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            executable = root / "fake-pcs.exe"
            executable.write_bytes(b"not executed")
            service = self.service()
            service.settings = SimpleNamespace(backend="pcs", state_dir=root / "state",
                                              pcs_executable=str(executable), timeout=60)
            with patch("cli.getpass.getpass", side_effect=['"BDUSS=FAKE_BDUSS_ONLY"', "FAKE_STOKEN_ONLY"]), \
                    patch("baidu_netdisk.session_import.import_cookie", return_value={"ok": True, "account_id": "100"}) as imported, \
                    patch("cli.subprocess.run", side_effect=AssertionError("Secrets must not be process arguments")):
                code, output, _ = self.run_cli(["login", "--method", "bduss"], service)
            self.assertEqual(code, 0)
            self.assertEqual(imported.call_args.args[0], "BDUSS=FAKE_BDUSS_ONLY; STOKEN=FAKE_STOKEN_ONLY")
            self.assertNotIn("FAKE_BDUSS_ONLY", output)
            self.assertNotIn("FAKE_STOKEN_ONLY", output)

    def test_wrong_cookie_field_in_bduss_mode_is_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            executable = root / "fake-pcs.exe"
            executable.write_bytes(b"not executed")
            service = self.service()
            service.settings = SimpleNamespace(backend="pcs", state_dir=root / "state",
                                              pcs_executable=str(executable), timeout=60)
            with patch("cli.getpass.getpass", return_value="STOKEN=FAKE_OTHER_COOKIE_VALUE"), \
                    patch("baidu_netdisk.session_import.import_cookie") as imported:
                code, output, _ = self.run_cli(["login", "--method", "bduss"], service)
            self.assertEqual(code, 1)
            self.assertIn('"error": "invalid_bduss"', output)
            self.assertNotIn("FAKE_OTHER_COOKIE_VALUE", output)
            imported.assert_not_called()


if __name__ == "__main__":
    unittest.main()
