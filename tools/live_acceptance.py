"""Opt-in real-account acceptance, never a simulated validation result.

Default invocation prints a plan and does not initialize a backend or read
credentials. Add --run only after local account authorization is verified.
Fixtures and cloud objects are uniquely named and retained for inspection.
The polling deadline does not cancel an in-flight provider operation: on timeout
the report retains its job ID, and Python may stay alive while workers finish.
This helper does not validate completeness of the personal-drive index.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from baidu_netdisk.common import NetdiskError, checked_local
from baidu_netdisk.config import Settings
from baidu_netdisk.service import NetdiskService

TEXT = "百度网盘真实账号验收\naccess_token=USER_FILE_LITERAL\n第二行中文、emoji 🧪\n"
BINARY = bytes(range(256)) * 513 + b"\x00LIVE-ACCEPTANCE\xff"


class AcceptanceFailure(Exception):
    def __init__(self, code, stage, **safe_details):
        self.code, self.stage, self.safe_details = code, stage, safe_details


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        while data := source.read(1024 * 1024):
            result.update(data)
    return result.hexdigest()


def require(condition, code, stage, **details):
    if not condition:
        raise AcceptanceFailure(code, stage, **details)


class Acceptance:
    def __init__(self, config, workspace, timeout):
        self.config = config
        self.settings = Settings.load(config)
        require(self.settings.backend == "pcs", "pcs_backend_required", "preflight")
        self.identifier = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
        parent = checked_local(workspace, self.settings.allowed_local_roots, directory=True)
        require(not parent.is_relative_to(self.settings.state_dir), "private_path_denied", "preflight")
        self.local = parent / self.identifier
        self.remote = "/Codex插件验收/" + self.identifier
        self.deadline = time.monotonic() + timeout
        self.service = None
        self.stage = "plan"
        self.report = {"ok": False, "mode": "plan", "run_id": self.identifier,
                       "local_root": str(self.local), "remote_root": self.remote,
                       "fixtures_retained": True, "personal_index_verified": False,
                       "jobs": [], "checks": {}}

    def check_time(self):
        if time.monotonic() >= self.deadline:
            raise AcceptanceFailure("observation_timeout", self.stage,
                                    provider_operation_may_still_be_running=True)

    def wait_job(self, started, stage, verified=False):
        self.stage = stage
        identifier = started.get("job_id")
        require(isinstance(identifier, str) and re.fullmatch(r"[a-f0-9]{32}", identifier),
                "missing_job_id", stage)
        record = {"stage": stage, "job_id": identifier, "status": "queued"}
        self.report["jobs"].append(record)
        next_progress = time.monotonic() + 30
        while True:
            job = self.service.jobs.get(identifier)
            record["status"] = job["status"]
            if job["status"] not in ("queued", "running"):
                break
            self.check_time()
            if time.monotonic() >= next_progress:
                print(json.dumps({"event": "waiting", **record}, ensure_ascii=False),
                      file=sys.stderr, flush=True)
                next_progress = time.monotonic() + 30
            time.sleep(0.25)
        result = job.get("result")
        require(job["status"] == "succeeded" and isinstance(result, dict) and result.get("ok") is True,
                "job_not_succeeded", stage, job_id=identifier, status=job["status"],
                result_error=safe_error(result))
        if verified:
            require(result.get("verified") is True, "unverified_receipt", stage, job_id=identifier)
        # A second manager reads the persisted receipt through the public API.
        persisted = NetdiskService(self.config).jobs.get(identifier)
        require(persisted.get("status") == "succeeded" and persisted.get("result") == result,
                "persisted_job_mismatch", stage, job_id=identifier)
        record["persisted_receipt_checked"] = True
        return result

    def read_ready(self, callback, stage):
        self.stage = stage
        while True:
            self.check_time()
            result = callback()
            require(isinstance(result, dict), "invalid_read_result", stage)
            if result.get("status") != "preparing":
                require(result.get("ok") is True, "read_failed", stage,
                        result_error=safe_error(result))
                return result
            self.wait_job(result["job"], stage + "_materialize", verified=True)

    def manifest(self, transfer_result, stage, expected):
        self.stage = stage
        identifier = transfer_result.get("manifest_id")
        entries, seen, offset, count, pages = [], set(), 0, None, 0
        while True:
            self.check_time()
            page = self.service.transfer_receipt(identifier, offset=offset, limit=2)
            require(page.get("ok") is True and page.get("status") == "succeeded",
                    "manifest_not_succeeded", stage)
            total = page.get("count")
            require(isinstance(total, int) and total >= 0 and (count is None or count == total),
                    "manifest_count_changed", stage)
            count = total
            selected = page.get("entries")
            require(isinstance(selected, list) and page.get("offset") == offset,
                    "invalid_manifest_page", stage)
            for entry in selected:
                remote = entry.get("remote_path")
                require(remote in expected and remote not in seen and entry.get("status") == "succeeded",
                        "manifest_entry_mismatch", stage)
                require(entry.get("kind") == expected[remote], "manifest_kind_mismatch", stage)
                if entry["kind"] == "file":
                    require(isinstance(entry.get("receipt"), dict) and entry["receipt"].get("verified") is True,
                            "manifest_file_unverified", stage)
                entries.append(entry)
                seen.add(remote)
            pages += 1
            require(page.get("next_offset") == offset + len(selected), "invalid_manifest_cursor", stage)
            offset = page["next_offset"]
            if not page.get("has_more"):
                break
            require(bool(selected) and pages <= len(expected), "manifest_pagination_stalled", stage)
        require(offset == count == len(expected) and seen == set(expected) and pages > 1,
                "manifest_incomplete", stage)
        return {"manifest_id": identifier, "entries": len(entries), "pages": pages,
                "all_receipts_verified": True}

    def verify_remote_file(self, path, size):
        entry = self.service.stat(path).get("entry", {})
        require(entry.get("path") == path and entry.get("is_dir") is False and entry.get("size") == size,
                "file_management_metadata_mismatch", self.stage)

    def verify_absent(self, path):
        try:
            self.service.stat(path)
        except NetdiskError as exc:
            if exc.code == "file_not_found":
                return
            raise
        raise AcceptanceFailure("file_management_source_still_present", self.stage)

    def file_management(self, remote_text, text_path, downloads):
        self.stage = "file_management"
        copy_dir, move_dir = self.remote + "/管理操作/复制目录", self.remote + "/管理操作/移动目录"
        # Parent creation uses the public filesystem operation and its readback.
        for parent in (copy_dir, move_dir):
            self.check_time()
            created = self.service.filesystem.mkdir(parent)
            require(created.get("ok") is True and self.service.stat(parent)["entry"].get("is_dir") is True,
                    "mkdir_not_verified", self.stage)
        self.check_time()
        copied = self.service.copy([remote_text], copy_dir)
        require(copied.get("ok") is True, "copy_not_succeeded", self.stage, result_error=safe_error(copied))
        copy_path = copy_dir + "/云端改名.txt"
        self.verify_remote_file(copy_path, text_path.stat().st_size)
        self.check_time()
        renamed = self.service.rename(copy_path, "重命名.txt")
        require(renamed.get("ok") is True, "rename_not_succeeded", self.stage, result_error=safe_error(renamed))
        renamed_path = copy_dir + "/重命名.txt"
        self.verify_remote_file(renamed_path, text_path.stat().st_size)
        self.verify_absent(copy_path)
        self.check_time()
        moved = self.service.move([renamed_path], move_dir)
        require(moved.get("ok") is True, "move_not_succeeded", self.stage, result_error=safe_error(moved))
        moved_path = move_dir + "/重命名.txt"
        self.verify_remote_file(moved_path, text_path.stat().st_size)
        self.verify_absent(renamed_path)
        target = downloads / "管理操作内容校验.txt"
        self.wait_job(self.service.start_get(moved_path, str(target)), "get_after_file_management", verified=True)
        require(digest(target) == digest(text_path), "file_management_content_mismatch", self.stage)
        self.report["checks"]["mkdir_copy_rename_move_verified"] = True

    def run(self):
        self.report["mode"] = "real_account"
        self.service = NetdiskService(self.config)
        self.stage = "authenticated_root_read"
        # This is a real provider read, rather than the CLI's local who record.
        root = self.service.list_entries("/", start=0, limit=1)
        require(isinstance(root.get("entries"), list), "root_read_failed", self.stage)
        self.report["checks"]["authenticated_root_read"] = True
        self.local.mkdir(parents=True, exist_ok=False)
        source, downloads = self.local / "source", self.local / "downloads"
        source.mkdir()
        downloads.mkdir()
        text_path, binary_path = source / "本地原文.txt", source / "本地数据.bin"
        text_path.write_bytes(TEXT.encode("utf-8"))
        binary_path.write_bytes(BINARY)
        remote_text, remote_binary = self.remote + "/单文件/云端改名.txt", self.remote + "/单文件/云端数据.bin"
        self.wait_job(self.service.start_put(str(text_path), remote_text), "put_text", verified=True)
        self.wait_job(self.service.start_put(str(binary_path), remote_binary), "put_binary", verified=True)
        text_read = self.read_ready(lambda: self.service.read_file(remote_text), "natural_text_read")
        require(text_read.get("text") == TEXT and text_read.get("text_complete") is True,
                "literal_text_not_preserved", self.stage)
        self.report["checks"]["unicode_and_literal_text_preserved"] = True
        offset, chunks, raw_digest = 0, 0, hashlib.sha256()
        while True:
            page = self.read_ready(lambda: self.service.read_bytes(remote_binary, offset=offset, limit=17000),
                                   "natural_binary_read")
            try:
                data = base64.b64decode(page.get("data_base64", ""), validate=True)
            except (ValueError, TypeError):
                raise AcceptanceFailure("invalid_binary_encoding", self.stage) from None
            require(page.get("offset") == offset and page.get("bytes_returned") == len(data) and
                    page.get("next_offset") == offset + len(data), "invalid_binary_cursor", self.stage)
            raw_digest.update(data)
            offset += len(data)
            chunks += 1
            if page.get("eof") is True:
                break
            require(bool(data) and offset <= len(BINARY), "binary_pagination_stalled", self.stage)
        require(offset == len(BINARY) and raw_digest.hexdigest() == digest(binary_path) and chunks > 1,
                "binary_hash_mismatch", self.stage)
        self.report["checks"]["binary_pages"] = {"pages": chunks, "bytes": offset, "sha256_verified": True}
        for label, origin, remote, target in (
                ("text", text_path, remote_text, downloads / "下载后的不同名称.txt"),
                ("binary", binary_path, remote_binary, downloads / "下载改名数据.bin")):
            receipt = self.wait_job(self.service.start_get(remote, str(target)), "get_" + label, verified=True)
            require(receipt.get("local_path") == str(target) and target.is_file() and
                    digest(target) == digest(origin) == receipt.get("sha256"),
                    "exact_download_or_hash_mismatch", self.stage)
        self.report["checks"]["exact_renamed_downloads_sha256"] = True
        tree = self.local / "tree-source"
        (tree / "子目录" / "深层空目录").mkdir(parents=True)
        (tree / "空目录").mkdir()
        (tree / "树根文字.txt").write_bytes(TEXT.encode("utf-8"))
        (tree / "子目录" / "树中数据.bin").write_bytes(BINARY)
        remote_tree, restored = self.remote + "/目录往返", self.local / "tree-restored"
        expected = {remote_tree: "directory", remote_tree + "/空目录": "directory",
                    remote_tree + "/子目录": "directory", remote_tree + "/子目录/深层空目录": "directory",
                    remote_tree + "/树根文字.txt": "file", remote_tree + "/子目录/树中数据.bin": "file"}
        up = self.wait_job(self.service.start_tree_transfer("upload", str(tree), remote_tree), "upload_tree")
        self.report["checks"]["upload_manifest"] = self.manifest(up, "upload_manifest", expected)
        down = self.wait_job(self.service.start_tree_transfer("download", str(restored), remote_tree), "download_tree")
        self.report["checks"]["download_manifest"] = self.manifest(down, "download_manifest", expected)
        require(tree_snapshot(tree) == tree_snapshot(restored), "tree_roundtrip_mismatch", "tree_hashes")
        require((restored / "空目录").is_dir() and not any((restored / "空目录").iterdir()) and
                (restored / "子目录" / "深层空目录").is_dir() and
                not any((restored / "子目录" / "深层空目录").iterdir()),
                "empty_directories_not_preserved", "tree_hashes")
        self.report["checks"]["tree_files_sha256_and_empty_directories"] = True
        self.file_management(remote_text, text_path, downloads)
        self.report.update(ok=True, stage="complete", actual_provider_operations_verified=True)
        return self.report


def tree_snapshot(root):
    return {str(path.relative_to(root)): {"kind": "directory"} if path.is_dir() else
            {"kind": "file", "size": path.stat().st_size, "sha256": digest(path)}
            for path in Path(root).rglob("*")}


def safe_error(result):
    value = result.get("error") if isinstance(result, dict) else None
    value = value.get("code") if isinstance(value, dict) else value
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value) else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=PROJECT / "config.json")
    parser.add_argument("--workspace", type=Path, default=PROJECT / "artifacts" / "live-acceptance")
    parser.add_argument("--timeout", type=float, default=1800, help="Polling observation limit in seconds; does not cancel transfers")
    parser.add_argument("--run", action="store_true", help="Perform real reads and writes on the locally authorized account")
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or not 1 <= args.timeout <= 86400:
        parser.error("--timeout must be finite and between 1 and 86400 seconds")
    acceptance = None
    try:
        acceptance = Acceptance(args.config, args.workspace, args.timeout)
        report = acceptance.run() if args.run else acceptance.report
    except AcceptanceFailure as exc:
        report = acceptance.report if acceptance else {"mode": "real_account" if args.run else "plan"}
        report.update(ok=False, error=exc.code, stage=exc.stage, **exc.safe_details)
    except NetdiskError as exc:
        report = acceptance.report if acceptance else {"mode": "real_account" if args.run else "plan"}
        report.update(ok=False, error=safe_error({"error": exc.code}) or "netdisk_error",
                      stage=acceptance.stage if acceptance else "preflight")
    except Exception as exc:
        report = acceptance.report if acceptance else {"mode": "real_account" if args.run else "plan"}
        report.update(ok=False, error=type(exc).__name__, stage=acceptance.stage if acceptance else "preflight")
    if acceptance and acceptance.local.is_dir():
        try:
            (acceptance.local / "acceptance-report.json").write_text(
                json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            report.update(ok=False, report_write_failed=True)
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    return 0 if not args.run or report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
