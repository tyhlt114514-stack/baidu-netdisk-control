"""Local console setup and direct command entry point. Never pass secrets as flags."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from baidu_netdisk.common import NetdiskError, file_lock, redact
from baidu_netdisk.config import Settings
from baidu_netdisk.service import NetdiskService


def output(value, preserve_content=False):
    print(json.dumps(value if preserve_content else redact(value), ensure_ascii=False, indent=2), flush=True)


def login(settings, method, gui=False):
    if settings.backend == "openapi":
        from baidu_netdisk.auth import TokenStore
        return TokenStore(settings).login_interactive()
    executable = Path(settings.pcs_executable)
    if not executable.is_file():
        raise NetdiskError("not_installed", "请先运行 setup.ps1 安装 BaiduPCS-Go。")
    print("账号授权只在本地窗口或终端完成；凭据请勿发送到聊天中。")
    state = settings.state_dir / "pcs"
    state.mkdir(parents=True, exist_ok=True)
    # Validate directly against Netdisk HTTPS endpoints. The upstream CLI login
    # also depends on an unrelated legacy Tieba identity endpoint.
    from baidu_netdisk.session_import import import_cookie
    from baidu_netdisk.common import atomic_json
    from baidu_netdisk.pending_session import PendingSession
    pending = PendingSession(settings.state_dir)

    def verify(cookie, *, cancelled=None, source=method):
        def stopped():
            try:
                return cancelled is not None and bool(cancelled())
            except Exception:
                return True
        if stopped():
            raise NetdiskError("login_cancelled", "本次授权已取消，未保存会话。")
        generation = pending.save(cookie, source=source)
        try:
            verified = import_cookie(cookie, state, timeout=timeout, cancelled=cancelled) if cancelled is not None else import_cookie(cookie, state, timeout=timeout)
        except NetdiskError as exc:
            if exc.code == "login_cancelled" or stopped():
                pending.clear(generation)
            atomic_json(settings.state_dir / "login-diagnostic.json", {**exc.as_dict(), "pending_session": pending.status()})
            raise
        pending.clear(generation)
        return verified

    try:
        timeout = min(300, max(1, int(settings.timeout)))
        if method == "qr":
            from baidu_netdisk.qr_login import masked_qr_login_dialog
            status = masked_qr_login_dialog(lambda cookie, cancelled: verify(cookie, cancelled=cancelled))
        else:
            if method == "cookie":
                from baidu_netdisk.login import normalize_cookie, masked_cookie_dialog
                cookie = masked_cookie_dialog() if gui else normalize_cookie(getpass.getpass("百度网盘 Cookie（输入不会显示）: "))
            else:
                from baidu_netdisk.login import normalize_login_input
                cookie = normalize_login_input(getpass.getpass("BDUSS（输入不会显示）: "), "bduss")
                stoken = getpass.getpass("STOKEN（可留空，部分分享操作需要）: ").strip()
                if any(ord(c) < 32 or ord(c) > 126 for c in stoken):
                    raise NetdiskError("invalid_credential", "凭据不能包含换行或控制字符。")
                if stoken:
                    cookie += "; STOKEN=" + stoken
            status = verify(cookie)
        atomic_json(settings.state_dir / "login-diagnostic.json", status)
        return status
    except NetdiskError as exc:
        atomic_json(settings.state_dir / "login-diagnostic.json", {**exc.as_dict(), "pending_session": pending.status()})
        raise


def retry_login(settings):
    if settings.backend != "pcs":
        raise NetdiskError("unsupported_operation", "待验证会话重试用于个人网盘 PCS 后端。")
    from baidu_netdisk.pending_session import PendingSession
    from baidu_netdisk.session_import import import_cookie
    from baidu_netdisk.common import atomic_json
    pending = PendingSession(settings.state_dir)
    try:
        current = pending.load()
        result = import_cookie(current["cookie"], settings.state_dir / "pcs",
                               timeout=min(300, max(1, int(settings.timeout))))
        pending.clear(current["generation"])
        atomic_json(settings.state_dir / "login-diagnostic.json", result)
        return result
    except NetdiskError as exc:
        atomic_json(settings.state_dir / "login-diagnostic.json", {**exc.as_dict(), "pending_session": pending.status()})
        raise


def main():
    parser = argparse.ArgumentParser(description="直接调用百度网盘接口，不使用 Computer Use")
    parser.add_argument("--config", type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("login-status")
    sub.add_parser("login-retry", help="重试本机加密的待验证会话，不需再输入凭据或扫码")
    auth = sub.add_parser("login")
    auth.add_argument("--method", choices=["bduss", "cookie", "qr"], default="cookie")
    auth.add_argument("--gui", action="store_true", help="使用本地隐藏输入窗口，可直接粘贴 Cookie")
    ls = sub.add_parser("list")
    ls.add_argument("path", nargs="?", default="/")
    ls.add_argument("--limit", type=int, default=100)
    ls.add_argument("--start", type=int, default=0)
    search = sub.add_parser("search")
    search.add_argument("keyword")
    search.add_argument("--path", default="/")
    sub.add_parser("quota")
    info = sub.add_parser("info")
    info.add_argument("--path")
    info.add_argument("--fs-id", type=int)
    mkdir = sub.add_parser("mkdir")
    mkdir.add_argument("path")
    rename = sub.add_parser("rename")
    rename.add_argument("path")
    rename.add_argument("new_name")
    for command in ("move", "copy"):
        child = sub.add_parser(command)
        child.add_argument("destination")
        child.add_argument("paths", nargs="+")
    delete = sub.add_parser("delete")
    delete.add_argument("paths", nargs="+")
    upload = sub.add_parser("upload")
    upload.add_argument("local_path")
    upload.add_argument("remote_path")
    upload.add_argument("--overwrite", action="store_true")
    download = sub.add_parser("download")
    download.add_argument("local_path")
    download.add_argument("--remote-path")
    download.add_argument("--fs-id", type=int)
    download.add_argument("--overwrite", action="store_true")
    job = sub.add_parser("job")
    job.add_argument("job_id")
    sub.add_parser("jobs")
    share = sub.add_parser("share")
    share.add_argument("paths", nargs="+")
    share.add_argument("--code", required=True)
    share.add_argument("--days", type=int, default=7)
    sub.add_parser("shares")
    cancel = sub.add_parser("cancel-share")
    cancel.add_argument("share_ids", nargs="+", type=int)
    scan = sub.add_parser("scan")
    scan.add_argument("path", nargs="?", default="/")
    scan.add_argument("--max-entries", type=int)
    sub.add_parser("index-status")
    glob = sub.add_parser("glob")
    glob.add_argument("pattern")
    glob.add_argument("--path", default="/")
    glob.add_argument("--offset", type=int, default=0)
    glob.add_argument("--limit", type=int, default=100)
    find = sub.add_parser("find")
    find.add_argument("keyword")
    find.add_argument("--path", default="/")
    find.add_argument("--offset", type=int, default=0)
    find.add_argument("--limit", type=int, default=100)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("remote_path")
    read = sub.add_parser("read")
    read.add_argument("remote_path")
    read.add_argument("--start-line", type=int, default=1)
    read.add_argument("--lines", type=int, default=200)
    binary = sub.add_parser("read-bytes")
    binary.add_argument("remote_path")
    binary.add_argument("--offset", type=int, default=0)
    binary.add_argument("--limit", type=int, default=65536)
    for command in ("put", "get"):
        transfer = sub.add_parser(command)
        transfer.add_argument("source")
        transfer.add_argument("destination")
        transfer.add_argument("--overwrite", action="store_true")
    for command in ("upload-tree", "download-tree"):
        transfer = sub.add_parser(command)
        transfer.add_argument("source")
        transfer.add_argument("destination")
        transfer.add_argument("--overwrite", action="store_true")
    manifest = sub.add_parser("transfer-receipt")
    manifest.add_argument("manifest_id")
    manifest.add_argument("--offset", type=int, default=0)
    manifest.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    service = NetdiskService(args.config)
    try:
        command = args.command
        if command == "login":
            result = login(service.settings, args.method, args.gui)
        elif command == "login-retry":
            result = retry_login(service.settings)
        elif command == "status":
            result = service.status()
        elif command == "login-status":
            diagnostic = service.settings.state_dir / "login-diagnostic.json"
            result = json.loads(diagnostic.read_text(encoding="utf-8")) if diagnostic.exists() else {
                "ok": True, "attempt_recorded": False, "message": "更新登录入口后尚无授权记录。"}
            from baidu_netdisk.pending_session import PendingSession
            result["pending_session"] = PendingSession(service.settings.state_dir).status()
        elif command == "list":
            result = service.list_files(args.path, args.limit, args.start)
        elif command == "search":
            result = service.search(args.keyword, args.path)
        elif command == "quota":
            result = service.quota()
        elif command == "info":
            result = service.file_info(args.path, [args.fs_id] if args.fs_id else None)
        elif command == "mkdir":
            result = service.mkdir(args.path)
        elif command == "rename":
            result = service.rename(args.path, args.new_name)
        elif command in ("move", "copy"):
            result = getattr(service, command)(args.paths, args.destination)
        elif command == "delete":
            result = service.delete(args.paths)
        elif command == "upload":
            result = service.start_upload(args.local_path, args.remote_path, args.overwrite)
        elif command == "download":
            result = service.start_download(args.local_path, args.remote_path, args.fs_id, args.overwrite)
        elif command == "job":
            result = service.jobs.get(args.job_id)
        elif command == "jobs":
            result = {"jobs": service.jobs.list()}
        elif command == "share":
            result = service.share(args.paths, args.code, args.days)
        elif command == "shares":
            result = service.shares()
        elif command == "cancel-share":
            result = service.cancel_share(args.share_ids)
        elif command == "scan":
            result = service.start_scan(args.path, max_entries=args.max_entries)
        elif command == "index-status":
            result = service.index_status()
        elif command == "glob":
            result = service.query_index(args.path, recursive=True, pattern=args.pattern, offset=args.offset, limit=args.limit)
        elif command == "find":
            result = service.search_index(args.keyword, args.path, args.offset, args.limit)
        elif command == "prepare":
            result = service.prepare_file(args.remote_path)
        elif command == "read":
            result = service.read_file(args.remote_path, args.start_line, args.lines)
        elif command == "read-bytes":
            result = service.read_bytes(args.remote_path, args.offset, args.limit)
        elif command == "put":
            result = service.start_put(args.source, args.destination, overwrite=args.overwrite)
        elif command == "get":
            result = service.start_get(args.source, args.destination, overwrite=args.overwrite)
        elif command == "upload-tree":
            result = service.start_tree_transfer("upload", args.source, args.destination, overwrite=args.overwrite)
        elif command == "download-tree":
            result = service.start_tree_transfer("download", args.destination, args.source, overwrite=args.overwrite)
        else:
            result = service.transfer_receipt(args.manifest_id, args.offset, args.limit)
        # A verified download can become stale before the following read (for
        # example if another client replaced the cloud file). Keep waiting on
        # each new preparation rather than returning a pending read as success.
        while command in ("prepare", "read", "read-bytes") and result.get("status") == "preparing":
            task = service.jobs.get(result["job_id"])
            while task["status"] in ("queued", "running"):
                time.sleep(0.25)
                task = service.jobs.get(task["job_id"])
            if task["status"] != "succeeded":
                output(task)
                return 1
            if command == "read":
                result = service.read_file(args.remote_path, args.start_line, args.lines)
            elif command == "read-bytes":
                result = service.read_bytes(args.remote_path, args.offset, args.limit)
            else:
                result = {"status": "ready", **task["result"]}
        if command in ("upload", "download", "scan", "put", "get", "upload-tree", "download-tree"):
            output(result)
            print("等待传输完成（MCP 工具会立即返回任务编号）...", flush=True)
            while result["status"] in ("queued", "running"):
                time.sleep(0.25)
                result = service.jobs.get(result["job_id"])
        output(result, preserve_content=command in ("read", "read-bytes"))
        if isinstance(result, dict) and (result.get("ok") is False or result.get("status") in ("failed", "interrupted")):
            return 1
        return 0
    except NetdiskError as exc:
        output(exc.as_dict())
        return 1
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        output({"ok": False, "error": type(exc).__name__, "message": "命令失败，请检查本地输入或网络。"})
        return 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
