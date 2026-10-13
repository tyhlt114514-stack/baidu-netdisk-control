"""Direct, authorized Baidu Netdisk Open Platform backend.

No browser automation or private web endpoints are used. File operations are
restricted to the configured app directory, including reads and downloads.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import posixpath
import tempfile
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

from .common import NetdiskError, atomic_json, checked_local, file_lock, normalize_remote, redact
from .http import HttpClient, trusted_url

FILE_API = "https://pan.baidu.com/rest/2.0/xpan/file"
USER_API = "https://pan.baidu.com/rest/2.0/xpan/nas"
LOCATE_API = "https://d.pcs.baidu.com/rest/2.0/pcs/file"
MIB = 1024 * 1024
GIB = 1024 * MIB
MAX_PARTS = 1024


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _positive_id(value) -> int:
    if isinstance(value, bool):
        raise NetdiskError("invalid_fs_id", "文件 ID 必须为正整数。")
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise NetdiskError("invalid_fs_id", "文件 ID 必须为正整数。") from None
    if result < 1 or result >= 2 ** 64 or str(value) != str(result):
        raise NetdiskError("invalid_fs_id", "文件 ID 必须为 uint64 范围内的正整数。")
    return result


class ApiBackend:
    _locks_guard = threading.Lock()
    _upload_locks: dict[str, threading.Lock] = {}

    def __init__(self, settings, token_store, http=None):
        self.settings = settings
        self.tokens = token_store
        self.http = http or HttpClient(settings.timeout)
        self.remote_root = normalize_remote(settings.remote_root, allow_root=False)
        if not self.remote_root.startswith("/apps/") or len(self.remote_root.split("/")) != 3:
            raise NetdiskError("invalid_app_directory", "官方 API 的 remote_root 必须为 /apps/应用名称。")
        self._known_paths: dict[int, str] = {}
        self._known_guard = threading.Lock()

    def _scope(self, path: str, allow_root: bool = True) -> str:
        path = normalize_remote(path)
        if path == "/" and allow_root:
            return self.remote_root
        if not (path == self.remote_root or path.startswith(self.remote_root + "/")):
            raise NetdiskError("remote_path_denied", "官方 API 仅能操作此应用的授权目录。",
                               {"remote_root": self.remote_root})
        if not allow_root and path == self.remote_root:
            raise NetdiskError("app_root_protected", "不能修改或删除整个应用目录。")
        return path

    def _local(self, path, must_exist=False) -> Path:
        local = checked_local(path, self.settings.allowed_local_roots, must_exist=must_exist)
        if local.is_relative_to(Path(self.settings.state_dir).resolve()):
            raise NetdiskError("private_path_denied", "不能上传或覆盖插件的凭据、任务及续传状态目录。")
        return local

    @staticmethod
    def _name(name: str) -> str:
        if (not isinstance(name, str) or not name or name in (".", "..") or
                any(c in name for c in '/\\:*?"<>|') or any(ord(c) < 32 for c in name)):
            raise NetdiskError("invalid_name", "文件名不能为空，且不能含路径分隔符或非法字符。")
        return name

    def _check(self, response: dict) -> dict:
        # The locateupload endpoint uses error_code; XPan uses errno. Both may
        # appear inside a data envelope. An HTTP 200 alone never implies success.
        envelopes = [response]
        if isinstance(response.get("data"), dict):
            envelopes.append(response["data"])
        for envelope in envelopes:
            for field in ("errno", "error_code"):
                if field in envelope and str(envelope[field]) not in ("0", "None"):
                    code = str(envelope[field])
                    message = (envelope.get("errmsg") or envelope.get("error_msg") or
                               envelope.get("show_msg") or "百度网盘接口返回业务错误。")
                    raise NetdiskError("baidu_" + code, str(redact(message)),
                                       {"errno": code, "request_id": response.get("request_id")})
        return response

    def _request(self, method: str | None, *, url=FILE_API, params=None, data=None,
                 body=None, headers=None, http_method="GET") -> dict:
        query = {"access_token": self.tokens.access_token(), **(params or {})}
        if method is not None:
            query["method"] = method
        response = self.http.request_json(url, params=query, data=data, body=body,
                                          headers=headers, method=http_method)
        if method != "upload" and not ("errno" in response or "error_code" in response or
                isinstance(response.get("data"), dict) and
                ("errno" in response["data"] or "error_code" in response["data"])):
            raise NetdiskError("invalid_response", "百度接口缺少业务结果码，无法确认操作结果。")
        return self._check(response)

    def _entries(self, response: dict) -> list[dict]:
        entries = response.get("list")
        if entries is None and isinstance(response.get("data"), dict):
            entries = response["data"].get("list")
        if not isinstance(entries, list):
            raise NetdiskError("invalid_response", "文件接口未返回有效列表。")
        for entry in entries:
            if not isinstance(entry, dict):
                raise NetdiskError("invalid_response", "文件接口返回了无效条目。")
            self._check(entry)
            returned_path = normalize_remote(entry.get("path", ""))
            if not (returned_path == self.remote_root or returned_path.startswith(self.remote_root + "/")):
                raise NetdiskError("remote_path_denied", "百度返回的文件不在应用授权目录内。")
            if entry.get("fs_id") is not None:
                with self._known_guard:
                    self._known_paths[_positive_id(entry["fs_id"])] = returned_path
        return entries

    def status(self) -> dict:
        authorization = self.tokens.status() if hasattr(self.tokens, "status") else {"authorized": True}
        return {"backend": "openapi", "remote_root": self.remote_root,
                "scope": "应用授权目录内的文件查询、管理、上传和下载", **authorization,
                "upload_resume": "根据服务端 precreate 返回的缺失分片续传",
                "share_supported": False,
                "share_requirement": "官方分享 REST 服务需企业认证、付费及单独开通权限；本后端未接入。"}

    def list_files(self, path="/", limit=100, start=0) -> dict:
        path = self._scope(path)
        if (isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000 or
                isinstance(start, bool) or not isinstance(start, int) or start < 0):
            raise NetdiskError("invalid_pagination", "limit 应为 1～1000 的整数，start 应为非负整数。")
        response = self._request("list", params={"dir": path, "limit": limit, "start": start,
                                                  "order": "name"})
        entries = self._entries(response)
        return {"path": path, "list": entries, "start": start, "limit": limit,
                "next_start": start + len(entries), "has_more": len(entries) == limit}

    def search(self, keyword, path="/", recursive=True, limit=100) -> dict:
        path = self._scope(path)
        if not isinstance(keyword, str) or not keyword or len(keyword) > 30:
            raise NetdiskError("invalid_keyword", "搜索关键字应为 1～30 个字符。")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise NetdiskError("invalid_limit", "搜索返回上限应为 1～500。")
        params = {"key": keyword, "dir": path, "num": 500}
        if recursive:
            params["recursion"] = 1
        response = self._request("search", params=params)
        entries = self._entries(response)
        return {"path": path, "list": entries[:limit],
                "has_more": bool(response.get("has_more")) or len(entries) > limit,
                "truncated": len(entries) > limit,
                "pagination_note": "官方搜索接口未定义可依赖的分页参数，单次至多返回 500 条。"}

    def quota(self) -> dict:
        return self._request(None, url="https://pan.baidu.com/api/quota",
                             params={"checkfree": 1, "checkexpire": 1})

    def user_info(self) -> dict:
        return self._request("uinfo", url=USER_API, params={"vip_version": "v2"})

    def _path_info(self, path: str, dlink: bool = False) -> dict | None:
        path = self._scope(path)
        try:
            response = self._request("filemetas", data={"target": _json([path]),
                                                       "dlink": int(dlink)}, http_method="POST")
            entries = self._entries(response)
        except NetdiskError as exc:
            if exc.code in ("baidu_-9", "baidu_31066", "baidu_31190"):
                return None
            raise
        for item in entries:
            if normalize_remote(item["path"]) == path:
                return item
        return None

    def _resolve_ids(self, fs_ids: list[int]) -> list[str]:
        with self._known_guard:
            pending = set(fs_ids) - self._known_paths.keys()
        if pending:
            # Resolve unknown IDs solely by traversing the authorized app folder.
            # Do not query arbitrary IDs before their authorization is known.
            queue, visited, scanned = [self.remote_root], set(), 0
            while queue and pending:
                directory = queue.pop()
                if directory in visited:
                    continue
                visited.add(directory)
                start = 0
                while True:
                    page = self.list_files(directory, limit=1000, start=start)
                    scanned += len(page["list"])
                    for item in page["list"]:
                        if item.get("fs_id") is not None:
                            pending.discard(int(item["fs_id"]))
                        if item.get("isdir"):
                            queue.append(item["path"])
                    if scanned > 100000 or len(visited) > 1000:
                        raise NetdiskError("lookup_limit", "应用目录较大，请先列出或搜索目标文件再使用其 ID。")
                    if not pending or not page["has_more"]:
                        break
                    start = page["next_start"]
        if pending:
            raise NetdiskError("file_not_found", "此文件 ID 不在应用授权目录的可见文件中。",
                               {"fs_ids": sorted(pending), "remote_root": self.remote_root})
        with self._known_guard:
            return [self._known_paths[i] for i in fs_ids]

    def _file_info(self, fs_ids, dlink=False) -> dict:
        if isinstance(fs_ids, (int, str)):
            fs_ids = [fs_ids]
        if not isinstance(fs_ids, (list, tuple)) or not 1 <= len(fs_ids) <= 100:
            raise NetdiskError("invalid_fs_ids", "请提供 1～100 个文件 ID。")
        ids = [_positive_id(i) for i in fs_ids]
        paths = self._resolve_ids(ids)
        response = self._request("filemetas", data={"target": _json(paths), "dlink": int(dlink)},
                                 http_method="POST")
        entries = self._entries(response)
        returned_ids = {_positive_id(i["fs_id"]) for i in entries if "fs_id" in i}
        if not set(ids).issubset(returned_ids):
            with self._known_guard:
                for fs_id in set(ids) - returned_ids:
                    self._known_paths.pop(fs_id, None)
            raise NetdiskError("file_not_found", "文件已被移动、替换或删除，请重新列出文件并取得 ID。")
        return {"list": entries}

    def file_info(self, fs_ids) -> dict:
        response = self._file_info(fs_ids)
        # Signed transport URLs are internal credentials, not model output.
        return {"list": [{k: v for k, v in item.items() if k != "dlink"} for item in response["list"]]}

    def mkdir(self, path) -> dict:
        path = self._scope(path, allow_root=False)
        response = self._request("create", data={"path": path, "isdir": 1, "rtype": 0},
                                 http_method="POST")
        if response.get("path") != path or int(response.get("isdir", 0)) != 1 or not response.get("fs_id"):
            raise NetdiskError("verification_failed", "百度未返回预期的文件夹创建结果。")
        with self._known_guard:
            self._known_paths[_positive_id(response["fs_id"])] = path
        return response

    def _manager(self, opera, files, overwrite=False) -> dict:
        if not 1 <= len(files) <= 100:
            raise NetdiskError("invalid_file_count", "单次文件管理需提供 1～100 个对象。")
        data = {"async": 0, "filelist": _json(files)}
        if opera != "delete":
            data["ondup"] = "overwrite" if overwrite else "fail"
        response = self._request("filemanager", params={"opera": opera}, data=data, http_method="POST")
        for item in response.get("info", []):
            if not isinstance(item, dict) or "errno" not in item:
                raise NetdiskError("invalid_response", "文件管理响应缺少逐项操作结果码。")
            self._check(item)
        if response.get("taskid"):
            # Never claim the mutation has completed merely because it was queued.
            return {**response, "completed": False, "message": "服务端返回异步任务，请重新查询文件确认结果。"}
        if not isinstance(response.get("info"), list) or len(response["info"]) != len(files):
            raise NetdiskError("verification_failed", "百度未返回每个文件的同步操作结果。")
        with self._known_guard:
            self._known_paths.clear()
        return {**response, "completed": True}

    def rename(self, path, new_name, overwrite=False) -> dict:
        path = self._scope(path, allow_root=False)
        return self._manager("rename", [{"path": path, "newname": self._name(new_name)}], overwrite)

    def move(self, path, destination, new_name=None, overwrite=False) -> dict:
        return self._move_copy("move", path, destination, new_name, overwrite)

    def copy(self, path, destination, new_name=None, overwrite=False) -> dict:
        return self._move_copy("copy", path, destination, new_name, overwrite)

    def _move_copy(self, opera, path, destination, new_name, overwrite) -> dict:
        path = self._scope(path, allow_root=False)
        destination = self._scope(destination)
        name = self._name(new_name or posixpath.basename(path))
        target = posixpath.join(destination, name)
        if target == path or target.startswith(path + "/"):
            raise NetdiskError("invalid_destination", "目标不能与源路径相同，也不能位于源目录内部。")
        return self._manager(opera, [{"path": path, "dest": destination, "newname": name}], overwrite)

    def delete(self, paths) -> dict:
        if isinstance(paths, str):
            paths = [paths]
        if not isinstance(paths, (list, tuple)):
            raise NetdiskError("invalid_paths", "paths 应为网盘路径数组。")
        return self._manager("delete", [self._scope(p, allow_root=False) for p in paths])

    def _upload_host(self, remote, uploadid) -> tuple[str, float]:
        response = self._request("locateupload", url=LOCATE_API,
                                 params={"appid": 250528, "path": remote, "uploadid": uploadid,
                                         "upload_version": "2.0"})
        candidates = [i.get("server") for i in response.get("servers", []) if isinstance(i, dict)]
        if response.get("host"):
            candidates.append("https://" + response["host"])
        for candidate in candidates:
            try:
                if not isinstance(candidate, str):
                    continue
                trusted_url(candidate)
                parsed = urllib.parse.urlsplit(candidate)
                if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
                    continue
                try:
                    expiry = float(response.get("expire", 60))
                except (ValueError, TypeError):
                    raise NetdiskError("invalid_upload_host", "百度返回了无效的上传域名有效期。") from None
                if not math.isfinite(expiry) or expiry <= 0:
                    raise NetdiskError("invalid_upload_host", "百度返回的上传域名已过期。")
                return candidate.rstrip("/"), expiry * 0.8
            except (NetdiskError, ValueError):
                continue
        raise NetdiskError("invalid_upload_host", "百度未提供可信的 HTTPS 上传域名。")

    @staticmethod
    def _hash_source(local: Path, part_size: int) -> tuple[list[str], str, str, tuple[int, int]]:
        before = local.stat()
        whole = hashlib.md5()
        blocks = []
        with local.open("rb") as source:
            first = source.read(256 * 1024)
            slice_md5 = hashlib.md5(first).hexdigest()
            source.seek(0)
            while block := source.read(part_size):
                blocks.append(hashlib.md5(block).hexdigest())
                whole.update(block)
        after = local.stat()
        fingerprint = (before.st_size, before.st_mtime_ns)
        if fingerprint != (after.st_size, after.st_mtime_ns):
            raise NetdiskError("source_changed", "计算校验值时本地文件发生变化，请重新上传。")
        return blocks or [hashlib.md5(b"").hexdigest()], whole.hexdigest(), slice_md5, fingerprint

    def upload(self, local_path, remote_path, overwrite=False) -> dict:
        local = self._local(local_path, must_exist=True)
        remote = self._scope(remote_path, allow_root=False)
        lock_key = str(self.settings.state_dir.resolve()) + remote
        with self._locks_guard:
            lock = self._upload_locks.setdefault(lock_key, threading.Lock())
        with lock:
            lock_name = hashlib.sha256(remote.encode("utf-8")).hexdigest() + ".lock"
            with file_lock(Path(self.settings.state_dir) / "upload-locks" / lock_name):
                return self._upload(local, remote, overwrite)

    def _upload(self, local, remote, overwrite) -> dict:
        existing = self._path_info(remote)
        if existing:
            if existing.get("isdir"):
                raise NetdiskError("destination_is_directory", "上传目标是目录，请提供完整目标文件路径。")
            if not overwrite:
                raise NetdiskError("file_exists", "网盘已有同名文件，默认不会覆盖。")
        size = local.stat().st_size
        part_size, maximum = 4 * MIB, 4 * GIB
        if size > maximum:
            vip = int(self.user_info().get("vip_type", 0))
            if vip == 1:
                part_size, maximum = 16 * MIB, 10 * GIB
            elif vip == 2:
                part_size, maximum = 32 * MIB, 20 * GIB
        if size > maximum or max(1, math.ceil(size / part_size)) > MAX_PARTS:
            raise NetdiskError("upload_size_limit", "文件超过当前账号的官方上传上限。",
                               {"file_bytes": size, "maximum_bytes": maximum})
        blocks, content_md5, slice_md5, fingerprint = self._hash_source(local, part_size)
        if fingerprint[0] != size:
            raise NetdiskError("source_changed", "开始计算校验值前本地文件大小发生变化。")
        state_key = hashlib.sha256((str(local) + "\0" + remote).encode("utf-8")).hexdigest()
        state_path = Path(self.settings.state_dir) / "uploads" / (state_key + ".json")
        identity = {"path": remote, "local_path": str(local), "size": size,
                    "mtime_ns": fingerprint[1], "part_size": part_size,
                    "block_list": blocks, "overwrite": bool(overwrite)}
        state = {}
        if state_path.exists():
            try:
                candidate = json.loads(state_path.read_text(encoding="utf-8"))
                if candidate.get("identity") == identity:
                    state = candidate
            except (ValueError, OSError, AttributeError):
                pass
        rtype = 3 if overwrite else 0
        predata = {"path": remote, "size": size, "isdir": 0, "autoinit": 1, "rtype": rtype,
                   "block_list": _json(blocks), "content-md5": content_md5, "slice-md5": slice_md5,
                   "local_ctime": int(local.stat().st_ctime), "local_mtime": int(local.stat().st_mtime)}
        if state.get("uploadid"):
            predata["uploadid"] = state["uploadid"]
        try:
            precreate = self._request("precreate", data=predata, http_method="POST")
        except NetdiskError as exc:
            if "uploadid" not in predata or exc.code not in ("baidu_31355", "baidu_31081"):
                raise
            # Invalid/expired upload task: start a fresh task with the same safe
            # conflict strategy. Never blindly retry non-idempotent create.
            predata.pop("uploadid")
            precreate = self._request("precreate", data=predata, http_method="POST")
        uploadid = precreate.get("uploadid")
        if not isinstance(uploadid, str) or not uploadid:
            raise NetdiskError("invalid_response", "预上传未返回有效 uploadid。")
        returned_path = precreate.get("path", remote)
        if returned_path != remote:
            raise NetdiskError("verification_failed", "预上传返回了意外的文件路径。")
        parts = precreate.get("block_list")
        if not isinstance(parts, list):
            raise NetdiskError("invalid_response", "预上传未返回所需分片序号。")
        # Current official docs explicitly say [] is equivalent to [0].
        parts = parts or [0]
        if (any(isinstance(i, bool) or not isinstance(i, int) or not 0 <= i < len(blocks) for i in parts)
                or len(parts) != len(set(parts))):
            raise NetdiskError("invalid_response", "预上传返回了无效分片序号。")
        state = {"version": 1, "identity": identity, "uploadid": uploadid,
                 "completed_parts": [], "phase": "uploading", "updated_at": time.time()}
        atomic_json(state_path, state)
        host, host_ttl = self._upload_host(remote, uploadid)
        host_at = time.monotonic()
        uploaded_bytes = 0
        with local.open("rb") as source:
            for seq in sorted(parts):
                if (local.stat().st_size, local.stat().st_mtime_ns) != fingerprint:
                    raise NetdiskError("source_changed", "上传期间本地文件发生变化，请重新上传。")
                source.seek(seq * part_size)
                chunk = source.read(part_size)
                if hashlib.md5(chunk).hexdigest() != blocks[seq]:
                    raise NetdiskError("source_changed", "上传分片与最初计算的校验值不同。")
                if time.monotonic() - host_at >= host_ttl:
                    host, host_ttl = self._upload_host(remote, uploadid)
                    host_at = time.monotonic()
                boundary = "baidu-netdisk-" + uuid.uuid4().hex
                head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
                        f"filename=\"part-{seq}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode("ascii")
                body = head + chunk + f"\r\n--{boundary}--\r\n".encode("ascii")
                response = self._request("upload", url=host + "/rest/2.0/pcs/superfile2",
                                         params={"type": "tmpfile", "path": remote,
                                                 "uploadid": uploadid, "partseq": seq},
                                         body=body, headers={"Content-Type": "multipart/form-data; boundary=" + boundary},
                                         http_method="POST")
                if str(response.get("md5", "")).lower() != blocks[seq]:
                    raise NetdiskError("upload_hash_mismatch", "百度返回的分片 MD5 与本地分片不同。", {"partseq": seq})
                uploaded_bytes += len(chunk)
                state["completed_parts"].append(seq)
                state["updated_at"] = time.time()
                atomic_json(state_path, state)
        if (local.stat().st_size, local.stat().st_mtime_ns) != fingerprint:
            raise NetdiskError("source_changed", "完成分片上传前本地文件发生变化。")
        state["phase"] = "creating"
        atomic_json(state_path, state)
        created = self._request("create", data={"path": remote, "size": size, "isdir": 0,
                                                 "rtype": rtype, "uploadid": uploadid,
                                                 "block_list": _json(blocks),
                                                 "local_ctime": predata["local_ctime"],
                                                 "local_mtime": predata["local_mtime"]}, http_method="POST")
        if created.get("path") != remote or int(created.get("size", -1)) != size or not created.get("fs_id"):
            raise NetdiskError("verification_failed", "文件创建结果与上传目标或大小不符。")
        verified = self._path_info(remote)
        if (not verified or int(verified.get("size", -1)) != size or verified.get("isdir") or
                str(verified.get("fs_id")) != str(created["fs_id"])):
            raise NetdiskError("verification_failed", "上传后回查未找到预期文件。")
        state_path.unlink(missing_ok=True)
        return {"path": remote, "fs_id": created["fs_id"], "size": size,
                "uploaded_bytes": uploaded_bytes, "part_size": part_size,
                "parts_uploaded": len(parts), "parts_total": len(blocks), "verified": True,
                "local_md5": content_md5,
                "verification": "所有上传分片 MD5 一致，完成创建后已回查路径、文件 ID 和大小"}

    def download(self, fs_id, local_path, overwrite=False) -> dict:
        local = self._local(local_path)
        if local.exists() and not overwrite:
            raise NetdiskError("file_exists", "本地已有同名文件，默认不会覆盖。")
        metadata = self._file_info([fs_id], dlink=True)["list"]
        item = next((i for i in metadata if int(i["fs_id"]) == _positive_id(fs_id)), None)
        if not item or item.get("isdir") or not item.get("dlink"):
            raise NetdiskError("download_unavailable", "此对象不是可下载文件，或没有返回下载地址。")
        dlink = trusted_url(item["dlink"])
        # Preserve Baidu's signed query verbatim; append just the OAuth token.
        if urllib.parse.urlsplit(dlink).fragment:
            raise NetdiskError("invalid_download_url", "下载地址含意外 fragment。")
        dlink += ("&" if "?" in dlink else "?") + urllib.parse.urlencode({"access_token": self.tokens.access_token()})
        local.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".baidu-download-", suffix=".part", dir=local.parent)
        os.close(fd)
        temporary = Path(name)
        try:
            self.http.download(dlink, temporary, headers={"User-Agent": "pan.baidu.com"},
                               expected_size=int(item["size"]))
            if temporary.stat().st_size != int(item["size"]):
                raise NetdiskError("download_size_mismatch", "下载结果大小与网盘记录不同。")
            if overwrite:
                os.replace(temporary, local)
            else:
                try:
                    # Atomic no-clobber publication on Windows NTFS and POSIX.
                    os.link(temporary, local)
                except FileExistsError:
                    raise NetdiskError("file_exists", "下载期间本地目标被创建，已保留原文件。") from None
                except OSError:
                    raise NetdiskError("download_commit_failed", "本地文件系统无法安全完成下载文件，请检查目录权限。") from None
            return {"fs_id": item["fs_id"], "remote_path": item["path"], "local_path": str(local),
                    "size": item["size"], "verified": True, "verification": "下载字节数与网盘文件大小一致"}
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _unsupported_share():
        raise NetdiskError("unsupported_share", "本官方 API 后端未接入企业付费分享服务。可使用 PCS 后端或百度官方 MCP 的分享工具。")

    def share(self, *args, **kwargs):
        return self._unsupported_share()

    def list_shares(self, *args, **kwargs):
        return self._unsupported_share()

    def cancel_share(self, *args, **kwargs):
        return self._unsupported_share()

    def transfer(self, *args, **kwargs):
        return self._unsupported_share()
