"""Structured, read-only PCS access using the local isolated BaiduPCS-Go session.

Credentials are loaded inside this module, never returned, printed, put in URLs,
or passed through an agent tool argument. This uses the maintained v4.0.2 source
interfaces documented in docs/pcs-json-sources.md, not CLI table parsing.
"""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .common import NetdiskError


_PAGE_SIZE = 1000
_MAX_JSON = 8 * 1024 * 1024
_PAN_URL = "https://pan.baidu.com/api/list"
_PCS_URL = "https://pcs.baidu.com/rest/2.0/pcs/file"
_PAN_UA = "netdisk;P2SP;3.0.0.8;netdisk;11.12.3;ANG-AN00;android-android;10.0;JSbridge4.4.0;jointBridge;1.1.0;"
# requester.DefaultUserAgent in pinned BaiduPCS-Go v4.0.2. Native PCS requests
# explicitly use the global/browser default when no override is configured;
# the Go CLI's empty PCSUA can overwrite that header with an empty value.
_PCS_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"
_COOKIE_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")


def _path(value: str) -> str:
    if (not isinstance(value, str) or not value.startswith("/") or len(value) > 4096
            or "\\" in value or "//" in value or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(piece in (".", "..") for piece in value.split("/"))):
        raise NetdiskError("invalid_path", "需要不含遍历、反斜杠或控制字符的网盘绝对路径。")
    return posixpath.normpath(value)


def _int(value: Any, field_name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not re.fullmatch(r"-?\d+", str(value)):
        raise NetdiskError("invalid_response", f"网盘 {field_name} 字段不是有效整数。")
    number = int(value)
    if number < minimum or number > 2**64 - 1:
        raise NetdiskError("invalid_response", f"网盘 {field_name} 字段超出允许范围。")
    return number


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON property")
        result[key] = value
    return result


def _metadata_md5(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return value.lower()
    if not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9]{9}[g-vG-V][a-fA-F0-9]{22}", value):
        raise NetdiskError("invalid_response", "网盘 md5 元信息无效。")
    # Adapt pinned BaiduPCS-Go v4.0.2 util.go DecryptMD5 (Apache-2.0):
    # restore the marked nibble, undo position XOR, then reorder four blocks.
    # Only the observed encoded format is accepted; this is still unverified
    # server metadata, never proof that downloaded bytes match the digest.
    encoded = value.lower()
    digits = encoded[:9] + format(ord(encoded[9]) - ord("g"), "x") + encoded[10:]
    decoded = "".join(format(int(digit, 16) ^ (index & 15), "x") for index, digit in enumerate(digits))
    return decoded[8:16] + decoded[:8] + decoded[24:32] + decoded[16:24]


def _is_link(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)
    except FileNotFoundError:
        return False


def _trusted_download_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
        host = (parsed.hostname or "").lower()
        allowed = (host == "baidu.com" or host.endswith(".baidu.com")
                   or host == "baidupcs.com" or host.endswith(".baidupcs.com"))
        if (parsed.scheme != "https" or parsed.username or parsed.password
                or parsed.port not in (None, 443) or not allowed):
            raise ValueError("Untrusted origin")
    except (ValueError, TypeError):
        raise NetdiskError("untrusted_url", "下载只允许百度所属域名的 HTTPS 连接。") from None
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise NetdiskError("redirect_blocked", "元信息请求发生重定向，已阻止会话凭证转发。")


class _DownloadRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _trusted_download_url(newurl)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            for header in ("Cookie", "Authorization", "Proxy-Authorization"):
                redirected.remove_header(header)
        return redirected


@dataclass(repr=False)
class _Session:
    uid: str
    name: str
    app_id: int
    pan_ua: str
    pcs_ua: str
    cookie: str = field(repr=False)
    fingerprint: bytes = field(repr=False)

    @property
    def account_id(self) -> str:
        # Upstream force-login uses synthetic UID 24. Distinguish those accounts
        # using the configured account name, never a published credential hash.
        suffix = ":" + hashlib.sha256(self.name.encode("utf-8")).hexdigest()[:16] if self.uid == "24" else ""
        return "pcs:" + self.uid + suffix

    def public_identity(self) -> dict[str, Any]:
        return {"account_id": self.account_id, "account": {"uid": self.uid, "name": self.name},
                "account_source": "local_pcs_config"}


class PcsJsonReader:
    def __init__(self, config_dir: Path, *, timeout: int = 60, transfer_timeout: int = 3600):
        self.config_dir = Path(config_dir).absolute()
        self.timeout = timeout
        self.transfer_timeout = transfer_timeout
        self._lock = threading.RLock()
        self._opener = urllib.request.build_opener(_NoRedirect())
        self._download_opener = urllib.request.build_opener(_DownloadRedirect())

    def _load_session(self) -> _Session:
        source = self.config_dir / "pcs_config.json"
        for ancestor in [source, *source.parents]:
            if _is_link(ancestor):
                raise NetdiskError("unsafe_config", "私有 PCS 配置路径不能含符号链接或重解析点。")
        try:
            with source.open("rb") as file:
                raw = file.read(1024 * 1024 + 1)
        except FileNotFoundError:
            raise NetdiskError("authentication_required", "请先在本地 setup 导入本人网盘会话。") from None
        except OSError:
            raise NetdiskError("config_unreadable", "无法读取插件的私有 PCS 配置。") from None
        if len(raw) > 1024 * 1024:
            raise NetdiskError("invalid_config", "私有 PCS 配置超过大小上限。")
        try:
            config = json.loads(raw, object_pairs_hook=_pairs)
            if not isinstance(config, dict):
                raise ValueError("Config object required")
            uid = _int(config.get("baidu_active_uid", 0), "account_uid")
            users = config.get("baidu_user_list", [])
            if not isinstance(users, list):
                raise ValueError("User list required")
            matches = [user for user in users if isinstance(user, dict) and str(user.get("uid")) == str(uid)]
            if uid == 0 or not matches:
                raise NetdiskError("authentication_required", "请先在本地 setup 导入本人网盘会话。")
            if len(matches) != 1:
                raise ValueError("Ambiguous active account")
            user = matches[0]
            name = user.get("name", "")
            if not isinstance(name, str):
                raise ValueError("Account name required")
            cookies: dict[str, str] = {}
            cookie_text = user.get("cookies", "") or ""
            if not isinstance(cookie_text, str) or len(cookie_text) > 65536:
                raise ValueError("Invalid cookie text")
            for part in cookie_text.split(";"):
                if not part.strip():
                    continue
                key, separator, value = part.strip().partition("=")
                if not separator or not _COOKIE_NAME.fullmatch(key):
                    raise ValueError("Invalid cookie name")
                cookies[key] = value.strip().strip('"')
            for key, setting in (("BDUSS", "bduss"), ("STOKEN", "stoken"), ("PTOKEN", "ptoken"),
                                 ("BAIDUID", "baiduid"), ("SBOXTKN", "sboxtkn")):
                value = user.get(setting, "") or ""
                if not isinstance(value, str):
                    raise ValueError("Invalid session field")
                if value:
                    if key == "BDUSS" and key in cookies and cookies[key] != value:
                        raise ValueError("Conflicting session values")
                    cookies[key] = value
            if not cookies.get("BDUSS"):
                raise NetdiskError("authentication_required", "私有 PCS 配置中缺少有效会话，请重新运行本地 setup。")
            if any(any(ord(c) < 32 or ord(c) > 126 or c == ";" for c in value) for value in cookies.values()):
                raise ValueError("Unsafe cookie characters")
            cookie = "; ".join(f"{key}={value}" for key, value in cookies.items())
            if len(cookie) > 65536:
                raise ValueError("Cookie header too large")
            app_id = _int(config.get("appid", 266719), "app_id", minimum=1)
            pan_ua = config.get("pan_ua") or _PAN_UA
            pcs_ua = config.get("pcs_ua") or config.get("user_agent") or _PCS_UA
            if any(not isinstance(ua, str) or len(ua) > 2048 or any(ord(c) < 32 or ord(c) > 126 for c in ua)
                   for ua in (pan_ua, pcs_ua)):
                raise ValueError("Invalid user agent")
            identity_bytes = json.dumps([str(uid), name, app_id, pan_ua, pcs_ua, cookie], ensure_ascii=False).encode("utf-8")
            return _Session(str(uid), name, app_id, pan_ua, pcs_ua, cookie, hashlib.sha256(identity_bytes).digest())
        except NetdiskError as exc:
            if exc.code == "authentication_required":
                raise
            raise NetdiskError("invalid_config", "私有 PCS 配置格式无效。") from None
        except (ValueError, TypeError, UnicodeError):
            raise NetdiskError("invalid_config", "私有 PCS 配置格式无效。") from None

    def _assert_current(self, session: _Session):
        try:
            current = self._load_session()
        except NetdiskError as exc:
            if exc.code == "authentication_required":
                raise NetdiskError("account_changed", "读取期间网盘会话被移除，请重新开始操作。") from None
            raise
        if current.fingerprint != session.fingerprint:
            raise NetdiskError("account_changed", "读取期间网盘账号或会话改变，请重新开始操作。")

    def account_identity(self) -> dict[str, Any]:
        with self._lock:
            return self._load_session().public_identity()

    @staticmethod
    def _check_api(data: dict[str, Any]):
        for field_name in ("errno", "error_code"):
            if field_name not in data:
                continue
            value = data[field_name]
            if isinstance(value, bool) or not isinstance(value, (int, str)) or not re.fullmatch(r"-?\d+", str(value)):
                raise NetdiskError("invalid_response", "网盘响应错误码格式无效。")
            code = int(value)
            if code:
                category = "authentication_required" if code in (-6, 31045) else "not_found" if code in (-9, 31066) else "remote_error"
                message = "百度未接受当前会话，请检查登录状态与接口兼容性。" if category == "authentication_required" else "网盘文件或目录不存在。" if category == "not_found" else "百度接口拒绝此次读取。"
                # Do not echo server error messages: they can reflect credentials.
                raise NetdiskError(category, message, {"api_code": code})

    def _request_json(self, session: _Session, url: str, *, params: dict[str, Any], body: bytes | None = None,
                      content_type: str | None = None) -> dict[str, Any]:
        if url not in (_PAN_URL, _PCS_URL):
            raise NetdiskError("untrusted_url", "仅允许固定的百度元信息接口。")
        stage = "directory_list" if url == _PAN_URL else "file_meta"
        query = urllib.parse.urlencode(params)
        headers = {"Cookie": session.cookie, "User-Agent": session.pan_ua if url == _PAN_URL else session.pcs_ua,
                   "Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(url + "?" + query, data=body, headers=headers, method="POST" if body is not None else "GET")
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(_MAX_JSON + 1)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise NetdiskError("authentication_required", "百度拒绝读取，请检查网盘会话和权限。", {"status": exc.code, "stage": stage}) from None
            if exc.code == 404:
                # PCS meta uses HTTP 404 for a missing target with its normal
                # JSON business error. A route/proxy 404 must remain HTTP error.
                try:
                    with exc:
                        error_raw = exc.read(_MAX_JSON + 1)
                    if len(error_raw) <= _MAX_JSON:
                        error_data = json.loads(error_raw, object_pairs_hook=_pairs)
                        if isinstance(error_data, dict):
                            codes = [error_data[key] for key in ("errno", "error_code") if key in error_data]
                            if all(not isinstance(code, bool) and isinstance(code, (int, str))
                                   and re.fullmatch(r"-?\d+", str(code))
                                   and int(code) in (0, -9, 31066) for code in codes):
                                self._check_api(error_data)
                except NetdiskError as api_error:
                    if api_error.code == "not_found":
                        raise NetdiskError("not_found", "网盘文件或目录不存在。",
                                           {**api_error.details, "status": 404, "stage": stage}) from None
                except (ValueError, UnicodeError, OSError):
                    pass
            raise NetdiskError("http_error", "百度元信息接口返回 HTTP 错误。", {"status": exc.code, "stage": stage}) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise NetdiskError("network_error", "百度接口连接失败或超时。", {"stage": stage}) from None
        if len(raw) > _MAX_JSON:
            raise NetdiskError("invalid_response", "网盘 JSON 响应超过大小限制。")
        try:
            data = json.loads(raw, object_pairs_hook=_pairs)
        except (ValueError, UnicodeError):
            raise NetdiskError("invalid_response", "百度没有返回有效的 JSON 元信息。") from None
        if not isinstance(data, dict):
            raise NetdiskError("invalid_response", "百度返回了无效的元信息结构。")
        try:
            self._check_api(data)
        except NetdiskError as exc:
            raise NetdiskError(exc.code, exc.message, {**exc.details, "stage": stage}) from None
        self._assert_current(session)
        return data

    @staticmethod
    def _entry(raw: Any, session: _Session) -> dict[str, Any]:
        if not isinstance(raw, dict) or not isinstance(raw.get("path"), str):
            raise NetdiskError("invalid_response", "网盘条目缺少路径。")
        try:
            path = _path(raw["path"])
        except NetdiskError:
            raise NetdiskError("invalid_response", "网盘条目路径无效。") from None
        if path != raw["path"]:
            raise NetdiskError("invalid_response", "网盘条目路径格式不明确。")
        name = raw.get("server_filename", posixpath.basename(path))
        if not isinstance(name, str) or name != posixpath.basename(path):
            raise NetdiskError("invalid_response", "网盘条目名称和路径不一致。")
        is_dir = _int(raw.get("isdir"), "isdir")
        if is_dir not in (0, 1):
            raise NetdiskError("invalid_response", "网盘条目类型无效。")
        fs_id = _int(raw.get("fs_id"), "fs_id", minimum=0 if path == "/" else 1)
        size = _int(raw.get("size", 0) if is_dir else raw.get("size"), "size")
        md5 = _metadata_md5(raw.get("md5"))
        def timestamp(primary, secondary):
            value = raw.get(primary, raw.get(secondary))
            return None if value is None else _int(value, primary)
        return {"path": path, "name": name, "is_dir": bool(is_dir), "size": size,
                "fs_id": str(fs_id), "mtime": timestamp("server_mtime", "mtime"),
                "ctime": timestamp("server_ctime", "ctime"), "md5": md5,
                "md5_source": "server_metadata_unverified", "account_id": session.account_id}

    def _list_page(self, session: _Session, path: str, page: int) -> list[dict[str, Any]]:
        data = self._request_json(session, _PAN_URL, params={"dir": path, "order": "name", "desc": 0,
                                                           "clienttype": 0, "num": _PAGE_SIZE, "page": page})
        raw = data.get("list")
        if not isinstance(raw, list) or len(raw) > _PAGE_SIZE:
            raise NetdiskError("invalid_response", "网盘目录分页没有返回有效的条目列表。")
        if "has_more" in data:
            hint = data["has_more"]
            if hint not in (0, 1, False, True):
                raise NetdiskError("invalid_response", "网盘分页完整性标记无效。")
            if hint and len(raw) < _PAGE_SIZE:
                raise NetdiskError("pagination_inconsistent", "网盘短分页仍标记有后续内容，未声明读取完整。")
        entries = [self._entry(item, session) for item in raw]
        ids, names = set(), set()
        for entry in entries:
            if entry["path"] == path or posixpath.dirname(entry["path"]) != path:
                raise NetdiskError("invalid_response", "网盘目录分页含非直属条目。")
            if entry["fs_id"] in ids or entry["path"] in names:
                raise NetdiskError("pagination_inconsistent", "网盘目录分页含重复条目，未声明目录读取完整。")
            ids.add(entry["fs_id"])
            names.add(entry["path"])
        return entries

    def list_entries(self, path: str = "/", start: int = 0, limit: int = 1000) -> dict[str, Any]:
        path = _path(path)
        if isinstance(start, bool) or not isinstance(start, int) or not 0 <= start <= 2**63 - 1:
            raise NetdiskError("invalid_pagination", "start 应为非负的 64 位整数。")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise NetdiskError("invalid_pagination", "limit 应为 1..1000 的整数。")
        with self._lock:
            session = self._load_session()
            page = start // _PAGE_SIZE + 1
            offset = start % _PAGE_SIZE
            selected = []
            seen = set()
            pages = []
            has_more = False
            while len(selected) < limit:
                entries = self._list_page(session, path, page)
                for entry in entries:
                    if entry["fs_id"] in seen:
                        raise NetdiskError("pagination_inconsistent", "相邻网盘分页重复，未声明目录读取完整。")
                    seen.add(entry["fs_id"])
                pages.append(page)
                remaining = entries[offset:]
                take = min(limit - len(selected), len(remaining))
                selected.extend(remaining[:take])
                has_more = take < len(remaining) or len(entries) == _PAGE_SIZE
                if len(entries) < _PAGE_SIZE or len(selected) == limit:
                    break
                page += 1
                offset = 0
            self._assert_current(session)
            return {"ok": True, "backend": "pcs", "entries": selected, **session.public_identity(),
                    "path": path, "start": start, "limit": limit, "returned": len(selected),
                    "has_more": has_more, "next_start": start + len(selected) if has_more else None,
                    "complete": not has_more, "pagination": {"api_page_size": _PAGE_SIZE, "api_pages": pages,
                        "completion": "short_or_empty_page" if not has_more else "more_or_full_page",
                        "consistency": "live_directory_not_atomic_snapshot",
                        "cross_call_duplicates_must_be_checked": True}}

    def _stat(self, session: _Session, path: str) -> dict[str, Any]:
        boundary = "pcs-meta-" + uuid.uuid4().hex
        param = json.dumps({"list": [{"path": path}]}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="param"\r\n\r\n'.encode("ascii")
                + param + f"\r\n--{boundary}--\r\n".encode("ascii"))
        data = self._request_json(session, _PCS_URL, params={"method": "meta", "app_id": session.app_id},
                                  body=body, content_type="multipart/form-data; boundary=" + boundary)
        values = data.get("list")
        if not isinstance(values, list) or len(values) != 1:
            raise NetdiskError("invalid_response", "网盘元信息没有返回唯一条目。")
        entry = self._entry(values[0], session)
        if entry["path"] != path:
            raise NetdiskError("invalid_response", "网盘元信息返回了不同路径。")
        return entry

    def stat_entry(self, path: str) -> dict[str, Any]:
        path = _path(path)
        with self._lock:
            session = self._load_session()
            return {"ok": True, "backend": "pcs", "entry": self._stat(session, path), **session.public_identity()}

    def download_to(self, remote_path: str, destination: Path, expected_entry: dict[str, Any]) -> dict[str, Any]:
        path = _path(remote_path)
        destination = Path(destination).expanduser()
        if not destination.is_absolute() or ".." in destination.parts:
            raise NetdiskError("unsafe_local_path", "下载临时文件需要不含遍历的完整绝对路径。")
        if any(_is_link(ancestor) for ancestor in [destination, *destination.parents]):
            raise NetdiskError("unsafe_local_path", "下载临时路径不能含链接或重解析点。")
        if destination.exists():
            raise NetdiskError("local_file_exists", "下载只创建新的临时文件，不覆盖现有目标。")
        if not isinstance(expected_entry, dict) or expected_entry.get("path") != path or expected_entry.get("is_dir") is not False:
            raise NetdiskError("invalid_entry", "下载需要同一路径的已确认文件元信息。")
        expected_size = _int(expected_entry.get("size"), "size")
        with self._lock:
            session = self._load_session()
            expected_account = expected_entry.get("account_id")
            if expected_account is not None and expected_account != session.account_id:
                raise NetdiskError("account_changed", "下载元信息属于不同网盘账号。")
            before = self._stat(session, path)
            keys = ["fs_id", "size"] + (["mtime"] if expected_entry.get("mtime") is not None else [])
            if before["is_dir"] or any(before.get(key) != expected_entry.get(key) for key in keys):
                raise NetdiskError("remote_changed", "下载前网盘文件已变化，请刷新元信息。")
            query = urllib.parse.urlencode({"method": "download", "app_id": session.app_id, "path": path})
            request = urllib.request.Request(_PCS_URL + "?" + query,
                                            headers={"Cookie": session.cookie, "User-Agent": session.pcs_ua})
            written = 0
            created = False
            complete = False
            digest = hashlib.sha256()
            deadline = time.monotonic() + self.transfer_timeout
            try:
                try:
                    with self._download_opener.open(request, timeout=self.timeout) as response:
                        _trusted_download_url(response.geturl())
                        if response.status not in (200, 206):
                            raise NetdiskError("http_error", "百度下载接口未返回完整文件。", {"status": response.status})
                        with destination.open("xb") as file:
                            created = True
                            while chunk := response.read(1024 * 1024):
                                if time.monotonic() > deadline:
                                    raise NetdiskError("timeout", "下载超过允许的总时限。")
                                if written + len(chunk) > expected_size:
                                    raise NetdiskError("download_size_mismatch", "下载内容大于网盘元信息大小。")
                                file.write(chunk)
                                digest.update(chunk)
                                written += len(chunk)
                            file.flush()
                            os.fsync(file.fileno())
                except FileExistsError:
                    raise NetdiskError("local_file_exists", "下载目标已出现，未覆盖它。") from None
                except urllib.error.HTTPError as exc:
                    raise NetdiskError("authentication_required" if exc.code in (401, 403) else "http_error",
                                       "百度拒绝文件下载，请检查网盘会话和权限。", {"status": exc.code}) from None
                except (urllib.error.URLError, TimeoutError, OSError):
                    raise NetdiskError("download_failed", "文件下载遇到网络或本地写入错误。") from None
                if written != expected_size:
                    raise NetdiskError("download_size_mismatch", "下载内容大小与网盘元信息不符。")
                self._assert_current(session)
                after = self._stat(session, path)
                if any(before.get(key) != after.get(key) for key in ("fs_id", "size", "mtime", "md5", "is_dir")):
                    raise NetdiskError("remote_changed", "下载期间网盘文件已变化，临时文件未发布。")
                complete = True
                return {"ok": True, "backend": "pcs", "verified": True, "verification": "size_and_unchanged_remote_metadata",
                        "size": written, "sha256": digest.hexdigest(), "local_path": str(destination),
                        "entry": after, **session.public_identity()}
            finally:
                if created and not complete:
                    try:
                        destination.unlink()
                    except OSError:
                        pass
