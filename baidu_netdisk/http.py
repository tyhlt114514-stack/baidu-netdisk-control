from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .common import NetdiskError, redact


def trusted_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    if (parsed.scheme != "https" or parsed.username or parsed.password or
            parsed.port not in (None, 443) or
            not (host == "baidu.com" or host.endswith(".baidu.com") or
                 host == "baidupcs.com" or host.endswith(".baidupcs.com"))):
        raise NetdiskError("untrusted_url", "网盘请求必须使用百度所属 HTTPS 域名。")
    return url


class _BaiduRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        trusted_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpClient:
    def __init__(self, timeout: float = 60):
        self.timeout = timeout
        self.opener = urllib.request.build_opener(_BaiduRedirect())

    def _open(self, request):
        trusted_url(request.full_url)
        try:
            return self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            # Never leak URLs, auth headers or response pages to MCP output.
            raise NetdiskError("http_error", f"百度接口返回 HTTP {exc.code}。",
                               {"status": exc.code}) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise NetdiskError("network_error", "百度接口连接失败或超时，请检查网络后重试。") from None

    def request_json(self, url, params=None, data=None, headers=None,
                     method="GET", body=None) -> dict:
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        request_headers = {"User-Agent": "pan.baidu.com", **(headers or {})}
        if data is not None:
            if body is not None:
                raise ValueError("data and body are mutually exclusive")
            body = urllib.parse.urlencode(data).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        with self._open(urllib.request.Request(url, data=body, headers=request_headers, method=method)) as response:
            raw = response.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise NetdiskError("invalid_response", "百度接口响应超过 8 MiB。")
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError):
            raise NetdiskError("invalid_response", "百度接口未返回 JSON 数据。") from None
        if not isinstance(result, dict):
            raise NetdiskError("invalid_response", "百度接口返回了无效的数据结构。")
        return result

    def download(self, url, destination: Path, headers=None, expected_size=None):
        destination = Path(destination)
        written = 0
        try:
            with self._open(urllib.request.Request(url, headers={"User-Agent": "pan.baidu.com", **(headers or {})})) as response:
                with destination.open("wb") as f:
                    while chunk := response.read(1024 * 1024):
                        f.write(chunk)
                        written += len(chunk)
                    f.flush()
                    os.fsync(f.fileno())
            if expected_size is not None and written != int(expected_size):
                raise NetdiskError("download_size_mismatch", "下载文件大小与网盘记录不符。",
                                   {"expected": expected_size, "received": written})
            return {"bytes": written}
        except (OSError, TimeoutError) as exc:
            raise NetdiskError("download_failed", "下载时发生网络或本地文件错误。") from None
