"""One structured filesystem contract over the authorized providers."""
from __future__ import annotations

import posixpath

from .common import NetdiskError, normalize_remote


def api_entry(raw):
    path = normalize_remote(raw["path"])
    return {"path": path, "name": raw.get("server_filename") or posixpath.basename(path),
            "is_dir": bool(raw.get("isdir")), "size": int(raw.get("size", 0)),
            "fs_id": str(raw["fs_id"]), "mtime": raw.get("server_mtime", raw.get("mtime")),
            "ctime": raw.get("server_ctime", raw.get("ctime")), "md5": raw.get("md5")}


class StructuredAdapter:
    def __init__(self, service):
        self.service = service
        self.remote_root = service.settings.remote_root if service.settings.backend == "openapi" else "/"

    def _call(self, method, *args, **kwargs):
        result = self.service._call(method, *args, **kwargs)
        if isinstance(result, dict) and result.get("ok") is False:
            error = result.get("error", {})
            code = error.get("code", "remote_error") if isinstance(error, dict) else str(error)
            raise NetdiskError(code, "网盘接口未确认操作成功。", {"result": result})
        return result

    def account_identity(self):
        if self.service.settings.backend == "pcs":
            return self._call("account_identity")
        info = self._call("user_info")
        uid = info.get("uk") or info.get("uid") or info.get("userid")
        if uid is None:
            raise NetdiskError("account_identity_missing", "百度未返回可靠账号 ID，不能建立跨文件缓存。")
        return {"account_id": "openapi:" + str(uid), "account": {"uid": str(uid), "name": info.get("netdisk_name", "")}}

    def stat_entry(self, path):
        if self.service.settings.backend == "pcs":
            return self._call("stat_entry", path)
        raw = self._call("_path_info", path)
        if raw is None:
            raise NetdiskError("file_not_found", "授权目录中没有此文件。")
        return {"entry": api_entry(raw)}

    def list_entries(self, path="/", start=0, limit=1000):
        if self.service.settings.backend == "pcs":
            return self._call("list_entries", path, start=start, limit=limit)
        result = self._call("list_files", path, start=start, limit=limit)
        return {"entries": [api_entry(raw) for raw in result["list"]], "start": start,
                "next_start": result["next_start"] if result["has_more"] else None,
                "has_more": result["has_more"], "path": result["path"],
                "pagination": {"consistency": "live_directory_not_atomic_snapshot"}}

    def download_to(self, remote_path, destination, expected_entry):
        if self.service.settings.backend == "pcs":
            return self._call("download_to", remote_path, destination, expected_entry)
        return self._call("download", int(expected_entry["fs_id"]), str(destination), overwrite=False)

    def upload(self, *args, **kwargs):
        return self._call("upload", *args, **kwargs)

    def mkdir(self, path):
        return self._call("mkdir", path)
