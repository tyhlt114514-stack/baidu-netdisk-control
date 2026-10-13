from __future__ import annotations

import threading
from pathlib import Path

from .common import NetdiskError, checked_local, normalize_remote, redact, file_lock
from .config import Settings
from .jobs import JobManager


class NetdiskService:
    def __init__(self, config_path: Path | None = None):
        self.config_path = config_path
        self._backend = None
        self._settings = None
        self._jobs = None
        self._lock = threading.RLock()
        self._pcs_lock = threading.RLock()
        self._filesystem = None
        self._catalog = None

    @property
    def settings(self):
        if self._settings is None:
            self._settings = Settings.load(self.config_path)
        return self._settings

    @property
    def backend(self):
        with self._lock:
            if self._backend is None:
                s = self.settings
                if s.backend == "openapi":
                    from .api import ApiBackend
                    from .auth import TokenStore
                    self._backend = ApiBackend(s, TokenStore(s))
                else:
                    from .pcs import PcsBackend
                    self._backend = PcsBackend(s.pcs_executable, s.state_dir / "pcs", s.allowed_local_roots)
            return self._backend

    @property
    def jobs(self):
        with self._lock:
            if self._jobs is None:
                self._jobs = JobManager(self.settings.state_dir)
            return self._jobs

    def _call(self, method, *args, **kwargs):
        def execute():
            handler = getattr(self.backend, method, None)
            if handler is None:
                raise NetdiskError("unsupported_operation", f"当前 {self.settings.backend} 后端不提供 {method}。")
            try:
                return redact(handler(*args, **kwargs))
            except ValueError as exc:
                raise NetdiskError("invalid_argument", str(redact(str(exc)))) from None
        if self.settings.backend == "pcs":
            # Each CLI process shares the account database. Keep commands serialized.
            with self._pcs_lock:
                with file_lock(self.settings.state_dir / "pcs-process.lock"):
                    return execute()
        return execute()

    def status(self):
        try:
            result = self._call("status")
            return {"ok": result.get("ok", True), "configured": True, "backend": self.settings.backend,
                    "remote_root": self.settings.remote_root if self.settings.backend == "openapi" else "/",
                    "allowed_local_roots": [str(p) for p in self.settings.allowed_local_roots],
                    "connection": result}
        except NetdiskError as exc:
            return {**exc.as_dict(), "configured": exc.code != "not_configured"}

    def _read_path(self, path):
        path = normalize_remote(path)
        return self.settings.remote_root if self.settings.backend == "openapi" and path == "/" else path

    def list_files(self, path="/", limit=100, start=0):
        if not 1 <= limit <= 1000 or start < 0:
            raise NetdiskError("invalid_pagination", "limit 应为 1..1000，start 应大于等于 0。")
        return self.list_entries(path, start=start, limit=limit)

    def search(self, keyword, path="/", recursive=True, limit=100):
        if not keyword or not 1 <= limit <= 1000:
            raise NetdiskError("invalid_search", "关键词不能为空，limit 应为 1..1000。")
        path = self._read_path(path)
        result = self.catalog.search(keyword, path=path, recursive=recursive, offset=0, limit=limit)
        if not result["complete"]:
            result["next_action"] = "调用 netdisk_start_scan 并等待 complete=true 后重新搜索，不要求用户手动操作。"
        return result

    def quota(self):
        return self._call("quota")

    def _structured(self):
        from .adapter import StructuredAdapter
        return StructuredAdapter(self)

    @property
    def filesystem(self):
        from .filesystem import CloudFilesystem
        adapter = self._structured()
        identity = adapter.account_identity()["account_id"]
        with self._lock:
            if self._filesystem is None or self._filesystem.account_id != identity:
                cache = self.settings.cache_root or self.settings.state_dir.parent / "cache"
                self._filesystem = CloudFilesystem(adapter, cache, self.settings.allowed_local_roots,
                                                   self.settings.state_dir, identity, self.settings.backend)
            return self._filesystem

    @property
    def catalog(self):
        from .catalog import Catalog
        identity = self._structured().account_identity()["account_id"]
        with self._lock:
            if self._catalog is None or getattr(self._catalog, "account_id", None) != identity:
                self._catalog = Catalog(self.settings.state_dir, self.settings.backend, identity)
            return self._catalog

    def list_entries(self, path="/", start=0, limit=100):
        if isinstance(start, bool) or isinstance(limit, bool) or start < 0 or not 1 <= limit <= 1000:
            raise NetdiskError("invalid_pagination", "start 应为非负整数，limit 应为 1..1000。")
        path = self._read_path(path)
        return self.filesystem.list_entries(path, start=start, limit=limit)

    def stat(self, path):
        path = self._read_path(path)
        entry = self.filesystem.stat(path)
        if entry is None:
            raise NetdiskError("file_not_found", "网盘文件不存在。")
        return {"entry": entry}

    def start_scan(self, path="/", recursive=True, max_entries=None):
        path = self._read_path(path)
        catalog = self.catalog
        filesystem = self.filesystem
        return self.jobs.start("scan", {"path": path, "recursive": recursive, "max_entries": max_entries},
                               lambda: catalog.scan(filesystem, remote_root=path, recursive=recursive, max_entries=max_entries))

    def query_index(self, path="/", recursive=False, pattern=None, offset=0, limit=100):
        return self.catalog.query(self._read_path(path), recursive=recursive, pattern=pattern, offset=offset, limit=limit)

    def search_index(self, keyword, path="/", offset=0, limit=100):
        return self.catalog.search(keyword, path=self._read_path(path), recursive=True, offset=offset, limit=limit)

    def index_status(self):
        return {"stats": self.catalog.stats(), "latest_scan": self.catalog.receipt()}

    def prepare_file(self, remote_path, refresh=False):
        path = self._read_path(remote_path)
        filesystem = self.filesystem
        if not refresh:
            hit = filesystem.cached(path)
            if hit:
                return {"status": "ready", **hit}
        # Large downloads stay outside the MCP request's time limit.
        task = self.jobs.start("materialize", {"remote_path": path, "refresh": refresh},
                               lambda: filesystem.materialize(path, refresh=refresh))
        return {"status": "preparing", "job": task, "job_id": task["job_id"],
                "message": "查询任务完成后再次读取；无需用户手动下载。"}

    def read_file(self, remote_path, start_line=1, line_count=200, max_bytes=65536):
        if not 1 <= start_line or not 1 <= line_count <= 200 or not 1 <= max_bytes <= 65536:
            raise NetdiskError("invalid_read_range", "读取范围应为正行号、1..200行及1..65536字节。")
        prepared = self.prepare_file(remote_path)
        if prepared["status"] != "ready":
            return prepared
        from .reader import FileReader
        fs = self.filesystem
        return FileReader(fs.cache_root, fs.materialize).read(self._read_path(remote_path),
                     start_line=start_line, line_count=line_count, max_bytes=max_bytes)

    def read_bytes(self, remote_path, offset=0, limit=65536):
        if offset < 0 or not 1 <= limit <= 65536:
            raise NetdiskError("invalid_read_range", "offset 应为非负整数，limit 应为1..65536。")
        prepared = self.prepare_file(remote_path)
        if prepared["status"] != "ready":
            return prepared
        from .reader import FileReader
        fs = self.filesystem
        return FileReader(fs.cache_root, fs.materialize).read_bytes(self._read_path(remote_path), offset=offset, limit=limit)

    def start_put(self, local_path, remote_path, create_parents=True, overwrite=False):
        local = checked_local(local_path, self.settings.allowed_local_roots, must_exist=True)
        if local.is_relative_to(self.settings.state_dir.resolve()):
            raise NetdiskError("private_path_denied", "不能上传私有凭据或任务文件。")
        filesystem = self.filesystem
        remote = self._read_path(remote_path)
        return self.jobs.start("put", {"local_path": str(local), "remote_path": remote},
            lambda: filesystem.upload_file(local, remote, create_parents=create_parents, overwrite=overwrite))

    def start_get(self, remote_path, local_path, overwrite=False):
        local = checked_local(local_path, self.settings.allowed_local_roots)
        if local.is_relative_to(self.settings.state_dir.resolve()):
            raise NetdiskError("private_path_denied", "不能下载覆盖插件私有目录。")
        filesystem = self.filesystem
        remote = self._read_path(remote_path)
        return self.jobs.start("get", {"local_path": str(local), "remote_path": remote},
                               lambda: filesystem.download_file(remote, local, overwrite=overwrite))

    def start_tree_transfer(self, direction, local_dir, remote_dir, overwrite=False):
        from .tree_transfer import TreeTransfer
        local = checked_local(local_dir, self.settings.allowed_local_roots, must_exist=(direction == "upload"), directory=True)
        filesystem = self.filesystem
        transfer = TreeTransfer(filesystem, self.settings.allowed_local_roots, self.settings.state_dir)
        remote = self._read_path(remote_dir)
        if direction not in ("upload", "download"):
            raise NetdiskError("invalid_direction", "direction 应为 upload 或 download。")
        callback = (lambda: transfer.upload_tree(local, remote, overwrite=overwrite)) if direction == "upload" else (
            lambda: transfer.download_tree(remote, local, overwrite=overwrite))
        return self.jobs.start(direction + "_tree", {"local_dir": str(local), "remote_dir": remote}, callback)

    def transfer_receipt(self, manifest_id, offset=0, limit=100):
        from .tree_transfer import TreeTransfer
        transfer = TreeTransfer(self.filesystem, self.settings.allowed_local_roots, self.settings.state_dir)
        return transfer.get_manifest(manifest_id, offset=offset, limit=limit)

    def file_info(self, remote_path=None, fs_ids=None):
        if self.settings.backend == "pcs":
            if not remote_path:
                raise NetdiskError("path_required", "PCS 后端查询详情需要 remote_path。")
            return self._call("file_info", normalize_remote(remote_path))
        if not fs_ids:
            raise NetdiskError("fs_id_required", "官方接口需要 fs_ids，请先从文件列表获取。")
        return self._call("file_info", fs_ids)

    def mkdir(self, path):
        return self._call("mkdir", normalize_remote(path, allow_root=False))

    def rename(self, path, new_name):
        if not new_name or new_name in (".", "..") or any(c in new_name for c in ("/", "\\")):
            raise NetdiskError("invalid_name", "新名称应为单个文件名或目录名。")
        return self._call("rename", normalize_remote(path, allow_root=False), new_name)

    def move(self, paths, destination):
        return self._file_operation("move", paths, destination)

    def copy(self, paths, destination):
        return self._file_operation("copy", paths, destination)

    def _file_operation(self, method, paths, destination):
        if not paths or len(paths) > 100:
            raise NetdiskError("invalid_paths", "每次需要 1..100 个网盘源路径。")
        paths = [normalize_remote(p, allow_root=False) for p in paths]
        destination = normalize_remote(destination)
        if self.settings.backend == "pcs":
            return self._call(method, paths, destination)
        # Preserve one receipt per source; never imply an entire batch succeeded.
        receipts = []
        for path in paths:
            try:
                receipts.append({"path": path, "result": self._call(method, path, destination)})
            except NetdiskError as exc:
                receipts.append({"path": path, "result": exc.as_dict()})
        return {"ok": all(r["result"].get("ok", True) for r in receipts), "receipts": receipts}

    def delete(self, paths):
        if not paths or len(paths) > 100:
            raise NetdiskError("invalid_paths", "每次需要 1..100 个网盘路径。")
        return self._call("delete", [normalize_remote(p, allow_root=False) for p in paths])

    def start_upload(self, local_path, remote_path, overwrite=False):
        local = checked_local(local_path, self.settings.allowed_local_roots, must_exist=True)
        if local.is_relative_to(self.settings.state_dir.resolve()):
            raise NetdiskError("private_path_denied", "不能上传插件的私有凭据或任务目录。")
        remote = normalize_remote(remote_path, allow_root=False)
        # Validate before queuing so callers receive actionable errors immediately.
        if self.settings.backend == "pcs":
            if overwrite:
                raise NetdiskError("unsupported_overwrite", "PCS 上传使用跳过同名文件策略，不提供自动覆盖。")
            if remote.rsplit("/", 1)[-1] != local.name:
                raise NetdiskError("destination_name_mismatch", "PCS 上传目标文件名须与本地文件名一致；上传后可重命名。")
            callback = lambda: self._call("upload", str(local), remote.rsplit("/", 1)[0] or "/")
        else:
            callback = lambda: self._call("upload", str(local), remote, overwrite=overwrite)
        return self.jobs.start("upload", {"local_path": str(local), "remote_path": remote,
                                           "overwrite": overwrite}, callback)

    def start_download(self, local_path, remote_path=None, fs_id=None, overwrite=False):
        if self.settings.backend == "pcs":
            if not remote_path:
                raise NetdiskError("path_required", "PCS 下载需要 remote_path。")
            if overwrite:
                raise NetdiskError("unsupported_overwrite", "PCS 下载不提供自动覆盖。")
            local = checked_local(local_path, self.settings.allowed_local_roots, directory=True)
            remote_path = normalize_remote(remote_path, allow_root=False)
            callback = lambda: self._call("download", remote_path, str(local))
        else:
            if fs_id is None:
                raise NetdiskError("fs_id_required", "官方接口下载需要 fs_id。")
            local = checked_local(local_path, self.settings.allowed_local_roots)
            if local.exists() and not overwrite:
                raise NetdiskError("local_file_exists", "本地目标文件已存在，请换一个路径。")
            callback = lambda: self._call("download", fs_id, str(local), overwrite=overwrite)
        if local.is_relative_to(self.settings.state_dir.resolve()):
            raise NetdiskError("private_path_denied", "不能下载到插件的私有凭据或任务目录。")
        return self.jobs.start("download", {"local_path": str(local), "remote_path": remote_path,
                                             "fs_id": fs_id, "overwrite": overwrite}, callback)

    def share(self, paths, password, period=7):
        if self.settings.backend != "pcs":
            raise NetdiskError("unsupported_operation", "此版本分享工具仅在 PCS 后端开放。")
        return self._call("share", paths, password, period)

    def shares(self):
        return self._call("shares")

    def cancel_share(self, share_ids):
        return self._call("cancel_share", share_ids)
