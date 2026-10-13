"""A lazy local view of cloud files, with verified publication and account isolation."""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shutil
import tempfile
from pathlib import Path

from .common import NetdiskError, atomic_json, checked_local, file_lock, normalize_remote


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint(entry: dict) -> dict:
    return {key: entry.get(key) for key in ("path", "fs_id", "size", "mtime", "md5", "is_dir")}


class CloudFilesystem:
    def __init__(self, backend, cache_root: Path, allowed_local_roots: list[Path],
                 state_dir: Path, account_id: str, backend_name: str):
        self.backend = backend
        self.cache_root = checked_local(cache_root, allowed_local_roots, directory=True)
        self.allowed_local_roots = allowed_local_roots
        self.state_dir = state_dir.resolve()
        if self.cache_root.is_relative_to(self.state_dir):
            raise NetdiskError("invalid_cache_root", "文件缓存应放在私有凭据目录之外。")
        self.account_id = str(account_id)
        self.backend_name = backend_name
        self.remote_root = getattr(backend, "remote_root", "/")
        self.account_key = hashlib.sha256((backend_name + "\0" + self.account_id).encode()).hexdigest()

    def _identity(self):
        current = self.backend.account_identity()
        if str(current["account_id"]) != self.account_id:
            raise NetdiskError("account_changed", "当前网盘账号已变化，请重新开始文件操作。")

    def _local(self, path, must_exist=False, directory=False):
        result = checked_local(path, self.allowed_local_roots, must_exist=must_exist, directory=directory)
        if result.is_relative_to(self.state_dir):
            raise NetdiskError("private_path_denied", "文件操作不能读写插件私有凭据目录。")
        # Resolve rejects links escaping roots; reject all reparse points to keep
        # native path operations from changing meaning between validation and use.
        original = Path(path).absolute()
        for ancestor in (original, *original.parents):
            if ancestor.is_symlink() or (ancestor.exists() and getattr(ancestor.lstat(), "st_file_attributes", 0) & 0x400):
                raise NetdiskError("unsafe_local_path", "本地传输路径不能含符号链接或重解析点。")
        return result

    def stat(self, remote_path):
        self._identity()
        try:
            result = self.backend.stat_entry(normalize_remote(remote_path))
        except NetdiskError as exc:
            if exc.code in ("not_found", "file_not_found", "baidu_-9", "baidu_31066"):
                return None
            raise
        self._identity()
        return result["entry"] if "entry" in result else result

    def list_entries(self, path="/", start=0, limit=1000):
        self._identity()
        result = self.backend.list_entries(normalize_remote(path), start=start, limit=limit)
        self._identity()
        if result.get("account_id") is not None and str(result["account_id"]) != self.account_id:
            raise NetdiskError("account_changed", "文件列表来自不同账号，已停止操作。")
        return result

    def _paths(self, entry):
        key = hashlib.sha256(entry["path"].encode("utf-8")).hexdigest()
        suffix = Path(entry["name"]).suffix.lower()
        if len(suffix) > 16 or not all(c.isascii() and (c.isalnum() or c == ".") for c in suffix):
            suffix = ".bin"
        directory = self.cache_root / self.account_key / key
        return directory / ("content" + suffix), directory / "receipt.json", self.cache_root / "locks" / (self.account_key + key + ".lock")

    def cached(self, remote_path):
        entry = self.stat(remote_path)
        if entry is None:
            raise NetdiskError("file_not_found", "网盘文件不存在。")
        if entry["is_dir"]:
            raise NetdiskError("is_directory", "此路径是目录，请先列出目录再读取文件。")
        path, receipt_path, _ = self._paths(entry)
        path = self._local(path)
        if not path.is_file() or not receipt_path.is_file():
            return None
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            if (not isinstance(receipt, dict) or receipt.get("account_id") != self.account_id or
                    receipt.get("fingerprint") != fingerprint(entry) or
                    path.stat().st_size != entry["size"] or sha256_file(path) != receipt.get("sha256")):
                return None
        except (ValueError, OSError):
            return None
        self._identity()
        return {"ok": True, "local_path": str(path), "entry": entry, "cache_hit": True,
                "sha256": receipt["sha256"], "verified": True}

    def materialize(self, remote_path, refresh=False):
        entry = self.stat(remote_path)
        if entry is None:
            raise NetdiskError("file_not_found", "网盘文件不存在。")
        if entry["is_dir"]:
            raise NetdiskError("is_directory", "目录不能当作单文件读取。")
        target, receipt_path, lock_path = self._paths(entry)
        target = self._local(target)
        with file_lock(lock_path, timeout=3600):
            if not refresh:
                hit = self.cached(remote_path)
                if hit:
                    return hit
            target.parent.mkdir(parents=True, exist_ok=True)
            # download_to requires a nonexistent target. The private staging
            # directory has an unguessable name; the file is published atomically.
            with tempfile.TemporaryDirectory(prefix=".fetch-", dir=target.parent) as temporary:
                stage = Path(temporary) / "payload"
                transfer = self.backend.download_to(remote_path, stage, expected_entry=entry)
                if transfer.get("ok") is False or not transfer.get("verified"):
                    raise NetdiskError("download_unverified", "下载未得到成功核验回执。", {"result": transfer})
                if not stage.is_file() or stage.stat().st_size != entry["size"]:
                    raise NetdiskError("download_size_mismatch", "本地下载文件与网盘记录不符。")
                after = self.stat(remote_path)
                if after is None or fingerprint(entry) != fingerprint(after):
                    raise NetdiskError("remote_changed", "下载期间网盘文件发生变化，请重新读取。")
                self._identity()
                digest = sha256_file(stage)
                os.replace(stage, target)
                atomic_json(receipt_path, {"version": 1, "account_id": self.account_id,
                                          "fingerprint": fingerprint(after), "sha256": digest})
            return {"ok": True, "local_path": str(target), "entry": after, "cache_hit": False,
                    "sha256": digest, "verified": True}

    def download_file(self, remote_path, local_path, overwrite=False):
        local = self._local(local_path)
        if local.exists() and not overwrite:
            raise NetdiskError("local_file_exists", "本地目标已存在，默认不会覆盖。")
        materialized = self.materialize(remote_path)
        local.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".netdisk-", suffix=".part", dir=local.parent)
        os.close(fd)
        stage = Path(name)
        try:
            shutil.copyfile(materialized["local_path"], stage)
            if sha256_file(stage) != materialized["sha256"]:
                raise NetdiskError("cache_changed", "本地缓存复制时发生变化，未发布下载目标。")
            self._identity()
            if overwrite:
                os.replace(stage, local)
            else:
                try:
                    os.link(stage, local)
                except FileExistsError:
                    raise NetdiskError("local_file_exists", "下载期间本地目标被创建，已保留原文件。") from None
            return {"ok": True, "verified": True, "local_path": str(local), "remote_path": remote_path,
                    "size": local.stat().st_size, "sha256": materialized["sha256"], "entry": materialized["entry"]}
        finally:
            stage.unlink(missing_ok=True)

    def mkdir(self, remote_path):
        remote_path = normalize_remote(remote_path)
        remote_root = normalize_remote(self.remote_root)
        if remote_path == "/" and remote_root != "/":
            remote_path = remote_root
        if remote_root != "/" and not (remote_path == remote_root or remote_path.startswith(remote_root + "/")):
            raise NetdiskError("remote_path_denied", "目录创建超出此后端的授权目录。")
        if remote_path == remote_root:
            self._identity()
            if remote_root != "/":
                existing = self.stat(remote_root)
                if existing is None:
                    raise NetdiskError("app_root_missing", "应用授权根目录尚不存在，不能在其外部递归创建目录。")
                if not existing["is_dir"]:
                    raise NetdiskError("not_directory", "应用授权根路径被普通文件占用。")
            return {"ok": True, "exists": True, "path": remote_path}
        existing = self.stat(remote_path)
        if existing:
            if not existing["is_dir"]:
                raise NetdiskError("not_directory", "网盘父目录路径被普通文件占用。")
            return {"ok": True, "exists": True, "path": remote_path}
        self.mkdir(posixpath.dirname(remote_path) or "/")
        result = self.backend.mkdir(remote_path)
        self._identity()
        created = self.stat(remote_path)
        if not created or not created["is_dir"]:
            raise NetdiskError("mkdir_unverified", "网盘目录创建后未通过核验。", {"result": result})
        return {"ok": True, "verified": True, "path": remote_path}

    def upload_file(self, local_path, remote_path, create_parents=True, overwrite=False):
        local = self._local(local_path, must_exist=True)
        remote = normalize_remote(remote_path, allow_root=False)
        basename = posixpath.basename(remote)
        if self.backend_name == "pcs":
            # The renamed CLI source must be representable on Windows. Validate
            # before mkdir can create any parent directories in the cloud.
            from .pcs import _safe_basename
            try:
                _safe_basename(basename)
            except ValueError:
                raise NetdiskError("invalid_remote_name", "PCS 上传目标文件名无法安全表示为本地 Windows 文件。") from None
        self._identity()
        existing = self.stat(remote)
        if existing and not overwrite:
            raise NetdiskError("file_exists", "网盘目标已存在，默认不覆盖。")
        if existing and existing["is_dir"]:
            raise NetdiskError("is_directory", "上传目标应为完整的文件路径。")
        if overwrite and self.backend_name == "pcs":
            # A remove+upload replacement is not atomic. Refuse until a native
            # provider with server-side conflict semantics is available.
            raise NetdiskError("unsupported_overwrite", "PCS 不执行删除后替换；请指定新文件路径。")
        source_before = (local.stat().st_size, local.stat().st_mtime_ns)
        digest = sha256_file(local)
        if create_parents:
            self.mkdir(posixpath.dirname(remote))
        if self.backend_name == "pcs":
            # Support arbitrary requested names without leaving an intermediate
            # cloud file. The CLI sees a staged local source named as requested.
            stage_parent = self.cache_root / "upload-staging"
            stage_parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="send-", dir=stage_parent) as stage_dir:
                staged = Path(stage_dir) / basename
                shutil.copyfile(local, staged)
                if sha256_file(staged) != digest:
                    raise NetdiskError("source_changed", "准备上传时源文件改变。")
                result = self.backend.upload(str(staged), posixpath.dirname(remote) or "/")
        else:
            result = self.backend.upload(str(local), remote, overwrite=overwrite)
        if result.get("ok") is False:
            raise NetdiskError("upload_failed", "网盘上传失败。", {"result": result})
        if source_before != (local.stat().st_size, local.stat().st_mtime_ns) or sha256_file(local) != digest:
            raise NetdiskError("source_changed", "上传期间源文件改变，请核对网盘目标。")
        self._identity()
        entry = self.stat(remote)
        if not entry or entry["is_dir"] or entry["size"] != source_before[0]:
            raise NetdiskError("upload_unverified", "上传后网盘路径或大小不符。")
        return {"ok": True, "verified": True, "entry": entry, "remote_path": remote,
                "local_path": str(local), "size": source_before[0], "local_sha256": digest,
                "verification": "stable_local_source_and_remote_metadata"}
