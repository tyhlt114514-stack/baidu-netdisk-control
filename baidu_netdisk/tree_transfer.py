"""Preflighted directory transfers with persistent, account-bound receipts.

Cloud transfers remain explicit per-file filesystem calls. A directory is never
silently omitted, and Windows-incompatible remote names have a reversible map
in the manifest. Only a verified receipt plus unchanged source and destination
fingerprints allows a resume skip.
"""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import stat
import time
from pathlib import Path

from .catalog import Catalog
from .common import NetdiskError, atomic_json, checked_local, file_lock, normalize_remote, redact


class TreeTransfer:
    PAGE_SIZE = 1000
    _NOT_FOUND = {"not_found", "file_not_found", "remote_missing", "baidu_-9", "baidu_31066"}

    def __init__(self, filesystem, allowed_local_roots, state_dir):
        self.fs = filesystem
        self.allowed_local_roots = [Path(root).resolve() for root in allowed_local_roots]
        self.state_dir = Path(state_dir).resolve()
        self.account_id = getattr(filesystem, "account_id", None)
        self.backend_name = getattr(filesystem, "backend_name", None)
        if self.account_id is None or not self.backend_name:
            identity = getattr(filesystem, "identity", None)
            if callable(identity):
                identity = identity()
                self.account_id = identity.get("account_id")
                self.backend_name = identity.get("backend") or identity.get("backend_name")
        if self.account_id is None or not str(self.account_id) or not self.backend_name:
            raise NetdiskError("transfer_account_required", "目录传输必须绑定已登录账号与后端。")
        self.account_id, self.backend_name = str(self.account_id), str(self.backend_name)
        self.remote_root = normalize_remote(getattr(filesystem, "remote_root", "/"))

    @staticmethod
    def _reject_links(path: Path):
        for candidate in (path, *path.parents):
            try:
                info = candidate.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise NetdiskError("unsafe_local_path", "目录传输不能经过符号链接、junction 或重解析点。")

    def _local(self, path, directory=False, must_exist=False, upload_root=False):
        original = Path(path).expanduser()
        if not original.is_absolute():
            raise NetdiskError("invalid_local_path", "目录传输需要本地绝对路径。")
        self._reject_links(original)
        local = checked_local(original, self.allowed_local_roots, must_exist=must_exist, directory=directory)
        if local.is_relative_to(self.state_dir) or (upload_root and self.state_dir.is_relative_to(local)):
            raise NetdiskError("private_path_denied", "目录传输不能读写插件私有状态；上传源不能包含该目录。")
        return local

    def _remote(self, path):
        remote = normalize_remote(path)
        if remote == "/" and self.remote_root != "/":
            remote = self.remote_root
        if self.remote_root != "/" and not (remote == self.remote_root or remote.startswith(self.remote_root + "/")):
            raise NetdiskError("remote_path_denied", "目录传输超出此后端的授权目录。")
        return remote

    def _stat(self, remote):
        try:
            result = self.fs.stat(remote)
        except NetdiskError as exc:
            if exc.code in self._NOT_FOUND:
                return None
            raise
        if result is None:
            return None
        if not isinstance(result, dict) or "is_dir" not in result:
            raise NetdiskError("invalid_remote_stat", "网盘未返回可核验的文件类型。")
        if result.get("path") != remote:
            raise NetdiskError("invalid_remote_stat", "网盘文件信息与请求路径不同。")
        return result

    @staticmethod
    def _remote_snapshot(entry):
        return {key: str(entry[key]) if key == "fs_id" and entry.get(key) is not None else entry.get(key)
                for key in ("path", "is_dir", "size", "fs_id", "mtime", "ctime", "md5")}

    def _local_snapshot(self, local):
        local = self._local(local, must_exist=True)
        before = local.stat()
        if not stat.S_ISREG(before.st_mode):
            raise NetdiskError("unsafe_local_path", "目录传输仅支持普通文件和目录。")
        digest = hashlib.sha256()
        with local.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        self._reject_links(local)
        after = local.stat()
        values = (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_dev, before.st_ino)
        if values != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_dev, after.st_ino):
            raise NetdiskError("source_changed", "计算文件校验值时本地源发生变化。")
        return {"size": before.st_size, "mtime_ns": before.st_mtime_ns, "ctime_ns": before.st_ctime_ns,
                "device": before.st_dev, "inode": before.st_ino, "sha256": digest.hexdigest()}

    def _directory_snapshot(self, local):
        local = self._local(local, directory=True, must_exist=True)
        info = local.stat()
        return {"mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
                "device": info.st_dev, "inode": info.st_ino}

    @staticmethod
    def _safe_windows_name(name):
        if (not name or name in (".", "..") or name[-1] in (" ", ".") or
                any(ord(character) < 32 or character in '<>:"/\\|?*' for character in name)):
            return False
        base = name.split(".", 1)[0].upper()
        if (base in ("CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$") or
                re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", base)):
            return False
        return len(name.encode("utf-16-le")) // 2 <= 200

    @staticmethod
    def _encoded_name(name):
        suffix = posixpath.splitext(name)[1]
        if len(suffix) > 16 or not re.fullmatch(r"\.[A-Za-z0-9]+", suffix or ""):
            suffix = ""
        return "__bd_" + hashlib.sha256(name.encode("utf-8")).hexdigest() + suffix

    @classmethod
    def _name_map(cls, entries):
        mapped = {item["path"]: item["name"] if cls._safe_windows_name(item["name"]) else cls._encoded_name(item["name"])
                  for item in entries}
        groups = {}
        for item in entries:
            groups.setdefault(mapped[item["path"]].casefold(), []).append(item)
        for group in groups.values():
            if len(group) > 1:
                for item in group:
                    mapped[item["path"]] = cls._encoded_name(item["name"])
        if len({name.casefold() for name in mapped.values()}) != len(mapped):
            raise NetdiskError("local_mapping_collision", "远端文件名编码后仍存在大小写冲突，未写入本地文件。")
        return mapped

    def _existing_target(self, parent, name, is_dir):
        """Reuse the actual spelling of an existing Windows case-insensitive name."""
        candidate = parent / name
        self._reject_links(parent)
        if parent.exists():
            if not parent.is_dir():
                raise NetdiskError("local_path_conflict", "目录传输的父路径被普通文件占用。")
            matches = [child for child in parent.iterdir() if child.name.casefold() == name.casefold()]
            if len(matches) > 1:
                raise NetdiskError("local_case_collision", "本地目录存在多个大小写等价的名字，无法安全映射。")
            if matches:
                candidate = matches[0]
        candidate = self._local(candidate, directory=is_dir)
        if candidate.exists() and is_dir and not candidate.is_dir():
            raise NetdiskError("local_path_conflict", "待创建的目录路径被普通文件占用。")
        if candidate.exists() and not is_dir and not candidate.is_file():
            raise NetdiskError("local_path_conflict", "待下载的文件路径被目录占用。")
        return candidate

    def _upload_plan(self, local_root, remote_root):
        plan = [{"kind": "directory", "local_path": str(local_root), "remote_path": remote_root,
                 "source_snapshot": self._directory_snapshot(local_root)}]
        queue = [(local_root, remote_root)]
        while queue:
            local_dir, remote_dir = queue.pop(0)
            self._local(local_dir, directory=True, must_exist=True)
            with os.scandir(local_dir) as iterator:
                children = sorted(iterator, key=lambda item: item.name)
            for child in children:
                local = Path(child.path)
                self._reject_links(local)
                info = child.stat(follow_symlinks=False)
                remote = self._remote(posixpath.join(remote_dir, child.name))
                if any(character in '\\:*?"<>|' or ord(character) < 32 for character in child.name):
                    raise NetdiskError("invalid_remote_name", "本地树包含百度网盘无法接受的文件名。")
                if stat.S_ISDIR(info.st_mode):
                    self._local(local, directory=True, must_exist=True)
                    plan.append({"kind": "directory", "local_path": str(local), "remote_path": remote,
                                 "source_snapshot": self._directory_snapshot(local)})
                    queue.append((local, remote))
                elif stat.S_ISREG(info.st_mode):
                    plan.append({"kind": "file", "local_path": str(local), "remote_path": remote,
                                 "source_snapshot": self._local_snapshot(local)})
                else:
                    raise NetdiskError("unsafe_local_path", "本地树包含设备、管道或其他特殊文件。")
        for item in plan:
            if item["kind"] == "directory" and self._directory_snapshot(item["local_path"]) != item["source_snapshot"]:
                raise NetdiskError("source_changed", "本地目录在树枚举期间发生变化。")
        return plan

    def _download_plan(self, remote_root, local_root):
        root_entry = self._stat(remote_root)
        if not root_entry or not root_entry["is_dir"]:
            raise NetdiskError("not_directory", "目录下载源不存在，或源路径不是目录。")
        plan = [{"kind": "directory", "remote_path": remote_root, "local_path": str(local_root),
                 "source_snapshot": self._remote_snapshot(root_entry), "mapping_encoded": False}]
        queue, known = [(remote_root, local_root)], {remote_root}
        while queue:
            remote_dir, local_dir = queue.pop(0)
            entries, start, page_digests = [], 0, set()
            while True:
                response = self.fs.list_entries(remote_dir, start=start, limit=self.PAGE_SIZE)
                prepared, next_start, has_more, digest = Catalog._validate_page(response, remote_dir, start, self.PAGE_SIZE)
                if prepared and digest in page_digests:
                    raise NetdiskError("transfer_duplicate_page", "目录下载枚举遇到重复页，未写入本地文件。")
                page_digests.add(digest)
                for item in prepared:
                    if item["path"] in known:
                        raise NetdiskError("transfer_duplicate_entry", "目录下载枚举重复返回文件或目录。")
                    known.add(item["path"])
                entries.extend(prepared)
                if not has_more:
                    break
                start = next_start
            mapping = self._name_map(entries)
            for item in entries:
                local = self._existing_target(local_dir, mapping[item["path"]], item["is_dir"])
                descriptor = {"kind": "directory" if item["is_dir"] else "file", "remote_path": item["path"],
                              "local_path": str(local), "source_snapshot": self._remote_snapshot(item),
                              "mapping_encoded": local.name != item["name"], "remote_name": item["name"]}
                plan.append(descriptor)
                if item["is_dir"]:
                    queue.append((item["path"], local))
        return plan

    def _identity(self, operation, source, target):
        return {"backend": self.backend_name, "account_id": self.account_id,
                "operation": operation, "source": str(source), "target": str(target)}

    def _manifest_path(self, identity):
        identifier = hashlib.sha256(json.dumps(identity, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
        return self.state_dir / "tree-transfers" / (identifier + ".json")

    @staticmethod
    def _previous(path, identity):
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("identity") != identity or data.get("version") != 1 or not isinstance(data.get("entries"), list):
                return {}
            previous = {}
            for item in data["entries"]:
                if not isinstance(item, dict) or "remote_path" not in item:
                    continue
                if item.get("status") == "succeeded" and isinstance(item.get("receipt"), dict) and item["receipt"].get("verified") is True:
                    previous[item["remote_path"]] = item
                elif isinstance(item.get("previous_verified"), dict):
                    previous[item["remote_path"]] = item["previous_verified"]
            return previous
        except (ValueError, OSError, AttributeError):
            return {}

    @staticmethod
    def _verified(previous, item):
        return (previous and previous.get("kind") == "file" and previous.get("status") == "succeeded" and
                previous.get("receipt", {}).get("verified") is True and
                previous.get("source_snapshot") == item["source_snapshot"] and
                previous.get("local_path") == item["local_path"])

    def _preflight_upload(self, plan, previous, overwrite):
        ancestor = (self.remote_root if plan[0]["remote_path"] == self.remote_root else
                    posixpath.dirname(plan[0]["remote_path"]))
        while ancestor and ancestor != self.remote_root:
            ancestor = self._remote(ancestor)
            existing = self._stat(ancestor)
            if existing and not existing["is_dir"]:
                raise NetdiskError("remote_path_conflict", "远端目标的祖先目录被普通文件占用。")
            ancestor = posixpath.dirname(ancestor)
        if ancestor == self.remote_root:
            root = self._stat(ancestor)
            if root and not root["is_dir"]:
                raise NetdiskError("remote_path_conflict", "网盘授权根目录被普通文件占用。")
        for item in plan:
            existing = self._stat(item["remote_path"])
            item["existing_snapshot"] = self._remote_snapshot(existing) if existing else None
            if item["kind"] == "directory":
                if existing and not existing["is_dir"]:
                    raise NetdiskError("remote_path_conflict", "远端目录路径已被普通文件占用。")
                continue
            if existing and existing["is_dir"]:
                raise NetdiskError("remote_path_conflict", "远端文件路径已被目录占用。")
            old = previous.get(item["remote_path"])
            if (self._verified(old, item) and existing and
                    old.get("destination_snapshot") == self._remote_snapshot(existing)):
                item.update(status="succeeded", receipt=old["receipt"], destination_snapshot=old["destination_snapshot"], resumed=True)
            elif existing and not overwrite:
                raise NetdiskError("file_exists", "目录上传存在同名文件冲突；所有文件均未开始上传。",
                                   {"remote_path": item["remote_path"]})
        # Recheck the entire local tree before the first mkdir/upload mutation.
        for item in plan:
            if item["kind"] == "directory":
                if self._directory_snapshot(item["local_path"]) != item["source_snapshot"]:
                    raise NetdiskError("source_changed", "目录预检期间本地目录结构变化；尚未开始云端写入。")
            elif self._local_snapshot(Path(item["local_path"])) != item["source_snapshot"]:
                raise NetdiskError("source_changed", "目录预检期间源文件变化；所有文件均未开始上传。")

    def _preflight_download(self, plan, previous, overwrite):
        for item in plan:
            local = self._local(item["local_path"], directory=item["kind"] == "directory")
            if item["kind"] != "file":
                continue
            old = previous.get(item["remote_path"])
            if (self._verified(old, item) and item["source_snapshot"].get("md5") and local.is_file() and
                    self._local_snapshot(local) == old.get("destination_snapshot")):
                item.update(status="succeeded", receipt=old["receipt"], destination_snapshot=old["destination_snapshot"], resumed=True)
            elif local.exists() and not overwrite:
                raise NetdiskError("local_file_exists", "目录下载存在本地同名文件冲突；所有文件均未开始下载。",
                                   {"local_path": str(local)})

    @staticmethod
    def _error(error):
        if isinstance(error, NetdiskError):
            return {"code": error.code, "message": str(redact(error.message)), "details": redact(error.details)}
        return {"code": "tree_transfer_error", "message": "目录传输异常（" + type(error).__name__ + "）。"}

    def _save(self, path, manifest):
        manifest["updated_at"] = time.time()
        atomic_json(path, manifest)

    def _summary(self, path, manifest):
        entries = manifest["entries"]
        files = [item for item in entries if item["kind"] == "file"]
        directories = [item for item in entries if item["kind"] == "directory"]
        successful = sum(item.get("status") == "succeeded" for item in files)
        failed = sum(item.get("status") == "failed" for item in files)
        directory_failed = sum(item.get("status") == "failed" for item in directories)
        result = {"ok": manifest["status"] == "succeeded", "operation": manifest["identity"]["operation"],
                  "status": manifest["status"], "manifest_id": path.stem,
                  "manifest_path": str(path), "updated_at": manifest["updated_at"],
                  "files_total": len(files), "files_succeeded": successful, "files_failed": failed,
                  "files_pending": len(files) - successful - failed,
                  "files_resumed": sum(bool(item.get("resumed")) for item in files),
                  "directories_total": len(directories),
                  "directories_succeeded": sum(item.get("status") == "succeeded" for item in directories),
                  "directories_failed": directory_failed,
                  "encoded_names": sum(bool(item.get("mapping_encoded")) for item in entries),
                  "files": [{key: value for key, value in item.items() if key in
                             ("remote_path", "local_path", "status", "receipt", "error", "resumed", "mapping_encoded")}
                            for item in files[:100]],
                  "receipts_truncated": len(files) > 100,
                  "receipt_note": "全部条目的原始网盘路径、本地映射、快照及回执保存在 manifest。"}
        if manifest.get("error"):
            result["error"] = manifest["error"]
        return result

    def get_manifest(self, manifest_id: str, offset=0, limit=100):
        """Return only this account's validated receipt, with stable entry paging."""
        if not isinstance(manifest_id, str) or not re.fullmatch(r"[a-f0-9]{64}", manifest_id):
            raise NetdiskError("invalid_manifest_id", "目录传输回执 ID 必须为 64 位小写十六进制。")
        Catalog._pagination(offset, limit)
        path = self.state_dir / "tree-transfers" / (manifest_id + ".json")
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise NetdiskError("manifest_not_found", "当前账号没有对应的目录传输回执。") from None
        except (ValueError, OSError):
            raise NetdiskError("manifest_invalid", "目录传输回执损坏，无法读取。") from None
        identity = manifest.get("identity") if isinstance(manifest, dict) else None
        if (not isinstance(identity, dict) or identity.get("account_id") != self.account_id or
                identity.get("backend") != self.backend_name):
            raise NetdiskError("manifest_not_found", "当前账号没有对应的目录传输回执。")
        if (manifest.get("version") != 1 or identity.get("operation") not in ("upload", "download") or
                not isinstance(identity.get("source"), str) or not isinstance(identity.get("target"), str) or
                self._manifest_path(identity).stem != manifest_id or
                manifest.get("status") not in ("preflight", "preflight_failed", "running", "failed", "succeeded") or
                not isinstance(manifest.get("updated_at"), (int, float)) or
                not isinstance(manifest.get("entries"), list) or
                any(not isinstance(item, dict) or item.get("kind") not in ("file", "directory")
                    for item in manifest["entries"])):
            raise NetdiskError("manifest_invalid", "目录传输回执的数据结构或身份摘要不一致。")
        result = self._summary(path, manifest)
        result.pop("files")
        entries = manifest["entries"]
        page = entries[offset:offset + limit]
        result.update(entries=page, count=len(entries), offset=offset, limit=limit,
                      next_offset=offset + len(page), has_more=offset + len(page) < len(entries),
                      identity=identity)
        return result

    def _run(self, operation, source, target, overwrite):
        identity = self._identity(operation, source, target)
        path = self._manifest_path(identity)
        with file_lock(path.with_suffix(".lock"), timeout=0):
            previous = self._previous(path, identity)
            manifest = {"version": 1, "identity": identity, "status": "preflight", "created_at": time.time(),
                        "updated_at": time.time(), "entries": []}
            try:
                if operation == "upload":
                    plan = self._upload_plan(source, target)
                else:
                    plan = self._download_plan(source, target)
                manifest["entries"] = plan
                for item in plan:
                    item["status"] = "pending"
                    old = previous.get(item["remote_path"])
                    if old and old.get("kind") == "file":
                        # A later preflight conflict must not destroy verified
                        # progress for files that were not yet inspected again.
                        item["previous_verified"] = {key: value for key, value in old.items() if key in
                            ("kind", "remote_path", "local_path", "source_snapshot", "destination_snapshot", "status", "receipt")}
                if operation == "upload":
                    self._preflight_upload(plan, previous, overwrite)
                else:
                    self._preflight_download(plan, previous, overwrite)
            except Exception as error:
                manifest.update(status="preflight_failed", error=self._error(error))
                self._save(path, manifest)
                return self._summary(path, manifest)
            manifest["status"] = "running"
            self._save(path, manifest)
            failed_directories = []
            for item in plan:
                if item["kind"] != "directory":
                    continue
                if any(item["remote_path"] == parent or item["remote_path"].startswith(parent.rstrip("/") + "/")
                       for parent in failed_directories):
                    item.update(status="failed", error={"code": "parent_directory_failed", "message": "父目录准备失败。"})
                    self._save(path, manifest)
                    continue
                try:
                    if operation == "upload":
                        self._local(item["local_path"], directory=True, must_exist=True)
                        result = self.fs.mkdir(item["remote_path"])
                        if isinstance(result, dict) and result.get("ok") is False:
                            raise NetdiskError("mkdir_failed", "网盘目录创建返回失败回执。")
                        created = self._stat(item["remote_path"])
                        if not created or not created["is_dir"]:
                            raise NetdiskError("mkdir_unverified", "网盘目录未通过创建后回查。")
                    else:
                        local = self._local(item["local_path"], directory=True)
                        local.mkdir(parents=True, exist_ok=True)
                        self._local(local, directory=True, must_exist=True)
                    item.update(status="succeeded", receipt={"ok": True, "verified": True, "is_dir": True})
                except Exception as error:
                    item.update(status="failed", error=self._error(error))
                    failed_directories.append(item["remote_path"])
                self._save(path, manifest)
            for item in plan:
                if item["kind"] != "file":
                    continue
                if any(item["remote_path"].startswith(parent.rstrip("/") + "/") for parent in failed_directories):
                    item.update(status="failed", error={"code": "parent_directory_failed", "message": "父目录准备失败，文件未传输。"})
                    self._save(path, manifest)
                    continue
                if item.get("resumed"):
                    continue
                try:
                    local = Path(item["local_path"])
                    if operation == "upload":
                        if self._local_snapshot(local) != item["source_snapshot"]:
                            raise NetdiskError("source_changed", "源文件在目录预检后发生变化，未传输该文件。")
                        receipt = self.fs.upload_file(local, item["remote_path"], create_parents=True, overwrite=overwrite)
                        if not isinstance(receipt, dict) or receipt.get("ok") is False or receipt.get("verified") is not True:
                            raise NetdiskError("upload_unverified", "上传未返回成功且 verified 的文件回执。")
                        if self._local_snapshot(local) != item["source_snapshot"]:
                            raise NetdiskError("source_changed", "上传期间源文件发生变化，请核对网盘结果。")
                        destination = self._stat(item["remote_path"])
                        if not destination or destination["is_dir"] or destination.get("size") != item["source_snapshot"]["size"]:
                            raise NetdiskError("upload_unverified", "上传目标未通过路径、类型与大小核验。")
                        snapshot = self._remote_snapshot(destination)
                    else:
                        current = self._stat(item["remote_path"])
                        if not current or self._remote_snapshot(current) != item["source_snapshot"]:
                            raise NetdiskError("remote_changed", "远端源文件在枚举后发生变化，未下载该文件。")
                        self._local(local)
                        receipt = self.fs.download_file(item["remote_path"], local, overwrite=overwrite)
                        if not isinstance(receipt, dict) or receipt.get("ok") is False or receipt.get("verified") is not True:
                            raise NetdiskError("download_unverified", "下载未返回成功且 verified 的文件回执。")
                        snapshot = self._local_snapshot(local)
                        if snapshot["size"] != item["source_snapshot"]["size"]:
                            raise NetdiskError("download_size_mismatch", "下载文件大小与远端源文件不符。")
                        after = self._stat(item["remote_path"])
                        if not after or self._remote_snapshot(after) != item["source_snapshot"]:
                            raise NetdiskError("remote_changed", "下载期间远端源文件发生变化，请核对本地结果。")
                    item.update(status="succeeded", receipt=redact(receipt), destination_snapshot=snapshot, resumed=False)
                except Exception as error:
                    item.update(status="failed", error=self._error(error))
                self._save(path, manifest)
            manifest["status"] = "succeeded" if all(item["status"] == "succeeded" for item in plan) else "failed"
            self._save(path, manifest)
            return self._summary(path, manifest)

    def upload_tree(self, local_dir, remote_dir, overwrite=False):
        local = self._local(local_dir, directory=True, must_exist=True, upload_root=True)
        remote = self._remote(remote_dir)
        return self._run("upload", local, remote, overwrite)

    def download_tree(self, remote_dir, local_dir, overwrite=False):
        remote = self._remote(remote_dir)
        local = self._local(local_dir, directory=True)
        return self._run("download", remote, local, overwrite)
