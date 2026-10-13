"""Account-isolated, resumable local index of remote Netdisk metadata.

Every committed page is a scan checkpoint. No network request holds a SQLite
transaction, and incomplete scans never remove older metadata. The catalog is
a cached view, not a claim that remote files cannot change after enumeration.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import posixpath
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from .common import NetdiskError, file_lock, normalize_remote, redact


def _inside(path: str, root: str) -> bool:
    return root == "/" or path == root or path.startswith(root + "/")


def _like_prefix(path: str) -> str:
    # SQL LIKE treats % and _ as wildcards, while Netdisk treats them as names.
    prefix = "/" if path == "/" else path + "/"
    return prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Catalog:
    PAGE_SIZE = 1000
    _guard = threading.Lock()
    _scan_locks: dict[str, threading.Lock] = {}

    def __init__(self, state_dir: Path, backend_name: str, account_id: str):
        if not isinstance(backend_name, str) or not backend_name.strip():
            raise NetdiskError("catalog_account_required", "索引必须绑定已登录的网盘后端。")
        if account_id is None or not str(account_id).strip():
            raise NetdiskError("catalog_account_required", "索引必须绑定当前登录账号的用户 ID。")
        self.state_dir = Path(state_dir).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.state_dir / "catalog.sqlite"
        self.backend_name, self.account_id = backend_name, str(account_id)
        self.account_key = hashlib.sha256((backend_name + "\0" + self.account_id).encode("utf-8")).hexdigest()
        self._initialize()

    @contextlib.contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self):
        with self._connection() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS catalog_accounts (
                    account_key TEXT PRIMARY KEY,
                    backend_name TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS catalog_files (
                    account_key TEXT NOT NULL,
                    path TEXT NOT NULL,
                    parent_path TEXT NOT NULL,
                    name TEXT NOT NULL,
                    name_fold TEXT NOT NULL,
                    is_dir INTEGER NOT NULL CHECK (is_dir IN (0, 1)),
                    size INTEGER NOT NULL,
                    fs_id TEXT,
                    payload TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    indexed_at REAL NOT NULL,
                    PRIMARY KEY (account_key, path)
                );
                CREATE INDEX IF NOT EXISTS catalog_files_parent
                    ON catalog_files (account_key, parent_path, path);
                CREATE INDEX IF NOT EXISTS catalog_files_generation
                    ON catalog_files (account_key, generation);
                CREATE INDEX IF NOT EXISTS catalog_files_fsid
                    ON catalog_files (account_key, fs_id);
                CREATE TABLE IF NOT EXISTS catalog_scans (
                    scan_id TEXT PRIMARY KEY,
                    account_key TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    remote_root TEXT NOT NULL,
                    recursive INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    finished_at REAL,
                    entries_seen INTEGER NOT NULL DEFAULT 0,
                    pages_seen INTEGER NOT NULL DEFAULT 0,
                    stale_removed INTEGER NOT NULL DEFAULT 0,
                    error_code TEXT,
                    error_message TEXT,
                    UNIQUE(account_key, generation)
                );
                CREATE INDEX IF NOT EXISTS catalog_scans_account
                    ON catalog_scans(account_key, generation);
                CREATE TABLE IF NOT EXISTS catalog_scan_dirs (
                    scan_id TEXT NOT NULL REFERENCES catalog_scans(scan_id),
                    path TEXT NOT NULL,
                    parent_path TEXT,
                    depth INTEGER NOT NULL,
                    next_start INTEGER NOT NULL DEFAULT 0,
                    complete INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(scan_id, path)
                );
                CREATE TABLE IF NOT EXISTS catalog_scan_pages (
                    scan_id TEXT NOT NULL REFERENCES catalog_scans(scan_id),
                    directory TEXT NOT NULL,
                    start INTEGER NOT NULL,
                    next_start INTEGER NOT NULL,
                    item_count INTEGER NOT NULL,
                    digest TEXT NOT NULL,
                    PRIMARY KEY(scan_id, directory, start)
                );
            """)
            db.execute("INSERT OR IGNORE INTO catalog_accounts(account_key,backend_name,created_at) VALUES (?,?,?)",
                       (self.account_key, self.backend_name, time.time()))

    @staticmethod
    def _scope_clause(path: str, recursive: bool) -> tuple[str, list]:
        if recursive:
            return "path LIKE ? ESCAPE '\\'", [_like_prefix(path)]
        return "parent_path = ?", [path]

    def _begin_scan(self, remote_root, recursive):
        now = time.time()
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                previous = db.execute("SELECT * FROM catalog_scans WHERE account_key=? ORDER BY generation DESC LIMIT 1",
                                      (self.account_key,)).fetchone()
                # Resuming an older scan after a newer scope scan could delete
                # files learned by the newer generation. Only resume the newest.
                if (previous and previous["status"] in ("running", "paused", "failed") and
                        previous["remote_root"] == remote_root and bool(previous["recursive"]) == recursive):
                    scan_id, generation, resumed = previous["scan_id"], previous["generation"], True
                    db.execute("UPDATE catalog_scans SET status='running',updated_at=?,finished_at=NULL,"
                               "error_code=NULL,error_message=NULL WHERE scan_id=?", (now, scan_id))
                else:
                    scan_id = uuid.uuid4().hex
                    generation = previous["generation"] + 1 if previous else 1
                    resumed = False
                    db.execute("INSERT INTO catalog_scans(scan_id,account_key,generation,remote_root,recursive,"
                               "status,started_at,updated_at) VALUES (?,?,?,?,?,'running',?,?)",
                               (scan_id, self.account_key, generation, remote_root, int(recursive), now, now))
                    db.execute("INSERT INTO catalog_scan_dirs(scan_id,path,depth) VALUES (?,?,0)",
                               (scan_id, remote_root))
                db.commit()
                return scan_id, generation, resumed
            except BaseException:
                db.rollback()
                raise

    @staticmethod
    def _entry(raw, directory):
        if not isinstance(raw, dict):
            raise NetdiskError("catalog_invalid_page", "文件列表包含无效条目。")
        path = normalize_remote(raw.get("path", ""), allow_root=False)
        if path != raw["path"] or posixpath.dirname(path) != directory:
            raise NetdiskError("catalog_wrong_directory", "列表返回了当前目录以外的文件，扫描未完成。")
        name = raw.get("name", posixpath.basename(path))
        if not isinstance(name, str) or name != posixpath.basename(path):
            raise NetdiskError("catalog_invalid_page", "列表文件名与完整路径不一致。")
        directory_flag = raw.get("is_dir")
        if not isinstance(directory_flag, (bool, int)) or directory_flag not in (False, True, 0, 1):
            raise NetdiskError("catalog_invalid_page", "列表缺少文件与目录类型。")
        size = raw.get("size", 0)
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size < 2 ** 63:
            raise NetdiskError("catalog_invalid_page", "列表返回了无效文件大小。")
        fs_id = raw.get("fs_id")
        if fs_id is not None:
            if isinstance(fs_id, bool) or not isinstance(fs_id, (int, str)):
                raise NetdiskError("catalog_invalid_page", "列表返回了无效文件 ID。")
            fs_id = str(fs_id)
            if not fs_id.isdecimal() or not 0 < int(fs_id) < 2 ** 64:
                raise NetdiskError("catalog_invalid_page", "文件 ID 超出 uint64 范围。")
        # Preserve filename, timestamps, hash, and the full decimal ID without
        # accidentally persisting signed URLs or credentials from an adapter.
        return {"path": path, "name": name, "is_dir": bool(directory_flag), "size": size,
                "fs_id": fs_id, "mtime": raw.get("mtime"), "ctime": raw.get("ctime"), "md5": raw.get("md5")}

    @classmethod
    def _validate_page(cls, response, directory, start, limit):
        if not isinstance(response, dict):
            raise NetdiskError("catalog_invalid_page", "网盘未返回结构化分页列表。")
        for field in ("errno", "error_code"):
            if field in response and str(response[field]) != "0":
                raise NetdiskError("catalog_remote_error", "网盘列表返回业务错误，扫描未完成。",
                                   {"errno": str(response[field])})
        if response.get("ok") is False:
            raise NetdiskError("catalog_remote_error", "网盘列表读取失败，扫描未完成。")
        entries = response.get("entries")
        if not isinstance(entries, list) or len(entries) > limit:
            raise NetdiskError("catalog_invalid_page", "网盘返回的条目数量不符合分页请求。")
        has_more = response.get("has_more")
        if not isinstance(has_more, bool):
            raise NetdiskError("catalog_invalid_page", "网盘列表缺少明确的分页结束标记。")
        returned_start, next_start = response.get("start"), response.get("next_start")
        # Both provider adapters use None when there is no next page. Keep the
        # checkpoint as a numeric consumed offset, while requiring an explicit
        # cursor on every continuing page.
        if next_start is None and has_more is False:
            next_start = start + len(entries)
        if (isinstance(returned_start, bool) or not isinstance(returned_start, int) or returned_start != start or
                isinstance(next_start, bool) or not isinstance(next_start, int) or next_start != start + len(entries)):
            raise NetdiskError("catalog_page_gap", "分页起点或下一页位置不连续，扫描未完成。")
        if has_more and not entries:
            raise NetdiskError("catalog_page_gap", "网盘返回空页但仍声明有下一页，扫描未完成。")
        prepared = [cls._entry(raw, directory) for raw in entries]
        if len({item["path"] for item in prepared}) != len(prepared):
            raise NetdiskError("catalog_duplicate_entry", "同一页重复返回文件或目录，扫描未完成。")
        digest = hashlib.sha256(json.dumps([item["path"] for item in prepared], ensure_ascii=False).encode()).hexdigest()
        return prepared, next_start, has_more, digest

    def _commit_page(self, scan_id, generation, directory, start, limit, response, recursive):
        entries, next_start, has_more, digest = self._validate_page(response, directory, start, limit)
        now = time.time()
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                cursor = db.execute("SELECT next_start,complete,depth FROM catalog_scan_dirs WHERE scan_id=? AND path=?",
                                    (scan_id, directory)).fetchone()
                if not cursor or cursor["complete"] or cursor["next_start"] != start:
                    raise NetdiskError("catalog_checkpoint_error", "扫描目录检查点不连续。")
                if entries and db.execute("SELECT 1 FROM catalog_scan_pages WHERE scan_id=? AND directory=? AND digest=?",
                                          (scan_id, directory, digest)).fetchone():
                    raise NetdiskError("catalog_duplicate_page", "网盘重复返回已读取分页，扫描未完成。")
                for offset in range(0, len(entries), 400):
                    paths = [item["path"] for item in entries[offset:offset + 400]]
                    placeholders = ",".join("?" for _ in paths)
                    if paths and db.execute("SELECT 1 FROM catalog_files WHERE account_key=? AND generation=? AND path IN ("
                                            + placeholders + ") LIMIT 1", [self.account_key, generation, *paths]).fetchone():
                        raise NetdiskError("catalog_duplicate_entry", "不同分页重复返回文件或目录，扫描未完成。")
                for item in entries:
                    payload = json.dumps(item, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
                    db.execute("INSERT INTO catalog_files(account_key,path,parent_path,name,name_fold,is_dir,size,fs_id,"
                               "payload,generation,indexed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                               "ON CONFLICT(account_key,path) DO UPDATE SET parent_path=excluded.parent_path,name=excluded.name,"
                               "name_fold=excluded.name_fold,is_dir=excluded.is_dir,size=excluded.size,fs_id=excluded.fs_id,"
                               "payload=excluded.payload,generation=excluded.generation,indexed_at=excluded.indexed_at",
                               (self.account_key, item["path"], directory, item["name"], item["name"].casefold(),
                                int(item["is_dir"]), item["size"], item["fs_id"], payload, generation, now))
                    if recursive and item["is_dir"]:
                        if db.execute("SELECT 1 FROM catalog_scan_dirs WHERE scan_id=? AND path=?",
                                      (scan_id, item["path"])).fetchone():
                            raise NetdiskError("catalog_duplicate_directory", "扫描队列出现重复目录，扫描未完成。")
                        db.execute("INSERT INTO catalog_scan_dirs(scan_id,path,parent_path,depth) VALUES (?,?,?,?)",
                                   (scan_id, item["path"], directory, cursor["depth"] + 1))
                db.execute("INSERT INTO catalog_scan_pages(scan_id,directory,start,next_start,item_count,digest) VALUES (?,?,?,?,?,?)",
                           (scan_id, directory, start, next_start, len(entries), digest))
                db.execute("UPDATE catalog_scan_dirs SET next_start=?,complete=? WHERE scan_id=? AND path=?",
                           (next_start, int(not has_more), scan_id, directory))
                db.execute("UPDATE catalog_scans SET entries_seen=entries_seen+?,pages_seen=pages_seen+1,updated_at=? WHERE scan_id=?",
                           (len(entries), now, scan_id))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return len(entries)

    def _finish(self, scan_id, generation, remote_root, recursive):
        now = time.time()
        scope_sql, scope_params = self._scope_clause(remote_root, recursive)
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute("SELECT 1 FROM catalog_scan_dirs WHERE scan_id=? AND complete=0", (scan_id,)).fetchone():
                    raise NetdiskError("catalog_incomplete", "尚有目录没有读取完毕，不能标记完整。")
                removed = db.execute("DELETE FROM catalog_files WHERE account_key=? AND generation<>? AND " + scope_sql,
                                     [self.account_key, generation, *scope_params]).rowcount
                db.execute("UPDATE catalog_scans SET status='complete',updated_at=?,finished_at=?,stale_removed=? WHERE scan_id=?",
                           (now, now, removed, scan_id))
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def _set_status(self, scan_id, status, error=None):
        with self._connection() as db:
            db.execute("UPDATE catalog_scans SET status=?,updated_at=?,error_code=?,error_message=? WHERE scan_id=?",
                       (status, time.time(), error.code if error else None,
                        str(redact(error.message)) if error else None, scan_id))

    def _receipt(self, db, row):
        directories = db.execute("SELECT count(*) total,sum(complete) completed FROM catalog_scan_dirs WHERE scan_id=?",
                                 (row["scan_id"],)).fetchone()
        pending = db.execute("SELECT path,next_start FROM catalog_scan_dirs WHERE scan_id=? AND complete=0 ORDER BY depth,path LIMIT 1",
                             (row["scan_id"],)).fetchone()
        result = {"ok": row["status"] != "failed", "scan_id": row["scan_id"], "generation": row["generation"],
                  "status": row["status"], "complete": row["status"] == "complete",
                  "scope": {"backend": self.backend_name, "account_id": self.account_id,
                            "path": row["remote_root"], "recursive": bool(row["recursive"])},
                  "entries_seen": row["entries_seen"], "pages_seen": row["pages_seen"],
                  "dirs_seen": directories["total"], "dirs_completed": directories["completed"] or 0,
                  "stale_removed": row["stale_removed"], "started_at": row["started_at"],
                  "updated_at": row["updated_at"], "finished_at": row["finished_at"],
                  "checkpoint": dict(pending) if pending else None,
                  "consistency": "已枚举范围的本地缓存；网盘可能在扫描中或扫描后变化。"}
        if row["error_code"]:
            result["error"] = {"code": row["error_code"], "message": row["error_message"]}
        return result

    def receipt(self, scan_id=None):
        """Read a persisted scan receipt, including after process restart."""
        with self._connection() as db:
            if scan_id is None:
                row = db.execute("SELECT * FROM catalog_scans WHERE account_key=? ORDER BY generation DESC LIMIT 1",
                                 (self.account_key,)).fetchone()
            else:
                row = db.execute("SELECT * FROM catalog_scans WHERE account_key=? AND scan_id=?",
                                 (self.account_key, scan_id)).fetchone()
            if not row:
                raise NetdiskError("catalog_scan_missing", "此账号尚无对应扫描回执。")
            return self._receipt(db, row)

    def scan(self, backend, remote_root="/", recursive=True, max_entries=None):
        remote_root = normalize_remote(remote_root)
        if not isinstance(recursive, bool):
            raise NetdiskError("invalid_recursive", "recursive 必须为布尔值。")
        if max_entries is not None and (isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1):
            raise NetdiskError("invalid_max_entries", "max_entries 必须为正整数或省略。")
        if not callable(getattr(backend, "list_entries", None)):
            raise NetdiskError("catalog_backend_unsupported", "此网盘后端没有结构化文件分页接口。")
        lock_key = str(self.path) + self.account_key
        with self._guard:
            thread_lock = self._scan_locks.setdefault(lock_key, threading.Lock())
        processed = 0
        with thread_lock, file_lock(self.state_dir / "catalog-locks" / (self.account_key + ".lock"), timeout=0):
            scan_id, generation, resumed = self._begin_scan(remote_root, recursive)
            try:
                while True:
                    with self._connection() as db:
                        directory = db.execute("SELECT path,next_start FROM catalog_scan_dirs WHERE scan_id=? AND complete=0 "
                                               "ORDER BY depth,path LIMIT 1", (scan_id,)).fetchone()
                    if directory is None:
                        self._finish(scan_id, generation, remote_root, recursive)
                        break
                    if max_entries is not None and processed >= max_entries:
                        self._set_status(scan_id, "paused")
                        break
                    limit = self.PAGE_SIZE if max_entries is None else min(self.PAGE_SIZE, max_entries - processed)
                    # Only this call reads the cloud. All transactions are closed.
                    response = backend.list_entries(path=directory["path"], start=directory["next_start"], limit=limit)
                    processed += self._commit_page(scan_id, generation, directory["path"], directory["next_start"],
                                                   limit, response, recursive)
            except NetdiskError as error:
                self._set_status(scan_id, "failed", error)
            except Exception as error:
                # Do not persist URLs, cookies or stack traces from third parties.
                safe = NetdiskError("catalog_scan_error", "扫描异常（" + type(error).__name__ + "），已保留扫描检查点。")
                self._set_status(scan_id, "failed", safe)
            result = self.receipt(scan_id)
            result.update(resumed=resumed, entries_processed=processed)
            return result

    @staticmethod
    def _pagination(offset, limit):
        if (isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or
                isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000):
            raise NetdiskError("invalid_pagination", "offset 应为非负整数，limit 应为 1～1000。")

    def _coverage(self, db, path, recursive):
        scans = db.execute("SELECT * FROM catalog_scans WHERE account_key=? ORDER BY generation DESC",
                           (self.account_key,)).fetchall()
        def covers(scan):
            return ((bool(scan["recursive"]) and _inside(path, scan["remote_root"])) or
                    (not recursive and scan["remote_root"] == path))

        covering = next((s for s in scans if covers(s)), None)
        previous_complete = next((s for s in scans if covers(s) and s["status"] == "complete"), None)
        complete = bool(covering and covering["status"] == "complete")
        relevant = [s for s in scans if covers(s) or (recursive and _inside(s["remote_root"], path))]
        latest = relevant[0] if relevant else None
        # A newer incomplete subdirectory scan creates a mixed generation view.
        if complete and any(s["generation"] > covering["generation"] and s["status"] != "complete" for s in relevant):
            complete = False
        return {"complete": complete, "scan_id": latest["scan_id"] if latest else None,
                "scan_status": latest["status"] if latest else "never_scanned",
                "index_updated_at": latest["updated_at"] if latest else None,
                "last_complete_at": previous_complete["finished_at"] if previous_complete else None,
                "consistency": "目录枚举缓存，非网盘实时事务快照。"}

    def _query(self, path, recursive, pattern, keyword, offset, limit):
        path = normalize_remote(path)
        if not isinstance(recursive, bool):
            raise NetdiskError("invalid_recursive", "recursive 必须为布尔值。")
        self._pagination(offset, limit)
        if pattern is not None and not isinstance(pattern, str):
            raise NetdiskError("invalid_pattern", "pattern 应为文件名通配符字符串。")
        scope_sql, values = self._scope_clause(path, recursive)
        where = "account_key=? AND " + scope_sql
        parameters = [self.account_key, *values]
        if pattern is not None:
            where += " AND name GLOB ?"
            parameters.append(pattern)
        if keyword is not None:
            where += " AND instr(name_fold,?) > 0"
            parameters.append(keyword.casefold())
        with self._connection() as db:
            db.execute("BEGIN")
            try:
                count = db.execute("SELECT count(*) FROM catalog_files WHERE " + where, parameters).fetchone()[0]
                rows = db.execute("SELECT payload,generation,indexed_at FROM catalog_files WHERE " + where +
                                  " ORDER BY path COLLATE BINARY LIMIT ? OFFSET ?", [*parameters, limit, offset]).fetchall()
                coverage = self._coverage(db, path, recursive)
                db.commit()
            except BaseException:
                db.rollback()
                raise
        entries = [{**json.loads(row["payload"]), "generation": row["generation"], "indexed_at": row["indexed_at"]}
                   for row in rows]
        return {"entries": entries, "count": count, "offset": offset, "limit": limit,
                "next_offset": offset + len(entries), "has_more": offset + len(entries) < count,
                "scope": {"backend": self.backend_name, "account_id": self.account_id, "path": path,
                          "recursive": recursive}, **coverage}

    def query(self, path="/", recursive=False, pattern=None, offset=0, limit=100):
        """List cached children/descendants; pattern is a literal SQL GLOB filename pattern."""
        return self._query(path, recursive, pattern, None, offset, limit)

    def search(self, keyword, path="/", recursive=True, offset=0, limit=100):
        if not isinstance(keyword, str) or not keyword:
            raise NetdiskError("invalid_keyword", "搜索关键字不能为空。")
        return self._query(path, recursive, None, keyword, offset, limit)

    def stats(self):
        with self._connection() as db:
            db.execute("BEGIN")
            try:
                totals = db.execute("SELECT count(*) entries,sum(is_dir) directories,"
                                    "sum(CASE WHEN is_dir=0 THEN 1 ELSE 0 END) files,"
                                    "sum(CASE WHEN is_dir=0 THEN size ELSE 0 END) bytes,max(indexed_at) updated_at "
                                    "FROM catalog_files WHERE account_key=?", (self.account_key,)).fetchone()
                scan = db.execute("SELECT * FROM catalog_scans WHERE account_key=? ORDER BY generation DESC LIMIT 1",
                                  (self.account_key,)).fetchone()
                receipt = self._receipt(db, scan) if scan else None
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return {"backend": self.backend_name, "account_id": self.account_id,
                "entries": totals["entries"], "directories": totals["directories"] or 0,
                "files": totals["files"] or 0, "total_bytes": totals["bytes"] or 0,
                "updated_at": totals["updated_at"], "latest_scan": receipt,
                "complete": bool(receipt and receipt["complete"] and receipt["scope"]["path"] == "/" and
                                 receipt["scope"]["recursive"])}
