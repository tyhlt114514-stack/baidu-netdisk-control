"""Restricted BaiduPCS-Go v4.0.2 backend; no browser or desktop automation.

Command syntax and success messages are checked against the maintained source:
https://github.com/qjfoidnh/BaiduPCS-Go/tree/v4.0.2/internal/pcscommand
https://github.com/qjfoidnh/BaiduPCS-Go/blob/v4.0.2/main.go

Authentication is deliberately outside this API. A person must use the local setup
helper to import their own web-session cookies or BDUSS/STOKEN, with the private
BAIDUPCS_GO_CONFIG_DIR set to this backend's config_dir. Upstream advises against its
unmaintained username/password login. Never put BDUSS, cookies, account passwords or
STOKEN in MCP arguments. The CLI stores secrets in its private local config directory.

The CLI has no JSON output. Read results retain bounded, redacted human-readable
text. Metadata needed for safety is parsed conservatively; ambiguous output fails
closed. Downloads support individual files only. The third-party CLI and Baidu's
private endpoints can change; a command returning exit status 0 alone is not proof
of success. No raw CLI command, login, shell, overwrite or permanent-delete API is
exposed here.
"""

from __future__ import annotations

import os
import posixpath
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any, Sequence


_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_SECRET = re.compile(
    r'''(?i)(["']?\b(?:BDUSS|STOKEN|PTOKEN|BAIDUID|bdstoken|SBOXTKN|access[_-]?token|'''
    r'''refresh[_-]?token|authorization|password|cookie)\b["']?\s*[=:]\s*)'''
    r'''("[^"\r\n]*"|'[^'\r\n]*'|[^\s;,\r\n]+)'''
)
_ERROR = re.compile(
    r"(?im)(?:遇到错误|远端服务器返回错误|[:：]\s*网络错误[,，]|未设置任何百度帐号|请先登录|"
    r"(?:^|\n)\s*(?:Incorrect Usage:|FATAL ERROR:|panic:|未找到命令:|"
    r"重载配置错误:|保存配置错误:|未检测到上传的文件|"
    r"(?:\[\d+\]\s*)?(?:上传文件失败|下载文件失败|以下文件上传失败|以下文件下载失败|"
    r"创建分享链接失败|取消分享链接失败|操作失败|重命名失败|文件/目录拷贝失败))|"
    r"上传失败文件数:\s*[1-9]\d*|(?:copy|move) path error|"
    r"目标[^\n]*不是一个目录|(?:^|\n)\s*创建目录 .+ 失败,)"
)
_OUTPUT_MAX = 24_000
_FORBIDDEN_REMOTE = re.compile(r"[\\*?\[\]{}\x00-\x1f\x7f]")
_WINDOWS_RESERVED = re.compile(r"(?i)^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$")


def _redact(value: str) -> str:
    """Remove escape codes and authentication values before exposing CLI output."""
    value = _ANSI.sub("", value)
    # Cookies can contain several fields; remove the complete header first.
    value = re.sub(r"(?im)(\b(?:Cookie|Authorization)\s*[:=]\s*)[^\r\n]*", r"\1[REDACTED]", value)
    return _SECRET.sub(lambda match: match.group(1) + "[REDACTED]", value)


def _remote(value: str, *, allow_root: bool = True) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError("A remote path must be an absolute path beginning with '/'.")
    if len(value) > 4096 or _FORBIDDEN_REMOTE.search(value):
        raise ValueError("Remote paths cannot contain control characters, backslashes or wildcards.")
    segments = value.split("/")
    if any(segment in (".", "..") for segment in segments):
        raise ValueError("Remote path traversal is not allowed.")
    if "//" in value:
        raise ValueError("Remote paths cannot contain empty path components.")
    cleaned = posixpath.normpath(value)
    if cleaned == "/" and not allow_root:
        raise ValueError("This operation cannot target the whole remote root directory.")
    return cleaned


def _paths(values: Sequence[str]) -> list[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        raise ValueError("paths must be a nonempty list of absolute remote paths.")
    if not 1 <= len(values) <= 100:
        raise ValueError("Provide between 1 and 100 remote paths.")
    result = [_remote(value, allow_root=False) for value in values]
    if len(set(result)) != len(result):
        raise ValueError("Duplicate remote paths are not allowed.")
    return result


def _integer(value: int, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{name} must be an integer between {low} and {high}.")
    return value


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _linked(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        return bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)
    except FileNotFoundError:
        return False


def _safe_basename(name: str) -> str:
    if not isinstance(name, str) or not name or name in (".", ".."):
        raise ValueError("A nonempty filename is required.")
    if re.search(r'[<>:"/\\|?*\x00-\x1f\x7f]', name) or name.endswith((" ", ".")):
        raise ValueError("The filename is unsafe for local Windows files.")
    if _WINDOWS_RESERVED.match(name) or len(name) > 255:
        raise ValueError("The filename is reserved or too long.")
    return name


class PcsBackend:
    """Fixed-command subprocess adapter with isolated state and local path bounds."""

    def __init__(
        self,
        executable: str,
        config_dir: Path,
        allowed_local_roots: list[Path],
        *,
        timeout: int = 60,
        transfer_timeout: int = 3600,
    ) -> None:
        if not isinstance(executable, str) or not executable or any(c in executable for c in "\r\n\x00"):
            raise ValueError("Specify the BaiduPCS-Go executable path.")
        if Path(executable).suffix.lower() in (".cmd", ".bat", ".ps1", ".sh"):
            raise ValueError("Shell scripts cannot be used as the BaiduPCS-Go executable.")
        # Resolve bare executable names once; later PATH changes cannot replace it.
        found = shutil.which(executable)
        candidate = Path(found or executable).expanduser()
        self.executable = str(candidate.resolve())
        self.config_dir = Path(config_dir).expanduser().absolute()
        for ancestor in [self.config_dir, *self.config_dir.parents]:
            if _linked(ancestor):
                raise ValueError("The private PCS config directory cannot contain links or junctions.")
        self.config_dir = self.config_dir.resolve()
        if not allowed_local_roots:
            raise ValueError("At least one allowed local directory is required.")
        self.allowed_local_roots = [Path(root).expanduser().resolve() for root in allowed_local_roots]
        if any(not root.is_dir() for root in self.allowed_local_roots):
            raise ValueError("Every allowed local root must be an existing directory.")
        self.timeout = _integer(timeout, "timeout", 1, 3600)
        self.transfer_timeout = _integer(transfer_timeout, "transfer_timeout", 1, 86400)
        self._lock = threading.RLock()
        self._json_reader = None

    def _structured_reader(self):
        if self._json_reader is None:
            from .pcs_json import PcsJsonReader
            self._json_reader = PcsJsonReader(self.config_dir, timeout=self.timeout,
                                             transfer_timeout=self.transfer_timeout)
        return self._json_reader

    def account_identity(self) -> dict[str, Any]:
        with self._lock:
            return self._structured_reader().account_identity()

    def list_entries(self, path: str = "/", start: int = 0, limit: int = 1000) -> dict[str, Any]:
        with self._lock:
            return self._structured_reader().list_entries(path, start, limit)

    def stat_entry(self, path: str) -> dict[str, Any]:
        with self._lock:
            return self._structured_reader().stat_entry(path)

    def download_to(self, remote_path: str, destination: str | Path,
                    expected_entry: dict[str, Any]) -> dict[str, Any]:
        local = self._local(destination, must_exist=False)
        with self._lock:
            return self._structured_reader().download_to(remote_path, local, expected_entry)

    @staticmethod
    def _failure(operation: str, code: str, message: str, **extra: Any) -> dict[str, Any]:
        return {"ok": False, "backend": "pcs", "operation": operation,
                "error": {"code": code, "message": message}, **extra}

    def _local(self, value: str | Path, *, must_exist: bool) -> Path:
        raw = Path(value).expanduser()
        if not raw.is_absolute() or ".." in re.split(r"[/\\]", str(value)):
            raise ValueError("Local paths must be absolute and cannot contain '..'.")
        for ancestor in [raw, *raw.parents]:
            if _linked(ancestor):
                raise ValueError("Local paths cannot contain symbolic links, junctions or reparse points.")
        path = raw.resolve()
        if not any(_within(path, root) for root in self.allowed_local_roots):
            raise ValueError("The local path is outside allowed_local_roots.")
        if _within(path, self.config_dir):
            raise ValueError("The private PCS configuration cannot be uploaded or overwritten.")
        if must_exist and not path.exists():
            raise ValueError("The local path does not exist.")
        return path

    def _execute(self, operation: str, args: list[str], *, success: str | None = None,
                 timeout: int | None = None) -> dict[str, Any]:
        """Private fixed-argument execution; callers cannot select arbitrary commands."""
        with self._lock:
            if not Path(self.executable).is_file():
                return self._failure(operation, "not_installed", "BaiduPCS-Go executable was not found.")
            self.config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            env = os.environ.copy()
            env["BAIDUPCS_GO_CONFIG_DIR"] = str(self.config_dir)
            env["BAIDUPCS_GO_VERBOSE"] = "0"
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            time_limit = self.timeout if timeout is None else _integer(timeout, "timeout", 1, 86400)
            # File-backed streams prevent progress output from filling process RAM.
            with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                try:
                    process = subprocess.run(
                        [self.executable, *args], stdin=subprocess.DEVNULL,
                        stdout=stdout_file, stderr=stderr_file, cwd=str(self.config_dir),
                        env=env, timeout=time_limit, shell=False, check=False,
                        creationflags=creationflags,
                    )
                except subprocess.TimeoutExpired:
                    return self._failure(operation, "timeout", "PCS command timed out; remote state may have changed.",
                                         timed_out=True, timeout_seconds=time_limit)
                except OSError as exc:
                    return self._failure(operation, "execution_error", _redact(str(exc)))
                captured: list[str] = []
                has_error = False
                has_network_error = False
                has_auth_error = False
                has_success = success is None
                truncated = False
                # Scan every line for failures and success markers before truncating output.
                for stream in (stdout_file, stderr_file):
                    stream.seek(0)
                    chunks: list[str] = []
                    total = 0
                    for raw_line in stream:
                        line = _redact(raw_line.decode("utf-8", errors="replace"))
                        has_error = has_error or bool(_ERROR.search(line))
                        has_network_error = has_network_error or bool(re.search(r"[:：]\s*网络错误[,，]", line))
                        has_auth_error = has_auth_error or bool(re.search(
                            r"(?:代码|code)\s*[:=]\s*(?:31045|-6)\b|登录状态过期|消息:\s*请重新登录", line))
                        has_success = has_success or (success is not None and bool(re.search(success, line)))
                        if total < _OUTPUT_MAX:
                            chunks.append(line[:_OUTPUT_MAX - total])
                        else:
                            truncated = True
                        total += len(line)
                        if total > _OUTPUT_MAX:
                            truncated = True
                    captured.append("".join(chunks))
                stdout, stderr = captured
                result: dict[str, Any] = {
                    "ok": process.returncode == 0 and not has_error and has_success,
                    "backend": "pcs", "operation": operation, "returncode": process.returncode,
                    "stdout": stdout, "stderr": stderr, "output_truncated": truncated,
                    "output_format": "cli_text",
                }
                if not result["ok"]:
                    code = "cli_error" if process.returncode or has_error else "unrecognized_output"
                    if has_network_error:
                        code = "network_error"
                    elif has_auth_error:
                        code = "authentication_required"
                    if re.search(r"(?:代码|code)\s*[:=]\s*(?:31066|-9)\b", stdout + stderr):
                        code = "not_found"
                    result["error"] = {"code": code,
                                       "message": ("PCS could not reach Baidu; inspect network access and stdout/stderr."
                                                   if has_network_error else
                                                   "Baidu requires a valid session; run the local masked session-import setup."
                                                   if has_auth_error else
                                                   "PCS reported an error or did not confirm completion; inspect stdout/stderr.")}
                return result

    def status(self) -> dict[str, Any]:
        if not Path(self.executable).is_file():
            return {"ok": True, "backend": "pcs", "operation": "status", "installed": False,
                    "logged_in": False, "executable": self.executable,
                    "setup_required": "Install BaiduPCS-Go, then run the local masked session-import setup."}
        result = self._execute("status", ["who"], success=r"当前帐号 uid:")
        match = re.search(r"当前帐号 uid:\s*(\d+),\s*用户名:\s*([^,\r\n]*)", result.get("stdout", ""))
        result.update(installed=True, logged_in=bool(match and int(match.group(1))), session_validated=False)
        if match:
            result["account"] = {"uid": match.group(1), "name": match.group(2).strip()}
        if not result["logged_in"]:
            result["setup_required"] = "Run the local setup helper to import your own web-session cookies or BDUSS/STOKEN into the private PCS directory."
        return result

    def file_info(self, remote_path: str) -> dict[str, Any]:
        path = _remote(remote_path)
        result = self._execute("file_info", ["meta", path], success=r"\bfs_id\s+")
        if not result["ok"]:
            return result
        text = result["stdout"]
        path_match = re.search(r"(?m)^\s*\|?\s*(?:文件路径|目录路径)\s+([^|\r\n]+)", text)
        type_match = re.search(r"(?m)^\s*\|?\s*类型\s+(目录|文件)\b", text)
        id_match = re.search(r"\bfs_id\s+(\d+)\b", text)
        if not path_match or not type_match or not id_match or path_match.group(1).strip() != path:
            return self._failure("file_info", "unrecognized_output", "Cannot safely interpret this PCS metadata output.",
                                 stdout=text, stderr=result["stderr"], returncode=result["returncode"])
        size_match = re.search(r"文件大小\s+(\d+),", text)
        result["file"] = {"path": path, "name": posixpath.basename(path),
                          "fs_id": id_match.group(1), "is_dir": type_match.group(1) == "目录",
                          "size": int(size_match.group(1)) if size_match else None}
        return result

    @staticmethod
    def _bounded_rows(result: dict[str, Any], limit: int) -> dict[str, Any]:
        """Limit presented table lines, retaining the CLI text rather than inventing JSON rows."""
        lines = result.get("stdout", "").splitlines()
        data_rows = 0
        output: list[str] = []
        for line in lines:
            if re.match(r"^\s*\|?\s*\d+\s+", line):
                data_rows += 1
                if data_rows > limit:
                    continue
            output.append(line)
        result["stdout"] = "\n".join(output)
        result["limit"] = limit
        result["rows_truncated"] = data_rows > limit
        result["pagination"] = "CLI fetches the directory; limit bounds displayed rows only."
        return result

    def list_files(self, path: str = "/", limit: int = 100) -> dict[str, Any]:
        path = _remote(path)
        limit = _integer(limit, "limit", 1, 1000)
        return self._bounded_rows(self._execute("list_files", ["ls", path], success=r"文件总数:"), limit)

    def search(self, keyword: str, path: str = "/", recursive: bool = True,
               limit: int = 100) -> dict[str, Any]:
        path = _remote(path)
        limit = _integer(limit, "limit", 1, 1000)
        if not isinstance(keyword, str) or not keyword.strip() or len(keyword) > 256 or re.search(r"[\x00-\x1f\x7f]", keyword):
            raise ValueError("Provide a nonempty keyword of at most 256 characters without control characters.")
        if not isinstance(recursive, bool):
            raise ValueError("recursive must be a boolean.")
        args = ["search", "-path=" + path]
        if recursive:
            args.append("-r")
        # A separator prevents a keyword beginning with '-' from becoming a CLI flag.
        args.extend(["--", keyword])
        result = self._bounded_rows(self._execute("search", args, success=r"文件总数:"), limit)
        result["searches_directories"] = False
        return result

    def quota(self) -> dict[str, Any]:
        return self._execute("quota", ["quota"], success=r"总空间:.*已用空间:")

    def _expect_directory(self, path: str, operation: str) -> dict[str, Any] | None:
        info = self.file_info(path)
        if not info["ok"]:
            return self._failure(operation, "preflight_failed", "Could not verify the remote destination directory.", preflight=info)
        if not info["file"]["is_dir"]:
            return self._failure(operation, "not_directory", "The remote destination must be an existing directory.")
        return None

    def _expect_absent(self, path: str, operation: str) -> dict[str, Any] | None:
        info = self.file_info(path)
        if info["ok"]:
            return self._failure(operation, "already_exists", "The target already exists; overwriting is not supported.", path=path)
        if info.get("error", {}).get("code") != "not_found":
            return self._failure(operation, "preflight_failed", "Could not safely establish that the target is absent.", preflight=info)
        return None

    def mkdir(self, path: str) -> dict[str, Any]:
        path = _remote(path, allow_root=False)
        with self._lock:
            failure = self._expect_absent(path, "mkdir")
            return failure or self._execute("mkdir", ["mkdir", path], success=r"创建目录成功:")

    def rename(self, path: str, new_name: str) -> dict[str, Any]:
        path = _remote(path, allow_root=False)
        new_name = _safe_basename(new_name)
        target = posixpath.join(posixpath.dirname(path), new_name)
        if target == path:
            raise ValueError("The new name equals the existing filename.")
        with self._lock:
            failure = self._expect_absent(target, "rename")
            return failure or self._execute("rename", ["mv", path, target], success=r"重命名成功:")

    def _copy_or_move(self, operation: str, paths: Sequence[str], dest: str) -> dict[str, Any]:
        sources = _paths(paths)
        destination = _remote(dest)
        names = [posixpath.basename(path) for path in sources]
        if len(set(names)) != len(names):
            raise ValueError("Sources must have distinct filenames in the destination directory.")
        if any(destination == path or destination.startswith(path + "/") for path in sources):
            raise ValueError("A path cannot be moved or copied into itself or its descendants.")
        with self._lock:
            failure = self._expect_directory(destination, operation)
            if failure:
                return failure
            for source in sources:
                failure = self._expect_absent(posixpath.join(destination, posixpath.basename(source)), operation)
                if failure:
                    return failure
            command = "cp" if operation == "copy" else "mv"
            return self._execute(operation, [command, *sources, destination], success=r"操作成功, 以下文件/目录")

    def move(self, paths: Sequence[str], dest: str) -> dict[str, Any]:
        return self._copy_or_move("move", paths, dest)

    def copy(self, paths: Sequence[str], dest: str) -> dict[str, Any]:
        return self._copy_or_move("copy", paths, dest)

    def delete(self, paths: Sequence[str]) -> dict[str, Any]:
        return self._execute("delete", ["rm", *_paths(paths)], success=r"操作成功, 以下文件/目录已删除")

    def upload(self, local_path: str | Path, remote_dir: str, *, timeout: int | None = None) -> dict[str, Any]:
        local = self._local(local_path, must_exist=True)
        destination = _remote(remote_dir)
        _safe_basename(local.name)
        snapshot = local.stat()
        if local.is_dir():
            if _within(self.config_dir, local):
                raise ValueError("Uploading this directory would expose the private PCS configuration.")
            for current, dirs, files in os.walk(local, followlinks=False):
                for name in dirs + files:
                    child = Path(current, name)
                    self._local(child, must_exist=True)
                    _safe_basename(name)
                    if not child.is_dir() and not stat.S_ISREG(child.stat().st_mode):
                        raise ValueError("Only regular files can be uploaded.")
        elif not local.is_file() or not stat.S_ISREG(local.stat().st_mode):
            raise ValueError("Only regular files or directories can be uploaded.")
        with self._lock:
            failure = self._expect_directory(destination, "upload")
            if failure:
                return failure
            failure = self._expect_absent(posixpath.join(destination, local.name), "upload")
            if failure:
                return failure
            # Explicit skip overrides a dangerous user UPolicy setting. Rapid upload
            # is disabled because BaiduPCS-Go documents that it no longer works.
            result = self._execute("upload", ["upload", "-policy=skip", "-norapid", "-p=1", "-l=1", "-retry=1",
                                               str(local), destination], success=r"上传结束,",
                                   timeout=self.transfer_timeout if timeout is None else timeout)
            target_path = posixpath.join(destination, local.name)
            if result["ok"] and local.is_file():
                uploaded = self.file_info(target_path)
                current = local.stat()
                if (not uploaded["ok"] or uploaded["file"]["is_dir"]
                        or uploaded["file"]["size"] != snapshot.st_size
                        or (current.st_size, current.st_mtime_ns) != (snapshot.st_size, snapshot.st_mtime_ns)):
                    result = self._failure("upload", "verification_failed",
                                           "The upload was not verified against an unchanged local file and matching remote size.",
                                           stdout=result["stdout"], stderr=result["stderr"], verification=uploaded)
                else:
                    result["verification"] = "remote_metadata_size_matches_unchanged_local_file"
            elif result["ok"]:
                result["verification"] = "cli_completion_only_for_directory"
            result.update(local_path=str(local), remote_dir=destination,
                          remote_path=target_path, overwrite=False)
            return result

    def download(self, remote_path: str, local_dir: str | Path, *, timeout: int | None = None) -> dict[str, Any]:
        path = _remote(remote_path, allow_root=False)
        basename = _safe_basename(posixpath.basename(path))
        directory = self._local(local_dir, must_exist=False)
        if directory.exists() and not directory.is_dir():
            raise ValueError("local_dir must be a directory.")
        target = self._local(directory / basename, must_exist=False)
        if target.exists():
            return self._failure("download", "already_exists", "The local target already exists; overwriting is not supported.", path=str(target))
        with self._lock:
            info = self.file_info(path)
            if not info["ok"]:
                return self._failure("download", "preflight_failed", "Could not verify the remote file.", preflight=info)
            if info["file"]["is_dir"]:
                return self._failure("download", "unsupported", "PCS directory downloads are disabled; download individual files to protect local path boundaries.")
            directory.mkdir(parents=True, exist_ok=True)
            result = self._execute("download", ["download", "-saveto=" + str(directory), "-p=1", "-l=1", "-retry=1", path],
                                   success=r"下载结束,", timeout=self.transfer_timeout if timeout is None else timeout)
            if result["ok"] and (not target.is_file() or _linked(target)):
                result = self._failure("download", "verification_failed", "PCS did not create the expected regular local file.",
                                       stdout=result["stdout"], stderr=result["stderr"])
            if result["ok"] and info["file"]["size"] is not None and target.stat().st_size != info["file"]["size"]:
                result = self._failure("download", "verification_failed", "The downloaded file size differs from remote metadata.",
                                       stdout=result["stdout"], stderr=result["stderr"])
            result.update(remote_path=path, local_path=str(target), overwrite=False)
            return result

    def share(self, paths: Sequence[str], password: str, period: int = 7) -> dict[str, Any]:
        sources = _paths(paths)
        if not isinstance(password, str) or not re.fullmatch(r"[A-Za-z0-9]{4}", password):
            raise ValueError("A private share requires a four-character alphanumeric extraction code.")
        period = _integer(period, "period", 0, 36500)
        result = self._execute("share", ["share", "set", "-p=" + password, "-period=" + str(period), *sources],
                               success=r"shareID:\s*\d+,\s*链接:")
        if result["ok"]:
            match = re.search(r"shareID:\s*(\d+),\s*链接:\s*(https://pan\.baidu\.com/[^\s,]+)", result["stdout"])
            if match:
                result["share"] = {"share_id": match.group(1), "url": match.group(2), "extraction_code": password, "period": period}
        return result

    def shares(self, page: int = 1) -> dict[str, Any]:
        page = _integer(page, "page", 1, 10000)
        return self._execute("shares", ["share", "list", "-page=" + str(page)], success=r"(?:SHAREID|ShareID)")

    def cancel_share(self, share_ids: Sequence[str | int]) -> dict[str, Any]:
        if isinstance(share_ids, (str, bytes)) or not isinstance(share_ids, (list, tuple)) or not 1 <= len(share_ids) <= 100:
            raise ValueError("Provide between 1 and 100 share IDs.")
        values: list[str] = []
        for value in share_ids:
            if isinstance(value, bool) or not re.fullmatch(r"[1-9][0-9]{0,18}", str(value)) or int(value) > 2**63 - 1:
                raise ValueError("Every share ID must be a positive 64-bit integer.")
            values.append(str(value))
        return self._execute("cancel_share", ["share", "cancel", *values], success=r"取消分享(?:链接)?成功")
