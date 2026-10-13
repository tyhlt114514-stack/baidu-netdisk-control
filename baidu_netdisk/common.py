from __future__ import annotations

import os
import posixpath
import re
import contextlib
import time
from pathlib import Path
from typing import Any


class NetdiskError(Exception):
    def __init__(self, code: str, message: str, details: dict | None = None):
        super().__init__(message)
        self.code, self.message, self.details = code, message, details or {}

    def as_dict(self) -> dict:
        return {"ok": False, "error": self.code, "message": redact(self.message),
                "details": redact(self.details)}


def normalize_remote(path: str, allow_root: bool = True) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise NetdiskError("invalid_path", "网盘路径必须是以 / 开头的绝对路径。")
    if any(ord(c) < 32 for c in path) or "\\" in path:
        raise NetdiskError("invalid_path", "网盘路径含控制字符或反斜杠。")
    if any(part in (".", "..") for part in path.split("/")):
        raise NetdiskError("invalid_path", "网盘路径不能含 . 或 ..。")
    result = posixpath.normpath("/" + path.lstrip("/"))
    if not allow_root and result == "/":
        raise NetdiskError("invalid_path", "不能对网盘根目录执行此操作。")
    return result


def checked_local(path: str | Path, roots: list[Path], must_exist: bool = False,
                  directory: bool = False) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise NetdiskError("invalid_local_path", "请提供完整的本地绝对路径。")
    candidate = candidate.resolve()
    if not roots or not any(candidate.is_relative_to(Path(r).resolve()) for r in roots):
        raise NetdiskError("local_path_denied", "本地路径不在 config.json 的 allowed_local_roots 中。")
    if must_exist and not candidate.exists():
        raise NetdiskError("local_file_missing", "本地文件或目录不存在。")
    if candidate.exists() and directory and not candidate.is_dir():
        raise NetdiskError("invalid_local_path", "本地目标应为目录。")
    if candidate.exists() and not directory and not candidate.is_file():
        raise NetdiskError("invalid_local_path", "本地源或目标应为普通文件。")
    return candidate


_SECRET_KEYS = re.compile(r"token|secret|bduss|stoken|cookie|authorization|password", re.I)
_SECRET_TEXT = re.compile(r"(?i)((?:access_token|refresh_token|client_secret|BDUSS|STOKEN|cookie|authorization)\s*[=:]\s*)([^\s&;,\"']+)")
_AUTH_TEXT = re.compile(r"(?i)(authorization\s*[=:]\s*)(?:bearer|basic)\s+[^\s\"']+")


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if _SECRET_KEYS.search(str(k)) else redact(v)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _SECRET_TEXT.sub(r"\1[REDACTED]", _AUTH_TEXT.sub(r"\1[REDACTED]", value))
    return value


def atomic_json(path: Path, value: Any) -> None:
    import json
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextlib.contextmanager
def file_lock(path: Path, timeout: float = 10):
    """Advisory cross-process lock for the shared PCS account database."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    handle.seek(0, 2)
    if handle.tell() == 0:
        handle.write(b"0")
        handle.flush()
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise NetdiskError("backend_busy", "网盘正在处理另一个操作，请稍后重试。") from None
                time.sleep(0.05)
        yield
    finally:
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        handle.close()


def process_alive(pid: int) -> bool:
    if pid == os.getpid():
        return True
    if pid <= 0:
        return False
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
    import ctypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return ctypes.get_last_error() == 5
    try:
        code = ctypes.c_ulong()
        return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
    finally:
        kernel.CloseHandle(handle)
