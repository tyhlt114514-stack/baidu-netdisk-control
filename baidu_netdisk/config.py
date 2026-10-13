from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

from .common import NetdiskError, normalize_remote

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Settings:
    backend: str
    state_dir: Path
    allowed_local_roots: list[Path]
    remote_root: str = "/apps/baidu-netdisk"
    timeout: float = 60.0
    pcs_executable: str = ""
    client_id: str = ""
    redirect_uri: str = "oob"
    cache_root: Path | None = None

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        path = (path or PROJECT_ROOT / "config.json").resolve()
        if not path.exists():
            raise NetdiskError("not_configured", "请先运行 setup.ps1 创建配置和登录网盘。")
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            if not isinstance(data, dict):
                raise ValueError("配置顶层必须是对象")
            backend = data.get("backend", "pcs")
            if backend not in ("pcs", "openapi"):
                raise ValueError("backend 必须为 pcs 或 openapi")
            raw_roots = data["allowed_local_roots"]
            if not isinstance(raw_roots, list) or not raw_roots or not all(
                    isinstance(p, str) and Path(p).expanduser().is_absolute() for p in raw_roots):
                raise ValueError("allowed_local_roots 必须是非空绝对路径字符串数组")
            roots = [Path(p).expanduser().resolve() for p in raw_roots]
            if not roots:
                raise ValueError("allowed_local_roots 不能为空")
            timeout = float(data.get("timeout", 60))
            if not math.isfinite(timeout) or not 0 < timeout <= 3600:
                raise ValueError("timeout 必须大于0且不超过3600秒")
            state = Path(data.get("state_dir", str(path.parent / ".private"))).expanduser().resolve()
            executable = data.get("pcs_executable", str(path.parent / "bin" / "BaiduPCS-Go.exe"))
            cache = Path(data.get("cache_root", str(path.parent / "cache"))).expanduser()
            if not cache.is_absolute():
                raise ValueError("cache_root 必须是绝对路径")
            return cls(backend, state, roots, normalize_remote(data.get("remote_root", "/apps/baidu-netdisk")),
                       timeout, executable,
                       data.get("client_id", ""), data.get("redirect_uri", "oob"), cache.resolve())
        except (ValueError, TypeError, KeyError) as exc:
            raise NetdiskError("invalid_config", f"配置无效：{exc}") from None
