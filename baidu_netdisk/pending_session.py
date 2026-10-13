"""Short-lived, current-user encrypted authorization for local verification retry.

This is application-internal credential handling. Public status never contains
the Cookie; the agent only invokes login-retry or reads the safe login result.
"""
from __future__ import annotations

import base64
import json
import math
import time
import uuid
from pathlib import Path

from .auth import _dpapi
from .common import NetdiskError, atomic_json, file_lock
from .pcs_json import _is_link, _pairs
from .session_import import _cookie_fields


class PendingSession:
    lifetime = 1800

    def __init__(self, state_dir: Path):
        root = Path(state_dir)
        if not root.is_absolute():
            raise NetdiskError("unsafe_config", "待验证会话必须保存在插件的绝对私有目录。")
        self.path = root / "pending-session.dpapi.json"
        self.lock = root / "pending-session.lock"
        for item in (self.path, self.lock, *self.path.parents):
            if _is_link(item):
                raise NetdiskError("unsafe_config", "私有凭据目录不能含重解析点。")

    def _envelope(self):
        if not self.path.exists():
            return None
        try:
            with self.path.open("rb") as stream:
                raw = stream.read(200000)
            if len(raw) >= 200000:
                raise ValueError()
            result = json.loads(raw, object_pairs_hook=_pairs)
            if not isinstance(result, dict) or result.get("version") != 1:
                raise ValueError()
            return result
        except (OSError, ValueError, UnicodeError):
            raise NetdiskError("credential_storage_error", "待验证的加密会话记录无法读取。") from None

    def save(self, cookie: str, *, source: str) -> str:
        _cookie_fields(cookie)
        if source not in ("qr", "cookie", "bduss"):
            raise NetdiskError("invalid_credential_type", "未知的本地授权方式。")
        created = time.time()
        generation = uuid.uuid4().hex
        record = {"generation": generation, "source": source, "cookie": cookie,
                  "created_at": created, "expires_at": created + self.lifetime}
        encrypted = _dpapi(json.dumps(record, ensure_ascii=False).encode("utf-8"))
        with file_lock(self.lock):
            atomic_json(self.path, {"version": 1, "protection": "windows-dpapi-current-user",
                "generation": generation, "source": source, "created_at": created,
                "expires_at": created + self.lifetime, "ciphertext": base64.b64encode(encrypted).decode("ascii")})
        return generation

    def _load_unlocked(self):
        envelope = self._envelope()
        if envelope is None:
            raise NetdiskError("pending_login_missing", "没有可重试的本地授权会话。")
        try:
            plain = _dpapi(base64.b64decode(envelope["ciphertext"], validate=True), decrypt=True)
            value = json.loads(plain, object_pairs_hook=_pairs)
            if (not isinstance(value, dict) or any(value.get(key) != envelope.get(key) for key in
                    ("generation", "source", "created_at", "expires_at")) or
                    not isinstance(value.get("generation"), str) or len(value["generation"]) != 32 or
                    value.get("source") not in ("qr", "cookie", "bduss")):
                raise ValueError()
            created, expires = value["created_at"], value["expires_at"]
            if (type(created) not in (int, float) or type(expires) not in (int, float) or
                    not math.isfinite(created) or not math.isfinite(expires) or
                    not 0 < expires - created <= self.lifetime or created > time.time() + 60):
                raise ValueError()
            if time.time() >= expires:
                self.path.unlink(missing_ok=True)
                raise NetdiskError("pending_login_expired", "本地待验证授权已过期，需要本人重新授权。")
            _cookie_fields(value.get("cookie"))
            return value
        except NetdiskError:
            raise
        except (ValueError, UnicodeError, KeyError, TypeError, OSError):
            raise NetdiskError("credential_storage_error", "待验证的加密会话损坏，未使用它。") from None

    def load(self) -> dict:
        """Private credential value for the local importer, never a tool result."""
        with file_lock(self.lock):
            return self._load_unlocked()

    def status(self) -> dict:
        if not self.path.exists():
            return {"available": False}
        try:
            value = self.load()
            return {"available": True, "source": value["source"], "expires_at": value["expires_at"],
                    "protection": "windows-dpapi-current-user"}
        except NetdiskError as exc:
            return {"available": False, "error": exc.code}

    def clear(self, generation: str):
        with file_lock(self.lock):
            envelope = self._envelope()
            if envelope and envelope.get("generation") == generation:
                self.path.unlink(missing_ok=True)
