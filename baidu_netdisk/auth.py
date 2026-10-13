from __future__ import annotations

import base64
import ctypes
import getpass
import json
import os
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path

from .common import NetdiskError, atomic_json, file_lock
from .http import HttpClient

OAUTH_AUTHORIZE = "https://openapi.baidu.com/oauth/2.0/authorize"
OAUTH_TOKEN = "https://openapi.baidu.com/oauth/2.0/token"


def _dpapi(data: bytes, decrypt: bool = False) -> bytes:
    if os.name != "nt":
        raise NetdiskError("unsupported_platform", "此凭据存储使用 Windows DPAPI，请在 Windows 上登录。")

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source, result = Blob(len(data), buffer), Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    operation = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    operation.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob),
                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(Blob)]
    operation.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    # CRYPTPROTECT_UI_FORBIDDEN: no interactive Windows prompt in an MCP process.
    if not operation(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result)):
        raise NetdiskError("credential_storage_error", "Windows 无法读取或保存此账号的加密凭据。")
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        kernel.LocalFree(result.pbData)


class SecretStore:
    def __init__(self, state_dir: Path):
        self.path = state_dir / "oauth.dpapi.json"

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            envelope = json.loads(self.path.read_text(encoding="utf-8"))
            return json.loads(_dpapi(base64.b64decode(envelope["ciphertext"]), decrypt=True))
        except (ValueError, KeyError, TypeError):
            raise NetdiskError("credential_storage_error", "加密凭据文件损坏，请重新登录。") from None

    def save(self, data: dict) -> None:
        cipher = _dpapi(json.dumps(data).encode("utf-8"))
        atomic_json(self.path, {"version": 1, "protection": "windows-dpapi-current-user",
                                "ciphertext": base64.b64encode(cipher).decode("ascii")})


class TokenStore:
    def __init__(self, settings, http=None):
        self.settings = settings
        self.http = http or HttpClient(settings.timeout)
        self.secrets = SecretStore(settings.state_dir)
        self.lock = threading.Lock()

    def _exchange(self, params: dict, secret_data: dict) -> dict:
        response = self.http.request_json(OAUTH_TOKEN, data=params, method="POST")
        if response.get("error") or not response.get("access_token"):
            raise NetdiskError("authorization_failed", "百度授权失败，请在本地重新登录。",
                               {"error": response.get("error", "missing_access_token")})
        secret_data.update(response)
        secret_data["expires_at"] = time.time() + int(response.get("expires_in", 2592000))
        self.secrets.save(secret_data)
        return secret_data

    def access_token(self) -> str:
        with self.lock, file_lock(self.settings.state_dir / "oauth.lock"):
            data = self.secrets.load()
            if not data.get("access_token"):
                # Optionally allow a token injected into the server's environment.
                token = os.environ.get("BAIDU_ACCESS_TOKEN")
                if token:
                    return token
                raise NetdiskError("login_required", "尚未登录：请运行 setup.ps1 -Backend openapi -Login。")
            if time.time() < data.get("expires_at", 0) - 60:
                return data["access_token"]
            if not data.get("refresh_token") or not data.get("client_secret"):
                raise NetdiskError("login_required", "百度授权已过期，请重新登录。")
            data = self._exchange({"grant_type": "refresh_token", "refresh_token": data["refresh_token"],
                                   "client_id": self.settings.client_id,
                                   "client_secret": data["client_secret"]}, data)
            return data["access_token"]

    def status(self) -> dict:
        data = self.secrets.load()
        return {"authorized": bool(data.get("access_token") or os.environ.get("BAIDU_ACCESS_TOKEN")),
                "expires_at": data.get("expires_at"),
                "can_refresh": bool(data.get("refresh_token")),
                "credential_storage": "Windows DPAPI"}

    def login_interactive(self, open_browser: bool = True) -> dict:
        if not self.settings.client_id:
            raise NetdiskError("client_id_required", "请先填写开放平台 AppKey（client_id）。")
        if self.settings.redirect_uri != "oob":
            raise NetdiskError("unsupported_redirect", "本地交互授权目前使用 oob 回调。请将 redirect_uri 设置为 oob。")
        client_secret = getpass.getpass("SecretKey（输入不会显示）: ")
        if not client_secret.strip():
            raise NetdiskError("client_secret_required", "SecretKey 不能为空。")
        url = OAUTH_AUTHORIZE + "?" + urllib.parse.urlencode({
            "response_type": "code", "client_id": self.settings.client_id,
            "redirect_uri": "oob", "scope": "basic,netdisk", "display": "page"})
        print("请在百度页面登录并授权，随后复制授权码到本地终端：\n" + url)
        if open_browser:
            webbrowser.open(url)
        code = getpass.getpass("授权码（输入不会显示）: ").strip()
        if not code:
            raise NetdiskError("authorization_code_required", "授权码不能为空。")
        with file_lock(self.settings.state_dir / "oauth.lock"):
            self._exchange({"grant_type": "authorization_code", "code": code, "client_id": self.settings.client_id,
                            "client_secret": client_secret, "redirect_uri": "oob"}, {"client_secret": client_secret})
        return self.status()
