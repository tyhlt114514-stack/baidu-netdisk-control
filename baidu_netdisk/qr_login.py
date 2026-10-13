"""Local Baidu passport QR authorization, without browser or computer automation.

QR handles and the temporary exchange credential remain inside this process.
Only a validated Netdisk identity is returned by the dialog. See qr-login-sources.md.
"""
from __future__ import annotations

import base64
import http.cookiejar
from http.cookies import SimpleCookie
import io
import json
import queue
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .common import NetdiskError


_ORIGIN = "https://passport.baidu.com"
_CREATE = _ORIGIN + "/v2/api/getqrcode?lp=pc&qrloginfrom=pc&tpl=netdisk&apiver=v3"
_CHANNEL = "/channel/unicast"
_EXCHANGE = "/v3/login/main/qrbdusslogin"
_MAX_BODY = 1024 * 1024
_UA = "Mozilla/5.0"


class _NoFollow(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _trusted(url: str, paths: set[str]) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname != "passport.baidu.com" or
                parsed.port not in (None, 443) or parsed.username or parsed.password or
                parsed.fragment or parsed.path not in paths):
            raise ValueError()
    except (TypeError, ValueError):
        raise NetdiskError("qr_untrusted_url", "扫码登录只允许百度账号服务的固定 HTTPS 接口。") from None
    return url


def _json(raw: bytes) -> dict:
    try:
        text = raw.decode("utf-8").strip()
        if text.startswith("(") and text.endswith(")"):
            text = text[1:-1]
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError()
        return data
    except (UnicodeError, ValueError):
        raise NetdiskError("qr_invalid_response", "百度扫码接口返回了无法识别的数据。") from None


class QrLoginClient:
    def __init__(self, timeout=40, lifetime=300, *, opener=None, jar=None):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 60:
            raise NetdiskError("invalid_timeout", "扫码请求超时应为 1..60 秒。")
        if isinstance(lifetime, bool) or not isinstance(lifetime, (int, float)) or not 30 <= lifetime <= 600:
            raise NetdiskError("invalid_timeout", "二维码有效期应为 30..600 秒。")
        self.timeout = timeout
        self.lifetime = lifetime
        self.jar = jar if jar is not None else http.cookiejar.CookieJar()
        self.opener = opener if opener is not None else urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), _NoFollow())
        self._sign = None
        self._temporary = None
        self._deadline = None
        self._exchanged = False
        self._terminal = None
        self._exchange_issued_bduss = False

    def _read(self, url: str, paths: set[str], *, exchange=False) -> bytes:
        _trusted(url, paths)
        request = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
        try:
            try:
                response = self.opener.open(request, timeout=self.timeout)
            except urllib.error.HTTPError as exc:
                if exchange and exc.code in (301, 302, 303, 307, 308):
                    response = exc  # Extract Set-Cookie without following Location.
                else:
                    raise NetdiskError("qr_http_error", "百度扫码请求失败。", {"status": exc.code}) from None
            if response is None or not callable(getattr(response, "read", None)) or not callable(getattr(response, "info", None)):
                raise NetdiskError("qr_invalid_response", "百度扫码请求未返回可用响应。")
            with response:
                self.jar.extract_cookies(response, request)
                if exchange:
                    for header in response.info().get_all("Set-Cookie", []):
                        issued = SimpleCookie()
                        try:
                            issued.load(header)
                        except Exception:
                            continue
                        if "BDUSS" in issued and issued["BDUSS"].value:
                            self._exchange_issued_bduss = True
                raw = response.read(_MAX_BODY + 1)
        except TimeoutError:
            raise NetdiskError("qr_request_timeout", "百度扫码状态仍在等待响应。") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise NetdiskError("qr_request_timeout", "百度扫码状态仍在等待响应。") from None
            raise NetdiskError("qr_network_error", "无法连接百度扫码接口，请检查网络后刷新。") from None
        except OSError:
            raise NetdiskError("qr_network_error", "百度扫码请求暂未返回，请检查网络后重试。") from None
        if len(raw) > _MAX_BODY:
            raise NetdiskError("qr_invalid_response", "百度扫码响应超过大小上限。")
        return raw

    def create(self) -> dict:
        self._sign = self._temporary = self._deadline = None
        self._exchanged = False
        self._terminal = None
        self._exchange_issued_bduss = False
        data = _json(self._read(_CREATE, {"/v2/api/getqrcode"}))
        if type(data.get("errno")) is not int or data["errno"] != 0:
            code = data.get("errno")
            raise NetdiskError("qr_creation_failed", "百度未生成登录二维码。",
                               {"api_code": code if isinstance(code, int) and not isinstance(code, bool) else None})
        sign, image_url = data.get("sign"), data.get("imgurl")
        if (not isinstance(sign, str) or not sign or len(sign) > 1024 or
                any(ord(c) < 33 or ord(c) > 126 for c in sign) or not isinstance(image_url, str)):
            raise NetdiskError("qr_invalid_response", "百度没有返回完整的登录二维码。")
        if image_url.startswith("//"):
            image_url = "https:" + image_url
        elif not image_url.startswith(("http://", "https://")):
            image_url = "https://" + image_url
        # This is the image endpoint actually returned by Baidu getqrcode.
        image = self._read(image_url, {"/v2/api/qrcode", "/v2/api/qrcode/"})
        if not (image.startswith(b"\x89PNG\r\n\x1a\n") or image.startswith((b"GIF87a", b"GIF89a", b"\xff\xd8\xff"))):
            raise NetdiskError("qr_invalid_image", "百度未返回可显示的二维码图片。")
        self._sign = sign
        self._deadline = time.monotonic() + self.lifetime
        return {"status": "waiting", "image": image}

    def poll(self) -> dict:
        if self._terminal:
            return {"status": self._terminal}
        if self._sign is None:
            raise NetdiskError("qr_not_started", "请先生成登录二维码。")
        if time.monotonic() >= self._deadline:
            self._temporary = None
            self._terminal = "expired"
            return {"status": "expired"}
        if self._temporary is not None:
            return {"status": "confirmed"}
        url = _ORIGIN + _CHANNEL + "?" + urllib.parse.urlencode({"channel_id": self._sign, "callback": "",
             "tpl": "netdisk", "apiver": "v3", "tt": str(int(time.time() * 1000)), "_sdkFrom": "1"})
        try:
            data = _json(self._read(url, {_CHANNEL}))
        except NetdiskError as exc:
            if exc.code == "qr_request_timeout":
                return {"status": "waiting", "network_pending": True}
            raise
        code = data.get("errno")
        if type(code) is not int:
            raise NetdiskError("qr_invalid_response", "百度扫码状态响应缺少有效错误码。")
        if code == 1 and not data.get("channel_v"):
            return {"status": "waiting"}
        if code != 0:
            raise NetdiskError("qr_poll_failed", "百度未接受扫码状态请求，请刷新二维码。",
                               {"api_code": code if isinstance(code, int) and not isinstance(code, bool) else None})
        channel = data.get("channel_v")
        if not channel:
            return {"status": "waiting"}
        if isinstance(channel, str):
            channel = _json(channel.encode("utf-8"))
        if not isinstance(channel, dict) or type(channel.get("status")) is not int:
            raise NetdiskError("qr_invalid_response", "百度没有返回有效的扫码确认状态。")
        value = channel.get("v")
        if channel["status"] == 0 and isinstance(value, str) and value:
            if len(value) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in value):
                raise NetdiskError("qr_invalid_response", "扫码确认凭据格式异常。")
            self._temporary = value
            return {"status": "confirmed"}
        if channel["status"] == 1:
            return {"status": "scanned"}
        if channel["status"] == 2:
            self._temporary = None
            self._terminal = "cancelled"
            return {"status": "cancelled"}
        raise NetdiskError("qr_invalid_response", "百度返回了未识别的扫码状态，请刷新二维码。")

    def exchange(self) -> str:
        if not self._temporary or self._exchanged:
            raise NetdiskError("qr_not_confirmed", "需要本人扫码并在手机上确认登录。")
        if time.monotonic() >= self._deadline:
            self._temporary = None
            raise NetdiskError("qr_expired", "二维码已过期，请刷新后重新扫码。")
        # Only credentials newly issued by this exchange may authenticate the
        # selected account. Keep supporting cookies, but remove every old BDUSS
        # domain/path variant so a rejected Set-Cookie cannot reuse another user.
        for old in list(self.jar):
            if old.name == "BDUSS":
                self.jar.clear(old.domain, old.path, old.name)
        # Baidu's documented-by-source exchange requires a temporary credential
        # in this fixed HTTPS request. The URL never leaves this local module.
        url = _ORIGIN + _EXCHANGE + "?" + urllib.parse.urlencode({"bduss": self._temporary,
            "u": urllib.parse.quote("https://pan.baidu.com/disk/main", safe=""),
            "loginVersion": "v4", "qrcode": "1", "tpl": "netdisk", "v": str(int(time.time() * 1000))})
        try:
            self._read(url, {_EXCHANGE}, exchange=True)
        finally:
            self._temporary = None
            self._exchanged = True
        if not self._exchange_issued_bduss:
            raise NetdiskError("qr_exchange_failed", "百度没有签发正式登录会话，请刷新二维码后重试。")
        request = urllib.request.Request("https://pan.baidu.com/api/user/getinfo?need_selfinfo=1")
        self.jar.add_cookie_header(request)
        cookie = request.get_header("Cookie", "")
        from .session_import import _cookie_fields
        try:
            _cookie_fields(cookie)
        except NetdiskError:
            raise NetdiskError("qr_exchange_failed", "百度没有签发可用于网盘的完整登录会话。") from None
        return cookie


def masked_qr_login_dialog(verify) -> dict:
    """Show the original Baidu QR image locally; verify(cookie) returns public status."""
    import tkinter as tk
    root = tk.Tk()
    root.title("百度网盘 · 扫码授权")
    root.geometry("460x510")
    root.resizable(False, False)
    tk.Label(root, text="使用本人百度网盘手机 App 扫码\n并在手机上确认登录", font=("Microsoft YaHei", 12)).pack(pady=(18, 8))
    image_label = tk.Label(root)
    image_label.pack(pady=8)
    status = tk.StringVar(value="正在向百度获取二维码…")
    tk.Label(root, textvariable=status, wraplength=420, justify="center").pack(padx=12, pady=8)
    tk.Label(root, text="二维码由百度签发。验证失败时，会话在本地加密暂存30分钟，以便自动重试。", wraplength=420).pack(padx=12, pady=8)
    events = queue.Queue()
    cancelled = threading.Event()
    result = {}
    generation = {"value": 0}

    def close():
        cancelled.set()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", close)

    def worker(current):
        try:
            session = QrLoginClient()
            created = session.create()
            events.put((current, "image", created["image"]))
            while not cancelled.is_set() and current == generation["value"]:
                polled = session.poll()
                if cancelled.is_set() or current != generation["value"]:
                    return
                state = polled["status"]
                if state == "expired":
                    events.put((current, "expired", "二维码已过期，请点击刷新。"))
                    return
                if state == "cancelled":
                    events.put((current, "cancelled", "你已在手机上取消登录；需要时可刷新二维码。"))
                    return
                if state == "confirmed":
                    events.put((current, "status", "已确认，正在验证网盘身份和目录读取权限…"))
                    cookie = session.exchange()
                    if cancelled.is_set() or current != generation["value"]:
                        return
                    authenticated = verify(cookie, cancelled=lambda: cancelled.is_set() or current != generation["value"])
                    cookie = None
                    events.put((current, "success", authenticated))
                    return
                events.put((current, "status", "已扫码，请在手机上确认登录。" if state == "scanned" else "等待本人扫码并确认登录…"))
                if cancelled.wait(2):
                    return
        except NetdiskError as exc:
            events.put((current, "error", exc))
        except Exception:
            events.put((current, "error", NetdiskError("qr_login_failed", "扫码登录未完成，请刷新二维码后重试。")))

    def refresh():
        generation["value"] += 1
        result.pop("error", None)
        image_label.configure(image="")
        status.set("正在向百度获取二维码…")
        threading.Thread(target=worker, args=(generation["value"],), daemon=True).start()

    def consume():
        try:
            while True:
                current, event, value = events.get_nowait()
                if current != generation["value"]:
                    continue
                if event == "image":
                    try:
                        photo = tk.PhotoImage(data=base64.b64encode(value).decode("ascii"))
                        if 0 < photo.width() < 240:
                            photo = photo.zoom(max(1, 256 // photo.width()))
                    except tk.TclError:
                        try:
                            from PIL import Image, ImageTk
                            bitmap = Image.open(io.BytesIO(value))
                            if bitmap.width < 240:
                                scale = max(1, 256 // bitmap.width)
                                bitmap = bitmap.resize((bitmap.width * scale, bitmap.height * scale), Image.Resampling.NEAREST)
                            photo = ImageTk.PhotoImage(bitmap)
                        except Exception:
                            result["error"] = NetdiskError("qr_invalid_image", "二维码图片无法显示，请刷新重试。")
                            status.set(result["error"].message)
                            continue
                    image_label.configure(image=photo)
                    image_label.image = photo
                    status.set("等待本人扫码并确认登录…")
                elif event == "success":
                    result["status"] = value
                    cancelled.set()
                    root.destroy()
                    return
                elif event == "error":
                    result["error"] = value
                    status.set(value.message + "（可刷新重试）")
                else:
                    status.set(value)
        except queue.Empty:
            pass
        root.after(100, consume)

    buttons = tk.Frame(root)
    buttons.pack(pady=8)
    tk.Button(buttons, text="刷新二维码", command=refresh, width=18).pack(side="left", padx=8)
    tk.Button(buttons, text="取消", command=close, width=14).pack(side="left", padx=8)
    refresh()
    root.after(100, consume)
    root.mainloop()
    cancelled.set()
    if "status" in result:
        return result["status"]
    if "error" in result:
        raise result["error"]
    raise NetdiskError("login_cancelled", "本地扫码授权已取消。")
