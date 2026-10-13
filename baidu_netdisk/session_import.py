"""Local-only Cookie import validated by Baidu Netdisk, without Tieba login.

This function is for the local masked setup helper, never an MCP tool. It validates
the supplied session using fixed HTTPS read-only endpoints before atomically
updating the isolated BaiduPCS-Go configuration. It returns public identity only.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .common import NetdiskError, atomic_json, file_lock
from .pcs_json import _COOKIE_NAME, _MAX_JSON, _NoRedirect, _PAN_UA, _PCS_UA, _Session, _int, _is_link, _pairs, PcsJsonReader


_IDENTITY_URL = "https://pan.baidu.com/api/user/getinfo?need_selfinfo=1"
_TEMPLATE_IDENTITY_URL = "https://pan.baidu.com/api/gettemplatevariable?channel=chunlei&web=1&app_id=250528&clienttype=0"
_TEMPLATE_IDENTITY_BODY = urllib.parse.urlencode({"fields": '["username","loginstate","uk"]'}).encode("ascii")
_LIST_URL = "https://pan.baidu.com/api/list?dir=%2F&order=name&desc=0&clienttype=0&num=1&page=1"


def _check_cancelled(cancelled):
    if cancelled is None:
        return
    check = cancelled if callable(cancelled) else getattr(cancelled, "is_set", None)
    if not callable(check):
        raise NetdiskError("invalid_cancellation", "取消检查需要 callable 或 Event。")
    try:
        stopped = bool(check())
    except Exception:
        # An unavailable generation check must never authorize saving a session.
        raise NetdiskError("login_cancelled", "本次授权已取消，未保存会话。", {"stage": "cancellation"}) from None
    if stopped:
        raise NetdiskError("login_cancelled", "本次授权已取消，未保存会话。", {"stage": "cancellation"})


def _cookie_fields(cookie: str) -> dict[str, str]:
    if not isinstance(cookie, str) or not cookie.strip() or len(cookie) > 65536:
        raise NetdiskError("invalid_cookie", "请输入完整的本人网盘 Cookie。")
    text = re.sub(r"^\s*Cookie\s*:\s*", "", cookie, flags=re.I).strip()
    if any(ord(char) < 32 or ord(char) > 126 for char in text):
        raise NetdiskError("invalid_cookie", "Cookie 应为一行，不应包含换行或控制字符。")
    fields = {}
    for part in text.split(";"):
        if not part.strip():
            continue
        name, separator, value = part.strip().partition("=")
        name, value = name.strip(), value.strip().strip('"')
        if not separator or not _COOKIE_NAME.fullmatch(name):
            raise NetdiskError("invalid_cookie", "Cookie 格式无效，请从网盘请求头完整复制。")
        if name in fields and fields[name] != value:
            raise NetdiskError("invalid_cookie", "Cookie 中同一字段出现不同值，请重新复制。")
        fields[name] = value
    if not fields.get("BDUSS"):
        raise NetdiskError("missing_bduss", "Cookie 中缺少 BDUSS，请在已登录的百度网盘页面重新获取。")
    return fields


def _request(opener, url: str, cookie: str, timeout: int, *, identity_empty_ua: bool = False) -> dict:
    if url not in (_IDENTITY_URL, _TEMPLATE_IDENTITY_URL, _LIST_URL) or (identity_empty_ua and url != _IDENTITY_URL):
        raise NetdiskError("untrusted_url", "会话验证只允许固定的百度网盘 HTTPS 接口。")
    stage = "root_list" if url == _LIST_URL else "identity"
    profile = ("pan_template" if url == _TEMPLATE_IDENTITY_URL else
               ("upstream_empty_pcs_ua" if identity_empty_ua else "pcs_browser_default")) if stage == "identity" else "pan_android"
    user_agent = _PAN_UA if url in (_TEMPLATE_IDENTITY_URL, _LIST_URL) else ("" if identity_empty_ua else _PCS_UA)
    diagnostics = {"stage": stage, "profile": profile}
    headers = {"Cookie": cookie, "User-Agent": user_agent, "Accept": "application/json"}
    body = None
    if url == _TEMPLATE_IDENTITY_URL:
        # Maintained baiduwp AccountStatus uses this fixed form POST; the rclone
        # Netdisk backend separately documents uk as a supported template field.
        # The same authenticated session returned -6 with PCS UA but explicit
        # loginstate=1 and a valid UK with the maintained Netdisk Android UA;
        # root listing succeeded independently. Keep that verified profile.
        # Do not request token fields or put any credential in the query/body.
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Referer"] = "https://pan.baidu.com/disk/home"
        body = _TEMPLATE_IDENTITY_BODY
    request = urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(_MAX_JSON + 1)
    except urllib.error.HTTPError as exc:
        raise NetdiskError("authentication_required" if exc.code in (401, 403) else "http_error",
                           "百度拒绝此会话验证请求，请检查登录状态与接口兼容性。", {**diagnostics, "status": exc.code}) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise NetdiskError("network_error", "无法连接百度网盘，请检查网络。", diagnostics) from None
    except NetdiskError as exc:
        raise NetdiskError(exc.code, exc.message, {**exc.details, **diagnostics}) from None
    if len(raw) > _MAX_JSON:
        raise NetdiskError("invalid_response", "百度会话验证响应超过大小上限。", diagnostics)
    try:
        data = json.loads(raw, object_pairs_hook=_pairs)
    except (ValueError, UnicodeError):
        raise NetdiskError("invalid_response", "百度会话验证没有返回有效 JSON。", diagnostics) from None
    if not isinstance(data, dict):
        raise NetdiskError("invalid_response", "百度会话验证返回了无效结构。", diagnostics)
    try:
        PcsJsonReader._check_api(data)
    except NetdiskError as exc:
        raise NetdiskError(exc.code, exc.message, {**exc.details, **diagnostics}) from None
    return data


def _identity_compat_failure(exc: NetdiskError) -> bool:
    """Only retry documented identity contracts for bounded remote rejection."""
    return (exc.code == "authentication_required"
            or (exc.code == "http_error" and exc.details.get("status") == 400)
            or (exc.code == "remote_error" and exc.details.get("api_code") == 2))


def _template_identity(data: dict, diagnostics: dict) -> dict:
    # A public template can be returned for a logged-out visitor. A username,
    # a truthy loginstate, or a UK alone must not be treated as authentication.
    error = data.get("errno")
    if isinstance(error, bool) or error not in (0, "0") or not isinstance(error, (int, str)):
        raise NetdiskError("invalid_identity", "百度没有明确确认模板身份请求成功。", diagnostics)
    record = data.get("result")
    if not isinstance(record, dict):
        raise NetdiskError("invalid_identity", "百度没有返回唯一的本人网盘模板身份。", diagnostics)
    state = record.get("loginstate")
    if (type(state) is int and state == 0) or (type(state) is str and state == "0"):
        raise NetdiskError("authentication_required", "百度网盘尚未确认该会话处于登录状态。", diagnostics)
    if not ((type(state) is int and state == 1) or (type(state) is str and state == "1")):
        raise NetdiskError("invalid_identity", "百度没有返回明确的本人网盘登录状态。", diagnostics)
    return record


def import_cookie(cookie: str, config_dir: Path, timeout: int = 60, *, cancelled=None) -> dict:
    """Validate a locally entered session and merge its public Netdisk UK identity.

    ``uid`` is the UK returned by the Netdisk identity endpoint. The Go schema uses
    this field as the active-account key; this route does not query Tieba to derive
    identity. Cookies authorize the native Netdisk requests independently of UID.
    ``cancelled`` is a local callable or Event; the final check runs under the
    configuration lock immediately before atomic save, preventing stale QR jobs
    from importing a cancelled authorization generation.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 300:
        raise NetdiskError("invalid_timeout", "会话验证超时应为 1..300 秒。")
    _check_cancelled(cancelled)
    try:
        fields = _cookie_fields(cookie)
    except NetdiskError as exc:
        raise NetdiskError(exc.code, exc.message, {**exc.details, "stage": "credential_format"}) from None
    header = "; ".join(f"{name}={value}" for name, value in fields.items())
    if len(header) + 1 > 65536:
        raise NetdiskError("invalid_cookie", "规范化后的 Cookie 超过允许大小。")
    opener = urllib.request.build_opener(_NoRedirect())
    identity_attempts = []
    identity_source = "netdisk_api_user_getinfo"
    try:
        data = _request(opener, _IDENTITY_URL, header, timeout)
        identity_profile = "pcs_browser_default"
    except NetdiskError as exc:
        # v4.0.2 PrepareUK uses reqTypePCS; default empty PCSUA overwrites the
        # requester's global browser UA. Try that source-backed profile only on
        # auth rejection, with the same HTTPS identity URL and credential.
        # The live legacy endpoint also returns HTTP 400 / errno 2 for its old
        # need_selfinfo contract. That is an interface error, not expired Cookie.
        if not _identity_compat_failure(exc):
            raise
        identity_attempts.append({"profile": "pcs_browser_default", "ok": False,
                                  "error": exc.code, **exc.details})
        needs_template = exc.code != "authentication_required"
        if not needs_template:
            _check_cancelled(cancelled)
            try:
                data = _request(opener, _IDENTITY_URL, header, timeout, identity_empty_ua=True)
                identity_profile = "upstream_empty_pcs_ua"
            except NetdiskError as fallback:
                identity_attempts.append({"profile": "upstream_empty_pcs_ua", "ok": False,
                                          "error": fallback.code, **fallback.details})
                if not _identity_compat_failure(fallback):
                    raise NetdiskError(fallback.code, fallback.message,
                                       {**fallback.details, "attempts": identity_attempts}) from None
                needs_template = True
        if needs_template:
            _check_cancelled(cancelled)
            try:
                data = _request(opener, _TEMPLATE_IDENTITY_URL, header, timeout)
                identity_profile = "pan_template"
                identity_source = "netdisk_api_gettemplatevariable"
            except NetdiskError as fallback:
                identity_attempts.append({"profile": "pan_template", "ok": False,
                                          "error": fallback.code, **fallback.details})
                raise NetdiskError(fallback.code, fallback.message,
                                   {**fallback.details, "attempts": identity_attempts}) from None
    _check_cancelled(cancelled)
    identity_diagnostics = {"stage": "identity", "profile": identity_profile, "attempts": identity_attempts}
    if identity_source == "netdisk_api_gettemplatevariable":
        record = _template_identity(data, identity_diagnostics)
    else:
        records = data.get("records")
        if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
            raise NetdiskError("invalid_identity", "百度没有返回唯一的本人网盘身份。", identity_diagnostics)
        record = records[0]
    try:
        uid = _int(record.get("uk"), "netdisk_uk", minimum=1)
    except NetdiskError:
        raise NetdiskError("invalid_identity", "百度没有返回有效的本人网盘 UK。", identity_diagnostics) from None
    if uid > 2**64 - 1:
        raise NetdiskError("invalid_identity", "百度网盘身份超出配置字段范围。", identity_diagnostics)
    identity_attempts.append({"profile": identity_profile, "ok": True, "stage": "identity"})
    name = next((record[key] for key in ("baidu_name", "netdisk_name", "uname", "username")
                 if isinstance(record.get(key), str) and record[key].strip()), f"网盘用户 {uid}")
    name = name.strip()[:256]
    if any(value and len(value) >= 8 and value in name for value in fields.values()):
        name = f"网盘用户 {uid}"
    try:
        directory = _request(opener, _LIST_URL, header, timeout)
    except NetdiskError as exc:
        raise NetdiskError(exc.code, exc.message, {**exc.details, "identity_profile": identity_profile,
                                                  "identity_attempts": identity_attempts}) from None
    if not isinstance(directory.get("list"), list):
        raise NetdiskError("invalid_response", "百度没有确认该会话可以读取本人网盘目录。", {"stage": "root_list", "profile": "pan_android"})
    _check_cancelled(cancelled)
    private = Path(config_dir).expanduser()
    if not private.is_absolute():
        raise NetdiskError("unsafe_config", "PCS 配置必须使用独立的绝对路径。")
    source = private / "pcs_config.json"
    for ancestor in [source, *source.parents]:
        if _is_link(ancestor):
            raise NetdiskError("unsafe_config", "私有 PCS 配置不能含符号链接或重解析点。")
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Same lock path as NetdiskService; merging waits for ongoing CLI operations.
    with file_lock(private.parent / "pcs-process.lock"):
        try:
            if source.exists():
                with source.open("rb") as file:
                    raw = file.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError("Config too large")
                config = json.loads(raw, object_pairs_hook=_pairs)
            else:
                # Go calls InitDefaultConfig before JSON unmarshal, so omitted
                # non-account options retain the upstream defaults.
                config = {"appid": 266719, "enable_https": True, "baidu_active_uid": 0, "baidu_user_list": []}
            if not isinstance(config, dict):
                raise ValueError("Invalid config object")
            users = config.get("baidu_user_list", [])
            if users is None:
                # Go's initial nil account slice is serialized as JSON null.
                # Accept only an actually empty config; a selected account with
                # no list is inconsistent and must not be silently repaired.
                active = config.get("baidu_active_uid", 0)
                if type(active) is not int or active != 0:
                    raise ValueError("Invalid empty active account")
                users = []
            elif not isinstance(users, list):
                raise ValueError("Invalid user list")
            try:
                app_id = _int(config.get("appid", 266719), "app_id", minimum=1)
            except NetdiskError:
                raise ValueError("Invalid config app id") from None
            pan_ua = config.get("pan_ua") or _PAN_UA
            pcs_ua = config.get("pcs_ua") or config.get("user_agent") or _PCS_UA
            if any(not isinstance(ua, str) or len(ua) > 2048 or any(ord(char) < 32 or ord(char) > 126 for char in ua)
                   for ua in (pan_ua, pcs_ua)):
                raise ValueError("Invalid configured user agent")
            same = [user for user in users if isinstance(user, dict) and str(user.get("uid")) == str(uid)]
            if len(same) > 1 or any(not isinstance(user, dict) for user in users):
                raise ValueError("Invalid user list")
            user = dict(same[0]) if same else {"sex": "", "age": 0.0, "workdir": "/", "accesstoken": ""}
            user.update(uid=uid, name=name, bduss=fields["BDUSS"], stoken=fields.get("STOKEN", ""),
                        ptoken=fields.get("PTOKEN", ""), baiduid=fields.get("BAIDUID", ""),
                        sboxtkn=fields.get("SBOXTKN", ""), cookies=header + ";")
            config["baidu_user_list"] = [user if str(existing.get("uid")) == str(uid) else existing for existing in users]
            if not same:
                config["baidu_user_list"].append(user)
            config["baidu_active_uid"] = uid
            result = _Session(str(uid), name, app_id, pan_ua, pcs_ua, header, b"").public_identity()
            _check_cancelled(cancelled)
            atomic_json(source, config)
        except (ValueError, TypeError, UnicodeError):
            raise NetdiskError("invalid_config", "已有私有 PCS 配置格式无效，未覆盖它。", {"stage": "config"}) from None
        except OSError:
            raise NetdiskError("config_write_failed", "会话已验证，但无法保存到私有 PCS 配置。", {"stage": "config"}) from None
    # Return only public identity, with the same identity convention as the reader.
    return {"ok": True, **result, "identity_source": identity_source, "netdisk_read_verified": True,
            "identity_profile": identity_profile, "identity_attempts": identity_attempts}
